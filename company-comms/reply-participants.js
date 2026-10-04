import {
  authorizeConversation,
  conversationAccessSQL,
  conversationJoins,
  uuid,
} from "./access.js";

const AUTHOR_SCAN_LIMIT = 200;
const PREVIEW_LIMIT = 8;

// Both the root and every counted reply must be visible in the same canonical
// conversation, including admission history and generated-source ancestry.
const visibleReplies = (
  actor,
) => `SELECT reply.id,reply.reply_root_id,reply.sender_id,c.id AS conversation_id
 FROM messages root JOIN conversations c ON c.id=COALESCE(root.conversation_id,(SELECT rt.conversation_id FROM comms_threads rt WHERE rt.legacy_channel_id=root.channel_id))
 ${conversationJoins} JOIN messages reply ON reply.reply_root_id=root.id AND (reply.conversation_id=c.id OR reply.channel_id=t.legacy_channel_id)
 WHERE root.id=ANY($3::text[]) AND root.company_id=$2 AND reply.company_id=$2 AND root.deleted_at IS NULL AND reply.deleted_at IS NULL
 AND ${conversationAccessSQL(actor)} AND root.created_at>=COALESCE(cp.history_from,'-infinity') AND reply.created_at>=COALESCE(cp.history_from,'-infinity')`;

async function currentAuthor(db, actor, conversation, user, cache) {
  const key = conversation + ":" + user;
  if (cache.has(key)) return cache.get(key);
  let person = null;
  try {
    const current = await authorizeConversation(
      db,
      { userId: user, companyId: actor.companyId },
      conversation,
    );
    person = { id: user, display_name: current.actor.displayName };
  } catch (error) {
    if (!error.status || error.status >= 500) throw error;
  }
  cache.set(key, person);
  return person;
}

export async function replyOverview(db, actor, messageIds) {
  if (!messageIds.length) return new Map();
  const rows = (
    await db.query(
      `WITH visible AS (${visibleReplies(actor)}),
    counts AS(SELECT reply_root_id,count(*)::int AS reply_count FROM visible GROUP BY reply_root_id),
    authors AS(SELECT DISTINCT reply_root_id,conversation_id,sender_id FROM visible),
    ranked AS(SELECT *,row_number() OVER(PARTITION BY reply_root_id ORDER BY sender_id) AS position FROM authors)
    SELECT counts.*,ranked.conversation_id,ranked.sender_id,ranked.position FROM counts JOIN ranked USING(reply_root_id)
    WHERE ranked.position<=$4 ORDER BY counts.reply_root_id,ranked.position`,
      [actor.userId, actor.companyId, messageIds, AUTHOR_SCAN_LIMIT + 1],
    )
  ).rows;
  const result = new Map(),
    cache = new Map();
  for (const row of rows) {
    let item = result.get(row.reply_root_id);
    if (!item) {
      item = {
        reply_count: row.reply_count,
        reply_participants: [],
        reply_participant_count: 0,
        reply_participants_truncated: false,
      };
      result.set(row.reply_root_id, item);
    }
    if (Number(row.position) > AUTHOR_SCAN_LIMIT) {
      item.reply_participant_count = null;
      item.reply_participants_truncated = true;
      continue;
    }
    const author = await currentAuthor(
      db,
      actor,
      row.conversation_id,
      row.sender_id,
      cache,
    );
    if (!author) continue;
    item.reply_participant_count++;
    if (item.reply_participants.length < PREVIEW_LIMIT)
      item.reply_participants.push(author);
    else item.reply_participants_truncated = true;
  }
  return result;
}

export async function replyParticipantPage(db, actor, rootId, afterId) {
  const after = afterId ? uuid(afterId) : null;
  const rows = (
    await db.query(
      `WITH visible AS (${visibleReplies(actor)}) SELECT DISTINCT conversation_id,sender_id FROM visible WHERE ($4::uuid IS NULL OR sender_id>$4::uuid) ORDER BY sender_id LIMIT $5`,
      [actor.userId, actor.companyId, [rootId], after, AUTHOR_SCAN_LIMIT + 1],
    )
  ).rows;
  const participants = [],
    cache = new Map();
  let processed = 0;
  for (const row of rows.slice(0, AUTHOR_SCAN_LIMIT)) {
    processed++;
    const author = await currentAuthor(
      db,
      actor,
      row.conversation_id,
      row.sender_id,
      cache,
    );
    if (author) participants.push(author);
    if (participants.length === 50) break;
  }
  // A continuation identifies only an author of an already-visible reply. It
  // never contains an author from another conversation or outside history bounds.
  return {
    participants,
    next_cursor:
      processed < rows.length ? rows[processed - 1]?.sender_id || null : null,
  };
}
