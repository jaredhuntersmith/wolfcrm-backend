import { can, fail, ids, requireCapability } from "./access.js";

export const BROADCAST_MENTION_COOLDOWN_SECONDS = 60;
export const MAX_MENTION_AUDIENCE = 200;

export async function installMentionsSchema(db) {
  await db.query(`
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS mention_scope text CHECK(mention_scope IN('group','channel','here'));
    CREATE INDEX IF NOT EXISTS comms_mention_cooldown ON messages(company_id,sender_id,conversation_id,created_at DESC) WHERE mention_scope IS NOT NULL;
  `);
}

export function mentionScopes(actor, conversation) {
  if (
    !can(actor, "communications.manage") ||
    !can(actor, "communications.send")
  )
    return [];
  if (
    conversation.archived_at ||
    conversation.thread_archived ||
    conversation.section_archived ||
    conversation.group_archived
  )
    return [];
  if (
    conversation.thread_kind === "announcement" &&
    conversation.owner_user_id !== actor.userId
  )
    return [];
  if (conversation.thread_id) return ["channel", "here"];
  if (["group_dm", "meeting"].includes(conversation.scope))
    return ["group", "here"];
  return [];
}

// The selection is intent, not an audience snapshot. Scheduled sends keep this
// intent and resolve all scopes against current permissions/presence on delivery.
export function mentionSelection(actor, conversation, body) {
  if (body.mention_all !== undefined && typeof body.mention_all !== "boolean")
    fail(400, "invalid_mention_scope");
  let scope = body.mention_scope ?? null;
  if (body.mention_all === true) {
    if (scope) fail(400, "invalid_mention_scope");
    scope = conversation.thread_id ? "channel" : "group";
  }
  if (scope !== null) {
    if (!["group", "channel", "here"].includes(scope))
      fail(400, "invalid_mention_scope");
    requireCapability(actor, "communications.manage");
    if (!mentionScopes(actor, conversation).includes(scope))
      fail(400, "invalid_mention_scope");
  }
  return {
    mention_scope: scope,
    mention_user_ids: ids(body.mention_user_ids || []),
  };
}

export async function resolveMentions(
  db,
  actor,
  conversation,
  body,
  recipients,
  { claim = true } = {},
) {
  const selection = mentionSelection(actor, conversation, body);
  const current = new Set(recipients.map((person) => person.id));
  if (selection.mention_user_ids.some((user) => !current.has(user)))
    fail(400, "invalid_mention");
  let audience = [];
  if (selection.mention_scope) {
    if (
      recipients.audience_truncated ||
      recipients.length > MAX_MENTION_AUDIENCE
    )
      fail(400, "mention_audience_too_large");
    audience = [...current];
    if (selection.mention_scope === "here") {
      // Here means currently available/online, even if viewing another screen.
      audience = (
        await db.query(
          `SELECT user_id FROM comms_presence WHERE company_id=$1 AND user_id=ANY($2::uuid[]) AND availability='available' AND expires_at>now()`,
          [actor.companyId, audience],
        )
      ).rows.map((row) => row.user_id);
    }
    if (claim) {
      // Held until the enclosing message transaction commits. The existing
      // client_key replay check runs before this claim, including concurrent retries.
      await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
        "comms-broadcast-mention:" +
          actor.companyId +
          ":" +
          actor.userId +
          ":" +
          conversation.id,
      ]);
      const recent = (
        await db.query(
          `SELECT 1 FROM messages WHERE company_id=$1 AND sender_id=$2 AND conversation_id=$3 AND mention_scope IS NOT NULL AND created_at>now()-$4::int*interval '1 second' LIMIT 1`,
          [
            actor.companyId,
            actor.userId,
            conversation.id,
            BROADCAST_MENTION_COOLDOWN_SECONDS,
          ],
        )
      ).rowCount;
      if (recent)
        fail(
          429,
          "mention_rate_limited",
          "Wait one minute between audience mentions in this conversation.",
        );
    }
  }
  return {
    ...selection,
    resolved_user_ids: [
      ...new Set([...selection.mention_user_ids, ...audience]),
    ],
  };
}
