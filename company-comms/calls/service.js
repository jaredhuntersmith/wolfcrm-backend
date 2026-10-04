import {callReadSQL} from './access.js';
import { randomUUID } from "node:crypto";
import { readCallUsage } from "./usage.js";
import { observeRecording } from "./recording-lifecycle.js";
import {
  conversationJoins,
  conversationAccessSQL,
  loadActor,
  cursor,
  encodeCursor,
} from "../access.js";
import {
  CallError,
  fail,
  uuid,
  requireCapability,
  terminal,
  safeCall,
  text,
  settingsInput,
} from "./domain.js";

export function createCallsService({
  pool,
  provider,
  authorizeConversation,
  publish = async () => {},
  sendIncomingCall,
  meetingDelivery,
  adoptRecording,
  resolveActor,
  env = process.env,
}) {
  const transaction = async (fn) => {
    const db = await pool.connect();
    try {
      await db.query("BEGIN");
      const value = await fn(db);
      await db.query("COMMIT");
      return value;
    } catch (e) {
      await db.query("ROLLBACK");
      throw e;
    } finally {
      db.release();
    }
  };
  const actorFor = async (req) =>
    resolveActor ? resolveActor(req) : req.commsActor || req;
  const settings = async (db, a) => {
    await db.query(
      "INSERT INTO comms_call_settings(company_id) VALUES($1) ON CONFLICT DO NOTHING",
      [a.companyId],
    );
    return (
      await db.query(
        "SELECT * FROM comms_call_settings WHERE company_id=$1 FOR UPDATE",
        [a.companyId],
      )
    ).rows[0];
  };
  const authorize = async (db, a, c, write = false) => {
    const conversation = await authorizeConversation(db, a, String(c), {
      write,
      capability: "communications.calls",
    });
    if (conversation.actor) Object.assign(a, conversation.actor);
    requireCapability(a);
    return conversation;
  };
  const row = async (db, a, id, lock = true) => {
    const c = (
      await db.query(
        `SELECT * FROM comms_call_sessions WHERE id=$1 AND company_id=$2 ${lock ? "FOR UPDATE" : ""}`,
        [uuid(id), a.companyId],
      )
    ).rows[0];
    if (!c) fail(404, "call_unavailable");
    if (c.meeting_id) {
      const m = (
        await db.query(
          "SELECT * FROM comms_meetings WHERE id=$1 AND company_id=$2",
          [c.meeting_id, a.companyId],
        )
      ).rows[0];
      if (!m || (m.status === "canceled" && !terminal(c.status)))
        fail(404, "meeting_unavailable");
      await authorize(db, a, m.source_conversation_id || m.conversation_id);
      const invited = await db.query(
        "SELECT 1 FROM comms_meeting_attendees WHERE meeting_id=$1 AND user_id=$2",
        [m.id, a.userId],
      );
      if (m.host_user_id !== a.userId && !invited.rowCount)
        fail(404, "meeting_unavailable");
    } else await authorize(db, a, c.conversation_id);
    const p = (
      await db.query(
        "SELECT * FROM comms_call_participants WHERE call_id=$1 AND user_id=$2",
        [c.id, a.userId],
      )
    ).rows[0];
    if (p?.state === "removed") fail(404, "call_unavailable");
    return { c, p };
  };
  const eligibilityConversation = async (db, c) =>
    c.meeting_id
      ? (
          await db.query(
            "SELECT source_conversation_id FROM comms_meetings WHERE id=$1",
            [c.meeting_id],
          )
        ).rows[0]?.source_conversation_id || c.conversation_id
      : c.conversation_id;
  const host = (a, c) => {
    if (a.userId !== c.host_user_id) fail(403, "host_required");
  };
  const audit = async (db, a, c, action, target = null) =>
    db.query(
      "INSERT INTO comms_call_audit(company_id,call_id,actor_user_id,action,target_user_id) VALUES($1,$2,$3,$4,$5)",
      [a.companyId, c?.id, a.userId, action, target],
    );
  const event = async (db, a, c, type) =>
    publish(db, a, c.conversation_id, type, c.id, { call_id: c.id });
  const job = async (db, c, kind, payload = {}) =>
    db.query(
      "INSERT INTO comms_call_jobs(id,call_id,kind,payload) VALUES($1,$2,$3,$4)",
      [randomUUID(), c.id, kind, payload],
    );
  const effectiveUsage = async (db, a) =>
    Number(
      (
        await db.query(
          `SELECT COALESCE(sum(p.participant_seconds+CASE WHEN p.state='joined' THEN greatest(0,extract(epoch from now()-p.joined_at)) ELSE 0 END),0) seconds FROM comms_call_participants p JOIN comms_call_sessions c ON c.id=p.call_id WHERE c.company_id=$1 AND c.created_at>=date_trunc('month',now())`,
          [a.companyId],
        )
      ).rows[0].seconds,
    ) + (service.guests ? await service.guests.usage(db, a.companyId) : 0);
  const ensureBudget = async (db, a, s) => {
    if (!s.enabled) fail(403, "calling_disabled");
    if ((await effectiveUsage(db, a)) >= s.monthly_participant_minutes * 60)
      fail(
        429,
        "calling_usage_limit",
        "Your company call allowance has been reached.",
      );
  };
  const ensureActive = (c) => {
    if (terminal(c.status)) fail(409, "call_ended");
  };
  const finish = async (db, a, c, status = "ended", reason = "ended") => {
    if (terminal(c.status)) return safeCall(c);
    const updated = (
      await db.query(
        "UPDATE comms_call_sessions SET status=$2,ended_at=now(),end_reason=$3,version=version+1 WHERE id=$1 RETURNING *",
        [c.id, status, reason],
      )
    ).rows[0];
    await db.query(
      `UPDATE comms_call_participants SET participant_seconds=participant_seconds+CASE WHEN state='joined' THEN greatest(0,extract(epoch from now()-joined_at))::bigint ELSE 0 END,state=CASE WHEN state='removed' THEN state ELSE 'left' END,left_at=now() WHERE call_id=$1`,
      [c.id],
    );
    await job(db, c, "close");
    await db.query(
      "UPDATE comms_call_recordings SET status='failed',error_code='call_ended' WHERE call_id=$1 AND status='consent'",
      [c.id],
    );
    await db.query(
      "UPDATE comms_call_recordings SET status='stopping' WHERE call_id=$1 AND status IN('starting','recording')",
      [c.id],
    );
    await job(db, c, "stop_recordings");
    await event(db, a, c, "call.ended");
    return safeCall(updated);
  };
  const eligibleUser = async (db, a, userId, conversationId) => {
    const u = (
      await db.query(
        "SELECT id,company_id,deleted_at FROM users WHERE id=$1 AND company_id=$2 AND deleted_at IS NULL",
        [uuid(userId), a.companyId],
      )
    ).rows[0];
    if (!u) fail(400, "ineligible_member");
    await authorizeConversation(
      db,
      { ...a, userId: u.id, isCompanyOwner: false, permissions: undefined },
      conversationId,
      { capability: "communications.calls" },
    );
    return u;
  };
  const joinParticipant = async (db, a, c, state = "accepted") => {
    let p = (
      await db.query(
        "SELECT * FROM comms_call_participants WHERE call_id=$1 AND user_id=$2",
        [c.id, a.userId],
      )
    ).rows[0];
    if (p?.state === "removed") fail(403, "call_removed");
    if (!p)
      p = (
        await db.query(
          "INSERT INTO comms_call_participants(call_id,user_id,state,identity) VALUES($1,$2,$3,$4) RETURNING *",
          [c.id, a.userId, state, "p_" + randomUUID().replaceAll("-", "")],
        )
      ).rows[0];
    return p;
  };
  const sanitizeRecording = (r) => {
    const { object_key, egress_id, ...safe } = r;
    return safe;
  };
  const recordingAuthorized = async (db, c, r) => {
    try {
      const actor = await loadActor(db, {
        companyId: c.company_id,
        userId: r.requested_by,
      });
      requireCapability(actor, "communications.record");
      await authorize(db, actor, c.conversation_id);
      await authorize(db, actor, await eligibilityConversation(db, c));
      const policy = await settings(db, actor);
      return (
        policy.enabled &&
        policy.recording_enabled &&
        !(service.guests && (await service.guests.recordingBlocked(db, c.id)))
      );
    } catch (error) {
      if ([400, 403, 404].includes(error.status)) return false;
      throw error;
    }
  };
  const reconcileRecordings = async (db, c) => {
    const rows = (
      await db.query(
        "SELECT * FROM comms_call_recordings WHERE call_id=$1 AND status IN('consent','starting','recording') FOR UPDATE",
        [c.id],
      )
    ).rows;
    for (const r of rows)
      if (!(await recordingAuthorized(db, c, r))) {
        await db.query(
          "UPDATE comms_call_recordings SET status=CASE WHEN status='consent' THEN 'failed' ELSE 'stopping' END,error_code='recording_access_ended' WHERE id=$1",
          [r.id],
        );
        await job(db, c, "stop_recordings");
      }
  };
  const reconcileParticipant = async (db, c, p) => {
    try {
      const authorized = await authorizeConversation(
        db,
        { userId: p.user_id, companyId: c.company_id },
        await eligibilityConversation(db, c),
        { capability: "communications.calls" },
      );
      if (
        c.meeting_id &&
        c.host_user_id !== p.user_id &&
        !(
          await db.query(
            "SELECT 1 FROM comms_meeting_attendees WHERE meeting_id=$1 AND user_id=$2 AND rsvp<>'declined'",
            [c.meeting_id, p.user_id],
          )
        ).rowCount
      )
        fail(403, "invitation_required");
      if (c.meeting_id && ["admitted", "joined"].includes(p.state))
        await authorizeConversation(
          db,
          { userId: p.user_id, companyId: c.company_id },
          c.conversation_id,
          { capability: "communications.calls" },
        );
      const allowed =
        p.can_screen_share &&
        (authorized.actor.isCompanyOwner ||
          authorized.actor.permissions.capabilities[
            "communications.screenshare"
          ] === true);
      if (p.last_screen_share_allowed !== allowed) {
        await db.query(
          "UPDATE comms_call_participants SET last_screen_share_allowed=$3 WHERE call_id=$1 AND user_id=$2",
          [c.id, p.user_id, allowed],
        );
        if (p.state === "joined")
          await job(db, c, "restrict", {
            identity: p.identity,
            canScreenShare: allowed,
          });
      }
      return true;
    } catch (error) {
      if (![400, 403, 404].includes(error.status)) throw error;
      await db.query(
        "UPDATE comms_call_participants SET state='removed',removed_at=now(),left_at=now(),participant_seconds=participant_seconds+CASE WHEN state='joined' THEN greatest(0,extract(epoch from now()-joined_at))::bigint ELSE 0 END WHERE call_id=$1 AND user_id=$2",
        [c.id, p.user_id],
      );
      if (c.meeting_id)
        await db.query(
          "UPDATE conversation_participants SET left_at=now() WHERE conversation_id=$1 AND user_id=$2",
          [c.conversation_id, p.user_id],
        );
      await job(db, c, "remove", { identity: p.identity });
      return false;
    }
  };
  const service = {
    async presence(a, ids) {
      if (!Array.isArray(ids) || ids.length > 50)
        fail(400, "invalid_presence_scope");
      return transaction(async (db) => {
        const current = await loadActor(db, a);
        requireCapability(current);
        const rooms = [];
        let budget = 100;
        for (const conversation of [...new Set(ids.map(String))]) {
          try {
            await authorize(db, current, conversation);
          } catch (error) {
            if ([400, 403, 404].includes(error.status)) continue;
            throw error;
          }
          const call = (
            await db.query(
              "SELECT * FROM comms_call_sessions WHERE conversation_id=$1 AND company_id=$2 AND kind='huddle' AND ended_at IS NULL ORDER BY created_at DESC LIMIT 1",
              [conversation, current.companyId],
            )
          ).rows[0];
          if (!call) continue;
          const participants = [];
          const observed = (
            await db.query(
              "SELECT p.user_id,u.display_name,to_jsonb(u)->>'photo_url' AS photo_url FROM comms_call_participants p JOIN users u ON u.id=p.user_id AND u.company_id=$2 AND u.deleted_at IS NULL WHERE p.call_id=$1 AND p.state='joined' ORDER BY p.joined_at,p.user_id LIMIT $3",
              [call.id, current.companyId, Math.min(24, budget)],
            )
          ).rows;
          budget -= observed.length;
          for (const person of observed)
            try {
              await eligibleUser(db, current, person.user_id, conversation);
              participants.push(person);
            } catch (error) {
              if (![400, 403, 404].includes(error.status)) throw error;
            }
          rooms.push({
            conversation_id: conversation,
            call_id: call.id,
            participants,
          });
        }
        return { rooms };
      });
    },
    async context(a, id) {
      const c = await authorize(pool, a, id);
      let recipient = null;
      if (c.scope === "dm" && !c.is_group) {
        const members = (
          await pool.query(
            "SELECT user_id FROM conversation_participants WHERE conversation_id=$1 AND user_id<>$2 AND left_at IS NULL",
            [id, a.userId],
          )
        ).rows;
        if (members.length === 1) {
          await eligibleUser(pool, a, members[0].user_id, id);
          recipient = members[0].user_id;
        }
      }
      return {
        conversation_id: id,
        kind: recipient ? "direct" : "huddle",
        recipient_id: recipient,
      };
    },
    actorFor,
    async diagnostics(a) {
      requireCapability(a);
      return {
        calling_configured: provider.configured,
        captions_configured: service.captions?.configured === true,
        recording_configured:
          provider.recordingConfigured && Boolean(adoptRecording),
        apns_configured: Boolean(sendIncomingCall),
        transcription_configured: provider.transcriptionConfigured === true,
        ai_configured: provider.aiConfigured === true,
        guests_configured: service.guests?.configured === true,
        screen_share_requires_extension: true,
        token_ttl_seconds: 120,
      };
    },
    async ownerDiagnostics(a, { device_id } = {}) {
      a = await loadActor(pool, a);
      if (!a.isCompanyOwner) fail(403, "owner_required");
      const result = await service.diagnostics(a);
      if (device_id !== undefined)
        result.voip_device_registered = Boolean(
          (
            await pool.query(
              "SELECT 1 FROM comms_voip_devices WHERE user_id=$1 AND device_id=$2",
              [a.userId, uuid(device_id)],
            )
          ).rowCount,
        );
      return result;
    },
    async getSettings(a) {
      requireCapability(a);
      if (!a.isCompanyOwner) fail(403, "owner_required");
      return transaction((db) => settings(db, a));
    },
    async updateSettings(a, b) {
      if (!a.isCompanyOwner) fail(403, "owner_required");
      const changes = settingsInput(b);
      return transaction(async (db) => {
        const current = await settings(db, a);
        if (b.expected_version !== current.version) fail(409, "stale_settings");
        if (changes.guests_enabled === true && !service.guests?.configured)
          fail(
            409,
            "guest_join_not_configured",
            "Guest joining is not configured.",
          );
        const keys = Object.keys(changes);
        if (!keys.length) return current;
        const values = keys.map((k) => changes[k]);
        const r = (
          await db.query(
            `UPDATE comms_call_settings SET ${keys.map((k, i) => `${k}=$${i + 2}`).join(",")},version=version+1 WHERE company_id=$1 RETURNING *`,
            [a.companyId, ...values],
          )
        ).rows[0];
        await audit(db, a, null, "settings.updated");
        return r;
      });
    },
    async usage(a) {
      return transaction((db) =>
        readCallUsage(db, a, settings, effectiveUsage),
      );
    },
    async list(a, { conversation_id, before, q, filter = "all" } = {}) {
      a = await loadActor(pool, a);
      requireCapability(a);
      const after = cursor(before);
      if (after) uuid(after.id);
      if (!["all", "active", "missed", "recorded"].includes(filter)) fail(400, "invalid_call_filter");
      if (conversation_id) await authorize(pool, a, conversation_id);
      const recordingPredicate = "EXISTS(SELECT 1 FROM comms_call_recordings cr WHERE cr.call_id=cs.id AND cr.status='ready' AND cr.asset_id IS NOT NULL)";
      const filterPredicate = filter === "active" ? "cs.status NOT IN('ended','canceled','declined','missed','failed')" : filter === "missed" ? "cs.status='missed' AND p.user_id=$1" : filter === "recorded" ? recordingPredicate : "true";
      const rows = (await pool.query(
        `SELECT cs.*,cs.created_at::text AS cursor_created_at,p.state AS my_state,COALESCE(cm.title,c.title,initcap(cs.kind)) AS display_title,${recordingPredicate} AS has_recording FROM comms_call_sessions cs LEFT JOIN comms_meetings cm ON cm.id=cs.meeting_id JOIN conversations c ON c.id=cs.conversation_id ${conversationJoins} LEFT JOIN comms_call_participants p ON p.call_id=cs.id AND p.user_id=$1 WHERE ${conversationAccessSQL(a)} AND ${callReadSQL(a)} AND ${filterPredicate} AND (p.state IS NULL OR p.state<>'removed') AND ($3::text IS NULL OR cs.conversation_id=$3) AND ($4::timestamptz IS NULL OR (cs.created_at,cs.id)<($4::timestamptz,$5::uuid)) AND ($6='' OR strpos(lower(COALESCE(cm.title,c.title,'')||' '||cs.kind||' '||cs.status),$6)>0) ORDER BY cs.created_at DESC,cs.id DESC LIMIT 101`,
        [a.userId,a.companyId,conversation_id || null,after?.at || null,after?.id || null,text(q,160).toLowerCase()],
      )).rows;
      const page = rows.slice(0,100), authorizedRows = [];
      for (const item of page) {
        try { await row(pool,a,item.id,false); const {cursor_created_at,...value} = item; authorizedRows.push(safeCall(value)); }
        catch (error) { if (![400,403,404].includes(error.status)) throw error; }
      }
      return { calls: authorizedRows, next_cursor: rows.length > 100 ? encodeCursor(page.at(-1)) : null };
    },
    async get(a, id) {
      return transaction(async (db) => {
        const { c, p } = await row(db, a, id);
        const participants = (
          await db.query(
            `SELECT p.user_id,p.state,p.can_screen_share,p.recording_consent,p.joined_at,p.left_at,p.hand_raised_at,CASE WHEN p.reaction_expires_at>now() THEN p.reaction END AS reaction,u.display_name FROM comms_call_participants p JOIN users u ON u.id=p.user_id AND u.company_id=$2 AND u.deleted_at IS NULL WHERE p.call_id=$1`,
            [c.id, a.companyId],
          )
        ).rows;
        const me = participants.find((p) => p.user_id === a.userId);
        if (me)
          me.can_screen_share =
            me.can_screen_share &&
            (a.isCompanyOwner ||
              a.permissions?.capabilities?.["communications.screenshare"] ===
                true);
        let canReadRecordings = true;
        try {
          await authorize(db, a, c.conversation_id);
        } catch (error) {
          if (![400, 403, 404].includes(error.status)) throw error;
          canReadRecordings = false;
        }
        return {
          ...safeCall(c),
          participants,
          recordings: canReadRecordings
            ? (
                await db.query(
                  "SELECT * FROM comms_call_recordings WHERE call_id=$1 ORDER BY created_at DESC",
                  [c.id],
                )
              ).rows.map(sanitizeRecording)
            : [],
          my_state: p?.state,
        };
      });
    },
    async recordingMetadata(a, id) {
      return transaction(async (db) => {
        const recording = (
          await db.query(
            "SELECT * FROM comms_call_recordings WHERE id=$1 AND company_id=$2",
            [uuid(id), a.companyId],
          )
        ).rows[0];
        if (!recording) fail(404, "recording_unavailable");
        const { c } = await row(db, a, recording.call_id, false);
        await authorize(db, a, c.conversation_id);
        return sanitizeRecording(recording);
      });
    },
    async create(a, b) {
      if (!provider.configured)
        fail(503, "calling_not_configured", "Calling is not configured.");
      const id = uuid(b.id),
        conversationId = String(b.conversation_id || "");
      if (!["direct", "huddle", "meeting"].includes(b.kind))
        fail(400, "invalid_call_kind");
      const kind = b.kind;
      const media = b.media === "video" ? "video" : "audio";
      return transaction(async (db) => {
        await authorize(db, a, conversationId, true);
        let meeting = null;
        if (b.meeting_id) {
          meeting = (
            await db.query(
              "SELECT * FROM comms_meetings WHERE id=$1 AND company_id=$2 FOR UPDATE",
              [uuid(b.meeting_id), a.companyId],
            )
          ).rows[0];
          if (
            !meeting ||
            meeting.host_user_id !== a.userId ||
            meeting.status !== "scheduled" ||
            meeting.conversation_id !== conversationId ||
            kind !== "meeting"
          )
            fail(403, "meeting_host_required");
        }
        const s = await settings(db, a);
        await ensureBudget(db, a, s);
        const old = (
          await db.query("SELECT * FROM comms_call_sessions WHERE id=$1", [id])
        ).rows[0];
        if (old) {
          if (
            old.company_id !== a.companyId ||
            old.creator_user_id !== a.userId ||
            old.conversation_id !== conversationId
          )
            fail(409, "idempotency_conflict");
          return safeCall(old);
        }
        if (!Array.isArray(b.invitee_ids || [])) fail(400, "invalid_invitees");
        const users = [...new Set((b.invitee_ids || []).map(uuid))].filter(
          (x) => x !== a.userId,
        );
        if (users.length > s.max_participants - 1) fail(400, "room_capacity");
        if (kind === "direct" && users.length !== 1)
          fail(400, "direct_requires_one_recipient");
        for (const user of users)
          await eligibleUser(db, a, user, conversationId);
        if (meeting) {
          const prior = (
            await db.query(
              "SELECT * FROM comms_call_sessions WHERE meeting_id=$1 AND ended_at IS NULL",
              [meeting.id],
            )
          ).rows[0];
          if (prior) return safeCall(prior);
        }
        const pair =
          kind === "direct" ? [a.userId, ...users].sort().join(":") : null;
        const existing = (
          await db.query(
            `SELECT * FROM comms_call_sessions WHERE company_id=$1 AND ended_at IS NULL AND (($2::text IS NOT NULL AND pair_key=$2) OR ($3='huddle' AND kind='huddle' AND conversation_id=$4))`,
            [a.companyId, pair, kind, conversationId],
          )
        ).rows[0];
        if (existing) return safeCall(existing);
        const busy = (
          await db.query(
            `SELECT p.user_id FROM comms_call_participants p JOIN comms_call_sessions c ON c.id=p.call_id WHERE p.user_id=ANY($1::uuid[]) AND c.ended_at IS NULL AND p.state IN('accepted','admitted','joined')`,
            [[a.userId, ...users]],
          )
        ).rows;
        if (busy.length) fail(409, "participant_busy");
        const c = (
          await db.query(
            `INSERT INTO comms_call_sessions(id,company_id,conversation_id,creator_user_id,host_user_id,kind,media,room_name,pair_key,status,waiting_room) VALUES($1,$2,$3,$4,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
            [
              id,
              a.companyId,
              conversationId,
              a.userId,
              kind,
              media,
              "w_" + randomUUID().replaceAll("-", ""),
              pair,
              kind === "direct" ? "ringing" : "connecting",
              kind === "meeting" && b.waiting_room !== false,
            ],
          )
        ).rows[0];
        if (meeting) {
          await db.query(
            "UPDATE comms_call_sessions SET meeting_id=$2 WHERE id=$1",
            [c.id, meeting.id],
          );
          c.meeting_id = meeting.id;
        }
        await joinParticipant(db, a, c);
        for (const user of users)
          await joinParticipant(db, { ...a, userId: user }, c, "invited");
        await job(db, c, "create_room", { capacity: s.max_participants });
        if (kind === "direct") await job(db, c, "invite");
        await event(db, a, c, "call.created");
        return safeCall(c);
      });
    },
    async accept(a, id, b = {}) {
      return transaction(async (db) => {
        const { c, p } = await row(db, a, id);
        ensureActive(c);
        if (!p || p.state === "removed") fail(403, "invitation_required");
        if (
          c.kind === "direct" &&
          p.state === "invited" &&
          Date.now() > new Date(c.expires_at).getTime()
        )
          fail(409, "invitation_expired");
        const device = uuid(b.device_id);
        if (
          p.device_id &&
          p.device_id !== device &&
          ["accepted", "admitted", "joined"].includes(p.state)
        )
          fail(409, "answered_on_another_device");
        await db.query(
          "UPDATE comms_call_participants SET state='accepted',device_id=$3 WHERE call_id=$1 AND user_id=$2",
          [c.id, a.userId, device],
        );
        await db.query(
          "UPDATE comms_call_sessions SET status=CASE WHEN status='ringing' THEN 'connecting' ELSE status END,version=version+1 WHERE id=$1",
          [c.id],
        );
        await event(db, a, c, "call.accepted");
        return { accepted: true, call_id: c.id };
      });
    },
    async join(a, id, b = {}) {
      return transaction(async (db) => {
        const { c, p: existing } = await row(db, a, id);
        ensureActive(c);
        const s = await settings(db, a);
        await ensureBudget(db, a, s);
        if (
          c.locked &&
          a.userId !== c.host_user_id &&
          existing?.state !== "joined"
        )
          fail(403, "meeting_locked");
        if (
          c.kind === "direct" &&
          !["accepted", "joined"].includes(existing?.state)
        )
          fail(403, "accept_required");
        const p =
          existing ||
          (await joinParticipant(
            db,
            a,
            c,
            c.waiting_room && a.userId !== c.host_user_id
              ? "waiting"
              : "accepted",
          ));
        if (p.state === "declined") fail(403, "invitation_declined");
        if (
          c.waiting_room &&
          a.userId !== c.host_user_id &&
          !["admitted", "joined"].includes(p.state)
        ) {
          await db.query(
            "UPDATE comms_call_participants SET state='waiting' WHERE call_id=$1 AND user_id=$2",
            [c.id, a.userId],
          );
          await event(db, a, c, "call.waiting");
          return { waiting: true, call_id: c.id };
        }
        const recording = (
          await db.query(
            "SELECT id FROM comms_call_recordings WHERE call_id=$1 AND status IN('starting','recording','stopping')",
            [c.id],
          )
        ).rows[0];
        if (recording && !p.recording_consent)
          fail(409, "recording_consent_required");
        const busy = (
          await db.query(
            `SELECT p.call_id FROM comms_call_participants p JOIN comms_call_sessions c ON c.id=p.call_id WHERE p.user_id=$1 AND c.ended_at IS NULL AND p.call_id<>$2 AND p.state IN('accepted','admitted','joined')`,
            [a.userId, c.id],
          )
        ).rows;
        if (busy.length) fail(409, "participant_busy");
        const occupied = Number(
          (
            await db.query(
              "SELECT count(*) FROM comms_call_participants WHERE call_id=$1 AND state IN('accepted','admitted','joined') AND user_id<>$2",
              [c.id, a.userId],
            )
          ).rows[0].count,
        );
        if (
          occupied +
            (service.guests ? await service.guests.occupied(db, c.id) : 0) >=
          s.max_participants
        )
          fail(409, "room_capacity");
        if (["left", "invited"].includes(p.state)) {
          await db.query(
            "UPDATE comms_call_participants SET state='accepted',left_at=NULL WHERE call_id=$1 AND user_id=$2",
            [c.id, a.userId],
          );
          p.state = "accepted";
        }
        await provider.create(c, s.max_participants);
        const shareAllowed =
          p.can_screen_share &&
          (a.isCompanyOwner ||
            a.permissions?.capabilities?.["communications.screenshare"] ===
              true);
        if (c.meeting_id && !c.waiting_room && a.userId !== c.host_user_id)
          await db.query(
            "INSERT INTO conversation_participants(id,conversation_id,user_id,history_from) VALUES($1,$2,$3,now()) ON CONFLICT(conversation_id,user_id) DO UPDATE SET left_at=NULL",
            [randomUUID(), c.conversation_id, a.userId],
          );
        await db.query(
          "UPDATE comms_call_participants SET last_screen_share_allowed=$3 WHERE call_id=$1 AND user_id=$2",
          [c.id, a.userId, shareAllowed],
        );
        const connection = await provider.token(c, {
          ...p,
          display_name: a.displayName,
          can_screen_share: shareAllowed,
        });
        await event(db, a, c, "call.join_authorized");
        return {
          ...connection,
          call_id: c.id,
          identity: p.identity,
          waiting: false,
          screen_share_allowed: shareAllowed,
        };
      });
    },
    async inviteCandidates(a, id) {
      return transaction(async (db) => {
        const { c } = await row(db, a, id);
        ensureActive(c);
        host(a, c);
        if (c.kind === "direct") return { members: [] };
        const source = await eligibilityConversation(db, c),
          members = [];
        const candidates = (
          await db.query(
            "SELECT id,display_name FROM users WHERE company_id=$1 AND deleted_at IS NULL AND id<>$2 ORDER BY display_name,id LIMIT 100",
            [a.companyId, a.userId],
          )
        ).rows;
        for (const candidate of candidates)
          try {
            await eligibleUser(db, a, candidate.id, source);
            const prior = (
              await db.query(
                "SELECT state FROM comms_call_participants WHERE call_id=$1 AND user_id=$2",
                [c.id, candidate.id],
              )
            ).rows[0];
            if (!prior || ["left", "declined"].includes(prior.state))
              members.push(candidate);
          } catch (error) {
            if (![400, 403, 404].includes(error.status)) throw error;
          }
        return { members };
      });
    },
    async action(a, id, action, b = {}) {
      return transaction(async (db) => {
        const { c, p } = await row(db, a, id);
        if (terminal(c.status)) return safeCall(c);
        if (action === "end") {
          host(a, c);
          await audit(db, a, c, "call.ended");
          return finish(db, a, c, "ended", "host_ended");
        }
        if (action === "decline") {
          if (!p || p.state !== "invited") fail(409, "invitation_not_ringing");
          await db.query(
            "UPDATE comms_call_participants SET state='declined',left_at=now() WHERE call_id=$1 AND user_id=$2",
            [c.id, a.userId],
          );
          return c.kind === "direct"
            ? finish(db, a, c, "declined", "declined")
            : safeCall(c);
        }
        if (action === "leave") {
          if (p) {
            await db.query(
              "UPDATE comms_call_participants SET participant_seconds=participant_seconds+CASE WHEN state='joined' THEN greatest(0,extract(epoch from now()-joined_at))::bigint ELSE 0 END,state='left',left_at=now() WHERE call_id=$1 AND user_id=$2",
              [c.id, a.userId],
            );
            await job(db, c, "remove", { identity: p.identity });
          }
          if (c.kind === "direct")
            return finish(
              db,
              a,
              c,
              c.status === "ringing" ? "canceled" : "ended",
              "left",
            );
          await event(db, a, c, "call.left");
          return safeCall(c);
        }
        if (["hand", "reaction"].includes(action)) {
          if (!p || !["joined", "accepted", "admitted"].includes(p.state))
            fail(403, "active_participant_required");
          await authorize(db, a, c.conversation_id);
          if (action === "hand")
            await db.query(
              "UPDATE comms_call_participants SET hand_raised_at=CASE WHEN $3 THEN now() ELSE NULL END WHERE call_id=$1 AND user_id=$2",
              [c.id, a.userId, b.allowed === true],
            );
          else {
            if (!["👍", "👏", "❤️", "🎉", "😂"].includes(b.reaction))
              fail(400, "unsupported_reaction");
            await db.query(
              "UPDATE comms_call_participants SET reaction=$3,reaction_expires_at=now()+interval '8 seconds' WHERE call_id=$1 AND user_id=$2",
              [c.id, a.userId, b.reaction],
            );
          }
          await event(db, a, c, "call.signal");
          return { ok: true };
        }
        host(a, c);
        if (action === "invite") {
          if (c.kind === "direct") fail(409, "start_huddle_for_more_people");
          const target = uuid(b.user_id),
            source = await eligibilityConversation(db, c);
          await eligibleUser(db, a, target, source);
          const policy = await settings(db, a);
          await ensureBudget(db, a, policy);
          if (
            (
              await db.query(
                "SELECT 1 FROM comms_presence WHERE user_id=$1 AND availability='dnd' AND expires_at>now()",
                [target],
              )
            ).rowCount
          )
            fail(409, "participant_do_not_disturb");
          if (
            (
              await db.query(
                "SELECT 1 FROM comms_call_participants p JOIN comms_call_sessions cs ON cs.id=p.call_id WHERE p.user_id=$1 AND p.call_id<>$2 AND cs.ended_at IS NULL AND p.state IN('accepted','admitted','joined')",
                [target, c.id],
              )
            ).rowCount
          )
            fail(409, "participant_busy");
          const prior = (
            await db.query(
              "SELECT * FROM comms_call_participants WHERE call_id=$1 AND user_id=$2",
              [c.id, target],
            )
          ).rows[0];
          if (prior?.state === "removed") fail(403, "call_removed");
          if (prior && !["left", "declined"].includes(prior.state))
            return { ok: true };
          if (c.meeting_id)
            await db.query(
              "INSERT INTO comms_meeting_attendees(meeting_id,user_id) VALUES($1,$2) ON CONFLICT(meeting_id,user_id) DO UPDATE SET rsvp='invited'",
              [c.meeting_id, target],
            );
          if (prior)
            await db.query(
              "UPDATE comms_call_participants SET state='invited',device_id=NULL WHERE call_id=$1 AND user_id=$2",
              [c.id, target],
            );
          else
            await joinParticipant(db, { ...a, userId: target }, c, "invited");
          await job(db, c, "invite", {
            user_id: target,
            expires_at: new Date(Date.now() + 45000).toISOString(),
          });
          await audit(db, a, c, "participant.invited", target);
          await event(db, a, c, "call.invited");
          return { ok: true };
        }
        if (action === "transfer-host") {
          const target = uuid(b.user_id);
          const next = (
            await db.query(
              "SELECT * FROM comms_call_participants WHERE call_id=$1 AND user_id=$2 AND state IN('admitted','joined','accepted')",
              [c.id, target],
            )
          ).rows[0];
          if (!next) fail(409, "host_must_participate");
          await eligibleUser(
            db,
            a,
            target,
            await eligibilityConversation(db, c),
          );
          await db.query(
            "UPDATE comms_call_sessions SET host_user_id=$2,version=version+1 WHERE id=$1",
            [c.id, target],
          );
          await audit(db, a, c, "host.transferred", target);
          await event(db, a, c, "call.updated");
          return { ok: true };
        }
        if (action === "lock") {
          await db.query(
            "UPDATE comms_call_sessions SET locked=$2,version=version+1 WHERE id=$1",
            [c.id, b.locked === true],
          );
          await event(db, a, c, "call.updated");
          return { ok: true };
        }
        const target = uuid(b.user_id);
        const participant = (
          await db.query(
            "SELECT * FROM comms_call_participants WHERE call_id=$1 AND user_id=$2",
            [c.id, target],
          )
        ).rows[0];
        if (!participant) fail(404, "participant_unavailable");
        if (action === "admit") {
          await eligibleUser(
            db,
            a,
            target,
            await eligibilityConversation(db, c),
          );
          if (participant.state !== "waiting") fail(409, "not_waiting");
          const policy = await settings(db, a);
          const reserved =
            Number(
              (
                await db.query(
                  "SELECT count(*) FROM comms_call_participants WHERE call_id=$1 AND state IN('accepted','admitted','joined')",
                  [c.id],
                )
              ).rows[0].count,
            ) + (service.guests ? await service.guests.occupied(db, c.id) : 0);
          if (reserved >= policy.max_participants) fail(409, "room_capacity");
          if (c.meeting_id)
            await db.query(
              "INSERT INTO conversation_participants(id,conversation_id,user_id,history_from) VALUES($1,$2,$3,now()) ON CONFLICT(conversation_id,user_id) DO UPDATE SET left_at=NULL,history_from=greatest(conversation_participants.history_from,now())",
              [randomUUID(), c.conversation_id, target],
            );
          await db.query(
            "UPDATE comms_call_participants SET state='admitted' WHERE call_id=$1 AND user_id=$2",
            [c.id, target],
          );
        } else if (action === "remove") {
          if (target === c.host_user_id) fail(409, "host_cannot_remove_self");
          await db.query(
            "UPDATE comms_call_participants SET state='removed',removed_at=now(),left_at=now(),participant_seconds=participant_seconds+CASE WHEN state='joined' THEN greatest(0,extract(epoch from now()-joined_at))::bigint ELSE 0 END WHERE call_id=$1 AND user_id=$2",
            [c.id, target],
          );
          if (c.meeting_id)
            await db.query(
              "UPDATE conversation_participants SET left_at=now() WHERE conversation_id=$1 AND user_id=$2",
              [c.conversation_id, target],
            );
          await job(db, c, "remove", { identity: participant.identity });
        } else if (action === "screen-permission") {
          if (b.allowed === true)
            await authorizeConversation(
              db,
              { userId: target, companyId: a.companyId },
              await eligibilityConversation(db, c),
              { capability: "communications.screenshare" },
            );
          await db.query(
            "UPDATE comms_call_participants SET can_screen_share=$3 WHERE call_id=$1 AND user_id=$2",
            [c.id, target, b.allowed === true],
          );
          await job(db, c, "restrict", {
            identity: participant.identity,
            canScreenShare: b.allowed === true,
          });
        } else if (action === "mute") {
          await job(db, c, "mute", { identity: participant.identity });
        } else fail(400, "invalid_action");
        await audit(db, a, c, "participant." + action, target);
        await event(db, a, c, "call.participant_updated");
        return { ok: true };
      });
    },
    async consent(a, id, b) {
      return transaction(async (db) => {
        const { c, p } = await row(db, a, id);
        ensureActive(c);
        if (!p || ["removed", "declined", "left"].includes(p.state))
          fail(403, "participant_required");
        if (typeof b.consented !== "boolean") fail(400, "consent_required");
        await db.query(
          "UPDATE comms_call_participants SET recording_consent=$3 WHERE call_id=$1 AND user_id=$2",
          [c.id, a.userId, b.consented],
        );
        await db.query(
          "INSERT INTO comms_call_consents(call_id,user_id,consented) VALUES($1,$2,$3)",
          [c.id, a.userId, b.consented],
        );
        if (!b.consented) {
          await db.query(
            "UPDATE comms_call_recordings SET status=CASE WHEN status='consent' THEN 'failed' ELSE 'stopping' END,error_code='consent_withdrawn' WHERE call_id=$1 AND status IN('consent','starting','recording')",
            [c.id],
          );
          await job(db, c, "stop_recordings");
        }
        await audit(
          db,
          a,
          c,
          b.consented ? "recording.consent" : "recording.refused",
        );
        if (b.consented) {
          const pending = (
            await db.query(
              "SELECT id FROM comms_call_recordings WHERE call_id=$1 AND status='consent' FOR UPDATE",
              [c.id],
            )
          ).rows[0];
          const missing = (
            await db.query(
              "SELECT 1 FROM comms_call_participants WHERE call_id=$1 AND state IN('joined','accepted','admitted') AND NOT recording_consent LIMIT 1",
              [c.id],
            )
          ).rows;
          if (pending && !missing.length) {
            await db.query(
              "UPDATE comms_call_recordings SET status='starting' WHERE id=$1",
              [pending.id],
            );
            await job(db, c, "start_recording", { id: pending.id });
          }
        }
        await event(db, a, c, "call.recording_consent");
        return { ok: true };
      });
    },
    async recording(a, id, b) {
      return transaction(async (db) => {
        const { c } = await row(db, a, id);
        requireCapability(a, "communications.record");
        host(a, c);
        ensureActive(c);
        const s = await settings(db, a);
        if (!s.recording_enabled) fail(403, "recording_disabled");
        if (!provider.recordingConfigured || !adoptRecording)
          fail(503, "recording_storage_unavailable");
        if (service.guests && (await service.guests.recordingBlocked(db, c.id)))
          fail(
            409,
            "guest_recording_disabled",
            "Recording is unavailable while external guests participate.",
          );
        const active = (
          await db.query(
            "SELECT * FROM comms_call_recordings WHERE call_id=$1 AND status IN('consent','starting','recording','stopping','processing') FOR UPDATE",
            [c.id],
          )
        ).rows[0];
        if (b.action === "stop") {
          if (active) {
            await db.query(
              "UPDATE comms_call_recordings SET status=CASE WHEN status='consent' THEN 'failed' ELSE 'stopping' END WHERE id=$1",
              [active.id],
            );
            await job(db, c, "stop_recordings");
          }
          return { ok: true };
        }
        if (active && active.status !== "consent")
          return sanitizeRecording(active);
        const recordId = active?.id || uuid(b.id);
        if (
          !active &&
          (await db.query("SELECT 1 FROM stored_files WHERE id=$1", [recordId]))
            .rowCount
        )
          fail(409, "recording_asset_conflict");
        if (!active)
          await db.query(
            "UPDATE comms_call_participants SET recording_consent=false WHERE call_id=$1",
            [c.id],
          );
        const recording =
          active ||
          (
            await db.query(
              "INSERT INTO comms_call_recordings(id,call_id,company_id,requested_by,object_key,media) VALUES($1,$2,$3,$4,$5,$6) RETURNING *",
              [
                recordId,
                c.id,
                a.companyId,
                a.userId,
                `storage/comms/${a.companyId}/${recordId}.${b.media === "audio" ? "ogg" : "mp4"}`,
                b.media === "audio" ? "audio" : "video",
              ],
            )
          ).rows[0];
        const missing = (
          await db.query(
            "SELECT user_id FROM comms_call_participants WHERE call_id=$1 AND state IN('joined','accepted','admitted') AND NOT recording_consent",
            [c.id],
          )
        ).rows;
        if (missing.length) {
          await event(db, a, c, "call.recording_consent_requested");
          return {
            ...sanitizeRecording(recording),
            needs_consent: missing.map((x) => x.user_id),
          };
        }
        await db.query(
          "UPDATE comms_call_recordings SET status='starting' WHERE id=$1",
          [recordId],
        );
        await job(db, c, "start_recording", { id: recordId });
        await audit(db, a, c, "recording.requested");
        await event(db, a, c, "call.recording_updated");
        return { ...sanitizeRecording(recording), status: "starting" };
      });
    },
    async registerDevice(a, b) {
      requireCapability(a);
      if (!["production", "sandbox"].includes(b.environment))
        fail(400, "invalid_environment");
      await pool.query(
        "DELETE FROM comms_voip_devices WHERE token=$1 AND user_id<>$2",
        [b.token, a.userId],
      );
      if (!/^[a-f0-9]{32,512}$/i.test(b.token || ""))
        fail(400, "invalid_device_token");
      await pool.query(
        "INSERT INTO comms_voip_devices(user_id,device_id,token,environment) VALUES($1,$2,$3,$4) ON CONFLICT(user_id,device_id) DO UPDATE SET token=excluded.token,environment=excluded.environment,updated_at=now()",
        [
          a.userId,
          uuid(b.device_id),
          b.token,
          b.environment === "production" ? "production" : "sandbox",
        ],
      );
      return { ok: true };
    },
    async unregisterDevice(a, id) {
      await pool.query(
        "DELETE FROM comms_voip_devices WHERE user_id=$1 AND device_id=$2",
        [a.userId, uuid(id)],
      );
      return { ok: true };
    },
    async revokeUser(companyId, userId) {
      return transaction(async (db) => {
        const active = (
          await db.query(
            `SELECT c.* FROM comms_call_sessions c JOIN comms_call_participants p ON p.call_id=c.id WHERE c.company_id=$1 AND p.user_id=$2 AND c.ended_at IS NULL AND p.state NOT IN('left','declined','removed') FOR UPDATE OF c`,
            [companyId, userId],
          )
        ).rows;
        let removed = 0;
        for (const c of active) {
          const p = (
            await db.query(
              "SELECT * FROM comms_call_participants WHERE call_id=$1 AND user_id=$2",
              [c.id, userId],
            )
          ).rows[0];
          if (!(await reconcileParticipant(db, c, p))) removed++;
        }
        const current = await loadActor(db, { userId, companyId }).catch(
          () => null,
        );
        if (
          !current ||
          !current.permissions.capabilities["communications.calls"]
        )
          await db.query("DELETE FROM comms_voip_devices WHERE user_id=$1", [
            userId,
          ]);
        return { calls: active.length, removed };
      });
    },
    async meetings(a, { from, to, id, q } = {}) {
      a = await loadActor(pool, a);
      requireCapability(a);
      const meetingID = id === undefined ? null : uuid(id);
      const range = from !== undefined || to !== undefined;
      const start = range ? new Date(from) : null,
        end = range ? new Date(to) : null;
      if (
        range &&
        (!Number.isFinite(+start) ||
          !Number.isFinite(+end) ||
          end <= start ||
          end - start > 370 * 86400000)
      )
        fail(400, "invalid_meeting_range");
      const candidates = (
        await pool.query(
          `SELECT m.*,(SELECT json_agg(ma.user_id ORDER BY ma.user_id) FROM comms_meeting_attendees ma WHERE ma.meeting_id=m.id) AS attendee_ids,(SELECT ma.rsvp FROM comms_meeting_attendees ma WHERE ma.meeting_id=m.id AND ma.user_id=$1) AS my_rsvp FROM comms_meetings m JOIN conversations c ON c.id=COALESCE(m.source_conversation_id,m.conversation_id) ${conversationJoins} WHERE ${conversationAccessSQL(a)} AND (m.host_user_id=$1 OR EXISTS(SELECT 1 FROM comms_meeting_attendees ma WHERE ma.meeting_id=m.id AND ma.user_id=$1)) AND ($5::uuid IS NULL OR m.id=$5) AND ($6='' OR strpos(lower(m.title||' '||m.agenda),$6)>0) AND ($3::timestamptz IS NULL OR (m.starts_at<$4 AND m.starts_at+m.duration_minutes*interval '1 minute'>$3)) ORDER BY m.starts_at ${range ? "ASC" : "DESC"},m.id LIMIT 101`,
          [a.userId, a.companyId, start, end, meetingID, text(q,160).toLowerCase()],
        )
      ).rows;
      const meetings = [];
      for (const meeting of candidates) {
        try {
          await authorize(
            pool,
            a,
            meeting.source_conversation_id || meeting.conversation_id,
          );
          meetings.push(meeting);
        } catch (error) {
          if (![400, 403, 404].includes(error.status)) throw error;
        }
      }
      return {
        meetings: meetings.slice(0, 100),
        has_more: candidates.length > 100,
      };
    },
    async meetingInvitees(a, { conversation_id, after_id } = {}) {
      return transaction(async (db) => {
        await authorize(db, a, conversation_id, true);
        const after = after_id ? uuid(after_id) : null;
        const rows = (await db.query(
          "SELECT id,display_name FROM users WHERE company_id=$1 AND deleted_at IS NULL AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT 101",
          [a.companyId, after],
        )).rows;
        const members = [];
        for (const user of rows.slice(0, 100)) {
          try {
            await eligibleUser(db, a, user.id, conversation_id);
            members.push(user);
          } catch (error) {
            if (![400, 403, 404].includes(error.status)) throw error;
          }
        }
        return { members, next_cursor: rows.length > 100 ? rows[99].id : null };
      });
    },
    async saveMeeting(a, b, id = null) {
      return transaction(async (db) => {
        const source = String(b.conversation_id || "");
        await authorize(db, a, source, true);
        const title = text(b.title);
        if (!title) fail(400, "meeting_title_required");
        const start = new Date(b.starts_at);
        if (
          !Number.isFinite(+start) ||
          !Number.isInteger(b.duration_minutes) ||
          b.duration_minutes < 5 ||
          b.duration_minutes > 1440
        )
          fail(400, "invalid_meeting_time");
        try {
          new Intl.DateTimeFormat("en", { timeZone: b.timezone });
        } catch {
          fail(400, "invalid_timezone");
        }
        if (!Array.isArray(b.attendee_ids || []))
          fail(400, "invalid_attendees");
        let requested = b.attendee_ids || [];
        if (!requested.length) {
          const candidates = (
            await db.query(
              "SELECT id FROM users WHERE company_id=$1 AND deleted_at IS NULL LIMIT 101",
              [a.companyId],
            )
          ).rows;
          requested = [];
          for (const u of candidates) {
            try {
              await eligibleUser(db, a, u.id, source);
              requested.push(u.id);
            } catch (e) {
              if (![400, 403, 404].includes(e.status)) throw e;
            }
          }
        }
        const users = [...new Set([a.userId, ...requested.map(uuid)])];
        if (users.length > 100) fail(400, "too_many_attendees");
        for (const u of users)
          if (u !== a.userId) await eligibleUser(db, a, u, source);
        const meetingId = uuid(id || b.id),
          old = (
            await db.query(
              "SELECT * FROM comms_meetings WHERE id=$1 FOR UPDATE",
              [meetingId],
            )
          ).rows[0];
        if (old) {
          if (
            old.company_id !== a.companyId ||
            old.host_user_id !== a.userId ||
            old.source_conversation_id !== source
          )
            fail(403, "host_required");
          if (!id) return old;
          if (old.version !== b.expected_version) fail(409, "stale_meeting");
        }
        const conversation =
          old?.conversation_id || "comms-meeting:" + meetingId;
        if (!old) {
          await db.query(
            "INSERT INTO conversations(id,company_id,title,is_group,created_by,scope,source_kind,source_id) VALUES($1,$2,$3,true,$4,'meeting','conversation',$5)",
            [conversation, a.companyId, title, a.userId, source],
          );
          await db.query(
            "INSERT INTO conversation_participants(id,conversation_id,user_id,history_from) VALUES($1,$2,$3,now())",
            [randomUUID(), conversation, a.userId],
          );
        }
        // Validate the newly linked target too: over-deep ancestry rolls back
        // the complete creation rather than persisting an unusable meeting.
        await authorize(db, a, conversation);
        const m = (
          await db.query(
            `INSERT INTO comms_meetings(id,company_id,conversation_id,source_conversation_id,host_user_id,title,agenda,starts_at,duration_minutes,timezone,waiting_room) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(id) DO UPDATE SET title=excluded.title,agenda=excluded.agenda,starts_at=excluded.starts_at,duration_minutes=excluded.duration_minutes,timezone=excluded.timezone,waiting_room=excluded.waiting_room,version=comms_meetings.version+1 RETURNING *`,
            [
              meetingId,
              a.companyId,
              conversation,
              source,
              a.userId,
              title,
              text(b.agenda, 5000),
              start,
              b.duration_minutes,
              b.timezone,
              b.waiting_room !== false,
            ],
          )
        ).rows[0];
        await db.query(
          "DELETE FROM comms_meeting_attendees WHERE meeting_id=$1 AND NOT(user_id=ANY($2::uuid[]))",
          [m.id, users],
        );
        for (const u of users)
          await db.query(
            "INSERT INTO comms_meeting_attendees(meeting_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING",
            [m.id, u],
          );
        await publish(db, a, source, "meeting.updated", m.id, {
          meeting_id: m.id,
        });
        await meetingDelivery?.changed(db, m);
        return m;
      });
    },
    async meetingAction(a, id, b) {
      return transaction(async (db) => {
        const m = (
          await db.query(
            "SELECT * FROM comms_meetings WHERE id=$1 AND company_id=$2 FOR UPDATE",
            [uuid(id), a.companyId],
          )
        ).rows[0];
        if (!m) fail(404, "meeting_unavailable");
        await authorize(db, a, m.source_conversation_id || m.conversation_id);
        if (b.action === "cancel") {
          if (m.host_user_id !== a.userId) fail(403, "host_required");
          await db.query(
            "UPDATE comms_meetings SET status='canceled',version=version+1 WHERE id=$1",
            [m.id],
          );
          const call = (
            await db.query(
              "SELECT * FROM comms_call_sessions WHERE meeting_id=$1 AND ended_at IS NULL FOR UPDATE",
              [m.id],
            )
          ).rows[0];
          if (call) await finish(db, a, call, "canceled", "meeting_canceled");
          await meetingDelivery?.changed(
            db,
            { ...m, version: m.version + 1, status: "canceled" },
            "canceled",
          );
        } else {
          if (!["accepted", "declined", "tentative"].includes(b.rsvp))
            fail(400, "invalid_rsvp");
          const r = await db.query(
            "UPDATE comms_meeting_attendees SET rsvp=$3 WHERE meeting_id=$1 AND user_id=$2",
            [m.id, a.userId, b.rsvp],
          );
          if (!r.rowCount) fail(403, "invitation_required");
        }
        await publish(
          db,
          a,
          m.source_conversation_id || m.conversation_id,
          "meeting.updated",
          m.id,
          { meeting_id: m.id },
        );
        return { ok: true };
      });
    },
    async joinMeeting(a, id) {
      const m = (
        await pool.query(
          "SELECT * FROM comms_meetings WHERE id=$1 AND company_id=$2",
          [uuid(id), a.companyId],
        )
      ).rows[0];
      if (!m || m.status !== "scheduled") fail(404, "meeting_unavailable");
      await authorize(pool, a, m.source_conversation_id || m.conversation_id);
      if (
        m.host_user_id !== a.userId &&
        !(
          await pool.query(
            "SELECT 1 FROM comms_meeting_attendees WHERE meeting_id=$1 AND user_id=$2 AND rsvp<>'declined'",
            [m.id, a.userId],
          )
        ).rowCount
      )
        fail(404, "meeting_unavailable");
      let c = (
        await pool.query(
          "SELECT * FROM comms_call_sessions WHERE meeting_id=$1 AND ended_at IS NULL",
          [m.id],
        )
      ).rows[0];
      if (!c) {
        if (m.host_user_id !== a.userId)
          fail(
            409,
            "host_start_required",
            "The host has not started this meeting.",
          );
        c = await service.create(a, {
          id: randomUUID(),
          conversation_id: m.conversation_id,
          kind: "meeting",
          media: "video",
          meeting_id: m.id,
          waiting_room: m.waiting_room,
          invitee_ids: [],
        });
      }
      return safeCall(c);
    },
    async webhook(body, authorization) {
      const e = await provider.webhook(body, authorization);
      if (!e.id || !e.event) fail(400, "invalid_provider_event");
      return transaction(async (db) => {
        const inserted = await db.query(
          "INSERT INTO comms_call_provider_events(id,event_type) VALUES($1,$2) ON CONFLICT DO NOTHING",
          [e.id, e.event],
        );
        if (!inserted.rowCount) return { ok: true, duplicate: true };
        const roomName = e.room?.name || e.egressInfo?.roomName;
        if (!roomName) return { ok: true };
        const c = (
          await db.query(
            "SELECT * FROM comms_call_sessions WHERE room_name=$1 FOR UPDATE",
            [roomName],
          )
        ).rows[0];
        if (!c) return { ok: true };
        const actor = { userId: c.host_user_id, companyId: c.company_id };
        if (e.event === "participant_joined" && e.participant?.identity) {
          const p = (
            await db.query(
              "SELECT * FROM comms_call_participants WHERE call_id=$1 AND identity=$2",
              [c.id, e.participant.identity],
            )
          ).rows[0];
          if (
            !p &&
            service.captions &&
            (await service.captions.acceptAgent(db, c, e.participant.identity))
          )
            return { ok: true };
          if (!p && service.guests) {
            try {
              if (await service.guests.joined(db, c, e.participant.identity))
                return { ok: true };
            } catch (error) {
              if (error.status !== 409) throw error;
            }
          }
          if (
            !p ||
            !["accepted", "admitted", "joined"].includes(p.state) ||
            terminal(c.status)
          ) {
            await job(db, c, "remove", { identity: e.participant.identity });
            return { ok: true };
          }
          try {
            await authorizeConversation(
              db,
              { userId: p.user_id, companyId: c.company_id },
              c.conversation_id,
              { capability: "communications.calls" },
            );
          } catch {
            await job(db, c, "remove", { identity: p.identity });
            return { ok: true };
          }
          await db.query(
            "UPDATE comms_call_participants SET state='joined',joined_at=CASE WHEN state='joined' THEN joined_at ELSE now() END,left_at=NULL WHERE call_id=$1 AND identity=$2",
            [c.id, p.identity],
          );
          await db.query(
            "UPDATE comms_call_sessions SET status='connected',connected_at=COALESCE(connected_at,now()),version=version+1 WHERE id=$1 AND ended_at IS NULL AND (kind<>'direct' OR (SELECT count(*) FROM comms_call_participants WHERE call_id=$1 AND state='joined')>=2)",
            [c.id],
          );
          await event(db, actor, c, "call.participant_joined");
        }
        if (e.event === "participant_left" && e.participant?.identity) {
          if (service.guests)
            await service.guests.left(db, c, e.participant.identity);
          await db.query(
            "UPDATE comms_call_participants SET participant_seconds=participant_seconds+greatest(0,extract(epoch from now()-joined_at))::bigint,state='left',left_at=now() WHERE call_id=$1 AND identity=$2 AND state='joined'",
            [c.id, e.participant.identity],
          );
          await event(db, actor, c, "call.participant_left");
        }
        if (e.event === "room_finished")
          await finish(db, actor, c, "ended", "room_finished");
        if (e.egressInfo) {
          const info = e.egressInfo;
          const recording = (
            await db.query(
              "SELECT * FROM comms_call_recordings WHERE egress_id=$1 FOR UPDATE",
              [info.egressId],
            )
          ).rows[0];
          if (recording)
            await observeRecording(db, c, recording, info, publish);
        }
        return { ok: true };
      });
    },
    async work() {
      await transaction(async (db) => {
        const j = (
          await db.query(
            "SELECT * FROM comms_call_jobs WHERE status='pending' AND available_at<=now() ORDER BY CASE WHEN kind IN('remove','close','restrict','stop_recordings') THEN 0 ELSE 1 END,available_at FOR UPDATE SKIP LOCKED LIMIT 1",
          )
        ).rows[0];
        if (!j) return;
        const c = (
          await db.query(
            "SELECT * FROM comms_call_sessions WHERE id=$1 FOR UPDATE",
            [j.call_id],
          )
        ).rows[0];
        await db.query("SAVEPOINT call_job");
        try {
          if (j.kind === "create_room" && !terminal(c.status))
            await provider.create(c, j.payload.capacity);
          if (j.kind === "close") await provider.close(c);
          if (j.kind === "remove") await provider.remove(c, j.payload.identity);
          if (j.kind === "restrict")
            await provider.restrict(c, j.payload.identity, {
              canPublish: true,
              canScreenShare: j.payload.canScreenShare,
            });
          if (j.kind === "mute") await provider.mute(c, j.payload.identity);
          if (
            j.kind === "invite" &&
            !terminal(c.status) &&
            ((c.kind === "direct" &&
              c.status === "ringing" &&
              new Date(c.expires_at) > new Date()) ||
              (c.kind !== "direct" &&
                j.payload.user_id &&
                new Date(j.payload.expires_at) > new Date())) &&
            sendIncomingCall
          ) {
            const recipients = (
              await db.query(
                "SELECT user_id FROM comms_call_participants WHERE call_id=$1 AND state='invited' AND ($2::uuid IS NULL OR user_id=$2)",
                [c.id, j.payload.user_id || null],
              )
            ).rows;
            for (const { user_id } of recipients) {
              try {
                const source = await eligibilityConversation(db, c);
                await authorizeConversation(
                  db,
                  { companyId: c.company_id, userId: c.host_user_id },
                  source,
                  { capability: "communications.calls" },
                );
                if (
                  (
                    await db.query(
                      "SELECT 1 FROM comms_presence WHERE user_id=$1 AND availability='dnd' AND expires_at>now()",
                      [user_id],
                    )
                  ).rowCount
                )
                  continue;
                await eligibleUser(
                  db,
                  { companyId: c.company_id, userId: c.host_user_id },
                  user_id,
                  source,
                );
              } catch (e) {
                if ([400, 403, 404].includes(e.status)) continue;
                throw e;
              }
              await sendIncomingCall(
                { ...c, expires_at: j.payload.expires_at || c.expires_at },
                user_id,
              );
            }
          }
          if (j.kind === "start_recording") {
            const r = (
              await db.query(
                "SELECT * FROM comms_call_recordings WHERE id=$1 FOR UPDATE",
                [j.payload.id],
              )
            ).rows[0];
            if (
              r.status === "starting" &&
              !terminal(c.status) &&
              !(await recordingAuthorized(db, c, r))
            ) {
              await db.query(
                "UPDATE comms_call_recordings SET status='stopping',error_code='recording_access_ended' WHERE id=$1",
                [r.id],
              );
              await job(db, c, "stop_recordings");
            } else if (r.status === "starting" && !terminal(c.status)) {
              const missing = (
                await db.query(
                  "SELECT 1 FROM comms_call_participants WHERE call_id=$1 AND state IN('joined','accepted','admitted') AND NOT recording_consent LIMIT 1",
                  [c.id],
                )
              ).rows;
              if (missing.length) {
                await db.query(
                  "UPDATE comms_call_recordings SET status='consent' WHERE id=$1",
                  [r.id],
                );
              } else {
                const info = await provider.record(c, r);
                await db.query(
                  "UPDATE comms_call_recordings SET egress_id=$2 WHERE id=$1",
                  [r.id, info.egressId],
                );
              }
            }
          }
          if (j.kind === "stop_recordings") {
            const recordings = (
              await db.query(
                "SELECT * FROM comms_call_recordings WHERE call_id=$1 AND status='stopping'",
                [c.id],
              )
            ).rows;
            for (const r of recordings) {
              let egressID = r.egress_id;
              if (!egressID && provider.findRecording)
                egressID = (await provider.findRecording(c, r))?.egressId;
              if (egressID) {
                await provider.stopRecording(egressID);
                await db.query(
                  "UPDATE comms_call_recordings SET egress_id=$2 WHERE id=$1",
                  [r.id, egressID],
                );
              } else
                await db.query(
                  "UPDATE comms_call_recordings SET status='failed',error_code='stopped_before_start' WHERE id=$1",
                  [r.id],
                );
            }
          }
          if (j.kind === "adopt_recording") {
            const r = (
              await db.query(
                "SELECT * FROM comms_call_recordings WHERE id=$1 FOR UPDATE",
                [j.payload.id],
              )
            ).rows[0];
            if (r.status === "processing" && adoptRecording) {
              const asset = await adoptRecording(db, c, r, j.payload);
              await db.query(
                "UPDATE comms_call_recordings SET status='ready',asset_id=$2,byte_size=$3,duration_seconds=$4 WHERE id=$1",
                [
                  r.id,
                  asset.id,
                  asset.byte_size,
                  Number(j.payload.duration) / 1e9,
                ],
              );
            }
          }
          await db.query(
            "UPDATE comms_call_jobs SET status='done',last_error=NULL WHERE id=$1",
            [j.id],
          );
        } catch (e) {
          await db.query("ROLLBACK TO SAVEPOINT call_job");
          await db.query(
            "UPDATE comms_call_jobs SET attempts=attempts+1,available_at=now()+least(300,power(2,least(attempts,8))*5)*interval '1 second',last_error=$2 WHERE id=$1",
            [j.id, String(e.code || "provider_unavailable").slice(0, 100)],
          );
        }
      });
    },
    async reconcileEgress() {
      if (!provider.recordings) return;
      const candidates = (
        await pool.query(
          "SELECT DISTINCT call_id FROM comms_call_recordings WHERE status IN('starting','recording','stopping','processing') AND (reconciled_at IS NULL OR reconciled_at<now()-interval '30 seconds') LIMIT 3",
        )
      ).rows;
      for (const candidate of candidates)
        await transaction(async (db) => {
          const c = (
            await db.query(
              "SELECT * FROM comms_call_sessions WHERE id=$1 FOR UPDATE SKIP LOCKED",
              [candidate.call_id],
            )
          ).rows[0];
          if (!c) return;
          const records = (
            await db.query(
              "SELECT * FROM comms_call_recordings WHERE call_id=$1 AND status IN('starting','recording','stopping','processing') FOR UPDATE",
              [c.id],
            )
          ).rows;
          if (!records.length) return;
          const observed = await provider.recordings(c).catch(() => null);
          await db.query(
            "UPDATE comms_call_recordings SET reconciled_at=now() WHERE id=ANY($1::uuid[])",
            [records.map((r) => r.id)],
          );
          if (!observed) return;
          const contains = (value, key) =>
            value === key ||
            (value &&
              typeof value === "object" &&
              Object.values(value).some((v) => contains(v, key)));
          for (const record of records) {
            const info = observed.find(
              (i) =>
                i.egressId === record.egress_id ||
                contains(i.toJson ? i.toJson() : i, record.object_key),
            );
            if (!info) continue;
            await db.query(
              "UPDATE comms_call_recordings SET egress_id=$2 WHERE id=$1",
              [record.id, info.egressId],
            );
            await observeRecording(db, c, record, info, publish);
          }
        });
    },
    async reconcile() {
      return transaction(async (db) => {
        const calls = (
          await db.query(
            "SELECT c.*,s.max_call_minutes,s.monthly_participant_minutes,s.enabled FROM comms_call_sessions c JOIN comms_call_settings s ON s.company_id=c.company_id WHERE c.ended_at IS NULL ORDER BY c.created_at LIMIT 100 FOR UPDATE OF c SKIP LOCKED",
          )
        ).rows;
        for (const c of calls) {
          await reconcileRecordings(db, c);
          const actor = { companyId: c.company_id, userId: c.host_user_id };
          const participants = (
            await db.query(
              "SELECT * FROM comms_call_participants WHERE call_id=$1 AND state NOT IN('left','declined','removed')",
              [c.id],
            )
          ).rows;
          const eligible = [];
          for (const participant of participants)
            if (await reconcileParticipant(db, c, participant))
              eligible.push(participant);
          if (!eligible.some((p) => p.user_id === c.host_user_id)) {
            const next = eligible.find((p) =>
              ["joined", "admitted", "accepted"].includes(p.state),
            );
            if (next) {
              await db.query(
                "UPDATE comms_call_sessions SET host_user_id=$2,version=version+1 WHERE id=$1",
                [c.id, next.user_id],
              );
              c.host_user_id = next.user_id;
            } else {
              await finish(db, actor, c, "ended", "host_access_ended");
              continue;
            }
          }
          if (
            c.status === "ringing" &&
            Date.now() > new Date(c.expires_at).getTime()
          )
            await finish(db, actor, c, "missed", "expired");
          else if (
            !c.enabled ||
            Date.now() - new Date(c.created_at) > c.max_call_minutes * 60000 ||
            (await effectiveUsage(db, actor)) >=
              c.monthly_participant_minutes * 60
          )
            await finish(db, actor, c, "ended", "usage_limit");
          else if (
            provider.configured &&
            Date.now() - new Date(c.created_at) > 90000
          ) {
            const people = await provider.participants(c).catch(() => null);
            if (people?.length === 0)
              await finish(db, actor, c, "ended", "empty_room");
          }
        }
        return { checked: calls.length };
      });
    },
  };
  return service;
}
