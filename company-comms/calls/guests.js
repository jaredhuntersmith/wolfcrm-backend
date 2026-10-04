import { randomBytes, randomUUID, createHash } from "node:crypto";
import { transact, loadActor } from "../access.js";
import { fail, uuid, requireCapability, terminal } from "./domain.js";

export async function installGuestSchema(db) {
  await db.query(`
 CREATE TABLE IF NOT EXISTS comms_guest_invites(id uuid PRIMARY KEY,company_id uuid NOT NULL REFERENCES companies(id),meeting_id uuid NOT NULL REFERENCES comms_meetings(id),created_by uuid NOT NULL REFERENCES users(id),token_hash text NOT NULL UNIQUE,label text NOT NULL,expires_at timestamptz NOT NULL,consumed_at timestamptz,revoked_at timestamptz,created_at timestamptz NOT NULL DEFAULT now());
 CREATE TABLE IF NOT EXISTS comms_guest_sessions(id uuid PRIMARY KEY,invite_id uuid NOT NULL UNIQUE REFERENCES comms_guest_invites(id),company_id uuid NOT NULL REFERENCES companies(id),meeting_id uuid NOT NULL REFERENCES comms_meetings(id),call_id uuid REFERENCES comms_call_sessions(id),session_hash text NOT NULL UNIQUE,identity text NOT NULL UNIQUE,display_name text NOT NULL,state text NOT NULL DEFAULT 'waiting' CHECK(state IN('waiting','admitted','joined','left','removed')),joined_at timestamptz,left_at timestamptz,participant_seconds bigint NOT NULL DEFAULT 0,expires_at timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
 CREATE INDEX IF NOT EXISTS comms_guest_call ON comms_guest_sessions(call_id,state);
`);
}
const hash = (secret) => createHash("sha256").update(secret).digest("hex");
const secret = () => randomBytes(32).toString("base64url");
const valid = (token) =>
  typeof token === "string" && /^[A-Za-z0-9_-]{43}$/.test(token);
export function createGuestService({
  pool,
  provider,
  authorizeConversation,
  publish,
  env = process.env,
}) {
  const configured = env.COMMS_GUESTS_ENABLED === "true" && provider.configured;
  const transaction = (fn) => transact(pool, fn);
  const enabled = async (db, company) => {
    if (!configured) fail(503, "guest_join_not_configured");
    const settings = (
      await db.query(
        "SELECT * FROM comms_call_settings WHERE company_id=$1 FOR UPDATE",
        [company],
      )
    ).rows[0];
    if (!settings?.enabled || !settings.guests_enabled)
      fail(403, "guest_join_disabled");
    return settings;
  };
  const host = async (db, a, meetingID) => {
    await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
      "comms-guests:" + a.companyId,
    ]);
    a = await loadActor(db, a);
    requireCapability(a, "communications.guests");
    const meeting = (
      await db.query(
        "SELECT * FROM comms_meetings WHERE id=$1 AND company_id=$2 FOR UPDATE",
        [uuid(meetingID), a.companyId],
      )
    ).rows[0];
    if (!meeting || meeting.status !== "scheduled")
      fail(404, "meeting_unavailable");
    await authorizeConversation(
      db,
      a,
      meeting.source_conversation_id || meeting.conversation_id,
      { capability: "communications.guests" },
    );
    const call = (
      await db.query(
        "SELECT * FROM comms_call_sessions WHERE meeting_id=$1 AND ended_at IS NULL FOR UPDATE",
        [meeting.id],
      )
    ).rows[0];
    if (a.userId !== (call?.host_user_id || meeting.host_user_id))
      fail(403, "host_required");
    const settings = await enabled(db, a.companyId);
    return { a, meeting, call, settings };
  };
  const session = async (db, token) => {
    if (!valid(token)) fail(404, "guest_session_unavailable");
    const row = (
      await db.query(
        "SELECT g.*,i.revoked_at,i.expires_at AS invite_expires,m.status AS meeting_status,m.title AS meeting_title,m.source_conversation_id FROM comms_guest_sessions g JOIN comms_guest_invites i ON i.id=g.invite_id JOIN comms_meetings m ON m.id=g.meeting_id WHERE g.session_hash=$1",
        [hash(token)],
      )
    ).rows[0];
    if (
      !row ||
      row.revoked_at ||
      new Date(row.expires_at) <= new Date() ||
      new Date(row.invite_expires) <= new Date() ||
      row.meeting_status !== "scheduled" ||
      ["left", "removed"].includes(row.state)
    )
      fail(404, "guest_session_unavailable");
    await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
      "comms-guests:" + row.company_id,
    ]);
    const fresh = (
      await db.query("SELECT state FROM comms_guest_sessions WHERE id=$1", [
        row.id,
      ])
    ).rows[0];
    if (["left", "removed"].includes(fresh.state))
      fail(404, "guest_session_unavailable");
    row.state = fresh.state;
    const call = (
      await db.query(
        "SELECT * FROM comms_call_sessions WHERE meeting_id=$1 AND ended_at IS NULL FOR UPDATE",
        [row.meeting_id],
      )
    ).rows[0];
    const settings = await enabled(db, row.company_id);
    if (row.call_id && !call) fail(410, "meeting_ended");
    if (call && row.call_id !== call.id) {
      if (row.call_id) fail(410, "meeting_ended");
      await db.query("UPDATE comms_guest_sessions SET call_id=$2 WHERE id=$1", [
        row.id,
        call.id,
      ]);
      row.call_id = call.id;
    }
    if (call) {
      try {
        const current = await loadActor(db, {
          companyId: row.company_id,
          userId: call.host_user_id,
        });
        requireCapability(current, "communications.guests");
        await authorizeConversation(db, current, call.conversation_id, {
          capability: "communications.guests",
        });
        if (row.source_conversation_id)
          await authorizeConversation(db, current, row.source_conversation_id, {
            capability: "communications.guests",
          });
      } catch {
        fail(403, "guest_join_disabled");
      }
    }
    return { row, call, settings };
  };
  const publicStatus = ({ row, call }) => ({
    guest_id: row.id,
    guest_name: row.display_name,
    meeting_title: row.meeting_title,
    call_id: call?.id || null,
    state: row.state,
    media: call?.media || "video",
    expires_at: row.expires_at,
    recording_allowed: false,
  });
  const noRecording = async (db, call) => {
    if (
      (
        await db.query(
          "SELECT 1 FROM comms_call_recordings WHERE call_id=$1 AND status IN('starting','recording','stopping')",
          [call.id],
        )
      ).rowCount
    )
      fail(
        409,
        "recording_in_progress",
        "Stop recording before admitting an external guest.",
      );
  };
  const queueRemove = async (db, g) => {
    if (g.call_id)
      await db.query(
        "INSERT INTO comms_call_jobs(id,call_id,kind,payload) VALUES($1,$2,'remove',$3)",
        [randomUUID(), g.call_id, { identity: g.identity }],
      );
  };
  const service = {
    configured,
    async invite(a, meetingID, b) {
      return transaction(async (db) => {
        const { a: current, meeting } = await host(db, a, meetingID);
        const label = String(b.label || "Guest").trim();
        if (!label || label.length > 100) fail(400, "invalid_guest_label");
        const expires = new Date(
          Math.min(
            Date.now() + 24 * 3600000,
            new Date(meeting.starts_at).getTime() +
              (meeting.duration_minutes + 120) * 60000,
          ),
        );
        if (expires <= new Date()) fail(409, "meeting_expired");
        const count = Number(
          (
            await db.query(
              "SELECT count(*) FROM comms_guest_invites WHERE meeting_id=$1 AND revoked_at IS NULL AND expires_at>now()",
              [meeting.id],
            )
          ).rows[0].count,
        );
        if (count >= 20) fail(429, "guest_invitation_limit");
        const token = secret(),
          id = randomUUID();
        await db.query(
          "INSERT INTO comms_guest_invites(id,company_id,meeting_id,created_by,token_hash,label,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)",
          [
            id,
            current.companyId,
            meeting.id,
            current.userId,
            hash(token),
            label,
            expires,
          ],
        );
        await publish(
          db,
          current,
          meeting.conversation_id,
          "meeting.guest_invited",
          id,
          { meeting_id: meeting.id },
        );
        return {
          id,
          label,
          expires_at: expires,
          join_url: "wolfcrm://comms-guest#token=" + token,
        };
      });
    },
    async list(a, meetingID) {
      return transaction(async (db) => {
        const { meeting } = await host(db, a, meetingID);
        return {
          guests: (
            await db.query(
              "SELECT i.id AS invite_id,i.label,i.expires_at,i.revoked_at,g.id,g.display_name,g.state FROM comms_guest_invites i LEFT JOIN comms_guest_sessions g ON g.invite_id=i.id WHERE i.meeting_id=$1 ORDER BY i.created_at",
              [meeting.id],
            )
          ).rows,
        };
      });
    },
    async redeem(token, name) {
      return transaction(async (db) => {
        if (!configured || !valid(token))
          fail(404, "guest_invitation_unavailable");
        const display = String(name || "").trim();
        if (!display || display.length > 80) fail(400, "guest_name_required");
        const invitationCompany = (
          await db.query(
            "SELECT company_id FROM comms_guest_invites WHERE token_hash=$1",
            [hash(token)],
          )
        ).rows[0];
        if (!invitationCompany) fail(404, "guest_invitation_unavailable");
        await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
          "comms-guests:" + invitationCompany.company_id,
        ]);
        const invite = (
          await db.query(
            "SELECT i.*,m.status AS meeting_status,m.title AS meeting_title FROM comms_guest_invites i JOIN comms_meetings m ON m.id=i.meeting_id WHERE token_hash=$1 FOR UPDATE OF i",
            [hash(token)],
          )
        ).rows[0];
        if (
          !invite ||
          invite.consumed_at ||
          invite.revoked_at ||
          new Date(invite.expires_at) <= new Date() ||
          invite.meeting_status !== "scheduled"
        )
          fail(404, "guest_invitation_unavailable");
        await enabled(db, invite.company_id);
        const tokenValue = secret(),
          id = randomUUID();
        await db.query(
          "INSERT INTO comms_guest_sessions(id,invite_id,company_id,meeting_id,session_hash,identity,display_name,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
          [
            id,
            invite.id,
            invite.company_id,
            invite.meeting_id,
            hash(tokenValue),
            "g_" + randomUUID().replaceAll("-", ""),
            display,
            invite.expires_at,
          ],
        );
        await db.query(
          "UPDATE comms_guest_invites SET consumed_at=now() WHERE id=$1",
          [invite.id],
        );
        return {
          session_token: tokenValue,
          guest_id: id,
          guest_name: display,
          meeting_title: invite.meeting_title,
          state: "waiting",
          call_id: null,
          media: "video",
          expires_at: invite.expires_at,
          recording_allowed: false,
        };
      });
    },
    async status(token) {
      return transaction(async (db) => publicStatus(await session(db, token)));
    },
    async token(token) {
      return transaction(async (db) => {
        const context = await session(db, token),
          { row, call, settings } = context;
        if (!call || row.state === "waiting")
          return { ...publicStatus(context), waiting: true };
        if (call.locked && row.state !== "joined") fail(403, "meeting_locked");
        await noRecording(db, call);
        const occupied = Number(
          (
            await db.query(
              "SELECT (SELECT count(*) FROM comms_call_participants WHERE call_id=$1 AND state IN('accepted','admitted','joined'))+(SELECT count(*) FROM comms_guest_sessions WHERE call_id=$1 AND state IN('admitted','joined') AND id<>$2) AS count",
              [call.id, row.id],
            )
          ).rows[0].count,
        );
        if (occupied >= settings.max_participants) fail(409, "room_capacity");
        const connection = await provider.token(call, {
          identity: row.identity,
          display_name: row.display_name + " (Guest)",
          can_screen_share: false,
        });
        return {
          ...publicStatus(context),
          ...connection,
          waiting: false,
          screen_share_allowed: false,
        };
      });
    },
    async moderate(a, meetingID, id, b) {
      return transaction(async (db) => {
        const {
          a: current,
          meeting,
          call,
          settings,
        } = await host(db, a, meetingID);
        const guest = (
          await db.query(
            "SELECT g.* FROM comms_guest_sessions g WHERE g.id=$1 AND g.meeting_id=$2 FOR UPDATE",
            [uuid(id), meeting.id],
          )
        ).rows[0];
        if (!guest) fail(404, "guest_unavailable");
        if (b.action === "admit") {
          if (!call || call.locked) fail(409, "meeting_not_open");
          if (guest.state !== "waiting") fail(409, "guest_not_waiting");
          await noRecording(db, call);
          const occupied = Number(
            (
              await db.query(
                "SELECT (SELECT count(*) FROM comms_call_participants WHERE call_id=$1 AND state IN('accepted','admitted','joined'))+(SELECT count(*) FROM comms_guest_sessions WHERE call_id=$1 AND state IN('admitted','joined')) AS count",
                [call.id],
              )
            ).rows[0].count,
          );
          if (occupied >= settings.max_participants) fail(409, "room_capacity");
          await db.query(
            "UPDATE comms_guest_sessions SET state='admitted',call_id=$2 WHERE id=$1",
            [guest.id, call.id],
          );
        } else if (b.action === "remove") {
          await db.query(
            "UPDATE comms_guest_sessions SET state='removed',left_at=now(),participant_seconds=participant_seconds+CASE WHEN state='joined' THEN greatest(0,extract(epoch from now()-joined_at))::bigint ELSE 0 END WHERE id=$1",
            [guest.id],
          );
          await db.query(
            "UPDATE comms_guest_invites SET revoked_at=now() WHERE id=$1",
            [guest.invite_id],
          );
          await queueRemove(db, guest);
        } else fail(400, "invalid_guest_action");
        await publish(
          db,
          current,
          meeting.conversation_id,
          "meeting.guest_updated",
          guest.id,
          { meeting_id: meeting.id },
        );
        return { ok: true };
      });
    },
    async revoke(a, meetingID, id) {
      return transaction(async (db) => {
        const { meeting } = await host(db, a, meetingID);
        const invite = (
          await db.query(
            "UPDATE comms_guest_invites SET revoked_at=now() WHERE id=$1 AND meeting_id=$2 RETURNING id",
            [uuid(id), meeting.id],
          )
        ).rows[0];
        if (!invite) fail(404, "guest_invitation_unavailable");
        const guests = (
          await db.query(
            "UPDATE comms_guest_sessions SET state='removed',left_at=now() WHERE invite_id=$1 RETURNING *",
            [id],
          )
        ).rows;
        for (const g of guests) await queueRemove(db, g);
        return { ok: true };
      });
    },
    async leave(token) {
      return transaction(async (db) => {
        const { row } = await session(db, token);
        await db.query(
          "UPDATE comms_guest_sessions SET state='left',left_at=now(),participant_seconds=participant_seconds+CASE WHEN state='joined' THEN greatest(0,extract(epoch from now()-joined_at))::bigint ELSE 0 END WHERE id=$1",
          [row.id],
        );
        await queueRemove(db, row);
        return { ok: true };
      });
    },
    async occupied(db, callID) {
      return Number(
        (
          await db.query(
            "SELECT count(*) FROM comms_guest_sessions WHERE call_id=$1 AND state IN('admitted','joined')",
            [callID],
          )
        ).rows[0].count,
      );
    },
    async recordingBlocked(db, callID) {
      return (await service.occupied(db, callID)) > 0;
    },
    async joined(db, call, identity) {
      const g = (
        await db.query(
          "SELECT g.* FROM comms_guest_sessions g JOIN comms_guest_invites i ON i.id=g.invite_id WHERE g.call_id=$1 AND g.identity=$2 AND g.state IN('admitted','joined') AND g.expires_at>now() AND i.revoked_at IS NULL",
          [call.id, identity],
        )
      ).rows[0];
      if (!g || terminal(call.status)) return false;
      await noRecording(db, call);
      await db.query(
        "UPDATE comms_guest_sessions SET state='joined',joined_at=CASE WHEN state='joined' THEN joined_at ELSE now() END WHERE id=$1",
        [g.id],
      );
      return true;
    },
    async left(db, call, identity) {
      await db.query(
        "UPDATE comms_guest_sessions SET state='left',left_at=now(),participant_seconds=participant_seconds+greatest(0,extract(epoch from now()-joined_at))::bigint WHERE call_id=$1 AND identity=$2 AND state='joined'",
        [call.id, identity],
      );
    },
    async usage(db, companyID) {
      return Number(
        (
          await db.query(
            "SELECT COALESCE(sum(participant_seconds+CASE WHEN state='joined' THEN greatest(0,extract(epoch from now()-joined_at)) ELSE 0 END),0) AS seconds FROM comms_guest_sessions WHERE company_id=$1 AND created_at>=date_trunc('month',now())",
            [companyID],
          )
        ).rows[0].seconds,
      );
    },
    async reconcile() {
      await transaction(async (db) => {
        const rows = (
          await db.query(
            "SELECT g.* FROM comms_guest_sessions g WHERE state IN('waiting','admitted','joined') ORDER BY created_at LIMIT 100",
          )
        ).rows;
        for (const g of rows) {
          await db.query(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
            ["comms-guests:" + g.company_id],
          );
          let denied = new Date(g.expires_at) <= new Date();
          if (!denied) {
            try {
              await enabled(db, g.company_id);
              const m = (
                await db.query("SELECT * FROM comms_meetings WHERE id=$1", [
                  g.meeting_id,
                ])
              ).rows[0];
              const c = g.call_id
                ? (
                    await db.query(
                      "SELECT * FROM comms_call_sessions WHERE id=$1",
                      [g.call_id],
                    )
                  ).rows[0]
                : null;
              if (
                !m ||
                m.status !== "scheduled" ||
                (g.call_id && (!c || terminal(c.status)))
              )
                denied = true;
              else {
                const a = await loadActor(db, {
                  userId: c?.host_user_id || m.host_user_id,
                  companyId: g.company_id,
                });
                requireCapability(a, "communications.guests");
                await authorizeConversation(
                  db,
                  a,
                  m.source_conversation_id || m.conversation_id,
                  { capability: "communications.guests" },
                );
              }
            } catch (e) {
              if ([400, 403, 404, 503].includes(e.status)) denied = true;
              else throw e;
            }
          }
          if (denied) {
            await db.query(
              "UPDATE comms_guest_sessions SET state='removed',left_at=now(),participant_seconds=participant_seconds+CASE WHEN state='joined' THEN greatest(0,extract(epoch from now()-joined_at))::bigint ELSE 0 END WHERE id=$1",
              [g.id],
            );
            await queueRemove(db, g);
          }
        }
      });
    },
  };
  return service;
}
