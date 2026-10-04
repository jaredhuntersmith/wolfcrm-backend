import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import pg from "pg";
import { startLocalPostgres } from "../../tests/helpers/local-postgres.js";
import { installCommsSchema } from "../schema.js";
import { authorizeConversation, loadActor, publish } from "../access.js";
import { installCallsSchema } from "./schema.js";
import { createCallsService } from "./service.js";

// Disposable socket-only PostgreSQL; no production database or provider traffic.
test(
  "calls, admission, consent and provider jobs on PostgreSQL",
  { timeout: 120000 },
  async (t) => {
    const local = startLocalPostgres(),
      pool = new pg.Pool(local.config),
      company = randomUUID(),
      other = randomUUID();
    const ids = Object.fromEntries(
      ["owner", "employee", "peer", "outsider", "foreign"].map((k) => [
        k,
        randomUUID(),
      ]),
    );
    const effects = {
      tokens: [],
      removed: [],
      starts: 0,
      stops: 0,
      invites: [],
    };
    const provider = {
      configured: true,
      recordingConfigured: true,
      create: async () => ({}),
      close: async () => {},
      participants: async () => [{ identity: "alive" }],
      remove: async (c, p) => effects.removed.push(p),
      restrict: async () => {},
      mute: async () => {},
      token: async (c, p) => {
        effects.tokens.push({ ...p });
        return { url: "wss://example.invalid", token: "test-only" };
      },
      webhook: async (body) => JSON.parse(body),
      record: async () => {
        effects.starts++;
        return { egressId: "EG_" + randomUUID() };
      },
      stopRecording: async () => {
        effects.stops++;
      },
    };
    const service = createCallsService({
      pool,
      provider,
      authorizeConversation,
      publish,
      sendIncomingCall: async (c, u) => effects.invites.push(u),
      adoptRecording: async (db, c, r) => ({ id: r.id, byte_size: 120 }),
    });
    const actor = (key) =>
      loadActor(pool, {
        userId: ids[key],
        companyId: key === "foreign" ? other : company,
      });
    const make = async (key = "owner", kind = "huddle", invitees = []) =>
      service.create(await actor(key), {
        id: randomUUID(),
        conversation_id: "room",
        kind,
        media: "audio",
        invitee_ids: invitees,
      });
    const end = async (c) => {
      const host = (
        await pool.query(
          "SELECT host_user_id FROM comms_call_sessions WHERE id=$1",
          [c.id],
        )
      ).rows[0].host_user_id;
      return service.action(
        await loadActor(pool, { userId: host, companyId: company }),
        c.id,
        "end",
      );
    };
    const work = async () => {
      for (let i = 0; i < 20; i++) await service.work();
    };
    try {
      await pool.query(`CREATE EXTENSION pgcrypto;CREATE TABLE schedule_events(id text PRIMARY KEY,company_id uuid,deleted_at timestamptz);CREATE TABLE companies(id uuid PRIMARY KEY,owner_user_id uuid);CREATE TABLE users(id uuid PRIMARY KEY,company_id uuid REFERENCES companies(id),display_name text,photo_url text,role text,deleted_at timestamptz);CREATE TABLE employee_permissions(user_id uuid PRIMARY KEY,company_id uuid,permission_preset text,permission_overrides jsonb DEFAULT '{}');CREATE TABLE stored_files(id uuid PRIMARY KEY);
   CREATE TABLE conversations(id text PRIMARY KEY,company_id uuid REFERENCES companies(id),title text,is_group boolean DEFAULT false,created_by uuid,created_at timestamptz DEFAULT now(),updated_at timestamptz DEFAULT now(),deleted_at timestamptz);
   CREATE TABLE conversation_participants(id text PRIMARY KEY,conversation_id text REFERENCES conversations(id),user_id uuid REFERENCES users(id),joined_at timestamptz DEFAULT now(),last_read_at timestamptz,UNIQUE(conversation_id,user_id));
   CREATE TABLE channels(id text PRIMARY KEY,company_id uuid,name text,description text,created_by uuid,created_at timestamptz,archived_at timestamptz);
   CREATE TABLE messages(id text PRIMARY KEY,conversation_id text,channel_id text,sender_id uuid,body text,created_at timestamptz,deleted_at timestamptz);`);
      await pool.query("INSERT INTO companies VALUES($1,$2),($3,$4)", [
        company,
        ids.owner,
        other,
        ids.foreign,
      ]);
      for (const [key, id] of Object.entries(ids)) {
        await pool.query(
          "INSERT INTO users(id,company_id,display_name,role,deleted_at) VALUES($1,$2,$3,$4,NULL)",
          [id, key === "foreign" ? other : company, key, "employee"],
        );
        await pool.query(
          "INSERT INTO employee_permissions VALUES($1,$2,'technician',$3)",
          [
            id,
            key === "foreign" ? other : company,
            {
              "communications.calls": true,
              "communications.screenshare": false,
              "communications.view": true,
              "communications.send": true,
            },
          ],
        );
      }
      await pool.query(
        "INSERT INTO conversations(id,company_id,title,created_by) VALUES('room',$1,'Private team room',$2)",
        [company, ids.owner],
      );
      for (const key of ["owner", "employee", "peer"])
        await pool.query(
          "INSERT INTO conversation_participants(id,conversation_id,user_id) VALUES($1,'room',$2)",
          [randomUUID(), ids[key]],
        );
      await installCommsSchema(pool);
      await installCallsSchema(pool);
      await installCallsSchema(pool);
      await t.test("directory search and filters preserve precise history cursors at equal microsecond timestamps", async () => {
        const owner = await actor("owner"), callIDs = Array.from({length: 103}, () => randomUUID());
        try {
          for (const id of callIDs) await pool.query(
            "INSERT INTO comms_call_sessions(id,company_id,conversation_id,creator_user_id,host_user_id,kind,media,status,room_name,created_at,ended_at) VALUES($1,$2,'room',$3,$3,'huddle','audio','ended',$4,'2020-01-01T00:00:00.123456Z','2020-01-01T01:00:00Z')",
            [id,company,ids.owner,'fixture-'+id]);
          const first = await service.list(owner, {q: 'private team'});
          assert.equal(first.calls.length,100);
          assert.ok(first.next_cursor);
          assert.ok(first.calls.every(c => c.display_title === 'Private team room'));
          const second = await service.list(owner, {q:'private team',before:first.next_cursor});
          assert.equal(second.calls.length,3); assert.equal(second.next_cursor,null);
          assert.equal(new Set([...first.calls,...second.calls].map(c=>c.id)).size,103);
          assert.deepEqual((await service.list(owner,{filter:'active'})).calls,[]);
          assert.deepEqual((await service.list(owner,{filter:'recorded'})).calls,[]);
          assert.deepEqual((await service.list(owner,{q:'unmatched-search'})).calls,[]);
          assert.deepEqual((await service.list(await actor('outsider'),{q:'private team'})).calls,[]);
          await assert.rejects(service.list(owner,{before:'not-a-cursor'}), e=>e.status===400);
          await assert.rejects(service.list(owner,{filter:'unknown'}), e=>e.status===400);
        } finally { await pool.query("DELETE FROM comms_call_sessions WHERE id=ANY($1::uuid[])",[callIDs]); }
      });
      await t.test("meeting planning is provider-independent with explicit current eligible attendees and stable replay", async () => {
        const owner = await actor("owner");
        provider.configured = false;
        try {
          const eligible = await service.meetingInvitees(owner, { conversation_id: "room" });
          assert.deepEqual(eligible.members.map(u => u.id).sort(), [ids.owner, ids.employee, ids.peer].sort());
          assert.equal(eligible.next_cursor, null);
          await assert.rejects(service.meetingInvitees(await actor("outsider"), { conversation_id: "room" }), e => [403,404].includes(e.status));
          await assert.rejects(service.meetingInvitees(await actor("foreign"), { conversation_id: "room" }), e => [403,404].includes(e.status));
          await pool.query("UPDATE employee_permissions SET permission_overrides=permission_overrides || '{\"communications.calls\":false}'::jsonb WHERE user_id=$1", [ids.peer]);
          assert.ok(!(await service.meetingInvitees(owner, { conversation_id: "room" })).members.some(u => u.id === ids.peer));
          const body = { id: randomUUID(), conversation_id: "room", title: "Planning without media", starts_at: "2026-11-02T14:00:00Z", duration_minutes: 45, timezone: "America/New_York", attendee_ids: [ids.owner, ids.employee], waiting_room: false };
          const first = await service.saveMeeting(owner, body), replay = await service.saveMeeting(owner, body);
          assert.equal(first.id, replay.id);
          assert.equal(first.waiting_room, false);
          assert.equal(first.timezone, body.timezone);
          assert.deepEqual((await pool.query("SELECT user_id FROM comms_meeting_attendees WHERE meeting_id=$1", [first.id])).rows.map(u => u.user_id).sort(), body.attendee_ids.sort());
          const page = await service.meetingInvitees(owner, { conversation_id: "room", after_id: eligible.members[0].id });
          assert.ok(page.members.every(u => u.id > eligible.members[0].id));
          await service.meetingAction(owner, first.id, { action: "cancel" });
        } finally {
          provider.configured = true;
          await pool.query("UPDATE employee_permissions SET permission_overrides=permission_overrides || '{\"communications.calls\":true}'::jsonb WHERE user_id=$1", [ids.peer]);
        }
      });
      await t.test(
        "private and cross-company users cannot create, list or fetch calls",
        async () => {
          const c = await make();
          await assert.rejects(make("outsider"), (e) =>
            [403, 404].includes(e.status),
          );
          await assert.rejects(make("foreign"), (e) =>
            [403, 404].includes(e.status),
          );
          assert.deepEqual(
            (await service.list(await actor("outsider"))).calls,
            [],
          );
          assert.deepEqual(
            (await service.list(await actor("foreign"))).calls,
            [],
          );
          await assert.rejects(
            service.get(await actor("outsider"), c.id),
            (e) => e.status === 404,
          );
          await end(c);
        },
      );
      await t.test(
        "concurrent huddle and direct-call attempts converge; replay cannot reveal foreign call",
        async () => {
          const calls = await Promise.all([make(), make()]);
          assert.equal(calls[0].id, calls[1].id);
          await end(calls[0]);
          const direct = await Promise.all([
            make("owner", "direct", [ids.employee]),
            make("employee", "direct", [ids.owner]),
          ]);
          assert.equal(direct[0].id, direct[1].id);
          await end(direct[0]);
          const nonCreator =
            direct[0].creator_user_id === ids.owner ? "employee" : "owner";
          await assert.rejects(
            service.create(await actor(nonCreator), {
              id: direct[0].id,
              conversation_id: "room",
              kind: "direct",
              invitee_ids: [direct[0].creator_user_id],
            }),
            (e) => e.code === "idempotency_conflict",
          );
        },
      );
      await t.test(
        "answer is atomically claimed by one device; token source scope follows current capability",
        async () => {
          const c = await make("owner", "direct", [ids.employee]);
          const a = await actor("employee");
          const results = await Promise.allSettled([
            service.accept(a, c.id, { device_id: randomUUID() }),
            service.accept(a, c.id, { device_id: randomUUID() }),
          ]);
          assert.equal(
            results.filter((r) => r.status === "fulfilled").length,
            1,
          );
          assert.equal(
            results.find((r) => r.status === "rejected").reason.code,
            "answered_on_another_device",
          );
          const joined = await service.join(a, c.id);
          assert.equal(joined.screen_share_allowed, false);
          assert.equal(effects.tokens.at(-1).can_screen_share, false);
          await pool.query(
            "UPDATE employee_permissions SET permission_overrides=permission_overrides||'{\"communications.calls\":false}'::jsonb WHERE user_id=$1",
            [ids.employee],
          );
          await assert.rejects(service.join(a, c.id), (e) => e.status === 403);
          await pool.query(
            "UPDATE employee_permissions SET permission_overrides=permission_overrides||'{\"communications.calls\":true}'::jsonb WHERE user_id=$1",
            [ids.employee],
          );
          await end(c);
        },
      );
      await t.test(
        "waiting meeting has neither media token nor canonical chat history before admission",
        async () => {
          const owner = await actor("owner"),
            employee = await actor("employee");
          const meeting = await service.saveMeeting(owner, {
            id: randomUUID(),
            conversation_id: "room",
            title: "Operations",
            agenda: "Agenda",
            starts_at: new Date(Date.now() + 60000).toISOString(),
            duration_minutes: 30,
            timezone: "America/New_York",
            attendee_ids: [ids.employee],
          });
          assert.notEqual(meeting.conversation_id, "room");
          await assert.rejects(
            authorizeConversation(pool, employee, meeting.conversation_id),
            (e) => e.status === 404,
          );
          const c = await service.joinMeeting(owner, meeting.id),
            otherCall = await service.joinMeeting(employee, meeting.id);
          assert.equal(c.id, otherCall.id);
          const n = effects.tokens.length;
          assert.equal((await service.join(employee, c.id)).waiting, true);
          assert.equal(effects.tokens.length, n);
          await assert.rejects(
            authorizeConversation(pool, employee, meeting.conversation_id),
            (e) => e.status === 404,
          );
          await service.action(owner, c.id, "admit", { user_id: ids.employee });
          await authorizeConversation(pool, employee, meeting.conversation_id);
          assert.equal((await service.join(employee, c.id)).waiting, false);
          await service.action(owner, c.id, "remove", {
            user_id: ids.employee,
          });
          await assert.rejects(service.join(employee, c.id), (e) =>
            [403, 404].includes(e.status),
          );
          await assert.rejects(
            authorizeConversation(pool, employee, meeting.conversation_id),
            (e) => e.status === 404,
          );
          await end(c);
        },
      );
      await t.test(
        "recording requires separate capability and fresh unanimous consent; withdrawal queues stop",
        async () => {
          const c = await make("owner", "huddle", [ids.employee]),
            owner = await actor("owner"),
            employee = await actor("employee");
          await service.join(employee, c.id);
          await pool.query(
            "UPDATE comms_call_participants SET state='joined',joined_at=now() WHERE call_id=$1",
            [c.id],
          );
          await pool.query(
            "UPDATE comms_call_settings SET recording_enabled=true WHERE company_id=$1",
            [company],
          );
          await assert.rejects(
            service.recording(employee, c.id, { id: randomUUID() }),
            (e) => e.status === 403,
          );
          const r = await service.recording(owner, c.id, {
            id: randomUUID(),
            media: "audio",
          });
          assert.equal(r.status, "consent");
          await work();
          assert.equal(effects.starts, 0);
          await service.consent(owner, c.id, { consented: true });
          await work();
          assert.equal(effects.starts, 0);
          await service.consent(employee, c.id, { consented: true });
          await work();
          assert.equal(effects.starts, 1);
          await service.consent(employee, c.id, { consented: false });
          await work();
          assert.equal(effects.stops, 1);
          await end(c);
        },
      );
      await t.test(
        "host operations and usage limits are server enforced",
        async () => {
          const c = await make();
          await service.join(await actor("employee"), c.id);
          await assert.rejects(
            service.action(await actor("employee"), c.id, "end"),
            (e) => e.code === "host_required",
          );
          await assert.rejects(
            service.action(await actor("owner"), c.id, "screen-permission", {
              user_id: ids.employee,
              allowed: true,
            }),
            (e) => e.status === 403,
          );
          await service.action(await actor("owner"), c.id, "lock", {
            locked: true,
          });
          await assert.rejects(
            service.join(await actor("employee"), c.id),
            (e) => e.code === "meeting_locked",
          );
          await end(c);
          await pool.query(
            "UPDATE comms_call_settings SET monthly_participant_minutes=0 WHERE company_id=$1",
            [company],
          );
          await assert.rejects(make(), (e) => e.code === "calling_usage_limit");
          await pool.query(
            "UPDATE comms_call_settings SET monthly_participant_minutes=10000 WHERE company_id=$1",
            [company],
          );
        },
      );
      await t.test(
        "webhook duplicates do not double count; departed revoked identities are ejected",
        async () => {
          const c = await make(),
            p = (
              await pool.query(
                "SELECT * FROM comms_call_participants WHERE call_id=$1",
                [c.id],
              )
            ).rows[0],
            dbcall = (
              await pool.query(
                "SELECT * FROM comms_call_sessions WHERE id=$1",
                [c.id],
              )
            ).rows[0];
          const e = {
            id: randomUUID(),
            event: "participant_joined",
            room: { name: dbcall.room_name },
            participant: { identity: p.identity },
          };
          await service.webhook(JSON.stringify(e));
          assert.equal(
            (await service.webhook(JSON.stringify(e))).duplicate,
            true,
          );
          await pool.query(
            "UPDATE conversation_participants SET left_at=now() WHERE conversation_id='room' AND user_id=$1",
            [ids.owner],
          );
          await service.revokeUser(company, ids.owner);
          await service.webhook(JSON.stringify({ ...e, id: randomUUID() }));
          await work();
          assert.ok(effects.removed.includes(p.identity));
          await pool.query(
            "UPDATE conversation_participants SET left_at=NULL WHERE conversation_id='room' AND user_id=$1",
            [ids.owner],
          );
          await pool.query(
            "UPDATE comms_call_participants SET state='accepted' WHERE call_id=$1 AND user_id=$2",
            [c.id, ids.owner],
          );
          await end(c);
        },
      );
      await t.test(
        "the caller joining alone preserves ringing until answer or expiry",
        async () => {
          const c = await make("owner", "direct", [ids.employee]);
          const raw = (
            await pool.query("SELECT * FROM comms_call_sessions WHERE id=$1", [
              c.id,
            ])
          ).rows[0];
          const caller = (
            await pool.query(
              "SELECT identity FROM comms_call_participants WHERE call_id=$1 AND user_id=$2",
              [c.id, ids.owner],
            )
          ).rows[0];
          await service.webhook(
            JSON.stringify({
              id: randomUUID(),
              event: "participant_joined",
              room: { name: raw.room_name },
              participant: caller,
            }),
          );
          assert.equal(
            (await service.get(await actor("owner"), c.id)).status,
            "ringing",
          );
          await work();
          assert.ok(effects.invites.includes(ids.employee));
          await pool.query(
            "UPDATE comms_call_sessions SET expires_at=now()-interval '1 second' WHERE id=$1",
            [c.id],
          );
          await service.reconcile();
          assert.equal(
            (await service.get(await actor("owner"), c.id)).status,
            "missed",
          );
        },
      );
      await t.test(
        "audience reconciliation removes source membership and preserves benign permission changes",
        async () => {
          const c = await make("owner", "huddle", [ids.employee]);
          await service.join(await actor("employee"), c.id);
          const p = (
            await pool.query(
              "SELECT identity FROM comms_call_participants WHERE call_id=$1 AND user_id=$2",
              [c.id, ids.employee],
            )
          ).rows[0];
          assert.equal(
            (await service.revokeUser(company, ids.employee)).removed,
            0,
          );
          await pool.query(
            "UPDATE conversation_participants SET left_at=now() WHERE conversation_id='room' AND user_id=$1",
            [ids.employee],
          );
          await service.reconcile();
          await work();
          assert.ok(effects.removed.includes(p.identity));
          await assert.rejects(
            service.join(await actor("employee"), c.id),
            (e) => [403, 404].includes(e.status),
          );
          await pool.query(
            "UPDATE conversation_participants SET left_at=NULL WHERE conversation_id='room' AND user_id=$1",
            [ids.employee],
          );
          await end(c);
        },
      );
      await t.test(
        "paid recording jobs revalidate configuration after consent",
        async () => {
          const c = await make();
          const owner = await actor("owner");
          const r = await service.recording(owner, c.id, {
            id: randomUUID(),
            media: "audio",
          });
          await service.consent(owner, c.id, { consented: true });
          const starts = effects.starts;
          await pool.query(
            "UPDATE comms_call_settings SET recording_enabled=false WHERE company_id=$1",
            [company],
          );
          await work();
          assert.equal(effects.starts, starts);
          const result = await service.recordingMetadata(owner, r.id);
          assert.equal(result.status, "failed");
          assert.equal(result.object_key, undefined);
          await assert.rejects(
            service.recordingMetadata(await actor("outsider"), r.id),
            (e) => e.status === 404,
          );
          await pool.query(
            "UPDATE comms_call_settings SET recording_enabled=true WHERE company_id=$1",
            [company],
          );
          await end(c);
        },
      );
      await t.test(
        "out-of-order recording events cannot restart finalization and lost callbacks reconcile",
        async () => {
          const c = await make(),
            owner = await actor("owner");
          const r = await service.recording(owner, c.id, {
            id: randomUUID(),
            media: "audio",
          });
          await service.consent(owner, c.id, { consented: true });
          await work();
          const record = (
            await pool.query(
              "SELECT * FROM comms_call_recordings WHERE id=$1",
              [r.id],
            )
          ).rows[0];
          const raw = (
            await pool.query("SELECT * FROM comms_call_sessions WHERE id=$1", [
              c.id,
            ])
          ).rows[0];
          const info = {
            egressId: record.egress_id,
            roomName: raw.room_name,
            status: 3,
            fileResults: [{ size: 120, duration: "1000000000" }],
          };
          await service.webhook(
            JSON.stringify({
              id: randomUUID(),
              event: "egress_ended",
              egressInfo: info,
            }),
          );
          await service.webhook(
            JSON.stringify({
              id: randomUUID(),
              event: "egress_started",
              egressInfo: { ...info, status: 1 },
            }),
          );
          assert.equal(
            (await service.recordingMetadata(owner, r.id)).status,
            "processing",
          );
          assert.equal(
            (
              await pool.query(
                "SELECT 1 FROM comms_call_jobs WHERE call_id=$1 AND kind='adopt_recording'",
                [c.id],
              )
            ).rowCount,
            1,
          );
          await work();
          assert.equal(
            (await service.recordingMetadata(owner, r.id)).status,
            "ready",
          );
          const r2 = await service.recording(owner, c.id, {
            id: randomUUID(),
            media: "audio",
          });
          await service.consent(owner, c.id, { consented: true });
          await work();
          const record2 = (
            await pool.query(
              "SELECT * FROM comms_call_recordings WHERE id=$1",
              [r2.id],
            )
          ).rows[0];
          provider.recordings = async () => [
            { ...info, egressId: record2.egress_id },
          ];
          await service.reconcileEgress();
          await work();
          assert.equal(
            (await service.recordingMetadata(owner, r2.id)).status,
            "ready",
          );
          delete provider.recordings;
          await end(c);
        },
      );
      await t.test(
        "reactions and raised hands require an active authorized participant",
        async () => {
          const c = await make(),
            owner = await actor("owner");
          await service.action(owner, c.id, "hand", { allowed: true });
          await service.action(owner, c.id, "reaction", { reaction: "👍" });
          const me = (await service.get(owner, c.id)).participants.find(
            (p) => p.user_id === ids.owner,
          );
          assert.ok(me.hand_raised_at);
          assert.equal(me.reaction, "👍");
          await assert.rejects(
            service.action(await actor("outsider"), c.id, "reaction", {
              reaction: "👍",
            }),
            (e) => e.status === 404,
          );
          await assert.rejects(
            service.action(owner, c.id, "reaction", {
              reaction: "arbitrary private text",
            }),
            (e) => e.status === 400,
          );
          await end(c);
        },
      );
      await t.test(
        "capacity reserves issued media tokens and authorized huddle participants can rejoin",
        async () => {
          const c = await make();
          await pool.query(
            "UPDATE comms_call_settings SET max_participants=2 WHERE company_id=$1",
            [company],
          );
          await service.join(await actor("employee"), c.id);
          await assert.rejects(
            service.join(await actor("peer"), c.id),
            (e) => e.code === "room_capacity",
          );
          await service.action(await actor("employee"), c.id, "leave");
          const again = await service.join(await actor("employee"), c.id);
          assert.equal(again.waiting, false);
          assert.equal(
            (await service.get(await actor("employee"), c.id)).my_state,
            "accepted",
          );
          await pool.query(
            "UPDATE comms_call_settings SET max_participants=12 WHERE company_id=$1",
            [company],
          );
          await end(c);
        },
      );
      await t.test(
        "huddle ringing is an explicit eligible host invitation",
        async () => {
          const c = await make(),
            owner = await actor("owner");
          const candidates = await service.inviteCandidates(owner, c.id);
          assert.ok(candidates.members.some((x) => x.id === ids.employee));
          assert.ok(
            !candidates.members.some((x) =>
              [ids.foreign, ids.outsider].includes(x.id),
            ),
          );
          await assert.rejects(
            service.action(await actor("employee"), c.id, "invite", {
              user_id: ids.peer,
            }),
            (e) => e.code === "host_required",
          );
          const invites = effects.invites.length;
          await work();
          assert.equal(effects.invites.length, invites);
          await service.action(owner, c.id, "invite", {
            user_id: ids.employee,
          });
          await work();
          assert.equal(effects.invites.at(-1), ids.employee);
          await service.action(owner, c.id, "invite", {
            user_id: ids.employee,
          });
          await work();
          assert.equal(effects.invites.length, invites + 1);
          await end(c);
        },
      );
      await t.test(
        "room presence exposes observed eligible participants without issuing media tokens",
        async () => {
          const c = await make();
          await service.join(await actor("employee"), c.id);
          await pool.query(
            "UPDATE comms_call_participants SET state='joined',joined_at=now() WHERE call_id=$1 AND user_id=$2",
            [c.id, ids.employee],
          );
          const tokenCount = effects.tokens.length;
          const visible = await service.presence(await actor("owner"), [
            "room",
          ]);
          assert.equal(visible.rooms[0].call_id, c.id);
          assert.equal(visible.rooms[0].participants[0].user_id, ids.employee);
          assert.equal(effects.tokens.length, tokenCount);
          assert.deepEqual(
            (await service.presence(await actor("outsider"), ["room"])).rooms,
            [],
          );
          assert.deepEqual(
            (await service.presence(await actor("foreign"), ["room"])).rooms,
            [],
          );
          await pool.query(
            "UPDATE conversation_participants SET left_at=now() WHERE conversation_id='room' AND user_id=$1",
            [ids.employee],
          );
          assert.deepEqual(
            (await service.presence(await actor("owner"), ["room"])).rooms[0]
              .participants,
            [],
          );
          await pool.query(
            "UPDATE conversation_participants SET left_at=NULL WHERE conversation_id='room' AND user_id=$1",
            [ids.employee],
          );
          await end(c);
        },
      );
      await t.test(
        "meeting range projection and call lists prefilter current Job source access",
        async () => {
          const owner = await actor("owner");
          const starts = "2026-11-01T05:45:00Z";
          const meeting = await service.saveMeeting(owner, {
            id: randomUUID(),
            conversation_id: "room",
            title: "Night meeting",
            agenda: "",
            starts_at: starts,
            duration_minutes: 90,
            timezone: "America/New_York",
            attendee_ids: [ids.employee],
          });
          assert.equal(
            (await service.meetings(owner, { id: meeting.id })).meetings.length,
            1,
          );
          const range = {
            from: "2026-11-01T06:00:00Z",
            to: "2026-11-01T07:00:00Z",
          };
          assert.equal(
            (await service.meetings(owner, range)).meetings.some(
              (m) => m.id === meeting.id,
            ),
            true,
          );
          assert.equal(
            (
              await service.meetings(owner, {
                from: "2026-11-02T00:00:00Z",
                to: "2026-11-03T00:00:00Z",
              })
            ).meetings.some((m) => m.id === meeting.id),
            false,
          );
          await assert.rejects(
            service.meetings(owner, { from: "bad", to: range.to }),
            (e) => e.code === "invalid_meeting_range",
          );
          await pool.query(
            "CREATE TABLE IF NOT EXISTS schedule_events(id text PRIMARY KEY,company_id uuid,deleted_at timestamptz);CREATE TABLE IF NOT EXISTS comms_job_huddles(conversation_id text PRIMARY KEY,company_id uuid,job_id text)",
          );
          await pool.query(
            "INSERT INTO schedule_events(id,company_id) VALUES('job-usage',$1);",
            [company],
          );
          await pool.query(
            "INSERT INTO comms_job_huddles VALUES('room',$1,'job-usage')",
            [company],
          );
          // Mirror the canonical link written atomically by Job Huddle creation.
          await pool.query("UPDATE conversations SET source_kind='job',source_id='job-usage' WHERE id='room'");
          const call = await make();
          await pool.query(
            "UPDATE employee_permissions SET permission_overrides=permission_overrides||'{\"jobs.view\":false}'::jsonb WHERE user_id=$1",
            [ids.employee],
          );
          assert.deepEqual(
            (await service.meetings(await actor("employee"), range)).meetings,
            [],
          );
          assert.deepEqual(
            (await service.list(await actor("employee"))).calls,
            [],
          );
          assert.equal(
            (await service.meetings(owner, range)).meetings.some(
              (m) => m.id === meeting.id,
            ),
            true,
          );
          await pool.query(
            "UPDATE schedule_events SET deleted_at=now() WHERE id='job-usage'",
          );
          assert.deepEqual((await service.meetings(owner, range)).meetings, []);
          assert.deepEqual((await service.list(owner)).calls, []);
          await pool.query(
            "UPDATE employee_permissions SET permission_overrides=permission_overrides-'jobs.view' WHERE user_id=$1",
            [ids.employee],
          );
          await pool.query(
            "DELETE FROM comms_job_huddles WHERE conversation_id='room'",
          );
          await pool.query("UPDATE conversations SET source_kind=NULL,source_id=NULL WHERE id='room'");
          await end(call);
        },
      );
      await t.test(
        "owner diagnostics reveal only own-device registration and readiness stays minimal",
        async () => {
          const device = randomUUID(),
            otherDevice = randomUUID(),
            owner = await actor("owner");
          await pool.query(
            "INSERT INTO comms_voip_devices VALUES($1,$2,'test-owner','sandbox',now()),($3,$4,'test-other','sandbox',now())",
            [ids.owner, device, ids.employee, otherDevice],
          );
          assert.equal(
            (await service.ownerDiagnostics(owner, { device_id: device }))
              .voip_device_registered,
            true,
          );
          assert.equal(
            (await service.ownerDiagnostics(owner, { device_id: otherDevice }))
              .voip_device_registered,
            false,
          );
          assert.equal(
            "voip_device_registered" in (await service.diagnostics(owner)),
            false,
          );
          await assert.rejects(
            service.ownerDiagnostics(
              { ...(await actor("employee")), isCompanyOwner: true },
              { device_id: device },
            ),
            (e) => e.code === "owner_required",
          );
          await assert.rejects(
            service.ownerDiagnostics(owner, { device_id: "bad" }),
            (e) => e.code === "invalid_id",
          );
        },
      );
      await t.test(
        "provider failure in a job persists a bounded retry",
        async () => {
          const c = await make();
          await work();
          const job = randomUUID();
          await pool.query(
            "INSERT INTO comms_call_jobs(id,call_id,kind) VALUES($1,$2,'create_room')",
            [job, c.id],
          );
          const original = provider.create;
          provider.create = async () => {
            await pool.query("SELECT 1");
            throw Object.assign(Error("offline"), { code: "offline" });
          };
          await service.work();
          provider.create = original;
          const state = (
            await pool.query(
              "SELECT status,attempts,last_error FROM comms_call_jobs WHERE id=$1",
              [job],
            )
          ).rows[0];
          assert.equal(state.status, "pending");
          assert.equal(state.attempts, 1);
          assert.equal(state.last_error, "offline");
          await end(c);
        },
      );
    } finally {
      await pool.end();
      local.stop();
    }
  },
);
