import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createCommsFixture } from "../../tests/helpers/comms-fixture.js";
import { authorizeConversation, publish } from "../access.js";
import { installCallsSchema } from "./schema.js";
import { installGuestSchema } from "./guests.js";
import { installCaptionSchema } from "./caption-schema.js";
import { createCaptionService } from "./captions.js";

test(
  "live caption consent, targeted leases and provider lifecycle on PostgreSQL",
  { timeout: 120000 },
  async (t) => {
    const f = await createCommsFixture(),
      { pool, companies, ids } = f;
    const effects = { started: [], removed: [], stopped: [] },
      dispatches = [];
    const provider = {
      configured: true,
      startCaptions: async (call, run) => {
        effects.started.push(run.id);
        const value = {
          id: "dispatch-" + run.id,
          metadata: JSON.stringify({ caption_run_id: run.id }),
        };
        dispatches.push(value);
        return value;
      },
      captionDispatches: async () => dispatches,
      stopCaptions: async (call, id) => {
        effects.stopped.push(id);
      },
      remove: async (call, identity) => effects.removed.push(identity),
    };
    const env = {
      COMMS_CAPTIONS_ENABLED: "true",
      COMMS_CAPTIONS_WORKER_SECRET: "test-only-" + "x".repeat(40),
    };
    const service = createCaptionService({
      pool,
      provider,
      authorizeConversation,
      publish,
      env,
    });
    const owner = await f.actor("owner"),
      alice = await f.actor("alice");
    const seed = async () => {
      const conversation = "caption-" + randomUUID(),
        call = randomUUID();
      await pool.query(
        "INSERT INTO conversations(id,company_id,title,created_by) VALUES($1,$2,$3,$4)",
        [conversation, companies.a, "Caption test", ids.owner],
      );
      for (const user of [ids.owner, ids.alice, ids.carol])
        await pool.query(
          "INSERT INTO conversation_participants(id,conversation_id,user_id) VALUES($1,$2,$3)",
          [randomUUID(), conversation, user],
        );
      await pool.query(
        "INSERT INTO comms_call_sessions(id,company_id,conversation_id,creator_user_id,host_user_id,kind,media,room_name,status) VALUES($1,$2,$3,$4,$4,'huddle','audio',$5,'connected')",
        [call, companies.a, conversation, ids.owner, "room-" + call],
      );
      for (const user of [ids.owner, ids.alice])
        await pool.query(
          "INSERT INTO comms_call_participants(call_id,user_id,state,identity,joined_at) VALUES($1,$2,'joined',$3,now())",
          [call, user, "p_" + user],
        );
      return { call, conversation };
    };
    const consenting = async (call) => {
      const r = await service.start(owner, call);
      await service.consent(owner, call, { run_id: r.run_id, consented: true });
      await service.consent(alice, call, { run_id: r.run_id, consented: true });
      return r.run_id;
    };
    try {
      await installCallsSchema(pool);
      await installGuestSchema(pool);
      await installCaptionSchema(pool);
      await pool.query(
        "UPDATE employee_permissions SET permission_overrides=permission_overrides||$2::jsonb WHERE user_id=$1",
        [ids.alice, JSON.stringify({ "communications.transcribe": false })],
      );
      await installCaptionSchema(pool);
      await pool.query(
        "INSERT INTO comms_call_settings(company_id,captions_enabled) VALUES($1,true)",
        [companies.a],
      );
      await t.test(
        "configuration, tenant, host and explicit unanimous consent gate all dispatch",
        async () => {
          const { call } = await seed();
          assert.equal(
            service.workerAuthorized(
              "Bearer " + env.COMMS_CAPTIONS_WORKER_SECRET,
            ),
            true,
          );
          assert.equal(service.workerAuthorized("Bearer bad"), false);
          await assert.rejects(
            service.start(await f.actor("foreign"), call),
            (e) => [403, 404].includes(e.status),
          );
          await assert.rejects(
            service.start(alice, call),
            (e) => e.status === 403,
          );
          const disabled = createCaptionService({
            pool,
            provider,
            authorizeConversation,
            publish,
            env: {},
          });
          await assert.rejects(
            disabled.start(owner, call),
            (e) => e.code === "captions_not_configured",
          );
          const { run_id } = await service.start(owner, call);
          await service.consent(owner, call, { run_id, consented: true });
          await service.reconcile();
          assert.equal(effects.started.length, 0);
          await service.consent(alice, call, { run_id, consented: true });
          await Promise.all([service.reconcile(), service.reconcile()]);
          assert.deepEqual(effects.started, [run_id]);
          const worker_id = randomUUID(),
            lease = await service.lease({ run_id, worker_id });
          assert.equal(lease.active, true);
          assert.equal(lease.status, "starting");
          assert.equal((await service.get(owner, call)).status, "starting");
          assert.equal(
            await service.acceptAgent(pool, { id: call }, lease.agent_identity),
            true,
          );
          assert.equal((await service.get(owner, call)).status, "active");
          assert.equal(lease.lease_seconds, 3);
          assert.equal(lease.room_name, "room-" + call);
          assert.deepEqual(lease.recipients, ["p_" + ids.owner]);
          assert.equal(lease.participants.length, 2);
          assert.equal(
            lease.agent_identity,
            "cc_" + run_id.replaceAll("-", ""),
          );
          await assert.rejects(
            service.lease({ run_id, worker_id: randomUUID() }),
            (e) => e.code === "caption_worker_claimed",
          );
          const used = Number(
            (
              await pool.query(
                "SELECT reserved_seconds FROM comms_caption_usage WHERE run_id=$1",
                [run_id],
              )
            ).rows[0].reserved_seconds,
          );
          assert.ok(used >= 6 && used < 7);
          assert.equal((await service.get(alice, call)).can_view, false);
          await service.stop(owner, call);
          assert.equal(
            (await service.lease({ run_id, worker_id })).active,
            false,
          );
          await service.reconcile();
          assert.ok(effects.removed.includes(lease.agent_identity));
          assert.ok(effects.stopped.includes("dispatch-" + run_id));
        },
      );
      await t.test(
        "late arrivals pause, renewed consent resumes, withdrawal ends the run",
        async () => {
          const { call } = await seed(),
            run_id = await consenting(call),
            worker_id = randomUUID();
          await service.reconcile();
          assert.equal(
            (await service.lease({ run_id, worker_id })).active,
            true,
          );
          await pool.query(
            "INSERT INTO comms_call_participants(call_id,user_id,state,identity,joined_at) VALUES($1,$2,'joined',$3,now())",
            [call, ids.carol, "p_" + ids.carol],
          );
          assert.equal(
            (await service.lease({ run_id, worker_id })).status,
            "consent",
          );
          assert.equal((await service.get(owner, call)).status, "consent");
          await service.consent(await f.actor("carol"), call, {
            run_id,
            consented: true,
          });
          assert.equal(
            (await service.lease({ run_id, worker_id })).active,
            true,
          );
          await service.consent(alice, call, { run_id, consented: false });
          assert.equal(
            (await service.lease({ run_id, worker_id })).active,
            false,
          );
          await service.reconcile();
          assert.equal((await service.get(owner, call)).status, "stopped");
        },
      );
      await t.test(
        "source revocation and worker expiry fail closed without inventing transcript output",
        async () => {
          const { call, conversation } = await seed(),
            run_id = await consenting(call),
            worker_id = randomUUID();
          await service.reconcile();
          await service.lease({ run_id, worker_id });
          await pool.query(
            "UPDATE conversation_participants SET left_at=now() WHERE conversation_id=$1 AND user_id=$2",
            [conversation, ids.alice],
          );
          assert.equal(
            (await service.lease({ run_id, worker_id })).active,
            false,
          );
          await service.reconcile();
          assert.equal((await service.get(owner, call)).status, "failed");
          const second = await seed(),
            next = await consenting(second.call),
            worker = randomUUID();
          await service.reconcile();
          await service.lease({ run_id: next, worker_id: worker });
          await pool.query(
            "UPDATE comms_caption_runs SET lease_expires_at=now()-interval '10 seconds',updated_at=now()-interval '10 seconds' WHERE id=$1",
            [next],
          );
          await service.reconcile();
          assert.equal(
            (await service.get(owner, second.call)).error_code,
            "caption_worker_expired",
          );
        },
      );
      await t.test(
        "month boundary ends a caption run before previous-month usage can bypass the cap",
        async () => {
          const { call } = await seed(),
            run_id = await consenting(call),
            worker_id = randomUUID();
          await service.reconcile();
          await service.lease({ run_id, worker_id });
          await pool.query(
            "UPDATE comms_caption_runs SET created_at=date_trunc('month',now())-interval '1 second' WHERE id=$1",
            [run_id],
          );
          assert.equal(
            (await service.lease({ run_id, worker_id })).active,
            false,
          );
          await service.reconcile();
          assert.equal(
            (await service.get(owner, call)).error_code,
            "caption_period_ended",
          );
          assert.notEqual((await service.start(owner, call)).run_id, run_id);
          await service.stop(owner, call);
          await service.reconcile();
        },
      );
      await t.test(
        "a long consent wait still dispatches once and an absent worker becomes a visible failure",
        async () => {
          const { call } = await seed(),
            run_id = await consenting(call);
          await pool.query(
            "UPDATE comms_caption_runs SET updated_at=now()-interval '2 minutes' WHERE id=$1",
            [run_id],
          );
          await service.reconcile();
          assert.equal((await service.get(owner, call)).status, "starting");
          await pool.query(
            "UPDATE comms_caption_runs SET updated_at=now()-interval '31 seconds' WHERE id=$1",
            [run_id],
          );
          await service.reconcile();
          assert.equal(
            (await service.get(owner, call)).error_code,
            "caption_worker_unavailable",
          );
        },
      );
      await t.test(
        "an admitted guest cannot be captured without a guest caption-consent contract",
        async () => {
          const { call, conversation } = await seed(),
            meeting = randomUUID(),
            invite = randomUUID();
          await pool.query(
            "INSERT INTO comms_meetings(id,company_id,conversation_id,host_user_id,title,starts_at,duration_minutes,timezone) VALUES($1,$2,$3,$4,'Guest test',now(),30,'UTC')",
            [meeting, companies.a, conversation, ids.owner],
          );
          await pool.query(
            "INSERT INTO comms_guest_invites(id,company_id,meeting_id,created_by,token_hash,label,expires_at) VALUES($1,$2,$3,$4,$5,'Guest',now()+interval '1 hour')",
            [invite, companies.a, meeting, ids.owner, randomUUID()],
          );
          await pool.query(
            "INSERT INTO comms_guest_sessions(id,invite_id,company_id,meeting_id,call_id,session_hash,identity,display_name,state,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,'Guest','admitted',now()+interval '1 hour')",
            [
              randomUUID(),
              invite,
              companies.a,
              meeting,
              call,
              randomUUID(),
              "guest_" + randomUUID(),
            ],
          );
          await assert.rejects(
            service.start(owner, call),
            (e) => e.code === "guest_caption_consent_unavailable",
          );
        },
      );
      await t.test(
        "company toggle, paid allowance and fatal worker failure stop or deny capture",
        async () => {
          const { call } = await seed(),
            run_id = await consenting(call),
            worker_id = randomUUID();
          await service.reconcile();
          await service.lease({ run_id, worker_id });
          await service.failure({ run_id, worker_id, code: "stt_unavailable" });
          await service.reconcile();
          assert.equal(
            (await service.get(owner, call)).error_code,
            "stt_unavailable",
          );
          await pool.query(
            "UPDATE comms_call_settings SET monthly_caption_minutes=0 WHERE company_id=$1",
            [companies.a],
          );
          await assert.rejects(
            service.start(owner, call),
            (e) => e.code === "caption_usage_limit",
          );
          await pool.query(
            "UPDATE comms_call_settings SET monthly_caption_minutes=1000 WHERE company_id=$1",
            [companies.a],
          );
          const second = await seed(),
            next = await consenting(second.call),
            worker = randomUUID();
          await service.reconcile();
          await service.lease({ run_id: next, worker_id: worker });
          await pool.query(
            "UPDATE comms_call_settings SET captions_enabled=false WHERE company_id=$1",
            [companies.a],
          );
          assert.equal(
            (await service.lease({ run_id: next, worker_id: worker })).active,
            false,
          );
          await service.reconcile();
          assert.equal(
            (await service.get(owner, second.call)).status,
            "failed",
          );
        },
      );
    } finally {
      await f.close();
    }
  },
);
