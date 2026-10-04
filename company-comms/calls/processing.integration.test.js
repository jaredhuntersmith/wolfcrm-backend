import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createCommsFixture } from "../../tests/helpers/comms-fixture.js";
import { authorizeConversation, publish } from "../access.js";
import { installCollaborationSchema } from "../collaboration-schema.js";
import { installCaptionSchema } from "./caption-schema.js";
import { installGuestSchema } from "./guests.js";
import { createCallsService } from "./service.js";
import { installCallsSchema } from "./schema.js";
import {
  installProcessingSchema,
  createProcessingService,
} from "./processing.js";

test(
  "recording processing consent, stale access and explicit task approval",
  { timeout: 120000 },
  async (t) => {
    const f = await createCommsFixture(),
      { pool, companies, ids } = f;
    const conversation = "recording-review";
    let executions = 0;
    const segments = [
      {
        id: "0:0",
        start: 0,
        end: 8,
        speaker: "Unknown speaker",
        text: "We should prepare the quote.",
      },
    ];
    const provider = {
      configured: true,
      aiConfigured: true,
      transcribe: async () => {
        executions++;
        return { segments, text: segments[0].text, model: "test-fake" };
      },
      summarize: async () => ({
        model: "test-fake",
        usage: {
          input_tokens: 100,
          output_tokens: 20,
          total_tokens: 120,
          ignored: "not stored",
        },
        result: {
          summary: "A quote was discussed.",
          decisions: [],
          questions: [],
          tasks: [
            {
              title: "Prepare quote draft",
              detail: "Review the quote before sending.",
              segment_ids: ["0:0"],
            },
          ],
        },
      }),
    };
    const service = createProcessingService({
      pool,
      authorizeConversation,
      publish,
      provider,
    });
    const owner = await f.actor("owner"),
      alice = await f.actor("alice");
    const seed = async () => {
      const call = randomUUID(),
        recording = randomUUID(),
        asset = await f.asset("owner", "audio");
      await pool.query(
        "INSERT INTO comms_call_sessions(id,company_id,conversation_id,creator_user_id,host_user_id,kind,media,room_name,status,ended_at) VALUES($1,$2,$3,$4,$4,'meeting','audio',$5,'ended',now())",
        [call, companies.a, conversation, ids.owner, "test_" + call],
      );
      for (const user of [ids.owner, ids.alice])
        await pool.query(
          "INSERT INTO comms_call_participants(call_id,user_id,state,identity,joined_at,left_at) VALUES($1,$2,'left',$3,now()-interval '1 minute',now())",
          [call, user, "p_" + user],
        );
      await pool.query(
        "INSERT INTO comms_call_recordings(id,call_id,company_id,requested_by,object_key,asset_id,media,status,duration_seconds) VALUES($1,$2,$3,$4,$5,$6,'audio','ready',60)",
        [recording, call, companies.a, ids.owner, "test/" + asset, asset],
      );
      return { call, recording };
    };
    const consent = async (id, purpose) => {
      await service.consent(owner, id, { purpose, consented: true });
      await service.consent(alice, id, { purpose, consented: true });
    };
    try {
      await installCollaborationSchema(pool);
      await installCallsSchema(pool);
      await installGuestSchema(pool);
      await installCaptionSchema(pool);
      await installProcessingSchema(pool);
      await installProcessingSchema(pool);
      await pool.query(
        'UPDATE employee_permissions SET permission_overrides=permission_overrides||\'{"communications.transcribe":false,"communications.ai":false}\'::jsonb WHERE user_id=$1',
        [ids.alice],
      );
      await pool.query(
        "ALTER TABLE todo_tasks ADD COLUMN IF NOT EXISTS detail text;ALTER TABLE todo_tasks ADD COLUMN IF NOT EXISTS status text;ALTER TABLE todo_tasks ADD COLUMN IF NOT EXISTS priority text;ALTER TABLE todo_tasks ADD COLUMN IF NOT EXISTS completed boolean DEFAULT false;",
      );
      await pool.query(
        "INSERT INTO conversations(id,company_id,title,created_by) VALUES($1,$2,$3,$4)",
        [conversation, companies.a, "Review", ids.owner],
      );
      for (const user of [ids.owner, ids.alice])
        await pool.query(
          "INSERT INTO conversation_participants(id,conversation_id,user_id) VALUES($1,$2,$3)",
          [randomUUID(), conversation, user],
        );
      await pool.query(
        "INSERT INTO comms_call_settings(company_id,recording_enabled,transcription_enabled,ai_enabled) VALUES($1,true,true,true)",
        [companies.a],
      );
      await t.test(
        "every recorded participant must separately consent before processing",
        async () => {
          const { recording } = await seed();
          await assert.rejects(
            service.request(owner, recording, { kind: "transcript" }),
            (e) => e.code === "processing_consent_required",
          );
          await service.consent(owner, recording, {
            purpose: "transcript",
            consented: true,
          });
          await assert.rejects(
            service.request(owner, recording, { kind: "transcript" }),
            (e) => e.code === "processing_consent_required",
          );
          await service.consent(alice, recording, {
            purpose: "transcript",
            consented: true,
          });
          const queued = await service.request(owner, recording, {
            kind: "transcript",
          });
          assert.equal(queued.status, "queued");
          await service.runOnce();
          assert.equal(
            (await service.get(owner, recording)).jobs[0].status,
            "ready",
          );
          assert.equal(executions, 1);
          await service.consent(alice, recording, {
            purpose: "transcript",
            consented: false,
          });
          const canceled = (await service.get(owner, recording)).jobs[0];
          assert.equal(canceled.status, "canceled");
          assert.equal(canceled.result, null);
        },
      );
      await t.test(
        "foreign company, nonmember and ordinary unpaid capability cannot read or request transcript",
        async () => {
          const { recording } = await seed();
          await consent(recording, "transcript");
          await assert.rejects(
            service.get(await f.actor("foreign"), recording),
            (e) => [403, 404].includes(e.status),
          );
          await assert.rejects(
            service.get(await f.actor("bob"), recording),
            (e) => e.status === 404,
          );
          await assert.rejects(
            service.request(alice, recording, { kind: "transcript" }),
            (e) => e.status === 403,
          );
        },
      );
      await t.test(
        "summary creates review proposals only; approve writes one canonical task and repeats return same task",
        async () => {
          const { recording } = await seed();
          await consent(recording, "transcript");
          await service.request(owner, recording, { kind: "transcript" });
          await service.runOnce();
          await consent(recording, "summary");
          await service.request(owner, recording, { kind: "summary" });
          await service.runOnce();
          assert.equal(
            Number(
              (await pool.query("SELECT count(*) FROM todo_tasks")).rows[0]
                .count,
            ),
            0,
          );
          const metered = (
            await pool.query(
              "SELECT provider_usage FROM comms_processing_usage WHERE kind='summary' ORDER BY created_at DESC LIMIT 1",
            )
          ).rows[0].provider_usage;
          assert.deepEqual(metered, {
            input_tokens: 100,
            output_tokens: 20,
            total_tokens: 120,
          });
          const action = (await service.get(owner, recording)).actions[0];
          assert.ok(action);
          await assert.rejects(
            service.review(owner, action.id, {
              action: "approve",
              expected_version: action.version,
              assignee_ids: [ids.foreign],
            }),
            (e) => [403, 404].includes(e.status),
          );
          const result = await service.review(owner, action.id, {
            action: "approve",
            expected_version: action.version,
            title: "Reviewed quote task",
            assignee_ids: [ids.owner],
          });
          assert.equal(result.state, "approved");
          const again = await service.review(owner, action.id, {
            action: "approve",
            expected_version: action.version,
          });
          assert.equal(again.task_id, result.task_id);
          assert.equal(
            Number(
              (await pool.query("SELECT count(*) FROM todo_tasks")).rows[0]
                .count,
            ),
            1,
          );
        },
      );
      await t.test(
        "owner usage reports tenant-scoped monthly estimates, token availability and allowance warnings without media calls",
        async () => {
          const calls = createCallsService({
            pool,
            authorizeConversation,
            provider: {},
          });
          await assert.rejects(
            calls.usage({ ...alice, isCompanyOwner: true }),
            (e) => e.code === "owner_required",
          );
          const usage = await calls.usage(owner);
          assert.ok(usage.transcript_seconds >= 60);
          assert.ok(usage.summary_seconds >= 60);
          assert.ok(usage.ai_tokens >= 120);
          assert.ok(usage.recording_storage_bytes > 0);
          assert.equal(usage.provider_cost, null);
          assert.equal(usage.provider_bill_available, false);
          assert.equal(usage.estimated, true);
          const minutes =
            (usage.transcript_seconds + usage.summary_seconds) / 60;
          await pool.query(
            "UPDATE comms_call_settings SET monthly_processing_minutes=$2 WHERE company_id=$1",
            [companies.a, Math.ceil(minutes)],
          );
          assert.equal(
            (await calls.usage(owner)).processing_allowance.state,
            "reached",
          );
          let settings = await calls.getSettings(owner);
          settings = await calls.updateSettings(owner, {
            expected_version: settings.version,
            monthly_processing_minutes: Math.ceil(minutes * 2),
            usage_warning_percent: 40,
          });
          assert.equal(
            (await calls.usage(owner)).processing_allowance.state,
            "near_limit",
          );
          await calls.updateSettings(owner, {
            expected_version: settings.version,
            usage_warning_percent: 80,
          });
          assert.equal(
            (await calls.usage(owner)).processing_allowance.state,
            "available",
          );
          await pool.query(
            "UPDATE comms_call_settings SET monthly_processing_minutes=1000 WHERE company_id=$1",
            [companies.a],
          );
          const foreign = await calls.usage(await f.actor("foreign"));
          assert.equal(foreign.recording_storage_bytes, 0);
          assert.equal(foreign.transcript_seconds, 0);
          assert.equal(foreign.ai_tokens, null);
        },
      );
      await t.test(
        "human summary edits preserve generated evidence and reject stale, unauthorized or ungrounded edits",
        async () => {
          const { recording } = await seed();
          await consent(recording, "transcript");
          await service.request(owner, recording, { kind: "transcript" });
          await service.runOnce();
          await consent(recording, "summary");
          await service.request(owner, recording, { kind: "summary" });
          await service.runOnce();
          const job = (await service.get(owner, recording)).jobs.find(
            (j) => j.kind === "summary",
          );
          const body = {
            expected_version: job.version,
            summary: "Reviewed meeting summary.",
            decisions: [
              {
                title: "Prepare a draft",
                detail: "Needs review",
                segment_ids: ["0:0"],
              },
            ],
            questions: [],
          };
          await assert.rejects(
            service.editSummary(alice, job.id, body),
            (e) => e.status === 403,
          );
          await assert.rejects(
            service.editSummary(owner, job.id, {
              ...body,
              decisions: [{ ...body.decisions[0], segment_ids: ["invented"] }],
            }),
            (e) => e.status === 400,
          );
          const edited = await service.editSummary(owner, job.id, body);
          assert.equal(edited.version, job.version + 1);
          assert.equal(edited.result.result.summary, body.summary);
          assert.equal(
            edited.result.generated_result.summary,
            "A quote was discussed.",
          );
          assert.equal(edited.result.human_review.edited_by, ids.owner);
          await assert.rejects(
            service.editSummary(owner, job.id, body),
            (e) => e.code === "stale_summary",
          );
          const audit = (
            await pool.query(
              "SELECT * FROM comms_summary_edits WHERE job_id=$1",
              [job.id],
            )
          ).rows;
          assert.equal(audit.length, 1);
          assert.equal(audit[0].next_hash.length, 64);
          await service.consent(alice, recording, {
            purpose: "summary",
            consented: false,
          });
          await assert.rejects(
            service.editSummary(owner, job.id, {
              ...body,
              expected_version: edited.version,
            }),
            (e) => e.status === 409,
          );
        },
      );
      await t.test(
        "job recording provenance gates transcript reads after source revocation",
        async () => {
          const { recording } = await seed();
          const asset = (
            await pool.query(
              "SELECT asset_id FROM comms_call_recordings WHERE id=$1",
              [recording],
            )
          ).rows[0].asset_id;
          await pool.query(
            "INSERT INTO schedule_events(id,company_id,title) VALUES('recorded-job',$1,'Sensitive job') ON CONFLICT DO NOTHING",
            [companies.a],
          );
          await pool.query(
            "INSERT INTO comms_asset_provenance(asset_id,company_id,source_type,source_id,context_type) VALUES($1,$2,'job','recorded-job','job')",
            [asset, companies.a],
          );
          await service.get(alice, recording);
          await pool.query(
            "UPDATE employee_permissions SET permission_overrides=permission_overrides||'{\"jobs.view\":false}'::jsonb WHERE user_id=$1",
            [ids.alice],
          );
          await assert.rejects(
            service.get(alice, recording),
            (e) => e.status === 404,
          );
          await pool.query(
            "UPDATE employee_permissions SET permission_overrides=permission_overrides- 'jobs.view' WHERE user_id=$1",
            [ids.alice],
          );
        },
      );
      await t.test(
        "consent revoked during provider work discards the result",
        async () => {
          const { recording } = await seed();
          await consent(recording, "transcript");
          await service.request(owner, recording, { kind: "transcript" });
          let began, release;
          const started = new Promise((r) => (began = r)),
            gate = new Promise((r) => (release = r)),
            original = provider.transcribe;
          provider.transcribe = async () => {
            began();
            await gate;
            return { segments, text: segments[0].text, model: "test-fake" };
          };
          const running = service.runOnce();
          await started;
          await service.consent(alice, recording, {
            purpose: "transcript",
            consented: false,
          });
          release();
          await running;
          provider.transcribe = original;
          const job = (await service.get(owner, recording)).jobs[0];
          assert.equal(job.status, "canceled");
          assert.equal(job.result, null);
        },
      );
      await t.test(
        "configuration missing and exhausted budgets cannot enqueue paid work",
        async () => {
          const { recording } = await seed();
          await consent(recording, "transcript");
          provider.configured = false;
          await assert.rejects(
            service.request(owner, recording, { kind: "transcript" }),
            (e) => e.code === "transcription_not_configured",
          );
          provider.configured = true;
          await pool.query(
            "UPDATE comms_call_settings SET monthly_processing_minutes=0 WHERE company_id=$1",
            [companies.a],
          );
          await assert.rejects(
            service.request(owner, recording, { kind: "transcript" }),
            (e) => e.code === "processing_usage_limit",
          );
        },
      );
    } finally {
      await f.close();
    }
  },
);
