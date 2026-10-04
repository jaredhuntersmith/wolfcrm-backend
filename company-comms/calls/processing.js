import { safeProviderUsage } from "./usage.js";
import { createTaskInTransaction } from "../tasks.js";
import { hydrateSources, sourceAccessSQL } from "../sources.js";
import { randomUUID, createHash } from "node:crypto";
import {
  loadActor,
  transact,
  conversationJoins,
  conversationAccessSQL,
} from "../access.js";
import { fail, requireCapability, uuid, text } from "./domain.js";

export async function installProcessingSchema(db) {
  await db.query(`
  ALTER TABLE comms_call_settings ADD COLUMN IF NOT EXISTS transcription_enabled boolean NOT NULL DEFAULT false;
  ALTER TABLE comms_call_settings ADD COLUMN IF NOT EXISTS ai_enabled boolean NOT NULL DEFAULT false;
  ALTER TABLE comms_call_settings ADD COLUMN IF NOT EXISTS monthly_processing_minutes integer NOT NULL DEFAULT 1000 CHECK(monthly_processing_minutes BETWEEN 0 AND 1000000);
  ALTER TABLE comms_call_settings ADD COLUMN IF NOT EXISTS processing_retention_days integer NOT NULL DEFAULT 90 CHECK(processing_retention_days BETWEEN 1 AND 3650);
  CREATE TABLE IF NOT EXISTS comms_processing_consents(recording_id uuid NOT NULL REFERENCES comms_call_recordings(id),user_id uuid NOT NULL REFERENCES users(id),purpose text NOT NULL CHECK(purpose IN('transcript','summary')),consented boolean NOT NULL,updated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(recording_id,user_id,purpose));
  CREATE TABLE IF NOT EXISTS comms_processing_jobs(id uuid PRIMARY KEY,company_id uuid NOT NULL REFERENCES companies(id),recording_id uuid NOT NULL REFERENCES comms_call_recordings(id),requested_by uuid NOT NULL REFERENCES users(id),kind text NOT NULL CHECK(kind IN('transcript','summary')),status text NOT NULL DEFAULT 'queued' CHECK(status IN('queued','processing','ready','failed','canceled')),version integer NOT NULL DEFAULT 1,attempts integer NOT NULL DEFAULT 0,error_code text,model text,result jsonb,source_version integer,created_at timestamptz NOT NULL DEFAULT now(),started_at timestamptz,completed_at timestamptz,UNIQUE(recording_id,kind));
  CREATE TABLE IF NOT EXISTS comms_summary_edits(id bigserial PRIMARY KEY,job_id uuid NOT NULL REFERENCES comms_processing_jobs(id),company_id uuid NOT NULL REFERENCES companies(id),edited_by uuid NOT NULL REFERENCES users(id),revision integer NOT NULL,previous_hash text NOT NULL,next_hash text NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(job_id,revision));
  CREATE INDEX IF NOT EXISTS comms_processing_queue ON comms_processing_jobs(created_at) WHERE status='queued';
  CREATE TABLE IF NOT EXISTS comms_processing_usage(id uuid PRIMARY KEY,company_id uuid NOT NULL REFERENCES companies(id),job_id uuid NOT NULL REFERENCES comms_processing_jobs(id),kind text NOT NULL,estimated_seconds double precision NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
  ALTER TABLE comms_processing_usage ADD COLUMN IF NOT EXISTS provider_usage jsonb;
  CREATE INDEX IF NOT EXISTS comms_processing_usage_month ON comms_processing_usage(company_id,created_at);
  CREATE TABLE IF NOT EXISTS comms_review_actions(id uuid PRIMARY KEY,job_id uuid NOT NULL REFERENCES comms_processing_jobs(id),company_id uuid NOT NULL REFERENCES companies(id),title text NOT NULL,detail text NOT NULL,segment_ids jsonb NOT NULL,state text NOT NULL DEFAULT 'proposed' CHECK(state IN('proposed','approved','rejected')),reviewed_by uuid REFERENCES users(id),reviewed_at timestamptz,task_id text,version integer NOT NULL DEFAULT 1);
 `);
}

export function createProcessingService({
  pool,
  calls,
  authorizeConversation,
  publish,
  provider,
}) {
  const transaction = (fn) => transact(pool, fn);
  const authorize = async (
    db,
    a,
    recordingId,
    capability = "communications.calls",
  ) => {
    a = await loadActor(db, a);
    requireCapability(a, capability);
    const recording = (
      await db.query(
        "SELECT * FROM comms_call_recordings WHERE id=$1 AND company_id=$2 FOR UPDATE",
        [uuid(recordingId), a.companyId],
      )
    ).rows[0];
    if (!recording) fail(404, "recording_unavailable");
    const call = (
      await db.query("SELECT * FROM comms_call_sessions WHERE id=$1", [
        recording.call_id,
      ])
    ).rows[0];
    await authorizeConversation(db, a, call.conversation_id, { capability });
    if (call.meeting_id) {
      const meeting = (
        await db.query(
          "SELECT source_conversation_id FROM comms_meetings WHERE id=$1 AND company_id=$2",
          [call.meeting_id, a.companyId],
        )
      ).rows[0];
      if (meeting?.source_conversation_id)
        await authorizeConversation(db, a, meeting.source_conversation_id, {
          capability,
        });
    }
    if (
      (
        await db.query(
          "SELECT 1 FROM comms_call_participants WHERE call_id=$1 AND user_id=$2 AND state='removed'",
          [call.id, a.userId],
        )
      ).rowCount
    )
      fail(404, "recording_unavailable");
    const asset = (
      await db.query(
        "SELECT * FROM stored_files WHERE id=$1 AND company_id=$2 AND cloud_status='active' AND deleted_at IS NULL",
        [recording.asset_id, a.companyId],
      )
    ).rows[0];
    if (recording.status !== "ready" || !asset)
      fail(409, "recording_not_ready");
    const refs = (
      await db.query(
        "SELECT source_type,source_id,context_type,context_id FROM comms_asset_provenance WHERE asset_id=$1 AND company_id=$2",
        [asset.id, a.companyId],
      )
    ).rows;
    const sources = await hydrateSources(db, a, refs);
    if (
      [...sources.values()].some(
        (card) => !card.accessible || card.text === "Unavailable",
      )
    )
      fail(404, "recording_unavailable");
    return { a, recording, call, asset };
  };
  const consentStatus = async (db, r, kind) => {
    // Only people whose participation is provider-confirmed are processing subjects.
    const rows = (
      await db.query(
        `SELECT p.user_id,COALESCE(s.consented,false) AS consented FROM comms_call_participants p LEFT JOIN comms_processing_consents s ON s.recording_id=$2 AND s.user_id=p.user_id AND s.purpose=$3 WHERE p.call_id=$1 AND (p.joined_at IS NOT NULL OR p.user_id=$4)`,
        [r.call_id, r.id, kind, r.requested_by],
      )
    ).rows;
    return {
      all: rows.length > 0 && rows.every((p) => p.consented),
      participants: rows,
    };
  };
  const capability = (kind) =>
    kind === "summary" ? "communications.ai" : "communications.transcribe";
  const publicJob = (j) => {
    if (!j) return null;
    const { requested_by, ...safe } = j;
    return safe;
  };
  const validate = async (db, a, id, kind) => {
    const context = await authorize(db, a, id, capability(kind));
    const settings = (
      await db.query(
        "SELECT * FROM comms_call_settings WHERE company_id=$1 FOR UPDATE",
        [context.a.companyId],
      )
    ).rows[0];
    if (
      !settings?.[kind === "summary" ? "ai_enabled" : "transcription_enabled"]
    )
      fail(403, "processing_disabled");
    if (!(await consentStatus(db, context.recording, kind)).all)
      fail(409, "processing_consent_required");
    if (
      kind === "summary" &&
      !(await consentStatus(db, context.recording, "transcript")).all
    )
      fail(409, "processing_consent_required");
    return { ...context, settings };
  };
  const service = {
    async export(a, id) {
      return transaction(async (db) => {
        const context = await authorize(db, a, id, "communications.transcribe");
        requireCapability(context.a, "communications.export");
        if (!(await consentStatus(db, context.recording, "transcript")).all)
          fail(409, "processing_consent_required");
        const transcript = (
          await db.query(
            "SELECT * FROM comms_processing_jobs WHERE recording_id=$1 AND kind='transcript' AND status='ready'",
            [id],
          )
        ).rows[0];
        if (!transcript?.result) fail(409, "transcript_not_ready");
        const lines = transcript.result.segments.map(
          (segment) =>
            `[${segment.start.toFixed(1)}s] ${segment.speaker}: ${segment.text}`,
        );
        await db.query(
          "INSERT INTO comms_call_audit(company_id,call_id,actor_user_id,action) VALUES($1,$2,$3,$4)",
          [
            context.a.companyId,
            context.call.id,
            context.a.userId,
            "transcript.exported",
          ],
        );
        return {
          filename: "Meeting transcript.txt",
          mime_type: "text/plain",
          text:
            "Meeting transcript — automatic, unverified speaker labels\n\n" +
            lines.join("\n\n"),
        };
      });
    },
    async remove(a, id) {
      return transaction(async (db) => {
        const context = await authorize(db, a, id, "communications.record");
        if (
          !context.a.isCompanyOwner &&
          context.call.host_user_id !== context.a.userId &&
          context.recording.requested_by !== context.a.userId
        )
          fail(403, "host_required");
        await db.query(
          "UPDATE comms_processing_jobs SET status='canceled',result=NULL,error_code='removed_by_host',version=version+1 WHERE recording_id=$1",
          [id],
        );
        await db.query(
          "UPDATE comms_task_links SET revoked_at=now() WHERE source_type='recording_review' AND source_id IN (SELECT a.id::text FROM comms_review_actions a JOIN comms_processing_jobs j ON j.id=a.job_id WHERE j.recording_id=$1)",
          [id],
        );
        await db.query(
          "INSERT INTO comms_call_audit(company_id,call_id,actor_user_id,action) VALUES($1,$2,$3,$4)",
          [
            context.a.companyId,
            context.call.id,
            context.a.userId,
            "processing.removed",
          ],
        );
        return { ok: true };
      });
    },
    async get(a, recordingId) {
      return transaction(async (db) => {
        const { a: current, recording } = await authorize(db, a, recordingId);
        const jobs = (
          await db.query(
            "SELECT * FROM comms_processing_jobs WHERE recording_id=$1 ORDER BY created_at",
            [recording.id],
          )
        ).rows;
        const consents = {
          transcript: await consentStatus(db, recording, "transcript"),
          summary: await consentStatus(db, recording, "summary"),
        };
        const canTranscript =
          current.isCompanyOwner ||
          current.permissions.capabilities["communications.transcribe"];
        const canSummary =
          current.isCompanyOwner ||
          current.permissions.capabilities["communications.ai"];
        const visible = jobs
          .filter((j) => (j.kind === "transcript" ? canTranscript : canSummary))
          .map((j) =>
            publicJob({ ...j, result: consents[j.kind].all ? j.result : null }),
          );
        const actions =
          canSummary && consents.summary.all
            ? (
                await db.query(
                  "SELECT a.* FROM comms_review_actions a JOIN comms_processing_jobs j ON j.id=a.job_id WHERE j.recording_id=$1 AND j.status='ready' ORDER BY a.id",
                  [recording.id],
                )
              ).rows
            : [];
        return {
          recording_id: recording.id,
          jobs: visible,
          consents,
          actions,
          transcription_configured: provider.configured,
          ai_configured: provider.aiConfigured,
        };
      });
    },
    async consent(a, id, b) {
      return transaction(async (db) => {
        if (
          !["transcript", "summary"].includes(b.purpose) ||
          typeof b.consented !== "boolean"
        )
          fail(400, "invalid_processing_consent");
        const { a: current, recording, call } = await authorize(db, a, id);
        const subjects = await consentStatus(db, recording, b.purpose);
        if (!subjects.participants.some((p) => p.user_id === current.userId))
          fail(403, "participant_required");
        await db.query(
          "INSERT INTO comms_processing_consents(recording_id,user_id,purpose,consented) VALUES($1,$2,$3,$4) ON CONFLICT(recording_id,user_id,purpose) DO UPDATE SET consented=excluded.consented,updated_at=now()",
          [id, current.userId, b.purpose, b.consented],
        );
        if (!b.consented)
          await db.query(
            "UPDATE comms_processing_jobs SET status='canceled',result=NULL,error_code='consent_withdrawn',version=version+1 WHERE recording_id=$1 AND (kind=$2 OR $2='transcript')",
            [id, b.purpose],
          );
        if (!b.consented)
          await db.query(
            "UPDATE comms_task_links SET revoked_at=now() WHERE source_type='recording_review' AND source_id IN (SELECT a.id::text FROM comms_review_actions a JOIN comms_processing_jobs j ON j.id=a.job_id WHERE j.recording_id=$1)",
            [id],
          );
        await db.query(
          "INSERT INTO comms_call_audit(company_id,call_id,actor_user_id,action) VALUES($1,$2,$3,$4)",
          [
            current.companyId,
            call.id,
            current.userId,
            b.purpose + (b.consented ? ".consented" : ".consent_withdrawn"),
          ],
        );
        await publish(
          db,
          current,
          call.conversation_id,
          "call.processing_consent",
          id,
          { recording_id: id },
        );
        return { ok: true };
      });
    },
    async request(a, id, b) {
      return transaction(async (db) => {
        const kind = b.kind;
        if (!["transcript", "summary"].includes(kind))
          fail(400, "invalid_processing_kind");
        const {
          a: current,
          recording,
          call,
          settings,
        } = await validate(db, a, id, kind);
        if (!(kind === "summary" ? provider.aiConfigured : provider.configured))
          fail(
            503,
            kind === "summary"
              ? "comms_ai_not_configured"
              : "transcription_not_configured",
          );
        const existing = (
          await db.query(
            "SELECT * FROM comms_processing_jobs WHERE recording_id=$1 AND kind=$2 FOR UPDATE",
            [id, kind],
          )
        ).rows[0];
        if (
          existing &&
          ["queued", "processing", "ready"].includes(existing.status)
        )
          return publicJob(existing);
        if (existing && b.expected_version !== existing.version)
          fail(409, "stale_processing_job");
        if (kind === "summary") {
          const transcript = (
            await db.query(
              "SELECT * FROM comms_processing_jobs WHERE recording_id=$1 AND kind='transcript' AND status='ready'",
              [id],
            )
          ).rows[0];
          if (!transcript) fail(409, "transcript_not_ready");
        }
        const used = Number(
          (
            await db.query(
              "SELECT COALESCE(sum(estimated_seconds),0) AS used FROM comms_processing_usage WHERE company_id=$1 AND created_at>=date_trunc('month',now())",
              [current.companyId],
            )
          ).rows[0].used,
        );
        if (
          used + Number(recording.duration_seconds || 0) >
          settings.monthly_processing_minutes * 60
        )
          fail(429, "processing_usage_limit");
        const job = (
          await db.query(
            "INSERT INTO comms_processing_jobs(id,company_id,recording_id,requested_by,kind) VALUES($1,$2,$3,$4,$5) ON CONFLICT(recording_id,kind) DO UPDATE SET status='queued',requested_by=excluded.requested_by,error_code=NULL,result=NULL,version=comms_processing_jobs.version+1 RETURNING *",
            [
              existing?.id || randomUUID(),
              current.companyId,
              id,
              current.userId,
              kind,
            ],
          )
        ).rows[0];
        await publish(
          db,
          current,
          call.conversation_id,
          "call.processing_queued",
          job.id,
          { recording_id: id },
        );
        return publicJob(job);
      });
    },
    async runOnce() {
      let snapshot;
      await transaction(async (db) => {
        await db.query(
          "UPDATE comms_processing_jobs j SET status='canceled',result=NULL,error_code='retention_expired',version=j.version+1 FROM comms_call_settings s WHERE s.company_id=j.company_id AND j.created_at<now()-s.processing_retention_days*interval '1 day' AND j.status<>'canceled'",
        );
        await db.query(
          "UPDATE comms_task_links SET revoked_at=now() WHERE source_type='recording_review' AND revoked_at IS NULL AND source_id IN (SELECT a.id::text FROM comms_review_actions a JOIN comms_processing_jobs j ON j.id=a.job_id WHERE j.status='canceled')",
        );
        // Interrupted paid requests require explicit review/retry; never silently repeat uncertain charges.
        await db.query(
          "UPDATE comms_processing_jobs SET status='failed',error_code='processing_interrupted',version=version+1 WHERE status='processing' AND started_at<now()-interval '30 minutes'",
        );
        const job = (
          await db.query(
            "SELECT * FROM comms_processing_jobs WHERE status='queued' ORDER BY created_at LIMIT 1",
          )
        ).rows[0];
        if (!job) return;
        await db.query("SAVEPOINT processing_claim");
        try {
          const context = await validate(
            db,
            { companyId: job.company_id, userId: job.requested_by },
            job.recording_id,
            job.kind,
          );
          const claim = (
            await db.query(
              "SELECT status FROM comms_processing_jobs WHERE id=$1 FOR UPDATE",
              [job.id],
            )
          ).rows[0];
          if (claim.status !== "queued") return;
          const used = Number(
            (
              await db.query(
                "SELECT COALESCE(sum(estimated_seconds),0) AS used FROM comms_processing_usage WHERE company_id=$1 AND created_at>=date_trunc('month',now())",
                [job.company_id],
              )
            ).rows[0].used,
          );
          if (
            used + Number(context.recording.duration_seconds || 0) >
            context.settings.monthly_processing_minutes * 60
          )
            fail(429, "processing_usage_limit");
          const transcript =
            job.kind === "summary"
              ? (
                  await db.query(
                    "SELECT * FROM comms_processing_jobs WHERE recording_id=$1 AND kind='transcript' AND status='ready'",
                    [job.recording_id],
                  )
                ).rows[0]
              : null;
          if (job.kind === "summary" && !transcript)
            fail(409, "transcript_not_ready");
          await db.query(
            "UPDATE comms_processing_jobs SET status='processing',started_at=now(),attempts=attempts+1,source_version=$2 WHERE id=$1",
            [job.id, transcript?.version || context.asset.version],
          );
          const usageID = randomUUID();
          await db.query(
            "INSERT INTO comms_processing_usage(id,company_id,job_id,kind,estimated_seconds) VALUES($1,$2,$3,$4,$5)",
            [
              usageID,
              job.company_id,
              job.id,
              job.kind,
              Number(context.recording.duration_seconds || 0),
            ],
          );
          snapshot = { job, ...context, transcript, usageID };
        } catch (e) {
          await db.query("ROLLBACK TO SAVEPOINT processing_claim");
          await db.query(
            "UPDATE comms_processing_jobs SET status='canceled',error_code=$2,version=version+1 WHERE id=$1",
            [job.id, e.code || "processing_access_changed"],
          );
        }
      });
      if (!snapshot) return;
      const { job, asset, transcript } = snapshot;
      try {
        const output =
          job.kind === "transcript"
            ? await provider.transcribe(asset)
            : await provider.summarize(transcript.result);
        const usage = safeProviderUsage(output.usage);
        if (usage)
          await pool.query(
            "UPDATE comms_processing_usage SET provider_usage=$2 WHERE id=$1",
            [snapshot.usageID, usage],
          );
        if (job.kind === "transcript") validateTranscript(output);
        await transaction(async (db) => {
          const context = await validate(
            db,
            { companyId: job.company_id, userId: job.requested_by },
            job.recording_id,
            job.kind,
          );
          const current = (
            await db.query(
              "SELECT * FROM comms_processing_jobs WHERE id=$1 FOR UPDATE",
              [job.id],
            )
          ).rows[0];
          if (
            current.status !== "processing" ||
            current.version !== job.version
          )
            return;
          if (context.asset.version !== asset.version)
            fail(409, "recording_changed");
          if (job.kind === "summary") {
            const source = (
              await db.query(
                "SELECT * FROM comms_processing_jobs WHERE recording_id=$1 AND kind='transcript'",
                [job.recording_id],
              )
            ).rows[0];
            if (
              source.status !== "ready" ||
              source.version !== transcript.version
            )
              fail(409, "transcript_changed");
            validateSummary(output.result, transcript.result.segments);
            await db.query(
              "DELETE FROM comms_review_actions WHERE job_id=$1 AND state='proposed'",
              [job.id],
            );
            for (const task of output.result.tasks)
              await db.query(
                "INSERT INTO comms_review_actions(id,job_id,company_id,title,detail,segment_ids) VALUES($1,$2,$3,$4,$5,$6)",
                [
                  randomUUID(),
                  job.id,
                  job.company_id,
                  task.title,
                  task.detail,
                  JSON.stringify(task.segment_ids),
                ],
              );
          }
          await db.query(
            "UPDATE comms_processing_jobs SET status='ready',result=$2,model=$3,completed_at=now() WHERE id=$1",
            [job.id, output, output.model],
          );
          await publish(
            db,
            context.a,
            context.call.conversation_id,
            "call.processing_ready",
            job.id,
            { recording_id: job.recording_id },
          );
        });
      } catch (e) {
        await pool.query(
          "UPDATE comms_processing_jobs SET status='failed',error_code=$2,version=version+1 WHERE id=$1 AND status='processing' AND version=$3",
          [
            job.id,
            String(e.code || "processing_provider_failed").slice(0, 100),
            job.version,
          ],
        );
      }
    },
    async editSummary(a, id, b) {
      return transaction(async (db) => {
        const job = (
          await db.query(
            "SELECT * FROM comms_processing_jobs WHERE id=$1 AND company_id=$2 AND kind='summary'",
            [uuid(id), a.companyId],
          )
        ).rows[0];
        if (!job) fail(404, "summary_unavailable");
        const {
          a: current,
          recording,
          call,
        } = await authorize(db, a, job.recording_id, "communications.ai");
        requireCapability(current, "communications.send");
        Object.assign(
          job,
          (
            await db.query(
              "SELECT * FROM comms_processing_jobs WHERE id=$1 FOR UPDATE",
              [job.id],
            )
          ).rows[0],
        );
        if (job.status !== "ready" || !job.result?.result)
          fail(409, "summary_unavailable");
        if (job.version !== b.expected_version) fail(409, "stale_summary");
        if (
          !(await consentStatus(db, recording, "summary")).all ||
          !(await consentStatus(db, recording, "transcript")).all
        )
          fail(409, "processing_consent_required");
        const transcript = (
          await db.query(
            "SELECT result FROM comms_processing_jobs WHERE recording_id=$1 AND kind='transcript' AND status='ready'",
            [recording.id],
          )
        ).rows[0];
        if (!transcript?.result?.segments) fail(409, "transcript_not_ready");
        const next = {
          summary: b.summary,
          decisions: b.decisions,
          questions: b.questions,
          tasks: job.result.result.tasks,
        };
        try {
          validateSummary(next, transcript.result.segments);
        } catch (error) {
          if (error.status === 502) fail(400, error.code);
          throw error;
        }
        const hash = (value) =>
          createHash("sha256").update(JSON.stringify(value)).digest("hex");
        const result = {
          ...job.result,
          generated_result: job.result.generated_result || job.result.result,
          result: next,
          human_review: {
            edited_by: current.userId,
            edited_at: new Date().toISOString(),
          },
        };
        const updated = (
          await db.query(
            "UPDATE comms_processing_jobs SET result=$2,version=version+1 WHERE id=$1 RETURNING *",
            [job.id, result],
          )
        ).rows[0];
        await db.query(
          "INSERT INTO comms_summary_edits(job_id,company_id,edited_by,revision,previous_hash,next_hash) VALUES($1,$2,$3,$4,$5,$6)",
          [
            job.id,
            current.companyId,
            current.userId,
            updated.version,
            hash(job.result.result),
            hash(next),
          ],
        );
        await publish(
          db,
          current,
          call.conversation_id,
          "call.summary_edited",
          job.id,
          { recording_id: recording.id },
        );
        return publicJob(updated);
      });
    },
    async review(a, id, b) {
      return transaction(async (db) => {
        const action = (
          await db.query(
            "SELECT a.*,j.recording_id,j.status AS job_status FROM comms_review_actions a JOIN comms_processing_jobs j ON j.id=a.job_id WHERE a.id=$1 AND a.company_id=$2",
            [uuid(id), a.companyId],
          )
        ).rows[0];
        if (!action) fail(404, "proposal_unavailable");
        const {
          a: current,
          recording,
          call,
        } = await authorize(db, a, action.recording_id, "communications.ai");
        Object.assign(
          action,
          (
            await db.query(
              "SELECT * FROM comms_review_actions WHERE id=$1 FOR UPDATE",
              [id],
            )
          ).rows[0],
        );
        if (
          !(await consentStatus(db, recording, "summary")).all ||
          action.job_status !== "ready"
        )
          fail(409, "summary_unavailable");
        if (action.state === "approved")
          return { task_id: action.task_id, state: action.state };
        if (action.version !== b.expected_version) fail(409, "stale_proposal");
        if (b.action === "reject") {
          await db.query(
            "UPDATE comms_review_actions SET state='rejected',reviewed_by=$2,reviewed_at=now(),version=version+1 WHERE id=$1",
            [id, current.userId],
          );
          return { state: "rejected" };
        }
        if (b.action !== "approve") fail(400, "invalid_review");
        requireCapability(current, "tasks.manage");
        requireCapability(current, "communications.tasks");
        if (action.state !== "proposed") fail(409, "proposal_already_reviewed");
        const title = text(b.title || action.title, 160),
          detail = text(b.detail ?? action.detail, 5000);
        if (!title) fail(400, "task_title_required");
        const assignees = [
          ...new Set((b.assignee_ids || [current.userId]).map(uuid)),
        ];
        if (!assignees.length || assignees.length > 30)
          fail(400, "invalid_assignees");
        for (const userId of assignees) {
          const member = await loadActor(db, {
            userId,
            companyId: current.companyId,
          });
          requireCapability(member, "tasks.view");
          await authorizeConversation(db, member, call.conversation_id);
        }
        const due = b.due_date ? new Date(b.due_date) : null;
        if (due && !Number.isFinite(+due)) fail(400, "invalid_due_date");
        const refs = (
          await db.query(
            "SELECT source_type,source_id,context_type,context_id FROM comms_asset_provenance WHERE asset_id=$1 AND company_id=$2",
            [recording.asset_id, current.companyId],
          )
        ).rows;
        await db.query(
          "UPDATE comms_review_actions SET state='approved',reviewed_by=$2,reviewed_at=now(),version=version+1 WHERE id=$1",
          [id, current.userId],
        );
        const task = await createTaskInTransaction(
          db,
          current,
          {
            conversation_id: call.conversation_id,
            source_type: "recording_review",
            source_id: id,
            recording_id: recording.id,
            requirements: ["communications.ai"],
            source_refs: refs,
          },
          {
            client_key: "comms-review:" + id,
            title,
            detail,
            assignee_ids: assignees,
            due_date: due?.toISOString() || null,
          },
        );
        const taskId = task.id;
        await db.query(
          "UPDATE comms_review_actions SET task_id=$2 WHERE id=$1",
          [id, taskId],
        );
        await db.query(
          "INSERT INTO comms_call_audit(company_id,call_id,actor_user_id,action) VALUES($1,$2,$3,$4)",
          [
            current.companyId,
            call.id,
            current.userId,
            "processing.task_approved",
          ],
        );
        await publish(
          db,
          current,
          call.conversation_id,
          "call.task_created",
          id,
          { task_id: taskId, recording_id: recording.id },
        );
        return { task_id: taskId, state: "approved" };
      });
    },
  };
  return service;
}
export function validateSummary(result, segments) {
  if (
    !result ||
    typeof result.summary !== "string" ||
    result.summary.length > 20000
  )
    fail(502, "invalid_summary_output");
  const ids = new Set(segments.map((s) => s.id));
  for (const name of ["decisions", "questions", "tasks"]) {
    if (!Array.isArray(result[name]) || result[name].length > 100)
      fail(502, "invalid_summary_output");
    for (const item of result[name])
      if (
        typeof item.title !== "string" ||
        !item.title.trim() ||
        item.title.length > 160 ||
        typeof item.detail !== "string" ||
        item.detail.length > 5000 ||
        !Array.isArray(item.segment_ids) ||
        !item.segment_ids.length ||
        item.segment_ids.length > 50 ||
        item.segment_ids.some((id) => !ids.has(id))
      )
        fail(502, "summary_evidence_invalid");
  }
}

export function validateTranscript(result) {
  if (
    !Array.isArray(result?.segments) ||
    !result.segments.length ||
    result.segments.length > 100000 ||
    typeof result.text !== "string" ||
    result.text.length > 2000000
  )
    fail(502, "invalid_transcript_output");
  const ids = new Set();
  for (const segment of result.segments) {
    if (
      typeof segment.id !== "string" ||
      segment.id.length > 80 ||
      ids.has(segment.id) ||
      typeof segment.text !== "string" ||
      segment.text.length > 10000 ||
      typeof segment.speaker !== "string" ||
      segment.speaker.length > 160 ||
      !Number.isFinite(segment.start) ||
      !Number.isFinite(segment.end) ||
      segment.start < 0 ||
      segment.end < segment.start
    )
      fail(502, "invalid_transcript_output");
    ids.add(segment.id);
  }
}

// Apply before matching text, counts or snippets; aliases are internal code constants only.
export function processingSearchSQL(
  actor,
  jobAlias = "j",
  recordingAlias = "r",
  callAlias = "cs",
  assetAlias = "f",
) {
  const caps = actor.permissions?.capabilities || {};
  if (!caps["communications.view"] || !caps["communications.calls"])
    return "false";
  const permitted = [];
  if (caps["communications.transcribe"]) permitted.push("'transcript'");
  if (caps["communications.ai"]) permitted.push("'summary'");
  if (!permitted.length) return "false";
  const consent = (purpose) =>
    `NOT EXISTS(SELECT 1 FROM comms_call_participants p LEFT JOIN comms_processing_consents pc ON pc.recording_id=${recordingAlias}.id AND pc.user_id=p.user_id AND pc.purpose=${purpose} WHERE p.call_id=${callAlias}.id AND (p.joined_at IS NOT NULL OR p.user_id=${recordingAlias}.requested_by) AND COALESCE(pc.consented,false)=false)`;
  return `(${jobAlias}.company_id=$2 AND ${jobAlias}.kind IN(${permitted.join(",")}) AND ${jobAlias}.status='ready' AND ${jobAlias}.result IS NOT NULL AND ${recordingAlias}.company_id=$2 AND ${recordingAlias}.status='ready' AND ${assetAlias}.company_id=$2 AND ${assetAlias}.cloud_status='active' AND ${assetAlias}.deleted_at IS NULL AND NOT EXISTS(SELECT 1 FROM comms_asset_provenance recording_source WHERE recording_source.asset_id=${assetAlias}.id AND NOT ${sourceAccessSQL(actor, "recording_source")}) AND NOT EXISTS(SELECT 1 FROM comms_meetings meeting_source WHERE meeting_source.id=${callAlias}.meeting_id AND meeting_source.source_conversation_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM conversations c ${conversationJoins} WHERE c.id=meeting_source.source_conversation_id AND ${conversationAccessSQL(actor)})) AND NOT EXISTS(SELECT 1 FROM comms_call_participants p WHERE p.call_id=${callAlias}.id AND p.user_id=$1 AND p.state='removed') AND EXISTS(SELECT 1 FROM conversations c ${conversationJoins} WHERE c.id=${callAlias}.conversation_id AND ${conversationAccessSQL(actor)}) AND ${consent(jobAlias + ".kind")} AND (${jobAlias}.kind<>'summary' OR ${consent("'transcript'")}))`;
}
