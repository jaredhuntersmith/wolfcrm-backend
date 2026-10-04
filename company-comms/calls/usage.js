import { loadActor } from "../access.js";
import { fail, requireCapability } from "./domain.js";

export function allowance(used, limit, warningPercent = 80) {
  const fraction = limit > 0 ? used / limit : used > 0 ? 1 : 0;
  return {
    used,
    limit,
    fraction,
    state:
      limit === 0 || used >= limit
        ? "reached"
        : fraction >= warningPercent / 100
          ? "near_limit"
          : "available",
  };
}

// Operational estimates stay separate from a provider invoice. No media connection
// or provider request is made while reading the company's usage.
export async function readCallUsage(
  db,
  inputActor,
  settings,
  participantSeconds,
) {
  const actor = await loadActor(db, inputActor);
  requireCapability(actor);
  if (!actor.isCompanyOwner) fail(403, "owner_required");
  const company = actor.companyId;
  const s = await settings(db, actor);
  const participant_seconds = await participantSeconds(db, actor);
  const totals = (
    await db.query(
      `SELECT
    date_trunc('month',now()) AS period_start, now() AS measured_at,
    (SELECT count(*) FROM comms_call_sessions WHERE company_id=$1 AND ended_at IS NULL) AS active_calls,
    (SELECT count(*) FROM comms_call_participants p JOIN comms_call_sessions c ON c.id=p.call_id WHERE c.company_id=$1 AND c.ended_at IS NULL AND p.state='joined') AS active_employees,
    (SELECT count(*) FROM comms_guest_sessions WHERE company_id=$1 AND state='joined') AS active_guests,
    (SELECT COALESCE(sum(duration_seconds),0) FROM comms_call_recordings WHERE company_id=$1 AND created_at>=date_trunc('month',now())) AS recording_seconds,
    (SELECT COALESCE(sum(f.byte_size),0) FROM stored_files f WHERE f.company_id=$1 AND f.cloud_status='active' AND f.deleted_at IS NULL AND EXISTS(SELECT 1 FROM comms_call_recordings r WHERE r.asset_id=f.id AND r.company_id=$1)) AS recording_storage_bytes`,
      [company],
    )
  ).rows[0];
  const processing = (
    await db.query(
      `SELECT
    COALESCE(sum(estimated_seconds) FILTER(WHERE kind='transcript'),0) AS transcript_seconds,
    COALESCE(sum(estimated_seconds) FILTER(WHERE kind='summary'),0) AS summary_seconds,
    count(*) FILTER(WHERE kind='summary') AS ai_requests,
    count(*) FILTER(WHERE kind='summary' AND provider_usage IS NOT NULL) AS ai_requests_with_usage,
    sum((provider_usage->>'total_tokens')::bigint) FILTER(WHERE kind='summary') AS ai_tokens
    FROM comms_processing_usage WHERE company_id=$1 AND created_at>=date_trunc('month',now())`,
      [company],
    )
  ).rows[0];
  const caption_seconds = Number(
    (
      await db.query(
        "SELECT COALESCE(sum(reserved_seconds),0) AS seconds FROM comms_caption_usage WHERE company_id=$1 AND created_at>=date_trunc('month',now())",
        [company],
      )
    ).rows[0].seconds,
  );
  const transcript_seconds = Number(processing.transcript_seconds);
  const summary_seconds = Number(processing.summary_seconds);
  return {
    period_start: totals.period_start,
    measured_at: totals.measured_at,
    participant_seconds,
    active_calls: Number(totals.active_calls),
    active_participants:
      Number(totals.active_employees) + Number(totals.active_guests),
    recording_seconds: Number(totals.recording_seconds),
    recording_storage_bytes: Number(totals.recording_storage_bytes),
    transcript_seconds,
    summary_seconds,
    caption_seconds,
    caption_allowance: allowance(
      caption_seconds / 60,
      s.monthly_caption_minutes,
      s.usage_warning_percent,
    ),
    ai_requests: Number(processing.ai_requests),
    ai_requests_with_usage: Number(processing.ai_requests_with_usage),
    ai_tokens:
      processing.ai_tokens === null ? null : Number(processing.ai_tokens),
    participant_allowance: allowance(
      participant_seconds / 60,
      s.monthly_participant_minutes,
      s.usage_warning_percent,
    ),
    processing_allowance: allowance(
      (transcript_seconds + summary_seconds) / 60,
      s.monthly_processing_minutes,
      s.usage_warning_percent,
    ),
    provider_bill_available: false,
    provider_cost: null,
    estimated: true,
  };
}

export function safeProviderUsage(value) {
  if (!value || typeof value !== "object") return null;
  const fields = ["input_tokens", "output_tokens", "total_tokens"];
  if (
    !fields.every((key) => Number.isSafeInteger(value[key]) && value[key] >= 0)
  )
    return null;
  return Object.fromEntries(fields.map((key) => [key, value[key]]));
}
