import test from "node:test";
import assert from "node:assert/strict";
import {
  BusinessExceptionError,
  buildBusinessExceptionCandidates,
  buildBusinessExceptionEvaluation,
  compareBusinessExceptions,
  validateBusinessExceptionMutation
} from "../business-exceptions.js";

const now = new Date("2026-08-19T16:00:00Z");

function job(id, overrides = {}) {
  return {
    id,
    title: `Job ${id}`,
    contact_name: `Customer ${id}`,
    start_at: "2026-08-19T15:00:00Z",
    end_at: "2026-08-19T16:00:00Z",
    started_at: null,
    finished_at: null,
    worker_user_ids: [],
    ...overrides
  };
}

test("missed starts use exact grace and critical thresholds without refresh fingerprints", () => {
  const beforeGrace = buildBusinessExceptionCandidates({
    jobs: [job("before", { start_at: "2026-08-19T15:46:00Z", end_at: "2026-08-19T16:46:00Z" })],
    now
  });
  assert.equal(beforeGrace.length, 0);
  const atGrace = buildBusinessExceptionCandidates({
    jobs: [job("grace", { start_at: "2026-08-19T15:45:00Z", end_at: "2026-08-19T16:45:00Z" })],
    now
  })[0];
  assert.equal(atGrace.type, "job_not_started");
  assert.equal(atGrace.severity, "high");
  const critical = buildBusinessExceptionCandidates({ jobs: [job("critical")], now })[0];
  assert.equal(critical.severity, "critical");
  const later = buildBusinessExceptionCandidates({ jobs: [job("critical")], now: "2026-08-19T16:30:00Z" })[0];
  assert.equal(later.fingerprint, critical.fingerprint);
});

test("duration overrun requires positive plan more than 2x and escalates after 3x", () => {
  const exactlyTwice = buildBusinessExceptionCandidates({
    jobs: [job("twice", { start_at: "2026-08-19T14:00:00Z", end_at: "2026-08-19T15:00:00Z", started_at: "2026-08-19T14:00:00Z" })],
    now
  });
  assert.equal(exactlyTwice.some((item) => item.type === "job_duration_overrun"), false);
  const high = buildBusinessExceptionCandidates({
    jobs: [job("high", { start_at: "2026-08-19T14:00:00Z", end_at: "2026-08-19T15:00:00Z", started_at: "2026-08-19T13:59:00Z" })],
    now
  }).find((item) => item.type === "job_duration_overrun");
  assert.equal(high.severity, "high");
  const critical = buildBusinessExceptionCandidates({
    jobs: [job("critical", { start_at: "2026-08-19T14:00:00Z", end_at: "2026-08-19T15:00:00Z", started_at: "2026-08-19T12:59:00Z" })],
    now
  }).find((item) => item.type === "job_duration_overrun");
  assert.equal(critical.severity, "critical");
  assert.equal(buildBusinessExceptionCandidates({
    jobs: [job("invalid", { start_at: "2026-08-19T15:00:00Z", end_at: "2026-08-19T15:00:00Z", started_at: "2026-08-19T14:00:00Z" })],
    now
  }).length, 0);
});

test("schedule conflicts are half-open stable per active worker and job pair", () => {
  const workers = [{ id: "worker-a", display_name: "Alex" }, { id: "deleted", display_name: "Gone", deleted_at: now }];
  const conflicts = buildBusinessExceptionCandidates({
    jobs: [
      job("b", { start_at: "2026-08-20T14:30:00Z", end_at: "2026-08-20T15:30:00Z", worker_user_ids: ["worker-a", "deleted"] }),
      job("a", { start_at: "2026-08-20T14:00:00Z", end_at: "2026-08-20T15:00:00Z", worker_user_ids: ["worker-a", "deleted"] }),
      job("touching", { start_at: "2026-08-20T15:30:00Z", end_at: "2026-08-20T16:00:00Z", worker_user_ids: ["worker-a"] })
    ],
    workers,
    now
  }).filter((item) => item.type === "schedule_conflict");
  assert.equal(conflicts.length, 1);
  assert.equal(conflicts[0].source_id, "worker-a:a:b");
  assert.equal(conflicts[0].metadata.overlap_minutes, 30);
});

test("dense schedule conflicts are bounded and marked partial for safe synchronization", () => {
  const jobs = Array.from({ length: 102 }, (_, index) => job(`dense-${index}`, {
    start_at: "2026-08-20T14:00:00Z",
    end_at: "2026-08-20T15:00:00Z",
    worker_user_ids: ["worker-a"]
  }));
  const evaluation = buildBusinessExceptionEvaluation({
    jobs,
    workers: [{ id: "worker-a", display_name: "Alex" }],
    now
  });
  assert.equal(evaluation.candidates.filter((item) => item.type === "schedule_conflict").length, 100);
  assert.deepEqual(evaluation.truncatedTypes, ["schedule_conflict"]);
});

test("overdue task severity uses priority and 24-hour age while completed tasks disappear", () => {
  const candidates = buildBusinessExceptionCandidates({
    tasks: [
      { id: "recent", title: "Recent", due_date: "2026-08-19T15:30:00Z", priority: "normal", completed: false },
      { id: "old", title: "Old", due_date: "2026-08-18T15:59:00Z", priority: "normal", completed: false },
      { id: "urgent", title: "Urgent", due_date: "2026-08-19T15:59:00Z", priority: "urgent", completed: false },
      { id: "done", title: "Done", due_date: "2026-08-18T00:00:00Z", priority: "urgent", completed: true }
    ],
    now
  }).filter((item) => item.type === "overdue_task");
  assert.equal(candidates.length, 3);
  assert.equal(candidates.find((item) => item.source_id === "recent").severity, "medium");
  assert.equal(candidates.find((item) => item.source_id === "old").severity, "high");
  assert.equal(candidates.find((item) => item.source_id === "urgent").severity, "high");
});

test("open automation dead letters and outbound provider failures become bounded exceptions", () => {
  const candidates = buildBusinessExceptionCandidates({
    automationIssues: [
      { id: "dead", status: "open", attempts: 5, error_code: "timeout", error_message: "Provider timed out", failed_at: now },
      { id: "dismissed", status: "dismissed", attempts: 2, failed_at: now }
    ],
    messageFailures: [
      { id: "sms", direction: "outbound", message_status: "undelivered", conversation_id: "conversation", contact_name: "Morgan", twilio_error_code: "30007", updated_at: now },
      { id: "inbound", direction: "inbound", message_status: "failed", updated_at: now }
    ],
    deliveryUnknownItems: [
      { batch_id: "batch", contact_id: "contact", outcome: "delivery_unknown", provider_message_sid: "SM123", updated_at: now }
    ],
    now
  });
  assert.equal(candidates.find((item) => item.type === "automation_failure").severity, "critical");
  assert.equal(candidates.filter((item) => item.type === "customer_message_failure").length, 2);
  assert.equal(candidates[0].severity, "critical");
  assert.equal(candidates.some((item) => JSON.stringify(item).includes("message body")), false);

  const refreshed = buildBusinessExceptionCandidates({
    messageFailures: [
      { id: "sms", direction: "outbound", message_status: "undelivered", conversation_id: "conversation", contact_name: "Morgan", twilio_error_code: "30007", updated_at: "2026-08-19T16:05:00Z" }
    ],
    deliveryUnknownItems: [
      { batch_id: "batch", contact_id: "contact", outcome: "delivery_unknown", provider_message_sid: "SM123", updated_at: "2026-08-19T16:05:00Z" }
    ],
    now
  });
  assert.equal(
    refreshed.find((item) => item.source_type === "sms_message").fingerprint,
    candidates.find((item) => item.source_type === "sms_message").fingerprint
  );
  assert.equal(
    refreshed.find((item) => item.source_type === "sms_delivery_unknown").fingerprint,
    candidates.find((item) => item.source_type === "sms_delivery_unknown").fingerprint
  );
});

test("candidate sorting is severity then evidence time then stable identity", () => {
  const values = [
    { severity: "medium", type: "z", source_id: "2", due_at: "2026-01-01T00:00:00Z" },
    { severity: "critical", type: "b", source_id: "2", due_at: "2026-02-01T00:00:00Z" },
    { severity: "critical", type: "a", source_id: "1", due_at: "2026-01-01T00:00:00Z" }
  ].sort(compareBusinessExceptions);
  assert.deepEqual(values.map((item) => item.source_id), ["1", "2", "2"]);
});

test("lifecycle mutation validation is exact and snooze is bounded", () => {
  assert.deepEqual(validateBusinessExceptionMutation({ status: "dismissed" }, now), { status: "dismissed", snoozed_until: null });
  assert.equal(
    validateBusinessExceptionMutation({ status: "snoozed", snoozed_until: "2026-08-20T16:00:00Z" }, now).snoozed_until,
    "2026-08-20T16:00:00.000Z"
  );
  assert.throws(
    () => validateBusinessExceptionMutation({ status: "snoozed", snoozed_until: now }, now),
    (error) => error instanceof BusinessExceptionError && error.code === "business_exception_snooze_invalid"
  );
  assert.throws(
    () => validateBusinessExceptionMutation({ status: "dismissed", snoozed_until: "2026-08-20T16:00:00Z" }, now),
    (error) => error.code === "business_exception_snooze_invalid"
  );
  assert.throws(
    () => validateBusinessExceptionMutation({ status: "ignored", extra: true }, now),
    (error) => error.code === "business_exception_mutation_invalid"
  );
});
