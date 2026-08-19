import { createHash } from "crypto";

export const BUSINESS_EXCEPTION_LIMITS = Object.freeze({
  maximumJobs: 200,
  maximumTasks: 100,
  maximumAutomationIssues: 100,
  maximumMessageFailures: 100,
  maximumScheduleConflicts: 100,
  maximumReturned: 100,
  missedStartGraceMinutes: 15,
  minimumOverrunMinutes: 30,
  maximumSnoozeDays: 30,
  maximumTextLength: 500
});

export const BUSINESS_EXCEPTION_TYPES = Object.freeze([
  "job_not_started",
  "job_duration_overrun",
  "schedule_conflict",
  "overdue_task",
  "automation_failure",
  "customer_message_failure"
]);

export class BusinessExceptionError extends Error {
  constructor(code, message, statusCode = 400) {
    super(message);
    this.name = "BusinessExceptionError";
    this.code = code;
    this.statusCode = statusCode;
  }
}

export function buildBusinessExceptionCandidates({
  jobs = [],
  tasks = [],
  automationIssues = [],
  messageFailures = [],
  deliveryUnknownItems = [],
  workers = [],
  now = new Date()
} = {}) {
  return buildBusinessExceptionEvaluation({
    jobs, tasks, automationIssues, messageFailures, deliveryUnknownItems, workers, now
  }).candidates;
}

export function buildBusinessExceptionEvaluation({
  jobs = [],
  tasks = [],
  automationIssues = [],
  messageFailures = [],
  deliveryUnknownItems = [],
  workers = [],
  now = new Date()
} = {}) {
  const current = validDate(now);
  if (!current) throw new BusinessExceptionError("business_exception_now_invalid", "Exception evaluation time is invalid.");
  assertBounded(jobs, BUSINESS_EXCEPTION_LIMITS.maximumJobs, "jobs");
  assertBounded(tasks, BUSINESS_EXCEPTION_LIMITS.maximumTasks, "tasks");
  assertBounded(automationIssues, BUSINESS_EXCEPTION_LIMITS.maximumAutomationIssues, "automation issues");
  assertBounded(messageFailures, BUSINESS_EXCEPTION_LIMITS.maximumMessageFailures, "message failures");
  assertBounded(deliveryUnknownItems, BUSINESS_EXCEPTION_LIMITS.maximumMessageFailures, "uncertain message deliveries");
  assertBounded(workers, BUSINESS_EXCEPTION_LIMITS.maximumJobs, "workers");

  const jobEvaluation = detectJobExceptions(jobs, workers, current);
  const candidates = [
    ...jobEvaluation.candidates,
    ...detectTaskExceptions(tasks, current),
    ...detectAutomationExceptions(automationIssues),
    ...detectMessageExceptions(messageFailures, deliveryUnknownItems)
  ];
  const deduped = new Map();
  for (const candidate of candidates) {
    const key = `${candidate.type}:${candidate.source_type}:${candidate.source_id}`;
    if (!deduped.has(key)) deduped.set(key, candidate);
  }
  return {
    candidates: [...deduped.values()].sort(compareBusinessExceptions),
    truncatedTypes: jobEvaluation.conflictsTruncated ? ["schedule_conflict"] : []
  };
}

export function validateBusinessExceptionMutation(raw = {}, now = new Date()) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new BusinessExceptionError("business_exception_mutation_invalid", "The exception update is invalid.");
  }
  const unknown = Object.keys(raw).filter((key) => !["status", "snoozed_until"].includes(key));
  if (unknown.length) {
    throw new BusinessExceptionError("business_exception_mutation_invalid", `Unsupported exception field: ${unknown[0]}.`);
  }
  const status = clean(raw.status).toLowerCase();
  if (!["open", "snoozed", "dismissed", "resolved"].includes(status)) {
    throw new BusinessExceptionError("business_exception_status_invalid", "Choose Open, Snoozed, Dismissed, or Resolved.");
  }
  const current = validDate(now);
  if (!current) throw new BusinessExceptionError("business_exception_now_invalid", "Exception update time is invalid.");
  if (status !== "snoozed") {
    if (raw.snoozed_until != null && raw.snoozed_until !== "") {
      throw new BusinessExceptionError("business_exception_snooze_invalid", "Only a snoozed exception may have a snooze deadline.");
    }
    return { status, snoozed_until: null };
  }
  const snoozedUntil = validDate(raw.snoozed_until);
  const maximum = new Date(current.getTime() + BUSINESS_EXCEPTION_LIMITS.maximumSnoozeDays * 86_400_000);
  if (!snoozedUntil || snoozedUntil <= current || snoozedUntil > maximum) {
    throw new BusinessExceptionError(
      "business_exception_snooze_invalid",
      `Snooze must end within the next ${BUSINESS_EXCEPTION_LIMITS.maximumSnoozeDays} days.`
    );
  }
  return { status, snoozed_until: snoozedUntil.toISOString() };
}

export function compareBusinessExceptions(lhs, rhs) {
  const severityRank = { critical: 0, high: 1, medium: 2, low: 3 };
  const severity = (severityRank[lhs.severity] ?? 9) - (severityRank[rhs.severity] ?? 9);
  if (severity) return severity;
  const leftTime = validDate(lhs.detected_at || lhs.due_at)?.getTime() || 0;
  const rightTime = validDate(rhs.detected_at || rhs.due_at)?.getTime() || 0;
  if (leftTime !== rightTime) return leftTime - rightTime;
  return `${lhs.type}:${lhs.source_id}`.localeCompare(`${rhs.type}:${rhs.source_id}`);
}

function detectJobExceptions(rawJobs, rawWorkers, now) {
  const activeWorkers = new Map(rawWorkers.flatMap((worker) => {
    const id = clean(worker?.id);
    if (!id || worker?.deleted_at) return [];
    return [[id, clean(worker.display_name) || clean(worker.email) || "Assigned employee"]];
  }));
  const jobs = rawJobs.map(normalizeJob).filter(Boolean);
  const candidates = [];
  for (const job of jobs) {
    if (job.finishedAt) continue;
    if (!job.startedAt && now.getTime() - job.start.getTime() >= BUSINESS_EXCEPTION_LIMITS.missedStartGraceMinutes * 60_000) {
      const minutesLate = Math.max(0, Math.floor((now.getTime() - job.start.getTime()) / 60_000));
      candidates.push(candidate({
        type: "job_not_started",
        severity: minutesLate >= 60 ? "critical" : "high",
        sourceType: "scheduled_job",
        sourceId: job.id,
        fingerprintParts: [job.start, job.end, job.workerIDs, minutesLate >= 60 ? "critical" : "high"],
        title: "Job has not started",
        explanation: `${job.displayName} was scheduled to start ${minutesLate} minute${minutesLate === 1 ? "" : "s"} ago, but WolfCRM has no start record.`,
        recommendedAction: "Check on the assigned crew, then start, reschedule, or complete the job as appropriate.",
        destination: { type: "scheduled_job", id: job.id },
        metadata: { job_id: job.id, minutes_late: minutesLate, worker_user_ids: job.workerIDs },
        dueAt: job.start
      }));
    }
    if (job.startedAt) {
      const plannedMinutes = Math.floor((job.end.getTime() - job.start.getTime()) / 60_000);
      const actualMinutes = Math.floor((now.getTime() - job.startedAt.getTime()) / 60_000);
      if (plannedMinutes > 0
          && actualMinutes >= BUSINESS_EXCEPTION_LIMITS.minimumOverrunMinutes
          && actualMinutes > plannedMinutes * 2) {
        const severity = actualMinutes > plannedMinutes * 3 ? "critical" : "high";
        candidates.push(candidate({
          type: "job_duration_overrun",
          severity,
          sourceType: "scheduled_job",
          sourceId: job.id,
          fingerprintParts: [job.start, job.end, job.startedAt, severity],
          title: "Job is running far over plan",
          explanation: `${job.displayName} has run ${actualMinutes} minutes against a ${plannedMinutes}-minute schedule.`,
          recommendedAction: "Check job and crew status, then update the schedule or finish the job if work is complete.",
          destination: { type: "scheduled_job", id: job.id },
          metadata: { job_id: job.id, planned_minutes: plannedMinutes, actual_minutes: actualMinutes },
          dueAt: job.end
        }));
      }
    }
  }

  const schedulable = jobs.filter((job) => !job.finishedAt && job.workerIDs.length);
  let conflictCount = 0;
  let conflictsTruncated = false;
  conflictScan: for (let leftIndex = 0; leftIndex < schedulable.length; leftIndex += 1) {
    const left = schedulable[leftIndex];
    for (let rightIndex = leftIndex + 1; rightIndex < schedulable.length; rightIndex += 1) {
      const right = schedulable[rightIndex];
      if (right.start >= left.end || right.end <= left.start) continue;
      const sharedWorkers = left.workerIDs.filter((id) => right.workerIDs.includes(id) && activeWorkers.has(id));
      for (const workerID of sharedWorkers) {
        if (conflictCount >= BUSINESS_EXCEPTION_LIMITS.maximumScheduleConflicts) {
          conflictsTruncated = true;
          break conflictScan;
        }
        const [firstID, secondID] = [left.id, right.id].sort();
        const overlapMinutes = Math.max(1, Math.ceil((Math.min(left.end, right.end) - Math.max(left.start, right.start)) / 60_000));
        candidates.push(candidate({
          type: "schedule_conflict",
          severity: "high",
          sourceType: "worker_job_pair",
          sourceId: `${workerID}:${firstID}:${secondID}`,
          fingerprintParts: [workerID, firstID, secondID, left.start, left.end, right.start, right.end],
          title: "Employee has overlapping jobs",
          explanation: `${activeWorkers.get(workerID)} is assigned to ${left.displayName} and ${right.displayName} for ${overlapMinutes} overlapping minute${overlapMinutes === 1 ? "" : "s"}.`,
          recommendedAction: "Reassign or reschedule one job before the overlap begins.",
          destination: { type: "scheduled_job", id: left.start <= right.start ? left.id : right.id },
          metadata: { worker_user_id: workerID, job_ids: [firstID, secondID], overlap_minutes: overlapMinutes },
          dueAt: left.start <= right.start ? left.start : right.start
        }));
        conflictCount += 1;
      }
    }
  }
  return { candidates, conflictsTruncated };
}

function detectTaskExceptions(rawTasks, now) {
  return rawTasks.flatMap((task) => {
    const id = clean(task?.id);
    const due = validDate(task?.due_date);
    if (!id || !due || due >= now || task.completed === true) return [];
    const minutesOverdue = Math.floor((now.getTime() - due.getTime()) / 60_000);
    const priority = clean(task.priority).toLowerCase();
    const severity = ["urgent", "high"].includes(priority) || minutesOverdue >= 1_440 ? "high" : "medium";
    return [candidate({
      type: "overdue_task",
      severity,
      sourceType: "todo_task",
      sourceId: id,
      fingerprintParts: [due, priority, severity, task.assignee_ids || []],
      title: "Task is overdue",
      explanation: `${clean(task.title) || "A company task"} is ${humanDuration(minutesOverdue)} overdue and remains incomplete.`,
      recommendedAction: "Complete, reassign, or reschedule the task.",
      destination: { type: "todo", id },
      metadata: { task_id: id, minutes_overdue: minutesOverdue, priority: priority || "normal" },
      dueAt: due
    })];
  });
}

function detectAutomationExceptions(rawIssues) {
  return rawIssues.flatMap((issue) => {
    const id = clean(issue?.id);
    if (!id || clean(issue.status).toLowerCase() !== "open") return [];
    const attempts = nonnegativeInteger(issue.attempts);
    const failedAt = validDate(issue.failed_at);
    const severity = attempts >= 5 ? "critical" : "high";
    const detail = boundedText(issue.error_message) || boundedText(issue.error_code) || "An automation effect could not be completed.";
    return [candidate({
      type: "automation_failure",
      severity,
      sourceType: "automation_dead_letter",
      sourceId: id,
      fingerprintParts: [issue.error_code, issue.failed_at, attempts, severity],
      title: "Automation needs attention",
      explanation: detail,
      recommendedAction: "Open Automations, inspect the failed run, then retry or dismiss the system issue.",
      destination: { type: "automations", id: clean(issue.automation_id) || null },
      metadata: { dead_letter_id: id, automation_id: clean(issue.automation_id) || null, attempts, error_code: clean(issue.error_code) || null },
      dueAt: failedAt
    })];
  });
}

function detectMessageExceptions(rawFailures, rawUnknown) {
  const failed = rawFailures.flatMap((message) => {
    const id = clean(message?.id);
    const status = clean(message?.message_status).toLowerCase();
    if (!id || message?.direction !== "outbound" || !["failed", "undelivered"].includes(status)) return [];
    const customer = clean(message.contact_name) || clean(message.to_number) || "A customer";
    return [candidate({
      type: "customer_message_failure",
      severity: "high",
      sourceType: "sms_message",
      sourceId: id,
      fingerprintParts: [status, message.twilio_error_code],
      title: "Customer message failed",
      explanation: `An outbound message to ${customer} is ${status}${message.twilio_error_code ? ` (Twilio ${boundedText(message.twilio_error_code)})` : ""}.`,
      recommendedAction: "Open Messages, review the provider error and customer consent, then choose a safe follow-up channel.",
      destination: { type: "message_thread", id: clean(message.conversation_id) || null },
      metadata: { sms_message_id: id, conversation_id: clean(message.conversation_id) || null, provider_status: status, error_code: clean(message.twilio_error_code) || null },
      dueAt: validDate(message.updated_at || message.created_at)
    })];
  });
  const unknown = rawUnknown.flatMap((item) => {
    const batchID = clean(item?.batch_id);
    const contactID = clean(item?.contact_id);
    if (!batchID || !contactID || item.outcome !== "delivery_unknown") return [];
    return [candidate({
      type: "customer_message_failure",
      severity: "critical",
      sourceType: "sms_delivery_unknown",
      sourceId: `${batchID}:${contactID}`,
      fingerprintParts: [item.provider_message_sid, item.error_code],
      title: "Customer message delivery is uncertain",
      explanation: "Twilio may have accepted a customer message, but WolfCRM could not finish local persistence.",
      recommendedAction: "Check Twilio and Messages before any resend. Do not automatically send this message again.",
      destination: { type: "message_thread", id: clean(item.sms_conversation_id) || null },
      metadata: { batch_id: batchID, contact_id: contactID, provider_message_sid: clean(item.provider_message_sid) || null },
      dueAt: validDate(item.updated_at || item.created_at)
    })];
  });
  return [...failed, ...unknown];
}

function normalizeJob(raw) {
  const id = clean(raw?.id);
  const start = validDate(raw?.start_at ?? raw?.start);
  const end = validDate(raw?.end_at ?? raw?.end);
  if (!id || !start || !end || end <= start) return null;
  return {
    id,
    start,
    end,
    startedAt: validDate(raw.started_at),
    finishedAt: validDate(raw.finished_at),
    workerIDs: [...new Set((Array.isArray(raw.worker_user_ids) ? raw.worker_user_ids : []).map(clean).filter(Boolean))],
    displayName: clean(raw.contact_name) || clean(raw.title) || "Scheduled job"
  };
}

function candidate({ type, severity, sourceType, sourceId, fingerprintParts, title, explanation, recommendedAction, destination, metadata, dueAt }) {
  return {
    type,
    severity,
    source_type: sourceType,
    source_id: sourceId,
    fingerprint: fingerprint(fingerprintParts),
    title: boundedText(title),
    explanation: boundedText(explanation),
    recommended_action: boundedText(recommendedAction),
    destination: destination || null,
    metadata: metadata || {},
    due_at: validDate(dueAt)?.toISOString() || null
  };
}

function fingerprint(parts) {
  return createHash("sha256").update(JSON.stringify(parts, (_, value) => value instanceof Date ? value.toISOString() : value)).digest("hex");
}

function humanDuration(minutes) {
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"}`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours} hour${hours === 1 ? "" : "s"}`;
  const days = Math.floor(hours / 24);
  return `${days} day${days === 1 ? "" : "s"}`;
}

function assertBounded(value, maximum, label) {
  if (!Array.isArray(value) || value.length > maximum) {
    throw new BusinessExceptionError("business_exception_source_invalid", `Exception ${label} must contain at most ${maximum} records.`);
  }
}

function boundedText(value) {
  return clean(value).slice(0, BUSINESS_EXCEPTION_LIMITS.maximumTextLength);
}

function nonnegativeInteger(value) {
  const number = Number(value);
  return Number.isSafeInteger(number) && number >= 0 ? number : 0;
}

function validDate(value) {
  if (value == null || value === "") return null;
  const date = value instanceof Date ? new Date(value) : new Date(value);
  return Number.isFinite(date.getTime()) ? date : null;
}

function clean(value) {
  return value == null ? "" : String(value).trim();
}
