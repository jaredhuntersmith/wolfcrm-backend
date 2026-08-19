export const ASSIGNMENT_RECOMMENDATION_LIMITS = Object.freeze({
  maximumWorkers: 50,
  maximumScheduleJobs: 500
});

export class AssignmentRecommendationError extends Error {
  constructor(code, message, { statusCode = 400, details = null } = {}) {
    super(message);
    this.name = "AssignmentRecommendationError";
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
  }
}

export function planAssignmentApplication({
  report,
  selectedWorkerID,
  assignmentMode,
  expectedUpdatedAt
} = {}) {
  const selectedID = clean(selectedWorkerID).toLowerCase();
  if (!selectedID) {
    throw new AssignmentRecommendationError("assignment_worker_required", "Choose an employee to assign.");
  }
  if (!['add', 'replace'].includes(assignmentMode)) {
    throw new AssignmentRecommendationError("assignment_mode_invalid", "Choose whether to add to or replace the current crew.");
  }
  const expected = validDate(expectedUpdatedAt);
  const current = validDate(report?.target_job?.updated_at);
  if (!expected || !current) {
    throw new AssignmentRecommendationError("assignment_expected_version_required", "Reload recommendations before applying this assignment.");
  }
  if (expected.getTime() !== current.getTime()) {
    throw new AssignmentRecommendationError(
      "assignment_job_changed",
      "This job changed after the recommendation was loaded. Refresh and review it again.",
      { statusCode: 409 }
    );
  }
  const recommendation = report?.recommendations?.find((item) => item.worker_id === selectedID);
  if (!recommendation || !recommendation.eligible) {
    throw new AssignmentRecommendationError(
      "assignment_candidate_ineligible",
      "That employee is no longer eligible for this job. Refresh and review the alternatives.",
      { statusCode: 409 }
    );
  }
  const previousWorkerIDs = Array.isArray(report.target_job.current_worker_user_ids)
    ? [...new Set(report.target_job.current_worker_user_ids.map((value) => clean(value).toLowerCase()).filter(Boolean))]
    : [];
  const nextWorkerIDs = assignmentMode === "add"
    ? [...new Set([...previousWorkerIDs, selectedID])]
    : [selectedID];
  if (nextWorkerIDs.length > ASSIGNMENT_RECOMMENDATION_LIMITS.maximumWorkers) {
    throw new AssignmentRecommendationError("assignment_workers_invalid", "This job has too many assigned employees.");
  }
  return {
    selected_worker_id: selectedID,
    assignment_mode: assignmentMode,
    previous_worker_user_ids: previousWorkerIDs,
    new_worker_user_ids: nextWorkerIDs,
    recommendation
  };
}

export function buildAssignmentRecommendations({
  targetJob,
  workers = [],
  existingJobs = [],
  availabilityByWorker = {},
  companyAvailability = null,
  timeZone = "UTC",
  travelByWorker = {},
  routingStatus = { configured: false, provider: "google" },
  now = new Date()
} = {}) {
  const target = normalizeJob(targetJob, { target: true });
  const generatedAt = validDate(now) || new Date();
  if (target.started || target.finished || target.end <= generatedAt) {
    throw new AssignmentRecommendationError(
      "assignment_job_not_eligible",
      "Worker recommendations are available only for future jobs that have not started or finished.",
      { statusCode: 409 }
    );
  }
  if (!Array.isArray(workers) || workers.length > ASSIGNMENT_RECOMMENDATION_LIMITS.maximumWorkers) {
    throw new AssignmentRecommendationError(
      "assignment_workers_invalid",
      `Recommendations support up to ${ASSIGNMENT_RECOMMENDATION_LIMITS.maximumWorkers} active workers.`
    );
  }
  if (!Array.isArray(existingJobs) || existingJobs.length > ASSIGNMENT_RECOMMENDATION_LIMITS.maximumScheduleJobs) {
    throw new AssignmentRecommendationError("assignment_schedule_too_large", "The recommendation schedule window is too large.");
  }

  const normalizedWorkers = normalizeWorkers(workers);
  const schedule = existingJobs
    .map((job) => normalizeJob(job, { target: false }))
    .filter(Boolean)
    .filter((job) => !job.finished && job.id !== target.id);
  const targetDurationSeconds = Math.round((target.end - target.start) / 1000);
  const targetDay = localDateKey(target.start, timeZone);
  const recommendations = normalizedWorkers.map((worker) => {
    const workerJobs = schedule
      .filter((job) => job.workerIDs.includes(worker.id))
      .sort(compareJobs);
    const dayJobs = workerJobs.filter((job) => localDateKey(job.start, timeZone) === targetDay);
    const conflicts = workerJobs.filter((job) => intervalsOverlap(job.start, job.end, target.start, target.end));
    const previous = dayJobs
      .filter((job) => job.end <= target.start)
      .sort((lhs, rhs) => rhs.end - lhs.end || rhs.start - lhs.start || lhs.id.localeCompare(rhs.id))[0] || null;
    const next = dayJobs
      .filter((job) => job.start >= target.end)
      .sort(compareJobs)[0] || null;
    const availability = effectiveAvailability(worker.id, availabilityByWorker, companyAvailability);
    const fitsAvailability = availability ? eventFitsAvailability(target, availability, timeZone) : true;
    const assignedSeconds = dayJobs
      .reduce((sum, job) => sum + Math.max(0, Math.round((job.end - job.start) / 1000)), 0);
    const currentlyAssigned = target.workerIDs.includes(worker.id);
    const projectedAssignedSeconds = assignedSeconds + (currentlyAssigned ? 0 : targetDurationSeconds);
    const previousGapSeconds = previous ? Math.max(0, Math.round((target.start - previous.end) / 1000)) : null;
    const nextGapSeconds = next ? Math.max(0, Math.round((next.start - target.end) / 1000)) : null;
    const travel = normalizeTravel(travelByWorker?.[worker.id]);
    const incomingAvailableSeconds = finiteNonnegative(travel.incoming_available_seconds) ?? previousGapSeconds;
    const outgoingAvailableSeconds = finiteNonnegative(travel.outgoing_available_seconds) ?? nextGapSeconds;
    const incomingInfeasible = travel.incoming_seconds != null && incomingAvailableSeconds != null
      && travel.incoming_seconds > incomingAvailableSeconds;
    const outgoingInfeasible = travel.outgoing_seconds != null && outgoingAvailableSeconds != null
      && travel.outgoing_seconds > outgoingAvailableSeconds;

    const reasons = [];
    if (!worker.permitted) reasons.push(reason("jobs_work_required", "Employee is not permitted to perform job work.", "blocking"));
    if (conflicts.length) reasons.push(reason(
      "schedule_overlap",
      `Overlaps ${conflicts.length} scheduled ${conflicts.length === 1 ? "job" : "jobs"}.`,
      "blocking"
    ));
    else reasons.push(reason("schedule_clear", "No appointment overlaps this job.", "positive"));
    if (!fitsAvailability) reasons.push(reason("outside_availability", "Job falls outside this employee's effective working hours.", "blocking"));
    else reasons.push(reason("inside_availability", "Job fits effective working hours.", "positive"));
    if (incomingInfeasible) reasons.push(reason(
      "incoming_travel_conflict",
      `Needs ${durationText(travel.incoming_seconds)} of incoming travel with only ${durationText(incomingAvailableSeconds)} available.`,
      "blocking"
    ));
    if (outgoingInfeasible) reasons.push(reason(
      "outgoing_travel_conflict",
      `Needs ${durationText(travel.outgoing_seconds)} to the next job with only ${durationText(outgoingAvailableSeconds)} available.`,
      "blocking"
    ));
    if (travel.coverage === "complete" && !incomingInfeasible && !outgoingInfeasible) {
      reasons.push(reason("road_feasible", "Known road legs fit the surrounding schedule gaps.", "positive"));
    } else if (travel.coverage !== "complete") {
      reasons.push(reason("road_evidence_incomplete", travel.warning || "Some road-time evidence is unavailable.", "warning"));
    }

    const eligible = worker.permitted && !conflicts.length && fitsAvailability && !incomingInfeasible && !outgoingInfeasible;
    const score = recommendationScore({
      eligible,
      projectedAssignedSeconds,
      travel,
      currentlyAssigned
    });
    return {
      worker_id: worker.id,
      worker_name: worker.name,
      eligible,
      score,
      rank: 0,
      confidence: travel.coverage === "complete" ? "high" : travel.coverage === "partial" ? "medium" : "low",
      currently_assigned: currentlyAssigned,
      conflict_job_ids: conflicts.map((job) => job.id),
      fits_availability: fitsAvailability,
      assigned_seconds: assignedSeconds,
      projected_assigned_seconds: projectedAssignedSeconds,
      previous_gap_seconds: previousGapSeconds,
      next_gap_seconds: nextGapSeconds,
      previous_job: adjacentJobPayload(previous, "previous"),
      next_job: adjacentJobPayload(next, "next"),
      travel,
      reasons
    };
  });

  recommendations.sort(compareRecommendations);
  recommendations.forEach((recommendation, index) => { recommendation.rank = index + 1; });
  const best = recommendations.find((recommendation) => recommendation.eligible) || null;
  const warnings = [];
  if (!routingStatus?.configured) warnings.push("Google routing is not configured; rankings use schedule and availability only.");
  if (target.latitude == null || target.longitude == null) warnings.push("The target job has no saved coordinates, so road-time impact is unavailable.");
  if (!normalizedWorkers.length) warnings.push("No active employees were available to evaluate.");
  else if (!normalizedWorkers.some((worker) => worker.permitted)) {
    warnings.push("No active employee currently has permission to perform job work.");
  }

  return {
    generated_at: generatedAt.toISOString(),
    target_job: {
      id: target.id,
      title: target.title,
      start_at: target.start.toISOString(),
      end_at: target.end.toISOString(),
      updated_at: target.updatedAt?.toISOString() || null,
      current_worker_user_ids: target.workerIDs
    },
    routing: {
      provider: routingStatus?.provider || "google",
      configured: Boolean(routingStatus?.configured)
    },
    best_worker_id: best?.worker_id || null,
    warnings,
    recommendations
  };
}

function normalizeWorkers(workers) {
  const seen = new Set();
  return workers.map((worker) => {
    const id = clean(worker?.id).toLowerCase();
    if (!id || id.length > 160 || seen.has(id)) {
      throw new AssignmentRecommendationError("assignment_workers_invalid", "Every candidate employee must have a unique ID.");
    }
    seen.add(id);
    return {
      id,
      name: clean(worker.display_name || worker.name || worker.email) || "Team member",
      permitted: worker.permitted !== false
    };
  });
}

function normalizeJob(raw, { target }) {
  if (!raw || typeof raw !== "object") {
    if (!target) return null;
    throw invalidJob();
  }
  const id = clean(raw.id);
  const start = validDate(raw.start_at ?? raw.start);
  const end = validDate(raw.end_at ?? raw.end);
  if (!id || !start || !end || end <= start) {
    if (!target) return null;
    throw invalidJob();
  }
  return {
    id,
    title: clean(raw.title) || "Job",
    start,
    end,
    started: Boolean(raw.started_at),
    finished: Boolean(raw.finished_at),
    updatedAt: validDate(raw.updated_at),
    workerIDs: Array.isArray(raw.worker_user_ids)
      ? [...new Set(raw.worker_user_ids.map((value) => clean(value).toLowerCase()).filter(Boolean))]
      : [],
    latitude: coordinate(raw.contact_latitude ?? raw.latitude, -90, 90),
    longitude: coordinate(raw.contact_longitude ?? raw.longitude, -180, 180)
  };
}

function invalidJob() {
  return new AssignmentRecommendationError("assignment_job_invalid", "The target job has an invalid schedule interval.");
}

function normalizeTravel(raw) {
  const coverage = ["complete", "partial", "unavailable"].includes(raw?.coverage) ? raw.coverage : "unavailable";
  const incoming = finiteNonnegative(raw?.incoming_seconds);
  const outgoing = finiteNonnegative(raw?.outgoing_seconds);
  const baseline = finiteNonnegative(raw?.baseline_seconds);
  let added = finiteNumber(raw?.added_seconds);
  if (added == null && incoming != null && outgoing != null && baseline != null) added = incoming + outgoing - baseline;
  return {
    coverage,
    source: clean(raw?.source) || null,
    incoming_seconds: incoming,
    outgoing_seconds: outgoing,
    baseline_seconds: baseline,
    added_seconds: added == null ? null : Math.round(added),
    distance_meters: finiteNonnegative(raw?.distance_meters),
    incoming_available_seconds: finiteNonnegative(raw?.incoming_available_seconds),
    outgoing_available_seconds: finiteNonnegative(raw?.outgoing_available_seconds),
    warning: clean(raw?.warning) || null
  };
}

function recommendationScore({ eligible, projectedAssignedSeconds, travel, currentlyAssigned }) {
  let score = 100;
  const addedMinutes = travel.added_seconds == null ? null : travel.added_seconds / 60;
  if (addedMinutes != null) {
    score -= Math.min(45, Math.max(0, addedMinutes) * 0.6);
    score += Math.min(10, Math.max(0, -addedMinutes) * 0.25);
  } else {
    score -= travel.coverage === "partial" ? 6 : 12;
  }
  score -= Math.min(25, projectedAssignedSeconds / 3600 * 1.5);
  if (currentlyAssigned) score += 3;
  if (!eligible) score -= 70;
  return Math.round(Math.max(0, Math.min(100, score)) * 10) / 10;
}

function compareRecommendations(lhs, rhs) {
  if (lhs.eligible !== rhs.eligible) return lhs.eligible ? -1 : 1;
  if (lhs.score !== rhs.score) return rhs.score - lhs.score;
  const lhsAdded = lhs.travel.added_seconds ?? Number.POSITIVE_INFINITY;
  const rhsAdded = rhs.travel.added_seconds ?? Number.POSITIVE_INFINITY;
  if (lhsAdded !== rhsAdded) return lhsAdded - rhsAdded;
  if (lhs.projected_assigned_seconds !== rhs.projected_assigned_seconds) {
    return lhs.projected_assigned_seconds - rhs.projected_assigned_seconds;
  }
  const name = lhs.worker_name.localeCompare(rhs.worker_name);
  return name || lhs.worker_id.localeCompare(rhs.worker_id);
}

function effectiveAvailability(workerID, availabilityByWorker, companyAvailability) {
  const override = availabilityByWorker?.[workerID];
  return override?.enabled === false ? companyAvailability : (override || companyAvailability);
}

function eventFitsAvailability(event, profile, timeZone) {
  const start = zonedParts(event.start, timeZone);
  const end = zonedParts(event.end, timeZone);
  const startMinutes = timeMinutes(profile?.start_time);
  const endMinutes = timeMinutes(profile?.end_time);
  const weekdays = Array.isArray(profile?.weekdays) ? profile.weekdays.map(Number) : [];
  return start != null && end != null && start.dateKey === end.dateKey
    && weekdays.includes(start.isoWeekday)
    && startMinutes != null && endMinutes != null
    && start.minutes >= startMinutes && end.minutes <= endMinutes;
}

function zonedParts(date, timeZone) {
  try {
    const formatter = new Intl.DateTimeFormat("en-CA", {
      timeZone: clean(timeZone) || "UTC",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hourCycle: "h23"
    });
    const values = Object.fromEntries(formatter.formatToParts(date)
      .filter((part) => part.type !== "literal")
      .map((part) => [part.type, Number(part.value)]));
    const jsWeekday = new Date(Date.UTC(values.year, values.month - 1, values.day)).getUTCDay();
    return {
      dateKey: `${values.year}-${String(values.month).padStart(2, "0")}-${String(values.day).padStart(2, "0")}`,
      isoWeekday: ((jsWeekday + 6) % 7) + 1,
      minutes: values.hour * 60 + values.minute
    };
  } catch (_) {
    return null;
  }
}

function localDateKey(date, timeZone) {
  return zonedParts(date, timeZone)?.dateKey || date.toISOString().slice(0, 10);
}

function timeMinutes(value) {
  const match = /^(\d{2}):(\d{2})$/.exec(clean(value));
  if (!match) return null;
  const hour = Number(match[1]);
  const minute = Number(match[2]);
  return hour <= 23 && minute <= 59 ? hour * 60 + minute : null;
}

function adjacentJobPayload(job, direction) {
  if (!job) return null;
  return {
    id: job.id,
    title: job.title,
    [direction === "previous" ? "end_at" : "start_at"]: (direction === "previous" ? job.end : job.start).toISOString()
  };
}

function reason(code, label, kind) {
  return { code, label, kind };
}

function durationText(seconds) {
  const minutes = Math.max(0, Math.ceil(Number(seconds || 0) / 60));
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  const remainder = minutes % 60;
  return remainder ? `${hours} hr ${remainder} min` : `${hours} hr`;
}

function intervalsOverlap(firstStart, firstEnd, secondStart, secondEnd) {
  return firstStart < secondEnd && firstEnd > secondStart;
}

function compareJobs(lhs, rhs) {
  return lhs.start - rhs.start || lhs.end - rhs.end || lhs.id.localeCompare(rhs.id);
}

function coordinate(value, minimum, maximum) {
  if (value == null || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= minimum && number <= maximum ? number : null;
}

function finiteNumber(value) {
  if (value == null || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function finiteNonnegative(value) {
  const number = finiteNumber(value);
  return number != null && number >= 0 ? Math.round(number) : null;
}

function validDate(value) {
  if (value == null) return null;
  const date = value instanceof Date ? new Date(value) : new Date(value);
  return Number.isFinite(date.getTime()) ? date : null;
}

function clean(value) {
  return String(value ?? "").replace(/\s+/g, " ").trim();
}
