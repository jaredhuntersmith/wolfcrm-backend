const REPAIR_STATUSES = new Set([
  "reported",
  "approved",
  "scheduled",
  "in_repair",
  "waiting_for_parts",
  "completed",
  "not_repairable",
  "cancelled",
]);

const REPAIR_PRIORITIES = new Set(["normal", "high", "urgent"]);

export class OperationsRepairInputError extends Error {
  constructor(message, code = "invalid_repair", statusCode = 400) {
    super(message);
    this.name = "OperationsRepairInputError";
    this.code = code;
    this.statusCode = statusCode;
  }
}

function requiredText(value, label, maximumLength) {
  const normalized = typeof value === "string" ? value.trim() : "";
  if (!normalized || normalized.length > maximumLength) {
    throw new OperationsRepairInputError(`${label} must be 1–${maximumLength} characters.`);
  }
  return normalized;
}

function optionalText(value, label, maximumLength) {
  if (value == null) return null;
  if (typeof value !== "string") {
    throw new OperationsRepairInputError(`${label} must be text.`);
  }
  const normalized = value.trim();
  if (normalized.length > maximumLength) {
    throw new OperationsRepairInputError(`${label} must be at most ${maximumLength} characters.`);
  }
  return normalized || null;
}

function optionalUUID(value, label) {
  const normalized = optionalText(value, label, 64);
  if (normalized && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(normalized)) {
    throw new OperationsRepairInputError(`${label} must be a valid identifier.`);
  }
  return normalized;
}

function optionalCost(value, label) {
  if (value == null || value === "") return null;
  const normalized = Number(value);
  if (!Number.isSafeInteger(normalized) || normalized < 0 || normalized > 1_000_000_000) {
    throw new OperationsRepairInputError(`${label} must be whole cents between 0 and 1,000,000,000.`);
  }
  return normalized;
}

function optionalDate(value, label) {
  if (value == null || value === "") return null;
  if (typeof value !== "string") throw new OperationsRepairInputError(`${label} must be an ISO date.`);
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) throw new OperationsRepairInputError(`${label} must be a valid ISO date.`);
  return parsed.toISOString();
}

function status(value, fallback) {
  const normalized = value == null ? fallback : String(value).trim();
  if (!REPAIR_STATUSES.has(normalized)) throw new OperationsRepairInputError("Choose a valid repair status.");
  return normalized;
}

function priority(value, fallback) {
  const normalized = value == null ? fallback : String(value).trim();
  if (!REPAIR_PRIORITIES.has(normalized)) throw new OperationsRepairInputError("Choose a valid repair priority.");
  return normalized;
}

export function normalizeRepairCreate(input) {
  const source = input && typeof input === "object" && !Array.isArray(input) ? input : {};
  return {
    item_id: requiredText(source.item_id, "Item", 160),
    request_id: optionalText(source.request_id, "Request", 160),
    assigned_user_id: optionalUUID(source.assigned_user_id, "Assigned user"),
    vendor: optionalText(source.vendor, "Vendor", 200),
    problem: requiredText(source.problem, "Problem", 2_000),
    diagnosis: optionalText(source.diagnosis, "Diagnosis", 4_000),
    status: status(source.status, "reported"),
    priority: priority(source.priority, "normal"),
    estimated_cost_cents: optionalCost(source.estimated_cost_cents, "Estimated cost"),
    actual_cost_cents: optionalCost(source.actual_cost_cents, "Actual cost"),
    scheduled_at: optionalDate(source.scheduled_at, "Scheduled time"),
    resolution_notes: optionalText(source.resolution_notes, "Resolution notes", 4_000),
  };
}

export function normalizeRepairUpdate(input) {
  const source = input && typeof input === "object" && !Array.isArray(input) ? input : {};
  const allowed = new Set([
    "assigned_user_id", "vendor", "problem", "diagnosis", "status", "priority",
    "estimated_cost_cents", "actual_cost_cents", "scheduled_at", "resolution_notes",
  ]);
  const output = {};
  for (const key of Object.keys(source)) {
    if (!allowed.has(key)) continue;
    if (key === "problem") output.problem = requiredText(source.problem, "Problem", 2_000);
    else if (key === "status") output.status = status(source.status, "reported");
    else if (key === "priority") output.priority = priority(source.priority, "normal");
    else if (key === "estimated_cost_cents") output.estimated_cost_cents = optionalCost(source.estimated_cost_cents, "Estimated cost");
    else if (key === "actual_cost_cents") output.actual_cost_cents = optionalCost(source.actual_cost_cents, "Actual cost");
    else if (key === "scheduled_at") output.scheduled_at = optionalDate(source.scheduled_at, "Scheduled time");
    else if (key === "assigned_user_id") output.assigned_user_id = optionalUUID(source.assigned_user_id, "Assigned user");
    else if (key === "vendor") output.vendor = optionalText(source.vendor, "Vendor", 200);
    else if (key === "diagnosis") output.diagnosis = optionalText(source.diagnosis, "Diagnosis", 4_000);
    else if (key === "resolution_notes") output.resolution_notes = optionalText(source.resolution_notes, "Resolution notes", 4_000);
  }
  if (Object.keys(output).length === 0) throw new OperationsRepairInputError("Change at least one repair field.");
  return output;
}

export function repairLifecycleTimestamps({ previousStatus = null, nextStatus, startedAt = null, completedAt = null, now }) {
  const timestamp = now instanceof Date ? now.toISOString() : new Date(now).toISOString();
  return {
    started_at: nextStatus === "in_repair" && !startedAt ? timestamp : startedAt,
    completed_at: ["completed", "not_repairable"].includes(nextStatus)
      ? (completedAt || timestamp)
      : (["completed", "not_repairable"].includes(previousStatus) ? null : completedAt),
  };
}

export const repairStatusValues = () => [...REPAIR_STATUSES];
export const repairPriorityValues = () => [...REPAIR_PRIORITIES];
