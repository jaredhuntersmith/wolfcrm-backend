const FREQUENCIES = new Set(["weekly", "biweekly", "monthly", "quarterly"]);
const REVIEW_ACTIONS = new Set(["approve", "reject"]);

export class InventoryCountInputError extends Error {
  constructor(message, code = "invalid_inventory_count", statusCode = 400) {
    super(message);
    this.name = "InventoryCountInputError";
    this.code = code;
    this.statusCode = statusCode;
  }
}

function text(value, label, maximumLength, required = false) {
  if (value == null && !required) return null;
  const normalized = typeof value === "string" ? value.trim() : "";
  if ((required && !normalized) || normalized.length > maximumLength) {
    throw new InventoryCountInputError(`${label} must be ${required ? `1–${maximumLength}` : `at most ${maximumLength}`} characters.`);
  }
  return normalized || null;
}

function identifier(value, label, required = false) {
  return text(value, label, 160, required);
}

function userIdentifier(value, label) {
  const normalized = text(value, label, 64);
  if (normalized && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(normalized)) {
    throw new InventoryCountInputError(`${label} must be a valid user identifier.`);
  }
  return normalized;
}

function day(value, label, required = false) {
  const normalized = text(value, label, 10, required);
  if (!normalized) return null;
  const parsed = new Date(`${normalized}T00:00:00Z`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(normalized) || Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== normalized) {
    throw new InventoryCountInputError(`${label} must be a valid YYYY-MM-DD date.`);
  }
  return normalized;
}

export function normalizeCountSchedule(input) {
  const source = input && typeof input === "object" && !Array.isArray(input) ? input : {};
  const frequency = text(source.frequency, "Frequency", 20, true);
  if (!FREQUENCIES.has(frequency)) throw new InventoryCountInputError("Choose a valid count frequency.");
  const dueTime = text(source.due_time, "Due time", 5);
  if (dueTime && !/^([01]\d|2[0-3]):[0-5]\d$/.test(dueTime)) throw new InventoryCountInputError("Due time must use HH:mm.");
  const threshold = Number(source.variance_threshold ?? 0);
  if (!Number.isFinite(threshold) || threshold < 0 || threshold > 1_000_000_000) throw new InventoryCountInputError("Variance threshold must be between 0 and 1,000,000,000.");
  const reminder = source.reminder_minutes == null || source.reminder_minutes === "" ? null : Number(source.reminder_minutes);
  if (reminder != null && (!Number.isInteger(reminder) || reminder < 0 || reminder > 10_080)) throw new InventoryCountInputError("Reminder must be 0–10,080 minutes.");
  return {
    name: text(source.name, "Name", 160, true),
    location_id: identifier(source.location_id, "Location", true),
    assigned_user_id: userIdentifier(source.assigned_user_id, "Assigned user"),
    frequency,
    due_date: day(source.due_date, "Due date"),
    due_time: dueTime,
    reminder_minutes: reminder,
    variance_threshold: threshold,
    approval_required: source.approval_required !== false,
    enabled: source.enabled !== false,
  };
}

export function normalizeCountGeneration(input) {
  const source = input && typeof input === "object" && !Array.isArray(input) ? input : {};
  return { due_date: day(source.due_date, "Due date") };
}

export function normalizeCountSubmission(input) {
  const source = input && typeof input === "object" && !Array.isArray(input) ? input : {};
  if (!Array.isArray(source.items) || source.items.length === 0 || source.items.length > 500) {
    throw new InventoryCountInputError("Submit 1–500 count items.");
  }
  const seen = new Set();
  const items = source.items.map((item) => {
    const row = item && typeof item === "object" && !Array.isArray(item) ? item : {};
    const itemID = identifier(row.item_id, "Item", true);
    if (seen.has(itemID)) throw new InventoryCountInputError("Each inventory item may be counted once.");
    seen.add(itemID);
    const counted = Number(row.counted_quantity);
    if (!Number.isFinite(counted) || counted < 0 || counted > 1_000_000_000) throw new InventoryCountInputError("Counted quantity must be between 0 and 1,000,000,000.");
    return { item_id: itemID, counted_quantity: counted, note: text(row.note, "Item note", 1_000) };
  });
  return { items };
}

export function normalizeCountReview(input) {
  const source = input && typeof input === "object" && !Array.isArray(input) ? input : {};
  const action = text(source.action, "Action", 20, true);
  if (!REVIEW_ACTIONS.has(action)) throw new InventoryCountInputError("Choose approve or reject.");
  return { action, note: text(source.note, "Review note", 2_000) };
}

export function countAdjustment(currentQuantity, countedQuantity) {
  const current = Number(currentQuantity);
  const counted = Number(countedQuantity);
  if (!Number.isFinite(current) || !Number.isFinite(counted)) throw new InventoryCountInputError("Inventory quantities must be finite.");
  return counted - current;
}
