export class CallError extends Error {
  constructor(status, code, message = code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}
export const fail = (status, code, message) => {
  throw new CallError(status, code, message);
};
export function uuid(value) {
  if (
    typeof value !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      value,
    )
  )
    fail(400, "invalid_id");
  return value.toLowerCase();
}
export function requireCapability(actor, capability = "communications.calls") {
  if (!actor.userId || !actor.companyId) fail(403, "company_required");
  const c = actor.permissions?.capabilities;
  if (!actor.isCompanyOwner && c?.[capability] !== true)
    fail(403, "capability_required");
}
export const terminal = (s) =>
  ["ended", "canceled", "declined", "missed", "failed"].includes(s);
export const safeCall = (row) => {
  const { room_name, pair_key, ...safe } = row;
  return safe;
};
export function text(value, max = 160) {
  return String(value || "")
    .trim()
    .slice(0, max);
}
export function settingsInput(body) {
  const out = {};
  for (const key of [
    "enabled",
    "recording_enabled",
    "guests_enabled",
    "transcription_enabled",
    "ai_enabled",
    "captions_enabled",
  ])
    if (key in body) {
      if (typeof body[key] !== "boolean") fail(400, "invalid_settings");
      out[key] = body[key];
    }
  for (const [key, min, max] of [
    ["max_participants", 2, 100],
    ["usage_warning_percent", 10, 100],
    ["monthly_caption_minutes", 0, 1000000],
    ["monthly_participant_minutes", 0, 10000000],
    ["max_call_minutes", 1, 1440],
    ["monthly_processing_minutes", 0, 1000000],
    ["processing_retention_days", 1, 3650],
  ])
    if (key in body) {
      if (!Number.isInteger(body[key]) || body[key] < min || body[key] > max)
        fail(400, "invalid_settings");
      out[key] = body[key];
    }
  return out;
}
