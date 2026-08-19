export const DEFAULT_ON_MY_WAY_TEMPLATE = "Hi {{customer_first_name}}, {{employee_name}} from {{company_name}} is on the way. Estimated arrival: {{eta}}.";
export const ON_MY_WAY_MAX_MESSAGE_LENGTH = 1_200;
export const ON_MY_WAY_DUPLICATE_WINDOW_MINUTES = 30;

const SUPPORTED_PLACEHOLDERS = new Set([
  "customer_first_name",
  "customer_name",
  "employee_name",
  "company_name",
  "eta"
]);
const ACTIVE_DELIVERY_STATUSES = new Set(["sending", "queued", "sent", "delivered", "delivery_unknown"]);

export class OnMyWayError extends Error {
  constructor(code, message, { statusCode = 400, details = null } = {}) {
    super(message);
    this.name = "OnMyWayError";
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
  }
}

export function validateOnMyWayTemplate(value) {
  if (typeof value !== "string") {
    throw new OnMyWayError("on_my_way_template_required", "Enter an On My Way message template.");
  }
  const template = value.trim();
  if (!template) {
    throw new OnMyWayError("on_my_way_template_required", "Enter an On My Way message template.");
  }
  if (template.length > ON_MY_WAY_MAX_MESSAGE_LENGTH) {
    throw new OnMyWayError(
      "on_my_way_template_too_long",
      `Keep the On My Way template under ${ON_MY_WAY_MAX_MESSAGE_LENGTH} characters.`,
      { details: { max_length: ON_MY_WAY_MAX_MESSAGE_LENGTH } }
    );
  }
  const unknown = [...template.matchAll(/{{\s*([^{}]+?)\s*}}/g)]
    .map((match) => match[1].trim())
    .filter((key) => !SUPPORTED_PLACEHOLDERS.has(key));
  if (unknown.length) {
    throw new OnMyWayError(
      "unsupported_on_my_way_placeholder",
      `Unsupported placeholder: {{${unknown[0]}}}.`,
      { details: { placeholders: [...new Set(unknown)] } }
    );
  }
  return template;
}

export function validateOnMyWayMessage(value) {
  if (typeof value !== "string") {
    throw new OnMyWayError("on_my_way_message_required", "Enter a customer message.");
  }
  const message = value.trim();
  if (!message) {
    throw new OnMyWayError("on_my_way_message_required", "Enter a customer message.");
  }
  if (message.length > ON_MY_WAY_MAX_MESSAGE_LENGTH) {
    throw new OnMyWayError(
      "on_my_way_message_too_long",
      `Keep the message under ${ON_MY_WAY_MAX_MESSAGE_LENGTH} characters.`,
      { details: { max_length: ON_MY_WAY_MAX_MESSAGE_LENGTH } }
    );
  }
  return message;
}

export function friendlyOnMyWayEta(seconds) {
  const numeric = Number(seconds);
  if (!Number.isFinite(numeric) || numeric <= 0 || numeric > 86_400) return "soon";
  const minutes = Math.max(5, Math.ceil(numeric / 300) * 5);
  if (minutes < 60) return `about ${minutes} minutes`;
  const hours = Math.floor(minutes / 60);
  const remaining = minutes % 60;
  const hourText = `${hours} ${hours === 1 ? "hour" : "hours"}`;
  return remaining ? `about ${hourText} ${remaining} minutes` : `about ${hourText}`;
}

export function renderOnMyWayTemplate(template, values = {}) {
  const validated = validateOnMyWayTemplate(template);
  const customerName = cleanValue(values.customerName, "there");
  const firstName = customerName === "there" ? customerName : customerName.split(/\s+/)[0];
  const replacements = {
    customer_first_name: firstName,
    customer_name: customerName,
    employee_name: cleanValue(values.employeeName, "A team member"),
    company_name: cleanValue(values.companyName, "Our team"),
    eta: friendlyOnMyWayEta(values.etaSeconds)
  };
  return validated.replace(/{{\s*([^{}]+?)\s*}}/g, (_match, key) => replacements[key.trim()] ?? "");
}

export function parseOnMyWayCoordinate(latitude, longitude) {
  if (latitude == null && longitude == null) return null;
  const lat = Number(latitude);
  const lng = Number(longitude);
  if (!Number.isFinite(lat) || !Number.isFinite(lng) || lat < -90 || lat > 90 || lng < -180 || lng > 180) {
    throw new OnMyWayError("invalid_on_my_way_coordinate", "The route location is invalid.");
  }
  return { latitude: lat, longitude: lng };
}

export function normalizeOnMyWayChannel(value = "sms") {
  const channel = (value || "sms").toString().trim().toLowerCase();
  if (channel !== "sms") {
    throw new OnMyWayError("on_my_way_channel_unavailable", "Only SMS is available for On My Way messages.", { statusCode: 422 });
  }
  return channel;
}

export function blocksRecentOnMyWay(event, { now = new Date(), windowMinutes = ON_MY_WAY_DUPLICATE_WINDOW_MINUTES } = {}) {
  if (!event || !ACTIVE_DELIVERY_STATUSES.has((event.status || "").toString().toLowerCase())) return false;
  const createdAt = new Date(event.created_at);
  if (Number.isNaN(createdAt.getTime())) return false;
  const ageMs = now.getTime() - createdAt.getTime();
  return ageMs >= 0 && ageMs < windowMinutes * 60_000;
}

function cleanValue(value, fallback) {
  const text = (value || "").toString().trim();
  return text || fallback;
}
