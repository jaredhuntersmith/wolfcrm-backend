import { createHash, randomUUID } from "node:crypto";
import { resolveCname, resolveTxt } from "node:dns/promises";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";

export const WEBSITE_PROJECT_KINDS = Object.freeze([
  "website",
  "landing_page",
  "funnel",
]);

export const WEBSITE_LIFECYCLE_STATUSES = Object.freeze(["draft", "archived"]);

const PROJECT_NAME_LIMIT = 120;
const PAGE_NAME_LIMIT = 120;
const PAGE_SLUG_LIMIT = 160;
const SUBDOMAIN_LIMIT = 63;
const DOMAIN_HOSTNAME_LIMIT = 253;
const MAX_PROJECTS_PER_COMPANY = 100;
const MAX_PAGES_PER_PROJECT = 250;
const MAX_BLOCKS_PER_PAGE = 100;
const MAX_BLOCK_DEPTH = 6;
const MAX_PAGE_CONTENT_BYTES = 262144;
const MAX_RICH_TEXT_SPANS = 250;
const SEO_TITLE_LIMIT = 70;
const SEO_DESCRIPTION_LIMIT = 200;
const MAX_NAVIGATION_ITEMS = 30;
const NAVIGATION_LABEL_LIMIT = 80;
const MAX_REUSABLE_SECTIONS_PER_COMPANY = 100;
const MAX_MEDIA_PER_COMPANY = 1000;
const MAX_MEDIA_BYTES = 10 * 1024 * 1024;
const MAX_FORMS_PER_PROJECT = 50;
const MAX_FORM_FIELDS = 20;
const MAX_FORM_SUBMISSIONS_PER_RESPONSE = 100;
const FORM_RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const FORM_RATE_LIMIT_MAX = 10;
const ANALYTICS_RATE_LIMIT_WINDOW_MS = 60 * 1000;
const ANALYTICS_RATE_LIMIT_MAX = 60;
const WEBSITE_ANALYTICS_EVENT_TYPES = new Set(["page_view", "cta_click", "form_view"]);
const WEBSITE_ANALYTICS_REPORT_DAYS = new Set([7, 30, 90, 365]);
const WEBSITE_FORM_FIELD_TYPES = new Set(["name", "phone", "email", "address", "text", "textarea", "select"]);
const WEBSITE_MEDIA_MIME_TYPES = new Set(["image/jpeg", "image/png", "image/webp", "image/gif"]);
const WEBSITE_THEME_DEFAULTS = Object.freeze({
  primary_color: "#0f766e",
  accent_color: "#f59e0b",
  background_color: "#f8fafc",
  surface_color: "#ffffff",
  text_color: "#172033",
  muted_text_color: "#64748b",
  heading_font: "modern",
  body_font: "system",
  corner_style: "rounded",
  heading_scale: "balanced",
  body_scale: "comfortable",
  content_width: "standard",
  section_spacing: "balanced",
  button_style: "solid",
});
const WEBSITE_THEME_COLOR_FIELDS = Object.freeze([
  "primary_color",
  "accent_color",
  "background_color",
  "surface_color",
  "text_color",
  "muted_text_color",
]);
const WEBSITE_THEME_FONT_CHOICES = new Set(["system", "modern", "classic"]);
const WEBSITE_THEME_CORNER_CHOICES = new Set(["square", "soft", "rounded"]);
const WEBSITE_THEME_HEADING_SCALE_CHOICES = new Set(["compact", "balanced", "display"]);
const WEBSITE_THEME_BODY_SCALE_CHOICES = new Set(["compact", "comfortable", "large"]);
const WEBSITE_THEME_CONTENT_WIDTH_CHOICES = new Set(["narrow", "standard", "wide"]);
const WEBSITE_THEME_SECTION_SPACING_CHOICES = new Set(["compact", "balanced", "spacious"]);
const WEBSITE_THEME_BUTTON_STYLE_CHOICES = new Set(["solid", "soft", "outline"]);
const WEBSITE_NAVIGATION_DEFAULTS = Object.freeze({
  mode: "automatic",
  show_brand: true,
  cta_label: "",
  cta_href: "",
  items: [],
  footer_text: "",
  show_powered_by: true,
  header_content: { schema_version: 1, blocks: [] },
  footer_content: { schema_version: 1, blocks: [] },
});
const WEBSITE_PAGE_CHROME_DEFAULTS = Object.freeze({
  header_mode: "inherit",
  footer_mode: "inherit",
  header_content: { schema_version: 1, blocks: [] },
  footer_content: { schema_version: 1, blocks: [] },
});
const WEBSITE_CHROME_BLOCK_TYPES = new Set(["text", "callout", "button"]);
const WEBSITE_BLOCK_TYPES = new Set(["hero", "text", "callout", "features", "image", "gallery", "form", "spacer", "section", "container", "row", "column", "stack", "grid", "divider", "button", "testimonials", "stats", "services", "contact_details", "link_list", "step_indicator", "urgency_banner", "announcement_bar", "accordion", "tabs", "video", "social_links", "map"]);
const WEBSITE_CONTAINER_BLOCK_TYPES = new Set(["section", "container", "row", "column", "stack", "grid"]);
const WEBSITE_RICH_TEXT_MARKS = Object.freeze(["bold", "italic", "underline", "strikethrough"]);
const WEBSITE_BLOCK_DESIGN_CHOICES = Object.freeze({
  font_family: new Set(["heading", "body", "system"]),
  font_size: new Set(["xs", "sm", "base", "lg", "xl", "2xl", "3xl"]),
  font_weight: new Set(["regular", "medium", "semibold", "bold"]),
  line_height: new Set(["tight", "normal", "relaxed"]),
  text_color: new Set(["text", "muted", "primary", "accent", "inverse"]),
  text_align: new Set(["left", "center", "right"]),
  padding: new Set(["none", "xs", "sm", "md", "lg", "xl"]),
  margin: new Set(["none", "xs", "sm", "md", "lg", "xl"]),
  width: new Set(["fit", "full"]),
  max_width: new Set(["narrow", "standard", "wide"]),
  min_height: new Set(["small", "medium", "large", "screen"]),
  background: new Set(["transparent", "background", "surface", "primary", "accent"]),
  border_style: new Set(["none", "solid", "dashed"]),
  border_width: new Set(["thin", "medium", "thick"]),
  border_color: new Set(["text", "muted", "primary", "accent"]),
  radius: new Set(["none", "soft", "rounded", "pill"]),
  shadow: new Set(["none", "soft", "medium", "strong"]),
  opacity: new Set(["muted", "subtle", "opaque"]),
  hover_effect: new Set(["none", "lift", "grow", "glow"]),
  button_style: new Set(["primary", "secondary", "outline", "text"]),
  button_size: new Set(["small", "medium", "large"]),
  button_width: new Set(["fit", "full"]),
  snap_alignment: new Set(["start", "center", "end"]),
});
const WEBSITE_BLOCK_DESIGN_CUSTOM_COLOR_FIELDS = new Set([
  "custom_text_color", "custom_background_color", "custom_border_color",
  "custom_button_background_color", "custom_button_text_color",
  "custom_card_background_color", "custom_card_text_color", "custom_card_border_color",
]);
const WEBSITE_BLOCK_DESIGN_CUSTOM_NUMBER_FIELDS = Object.freeze({
  custom_width_percent: [10, 220],
  custom_min_height_px: [0, 2400],
  custom_padding_px: [0, 320],
  custom_offset_x_px: [-800, 800],
  custom_offset_y_px: [-800, 800],
});
const WEBSITE_BLOCK_DESIGN_BOOLEAN_FIELDS = new Set(["locked"]);
const WEBSITE_RESPONSIVE_BREAKPOINTS = Object.freeze(["desktop", "tablet", "mobile"]);
const WEBSITE_RESPONSIVE_LAYOUT_CHOICES = Object.freeze({
  gap: new Set(["none", "small", "medium", "large"]),
  alignment: new Set(["start", "center", "end", "stretch"]),
  padding: new Set(["none", "small", "medium", "large"]),
});
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export class WebsiteBuilderError extends Error {
  constructor(code, message, statusCode = 400, details = {}) {
    super(message);
    this.name = "WebsiteBuilderError";
    this.code = code;
    this.statusCode = statusCode;
    Object.assign(this, details);
  }
}

function cleanString(value, maximumLength) {
  const text = typeof value === "string" ? value.trim() : "";
  if (text.length > maximumLength) {
    throw new WebsiteBuilderError(
      "website_field_too_long",
      `Use at most ${maximumLength} characters.`,
    );
  }
  return text;
}

function requiredName(value, label, maximumLength) {
  const name = cleanString(value, maximumLength);
  if (!name) {
    throw new WebsiteBuilderError(
      `${label.toLowerCase().replaceAll(" ", "_")}_required`,
      `${label} is required.`,
    );
  }
  return name;
}

function requiredVersion(value, field = "expected_version") {
  const parsed = typeof value === "string" && /^\d+$/.test(value.trim())
    ? Number(value.trim())
    : value;
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new WebsiteBuilderError(
      "website_version_invalid",
      `${field.replaceAll("_", " ")} is invalid.`,
    );
  }
  return parsed;
}

function contentError(message) {
  return new WebsiteBuilderError("website_page_content_invalid", message);
}

function seoError(message) {
  return new WebsiteBuilderError("website_page_seo_invalid", message);
}

function themeError(message) {
  return new WebsiteBuilderError("website_project_theme_invalid", message);
}

function navigationError(message) {
  return new WebsiteBuilderError("website_project_navigation_invalid", message);
}

function sectionError(message) {
  return new WebsiteBuilderError("website_section_invalid", message);
}

function mediaError(message, code = "website_media_invalid", statusCode = 400) {
  return new WebsiteBuilderError(code, message, statusCode);
}

function formError(message, code = "website_form_invalid", statusCode = 400) {
  return new WebsiteBuilderError(code, message, statusCode);
}

function analyticsError(message, code = "website_analytics_invalid", statusCode = 400) {
  return new WebsiteBuilderError(code, message, statusCode);
}

function normalizeWebsiteAttribution(value = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw analyticsError("Attribution is invalid.");
  const allowed = new Set(["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "referrer_host"]);
  if (Object.keys(value).some((key) => !allowed.has(key))) throw analyticsError("Attribution contains an unsupported field.");
  const referrerHost = cleanString(value.referrer_host, 253).toLowerCase().replace(/\.$/, "");
  if (referrerHost && (isIP(referrerHost) !== 0 || !referrerHost.split(".").every((label) => label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)))) {
    throw analyticsError("Referrer host is invalid.");
  }
  return {
    utm_source: cleanString(value.utm_source, 120),
    utm_medium: cleanString(value.utm_medium, 120),
    utm_campaign: cleanString(value.utm_campaign, 200),
    utm_term: cleanString(value.utm_term, 200),
    utm_content: cleanString(value.utm_content, 200),
    referrer_host: referrerHost,
  };
}

function normalizeWebsiteAnalyticsContext(value, { requireEventType = true } = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw analyticsError("Analytics context is invalid.");
  const allowed = new Set(["event_type", "event_key", "publication_id", "page_id", "form_id", "block_id", "visitor_token", "attribution"]);
  if (Object.keys(value).some((key) => !allowed.has(key))) throw analyticsError("Analytics context contains an unsupported field.");
  const eventType = requireEventType ? cleanString(value.event_type, 40) : "";
  if (requireEventType && !WEBSITE_ANALYTICS_EVENT_TYPES.has(eventType)) throw analyticsError("Analytics event type is unsupported.");
  const requiredIds = ["publication_id", "page_id"];
  for (const field of requiredIds) if (!UUID_PATTERN.test(String(value[field] || ""))) throw analyticsError(`Analytics ${field.replace("_", " ")} is invalid.`);
  const optionalId = (field) => {
    const raw = value[field];
    if (raw == null || raw === "") return null;
    if (!UUID_PATTERN.test(String(raw))) throw analyticsError(`Analytics ${field.replace("_", " ")} is invalid.`);
    return String(raw);
  };
  const visitorToken = cleanString(value.visitor_token, 100);
  if (!/^[a-zA-Z0-9_-]{16,100}$/.test(visitorToken)) throw analyticsError("Analytics visitor token is invalid.");
  const eventKey = cleanString(value.event_key, 80);
  if (!UUID_PATTERN.test(eventKey)) throw analyticsError("Analytics event identifier is invalid.");
  return {
    event_type: eventType,
    event_key: eventKey,
    publication_id: String(value.publication_id),
    page_id: String(value.page_id),
    form_id: optionalId("form_id"),
    block_id: optionalId("block_id"),
    visitor_token: visitorToken,
    attribution: normalizeWebsiteAttribution(value.attribution ?? {}),
  };
}

export function normalizeWebsiteAnalyticsEvent(body = {}) {
  return normalizeWebsiteAnalyticsContext(body);
}

export function normalizeWebsiteAnalyticsReportQuery(query = {}) {
  const days = Number(query.days ?? 30);
  if (!WEBSITE_ANALYTICS_REPORT_DAYS.has(days)) throw analyticsError("Analytics range must be 7, 30, 90, or 365 days.");
  return { days };
}

function normalizeWebsiteFormFields(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_FORM_FIELDS) {
    throw formError(`Forms must contain 1–${MAX_FORM_FIELDS} fields.`);
  }
  const keys = new Set();
  const fields = value.map((field, index) => {
    if (!field || typeof field !== "object" || Array.isArray(field)) throw formError(`Form field ${index + 1} is invalid.`);
    const key = cleanString(field.key, 40).toLowerCase().replace(/[^a-z0-9_]/g, "_").replace(/^_+|_+$/g, "");
    const label = requiredName(field.label, `Form field ${index + 1} label`, 80);
    if (!key || keys.has(key)) throw formError(`Form field ${index + 1} needs a unique key.`);
    if (!WEBSITE_FORM_FIELD_TYPES.has(field.type)) throw formError(`Form field ${index + 1} has an unsupported type.`);
    const options = field.type === "select"
      ? (Array.isArray(field.options) ? field.options.map((option) => cleanString(option, 80)).filter(Boolean).slice(0, 20) : [])
      : [];
    if (field.type === "select" && !options.length) throw formError(`Select field ${label} needs at least one option.`);
    keys.add(key);
    return { key, label, type: field.type, required: field.required === true, options };
  });
  if (!fields.some((field) => field.type === "name")) throw formError("Forms must include a name field.");
  return fields;
}

function normalizeWebsiteFormSettings(value = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw formError("Form CRM settings are invalid.");
  const tags = Array.isArray(value.tags)
    ? [...new Set(value.tags.map((tag) => cleanString(tag, 50)).filter(Boolean))].slice(0, 20)
    : [];
  const taskTitle = cleanString(value.task_title, 160);
  const taskDueDays = value.task_due_days == null || value.task_due_days === ""
    ? null
    : Number(value.task_due_days);
  if (taskDueDays !== null && (!Number.isSafeInteger(taskDueDays) || taskDueDays < 0 || taskDueDays > 365)) {
    throw formError("Task due days must be between 0 and 365.");
  }
  const stageId = value.stage_id == null || value.stage_id === "" ? null : cleanString(value.stage_id, 80);
  if (stageId && !UUID_PATTERN.test(stageId)) throw formError("Choose a valid Pipeline stage.");
  const contactMode = value.contact_mode ?? "create";
  if (contactMode !== "create" && contactMode !== "upsert") throw formError("Contact handling must create a new Contact or update an exact match.");
  return {
    contact_mode: contactMode,
    source: cleanString(value.source, 120) || "WolfCRM Website",
    tags: tags.length ? tags : ["lead", "website"],
    job_type: cleanString(value.job_type, 120),
    stage_id: stageId,
    task_title: taskTitle,
    task_due_days: taskTitle ? (taskDueDays ?? 0) : null,
    notify_owners: value.notify_owners !== false,
    success_message: cleanString(value.success_message, 300) || "Thanks — your request was received.",
  };
}

export function normalizeWebsiteFormCreate(body = {}) {
  return {
    expected_project_version: requiredVersion(body.expected_project_version, "expected_project_version"),
    name: requiredName(body.name, "Form name", 120),
    fields: normalizeWebsiteFormFields(body.fields),
    settings: normalizeWebsiteFormSettings(body.settings),
  };
}

export function normalizeWebsiteFormUpdate(body = {}) {
  const lifecycle = body.lifecycle_status;
  if (lifecycle !== undefined && lifecycle !== "draft" && lifecycle !== "archived") throw formError("Form status must be draft or archived.");
  if (body.name === undefined && body.fields === undefined && body.settings === undefined && lifecycle === undefined) {
    throw formError("Change at least one form setting.");
  }
  return {
    expected_version: requiredVersion(body.expected_version),
    expected_project_version: requiredVersion(body.expected_project_version, "expected_project_version"),
    name: body.name === undefined ? undefined : requiredName(body.name, "Form name", 120),
    fields: body.fields === undefined ? undefined : normalizeWebsiteFormFields(body.fields),
    settings: body.settings === undefined ? undefined : normalizeWebsiteFormSettings(body.settings),
    lifecycle_status: lifecycle,
  };
}

export function normalizeWebsiteFormSubmission(body = {}) {
  const idempotencyKey = cleanString(body.idempotency_key, 100);
  if (!idempotencyKey || !/^[a-zA-Z0-9_-]{16,100}$/.test(idempotencyKey)) throw formError("Submission identifier is invalid.", "website_form_submission_invalid");
  if (!body.values || typeof body.values !== "object" || Array.isArray(body.values)) throw formError("Submission values are invalid.", "website_form_submission_invalid");
  const honeypot = typeof body.website === "string" ? body.website.trim() : "";
  return {
    idempotency_key: idempotencyKey,
    values: body.values,
    honeypot,
    analytics: body.analytics == null ? null : normalizeWebsiteAnalyticsContext(body.analytics, { requireEventType: false }),
  };
}

export function normalizeWebsiteSubdomain(value) {
  const subdomain = typeof value === "string" ? value.trim().toLowerCase() : "";
  if (!subdomain || subdomain.length > SUBDOMAIN_LIMIT || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(subdomain)) {
    throw new WebsiteBuilderError(
      "website_subdomain_invalid",
      "Use 1–63 lowercase letters, numbers, or hyphens, beginning and ending with a letter or number.",
    );
  }
  return subdomain;
}

export function normalizeWebsitePublishingSettings(body = {}) {
  return {
    expected_version: requiredVersion(body.expected_version),
    subdomain: normalizeWebsiteSubdomain(body.subdomain),
  };
}

export function normalizeWebsiteDomainHostname(value) {
  const input = typeof value === "string" ? value.trim().toLowerCase().replace(/\.$/, "") : "";
  const hostname = domainToASCII(input);
  if (!hostname || hostname.length > DOMAIN_HOSTNAME_LIMIT || !hostname.includes(".") || isIP(hostname) !== 0 ||
      hostname.endsWith(".wolfcrm.site") || hostname === "wolfcrm.site" ||
      !hostname.split(".").every((label) => label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) {
    throw new WebsiteBuilderError("website_domain_invalid", "Enter a valid custom hostname outside wolfcrm.site without a protocol, port, path, or wildcard.");
  }
  return hostname;
}

export function normalizeWebsiteDomainSettings(body = {}) {
  const canonicalMode = body.canonical_mode ?? "primary";
  if (canonicalMode !== "primary" && canonicalMode !== "redirect_to_subdomain") {
    throw new WebsiteBuilderError("website_domain_canonical_invalid", "Choose custom domain primary or redirect to WolfCRM subdomain.");
  }
  return {
    expected_project_version: requiredVersion(body.expected_project_version, "expected_project_version"),
    hostname: normalizeWebsiteDomainHostname(body.hostname),
    canonical_mode: canonicalMode,
  };
}

export function normalizeWebsiteDomainVerification(body = {}) {
  return { expected_version: requiredVersion(body.expected_version) };
}

export function normalizeWebsitePublish(body = {}) {
  return { expected_project_version: requiredVersion(body.expected_project_version, "expected_project_version") };
}

function assertOnlyKeys(value, allowed, label) {
  const unknown = Object.keys(value).find((key) => !allowed.has(key));
  if (unknown) throw contentError(`${label} contains an unsupported ${unknown} field.`);
}

function blockText(value, label, maximumLength, fallback = "") {
  if (value === undefined) return fallback;
  if (typeof value !== "string") throw contentError(`${label} must be text.`);
  if (value.length > maximumLength) {
    throw contentError(`${label} may be at most ${maximumLength} characters.`);
  }
  return value;
}

function blockAlignment(value) {
  if (value === undefined) return "left";
  if (value !== "left" && value !== "center") {
    throw contentError("Block alignment must be left or center.");
  }
  return value;
}

function blockLink(value) {
  const link = blockText(value, "Button link", 500).trim();
  if (!link) return "";
  if (
    (link.startsWith("/") && !link.startsWith("//") && !/\s/.test(link)) ||
    /^https?:\/\/[^\s]+$/i.test(link) ||
    /^mailto:[^\s@]+@[^\s@]+$/i.test(link) ||
    /^tel:\+?[0-9(). -]{7,30}$/i.test(link)
  ) return link;
  throw contentError("Button links must use a local path, HTTP(S), mailto, or tel address.");
}

function normalizeWebsiteRichText(value, label, maximumLength) {
  if (value === undefined) return undefined;
  if (!value || typeof value !== "object" || Array.isArray(value)) throw contentError(`${label} rich text must be a structured object.`);
  assertOnlyKeys(value, new Set(["version", "spans"]), `${label} rich text`);
  if (value.version !== 1 || !Array.isArray(value.spans) || value.spans.length < 1 || value.spans.length > MAX_RICH_TEXT_SPANS) {
    throw contentError(`${label} rich text must use version 1 with 1–${MAX_RICH_TEXT_SPANS} spans.`);
  }
  let totalLength = 0;
  const spans = [];
  for (const [index, source] of value.spans.entries()) {
    if (!source || typeof source !== "object" || Array.isArray(source)) throw contentError(`${label} rich text span ${index + 1} must be an object.`);
    assertOnlyKeys(source, new Set(["text", "marks", "link"]), `${label} rich text span ${index + 1}`);
    const text = blockText(source.text, `${label} rich text span ${index + 1}`, maximumLength);
    totalLength += text.length;
    if (totalLength > maximumLength) throw contentError(`${label} rich text may be at most ${maximumLength} characters.`);
    const sourceMarks = source.marks ?? [];
    if (!Array.isArray(sourceMarks) || sourceMarks.some((mark) => typeof mark !== "string" || !WEBSITE_RICH_TEXT_MARKS.includes(mark))) {
      throw contentError(`${label} rich text span ${index + 1} contains an unsupported mark.`);
    }
    const marks = WEBSITE_RICH_TEXT_MARKS.filter((mark) => sourceMarks.includes(mark));
    if (new Set(sourceMarks).size !== sourceMarks.length) throw contentError(`${label} rich text span ${index + 1} contains duplicate marks.`);
    const link = source.link === undefined ? "" : blockLink(source.link);
    const normalized = { text, ...(marks.length ? { marks } : {}), ...(link ? { link } : {}) };
    const previous = spans.at(-1);
    if (previous && JSON.stringify(previous.marks ?? []) === JSON.stringify(normalized.marks ?? []) && (previous.link ?? "") === (normalized.link ?? "")) previous.text += normalized.text;
    else spans.push(normalized);
  }
  return { version: 1, spans: spans.length ? spans : [{ text: "" }] };
}

function blockItems(value, label, maximumItems, maximumLength = 300) {
  if (!Array.isArray(value) || value.length > maximumItems) {
    throw contentError(`${label} blocks may contain up to ${maximumItems} items.`);
  }
  return value.map((item, itemIndex) => blockText(item, `${label} item ${itemIndex + 1}`, maximumLength).trim());
}

function navigationLink(value) {
  try {
    return blockLink(value);
  } catch {
    throw navigationError("Navigation calls to action must use a local path, HTTP(S), mailto, or tel address.");
  }
}

function layoutChoice(value, fallback, choices, label) {
  const choice = value === undefined ? fallback : value;
  if (!choices.includes(choice)) throw contentError(`${label} is invalid.`);
  return choice;
}

function normalizeWebsiteBlockDesign(value) {
  if (value === undefined) return {};
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw contentError("Block design settings must be an object.");
  }
  assertOnlyKeys(value, new Set([...Object.keys(WEBSITE_BLOCK_DESIGN_CHOICES), ...WEBSITE_BLOCK_DESIGN_CUSTOM_COLOR_FIELDS, ...Object.keys(WEBSITE_BLOCK_DESIGN_CUSTOM_NUMBER_FIELDS), ...WEBSITE_BLOCK_DESIGN_BOOLEAN_FIELDS]), "Block design settings");
  const design = {};
  for (const [field, choices] of Object.entries(WEBSITE_BLOCK_DESIGN_CHOICES)) {
    const choice = value[field];
    if (choice === undefined || choice === "inherit") continue;
    if (typeof choice !== "string" || !choices.has(choice)) {
      throw contentError(`${field.replaceAll("_", " ")} design setting is invalid.`);
    }
    design[field] = choice;
  }
  for (const field of WEBSITE_BLOCK_DESIGN_CUSTOM_COLOR_FIELDS) {
    const color = value[field];
    if (color === undefined || color === "inherit") continue;
    if (typeof color !== "string" || !/^#[0-9a-f]{6}$/i.test(color)) throw contentError(`${field.replaceAll("_", " ")} design color is invalid.`);
    design[field] = color.toLowerCase();
  }
  for (const [field, [minimum, maximum]] of Object.entries(WEBSITE_BLOCK_DESIGN_CUSTOM_NUMBER_FIELDS)) {
    const number = value[field];
    if (number === undefined || number === "inherit") continue;
    if (!Number.isSafeInteger(number) || number < minimum || number > maximum) throw contentError(`${field.replaceAll("_", " ")} design measurement is invalid.`);
    design[field] = number;
  }
  for (const field of WEBSITE_BLOCK_DESIGN_BOOLEAN_FIELDS) {
    const boolean = value[field];
    if (boolean === undefined || boolean === "inherit") continue;
    if (typeof boolean !== "boolean") throw contentError(`${field.replaceAll("_", " ")} design setting is invalid.`);
    design[field] = boolean;
  }
  return design;
}

function normalizeWebsiteBlockResponsive(value) {
  if (value === undefined) return {};
  if (!value || typeof value !== "object" || Array.isArray(value)) throw contentError("Responsive block settings must be an object.");
  assertOnlyKeys(value, new Set(WEBSITE_RESPONSIVE_BREAKPOINTS), "Responsive block settings");
  const responsive = {};
  for (const breakpoint of WEBSITE_RESPONSIVE_BREAKPOINTS) {
    const source = value[breakpoint];
    if (source === undefined) continue;
    if (!source || typeof source !== "object" || Array.isArray(source)) throw contentError(`${breakpoint} responsive settings must be an object.`);
    assertOnlyKeys(source, new Set(["design", "layout", "visibility", "order"]), `${breakpoint} responsive settings`);
    const design = normalizeWebsiteBlockDesign(source.design);
    let layout = {};
    if (source.layout !== undefined) {
      if (!source.layout || typeof source.layout !== "object" || Array.isArray(source.layout)) throw contentError(`${breakpoint} responsive layout must be an object.`);
      assertOnlyKeys(source.layout, new Set(["columns", "gap", "alignment", "padding"]), `${breakpoint} responsive layout`);
      if (source.layout.columns !== undefined) {
        if (!Number.isSafeInteger(source.layout.columns) || source.layout.columns < 1 || source.layout.columns > 6) throw contentError(`${breakpoint} responsive columns must be one through six.`);
        layout.columns = source.layout.columns;
      }
      for (const [field, choices] of Object.entries(WEBSITE_RESPONSIVE_LAYOUT_CHOICES)) {
        const choice = source.layout[field];
        if (choice === undefined || choice === "inherit") continue;
        if (typeof choice !== "string" || !choices.has(choice)) throw contentError(`${breakpoint} responsive ${field} is invalid.`);
        layout[field] = choice;
      }
    }
    const visibility = source.visibility;
    if (visibility !== undefined && visibility !== "visible" && visibility !== "hidden" && visibility !== "inherit") throw contentError(`${breakpoint} responsive visibility is invalid.`);
    const order = source.order;
    if (order !== undefined && (!Number.isSafeInteger(order) || order < -20 || order > 20)) throw contentError(`${breakpoint} responsive order must be a whole number from -20 through 20.`);
    const override = {
      ...(Object.keys(design).length ? { design } : {}),
      ...(Object.keys(layout).length ? { layout } : {}),
      ...(visibility && visibility !== "inherit" ? { visibility } : {}),
      ...(order !== undefined ? { order } : {}),
    };
    if (Object.keys(override).length) responsive[breakpoint] = override;
  }
  return responsive;
}

function normalizeWebsiteBlock(value, index, context, depth = 1) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw contentError(`Block ${index + 1} must be an object.`);
  }
  assertOnlyKeys(value, new Set(["id", "type", "data", "design", "responsive", "children"]), `Block ${index + 1}`);
  if (typeof value.id !== "string" || !UUID_PATTERN.test(value.id)) {
    throw contentError(`Block ${index + 1} has an invalid identifier.`);
  }
  if (typeof value.type !== "string" || !WEBSITE_BLOCK_TYPES.has(value.type)) {
    throw contentError(`Block ${index + 1} has an unsupported type.`);
  }
  if (!value.data || typeof value.data !== "object" || Array.isArray(value.data)) {
    throw contentError(`Block ${index + 1} properties must be an object.`);
  }
  if (depth > MAX_BLOCK_DEPTH) throw contentError(`Page layout may be at most ${MAX_BLOCK_DEPTH} levels deep.`);
  context.count += 1;
  if (context.count > MAX_BLOCKS_PER_PAGE) throw contentError(`A page may contain up to ${MAX_BLOCKS_PER_PAGE} blocks.`);
  if (context.ids.has(value.id)) throw contentError("Every block must have a unique identifier.");
  context.ids.add(value.id);
  const design = normalizeWebsiteBlockDesign(value.design);
  const responsive = normalizeWebsiteBlockResponsive(value.responsive);
  let data;
  if (value.type === "hero" || value.type === "callout") {
    assertOnlyKeys(
      value.data,
      new Set(["heading", "body", "body_rich_text", "button_label", "button_href", "alignment"]),
      `${value.type} block`,
    );
    const richText = normalizeWebsiteRichText(value.data.body_rich_text, "Body", 2000);
    data = {
      heading: blockText(value.data.heading, "Heading", 160),
      body: richText ? richText.spans.map((span) => span.text).join("") : blockText(value.data.body, "Body", 2000),
      ...(richText ? { body_rich_text: richText } : {}),
      button_label: blockText(value.data.button_label, "Button label", 80),
      button_href: blockLink(value.data.button_href),
      alignment: blockAlignment(value.data.alignment),
    };
  } else if (value.type === "text") {
    assertOnlyKeys(value.data, new Set(["heading", "body", "body_rich_text", "alignment"]), "Text block");
    const richText = normalizeWebsiteRichText(value.data.body_rich_text, "Body", 5000);
    data = {
      heading: blockText(value.data.heading, "Heading", 160),
      body: richText ? richText.spans.map((span) => span.text).join("") : blockText(value.data.body, "Body", 5000),
      ...(richText ? { body_rich_text: richText } : {}),
      alignment: blockAlignment(value.data.alignment),
    };
  } else if (value.type === "features") {
    assertOnlyKeys(value.data, new Set(["heading", "items", "columns"]), "Features block");
    if (!Array.isArray(value.data.items) || value.data.items.length > 12) {
      throw contentError("Features blocks may contain up to 12 items.");
    }
    const columns = value.data.columns === undefined ? 3 : value.data.columns;
    if (![2, 3, 4].includes(columns)) {
      throw contentError("Feature columns must be 2, 3, or 4.");
    }
    data = {
      heading: blockText(value.data.heading, "Heading", 160),
      items: value.data.items.map((item, itemIndex) =>
        blockText(item, `Feature ${itemIndex + 1}`, 180).trim(),
      ),
      columns,
    };
  } else if (["testimonials", "stats", "services"].includes(value.type)) {
    assertOnlyKeys(value.data, new Set(["heading", "items", "columns"]), `${value.type} block`);
    const maximumItems = value.type === "testimonials" ? 8 : value.type === "stats" ? 6 : 12;
    const columns = value.data.columns === undefined ? (value.type === "testimonials" ? 2 : 3) : value.data.columns;
    if (!Number.isSafeInteger(columns) || columns < 1 || columns > 4) throw contentError(`${value.type} columns must be one through four.`);
    data = { heading: blockText(value.data.heading, "Heading", 160), items: blockItems(value.data.items, value.type, maximumItems), columns };
  } else if (value.type === "link_list") {
    assertOnlyKeys(value.data, new Set(["heading", "items", "columns"]), "Link list block");
    const columns = value.data.columns === undefined ? 3 : value.data.columns;
    if (!Number.isSafeInteger(columns) || columns < 1 || columns > 4) throw contentError("Link list columns must be one through four.");
    const items = blockItems(value.data.items, "Link list", 12, 600).map((item, itemIndex) => {
      const separator = item.indexOf("|");
      if (separator < 1) throw contentError(`Link list item ${itemIndex + 1} must use Label|URL.`);
      const label = blockText(item.slice(0, separator).trim(), `Link list label ${itemIndex + 1}`, 80);
      const href = blockLink(item.slice(separator + 1).trim());
      if (!label || !href) throw contentError(`Link list item ${itemIndex + 1} must include a label and URL.`);
      return `${label}|${href}`;
    });
    data = { heading: blockText(value.data.heading, "Heading", 160), items, columns };
  } else if (value.type === "step_indicator") {
    assertOnlyKeys(value.data, new Set(["heading", "items", "active_step"]), "Funnel step block");
    const items = blockItems(value.data.items, "Funnel step", 8);
    const activeStep = value.data.active_step === undefined ? 1 : value.data.active_step;
    if (!Number.isSafeInteger(activeStep) || activeStep < 1 || activeStep > 8) throw contentError("Active funnel step must be one through eight.");
    data = { heading: blockText(value.data.heading, "Heading", 160), items, active_step: activeStep };
  } else if (value.type === "accordion" || value.type === "tabs") {
    assertOnlyKeys(value.data, new Set(["heading", "items", "active_item"]), `${value.type} block`);
    const items = blockItems(value.data.items, value.type, 10, 760).map((item, itemIndex) => {
      const separator = item.indexOf("|");
      if (separator < 1 || separator === item.length - 1) throw contentError(`${value.type} item ${itemIndex + 1} must use Label|Content.`);
      const label = blockText(item.slice(0, separator).trim(), `${value.type} label ${itemIndex + 1}`, 120);
      const content = blockText(item.slice(separator + 1).trim(), `${value.type} content ${itemIndex + 1}`, 600);
      if (!label || !content) throw contentError(`${value.type} item ${itemIndex + 1} must include a label and content.`);
      return `${label}|${content}`;
    });
    if (!items.length) throw contentError(`${value.type} blocks require at least one item.`);
    const activeItem = value.data.active_item === undefined ? 1 : value.data.active_item;
    if (!Number.isSafeInteger(activeItem) || activeItem < 1 || activeItem > items.length) throw contentError(`Active ${value.type} item must reference an existing item.`);
    data = { heading: blockText(value.data.heading, "Heading", 160), items, active_item: activeItem };
  } else if (value.type === "video") {
    assertOnlyKeys(value.data, new Set(["heading", "provider", "video_id", "caption", "aspect_ratio"]), "Video block");
    const provider = layoutChoice(value.data.provider, "youtube", ["youtube", "vimeo"], "Video provider");
    const videoId = blockText(value.data.video_id, "Video identifier", 20).trim();
    const validId = provider === "youtube" ? /^[A-Za-z0-9_-]{6,20}$/.test(videoId) : /^\d{6,12}$/.test(videoId);
    if (!validId) throw contentError("Video identifiers must be a valid YouTube or Vimeo ID, not a URL or embed code.");
    data = {
      heading: blockText(value.data.heading, "Heading", 160),
      provider,
      video_id: videoId,
      caption: blockText(value.data.caption, "Video caption", 500),
      aspect_ratio: layoutChoice(value.data.aspect_ratio, "widescreen", ["widescreen", "square", "portrait"], "Video aspect ratio"),
    };
  } else if (value.type === "social_links") {
    assertOnlyKeys(value.data, new Set(["heading", "items", "alignment"]), "Social links block");
    const platformHosts = {
      facebook: ["facebook.com"], instagram: ["instagram.com"], youtube: ["youtube.com"], linkedin: ["linkedin.com"],
      tiktok: ["tiktok.com"], x: ["x.com", "twitter.com"], nextdoor: ["nextdoor.com"],
    };
    const items = blockItems(value.data.items, "Social link", 8, 520).map((item, itemIndex) => {
      const separator = item.indexOf("|");
      const platform = item.slice(0, separator).trim().toLowerCase();
      const href = item.slice(separator + 1).trim();
      let url;
      try { url = new URL(href); } catch { throw contentError(`Social link ${itemIndex + 1} must be a valid platform HTTPS URL.`); }
      const allowedHosts = platformHosts[platform];
      const hostAllowed = allowedHosts?.some((host) => url.hostname === host || url.hostname.endsWith(`.${host}`));
      const explicitPort = /:\d+$/.test(href.slice("https://".length).split(/[/?#]/, 1)[0]);
      if (separator < 1 || !allowedHosts || url.protocol !== "https:" || url.username || url.password || url.port || explicitPort || !hostAllowed) throw contentError(`Social link ${itemIndex + 1} must match its supported platform HTTPS hostname.`);
      return `${platform}|${url.toString()}`;
    });
    if (!items.length) throw contentError("Social links blocks require at least one profile.");
    data = { heading: blockText(value.data.heading, "Heading", 160), items, alignment: blockAlignment(value.data.alignment) };
  } else if (value.type === "map") {
    assertOnlyKeys(value.data, new Set(["heading", "address", "zoom", "height", "link_label"]), "Map block");
    const zoom = value.data.zoom === undefined ? 14 : value.data.zoom;
    if (!Number.isSafeInteger(zoom) || zoom < 3 || zoom > 20) throw contentError("Map zoom must be a whole number from 3 through 20.");
    const address = blockText(value.data.address, "Map address", 300).trim();
    if (!address) throw contentError("Map blocks require a public address or location.");
    data = { heading: blockText(value.data.heading, "Heading", 160), address, zoom, height: layoutChoice(value.data.height, "standard", ["compact", "standard", "tall"], "Map height"), link_label: blockText(value.data.link_label, "Map link label", 80) };
  } else if (value.type === "button") {
    assertOnlyKeys(value.data, new Set(["label", "href", "alignment", "style"]), "Button block");
    data = {
      label: blockText(value.data.label, "Button label", 80),
      href: blockLink(value.data.href),
      alignment: blockAlignment(value.data.alignment),
      style: layoutChoice(value.data.style, "primary", ["primary", "secondary", "text"], "Button style"),
    };
  } else if (value.type === "contact_details") {
    assertOnlyKeys(value.data, new Set(["heading", "phone", "email", "address", "hours"]), "Contact details block");
    data = {
      heading: blockText(value.data.heading, "Heading", 160),
      phone: blockText(value.data.phone, "Phone", 80),
      email: blockText(value.data.email, "Email", 254),
      address: blockText(value.data.address, "Address", 300),
      hours: blockText(value.data.hours, "Hours", 300),
    };
  } else if (value.type === "urgency_banner") {
    assertOnlyKeys(value.data, new Set(["heading", "body", "body_rich_text", "button_label", "button_href", "alignment"]), "Urgency banner block");
    const richText = normalizeWebsiteRichText(value.data.body_rich_text, "Body", 2000);
    data = {
      heading: blockText(value.data.heading, "Heading", 160),
      body: richText ? richText.spans.map((span) => span.text).join("") : blockText(value.data.body, "Body", 2000),
      ...(richText ? { body_rich_text: richText } : {}),
      button_label: blockText(value.data.button_label, "Button label", 80),
      button_href: blockLink(value.data.button_href),
      alignment: blockAlignment(value.data.alignment),
    };
  } else if (value.type === "announcement_bar") {
    assertOnlyKeys(value.data, new Set(["message", "link_label", "link_href", "tone", "alignment", "behavior"]), "Announcement bar block");
    const message = blockText(value.data.message, "Announcement message", 240).trim();
    const linkLabel = blockText(value.data.link_label, "Announcement link label", 80).trim();
    const linkHref = blockLink(value.data.link_href);
    if (!message) throw contentError("Announcement bars require a message.");
    if (Boolean(linkLabel) !== Boolean(linkHref)) throw contentError("Announcement action label and link must be provided together.");
    data = {
      message,
      link_label: linkLabel,
      link_href: linkHref,
      tone: layoutChoice(value.data.tone, "primary", ["neutral", "primary", "accent"], "Announcement tone"),
      alignment: blockAlignment(value.data.alignment),
      behavior: layoutChoice(value.data.behavior, "static", ["static", "dismissible"], "Announcement behavior"),
    };
  } else if (value.type === "image") {
    assertOnlyKeys(value.data, new Set(["media_id", "alt_text", "caption", "fit", "focal_x", "focal_y"]), "Image block");
    if (typeof value.data.media_id !== "string" || !UUID_PATTERN.test(value.data.media_id)) {
      throw contentError("Image blocks must reference a valid company media item.");
    }
    const fit = value.data.fit === undefined ? "cover" : value.data.fit;
    if (fit !== "cover" && fit !== "contain") throw contentError("Image fit must be cover or contain.");
    const focalX = value.data.focal_x === undefined ? 50 : value.data.focal_x;
    const focalY = value.data.focal_y === undefined ? 50 : value.data.focal_y;
    if (!Number.isSafeInteger(focalX) || focalX < 0 || focalX > 100 || !Number.isSafeInteger(focalY) || focalY < 0 || focalY > 100) {
      throw contentError("Image focal points must be whole percentages from 0 through 100.");
    }
    data = {
      media_id: value.data.media_id,
      alt_text: blockText(value.data.alt_text, "Image alternative text", 300),
      caption: blockText(value.data.caption, "Image caption", 500),
      fit,
      focal_x: focalX,
      focal_y: focalY,
    };
  } else if (value.type === "gallery") {
    assertOnlyKeys(value.data, new Set(["heading", "items", "columns", "aspect_ratio", "gap"]), "Gallery block");
    const items = blockItems(value.data.items, "Gallery", 12, 340).map((item, itemIndex) => {
      const separator = item.indexOf("|");
      const mediaId = item.slice(0, separator).trim();
      const altText = blockText(item.slice(separator + 1), `Gallery image ${itemIndex + 1} alternative text`, 300);
      if (separator < 1 || !UUID_PATTERN.test(mediaId)) throw contentError(`Gallery image ${itemIndex + 1} must reference valid company media.`);
      return `${mediaId}|${altText}`;
    });
    if (new Set(items.map((item) => item.slice(0, item.indexOf("|")))).size !== items.length) throw contentError("Gallery images must be unique.");
    const columns = value.data.columns === undefined ? 3 : value.data.columns;
    if (![2, 3, 4].includes(columns)) throw contentError("Gallery columns must be 2, 3, or 4.");
    data = {
      heading: blockText(value.data.heading, "Gallery heading", 160),
      items,
      columns,
      aspect_ratio: layoutChoice(value.data.aspect_ratio, "landscape", ["landscape", "square", "portrait"], "Gallery aspect ratio"),
      gap: layoutChoice(value.data.gap, "standard", ["compact", "standard", "spacious"], "Gallery gap"),
    };
  } else if (value.type === "form") {
    assertOnlyKeys(value.data, new Set(["form_id", "heading", "body", "body_rich_text", "button_label"]), "Form block");
    if (typeof value.data.form_id !== "string" || !UUID_PATTERN.test(value.data.form_id)) {
      throw contentError("Form blocks must reference a valid project form.");
    }
    const richText = normalizeWebsiteRichText(value.data.body_rich_text, "Form body", 1000);
    data = {
      form_id: value.data.form_id,
      heading: blockText(value.data.heading, "Form heading", 160),
      body: richText ? richText.spans.map((span) => span.text).join("") : blockText(value.data.body, "Form body", 1000),
      ...(richText ? { body_rich_text: richText } : {}),
      button_label: blockText(value.data.button_label, "Form button label", 80) || "Send request",
    };
  } else if (value.type === "spacer") {
    assertOnlyKeys(value.data, new Set(["size"]), "Spacer block");
    const size = value.data.size === undefined ? "medium" : value.data.size;
    if (!["small", "medium", "large"].includes(size)) {
      throw contentError("Spacer size must be small, medium, or large.");
    }
    data = { size };
  } else if (value.type === "divider") {
    assertOnlyKeys(value.data, new Set(["style", "width", "tone"]), "Divider block");
    data = {
      style: layoutChoice(value.data.style, "solid", ["solid", "dashed", "dotted"], "Divider style"),
      width: layoutChoice(value.data.width, "full", ["short", "medium", "full"], "Divider width"),
      tone: layoutChoice(value.data.tone, "muted", ["muted", "primary", "accent"], "Divider tone"),
    };
  } else if (value.type === "section") {
    assertOnlyKeys(value.data, new Set(["width", "padding", "background", "overlay"]), "Section block");
    const overlay = value.data.overlay === undefined ? 0 : value.data.overlay;
    if (!Number.isSafeInteger(overlay) || overlay < 0 || overlay > 80) throw contentError("Section overlay must be a whole percentage from 0 through 80.");
    data = {
      width: layoutChoice(value.data.width, "full", ["full", "boxed"], "Section width"),
      padding: layoutChoice(value.data.padding, "large", ["none", "small", "medium", "large"], "Section padding"),
      background: layoutChoice(value.data.background, "default", ["default", "surface", "primary", "accent"], "Section background"),
      overlay,
    };
  } else if (value.type === "container") {
    assertOnlyKeys(value.data, new Set(["max_width", "padding", "alignment"]), "Container block");
    data = {
      max_width: layoutChoice(value.data.max_width, "standard", ["narrow", "standard", "wide"], "Container width"),
      padding: layoutChoice(value.data.padding, "medium", ["none", "small", "medium", "large"], "Container padding"),
      alignment: layoutChoice(value.data.alignment, "stretch", ["start", "center", "end", "stretch"], "Container alignment"),
    };
  } else if (value.type === "row") {
    assertOnlyKeys(value.data, new Set(["columns", "gap", "stack_at", "alignment"]), "Row block");
    const columns = value.data.columns === undefined ? 2 : value.data.columns;
    if (!Number.isSafeInteger(columns) || columns < 1 || columns > 6) throw contentError("Rows must contain one through six columns.");
    data = {
      columns,
      gap: layoutChoice(value.data.gap, "medium", ["none", "small", "medium", "large"], "Row gap"),
      stack_at: layoutChoice(value.data.stack_at, "mobile", ["never", "tablet", "mobile"], "Row stacking breakpoint"),
      alignment: layoutChoice(value.data.alignment, "stretch", ["start", "center", "end", "stretch"], "Row alignment"),
    };
  } else if (value.type === "column") {
    assertOnlyKeys(value.data, new Set(["alignment", "padding"]), "Column block");
    data = {
      alignment: layoutChoice(value.data.alignment, "stretch", ["start", "center", "end", "stretch"], "Column alignment"),
      padding: layoutChoice(value.data.padding, "none", ["none", "small", "medium", "large"], "Column padding"),
    };
  } else if (value.type === "stack") {
    assertOnlyKeys(value.data, new Set(["gap", "alignment"]), "Stack block");
    data = {
      gap: layoutChoice(value.data.gap, "medium", ["none", "small", "medium", "large"], "Stack gap"),
      alignment: layoutChoice(value.data.alignment, "stretch", ["start", "center", "end", "stretch"], "Stack alignment"),
    };
  } else {
    assertOnlyKeys(value.data, new Set(["columns", "gap", "stack_at"]), "Grid block");
    const columns = value.data.columns === undefined ? 3 : value.data.columns;
    if (!Number.isSafeInteger(columns) || columns < 1 || columns > 6) throw contentError("Grids must use one through six columns.");
    data = {
      columns,
      gap: layoutChoice(value.data.gap, "medium", ["none", "small", "medium", "large"], "Grid gap"),
      stack_at: layoutChoice(value.data.stack_at, "mobile", ["never", "tablet", "mobile"], "Grid stacking breakpoint"),
    };
  }
  if (!WEBSITE_CONTAINER_BLOCK_TYPES.has(value.type)) {
    if (value.children !== undefined) throw contentError(`${value.type} blocks cannot contain child blocks.`);
    return { id: value.id, type: value.type, data, ...(Object.keys(design).length ? { design } : {}), ...(Object.keys(responsive).length ? { responsive } : {}) };
  }
  if (!Array.isArray(value.children)) throw contentError(`${value.type} blocks must contain a child block list.`);
  const children = value.children.map((child, childIndex) => normalizeWebsiteBlock(child, childIndex, context, depth + 1));
  if (value.type === "row" && (children.length !== data.columns || children.some((child) => child.type !== "column"))) {
    throw contentError("Row children must be columns matching the configured column count.");
  }
  if (value.type !== "row" && children.some((child) => child.type === "column")) {
    throw contentError("Columns may only be direct children of a row.");
  }
  return { id: value.id, type: value.type, data, ...(Object.keys(design).length ? { design } : {}), ...(Object.keys(responsive).length ? { responsive } : {}), children };
}

export function flattenWebsiteBlocks(content) {
  const flattened = [];
  const visit = (blocks) => blocks.forEach((block) => { flattened.push(block); if (Array.isArray(block.children)) visit(block.children); });
  visit(Array.isArray(content?.blocks) ? content.blocks : []);
  return flattened;
}

function websiteMediaReferences(content) {
  const ids = [];
  for (const block of flattenWebsiteBlocks(content)) {
    if (block?.type === "image" && typeof block.data?.media_id === "string" && UUID_PATTERN.test(block.data.media_id)) ids.push(block.data.media_id);
    if (block?.type === "gallery" && Array.isArray(block.data?.items)) {
      for (const item of block.data.items) {
        const mediaId = typeof item === "string" ? item.slice(0, item.indexOf("|")) : "";
        if (UUID_PATTERN.test(mediaId)) ids.push(mediaId);
      }
    }
  }
  return [...new Set(ids)];
}

export function normalizeWebsitePageContent(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw contentError("Page content must be a structured document.");
  }
  assertOnlyKeys(value, new Set(["schema_version", "blocks"]), "Page content");
  if (value.schema_version !== 1 || !Array.isArray(value.blocks)) {
    throw contentError("Page content must use block schema version 1.");
  }
  const context = { count: 0, ids: new Set() };
  const blocks = value.blocks.map((block, index) => normalizeWebsiteBlock(block, index, context));
  const content = { schema_version: 1, blocks };
  if (Buffer.byteLength(JSON.stringify(content), "utf8") > MAX_PAGE_CONTENT_BYTES) {
    throw contentError("Page content is too large to save.");
  }
  return content;
}

function normalizeWebsiteChromeContent(value, label) {
  const content = normalizeWebsitePageContent(value ?? { schema_version: 1, blocks: [] });
  if (content.blocks.length > 12 || content.blocks.some((block) => !WEBSITE_CHROME_BLOCK_TYPES.has(block.type))) {
    throw navigationError(`${label} may contain up to 12 Text, Callout, or Button elements.`);
  }
  return content;
}

export function normalizeWebsitePageChrome(value = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new WebsiteBuilderError("website_page_chrome_invalid", "Page chrome settings must be an object.");
  }
  const allowed = new Set(["header_mode", "footer_mode", "header_content", "footer_content"]);
  const unknown = Object.keys(value).find((key) => !allowed.has(key));
  if (unknown) throw new WebsiteBuilderError("website_page_chrome_invalid", `Page chrome contains an unsupported ${unknown} field.`);
  const mode = (candidate, label) => {
    const result = candidate ?? "inherit";
    if (!new Set(["inherit", "hidden", "replace"]).has(result)) {
      throw new WebsiteBuilderError("website_page_chrome_invalid", `${label} must inherit, hide, or replace the global region.`);
    }
    return result;
  };
  return {
    header_mode: mode(value.header_mode, "Header"),
    footer_mode: mode(value.footer_mode, "Footer"),
    header_content: normalizeWebsiteChromeContent(value.header_content, "Page header"),
    footer_content: normalizeWebsiteChromeContent(value.footer_content, "Page footer"),
  };
}

function websitePageChromePayload(value) {
  const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const compatible = Object.fromEntries(Object.entries(source).filter(([key]) => Object.hasOwn(WEBSITE_PAGE_CHROME_DEFAULTS, key)));
  try { return normalizeWebsitePageChrome({ ...WEBSITE_PAGE_CHROME_DEFAULTS, ...compatible }); }
  catch { return structuredClone(WEBSITE_PAGE_CHROME_DEFAULTS); }
}

export function normalizeWebsiteSectionCreate(body = {}) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw sectionError("Reusable section details must be an object.");
  }
  const unknown = Object.keys(body).find((key) => !["name", "content"].includes(key));
  if (unknown) throw sectionError(`Reusable section contains an unsupported ${unknown} field.`);
  const content = normalizeWebsitePageContent(body.content);
  if (!content.blocks.length) throw sectionError("A reusable section must contain at least one block.");
  if (flattenWebsiteBlocks(content).some((block) => block.type === "form")) throw sectionError("Project forms cannot be saved as company reusable sections.");
  return { name: requiredName(body.name, "Reusable section name", PAGE_NAME_LIMIT), content };
}

export function normalizeWebsiteSectionUpdate(body = {}) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw sectionError("Reusable section changes must be an object.");
  }
  const unknown = Object.keys(body).find((key) => !["expected_version", "name", "content", "lifecycle_status"].includes(key));
  if (unknown) throw sectionError(`Reusable section changes contain an unsupported ${unknown} field.`);
  const update = {
    expected_version: requiredVersion(body.expected_version),
    name: body.name === undefined ? undefined : requiredName(body.name, "Reusable section name", PAGE_NAME_LIMIT),
    content: body.content === undefined ? undefined : normalizeWebsitePageContent(body.content),
    lifecycle_status: body.lifecycle_status === undefined ? undefined : lifecycleStatus(body.lifecycle_status),
  };
  if (update.content && !update.content.blocks.length) throw sectionError("A reusable section must contain at least one block.");
  if (update.content && flattenWebsiteBlocks(update.content).some((block) => block.type === "form")) throw sectionError("Project forms cannot be saved as company reusable sections.");
  if (update.name === undefined && update.content === undefined && update.lifecycle_status === undefined) {
    throw sectionError("Change the reusable section before saving.");
  }
  return update;
}

function safeMediaFileName(value) {
  return requiredName(value, "Media file name", 160)
    .replace(/[^a-zA-Z0-9._ -]+/g, "_")
    .replace(/\s+/g, " ");
}

export function normalizeWebsiteMediaReserve(body = {}) {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw mediaError("Media details must be an object.");
  const unknown = Object.keys(body).find((key) => !["file_name", "mime_type", "byte_size", "alt_text"].includes(key));
  if (unknown) throw mediaError(`Media details contain an unsupported ${unknown} field.`);
  if (!WEBSITE_MEDIA_MIME_TYPES.has(body.mime_type)) throw mediaError("Choose a JPEG, PNG, WebP, or GIF image.");
  if (!Number.isSafeInteger(body.byte_size) || body.byte_size < 1 || body.byte_size > MAX_MEDIA_BYTES) {
    throw mediaError("Website images must be between 1 byte and 10 MB.", body.byte_size > MAX_MEDIA_BYTES ? "website_media_too_large" : "website_media_invalid", body.byte_size > MAX_MEDIA_BYTES ? 413 : 400);
  }
  return {
    file_name: safeMediaFileName(body.file_name),
    mime_type: body.mime_type,
    byte_size: body.byte_size,
    alt_text: cleanString(body.alt_text, 300),
  };
}

export function normalizeWebsiteMediaUpdate(body = {}) {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw mediaError("Media changes must be an object.");
  const unknown = Object.keys(body).find((key) => !["expected_version", "alt_text", "lifecycle_status"].includes(key));
  if (unknown) throw mediaError(`Media changes contain an unsupported ${unknown} field.`);
  const lifecycle = body.lifecycle_status;
  if (lifecycle !== undefined && lifecycle !== "ready" && lifecycle !== "archived") throw mediaError("Media may be ready or archived.");
  const update = {
    expected_version: requiredVersion(body.expected_version),
    alt_text: body.alt_text === undefined ? undefined : cleanString(body.alt_text, 300),
    lifecycle_status: lifecycle,
  };
  if (update.alt_text === undefined && update.lifecycle_status === undefined) throw mediaError("Change the media item before saving.");
  return update;
}

function templateBlock(type, data, { design, responsive, children } = {}) {
  return { type, data, ...(design ? { design } : {}), ...(responsive ? { responsive } : {}), ...(children ? { children } : {}) };
}

function templateSection(children, { background = "default", padding = "large", width = "full", design } = {}) {
  return templateBlock("section", { width, padding, background, overlay: 0 }, { design, children });
}

function templateContainer(children, { maxWidth = "standard", padding = "medium", alignment = "stretch" } = {}) {
  return templateBlock("container", { max_width: maxWidth, padding, alignment }, { children });
}

function templateRow(columns, { gap = "large", alignment = "stretch", stackAt = "tablet" } = {}) {
  return templateBlock("row", { columns: columns.length, gap, stack_at: stackAt, alignment }, {
    children: columns.map((children) => templateBlock("column", { alignment: "stretch", padding: "small" }, { children })),
  });
}

function instantiateTemplateBlock(blueprint) {
  return {
    id: randomUUID(),
    type: blueprint.type,
    data: structuredClone(blueprint.data),
    ...(blueprint.design ? { design: structuredClone(blueprint.design) } : {}),
    ...(blueprint.responsive ? { responsive: structuredClone(blueprint.responsive) } : {}),
    ...(blueprint.children ? { children: blueprint.children.map(instantiateTemplateBlock) } : {}),
  };
}

const WEBSITE_TEMPLATE_BLUEPRINTS = Object.freeze([
  {
    id: "service-authority",
    name: "Local service authority",
    description: "A complete service-business homepage with trust, services, process, proof, and estimate calls to action.",
    kinds: ["website", "landing_page"],
    blocks: [
      templateSection([templateContainer([
        templateBlock("hero", { heading: "Home service done right, from the first call", body: "Dependable local professionals, clear communication, and workmanship built around your home.", button_label: "Request a free estimate", button_href: "/contact", alignment: "left" }, { design: { min_height: "large", max_width: "wide", text_color: "inverse" } }),
      ], { maxWidth: "wide" })], { background: "primary" }),
      templateSection([templateContainer([
        templateBlock("stats", { heading: "Trusted across our community", items: ["Locally owned and operated", "Clear estimates before work begins", "Responsive support from start to finish"], columns: 3 }),
      ])], { background: "surface", padding: "medium" }),
      templateSection([templateContainer([
        templateRow([
          [templateBlock("text", { heading: "A better service experience", body: "Tell visitors which problems you solve, the neighborhoods you serve, and the standards your crew brings to every appointment.", alignment: "left" }, { design: { font_size: "lg", line_height: "relaxed" } })],
          [templateBlock("features", { heading: "What you can expect", items: ["Fast, respectful communication", "Experienced, prepared technicians", "Straightforward options and pricing", "A clean, professional jobsite"], columns: 2 })],
        ]),
      ], { maxWidth: "wide" })]),
      templateSection([templateContainer([
        templateBlock("services", { heading: "Services built around your property", items: ["Repairs and troubleshooting", "Preventive maintenance", "Replacement and installation", "Urgent service support", "Property assessments", "Custom project planning"], columns: 3 }),
      ], { maxWidth: "wide" })], { background: "surface" }),
      templateSection([templateContainer([
        templateBlock("step_indicator", { heading: "Simple from first call to final walkthrough", items: ["Tell us what you need", "Review your options", "Choose the right plan", "Enjoy the finished work"], active_step: 1 }),
      ])]),
      templateSection([templateContainer([
        templateBlock("testimonials", { heading: "Neighbors recommend our team", items: ["The team explained every option and kept us updated throughout the project. — Jamie R.", "Professional, punctual, and careful with our home from beginning to end. — Morgan T.", "The estimate was clear and the finished work exceeded our expectations. — Casey L."], columns: 3 }),
      ], { maxWidth: "wide" })], { background: "surface" }),
      templateSection([templateContainer([
        templateRow([
          [templateBlock("contact_details", { heading: "Talk with a local expert", phone: "(555) 555-0123", email: "hello@example.com", address: "Proudly serving your local area", hours: "Monday–Friday, 8am–5pm" })],
          [templateBlock("callout", { heading: "Ready for a clear plan?", body: "Share a few details and our team will follow up with the right next step.", button_label: "Get my free estimate", button_href: "/contact", alignment: "center" }, { design: { background: "accent", radius: "rounded", shadow: "medium", padding: "lg" } })],
        ]),
      ], { maxWidth: "wide" })], { background: "primary" }),
    ],
  },
  {
    id: "campaign-offer",
    name: "Lead-generation campaign",
    description: "A focused campaign page with offer framing, qualification, trust proof, urgency, and a CRM-form-ready close.",
    kinds: ["landing_page", "website"],
    blocks: [
      templateSection([templateContainer([
        templateBlock("urgency_banner", { heading: "Seasonal appointments are now open", body: "Reserve a convenient time before this service window fills.", button_label: "Check availability", button_href: "/contact", alignment: "center" }),
        templateBlock("hero", { heading: "Solve the problem before it becomes a bigger repair", body: "Lead with one specific outcome, a credible offer, and a low-friction reason to act today.", button_label: "Request my estimate", button_href: "/contact", alignment: "center" }, { design: { min_height: "medium", max_width: "standard", text_color: "inverse" } }),
      ], { maxWidth: "wide" })], { background: "primary" }),
      templateSection([templateContainer([
        templateBlock("stats", { heading: "A local team homeowners trust", items: ["Fast response", "Clear recommendations", "Professional service"], columns: 3 }),
      ])], { background: "surface", padding: "medium" }),
      templateSection([templateContainer([
        templateRow([
          [templateBlock("text", { heading: "Is this service right for your home?", body: "Explain the warning signs, homeowner concerns, or seasonal conditions that make this offer relevant.", alignment: "left" })],
          [templateBlock("features", { heading: "Your visit includes", items: ["A focused property assessment", "Straightforward findings", "Options matched to your goals", "A written next-step recommendation"], columns: 2 })],
        ]),
      ], { maxWidth: "wide" })]),
      templateSection([templateContainer([
        templateBlock("services", { heading: "Choose the help you need", items: ["Inspection and diagnosis", "Repair recommendation", "Maintenance option", "Replacement estimate"], columns: 4 }),
      ], { maxWidth: "wide" })], { background: "surface" }),
      templateSection([templateContainer([
        templateBlock("testimonials", { heading: "Real service, clearly explained", items: ["They found the issue quickly and gave us options without pressure. — Alex P.", "Booking was easy, communication was excellent, and the work was spotless. — Jordan M."], columns: 2 }),
      ])]),
      templateSection([templateContainer([
        templateBlock("features", { heading: "What happens after you reach out", items: ["We review your request", "A local specialist follows up", "You choose a convenient appointment"], columns: 3 }),
        templateBlock("callout", { heading: "Get your personalized recommendation", body: "Add your CRM-native form below this section, or link this action to your contact page.", button_label: "Start my request", button_href: "/contact", alignment: "center" }, { design: { background: "accent", radius: "rounded", shadow: "medium", padding: "xl" } }),
      ], { maxWidth: "standard" })], { background: "primary" }),
    ],
  },
  {
    id: "funnel-conversion-step",
    name: "Quote request funnel",
    description: "A complete quote-intake step with progress, service choices, expectations, proof, and a single next action.",
    kinds: ["funnel"],
    blocks: [
      templateSection([templateContainer([
        templateBlock("step_indicator", { heading: "Your free quote", items: ["Project details", "Property information", "Preferred timing", "Review request"], active_step: 1 }),
      ])], { background: "surface", padding: "medium" }),
      templateSection([templateContainer([
        templateBlock("hero", { heading: "Let’s build the right quote for your project", body: "Share what you need and we’ll prepare the most useful next step—without pressure or unnecessary appointments.", button_label: "Start my quote", button_href: "/next-step", alignment: "center" }, { design: { min_height: "medium", text_color: "inverse" } }),
      ])], { background: "primary" }),
      templateSection([templateContainer([
        templateBlock("services", { heading: "What can we help with?", items: ["Repair or troubleshooting", "Maintenance service", "New installation", "Replacement project", "Urgent service", "Not sure yet"], columns: 3 }),
      ], { maxWidth: "wide" })]),
      templateSection([templateContainer([
        templateRow([
          [templateBlock("features", { heading: "Helpful details to share", items: ["What you are noticing", "Where the work is needed", "Any timing constraints", "Photos or measurements, if available"], columns: 2 })],
          [templateBlock("text", { heading: "A quote built for a real conversation", body: "Your team can use the next funnel steps to collect only the details needed for an accurate, respectful follow-up.", alignment: "left" }, { design: { background: "surface", radius: "rounded", shadow: "soft", padding: "lg" } })],
        ]),
      ], { maxWidth: "wide" })], { background: "surface" }),
      templateSection([templateContainer([
        templateBlock("testimonials", { heading: "Clear answers from local professionals", items: ["The quote was detailed, easy to understand, and matched the final work. — Sam K.", "We knew exactly what would happen next and never felt pressured. — Riley D."], columns: 2 }),
      ])]),
      templateSection([templateContainer([
        templateBlock("urgency_banner", { heading: "Ready when you are", body: "Continue to share your project details. You can review everything before submitting.", button_label: "Continue to project details", button_href: "/next-step", alignment: "center" }, { design: { radius: "rounded", shadow: "medium", padding: "xl" } }),
        templateBlock("contact_details", { heading: "Prefer to talk first?", phone: "(555) 555-0123", email: "quotes@example.com", address: "Serving your local area", hours: "Monday–Friday, 8am–5pm" }),
      ], { maxWidth: "standard" })], { background: "primary" }),
    ],
  },
]);

export function websiteTemplatesForKind(kind) {
  const projectKind = projectKindForTemplate(kind);
  return WEBSITE_TEMPLATE_BLUEPRINTS
    .filter((template) => template.kinds.includes(projectKind))
    .map((template) => ({
      id: template.id,
      name: template.name,
      description: template.description,
      kinds: [...template.kinds],
      content: normalizeWebsitePageContent({
        schema_version: 1,
        blocks: template.blocks.map(instantiateTemplateBlock),
      }),
    }));
}

function projectKindForTemplate(value) {
  if (!WEBSITE_PROJECT_KINDS.includes(value)) {
    throw new WebsiteBuilderError("website_project_kind_invalid", "Choose Website, Landing Page, or Funnel.");
  }
  return value;
}

function seoText(value, label, maximumLength) {
  if (value === undefined || value === null) return "";
  if (typeof value !== "string") throw seoError(`${label} must be text.`);
  const text = value.trim();
  if (text.length > maximumLength) {
    throw seoError(`${label} may be at most ${maximumLength} characters.`);
  }
  return text;
}

export function normalizeWebsitePageSeo(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw seoError("SEO metadata must be an object.");
  }
  const allowed = new Set([
    "title",
    "description",
    "social_title",
    "social_description",
    "hide_from_search",
  ]);
  const unknown = Object.keys(value).find((key) => !allowed.has(key));
  if (unknown) throw seoError(`SEO metadata contains an unsupported ${unknown} field.`);
  if (value.hide_from_search !== undefined && typeof value.hide_from_search !== "boolean") {
    throw seoError("Search visibility must be true or false.");
  }
  return {
    title: seoText(value.title, "Search title", SEO_TITLE_LIMIT),
    description: seoText(value.description, "Search description", SEO_DESCRIPTION_LIMIT),
    social_title: seoText(value.social_title, "Social title", SEO_TITLE_LIMIT),
    social_description: seoText(value.social_description, "Social description", SEO_DESCRIPTION_LIMIT),
    hide_from_search: value.hide_from_search === true,
  };
}

function websitePageSeoPayload(value) {
  const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  return {
    title: typeof source.title === "string" ? source.title.slice(0, SEO_TITLE_LIMIT) : "",
    description: typeof source.description === "string" ? source.description.slice(0, SEO_DESCRIPTION_LIMIT) : "",
    social_title: typeof source.social_title === "string" ? source.social_title.slice(0, SEO_TITLE_LIMIT) : "",
    social_description: typeof source.social_description === "string" ? source.social_description.slice(0, SEO_DESCRIPTION_LIMIT) : "",
    hide_from_search: source.hide_from_search === true,
  };
}

export function normalizeWebsiteProjectTheme(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw themeError("Theme settings must be an object.");
  }
  const allowed = new Set([
    ...WEBSITE_THEME_COLOR_FIELDS,
    "heading_font",
    "body_font",
    "corner_style",
    "heading_scale",
    "body_scale",
    "content_width",
    "section_spacing",
    "button_style",
  ]);
  const unknown = Object.keys(value).find((key) => !allowed.has(key));
  if (unknown) throw themeError(`Theme settings contain an unsupported ${unknown} field.`);
  const theme = { ...WEBSITE_THEME_DEFAULTS };
  for (const field of WEBSITE_THEME_COLOR_FIELDS) {
    if (value[field] === undefined) continue;
    if (typeof value[field] !== "string" || !/^#[0-9a-f]{6}$/i.test(value[field])) {
      throw themeError(`${field.replaceAll("_", " ")} must be a six-digit hex color.`);
    }
    theme[field] = value[field].toLowerCase();
  }
  for (const field of ["heading_font", "body_font"]) {
    if (value[field] === undefined) continue;
    if (!WEBSITE_THEME_FONT_CHOICES.has(value[field])) {
      throw themeError(`${field.replaceAll("_", " ")} is unsupported.`);
    }
    theme[field] = value[field];
  }
  if (value.corner_style !== undefined) {
    if (!WEBSITE_THEME_CORNER_CHOICES.has(value.corner_style)) {
      throw themeError("Corner style is unsupported.");
    }
    theme.corner_style = value.corner_style;
  }
  for (const [field, choices] of [
    ["heading_scale", WEBSITE_THEME_HEADING_SCALE_CHOICES],
    ["body_scale", WEBSITE_THEME_BODY_SCALE_CHOICES],
    ["content_width", WEBSITE_THEME_CONTENT_WIDTH_CHOICES],
    ["section_spacing", WEBSITE_THEME_SECTION_SPACING_CHOICES],
    ["button_style", WEBSITE_THEME_BUTTON_STYLE_CHOICES],
  ]) {
    if (value[field] === undefined) continue;
    if (!choices.has(value[field])) {
      throw themeError(`${field.replaceAll("_", " ")} is unsupported.`);
    }
    theme[field] = value[field];
  }
  return theme;
}

function websiteProjectThemePayload(value) {
  const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const compatible = Object.fromEntries(
    Object.entries(source).filter(([key]) => Object.hasOwn(WEBSITE_THEME_DEFAULTS, key)),
  );
  try {
    return normalizeWebsiteProjectTheme(compatible);
  } catch {
    return { ...WEBSITE_THEME_DEFAULTS };
  }
}

export function normalizeWebsiteProjectNavigation(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw navigationError("Navigation settings must be an object.");
  }
  const allowed = new Set(["mode", "show_brand", "cta_label", "cta_href", "items", "footer_text", "show_powered_by", "header_content", "footer_content"]);
  const unknown = Object.keys(value).find((key) => !allowed.has(key));
  if (unknown) throw navigationError(`Navigation settings contain an unsupported ${unknown} field.`);
  const mode = value.mode ?? "automatic";
  if (mode !== "automatic" && mode !== "custom") {
    throw navigationError("Navigation mode must be automatic or custom.");
  }
  if (value.show_brand !== undefined && typeof value.show_brand !== "boolean") {
    throw navigationError("Brand visibility must be true or false.");
  }
  if (value.show_powered_by !== undefined && typeof value.show_powered_by !== "boolean") {
    throw navigationError("Footer attribution visibility must be true or false.");
  }
  const ctaLabel = cleanString(value.cta_label, NAVIGATION_LABEL_LIMIT);
  const ctaHref = navigationLink(value.cta_href);
  if ((ctaLabel && !ctaHref) || (!ctaLabel && ctaHref)) {
    throw navigationError("Navigation call-to-action label and link must be provided together.");
  }
  const rawItems = value.items ?? [];
  if (!Array.isArray(rawItems) || rawItems.length > MAX_NAVIGATION_ITEMS) {
    throw navigationError(`Custom navigation may contain up to ${MAX_NAVIGATION_ITEMS} items.`);
  }
  const items = rawItems.map((item, index) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw navigationError(`Navigation item ${index + 1} must be an object.`);
    }
    const itemUnknown = Object.keys(item).find((key) => key !== "page_id" && key !== "label");
    if (itemUnknown) throw navigationError(`Navigation item ${index + 1} contains an unsupported ${itemUnknown} field.`);
    if (typeof item.page_id !== "string" || !UUID_PATTERN.test(item.page_id)) {
      throw navigationError(`Navigation item ${index + 1} has an invalid page identifier.`);
    }
    return {
      page_id: item.page_id,
      label: requiredName(item.label, `Navigation item ${index + 1} label`, NAVIGATION_LABEL_LIMIT),
    };
  });
  if (new Set(items.map((item) => item.page_id)).size !== items.length) {
    throw navigationError("A page may appear only once in custom navigation.");
  }
  return {
    mode,
    show_brand: value.show_brand !== false,
    cta_label: ctaLabel,
    cta_href: ctaHref,
    items: mode === "custom" ? items : [],
    footer_text: cleanString(value.footer_text, 240),
    show_powered_by: value.show_powered_by !== false,
    header_content: normalizeWebsiteChromeContent(value.header_content, "Global header"),
    footer_content: normalizeWebsiteChromeContent(value.footer_content, "Global footer"),
  };
}

function websiteProjectNavigationPayload(value) {
  const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const compatible = Object.fromEntries(
    Object.entries(source).filter(([key]) => Object.hasOwn(WEBSITE_NAVIGATION_DEFAULTS, key)),
  );
  try {
    return normalizeWebsiteProjectNavigation({ ...WEBSITE_NAVIGATION_DEFAULTS, ...compatible });
  } catch {
    return { ...WEBSITE_NAVIGATION_DEFAULTS, items: [] };
  }
}

function lifecycleStatus(value) {
  if (!WEBSITE_LIFECYCLE_STATUSES.includes(value)) {
    throw new WebsiteBuilderError(
      "website_status_invalid",
      "Website lifecycle status is invalid.",
    );
  }
  return value;
}

function projectKind(value) {
  if (!WEBSITE_PROJECT_KINDS.includes(value)) {
    throw new WebsiteBuilderError(
      "website_project_kind_invalid",
      "Choose Website, Landing Page, or Funnel.",
    );
  }
  return value;
}

function slugSegment(value) {
  return String(value ?? "")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-+/g, "-");
}

export function normalizeWebsiteSlug(value, fallbackName = "page") {
  const raw = typeof value === "string" ? value.trim() : "";
  if (raw === "/") return "/";
  const source = raw || fallbackName;
  if (/^[a-z]+:\/\//i.test(source) || source.includes("?") || source.includes("#")) {
    throw new WebsiteBuilderError(
      "website_page_slug_invalid",
      "Use a path such as /services or /roofing/estimate.",
    );
  }
  const segments = source
    .replace(/^\/+|\/+$/g, "")
    .split("/")
    .map(slugSegment)
    .filter(Boolean);
  if (!segments.length) {
    throw new WebsiteBuilderError(
      "website_page_slug_invalid",
      "Page path is required.",
    );
  }
  const slug = `/${segments.join("/")}`;
  if (slug.length > PAGE_SLUG_LIMIT) {
    throw new WebsiteBuilderError(
      "website_page_slug_too_long",
      `Page paths may be at most ${PAGE_SLUG_LIMIT} characters.`,
    );
  }
  return slug;
}

export function normalizeWebsiteProjectCreate(body = {}) {
  return {
    name: requiredName(body.name, "Project name", PROJECT_NAME_LIMIT),
    kind: projectKind(body.kind),
  };
}

export function normalizeWebsiteProjectUpdate(body = {}) {
  const update = {
    expected_version: requiredVersion(body.expected_version),
    name: body.name === undefined
      ? undefined
      : requiredName(body.name, "Project name", PROJECT_NAME_LIMIT),
    lifecycle_status: body.lifecycle_status === undefined
      ? undefined
      : lifecycleStatus(body.lifecycle_status),
    theme: body.theme === undefined
      ? undefined
      : normalizeWebsiteProjectTheme(body.theme),
    navigation: body.navigation === undefined
      ? undefined
      : normalizeWebsiteProjectNavigation(body.navigation),
  };
  if (
    update.name === undefined &&
    update.lifecycle_status === undefined &&
    update.theme === undefined &&
    update.navigation === undefined
  ) {
    throw new WebsiteBuilderError(
      "website_project_update_empty",
      "Change the project name or lifecycle status before saving.",
    );
  }
  return update;
}

export function pageKindForProject(kind) {
  if (kind === "funnel") return "funnel_step";
  if (kind === "landing_page") return "landing";
  return "standard";
}

export function starterPageForProject({ kind, projectName }) {
  const name = kind === "funnel" ? "Step 1" : kind === "landing_page" ? "Landing" : "Home";
  const slug = kind === "funnel" ? "/step-1" : "/";
  return {
    name,
    slug,
    page_kind: pageKindForProject(kind),
    content: {
      schema_version: 1,
      blocks: [
        {
          id: randomUUID(),
          type: "hero",
          data: {
            heading: projectName,
            body: "Tell visitors what makes your company the right choice.",
          },
        },
      ],
    },
    seo: normalizeWebsitePageSeo({ title: projectName }),
  };
}

export function normalizeWebsitePageCreate(body = {}, kind = "website") {
  const name = requiredName(body.name, "Page name", PAGE_NAME_LIMIT);
  return {
    name,
    slug: normalizeWebsiteSlug(body.slug, name),
    page_kind: pageKindForProject(projectKind(kind)),
    expected_project_version: requiredVersion(
      body.expected_project_version,
      "expected_project_version",
    ),
  };
}

export function normalizeWebsitePageUpdate(body = {}) {
  const update = {
    expected_version: requiredVersion(body.expected_version),
    expected_project_version: requiredVersion(
      body.expected_project_version,
      "expected_project_version",
    ),
    name: body.name === undefined
      ? undefined
      : requiredName(body.name, "Page name", PAGE_NAME_LIMIT),
    slug: body.slug === undefined ? undefined : normalizeWebsiteSlug(body.slug),
    lifecycle_status: body.lifecycle_status === undefined
      ? undefined
      : lifecycleStatus(body.lifecycle_status),
    is_home: body.is_home === undefined ? undefined : body.is_home,
    content: body.content === undefined ? undefined : normalizeWebsitePageContent(body.content),
    seo: body.seo === undefined ? undefined : normalizeWebsitePageSeo(body.seo),
    chrome: body.chrome === undefined ? undefined : normalizeWebsitePageChrome(body.chrome),
  };
  if (update.is_home !== undefined && typeof update.is_home !== "boolean") {
    throw new WebsiteBuilderError(
      "website_page_home_invalid",
      "Home/entry selection must be true or false.",
    );
  }
  if (
    update.name === undefined &&
    update.slug === undefined &&
    update.lifecycle_status === undefined &&
    update.is_home === undefined &&
    update.content === undefined &&
    update.seo === undefined &&
    update.chrome === undefined
  ) {
    throw new WebsiteBuilderError(
      "website_page_update_empty",
      "Change the page before saving.",
    );
  }
  return update;
}

export function normalizeWebsitePageDuplicate(body = {}) {
  return {
    expected_version: requiredVersion(body.expected_version),
    expected_project_version: requiredVersion(body.expected_project_version, "expected_project_version"),
  };
}

function cloneWebsiteContentWithFreshIds(value) {
  const content = normalizeWebsitePageContent(value);
  const clone = (block) => ({ ...block, id: randomUUID(), ...(block.children ? { children: block.children.map(clone) } : {}) });
  return { schema_version: 1, blocks: content.blocks.map(clone) };
}

export function normalizeWebsitePageReorder(body = {}) {
  const targetIndex = typeof body.target_index === "string" && /^\d+$/.test(body.target_index.trim())
    ? Number(body.target_index.trim())
    : body.target_index;
  if (!Number.isSafeInteger(targetIndex) || targetIndex < 0 || targetIndex >= MAX_PAGES_PER_PROJECT) {
    throw new WebsiteBuilderError(
      "website_page_position_invalid",
      "Page position is invalid.",
    );
  }
  return {
    target_index: targetIndex,
    expected_project_version: requiredVersion(
      body.expected_project_version,
      "expected_project_version",
    ),
  };
}

function timestamp(value) {
  if (!value) return null;
  const parsed = value instanceof Date ? value : new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed.toISOString() : null;
}

function exactNumber(value) {
  const number = Number(value);
  return Number.isSafeInteger(number) ? number : 0;
}

function projectPayload(row) {
  return {
    id: String(row.id),
    name: String(row.name),
    kind: row.kind,
    lifecycle_status: row.lifecycle_status,
    theme: websiteProjectThemePayload(row.theme),
    navigation: websiteProjectNavigationPayload(row.navigation),
    subdomain: row.subdomain ? String(row.subdomain) : null,
    published_publication_id: row.published_publication_id ? String(row.published_publication_id) : null,
    version: exactNumber(row.version),
    active_page_count: exactNumber(row.active_page_count),
    archived_page_count: exactNumber(row.archived_page_count),
    created_at: timestamp(row.created_at),
    updated_at: timestamp(row.updated_at),
    archived_at: timestamp(row.archived_at),
  };
}

function pagePayload(row) {
  return {
    id: String(row.id),
    project_id: String(row.project_id),
    name: String(row.name),
    slug: String(row.slug),
    page_kind: row.page_kind,
    lifecycle_status: row.lifecycle_status,
    is_home: row.is_home === true,
    sort_order: exactNumber(row.sort_order),
    content: row.content && typeof row.content === "object" ? row.content : { schema_version: 1, blocks: [] },
    seo: websitePageSeoPayload(row.seo),
    chrome: websitePageChromePayload(row.chrome),
    version: exactNumber(row.version),
    created_at: timestamp(row.created_at),
    updated_at: timestamp(row.updated_at),
    archived_at: timestamp(row.archived_at),
  };
}

function sectionPayload(row) {
  return {
    id: String(row.id),
    name: String(row.name),
    lifecycle_status: row.lifecycle_status,
    content: row.content && typeof row.content === "object" ? row.content : { schema_version: 1, blocks: [] },
    version: exactNumber(row.version),
    created_at: timestamp(row.created_at),
    updated_at: timestamp(row.updated_at),
    archived_at: timestamp(row.archived_at),
  };
}

function mediaPayload(row, previewUrl = null) {
  return {
    id: String(row.id),
    file_name: String(row.file_name),
    mime_type: String(row.mime_type),
    byte_size: exactNumber(row.byte_size),
    alt_text: String(row.alt_text || ""),
    lifecycle_status: row.lifecycle_status,
    version: exactNumber(row.version),
    preview_url: previewUrl,
    created_at: timestamp(row.created_at),
    updated_at: timestamp(row.updated_at),
    archived_at: timestamp(row.archived_at),
  };
}

function formPayload(row) {
  return {
    id: String(row.id),
    project_id: String(row.project_id),
    public_id: String(row.public_id),
    name: String(row.name),
    lifecycle_status: row.lifecycle_status,
    fields: normalizeWebsiteFormFields(row.fields),
    settings: normalizeWebsiteFormSettings(row.settings),
    version: exactNumber(row.version),
    created_at: timestamp(row.created_at),
    updated_at: timestamp(row.updated_at),
    archived_at: timestamp(row.archived_at),
  };
}

function submissionPayload(row) {
  return {
    id: String(row.id),
    form_id: String(row.form_id),
    status: row.status,
    values: row.submitted_values && typeof row.submitted_values === "object" ? row.submitted_values : {},
    contact_id: row.contact_id ? String(row.contact_id) : null,
    opportunity_id: row.opportunity_id ? String(row.opportunity_id) : null,
    task_id: row.task_id ? String(row.task_id) : null,
    error_code: row.error_code || null,
    created_at: timestamp(row.created_at),
    processed_at: timestamp(row.processed_at),
  };
}

function publicationPayload(row) {
  return {
    id: String(row.id),
    project_id: String(row.project_id),
    version_number: exactNumber(row.version_number),
    source_publication_id: row.source_publication_id ? String(row.source_publication_id) : null,
    created_at: timestamp(row.created_at),
    public_path: row.subdomain ? `/sites/${row.subdomain}` : null,
  };
}

function domainPayload(row) {
  if (!row) return null;
  return {
    id: String(row.id),
    project_id: String(row.project_id),
    hostname: String(row.hostname),
    canonical_mode: row.canonical_mode,
    verification_status: row.verification_status,
    routing_status: row.routing_status,
    ssl_status: row.ssl_status,
    verification_name: `_wolfcrm.${row.hostname}`,
    verification_value: `wolfcrm-verification=${row.verification_token}`,
    cname_target: String(row.cname_target),
    version: exactNumber(row.version),
    last_checked_at: timestamp(row.last_checked_at),
    verified_at: timestamp(row.verified_at),
    updated_at: timestamp(row.updated_at),
  };
}

async function inspectWebsiteDomainDns(row) {
  const expectedTxt = `wolfcrm-verification=${row.verification_token}`;
  const expectedCname = String(row.cname_target).toLowerCase().replace(/\.$/, "");
  let txtVerified = false;
  let routingVerified = false;
  try {
    const records = await resolveTxt(`_wolfcrm.${row.hostname}`);
    txtVerified = records.some((parts) => parts.join("").trim() === expectedTxt);
  } catch {}
  try {
    const records = await resolveCname(row.hostname);
    routingVerified = records.some((record) => record.toLowerCase().replace(/\.$/, "") === expectedCname);
  } catch {}
  return { txtVerified, routingVerified };
}

async function inspectWebsiteDomainTls(row) {
  try {
    const response = await fetch(`https://${row.hostname}/.well-known/wolfcrm-domain-verification/${row.verification_token}`, {
      redirect: "error",
      signal: AbortSignal.timeout(5000),
    });
    return response.status === 204;
  } catch {
    return false;
  }
}

async function publicWebsitePayload(pool, mediaStorage, row, requestedPath) {
  const snapshot = row.snapshot;
  const pages = Array.isArray(snapshot?.pages) ? snapshot.pages : [];
  const page = pages.find((candidate) => candidate?.slug === requestedPath)
    ?? (requestedPath === "/" ? pages.find((candidate) => candidate?.is_home === true) : null);
  if (!page) throw new WebsiteBuilderError("website_public_page_not_found", "Published page was not found.", 404);
  const mediaIds = websiteMediaReferences(page?.content);
  const mediaRows = mediaIds.length
    ? (await pool.query(
      `SELECT id::text AS id, object_key FROM website_media
        WHERE company_id = $1 AND lifecycle_status IN ('ready', 'archived') AND id = ANY($2::uuid[])`,
      [row.company_id, mediaIds],
    )).rows
    : [];
  const media = {};
  for (const item of mediaRows) media[item.id] = mediaStorage?.downloadUrl ? await mediaStorage.downloadUrl(item.object_key) : null;
  return {
    publication_id: String(row.published_publication_id),
    project: { ...snapshot.project, subdomain: row.subdomain },
    pages,
    page,
    media,
    forms: Array.isArray(snapshot?.forms) ? snapshot.forms.map(websiteFormPublicPayload) : [],
    domain: row.domain_hostname ? {
      hostname: row.domain_hostname,
      canonical_mode: row.canonical_mode,
      ssl_status: row.ssl_status,
    } : null,
  };
}

function projectAuditSnapshot(row) {
  return row ? {
    id: String(row.id),
    name: row.name,
    kind: row.kind,
    lifecycle_status: row.lifecycle_status,
    theme: websiteProjectThemePayload(row.theme),
    navigation: websiteProjectNavigationPayload(row.navigation),
    version: exactNumber(row.version),
  } : null;
}

function pageAuditSnapshot(row) {
  const content = row?.content && typeof row.content === "object" ? row.content : null;
  return row ? {
    id: String(row.id),
    project_id: String(row.project_id),
    name: row.name,
    slug: row.slug,
    page_kind: row.page_kind,
    lifecycle_status: row.lifecycle_status,
    is_home: row.is_home === true,
    sort_order: exactNumber(row.sort_order),
    content_schema_version: exactNumber(content?.schema_version),
    content_block_count: flattenWebsiteBlocks(content).length,
    seo: websitePageSeoPayload(row.seo),
    chrome: websitePageChromePayload(row.chrome),
    version: exactNumber(row.version),
  } : null;
}

function sectionAuditSnapshot(row) {
  const content = row?.content && typeof row.content === "object" ? row.content : null;
  return row ? {
    id: String(row.id),
    name: row.name,
    lifecycle_status: row.lifecycle_status,
    content_schema_version: exactNumber(content?.schema_version),
    content_block_count: flattenWebsiteBlocks(content).length,
    version: exactNumber(row.version),
  } : null;
}

function mediaAuditSnapshot(row) {
  return row ? {
    id: String(row.id),
    file_name: row.file_name,
    mime_type: row.mime_type,
    byte_size: exactNumber(row.byte_size),
    alt_text: row.alt_text || "",
    lifecycle_status: row.lifecycle_status,
    version: exactNumber(row.version),
  } : null;
}

function formAuditSnapshot(row) {
  return row ? {
    id: String(row.id),
    project_id: String(row.project_id),
    name: row.name,
    lifecycle_status: row.lifecycle_status,
    field_count: Array.isArray(row.fields) ? row.fields.length : 0,
    settings: normalizeWebsiteFormSettings(row.settings),
    version: exactNumber(row.version),
  } : null;
}

async function appendAudit(client, { companyId, projectId = null, pageId = null, sectionId = null, mediaId = null, formId = null, actorUserId, action, before = null, after = null }) {
  await client.query(
    `INSERT INTO website_builder_audit (
       company_id, project_id, page_id, section_id, media_id, form_id, actor_user_id, action, before_state, after_state
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb)`,
    [
      companyId,
      projectId,
      pageId,
      sectionId,
      mediaId,
      formId,
      actorUserId,
      action,
      before == null ? null : JSON.stringify(before),
      after == null ? null : JSON.stringify(after),
    ],
  );
}

async function loadProject(client, companyId, projectId, lock = false) {
  const { rows } = await client.query(
    `SELECT * FROM website_projects
      WHERE id::text = $1 AND company_id = $2${lock ? " FOR UPDATE" : ""}`,
    [projectId, companyId],
  );
  if (!rows[0]) {
    throw new WebsiteBuilderError(
      "website_project_not_found",
      "Website project was not found.",
      404,
    );
  }
  return rows[0];
}

async function loadPage(client, companyId, projectId, pageId, lock = false) {
  const { rows } = await client.query(
    `SELECT * FROM website_pages
      WHERE id::text = $1 AND project_id::text = $2 AND company_id = $3${lock ? " FOR UPDATE" : ""}`,
    [pageId, projectId, companyId],
  );
  if (!rows[0]) {
    throw new WebsiteBuilderError(
      "website_page_not_found",
      "Website page was not found.",
      404,
    );
  }
  return rows[0];
}

async function loadSection(client, companyId, sectionId, lock = false) {
  const { rows } = await client.query(
    `SELECT * FROM website_sections
      WHERE id::text = $1 AND company_id = $2${lock ? " FOR UPDATE" : ""}`,
    [sectionId, companyId],
  );
  if (!rows[0]) {
    throw new WebsiteBuilderError("website_section_not_found", "Reusable section was not found.", 404);
  }
  return rows[0];
}

async function loadMedia(client, companyId, mediaId, lock = false) {
  const { rows } = await client.query(
    `SELECT * FROM website_media WHERE id::text = $1 AND company_id = $2${lock ? " FOR UPDATE" : ""}`,
    [mediaId, companyId],
  );
  if (!rows[0]) throw new WebsiteBuilderError("website_media_not_found", "Website media was not found.", 404);
  return rows[0];
}

async function loadForm(client, companyId, projectId, formId, lock = false) {
  const { rows } = await client.query(
    `SELECT * FROM website_forms WHERE id::text = $1 AND project_id::text = $2 AND company_id = $3${lock ? " FOR UPDATE" : ""}`,
    [formId, projectId, companyId],
  );
  if (!rows[0]) throw new WebsiteBuilderError("website_form_not_found", "Website form was not found.", 404);
  return rows[0];
}

async function assertReadyMediaReferences(client, companyId, content) {
  const ids = websiteMediaReferences(content);
  if (!ids.length) return;
  const { rows } = await client.query(
    `SELECT id::text AS id FROM website_media WHERE company_id = $1 AND lifecycle_status = 'ready' AND id = ANY($2::uuid[])`,
    [companyId, ids],
  );
  if (rows.length !== ids.length) throw new WebsiteBuilderError("website_media_reference_invalid", "Image and gallery blocks may use only active media from this company.", 409);
}

async function assertActiveFormReferences(client, companyId, projectId, content) {
  const ids = [...new Set(flattenWebsiteBlocks(content).filter((block) => block.type === "form").map((block) => block.data.form_id))];
  if (!ids.length) return;
  const { rows } = await client.query(
    `SELECT id::text AS id FROM website_forms
      WHERE company_id = $1 AND project_id = $2 AND lifecycle_status = 'draft' AND id = ANY($3::uuid[])`,
    [companyId, projectId, ids],
  );
  if (rows.length !== ids.length) throw new WebsiteBuilderError("website_form_reference_invalid", "Form blocks may use only active forms from this project.", 409);
}

function requireCompany(req) {
  if (!req.companyId) {
    throw new WebsiteBuilderError(
      "company_required",
      "Website Builder requires a company workspace.",
      400,
    );
  }
  return req.companyId;
}

function assertVersion(row, expected, subject) {
  if (exactNumber(row.version) !== expected) {
    throw new WebsiteBuilderError(
      `website_${subject}_stale`,
      `This ${subject} changed after it was loaded. Refresh before saving again.`,
      409,
      { current_version: exactNumber(row.version) },
    );
  }
}

function websiteFormSubmissionValues(form, rawValues) {
  const fields = normalizeWebsiteFormFields(form.fields);
  const allowed = new Set(fields.map((field) => field.key));
  const unknown = Object.keys(rawValues).find((key) => !allowed.has(key));
  if (unknown) throw formError("Submission contains an unsupported field.", "website_form_submission_invalid");
  const values = {};
  const contact = { name: "", phone: "", email: "", address: "" };
  const leadInfo = [];
  for (const field of fields) {
    const maximum = field.type === "textarea" ? 4000 : 500;
    const value = typeof rawValues[field.key] === "string" ? rawValues[field.key].trim() : "";
    if (value.length > maximum) throw formError(`${field.label} is too long.`, "website_form_submission_invalid");
    if (field.required && !value) throw formError(`${field.label} is required.`, "website_form_submission_invalid");
    if (field.type === "select" && value && !field.options.includes(value)) throw formError(`${field.label} has an invalid choice.`, "website_form_submission_invalid");
    if (field.type === "email" && value && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) throw formError("Enter a valid email address.", "website_form_submission_invalid");
    if (field.type === "phone" && value && !/^[+0-9().\-\s]{7,30}$/.test(value)) throw formError("Enter a valid phone number.", "website_form_submission_invalid");
    values[field.key] = value;
    if (["name", "phone", "email", "address"].includes(field.type) && !contact[field.type]) contact[field.type] = value;
    else if (value) leadInfo.push({ question: field.label, answer: value });
  }
  if (!contact.name) throw formError("Name is required.", "website_form_submission_invalid");
  if (Buffer.byteLength(JSON.stringify(values), "utf8") > 16384) throw formError("Submission is too large.", "website_form_submission_invalid");
  return { values, contact, leadInfo };
}

function websiteFormRequestHash(req, formId) {
  const forwarded = typeof req.get === "function" ? req.get("x-forwarded-for") : "";
  const address = String(forwarded?.split(",")[0]?.trim() || req.ip || req.socket?.remoteAddress || "unknown");
  const salt = process.env.WEBSITE_FORM_HASH_SALT || "wolfcrm-public-form-v1";
  return createHash("sha256").update(`${salt}:${formId}:${address}`).digest("hex");
}

function websiteAnalyticsVisitorHash(projectId, visitorToken) {
  if (!visitorToken) return null;
  const salt = process.env.WEBSITE_ANALYTICS_HASH_SALT || process.env.WEBSITE_FORM_HASH_SALT || "wolfcrm-website-analytics-v1";
  const rotation = new Date().toISOString().slice(0, 7);
  return createHash("sha256").update(`${salt}:${rotation}:${projectId}:${visitorToken}`).digest("hex");
}

function websiteAnalyticsSnapshotContext(snapshot, input, { formId = null } = {}) {
  const pages = Array.isArray(snapshot?.pages) ? snapshot.pages : [];
  const page = pages.find((item) => String(item?.id) === input.page_id);
  if (!page) throw analyticsError("Published analytics page was not found.", "website_analytics_page_not_found", 404);
  const blocks = flattenWebsiteBlocks(page?.content);
  const requiredFormId = formId || input.form_id;
  if (requiredFormId) {
    const form = Array.isArray(snapshot?.forms) ? snapshot.forms.find((item) => String(item?.id) === requiredFormId) : null;
    const formBlock = blocks.some((block) => block?.type === "form" && String(block?.data?.form_id) === requiredFormId);
    if (!form || !formBlock) throw analyticsError("Published analytics form was not found on this page.", "website_analytics_form_not_found", 404);
  }
  if (input.event_type === "form_view" && !input.form_id) throw analyticsError("Form exposure events require a form.");
  if (input.event_type === "cta_click") {
    const block = blocks.find((item) => String(item?.id) === input.block_id);
    const hasCta = block && (
      (["hero", "callout", "urgency_banner"].includes(block.type) && block?.data?.button_href) ||
      (block.type === "announcement_bar" && block?.data?.link_href) ||
      (block.type === "button" && block?.data?.href) ||
      (block.type === "link_list" && Array.isArray(block?.data?.items) && block.data.items.length)
    );
    if (!hasCta) {
      throw analyticsError("Published call to action was not found on this page.", "website_analytics_cta_not_found", 404);
    }
  }
  return { page };
}

function websiteContactTags(value) {
  const tags = Array.isArray(value) ? value : [];
  return tags.map((tag) => String(tag).replace(/[{},;]/g, "").trim()).filter(Boolean).join(",") || "lead,website";
}

function websiteFormPublicPayload(form) {
  return {
    id: String(form.id),
    public_id: String(form.public_id),
    name: String(form.name),
    fields: normalizeWebsiteFormFields(form.fields),
    success_message: normalizeWebsiteFormSettings(form.settings).success_message,
  };
}

function sendWebsiteBuilderError(res, error, fallbackCode) {
  if (error instanceof WebsiteBuilderError || error?.statusCode) {
    return res.status(error.statusCode || 400).json({
      error: error.code || fallbackCode,
      message: error.message,
      current_version: error.current_version,
    });
  }
  if (error?.code === "23505") {
    if (error?.constraint === "website_projects_subdomain_uidx") {
      return res.status(409).json({
        error: "website_subdomain_conflict",
        message: "That WolfCRM subdomain is already assigned.",
      });
    }
    if (error?.constraint === "website_domains_hostname_uidx") {
      return res.status(409).json({
        error: "website_domain_conflict",
        message: "That custom domain is already assigned.",
      });
    }
    return res.status(409).json({
      error: "website_slug_conflict",
      message: "That active page path is already used in this project.",
    });
  }
  console.error("[website-builder]", fallbackCode, {
    code: error?.code,
    message: error?.message,
  });
  return res.status(500).json({
    error: fallbackCode,
    message: "Website Builder could not complete that request.",
  });
}

export async function installWebsiteBuilderSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS website_projects (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      kind TEXT NOT NULL CHECK (kind IN ('website', 'landing_page', 'funnel')),
      lifecycle_status TEXT NOT NULL DEFAULT 'draft' CHECK (lifecycle_status IN ('draft', 'archived')),
      theme JSONB NOT NULL DEFAULT '{}'::jsonb,
      navigation JSONB NOT NULL DEFAULT '{}'::jsonb,
      version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      archived_at TIMESTAMPTZ,
      UNIQUE(id, company_id),
      CHECK (char_length(name) BETWEEN 1 AND ${PROJECT_NAME_LIMIT}),
      CHECK (jsonb_typeof(theme) = 'object'),
      CHECK (octet_length(theme::text) <= 8192),
      CHECK (jsonb_typeof(navigation) = 'object'),
      CHECK (octet_length(navigation::text) <= 32768)
    );
    ALTER TABLE website_projects
      ADD COLUMN IF NOT EXISTS theme JSONB NOT NULL DEFAULT '{}'::jsonb;
    ALTER TABLE website_projects
      ADD COLUMN IF NOT EXISTS navigation JSONB NOT NULL DEFAULT '{}'::jsonb;
    CREATE INDEX IF NOT EXISTS website_projects_company_status_updated_idx
      ON website_projects(company_id, lifecycle_status, updated_at DESC);

    CREATE TABLE IF NOT EXISTS website_pages (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      project_id UUID NOT NULL,
      name TEXT NOT NULL,
      slug TEXT NOT NULL,
      page_kind TEXT NOT NULL CHECK (page_kind IN ('standard', 'landing', 'funnel_step')),
      lifecycle_status TEXT NOT NULL DEFAULT 'draft' CHECK (lifecycle_status IN ('draft', 'archived')),
      is_home BOOLEAN NOT NULL DEFAULT false,
      sort_order INTEGER NOT NULL DEFAULT 0 CHECK (sort_order >= 0),
      content JSONB NOT NULL DEFAULT '{"schema_version":1,"blocks":[]}'::jsonb,
      seo JSONB NOT NULL DEFAULT '{}'::jsonb,
      chrome JSONB NOT NULL DEFAULT '{}'::jsonb,
      version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      archived_at TIMESTAMPTZ,
      UNIQUE(id, project_id, company_id),
      FOREIGN KEY(project_id, company_id) REFERENCES website_projects(id, company_id) ON DELETE CASCADE,
      CHECK (char_length(name) BETWEEN 1 AND ${PAGE_NAME_LIMIT}),
      CHECK (char_length(slug) BETWEEN 1 AND ${PAGE_SLUG_LIMIT}),
      CHECK (jsonb_typeof(content) = 'object'),
      CHECK (jsonb_typeof(seo) = 'object'),
      CHECK (jsonb_typeof(chrome) = 'object'),
      CHECK (octet_length(content::text) <= 262144),
      CHECK (octet_length(seo::text) <= 32768)
    );
    ALTER TABLE website_pages
      ADD COLUMN IF NOT EXISTS chrome JSONB NOT NULL DEFAULT '{}'::jsonb;
    CREATE INDEX IF NOT EXISTS website_pages_project_status_order_idx
      ON website_pages(company_id, project_id, lifecycle_status, sort_order, created_at);
    CREATE UNIQUE INDEX IF NOT EXISTS website_pages_active_slug_uidx
      ON website_pages(project_id, lower(slug)) WHERE archived_at IS NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS website_pages_active_home_uidx
      ON website_pages(project_id) WHERE is_home AND archived_at IS NULL;

    CREATE TABLE IF NOT EXISTS website_sections (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      lifecycle_status TEXT NOT NULL DEFAULT 'draft' CHECK (lifecycle_status IN ('draft', 'archived')),
      content JSONB NOT NULL,
      version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      archived_at TIMESTAMPTZ,
      UNIQUE(id, company_id),
      CHECK (char_length(name) BETWEEN 1 AND ${PAGE_NAME_LIMIT}),
      CHECK (jsonb_typeof(content) = 'object'),
      CHECK (octet_length(content::text) <= ${MAX_PAGE_CONTENT_BYTES})
    );
    CREATE INDEX IF NOT EXISTS website_sections_company_status_updated_idx
      ON website_sections(company_id, lifecycle_status, updated_at DESC);

    CREATE TABLE IF NOT EXISTS website_media (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      file_name TEXT NOT NULL,
      mime_type TEXT NOT NULL CHECK (mime_type IN ('image/jpeg','image/png','image/webp','image/gif')),
      byte_size INTEGER NOT NULL CHECK (byte_size BETWEEN 1 AND ${MAX_MEDIA_BYTES}),
      object_key TEXT NOT NULL UNIQUE,
      alt_text TEXT NOT NULL DEFAULT '',
      lifecycle_status TEXT NOT NULL DEFAULT 'uploading' CHECK (lifecycle_status IN ('uploading','ready','archived')),
      version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      archived_at TIMESTAMPTZ,
      UNIQUE(id, company_id),
      CHECK (char_length(file_name) BETWEEN 1 AND 160),
      CHECK (char_length(alt_text) <= 300)
    );
    CREATE INDEX IF NOT EXISTS website_media_company_status_updated_idx
      ON website_media(company_id, lifecycle_status, updated_at DESC);

    CREATE TABLE IF NOT EXISTS website_forms (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      project_id UUID NOT NULL,
      public_id UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
      name TEXT NOT NULL,
      lifecycle_status TEXT NOT NULL DEFAULT 'draft' CHECK (lifecycle_status IN ('draft','archived')),
      fields JSONB NOT NULL,
      settings JSONB NOT NULL DEFAULT '{}'::jsonb,
      version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      archived_at TIMESTAMPTZ,
      UNIQUE(id, project_id, company_id),
      FOREIGN KEY(project_id, company_id) REFERENCES website_projects(id, company_id) ON DELETE CASCADE,
      CHECK (char_length(name) BETWEEN 1 AND 120),
      CHECK (jsonb_typeof(fields) = 'array'),
      CHECK (jsonb_array_length(fields) BETWEEN 1 AND ${MAX_FORM_FIELDS}),
      CHECK (jsonb_typeof(settings) = 'object')
    );
    CREATE INDEX IF NOT EXISTS website_forms_project_status_updated_idx
      ON website_forms(company_id, project_id, lifecycle_status, updated_at DESC);

    CREATE TABLE IF NOT EXISTS website_form_submissions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      project_id UUID NOT NULL,
      form_id UUID NOT NULL,
      publication_id UUID,
      idempotency_key TEXT NOT NULL,
      submitted_values JSONB NOT NULL,
      status TEXT NOT NULL DEFAULT 'accepted' CHECK (status IN ('accepted','processed','failed','spam')),
      contact_id UUID,
      opportunity_id UUID,
      task_id UUID,
      ip_hash TEXT,
      error_code TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      processed_at TIMESTAMPTZ,
      FOREIGN KEY(form_id, project_id, company_id) REFERENCES website_forms(id, project_id, company_id) ON DELETE CASCADE,
      UNIQUE(form_id, idempotency_key)
    );
    CREATE INDEX IF NOT EXISTS website_form_submissions_project_created_idx
      ON website_form_submissions(company_id, project_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS website_form_submissions_rate_idx
      ON website_form_submissions(form_id, ip_hash, created_at DESC);

    CREATE TABLE IF NOT EXISTS website_builder_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      project_id UUID REFERENCES website_projects(id) ON DELETE SET NULL,
      page_id UUID REFERENCES website_pages(id) ON DELETE SET NULL,
      section_id UUID REFERENCES website_sections(id) ON DELETE SET NULL,
      media_id UUID REFERENCES website_media(id) ON DELETE SET NULL,
      form_id UUID REFERENCES website_forms(id) ON DELETE SET NULL,
      actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      before_state JSONB,
      after_state JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    ALTER TABLE website_builder_audit
      ADD COLUMN IF NOT EXISTS section_id UUID REFERENCES website_sections(id) ON DELETE SET NULL;
    ALTER TABLE website_builder_audit
      ADD COLUMN IF NOT EXISTS media_id UUID REFERENCES website_media(id) ON DELETE SET NULL;
    ALTER TABLE website_builder_audit
      ADD COLUMN IF NOT EXISTS form_id UUID REFERENCES website_forms(id) ON DELETE SET NULL;
    CREATE INDEX IF NOT EXISTS website_builder_audit_company_project_idx
      ON website_builder_audit(company_id, project_id, created_at DESC);

    ALTER TABLE website_projects ADD COLUMN IF NOT EXISTS subdomain TEXT;
    CREATE UNIQUE INDEX IF NOT EXISTS website_projects_subdomain_uidx
      ON website_projects(lower(subdomain)) WHERE subdomain IS NOT NULL;
    CREATE TABLE IF NOT EXISTS website_publications (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL,
      project_id UUID NOT NULL,
      version_number INTEGER NOT NULL CHECK (version_number > 0),
      subdomain TEXT NOT NULL,
      snapshot JSONB NOT NULL,
      source_publication_id UUID REFERENCES website_publications(id) ON DELETE SET NULL,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      FOREIGN KEY(project_id, company_id) REFERENCES website_projects(id, company_id) ON DELETE CASCADE,
      UNIQUE(project_id, version_number)
    );
    CREATE INDEX IF NOT EXISTS website_publications_project_created_idx
      ON website_publications(company_id, project_id, created_at DESC);
    ALTER TABLE website_projects
      ADD COLUMN IF NOT EXISTS published_publication_id UUID REFERENCES website_publications(id) ON DELETE SET NULL;
    CREATE TABLE IF NOT EXISTS website_analytics_events (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      project_id UUID NOT NULL,
      publication_id UUID NOT NULL REFERENCES website_publications(id) ON DELETE CASCADE,
      page_id UUID,
      form_id UUID,
      event_type TEXT NOT NULL CHECK (event_type IN ('page_view','cta_click','form_view','form_submit')),
      event_key UUID NOT NULL,
      visitor_hash TEXT,
      block_id UUID,
      attribution JSONB NOT NULL DEFAULT '{}'::jsonb,
      occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      FOREIGN KEY(project_id, company_id) REFERENCES website_projects(id, company_id) ON DELETE CASCADE,
      UNIQUE(publication_id, event_key),
      CHECK (jsonb_typeof(attribution) = 'object'),
      CHECK (octet_length(attribution::text) <= 4096)
    );
    CREATE INDEX IF NOT EXISTS website_analytics_project_time_idx
      ON website_analytics_events(company_id, project_id, occurred_at DESC);
    CREATE INDEX IF NOT EXISTS website_analytics_publication_visitor_idx
      ON website_analytics_events(publication_id, visitor_hash, occurred_at DESC);
    CREATE TABLE IF NOT EXISTS website_domains (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL,
      project_id UUID NOT NULL,
      hostname TEXT NOT NULL,
      canonical_mode TEXT NOT NULL DEFAULT 'primary' CHECK (canonical_mode IN ('primary','redirect_to_subdomain')),
      verification_token TEXT NOT NULL,
      verification_status TEXT NOT NULL DEFAULT 'pending' CHECK (verification_status IN ('pending','verified')),
      routing_status TEXT NOT NULL DEFAULT 'pending' CHECK (routing_status IN ('pending','verified')),
      ssl_status TEXT NOT NULL DEFAULT 'pending_provider' CHECK (ssl_status IN ('pending_provider','active','failed')),
      cname_target TEXT NOT NULL DEFAULT 'sites.wolfcrm.site',
      version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
      last_checked_at TIMESTAMPTZ,
      verified_at TIMESTAMPTZ,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      FOREIGN KEY(project_id, company_id) REFERENCES website_projects(id, company_id) ON DELETE CASCADE,
      UNIQUE(project_id),
      UNIQUE(id, company_id)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS website_domains_hostname_uidx ON website_domains(lower(hostname));
    CREATE INDEX IF NOT EXISTS website_domains_company_project_idx ON website_domains(company_id, project_id);
  `);
}

export async function installWebsiteBuilderSystem({ app, pool, authRequired, requireView, requireManage, requirePublish, mediaStorage, emitAutomationEvent, markContactDirty, sendPushToUsers, syncTaskSchedules }) {
  await installWebsiteBuilderSchema(pool);

  app.post("/api/public/website-analytics/events", async (req, res) => {
    try {
      const input = normalizeWebsiteAnalyticsEvent(req.body);
      const row = (await pool.query(
        `SELECT p.id AS project_id, p.company_id, p.published_publication_id, pub.snapshot
           FROM website_projects p
           JOIN website_publications pub ON pub.id = p.published_publication_id AND pub.project_id = p.id AND pub.company_id = p.company_id
          WHERE p.published_publication_id = $1 AND p.lifecycle_status = 'draft'`,
        [input.publication_id],
      )).rows[0];
      if (!row) throw analyticsError("Published analytics destination was not found.", "website_analytics_publication_not_found", 404);
      websiteAnalyticsSnapshotContext(row.snapshot, input);
      const visitorHash = websiteAnalyticsVisitorHash(row.project_id, input.visitor_token);
      const recentCount = Number((await pool.query(
        `SELECT COUNT(*)::int AS count FROM website_analytics_events
          WHERE publication_id = $1 AND visitor_hash = $2 AND occurred_at >= $3`,
        [row.published_publication_id, visitorHash, new Date(Date.now() - ANALYTICS_RATE_LIMIT_WINDOW_MS)],
      )).rows[0]?.count || 0);
      if (recentCount >= ANALYTICS_RATE_LIMIT_MAX) throw analyticsError("Analytics event rate exceeded.", "website_analytics_rate_limited", 429);
      await pool.query(
        `INSERT INTO website_analytics_events(company_id, project_id, publication_id, page_id, form_id, event_type, event_key, visitor_hash, block_id, attribution)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)
         ON CONFLICT(publication_id, event_key) DO NOTHING`,
        [row.company_id, row.project_id, row.published_publication_id, input.page_id, input.form_id, input.event_type,
          input.event_key, visitorHash, input.block_id, JSON.stringify(input.attribution)],
      );
      res.set("Cache-Control", "no-store").status(202).json({ accepted: true });
    } catch (error) {
      sendWebsiteBuilderError(res, error, "website_analytics_event_failed");
    }
  });

  app.post("/api/public/website-forms/:publicId/submissions", async (req, res) => {
    let input;
    try {
      input = normalizeWebsiteFormSubmission(req.body);
      if (!UUID_PATTERN.test(req.params.publicId)) throw formError("Form was not found.", "website_form_not_found", 404);
    } catch (error) {
      return sendWebsiteBuilderError(res, error, "website_form_submit_failed");
    }
    if (input.honeypot) return res.status(201).json({ accepted: true });

    const client = await pool.connect();
    let result = null;
    try {
      await client.query("BEGIN");
      const row = (await client.query(
        `SELECT f.*, p.published_publication_id, pub.snapshot
           FROM website_forms f
           JOIN website_projects p ON p.id = f.project_id AND p.company_id = f.company_id
           JOIN website_publications pub ON pub.id = p.published_publication_id AND pub.project_id = p.id AND pub.company_id = p.company_id
          WHERE f.public_id::text = $1 AND f.lifecycle_status = 'draft' AND p.lifecycle_status = 'draft'
          FOR SHARE OF f, p, pub`,
        [req.params.publicId],
      )).rows[0];
      const publishedForm = Array.isArray(row?.snapshot?.forms)
        ? row.snapshot.forms.find((form) => String(form?.public_id) === req.params.publicId)
        : null;
      if (!row || !publishedForm) throw formError("Form was not found.", "website_form_not_found", 404);
      if (input.analytics) {
        if (input.analytics.publication_id !== String(row.published_publication_id)) {
          throw analyticsError("The published form version changed. Refresh before submitting.", "website_analytics_publication_stale", 409);
        }
        websiteAnalyticsSnapshotContext(row.snapshot, input.analytics, { formId: String(row.id) });
      }

      const existing = (await client.query(
        `SELECT * FROM website_form_submissions WHERE form_id = $1 AND idempotency_key = $2`,
        [row.id, input.idempotency_key],
      )).rows[0];
      if (existing) {
        await client.query("COMMIT");
        return res.status(200).json({ accepted: existing.status === "processed", submission_id: String(existing.id), duplicate: true });
      }
      const ipHash = websiteFormRequestHash(req, row.id);
      const recentCount = Number((await client.query(
        `SELECT COUNT(*)::int AS count FROM website_form_submissions
          WHERE form_id = $1 AND ip_hash = $2 AND created_at >= $3`,
        [row.id, ipHash, new Date(Date.now() - FORM_RATE_LIMIT_WINDOW_MS)],
      )).rows[0]?.count || 0);
      if (recentCount >= FORM_RATE_LIMIT_MAX) throw formError("Too many requests. Wait a few minutes and try again.", "website_form_rate_limited", 429);

      const normalized = websiteFormSubmissionValues(publishedForm, input.values);
      const settings = normalizeWebsiteFormSettings(publishedForm.settings);
      const owner = (await client.query(
        `SELECT u.id FROM users u
          LEFT JOIN companies c ON c.id = u.company_id
         WHERE u.company_id = $1 AND u.deleted_at IS NULL
         ORDER BY (u.id = $2) DESC, (u.id = c.owner_user_id) DESC, (u.role = 'employer') DESC, u.created_at ASC
         LIMIT 1`,
        [row.company_id, row.created_by],
      )).rows[0];
      if (!owner) throw formError("This form is temporarily unavailable.", "website_form_owner_unavailable", 503);

      const submissionId = randomUUID();
      await client.query(
        `INSERT INTO website_form_submissions(id, company_id, project_id, form_id, publication_id, idempotency_key, submitted_values, ip_hash)
         VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8)`,
        [submissionId, row.company_id, row.project_id, row.id, row.published_publication_id, input.idempotency_key, JSON.stringify(normalized.values), ipHash],
      );

      let contact = null;
      let contactCreated = true;
      if (settings.contact_mode === "upsert" && (normalized.contact.email || normalized.contact.phone)) {
        contact = (await client.query(
          `SELECT * FROM contacts WHERE company_id = $1 AND deleted_at IS NULL
            AND (($2 <> '' AND lower(email) = lower($2)) OR ($3 <> '' AND regexp_replace(COALESCE(phone,''), '[^0-9]', '', 'g') = regexp_replace($3, '[^0-9]', '', 'g')))
            ORDER BY updated_at DESC LIMIT 1 FOR UPDATE`,
          [row.company_id, normalized.contact.email, normalized.contact.phone],
        )).rows[0] || null;
      }
      if (contact) {
        contactCreated = false;
        const mergedTags = websiteContactTags([...(String(contact.tags || "").replace(/[{}\"]/g, "").split(/[;,]/)), ...settings.tags]);
        const mergedLeadInfo = [...(Array.isArray(contact.lead_info) ? contact.lead_info : []), ...normalized.leadInfo].slice(-50);
        contact = (await client.query(
          `UPDATE contacts SET name = $3, phone = COALESCE(NULLIF($4,''), phone), email = COALESCE(NULLIF($5,''), email),
             address = COALESCE(NULLIF($6,''), address), tags = $7, job_type = COALESCE(NULLIF($8,''), job_type),
             source = $9, lead_info = $10::jsonb, lead_submitted_at = now(), updated_at = now()
           WHERE id = $1 AND company_id = $2 RETURNING *`,
          [contact.id, row.company_id, normalized.contact.name, normalized.contact.phone, normalized.contact.email, normalized.contact.address,
            mergedTags, settings.job_type, settings.source, JSON.stringify(mergedLeadInfo)],
        )).rows[0];
      } else {
        contact = (await client.query(
          `INSERT INTO contacts(id, user_id, company_id, name, phone, email, address, tags, job_type, lead_info, source, lead_submitted_at)
           VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,now()) RETURNING *`,
          [randomUUID(), owner.id, row.company_id, normalized.contact.name, normalized.contact.phone, normalized.contact.email,
            normalized.contact.address, websiteContactTags(settings.tags), settings.job_type, JSON.stringify(normalized.leadInfo), settings.source],
        )).rows[0];
      }

      let opportunity = null;
      let opportunityCreated = false;
      let opportunityStageChanged = false;
      if (settings.stage_id) {
        const stage = (await client.query(`SELECT id FROM stages WHERE id = $1 AND company_id = $2`, [settings.stage_id, row.company_id])).rows[0];
        if (!stage) throw formError("The configured Pipeline stage is unavailable.", "website_form_stage_unavailable", 409);
        const beforeOpportunity = (await client.query(`SELECT * FROM opportunities WHERE user_id = $1 AND contact_id = $2 LIMIT 1 FOR UPDATE`, [owner.id, String(contact.id)])).rows[0] || null;
        opportunityCreated = !beforeOpportunity;
        opportunityStageChanged = !beforeOpportunity || beforeOpportunity.state !== "stage" || String(beforeOpportunity.stage_id || "") !== settings.stage_id;
        opportunity = (await client.query(
          `INSERT INTO opportunities(id, user_id, company_id, contact_id, state, stage_id, stage_entered_at)
           VALUES($1,$2,$3,$4,'stage',$5,now())
           ON CONFLICT (user_id, contact_id) DO UPDATE SET company_id = EXCLUDED.company_id, state = 'stage', stage_id = EXCLUDED.stage_id, stage_entered_at = now(), updated_at = now()
           RETURNING *`,
          [randomUUID(), owner.id, row.company_id, String(contact.id), settings.stage_id],
        )).rows[0];
      }

      let task = null;
      if (settings.task_title) {
        const due = new Date(Date.now() + settings.task_due_days * 86400000);
        task = (await client.query(
          `INSERT INTO todo_tasks(id, user_id, title, detail, creator_id, assignee_ids, due_date, priority, status, linked_contact_id, reminders, subtasks, completed)
           VALUES($1,$2,$3,$4,$2,$5::jsonb,$6,'normal','open',$7,'[]'::jsonb,'[]'::jsonb,false) RETURNING *`,
          [randomUUID(), owner.id, settings.task_title, `Created from ${publishedForm.name}.`, JSON.stringify([owner.id]), due, String(contact.id)],
        )).rows[0];
      }

      const notificationUsers = settings.notify_owners ? (await client.query(
        `SELECT id FROM users WHERE company_id = $1 AND deleted_at IS NULL AND role IN ('employer','admin','manager') ORDER BY created_at ASC`,
        [row.company_id],
      )).rows.map((item) => item.id) : [];
      for (const userId of notificationUsers) {
        await client.query(
          `INSERT INTO notifications(id, user_id, company_id, kind, title, body, data)
           VALUES($1,$2,$3,'new_lead',$4,$5,$6::jsonb)`,
          [randomUUID(), userId, row.company_id, `New website lead: ${contact.name}`, publishedForm.name,
            JSON.stringify({ type: "new_lead", contact_id: String(contact.id), website_form_id: String(row.id), submission_id: submissionId })],
        );
      }
      const processed = (await client.query(
        `UPDATE website_form_submissions SET status = 'processed', contact_id = $2, opportunity_id = $3, task_id = $4, processed_at = now()
          WHERE id = $1 RETURNING *`,
        [submissionId, contact.id, opportunity?.id || null, task?.id || null],
      )).rows[0];
      const analytics = input.analytics;
      await client.query(
        `INSERT INTO website_analytics_events(company_id, project_id, publication_id, page_id, form_id, event_type, event_key, visitor_hash, attribution)
         VALUES($1,$2,$3,$4,$5,'form_submit',$6,$7,$8::jsonb)
         ON CONFLICT(publication_id, event_key) DO NOTHING`,
        [row.company_id, row.project_id, row.published_publication_id, analytics?.page_id || null, row.id,
          analytics?.event_key || submissionId, websiteAnalyticsVisitorHash(row.project_id, analytics?.visitor_token),
          JSON.stringify(analytics?.attribution || {})],
      );
      await client.query("COMMIT");
      result = { submission: processed, contact, contactCreated, opportunity, opportunityCreated, opportunityStageChanged, task, notificationUsers, settings, publishedForm, companyId: row.company_id, actorUserId: owner.id };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      return sendWebsiteBuilderError(res, error, "website_form_submit_failed");
    } finally {
      client.release();
    }

    const base = { contact_id: String(result.contact.id), website_form_id: String(result.submission.form_id), submission_id: String(result.submission.id), source: result.settings.source };
    try {
      if (emitAutomationEvent) {
        await emitAutomationEvent({ companyId: result.companyId, eventType: result.contactCreated ? "contact.created" : "contact.updated", subjectType: "contact", subjectId: result.contact.id, actorUserId: result.actorUserId, source: "website.form", dedupeKey: `website.form.contact:${result.submission.id}`, payload: base });
        for (const eventType of ["lead.created", "lead.received_website", "lead.external_form_received"]) {
          await emitAutomationEvent({ companyId: result.companyId, eventType, subjectType: "contact", subjectId: result.contact.id, actorUserId: result.actorUserId, source: "website.form", dedupeKey: `${eventType}:${result.submission.id}`, payload: base });
        }
        if (result.opportunity) {
          const pipelinePayload = { ...base, opportunity_id: result.opportunity.id, stage_id: result.opportunity.stage_id };
          await emitAutomationEvent({ companyId: result.companyId, eventType: result.opportunityCreated ? "pipeline.opportunity_created" : "pipeline.opportunity_updated", subjectType: "opportunity", subjectId: result.opportunity.id, actorUserId: result.actorUserId, source: "website.form", dedupeKey: `pipeline.opportunity:${result.submission.id}`, payload: pipelinePayload });
          if (result.opportunityStageChanged) await emitAutomationEvent({ companyId: result.companyId, eventType: "pipeline.stage_entered", subjectType: "opportunity", subjectId: result.opportunity.id, actorUserId: result.actorUserId, source: "website.form", dedupeKey: `pipeline.stage_entered:${result.submission.id}`, payload: pipelinePayload });
        }
        if (result.task) await emitAutomationEvent({ companyId: result.companyId, eventType: "task.created", subjectType: "task", subjectId: result.task.id, actorUserId: result.actorUserId, source: "website.form", dedupeKey: `task.created:${result.submission.id}`, payload: { ...base, task_id: result.task.id, due_date: result.task.due_date } });
      }
      if (markContactDirty) await markContactDirty(result.companyId, result.contact.id, result.contactCreated ? "contact.created" : "contact.updated");
      if (result.task && syncTaskSchedules) await syncTaskSchedules(result.companyId, result.task);
      if (sendPushToUsers && result.notificationUsers.length) await sendPushToUsers(result.notificationUsers, "new_lead", { title: `New website lead: ${result.contact.name}`, body: result.publishedForm.name, contactId: result.contact.id, payload: { type: "new_lead", contact_id: String(result.contact.id) }, threadId: `new_lead_${result.contact.id}` });
    } catch (effectError) {
      console.warn("[website-builder] form submission downstream effect failed", { submissionId: result.submission.id, code: effectError?.code, message: effectError?.message });
    }
    res.status(201).json({ accepted: true, submission_id: String(result.submission.id), message: result.settings.success_message });
  });

  app.get("/api/public/websites/:subdomain", async (req, res) => {
    try {
      const subdomain = normalizeWebsiteSubdomain(req.params.subdomain);
      const requestedPath = normalizeWebsiteSlug(typeof req.query.path === "string" ? req.query.path : "/", "home");
      const { rows } = await pool.query(
        `SELECT p.company_id, p.subdomain, p.published_publication_id, pub.snapshot,
                d.hostname AS domain_hostname, d.canonical_mode, d.ssl_status
           FROM website_projects p
           JOIN website_publications pub ON pub.id = p.published_publication_id AND pub.project_id = p.id AND pub.company_id = p.company_id
           LEFT JOIN website_domains d ON d.project_id = p.id AND d.company_id = p.company_id
             AND d.verification_status = 'verified' AND d.routing_status = 'verified'
          WHERE lower(p.subdomain) = $1 AND p.lifecycle_status = 'draft'`,
        [subdomain],
      );
      if (!rows[0]) throw new WebsiteBuilderError("website_publication_not_found", "Published website was not found.", 404);
      res.json(await publicWebsitePayload(pool, mediaStorage, rows[0], requestedPath));
    } catch (error) {
      sendWebsiteBuilderError(res, error, "website_publication_load_failed");
    }
  });

  app.get("/api/public/websites/domain/:hostname", async (req, res) => {
    try {
      const hostname = normalizeWebsiteDomainHostname(req.params.hostname);
      const requestedPath = normalizeWebsiteSlug(typeof req.query.path === "string" ? req.query.path : "/", "home");
      const { rows } = await pool.query(
        `SELECT p.company_id, p.subdomain, p.published_publication_id, pub.snapshot,
                d.hostname AS domain_hostname, d.canonical_mode, d.ssl_status
           FROM website_domains d
           JOIN website_projects p ON p.id = d.project_id AND p.company_id = d.company_id
           JOIN website_publications pub ON pub.id = p.published_publication_id AND pub.project_id = p.id AND pub.company_id = p.company_id
          WHERE lower(d.hostname) = $1 AND d.verification_status = 'verified' AND d.routing_status = 'verified'
            AND p.lifecycle_status = 'draft'`,
        [hostname],
      );
      if (!rows[0]) throw new WebsiteBuilderError("website_domain_not_ready", "Custom domain is not ready.", 404);
      res.json(await publicWebsitePayload(pool, mediaStorage, rows[0], requestedPath));
    } catch (error) {
      sendWebsiteBuilderError(res, error, "website_domain_publication_load_failed");
    }
  });

  app.get("/api/public/websites/domain-verification/:hostname/:token", async (req, res) => {
    try {
      const hostname = normalizeWebsiteDomainHostname(req.params.hostname);
      const token = typeof req.params.token === "string" && /^[a-f0-9]{32}$/.test(req.params.token) ? req.params.token : "";
      if (!token) throw new WebsiteBuilderError("website_domain_verification_not_found", "Domain verification was not found.", 404);
      const { rows } = await pool.query(`SELECT 1 FROM website_domains WHERE lower(hostname) = $1 AND verification_token = $2`, [hostname, token]);
      if (!rows[0]) throw new WebsiteBuilderError("website_domain_verification_not_found", "Domain verification was not found.", 404);
      res.status(204).end();
    } catch (error) {
      sendWebsiteBuilderError(res, error, "website_domain_verification_load_failed");
    }
  });

  app.patch("/api/website-builder/projects/:projectId/publishing", authRequired, requirePublish, async (req, res) => {
    let input;
    try {
      input = normalizeWebsitePublishingSettings(req.body);
      requireCompany(req);
    } catch (error) {
      return sendWebsiteBuilderError(res, error, "website_publishing_settings_failed");
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const current = await loadProject(client, req.companyId, req.params.projectId, true);
      if (current.lifecycle_status === "archived") throw new WebsiteBuilderError("website_project_archived", "Restore the project before configuring publishing.", 409);
      assertVersion(current, input.expected_version, "project");
      const updated = (await client.query(
        `UPDATE website_projects SET subdomain = $3, version = version + 1, updated_at = now(), updated_by = $4
          WHERE id = $1 AND company_id = $2 RETURNING *`,
        [current.id, req.companyId, input.subdomain, req.userId],
      )).rows[0];
      await appendAudit(client, { companyId: req.companyId, projectId: current.id, actorUserId: req.userId, action: "project.subdomain_updated", before: { subdomain: current.subdomain || null }, after: { subdomain: updated.subdomain } });
      await client.query("COMMIT");
      res.json({ project: projectPayload(updated) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendWebsiteBuilderError(res, error, "website_publishing_settings_failed");
    } finally {
      client.release();
    }
  });

  app.get("/api/website-builder/projects/:projectId/domain", authRequired, requireView, async (req, res) => {
    try {
      requireCompany(req);
      const project = await loadProject(pool, req.companyId, req.params.projectId);
      const domain = (await pool.query(
        `SELECT * FROM website_domains WHERE company_id = $1 AND project_id = $2`,
        [req.companyId, project.id],
      )).rows[0];
      res.json({ domain: domainPayload(domain) });
    } catch (error) {
      sendWebsiteBuilderError(res, error, "website_domain_load_failed");
    }
  });

  app.put("/api/website-builder/projects/:projectId/domain", authRequired, requirePublish, async (req, res) => {
    let input;
    try {
      input = normalizeWebsiteDomainSettings(req.body);
      requireCompany(req);
    } catch (error) {
      return sendWebsiteBuilderError(res, error, "website_domain_save_failed");
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const project = await loadProject(client, req.companyId, req.params.projectId, true);
      if (project.lifecycle_status === "archived") throw new WebsiteBuilderError("website_project_archived", "Restore the project before assigning a domain.", 409);
      if (!project.subdomain) throw new WebsiteBuilderError("website_subdomain_required", "Reserve a WolfCRM subdomain before assigning a custom domain.", 409);
      assertVersion(project, input.expected_project_version, "project");
      const current = (await client.query(`SELECT * FROM website_domains WHERE company_id = $1 AND project_id = $2 FOR UPDATE`, [req.companyId, project.id])).rows[0];
      const hostnameChanged = current && current.hostname !== input.hostname;
      const token = hostnameChanged || !current ? randomUUID().replaceAll("-", "") : current.verification_token;
      const domain = (await client.query(
        `INSERT INTO website_domains (company_id, project_id, hostname, canonical_mode, verification_token, cname_target, created_by, updated_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
         ON CONFLICT (project_id) DO UPDATE SET
           hostname = EXCLUDED.hostname, canonical_mode = EXCLUDED.canonical_mode,
           verification_token = EXCLUDED.verification_token,
           verification_status = CASE WHEN website_domains.hostname = EXCLUDED.hostname THEN website_domains.verification_status ELSE 'pending' END,
           routing_status = CASE WHEN website_domains.hostname = EXCLUDED.hostname THEN website_domains.routing_status ELSE 'pending' END,
           ssl_status = CASE WHEN website_domains.hostname = EXCLUDED.hostname THEN website_domains.ssl_status ELSE 'pending_provider' END,
           version = website_domains.version + 1, last_checked_at = CASE WHEN website_domains.hostname = EXCLUDED.hostname THEN website_domains.last_checked_at ELSE NULL END,
           verified_at = CASE WHEN website_domains.hostname = EXCLUDED.hostname THEN website_domains.verified_at ELSE NULL END,
           updated_by = EXCLUDED.updated_by, updated_at = now()
         RETURNING *`,
        [req.companyId, project.id, input.hostname, input.canonical_mode, token, process.env.WEBSITE_CUSTOM_DOMAIN_CNAME_TARGET || "sites.wolfcrm.site", req.userId],
      )).rows[0];
      const updatedProject = (await client.query(
        `UPDATE website_projects SET version = version + 1, updated_at = now(), updated_by = $3 WHERE id = $1 AND company_id = $2 RETURNING *`,
        [project.id, req.companyId, req.userId],
      )).rows[0];
      await appendAudit(client, { companyId: req.companyId, projectId: project.id, actorUserId: req.userId, action: "domain.saved", before: current ? { hostname: current.hostname, canonical_mode: current.canonical_mode } : null, after: { hostname: domain.hostname, canonical_mode: domain.canonical_mode } });
      await client.query("COMMIT");
      res.json({ project: projectPayload(updatedProject), domain: domainPayload(domain) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendWebsiteBuilderError(res, error, "website_domain_save_failed");
    } finally {
      client.release();
    }
  });

  app.post("/api/website-builder/projects/:projectId/domain/verify", authRequired, requirePublish, async (req, res) => {
    let input;
    try {
      input = normalizeWebsiteDomainVerification(req.body);
      requireCompany(req);
    } catch (error) {
      return sendWebsiteBuilderError(res, error, "website_domain_verification_failed");
    }
    try {
      const project = await loadProject(pool, req.companyId, req.params.projectId);
      const current = (await pool.query(`SELECT * FROM website_domains WHERE company_id = $1 AND project_id = $2`, [req.companyId, project.id])).rows[0];
      if (!current) throw new WebsiteBuilderError("website_domain_not_found", "Assign a custom domain first.", 404);
      assertVersion(current, input.expected_version, "domain");
      const result = await inspectWebsiteDomainDns(current);
      const verified = result.txtVerified && result.routingVerified;
      const sslActive = verified ? await inspectWebsiteDomainTls(current) : false;
      const domain = (await pool.query(
        `UPDATE website_domains SET verification_status = $3, routing_status = $4,
           ssl_status = $8,
           verified_at = CASE WHEN $5 THEN COALESCE(verified_at, now()) ELSE NULL END,
           last_checked_at = now(), version = version + 1, updated_by = $6, updated_at = now()
         WHERE company_id = $1 AND project_id = $2 AND version = $7 RETURNING *`,
        [req.companyId, project.id, result.txtVerified ? "verified" : "pending", result.routingVerified ? "verified" : "pending", verified, req.userId, current.version, sslActive ? "active" : "pending_provider"],
      )).rows[0];
      if (!domain) throw new WebsiteBuilderError("website_domain_stale", "This domain changed while DNS was checked. Refresh and try again.", 409);
      await appendAudit(pool, { companyId: req.companyId, projectId: project.id, actorUserId: req.userId, action: "domain.dns_checked", after: { hostname: current.hostname, verification_status: domain.verification_status, routing_status: domain.routing_status } });
      res.json({ domain: domainPayload(domain) });
    } catch (error) {
      sendWebsiteBuilderError(res, error, "website_domain_verification_failed");
    }
  });

  app.delete("/api/website-builder/projects/:projectId/domain", authRequired, requirePublish, async (req, res) => {
    try {
      const input = normalizeWebsiteDomainVerification(req.body);
      requireCompany(req);
      const project = await loadProject(pool, req.companyId, req.params.projectId);
      const domain = (await pool.query(`DELETE FROM website_domains WHERE company_id = $1 AND project_id = $2 AND version = $3 RETURNING *`, [req.companyId, project.id, input.expected_version])).rows[0];
      if (!domain) throw new WebsiteBuilderError("website_domain_stale", "Custom domain was not found or changed. Refresh and try again.", 409);
      await appendAudit(pool, { companyId: req.companyId, projectId: project.id, actorUserId: req.userId, action: "domain.removed", before: { hostname: domain.hostname } });
      res.json({ removed: true });
    } catch (error) {
      sendWebsiteBuilderError(res, error, "website_domain_remove_failed");
    }
  });

  app.get("/api/website-builder/projects/:projectId/forms", authRequired, requireView, async (req, res) => {
    try {
      requireCompany(req);
      const project = await loadProject(pool, req.companyId, req.params.projectId);
      const { rows } = await pool.query(
        `SELECT f.*, COUNT(s.id)::int AS submission_count
           FROM website_forms f
           LEFT JOIN website_form_submissions s ON s.form_id = f.id
          WHERE f.company_id = $1 AND f.project_id = $2
          GROUP BY f.id ORDER BY f.archived_at NULLS FIRST, f.updated_at DESC LIMIT ${MAX_FORMS_PER_PROJECT}`,
        [req.companyId, project.id],
      );
      res.json({ forms: rows.map((row) => ({ ...formPayload(row), submission_count: exactNumber(row.submission_count) })) });
    } catch (error) {
      sendWebsiteBuilderError(res, error, "website_forms_load_failed");
    }
  });

  app.post("/api/website-builder/projects/:projectId/forms", authRequired, requireManage, async (req, res) => {
    let input;
    try { input = normalizeWebsiteFormCreate(req.body); requireCompany(req); }
    catch (error) { return sendWebsiteBuilderError(res, error, "website_form_create_failed"); }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const project = await loadProject(client, req.companyId, req.params.projectId, true);
      if (project.lifecycle_status === "archived") throw new WebsiteBuilderError("website_project_archived", "Restore the project before creating forms.", 409);
      assertVersion(project, input.expected_project_version, "project");
      const count = Number((await client.query(`SELECT COUNT(*)::int AS count FROM website_forms WHERE company_id = $1 AND project_id = $2`, [req.companyId, project.id])).rows[0]?.count || 0);
      if (count >= MAX_FORMS_PER_PROJECT) throw formError(`A project may contain up to ${MAX_FORMS_PER_PROJECT} forms.`, "website_form_limit", 409);
      const form = (await client.query(
        `INSERT INTO website_forms(company_id, project_id, name, fields, settings, created_by, updated_by)
         VALUES($1,$2,$3,$4::jsonb,$5::jsonb,$6,$6) RETURNING *`,
        [req.companyId, project.id, input.name, JSON.stringify(input.fields), JSON.stringify(input.settings), req.userId],
      )).rows[0];
      const updatedProject = (await client.query(
        `UPDATE website_projects SET version = version + 1, updated_at = now(), updated_by = $3 WHERE id = $1 AND company_id = $2 RETURNING *`,
        [project.id, req.companyId, req.userId],
      )).rows[0];
      await appendAudit(client, { companyId: req.companyId, projectId: project.id, formId: form.id, actorUserId: req.userId, action: "form.created", after: formAuditSnapshot(form) });
      await client.query("COMMIT");
      res.status(201).json({ project: projectPayload(updatedProject), form: formPayload(form) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendWebsiteBuilderError(res, error, "website_form_create_failed");
    } finally { client.release(); }
  });

  app.patch("/api/website-builder/projects/:projectId/forms/:formId", authRequired, requireManage, async (req, res) => {
    let input;
    try { input = normalizeWebsiteFormUpdate(req.body); requireCompany(req); }
    catch (error) { return sendWebsiteBuilderError(res, error, "website_form_update_failed"); }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const project = await loadProject(client, req.companyId, req.params.projectId, true);
      if (project.lifecycle_status === "archived") throw new WebsiteBuilderError("website_project_archived", "Restore the project before changing forms.", 409);
      assertVersion(project, input.expected_project_version, "project");
      const current = await loadForm(client, req.companyId, project.id, req.params.formId, true);
      assertVersion(current, input.expected_version, "form");
      const nextStatus = input.lifecycle_status ?? current.lifecycle_status;
      if (nextStatus === "archived" && current.lifecycle_status !== "archived") {
        const pageRows = (await client.query(`SELECT name, content FROM website_pages WHERE company_id = $1 AND project_id = $2 AND archived_at IS NULL`, [req.companyId, project.id])).rows;
        if (pageRows.some((page) => flattenWebsiteBlocks(page.content).some((block) => block?.type === "form" && block?.data?.form_id === String(current.id)))) {
          throw formError("Remove this form from active pages before archiving it.", "website_form_in_use", 409);
        }
      }
      const form = (await client.query(
        `UPDATE website_forms SET name = $4, fields = $5::jsonb, settings = $6::jsonb, lifecycle_status = $7,
           archived_at = CASE WHEN $7 = 'archived' THEN COALESCE(archived_at, now()) ELSE NULL END,
           version = version + 1, updated_at = now(), updated_by = $8
         WHERE id = $1 AND project_id = $2 AND company_id = $3 RETURNING *`,
        [current.id, project.id, req.companyId, input.name ?? current.name, JSON.stringify(input.fields ?? normalizeWebsiteFormFields(current.fields)),
          JSON.stringify(input.settings ?? normalizeWebsiteFormSettings(current.settings)), nextStatus, req.userId],
      )).rows[0];
      const updatedProject = (await client.query(
        `UPDATE website_projects SET version = version + 1, updated_at = now(), updated_by = $3 WHERE id = $1 AND company_id = $2 RETURNING *`,
        [project.id, req.companyId, req.userId],
      )).rows[0];
      await appendAudit(client, { companyId: req.companyId, projectId: project.id, formId: form.id, actorUserId: req.userId,
        action: nextStatus !== current.lifecycle_status ? `form.${nextStatus}` : "form.updated", before: formAuditSnapshot(current), after: formAuditSnapshot(form) });
      await client.query("COMMIT");
      res.json({ project: projectPayload(updatedProject), form: formPayload(form) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendWebsiteBuilderError(res, error, "website_form_update_failed");
    } finally { client.release(); }
  });

  app.get("/api/website-builder/projects/:projectId/forms/:formId/submissions", authRequired, requireView, async (req, res) => {
    try {
      requireCompany(req);
      const project = await loadProject(pool, req.companyId, req.params.projectId);
      const form = await loadForm(pool, req.companyId, project.id, req.params.formId);
      const { rows } = await pool.query(
        `SELECT * FROM website_form_submissions WHERE company_id = $1 AND project_id = $2 AND form_id = $3
          ORDER BY created_at DESC LIMIT ${MAX_FORM_SUBMISSIONS_PER_RESPONSE}`,
        [req.companyId, project.id, form.id],
      );
      res.json({ submissions: rows.map(submissionPayload) });
    } catch (error) { sendWebsiteBuilderError(res, error, "website_form_submissions_load_failed"); }
  });

  app.get("/api/website-builder/projects/:projectId/analytics", authRequired, requireView, async (req, res) => {
    try {
      requireCompany(req);
      const { days } = normalizeWebsiteAnalyticsReportQuery(req.query);
      const project = await loadProject(pool, req.companyId, req.params.projectId);
      const parameters = [req.companyId, project.id, days];
      const [summaryResult, pageResult, sourceResult, trendResult] = await Promise.all([
        pool.query(
          `SELECT COUNT(*) FILTER (WHERE event_type = 'page_view')::int AS page_views,
                  COUNT(DISTINCT visitor_hash) FILTER (WHERE event_type = 'page_view')::int AS unique_visitors,
                  COUNT(*) FILTER (WHERE event_type = 'cta_click')::int AS cta_clicks,
                  COUNT(*) FILTER (WHERE event_type = 'form_view')::int AS form_views,
                  COUNT(*) FILTER (WHERE event_type = 'form_submit')::int AS form_submissions,
                  COUNT(DISTINCT visitor_hash) FILTER (WHERE event_type = 'form_submit')::int AS unique_converters
             FROM website_analytics_events
            WHERE company_id = $1 AND project_id = $2 AND occurred_at >= now() - ($3::int * interval '1 day')`,
          parameters,
        ),
        pool.query(
          `SELECT p.id::text AS id, p.name, p.slug, p.sort_order,
                  COUNT(e.id) FILTER (WHERE e.event_type = 'page_view')::int AS page_views,
                  COUNT(DISTINCT e.visitor_hash) FILTER (WHERE e.event_type = 'page_view')::int AS unique_visitors,
                  COUNT(e.id) FILTER (WHERE e.event_type = 'cta_click')::int AS cta_clicks,
                  COUNT(e.id) FILTER (WHERE e.event_type = 'form_view')::int AS form_views,
                  COUNT(e.id) FILTER (WHERE e.event_type = 'form_submit')::int AS form_submissions
             FROM website_pages p
             LEFT JOIN website_analytics_events e ON e.page_id = p.id AND e.company_id = p.company_id
               AND e.project_id = p.project_id AND e.occurred_at >= now() - ($3::int * interval '1 day')
            WHERE p.company_id = $1 AND p.project_id = $2 AND p.lifecycle_status = 'draft'
            GROUP BY p.id, p.name, p.slug, p.sort_order
            ORDER BY p.sort_order ASC, p.created_at ASC`,
          parameters,
        ),
        pool.query(
          `SELECT COALESCE(NULLIF(attribution->>'utm_source',''), 'Direct / none') AS source,
                  COALESCE(attribution->>'utm_medium','') AS medium,
                  COALESCE(attribution->>'utm_campaign','') AS campaign,
                  COUNT(*) FILTER (WHERE event_type = 'page_view')::int AS page_views,
                  COUNT(*) FILTER (WHERE event_type = 'form_submit')::int AS form_submissions
             FROM website_analytics_events
            WHERE company_id = $1 AND project_id = $2 AND occurred_at >= now() - ($3::int * interval '1 day')
            GROUP BY 1, 2, 3
            ORDER BY page_views DESC, form_submissions DESC, source ASC
            LIMIT 20`,
          parameters,
        ),
        pool.query(
          `SELECT to_char(date_trunc('day', occurred_at AT TIME ZONE 'UTC'), 'YYYY-MM-DD') AS date,
                  COUNT(*) FILTER (WHERE event_type = 'page_view')::int AS page_views,
                  COUNT(*) FILTER (WHERE event_type = 'form_submit')::int AS form_submissions
             FROM website_analytics_events
            WHERE company_id = $1 AND project_id = $2 AND occurred_at >= now() - ($3::int * interval '1 day')
            GROUP BY 1 ORDER BY 1 ASC`,
          parameters,
        ),
      ]);
      const numbers = (row) => Object.fromEntries(Object.entries(row).map(([key, value]) => [key, typeof value === "number" ? value : Number(value) || 0]));
      res.set("Cache-Control", "no-store").json({
        range: { days, from: new Date(Date.now() - days * 86400000).toISOString(), to: new Date().toISOString() },
        summary: numbers(summaryResult.rows[0] || {}),
        pages: pageResult.rows.map((row) => ({ ...row, ...numbers({ sort_order: row.sort_order, page_views: row.page_views, unique_visitors: row.unique_visitors, cta_clicks: row.cta_clicks, form_views: row.form_views, form_submissions: row.form_submissions }) })),
        sources: sourceResult.rows.map((row) => ({ ...row, ...numbers({ page_views: row.page_views, form_submissions: row.form_submissions }) })),
        trend: trendResult.rows.map((row) => ({ ...row, ...numbers({ page_views: row.page_views, form_submissions: row.form_submissions }) })),
      });
    } catch (error) {
      sendWebsiteBuilderError(res, error, "website_analytics_report_failed");
    }
  });

  app.get("/api/website-builder/projects/:projectId/publications", authRequired, requireView, async (req, res) => {
    try {
      requireCompany(req);
      const project = await loadProject(pool, req.companyId, req.params.projectId);
      const { rows } = await pool.query(
        `SELECT id, project_id, version_number, subdomain, source_publication_id, created_at
           FROM website_publications WHERE company_id = $1 AND project_id = $2
          ORDER BY version_number DESC LIMIT 100`,
        [req.companyId, project.id],
      );
      res.json({ current_publication_id: project.published_publication_id ? String(project.published_publication_id) : null, publications: rows.map(publicationPayload) });
    } catch (error) {
      sendWebsiteBuilderError(res, error, "website_publications_load_failed");
    }
  });

  app.post("/api/website-builder/projects/:projectId/publications", authRequired, requirePublish, async (req, res) => {
    let input;
    try {
      input = normalizeWebsitePublish(req.body);
      requireCompany(req);
    } catch (error) {
      return sendWebsiteBuilderError(res, error, "website_publish_failed");
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const project = await loadProject(client, req.companyId, req.params.projectId, true);
      if (project.lifecycle_status === "archived") throw new WebsiteBuilderError("website_project_archived", "Restore the project before publishing.", 409);
      if (!project.subdomain) throw new WebsiteBuilderError("website_subdomain_required", "Choose a subdomain before publishing.", 409);
      assertVersion(project, input.expected_project_version, "project");
      const pages = (await client.query(
        `SELECT * FROM website_pages WHERE company_id = $1 AND project_id = $2 AND archived_at IS NULL ORDER BY sort_order ASC, created_at ASC FOR SHARE`,
        [req.companyId, project.id],
      )).rows;
      if (!pages.length) throw new WebsiteBuilderError("website_last_page_required", "A project needs an active page before publishing.", 409);
      for (const page of pages) {
        await assertReadyMediaReferences(client, req.companyId, page.content);
        await assertActiveFormReferences(client, req.companyId, project.id, page.content);
      }
      const forms = (await client.query(
        `SELECT * FROM website_forms WHERE company_id = $1 AND project_id = $2 AND lifecycle_status = 'draft' ORDER BY created_at ASC FOR SHARE`,
        [req.companyId, project.id],
      )).rows;
      const versionNumber = exactNumber((await client.query(
        `SELECT COALESCE(MAX(version_number), 0)::int + 1 AS next_version FROM website_publications WHERE project_id = $1`,
        [project.id],
      )).rows[0]?.next_version);
      const snapshot = {
        schema_version: 1,
        project: { id: String(project.id), name: project.name, kind: project.kind, theme: websiteProjectThemePayload(project.theme), navigation: websiteProjectNavigationPayload(project.navigation), subdomain: project.subdomain },
        pages: pages.map(pagePayload),
        forms: forms.map(formPayload),
      };
      const publication = (await client.query(
        `INSERT INTO website_publications (company_id, project_id, version_number, subdomain, snapshot, created_by)
         VALUES ($1,$2,$3,$4,$5::jsonb,$6) RETURNING *`,
        [req.companyId, project.id, versionNumber, project.subdomain, JSON.stringify(snapshot), req.userId],
      )).rows[0];
      const updatedProject = (await client.query(
        `UPDATE website_projects SET published_publication_id = $3, version = version + 1, updated_at = now(), updated_by = $4
          WHERE id = $1 AND company_id = $2 RETURNING *`,
        [project.id, req.companyId, publication.id, req.userId],
      )).rows[0];
      await appendAudit(client, { companyId: req.companyId, projectId: project.id, actorUserId: req.userId, action: "publication.created", after: { publication_id: String(publication.id), version_number: versionNumber } });
      await client.query("COMMIT");
      res.status(201).json({ project: projectPayload(updatedProject), publication: publicationPayload(publication) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendWebsiteBuilderError(res, error, "website_publish_failed");
    } finally {
      client.release();
    }
  });

  app.post("/api/website-builder/projects/:projectId/publications/:publicationId/rollback", authRequired, requirePublish, async (req, res) => {
    let input;
    try {
      input = normalizeWebsitePublish(req.body);
      requireCompany(req);
    } catch (error) {
      return sendWebsiteBuilderError(res, error, "website_rollback_failed");
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const project = await loadProject(client, req.companyId, req.params.projectId, true);
      if (project.lifecycle_status === "archived") throw new WebsiteBuilderError("website_project_archived", "Restore the project before rolling back.", 409);
      if (!project.subdomain) throw new WebsiteBuilderError("website_subdomain_required", "Choose a subdomain before rolling back.", 409);
      assertVersion(project, input.expected_project_version, "project");
      const source = (await client.query(
        `SELECT * FROM website_publications WHERE id::text = $1 AND company_id = $2 AND project_id = $3 FOR SHARE`,
        [req.params.publicationId, req.companyId, project.id],
      )).rows[0];
      if (!source) throw new WebsiteBuilderError("website_publication_not_found", "Publication version was not found.", 404);
      const versionNumber = exactNumber((await client.query(
        `SELECT COALESCE(MAX(version_number), 0)::int + 1 AS next_version FROM website_publications WHERE project_id = $1`,
        [project.id],
      )).rows[0]?.next_version);
      const snapshot = { ...source.snapshot, project: { ...source.snapshot.project, subdomain: project.subdomain } };
      const publication = (await client.query(
        `INSERT INTO website_publications (company_id, project_id, version_number, subdomain, snapshot, source_publication_id, created_by)
         VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7) RETURNING *`,
        [req.companyId, project.id, versionNumber, project.subdomain, JSON.stringify(snapshot), source.id, req.userId],
      )).rows[0];
      const updatedProject = (await client.query(
        `UPDATE website_projects SET published_publication_id = $3, version = version + 1, updated_at = now(), updated_by = $4
          WHERE id = $1 AND company_id = $2 RETURNING *`,
        [project.id, req.companyId, publication.id, req.userId],
      )).rows[0];
      await appendAudit(client, { companyId: req.companyId, projectId: project.id, actorUserId: req.userId, action: "publication.rolled_back", before: { publication_id: project.published_publication_id ? String(project.published_publication_id) : null }, after: { publication_id: String(publication.id), version_number: versionNumber, source_publication_id: String(source.id) } });
      await client.query("COMMIT");
      res.status(201).json({ project: projectPayload(updatedProject), publication: publicationPayload(publication) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendWebsiteBuilderError(res, error, "website_rollback_failed");
    } finally {
      client.release();
    }
  });

  app.get("/api/website-builder/media", authRequired, requireView, async (req, res) => {
    try {
      const companyId = requireCompany(req);
      const status = req.query.status === "archived" ? "archived" : "ready";
      const { rows } = await pool.query(
        `SELECT * FROM website_media WHERE company_id = $1 AND lifecycle_status = $2
          ORDER BY updated_at DESC, lower(file_name) ASC LIMIT ${MAX_MEDIA_PER_COMPANY}`,
        [companyId, status],
      );
      const media = await Promise.all(rows.map(async (row) => mediaPayload(row, await mediaStorage?.downloadUrl?.(row.object_key))));
      res.json({ media });
    } catch (error) {
      sendWebsiteBuilderError(res, error, "website_media_load_failed");
    }
  });

  app.post("/api/website-builder/media/upload-url", authRequired, requireManage, async (req, res) => {
    try {
      const companyId = requireCompany(req);
      if (!mediaStorage?.uploadUrl) throw new WebsiteBuilderError("media_bucket_not_configured", "Website media storage is not configured.", 503);
      const input = normalizeWebsiteMediaReserve(req.body);
      const count = await pool.query(`SELECT COUNT(*)::int AS count FROM website_media WHERE company_id = $1`, [companyId]);
      if (exactNumber(count.rows[0]?.count) >= MAX_MEDIA_PER_COMPANY) throw new WebsiteBuilderError("website_media_limit_reached", `A company may have up to ${MAX_MEDIA_PER_COMPANY} media items.`, 409);
      const id = randomUUID();
      const objectKey = `companies/${companyId}/website/${id}/${input.file_name}`;
      const uploadUrl = await mediaStorage.uploadUrl(objectKey, input.mime_type, input.byte_size);
      if (!uploadUrl) throw new WebsiteBuilderError("media_bucket_not_configured", "Website media storage is not configured.", 503);
      const media = (await pool.query(
        `INSERT INTO website_media (id, company_id, file_name, mime_type, byte_size, object_key, alt_text, created_by, updated_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8) RETURNING *`,
        [id, companyId, input.file_name, input.mime_type, input.byte_size, objectKey, input.alt_text, req.userId],
      )).rows[0];
      res.status(201).json({ media: mediaPayload(media), upload_url: uploadUrl });
    } catch (error) {
      sendWebsiteBuilderError(res, error, "website_media_upload_url_failed");
    }
  });

  app.post("/api/website-builder/media/:mediaId/complete", authRequired, requireManage, async (req, res) => {
    const client = await pool.connect();
    try {
      requireCompany(req);
      if (!mediaStorage?.inspect || !mediaStorage?.downloadUrl) throw new WebsiteBuilderError("media_bucket_not_configured", "Website media storage is not configured.", 503);
      const expectedVersion = requiredVersion(req.body?.expected_version);
      await client.query("BEGIN");
      const current = await loadMedia(client, req.companyId, req.params.mediaId, true);
      assertVersion(current, expectedVersion, "media");
      if (current.lifecycle_status !== "uploading") throw new WebsiteBuilderError("website_media_upload_completed", "This media upload is already complete.", 409);
      const object = await mediaStorage.inspect(current.object_key);
      if (exactNumber(object.byte_size) !== exactNumber(current.byte_size) || object.mime_type !== current.mime_type) {
        throw new WebsiteBuilderError("website_media_upload_mismatch", "Uploaded media does not match the reserved image.", 409);
      }
      const media = (await client.query(
        `UPDATE website_media SET lifecycle_status = 'ready', updated_at = now(), updated_by = $3, version = version + 1
          WHERE id = $1 AND company_id = $2 RETURNING *`, [current.id, req.companyId, req.userId],
      )).rows[0];
      await appendAudit(client, { companyId: req.companyId, mediaId: media.id, actorUserId: req.userId, action: "media.ready", before: mediaAuditSnapshot(current), after: mediaAuditSnapshot(media) });
      await client.query("COMMIT");
      res.json({ media: mediaPayload(media, await mediaStorage.downloadUrl(media.object_key)) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendWebsiteBuilderError(res, error, "website_media_complete_failed");
    } finally { client.release(); }
  });

  app.patch("/api/website-builder/media/:mediaId", authRequired, requireManage, async (req, res) => {
    const client = await pool.connect();
    try {
      requireCompany(req);
      const input = normalizeWebsiteMediaUpdate(req.body);
      await client.query("BEGIN");
      const current = await loadMedia(client, req.companyId, req.params.mediaId, true);
      assertVersion(current, input.expected_version, "media");
      if (current.lifecycle_status === "uploading") throw new WebsiteBuilderError("website_media_upload_incomplete", "Complete the upload before editing this media item.", 409);
      const status = input.lifecycle_status ?? current.lifecycle_status;
      const altText = input.alt_text ?? current.alt_text;
      if (status === "archived" && current.lifecycle_status !== "archived") {
        const usage = await client.query(
          `SELECT EXISTS (
             SELECT 1 FROM website_pages p
             WHERE p.company_id = $1 AND p.archived_at IS NULL
               AND (
                 jsonb_path_exists(p.content, '$.** ? (@.type == "image" && @.data.media_id == $mediaId)', jsonb_build_object('mediaId', to_jsonb($2::text)))
                 OR EXISTS (SELECT 1 FROM jsonb_path_query(p.content, '$.** ? (@.type == "gallery")') gallery_block, jsonb_array_elements_text(gallery_block->'data'->'items') gallery_item WHERE split_part(gallery_item, '|', 1) = $2)
               )
             UNION ALL
             SELECT 1 FROM website_sections s
             WHERE s.company_id = $1 AND s.archived_at IS NULL
               AND (
                 jsonb_path_exists(s.content, '$.** ? (@.type == "image" && @.data.media_id == $mediaId)', jsonb_build_object('mediaId', to_jsonb($2::text)))
                 OR EXISTS (SELECT 1 FROM jsonb_path_query(s.content, '$.** ? (@.type == "gallery")') gallery_block, jsonb_array_elements_text(gallery_block->'data'->'items') gallery_item WHERE split_part(gallery_item, '|', 1) = $2)
               )
           ) AS in_use`,
          [req.companyId, String(current.id)],
        );
        if (usage.rows[0]?.in_use) throw new WebsiteBuilderError("website_media_in_use", "Remove this image from active pages, Galleries, and reusable sections before retiring it.", 409);
      }
      const media = (await client.query(
        `UPDATE website_media SET alt_text = $3, lifecycle_status = $4,
          archived_at = CASE WHEN $4 = 'archived' THEN COALESCE(archived_at, now()) ELSE NULL END,
          updated_at = now(), updated_by = $5, version = version + 1
          WHERE id = $1 AND company_id = $2 RETURNING *`, [current.id, req.companyId, altText, status, req.userId],
      )).rows[0];
      await appendAudit(client, { companyId: req.companyId, mediaId: media.id, actorUserId: req.userId, action: status !== current.lifecycle_status ? `media.${status}` : "media.updated", before: mediaAuditSnapshot(current), after: mediaAuditSnapshot(media) });
      await client.query("COMMIT");
      res.json({ media: mediaPayload(media, status === "ready" ? await mediaStorage?.downloadUrl?.(media.object_key) : null) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendWebsiteBuilderError(res, error, "website_media_update_failed");
    } finally { client.release(); }
  });

  app.get("/api/website-builder/templates", authRequired, requireView, async (req, res) => {
    try {
      requireCompany(req);
      res.json({ templates: websiteTemplatesForKind(req.query.kind) });
    } catch (error) {
      sendWebsiteBuilderError(res, error, "website_templates_load_failed");
    }
  });

  app.get("/api/website-builder/sections", authRequired, requireView, async (req, res) => {
    try {
      const companyId = requireCompany(req);
      const status = req.query.status === "all" ? "all" : req.query.status === "archived" ? "archived" : "draft";
      const values = [companyId];
      const statusWhere = status === "all" ? "" : " AND lifecycle_status = $2";
      if (status !== "all") values.push(status);
      const { rows } = await pool.query(
        `SELECT * FROM website_sections
          WHERE company_id = $1${statusWhere}
          ORDER BY (archived_at IS NOT NULL) ASC, updated_at DESC, lower(name) ASC
          LIMIT ${MAX_REUSABLE_SECTIONS_PER_COMPANY}`,
        values,
      );
      res.json({ sections: rows.map(sectionPayload) });
    } catch (error) {
      sendWebsiteBuilderError(res, error, "website_sections_load_failed");
    }
  });

  app.post("/api/website-builder/sections", authRequired, requireManage, async (req, res) => {
    let input;
    try {
      requireCompany(req);
      input = normalizeWebsiteSectionCreate(req.body);
    } catch (error) {
      return sendWebsiteBuilderError(res, error, "website_section_create_failed");
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const count = await client.query(`SELECT COUNT(*)::int AS count FROM website_sections WHERE company_id = $1`, [req.companyId]);
      if (exactNumber(count.rows[0]?.count) >= MAX_REUSABLE_SECTIONS_PER_COMPANY) {
        throw new WebsiteBuilderError("website_section_limit_reached", `A company may have up to ${MAX_REUSABLE_SECTIONS_PER_COMPANY} reusable sections.`, 409);
      }
      const section = (await client.query(
        `INSERT INTO website_sections (company_id, name, content, created_by, updated_by)
         VALUES ($1,$2,$3::jsonb,$4,$4) RETURNING *`,
        [req.companyId, input.name, JSON.stringify(input.content), req.userId],
      )).rows[0];
      await appendAudit(client, {
        companyId: req.companyId,
        sectionId: section.id,
        actorUserId: req.userId,
        action: "section.created",
        after: sectionAuditSnapshot(section),
      });
      await client.query("COMMIT");
      res.status(201).json({ section: sectionPayload(section) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendWebsiteBuilderError(res, error, "website_section_create_failed");
    } finally {
      client.release();
    }
  });

  app.patch("/api/website-builder/sections/:sectionId", authRequired, requireManage, async (req, res) => {
    let input;
    try {
      requireCompany(req);
      input = normalizeWebsiteSectionUpdate(req.body);
    } catch (error) {
      return sendWebsiteBuilderError(res, error, "website_section_update_failed");
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const current = await loadSection(client, req.companyId, req.params.sectionId, true);
      assertVersion(current, input.expected_version, "section");
      if (current.lifecycle_status === "archived" && (input.name !== undefined || input.content !== undefined) && input.lifecycle_status !== "draft") {
        throw new WebsiteBuilderError("website_section_archived", "Restore the reusable section before changing it.", 409);
      }
      const nextName = input.name ?? current.name;
      const nextContent = input.content ?? current.content;
      if (input.content !== undefined || input.lifecycle_status === "draft") {
        await assertReadyMediaReferences(client, req.companyId, nextContent);
        await assertActiveFormReferences(client, req.companyId, project.id, nextContent);
      }
      const nextStatus = input.lifecycle_status ?? current.lifecycle_status;
      if (nextName === current.name && nextStatus === current.lifecycle_status && JSON.stringify(nextContent) === JSON.stringify(current.content)) {
        await client.query("COMMIT");
        return res.json({ section: sectionPayload(current) });
      }
      const section = (await client.query(
        `UPDATE website_sections
            SET name = $3, content = $4::jsonb, lifecycle_status = $5,
                archived_at = CASE WHEN $5 = 'archived' THEN COALESCE(archived_at, now()) ELSE NULL END,
                updated_by = $6, updated_at = now(), version = version + 1
          WHERE id = $1 AND company_id = $2 RETURNING *`,
        [current.id, req.companyId, nextName, JSON.stringify(nextContent), nextStatus, req.userId],
      )).rows[0];
      await appendAudit(client, {
        companyId: req.companyId,
        sectionId: current.id,
        actorUserId: req.userId,
        action: nextStatus !== current.lifecycle_status ? `section.${nextStatus}` : "section.updated",
        before: sectionAuditSnapshot(current),
        after: sectionAuditSnapshot(section),
      });
      await client.query("COMMIT");
      res.json({ section: sectionPayload(section) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendWebsiteBuilderError(res, error, "website_section_update_failed");
    } finally {
      client.release();
    }
  });

  app.get("/api/website-builder/projects", authRequired, requireView, async (req, res) => {
    try {
      const companyId = requireCompany(req);
      const status = req.query.status === "archived" ? "archived" : req.query.status === "all" ? "all" : "draft";
      const values = [companyId];
      const where = status === "all" ? "" : " AND p.lifecycle_status = $2";
      if (status !== "all") values.push(status);
      const { rows } = await pool.query(
        `SELECT p.*,
                COUNT(pg.id) FILTER (WHERE pg.archived_at IS NULL)::int AS active_page_count,
                COUNT(pg.id) FILTER (WHERE pg.archived_at IS NOT NULL)::int AS archived_page_count
           FROM website_projects p
           LEFT JOIN website_pages pg ON pg.project_id = p.id AND pg.company_id = p.company_id
          WHERE p.company_id = $1${where}
          GROUP BY p.id
          ORDER BY (p.lifecycle_status = 'archived') ASC, p.updated_at DESC, lower(p.name) ASC
          LIMIT ${MAX_PROJECTS_PER_COMPANY}`,
        values,
      );
      res.json({ projects: rows.map(projectPayload) });
    } catch (error) {
      sendWebsiteBuilderError(res, error, "website_projects_load_failed");
    }
  });

  app.post("/api/website-builder/projects", authRequired, requireManage, async (req, res) => {
    let input;
    try {
      input = normalizeWebsiteProjectCreate(req.body);
      requireCompany(req);
    } catch (error) {
      return sendWebsiteBuilderError(res, error, "website_project_create_failed");
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const count = await client.query(
        `SELECT COUNT(*)::int AS count FROM website_projects WHERE company_id = $1`,
        [req.companyId],
      );
      if (exactNumber(count.rows[0]?.count) >= MAX_PROJECTS_PER_COMPANY) {
        throw new WebsiteBuilderError(
          "website_project_limit_reached",
          `A company may have up to ${MAX_PROJECTS_PER_COMPANY} Website Builder projects.`,
          409,
        );
      }
      const projectId = randomUUID();
      const pageId = randomUUID();
      const project = (await client.query(
        `INSERT INTO website_projects (
           id, company_id, name, kind, created_by, updated_by
         ) VALUES ($1,$2,$3,$4,$5,$5)
         RETURNING *`,
        [projectId, req.companyId, input.name, input.kind, req.userId],
      )).rows[0];
      const starter = starterPageForProject({ kind: input.kind, projectName: input.name });
      const page = (await client.query(
        `INSERT INTO website_pages (
           id, company_id, project_id, name, slug, page_kind, is_home,
           sort_order, content, seo, created_by, updated_by
         ) VALUES ($1,$2,$3,$4,$5,$6,true,0,$7::jsonb,$8::jsonb,$9,$9)
         RETURNING *`,
        [
          pageId,
          req.companyId,
          projectId,
          starter.name,
          starter.slug,
          starter.page_kind,
          JSON.stringify(starter.content),
          JSON.stringify(starter.seo),
          req.userId,
        ],
      )).rows[0];
      await appendAudit(client, {
        companyId: req.companyId,
        projectId,
        pageId,
        actorUserId: req.userId,
        action: "project.created",
        after: { project: projectAuditSnapshot(project), starter_page: pageAuditSnapshot(page) },
      });
      await client.query("COMMIT");
      res.status(201).json({
        project: projectPayload({ ...project, active_page_count: 1, archived_page_count: 0 }),
        pages: [pagePayload(page)],
      });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendWebsiteBuilderError(res, error, "website_project_create_failed");
    } finally {
      client.release();
    }
  });

  app.get("/api/website-builder/projects/:projectId", authRequired, requireView, async (req, res) => {
    try {
      const companyId = requireCompany(req);
      const project = await loadProject(pool, companyId, req.params.projectId);
      const { rows } = await pool.query(
        `SELECT * FROM website_pages
          WHERE company_id = $1 AND project_id = $2
          ORDER BY (archived_at IS NOT NULL) ASC, sort_order ASC, created_at ASC`,
        [companyId, project.id],
      );
      const activeCount = rows.filter((row) => !row.archived_at).length;
      res.json({
        project: projectPayload({
          ...project,
          active_page_count: activeCount,
          archived_page_count: rows.length - activeCount,
        }),
        pages: rows.map(pagePayload),
      });
    } catch (error) {
      sendWebsiteBuilderError(res, error, "website_project_load_failed");
    }
  });

  app.patch("/api/website-builder/projects/:projectId", authRequired, requireManage, async (req, res) => {
    let input;
    try {
      input = normalizeWebsiteProjectUpdate(req.body);
      requireCompany(req);
    } catch (error) {
      return sendWebsiteBuilderError(res, error, "website_project_update_failed");
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const current = await loadProject(client, req.companyId, req.params.projectId, true);
      assertVersion(current, input.expected_version, "project");
      if (
        current.lifecycle_status === "archived" &&
        (input.name !== undefined || input.theme !== undefined || input.navigation !== undefined) &&
        input.lifecycle_status !== "draft"
      ) {
        throw new WebsiteBuilderError(
          "website_project_archived",
          "Restore the project before changing its settings.",
          409,
        );
      }
      const nextName = input.name ?? current.name;
      const nextStatus = input.lifecycle_status ?? current.lifecycle_status;
      const nextTheme = input.theme ?? websiteProjectThemePayload(current.theme);
      const nextNavigation = input.navigation ?? websiteProjectNavigationPayload(current.navigation);
      if (input.navigation?.mode === "custom") {
        const pageIds = input.navigation.items.map((item) => item.page_id);
        if (pageIds.length) {
          const { rows } = await client.query(
            `SELECT id::text AS id FROM website_pages
              WHERE company_id = $1 AND project_id = $2 AND archived_at IS NULL
                AND id = ANY($3::uuid[])`,
            [req.companyId, current.id, pageIds],
          );
          if (rows.length !== pageIds.length) {
            throw new WebsiteBuilderError(
              "website_project_navigation_page_invalid",
              "Custom navigation may include only active pages from this project.",
              409,
            );
          }
        }
      }
      const themeUnchanged = JSON.stringify(nextTheme) === JSON.stringify(websiteProjectThemePayload(current.theme));
      const navigationUnchanged = JSON.stringify(nextNavigation) === JSON.stringify(websiteProjectNavigationPayload(current.navigation));
      if (nextName === current.name && nextStatus === current.lifecycle_status && themeUnchanged && navigationUnchanged) {
        await client.query("COMMIT");
        return res.json({ project: projectPayload(current) });
      }
      const updated = (await client.query(
        `UPDATE website_projects
            SET name = $3,
                lifecycle_status = $4,
                theme = $5::jsonb,
                navigation = $6::jsonb,
                archived_at = CASE WHEN $4 = 'archived' THEN COALESCE(archived_at, now()) ELSE NULL END,
                updated_by = $7,
                updated_at = now(),
                version = version + 1
          WHERE id = $1 AND company_id = $2
          RETURNING *`,
        [current.id, req.companyId, nextName, nextStatus, JSON.stringify(nextTheme), JSON.stringify(nextNavigation), req.userId],
      )).rows[0];
      await appendAudit(client, {
        companyId: req.companyId,
        projectId: current.id,
        actorUserId: req.userId,
        action: nextStatus !== current.lifecycle_status
          ? `project.${nextStatus}`
          : !navigationUnchanged && nextName === current.name && themeUnchanged
            ? "project.navigation_updated"
            : !themeUnchanged && nextName === current.name && navigationUnchanged
              ? "project.theme_updated"
              : "project.updated",
        before: projectAuditSnapshot(current),
        after: projectAuditSnapshot(updated),
      });
      await client.query("COMMIT");
      res.json({ project: projectPayload(updated) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendWebsiteBuilderError(res, error, "website_project_update_failed");
    } finally {
      client.release();
    }
  });

  app.post("/api/website-builder/projects/:projectId/pages", authRequired, requireManage, async (req, res) => {
    let companyId;
    try {
      companyId = requireCompany(req);
    } catch (error) {
      return sendWebsiteBuilderError(res, error, "website_page_create_failed");
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const project = await loadProject(client, companyId, req.params.projectId, true);
      if (project.lifecycle_status === "archived") {
        throw new WebsiteBuilderError(
          "website_project_archived",
          "Restore the project before adding pages.",
          409,
        );
      }
      const input = normalizeWebsitePageCreate(req.body, project.kind);
      assertVersion(project, input.expected_project_version, "project");
      const count = await client.query(
        `SELECT COUNT(*)::int AS count,
                COALESCE(MAX(sort_order) FILTER (WHERE archived_at IS NULL), -1)::int AS maximum
           FROM website_pages WHERE company_id = $1 AND project_id = $2`,
        [companyId, project.id],
      );
      if (exactNumber(count.rows[0]?.count) >= MAX_PAGES_PER_PROJECT) {
        throw new WebsiteBuilderError(
          "website_page_limit_reached",
          `A project may have up to ${MAX_PAGES_PER_PROJECT} total pages.`,
          409,
        );
      }
      const pageId = randomUUID();
      const content = {
        schema_version: 1,
        blocks: [{
          id: randomUUID(),
          type: "hero",
          data: { heading: input.name, body: "Add the details visitors need to take the next step." },
        }],
      };
      const page = (await client.query(
        `INSERT INTO website_pages (
           id, company_id, project_id, name, slug, page_kind, sort_order,
           content, seo, created_by, updated_by
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10,$10)
         RETURNING *`,
        [
          pageId,
          companyId,
          project.id,
          input.name,
          input.slug,
          input.page_kind,
          exactNumber(count.rows[0]?.maximum) + 1,
          JSON.stringify(content),
          JSON.stringify(normalizeWebsitePageSeo({ title: input.name })),
          req.userId,
        ],
      )).rows[0];
      const updatedProject = (await client.query(
        `UPDATE website_projects
            SET version = version + 1, updated_at = now(), updated_by = $3
          WHERE id = $1 AND company_id = $2
          RETURNING *`,
        [project.id, companyId, req.userId],
      )).rows[0];
      await appendAudit(client, {
        companyId,
        projectId: project.id,
        pageId,
        actorUserId: req.userId,
        action: "page.created",
        after: pageAuditSnapshot(page),
      });
      await client.query("COMMIT");
      res.status(201).json({ project: projectPayload(updatedProject), page: pagePayload(page) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendWebsiteBuilderError(res, error, "website_page_create_failed");
    } finally {
      client.release();
    }
  });

  app.patch("/api/website-builder/projects/:projectId/pages/:pageId", authRequired, requireManage, async (req, res) => {
    let input;
    try {
      input = normalizeWebsitePageUpdate(req.body);
      requireCompany(req);
    } catch (error) {
      return sendWebsiteBuilderError(res, error, "website_page_update_failed");
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const project = await loadProject(client, req.companyId, req.params.projectId, true);
      if (project.lifecycle_status === "archived") {
        throw new WebsiteBuilderError(
          "website_project_archived",
          "Restore the project before changing its pages.",
          409,
        );
      }
      assertVersion(project, input.expected_project_version, "project");
      const current = await loadPage(client, req.companyId, project.id, req.params.pageId, true);
      assertVersion(current, input.expected_version, "page");
      const nextName = input.name ?? current.name;
      const nextSlug = input.slug ?? current.slug;
      const nextStatus = input.lifecycle_status ?? current.lifecycle_status;
      const nextContent = input.content ?? current.content;
      if (input.content !== undefined || input.lifecycle_status === "draft") {
        await assertReadyMediaReferences(client, req.companyId, nextContent);
      }
      const nextSeo = input.seo ?? current.seo;
      const nextChrome = input.chrome ?? websitePageChromePayload(current.chrome);
      let nextHome = input.is_home ?? current.is_home;
      let replacementHomeId = null;

      if (nextStatus === "archived") nextHome = false;
      if (current.is_home && nextStatus !== "archived" && nextHome === false) {
        throw new WebsiteBuilderError(
          "website_home_required",
          "Choose another home/entry page before removing this one.",
          409,
        );
      }
      if (current.lifecycle_status !== "archived" && nextStatus === "archived") {
        const siblings = (await client.query(
          `SELECT * FROM website_pages
            WHERE company_id = $1 AND project_id = $2 AND id <> $3 AND archived_at IS NULL
            ORDER BY sort_order ASC, created_at ASC
            FOR UPDATE`,
          [req.companyId, project.id, current.id],
        )).rows;
        if (!siblings.length) {
          throw new WebsiteBuilderError(
            "website_last_page_required",
            "A project must keep at least one active page.",
            409,
          );
        }
        if (current.is_home) {
          replacementHomeId = siblings[0].id;
        }
      }
      if (nextHome && nextStatus !== "archived") {
        await client.query(
          `UPDATE website_pages
              SET is_home = false, version = version + 1, updated_at = now(), updated_by = $4
            WHERE project_id = $1 AND company_id = $2 AND id <> $3 AND is_home = true AND archived_at IS NULL`,
          [project.id, req.companyId, current.id, req.userId],
        );
      }
      const unchanged =
        nextName === current.name &&
        nextSlug === current.slug &&
        nextStatus === current.lifecycle_status &&
        nextHome === current.is_home &&
        JSON.stringify(nextContent) === JSON.stringify(current.content) &&
        JSON.stringify(websitePageSeoPayload(nextSeo)) === JSON.stringify(websitePageSeoPayload(current.seo)) &&
        JSON.stringify(nextChrome) === JSON.stringify(websitePageChromePayload(current.chrome));
      if (unchanged) {
        await client.query("COMMIT");
        return res.json({ project: projectPayload(project), page: pagePayload(current) });
      }
      const page = (await client.query(
        `UPDATE website_pages
            SET name = $4,
                slug = $5,
                lifecycle_status = $6,
                is_home = $7,
                content = $8::jsonb,
                seo = $9::jsonb,
                chrome = $10::jsonb,
                archived_at = CASE WHEN $6 = 'archived' THEN COALESCE(archived_at, now()) ELSE NULL END,
                updated_by = $11,
                updated_at = now(),
                version = version + 1
          WHERE id = $1 AND project_id = $2 AND company_id = $3
          RETURNING *`,
        [current.id, project.id, req.companyId, nextName, nextSlug, nextStatus, nextHome, JSON.stringify(nextContent), JSON.stringify(websitePageSeoPayload(nextSeo)), JSON.stringify(nextChrome), req.userId],
      )).rows[0];
      if (replacementHomeId) {
        await client.query(
          `UPDATE website_pages
              SET is_home = true, version = version + 1, updated_at = now(), updated_by = $4
            WHERE id = $1 AND project_id = $2 AND company_id = $3`,
          [replacementHomeId, project.id, req.companyId, req.userId],
        );
      }
      const nextProjectNavigation = websiteProjectNavigationPayload(project.navigation);
      if (nextStatus === "archived" && nextProjectNavigation.mode === "custom") {
        nextProjectNavigation.items = nextProjectNavigation.items.filter(
          (item) => item.page_id !== String(current.id),
        );
      }
      const updatedProject = (await client.query(
        `UPDATE website_projects
            SET navigation = $3::jsonb, version = version + 1, updated_at = now(), updated_by = $4
          WHERE id = $1 AND company_id = $2
          RETURNING *`,
        [project.id, req.companyId, JSON.stringify(nextProjectNavigation), req.userId],
      )).rows[0];
      await appendAudit(client, {
        companyId: req.companyId,
        projectId: project.id,
        pageId: current.id,
        actorUserId: req.userId,
        action: nextStatus !== current.lifecycle_status
          ? `page.${nextStatus}`
          : input.content !== undefined
            ? "page.content_updated"
            : input.chrome !== undefined
              ? "page.chrome_updated"
            : input.seo !== undefined
              ? "page.seo_updated"
              : "page.updated",
        before: pageAuditSnapshot(current),
        after: pageAuditSnapshot(page),
      });
      await client.query("COMMIT");
      res.json({ project: projectPayload(updatedProject), page: pagePayload(page) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendWebsiteBuilderError(res, error, "website_page_update_failed");
    } finally {
      client.release();
    }
  });

  app.post("/api/website-builder/projects/:projectId/pages/:pageId/duplicate", authRequired, requireManage, async (req, res) => {
    let input;
    try { input = normalizeWebsitePageDuplicate(req.body); requireCompany(req); }
    catch (error) { return sendWebsiteBuilderError(res, error, "website_page_duplicate_failed"); }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const project = await loadProject(client, req.companyId, req.params.projectId, true);
      if (project.lifecycle_status === "archived") throw new WebsiteBuilderError("website_project_archived", "Restore the project before duplicating pages.", 409);
      assertVersion(project, input.expected_project_version, "project");
      const source = await loadPage(client, req.companyId, project.id, req.params.pageId, true);
      assertVersion(source, input.expected_version, "page");
      if (source.archived_at) throw new WebsiteBuilderError("website_page_archived", "Restore the page before duplicating it.", 409);
      const rows = (await client.query(
        `SELECT name, slug, sort_order FROM website_pages WHERE company_id = $1 AND project_id = $2 FOR UPDATE`,
        [req.companyId, project.id],
      )).rows;
      if (rows.length >= MAX_PAGES_PER_PROJECT) throw new WebsiteBuilderError("website_page_limit_reached", `A project may have up to ${MAX_PAGES_PER_PROJECT} total pages.`, 409);
      const names = new Set(rows.map((row) => String(row.name).toLowerCase()));
      const slugs = new Set(rows.filter((row) => row.slug).map((row) => String(row.slug).toLowerCase()));
      let suffix = 1;
      let name;
      let slug;
      do {
        const nameSuffix = ` Copy${suffix === 1 ? "" : ` ${suffix}`}`;
        name = `${String(source.name).slice(0, PAGE_NAME_LIMIT - nameSuffix.length).trimEnd()}${nameSuffix}`;
        const base = source.slug === "/" ? "/home" : source.slug;
        const slugSuffix = `-copy${suffix === 1 ? "" : `-${suffix}`}`;
        slug = `${String(base).slice(0, PAGE_SLUG_LIMIT - slugSuffix.length).replace(/-+$/, "")}${slugSuffix}`;
        suffix += 1;
      } while (names.has(name.toLowerCase()) || slugs.has(slug.toLowerCase()));
      await client.query(
        `UPDATE website_pages SET sort_order = sort_order + 1 WHERE company_id = $1 AND project_id = $2 AND archived_at IS NULL AND sort_order > $3`,
        [req.companyId, project.id, exactNumber(source.sort_order)],
      );
      const chrome = websitePageChromePayload(source.chrome);
      const page = (await client.query(
        `INSERT INTO website_pages (id, company_id, project_id, name, slug, page_kind, is_home, sort_order, content, seo, chrome, created_by, updated_by)
         VALUES ($1,$2,$3,$4,$5,$6,false,$7,$8::jsonb,$9::jsonb,$10::jsonb,$11,$11) RETURNING *`,
        [randomUUID(), req.companyId, project.id, name, slug, source.page_kind, exactNumber(source.sort_order) + 1, JSON.stringify(cloneWebsiteContentWithFreshIds(source.content)), JSON.stringify(websitePageSeoPayload({ ...source.seo, title: name })), JSON.stringify({ ...chrome, header_content: cloneWebsiteContentWithFreshIds(chrome.header_content), footer_content: cloneWebsiteContentWithFreshIds(chrome.footer_content) }), req.userId],
      )).rows[0];
      const updatedProject = (await client.query(
        `UPDATE website_projects SET version = version + 1, updated_at = now(), updated_by = $3 WHERE id = $1 AND company_id = $2 RETURNING *`,
        [project.id, req.companyId, req.userId],
      )).rows[0];
      await appendAudit(client, { companyId: req.companyId, projectId: project.id, pageId: page.id, actorUserId: req.userId, action: "page.duplicated", before: { source_page_id: String(source.id) }, after: pageAuditSnapshot(page) });
      await client.query("COMMIT");
      res.status(201).json({ project: projectPayload(updatedProject), page: pagePayload(page) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendWebsiteBuilderError(res, error, "website_page_duplicate_failed");
    } finally { client.release(); }
  });

  app.post("/api/website-builder/projects/:projectId/pages/:pageId/reorder", authRequired, requireManage, async (req, res) => {
    let input;
    try {
      input = normalizeWebsitePageReorder(req.body);
      requireCompany(req);
    } catch (error) {
      return sendWebsiteBuilderError(res, error, "website_page_reorder_failed");
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const project = await loadProject(client, req.companyId, req.params.projectId, true);
      if (project.lifecycle_status === "archived") {
        throw new WebsiteBuilderError(
          "website_project_archived",
          "Restore the project before reordering pages.",
          409,
        );
      }
      assertVersion(project, input.expected_project_version, "project");
      const pages = (await client.query(
        `SELECT * FROM website_pages
          WHERE company_id = $1 AND project_id = $2 AND archived_at IS NULL
          ORDER BY sort_order ASC, created_at ASC
          FOR UPDATE`,
        [req.companyId, project.id],
      )).rows;
      const currentIndex = pages.findIndex((page) => String(page.id) === req.params.pageId);
      if (currentIndex < 0) {
        throw new WebsiteBuilderError(
          "website_page_not_found",
          "Active website page was not found.",
          404,
        );
      }
      const targetIndex = Math.min(input.target_index, pages.length - 1);
      if (targetIndex === currentIndex) {
        await client.query("COMMIT");
        return res.json({ project: projectPayload(project), pages: pages.map(pagePayload) });
      }
      const [moved] = pages.splice(currentIndex, 1);
      pages.splice(targetIndex, 0, moved);
      for (let index = 0; index < pages.length; index += 1) {
        if (exactNumber(pages[index].sort_order) === index) continue;
        pages[index] = (await client.query(
          `UPDATE website_pages
              SET sort_order = $4, version = version + 1, updated_at = now(), updated_by = $5
            WHERE id = $1 AND project_id = $2 AND company_id = $3
            RETURNING *`,
          [pages[index].id, project.id, req.companyId, index, req.userId],
        )).rows[0];
      }
      const updatedProject = (await client.query(
        `UPDATE website_projects
            SET version = version + 1, updated_at = now(), updated_by = $3
          WHERE id = $1 AND company_id = $2
          RETURNING *`,
        [project.id, req.companyId, req.userId],
      )).rows[0];
      await appendAudit(client, {
        companyId: req.companyId,
        projectId: project.id,
        pageId: moved.id,
        actorUserId: req.userId,
        action: "page.reordered",
        before: { index: currentIndex },
        after: { index: targetIndex },
      });
      await client.query("COMMIT");
      res.json({ project: projectPayload(updatedProject), pages: pages.map(pagePayload) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendWebsiteBuilderError(res, error, "website_page_reorder_failed");
    } finally {
      client.release();
    }
  });
}
