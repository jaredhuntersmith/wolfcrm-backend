// Pure, retention-first mapping. Never return raw provider responses or ignored values.
export class FacebookLeadError extends Error {
  constructor(code, status = 400, retryable = false, retryAfter = 0) {
    super(code);
    this.code = code;
    this.status = status;
    this.retryable = retryable;
    this.retryAfter = retryAfter;
  }
}
export const fail = (code, status = 400) => {
  throw new FacebookLeadError(code, status);
};
export const DESTINATIONS = [
  ...[
    "name",
    "email",
    "phone",
    "address",
    "value_cents",
    "lat",
    "lng",
    "tags",
    "job_type",
    "source",
    "lead_submitted_at",
  ].map((id) => ({
    id,
    label:
      {
        job_type: "Job type",
        lead_submitted_at: "Lead submitted at",
        value_cents: "Contact value (cents)",
        lat: "Latitude",
        lng: "Longitude",
        tags: "Tags",
      }[id] || id.replace(/^./, (c) => c.toUpperCase()),
    type: ["value_cents", "lat", "lng"].includes(id)
      ? "number"
      : id === "tags"
        ? "array"
        : id === "lead_submitted_at"
          ? "datetime"
          : ["email", "phone"].includes(id)
            ? id
            : "text",
  })),
  { id: "lead_info", label: "Lead Info — append labeled Q&A", type: "text" },
  ...Array.from({ length: 25 }, (_, i) => ({
    id: `lead_info:${i + 1}`,
    label: `Lead Info ${i + 1}${i < 5 ? " (legacy custom field)" : ""}`,
    type: "text",
  })),
  { id: "ignore", label: "Ignore — do not retain", type: "none" },
];
const allowed = new Set(DESTINATIONS.map((d) => d.id));
export const METADATA = [
  "id",
  "page_id",
  "form_id",
  "page_name",
  "form_name",
  "created_time",
  "ad_id",
  "ad_name",
  "adset_id",
  "adset_name",
  "campaign_id",
  "campaign_name",
  "is_organic",
  "platform",
  "partner_name",
  "retailer_item_id",
  "home_listing",
  "vehicle",
  "post",
  "post_submission_check_result",
].map((key) => ({
  key: `meta:${key}`,
  label: key.replaceAll("_", " "),
  type: key === "created_time" ? "datetime" : "text",
}));
export const DEFAULT_SETTINGS = {
  unknown_policy: "lead_info",
  overwrite: false,
  mappings: {},
};
const names = ["full_name", "first_name", "last_name"];
const addresses = [
  "street_address",
  "city",
  "state",
  "province",
  "region",
  "zip_code",
  "zip",
  "postal_code",
  "country",
];
export function autoMapping(source, unknownPolicy = "lead_info") {
  const key = source.key.replace(/^field:/, "");
  if (source.key === "meta:created_time")
    return { destination: "lead_submitted_at", origin: "automatic" };
  if (source.key.startsWith("meta:"))
    return { destination: "ignore", origin: "automatic" };
  // A discard policy applies to newly encountered custom questions, not known standard fields.
  if (source.key.startsWith("field:")) {
    if (names.includes(key))
      return { destination: "name", rule: "name", origin: "automatic" };
    if (key === "email") return { destination: "email", origin: "automatic" };
    if (["phone_number", "phone"].includes(key))
      return {
        destination: "phone",
        origin: "automatic",
        rule: "priority",
        priority: key === "phone_number" ? 0 : 1,
      };
    if (addresses.includes(key) || key === "address")
      return { destination: "address", rule: "address", origin: "automatic" };
  }
  return {
    destination: unknownPolicy === "ignore" ? "ignore" : "lead_info",
    origin: "automatic",
  };
}
export function effectiveMapping(source, settings, overrides = {}) {
  return (
    overrides[source.key] ||
    settings.mappings?.[source.key] ||
    autoMapping(source, settings.unknown_policy)
  );
}
export function validateMappings(
  mappings,
  sources,
  settings = DEFAULT_SETTINGS,
) {
  if (
    !mappings ||
    typeof mappings !== "object" ||
    Array.isArray(mappings) ||
    Object.keys(mappings).length > 1000
  )
    fail("invalid_mappings");
  const clean = {};
  for (const [key, row] of Object.entries(mappings)) {
    if (
      !/^(field|consent|meta):.{1,250}$/u.test(key) ||
      !row ||
      !allowed.has(row.destination)
    )
      fail("invalid_mapping_destination");
    if (
      row.rule &&
      !["combine", "priority", "name", "address"].includes(row.rule)
    )
      fail("invalid_combination_rule");
    if (
      row.rule === "name" &&
      (row.destination !== "name" || !names.includes(key.slice(6)))
    )
      fail("invalid_name_component");
    if (
      row.rule === "address" &&
      (row.destination !== "address" ||
        ![...addresses, "address"].includes(key.slice(6)))
    )
      fail("invalid_address_component");
    if (
      row.rule === "combine" &&
      [
        "email",
        "phone",
        "lead_submitted_at",
        "value_cents",
        "lat",
        "lng",
      ].includes(row.destination)
    )
      fail("scalar_type_requires_priority");
    if (
      row.rule === "priority" &&
      (!Number.isInteger(row.priority) || Math.abs(row.priority) > 10000)
    )
      fail("invalid_mapping_priority");
    clean[key] = {
      destination: row.destination,
      origin: row.origin === "automatic" ? "automatic" : "manual",
      ...(row.rule ? { rule: row.rule } : {}),
      ...(row.rule === "priority" ? { priority: row.priority } : {}),
    };
  }
  const groups = new Map();
  for (const source of sources) {
    const row = effectiveMapping(source, settings, clean);
    if (row.destination === "ignore" || row.destination.startsWith("lead_info"))
      continue;
    const group = groups.get(row.destination) || [];
    group.push(row);
    groups.set(row.destination, group);
  }
  for (const group of groups.values())
    if (group.length > 1) {
      const rule = group[0].rule;
      if (!rule || !group.every((row) => row.rule === rule))
        fail("competing_mappings_require_rule");
      if (
        rule === "priority" &&
        new Set(group.map((row) => row.priority)).size !== group.length
      )
        fail("competing_mappings_require_unique_priorities");
    }
  return clean;
}
export function definitionSources(questions = [], legalContent) {
  const fields = (Array.isArray(questions) ? questions : []).flatMap((q) => [
    q,
    ...(q.dependent_conditional_questions || []).map((child) => ({
      key: child.field_key,
      label: child.name,
      type: child.input_type,
    })),
  ]);
  const sources = fields
    .filter((q) => typeof q.key === "string" && q.key.length <= 250)
    .map((q) => ({
      key: `field:${q.key}`,
      label: String(q.label || q.key),
      type: String(q.type || "text"),
      review: false,
    }));
  for (const checkbox of legalContent?.custom_disclaimer?.checkboxes || []) {
    if (
      typeof checkbox.key !== "string" ||
      !checkbox.key ||
      checkbox.key.length > 250
    )
      continue;
    sources.push({
      key: `consent:${checkbox.key}`,
      label: String(checkbox.text || checkbox.key),
      type: "boolean",
      review: false,
    });
  }
  return [...new Map(sources.map((source) => [source.key, source])).values()];
}
function textValue(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}
export function leadSources(lead, form) {
  const defs = new Map((form.sources || []).map((s) => [s.key, s]));
  const entries = [];
  for (const field of Array.isArray(lead.field_data) ? lead.field_data : []) {
    if (typeof field.name !== "string" || field.name.length > 250)
      fail("invalid_source_key");
    const key = `field:${field.name}`;
    entries.push({
      ...defs.get(key),
      key,
      label: defs.get(key)?.label || field.name,
      type: defs.get(key)?.type || "text",
      review: !defs.has(key),
      values: Array.isArray(field.values)
        ? field.values.map(textValue)
        : [textValue(field.values)],
    });
  }
  for (const consent of Array.isArray(lead.custom_disclaimer_responses)
    ? lead.custom_disclaimer_responses
    : []) {
    const key = `consent:${String(consent.checkbox_key)}`;
    entries.push({
      key,
      label: defs.get(key)?.label || `Consent: ${consent.checkbox_key}`,
      type: "boolean",
      review: !defs.has(key),
      values: [
        consent.is_checked === ""
          ? "Not checked (Meta returned an empty checkbox response)"
          : textValue(consent.is_checked),
      ],
    });
  }
  const metadata = {
    ...lead,
    page_id: form.page_id,
    form_id: form.form_id,
    page_name: form.page_name,
    form_name: form.name,
  };
  for (const field of METADATA)
    if (metadata[field.key.slice(5)] !== undefined)
      entries.push({
        ...field,
        values: [textValue(metadata[field.key.slice(5)])],
        review: false,
      });
  return entries;
}
export function mapLead(lead, form, settings = DEFAULT_SETTINGS) {
  const contact = {},
    entries = [],
    ignored = [],
    issues = [],
    discovered = [],
    groups = new Map(),
    rows = [];
  const addQA = (s, destination = "lead_info") =>
    entries.push({
      destination,
      key: s.key,
      label: s.label,
      value: s.values.join("\n"),
    });
  for (const source of leadSources(lead, form)) {
    const mapping = effectiveMapping(source, settings, form.mappings || {});
    // Drop values before constructing any output/diagnostic/discovery structure.
    if (mapping.destination === "ignore") {
      if (source.review)
        discovered.push({
          key: source.key,
          label: source.label,
          type: source.type,
          review: true,
        });
      ignored.push(source.key);
      rows.push({
        key: source.key,
        label: source.label,
        mapping,
        ignored: true,
      });
      continue;
    }
    if (source.review)
      discovered.push({
        key: source.key,
        label: source.label,
        type: source.type,
        review: true,
      });
    const values = source.values.filter((v) => v !== "");
    if (!values.length) continue;
    const item = { ...source, values, mapping };
    rows.push({
      key: source.key,
      label: source.label,
      mapping,
      example: values.join("\n"),
    });
    if (!allowed.has(mapping.destination)) {
      issues.push({
        key: source.key,
        code: "destination_unavailable_saved_to_lead_info",
      });
      addQA(item);
      continue;
    }
    if (mapping.destination.startsWith("lead_info")) {
      addQA(item, mapping.destination);
      continue;
    }
    const group = groups.get(mapping.destination) || [];
    group.push(item);
    groups.set(mapping.destination, group);
  }
  for (const [destination, group] of groups) {
    let value,
      selected = group;
    const rule = group[0].mapping.rule;
    if (
      group.length > 1 &&
      (!rule || !group.every((s) => s.mapping.rule === rule))
    ) {
      group.forEach((s) => {
        addQA(s);
        issues.push({
          key: s.key,
          code: "competing_mappings_saved_to_lead_info",
        });
      });
      continue;
    }
    if (rule === "name" || rule === "address") {
      const ordered = rule === "name" ? names : ["address", ...addresses];
      selected = [...group].sort(
        (a, b) =>
          ordered.indexOf(a.key.slice(6)) - ordered.indexOf(b.key.slice(6)),
      );
      if (rule === "name" && selected.some((s) => s.key === "field:full_name"))
        selected = selected.filter((s) => s.key === "field:full_name");
      value = selected
        .map((s) => s.values.join("\n"))
        .join(rule === "name" ? " " : ", ");
    } else if (rule === "priority") {
      selected = [...group]
        .sort((a, b) => a.mapping.priority - b.mapping.priority)
        .slice(0, 1);
      value = selected[0].values.join("\n");
    } else value = group.map((s) => s.values.join("\n")).join("\n");
    const invalid =
      (["value_cents", "lat", "lng"].includes(destination) &&
        (!/^-?\d+(\.\d+)?$/.test(value.trim()) ||
          !Number.isFinite(Number(value)))) ||
      (destination === "value_cents" &&
        (!Number.isInteger(Number(value)) ||
          Number(value) < 0 ||
          Number(value) > 2147483647)) ||
      (destination === "lat" && Math.abs(Number(value)) > 90) ||
      (destination === "lng" && Math.abs(Number(value)) > 180) ||
      (destination === "email" && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) ||
      (destination === "phone" &&
        (!/^\+?[\d\s().-]+$/.test(value) ||
          value.replace(/\D/g, "").length < 7 ||
          value.replace(/\D/g, "").length > 15)) ||
      (destination === "lead_submitted_at" &&
        !Number.isFinite(Date.parse(value)));
    if (invalid) {
      group.forEach((s) => {
        addQA(s);
        issues.push({
          key: s.key,
          code: "invalid_optional_value_saved_to_lead_info",
        });
      });
      continue;
    }
    contact[destination] = ["value_cents", "lat", "lng"].includes(destination)
      ? Number(value)
      : destination === "tags"
        ? selected.flatMap((s) => s.values)
        : destination === "lead_submitted_at"
          ? new Date(value).toISOString()
          : value;
    for (const s of group) if (!selected.includes(s)) addQA(s);
  }
  return { contact, entries, ignored, issues, discovered, rows };
}
export function mergeContact(existing, mapped, settings, leadID) {
  const contact = { ...(existing || {}), ...mapped.contact };
  const entries = [...mapped.entries];
  for (const [key, value] of Object.entries(mapped.contact)) {
    if (
      existing?.[key] !== null &&
      existing?.[key] !== undefined &&
      String(existing[key]).trim() &&
      !settings.overwrite
    ) {
      contact[key] = existing[key];
      // Distinguishable submission entry even when the answer matches an earlier lead.
      entries.push({
        key,
        label: key.replaceAll("_", " "),
        value: Array.isArray(value) ? JSON.stringify(value) : value,
        destination: "lead_info",
      });
    }
  }
  const boxes = existing?.lead_info
    ? [...existing.lead_info]
    : existing
      ? Array.from({ length: 5 }, (_, i) => existing[`u${i + 1}`] || "")
      : [];
  for (const e of entries) {
    let index = e.destination.includes(":")
      ? Number(e.destination.split(":")[1]) - 1
      : boxes.findIndex((x) => !x);
    if (index < 0) index = Math.min(boxes.length, 24);
    while (boxes.length <= index) boxes.push("");
    const text = `Facebook lead ${leadID}\n${e.label}\n${e.value}`;
    boxes[index] = boxes[index] ? `${boxes[index]}\n\n${text}` : text;
  }
  contact.name = contact.name || "Facebook lead";
  contact.lead_info = boxes;
  return contact;
}
export const normalizeEmail = (value) =>
  String(value || "")
    .trim()
    .toLowerCase();
// Matches the app's North American normalization without matching arbitrary international suffixes.
export function normalizePhone(value) {
  const d = String(value || "").replace(/\D/g, "");
  return d.length === 11 && d.startsWith("1") ? d.slice(1) : d;
}
export function dateRange(from, to) {
  const start = new Date(from),
    end = new Date(to);
  if (
    !Number.isFinite(+start) ||
    !Number.isFinite(+end) ||
    start >= end ||
    end > Date.now() + 60000 ||
    end - start > 90 * 86400000
  )
    fail("date_range_requires_past_90_days_or_less");
  return { from: start.toISOString(), to: end.toISOString() };
}
