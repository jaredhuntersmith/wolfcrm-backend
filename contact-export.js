export const CONTACT_EXPORT_HEADERS = Object.freeze([
  "Contact ID", "Name", "Phone", "Email", "Address", "Value", "Latitude", "Longitude",
  "Tags", "Job Type", "Lead Info 1", "Lead Info 2", "Lead Info 3", "Lead Info 4", "Lead Info 5",
  "Lead Info", "Notes", "Lead Submitted At", "Created At", "Updated At",
  "Quote Count", "Quote Total", "Quotes Made",
  "Completed Job Count", "Completed Job Total", "Jobs Completed"
]);

export function defaultContactExportFilename(date = new Date()) {
  const parsed = date instanceof Date ? date : new Date(date);
  const day = Number.isFinite(parsed.getTime()) ? parsed.toISOString().slice(0, 10) : "export";
  return `wolfcrm-contacts-${day}.csv`;
}

export function escapeContactCSVCell(value) {
  const normalized = String(value ?? "").replaceAll("\r\n", "\n").replaceAll("\r", "\n");
  // Customer-entered values can otherwise become executable spreadsheet formulas.
  const spreadsheetFormula = /^\s*[=+\-@]/.test(normalized) || normalized.startsWith("\t");
  const knownNumeric = /^-?\d+(?:\.\d+)?$/.test(normalized);
  const internationalPhone = /^\+\d[\d\s().-]*$/.test(normalized);
  const safe = spreadsheetFormula && !knownNumeric && !internationalPhone
    ? `'${normalized}`
    : normalized;
  return /[,"\n]/.test(safe) ? `"${safe.replaceAll('"', '""')}"` : safe;
}

export function buildContactExportRows({ contacts = [], quotes = [], completedJobs = [] } = {}) {
  const contactIDs = new Set(contacts.map((contact) => String(contact.id)));
  const quotesByContact = groupByContact(quotes, contactIDs);
  const jobsByContact = groupByContact(completedJobs, contactIDs);
  const rows = [CONTACT_EXPORT_HEADERS];

  for (const contact of [...contacts].sort(contactExportSort)) {
    const contactQuotes = [...(quotesByContact.get(String(contact.id)) || [])].sort(quoteExportSort);
    const contactJobs = [...(jobsByContact.get(String(contact.id)) || [])].sort(jobExportSort);
    const quoteTotal = contactQuotes.reduce((sum, quote) => sum + integerOrZero(quote.total_cents), 0);
    const jobTotal = contactJobs.reduce((sum, job) => sum + integerOrZero(job.price_cents ?? job.priceCents), 0);
    const leadInfo = effectiveLeadInfo(contact).filter((value) => value.trim()).join(" | ");

    rows.push([
      text(contact.id),
      text(contact.name),
      text(contact.phone),
      text(contact.email),
      text(contact.address),
      moneyString(contact.value_cents),
      nullableNumberString(contact.lat),
      nullableNumberString(contact.lng),
      normalizeTags(contact.tags).join("; "),
      text(contact.job_type),
      text(contact.u1),
      text(contact.u2),
      text(contact.u3),
      text(contact.u4),
      text(contact.u5),
      leadInfo,
      "", // iPhone notes are device-local and must not be presented as shared server data.
      exportDateString(contact.lead_submitted_at),
      exportDateString(contact.created_at),
      exportDateString(contact.updated_at),
      String(contactQuotes.length),
      moneyString(quoteTotal),
      contactQuotes.map(quoteExportSummary).join(" | "),
      String(contactJobs.length),
      moneyString(jobTotal),
      contactJobs.map(jobExportSummary).join(" | ")
    ]);
  }

  return rows;
}

export function buildContactExportCSV(data) {
  return `${buildContactExportRows(data).map((row) => row.map(escapeContactCSVCell).join(",")).join("\n")}\n`;
}

function groupByContact(records, contactIDs) {
  const grouped = new Map();
  for (const record of records) {
    const contactID = record?.contact_id == null ? "" : String(record.contact_id);
    if (!contactIDs.has(contactID)) continue;
    const existing = grouped.get(contactID) || [];
    existing.push(record);
    grouped.set(contactID, existing);
  }
  return grouped;
}

function effectiveLeadInfo(contact) {
  const raw = Array.isArray(contact.lead_info)
    ? contact.lead_info
    : [contact.u1, contact.u2, contact.u3, contact.u4, contact.u5];
  return raw.map(text);
}

function normalizeTags(value) {
  if (Array.isArray(value)) return value.flatMap(normalizeTags);
  if (value == null) return [];
  let raw = String(value).trim();
  if (raw.startsWith("{") && raw.endsWith("}")) raw = raw.slice(1, -1).replaceAll('"', "");
  return raw.split(/[;,]/).map((tag) => tag.trim()).filter(Boolean);
}

function quoteExportSummary(quote) {
  const title = text(quote.title).trim() || "Quote";
  const status = text(quote.status).trim();
  const items = array(quote.line_items)
    .map((item) => `${text(item?.name)} x${numberString(item?.qty)} ${moneyString(item?.price_cents)}`)
    .join("; ");
  return compact([
    title,
    status,
    exportDateString(quote.created_at),
    moneyString(integerOrZero(quote.total_cents)),
    items,
    text(quote.notes).trim()
  ]).join(" - ");
}

function jobExportSummary(job) {
  const serviceItems = array(job.service_items ?? job.serviceItems);
  const services = serviceItems.length
    ? serviceItems.map((item) => `${text(item?.name)}${item?.price_cents != null || item?.priceCents != null ? ` ${moneyString(item.price_cents ?? item.priceCents)}` : ""}`).join("; ")
    : array(job.services).map(text).join("; ");
  return compact([
    text(job.title),
    exportDateString(job.start_at ?? job.start),
    job.finished_at ?? job.finishedAt ? `Finished ${exportDateString(job.finished_at ?? job.finishedAt)}` : "",
    job.price_cents != null || job.priceCents != null ? moneyString(job.price_cents ?? job.priceCents) : "",
    services,
    text(job.notes).trim()
  ]).join(" - ");
}

function contactExportSort(left, right) {
  const comparison = text(left.name).localeCompare(text(right.name), "en", { sensitivity: "base" });
  return comparison || text(left.id).localeCompare(text(right.id));
}

function quoteExportSort(left, right) {
  return dateValue(left.created_at ?? left.updated_at) - dateValue(right.created_at ?? right.updated_at);
}

function jobExportSort(left, right) {
  return dateValue(left.start_at ?? left.start) - dateValue(right.start_at ?? right.start);
}

function exportDateString(value) {
  if (value == null || value === "") return "";
  const parsed = value instanceof Date ? value : new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed.toISOString().replace(/\.\d{3}Z$/, "Z") : "";
}

function moneyString(cents) {
  if (cents == null || cents === "") return "";
  const numeric = Number(cents);
  return Number.isFinite(numeric) ? (numeric / 100).toFixed(2) : "";
}

function nullableNumberString(value) {
  if (value == null || value === "") return "";
  const numeric = Number(value);
  return Number.isFinite(numeric) ? String(numeric) : "";
}

function numberString(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return "0";
  return Number.isInteger(numeric) ? String(numeric) : String(numeric);
}

function integerOrZero(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? Math.trunc(numeric) : 0;
}

function text(value) {
  return value == null ? "" : String(value);
}

function array(value) {
  return Array.isArray(value) ? value : [];
}

function compact(values) {
  return values.filter((value) => value !== "");
}
