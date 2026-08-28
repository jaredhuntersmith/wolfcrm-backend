import { createHash } from "node:crypto";

export const CONTACT_IMPORT_LIMITS = Object.freeze({
  maximumBytes: 1_000_000,
  maximumRows: 500,
  maximumPreviewRows: 20,
  maximumCellCharacters: 10_000,
  maximumTags: 50,
  maximumLeadInfo: 25
});

export const CONTACT_IMPORT_HEADERS = Object.freeze([
  "Name",
  "Phone",
  "Email",
  "Address",
  "Value",
  "Latitude",
  "Longitude",
  "Tags",
  "Job Type",
  "Source",
  "Lead Submitted At",
  "Contact Created At",
  "Notes",
  "Lead Info"
]);

const HEADER_ALIASES = Object.freeze({
  Name: ["name", "full name", "contact", "contact name", "customer", "customer name", "company", "business name"],
  Phone: ["phone", "phone number", "mobile", "cell", "cell phone", "telephone"],
  Email: ["email", "email address", "e mail"],
  Address: ["address", "street address", "full address", "service address"],
  Value: ["value", "contact value", "value cents", "estimate value"],
  Latitude: ["latitude", "lat"],
  Longitude: ["longitude", "lng", "lon", "long"],
  Tags: ["tags", "tag", "labels", "status"],
  "Job Type": ["job type", "service", "service type", "project type"],
  Source: ["source", "lead source", "origin"],
  "Lead Submitted At": ["lead submitted at", "submitted at", "lead date", "inquiry date"],
  "Contact Created At": ["contact created at", "created at", "contact age", "age of contact", "became contact at", "customer since", "contact since"],
  Notes: ["notes", "note", "internal notes", "description"],
  "Lead Info": ["lead info", "lead information", "extra info", "details", "universal", "universal fields"]
});

export class ContactImportError extends Error {
  constructor(code, message, status = 400, details = {}) {
    super(message);
    this.name = "ContactImportError";
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

function normalizeHeader(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase()
    .replaceAll("_", " ")
    .replaceAll("-", " ")
    .split(/\s+/)
    .filter(Boolean)
    .join(" ");
}

function canonicalFileName(value) {
  const trimmed = String(value ?? "contacts.csv").trim().slice(0, 180);
  return trimmed || "contacts.csv";
}

function normalizedCSVText(value) {
  if (typeof value !== "string") {
    throw new ContactImportError("csv_required", "Choose a CSV file before previewing the import.");
  }
  if (Buffer.byteLength(value, "utf8") > CONTACT_IMPORT_LIMITS.maximumBytes) {
    throw new ContactImportError(
      "csv_too_large",
      `CSV files are limited to ${CONTACT_IMPORT_LIMITS.maximumBytes.toLocaleString("en-US")} bytes.`,
      413
    );
  }
  return value.replace(/^\uFEFF/, "").replaceAll("\r\n", "\n").replaceAll("\r", "\n");
}

export function contactImportFingerprint(csvText) {
  return createHash("sha256").update(normalizedCSVText(csvText), "utf8").digest("hex");
}

export function contactImportContactIsUnchanged(importedUpdatedAt, currentUpdatedAt) {
  const imported = importedUpdatedAt ? new Date(importedUpdatedAt).getTime() : Number.NaN;
  const current = currentUpdatedAt ? new Date(currentUpdatedAt).getTime() : Number.NaN;
  return Number.isFinite(imported) && imported === current;
}

export function parseContactCSV(csvText) {
  const text = normalizedCSVText(csvText);
  const rows = [];
  let row = [];
  let field = "";
  let quoted = false;

  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quoted) {
      if (character === '"') {
        if (text[index + 1] === '"') {
          field += '"';
          index += 1;
        } else {
          quoted = false;
        }
      } else {
        field += character;
      }
      continue;
    }
    if (character === '"' && field.length === 0) {
      quoted = true;
    } else if (character === ",") {
      row.push(field);
      field = "";
    } else if (character === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else {
      field += character;
    }
  }

  if (quoted) {
    throw new ContactImportError("csv_malformed", "The CSV ends inside a quoted field.");
  }
  if (field.length || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows.filter((columns) => columns.some((column) => String(column).trim().length > 0));
}

function headerMap(row) {
  const aliases = new Set(Object.values(HEADER_ALIASES).flat());
  const map = new Map();
  row.forEach((value, index) => {
    const key = normalizeHeader(value);
    if (aliases.has(key)) map.set(key, index);
  });
  return map.size ? map : null;
}

function valueFrom(columns, map, header) {
  for (const alias of HEADER_ALIASES[header]) {
    const index = map.get(alias);
    if (index != null && index < columns.length) return String(columns[index] ?? "").trim();
  }
  return "";
}

function boundedCell(value, rowNumber, field) {
  const text = String(value ?? "").trim();
  if (text.length > CONTACT_IMPORT_LIMITS.maximumCellCharacters) {
    throw new ContactImportError(
      "csv_cell_too_large",
      `Row ${rowNumber} has more than ${CONTACT_IMPORT_LIMITS.maximumCellCharacters.toLocaleString("en-US")} characters in ${field}.`,
      400,
      { row_number: rowNumber, field }
    );
  }
  return text;
}

function parseTags(value) {
  const tags = String(value ?? "")
    .split(/[;|,]/)
    .map((tag) => tag.trim().toLowerCase())
    .filter(Boolean);
  return [...new Set(tags)].slice(0, CONTACT_IMPORT_LIMITS.maximumTags);
}

function parseLeadInfo(value) {
  const leadInfo = String(value ?? "")
    .replaceAll("\r\n", "\n")
    .replaceAll("\r", "\n")
    .split(/[|\n]/)
    .map((item) => item.trim())
    .filter(Boolean);
  return leadInfo.slice(0, CONTACT_IMPORT_LIMITS.maximumLeadInfo);
}

function parseMoney(value, isCents, warnings) {
  const cleaned = String(value ?? "").replaceAll("$", "").replaceAll(",", "").trim();
  if (!cleaned) return null;
  const amount = Number(cleaned);
  if (!Number.isFinite(amount)) {
    warnings.push("Value was not a valid number and will be left blank.");
    return null;
  }
  return Math.round(isCents ? amount : amount * 100);
}

function parseCoordinate(value, label, warnings) {
  const cleaned = String(value ?? "").replaceAll(",", "").trim();
  if (!cleaned) return null;
  const coordinate = Number(cleaned);
  const validRange = label === "Latitude"
    ? coordinate >= -90 && coordinate <= 90
    : coordinate >= -180 && coordinate <= 180;
  if (!Number.isFinite(coordinate) || !validRange) {
    warnings.push(`${label} was invalid and will be left blank.`);
    return null;
  }
  return coordinate;
}

function validUTCDateParts(year, month, day) {
  if (![year, month, day].every(Number.isInteger) || month < 1 || month > 12 || day < 1 || day > 31) return null;
  const date = new Date(Date.UTC(year, month - 1, day));
  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day ? date : null;
}

function parseDate(value, label, warnings) {
  const text = String(value ?? "").trim();
  if (!text) return null;

  const plain = text.match(/^(\d{4})[-/](\d{1,2})[-/](\d{1,2})$/);
  const us = text.match(/^(\d{1,2})\/(\d{1,2})\/(\d{2}|\d{4})$/);
  let date;
  if (plain) {
    date = validUTCDateParts(Number(plain[1]), Number(plain[2]), Number(plain[3]));
  } else if (us) {
    const year = Number(us[3]) < 100 ? 2000 + Number(us[3]) : Number(us[3]);
    date = validUTCDateParts(year, Number(us[1]), Number(us[2]));
  } else {
    const isoDate = text.match(/^(\d{4})-(\d{2})-(\d{2})T/);
    date = isoDate && !validUTCDateParts(Number(isoDate[1]), Number(isoDate[2]), Number(isoDate[3])) ? null : new Date(text);
  }
  if (!date || Number.isNaN(date.getTime())) {
    warnings.push(`${label} was invalid and will be left blank.`);
    return null;
  }
  return date.toISOString();
}

function normalizedHeaderRow(columns, map, rowNumber) {
  const warnings = [];
  const get = (header) => boundedCell(valueFrom(columns, map, header), rowNumber, header);
  const createdAt = parseDate(get("Contact Created At"), "Contact Created At", warnings);
  const submittedAt = parseDate(get("Lead Submitted At"), "Lead Submitted At", warnings);
  const tags = parseTags(get("Tags"));
  const notes = get("Notes");
  if (notes) warnings.push("Notes are iPhone-local and will not be imported into shared CRM history.");
  const leadInfo = parseLeadInfo(get("Lead Info"));
  return {
    row_number: rowNumber,
    contact: {
      name: get("Name") || "Unnamed",
      phone: get("Phone") || null,
      email: get("Email") || null,
      address: get("Address") || null,
      value_cents: parseMoney(get("Value"), map.has("value cents"), warnings),
      lat: parseCoordinate(get("Latitude"), "Latitude", warnings),
      lng: parseCoordinate(get("Longitude"), "Longitude", warnings),
      tags: tags.length ? tags : ["lead"],
      job_type: get("Job Type") || null,
      source: get("Source") || "csv",
      lead_submitted_at: submittedAt,
      created_at: createdAt || submittedAt,
      lead_info: leadInfo.length ? leadInfo : null
    },
    warnings,
    notes_excluded: Boolean(notes)
  };
}

function normalizedLegacyRow(columns, rowNumber) {
  const values = [...columns.slice(0, 10)];
  while (values.length < 10) values.push("");
  values.forEach((value, index) => boundedCell(value, rowNumber, `column ${index + 1}`));
  const leadInfo = values.slice(5, 10).map((value) => String(value).trim()).filter(Boolean);
  return {
    row_number: rowNumber,
    contact: {
      name: String(values[0]).trim() || "Unnamed",
      phone: String(values[1]).trim() || null,
      email: String(values[3]).trim() || null,
      address: String(values[2]).trim() || null,
      value_cents: null,
      lat: null,
      lng: null,
      tags: ["lead"],
      job_type: String(values[4]).trim() || null,
      source: "csv",
      lead_submitted_at: null,
      created_at: null,
      lead_info: leadInfo.length ? leadInfo.slice(0, CONTACT_IMPORT_LIMITS.maximumLeadInfo) : null
    },
    warnings: [],
    notes_excluded: false
  };
}

export function prepareContactImport(csvText, { fileName = "contacts.csv" } = {}) {
  const normalizedText = normalizedCSVText(csvText);
  const parsedRows = parseContactCSV(normalizedText);
  if (!parsedRows.length) {
    throw new ContactImportError("csv_empty", "The CSV does not contain any contact rows.");
  }
  const map = headerMap(parsedRows[0]);
  const sourceRows = map ? parsedRows.slice(1) : parsedRows;
  if (!sourceRows.length) {
    throw new ContactImportError("csv_empty", "The CSV has a header but no contact rows.");
  }
  if (sourceRows.length > CONTACT_IMPORT_LIMITS.maximumRows) {
    throw new ContactImportError(
      "csv_too_many_rows",
      `Import at most ${CONTACT_IMPORT_LIMITS.maximumRows} contacts at a time.`,
      413,
      { row_count: sourceRows.length }
    );
  }

  const rows = sourceRows.map((columns, index) => map
    ? normalizedHeaderRow(columns, map, index + 2)
    : normalizedLegacyRow(columns, index + 1));
  const notesExcluded = rows.filter((row) => row.notes_excluded).length;
  const warningCount = rows.reduce((total, row) => total + row.warnings.length, 0);
  return {
    file_name: canonicalFileName(fileName),
    fingerprint: createHash("sha256").update(normalizedText, "utf8").digest("hex"),
    format: map ? "header" : "legacy",
    total_rows: rows.length,
    warning_count: warningCount,
    notes_excluded_count: notesExcluded,
    rows,
    preview_rows: rows.slice(0, CONTACT_IMPORT_LIMITS.maximumPreviewRows).map((row) => ({
      row_number: row.row_number,
      name: row.contact.name,
      phone: row.contact.phone,
      email: row.contact.email,
      source: row.contact.source,
      warnings: row.warnings
    }))
  };
}
