import crypto from "node:crypto";
import { decryptAccessToken, encryptAccessToken } from "./finance-plaid-helpers.js";

export const GOOGLE_SHEETS_SCOPE = "https://www.googleapis.com/auth/drive.file";
export const GOOGLE_SHEETS_MIME = "application/vnd.google-apps.spreadsheet";
export const GOOGLE_SHEETS_CELL_LIMIT = 30000;
const OAUTH_STATE_TTL_MINUTES = 15;

function cleanString(value, maxLength = 4000) {
  return (value ?? "").toString().trim().slice(0, maxLength);
}

function nowIso() {
  return new Date().toISOString();
}

function baseURL(env = process.env) {
  return (env.PUBLIC_BACKEND_URL || env.RAILWAY_PUBLIC_DOMAIN && `https://${env.RAILWAY_PUBLIC_DOMAIN}` || "https://wolfcrm-backend-production.up.railway.app").replace(/\/+$/, "");
}

export function googleOAuthRedirectURI(env = process.env) {
  return env.GOOGLE_OAUTH_REDIRECT_URI || `${baseURL(env)}/api/integrations/google-sheets/oauth/callback`;
}

function googleClientConfig(env = process.env) {
  return {
    clientId: env.GOOGLE_OAUTH_CLIENT_ID || "",
    clientSecret: env.GOOGLE_OAUTH_CLIENT_SECRET || "",
    redirectURI: googleOAuthRedirectURI(env)
  };
}

function requireGoogleConfig(env = process.env) {
  const config = googleClientConfig(env);
  if (!config.clientId || !config.clientSecret || !config.redirectURI) {
    const error = new Error("google_sheets_not_configured");
    error.statusCode = 503;
    error.code = "google_sheets_not_configured";
    throw error;
  }
  return config;
}

function encryptRefreshToken(refreshToken, env = process.env) {
  const encrypted = encryptAccessToken(refreshToken, env);
  return {
    refresh_token_ciphertext: encrypted.access_token_ciphertext,
    refresh_token_iv: encrypted.access_token_iv,
    refresh_token_auth_tag: encrypted.access_token_auth_tag,
    token_encryption_version: encrypted.token_encryption_version
  };
}

function decryptRefreshToken(record, env = process.env) {
  return decryptAccessToken({
    access_token_ciphertext: record.refresh_token_ciphertext,
    access_token_iv: record.refresh_token_iv,
    access_token_auth_tag: record.refresh_token_auth_tag
  }, env);
}

function safeGoogleError(error) {
  const status = error?.status || error?.statusCode || error?.response?.status || 500;
  const body = error?.body || error?.responseBody || error?.response?.data || {};
  const reason = body?.error || body?.error_description || error?.code || error?.message || "google_request_failed";
  return { status, reason: cleanString(reason, 160) };
}

async function googleFetch(url, options = {}, retry = 2) {
  let attempt = 0;
  while (true) {
    const response = await fetch(url, options);
    const text = await response.text();
    const body = text ? safeJSON(text) : null;
    if (response.ok) return body;
    const retryable = response.status === 429 || response.status >= 500;
    if (!retryable || attempt >= retry) {
      const error = new Error(body?.error?.message || body?.error_description || body?.error || `google_http_${response.status}`);
      error.status = response.status;
      error.body = body;
      throw error;
    }
    const delay = Math.min(2500, 250 * Math.pow(2, attempt)) + Math.floor(Math.random() * 200);
    await new Promise((resolve) => setTimeout(resolve, delay));
    attempt += 1;
  }
}

function safeJSON(text) {
  try { return JSON.parse(text); } catch { return { raw: text }; }
}

async function exchangeAuthorizationCode(code, env = process.env) {
  const config = requireGoogleConfig(env);
  const body = new URLSearchParams({
    code,
    client_id: config.clientId,
    client_secret: config.clientSecret,
    redirect_uri: config.redirectURI,
    grant_type: "authorization_code"
  });
  return googleFetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  }, 1);
}

async function refreshAccessToken(connection, env = process.env) {
  const config = requireGoogleConfig(env);
  const refreshToken = decryptRefreshToken(connection, env);
  const body = new URLSearchParams({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    refresh_token: refreshToken,
    grant_type: "refresh_token"
  });
  return googleFetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  }, 1);
}

async function googleAPI(connection, url, options = {}, pool = null, env = process.env) {
  try {
    const token = await refreshAccessToken(connection, env);
    return await googleFetch(url, {
      ...options,
      headers: {
        Authorization: `Bearer ${token.access_token}`,
        "Content-Type": "application/json",
        ...(options.headers || {})
      }
    });
  } catch (error) {
    const status = error?.status || error?.statusCode;
    if (pool && (status === 400 || status === 401 || status === 403)) {
      await pool.query(
        `UPDATE google_sheets_connections
            SET reconnect_required = true, status = 'needs_reconnect', last_error = $2, updated_at = now()
          WHERE id = $1`,
        [connection.id, safeGoogleError(error).reason]
      );
    }
    throw error;
  }
}

async function googleAPIWithAccessToken(accessToken, url, options = {}) {
  return googleFetch(url, {
    ...options,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });
}

async function getSpreadsheetMetadata(connection, spreadsheetId, pool, env = process.env) {
  const encoded = encodeURIComponent(spreadsheetId);
  return googleAPI(connection, `https://sheets.googleapis.com/v4/spreadsheets/${encoded}?fields=spreadsheetId,properties(title),sheets(properties(sheetId,title,index,gridProperties(rowCount,columnCount)))`, {}, pool, env);
}

async function getDriveFileMetadata(connection, fileId, pool, env = process.env) {
  const encoded = encodeURIComponent(fileId);
  return googleAPI(connection, `https://www.googleapis.com/drive/v3/files/${encoded}?fields=id,name,mimeType`, {}, pool, env);
}

function a1Column(index) {
  let n = index + 1;
  let s = "";
  while (n > 0) {
    const m = (n - 1) % 26;
    s = String.fromCharCode(65 + m) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s;
}

function quoteSheetName(name) {
  return `'${String(name || "Sheet1").replace(/'/g, "''")}'`;
}

function splitLongValue(value, limit = GOOGLE_SHEETS_CELL_LIMIT) {
  const text = value == null ? "" : String(value);
  if (text.length <= limit) return [text];
  const chunks = [];
  for (let i = 0; i < text.length; i += limit) chunks.push(text.slice(i, i + limit));
  return chunks;
}

function money(cents) {
  if (cents == null || cents === "") return "";
  return `$${(Number(cents || 0) / 100).toFixed(2)}`;
}

function dateTime(value) {
  if (!value) return "";
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleString("en-US", { timeZone: "UTC", year: "numeric", month: "2-digit", day: "2-digit", hour: "numeric", minute: "2-digit" });
}

function dateOnly(value) {
  if (!value) return "";
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toISOString().slice(0, 10);
}

function tagsArray(value) {
  if (Array.isArray(value)) return value.flatMap(tagsArray);
  if (value == null) return [];
  return String(value).split(",").map((tag) => tag.trim()).filter(Boolean).sort((a, b) => a.localeCompare(b));
}

function leadInfoArray(contact) {
  if (Array.isArray(contact.lead_info)) return contact.lead_info.map((v) => cleanString(v, 5000));
  const legacy = [contact.u1, contact.u2, contact.u3, contact.u4, contact.u5].map((v) => cleanString(v, 5000)).filter(Boolean);
  return legacy;
}

function nameParts(name) {
  const parts = cleanString(name, 300).split(/\s+/).filter(Boolean);
  if (parts.length <= 1) return { first: parts[0] || "", last: "" };
  return { first: parts[0], last: parts.slice(1).join(" ") };
}

function parseAddress(address) {
  const parts = cleanString(address, 600).split(",").map((p) => p.trim()).filter(Boolean);
  const line1 = parts[0] || "";
  const city = parts.length >= 2 ? parts[parts.length - 2] : "";
  const stateZip = parts.length >= 2 ? parts[parts.length - 1] : "";
  const m = stateZip.match(/^([A-Za-z]{2})\s+(.+)$/);
  return { line1, line2: "", city, state: m ? m[1] : "", zip: m ? m[2] : "" };
}

function formatLineItems(items) {
  return (Array.isArray(items) ? items : []).map((item) => {
    const qty = Number(item.qty ?? 1);
    const unit = Number(item.price_cents ?? 0);
    const total = Math.round(qty * unit);
    const desc = item.description ? ` - ${item.description}` : "";
    return `${item.name || "Line Item"}${desc} | ${qty} x ${money(unit)} = ${money(total)}`;
  }).join("\n");
}

function formatQuotes(quotes) {
  return quotes.map((quote) => {
    const header = `Quote ${quote.id} | ${quote.status || "draft"} | ${money(quote.total_cents)} | ${dateOnly(quote.created_at)}`;
    const meta = [
      quote.title ? `Title: ${quote.title}` : "",
      quote.expires_at ? `Expires: ${dateOnly(quote.expires_at)}` : "",
      quote.accepted_at ? `Accepted: ${dateTime(quote.accepted_at)}` : "",
      quote.declined_at ? `Declined: ${dateTime(quote.declined_at)}` : "",
      quote.notes ? `Notes: ${quote.notes}` : ""
    ].filter(Boolean).join("\n");
    return [header, formatLineItems(quote.line_items), meta].filter(Boolean).join("\n");
  }).join("\n\n");
}

function formatJobs(jobs) {
  return jobs.map((job) => {
    const assigned = [...new Set([...(job.sales_user_names || []), ...(job.worker_user_names || [])].filter(Boolean))].join(", ");
    const services = (Array.isArray(job.service_items) ? job.service_items : []).map((item) => `${item.name || "Service"}${item.priceCents != null || item.price_cents != null ? ` ${money(item.priceCents ?? item.price_cents)}` : ""}`).join("; ");
    return [
      `${job.id} | ${job.finished_at ? "Completed" : "Scheduled"} | ${dateTime(job.start_at)}-${dateTime(job.end_at)}`,
      job.finished_at ? `Completed: ${dateTime(job.finished_at)}` : "",
      job.title ? `Title: ${job.title}` : "",
      job.price_cents != null ? `Price: ${money(job.price_cents)}` : "",
      assigned ? `Assigned: ${assigned}` : "",
      services ? `Services: ${services}` : "",
      job.notes ? `Notes: ${job.notes}` : ""
    ].filter(Boolean).join("\n");
  }).join("\n\n");
}

function formatSms(messages) {
  return messages.map((m) => [
    `${dateTime(m.created_at)} | ${String(m.direction || "").toUpperCase()} | ${m.message_status || ""}`.trim(),
    m.direction === "inbound" ? `From: ${m.from_number}` : `To: ${m.to_number}`,
    m.body || ""
  ].filter(Boolean).join("\n")).join("\n\n");
}

function formatCalls(calls) {
  return calls.map((c) => [
    `${dateTime(c.started_at)} | ${String(c.direction || "").toUpperCase()} | ${c.status || ""}`.trim(),
    c.from_number || c.to_number ? `Phone: ${c.direction === "inbound" ? c.from_number : c.to_number}` : "",
    c.answered_at ? `Answered: ${dateTime(c.answered_at)}` : "",
    c.ended_at ? `Ended: ${dateTime(c.ended_at)}` : "",
    c.duration_seconds != null ? `Duration: ${c.duration_seconds}s` : "",
    c.disposition ? `Disposition: ${c.disposition}` : ""
  ].filter(Boolean).join("\n")).join("\n\n");
}

function formatActivity(activity) {
  return activity.map((a) => [
    `${dateTime(a.occurred_at || a.created_at)} | ${a.event_type || a.type || "activity"}`,
    a.actor_email ? `Actor: ${a.actor_email}` : "",
    a.description || a.title || "",
    a.payload ? JSON.stringify(a.payload) : ""
  ].filter(Boolean).join("\n")).join("\n\n");
}

export function buildContactExportSchema(contacts) {
  const standard = [
    "WolfCRM Contact ID",
    "First Name",
    "Last Name",
    "Display/Full Name",
    "Company/Business Name",
    "Primary Phone",
    "Additional Phone Numbers",
    "Email",
    "Address Line 1",
    "Address Line 2",
    "City",
    "State",
    "ZIP/Postal Code",
    "Contact Status/Type",
    "Tags",
    "Current Stage",
    "Created Date",
    "Updated Date",
    "Last Activity Date",
    "Last Synchronized Date"
  ];
  const historyKeys = ["Notes", "Scheduled Jobs", "Completed Jobs", "Quotes", "SMS Messages", "Calls", "Activity Log"];
  const maxChunks = Object.fromEntries(historyKeys.map((key) => [key, 1]));
  let maxLead = 0;
  for (const c of contacts) {
    maxLead = Math.max(maxLead, leadInfoArray(c.contact).length);
    for (const key of historyKeys) {
      maxChunks[key] = Math.max(maxChunks[key], splitLongValue(c.history[key] || "").length);
    }
  }
  const historyHeaders = [];
  for (const key of historyKeys) {
    for (let i = 1; i <= maxChunks[key]; i += 1) historyHeaders.push(i === 1 ? key : `${key} ${i}`);
  }
  const leadHeaders = Array.from({ length: Math.max(25, maxLead) }, (_, i) => `Lead Info ${i + 1}`);
  return { headers: [...standard, ...historyHeaders, ...leadHeaders], historyKeys, maxChunks, leadHeaders };
}

export function buildContactExportRows(contacts, syncDate = new Date()) {
  const schema = buildContactExportSchema(contacts);
  const rows = contacts.map((entry) => {
    const c = entry.contact;
    const parts = nameParts(c.name);
    const addr = parseAddress(c.address);
    const leadValues = leadInfoArray(c);
    const base = [
      c.id,
      parts.first,
      parts.last,
      c.name || "",
      "",
      c.phone || "",
      "",
      c.email || "",
      addr.line1,
      addr.line2,
      addr.city,
      addr.state,
      addr.zip,
      c.job_type || "",
      tagsArray(c.tags).join("; "),
      entry.stage_name || "",
      dateTime(c.created_at),
      dateTime(c.updated_at),
      dateTime(entry.last_activity_at),
      dateTime(syncDate)
    ];
    const history = [];
    for (const key of schema.historyKeys) {
      const chunks = splitLongValue(entry.history[key] || "");
      for (let i = 0; i < schema.maxChunks[key]; i += 1) history.push(chunks[i] || "");
    }
    const lead = schema.leadHeaders.map((_, i) => leadValues[i] || "");
    return [...base, ...history, ...lead];
  });
  return { schema, rows };
}

export async function loadCompanyContactExportData(pool, companyId) {
  const contacts = (await pool.query(
    `SELECT * FROM contacts WHERE company_id = $1 AND deleted_at IS NULL ORDER BY created_at ASC, id ASC`,
    [companyId]
  )).rows;
  const contactIds = contacts.map((c) => c.id);
  if (!contactIds.length) return [];
  const [stageRows, quoteRows, jobRows, smsRows, callRows, activityRows] = await Promise.all([
    pool.query(
      `SELECT o.contact_id, s.name AS stage_name
         FROM opportunities o
         LEFT JOIN stages s ON s.id = o.stage_id AND (s.company_id = $1 OR s.company_id IS NULL)
        WHERE o.company_id = $1 AND o.contact_id = ANY($2::text[])`,
      [companyId, contactIds]
    ),
    pool.query(`SELECT * FROM quotes WHERE company_id = $1 AND contact_id = ANY($2::text[]) ORDER BY created_at DESC`, [companyId, contactIds]),
    pool.query(
      `SELECT se.*,
              COALESCE((SELECT array_agg(COALESCE(u.display_name, u.email) ORDER BY COALESCE(u.display_name, u.email)) FROM users u WHERE u.id::text IN (SELECT jsonb_array_elements_text(se.sales_user_ids))), ARRAY[]::text[]) AS sales_user_names,
              COALESCE((SELECT array_agg(COALESCE(u.display_name, u.email) ORDER BY COALESCE(u.display_name, u.email)) FROM users u WHERE u.id::text IN (SELECT jsonb_array_elements_text(se.worker_user_ids))), ARRAY[]::text[]) AS worker_user_names
         FROM schedule_events se
        WHERE se.company_id = $1 AND se.contact_id = ANY($2::text[])
        ORDER BY se.start_at DESC`,
      [companyId, contactIds]
    ),
    pool.query(
      `SELECT sc.contact_id, sm.*
         FROM sms_conversations sc
         JOIN phone_lines pl ON pl.id = sc.phone_line_id
         JOIN sms_messages sm ON sm.conversation_id = sc.id
        WHERE pl.company_id = $1 AND sc.contact_id = ANY($2::uuid[]) AND sm.deleted_at IS NULL
        ORDER BY sm.created_at DESC`,
      [companyId, contactIds]
    ),
    pool.query(`SELECT * FROM phone_calls WHERE company_id = $1 AND contact_id = ANY($2::uuid[]) ORDER BY started_at DESC`, [companyId, contactIds]),
    pool.query(
      `SELECT ae.subject_id AS contact_id, ae.event_type, ae.occurred_at, ae.created_at, ae.payload, u.email AS actor_email
         FROM automation_events ae
         LEFT JOIN users u ON u.id = ae.actor_user_id
        WHERE ae.company_id = $1 AND ae.subject_type = 'contact' AND ae.subject_id = ANY($2::text[])
        ORDER BY ae.occurred_at DESC`,
      [companyId, contactIds]
    )
  ]);
  const by = (rows, key = "contact_id") => rows.reduce((acc, row) => {
    const id = String(row[key] || "");
    if (!id) return acc;
    acc[id] = acc[id] || [];
    acc[id].push(row);
    return acc;
  }, {});
  const stages = Object.fromEntries(stageRows.rows.map((r) => [String(r.contact_id), r.stage_name || ""]));
  const quotes = by(quoteRows.rows);
  const jobs = by(jobRows.rows);
  const sms = by(smsRows.rows);
  const calls = by(callRows.rows);
  const activities = by(activityRows.rows);
  return contacts.map((contact) => {
    const contactJobs = jobs[contact.id] || [];
    const scheduled = contactJobs.filter((j) => !j.finished_at);
    const completed = contactJobs.filter((j) => j.finished_at);
    const lastActivity = [
      contact.updated_at,
      ...(sms[contact.id] || []).map((r) => r.created_at),
      ...(calls[contact.id] || []).map((r) => r.started_at),
      ...(activities[contact.id] || []).map((r) => r.occurred_at || r.created_at)
    ].filter(Boolean).sort((a, b) => new Date(b) - new Date(a))[0] || null;
    return {
      contact,
      stage_name: stages[contact.id] || "",
      last_activity_at: lastActivity,
      history: {
        Notes: "",
        "Scheduled Jobs": formatJobs(scheduled),
        "Completed Jobs": formatJobs(completed),
        Quotes: formatQuotes(quotes[contact.id] || []),
        "SMS Messages": formatSms(sms[contact.id] || []),
        Calls: formatCalls(calls[contact.id] || []),
        "Activity Log": formatActivity(activities[contact.id] || [])
      }
    };
  });
}

export async function installGoogleSheetsSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS google_sheets_oauth_states (
      state TEXT PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      purpose TEXT NOT NULL DEFAULT 'connect',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ,
      selected_file_ids TEXT
    );
    CREATE INDEX IF NOT EXISTS google_sheets_oauth_states_company_idx ON google_sheets_oauth_states(company_id, expires_at);

    CREATE TABLE IF NOT EXISTS google_sheets_connections (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL UNIQUE REFERENCES companies(id) ON DELETE CASCADE,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      google_account_email TEXT,
      google_account_id TEXT,
      authorized_scopes TEXT NOT NULL DEFAULT '',
      refresh_token_ciphertext TEXT,
      refresh_token_iv TEXT,
      refresh_token_auth_tag TEXT,
      token_encryption_version INTEGER NOT NULL DEFAULT 1,
      spreadsheet_id TEXT,
      spreadsheet_title TEXT,
      sheet_id INTEGER,
      sheet_title TEXT,
      sync_mode TEXT NOT NULL DEFAULT 'manual' CHECK (sync_mode IN ('after_every_change','daily','weekly','manual')),
      timezone TEXT NOT NULL DEFAULT 'America/New_York',
      schedule_time TEXT,
      schedule_weekday INTEGER,
      next_sync_at TIMESTAMPTZ,
      last_attempted_sync_at TIMESTAMPTZ,
      last_successful_sync_at TIMESTAMPTZ,
      last_result_contact_count INTEGER,
      last_result_inserted INTEGER,
      last_result_updated INTEGER,
      reconnect_required BOOLEAN NOT NULL DEFAULT false,
      tab_requires_confirmation BOOLEAN NOT NULL DEFAULT false,
      last_error TEXT,
      status TEXT NOT NULL DEFAULT 'connected' CHECK (status IN ('connected','needs_reconnect','disconnected')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      disconnected_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS google_sheets_connections_sync_idx ON google_sheets_connections(status, sync_mode, next_sync_at);

    CREATE TABLE IF NOT EXISTS google_sheets_dirty_contacts (
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      contact_id UUID NOT NULL,
      dirty_reason TEXT,
      dirty_count INTEGER NOT NULL DEFAULT 1,
      first_dirty_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      last_dirty_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      processing_at TIMESTAMPTZ,
      PRIMARY KEY(company_id, contact_id)
    );
    CREATE INDEX IF NOT EXISTS google_sheets_dirty_company_idx ON google_sheets_dirty_contacts(company_id, last_dirty_at);
  `);
}

async function loadConnection(pool, companyId) {
  return (await pool.query(`SELECT * FROM google_sheets_connections WHERE company_id = $1 AND status <> 'disconnected'`, [companyId])).rows[0] || null;
}

function serializeConnection(row) {
  if (!row) return { connected: false };
  return {
    connected: row.status !== "disconnected" && !!row.refresh_token_ciphertext,
    id: row.id,
    google_account_email: row.google_account_email,
    spreadsheet_id: row.spreadsheet_id,
    spreadsheet_title: row.spreadsheet_title,
    sheet_id: row.sheet_id,
    sheet_title: row.sheet_title,
    sync_mode: row.sync_mode,
    timezone: row.timezone,
    schedule_time: row.schedule_time,
    schedule_weekday: row.schedule_weekday,
    next_sync_at: row.next_sync_at,
    last_attempted_sync_at: row.last_attempted_sync_at,
    last_successful_sync_at: row.last_successful_sync_at,
    last_result_contact_count: row.last_result_contact_count,
    last_result_inserted: row.last_result_inserted,
    last_result_updated: row.last_result_updated,
    reconnect_required: !!row.reconnect_required,
    tab_requires_confirmation: !!row.tab_requires_confirmation,
    last_error: row.last_error
  };
}

export async function markGoogleSheetsContactDirty(pool, companyId, contactId, reason = "changed") {
  if (!companyId || !contactId) return;
  await pool.query(
    `INSERT INTO google_sheets_dirty_contacts(company_id, contact_id, dirty_reason)
     SELECT $1, $2, $3
      WHERE EXISTS (
        SELECT 1 FROM google_sheets_connections
         WHERE company_id = $1 AND status = 'connected' AND reconnect_required = false AND sync_mode = 'after_every_change'
      )
     ON CONFLICT(company_id, contact_id)
     DO UPDATE SET dirty_reason = EXCLUDED.dirty_reason, dirty_count = google_sheets_dirty_contacts.dirty_count + 1, last_dirty_at = now()`,
    [companyId, contactId, reason]
  );
}

async function selectedSheetTitle(connection, metadata) {
  const sheet = metadata.sheets?.find((s) => Number(s.properties.sheetId) === Number(connection.sheet_id));
  return sheet?.properties?.title || connection.sheet_title || "Sheet1";
}

async function inspectSheet(connection, pool, env = process.env) {
  const metadata = await getSpreadsheetMetadata(connection, connection.spreadsheet_id, pool, env);
  const title = await selectedSheetTitle(connection, metadata);
  const firstRows = await googleAPI(connection, `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(connection.spreadsheet_id)}/values/${encodeURIComponent(`${title}!A1:Z20`)}?majorDimension=ROWS`, {}, pool, env);
  const rows = firstRows.values || [];
  const header = rows[0] || [];
  const wolfManaged = header[0] === "WolfCRM Contact ID";
  const nonEmpty = rows.some((row) => row.some((cell) => cleanString(cell)));
  return { title, wolfManaged, nonEmpty, requiresConfirmation: nonEmpty && !wolfManaged };
}

async function writeSheetSchema(connection, sheetTitle, headers, pool, env) {
  const range = `${quoteSheetName(sheetTitle)}!A1:${a1Column(headers.length - 1)}1`;
  await googleAPI(connection, `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(connection.spreadsheet_id)}/values/${encodeURIComponent(range)}?valueInputOption=RAW`, {
    method: "PUT",
    body: JSON.stringify({ range, majorDimension: "ROWS", values: [headers] })
  }, pool, env);
  const requests = [
    { updateSheetProperties: { properties: { sheetId: Number(connection.sheet_id), gridProperties: { frozenRowCount: 1 } }, fields: "gridProperties.frozenRowCount" } },
    { repeatCell: { range: { sheetId: Number(connection.sheet_id), startRowIndex: 0, endRowIndex: 1 }, cell: { userEnteredFormat: { textFormat: { bold: true }, wrapStrategy: "WRAP" } }, fields: "userEnteredFormat(textFormat,wrapStrategy)" } },
    { updateDimensionProperties: { range: { sheetId: Number(connection.sheet_id), dimension: "COLUMNS", startIndex: 0, endIndex: 1 }, properties: { hiddenByUser: true }, fields: "hiddenByUser" } },
    { updateDimensionProperties: { range: { sheetId: Number(connection.sheet_id), dimension: "COLUMNS", startIndex: 1, endIndex: Math.min(headers.length, 80) }, properties: { pixelSize: 180 }, fields: "pixelSize" } },
    { setBasicFilter: { filter: { range: { sheetId: Number(connection.sheet_id), startRowIndex: 0, startColumnIndex: 0, endColumnIndex: headers.length } } } }
  ];
  await googleAPI(connection, `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(connection.spreadsheet_id)}:batchUpdate`, {
    method: "POST",
    body: JSON.stringify({ requests })
  }, pool, env);
}

async function readContactRowMap(connection, sheetTitle, pool, env) {
  const range = `${quoteSheetName(sheetTitle)}!A:A`;
  const data = await googleAPI(connection, `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(connection.spreadsheet_id)}/values/${encodeURIComponent(range)}?majorDimension=COLUMNS`, {}, pool, env);
  const values = data.values?.[0] || [];
  const map = new Map();
  values.forEach((id, index) => {
    if (index === 0 || !id) return;
    if (!map.has(String(id))) map.set(String(id), index + 1);
  });
  return { map, lastRow: values.length };
}

export async function syncGoogleSheetsContacts({ pool, companyId, type = "manual", contactIds = null, force = false, env = process.env }) {
  const started = Date.now();
  const connection = await loadConnection(pool, companyId);
  if (!connection || connection.reconnect_required || !connection.spreadsheet_id || connection.sheet_id == null) {
    return { skipped: true, reason: "not_connected" };
  }
  const inspection = await inspectSheet(connection, pool, env);
  if (inspection.requiresConfirmation && !force) {
    await pool.query(`UPDATE google_sheets_connections SET tab_requires_confirmation = true, last_error = NULL, updated_at = now() WHERE id = $1`, [connection.id]);
    return { needs_confirmation: true };
  }
  const data = await loadCompanyContactExportData(pool, companyId);
  const wantedIds = contactIds ? new Set(contactIds.map((id) => String(id))) : null;
  const currentIds = new Set(data.map((entry) => String(entry.contact.id)));
  const { schema, rows: allRows } = buildContactExportRows(data, new Date());
  const rowByContactId = new Map(data.map((entry, index) => [String(entry.contact.id), allRows[index]]));
  const filtered = wantedIds ? data.filter((entry) => wantedIds.has(String(entry.contact.id))) : data;
  const { map: rowMap, lastRow } = await readContactRowMap(connection, inspection.title, pool, env);
  await writeSheetSchema(connection, inspection.title, schema.headers, pool, env);
  const updates = [];
  const appends = [];
  let inserted = 0;
  let updated = 0;
  let markedDeleted = 0;
  for (const entry of filtered) {
    const contactId = String(entry.contact.id);
    const row = rowByContactId.get(contactId);
    const existingRow = rowMap.get(contactId);
    if (existingRow) {
      updates.push({ range: `${quoteSheetName(inspection.title)}!A${existingRow}:${a1Column(schema.headers.length - 1)}${existingRow}`, values: [row] });
      updated += 1;
    } else {
      appends.push(row);
      inserted += 1;
    }
  }
  const deletedCandidateIds = wantedIds ? [...wantedIds].filter((id) => !currentIds.has(id)) : [...rowMap.keys()].filter((id) => !currentIds.has(id));
  for (const contactId of deletedCandidateIds) {
    const existingRow = rowMap.get(contactId);
    if (!existingRow) continue;
    const row = new Array(schema.headers.length).fill("");
    row[0] = contactId;
    const statusIndex = schema.headers.indexOf("Contact Status/Type");
    const syncIndex = schema.headers.indexOf("Last Synchronized Date");
    if (statusIndex >= 0) row[statusIndex] = "Deleted in WolfCRM";
    if (syncIndex >= 0) row[syncIndex] = formatDateTime(new Date());
    updates.push({ range: `${quoteSheetName(inspection.title)}!A${existingRow}:${a1Column(schema.headers.length - 1)}${existingRow}`, values: [row] });
    markedDeleted += 1;
  }
  const chunks = [];
  if (updates.length) chunks.push(...updates);
  if (appends.length) chunks.push({ range: `${quoteSheetName(inspection.title)}!A${lastRow + 1}:${a1Column(schema.headers.length - 1)}${lastRow + appends.length}`, values: appends });
  for (let i = 0; i < chunks.length; i += 50) {
    await googleAPI(connection, `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(connection.spreadsheet_id)}/values:batchUpdate`, {
      method: "POST",
      body: JSON.stringify({ valueInputOption: "RAW", data: chunks.slice(i, i + 50) })
    }, pool, env);
  }
  await pool.query(
    `UPDATE google_sheets_connections
        SET last_attempted_sync_at = now(), last_successful_sync_at = now(), last_result_contact_count = $2,
            last_result_inserted = $3, last_result_updated = $4, last_error = NULL, tab_requires_confirmation = false, updated_at = now()
      WHERE id = $1`,
    [connection.id, data.length, inserted, updated]
  );
  if (contactIds) await pool.query(`DELETE FROM google_sheets_dirty_contacts WHERE company_id = $1 AND contact_id = ANY($2::uuid[])`, [companyId, contactIds]);
  console.log("[google-sheets] sync complete", { companyId, connectionId: connection.id, type, contactCount: data.length, inserted, updated, markedDeleted, durationMs: Date.now() - started });
  return { contact_count: data.length, inserted, updated, marked_deleted: markedDeleted, duration_ms: Date.now() - started };
}

async function processDirtyContacts(pool, env = process.env) {
  const companies = (await pool.query(
    `SELECT DISTINCT d.company_id
       FROM google_sheets_dirty_contacts d
       JOIN google_sheets_connections c ON c.company_id = d.company_id
      WHERE c.status = 'connected' AND c.reconnect_required = false AND c.sync_mode = 'after_every_change'
        AND d.last_dirty_at < now() - interval '20 seconds'
      LIMIT 10`
  )).rows;
  for (const row of companies) {
    const lock = await pool.query(`SELECT pg_try_advisory_lock(hashtext($1)) AS locked`, [`google_sheets_dirty:${row.company_id}`]);
    if (!lock.rows[0]?.locked) continue;
    try {
      const contactIds = (await pool.query(`SELECT contact_id::text AS contact_id FROM google_sheets_dirty_contacts WHERE company_id = $1 ORDER BY last_dirty_at ASC LIMIT 100`, [row.company_id])).rows.map((r) => r.contact_id);
      if (contactIds.length) await syncGoogleSheetsContacts({ pool, companyId: row.company_id, type: "incremental", contactIds, env });
    } catch (error) {
      console.error("[google-sheets] dirty sync failed", { companyId: row.company_id, error: safeGoogleError(error).reason });
    } finally {
      await pool.query(`SELECT pg_advisory_unlock(hashtext($1))`, [`google_sheets_dirty:${row.company_id}`]);
    }
  }
}

function zonedParts(date, timezone) {
  const formatter = new Intl.DateTimeFormat("en-US", {
    timeZone: timezone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    weekday: "short"
  });
  const parts = Object.fromEntries(formatter.formatToParts(date).map((part) => [part.type, part.value]));
  const weekdayMap = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
  return {
    year: Number(parts.year),
    month: Number(parts.month),
    day: Number(parts.day),
    hour: Number(parts.hour === "24" ? 0 : parts.hour),
    minute: Number(parts.minute),
    weekday: weekdayMap[parts.weekday] ?? 0
  };
}

function utcForZonedLocal(year, month, day, hour, minute, timezone) {
  let utcMs = Date.UTC(year, month - 1, day, hour, minute, 0, 0);
  for (let i = 0; i < 4; i += 1) {
    const actual = zonedParts(new Date(utcMs), timezone);
    const desiredMs = Date.UTC(year, month - 1, day, hour, minute, 0, 0);
    const actualMs = Date.UTC(actual.year, actual.month - 1, actual.day, actual.hour, actual.minute, 0, 0);
    const delta = desiredMs - actualMs;
    if (delta === 0) break;
    utcMs += delta;
  }
  return new Date(utcMs);
}

function computeNextSync(syncMode, timezone = "America/New_York", scheduleTime = "02:00", weekday = 1, from = new Date()) {
  if (syncMode !== "daily" && syncMode !== "weekly") return null;
  const [hour, minute] = (scheduleTime || "02:00").split(":").map((n) => Number(n));
  const scheduledHour = Number.isFinite(hour) ? hour : 2;
  const scheduledMinute = Number.isFinite(minute) ? minute : 0;
  const targetWeekday = Number.isInteger(Number(weekday)) ? Number(weekday) : 1;
  try {
    const current = zonedParts(from, timezone || "America/New_York");
    for (let offset = 0; offset <= 14; offset += 1) {
      const noon = new Date(Date.UTC(current.year, current.month - 1, current.day + offset, 12, 0, 0, 0));
      const candidateDay = zonedParts(noon, timezone || "America/New_York");
      if (syncMode === "weekly" && candidateDay.weekday !== targetWeekday) continue;
      const candidate = utcForZonedLocal(candidateDay.year, candidateDay.month, candidateDay.day, scheduledHour, scheduledMinute, timezone || "America/New_York");
      if (candidate > from) return candidate;
    }
  } catch {
    const fallback = new Date(from);
    fallback.setUTCSeconds(0, 0);
    fallback.setUTCHours(scheduledHour, scheduledMinute, 0, 0);
    if (fallback <= from) fallback.setUTCDate(fallback.getUTCDate() + 1);
    if (syncMode === "weekly") {
      while (fallback.getUTCDay() !== targetWeekday) fallback.setUTCDate(fallback.getUTCDate() + 1);
    }
    return fallback;
  }
  return null;
}

async function processScheduledSyncs(pool, env = process.env) {
  const due = (await pool.query(
    `SELECT * FROM google_sheets_connections
      WHERE status = 'connected' AND reconnect_required = false AND sync_mode IN ('daily','weekly')
        AND (next_sync_at IS NULL OR next_sync_at <= now())
      ORDER BY next_sync_at NULLS FIRST
      LIMIT 5`
  )).rows;
  for (const connection of due) {
    const lock = await pool.query(`SELECT pg_try_advisory_lock(hashtext($1)) AS locked`, [`google_sheets_scheduled:${connection.company_id}`]);
    if (!lock.rows[0]?.locked) continue;
    try {
      await syncGoogleSheetsContacts({ pool, companyId: connection.company_id, type: connection.sync_mode, env });
      await pool.query(`UPDATE google_sheets_connections SET next_sync_at = $2, updated_at = now() WHERE id = $1`, [connection.id, computeNextSync(connection.sync_mode, connection.timezone, connection.schedule_time, connection.schedule_weekday)]);
    } catch (error) {
      await pool.query(`UPDATE google_sheets_connections SET last_attempted_sync_at = now(), last_error = $2, updated_at = now() WHERE id = $1`, [connection.id, safeGoogleError(error).reason]);
      console.error("[google-sheets] scheduled sync failed", { companyId: connection.company_id, error: safeGoogleError(error).reason });
    } finally {
      await pool.query(`SELECT pg_advisory_unlock(hashtext($1))`, [`google_sheets_scheduled:${connection.company_id}`]);
    }
  }
}

export function startGoogleSheetsWorkers(pool, env = process.env) {
  if (env.WOLFCRM_DISABLE_GOOGLE_SHEETS_WORKERS === "true") return;
  setInterval(() => processDirtyContacts(pool, env).catch((e) => console.error("[google-sheets] dirty worker error", e?.message)), 30000).unref();
  setInterval(() => processScheduledSyncs(pool, env).catch((e) => console.error("[google-sheets] schedule worker error", e?.message)), 60000).unref();
}

export async function createGoogleSheetsAuthURL(pool, { companyId, userId, purpose = "connect" }, env = process.env) {
  const config = requireGoogleConfig(env);
  const state = crypto.randomBytes(32).toString("base64url");
  await pool.query(
    `INSERT INTO google_sheets_oauth_states(state, company_id, user_id, purpose, expires_at)
     VALUES($1, $2, $3, $4, now() + ($5 || ' minutes')::interval)`,
    [state, companyId, userId, purpose, OAUTH_STATE_TTL_MINUTES]
  );
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("redirect_uri", config.redirectURI);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", GOOGLE_SHEETS_SCOPE);
  url.searchParams.set("access_type", "offline");
  url.searchParams.set("prompt", "consent");
  url.searchParams.set("trigger_onepick", "true");
  url.searchParams.set("mimetypes", GOOGLE_SHEETS_MIME);
  url.searchParams.set("state", state);
  return { state, authorization_url: url.toString(), redirect_uri: config.redirectURI };
}

async function userInfo(accessToken) {
  return googleFetch("https://openidconnect.googleapis.com/v1/userinfo", {
    headers: { Authorization: `Bearer ${accessToken}` }
  }, 1).catch(() => ({}));
}

async function handleOAuthCallback(pool, query, env = process.env) {
  const state = cleanString(query.state, 300);
  const code = cleanString(query.code, 3000);
  const error = cleanString(query.error, 160);
  const picked = cleanString(query.picked_file_ids, 2000);
  if (!state) throw Object.assign(new Error("invalid_state"), { statusCode: 400 });
  const stateRow = (await pool.query(
    `UPDATE google_sheets_oauth_states
        SET used_at = now(), selected_file_ids = $2
      WHERE state = $1 AND used_at IS NULL AND expires_at > now()
      RETURNING *`,
    [state, picked || null]
  )).rows[0];
  if (!stateRow) throw Object.assign(new Error("invalid_or_expired_state"), { statusCode: 400 });
  if (error) throw Object.assign(new Error(error), { statusCode: 400, companyId: stateRow.company_id });
  if (!code || !picked) throw Object.assign(new Error("google_authorization_incomplete"), { statusCode: 400, companyId: stateRow.company_id });
  const fileId = picked.split(",").map((v) => v.trim()).filter(Boolean)[0];
  const token = await exchangeAuthorizationCode(code, env);
  if (!token.refresh_token) throw Object.assign(new Error("google_refresh_token_missing"), { statusCode: 409, companyId: stateRow.company_id });
  const encrypted = encryptRefreshToken(token.refresh_token, env);
  const file = await googleAPIWithAccessToken(token.access_token, `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}?fields=id,name,mimeType`);
  if (file.mimeType !== GOOGLE_SHEETS_MIME) throw Object.assign(new Error("selected_file_not_google_sheet"), { statusCode: 400, companyId: stateRow.company_id });
  const info = await userInfo(token.access_token);
  const { rows } = await pool.query(
    `INSERT INTO google_sheets_connections(
       company_id, created_by, google_account_email, google_account_id, authorized_scopes,
       refresh_token_ciphertext, refresh_token_iv, refresh_token_auth_tag, token_encryption_version,
       spreadsheet_id, spreadsheet_title, status, reconnect_required, disconnected_at
     ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'connected',false,NULL)
     ON CONFLICT(company_id) DO UPDATE SET
       created_by = EXCLUDED.created_by,
       google_account_email = EXCLUDED.google_account_email,
       google_account_id = EXCLUDED.google_account_id,
       authorized_scopes = EXCLUDED.authorized_scopes,
       refresh_token_ciphertext = EXCLUDED.refresh_token_ciphertext,
       refresh_token_iv = EXCLUDED.refresh_token_iv,
       refresh_token_auth_tag = EXCLUDED.refresh_token_auth_tag,
       token_encryption_version = EXCLUDED.token_encryption_version,
       spreadsheet_id = EXCLUDED.spreadsheet_id,
       spreadsheet_title = EXCLUDED.spreadsheet_title,
       sheet_id = NULL,
       sheet_title = NULL,
       status = 'connected',
       reconnect_required = false,
       disconnected_at = NULL,
       last_error = NULL,
       updated_at = now()
     RETURNING *`,
    [stateRow.company_id, stateRow.user_id, info.email || null, info.sub || null, token.scope || GOOGLE_SHEETS_SCOPE, encrypted.refresh_token_ciphertext, encrypted.refresh_token_iv, encrypted.refresh_token_auth_tag, encrypted.token_encryption_version, file.id, file.name]
  );
  return rows[0];
}

export function installGoogleSheetsSystem({ app, pool, authRequired, requireEmployer, env = process.env }) {
  app.get("/api/integrations/google-sheets/status", authRequired, async (req, res) => {
    try {
      if (!req.companyId) return res.status(400).json({ error: "company_required" });
      res.json(serializeConnection(await loadConnection(pool, req.companyId)));
    } catch (e) {
      res.status(500).json({ error: "google_sheets_status_failed", message: "Could not load Google Sheets integration." });
    }
  });

  app.post("/api/integrations/google-sheets/start", authRequired, requireEmployer, async (req, res) => {
    try {
      if (!req.companyId) return res.status(400).json({ error: "company_required" });
      res.json(await createGoogleSheetsAuthURL(pool, { companyId: req.companyId, userId: req.userId, purpose: req.body?.purpose || "connect" }, env));
    } catch (e) {
      const status = e.statusCode || 500;
      res.status(status).json({ error: e.code || "google_sheets_start_failed", message: "Could not start Google authorization." });
    }
  });

  app.get("/api/integrations/google-sheets/oauth/callback", async (req, res) => {
    try {
      const connection = await handleOAuthCallback(pool, req.query || {}, env);
      res.redirect(`wolfcrm://google-sheets?status=connected&connection_id=${encodeURIComponent(connection.id)}`);
    } catch (e) {
      console.error("[google-sheets] oauth callback failed", { error: e.message, companyId: e.companyId || null });
      res.redirect(`wolfcrm://google-sheets?status=error&error=${encodeURIComponent(e.message || "google_oauth_failed")}`);
    }
  });

  app.get("/api/integrations/google-sheets/tabs", authRequired, async (req, res) => {
    try {
      if (!req.companyId) return res.status(400).json({ error: "company_required" });
      const connection = await loadConnection(pool, req.companyId);
      if (!connection) return res.status(404).json({ error: "not_connected" });
      const metadata = await getSpreadsheetMetadata(connection, connection.spreadsheet_id, pool, env);
      res.json({
        spreadsheet_title: metadata.properties?.title || connection.spreadsheet_title,
        tabs: (metadata.sheets || []).map((sheet) => ({ sheet_id: sheet.properties.sheetId, title: sheet.properties.title }))
      });
    } catch (e) {
      res.status(500).json({ error: "google_sheets_tabs_failed", message: "Could not load spreadsheet tabs." });
    }
  });

  app.put("/api/integrations/google-sheets/tab", authRequired, requireEmployer, async (req, res) => {
    try {
      if (!req.companyId) return res.status(400).json({ error: "company_required" });
      const sheetId = Number(req.body?.sheet_id);
      if (!Number.isInteger(sheetId)) return res.status(400).json({ error: "sheet_id_required" });
      const connection = await loadConnection(pool, req.companyId);
      if (!connection) return res.status(404).json({ error: "not_connected" });
      const metadata = await getSpreadsheetMetadata(connection, connection.spreadsheet_id, pool, env);
      const sheet = metadata.sheets?.find((s) => Number(s.properties.sheetId) === sheetId);
      if (!sheet) return res.status(404).json({ error: "sheet_not_found" });
      const updated = (await pool.query(`UPDATE google_sheets_connections SET sheet_id = $2, sheet_title = $3, updated_at = now() WHERE id = $1 RETURNING *`, [connection.id, sheetId, sheet.properties.title])).rows[0];
      const inspection = await inspectSheet(updated, pool, env);
      if (inspection.requiresConfirmation) {
        await pool.query(`UPDATE google_sheets_connections SET tab_requires_confirmation = true WHERE id = $1`, [connection.id]);
      }
      res.json({ ...serializeConnection({ ...updated, tab_requires_confirmation: inspection.requiresConfirmation }), requires_confirmation: inspection.requiresConfirmation });
    } catch (e) {
      res.status(500).json({ error: "google_sheets_select_tab_failed", message: "Could not select spreadsheet tab." });
    }
  });

  app.put("/api/integrations/google-sheets/settings", authRequired, requireEmployer, async (req, res) => {
    try {
      if (!req.companyId) return res.status(400).json({ error: "company_required" });
      const mode = ["after_every_change", "daily", "weekly", "manual"].includes(req.body?.sync_mode) ? req.body.sync_mode : "manual";
      const time = /^\d{2}:\d{2}$/.test(req.body?.schedule_time || "") ? req.body.schedule_time : null;
      const weekday = Number.isInteger(Number(req.body?.schedule_weekday)) ? Number(req.body.schedule_weekday) : null;
      const timezone = cleanString(req.body?.timezone || "America/New_York", 80) || "America/New_York";
      const next = computeNextSync(mode, timezone, time || "02:00", weekday ?? 1);
      const { rows } = await pool.query(
        `UPDATE google_sheets_connections
            SET sync_mode = $2, timezone = $3, schedule_time = $4, schedule_weekday = $5, next_sync_at = $6, updated_at = now()
          WHERE company_id = $1 AND status <> 'disconnected'
          RETURNING *`,
        [req.companyId, mode, timezone, time, weekday, next]
      );
      if (!rows.length) return res.status(404).json({ error: "not_connected" });
      res.json(serializeConnection(rows[0]));
    } catch (e) {
      res.status(500).json({ error: "google_sheets_settings_failed", message: "Could not save sync settings." });
    }
  });

  app.post("/api/integrations/google-sheets/sync", authRequired, requireEmployer, async (req, res) => {
    try {
      if (!req.companyId) return res.status(400).json({ error: "company_required" });
      res.json(await syncGoogleSheetsContacts({ pool, companyId: req.companyId, type: "manual", force: !!req.body?.force, env }));
    } catch (e) {
      const safe = safeGoogleError(e);
      res.status(safe.status >= 400 && safe.status < 500 ? safe.status : 500).json({ error: "google_sheets_sync_failed", message: "Google Sheets sync failed." });
    }
  });

  app.delete("/api/integrations/google-sheets", authRequired, requireEmployer, async (req, res) => {
    try {
      if (!req.companyId) return res.status(400).json({ error: "company_required" });
      await pool.query(
        `UPDATE google_sheets_connections
            SET status = 'disconnected', reconnect_required = false, refresh_token_ciphertext = NULL, refresh_token_iv = NULL,
                refresh_token_auth_tag = NULL, disconnected_at = now(), updated_at = now()
          WHERE company_id = $1`,
        [req.companyId]
      );
      await pool.query(`DELETE FROM google_sheets_dirty_contacts WHERE company_id = $1`, [req.companyId]);
      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: "google_sheets_disconnect_failed", message: "Could not disconnect Google Sheets." });
    }
  });
}

export const googleSheetsTestHooks = {
  splitLongValue,
  buildContactExportRows,
  buildContactExportSchema,
  createGoogleSheetsAuthURL,
  computeNextSync,
  encryptRefreshToken,
  decryptRefreshToken,
  GOOGLE_SHEETS_SCOPE,
  GOOGLE_SHEETS_CELL_LIMIT
};
