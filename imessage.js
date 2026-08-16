import crypto from "crypto";
import { emitAutomationEvent } from "./automations.js";

const TEXTING_BLUE_BASE_URL = (process.env.TEXTING_BLUE_BASE_URL || "https://api.texting.blue/v1").replace(/\/+$/, "");
const MAX_MESSAGE_LENGTH = 5000;
const SYNC_COOLDOWN_MS = 30_000;
const DEVICE_STALE_MS = 5 * 60 * 1000;
const recentSyncAt = new Map();

function cleanString(value, maxLength = 5000) {
  return (value ?? "").toString().trim().slice(0, maxLength);
}

function phoneDigits(value) {
  return cleanString(value, 64).replace(/[^0-9]/g, "");
}

export function normalizeIMessageE164(value) {
  const raw = cleanString(value, 64);
  if (!raw) return null;
  if (raw.startsWith("+")) {
    const digits = phoneDigits(raw);
    return /^[1-9]\d{6,14}$/.test(digits) ? `+${digits}` : null;
  }
  const digits = phoneDigits(raw);
  if (digits.length === 10) return `+1${digits}`;
  if (digits.length === 11 && digits.startsWith("1")) return `+${digits}`;
  return null;
}

function textingBlueApiKey() {
  return cleanString(process.env.TEXTING_BLUE_API_KEY, 512);
}

function textingBlueConfiguredPhone() {
  return normalizeIMessageE164(process.env.TEXTING_BLUE_PHONE_NUMBER || "");
}

function providerErrorPayload(payload) {
  if (payload?.error && typeof payload.error === "object") return payload.error;
  if (payload?.error && typeof payload.error === "string") return { code: payload.error, message: payload.message };
  return { code: payload?.code, message: payload?.message };
}

function translateProviderError(status, payload, retryAfter) {
  const provider = providerErrorPayload(payload);
  const code = provider.code || "texting_blue_request_failed";
  const mapped = {
    invalid_request: "invalid_request",
    unauthorized: "unauthorized",
    forbidden: "forbidden",
    plan_limit_exceeded: "plan_limit_exceeded",
    not_found: "not_found",
    conflict: "conflict",
    rate_limited: "rate_limited",
    internal_error: "provider_internal_error",
    device_offline: "texting_blue_device_offline",
    number_paused: "imessage_line_inactive"
  }[code] || (status >= 500 ? "provider_internal_error" : code);
  const error = new Error(provider.message || mapped);
  error.status = status === 402 ? 402 : status;
  error.code = mapped;
  error.retryAfter = retryAfter;
  error.providerPayload = payload;
  return error;
}

async function textingBlueRequest(path, { method = "GET", body = null, query = null, fetchImpl = fetch } = {}) {
  const apiKey = textingBlueApiKey();
  if (!apiKey) {
    const error = new Error("imessage_not_configured");
    error.status = 503;
    error.code = "imessage_not_configured";
    throw error;
  }

  const url = new URL(`${TEXTING_BLUE_BASE_URL}${path}`);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value !== null && value !== undefined && value !== "") url.searchParams.set(key, String(value));
    }
  }

  const response = await fetchImpl(url, {
    method,
    headers: {
      "x-api-key": apiKey,
      ...(body ? { "Content-Type": "application/json" } : {})
    },
    body: body ? JSON.stringify(body) : undefined
  });

  const raw = await response.text();
  let payload = null;
  if (raw) {
    try { payload = JSON.parse(raw); } catch (_) { payload = { message: raw }; }
  }

  if (!response.ok) {
    throw translateProviderError(response.status, payload, response.headers.get("Retry-After"));
  }
  return payload;
}

export function verifyTextingBlueSignature(rawBody, signature, secret) {
  if (!rawBody || !signature || !secret) return false;
  const receivedHex = cleanString(signature, 512).replace(/^sha256=/i, "");
  if (!/^[a-f0-9]{64}$/i.test(receivedHex)) return false;
  const expected = crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
  const received = Buffer.from(receivedHex, "hex");
  const expectedBuffer = Buffer.from(expected, "hex");
  return received.length === expectedBuffer.length && crypto.timingSafeEqual(received, expectedBuffer);
}

async function ensureIMessageSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS imessage_lines (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      provider TEXT NOT NULL DEFAULT 'texting_blue',
      provider_number_id TEXT,
      phone_number TEXT NOT NULL,
      label TEXT,
      status TEXT,
      verified BOOLEAN NOT NULL DEFAULT false,
      device_name TEXT,
      last_seen_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, provider),
      UNIQUE(provider, phone_number)
    );
    CREATE INDEX IF NOT EXISTS imessage_lines_company_idx ON imessage_lines(company_id, provider);
    CREATE INDEX IF NOT EXISTS imessage_lines_phone_idx ON imessage_lines(phone_number);

    CREATE TABLE IF NOT EXISTS imessage_conversations (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      line_id UUID NOT NULL REFERENCES imessage_lines(id) ON DELETE CASCADE,
      external_phone_number TEXT NOT NULL,
      contact_id UUID REFERENCES contacts(id) ON DELETE SET NULL,
      last_message_at TIMESTAMPTZ,
      last_read_at TIMESTAMPTZ,
      deleted_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(line_id, external_phone_number)
    );
    CREATE INDEX IF NOT EXISTS imessage_conversations_company_last_idx ON imessage_conversations(company_id, last_message_at DESC);
    CREATE INDEX IF NOT EXISTS imessage_conversations_contact_idx ON imessage_conversations(contact_id);
    CREATE INDEX IF NOT EXISTS imessage_conversations_unread_idx ON imessage_conversations(company_id, last_read_at);

    CREATE TABLE IF NOT EXISTS imessage_messages (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      conversation_id UUID NOT NULL REFERENCES imessage_conversations(id) ON DELETE CASCADE,
      provider_message_id TEXT,
      direction TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound')),
      from_number TEXT NOT NULL,
      to_number TEXT NOT NULL,
      body TEXT,
      media_url TEXT,
      message_status TEXT,
      error_code TEXT,
      error_message TEXT,
      provider_created_at TIMESTAMPTZ,
      deleted_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS imessage_messages_provider_id_uidx
      ON imessage_messages(provider_message_id)
      WHERE provider_message_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS imessage_messages_conversation_created_idx
      ON imessage_messages(conversation_id, COALESCE(provider_created_at, created_at));
    CREATE INDEX IF NOT EXISTS imessage_messages_unread_idx
      ON imessage_messages(conversation_id, direction, COALESCE(provider_created_at, created_at))
      WHERE deleted_at IS NULL;

    CREATE TABLE IF NOT EXISTS imessage_webhook_events (
      event_id TEXT PRIMARY KEY,
      event_type TEXT NOT NULL,
      provider_message_id TEXT,
      received_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS imessage_webhook_events_provider_idx ON imessage_webhook_events(provider_message_id);
  `);
}

async function findContactId(pool, companyId, phone) {
  const digits = phoneDigits(phone);
  if (!companyId || !digits) return null;
  const local = digits.length === 11 && digits.startsWith("1") ? digits.slice(1) : digits;
  const { rows } = await pool.query(
    `SELECT id
       FROM contacts
      WHERE company_id = $1
        AND deleted_at IS NULL
        AND (
          regexp_replace(COALESCE(phone,''), '[^0-9]', '', 'g') = $2
          OR (length($3) = 10 AND right(regexp_replace(COALESCE(phone,''), '[^0-9]', '', 'g'), 10) = $3)
        )
      LIMIT 2`,
    [companyId, digits, local]
  );
  return rows.length === 1 ? rows[0].id : null;
}

async function listProviderNumbers(fetchImpl) {
  const payload = await textingBlueRequest("/numbers", { fetchImpl });
  return Array.isArray(payload?.numbers) ? payload.numbers : [];
}

function normalizedProviderNumber(row) {
  return normalizeIMessageE164(row?.phone_number || row?.phoneNumber || "");
}

async function upsertLine(pool, companyId, providerNumber) {
  const phoneNumber = normalizedProviderNumber(providerNumber);
  if (!phoneNumber) return null;
  const { rows } = await pool.query(
    `INSERT INTO imessage_lines(
       company_id, provider, provider_number_id, phone_number, label, status,
       verified, device_name, last_seen_at, updated_at
     )
     VALUES($1,'texting_blue',$2,$3,$4,$5,$6,$7,$8,now())
     ON CONFLICT (company_id, provider)
     DO UPDATE SET
       provider_number_id = EXCLUDED.provider_number_id,
       phone_number = EXCLUDED.phone_number,
       label = EXCLUDED.label,
       status = EXCLUDED.status,
       verified = EXCLUDED.verified,
       device_name = EXCLUDED.device_name,
       last_seen_at = EXCLUDED.last_seen_at,
       updated_at = now()
     RETURNING *`,
    [
      companyId,
      cleanString(providerNumber?.id, 200) || null,
      phoneNumber,
      cleanString(providerNumber?.label, 200) || null,
      cleanString(providerNumber?.status, 40) || null,
      providerNumber?.verified === true,
      cleanString(providerNumber?.device_name, 200) || null,
      providerNumber?.last_seen_at || null
    ]
  );
  return rows[0] || null;
}

async function resolveLine(pool, companyId, { refresh = true, fetchImpl = fetch } = {}) {
  if (!companyId) return null;
  const existing = (await pool.query(
    `SELECT * FROM imessage_lines WHERE company_id = $1 AND provider = 'texting_blue' LIMIT 1`,
    [companyId]
  )).rows[0] || null;
  if (!refresh && existing) return existing;

  const numbers = await listProviderNumbers(fetchImpl);
  if (!numbers.length) return existing;

  const configured = textingBlueConfiguredPhone();
  const companyPhone = normalizeIMessageE164((await pool.query(`SELECT phone FROM companies WHERE id = $1 LIMIT 1`, [companyId])).rows[0]?.phone || "");
  const existingPhone = normalizeIMessageE164(existing?.phone_number || "");
  const existingProviderId = cleanString(existing?.provider_number_id, 200);

  let selected = null;
  if (existingProviderId) selected = numbers.find((row) => cleanString(row?.id, 200) === existingProviderId) || null;
  if (!selected && existingPhone) selected = numbers.find((row) => normalizedProviderNumber(row) === existingPhone) || null;
  if (!selected && configured) selected = numbers.find((row) => normalizedProviderNumber(row) === configured) || null;
  if (!selected && companyPhone) selected = numbers.find((row) => normalizedProviderNumber(row) === companyPhone) || null;
  if (!selected && numbers.length === 1) selected = numbers[0];
  if (!selected) return existing;
  return upsertLine(pool, companyId, selected);
}

function lineConnectionStatus(line) {
  if (!line) return { connected: false, stale: true };
  const active = cleanString(line.status, 40).toLowerCase() === "active";
  const verified = line.verified === true;
  const lastSeen = line.last_seen_at ? new Date(line.last_seen_at) : null;
  const stale = !lastSeen || Number.isNaN(lastSeen.getTime()) || (Date.now() - lastSeen.getTime()) > DEVICE_STALE_MS;
  return { connected: active && verified && !stale, stale };
}

async function getOrCreateConversation(pool, line, externalPhone) {
  const external = normalizeIMessageE164(externalPhone);
  if (!external) {
    const error = new Error("invalid_phone_number");
    error.status = 400;
    error.code = "invalid_phone_number";
    throw error;
  }
  const contactId = await findContactId(pool, line.company_id, external);
  const { rows } = await pool.query(
    `INSERT INTO imessage_conversations(company_id, line_id, external_phone_number, contact_id, updated_at)
     VALUES($1,$2,$3,$4,now())
     ON CONFLICT (line_id, external_phone_number)
     DO UPDATE SET
       contact_id = COALESCE(imessage_conversations.contact_id, EXCLUDED.contact_id),
       deleted_at = NULL,
       updated_at = now()
     RETURNING *`,
    [line.company_id, line.id, external, contactId]
  );
  return rows[0];
}

function providerMessageTimestamp(message) {
  return message?.received_at || message?.created_at || message?.sent_at || message?.delivered_at || new Date().toISOString();
}

async function persistProviderMessage(pool, line, providerMessage) {
  const providerId = cleanString(providerMessage?.id, 250);
  const fromNumber = normalizeIMessageE164(providerMessage?.from);
  const toNumber = normalizeIMessageE164(providerMessage?.to);
  if (!providerId || !fromNumber || !toNumber) return null;

  const business = normalizeIMessageE164(line.phone_number);
  let direction = cleanString(providerMessage?.direction, 20).toLowerCase();
  if (direction !== "inbound" && direction !== "outbound") {
    direction = toNumber === business ? "inbound" : "outbound";
  }
  const external = direction === "inbound" ? fromNumber : toNumber;
  const conversation = await getOrCreateConversation(pool, line, external);
  const providerCreatedAt = providerMessageTimestamp(providerMessage);
  const status = cleanString(providerMessage?.status || (direction === "inbound" ? "received" : "queued"), 80) || null;
  const body = providerMessage?.content == null ? null : providerMessage.content.toString().slice(0, MAX_MESSAGE_LENGTH);
  const mediaUrl = cleanString(providerMessage?.media_url, 4000) || null;
  const errorCode = cleanString(providerMessage?.error_code, 200) || null;
  const errorMessage = cleanString(providerMessage?.error_message, 1000) || null;

  const { rows } = await pool.query(
    `INSERT INTO imessage_messages(
       conversation_id, provider_message_id, direction, from_number, to_number,
       body, media_url, message_status, error_code, error_message,
       provider_created_at, created_at, updated_at
     )
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11,now())
     ON CONFLICT (provider_message_id)
     WHERE provider_message_id IS NOT NULL
     DO UPDATE SET
       message_status = COALESCE(EXCLUDED.message_status, imessage_messages.message_status),
       body = COALESCE(EXCLUDED.body, imessage_messages.body),
       media_url = COALESCE(EXCLUDED.media_url, imessage_messages.media_url),
       error_code = EXCLUDED.error_code,
       error_message = EXCLUDED.error_message,
       updated_at = now()
     RETURNING *`,
    [conversation.id, providerId, direction, fromNumber, toNumber, body, mediaUrl, status, errorCode, errorMessage, providerCreatedAt]
  );

  await pool.query(
    `UPDATE imessage_conversations
        SET last_message_at = GREATEST(COALESCE(last_message_at, $2::timestamptz), $2::timestamptz),
            contact_id = COALESCE(contact_id, $3),
            updated_at = now()
      WHERE id = $1`,
    [conversation.id, providerCreatedAt, conversation.contact_id || null]
  );

  return { message: rows[0], conversation };
}

async function syncRecentMessages(pool, line, { force = false, fetchImpl = fetch } = {}) {
  if (!line) return;
  const key = String(line.id);
  const last = recentSyncAt.get(key) || 0;
  if (!force && Date.now() - last < SYNC_COOLDOWN_MS) return;
  recentSyncAt.set(key, Date.now());

  const phone = normalizeIMessageE164(line.phone_number);
  if (!phone) return;
  try {
    const [outbound, inbound] = await Promise.all([
      textingBlueRequest("/messages", { query: { from: phone, limit: 100 }, fetchImpl }),
      textingBlueRequest("/messages", { query: { to: phone, limit: 100 }, fetchImpl })
    ]);
    const merged = [...(outbound?.messages || []), ...(inbound?.messages || [])];
    const seen = new Set();
    for (const providerMessage of merged.reverse()) {
      const id = cleanString(providerMessage?.id, 250);
      if (!id || seen.has(id)) continue;
      seen.add(id);
      await persistProviderMessage(pool, line, providerMessage);
    }
  } catch (error) {
    recentSyncAt.delete(key);
    console.warn("[imessage/sync] provider sync failed:", { status: error?.status, code: error?.code, message: error?.message });
  }
}

async function emitIMessageEvent({ line, saved, eventType, source = "texting_blue.webhook", actorUserId = null }) {
  if (!saved?.message || !line?.company_id || !eventType) return;
  await emitAutomationEvent({
    companyId: line.company_id,
    eventType,
    subjectType: "imessage_message",
    subjectId: saved.message.id,
    actorUserId,
    source,
    dedupeKey: `${eventType}:${saved.message.provider_message_id || saved.message.id}`,
    payload: {
      message_id: saved.message.id,
      provider_message_id: saved.message.provider_message_id,
      conversation_id: saved.conversation.id,
      contact_id: saved.conversation.contact_id || null,
      external_number: saved.conversation.external_phone_number,
      from_number: saved.message.from_number,
      to_number: saved.message.to_number,
      body: saved.message.body,
      direction: saved.message.direction,
      status: saved.message.message_status,
      channel: "imessage",
      provider: "texting_blue"
    }
  });
}

async function sendProviderMessage(pool, line, conversation, body, actorUserId = null, { fetchImpl = fetch, source = "wolfcrm.ios" } = {}) {
  const content = cleanString(body, MAX_MESSAGE_LENGTH);
  if (!content) {
    const error = new Error("message_body_required");
    error.status = 400;
    error.code = "message_body_required";
    throw error;
  }
  const connection = lineConnectionStatus(line);
  if (cleanString(line.status, 40).toLowerCase() !== "active" || line.verified !== true) {
    const error = new Error("imessage_line_inactive");
    error.status = 409;
    error.code = "imessage_line_inactive";
    throw error;
  }

  const providerMessage = await textingBlueRequest("/messages/send", {
    method: "POST",
    body: { to: conversation.external_phone_number, from: line.phone_number, content },
    fetchImpl
  });
  providerMessage.direction = providerMessage.direction || "outbound";
  const saved = await persistProviderMessage(pool, line, providerMessage);
  await emitIMessageEvent({ line, saved, eventType: "imessage.sent", source, actorUserId });
  return { message: { ...saved.message, device_may_be_offline: connection.stale }, conversation };
}

function providerEventToAutomationEvent(eventType) {
  switch (eventType) {
    case "message.received": return "imessage.received";
    case "message.sent": return "imessage.sent";
    case "message.delivered": return "imessage.delivered";
    case "message.failed": return "imessage.failed";
    default: return null;
  }
}

async function resolveWebhookLine(pool, providerMessage) {
  const fromNumber = normalizeIMessageE164(providerMessage?.from);
  const toNumber = normalizeIMessageE164(providerMessage?.to);
  const candidates = [fromNumber, toNumber].filter(Boolean);
  if (!candidates.length) return null;
  const { rows } = await pool.query(
    `SELECT *
       FROM imessage_lines
      WHERE provider = 'texting_blue'
        AND phone_number = ANY($1::text[])
      LIMIT 2`,
    [candidates]
  );
  return rows.length === 1 ? rows[0] : null;
}

async function notifyInboundIMessage({ pool, sendCompanyPhonePush, line, saved }) {
  if (!sendCompanyPhonePush || saved?.message?.direction !== "inbound") return;
  const contactName = saved.conversation.contact_id
    ? (await pool.query(`SELECT name FROM contacts WHERE id = $1 AND company_id = $2 LIMIT 1`, [saved.conversation.contact_id, line.company_id])).rows[0]?.name
    : null;
  const titleName = cleanString(contactName, 120) || saved.conversation.external_phone_number;
  await sendCompanyPhonePush(line.company_id, {
    title: `iMessage from ${titleName}`,
    body: saved.message.body || "New iMessage",
    contactId: saved.conversation.contact_id || undefined,
    threadId: `imessage_${saved.conversation.id}`,
    payload: {
      type: "imessage",
      conversation_id: saved.conversation.id,
      contact_id: saved.conversation.contact_id || null,
      external_phone_number: saved.conversation.external_phone_number
    }
  });
}

function sendError(res, error, fallback) {
  const status = error?.status || 500;
  const body = { error: error?.code || fallback, message: error?.message || fallback };
  if (error?.retryAfter) body.retry_after = error.retryAfter;
  res.status(status).json(body);
}

export async function sendAutomatedIMessage({ pool, companyId, userId = null, contactId = null, phone = null, conversationId = null, body, fetchImpl = fetch }) {
  const line = await resolveLine(pool, companyId, { refresh: true, fetchImpl });
  if (!line) {
    const error = new Error("imessage_number_selection_required");
    error.status = 409;
    error.code = "imessage_number_selection_required";
    throw error;
  }
  let conversation;
  if (conversationId) {
    conversation = (await pool.query(
      `SELECT * FROM imessage_conversations WHERE id::text = $1 AND company_id = $2 AND deleted_at IS NULL LIMIT 1`,
      [conversationId, companyId]
    )).rows[0];
    if (!conversation) {
      const error = new Error("imessage_conversation_not_found");
      error.status = 404;
      error.code = "imessage_conversation_not_found";
      throw error;
    }
  } else {
    let targetPhone = phone;
    if (!targetPhone && contactId) {
      targetPhone = (await pool.query(`SELECT phone FROM contacts WHERE id::text = $1 AND company_id = $2 AND deleted_at IS NULL LIMIT 1`, [contactId, companyId])).rows[0]?.phone;
    }
    conversation = await getOrCreateConversation(pool, line, targetPhone);
  }
  const sent = await sendProviderMessage(pool, line, conversation, body, userId, { fetchImpl, source: "automation" });
  return sent;
}

export async function installIMessageSystem({ app, pool, authRequired, sendCompanyPhonePush, fetchImpl = fetch }) {
  await ensureIMessageSchema(pool);

  app.get("/api/imessage/status", authRequired, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required" });
    if (!textingBlueApiKey()) return res.json({ configured: false, connected: false, provider: "texting_blue", error: "imessage_not_configured" });
    try {
      const line = await resolveLine(pool, req.companyId, { refresh: true, fetchImpl });
      if (!line) return res.json({ configured: true, connected: false, provider: "texting_blue", error: "imessage_number_selection_required" });
      const connection = lineConnectionStatus(line);
      res.json({
        configured: true,
        connected: connection.connected,
        provider: "texting_blue",
        line_id: line.id,
        phone_number: line.phone_number,
        provider_number_id: line.provider_number_id,
        label: line.label,
        status: line.status,
        verified: line.verified,
        device_name: line.device_name,
        last_seen_at: line.last_seen_at,
        device_may_be_offline: connection.stale,
        error: null
      });
    } catch (error) {
      console.error("[imessage/status] failed:", { status: error?.status, code: error?.code, message: error?.message });
      sendError(res, error, "imessage_status_failed");
    }
  });

  app.get("/api/imessage/conversations", authRequired, async (req, res) => {
    if (!req.companyId) return res.json([]);
    try {
      const line = await resolveLine(pool, req.companyId, { refresh: true, fetchImpl });
      if (!line) return res.json([]);
      await syncRecentMessages(pool, line, { fetchImpl });
      const { rows } = await pool.query(
        `SELECT ic.id,
                ic.line_id,
                il.phone_number AS business_phone_number,
                ic.external_phone_number,
                ic.contact_id,
                c.name AS contact_name,
                last.body AS last_message_body,
                last.direction AS last_message_direction,
                last.message_status AS last_message_status,
                COALESCE(unread.count, 0)::int AS unread_count,
                ic.last_message_at,
                ic.last_read_at,
                ic.created_at,
                ic.updated_at
           FROM imessage_conversations ic
           JOIN imessage_lines il ON il.id = ic.line_id
           LEFT JOIN contacts c ON c.id = ic.contact_id AND c.company_id = ic.company_id
           LEFT JOIN LATERAL (
             SELECT body, direction, message_status
               FROM imessage_messages im
              WHERE im.conversation_id = ic.id AND im.deleted_at IS NULL
              ORDER BY COALESCE(im.provider_created_at, im.created_at) DESC, im.id DESC
              LIMIT 1
           ) last ON true
           LEFT JOIN LATERAL (
             SELECT COUNT(*)::int AS count
               FROM imessage_messages im
              WHERE im.conversation_id = ic.id
                AND im.deleted_at IS NULL
                AND im.direction = 'inbound'
                AND COALESCE(im.provider_created_at, im.created_at) > COALESCE(ic.last_read_at, '1970-01-01'::timestamptz)
           ) unread ON true
          WHERE ic.company_id = $1
            AND ic.deleted_at IS NULL
          ORDER BY ic.last_message_at DESC NULLS LAST, ic.updated_at DESC
          LIMIT 250`,
        [req.companyId]
      );
      res.json(rows);
    } catch (error) {
      console.error("[imessage/conversations] failed:", { status: error?.status, code: error?.code, message: error?.message });
      sendError(res, error, "imessage_conversations_failed");
    }
  });

  app.get("/api/imessage/conversations/:id/messages", authRequired, async (req, res) => {
    if (!req.companyId) return res.status(404).json({ error: "conversation_not_found" });
    try {
      const owned = await pool.query(
        `SELECT ic.id, ic.line_id
           FROM imessage_conversations ic
          WHERE ic.id = $1 AND ic.company_id = $2 AND ic.deleted_at IS NULL
          LIMIT 1`,
        [req.params.id, req.companyId]
      );
      if (!owned.rowCount) return res.status(404).json({ error: "conversation_not_found" });
      const line = (await pool.query(`SELECT * FROM imessage_lines WHERE id = $1 LIMIT 1`, [owned.rows[0].line_id])).rows[0];
      if (line) await syncRecentMessages(pool, line, { fetchImpl });
      await pool.query(`UPDATE imessage_conversations SET last_read_at = now(), updated_at = now() WHERE id = $1`, [req.params.id]);
      const { rows } = await pool.query(
        `SELECT id, conversation_id, provider_message_id, direction, from_number, to_number,
                body, media_url, message_status, error_code, error_message,
                COALESCE(provider_created_at, created_at) AS created_at, updated_at
           FROM imessage_messages
          WHERE conversation_id = $1 AND deleted_at IS NULL
          ORDER BY COALESCE(provider_created_at, created_at) ASC, id ASC
          LIMIT 1000`,
        [req.params.id]
      );
      res.json(rows);
    } catch (error) {
      console.error("[imessage/messages] failed:", { code: error?.code, message: error?.message });
      sendError(res, error, "imessage_messages_failed");
    }
  });

  app.post("/api/imessage/conversations/:id/messages", authRequired, async (req, res) => {
    if (!req.companyId) return res.status(404).json({ error: "conversation_not_found" });
    try {
      const content = cleanString(req.body?.body, MAX_MESSAGE_LENGTH);
      if (!content) return res.status(400).json({ error: "message_body_required" });
      const row = (await pool.query(
        `SELECT ic.*, il.phone_number, il.status, il.verified, il.last_seen_at, il.company_id
           FROM imessage_conversations ic
           JOIN imessage_lines il ON il.id = ic.line_id
          WHERE ic.id = $1 AND ic.company_id = $2 AND ic.deleted_at IS NULL
          LIMIT 1`,
        [req.params.id, req.companyId]
      )).rows[0];
      if (!row) return res.status(404).json({ error: "conversation_not_found" });
      const line = { id: row.line_id, company_id: row.company_id, phone_number: row.phone_number, status: row.status, verified: row.verified, last_seen_at: row.last_seen_at };
      const sent = await sendProviderMessage(pool, line, row, content, req.userId, { fetchImpl });
      res.status(201).json(sent.message);
    } catch (error) {
      console.error("[imessage/send] failed:", { status: error?.status, code: error?.code, message: error?.message });
      sendError(res, error, "imessage_send_failed");
    }
  });

  app.post("/api/imessage/send", authRequired, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required" });
    try {
      const to = normalizeIMessageE164(req.body?.to);
      const content = cleanString(req.body?.body, MAX_MESSAGE_LENGTH);
      if (!to) return res.status(400).json({ error: "invalid_phone_number" });
      if (!content) return res.status(400).json({ error: "message_body_required" });
      const line = await resolveLine(pool, req.companyId, { refresh: true, fetchImpl });
      if (!line) return res.status(409).json({ error: "imessage_number_selection_required" });
      const conversation = await getOrCreateConversation(pool, line, to);
      const sent = await sendProviderMessage(pool, line, conversation, content, req.userId, { fetchImpl });
      res.status(201).json({ conversation_id: conversation.id, message: sent.message });
    } catch (error) {
      console.error("[imessage/send-new] failed:", { status: error?.status, code: error?.code, message: error?.message });
      sendError(res, error, "imessage_send_failed");
    }
  });

  app.post("/api/imessage/sync", authRequired, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required" });
    try {
      const line = await resolveLine(pool, req.companyId, { refresh: true, fetchImpl });
      if (!line) return res.status(409).json({ error: "imessage_number_selection_required" });
      await syncRecentMessages(pool, line, { force: true, fetchImpl });
      res.json({ ok: true });
    } catch (error) {
      sendError(res, error, "imessage_sync_failed");
    }
  });

  app.get("/api/imessage/unread-count", authRequired, async (req, res) => {
    if (!req.companyId) return res.json({ count: 0 });
    const { rows } = await pool.query(
      `SELECT COUNT(*)::int AS count
         FROM imessage_messages im
         JOIN imessage_conversations ic ON ic.id = im.conversation_id
        WHERE ic.company_id = $1
          AND ic.deleted_at IS NULL
          AND im.deleted_at IS NULL
          AND im.direction = 'inbound'
          AND COALESCE(im.provider_created_at, im.created_at) > COALESCE(ic.last_read_at, '1970-01-01'::timestamptz)`,
      [req.companyId]
    );
    res.json({ count: Number(rows[0]?.count || 0) });
  });

  app.post("/webhooks/texting-blue", async (req, res) => {
    try {
      const secret = cleanString(process.env.TEXTING_BLUE_WEBHOOK_SECRET, 512);
      const rawBody = req.rawBody;
      if (!verifyTextingBlueSignature(rawBody, req.header("x-textingblue-signature"), secret)) {
        return res.status(401).json({ error: "invalid_signature" });
      }
      const event = req.body || {};
      const eventType = cleanString(req.header("x-textingblue-event") || event.type, 100);
      const eventId = cleanString(event.id, 250);
      const providerMessageId = cleanString(event.data?.id, 250);
      if (!eventType || !providerMessageId || !event.data) return res.status(400).json({ error: "invalid_webhook" });

      if (eventId) {
        const inserted = await pool.query(
          `INSERT INTO imessage_webhook_events(event_id, event_type, provider_message_id)
           VALUES($1,$2,$3)
           ON CONFLICT (event_id) DO NOTHING
           RETURNING event_id`,
          [eventId, eventType, providerMessageId]
        );
        if (!inserted.rowCount) return res.json({ received: true, duplicate: true });
      }

      const line = await resolveWebhookLine(pool, event.data);
      if (!line) {
        console.warn("[imessage/webhook] no WolfCRM line mapping; history sync can recover after line setup", { eventType, providerMessageId });
        return res.json({ received: true, mapped: false });
      }

      const saved = await persistProviderMessage(pool, line, event.data);
      const automationEvent = providerEventToAutomationEvent(eventType);
      if (automationEvent) await emitIMessageEvent({ line, saved, eventType: automationEvent });
      await notifyInboundIMessage({ pool, sendCompanyPhonePush, line, saved });
      res.json({ received: true });
    } catch (error) {
      console.error("[imessage/webhook] failed:", { code: error?.code, message: error?.message });
      res.status(500).json({ error: "imessage_webhook_failed" });
    }
  });

  console.log("[imessage] Texting Blue system installed");
}
