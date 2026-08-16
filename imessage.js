import crypto from "crypto";
import { emitAutomationEvent } from "./automations.js";

const TEXTING_BLUE_BASE_URL = (process.env.TEXTING_BLUE_BASE_URL || "https://api.texting.blue/v1").replace(/\/$/, "");
const MAX_MESSAGE_LENGTH = 5000;
const SYNC_COOLDOWN_MS = 30_000;
const recentSyncAt = new Map();

function bearer(req) {
  const header = req.header("authorization") || req.header("Authorization") || "";
  const match = header.match(/^Bearer (.+)$/i);
  return match ? match[1] : null;
}

function cleanString(value, maxLength = 5000) {
  return (value ?? "").toString().trim().slice(0, maxLength);
}

function phoneDigits(value) {
  return cleanString(value, 64).replace(/[^0-9]/g, "");
}

function normalizeE164(value) {
  const raw = cleanString(value, 64);
  if (!raw) return null;
  if (raw.startsWith("+")) {
    const digits = phoneDigits(raw);
    return /^\d{7,15}$/.test(digits) ? `+${digits}` : null;
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
  return normalizeE164(process.env.TEXTING_BLUE_PHONE_NUMBER || "");
}

async function textingBlueRequest(path, { method = "GET", body = null, query = null } = {}) {
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

  const response = await fetch(url, {
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
    const error = new Error(payload?.message || payload?.error || `texting_blue_${response.status}`);
    error.status = response.status;
    error.code = payload?.code || payload?.error || "texting_blue_request_failed";
    error.providerPayload = payload;
    throw error;
  }
  return payload;
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
      ON imessage_messages(conversation_id, created_at);

    CREATE TABLE IF NOT EXISTS imessage_webhook_events (
      event_id TEXT PRIMARY KEY,
      event_type TEXT NOT NULL,
      provider_message_id TEXT,
      received_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}

function createAuthRequired(pool) {
  return async function imessageAuthRequired(req, res, next) {
    try {
      const token = bearer(req);
      if (!token) return res.status(401).json({ error: "unauthorized" });
      const { rows } = await pool.query(
        `UPDATE sessions s
            SET last_used_at = now()
           FROM users u
          WHERE s.token = $1
            AND u.id = s.user_id
            AND u.deleted_at IS NULL
          RETURNING s.user_id, u.email, u.role, u.company_id`,
        [token]
      );
      if (!rows.length) return res.status(401).json({ error: "unauthorized" });
      req.userId = rows[0].user_id;
      req.userEmail = rows[0].email;
      req.role = rows[0].role;
      req.companyId = rows[0].company_id;
      req.sessionToken = token;
      next();
    } catch (error) {
      console.error("[imessage/auth] failed:", { code: error?.code, message: error?.message });
      res.status(500).json({ error: "imessage_auth_failed" });
    }
  };
}

async function findContactId(pool, companyId, phone) {
  const digits = phoneDigits(phone);
  if (!companyId || !digits) return null;
  const local = digits.length === 11 && digits.startsWith("1") ? digits.slice(1) : digits;
  const { rows } = await pool.query(
    `SELECT id
       FROM contacts
      WHERE company_id = $1
        AND (
          regexp_replace(COALESCE(phone,''), '[^0-9]', '', 'g') = $2
          OR (length($3) = 10 AND right(regexp_replace(COALESCE(phone,''), '[^0-9]', '', 'g'), 10) = $3)
        )
      LIMIT 2`,
    [companyId, digits, local]
  );
  return rows.length === 1 ? rows[0].id : null;
}

async function listProviderNumbers() {
  const payload = await textingBlueRequest("/numbers");
  return Array.isArray(payload?.numbers) ? payload.numbers : [];
}

function normalizedProviderNumber(row) {
  return normalizeE164(row?.phone_number || row?.phoneNumber || "");
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

async function resolveLine(pool, companyId, { refresh = true } = {}) {
  if (!companyId) return null;
  const existingResult = await pool.query(
    `SELECT * FROM imessage_lines WHERE company_id = $1 AND provider = 'texting_blue' LIMIT 1`,
    [companyId]
  );
  const existing = existingResult.rows[0] || null;
  if (!refresh && existing) return existing;

  const numbers = await listProviderNumbers();
  if (!numbers.length) return existing;

  const configured = textingBlueConfiguredPhone();
  const companyResult = await pool.query(`SELECT phone FROM companies WHERE id = $1 LIMIT 1`, [companyId]);
  const companyPhone = normalizeE164(companyResult.rows[0]?.phone || "");
  const existingPhone = normalizeE164(existing?.phone_number || "");
  const existingProviderId = cleanString(existing?.provider_number_id, 200);

  let selected = null;
  if (existingProviderId) selected = numbers.find((row) => cleanString(row?.id, 200) === existingProviderId) || null;
  if (!selected && existingPhone) selected = numbers.find((row) => normalizedProviderNumber(row) === existingPhone) || null;
  if (!selected && configured) selected = numbers.find((row) => normalizedProviderNumber(row) === configured) || null;
  if (!selected && companyPhone) selected = numbers.find((row) => normalizedProviderNumber(row) === companyPhone) || null;

  if (!selected && numbers.length === 1) {
    const onlyPhone = normalizedProviderNumber(numbers[0]);
    const claimed = onlyPhone
      ? await pool.query(
          `SELECT company_id FROM imessage_lines WHERE provider = 'texting_blue' AND phone_number = $1 AND company_id <> $2 LIMIT 1`,
          [onlyPhone, companyId]
        )
      : { rowCount: 1 };
    if (!claimed.rowCount) selected = numbers[0];
  }

  if (!selected) return existing;
  return await upsertLine(pool, companyId, selected);
}

function lineConnectionStatus(line) {
  if (!line) return { connected: false, stale: true };
  const active = cleanString(line.status, 40).toLowerCase() === "active";
  const verified = line.verified === true;
  const lastSeen = line.last_seen_at ? new Date(line.last_seen_at) : null;
  const stale = !lastSeen || Number.isNaN(lastSeen.getTime()) || (Date.now() - lastSeen.getTime()) > 5 * 60 * 1000;
  return { connected: active && verified && !stale, stale };
}

async function getOrCreateConversation(pool, line, externalPhone) {
  const external = normalizeE164(externalPhone);
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
  const fromNumber = normalizeE164(providerMessage?.from);
  const toNumber = normalizeE164(providerMessage?.to);
  if (!providerId || !fromNumber || !toNumber) return null;

  const business = normalizeE164(line.phone_number);
  let direction = cleanString(providerMessage?.direction, 20).toLowerCase();
  if (direction !== "inbound" && direction !== "outbound") {
    direction = toNumber === business ? "inbound" : "outbound";
  }
  const external = direction === "inbound" ? fromNumber : toNumber;
  const conversation = await getOrCreateConversation(pool, line, external);
  const providerCreatedAt = providerMessageTimestamp(providerMessage);
  const status = cleanString(providerMessage?.status || (direction === "inbound" ? "received" : "queued"), 80) || null;
  const body = providerMessage?.content === null || providerMessage?.content === undefined
    ? null
    : providerMessage.content.toString().slice(0, MAX_MESSAGE_LENGTH);
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
    [
      conversation.id,
      providerId,
      direction,
      fromNumber,
      toNumber,
      body,
      mediaUrl,
      status,
      errorCode,
      errorMessage,
      providerCreatedAt
    ]
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

async function syncRecentMessages(pool, line, { force = false } = {}) {
  if (!line) return;
  const key = String(line.id);
  const last = recentSyncAt.get(key) || 0;
  if (!force && Date.now() - last < SYNC_COOLDOWN_MS) return;
  recentSyncAt.set(key, Date.now());

  const phone = normalizeE164(line.phone_number);
  if (!phone) return;
  try {
    const [outbound, inbound] = await Promise.all([
      textingBlueRequest("/messages", { query: { from: phone, limit: 100 } }),
      textingBlueRequest("/messages", { query: { to: phone, limit: 100 } })
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

async function emitIMessageEvent({ pool, line, saved, eventType, source = "texting_blue.webhook", actorUserId = null }) {
  if (!saved?.message || !line?.company_id || !eventType) return;
  const payload = {
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
  };
  try {
    await emitAutomationEvent({
      companyId: line.company_id,
      eventType,
      subjectType: "imessage_message",
      subjectId: saved.message.id,
      actorUserId,
      source,
      dedupeKey: `${eventType}:${saved.message.provider_message_id || saved.message.id}`,
      payload
    });
  } catch (error) {
    console.error("[imessage/automation] event failed:", { eventType, code: error?.code, message: error?.message });
  }
}

async function sendProviderMessage(pool, line, conversation, body, actorUserId = null) {
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
    body: {
      to: conversation.external_phone_number,
      from: line.phone_number,
      content
    }
  });
  providerMessage.direction = providerMessage.direction || "outbound";
  const saved = await persistProviderMessage(pool, line, providerMessage);
  await emitIMessageEvent({
    pool,
    line,
    saved,
    eventType: "imessage.outbound_queued",
    source: "wolfcrm.ios",
    actorUserId
  });
  return { ...saved.message, device_may_be_offline: connection.stale };
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

function safeSignatureMatches(req) {
  const secret = cleanString(process.env.TEXTING_BLUE_WEBHOOK_SECRET, 512);
  const signature = cleanString(req.header("x-textingblue-signature"), 512);
  if (!secret || !signature) return false;
  try {
    const reconstructed = Buffer.from(JSON.stringify(req.body ?? {}));
    const expected = `sha256=${crypto.createHmac("sha256", secret).update(reconstructed).digest("hex")}`;
    const left = Buffer.from(signature);
    const right = Buffer.from(expected);
    return left.length === right.length && crypto.timingSafeEqual(left, right);
  } catch (_) {
    return false;
  }
}

async function resolveWebhookLine(pool, providerMessage) {
  const fromNumber = normalizeE164(providerMessage?.from);
  const toNumber = normalizeE164(providerMessage?.to);
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

export async function installIMessageSystem({ app, pool }) {
  await ensureIMessageSchema(pool);
  const authRequired = createAuthRequired(pool);

  app.get("/api/imessage/status", authRequired, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required" });
    if (!textingBlueApiKey()) {
      return res.json({ configured: false, connected: false, provider: "texting_blue", error: "imessage_not_configured" });
    }
    try {
      const line = await resolveLine(pool, req.companyId, { refresh: true });
      if (!line) {
        return res.json({
          configured: true,
          connected: false,
          provider: "texting_blue",
          error: "imessage_number_selection_required"
        });
      }
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
      res.status(error?.status || 500).json({ error: error?.code || "imessage_status_failed", message: error?.message });
    }
  });

  app.get("/api/imessage/conversations", authRequired, async (req, res) => {
    if (!req.companyId) return res.json([]);
    try {
      const line = await resolveLine(pool, req.companyId, { refresh: true });
      if (!line) return res.json([]);
      await syncRecentMessages(pool, line);
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
      res.status(error?.status || 500).json({ error: error?.code || "imessage_conversations_failed", message: error?.message });
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
      const lineResult = await pool.query(`SELECT * FROM imessage_lines WHERE id = $1 LIMIT 1`, [owned.rows[0].line_id]);
      if (lineResult.rows[0]) await syncRecentMessages(pool, lineResult.rows[0]);
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
      res.status(error?.status || 500).json({ error: error?.code || "imessage_messages_failed", message: error?.message });
    }
  });

  app.post("/api/imessage/conversations/:id/messages", authRequired, async (req, res) => {
    if (!req.companyId) return res.status(404).json({ error: "conversation_not_found" });
    try {
      const content = cleanString(req.body?.body, MAX_MESSAGE_LENGTH);
      if (!content) return res.status(400).json({ error: "message_body_required" });
      const { rows } = await pool.query(
        `SELECT ic.*, il.phone_number, il.status, il.verified, il.last_seen_at, il.company_id
           FROM imessage_conversations ic
           JOIN imessage_lines il ON il.id = ic.line_id
          WHERE ic.id = $1 AND ic.company_id = $2 AND ic.deleted_at IS NULL
          LIMIT 1`,
        [req.params.id, req.companyId]
      );
      if (!rows.length) return res.status(404).json({ error: "conversation_not_found" });
      const row = rows[0];
      const line = {
        id: row.line_id,
        company_id: row.company_id,
        phone_number: row.phone_number,
        status: row.status,
        verified: row.verified,
        last_seen_at: row.last_seen_at
      };
      const message = await sendProviderMessage(pool, line, row, content, req.userId);
      res.status(201).json(message);
    } catch (error) {
      console.error("[imessage/send] failed:", { status: error?.status, code: error?.code, message: error?.message });
      res.status(error?.status || 500).json({ error: error?.code || "imessage_send_failed", message: error?.message });
    }
  });

  app.post("/api/imessage/send", authRequired, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required" });
    try {
      const to = normalizeE164(req.body?.to);
      const content = cleanString(req.body?.body, MAX_MESSAGE_LENGTH);
      if (!to) return res.status(400).json({ error: "invalid_phone_number" });
      if (!content) return res.status(400).json({ error: "message_body_required" });
      const line = await resolveLine(pool, req.companyId, { refresh: true });
      if (!line) return res.status(409).json({ error: "imessage_number_selection_required" });
      const conversation = await getOrCreateConversation(pool, line, to);
      const message = await sendProviderMessage(pool, line, conversation, content, req.userId);
      res.status(201).json({ conversation_id: conversation.id, message });
    } catch (error) {
      console.error("[imessage/send-new] failed:", { status: error?.status, code: error?.code, message: error?.message });
      res.status(error?.status || 500).json({ error: error?.code || "imessage_send_failed", message: error?.message });
    }
  });

  app.post("/api/imessage/sync", authRequired, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required" });
    try {
      const line = await resolveLine(pool, req.companyId, { refresh: true });
      if (!line) return res.status(409).json({ error: "imessage_number_selection_required" });
      await syncRecentMessages(pool, line, { force: true });
      res.json({ ok: true });
    } catch (error) {
      res.status(error?.status || 500).json({ error: error?.code || "imessage_sync_failed", message: error?.message });
    }
  });

  app.post("/webhooks/texting-blue", async (req, res) => {
    try {
      const eventType = cleanString(req.header("x-textingblue-event") || req.body?.type, 100);
      const eventId = cleanString(req.body?.id, 250);
      const providerMessageId = cleanString(req.body?.data?.id, 250);
      if (!eventType || !providerMessageId) return res.status(400).json({ error: "invalid_webhook" });

      if (eventId) {
        const duplicate = await pool.query(`SELECT event_id FROM imessage_webhook_events WHERE event_id = $1 LIMIT 1`, [eventId]);
        if (duplicate.rowCount) return res.json({ received: true, duplicate: true });
      }

      // Express' global JSON parser runs before this modular route, so exact raw bytes are
      // not always available for HMAC comparison. We try the signature first, then verify
      // the message against Texting Blue's authenticated GET /messages/:id endpoint.
      const signatureMatches = safeSignatureMatches(req);
      let providerMessage;
      try {
        providerMessage = await textingBlueRequest(`/messages/${encodeURIComponent(providerMessageId)}`);
      } catch (providerError) {
        console.error("[imessage/webhook] provider verification failed:", { eventType, providerMessageId, status: providerError?.status, code: providerError?.code });
        return res.status(503).json({ error: "provider_verification_failed" });
      }
      if (!providerMessage || cleanString(providerMessage.id, 250) !== providerMessageId) {
        return res.status(401).json({ error: "invalid_webhook" });
      }

      const line = await resolveWebhookLine(pool, providerMessage);
      if (!line) {
        console.warn("[imessage/webhook] no WolfCRM line mapping; history sync will recover", { eventType, providerMessageId });
        return res.json({ received: true, mapped: false, signature_matches: signatureMatches });
      }

      const saved = await persistProviderMessage(pool, line, providerMessage);
      const automationEvent = providerEventToAutomationEvent(eventType);
      if (automationEvent) {
        await emitIMessageEvent({ pool, line, saved, eventType: automationEvent });
      }
      if (eventId) {
        await pool.query(
          `INSERT INTO imessage_webhook_events(event_id, event_type, provider_message_id)
           VALUES($1,$2,$3)
           ON CONFLICT (event_id) DO NOTHING`,
          [eventId, eventType, providerMessageId]
        );
      }
      res.json({ received: true, signature_matches: signatureMatches });
    } catch (error) {
      console.error("[imessage/webhook] failed:", { code: error?.code, message: error?.message });
      res.status(500).json({ error: "imessage_webhook_failed" });
    }
  });

  console.log("[imessage] Texting Blue system installed");
}
