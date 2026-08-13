/* WolfCRM backend — email/password auth + user-scoped CRM data */
/* WolfCRM backend auto-sync verification */
/* WolfCRM direct-repo auto-sync verification 1 */
/* WolfCRM direct-repo auto-sync verification 2 */
/* WolfCRM post-reload auto-sync verification */
/* Railway deploy smoke-test touch: 2026-08-12 */
import express from "express";
import cors from "cors";
import { randomUUID, randomBytes, scryptSync, timingSafeEqual } from "crypto";
import pkg from "pg";
import { S3Client, PutObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import Stripe from "stripe";
import apn from "@parse/node-apn";
import twilio from "twilio";
import { calculateStripeConnectReadiness } from "./stripe-connect-status.js";
import {
  isStripePaymentCollectionPaused,
  mapStripePaymentIntentStatus,
  mapStripeSubscriptionStatus as mapStripeSubscriptionStatusValue,
  mapStripeSubscriptionToWolfCRMStatus,
  nextServiceDateAfterResume,
  selectRecoverableSubscription,
  subscriptionBlocksNewStart,
  subscriptionCanResumePayment,
  stripeSubscriptionCustomerId
} from "./stripe-payment-sync.js";
import {
  installAutomationSystem,
  emitAutomationEvent,
  syncAutomationSchedulesForJob,
  syncAutomationSchedulesForTask,
  syncAutomationSchedulesForRoutine,
  syncAutomationSchedulesForCustomerReminder,
  cancelAutomationSchedulesForSubject,
  syncAutomationSchedulesForSmsOutbound,
  syncAutomationSchedulesForSmsConversationActivity,
  cancelNoReplySchedulesForConversation,
  syncAutomationSchedulesForVoicemail,
  recordPhoneSmsConsent,
  syncAutomationSchedulesForQuote,
  syncAutomationSchedulesForInvoice,
  syncAutomationSchedulesForServicePlan,
  syncAutomationSchedulesForMapPin,
  syncAutomationSchedulesForTimeEntry
} from "./automations.js";
import { installFinanceSystem, loadProjection } from "./finance.js";

const { Pool } = pkg;
const app = express();
const PORT = process.env.PORT || 8080;

const useSSL =
  process.env.DB_SSL === "true" ||
  (process.env.DATABASE_URL && process.env.DATABASE_URL.includes("railway.app"));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: useSSL ? { rejectUnauthorized: false } : false
});

// ---------- APNs client (lazy) ----------
// Real Apple push. Delivers even when the app is closed and the phone is
// locked. Requires env vars:
//   APNS_KEY_P8         Contents of your .p8 auth key (PEM, or base64-encoded PEM)
//   APNS_KEY_ID         Key ID from developer.apple.com
//   APNS_TEAM_ID        Your Apple Developer team ID
//   APNS_BUNDLE_ID      Your app's bundle ID (topic)
//   APNS_PRODUCTION     fallback environment for old tokens without stored environment
const apnProviderInstances = new Map();
function getApnProvider(environment = null) {
  const production = environment
    ? environment === "production"
    : process.env.APNS_PRODUCTION === "true";
  const cacheKey = production ? "production" : "sandbox";
  if (apnProviderInstances.has(cacheKey)) return apnProviderInstances.get(cacheKey);
  let keyPem = process.env.APNS_KEY_P8 || "";
  const keyId = process.env.APNS_KEY_ID || "";
  const teamId = process.env.APNS_TEAM_ID || "";
  if (!keyPem || !keyId || !teamId) return null;
  // Support base64-encoded p8 in env (avoids newline hassles on some hosts).
  if (!keyPem.includes("BEGIN PRIVATE KEY")) {
    try { keyPem = Buffer.from(keyPem, "base64").toString("utf8"); } catch (_) {}
  }
  try {
    const provider = new apn.Provider({
      token: { key: keyPem, keyId, teamId },
      production
    });
    apnProviderInstances.set(cacheKey, provider);
  } catch (e) {
    console.error("[apns] provider init failed:", e && e.message ? e.message : e);
    return null;
  }
  return apnProviderInstances.get(cacheKey);
}

async function sendApnsPush(deviceTokens, { title, body, contactId, payload = {}, badge = null, threadId = null }) {
  const bundleId = process.env.APNS_BUNDLE_ID;
  if (!bundleId) {
    return { sent: 0, failed: 0, skipped: true, reason: "not_configured" };
  }
  if (!Array.isArray(deviceTokens) || deviceTokens.length === 0) {
    return { sent: 0, failed: 0, skipped: true, reason: "no_tokens" };
  }
  const note = new apn.Notification();
  note.alert = { title, body: body || "" };
  note.sound = "default";
  note.topic = bundleId;
  note.expiry = Math.floor(Date.now() / 1000) + 3600;
  if (Number.isInteger(badge) && badge >= 0) note.badge = badge;
  if (threadId) note.threadId = threadId;
  note.payload = { ...payload };
  if (contactId) note.payload.contact_id = contactId;
  try {
    const tokenRows = deviceTokens.map((entry) => {
      if (typeof entry === "string") {
        return {
          token: entry,
          environment: process.env.APNS_PRODUCTION === "true" ? "production" : "sandbox"
        };
      }
      return {
        token: entry.token,
        environment: entry.environment === "production" ? "production" : "sandbox"
      };
    }).filter((entry) => entry.token);
    const groups = tokenRows.reduce((acc, entry) => {
      acc[entry.environment] = acc[entry.environment] || [];
      acc[entry.environment].push(entry.token);
      return acc;
    }, {});
    let sent = 0;
    let failed = 0;
    const badTokens = [];
    for (const [environment, tokens] of Object.entries(groups)) {
      const provider = getApnProvider(environment);
      if (!provider) {
        console.error("[apns] provider missing for environment", { environment });
        failed += tokens.length;
        continue;
      }
      console.log("[apns] sending", { environment, tokenCount: tokens.length, payloadType: note.payload?.type || null });
      const result = await provider.send(note, tokens);
      sent += (result.sent || []).length;
      failed += (result.failed || []).length;
      for (const failure of (result.failed || [])) {
        console.error("[apns] failed", {
          environment,
          status: failure.status,
          reason: failure.response?.reason || failure.error?.message || "unknown"
        });
      }
      badTokens.push(...(result.failed || [])
        .filter(f => f.status === "410" || (f.response && f.response.reason === "Unregistered"))
        .map(f => f.device));
    }
    // Prune tokens Apple flagged as unregistered so we stop sending to dead devices.
    if (badTokens.length) {
      try {
        await pool.query(`DELETE FROM device_tokens WHERE token = ANY($1::text[])`, [badTokens]);
      } catch (_) {}
    }
    return { sent, failed };
  } catch (e) {
    console.error("[apns] send failed:", e && e.message ? e.message : e);
    return { sent: 0, failed: deviceTokens.length, error: "send_failed" };
  }
}

async function deviceTokensForCompany(companyId) {
  if (!companyId) return [];
  const { rows } = await pool.query(
    `SELECT DISTINCT dt.token, COALESCE(dt.environment, CASE WHEN $2::boolean THEN 'production' ELSE 'sandbox' END) AS environment
       FROM device_tokens dt
       JOIN users u ON u.id = dt.user_id
      WHERE u.company_id = $1
        AND u.deleted_at IS NULL
        AND u.role = 'employer'`,
    [companyId, process.env.APNS_PRODUCTION === "true"]
  );
  return rows.map((row) => ({ token: row.token, environment: row.environment })).filter((row) => row.token);
}

async function deviceTokensForUsers(userIds) {
  const ids = [...new Set((userIds || []).filter(Boolean))];
  if (!ids.length) return [];
  const { rows } = await pool.query(
    `SELECT dt.token,
            COALESCE(dt.environment, CASE WHEN $2::boolean THEN 'production' ELSE 'sandbox' END) AS environment,
            dt.user_id
       FROM device_tokens dt
      WHERE dt.user_id = ANY($1::uuid[])`,
    [ids, process.env.APNS_PRODUCTION === "true"]
  );
  return rows.map((row) => ({ token: row.token, environment: row.environment, userId: row.user_id })).filter((row) => row.token);
}

const DEFAULT_PUSH_CATEGORIES = {
  cellular_sms: true,
  missed_call: true,
  voicemail: true,
  internal_message: true,
  channel_message: true,
  job_assignment: true,
  job_scheduled: true
};

function normalizePushCategories(value) {
  const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  return { ...DEFAULT_PUSH_CATEGORIES, ...source };
}

async function shouldSendPush({ userId, category }) {
  if (!userId || !category) return false;
  const { rows } = await pool.query(
    `SELECT notifications_enabled, notification_categories
       FROM zapier_tokens
      WHERE user_id = $1
      LIMIT 1`,
    [userId]
  );
  if (!rows.length) {
    return category === "new_lead" ? false : true;
  }
  if (category === "new_lead") {
    return !!rows[0].notifications_enabled;
  }
  const categories = normalizePushCategories(rows[0].notification_categories);
  return categories[category] !== false;
}

async function pushEligibleUsers(userIds, category) {
  const eligible = [];
  for (const userId of [...new Set((userIds || []).filter(Boolean))]) {
    try {
      if (await shouldSendPush({ userId, category })) eligible.push(userId);
      else console.log("[push] skipped", { category, userId, reason: "preference_disabled" });
    } catch (e) {
      console.error("[push] preference check failed:", { category, userId, code: e?.code, message: e?.message });
    }
  }
  return eligible;
}

async function sendPushToUsers(userIds, category, options) {
  const eligible = await pushEligibleUsers(userIds, category);
  console.log("[push] event", { category, userCount: eligible.length });
  if (!eligible.length) return { skipped: true, reason: "preference_disabled" };
  const tokens = await deviceTokensForUsers(eligible);
  if (!tokens.length) return { skipped: true, reason: "no_device_tokens" };
  const result = await sendApnsPush(tokens, options);
  console.log("[push] sent", { category, sent: result.sent || 0, failed: result.failed || 0, skipped: result.skipped || false });
  return result;
}

async function employerUserIdsForCompany(companyId) {
  if (!companyId) return [];
  const { rows } = await pool.query(
    `SELECT id
       FROM users
      WHERE company_id = $1
        AND deleted_at IS NULL
        AND role = 'employer'
      ORDER BY created_at ASC, id ASC`,
    [companyId]
  );
  return rows.map((row) => row.id);
}

async function phoneUnreadBadgeCount(companyId) {
  if (!companyId) return 0;
  const { rows } = await pool.query(
    `SELECT
       COALESCE((
         SELECT COUNT(*)
           FROM sms_messages sm
           JOIN sms_conversations sc ON sc.id = sm.conversation_id
           JOIN phone_lines pl ON pl.id = sc.phone_line_id
          WHERE pl.company_id = $1
            AND sc.deleted_at IS NULL
            AND sm.deleted_at IS NULL
            AND sm.direction = 'inbound'
            AND sm.created_at > COALESCE(sc.last_read_at, '1970-01-01'::timestamptz)
       ), 0)::int
       +
       COALESCE((
         SELECT COUNT(*)
           FROM voicemails vm
          WHERE vm.company_id = $1
            AND vm.deleted_at IS NULL
            AND vm.is_read = false
       ), 0)::int AS count`,
    [companyId]
  );
  return Number(rows[0]?.count || 0);
}

async function sendCompanyPhonePush(companyId, options) {
  try {
    const tokens = await deviceTokensForCompany(companyId);
    console.log("[apns] company users/device tokens resolved", { companyId, tokenCount: tokens.length });
    if (!tokens.length) return { skipped: true, reason: "no_device_tokens" };
    const badge = await phoneUnreadBadgeCount(companyId).catch(() => null);
    return await sendApnsPush(tokens, { ...options, badge });
  } catch (e) {
    console.error("[phone/apns] push failed:", { code: e?.code, message: e?.message });
    return { sent: 0, failed: 0, error: "phone_push_failed" };
  }
}

async function sendMissedCallPush({ companyId, callId, externalPhone, contactId }) {
  if (!companyId || !externalPhone) return;
  let caller = externalPhone;
  if (contactId) {
    const contact = await pool.query(
      `SELECT name FROM contacts WHERE id = $1 AND company_id = $2 LIMIT 1`,
      [contactId, companyId]
    );
    const name = (contact.rows[0]?.name || "").toString().trim();
    if (name) caller = name;
  }
  const userIds = await employerUserIdsForCompany(companyId);
  const badge = await phoneUnreadBadgeCount(companyId).catch(() => null);
  await sendPushToUsers(userIds, "missed_call", {
    title: `Missed call from ${caller}`,
    body: "Tap to call or text back.",
    badge,
    contactId: contactId || undefined,
    threadId: callId ? `missed_call_${callId}` : "missed_call",
    payload: {
      type: "missed_call",
      call_id: callId || null,
      external_phone_number: externalPhone,
      contact_id: contactId || null
    }
  });
}

// ---------- Stripe client (lazy) ----------
// Only initialised when a route actually needs it, so missing keys never
// crash the process. Every Stripe route below calls `requireStripe(res)`
// which returns a live client or sends a clear 503 error.
let stripeClient = null;
function getStripe() {
  if (stripeClient) return stripeClient;
  const secret = process.env.STRIPE_SECRET_KEY;
  if (!secret) return null;
  stripeClient = new Stripe(secret, { apiVersion: "2024-06-20" });
  return stripeClient;
}
function requireStripe(res) {
  const s = getStripe();
  if (!s) {
    res.status(503).json({ error: "stripe_not_configured" });
    return null;
  }
  return s;
}
const STRIPE_PLATFORM_FEE_BPS = Math.max(
  0,
  Math.min(10000, parseInt(process.env.STRIPE_PLATFORM_FEE_BPS || "0", 10) || 0)
);
// Stripe iOS 26.6.0 still sends Stripe-Version 2020-08-27. PaymentSheet
// consumes these ephemeral keys on-device, so mint them for the mobile SDK's
// expected API version instead of the server client's newer API version.
const STRIPE_MOBILE_EPHEMERAL_KEY_API_VERSION = "2020-08-27";
const STRIPE_CONNECT_RETURN_URL = process.env.STRIPE_CONNECT_RETURN_URL
  || "https://wolfcrm-backend-production.up.railway.app/stripe/connect/return";
const STRIPE_CONNECT_REFRESH_URL = process.env.STRIPE_CONNECT_REFRESH_URL
  || "https://wolfcrm-backend-production.up.railway.app/stripe/connect/refresh";

app.use(cors());

// Stripe webhook MUST see the raw request body for signature verification.
// It has to be registered BEFORE the global JSON body parser below so the
// raw bytes aren't consumed. The handler is defined further down but the
// raw-body middleware for that exact path lives here.
app.use("/stripe/webhook", express.raw({ type: "application/json", limit: "2mb" }));
app.use("/stripe/connect-webhook", express.raw({ type: "application/json", limit: "2mb" }));

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false, limit: "2mb" }));

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    phone_calls_route: true,
    incoming_voice_route: true,
    sms_route: true
  });
});

const mediaBucketConfig = () => {
  const endpoint = process.env.MEDIA_ENDPOINT || process.env.AWS_ENDPOINT_URL;
  const bucket = process.env.MEDIA_BUCKET || process.env.AWS_S3_BUCKET_NAME;
  const region = process.env.MEDIA_REGION || process.env.AWS_DEFAULT_REGION || "auto";
  const accessKeyId = process.env.MEDIA_ACCESS_KEY_ID || process.env.AWS_ACCESS_KEY_ID;
  const secretAccessKey = process.env.MEDIA_SECRET_ACCESS_KEY || process.env.AWS_SECRET_ACCESS_KEY;
  if (!endpoint || !bucket || !accessKeyId || !secretAccessKey) return null;
  return { endpoint, bucket, region, accessKeyId, secretAccessKey };
};

let mediaS3Client = null;
const getMediaS3Client = () => {
  const cfg = mediaBucketConfig();
  if (!cfg) return null;
  if (!mediaS3Client) {
    mediaS3Client = new S3Client({
      endpoint: cfg.endpoint,
      region: cfg.region,
      forcePathStyle: true,
      credentials: {
        accessKeyId: cfg.accessKeyId,
        secretAccessKey: cfg.secretAccessKey
      }
    });
  }
  return mediaS3Client;
};

// ---------- helpers ----------
const nowIso = () => new Date().toISOString();
const bearer = (req) => {
  const h = req.header("authorization") || req.header("Authorization") || "";
  const m = h.match(/^Bearer (.+)$/i);
  return m ? m[1] : null;
};

const twilioConfig = () => {
  const accountSid = (process.env.TWILIO_ACCOUNT_SID || "").trim();
  const apiKeySid = (process.env.TWILIO_API_KEY_SID || "").trim();
  const apiKeySecret = (process.env.TWILIO_API_KEY_SECRET || "").trim();
  const webhookBaseUrl = (process.env.TWILIO_WEBHOOK_BASE_URL || "").trim();
  const configured = Boolean(accountSid && apiKeySid && apiKeySecret && webhookBaseUrl);
  return { configured, accountSid, apiKeySid, apiKeySecret, webhookBaseUrl };
};

const createTwilioClient = () => {
  const { configured, accountSid, apiKeySid, apiKeySecret } = twilioConfig();
  if (!configured) return null;
  return twilio(apiKeySid, apiKeySecret, { accountSid });
};

const normalizeE164Phone = (value) => {
  const raw = (value || "").toString().trim();
  if (!raw) return "";
  if (raw.startsWith("+")) {
    const digits = raw.slice(1).replace(/[^\d]/g, "");
    return digits ? `+${digits}` : "";
  }
  const digits = raw.replace(/[^\d]/g, "");
  if (digits.length === 10) return `+1${digits}`;
  if (digits.length === 11 && digits.startsWith("1")) return `+${digits}`;
  return digits ? `+${digits}` : "";
};

const phoneDigits = (value) => (value || "").toString().replace(/[^\d]/g, "");
const MAX_SMS_BODY_LENGTH = 1600;
const isUsableE164 = (value) => /^\+[1-9]\d{6,14}$/.test((value || "").toString());
const VOICE_TOKEN_TTL_SECONDS = 3600;

const twilioVoiceConfig = () => {
  const { accountSid, apiKeySid, apiKeySecret } = twilioConfig();
  const twimlAppSid = (process.env.TWILIO_TWIML_APP_SID || "").trim();
  const pushCredentialSid = (process.env.TWILIO_PUSH_CREDENTIAL_SID || "").trim();
  const configured = Boolean(accountSid && apiKeySid && apiKeySecret && twimlAppSid);
  return { configured, accountSid, apiKeySid, apiKeySecret, twimlAppSid, pushCredentialSid };
};

const voiceIdentityForUserID = (userID) => {
  const hex = (userID || "").toString().replace(/-/g, "").toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(hex)) return null;
  return `wolfcrm_${hex}`;
};

const uuidFromVoiceIdentity = (identity) => {
  const raw = (identity || "").toString().trim();
  const clean = raw.startsWith("client:") ? raw.slice("client:".length) : raw;
  const match = clean.match(/^wolfcrm_([0-9a-f]{32})$/i);
  if (!match) return null;
  const hex = match[1].toLowerCase();
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
};

const callDispositionForStatus = (status) => {
  const s = (status || "").toString().trim().toLowerCase();
  if (s === "completed") return "completed";
  if (s === "busy") return "busy";
  if (s === "no-answer") return "missed";
  if (s === "canceled" || s === "cancelled") return "canceled";
  if (s === "failed") return "failed";
  return null;
};

const callAutomationEventTypes = ({ status, disposition, direction, durationSeconds }) => {
  const s = (status || "").toString().trim().toLowerCase();
  const d = (disposition || "").toString().trim().toLowerCase();
  const events = [];
  if (s === "ringing") events.push("call.ringing");
  if (s === "in-progress" || s === "answered") events.push("call.answered", "call.connected");
  if (s === "completed") events.push("call.completed");
  if (d === "busy") events.push("call.busy");
  if (d === "missed") events.push("call.no_answer");
  if (d === "failed") events.push("call.failed");
  if (direction === "inbound" && ["busy", "missed", "failed", "canceled"].includes(d)) events.push("call.missed");
  if (s === "completed" && Number(durationSeconds || 0) > 0) {
    if (Number(durationSeconds) <= 30) events.push("call.short_call");
    if (Number(durationSeconds) >= 300) events.push("call.long_call");
  }
  return [...new Set(events)];
};

async function emitCallAutomationEvents({ companyId, callId, callSid, eventTypes, payload }) {
  for (const eventType of eventTypes) {
    await emitAutomationEvent({
      companyId,
      eventType,
      subjectType: "call",
      subjectId: callId,
      source: "twilio.voice",
      dedupeKey: `${eventType}:${callId || callSid}`,
      payload
    });
  }
}

const emptyMessagingResponse = () => {
  const response = new twilio.twiml.MessagingResponse();
  return response.toString();
};

const twilioPublicUrl = (path) => {
  const base = (process.env.TWILIO_WEBHOOK_BASE_URL || "").trim().replace(/\/+$/, "");
  const cleanPath = (path || "").toString().startsWith("/") ? path : `/${path || ""}`;
  return `${base}${cleanPath}`;
};

const twilioWebhookUrl = (req) => twilioPublicUrl(req.originalUrl);

const validateTwilioWebhook = (req) => {
  const authToken = (process.env.TWILIO_AUTH_TOKEN || "").trim();
  if (!authToken) return { ok: false, error: "twilio_auth_token_missing" };
  const signature = req.header("X-Twilio-Signature") || "";
  if (!signature) return { ok: false, error: "twilio_signature_missing" };
  const valid = twilio.validateRequest(authToken, signature, twilioWebhookUrl(req), req.body || {});
  return { ok: valid, error: valid ? null : "twilio_signature_invalid" };
};

const twilioMediaMetadata = (body) => {
  const count = Math.max(0, parseInt(body.NumMedia || "0", 10) || 0);
  const media = [];
  for (let i = 0; i < count; i += 1) {
    media.push({
      index: i,
      url: body[`MediaUrl${i}`] || null,
      contentType: body[`MediaContentType${i}`] || null
    });
  }
  return { count, media };
};

const safeSmsMediaArray = (value) => {
  if (Array.isArray(value)) return value;
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed : [];
    } catch (_) {
      return [];
    }
  }
  return [];
};

async function fetchTwilioResource(url) {
  const accountSid = (process.env.TWILIO_ACCOUNT_SID || "").trim();
  const authToken = (process.env.TWILIO_AUTH_TOKEN || "").trim();
  if (!accountSid || !authToken) {
    const error = new Error("twilio_auth_not_configured");
    error.status = 503;
    throw error;
  }
  const response = await fetch(url, {
    headers: {
      Authorization: `Basic ${Buffer.from(`${accountSid}:${authToken}`).toString("base64")}`
    }
  });
  if (!response.ok) {
    const error = new Error("twilio_fetch_failed");
    error.status = response.status;
    throw error;
  }
  return response;
}

const buildRecordingAudioUrl = (recordingSid) => {
  const accountSid = (process.env.TWILIO_ACCOUNT_SID || "").trim();
  return `https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Recordings/${recordingSid}.mp3`;
};

async function findSmsContactID({ companyId, externalPhone }) {
  const normalized = normalizeE164Phone(externalPhone);
  const digits = phoneDigits(normalized || externalPhone);
  if (!companyId || !digits) return null;
  const localDigits = digits.length === 11 && digits.startsWith("1") ? digits.slice(1) : digits;
  const { rows } = await pool.query(
    `SELECT id
       FROM contacts
      WHERE company_id = $1
        AND (
          regexp_replace(COALESCE(phone,''), '[^0-9]', '', 'g') = $2
          OR (
            length($3) = 10
            AND right(regexp_replace(COALESCE(phone,''), '[^0-9]', '', 'g'), 10) = $3
          )
        )
      LIMIT 2`,
    [companyId, digits, localDigits]
  );
  return rows.length === 1 ? rows[0].id : null;
}

const contactMatchJoinSQL = (phoneExpr, companyExpr) => `
  LEFT JOIN LATERAL (
    SELECT CASE WHEN COUNT(*) = 1 THEN MIN(c.id::text) ELSE NULL END AS id,
           CASE WHEN COUNT(*) = 1 THEN MIN(c.name) ELSE NULL END AS name
      FROM contacts c
     WHERE c.company_id = ${companyExpr}
       AND regexp_replace(COALESCE(c.phone,''), '[^0-9]', '', 'g') <> ''
       AND regexp_replace(COALESCE(${phoneExpr},''), '[^0-9]', '', 'g') <> ''
       AND (
         regexp_replace(COALESCE(c.phone,''), '[^0-9]', '', 'g') = regexp_replace(COALESCE(${phoneExpr},''), '[^0-9]', '', 'g')
         OR (
           length(regexp_replace(COALESCE(${phoneExpr},''), '[^0-9]', '', 'g')) IN (10, 11)
           AND right(regexp_replace(COALESCE(c.phone,''), '[^0-9]', '', 'g'), 10) =
               right(regexp_replace(COALESCE(${phoneExpr},''), '[^0-9]', '', 'g'), 10)
         )
       )
  ) matched_contacts ON true
`;

const normalizeEmail = (email) => (email || "").toString().trim().toLowerCase();
const passwordIsValid = (password) =>
  typeof password === "string" &&
  password.length >= 8 &&
  /[A-Z]/.test(password) &&
  /[0-9]/.test(password) &&
  /[^A-Za-z0-9]/.test(password);
const companyCodeIsValid = (code) => /^[A-Za-z0-9]{8,15}$/.test((code || "").toString());
const hashPassword = (password) => {
  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
};
const verifyPassword = (password, stored) => {
  if (!stored || !stored.includes(":")) return false;
  const [salt, key] = stored.split(":");
  const hash = scryptSync(password, salt, 64);
  const storedHash = Buffer.from(key, "hex");
  return storedHash.length === hash.length && timingSafeEqual(storedHash, hash);
};

// Email via Resend (fallback to console)
async function sendEmailCode(email, code, expiresIso, purpose = "reset") {
  const key = process.env.RESEND_API_KEY;
  const from = process.env.RESEND_FROM || "WolfCRM <no-reply@wolfcrm.local>";
  const subject = purpose === "reset" ? "Your WolfCRM password reset code" : "Your WolfCRM code";
  const text =
    `Your WolfCRM code is ${code}\n\n` +
    `It expires at ${expiresIso}\n\n` +
    `If you didn’t request this, you can ignore this email.`;

  if (!key) {
    console.log(`[DEV EMAIL CODE:${purpose}] ${email} -> ${code} (expires ${expiresIso})`);
    return { delivery: "console" };
  }

  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ from, to: [email], subject, text })
  });

  if (!r.ok) {
    const msg = await r.text().catch(() => "");
    console.error("Resend error:", r.status, msg);
    console.log(`[DEV MAGIC CODE] ${email} -> ${code} (expires ${expiresIso})`);
    return { delivery: "console" };
  }
  return { delivery: "email" };
}

// ---------- bootstrap (schema + one-time backfill) ----------
async function bootstrap() {
  await pool.query(`
    CREATE EXTENSION IF NOT EXISTS pgcrypto;

    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT,
      role TEXT NOT NULL DEFAULT 'employer',
      company_id UUID,
      display_name TEXT,
      photo_url TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    -- Soft-delete columns for revoking employee access without destroying
    -- their historical contributions (contacts, quotes, jobs, etc.).
    ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_by UUID;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS pre_delete_email TEXT;
    CREATE INDEX IF NOT EXISTS users_deleted_at_idx ON users(deleted_at);

    CREATE TABLE IF NOT EXISTS companies (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL DEFAULT 'Company',
      join_code TEXT UNIQUE NOT NULL,
      logo_data_url TEXT,
      website TEXT,
      address TEXT,
      phone TEXT,
      email TEXT,
      owner_user_id UUID,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS companies_join_code_idx ON companies(join_code);

    CREATE TABLE IF NOT EXISTS employee_permissions (
      user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      company_id UUID REFERENCES companies(id) ON DELETE CASCADE,
      can_delete_contacts BOOLEAN NOT NULL DEFAULT false,
      can_view_finance BOOLEAN NOT NULL DEFAULT false,
      can_use_finance_ai BOOLEAN NOT NULL DEFAULT false,
      can_view_finance_transactions BOOLEAN NOT NULL DEFAULT false,
      can_edit_finance_transactions BOOLEAN NOT NULL DEFAULT false,
      can_view_finance_accounts BOOLEAN NOT NULL DEFAULT false,
      can_create_finance_accounts BOOLEAN NOT NULL DEFAULT false,
      can_edit_finance_accounts BOOLEAN NOT NULL DEFAULT false,
      can_adjust_finance_account_balances BOOLEAN NOT NULL DEFAULT false,
      can_view_finance_receipts BOOLEAN NOT NULL DEFAULT false,
      can_edit_finance_receipts BOOLEAN NOT NULL DEFAULT false,
      can_view_finance_planning BOOLEAN NOT NULL DEFAULT false,
      can_edit_finance_planning BOOLEAN NOT NULL DEFAULT false,
      can_view_finance_budgets BOOLEAN NOT NULL DEFAULT false,
      can_edit_finance_budgets BOOLEAN NOT NULL DEFAULT false,
      can_view_finance_goals BOOLEAN NOT NULL DEFAULT false,
      can_edit_finance_goals BOOLEAN NOT NULL DEFAULT false,
      can_view_finance_debts BOOLEAN NOT NULL DEFAULT false,
      can_edit_finance_debts BOOLEAN NOT NULL DEFAULT false,
      can_view_finance_settings BOOLEAN NOT NULL DEFAULT false,
      can_edit_finance_settings BOOLEAN NOT NULL DEFAULT false,
      can_manage_company_finance_ai_memories BOOLEAN NOT NULL DEFAULT false,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS password_reset_codes (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT NOT NULL,
      code TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS password_reset_codes_email_idx ON password_reset_codes(email);

    CREATE TABLE IF NOT EXISTS magic_tokens (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT NOT NULL,
      code TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS magic_tokens_email_idx ON magic_tokens(email);

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      last_used_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS contacts (
      id UUID PRIMARY KEY,
      -- We'll add user_id below if missing
      company_id UUID,
      name TEXT NOT NULL,
      phone TEXT,
      email TEXT,
      address TEXT,
      value_cents INTEGER,
      lat DOUBLE PRECISION,
      lng DOUBLE PRECISION,
      tags TEXT,
      job_type TEXT,
      u1 TEXT, u2 TEXT, u3 TEXT, u4 TEXT, u5 TEXT,
      lead_info JSONB,
      deleted_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS contacts_updated_idx ON contacts(updated_at DESC);
    ALTER TABLE contacts ADD COLUMN IF NOT EXISTS lead_info JSONB;

    CREATE TABLE IF NOT EXISTS crm_routes (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID,
      user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      name TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'saved',
      start_label TEXT,
      start_latitude DOUBLE PRECISION,
      start_longitude DOUBLE PRECISION,
      start_mode TEXT NOT NULL DEFAULT 'current_location',
      ending_behavior TEXT NOT NULL DEFAULT 'finish_at_final_stop',
      distance_meters DOUBLE PRECISION,
      travel_time_seconds DOUBLE PRECISION,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS crm_routes_company_updated_idx ON crm_routes(company_id, updated_at DESC);
    CREATE INDEX IF NOT EXISTS crm_routes_user_updated_idx ON crm_routes(user_id, updated_at DESC);

    CREATE TABLE IF NOT EXISTS crm_route_stops (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      route_id UUID NOT NULL REFERENCES crm_routes(id) ON DELETE CASCADE,
      company_id UUID,
      contact_id UUID,
      stop_order INTEGER NOT NULL,
      name_snapshot TEXT NOT NULL,
      address_snapshot TEXT NOT NULL,
      latitude DOUBLE PRECISION,
      longitude DOUBLE PRECISION,
      status TEXT NOT NULL DEFAULT 'not_visited',
      batch_number INTEGER,
      source_type TEXT NOT NULL DEFAULT 'contact',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS crm_route_stops_route_order_idx ON crm_route_stops(route_id, stop_order);
    CREATE INDEX IF NOT EXISTS crm_route_stops_company_idx ON crm_route_stops(company_id);
    ALTER TABLE crm_routes ADD COLUMN IF NOT EXISTS start_mode TEXT NOT NULL DEFAULT 'current_location';
    ALTER TABLE crm_route_stops ADD COLUMN IF NOT EXISTS source_type TEXT NOT NULL DEFAULT 'contact';

    CREATE TABLE IF NOT EXISTS zapier_tokens (
      user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      token TEXT UNIQUE NOT NULL,
      auto_stage_id TEXT,
      auto_assign_stage_enabled BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS zapier_tokens_token_idx ON zapier_tokens(token);
    ALTER TABLE zapier_tokens ADD COLUMN IF NOT EXISTS auto_assign_stage_enabled BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE zapier_tokens ADD COLUMN IF NOT EXISTS notifications_enabled BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE zapier_tokens ADD COLUMN IF NOT EXISTS notification_fields JSONB;
    ALTER TABLE zapier_tokens ADD COLUMN IF NOT EXISTS notification_categories JSONB NOT NULL DEFAULT '{}'::jsonb;

    -- Queue of pending lead notifications for iOS foreground delivery.
    CREATE TABLE IF NOT EXISTS lead_notifications (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL,
      company_id UUID,
      contact_id TEXT,
      title TEXT NOT NULL,
      body TEXT,
      delivered_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS lead_notifications_user_idx ON lead_notifications(user_id, created_at DESC);

    -- Quotes (contact-scoped, with JSON line items and cached total).
    CREATE TABLE IF NOT EXISTS quotes (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL,
      company_id UUID,
      contact_id TEXT NOT NULL,
      title TEXT,
      line_items JSONB NOT NULL DEFAULT '[]'::jsonb,
      total_cents INTEGER NOT NULL DEFAULT 0,
      notes TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS quotes_contact_idx ON quotes(contact_id);
    CREATE INDEX IF NOT EXISTS quotes_company_idx ON quotes(company_id, updated_at DESC);
    CREATE INDEX IF NOT EXISTS quotes_user_idx ON quotes(user_id, updated_at DESC);

    CREATE TABLE IF NOT EXISTS quote_settings (
      company_id UUID PRIMARY KEY REFERENCES companies(id) ON DELETE CASCADE,
      tagline TEXT,
      phone TEXT,
      email TEXT,
      website TEXT,
      notes TEXT,
      tax_enabled BOOLEAN NOT NULL DEFAULT false,
      tax_rate_basis_points INTEGER NOT NULL DEFAULT 0,
      valid_for_days INTEGER NOT NULL DEFAULT 30,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    ALTER TABLE quote_settings ADD COLUMN IF NOT EXISTS tagline TEXT;
    ALTER TABLE quote_settings ADD COLUMN IF NOT EXISTS phone TEXT;
    ALTER TABLE quote_settings ADD COLUMN IF NOT EXISTS email TEXT;
    ALTER TABLE quote_settings ADD COLUMN IF NOT EXISTS website TEXT;
    ALTER TABLE quote_settings ADD COLUMN IF NOT EXISTS notes TEXT;
    ALTER TABLE quote_settings ADD COLUMN IF NOT EXISTS tax_enabled BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE quote_settings ADD COLUMN IF NOT EXISTS tax_rate_basis_points INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE quote_settings ADD COLUMN IF NOT EXISTS valid_for_days INTEGER NOT NULL DEFAULT 30;

    -- APNs device tokens for real push notifications.
    CREATE TABLE IF NOT EXISTS device_tokens (
      token TEXT PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      platform TEXT NOT NULL DEFAULT 'ios',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    ALTER TABLE device_tokens ADD COLUMN IF NOT EXISTS environment TEXT NOT NULL DEFAULT 'sandbox';
    ALTER TABLE device_tokens ADD COLUMN IF NOT EXISTS last_registration_error TEXT;
    CREATE INDEX IF NOT EXISTS device_tokens_user_idx ON device_tokens(user_id);
    CREATE INDEX IF NOT EXISTS device_tokens_user_environment_idx ON device_tokens(user_id, environment);

    -- Contact provenance for webhook-imported leads
    ALTER TABLE contacts ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
    ALTER TABLE contacts ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
    ALTER TABLE contacts ADD COLUMN IF NOT EXISTS source TEXT;
    ALTER TABLE contacts ADD COLUMN IF NOT EXISTS external_lead_id TEXT;
    ALTER TABLE contacts ADD COLUMN IF NOT EXISTS lead_form_id TEXT;
    ALTER TABLE contacts ADD COLUMN IF NOT EXISTS lead_page_id TEXT;
    ALTER TABLE contacts ADD COLUMN IF NOT EXISTS lead_submitted_at TIMESTAMPTZ;

    -- Full raw webhook payload (kept separately so we can debug without touching contacts)
    CREATE TABLE IF NOT EXISTS lead_imports (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID,
      user_id UUID NOT NULL,
      contact_id TEXT,
      source TEXT NOT NULL DEFAULT 'zapier',
      external_lead_id TEXT,
      form_id TEXT,
      page_id TEXT,
      submitted_at TIMESTAMPTZ,
      raw_payload JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS lead_imports_company_idx ON lead_imports(company_id, created_at DESC);
    -- Dedup by external lead id per company (partial unique index skips rows without an id)
    CREATE UNIQUE INDEX IF NOT EXISTS lead_imports_unique_ext
      ON lead_imports(company_id, source, external_lead_id)
      WHERE external_lead_id IS NOT NULL;

    CREATE TABLE IF NOT EXISTS stage_reminders (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      contact_id TEXT NOT NULL,
      opportunity_id TEXT,
      remind_at TIMESTAMPTZ NOT NULL,
      note TEXT,
      archived BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS stage_reminders_user_idx ON stage_reminders(user_id, remind_at);

    CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS TRIGGER AS $$
    BEGIN
      NEW.updated_at = now();
      RETURN NEW;
    END; $$ LANGUAGE plpgsql;

    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'contacts_touch_updated_at') THEN
        CREATE TRIGGER contacts_touch_updated_at
        BEFORE UPDATE ON contacts
        FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
      END IF;
    END $$;

    CREATE TABLE IF NOT EXISTS phone_lines (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      phone_number TEXT NOT NULL,
      twilio_phone_number_sid TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS phone_lines_phone_number_uidx ON phone_lines(phone_number);
    CREATE INDEX IF NOT EXISTS phone_lines_company_idx ON phone_lines(company_id, active);
    CREATE INDEX IF NOT EXISTS phone_lines_twilio_sid_idx ON phone_lines(twilio_phone_number_sid);

    CREATE TABLE IF NOT EXISTS sms_conversations (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      phone_line_id UUID NOT NULL REFERENCES phone_lines(id) ON DELETE CASCADE,
      external_phone_number TEXT NOT NULL,
      contact_id UUID REFERENCES contacts(id) ON DELETE SET NULL,
      last_message_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(phone_line_id, external_phone_number)
    );
    ALTER TABLE sms_conversations ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
    ALTER TABLE sms_conversations ADD COLUMN IF NOT EXISTS last_read_at TIMESTAMPTZ;
    CREATE INDEX IF NOT EXISTS sms_conversations_line_last_idx ON sms_conversations(phone_line_id, last_message_at DESC);
    CREATE INDEX IF NOT EXISTS sms_conversations_contact_idx ON sms_conversations(contact_id);
    CREATE INDEX IF NOT EXISTS sms_conversations_deleted_idx ON sms_conversations(deleted_at);

    CREATE TABLE IF NOT EXISTS sms_messages (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      conversation_id UUID NOT NULL REFERENCES sms_conversations(id) ON DELETE CASCADE,
      twilio_message_sid TEXT,
      direction TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound')),
      from_number TEXT NOT NULL,
      to_number TEXT NOT NULL,
      body TEXT,
      message_status TEXT,
      media_count INTEGER NOT NULL DEFAULT 0,
      media JSONB NOT NULL DEFAULT '[]'::jsonb,
      twilio_error_code TEXT,
      twilio_error_message TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    ALTER TABLE sms_messages ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
    CREATE UNIQUE INDEX IF NOT EXISTS sms_messages_twilio_sid_uidx
      ON sms_messages(twilio_message_sid)
      WHERE twilio_message_sid IS NOT NULL;
    CREATE INDEX IF NOT EXISTS sms_messages_conversation_created_idx ON sms_messages(conversation_id, created_at);
    CREATE INDEX IF NOT EXISTS sms_messages_conversation_updated_idx ON sms_messages(conversation_id, updated_at DESC);
    CREATE INDEX IF NOT EXISTS sms_messages_deleted_idx ON sms_messages(deleted_at);

    CREATE TABLE IF NOT EXISTS phone_calls (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      phone_line_id UUID REFERENCES phone_lines(id) ON DELETE SET NULL,
      contact_id UUID REFERENCES contacts(id) ON DELETE SET NULL,
      twilio_call_sid TEXT,
      twilio_parent_call_sid TEXT,
      direction TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound')),
      from_number TEXT,
      to_number TEXT,
      status TEXT,
      started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      answered_at TIMESTAMPTZ,
      ended_at TIMESTAMPTZ,
      duration_seconds INTEGER,
      disposition TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS phone_calls_twilio_call_sid_uidx
      ON phone_calls(twilio_call_sid)
      WHERE twilio_call_sid IS NOT NULL;
    CREATE INDEX IF NOT EXISTS phone_calls_company_started_idx ON phone_calls(company_id, started_at DESC);
    CREATE INDEX IF NOT EXISTS phone_calls_contact_idx ON phone_calls(contact_id);
    CREATE INDEX IF NOT EXISTS phone_calls_phone_line_idx ON phone_calls(phone_line_id);
    CREATE INDEX IF NOT EXISTS phone_calls_parent_sid_idx ON phone_calls(twilio_parent_call_sid);

    CREATE TABLE IF NOT EXISTS voicemails (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      phone_line_id UUID REFERENCES phone_lines(id) ON DELETE SET NULL,
      contact_id UUID REFERENCES contacts(id) ON DELETE SET NULL,
      phone_call_id UUID REFERENCES phone_calls(id) ON DELETE SET NULL,
      twilio_call_sid TEXT,
      twilio_recording_sid TEXT,
      external_phone_number TEXT,
      recording_status TEXT,
      duration_seconds INTEGER,
      is_read BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      deleted_at TIMESTAMPTZ
    );
    CREATE UNIQUE INDEX IF NOT EXISTS voicemails_recording_sid_uidx
      ON voicemails(twilio_recording_sid)
      WHERE twilio_recording_sid IS NOT NULL;
    CREATE INDEX IF NOT EXISTS voicemails_company_created_idx ON voicemails(company_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS voicemails_contact_idx ON voicemails(contact_id);
    CREATE INDEX IF NOT EXISTS voicemails_phone_line_idx ON voicemails(phone_line_id);
    CREATE INDEX IF NOT EXISTS voicemails_call_sid_idx ON voicemails(twilio_call_sid);
    CREATE INDEX IF NOT EXISTS voicemails_unread_idx ON voicemails(company_id, is_read) WHERE deleted_at IS NULL;

    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'phone_lines_touch_updated_at') THEN
        CREATE TRIGGER phone_lines_touch_updated_at
        BEFORE UPDATE ON phone_lines
        FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'sms_conversations_touch_updated_at') THEN
        CREATE TRIGGER sms_conversations_touch_updated_at
        BEFORE UPDATE ON sms_conversations
        FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'sms_messages_touch_updated_at') THEN
        CREATE TRIGGER sms_messages_touch_updated_at
        BEFORE UPDATE ON sms_messages
        FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'phone_calls_touch_updated_at') THEN
        CREATE TRIGGER phone_calls_touch_updated_at
        BEFORE UPDATE ON phone_calls
        FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'voicemails_touch_updated_at') THEN
        CREATE TRIGGER voicemails_touch_updated_at
        BEFORE UPDATE ON voicemails
        FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
      END IF;
    END $$;

    CREATE TABLE IF NOT EXISTS stages (
      id TEXT PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      order_idx INTEGER NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS stages_user_idx ON stages(user_id, order_idx);

    -- Migrate stages to company-scoping so every teammate sees the same set.
    ALTER TABLE stages ADD COLUMN IF NOT EXISTS company_id UUID;
    UPDATE stages s
      SET company_id = u.company_id
      FROM users u
      WHERE u.id = s.user_id
        AND s.company_id IS NULL
        AND u.company_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS stages_company_idx ON stages(company_id, order_idx);

    CREATE TABLE IF NOT EXISTS opportunities (
      id TEXT PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      contact_id TEXT NOT NULL,
      state TEXT NOT NULL,
      stage_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS opportunities_user_contact_idx
      ON opportunities(user_id, contact_id);

    -- Same for opportunities so auto-assigned webhook leads are visible company-wide.
    ALTER TABLE opportunities ADD COLUMN IF NOT EXISTS company_id UUID;
    UPDATE opportunities o
      SET company_id = u.company_id
      FROM users u
      WHERE u.id = o.user_id
        AND o.company_id IS NULL
        AND u.company_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS opportunities_company_idx ON opportunities(company_id);

    CREATE TABLE IF NOT EXISTS schedule_events (
      id TEXT PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      start_at TIMESTAMPTZ NOT NULL,
      end_at TIMESTAMPTZ NOT NULL,
      color TEXT NOT NULL DEFAULT '#3478F6',
      notes TEXT,
      contact_id TEXT,
      reminder_minutes JSONB NOT NULL DEFAULT '[]'::jsonb,
      service_items JSONB NOT NULL DEFAULT '[]'::jsonb,
      company_id UUID,
      created_by UUID,
      sales_user_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
      worker_user_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
      started_at TIMESTAMPTZ,
      started_by UUID,
      finished_at TIMESTAMPTZ,
      finished_by UUID,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS schedule_user_start_idx
      ON schedule_events(user_id, start_at);

    CREATE TABLE IF NOT EXISTS map_pins (
      id TEXT PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      latitude DOUBLE PRECISION NOT NULL,
      longitude DOUBLE PRECISION NOT NULL,
      name TEXT NOT NULL DEFAULT '',
      address TEXT NOT NULL DEFAULT '',
      notes TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'lead',
      phone TEXT,
      email TEXT,
      contact_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS map_pins_user_idx ON map_pins(user_id);
    CREATE INDEX IF NOT EXISTS map_pins_user_created_idx ON map_pins(user_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS measurements (
      id TEXT PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL DEFAULT '',
      points JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      linked_contact_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
      units TEXT NOT NULL DEFAULT 'feet',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS measurements_user_idx ON measurements(user_id);

    CREATE TABLE IF NOT EXISTS todo_tasks (
      id TEXT PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      due_date TIMESTAMPTZ,
      reminders JSONB NOT NULL DEFAULT '[]'::jsonb,
      subtasks JSONB NOT NULL DEFAULT '[]'::jsonb,
      completed BOOLEAN NOT NULL DEFAULT false,
      completed_at TIMESTAMPTZ,
      color_hex TEXT,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS todo_tasks_user_idx ON todo_tasks(user_id);

    CREATE TABLE IF NOT EXISTS todo_routines (
      id TEXT PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      time TIMESTAMPTZ,
      weekdays JSONB NOT NULL DEFAULT '[]'::jsonb,
      reminders JSONB NOT NULL DEFAULT '[]'::jsonb,
      enabled BOOLEAN NOT NULL DEFAULT true,
      color_hex TEXT,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS todo_routines_user_idx ON todo_routines(user_id);

    CREATE TABLE IF NOT EXISTS todo_routine_done (
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      routine_id TEXT NOT NULL,
      day_key TEXT NOT NULL,
      PRIMARY KEY (user_id, routine_id, day_key)
    );

    CREATE TABLE IF NOT EXISTS todo_customer_reminders (
      id TEXT PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT,
      contact_id TEXT,
      contact_name TEXT NOT NULL,
      phone TEXT,
      due_date TIMESTAMPTZ,
      completed BOOLEAN NOT NULL DEFAULT false,
      color_hex TEXT,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS todo_customer_reminders_user_idx
      ON todo_customer_reminders(user_id);

    CREATE TABLE IF NOT EXISTS todo_logs (
      id TEXT PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      kind TEXT NOT NULL,
      ts TIMESTAMPTZ NOT NULL DEFAULT now(),
      task_id TEXT,
      routine_id TEXT,
      contact_id TEXT,
      note TEXT
    );
    CREATE INDEX IF NOT EXISTS todo_logs_user_ts_idx ON todo_logs(user_id, ts DESC);

    CREATE TABLE IF NOT EXISTS job_workflow_templates (
      id TEXT PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      scope TEXT NOT NULL DEFAULT 'company_default',
      service_type TEXT,
      enabled BOOLEAN NOT NULL DEFAULT true,
      sections JSONB NOT NULL DEFAULT '[]'::jsonb,
      archived_at TIMESTAMPTZ,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS job_workflow_templates_company_idx ON job_workflow_templates(company_id, archived_at, enabled);

    CREATE TABLE IF NOT EXISTS job_workflow_job_additions (
      id TEXT PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      job_id TEXT NOT NULL REFERENCES schedule_events(id) ON DELETE CASCADE,
      sections JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, job_id)
    );
    CREATE INDEX IF NOT EXISTS job_workflow_job_additions_job_idx ON job_workflow_job_additions(company_id, job_id);

    CREATE TABLE IF NOT EXISTS job_workflow_runs (
      id TEXT PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      job_id TEXT NOT NULL REFERENCES schedule_events(id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'in_progress',
      started_at TIMESTAMPTZ,
      started_by UUID REFERENCES users(id) ON DELETE SET NULL,
      completed_at TIMESTAMPTZ,
      completed_by UUID REFERENCES users(id) ON DELETE SET NULL,
      override_reason TEXT,
      snapshot JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, job_id)
    );
    CREATE INDEX IF NOT EXISTS job_workflow_runs_job_idx ON job_workflow_runs(company_id, job_id);

    CREATE TABLE IF NOT EXISTS job_photos (
      id TEXT PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      job_id TEXT NOT NULL REFERENCES schedule_events(id) ON DELETE CASCADE,
      contact_id TEXT,
      category TEXT NOT NULL DEFAULT 'general',
      caption TEXT,
      object_key TEXT NOT NULL,
      thumbnail_key TEXT,
      workflow_item_id TEXT,
      uploaded_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS job_photos_job_idx ON job_photos(company_id, job_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS inventory_locations (
      id TEXT PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      kind TEXT NOT NULL DEFAULT 'other',
      active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS inventory_locations_company_idx ON inventory_locations(company_id, active);

    CREATE TABLE IF NOT EXISTS inventory_items (
      id TEXT PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      item_type TEXT NOT NULL DEFAULT 'material',
      tracking_mode TEXT NOT NULL DEFAULT 'quantity',
      category TEXT,
      unit TEXT NOT NULL DEFAULT 'each',
      quantity_on_hand NUMERIC NOT NULL DEFAULT 0,
      reorder_point NUMERIC,
      cost_per_unit_cents INTEGER,
      status TEXT NOT NULL DEFAULT 'available',
      location_id TEXT,
      assigned_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      notes TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS inventory_items_company_idx ON inventory_items(company_id, item_type, status);

    CREATE TABLE IF NOT EXISTS inventory_transactions (
      id TEXT PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      item_id TEXT NOT NULL REFERENCES inventory_items(id) ON DELETE CASCADE,
      transaction_type TEXT NOT NULL,
      quantity NUMERIC NOT NULL,
      from_location_id TEXT,
      to_location_id TEXT,
      job_id TEXT,
      employee_id UUID REFERENCES users(id) ON DELETE SET NULL,
      note TEXT,
      cost_snapshot_cents INTEGER,
      idempotency_key TEXT,
      reverses_transaction_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS inventory_transactions_item_idx ON inventory_transactions(company_id, item_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS inventory_transactions_job_idx ON inventory_transactions(company_id, job_id);

    CREATE TABLE IF NOT EXISTS equipment_requests (
      id TEXT PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      request_type TEXT NOT NULL,
      item_id TEXT,
      item_name TEXT,
      quantity NUMERIC,
      urgency TEXT NOT NULL DEFAULT 'normal',
      explanation TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      requester_id UUID REFERENCES users(id) ON DELETE SET NULL,
      owner_response TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS equipment_requests_company_idx ON equipment_requests(company_id, status, created_at);

    CREATE TABLE IF NOT EXISTS equipment_asset_history (
      id TEXT PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      item_id TEXT NOT NULL REFERENCES inventory_items(id) ON DELETE CASCADE,
      event_type TEXT NOT NULL,
      actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      summary TEXT NOT NULL,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS equipment_asset_history_item_idx ON equipment_asset_history(company_id, item_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS equipment_repairs (
      id TEXT PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      item_id TEXT NOT NULL REFERENCES inventory_items(id) ON DELETE CASCADE,
      request_id TEXT REFERENCES equipment_requests(id) ON DELETE SET NULL,
      reported_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      assigned_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      vendor TEXT,
      problem TEXT NOT NULL,
      diagnosis TEXT,
      status TEXT NOT NULL DEFAULT 'reported',
      priority TEXT NOT NULL DEFAULT 'normal',
      estimated_cost_cents INTEGER,
      actual_cost_cents INTEGER,
      opened_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      scheduled_at TIMESTAMPTZ,
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      resolution_notes TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS equipment_repairs_company_idx ON equipment_repairs(company_id, status, updated_at DESC);
    CREATE INDEX IF NOT EXISTS equipment_repairs_item_idx ON equipment_repairs(company_id, item_id, updated_at DESC);

    CREATE TABLE IF NOT EXISTS material_usages (
      id TEXT PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      job_id TEXT NOT NULL REFERENCES schedule_events(id) ON DELETE CASCADE,
      item_id TEXT NOT NULL REFERENCES inventory_items(id) ON DELETE RESTRICT,
      location_id TEXT,
      quantity NUMERIC NOT NULL DEFAULT 0,
      unit_cost_snapshot_cents INTEGER,
      current_transaction_id TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      note TEXT,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
      idempotency_key TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS material_usages_job_idx ON material_usages(company_id, job_id, status);

    CREATE TABLE IF NOT EXISTS inventory_count_schedules (
      id TEXT PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      location_id TEXT NOT NULL,
      assigned_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      frequency TEXT NOT NULL DEFAULT 'weekly',
      due_date DATE,
      due_time TEXT,
      reminder_minutes INTEGER,
      variance_threshold NUMERIC NOT NULL DEFAULT 0,
      approval_required BOOLEAN NOT NULL DEFAULT true,
      enabled BOOLEAN NOT NULL DEFAULT true,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS inventory_count_schedules_company_idx ON inventory_count_schedules(company_id, enabled, due_date);

    CREATE TABLE IF NOT EXISTS inventory_count_submissions (
      id TEXT PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      schedule_id TEXT REFERENCES inventory_count_schedules(id) ON DELETE SET NULL,
      location_id TEXT NOT NULL,
      assigned_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      submitted_by UUID REFERENCES users(id) ON DELETE SET NULL,
      status TEXT NOT NULL DEFAULT 'draft',
      due_date DATE,
      submitted_at TIMESTAMPTZ,
      reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL,
      reviewed_at TIMESTAMPTZ,
      review_note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS inventory_count_submissions_company_idx ON inventory_count_submissions(company_id, status, due_date DESC);

    CREATE TABLE IF NOT EXISTS inventory_count_submission_items (
      id TEXT PRIMARY KEY,
      submission_id TEXT NOT NULL REFERENCES inventory_count_submissions(id) ON DELETE CASCADE,
      item_id TEXT NOT NULL REFERENCES inventory_items(id) ON DELETE RESTRICT,
      expected_quantity NUMERIC NOT NULL DEFAULT 0,
      counted_quantity NUMERIC NOT NULL DEFAULT 0,
      variance NUMERIC NOT NULL DEFAULT 0,
      note TEXT
    );

    CREATE TABLE IF NOT EXISTS mileage_company_settings (
      company_id UUID PRIMARY KEY REFERENCES companies(id) ON DELETE CASCADE,
      enabled BOOLEAN NOT NULL DEFAULT false,
      default_rate_cents_per_mile INTEGER NOT NULL DEFAULT 67,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS mileage_employee_settings (
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      employee_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      enabled BOOLEAN NOT NULL DEFAULT false,
      rate_cents_per_mile INTEGER,
      start_rule TEXT NOT NULL DEFAULT 'company_location',
      end_rule TEXT NOT NULL DEFAULT 'last_completed_job',
      start_location_id TEXT,
      end_location_id TEXT,
      vehicle_type TEXT NOT NULL DEFAULT 'not_specified',
      effective_date DATE,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY(company_id, employee_id)
    );

    CREATE TABLE IF NOT EXISTS mileage_company_locations (
      id TEXT PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      address TEXT NOT NULL,
      lat DOUBLE PRECISION,
      lng DOUBLE PRECISION,
      active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS mileage_daily_logs (
      id TEXT PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      employee_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      service_date DATE NOT NULL,
      status TEXT NOT NULL DEFAULT 'draft',
      start_rule TEXT,
      end_rule TEXT,
      start_label TEXT,
      start_lat DOUBLE PRECISION,
      start_lng DOUBLE PRECISION,
      end_label TEXT,
      end_lat DOUBLE PRECISION,
      end_lng DOUBLE PRECISION,
      job_order_estimated BOOLEAN NOT NULL DEFAULT false,
      total_miles NUMERIC NOT NULL DEFAULT 0,
      rate_cents_per_mile INTEGER NOT NULL DEFAULT 0,
      reimbursement_cents INTEGER NOT NULL DEFAULT 0,
      employee_notes TEXT,
      owner_notes TEXT,
      reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL,
      reviewed_at TIMESTAMPTZ,
      paid_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, employee_id, service_date)
    );

    CREATE TABLE IF NOT EXISTS mileage_legs (
      id TEXT PRIMARY KEY,
      log_id TEXT NOT NULL REFERENCES mileage_daily_logs(id) ON DELETE CASCADE,
      sequence INTEGER NOT NULL,
      from_label TEXT NOT NULL,
      to_label TEXT NOT NULL,
      distance_miles NUMERIC NOT NULL DEFAULT 0,
      duration_seconds NUMERIC,
      job_id TEXT,
      manual_trip_id TEXT,
      calculation_status TEXT NOT NULL DEFAULT 'calculated',
      error_message TEXT
    );

    CREATE TABLE IF NOT EXISTS mileage_address_proposals (
      id TEXT PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      employee_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      kind TEXT NOT NULL DEFAULT 'start',
      label TEXT,
      address TEXT NOT NULL,
      lat DOUBLE PRECISION,
      lng DOUBLE PRECISION,
      explanation TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL,
      reviewed_at TIMESTAMPTZ,
      review_note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS mileage_address_proposals_company_idx ON mileage_address_proposals(company_id, status, created_at);

    CREATE TABLE IF NOT EXISTS mileage_manual_trips (
      id TEXT PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      employee_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      service_date DATE NOT NULL,
      purpose TEXT NOT NULL,
      notes TEXT,
      from_label TEXT NOT NULL,
      from_address TEXT,
      from_lat DOUBLE PRECISION NOT NULL,
      from_lng DOUBLE PRECISION NOT NULL,
      to_label TEXT NOT NULL,
      to_address TEXT,
      to_lat DOUBLE PRECISION NOT NULL,
      to_lng DOUBLE PRECISION NOT NULL,
      distance_miles NUMERIC,
      duration_seconds NUMERIC,
      status TEXT NOT NULL DEFAULT 'pending',
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL,
      reviewed_at TIMESTAMPTZ,
      review_note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS mileage_manual_trips_company_idx ON mileage_manual_trips(company_id, employee_id, service_date);

    CREATE TABLE IF NOT EXISTS time_clock_settings (
      company_id UUID PRIMARY KEY REFERENCES companies(id) ON DELETE CASCADE,
      week_start INTEGER NOT NULL DEFAULT 1,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS time_clock_entries (
      id TEXT PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      company_id UUID REFERENCES companies(id) ON DELETE CASCADE,
      start_at TIMESTAMPTZ NOT NULL,
      end_at TIMESTAMPTZ,
      note TEXT,
      created_by UUID REFERENCES users(id),
      updated_by UUID REFERENCES users(id),
      manual_entry BOOLEAN NOT NULL DEFAULT false,
      manual_status TEXT NOT NULL DEFAULT 'approved',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS time_clock_entries_user_start_idx ON time_clock_entries(user_id, start_at DESC);
    CREATE INDEX IF NOT EXISTS time_clock_entries_company_start_idx ON time_clock_entries(company_id, start_at DESC);

    CREATE TABLE IF NOT EXISTS conversations (
      id TEXT PRIMARY KEY,
      company_id UUID,
      title TEXT,
      is_group BOOLEAN NOT NULL DEFAULT false,
      created_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    ALTER TABLE conversations ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
    CREATE INDEX IF NOT EXISTS conversations_company_updated_idx ON conversations(company_id, updated_at DESC);
    CREATE INDEX IF NOT EXISTS conversations_deleted_idx ON conversations(deleted_at);

    CREATE TABLE IF NOT EXISTS conversation_participants (
      id TEXT PRIMARY KEY,
      conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      last_read_at TIMESTAMPTZ,
      UNIQUE(conversation_id, user_id)
    );
    CREATE INDEX IF NOT EXISTS conversation_participants_user_idx ON conversation_participants(user_id);

    CREATE TABLE IF NOT EXISTS channels (
      id TEXT PRIMARY KEY,
      company_id UUID,
      name TEXT NOT NULL,
      description TEXT,
      created_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      archived_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS channels_company_idx ON channels(company_id, archived_at);

    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      conversation_id TEXT REFERENCES conversations(id) ON DELETE CASCADE,
      channel_id TEXT REFERENCES channels(id) ON DELETE CASCADE,
      sender_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      body TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      deleted_at TIMESTAMPTZ,
      CHECK ((conversation_id IS NOT NULL AND channel_id IS NULL) OR (conversation_id IS NULL AND channel_id IS NOT NULL))
    );
    CREATE INDEX IF NOT EXISTS messages_conversation_idx ON messages(conversation_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS messages_channel_idx ON messages(channel_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS message_attachments (
      id TEXT PRIMARY KEY,
      message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
      kind TEXT NOT NULL,
      object_key TEXT,
      url TEXT,
      thumbnail_object_key TEXT,
      thumbnail_url TEXT,
      file_name TEXT,
      mime_type TEXT,
      byte_size INTEGER,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS message_attachments_message_idx ON message_attachments(message_id);

    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      company_id UUID,
      kind TEXT NOT NULL,
      title TEXT NOT NULL,
      body TEXT,
      data JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      read_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS notifications_user_unread_idx ON notifications(user_id, read_at, created_at DESC);

    CREATE TABLE IF NOT EXISTS dashboard_dismissals (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      item_type TEXT NOT NULL,
      source_id TEXT NOT NULL,
      fingerprint TEXT NOT NULL DEFAULT '',
      dismissed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      expires_at TIMESTAMPTZ
    );
    CREATE UNIQUE INDEX IF NOT EXISTS dashboard_dismissals_unique_idx
      ON dashboard_dismissals(user_id, item_type, source_id, fingerprint);
    CREATE INDEX IF NOT EXISTS dashboard_dismissals_user_idx
      ON dashboard_dismissals(user_id, dismissed_at DESC);
  `);

  // Schedule events extra fields (services + price)
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'employer';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS company_id UUID;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS photo_url TEXT;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS notify_all_members_on_jobs BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE time_clock_entries ADD COLUMN IF NOT EXISTS manual_entry BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE time_clock_entries ADD COLUMN IF NOT EXISTS manual_status TEXT NOT NULL DEFAULT 'approved';
    ALTER TABLE time_clock_entries ADD COLUMN IF NOT EXISTS break_seconds INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE time_clock_entries ADD COLUMN IF NOT EXISTS break_started_at TIMESTAMPTZ;
    ALTER TABLE map_pins ADD COLUMN IF NOT EXISTS contact_id TEXT;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS logo_data_url TEXT;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS website TEXT;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS address TEXT;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS phone TEXT;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS email TEXT;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS timezone TEXT NOT NULL DEFAULT 'America/New_York';
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS business_days JSONB NOT NULL DEFAULT '[1,2,3,4,5]'::jsonb;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS business_open_time TEXT NOT NULL DEFAULT '09:00';
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS business_close_time TEXT NOT NULL DEFAULT '17:00';
    ALTER TABLE employee_permissions ADD COLUMN IF NOT EXISTS can_view_finance BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE employee_permissions ADD COLUMN IF NOT EXISTS can_use_finance_ai BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE employee_permissions ADD COLUMN IF NOT EXISTS can_view_finance_transactions BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE employee_permissions ADD COLUMN IF NOT EXISTS can_edit_finance_transactions BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE employee_permissions ADD COLUMN IF NOT EXISTS can_view_finance_accounts BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE employee_permissions ADD COLUMN IF NOT EXISTS can_create_finance_accounts BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE employee_permissions ADD COLUMN IF NOT EXISTS can_edit_finance_accounts BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE employee_permissions ADD COLUMN IF NOT EXISTS can_adjust_finance_account_balances BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE employee_permissions ADD COLUMN IF NOT EXISTS can_view_finance_receipts BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE employee_permissions ADD COLUMN IF NOT EXISTS can_edit_finance_receipts BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE employee_permissions ADD COLUMN IF NOT EXISTS can_view_finance_planning BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE employee_permissions ADD COLUMN IF NOT EXISTS can_edit_finance_planning BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE employee_permissions ADD COLUMN IF NOT EXISTS can_view_finance_budgets BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE employee_permissions ADD COLUMN IF NOT EXISTS can_edit_finance_budgets BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE employee_permissions ADD COLUMN IF NOT EXISTS can_view_finance_goals BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE employee_permissions ADD COLUMN IF NOT EXISTS can_edit_finance_goals BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE employee_permissions ADD COLUMN IF NOT EXISTS can_view_finance_debts BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE employee_permissions ADD COLUMN IF NOT EXISTS can_edit_finance_debts BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE employee_permissions ADD COLUMN IF NOT EXISTS can_view_finance_settings BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE employee_permissions ADD COLUMN IF NOT EXISTS can_edit_finance_settings BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE employee_permissions ADD COLUMN IF NOT EXISTS can_manage_company_finance_ai_memories BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS services JSONB NOT NULL DEFAULT '[]'::jsonb;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS service_items JSONB NOT NULL DEFAULT '[]'::jsonb;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS price_cents INTEGER;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS material_cost_cents INTEGER;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS company_id UUID;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS created_by UUID;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS sales_user_ids JSONB NOT NULL DEFAULT '[]'::jsonb;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS worker_user_ids JSONB NOT NULL DEFAULT '[]'::jsonb;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS started_by UUID;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS finished_at TIMESTAMPTZ;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS finished_by UUID;

    ALTER TABLE mileage_daily_logs ADD COLUMN IF NOT EXISTS start_rule TEXT;
    ALTER TABLE mileage_daily_logs ADD COLUMN IF NOT EXISTS end_rule TEXT;
    ALTER TABLE mileage_daily_logs ADD COLUMN IF NOT EXISTS start_label TEXT;
    ALTER TABLE mileage_daily_logs ADD COLUMN IF NOT EXISTS start_lat DOUBLE PRECISION;
    ALTER TABLE mileage_daily_logs ADD COLUMN IF NOT EXISTS start_lng DOUBLE PRECISION;
    ALTER TABLE mileage_daily_logs ADD COLUMN IF NOT EXISTS end_label TEXT;
    ALTER TABLE mileage_daily_logs ADD COLUMN IF NOT EXISTS end_lat DOUBLE PRECISION;
    ALTER TABLE mileage_daily_logs ADD COLUMN IF NOT EXISTS end_lng DOUBLE PRECISION;
    ALTER TABLE mileage_daily_logs ADD COLUMN IF NOT EXISTS job_order_estimated BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE mileage_daily_logs ADD COLUMN IF NOT EXISTS employee_notes TEXT;
    ALTER TABLE mileage_daily_logs ADD COLUMN IF NOT EXISTS owner_notes TEXT;
    ALTER TABLE mileage_daily_logs ADD COLUMN IF NOT EXISTS reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL;
    ALTER TABLE mileage_daily_logs ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;
    ALTER TABLE mileage_daily_logs ADD COLUMN IF NOT EXISTS paid_at TIMESTAMPTZ;
    ALTER TABLE mileage_legs ADD COLUMN IF NOT EXISTS duration_seconds NUMERIC;
    ALTER TABLE mileage_legs ADD COLUMN IF NOT EXISTS manual_trip_id TEXT;
    ALTER TABLE mileage_legs ADD COLUMN IF NOT EXISTS calculation_status TEXT NOT NULL DEFAULT 'calculated';
    ALTER TABLE mileage_legs ADD COLUMN IF NOT EXISTS error_message TEXT;
    ALTER TABLE inventory_transactions ADD COLUMN IF NOT EXISTS idempotency_key TEXT;
    ALTER TABLE inventory_transactions ADD COLUMN IF NOT EXISTS reverses_transaction_id TEXT;
    ALTER TABLE todo_tasks ADD COLUMN IF NOT EXISTS linked_equipment_request_id TEXT;
    ALTER TABLE todo_tasks ADD COLUMN IF NOT EXISTS linked_inventory_count_id TEXT;

    ALTER TABLE todo_tasks ADD COLUMN IF NOT EXISTS detail TEXT;
    ALTER TABLE todo_tasks ADD COLUMN IF NOT EXISTS creator_id UUID;
    ALTER TABLE todo_tasks ADD COLUMN IF NOT EXISTS assignee_ids JSONB NOT NULL DEFAULT '[]'::jsonb;
    ALTER TABLE todo_tasks ADD COLUMN IF NOT EXISTS priority TEXT NOT NULL DEFAULT 'normal';
    ALTER TABLE todo_tasks ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'open';
    ALTER TABLE todo_tasks ADD COLUMN IF NOT EXISTS linked_contact_id TEXT;
    ALTER TABLE todo_tasks ADD COLUMN IF NOT EXISTS linked_job_id TEXT;
    ALTER TABLE todo_tasks ADD COLUMN IF NOT EXISTS linked_equipment_id TEXT;
    ALTER TABLE todo_tasks ADD COLUMN IF NOT EXISTS completed_by UUID;
    ALTER TABLE todo_tasks ADD COLUMN IF NOT EXISTS completion_note TEXT;
    ALTER TABLE todo_tasks ADD COLUMN IF NOT EXISTS completion_note_required BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE map_pins ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
    ALTER TABLE measurements ADD COLUMN IF NOT EXISTS linked_contact_ids JSONB NOT NULL DEFAULT '[]'::jsonb;
    ALTER TABLE measurements ADD COLUMN IF NOT EXISTS units TEXT NOT NULL DEFAULT 'feet';
    ALTER TABLE measurements ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
  `);

  // Ensure user_id column exists
  await pool.query(`ALTER TABLE contacts ADD COLUMN IF NOT EXISTS user_id UUID;`);
  await pool.query(`ALTER TABLE contacts ADD COLUMN IF NOT EXISTS company_id UUID;`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS inventory_transactions_idempotency_idx ON inventory_transactions(company_id, idempotency_key) WHERE idempotency_key IS NOT NULL;`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS material_usages_idempotency_idx ON material_usages(company_id, idempotency_key) WHERE idempotency_key IS NOT NULL;`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS inventory_count_submission_once_idx ON inventory_count_submissions(company_id, schedule_id, due_date);`);

  // Ensure owner user exists (from env) and backfill any NULL user_id rows to this owner
  const ownerEmail = (process.env.OWNER_EMAIL || "").trim().toLowerCase();
  if (ownerEmail) {
    const { rows: u } = await pool.query(
      `INSERT INTO users(email) VALUES($1)
       ON CONFLICT(email) DO UPDATE SET email = EXCLUDED.email
       RETURNING id`,
      [ownerEmail]
    );
    const ownerId = u[0].id;

    // Backfill any orphaned contacts
    const res = await pool.query(
      `UPDATE contacts SET user_id = $1 WHERE user_id IS NULL`,
      [ownerId]
    );
    if (res.rowCount) {
      console.log(`[backfill] Attached ${res.rowCount} existing contacts to ${ownerEmail}`);
    }

    // Enforce NOT NULL + FK (idempotent)
    await pool.query(`
      ALTER TABLE contacts
        ALTER COLUMN user_id SET NOT NULL;
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.table_constraints
          WHERE constraint_name = 'contacts_user_fk'
            AND table_name = 'contacts'
        ) THEN
          ALTER TABLE contacts
            ADD CONSTRAINT contacts_user_fk
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
        END IF;
      END $$;
      CREATE INDEX IF NOT EXISTS contacts_user_updated_idx
        ON contacts(user_id, updated_at DESC);
    `);
  } else {
    console.warn("[bootstrap] OWNER_EMAIL not set; skipping contacts backfill/enforcement");
  }

  await pool.query(`
    UPDATE contacts c
       SET company_id = u.company_id
      FROM users u
     WHERE c.user_id = u.id
       AND c.company_id IS NULL;

    CREATE INDEX IF NOT EXISTS contacts_company_updated_idx
      ON contacts(company_id, updated_at DESC);
  `);

  // ---------- Stripe / Service Plans / Payments schema ----------
  // business_settings is scoped by the employer/owner user, but every row
  // also carries company_id so employee lookups can share the connected
  // Stripe account without querying by user_id.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS business_settings (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      company_id UUID,
      business_name TEXT,
      stripe_account_id TEXT,
      stripe_connect_status TEXT NOT NULL DEFAULT 'not_connected',
      stripe_charges_enabled BOOLEAN NOT NULL DEFAULT false,
      stripe_payouts_enabled BOOLEAN NOT NULL DEFAULT false,
      stripe_details_submitted BOOLEAN NOT NULL DEFAULT false,
      stripe_default_currency TEXT NOT NULL DEFAULT 'usd',
      stripe_requirements JSONB NOT NULL DEFAULT '{}'::jsonb,
      stripe_capabilities JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    ALTER TABLE business_settings ADD COLUMN IF NOT EXISTS company_id UUID;
    ALTER TABLE business_settings ADD COLUMN IF NOT EXISTS stripe_requirements JSONB NOT NULL DEFAULT '{}'::jsonb;
    ALTER TABLE business_settings ADD COLUMN IF NOT EXISTS stripe_capabilities JSONB NOT NULL DEFAULT '{}'::jsonb;
    CREATE INDEX IF NOT EXISTS business_settings_user_idx ON business_settings(user_id);
    CREATE INDEX IF NOT EXISTS business_settings_company_idx ON business_settings(company_id);
    CREATE INDEX IF NOT EXISTS business_settings_stripe_account_idx ON business_settings(stripe_account_id);

    CREATE TABLE IF NOT EXISTS service_plans (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      company_id UUID,
      created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      contact_id UUID,
      plan_name TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'draft',
      price_cents INTEGER NOT NULL,
      currency TEXT NOT NULL DEFAULT 'usd',
      billing_interval TEXT NOT NULL,
      billing_interval_count INTEGER NOT NULL DEFAULT 1,
      service_interval TEXT NOT NULL,
      service_interval_count INTEGER NOT NULL DEFAULT 1,
      first_service_date DATE,
      next_service_date DATE,
      last_service_date DATE,
      included_services TEXT,
      notes TEXT,
      stripe_connected_account_id TEXT,
      stripe_customer_id TEXT,
      stripe_product_id TEXT,
      stripe_price_id TEXT,
      stripe_subscription_id TEXT,
      stripe_payment_intent_id TEXT,
      stripe_subscription_status TEXT,
      stripe_latest_invoice_id TEXT,
      stripe_payment_collection_paused BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    ALTER TABLE service_plans ADD COLUMN IF NOT EXISTS stripe_payment_collection_paused BOOLEAN NOT NULL DEFAULT false;
    CREATE INDEX IF NOT EXISTS service_plans_user_status_idx ON service_plans(user_id, status);
    CREATE INDEX IF NOT EXISTS service_plans_company_status_idx ON service_plans(company_id, status);
    CREATE INDEX IF NOT EXISTS service_plans_created_by_idx ON service_plans(created_by_user_id);
    CREATE INDEX IF NOT EXISTS service_plans_contact_idx ON service_plans(contact_id);
    CREATE INDEX IF NOT EXISTS service_plans_stripe_sub_idx ON service_plans(stripe_subscription_id);
    CREATE INDEX IF NOT EXISTS service_plans_stripe_acct_idx ON service_plans(stripe_connected_account_id);

    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'service_plans_touch_updated_at') THEN
        CREATE TRIGGER service_plans_touch_updated_at
        BEFORE UPDATE ON service_plans
        FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
      END IF;
    END $$;

    CREATE TABLE IF NOT EXISTS service_plan_events (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      company_id UUID,
      created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      service_plan_id UUID NOT NULL REFERENCES service_plans(id) ON DELETE CASCADE,
      contact_id UUID,
      event_type TEXT NOT NULL,
      scheduled_date DATE,
      completed_date DATE,
      notes TEXT,
      stripe_event_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS service_plan_events_plan_idx ON service_plan_events(service_plan_id);
    CREATE INDEX IF NOT EXISTS service_plan_events_stripe_event_idx ON service_plan_events(stripe_event_id);
    CREATE UNIQUE INDEX IF NOT EXISTS service_plan_events_stripe_event_unique
      ON service_plan_events(stripe_event_id) WHERE stripe_event_id IS NOT NULL;

    CREATE TABLE IF NOT EXISTS payment_records (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      company_id UUID,
      created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      contact_id UUID,
      service_plan_id UUID REFERENCES service_plans(id) ON DELETE SET NULL,
      payment_type TEXT NOT NULL DEFAULT 'one_time',
      status TEXT NOT NULL DEFAULT 'pending',
      amount_cents INTEGER NOT NULL,
      currency TEXT NOT NULL DEFAULT 'usd',
      description TEXT,
      stripe_connected_account_id TEXT,
      stripe_customer_id TEXT,
      stripe_payment_intent_id TEXT,
      stripe_invoice_id TEXT,
      stripe_subscription_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS payment_records_user_status_idx ON payment_records(user_id, status);
    CREATE INDEX IF NOT EXISTS payment_records_company_status_idx ON payment_records(company_id, status);
    CREATE INDEX IF NOT EXISTS payment_records_contact_idx ON payment_records(contact_id);
    CREATE INDEX IF NOT EXISTS payment_records_service_plan_idx ON payment_records(service_plan_id);
    CREATE INDEX IF NOT EXISTS payment_records_pi_idx ON payment_records(stripe_payment_intent_id);
    CREATE INDEX IF NOT EXISTS payment_records_sub_idx ON payment_records(stripe_subscription_id);
    CREATE INDEX IF NOT EXISTS payment_records_invoice_idx ON payment_records(stripe_invoice_id);

    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'payment_records_touch_updated_at') THEN
        CREATE TRIGGER payment_records_touch_updated_at
        BEFORE UPDATE ON payment_records
        FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
      END IF;
    END $$;
  `);

  console.log(`[bootstrap] DB ready @ ${nowIso()}`);
}

// ---------- auth middleware ----------
async function authRequired(req, res, next) {
  const token = bearer(req);
  if (!token) return res.status(401).json({ error: "unauthorized" });
  const { rows } = await pool.query(
    `UPDATE sessions s
       SET last_used_at = now()
       FROM users u
       LEFT JOIN employee_permissions p ON p.user_id = u.id
      WHERE s.token = $1 AND u.id = s.user_id AND u.deleted_at IS NULL
      RETURNING s.user_id, u.email, u.role, u.company_id,
                COALESCE(p.can_delete_contacts, u.role = 'employer') AS can_delete_contacts,
                COALESCE(p.can_view_finance, u.role = 'employer') AS can_view_finance,
                COALESCE(p.can_use_finance_ai, u.role = 'employer') AS can_use_finance_ai,
                COALESCE(p.can_view_finance_transactions, u.role = 'employer') AS can_view_finance_transactions,
                COALESCE(p.can_edit_finance_transactions, u.role = 'employer') AS can_edit_finance_transactions,
                COALESCE(p.can_view_finance_accounts, u.role = 'employer') AS can_view_finance_accounts,
                COALESCE(p.can_create_finance_accounts, u.role = 'employer') AS can_create_finance_accounts,
                COALESCE(p.can_edit_finance_accounts, u.role = 'employer') AS can_edit_finance_accounts,
                COALESCE(p.can_adjust_finance_account_balances, u.role = 'employer') AS can_adjust_finance_account_balances,
                COALESCE(p.can_view_finance_receipts, u.role = 'employer') AS can_view_finance_receipts,
                COALESCE(p.can_edit_finance_receipts, u.role = 'employer') AS can_edit_finance_receipts,
                COALESCE(p.can_view_finance_planning, u.role = 'employer') AS can_view_finance_planning,
                COALESCE(p.can_edit_finance_planning, u.role = 'employer') AS can_edit_finance_planning,
                COALESCE(p.can_view_finance_budgets, u.role = 'employer') AS can_view_finance_budgets,
                COALESCE(p.can_edit_finance_budgets, u.role = 'employer') AS can_edit_finance_budgets,
                COALESCE(p.can_view_finance_goals, u.role = 'employer') AS can_view_finance_goals,
                COALESCE(p.can_edit_finance_goals, u.role = 'employer') AS can_edit_finance_goals,
                COALESCE(p.can_view_finance_debts, u.role = 'employer') AS can_view_finance_debts,
                COALESCE(p.can_edit_finance_debts, u.role = 'employer') AS can_edit_finance_debts,
                COALESCE(p.can_view_finance_settings, u.role = 'employer') AS can_view_finance_settings,
                COALESCE(p.can_edit_finance_settings, u.role = 'employer') AS can_edit_finance_settings,
                COALESCE(p.can_manage_company_finance_ai_memories, u.role = 'employer') AS can_manage_company_finance_ai_memories`,
    [token]
  );
  if (!rows.length) return res.status(401).json({ error: "unauthorized" });
  req.userId = rows[0].user_id;
  req.userEmail = rows[0].email;
  req.role = rows[0].role;
  req.companyId = rows[0].company_id;
  req.permissions = {
    canDeleteContacts: !!rows[0].can_delete_contacts,
    canViewFinance: !!rows[0].can_view_finance,
    canUseFinanceAi: !!rows[0].can_use_finance_ai,
    canViewFinanceTransactions: !!rows[0].can_view_finance_transactions,
    canEditFinanceTransactions: !!rows[0].can_edit_finance_transactions,
    canViewFinanceAccounts: !!rows[0].can_view_finance_accounts,
    canCreateFinanceAccounts: !!rows[0].can_create_finance_accounts,
    canEditFinanceAccounts: !!rows[0].can_edit_finance_accounts,
    canAdjustFinanceAccountBalances: !!rows[0].can_adjust_finance_account_balances,
    canViewFinanceReceipts: !!rows[0].can_view_finance_receipts,
    canEditFinanceReceipts: !!rows[0].can_edit_finance_receipts,
    canViewFinancePlanning: !!rows[0].can_view_finance_planning,
    canEditFinancePlanning: !!rows[0].can_edit_finance_planning,
    canViewFinanceBudgets: !!rows[0].can_view_finance_budgets,
    canEditFinanceBudgets: !!rows[0].can_edit_finance_budgets,
    canViewFinanceGoals: !!rows[0].can_view_finance_goals,
    canEditFinanceGoals: !!rows[0].can_edit_finance_goals,
    canViewFinanceDebts: !!rows[0].can_view_finance_debts,
    canEditFinanceDebts: !!rows[0].can_edit_finance_debts,
    canViewFinanceSettings: !!rows[0].can_view_finance_settings,
    canEditFinanceSettings: !!rows[0].can_edit_finance_settings,
    canManageCompanyFinanceAiMemories: !!rows[0].can_manage_company_finance_ai_memories
  };
  req.sessionToken = token;
  next();
}

function requireEmployer(req, res, next) {
  if (req.role !== "employer") return res.status(403).json({ error: "employer_required" });
  next();
}

// ---------- Service plan permission helpers ----------
// Both employers and employees can create new plans and collect the initial
// payment. Only employers can view aggregate financial data, edit existing
// plans, or manage Stripe connectivity.
function canCreateServicePlan(req) { return req.role === "employer" || req.role === "employee"; }
function canCollectServicePlanPayment(req) { return req.role === "employer" || req.role === "employee"; }
function canManageServicePlan(req) { return req.role === "employer"; }
function canViewPaymentDashboard(req) { return req.role === "employer"; }
function canTakeContactPayment(req) { return req.role === "employer" || req.role === "employee"; }

// Resolve the "owning" employer user for the current session.
// Contacts, plans, and business_settings are all scoped to the employer's
// user id even when an employee performs the action, so the whole team
// sees the same data. Falls back to req.userId (employer creating their
// own workspace) when no company owner is recorded.
async function resolveEmployerUserId(req) {
  if (req.role === "employer") return req.userId;
  if (!req.companyId) return req.userId;
  const { rows } = await pool.query(
    `SELECT owner_user_id FROM companies WHERE id = $1`,
    [req.companyId]
  );
  return (rows[0] && rows[0].owner_user_id) || req.userId;
}

async function ensureBusinessSettings(employerUserId, companyId) {
  const existing = await pool.query(
    `SELECT * FROM business_settings WHERE user_id = $1`,
    [employerUserId]
  );
  if (existing.rows.length) {
    if (companyId && !existing.rows[0].company_id) {
      await pool.query(
        `UPDATE business_settings SET company_id = $1, updated_at = now() WHERE user_id = $2`,
        [companyId, employerUserId]
      );
      existing.rows[0].company_id = companyId;
    }
    return existing.rows[0];
  }
  const inserted = await pool.query(
    `INSERT INTO business_settings (user_id, company_id)
     VALUES ($1, $2)
     RETURNING *`,
    [employerUserId, companyId || null]
  );
  return inserted.rows[0];
}

function sanitizeBusinessSettings(row) {
  if (!row) return null;
  return {
    id: row.id,
    user_id: row.user_id,
    company_id: row.company_id,
    business_name: row.business_name,
    stripe_account_id: row.stripe_account_id,
    stripe_connect_status: row.stripe_connect_status,
    stripe_charges_enabled: row.stripe_charges_enabled,
    stripe_payouts_enabled: row.stripe_payouts_enabled,
    stripe_details_submitted: row.stripe_details_submitted,
    stripe_default_currency: row.stripe_default_currency,
    stripe_requirements: row.stripe_requirements || {},
    stripe_capabilities: row.stripe_capabilities || {},
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

async function persistStripeAccountReadiness(userId, account) {
  const readiness = calculateStripeConnectReadiness(account);
  const updated = await pool.query(
    `UPDATE business_settings
        SET stripe_charges_enabled = $2,
            stripe_payouts_enabled = $3,
            stripe_details_submitted = $4,
            stripe_default_currency = COALESCE($5, stripe_default_currency),
            stripe_connect_status = $6,
            stripe_requirements = $7::jsonb,
            stripe_capabilities = $8::jsonb,
            updated_at = now()
      WHERE user_id = $1
      RETURNING *`,
    [
      userId,
      readiness.stripe_charges_enabled,
      readiness.stripe_payouts_enabled,
      readiness.stripe_details_submitted,
      readiness.stripe_default_currency,
      readiness.stripe_connect_status,
      JSON.stringify(readiness.stripe_requirements),
      JSON.stringify(readiness.stripe_capabilities)
    ]
  );
  return updated.rows[0];
}

async function persistStripeAccountReadinessByAccountId(account) {
  const readiness = calculateStripeConnectReadiness(account);
  await pool.query(
    `UPDATE business_settings
        SET stripe_charges_enabled = $2,
            stripe_payouts_enabled = $3,
            stripe_details_submitted = $4,
            stripe_default_currency = COALESCE($5, stripe_default_currency),
            stripe_connect_status = $6,
            stripe_requirements = $7::jsonb,
            stripe_capabilities = $8::jsonb,
            updated_at = now()
      WHERE stripe_account_id = $1`,
    [
      account.id,
      readiness.stripe_charges_enabled,
      readiness.stripe_payouts_enabled,
      readiness.stripe_details_submitted,
      readiness.stripe_default_currency,
      readiness.stripe_connect_status,
      JSON.stringify(readiness.stripe_requirements),
      JSON.stringify(readiness.stripe_capabilities)
    ]
  );
}

function stripeChargesBlockedResponse(account) {
  const readiness = calculateStripeConnectReadiness(account);
  return {
    error: readiness.stripe_connect_status === "action_required" ? "stripe_action_required" : "charges_not_enabled",
    message: readiness.stripe_connect_status === "action_required"
      ? "Stripe requires additional verification before you can accept payments."
      : "Stripe is still reviewing your account before payments can be accepted.",
    stripe_connect_status: readiness.stripe_connect_status,
    stripe_requirements: readiness.stripe_requirements
  };
}

function mapStripeSubscriptionStatus(s) {
  return mapStripeSubscriptionStatusValue(s);
}

function localPaymentStatusFromStripePaymentIntent(pi) {
  return mapStripePaymentIntentStatus(pi);
}

function automationEventForPaymentStatus(status) {
  switch (status) {
    case "succeeded": return "payment.succeeded";
    case "failed": return "payment.failed";
    case "canceled": return "payment.canceled";
    default: return null;
  }
}

async function applyStripePaymentIntentStatus({
  paymentIntent,
  connectedAccountId = null,
  paymentRecordId = null,
  source = "stripe.reconcile",
  stripeEventId = null
}) {
  if (!paymentIntent || !paymentIntent.id) return [];
  const localStatus = localPaymentStatusFromStripePaymentIntent(paymentIntent);
  const params = [paymentIntent.id, localStatus, connectedAccountId];
  let idClause = "";
  if (paymentRecordId) {
    params.push(paymentRecordId);
    idClause = ` AND id = $4`;
  }
  const { rows } = await pool.query(
    `UPDATE payment_records
        SET status = $2,
            updated_at = now()
      WHERE stripe_payment_intent_id = $1
        AND ($3::text IS NULL OR stripe_connected_account_id = $3)
        ${idClause}
      RETURNING id, company_id, contact_id, service_plan_id, amount_cents, currency, status, stripe_connected_account_id`,
    params
  );
  const eventType = automationEventForPaymentStatus(localStatus);
  if (eventType) {
    for (const rec of rows) {
      await emitAutomationEvent({
        companyId: rec.company_id,
        eventType,
        subjectType: "payment",
        subjectId: rec.id,
        source,
        dedupeKey: `${eventType}:${stripeEventId || paymentIntent.id}:${rec.id}`,
        payload: {
          payment_id: rec.id,
          contact_id: rec.contact_id,
          service_plan_id: rec.service_plan_id,
          amount_cents: rec.amount_cents,
          currency: rec.currency,
          stripe_event_id: stripeEventId || null,
          stripe_payment_intent_id: paymentIntent.id,
          stripe_payment_intent_status: paymentIntent.status,
          local_status: localStatus
        }
      });
    }
  }
  console.log("[stripe] payment intent reconciled", {
    source,
    stripe_event_id: stripeEventId || null,
    connected_account_id: connectedAccountId,
    payment_intent_id: paymentIntent.id,
    stripe_status: paymentIntent.status,
    local_status: localStatus,
    matched_records: rows.length
  });
  return rows;
}

async function reconcilePaymentRecordFromStripe(record, { source = "stripe.reconcile" } = {}) {
  const stripe = getStripe();
  if (!stripe) throw new Error("stripe_not_configured");
  if (!record || !record.stripe_payment_intent_id) return record;
  if (!record.stripe_connected_account_id) throw new Error("stripe_connected_account_missing");
  const pi = await stripe.paymentIntents.retrieve(
    record.stripe_payment_intent_id,
    {},
    { stripeAccount: record.stripe_connected_account_id }
  );
  const rows = await applyStripePaymentIntentStatus({
    paymentIntent: pi,
    connectedAccountId: record.stripe_connected_account_id,
    paymentRecordId: record.id,
    source
  });
  return rows[0] || record;
}

function stripeInvoicePaymentIntent(invoice) {
  if (!invoice) return null;
  const pi = invoice.payment_intent || invoice.confirmation_secret?.payment_intent || null;
  return pi && typeof pi === "object" ? pi : null;
}

async function applyStripeSubscriptionStatus({
  subscription,
  connectedAccountId,
  servicePlanId = null,
  source = "stripe.subscription_reconcile",
  stripeEventId = null
}) {
  if (!subscription || !subscription.id) return [];
  const invoice = subscription.latest_invoice && typeof subscription.latest_invoice === "object"
    ? subscription.latest_invoice
    : null;
  const pi = stripeInvoicePaymentIntent(invoice);
  const paymentCollectionPaused = isStripePaymentCollectionPaused(subscription);
  const localStatus = mapStripeSubscriptionToWolfCRMStatus(subscription);
  const params = [
    subscription.id,
    subscription.status,
    localStatus,
    invoice?.id || null,
    pi?.id || null,
    connectedAccountId,
    paymentCollectionPaused
  ];
  let idClause = "";
  if (servicePlanId) {
    params.push(servicePlanId);
    idClause = ` AND id = $8`;
  }
  const { rows } = await pool.query(
    `UPDATE service_plans
        SET stripe_subscription_status = $2,
            status = COALESCE($3, status),
            stripe_latest_invoice_id = COALESCE($4, stripe_latest_invoice_id),
            stripe_payment_intent_id = COALESCE($5, stripe_payment_intent_id),
            stripe_payment_collection_paused = $7,
            updated_at = now()
      WHERE stripe_subscription_id = $1
        AND ($6::text IS NULL OR stripe_connected_account_id = $6)
        ${idClause}
      RETURNING *`,
    params
  );
  for (const plan of rows) {
    if (plan.company_id) {
      const eventType = localStatus === "active"
        ? "service_plan.subscription_active"
        : ({
            past_due: "service_plan.subscription_past_due",
            paused: "service_plan.subscription_paused",
            canceled: "service_plan.subscription_canceled",
            failed: "service_plan.subscription_failed",
            payment_pending: "service_plan.subscription_payment_pending"
          }[localStatus] || "service_plan.updated");
      await emitAutomationEvent({
        companyId: plan.company_id,
        eventType,
        subjectType: "service_plan",
        subjectId: plan.id,
        source,
        dedupeKey: `${eventType}:${stripeEventId || subscription.id}:${plan.id}`,
        payload: {
          service_plan_id: plan.id,
          contact_id: plan.contact_id,
          stripe_event_id: stripeEventId || null,
          stripe_subscription_id: subscription.id,
          stripe_invoice_id: invoice?.id || null,
          stripe_payment_intent_id: pi?.id || null,
          subscription_status: subscription.status,
          stripe_payment_collection_paused: paymentCollectionPaused,
          status: plan.status
        }
      });
      if (localStatus === "paused" || localStatus === "canceled") {
        await cancelAutomationSchedulesForSubject(plan.company_id, "service_plan", plan.id);
      } else {
        await syncAutomationSchedulesForServicePlan(plan.company_id, plan);
      }
    }
  }
  if (pi) {
    await applyStripePaymentIntentStatus({
      paymentIntent: pi,
      connectedAccountId,
      source,
      stripeEventId
    });
  }
  console.log("[stripe] subscription reconciled", {
    source,
    stripe_event_id: stripeEventId || null,
    connected_account_id: connectedAccountId,
    subscription_id: subscription.id,
    stripe_subscription_status: subscription.status,
    stripe_payment_collection_paused: paymentCollectionPaused,
    local_status: localStatus,
    latest_invoice_id: invoice?.id || null,
    payment_intent_id: pi?.id || null,
    matched_plans: rows.length
  });
  return rows;
}

async function reconcileServicePlanFromStripe(plan, { source = "stripe.service_plan_reconcile" } = {}) {
  const stripe = getStripe();
  if (!stripe) throw new Error("stripe_not_configured");
  if (!plan || !plan.stripe_subscription_id) throw new Error("stripe_subscription_missing");
  if (!plan.stripe_connected_account_id) throw new Error("stripe_connected_account_missing");
  let subscription = await stripe.subscriptions.retrieve(
    plan.stripe_subscription_id,
    { expand: ["latest_invoice.payment_intent"] },
    { stripeAccount: plan.stripe_connected_account_id }
  );
  if (["canceled", "incomplete_expired"].includes(subscription.status)) {
    subscription = await recoverServicePlanSubscriptionFromStripe(plan, subscription, { source });
  }
  const rows = await applyStripeSubscriptionStatus({
    subscription,
    connectedAccountId: plan.stripe_connected_account_id,
    servicePlanId: plan.id,
    source
  });
  return rows[0] || plan;
}

async function recoverServicePlanSubscriptionFromStripe(plan, storedSubscription, { source = "stripe.service_plan_recover" } = {}) {
  const stripe = getStripe();
  if (!plan.stripe_customer_id) {
    console.warn("[stripe] subscription recovery skipped without customer", {
      source,
      service_plan_id: plan.id,
      stored_subscription_id: storedSubscription.id,
      stored_subscription_status: storedSubscription.status
    });
    return storedSubscription;
  }
  const listed = await stripe.subscriptions.list(
    {
      customer: plan.stripe_customer_id,
      status: "all",
      limit: 100,
      expand: ["data.latest_invoice.payment_intent"]
    },
    { stripeAccount: plan.stripe_connected_account_id }
  );
  const recovery = selectRecoverableSubscription(listed.data || [], {
    planId: plan.id,
    customerId: plan.stripe_customer_id
  });
  if (recovery.action === "conflict") {
    const err = new Error("multiple_active_matching_subscriptions");
    err.statusCode = 409;
    err.subscriptionIds = recovery.subscriptions.map((subscription) => subscription.id);
    console.warn("[stripe] subscription recovery conflict", {
      source,
      service_plan_id: plan.id,
      customer_id: plan.stripe_customer_id,
      connected_account_id: plan.stripe_connected_account_id,
      stored_subscription_id: storedSubscription.id,
      matching_subscription_ids: err.subscriptionIds
    });
    throw err;
  }
  if (recovery.action !== "adopt") {
    console.warn("[stripe] subscription recovery found no viable match", {
      source,
      service_plan_id: plan.id,
      customer_id: plan.stripe_customer_id,
      connected_account_id: plan.stripe_connected_account_id,
      stored_subscription_id: storedSubscription.id,
      stored_subscription_status: storedSubscription.status,
      reason: recovery.reason
    });
    return storedSubscription;
  }
  const recovered = recovery.subscription;
  const invoice = recovered.latest_invoice && typeof recovered.latest_invoice === "object"
    ? recovered.latest_invoice
    : null;
  const pi = stripeInvoicePaymentIntent(invoice);
  const customerId = stripeSubscriptionCustomerId(recovered) || plan.stripe_customer_id;
  await pool.query(
    `UPDATE service_plans
        SET stripe_subscription_id = $2,
            stripe_subscription_status = $3,
            stripe_customer_id = COALESCE($4, stripe_customer_id),
            stripe_latest_invoice_id = COALESCE($5, stripe_latest_invoice_id),
            stripe_payment_intent_id = COALESCE($6, stripe_payment_intent_id),
            updated_at = now()
      WHERE id = $1`,
    [plan.id, recovered.id, recovered.status, customerId, invoice?.id || null, pi?.id || null]
  );
  await pool.query(
    `INSERT INTO service_plan_events (user_id, company_id, service_plan_id, contact_id, event_type, notes)
     VALUES ($1,$2,$3,$4,'stripe_subscription_recovered',$5)
     ON CONFLICT DO NOTHING`,
    [
      plan.user_id,
      plan.company_id || null,
      plan.id,
      plan.contact_id || null,
      `Recovered Stripe subscription ${recovered.id} (${recovered.status}) from stored subscription ${storedSubscription.id} (${storedSubscription.status})`
    ]
  );
  console.warn("[stripe] subscription recovered from metadata", {
    source,
    service_plan_id: plan.id,
    customer_id: customerId,
    connected_account_id: plan.stripe_connected_account_id,
    previous_subscription_id: storedSubscription.id,
    previous_subscription_status: storedSubscription.status,
    recovered_subscription_id: recovered.id,
    recovered_subscription_status: recovered.status,
    metadata_plan_id: recovered.metadata?.wolfcrm_plan_id || null
  });
  return recovered;
}

async function buildExistingSubscriptionPaymentSheetResponse({ plan, subscription, connectedAccountId, publishableKey, actorUserId }) {
  const stripe = getStripe();
  const invoice = subscription.latest_invoice && typeof subscription.latest_invoice === "object"
    ? subscription.latest_invoice
    : null;
  const pi = stripeInvoicePaymentIntent(invoice);
  if (!subscriptionCanResumePayment(subscription) || !invoice || !pi) return null;
  const customerId = typeof subscription.customer === "string" ? subscription.customer : subscription.customer?.id;
  if (!customerId) return null;
  const ephemeralKey = await stripe.ephemeralKeys.create(
    { customer: customerId },
    { apiVersion: STRIPE_MOBILE_EPHEMERAL_KEY_API_VERSION, stripeAccount: connectedAccountId }
  );
  const paymentRecord = await pool.query(
    `UPDATE payment_records
        SET stripe_customer_id = COALESCE(stripe_customer_id, $4),
            stripe_invoice_id = COALESCE(stripe_invoice_id, $5),
            stripe_payment_intent_id = COALESCE(stripe_payment_intent_id, $6),
            updated_at = now()
      WHERE service_plan_id = $1
        AND stripe_subscription_id = $2
        AND user_id = $3
      RETURNING *`,
    [plan.id, subscription.id, plan.user_id, customerId, invoice.id, pi.id]
  );
  let rec = paymentRecord.rows[0];
  if (!rec) {
    const inserted = await pool.query(
      `INSERT INTO payment_records (
         user_id, company_id, created_by_user_id, contact_id, service_plan_id,
         payment_type, status, amount_cents, currency, description,
         stripe_connected_account_id, stripe_customer_id, stripe_payment_intent_id,
         stripe_invoice_id, stripe_subscription_id
       ) VALUES ($1,$2,$3,$4,$5,'service_plan_first_payment','pending',$6,$7,$8,$9,$10,$11,$12,$13)
       RETURNING *`,
      [
        plan.user_id, plan.company_id || null, actorUserId || plan.created_by_user_id || null,
        plan.contact_id, plan.id,
        plan.price_cents, (plan.currency || "usd").toLowerCase(),
        `Initial payment for ${plan.plan_name}`,
        connectedAccountId, customerId, pi.id, invoice.id, subscription.id
      ]
    );
    rec = inserted.rows[0];
  }
  return {
    publishable_key: publishableKey,
    connected_account_id: connectedAccountId,
    customer_id: customerId,
    ephemeral_key_secret: ephemeralKey.secret,
    payment_intent_client_secret: pi.client_secret,
    subscription_id: subscription.id,
    service_plan_id: plan.id,
    payment_record_id: rec.id,
    reused_existing_subscription: true
  };
}

function serviceIntervalDays(interval, count) {
  const n = Math.max(1, parseInt(count || 1, 10));
  switch ((interval || "month").toLowerCase()) {
    case "day":  return n;
    case "week": return n * 7;
    case "year": return n * 365;
    case "month":
    default:     return n * 30;
  }
}

function addDaysISO(dateInput, days) {
  const d = dateInput ? new Date(dateInput) : new Date();
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}

function stripeIntervalMap(interval, count) {
  const c = Math.max(1, parseInt(count || 1, 10));
  const iv = (interval || "month").toLowerCase();
  if (iv === "day" || iv === "week" || iv === "month" || iv === "year") {
    return { interval: iv, interval_count: c };
  }
  return { interval: "month", interval_count: c };
}

function sanitizeServicePlan(row, { employeeSafe = false } = {}) {
  if (!row) return null;
  const base = {
    id: row.id,
    contact_id: row.contact_id,
    plan_name: row.plan_name,
    status: row.status,
    price_cents: row.price_cents,
    currency: row.currency,
    billing_interval: row.billing_interval,
    billing_interval_count: row.billing_interval_count,
    service_interval: row.service_interval,
    service_interval_count: row.service_interval_count,
    first_service_date: row.first_service_date,
    next_service_date: row.next_service_date,
    last_service_date: row.last_service_date,
    included_services: row.included_services,
    notes: row.notes,
    stripe_subscription_status: row.stripe_subscription_status,
    stripe_payment_collection_paused: Boolean(row.stripe_payment_collection_paused),
    created_at: row.created_at,
    updated_at: row.updated_at,
    // Contact info if joined
    contact_name: row.contact_name,
    contact_phone: row.contact_phone,
    contact_email: row.contact_email,
    contact_address: row.contact_address
  };
  if (employeeSafe) return base;
  return {
    ...base,
    user_id: row.user_id,
    created_by_user_id: row.created_by_user_id,
    stripe_connected_account_id: row.stripe_connected_account_id,
    stripe_customer_id: row.stripe_customer_id,
    stripe_product_id: row.stripe_product_id,
    stripe_price_id: row.stripe_price_id,
    stripe_subscription_id: row.stripe_subscription_id,
    stripe_payment_intent_id: row.stripe_payment_intent_id,
    stripe_latest_invoice_id: row.stripe_latest_invoice_id
  };
}

function sanitizePaymentRecord(row, { employeeSafe = false } = {}) {
  if (!row) return null;
  const base = {
    id: row.id,
    contact_id: row.contact_id,
    service_plan_id: row.service_plan_id,
    payment_type: row.payment_type,
    status: row.status,
    amount_cents: row.amount_cents,
    currency: row.currency,
    description: row.description,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
  if (employeeSafe) return base;
  return {
    ...base,
    user_id: row.user_id,
    created_by_user_id: row.created_by_user_id,
    stripe_connected_account_id: row.stripe_connected_account_id,
    stripe_customer_id: row.stripe_customer_id,
    stripe_payment_intent_id: row.stripe_payment_intent_id,
    stripe_invoice_id: row.stripe_invoice_id,
    stripe_subscription_id: row.stripe_subscription_id
  };
}

function userPayload(user, permissions = null, company = null) {
  return {
    id: user.id,
    email: user.email,
    role: user.role,
    company_id: user.company_id,
    display_name: user.display_name,
    photo_url: user.photo_url,
    company,
    permissions: permissions || { can_delete_contacts: user.role === "employer" }
  };
}

function employeePermissionPayload(row = {}) {
  return {
    can_delete_contacts: !!row.can_delete_contacts,
    can_view_finance: !!row.can_view_finance,
    can_use_finance_ai: !!row.can_use_finance_ai,
    can_view_finance_transactions: !!row.can_view_finance_transactions,
    can_edit_finance_transactions: !!row.can_edit_finance_transactions,
    can_view_finance_accounts: !!row.can_view_finance_accounts,
    can_create_finance_accounts: !!row.can_create_finance_accounts,
    can_edit_finance_accounts: !!row.can_edit_finance_accounts,
    can_adjust_finance_account_balances: !!row.can_adjust_finance_account_balances,
    can_view_finance_receipts: !!row.can_view_finance_receipts,
    can_edit_finance_receipts: !!row.can_edit_finance_receipts,
    can_view_finance_planning: !!row.can_view_finance_planning,
    can_edit_finance_planning: !!row.can_edit_finance_planning,
    can_view_finance_budgets: !!row.can_view_finance_budgets,
    can_edit_finance_budgets: !!row.can_edit_finance_budgets,
    can_view_finance_goals: !!row.can_view_finance_goals,
    can_edit_finance_goals: !!row.can_edit_finance_goals,
    can_view_finance_debts: !!row.can_view_finance_debts,
    can_edit_finance_debts: !!row.can_edit_finance_debts,
    can_view_finance_settings: !!row.can_view_finance_settings,
    can_edit_finance_settings: !!row.can_edit_finance_settings,
    can_manage_company_finance_ai_memories: !!row.can_manage_company_finance_ai_memories
  };
}

async function createNotification(userId, companyId, kind, title, body, data = {}) {
  if (!userId) return;
  await pool.query(
    `INSERT INTO notifications(id, user_id, company_id, kind, title, body, data)
     VALUES($1, $2, $3, $4, $5, $6, $7::jsonb)`,
    [randomUUID(), userId, companyId || null, kind, title, body || null, JSON.stringify(data || {})]
  );
}

async function notifyMany(userIds, companyId, kind, title, body, data = {}, skipUserId = null) {
  const unique = [...new Set((userIds || []).filter(Boolean))].filter((id) => id !== skipUserId);
  for (const userId of unique) {
    await createNotification(userId, companyId, kind, title, body, data);
  }
  if (["internal_message", "channel_message", "job_assignment", "job_scheduled"].includes(kind)) {
    await sendPushToUsers(unique, kind, {
      title,
      body,
      payload: { type: kind, ...(data || {}) },
      threadId: kind
    }).catch((e) => {
      console.error("[push] notifyMany APNs failed:", { category: kind, code: e?.code, message: e?.message });
    });
  }
}

function parseAttachments(input) {
  if (!Array.isArray(input)) return [];
  return input.slice(0, 10).map((a) => ({
    kind: ["photo", "video", "file"].includes(a.kind) ? a.kind : "file",
    object_key: (a.object_key || "").toString() || null,
    url: (a.url || "").toString() || null,
    thumbnail_object_key: (a.thumbnail_object_key || "").toString() || null,
    thumbnail_url: (a.thumbnail_url || "").toString() || null,
    file_name: (a.file_name || "").toString() || null,
    mime_type: (a.mime_type || "").toString() || null,
    byte_size: Number.isFinite(Number(a.byte_size)) ? Number(a.byte_size) : null
  }));
}

async function attachRows(messageId, attachments) {
  for (const a of parseAttachments(attachments)) {
    await pool.query(
      `INSERT INTO message_attachments
        (id, message_id, kind, object_key, url, thumbnail_object_key, thumbnail_url, file_name, mime_type, byte_size)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [randomUUID(), messageId, a.kind, a.object_key, a.url, a.thumbnail_object_key, a.thumbnail_url, a.file_name, a.mime_type, a.byte_size]
    );
  }
}

async function messageRowsWithAttachments(rows) {
  if (!rows.length) return rows;
  const ids = rows.map((r) => r.id);
  const { rows: atts } = await pool.query(
    `SELECT id, message_id, kind, object_key, url, thumbnail_object_key, thumbnail_url,
            file_name, mime_type, byte_size, created_at
       FROM message_attachments
      WHERE message_id = ANY($1::text[])
      ORDER BY created_at ASC`,
    [ids]
  );
  const byMessage = new Map();
  for (const a of atts) {
    if (!byMessage.has(a.message_id)) byMessage.set(a.message_id, []);
    byMessage.get(a.message_id).push(a);
  }
  return rows.map((r) => ({ ...r, attachments: byMessage.get(r.id) || [] }));
}

// ---------- auth routes ----------
app.post("/auth/signup", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = (req.body.password || "").toString();
    const role = req.body.role === "employee" ? "employee" : "employer";
    const joinCode = (req.body.join_code || "").toString().trim();
    const companyName = (req.body.company_name || "Company").toString().trim() || "Company";
    const companyCode = (req.body.company_code || "").toString().trim();

    if (!email || !email.includes("@")) return res.status(400).json({ error: "invalid_email" });
    if (!passwordIsValid(password)) return res.status(400).json({ error: "weak_password" });

    const existing = await pool.query(`SELECT id, password_hash FROM users WHERE email = $1`, [email]);
    if (existing.rows.length && existing.rows[0].password_hash) {
      return res.status(409).json({ error: "email_exists" });
    }

    let company;
    if (role === "employee") {
      if (!companyCodeIsValid(joinCode)) return res.status(400).json({ error: "invalid_join_code" });
      const r = await pool.query(`SELECT * FROM companies WHERE join_code = $1`, [joinCode]);
      if (!r.rows.length) return res.status(400).json({ error: "company_not_found" });
      company = r.rows[0];
    } else {
      if (!companyCodeIsValid(companyCode)) return res.status(400).json({ error: "invalid_company_code" });
      const r = await pool.query(
        `INSERT INTO companies(name, join_code)
         VALUES($1,$2)
         RETURNING *`,
        [companyName, companyCode]
      );
      company = r.rows[0];
    }

    const { rows } = existing.rows.length
      ? await pool.query(
          `UPDATE users
           SET password_hash = $1, role = $2, company_id = $3
           WHERE email = $4
           RETURNING id, email, role, company_id`,
          [hashPassword(password), role, company.id, email]
        )
      : await pool.query(
          `INSERT INTO users(email, password_hash, role, company_id)
           VALUES($1,$2,$3,$4)
           RETURNING id, email, role, company_id`,
          [email, hashPassword(password), role, company.id]
        );
    const user = rows[0];

    if (role === "employer") {
      await pool.query(`UPDATE companies SET owner_user_id = $1 WHERE id = $2`, [user.id, company.id]);
    } else {
      await pool.query(
        `INSERT INTO employee_permissions(user_id, company_id, can_delete_contacts)
         VALUES($1,$2,false)`,
        [user.id, company.id]
      );
    }
    try {
      const payload = { employee_id: user.id, email: user.email, role: user.role, active: true };
      await emitAutomationEvent({ companyId: company.id, eventType: "employee.created", subjectType: "employee", subjectId: user.id, actorUserId: user.id, source: "ios", dedupeKey: `employee.created:${user.id}`, payload });
      if (role === "employee") {
        await emitAutomationEvent({ companyId: company.id, eventType: "employee.joined", subjectType: "employee", subjectId: user.id, actorUserId: user.id, source: "ios", dedupeKey: `employee.joined:${user.id}`, payload });
      }
    } catch (automationErr) {
      console.warn("[automations] employee signup hook failed", automationErr?.message || automationErr);
    }

    const token = randomUUID();
    await pool.query(`INSERT INTO sessions(token, user_id) VALUES($1,$2)`, [token, user.id]);
    res.json({ token, user: userPayload(user, { can_delete_contacts: role === "employer" }, { id: company.id, name: company.name, join_code: company.join_code }) });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "company_code_taken" });
    console.error(e);
    res.status(500).json({ error: "signup_failed" });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = (req.body.password || "").toString();
    const { rows } = await pool.query(
      `SELECT u.*, c.name AS company_name, c.join_code, COALESCE(p.can_delete_contacts, u.role = 'employer') AS can_delete_contacts
         FROM users u
         LEFT JOIN companies c ON c.id = u.company_id
         LEFT JOIN employee_permissions p ON p.user_id = u.id
        WHERE u.email = $1`,
      [email]
    );
    if (!rows.length || !verifyPassword(password, rows[0].password_hash)) {
      return res.status(401).json({ error: "invalid_login" });
    }
    if (rows[0].deleted_at) {
      // Account was revoked by the employer.
      return res.status(403).json({ error: "account_disabled", message: "This account has been removed. Contact your employer to restore access." });
    }
    const u = rows[0];
    const token = randomUUID();
    await pool.query(`INSERT INTO sessions(token, user_id) VALUES($1,$2)`, [token, u.id]);
    res.json({
      token,
      user: userPayload(
        u,
        { can_delete_contacts: !!u.can_delete_contacts },
        u.company_id ? { id: u.company_id, name: u.company_name, join_code: u.join_code } : null
      )
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "login_failed" });
  }
});

app.post("/auth/password/request-reset", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    if (!email || !email.includes("@")) return res.status(400).json({ error: "invalid_email" });
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = new Date(Date.now() + 10 * 60 * 1000);
    await pool.query(
      `INSERT INTO password_reset_codes(email, code, expires_at) VALUES($1,$2,$3)`,
      [email, code, expires.toISOString()]
    );
    const delivery = await sendEmailCode(email, code, expires.toISOString(), "reset");
    res.json({ ok: true, ...delivery });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "reset_request_failed" });
  }
});

app.post("/auth/password/reset", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const code = (req.body.code || "").toString().trim();
    const password = (req.body.password || "").toString();
    if (!passwordIsValid(password)) return res.status(400).json({ error: "weak_password" });
    const { rows } = await pool.query(
      `SELECT * FROM password_reset_codes
       WHERE email = $1 AND code = $2
       ORDER BY created_at DESC
       LIMIT 1`,
      [email, code]
    );
    if (!rows.length) return res.status(400).json({ error: "invalid_code" });
    const reset = rows[0];
    if (reset.used_at) return res.status(400).json({ error: "code_used" });
    if (new Date(reset.expires_at).getTime() < Date.now()) return res.status(400).json({ error: "code_expired" });

    await pool.query(`UPDATE password_reset_codes SET used_at = now() WHERE id = $1`, [reset.id]);
    const r = await pool.query(
      `UPDATE users SET password_hash = $1 WHERE email = $2 RETURNING id`,
      [hashPassword(password), email]
    );
    if (!r.rowCount) return res.status(404).json({ error: "user_not_found" });
    await pool.query(`DELETE FROM sessions WHERE user_id = $1`, [r.rows[0].id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "reset_failed" });
  }
});

app.post("/auth/request", async (req, res) => {
  try {
    const emailRaw = (req.body.email || "").toString().trim().toLowerCase();
    if (!emailRaw || !emailRaw.includes("@")) {
      return res.status(400).json({ error: "invalid_email" });
    }

    await pool.query(
      `INSERT INTO users(email) VALUES($1)
       ON CONFLICT(email) DO UPDATE SET email = EXCLUDED.email`,
      [emailRaw]
    );

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 min
    await pool.query(
      `INSERT INTO magic_tokens(email, code, expires_at) VALUES($1,$2,$3)`,
      [emailRaw, code, expires.toISOString()]
    );

    const delivery = await sendEmailCode(emailRaw, code, expires.toISOString(), "login");
    res.json({ ok: true, ...delivery, expires_at: expires.toISOString() });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "request_failed" });
  }
});

app.post("/auth/verify", async (req, res) => {
  try {
    const email = (req.body.email || "").toString().trim().toLowerCase();
    const code = (req.body.code || "").toString().trim();
    if (!email || !code) return res.status(400).json({ error: "missing_params" });

    const { rows: tokens } = await pool.query(
      `SELECT * FROM magic_tokens
       WHERE email = $1 AND code = $2
       ORDER BY created_at DESC
       LIMIT 1`,
      [email, code]
    );
    if (!tokens.length) return res.status(400).json({ error: "invalid_code" });

    const t = tokens[0];
    if (t.used_at) return res.status(400).json({ error: "code_used" });
    if (new Date(t.expires_at).getTime() < Date.now()) {
      return res.status(400).json({ error: "code_expired" });
    }

    await pool.query(`UPDATE magic_tokens SET used_at = now() WHERE id = $1`, [t.id]);

    const { rows: users } = await pool.query(`SELECT * FROM users WHERE email = $1`, [email]);
    if (!users.length) return res.status(400).json({ error: "user_missing" });
    const user = users[0];

    const token = randomUUID();
    await pool.query(`INSERT INTO sessions(token, user_id) VALUES($1,$2)`, [token, user.id]);

    res.json({ token, user: { id: user.id, email: user.email } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "verify_failed" });
  }
});

app.post("/auth/logout", authRequired, async (req, res) => {
  try {
    await pool.query(`DELETE FROM sessions WHERE token = $1`, [req.sessionToken]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "logout_failed" });
  }
});

app.get("/me", authRequired, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT u.id, u.email, u.role, u.company_id, u.created_at,
            u.display_name, u.photo_url,
            c.name AS company_name, c.join_code,
            COALESCE(p.can_delete_contacts, u.role = 'employer') AS can_delete_contacts,
            COALESCE(p.can_view_finance, u.role = 'employer') AS can_view_finance,
            COALESCE(p.can_use_finance_ai, u.role = 'employer') AS can_use_finance_ai,
            COALESCE(p.can_view_finance_transactions, u.role = 'employer') AS can_view_finance_transactions,
            COALESCE(p.can_edit_finance_transactions, u.role = 'employer') AS can_edit_finance_transactions,
            COALESCE(p.can_view_finance_accounts, u.role = 'employer') AS can_view_finance_accounts,
            COALESCE(p.can_create_finance_accounts, u.role = 'employer') AS can_create_finance_accounts,
            COALESCE(p.can_edit_finance_accounts, u.role = 'employer') AS can_edit_finance_accounts,
            COALESCE(p.can_adjust_finance_account_balances, u.role = 'employer') AS can_adjust_finance_account_balances,
            COALESCE(p.can_view_finance_receipts, u.role = 'employer') AS can_view_finance_receipts,
            COALESCE(p.can_edit_finance_receipts, u.role = 'employer') AS can_edit_finance_receipts,
            COALESCE(p.can_view_finance_planning, u.role = 'employer') AS can_view_finance_planning,
            COALESCE(p.can_edit_finance_planning, u.role = 'employer') AS can_edit_finance_planning,
            COALESCE(p.can_view_finance_budgets, u.role = 'employer') AS can_view_finance_budgets,
            COALESCE(p.can_edit_finance_budgets, u.role = 'employer') AS can_edit_finance_budgets,
            COALESCE(p.can_view_finance_goals, u.role = 'employer') AS can_view_finance_goals,
            COALESCE(p.can_edit_finance_goals, u.role = 'employer') AS can_edit_finance_goals,
            COALESCE(p.can_view_finance_debts, u.role = 'employer') AS can_view_finance_debts,
            COALESCE(p.can_edit_finance_debts, u.role = 'employer') AS can_edit_finance_debts,
            COALESCE(p.can_view_finance_settings, u.role = 'employer') AS can_view_finance_settings,
            COALESCE(p.can_edit_finance_settings, u.role = 'employer') AS can_edit_finance_settings,
            COALESCE(p.can_manage_company_finance_ai_memories, u.role = 'employer') AS can_manage_company_finance_ai_memories
       FROM users u
       LEFT JOIN companies c ON c.id = u.company_id
       LEFT JOIN employee_permissions p ON p.user_id = u.id
      WHERE u.id = $1`,
    [req.userId]
  );
  const u = rows[0];
  res.json({
    user: userPayload(
      u,
      employeePermissionPayload(u),
      u.company_id ? { id: u.company_id, name: u.company_name, join_code: u.join_code } : null
    )
  });
});

// ---------- Twilio diagnostics ----------
app.get("/api/twilio/status", authRequired, async (_req, res) => {
  const { configured, accountSid } = twilioConfig();
  if (!configured) {
    return res.json({
      configured: false,
      connected: false,
      error: "twilio_not_configured"
    });
  }

  try {
    const client = createTwilioClient();
    await client.incomingPhoneNumbers.list({ limit: 1 });
    res.json({
      configured: true,
      connected: true,
      accountSid
    });
  } catch (e) {
    console.error("[twilio/status] connection failed:", {
      status: e?.status,
      code: e?.code,
      message: e?.message
    });
    res.json({
      configured: true,
      connected: false,
      error: "twilio_connection_failed"
    });
  }
});

// Public Twilio inbound SMS/MMS webhook. Authenticated by Twilio signature,
// not by WolfCRM bearer sessions.
app.post("/webhooks/twilio/sms", async (req, res) => {
  const messageSid = (req.body.MessageSid || req.body.SmsSid || "").toString().trim();
  const fromNumber = normalizeE164Phone(req.body.From);
  const toNumber = normalizeE164Phone(req.body.To);

  try {
    const validation = validateTwilioWebhook(req);
    if (!validation.ok) {
      console.error("[twilio/sms] webhook validation failed:", validation.error);
      if (validation.error === "twilio_auth_token_missing") {
        return res.status(500).type("text/plain").send("Twilio webhook auth is not configured");
      }
      return res.status(403).type("text/plain").send("Forbidden");
    }

    if (!fromNumber || !toNumber) {
      console.warn("[twilio/sms] missing from/to", { messageSid, hasFrom: !!fromNumber, hasTo: !!toNumber });
      return res.status(200).type("text/xml").send(emptyMessagingResponse());
    }

    const { rows: lineRows } = await pool.query(
      `SELECT id, company_id
         FROM phone_lines
        WHERE phone_number = $1 AND active = true
        LIMIT 1`,
      [toNumber]
    );
    if (!lineRows.length) {
      console.warn("[twilio/sms] destination phone line not provisioned", { messageSid, toNumber });
      return res.status(200).type("text/xml").send(emptyMessagingResponse());
    }
    const phoneLine = lineRows[0];

    if (messageSid) {
      const existing = await pool.query(
        `SELECT id FROM sms_messages WHERE twilio_message_sid = $1 LIMIT 1`,
        [messageSid]
      );
      if (existing.rowCount) {
        console.log("[twilio/sms] duplicate webhook ignored", { messageSid });
        return res.status(200).type("text/xml").send(emptyMessagingResponse());
      }
    }

    const contactID = await findSmsContactID({
      companyId: phoneLine.company_id,
      externalPhone: fromNumber
    });
    const { count: mediaCount, media } = twilioMediaMetadata(req.body);
    const messageStatus = (req.body.SmsStatus || req.body.MessageStatus || "received").toString();
    const body = (req.body.Body || "").toString();
    const client = await pool.connect();
    let storedConversationID = null;
    let storedMessage = null;
    let pushTitle = fromNumber;

    try {
      await client.query("BEGIN");
      const { rows: conversationRows } = await client.query(
        `INSERT INTO sms_conversations(phone_line_id, external_phone_number, contact_id, last_message_at)
         VALUES($1, $2, $3, now())
         ON CONFLICT(phone_line_id, external_phone_number)
         DO UPDATE SET
           contact_id = COALESCE(sms_conversations.contact_id, EXCLUDED.contact_id),
           last_message_at = now(),
           updated_at = now(),
           deleted_at = NULL
         RETURNING id`,
        [phoneLine.id, fromNumber, contactID]
      );
      const conversationID = conversationRows[0].id;
      storedConversationID = conversationID;

      try {
        const messageInsert = await client.query(
          `INSERT INTO sms_messages(
             conversation_id, twilio_message_sid, direction, from_number, to_number,
             body, message_status, media_count, media, twilio_error_code, twilio_error_message
           )
           VALUES($1,$2,'inbound',$3,$4,$5,$6,$7,$8::jsonb,$9,$10)
           RETURNING id, conversation_id, twilio_message_sid, direction, from_number, to_number, body, message_status, media_count, created_at`,
          [
            conversationID,
            messageSid || null,
            fromNumber,
            toNumber,
            body,
            messageStatus,
            mediaCount,
            JSON.stringify(media),
            req.body.ErrorCode || null,
            req.body.ErrorMessage || null
          ]
        );
        storedMessage = messageInsert.rows[0] || null;
      } catch (e) {
        if (e?.code === "23505" && messageSid) {
          await client.query("ROLLBACK");
          console.log("[twilio/sms] duplicate webhook ignored after unique check", { messageSid });
          return res.status(200).type("text/xml").send(emptyMessagingResponse());
        }
        throw e;
      }

      await client.query(
        `UPDATE sms_conversations
            SET last_message_at = now(), updated_at = now()
          WHERE id = $1`,
        [conversationID]
      );
      await client.query("COMMIT");
      console.log("[twilio/sms] inbound stored", { messageSid, phoneLineID: phoneLine.id, conversationID, mediaCount });
      try {
        const normalizedBody = body.trim().toUpperCase();
        if (["STOP", "STOPALL", "UNSUBSCRIBE", "CANCEL", "END", "QUIT"].includes(normalizedBody)) {
          await recordPhoneSmsConsent(phoneLine.company_id, fromNumber, "opted_out", "twilio.opt_out");
        } else if (["START", "YES", "UNSTOP"].includes(normalizedBody)) {
          await recordPhoneSmsConsent(phoneLine.company_id, fromNumber, "opted_in", "twilio.opt_in");
        }
        await cancelNoReplySchedulesForConversation(phoneLine.company_id, conversationID);
        await syncAutomationSchedulesForSmsConversationActivity(phoneLine.company_id, conversationID, storedMessage || { id: messageSid, created_at: new Date().toISOString() });
        const counts = await pool.query(
          `SELECT COUNT(*) FILTER (WHERE direction = 'inbound')::int AS inbound_count,
                  COUNT(*) FILTER (WHERE direction = 'outbound')::int AS outbound_count,
                  COUNT(*)::int AS total_count,
                  MAX(created_at) FILTER (WHERE direction = 'outbound') AS last_outbound_at,
                  (SELECT id FROM sms_messages WHERE conversation_id = $1 AND direction = 'outbound' ORDER BY created_at DESC LIMIT 1) AS last_outbound_message_id
             FROM sms_messages
            WHERE conversation_id = $1 AND deleted_at IS NULL`,
          [conversationID]
        );
        const stats = counts.rows[0] || {};
        const basePayload = {
          message_id: storedMessage?.id || null,
          conversation_id: conversationID,
          contact_id: contactID,
          contact_exists: Boolean(contactID),
          message_sid: messageSid || null,
          from_number: fromNumber,
          to_number: toNumber,
          external_number: fromNumber,
          body,
          direction: "inbound",
          status: messageStatus,
          media_count: mediaCount,
          has_media: mediaCount > 0,
          inbound_count: stats.inbound_count || 0,
          outbound_count: stats.outbound_count || 0
        };
        const subjectId = storedMessage?.id || conversationID;
        const eventTypes = ["sms.received", "sms.keyword_received", contactID ? "sms.message_received_from_contact" : "sms.message_received_from_unknown_number"];
        if (mediaCount > 0) eventTypes.push("sms.attachment_received", "sms.mms_received");
        if (Number(stats.inbound_count || 0) === 1) eventTypes.push("sms.first_inbound");
        if (Number(stats.total_count || 0) === 1) eventTypes.push("sms.first_message_from_number");
        if (Number(stats.outbound_count || 0) > 0) {
          eventTypes.push("sms.reply_received");
          basePayload.last_outbound_message_id = stats.last_outbound_message_id || null;
          basePayload.last_outbound_at = stats.last_outbound_at || null;
          basePayload.reply_latency_seconds = stats.last_outbound_at ? Math.max(0, Math.round((Date.now() - new Date(stats.last_outbound_at).getTime()) / 1000)) : null;
        }
        for (const eventType of eventTypes) {
          await emitAutomationEvent({
            companyId: phoneLine.company_id,
            eventType,
            subjectType: "sms_message",
            subjectId,
            source: "twilio.sms",
            dedupeKey: messageSid ? `${eventType}:${messageSid}` : `${eventType}:${subjectId}`,
            payload: basePayload
          });
        }
      } catch (automationError) {
        console.error("[twilio/sms] automation emission failed:", { messageSid, code: automationError?.code, message: automationError?.message });
      }
    } catch (e) {
      await client.query("ROLLBACK").catch(() => {});
      throw e;
    } finally {
      client.release();
    }

    try {
      if (contactID) {
        const contact = await pool.query(
          `SELECT name FROM contacts WHERE id = $1 AND company_id = $2 LIMIT 1`,
          [contactID, phoneLine.company_id]
        );
        const name = (contact.rows[0]?.name || "").toString().trim();
        if (name) pushTitle = name;
      }
      const preview = body.trim()
        ? body.trim().slice(0, 140)
        : (mediaCount > 0 ? "Sent an attachment" : "New message");
      console.log("[apns] inbound SMS push requested", {
        companyId: phoneLine.company_id,
        conversationID: storedConversationID,
        hasContact: Boolean(contactID),
        mediaCount
      });
      const userIds = await employerUserIdsForCompany(phoneLine.company_id);
      const badge = await phoneUnreadBadgeCount(phoneLine.company_id).catch(() => null);
      sendPushToUsers(userIds, "cellular_sms", {
        title: pushTitle,
        body: preview,
        badge,
        contactId: contactID || undefined,
        threadId: storedConversationID ? `cellular_sms_${storedConversationID}` : "cellular_sms",
        payload: {
          type: "cellular_sms",
          conversation_id: storedConversationID,
          external_phone_number: fromNumber,
          contact_id: contactID || null
        }
      }).then((result) => {
        console.log("[twilio/sms] APNs result", { messageSid, conversationID: storedConversationID, ...result });
      }).catch((e) => {
        console.error("[twilio/sms] APNs failed:", { messageSid, code: e?.code, message: e?.message });
      });
    } catch (e) {
      console.error("[twilio/sms] APNs scheduling failed:", { messageSid, code: e?.code, message: e?.message });
    }

    res.status(200).type("text/xml").send(emptyMessagingResponse());
  } catch (e) {
    console.error("[twilio/sms] processing failed:", {
      messageSid,
      status: e?.status,
      code: e?.code,
      message: e?.message
    });
    res.status(500).type("text/plain").send("Twilio webhook processing failed");
  }
});

app.get("/api/phone/conversations", authRequired, async (req, res) => {
  if (!req.companyId) return res.json([]);
  try {
    const { rows } = await pool.query(
      `SELECT sc.id,
              sc.phone_line_id,
              pl.phone_number AS phone_line_number,
              sc.external_phone_number,
              COALESCE(sc.contact_id, matched_contacts.id::uuid) AS contact_id,
              COALESCE(c.name, matched_contacts.name) AS contact_name,
              lm.body AS last_message_body,
              lm.direction AS last_message_direction,
              lm.message_status AS last_message_status,
              lm.media_count AS last_message_media_count,
              COALESCE((
                SELECT COUNT(*)
                  FROM sms_messages unread
                 WHERE unread.conversation_id = sc.id
                   AND unread.direction = 'inbound'
                   AND unread.deleted_at IS NULL
                   AND unread.created_at > COALESCE(sc.last_read_at, '1970-01-01'::timestamptz)
              ), 0)::int AS unread_count,
              sc.last_message_at,
              sc.last_read_at,
              sc.created_at,
              sc.updated_at
         FROM sms_conversations sc
         JOIN phone_lines pl ON pl.id = sc.phone_line_id
         LEFT JOIN contacts c ON c.id = sc.contact_id AND c.company_id = pl.company_id
         ${contactMatchJoinSQL("sc.external_phone_number", "pl.company_id")}
         LEFT JOIN LATERAL (
           SELECT body, direction, message_status, media_count, created_at
             FROM sms_messages
            WHERE conversation_id = sc.id
              AND deleted_at IS NULL
            ORDER BY created_at DESC, id DESC
            LIMIT 1
         ) lm ON true
        WHERE pl.company_id = $1
          AND sc.deleted_at IS NULL
        ORDER BY sc.last_message_at DESC NULLS LAST, sc.updated_at DESC
        LIMIT 200`,
      [req.companyId]
    );
    res.json(rows);
  } catch (e) {
    console.error("[phone/conversations] failed:", { code: e?.code, message: e?.message });
    res.status(500).json({ error: "phone_conversations_failed" });
  }
});

app.get("/api/phone/lines", authRequired, async (req, res) => {
  if (!req.companyId) return res.json([]);
  try {
    const { rows } = await pool.query(
      `SELECT id,
              company_id,
              phone_number,
              twilio_phone_number_sid,
              status,
              active,
              created_at,
              updated_at
         FROM phone_lines
        WHERE company_id = $1
        ORDER BY created_at ASC`,
      [req.companyId]
    );
    res.json(rows);
  } catch (e) {
    console.error("[phone/lines] list failed:", { code: e?.code, message: e?.message });
    res.status(500).json({ error: "phone_lines_failed" });
  }
});

app.post("/api/phone/lines/attach-existing", authRequired, requireEmployer, async (req, res) => {
  if (!req.companyId) return res.status(400).json({ error: "company_required" });

  const phoneNumber = normalizeE164Phone(req.body?.phoneNumber);
  if (!isUsableE164(phoneNumber)) {
    return res.status(400).json({ error: "invalid_phone_number" });
  }

  const client = createTwilioClient();
  if (!client) return res.status(503).json({ error: "twilio_not_configured" });

  try {
    const numbers = await client.incomingPhoneNumbers.list({
      phoneNumber,
      limit: 1
    });
    const ownedNumber = numbers.find((number) => normalizeE164Phone(number.phoneNumber) === phoneNumber);
    if (!ownedNumber) {
      return res.status(404).json({ error: "twilio_number_not_found" });
    }

    const { rows } = await pool.query(
      `INSERT INTO phone_lines(company_id, phone_number, twilio_phone_number_sid, status, active)
       VALUES($1, $2, $3, 'active', true)
       ON CONFLICT(phone_number)
       DO UPDATE SET
         company_id = EXCLUDED.company_id,
         twilio_phone_number_sid = EXCLUDED.twilio_phone_number_sid,
         status = 'active',
         active = true,
         updated_at = now()
       WHERE phone_lines.company_id = EXCLUDED.company_id
       RETURNING id,
                 company_id,
                 phone_number,
                 twilio_phone_number_sid,
                 status,
                 active,
                 created_at,
                 updated_at`,
      [req.companyId, phoneNumber, ownedNumber.sid || null]
    );
    if (!rows.length) {
      return res.status(409).json({ error: "phone_line_already_attached" });
    }

    res.json(rows[0]);
  } catch (e) {
    console.error("[phone/lines/attach-existing] failed:", {
      status: e?.status,
      code: e?.code,
      message: e?.message
    });
    res.status(500).json({ error: "phone_line_attach_failed" });
  }
});

app.get("/api/voice/token", authRequired, async (req, res) => {
  if (!req.userId || !req.companyId) {
    return res.status(400).json({ error: "company_required" });
  }

  const { configured, accountSid, apiKeySid, apiKeySecret, twimlAppSid, pushCredentialSid } = twilioVoiceConfig();
  if (!configured) {
    return res.status(503).json({ error: "twilio_voice_not_configured" });
  }

  const identity = voiceIdentityForUserID(req.userId);
  if (!identity) {
    return res.status(400).json({ error: "invalid_voice_identity" });
  }

  try {
    const { rows } = await pool.query(
      `SELECT id
         FROM phone_lines
        WHERE company_id = $1
          AND active = true
          AND status = 'active'
          AND phone_number ~ '^\\+[1-9][0-9]{6,14}$'
        ORDER BY created_at ASC
        LIMIT 1`,
      [req.companyId]
    );
    if (!rows.length) {
      return res.status(400).json({ error: "phone_line_required" });
    }

    const AccessToken = twilio.jwt.AccessToken;
    const VoiceGrant = AccessToken.VoiceGrant;
    const token = new AccessToken(accountSid, apiKeySid, apiKeySecret, {
      identity,
      ttl: VOICE_TOKEN_TTL_SECONDS
    });
    const voiceGrantOptions = {
      outgoingApplicationSid: twimlAppSid,
      incomingAllow: true
    };
    if (pushCredentialSid) {
      voiceGrantOptions.pushCredentialSid = pushCredentialSid;
    }
    token.addGrant(new VoiceGrant(voiceGrantOptions));

    res.json({
      token: token.toJwt(),
      identity,
      expiresIn: VOICE_TOKEN_TTL_SECONDS
    });
  } catch (e) {
    console.error("[voice/token] failed:", { code: e?.code, message: e?.message });
    res.status(500).json({ error: "voice_token_failed" });
  }
});

app.get("/api/voice/diagnostics", authRequired, async (req, res) => {
  const { configured, twimlAppSid, pushCredentialSid } = twilioVoiceConfig();
  const voiceIdentity = voiceIdentityForUserID(req.userId);
  try {
    const activeLine = req.companyId
      ? await pool.query(
          `SELECT id, phone_number
             FROM phone_lines
            WHERE company_id = $1
              AND active = true
              AND status = 'active'
              AND phone_number ~ '^\\+[1-9][0-9]{6,14}$'
            ORDER BY created_at ASC
            LIMIT 1`,
          [req.companyId]
        )
      : { rows: [] };
    const employer = req.companyId
      ? await pool.query(
          `SELECT u.id
             FROM users u
             LEFT JOIN companies c ON c.id = u.company_id
            WHERE u.company_id = $1
              AND u.deleted_at IS NULL
              AND u.role = 'employer'
            ORDER BY (u.id = c.owner_user_id) DESC, u.created_at ASC, u.id ASC
            LIMIT 1`,
          [req.companyId]
        )
      : { rows: [] };
    const incomingTargetIdentity = employer.rows[0]?.id ? voiceIdentityForUserID(employer.rows[0].id) : null;
    res.json({
      ok: true,
      user_id: req.userId,
      company_id: req.companyId,
      role: req.role,
      voice_identity: voiceIdentity,
      active_phone_line: activeLine.rows[0]?.phone_number || null,
      twiml_app_configured: Boolean(twimlAppSid && configured),
      push_credential_configured: Boolean(pushCredentialSid),
      incoming_target_identity: incomingTargetIdentity,
      identity_matches: Boolean(voiceIdentity && incomingTargetIdentity && voiceIdentity === incomingTargetIdentity)
    });
  } catch (e) {
    console.error("[voice/diagnostics] failed:", { code: e?.code, message: e?.message });
    res.status(500).json({ error: "voice_diagnostics_failed" });
  }
});

app.post("/webhooks/twilio/voice/outgoing", async (req, res) => {
  try {
    const validation = validateTwilioWebhook(req);
    if (!validation.ok) {
      console.error("[twilio/voice/outgoing] webhook validation failed:", validation.error);
      if (validation.error === "twilio_auth_token_missing") {
        return res.status(500).type("text/plain").send("Twilio webhook auth is not configured");
      }
      return res.status(403).type("text/plain").send("Forbidden");
    }

    const voiceResponse = new twilio.twiml.VoiceResponse();
    const identity = req.body.ClientIdentity || req.body.From || req.body.Caller || "";
    const userID = uuidFromVoiceIdentity(identity);
    const toNumber = normalizeE164Phone(req.body.to || req.body.To);
    console.info("[voice outgoing]", {
      rawIdentity: identity || null,
      requestedDestination: toNumber || null,
      parsedUserID: userID || null,
      hasToParam: Boolean(req.body.to),
      hasToField: Boolean(req.body.To)
    });

    if (!userID) {
      console.warn("[voice outgoing] rejected", { reason: "invalid_identity", rawIdentity: identity || null });
      return res.status(200).type("text/xml").send(voiceResponse.toString());
    }
    if (!isUsableE164(toNumber)) {
      console.warn("[voice outgoing] rejected", { reason: "invalid_destination", userID, requestedDestination: toNumber || null });
      return res.status(200).type("text/xml").send(voiceResponse.toString());
    }

    const { rows } = await pool.query(
      `SELECT u.id AS user_id,
              u.company_id,
              pl.id AS phone_line_id,
              pl.phone_number
         FROM users u
         JOIN phone_lines pl ON pl.company_id = u.company_id
        WHERE u.id = $1
          AND u.deleted_at IS NULL
          AND u.company_id IS NOT NULL
          AND pl.active = true
          AND pl.status = 'active'
          AND pl.phone_number ~ '^\\+[1-9][0-9]{6,14}$'
        ORDER BY pl.created_at ASC
        LIMIT 1`,
      [userID]
    );
    if (!rows.length) {
      console.warn("[voice outgoing] rejected", {
        reason: "user_or_phone_line_not_found",
        userID,
        userFound: false,
        phoneLineFound: false
      });
      return res.status(200).type("text/xml").send(voiceResponse.toString());
    }

    const callerId = normalizeE164Phone(rows[0].phone_number);
    if (!isUsableE164(callerId)) {
      console.warn("[voice outgoing] rejected", {
        reason: "invalid_caller_id",
        userID,
        companyID: rows[0].company_id,
        phoneLineFound: true
      });
      return res.status(200).type("text/xml").send(voiceResponse.toString());
    }

    try {
      const contactID = await findSmsContactID({
        companyId: rows[0].company_id,
        externalPhone: toNumber
      });
      const history = await pool.query(
        `INSERT INTO phone_calls(
           company_id, phone_line_id, contact_id, twilio_call_sid, direction,
           from_number, to_number, status, started_at
         )
         VALUES($1, $2, $3, $4, 'outbound', $5, $6, $7, now())
         ON CONFLICT (twilio_call_sid)
         WHERE twilio_call_sid IS NOT NULL
         DO UPDATE SET
           status = EXCLUDED.status,
           updated_at = now()
         RETURNING id`,
        [
          rows[0].company_id,
          rows[0].phone_line_id || null,
          contactID,
          (req.body.CallSid || "").toString().trim() || null,
          callerId,
          toNumber,
          (req.body.CallStatus || "initiated").toString()
        ]
      );
      const callId = history.rows[0]?.id;
      if (callId) {
        await emitCallAutomationEvents({
          companyId: rows[0].company_id,
          callId,
          callSid: (req.body.CallSid || "").toString().trim() || callId,
          eventTypes: ["call.outgoing", "call.started"],
          payload: { call_id: callId, external_phone_number: toNumber, contact_id: contactID, direction: "outbound", status: (req.body.CallStatus || "initiated").toString(), from_number: callerId, to_number: toNumber }
        }).catch((automationError) => console.error("[voice outgoing] automation emission failed:", { code: automationError?.code, message: automationError?.message }));
      }
    } catch (historyError) {
      console.error("[voice outgoing] call history failed; continuing call routing:", {
        code: historyError?.code,
        message: historyError?.message
      });
    }

    const dial = voiceResponse.dial({
      callerId,
      statusCallback: twilioPublicUrl("/webhooks/twilio/voice/status"),
      statusCallbackEvent: "initiated ringing answered completed"
    });
    dial.number(toNumber);
    console.info("[voice outgoing] routing", {
      decision: "dial_number",
      userID,
      companyID: rows[0].company_id,
      phoneLineFound: true,
      selectedCallerID: callerId,
      destination: toNumber
    });
    res.status(200).type("text/xml").send(voiceResponse.toString());
  } catch (e) {
    console.error("[twilio/voice/outgoing] failed:", {
      status: e?.status,
      code: e?.code,
      message: e?.message
    });
    const voiceResponse = new twilio.twiml.VoiceResponse();
    res.status(200).type("text/xml").send(voiceResponse.toString());
  }
});

app.post("/webhooks/twilio/voice/incoming", async (req, res) => {
  try {
    const validation = validateTwilioWebhook(req);
    if (!validation.ok) {
      console.error("[twilio/voice/incoming] webhook validation failed:", validation.error);
      if (validation.error === "twilio_auth_token_missing") {
        return res.status(500).type("text/plain").send("Twilio webhook auth is not configured");
      }
      return res.status(403).type("text/plain").send("Forbidden");
    }

    const voiceResponse = new twilio.twiml.VoiceResponse();
    const fromNumber = normalizeE164Phone(req.body.From);
    const toNumber = normalizeE164Phone(req.body.To);
    console.info("[voice incoming]", {
      externalFrom: fromNumber || null,
      calledTo: toNumber || null
    });
    if (!isUsableE164(toNumber)) {
      console.warn("[voice incoming] rejected", { reason: "invalid_called_number", calledTo: toNumber || null });
      return res.status(200).type("text/xml").send(voiceResponse.toString());
    }

    const { rows } = await pool.query(
      `WITH matched_line AS (
         SELECT id, company_id
           FROM phone_lines
          WHERE phone_number = $1
            AND active = true
            AND status = 'active'
          LIMIT 1
       ),
       eligible_employers AS (
         SELECT u.id, u.created_at, c.owner_user_id
           FROM matched_line pl
           JOIN users u ON u.company_id = pl.company_id
           LEFT JOIN companies c ON c.id = pl.company_id
          WHERE u.deleted_at IS NULL
            AND u.role = 'employer'
       )
       SELECT pl.id AS phone_line_id,
              pl.company_id,
              ee.id AS owner_user_id,
              (SELECT COUNT(*) FROM eligible_employers) AS eligible_employer_count
         FROM matched_line pl
         LEFT JOIN eligible_employers ee ON true
        ORDER BY (ee.id = ee.owner_user_id) DESC, ee.created_at ASC, ee.id ASC
        LIMIT 1`,
      [toNumber]
    );
    if (!rows.length) {
      console.warn("[voice incoming] rejected", { reason: "phone_line_not_found", calledTo: toNumber });
      return res.status(200).type("text/xml").send(voiceResponse.toString());
    }

    const route = rows[0];
    console.info("[voice incoming] route lookup", {
      phoneLineFound: true,
      companyID: route.company_id,
      eligibleEmployerCount: Number(route.eligible_employer_count || 0),
      selectedUserID: route.owner_user_id || null
    });
    if (!route.owner_user_id) {
      console.warn("[voice incoming] rejected", {
        reason: "eligible_employer_not_found",
        companyID: route.company_id,
        eligibleEmployerCount: Number(route.eligible_employer_count || 0)
      });
      return res.status(200).type("text/xml").send(voiceResponse.toString());
    }
    const identity = voiceIdentityForUserID(route.owner_user_id);
    if (!identity) {
      console.warn("[voice incoming] rejected", { reason: "invalid_owner_identity", userID: route.owner_user_id });
      return res.status(200).type("text/xml").send(voiceResponse.toString());
    }

    try {
      const contactID = isUsableE164(fromNumber)
        ? await findSmsContactID({ companyId: route.company_id, externalPhone: fromNumber })
        : null;
      const history = await pool.query(
        `INSERT INTO phone_calls(
           company_id, phone_line_id, contact_id, twilio_call_sid, direction,
           from_number, to_number, status, started_at
         )
         VALUES($1, $2, $3, $4, 'inbound', $5, $6, $7, now())
         ON CONFLICT (twilio_call_sid)
         WHERE twilio_call_sid IS NOT NULL
         DO UPDATE SET
           status = EXCLUDED.status,
           updated_at = now()
         RETURNING id`,
        [
          route.company_id,
          route.phone_line_id,
          contactID,
          (req.body.CallSid || "").toString().trim() || null,
          fromNumber || null,
          toNumber,
          (req.body.CallStatus || "ringing").toString()
        ]
      );
      const callId = history.rows[0]?.id;
      if (callId) {
        await emitCallAutomationEvents({
          companyId: route.company_id,
          callId,
          callSid: (req.body.CallSid || "").toString().trim() || callId,
          eventTypes: ["call.incoming", "call.ringing"],
          payload: { call_id: callId, external_phone_number: fromNumber, contact_id: contactID, direction: "inbound", status: (req.body.CallStatus || "ringing").toString(), from_number: fromNumber, to_number: toNumber }
        }).catch((automationError) => console.error("[voice incoming] automation emission failed:", { code: automationError?.code, message: automationError?.message }));
      }
    } catch (historyError) {
      console.error("[voice incoming] call history failed; continuing call routing:", {
        code: historyError?.code,
        message: historyError?.message
      });
    }

    const dial = voiceResponse.dial({
      callerId: fromNumber || undefined,
      action: twilioPublicUrl("/webhooks/twilio/voice/incoming-complete"),
      method: "POST",
      timeout: 25,
      statusCallback: twilioPublicUrl("/webhooks/twilio/voice/status"),
      statusCallbackEvent: "initiated ringing answered completed"
    });
    const client = dial.client();
    client.identity(identity);
    console.info("[voice incoming] routing", {
      decision: "dial_client",
      companyID: route.company_id,
      selectedUserID: route.owner_user_id,
      generatedClientIdentity: identity
    });
    res.status(200).type("text/xml").send(voiceResponse.toString());
  } catch (e) {
    console.error("[twilio/voice/incoming] failed:", { status: e?.status, code: e?.code, message: e?.message });
    const voiceResponse = new twilio.twiml.VoiceResponse();
    res.status(200).type("text/xml").send(voiceResponse.toString());
  }
});

app.post("/webhooks/twilio/voice/incoming-complete", async (req, res) => {
  try {
    const validation = validateTwilioWebhook(req);
    if (!validation.ok) {
      console.error("[twilio/voice/incoming-complete] webhook validation failed:", validation.error);
      if (validation.error === "twilio_auth_token_missing") {
        return res.status(500).type("text/plain").send("Twilio webhook auth is not configured");
      }
      return res.status(403).type("text/plain").send("Forbidden");
    }

    const voiceResponse = new twilio.twiml.VoiceResponse();
    const dialStatus = (req.body.DialCallStatus || "").toString().trim().toLowerCase();
    const callSid = (req.body.CallSid || "").toString().trim();
    if (dialStatus === "completed" || dialStatus === "answered") {
      return res.status(200).type("text/xml").send(voiceResponse.toString());
    }

    const fromNumber = normalizeE164Phone(req.body.From);
    const toNumber = normalizeE164Phone(req.body.To);
    let route = null;
    if (callSid) {
      const call = await pool.query(
        `SELECT pc.id AS phone_call_id,
                pc.company_id,
                pc.phone_line_id,
                pc.contact_id,
                pc.from_number,
                pc.to_number
           FROM phone_calls pc
          WHERE pc.twilio_call_sid = $1
          LIMIT 1`,
        [callSid]
      );
      route = call.rows[0] || null;
    }
    if (!route && isUsableE164(toNumber)) {
      const line = await pool.query(
        `SELECT id AS phone_line_id, company_id
           FROM phone_lines
          WHERE phone_number = $1
            AND active = true
            AND status = 'active'
          LIMIT 1`,
        [toNumber]
      );
      if (line.rows.length) {
        const contactID = isUsableE164(fromNumber)
          ? await findSmsContactID({ companyId: line.rows[0].company_id, externalPhone: fromNumber })
          : null;
        route = {
          company_id: line.rows[0].company_id,
          phone_line_id: line.rows[0].phone_line_id,
          contact_id: contactID,
          from_number: fromNumber,
          to_number: toNumber
        };
      }
    }

    if (route) {
      await pool.query(
        `UPDATE phone_calls
            SET disposition = COALESCE(disposition, $2),
                status = COALESCE(status, $3),
                ended_at = COALESCE(ended_at, now()),
                updated_at = now()
          WHERE twilio_call_sid = $1`,
        [callSid, callDispositionForStatus(dialStatus) || "missed", dialStatus || "no-answer"]
      ).catch((e) => {
        console.error("[twilio/voice/incoming-complete] history update failed:", { code: e?.code, message: e?.message });
      });
    }

    voiceResponse.say({ voice: "alice" }, "Please leave a message after the tone.");
    voiceResponse.record({
      maxLength: 180,
      playBeep: true,
      trim: "trim-silence",
      recordingStatusCallback: twilioPublicUrl("/webhooks/twilio/voice/voicemail-recording"),
      recordingStatusCallbackMethod: "POST",
      recordingStatusCallbackEvent: "completed"
    });
    res.status(200).type("text/xml").send(voiceResponse.toString());
  } catch (e) {
    console.error("[twilio/voice/incoming-complete] failed:", { status: e?.status, code: e?.code, message: e?.message });
    const voiceResponse = new twilio.twiml.VoiceResponse();
    res.status(200).type("text/xml").send(voiceResponse.toString());
  }
});

app.post("/webhooks/twilio/voice/voicemail-recording", async (req, res) => {
  try {
    const validation = validateTwilioWebhook(req);
    if (!validation.ok) {
      console.error("[twilio/voice/voicemail-recording] webhook validation failed:", validation.error);
      if (validation.error === "twilio_auth_token_missing") {
        return res.status(500).type("text/plain").send("Twilio webhook auth is not configured");
      }
      return res.status(403).type("text/plain").send("Forbidden");
    }

    const callSid = (req.body.CallSid || "").toString().trim();
    const recordingSid = (req.body.RecordingSid || "").toString().trim();
    if (!callSid || !recordingSid) return res.status(200).type("text/plain").send("OK");
    const recordingStatus = (req.body.RecordingStatus || "completed").toString().trim();
    const duration = req.body.RecordingDuration ? Math.max(0, parseInt(req.body.RecordingDuration, 10) || 0) : null;

    const call = await pool.query(
      `SELECT pc.id AS phone_call_id,
              pc.company_id,
              pc.phone_line_id,
              pc.contact_id,
              pc.from_number,
              pc.to_number
         FROM phone_calls pc
        WHERE pc.twilio_call_sid = $1
        LIMIT 1`,
      [callSid]
    );
    if (!call.rows.length) {
      console.warn("[twilio/voice/voicemail-recording] call not found", { callSid, recordingSid });
      return res.status(200).type("text/plain").send("OK");
    }
    const row = call.rows[0];
    const externalPhone = row.from_number;
    const contactID = row.contact_id || (isUsableE164(externalPhone)
      ? await findSmsContactID({ companyId: row.company_id, externalPhone })
      : null);

    const saved = await pool.query(
      `INSERT INTO voicemails(
         company_id, phone_line_id, contact_id, phone_call_id, twilio_call_sid,
         twilio_recording_sid, external_phone_number, recording_status, duration_seconds
       )
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT (twilio_recording_sid)
       WHERE twilio_recording_sid IS NOT NULL
       DO UPDATE SET
         contact_id = COALESCE(voicemails.contact_id, EXCLUDED.contact_id),
         recording_status = EXCLUDED.recording_status,
         duration_seconds = COALESCE(EXCLUDED.duration_seconds, voicemails.duration_seconds),
         deleted_at = NULL,
         updated_at = now()
       RETURNING id, contact_id, external_phone_number, duration_seconds, recording_status, created_at`,
      [
        row.company_id,
        row.phone_line_id,
        contactID,
        row.phone_call_id,
        callSid,
        recordingSid,
        externalPhone || null,
        recordingStatus,
        duration
      ]
    );

    if (recordingStatus.toLowerCase() === "completed") {
      try {
        const voicemail = saved.rows[0];
        const payload = {
          voicemail_id: voicemail.id,
          call_id: row.phone_call_id,
          call_sid: callSid,
          recording_sid: recordingSid,
          external_phone_number: externalPhone,
          contact_id: voicemail.contact_id || null,
          duration_seconds: voicemail.duration_seconds || null,
          recording_status: voicemail.recording_status,
          contact_exists: Boolean(voicemail.contact_id)
        };
        for (const eventType of ["voicemail.received", "voicemail.recording_ready", voicemail.contact_id ? "voicemail.from_contact" : "voicemail.from_unknown_number"]) {
          await emitAutomationEvent({
            companyId: row.company_id,
            eventType,
            subjectType: "voicemail",
            subjectId: voicemail.id,
            source: "twilio.voice",
            dedupeKey: `${eventType}:${recordingSid}`,
            payload
          });
        }
        await syncAutomationSchedulesForVoicemail(row.company_id, voicemail);
      } catch (automationError) {
        console.error("[twilio/voice/voicemail-recording] automation emission failed:", { recordingSid, code: automationError?.code, message: automationError?.message });
      }
      let title = externalPhone || "Unknown caller";
      if (saved.rows[0]?.contact_id) {
        const contact = await pool.query(
          `SELECT name FROM contacts WHERE id = $1 AND company_id = $2 LIMIT 1`,
          [saved.rows[0].contact_id, row.company_id]
        );
        const name = (contact.rows[0]?.name || "").toString().trim();
        if (name) title = name;
      }
      const userIds = await employerUserIdsForCompany(row.company_id);
      const badge = await phoneUnreadBadgeCount(row.company_id).catch(() => null);
      sendPushToUsers(userIds, "voicemail", {
        title: `New voicemail from ${title}`,
        body: "Tap to listen.",
        badge,
        contactId: saved.rows[0]?.contact_id || undefined,
        threadId: `voicemail_${saved.rows[0].id}`,
        payload: {
          type: "voicemail",
          voicemail_id: saved.rows[0].id,
          call_id: row.phone_call_id,
          external_phone_number: externalPhone || null,
          contact_id: saved.rows[0]?.contact_id || null
        }
      }).catch((e) => {
        console.error("[twilio/voice/voicemail-recording] APNs failed:", { recordingSid, code: e?.code, message: e?.message });
      });
    }

    res.status(200).type("text/plain").send("OK");
  } catch (e) {
    console.error("[twilio/voice/voicemail-recording] failed:", { status: e?.status, code: e?.code, message: e?.message });
    res.status(200).type("text/plain").send("OK");
  }
});

app.post("/webhooks/twilio/voice/status", async (req, res) => {
  try {
    const validation = validateTwilioWebhook(req);
    if (!validation.ok) {
      console.error("[twilio/voice/status] webhook validation failed:", validation.error);
      if (validation.error === "twilio_auth_token_missing") {
        return res.status(500).type("text/plain").send("Twilio webhook auth is not configured");
      }
      return res.status(403).type("text/plain").send("Forbidden");
    }

    const callSid = (req.body.CallSid || "").toString().trim();
    if (!callSid) return res.status(200).type("text/plain").send("OK");

    const parentCallSid = (req.body.ParentCallSid || "").toString().trim() || null;
    const status = (req.body.CallStatus || "").toString().trim() || null;
    const fromNumber = normalizeE164Phone(req.body.From);
    const toNumber = normalizeE164Phone(req.body.To);
    const duration = req.body.CallDuration ? Math.max(0, parseInt(req.body.CallDuration, 10) || 0) : null;
    const disposition = callDispositionForStatus(status);
    const endedAtSQL = status === "completed" || disposition ? "now()" : "NULL";
    const answeredAtInsert = status === "in-progress" || status === "answered" || status === "completed" ? new Date().toISOString() : null;
    const answeredAtUpdateSQL = status === "in-progress" || status === "answered" || status === "completed"
      ? "COALESCE(phone_calls.answered_at, EXCLUDED.answered_at, now())"
      : "phone_calls.answered_at";

    let lineRows = [];
    if (isUsableE164(toNumber) || isUsableE164(fromNumber)) {
      const result = await pool.query(
        `SELECT id, company_id, phone_number
           FROM phone_lines
          WHERE active = true
            AND status = 'active'
            AND phone_number = ANY($1::text[])
          LIMIT 1`,
        [[toNumber, fromNumber].filter(Boolean)]
      );
      lineRows = result.rows;
    }

    if (!lineRows.length && parentCallSid) {
      const parent = await pool.query(
        `SELECT company_id, phone_line_id FROM phone_calls WHERE twilio_call_sid = $1 LIMIT 1`,
        [parentCallSid]
      );
      lineRows = parent.rows.map((row) => ({ id: row.phone_line_id, company_id: row.company_id }));
    }
    if (!lineRows.length) {
      console.warn("[twilio/voice/status] no company resolved", { callSid, parentCallSid });
      return res.status(200).type("text/plain").send("OK");
    }

    const line = lineRows[0];
    const directionRaw = (req.body.Direction || "").toString().toLowerCase();
    const direction = directionRaw.includes("inbound") ? "inbound" : "outbound";
    const externalNumber = direction === "inbound" ? fromNumber : toNumber;
    const contactID = isUsableE164(externalNumber)
      ? await findSmsContactID({ companyId: line.company_id, externalPhone: externalNumber })
      : null;

    if (parentCallSid) {
      const parentUpdate = await pool.query(
        `UPDATE phone_calls
            SET contact_id = COALESCE(phone_calls.contact_id, $2),
                status = COALESCE($3, phone_calls.status),
                answered_at = CASE
                  WHEN $4::timestamptz IS NOT NULL THEN COALESCE(phone_calls.answered_at, $4::timestamptz, now())
                  ELSE phone_calls.answered_at
                END,
                ended_at = CASE
                  WHEN $5::boolean THEN COALESCE(phone_calls.ended_at, now())
                  ELSE phone_calls.ended_at
                END,
                duration_seconds = COALESCE($6, phone_calls.duration_seconds),
                disposition = COALESCE($7, phone_calls.disposition),
                updated_at = now()
          WHERE twilio_call_sid = $1
            AND company_id = $8
          RETURNING id`,
        [
          parentCallSid,
          contactID,
          status,
          answeredAtInsert,
          Boolean(status === "completed" || disposition),
          duration,
          disposition,
          line.company_id
        ]
      );
      if (parentUpdate.rowCount) {
        try {
          const payload = { call_id: parentUpdate.rows[0].id, call_sid: parentCallSid, external_phone_number: externalNumber, contact_id: contactID, direction, status, disposition, duration_seconds: duration };
          await emitCallAutomationEvents({
            companyId: line.company_id,
            callId: parentUpdate.rows[0].id,
            callSid: parentCallSid,
            eventTypes: callAutomationEventTypes({ status, disposition, direction, durationSeconds: duration }).filter((eventType) => eventType !== "call.missed"),
            payload
          });
        } catch (automationError) {
          console.error("[twilio/voice/status] call automation emission failed:", { callSid: parentCallSid, code: automationError?.code, message: automationError?.message });
        }
        if (direction === "inbound" && ["busy", "failed", "canceled", "missed"].includes(disposition || "")) {
          await emitAutomationEvent({
            companyId: line.company_id,
            eventType: "call.missed",
            subjectType: "call",
            subjectId: parentUpdate.rows[0].id,
            source: "twilio.voice",
            dedupeKey: `call.missed:${parentCallSid}`,
            payload: { call_id: parentUpdate.rows[0].id, call_sid: parentCallSid, external_phone_number: externalNumber, contact_id: contactID }
          });
          sendMissedCallPush({
            companyId: line.company_id,
            callId: parentUpdate.rows[0].id,
            externalPhone: externalNumber,
            contactId: contactID
          }).catch((e) => {
            console.error("[twilio/voice/status] missed-call APNs failed:", { callSid: parentCallSid, code: e?.code, message: e?.message });
          });
        }
        return res.status(200).type("text/plain").send("OK");
      }
    }

    const savedCall = await pool.query(
      `INSERT INTO phone_calls(
         company_id, phone_line_id, contact_id, twilio_call_sid, twilio_parent_call_sid,
         direction, from_number, to_number, status, started_at, answered_at,
         ended_at, duration_seconds, disposition
       )
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,now(),$10,${endedAtSQL},$11,$12)
       ON CONFLICT (twilio_call_sid)
       WHERE twilio_call_sid IS NOT NULL
       DO UPDATE SET
         twilio_parent_call_sid = COALESCE(EXCLUDED.twilio_parent_call_sid, phone_calls.twilio_parent_call_sid),
         contact_id = COALESCE(phone_calls.contact_id, EXCLUDED.contact_id),
         status = COALESCE(EXCLUDED.status, phone_calls.status),
         answered_at = ${answeredAtUpdateSQL},
         ended_at = COALESCE(phone_calls.ended_at, EXCLUDED.ended_at),
         duration_seconds = COALESCE(EXCLUDED.duration_seconds, phone_calls.duration_seconds),
         disposition = COALESCE(EXCLUDED.disposition, phone_calls.disposition),
         updated_at = now()
       RETURNING id`,
      [
        line.company_id,
        line.id || null,
        contactID,
        callSid,
        parentCallSid,
        direction,
        fromNumber || null,
        toNumber || null,
        status,
        answeredAtInsert,
        duration,
        disposition
      ]
    );

    if (direction === "inbound" && ["busy", "failed", "canceled", "missed"].includes(disposition || "")) {
      await emitAutomationEvent({
        companyId: line.company_id,
        eventType: "call.missed",
        subjectType: "call",
        subjectId: savedCall.rows[0]?.id,
        source: "twilio.voice",
        dedupeKey: `call.missed:${callSid}`,
        payload: { call_id: savedCall.rows[0]?.id, call_sid: callSid, external_phone_number: externalNumber, contact_id: contactID }
      });
      sendMissedCallPush({
        companyId: line.company_id,
        callId: savedCall.rows[0]?.id,
        externalPhone: externalNumber,
        contactId: contactID
      }).catch((e) => {
        console.error("[twilio/voice/status] missed-call APNs failed:", { callSid, code: e?.code, message: e?.message });
      });
    }
    try {
      const payload = { call_id: savedCall.rows[0]?.id, call_sid: callSid, external_phone_number: externalNumber, contact_id: contactID, direction, status, disposition, duration_seconds: duration };
      await emitCallAutomationEvents({
        companyId: line.company_id,
        callId: savedCall.rows[0]?.id,
        callSid,
        eventTypes: callAutomationEventTypes({ status, disposition, direction, durationSeconds: duration }).filter((eventType) => eventType !== "call.missed"),
        payload
      });
    } catch (automationError) {
      console.error("[twilio/voice/status] call automation emission failed:", { callSid, code: automationError?.code, message: automationError?.message });
    }

    res.status(200).type("text/plain").send("OK");
  } catch (e) {
    console.error("[twilio/voice/status] failed:", { status: e?.status, code: e?.code, message: e?.message });
    res.status(200).type("text/plain").send("OK");
  }
});

app.get("/api/phone/calls", authRequired, async (req, res) => {
  if (!req.companyId) return res.json([]);
  const limit = Math.min(Math.max(parseInt(req.query.limit || "100", 10) || 100, 1), 200);
  try {
    const { rows } = await pool.query(
      `SELECT pc.id,
              pc.direction,
              CASE WHEN pc.direction = 'inbound' THEN pc.from_number ELSE pc.to_number END AS external_phone_number,
              CASE WHEN pc.direction = 'inbound' THEN pc.to_number ELSE pc.from_number END AS business_phone_number,
              pc.from_number,
              pc.to_number,
              pc.status,
              pc.disposition,
              pc.started_at,
              pc.answered_at,
              pc.ended_at,
              pc.duration_seconds,
              COALESCE(pc.contact_id, matched_contacts.id::uuid) AS contact_id,
              COALESCE(c.name, matched_contacts.name) AS contact_name
         FROM phone_calls pc
         LEFT JOIN contacts c ON c.id = pc.contact_id AND c.company_id = pc.company_id
         ${contactMatchJoinSQL("CASE WHEN pc.direction = 'inbound' THEN pc.from_number ELSE pc.to_number END", "pc.company_id")}
        WHERE pc.company_id = $1
          AND (
            pc.twilio_parent_call_sid IS NULL
            OR NOT EXISTS (
              SELECT 1
                FROM phone_calls parent
               WHERE parent.twilio_call_sid = pc.twilio_parent_call_sid
                 AND parent.company_id = pc.company_id
            )
          )
        ORDER BY pc.started_at DESC
        LIMIT $2`,
      [req.companyId, limit]
    );
    res.json(rows);
  } catch (e) {
    console.error("[phone/calls] failed:", { code: e?.code, message: e?.message });
    res.status(500).json({ error: "phone_calls_failed" });
  }
});

app.get("/api/phone/unread-count", authRequired, async (req, res) => {
  if (!req.companyId) return res.json({ count: 0 });
  try {
    res.json({ count: await phoneUnreadBadgeCount(req.companyId) });
  } catch (e) {
    console.error("[phone/unread-count] failed:", { code: e?.code, message: e?.message });
    res.status(500).json({ error: "phone_unread_count_failed" });
  }
});

app.get("/api/phone/voicemails", authRequired, async (req, res) => {
  if (!req.companyId) return res.json([]);
  const limit = Math.min(Math.max(parseInt(req.query.limit || "100", 10) || 100, 1), 200);
  try {
    const { rows } = await pool.query(
      `SELECT vm.id,
              vm.external_phone_number,
              COALESCE(vm.contact_id, matched_contacts.id::uuid) AS contact_id,
              COALESCE(c.name, matched_contacts.name) AS contact_name,
              vm.created_at,
              vm.duration_seconds,
              vm.is_read,
              vm.recording_status,
              vm.phone_call_id AS call_id
         FROM voicemails vm
         LEFT JOIN contacts c ON c.id = vm.contact_id AND c.company_id = vm.company_id
         ${contactMatchJoinSQL("vm.external_phone_number", "vm.company_id")}
        WHERE vm.company_id = $1
          AND vm.deleted_at IS NULL
        ORDER BY vm.created_at DESC
        LIMIT $2`,
      [req.companyId, limit]
    );
    res.json(rows);
  } catch (e) {
    console.error("[phone/voicemails] failed:", { code: e?.code, message: e?.message });
    res.status(500).json({ error: "phone_voicemails_failed" });
  }
});

app.post("/api/phone/voicemails/:id/read", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(404).json({ error: "voicemail_not_found" });
  try {
    const { rows } = await pool.query(
      `UPDATE voicemails
          SET is_read = true, updated_at = now()
        WHERE id = $1
          AND company_id = $2
          AND deleted_at IS NULL
        RETURNING id, contact_id, external_phone_number, duration_seconds, recording_status`,
      [req.params.id, req.companyId]
    );
    if (!rows.length) return res.status(404).json({ error: "voicemail_not_found" });
    try {
      await cancelAutomationSchedulesForSubject(req.companyId, "voicemail", req.params.id, ["voicemail.unread_for"]);
      await emitAutomationEvent({
        companyId: req.companyId,
        eventType: "voicemail.read",
        subjectType: "voicemail",
        subjectId: rows[0].id,
        actorUserId: req.userId,
        source: "ios",
        dedupeKey: `voicemail.read:${rows[0].id}:${Date.now()}`,
        payload: {
          voicemail_id: rows[0].id,
          contact_id: rows[0].contact_id || null,
          external_phone_number: rows[0].external_phone_number,
          duration_seconds: rows[0].duration_seconds || null,
          recording_status: rows[0].recording_status
        }
      });
    } catch (automationError) {
      console.error("[phone/voicemail/read] automation emission failed:", { code: automationError?.code, message: automationError?.message });
    }
    res.json({ ok: true });
  } catch (e) {
    console.error("[phone/voicemail/read] failed:", { code: e?.code, message: e?.message });
    res.status(500).json({ error: "voicemail_read_failed" });
  }
});

app.delete("/api/phone/voicemails/:id", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(404).json({ error: "voicemail_not_found" });
  try {
    const { rows } = await pool.query(
      `UPDATE voicemails
          SET deleted_at = now(), updated_at = now()
        WHERE id = $1
          AND company_id = $2
          AND deleted_at IS NULL
        RETURNING id, twilio_recording_sid, contact_id, external_phone_number, duration_seconds, recording_status`,
      [req.params.id, req.companyId]
    );
    if (!rows.length) return res.status(404).json({ error: "voicemail_not_found" });
    try {
      await cancelAutomationSchedulesForSubject(req.companyId, "voicemail", req.params.id, ["voicemail.unread_for"]);
      await emitAutomationEvent({
        companyId: req.companyId,
        eventType: "voicemail.deleted",
        subjectType: "voicemail",
        subjectId: rows[0].id,
        actorUserId: req.userId,
        source: "ios",
        dedupeKey: `voicemail.deleted:${rows[0].id}`,
        payload: {
          voicemail_id: rows[0].id,
          contact_id: rows[0].contact_id || null,
          external_phone_number: rows[0].external_phone_number,
          duration_seconds: rows[0].duration_seconds || null,
          recording_status: rows[0].recording_status
        }
      });
    } catch (automationError) {
      console.error("[phone/voicemail/delete] automation emission failed:", { code: automationError?.code, message: automationError?.message });
    }
    const recordingSid = (rows[0].twilio_recording_sid || "").toString().trim();
    if (recordingSid) {
      const client = createTwilioClient();
      if (client) {
        client.recordings(recordingSid).remove().catch((e) => {
          console.error("[phone/voicemail/delete] Twilio recording delete failed:", {
            status: e?.status,
            code: e?.code,
            message: e?.message
          });
        });
      }
    }
    res.status(204).end();
  } catch (e) {
    console.error("[phone/voicemail/delete] failed:", { code: e?.code, message: e?.message });
    res.status(500).json({ error: "voicemail_delete_failed" });
  }
});

app.get("/api/phone/voicemails/:id/audio", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(404).json({ error: "voicemail_not_found" });
  try {
    const { rows } = await pool.query(
      `SELECT twilio_recording_sid
         FROM voicemails
        WHERE id = $1
          AND company_id = $2
          AND deleted_at IS NULL
        LIMIT 1`,
      [req.params.id, req.companyId]
    );
    if (!rows.length) return res.status(404).json({ error: "voicemail_not_found" });
    const recordingSid = (rows[0].twilio_recording_sid || "").toString().trim();
    if (!recordingSid) return res.status(404).json({ error: "voicemail_audio_not_ready" });
    await pool.query(
      `UPDATE voicemails SET is_read = true, updated_at = now() WHERE id = $1 AND company_id = $2`,
      [req.params.id, req.companyId]
    );
    const upstream = await fetchTwilioResource(buildRecordingAudioUrl(recordingSid));
    const buffer = Buffer.from(await upstream.arrayBuffer());
    res.type("audio/mpeg").send(buffer);
  } catch (e) {
    console.error("[phone/voicemail/audio] failed:", { code: e?.code, status: e?.status, message: e?.message });
    res.status(e?.status || 500).json({ error: "voicemail_audio_failed" });
  }
});

app.get("/api/phone/conversations/:id/messages", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(404).json({ error: "conversation_not_found" });
  try {
    const owned = await pool.query(
      `SELECT sc.id
         FROM sms_conversations sc
         JOIN phone_lines pl ON pl.id = sc.phone_line_id
        WHERE sc.id = $1 AND pl.company_id = $2 AND sc.deleted_at IS NULL
        LIMIT 1`,
      [req.params.id, req.companyId]
    );
    if (!owned.rowCount) return res.status(404).json({ error: "conversation_not_found" });

    await pool.query(`UPDATE sms_conversations SET last_read_at = now(), updated_at = now() WHERE id = $1`, [req.params.id]);

    const { rows } = await pool.query(
      `SELECT id,
              conversation_id,
              twilio_message_sid,
              direction,
              from_number,
              to_number,
              body,
              message_status,
              media_count,
              media,
              twilio_error_code,
              twilio_error_message,
              created_at,
              updated_at
         FROM sms_messages
        WHERE conversation_id = $1
          AND deleted_at IS NULL
        ORDER BY created_at ASC, id ASC
        LIMIT 500`,
      [req.params.id]
    );
    res.json(rows);
  } catch (e) {
    console.error("[phone/conversation/messages] failed:", { code: e?.code, message: e?.message });
    res.status(500).json({ error: "phone_messages_failed" });
  }
});

app.get("/api/phone/messages/:id/media/:index", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(404).json({ error: "media_not_found" });
  const mediaIndex = Math.max(0, parseInt(req.params.index || "0", 10) || 0);
  try {
    const { rows } = await pool.query(
      `SELECT sm.media
         FROM sms_messages sm
         JOIN sms_conversations sc ON sc.id = sm.conversation_id
         JOIN phone_lines pl ON pl.id = sc.phone_line_id
        WHERE sm.id = $1
          AND pl.company_id = $2
          AND sm.deleted_at IS NULL
          AND sc.deleted_at IS NULL
        LIMIT 1`,
      [req.params.id, req.companyId]
    );
    if (!rows.length) return res.status(404).json({ error: "media_not_found" });
    const media = safeSmsMediaArray(rows[0].media);
    const item = media.find((entry) => Number(entry.index ?? 0) === mediaIndex) || media[mediaIndex];
    if (!item) return res.status(404).json({ error: "media_not_found" });

    if (item.objectKey) {
      const cfg = mediaBucketConfig();
      const s3 = getMediaS3Client();
      if (!cfg || !s3) return res.status(503).json({ error: "media_bucket_not_configured" });
      const allowedPrefix = `companies/${req.companyId}/messages/`;
      if (!item.objectKey.toString().startsWith(allowedPrefix)) {
        return res.status(403).json({ error: "media_forbidden" });
      }
      const command = new GetObjectCommand({ Bucket: cfg.bucket, Key: item.objectKey });
      const signedUrl = await getSignedUrl(s3, command, { expiresIn: 300 });
      const upstream = await fetch(signedUrl);
      if (!upstream.ok) return res.status(upstream.status).json({ error: "media_fetch_failed" });
      const contentType = upstream.headers.get("content-type") || item.contentType || "application/octet-stream";
      const buffer = Buffer.from(await upstream.arrayBuffer());
      return res.type(contentType).send(buffer);
    }

    if (!item.url) return res.status(404).json({ error: "media_not_found" });
    const upstream = await fetchTwilioResource(item.url);
    const contentType = upstream.headers.get("content-type") || item.contentType || "application/octet-stream";
    const buffer = Buffer.from(await upstream.arrayBuffer());
    res.type(contentType).send(buffer);
  } catch (e) {
    console.error("[phone/message/media] failed:", { code: e?.code, status: e?.status, message: e?.message });
    res.status(e?.status || 500).json({ error: "media_fetch_failed" });
  }
});

app.post("/api/phone/conversations/:id/messages", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(404).json({ error: "conversation_not_found" });

  const rawBody = req.body?.body;
  if (rawBody !== undefined && typeof rawBody !== "string") {
    return res.status(400).json({ error: "message_body_required" });
  }
  const body = (rawBody || "").trim();
  const requestedMedia = Array.isArray(req.body?.media) ? req.body.media.slice(0, 5) : [];
  if (!body && requestedMedia.length === 0) return res.status(400).json({ error: "message_body_required" });
  if (body.length > MAX_SMS_BODY_LENGTH) {
    return res.status(400).json({ error: "message_too_long", max_length: MAX_SMS_BODY_LENGTH });
  }

  try {
    const { rows } = await pool.query(
      `SELECT sc.id AS conversation_id,
              sc.external_phone_number,
              sc.contact_id,
              pl.id AS phone_line_id,
              pl.phone_number,
              pl.status,
              pl.active
         FROM sms_conversations sc
         JOIN phone_lines pl ON pl.id = sc.phone_line_id
        WHERE sc.id = $1 AND pl.company_id = $2
          AND sc.deleted_at IS NULL
        LIMIT 1`,
      [req.params.id, req.companyId]
    );
    if (!rows.length) return res.status(404).json({ error: "conversation_not_found" });

    const conversation = rows[0];
    const lineStatus = (conversation.status || "").toString().trim().toLowerCase();
    const fromNumber = normalizeE164Phone(conversation.phone_number);
    const toNumber = normalizeE164Phone(conversation.external_phone_number);
    if (!conversation.active || lineStatus !== "active" || !isUsableE164(fromNumber) || !isUsableE164(toNumber)) {
      return res.status(400).json({ error: "phone_line_inactive" });
    }

    const client = createTwilioClient();
    if (!client) return res.status(503).json({ error: "twilio_not_configured" });

    const outboundMedia = [];
    const mediaUrls = [];
    if (requestedMedia.length) {
      const cfg = mediaBucketConfig();
      const s3 = getMediaS3Client();
      if (!cfg || !s3) return res.status(503).json({ error: "media_bucket_not_configured" });
      const allowedPrefix = `companies/${req.companyId}/messages/`;
      for (const item of requestedMedia) {
        const objectKey = (item?.object_key || "").toString();
        if (!objectKey.startsWith(allowedPrefix)) {
          return res.status(403).json({ error: "media_forbidden" });
        }
        const mimeType = (item?.mime_type || item?.contentType || "application/octet-stream").toString().slice(0, 120);
        const fileName = (item?.file_name || "attachment").toString().slice(0, 160);
        const command = new GetObjectCommand({ Bucket: cfg.bucket, Key: objectKey });
        const signedUrl = await getSignedUrl(s3, command, { expiresIn: 3600 });
        mediaUrls.push(signedUrl);
        outboundMedia.push({
          index: outboundMedia.length,
          objectKey,
          contentType: mimeType,
          fileName
        });
      }
    }

    let sent;
    try {
      const sendPayload = {
        from: fromNumber,
        to: toNumber,
        statusCallback: twilioPublicUrl("/webhooks/twilio/message-status")
      };
      if (body) sendPayload.body = body;
      if (mediaUrls.length) sendPayload.mediaUrl = mediaUrls;
      sent = await client.messages.create(sendPayload);
    } catch (e) {
      console.error("[phone/messages] Twilio send failed:", {
        status: e?.status,
        code: e?.code,
        message: e?.message
      });
      return res.status(502).json({ error: "twilio_send_failed" });
    }

    const db = await pool.connect();
    try {
      await db.query("BEGIN");
      const inserted = await db.query(
        `INSERT INTO sms_messages(
           conversation_id, twilio_message_sid, direction, from_number, to_number,
           body, message_status, media_count, media
         )
         VALUES($1,$2,'outbound',$3,$4,$5,$6,$7,$8::jsonb)
         RETURNING id,
                   conversation_id,
                   twilio_message_sid,
                   direction,
                   from_number,
                   to_number,
                   body,
                   message_status,
                   media_count,
                   media,
                   twilio_error_code,
                   twilio_error_message,
                   created_at,
                   updated_at`,
        [
          conversation.conversation_id,
          sent.sid || null,
          fromNumber,
          toNumber,
          body || null,
          sent.status || "queued",
          outboundMedia.length,
          JSON.stringify(outboundMedia)
        ]
      );
      await db.query(
        `UPDATE sms_conversations
            SET last_message_at = now(), updated_at = now()
          WHERE id = $1`,
        [conversation.conversation_id]
      );
      await db.query("COMMIT");
      const stored = inserted.rows[0];
      try {
        const stats = await pool.query(
          `SELECT COUNT(*) FILTER (WHERE direction = 'outbound')::int AS outbound_count
             FROM sms_messages
            WHERE conversation_id = $1 AND deleted_at IS NULL`,
          [conversation.conversation_id]
        );
        const payload = {
          message_id: stored.id,
          conversation_id: stored.conversation_id,
          contact_id: conversation.contact_id || null,
          external_number: toNumber,
          from_number: fromNumber,
          to_number: toNumber,
          body,
          direction: "outbound",
          status: stored.message_status,
          media_count: stored.media_count || 0,
          has_media: Number(stored.media_count || 0) > 0,
          outbound_count: stats.rows[0]?.outbound_count || 0
        };
        await emitAutomationEvent({
          companyId: req.companyId,
          eventType: Number(stored.media_count || 0) > 0 ? "sms.mms_sent" : "sms.sent",
          subjectType: "sms_message",
          subjectId: stored.id,
          actorUserId: req.userId,
          source: "ios",
          dedupeKey: `${Number(stored.media_count || 0) > 0 ? "sms.mms_sent" : "sms.sent"}:${stored.id}`,
          payload
        });
        if (Number(stats.rows[0]?.outbound_count || 0) === 1) {
          await emitAutomationEvent({
            companyId: req.companyId,
            eventType: "sms.first_outbound",
            subjectType: "sms_message",
            subjectId: stored.id,
            actorUserId: req.userId,
            source: "ios",
            dedupeKey: `sms.first_outbound:${stored.conversation_id}`,
            payload
          });
        }
        await syncAutomationSchedulesForSmsOutbound(req.companyId, { ...stored, contact_id: conversation.contact_id || null, external_phone_number: toNumber });
        await syncAutomationSchedulesForSmsConversationActivity(req.companyId, stored.conversation_id, stored);
      } catch (automationError) {
        console.error("[phone/messages] automation emission failed:", { messageId: stored.id, code: automationError?.code, message: automationError?.message });
      }
      res.status(201).json(stored);
    } catch (e) {
      await db.query("ROLLBACK").catch(() => {});
      console.error("[phone/messages] outbound persistence failed:", { code: e?.code, message: e?.message });
      res.status(500).json({ error: "message_store_failed" });
    } finally {
      db.release();
    }
  } catch (e) {
    console.error("[phone/messages] outbound failed:", { code: e?.code, message: e?.message });
    res.status(500).json({ error: "phone_message_send_failed" });
  }
});

app.delete("/api/phone/messages/:id", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(404).json({ error: "message_not_found" });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { rows } = await client.query(
      `UPDATE sms_messages sm
          SET deleted_at = now(), updated_at = now()
         FROM sms_conversations sc
         JOIN phone_lines pl ON pl.id = sc.phone_line_id
        WHERE sm.id = $1
          AND sm.conversation_id = sc.id
          AND pl.company_id = $2
          AND sm.deleted_at IS NULL
        RETURNING sm.conversation_id`,
      [req.params.id, req.companyId]
    );
    if (!rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "message_not_found" });
    }
    const conversationID = rows[0].conversation_id;
    await client.query(
      `UPDATE sms_conversations sc
          SET last_message_at = (
                SELECT MAX(created_at)
                  FROM sms_messages
                 WHERE conversation_id = sc.id
                   AND deleted_at IS NULL
              ),
              updated_at = now()
        WHERE sc.id = $1`,
      [conversationID]
    );
    await client.query("COMMIT");
    res.status(204).end();
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("[phone/messages] delete failed:", { code: e?.code, message: e?.message });
    res.status(500).json({ error: "delete_phone_message_failed" });
  } finally {
    client.release();
  }
});

app.delete("/api/phone/conversations/:id", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(404).json({ error: "conversation_not_found" });
  try {
    const { rows } = await pool.query(
      `UPDATE sms_conversations sc
          SET deleted_at = now(), updated_at = now()
         FROM phone_lines pl
        WHERE sc.id = $1
          AND pl.id = sc.phone_line_id
          AND pl.company_id = $2
          AND sc.deleted_at IS NULL
        RETURNING sc.id`,
      [req.params.id, req.companyId]
    );
    if (!rows.length) return res.status(404).json({ error: "conversation_not_found" });
    await pool.query(
      `UPDATE sms_messages
          SET deleted_at = COALESCE(deleted_at, now()), updated_at = now()
        WHERE conversation_id = $1
          AND deleted_at IS NULL`,
      [req.params.id]
    );
    res.status(204).end();
  } catch (e) {
    console.error("[phone/conversation] delete failed:", { code: e?.code, message: e?.message });
    res.status(500).json({ error: "delete_phone_conversation_failed" });
  }
});

app.post("/webhooks/twilio/message-status", async (req, res) => {
  const messageSid = (req.body.MessageSid || "").toString().trim();

  try {
    const validation = validateTwilioWebhook(req);
    if (!validation.ok) {
      console.error("[twilio/message-status] webhook validation failed:", validation.error);
      if (validation.error === "twilio_auth_token_missing") {
        return res.status(500).type("text/plain").send("Twilio webhook auth is not configured");
      }
      return res.status(403).type("text/plain").send("Forbidden");
    }

    if (!messageSid) {
      console.warn("[twilio/message-status] missing MessageSid");
      return res.status(200).type("text/plain").send("OK");
    }

    const status = (req.body.MessageStatus || req.body.SmsStatus || "").toString().trim() || null;
    const errorCode = req.body.ErrorCode ? req.body.ErrorCode.toString() : null;
    const errorMessage = req.body.ErrorMessage ? req.body.ErrorMessage.toString() : null;
    const before = await pool.query(
      `SELECT sm.id, sm.conversation_id, sm.message_status, sm.direction, sm.from_number, sm.to_number, sm.body,
              sm.media_count, sc.contact_id, sc.external_phone_number, pl.company_id
         FROM sms_messages sm
         JOIN sms_conversations sc ON sc.id = sm.conversation_id
         JOIN phone_lines pl ON pl.id = sc.phone_line_id
        WHERE sm.twilio_message_sid = $1
        LIMIT 1`,
      [messageSid]
    );
    const previous = before.rows[0] || null;
    const { rowCount } = await pool.query(
      `UPDATE sms_messages
          SET message_status = COALESCE($2, message_status),
              twilio_error_code = $3,
              twilio_error_message = $4,
              updated_at = now()
        WHERE twilio_message_sid = $1`,
      [messageSid, status, errorCode, errorMessage]
    );
    if (!rowCount) {
      console.log("[twilio/message-status] message not found", { messageSid, status });
    } else if (previous && status && status !== previous.message_status) {
      const mapped = {
        queued: "sms.queued",
        sending: "sms.sending",
        delivered: "sms.delivered",
        failed: "sms.failed",
        undelivered: "sms.undelivered"
      }[status];
      if (mapped) {
        try {
          await emitAutomationEvent({
            companyId: previous.company_id,
            eventType: mapped,
            subjectType: "sms_message",
            subjectId: previous.id,
            source: "twilio.status",
            dedupeKey: `${mapped}:${messageSid}:${status}`,
            payload: {
              message_id: previous.id,
              conversation_id: previous.conversation_id,
              contact_id: previous.contact_id || null,
              external_number: previous.external_phone_number,
              direction: previous.direction,
              from_number: previous.from_number,
              to_number: previous.to_number,
              body: previous.body,
              status,
              previous_status: previous.message_status,
              error_code: errorCode,
              failure_reason: errorMessage,
              media_count: previous.media_count || 0,
              has_media: Number(previous.media_count || 0) > 0
            }
          });
        } catch (automationError) {
          console.error("[twilio/message-status] automation emission failed:", { messageSid, code: automationError?.code, message: automationError?.message });
        }
      }
    }
    res.status(200).type("text/plain").send("OK");
  } catch (e) {
    console.error("[twilio/message-status] processing failed:", {
      messageSid,
      status: e?.status,
      code: e?.code,
      message: e?.message
    });
    res.status(500).type("text/plain").send("Twilio status processing failed");
  }
});

app.patch("/api/profile", authRequired, async (req, res) => {
  try {
    const displayName = (req.body.display_name || "").toString().trim();
    const photoUrl = (req.body.photo_url || req.body.photo_data_url || "").toString().trim();
    if (photoUrl && photoUrl.length > 350000) {
      return res.status(413).json({ error: "profile_photo_too_large" });
    }
    const { rows } = await pool.query(
      `UPDATE users
          SET display_name = $2,
              photo_url = $3
        WHERE id = $1
        RETURNING id, email, role, company_id, display_name, photo_url`,
      [req.userId, displayName || null, photoUrl || null]
    );
    res.json({ user: userPayload(rows[0], req.permissions, null) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "profile_update_failed" });
  }
});

app.get("/api/company/users", authRequired, async (req, res) => {
  try {
    if (!req.companyId) {
      const { rows } = await pool.query(
        `SELECT id, email, role, display_name, photo_url FROM users WHERE id = $1 AND deleted_at IS NULL`,
        [req.userId]
      );
      return res.json(rows);
    }
    // Hide removed employees from pickers (worker assignment, salesperson, etc.)
    const { rows } = await pool.query(
      `SELECT id, email, role, display_name, photo_url
         FROM users
        WHERE company_id = $1 AND deleted_at IS NULL
        ORDER BY COALESCE(display_name, email) ASC`,
      [req.companyId]
    );
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "company_users_failed" });
  }
});

app.get("/api/company/settings", authRequired, requireEmployer, async (req, res) => {
  try {
    const company = await pool.query(
      `SELECT id, name, join_code, logo_data_url, website, address, phone, email, notify_all_members_on_jobs
         FROM companies WHERE id = $1`,
      [req.companyId]
    );
    const employees = await pool.query(
      `SELECT u.id,
              u.email,
              u.display_name,
              u.photo_url,
              u.deleted_at,
              COALESCE(u.pre_delete_email, u.email) AS original_email,
              COALESCE(p.can_delete_contacts,false) AS can_delete_contacts,
              COALESCE(p.can_view_finance,false) AS can_view_finance,
              COALESCE(p.can_use_finance_ai,false) AS can_use_finance_ai,
              COALESCE(p.can_view_finance_transactions,false) AS can_view_finance_transactions,
              COALESCE(p.can_edit_finance_transactions,false) AS can_edit_finance_transactions,
              COALESCE(p.can_view_finance_accounts,false) AS can_view_finance_accounts,
              COALESCE(p.can_create_finance_accounts,false) AS can_create_finance_accounts,
              COALESCE(p.can_edit_finance_accounts,false) AS can_edit_finance_accounts,
              COALESCE(p.can_adjust_finance_account_balances,false) AS can_adjust_finance_account_balances,
              COALESCE(p.can_view_finance_receipts,false) AS can_view_finance_receipts,
              COALESCE(p.can_edit_finance_receipts,false) AS can_edit_finance_receipts,
              COALESCE(p.can_view_finance_planning,false) AS can_view_finance_planning,
              COALESCE(p.can_edit_finance_planning,false) AS can_edit_finance_planning,
              COALESCE(p.can_view_finance_budgets,false) AS can_view_finance_budgets,
              COALESCE(p.can_edit_finance_budgets,false) AS can_edit_finance_budgets,
              COALESCE(p.can_view_finance_goals,false) AS can_view_finance_goals,
              COALESCE(p.can_edit_finance_goals,false) AS can_edit_finance_goals,
              COALESCE(p.can_view_finance_debts,false) AS can_view_finance_debts,
              COALESCE(p.can_edit_finance_debts,false) AS can_edit_finance_debts,
              COALESCE(p.can_view_finance_settings,false) AS can_view_finance_settings,
              COALESCE(p.can_edit_finance_settings,false) AS can_edit_finance_settings,
              COALESCE(p.can_manage_company_finance_ai_memories,false) AS can_manage_company_finance_ai_memories
         FROM users u
         LEFT JOIN employee_permissions p ON p.user_id = u.id
        WHERE u.company_id = $1 AND u.role = 'employee'
        ORDER BY u.deleted_at IS NOT NULL, COALESCE(u.display_name, u.email) ASC`,
      [req.companyId]
    );
    res.json({ company: company.rows[0], employees: employees.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "company_settings_failed" });
  }
});

app.patch("/api/company/invoice-settings", authRequired, requireEmployer, async (req, res) => {
  try {
    const logo = (req.body.logo_data_url || "").toString();
    if (logo && logo.length > 350000) return res.status(413).json({ error: "logo_too_large" });
    const { rows } = await pool.query(
      `UPDATE companies
          SET logo_data_url = $2,
              website = $3,
              address = $4,
              phone = $5,
              email = $6,
              updated_at = now()
        WHERE id = $1
        RETURNING id, name, join_code, logo_data_url, website, address, phone, email`,
      [
        req.companyId,
        logo || null,
        (req.body.website || "").toString().trim() || null,
        (req.body.address || "").toString().trim() || null,
        (req.body.phone || "").toString().trim() || null,
        (req.body.email || "").toString().trim() || null
      ]
    );
    res.json({ company: rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "invoice_settings_update_failed" });
  }
});

app.patch("/api/company/job-notification-settings", authRequired, requireEmployer, async (req, res) => {
  try {
    const notifyAll = !!req.body.notify_all_members_on_jobs;
    const { rows } = await pool.query(
      `UPDATE companies
          SET notify_all_members_on_jobs = $2,
              updated_at = now()
        WHERE id = $1
        RETURNING id, name, join_code, logo_data_url, website, address, phone, email, notify_all_members_on_jobs`,
      [req.companyId, notifyAll]
    );
    res.json({ company: rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "job_notification_settings_update_failed" });
  }
});

app.get("/api/company/invoice-settings", authRequired, async (req, res) => {
  try {
    if (!req.companyId) return res.status(404).json({ error: "company_not_found" });
    const { rows } = await pool.query(
      `SELECT id, name, join_code, logo_data_url, website, address, phone, email, notify_all_members_on_jobs
         FROM companies WHERE id = $1`,
      [req.companyId]
    );
    res.json({ company: rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "invoice_settings_failed" });
  }
});

app.put("/api/company/join-code", authRequired, requireEmployer, async (req, res) => {
  try {
    const code = (req.body.join_code || "").toString().trim();
    if (!companyCodeIsValid(code)) return res.status(400).json({ error: "invalid_company_code" });
    const { rows } = await pool.query(
      `UPDATE companies SET join_code = $1, updated_at = now()
       WHERE id = $2
       RETURNING id, name, join_code`,
      [code, req.companyId]
    );
    res.json({ company: rows[0] });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "company_code_taken" });
    console.error(e);
    res.status(500).json({ error: "join_code_update_failed" });
  }
});

// Soft-delete an employee: revoke login access and scrub credentials/photo,
// but keep the row + display_name intact so historical records still resolve.
// Restore is always available via /api/company/employees/:id/restore.
app.delete("/api/company/employees/:id", authRequired, requireEmployer, async (req, res) => {
  const targetId = req.params.id;
  if (!targetId) return res.status(400).json({ error: "bad_id" });
  if (targetId === req.userId) {
    return res.status(400).json({ error: "cannot_delete_self", message: "You cannot remove your own account here." });
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    // Verify target is an employee in this company and is not an employer.
    const check = await client.query(
      `SELECT id, role, deleted_at FROM users WHERE id = $1 AND company_id = $2 FOR UPDATE`,
      [targetId, req.companyId]
    );
    if (!check.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "employee_not_found" });
    }
    if (check.rows[0].role === "employer") {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "cannot_delete_employer", message: "The employer/owner account cannot be removed." });
    }
    if (check.rows[0].deleted_at) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "already_deleted", message: "This employee has already been removed." });
    }
    // Scrub credentials/PII; preserve original email so restore can put it back.
    await client.query(
      `UPDATE users SET
         pre_delete_email = COALESCE(pre_delete_email, email),
         email = 'deleted+' || id::text || '@wolfcrm.deleted',
         password_hash = NULL,
         photo_url = NULL,
         deleted_at = now(),
         deleted_by = $2
       WHERE id = $1`,
      [targetId, req.userId]
    );
    // Kill all their sessions / recovery tokens / device tokens.
    await client.query(`DELETE FROM sessions WHERE user_id = $1`, [targetId]);
    await client.query(`DELETE FROM password_reset_codes WHERE email IN (SELECT pre_delete_email FROM users WHERE id = $1)`, [targetId]);
    await client.query(`DELETE FROM magic_tokens WHERE user_id = $1`, [targetId]).catch(() => {});
    await client.query(`DELETE FROM device_tokens WHERE user_id = $1`, [targetId]).catch(() => {});
    await client.query(`DELETE FROM employee_permissions WHERE user_id = $1`, [targetId]).catch(() => {});
    await client.query("COMMIT");
    try {
      await emitAutomationEvent({ companyId: req.companyId, eventType: "employee.deactivated", subjectType: "employee", subjectId: targetId, actorUserId: req.userId, source: "ios", payload: { employee_id: targetId, active: false } });
      await emitAutomationEvent({ companyId: req.companyId, eventType: "employee.removed", subjectType: "employee", subjectId: targetId, actorUserId: req.userId, source: "ios", payload: { employee_id: targetId, active: false } });
    } catch (automationErr) {
      console.warn("[automations] employee delete hook failed", automationErr?.message || automationErr);
    }
    console.log("[employees] removed", { targetId, by: req.userId, company: req.companyId });
    res.json({ success: true });
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("[employees] delete failed:", e && e.message ? e.message : e);
    res.status(500).json({ error: "delete_failed", message: "Could not remove that employee." });
  } finally {
    client.release();
  }
});

// Restore a previously removed employee. Their old email is put back, but
// password_hash stays NULL — they'll need to request a password reset to
// regain access.
app.post("/api/company/employees/:id/restore", authRequired, requireEmployer, async (req, res) => {
  const targetId = req.params.id;
  if (!targetId) return res.status(400).json({ error: "bad_id" });
  try {
    const check = await pool.query(
      `SELECT id, deleted_at, pre_delete_email FROM users WHERE id = $1 AND company_id = $2`,
      [targetId, req.companyId]
    );
    if (!check.rowCount) return res.status(404).json({ error: "employee_not_found" });
    if (!check.rows[0].deleted_at) {
      return res.status(409).json({ error: "not_deleted", message: "This employee is already active." });
    }
    const originalEmail = check.rows[0].pre_delete_email;
    // Check the original email isn't now taken by someone else.
    if (originalEmail) {
      const collision = await pool.query(
        `SELECT id FROM users WHERE email = $1 AND id <> $2 LIMIT 1`,
        [originalEmail, targetId]
      );
      if (collision.rowCount) {
        return res.status(409).json({ error: "email_taken", message: "The original email is already in use by another account. Update the employee's email after restoring." });
      }
    }
    await pool.query(
      `UPDATE users SET
         email = COALESCE(pre_delete_email, email),
         pre_delete_email = NULL,
         deleted_at = NULL,
         deleted_by = NULL
       WHERE id = $1`,
      [targetId]
    );
    try {
      await emitAutomationEvent({ companyId: req.companyId, eventType: "employee.reactivated", subjectType: "employee", subjectId: targetId, actorUserId: req.userId, source: "ios", payload: { employee_id: targetId, active: true } });
    } catch (automationErr) {
      console.warn("[automations] employee restore hook failed", automationErr?.message || automationErr);
    }
    console.log("[employees] restored", { targetId, by: req.userId, company: req.companyId });
    res.json({ success: true });
  } catch (e) {
    console.error("[employees] restore failed:", e && e.message ? e.message : e);
    res.status(500).json({ error: "restore_failed", message: "Could not restore that employee." });
  }
});

app.put("/api/company/employees/:id/permissions", authRequired, requireEmployer, async (req, res) => {
  try {
    const canDelete = !!req.body.can_delete_contacts;
    const financePermissions = {
      can_view_finance: !!req.body.can_view_finance,
      can_use_finance_ai: !!req.body.can_use_finance_ai,
      can_view_finance_transactions: !!req.body.can_view_finance_transactions,
      can_edit_finance_transactions: !!req.body.can_edit_finance_transactions,
      can_view_finance_accounts: !!req.body.can_view_finance_accounts,
      can_create_finance_accounts: !!req.body.can_create_finance_accounts,
      can_edit_finance_accounts: !!req.body.can_edit_finance_accounts,
      can_adjust_finance_account_balances: !!req.body.can_adjust_finance_account_balances,
      can_view_finance_receipts: !!req.body.can_view_finance_receipts,
      can_edit_finance_receipts: !!req.body.can_edit_finance_receipts,
      can_view_finance_planning: !!req.body.can_view_finance_planning,
      can_edit_finance_planning: !!req.body.can_edit_finance_planning,
      can_view_finance_budgets: !!req.body.can_view_finance_budgets,
      can_edit_finance_budgets: !!req.body.can_edit_finance_budgets,
      can_view_finance_goals: !!req.body.can_view_finance_goals,
      can_edit_finance_goals: !!req.body.can_edit_finance_goals,
      can_view_finance_debts: !!req.body.can_view_finance_debts,
      can_edit_finance_debts: !!req.body.can_edit_finance_debts,
      can_view_finance_settings: !!req.body.can_view_finance_settings,
      can_edit_finance_settings: !!req.body.can_edit_finance_settings,
      can_manage_company_finance_ai_memories: !!req.body.can_manage_company_finance_ai_memories
    };
    const employee = await pool.query(
      `SELECT id FROM users WHERE id = $1 AND company_id = $2 AND role = 'employee'`,
      [req.params.id, req.companyId]
    );
    if (!employee.rowCount) return res.status(404).json({ error: "employee_not_found" });
    const { rows } = await pool.query(
      `INSERT INTO employee_permissions(
         user_id, company_id, can_delete_contacts,
         can_view_finance, can_use_finance_ai,
         can_view_finance_transactions, can_edit_finance_transactions,
         can_view_finance_accounts, can_create_finance_accounts, can_edit_finance_accounts, can_adjust_finance_account_balances,
         can_view_finance_receipts, can_edit_finance_receipts,
         can_view_finance_planning, can_edit_finance_planning,
         can_view_finance_budgets, can_edit_finance_budgets,
         can_view_finance_goals, can_edit_finance_goals,
         can_view_finance_debts, can_edit_finance_debts,
         can_view_finance_settings, can_edit_finance_settings,
         can_manage_company_finance_ai_memories
       )
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)
       ON CONFLICT(user_id) DO UPDATE
         SET can_delete_contacts = EXCLUDED.can_delete_contacts,
             can_view_finance = EXCLUDED.can_view_finance,
             can_use_finance_ai = EXCLUDED.can_use_finance_ai,
             can_view_finance_transactions = EXCLUDED.can_view_finance_transactions,
             can_edit_finance_transactions = EXCLUDED.can_edit_finance_transactions,
             can_view_finance_accounts = EXCLUDED.can_view_finance_accounts,
             can_create_finance_accounts = EXCLUDED.can_create_finance_accounts,
             can_edit_finance_accounts = EXCLUDED.can_edit_finance_accounts,
             can_adjust_finance_account_balances = EXCLUDED.can_adjust_finance_account_balances,
             can_view_finance_receipts = EXCLUDED.can_view_finance_receipts,
             can_edit_finance_receipts = EXCLUDED.can_edit_finance_receipts,
             can_view_finance_planning = EXCLUDED.can_view_finance_planning,
             can_edit_finance_planning = EXCLUDED.can_edit_finance_planning,
             can_view_finance_budgets = EXCLUDED.can_view_finance_budgets,
             can_edit_finance_budgets = EXCLUDED.can_edit_finance_budgets,
             can_view_finance_goals = EXCLUDED.can_view_finance_goals,
             can_edit_finance_goals = EXCLUDED.can_edit_finance_goals,
             can_view_finance_debts = EXCLUDED.can_view_finance_debts,
             can_edit_finance_debts = EXCLUDED.can_edit_finance_debts,
             can_view_finance_settings = EXCLUDED.can_view_finance_settings,
             can_edit_finance_settings = EXCLUDED.can_edit_finance_settings,
             can_manage_company_finance_ai_memories = EXCLUDED.can_manage_company_finance_ai_memories,
             updated_at = now()
      RETURNING user_id AS id, can_delete_contacts,
                can_view_finance, can_use_finance_ai,
                can_view_finance_transactions, can_edit_finance_transactions,
                can_view_finance_accounts, can_create_finance_accounts, can_edit_finance_accounts, can_adjust_finance_account_balances,
                can_view_finance_receipts, can_edit_finance_receipts,
                can_view_finance_planning, can_edit_finance_planning,
                can_view_finance_budgets, can_edit_finance_budgets,
                can_view_finance_goals, can_edit_finance_goals,
                can_view_finance_debts, can_edit_finance_debts,
                can_view_finance_settings, can_edit_finance_settings,
                can_manage_company_finance_ai_memories`,
      [
        req.params.id, req.companyId, canDelete,
        financePermissions.can_view_finance, financePermissions.can_use_finance_ai,
        financePermissions.can_view_finance_transactions, financePermissions.can_edit_finance_transactions,
        financePermissions.can_view_finance_accounts, financePermissions.can_create_finance_accounts, financePermissions.can_edit_finance_accounts, financePermissions.can_adjust_finance_account_balances,
        financePermissions.can_view_finance_receipts, financePermissions.can_edit_finance_receipts,
        financePermissions.can_view_finance_planning, financePermissions.can_edit_finance_planning,
        financePermissions.can_view_finance_budgets, financePermissions.can_edit_finance_budgets,
        financePermissions.can_view_finance_goals, financePermissions.can_edit_finance_goals,
        financePermissions.can_view_finance_debts, financePermissions.can_edit_finance_debts,
        financePermissions.can_view_finance_settings, financePermissions.can_edit_finance_settings,
        financePermissions.can_manage_company_finance_ai_memories
      ]
    );
    try {
      await emitAutomationEvent({ companyId: req.companyId, eventType: "employee.permission_changed", subjectType: "employee", subjectId: req.params.id, actorUserId: req.userId, source: "ios", payload: { employee_id: req.params.id, permission: "can_delete_contacts", new_value: canDelete } });
    } catch (automationErr) {
      console.warn("[automations] employee permission hook failed", automationErr?.message || automationErr);
    }
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "permissions_update_failed" });
  }
});

function weekRangeFromQuery(req) {
  const startRaw = (req.query.week_start || "").toString();
  const start = startRaw ? new Date(startRaw) : new Date();
  if (Number.isNaN(start.getTime())) return null;
  start.setUTCHours(0, 0, 0, 0);
  const end = new Date(start.getTime() + 7 * 24 * 60 * 60 * 1000);
  return { start, end };
}

function entrySelect(prefix = "e") {
  return `${prefix}.id, ${prefix}.user_id, u.email AS user_email, ${prefix}.company_id,
          ${prefix}.start_at, ${prefix}.end_at, ${prefix}.note,
          ${prefix}.manual_entry, ${prefix}.manual_status,
          ${prefix}.break_seconds, ${prefix}.break_started_at,
          ${prefix}.created_at, ${prefix}.updated_at`;
}

function canEmployeeChangeTimeEntry(start, now = new Date()) {
  const weekStart = new Date(start);
  weekStart.setUTCHours(0, 0, 0, 0);
  const weekday = weekStart.getUTCDay();
  weekStart.setUTCDate(weekStart.getUTCDate() - weekday);
  const cutoff = new Date(weekStart.getTime() + 9 * 24 * 60 * 60 * 1000);
  cutoff.setUTCHours(0, 0, 0, 0);
  return now < cutoff;
}

// ---------- INTERNAL MESSAGING ----------
app.get("/api/notifications", authRequired, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, kind, title, body, data, created_at, read_at
         FROM notifications
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT 100`,
      [req.userId]
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "notifications_failed" }); }
});

app.post("/api/notifications/:id/read", authRequired, async (req, res) => {
  try {
    await pool.query(`UPDATE notifications SET read_at = now() WHERE id = $1 AND user_id = $2`, [req.params.id, req.userId]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "notification_read_failed" }); }
});

app.post("/api/internal/media/upload-url", authRequired, async (req, res) => {
  try {
    const cfg = mediaBucketConfig();
    const s3 = getMediaS3Client();
    if (!cfg || !s3) return res.status(503).json({ error: "media_bucket_not_configured" });

    const kind = ["photo", "video", "file"].includes(req.body.kind) ? req.body.kind : "file";
    const fileName = (req.body.file_name || "upload").toString().replace(/[^\w.\- ]+/g, "_").slice(0, 160);
    const mimeType = (req.body.mime_type || "application/octet-stream").toString().slice(0, 120);
    const byteSize = Number(req.body.byte_size || 0);
    if (!Number.isFinite(byteSize) || byteSize <= 0) return res.status(400).json({ error: "invalid_file_size" });
    if (byteSize > 200 * 1024 * 1024) return res.status(413).json({ error: "file_too_large" });

    const scope = req.companyId || req.userId;
    const objectKey = `companies/${scope}/messages/${new Date().toISOString().slice(0, 10)}/${randomUUID()}-${fileName}`;
    const command = new PutObjectCommand({
      Bucket: cfg.bucket,
      Key: objectKey,
      ContentType: mimeType
    });
    const upload_url = await getSignedUrl(s3, command, { expiresIn: 900 });
    res.json({
      object_key: objectKey,
      upload_url,
      kind,
      file_name: fileName,
      mime_type: mimeType,
      byte_size: byteSize
    });
  } catch (e) { console.error(e); res.status(500).json({ error: "media_upload_url_failed" }); }
});

app.get("/api/internal/media/download-url", authRequired, async (req, res) => {
  try {
    const cfg = mediaBucketConfig();
    const s3 = getMediaS3Client();
    if (!cfg || !s3) return res.status(503).json({ error: "media_bucket_not_configured" });

    const objectKey = (req.query.object_key || "").toString();
    const scope = req.companyId || req.userId;
    if (!objectKey.startsWith(`companies/${scope}/messages/`)) {
      return res.status(403).json({ error: "media_forbidden" });
    }
    const command = new GetObjectCommand({ Bucket: cfg.bucket, Key: objectKey });
    const download_url = await getSignedUrl(s3, command, { expiresIn: 900 });
    res.json({ download_url });
  } catch (e) { console.error(e); res.status(500).json({ error: "media_download_url_failed" }); }
});

app.get("/api/internal/conversations", authRequired, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT c.id, c.company_id, c.title, c.is_group, c.created_by, c.created_at, c.updated_at,
              COALESCE((
                SELECT json_agg(json_build_object(
                  'id', u.id, 'email', u.email, 'role', u.role,
                  'display_name', u.display_name, 'photo_url', u.photo_url
                ) ORDER BY COALESCE(u.display_name, u.email))
                FROM conversation_participants cp2
                JOIN users u ON u.id = cp2.user_id
                WHERE cp2.conversation_id = c.id
              ), '[]'::json) AS participants,
              lm.body AS latest_body,
              lm.created_at AS latest_at,
              (
                SELECT COUNT(*)
                  FROM messages m
                 WHERE m.conversation_id = c.id
                   AND m.sender_id <> $1
                   AND m.deleted_at IS NULL
                   AND m.created_at > COALESCE(cp.last_read_at, '1970-01-01'::timestamptz)
              )::int AS unread_count
         FROM conversation_participants cp
         JOIN conversations c ON c.id = cp.conversation_id
         LEFT JOIN LATERAL (
           SELECT body, created_at FROM messages
            WHERE conversation_id = c.id
            ORDER BY created_at DESC
            LIMIT 1
         ) lm ON true
        WHERE cp.user_id = $1
          AND c.deleted_at IS NULL
        ORDER BY COALESCE(lm.created_at, c.updated_at) DESC`,
      [req.userId]
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "conversation_list_failed" }); }
});

app.post("/api/internal/conversations/private", authRequired, async (req, res) => {
  const otherUserId = (req.body.user_id || "").toString();
  if (!otherUserId || otherUserId === req.userId) return res.status(400).json({ error: "invalid_user" });
  try {
    const member = await pool.query(
      req.companyId ? `SELECT id FROM users WHERE id = $1 AND company_id = $2` : `SELECT id FROM users WHERE id = $1`,
      req.companyId ? [otherUserId, req.companyId] : [otherUserId]
    );
    if (!member.rows.length) return res.status(404).json({ error: "user_not_found" });
    const existing = await pool.query(
      `SELECT c.id
         FROM conversations c
         JOIN conversation_participants a ON a.conversation_id = c.id AND a.user_id = $1
         JOIN conversation_participants b ON b.conversation_id = c.id AND b.user_id = $2
        WHERE c.is_group = false
          AND (SELECT COUNT(*) FROM conversation_participants cp WHERE cp.conversation_id = c.id) = 2
        LIMIT 1`,
      [req.userId, otherUserId]
    );
    if (existing.rows.length) return res.json({ id: existing.rows[0].id });
    const id = randomUUID();
    await pool.query(`INSERT INTO conversations(id, company_id, is_group, created_by) VALUES($1,$2,false,$3)`, [id, req.companyId || null, req.userId]);
    await pool.query(
      `INSERT INTO conversation_participants(id, conversation_id, user_id) VALUES($1,$2,$3),($4,$2,$5)`,
      [randomUUID(), id, req.userId, randomUUID(), otherUserId]
    );
    if (req.companyId) {
      emitAutomationEvent({
        companyId: req.companyId,
        eventType: "internal.conversation_created",
        subjectType: "internal_conversation",
        subjectId: id,
        actorUserId: req.userId,
        source: "ios",
        dedupeKey: `internal.conversation_created:${id}`,
        payload: { conversation_id: id, is_dm: true, recipient_user_ids: [otherUserId], sender_user_id: req.userId }
      }).catch((e) => console.error("[internal/private] automation emission failed:", { code: e?.code, message: e?.message }));
    }
    res.status(201).json({ id });
  } catch (e) { console.error(e); res.status(500).json({ error: "private_conversation_failed" }); }
});

app.post("/api/internal/conversations/group", authRequired, async (req, res) => {
  const title = (req.body.title || "Group").toString().trim() || "Group";
  const ids = [...new Set([req.userId, ...((Array.isArray(req.body.participant_ids) ? req.body.participant_ids : []).map(String))])];
  if (ids.length < 2) return res.status(400).json({ error: "group_needs_members" });
  try {
    if (req.companyId) {
      const valid = await pool.query(`SELECT id FROM users WHERE company_id = $1 AND id = ANY($2::uuid[])`, [req.companyId, ids]);
      if (valid.rows.length !== ids.length) return res.status(400).json({ error: "invalid_participant" });
    }
    const id = randomUUID();
    await pool.query(`INSERT INTO conversations(id, company_id, title, is_group, created_by) VALUES($1,$2,$3,true,$4)`, [id, req.companyId || null, title, req.userId]);
    for (const userId of ids) {
      await pool.query(`INSERT INTO conversation_participants(id, conversation_id, user_id) VALUES($1,$2,$3)`, [randomUUID(), id, userId]);
    }
    if (req.companyId) {
      emitAutomationEvent({
        companyId: req.companyId,
        eventType: "internal.group_created",
        subjectType: "internal_conversation",
        subjectId: id,
        actorUserId: req.userId,
        source: "ios",
        dedupeKey: `internal.group_created:${id}`,
        payload: { conversation_id: id, title, recipient_user_ids: ids.filter((userId) => userId !== req.userId), sender_user_id: req.userId, is_group: true }
      }).catch((e) => console.error("[internal/group] automation emission failed:", { code: e?.code, message: e?.message }));
    }
    res.status(201).json({ id });
  } catch (e) { console.error(e); res.status(500).json({ error: "group_conversation_failed" }); }
});

app.get("/api/internal/conversations/:id/messages", authRequired, async (req, res) => {
  try {
    const member = await pool.query(`SELECT 1 FROM conversation_participants WHERE conversation_id = $1 AND user_id = $2`, [req.params.id, req.userId]);
    if (!member.rows.length) return res.status(403).json({ error: "not_participant" });
    const { rows } = await pool.query(
      `SELECT m.id, m.conversation_id, m.channel_id, m.sender_id, m.body, m.created_at, m.updated_at, m.deleted_at,
              u.display_name AS sender_name, u.email AS sender_email, u.photo_url AS sender_photo_url
         FROM messages m
         JOIN users u ON u.id = m.sender_id
        WHERE m.conversation_id = $1
        ORDER BY m.created_at ASC
        LIMIT 200`,
      [req.params.id]
    );
    res.json(await messageRowsWithAttachments(rows));
  } catch (e) { console.error(e); res.status(500).json({ error: "conversation_messages_failed" }); }
});

app.delete("/api/internal/conversations/:id", authRequired, requireEmployer, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `UPDATE conversations
          SET deleted_at = now(), updated_at = now()
        WHERE id = $1
          AND company_id = $2
          AND deleted_at IS NULL
        RETURNING id`,
      [req.params.id, req.companyId]
    );
    if (!rows.length) return res.status(404).json({ error: "conversation_not_found" });
    await pool.query(`UPDATE messages SET deleted_at = COALESCE(deleted_at, now()), body = '' WHERE conversation_id = $1 AND deleted_at IS NULL`, [req.params.id]);
    res.status(204).end();
  } catch (e) { console.error(e); res.status(500).json({ error: "delete_conversation_failed" }); }
});

app.post("/api/internal/conversations/:id/messages", authRequired, async (req, res) => {
  const body = (req.body.body || "").toString();
  const attachments = parseAttachments(req.body.attachments);
  if (!body.trim() && !attachments.length) return res.status(400).json({ error: "empty_message" });
  try {
    const member = await pool.query(`SELECT 1 FROM conversation_participants WHERE conversation_id = $1 AND user_id = $2`, [req.params.id, req.userId]);
    if (!member.rows.length) return res.status(403).json({ error: "not_participant" });
    const id = randomUUID();
    const { rows } = await pool.query(
      `INSERT INTO messages(id, conversation_id, sender_id, body) VALUES($1,$2,$3,$4)
       RETURNING id, conversation_id, channel_id, sender_id, body, created_at, updated_at, deleted_at`,
      [id, req.params.id, req.userId, body]
    );
    await attachRows(id, attachments);
    await pool.query(`UPDATE conversations SET updated_at = now() WHERE id = $1`, [req.params.id]);
    const recipients = await pool.query(`SELECT user_id FROM conversation_participants WHERE conversation_id = $1`, [req.params.id]);
    const recipientIds = recipients.rows.map((r) => r.user_id).filter((userId) => userId !== req.userId);
    if (req.companyId) {
      const convo = await pool.query(`SELECT is_group FROM conversations WHERE id = $1 AND company_id = $2 LIMIT 1`, [req.params.id, req.companyId]);
      const eventTypes = ["internal.message_sent", "internal.message_received", convo.rows[0]?.is_group ? "internal.group_message_received" : "internal.dm_received"];
      if (attachments.length) eventTypes.push("internal.attachment_received");
      for (const eventType of eventTypes) {
        await emitAutomationEvent({
          companyId: req.companyId,
          eventType,
          subjectType: "internal_message",
          subjectId: id,
          actorUserId: req.userId,
          source: "ios",
          dedupeKey: `${eventType}:${id}`,
          payload: { message_id: id, conversation_id: req.params.id, sender_user_id: req.userId, recipient_user_ids: recipientIds, body, message_body: body, has_attachments: attachments.length > 0, attachment_count: attachments.length, conversation_type: convo.rows[0]?.is_group ? "group" : "dm" }
        });
      }
    }
    await notifyMany(recipients.rows.map((r) => r.user_id), req.companyId, "internal_message", "New message", body || "Attachment", { conversation_id: req.params.id, message_id: id }, req.userId);
    res.status(201).json((await messageRowsWithAttachments(rows))[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "send_conversation_message_failed" }); }
});

app.post("/api/internal/conversations/:id/read", authRequired, async (req, res) => {
  try {
    const result = await pool.query(`UPDATE conversation_participants SET last_read_at = now() WHERE conversation_id = $1 AND user_id = $2 RETURNING conversation_id`, [req.params.id, req.userId]);
    if (result.rowCount && req.companyId) {
      emitAutomationEvent({
        companyId: req.companyId,
        eventType: "internal.conversation_read",
        subjectType: "internal_conversation",
        subjectId: req.params.id,
        actorUserId: req.userId,
        source: "ios",
        dedupeKey: `internal.conversation_read:${req.params.id}:${req.userId}:${Date.now()}`,
        payload: { conversation_id: req.params.id, user_id: req.userId }
      }).catch((e) => console.error("[internal/read] automation emission failed:", { code: e?.code, message: e?.message }));
    }
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "mark_read_failed" }); }
});

app.get("/api/internal/channels", authRequired, async (req, res) => {
  try {
    const where = req.companyId ? `company_id = $1` : `created_by = $1`;
    const { rows } = await pool.query(
      `SELECT id, company_id, name, description, created_by, created_at, archived_at
         FROM channels
        WHERE ${where} AND archived_at IS NULL
        ORDER BY lower(name) ASC`,
      [req.companyId || req.userId]
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "channels_failed" }); }
});

app.delete("/api/internal/channels/:id", authRequired, requireEmployer, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `UPDATE channels
          SET archived_at = now()
        WHERE id = $1
          AND company_id = $2
          AND archived_at IS NULL
        RETURNING id`,
      [req.params.id, req.companyId]
    );
    if (!rows.length) return res.status(404).json({ error: "channel_not_found" });
    await pool.query(`UPDATE messages SET deleted_at = COALESCE(deleted_at, now()), body = '' WHERE channel_id = $1 AND deleted_at IS NULL`, [req.params.id]);
    emitAutomationEvent({
      companyId: req.companyId,
      eventType: "internal.channel_deleted",
      subjectType: "channel",
      subjectId: rows[0].id,
      actorUserId: req.userId,
      source: "ios",
      dedupeKey: `internal.channel_deleted:${rows[0].id}`,
      payload: { channel_id: rows[0].id }
    }).catch((e) => console.error("[internal/channel/delete] automation emission failed:", { code: e?.code, message: e?.message }));
    res.status(204).end();
  } catch (e) { console.error(e); res.status(500).json({ error: "delete_channel_failed" }); }
});

app.post("/api/internal/channels", authRequired, async (req, res) => {
  const name = (req.body.name || "").toString().trim();
  const description = (req.body.description || "").toString().trim();
  if (!name) return res.status(400).json({ error: "missing_name" });
  try {
    const { rows } = await pool.query(
      `INSERT INTO channels(id, company_id, name, description, created_by)
       VALUES($1,$2,$3,$4,$5)
       RETURNING id, company_id, name, description, created_by, created_at, archived_at`,
      [randomUUID(), req.companyId || null, name, description || null, req.userId]
    );
    if (req.companyId) {
      emitAutomationEvent({
        companyId: req.companyId,
        eventType: "internal.channel_created",
        subjectType: "channel",
        subjectId: rows[0].id,
        actorUserId: req.userId,
        source: "ios",
        dedupeKey: `internal.channel_created:${rows[0].id}`,
        payload: { channel_id: rows[0].id, name: rows[0].name, description: rows[0].description || null }
      }).catch((e) => console.error("[internal/channel/create] automation emission failed:", { code: e?.code, message: e?.message }));
    }
    res.status(201).json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "create_channel_failed" }); }
});

app.get("/api/internal/channels/:id/messages", authRequired, async (req, res) => {
  try {
    const channel = await pool.query(
      req.companyId ? `SELECT id FROM channels WHERE id = $1 AND company_id = $2 AND archived_at IS NULL` : `SELECT id FROM channels WHERE id = $1 AND created_by = $2 AND archived_at IS NULL`,
      req.companyId ? [req.params.id, req.companyId] : [req.params.id, req.userId]
    );
    if (!channel.rows.length) return res.status(404).json({ error: "channel_not_found" });
    const { rows } = await pool.query(
      `SELECT m.id, m.conversation_id, m.channel_id, m.sender_id, m.body, m.created_at, m.updated_at, m.deleted_at,
              u.display_name AS sender_name, u.email AS sender_email, u.photo_url AS sender_photo_url
         FROM messages m
         JOIN users u ON u.id = m.sender_id
        WHERE m.channel_id = $1
        ORDER BY m.created_at ASC
        LIMIT 200`,
      [req.params.id]
    );
    res.json(await messageRowsWithAttachments(rows));
  } catch (e) { console.error(e); res.status(500).json({ error: "channel_messages_failed" }); }
});

app.post("/api/internal/channels/:id/messages", authRequired, async (req, res) => {
  const body = (req.body.body || "").toString();
  const attachments = parseAttachments(req.body.attachments);
  if (!body.trim() && !attachments.length) return res.status(400).json({ error: "empty_message" });
  try {
    const channel = await pool.query(
      req.companyId ? `SELECT id, name FROM channels WHERE id = $1 AND company_id = $2 AND archived_at IS NULL` : `SELECT id, name FROM channels WHERE id = $1 AND created_by = $2 AND archived_at IS NULL`,
      req.companyId ? [req.params.id, req.companyId] : [req.params.id, req.userId]
    );
    if (!channel.rows.length) return res.status(404).json({ error: "channel_not_found" });
    const id = randomUUID();
    const { rows } = await pool.query(
      `INSERT INTO messages(id, channel_id, sender_id, body) VALUES($1,$2,$3,$4)
       RETURNING id, conversation_id, channel_id, sender_id, body, created_at, updated_at, deleted_at`,
      [id, req.params.id, req.userId, body]
    );
    await attachRows(id, attachments);
    const recipients = await pool.query(
      req.companyId ? `SELECT id FROM users WHERE company_id = $1` : `SELECT id FROM users WHERE id = $1`,
      [req.companyId || req.userId]
    );
    if (req.companyId) {
      const recipientIds = recipients.rows.map((r) => r.id).filter((userId) => userId !== req.userId);
      const eventTypes = ["internal.message_sent", "internal.channel_message_received"];
      if (attachments.length) eventTypes.push("internal.attachment_received");
      for (const eventType of eventTypes) {
        await emitAutomationEvent({
          companyId: req.companyId,
          eventType,
          subjectType: "internal_message",
          subjectId: id,
          actorUserId: req.userId,
          source: "ios",
          dedupeKey: `${eventType}:${id}`,
          payload: { message_id: id, channel_id: req.params.id, channel_name: channel.rows[0].name, sender_user_id: req.userId, recipient_user_ids: recipientIds, body, message_body: body, has_attachments: attachments.length > 0, attachment_count: attachments.length, conversation_type: "channel" }
        });
      }
    }
    await notifyMany(recipients.rows.map((r) => r.id), req.companyId, "channel_message", `#${channel.rows[0].name}`, body || "Attachment", { channel_id: req.params.id, message_id: id }, req.userId);
    res.status(201).json((await messageRowsWithAttachments(rows))[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "send_channel_message_failed" }); }
});

app.delete("/api/internal/messages/:id", authRequired, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `UPDATE messages m
          SET deleted_at = now(), body = ''
         FROM users sender
         LEFT JOIN conversations c ON c.id = m.conversation_id
         LEFT JOIN channels ch ON ch.id = m.channel_id
        WHERE m.id = $1
          AND sender.id = m.sender_id
          AND m.deleted_at IS NULL
          AND (
            m.sender_id = $2
            OR (
              $3 = 'employer'
              AND sender.company_id = $4
              AND (
                (c.id IS NOT NULL AND c.company_id = $4)
                OR (ch.id IS NOT NULL AND ch.company_id = $4)
              )
            )
          )
        RETURNING m.id, m.conversation_id, m.channel_id`,
      [req.params.id, req.userId, req.role, req.companyId]
    );
    if (!rows.length) return res.status(404).json({ error: "message_not_found" });
    if (req.companyId) {
      emitAutomationEvent({
        companyId: req.companyId,
        eventType: "internal.message_deleted",
        subjectType: "internal_message",
        subjectId: rows[0].id,
        actorUserId: req.userId,
        source: "ios",
        dedupeKey: `internal.message_deleted:${rows[0].id}`,
        payload: { message_id: rows[0].id, conversation_id: rows[0].conversation_id || null, channel_id: rows[0].channel_id || null }
      }).catch((e) => console.error("[internal/message/delete] automation emission failed:", { code: e?.code, message: e?.message }));
    }
    res.status(204).end();
  } catch (e) { console.error(e); res.status(500).json({ error: "delete_message_failed" }); }
});

// ---------- TIME CLOCK ----------
app.get("/api/time-clock/settings", authRequired, async (req, res) => {
  try {
    if (!req.companyId) return res.json({ week_start: 1 });
    const { rows } = await pool.query(
      `INSERT INTO time_clock_settings(company_id, week_start)
       VALUES($1, 1)
       ON CONFLICT(company_id) DO UPDATE SET company_id = EXCLUDED.company_id
       RETURNING week_start`,
      [req.companyId]
    );
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "time_settings_failed" }); }
});

app.put("/api/time-clock/settings", authRequired, requireEmployer, async (req, res) => {
  try {
    const weekStart = Number(req.body.week_start);
    if (!Number.isInteger(weekStart) || weekStart < 0 || weekStart > 6) {
      return res.status(400).json({ error: "invalid_week_start" });
    }
    const { rows } = await pool.query(
      `INSERT INTO time_clock_settings(company_id, week_start)
       VALUES($1,$2)
       ON CONFLICT(company_id) DO UPDATE
         SET week_start = EXCLUDED.week_start,
             updated_at = now()
       RETURNING week_start`,
      [req.companyId, weekStart]
    );
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "time_settings_update_failed" }); }
});

app.get("/api/time-clock/me", authRequired, async (req, res) => {
  try {
    const range = weekRangeFromQuery(req);
    if (!range) return res.status(400).json({ error: "invalid_week_start" });
    const open = await pool.query(
      `SELECT ${entrySelect("e")}
         FROM time_clock_entries e
         JOIN users u ON u.id = e.user_id
        WHERE e.user_id = $1 AND e.end_at IS NULL AND e.manual_status <> 'disapproved'
        ORDER BY e.start_at DESC LIMIT 1`,
      [req.userId]
    );
    const entries = await pool.query(
      `SELECT ${entrySelect("e")}
         FROM time_clock_entries e
         JOIN users u ON u.id = e.user_id
        WHERE e.user_id = $1 AND e.start_at >= $2 AND e.start_at < $3 AND e.manual_status <> 'disapproved'
        ORDER BY e.start_at DESC`,
      [req.userId, range.start.toISOString(), range.end.toISOString()]
    );
    res.json({ open_entry: open.rows[0] || null, entries: entries.rows });
  } catch (e) { console.error(e); res.status(500).json({ error: "time_me_failed" }); }
});

app.post("/api/time-clock/clock-in", authRequired, async (req, res) => {
  try {
    const existing = await pool.query(
      `SELECT id FROM time_clock_entries WHERE user_id = $1 AND end_at IS NULL LIMIT 1`,
      [req.userId]
    );
    if (existing.rowCount) return res.status(409).json({ error: "already_clocked_in" });
    const start = req.body.start_at ? new Date(req.body.start_at) : new Date();
    if (Number.isNaN(start.getTime())) return res.status(400).json({ error: "invalid_start" });
    if (start > new Date()) return res.status(400).json({ error: "future_time_not_allowed" });
    const note = req.body.note || null;
    const { rows } = await pool.query(
      `INSERT INTO time_clock_entries(id, user_id, company_id, start_at, note, created_by, updated_by)
       VALUES($1,$2,$3,$4,$5,$2,$2)
       RETURNING *`,
      [randomUUID(), req.userId, req.companyId, start.toISOString(), note]
    );
    try {
      const entry = rows[0];
      await emitAutomationEvent({ companyId: req.companyId, eventType: "time_clock.clocked_in", subjectType: "time_entry", subjectId: entry.id, actorUserId: req.userId, source: "ios", dedupeKey: `time_clock.clocked_in:${entry.id}`, payload: { time_entry_id: entry.id, employee_id: entry.user_id, clock_in: entry.start_at, source: "ios" } });
      await emitAutomationEvent({ companyId: req.companyId, eventType: "time_clock.shift_started", subjectType: "time_entry", subjectId: entry.id, actorUserId: req.userId, source: "ios", dedupeKey: `time_clock.shift_started:${entry.id}`, payload: { time_entry_id: entry.id, employee_id: entry.user_id, clock_in: entry.start_at, source: "ios" } });
      await syncAutomationSchedulesForTimeEntry(req.companyId, entry);
    } catch (automationErr) {
      console.warn("[automations] clock-in hook failed", automationErr?.message || automationErr);
    }
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "clock_in_failed" }); }
});

app.post("/api/time-clock/clock-out", authRequired, async (req, res) => {
  try {
    const end = req.body.end_at ? new Date(req.body.end_at) : new Date();
    if (Number.isNaN(end.getTime())) return res.status(400).json({ error: "invalid_end" });
    if (end > new Date()) return res.status(400).json({ error: "future_time_not_allowed" });
    const { rows } = await pool.query(
      `UPDATE time_clock_entries
          SET end_at = $3,
              break_seconds = break_seconds + CASE
                WHEN break_started_at IS NULL THEN 0
                ELSE GREATEST(0, EXTRACT(EPOCH FROM ($3::timestamptz - break_started_at))::integer)
              END,
              break_started_at = NULL,
              updated_by = $2,
              updated_at = now()
        WHERE id = (
          SELECT id FROM time_clock_entries
          WHERE user_id = $1 AND end_at IS NULL
          ORDER BY start_at DESC LIMIT 1
        )
        RETURNING *`,
      [req.userId, req.userId, end.toISOString()]
    );
    if (!rows.length) return res.status(404).json({ error: "not_clocked_in" });
    try {
      const entry = rows[0];
      const durationMinutes = Math.max(0, Math.floor((new Date(entry.end_at).getTime() - new Date(entry.start_at).getTime()) / 60000) - Math.floor(Number(entry.break_seconds || 0) / 60));
      await cancelAutomationSchedulesForSubject(req.companyId, "time_entry", entry.id);
      await emitAutomationEvent({ companyId: req.companyId, eventType: "time_clock.clocked_out", subjectType: "time_entry", subjectId: entry.id, actorUserId: req.userId, source: "ios", dedupeKey: `time_clock.clocked_out:${entry.id}`, payload: { time_entry_id: entry.id, employee_id: entry.user_id, clock_in: entry.start_at, clock_out: entry.end_at, duration_minutes: durationMinutes, duration_hours: durationMinutes / 60, source: "ios" } });
      await emitAutomationEvent({ companyId: req.companyId, eventType: "time_clock.shift_completed", subjectType: "time_entry", subjectId: entry.id, actorUserId: req.userId, source: "ios", dedupeKey: `time_clock.shift_completed:${entry.id}`, payload: { time_entry_id: entry.id, employee_id: entry.user_id, clock_in: entry.start_at, clock_out: entry.end_at, duration_minutes: durationMinutes, duration_hours: durationMinutes / 60, source: "ios" } });
    } catch (automationErr) {
      console.warn("[automations] clock-out hook failed", automationErr?.message || automationErr);
    }
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "clock_out_failed" }); }
});

app.post("/api/time-clock/break-start", authRequired, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `UPDATE time_clock_entries
          SET break_started_at = COALESCE(break_started_at, now()),
              updated_by = $2,
              updated_at = now()
        WHERE id = (
          SELECT id FROM time_clock_entries
          WHERE user_id = $1 AND end_at IS NULL
          ORDER BY start_at DESC LIMIT 1
        )
        RETURNING *`,
      [req.userId, req.userId]
    );
    if (!rows.length) return res.status(404).json({ error: "not_clocked_in" });
    try {
      const entry = rows[0];
      await emitAutomationEvent({ companyId: req.companyId, eventType: "time_clock.break_started", subjectType: "time_entry", subjectId: entry.id, actorUserId: req.userId, source: "ios", dedupeKey: `time_clock.break_started:${entry.id}:${entry.break_started_at}`, payload: { time_entry_id: entry.id, employee_id: entry.user_id, break_started_at: entry.break_started_at } });
    } catch (automationErr) {
      console.warn("[automations] break-start hook failed", automationErr?.message || automationErr);
    }
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "break_start_failed" }); }
});

app.post("/api/time-clock/break-end", authRequired, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `UPDATE time_clock_entries
          SET break_seconds = break_seconds + GREATEST(0, EXTRACT(EPOCH FROM (now() - break_started_at))::integer),
              break_started_at = NULL,
              updated_by = $2,
              updated_at = now()
        WHERE id = (
          SELECT id FROM time_clock_entries
          WHERE user_id = $1 AND end_at IS NULL AND break_started_at IS NOT NULL
          ORDER BY start_at DESC LIMIT 1
        )
        RETURNING *`,
      [req.userId, req.userId]
    );
    if (!rows.length) return res.status(404).json({ error: "not_on_break" });
    try {
      const entry = rows[0];
      await emitAutomationEvent({ companyId: req.companyId, eventType: "time_clock.break_ended", subjectType: "time_entry", subjectId: entry.id, actorUserId: req.userId, source: "ios", payload: { time_entry_id: entry.id, employee_id: entry.user_id, break_seconds: entry.break_seconds } });
    } catch (automationErr) {
      console.warn("[automations] break-end hook failed", automationErr?.message || automationErr);
    }
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "break_end_failed" }); }
});

app.get("/api/time-clock/company", authRequired, requireEmployer, async (req, res) => {
  try {
    const range = weekRangeFromQuery(req);
    if (!range) return res.status(400).json({ error: "invalid_week_start" });
    const employees = await pool.query(
      `SELECT id, email, role FROM users WHERE company_id = $1 ORDER BY email ASC`,
      [req.companyId]
    );
    const entries = await pool.query(
      `SELECT ${entrySelect("e")}
         FROM time_clock_entries e
         JOIN users u ON u.id = e.user_id
        WHERE e.company_id = $1 AND e.start_at >= $2 AND e.start_at < $3 AND e.manual_status <> 'disapproved'
        ORDER BY u.email ASC, e.start_at DESC`,
      [req.companyId, range.start.toISOString(), range.end.toISOString()]
    );
    res.json({ employees: employees.rows, entries: entries.rows });
  } catch (e) { console.error(e); res.status(500).json({ error: "time_company_failed" }); }
});

app.get("/api/time-clock/range", authRequired, async (req, res) => {
  try {
    const start = new Date(req.query.start);
    const end = new Date(req.query.end);
    if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || start >= end) {
      return res.status(400).json({ error: "invalid_range" });
    }
    if (req.role !== "employer") {
      const entries = await pool.query(
        `SELECT ${entrySelect("e")}
           FROM time_clock_entries e
          WHERE e.user_id = $1 AND e.start_at >= $2 AND e.start_at < $3 AND e.manual_status <> 'disapproved'
          ORDER BY e.start_at DESC`,
        [req.userId, start.toISOString(), end.toISOString()]
      );
      return res.json({
        employees: [{ id: req.userId, email: req.userEmail, role: req.role }],
        entries: entries.rows
      });
    }
    const employees = await pool.query(
      `SELECT id, email, role FROM users WHERE company_id = $1 ORDER BY email ASC`,
      [req.companyId]
    );
    const entries = await pool.query(
      `SELECT ${entrySelect("e")}
         FROM time_clock_entries e
         JOIN users u ON u.id = e.user_id
        WHERE e.company_id = $1 AND e.start_at >= $2 AND e.start_at < $3 AND e.manual_status <> 'disapproved'
        ORDER BY u.email ASC, e.start_at DESC`,
      [req.companyId, start.toISOString(), end.toISOString()]
    );
    res.json({ employees: employees.rows, entries: entries.rows });
  } catch (e) { console.error(e); res.status(500).json({ error: "time_range_failed" }); }
});

app.post("/api/time-clock/entries", authRequired, async (req, res) => {
  try {
    const start = new Date(req.body.start_at);
    const end = req.body.end_at ? new Date(req.body.end_at) : null;
    if (Number.isNaN(start.getTime()) || !end || Number.isNaN(end.getTime()) || end <= start) {
      return res.status(400).json({ error: "invalid_dates" });
    }
    if (start > new Date() || end > new Date()) return res.status(400).json({ error: "future_time_not_allowed" });
    if (req.role !== "employer" && !canEmployeeChangeTimeEntry(start)) {
      return res.status(403).json({ error: "Cannot change previous week time cards at this Time" });
    }
    const { rows } = await pool.query(
      `INSERT INTO time_clock_entries(id, user_id, company_id, start_at, end_at, note, created_by, updated_by, manual_entry, manual_status)
       VALUES($1,$2,$3,$4,$5,$6,$2,$2,true,'approved')
       RETURNING *`,
      [randomUUID(), req.userId, req.companyId, start.toISOString(), end.toISOString(), req.body.note || "Manual employee entry"]
    );
    try {
      const entry = rows[0];
      const durationMinutes = Math.max(0, Math.floor((new Date(entry.end_at).getTime() - new Date(entry.start_at).getTime()) / 60000) - Math.floor(Number(entry.break_seconds || 0) / 60));
      await emitAutomationEvent({ companyId: req.companyId, eventType: "time_clock.manual_edit", subjectType: "time_entry", subjectId: entry.id, actorUserId: req.userId, source: "ios", dedupeKey: `time_clock.manual_edit:create:${entry.id}`, payload: { time_entry_id: entry.id, employee_id: entry.user_id, clock_in: entry.start_at, clock_out: entry.end_at, duration_minutes: durationMinutes, source: "ios" } });
    } catch (automationErr) {
      console.warn("[automations] manual time create hook failed", automationErr?.message || automationErr);
    }
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "time_entry_create_failed" }); }
});

app.patch("/api/time-clock/entries/:id", authRequired, async (req, res) => {
  try {
    const start = new Date(req.body.start_at);
    const end = req.body.end_at ? new Date(req.body.end_at) : null;
    if (Number.isNaN(start.getTime()) || (end && Number.isNaN(end.getTime()))) {
      return res.status(400).json({ error: "invalid_dates" });
    }
    if (start > new Date() || (end && end > new Date())) return res.status(400).json({ error: "future_time_not_allowed" });
    if (req.role !== "employer" && !canEmployeeChangeTimeEntry(start)) {
      return res.status(403).json({ error: "Cannot change previous week time cards at this Time" });
    }
    const ownerClause = req.role === "employer"
      ? `id = $1 AND company_id = $6`
      : `id = $1 AND user_id = $2`;
    const before = (await pool.query(`SELECT * FROM time_clock_entries WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId])).rows[0];
    const { rows } = await pool.query(
      `UPDATE time_clock_entries
          SET start_at = $3,
              end_at = $4,
              note = $5,
              updated_by = $2,
              manual_entry = CASE WHEN user_id = $2 THEN true ELSE manual_entry END,
              manual_status = CASE WHEN user_id = $2 THEN 'approved' ELSE manual_status END,
              updated_at = now()
        WHERE ${ownerClause}
        RETURNING *`,
      [req.params.id, req.userId, start.toISOString(), end ? end.toISOString() : null, req.body.note || null, req.companyId]
    );
    if (!rows.length) return res.status(404).json({ error: "entry_not_found" });
    try {
      const entry = rows[0];
      const changedFields = before ? ["start_at", "end_at", "note"].filter((field) => JSON.stringify(before[field] ?? null) !== JSON.stringify(entry[field] ?? null)).map((field) => ({ field, old_value: before[field] ?? null, new_value: entry[field] ?? null })) : [];
      if (changedFields.length) {
        await emitAutomationEvent({ companyId: req.companyId, eventType: "time_clock.shift_updated", subjectType: "time_entry", subjectId: entry.id, actorUserId: req.userId, source: "ios", payload: { time_entry_id: entry.id, employee_id: entry.user_id, changed_fields: changedFields } });
        await emitAutomationEvent({ companyId: req.companyId, eventType: "time_clock.manual_edit", subjectType: "time_entry", subjectId: entry.id, actorUserId: req.userId, source: "ios", payload: { time_entry_id: entry.id, employee_id: entry.user_id, changed_fields: changedFields } });
        if (!entry.end_at) await syncAutomationSchedulesForTimeEntry(req.companyId, entry); else await cancelAutomationSchedulesForSubject(req.companyId, "time_entry", entry.id);
      }
    } catch (automationErr) {
      console.warn("[automations] time update hook failed", automationErr?.message || automationErr);
    }
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "time_entry_update_failed" }); }
});

app.delete("/api/time-clock/entries/:id", authRequired, async (req, res) => {
  try {
    const existing = await pool.query(`SELECT start_at FROM time_clock_entries WHERE id = $1 AND user_id = $2`, [req.params.id, req.userId]);
    if (req.role !== "employer") {
      if (!existing.rowCount) return res.status(404).json({ error: "entry_not_found" });
      if (!canEmployeeChangeTimeEntry(existing.rows[0].start_at)) {
        return res.status(403).json({ error: "Cannot change previous week time cards at this Time" });
      }
    }
    const { rowCount } = await pool.query(
      req.role === "employer"
        ? `DELETE FROM time_clock_entries WHERE id = $1 AND company_id = $2`
        : `DELETE FROM time_clock_entries WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.role === "employer" ? req.companyId : req.userId]
    );
    if (!rowCount) return res.status(404).json({ error: "entry_not_found" });
    try {
      await cancelAutomationSchedulesForSubject(req.companyId, "time_entry", req.params.id);
      await emitAutomationEvent({ companyId: req.companyId, eventType: "time_clock.shift_updated", subjectType: "time_entry", subjectId: req.params.id, actorUserId: req.userId, source: "ios", payload: { time_entry_id: req.params.id, deleted: true } });
    } catch (automationErr) {
      console.warn("[automations] time delete hook failed", automationErr?.message || automationErr);
    }
    res.status(204).end();
  } catch (e) { console.error(e); res.status(500).json({ error: "time_entry_delete_failed" }); }
});

app.get("/api/time-clock/manual-entries", authRequired, requireEmployer, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT ${entrySelect("e")}
         FROM time_clock_entries e
         JOIN users u ON u.id = e.user_id
        WHERE e.company_id = $1 AND e.manual_entry = true
        ORDER BY e.updated_at DESC
        LIMIT 200`,
      [req.companyId]
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "manual_entries_failed" }); }
});

app.post("/api/time-clock/manual-entries/:id/:status", authRequired, requireEmployer, async (req, res) => {
  try {
    const status = req.params.status === "disapproved" ? "disapproved" : "approved";
    const { rows } = await pool.query(
      `UPDATE time_clock_entries
          SET manual_status = $3, updated_by = $2, updated_at = now()
        WHERE id = $1 AND company_id = $4 AND manual_entry = true
        RETURNING *`,
      [req.params.id, req.userId, status, req.companyId]
    );
    if (!rows.length) return res.status(404).json({ error: "entry_not_found" });
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "manual_entry_status_failed" }); }
});

function companyOrUserContactWhere(req, alias = "") {
  const p = alias ? `${alias}.` : "";
  return req.companyId
    ? { sql: `${p}company_id = $1`, values: [req.companyId] }
    : { sql: `${p}user_id = $1`, values: [req.userId] };
}

function contactTagsArray(value) {
  if (Array.isArray(value)) return value.flatMap(contactTagsArray);
  if (value == null) return [];
  return String(value).split(",").map((t) => t.trim()).filter(Boolean);
}

function contactChangedFields(before, after, fields) {
  return fields
    .map((field) => ({ field, old_value: before?.[field] ?? null, new_value: after?.[field] ?? null }))
    .filter((item) => JSON.stringify(item.old_value) !== JSON.stringify(item.new_value));
}

function contactFieldEventType(field) {
  if (["name", "phone", "email", "address", "job_type", "source"].includes(field)) return `contact.${field}_changed`;
  if (field === "value_cents") return "contact.value_changed";
  if (["u1", "u2", "u3", "u4", "u5"].includes(field)) return `contact.${field}_changed`;
  if (field === "lat" || field === "lng") return "contact.location_changed";
  return null;
}

async function emitContactUpdateEvents({ companyId, contactId, actorUserId, source, changedFields, extra = {} }) {
  if (!companyId || !changedFields.length) return;
  const base = { contact_id: contactId, changed_fields: changedFields, ...extra };
  await emitAutomationEvent({ companyId, eventType: "contact.updated", subjectType: "contact", subjectId: contactId, actorUserId, source, payload: base });
  await emitAutomationEvent({ companyId, eventType: "contact.field_changed", subjectType: "contact", subjectId: contactId, actorUserId, source, payload: base });
  for (const change of changedFields) {
    const eventType = contactFieldEventType(change.field);
    if (eventType) await emitAutomationEvent({ companyId, eventType, subjectType: "contact", subjectId: contactId, actorUserId, source, payload: { ...base, changed_fields: [change], field: change.field, old_value: change.old_value, new_value: change.new_value } });
  }
}

async function emitContactTagEvents({ companyId, contactId, actorUserId, source, previousTags, nextTags, extra = {} }) {
  if (!companyId) return;
  const prevLower = previousTags.map((t) => t.toLowerCase());
  const nextLower = nextTags.map((t) => t.toLowerCase());
  const added = nextTags.filter((t) => !prevLower.includes(t.toLowerCase()));
  const removed = previousTags.filter((t) => !nextLower.includes(t.toLowerCase()));
  const payload = { contact_id: contactId, tags: nextTags, added_tags: added, removed_tags: removed, ...extra };
  if (added.length) await emitAutomationEvent({ companyId, eventType: "contact.tag_added", subjectType: "contact", subjectId: contactId, actorUserId, source, payload });
  if (removed.length) await emitAutomationEvent({ companyId, eventType: "contact.tag_removed", subjectType: "contact", subjectId: contactId, actorUserId, source, payload });
  if (added.length || removed.length) await emitAutomationEvent({ companyId, eventType: "contact.tags_changed", subjectType: "contact", subjectId: contactId, actorUserId, source, payload });
}

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function rowChanges(before, after, fields) {
  return fields
    .map((field) => ({ field, old_value: before?.[field] ?? null, new_value: after?.[field] ?? null }))
    .filter((item) => JSON.stringify(item.old_value) !== JSON.stringify(item.new_value));
}

async function emitJobRouteEvents(companyId, actorUserId, before, after, source = "schedule.api") {
  if (!companyId || !after?.id) return;
  const base = { job_id: after.id, contact_id: after.contact_id || null, title: after.title, start: after.start || after.start_at, end: after.end || after.end_at };
  if (!before) {
    await emitAutomationEvent({ companyId, eventType: "job.created", subjectType: "job", subjectId: after.id, actorUserId, source, dedupeKey: `job.created:${after.id}`, payload: base });
    await emitAutomationEvent({ companyId, eventType: "job.scheduled", subjectType: "job", subjectId: after.id, actorUserId, source, dedupeKey: `job.scheduled:${after.id}:${base.start}:${base.end}`, payload: base });
    await emitAutomationEvent({ companyId, eventType: "job.created_manually", subjectType: "job", subjectId: after.id, actorUserId, source, dedupeKey: `job.created_manually:${after.id}`, payload: base });
    if (after.contact_id) {
      const count = (await pool.query(`SELECT COUNT(*)::int AS count FROM schedule_events WHERE company_id = $1 AND contact_id = $2`, [companyId, after.contact_id])).rows[0]?.count || 0;
      await emitAutomationEvent({ companyId, eventType: Number(count) <= 1 ? "job.first_job_for_contact" : "job.repeat_job_for_contact", subjectType: "job", subjectId: after.id, actorUserId, source, payload: { ...base, job_count_for_contact: Number(count) } });
    }
    await emitJobAssignmentRouteEvents(companyId, actorUserId, after.id, "worker", [], safeArray(after.worker_user_ids), base, source);
    await emitJobAssignmentRouteEvents(companyId, actorUserId, after.id, "salesperson", [], safeArray(after.sales_user_ids), base, source);
    return;
  }
  const changed = rowChanges(before, after, ["title", "start_at", "end_at", "color", "notes", "contact_id", "price_cents", "material_cost_cents", "service_items", "worker_user_ids", "sales_user_ids", "finished_at"]);
  if (!changed.length) return;
  await emitAutomationEvent({ companyId, eventType: "job.updated", subjectType: "job", subjectId: after.id, actorUserId, source, payload: { ...base, changed_fields: changed } });
  await emitAutomationEvent({ companyId, eventType: "job.field_changed", subjectType: "job", subjectId: after.id, actorUserId, source, payload: { ...base, changed_fields: changed } });
  if (changed.some((c) => c.field === "start_at" || c.field === "end_at")) {
    await emitAutomationEvent({ companyId, eventType: "job.rescheduled", subjectType: "job", subjectId: after.id, actorUserId, source, payload: { ...base, old_start: before.start_at, new_start: after.start_at, old_end: before.end_at, new_end: after.end_at } });
    await emitAutomationEvent({ companyId, eventType: "job.date_changed", subjectType: "job", subjectId: after.id, actorUserId, source, payload: base });
  }
  for (const change of changed) {
    const map = { start_at: "job.start_changed", end_at: "job.end_changed", price_cents: "job.price_changed", material_cost_cents: "job.material_cost_changed", color: "job.color_changed", contact_id: "job.contact_changed" };
    if (map[change.field]) await emitAutomationEvent({ companyId, eventType: map[change.field], subjectType: "job", subjectId: after.id, actorUserId, source, payload: { ...base, changed_fields: [change] } });
  }
  await emitJobServiceRouteEvents(companyId, actorUserId, after.id, before, after, base, source);
  await emitJobAssignmentRouteEvents(companyId, actorUserId, after.id, "worker", safeArray(before.worker_user_ids), safeArray(after.worker_user_ids), base, source);
  await emitJobAssignmentRouteEvents(companyId, actorUserId, after.id, "salesperson", safeArray(before.sales_user_ids), safeArray(after.sales_user_ids), base, source);
  if (!before.finished_at && after.finished_at) await emitAutomationEvent({ companyId, eventType: "job.completed", subjectType: "job", subjectId: after.id, actorUserId, source, dedupeKey: `job.completed:${after.id}:${after.finished_at}`, payload: { ...base, finished_at: after.finished_at } });
  if (before.finished_at && !after.finished_at) await emitAutomationEvent({ companyId, eventType: "job.reopened", subjectType: "job", subjectId: after.id, actorUserId, source, payload: base });
}

async function emitJobAssignmentRouteEvents(companyId, actorUserId, jobId, kind, beforeIds, afterIds, base, source) {
  const added = afterIds.filter((id) => !beforeIds.includes(id));
  const removed = beforeIds.filter((id) => !afterIds.includes(id));
  const prefix = kind === "worker" ? "worker" : "salesperson";
  if (added.length) await emitAutomationEvent({ companyId, eventType: `job.${prefix}_assigned`, subjectType: "job", subjectId: jobId, actorUserId, source, payload: { ...base, added } });
  if (removed.length) await emitAutomationEvent({ companyId, eventType: `job.${prefix}_removed`, subjectType: "job", subjectId: jobId, actorUserId, source, payload: { ...base, removed } });
  if (added.length || removed.length) await emitAutomationEvent({ companyId, eventType: `job.${prefix === "worker" ? "workers" : "salespeople"}_changed`, subjectType: "job", subjectId: jobId, actorUserId, source, payload: { ...base, added, removed } });
}

async function emitJobServiceRouteEvents(companyId, actorUserId, jobId, before, after, base, source) {
  const oldNames = safeArray(before.service_items || before.services).map((s) => String(s.name || s).toLowerCase());
  const newItems = safeArray(after.service_items || after.services);
  const newNames = newItems.map((s) => String(s.name || s).toLowerCase());
  const added = newItems.filter((s) => !oldNames.includes(String(s.name || s).toLowerCase()));
  const removed = safeArray(before.service_items || before.services).filter((s) => !newNames.includes(String(s.name || s).toLowerCase()));
  if (added.length) await emitAutomationEvent({ companyId, eventType: "job.service_added", subjectType: "job", subjectId: jobId, actorUserId, source, payload: { ...base, services: added } });
  if (removed.length) await emitAutomationEvent({ companyId, eventType: "job.service_removed", subjectType: "job", subjectId: jobId, actorUserId, source, payload: { ...base, services: removed } });
  if (added.length || removed.length) await emitAutomationEvent({ companyId, eventType: "job.services_changed", subjectType: "job", subjectId: jobId, actorUserId, source, payload: { ...base, added_services: added, removed_services: removed } });
}

// ---------- contacts (AUTH REQUIRED + COMPANY-SCOPED) ----------
app.get("/api/contacts", authRequired, async (req, res) => {
  const q = (req.query.q || "").toString().trim();
  try {
    const scope = companyOrUserContactWhere(req);
    let rows;
    if (q) {
      rows = (
        await pool.query(
          `
          SELECT * FROM contacts
          WHERE ${scope.sql}
            AND (name ILIKE $2 OR COALESCE(phone,'') ILIKE $2 OR COALESCE(email,'') ILIKE $2
                 OR COALESCE(address,'') ILIKE $2 OR COALESCE(job_type,'') ILIKE $2
                 OR COALESCE(u1,'') ILIKE $2 OR COALESCE(u2,'') ILIKE $2
                 OR COALESCE(u3,'') ILIKE $2 OR COALESCE(u4,'') ILIKE $2
                 OR COALESCE(u5,'') ILIKE $2)
          ORDER BY updated_at DESC
        `,
          [...scope.values, `%${q}%`]
        )
      ).rows;
    } else {
      rows = (
        await pool.query(
          `SELECT * FROM contacts WHERE ${scope.sql} ORDER BY updated_at DESC LIMIT 200`,
          scope.values
        )
      ).rows;
    }
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "failed_list" });
  }
});

app.get("/api/contacts/:id", authRequired, async (req, res) => {
  try {
    const scope = companyOrUserContactWhere(req);
    const { rows } = await pool.query(
      `SELECT * FROM contacts WHERE id = $1 AND ${scope.sql.replace("$1", "$2")}`,
      [req.params.id, ...scope.values]
    );
    if (!rows.length) return res.status(404).json({ error: "not_found" });
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "failed_get" });
  }
});

app.post("/api/contacts", authRequired, async (req, res) => {
  const {
    name, phone, email, address,
    value_cents, lat, lng, tags, job_type,
    u1, u2, u3, u4, u5, lead_info, source
  } = req.body || {};
  if (!name) return res.status(400).json({ error: "name_required" });

  const id = randomUUID();
  try {
    const r = await pool.query(
      `
      INSERT INTO contacts (
        id, user_id, company_id, name, phone, email, address, value_cents, lat, lng, tags, job_type, u1, u2, u3, u4, u5, lead_info, source
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
      ) RETURNING *;
      `,
      [
        id, req.userId, req.companyId, name || "", phone || "", email || "", address || "",
        Number.isFinite(Number(value_cents)) ? Number(value_cents) : null,
        lat ?? null, lng ?? null, tags || "", job_type || "",
        u1 || "", u2 || "", u3 || "", u4 || "", u5 || "",
        Array.isArray(lead_info) ? JSON.stringify(lead_info) : null,
        source || "manual"
      ]
    );
    if (req.companyId) {
      const origin = source || "manual";
      await emitAutomationEvent({
        companyId: req.companyId,
        eventType: "contact.created",
        subjectType: "contact",
        subjectId: r.rows[0].id,
        actorUserId: req.userId,
        source: "contacts.api",
        dedupeKey: `contact.created:${r.rows[0].id}`,
        payload: { contact_id: r.rows[0].id, name: r.rows[0].name, source: origin }
      });
      const sourceEvent = origin === "csv" ? "contact.imported_csv"
        : origin === "phone" ? "contact.imported_phone"
          : origin === "map" ? "contact.converted_from_map_pin"
            : origin === "schedule" ? "contact.created_from_schedule"
              : "contact.created_manually";
      await emitAutomationEvent({
        companyId: req.companyId,
        eventType: sourceEvent,
        subjectType: "contact",
        subjectId: r.rows[0].id,
        actorUserId: req.userId,
        source: `contacts.${origin}`,
        dedupeKey: `${sourceEvent}:${r.rows[0].id}`,
        payload: { contact_id: r.rows[0].id, name: r.rows[0].name, source: origin }
      });
    }
    res.status(201).json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "failed_create" });
  }
});

app.put("/api/contacts/:id", authRequired, async (req, res) => {
  const {
    name, phone, email, address,
    value_cents, lat, lng, tags, job_type,
    u1, u2, u3, u4, u5, lead_info, source
  } = req.body || {};
  try {
    const scope = companyOrUserContactWhere(req);
    const before = (await pool.query(
      `SELECT * FROM contacts WHERE id = $1 AND ${scope.sql.replace("$1", "$2")}`,
      [req.params.id, ...scope.values]
    )).rows[0];
    const body = req.body || {};
    const has = (key) => Object.prototype.hasOwnProperty.call(body, key);
    const updates = [];
    const values = [req.params.id];
    const addUpdate = (column, value, cast = "") => {
      values.push(value);
      updates.push(`${column} = $${values.length}${cast}`);
    };
    if (has("name")) addUpdate("name", name || "");
    if (has("phone")) addUpdate("phone", phone || null);
    if (has("email")) addUpdate("email", email || null);
    if (has("address")) addUpdate("address", address || null);
    if (has("value_cents")) addUpdate("value_cents", Number.isFinite(Number(value_cents)) ? Number(value_cents) : null);
    if (has("lat")) addUpdate("lat", lat == null ? null : Number(lat));
    if (has("lng")) addUpdate("lng", lng == null ? null : Number(lng));
    if (has("address") && !address && !has("lat")) addUpdate("lat", null);
    if (has("address") && !address && !has("lng")) addUpdate("lng", null);
    if (has("tags")) addUpdate("tags", Array.isArray(tags) ? tags.join(",") : (tags || null));
    if (has("job_type")) addUpdate("job_type", job_type || null);
    if (has("u1")) addUpdate("u1", u1 || null);
    if (has("u2")) addUpdate("u2", u2 || null);
    if (has("u3")) addUpdate("u3", u3 || null);
    if (has("u4")) addUpdate("u4", u4 || null);
    if (has("u5")) addUpdate("u5", u5 || null);
    if (has("lead_info")) addUpdate("lead_info", Array.isArray(lead_info) ? JSON.stringify(lead_info) : null, "::jsonb");
    if (has("source")) addUpdate("source", source || null);
    if (!updates.length) return res.json(before);
    addUpdate("updated_at", new Date());
    values.push(...scope.values);
    const scopeSQL = scope.sql.replace("$1", `$${values.length - scope.values.length + 1}`);
    const r = await pool.query(
      `UPDATE contacts SET ${updates.join(", ")}
        WHERE id = $1 AND ${scopeSQL}
        RETURNING *;`,
      values
    );
    if (!r.rowCount) return res.status(404).json({ error: "not_found" });
    if (req.companyId) {
      const fields = ["name", "phone", "email", "address", "value_cents", "lat", "lng", "job_type", "u1", "u2", "u3", "u4", "u5", "source"].filter((key) => has(key));
      const changed = contactChangedFields(before, r.rows[0], fields);
      await emitContactUpdateEvents({ companyId: req.companyId, contactId: r.rows[0].id, actorUserId: req.userId, source: "contacts.api", changedFields: changed });
      if (Object.prototype.hasOwnProperty.call(req.body || {}, "tags")) {
        await emitContactTagEvents({ companyId: req.companyId, contactId: r.rows[0].id, actorUserId: req.userId, source: "contacts.api", previousTags: contactTagsArray(before?.tags), nextTags: contactTagsArray(r.rows[0].tags) });
      }
    }
    res.json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "failed_update" });
  }
});

function routeScope(req, alias = "r") {
  if (req.companyId) return { sql: `${alias}.company_id = $1`, values: [req.companyId] };
  return { sql: `${alias}.user_id = $1`, values: [req.userId] };
}

function mapRouteRow(row, stops = []) {
  return {
    id: row.id,
    name: row.name,
    status: row.status,
    start_label: row.start_label,
    start_latitude: row.start_latitude,
    start_longitude: row.start_longitude,
    start_mode: row.start_mode || "current_location",
    ending_behavior: row.ending_behavior,
    stop_count: Number(row.stop_count || stops.length || 0),
    distance_meters: row.distance_meters,
    travel_time_seconds: row.travel_time_seconds,
    created_at: row.created_at,
    updated_at: row.updated_at,
    stops
  };
}

function mapRouteStopRow(row) {
  return {
    id: row.id,
    contact_id: row.contact_id,
    stop_order: Number(row.stop_order || 0),
    name: row.name_snapshot,
    address: row.address_snapshot,
    latitude: row.latitude,
    longitude: row.longitude,
    status: row.status,
    batch_number: row.batch_number == null ? null : Number(row.batch_number),
    source_type: row.source_type || (row.contact_id ? "contact" : "custom")
  };
}

async function fetchRouteWithStops(req, id) {
  const scope = routeScope(req, "r");
  const route = await pool.query(
    `SELECT r.*, COUNT(s.id)::int AS stop_count
       FROM crm_routes r
       LEFT JOIN crm_route_stops s ON s.route_id = r.id
      WHERE r.id = $2 AND ${scope.sql}
      GROUP BY r.id`,
    [...scope.values, id]
  );
  if (!route.rows.length) return null;
  const stops = (await pool.query(
    `SELECT * FROM crm_route_stops WHERE route_id = $1 ORDER BY stop_order ASC`,
    [id]
  )).rows.map(mapRouteStopRow);
  return mapRouteRow(route.rows[0], stops);
}

async function replaceRouteStops(client, routeId, companyId, stops) {
  await client.query(`DELETE FROM crm_route_stops WHERE route_id = $1`, [routeId]);
  const cleanStops = Array.isArray(stops) ? stops : [];
  for (const raw of cleanStops) {
    const order = Number(raw.stop_order);
    const name = (raw.name_snapshot || raw.name || "").toString().trim();
    const address = (raw.address_snapshot || raw.address || "").toString().trim();
    if (!Number.isFinite(order) || order < 1 || !name) continue;
    await client.query(
      `INSERT INTO crm_route_stops(
         id, route_id, company_id, contact_id, stop_order, name_snapshot, address_snapshot,
         latitude, longitude, status, batch_number, source_type
       )
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [
        randomUUID(),
        routeId,
        companyId || null,
        raw.contact_id || null,
        order,
        name,
        address,
        Number.isFinite(Number(raw.latitude)) ? Number(raw.latitude) : null,
        Number.isFinite(Number(raw.longitude)) ? Number(raw.longitude) : null,
        ["not_visited", "arrived", "completed", "skipped"].includes(raw.status) ? raw.status : "not_visited",
        Number.isFinite(Number(raw.batch_number)) ? Number(raw.batch_number) : null,
        ["contact", "custom"].includes(raw.source_type) ? raw.source_type : (raw.contact_id ? "contact" : "custom")
      ]
    );
  }
}

// ---------- routes (AUTH REQUIRED + COMPANY-SCOPED) ----------
app.get("/api/routes", authRequired, async (req, res) => {
  try {
    const scope = routeScope(req, "r");
    const { rows } = await pool.query(
      `SELECT r.*, COUNT(s.id)::int AS stop_count
         FROM crm_routes r
         LEFT JOIN crm_route_stops s ON s.route_id = r.id
        WHERE ${scope.sql}
        GROUP BY r.id
        ORDER BY r.updated_at DESC
        LIMIT 50`,
      scope.values
    );
    res.json(rows.map((row) => mapRouteRow(row, [])));
  } catch (e) {
    console.error("[routes/list]", e);
    res.status(500).json({ error: "routes_failed", message: "Couldn't load routes." });
  }
});

app.get("/api/routes/:id", authRequired, async (req, res) => {
  try {
    const route = await fetchRouteWithStops(req, req.params.id);
    if (!route) return res.status(404).json({ error: "route_not_found" });
    res.json(route);
  } catch (e) {
    console.error("[routes/get]", e);
    res.status(500).json({ error: "route_failed", message: "Couldn't load this route." });
  }
});

app.post("/api/routes", authRequired, async (req, res) => {
  const name = (req.body.name || "").toString().trim() || `Route ${new Date().toISOString().slice(0, 10)}`;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const id = randomUUID();
    await client.query(
      `INSERT INTO crm_routes(
         id, company_id, user_id, name, status, start_label, start_latitude, start_longitude,
         start_mode, ending_behavior, distance_meters, travel_time_seconds
       )
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [
        id,
        req.companyId || null,
        req.userId,
        name,
        ["active", "saved", "completed", "archived"].includes(req.body.status) ? req.body.status : "saved",
        req.body.start_label || null,
        Number.isFinite(Number(req.body.start_latitude)) ? Number(req.body.start_latitude) : null,
        Number.isFinite(Number(req.body.start_longitude)) ? Number(req.body.start_longitude) : null,
        ["current_location", "custom_address"].includes(req.body.start_mode) ? req.body.start_mode : "current_location",
        ["finish_at_final_stop", "return_to_start"].includes(req.body.ending_behavior) ? req.body.ending_behavior : "finish_at_final_stop",
        Number.isFinite(Number(req.body.distance_meters)) ? Number(req.body.distance_meters) : null,
        Number.isFinite(Number(req.body.travel_time_seconds)) ? Number(req.body.travel_time_seconds) : null
      ]
    );
    await replaceRouteStops(client, id, req.companyId, req.body.stops);
    await client.query("COMMIT");
    res.status(201).json(await fetchRouteWithStops(req, id));
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("[routes/create]", e);
    res.status(500).json({ error: "route_create_failed", message: "Couldn't save route." });
  } finally {
    client.release();
  }
});

app.put("/api/routes/:id", authRequired, async (req, res) => {
  const scope = routeScope(req, "r");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const existing = await client.query(`SELECT id FROM crm_routes r WHERE r.id = $2 AND ${scope.sql} FOR UPDATE`, [...scope.values, req.params.id]);
    if (!existing.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "route_not_found" });
    }
    await client.query(
      `UPDATE crm_routes
          SET name = COALESCE($2, name),
              status = COALESCE($3, status),
              start_label = $4,
              start_latitude = $5,
              start_longitude = $6,
              start_mode = COALESCE($7, start_mode),
              ending_behavior = COALESCE($8, ending_behavior),
              distance_meters = $9,
              travel_time_seconds = $10,
              updated_at = now()
        WHERE id = $1`,
      [
        req.params.id,
        (req.body.name || "").toString().trim() || null,
        ["active", "saved", "completed", "archived"].includes(req.body.status) ? req.body.status : null,
        req.body.start_label || null,
        Number.isFinite(Number(req.body.start_latitude)) ? Number(req.body.start_latitude) : null,
        Number.isFinite(Number(req.body.start_longitude)) ? Number(req.body.start_longitude) : null,
        ["current_location", "custom_address"].includes(req.body.start_mode) ? req.body.start_mode : null,
        ["finish_at_final_stop", "return_to_start"].includes(req.body.ending_behavior) ? req.body.ending_behavior : null,
        Number.isFinite(Number(req.body.distance_meters)) ? Number(req.body.distance_meters) : null,
        Number.isFinite(Number(req.body.travel_time_seconds)) ? Number(req.body.travel_time_seconds) : null
      ]
    );
    await replaceRouteStops(client, req.params.id, req.companyId, req.body.stops);
    await client.query("COMMIT");
    res.json(await fetchRouteWithStops(req, req.params.id));
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("[routes/update]", e);
    res.status(500).json({ error: "route_update_failed", message: "Couldn't save route." });
  } finally {
    client.release();
  }
});

app.patch("/api/routes/:routeId/stops/:stopId", authRequired, async (req, res) => {
  try {
    const scope = routeScope(req, "r");
    const allowed = await pool.query(`SELECT r.id FROM crm_routes r WHERE r.id = $2 AND ${scope.sql}`, [...scope.values, req.params.routeId]);
    if (!allowed.rows.length) return res.status(404).json({ error: "route_not_found" });
    const status = ["not_visited", "arrived", "completed", "skipped"].includes(req.body.status) ? req.body.status : null;
    const order = Number.isFinite(Number(req.body.stop_order)) ? Number(req.body.stop_order) : null;
    const { rows } = await pool.query(
      `UPDATE crm_route_stops
          SET status = COALESCE($3, status),
              stop_order = COALESCE($4, stop_order),
              updated_at = now()
        WHERE id = $1 AND route_id = $2
        RETURNING *`,
      [req.params.stopId, req.params.routeId, status, order]
    );
    if (!rows.length) return res.status(404).json({ error: "route_stop_not_found" });
    await pool.query(`UPDATE crm_routes SET updated_at = now() WHERE id = $1`, [req.params.routeId]);
    res.json(mapRouteStopRow(rows[0]));
  } catch (e) {
    console.error("[routes/stop/update]", e);
    res.status(500).json({ error: "route_stop_update_failed", message: "Couldn't update stop." });
  }
});

app.delete("/api/contacts/:id", authRequired, async (req, res) => {
  try {
    if (!req.permissions.canDeleteContacts) {
      return res.status(403).json({ error: "permission_denied" });
    }
    const scope = companyOrUserContactWhere(req);
    const before = (await pool.query(
      `SELECT id, name, tags FROM contacts WHERE id = $1 AND ${scope.sql.replace("$1", "$2")}`,
      [req.params.id, ...scope.values]
    )).rows[0];
    await pool.query(
      `UPDATE schedule_events
       SET contact_id = NULL, updated_at = now()
       WHERE contact_id = $1 AND ${req.companyId ? "company_id = $2" : "user_id = $2"}`,
      [req.params.id, req.companyId || req.userId]
    );
    await pool.query(
      `DELETE FROM opportunities WHERE contact_id = $1 AND user_id IN (SELECT id FROM users WHERE ${req.companyId ? "company_id = $2" : "id = $2"})`,
      [req.params.id, req.companyId || req.userId]
    );
    const r = await pool.query(
      `DELETE FROM contacts WHERE id = $1 AND ${scope.sql.replace("$1", "$2")}`,
      [req.params.id, ...scope.values]
    );
    if (r.rowCount && req.companyId) {
      await emitAutomationEvent({
        companyId: req.companyId,
        eventType: "contact.deleted",
        subjectType: "contact",
        subjectId: req.params.id,
        actorUserId: req.userId,
        source: "contacts.api",
        dedupeKey: `contact.deleted:${req.params.id}`,
        payload: { contact_id: req.params.id, name: before?.name || null, tags: contactTagsArray(before?.tags) }
      });
    }
    res.status(204).end();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "failed_delete" });
  }
});


// ---------- generic upsert helpers ----------
function toBool(v, fallback = false) {
  if (v === undefined || v === null) return fallback;
  return !!v;
}

// ---------- INTEGRATIONS: Zapier / Meta Lead webhook ----------

// Shape returned by all integration endpoints. Never includes internals.
function integrationPayload(row) {
  return {
    token: row.token,
    auto_stage_id: row.auto_stage_id,
    auto_assign_stage_enabled: !!row.auto_assign_stage_enabled,
    notifications_enabled: !!row.notifications_enabled,
    notification_fields: Array.isArray(row.notification_fields) ? row.notification_fields : (row.notification_fields || null),
    notification_categories: normalizePushCategories(row.notification_categories)
  };
}

// Valid field keys the user can pick to include in the notification body.
const NOTIFICATION_FIELD_KEYS = new Set([
  "name", "phone", "email", "address", "form", "source", "qa"
]);
function sanitizeNotificationFields(input) {
  if (!Array.isArray(input)) return null;
  const cleaned = input
    .filter(k => typeof k === "string" && NOTIFICATION_FIELD_KEYS.has(k));
  return cleaned;
}

const PUSH_CATEGORY_KEYS = new Set(Object.keys(DEFAULT_PUSH_CATEGORIES));
function sanitizePushCategories(input) {
  const cleaned = normalizePushCategories(input);
  if (input && typeof input === "object" && !Array.isArray(input)) {
    for (const [key, value] of Object.entries(input)) {
      if (PUSH_CATEGORY_KEYS.has(key)) cleaned[key] = value !== false;
    }
  }
  return cleaned;
}

// GET current token (create if missing)
app.get("/api/integrations/zapier/token", authRequired, async (req, res) => {
  try {
    let { rows } = await pool.query(
      `SELECT token, auto_stage_id, auto_assign_stage_enabled, notifications_enabled, notification_fields, notification_categories
       FROM zapier_tokens WHERE user_id = $1`,
      [req.userId]
    );
    if (!rows.length) {
      const token = randomBytes(24).toString("hex");
      await pool.query(
        `INSERT INTO zapier_tokens (user_id, token, auto_assign_stage_enabled) VALUES ($1, $2, false)`,
        [req.userId, token]
      );
      rows = [{ token, auto_stage_id: null, auto_assign_stage_enabled: false, notifications_enabled: false, notification_fields: null, notification_categories: {} }];
    }
    // Self-heal: if the saved stage no longer belongs to the account, quietly clear it.
    const row = rows[0];
    if (row.auto_stage_id) {
      const check = await pool.query(
        `SELECT 1 FROM stages
         WHERE id = $1 AND (user_id = $2 OR (company_id IS NOT NULL AND company_id = $3))
         LIMIT 1`,
        [row.auto_stage_id, req.userId, req.companyId || null]
      );
      if (!check.rowCount) {
        await pool.query(
          `UPDATE zapier_tokens SET auto_stage_id = NULL, auto_assign_stage_enabled = false WHERE user_id = $1`,
          [req.userId]
        );
        row.auto_stage_id = null;
        row.auto_assign_stage_enabled = false;
      }
    }
    res.json(integrationPayload(row));
  } catch (e) {
    console.error("[integrations] get token failed:", e && e.message ? e.message : e);
    res.status(500).json({ error: "failed_get_token", message: "Could not load your integration configuration." });
  }
});

// Rotate token
app.post("/api/integrations/zapier/token/rotate", authRequired, async (req, res) => {
  try {
    const token = randomBytes(24).toString("hex");
    const { rows } = await pool.query(
      `INSERT INTO zapier_tokens (user_id, token)
       VALUES ($1, $2)
       ON CONFLICT (user_id) DO UPDATE SET token = EXCLUDED.token, created_at = now()
       RETURNING token, auto_stage_id, auto_assign_stage_enabled, notifications_enabled, notification_fields, notification_categories`,
      [req.userId, token]
    );
    res.json(integrationPayload(rows[0]));
  } catch (e) {
    console.error("[integrations] rotate failed:", e && e.message ? e.message : e);
    res.status(500).json({ error: "failed_rotate_token", message: "Could not rotate the webhook token." });
  }
});

// Set stage to auto-assign new leads into.
// This endpoint is intentionally TOLERANT: it never returns 4xx for a stale/missing
// stage — it silently clears the invalid ref instead. This lets the app self-heal
// during migrations, deletes, and cross-account edge cases.
app.put("/api/integrations/zapier/auto-stage", authRequired, async (req, res) => {
  const { stage_id } = req.body || {};
  try {
    let effectiveStageId = null;
    let warning = null;
    if (stage_id) {
      const check = await pool.query(
        `SELECT 1 FROM stages
         WHERE id = $1
           AND (user_id = $2 OR (company_id IS NOT NULL AND company_id = $3))
         LIMIT 1`,
        [stage_id, req.userId, req.companyId || null]
      );
      if (check.rowCount) {
        effectiveStageId = stage_id;
      } else {
        warning = "stage_not_in_scope_cleared";
      }
    }
    const { rows } = await pool.query(
      `UPDATE zapier_tokens
         SET auto_stage_id = $2,
             auto_assign_stage_enabled = CASE WHEN $2::text IS NULL THEN false ELSE auto_assign_stage_enabled END
       WHERE user_id = $1
       RETURNING token, auto_stage_id, auto_assign_stage_enabled, notifications_enabled, notification_fields, notification_categories`,
      [req.userId, effectiveStageId]
    );
    if (!rows.length) return res.status(404).json({ error: "token_not_found", message: "No webhook is set up for this account yet." });
    const payload = integrationPayload(rows[0]);
    if (warning) payload.warning = warning;
    res.json(payload);
  } catch (e) {
    console.error("[integrations] set auto_stage failed:", e && e.message ? e.message : e);
    res.status(500).json({ error: "failed_set_auto_stage", message: "Could not save your stage selection." });
  }
});

// Toggle whether new imported leads are auto-assigned to a stage at all.
app.put("/api/integrations/zapier/auto-assign-enabled", authRequired, async (req, res) => {
  const enabled = !!(req.body && req.body.enabled);
  try {
    const { rows } = await pool.query(
      `UPDATE zapier_tokens
         SET auto_assign_stage_enabled = $2
       WHERE user_id = $1
       RETURNING token, auto_stage_id, auto_assign_stage_enabled, notifications_enabled, notification_fields, notification_categories`,
      [req.userId, enabled]
    );
    if (!rows.length) return res.status(404).json({ error: "token_not_found", message: "No webhook is set up for this account yet." });
    res.json(integrationPayload(rows[0]));
  } catch (e) {
    console.error("[integrations] set auto_assign_enabled failed:", e && e.message ? e.message : e);
    res.status(500).json({ error: "failed_set_toggle", message: "Could not save that setting." });
  }
});

// Push-notification preferences for new-lead alerts.
// Body: { enabled: bool, fields: [string], categories: object }
app.put("/api/integrations/zapier/notifications", authRequired, async (req, res) => {
  const enabled = !!(req.body && req.body.enabled);
  const fields = sanitizeNotificationFields(req.body && req.body.fields);
  const categories = sanitizePushCategories(req.body && req.body.categories);
  try {
    const { rows } = await pool.query(
      `UPDATE zapier_tokens
         SET notifications_enabled = $2,
             notification_fields = $3::jsonb,
             notification_categories = $4::jsonb
       WHERE user_id = $1
       RETURNING token, auto_stage_id, auto_assign_stage_enabled, notifications_enabled, notification_fields, notification_categories`,
      [req.userId, enabled, fields ? JSON.stringify(fields) : null, JSON.stringify(categories)]
    );
    if (!rows.length) return res.status(404).json({ error: "token_not_found", message: "No webhook is set up for this account yet." });
    res.json(integrationPayload(rows[0]));
  } catch (e) {
    console.error("[integrations] set notifications failed:", e && e.message ? e.message : e);
    res.status(500).json({ error: "failed_set_notifications", message: "Could not save your notification preferences." });
  }
});

// Register (or refresh) an iOS device token for the current user.
app.post("/api/integrations/device-token", authRequired, async (req, res) => {
  const raw = (req.body && req.body.token) || "";
  const token = typeof raw === "string" ? raw.trim() : "";
  const rawEnvironment = (req.body && req.body.environment) || "";
  const environment = rawEnvironment === "production" ? "production" : "sandbox";
  if (!token || token.length < 32 || token.length > 200) {
    return res.status(400).json({ error: "bad_token", message: "Missing or malformed device token." });
  }
  try {
    await pool.query(
      `INSERT INTO device_tokens (token, user_id, platform, environment, last_registration_error)
       VALUES ($1, $2, 'ios', $3, NULL)
       ON CONFLICT (token) DO UPDATE
         SET user_id = EXCLUDED.user_id,
             environment = EXCLUDED.environment,
             last_registration_error = NULL,
             updated_at = now()`,
      [token, req.userId, environment]
    );
    console.log("[device-token] registered", { userId: req.userId, environment });
    res.json({ ok: true });
  } catch (e) {
    console.error("[device-token] upsert failed:", e && e.message ? e.message : e);
    res.status(500).json({ error: "failed_upsert" });
  }
});

app.get("/api/integrations/push/diagnostics", authRequired, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT environment, updated_at, last_registration_error
         FROM device_tokens
        WHERE user_id = $1
        ORDER BY updated_at DESC
        LIMIT 5`,
      [req.userId]
    );
    const prefs = await pool.query(
      `SELECT notifications_enabled, notification_categories
         FROM zapier_tokens
        WHERE user_id = $1
        LIMIT 1`,
      [req.userId]
    );
    const prefRow = prefs.rows[0] || {};
    res.json({
      ok: true,
      apns_configured: Boolean(process.env.APNS_KEY_P8 && process.env.APNS_KEY_ID && process.env.APNS_TEAM_ID && process.env.APNS_BUNDLE_ID),
      bundle_id_configured: Boolean(process.env.APNS_BUNDLE_ID),
      registered_token_count: rows.length,
      environments: rows.map((row) => row.environment),
      last_registration_error: rows.find((row) => row.last_registration_error)?.last_registration_error || null,
      new_leads_enabled: !!prefRow.notifications_enabled,
      notification_categories: normalizePushCategories(prefRow.notification_categories)
    });
  } catch (e) {
    console.error("[push/diagnostics] failed:", { code: e?.code, message: e?.message });
    res.status(500).json({ error: "push_diagnostics_failed" });
  }
});

app.post("/api/integrations/push/test", authRequired, requireEmployer, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT token, COALESCE(environment, CASE WHEN $2::boolean THEN 'production' ELSE 'sandbox' END) AS environment
         FROM device_tokens
        WHERE user_id = $1`,
      [req.userId, process.env.APNS_PRODUCTION === "true"]
    );
    const result = await sendApnsPush(rows, {
      title: "WolfCRM test notification",
      body: "Normal push notifications are registered.",
      payload: { type: "push_test" },
      threadId: "push_test"
    });
    res.json({ ok: true, sent: result.sent || 0, failed: result.failed || 0, skipped: result.skipped || false, reason: result.reason || null });
  } catch (e) {
    console.error("[push/test] failed:", { code: e?.code, message: e?.message });
    res.status(500).json({ error: "push_test_failed" });
  }
});

// Remove a device token (called on logout or when notifications turned off).
app.delete("/api/integrations/device-token", authRequired, async (req, res) => {
  const raw = (req.body && req.body.token) || "";
  const token = typeof raw === "string" ? raw.trim() : "";
  if (!token) return res.status(400).json({ error: "bad_token" });
  try {
    await pool.query(`DELETE FROM device_tokens WHERE token = $1 AND user_id = $2`,
      [token, req.userId]);
    res.status(204).end();
  } catch (e) {
    console.error("[device-token] delete failed:", e && e.message ? e.message : e);
    res.status(500).json({ error: "failed_delete" });
  }
});

// GET pending notifications and mark them delivered.
// iOS polls this when the app becomes active and fires local notifications.
app.get("/api/integrations/zapier/pending-notifications", authRequired, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, title, body, contact_id, created_at
       FROM lead_notifications
       WHERE user_id = $1 AND delivered_at IS NULL
       ORDER BY created_at ASC
       LIMIT 25`,
      [req.userId]
    );
    if (rows.length) {
      const ids = rows.map(r => r.id);
      await pool.query(
        `UPDATE lead_notifications SET delivered_at = now() WHERE id = ANY($1::uuid[])`,
        [ids]
      );
    }
    res.json({ notifications: rows });
  } catch (e) {
    console.error("[notifications] pending fetch failed:", e && e.message ? e.message : e);
    res.status(500).json({ error: "failed_fetch_pending" });
  }
});

// One-shot backfill: re-processes every stored lead_import belonging to this
// caller and writes Lead Info onto any contact whose lead_info is empty/null.
// Idempotent — running it twice is safe.
app.post("/api/integrations/zapier/backfill-lead-info", authRequired, async (req, res) => {
  const force = !!(req.body && req.body.force);
  try {
    // Company-scoped when available (so any teammate can trigger the backfill
    // for the whole company), user-scoped otherwise.
    const scopeSQL = req.companyId
      ? `(li.company_id = $1 OR (li.company_id IS NULL AND li.user_id = $2))`
      : `li.user_id = $1`;
    const scopeVals = req.companyId ? [req.companyId, req.userId] : [req.userId];

    const { rows } = await pool.query(
      `SELECT li.id AS import_id, li.contact_id, li.raw_payload, li.submitted_at, c.lead_info, c.lead_submitted_at
       FROM lead_imports li
       JOIN contacts c ON c.id::text = li.contact_id
       WHERE ${scopeSQL}
       ORDER BY li.created_at ASC`,
      scopeVals
    );

    let updated = 0, skippedEmpty = 0, skippedAlreadyHas = 0, errored = 0;

    for (const row of rows) {
      const existing = row.lead_info;
      const alreadyHas = Array.isArray(existing) && existing.length > 0;
      const shouldRepairSubmittedAt = !row.lead_submitted_at && row.submitted_at;
      if (alreadyHas && !force) {
        if (shouldRepairSubmittedAt) {
          try {
            await pool.query(
              `UPDATE contacts
               SET lead_submitted_at = $1::timestamptz,
                   updated_at = now()
               WHERE id = $2 AND lead_submitted_at IS NULL`,
              [row.submitted_at, row.contact_id]
            );
            updated++;
          } catch (e) {
            console.error("[backfill] timestamp repair failed for", row.contact_id, e && e.message ? e.message : e);
            errored++;
          }
        }
        skippedAlreadyHas++;
        continue;
      }

      const questions = buildQuestionsFromPayload(row.raw_payload || {});
      const leadInfo = buildLeadInfoStrings(questions);
      if (leadInfo.length === 0) {
        if (shouldRepairSubmittedAt) {
          try {
            await pool.query(
              `UPDATE contacts
               SET lead_submitted_at = $1::timestamptz,
                   updated_at = now()
               WHERE id = $2 AND lead_submitted_at IS NULL`,
              [row.submitted_at, row.contact_id]
            );
            updated++;
          } catch (e) {
            console.error("[backfill] timestamp repair failed for", row.contact_id, e && e.message ? e.message : e);
            errored++;
          }
        }
        skippedEmpty++;
        continue;
      }

      try {
        await pool.query(
          `UPDATE contacts
           SET lead_info = $1::jsonb,
               lead_submitted_at = COALESCE(lead_submitted_at, $3::timestamptz),
               updated_at = now()
           WHERE id = $2`,
          [JSON.stringify(leadInfo), row.contact_id, row.submitted_at || null]
        );
        updated++;
      } catch (e) {
        console.error("[backfill] update failed for", row.contact_id, e && e.message ? e.message : e);
        errored++;
      }
    }

    console.log("[backfill] done", {
      userId: req.userId, companyId: req.companyId || "user-scope",
      scanned: rows.length, updated, skippedEmpty, skippedAlreadyHas, errored, force
    });

    res.json({
      success: true,
      scanned: rows.length,
      updated,
      skipped_empty: skippedEmpty,
      skipped_already_populated: skippedAlreadyHas,
      errored
    });
  } catch (e) {
    console.error("[backfill] failed:", e && e.message ? e.message : e);
    res.status(500).json({ success: false, error: "backfill_failed", message: "Could not run the backfill." });
  }
});

// ---------- STAGE REMINDERS ----------
app.get("/api/stage-reminders", authRequired, async (req, res) => {
  const includeArchived = String(req.query.includeArchived || "").toLowerCase() === "true";
  try {
    const { rows } = await pool.query(
      `SELECT id, contact_id, opportunity_id, remind_at, note, archived
       FROM stage_reminders
       WHERE user_id = $1 ${includeArchived ? "" : "AND archived = false"}
       ORDER BY remind_at ASC`,
      [req.userId]
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_list_reminders" }); }
});

app.post("/api/stage-reminders", authRequired, async (req, res) => {
  const { contact_id, opportunity_id, remind_at, note } = req.body || {};
  if (!contact_id || !remind_at) return res.status(400).json({ error: "missing_fields" });
  try {
    const { rows } = await pool.query(
      `INSERT INTO stage_reminders (user_id, contact_id, opportunity_id, remind_at, note)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, contact_id, opportunity_id, remind_at, note, archived`,
      [req.userId, contact_id, opportunity_id || null, remind_at, note || null]
    );
    if (req.companyId) {
      await emitAutomationEvent({
        companyId: req.companyId,
        eventType: "pipeline.reminder_created",
        subjectType: opportunity_id ? "opportunity" : "contact",
        subjectId: opportunity_id || contact_id,
        actorUserId: req.userId,
        source: "stage_reminders.api",
        dedupeKey: `pipeline.reminder_created:${rows[0].id}`,
        payload: { reminder_id: rows[0].id, contact_id, opportunity_id: opportunity_id || null, remind_at }
      });
    }
    res.status(201).json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_create_reminder" }); }
});

app.put("/api/stage-reminders/:id", authRequired, async (req, res) => {
  const { remind_at, note, archived } = req.body || {};
  try {
    const { rows } = await pool.query(
      `UPDATE stage_reminders SET
         remind_at = COALESCE($2, remind_at),
         note = COALESCE($3, note),
         archived = COALESCE($4, archived),
         updated_at = now()
       WHERE id = $1 AND user_id = $5
       RETURNING id, contact_id, opportunity_id, remind_at, note, archived`,
      [req.params.id, remind_at || null, note ?? null, typeof archived === "boolean" ? archived : null, req.userId]
    );
    if (!rows.length) return res.status(404).json({ error: "not_found" });
    if (req.companyId && archived === true) {
      await emitAutomationEvent({
        companyId: req.companyId,
        eventType: "pipeline.reminder_archived",
        subjectType: rows[0].opportunity_id ? "opportunity" : "contact",
        subjectId: rows[0].opportunity_id || rows[0].contact_id,
        actorUserId: req.userId,
        source: "stage_reminders.api",
        payload: { reminder_id: rows[0].id, contact_id: rows[0].contact_id, opportunity_id: rows[0].opportunity_id }
      });
    }
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_update_reminder" }); }
});

app.delete("/api/stage-reminders/:id", authRequired, async (req, res) => {
  try {
    await pool.query(`DELETE FROM stage_reminders WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.userId]);
    res.status(204).end();
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_delete_reminder" }); }
});

// ============================================================================
// Public webhook (no auth) — POST /webhooks/leads/:token
// ============================================================================
//
// PRIMARY GUARANTEE: contact creation is mandatory. Stage assignment is
// optional and MUST NEVER block, undo, or roll back the contact/lead_info.
//
// Processing steps (in strict order):
//   1) Validate the webhook token → resolve user + company
//   2) Parse payload (structured "questions" shape OR raw Facebook Lead Ads
//      field_data OR any mix)
//   3) Duplicate check via (company_id, source, external_lead_id)
//   4) Create the contact
//   5) Save Lead Info + lead_imports record (with raw payload)
//   6) OPTIONAL stage assignment — only if enabled + stage still valid
//
// Only returns a non-2xx status when the token is bad, payload is totally
// unusable, or the contact itself couldn't be saved. Stage errors → warning
// in the 2xx response.
// ============================================================================

function zLog(...args) { console.log("[zapier]", ...args); }
function zWarn(...args) { console.warn("[zapier]", ...args); }
function zErr(...args) { console.error("[zapier]", ...args); }

// Facebook Lead Ads uses fixed field slugs — recognize them so structured
// columns get populated in addition to Lead Info boxes.
const FB_NAME_KEYS  = new Set(["full_name", "name"]);
const FB_FIRST_KEYS = new Set(["first_name", "firstname"]);
const FB_LAST_KEYS  = new Set(["last_name", "lastname", "surname"]);
const FB_PHONE_KEYS = new Set(["phone_number", "phone", "mobile_number", "mobile", "cell_phone", "work_phone"]);
const FB_EMAIL_KEYS = new Set(["email", "e_mail", "email_address"]);
const FB_ADDR_KEYS  = new Set(["address", "street_address", "full_address", "city_state_zip"]);
const FB_CITY_KEYS  = new Set(["city"]);
const FB_STATE_KEYS = new Set(["state", "province"]);
const FB_ZIP_KEYS   = new Set(["zip", "postal_code", "zip_code", "postcode"]);

function firstAnswer(field) {
  if (!field) return "";
  if (Array.isArray(field.values) && field.values.length) return String(field.values[0]);
  if (field.value != null) return String(field.value);
  if (field.answer != null) return String(field.answer);
  return "";
}

function normalizedFieldData(fieldData) {
  if (!Array.isArray(fieldData)) return [];
  return fieldData
    .filter(f => f && typeof f === "object")
    .map(f => ({
      key: (f.name || f.key || f.label || "").toString().trim(),
      question: (f.label || f.question || f.name || "").toString().trim(),
      answer: firstAnswer(f).trim()
    }));
}

function composeAddress(base, city, state, zip) {
  const parts = [];
  if (base) parts.push(base);
  const tail = [city, state].filter(Boolean).join(", ");
  if (tail) parts.push(tail);
  if (zip) parts.push(zip);
  return parts.join(" ").trim() || null;
}

function tokenTail(token) {
  // Safe identifier for logs: last 4 chars only.
  return token && token.length >= 4 ? `…${token.slice(-4)}` : "";
}

// Zapier's "unflatten" mode explodes Facebook Lead Ads field_data into
// top-level JSON keys. Anything that isn't a known contact/metadata key is
// treated as a lead-form question. Meta uses keys like
// "interested_in_our_window_cleaning_maintenance_plan?" and "vehicle".
const RESERVED_TOP_LEVEL_KEYS = new Set([
  // Structured contact keys we already extract above
  "name", "full_name", "first_name", "last_name",
  "phone", "phone_number", "mobile_number", "mobile", "cell_phone", "work_phone",
  "email", "e_mail", "email_address",
  "address", "street_address", "full_address", "city_state_zip",
  "city", "state", "province", "zip", "postal_code", "zip_code", "postcode",
  // Facebook/Meta metadata
  "id", "leadgen_id", "lead_id", "created_time", "submitted_at",
  "form_id", "form", "form_name",
  "page_id", "page", "page_name",
  "ad_id", "ad_name", "adset_id", "adset_name", "campaign_id", "campaign_name",
  "platform", "inbox_url", "partner_name", "retailer_item_id",
  "custom_disclaimer_responses", "raw",
  // Structured fallback keys we already parse
  "field_data", "questions"
]);

const RESERVED_TOP_LEVEL_PREFIXES = [
  "ad_",
  "adgroup",
  "ad_group",
  "adset",
  "ad_set",
  "campaign",
  "event_",
  "leadgen_",
  "lead_",
  "account_",
  "business_",
  "page_",
  "form_",
  "platform_",
  "partner_",
  "retailer_",
  "inbox_",
  "custom_disclaimer_"
];

const RESERVED_TOP_LEVEL_SUFFIXES = [
  "_id",
  "_ids",
  "_url",
  "_urls",
  "_time",
  "_timestamp",
  "_created_time"
];

function isReservedTopLevelKey(key) {
  const normalized = (key || "").toString().trim().toLowerCase();
  if (!normalized) return true;
  if (RESERVED_TOP_LEVEL_KEYS.has(normalized)) return true;
  if (RESERVED_TOP_LEVEL_PREFIXES.some(prefix => normalized.startsWith(prefix))) return true;
  if (RESERVED_TOP_LEVEL_SUFFIXES.some(suffix => normalized.endsWith(suffix))) {
    // Most top-level *_id values from Meta/Zapier are system identifiers, not
    // lead-form answers. Real Q&A should come through `questions`, `field_data`,
    // or a human question label such as `vehicle`.
    return true;
  }
  return false;
}

function humanizeFieldKey(key) {
  // "interested_in_our_window_cleaning_maintenance_plan?" → "Interested In Our Window Cleaning Maintenance Plan?"
  return key
    .replace(/[_\-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .split(" ")
    .map(w => w.length ? w[0].toUpperCase() + w.slice(1) : w)
    .join(" ");
}

function extractQuestionsFromTopLevel(body) {
  const results = [];
  for (const key of Object.keys(body || {})) {
    if (isReservedTopLevelKey(key)) continue;
    const raw = body[key];
    // Skip nested objects / arrays that aren't simple scalar answers
    let answer = "";
    if (raw == null) continue;
    if (typeof raw === "string" || typeof raw === "number" || typeof raw === "boolean") {
      answer = String(raw).trim();
    } else if (Array.isArray(raw)) {
      answer = raw.map(v => (v == null ? "" : String(v))).filter(Boolean).join(", ");
    } else if (typeof raw === "object") {
      // Zapier occasionally hands nested objects — flatten to JSON string
      try { answer = JSON.stringify(raw); } catch (_) { answer = ""; }
    }
    if (!answer) continue;
    results.push({ question: humanizeFieldKey(key), answer });
  }
  return results;
}

const FB_USED_KEYS = new Set([
  ...FB_NAME_KEYS, ...FB_FIRST_KEYS, ...FB_LAST_KEYS,
  ...FB_PHONE_KEYS, ...FB_EMAIL_KEYS, ...FB_ADDR_KEYS,
  ...FB_CITY_KEYS, ...FB_STATE_KEYS, ...FB_ZIP_KEYS
]);

/// Given a raw webhook payload, return the extracted Q&A pairs.
/// Handles all three shapes: structured `questions`, Facebook `field_data`,
/// or Zapier's "unflatten" top-level keys.
function buildQuestionsFromPayload(body) {
  if (!body || typeof body !== "object") return [];
  if (Array.isArray(body.questions)) {
    return body.questions
      .filter(q => q && typeof q === "object")
      .map(q => ({ question: (q.question || "").toString(), answer: (q.answer || "").toString() }));
  }
  const fieldEntries = normalizedFieldData(body.field_data);
  if (fieldEntries.length) {
    return fieldEntries
      .filter(e => !FB_USED_KEYS.has(e.key.toLowerCase()))
      .map(e => ({ question: e.question || e.key, answer: e.answer }));
  }
  return extractQuestionsFromTopLevel(body);
}

/// Convert [{question, answer}] into the Lead Info string boxes
/// (`Question\n**Answer**`), capped at 25.
function buildLeadInfoStrings(questions) {
  return (questions || [])
    .filter(q => q && (q.question || q.answer))
    .slice(0, 25)
    .map(q => {
      const question = (q.question || "").toString().trim();
      const answer = (q.answer || "").toString().trim();
      if (!question && !answer) return "";
      if (!answer) return question;
      if (!question) return `**${answer}**`;
      return `${question}\n**${answer}**`;
    });
}

// Formats the notification body from a lead using the user's chosen fields.
// "New Lead" is ALWAYS the leading title — user configures the trailing detail.
function formatNotification(fieldKeys, ctx) {
  // ctx: { name, phone, email, address, source, formName, questions: [{question, answer}] }
  const keys = Array.isArray(fieldKeys) && fieldKeys.length ? fieldKeys : ["name", "phone", "email"];
  const titleParts = ["New Lead"];
  if (keys.includes("name") && ctx.name) titleParts.push(ctx.name);
  const title = titleParts.join(": ");

  const bodyParts = [];
  if (keys.includes("phone") && ctx.phone)     bodyParts.push(ctx.phone);
  if (keys.includes("email") && ctx.email)     bodyParts.push(ctx.email);
  if (keys.includes("address") && ctx.address) bodyParts.push(ctx.address);
  if (keys.includes("form") && ctx.formName)   bodyParts.push(`Form: ${ctx.formName}`);
  if (keys.includes("source") && ctx.source)   bodyParts.push(`Source: ${ctx.source}`);
  if (keys.includes("qa") && ctx.questions && ctx.questions.length) {
    // Include at most 3 Q&A answers in the notification body — anything more
    // is overwhelming for a push. The full detail lives on the contact.
    const answers = ctx.questions.slice(0, 3).map(q => {
      if (q.answer && q.question) return `${q.question}: ${q.answer}`;
      return q.answer || q.question || "";
    }).filter(Boolean);
    bodyParts.push(...answers);
  }
  return { title, body: bodyParts.join(" · ") };
}

app.post("/webhooks/leads/:token", async (req, res) => {
  const startedAt = Date.now();
  const { token } = req.params;
  const bodyKeys = Object.keys(req.body || {});
  zLog("webhook_received", { tokenTail: tokenTail(token), bodyKeys });

  // ---- STEP 1: TOKEN VALIDATION ---------------------------------------------
  if (!token || token.length < 16) {
    zWarn("token_validation_failed", { reason: "bad_format" });
    return res.status(400).json({
      success: false,
      error: "bad_token",
      message: "Webhook URL is malformed."
    });
  }

  let tokenRow;
  try {
    const q = await pool.query(
      `SELECT zt.user_id, zt.auto_stage_id, zt.auto_assign_stage_enabled,
              zt.notifications_enabled, zt.notification_fields,
              u.company_id
       FROM zapier_tokens zt
       JOIN users u ON u.id = zt.user_id
       WHERE zt.token = $1`,
      [token]
    );
    tokenRow = q.rows[0];
  } catch (e) {
    zErr("token_lookup_failed", { message: e && e.message ? e.message : "unknown" });
    return res.status(500).json({
      success: false,
      error: "auth_lookup_failed",
      message: "Authentication check failed. Please retry."
    });
  }

  if (!tokenRow) {
    zWarn("token_not_found");
    return res.status(404).json({
      success: false,
      error: "token_not_found",
      message: "Unknown webhook token."
    });
  }

  const userId     = tokenRow.user_id;
  const companyId  = tokenRow.company_id || null;
  const autoStageId = tokenRow.auto_stage_id;
  const autoAssignEnabled = !!tokenRow.auto_assign_stage_enabled;
  const notificationsEnabled = !!tokenRow.notifications_enabled;
  const notificationFields = Array.isArray(tokenRow.notification_fields) ? tokenRow.notification_fields : null;

  zLog("token_validated", { hasCompany: !!companyId });
  zLog("company_resolved", { companyId: companyId || "user-scope" });

  // ---- STEP 2: PARSE PAYLOAD ------------------------------------------------
  const body = req.body || {};
  const fieldEntries = normalizedFieldData(body.field_data);
  const findFB = (matcher) => {
    const e = fieldEntries.find(x => matcher.has(x.key.toLowerCase()));
    return e ? e.answer : "";
  };

  const fullName = (body.full_name || body.name || findFB(FB_NAME_KEYS) || "").toString().trim();
  const first    = (body.first_name || findFB(FB_FIRST_KEYS) || "").toString().trim();
  const last     = (body.last_name  || findFB(FB_LAST_KEYS)  || "").toString().trim();
  const composed = [first, last].filter(Boolean).join(" ").trim();
  let   name     = fullName || composed || "";

  const phone = (body.phone || body.phone_number || findFB(FB_PHONE_KEYS) || "").toString().trim() || null;
  const email = (body.email || findFB(FB_EMAIL_KEYS) || "").toString().trim() || null;
  const baseAddress = (body.address || body.street_address || findFB(FB_ADDR_KEYS) || "").toString().trim();
  const city  = (body.city  || findFB(FB_CITY_KEYS)  || "").toString().trim();
  const state = (body.state || findFB(FB_STATE_KEYS) || "").toString().trim();
  const zip   = (body.zip   || body.postal_code || findFB(FB_ZIP_KEYS) || "").toString().trim();
  const address = composeAddress(baseAddress, city, state, zip);

  // A lead is "usable" if we have at least one useful identifier.
  const haveAnyIdentifier = !!(name || phone || email || address);
  if (!haveAnyIdentifier) {
    zWarn("payload_unusable");
    return res.status(400).json({
      success: false,
      error: "payload_unusable",
      message: "Lead had no name, phone, email or address — nothing to save."
    });
  }
  if (!name) name = phone || email || "New Lead";

  // Facebook / Meta metadata
  const externalLeadId = (body.id || body.leadgen_id || body.lead_id || "").toString().trim() || null;
  const formId  = (body.form_id || body.form || "").toString().trim() || null;
  const pageId  = (body.page_id || body.page || "").toString().trim() || null;
  const submittedAt = body.created_time || body.submitted_at || null;

  const source = externalLeadId ? "facebook_zapier" : "zapier";

  // Coerce submittedAt into either a valid ISO string or null. Postgres
  // otherwise rejects empty strings / numbers with an "invalid input syntax
  // for type timestamp with time zone" error that would fail the whole insert.
  let submittedAtSafe = null;
  if (submittedAt) {
    try {
      const d = new Date(submittedAt);
      if (!isNaN(d.getTime())) submittedAtSafe = d.toISOString();
    } catch (_) { /* leave as null */ }
  }

  zLog("payload_parsed", {
    hasName: !!name, hasPhone: !!phone, hasEmail: !!email, hasAddress: !!address,
    fieldCount: fieldEntries.length,
    externalLeadId: externalLeadId ? "yes" : "no",
    submittedAtSafe: submittedAtSafe ? "yes" : "no"
  });

  // Build Lead Info boxes from whatever shape Zapier / Meta delivered.
  const questions = buildQuestionsFromPayload(body);
  zLog("questions_extracted", { count: questions.length });
  const leadInfo = buildLeadInfoStrings(questions);

  // ---- STEP 3: DUPLICATE CHECK ---------------------------------------------
  let duplicateContactId = null;
  if (externalLeadId) {
    try {
      const scopeSQL = companyId
        ? `company_id = $1 AND source = $2 AND external_lead_id = $3`
        : `user_id = $1 AND source = $2 AND external_lead_id = $3`;
      const scopeVal = companyId || userId;
      const dup = await pool.query(
        `SELECT id FROM contacts WHERE ${scopeSQL} LIMIT 1`,
        [scopeVal, source, externalLeadId]
      );
      if (dup.rowCount) duplicateContactId = dup.rows[0].id;
    } catch (e) {
      // Duplicate check is a nice-to-have; log and continue.
      zWarn("duplicate_check_failed", { message: e && e.message ? e.message : "unknown" });
    }
  }
  zLog("duplicate_check_completed", { duplicate: !!duplicateContactId });

  if (duplicateContactId) {
    zLog("webhook_completed", { ms: Date.now() - startedAt, duplicate: true });
    return res.status(200).json({
      success: true,
      contact_created: false,
      duplicate: true,
      contact_id: duplicateContactId
    });
  }

  // ---- STEP 4: CREATE CONTACT (mandatory) -----------------------------------
  // Two-stage insert. Primary attempt writes source/external_lead_id/etc.
  // If that fails for ANY reason (missing columns on a stale schema, bad
  // Facebook timestamp, JSONB weirdness, whatever), fall back to a minimal
  // insert that only uses columns present since day one. This guarantees
  // contact creation is never blocked by webhook-specific metadata.
  const contactId = randomUUID();
  let contactRow;
  let fallbackUsed = false;

  // `contacts.tags` is TEXT[] in production. Pass a real array, not a
  // comma-joined string — Postgres error 22P02 otherwise.
  const tagsArray = ["lead", "zapier"];

  try {
    const inserted = await pool.query(
      `INSERT INTO contacts (
        id, user_id, company_id, name, phone, email, address,
        value_cents, lat, lng, tags, job_type,
        u1, u2, u3, u4, u5, lead_info,
        source, external_lead_id, lead_form_id, lead_page_id, lead_submitted_at
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7,
        NULL, NULL, NULL, $8, NULL,
        NULL, NULL, NULL, NULL, NULL, $9,
        $10, $11, $12, $13, $14
      ) RETURNING *`,
      [
        contactId, userId, companyId, name, phone || "", email || "", address || "",
        tagsArray,
        JSON.stringify(leadInfo),
        source, externalLeadId, formId, pageId, submittedAtSafe
      ]
    );
    contactRow = inserted.rows[0];
    zLog("contact_created", { contactId, source });
  } catch (primaryErr) {
    zErr("contact_insert_primary_failed", {
      code: primaryErr && primaryErr.code ? primaryErr.code : null,
      message: primaryErr && primaryErr.message ? primaryErr.message : "unknown"
    });
    // Fallback: minimal insert using only columns that have been on
    // `contacts` from the beginning. Lead Info is still saved.
    try {
      const fallback = await pool.query(
        `INSERT INTO contacts (
          id, user_id, company_id, name, phone, email, address,
          tags, lead_info
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *`,
        [
          contactId, userId, companyId, name, phone || "", email || "", address || "",
          tagsArray,
          JSON.stringify(leadInfo)
        ]
      );
      contactRow = fallback.rows[0];
      fallbackUsed = true;
      zWarn("contact_created_via_fallback", { contactId });
    } catch (fallbackErr) {
      // Very last try: minimal-minimal insert without lead_info, in case
      // the lead_info column also isn't present on ancient schemas.
      try {
        const minimal = await pool.query(
          `INSERT INTO contacts (
            id, user_id, company_id, name, phone, email, address, tags
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
          RETURNING *`,
          [
            contactId, userId, companyId, name, phone || "", email || "", address || "",
            tagsArray
          ]
        );
        contactRow = minimal.rows[0];
        fallbackUsed = true;
        zWarn("contact_created_via_minimal_fallback", { contactId });
      } catch (finalErr) {
        zErr("contact_create_failed_all_paths", {
          primaryCode: primaryErr && primaryErr.code,
          primaryMessage: primaryErr && primaryErr.message,
          fallbackCode: fallbackErr && fallbackErr.code,
          fallbackMessage: fallbackErr && fallbackErr.message,
          finalCode: finalErr && finalErr.code,
          finalMessage: finalErr && finalErr.message
        });
        return res.status(500).json({
          success: false,
          contact_created: false,
          error: "contact_create_failed",
          message: "We couldn't save this lead. Please retry."
        });
      }
    }
  }

  // ---- STEP 4b: SAVE RAW PAYLOAD FOR DEBUGGING ------------------------------
  // Stored separately from contacts so debugging doesn't clutter normal reads.
  try {
    await pool.query(
      `INSERT INTO lead_imports
         (company_id, user_id, contact_id, source, external_lead_id, form_id, page_id, submitted_at, raw_payload)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [companyId, userId, contactId, source, externalLeadId, formId, pageId, submittedAtSafe, body]
    );
    zLog("lead_info_saved", { boxes: leadInfo.length });
  } catch (e) {
    // Non-fatal — the contact & lead_info are safely on the contact row.
    zWarn("lead_import_record_failed", { message: e && e.message ? e.message : "unknown" });
  }

  // ---- STEP 4c: OPTIONAL PUSH NOTIFICATION (APNs + foreground queue) --------
  // Two delivery paths, both non-fatal:
  //   1) Real APNs push — reaches locked/closed devices (requires env config)
  //   2) Foreground queue — iOS also polls this on scene-active as a fallback
  if (notificationsEnabled) {
    try {
      const formName = (body.form_name || "").toString().trim() || null;
      const { title, body: notifBody } = formatNotification(notificationFields, {
        name, phone, email, address,
        source: "Meta / Zapier",
        formName,
        questions
      });

      const apnsConfigured = Boolean(process.env.APNS_KEY_P8 && process.env.APNS_KEY_ID && process.env.APNS_TEAM_ID && process.env.APNS_BUNDLE_ID);
      if (!apnsConfigured) {
        try {
          await pool.query(
            `INSERT INTO lead_notifications (user_id, company_id, contact_id, title, body)
             VALUES ($1, $2, $3, $4, $5)`,
            [userId, companyId, contactId, title, notifBody]
          );
          zLog("notification_enqueued", { contactId });
        } catch (e) {
          zWarn("notification_enqueue_failed", { message: e && e.message ? e.message : "unknown" });
        }
      }

      try {
        const result = await sendPushToUsers([userId], "new_lead", {
          title,
          body: notifBody,
          contactId,
          threadId: `new_lead_${contactId}`,
          payload: { type: "new_lead", contact_id: contactId, source }
        });
        zLog("apns_push_result", { contactId, ...result });
      } catch (e) {
        zWarn("apns_push_error", { message: e && e.message ? e.message : "unknown" });
      }
    } catch (e) {
      zWarn("notification_pipeline_failed", { message: e && e.message ? e.message : "unknown" });
    }
  }

  // ---- STEP 5: OPTIONAL STAGE ASSIGNMENT ------------------------------------
  // Isolated from everything above. Failures here NEVER touch the contact.
  const stageResult = {
    attempted: false,
    applied: false,
    reason: null,
    stage_id: null
  };

  if (!autoAssignEnabled) {
    stageResult.reason = "auto_assign_disabled";
    zLog("stage_assignment_skipped", { reason: stageResult.reason });
  } else if (!autoStageId) {
    stageResult.reason = "no_stage_selected";
    zLog("stage_assignment_skipped", { reason: stageResult.reason });
  } else {
    stageResult.attempted = true;
    zLog("stage_assignment_attempted", { stageId: autoStageId });
    try {
      const stageCheck = await pool.query(
        `SELECT id FROM stages
         WHERE id = $1
           AND (user_id = $2 OR (company_id IS NOT NULL AND company_id = $3))
         LIMIT 1`,
        [autoStageId, userId, companyId || null]
      );
      if (!stageCheck.rowCount) {
        stageResult.reason = "stage_missing_or_out_of_scope";
        zWarn("stage_assignment_skipped", { reason: stageResult.reason, stageId: autoStageId });
        // Self-heal: clear the bad reference so it stops firing.
        try {
          await pool.query(
            `UPDATE zapier_tokens SET auto_stage_id = NULL, auto_assign_stage_enabled = false WHERE user_id = $1`,
            [userId]
          );
        } catch (_) { /* ignore */ }
      } else {
        const oppId = randomUUID();
        await pool.query(
          `INSERT INTO opportunities (id, user_id, company_id, contact_id, state, stage_id)
           VALUES ($1, $2, $3, $4, 'stage', $5)`,
          [oppId, userId, companyId || null, contactId, autoStageId]
        );
        stageResult.applied = true;
        stageResult.stage_id = autoStageId;
        await emitAutomationEvent({
          companyId,
          eventType: "pipeline.opportunity_created",
          subjectType: "opportunity",
          subjectId: oppId,
          actorUserId: userId,
          source: "lead_intake",
          dedupeKey: externalLeadId ? `pipeline.opportunity_created:${source}:${externalLeadId}` : `pipeline.opportunity_created:${oppId}`,
          payload: { opportunity_id: oppId, contact_id: contactId, stage_id: autoStageId, source }
        });
        await emitAutomationEvent({
          companyId,
          eventType: "pipeline.stage_entered",
          subjectType: "opportunity",
          subjectId: oppId,
          actorUserId: userId,
          source: "lead_intake",
          dedupeKey: externalLeadId ? `pipeline.stage_entered:${source}:${externalLeadId}:${autoStageId}` : `pipeline.stage_entered:${oppId}:${autoStageId}`,
          payload: { opportunity_id: oppId, contact_id: contactId, stage_id: autoStageId, source }
        });
        zLog("stage_assignment_succeeded", { oppId, stageId: autoStageId });
      }
    } catch (e) {
      stageResult.reason = "opportunity_insert_failed";
      zErr("stage_assignment_error_soft", {
        contactId, stageId: autoStageId,
        message: e && e.message ? e.message : "unknown"
      });
    }
  }

  zLog("webhook_completed", { ms: Date.now() - startedAt, contactId, stageResult });

  // ---- RESPONSE -------------------------------------------------------------
  const responseBody = {
    success: true,
    contact_created: true,
    contact_id: contactRow.id,
    stage_assigned: stageResult.applied
  };
  if (stageResult.applied) {
    responseBody.stage_id = stageResult.stage_id;
  } else if (stageResult.attempted) {
    responseBody.warning = "stage_assignment_skipped";
    responseBody.stage_skip_reason = stageResult.reason;
  }
  await emitAutomationEvent({
    companyId,
    eventType: "lead.created",
    subjectType: "contact",
    subjectId: contactRow.id,
    actorUserId: userId,
    source: "lead_intake",
    dedupeKey: externalLeadId ? `lead.created:${source}:${externalLeadId}` : `lead.created:${contactRow.id}`,
    payload: {
      contact_id: contactRow.id,
      source,
      external_lead_id: externalLeadId,
      form_id: formId,
      page_id: pageId,
      fallback_used: fallbackUsed
    }
  });
  const leadEvents = ["lead.received_external", "lead.received_webhook", "lead.received_zapier"];
  if (source && /facebook|meta|instagram/i.test(source)) leadEvents.push("lead.received_meta", "lead.external_form_received");
  if (source && /website|site/i.test(source)) leadEvents.push("lead.received_website");
  for (const eventType of leadEvents) {
    await emitAutomationEvent({
      companyId,
      eventType,
      subjectType: "contact",
      subjectId: contactRow.id,
      actorUserId: userId,
      source: "lead_intake",
      dedupeKey: externalLeadId ? `${eventType}:${source}:${externalLeadId}` : `${eventType}:${contactRow.id}`,
      payload: {
        contact_id: contactRow.id,
        source,
        external_lead_id: externalLeadId,
        form_id: formId,
        page_id: pageId,
        submitted_at: submittedAtSafe,
        lead_info: leadInfo
      }
    });
  }
  return res.status(201).json(responseBody);
});


// ---------- QUOTES ----------
// Line items are stored as JSON: [{ name: string, qty: number, price_cents: number }]
// total_cents is the server-authoritative sum so listing/cards don't have to compute.
function computeQuoteTotalCents(lineItems) {
  if (!Array.isArray(lineItems)) return 0;
  return lineItems.reduce((sum, li) => {
    if (!li || typeof li !== "object") return sum;
    const qty = Number(li.qty) || 0;
    const price = Number(li.price_cents) || 0;
    return sum + Math.max(0, Math.round(qty * price));
  }, 0);
}

function cleanQuoteString(value, maxLength = 1000) {
  return (value || "").toString().trim().slice(0, maxLength);
}

function quoteSettingsPayload(row, company = {}) {
  return {
    tagline: row?.tagline || "Thank you for the opportunity to earn your business!",
    phone: row?.phone || null,
    email: row?.email || null,
    website: row?.website || null,
    notes: row?.notes || "This quote includes the services listed above.\nIf you have any questions or would like to move forward,\nwe're here to help!\n\nWe look forward to working with you.",
    tax_enabled: Boolean(row?.tax_enabled),
    tax_rate_basis_points: Number(row?.tax_rate_basis_points || 0),
    valid_for_days: Number(row?.valid_for_days || 30),
    company_name: company.name || "",
    company_logo_data_url: company.logo_data_url || "",
    company_phone: company.phone || "",
    company_email: company.email || "",
    company_website: company.website || "",
    company_address: company.address || ""
  };
}

async function getQuoteSettings(pool, companyId) {
  const company = (await pool.query(
    `SELECT name, logo_data_url, website, address, phone, email FROM companies WHERE id = $1`,
    [companyId]
  )).rows[0] || {};
  const settings = (await pool.query(`SELECT * FROM quote_settings WHERE company_id = $1`, [companyId])).rows[0] || null;
  return quoteSettingsPayload(settings, company);
}

function quoteScopeSQL(req, alias = "q") {
  const p = `${alias}.`;
  return req.companyId
    ? { sql: `(${p}company_id = $1 OR (${p}company_id IS NULL AND ${p}user_id = $2))`, values: [req.companyId, req.userId] }
    : { sql: `${p}user_id = $1`, values: [req.userId] };
}

app.get("/api/quotes/settings", authRequired, async (req, res) => {
  try {
    if (!req.companyId) return res.status(400).json({ error: "company_required" });
    res.json(await getQuoteSettings(pool, req.companyId));
  } catch (e) {
    console.error("[quotes] settings failed:", e && e.message ? e.message : e);
    res.status(500).json({ error: "quote_settings_failed" });
  }
});

app.patch("/api/quotes/settings", authRequired, requireEmployer, async (req, res) => {
  try {
    if (!req.companyId) return res.status(400).json({ error: "company_required" });
    const taxRate = Number(req.body?.tax_rate_basis_points || 0);
    const validFor = Number(req.body?.valid_for_days || 30);
    if (!Number.isInteger(taxRate) || taxRate < 0 || taxRate > 5000) return res.status(400).json({ error: "quote_tax_rate_invalid" });
    if (!Number.isInteger(validFor) || validFor < 1 || validFor > 365) return res.status(400).json({ error: "quote_valid_for_invalid" });
    await pool.query(
      `INSERT INTO quote_settings(company_id, tagline, phone, email, website, notes, tax_enabled, tax_rate_basis_points, valid_for_days)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT(company_id) DO UPDATE SET
         tagline = EXCLUDED.tagline,
         phone = EXCLUDED.phone,
         email = EXCLUDED.email,
         website = EXCLUDED.website,
         notes = EXCLUDED.notes,
         tax_enabled = EXCLUDED.tax_enabled,
         tax_rate_basis_points = EXCLUDED.tax_rate_basis_points,
         valid_for_days = EXCLUDED.valid_for_days,
         updated_at = now()`,
      [
        req.companyId,
        cleanQuoteString(req.body?.tagline, 400) || null,
        cleanQuoteString(req.body?.phone, 80) || null,
        cleanQuoteString(req.body?.email, 160) || null,
        cleanQuoteString(req.body?.website, 200) || null,
        cleanQuoteString(req.body?.notes, 3000) || null,
        Boolean(req.body?.tax_enabled),
        taxRate,
        validFor
      ]
    );
    res.json(await getQuoteSettings(pool, req.companyId));
  } catch (e) {
    console.error("[quotes] settings update failed:", e && e.message ? e.message : e);
    res.status(500).json({ error: "quote_settings_update_failed" });
  }
});

app.get("/api/quotes", authRequired, async (req, res) => {
  try {
    const scope = quoteScopeSQL(req);
    const contactID = (req.query.contact_id || "").toString().trim();
    let rows;
    if (contactID) {
      rows = (await pool.query(
        `SELECT id, contact_id, title, line_items, total_cents, notes, status, expires_at, sent_at, accepted_at, declined_at, converted_job_id, created_at, updated_at
         FROM quotes q
         WHERE ${scope.sql} AND contact_id = $${scope.values.length + 1}
         ORDER BY updated_at DESC`,
        [...scope.values, contactID]
      )).rows;
    } else {
      rows = (await pool.query(
        `SELECT id, contact_id, title, line_items, total_cents, notes, status, expires_at, sent_at, accepted_at, declined_at, converted_job_id, created_at, updated_at
         FROM quotes q
         WHERE ${scope.sql}
         ORDER BY updated_at DESC
         LIMIT 500`,
        scope.values
      )).rows;
    }
    res.json(rows);
  } catch (e) {
    console.error("[quotes] list failed:", e && e.message ? e.message : e);
    res.status(500).json({ error: "failed_list_quotes" });
  }
});

app.get("/api/quotes/totals", authRequired, async (req, res) => {
  try {
    const scope = quoteScopeSQL(req);
    const { rows } = await pool.query(
      `SELECT contact_id, SUM(total_cents)::int AS total_cents, COUNT(*)::int AS quote_count
       FROM quotes q
       WHERE ${scope.sql}
       GROUP BY contact_id`,
      scope.values
    );
    res.json(rows);
  } catch (e) {
    console.error("[quotes] totals failed:", e && e.message ? e.message : e);
    res.status(500).json({ error: "failed_quote_totals" });
  }
});

app.post("/api/quotes", authRequired, async (req, res) => {
  const { contact_id, title, line_items, notes, status, expires_at } = req.body || {};
  if (!contact_id) return res.status(400).json({ error: "contact_id_required" });
  const items = Array.isArray(line_items) ? line_items : [];
  const total = computeQuoteTotalCents(items);
  try {
    const { rows } = await pool.query(
      `INSERT INTO quotes (user_id, company_id, contact_id, title, line_items, total_cents, notes, status, expires_at)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9)
       RETURNING id, contact_id, title, line_items, total_cents, notes, status, expires_at, sent_at, accepted_at, declined_at, converted_job_id, created_at, updated_at`,
      [req.userId, req.companyId || null, contact_id, title || null, JSON.stringify(items), total, notes || null, ["draft","sent","accepted","declined","expired","converted"].includes(status) ? status : "draft", expires_at || null]
    );
    if (req.companyId) {
      await emitAutomationEvent({
        companyId: req.companyId,
        eventType: "quote.created",
        subjectType: "quote",
        subjectId: rows[0].id,
        actorUserId: req.userId,
        source: "quotes.api",
        dedupeKey: `quote.created:${rows[0].id}`,
        payload: { quote_id: rows[0].id, contact_id, status: rows[0].status, total_cents: rows[0].total_cents, line_item_count: items.length, expires_at: rows[0].expires_at }
      });
      await syncAutomationSchedulesForQuote(req.companyId, rows[0]);
    }
    res.status(201).json(rows[0]);
  } catch (e) {
    console.error("[quotes] create failed:", e && e.message ? e.message : e);
    res.status(500).json({ error: "failed_create_quote" });
  }
});

app.put("/api/quotes/:id", authRequired, async (req, res) => {
  const { title, line_items, notes, status, expires_at } = req.body || {};
  const items = Array.isArray(line_items) ? line_items : null;
  const total = items ? computeQuoteTotalCents(items) : null;
  try {
    // Fixed placeholder numbering — $1 is the quote id, $2..$5 are the
    // updatable fields, then scope filters follow at $6+ so they never
    // collide with the id.
    const params = [
      req.params.id,
      title || null,
      items ? JSON.stringify(items) : null,
      total,
      notes || null,
      ["draft","sent","accepted","declined","expired","converted"].includes(status) ? status : null,
      expires_at || null
    ];
    let whereScope;
    if (req.companyId) {
      params.push(req.companyId, req.userId);
      whereScope = `(q.company_id = $${params.length - 1} OR (q.company_id IS NULL AND q.user_id = $${params.length}))`;
    } else {
      params.push(req.userId);
      whereScope = `q.user_id = $${params.length}`;
    }
    const before = await pool.query(`SELECT * FROM quotes q WHERE id = $1 AND ${whereScope}`, params);
    const { rows } = await pool.query(
      `UPDATE quotes q SET
         title = COALESCE($2, title),
         line_items = COALESCE($3::jsonb, line_items),
         total_cents = COALESCE($4, total_cents),
         notes = COALESCE($5, notes),
         status = COALESCE($6, status),
         expires_at = COALESCE($7::timestamptz, expires_at),
         sent_at = CASE WHEN $6 = 'sent' THEN COALESCE(sent_at, now()) ELSE sent_at END,
         accepted_at = CASE WHEN $6 = 'accepted' THEN COALESCE(accepted_at, now()) ELSE accepted_at END,
         declined_at = CASE WHEN $6 = 'declined' THEN COALESCE(declined_at, now()) ELSE declined_at END,
         updated_at = now()
       WHERE id = $1 AND ${whereScope}
       RETURNING id, contact_id, title, line_items, total_cents, notes, status, expires_at, sent_at, accepted_at, declined_at, converted_job_id, created_at, updated_at`,
      params
    );
    if (!rows.length) return res.status(404).json({ error: "not_found" });
    if (req.companyId) {
      const prev = before.rows[0] || {};
      const changed = ["title", "notes", "status", "total_cents", "expires_at"].filter((field) => JSON.stringify(prev[field] ?? null) !== JSON.stringify(rows[0][field] ?? null)).map((field) => ({ field, old_value: prev[field] ?? null, new_value: rows[0][field] ?? null }));
      if (JSON.stringify(prev.line_items || []) !== JSON.stringify(rows[0].line_items || [])) changed.push({ field: "line_items", old_value: prev.line_items || [], new_value: rows[0].line_items || [] });
      if (changed.length) {
        const payload = { quote_id: rows[0].id, contact_id: rows[0].contact_id, status: rows[0].status, total_cents: rows[0].total_cents, line_item_count: Array.isArray(rows[0].line_items) ? rows[0].line_items.length : 0, changed_fields: changed };
        await emitAutomationEvent({ companyId: req.companyId, eventType: "quote.updated", subjectType: "quote", subjectId: rows[0].id, actorUserId: req.userId, source: "quotes.api", dedupeKey: `quote.updated:${rows[0].id}:${rows[0].updated_at?.toISOString?.() || Date.now()}`, payload });
        if (prev.status !== rows[0].status) {
          await emitAutomationEvent({ companyId: req.companyId, eventType: "quote.status_changed", subjectType: "quote", subjectId: rows[0].id, actorUserId: req.userId, source: "quotes.api", dedupeKey: `quote.status_changed:${rows[0].id}:${rows[0].status}:${rows[0].updated_at?.toISOString?.() || Date.now()}`, payload });
          const eventType = { sent: "quote.sent", accepted: "quote.accepted", declined: "quote.declined", expired: "quote.expired" }[rows[0].status];
          if (eventType) await emitAutomationEvent({ companyId: req.companyId, eventType, subjectType: "quote", subjectId: rows[0].id, actorUserId: req.userId, source: "quotes.api", dedupeKey: `${eventType}:${rows[0].id}`, payload });
        }
        if (prev.total_cents !== rows[0].total_cents) await emitAutomationEvent({ companyId: req.companyId, eventType: "quote.total_changed", subjectType: "quote", subjectId: rows[0].id, actorUserId: req.userId, source: "quotes.api", dedupeKey: `quote.total_changed:${rows[0].id}:${rows[0].updated_at?.toISOString?.() || Date.now()}`, payload });
        if (JSON.stringify(prev.line_items || []) !== JSON.stringify(rows[0].line_items || [])) await emitAutomationEvent({ companyId: req.companyId, eventType: "quote.line_items_changed", subjectType: "quote", subjectId: rows[0].id, actorUserId: req.userId, source: "quotes.api", dedupeKey: `quote.line_items_changed:${rows[0].id}:${rows[0].updated_at?.toISOString?.() || Date.now()}`, payload });
      }
      await syncAutomationSchedulesForQuote(req.companyId, rows[0]);
    }
    res.json(rows[0]);
  } catch (e) {
    console.error("[quotes] update failed:", e && e.message ? e.message : e);
    res.status(500).json({ error: "failed_update_quote" });
  }
});

app.delete("/api/quotes/:id", authRequired, async (req, res) => {
  try {
    // Fixed placeholder numbering (see PUT above).
    const params = [req.params.id];
    let whereScope;
    if (req.companyId) {
      params.push(req.companyId, req.userId);
      whereScope = `(q.company_id = $2 OR (q.company_id IS NULL AND q.user_id = $3))`;
    } else {
      params.push(req.userId);
      whereScope = `q.user_id = $2`;
    }
    const result = await pool.query(
      `DELETE FROM quotes q WHERE id = $1 AND ${whereScope}
       RETURNING id, company_id, contact_id, status, total_cents`,
      params
    );
    console.log("[quotes] delete", { id: req.params.id, deleted: result.rowCount });
    if (!result.rowCount) return res.status(404).json({ error: "not_found" });
    if (req.companyId) {
      await cancelAutomationSchedulesForSubject(req.companyId, "quote", req.params.id);
      await emitAutomationEvent({
        companyId: req.companyId,
        eventType: "quote.deleted",
        subjectType: "quote",
        subjectId: req.params.id,
        actorUserId: req.userId,
        source: "quotes.api",
        dedupeKey: `quote.deleted:${req.params.id}`,
        payload: { quote_id: req.params.id, contact_id: result.rows[0].contact_id || null, status: result.rows[0].status, total_cents: result.rows[0].total_cents || 0 }
      });
    }
    res.status(204).end();
  } catch (e) {
    console.error("[quotes] delete failed:", e && e.message ? e.message : e);
    res.status(500).json({ error: "failed_delete_quote" });
  }
});

// ---------- STAGES ----------
// Stages are company-scoped when the user belongs to a company; otherwise they
// fall back to the individual user. This is the SAME set of rows both the
// Stages tab and the Integrations "auto-assign" picker read from.
app.get("/api/stages", authRequired, async (req, res) => {
  try {
    const { rows } = req.companyId
      ? await pool.query(
          `SELECT id, name, order_idx FROM stages
           WHERE company_id = $1
              OR (company_id IS NULL AND user_id = $2)
           ORDER BY order_idx ASC`,
          [req.companyId, req.userId]
        )
      : await pool.query(
          `SELECT id, name, order_idx FROM stages
           WHERE user_id = $1
           ORDER BY order_idx ASC`,
          [req.userId]
        );
    console.log("[stages] list", {
      userId: req.userId,
      companyId: req.companyId || "none",
      returned: rows.length,
      ids: rows.map(r => r.id)
    });
    res.json(rows);
  } catch (e) {
    console.error("[stages] list failed:", e && e.message ? e.message : e);
    res.status(500).json({ error: "failed_list_stages" });
  }
});

app.put("/api/stages/:id", authRequired, async (req, res) => {
  const { name, order_idx } = req.body || {};
  if (!name) return res.status(400).json({ error: "name_required" });
  try {
    const r = await pool.query(
      `INSERT INTO stages (id, user_id, company_id, name, order_idx)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (id) DO UPDATE
         SET name = EXCLUDED.name,
             order_idx = EXCLUDED.order_idx,
             company_id = COALESCE(EXCLUDED.company_id, stages.company_id),
             updated_at = now()
       WHERE stages.user_id = $2
          OR (stages.company_id IS NOT NULL AND stages.company_id = $3)
       RETURNING id, name, order_idx`,
      [req.params.id, req.userId, req.companyId || null, name, Number(order_idx) || 0]
    );
    res.json(r.rows[0]);
  } catch (e) { console.error("[stages] upsert failed:", e); res.status(500).json({ error: "failed_upsert_stage" }); }
});

app.delete("/api/stages/:id", authRequired, async (req, res) => {
  try {
    // Null out any zapier_tokens auto-assign refs that pointed here so future
    // webhooks don't try to assign to a deleted stage.
    await pool.query(
      `UPDATE zapier_tokens
         SET auto_stage_id = NULL,
             auto_assign_stage_enabled = false
       WHERE auto_stage_id = $1`,
      [req.params.id]
    );
    await pool.query(
      `DELETE FROM stages
       WHERE id = $1
         AND (user_id = $2 OR (company_id IS NOT NULL AND company_id = $3))`,
      [req.params.id, req.userId, req.companyId || null]);
    res.status(204).end();
  } catch (e) { console.error("[stages] delete failed:", e); res.status(500).json({ error: "failed_delete_stage" }); }
});

// ---------- OPPORTUNITIES (each contact has at most one) ----------
// Company-scoped when the caller belongs to a company; user-scoped otherwise.
// This is important so webhook-created opportunities show up for every teammate.
app.get("/api/opportunities", authRequired, async (req, res) => {
  try {
    const { rows } = req.companyId
      ? await pool.query(
          `SELECT id, contact_id, state, stage_id, created_at
           FROM opportunities
           WHERE company_id = $1 OR (company_id IS NULL AND user_id = $2)`,
          [req.companyId, req.userId]
        )
      : await pool.query(
          `SELECT id, contact_id, state, stage_id, created_at
           FROM opportunities WHERE user_id = $1`,
          [req.userId]
        );
    res.json(rows);
  } catch (e) { console.error("[opportunities] list failed:", e); res.status(500).json({ error: "failed_list_opportunities" }); }
});

app.put("/api/opportunities/:id", authRequired, async (req, res) => {
  const { contact_id, state, stage_id, created_at } = req.body || {};
  if (!contact_id || !state) return res.status(400).json({ error: "missing_params" });
  try {
    const previous = await pool.query(
      `SELECT * FROM opportunities WHERE id = $1 AND (user_id = $2 OR company_id = $3) LIMIT 1`,
      [req.params.id, req.userId, req.companyId || null]
    );
    const before = previous.rows[0] || null;
    const r = await pool.query(
      `INSERT INTO opportunities (id, user_id, company_id, contact_id, state, stage_id, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7, now()))
       ON CONFLICT (user_id, contact_id) DO UPDATE
         SET state = EXCLUDED.state,
             stage_id = EXCLUDED.stage_id,
             company_id = COALESCE(EXCLUDED.company_id, opportunities.company_id),
             updated_at = now()
       RETURNING id, contact_id, state, stage_id, created_at`,
      [req.params.id, req.userId, req.companyId || null, contact_id, state, stage_id || null, created_at || null]
    );
    if (req.companyId) {
      const after = r.rows[0];
      const base = { opportunity_id: after.id, contact_id, state: after.state, stage_id: after.stage_id, previous_state: before?.state || null, previous_stage_id: before?.stage_id || null };
      if (!before) {
        await emitAutomationEvent({ companyId: req.companyId, eventType: "pipeline.opportunity_created", subjectType: "opportunity", subjectId: after.id, actorUserId: req.userId, source: "opportunities.api", dedupeKey: `pipeline.opportunity_created:${after.id}`, payload: base });
      } else {
        await emitAutomationEvent({ companyId: req.companyId, eventType: "pipeline.opportunity_updated", subjectType: "opportunity", subjectId: after.id, actorUserId: req.userId, source: "opportunities.api", payload: base });
      }
      if (before?.stage_id && before.stage_id !== after.stage_id) {
        await emitAutomationEvent({ companyId: req.companyId, eventType: "pipeline.stage_exited", subjectType: "opportunity", subjectId: after.id, actorUserId: req.userId, source: "opportunities.api", payload: { ...base, stage_id: before.stage_id, new_stage_id: after.stage_id } });
      }
      if (after.stage_id && before?.stage_id !== after.stage_id) {
        await emitAutomationEvent({ companyId: req.companyId, eventType: "pipeline.stage_entered", subjectType: "opportunity", subjectId: after.id, actorUserId: req.userId, source: "opportunities.api", payload: { ...base, stage_id: after.stage_id, new_stage_id: after.stage_id } });
      }
      if (before && before.stage_id !== after.stage_id) {
        await emitAutomationEvent({ companyId: req.companyId, eventType: "pipeline.stage_changed", subjectType: "opportunity", subjectId: after.id, actorUserId: req.userId, source: "opportunities.api", payload: { ...base, old_stage_id: before.stage_id, new_stage_id: after.stage_id } });
        await emitAutomationEvent({ companyId: req.companyId, eventType: "pipeline.opportunity_moved", subjectType: "opportunity", subjectId: after.id, actorUserId: req.userId, source: "opportunities.api", payload: base });
      }
      if (before?.state !== "won" && after.state === "won") {
        await emitAutomationEvent({ companyId: req.companyId, eventType: "pipeline.won", subjectType: "opportunity", subjectId: after.id, actorUserId: req.userId, source: "opportunities.api", payload: base });
      }
      if (before?.state !== "lost" && after.state === "lost") {
        await emitAutomationEvent({ companyId: req.companyId, eventType: "pipeline.lost", subjectType: "opportunity", subjectId: after.id, actorUserId: req.userId, source: "opportunities.api", payload: base });
      }
      if (["won", "lost"].includes(before?.state) && after.state === "stage") {
        await emitAutomationEvent({ companyId: req.companyId, eventType: "pipeline.reopened", subjectType: "opportunity", subjectId: after.id, actorUserId: req.userId, source: "opportunities.api", payload: base });
      }
    }
    res.json(r.rows[0]);
  } catch (e) { console.error("[opportunities] upsert failed:", e); res.status(500).json({ error: "failed_upsert_opportunity" }); }
});

app.delete("/api/opportunities/:id", authRequired, async (req, res) => {
  try {
    const before = (await pool.query(
      `DELETE FROM opportunities
       WHERE id = $1
         AND (user_id = $2 OR (company_id IS NOT NULL AND company_id = $3))
       RETURNING *`,
      [req.params.id, req.userId, req.companyId || null])).rows?.[0];
    if (before && req.companyId) {
      const payload = { opportunity_id: before.id, contact_id: before.contact_id, stage_id: before.stage_id, previous_stage_id: before.stage_id, state: before.state };
      await emitAutomationEvent({ companyId: req.companyId, eventType: "pipeline.opportunity_removed", subjectType: "opportunity", subjectId: before.id, actorUserId: req.userId, source: "opportunities.api", payload });
      if (before.stage_id) await emitAutomationEvent({ companyId: req.companyId, eventType: "pipeline.stage_exited", subjectType: "opportunity", subjectId: before.id, actorUserId: req.userId, source: "opportunities.api", payload });
    }
    res.status(204).end();
  } catch (e) { console.error("[opportunities] delete failed:", e); res.status(500).json({ error: "failed_delete_opportunity" }); }
});

// ---------- SCHEDULE EVENTS ----------
app.get("/api/schedule", authRequired, async (req, res) => {
  try {
    const where = req.companyId
      ? { sql: `company_id = $1`, values: [req.companyId] }
      : { sql: `user_id = $1`, values: [req.userId] };
    const { rows } = await pool.query(
      `SELECT id, title, start_at AS start, end_at AS "end", color, notes,
              contact_id, reminder_minutes, services, service_items, price_cents, material_cost_cents,
              company_id, created_by, sales_user_ids, worker_user_ids, started_at, started_by, finished_at, finished_by
       FROM schedule_events WHERE ${where.sql} ORDER BY start_at ASC`,
      where.values
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_list_schedule" }); }
});

app.put("/api/schedule/:id", authRequired, async (req, res) => {
  const {
    title, start, end, color, notes, contact_id, reminder_minutes, services, service_items, price_cents, material_cost_cents,
    sales_user_ids, worker_user_ids, started_at, started_by, finished_at, finished_by
  } = req.body || {};
  if (!title || !start || !end) return res.status(400).json({ error: "missing_params" });
  const salesIDs = Array.isArray(sales_user_ids) ? sales_user_ids.slice(0, 2) : [req.userId];
  const workerIDs = Array.isArray(worker_user_ids) ? worker_user_ids : [];
  try {
    const previous = await pool.query(
      `SELECT * FROM schedule_events WHERE id = $1 AND (user_id = $2 OR company_id = $3)`,
      [req.params.id, req.userId, req.companyId]
    );
    const oldWorkerIDs = previous.rows.length && Array.isArray(previous.rows[0].worker_user_ids)
      ? previous.rows[0].worker_user_ids
      : [];
    const isNewJob = previous.rowCount === 0;
    const r = await pool.query(
      `INSERT INTO schedule_events
        (id, user_id, company_id, created_by, title, start_at, end_at, color, notes, contact_id,
         reminder_minutes, services, service_items, price_cents, material_cost_cents, sales_user_ids, worker_user_ids, started_at, started_by, finished_at, finished_by)
       VALUES ($1, $2, $3, $2, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb, $12::jsonb, $13, $14, $15::jsonb, $16::jsonb, $17, $18, $19, $20)
       ON CONFLICT (id) DO UPDATE
         SET title = EXCLUDED.title,
             start_at = EXCLUDED.start_at,
             end_at = EXCLUDED.end_at,
             color = EXCLUDED.color,
             notes = EXCLUDED.notes,
             contact_id = EXCLUDED.contact_id,
             reminder_minutes = EXCLUDED.reminder_minutes,
             services = EXCLUDED.services,
             service_items = EXCLUDED.service_items,
             price_cents = EXCLUDED.price_cents,
             material_cost_cents = EXCLUDED.material_cost_cents,
             company_id = EXCLUDED.company_id,
             sales_user_ids = EXCLUDED.sales_user_ids,
             worker_user_ids = EXCLUDED.worker_user_ids,
             started_at = EXCLUDED.started_at,
             started_by = EXCLUDED.started_by,
             finished_at = EXCLUDED.finished_at,
             finished_by = EXCLUDED.finished_by,
             updated_at = now()
       WHERE schedule_events.user_id = $2 OR schedule_events.company_id = $3
       RETURNING id, title, start_at AS start, end_at AS "end", color, notes,
                 contact_id, reminder_minutes, services, price_cents, material_cost_cents,
                 service_items, company_id, created_by, sales_user_ids, worker_user_ids, started_at, started_by, finished_at, finished_by`,
      [
        req.params.id, req.userId, req.companyId, title, start, end,
        color || '#3478F6', notes || null, contact_id || null,
        JSON.stringify(reminder_minutes || []),
        JSON.stringify(services || []),
        JSON.stringify(Array.isArray(service_items) ? service_items : []),
        Number.isFinite(Number(price_cents)) ? Number(price_cents) : null,
        Number.isFinite(Number(material_cost_cents)) ? Number(material_cost_cents) : null,
        JSON.stringify(salesIDs),
        JSON.stringify(workerIDs),
        started_at || null,
        started_by || null,
        finished_at || null,
        finished_by || null
      ]
    );
    const addedWorkers = workerIDs.filter((id) => !oldWorkerIDs.includes(id));
    await notifyMany(
      addedWorkers,
      req.companyId,
      "job_assignment",
      "New Job Assigned to You",
      title,
      { schedule_event_id: req.params.id },
      req.userId
    );
    if (isNewJob && req.companyId) {
      const setting = await pool.query(
        `SELECT notify_all_members_on_jobs FROM companies WHERE id = $1`,
        [req.companyId]
      );
      if (setting.rows[0]?.notify_all_members_on_jobs) {
        const members = await pool.query(
          `SELECT id FROM users WHERE company_id = $1`,
          [req.companyId]
        );
        await notifyMany(
          members.rows.map((m) => m.id),
          req.companyId,
          "job_scheduled",
          "New Job Scheduled",
          title,
          { schedule_event_id: req.params.id },
          req.userId
        );
      }
    }
    if (req.companyId) {
      await emitJobRouteEvents(req.companyId, req.userId, previous.rows[0] || null, r.rows[0], "schedule.api");
      await syncAutomationSchedulesForJob(req.companyId, r.rows[0]);
    }
    res.json(r.rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_upsert_schedule" }); }
});

app.delete("/api/schedule/:id", authRequired, async (req, res) => {
  try {
    const before = req.companyId
      ? (await pool.query(`SELECT * FROM schedule_events WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId])).rows[0]
      : null;
    if (req.companyId) {
      await pool.query(`DELETE FROM schedule_events WHERE id = $1 AND company_id = $2`,
        [req.params.id, req.companyId]);
    } else {
      await pool.query(`DELETE FROM schedule_events WHERE id = $1 AND user_id = $2`,
        [req.params.id, req.userId]);
    }
    if (before && req.companyId) {
      await emitAutomationEvent({ companyId: req.companyId, eventType: "job.deleted", subjectType: "job", subjectId: before.id, actorUserId: req.userId, source: "schedule.api", dedupeKey: `job.deleted:${before.id}`, payload: { job_id: before.id, contact_id: before.contact_id, title: before.title } });
      await cancelAutomationSchedulesForSubject(req.companyId, "job", before.id);
    }
    res.status(204).end();
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_delete_schedule" }); }
});

// ---------- OPERATIONS: JOB WORKFLOWS ----------
function defaultWorkflowSections() {
  return [
    { id: randomUUID(), title: "Before Starting", instructions: "Confirm scope and document the property before work begins.", items: [
      { id: randomUUID(), kind: "acknowledgment", label: "Confirm arrival at the correct property", detail: null, required: true, response: null, completed: false, minPhotos: null },
      { id: randomUUID(), kind: "acknowledgment", label: "Review customer notes and job instructions", detail: null, required: true, response: null, completed: false, minPhotos: null },
      { id: randomUUID(), kind: "before_photo", label: "Take required before photos", detail: null, required: true, response: null, completed: false, minPhotos: 1 }
    ] },
    { id: randomUUID(), title: "Work Checklist", instructions: null, items: [
      { id: randomUUID(), kind: "checkbox", label: "Complete scheduled service scope", detail: null, required: true, response: null, completed: false, minPhotos: null },
      { id: randomUUID(), kind: "employee_note", label: "Record employee notes or exceptions", detail: null, required: false, response: null, completed: false, minPhotos: null }
    ] },
    { id: randomUUID(), title: "Quality Check", instructions: "Inspect the work before leaving.", items: [
      { id: randomUUID(), kind: "checkbox", label: "Inspect completed work", detail: null, required: true, response: null, completed: false, minPhotos: null },
      { id: randomUUID(), kind: "after_photo", label: "Take required after photos", detail: null, required: true, response: null, completed: false, minPhotos: 1 },
      { id: randomUUID(), kind: "acknowledgment", label: "Confirm tools, hoses, gates, and doors are secured", detail: null, required: true, response: null, completed: false, minPhotos: null }
    ] },
    { id: randomUUID(), title: "Customer Completion", instructions: null, items: [
      { id: randomUUID(), kind: "checkbox", label: "Customer walkthrough completed or unavailable noted", detail: null, required: true, response: null, completed: false, minPhotos: null },
      { id: randomUUID(), kind: "long_text", label: "Final employee notes", detail: null, required: false, response: null, completed: false, minPhotos: null }
    ] }
  ];
}

async function resolvedWorkflowSections(companyId, job) {
  const services = Array.isArray(job.services) ? job.services : [];
  const { rows } = await pool.query(
    `SELECT sections FROM job_workflow_templates
     WHERE company_id = $1 AND enabled = true AND archived_at IS NULL
       AND (scope = 'company_default' OR (scope = 'service_type' AND service_type = ANY($2::text[])))
     ORDER BY CASE WHEN scope = 'company_default' THEN 0 ELSE 1 END, updated_at ASC`,
    [companyId, services]
  );
  const merged = rows.flatMap((r) => Array.isArray(r.sections) ? r.sections : []);
  const base = merged.length ? merged : defaultWorkflowSections();
  const additions = (await pool.query(
    `SELECT sections FROM job_workflow_job_additions WHERE company_id = $1 AND job_id = $2`,
    [companyId, job.id]
  )).rows[0];
  const jobSections = additions && Array.isArray(additions.sections) ? additions.sections : [];
  return jobSections.length ? base.concat(jobSections) : base;
}

function workflowMissingRequired(snapshot) {
  return (Array.isArray(snapshot) ? snapshot : []).flatMap((section) => Array.isArray(section.items) ? section.items : []).filter((item) => {
    if (!item.required) return false;
    if (["short_text", "long_text", "employee_note", "customer_signature"].includes(item.kind)) {
      return !(item.response || "").toString().trim();
    }
    return !item.completed;
  });
}

function workflowRunPayload(row) {
  return {
    id: row.id, job_id: row.job_id, status: row.status,
    started_at: row.started_at, started_by: row.started_by,
    completed_at: row.completed_at, completed_by: row.completed_by,
    override_reason: row.override_reason,
    snapshot: Array.isArray(row.snapshot) ? row.snapshot : []
  };
}

app.post("/api/jobs/:id/workflow/start", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const job = (await client.query(`SELECT * FROM schedule_events WHERE id = $1 AND company_id = $2 FOR UPDATE`, [req.params.id, req.companyId])).rows[0];
    if (!job) { await client.query("ROLLBACK"); return res.status(404).json({ error: "job_not_found" }); }
    const now = new Date();
    const snapshot = await resolvedWorkflowSections(req.companyId, job);
    await client.query(`UPDATE schedule_events SET started_at = COALESCE(started_at, $3), started_by = COALESCE(started_by, $4), updated_at = now() WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId, now, req.userId]);
    const run = (await client.query(
      `INSERT INTO job_workflow_runs(id, company_id, job_id, status, started_at, started_by, snapshot)
       VALUES($1, $2, $3, 'in_progress', $4, $5, $6::jsonb)
       ON CONFLICT(company_id, job_id) DO UPDATE
         SET started_at = COALESCE(job_workflow_runs.started_at, EXCLUDED.started_at),
             started_by = COALESCE(job_workflow_runs.started_by, EXCLUDED.started_by),
             status = CASE WHEN job_workflow_runs.status = 'completed' THEN 'completed' ELSE 'in_progress' END,
             updated_at = now()
       RETURNING *`,
      [randomUUID(), req.companyId, req.params.id, now, req.userId, JSON.stringify(snapshot)]
    )).rows[0];
    await emitAutomationEvent({ companyId: req.companyId, eventType: "job.started", subjectType: "job", subjectId: req.params.id, actorUserId: req.userId, source: "job.workflow", dedupeKey: `job.started:${req.params.id}`, payload: { job_id: req.params.id, started_at: now } });
    await client.query("COMMIT");
    res.json(workflowRunPayload(run));
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("[operations] workflow start failed:", e);
    res.status(500).json({ error: "job_workflow_start_failed" });
  } finally { client.release(); }
});

app.get("/api/jobs/:id/workflow", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  try {
    const row = (await pool.query(`SELECT * FROM job_workflow_runs WHERE company_id = $1 AND job_id = $2`, [req.companyId, req.params.id])).rows[0];
    if (!row) return res.status(404).json({ error: "workflow_not_found" });
    res.json(workflowRunPayload(row));
  } catch (e) { console.error(e); res.status(500).json({ error: "job_workflow_load_failed" }); }
});

app.put("/api/jobs/:id/workflow", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  const snapshot = Array.isArray(req.body?.snapshot) ? req.body.snapshot : [];
  try {
    const row = (await pool.query(`UPDATE job_workflow_runs SET snapshot = $3::jsonb, updated_at = now() WHERE company_id = $1 AND job_id = $2 AND status <> 'completed' RETURNING *`, [req.companyId, req.params.id, JSON.stringify(snapshot)])).rows[0];
    if (!row) return res.status(404).json({ error: "workflow_not_found" });
    res.json(workflowRunPayload(row));
  } catch (e) { console.error(e); res.status(500).json({ error: "job_workflow_update_failed" }); }
});

app.post("/api/jobs/:id/workflow/complete", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  const snapshot = Array.isArray(req.body?.snapshot) ? req.body.snapshot : [];
  const overrideReason = (req.body?.override_reason || "").toString().trim() || null;
  const missing = workflowMissingRequired(snapshot);
  if (missing.length && !overrideReason) return res.status(422).json({ error: "workflow_required_items_missing", missing });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const job = (await client.query(`SELECT * FROM schedule_events WHERE id = $1 AND company_id = $2 FOR UPDATE`, [req.params.id, req.companyId])).rows[0];
    if (!job) { await client.query("ROLLBACK"); return res.status(404).json({ error: "job_not_found" }); }
    const now = new Date();
    await client.query(
      `INSERT INTO job_workflow_runs(id, company_id, job_id, status, started_at, started_by, completed_at, completed_by, override_reason, snapshot)
       VALUES($1, $2, $3, 'completed', COALESCE($4, now()), $5, $4, $5, $6, $7::jsonb)
       ON CONFLICT(company_id, job_id) DO UPDATE
         SET status = 'completed', completed_at = COALESCE(job_workflow_runs.completed_at, EXCLUDED.completed_at),
             completed_by = COALESCE(job_workflow_runs.completed_by, EXCLUDED.completed_by),
             override_reason = EXCLUDED.override_reason, snapshot = EXCLUDED.snapshot, updated_at = now()`,
      [randomUUID(), req.companyId, req.params.id, now, req.userId, overrideReason, JSON.stringify(snapshot)]
    );
    const updated = (await client.query(
      `UPDATE schedule_events SET started_at = COALESCE(started_at, $3), started_by = COALESCE(started_by, $4),
              finished_at = COALESCE(finished_at, $3), finished_by = COALESCE(finished_by, $4), updated_at = now()
       WHERE id = $1 AND company_id = $2
       RETURNING id, title, start_at AS start, end_at AS "end", color, notes,
                 contact_id, reminder_minutes, services, service_items, price_cents, material_cost_cents,
                 company_id, created_by, sales_user_ids, worker_user_ids, started_at, started_by, finished_at, finished_by`,
      [req.params.id, req.companyId, now, req.userId]
    )).rows[0];
    await emitAutomationEvent({ companyId: req.companyId, eventType: "job.completed", subjectType: "job", subjectId: req.params.id, actorUserId: req.userId, source: "job.workflow", dedupeKey: `job.completed:${req.params.id}:${updated.finished_at}`, payload: { job_id: req.params.id, finished_at: updated.finished_at, override: !!overrideReason } });
    await syncAutomationSchedulesForJob(req.companyId, updated);
    await client.query("COMMIT");
    res.json(updated);
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("[operations] workflow complete failed:", e);
    res.status(500).json({ error: "job_workflow_complete_failed" });
  } finally { client.release(); }
});

app.get("/api/job-workflow-templates", authRequired, requireEmployer, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT id, name, scope, service_type, enabled, archived_at, sections FROM job_workflow_templates WHERE company_id = $1 AND archived_at IS NULL ORDER BY updated_at DESC`, [req.companyId]);
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "workflow_templates_failed" }); }
});

app.put("/api/job-workflow-templates/:id", authRequired, requireEmployer, async (req, res) => {
  const { name, scope, service_type, enabled, sections } = req.body || {};
  if (!name) return res.status(400).json({ error: "name_required" });
  try {
    const { rows } = await pool.query(
      `INSERT INTO job_workflow_templates(id, company_id, name, scope, service_type, enabled, sections, created_by)
       VALUES($1, $2, $3, $4, $5, $6, $7::jsonb, $8)
       ON CONFLICT(id) DO UPDATE SET name = EXCLUDED.name, scope = EXCLUDED.scope, service_type = EXCLUDED.service_type, enabled = EXCLUDED.enabled, sections = EXCLUDED.sections, updated_at = now()
       WHERE job_workflow_templates.company_id = $2
       RETURNING id, name, scope, service_type, enabled, archived_at, sections`,
      [req.params.id, req.companyId, name, scope || "company_default", service_type || null, toBool(enabled, true), JSON.stringify(Array.isArray(sections) ? sections : []), req.userId]
    );
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "workflow_template_save_failed" }); }
});

app.delete("/api/job-workflow-templates/:id", authRequired, requireEmployer, async (req, res) => {
  try {
    await pool.query(`UPDATE job_workflow_templates SET archived_at = now(), updated_at = now() WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId]);
    res.status(204).end();
  } catch (e) { console.error(e); res.status(500).json({ error: "workflow_template_archive_failed" }); }
});

app.get("/api/jobs/:id/workflow/additions", authRequired, requireEmployer, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  try {
    const job = (await pool.query(`SELECT id FROM schedule_events WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId])).rows[0];
    if (!job) return res.status(404).json({ error: "job_not_found" });
    const row = (await pool.query(`SELECT sections FROM job_workflow_job_additions WHERE company_id = $1 AND job_id = $2`, [req.companyId, req.params.id])).rows[0];
    res.json({ sections: row && Array.isArray(row.sections) ? row.sections : [] });
  } catch (e) { console.error(e); res.status(500).json({ error: "workflow_job_additions_failed" }); }
});

app.put("/api/jobs/:id/workflow/additions", authRequired, requireEmployer, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  const sections = Array.isArray(req.body && req.body.sections) ? req.body.sections : [];
  try {
    const job = (await pool.query(`SELECT id FROM schedule_events WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId])).rows[0];
    if (!job) return res.status(404).json({ error: "job_not_found" });
    const running = (await pool.query(`SELECT status FROM job_workflow_runs WHERE company_id = $1 AND job_id = $2`, [req.companyId, req.params.id])).rows[0];
    if (running && running.status === "completed") return res.status(409).json({ error: "workflow_completed" });
    const { rows } = await pool.query(
      `INSERT INTO job_workflow_job_additions(id, company_id, job_id, sections, created_by, updated_by)
       VALUES($1, $2, $3, $4::jsonb, $5, $5)
       ON CONFLICT(company_id, job_id) DO UPDATE
         SET sections = EXCLUDED.sections, updated_by = EXCLUDED.updated_by, updated_at = now()
       RETURNING sections`,
      [randomUUID(), req.companyId, req.params.id, JSON.stringify(sections), req.userId]
    );
    res.json({ sections: Array.isArray(rows[0].sections) ? rows[0].sections : [] });
  } catch (e) { console.error(e); res.status(500).json({ error: "workflow_job_additions_save_failed" }); }
});

app.get("/api/jobs/:id/photos", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  try {
    const allowed = (await pool.query(`SELECT contact_id FROM schedule_events WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId])).rows[0];
    if (!allowed) return res.status(404).json({ error: "job_not_found" });
    const { rows } = await pool.query(`SELECT id, job_id, contact_id, category, caption, object_key, thumbnail_key, uploaded_by, created_at FROM job_photos WHERE company_id = $1 AND job_id = $2 ORDER BY created_at DESC`, [req.companyId, req.params.id]);
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "job_photos_failed" }); }
});

app.post("/api/jobs/:id/photos", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  const { category, caption, object_key, thumbnail_key, workflow_item_id } = req.body || {};
  if (!object_key) return res.status(400).json({ error: "object_key_required" });
  try {
    const job = (await pool.query(`SELECT contact_id FROM schedule_events WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId])).rows[0];
    if (!job) return res.status(404).json({ error: "job_not_found" });
    if (!object_key.toString().startsWith(`${req.companyId}/`)) return res.status(403).json({ error: "media_forbidden" });
    const { rows } = await pool.query(
      `INSERT INTO job_photos(id, company_id, job_id, contact_id, category, caption, object_key, thumbnail_key, workflow_item_id, uploaded_by)
       VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING id, job_id, contact_id, category, caption, object_key, thumbnail_key, uploaded_by, created_at`,
      [randomUUID(), req.companyId, req.params.id, job.contact_id || null, category || "general", caption || null, object_key, thumbnail_key || null, workflow_item_id || null, req.userId]
    );
    res.status(201).json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "job_photo_save_failed" }); }
});

// ---------- OPERATIONS: EQUIPMENT & MATERIALS ----------
async function recordAssetHistory(client, companyId, itemId, eventType, actorUserId, summary, metadata = {}) {
  await client.query(
    `INSERT INTO equipment_asset_history(id, company_id, item_id, event_type, actor_user_id, summary, metadata)
     VALUES($1,$2,$3,$4,$5,$6,$7::jsonb)`,
    [randomUUID(), companyId, itemId, eventType, actorUserId || null, summary, JSON.stringify(metadata || {})]
  );
}

function inventoryDeltaForType(type, qty) {
  if (["received", "returned", "recount_correction"].includes(type)) return qty;
  if (["used_on_job", "damaged", "lost", "disposed"].includes(type)) return -qty;
  return 0;
}

app.get("/api/operations/inventory/locations", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  try {
    await pool.query(`INSERT INTO inventory_locations(id, company_id, name, kind) VALUES($1, $2, 'Shop', 'shop') ON CONFLICT(id) DO NOTHING`, [`${req.companyId}:shop`, req.companyId]);
    const { rows } = await pool.query(`SELECT id, name, kind, active FROM inventory_locations WHERE company_id = $1 ORDER BY active DESC, name`, [req.companyId]);
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "inventory_locations_failed" }); }
});

app.get("/api/operations/inventory/items", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  try {
    const { rows } = await pool.query(`SELECT id, name, item_type, tracking_mode, category, unit, quantity_on_hand::float8 AS quantity_on_hand, reorder_point::float8 AS reorder_point, cost_per_unit_cents, status, location_id, assigned_user_id, notes FROM inventory_items WHERE company_id = $1 ORDER BY updated_at DESC`, [req.companyId]);
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "inventory_items_failed" }); }
});

app.put("/api/operations/inventory/items/:id", authRequired, requireEmployer, async (req, res) => {
  const { name, item_type, tracking_mode, category, unit, reorder_point, cost_per_unit_cents, status, location_id, assigned_user_id, notes } = req.body || {};
  if (!name) return res.status(400).json({ error: "name_required" });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const before = (await client.query(`SELECT * FROM inventory_items WHERE id = $1 AND company_id = $2 FOR UPDATE`, [req.params.id, req.companyId])).rows[0];
    const { rows } = await client.query(
      `INSERT INTO inventory_items(id, company_id, name, item_type, tracking_mode, category, unit, reorder_point, cost_per_unit_cents, status, location_id, assigned_user_id, notes)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
       ON CONFLICT(id) DO UPDATE SET name = EXCLUDED.name, item_type = EXCLUDED.item_type, tracking_mode = EXCLUDED.tracking_mode, category = EXCLUDED.category, unit = EXCLUDED.unit, reorder_point = EXCLUDED.reorder_point, cost_per_unit_cents = EXCLUDED.cost_per_unit_cents, status = EXCLUDED.status, location_id = EXCLUDED.location_id, assigned_user_id = EXCLUDED.assigned_user_id, notes = EXCLUDED.notes, updated_at = now()
       WHERE inventory_items.company_id = $2
       RETURNING id, name, item_type, tracking_mode, category, unit, quantity_on_hand::float8 AS quantity_on_hand, reorder_point::float8 AS reorder_point, cost_per_unit_cents, status, location_id, assigned_user_id, notes`,
      [req.params.id, req.companyId, name, item_type || "material", tracking_mode || "quantity", category || null, unit || "each", reorder_point ?? null, cost_per_unit_cents ?? null, status || "available", location_id || null, assigned_user_id || null, notes || null]
    );
    if (!before) {
      await recordAssetHistory(client, req.companyId, req.params.id, "asset_created", req.userId, `Added ${name}`, { status: status || "available", location_id: location_id || null });
    } else {
      if ((before.status || "") !== (status || "available")) await recordAssetHistory(client, req.companyId, req.params.id, "status_changed", req.userId, `Status changed to ${(status || "available").replace(/_/g, " ")}`, { from: before.status, to: status || "available" });
      if ((before.location_id || "") !== (location_id || "")) await recordAssetHistory(client, req.companyId, req.params.id, "moved_location", req.userId, "Location changed", { from: before.location_id || null, to: location_id || null });
      if ((before.assigned_user_id || "") !== (assigned_user_id || "")) await recordAssetHistory(client, req.companyId, req.params.id, "assigned", req.userId, "Assignment changed", { from: before.assigned_user_id || null, to: assigned_user_id || null });
    }
    await client.query("COMMIT");
    res.json(rows[0]);
  } catch (e) {
    await client.query("ROLLBACK");
    console.error(e); res.status(500).json({ error: "inventory_item_save_failed" });
  } finally { client.release(); }
});

app.post("/api/operations/inventory/transactions", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  const { item_id, transaction_type, quantity, from_location_id, to_location_id, job_id, note, idempotency_key, reverses_transaction_id } = req.body || {};
  const qty = Number(quantity);
  if (!item_id || !transaction_type || !Number.isFinite(qty) || qty <= 0) return res.status(400).json({ error: "invalid_inventory_transaction" });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const idempotencyKey = cleanString(idempotency_key, 160) || null;
    if (idempotencyKey) {
      const existing = (await client.query(`SELECT id, item_id, transaction_type, quantity::float8 AS quantity, from_location_id, to_location_id, job_id, employee_id, note, cost_snapshot_cents, created_at FROM inventory_transactions WHERE company_id = $1 AND idempotency_key = $2 LIMIT 1`, [req.companyId, idempotencyKey])).rows[0];
      if (existing) {
        await client.query("COMMIT");
        return res.json(existing);
      }
    }
    const item = (await client.query(`SELECT * FROM inventory_items WHERE id = $1 AND company_id = $2 FOR UPDATE`, [item_id, req.companyId])).rows[0];
    if (!item) { await client.query("ROLLBACK"); return res.status(404).json({ error: "item_not_found" }); }
    const delta = inventoryDeltaForType(transaction_type, qty);
    if (item.tracking_mode === "quantity" && Number(item.quantity_on_hand) + delta < 0) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "insufficient_inventory" });
    }
    const row = (await client.query(`INSERT INTO inventory_transactions(id, company_id, item_id, transaction_type, quantity, from_location_id, to_location_id, job_id, employee_id, note, cost_snapshot_cents, idempotency_key, reverses_transaction_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id, item_id, transaction_type, quantity::float8 AS quantity, from_location_id, to_location_id, job_id, employee_id, note, cost_snapshot_cents, created_at`, [randomUUID(), req.companyId, item_id, transaction_type, qty, from_location_id || null, to_location_id || null, job_id || null, req.userId, note || null, item.cost_per_unit_cents || null, idempotencyKey, reverses_transaction_id || null])).rows[0];
    if (delta !== 0) await client.query(`UPDATE inventory_items SET quantity_on_hand = quantity_on_hand + $3, updated_at = now() WHERE id = $1 AND company_id = $2`, [item_id, req.companyId, delta]);
    if (job_id && transaction_type === "used_on_job" && item.cost_per_unit_cents) {
      await client.query(`UPDATE schedule_events SET material_cost_cents = COALESCE(material_cost_cents, 0) + $3, updated_at = now() WHERE id = $1 AND company_id = $2`, [job_id, req.companyId, Math.round(qty * Number(item.cost_per_unit_cents))]);
    }
    await client.query("COMMIT");
    res.status(201).json(row);
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("[operations] inventory transaction failed:", e);
    res.status(500).json({ error: "inventory_transaction_failed" });
  } finally { client.release(); }
});

app.get("/api/operations/jobs/:id/material-usages", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  try {
    const { rows } = await pool.query(
      `SELECT mu.id, mu.job_id, mu.item_id, ii.name AS item_name, mu.location_id, mu.quantity::float8 AS quantity,
              mu.unit_cost_snapshot_cents, mu.current_transaction_id, mu.status, mu.note, mu.created_by, mu.updated_by, mu.created_at, mu.updated_at
         FROM material_usages mu
         JOIN inventory_items ii ON ii.id = mu.item_id AND ii.company_id = mu.company_id
        WHERE mu.company_id = $1 AND mu.job_id = $2
        ORDER BY mu.created_at DESC`,
      [req.companyId, req.params.id]
    );
    res.json(rows);
  } catch (e) { console.error("[operations] material usages failed:", e); res.status(500).json({ error: "material_usages_failed" }); }
});

app.post("/api/operations/jobs/:id/material-usages", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  const { item_id, location_id, quantity, note, idempotency_key } = req.body || {};
  const qty = Number(quantity);
  if (!item_id || !Number.isFinite(qty) || qty <= 0) return res.status(400).json({ error: "invalid_material_usage" });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const key = cleanString(idempotency_key, 180) || `material-use:${req.params.id}:${item_id}:${location_id || ""}:${qty}:${cleanString(note, 200) || ""}`;
    const existing = (await client.query(`SELECT id FROM material_usages WHERE company_id = $1 AND idempotency_key = $2`, [req.companyId, key])).rows[0];
    if (existing) {
      await client.query("COMMIT");
      return res.json((await pool.query(`SELECT mu.id, mu.job_id, mu.item_id, ii.name AS item_name, mu.location_id, mu.quantity::float8 AS quantity, mu.unit_cost_snapshot_cents, mu.current_transaction_id, mu.status, mu.note, mu.created_by, mu.updated_by, mu.created_at, mu.updated_at FROM material_usages mu JOIN inventory_items ii ON ii.id = mu.item_id AND ii.company_id = mu.company_id WHERE mu.company_id = $1 AND mu.id = $2`, [req.companyId, existing.id])).rows[0]);
    }
    const item = (await client.query(`SELECT * FROM inventory_items WHERE id = $1 AND company_id = $2 FOR UPDATE`, [item_id, req.companyId])).rows[0];
    if (!item) { await client.query("ROLLBACK"); return res.status(404).json({ error: "item_not_found" }); }
    if (item.tracking_mode === "quantity" && Number(item.quantity_on_hand) - qty < 0) { await client.query("ROLLBACK"); return res.status(409).json({ error: "insufficient_inventory" }); }
    const cost = item.cost_per_unit_cents == null ? null : Number(item.cost_per_unit_cents);
    const tx = (await client.query(`INSERT INTO inventory_transactions(id, company_id, item_id, transaction_type, quantity, from_location_id, job_id, employee_id, note, cost_snapshot_cents, idempotency_key) VALUES($1,$2,$3,'used_on_job',$4,$5,$6,$7,$8,$9,$10) RETURNING id`, [randomUUID(), req.companyId, item_id, qty, location_id || null, req.params.id, req.userId, cleanString(note, 1000) || null, cost, `${key}:tx`])).rows[0];
    await client.query(`UPDATE inventory_items SET quantity_on_hand = quantity_on_hand - $3, updated_at = now() WHERE id = $1 AND company_id = $2`, [item_id, req.companyId, qty]);
    if (cost != null) await client.query(`UPDATE schedule_events SET material_cost_cents = COALESCE(material_cost_cents, 0) + $3, updated_at = now() WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId, Math.round(qty * cost)]);
    const row = (await client.query(`INSERT INTO material_usages(id, company_id, job_id, item_id, location_id, quantity, unit_cost_snapshot_cents, current_transaction_id, status, note, created_by, updated_by, idempotency_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'active',$9,$10,$10,$11) RETURNING id`, [randomUUID(), req.companyId, req.params.id, item_id, location_id || null, qty, cost, tx.id, cleanString(note, 1000) || null, req.userId, key])).rows[0];
    await client.query("COMMIT");
    const out = (await pool.query(`SELECT mu.id, mu.job_id, mu.item_id, ii.name AS item_name, mu.location_id, mu.quantity::float8 AS quantity, mu.unit_cost_snapshot_cents, mu.current_transaction_id, mu.status, mu.note, mu.created_by, mu.updated_by, mu.created_at, mu.updated_at FROM material_usages mu JOIN inventory_items ii ON ii.id = mu.item_id AND ii.company_id = mu.company_id WHERE mu.company_id = $1 AND mu.id = $2`, [req.companyId, row.id])).rows[0];
    res.status(201).json(out);
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("[operations] material usage create failed:", e);
    res.status(500).json({ error: "material_usage_create_failed" });
  } finally { client.release(); }
});

app.patch("/api/operations/material-usages/:id", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  const mode = req.body?.delete ? "delete" : "edit";
  const newQty = Number(req.body?.quantity);
  if (mode === "edit" && (!Number.isFinite(newQty) || newQty <= 0)) return res.status(400).json({ error: "invalid_quantity" });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const key = cleanString(req.body?.idempotency_key, 180) || `material-correct:${req.params.id}:${mode}:${Number.isFinite(newQty) ? newQty : 0}`;
    const existingTx = (await client.query(`SELECT id FROM inventory_transactions WHERE company_id = $1 AND idempotency_key = ANY($2::text[]) LIMIT 1`, [req.companyId, [`${key}:replacement`, `${key}:reversal`]])).rows[0];
    if (existingTx) {
      await client.query("COMMIT");
      return res.json((await pool.query(`SELECT mu.id, mu.job_id, mu.item_id, ii.name AS item_name, mu.location_id, mu.quantity::float8 AS quantity, mu.unit_cost_snapshot_cents, mu.current_transaction_id, mu.status, mu.note, mu.created_by, mu.updated_by, mu.created_at, mu.updated_at FROM material_usages mu JOIN inventory_items ii ON ii.id = mu.item_id AND ii.company_id = mu.company_id WHERE mu.company_id = $1 AND mu.id = $2`, [req.companyId, req.params.id])).rows[0]);
    }
    const usage = (await client.query(`SELECT * FROM material_usages WHERE id = $1 AND company_id = $2 FOR UPDATE`, [req.params.id, req.companyId])).rows[0];
    if (!usage || usage.status !== "active") { await client.query("ROLLBACK"); return res.status(404).json({ error: "material_usage_not_found" }); }
    const reverseQty = Number(usage.quantity || 0);
    const cost = usage.unit_cost_snapshot_cents == null ? null : Number(usage.unit_cost_snapshot_cents);
    const reversal = (await client.query(`INSERT INTO inventory_transactions(id, company_id, item_id, transaction_type, quantity, from_location_id, job_id, employee_id, note, cost_snapshot_cents, idempotency_key, reverses_transaction_id) VALUES($1,$2,$3,'returned',$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`, [randomUUID(), req.companyId, usage.item_id, reverseQty, usage.location_id || null, usage.job_id, req.userId, "Material usage correction reversal", cost, `${key}:reversal`, usage.current_transaction_id || null])).rows[0];
    await client.query(`UPDATE inventory_items SET quantity_on_hand = quantity_on_hand + $3, updated_at = now() WHERE id = $1 AND company_id = $2`, [usage.item_id, req.companyId, reverseQty]);
    if (cost != null) await client.query(`UPDATE schedule_events SET material_cost_cents = GREATEST(0, COALESCE(material_cost_cents, 0) - $3), updated_at = now() WHERE id = $1 AND company_id = $2`, [usage.job_id, req.companyId, Math.round(reverseQty * cost)]);
    if (mode === "delete") {
      await client.query(`UPDATE material_usages SET status = 'deleted', quantity = 0, current_transaction_id = $3, updated_by = $4, updated_at = now() WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId, reversal.id, req.userId]);
    } else {
      const item = (await client.query(`SELECT * FROM inventory_items WHERE id = $1 AND company_id = $2 FOR UPDATE`, [usage.item_id, req.companyId])).rows[0];
      if (item.tracking_mode === "quantity" && Number(item.quantity_on_hand) - newQty < 0) { await client.query("ROLLBACK"); return res.status(409).json({ error: "insufficient_inventory" }); }
      const replacement = (await client.query(`INSERT INTO inventory_transactions(id, company_id, item_id, transaction_type, quantity, from_location_id, job_id, employee_id, note, cost_snapshot_cents, idempotency_key) VALUES($1,$2,$3,'used_on_job',$4,$5,$6,$7,$8,$9,$10) RETURNING id`, [randomUUID(), req.companyId, usage.item_id, newQty, usage.location_id || null, usage.job_id, req.userId, cleanString(req.body?.note, 1000) || usage.note, cost, `${key}:replacement`])).rows[0];
      await client.query(`UPDATE inventory_items SET quantity_on_hand = quantity_on_hand - $3, updated_at = now() WHERE id = $1 AND company_id = $2`, [usage.item_id, req.companyId, newQty]);
      if (cost != null) await client.query(`UPDATE schedule_events SET material_cost_cents = COALESCE(material_cost_cents, 0) + $3, updated_at = now() WHERE id = $1 AND company_id = $2`, [usage.job_id, req.companyId, Math.round(newQty * cost)]);
      await client.query(`UPDATE material_usages SET quantity = $3, note = COALESCE($4, note), current_transaction_id = $5, updated_by = $6, updated_at = now() WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId, newQty, cleanString(req.body?.note, 1000) || null, replacement.id, req.userId]);
    }
    await client.query("COMMIT");
    const out = (await pool.query(`SELECT mu.id, mu.job_id, mu.item_id, ii.name AS item_name, mu.location_id, mu.quantity::float8 AS quantity, mu.unit_cost_snapshot_cents, mu.current_transaction_id, mu.status, mu.note, mu.created_by, mu.updated_by, mu.created_at, mu.updated_at FROM material_usages mu JOIN inventory_items ii ON ii.id = mu.item_id AND ii.company_id = mu.company_id WHERE mu.company_id = $1 AND mu.id = $2`, [req.companyId, req.params.id])).rows[0];
    res.json(out);
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("[operations] material usage correction failed:", e);
    res.status(500).json({ error: "material_usage_correction_failed" });
  } finally { client.release(); }
});

app.get("/api/operations/requests", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  try {
    const { rows } = await pool.query(`SELECT id, request_type, item_id, item_name, quantity::float8 AS quantity, urgency, explanation, status, requester_id, owner_response, created_at FROM equipment_requests WHERE company_id = $1 AND ($2 = true OR requester_id = $3) ORDER BY CASE urgency WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 ELSE 2 END, created_at ASC`, [req.companyId, req.role === "employer", req.userId]);
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "equipment_requests_failed" }); }
});

app.post("/api/operations/requests", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  const { request_type, item_id, item_name, quantity, urgency, explanation } = req.body || {};
  if (!request_type || !explanation) return res.status(400).json({ error: "invalid_request" });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { rows } = await client.query(`INSERT INTO equipment_requests(id, company_id, request_type, item_id, item_name, quantity, urgency, explanation, requester_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id, request_type, item_id, item_name, quantity::float8 AS quantity, urgency, explanation, status, requester_id, owner_response, created_at`, [randomUUID(), req.companyId, request_type, item_id || null, item_name || null, quantity ?? null, urgency || "normal", explanation, req.userId]);
    if (item_id && ["report_broken", "report_damaged", "report_lost", "needs_inspection"].includes(request_type)) {
      await recordAssetHistory(client, req.companyId, item_id, request_type, req.userId, `${request_type.replace(/_/g, " ")}: ${cleanString(explanation, 180)}`, { request_id: rows[0].id, urgency: urgency || "normal" });
    }
    await client.query("COMMIT");
    res.status(201).json(rows[0]);
  } catch (e) {
    await client.query("ROLLBACK");
    console.error(e); res.status(500).json({ error: "equipment_request_failed" });
  } finally { client.release(); }
});

app.patch("/api/operations/requests/:id", authRequired, requireEmployer, async (req, res) => {
  const { status, owner_response } = req.body || {};
  try {
    const { rows } = await pool.query(`UPDATE equipment_requests SET status = COALESCE($3, status), owner_response = COALESCE($4, owner_response), updated_at = now() WHERE id = $1 AND company_id = $2 RETURNING id, request_type, item_id, item_name, quantity::float8 AS quantity, urgency, explanation, status, requester_id, owner_response, created_at`, [req.params.id, req.companyId, status || null, owner_response || null]);
    if (!rows[0]) return res.status(404).json({ error: "request_not_found" });
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "equipment_request_update_failed" }); }
});

app.get("/api/operations/inventory/items/:id/history", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  try {
    const item = (await pool.query(`SELECT id FROM inventory_items WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId])).rows[0];
    if (!item) return res.status(404).json({ error: "item_not_found" });
    let { rows } = await pool.query(`SELECT id, item_id, event_type, actor_user_id, summary, metadata, created_at FROM equipment_asset_history WHERE company_id = $1 AND item_id = $2 ORDER BY created_at DESC LIMIT 100`, [req.companyId, req.params.id]);
    if (!rows.length) {
      await pool.query(
        `INSERT INTO equipment_asset_history(id, company_id, item_id, event_type, actor_user_id, summary, metadata)
         VALUES($1,$2,$3,'existing_asset_imported',$4,'Existing asset imported','{}'::jsonb)
         ON CONFLICT DO NOTHING`,
        [randomUUID(), req.companyId, req.params.id, req.userId]
      );
      rows = (await pool.query(`SELECT id, item_id, event_type, actor_user_id, summary, metadata, created_at FROM equipment_asset_history WHERE company_id = $1 AND item_id = $2 ORDER BY created_at DESC LIMIT 100`, [req.companyId, req.params.id])).rows;
    }
    res.json(rows);
  } catch (e) { console.error("[operations] asset history failed:", e); res.status(500).json({ error: "asset_history_failed" }); }
});

function repairStatusToAssetStatus(status) {
  if (["approved", "scheduled", "reported"].includes(status)) return "broken";
  if (["in_repair", "waiting_for_parts"].includes(status)) return "under_repair";
  if (status === "not_repairable") return "broken";
  if (status === "completed") return "available";
  return null;
}

async function repairPayload(client, companyId, id) {
  return (await client.query(
    `SELECT r.id, r.item_id, ii.name AS item_name, r.request_id, r.reported_by, r.created_by, r.assigned_user_id, r.vendor,
            r.problem, r.diagnosis, r.status, r.priority, r.estimated_cost_cents, r.actual_cost_cents,
            r.opened_at, r.scheduled_at, r.started_at, r.completed_at, r.resolution_notes, r.created_at, r.updated_at
       FROM equipment_repairs r
       JOIN inventory_items ii ON ii.id = r.item_id AND ii.company_id = r.company_id
      WHERE r.company_id = $1 AND r.id = $2`,
    [companyId, id]
  )).rows[0];
}

async function inventoryCountSubmissionPayload(client, companyId, id, userId = null, isEmployer = true) {
  const { rows } = await client.query(
    `SELECT s.id, s.schedule_id, s.location_id, l.name AS location_name, s.assigned_user_id, s.status, s.due_date::text,
            s.submitted_by, s.submitted_at, s.reviewed_by, s.reviewed_at, s.review_note,
            COALESCE(jsonb_agg(jsonb_build_object('id', si.id, 'item_id', si.item_id, 'expected_quantity', si.expected_quantity::float8, 'counted_quantity', si.counted_quantity::float8, 'variance', si.variance::float8, 'note', si.note, 'item_name', ii.name) ORDER BY ii.name) FILTER (WHERE si.id IS NOT NULL), '[]'::jsonb) AS items
       FROM inventory_count_submissions s
       LEFT JOIN inventory_locations l ON l.id = s.location_id AND l.company_id = s.company_id
       LEFT JOIN inventory_count_submission_items si ON si.submission_id = s.id
       LEFT JOIN inventory_items ii ON ii.id = si.item_id
      WHERE s.company_id = $1 AND s.id = $2 AND ($3 = true OR s.assigned_user_id = $4 OR s.submitted_by = $4)
      GROUP BY s.id, l.name
      LIMIT 1`,
    [companyId, id, isEmployer, userId]
  );
  return rows[0];
}

app.get("/api/operations/repairs", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  try {
    const { rows } = await pool.query(
      `SELECT r.id, r.item_id, ii.name AS item_name, r.request_id, r.reported_by, r.created_by, r.assigned_user_id, r.vendor,
              r.problem, r.diagnosis, r.status, r.priority, r.estimated_cost_cents, r.actual_cost_cents,
              r.opened_at, r.scheduled_at, r.started_at, r.completed_at, r.resolution_notes, r.created_at, r.updated_at
         FROM equipment_repairs r
         JOIN inventory_items ii ON ii.id = r.item_id AND ii.company_id = r.company_id
        WHERE r.company_id = $1
        ORDER BY CASE r.priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 ELSE 2 END, r.updated_at DESC`,
      [req.companyId]
    );
    res.json(rows);
  } catch (e) { console.error("[operations] repairs failed:", e); res.status(500).json({ error: "repairs_failed" }); }
});

app.post("/api/operations/repairs", authRequired, requireEmployer, async (req, res) => {
  const { item_id, request_id, assigned_user_id, vendor, problem, diagnosis, priority, estimated_cost_cents, scheduled_at } = req.body || {};
  if (!item_id || !problem) return res.status(400).json({ error: "repair_fields_required" });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const item = (await client.query(`SELECT id, name FROM inventory_items WHERE id = $1 AND company_id = $2 FOR UPDATE`, [item_id, req.companyId])).rows[0];
    if (!item) { await client.query("ROLLBACK"); return res.status(404).json({ error: "item_not_found" }); }
    const request = request_id ? (await client.query(`SELECT requester_id, explanation FROM equipment_requests WHERE id = $1 AND company_id = $2`, [request_id, req.companyId])).rows[0] : null;
    const id = randomUUID();
    await client.query(
      `INSERT INTO equipment_repairs(id, company_id, item_id, request_id, reported_by, created_by, assigned_user_id, vendor, problem, diagnosis, priority, estimated_cost_cents, scheduled_at)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [id, req.companyId, item_id, request_id || null, request?.requester_id || null, req.userId, assigned_user_id || null, cleanString(vendor, 200) || null, cleanString(problem, 2000), cleanString(diagnosis, 2000) || null, priority || "normal", estimated_cost_cents ?? null, scheduled_at || null]
    );
    await client.query(`UPDATE inventory_items SET status = 'broken', updated_at = now() WHERE id = $1 AND company_id = $2`, [item_id, req.companyId]);
    if (request_id) await client.query(`UPDATE equipment_requests SET status = 'under_review', updated_at = now() WHERE id = $1 AND company_id = $2`, [request_id, req.companyId]);
    await recordAssetHistory(client, req.companyId, item_id, "repair_created", req.userId, `Repair created: ${cleanString(problem, 180)}`, { repair_id: id, request_id: request_id || null });
    await client.query("COMMIT");
    res.status(201).json(await repairPayload(pool, req.companyId, id));
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("[operations] repair create failed:", e);
    res.status(500).json({ error: "repair_create_failed" });
  } finally { client.release(); }
});

app.patch("/api/operations/repairs/:id", authRequired, requireEmployer, async (req, res) => {
  const allowedStatuses = new Set(["reported", "approved", "scheduled", "in_repair", "waiting_for_parts", "completed", "not_repairable", "cancelled"]);
  const status = req.body?.status && allowedStatuses.has(req.body.status) ? req.body.status : null;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const before = (await client.query(`SELECT * FROM equipment_repairs WHERE id = $1 AND company_id = $2 FOR UPDATE`, [req.params.id, req.companyId])).rows[0];
    if (!before) { await client.query("ROLLBACK"); return res.status(404).json({ error: "repair_not_found" }); }
    const startedAt = status === "in_repair" && !before.started_at ? new Date() : before.started_at;
    const completedAt = ["completed", "not_repairable"].includes(status) && !before.completed_at ? new Date() : before.completed_at;
    await client.query(
      `UPDATE equipment_repairs
          SET assigned_user_id = COALESCE($3, assigned_user_id),
              vendor = COALESCE($4, vendor),
              diagnosis = COALESCE($5, diagnosis),
              status = COALESCE($6, status),
              priority = COALESCE($7, priority),
              estimated_cost_cents = COALESCE($8, estimated_cost_cents),
              actual_cost_cents = COALESCE($9, actual_cost_cents),
              scheduled_at = COALESCE($10, scheduled_at),
              started_at = $11,
              completed_at = $12,
              resolution_notes = COALESCE($13, resolution_notes),
              updated_at = now()
        WHERE id = $1 AND company_id = $2`,
      [req.params.id, req.companyId, req.body?.assigned_user_id || null, cleanString(req.body?.vendor, 200) || null, cleanString(req.body?.diagnosis, 2000) || null, status, req.body?.priority || null, req.body?.estimated_cost_cents ?? null, req.body?.actual_cost_cents ?? null, req.body?.scheduled_at || null, startedAt, completedAt, cleanString(req.body?.resolution_notes, 2000) || null]
    );
    if (status && status !== before.status) {
      const assetStatus = repairStatusToAssetStatus(status);
      if (assetStatus) await client.query(`UPDATE inventory_items SET status = $3, updated_at = now() WHERE id = $1 AND company_id = $2`, [before.item_id, req.companyId, assetStatus]);
      await recordAssetHistory(client, req.companyId, before.item_id, `repair_${status}`, req.userId, `Repair ${status.replace(/_/g, " ")}`, { repair_id: req.params.id, previous_status: before.status });
    }
    await client.query("COMMIT");
    res.json(await repairPayload(pool, req.companyId, req.params.id));
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("[operations] repair update failed:", e);
    res.status(500).json({ error: "repair_update_failed" });
  } finally { client.release(); }
});

app.get("/api/operations/inventory-counts/schedules", authRequired, requireEmployer, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT id, name, location_id, assigned_user_id, frequency, due_date::text, due_time, reminder_minutes, variance_threshold::float8 AS variance_threshold, approval_required, enabled, created_by, created_at, updated_at FROM inventory_count_schedules WHERE company_id = $1 ORDER BY enabled DESC, name`, [req.companyId]);
    res.json(rows);
  } catch (e) { console.error("[operations] count schedules failed:", e); res.status(500).json({ error: "count_schedules_failed" }); }
});

app.put("/api/operations/inventory-counts/schedules/:id", authRequired, requireEmployer, async (req, res) => {
  const { name, location_id, assigned_user_id, frequency, due_date, due_time, reminder_minutes, variance_threshold, approval_required, enabled } = req.body || {};
  if (!name || !location_id) return res.status(400).json({ error: "count_schedule_fields_required" });
  try {
    const { rows } = await pool.query(
      `INSERT INTO inventory_count_schedules(id, company_id, name, location_id, assigned_user_id, frequency, due_date, due_time, reminder_minutes, variance_threshold, approval_required, enabled, created_by)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
       ON CONFLICT(id) DO UPDATE SET name = EXCLUDED.name, location_id = EXCLUDED.location_id, assigned_user_id = EXCLUDED.assigned_user_id, frequency = EXCLUDED.frequency, due_date = EXCLUDED.due_date, due_time = EXCLUDED.due_time, reminder_minutes = EXCLUDED.reminder_minutes, variance_threshold = EXCLUDED.variance_threshold, approval_required = EXCLUDED.approval_required, enabled = EXCLUDED.enabled, updated_at = now()
       WHERE inventory_count_schedules.company_id = $2
       RETURNING id, name, location_id, assigned_user_id, frequency, due_date::text, due_time, reminder_minutes, variance_threshold::float8 AS variance_threshold, approval_required, enabled, created_by, created_at, updated_at`,
      [req.params.id, req.companyId, name, location_id, assigned_user_id || null, frequency || "weekly", due_date || null, due_time || null, reminder_minutes ?? null, Number(variance_threshold || 0), toBool(approval_required, true), toBool(enabled, true), req.userId]
    );
    res.json(rows[0]);
  } catch (e) { console.error("[operations] count schedule save failed:", e); res.status(500).json({ error: "count_schedule_save_failed" }); }
});

app.post("/api/operations/inventory-counts/schedules/:id/generate", authRequired, requireEmployer, async (req, res) => {
  const due = (req.body?.due_date || new Date().toISOString().slice(0, 10)).toString().slice(0, 10);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const schedule = (await client.query(`SELECT * FROM inventory_count_schedules WHERE id = $1 AND company_id = $2 AND enabled = true FOR UPDATE`, [req.params.id, req.companyId])).rows[0];
    if (!schedule) { await client.query("ROLLBACK"); return res.status(404).json({ error: "count_schedule_not_found" }); }
    const submissionId = `${req.companyId}:${schedule.id}:${due}`;
    const submission = (await client.query(
      `INSERT INTO inventory_count_submissions(id, company_id, schedule_id, location_id, assigned_user_id, status, due_date)
       VALUES($1,$2,$3,$4,$5,'draft',$6::date)
       ON CONFLICT(company_id, schedule_id, due_date) DO UPDATE SET updated_at = now()
       RETURNING id, schedule_id, location_id, assigned_user_id, status, due_date::text, submitted_by, submitted_at, reviewed_by, reviewed_at, review_note`,
      [submissionId, req.companyId, schedule.id, schedule.location_id, schedule.assigned_user_id || null, due]
    )).rows[0];
    const taskId = `inventory-count:${submissionId}`;
    await client.query(
      `INSERT INTO todo_tasks(id, user_id, title, detail, creator_id, assignee_ids, due_date, priority, status, linked_inventory_count_id, reminders, subtasks, completed, completion_note_required)
       VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,'normal','open',$8,'[]'::jsonb,'[]'::jsonb,false,false)
       ON CONFLICT(id) DO UPDATE SET due_date = EXCLUDED.due_date, assignee_ids = EXCLUDED.assignee_ids, linked_inventory_count_id = EXCLUDED.linked_inventory_count_id, updated_at = now()`,
      [taskId, req.userId, `Inventory Recount — ${schedule.name}`, "Count inventory and submit variances for owner review.", req.userId, JSON.stringify(schedule.assigned_user_id ? [schedule.assigned_user_id] : []), due, submission.id]
    );
    await client.query("COMMIT");
    res.status(201).json(await inventoryCountSubmissionPayload(pool, req.companyId, submission.id, req.userId, true));
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("[operations] count generate failed:", e);
    res.status(500).json({ error: "count_generate_failed" });
  } finally { client.release(); }
});

app.get("/api/operations/inventory-counts/submissions", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  try {
    const submissions = await pool.query(
      `SELECT s.id, s.schedule_id, s.location_id, l.name AS location_name, s.assigned_user_id, s.status, s.due_date::text,
              s.submitted_by, s.submitted_at, s.reviewed_by, s.reviewed_at, s.review_note,
              COALESCE(jsonb_agg(jsonb_build_object('id', si.id, 'item_id', si.item_id, 'expected_quantity', si.expected_quantity::float8, 'counted_quantity', si.counted_quantity::float8, 'variance', si.variance::float8, 'note', si.note, 'item_name', ii.name) ORDER BY ii.name) FILTER (WHERE si.id IS NOT NULL), '[]'::jsonb) AS items
         FROM inventory_count_submissions s
         LEFT JOIN inventory_locations l ON l.id = s.location_id AND l.company_id = s.company_id
         LEFT JOIN inventory_count_submission_items si ON si.submission_id = s.id
         LEFT JOIN inventory_items ii ON ii.id = si.item_id
        WHERE s.company_id = $1 AND ($2 = true OR s.assigned_user_id = $3 OR s.submitted_by = $3)
        GROUP BY s.id, l.name
        ORDER BY s.due_date DESC, s.updated_at DESC LIMIT 80`,
      [req.companyId, req.role === "employer", req.userId]
    );
    res.json(submissions.rows);
  } catch (e) { console.error("[operations] count submissions failed:", e); res.status(500).json({ error: "count_submissions_failed" }); }
});

app.post("/api/operations/inventory-counts/submissions/:id/submit", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  const items = Array.isArray(req.body?.items) ? req.body.items : [];
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const submission = (await client.query(`SELECT s.*, sch.approval_required, sch.variance_threshold FROM inventory_count_submissions s LEFT JOIN inventory_count_schedules sch ON sch.id = s.schedule_id AND sch.company_id = s.company_id WHERE s.id = $1 AND s.company_id = $2 FOR UPDATE`, [req.params.id, req.companyId])).rows[0];
    if (!submission) { await client.query("ROLLBACK"); return res.status(404).json({ error: "count_submission_not_found" }); }
    if (req.role !== "employer" && submission.assigned_user_id && submission.assigned_user_id !== req.userId) { await client.query("ROLLBACK"); return res.status(403).json({ error: "not_assigned" }); }
    await client.query(`DELETE FROM inventory_count_submission_items WHERE submission_id = $1`, [submission.id]);
    for (const input of items) {
      const item = (await client.query(`SELECT id, quantity_on_hand FROM inventory_items WHERE id = $1 AND company_id = $2 AND location_id IS NOT DISTINCT FROM $3`, [input.item_id, req.companyId, submission.location_id])).rows[0];
      if (!item) continue;
      const counted = Number(input.counted_quantity);
      if (!Number.isFinite(counted)) continue;
      const expected = Number(item.quantity_on_hand || 0);
      const variance = counted - expected;
      if (Math.abs(variance) >= Number(submission.variance_threshold || 0) && !cleanString(input.note, 1000) && Number(submission.variance_threshold || 0) > 0) {
        await client.query("ROLLBACK");
        return res.status(422).json({ error: "variance_note_required", item_id: item.id });
      }
      await client.query(`INSERT INTO inventory_count_submission_items(id, submission_id, item_id, expected_quantity, counted_quantity, variance, note) VALUES($1,$2,$3,$4,$5,$6,$7)`, [randomUUID(), submission.id, item.id, expected, counted, variance, cleanString(input.note, 1000) || null]);
    }
    const nextStatus = toBool(submission.approval_required, true) ? "pending_approval" : "approved";
    await client.query(`UPDATE inventory_count_submissions SET status = $3, submitted_by = $4, submitted_at = now(), updated_at = now() WHERE id = $1 AND company_id = $2`, [submission.id, req.companyId, nextStatus, req.userId]);
    if (nextStatus === "approved") {
      const rows = (await client.query(`SELECT * FROM inventory_count_submission_items WHERE submission_id = $1`, [submission.id])).rows;
      for (const row of rows) {
        const variance = Number(row.variance || 0);
        if (variance === 0) continue;
        const key = `count:${submission.id}:${row.item_id}`;
        const existing = (await client.query(`SELECT id FROM inventory_transactions WHERE company_id = $1 AND idempotency_key = $2`, [req.companyId, key])).rows[0];
        if (!existing) {
          await client.query(`INSERT INTO inventory_transactions(id, company_id, item_id, transaction_type, quantity, from_location_id, employee_id, note, idempotency_key) VALUES($1,$2,$3,'recount_correction',$4,$5,$6,$7,$8)`, [randomUUID(), req.companyId, row.item_id, Math.abs(variance), submission.location_id, req.userId, `Inventory count correction variance ${variance}`, key]);
          await client.query(`UPDATE inventory_items SET quantity_on_hand = quantity_on_hand + $3, updated_at = now() WHERE id = $1 AND company_id = $2`, [row.item_id, req.companyId, variance]);
        }
      }
    }
    await client.query("COMMIT");
    res.json(await inventoryCountSubmissionPayload(pool, req.companyId, submission.id, req.userId, req.role === "employer"));
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("[operations] count submit failed:", e);
    res.status(500).json({ error: "count_submit_failed" });
  } finally { client.release(); }
});

app.post("/api/operations/inventory-counts/submissions/:id/review", authRequired, requireEmployer, async (req, res) => {
  const action = req.body?.action === "approve" ? "approved" : req.body?.action === "reject" ? "rejected" : null;
  if (!action) return res.status(400).json({ error: "invalid_action" });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const submission = (await client.query(`SELECT * FROM inventory_count_submissions WHERE id = $1 AND company_id = $2 FOR UPDATE`, [req.params.id, req.companyId])).rows[0];
    if (!submission) { await client.query("ROLLBACK"); return res.status(404).json({ error: "count_submission_not_found" }); }
    if (submission.submitted_by === req.userId) { await client.query("ROLLBACK"); return res.status(403).json({ error: "cannot_approve_own_count" }); }
    if (action === "approved") {
      const rows = (await client.query(`SELECT * FROM inventory_count_submission_items WHERE submission_id = $1`, [submission.id])).rows;
      for (const row of rows) {
        const variance = Number(row.variance || 0);
        if (variance === 0) continue;
        const key = `count:${submission.id}:${row.item_id}`;
        const existing = (await client.query(`SELECT id FROM inventory_transactions WHERE company_id = $1 AND idempotency_key = $2`, [req.companyId, key])).rows[0];
        if (!existing) {
          await client.query(`INSERT INTO inventory_transactions(id, company_id, item_id, transaction_type, quantity, from_location_id, employee_id, note, idempotency_key) VALUES($1,$2,$3,'recount_correction',$4,$5,$6,$7,$8)`, [randomUUID(), req.companyId, row.item_id, Math.abs(variance), submission.location_id, req.userId, `Inventory count correction variance ${variance}`, key]);
          await client.query(`UPDATE inventory_items SET quantity_on_hand = quantity_on_hand + $3, updated_at = now() WHERE id = $1 AND company_id = $2`, [row.item_id, req.companyId, variance]);
        }
      }
    }
    await client.query(`UPDATE inventory_count_submissions SET status = $3, reviewed_by = $4, reviewed_at = now(), review_note = $5, updated_at = now() WHERE id = $1 AND company_id = $2`, [submission.id, req.companyId, action, req.userId, cleanString(req.body?.note, 1000) || null]);
    if (action === "rejected" && submission.assigned_user_id) {
      const taskId = `inventory-count-recount:${submission.id}`;
      await client.query(`INSERT INTO todo_tasks(id, user_id, title, detail, creator_id, assignee_ids, due_date, priority, status, linked_inventory_count_id, reminders, subtasks, completed, completion_note_required) VALUES($1,$2,'Inventory Recount Correction',$3,$2,$4::jsonb,now(),'high','open',$5,'[]'::jsonb,'[]'::jsonb,false,true) ON CONFLICT(id) DO UPDATE SET status = 'open', detail = EXCLUDED.detail, updated_at = now()`, [taskId, req.userId, cleanString(req.body?.note, 1000) || "Please recount and resubmit inventory.", JSON.stringify([submission.assigned_user_id]), submission.id]);
    }
    await client.query("COMMIT");
    res.json(await inventoryCountSubmissionPayload(pool, req.companyId, submission.id, req.userId, true));
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("[operations] count review failed:", e);
    res.status(500).json({ error: "count_review_failed" });
  } finally { client.release(); }
});

// ---------- OPERATIONS: MILEAGE ----------
app.get("/api/operations/mileage", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  try {
    await pool.query(`INSERT INTO mileage_company_settings(company_id) VALUES($1) ON CONFLICT(company_id) DO NOTHING`, [req.companyId]);
    if (req.role === "employer") await pool.query(`INSERT INTO mileage_employee_settings(company_id, employee_id) SELECT $1, id FROM users WHERE company_id = $1 ON CONFLICT(company_id, employee_id) DO NOTHING`, [req.companyId]);
    else await pool.query(`INSERT INTO mileage_employee_settings(company_id, employee_id) VALUES($1,$2) ON CONFLICT(company_id, employee_id) DO NOTHING`, [req.companyId, req.userId]);
    const settings = (await pool.query(`SELECT enabled, default_rate_cents_per_mile FROM mileage_company_settings WHERE company_id = $1`, [req.companyId])).rows[0];
    const employeeSettings = await pool.query(`SELECT employee_id, enabled, rate_cents_per_mile, start_rule, end_rule, start_location_id, end_location_id, vehicle_type, effective_date::text FROM mileage_employee_settings WHERE company_id = $1 AND ($2 = true OR employee_id = $3) ORDER BY employee_id`, [req.companyId, req.role === "employer", req.userId]);
    const locations = await pool.query(`SELECT id, name, address, lat, lng, active FROM mileage_company_locations WHERE company_id = $1 ORDER BY active DESC, name`, [req.companyId]);
    const logs = await pool.query(`SELECT ml.id, ml.employee_id, ml.service_date::text, ml.status,
         ml.start_rule, ml.end_rule, ml.start_label, ml.start_lat, ml.start_lng, ml.end_label, ml.end_lat, ml.end_lng,
         ml.job_order_estimated, ml.total_miles::float8 AS total_miles, ml.rate_cents_per_mile, ml.reimbursement_cents,
         ml.employee_notes, ml.owner_notes, ml.reviewed_by, ml.reviewed_at, ml.paid_at,
         COALESCE(jsonb_agg(jsonb_build_object('id', l.id, 'sequence', l.sequence, 'from_label', l.from_label, 'to_label', l.to_label,
           'distance_miles', l.distance_miles::float8, 'duration_seconds', l.duration_seconds::float8, 'job_id', l.job_id,
           'manual_trip_id', l.manual_trip_id, 'calculation_status', l.calculation_status, 'error_message', l.error_message) ORDER BY l.sequence) FILTER (WHERE l.id IS NOT NULL), '[]'::jsonb) AS legs
       FROM mileage_daily_logs ml
       LEFT JOIN mileage_legs l ON l.log_id = ml.id
      WHERE ml.company_id = $1 AND ($2 = true OR ml.employee_id = $3)
      GROUP BY ml.id
      ORDER BY ml.service_date DESC LIMIT 60`, [req.companyId, req.role === "employer", req.userId]);
    const proposals = await pool.query(`SELECT id, employee_id, kind, label, address, lat, lng, explanation, status, reviewed_by, reviewed_at, review_note, created_at
       FROM mileage_address_proposals
      WHERE company_id = $1 AND ($2 = true OR employee_id = $3)
      ORDER BY created_at DESC LIMIT 50`, [req.companyId, req.role === "employer", req.userId]);
    const manualTrips = await pool.query(`SELECT id, employee_id, service_date::text, purpose, notes, from_label, from_address, from_lat, from_lng,
         to_label, to_address, to_lat, to_lng, distance_miles::float8 AS distance_miles, duration_seconds::float8 AS duration_seconds,
         status, created_by, reviewed_by, reviewed_at, review_note, created_at
       FROM mileage_manual_trips
      WHERE company_id = $1 AND ($2 = true OR employee_id = $3)
      ORDER BY service_date DESC, created_at DESC LIMIT 60`, [req.companyId, req.role === "employer", req.userId]);
    res.json({ settings, employee_settings: employeeSettings.rows, locations: locations.rows, logs: logs.rows, address_proposals: proposals.rows, manual_trips: manualTrips.rows });
  } catch (e) { console.error(e); res.status(500).json({ error: "mileage_load_failed" }); }
});

app.put("/api/operations/mileage/settings", authRequired, requireEmployer, async (req, res) => {
  const { enabled, default_rate_cents_per_mile } = req.body || {};
  try {
    const { rows } = await pool.query(`INSERT INTO mileage_company_settings(company_id, enabled, default_rate_cents_per_mile) VALUES($1,$2,$3) ON CONFLICT(company_id) DO UPDATE SET enabled = EXCLUDED.enabled, default_rate_cents_per_mile = EXCLUDED.default_rate_cents_per_mile, updated_at = now() RETURNING enabled, default_rate_cents_per_mile`, [req.companyId, toBool(enabled), Number(default_rate_cents_per_mile) || 0]);
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "mileage_settings_failed" }); }
});

app.put("/api/operations/mileage/employees/:id", authRequired, requireEmployer, async (req, res) => {
  const { enabled, rate_cents_per_mile, start_rule, end_rule, start_location_id, end_location_id, vehicle_type, effective_date } = req.body || {};
  try {
    const { rows } = await pool.query(`INSERT INTO mileage_employee_settings(company_id, employee_id, enabled, rate_cents_per_mile, start_rule, end_rule, start_location_id, end_location_id, vehicle_type, effective_date) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(company_id, employee_id) DO UPDATE SET enabled = EXCLUDED.enabled, rate_cents_per_mile = EXCLUDED.rate_cents_per_mile, start_rule = EXCLUDED.start_rule, end_rule = EXCLUDED.end_rule, start_location_id = EXCLUDED.start_location_id, end_location_id = EXCLUDED.end_location_id, vehicle_type = EXCLUDED.vehicle_type, effective_date = EXCLUDED.effective_date, updated_at = now() RETURNING employee_id, enabled, rate_cents_per_mile, start_rule, end_rule, start_location_id, end_location_id, vehicle_type, effective_date::text`, [req.companyId, req.params.id, toBool(enabled), rate_cents_per_mile ?? null, start_rule || "company_location", end_rule || "last_completed_job", start_location_id || null, end_location_id || null, vehicle_type || "not_specified", effective_date || null]);
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "mileage_employee_settings_failed" }); }
});

app.post("/api/operations/mileage/employees/:id/calculate", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  const employeeId = req.role === "employer" ? req.params.id : req.userId;
  const day = (req.body?.day || new Date().toISOString().slice(0, 10)).toString().slice(0, 10);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const settings = (await client.query(`SELECT mes.*, COALESCE(mes.rate_cents_per_mile, mcs.default_rate_cents_per_mile) AS rate FROM mileage_employee_settings mes JOIN mileage_company_settings mcs ON mcs.company_id = mes.company_id WHERE mes.company_id = $1 AND mes.employee_id = $2`, [req.companyId, employeeId])).rows[0];
    if (!settings || !settings.enabled || settings.vehicle_type === "company") { await client.query("ROLLBACK"); return res.status(409).json({ error: "mileage_not_enabled" }); }
    const existing = (await client.query(`SELECT status FROM mileage_daily_logs WHERE company_id = $1 AND employee_id = $2 AND service_date = $3::date FOR UPDATE`, [req.companyId, employeeId, day])).rows[0];
    if (existing && ["approved", "paid"].includes(existing.status)) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "mileage_locked" });
    }
    const legsInput = Array.isArray(req.body?.legs) ? req.body.legs : [];
    if (legsInput.some((leg) => leg?.calculation_status === "failed" || leg?.error_message)) {
      await client.query("ROLLBACK");
      return res.status(422).json({ error: "mileage_leg_failed" });
    }
    const miles = Math.round(legsInput.reduce((sum, leg) => sum + Math.max(0, Number(leg.distance_miles || 0)), 0) * 10) / 10;
    const reimbursement = Math.round(miles * Number(settings.rate || 0));
    const logId = `${req.companyId}:${employeeId}:${day}`;
    const start = req.body?.start_location || {};
    const end = req.body?.end_location || {};
    const status = req.body?.submit ? "submitted" : "ready_for_review";
    const log = (await client.query(`INSERT INTO mileage_daily_logs(
      id, company_id, employee_id, service_date, status, start_rule, end_rule, start_label, start_lat, start_lng,
      end_label, end_lat, end_lng, job_order_estimated, total_miles, rate_cents_per_mile, reimbursement_cents, employee_notes)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
      ON CONFLICT(company_id, employee_id, service_date) DO UPDATE SET
        status = EXCLUDED.status,
        start_rule = EXCLUDED.start_rule,
        end_rule = EXCLUDED.end_rule,
        start_label = EXCLUDED.start_label,
        start_lat = EXCLUDED.start_lat,
        start_lng = EXCLUDED.start_lng,
        end_label = EXCLUDED.end_label,
        end_lat = EXCLUDED.end_lat,
        end_lng = EXCLUDED.end_lng,
        job_order_estimated = EXCLUDED.job_order_estimated,
        total_miles = EXCLUDED.total_miles,
        rate_cents_per_mile = EXCLUDED.rate_cents_per_mile,
        reimbursement_cents = EXCLUDED.reimbursement_cents,
        employee_notes = COALESCE(EXCLUDED.employee_notes, mileage_daily_logs.employee_notes),
        updated_at = now()
      RETURNING id, employee_id, service_date::text, status, start_rule, end_rule, start_label, start_lat, start_lng,
        end_label, end_lat, end_lng, job_order_estimated, total_miles::float8 AS total_miles, rate_cents_per_mile, reimbursement_cents,
        employee_notes, owner_notes, reviewed_by, reviewed_at, paid_at`,
      [logId, req.companyId, employeeId, day, status, settings.start_rule, settings.end_rule,
       cleanString(start.label, 160) || null, Number.isFinite(Number(start.lat)) ? Number(start.lat) : null, Number.isFinite(Number(start.lng)) ? Number(start.lng) : null,
       cleanString(end.label, 160) || null, Number.isFinite(Number(end.lat)) ? Number(end.lat) : null, Number.isFinite(Number(end.lng)) ? Number(end.lng) : null,
       toBool(req.body?.job_order_estimated), miles, Number(settings.rate || 0), reimbursement, cleanString(req.body?.employee_notes, 1000) || null])).rows[0];
    await client.query(`DELETE FROM mileage_legs WHERE log_id = $1`, [log.id]);
    const legs = [];
    for (let i = 0; i < legsInput.length; i += 1) {
      const leg = legsInput[i] || {};
      const row = (await client.query(`INSERT INTO mileage_legs(id, log_id, sequence, from_label, to_label, distance_miles, duration_seconds, job_id, manual_trip_id, calculation_status, error_message)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        RETURNING id, sequence, from_label, to_label, distance_miles::float8 AS distance_miles, duration_seconds::float8 AS duration_seconds, job_id, manual_trip_id, calculation_status, error_message`,
        [randomUUID(), log.id, i + 1, cleanString(leg.from_label, 160) || "Start", cleanString(leg.to_label, 160) || "Stop",
         Math.max(0, Number(leg.distance_miles || 0)), Number.isFinite(Number(leg.duration_seconds)) ? Number(leg.duration_seconds) : null,
         leg.job_id || null, leg.manual_trip_id || null, leg.calculation_status || "calculated", leg.error_message || null])).rows[0];
      legs.push(row);
    }
    await client.query("COMMIT");
    res.json({ ...log, legs });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("[operations] mileage calculate failed:", e);
    res.status(500).json({ error: "mileage_calculate_failed" });
  } finally { client.release(); }
});

app.post("/api/operations/mileage/address-proposals", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  const { kind, label, address, lat, lng, explanation } = req.body || {};
  if (!address || !Number.isFinite(Number(lat)) || !Number.isFinite(Number(lng))) return res.status(400).json({ error: "valid_address_required" });
  try {
    const { rows } = await pool.query(
      `INSERT INTO mileage_address_proposals(id, company_id, employee_id, kind, label, address, lat, lng, explanation, status)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending')
       RETURNING id, employee_id, kind, label, address, lat, lng, explanation, status, reviewed_by, reviewed_at, review_note, created_at`,
      [randomUUID(), req.companyId, req.userId, ["start", "end"].includes(kind) ? kind : "start", cleanString(label, 120) || null, cleanString(address, 500), Number(lat), Number(lng), cleanString(explanation, 1000) || null]
    );
    res.status(201).json(rows[0]);
  } catch (e) { console.error("[operations] mileage address proposal failed:", e); res.status(500).json({ error: "mileage_address_proposal_failed" }); }
});

app.post("/api/operations/mileage/address-proposals/:id/review", authRequired, requireEmployer, async (req, res) => {
  const action = req.body?.action === "approve" ? "approved" : req.body?.action === "reject" ? "rejected" : null;
  if (!action) return res.status(400).json({ error: "invalid_action" });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const proposal = (await client.query(`SELECT * FROM mileage_address_proposals WHERE id = $1 AND company_id = $2 FOR UPDATE`, [req.params.id, req.companyId])).rows[0];
    if (!proposal) { await client.query("ROLLBACK"); return res.status(404).json({ error: "proposal_not_found" }); }
    if (proposal.employee_id === req.userId) { await client.query("ROLLBACK"); return res.status(403).json({ error: "cannot_review_own_address" }); }
    const { rows } = await client.query(
      `UPDATE mileage_address_proposals
          SET status = $3, reviewed_by = $4, reviewed_at = now(), review_note = $5, updated_at = now()
        WHERE id = $1 AND company_id = $2
        RETURNING id, employee_id, kind, label, address, lat, lng, explanation, status, reviewed_by, reviewed_at, review_note, created_at`,
      [req.params.id, req.companyId, action, req.userId, cleanString(req.body?.note, 1000) || null]
    );
    await client.query("COMMIT");
    res.json(rows[0]);
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("[operations] mileage proposal review failed:", e);
    res.status(500).json({ error: "mileage_proposal_review_failed" });
  } finally { client.release(); }
});

app.post("/api/operations/mileage/manual-trips", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  const employeeId = req.role === "employer" && req.body?.employee_id ? req.body.employee_id : req.userId;
  const day = (req.body?.service_date || new Date().toISOString().slice(0, 10)).toString().slice(0, 10);
  const distance = req.body?.distance_miles == null ? null : Math.max(0, Number(req.body.distance_miles));
  if (!req.body?.purpose || !Number.isFinite(Number(req.body?.from_lat)) || !Number.isFinite(Number(req.body?.from_lng)) || !Number.isFinite(Number(req.body?.to_lat)) || !Number.isFinite(Number(req.body?.to_lng))) {
    return res.status(400).json({ error: "manual_trip_fields_required" });
  }
  try {
    const status = req.role === "employer" ? "approved" : "pending";
    const { rows } = await pool.query(
      `INSERT INTO mileage_manual_trips(id, company_id, employee_id, service_date, purpose, notes, from_label, from_address, from_lat, from_lng, to_label, to_address, to_lat, to_lng, distance_miles, duration_seconds, status, created_by)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
       RETURNING id, employee_id, service_date::text, purpose, notes, from_label, from_address, from_lat, from_lng, to_label, to_address, to_lat, to_lng, distance_miles::float8 AS distance_miles, duration_seconds::float8 AS duration_seconds, status, created_by, reviewed_by, reviewed_at, review_note, created_at`,
      [randomUUID(), req.companyId, employeeId, day, cleanString(req.body.purpose, 200), cleanString(req.body.notes, 1000) || null,
       cleanString(req.body.from_label, 160) || "From", cleanString(req.body.from_address, 500) || null, Number(req.body.from_lat), Number(req.body.from_lng),
       cleanString(req.body.to_label, 160) || "To", cleanString(req.body.to_address, 500) || null, Number(req.body.to_lat), Number(req.body.to_lng),
       distance, Number.isFinite(Number(req.body.duration_seconds)) ? Number(req.body.duration_seconds) : null, status, req.userId]
    );
    res.status(201).json(rows[0]);
  } catch (e) { console.error("[operations] manual trip failed:", e); res.status(500).json({ error: "mileage_manual_trip_failed" }); }
});

app.post("/api/operations/mileage/manual-trips/:id/review", authRequired, requireEmployer, async (req, res) => {
  const status = req.body?.action === "approve" ? "approved" : req.body?.action === "reject" ? "rejected" : null;
  if (!status) return res.status(400).json({ error: "invalid_action" });
  try {
    const existing = (await pool.query(`SELECT employee_id FROM mileage_manual_trips WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId])).rows[0];
    if (!existing) return res.status(404).json({ error: "manual_trip_not_found" });
    if (existing.employee_id === req.userId) return res.status(403).json({ error: "cannot_review_own_trip" });
    const { rows } = await pool.query(
      `UPDATE mileage_manual_trips SET status = $3, reviewed_by = $4, reviewed_at = now(), review_note = $5, updated_at = now()
        WHERE id = $1 AND company_id = $2
        RETURNING id, employee_id, service_date::text, purpose, notes, from_label, from_address, from_lat, from_lng, to_label, to_address, to_lat, to_lng, distance_miles::float8 AS distance_miles, duration_seconds::float8 AS duration_seconds, status, created_by, reviewed_by, reviewed_at, review_note, created_at`,
      [req.params.id, req.companyId, status, req.userId, cleanString(req.body?.note, 1000) || null]
    );
    res.json(rows[0]);
  } catch (e) { console.error("[operations] manual trip review failed:", e); res.status(500).json({ error: "mileage_manual_trip_review_failed" }); }
});

app.post("/api/operations/mileage/logs/:id/review", authRequired, requireEmployer, async (req, res) => {
  const action = cleanString(req.body?.action, 40);
  const nextStatus = action === "approve" ? "approved" : action === "reject" ? "rejected" : action === "request_correction" ? "ready_for_review" : action === "mark_paid" ? "paid" : null;
  if (!nextStatus) return res.status(400).json({ error: "invalid_action" });
  try {
    const existing = (await pool.query(`SELECT employee_id, status FROM mileage_daily_logs WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId])).rows[0];
    if (!existing) return res.status(404).json({ error: "mileage_log_not_found" });
    if (existing.employee_id === req.userId) return res.status(403).json({ error: "cannot_review_own_mileage" });
    const paidAtSql = nextStatus === "paid" ? "paid_at = now()," : "";
    const { rows } = await pool.query(
      `UPDATE mileage_daily_logs
          SET status = $3, owner_notes = $4, reviewed_by = $5, reviewed_at = now(), ${paidAtSql} updated_at = now()
        WHERE id = $1 AND company_id = $2
        RETURNING id, employee_id, service_date::text, status, start_rule, end_rule, start_label, start_lat, start_lng,
          end_label, end_lat, end_lng, job_order_estimated, total_miles::float8 AS total_miles, rate_cents_per_mile,
          reimbursement_cents, employee_notes, owner_notes, reviewed_by, reviewed_at, paid_at`,
      [req.params.id, req.companyId, nextStatus, cleanString(req.body?.note, 1000) || null, req.userId]
    );
    const legs = (await pool.query(`SELECT id, sequence, from_label, to_label, distance_miles::float8 AS distance_miles, duration_seconds::float8 AS duration_seconds, job_id, manual_trip_id, calculation_status, error_message FROM mileage_legs WHERE log_id = $1 ORDER BY sequence`, [req.params.id])).rows;
    res.json({ ...rows[0], legs });
  } catch (e) { console.error("[operations] mileage log review failed:", e); res.status(500).json({ error: "mileage_log_review_failed" }); }
});

app.post("/api/operations/mileage/logs/:id/problem", authRequired, async (req, res) => {
  if (!req.companyId) return res.status(403).json({ error: "company_required" });
  const kind = cleanString(req.body?.kind, 80) || "other";
  const explanation = cleanString(req.body?.explanation, 1500);
  if (!explanation) return res.status(400).json({ error: "explanation_required" });
  try {
    const existing = (await pool.query(`SELECT employee_id, status, employee_notes FROM mileage_daily_logs WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId])).rows[0];
    if (!existing) return res.status(404).json({ error: "mileage_log_not_found" });
    if (req.role !== "employer" && existing.employee_id !== req.userId) return res.status(403).json({ error: "not_allowed" });
    const prefix = `[${new Date().toISOString()}] ${kind}: ${explanation}`;
    const previous = cleanString(existing.employee_notes, 3000);
    const note = previous ? `${previous}\n${prefix}` : prefix;
    const nextStatus = ["approved", "paid"].includes(existing.status) ? existing.status : "ready_for_review";
    const { rows } = await pool.query(
      `UPDATE mileage_daily_logs
          SET employee_notes = $3, status = $4, updated_at = now()
        WHERE id = $1 AND company_id = $2
        RETURNING id, employee_id, service_date::text, status, start_rule, end_rule, start_label, start_lat, start_lng,
          end_label, end_lat, end_lng, job_order_estimated, total_miles::float8 AS total_miles, rate_cents_per_mile,
          reimbursement_cents, employee_notes, owner_notes, reviewed_by, reviewed_at, paid_at`,
      [req.params.id, req.companyId, note, nextStatus]
    );
    const legs = (await pool.query(`SELECT id, sequence, from_label, to_label, distance_miles::float8 AS distance_miles, duration_seconds::float8 AS duration_seconds, job_id, manual_trip_id, calculation_status, error_message FROM mileage_legs WHERE log_id = $1 ORDER BY sequence`, [req.params.id])).rows;
    res.json({ ...rows[0], legs });
  } catch (e) { console.error("[operations] mileage problem failed:", e); res.status(500).json({ error: "mileage_problem_failed" }); }
});

app.get("/api/reports/weekly-sales", authRequired, async (req, res) => {
  try {
    const range = statsRange("week", req.query.date);
    if (!range) return res.status(400).json({ error: "invalid_range" });
    const requestedUser = (req.query.user_id || "").toString();
    const userID = req.role === "employer" && requestedUser ? requestedUser : req.userId;
    if (req.role === "employer") {
      const allowed = await pool.query(`SELECT id FROM users WHERE id = $1 AND company_id = $2`, [userID, req.companyId]);
      if (!allowed.rowCount) return res.status(404).json({ error: "employee_not_found" });
    }
    const { rows } = await pool.query(
      `SELECT id, title, start_at AS start, end_at AS "end", contact_id, price_cents,
              material_cost_cents, finished_at, sales_user_ids
         FROM schedule_events
        WHERE company_id = $1
          AND finished_at IS NOT NULL
          AND start_at >= $2
          AND start_at < $3
          AND (
            sales_user_ids ? $4
            OR (jsonb_array_length(sales_user_ids) = 0 AND created_by = $5)
          )
        ORDER BY start_at DESC`,
      [req.companyId, range.start.toISOString(), range.end.toISOString(), userID, userID]
    );
    const jobs = rows.map((job) => {
      const ids = Array.isArray(job.sales_user_ids) && job.sales_user_ids.length ? job.sales_user_ids : [userID];
      const share = Math.round(Number(job.price_cents || 0) / Math.max(ids.length, 1));
      return { ...job, credited_revenue_cents: share };
    });
    res.json({
      user_id: userID,
      start: range.start.toISOString(),
      end: range.end.toISOString(),
      total_revenue_cents: jobs.reduce((sum, job) => sum + Number(job.credited_revenue_cents || 0), 0),
      jobs
    });
  } catch (e) { console.error(e); res.status(500).json({ error: "weekly_sales_report_failed" }); }
});

// ---------- DASHBOARD COMMAND CENTER ----------
const DASHBOARD_DISMISS_TYPES = new Set([
  "scheduled_job",
  "upcoming_job",
  "unfinished_job",
  "job_missing_price",
  "todo",
  "routine",
  "customer_reminder",
  "finance_upcoming",
  "notification",
  "voicemail"
]);

function parseDashboardDate(value, fallback) {
  const date = value ? new Date(value) : fallback;
  return Number.isFinite(date?.getTime()) ? date : fallback;
}

function dashboardItemKey(item) {
  return `${item.type}:${item.source_id}:${item.fingerprint || ""}`;
}

function dashboardMoney(cents) {
  return Number.isFinite(Number(cents)) ? Number(cents) : null;
}

function dashboardRequestId(req) {
  return req.headers["x-request-id"] || req.headers["x-railway-request-id"] || `dashboard-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

async function dashboardSource(requestId, source, fn, fallback, critical = false) {
  const started = Date.now();
  try {
    const value = await fn();
    console.info("[dashboard] source_ok", { requestId, source, duration_ms: Date.now() - started });
    return { value, failed: false };
  } catch (error) {
    console.warn("[dashboard] source_failed", {
      requestId,
      source,
      duration_ms: Date.now() - started,
      code: error?.code || error?.name || null,
      message: error?.message || String(error)
    });
    if (critical) throw error;
    return { value: fallback, failed: true, source };
  }
}

function isInformationalJobNotification(row) {
  const kind = String(row.kind || "").toLowerCase();
  const title = String(row.title || "").trim().toLowerCase();
  if (kind === "job_scheduled" || kind === "scheduled_job_created") return true;
  return ["new job scheduled", "job scheduled"].includes(title);
}

function dashboardServiceTitle(row) {
  const items = Array.isArray(row.service_items) ? row.service_items : [];
  const names = items.map((item) => String(item?.name || "").trim()).filter(Boolean);
  if (names.length) return names.slice(0, 2).join(", ");
  const services = Array.isArray(row.services) ? row.services.map((s) => String(s || "").trim()).filter(Boolean) : [];
  if (services.length) return services.slice(0, 2).join(", ");
  return row.title || "Scheduled job";
}

function buildDashboardJobItem(row, section, priority = "normal", type = "scheduled_job") {
  const serviceTitle = dashboardServiceTitle(row);
  const price = dashboardMoney(row.price_cents);
  const subtitleParts = [];
  if (serviceTitle && serviceTitle !== row.title) subtitleParts.push(serviceTitle);
  if (row.contact_address) subtitleParts.push(row.contact_address);
  return {
    id: `${type}:${row.id}`,
    type,
    source_type: "scheduled_job",
    source_id: String(row.id),
    fingerprint: String(row.updated_at || row.start || ""),
    section,
    priority,
    title: row.contact_name || row.title || "Scheduled job",
    subtitle: subtitleParts.join(" • "),
    amount_cents: price,
    due_at: row.start,
    system_image: "calendar",
    tint: type === "unfinished_job" ? "red" : "blue",
    completable: false,
    dismissible: true,
    destination: { type: "scheduled_job", id: String(row.id) }
  };
}

function buildDashboardTodoItem(row, section, priority) {
  return {
    id: `todo:${row.id}`,
    type: "todo",
    source_type: "todo",
    source_id: String(row.id),
    fingerprint: String(row.updated_at || row.due_date || ""),
    section,
    priority,
    title: row.title,
    subtitle: row.due_date ? "Due " + new Date(row.due_date).toLocaleString("en-US", { dateStyle: "medium", timeStyle: "short" }) : "To-do",
    amount_cents: null,
    due_at: row.due_date,
    system_image: "checklist",
    tint: priority === "high" ? "red" : "purple",
    completable: true,
    dismissible: true,
    destination: { type: "todo", id: String(row.id) }
  };
}

function buildDashboardCustomerReminderItem(row, section, priority) {
  const action = String(row.title || "Follow up").trim();
  return {
    id: `customer_reminder:${row.id}`,
    type: "customer_reminder",
    source_type: "customer_reminder",
    source_id: String(row.id),
    fingerprint: String(row.updated_at || row.due_date || ""),
    section,
    priority,
    title: `${action} with ${row.contact_name}`,
    subtitle: row.due_date ? "Due " + new Date(row.due_date).toLocaleString("en-US", { dateStyle: "medium", timeStyle: "short" }) : "Customer follow-up",
    amount_cents: null,
    due_at: row.due_date,
    system_image: "person.crop.circle.badge.clock",
    tint: priority === "high" ? "red" : "teal",
    completable: false,
    dismissible: true,
    destination: row.contact_id ? { type: "contact", id: String(row.contact_id) } : { type: "todo", id: String(row.id) }
  };
}

function buildDashboardRoutineItem(row, dayKey, dueAt, section, priority) {
  return {
    id: `routine:${row.id}:${dayKey}`,
    type: "routine",
    source_type: "routine",
    source_id: `${row.id}:${dayKey}`,
    fingerprint: String(row.updated_at || dayKey),
    section,
    priority,
    title: row.title,
    subtitle: "Routine",
    amount_cents: null,
    due_at: dueAt,
    system_image: "repeat",
    tint: "orange",
    completable: true,
    dismissible: true,
    destination: { type: "todo", id: String(row.id) }
  };
}

function dedupeDashboardItems(items) {
  const seen = new Set();
  const deduped = [];
  for (const item of items) {
    if (seen.has(item.id)) continue;
    seen.add(item.id);
    deduped.push(item);
  }
  return deduped;
}

function filterDashboardDismissed(items, dismissals) {
  const hidden = new Set(dismissals.map((row) => `${row.item_type}:${row.source_id}:${row.fingerprint || ""}`));
  return items.filter((item) => !hidden.has(dashboardItemKey(item)));
}

app.get("/api/dashboard/summary", authRequired, async (req, res) => {
  try {
    const requestId = dashboardRequestId(req);
    const now = new Date();
    const currentAt = parseDashboardDate(req.query.now, now);
    const todayStart = parseDashboardDate(req.query.today_start, new Date(now.getFullYear(), now.getMonth(), now.getDate()));
    const todayEnd = parseDashboardDate(req.query.today_end, new Date(todayStart.getTime() + 86400000));
    const weekStart = parseDashboardDate(req.query.week_start, todayStart);
    const weekEnd = parseDashboardDate(req.query.week_end, new Date(weekStart.getTime() + 7 * 86400000));
    const monthStart = parseDashboardDate(req.query.month_start, new Date(now.getFullYear(), now.getMonth(), 1));
    const monthEnd = parseDashboardDate(req.query.month_end, new Date(now.getFullYear(), now.getMonth() + 1, 1));
    const upcomingEnd = parseDashboardDate(req.query.upcoming_end, new Date(todayStart.getTime() + 8 * 86400000));
    const jobsPastStart = parseDashboardDate(req.query.jobs_past_start, new Date(currentAt.getTime() - 120 * 86400000));
    const jobsUpcomingEnd = parseDashboardDate(req.query.jobs_upcoming_end, new Date(currentAt.getTime() + 30 * 86400000));
    const employer = req.role === "employer";
    const failedSources = [];
    const jobScope = employer
      ? { sql: "se.company_id = $1", values: [req.companyId] }
      : {
          sql: `se.company_id = $1 AND (
                  se.created_by = $2
                  OR se.sales_user_ids ? $3
                  OR se.worker_user_ids ? $3
                )`,
          values: [req.companyId, req.userId, String(req.userId)]
        };

    const jobsSource = await dashboardSource(requestId, "jobs", () => req.companyId ? pool.query(
      `SELECT se.id, se.title, se.start_at AS start, se.end_at AS "end", se.contact_id,
              se.services, se.service_items, se.price_cents, se.finished_at, se.updated_at,
              c.name AS contact_name, c.address AS contact_address
         FROM schedule_events se
         LEFT JOIN contacts c ON c.id::text = se.contact_id AND c.company_id = se.company_id
        WHERE ${jobScope.sql}
          AND se.start_at >= $${jobScope.values.length + 1}
          AND se.start_at < $${jobScope.values.length + 2}
        ORDER BY se.start_at ASC
        LIMIT 80`,
      [...jobScope.values, jobsPastStart.toISOString(), jobsUpcomingEnd.toISOString()]
    ) : Promise.resolve({ rows: [] }), { rows: [] });
    if (jobsSource.failed) failedSources.push(jobsSource.source);
    const jobsResult = jobsSource.value;

    const revenueSource = await dashboardSource(requestId, "metrics", () => employer && req.companyId ? pool.query(
      `SELECT
          COALESCE(SUM(price_cents) FILTER (WHERE start_at >= $2 AND start_at < $3), 0)::int AS today,
          COALESCE(SUM(price_cents) FILTER (WHERE start_at >= $4 AND start_at < $5), 0)::int AS week,
          COALESCE(SUM(price_cents) FILTER (WHERE start_at >= $6 AND start_at < $7), 0)::int AS month,
          COUNT(*) FILTER (WHERE start_at >= $2 AND start_at < $3 AND price_cents IS NULL)::int AS missing_today
         FROM schedule_events
        WHERE company_id = $1
          AND start_at >= LEAST($2::timestamptz, $4::timestamptz, $6::timestamptz)
          AND start_at < GREATEST($3::timestamptz, $5::timestamptz, $7::timestamptz)`,
      [req.companyId, todayStart.toISOString(), todayEnd.toISOString(), weekStart.toISOString(), weekEnd.toISOString(), monthStart.toISOString(), monthEnd.toISOString()]
    ) : Promise.resolve({ rows: [{ today: 0, week: 0, month: 0, missing_today: 0 }] }), { rows: [{ today: 0, week: 0, month: 0, missing_today: 0 }] });
    if (revenueSource.failed) failedSources.push(revenueSource.source);
    const revenueResult = revenueSource.value;

    const [tasksSource, taskStatsSource, customerSource, customerStatsSource, routinesSource, doneSource, notificationsSource, dismissalsSource, equipmentRequestsSource, mileageApprovalsSource, overdueTeamSource] = await Promise.all([
      dashboardSource(requestId, "todos", () => pool.query(
        `SELECT id, title, due_date, completed, updated_at, priority, assignee_ids
           FROM todo_tasks
          WHERE (user_id = $1 OR assignee_ids ? $1::text)
            AND completed = false
            AND due_date IS NOT NULL
            AND due_date < $2
          ORDER BY CASE priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 ELSE 2 END, due_date ASC
          LIMIT 40`,
        [req.userId, upcomingEnd.toISOString()]
      ), { rows: [] }),
      dashboardSource(requestId, "todo_stats", () => pool.query(
        `SELECT
            COUNT(*) FILTER (WHERE due_date >= $2 AND due_date < $3)::int AS total_today,
            COUNT(*) FILTER (WHERE due_date >= $2 AND due_date < $3 AND completed = true)::int AS completed_today
           FROM todo_tasks
          WHERE (user_id = $1 OR assignee_ids ? $1::text)
            AND due_date IS NOT NULL`,
        [req.userId, todayStart.toISOString(), todayEnd.toISOString()]
      ), { rows: [{ total_today: 0, completed_today: 0 }] }),
      dashboardSource(requestId, "customer_reminders", () => pool.query(
        `SELECT id, title, contact_id, contact_name, due_date, completed, updated_at
           FROM todo_customer_reminders
          WHERE user_id = $1
            AND completed = false
            AND due_date IS NOT NULL
            AND due_date < $2
          ORDER BY due_date ASC
          LIMIT 40`,
        [req.userId, upcomingEnd.toISOString()]
      ), { rows: [] }),
      dashboardSource(requestId, "customer_reminder_stats", () => pool.query(
        `SELECT
            COUNT(*) FILTER (WHERE due_date >= $2 AND due_date < $3)::int AS total_today,
            COUNT(*) FILTER (WHERE due_date >= $2 AND due_date < $3 AND completed = true)::int AS completed_today
           FROM todo_customer_reminders
          WHERE user_id = $1
            AND due_date IS NOT NULL`,
        [req.userId, todayStart.toISOString(), todayEnd.toISOString()]
      ), { rows: [{ total_today: 0, completed_today: 0 }] }),
      dashboardSource(requestId, "routines", () => pool.query(
        `SELECT id, title, time, weekdays, updated_at
           FROM todo_routines
          WHERE user_id = $1
            AND enabled = true
          ORDER BY updated_at DESC
          LIMIT 80`,
        [req.userId]
      ), { rows: [] }),
      dashboardSource(requestId, "routine_done", () => pool.query(
        `SELECT routine_id, day_key
           FROM todo_routine_done
          WHERE user_id = $1`,
        [req.userId]
      ), { rows: [] }),
      dashboardSource(requestId, "notifications", () => pool.query(
        `SELECT id, kind, title, body, data, created_at
           FROM notifications
          WHERE user_id = $1
            AND read_at IS NULL
          ORDER BY created_at DESC
          LIMIT 12`,
        [req.userId]
      ), { rows: [] }),
      dashboardSource(requestId, "dismissals", () => pool.query(
        `SELECT item_type, source_id, fingerprint
           FROM dashboard_dismissals
          WHERE user_id = $1
            AND (expires_at IS NULL OR expires_at > now())`,
        [req.userId]
      ), { rows: [] }),
      dashboardSource(requestId, "equipment_requests", () => employer && req.companyId ? pool.query(
        `SELECT id, request_type, item_name, urgency, explanation, status, created_at
           FROM equipment_requests
          WHERE company_id = $1 AND status IN ('pending','under_review','approved','ordered','ready')
          ORDER BY CASE urgency WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 ELSE 2 END, created_at ASC
          LIMIT 8`,
        [req.companyId]
      ) : Promise.resolve({ rows: [] }), { rows: [] }),
      dashboardSource(requestId, "mileage_approvals", () => employer && req.companyId ? pool.query(
        `SELECT id, employee_id, service_date, reimbursement_cents, status, updated_at
           FROM mileage_daily_logs
          WHERE company_id = $1 AND status IN ('ready_for_review','submitted')
          ORDER BY service_date ASC
          LIMIT 8`,
        [req.companyId]
      ) : Promise.resolve({ rows: [] }), { rows: [] }),
      dashboardSource(requestId, "overdue_team_assignments", () => employer && req.companyId ? pool.query(
        `SELECT t.id, t.title, t.due_date, t.completed, t.updated_at, t.priority, t.assignee_ids,
                COALESCE(NULLIF(u.display_name, ''), u.email) AS assignee_name
           FROM todo_tasks t
           LEFT JOIN LATERAL jsonb_array_elements_text(t.assignee_ids) a(id) ON true
           LEFT JOIN users u ON u.id::text = a.id AND u.company_id = $1
          WHERE t.user_id IN (SELECT id FROM users WHERE company_id = $1)
            AND t.completed = false
            AND t.due_date IS NOT NULL
            AND t.due_date < $2
            AND jsonb_array_length(t.assignee_ids) > 0
          ORDER BY CASE t.priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 ELSE 2 END, t.due_date ASC
          LIMIT 8`,
        [req.companyId, todayStart.toISOString()]
      ) : Promise.resolve({ rows: [] }), { rows: [] })
    ]);
    for (const source of [tasksSource, taskStatsSource, customerSource, customerStatsSource, routinesSource, doneSource, notificationsSource, dismissalsSource, equipmentRequestsSource, mileageApprovalsSource, overdueTeamSource]) {
      if (source.failed) failedSources.push(source.source);
    }
    const tasksResult = tasksSource.value;
    const taskStatsResult = taskStatsSource.value;
    const customerResult = customerSource.value;
    const customerStatsResult = customerStatsSource.value;
    const routinesResult = routinesSource.value;
    const doneResult = doneSource.value;
    const notificationsResult = notificationsSource.value;
    const dismissalsResult = dismissalsSource.value;
    const equipmentRequestsResult = equipmentRequestsSource.value;
    const mileageApprovalsResult = mileageApprovalsSource.value;
    const overdueTeamResult = overdueTeamSource.value;

    const items = [];
    const jobsToday = jobsResult.rows.filter((row) => new Date(row.start) >= todayStart && new Date(row.start) < todayEnd);
    const activeJobsToday = jobsToday.filter((row) => !row.finished_at);
    const completedJobsToday = jobsToday.length - activeJobsToday.length;
    const openJobs = jobsResult.rows.filter((row) => !row.finished_at);
    const unfinishedJobs = openJobs.filter((row) => new Date(row.start) < currentAt).sort((a, b) => new Date(a.start) - new Date(b.start));
    const upcomingJobs = openJobs.filter((row) => new Date(row.start) >= currentAt).sort((a, b) => new Date(a.start) - new Date(b.start));
    for (const row of unfinishedJobs.slice(0, 20)) {
      items.push(buildDashboardJobItem(row, "unfinished_jobs", "high", "unfinished_job"));
    }
    for (const row of upcomingJobs.slice(0, 20)) {
      items.push(buildDashboardJobItem(row, "upcoming_jobs", "normal", "upcoming_job"));
    }
    for (const row of activeJobsToday) {
      if (row.price_cents == null) {
        items.push({
          id: `job_missing_price:${row.id}`,
          type: "job_missing_price",
          source_type: "scheduled_job",
          source_id: String(row.id),
          fingerprint: String(row.updated_at || row.start || ""),
          section: "attention",
          priority: "high",
          title: "Job missing price",
          subtitle: row.contact_name || row.title || "Scheduled job",
          amount_cents: null,
          due_at: row.start,
          system_image: "exclamationmark.triangle.fill",
          tint: "red",
          completable: false,
          dismissible: true,
          destination: { type: "scheduled_job", id: String(row.id) }
        });
      }
    }

    for (const row of tasksResult.rows) {
      const due = new Date(row.due_date);
      const assignedToMe = Array.isArray(row.assignee_ids) && row.assignee_ids.includes(String(req.userId));
      const section = assignedToMe ? "my_assignments" : (due < todayStart ? "attention" : due < todayEnd ? "today" : "upcoming");
      const priority = due < todayStart || row.priority === "urgent" || row.priority === "high" ? "high" : "normal";
      items.push(buildDashboardTodoItem(row, section, priority));
    }
    for (const row of overdueTeamResult.rows) {
      const item = buildDashboardTodoItem(row, "overdue_assignments", "high");
      item.subtitle = `${row.assignee_name || "Employee"} • ${item.subtitle}`;
      item.tint = "red";
      items.push(item);
    }
    for (const row of customerResult.rows) {
      const due = new Date(row.due_date);
      const section = due < todayStart ? "attention" : due < todayEnd ? "today" : "upcoming";
      items.push(buildDashboardCustomerReminderItem(row, section, section === "attention" ? "high" : "normal"));
    }

    for (const row of equipmentRequestsResult.rows) {
      items.push({
        id: `equipment_request:${row.id}`,
        type: "equipment_request",
        source_type: "equipment_request",
        source_id: String(row.id),
        fingerprint: String(row.status || row.created_at || ""),
        section: "equipment_requests",
        priority: row.urgency === "urgent" ? "high" : "normal",
        title: row.item_name || row.request_type.replaceAll("_", " "),
        subtitle: row.explanation || "Equipment/material request",
        amount_cents: null,
        due_at: row.created_at,
        system_image: "wrench.and.screwdriver.fill",
        tint: row.urgency === "urgent" ? "red" : "orange",
        completable: false,
        dismissible: true,
        destination: { type: "equipment_request", id: String(row.id) }
      });
    }

    for (const row of mileageApprovalsResult.rows) {
      items.push({
        id: `mileage_approval:${row.id}`,
        type: "mileage_approval",
        source_type: "mileage_log",
        source_id: String(row.id),
        fingerprint: String(row.status || row.updated_at || ""),
        section: "attention",
        priority: "normal",
        title: "Mileage pending review",
        subtitle: `${row.service_date} · ${dashboardMoney(row.reimbursement_cents || 0)}`,
        amount_cents: row.reimbursement_cents || null,
        due_at: row.service_date,
        system_image: "car.fill",
        tint: "teal",
        completable: false,
        dismissible: true,
        destination: { type: "mileage", id: String(row.id) }
      });
    }

    const doneKeys = new Set(doneResult.rows.map((row) => `${row.routine_id}:${row.day_key}`));
    let routineTotalToday = 0;
    let routineCompletedToday = 0;
    for (let day = new Date(todayStart); day < upcomingEnd; day = new Date(day.getTime() + 86400000)) {
      const jsDay = day.getDay();
      const weekday = jsDay === 0 ? 1 : jsDay + 1;
      const dayKey = day.toISOString().slice(0, 10);
      for (const row of routinesResult.rows) {
        const weekdays = Array.isArray(row.weekdays) ? row.weekdays.map(Number) : [];
        if (!weekdays.includes(weekday)) continue;
        const isToday = day >= todayStart && day < todayEnd;
        if (isToday) routineTotalToday += 1;
        if (doneKeys.has(`${row.id}:${dayKey}`)) {
          if (isToday) routineCompletedToday += 1;
          continue;
        }
        const dueAt = new Date(day);
        if (row.time) {
          const time = new Date(row.time);
          if (!Number.isNaN(time.getTime())) {
            dueAt.setUTCHours(time.getUTCHours(), time.getUTCMinutes(), 0, 0);
          }
        }
        const section = day >= todayStart && day < todayEnd ? "today" : "upcoming";
        items.push(buildDashboardRoutineItem(row, dayKey, dueAt.toISOString(), section, "normal"));
      }
    }

    for (const row of notificationsResult.rows) {
      if (isInformationalJobNotification(row)) continue;
      items.push({
        id: `notification:${row.id}`,
        type: "notification",
        source_type: "notification",
        source_id: String(row.id),
        fingerprint: String(row.created_at || ""),
        section: "attention",
        priority: "normal",
        title: row.title,
        subtitle: row.body || "",
        amount_cents: null,
        due_at: row.created_at,
        system_image: "bell.badge.fill",
        tint: "orange",
        completable: false,
        dismissible: true,
        destination: { type: row.kind === "voicemail" ? "message_thread" : "notification", id: String(row.id) }
      });
    }

    if (employer && req.companyId) {
      const financeSource = await dashboardSource(requestId, "finance_upcoming", async () => {
        const projection = await loadProjection(pool, req.companyId, 7);
        return projection;
      }, { events: [] });
      if (financeSource.failed) failedSources.push(financeSource.source);
      const projection = financeSource.value;
        for (const event of (projection.events || []).slice(0, 8)) {
          const occurrenceAt = `${event.occurrence_date}T12:00:00.000Z`;
          items.push({
            id: `finance_upcoming:${event.planned_item_id}:${event.occurrence_date}`,
            type: "finance_upcoming",
            source_type: "finance_planned_occurrence",
            source_id: `${event.planned_item_id}:${event.occurrence_date}`,
            fingerprint: `${event.planned_item_id}:${event.occurrence_date}:${event.signed_amount_cents}`,
            section: event.occurrence_date <= todayStart.toISOString().slice(0, 10) ? "today" : "upcoming",
            priority: event.occurrence_date <= todayStart.toISOString().slice(0, 10) ? "normal" : "low",
            title: event.title,
            subtitle: event.direction === "income" ? "Expected income" : (event.recurrence === "none" ? "Planned expense" : "Recurring"),
            amount_cents: Number(event.signed_amount_cents || 0),
            due_at: occurrenceAt,
            system_image: event.direction === "income" ? "arrow.down.circle.fill" : "calendar.badge.clock",
            tint: event.direction === "income" ? "green" : "red",
            completable: false,
            dismissible: true,
            destination: { type: "finance_upcoming", id: String(event.planned_item_id) }
          });
        }
    }

    const priorityRank = { critical: 0, high: 1, normal: 2, low: 3 };
    const sectionRank = { unfinished_jobs: 0, overdue_assignments: 1, attention: 2, today: 3, upcoming_jobs: 4, equipment_requests: 5, upcoming: 6 };
    const visibleItems = filterDashboardDismissed(dedupeDashboardItems(items), dismissalsResult.rows)
      .sort((a, b) => {
        if (sectionRank[a.section] !== sectionRank[b.section]) return sectionRank[a.section] - sectionRank[b.section];
        if (a.section === "attention" && priorityRank[a.priority] !== priorityRank[b.priority]) return priorityRank[a.priority] - priorityRank[b.priority];
        return new Date(a.due_at || 0) - new Date(b.due_at || 0);
      });

    const revenue = revenueResult.rows[0] || {};
    const taskStats = taskStatsResult.rows[0] || {};
    const customerStats = customerStatsResult.rows[0] || {};
    const tasksTodayTotal = Number(taskStats.total_today || 0) + Number(customerStats.total_today || 0) + routineTotalToday;
    const tasksTodayCompleted = Number(taskStats.completed_today || 0) + Number(customerStats.completed_today || 0) + routineCompletedToday;
    res.json({
      generated_at: new Date().toISOString(),
      metrics: {
        jobs_today: jobsToday.length,
        jobs_today_completed: completedJobsToday,
        jobs_today_remaining: activeJobsToday.length,
        unfinished_jobs_count: unfinishedJobs.length,
        upcoming_jobs_count: upcomingJobs.length,
        tasks_today_total: tasksTodayTotal,
        tasks_today_completed: tasksTodayCompleted,
        revenue_today_cents: Number(revenue.today || 0),
        revenue_week_cents: Number(revenue.week || 0),
        revenue_month_cents: Number(revenue.month || 0),
        jobs_missing_prices_today: Number(revenue.missing_today || 0),
        revenue_visible: employer
      },
      partial: failedSources.length > 0,
      failed_sources: failedSources,
      items: visibleItems.slice(0, 60)
    });
  } catch (e) {
    console.error("[dashboard] summary failed:", e);
    res.status(500).json({ error: "dashboard_summary_failed" });
  }
});

app.post("/api/dashboard/items/dismiss", authRequired, async (req, res) => {
  const { type, source_id, fingerprint } = req.body || {};
  if (!DASHBOARD_DISMISS_TYPES.has(type) || !source_id) return res.status(400).json({ error: "invalid_dashboard_item" });
  try {
    await pool.query(
      `INSERT INTO dashboard_dismissals(company_id, user_id, item_type, source_id, fingerprint)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (user_id, item_type, source_id, fingerprint)
       DO UPDATE SET dismissed_at = now(), expires_at = NULL`,
      [req.companyId || null, req.userId, type, String(source_id), String(fingerprint || "")]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error("[dashboard] dismiss failed:", e);
    res.status(500).json({ error: "dashboard_dismiss_failed" });
  }
});

app.delete("/api/dashboard/items/dismiss", authRequired, async (req, res) => {
  const { type, source_id, fingerprint } = req.query?.type ? req.query : (req.body || {});
  if (!DASHBOARD_DISMISS_TYPES.has(type) || !source_id) return res.status(400).json({ error: "invalid_dashboard_item" });
  try {
    await pool.query(
      `DELETE FROM dashboard_dismissals
        WHERE user_id = $1
          AND item_type = $2
          AND source_id = $3
          AND fingerprint = $4`,
      [req.userId, type, String(source_id), String(fingerprint || "")]
    );
    res.status(204).end();
  } catch (e) {
    console.error("[dashboard] undismiss failed:", e);
    res.status(500).json({ error: "dashboard_undismiss_failed" });
  }
});

// ---------- MAP PINS ----------
app.get("/api/map-pins", authRequired, async (req, res) => {
  try {
    const companyScope = req.query.scope === "company" && req.companyId;
    const where = companyScope
      ? { sql: `u.company_id = $1`, values: [req.companyId] }
      : { sql: `p.user_id = $1`, values: [req.userId] };
    const { rows } = await pool.query(
      `SELECT p.id, p.user_id, p.latitude, p.longitude, p.name, p.address, p.notes,
              p.status, p.phone, p.email, p.contact_id, p.created_at,
              COALESCE(NULLIF(u.display_name, ''), u.email) AS owner_name
         FROM map_pins p
         JOIN users u ON u.id = p.user_id
        WHERE ${where.sql}
        ORDER BY p.created_at DESC`,
      where.values
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_list_pins" }); }
});

app.put("/api/map-pins/:id", authRequired, async (req, res) => {
  const { latitude, longitude, name, address, notes, status, phone, email, contact_id, created_at } = req.body || {};
  if (typeof latitude !== "number" || typeof longitude !== "number") {
    return res.status(400).json({ error: "missing_coords" });
  }
  try {
    const existing = await pool.query(
      `SELECT p.*, u.company_id
         FROM map_pins p
         JOIN users u ON u.id = p.user_id
        WHERE p.id = $1`,
      [req.params.id]
    );
    let ownerUserId = req.userId;
    if (existing.rowCount) {
      const row = existing.rows[0];
      const canEdit = row.user_id === req.userId || (req.role === "employer" && row.company_id === req.companyId);
      if (!canEdit) return res.status(403).json({ error: "pin_owner_required" });
      ownerUserId = row.user_id;
    }
    const r = await pool.query(
      `INSERT INTO map_pins (id, user_id, latitude, longitude, name, address, notes, status, phone, email, contact_id, created_at, source)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, COALESCE($12::timestamptz, now()), $13)
       ON CONFLICT (id) DO UPDATE
         SET latitude = EXCLUDED.latitude,
             longitude = EXCLUDED.longitude,
             name = EXCLUDED.name,
             address = EXCLUDED.address,
             notes = EXCLUDED.notes,
             status = EXCLUDED.status,
             phone = EXCLUDED.phone,
             email = EXCLUDED.email,
             contact_id = EXCLUDED.contact_id,
             updated_at = now()
       RETURNING id, user_id, latitude, longitude, name, address, notes, status, phone, email, contact_id, created_at, updated_at, list_id, source, last_visit_at, last_knock_at, visit_count, knock_count`,
      [
        req.params.id, ownerUserId, latitude, longitude,
        name || '', address || '', notes || '', status || 'lead',
        phone || null, email || null, contact_id || null, created_at || null, existing.rowCount ? existing.rows[0].source || "manual" : "manual"
      ]
    );
    const before = existing.rowCount ? existing.rows[0] : null;
    const after = r.rows[0];
    const payload = {
      pin_id: after.id,
      status: after.status,
      contact_id: after.contact_id || null,
      list_id: after.list_id || null,
      address: after.address || "",
      latitude: after.latitude,
      longitude: after.longitude,
      source: "ios",
      old_status: before?.status || null,
      new_status: after.status
    };
    const changed = before ? ["latitude", "longitude", "name", "address", "notes", "status", "phone", "email", "contact_id", "list_id"].filter((field) => JSON.stringify(before[field] ?? null) !== JSON.stringify(after[field] ?? null)).map((field) => ({ field, old_value: before[field] ?? null, new_value: after[field] ?? null })) : [];
    try {
      if (!before) {
        await emitAutomationEvent({ companyId: req.companyId, eventType: "map.pin_created", subjectType: "map_pin", subjectId: after.id, actorUserId: req.userId, source: "ios", dedupeKey: `map.pin_created:${after.id}`, payload });
        await syncAutomationSchedulesForMapPin(req.companyId, after, "status_changed");
      } else if (changed.length) {
        await emitAutomationEvent({ companyId: req.companyId, eventType: "map.pin_updated", subjectType: "map_pin", subjectId: after.id, actorUserId: req.userId, source: "ios", payload: { ...payload, changed_fields: changed } });
        if (changed.some((c) => c.field === "status")) {
          await emitAutomationEvent({ companyId: req.companyId, eventType: "map.pin_status_changed", subjectType: "map_pin", subjectId: after.id, actorUserId: req.userId, source: "ios", payload: { ...payload, changed_fields: changed.filter((c) => c.field === "status") } });
          const statusEvents = { lead: ["map.pin_converted_to_lead", "canvass.lead_created"], won: ["map.pin_marked_won", "canvass.sale_recorded"], lost: ["map.pin_marked_lost", "canvass.not_interested"], reloop: ["map.pin_marked_reloop", "canvass.reloop_created"], later: ["map.pin_marked_later", "canvass.no_answer"] };
          for (const eventType of statusEvents[after.status] || []) await emitAutomationEvent({ companyId: req.companyId, eventType, subjectType: "map_pin", subjectId: after.id, actorUserId: req.userId, source: "ios", payload });
          await syncAutomationSchedulesForMapPin(req.companyId, after, "status_changed");
        }
        if (changed.some((c) => c.field === "address")) await emitAutomationEvent({ companyId: req.companyId, eventType: "map.pin_address_changed", subjectType: "map_pin", subjectId: after.id, actorUserId: req.userId, source: "ios", payload });
        if (changed.some((c) => c.field === "latitude" || c.field === "longitude")) await emitAutomationEvent({ companyId: req.companyId, eventType: "map.pin_location_changed", subjectType: "map_pin", subjectId: after.id, actorUserId: req.userId, source: "ios", payload });
        if (changed.some((c) => c.field === "contact_id")) await emitAutomationEvent({ companyId: req.companyId, eventType: after.contact_id ? "map.pin_contact_linked" : "map.pin_contact_unlinked", subjectType: "map_pin", subjectId: after.id, actorUserId: req.userId, source: "ios", payload });
      }
    } catch (automationErr) {
      console.warn("[automations] map pin hook failed", automationErr?.message || automationErr);
    }
    res.json(r.rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_upsert_pin" }); }
});

app.delete("/api/map-pins/:id", authRequired, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `DELETE FROM map_pins p
        USING users u
        WHERE p.id = $1
          AND u.id = p.user_id
          AND (p.user_id = $2 OR ($3 = 'employer' AND u.company_id = $4))`,
      [req.params.id, req.userId, req.role, req.companyId]
    );
    try {
      await cancelAutomationSchedulesForSubject(req.companyId, "map_pin", req.params.id);
      await emitAutomationEvent({ companyId: req.companyId, eventType: "map.pin_deleted", subjectType: "map_pin", subjectId: req.params.id, actorUserId: req.userId, source: "ios", payload: { pin_id: req.params.id } });
    } catch (automationErr) {
      console.warn("[automations] map pin delete hook failed", automationErr?.message || automationErr);
    }
    res.status(204).end();
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_delete_pin" }); }
});

function statsRange(kind, dateValue) {
  const now = dateValue ? new Date(dateValue) : new Date();
  if (Number.isNaN(now.getTime())) return null;
  if (kind === "all") return { start: null, end: null };
  const start = new Date(now);
  start.setHours(0, 0, 0, 0);
  if (kind === "week") {
    const day = start.getDay();
    start.setDate(start.getDate() - day);
  } else if (kind === "month") {
    start.setDate(1);
  }
  const end = new Date(start);
  if (kind === "day") end.setDate(end.getDate() + 1);
  else if (kind === "week") end.setDate(end.getDate() + 7);
  else if (kind === "month") end.setMonth(end.getMonth() + 1);
  else return null;
  return { start, end };
}

app.get("/api/map-stats", authRequired, async (req, res) => {
  try {
    const period = ["day", "week", "month", "all"].includes(req.query.period) ? req.query.period : "day";
    const range = statsRange(period, req.query.date);
    if (!range) return res.status(400).json({ error: "invalid_range" });
    const requestedUser = (req.query.user_id || "").toString();
    const userID = req.role === "employer" && requestedUser ? requestedUser : req.userId;
    const values = [req.companyId || null, userID];
    let dateClause = "";
    if (range.start && range.end) {
      values.push(range.start.toISOString(), range.end.toISOString());
      dateClause = `AND p.created_at >= $3 AND p.created_at < $4`;
    }
    const { rows } = await pool.query(
      `SELECT
          p.user_id,
          COALESCE(NULLIF(u.display_name, ''), u.email) AS owner_name,
          COUNT(*)::int AS total_pins,
          COUNT(*) FILTER (WHERE p.status <> 'lead')::int AS doors_knocked,
          COUNT(*) FILTER (WHERE p.status = 'lead')::int AS leads,
          COUNT(*) FILTER (WHERE p.status = 'won')::int AS sold,
          COUNT(*) FILTER (WHERE p.status = 'reloop')::int AS follow_up,
          COUNT(*) FILTER (WHERE p.status = 'later')::int AS na,
          COUNT(*) FILTER (WHERE p.status = 'lost')::int AS no,
          CASE WHEN COUNT(*) FILTER (WHERE p.status <> 'lead') = 0 THEN 0
               ELSE ROUND((COUNT(*) FILTER (WHERE p.status = 'won')::numeric / COUNT(*) FILTER (WHERE p.status <> 'lead')::numeric) * 100, 2)
          END::double precision AS conversion_rate
         FROM map_pins p
         JOIN users u ON u.id = p.user_id
        WHERE ($1::uuid IS NULL OR u.company_id = $1)
          AND p.user_id = $2
          ${dateClause}
        GROUP BY p.user_id, owner_name`,
      values
    );
    res.json(rows[0] || {
      user_id: userID,
      owner_name: null,
      total_pins: 0,
      doors_knocked: 0,
      leads: 0,
      sold: 0,
      follow_up: 0,
      na: 0,
      no: 0,
      conversion_rate: 0
    });
  } catch (e) { console.error(e); res.status(500).json({ error: "map_stats_failed" }); }
});

// ---------- MEASUREMENTS ----------
app.get("/api/measurements", authRequired, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, name, points, created_at, linked_contact_ids, units
       FROM measurements
       WHERE user_id = $1
       ORDER BY updated_at DESC`,
      [req.userId]
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_list_measurements" }); }
});

app.put("/api/measurements/:id", authRequired, async (req, res) => {
  const { name, points, created_at, linked_contact_ids, units } = req.body || {};
  if (!Array.isArray(points)) {
    return res.status(400).json({ error: "missing_points" });
  }
  const cleanUnits = units === "meters" ? "meters" : "feet";
  const cleanLinkedContactIDs = Array.isArray(linked_contact_ids) ? linked_contact_ids : [];
  try {
    const before = (await pool.query(`SELECT * FROM measurements WHERE id = $1 AND user_id = $2`, [req.params.id, req.userId])).rows[0] || null;
    const r = await pool.query(
      `INSERT INTO measurements (id, user_id, name, points, created_at, linked_contact_ids, units)
       VALUES ($1, $2, $3, $4::jsonb, COALESCE($5::timestamptz, now()), $6::jsonb, $7)
       ON CONFLICT (id) DO UPDATE
         SET name = EXCLUDED.name,
             points = EXCLUDED.points,
             linked_contact_ids = EXCLUDED.linked_contact_ids,
             units = EXCLUDED.units,
             updated_at = now()
       WHERE measurements.user_id = $2
       RETURNING id, name, points, created_at, linked_contact_ids, units`,
      [
        req.params.id,
        req.userId,
        name || '',
        JSON.stringify(points),
        created_at || null,
        JSON.stringify(cleanLinkedContactIDs),
        cleanUnits
      ]
    );
    try {
      const after = r.rows[0];
      const payload = { measurement_id: after.id, name: after.name, units: after.units, point_count: Array.isArray(after.points) ? after.points.length : 0, linked_contact_ids: after.linked_contact_ids || [] };
      if (!before) {
        await emitAutomationEvent({ companyId: req.companyId, eventType: "measurement.created", subjectType: "measurement", subjectId: after.id, actorUserId: req.userId, source: "ios", dedupeKey: `measurement.created:${after.id}`, payload });
        if (Array.isArray(after.points) && after.points.length >= 2) await emitAutomationEvent({ companyId: req.companyId, eventType: "measurement.completed", subjectType: "measurement", subjectId: after.id, actorUserId: req.userId, source: "ios", dedupeKey: `measurement.completed:${after.id}`, payload });
      } else {
        const changedFields = ["name", "points", "linked_contact_ids", "units"].filter((field) => JSON.stringify(before[field] ?? null) !== JSON.stringify(after[field] ?? null)).map((field) => ({ field, old_value: before[field] ?? null, new_value: after[field] ?? null }));
        if (changedFields.length) await emitAutomationEvent({ companyId: req.companyId, eventType: "measurement.updated", subjectType: "measurement", subjectId: after.id, actorUserId: req.userId, source: "ios", payload: { ...payload, changed_fields: changedFields } });
        if (changedFields.some((c) => c.field === "linked_contact_ids")) {
          const oldIds = Array.isArray(before.linked_contact_ids) ? before.linked_contact_ids.map(String) : [];
          for (const contactId of cleanLinkedContactIDs.map(String).filter((id) => !oldIds.includes(id))) {
            await emitAutomationEvent({ companyId: req.companyId, eventType: "measurement.linked_to_contact", subjectType: "measurement", subjectId: after.id, actorUserId: req.userId, source: "ios", payload: { ...payload, contact_id: contactId } });
          }
        }
      }
    } catch (automationErr) {
      console.warn("[automations] measurement hook failed", automationErr?.message || automationErr);
    }
    res.json(r.rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_upsert_measurement" }); }
});

app.delete("/api/measurements/:id", authRequired, async (req, res) => {
  try {
    await pool.query(`DELETE FROM measurements WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.userId]);
    try {
      await emitAutomationEvent({ companyId: req.companyId, eventType: "measurement.deleted", subjectType: "measurement", subjectId: req.params.id, actorUserId: req.userId, source: "ios", payload: { measurement_id: req.params.id } });
    } catch (automationErr) {
      console.warn("[automations] measurement delete hook failed", automationErr?.message || automationErr);
    }
    res.status(204).end();
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_delete_measurement" }); }
});

// ---------- TO-DO: TASKS ----------
app.get("/api/todo/tasks", authRequired, async (req, res) => {
  try {
    const companyUsers = req.companyId
      ? (await pool.query(`SELECT id FROM users WHERE company_id = $1`, [req.companyId])).rows.map((r) => r.id)
      : [req.userId];
    const { rows } = await pool.query(
      `SELECT id, title, detail, creator_id, assignee_ids, due_date, priority, status,
              linked_contact_id, linked_job_id, linked_equipment_id, linked_equipment_request_id, linked_inventory_count_id,
              reminders, subtasks, completed, completed_at, completed_by, completion_note, completion_note_required, color_hex
       FROM todo_tasks
       WHERE user_id = $1
          OR ($2::uuid IS NOT NULL AND user_id = ANY($3::uuid[]))
          OR (assignee_ids ? $1::text)
       ORDER BY due_date NULLS LAST, updated_at DESC`,
      [req.userId, req.companyId, companyUsers]
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_list_tasks" }); }
});

app.put("/api/todo/tasks/:id", authRequired, async (req, res) => {
  const {
    title, detail, creator_id, assignee_ids, due_date, priority, status,
    linked_contact_id, linked_job_id, linked_equipment_id, linked_equipment_request_id, linked_inventory_count_id,
    reminders, subtasks, completed, completed_at, completed_by, completion_note, completion_note_required, color_hex
  } = req.body || {};
  if (!title) return res.status(400).json({ error: "title_required" });
  const assignees = Array.isArray(assignee_ids) ? assignee_ids.filter((id) => typeof id === "string").slice(0, 20) : [];
  try {
    const previous = await pool.query(
      `SELECT * FROM todo_tasks WHERE id = $1 AND (user_id = $2 OR ($3::uuid IS NOT NULL AND user_id IN (SELECT id FROM users WHERE company_id = $3)) OR assignee_ids ? $2::text)`,
      [req.params.id, req.userId, req.companyId]
    );
    const ownerUserId = previous.rows[0]?.user_id || creator_id || req.userId;
    const r = await pool.query(
      `INSERT INTO todo_tasks
        (id, user_id, title, detail, creator_id, assignee_ids, due_date, priority, status,
         linked_contact_id, linked_job_id, linked_equipment_id, linked_equipment_request_id, linked_inventory_count_id, reminders, subtasks,
         completed, completed_at, completed_by, completion_note, completion_note_required, color_hex)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10, $11, $12, $13, $14, $15::jsonb, $16::jsonb, $17, $18, $19, $20, $21, $22)
       ON CONFLICT (id) DO UPDATE
         SET title = EXCLUDED.title,
             detail = EXCLUDED.detail,
             creator_id = COALESCE(todo_tasks.creator_id, EXCLUDED.creator_id),
             assignee_ids = EXCLUDED.assignee_ids,
             due_date = EXCLUDED.due_date,
             priority = EXCLUDED.priority,
             status = EXCLUDED.status,
             linked_contact_id = EXCLUDED.linked_contact_id,
             linked_job_id = EXCLUDED.linked_job_id,
             linked_equipment_id = EXCLUDED.linked_equipment_id,
             linked_equipment_request_id = EXCLUDED.linked_equipment_request_id,
             linked_inventory_count_id = EXCLUDED.linked_inventory_count_id,
             reminders = EXCLUDED.reminders,
             subtasks = EXCLUDED.subtasks,
             completed = EXCLUDED.completed,
             completed_at = EXCLUDED.completed_at,
             completed_by = EXCLUDED.completed_by,
             completion_note = EXCLUDED.completion_note,
             completion_note_required = EXCLUDED.completion_note_required,
             color_hex = EXCLUDED.color_hex,
             updated_at = now()
       WHERE todo_tasks.user_id = $2
          OR ($23::uuid IS NOT NULL AND todo_tasks.user_id IN (SELECT id FROM users WHERE company_id = $23))
          OR todo_tasks.assignee_ids ? $24::text
       RETURNING id, title, detail, creator_id, assignee_ids, due_date, priority, status,
                 linked_contact_id, linked_job_id, linked_equipment_id, linked_equipment_request_id, linked_inventory_count_id,
                 reminders, subtasks, completed, completed_at, completed_by, completion_note, completion_note_required, color_hex`,
      [
        req.params.id, ownerUserId, title, detail || null, creator_id || req.userId, JSON.stringify(assignees), due_date || null,
        priority || "normal", completed ? "completed" : (status || "open"),
        linked_contact_id || null, linked_job_id || null, linked_equipment_id || null, linked_equipment_request_id || null, linked_inventory_count_id || null,
        JSON.stringify(reminders || []), JSON.stringify(subtasks || []),
        toBool(completed), completed_at || (completed ? new Date() : null),
        completed_by || (completed ? req.userId : null), completion_note || null, toBool(completion_note_required), color_hex || null,
        req.companyId, req.userId
      ]
    );
    if (req.companyId) {
      const before = previous.rows[0] || null;
      const after = r.rows[0];
      if (!before) {
        await emitAutomationEvent({ companyId: req.companyId, eventType: "task.created", subjectType: "task", subjectId: after.id, actorUserId: req.userId, source: "todo.api", dedupeKey: `task.created:${after.id}`, payload: { task_id: after.id, title: after.title, due_date: after.due_date } });
      } else {
        const changed = rowChanges(before, after, ["title", "due_date", "completed", "subtasks"]);
        if (changed.length) await emitAutomationEvent({ companyId: req.companyId, eventType: "task.updated", subjectType: "task", subjectId: after.id, actorUserId: req.userId, source: "todo.api", payload: { task_id: after.id, title: after.title, changed_fields: changed } });
        if (changed.some((c) => c.field === "title")) await emitAutomationEvent({ companyId: req.companyId, eventType: "task.title_changed", subjectType: "task", subjectId: after.id, actorUserId: req.userId, source: "todo.api", payload: { task_id: after.id } });
        if (changed.some((c) => c.field === "due_date")) {
          await emitAutomationEvent({ companyId: req.companyId, eventType: "task.due_changed", subjectType: "task", subjectId: after.id, actorUserId: req.userId, source: "todo.api", payload: { task_id: after.id, old_due: before.due_date, new_due: after.due_date } });
          await emitAutomationEvent({ companyId: req.companyId, eventType: "task.rescheduled", subjectType: "task", subjectId: after.id, actorUserId: req.userId, source: "todo.api", payload: { task_id: after.id, old_due: before.due_date, new_due: after.due_date } });
        }
        if (!before.completed && after.completed) await emitAutomationEvent({ companyId: req.companyId, eventType: "task.completed", subjectType: "task", subjectId: after.id, actorUserId: req.userId, source: "todo.api", dedupeKey: `task.completed:${after.id}:${after.completed_at || "completed"}`, payload: { task_id: after.id, title: after.title, completed_at: after.completed_at } });
        if (before.completed && !after.completed) await emitAutomationEvent({ companyId: req.companyId, eventType: "task.reopened", subjectType: "task", subjectId: after.id, actorUserId: req.userId, source: "todo.api", payload: { task_id: after.id } });
      }
      await syncAutomationSchedulesForTask(req.companyId, after);
    }
    res.json(r.rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_upsert_task" }); }
});

app.delete("/api/todo/tasks/:id", authRequired, async (req, res) => {
  try {
    const before = (await pool.query(`DELETE FROM todo_tasks WHERE id = $1 AND user_id = $2 RETURNING *`,
      [req.params.id, req.userId])).rows[0];
    if (before && req.companyId) {
      await emitAutomationEvent({ companyId: req.companyId, eventType: "task.deleted", subjectType: "task", subjectId: before.id, actorUserId: req.userId, source: "todo.api", dedupeKey: `task.deleted:${before.id}`, payload: { task_id: before.id, title: before.title } });
      await cancelAutomationSchedulesForSubject(req.companyId, "task", before.id);
    }
    res.status(204).end();
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_delete_task" }); }
});

// ---------- TO-DO: ROUTINES ----------
app.get("/api/todo/routines", authRequired, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, title, time, weekdays, reminders, enabled, color_hex
       FROM todo_routines WHERE user_id = $1 ORDER BY updated_at DESC`,
      [req.userId]
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_list_routines" }); }
});

app.put("/api/todo/routines/:id", authRequired, async (req, res) => {
  const { title, time, weekdays, reminders, enabled, color_hex } = req.body || {};
  if (!title) return res.status(400).json({ error: "title_required" });
  try {
    const previous = await pool.query(`SELECT * FROM todo_routines WHERE id = $1 AND user_id = $2`, [req.params.id, req.userId]);
    const r = await pool.query(
      `INSERT INTO todo_routines
        (id, user_id, title, time, weekdays, reminders, enabled, color_hex)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8)
       ON CONFLICT (id) DO UPDATE
         SET title = EXCLUDED.title,
             time = EXCLUDED.time,
             weekdays = EXCLUDED.weekdays,
             reminders = EXCLUDED.reminders,
             enabled = EXCLUDED.enabled,
             color_hex = EXCLUDED.color_hex,
             updated_at = now()
       WHERE todo_routines.user_id = $2
       RETURNING id, title, time, weekdays, reminders, enabled, color_hex`,
      [
        req.params.id, req.userId, title, time || null,
        JSON.stringify(weekdays || []), JSON.stringify(reminders || []),
        toBool(enabled, true), color_hex || null
      ]
    );
    if (req.companyId) {
      const before = previous.rows[0] || null;
      const after = r.rows[0];
      await emitAutomationEvent({ companyId: req.companyId, eventType: before ? "routine.updated" : "routine.created", subjectType: "routine", subjectId: after.id, actorUserId: req.userId, source: "todo.api", dedupeKey: before ? null : `routine.created:${after.id}`, payload: { routine_id: after.id, title: after.title } });
      if (before?.enabled && !after.enabled) await emitAutomationEvent({ companyId: req.companyId, eventType: "routine.ended", subjectType: "routine", subjectId: after.id, actorUserId: req.userId, source: "todo.api", payload: { routine_id: after.id } });
      if (before && !before.enabled && after.enabled) await emitAutomationEvent({ companyId: req.companyId, eventType: "routine.reactivated", subjectType: "routine", subjectId: after.id, actorUserId: req.userId, source: "todo.api", payload: { routine_id: after.id } });
      await syncAutomationSchedulesForRoutine(req.companyId, after);
    }
    res.json(r.rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_upsert_routine" }); }
});

app.delete("/api/todo/routines/:id", authRequired, async (req, res) => {
  try {
    const before = (await pool.query(`DELETE FROM todo_routines WHERE id = $1 AND user_id = $2 RETURNING *`,
      [req.params.id, req.userId])).rows[0];
    await pool.query(`DELETE FROM todo_routine_done WHERE routine_id = $1 AND user_id = $2`,
      [req.params.id, req.userId]);
    if (before && req.companyId) {
      await emitAutomationEvent({ companyId: req.companyId, eventType: "routine.ended", subjectType: "routine", subjectId: before.id, actorUserId: req.userId, source: "todo.api", dedupeKey: `routine.ended:${before.id}`, payload: { routine_id: before.id, title: before.title } });
      await cancelAutomationSchedulesForSubject(req.companyId, "routine", before.id);
    }
    res.status(204).end();
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_delete_routine" }); }
});

// ---------- TO-DO: PER-DAY ROUTINE COMPLETIONS ----------
app.get("/api/todo/routine-done", authRequired, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT routine_id, day_key FROM todo_routine_done WHERE user_id = $1`,
      [req.userId]
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_list_routine_done" }); }
});

app.put("/api/todo/routine-done", authRequired, async (req, res) => {
  const { routine_id, day_key } = req.body || {};
  if (!routine_id || !day_key) return res.status(400).json({ error: "missing_params" });
  try {
    await pool.query(
      `INSERT INTO todo_routine_done (user_id, routine_id, day_key)
       VALUES ($1, $2, $3)
       ON CONFLICT DO NOTHING`,
      [req.userId, routine_id, day_key]
    );
    if (req.companyId) {
      await emitAutomationEvent({ companyId: req.companyId, eventType: "routine.completed", subjectType: "routine", subjectId: routine_id, actorUserId: req.userId, source: "todo.api", dedupeKey: `routine.completed:${routine_id}:${day_key}`, payload: { routine_id, day_key } });
    }
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_mark_routine_done" }); }
});

app.delete("/api/todo/routine-done", authRequired, async (req, res) => {
  const { routine_id, day_key } = req.query || {};
  if (!routine_id || !day_key) return res.status(400).json({ error: "missing_params" });
  try {
    await pool.query(
      `DELETE FROM todo_routine_done
       WHERE user_id = $1 AND routine_id = $2 AND day_key = $3`,
      [req.userId, routine_id, day_key]
    );
    res.status(204).end();
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_clear_routine_done" }); }
});

// ---------- TO-DO: CUSTOMER REMINDERS ----------
app.get("/api/todo/customer-reminders", authRequired, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, title, contact_id, contact_name, phone, due_date, completed, color_hex
       FROM todo_customer_reminders WHERE user_id = $1 ORDER BY due_date NULLS LAST`,
      [req.userId]
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_list_customer_reminders" }); }
});

app.put("/api/todo/customer-reminders/:id", authRequired, async (req, res) => {
  const { title, contact_id, contact_name, phone, due_date, completed, color_hex } = req.body || {};
  if (!contact_name) return res.status(400).json({ error: "contact_name_required" });
  try {
    const previous = await pool.query(`SELECT * FROM todo_customer_reminders WHERE id = $1 AND user_id = $2`, [req.params.id, req.userId]);
    const r = await pool.query(
      `INSERT INTO todo_customer_reminders
        (id, user_id, title, contact_id, contact_name, phone, due_date, completed, color_hex)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (id) DO UPDATE
         SET title = EXCLUDED.title,
             contact_id = EXCLUDED.contact_id,
             contact_name = EXCLUDED.contact_name,
             phone = EXCLUDED.phone,
             due_date = EXCLUDED.due_date,
             completed = EXCLUDED.completed,
             color_hex = EXCLUDED.color_hex,
             updated_at = now()
       WHERE todo_customer_reminders.user_id = $2
       RETURNING id, title, contact_id, contact_name, phone, due_date, completed, color_hex`,
      [
        req.params.id, req.userId, title || null, contact_id || null,
        contact_name, phone || null, due_date || null,
        toBool(completed), color_hex || null
      ]
    );
    if (req.companyId) {
      const before = previous.rows[0] || null;
      const after = r.rows[0];
      if (!before) await emitAutomationEvent({ companyId: req.companyId, eventType: "customer_reminder.created", subjectType: "customer_reminder", subjectId: after.id, actorUserId: req.userId, source: "todo.api", dedupeKey: `customer_reminder.created:${after.id}`, payload: { reminder_id: after.id, contact_id: after.contact_id, due_date: after.due_date } });
      else if (!before.completed && after.completed) await emitAutomationEvent({ companyId: req.companyId, eventType: "customer_reminder.completed", subjectType: "customer_reminder", subjectId: after.id, actorUserId: req.userId, source: "todo.api", dedupeKey: `customer_reminder.completed:${after.id}:${after.updated_at || "completed"}`, payload: { reminder_id: after.id, contact_id: after.contact_id } });
      else if (before.completed && !after.completed) await emitAutomationEvent({ companyId: req.companyId, eventType: "customer_reminder.reopened", subjectType: "customer_reminder", subjectId: after.id, actorUserId: req.userId, source: "todo.api", payload: { reminder_id: after.id, contact_id: after.contact_id } });
      else if (before.due_date !== after.due_date) await emitAutomationEvent({ companyId: req.companyId, eventType: "customer_reminder.rescheduled", subjectType: "customer_reminder", subjectId: after.id, actorUserId: req.userId, source: "todo.api", payload: { reminder_id: after.id, old_due: before.due_date, new_due: after.due_date } });
      await syncAutomationSchedulesForCustomerReminder(req.companyId, after);
    }
    res.json(r.rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_upsert_customer_reminder" }); }
});

app.delete("/api/todo/customer-reminders/:id", authRequired, async (req, res) => {
  try {
    const before = (await pool.query(
      `DELETE FROM todo_customer_reminders WHERE id = $1 AND user_id = $2 RETURNING *`,
      [req.params.id, req.userId]
    )).rows[0];
    if (before && req.companyId) {
      await emitAutomationEvent({ companyId: req.companyId, eventType: "customer_reminder.deleted", subjectType: "customer_reminder", subjectId: before.id, actorUserId: req.userId, source: "todo.api", dedupeKey: `customer_reminder.deleted:${before.id}`, payload: { reminder_id: before.id, contact_id: before.contact_id } });
      await cancelAutomationSchedulesForSubject(req.companyId, "customer_reminder", before.id);
    }
    res.status(204).end();
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_delete_customer_reminder" }); }
});

// ---------- TO-DO: ACTIVITY LOGS ----------
app.get("/api/todo/logs", authRequired, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, kind, ts AS timestamp, task_id, routine_id, contact_id, note
       FROM todo_logs WHERE user_id = $1 ORDER BY ts DESC LIMIT 500`,
      [req.userId]
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_list_logs" }); }
});

app.put("/api/todo/logs/:id", authRequired, async (req, res) => {
  const { kind, timestamp, task_id, routine_id, contact_id, note } = req.body || {};
  if (!kind) return res.status(400).json({ error: "kind_required" });
  try {
    const r = await pool.query(
      `INSERT INTO todo_logs (id, user_id, kind, ts, task_id, routine_id, contact_id, note)
       VALUES ($1, $2, $3, COALESCE($4, now()), $5, $6, $7, $8)
       ON CONFLICT (id) DO NOTHING
       RETURNING id, kind, ts AS timestamp, task_id, routine_id, contact_id, note`,
      [
        req.params.id, req.userId, kind, timestamp || null,
        task_id || null, routine_id || null, contact_id || null, note || null
      ]
    );
    res.json(r.rows[0] || { id: req.params.id });
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_upsert_log" }); }
});

app.delete("/api/todo/logs/:id", authRequired, async (req, res) => {
  try {
    await pool.query(`DELETE FROM todo_logs WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.userId]);
    res.status(204).end();
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_delete_log" }); }
});

// ==========================================================================
//                           STRIPE CONNECT ROUTES
// ==========================================================================
// All of these are employer-only. Employees never touch Stripe onboarding
// or account settings.

app.get("/api/payments/connect/status", authRequired, requireEmployer, async (req, res) => {
  try {
    const settings = await ensureBusinessSettings(req.userId, req.companyId);
    const stripe = getStripe();
    if (settings.stripe_account_id && stripe) {
      try {
        const acct = await stripe.accounts.retrieve(settings.stripe_account_id);
        const updated = await persistStripeAccountReadiness(req.userId, acct);
        return res.json({ settings: sanitizeBusinessSettings(updated) });
      } catch (err) {
        console.error("stripe accounts.retrieve failed:", err.message);
      }
    }
    res.json({ settings: sanitizeBusinessSettings(settings) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "connect_status_failed" });
  }
});

app.post("/api/payments/connect/create-account", authRequired, requireEmployer, async (req, res) => {
  const stripe = requireStripe(res); if (!stripe) return;
  try {
    const settings = await ensureBusinessSettings(req.userId, req.companyId);
    if (settings.stripe_account_id) {
      return res.json({ settings: sanitizeBusinessSettings(settings) });
    }
    const account = await stripe.accounts.create({
      type: "standard",
      email: req.userEmail,
      metadata: { wolfcrm_user_id: req.userId, wolfcrm_company_id: req.companyId || "" }
    });
    const updated = await pool.query(
      `UPDATE business_settings
          SET stripe_account_id = $2,
              stripe_connect_status = 'setup_incomplete',
              updated_at = now()
        WHERE user_id = $1
        RETURNING *`,
      [req.userId, account.id]
    );
    res.json({ settings: sanitizeBusinessSettings(updated.rows[0]) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "connect_create_account_failed", detail: e.message });
  }
});

app.post("/api/payments/connect/create-account-link", authRequired, requireEmployer, async (req, res) => {
  const stripe = requireStripe(res); if (!stripe) return;
  try {
    let settings = await ensureBusinessSettings(req.userId, req.companyId);
    if (!settings.stripe_account_id) {
      const account = await stripe.accounts.create({
        type: "standard",
        email: req.userEmail,
        metadata: { wolfcrm_user_id: req.userId, wolfcrm_company_id: req.companyId || "" }
      });
      const upd = await pool.query(
        `UPDATE business_settings
            SET stripe_account_id = $2,
                stripe_connect_status = 'setup_incomplete',
                updated_at = now()
          WHERE user_id = $1
          RETURNING *`,
        [req.userId, account.id]
      );
      settings = upd.rows[0];
    }
    const link = await stripe.accountLinks.create({
      account: settings.stripe_account_id,
      return_url: STRIPE_CONNECT_RETURN_URL,
      refresh_url: STRIPE_CONNECT_REFRESH_URL,
      type: "account_onboarding"
    });
    res.json({
      url: link.url,
      expires_at: link.expires_at,
      settings: sanitizeBusinessSettings(settings)
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "connect_account_link_failed", detail: e.message });
  }
});

app.post("/api/payments/connect/refresh-status", authRequired, requireEmployer, async (req, res) => {
  const stripe = requireStripe(res); if (!stripe) return;
  try {
    const settings = await ensureBusinessSettings(req.userId, req.companyId);
    if (!settings.stripe_account_id) {
      return res.json({ settings: sanitizeBusinessSettings(settings) });
    }
    const acct = await stripe.accounts.retrieve(settings.stripe_account_id);
    const updated = await persistStripeAccountReadiness(req.userId, acct);
    res.json({ settings: sanitizeBusinessSettings(updated) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "connect_refresh_failed", detail: e.message });
  }
});

// Simple return/refresh pages the hosted onboarding will send the employer
// back to. They just tell the user they can close the window and return
// to the app; the app itself will call /refresh-status when it comes back.
app.get("/stripe/connect/return", (_req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>WolfCRM — Stripe Setup</title></head><body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0F1420;color:#F5F7FA;text-align:center;padding:60px 24px"><h1 style="font-weight:800">All set</h1><p style="opacity:.75">Stripe onboarding is complete. You can close this window and return to WolfCRM.</p></body></html>`);
});
app.get("/stripe/connect/refresh", (_req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>WolfCRM — Stripe Setup</title></head><body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0F1420;color:#F5F7FA;text-align:center;padding:60px 24px"><h1 style="font-weight:800">Setup link expired</h1><p style="opacity:.75">Please return to WolfCRM and tap "Finish Stripe Setup" again.</p></body></html>`);
});

// ==========================================================================
//                          SERVICE PLAN ROUTES
// ==========================================================================

app.get("/api/service-plans", authRequired, requireEmployer, async (req, res) => {
  try {
    const employerId = await resolveEmployerUserId(req);
    const { rows } = await pool.query(
      `SELECT sp.*,
              c.name    AS contact_name,
              c.phone   AS contact_phone,
              c.email   AS contact_email,
              c.address AS contact_address
         FROM service_plans sp
         LEFT JOIN contacts c ON c.id::text = sp.contact_id::text
        WHERE sp.user_id = $1
        ORDER BY sp.created_at DESC`,
      [employerId]
    );
    res.json(rows.map((r) => sanitizeServicePlan(r)));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "list_service_plans_failed" });
  }
});

app.get("/api/service-plans/dashboard", authRequired, requireEmployer, async (req, res) => {
  try {
    const employerId = await resolveEmployerUserId(req);
    const { rows } = await pool.query(
      `SELECT status, COUNT(*)::int AS n, COALESCE(SUM(price_cents),0)::bigint AS total_cents,
              billing_interval, billing_interval_count
         FROM service_plans
        WHERE user_id = $1
        GROUP BY status, billing_interval, billing_interval_count`,
      [employerId]
    );
    let active = 0, pending = 0, pastDue = 0, canceled = 0, paused = 0, mrrCents = 0;
    for (const r of rows) {
      const n = r.n;
      if (r.status === "active")          active   += n;
      if (r.status === "payment_pending") pending  += n;
      if (r.status === "past_due")        pastDue  += n;
      if (r.status === "canceled")        canceled += n;
      if (r.status === "paused")          paused   += n;
    }
    // Estimated MRR: normalize each active plan's price to a monthly figure.
    const active_plans = await pool.query(
      `SELECT price_cents, billing_interval, billing_interval_count
         FROM service_plans
        WHERE user_id = $1 AND status = 'active'`,
      [employerId]
    );
    for (const p of active_plans.rows) {
      const cnt = Math.max(1, p.billing_interval_count || 1);
      const iv = (p.billing_interval || "month").toLowerCase();
      let monthly = 0;
      if (iv === "day")   monthly = (p.price_cents / cnt) * 30;
      if (iv === "week")  monthly = (p.price_cents / cnt) * (30 / 7);
      if (iv === "month") monthly = p.price_cents / cnt;
      if (iv === "year")  monthly = p.price_cents / (cnt * 12);
      mrrCents += monthly;
    }
    const { rows: upcoming } = await pool.query(
      `SELECT sp.*, c.name AS contact_name
         FROM service_plans sp
         LEFT JOIN contacts c ON c.id::text = sp.contact_id::text
        WHERE sp.user_id = $1
          AND sp.status IN ('active','payment_pending','past_due')
          AND sp.next_service_date IS NOT NULL
          AND sp.next_service_date >= (CURRENT_DATE - INTERVAL '1 day')
        ORDER BY sp.next_service_date ASC
        LIMIT 25`,
      [employerId]
    );
    const { rows: events } = await pool.query(
      `SELECT e.*, sp.plan_name, c.name AS contact_name
         FROM service_plan_events e
         LEFT JOIN service_plans sp ON sp.id = e.service_plan_id
         LEFT JOIN contacts c ON c.id::text = e.contact_id::text
        WHERE e.user_id = $1
        ORDER BY e.created_at DESC
        LIMIT 20`,
      [employerId]
    );
    res.json({
      active_count: active,
      pending_payment_count: pending,
      past_due_count: pastDue,
      canceled_count: canceled,
      paused_count: paused,
      estimated_mrr_cents: Math.round(mrrCents),
      upcoming: upcoming.map((r) => sanitizeServicePlan(r)),
      recent_events: events.map((e) => ({
        id: e.id,
        service_plan_id: e.service_plan_id,
        plan_name: e.plan_name,
        contact_name: e.contact_name,
        event_type: e.event_type,
        notes: e.notes,
        created_at: e.created_at
      }))
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "dashboard_failed" });
  }
});

app.get("/api/service-plans/:id", authRequired, async (req, res) => {
  try {
    const employerId = await resolveEmployerUserId(req);
    const { rows } = await pool.query(
      `SELECT sp.*, c.name AS contact_name, c.phone AS contact_phone,
              c.email AS contact_email, c.address AS contact_address
         FROM service_plans sp
         LEFT JOIN contacts c ON c.id::text = sp.contact_id::text
        WHERE sp.id = $1 AND sp.user_id = $2`,
      [req.params.id, employerId]
    );
    const row = rows[0];
    if (!row) return res.status(404).json({ error: "not_found" });
    if (req.role !== "employer" && row.created_by_user_id !== req.userId) {
      return res.status(403).json({ error: "forbidden" });
    }
    res.json(sanitizeServicePlan(row, { employeeSafe: req.role !== "employer" }));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "get_service_plan_failed" });
  }
});

app.post("/api/service-plans/:id/reconcile", authRequired, async (req, res) => {
  try {
    const employerId = await resolveEmployerUserId(req);
    const { rows } = await pool.query(
      `SELECT sp.*, c.name AS contact_name, c.phone AS contact_phone,
              c.email AS contact_email, c.address AS contact_address
         FROM service_plans sp
         LEFT JOIN contacts c ON c.id::text = sp.contact_id::text
        WHERE sp.id = $1 AND sp.user_id = $2`,
      [req.params.id, employerId]
    );
    const plan = rows[0];
    if (!plan) return res.status(404).json({ error: "not_found" });
    if (req.role !== "employer" && plan.created_by_user_id !== req.userId) {
      return res.status(403).json({ error: "forbidden" });
    }
    const updated = await reconcileServicePlanFromStripe(plan, { source: "stripe.service_plan_client_reconcile" });
    const joined = await pool.query(
      `SELECT sp.*, c.name AS contact_name, c.phone AS contact_phone,
              c.email AS contact_email, c.address AS contact_address
         FROM service_plans sp
         LEFT JOIN contacts c ON c.id::text = sp.contact_id::text
        WHERE sp.id = $1`,
      [updated.id]
    );
    const payment = await pool.query(
      `SELECT *
         FROM payment_records
        WHERE service_plan_id = $1
        ORDER BY created_at DESC
        LIMIT 1`,
      [updated.id]
    );
    res.json({
      plan: sanitizeServicePlan(joined.rows[0] || updated, { employeeSafe: req.role !== "employer" }),
      payment: payment.rows[0] ? sanitizePaymentRecord(payment.rows[0], { employeeSafe: req.role !== "employer" }) : null
    });
  } catch (e) {
    console.error("service plan reconcile failed:", {
      message: e.message,
      type: e.type,
      code: e.code,
      requestId: e.requestId
    });
    if (e.statusCode === 409) {
      return res.status(409).json({
        error: e.message,
        subscription_ids: e.subscriptionIds || [],
        message: "Multiple active Stripe subscriptions match this WolfCRM plan. Review them in Stripe before adopting one."
      });
    }
    res.status(500).json({ error: "service_plan_reconcile_failed", detail: e.message });
  }
});

app.get("/api/contacts/:contactId/service-plans", authRequired, async (req, res) => {
  try {
    const employerId = await resolveEmployerUserId(req);
    // verify contact belongs to this employer scope
    const c = await pool.query(`SELECT id FROM contacts WHERE id = $1 AND user_id = $2`,
      [req.params.contactId, employerId]);
    if (!c.rows.length) return res.status(404).json({ error: "contact_not_found" });
    if (req.role === "employer") {
      const { rows } = await pool.query(
        `SELECT sp.*, c.name AS contact_name, c.phone AS contact_phone,
                c.email AS contact_email, c.address AS contact_address
           FROM service_plans sp
           LEFT JOIN contacts c ON c.id::text = sp.contact_id::text
          WHERE sp.user_id = $1 AND sp.contact_id::text = $2
          ORDER BY sp.created_at DESC`,
        [employerId, req.params.contactId]
      );
      return res.json(rows.map((r) => sanitizeServicePlan(r)));
    }
    // Employees only see limited data for plans they themselves created.
    const { rows } = await pool.query(
      `SELECT sp.*, c.name AS contact_name
         FROM service_plans sp
         LEFT JOIN contacts c ON c.id::text = sp.contact_id::text
        WHERE sp.user_id = $1
          AND sp.contact_id::text = $2
          AND sp.created_by_user_id = $3
        ORDER BY sp.created_at DESC`,
      [employerId, req.params.contactId, req.userId]
    );
    res.json(rows.map((r) => sanitizeServicePlan(r, { employeeSafe: true })));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "list_contact_plans_failed" });
  }
});

app.post("/api/service-plans", authRequired, async (req, res) => {
  if (!canCreateServicePlan(req)) return res.status(403).json({ error: "forbidden" });
  try {
    const {
      contact_id, contact,
      plan_name, price_cents, currency,
      billing_interval, billing_interval_count,
      service_interval, service_interval_count,
      first_service_date, included_services, notes
    } = req.body || {};

    if (!plan_name || typeof plan_name !== "string") return res.status(400).json({ error: "plan_name_required" });
    const priceInt = parseInt(price_cents, 10);
    if (!Number.isFinite(priceInt) || priceInt < 1) return res.status(400).json({ error: "invalid_price" });
    if (!billing_interval) return res.status(400).json({ error: "billing_interval_required" });
    if (!service_interval) return res.status(400).json({ error: "service_interval_required" });

    const employerId = await resolveEmployerUserId(req);
    let contactId = contact_id || null;

    // If no contact_id, allow creating a contact inline.
    if (!contactId && contact && contact.name) {
      const cid = randomUUID();
      await pool.query(
        `INSERT INTO contacts (id, user_id, company_id, name, phone, email, address)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          cid, employerId, req.companyId || null,
          (contact.name || "").toString(),
          contact.phone || null,
          contact.email || null,
          contact.address || null
        ]
      );
      contactId = cid;
    }

    // Verify contact ownership if one was supplied.
    if (contactId) {
      const cRow = await pool.query(
        `SELECT id FROM contacts WHERE id = $1 AND user_id = $2`,
        [contactId, employerId]
      );
      if (!cRow.rows.length) return res.status(404).json({ error: "contact_not_found" });
    }

    const firstDate = first_service_date ? new Date(first_service_date).toISOString().slice(0, 10) : null;
    const inserted = await pool.query(
      `INSERT INTO service_plans (
         user_id, company_id, created_by_user_id, contact_id, plan_name,
         status, price_cents, currency, billing_interval, billing_interval_count,
         service_interval, service_interval_count, first_service_date, next_service_date,
         included_services, notes
       ) VALUES ($1,$2,$3,$4,$5,'draft',$6,$7,$8,$9,$10,$11,$12,$12,$13,$14)
       RETURNING *`,
      [
        employerId, req.companyId || null, req.userId, contactId, plan_name,
        priceInt, (currency || "usd").toLowerCase(),
        billing_interval, Math.max(1, parseInt(billing_interval_count || 1, 10)),
        service_interval, Math.max(1, parseInt(service_interval_count || 1, 10)),
        firstDate,
        included_services || null, notes || null
      ]
    );
    await pool.query(
      `INSERT INTO service_plan_events (user_id, company_id, created_by_user_id, service_plan_id, contact_id, event_type, notes)
       VALUES ($1,$2,$3,$4,$5,'created',$6)`,
      [employerId, req.companyId || null, req.userId, inserted.rows[0].id, contactId, `Created by ${req.userEmail || req.userId}`]
    );
    if (req.companyId) {
      await emitAutomationEvent({
        companyId: req.companyId,
        eventType: "service_plan.created",
        subjectType: "service_plan",
        subjectId: inserted.rows[0].id,
        actorUserId: req.userId,
        source: "service_plans.api",
        dedupeKey: `service_plan.created:${inserted.rows[0].id}`,
        payload: { service_plan_id: inserted.rows[0].id, contact_id: contactId, plan_name }
      });
      await syncAutomationSchedulesForServicePlan(req.companyId, inserted.rows[0]);
    }
    // Join contact info for the response so the client shows the customer.
    const joined = await pool.query(
      `SELECT sp.*, c.name AS contact_name, c.phone AS contact_phone,
              c.email AS contact_email, c.address AS contact_address
         FROM service_plans sp
         LEFT JOIN contacts c ON c.id::text = sp.contact_id::text
        WHERE sp.id = $1`,
      [inserted.rows[0].id]
    );
    res.json(sanitizeServicePlan(joined.rows[0], { employeeSafe: req.role !== "employer" }));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "create_service_plan_failed", detail: e.message });
  }
});

app.put("/api/service-plans/:id", authRequired, requireEmployer, async (req, res) => {
  try {
    const employerId = await resolveEmployerUserId(req);
    const b = req.body || {};
    const owned = await pool.query(
      `SELECT id FROM service_plans WHERE id = $1 AND user_id = $2`,
      [req.params.id, employerId]
    );
    if (!owned.rows.length) return res.status(404).json({ error: "not_found" });
    const before = await pool.query(`SELECT * FROM service_plans WHERE id = $1 AND user_id = $2`, [req.params.id, employerId]);
    const { rows } = await pool.query(
      `UPDATE service_plans
          SET plan_name = COALESCE($2, plan_name),
              price_cents = COALESCE($3, price_cents),
              billing_interval = COALESCE($4, billing_interval),
              billing_interval_count = COALESCE($5, billing_interval_count),
              service_interval = COALESCE($6, service_interval),
              service_interval_count = COALESCE($7, service_interval_count),
              first_service_date = COALESCE($8::date, first_service_date),
              next_service_date  = COALESCE($9::date, next_service_date),
              included_services  = COALESCE($10, included_services),
              notes = COALESCE($11, notes),
              updated_at = now()
        WHERE id = $1
        RETURNING *`,
      [
        req.params.id,
        b.plan_name || null,
        Number.isFinite(parseInt(b.price_cents, 10)) ? parseInt(b.price_cents, 10) : null,
        b.billing_interval || null,
        Number.isFinite(parseInt(b.billing_interval_count, 10)) ? parseInt(b.billing_interval_count, 10) : null,
        b.service_interval || null,
        Number.isFinite(parseInt(b.service_interval_count, 10)) ? parseInt(b.service_interval_count, 10) : null,
        b.first_service_date || null,
        b.next_service_date || null,
        b.included_services || null,
        b.notes || null
      ]
    );
    if (req.companyId) {
      const prev = before.rows[0] || {};
      const changed = ["plan_name", "price_cents", "billing_interval", "billing_interval_count", "service_interval", "service_interval_count", "first_service_date", "next_service_date"].filter((field) => JSON.stringify(prev[field] ?? null) !== JSON.stringify(rows[0][field] ?? null)).map((field) => ({ field, old_value: prev[field] ?? null, new_value: rows[0][field] ?? null }));
      if (changed.length) {
        const payload = { service_plan_id: rows[0].id, contact_id: rows[0].contact_id, status: rows[0].status, price_cents: rows[0].price_cents, next_service_date: rows[0].next_service_date, changed_fields: changed };
        await emitAutomationEvent({ companyId: req.companyId, eventType: "service_plan.updated", subjectType: "service_plan", subjectId: rows[0].id, actorUserId: req.userId, source: "service_plans.api", dedupeKey: `service_plan.updated:${rows[0].id}:${rows[0].updated_at?.toISOString?.() || Date.now()}`, payload });
        const eventMap = { price_cents: "service_plan.price_changed", billing_interval: "service_plan.billing_interval_changed", billing_interval_count: "service_plan.billing_interval_changed", service_interval: "service_plan.service_interval_changed", service_interval_count: "service_plan.service_interval_changed", first_service_date: "service_plan.first_service_date_changed", next_service_date: "service_plan.next_service_changed" };
        for (const item of changed) {
          const eventType = eventMap[item.field];
          if (eventType) await emitAutomationEvent({ companyId: req.companyId, eventType, subjectType: "service_plan", subjectId: rows[0].id, actorUserId: req.userId, source: "service_plans.api", dedupeKey: `${eventType}:${rows[0].id}:${rows[0].updated_at?.toISOString?.() || Date.now()}:${item.field}`, payload: { ...payload, changed_fields: [item] } });
        }
      }
      await syncAutomationSchedulesForServicePlan(req.companyId, rows[0]);
    }
    res.json(sanitizeServicePlan(rows[0]));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "update_service_plan_failed" });
  }
});

// Start the connected-account subscription. Both employer and employee can
// call this because the whole point is to collect the customer's first
// payment at signup time.
app.post("/api/service-plans/:id/start-connected-subscription", authRequired, async (req, res) => {
  if (!canCollectServicePlanPayment(req)) return res.status(403).json({ error: "forbidden" });
  const stripe = requireStripe(res); if (!stripe) return;
  try {
    const employerId = await resolveEmployerUserId(req);
    const { rows } = await pool.query(
      `SELECT sp.*, c.name AS contact_name, c.phone AS contact_phone,
              c.email AS contact_email, c.address AS contact_address
         FROM service_plans sp
         LEFT JOIN contacts c ON c.id::text = sp.contact_id::text
        WHERE sp.id = $1 AND sp.user_id = $2`,
      [req.params.id, employerId]
    );
    const plan = rows[0];
    if (!plan) return res.status(404).json({ error: "not_found" });
    if (req.role !== "employer" && plan.created_by_user_id !== req.userId) {
      return res.status(403).json({ error: "forbidden" });
    }

    const settings = await ensureBusinessSettings(employerId, req.companyId);
    if (!settings.stripe_account_id) return res.status(400).json({ error: "stripe_not_connected" });

    // Confirm the connected account can charge right now.
    const acct = await stripe.accounts.retrieve(settings.stripe_account_id);
    if (!acct.charges_enabled) {
      await persistStripeAccountReadiness(employerId, acct);
      return res.status(400).json(stripeChargesBlockedResponse(acct));
    }

    const connectedAccountId = settings.stripe_account_id;
    const publishableKey = process.env.STRIPE_PUBLISHABLE_KEY;
    if (!publishableKey) return res.status(503).json({ error: "publishable_key_missing" });

    if (plan.stripe_subscription_id) {
      const existingConnectedAccountId = plan.stripe_connected_account_id || connectedAccountId;
      let subscription;
      try {
        subscription = await stripe.subscriptions.retrieve(
          plan.stripe_subscription_id,
          { expand: ["latest_invoice.payment_intent"] },
          { stripeAccount: existingConnectedAccountId }
        );
      } catch (err) {
        console.error("[stripe] existing subscription retrieve failed before start", {
          service_plan_id: plan.id,
          subscription_id: plan.stripe_subscription_id,
          connected_account_id: existingConnectedAccountId,
          message: err.message,
          type: err.type,
          code: err.code,
          requestId: err.requestId
        });
        return res.status(409).json({
          error: "existing_subscription_unavailable",
          message: "This plan already has a Stripe subscription. Refresh the plan or review it in Stripe before starting another payment."
        });
      }
      await applyStripeSubscriptionStatus({
        subscription,
        connectedAccountId: existingConnectedAccountId,
        servicePlanId: plan.id,
        source: "stripe.start_existing_subscription_guard"
      });
      const resume = await buildExistingSubscriptionPaymentSheetResponse({
        plan,
        subscription,
        connectedAccountId: existingConnectedAccountId,
        publishableKey,
        actorUserId: req.userId
      });
      console.warn("[stripe] blocked duplicate subscription start", {
        service_plan_id: plan.id,
        existing_subscription_id: subscription.id,
        connected_account_id: existingConnectedAccountId,
        stripe_subscription_status: subscription.status,
        returned_existing_payment_intent: Boolean(resume)
      });
      if (resume) return res.json(resume);
      const localStatus = mapStripeSubscriptionToWolfCRMStatus(subscription) || plan.status;
      const error = subscriptionBlocksNewStart(subscription.status)
        ? "stripe_subscription_already_exists"
        : "stripe_subscription_restart_required";
      return res.status(409).json({
        error,
        message: "This service plan already has a Stripe subscription. Refresh the plan instead of starting another payment.",
        subscription_id: subscription.id,
        stripe_subscription_status: subscription.status,
        status: localStatus
      });
    }

    // Create or reuse the Stripe customer ON THE CONNECTED ACCOUNT.
    let customerId = plan.stripe_customer_id;
    if (!customerId || plan.stripe_connected_account_id !== connectedAccountId) {
      const customer = await stripe.customers.create(
        {
          name: plan.contact_name || undefined,
          email: plan.contact_email || undefined,
          phone: plan.contact_phone || undefined,
          address: plan.contact_address ? { line1: plan.contact_address } : undefined,
          metadata: { wolfcrm_contact_id: plan.contact_id || "", wolfcrm_plan_id: plan.id }
        },
        { stripeAccount: connectedAccountId }
      );
      customerId = customer.id;
    }

    // Create ephemeral key so PaymentSheet can render the saved-cards flow.
    const ephemeralKey = await stripe.ephemeralKeys.create(
      { customer: customerId },
      { apiVersion: STRIPE_MOBILE_EPHEMERAL_KEY_API_VERSION, stripeAccount: connectedAccountId }
    );

    // Product + price on the connected account.
    let productId = plan.stripe_product_id;
    if (!productId) {
      const product = await stripe.products.create(
        { name: plan.plan_name, metadata: { wolfcrm_plan_id: plan.id } },
        { stripeAccount: connectedAccountId }
      );
      productId = product.id;
    }
    let priceId = plan.stripe_price_id;
    if (!priceId) {
      const iv = stripeIntervalMap(plan.billing_interval, plan.billing_interval_count);
      const price = await stripe.prices.create(
        {
          currency: (plan.currency || "usd").toLowerCase(),
          product: productId,
          unit_amount: plan.price_cents,
          recurring: iv,
          metadata: { wolfcrm_plan_id: plan.id }
        },
        { stripeAccount: connectedAccountId }
      );
      priceId = price.id;
    }

    // Subscription that requires initial payment via PaymentIntent (mobile-friendly).
    const subParams = {
      customer: customerId,
      items: [{ price: priceId }],
      payment_behavior: "default_incomplete",
      payment_settings: {
        save_default_payment_method: "on_subscription",
        payment_method_types: ["card"]
      },
      expand: ["latest_invoice.payment_intent"],
      metadata: {
        wolfcrm_plan_id: plan.id,
        wolfcrm_user_id: employerId,
        wolfcrm_contact_id: plan.contact_id || ""
      }
    };
    if (STRIPE_PLATFORM_FEE_BPS > 0) {
      subParams.application_fee_percent = STRIPE_PLATFORM_FEE_BPS / 100;
    }
    const subscription = await stripe.subscriptions.create(
      subParams,
      { stripeAccount: connectedAccountId }
    );

    const invoice = subscription.latest_invoice;
    const pi = invoice && invoice.payment_intent;
    if (!pi || !pi.client_secret) {
      return res.status(500).json({ error: "no_payment_intent" });
    }

    // Persist Stripe IDs and mark local plan as payment_pending.
    await pool.query(
      `UPDATE service_plans
          SET stripe_connected_account_id = $2,
              stripe_customer_id = $3,
              stripe_product_id = $4,
              stripe_price_id = $5,
              stripe_subscription_id = $6,
              stripe_subscription_status = $7,
              stripe_payment_intent_id = $8,
              stripe_latest_invoice_id = $9,
              stripe_payment_collection_paused = false,
              status = 'payment_pending',
              updated_at = now()
        WHERE id = $1`,
      [
        plan.id, connectedAccountId, customerId, productId, priceId,
        subscription.id, subscription.status,
        pi.id, invoice.id
      ]
    );

    // Payment record for the initial invoice.
    const paymentRecord = await pool.query(
      `INSERT INTO payment_records (
         user_id, company_id, created_by_user_id, contact_id, service_plan_id,
         payment_type, status, amount_cents, currency, description,
         stripe_connected_account_id, stripe_customer_id, stripe_payment_intent_id,
         stripe_invoice_id, stripe_subscription_id
       ) VALUES ($1,$2,$3,$4,$5,'service_plan_first_payment','pending',$6,$7,$8,$9,$10,$11,$12,$13)
       RETURNING *`,
      [
        employerId, req.companyId || null, req.userId,
        plan.contact_id, plan.id,
        plan.price_cents, (plan.currency || "usd").toLowerCase(),
        `Initial payment for ${plan.plan_name}`,
        connectedAccountId, customerId, pi.id, invoice.id, subscription.id
      ]
    );

    await pool.query(
      `INSERT INTO service_plan_events (user_id, company_id, created_by_user_id, service_plan_id, contact_id, event_type, notes)
       VALUES ($1,$2,$3,$4,$5,'payment_started',$6)`,
      [employerId, req.companyId || null, req.userId, plan.id, plan.contact_id,
       `Started by ${req.userEmail || req.userId}`]
    );
    if (req.companyId) {
      await emitAutomationEvent({
        companyId: req.companyId,
        eventType: "payment.started",
        subjectType: "payment",
        subjectId: paymentRecord.rows[0].id,
        actorUserId: req.userId,
        source: "stripe.api",
        dedupeKey: `payment.started:${paymentRecord.rows[0].id}`,
        payload: { payment_id: paymentRecord.rows[0].id, contact_id: plan.contact_id, service_plan_id: plan.id, amount_cents: plan.price_cents, currency: (plan.currency || "usd").toLowerCase(), status: "pending", stripe_payment_intent_id: pi.id, stripe_subscription_id: subscription.id }
      });
      await emitAutomationEvent({
        companyId: req.companyId,
        eventType: "service_plan.subscription_created",
        subjectType: "service_plan",
        subjectId: plan.id,
        actorUserId: req.userId,
        source: "stripe.api",
        dedupeKey: `service_plan.subscription_created:${subscription.id}`,
        payload: { service_plan_id: plan.id, contact_id: plan.contact_id, subscription_status: subscription.status, stripe_subscription_id: subscription.id }
      });
      await syncAutomationSchedulesForServicePlan(req.companyId, { ...plan, status: "payment_pending", stripe_subscription_id: subscription.id, stripe_subscription_status: subscription.status });
    }
    console.log("[stripe] connected subscription payment started", {
      mode: publishableKey.startsWith("pk_test_") ? "test" : publishableKey.startsWith("pk_live_") ? "live" : "unknown",
      connected_account_id: connectedAccountId,
      customer_id: customerId,
      payment_intent_id: pi.id,
      subscription_id: subscription.id,
      service_plan_id: plan.id,
      payment_record_id: paymentRecord.rows[0]?.id || null,
      amount_cents: plan.price_cents,
      currency: (plan.currency || "usd").toLowerCase()
    });

    res.json({
      publishable_key: publishableKey,
      connected_account_id: connectedAccountId,
      customer_id: customerId,
      ephemeral_key_secret: ephemeralKey.secret,
      payment_intent_client_secret: pi.client_secret,
      subscription_id: subscription.id,
      service_plan_id: plan.id,
      payment_record_id: paymentRecord.rows[0].id
    });
  } catch (e) {
    console.error("start-connected-subscription:", {
      message: e.message,
      type: e.type,
      code: e.code,
      decline_code: e.decline_code,
      requestId: e.requestId
    });
    res.status(500).json({ error: "start_subscription_failed", detail: e.message });
  }
});

app.post("/api/service-plans/:id/mark-serviced", authRequired, requireEmployer, async (req, res) => {
  try {
    const employerId = await resolveEmployerUserId(req);
    const { rows } = await pool.query(
      `SELECT * FROM service_plans WHERE id = $1 AND user_id = $2`,
      [req.params.id, employerId]
    );
    const plan = rows[0];
    if (!plan) return res.status(404).json({ error: "not_found" });
    const completed = req.body && req.body.completed_date
      ? new Date(req.body.completed_date).toISOString().slice(0, 10)
      : new Date().toISOString().slice(0, 10);
    const days = serviceIntervalDays(plan.service_interval, plan.service_interval_count);
    const next = addDaysISO(completed, days);
    const updated = await pool.query(
      `UPDATE service_plans
          SET last_service_date = $2::date,
              next_service_date = $3::date,
              updated_at = now()
        WHERE id = $1
        RETURNING *`,
      [plan.id, completed, next]
    );
    await pool.query(
      `INSERT INTO service_plan_events (user_id, company_id, created_by_user_id, service_plan_id, contact_id, event_type, completed_date, notes)
       VALUES ($1,$2,$3,$4,$5,'serviced',$6,$7)`,
      [employerId, req.companyId || null, req.userId, plan.id, plan.contact_id, completed,
       `Marked serviced by ${req.userEmail || req.userId}`]
    );
    if (req.companyId) {
      await emitAutomationEvent({
        companyId: req.companyId,
        eventType: "service_plan.serviced",
        subjectType: "service_plan",
        subjectId: plan.id,
        actorUserId: req.userId,
        source: "service_plans.api",
        dedupeKey: `service_plan.serviced:${plan.id}:${completed}`,
        payload: { service_plan_id: plan.id, contact_id: plan.contact_id, completed_date: completed, next_service_date: next }
      });
      await syncAutomationSchedulesForServicePlan(req.companyId, updated.rows[0]);
    }
    res.json(sanitizeServicePlan(updated.rows[0]));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "mark_serviced_failed" });
  }
});

app.post("/api/service-plans/:id/pause", authRequired, requireEmployer, async (req, res) => {
  try {
    const employerId = await resolveEmployerUserId(req);
    const planResult = await pool.query(
      `SELECT * FROM service_plans WHERE id = $1 AND user_id = $2`,
      [req.params.id, employerId]
    );
    const plan = planResult.rows[0];
    if (!plan) return res.status(404).json({ error: "not_found" });

    let updatedPlan = plan;
    const stripe = getStripe();
    if (stripe && plan.stripe_subscription_id) {
      if (!plan.stripe_connected_account_id) {
        return res.status(400).json({ error: "stripe_connected_account_missing" });
      }
      const subscription = await stripe.subscriptions.update(
        plan.stripe_subscription_id,
        { pause_collection: { behavior: "void" }, expand: ["latest_invoice.payment_intent"] },
        { stripeAccount: plan.stripe_connected_account_id }
      );
      const applied = await applyStripeSubscriptionStatus({
        subscription,
        connectedAccountId: plan.stripe_connected_account_id,
        servicePlanId: plan.id,
        source: "service_plans.api.pause"
      });
      updatedPlan = applied[0] || plan;
    } else {
      const { rows } = await pool.query(
        `UPDATE service_plans
            SET status = 'paused',
                stripe_payment_collection_paused = false,
                updated_at = now()
          WHERE id = $1 AND user_id = $2
          RETURNING *`,
        [req.params.id, employerId]
      );
      updatedPlan = rows[0];
    }

    await pool.query(
      `INSERT INTO service_plan_events (user_id, company_id, created_by_user_id, service_plan_id, contact_id, event_type, notes)
       VALUES ($1,$2,$3,$4,$5,'paused',$6)`,
      [employerId, req.companyId || null, req.userId, updatedPlan.id, updatedPlan.contact_id,
       `Paused by ${req.userEmail || req.userId}`]
    );
    if (req.companyId) {
      await cancelAutomationSchedulesForSubject(req.companyId, "service_plan", updatedPlan.id);
      await emitAutomationEvent({
        companyId: req.companyId,
        eventType: "service_plan.paused",
        subjectType: "service_plan",
        subjectId: updatedPlan.id,
        actorUserId: req.userId,
        source: "service_plans.api",
        dedupeKey: `service_plan.paused:${updatedPlan.id}:${updatedPlan.updated_at?.toISOString?.() || Date.now()}`,
        payload: {
          service_plan_id: updatedPlan.id,
          contact_id: updatedPlan.contact_id,
          status: updatedPlan.status,
          stripe_subscription_id: updatedPlan.stripe_subscription_id || null,
          stripe_payment_collection_paused: Boolean(updatedPlan.stripe_payment_collection_paused)
        }
      });
    }
    res.json(sanitizeServicePlan(updatedPlan));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "pause_failed" });
  }
});

app.post("/api/service-plans/:id/resume", authRequired, requireEmployer, async (req, res) => {
  try {
    const employerId = await resolveEmployerUserId(req);
    const planResult = await pool.query(
      `SELECT * FROM service_plans WHERE id = $1 AND user_id = $2`,
      [req.params.id, employerId]
    );
    const plan = planResult.rows[0];
    if (!plan) return res.status(404).json({ error: "not_found" });

    let updatedPlan = plan;
    const stripe = getStripe();
    if (stripe && plan.stripe_subscription_id) {
      if (!plan.stripe_connected_account_id) {
        return res.status(400).json({ error: "stripe_connected_account_missing" });
      }
      const subscription = await stripe.subscriptions.update(
        plan.stripe_subscription_id,
        { pause_collection: "", expand: ["latest_invoice.payment_intent"] },
        { stripeAccount: plan.stripe_connected_account_id }
      );
      const applied = await applyStripeSubscriptionStatus({
        subscription,
        connectedAccountId: plan.stripe_connected_account_id,
        servicePlanId: plan.id,
        source: "service_plans.api.resume"
      });
      updatedPlan = applied[0] || plan;
    } else {
      const { rows } = await pool.query(
        `UPDATE service_plans
            SET status = 'active',
                stripe_payment_collection_paused = false,
                updated_at = now()
          WHERE id = $1 AND user_id = $2
          RETURNING *`,
        [req.params.id, employerId]
      );
      updatedPlan = rows[0];
    }

    const resumeNextDate = nextServiceDateAfterResume(updatedPlan.next_service_date);
    if (resumeNextDate && String(updatedPlan.next_service_date).slice(0, 10) !== resumeNextDate) {
      const shifted = await pool.query(
        `UPDATE service_plans
            SET next_service_date = $2::date,
                updated_at = now()
          WHERE id = $1
          RETURNING *`,
        [updatedPlan.id, resumeNextDate]
      );
      updatedPlan = shifted.rows[0] || updatedPlan;
    }

    await pool.query(
      `INSERT INTO service_plan_events (user_id, company_id, created_by_user_id, service_plan_id, contact_id, event_type, notes)
       VALUES ($1,$2,$3,$4,$5,'resumed',$6)`,
      [employerId, req.companyId || null, req.userId, updatedPlan.id, updatedPlan.contact_id,
       `Resumed by ${req.userEmail || req.userId}`]
    );
    if (req.companyId) {
      await syncAutomationSchedulesForServicePlan(req.companyId, updatedPlan);
      await emitAutomationEvent({
        companyId: req.companyId,
        eventType: "service_plan.resumed",
        subjectType: "service_plan",
        subjectId: updatedPlan.id,
        actorUserId: req.userId,
        source: "service_plans.api",
        dedupeKey: `service_plan.resumed:${updatedPlan.id}:${updatedPlan.updated_at?.toISOString?.() || Date.now()}`,
        payload: {
          service_plan_id: updatedPlan.id,
          contact_id: updatedPlan.contact_id,
          status: updatedPlan.status,
          next_service_date: updatedPlan.next_service_date,
          stripe_subscription_id: updatedPlan.stripe_subscription_id || null,
          stripe_payment_collection_paused: Boolean(updatedPlan.stripe_payment_collection_paused)
        }
      });
    }
    res.json(sanitizeServicePlan(updatedPlan));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "resume_failed" });
  }
});

app.post("/api/service-plans/:id/cancel", authRequired, requireEmployer, async (req, res) => {
  try {
    const employerId = await resolveEmployerUserId(req);
    const { rows } = await pool.query(
      `SELECT * FROM service_plans WHERE id = $1 AND user_id = $2`,
      [req.params.id, employerId]
    );
    const plan = rows[0];
    if (!plan) return res.status(404).json({ error: "not_found" });
    const stripe = getStripe();
    let updatedPlan = null;
    if (stripe && plan.stripe_subscription_id && plan.stripe_connected_account_id) {
      try {
        const subscription = await stripe.subscriptions.cancel(
          plan.stripe_subscription_id,
          { expand: ["latest_invoice.payment_intent"] },
          { stripeAccount: plan.stripe_connected_account_id }
        );
        const applied = await applyStripeSubscriptionStatus({
          subscription,
          connectedAccountId: plan.stripe_connected_account_id,
          servicePlanId: plan.id,
          source: "service_plans.api.cancel"
        });
        updatedPlan = applied[0] || null;
      } catch (err) {
        console.error("stripe cancel failed:", err.message);
      }
    }
    if (!updatedPlan) {
      const updated = await pool.query(
        `UPDATE service_plans
            SET status = 'canceled',
                stripe_payment_collection_paused = false,
                updated_at = now()
          WHERE id = $1
          RETURNING *`,
        [plan.id]
      );
      updatedPlan = updated.rows[0];
    }
    await pool.query(
      `INSERT INTO service_plan_events (user_id, company_id, created_by_user_id, service_plan_id, contact_id, event_type, notes)
       VALUES ($1,$2,$3,$4,$5,'canceled',$6)`,
      [employerId, req.companyId || null, req.userId, plan.id, plan.contact_id,
       `Canceled by ${req.userEmail || req.userId}`]
    );
    if (req.companyId) {
      await cancelAutomationSchedulesForSubject(req.companyId, "service_plan", updatedPlan.id);
      await emitAutomationEvent({
        companyId: req.companyId,
        eventType: "service_plan.canceled",
        subjectType: "service_plan",
        subjectId: updatedPlan.id,
        actorUserId: req.userId,
        source: "service_plans.api",
        dedupeKey: `service_plan.canceled:${updatedPlan.id}`,
        payload: {
          service_plan_id: updatedPlan.id,
          contact_id: updatedPlan.contact_id,
          status: updatedPlan.status,
          stripe_subscription_id: updatedPlan.stripe_subscription_id || plan.stripe_subscription_id || null,
          stripe_subscription_status: updatedPlan.stripe_subscription_status || null,
          stripe_payment_collection_paused: Boolean(updatedPlan.stripe_payment_collection_paused)
        }
      });
    }
    res.json(sanitizeServicePlan(updatedPlan));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "cancel_failed" });
  }
});

// ==========================================================================
//                       CONTACT PAYMENT ROUTES
// ==========================================================================

app.post("/api/contacts/:contactId/payments/start", authRequired, async (req, res) => {
  if (!canTakeContactPayment(req)) return res.status(403).json({ error: "forbidden" });
  const stripe = requireStripe(res); if (!stripe) return;
  try {
    const employerId = await resolveEmployerUserId(req);
    const c = await pool.query(
      `SELECT * FROM contacts WHERE id = $1 AND user_id = $2`,
      [req.params.contactId, employerId]
    );
    if (!c.rows.length) return res.status(404).json({ error: "contact_not_found" });
    const contact = c.rows[0];

    const settings = await ensureBusinessSettings(employerId, req.companyId);
    if (!settings.stripe_account_id) return res.status(400).json({ error: "stripe_not_connected" });
    const acct = await stripe.accounts.retrieve(settings.stripe_account_id);
    if (!acct.charges_enabled) {
      await persistStripeAccountReadiness(employerId, acct);
      return res.status(400).json(stripeChargesBlockedResponse(acct));
    }

    const amountInt = parseInt((req.body || {}).amount_cents, 10);
    if (!Number.isFinite(amountInt) || amountInt < 50) return res.status(400).json({ error: "invalid_amount" });
    const currency = ((req.body || {}).currency || "usd").toLowerCase();
    const description = ((req.body || {}).description || "").toString();
    const paymentType = ((req.body || {}).payment_type || "one_time").toString();
    const publishableKey = process.env.STRIPE_PUBLISHABLE_KEY;
    if (!publishableKey) return res.status(503).json({ error: "publishable_key_missing" });

    const connectedAccountId = settings.stripe_account_id;
    const customer = await stripe.customers.create(
      {
        name: contact.name || undefined,
        email: contact.email || undefined,
        phone: contact.phone || undefined,
        address: contact.address ? { line1: contact.address } : undefined,
        metadata: { wolfcrm_contact_id: contact.id }
      },
      { stripeAccount: connectedAccountId }
    );
    const ephemeralKey = await stripe.ephemeralKeys.create(
      { customer: customer.id },
      { apiVersion: STRIPE_MOBILE_EPHEMERAL_KEY_API_VERSION, stripeAccount: connectedAccountId }
    );

    const piParams = {
      amount: amountInt,
      currency,
      customer: customer.id,
      description: description || `Payment from ${contact.name}`,
      automatic_payment_methods: { enabled: true },
      metadata: {
        wolfcrm_contact_id: contact.id,
        wolfcrm_user_id: employerId,
        wolfcrm_payment_type: paymentType
      }
    };
    if (STRIPE_PLATFORM_FEE_BPS > 0) {
      piParams.application_fee_amount = Math.floor((amountInt * STRIPE_PLATFORM_FEE_BPS) / 10000);
    }
    const intent = await stripe.paymentIntents.create(piParams, { stripeAccount: connectedAccountId });

    const record = await pool.query(
      `INSERT INTO payment_records (
         user_id, company_id, created_by_user_id, contact_id, service_plan_id,
         payment_type, status, amount_cents, currency, description,
         stripe_connected_account_id, stripe_customer_id, stripe_payment_intent_id
       ) VALUES ($1,$2,$3,$4,NULL,$5,'pending',$6,$7,$8,$9,$10,$11)
       RETURNING *`,
      [
        employerId, req.companyId || null, req.userId, contact.id,
        paymentType, amountInt, currency, description || null,
        connectedAccountId, customer.id, intent.id
      ]
    );
    if (req.companyId) {
      await emitAutomationEvent({
        companyId: req.companyId,
        eventType: "payment.created",
        subjectType: "payment",
        subjectId: record.rows[0].id,
        actorUserId: req.userId,
        source: "stripe.api",
        dedupeKey: `payment.created:${record.rows[0].id}`,
        payload: { payment_id: record.rows[0].id, contact_id: contact.id, amount_cents: amountInt, currency, status: "pending", stripe_payment_intent_id: intent.id }
      });
      await emitAutomationEvent({
        companyId: req.companyId,
        eventType: "payment.started",
        subjectType: "payment",
        subjectId: record.rows[0].id,
        actorUserId: req.userId,
        source: "stripe.api",
        dedupeKey: `payment.started:${record.rows[0].id}`,
        payload: { payment_id: record.rows[0].id, contact_id: contact.id, amount_cents: amountInt, currency, status: "pending", stripe_payment_intent_id: intent.id }
      });
    }
    console.log("[stripe] contact payment started", {
      mode: publishableKey.startsWith("pk_test_") ? "test" : publishableKey.startsWith("pk_live_") ? "live" : "unknown",
      connected_account_id: connectedAccountId,
      customer_id: customer.id,
      payment_intent_id: intent.id,
      contact_id: contact.id,
      payment_record_id: record.rows[0]?.id || null,
      amount_cents: amountInt,
      currency
    });
    res.json({
      publishable_key: publishableKey,
      connected_account_id: connectedAccountId,
      customer_id: customer.id,
      ephemeral_key_secret: ephemeralKey.secret,
      payment_intent_client_secret: intent.client_secret,
      payment_record_id: record.rows[0].id
    });
  } catch (e) {
    console.error("contact payment start:", {
      message: e.message,
      type: e.type,
      code: e.code,
      decline_code: e.decline_code,
      requestId: e.requestId
    });
    res.status(500).json({ error: "start_payment_failed", detail: e.message });
  }
});

app.get("/api/contacts/:contactId/payments", authRequired, async (req, res) => {
  try {
    const employerId = await resolveEmployerUserId(req);
    const c = await pool.query(`SELECT id FROM contacts WHERE id = $1 AND user_id = $2`,
      [req.params.contactId, employerId]);
    if (!c.rows.length) return res.status(404).json({ error: "contact_not_found" });
    if (req.query.reconcile_pending === "true") {
      const limit = Math.min(Math.max(Number(req.query.reconcile_limit || 20), 1), 25);
      const pending = await pool.query(
        `SELECT * FROM payment_records
          WHERE user_id = $1
            AND contact_id::text = $2
            AND status = 'pending'
            AND stripe_payment_intent_id IS NOT NULL
            AND stripe_connected_account_id IS NOT NULL
            AND created_at > now() - interval '14 days'
            AND ($3 = 'employer' OR created_by_user_id = $4)
          ORDER BY created_at DESC
          LIMIT $5`,
        [employerId, req.params.contactId, req.role, req.userId, limit]
      );
      for (const rec of pending.rows) {
        try {
          await reconcilePaymentRecordFromStripe(rec, { source: "stripe.history_reconcile" });
        } catch (err) {
          console.warn("[stripe] pending payment reconcile skipped", {
            payment_record_id: rec.id,
            payment_intent_id: rec.stripe_payment_intent_id,
            connected_account_id: rec.stripe_connected_account_id,
            message: err.message
          });
        }
      }
    }
    if (req.role === "employer") {
      const { rows } = await pool.query(
        `SELECT * FROM payment_records
          WHERE user_id = $1 AND contact_id::text = $2
          ORDER BY created_at DESC`,
        [employerId, req.params.contactId]
      );
      return res.json(rows.map((r) => sanitizePaymentRecord(r)));
    }
    const { rows } = await pool.query(
      `SELECT * FROM payment_records
        WHERE user_id = $1 AND contact_id::text = $2 AND created_by_user_id = $3
        ORDER BY created_at DESC`,
      [employerId, req.params.contactId, req.userId]
    );
    res.json(rows.map((r) => sanitizePaymentRecord(r, { employeeSafe: true })));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "list_payments_failed" });
  }
});

app.get("/api/payments", authRequired, async (req, res) => {
  try {
    const employerId = await resolveEmployerUserId(req);
    const limit = Math.min(Math.max(Number(req.query.limit || 100), 1), 200);
    if (req.role === "employer") {
      const { rows } = await pool.query(
        `SELECT * FROM payment_records
          WHERE user_id = $1
          ORDER BY created_at DESC
          LIMIT $2`,
        [employerId, limit]
      );
      return res.json(rows.map((r) => sanitizePaymentRecord(r)));
    }
    const { rows } = await pool.query(
      `SELECT * FROM payment_records
        WHERE user_id = $1 AND created_by_user_id = $2
        ORDER BY created_at DESC
        LIMIT $3`,
      [employerId, req.userId, limit]
    );
    res.json(rows.map((r) => sanitizePaymentRecord(r, { employeeSafe: true })));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "list_payments_failed" });
  }
});

app.post("/api/payments/:id/reconcile", authRequired, async (req, res) => {
  try {
    const employerId = await resolveEmployerUserId(req);
    const { rows } = await pool.query(
      `SELECT * FROM payment_records WHERE id = $1 AND user_id = $2`,
      [req.params.id, employerId]
    );
    const rec = rows[0];
    if (!rec) return res.status(404).json({ error: "payment_not_found" });
    if (req.role !== "employer" && rec.created_by_user_id !== req.userId) {
      return res.status(403).json({ error: "forbidden" });
    }
    const updated = await reconcilePaymentRecordFromStripe(rec, { source: "stripe.client_reconcile" });
    res.json(sanitizePaymentRecord(updated, { employeeSafe: req.role !== "employer" }));
  } catch (e) {
    console.error("payment reconcile failed:", {
      message: e.message,
      type: e.type,
      code: e.code,
      requestId: e.requestId
    });
    res.status(500).json({ error: "payment_reconcile_failed", detail: e.message });
  }
});

app.post("/api/payments/:id/client-result", authRequired, async (req, res) => {
  try {
    const employerId = await resolveEmployerUserId(req);
    const status = req.body?.status === "canceled" ? "canceled" : req.body?.status === "failed" ? "failed" : null;
    if (!status) return res.status(400).json({ error: "invalid_payment_client_status" });
    const note = cleanString(req.body?.note, 500) || null;
    const { rows } = await pool.query(
      `UPDATE payment_records
          SET status = $4,
              description = COALESCE(description, $5),
              updated_at = now()
        WHERE id = $1
          AND user_id = $2
          AND status = 'pending'
          AND ($3 = 'employer' OR created_by_user_id = $6)
        RETURNING *`,
      [req.params.id, employerId, req.role, status, note, req.userId]
    );
    if (!rows.length) {
      const existing = await pool.query(`SELECT * FROM payment_records WHERE id = $1 AND user_id = $2`, [req.params.id, employerId]);
      if (!existing.rows.length) return res.status(404).json({ error: "payment_not_found" });
      return res.json(sanitizePaymentRecord(existing.rows[0], { employeeSafe: req.role !== "employer" }));
    }
    res.json(sanitizePaymentRecord(rows[0], { employeeSafe: req.role !== "employer" }));
  } catch (e) {
    console.error("payment client result failed:", e);
    res.status(500).json({ error: "payment_client_result_failed" });
  }
});

app.get("/api/payments/:id", authRequired, async (req, res) => {
  try {
    const employerId = await resolveEmployerUserId(req);
    const { rows } = await pool.query(
      `SELECT * FROM payment_records WHERE id = $1 AND user_id = $2`,
      [req.params.id, employerId]
    );
    const rec = rows[0];
    if (!rec) return res.status(404).json({ error: "not_found" });
    if (req.role !== "employer" && rec.created_by_user_id !== req.userId) {
      return res.status(403).json({ error: "forbidden" });
    }
    res.json(sanitizePaymentRecord(rec, { employeeSafe: req.role !== "employer" }));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "get_payment_failed" });
  }
});

// ==========================================================================
//                            STRIPE WEBHOOK
// ==========================================================================
// The raw body middleware is registered near the top of the file. Here we
// verify the signature and update local state to match Stripe's authoritative
// view of the world.
function verifyStripeWebhookEvent(req, stripe) {
  const secrets = [
    ["STRIPE_WEBHOOK_SECRET", process.env.STRIPE_WEBHOOK_SECRET],
    ["STRIPE_CONNECT_WEBHOOK_SECRET", process.env.STRIPE_CONNECT_WEBHOOK_SECRET]
  ].filter(([, value]) => value);
  if (!secrets.length) {
    const err = new Error("stripe_webhook_secret_missing");
    err.statusCode = 503;
    throw err;
  }
  let lastError = null;
  for (const [name, secret] of secrets) {
    try {
      const event = stripe.webhooks.constructEvent(
        req.body,
        req.headers["stripe-signature"],
        secret
      );
      return { event, secretName: name };
    } catch (err) {
      lastError = err;
    }
  }
  const err = new Error(lastError?.message || "invalid_stripe_webhook_signature");
  err.statusCode = 400;
  throw err;
}

async function handleStripeWebhook(req, res) {
  const stripe = getStripe();
  if (!stripe) return res.status(503).send("stripe_not_configured");
  console.log("[stripe] webhook endpoint entered", {
    path: req.originalUrl || req.path,
    timestamp: new Date().toISOString(),
    stripe_signature_present: Boolean(req.headers["stripe-signature"])
  });

  let event;
  let verifiedWith = null;
  try {
    const verified = verifyStripeWebhookEvent(req, stripe);
    event = verified.event;
    verifiedWith = verified.secretName;
  } catch (err) {
    console.error("webhook signature failed:", err.message);
    return res.status(err.statusCode || 400).send(`Webhook Error: ${err.message}`);
  }

  const connectedAccountId = event.account || null;
  console.log("[stripe] webhook received", {
    event_id: event.id,
    event_type: event.type,
    connected_account_id: connectedAccountId,
    livemode: event.livemode,
    signature_verified: true,
    verified_with: verifiedWith
  });

  try {
    // Duplicate protection: check if we've already recorded this stripe_event_id.
    const dupe = await pool.query(
      `SELECT id FROM service_plan_events WHERE stripe_event_id = $1 LIMIT 1`,
      [event.id]
    );
    if (dupe.rows.length) {
      console.log("[stripe] webhook duplicate ignored", {
        event_id: event.id,
        event_type: event.type,
        connected_account_id: connectedAccountId
      });
      return res.json({ received: true, duplicate: true });
    }

    async function markServicePlanEvent(planId, contactId, employerId, companyId, type, notes = null) {
      if (!planId) return;
      await pool.query(
        `INSERT INTO service_plan_events (user_id, company_id, service_plan_id, contact_id, event_type, notes, stripe_event_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT DO NOTHING`,
        [employerId, companyId || null, planId, contactId || null, type, notes, event.id]
      );
    }

    switch (event.type) {
      case "account.updated": {
        const acct = event.data.object;
        await persistStripeAccountReadinessByAccountId(acct);
        break;
      }

      case "customer.subscription.created":
      case "customer.subscription.updated":
      case "customer.subscription.deleted": {
        const sub = event.data.object;
        const rows = await applyStripeSubscriptionStatus({
          subscription: sub,
          connectedAccountId,
          source: "stripe.webhook",
          stripeEventId: event.id
        });
        if (rows.length) {
          await markServicePlanEvent(rows[0].id, rows[0].contact_id, rows[0].user_id, rows[0].company_id,
            `stripe_${event.type}`, `Subscription is ${sub.status}`);
        }
        break;
      }

      case "invoice.paid":
      case "invoice.payment_succeeded": {
        const invoice = event.data.object;
        // Update payment record.
        const paidRecords = await pool.query(
          `UPDATE payment_records
              SET status = 'succeeded', updated_at = now()
            WHERE (stripe_invoice_id = $1 OR stripe_subscription_id = $2)
              AND ($3::text IS NULL OR stripe_connected_account_id = $3)
            RETURNING id, company_id, contact_id, service_plan_id, amount_cents, currency`,
          [invoice.id, invoice.subscription || null, connectedAccountId]
        );
        for (const rec of paidRecords.rows) {
          await emitAutomationEvent({
            companyId: rec.company_id,
            eventType: "payment.succeeded",
            subjectType: "payment",
            subjectId: rec.id,
            source: "stripe.webhook",
            dedupeKey: `payment.succeeded:invoice:${invoice.id}:${rec.id}`,
            payload: { payment_id: rec.id, contact_id: rec.contact_id, service_plan_id: rec.service_plan_id, amount_cents: rec.amount_cents, currency: rec.currency, stripe_event_id: event.id, stripe_invoice_id: invoice.id }
          });
        }
        console.log("[stripe] invoice payment matched records", {
          event_id: event.id,
          event_type: event.type,
          connected_account_id: connectedAccountId,
          invoice_id: invoice.id,
          subscription_id: invoice.subscription || null,
          matched_payment_records: paidRecords.rows.length
        });
        // If this is a subscription invoice, reconcile the authoritative subscription status.
        if (invoice.subscription) {
          let rows = [];
          try {
            const subscription = await stripe.subscriptions.retrieve(
              invoice.subscription,
              { expand: ["latest_invoice.payment_intent"] },
              connectedAccountId ? { stripeAccount: connectedAccountId } : undefined
            );
            rows = await applyStripeSubscriptionStatus({
              subscription,
              connectedAccountId,
              source: "stripe.webhook",
              stripeEventId: `invoice:${invoice.id}`
            });
          } catch (err) {
            console.warn("[stripe] invoice subscription reconcile failed", {
              event_id: event.id,
              invoice_id: invoice.id,
              subscription_id: invoice.subscription,
              connected_account_id: connectedAccountId,
              message: err.message
            });
          }
          if (rows.length) {
            await markServicePlanEvent(rows[0].id, rows[0].contact_id, rows[0].user_id, rows[0].company_id,
              "invoice_paid", `Invoice ${invoice.id} paid`);
            await emitAutomationEvent({
              companyId: rows[0].company_id,
              eventType: "service_plan.subscription_payment_succeeded",
              subjectType: "service_plan",
              subjectId: rows[0].id,
              source: "stripe.webhook",
              dedupeKey: `service_plan.subscription_payment_succeeded:invoice:${invoice.id}:${rows[0].id}`,
              payload: { service_plan_id: rows[0].id, contact_id: rows[0].contact_id, stripe_event_id: event.id, stripe_invoice_id: invoice.id, stripe_subscription_id: invoice.subscription, subscription_status: "active" }
            });
          }
        }
        break;
      }

      case "invoice.payment_failed": {
        const invoice = event.data.object;
        const failedRecords = await pool.query(
          `UPDATE payment_records
              SET status = 'failed', updated_at = now()
            WHERE (stripe_invoice_id = $1 OR stripe_subscription_id = $2)
              AND ($3::text IS NULL OR stripe_connected_account_id = $3)
            RETURNING id, company_id, contact_id, service_plan_id, amount_cents, currency`,
          [invoice.id, invoice.subscription || null, connectedAccountId]
        );
        for (const rec of failedRecords.rows) {
          await emitAutomationEvent({
            companyId: rec.company_id,
            eventType: "payment.failed",
            subjectType: "payment",
            subjectId: rec.id,
            source: "stripe.webhook",
            dedupeKey: `payment.failed:${event.id}:${rec.id}`,
            payload: { payment_id: rec.id, contact_id: rec.contact_id, service_plan_id: rec.service_plan_id, amount_cents: rec.amount_cents, currency: rec.currency, stripe_event_id: event.id, stripe_invoice_id: invoice.id }
          });
        }
        if (invoice.subscription) {
          let rows = [];
          try {
            const subscription = await stripe.subscriptions.retrieve(
              invoice.subscription,
              { expand: ["latest_invoice.payment_intent"] },
              connectedAccountId ? { stripeAccount: connectedAccountId } : undefined
            );
            rows = await applyStripeSubscriptionStatus({
              subscription,
              connectedAccountId,
              source: "stripe.webhook",
              stripeEventId: event.id
            });
          } catch (err) {
            console.warn("[stripe] failed-invoice subscription reconcile failed", {
              event_id: event.id,
              invoice_id: invoice.id,
              subscription_id: invoice.subscription,
              connected_account_id: connectedAccountId,
              message: err.message
            });
          }
          if (rows.length) {
            await markServicePlanEvent(rows[0].id, rows[0].contact_id, rows[0].user_id, rows[0].company_id,
              "invoice_failed", `Invoice ${invoice.id} failed`);
            await emitAutomationEvent({
              companyId: rows[0].company_id,
              eventType: "service_plan.subscription_payment_failed",
              subjectType: "service_plan",
              subjectId: rows[0].id,
              source: "stripe.webhook",
              dedupeKey: `service_plan.subscription_payment_failed:${event.id}:${rows[0].id}`,
              payload: { service_plan_id: rows[0].id, contact_id: rows[0].contact_id, stripe_event_id: event.id, stripe_invoice_id: invoice.id, stripe_subscription_id: invoice.subscription, subscription_status: "past_due" }
            });
          }
        }
        break;
      }

      case "payment_intent.succeeded":
      case "payment_intent.processing":
      case "payment_intent.payment_failed": {
        const pi = event.data.object;
        await applyStripePaymentIntentStatus({
          paymentIntent: pi,
          connectedAccountId,
          source: "stripe.webhook",
          stripeEventId: event.id
        });
        break;
      }

      case "charge.refunded": {
        const charge = event.data.object;
        if (charge.payment_intent) {
          const refunded = await pool.query(
            `UPDATE payment_records
                SET status = 'refunded', updated_at = now()
              WHERE stripe_payment_intent_id = $1
              RETURNING id, company_id, contact_id, service_plan_id, amount_cents, currency`,
            [charge.payment_intent]
          );
          for (const rec of refunded.rows) {
            await emitAutomationEvent({
              companyId: rec.company_id,
              eventType: charge.amount_refunded && charge.amount_refunded < charge.amount ? "payment.partially_refunded" : "payment.refunded",
              subjectType: "payment",
              subjectId: rec.id,
              source: "stripe.webhook",
              dedupeKey: `payment.refunded:${event.id}:${rec.id}`,
              payload: { payment_id: rec.id, contact_id: rec.contact_id, service_plan_id: rec.service_plan_id, amount_cents: rec.amount_cents, currency: rec.currency, stripe_event_id: event.id, stripe_payment_intent_id: charge.payment_intent }
            });
          }
        }
        break;
      }

      case "payment_intent.canceled":
      case "payment_intent.requires_action":
      case "payment_intent.requires_payment_method": {
        const pi = event.data.object;
        const statusMap = { "payment_intent.canceled": "canceled", "payment_intent.requires_action": "action_required", "payment_intent.requires_payment_method": "payment_method_required" };
        const eventMap = { "payment_intent.canceled": "payment.canceled", "payment_intent.requires_action": "payment.action_required", "payment_intent.requires_payment_method": "payment.payment_method_required" };
        const records = await pool.query(
          `UPDATE payment_records SET status = $2, updated_at = now()
            WHERE stripe_payment_intent_id = $1
            RETURNING id, company_id, contact_id, service_plan_id, amount_cents, currency`,
          [pi.id, statusMap[event.type]]
        );
        for (const rec of records.rows) {
          await emitAutomationEvent({
            companyId: rec.company_id,
            eventType: eventMap[event.type],
            subjectType: "payment",
            subjectId: rec.id,
            source: "stripe.webhook",
            dedupeKey: `${eventMap[event.type]}:${event.id}:${rec.id}`,
            payload: { payment_id: rec.id, contact_id: rec.contact_id, service_plan_id: rec.service_plan_id, amount_cents: rec.amount_cents, currency: rec.currency, stripe_event_id: event.id, stripe_payment_intent_id: pi.id }
          });
        }
        break;
      }

      case "charge.dispute.created":
      case "charge.dispute.updated":
      case "charge.dispute.closed": {
        const dispute = event.data.object;
        const eventType = event.type === "charge.dispute.created" ? "payment.dispute_created" : event.type === "charge.dispute.closed" ? "payment.dispute_closed" : "payment.dispute_updated";
        const records = await pool.query(
          `SELECT id, company_id, contact_id, service_plan_id, amount_cents, currency
             FROM payment_records
            WHERE stripe_payment_intent_id = $1 OR stripe_invoice_id = $2`,
          [dispute.payment_intent || null, dispute.invoice || null]
        );
        for (const rec of records.rows) {
          await emitAutomationEvent({
            companyId: rec.company_id,
            eventType,
            subjectType: "payment",
            subjectId: rec.id,
            source: "stripe.webhook",
            dedupeKey: `${eventType}:${event.id}:${rec.id}`,
            payload: { payment_id: rec.id, contact_id: rec.contact_id, service_plan_id: rec.service_plan_id, amount_cents: rec.amount_cents, currency: rec.currency, stripe_event_id: event.id, dispute_id: dispute.id, dispute_status: dispute.status }
          });
        }
        break;
      }

      default:
        // no-op — we simply acknowledge unhandled events.
        break;
    }

    res.json({ received: true });
  } catch (e) {
    console.error("webhook handling error:", e);
    res.status(500).json({ error: "webhook_handler_failed" });
  }
}

app.post("/stripe/webhook", handleStripeWebhook);
app.post("/stripe/connect-webhook", handleStripeWebhook);

app.get("/", (_req, res) => res.send("WolfCRM backend up"));

let serverStarted = false;
async function startServer() {
  if (serverStarted) {
    console.warn("[startup] startServer called after listener already started; ignoring duplicate call");
    return;
  }
  serverStarted = true;
  await bootstrap();
  await installAutomationSystem({
    app,
    pool,
    authRequired,
    requireEmployer,
    sendPushToUsers,
    createTwilioClient,
    twilioPublicUrl,
    getStripe
  });
  await installFinanceSystem({
    app,
    pool,
    authRequired,
    requireEmployer
  });
  app.listen(PORT, () => console.log(`API listening on ${PORT}`));
}

export { app, bootstrap, pool, startServer };

if (process.env.WOLFCRM_SKIP_SERVER_START !== "true") {
  startServer().catch((err) => {
    console.error("Server startup failed:", err);
    process.exit(1);
  });
}
