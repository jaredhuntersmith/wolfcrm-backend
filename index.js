/* WolfCRM backend — email/password auth + user-scoped CRM data */
import express from "express";
import cors from "cors";
import { randomUUID, randomBytes, scryptSync, timingSafeEqual } from "crypto";
import pkg from "pg";
import { S3Client, PutObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import Stripe from "stripe";

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

app.use(express.json({ limit: "2mb" }));

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
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS contacts_updated_idx ON contacts(updated_at DESC);
    ALTER TABLE contacts ADD COLUMN IF NOT EXISTS lead_info JSONB;

    CREATE TABLE IF NOT EXISTS zapier_tokens (
      user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      token TEXT UNIQUE NOT NULL,
      auto_stage_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS zapier_tokens_token_idx ON zapier_tokens(token);

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

    -- Same for opportunities so auto-assigned webhook leads are visible company-wide.
    ALTER TABLE opportunities ADD COLUMN IF NOT EXISTS company_id UUID;
    UPDATE opportunities o
      SET company_id = u.company_id
      FROM users u
      WHERE u.id = o.user_id
        AND o.company_id IS NULL
        AND u.company_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS opportunities_company_idx ON opportunities(company_id);

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
    CREATE INDEX IF NOT EXISTS conversations_company_updated_idx ON conversations(company_id, updated_at DESC);

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
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS services JSONB NOT NULL DEFAULT '[]'::jsonb;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS service_items JSONB NOT NULL DEFAULT '[]'::jsonb;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS price_cents INTEGER;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS material_cost_cents INTEGER;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS company_id UUID;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS created_by UUID;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS sales_user_ids JSONB NOT NULL DEFAULT '[]'::jsonb;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS worker_user_ids JSONB NOT NULL DEFAULT '[]'::jsonb;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS finished_at TIMESTAMPTZ;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS finished_by UUID;
    ALTER TABLE map_pins ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
    ALTER TABLE measurements ADD COLUMN IF NOT EXISTS linked_contact_ids JSONB NOT NULL DEFAULT '[]'::jsonb;
    ALTER TABLE measurements ADD COLUMN IF NOT EXISTS units TEXT NOT NULL DEFAULT 'feet';
    ALTER TABLE measurements ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
  `);

  // Ensure user_id column exists
  await pool.query(`ALTER TABLE contacts ADD COLUMN IF NOT EXISTS user_id UUID;`);
  await pool.query(`ALTER TABLE contacts ADD COLUMN IF NOT EXISTS company_id UUID;`);

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
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    ALTER TABLE business_settings ADD COLUMN IF NOT EXISTS company_id UUID;
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
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
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
bootstrap().catch((err) => {
  console.error("DB bootstrap failed:", err);
  process.exit(1);
});

// ---------- auth middleware ----------
async function authRequired(req, res, next) {
  const token = bearer(req);
  if (!token) return res.status(401).json({ error: "unauthorized" });
  const { rows } = await pool.query(
    `UPDATE sessions s
       SET last_used_at = now()
       FROM users u
       LEFT JOIN employee_permissions p ON p.user_id = u.id
      WHERE s.token = $1 AND u.id = s.user_id
      RETURNING s.user_id, u.email, u.role, u.company_id, COALESCE(p.can_delete_contacts, u.role = 'employer') AS can_delete_contacts`,
    [token]
  );
  if (!rows.length) return res.status(401).json({ error: "unauthorized" });
  req.userId = rows[0].user_id;
  req.userEmail = rows[0].email;
  req.role = rows[0].role;
  req.companyId = rows[0].company_id;
  req.permissions = { canDeleteContacts: !!rows[0].can_delete_contacts };
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
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

function mapStripeSubscriptionStatus(s) {
  switch (s) {
    case "active":
    case "trialing":
      return "active";
    case "incomplete":
      return "payment_pending";
    case "past_due":
    case "unpaid":
      return "past_due";
    case "canceled":
      return "canceled";
    case "incomplete_expired":
      return "failed";
    default:
      return null;
  }
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
            COALESCE(p.can_delete_contacts, u.role = 'employer') AS can_delete_contacts
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
      { can_delete_contacts: !!u.can_delete_contacts },
      u.company_id ? { id: u.company_id, name: u.company_name, join_code: u.join_code } : null
    )
  });
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
        `SELECT id, email, role, display_name, photo_url FROM users WHERE id = $1`,
        [req.userId]
      );
      return res.json(rows);
    }
    const { rows } = await pool.query(
      `SELECT id, email, role, display_name, photo_url
         FROM users
        WHERE company_id = $1
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
      `SELECT u.id, u.email, COALESCE(p.can_delete_contacts,false) AS can_delete_contacts
         FROM users u
         LEFT JOIN employee_permissions p ON p.user_id = u.id
        WHERE u.company_id = $1 AND u.role = 'employee'
        ORDER BY u.email ASC`,
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

app.put("/api/company/employees/:id/permissions", authRequired, requireEmployer, async (req, res) => {
  try {
    const canDelete = !!req.body.can_delete_contacts;
    const employee = await pool.query(
      `SELECT id FROM users WHERE id = $1 AND company_id = $2 AND role = 'employee'`,
      [req.params.id, req.companyId]
    );
    if (!employee.rowCount) return res.status(404).json({ error: "employee_not_found" });
    const { rows } = await pool.query(
      `INSERT INTO employee_permissions(user_id, company_id, can_delete_contacts)
       VALUES($1,$2,$3)
       ON CONFLICT(user_id) DO UPDATE
         SET can_delete_contacts = EXCLUDED.can_delete_contacts,
             updated_at = now()
       RETURNING user_id AS id, can_delete_contacts`,
      [req.params.id, req.companyId, canDelete]
    );
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
    await notifyMany(recipients.rows.map((r) => r.user_id), req.companyId, "internal_message", "New message", body || "Attachment", { conversation_id: req.params.id, message_id: id }, req.userId);
    res.status(201).json((await messageRowsWithAttachments(rows))[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "send_conversation_message_failed" }); }
});

app.post("/api/internal/conversations/:id/read", authRequired, async (req, res) => {
  try {
    await pool.query(`UPDATE conversation_participants SET last_read_at = now() WHERE conversation_id = $1 AND user_id = $2`, [req.params.id, req.userId]);
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
    await notifyMany(recipients.rows.map((r) => r.id), req.companyId, "channel_message", `#${channel.rows[0].name}`, body || "Attachment", { channel_id: req.params.id, message_id: id }, req.userId);
    res.status(201).json((await messageRowsWithAttachments(rows))[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "send_channel_message_failed" }); }
});

app.delete("/api/internal/messages/:id", authRequired, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `UPDATE messages SET deleted_at = now(), body = ''
        WHERE id = $1 AND sender_id = $2 AND deleted_at IS NULL
        RETURNING id`,
      [req.params.id, req.userId]
    );
    if (!rows.length) return res.status(404).json({ error: "message_not_found" });
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
    u1, u2, u3, u4, u5, lead_info
  } = req.body || {};
  if (!name) return res.status(400).json({ error: "name_required" });

  const id = randomUUID();
  try {
    const r = await pool.query(
      `
      INSERT INTO contacts (
        id, user_id, company_id, name, phone, email, address, value_cents, lat, lng, tags, job_type, u1, u2, u3, u4, u5, lead_info
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
      ) RETURNING *;
      `,
      [
        id, req.userId, req.companyId, name || "", phone || "", email || "", address || "",
        Number.isFinite(Number(value_cents)) ? Number(value_cents) : null,
        lat ?? null, lng ?? null, tags || "", job_type || "",
        u1 || "", u2 || "", u3 || "", u4 || "", u5 || "",
        Array.isArray(lead_info) ? JSON.stringify(lead_info) : null
      ]
    );
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
    u1, u2, u3, u4, u5, lead_info
  } = req.body || {};
  try {
    const scope = companyOrUserContactWhere(req);
    // lead_info: null means "leave as-is"; explicit array (even empty) overwrites.
    const leadInfoParam = Array.isArray(lead_info) ? JSON.stringify(lead_info) : null;
    const r = await pool.query(
      `
      UPDATE contacts SET
        name = COALESCE($2,name),
        phone = COALESCE($3,phone),
        email = COALESCE($4,email),
        address = COALESCE($5,address),
        value_cents = COALESCE($6,value_cents),
        lat = COALESCE($7,lat),
        lng = COALESCE($8,lng),
        tags = COALESCE($9,tags),
        job_type = COALESCE($10,job_type),
        u1 = COALESCE($11,u1),
        u2 = COALESCE($12,u2),
        u3 = COALESCE($13,u3),
        u4 = COALESCE($14,u4),
        u5 = COALESCE($15,u5),
        lead_info = COALESCE($16::jsonb, lead_info)
      WHERE id = $1 AND ${scope.sql.replace("$1", "$17")}
      RETURNING *;
      `,
      [
        req.params.id, name, phone, email, address,
        Number.isFinite(Number(value_cents)) ? Number(value_cents) : null,
        lat ?? null, lng ?? null, tags, job_type, u1, u2, u3, u4, u5,
        leadInfoParam,
        ...scope.values
      ]
    );
    if (!r.rowCount) return res.status(404).json({ error: "not_found" });
    res.json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "failed_update" });
  }
});

app.delete("/api/contacts/:id", authRequired, async (req, res) => {
  try {
    if (!req.permissions.canDeleteContacts) {
      return res.status(403).json({ error: "permission_denied" });
    }
    const scope = companyOrUserContactWhere(req);
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

// GET current token (create if missing)
app.get("/api/integrations/zapier/token", authRequired, async (req, res) => {
  try {
    let { rows } = await pool.query(
      `SELECT token, auto_stage_id FROM zapier_tokens WHERE user_id = $1`,
      [req.userId]
    );
    if (!rows.length) {
      const token = randomBytes(24).toString("hex");
      await pool.query(
        `INSERT INTO zapier_tokens (user_id, token) VALUES ($1, $2)`,
        [req.userId, token]
      );
      rows = [{ token, auto_stage_id: null }];
    }
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "failed_get_token" });
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
       RETURNING token, auto_stage_id`,
      [req.userId, token]
    );
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "failed_rotate_token" });
  }
});

// Set stage to auto-assign new leads into. The stage_id must belong to the
// caller (either their user_id or their company). Passing null clears it.
app.put("/api/integrations/zapier/auto-stage", authRequired, async (req, res) => {
  const { stage_id } = req.body || {};
  try {
    if (stage_id) {
      const check = await pool.query(
        `SELECT 1 FROM stages
         WHERE id = $1
           AND (user_id = $2 OR (company_id IS NOT NULL AND company_id = $3))
         LIMIT 1`,
        [stage_id, req.userId, req.companyId || null]
      );
      if (!check.rowCount) {
        return res.status(400).json({ error: "stage_not_in_scope", message: "That stage does not belong to your account." });
      }
    }
    const { rows } = await pool.query(
      `UPDATE zapier_tokens SET auto_stage_id = $2 WHERE user_id = $1
       RETURNING token, auto_stage_id`,
      [req.userId, stage_id || null]
    );
    if (!rows.length) return res.status(404).json({ error: "token_not_found" });
    res.json(rows[0]);
  } catch (e) {
    console.error("[zapier] set auto_stage failed:", e);
    res.status(500).json({ error: "failed_set_auto_stage" });
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

// ---------- Public webhook (no auth) ----------
// Accepts:
//   * Structured shape:  { full_name/name/first_name+last_name, phone, email, address,
//                          questions: [{question, answer}, ...] }
//   * Zapier Facebook Lead Ads raw shape (POST Data left blank in Zapier):
//                        { id, created_time, form_id, field_data: [{name, values:[]}], ... }
//   * Any mix — everything unknown becomes a Lead Info box so nothing is lost.
//
// Behavior:
//   * ALWAYS creates the contact (200/201) as long as the token is valid, even
//     if auto-assignment is off or the configured stage was deleted.
//   * Detailed [zapier] console logs at every step so Railway logs make issues
//     obvious.
//   * Never leaks internals in the JSON response.
function zLog(...args) { console.log("[zapier]", ...args); }
function zWarn(...args) { console.warn("[zapier]", ...args); }
function zErr(...args) { console.error("[zapier]", ...args); }

// Meta / Facebook Lead Ads uses fixed field slugs. We recognize the most common
// ones so we auto-populate the contact's structured fields as well as putting
// them in Lead Info boxes.
const FB_NAME_KEYS  = new Set(["full_name", "name"]);
const FB_FIRST_KEYS = new Set(["first_name", "firstname"]);
const FB_LAST_KEYS  = new Set(["last_name", "lastname", "surname"]);
const FB_PHONE_KEYS = new Set(["phone_number", "phone", "mobile_number", "mobile", "cell_phone"]);
const FB_EMAIL_KEYS = new Set(["email", "e_mail", "email_address"]);
const FB_ADDR_KEYS  = new Set(["address", "street_address", "full_address", "city_state_zip"]);

function firstAnswer(field) {
  if (!field) return "";
  if (Array.isArray(field.values) && field.values.length) return String(field.values[0]);
  if (field.value != null) return String(field.value);
  if (field.answer != null) return String(field.answer);
  return "";
}

function normalizedFieldData(fieldData) {
  if (!Array.isArray(fieldData)) return [];
  return fieldData.map(f => {
    if (!f || typeof f !== "object") return { question: "", answer: "" };
    return {
      key: (f.name || f.key || f.label || "").toString().trim(),
      question: (f.label || f.question || f.name || "").toString().trim(),
      answer: firstAnswer(f).trim()
    };
  });
}

app.post("/webhooks/leads/:token", async (req, res) => {
  const startedAt = Date.now();
  const { token } = req.params;
  const bodyKeys = Object.keys(req.body || {});
  zLog("request received", { tokenPrefix: (token || "").slice(0, 6), bodyKeys });

  try {
    if (!token || token.length < 16) {
      zWarn("bad token format");
      return res.status(400).json({ ok: false, error: "bad_token", message: "Webhook token missing or malformed." });
    }

    // ---- 1) look up the account this token belongs to
    const tokenRows = await pool.query(
      `SELECT zt.user_id, zt.auto_stage_id, u.company_id
       FROM zapier_tokens zt
       JOIN users u ON u.id = zt.user_id
       WHERE zt.token = $1`,
      [token]
    );
    if (!tokenRows.rows.length) {
      zWarn("token not found");
      return res.status(404).json({ ok: false, error: "token_not_found", message: "Unknown webhook token." });
    }
    const { user_id: userId, company_id: companyId, auto_stage_id: autoStageId } = tokenRows.rows[0];
    zLog("token matched", { userId, companyId, hasAutoStage: !!autoStageId });

    // ---- 2) parse payload — support structured, FB Lead Ads, and mixed shapes
    const body = req.body || {};
    const fieldEntries = normalizedFieldData(body.field_data);

    // Look up FB-style fields for structured columns
    const findFB = (matcher) => {
      const e = fieldEntries.find(x => matcher.has(x.key.toLowerCase()));
      return e ? e.answer : "";
    };

    const fullName = (body.full_name || body.name || findFB(FB_NAME_KEYS) || "").toString().trim();
    const first    = (body.first_name || findFB(FB_FIRST_KEYS) || "").toString().trim();
    const last     = (body.last_name  || findFB(FB_LAST_KEYS)  || "").toString().trim();
    const composed = [first, last].filter(Boolean).join(" ").trim();
    const name     = fullName || composed || "New Lead";

    const phone   = (body.phone   || body.phone_number || findFB(FB_PHONE_KEYS) || "").toString().trim() || null;
    const email   = (body.email   || findFB(FB_EMAIL_KEYS) || "").toString().trim() || null;
    const address = (body.address || body.street_address || findFB(FB_ADDR_KEYS) || "").toString().trim() || null;

    zLog("payload parsed", { name, hasPhone: !!phone, hasEmail: !!email, hasAddress: !!address, fieldCount: fieldEntries.length });

    // ---- 3) build Lead Info boxes
    // Questions come from body.questions (structured) OR from field_data
    // (Facebook). Skip entries we already captured in structured columns so
    // Lead Info doesn't just repeat the contact's phone/email/etc.
    const usedFBKeys = new Set([
      ...FB_NAME_KEYS, ...FB_FIRST_KEYS, ...FB_LAST_KEYS,
      ...FB_PHONE_KEYS, ...FB_EMAIL_KEYS, ...FB_ADDR_KEYS,
    ]);

    let questions = [];
    if (Array.isArray(body.questions)) {
      questions = body.questions.map(q => ({
        question: (q && q.question) || "",
        answer:   (q && q.answer)   || ""
      }));
    } else if (fieldEntries.length) {
      questions = fieldEntries
        .filter(e => !usedFBKeys.has(e.key.toLowerCase()))
        .map(e => ({ question: e.question || e.key, answer: e.answer }));
    }

    const leadInfo = questions
      .filter(q => q && (q.question || q.answer))
      .slice(0, 25)
      .map(q => {
        const question = (q.question || "").toString().trim();
        const answer   = (q.answer   || "").toString().trim();
        if (!question && !answer) return "";
        if (!answer) return question;
        if (!question) return `**${answer}**`;
        return `${question}\n**${answer}**`;
      });

    zLog("lead_info built", { boxes: leadInfo.length });

    // ---- 4) create the contact (this MUST succeed for the response to be 201)
    const contactId = randomUUID();
    let contactRow;
    try {
      const inserted = await pool.query(
        `INSERT INTO contacts (
          id, user_id, company_id, name, phone, email, address, value_cents, lat, lng, tags, job_type,
          u1, u2, u3, u4, u5, lead_info
        ) VALUES (
          $1, $2, $3, $4, $5, $6, $7, NULL, NULL, NULL, $8, NULL,
          NULL, NULL, NULL, NULL, NULL, $9
        ) RETURNING *`,
        [
          contactId, userId, companyId, name, phone || "", email || "", address || "",
          "lead,zapier",
          JSON.stringify(leadInfo)
        ]
      );
      contactRow = inserted.rows[0];
      zLog("contact created", { contactId, name });
    } catch (e) {
      zErr("contact insert failed:", e && e.message ? e.message : e);
      return res.status(500).json({ ok: false, error: "contact_create_failed", message: "Could not save the incoming lead. Check server logs." });
    }

    // ---- 5) auto-assign to a stage IF configured AND that stage still exists
    let stageAssignment = { attempted: !!autoStageId, applied: false, reason: null };
    if (autoStageId) {
      try {
        const stageCheck = await pool.query(
          `SELECT id FROM stages
           WHERE id = $1
             AND (user_id = $2 OR (company_id IS NOT NULL AND company_id = $3))
           LIMIT 1`,
          [autoStageId, userId, companyId || null]
        );
        if (!stageCheck.rowCount) {
          stageAssignment.reason = "stage_not_found_or_out_of_scope";
          zWarn("auto-assign skipped — stage missing or out of scope", { autoStageId, userId, companyId });
        } else {
          const oppId = randomUUID();
          await pool.query(
            `INSERT INTO opportunities (id, user_id, company_id, contact_id, state, stage_id)
             VALUES ($1, $2, $3, $4, 'stage', $5)`,
            [oppId, userId, companyId || null, contactId, autoStageId]
          );
          stageAssignment.applied = true;
          zLog("opportunity created", { oppId, stageId: autoStageId });
        }
      } catch (e) {
        stageAssignment.reason = "opportunity_insert_failed";
        zErr("auto-assign failed (contact still created):", e && e.message ? e.message : e);
      }
    } else {
      stageAssignment.reason = "no_auto_stage_configured";
      zLog("auto-assign skipped — none configured");
    }

    zLog("done", { ms: Date.now() - startedAt, stageAssignment });
    return res.status(201).json({
      ok: true,
      contact_id: contactRow.id,
      name: contactRow.name,
      lead_info_boxes: leadInfo.length,
      stage_assignment: stageAssignment
    });
  } catch (e) {
    zErr("unhandled webhook error:", e && e.message ? e.message : e, e && e.stack ? e.stack : "");
    return res.status(500).json({ ok: false, error: "webhook_failed", message: "Unexpected server error while processing the lead." });
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
    res.json(rows);
  } catch (e) { console.error("[stages] list failed:", e); res.status(500).json({ error: "failed_list_stages" }); }
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
    res.json(r.rows[0]);
  } catch (e) { console.error("[opportunities] upsert failed:", e); res.status(500).json({ error: "failed_upsert_opportunity" }); }
});

app.delete("/api/opportunities/:id", authRequired, async (req, res) => {
  try {
    await pool.query(
      `DELETE FROM opportunities
       WHERE id = $1
         AND (user_id = $2 OR (company_id IS NOT NULL AND company_id = $3))`,
      [req.params.id, req.userId, req.companyId || null]);
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
              company_id, created_by, sales_user_ids, worker_user_ids, finished_at, finished_by
       FROM schedule_events WHERE ${where.sql} ORDER BY start_at ASC`,
      where.values
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_list_schedule" }); }
});

app.put("/api/schedule/:id", authRequired, async (req, res) => {
  const {
    title, start, end, color, notes, contact_id, reminder_minutes, services, service_items, price_cents, material_cost_cents,
    sales_user_ids, worker_user_ids, finished_at, finished_by
  } = req.body || {};
  if (!title || !start || !end) return res.status(400).json({ error: "missing_params" });
  const salesIDs = Array.isArray(sales_user_ids) ? sales_user_ids.slice(0, 2) : [req.userId];
  const workerIDs = Array.isArray(worker_user_ids) ? worker_user_ids : [];
  try {
    const previous = await pool.query(
      `SELECT worker_user_ids FROM schedule_events WHERE id = $1 AND (user_id = $2 OR company_id = $3)`,
      [req.params.id, req.userId, req.companyId]
    );
    const oldWorkerIDs = previous.rows.length && Array.isArray(previous.rows[0].worker_user_ids)
      ? previous.rows[0].worker_user_ids
      : [];
    const isNewJob = previous.rowCount === 0;
    const r = await pool.query(
      `INSERT INTO schedule_events
        (id, user_id, company_id, created_by, title, start_at, end_at, color, notes, contact_id,
         reminder_minutes, services, service_items, price_cents, material_cost_cents, sales_user_ids, worker_user_ids, finished_at, finished_by)
       VALUES ($1, $2, $3, $2, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb, $12::jsonb, $13, $14, $15::jsonb, $16::jsonb, $17, $18)
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
             finished_at = EXCLUDED.finished_at,
             finished_by = EXCLUDED.finished_by,
             updated_at = now()
       WHERE schedule_events.user_id = $2 OR schedule_events.company_id = $3
       RETURNING id, title, start_at AS start, end_at AS "end", color, notes,
                 contact_id, reminder_minutes, services, price_cents, material_cost_cents,
                 service_items, company_id, created_by, sales_user_ids, worker_user_ids, finished_at, finished_by`,
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
    res.json(r.rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_upsert_schedule" }); }
});

app.delete("/api/schedule/:id", authRequired, async (req, res) => {
  try {
    if (req.companyId) {
      await pool.query(`DELETE FROM schedule_events WHERE id = $1 AND company_id = $2`,
        [req.params.id, req.companyId]);
    } else {
      await pool.query(`DELETE FROM schedule_events WHERE id = $1 AND user_id = $2`,
        [req.params.id, req.userId]);
    }
    res.status(204).end();
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_delete_schedule" }); }
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
          AND finished_at >= $2
          AND finished_at < $3
          AND (
            sales_user_ids ? $4
            OR (jsonb_array_length(sales_user_ids) = 0 AND created_by = $5)
          )
        ORDER BY finished_at DESC`,
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
      `SELECT p.user_id, u.company_id
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
      `INSERT INTO map_pins (id, user_id, latitude, longitude, name, address, notes, status, phone, email, contact_id, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, COALESCE($12::timestamptz, now()))
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
       RETURNING id, user_id, latitude, longitude, name, address, notes, status, phone, email, contact_id, created_at`,
      [
        req.params.id, ownerUserId, latitude, longitude,
        name || '', address || '', notes || '', status || 'lead',
        phone || null, email || null, contact_id || null, created_at || null
      ]
    );
    res.json(r.rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_upsert_pin" }); }
});

app.delete("/api/map-pins/:id", authRequired, async (req, res) => {
  try {
    await pool.query(
      `DELETE FROM map_pins p
        USING users u
        WHERE p.id = $1
          AND u.id = p.user_id
          AND (p.user_id = $2 OR ($3 = 'employer' AND u.company_id = $4))`,
      [req.params.id, req.userId, req.role, req.companyId]
    );
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
    res.json(r.rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_upsert_measurement" }); }
});

app.delete("/api/measurements/:id", authRequired, async (req, res) => {
  try {
    await pool.query(`DELETE FROM measurements WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.userId]);
    res.status(204).end();
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_delete_measurement" }); }
});

// ---------- TO-DO: TASKS ----------
app.get("/api/todo/tasks", authRequired, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, title, due_date, reminders, subtasks, completed, completed_at, color_hex
       FROM todo_tasks WHERE user_id = $1 ORDER BY due_date NULLS LAST, updated_at DESC`,
      [req.userId]
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_list_tasks" }); }
});

app.put("/api/todo/tasks/:id", authRequired, async (req, res) => {
  const { title, due_date, reminders, subtasks, completed, completed_at, color_hex } = req.body || {};
  if (!title) return res.status(400).json({ error: "title_required" });
  try {
    const r = await pool.query(
      `INSERT INTO todo_tasks
        (id, user_id, title, due_date, reminders, subtasks, completed, completed_at, color_hex)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8, $9)
       ON CONFLICT (id) DO UPDATE
         SET title = EXCLUDED.title,
             due_date = EXCLUDED.due_date,
             reminders = EXCLUDED.reminders,
             subtasks = EXCLUDED.subtasks,
             completed = EXCLUDED.completed,
             completed_at = EXCLUDED.completed_at,
             color_hex = EXCLUDED.color_hex,
             updated_at = now()
       WHERE todo_tasks.user_id = $2
       RETURNING id, title, due_date, reminders, subtasks, completed, completed_at, color_hex`,
      [
        req.params.id, req.userId, title, due_date || null,
        JSON.stringify(reminders || []), JSON.stringify(subtasks || []),
        toBool(completed), completed_at || null, color_hex || null
      ]
    );
    res.json(r.rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_upsert_task" }); }
});

app.delete("/api/todo/tasks/:id", authRequired, async (req, res) => {
  try {
    await pool.query(`DELETE FROM todo_tasks WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.userId]);
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
    res.json(r.rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_upsert_routine" }); }
});

app.delete("/api/todo/routines/:id", authRequired, async (req, res) => {
  try {
    await pool.query(`DELETE FROM todo_routines WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.userId]);
    await pool.query(`DELETE FROM todo_routine_done WHERE routine_id = $1 AND user_id = $2`,
      [req.params.id, req.userId]);
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
    res.json(r.rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_upsert_customer_reminder" }); }
});

app.delete("/api/todo/customer-reminders/:id", authRequired, async (req, res) => {
  try {
    await pool.query(
      `DELETE FROM todo_customer_reminders WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.userId]
    );
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
        const status = acct.details_submitted
          ? (acct.charges_enabled ? "ready" : "verification_pending")
          : "setup_incomplete";
        const updated = await pool.query(
          `UPDATE business_settings
              SET stripe_charges_enabled = $2,
                  stripe_payouts_enabled = $3,
                  stripe_details_submitted = $4,
                  stripe_default_currency = COALESCE($5, stripe_default_currency),
                  stripe_connect_status = $6,
                  updated_at = now()
            WHERE user_id = $1
            RETURNING *`,
          [
            req.userId,
            !!acct.charges_enabled,
            !!acct.payouts_enabled,
            !!acct.details_submitted,
            acct.default_currency || null,
            status
          ]
        );
        return res.json({ settings: sanitizeBusinessSettings(updated.rows[0]) });
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
    const status = acct.details_submitted
      ? (acct.charges_enabled ? "ready" : "verification_pending")
      : "setup_incomplete";
    const updated = await pool.query(
      `UPDATE business_settings
          SET stripe_charges_enabled = $2,
              stripe_payouts_enabled = $3,
              stripe_details_submitted = $4,
              stripe_default_currency = COALESCE($5, stripe_default_currency),
              stripe_connect_status = $6,
              updated_at = now()
        WHERE user_id = $1
        RETURNING *`,
      [
        req.userId,
        !!acct.charges_enabled,
        !!acct.payouts_enabled,
        !!acct.details_submitted,
        acct.default_currency || null,
        status
      ]
    );
    res.json({ settings: sanitizeBusinessSettings(updated.rows[0]) });
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
      await pool.query(
        `UPDATE business_settings
            SET stripe_charges_enabled = $2,
                stripe_payouts_enabled = $3,
                stripe_details_submitted = $4,
                updated_at = now()
          WHERE user_id = $1`,
        [employerId, !!acct.charges_enabled, !!acct.payouts_enabled, !!acct.details_submitted]
      );
      return res.status(400).json({ error: "charges_not_enabled" });
    }

    const connectedAccountId = settings.stripe_account_id;
    const publishableKey = process.env.STRIPE_PUBLISHABLE_KEY;
    if (!publishableKey) return res.status(503).json({ error: "publishable_key_missing" });

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
      { apiVersion: "2024-06-20", stripeAccount: connectedAccountId }
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
    console.error("start-connected-subscription:", e);
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
    res.json(sanitizeServicePlan(updated.rows[0]));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "mark_serviced_failed" });
  }
});

app.post("/api/service-plans/:id/pause", authRequired, requireEmployer, async (req, res) => {
  try {
    const employerId = await resolveEmployerUserId(req);
    const { rows } = await pool.query(
      `UPDATE service_plans
          SET status = 'paused', updated_at = now()
        WHERE id = $1 AND user_id = $2
        RETURNING *`,
      [req.params.id, employerId]
    );
    if (!rows.length) return res.status(404).json({ error: "not_found" });
    await pool.query(
      `INSERT INTO service_plan_events (user_id, company_id, created_by_user_id, service_plan_id, contact_id, event_type, notes)
       VALUES ($1,$2,$3,$4,$5,'paused',$6)`,
      [employerId, req.companyId || null, req.userId, rows[0].id, rows[0].contact_id,
       `Paused by ${req.userEmail || req.userId}`]
    );
    // TODO: also pause the Stripe subscription (`pause_collection`) when a
    // clear resume UX exists — leaving local-only for now so we never
    // accidentally break Stripe billing state.
    res.json(sanitizeServicePlan(rows[0]));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "pause_failed" });
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
    if (stripe && plan.stripe_subscription_id && plan.stripe_connected_account_id) {
      try {
        await stripe.subscriptions.cancel(plan.stripe_subscription_id,
          { stripeAccount: plan.stripe_connected_account_id });
      } catch (err) {
        console.error("stripe cancel failed:", err.message);
      }
    }
    const updated = await pool.query(
      `UPDATE service_plans
          SET status = 'canceled', updated_at = now()
        WHERE id = $1
        RETURNING *`,
      [plan.id]
    );
    await pool.query(
      `INSERT INTO service_plan_events (user_id, company_id, created_by_user_id, service_plan_id, contact_id, event_type, notes)
       VALUES ($1,$2,$3,$4,$5,'canceled',$6)`,
      [employerId, req.companyId || null, req.userId, plan.id, plan.contact_id,
       `Canceled by ${req.userEmail || req.userId}`]
    );
    res.json(sanitizeServicePlan(updated.rows[0]));
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
    if (!acct.charges_enabled) return res.status(400).json({ error: "charges_not_enabled" });

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
      { apiVersion: "2024-06-20", stripeAccount: connectedAccountId }
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
    res.json({
      publishable_key: publishableKey,
      connected_account_id: connectedAccountId,
      customer_id: customer.id,
      ephemeral_key_secret: ephemeralKey.secret,
      payment_intent_client_secret: intent.client_secret,
      payment_record_id: record.rows[0].id
    });
  } catch (e) {
    console.error("contact payment start:", e);
    res.status(500).json({ error: "start_payment_failed", detail: e.message });
  }
});

app.get("/api/contacts/:contactId/payments", authRequired, async (req, res) => {
  try {
    const employerId = await resolveEmployerUserId(req);
    const c = await pool.query(`SELECT id FROM contacts WHERE id = $1 AND user_id = $2`,
      [req.params.contactId, employerId]);
    if (!c.rows.length) return res.status(404).json({ error: "contact_not_found" });
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
app.post("/stripe/webhook", async (req, res) => {
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  const stripe = getStripe();
  if (!secret || !stripe) return res.status(503).send("stripe_not_configured");

  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers["stripe-signature"],
      secret
    );
  } catch (err) {
    console.error("webhook signature failed:", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  const connectedAccountId = event.account || null;

  try {
    // Duplicate protection: check if we've already recorded this stripe_event_id.
    const dupe = await pool.query(
      `SELECT id FROM service_plan_events WHERE stripe_event_id = $1 LIMIT 1`,
      [event.id]
    );
    if (dupe.rows.length) return res.json({ received: true, duplicate: true });

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
        await pool.query(
          `UPDATE business_settings
              SET stripe_charges_enabled = $2,
                  stripe_payouts_enabled = $3,
                  stripe_details_submitted = $4,
                  stripe_default_currency = COALESCE($5, stripe_default_currency),
                  stripe_connect_status = CASE
                    WHEN $4 = false THEN 'setup_incomplete'
                    WHEN $2 = true THEN 'ready'
                    ELSE 'verification_pending'
                  END,
                  updated_at = now()
            WHERE stripe_account_id = $1`,
          [acct.id, !!acct.charges_enabled, !!acct.payouts_enabled, !!acct.details_submitted, acct.default_currency || null]
        );
        break;
      }

      case "customer.subscription.created":
      case "customer.subscription.updated":
      case "customer.subscription.deleted": {
        const sub = event.data.object;
        const localStatus = event.type === "customer.subscription.deleted"
          ? "canceled"
          : (mapStripeSubscriptionStatus(sub.status) || null);
        const { rows } = await pool.query(
          `UPDATE service_plans
              SET stripe_subscription_status = $2,
                  status = COALESCE($3, status),
                  updated_at = now()
            WHERE stripe_subscription_id = $1
              AND (stripe_connected_account_id = $4 OR $4 IS NULL)
            RETURNING id, user_id, company_id, contact_id`,
          [sub.id, sub.status, localStatus, connectedAccountId]
        );
        if (rows.length) {
          await markServicePlanEvent(rows[0].id, rows[0].contact_id, rows[0].user_id, rows[0].company_id,
            `stripe_${event.type}`, `Subscription is ${sub.status}`);
        }
        break;
      }

      case "invoice.payment_succeeded": {
        const invoice = event.data.object;
        // Update payment record.
        await pool.query(
          `UPDATE payment_records
              SET status = 'succeeded', updated_at = now()
            WHERE stripe_invoice_id = $1
               OR stripe_subscription_id = $2`,
          [invoice.id, invoice.subscription || null]
        );
        // If this is the initial invoice, mark plan active.
        if (invoice.subscription) {
          const { rows } = await pool.query(
            `UPDATE service_plans
                SET status = 'active',
                    stripe_subscription_status = 'active',
                    updated_at = now()
              WHERE stripe_subscription_id = $1
                AND (stripe_connected_account_id = $2 OR $2 IS NULL)
              RETURNING id, user_id, company_id, contact_id`,
            [invoice.subscription, connectedAccountId]
          );
          if (rows.length) {
            await markServicePlanEvent(rows[0].id, rows[0].contact_id, rows[0].user_id, rows[0].company_id,
              "invoice_paid", `Invoice ${invoice.id} paid`);
          }
        }
        break;
      }

      case "invoice.payment_failed": {
        const invoice = event.data.object;
        await pool.query(
          `UPDATE payment_records
              SET status = 'failed', updated_at = now()
            WHERE stripe_invoice_id = $1`,
          [invoice.id]
        );
        if (invoice.subscription) {
          const { rows } = await pool.query(
            `UPDATE service_plans
                SET status = 'past_due', updated_at = now()
              WHERE stripe_subscription_id = $1
              RETURNING id, user_id, company_id, contact_id`,
            [invoice.subscription]
          );
          if (rows.length) {
            await markServicePlanEvent(rows[0].id, rows[0].contact_id, rows[0].user_id, rows[0].company_id,
              "invoice_failed", `Invoice ${invoice.id} failed`);
          }
        }
        break;
      }

      case "payment_intent.succeeded": {
        const pi = event.data.object;
        await pool.query(
          `UPDATE payment_records
              SET status = 'succeeded', updated_at = now()
            WHERE stripe_payment_intent_id = $1`,
          [pi.id]
        );
        break;
      }

      case "payment_intent.payment_failed": {
        const pi = event.data.object;
        await pool.query(
          `UPDATE payment_records
              SET status = 'failed', updated_at = now()
            WHERE stripe_payment_intent_id = $1`,
          [pi.id]
        );
        break;
      }

      case "charge.refunded": {
        const charge = event.data.object;
        if (charge.payment_intent) {
          await pool.query(
            `UPDATE payment_records
                SET status = 'refunded', updated_at = now()
              WHERE stripe_payment_intent_id = $1`,
            [charge.payment_intent]
          );
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
});

app.get("/", (_req, res) => res.send("WolfCRM backend up"));
app.listen(PORT, () => console.log(`API listening on ${PORT}`));
