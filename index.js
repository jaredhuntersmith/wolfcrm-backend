/* WolfCRM backend — email/password auth + user-scoped CRM data */
import express from "express";
import cors from "cors";
import { randomUUID, randomBytes, scryptSync, timingSafeEqual } from "crypto";
import pkg from "pg";
import { S3Client, PutObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

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

app.use(cors());
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
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS contacts_updated_idx ON contacts(updated_at DESC);

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
      `SELECT id, name, join_code, logo_data_url, website, address, phone, email
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

app.get("/api/company/invoice-settings", authRequired, async (req, res) => {
  try {
    if (!req.companyId) return res.status(404).json({ error: "company_not_found" });
    const { rows } = await pool.query(
      `SELECT id, name, join_code, logo_data_url, website, address, phone, email
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
          ${prefix}.created_at, ${prefix}.updated_at`;
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
        WHERE e.user_id = $1 AND e.end_at IS NULL
        ORDER BY e.start_at DESC LIMIT 1`,
      [req.userId]
    );
    const entries = await pool.query(
      `SELECT ${entrySelect("e")}
         FROM time_clock_entries e
         JOIN users u ON u.id = e.user_id
        WHERE e.user_id = $1 AND e.start_at >= $2 AND e.start_at < $3
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
    const { rows } = await pool.query(
      `UPDATE time_clock_entries
          SET end_at = $3, updated_by = $2, updated_at = now()
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
        WHERE e.company_id = $1 AND e.start_at >= $2 AND e.start_at < $3
        ORDER BY u.email ASC, e.start_at DESC`,
      [req.companyId, range.start.toISOString(), range.end.toISOString()]
    );
    res.json({ employees: employees.rows, entries: entries.rows });
  } catch (e) { console.error(e); res.status(500).json({ error: "time_company_failed" }); }
});

app.get("/api/time-clock/range", authRequired, requireEmployer, async (req, res) => {
  try {
    const start = new Date(req.query.start);
    const end = new Date(req.query.end);
    if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || start >= end) {
      return res.status(400).json({ error: "invalid_range" });
    }
    const employees = await pool.query(
      `SELECT id, email, role FROM users WHERE company_id = $1 ORDER BY email ASC`,
      [req.companyId]
    );
    const entries = await pool.query(
      `SELECT ${entrySelect("e")}
         FROM time_clock_entries e
         JOIN users u ON u.id = e.user_id
        WHERE e.company_id = $1 AND e.start_at >= $2 AND e.start_at < $3
        ORDER BY u.email ASC, e.start_at DESC`,
      [req.companyId, start.toISOString(), end.toISOString()]
    );
    res.json({ employees: employees.rows, entries: entries.rows });
  } catch (e) { console.error(e); res.status(500).json({ error: "time_range_failed" }); }
});

app.patch("/api/time-clock/entries/:id", authRequired, requireEmployer, async (req, res) => {
  try {
    const start = new Date(req.body.start_at);
    const end = req.body.end_at ? new Date(req.body.end_at) : null;
    if (Number.isNaN(start.getTime()) || (end && Number.isNaN(end.getTime()))) {
      return res.status(400).json({ error: "invalid_dates" });
    }
    const { rows } = await pool.query(
      `UPDATE time_clock_entries
          SET start_at = $3,
              end_at = $4,
              note = $5,
              updated_by = $2,
              updated_at = now()
        WHERE id = $1 AND company_id = $6
        RETURNING *`,
      [req.params.id, req.userId, start.toISOString(), end ? end.toISOString() : null, req.body.note || null, req.companyId]
    );
    if (!rows.length) return res.status(404).json({ error: "entry_not_found" });
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "time_entry_update_failed" }); }
});

// ---------- contacts (AUTH REQUIRED + USER-SCOPED) ----------
app.get("/api/contacts", authRequired, async (req, res) => {
  const q = (req.query.q || "").toString().trim();
  try {
    let rows;
    if (q) {
      rows = (
        await pool.query(
          `
          SELECT * FROM contacts
          WHERE user_id = $1
            AND (name ILIKE $2 OR COALESCE(phone,'') ILIKE $2 OR COALESCE(email,'') ILIKE $2
                 OR COALESCE(address,'') ILIKE $2 OR COALESCE(job_type,'') ILIKE $2
                 OR COALESCE(u1,'') ILIKE $2 OR COALESCE(u2,'') ILIKE $2
                 OR COALESCE(u3,'') ILIKE $2 OR COALESCE(u4,'') ILIKE $2
                 OR COALESCE(u5,'') ILIKE $2)
          ORDER BY updated_at DESC
        `,
          [req.userId, `%${q}%`]
        )
      ).rows;
    } else {
      rows = (
        await pool.query(
          `SELECT * FROM contacts WHERE user_id = $1 ORDER BY updated_at DESC LIMIT 200`,
          [req.userId]
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
    const { rows } = await pool.query(
      `SELECT * FROM contacts WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.userId]
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
    u1, u2, u3, u4, u5
  } = req.body || {};
  if (!name) return res.status(400).json({ error: "name_required" });

  const id = randomUUID();
  try {
    const r = await pool.query(
      `
      INSERT INTO contacts (
        id, user_id, name, phone, email, address, value_cents, lat, lng, tags, job_type, u1, u2, u3, u4, u5
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
      ) RETURNING *;
      `,
      [
        id, req.userId, name || "", phone || "", email || "", address || "",
        Number.isFinite(Number(value_cents)) ? Number(value_cents) : null,
        lat ?? null, lng ?? null, tags || "", job_type || "",
        u1 || "", u2 || "", u3 || "", u4 || "", u5 || ""
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
    u1, u2, u3, u4, u5
  } = req.body || {};
  try {
    const r = await pool.query(
      `
      UPDATE contacts SET
        name = COALESCE($3,name),
        phone = COALESCE($4,phone),
        email = COALESCE($5,email),
        address = COALESCE($6,address),
        value_cents = COALESCE($7,value_cents),
        lat = COALESCE($8,lat),
        lng = COALESCE($9,lng),
        tags = COALESCE($10,tags),
        job_type = COALESCE($11,job_type),
        u1 = COALESCE($12,u1),
        u2 = COALESCE($13,u2),
        u3 = COALESCE($14,u3),
        u4 = COALESCE($15,u4),
        u5 = COALESCE($16,u5)
      WHERE id = $1 AND user_id = $2
      RETURNING *;
      `,
      [
        req.params.id, req.userId,
        name, phone, email, address,
        Number.isFinite(Number(value_cents)) ? Number(value_cents) : null,
        lat ?? null, lng ?? null, tags, job_type, u1, u2, u3, u4, u5
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
    await pool.query(
      `UPDATE schedule_events
       SET contact_id = NULL, updated_at = now()
       WHERE contact_id = $1 AND user_id = $2`,
      [req.params.id, req.userId]
    );
    await pool.query(
      `DELETE FROM opportunities WHERE contact_id = $1 AND user_id = $2`,
      [req.params.id, req.userId]
    );
    const r = await pool.query(
      `DELETE FROM contacts WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.userId]
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

// ---------- STAGES ----------
app.get("/api/stages", authRequired, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, name, order_idx FROM stages WHERE user_id = $1 ORDER BY order_idx ASC`,
      [req.userId]
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_list_stages" }); }
});

app.put("/api/stages/:id", authRequired, async (req, res) => {
  const { name, order_idx } = req.body || {};
  if (!name) return res.status(400).json({ error: "name_required" });
  try {
    const r = await pool.query(
      `INSERT INTO stages (id, user_id, name, order_idx)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (id) DO UPDATE
         SET name = EXCLUDED.name,
             order_idx = EXCLUDED.order_idx,
             updated_at = now()
       WHERE stages.user_id = $2
       RETURNING id, name, order_idx`,
      [req.params.id, req.userId, name, Number(order_idx) || 0]
    );
    res.json(r.rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_upsert_stage" }); }
});

app.delete("/api/stages/:id", authRequired, async (req, res) => {
  try {
    await pool.query(`DELETE FROM stages WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.userId]);
    res.status(204).end();
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_delete_stage" }); }
});

// ---------- OPPORTUNITIES (each contact has at most one) ----------
app.get("/api/opportunities", authRequired, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, contact_id, state, stage_id, created_at
       FROM opportunities WHERE user_id = $1`,
      [req.userId]
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_list_opportunities" }); }
});

app.put("/api/opportunities/:id", authRequired, async (req, res) => {
  const { contact_id, state, stage_id, created_at } = req.body || {};
  if (!contact_id || !state) return res.status(400).json({ error: "missing_params" });
  try {
    const r = await pool.query(
      `INSERT INTO opportunities (id, user_id, contact_id, state, stage_id, created_at)
       VALUES ($1, $2, $3, $4, $5, COALESCE($6, now()))
       ON CONFLICT (user_id, contact_id) DO UPDATE
         SET state = EXCLUDED.state,
             stage_id = EXCLUDED.stage_id,
             updated_at = now()
       RETURNING id, contact_id, state, stage_id, created_at`,
      [req.params.id, req.userId, contact_id, state, stage_id || null, created_at || null]
    );
    res.json(r.rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_upsert_opportunity" }); }
});

app.delete("/api/opportunities/:id", authRequired, async (req, res) => {
  try {
    await pool.query(`DELETE FROM opportunities WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.userId]);
    res.status(204).end();
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_delete_opportunity" }); }
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
      "Assigned to job",
      title,
      { schedule_event_id: req.params.id },
      req.userId
    );
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

app.get("/", (_req, res) => res.send("WolfCRM backend up"));
app.listen(PORT, () => console.log(`API listening on ${PORT}`));
