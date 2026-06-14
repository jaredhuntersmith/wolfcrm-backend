/* WolfCRM backend — user-scoped contacts + auto-backfill + emailed codes + logout */
import express from "express";
import cors from "cors";
import { randomUUID } from "crypto";
import pkg from "pg";

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

// ---------- helpers ----------
const nowIso = () => new Date().toISOString();
const bearer = (req) => {
  const h = req.header("authorization") || req.header("Authorization") || "";
  const m = h.match(/^Bearer (.+)$/i);
  return m ? m[1] : null;
};

// Email via Resend (fallback to console)
async function sendLoginCode(email, code, expiresIso) {
  const key = process.env.RESEND_API_KEY;
  const from = process.env.RESEND_FROM || "WolfCRM <no-reply@wolfcrm.local>";
  const subject = "Your WolfCRM login code";
  const text =
    `Your login code is ${code}\n\n` +
    `It expires at ${expiresIso}\n\n` +
    `If you didn’t request this, you can ignore this email.`;

  if (!key) {
    console.log(`[DEV MAGIC CODE] ${email} -> ${code} (expires ${expiresIso})`);
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
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

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
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS map_pins_user_idx ON map_pins(user_id);

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
  `);

  // Schedule events extra fields (services + price)
  await pool.query(`
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS services JSONB NOT NULL DEFAULT '[]'::jsonb;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS price_cents INTEGER;
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
    `UPDATE sessions SET last_used_at = now() WHERE token = $1 RETURNING user_id`,
    [token]
  );
  if (!rows.length) return res.status(401).json({ error: "unauthorized" });
  req.userId = rows[0].user_id;
  req.sessionToken = token;
  next();
}

// ---------- auth routes ----------
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

    const delivery = await sendLoginCode(emailRaw, code, expires.toISOString());
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
  const { rows } = await pool.query(`SELECT id, email, created_at FROM users WHERE id = $1`, [req.userId]);
  res.json({ user: rows[0] });
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
    const r = await pool.query(
      `DELETE FROM contacts WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.userId]
    );
    if (!r.rowCount) return res.status(404).json({ error: "not_found" });
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
    const { rows } = await pool.query(
      `SELECT id, title, start_at AS start, end_at AS "end", color, notes,
              contact_id, reminder_minutes, services, price_cents
       FROM schedule_events WHERE user_id = $1 ORDER BY start_at ASC`,
      [req.userId]
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_list_schedule" }); }
});

app.put("/api/schedule/:id", authRequired, async (req, res) => {
  const { title, start, end, color, notes, contact_id, reminder_minutes, services, price_cents } = req.body || {};
  if (!title || !start || !end) return res.status(400).json({ error: "missing_params" });
  try {
    const r = await pool.query(
      `INSERT INTO schedule_events
        (id, user_id, title, start_at, end_at, color, notes, contact_id, reminder_minutes, services, price_cents)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::jsonb, $11)
       ON CONFLICT (id) DO UPDATE
         SET title = EXCLUDED.title,
             start_at = EXCLUDED.start_at,
             end_at = EXCLUDED.end_at,
             color = EXCLUDED.color,
             notes = EXCLUDED.notes,
             contact_id = EXCLUDED.contact_id,
             reminder_minutes = EXCLUDED.reminder_minutes,
             services = EXCLUDED.services,
             price_cents = EXCLUDED.price_cents,
             updated_at = now()
       WHERE schedule_events.user_id = $2
       RETURNING id, title, start_at AS start, end_at AS "end", color, notes,
                 contact_id, reminder_minutes, services, price_cents`,
      [
        req.params.id, req.userId, title, start, end,
        color || '#3478F6', notes || null, contact_id || null,
        JSON.stringify(reminder_minutes || []),
        JSON.stringify(services || []),
        Number.isFinite(Number(price_cents)) ? Number(price_cents) : null
      ]
    );
    res.json(r.rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_upsert_schedule" }); }
});

app.delete("/api/schedule/:id", authRequired, async (req, res) => {
  try {
    await pool.query(`DELETE FROM schedule_events WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.userId]);
    res.status(204).end();
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_delete_schedule" }); }
});

// ---------- MAP PINS ----------
app.get("/api/map-pins", authRequired, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, latitude, longitude, name, address, notes, status, phone, email
       FROM map_pins WHERE user_id = $1`,
      [req.userId]
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_list_pins" }); }
});

app.put("/api/map-pins/:id", authRequired, async (req, res) => {
  const { latitude, longitude, name, address, notes, status, phone, email } = req.body || {};
  if (typeof latitude !== "number" || typeof longitude !== "number") {
    return res.status(400).json({ error: "missing_coords" });
  }
  try {
    const r = await pool.query(
      `INSERT INTO map_pins (id, user_id, latitude, longitude, name, address, notes, status, phone, email)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ON CONFLICT (id) DO UPDATE
         SET latitude = EXCLUDED.latitude,
             longitude = EXCLUDED.longitude,
             name = EXCLUDED.name,
             address = EXCLUDED.address,
             notes = EXCLUDED.notes,
             status = EXCLUDED.status,
             phone = EXCLUDED.phone,
             email = EXCLUDED.email,
             updated_at = now()
       WHERE map_pins.user_id = $2
       RETURNING id, latitude, longitude, name, address, notes, status, phone, email`,
      [
        req.params.id, req.userId, latitude, longitude,
        name || '', address || '', notes || '', status || 'lead',
        phone || null, email || null
      ]
    );
    res.json(r.rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_upsert_pin" }); }
});

app.delete("/api/map-pins/:id", authRequired, async (req, res) => {
  try {
    await pool.query(`DELETE FROM map_pins WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.userId]);
    res.status(204).end();
  } catch (e) { console.error(e); res.status(500).json({ error: "failed_delete_pin" }); }
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
