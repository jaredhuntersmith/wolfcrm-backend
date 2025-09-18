/* WolfCRM backend - 1-hour blitz auth (6-digit codes) + contacts
 * Drop-in replacement for index.js
 * - Creates tables if missing (users, magic_tokens, sessions, contacts)
 * - /auth/request logs code to console (no email setup needed)
 * - /auth/verify returns a bearer session token
 * - Authorization middleware available but not required yet
 */
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

// --- Helpers ---
const nowIso = () => new Date().toISOString();
const toInt = (v, def = 0) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : def;
};
const bearer = (req) => {
  const h = req.header("authorization") || req.header("Authorization") || "";
  const m = h.match(/^Bearer (.+)$/i);
  return m ? m[1] : null;
};

// --- DB Bootstrap (safe to re-run) ---
async function bootstrap() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS magic_tokens (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT NOT NULL,
      code TEXT NOT NULL,              -- plain for blitz; hash later
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

    -- Minimal contacts table for existing app usage
    CREATE TABLE IF NOT EXISTS contacts (
      id UUID PRIMARY KEY,
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
  `);

  // Update trigger for updated_at
  await pool.query(`
    CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS TRIGGER AS $$
    BEGIN
      NEW.updated_at = now();
      RETURN NEW;
    END; $$ LANGUAGE plpgsql;

    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'contacts_touch_updated_at'
      ) THEN
        CREATE TRIGGER contacts_touch_updated_at
        BEFORE UPDATE ON contacts
        FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
      END IF;
    END $$;
  `);

  console.log(`[bootstrap] DB ready @ ${nowIso()}`);
}
bootstrap().catch(err => {
  console.error("DB bootstrap failed:", err);
  process.exit(1);
});

// --- Auth middleware (optional for now) ---
async function authOptional(req, _res, next) {
  const token = bearer(req);
  if (!token) return next();
  const { rows } = await pool.query(
    `UPDATE sessions SET last_used_at = now() WHERE token = $1 RETURNING user_id`,
    [token]
  );
  if (rows.length) req.userId = rows[0].user_id;
  next();
}

async function authRequired(req, res, next) {
  const token = bearer(req);
  if (!token) return res.status(401).json({ error: "unauthorized" });
  const { rows } = await pool.query(
    `UPDATE sessions SET last_used_at = now() WHERE token = $1 RETURNING user_id`,
    [token]
  );
  if (!rows.length) return res.status(401).json({ error: "unauthorized" });
  req.userId = rows[0].user_id;
  next();
}

app.use(authOptional);

// --- Auth routes (blitz) ---
// Request a 6-digit code. For speed, we LOG it instead of emailing.
app.post("/auth/request", async (req, res) => {
  try {
    const emailRaw = (req.body.email || "").toString().trim().toLowerCase();
    if (!emailRaw || !emailRaw.includes("@")) {
      return res.status(400).json({ error: "invalid_email" });
    }

    // Upsert user
    const user = await pool.query(
      `INSERT INTO users(email) VALUES($1)
       ON CONFLICT(email) DO UPDATE SET email = EXCLUDED.email
       RETURNING id, email, created_at`,
      [emailRaw]
    );

    const code = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit
    const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await pool.query(
      `INSERT INTO magic_tokens(email, code, expires_at) VALUES($1,$2,$3)`,
      [emailRaw, code, expires.toISOString()]
    );

    // Blitz: log the code to server console
    console.log(`[DEV MAGIC CODE] ${emailRaw} -> ${code} (expires ${expires.toISOString()})`);

    res.json({ ok: true, delivery: "console", expires_at: expires.toISOString() });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "request_failed" });
  }
});

// Verify the 6-digit code, issue a session token
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

    // Mark used
    await pool.query(`UPDATE magic_tokens SET used_at = now() WHERE id = $1`, [t.id]);

    // Ensure user exists
    const { rows: users } = await pool.query(`SELECT * FROM users WHERE email = $1`, [email]);
    if (!users.length) return res.status(400).json({ error: "user_missing" });
    const user = users[0];

    // Create session
    const token = randomUUID();
    await pool.query(`INSERT INTO sessions(token, user_id) VALUES($1,$2)`, [token, user.id]);

    res.json({
      token,
      user: { id: user.id, email: user.email }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "verify_failed" });
  }
});

app.get("/me", authRequired, async (req, res) => {
  const { rows } = await pool.query(`SELECT id, email, created_at FROM users WHERE id = $1`, [req.userId]);
  res.json({ user: rows[0] });
});

// --- Contacts API (kept public for now; you can add authRequired later) ---
app.get("/api/contacts", async (req, res) => {
  const q = (req.query.q || "").toString().trim();
  try {
    let rows;
    if (q) {
      rows = (
        await pool.query(
          `
          SELECT * FROM contacts
          WHERE (name ILIKE $1 OR COALESCE(phone,'') ILIKE $1 OR COALESCE(email,'') ILIKE $1 OR COALESCE(address,'') ILIKE $1
                 OR COALESCE(job_type,'') ILIKE $1 OR COALESCE(u1,'') ILIKE $1 OR COALESCE(u2,'') ILIKE $1
                 OR COALESCE(u3,'') ILIKE $1 OR COALESCE(u4,'') ILIKE $1 OR COALESCE(u5,'') ILIKE $1)
          ORDER BY updated_at DESC
        `,
          [`%${q}%`]
        )
      ).rows;
    } else {
      rows = (await pool.query(`SELECT * FROM contacts ORDER BY updated_at DESC LIMIT 200`)).rows;
    }
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "failed_list" });
  }
});

app.get("/api/contacts/:id", async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT * FROM contacts WHERE id = $1`, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: "not_found" });
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "failed_get" });
  }
});

app.post("/api/contacts", async (req, res) => {
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
      INSERT INTO contacts (id, name, phone, email, address, value_cents, lat, lng, tags, job_type, u1, u2, u3, u4, u5)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
      RETURNING *;
    `,
      [id, name || "", phone || "", email || "", address || "", toInt(value_cents, null), lat ?? null, lng ?? null, tags || "", job_type || "", u1 || "", u2 || "", u3 || "", u4 || "", u5 || ""]
    );
    res.status(201).json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "failed_create" });
  }
});

app.put("/api/contacts/:id", async (req, res) => {
  const {
    name, phone, email, address,
    value_cents, lat, lng, tags, job_type,
    u1, u2, u3, u4, u5
  } = req.body || {};
  try {
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
        u5 = COALESCE($15,u5)
      WHERE id = $1
      RETURNING *;
      `,
      [req.params.id, name, phone, email, address, toInt(value_cents, null), lat ?? null, lng ?? null, tags, job_type, u1, u2, u3, u4, u5]
    );
    if (!r.rowCount) return res.status(404).json({ error: "not_found" });
    res.json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "failed_update" });
  }
});

app.delete("/api/contacts/:id", async (req, res) => {
  try {
    const r = await pool.query(`DELETE FROM contacts WHERE id = $1`, [req.params.id]);
    if (!r.rowCount) return res.status(404).json({ error: "not_found" });
    res.status(204).end();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "failed_delete" });
  }
});

// Optional: today's todo
app.get("/api/todo/today", async (_req, res) => res.json([]));

app.get("/", (_req, res) => res.send("WolfCRM backend up"));

app.listen(PORT, () => console.log(`API listening on ${PORT}`));
