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

app.get("/", (_req, res) => res.send("WolfCRM backend up"));
app.listen(PORT, () => console.log(`API listening on ${PORT}`));
