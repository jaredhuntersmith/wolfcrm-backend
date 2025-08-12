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
app.use(express.json({ limit: "1mb" }));

// Ensure table exists
const ensureTable = async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS contacts (
      id UUID PRIMARY KEY,
      name TEXT NOT NULL,
      phone TEXT,
      email TEXT,
      address TEXT,
      value_cents INTEGER,
      lat DOUBLE PRECISION,
      lng DOUBLE PRECISION,
      tags TEXT[] DEFAULT '{}',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
};
await ensureTable();

// Health
app.get("/healthz", (_, res) => res.json({ ok: true }));

// GET /api/contacts?q=...
app.get("/api/contacts", async (req, res) => {
  const q = (req.query.q || "").toString().trim();
  try {
    let rows;
    if (q) {
      rows = (await pool.query(
        `SELECT * FROM contacts
         WHERE (name ILIKE $1 OR COALESCE(phone,'') ILIKE $1 OR COALESCE(email,'') ILIKE $1 OR COALESCE(address,'') ILIKE $1)
         ORDER BY updated_at DESC`,
        [`%${q}%`]
      )).rows;
    } else {
      rows = (await pool.query(`SELECT * FROM contacts ORDER BY updated_at DESC`)).rows;
    }
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "failed_list" });
  }
});

// GET /api/contacts/:id
app.get("/api/contacts/:id", async (req, res) => {
  try {
    const r = await pool.query(`SELECT * FROM contacts WHERE id = $1`, [req.params.id]);
    if (!r.rowCount) return res.status(404).json({ error: "not_found" });
    res.json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "failed_get" });
  }
});

// POST /api/contacts
app.post("/api/contacts", async (req, res) => {
  const {
    name, phone = null, email = null, address = null,
    value_cents = null, lat = null, lng = null, tags = []
  } = req.body || {};

  if (!name || typeof name !== "string") {
    return res.status(400).json({ error: "name_required" });
  }

  const id = randomUUID();

  try {
    const r = await pool.query(
      `INSERT INTO contacts (id, name, phone, email, address, value_cents, lat, lng, tags)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *;`,
      [id, name, phone, email, address, value_cents, lat, lng, tags]
    );
    res.status(201).json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "failed_create" });
  }
});

// PATCH /api/contacts/:id
app.patch("/api/contacts/:id", async (req, res) => {
  const fields = ["name","phone","email","address","value_cents","lat","lng","tags"];
  const sets = [];
  const vals = [];
  let idx = 1;

  for (const f of fields) {
    if (f in req.body) {
      sets.push(`${f} = $${idx++}`);
      vals.push(req.body[f]);
    }
  }

  if (sets.length === 0) {
    return res.status(400).json({ error: "no_fields" });
  }

  vals.push(req.params.id);

  try {
    const r = await pool.query(
      `UPDATE contacts SET ${sets.join(", ")}, updated_at = NOW()
       WHERE id = $${idx} RETURNING *;`,
      vals
    );
    if (!r.rowCount) return res.status(404).json({ error: "not_found" });
    res.json(r.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "failed_update" });
  }
});

// DELETE /api/contacts/:id
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

// Optional stub for your app
app.get("/api/todo/today", async (_req, res) => res.json([]));

app.listen(PORT, () => console.log(`API listening on ${PORT}`));
