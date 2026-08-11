import { S3Client, PutObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { randomUUID, createHash } from "node:crypto";
import { chooseReceiptMatch, findReceiptCandidates, normalizeMerchantName } from "./finance-receipt-matching.js";

const VALID_STATUSES = new Set(["processing", "unmatched", "possible_match", "matched", "manually_matched", "cash_purchase", "processing_failed", "archived"]);
const VALID_METHODS = new Set(["auto", "manual", "user_direct", "cash_purchase"]);

function cleanString(value, maxLength = 300) {
  return (value || "").toString().trim().slice(0, maxLength);
}

function parseCents(value, fieldName, { nullable = false } = {}) {
  if ((value === null || value === undefined || value === "") && nullable) return null;
  if (typeof value === "number" && Number.isInteger(value)) return value;
  if (typeof value === "string" && /^-?\d+$/.test(value.trim())) return Number(value.trim());
  const error = new Error(`${fieldName}_invalid`);
  error.statusCode = 400;
  error.code = `${fieldName}_invalid`;
  throw error;
}

function parseDateOnly(value, fieldName = "date", { nullable = false } = {}) {
  if ((value === null || value === undefined || value === "") && nullable) return null;
  const raw = cleanString(value, 20);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    const error = new Error(`${fieldName}_invalid`);
    error.statusCode = 400;
    error.code = `${fieldName}_invalid`;
    throw error;
  }
  return raw;
}

function parseTime(value) {
  const raw = cleanString(value, 10);
  return /^\d{2}:\d{2}(:\d{2})?$/.test(raw) ? raw : null;
}

function requireCompany(req, res) {
  if (!req.companyId) {
    res.status(400).json({ error: "company_required", message: "Finance requires a company workspace." });
    return false;
  }
  return true;
}

function handleReceiptError(res, error, fallback) {
  if (error?.statusCode) return res.status(error.statusCode).json({ error: error.code || fallback, message: error.message || "Receipt request failed." });
  console.error("[finance-receipts]", fallback, { message: error?.message });
  res.status(500).json({ error: fallback, message: "Receipt request failed." });
}

function mediaBucketConfig() {
  const endpoint = process.env.MEDIA_ENDPOINT || process.env.AWS_S3_ENDPOINT;
  const bucket = process.env.MEDIA_BUCKET || process.env.AWS_S3_BUCKET_NAME;
  const region = process.env.MEDIA_REGION || process.env.AWS_REGION || "auto";
  const accessKeyId = process.env.MEDIA_ACCESS_KEY_ID || process.env.AWS_ACCESS_KEY_ID;
  const secretAccessKey = process.env.MEDIA_SECRET_ACCESS_KEY || process.env.AWS_SECRET_ACCESS_KEY;
  if (!endpoint || !bucket || !accessKeyId || !secretAccessKey) return null;
  return { endpoint, bucket, region, accessKeyId, secretAccessKey };
}

let s3Client = null;
function getMediaS3Client() {
  const cfg = mediaBucketConfig();
  if (!cfg) return null;
  if (!s3Client) {
    s3Client = new S3Client({
      region: cfg.region,
      endpoint: cfg.endpoint,
      forcePathStyle: true,
      credentials: { accessKeyId: cfg.accessKeyId, secretAccessKey: cfg.secretAccessKey }
    });
  }
  return s3Client;
}

function receiptObjectPrefix(companyId, receiptId) {
  return `companies/${companyId}/finance-receipts/${receiptId}/`;
}

function receiptPayload(row) {
  return {
    id: row.id,
    company_id: row.company_id,
    transaction_id: row.transaction_id,
    status: row.status,
    source: row.source,
    merchant_name: row.merchant_name,
    normalized_merchant_name: row.normalized_merchant_name,
    purchase_date: row.purchase_date,
    purchase_time: row.purchase_time,
    amount_cents: row.amount_cents === null ? null : Number(row.amount_cents),
    subtotal_cents: row.subtotal_cents === null ? null : Number(row.subtotal_cents),
    tax_cents: row.tax_cents === null ? null : Number(row.tax_cents),
    tip_cents: row.tip_cents === null ? null : Number(row.tip_cents),
    currency: row.currency || "usd",
    address: row.address,
    city: row.city,
    state: row.state,
    postal_code: row.postal_code,
    country: row.country,
    payment_method_text: row.payment_method_text,
    card_last_four: row.card_last_four,
    finance_category: row.finance_category,
    business_use: row.business_use,
    note: row.note,
    ocr_text: row.ocr_text,
    ocr_confidence: row.ocr_confidence === null ? null : Number(row.ocr_confidence),
    object_key: row.object_key,
    thumbnail_object_key: row.thumbnail_object_key,
    mime_type: row.mime_type,
    pixel_width: row.pixel_width,
    pixel_height: row.pixel_height,
    file_size_bytes: row.file_size_bytes,
    content_sha256: row.content_sha256,
    match_method: row.match_method,
    match_confidence: row.match_confidence,
    matched_at: row.matched_at,
    archived_at: row.archived_at,
    created_at: row.created_at,
    updated_at: row.updated_at,
    transaction_merchant_name: row.transaction_merchant_name,
    transaction_amount_cents: row.transaction_amount_cents === null || row.transaction_amount_cents === undefined ? null : Number(row.transaction_amount_cents),
    account_name: row.account_name,
    institution_name: row.institution_name
  };
}

function transactionPayload(row) {
  return {
    id: row.id,
    merchant_name: row.merchant_name,
    original_name: row.original_name,
    amount_cents: Number(row.amount_cents || 0),
    direction: row.direction,
    status: row.status,
    pending: Boolean(row.pending),
    transaction_date: row.transaction_date,
    authorized_date: row.authorized_date,
    normalized_category: row.normalized_category,
    account_name: row.account_name,
    institution_name: row.institution_name,
    score: row.score
  };
}

function receiptUpdatePayload(body) {
  const merchant = cleanString(body.merchant_name, 200) || null;
  const cardRaw = cleanString(body.card_last_four, 40);
  const cardLastFour = cardRaw ? (cardRaw.match(/\d{4}(?!\d)/)?.[0] || null) : null;
  return {
    merchant_name: merchant,
    normalized_merchant_name: merchant ? normalizeMerchantName(merchant) : null,
    purchase_date: parseDateOnly(body.purchase_date, "purchase_date", { nullable: true }),
    purchase_time: parseTime(body.purchase_time),
    amount_cents: parseCents(body.amount_cents, "amount_cents", { nullable: true }),
    subtotal_cents: parseCents(body.subtotal_cents, "subtotal_cents", { nullable: true }),
    tax_cents: parseCents(body.tax_cents, "tax_cents", { nullable: true }),
    tip_cents: parseCents(body.tip_cents, "tip_cents", { nullable: true }),
    currency: cleanString(body.currency || "usd", 10).toLowerCase() || "usd",
    address: cleanString(body.address, 300) || null,
    city: cleanString(body.city, 120) || null,
    state: cleanString(body.state, 80) || null,
    postal_code: cleanString(body.postal_code, 20) || null,
    country: cleanString(body.country || "US", 80) || "US",
    payment_method_text: cleanString(body.payment_method_text, 160) || null,
    card_last_four: cardLastFour,
    finance_category: cleanString(body.finance_category || "Other", 80) || "Other",
    business_use: ["unknown", "business", "personal"].includes(body.business_use) ? body.business_use : "unknown",
    note: cleanString(body.note, 1000) || null,
    ocr_text: cleanString(body.ocr_text, 20000) || null,
    ocr_confidence: body.ocr_confidence === null || body.ocr_confidence === undefined ? null : Number(body.ocr_confidence),
    mime_type: cleanString(body.mime_type || "image/jpeg", 80) || "image/jpeg",
    pixel_width: Number.isInteger(body.pixel_width) ? body.pixel_width : null,
    pixel_height: Number.isInteger(body.pixel_height) ? body.pixel_height : null,
    file_size_bytes: Number.isInteger(body.file_size_bytes) ? body.file_size_bytes : null,
    content_sha256: cleanString(body.content_sha256, 128) || null
  };
}

export async function installReceiptSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS finance_receipts (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      transaction_id UUID REFERENCES finance_transactions(id) ON DELETE SET NULL,
      status TEXT NOT NULL DEFAULT 'processing' CHECK (status IN ('processing','unmatched','possible_match','matched','manually_matched','cash_purchase','processing_failed','archived')),
      source TEXT NOT NULL DEFAULT 'ios' CHECK (source IN ('ios','upload','manual','import')),
      merchant_name TEXT,
      normalized_merchant_name TEXT,
      purchase_date DATE,
      purchase_time TIME,
      amount_cents BIGINT CHECK (amount_cents IS NULL OR amount_cents >= 0),
      subtotal_cents BIGINT CHECK (subtotal_cents IS NULL OR subtotal_cents >= 0),
      tax_cents BIGINT CHECK (tax_cents IS NULL OR tax_cents >= 0),
      tip_cents BIGINT CHECK (tip_cents IS NULL OR tip_cents >= 0),
      currency TEXT NOT NULL DEFAULT 'usd',
      address TEXT,
      city TEXT,
      state TEXT,
      postal_code TEXT,
      country TEXT,
      payment_method_text TEXT,
      card_last_four TEXT CHECK (card_last_four IS NULL OR card_last_four ~ '^[0-9]{4}$'),
      finance_category TEXT,
      business_use TEXT NOT NULL DEFAULT 'unknown' CHECK (business_use IN ('unknown','business','personal')),
      note TEXT,
      ocr_text TEXT,
      ocr_confidence DOUBLE PRECISION,
      object_key TEXT,
      thumbnail_object_key TEXT,
      mime_type TEXT,
      pixel_width INTEGER,
      pixel_height INTEGER,
      file_size_bytes BIGINT,
      content_sha256 TEXT,
      match_method TEXT,
      match_confidence INTEGER CHECK (match_confidence IS NULL OR (match_confidence >= 0 AND match_confidence <= 100)),
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      matched_at TIMESTAMPTZ,
      archived_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS finance_receipts_company_status_idx ON finance_receipts(company_id, status, archived_at);
    CREATE INDEX IF NOT EXISTS finance_receipts_company_date_idx ON finance_receipts(company_id, purchase_date DESC);
    CREATE INDEX IF NOT EXISTS finance_receipts_transaction_idx ON finance_receipts(company_id, transaction_id);
    CREATE INDEX IF NOT EXISTS finance_receipts_hash_idx ON finance_receipts(company_id, content_sha256) WHERE content_sha256 IS NOT NULL;

    CREATE TABLE IF NOT EXISTS finance_receipt_matches (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      receipt_id UUID NOT NULL REFERENCES finance_receipts(id) ON DELETE RESTRICT,
      transaction_id UUID NOT NULL REFERENCES finance_transactions(id) ON DELETE RESTRICT,
      method TEXT NOT NULL CHECK (method IN ('auto','manual','user_direct','cash_purchase')),
      confidence_score INTEGER CHECK (confidence_score IS NULL OR (confidence_score >= 0 AND confidence_score <= 100)),
      was_selected BOOLEAN NOT NULL DEFAULT false,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS finance_receipt_matches_receipt_idx ON finance_receipt_matches(company_id, receipt_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS finance_receipt_matches_transaction_idx ON finance_receipt_matches(company_id, transaction_id, created_at DESC);
  `);
}

export async function installReceiptRoutes({ app, pool, authRequired, requireEmployer }) {
  app.get("/api/finance/receipts", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const filter = cleanString(req.query.filter, 40);
      const search = cleanString(req.query.search, 120);
      const conditions = ["r.company_id = $1"];
      const values = [req.companyId];
      if (filter === "unmatched") conditions.push("r.transaction_id IS NULL AND r.status IN ('unmatched','possible_match','processing_failed')");
      else if (filter === "matched") conditions.push("r.transaction_id IS NOT NULL");
      else if (filter === "cash") conditions.push("r.status = 'cash_purchase'");
      else if (filter === "processing") conditions.push("r.status IN ('processing','processing_failed')");
      else conditions.push("r.archived_at IS NULL");
      if (search) {
        values.push(`%${search.toLowerCase()}%`);
        conditions.push(`(lower(r.merchant_name) LIKE $${values.length} OR lower(COALESCE(r.ocr_text,'')) LIKE $${values.length} OR CAST(r.amount_cents AS TEXT) LIKE $${values.length})`);
      }
      const { rows } = await pool.query(
        `SELECT r.*, t.merchant_name AS transaction_merchant_name, t.amount_cents AS transaction_amount_cents,
                a.name AS account_name, a.institution_name
           FROM finance_receipts r
           LEFT JOIN finance_transactions t ON t.id = r.transaction_id AND t.company_id = r.company_id
           LEFT JOIN finance_accounts a ON a.id = t.account_id AND a.company_id = r.company_id
          WHERE ${conditions.join(" AND ")}
          ORDER BY r.created_at DESC
          LIMIT 100`,
        values
      );
      res.json(rows.map(receiptPayload));
    } catch (error) {
      handleReceiptError(res, error, "finance_receipts_failed");
    }
  });

  app.get("/api/finance/transactions/:id/receipts", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const tx = await pool.query(`SELECT id FROM finance_transactions WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId]);
      if (!tx.rows.length) return res.status(404).json({ error: "finance_transaction_not_found", message: "Transaction was not found." });
      const { rows } = await pool.query(
        `SELECT r.*, t.merchant_name AS transaction_merchant_name, t.amount_cents AS transaction_amount_cents,
                a.name AS account_name, a.institution_name
           FROM finance_receipts r
           JOIN finance_transactions t ON t.id = r.transaction_id AND t.company_id = r.company_id
           JOIN finance_accounts a ON a.id = t.account_id AND a.company_id = r.company_id
          WHERE r.company_id = $1
            AND r.transaction_id = $2
            AND r.archived_at IS NULL
          ORDER BY r.created_at DESC`,
        [req.companyId, req.params.id]
      );
      res.json(rows.map(receiptPayload));
    } catch (error) {
      handleReceiptError(res, error, "finance_transaction_receipts_failed");
    }
  });

  app.post("/api/finance/receipts", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const payload = receiptUpdatePayload(req.body || {});
      const transactionId = cleanString(req.body?.transaction_id, 80) || null;
      if (transactionId) {
        const tx = await pool.query(`SELECT id FROM finance_transactions WHERE id = $1 AND company_id = $2`, [transactionId, req.companyId]);
        if (!tx.rows.length) return res.status(404).json({ error: "finance_transaction_not_found", message: "Transaction was not found." });
      }
      if (payload.content_sha256) {
        const dup = await pool.query(`SELECT id FROM finance_receipts WHERE company_id = $1 AND content_sha256 = $2 AND archived_at IS NULL LIMIT 1`, [req.companyId, payload.content_sha256]);
        if (dup.rows.length) return res.status(409).json({ error: "duplicate_receipt", message: "This receipt image already exists.", existing_receipt_id: dup.rows[0].id });
      }
      const status = transactionId ? "matched" : "processing";
      const method = transactionId ? "user_direct" : null;
      const { rows } = await pool.query(
        `INSERT INTO finance_receipts (
           company_id, transaction_id, status, source, merchant_name, normalized_merchant_name,
           purchase_date, purchase_time, amount_cents, subtotal_cents, tax_cents, tip_cents,
           currency, address, city, state, postal_code, country, payment_method_text,
           card_last_four, finance_category, business_use, note, ocr_text, ocr_confidence,
           object_key, thumbnail_object_key, mime_type, pixel_width, pixel_height, file_size_bytes,
           content_sha256, match_method, match_confidence, matched_at, created_by
         ) VALUES ($1,$2,$3,'ios',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35)
         RETURNING *`,
        [
          req.companyId, transactionId, status, payload.merchant_name, payload.normalized_merchant_name,
          payload.purchase_date, payload.purchase_time, payload.amount_cents, payload.subtotal_cents,
          payload.tax_cents, payload.tip_cents, payload.currency, payload.address, payload.city,
          payload.state, payload.postal_code, payload.country, payload.payment_method_text,
          payload.card_last_four, payload.finance_category, payload.business_use, payload.note,
          payload.ocr_text, payload.ocr_confidence, req.body?.object_key || null,
          req.body?.thumbnail_object_key || null, payload.mime_type, payload.pixel_width,
          payload.pixel_height, payload.file_size_bytes, payload.content_sha256, method,
          transactionId ? 100 : null, transactionId ? new Date() : null, req.userId
        ]
      );
      if (transactionId) {
        await pool.query(
          `INSERT INTO finance_receipt_matches(company_id, receipt_id, transaction_id, method, confidence_score, was_selected, created_by)
           VALUES($1,$2,$3,'user_direct',100,true,$4)`,
          [req.companyId, rows[0].id, transactionId, req.userId]
        );
      }
      res.status(201).json(receiptPayload(rows[0]));
    } catch (error) {
      handleReceiptError(res, error, "finance_receipt_create_failed");
    }
  });

  app.post("/api/finance/receipts/:id/upload-url", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const cfg = mediaBucketConfig();
      const s3 = getMediaS3Client();
      if (!cfg || !s3) return res.status(503).json({ error: "media_bucket_not_configured", message: "Receipt storage is not configured." });
      const { rows } = await pool.query(`SELECT id FROM finance_receipts WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId]);
      if (!rows.length) return res.status(404).json({ error: "finance_receipt_not_found", message: "Receipt was not found." });
      const kind = req.body?.kind === "thumbnail" ? "thumbnail" : "image";
      const mimeType = cleanString(req.body?.mime_type || "image/jpeg", 80);
      const byteSize = Number(req.body?.byte_size || 0);
      if (!Number.isFinite(byteSize) || byteSize <= 0 || byteSize > 25 * 1024 * 1024) return res.status(400).json({ error: "invalid_receipt_file_size", message: "Receipt image size is invalid." });
      const objectKey = `${receiptObjectPrefix(req.companyId, req.params.id)}${kind}-${randomUUID()}.jpg`;
      const uploadUrl = await getSignedUrl(s3, new PutObjectCommand({ Bucket: cfg.bucket, Key: objectKey, ContentType: mimeType }), { expiresIn: 900 });
      res.json({ object_key: objectKey, upload_url: uploadUrl, mime_type: mimeType, byte_size: byteSize, kind });
    } catch (error) {
      handleReceiptError(res, error, "finance_receipt_upload_url_failed");
    }
  });

  app.get("/api/finance/receipts/:id/download-url", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const cfg = mediaBucketConfig();
      const s3 = getMediaS3Client();
      if (!cfg || !s3) return res.status(503).json({ error: "media_bucket_not_configured", message: "Receipt storage is not configured." });
      const field = req.query.thumbnail === "true" ? "thumbnail_object_key" : "object_key";
      const { rows } = await pool.query(`SELECT ${field} AS object_key FROM finance_receipts WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId]);
      if (!rows.length || !rows[0].object_key) return res.status(404).json({ error: "finance_receipt_image_not_found", message: "Receipt image was not found." });
      const objectKey = rows[0].object_key;
      if (!objectKey.startsWith(receiptObjectPrefix(req.companyId, req.params.id))) return res.status(403).json({ error: "media_forbidden", message: "Receipt image is not available." });
      const downloadUrl = await getSignedUrl(s3, new GetObjectCommand({ Bucket: cfg.bucket, Key: objectKey }), { expiresIn: 900 });
      res.json({ download_url: downloadUrl });
    } catch (error) {
      handleReceiptError(res, error, "finance_receipt_download_url_failed");
    }
  });

  app.get("/api/finance/receipts/:id", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const { rows } = await pool.query(
        `SELECT r.*, t.merchant_name AS transaction_merchant_name, t.amount_cents AS transaction_amount_cents,
                a.name AS account_name, a.institution_name
           FROM finance_receipts r
           LEFT JOIN finance_transactions t ON t.id = r.transaction_id AND t.company_id = r.company_id
           LEFT JOIN finance_accounts a ON a.id = t.account_id AND a.company_id = r.company_id
          WHERE r.id = $1 AND r.company_id = $2`,
        [req.params.id, req.companyId]
      );
      if (!rows.length) return res.status(404).json({ error: "finance_receipt_not_found", message: "Receipt was not found." });
      res.json(receiptPayload(rows[0]));
    } catch (error) {
      handleReceiptError(res, error, "finance_receipt_failed");
    }
  });

  app.patch("/api/finance/receipts/:id", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const payload = receiptUpdatePayload(req.body || {});
      const status = VALID_STATUSES.has(req.body?.status) ? req.body.status : (payload.object_key ? "unmatched" : undefined);
      const { rows } = await pool.query(
        `UPDATE finance_receipts
            SET merchant_name = COALESCE($3, merchant_name),
                normalized_merchant_name = COALESCE($4, normalized_merchant_name),
                purchase_date = COALESCE($5, purchase_date),
                purchase_time = COALESCE($6, purchase_time),
                amount_cents = COALESCE($7, amount_cents),
                subtotal_cents = COALESCE($8, subtotal_cents),
                tax_cents = COALESCE($9, tax_cents),
                tip_cents = COALESCE($10, tip_cents),
                currency = COALESCE($11, currency),
                address = COALESCE($12, address),
                city = COALESCE($13, city),
                state = COALESCE($14, state),
                postal_code = COALESCE($15, postal_code),
                country = COALESCE($16, country),
                payment_method_text = COALESCE($17, payment_method_text),
                card_last_four = COALESCE($18, card_last_four),
                finance_category = COALESCE($19, finance_category),
                business_use = COALESCE($20, business_use),
                note = COALESCE($21, note),
                ocr_text = COALESCE($22, ocr_text),
                ocr_confidence = COALESCE($23, ocr_confidence),
                object_key = COALESCE($24, object_key),
                thumbnail_object_key = COALESCE($25, thumbnail_object_key),
                mime_type = COALESCE($26, mime_type),
                pixel_width = COALESCE($27, pixel_width),
                pixel_height = COALESCE($28, pixel_height),
                file_size_bytes = COALESCE($29, file_size_bytes),
                content_sha256 = COALESCE($30, content_sha256),
                status = COALESCE($31, CASE WHEN transaction_id IS NULL THEN 'unmatched' ELSE status END),
                updated_at = now()
          WHERE id = $1 AND company_id = $2
          RETURNING *`,
        [
          req.params.id, req.companyId, payload.merchant_name, payload.normalized_merchant_name,
          payload.purchase_date, payload.purchase_time, payload.amount_cents, payload.subtotal_cents,
          payload.tax_cents, payload.tip_cents, payload.currency, payload.address, payload.city,
          payload.state, payload.postal_code, payload.country, payload.payment_method_text,
          payload.card_last_four, payload.finance_category, payload.business_use, payload.note,
          payload.ocr_text, payload.ocr_confidence, req.body?.object_key || null,
          req.body?.thumbnail_object_key || null, payload.mime_type, payload.pixel_width,
          payload.pixel_height, payload.file_size_bytes, payload.content_sha256, status
        ]
      );
      if (!rows.length) return res.status(404).json({ error: "finance_receipt_not_found", message: "Receipt was not found." });
      if (!rows[0].transaction_id) {
        const candidates = await findReceiptCandidates(pool, req.companyId, rows[0]);
        const decision = chooseReceiptMatch(rows[0], candidates.map((candidate) => candidate.transaction));
        if (decision.autoMatch) {
          const matched = await pool.query(
            `UPDATE finance_receipts
                SET transaction_id = $3, status = 'matched', match_method = 'auto',
                    match_confidence = $4, matched_at = now(), updated_at = now()
              WHERE id = $1 AND company_id = $2
              RETURNING *`,
            [req.params.id, req.companyId, decision.best.transaction.id, decision.best.score]
          );
          await pool.query(
            `INSERT INTO finance_receipt_matches(company_id, receipt_id, transaction_id, method, confidence_score, was_selected, created_by)
             VALUES($1,$2,$3,'auto',$4,true,$5)`,
            [req.companyId, req.params.id, decision.best.transaction.id, decision.best.score, req.userId]
          );
          return res.json(receiptPayload(matched.rows[0]));
        }
        if (candidates.length) {
          const possible = await pool.query(`UPDATE finance_receipts SET status = 'possible_match', match_confidence = $3, updated_at = now() WHERE id = $1 AND company_id = $2 RETURNING *`, [req.params.id, req.companyId, candidates[0].score]);
          return res.json(receiptPayload(possible.rows[0]));
        }
      }
      res.json(receiptPayload(rows[0]));
    } catch (error) {
      handleReceiptError(res, error, "finance_receipt_update_failed");
    }
  });

  app.get("/api/finance/receipts/:id/candidates", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const receipt = await pool.query(`SELECT * FROM finance_receipts WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId]);
      if (!receipt.rows.length) return res.status(404).json({ error: "finance_receipt_not_found", message: "Receipt was not found." });
      const candidates = await findReceiptCandidates(pool, req.companyId, receipt.rows[0], { limit: 20 });
      res.json(candidates.map((candidate) => ({ ...transactionPayload({ ...candidate.transaction, score: candidate.score }), score: candidate.score })));
    } catch (error) {
      handleReceiptError(res, error, "finance_receipt_candidates_failed");
    }
  });

  app.post("/api/finance/receipts/:id/match", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const transactionId = cleanString(req.body?.transaction_id, 80);
      const confidence = Number.isInteger(req.body?.confidence_score) ? req.body.confidence_score : null;
      const method = VALID_METHODS.has(req.body?.method) ? req.body.method : "manual";
      const tx = await pool.query(`SELECT id FROM finance_transactions WHERE id = $1 AND company_id = $2 AND removed_at IS NULL`, [transactionId, req.companyId]);
      if (!tx.rows.length) return res.status(404).json({ error: "finance_transaction_not_found", message: "Transaction was not found." });
      const { rows } = await pool.query(
        `UPDATE finance_receipts
            SET transaction_id = $3, status = $4, match_method = $5,
                match_confidence = $6, matched_at = now(), updated_at = now()
          WHERE id = $1 AND company_id = $2
          RETURNING *`,
        [req.params.id, req.companyId, transactionId, method === "user_direct" ? "matched" : "manually_matched", method, confidence]
      );
      if (!rows.length) return res.status(404).json({ error: "finance_receipt_not_found", message: "Receipt was not found." });
      await pool.query(
        `INSERT INTO finance_receipt_matches(company_id, receipt_id, transaction_id, method, confidence_score, was_selected, created_by)
         VALUES($1,$2,$3,$4,$5,true,$6)`,
        [req.companyId, req.params.id, transactionId, method, confidence, req.userId]
      );
      res.json(receiptPayload(rows[0]));
    } catch (error) {
      handleReceiptError(res, error, "finance_receipt_match_failed");
    }
  });

  app.post("/api/finance/receipts/:id/unmatch", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const { rows } = await pool.query(
        `UPDATE finance_receipts
            SET transaction_id = NULL, status = 'unmatched', match_method = NULL,
                match_confidence = NULL, matched_at = NULL, updated_at = now()
          WHERE id = $1 AND company_id = $2
          RETURNING *`,
        [req.params.id, req.companyId]
      );
      if (!rows.length) return res.status(404).json({ error: "finance_receipt_not_found", message: "Receipt was not found." });
      res.json(receiptPayload(rows[0]));
    } catch (error) {
      handleReceiptError(res, error, "finance_receipt_unmatch_failed");
    }
  });

  app.post("/api/finance/receipts/:id/archive", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const { rows } = await pool.query(
        `UPDATE finance_receipts
            SET status = 'archived', archived_at = COALESCE(archived_at, now()), updated_at = now()
          WHERE id = $1 AND company_id = $2
          RETURNING *`,
        [req.params.id, req.companyId]
      );
      if (!rows.length) return res.status(404).json({ error: "finance_receipt_not_found", message: "Receipt was not found." });
      res.json(receiptPayload(rows[0]));
    } catch (error) {
      handleReceiptError(res, error, "finance_receipt_archive_failed");
    }
  });

  app.post("/api/finance/receipts/:id/cash-purchase", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    const client = await pool.connect();
    try {
      const accountId = cleanString(req.body?.account_id, 80);
      const category = cleanString(req.body?.finance_category || "Other", 80) || "Other";
      await client.query("BEGIN");
      const receipt = await client.query(`SELECT * FROM finance_receipts WHERE id = $1 AND company_id = $2 FOR UPDATE`, [req.params.id, req.companyId]);
      if (!receipt.rows.length) throw Object.assign(new Error("Receipt was not found."), { statusCode: 404, code: "finance_receipt_not_found" });
      const amount = parseCents(req.body?.amount_cents ?? receipt.rows[0].amount_cents, "amount_cents");
      if (amount <= 0) throw Object.assign(new Error("Receipt amount is required."), { statusCode: 400, code: "receipt_amount_required" });
      const account = await client.query(`SELECT * FROM finance_accounts WHERE id = $1 AND company_id = $2 AND source = 'manual' AND account_type = 'cash' AND archived_at IS NULL FOR UPDATE`, [accountId, req.companyId]);
      if (!account.rows.length) throw Object.assign(new Error("Choose an active cash account."), { statusCode: 400, code: "cash_account_required" });
      const previous = Number(account.rows[0].current_balance_cents || 0);
      const nextBalance = previous - amount;
      const tx = await client.query(
        `INSERT INTO finance_transactions (
           company_id, account_id, source, status, direction, amount_cents, transaction_date,
           merchant_name, original_name, normalized_category, pending, iso_currency_code, provider_metadata
         ) VALUES ($1,$2,'manual','posted','expense',$3,$4,$5,$5,$6,false,'USD',$7)
         RETURNING *`,
        [
          req.companyId,
          accountId,
          amount,
          receipt.rows[0].purchase_date || new Date().toISOString().slice(0, 10),
          receipt.rows[0].merchant_name || "Cash Purchase",
          category,
          JSON.stringify({ receipt_id: req.params.id })
        ]
      );
      await client.query(`UPDATE finance_accounts SET current_balance_cents = $3, updated_at = now() WHERE id = $1 AND company_id = $2`, [accountId, req.companyId, nextBalance]);
      await client.query(
        `INSERT INTO finance_account_entries(company_id, account_id, entry_type, amount_delta_cents, previous_balance_cents, resulting_balance_cents, currency, note, created_by)
         VALUES($1,$2,'receipt_cash_purchase',$3,$4,$5,$6,$7,$8)`,
        [req.companyId, accountId, -amount, previous, nextBalance, account.rows[0].currency || "usd", `Receipt cash purchase: ${receipt.rows[0].merchant_name || "Receipt"}`, req.userId]
      );
      const updated = await client.query(
        `UPDATE finance_receipts
            SET transaction_id = $3, status = 'cash_purchase', match_method = 'cash_purchase',
                match_confidence = 100, finance_category = $4, matched_at = now(), updated_at = now()
          WHERE id = $1 AND company_id = $2
          RETURNING *`,
        [req.params.id, req.companyId, tx.rows[0].id, category]
      );
      await client.query(
        `INSERT INTO finance_receipt_matches(company_id, receipt_id, transaction_id, method, confidence_score, was_selected, created_by)
         VALUES($1,$2,$3,'cash_purchase',100,true,$4)`,
        [req.companyId, req.params.id, tx.rows[0].id, req.userId]
      );
      await client.query("COMMIT");
      res.json({ receipt: receiptPayload(updated.rows[0]), transaction: transactionPayload(tx.rows[0]), account_balance_cents: nextBalance });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      handleReceiptError(res, error, "finance_receipt_cash_purchase_failed");
    } finally {
      client.release();
    }
  });
}
