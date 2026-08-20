import { S3Client, PutObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { createHash } from "node:crypto";
import { chooseReceiptMatch, findReceiptCandidates, normalizeMerchantName } from "./finance-receipt-matching.js";
import {
  appendReceiptLifecycleAudit,
  executeReceiptLifecycleTransition,
  findReceiptLifecycleReplay,
  legacyReceiptLifecycleRequest,
  normalizeReceiptLifecycleRequest,
  receiptLifecycleAuditPayload,
  receiptLifecycleError,
  receiptLifecycleFingerprint,
  receiptLifecycleState
} from "./finance-receipt-lifecycle.js";

const VALID_STATUSES = new Set(["processing", "unmatched", "possible_match", "matched", "manually_matched", "cash_purchase", "processing_failed", "archived"]);
const RECEIPT_BUSINESS_USES = new Set(["unknown", "business", "personal"]);
const RECEIPT_DETAIL_FIELDS = [
  "merchant_name", "purchase_date", "purchase_time", "amount_cents", "subtotal_cents",
  "tax_cents", "tip_cents", "currency", "address", "city", "state", "postal_code",
  "country", "payment_method_text", "card_last_four", "finance_category", "business_use", "note"
];
const RECEIPT_UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

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

function parseContentSHA256(value) {
  const raw = cleanString(value, 128);
  if (!raw) return null;
  if (!/^[0-9a-f]{64}$/i.test(raw)) {
    throw receiptRequestError("content_sha256_invalid", "Receipt content hash is invalid.");
  }
  return raw.toLowerCase();
}

function receiptRequestError(code, message, statusCode = 400, details = {}) {
  return Object.assign(new Error(message), { code, statusCode, ...details });
}

function receiptUUID(value, field) {
  const raw = (value ?? "").toString().trim().toLowerCase();
  if (!RECEIPT_UUID_PATTERN.test(raw)) {
    throw receiptRequestError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return raw;
}

function exactReceiptInteger(value, field, minimum = 0) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value.trim()) ? Number(value.trim()) : value;
  if (!Number.isSafeInteger(parsed) || parsed < minimum) {
    throw receiptRequestError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return parsed;
}

function optionalReceiptText(value, field, maxLength) {
  if (value === null || value === undefined) return null;
  const text = value.toString().trim();
  if (!text) return null;
  if (text.length > maxLength) {
    throw receiptRequestError(`${field}_too_long`, `${field.replaceAll("_", " ")} must be ${maxLength} characters or fewer.`);
  }
  return text;
}

function optionalReceiptCents(value, field) {
  if (value === null || value === undefined || value === "") return null;
  return exactReceiptInteger(value, field);
}

function optionalReceiptDate(value, field = "purchase_date") {
  if (value === null || value === undefined || value === "") return null;
  const raw = value instanceof Date ? value.toISOString().slice(0, 10) : value.toString().trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    throw receiptRequestError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  const [year, month, day] = raw.split("-").map(Number);
  const parsed = new Date(Date.UTC(year, month - 1, day));
  if (parsed.getUTCFullYear() !== year || parsed.getUTCMonth() !== month - 1 || parsed.getUTCDate() !== day) {
    throw receiptRequestError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return raw;
}

function optionalReceiptTime(value) {
  if (value === null || value === undefined || value === "") return null;
  const raw = value.toString().trim();
  const match = raw.match(/^(\d{2}):(\d{2})(?::(\d{2}))?$/);
  if (!match || Number(match[1]) > 23 || Number(match[2]) > 59 || Number(match[3] || 0) > 59) {
    throw receiptRequestError("purchase_time_invalid", "Purchase time is invalid.");
  }
  return match[3] === undefined ? `${match[1]}:${match[2]}` : raw;
}

function stableReceiptValue(value) {
  if (Array.isArray(value)) return value.map(stableReceiptValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableReceiptValue(value[key])]));
  }
  return value;
}

export function receiptDetailFingerprint(value) {
  return createHash("sha256").update(JSON.stringify(stableReceiptValue(value))).digest("hex");
}

function normalizedReceiptDetailDocument(source = {}) {
  const currency = optionalReceiptText(source.currency ?? "usd", "currency", 3)?.toLowerCase();
  if (!currency || !/^[a-z]{3}$/.test(currency)) {
    throw receiptRequestError("currency_invalid", "Currency must be a three-letter code.");
  }
  const businessUse = optionalReceiptText(source.business_use ?? "unknown", "business_use", 20)?.toLowerCase();
  if (!businessUse || !RECEIPT_BUSINESS_USES.has(businessUse)) {
    throw receiptRequestError("business_use_invalid", "Business use is invalid.");
  }
  const cardLastFour = optionalReceiptText(source.card_last_four, "card_last_four", 4);
  if (cardLastFour && !/^\d{4}$/.test(cardLastFour)) {
    throw receiptRequestError("card_last_four_invalid", "Card last four must contain exactly four digits.");
  }
  return {
    merchant_name: optionalReceiptText(source.merchant_name, "merchant_name", 200),
    purchase_date: optionalReceiptDate(source.purchase_date),
    purchase_time: optionalReceiptTime(source.purchase_time),
    amount_cents: optionalReceiptCents(source.amount_cents, "amount_cents"),
    subtotal_cents: optionalReceiptCents(source.subtotal_cents, "subtotal_cents"),
    tax_cents: optionalReceiptCents(source.tax_cents, "tax_cents"),
    tip_cents: optionalReceiptCents(source.tip_cents, "tip_cents"),
    currency,
    address: optionalReceiptText(source.address, "address", 300),
    city: optionalReceiptText(source.city, "city", 120),
    state: optionalReceiptText(source.state, "state", 80),
    postal_code: optionalReceiptText(source.postal_code, "postal_code", 20),
    country: optionalReceiptText(source.country, "country", 80),
    payment_method_text: optionalReceiptText(source.payment_method_text, "payment_method_text", 160),
    card_last_four: cardLastFour,
    finance_category: optionalReceiptText(source.finance_category ?? "Other", "finance_category", 80) || "Other",
    business_use: businessUse,
    note: optionalReceiptText(source.note, "note", 1000)
  };
}

export function normalizeReceiptDetailEditRequest({ body = {}, receiptID }) {
  const reason = (body.reason ?? "").toString().trim();
  if (!reason) throw receiptRequestError("receipt_detail_reason_required", "An audit reason is required.");
  if (reason.length > 500) throw receiptRequestError("receipt_detail_reason_too_long", "Audit reason must be 500 characters or fewer.");
  const input = {
    receipt_id: receiptUUID(receiptID, "receipt_id"),
    client_request_id: receiptUUID(body.client_request_id, "client_request_id"),
    expected_details_version: exactReceiptInteger(body.expected_details_version, "expected_details_version", 1),
    details: normalizedReceiptDetailDocument(body),
    reason
  };
  return { ...input, request_fingerprint: receiptDetailFingerprint(input) };
}

export function receiptDetailDocument(row = {}) {
  return normalizedReceiptDetailDocument(row);
}

export function receiptDetailChangedFields(before = {}, after = {}) {
  return RECEIPT_DETAIL_FIELDS.filter((field) => before[field] !== after[field]);
}

export function receiptDetailAuditSnapshot(document = {}) {
  return {
    merchant_name: document.merchant_name || null,
    purchase_date: document.purchase_date || null,
    purchase_time: document.purchase_time || null,
    amount_cents: document.amount_cents ?? null,
    subtotal_cents: document.subtotal_cents ?? null,
    tax_cents: document.tax_cents ?? null,
    tip_cents: document.tip_cents ?? null,
    currency: document.currency,
    finance_category: document.finance_category,
    business_use: document.business_use,
    country: document.country,
    address_present: Boolean(document.address || document.city || document.state || document.postal_code),
    payment_method_present: Boolean(document.payment_method_text),
    card_last_four_present: Boolean(document.card_last_four),
    note_present: Boolean(document.note)
  };
}

function requireCompany(req, res) {
  if (!req.companyId) {
    res.status(400).json({ error: "company_required", message: "Finance requires a company workspace." });
    return false;
  }
  return true;
}

function handleReceiptError(res, error, fallback) {
  if (error?.statusCode) {
    const payload = { error: error.code || fallback, message: error.message || "Receipt request failed." };
    for (const key of ["current_version", "current_balance_cents", "existing_receipt_id"]) {
      if (error[key] !== undefined) payload[key] = error[key];
    }
    return res.status(error.statusCode).json(payload);
  }
  console.error("[finance-receipts]", fallback, { message: error?.message });
  res.status(500).json({ error: fallback, message: "Receipt request failed." });
}

function mediaBucketConfig() {
  const endpoint = process.env.MEDIA_ENDPOINT || process.env.AWS_ENDPOINT_URL || process.env.AWS_S3_ENDPOINT;
  const bucket = process.env.MEDIA_BUCKET || process.env.AWS_S3_BUCKET_NAME;
  const region = process.env.MEDIA_REGION || process.env.AWS_DEFAULT_REGION || process.env.AWS_REGION || "auto";
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

function cleanReceiptObjectKey(value, companyId, receiptId, fieldName) {
  const objectKey = cleanString(value, 500);
  if (!objectKey) return null;
  const prefix = receiptObjectPrefix(companyId, receiptId);
  if (!objectKey.startsWith(prefix) || objectKey.includes("..") || objectKey.includes("\\")) {
    const error = new Error(`${fieldName}_forbidden`);
    error.statusCode = 403;
    error.code = "media_forbidden";
    throw error;
  }
  return objectKey;
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
    institution_name: row.institution_name,
    details_version: Number(row.details_version || 1),
    lifecycle_version: Number(row.lifecycle_version || 1),
    archived_from_status: row.archived_from_status || null
  };
}

function receiptDetailAuditPayload(row) {
  return {
    id: String(row.id),
    receipt_id: String(row.receipt_id),
    version: Number(row.version),
    action: row.action,
    reason: row.reason,
    changed_fields: Array.isArray(row.changed_fields) ? row.changed_fields : [],
    actor_user_id: row.actor_user_id || null,
    actor_email: row.actor_email || null,
    created_at: row.created_at || null
  };
}

async function loadReceiptWithContext(poolOrClient, companyID, receiptID, { lock = false } = {}) {
  const { rows } = await poolOrClient.query(
    `SELECT r.*, t.merchant_name AS transaction_merchant_name, t.amount_cents AS transaction_amount_cents,
            a.name AS account_name, a.institution_name
       FROM finance_receipts r
       LEFT JOIN finance_transactions t ON t.id=r.transaction_id AND t.company_id=r.company_id
       LEFT JOIN finance_accounts a ON a.id=t.account_id AND a.company_id=r.company_id
      WHERE r.id=$1 AND r.company_id=$2${lock ? " FOR UPDATE OF r" : ""}`,
    [receiptID, companyID]
  );
  return rows[0] || null;
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

function isRecoverableReceiptCapture(row, transactionID) {
  if (!row || row.source !== "ios" || row.object_key || Number(row.details_version || 1) !== 1) return false;
  if (String(row.transaction_id || "") !== String(transactionID || "")) return false;
  if (["processing", "processing_failed"].includes(row.status)) return true;
  return row.status === "matched" && row.match_method === "user_direct" && Boolean(transactionID);
}

export async function createReceiptCapture({ pool, companyID, actorUserID, body = {} }) {
  if (body.object_key || body.thumbnail_object_key) {
    throw receiptRequestError(
      "receipt_object_key_not_allowed",
      "Receipt image keys must be issued by the server after the receipt is created."
    );
  }
  const payload = receiptUpdatePayload(body);
  const transactionID = cleanString(body.transaction_id, 80) || null;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    if (payload.content_sha256) {
      await client.query(
        `SELECT pg_advisory_xact_lock(hashtext($1::text))`,
        [`${companyID}|receipt-content|${payload.content_sha256}`]
      );
    }
    if (transactionID) {
      const transaction = await client.query(
        `SELECT id FROM finance_transactions
          WHERE id=$1 AND company_id=$2 AND removed_at IS NULL
          FOR UPDATE`,
        [transactionID, companyID]
      );
      if (!transaction.rows.length) {
        throw receiptRequestError("finance_transaction_not_found", "Transaction was not found.", 404);
      }
    }
    if (payload.content_sha256) {
      const duplicate = await client.query(
        `SELECT * FROM finance_receipts
          WHERE company_id=$1 AND content_sha256=$2 AND archived_at IS NULL
          ORDER BY created_at, id
          LIMIT 1
          FOR UPDATE`,
        [companyID, payload.content_sha256]
      );
      if (duplicate.rows.length) {
        const existing = duplicate.rows[0];
        if (isRecoverableReceiptCapture(existing, transactionID)) {
          await client.query("COMMIT");
          return { receipt: existing, recovered: true };
        }
        throw receiptRequestError(
          "duplicate_receipt",
          "This receipt image already exists.",
          409,
          { existing_receipt_id: existing.id }
        );
      }
    }
    const status = transactionID ? "matched" : "processing";
    const method = transactionID ? "user_direct" : null;
    const { rows } = await client.query(
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
        companyID, transactionID, status, payload.merchant_name, payload.normalized_merchant_name,
        payload.purchase_date, payload.purchase_time, payload.amount_cents, payload.subtotal_cents,
        payload.tax_cents, payload.tip_cents, payload.currency, payload.address, payload.city,
        payload.state, payload.postal_code, payload.country, payload.payment_method_text,
        payload.card_last_four, payload.finance_category, payload.business_use, payload.note,
        payload.ocr_text, payload.ocr_confidence, null,
        null, payload.mime_type, payload.pixel_width,
        payload.pixel_height, payload.file_size_bytes, payload.content_sha256, method,
        transactionID ? 100 : null, transactionID ? new Date() : null, actorUserID
      ]
    );
    if (transactionID) {
      await client.query(
        `INSERT INTO finance_receipt_matches(
           company_id, receipt_id, transaction_id, method, confidence_score, was_selected, created_by
         ) VALUES($1,$2,$3,'user_direct',100,true,$4)`,
        [companyID, rows[0].id, transactionID, actorUserID]
      );
    }
    await client.query("COMMIT");
    return { receipt: rows[0], recovered: false };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

export async function createReceiptCashPurchase({ pool, companyID, actorUserID, request }) {
  if (request.action !== "cash_purchase") {
    throw receiptLifecycleError("receipt_lifecycle_action_invalid", "Cash purchase action is invalid.");
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(`SELECT pg_advisory_xact_lock(hashtext($1::text))`, [`${companyID}|receipt-lifecycle`]);
    const replay = await findReceiptLifecycleReplay(client, companyID, request);
    if (replay) {
      const receipt = await loadReceiptWithContext(client, companyID, request.receipt_id);
      const transactionID = replay.after_state?.transaction_id;
      const transaction = transactionID
        ? (await client.query(`SELECT * FROM finance_transactions WHERE id=$1 AND company_id=$2`, [transactionID, companyID])).rows[0]
        : null;
      if (!receipt || !transaction) {
        throw receiptLifecycleError("receipt_cash_purchase_replay_invalid", "Cash purchase replay evidence is incomplete.", 409);
      }
      await client.query("COMMIT");
      return {
        replayed: true,
        receipt,
        transaction,
        account_balance_cents: Number(replay.after_state?.account_balance_cents),
        audit: replay
      };
    }

    const receipt = await loadReceiptWithContext(client, companyID, request.receipt_id, { lock: true });
    if (!receipt) throw receiptLifecycleError("finance_receipt_not_found", "Receipt was not found.", 404);
    const currentVersion = Number(receipt.lifecycle_version || 1);
    if (request.expected_lifecycle_version !== null && request.expected_lifecycle_version !== currentVersion) {
      throw receiptLifecycleError(
        "receipt_lifecycle_stale",
        "Receipt lifecycle changed after it was loaded.",
        409,
        { current_version: currentVersion }
      );
    }
    if (receipt.archived_at || receipt.status === "archived") {
      throw receiptLifecycleError("receipt_lifecycle_archived", "Restore the receipt before creating a cash purchase.", 409);
    }
    if (!["unmatched", "possible_match"].includes(receipt.status) || receipt.transaction_id) {
      throw receiptLifecycleError("receipt_cash_purchase_source_invalid", "Only an unmatched completed receipt can create a cash purchase.", 409);
    }
    if (!receipt.object_key) {
      throw receiptLifecycleError("receipt_lifecycle_processing", "Finish or recover receipt capture before creating a cash purchase.", 409);
    }
    const sourceAmount = Number(receipt.amount_cents);
    if (!Number.isSafeInteger(sourceAmount) || sourceAmount <= 0 || request.amount_cents !== sourceAmount) {
      throw receiptLifecycleError("receipt_cash_purchase_amount_mismatch", "Cash purchase amount must equal the current receipt total.", 409);
    }
    const sourceCategory = cleanString(receipt.finance_category || "Other", 80) || "Other";
    if (request.finance_category !== sourceCategory) {
      throw receiptLifecycleError("receipt_cash_purchase_category_mismatch", "Save the receipt category before creating the cash purchase.", 409);
    }
    const account = (await client.query(
      `SELECT * FROM finance_accounts
        WHERE id=$1 AND company_id=$2 AND source='manual' AND account_type='cash' AND archived_at IS NULL
        FOR UPDATE`,
      [request.account_id, companyID]
    )).rows[0];
    if (!account) throw receiptLifecycleError("cash_account_required", "Choose an active cash account.");
    const receiptCurrency = (receipt.currency || "usd").toString().toLowerCase();
    const accountCurrency = (account.currency || "usd").toString().toLowerCase();
    if (receiptCurrency !== accountCurrency) {
      throw receiptLifecycleError("receipt_cash_purchase_currency_mismatch", "Receipt and cash account currencies must match.", 409);
    }
    const previous = Number(account.current_balance_cents || 0);
    if (request.expected_account_balance_cents !== null
      && request.expected_account_balance_cents !== undefined
      && request.expected_account_balance_cents !== previous) {
      throw receiptLifecycleError(
        "receipt_cash_account_stale",
        "Cash account balance changed after it was loaded.",
        409,
        { current_balance_cents: previous }
      );
    }
    const nextBalance = previous - sourceAmount;
    if (!Number.isSafeInteger(previous) || !Number.isSafeInteger(nextBalance)) {
      throw receiptLifecycleError("receipt_cash_purchase_balance_invalid", "Cash account balance is outside the supported range.", 409);
    }
    const beforeState = receiptLifecycleState(receipt);
    const transaction = (await client.query(
      `INSERT INTO finance_transactions (
         company_id, account_id, source, status, direction, amount_cents, transaction_date,
         merchant_name, original_name, normalized_category, pending, iso_currency_code, provider_metadata
       ) VALUES ($1,$2,'manual','posted','expense',$3,$4,$5,$5,$6,false,$7,$8)
       RETURNING *`,
      [companyID, request.account_id, sourceAmount,
        receipt.purchase_date || new Date().toISOString().slice(0, 10),
        receipt.merchant_name || "Cash Purchase", sourceCategory, receiptCurrency.toUpperCase(),
        JSON.stringify({ receipt_id: request.receipt_id })]
    )).rows[0];
    await client.query(
      `UPDATE finance_accounts SET current_balance_cents=$3, updated_at=now()
        WHERE id=$1 AND company_id=$2`,
      [request.account_id, companyID, nextBalance]
    );
    await client.query(
      `INSERT INTO finance_account_entries(
         company_id, account_id, entry_type, amount_delta_cents, previous_balance_cents,
         resulting_balance_cents, currency, note, created_by
       ) VALUES($1,$2,'receipt_cash_purchase',$3,$4,$5,$6,$7,$8)`,
      [companyID, request.account_id, -sourceAmount, previous, nextBalance, accountCurrency,
        `Receipt cash purchase: ${receipt.merchant_name || "Receipt"}`, actorUserID]
    );
    const nextVersion = currentVersion + 1;
    if (!Number.isSafeInteger(nextVersion)) {
      throw receiptLifecycleError("receipt_lifecycle_version_invalid", "Receipt lifecycle version is invalid.", 409);
    }
    const updated = (await client.query(
      `UPDATE finance_receipts
          SET transaction_id=$3, status='cash_purchase', match_method='cash_purchase',
              match_confidence=100, matched_at=now(), lifecycle_version=$4, updated_at=now()
        WHERE id=$1 AND company_id=$2
        RETURNING *`,
      [request.receipt_id, companyID, transaction.id, nextVersion]
    )).rows[0];
    await client.query(
      `INSERT INTO finance_receipt_matches(
         company_id, receipt_id, transaction_id, method, confidence_score, was_selected, created_by
       ) VALUES($1,$2,$3,'cash_purchase',100,true,$4)`,
      [companyID, request.receipt_id, transaction.id, actorUserID]
    );
    const afterState = receiptLifecycleState(updated, {
      account_id: request.account_id,
      account_balance_cents: nextBalance
    });
    const audit = await appendReceiptLifecycleAudit(client, {
      companyID,
      receiptID: request.receipt_id,
      version: nextVersion,
      actorUserID,
      action: "cash_purchase_created",
      reason: request.reason,
      clientRequestID: request.client_request_id,
      requestFingerprint: request.request_fingerprint || receiptLifecycleFingerprint(request),
      beforeState,
      afterState
    });
    await client.query("COMMIT");
    return { replayed: false, receipt: updated, transaction, account_balance_cents: nextBalance, audit };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

export async function replaceReceiptDetails({ pool, companyID, actorUserID, receiptID, body }) {
  const request = normalizeReceiptDetailEditRequest({ body, receiptID });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(`SELECT pg_advisory_xact_lock(hashtext($1::text))`, [`${companyID}|receipt-details`]);
    const replay = await client.query(
      `SELECT * FROM finance_receipt_detail_audit
        WHERE company_id=$1 AND client_request_id=$2::uuid`,
      [companyID, request.client_request_id]
    );
    if (replay.rows.length) {
      const row = replay.rows[0];
      if (String(row.receipt_id) !== request.receipt_id || row.request_fingerprint !== request.request_fingerprint) {
        throw receiptRequestError(
          "receipt_detail_request_conflict",
          "That request ID was already used with different receipt details.",
          409
        );
      }
      const receipt = await loadReceiptWithContext(client, companyID, request.receipt_id);
      await client.query("COMMIT");
      return { replayed: true, receipt, audit: row };
    }
    const current = await loadReceiptWithContext(client, companyID, request.receipt_id, { lock: true });
    if (!current) throw receiptRequestError("finance_receipt_not_found", "Receipt was not found.", 404);
    if (current.archived_at || current.status === "archived") {
      throw receiptRequestError("receipt_details_archived", "Archived receipt details cannot be changed.", 409);
    }
    if (current.status === "processing" || current.status === "processing_failed" || !current.object_key) {
      throw receiptRequestError("receipt_details_processing", "Wait for receipt processing to finish before editing details.", 409);
    }
    if (current.status === "cash_purchase") {
      throw receiptRequestError(
        "receipt_details_cash_purchase_locked",
        "Cash-purchase receipt details require a coordinated transaction correction workflow.",
        409
      );
    }
    const currentVersion = Number(current.details_version || 1);
    if (request.expected_details_version !== currentVersion) {
      throw receiptRequestError(
        "receipt_details_stale",
        "Receipt details changed after they were loaded.",
        409,
        { current_version: currentVersion }
      );
    }
    const before = receiptDetailDocument(current);
    const after = request.details;
    const changedFields = receiptDetailChangedFields(before, after);
    if (!changedFields.length) {
      throw receiptRequestError("receipt_details_unchanged", "Change at least one receipt detail before saving.", 409);
    }
    const nextVersion = currentVersion + 1;
    if (!Number.isSafeInteger(nextVersion)) {
      throw receiptRequestError("receipt_details_version_invalid", "Receipt detail version is invalid.", 409);
    }
    const updated = (await client.query(
      `UPDATE finance_receipts
          SET merchant_name=$3, normalized_merchant_name=$4,
              purchase_date=$5::date, purchase_time=$6::time,
              amount_cents=$7, subtotal_cents=$8, tax_cents=$9, tip_cents=$10,
              currency=$11, address=$12, city=$13, state=$14, postal_code=$15,
              country=$16, payment_method_text=$17, card_last_four=$18,
              finance_category=$19, business_use=$20, note=$21,
              details_version=$22, updated_at=now()
        WHERE id=$1 AND company_id=$2
        RETURNING *`,
      [
        request.receipt_id, companyID, after.merchant_name,
        after.merchant_name ? normalizeMerchantName(after.merchant_name) : null,
        after.purchase_date, after.purchase_time, after.amount_cents, after.subtotal_cents,
        after.tax_cents, after.tip_cents, after.currency, after.address, after.city,
        after.state, after.postal_code, after.country, after.payment_method_text,
        after.card_last_four, after.finance_category, after.business_use, after.note, nextVersion
      ]
    )).rows[0];
    const audit = (await client.query(
      `INSERT INTO finance_receipt_detail_audit (
         company_id, receipt_id, version, actor_user_id, action, reason, changed_fields,
         client_request_id, request_fingerprint, before_state, after_state
       ) VALUES ($1,$2,$3,$4,'details_replaced',$5,$6,$7::uuid,$8,$9,$10)
       RETURNING *`,
      [companyID, request.receipt_id, nextVersion, actorUserID, request.reason, changedFields,
        request.client_request_id, request.request_fingerprint,
        JSON.stringify(receiptDetailAuditSnapshot(before)), JSON.stringify(receiptDetailAuditSnapshot(after))]
    )).rows[0];
    await client.query("COMMIT");
    return { replayed: false, receipt: updated, audit };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
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
    content_sha256: parseContentSHA256(body.content_sha256)
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
    DO $$
    DECLARE
      transaction_table REGCLASS := 'finance_transactions'::REGCLASS;
      transaction_namespace OID;
      index_name TEXT := 'finance_transactions_company_id_idx';
      suffix INTEGER := 0;
    BEGIN
      PERFORM pg_advisory_xact_lock(hashtext('wolfcrm.finance_transactions.company_id_id.unique'));
      SELECT relnamespace INTO transaction_namespace FROM pg_class WHERE oid=transaction_table;

      IF NOT EXISTS (
        SELECT 1
          FROM pg_index candidate
         WHERE candidate.indrelid=transaction_table
           AND candidate.indisunique
           AND candidate.indisvalid
           AND candidate.indisready
           AND candidate.indpred IS NULL
           AND candidate.indexprs IS NULL
           AND candidate.indnkeyatts=2
           AND (
             SELECT array_agg(attribute.attname::TEXT ORDER BY key_column.ordinality)
               FROM unnest(candidate.indkey::SMALLINT[]) WITH ORDINALITY
                    AS key_column(attnum, ordinality)
               JOIN pg_attribute attribute
                 ON attribute.attrelid=candidate.indrelid
                AND attribute.attnum=key_column.attnum
              WHERE key_column.ordinality <= candidate.indnkeyatts
           ) = ARRAY['company_id','id']::TEXT[]
      ) THEN
        WHILE EXISTS (
          SELECT 1 FROM pg_class
           WHERE relnamespace=transaction_namespace AND relname=index_name
        ) LOOP
          suffix := suffix + 1;
          index_name := 'finance_transactions_company_id_key_' || suffix;
        END LOOP;
        EXECUTE format(
          'CREATE UNIQUE INDEX %I ON finance_transactions(company_id, id)',
          index_name
        );
      END IF;
    END $$;

    ALTER TABLE finance_receipts
      ADD COLUMN IF NOT EXISTS details_version INTEGER NOT NULL DEFAULT 1;
    ALTER TABLE finance_receipts
      ADD COLUMN IF NOT EXISTS lifecycle_version INTEGER NOT NULL DEFAULT 1;
    ALTER TABLE finance_receipts
      ADD COLUMN IF NOT EXISTS archived_from_status TEXT;
    DO $$
    BEGIN
      ALTER TABLE finance_receipts
        ADD CONSTRAINT finance_receipts_details_version_positive CHECK(details_version > 0);
    EXCEPTION WHEN duplicate_object THEN NULL;
    END $$;
    DO $$
    BEGIN
      ALTER TABLE finance_receipts
        ADD CONSTRAINT finance_receipts_lifecycle_version_positive CHECK(lifecycle_version > 0);
    EXCEPTION WHEN duplicate_object THEN NULL;
    END $$;
    DO $$
    BEGIN
      ALTER TABLE finance_receipts
        ADD CONSTRAINT finance_receipts_archived_from_status_check
        CHECK(archived_from_status IS NULL OR archived_from_status IN (
          'unmatched','possible_match','matched','manually_matched','cash_purchase','processing_failed'
        ));
    EXCEPTION WHEN duplicate_object THEN NULL;
    END $$;
    DO $$
    DECLARE
      receipt_table REGCLASS := 'finance_receipts'::REGCLASS;
      receipt_namespace OID;
      constraint_name TEXT := 'finance_receipts_company_id_id_unique';
      suffix INTEGER := 0;
    BEGIN
      PERFORM pg_advisory_xact_lock(hashtext('wolfcrm.finance_receipts.company_id_id.unique'));
      SELECT relnamespace INTO receipt_namespace FROM pg_class WHERE oid=receipt_table;

      IF NOT EXISTS (
        SELECT 1
          FROM pg_index candidate
         WHERE candidate.indrelid=receipt_table
           AND candidate.indisunique
           AND candidate.indisvalid
           AND candidate.indisready
           AND candidate.indpred IS NULL
           AND candidate.indexprs IS NULL
           AND candidate.indnkeyatts=2
           AND (
             SELECT array_agg(attribute.attname::TEXT ORDER BY key_column.ordinality)
               FROM unnest(candidate.indkey::SMALLINT[]) WITH ORDINALITY
                    AS key_column(attnum, ordinality)
               JOIN pg_attribute attribute
                 ON attribute.attrelid=candidate.indrelid
                AND attribute.attnum=key_column.attnum
              WHERE key_column.ordinality <= candidate.indnkeyatts
           ) = ARRAY['company_id','id']::TEXT[]
      ) THEN
        WHILE EXISTS (
          SELECT 1 FROM pg_class
           WHERE relnamespace=receipt_namespace AND relname=constraint_name
        ) LOOP
          suffix := suffix + 1;
          constraint_name := 'finance_receipts_company_id_id_key_' || suffix;
        END LOOP;
        EXECUTE format(
          'ALTER TABLE finance_receipts ADD CONSTRAINT %I UNIQUE(company_id, id)',
          constraint_name
        );
      END IF;
    END $$;

    CREATE TABLE IF NOT EXISTS finance_receipt_matches (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      receipt_id UUID NOT NULL,
      transaction_id UUID NOT NULL,
      method TEXT NOT NULL CHECK (method IN ('auto','manual','user_direct','cash_purchase')),
      confidence_score INTEGER CHECK (confidence_score IS NULL OR (confidence_score >= 0 AND confidence_score <= 100)),
      was_selected BOOLEAN NOT NULL DEFAULT false,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      CONSTRAINT finance_receipt_matches_company_receipt_fk
        FOREIGN KEY (company_id, receipt_id) REFERENCES finance_receipts(company_id, id) ON DELETE RESTRICT,
      CONSTRAINT finance_receipt_matches_company_transaction_fk
        FOREIGN KEY (company_id, transaction_id) REFERENCES finance_transactions(company_id, id) ON DELETE RESTRICT
    );
    DO $$
    BEGIN
      ALTER TABLE finance_receipt_matches
        ADD CONSTRAINT finance_receipt_matches_company_receipt_fk
        FOREIGN KEY (company_id, receipt_id)
        REFERENCES finance_receipts(company_id, id) ON DELETE RESTRICT NOT VALID;
    EXCEPTION WHEN duplicate_object THEN NULL;
    END $$;
    DO $$
    BEGIN
      ALTER TABLE finance_receipt_matches
        ADD CONSTRAINT finance_receipt_matches_company_transaction_fk
        FOREIGN KEY (company_id, transaction_id)
        REFERENCES finance_transactions(company_id, id) ON DELETE RESTRICT NOT VALID;
    EXCEPTION WHEN duplicate_object THEN NULL;
    END $$;
    CREATE INDEX IF NOT EXISTS finance_receipt_matches_receipt_idx ON finance_receipt_matches(company_id, receipt_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS finance_receipt_matches_transaction_idx ON finance_receipt_matches(company_id, transaction_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS finance_receipt_detail_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      receipt_id UUID NOT NULL,
      version INTEGER NOT NULL CHECK (version > 1),
      actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL CHECK (action='details_replaced'),
      reason TEXT NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 500),
      changed_fields TEXT[] NOT NULL CHECK (cardinality(changed_fields) BETWEEN 1 AND 18),
      client_request_id UUID NOT NULL,
      request_fingerprint TEXT NOT NULL CHECK (char_length(request_fingerprint)=64),
      before_state JSONB NOT NULL,
      after_state JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, receipt_id, version),
      UNIQUE(company_id, client_request_id),
      FOREIGN KEY (company_id, receipt_id)
        REFERENCES finance_receipts(company_id, id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS finance_receipt_detail_audit_company_receipt_idx
      ON finance_receipt_detail_audit(company_id, receipt_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS finance_receipt_lifecycle_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      receipt_id UUID NOT NULL,
      version INTEGER NOT NULL CHECK (version > 1),
      actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL CHECK (action IN (
        'matched','rematched','auto_matched','unmatched','provider_history_unmatched',
        'archived','restored','cash_purchase_created'
      )),
      reason TEXT NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 500),
      client_request_id UUID,
      request_fingerprint TEXT NOT NULL CHECK (char_length(request_fingerprint)=64),
      before_state JSONB NOT NULL,
      after_state JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, receipt_id, version),
      UNIQUE(company_id, client_request_id),
      FOREIGN KEY (company_id, receipt_id)
        REFERENCES finance_receipts(company_id, id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS finance_receipt_lifecycle_audit_company_receipt_idx
      ON finance_receipt_lifecycle_audit(company_id, receipt_id, created_at DESC);
  `);
}

export async function installReceiptRoutes({ app, pool, authRequired, requireEmployer }) {
  app.get("/api/finance/receipts", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const filter = cleanString(req.query.filter, 40);
      const search = cleanString(req.query.search, 120);
      const limit = Math.min(Math.max(Number(req.query.limit || 50), 1), 100);
      const offset = Math.max(Number(req.query.offset || 0), 0);
      const conditions = ["r.company_id = $1"];
      const values = [req.companyId];
      if (filter === "unmatched") conditions.push("r.archived_at IS NULL AND r.transaction_id IS NULL AND r.status IN ('unmatched','possible_match','processing_failed')");
      else if (filter === "matched") conditions.push("r.archived_at IS NULL AND r.transaction_id IS NOT NULL");
      else if (filter === "cash") conditions.push("r.archived_at IS NULL AND r.status = 'cash_purchase'");
      else if (filter === "processing") conditions.push("r.archived_at IS NULL AND r.status IN ('processing','processing_failed')");
      else if (filter === "archived") conditions.push("r.archived_at IS NOT NULL AND r.status = 'archived'");
      else conditions.push("r.archived_at IS NULL");
      if (search) {
        values.push(`%${search.toLowerCase()}%`);
        conditions.push(`(lower(r.merchant_name) LIKE $${values.length} OR lower(COALESCE(r.ocr_text,'')) LIKE $${values.length} OR CAST(r.amount_cents AS TEXT) LIKE $${values.length})`);
      }
      values.push(limit, offset);
      const { rows } = await pool.query(
        `SELECT r.*, t.merchant_name AS transaction_merchant_name, t.amount_cents AS transaction_amount_cents,
                a.name AS account_name, a.institution_name
           FROM finance_receipts r
           LEFT JOIN finance_transactions t ON t.id = r.transaction_id AND t.company_id = r.company_id
           LEFT JOIN finance_accounts a ON a.id = t.account_id AND a.company_id = r.company_id
          WHERE ${conditions.join(" AND ")}
          ORDER BY r.created_at DESC
          LIMIT $${values.length - 1} OFFSET $${values.length}`,
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
      const result = await createReceiptCapture({
        pool,
        companyID: req.companyId,
        actorUserID: req.userId,
        body: req.body || {}
      });
      res.status(result.recovered ? 200 : 201).json(receiptPayload(result.receipt));
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
      const { rows } = await pool.query(
        `SELECT id, status, details_version, object_key, thumbnail_object_key
           FROM finance_receipts
          WHERE id=$1 AND company_id=$2`,
        [req.params.id, req.companyId]
      );
      if (!rows.length) return res.status(404).json({ error: "finance_receipt_not_found", message: "Receipt was not found." });
      const receipt = rows[0];
      const captureIncomplete = ["processing", "processing_failed"].includes(receipt.status)
        || (!receipt.object_key && Number(receipt.details_version || 1) === 1);
      if (!captureIncomplete || receipt.object_key || receipt.thumbnail_object_key) {
        return res.status(409).json({
          error: "receipt_capture_complete",
          message: "Completed receipt media cannot be replaced through the capture upload route."
        });
      }
      const kind = req.body?.kind === "thumbnail" ? "thumbnail" : "image";
      const mimeType = cleanString(req.body?.mime_type || "image/jpeg", 80);
      const byteSize = Number(req.body?.byte_size || 0);
      if (!Number.isFinite(byteSize) || byteSize <= 0 || byteSize > 25 * 1024 * 1024) return res.status(400).json({ error: "invalid_receipt_file_size", message: "Receipt image size is invalid." });
      const objectKey = `${receiptObjectPrefix(req.companyId, req.params.id)}${kind}.jpg`;
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

  app.get("/api/finance/receipts/:id/detail-audit", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const receiptID = receiptUUID(req.params.id, "receipt_id");
      const receipt = await pool.query(
        `SELECT id FROM finance_receipts WHERE id=$1 AND company_id=$2`,
        [receiptID, req.companyId]
      );
      if (!receipt.rows.length) {
        return res.status(404).json({ error: "finance_receipt_not_found", message: "Receipt was not found." });
      }
      const requestedLimit = Number(req.query.limit ?? 50);
      const limit = Number.isInteger(requestedLimit) ? Math.min(Math.max(requestedLimit, 1), 100) : 50;
      const { rows } = await pool.query(
        `SELECT audit.id, audit.receipt_id, audit.version, audit.action, audit.reason,
                audit.changed_fields, audit.actor_user_id, actor.email AS actor_email, audit.created_at
           FROM finance_receipt_detail_audit audit
           LEFT JOIN users actor
             ON actor.id=audit.actor_user_id AND actor.company_id=audit.company_id
          WHERE audit.company_id=$1 AND audit.receipt_id=$2
          ORDER BY audit.created_at DESC, audit.id DESC LIMIT $3`,
        [req.companyId, receiptID, limit]
      );
      res.json(rows.map(receiptDetailAuditPayload));
    } catch (error) {
      handleReceiptError(res, error, "finance_receipt_detail_audit_failed");
    }
  });

  app.get("/api/finance/receipts/:id/lifecycle-audit", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const receiptID = receiptUUID(req.params.id, "receipt_id");
      const receipt = await pool.query(
        `SELECT id FROM finance_receipts WHERE id=$1 AND company_id=$2`,
        [receiptID, req.companyId]
      );
      if (!receipt.rows.length) {
        return res.status(404).json({ error: "finance_receipt_not_found", message: "Receipt was not found." });
      }
      const requestedLimit = Number(req.query.limit ?? 50);
      const limit = Number.isInteger(requestedLimit) ? Math.min(Math.max(requestedLimit, 1), 100) : 50;
      const { rows } = await pool.query(
        `SELECT audit.id, audit.receipt_id, audit.version, audit.action, audit.reason,
                audit.before_state, audit.after_state, audit.actor_user_id,
                actor.email AS actor_email, audit.created_at
           FROM finance_receipt_lifecycle_audit audit
           LEFT JOIN users actor
             ON actor.id=audit.actor_user_id AND actor.company_id=audit.company_id
          WHERE audit.company_id=$1 AND audit.receipt_id=$2
          ORDER BY audit.created_at DESC, audit.id DESC LIMIT $3`,
        [req.companyId, receiptID, limit]
      );
      res.json(rows.map(receiptLifecycleAuditPayload));
    } catch (error) {
      handleReceiptError(res, error, "finance_receipt_lifecycle_audit_failed");
    }
  });

  app.post("/api/finance/receipts/:id/lifecycle", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const request = normalizeReceiptLifecycleRequest({ receiptID: req.params.id, body: req.body });
      const result = request.action === "cash_purchase"
        ? await createReceiptCashPurchase({ pool, companyID: req.companyId, actorUserID: req.userId, request })
        : await executeReceiptLifecycleTransition(pool, {
          companyID: req.companyId,
          actorUserID: req.userId,
          request
        });
      const receipt = await loadReceiptWithContext(pool, req.companyId, request.receipt_id);
      res.json({
        replayed: result.replayed,
        receipt: receiptPayload(receipt),
        audit: receiptLifecycleAuditPayload(result.audit),
        transaction: result.transaction ? transactionPayload(result.transaction) : null,
        account_balance_cents: result.account_balance_cents ?? null
      });
    } catch (error) {
      handleReceiptError(res, error, "finance_receipt_lifecycle_update_failed");
    }
  });

  app.put("/api/finance/receipts/:id/details", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const result = await replaceReceiptDetails({
        pool,
        companyID: req.companyId,
        actorUserID: req.userId,
        receiptID: req.params.id,
        body: req.body
      });
      res.json({
        replayed: result.replayed,
        receipt: receiptPayload(result.receipt),
        audit: receiptDetailAuditPayload(result.audit)
      });
    } catch (error) {
      handleReceiptError(res, error, "finance_receipt_detail_update_failed");
    }
  });

  app.patch("/api/finance/receipts/:id", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const payload = receiptUpdatePayload(req.body || {});
      const objectKey = cleanReceiptObjectKey(req.body?.object_key, req.companyId, req.params.id, "object_key");
      const thumbnailObjectKey = cleanReceiptObjectKey(req.body?.thumbnail_object_key, req.companyId, req.params.id, "thumbnail_object_key");
      const status = VALID_STATUSES.has(req.body?.status) ? req.body.status : (objectKey ? "unmatched" : undefined);
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
            AND (status IN ('processing','processing_failed') OR (object_key IS NULL AND details_version=1))
          RETURNING *`,
        [
          req.params.id, req.companyId, payload.merchant_name, payload.normalized_merchant_name,
          payload.purchase_date, payload.purchase_time, payload.amount_cents, payload.subtotal_cents,
          payload.tax_cents, payload.tip_cents, payload.currency, payload.address, payload.city,
          payload.state, payload.postal_code, payload.country, payload.payment_method_text,
          payload.card_last_four, payload.finance_category, payload.business_use, payload.note,
          payload.ocr_text, payload.ocr_confidence, objectKey,
          thumbnailObjectKey, payload.mime_type, payload.pixel_width,
          payload.pixel_height, payload.file_size_bytes, payload.content_sha256, status
        ]
      );
      if (!rows.length) {
        const existing = await pool.query(
          `SELECT id FROM finance_receipts WHERE id=$1 AND company_id=$2`,
          [req.params.id, req.companyId]
        );
        if (existing.rows.length) {
          return res.status(409).json({
            error: "receipt_details_audited_route_required",
            message: "Completed receipt details must be changed through the audited detail editor."
          });
        }
        return res.status(404).json({ error: "finance_receipt_not_found", message: "Receipt was not found." });
      }
      if (!rows[0].transaction_id) {
        const candidates = await findReceiptCandidates(pool, req.companyId, rows[0]);
        const decision = chooseReceiptMatch(rows[0], candidates.map((candidate) => candidate.transaction));
        if (decision.autoMatch) {
          const matched = await executeReceiptLifecycleTransition(pool, {
            companyID: req.companyId,
            actorUserID: null,
            auditAction: "auto_matched",
            allowNoop: true,
            request: {
              receipt_id: req.params.id,
              action: "match",
              client_request_id: null,
              expected_lifecycle_version: Number(rows[0].lifecycle_version || 1),
              reason: "Receipt automatically matched after capture processing.",
              transaction_id: decision.best.transaction.id,
              method: "auto",
              confidence_score: decision.best.score,
              account_id: null,
              expected_account_balance_cents: null,
              amount_cents: null,
              finance_category: null,
              request_fingerprint: null
            }
          });
          const withContext = await loadReceiptWithContext(pool, req.companyId, req.params.id);
          return res.json(receiptPayload(withContext || matched.receipt));
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
      const request = legacyReceiptLifecycleRequest({
        receiptID: req.params.id,
        action: "match",
        body: req.body,
        reason: "Receipt matched from a legacy client."
      });
      const result = await executeReceiptLifecycleTransition(pool, {
        companyID: req.companyId,
        actorUserID: req.userId,
        request
      });
      const receipt = await loadReceiptWithContext(pool, req.companyId, request.receipt_id);
      res.json(receiptPayload(receipt || result.receipt));
    } catch (error) {
      handleReceiptError(res, error, "finance_receipt_match_failed");
    }
  });

  app.post("/api/finance/receipts/:id/unmatch", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const request = legacyReceiptLifecycleRequest({
        receiptID: req.params.id,
        action: "unmatch",
        reason: "Receipt unmatched from a legacy client."
      });
      const result = await executeReceiptLifecycleTransition(pool, {
        companyID: req.companyId,
        actorUserID: req.userId,
        request
      });
      const receipt = await loadReceiptWithContext(pool, req.companyId, request.receipt_id);
      res.json(receiptPayload(receipt || result.receipt));
    } catch (error) {
      handleReceiptError(res, error, "finance_receipt_unmatch_failed");
    }
  });

  app.post("/api/finance/receipts/:id/archive", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const request = legacyReceiptLifecycleRequest({
        receiptID: req.params.id,
        action: "archive",
        reason: "Receipt archived from a legacy client."
      });
      const result = await executeReceiptLifecycleTransition(pool, {
        companyID: req.companyId,
        actorUserID: req.userId,
        request
      });
      const receipt = await loadReceiptWithContext(pool, req.companyId, request.receipt_id);
      res.json(receiptPayload(receipt || result.receipt));
    } catch (error) {
      handleReceiptError(res, error, "finance_receipt_archive_failed");
    }
  });

  app.post("/api/finance/receipts/:id/cash-purchase", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const request = legacyReceiptLifecycleRequest({
        receiptID: req.params.id,
        action: "cash_purchase",
        body: req.body,
        reason: "Cash purchase created from a legacy client."
      });
      const result = await createReceiptCashPurchase({
        pool,
        companyID: req.companyId,
        actorUserID: req.userId,
        request
      });
      const receipt = await loadReceiptWithContext(pool, req.companyId, request.receipt_id);
      res.json({
        receipt: receiptPayload(receipt || result.receipt),
        transaction: transactionPayload(result.transaction),
        account_balance_cents: result.account_balance_cents
      });
    } catch (error) {
      handleReceiptError(res, error, "finance_receipt_cash_purchase_failed");
    }
  });
}
