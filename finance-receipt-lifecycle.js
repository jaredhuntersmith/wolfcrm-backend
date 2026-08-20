import { createHash, randomUUID } from "node:crypto";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REQUEST_ACTIONS = new Set(["match", "unmatch", "archive", "restore", "cash_purchase"]);
export function receiptLifecycleError(code, message, statusCode = 400, details = {}) {
  return Object.assign(new Error(message), { code, statusCode, ...details });
}

function cleanText(value, field, maxLength, { required = false } = {}) {
  const text = (value ?? "").toString().trim();
  if (required && !text) throw receiptLifecycleError(`${field}_required`, `${field.replaceAll("_", " ")} is required.`);
  if (text.length > maxLength) throw receiptLifecycleError(`${field}_too_long`, `${field.replaceAll("_", " ")} must be ${maxLength} characters or fewer.`);
  return text || null;
}

function uuid(value, field, { required = true } = {}) {
  const text = (value ?? "").toString().trim().toLowerCase();
  if (!text && !required) return null;
  if (!UUID_PATTERN.test(text)) throw receiptLifecycleError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  return text;
}

function exactInteger(value, field, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value.trim()) ? Number(value.trim()) : value;
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw receiptLifecycleError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return parsed;
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
  }
  return value;
}

export function receiptLifecycleFingerprint(value) {
  return createHash("sha256").update(JSON.stringify(stableValue(value))).digest("hex");
}

export function normalizeReceiptLifecycleRequest({ receiptID, body = {} }) {
  const action = (body.action ?? "").toString().trim().toLowerCase();
  if (!REQUEST_ACTIONS.has(action)) {
    throw receiptLifecycleError("receipt_lifecycle_action_invalid", "Receipt lifecycle action is invalid.");
  }
  const requestedMethod = (body.method ?? "manual").toString().trim().toLowerCase();
  if (action === "match" && !["manual", "user_direct"].includes(requestedMethod)) {
    throw receiptLifecycleError("method_invalid", "Match method is invalid.");
  }
  const request = {
    receipt_id: uuid(receiptID, "receipt_id"),
    action,
    client_request_id: uuid(body.client_request_id, "client_request_id"),
    expected_lifecycle_version: exactInteger(body.expected_lifecycle_version, "expected_lifecycle_version", 1),
    reason: cleanText(body.reason, "reason", 500, { required: true }),
    transaction_id: action === "match" ? uuid(body.transaction_id, "transaction_id") : null,
    method: action === "match" ? requestedMethod : null,
    confidence_score: action === "match" && body.confidence_score !== null && body.confidence_score !== undefined
      ? exactInteger(body.confidence_score, "confidence_score", 0, 100)
      : null,
    account_id: action === "cash_purchase" ? uuid(body.account_id, "account_id") : null,
    expected_account_balance_cents: action === "cash_purchase"
      ? exactInteger(body.expected_account_balance_cents, "expected_account_balance_cents", Number.MIN_SAFE_INTEGER)
      : null,
    amount_cents: action === "cash_purchase" ? exactInteger(body.amount_cents, "amount_cents", 1) : null,
    finance_category: action === "cash_purchase"
      ? cleanText(body.finance_category ?? "Other", "finance_category", 80, { required: true })
      : null
  };
  return { ...request, request_fingerprint: receiptLifecycleFingerprint(request) };
}

export function legacyReceiptLifecycleRequest({ receiptID, action, body = {}, reason }) {
  const normalizedAction = action === "match" ? "match" : action;
  if (!REQUEST_ACTIONS.has(normalizedAction)) {
    throw receiptLifecycleError("receipt_lifecycle_action_invalid", "Receipt lifecycle action is invalid.");
  }
  return {
    receipt_id: uuid(receiptID, "receipt_id"),
    action: normalizedAction,
    client_request_id: randomUUID(),
    expected_lifecycle_version: null,
    reason: cleanText(reason, "reason", 500, { required: true }),
    transaction_id: normalizedAction === "match" ? uuid(body.transaction_id, "transaction_id") : null,
    method: normalizedAction === "match" && body.method === "user_direct" ? "user_direct" : "manual",
    confidence_score: normalizedAction === "match" && body.confidence_score !== null && body.confidence_score !== undefined
      ? exactInteger(body.confidence_score, "confidence_score", 0, 100)
      : null,
    account_id: normalizedAction === "cash_purchase" ? uuid(body.account_id, "account_id") : null,
    expected_account_balance_cents: null,
    amount_cents: normalizedAction === "cash_purchase" ? exactInteger(body.amount_cents, "amount_cents", 1) : null,
    finance_category: normalizedAction === "cash_purchase"
      ? cleanText(body.finance_category ?? "Other", "finance_category", 80, { required: true })
      : null,
    request_fingerprint: null,
    legacy: true
  };
}

export function receiptLifecycleState(row = {}, extras = {}) {
  return {
    status: row.status || null,
    transaction_id: row.transaction_id || null,
    match_method: row.match_method || null,
    match_confidence: row.match_confidence === null || row.match_confidence === undefined ? null : Number(row.match_confidence),
    archived: Boolean(row.archived_at || row.status === "archived"),
    archived_from_status: row.archived_from_status || null,
    account_id: extras.account_id || null,
    account_balance_cents: extras.account_balance_cents === undefined ? null : extras.account_balance_cents
  };
}

export function conservativeReceiptRestoreStatus(row = {}) {
  const storedStatus = row.archived_from_status;
  if (storedStatus === "cash_purchase" && row.transaction_id && row.match_method === "cash_purchase") return storedStatus;
  if (["matched", "manually_matched"].includes(storedStatus) && row.transaction_id) return storedStatus;
  if (["unmatched", "possible_match", "processing_failed"].includes(storedStatus) && !row.transaction_id) return storedStatus;
  if (row.match_method === "cash_purchase" && row.transaction_id) return "cash_purchase";
  if (row.transaction_id) return row.match_method === "manual" ? "manually_matched" : "matched";
  return "unmatched";
}

export function receiptLifecycleAuditPayload(row = {}) {
  return {
    id: String(row.id),
    receipt_id: String(row.receipt_id),
    version: Number(row.version),
    action: row.action,
    reason: row.reason,
    actor_user_id: row.actor_user_id || null,
    actor_email: row.actor_email || null,
    before_state: row.before_state || {},
    after_state: row.after_state || {},
    created_at: row.created_at || null
  };
}

export async function findReceiptLifecycleReplay(client, companyID, request) {
  if (!request.client_request_id) return null;
  const { rows } = await client.query(
    `SELECT * FROM finance_receipt_lifecycle_audit
      WHERE company_id=$1 AND client_request_id=$2::uuid`,
    [companyID, request.client_request_id]
  );
  if (!rows.length) return null;
  const row = rows[0];
  const fingerprint = request.request_fingerprint || receiptLifecycleFingerprint({
    receipt_id: request.receipt_id,
    action: request.action,
    client_request_id: request.client_request_id,
    expected_lifecycle_version: request.expected_lifecycle_version,
    reason: request.reason,
    transaction_id: request.transaction_id || null,
    method: request.method || null,
    confidence_score: request.confidence_score ?? null,
    account_id: request.account_id || null,
    expected_account_balance_cents: request.expected_account_balance_cents ?? null,
    amount_cents: request.amount_cents ?? null,
    finance_category: request.finance_category || null
  });
  if (String(row.receipt_id) !== request.receipt_id || row.request_fingerprint !== fingerprint) {
    throw receiptLifecycleError(
      "receipt_lifecycle_request_conflict",
      "That request ID was already used for a different receipt action.",
      409
    );
  }
  return row;
}

export async function appendReceiptLifecycleAudit(client, {
  companyID,
  receiptID,
  version,
  actorUserID = null,
  action,
  reason,
  clientRequestID = null,
  requestFingerprint = null,
  beforeState,
  afterState
}) {
  const fingerprint = requestFingerprint || receiptLifecycleFingerprint({
    receipt_id: receiptID,
    version,
    action,
    reason,
    before_state: beforeState,
    after_state: afterState
  });
  const { rows } = await client.query(
    `INSERT INTO finance_receipt_lifecycle_audit (
       company_id, receipt_id, version, actor_user_id, action, reason,
       client_request_id, request_fingerprint, before_state, after_state
     ) VALUES ($1,$2,$3,$4,$5,$6,$7::uuid,$8,$9,$10)
     RETURNING *`,
    [companyID, receiptID, version, actorUserID, action, reason, clientRequestID,
      fingerprint, JSON.stringify(beforeState), JSON.stringify(afterState)]
  );
  return rows[0];
}

async function loadReceiptForLifecycle(client, companyID, receiptID) {
  const { rows } = await client.query(
    `SELECT * FROM finance_receipts WHERE id=$1 AND company_id=$2 FOR UPDATE`,
    [receiptID, companyID]
  );
  if (!rows.length) throw receiptLifecycleError("finance_receipt_not_found", "Receipt was not found.", 404);
  return rows[0];
}

export async function applyReceiptLifecycleTransitionInClient(client, {
  companyID,
  actorUserID = null,
  request,
  auditAction = null,
  allowNoop = false,
  allowArchived = false,
  allowIncomplete = false,
  preserveArchive = false
}) {
  if (request.action === "cash_purchase") {
    throw receiptLifecycleError("receipt_lifecycle_action_invalid", "Cash purchase creation requires the coordinated cash workflow.");
  }
  const replay = await findReceiptLifecycleReplay(client, companyID, request);
  if (replay) {
    const current = await loadReceiptForLifecycle(client, companyID, request.receipt_id);
    return { replayed: true, receipt: current, audit: replay };
  }

  if (request.action === "match") {
    const transaction = await client.query(
      `SELECT id FROM finance_transactions
        WHERE id=$1 AND company_id=$2 AND removed_at IS NULL
        FOR KEY SHARE`,
      [request.transaction_id, companyID]
    );
    if (!transaction.rows.length) {
      throw receiptLifecycleError("finance_transaction_not_found", "Transaction was not found.", 404);
    }
  }

  const current = await loadReceiptForLifecycle(client, companyID, request.receipt_id);
  const currentVersion = Number(current.lifecycle_version || 1);
  if (request.expected_lifecycle_version !== null && request.expected_lifecycle_version !== currentVersion) {
    throw receiptLifecycleError(
      "receipt_lifecycle_stale",
      "Receipt lifecycle changed after it was loaded.",
      409,
      { current_version: currentVersion }
    );
  }

  const isArchived = Boolean(current.archived_at || current.status === "archived");
  if (request.action !== "restore" && isArchived && !allowArchived) {
    throw receiptLifecycleError("receipt_lifecycle_archived", "Restore the receipt before changing its lifecycle.", 409);
  }
  if (request.action === "restore" && !isArchived) {
    if (allowNoop) return { replayed: false, noop: true, receipt: current, audit: null };
    throw receiptLifecycleError("receipt_lifecycle_not_archived", "Receipt is not archived.", 409);
  }
  const failedCaptureArchive = request.action === "archive" && current.status === "processing_failed";
  const failedCaptureRestore = request.action === "restore" && current.archived_from_status === "processing_failed";
  if (!allowIncomplete && !failedCaptureArchive && !failedCaptureRestore
    && (["processing", "processing_failed"].includes(current.status) || !current.object_key)) {
    throw receiptLifecycleError("receipt_lifecycle_processing", "Finish or recover receipt capture before changing its lifecycle.", 409);
  }

  const beforeState = receiptLifecycleState(current);
  let updateSQL;
  let updateParams;
  let action = auditAction;
  if (request.action === "match") {
    if (current.status === "cash_purchase" || current.match_method === "cash_purchase") {
      throw receiptLifecycleError("receipt_cash_purchase_locked", "A cash-purchase receipt cannot be matched to another transaction.", 409);
    }
    if (String(current.transaction_id || "") === request.transaction_id) {
      if (allowNoop) return { replayed: false, noop: true, receipt: current, audit: null };
      throw receiptLifecycleError("receipt_lifecycle_unchanged", "Receipt is already matched to that transaction.", 409);
    }
    action ||= current.transaction_id ? "rematched" : (request.method === "manual" ? "matched" : "matched");
    updateSQL = `UPDATE finance_receipts
                    SET transaction_id=$3,
                        status=$4,
                        match_method=$5,
                        match_confidence=$6,
                        matched_at=now(),
                        lifecycle_version=$7,
                        updated_at=now()
                  WHERE id=$1 AND company_id=$2
                  RETURNING *`;
    updateParams = [request.receipt_id, companyID, request.transaction_id,
      request.method === "manual" ? "manually_matched" : "matched",
      request.method, request.confidence_score, currentVersion + 1];
  } else if (request.action === "unmatch") {
    if (current.status === "cash_purchase" || current.match_method === "cash_purchase") {
      throw receiptLifecycleError("receipt_cash_purchase_locked", "A cash-purchase receipt cannot be detached from its generated transaction.", 409);
    }
    if (!current.transaction_id) {
      if (allowNoop) return { replayed: false, noop: true, receipt: current, audit: null };
      throw receiptLifecycleError("receipt_lifecycle_unchanged", "Receipt is already unmatched.", 409);
    }
    action ||= "unmatched";
    updateSQL = preserveArchive && isArchived
      ? `UPDATE finance_receipts
            SET transaction_id=NULL, status='archived', archived_from_status='unmatched',
                match_method=NULL, match_confidence=NULL, matched_at=NULL,
                lifecycle_version=$3, updated_at=now()
          WHERE id=$1 AND company_id=$2
          RETURNING *`
      : `UPDATE finance_receipts
            SET transaction_id=NULL, status='unmatched', match_method=NULL,
                match_confidence=NULL, matched_at=NULL,
                lifecycle_version=$3, updated_at=now()
          WHERE id=$1 AND company_id=$2
          RETURNING *`;
    updateParams = [request.receipt_id, companyID, currentVersion + 1];
  } else if (request.action === "archive") {
    action ||= "archived";
    updateSQL = `UPDATE finance_receipts
                    SET archived_from_status=status, status='archived',
                        archived_at=COALESCE(archived_at, now()),
                        lifecycle_version=$3, updated_at=now()
                  WHERE id=$1 AND company_id=$2
                  RETURNING *`;
    updateParams = [request.receipt_id, companyID, currentVersion + 1];
  } else {
    const restoredStatus = conservativeReceiptRestoreStatus(current);
    action ||= "restored";
    updateSQL = `UPDATE finance_receipts
                    SET status=$3, archived_at=NULL, archived_from_status=NULL,
                        lifecycle_version=$4, updated_at=now()
                  WHERE id=$1 AND company_id=$2
                  RETURNING *`;
    updateParams = [request.receipt_id, companyID, restoredStatus, currentVersion + 1];
  }

  if (!Number.isSafeInteger(currentVersion + 1)) {
    throw receiptLifecycleError("receipt_lifecycle_version_invalid", "Receipt lifecycle version is invalid.", 409);
  }
  const updated = (await client.query(updateSQL, updateParams)).rows[0];
  if (request.action === "match") {
    await client.query(
      `INSERT INTO finance_receipt_matches(
         company_id, receipt_id, transaction_id, method, confidence_score, was_selected, created_by
       ) VALUES($1,$2,$3,$4,$5,true,$6)`,
      [companyID, request.receipt_id, request.transaction_id, request.method,
        request.confidence_score, actorUserID]
    );
  }
  const afterState = receiptLifecycleState(updated);
  const fingerprint = request.request_fingerprint || receiptLifecycleFingerprint({
    receipt_id: request.receipt_id,
    action: request.action,
    client_request_id: request.client_request_id,
    expected_lifecycle_version: request.expected_lifecycle_version,
    reason: request.reason,
    transaction_id: request.transaction_id || null,
    method: request.method || null,
    confidence_score: request.confidence_score ?? null,
    account_id: request.account_id || null,
    expected_account_balance_cents: request.expected_account_balance_cents ?? null,
    amount_cents: request.amount_cents ?? null,
    finance_category: request.finance_category || null
  });
  const audit = await appendReceiptLifecycleAudit(client, {
    companyID,
    receiptID: request.receipt_id,
    version: currentVersion + 1,
    actorUserID,
    action,
    reason: request.reason,
    clientRequestID: request.client_request_id,
    requestFingerprint: fingerprint,
    beforeState,
    afterState
  });
  return { replayed: false, receipt: updated, audit };
}

export async function executeReceiptLifecycleTransition(pool, options) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(`SELECT pg_advisory_xact_lock(hashtext($1::text))`, [`${options.companyID}|receipt-lifecycle`]);
    const result = await applyReceiptLifecycleTransitionInClient(client, options);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}
