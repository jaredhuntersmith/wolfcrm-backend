import assert from "node:assert/strict";
import fs from "node:fs";
import {
  chooseReceiptMatch,
  merchantSimilarity,
  normalizeMerchantName,
  scoreReceiptCandidate
} from "../finance-receipt-matching.js";
import {
  createReceiptCashPurchase,
  installReceiptRoutes,
  installReceiptSchema,
  normalizeReceiptDetailEditRequest,
  receiptDetailAuditSnapshot,
  receiptDetailChangedFields,
  receiptDetailDocument,
  receiptDetailFingerprint
} from "../finance-receipts.js";
import {
  conservativeReceiptRestoreStatus,
  executeReceiptLifecycleTransition,
  normalizeReceiptLifecycleRequest,
  receiptLifecycleState
} from "../finance-receipt-lifecycle.js";

const REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000";
const RECEIPT_ID = "223e4567-e89b-42d3-a456-426614174000";

function tx(overrides = {}) {
  return {
    id: overrides.id || "tx_1",
    direction: "expense",
    amount_cents: 14372,
    transaction_date: "2026-08-11",
    authorized_date: "2026-08-11",
    merchant_name: "LOWES #1234",
    original_name: "LOWES #1234",
    location_city: "Louisville",
    location_region: "KY",
    location_postal_code: "40202",
    account_mask: "1234",
    ...overrides
  };
}

function receipt(overrides = {}) {
  return {
    id: "receipt_1",
    merchant_name: "Lowe's",
    normalized_merchant_name: normalizeMerchantName("Lowe's"),
    amount_cents: 14372,
    purchase_date: "2026-08-11",
    city: "Louisville",
    state: "KY",
    postal_code: "40202",
    card_last_four: "1234",
    ...overrides
  };
}

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("merchant normalization strips store numbers and punctuation", () => {
  assert.equal(normalizeMerchantName("The Home Depot #2312"), "HOME DEPOT");
  assert.equal(normalizeMerchantName("McDonald's 1451"), "MCDONALDS");
});

test("merchant similarity handles common Plaid vs receipt names", () => {
  assert.ok(merchantSimilarity("LOWES #1234", "Lowe's") >= 0.9);
  assert.ok(merchantSimilarity("THE HOME DEPOT #2312", "Home Depot") >= 0.9);
});

test("exact amount date merchant creates high confidence", () => {
  assert.ok(scoreReceiptCandidate(receipt(), tx()) >= 95);
});

test("income transaction is excluded", () => {
  assert.equal(scoreReceiptCandidate(receipt(), tx({ direction: "income" })), 0);
});

test("date one day apart still scores as possible", () => {
  assert.ok(scoreReceiptCandidate(receipt({ purchase_date: "2026-08-10" }), tx()) >= 80);
});

test("posted date three days later can still match", () => {
  assert.ok(scoreReceiptCandidate(receipt({ purchase_date: "2026-08-08", card_last_four: null }), tx({ authorized_date: null })) >= 70);
});

test("different amounts do not auto match", () => {
  const decision = chooseReceiptMatch(receipt({ amount_cents: 6000 }), [tx({ merchant_name: "LOWES", amount_cents: 14372 })]);
  assert.equal(decision.autoMatch, false);
});

test("same-day identical purchases remain ambiguous", () => {
  const decision = chooseReceiptMatch(receipt(), [
    tx({ id: "tx_1" }),
    tx({ id: "tx_2" })
  ]);
  assert.equal(decision.autoMatch, false);
  assert.equal(decision.candidates.length, 2);
});

test("very high unique score auto matches", () => {
  const decision = chooseReceiptMatch(receipt(), [tx()]);
  assert.equal(decision.autoMatch, true);
});

test("best score too close to second avoids auto match", () => {
  const decision = chooseReceiptMatch(receipt({ card_last_four: null }), [
    tx({ id: "tx_1", location_postal_code: null }),
    tx({ id: "tx_2", merchant_name: "LOWES STORE", location_postal_code: null })
  ]);
  assert.equal(decision.autoMatch, false);
});

test("gas temporary hold does not auto match without amount evidence", () => {
  const decision = chooseReceiptMatch(receipt({ merchant_name: "Shell", normalized_merchant_name: normalizeMerchantName("Shell"), amount_cents: 7214 }), [
    tx({ id: "hold", merchant_name: "SHELL OIL", amount_cents: 10000, account_mask: null })
  ]);
  assert.equal(decision.autoMatch, false);
});

test("restaurant pending amount can remain possible until final posts", () => {
  const pendingDecision = chooseReceiptMatch(receipt({ merchant_name: "Restaurant", normalized_merchant_name: normalizeMerchantName("Restaurant"), amount_cents: 6000 }), [
    tx({ id: "pending", merchant_name: "RESTAURANT", amount_cents: 5000, pending: true })
  ]);
  assert.equal(pendingDecision.autoMatch, false);
  const postedDecision = chooseReceiptMatch(receipt({ merchant_name: "Restaurant", normalized_merchant_name: normalizeMerchantName("Restaurant"), amount_cents: 6000 }), [
    tx({ id: "posted", merchant_name: "RESTAURANT", amount_cents: 6000, pending: false })
  ]);
  assert.equal(postedDecision.autoMatch, true);
});

test("old receipt can match historical transaction by its own date", () => {
  assert.ok(scoreReceiptCandidate(receipt({ purchase_date: "2026-07-12" }), tx({ transaction_date: "2026-07-12", authorized_date: "2026-07-12" })) >= 95);
});

test("receipt lifecycle requests are exact versioned idempotent commands", () => {
  const transactionID = "323e4567-e89b-42d3-a456-426614174000";
  const request = normalizeReceiptLifecycleRequest({
    receiptID: RECEIPT_ID,
    body: {
      client_request_id: REQUEST_ID,
      expected_lifecycle_version: 4,
      action: "match",
      transaction_id: transactionID,
      method: "manual",
      confidence_score: 93,
      reason: "Selected the posted card transaction"
    }
  });
  assert.equal(request.receipt_id, RECEIPT_ID);
  assert.equal(request.expected_lifecycle_version, 4);
  assert.equal(request.transaction_id, transactionID);
  assert.equal(request.confidence_score, 93);
  assert.match(request.request_fingerprint, /^[0-9a-f]{64}$/);
  assert.throws(
    () => normalizeReceiptLifecycleRequest({ receiptID: RECEIPT_ID, body: { ...request, reason: "" } }),
    (error) => error.code === "reason_required"
  );
  assert.throws(
    () => normalizeReceiptLifecycleRequest({ receiptID: RECEIPT_ID, body: { ...request, expected_lifecycle_version: 0 } }),
    (error) => error.code === "expected_lifecycle_version_invalid"
  );
  assert.throws(
    () => normalizeReceiptLifecycleRequest({ receiptID: RECEIPT_ID, body: { ...request, method: "auto" } }),
    (error) => error.code === "method_invalid"
  );
});

test("receipt restore status preserves valid archived state and fails conservatively", () => {
  assert.equal(conservativeReceiptRestoreStatus({ archived_from_status: "possible_match" }), "possible_match");
  assert.equal(conservativeReceiptRestoreStatus({ archived_from_status: "matched", transaction_id: null }), "unmatched");
  assert.equal(conservativeReceiptRestoreStatus({ archived_from_status: "corrupt", transaction_id: "tx", match_method: "manual" }), "manually_matched");
  assert.equal(conservativeReceiptRestoreStatus({}), "unmatched");
  assert.deepEqual(receiptLifecycleState({ status: "archived", archived_at: new Date(), archived_from_status: "matched" }), {
    status: "archived",
    transaction_id: null,
    match_method: null,
    match_confidence: null,
    archived: true,
    archived_from_status: "matched",
    account_id: null,
    account_balance_cents: null
  });
});

test("receipt lifecycle match commits once and exact retry replays without another write", async () => {
  const companyID = "423e4567-e89b-42d3-a456-426614174000";
  const userID = "523e4567-e89b-42d3-a456-426614174000";
  const transactionID = "623e4567-e89b-42d3-a456-426614174000";
  const request = normalizeReceiptLifecycleRequest({
    receiptID: RECEIPT_ID,
    body: {
      client_request_id: REQUEST_ID,
      expected_lifecycle_version: 1,
      action: "match",
      transaction_id: transactionID,
      method: "manual",
      reason: "Matched after reviewing amount and date"
    }
  });
  let receiptRow = {
    id: RECEIPT_ID,
    company_id: companyID,
    status: "unmatched",
    transaction_id: null,
    object_key: `receipts/${companyID}/${RECEIPT_ID}/image.jpg`,
    lifecycle_version: 1
  };
  let auditRow = null;
  const queries = [];
  const client = {
    async query(sql, params = []) {
      const compact = sql.replace(/\s+/g, " ").trim();
      queries.push(compact);
      if (["BEGIN", "COMMIT", "ROLLBACK"].includes(compact) || compact.includes("pg_advisory_xact_lock")) return { rows: [] };
      if (compact.includes("FROM finance_receipt_lifecycle_audit") && compact.includes("client_request_id")) return { rows: auditRow ? [auditRow] : [] };
      if (compact.startsWith("SELECT id FROM finance_transactions")) return { rows: [{ id: transactionID }] };
      if (compact.startsWith("SELECT * FROM finance_receipts")) return { rows: [receiptRow] };
      if (compact.startsWith("UPDATE finance_receipts")) {
        receiptRow = { ...receiptRow, transaction_id: transactionID, status: "manually_matched", match_method: "manual", lifecycle_version: 2 };
        return { rows: [receiptRow] };
      }
      if (compact.startsWith("INSERT INTO finance_receipt_matches")) return { rows: [] };
      if (compact.startsWith("INSERT INTO finance_receipt_lifecycle_audit")) {
        auditRow = {
          id: "723e4567-e89b-42d3-a456-426614174000",
          company_id: companyID,
          receipt_id: RECEIPT_ID,
          version: 2,
          action: "matched",
          reason: request.reason,
          client_request_id: REQUEST_ID,
          request_fingerprint: request.request_fingerprint,
          before_state: {},
          after_state: {}
        };
        assert.equal(params[2], 2);
        assert.equal(params[4], "matched");
        return { rows: [auditRow] };
      }
      throw new Error(`Unexpected query: ${compact}`);
    },
    release() {}
  };
  const pool = { async connect() { return client; } };
  const first = await executeReceiptLifecycleTransition(pool, { companyID, actorUserID: userID, request });
  const retry = await executeReceiptLifecycleTransition(pool, { companyID, actorUserID: userID, request });
  assert.equal(first.replayed, false);
  assert.equal(first.receipt.lifecycle_version, 2);
  assert.equal(retry.replayed, true);
  assert.equal(queries.filter((sql) => sql.startsWith("UPDATE finance_receipts")).length, 1);
  assert.equal(queries.filter((sql) => sql.startsWith("INSERT INTO finance_receipt_matches")).length, 1);
  assert.equal(queries.filter((sql) => sql.startsWith("INSERT INTO finance_receipt_lifecycle_audit")).length, 1);
  assert.equal(queries.filter((sql) => sql === "COMMIT").length, 2);
});

test("cash receipt purchase creates one transaction and exact retry is balance safe", async () => {
  const companyID = "423e4567-e89b-42d3-a456-426614174000";
  const userID = "523e4567-e89b-42d3-a456-426614174000";
  const accountID = "623e4567-e89b-42d3-a456-426614174000";
  const transactionID = "723e4567-e89b-42d3-a456-426614174000";
  const request = normalizeReceiptLifecycleRequest({
    receiptID: RECEIPT_ID,
    body: {
      client_request_id: REQUEST_ID,
      expected_lifecycle_version: 1,
      action: "cash_purchase",
      account_id: accountID,
      expected_account_balance_cents: 5000,
      amount_cents: 1200,
      finance_category: "Supplies",
      reason: "Paid from the shop cash box"
    }
  });
  let receiptRow = {
    id: RECEIPT_ID,
    company_id: companyID,
    status: "unmatched",
    transaction_id: null,
    object_key: `receipts/${companyID}/${RECEIPT_ID}/image.jpg`,
    lifecycle_version: 1,
    amount_cents: 1200,
    finance_category: "Supplies",
    currency: "usd",
    merchant_name: "Supply Store",
    purchase_date: "2026-08-19"
  };
  const transactionRow = { id: transactionID, company_id: companyID, account_id: accountID, amount_cents: 1200 };
  let auditRow = null;
  const queries = [];
  const client = {
    async query(sql, params = []) {
      const compact = sql.replace(/\s+/g, " ").trim();
      queries.push(compact);
      if (["BEGIN", "COMMIT", "ROLLBACK"].includes(compact) || compact.includes("pg_advisory_xact_lock")) return { rows: [] };
      if (compact.includes("FROM finance_receipt_lifecycle_audit") && compact.includes("client_request_id")) return { rows: auditRow ? [auditRow] : [] };
      if (compact.startsWith("SELECT r.*")) return { rows: [receiptRow] };
      if (compact.startsWith("SELECT * FROM finance_accounts")) return { rows: [{ id: accountID, currency: "usd", current_balance_cents: 5000 }] };
      if (compact.startsWith("INSERT INTO finance_transactions")) return { rows: [transactionRow] };
      if (compact.startsWith("UPDATE finance_accounts") || compact.startsWith("INSERT INTO finance_account_entries") || compact.startsWith("INSERT INTO finance_receipt_matches")) return { rows: [] };
      if (compact.startsWith("UPDATE finance_receipts")) {
        receiptRow = { ...receiptRow, status: "cash_purchase", transaction_id: transactionID, match_method: "cash_purchase", match_confidence: 100, lifecycle_version: 2 };
        return { rows: [receiptRow] };
      }
      if (compact.startsWith("INSERT INTO finance_receipt_lifecycle_audit")) {
        auditRow = {
          id: "823e4567-e89b-42d3-a456-426614174000",
          company_id: companyID,
          receipt_id: RECEIPT_ID,
          version: 2,
          action: "cash_purchase_created",
          reason: request.reason,
          client_request_id: REQUEST_ID,
          request_fingerprint: request.request_fingerprint,
          before_state: {},
          after_state: { transaction_id: transactionID, account_id: accountID, account_balance_cents: 3800 }
        };
        return { rows: [auditRow] };
      }
      if (compact.startsWith("SELECT * FROM finance_transactions")) return { rows: [transactionRow] };
      throw new Error(`Unexpected query: ${compact}`);
    },
    release() {}
  };
  const pool = { async connect() { return client; } };
  const first = await createReceiptCashPurchase({ pool, companyID, actorUserID: userID, request });
  const retry = await createReceiptCashPurchase({ pool, companyID, actorUserID: userID, request });
  assert.equal(first.account_balance_cents, 3800);
  assert.equal(retry.replayed, true);
  assert.equal(retry.account_balance_cents, 3800);
  assert.equal(queries.filter((sql) => sql.startsWith("INSERT INTO finance_transactions")).length, 1);
  assert.equal(queries.filter((sql) => sql.startsWith("UPDATE finance_accounts")).length, 1);
  assert.equal(queries.filter((sql) => sql.startsWith("INSERT INTO finance_account_entries")).length, 1);
});

test("cash receipt purchase rejects a balance changed after confirmation", async () => {
  const companyID = "423e4567-e89b-42d3-a456-426614174000";
  const accountID = "623e4567-e89b-42d3-a456-426614174000";
  const request = normalizeReceiptLifecycleRequest({
    receiptID: RECEIPT_ID,
    body: {
      client_request_id: REQUEST_ID,
      expected_lifecycle_version: 1,
      action: "cash_purchase",
      account_id: accountID,
      expected_account_balance_cents: 5000,
      amount_cents: 1200,
      finance_category: "Supplies",
      reason: "Paid from the shop cash box"
    }
  });
  const queries = [];
  const client = {
    async query(sql) {
      const compact = sql.replace(/\s+/g, " ").trim();
      queries.push(compact);
      if (["BEGIN", "ROLLBACK"].includes(compact) || compact.includes("pg_advisory_xact_lock")) return { rows: [] };
      if (compact.includes("FROM finance_receipt_lifecycle_audit")) return { rows: [] };
      if (compact.startsWith("SELECT r.*")) return { rows: [{
        id: RECEIPT_ID, company_id: companyID, status: "unmatched", transaction_id: null,
        object_key: "receipts/image.jpg", lifecycle_version: 1, amount_cents: 1200,
        finance_category: "Supplies", currency: "usd"
      }] };
      if (compact.startsWith("SELECT * FROM finance_accounts")) {
        return { rows: [{ id: accountID, currency: "usd", current_balance_cents: 4900 }] };
      }
      throw new Error(`Unexpected query: ${compact}`);
    },
    release() {}
  };
  await assert.rejects(
    () => createReceiptCashPurchase({ pool: { async connect() { return client; } }, companyID, actorUserID: null, request }),
    (error) => error.code === "receipt_cash_account_stale"
  );
  assert.equal(queries.some((sql) => sql.startsWith("INSERT INTO finance_transactions")), false);
  assert.equal(queries.filter((sql) => sql === "ROLLBACK").length, 1);
});

test("receipt detail edits normalize an exact clearable replacement document", () => {
  const request = normalizeReceiptDetailEditRequest({
    receiptID: RECEIPT_ID,
    body: {
      client_request_id: REQUEST_ID,
      expected_details_version: 3,
      merchant_name: "  Main Street Grill  ",
      purchase_date: "2026-08-19",
      purchase_time: "14:05",
      amount_cents: "5294",
      subtotal_cents: null,
      tax_cents: 294,
      tip_cents: 500,
      currency: "USD",
      address: "",
      city: "Louisville",
      state: "KY",
      postal_code: null,
      country: "",
      payment_method_text: "Visa",
      card_last_four: "1234",
      finance_category: "Meals",
      business_use: "business",
      note: "Team lunch",
      reason: "Corrected the OCR total and category"
    }
  });
  assert.equal(request.details.merchant_name, "Main Street Grill");
  assert.equal(request.details.amount_cents, 5294);
  assert.equal(request.details.subtotal_cents, null);
  assert.equal(request.details.address, null);
  assert.equal(request.details.country, null);
  assert.equal(request.details.currency, "usd");
  assert.equal(request.expected_details_version, 3);
  assert.match(request.request_fingerprint, /^[0-9a-f]{64}$/);
  assert.equal(request.request_fingerprint, receiptDetailFingerprint({
    receipt_id: request.receipt_id,
    client_request_id: request.client_request_id,
    expected_details_version: request.expected_details_version,
    details: request.details,
    reason: request.reason
  }));
});

test("receipt detail edits reject malformed dates times money cards versions and reasons", () => {
  const valid = {
    client_request_id: REQUEST_ID,
    expected_details_version: 1,
    currency: "usd",
    business_use: "unknown",
    reason: "Correction"
  };
  const rejects = [
    [{ ...valid, purchase_date: "2026-02-30" }, "purchase_date_invalid"],
    [{ ...valid, purchase_time: "24:00" }, "purchase_time_invalid"],
    [{ ...valid, amount_cents: -1 }, "amount_cents_invalid"],
    [{ ...valid, amount_cents: Number.MAX_SAFE_INTEGER + 1 }, "amount_cents_invalid"],
    [{ ...valid, card_last_four: "12x4" }, "card_last_four_invalid"],
    [{ ...valid, business_use: "mostly" }, "business_use_invalid"],
    [{ ...valid, currency: "US" }, "currency_invalid"],
    [{ ...valid, expected_details_version: 0 }, "expected_details_version_invalid"],
    [{ ...valid, reason: "" }, "receipt_detail_reason_required"]
  ];
  for (const [body, code] of rejects) {
    assert.throws(
      () => normalizeReceiptDetailEditRequest({ receiptID: RECEIPT_ID, body }),
      (error) => error.code === code
    );
  }
});

test("receipt detail diffs are stable and audit snapshots minimize sensitive evidence", () => {
  const before = receiptDetailDocument({
    merchant_name: "Store", purchase_date: "2026-08-19", amount_cents: "1000",
    currency: "usd", country: "US", finance_category: "Other", business_use: "unknown",
    address: "1 Main St", payment_method_text: "Visa", card_last_four: "1234", note: "Private note"
  });
  const after = { ...before, amount_cents: 1200, address: null, note: null };
  assert.deepEqual(receiptDetailChangedFields(before, after), ["amount_cents", "address", "note"]);
  const snapshot = receiptDetailAuditSnapshot(before);
  assert.equal(snapshot.amount_cents, 1000);
  assert.equal(snapshot.address_present, true);
  assert.equal(snapshot.card_last_four_present, true);
  assert.equal(snapshot.note_present, true);
  assert.equal(Object.hasOwn(snapshot, "address"), false);
  assert.equal(Object.hasOwn(snapshot, "note"), false);
  assert.equal(Object.hasOwn(snapshot, "card_last_four"), false);
  assert.equal(JSON.stringify(snapshot).includes("Private note"), false);
  assert.deepEqual(receiptDetailChangedFields(before, { ...before }), []);
});

test("receipt detail route commits one audit, replays identically, and rolls stale edits back", async () => {
  const companyID = "323e4567-e89b-42d3-a456-426614174000";
  const userID = "423e4567-e89b-42d3-a456-426614174000";
  const body = {
    client_request_id: REQUEST_ID,
    expected_details_version: 1,
    merchant_name: "Corrected Store",
    purchase_date: "2026-08-19",
    amount_cents: 1200,
    currency: "usd",
    country: "US",
    finance_category: "Supplies",
    business_use: "business",
    reason: "Corrected the captured total"
  };
  const normalized = normalizeReceiptDetailEditRequest({ receiptID: RECEIPT_ID, body });
  const baseReceipt = {
    id: RECEIPT_ID,
    company_id: companyID,
    status: "unmatched",
    object_key: `receipts/${companyID}/${RECEIPT_ID}/image.jpg`,
    details_version: 1,
    merchant_name: "Store",
    purchase_date: "2026-08-19",
    amount_cents: 1000,
    currency: "usd",
    country: "US",
    finance_category: "Other",
    business_use: "unknown"
  };

  async function invoke({ receiptRow, replayAudit = null, requestBody = body }) {
    const handlers = new Map();
    const app = {};
    for (const method of ["get", "post", "patch", "put"]) {
      app[method] = (path, ...middleware) => handlers.set(`${method.toUpperCase()} ${path}`, middleware.at(-1));
    }
    const queries = [];
    const client = {
      async query(sql, params = []) {
        const compact = sql.replace(/\s+/g, " ").trim();
        queries.push({ sql: compact, params });
        if (compact === "BEGIN" || compact === "COMMIT" || compact === "ROLLBACK") return { rows: [] };
        if (compact.includes("pg_advisory_xact_lock")) return { rows: [{}] };
        if (compact.includes("FROM finance_receipt_detail_audit") && compact.includes("client_request_id")) {
          return { rows: replayAudit ? [replayAudit] : [] };
        }
        if (compact.startsWith("SELECT r.*")) return { rows: [receiptRow] };
        if (compact.startsWith("UPDATE finance_receipts")) {
          assert.equal(params[6], 1200);
          assert.equal(params[21], 2);
          return { rows: [{ ...receiptRow, merchant_name: "Corrected Store", amount_cents: 1200, details_version: 2 }] };
        }
        if (compact.startsWith("INSERT INTO finance_receipt_detail_audit")) {
          return { rows: [{
            id: "523e4567-e89b-42d3-a456-426614174000",
            receipt_id: RECEIPT_ID,
            version: 2,
            action: "details_replaced",
            reason: body.reason,
            changed_fields: ["merchant_name", "amount_cents", "finance_category", "business_use"],
            actor_user_id: userID,
            created_at: "2026-08-19T20:00:00Z"
          }] };
        }
        throw new Error(`Unexpected query: ${compact}`);
      },
      release() { queries.push({ sql: "RELEASE", params: [] }); }
    };
    const pool = { async connect() { return client; } };
    await installReceiptRoutes({ app, pool, authRequired() {}, requireEmployer() {} });
    const response = {
      statusCode: 200,
      body: null,
      status(code) { this.statusCode = code; return this; },
      json(value) { this.body = value; return this; }
    };
    await handlers.get("PUT /api/finance/receipts/:id/details")({
      companyId: companyID,
      userId: userID,
      params: { id: RECEIPT_ID },
      body: requestBody
    }, response);
    return { response, queries };
  }

  const committed = await invoke({ receiptRow: baseReceipt });
  assert.equal(committed.response.statusCode, 200);
  assert.equal(committed.response.body.replayed, false);
  assert.equal(committed.response.body.receipt.details_version, 2);
  assert.ok(committed.queries.findIndex((item) => item.sql.startsWith("UPDATE finance_receipts"))
    < committed.queries.findIndex((item) => item.sql.startsWith("INSERT INTO finance_receipt_detail_audit")));
  assert.ok(committed.queries.findIndex((item) => item.sql.startsWith("INSERT INTO finance_receipt_detail_audit"))
    < committed.queries.findIndex((item) => item.sql === "COMMIT"));
  assert.equal(committed.queries.some((item) => item.sql === "ROLLBACK"), false);

  const replayAudit = {
    id: "523e4567-e89b-42d3-a456-426614174000",
    receipt_id: RECEIPT_ID,
    version: 2,
    action: "details_replaced",
    reason: body.reason,
    changed_fields: ["merchant_name", "amount_cents", "finance_category", "business_use"],
    actor_user_id: userID,
    client_request_id: REQUEST_ID,
    request_fingerprint: normalized.request_fingerprint,
    created_at: "2026-08-19T20:00:00Z"
  };
  const replayed = await invoke({ receiptRow: { ...baseReceipt, details_version: 2 }, replayAudit });
  assert.equal(replayed.response.body.replayed, true);
  assert.equal(replayed.queries.some((item) => item.sql.startsWith("UPDATE finance_receipts")), false);
  assert.equal(replayed.queries.filter((item) => item.sql === "COMMIT").length, 1);

  const stale = await invoke({ receiptRow: { ...baseReceipt, details_version: 2 } });
  assert.equal(stale.response.statusCode, 409);
  assert.equal(stale.response.body.error, "receipt_details_stale");
  assert.equal(stale.queries.some((item) => item.sql.startsWith("UPDATE finance_receipts")), false);
  assert.equal(stale.queries.filter((item) => item.sql === "ROLLBACK").length, 1);
});

test("receipt detail schema is additive tenant scoped versioned and append only", async () => {
  const calls = [];
  await installReceiptSchema({ async query(sql) { calls.push(sql); return { rows: [] }; } });
  const sql = calls.join("\n");
  assert.match(sql, /ADD COLUMN IF NOT EXISTS details_version/);
  assert.match(sql, /finance_receipts_details_version_positive CHECK\(details_version > 0\)/);
  assert.match(sql, /CREATE TABLE IF NOT EXISTS finance_receipt_detail_audit/);
  assert.match(sql, /ADD COLUMN IF NOT EXISTS lifecycle_version/);
  assert.match(sql, /finance_receipts_lifecycle_version_positive CHECK\(lifecycle_version > 0\)/);
  assert.match(sql, /ADD COLUMN IF NOT EXISTS archived_from_status/);
  assert.match(sql, /CREATE TABLE IF NOT EXISTS finance_receipt_lifecycle_audit/);
  assert.match(sql, /provider_history_unmatched/);
  assert.match(sql, /cash_purchase_created/);
  assert.match(sql, /UNIQUE\(company_id, receipt_id, version\)/);
  assert.match(sql, /UNIQUE\(company_id, client_request_id\)/);
  assert.match(sql, /FOREIGN KEY \(company_id, receipt_id\)/);
  assert.doesNotMatch(sql, /DROP TABLE|TRUNCATE/);
});

test("receipt routes expose bounded detail audit and stale safe replacement", () => {
  const routes = [];
  const app = {
    get(path) { routes.push(["GET", path]); },
    post(path) { routes.push(["POST", path]); },
    patch(path) { routes.push(["PATCH", path]); },
    put(path) { routes.push(["PUT", path]); }
  };
  installReceiptRoutes({ app, pool: {}, authRequired() {}, requireEmployer() {} });
  assert.ok(routes.some(([method, path]) => method === "GET" && path === "/api/finance/receipts/:id/detail-audit"));
  assert.ok(routes.some(([method, path]) => method === "PUT" && path === "/api/finance/receipts/:id/details"));
  assert.ok(routes.some(([method, path]) => method === "GET" && path === "/api/finance/receipts/:id/lifecycle-audit"));
  assert.ok(routes.some(([method, path]) => method === "POST" && path === "/api/finance/receipts/:id/lifecycle"));
  const source = fs.readFileSync(new URL("../finance-receipts.js", import.meta.url), "utf8");
  assert.match(source, /FOR UPDATE OF r/);
  assert.match(source, /receipt_details_stale/);
  assert.match(source, /receipt_details_unchanged/);
  assert.match(source, /receipt_details_cash_purchase_locked/);
  assert.match(source, /client_request_id=\$2::uuid/);
  assert.match(source, /receipt_details_audited_route_required/);
  assert.match(source, /current\.status === "processing_failed" \|\| !current\.object_key/);
  assert.match(source, /status IN \('processing','processing_failed'\) OR \(object_key IS NULL AND details_version=1\)/);
  assert.match(source, /createReceiptCashPurchase/);
  assert.match(source, /receipt_cash_purchase_amount_mismatch/);
  assert.match(source, /receipt_cash_purchase_category_mismatch/);
  assert.match(source, /filter === "archived"/);
  assert.match(source, /filter === "matched"\) conditions\.push\("r\.archived_at IS NULL AND r\.transaction_id IS NOT NULL"\)/);
  const aiSource = fs.readFileSync(new URL("../finance-ai.js", import.meta.url), "utf8");
  assert.match(aiSource, /replaceReceiptDetails/);
  assert.match(aiSource, /executeReceiptLifecycleTransition/);
  assert.match(aiSource, /createReceiptCashPurchase/);
  assert.doesNotMatch(aiSource, /UPDATE finance_receipts/);
  assert.doesNotMatch(aiSource, /INSERT INTO finance_receipt_matches/);
  const matchingSource = fs.readFileSync(new URL("../finance-receipt-matching.js", import.meta.url), "utf8");
  assert.match(matchingSource, /executeReceiptLifecycleTransition/);
  assert.match(matchingSource, /auditAction: "auto_matched"/);
});

let passed = 0;
for (const item of tests) {
  try {
    await item.fn();
    passed += 1;
    console.log(`PASS ${item.name}`);
  } catch (error) {
    console.error(`FAIL ${item.name}`);
    console.error(error);
    process.exitCode = 1;
    break;
  }
}

if (!process.exitCode) console.log(`PASS finance receipt matching (${passed}/${tests.length})`);
