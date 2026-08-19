import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {
  buildTransferJournalInput,
  buildTransferReversalInput,
  evaluateBankTransferCandidate,
  evaluateBankTransferPair,
  installFinanceBankTransferRoutes,
  normalizeTransferActionRequest,
  normalizeTransferCreateRequest,
  parseBankTransferRange
} from "../finance-bank-transfers.js";

const IDs = {
  outflowTransaction: "00000000-0000-4000-8000-000000000001",
  inflowTransaction: "00000000-0000-4000-8000-000000000002",
  outflowAccount: "00000000-0000-4000-8000-000000000003",
  inflowAccount: "00000000-0000-4000-8000-000000000004",
  outflowMapping: "00000000-0000-4000-8000-000000000005",
  inflowMapping: "00000000-0000-4000-8000-000000000006",
  outflowChart: "00000000-0000-4000-8000-000000000007",
  inflowChart: "00000000-0000-4000-8000-000000000008",
  pair: "00000000-0000-4000-8000-000000000009",
  request: "00000000-0000-4000-8000-00000000000a",
  journal: "00000000-0000-4000-8000-00000000000b"
};

function side(role, overrides = {}) {
  const outflow = role === "outflow";
  const transactionID = outflow ? IDs.outflowTransaction : IDs.inflowTransaction;
  const financeAccountID = outflow ? IDs.outflowAccount : IDs.inflowAccount;
  const mappingID = outflow ? IDs.outflowMapping : IDs.inflowMapping;
  const chartID = outflow ? IDs.outflowChart : IDs.inflowChart;
  const counterChartID = outflow ? IDs.inflowChart : IDs.outflowChart;
  return {
    transaction: {
      id: transactionID,
      account_id: financeAccountID,
      source: "plaid",
      status: "posted",
      direction: outflow ? "expense" : "income",
      amount_cents: 25_000,
      transaction_date: outflow ? "2026-08-17" : "2026-08-18",
      pending: false,
      removed_at: null,
      reconciliation_status: "reconciled",
      accounting_version: 3,
      iso_currency_code: "USD",
      ...overrides.transaction
    },
    financeAccount: {
      id: financeAccountID,
      name: outflow ? "Operating Checking" : "Savings",
      source: "plaid",
      account_type: "checking",
      currency: "usd",
      ...overrides.financeAccount
    },
    mapping: overrides.mapping === null ? null : {
      id: mappingID,
      finance_account_id: financeAccountID,
      chart_account_id: chartID,
      version: 2,
      reason: "Reviewed mapping",
      ...overrides.mapping
    },
    chartAccount: overrides.chartAccount === null ? null : {
      id: chartID,
      code: outflow ? "1010" : "1020",
      name: outflow ? "Operating Checking" : "Savings",
      account_type: "asset",
      active: true,
      ...overrides.chartAccount
    },
    splits: overrides.splits || [{
      chart_account_id: counterChartID,
      code: outflow ? "1020" : "1010",
      name: outflow ? "Savings" : "Operating Checking",
      account_type: "asset",
      active: true,
      amount_cents: 25_000
    }],
    providerRefs: overrides.providerRefs || [{
      provider: "plaid",
      provider_transaction_id: outflow ? "plaid-out" : "plaid-in",
      is_current: true
    }],
    activeMembership: overrides.activeMembership || null,
    bankPosting: overrides.bankPosting || null
  };
}

test("a reconciled transfer side is exact, mapped, and fully allocated", () => {
  const candidate = evaluateBankTransferCandidate(side("outflow"));
  assert.equal(candidate.role, "outflow");
  assert.equal(candidate.eligible, true);
  assert.equal(candidate.blockers.length, 0);
  assert.equal(candidate.source_snapshot.amount_cents, 25_000);
});

test("an explicit pair produces one destination debit and one origin credit", () => {
  const result = evaluateBankTransferPair({ outflow: side("outflow"), inflow: side("inflow") });
  assert.equal(result.eligible, true);
  assert.equal(result.review_state, "ready");
  assert.equal(result.journal_preview.entry_date, "2026-08-18");
  assert.deepEqual(result.journal_preview.lines.map((line) => [line.chart_account_id, line.debit_cents, line.credit_cents]), [
    [IDs.inflowChart, 25_000, 0],
    [IDs.outflowChart, 0, 25_000]
  ]);
});

test("pairing fails closed for amount, counteraccount, reconciliation, and membership conflicts", () => {
  const result = evaluateBankTransferPair({
    outflow: side("outflow", {
      transaction: { reconciliation_status: "cleared" },
      activeMembership: { pair_id: "00000000-0000-4000-8000-00000000000c", role: "outflow" }
    }),
    inflow: side("inflow", {
      transaction: { amount_cents: 24_999 },
      splits: [{ chart_account_id: IDs.inflowChart, account_type: "asset", active: true, amount_cents: 24_999 }]
    })
  });
  const codes = new Set(result.blockers.map((item) => item.code));
  assert.equal(result.eligible, false);
  assert.ok(codes.has("outflow_transfer_not_reconciled"));
  assert.ok(codes.has("transfer_amount_mismatch"));
  assert.ok(codes.has("inflow_counteraccount_mismatch"));
  assert.ok(codes.has("outflow_already_paired"));
});

test("an individually posted bank source cannot also enter a transfer pair", () => {
  const result = evaluateBankTransferPair({
    outflow: side("outflow", {
      bankPosting: { id: IDs.journal, status: "posted", version: 1, journal_entry_id: IDs.journal }
    }),
    inflow: side("inflow")
  });
  assert.equal(result.eligible, false);
  assert.ok(result.blockers.some((item) => item.code === "outflow_transfer_source_posted_individually"));
  assert.equal(result.source_snapshot.outflow.individual_bank_posting.status, "posted");
});

test("source fingerprints detect changes and pair state distinguishes current, stale, and voided", () => {
  const outflow = side("outflow");
  const inflow = side("inflow");
  const base = evaluateBankTransferPair({ outflow, inflow });
  const current = evaluateBankTransferPair({
    outflow,
    inflow,
    pair: { id: IDs.pair, status: "posted", source_fingerprint: base.source_fingerprint }
  });
  assert.equal(current.review_state, "posted");
  assert.equal(current.source_current, true);
  const stale = evaluateBankTransferPair({
    outflow: side("outflow", { transaction: { accounting_version: 4 } }),
    inflow,
    pair: { id: IDs.pair, status: "posted", source_fingerprint: base.source_fingerprint }
  });
  assert.equal(stale.review_state, "stale");
  assert.equal(stale.can_post, true);
  assert.notEqual(stale.source_fingerprint, base.source_fingerprint);
  const voided = evaluateBankTransferPair({
    outflow,
    inflow,
    pair: { id: IDs.pair, status: "voided", source_fingerprint: base.source_fingerprint }
  });
  assert.equal(voided.review_state, "voided");
  assert.equal(voided.can_post, false);
});

test("transfer journal and exact reversal preserve pair authority", () => {
  const evaluation = evaluateBankTransferPair({ outflow: side("outflow"), inflow: side("inflow") });
  const journal = buildTransferJournalInput({
    evaluation,
    pairID: IDs.pair,
    version: 1,
    clientRequestID: IDs.request,
    reason: "Explicitly reviewed pair"
  });
  assert.equal(journal.entry_kind, "bank_transfer");
  assert.equal(journal.source_type, "finance_transfer_pair");
  assert.equal(journal.source_version, 1);
  const reversal = buildTransferReversalInput({
    original: { ...journal, id: IDs.journal },
    originalLines: journal.lines,
    pairID: IDs.pair,
    version: 2,
    clientRequestID: IDs.request,
    reason: "Correct pair"
  });
  assert.equal(reversal.reversal_of_entry_id, IDs.journal);
  assert.equal(reversal.source_type, "finance_transfer_pair");
  assert.deepEqual(reversal.lines.map((line) => [line.debit_cents, line.credit_cents]), journal.lines.map((line) => [line.credit_cents, line.debit_cents]));
});

test("create and action requests require exact optimistic versions and audit reasons", () => {
  const create = normalizeTransferCreateRequest({
    client_request_id: IDs.request,
    outflow_transaction_id: IDs.outflowTransaction,
    inflow_transaction_id: IDs.inflowTransaction,
    expected_outflow_accounting_version: 3,
    expected_inflow_accounting_version: 3,
    expected_outflow_mapping_version: 2,
    expected_inflow_mapping_version: 2,
    reason: "Explicitly paired"
  });
  assert.equal(create.request_fingerprint.length, 64);
  const action = normalizeTransferActionRequest({
    body: {
      client_request_id: IDs.request,
      expected_pair_version: 1,
      expected_outflow_accounting_version: 3,
      expected_inflow_accounting_version: 3,
      expected_outflow_mapping_version: 2,
      expected_inflow_mapping_version: 2,
      reason: "Re-review pair"
    },
    pairID: IDs.pair,
    action: "post"
  });
  assert.equal(action.expected_pair_version, 1);
  assert.deepEqual(parseBankTransferRange("2026-01-01", "2026-08-19"), { start_date: "2026-01-01", end_date: "2026-08-19" });
  assert.throws(() => parseBankTransferRange("2026-08-20", "2026-08-19"), (error) => error.code === "bank_transfer_range_invalid");
  assert.throws(() => normalizeTransferCreateRequest({ ...create, reason: "" }), (error) => error.code === "bank_transfer_reason_required");
});

test("schema, routes, locks, and source boundaries are explicit", () => {
  const source = fs.readFileSync(new URL("../finance-bank-transfers.js", import.meta.url), "utf8");
  assert.match(source, /CREATE TABLE IF NOT EXISTS finance_transfer_pairs/);
  assert.match(source, /CREATE TABLE IF NOT EXISTS finance_transfer_pair_members/);
  assert.match(source, /CREATE UNIQUE INDEX IF NOT EXISTS finance_transfer_pair_members_active_source_idx/);
  assert.match(source, /CREATE TABLE IF NOT EXISTS finance_transfer_pair_audit/);
  assert.match(source, /FOR UPDATE OF t, a/);
  assert.match(source, /FOR SHARE/);
  assert.doesNotMatch(source, /UPDATE finance_transactions\s+SET/);
  assert.doesNotMatch(source, /DELETE FROM finance_transactions/);
  const routes = [];
  installFinanceBankTransferRoutes({
    app: {
      get(path) { routes.push(["GET", path]); },
      post(path) { routes.push(["POST", path]); }
    },
    pool: {},
    authRequired: () => {},
    requireFinanceAccess: () => {},
    ensureChartAccounts: async () => {}
  });
  assert.deepEqual(routes, [
    ["GET", "/api/finance/accounting/transfers"],
    ["GET", "/api/finance/accounting/transfers/preview"],
    ["GET", "/api/finance/accounting/transfers/:pairId"],
    ["POST", "/api/finance/accounting/transfers"],
    ["POST", "/api/finance/accounting/transfers/:pairId/post"],
    ["POST", "/api/finance/accounting/transfers/:pairId/void"]
  ]);
});
