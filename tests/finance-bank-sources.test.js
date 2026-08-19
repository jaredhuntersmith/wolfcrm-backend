import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {
  buildBankJournalInput,
  buildBankReversalInput,
  evaluateBankTransactionSource,
  normalizeBankPostingRequest,
  normalizeFinanceAccountMapping,
  parseBankSourceRange
} from "../finance-bank-sources.js";

const IDs = {
  transaction: "00000000-0000-4000-8000-000000000001",
  financeAccount: "00000000-0000-4000-8000-000000000002",
  mapping: "00000000-0000-4000-8000-000000000003",
  cash: "00000000-0000-4000-8000-000000000004",
  revenue: "00000000-0000-4000-8000-000000000005",
  otherRevenue: "00000000-0000-4000-8000-000000000006",
  expense: "00000000-0000-4000-8000-000000000007",
  liability: "00000000-0000-4000-8000-000000000008",
  request: "00000000-0000-4000-8000-000000000009",
  journal: "00000000-0000-4000-8000-00000000000a"
};

function bundle(overrides = {}) {
  const transaction = {
    id: IDs.transaction,
    account_id: IDs.financeAccount,
    source: "plaid",
    status: "posted",
    direction: "income",
    amount_cents: 10_000,
    transaction_date: "2026-08-18",
    pending: false,
    removed_at: null,
    reconciliation_status: "reconciled",
    accounting_version: 3,
    iso_currency_code: "USD",
    ...overrides.transaction
  };
  const financeAccount = {
    id: IDs.financeAccount,
    name: "Checking",
    source: "plaid",
    account_type: "checking",
    currency: "usd",
    ...overrides.financeAccount
  };
  const mapping = overrides.mapping === null ? null : {
    id: IDs.mapping,
    finance_account_id: IDs.financeAccount,
    chart_account_id: IDs.cash,
    version: 2,
    reason: "Reviewed bank mapping",
    ...overrides.mapping
  };
  const chartAccount = overrides.chartAccount === null ? null : {
    id: IDs.cash,
    code: "1010",
    name: "Operating Checking",
    account_type: "asset",
    active: true,
    ...overrides.chartAccount
  };
  const splits = overrides.splits || [
    { chart_account_id: IDs.revenue, account_type: "income", active: true, amount_cents: 6_000, memo: "Service" },
    { chart_account_id: IDs.otherRevenue, account_type: "income", active: true, amount_cents: 4_000, memo: null }
  ];
  return {
    transaction,
    financeAccount,
    mapping,
    chartAccount,
    splits,
    providerRefs: overrides.providerRefs || [{ provider: "plaid", provider_transaction_id: "posted-1", is_current: true }],
    posting: overrides.posting || null,
    activeTransferMembership: overrides.activeTransferMembership || null,
    activeOperationalReceivableAuthorityCount: overrides.activeOperationalReceivableAuthorityCount || 0
  };
}

test("Finance account mapping is versioned, typed, exact, and replay-fingerprinted", () => {
  const financeAccount = bundle().financeAccount;
  const chart = [bundle().chartAccount, { id: IDs.revenue, account_type: "income", active: true }];
  const created = normalizeFinanceAccountMapping({
    body: { client_request_id: IDs.request, expected_version: 0, chart_account_id: IDs.cash, reason: "Reviewed mapping" },
    financeAccount,
    chartAccounts: chart
  });
  assert.equal(created.changed, true);
  assert.equal(created.next_version, 1);
  assert.equal(created.request_fingerprint.length, 64);

  const reviewed = normalizeFinanceAccountMapping({
    body: { client_request_id: IDs.request, expected_version: 2, chart_account_id: IDs.cash, reason: "Reviewed mapping" },
    financeAccount,
    currentMapping: bundle().mapping,
    chartAccounts: chart
  });
  assert.equal(reviewed.changed, false);
  assert.equal(reviewed.next_version, 2);

  assert.throws(() => normalizeFinanceAccountMapping({
    body: { client_request_id: IDs.request, expected_version: 1, chart_account_id: IDs.cash, reason: "Reviewed mapping" },
    financeAccount,
    currentMapping: bundle().mapping,
    chartAccounts: chart
  }), (error) => error.code === "finance_account_mapping_stale" && error.current_version === 2);
  const replayCandidate = normalizeFinanceAccountMapping({
    body: { client_request_id: IDs.request, expected_version: 1, chart_account_id: IDs.cash, reason: "Reviewed mapping" },
    financeAccount,
    currentMapping: bundle().mapping,
    chartAccounts: [],
    checkVersion: false,
    validateChart: false
  });
  assert.equal(replayCandidate.current_version, 2);
  assert.equal(replayCandidate.expected_version, 1);
  assert.throws(() => normalizeFinanceAccountMapping({
    body: { client_request_id: IDs.request, expected_version: 0, chart_account_id: IDs.revenue, reason: "Bad type" },
    financeAccount,
    chartAccounts: chart
  }), (error) => error.code === "mapping_chart_account_type_invalid");
});

test("reviewed money-in bank source debits mapped asset and credits exact income allocations", () => {
  const result = evaluateBankTransactionSource(bundle());
  assert.equal(result.eligible, true);
  assert.equal(result.review_state, "ready");
  assert.equal(result.journal_preview.total_debits_cents, 10_000);
  assert.equal(result.journal_preview.total_credits_cents, 10_000);
  assert.deepEqual(result.journal_preview.lines.map((line) => [line.chart_account_id, line.debit_cents, line.credit_cents]), [
    [IDs.cash, 10_000, 0],
    [IDs.revenue, 0, 6_000],
    [IDs.otherRevenue, 0, 4_000]
  ]);
});

test("reviewed credit-card charge debits expense and credits mapped liability", () => {
  const result = evaluateBankTransactionSource(bundle({
    transaction: { direction: "expense", amount_cents: 2_500 },
    financeAccount: { account_type: "other", plaid_account_type: "credit" },
    mapping: { chart_account_id: IDs.liability },
    chartAccount: { id: IDs.liability, account_type: "liability" },
    splits: [{ chart_account_id: IDs.expense, account_type: "expense", active: true, amount_cents: 2_500, memo: "Materials" }]
  }));
  assert.equal(result.eligible, true);
  assert.deepEqual(result.journal_preview.lines.map((line) => [line.chart_account_id, line.debit_cents, line.credit_cents]), [
    [IDs.expense, 2_500, 0],
    [IDs.liability, 0, 2_500]
  ]);
});

test("unreviewed, unmapped, non-P&L, non-USD, and removed sources fail closed with visible blockers", () => {
  const result = evaluateBankTransactionSource(bundle({
    transaction: { reconciliation_status: "cleared", removed_at: "2026-08-19T00:00:00Z", iso_currency_code: "CAD" },
    financeAccount: { currency: "cad" },
    mapping: null,
    chartAccount: null,
    splits: [{ chart_account_id: IDs.cash, account_type: "asset", active: true, amount_cents: 10_000 }]
  }));
  const codes = new Set(result.blockers.map((item) => item.code));
  assert.equal(result.eligible, false);
  assert.equal(result.review_state, "blocked");
  assert.deepEqual(codes, new Set([
    "transaction_removed",
    "transaction_not_reconciled",
    "transaction_currency_unsupported",
    "finance_account_unmapped",
    "transaction_non_profit_loss"
  ]));
});

test("an active transfer pair prevents a second individual source journal", () => {
  const result = evaluateBankTransactionSource(bundle({
    activeTransferMembership: { pair_id: "00000000-0000-4000-8000-00000000000b", role: "inflow" }
  }));
  assert.equal(result.eligible, false);
  assert.ok(result.blockers.some((item) => item.code === "transaction_active_transfer_pair"));
  assert.equal(result.source_snapshot.active_transfer_pair_id, "00000000-0000-4000-8000-00000000000b");
});

test("active completed-job revenue blocks bank income but not a reviewed bank expense", () => {
  const income = evaluateBankTransactionSource(bundle({ activeOperationalReceivableAuthorityCount: 2 }));
  assert.equal(income.eligible, false);
  assert.ok(income.blockers.some((item) => item.code === "operational_receivable_authority_active"));
  assert.equal(income.source_snapshot.active_operational_receivable_authority_count, 2);

  const expense = evaluateBankTransactionSource(bundle({
    activeOperationalReceivableAuthorityCount: 2,
    transaction: { direction: "expense", amount_cents: 2_500 },
    mapping: { chart_account_id: IDs.liability },
    chartAccount: { id: IDs.liability, account_type: "liability" },
    splits: [{ chart_account_id: IDs.expense, account_type: "expense", active: true, amount_cents: 2_500 }]
  }));
  assert.equal(expense.eligible, true);
});

test("source fingerprint changes for provider, accounting, mapping, and removal evidence", () => {
  const base = evaluateBankTransactionSource(bundle()).source_fingerprint;
  assert.notEqual(base, evaluateBankTransactionSource(bundle({ providerRefs: [{ provider: "plaid", provider_transaction_id: "posted-2", is_current: true }] })).source_fingerprint);
  assert.notEqual(base, evaluateBankTransactionSource(bundle({ transaction: { accounting_version: 4 } })).source_fingerprint);
  assert.notEqual(base, evaluateBankTransactionSource(bundle({ mapping: { version: 3 } })).source_fingerprint);
  assert.notEqual(base, evaluateBankTransactionSource(bundle({ transaction: { removed_at: "2026-08-19T00:00:00Z" } })).source_fingerprint);
  assert.notEqual(base, evaluateBankTransactionSource(bundle({ activeOperationalReceivableAuthorityCount: 1 })).source_fingerprint);

  const current = evaluateBankTransactionSource(bundle({ posting: { status: "posted", version: 1, source_fingerprint: base, journal_entry_id: IDs.journal } }));
  assert.equal(current.review_state, "posted");
  assert.equal(current.source_current, true);
  const stale = evaluateBankTransactionSource(bundle({ transaction: { accounting_version: 4 }, posting: { status: "posted", version: 1, source_fingerprint: base, journal_entry_id: IDs.journal } }));
  assert.equal(stale.review_state, "stale");
  assert.equal(stale.can_void, true);
});

test("bank journal and exact reversal retain source identity and balance", () => {
  const evaluation = evaluateBankTransactionSource(bundle());
  const journal = buildBankJournalInput({
    evaluation,
    transactionID: IDs.transaction,
    postingVersion: 1,
    clientRequestID: IDs.request,
    reason: "Reviewed source"
  });
  assert.equal(journal.entry_kind, "bank_transaction");
  assert.equal(journal.source_type, "finance_transaction");
  assert.equal(journal.source_version, 1);
  assert.equal(journal.request_fingerprint.length, 64);

  const reversal = buildBankReversalInput({
    original: { ...journal, id: IDs.journal, entry_date: journal.entry_date, source_id: IDs.transaction },
    originalLines: journal.lines,
    transactionID: IDs.transaction,
    postingVersion: 2,
    clientRequestID: IDs.request,
    reason: "Correct changed source"
  });
  assert.equal(reversal.entry_kind, "reversal");
  assert.equal(reversal.reversal_of_entry_id, IDs.journal);
  assert.equal(reversal.source_version, 2);
  assert.deepEqual(reversal.lines.map((line) => [line.debit_cents, line.credit_cents]), journal.lines.map((line) => [line.credit_cents, line.debit_cents]));
});

test("posting requests and date ranges are strict and canonical", () => {
  const request = normalizeBankPostingRequest({
    body: {
      client_request_id: IDs.request,
      expected_accounting_version: 3,
      expected_mapping_version: 2,
      expected_posting_version: 0,
      reason: "Reviewed source"
    },
    transactionID: IDs.transaction,
    action: "post"
  });
  assert.equal(request.request_fingerprint.length, 64);
  assert.deepEqual(parseBankSourceRange("2026-01-01", "2026-08-19"), { start_date: "2026-01-01", end_date: "2026-08-19" });
  assert.throws(() => parseBankSourceRange("2026-08-20", "2026-08-19"), (error) => error.code === "bank_source_range_invalid");
  assert.throws(() => normalizeBankPostingRequest({ body: { ...request, reason: "" }, transactionID: IDs.transaction, action: "post" }), (error) => error.code === "bank_source_reason_required");
});

test("schema and routes are additive, tenant-linked, audited, and source preserving", () => {
  const source = fs.readFileSync(new URL("../finance-bank-sources.js", import.meta.url), "utf8");
  assert.match(source, /CREATE TABLE IF NOT EXISTS finance_account_chart_mappings/);
  assert.match(source, /CREATE TABLE IF NOT EXISTS finance_account_chart_mapping_audit/);
  assert.match(source, /CREATE TABLE IF NOT EXISTS finance_bank_transaction_postings/);
  assert.match(source, /CREATE TABLE IF NOT EXISTS finance_bank_transaction_posting_audit/);
  assert.match(source, /FOREIGN KEY \(company_id, finance_transaction_id\)/);
  assert.match(source, /UNIQUE\(company_id, client_request_id\)/);
  assert.match(source, /bank-sources\/transactions\/:transactionId\/post/);
  assert.match(source, /bank-sources\/transactions\/:transactionId\/void/);
  assert.match(source, /Re-check after locking so identical retries remain idempotent/);
  assert.match(source, /operational_receivable_authority_active/);
  assert.match(source, /SELECT id FROM companies WHERE id=\$1 FOR UPDATE/);
  assert.doesNotMatch(source, /UPDATE finance_transactions\s+SET/);
  assert.doesNotMatch(source, /DELETE FROM finance_transactions/);
  assert.doesNotMatch(source, /UPDATE finance_transaction_splits\s+SET/);
});
