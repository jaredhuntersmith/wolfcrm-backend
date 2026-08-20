import assert from "node:assert/strict";
import fs from "node:fs";
import {
  balanceSheetChartSnapshot,
  buildStatementReadiness,
  evaluateBalanceSheetRules,
  evaluateStatementPeriodClose,
  evaluateOpeningCoverage,
  installFinanceStatementReadinessRoutes,
  installFinanceStatementReadinessSchema,
  normalizeBalanceSheetRuleReviewRequest,
  normalizeStatementCoverageArea,
  normalizeStatementCoverageProfileRequest,
  normalizeStatementPeriodCloseRequest,
  normalizeStatementWorkflowEvidence,
  statementReadinessFingerprint,
  summarizeBalanceSheetRows
} from "../finance-statement-readiness.js";

const REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000";
const JOURNAL_ID = "223e4567-e89b-42d3-a456-426614174000";

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

function request(overrides = {}) {
  return {
    client_request_id: REQUEST_ID,
    expected_version: 0,
    coverage_start_date: "2026-01-01",
    opening_balance_method: "company_inception_zero",
    opening_journal_entry_id: null,
    reason: "Reviewed company inception and retained sources",
    ...overrides
  };
}

function accounts() {
  return [
    { id: "cash", code: "1000", account_type: "asset", system_key: "cash" },
    { id: "loan", code: "2200", account_type: "liability", system_key: "loans_payable" },
    { id: "equity", code: "3200", account_type: "equity", system_key: "opening_balance_equity" }
  ];
}

function reviewedBalanceSheetRules(chartAccounts = [
  { id: "cash", code: "1000", name: "Cash", account_type: "asset", active: true, system_key: "cash" },
  { id: "equity", code: "3000", name: "Owner Equity", account_type: "equity", active: true, system_key: "owner_equity" },
  { id: "revenue", code: "4000", name: "Revenue", account_type: "income", active: true, system_key: "service_revenue" },
  { id: "expense", code: "5000", name: "Expense", account_type: "expense", active: true, system_key: "materials_supplies" }
]) {
  const provisional = {
    earnings_treatment: "cumulative_since_coverage_start",
    accountant_reviewed_on: "2026-08-18",
    accountant_reference: "CPA workpaper BS-1",
    accountant_review_confirmed: true,
    chart_fingerprint: "",
    evidence_fingerprint: ""
  };
  const chart = balanceSheetChartSnapshot(chartAccounts);
  provisional.chart_fingerprint = statementReadinessFingerprint(chart);
  provisional.evidence_fingerprint = statementReadinessFingerprint({
    earnings_treatment: provisional.earnings_treatment,
    accountant_reviewed_on: provisional.accountant_reviewed_on,
    accountant_reference: provisional.accountant_reference,
    accountant_review_confirmed: true,
    chart_fingerprint: provisional.chart_fingerprint,
    chart
  });
  return evaluateBalanceSheetRules({ profile: provisional, chartAccounts });
}

function openingJournal(overrides = {}) {
  return {
    id: JOURNAL_ID,
    entry_date: "2026-01-01",
    entry_kind: "opening_balance",
    source_type: "manual",
    reversed_by_entry_id: null,
    lines: [
      { chart_account_id: "cash", account_type: "asset", debit_cents: 10_000, credit_cents: 0 },
      { chart_account_id: "equity", account_type: "equity", debit_cents: 0, credit_cents: 10_000 }
    ],
    ...overrides
  };
}

test("coverage profile requests require exact date, method, journal identity, version, and reason", () => {
  const zero = normalizeStatementCoverageProfileRequest({ body: request(), companyToday: "2026-08-19" });
  assert.equal(zero.opening_balance_method, "company_inception_zero");
  assert.equal(zero.opening_journal_entry_id, null);
  assert.match(zero.request_fingerprint, /^[0-9a-f]{64}$/);

  const journal = normalizeStatementCoverageProfileRequest({
    body: request({ opening_balance_method: "reviewed_journal", opening_journal_entry_id: JOURNAL_ID }),
    companyToday: "2026-08-19"
  });
  assert.equal(journal.opening_journal_entry_id, JOURNAL_ID);

  assert.throws(() => normalizeStatementCoverageProfileRequest({
    body: request({ coverage_start_date: "2026-08-20" }), companyToday: "2026-08-19"
  }), (error) => error.code === "coverage_start_future");
  assert.throws(() => normalizeStatementCoverageProfileRequest({
    body: request({ opening_balance_method: "reviewed_journal" }), companyToday: "2026-08-19"
  }), (error) => error.code === "opening_journal_required");
  assert.throws(() => normalizeStatementCoverageProfileRequest({
    body: request({ opening_journal_entry_id: JOURNAL_ID }), companyToday: "2026-08-19"
  }), (error) => error.code === "opening_journal_not_allowed");
  assert.throws(() => normalizeStatementCoverageProfileRequest({
    body: request({ reason: "" }), companyToday: "2026-08-19"
  }), (error) => error.code === "statement_coverage_reason_required");
  assert.throws(() => normalizeStatementCoverageProfileRequest({
    body: request({ reason: "x".repeat(501) }), companyToday: "2026-08-19"
  }), (error) => error.code === "statement_coverage_reason_too_long");
});

test("period close requests require loaded versions, exact inventory identity, date, UUID, and reason", () => {
  const input = normalizeStatementPeriodCloseRequest({
    companyToday: "2026-08-19",
    body: {
      client_request_id: REQUEST_ID,
      expected_profile_version: 3,
      expected_close_version: 7,
      as_of_date: "2026-08-19",
      source_inventory_fingerprint: "a".repeat(64),
      reason: "Reviewed every current local source workflow"
    }
  });
  assert.equal(input.expected_profile_version, 3);
  assert.equal(input.expected_close_version, 7);
  assert.match(input.request_fingerprint, /^[0-9a-f]{64}$/);
  assert.throws(() => normalizeStatementPeriodCloseRequest({
    companyToday: "2026-08-19", body: { ...input, as_of_date: "2026-08-20" }
  }), (error) => error.code === "statement_as_of_future");
  assert.throws(() => normalizeStatementPeriodCloseRequest({
    companyToday: "2026-08-19", body: { ...input, source_inventory_fingerprint: "bad" }
  }), (error) => error.code === "source_inventory_fingerprint_invalid");
  assert.throws(() => normalizeStatementPeriodCloseRequest({
    companyToday: "2026-08-19", body: { ...input, reason: "" }
  }), (error) => error.code === "statement_period_close_reason_required");
});

test("company inception zero fails closed when retained activity predates the start", () => {
  const profile = {
    coverage_start_date: "2026-01-01",
    opening_balance_method: "company_inception_zero",
    evidence_fingerprint: null
  };
  const blocked = evaluateOpeningCoverage({
    profile,
    permanentAccounts: accounts(),
    earliestSourceDate: "2025-12-31"
  });
  assert.equal(blocked.status, "stale");
  assert.ok(blocked.blockers.some((item) => item.code === "opening_zero_has_prior_activity"));

  const review = evaluateOpeningCoverage({ profile, permanentAccounts: accounts(), earliestSourceDate: "2026-01-01" });
  const current = evaluateOpeningCoverage({
    profile: { ...profile, evidence_fingerprint: review.live_fingerprint },
    permanentAccounts: accounts(),
    earliestSourceDate: "2026-01-01"
  });
  assert.equal(current.status, "current");
  assert.equal(current.source_current, true);
});

test("reviewed opening journal requires exact date, permanent accounts, balance, and live fingerprint", () => {
  const baseProfile = {
    coverage_start_date: "2026-01-01",
    opening_balance_method: "reviewed_journal",
    opening_journal_entry_id: JOURNAL_ID,
    evidence_fingerprint: null
  };
  const review = evaluateOpeningCoverage({
    profile: baseProfile,
    permanentAccounts: accounts(),
    earliestSourceDate: "2024-01-01",
    journal: openingJournal()
  });
  assert.equal(review.blockers.length, 0);
  const current = evaluateOpeningCoverage({
    profile: { ...baseProfile, evidence_fingerprint: review.live_fingerprint },
    permanentAccounts: accounts(),
    earliestSourceDate: "2024-01-01",
    journal: openingJournal()
  });
  assert.equal(current.source_current, true);

  const changedChart = evaluateOpeningCoverage({
    profile: { ...baseProfile, evidence_fingerprint: review.live_fingerprint },
    permanentAccounts: [...accounts(), { id: "card", code: "2100", account_type: "liability", system_key: null }],
    earliestSourceDate: "2024-01-01",
    journal: openingJournal()
  });
  assert.ok(changedChart.blockers.some((item) => item.code === "opening_evidence_changed"));

  const reversed = evaluateOpeningCoverage({
    profile: baseProfile,
    permanentAccounts: accounts(),
    journal: openingJournal({ reversed_by_entry_id: "reversal" })
  });
  assert.ok(reversed.blockers.some((item) => item.code === "opening_journal_reversed"));
  const income = evaluateOpeningCoverage({
    profile: baseProfile,
    permanentAccounts: accounts(),
    journal: openingJournal({ lines: [
      { chart_account_id: "cash", account_type: "asset", debit_cents: 100, credit_cents: 0 },
      { chart_account_id: "revenue", account_type: "income", debit_cents: 0, credit_cents: 100 }
    ] })
  });
  assert.ok(income.blockers.some((item) => item.code === "opening_journal_account_type_invalid"));
});

test("coverage areas retain exact metrics and fail on impossible stored counts", () => {
  const area = normalizeStatementCoverageArea({
    key: "bank_transactions",
    label: "Bank transactions",
    row: {
      total_count: "4",
      covered_count: "3",
      blocking_count: "1",
      unrepresented_transaction_count: "1",
      evidence_hash: "abc"
    },
    blockerCode: "bank_incomplete",
    blockerMessage: "One bank transaction needs review."
  });
  assert.equal(area.status, "blocked");
  assert.equal(area.metrics.unrepresented_transaction_count, 1);
  assert.equal(area.blockers[0].code, "bank_incomplete");
  assert.throws(() => normalizeStatementCoverageArea({
    key: "bad", label: "Bad", row: { total_count: 1, covered_count: 2, blocking_count: 0 },
    blockerCode: "bad", blockerMessage: "Bad"
  }), (error) => error.code === "statement_inventory_inexact");
  assert.throws(() => normalizeStatementCoverageArea({
    key: "bad_partition", label: "Bad partition", row: { total_count: 3, covered_count: 1, blocking_count: 1 },
    blockerCode: "bad", blockerMessage: "Bad"
  }), (error) => error.code === "statement_inventory_inexact");
  assert.throws(() => normalizeStatementCoverageArea({
    key: "bad_zero", label: "Bad zero", row: { total_count: 0, covered_count: 1, blocking_count: 0 },
    blockerCode: "bad", blockerMessage: "Bad"
  }), (error) => error.code === "statement_inventory_inexact");
});

test("statement gates keep close, provider, payroll, and cash-flow limitations explicit", () => {
  const currentOpening = {
    status: "current",
    source_current: true,
    live_fingerprint: "opening",
    blockers: []
  };
  const clean = buildStatementReadiness({
    profile: { coverage_start_date: "2026-01-01" },
    opening: currentOpening,
    areas: [],
    balanceSheetRules: reviewedBalanceSheetRules(),
    stripeConnected: false,
    asOfDate: "2026-08-19"
  });
  assert.equal(clean.statements.balance_sheet.coverage_ready, false);
  assert.equal(clean.statements.balance_sheet.report_available, false);
  assert.ok(clean.statements.balance_sheet.blockers.some((item) => item.code === "source_period_close_not_reviewed"));
  assert.equal(clean.statements.cash_flow.coverage_ready, false);
  assert.ok(clean.statements.cash_flow.blockers.some((item) => item.code === "cash_flow_classification_unavailable"));

  const withoutRules = buildStatementReadiness({
    profile: { coverage_start_date: "2026-01-01" },
    opening: currentOpening,
    areas: [],
    stripeConnected: false,
    asOfDate: "2026-08-19"
  });
  assert.equal(withoutRules.statements.balance_sheet.report_available, false);
  assert.ok(withoutRules.statements.balance_sheet.blockers.some((item) => item.code === "balance_sheet_rules_not_reviewed"));

  const coveredArea = normalizeStatementCoverageArea({
    key: "finance_accounts", label: "Finance accounts",
    row: { total_count: 1, covered_count: 1, blocking_count: 0, evidence_hash: "accounts" },
    blockerCode: "finance_incomplete", blockerMessage: "Incomplete"
  });
  const populated = buildStatementReadiness({
    profile: { coverage_start_date: "2026-01-01" },
    opening: currentOpening,
    areas: [coveredArea],
    balanceSheetRules: reviewedBalanceSheetRules(),
    stripeConnected: false,
    asOfDate: "2026-08-19"
  });
  assert.equal(populated.statements.balance_sheet.coverage_ready, false);
  assert.ok(populated.statements.balance_sheet.blockers.some((item) => item.code === "source_period_close_not_reviewed"));

  const payroll = normalizeStatementCoverageArea({
    key: "payroll_accruals", label: "Payroll",
    row: { total_count: 1, covered_count: 1, blocking_count: 0, payroll_time_entry_count: 3, evidence_hash: "payroll" },
    blockerCode: "payroll_incomplete", blockerMessage: "Incomplete"
  });
  const blocked = buildStatementReadiness({
    profile: { coverage_start_date: "2026-01-01" },
    opening: currentOpening,
    areas: [coveredArea, payroll],
    balanceSheetRules: reviewedBalanceSheetRules(),
    stripeConnected: true,
    asOfDate: "2026-08-19"
  });
  assert.ok(blocked.statements.balance_sheet.blockers.some((item) => item.code === "payroll_cash_settlement_unsupported"));
  assert.ok(blocked.statements.balance_sheet.blockers.some((item) => item.code === "stripe_provider_period_inventory_unavailable"));
  assert.match(blocked.source_inventory_fingerprint, /^[0-9a-f]{64}$/);
});

test("workflow evidence is canonical, exact, and blocks stale or duplicate authority", () => {
  const current = normalizeStatementWorkflowEvidence([
    { workflow: "job_receivable", authority_id: "b", authority_version: 2, stored_fingerprint: "b".repeat(64), live_fingerprint: "b".repeat(64), source_current: true },
    { workflow: "bank_transaction", authority_id: "a", authority_version: 1, stored_fingerprint: "a".repeat(64), live_fingerprint: "a".repeat(64), source_current: true }
  ]);
  const reordered = normalizeStatementWorkflowEvidence([...current.records].reverse());
  assert.equal(current.evidence_fingerprint, reordered.evidence_fingerprint);
  assert.equal(current.current_count, 2);
  assert.equal(current.by_workflow.bank_transaction.current_count, 1);

  const stale = normalizeStatementWorkflowEvidence([
    { ...current.records[0], source_current: false, blocker_codes: ["source_changed"] }
  ]);
  assert.equal(stale.blocking_count, 1);
  assert.ok(stale.blockers.some((item) => item.code === "statement_close_workflow_stale"));

  const duplicate = normalizeStatementWorkflowEvidence([current.records[0], current.records[0]]);
  assert.ok(duplicate.blockers.some((item) => item.code === "statement_close_evidence_duplicate"));
  const oversized = normalizeStatementWorkflowEvidence([], { truncated: true });
  assert.ok(oversized.blockers.some((item) => item.code === "statement_close_evidence_too_large"));
});

test("a matching local close clears only the local-close blocker and becomes stale on evidence change", () => {
  const profile = { coverage_start_date: "2026-01-01", version: 2 };
  const opening = { status: "current", source_current: true, live_fingerprint: "o".repeat(64), blockers: [] };
  const area = normalizeStatementCoverageArea({
    key: "bank_transactions", label: "Bank transactions",
    row: { total_count: 1, covered_count: 1, blocking_count: 0, evidence_hash: "bank" },
    blockerCode: "bank_incomplete", blockerMessage: "Incomplete"
  });
  const workflows = normalizeStatementWorkflowEvidence([
    { workflow: "bank_transaction", authority_id: "source", authority_version: 1,
      stored_fingerprint: "a".repeat(64), live_fingerprint: "a".repeat(64), source_current: true }
  ]);
  const rules = reviewedBalanceSheetRules();
  const unclosed = buildStatementReadiness({ profile, opening, areas: [area], workflows, balanceSheetRules: rules, stripeConnected: false, asOfDate: "2026-08-19" });
  assert.ok(unclosed.statements.balance_sheet.blockers.some((item) => item.code === "source_period_close_not_reviewed"));
  const row = {
    id: "close", version: 4, coverage_profile_version: 2,
    coverage_start_date: "2026-01-01", as_of_date: "2026-08-19",
    opening_evidence_fingerprint: opening.live_fingerprint,
    source_inventory_fingerprint: unclosed.source_inventory_fingerprint,
    workflow_evidence_fingerprint: workflows.evidence_fingerprint,
    reason: "Reviewed", reviewed_by: "owner", created_at: null
  };
  const closed = buildStatementReadiness({
    profile, opening, areas: [area], workflows, balanceSheetRules: rules, periodCloseRow: row, latestCloseVersion: 4,
    stripeConnected: false, asOfDate: "2026-08-19"
  });
  assert.equal(closed.period_close.status, "current");
  assert.equal(closed.period_close.source_current, true);
  assert.equal(closed.statements.balance_sheet.report_available, true);
  assert.equal(closed.statements.balance_sheet.status, "available");
  assert.ok(!closed.statements.balance_sheet.blockers.some((item) => item.code.startsWith("source_period_close_")));
  assert.ok(closed.statements.cash_flow.blockers.some((item) => item.code === "cash_flow_classification_unavailable"));

  const stale = evaluateStatementPeriodClose({
    close: row, latestCloseVersion: 4, profile, opening, areas: [area], workflows,
    sourceInventoryFingerprint: "c".repeat(64), asOfDate: "2026-08-19"
  });
  assert.equal(stale.status, "stale");
  assert.ok(stale.blockers.some((item) => item.code === "source_period_close_stale"));
});

test("Balance Sheet rule review requires fixed treatment and a genuine dated accountant confirmation", () => {
  const input = normalizeBalanceSheetRuleReviewRequest({
    companyToday: "2026-08-19",
    body: {
      client_request_id: REQUEST_ID,
      expected_version: 2,
      as_of_date: "2026-08-19",
      earnings_treatment: "cumulative_since_coverage_start",
      accountant_reviewed_on: "2026-08-18",
      accountant_reference: "CPA workpaper BS-1",
      accountant_review_confirmed: true,
      reason: "Reviewed fixed chart presentation"
    }
  });
  assert.equal(input.expected_version, 2);
  assert.equal(input.as_of_date, "2026-08-19");
  assert.equal(input.accountant_review_confirmed, true);
  assert.match(input.request_fingerprint, /^[0-9a-f]{64}$/);
  assert.throws(() => normalizeBalanceSheetRuleReviewRequest({
    companyToday: "2026-08-19", body: { ...input, accountant_reviewed_on: "2026-08-20" }
  }), (error) => error.code === "balance_sheet_accountant_review_future");
  assert.throws(() => normalizeBalanceSheetRuleReviewRequest({
    companyToday: "2026-08-19", body: { ...input, accountant_review_confirmed: false }
  }), (error) => error.code === "balance_sheet_accountant_confirmation_required");
  assert.throws(() => normalizeBalanceSheetRuleReviewRequest({
    companyToday: "2026-08-19", body: { ...input, accountant_reference: "" }
  }), (error) => error.code === "balance_sheet_accountant_reference_required");
  assert.throws(() => normalizeBalanceSheetRuleReviewRequest({
    companyToday: "2026-08-19", body: { ...input, earnings_treatment: "current_year" }
  }), (error) => error.code === "balance_sheet_earnings_treatment_unsupported");
  assert.throws(() => normalizeBalanceSheetRuleReviewRequest({
    companyToday: "2026-08-19", body: { ...input, as_of_date: "2026-08-20" }
  }), (error) => error.code === "statement_as_of_future");
});

test("Balance Sheet rule evidence fingerprints the complete chart and becomes stale on presentation changes", () => {
  const current = reviewedBalanceSheetRules();
  assert.equal(current.status, "current");
  assert.equal(current.source_current, true);
  const changed = evaluateBalanceSheetRules({
    profile: {
      ...current.snapshot,
      evidence_fingerprint: current.live_fingerprint,
      chart_fingerprint: current.chart_fingerprint
    },
    chartAccounts: current.snapshot.chart.map((account) => account.id === "cash" ? { ...account, name: "Operating Cash" } : account)
  });
  assert.equal(changed.status, "stale");
  assert.ok(changed.blockers.some((item) => item.code === "balance_sheet_rules_stale"));
  assert.throws(() => balanceSheetChartSnapshot([
    { id: "same", code: "1000", name: "Cash", account_type: "asset" },
    { id: "same", code: "2000", name: "Loan", account_type: "liability" }
  ]), (error) => error.code === "balance_sheet_chart_duplicate");
});

test("Balance Sheet math preserves signed balances and exact accumulated earnings equation", () => {
  const empty = summarizeBalanceSheetRows([], { coverageStartDate: "2026-01-01", asOfDate: "2026-08-19" });
  assert.equal(empty.total_assets_cents, 0);
  assert.equal(empty.equation_difference_cents, 0);

  const result = summarizeBalanceSheetRows([
    { chart_account_id: "cash", code: "1000", name: "Cash", account_type: "asset", debit_cents: 20_000, credit_cents: 0 },
    { chart_account_id: "ar", code: "1100", name: "Accounts Receivable", account_type: "asset", debit_cents: 5_000, credit_cents: 0 },
    { chart_account_id: "loan", code: "2200", name: "Loan", account_type: "liability", debit_cents: 0, credit_cents: 8_000 },
    { chart_account_id: "equity", code: "3000", name: "Owner Equity", account_type: "equity", debit_cents: 0, credit_cents: 10_000 },
    { chart_account_id: "revenue", code: "4000", name: "Revenue", account_type: "income", debit_cents: 0, credit_cents: 10_000 },
    { chart_account_id: "expense", code: "5000", name: "Expense", account_type: "expense", debit_cents: 3_000, credit_cents: 0 }
  ], { coverageStartDate: "2026-01-01", asOfDate: "2026-08-19" });
  assert.equal(result.total_assets_cents, 25_000);
  assert.equal(result.total_liabilities_cents, 8_000);
  assert.equal(result.posted_equity_cents, 10_000);
  assert.equal(result.accumulated_earnings_cents, 7_000);
  assert.equal(result.total_liabilities_and_equity_cents, 25_000);
  assert.equal(result.equation_difference_cents, 0);

  const loss = summarizeBalanceSheetRows([
    { chart_account_id: "cash", code: "1000", name: "Cash", account_type: "asset", debit_cents: 0, credit_cents: 2_000 },
    { chart_account_id: "equity", code: "3000", name: "Owner Equity", account_type: "equity", debit_cents: 0, credit_cents: 1_000 },
    { chart_account_id: "expense", code: "5000", name: "Expense", account_type: "expense", debit_cents: 3_000, credit_cents: 0 }
  ], { coverageStartDate: "2026-01-01", asOfDate: "2026-08-19" });
  assert.equal(loss.assets[0].balance_cents, -2_000);
  assert.equal(loss.accumulated_earnings_cents, -3_000);
  assert.equal(loss.total_equity_cents, -2_000);
  assert.equal(loss.equation_difference_cents, 0);

  assert.throws(() => summarizeBalanceSheetRows([
    { chart_account_id: "cash", code: "1000", name: "Cash", account_type: "asset", debit_cents: 100, credit_cents: 0 }
  ], { coverageStartDate: "2026-01-01", asOfDate: "2026-08-19" }), (error) => error.code === "balance_sheet_unbalanced");
  assert.throws(() => summarizeBalanceSheetRows([
    { chart_account_id: "same", code: "1000", name: "Cash", account_type: "asset", debit_cents: 0, credit_cents: 0 },
    { chart_account_id: "same", code: "2000", name: "Loan", account_type: "liability", debit_cents: 0, credit_cents: 0 }
  ], { coverageStartDate: "2026-01-01", asOfDate: "2026-08-19" }), (error) => error.code === "balance_sheet_account_duplicate");
  assert.throws(() => summarizeBalanceSheetRows([
    { chart_account_id: "bad", code: "9000", name: "Unsupported", account_type: "memo", debit_cents: 0, credit_cents: 0 }
  ], { coverageStartDate: "2026-01-01", asOfDate: "2026-08-19" }), (error) => error.code === "balance_sheet_account_type_invalid");
});

test("fingerprints are canonical and content sensitive", () => {
  assert.equal(statementReadinessFingerprint({ b: 2, a: 1 }), statementReadinessFingerprint({ a: 1, b: 2 }));
  assert.notEqual(statementReadinessFingerprint({ a: 1 }), statementReadinessFingerprint({ a: 2 }));
});

test("schema is additive, tenant-scoped, audited, and caches no statement totals", async () => {
  const calls = [];
  await installFinanceStatementReadinessSchema({ async query(sql) { calls.push(sql); return { rows: [] }; } });
  const sql = calls.join("\n");
  assert.match(sql, /CREATE TABLE IF NOT EXISTS finance_statement_coverage_profiles/);
  assert.match(sql, /CREATE TABLE IF NOT EXISTS finance_statement_coverage_audit/);
  assert.match(sql, /CREATE TABLE IF NOT EXISTS finance_statement_period_closes/);
  assert.match(sql, /CREATE TABLE IF NOT EXISTS finance_statement_period_close_audit/);
  assert.match(sql, /CREATE TABLE IF NOT EXISTS finance_balance_sheet_rule_profiles/);
  assert.match(sql, /CREATE TABLE IF NOT EXISTS finance_balance_sheet_rule_audit/);
  assert.match(sql, /FOREIGN KEY \(company_id, opening_journal_entry_id\)/);
  assert.match(sql, /UNIQUE\(company_id, client_request_id\)/);
  assert.match(sql, /company_inception_zero/);
  assert.match(sql, /reviewed_journal/);
  assert.match(sql, /UNIQUE\(company_id, version\)/);
  assert.match(sql, /FOREIGN KEY \(company_id, supersedes_close_id\)/);
  assert.doesNotMatch(sql, /DROP TABLE|TRUNCATE/);
  assert.match(sql, /cumulative_since_coverage_start/);
  assert.doesNotMatch(sql, /DROP TABLE|TRUNCATE|finance_cash_flow/);
});

test("routes expose readiness, reviewed Balance Sheet rules/report, and append-only local close while retaining live gates", () => {
  const routes = [];
  const app = {
    get(path) { routes.push(["GET", path]); },
    put(path) { routes.push(["PUT", path]); },
    post(path) { routes.push(["POST", path]); }
  };
  installFinanceStatementReadinessRoutes({
    app,
    pool: {},
    authRequired: () => {},
    requireFinanceAccess: () => {},
    ensureChartAccounts: async () => {}
  });
  assert.deepEqual(routes, [
    ["GET", "/api/finance/accounting/statement-readiness"],
    ["PUT", "/api/finance/accounting/statement-readiness/profile"],
    ["POST", "/api/finance/accounting/statement-readiness/period-close"],
    ["PUT", "/api/finance/accounting/statements/balance-sheet/rules"],
    ["GET", "/api/finance/accounting/statements/balance-sheet"]
  ]);
  const source = fs.readFileSync(new URL("../finance-statement-readiness.js", import.meta.url), "utf8");
  assert.match(source, /BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY/);
  assert.match(source, /syncOperationalAccountingSources/);
  assert.match(source, /cash_flow_classification_unavailable/);
  assert.match(source, /stripe_provider_period_inventory_unavailable/);
  assert.match(source, /payroll_cash_settlement_unsupported/);
  assert.match(source, /loadBankSourceCloseEvaluation/);
  assert.match(source, /loadOperationalApplicationCloseEvaluation/);
  assert.match(source, /application\.kind='customer_credit'/);
  assert.match(source, /BEGIN ISOLATION LEVEL REPEATABLE READ/);
  assert.match(source, /\/statements\/balance-sheet/);
  assert.match(source, /balance_sheet_unavailable/);
  assert.match(source, /Accumulated Earnings Since Coverage Start/);
  assert.doesNotMatch(source, /\/cash-flow/);
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

if (!process.exitCode) console.log(`PASS finance statement readiness (${passed}/${tests.length})`);
