import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {
  buildPayrollJournalInput,
  buildPayrollJournalReversalInput,
  evaluatePayrollJournalSource,
  installFinancePayrollJournalRoutes,
  normalizePayrollJournalActionRequest,
  parsePayrollJournalRange
} from "../finance-payroll-journals.js";

const IDs = {
  period: "00000000-0000-4000-8000-000000000201",
  wages: "00000000-0000-4000-8000-000000000202",
  burden: "00000000-0000-4000-8000-000000000203",
  accrual: "00000000-0000-4000-8000-000000000204",
  request: "00000000-0000-4000-8000-000000000205",
  journal: "00000000-0000-4000-8000-000000000206"
};

function bundle(overrides = {}) {
  const recognition = {
    id: IDs.period,
    start_date: "2026-08-03",
    end_date: "2026-08-16",
    status: "recognized",
    policy_version: "supported_loaded_labor_v1",
    source_fingerprint: "a".repeat(64),
    source_current: true,
    version: 3,
    summary: {
      supported_gross_compensation_cents: 120_000,
      employer_burden_cents: 18_000,
      supported_loaded_labor_cents: 138_000
    },
    ...overrides.recognition
  };
  const preview = overrides.preview === null ? null : {
    policy_version: "supported_loaded_labor_v1",
    fingerprint: "a".repeat(64),
    can_recognize: true,
    summary: recognition.summary,
    ...overrides.preview
  };
  const wagesAccount = overrides.wagesAccount === null ? null : {
    id: IDs.wages, account_type: "expense", system_key: "payroll_wages_expense", active: true,
    ...overrides.wagesAccount
  };
  const burdenAccount = overrides.burdenAccount === null ? null : {
    id: IDs.burden, account_type: "expense", system_key: "payroll_burden_expense", active: true,
    ...overrides.burdenAccount
  };
  const accrualAccount = overrides.accrualAccount === null ? null : {
    id: IDs.accrual, account_type: "liability", system_key: "payroll_accrual_clearing", active: true,
    ...overrides.accrualAccount
  };
  return { recognition, preview, wagesAccount, burdenAccount, accrualAccount, posting: overrides.posting || null };
}

test("current supported payroll produces exact expense debits and accrual credit", () => {
  const result = evaluatePayrollJournalSource(bundle());
  assert.equal(result.eligible, true);
  assert.equal(result.review_state, "ready");
  assert.equal(result.journal_preview.entry_date, "2026-08-16");
  assert.deepEqual(result.journal_preview.lines.map((line) => [line.chart_account_id, line.debit_cents, line.credit_cents]), [
    [IDs.wages, 120_000, 0],
    [IDs.burden, 18_000, 0],
    [IDs.accrual, 0, 138_000]
  ]);
});

test("zero employer burden omits the zero line while retaining a balanced journal", () => {
  const summary = {
    supported_gross_compensation_cents: 120_000,
    employer_burden_cents: 0,
    supported_loaded_labor_cents: 120_000
  };
  const result = evaluatePayrollJournalSource(bundle({ recognition: { summary }, preview: { summary } }));
  assert.equal(result.eligible, true);
  assert.equal(result.journal_preview.lines.length, 2);
  assert.equal(result.journal_preview.total_debits_cents, 120_000);
  assert.equal(result.journal_preview.total_credits_cents, 120_000);
});

test("stale, cleared, unreconciled, zero, and invalid-account evidence fails closed", () => {
  const summary = {
    supported_gross_compensation_cents: 10,
    employer_burden_cents: 5,
    supported_loaded_labor_cents: 20
  };
  const result = evaluatePayrollJournalSource(bundle({
    recognition: { status: "cleared", source_current: false, summary },
    preview: { can_recognize: false, fingerprint: "b".repeat(64), summary },
    wagesAccount: { active: false },
    burdenAccount: { account_type: "liability" },
    accrualAccount: { account_type: "expense" }
  }));
  const codes = result.blockers.map((item) => item.code);
  for (const code of [
    "payroll_recognition_not_active", "payroll_recognition_stale", "payroll_preview_blocked",
    "payroll_fingerprint_changed", "payroll_amount_unreconciled", "payroll_wages_expense_invalid",
    "payroll_burden_expense_invalid", "payroll_accrual_clearing_invalid"
  ]) assert.ok(codes.includes(code), code);
});

test("source fingerprint detects evaluation and account authority changes", () => {
  const first = evaluatePayrollJournalSource(bundle());
  const sourceChanged = evaluatePayrollJournalSource(bundle({ recognition: { version: 4 } }));
  const accountChanged = evaluatePayrollJournalSource(bundle({ wagesAccount: { id: "00000000-0000-4000-8000-000000000207" } }));
  assert.notEqual(first.source_fingerprint, sourceChanged.source_fingerprint);
  assert.notEqual(first.source_fingerprint, accountChanged.source_fingerprint);
  const current = evaluatePayrollJournalSource(bundle({
    posting: {
      status: "posted", journal_entry_id: IDs.journal, source_fingerprint: first.source_fingerprint,
      wages_chart_account_id: IDs.wages, burden_chart_account_id: IDs.burden, accrual_chart_account_id: IDs.accrual
    }
  }));
  assert.equal(current.source_current, true);
  assert.equal(current.review_state, "posted");
  assert.equal(current.can_void, true);
});

test("journal and exact reversal retain supported-payroll source authority", () => {
  const evaluation = evaluatePayrollJournalSource(bundle());
  const journal = buildPayrollJournalInput({
    evaluation,
    evaluationPeriodID: IDs.period,
    evaluationVersion: 3,
    clientRequestID: IDs.request,
    reason: "Reviewed supported payroll"
  });
  assert.equal(journal.entry_kind, "payroll_recognition");
  assert.equal(journal.source_type, "finance_payroll_evaluation");
  assert.equal(journal.source_version, 3);
  assert.ok(journal.lines.every((line) => line.chart_account_id !== "cash"));
  const reversal = buildPayrollJournalReversalInput({
    original: { ...journal, id: IDs.journal },
    originalLines: journal.lines,
    evaluationPeriodID: IDs.period,
    evaluationVersion: 3,
    clientRequestID: IDs.request,
    reason: "Void unsupported accrual"
  });
  assert.equal(reversal.reversal_of_entry_id, IDs.journal);
  assert.deepEqual(reversal.lines.map((line) => [line.debit_cents, line.credit_cents]), journal.lines.map((line) => [line.credit_cents, line.debit_cents]));
});

test("action requests require exact versions, stable identity, and an audit reason", () => {
  const request = normalizePayrollJournalActionRequest({
    body: {
      client_request_id: IDs.request,
      expected_evaluation_version: 3,
      expected_posting_version: 0,
      reason: "Reviewed supported payroll"
    },
    evaluationPeriodID: IDs.period,
    action: "post"
  });
  assert.equal(request.request_fingerprint.length, 64);
  assert.equal(request.expected_evaluation_version, 3);
  assert.throws(() => normalizePayrollJournalActionRequest({
    body: { ...request, reason: "" }, evaluationPeriodID: IDs.period, action: "post"
  }), (error) => error.code === "payroll_journal_reason_required");
});

test("payroll journal ranges are exact, valid, and bounded", () => {
  assert.deepEqual(parsePayrollJournalRange("2025-01-01", "2027-01-01"), { start_date: "2025-01-01", end_date: "2027-01-01" });
  assert.throws(() => parsePayrollJournalRange("2026-08-20", "2026-08-19"), (error) => error.code === "payroll_journal_range_invalid");
  assert.throws(() => parsePayrollJournalRange("2025-01-01", "2027-01-02"), (error) => error.code === "payroll_journal_range_too_large");
});

test("schema and routes preserve tenant, lock, audit, and no-cash boundaries", () => {
  const source = fs.readFileSync(new URL("../finance-payroll-journals.js", import.meta.url), "utf8");
  assert.match(source, /CREATE TABLE IF NOT EXISTS finance_payroll_journal_postings/);
  assert.match(source, /CREATE TABLE IF NOT EXISTS finance_payroll_journal_posting_audit/);
  assert.match(source, /finance_payroll_evaluation_periods\(company_id, id\)/);
  assert.match(source, /SELECT pg_advisory_xact_lock/);
  assert.match(source, /SELECT id FROM companies WHERE id=\$1 FOR UPDATE/);
  assert.match(source, /FOR UPDATE/);
  assert.match(source, /FOR SHARE/);
  assert.doesNotMatch(source, /UPDATE finance_payroll_evaluation_periods\s+SET/);
  assert.doesNotMatch(source, /UPDATE finance_transactions\s+SET/);
  assert.doesNotMatch(source, /UPDATE payment_records\s+SET/);
  assert.match(source, /does not calculate withholding, employee deductions, net pay/);
  const routes = [];
  installFinancePayrollJournalRoutes({
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
    ["GET", "/api/finance/accounting/payroll-journals"],
    ["GET", "/api/finance/accounting/payroll-journals/:periodId"],
    ["POST", "/api/finance/accounting/payroll-journals/:periodId/post"],
    ["POST", "/api/finance/accounting/payroll-journals/:periodId/void"]
  ]);
});

test("supported-payroll recognition mutations interlock with a current accrual", () => {
  const source = fs.readFileSync(new URL("../finance-payroll-evaluation.js", import.meta.url), "utf8");
  assert.match(source, /finance_payroll_journal_postings/);
  assert.match(source, /payroll_evaluation_journal_active/);
  assert.match(source, /Void the current supported-payroll accrual journal/);
});
