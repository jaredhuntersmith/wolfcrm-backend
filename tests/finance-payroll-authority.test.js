import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  commissionEventRequestFingerprint,
  installFinancePayrollAuthorityRoutes,
  installFinancePayrollAuthoritySchema,
  normalizeCommissionEventInput,
  normalizePayrollPolicyInput,
  parsePayrollAuthorityRange,
  planPayrollPolicyUpdate,
  validateCommissionCorrectionFloor
} from "../finance-payroll-authority.js";

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

function reviewedPolicy(overrides = {}) {
  return {
    expected_version: 0,
    effective_from: "2026-08-19",
    status: "reviewed",
    jurisdiction_code: "US-FL",
    exemption_status: "nonexempt",
    overtime_method: "weekly_regular_rate",
    weekly_threshold_seconds: 144_000,
    weekly_multiplier_basis_points: 15_000,
    state_overtime_status: "none",
    daily_overtime_rules: [],
    burden_status: "none",
    burden_rules: [],
    special_rule_notes: null,
    notes: "Reviewed with payroll advisor",
    reason: "Initial rule review",
    ...overrides
  };
}

function policyRow(overrides = {}) {
  return {
    id: "11111111-1111-4111-8111-111111111111",
    effective_from: "2026-08-01",
    effective_to: null,
    version: 2,
    ...normalizePayrollPolicyInput(reviewedPolicy({ expected_version: 0, effective_from: "2026-08-01" })),
    ...overrides
  };
}

test("payroll authority ranges are exact, current, and bounded", () => {
  assert.deepEqual(parsePayrollAuthorityRange("2026-08-01", "2026-08-31", { companyToday: "2026-08-31" }), {
    start_date: "2026-08-01", end_date: "2026-08-31"
  });
  assert.throws(() => parsePayrollAuthorityRange("2026-08-01", "2026-09-01"), (error) => error.code === "payroll_authority_range_too_large");
  assert.throws(() => parsePayrollAuthorityRange("2026-08-20", "2026-08-19"));
  assert.throws(() => parsePayrollAuthorityRange("2026-08-19", "2026-08-20", { companyToday: "2026-08-19" }), (error) => error.code === "payroll_authority_future_period");
});

test("reviewed policy requires explicit complete exemption, overtime, state, and burden coverage", () => {
  const result = normalizePayrollPolicyInput(reviewedPolicy());
  assert.equal(result.jurisdiction_code, "US-FL");
  assert.equal(result.weekly_threshold_seconds, 144_000);
  assert.throws(
    () => normalizePayrollPolicyInput(reviewedPolicy({ exemption_status: "undetermined", overtime_method: "undetermined", weekly_threshold_seconds: null, weekly_multiplier_basis_points: null })),
    (error) => error.code === "reviewed_policy_incomplete"
  );
  assert.throws(
    () => normalizePayrollPolicyInput(reviewedPolicy({ exemption_status: "exempt" })),
    (error) => error.code === "exempt_overtime_method_invalid"
  );
  const exempt = normalizePayrollPolicyInput(reviewedPolicy({
    exemption_status: "exempt", overtime_method: "not_applicable",
    weekly_threshold_seconds: null, weekly_multiplier_basis_points: null
  }));
  assert.equal(exempt.exemption_status, "exempt");
});

test("daily overtime tiers and burden rules are exact, bounded, and basis-correct", () => {
  const result = normalizePayrollPolicyInput(reviewedPolicy({
    state_overtime_status: "configured",
    daily_overtime_rules: [
      { id: "double", threshold_seconds: 43_200, multiplier_basis_points: 20_000 },
      { id: "time-half", threshold_seconds: 28_800, multiplier_basis_points: 15_000 }
    ],
    burden_status: "configured",
    burden_rules: [
      { id: "fica", label: "Employer FICA", category: "employer_tax", basis: "percent_of_wages", rate_basis_points: 765, amount_cents: null, annual_wage_cap_cents: 18_450_000 },
      { id: "workers-comp", label: "Workers' compensation", category: "workers_comp", basis: "fixed_per_hour", rate_basis_points: null, amount_cents: 85, annual_wage_cap_cents: null },
      { id: "benefit", label: "Weekly benefit", category: "benefit", basis: "fixed_per_workweek", rate_basis_points: null, amount_cents: 2_500, annual_wage_cap_cents: null }
    ]
  }));
  assert.deepEqual(result.daily_overtime_rules.map((item) => item.id), ["time-half", "double"]);
  assert.equal(result.burden_rules[0].rate_basis_points, 765);
  assert.equal(result.burden_rules[2].basis, "fixed_per_workweek");
  assert.throws(
    () => normalizePayrollPolicyInput(reviewedPolicy({ burden_status: "none", burden_rules: [{ id: "x" }] })),
    (error) => ["burden_rule_label_required", "burden_rules_unexpected"].includes(error.code)
  );
  assert.throws(
    () => normalizePayrollPolicyInput(reviewedPolicy({ state_overtime_status: "manual", special_rule_notes: "" })),
    (error) => error.code === "special_rule_notes_required"
  );
  assert.throws(
    () => normalizePayrollPolicyInput(reviewedPolicy({
      overtime_method: "manual_premium", weekly_threshold_seconds: null,
      weekly_multiplier_basis_points: null, special_rule_notes: ""
    })),
    (error) => error.code === "special_rule_notes_required"
  );
});

test("draft policies preserve explicit unknowns without becoming reviewed authority", () => {
  const result = normalizePayrollPolicyInput(reviewedPolicy({
    status: "draft", jurisdiction_code: "US-CA", exemption_status: "undetermined",
    overtime_method: "undetermined", weekly_threshold_seconds: null, weekly_multiplier_basis_points: null,
    state_overtime_status: "undetermined", burden_status: "undetermined"
  }));
  assert.equal(result.status, "draft");
  assert.equal(result.state_overtime_status, "undetermined");
});

test("effective policy planning supports replay, same-day correction, insertion, predecessor closure, and stale rejection", () => {
  const row = policyRow();
  const replayUpdate = normalizePayrollPolicyInput(reviewedPolicy({ expected_version: 2, effective_from: "2026-08-01" }));
  assert.equal(planPayrollPolicyUpdate({ rows: [row], update: replayUpdate }).mode, "replay");
  const correction = normalizePayrollPolicyInput(reviewedPolicy({ expected_version: 2, effective_from: "2026-08-01", notes: "Corrected" }));
  assert.equal(planPayrollPolicyUpdate({ rows: [row], update: correction }).mode, "correct");
  const later = normalizePayrollPolicyInput(reviewedPolicy({ expected_version: 2, effective_from: "2026-08-19" }));
  const plan = planPayrollPolicyUpdate({ rows: [row], update: later });
  assert.equal(plan.mode, "create");
  assert.equal(plan.predecessor.id, row.id);
  assert.throws(
    () => planPayrollPolicyUpdate({ rows: [row], update: { ...later, expected_version: 1 } }),
    (error) => error.code === "payroll_policy_stale" && error.current_version === 2
  );
  assert.throws(
    () => planPayrollPolicyUpdate({ rows: [row, policyRow({ id: "22222222-2222-4222-8222-222222222222", effective_from: "2026-08-15" })], update: later }),
    (error) => error.code === "payroll_policy_history_invalid"
  );
});

test("commission earnings require explicit exact source and regular-rate treatment", () => {
  const earning = normalizeCommissionEventInput({
    client_request_id: "33333333-3333-4333-8333-333333333333",
    employee_id: "11111111-1111-4111-8111-111111111111",
    event_kind: "earning",
    earned_date: "2026-08-19",
    commission_cents: 12_345,
    regular_rate_treatment: "included",
    source_type: "job",
    source_id: "job_1",
    eligible_revenue_cents: 123_450,
    reason: "Reviewed sale"
  });
  assert.equal(earning.commission_cents, 12_345);
  assert.equal(earning.source_id, "job_1");
  assert.throws(
    () => normalizeCommissionEventInput({ ...earning, client_request_id: "44444444-4444-4444-8444-444444444444", regular_rate_treatment: "excluded", regular_rate_basis: null }),
    (error) => error.code === "regular_rate_basis_required"
  );
  assert.throws(
    () => normalizeCommissionEventInput({ ...earning, client_request_id: "55555555-5555-4555-8555-555555555555", commission_cents: -1 }),
    (error) => error.code === "commission_earning_negative"
  );
});

test("commission adjustments are append-only root corrections and cannot cross below zero", () => {
  const adjustment = normalizeCommissionEventInput({
    client_request_id: "66666666-6666-4666-8666-666666666666",
    employee_id: "11111111-1111-4111-8111-111111111111",
    event_kind: "adjustment",
    root_event_id: "77777777-7777-4777-8777-777777777777",
    earned_date: "2026-08-20",
    commission_cents: -2_500,
    reason: "Partial chargeback"
  });
  assert.equal(adjustment.root_event_id, "77777777-7777-4777-8777-777777777777");
  assert.equal(validateCommissionCorrectionFloor(10_000, -2_500, [-1_000]), 6_500);
  assert.throws(() => validateCommissionCorrectionFloor(10_000, -9_001, [-1_000]), (error) => error.code === "commission_adjustment_below_zero");
});

test("commission idempotency fingerprints are canonical and content-sensitive", () => {
  const left = commissionEventRequestFingerprint({ b: 2, a: { y: 1, z: 3 } });
  const right = commissionEventRequestFingerprint({ a: { z: 3, y: 1 }, b: 2 });
  assert.equal(left, right);
  assert.notEqual(left, commissionEventRequestFingerprint({ a: { z: 3, y: 2 }, b: 2 }));
});

test("schema is additive, audited, append-only, and tenant indexed", async () => {
  const calls = [];
  await installFinancePayrollAuthoritySchema({ async query(sql) { calls.push(sql); return { rows: [], rowCount: 0 }; } });
  assert.equal(calls.length, 1);
  assert.match(calls[0], /CREATE TABLE IF NOT EXISTS finance_payroll_policies/);
  assert.match(calls[0], /CREATE TABLE IF NOT EXISTS finance_payroll_policy_audit/);
  assert.match(calls[0], /CREATE TABLE IF NOT EXISTS finance_commission_events/);
  assert.match(calls[0], /UNIQUE\(company_id, client_request_id\)/);
  assert.doesNotMatch(calls[0], /DROP TABLE|TRUNCATE/);
});

test("routes are authenticated, accounting-gated, versioned, serialized, and source-preserving", async () => {
  const routes = [];
  const app = {
    get(path, ...handlers) { routes.push({ method: "GET", path, handlers }); },
    put(path, ...handlers) { routes.push({ method: "PUT", path, handlers }); },
    post(path, ...handlers) { routes.push({ method: "POST", path, handlers }); }
  };
  const auth = () => {};
  const finance = () => {};
  installFinancePayrollAuthorityRoutes({ app, pool: {}, authRequired: auth, requireFinanceAccess: finance });
  assert.deepEqual(routes.map((route) => `${route.method} ${route.path}`), [
    "GET /api/finance/accounting/payroll-authority",
    "GET /api/finance/accounting/payroll-authority/employees/:employeeId",
    "PUT /api/finance/accounting/payroll-authority/employees/:employeeId/policy",
    "POST /api/finance/accounting/payroll-authority/commission-events"
  ]);
  assert.ok(routes.every((route) => route.handlers[0] === auth && route.handlers[1] === finance));

  const source = await readFile(new URL("../finance-payroll-authority.js", import.meta.url), "utf8");
  assert.match(source, /FOR UPDATE/);
  assert.match(source, /pg_advisory_xact_lock/);
  assert.match(source, /INSERT INTO finance_payroll_policy_audit/);
  assert.match(source, /request_fingerprint/);
  assert.match(source, /SELECT p\.\*, u\.id AS employee_id/);
  assert.match(source, /SUM\(commission_cents\) FILTER/);
  assert.match(source, /commission-request/);
  assert.match(source, /finished_at IS NOT NULL FOR SHARE/);
  assert.match(source, /commission_future_date/);
  assert.match(source, /commission_adjustment_date_invalid/);
  assert.match(source, /normalizedInstant\(snapshot\.finished_at\)/);
  assert.match(source, /normalizedInstant\(snapshot\.accepted_at\)/);
  assert.doesNotMatch(source, /fixed_per_period/);
  assert.doesNotMatch(source, /UPDATE schedule_events|UPDATE quotes|UPDATE employee_pay_structures|DELETE FROM finance_commission_events/);
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
if (!process.exitCode) console.log(`PASS finance payroll authority (${passed}/${tests.length})`);
