import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  calculateSupportedPayrollPreview,
  installFinancePayrollEvaluationRoutes,
  installFinancePayrollEvaluationSchema,
  normalizeCommissionAllocationInput,
  parsePayrollEvaluationRange,
  payrollWorkweekStart,
  planCommissionAllocationUpdate,
  planPayrollEvaluationRecognition,
  recognitionAuditSnapshot
} from "../finance-payroll-evaluation.js";

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

const employeeID = "11111111-1111-4111-8111-111111111111";
const policyID = "22222222-2222-4222-8222-222222222222";
const baseID = "33333333-3333-4333-8333-333333333333";

function policy(overrides = {}) {
  return {
    id: policyID,
    employee_id: employeeID,
    effective_from: "2026-01-01",
    effective_to: null,
    status: "reviewed",
    jurisdiction_code: "US-FL",
    exemption_status: "nonexempt",
    overtime_method: "weekly_regular_rate",
    weekly_threshold_seconds: 40 * 3_600,
    weekly_multiplier_basis_points: 15_000,
    state_overtime_status: "none",
    overtime_combination_method: "weekly_only",
    daily_overtime_rules: [],
    burden_status: "none",
    burden_rules: [],
    version: 3,
    ...overrides
  };
}

function baseLines({ split = false, crossWorkday = false } = {}) {
  return [0, 1, 2, 3, 4].map((offset) => {
    const day = String(3 + offset).padStart(2, "0");
    const nextDay = String(4 + offset).padStart(2, "0");
    return {
      time_entry_id: `time-${offset}`,
      employee_id: employeeID,
      employee_name: "Taylor Tech",
      work_date: `2026-08-${day}`,
      source_start_at: `2026-08-${day}T08:00:00.000Z`,
      source_end_at: crossWorkday && offset === 0
        ? `2026-08-${nextDay}T01:00:00.000Z`
        : `2026-08-${day}T17:00:00.000Z`,
      source_work_seconds: 9 * 3_600,
      base_pay_cents: 9_000,
      allocations: split && offset === 4
        ? [
          { target_kind: "job", job_id: "job-1", job_title: "Window Cleaning", source_seconds: 4 * 3_600, base_pay_cents: 4_000 },
          { target_kind: "travel", job_id: null, job_title: null, source_seconds: 5 * 3_600, base_pay_cents: 5_000 }
        ]
        : [{ target_kind: "job", job_id: "job-1", job_title: "Window Cleaning", source_seconds: 9 * 3_600, base_pay_cents: 9_000 }]
    };
  });
}

function commission(overrides = {}) {
  return {
    id: "44444444-4444-4444-8444-444444444444",
    employee_id: employeeID,
    employee_name: "Taylor Tech",
    event_kind: "earning",
    root_event_id: null,
    earned_date: "2026-08-07",
    commission_cents: 5_000,
    regular_rate_treatment: "included",
    regular_rate_basis: null,
    job_id: "job-1",
    job_title: "Window Cleaning",
    allocation_status: "reviewed",
    allocation_version: 1,
    allocations: [{ workweek_start_date: "2026-08-03", commission_cents: 5_000 }],
    ...overrides
  };
}

function preview(overrides = {}) {
  return calculateSupportedPayrollPreview({
    range: { start_date: "2026-08-03", end_date: "2026-08-09" },
    weekStart: 1,
    timezone: "UTC",
    baseRecognition: {
      id: baseID,
      start_date: "2026-08-03",
      end_date: "2026-08-09",
      version: 1,
      source_fingerprint: "base-fingerprint",
      source_current: true
    },
    baseLines: baseLines(),
    policies: [policy()],
    commissionEvents: [commission()],
    jobFacts: [{ id: "job-1", title: "Window Cleaning", price_cents: 100_000, material_cost_cents: 20_000, service_names: ["Windows"] }],
    ...overrides
  });
}

test("evaluation periods identify exact full company workweeks", () => {
  assert.equal(payrollWorkweekStart("2026-08-09", 1), "2026-08-03");
  const exact = parsePayrollEvaluationRange("2026-08-03", "2026-08-09", { weekStart: 1, companyToday: "2026-08-19" });
  assert.equal(exact.full_workweeks, true);
  const partial = parsePayrollEvaluationRange("2026-08-04", "2026-08-08", { weekStart: 1 });
  assert.equal(partial.full_workweeks, false);
  assert.equal(partial.suggested_start_date, "2026-08-03");
  assert.equal(partial.suggested_end_date, "2026-08-09");
  const month = parsePayrollEvaluationRange("2026-08-01", "2026-08-31", { weekStart: 1 });
  assert.equal(month.suggested_start_date, "2026-08-03");
  assert.equal(month.suggested_end_date, "2026-08-30");
  const currentPartial = parsePayrollEvaluationRange("2026-08-17", "2026-08-19", { weekStart: 1, companyToday: "2026-08-19" });
  assert.equal(currentPartial.suggested_start_date, "2026-08-10");
  assert.equal(currentPartial.suggested_end_date, "2026-08-16");
});

test("commission allocation is exact, signed, root-bounded, and stale-safe", () => {
  const event = { event_kind: "earning", commission_cents: 5_000 };
  const input = normalizeCommissionAllocationInput({
    body: { expected_version: 0, reason: "Quarter review", allocations: [
      { workweek_start_date: "2026-08-03", commission_cents: 2_000 },
      { workweek_start_date: "2026-08-10", commission_cents: 3_000 }
    ] },
    event,
    weekStart: 1,
    companyToday: "2026-08-19"
  });
  assert.equal(input.lines.reduce((sum, item) => sum + item.commission_cents, 0), 5_000);
  assert.equal(planCommissionAllocationUpdate({ currentHeader: null, currentLines: [], input }).mode, "create");
  assert.throws(() => normalizeCommissionAllocationInput({
    body: { expected_version: 0, reason: "Bad", allocations: [{ workweek_start_date: "2026-08-04", commission_cents: 5_000 }] },
    event, weekStart: 1, companyToday: "2026-08-19"
  }), (error) => error.code === "commission_allocation_week_invalid");
  assert.throws(() => normalizeCommissionAllocationInput({
    body: { expected_version: 0, reason: "Bad", allocations: [{ workweek_start_date: "2026-08-03", commission_cents: 4_999 }] },
    event, weekStart: 1, companyToday: "2026-08-19"
  }), (error) => error.code === "commission_allocation_reconciliation_failed");

  const adjustment = normalizeCommissionAllocationInput({
    body: { expected_version: 0, reason: "Chargeback", allocations: [{ workweek_start_date: "2026-08-03", commission_cents: -500 }] },
    event: { event_kind: "adjustment", commission_cents: -500 },
    rootWorkweeks: ["2026-08-03"], weekStart: 1, companyToday: "2026-08-19"
  });
  assert.equal(adjustment.lines[0].commission_cents, -500);
  assert.throws(() => normalizeCommissionAllocationInput({
    body: { expected_version: 0, reason: "Bad week", allocations: [{ workweek_start_date: "2026-08-10", commission_cents: -500 }] },
    event: { event_kind: "adjustment", commission_cents: -500 },
    rootWorkweeks: ["2026-08-03"], weekStart: 1, companyToday: "2026-08-19"
  }), (error) => error.code === "commission_allocation_root_week_invalid");
});

test("weekly regular-rate evaluation includes commission once and reconciles exact targets", () => {
  const result = preview();
  assert.equal(result.can_recognize, true);
  assert.equal(result.summary.base_compensation_cents, 45_000);
  assert.equal(result.summary.commission_cents, 5_000);
  assert.equal(result.summary.overtime_seconds, 5 * 3_600);
  assert.equal(result.summary.overtime_premium_cents, 2_778);
  assert.equal(result.summary.supported_gross_compensation_cents, 52_778);
  assert.equal(result.summary.supported_loaded_labor_cents, 52_778);
  assert.equal(result.summary.job_loaded_labor_cents, 52_778);
  assert.equal(result.targets[0].supported_contribution_cents, 27_222);
});

test("excluded commission remains gross but not regular-rate remuneration", () => {
  const result = preview({ commissionEvents: [commission({ regular_rate_treatment: "excluded", regular_rate_basis: "Reviewed statutory exclusion" })] });
  assert.equal(result.can_recognize, true);
  assert.equal(result.summary.commission_cents, 5_000);
  assert.equal(result.summary.overtime_premium_cents, 2_500);
  assert.equal(result.summary.supported_gross_compensation_cents, 52_500);
});

test("daily and weekly overlap uses the highest multiplier once", () => {
  const result = preview({
    policies: [policy({
      state_overtime_status: "configured",
      overtime_combination_method: "highest_applicable_multiplier",
      daily_overtime_rules: [{ id: "daily-8", threshold_seconds: 8 * 3_600, multiplier_basis_points: 15_000 }]
    })]
  });
  assert.equal(result.can_recognize, true);
  // Five daily overtime hours plus four additional weekly-only hours on Friday;
  // the final Friday hour qualifies under both rules but is counted once.
  assert.equal(result.summary.overtime_seconds, 9 * 3_600);
  assert.equal(result.summary.overtime_premium_cents, 5_000);
});

test("split threshold entries keep exact premium employee cost but leave target chronology unallocated", () => {
  const result = preview({ baseLines: baseLines({ split: true }) });
  assert.equal(result.can_recognize, true);
  assert.equal(result.summary.overtime_premium_cents, 2_778);
  assert.equal(result.summary.unallocated_loaded_labor_cents, 2_778);
  assert.equal(result.summary.job_loaded_labor_cents, 40_000 + 5_000);
});

test("configured daily rules block cross-company-workday source evidence", () => {
  const result = preview({
    baseLines: baseLines({ crossWorkday: true }),
    policies: [policy({
      state_overtime_status: "configured",
      overtime_combination_method: "highest_applicable_multiplier",
      daily_overtime_rules: [{ id: "daily-8", threshold_seconds: 8 * 3_600, multiplier_basis_points: 15_000 }]
    })]
  });
  assert.equal(result.can_recognize, false);
  assert.ok(result.blockers.some((item) => item.code === "payroll_evaluation_daily_cross_workday"));
});

test("employer burden supports exact bases and blocks caps without YTD authority", () => {
  const result = preview({ policies: [policy({
    burden_status: "configured",
    burden_rules: [
      { id: "tax", label: "Employer tax", category: "employer_tax", basis: "percent_of_wages", rate_basis_points: 1_000, amount_cents: null, annual_wage_cap_cents: null },
      { id: "wc", label: "Workers comp", category: "workers_comp", basis: "fixed_per_hour", rate_basis_points: null, amount_cents: 100, annual_wage_cap_cents: null },
      { id: "benefit", label: "Benefit", category: "benefit", basis: "fixed_per_workweek", rate_basis_points: null, amount_cents: 1_000, annual_wage_cap_cents: null }
    ]
  })] });
  assert.equal(result.can_recognize, true);
  assert.equal(result.summary.employer_burden_cents, 5_278 + 4_500 + 1_000);
  assert.equal(result.summary.supported_loaded_labor_cents, 63_556);

  const capped = preview({ policies: [policy({
    burden_status: "configured",
    burden_rules: [{ id: "fica", label: "Capped tax", category: "employer_tax", basis: "percent_of_wages", rate_basis_points: 620, amount_cents: null, annual_wage_cap_cents: 18_450_000 }]
  })] });
  assert.equal(capped.can_recognize, false);
  assert.ok(capped.blockers.some((item) => item.code === "payroll_evaluation_ytd_evidence_required"));
});

test("fixed burden follows reviewed source time while unsupported special rules and hourless commission block", () => {
  const weightedLines = [
    {
      ...baseLines()[0], time_entry_id: "job-hour", source_work_seconds: 3_600, base_pay_cents: 1_000,
      allocations: [{ target_kind: "job", job_id: "job-1", job_title: "Window Cleaning", source_seconds: 3_600, base_pay_cents: 1_000 }]
    },
    {
      ...baseLines()[1], time_entry_id: "admin-hours", source_work_seconds: 10_800, base_pay_cents: 3_000,
      allocations: [{ target_kind: "admin", job_id: null, job_title: null, source_seconds: 10_800, base_pay_cents: 3_000 }]
    }
  ];
  const weighted = preview({
    baseLines: weightedLines,
    commissionEvents: [],
    policies: [policy({
      burden_status: "configured",
      burden_rules: [{ id: "wc", label: "Workers comp", category: "workers_comp", basis: "fixed_per_hour", rate_basis_points: null, amount_cents: 100, annual_wage_cap_cents: null }]
    })]
  });
  assert.equal(weighted.targets.find((item) => item.target_kind === "job").employer_burden_cents, 100);
  assert.equal(weighted.targets.find((item) => item.target_kind === "admin").employer_burden_cents, 300);

  const special = preview({ policies: [policy({ special_rule_notes: "Consecutive-day review required" })] });
  assert.equal(special.can_recognize, false);
  assert.ok(special.blockers.some((item) => item.code === "payroll_evaluation_special_rule_unsupported"));

  const hourless = preview({ baseLines: [], commissionEvents: [commission()] });
  assert.equal(hourless.can_recognize, false);
  assert.ok(hourless.blockers.some((item) => item.code === "payroll_evaluation_regular_rate_hours_required"));
});

test("missing base, policy, commission allocation, and partial weeks fail closed", () => {
  const result = preview({
    range: { start_date: "2026-08-04", end_date: "2026-08-09" },
    baseRecognition: null,
    policies: [policy({ status: "draft" })],
    commissionEvents: [commission({ allocation_status: "missing", allocations: [] })]
  });
  const codes = new Set(result.blockers.map((item) => item.code));
  assert.ok(codes.has("payroll_evaluation_full_workweeks_required"));
  assert.ok(codes.has("payroll_evaluation_base_recognition_required"));
  assert.ok(codes.has("payroll_evaluation_policy_not_reviewed"));
  assert.ok(codes.has("payroll_evaluation_commission_allocation_missing"));
  assert.equal(result.blockers.length, codes.size);
});

test("recognition planning is versioned, blocker-aware, replay-safe, and overlap-safe", () => {
  const supported = preview();
  assert.equal(planPayrollEvaluationRecognition({
    body: { expected_version: 0, action: "recognize", reason: "Reviewed" }, preview: supported
  }).mode, "create");
  const current = { version: 2, status: "recognized", policy_version: supported.policy_version, source_fingerprint: supported.fingerprint };
  assert.equal(planPayrollEvaluationRecognition({
    body: { expected_version: 2, action: "recognize", reason: "Replay" }, currentRecognition: current, preview: supported
  }).mode, "replay");
  assert.throws(() => planPayrollEvaluationRecognition({
    body: { expected_version: 1, action: "clear", reason: "Stale" }, currentRecognition: current, preview: supported
  }), (error) => error.code === "payroll_evaluation_stale");
  assert.throws(() => planPayrollEvaluationRecognition({
    body: { expected_version: 0, action: "recognize", reason: "Overlap" }, preview: supported, overlappingRecognitionCount: 1
  }), (error) => error.code === "payroll_evaluation_period_overlap");
});

test("append-only recognition audit snapshots retain bounded exact detail without display names", () => {
  const supported = preview();
  const snapshot = recognitionAuditSnapshot({
    id: "55555555-5555-4555-8555-555555555555",
    base_recognition_id: baseID,
    start_date: supported.start_date,
    end_date: supported.end_date,
    status: "recognized",
    policy_version: supported.policy_version,
    source_fingerprint: supported.fingerprint,
    summary: supported.summary,
    version: 1
  }, supported);
  assert.equal(snapshot.workweeks.length, 1);
  assert.equal(snapshot.workweeks[0].supported_loaded_labor_cents, supported.summary.supported_loaded_labor_cents);
  assert.equal(snapshot.workweeks[0].allocations[0].job_id, "job-1");
  assert.equal("employee_name" in snapshot.workweeks[0], false);
  assert.equal("job_title" in snapshot.workweeks[0].allocations[0], false);
});

test("schema is additive, tenant-indexed, exact, and audited", async () => {
  const calls = [];
  await installFinancePayrollEvaluationSchema({ async query(sql) { calls.push(sql); return { rows: [] }; } });
  assert.equal(calls.length, 1);
  assert.match(calls[0], /finance_commission_allocation_headers/);
  assert.match(calls[0], /finance_commission_allocation_lines/);
  assert.match(calls[0], /finance_commission_allocation_audit/);
  assert.match(calls[0], /finance_payroll_evaluation_periods/);
  assert.match(calls[0], /finance_payroll_evaluation_workweeks/);
  assert.match(calls[0], /finance_payroll_evaluation_allocations/);
  assert.match(calls[0], /finance_payroll_evaluation_audit/);
  assert.doesNotMatch(calls[0], /DROP TABLE|TRUNCATE/);
});

test("routes are accounting-gated and source/P&L/paycheck preserving", async () => {
  const routes = [];
  const app = {
    get(path, ...handlers) { routes.push({ method: "GET", path, handlers }); },
    put(path, ...handlers) { routes.push({ method: "PUT", path, handlers }); }
  };
  const auth = () => {};
  const finance = () => {};
  installFinancePayrollEvaluationRoutes({ app, pool: {}, authRequired: auth, requireFinanceAccess: finance });
  assert.deepEqual(routes.map((route) => `${route.method} ${route.path}`), [
    "GET /api/finance/accounting/payroll-evaluation",
    "GET /api/finance/accounting/payroll-evaluation/commission-events/:eventId/allocation",
    "PUT /api/finance/accounting/payroll-evaluation/commission-events/:eventId/allocation",
    "PUT /api/finance/accounting/payroll-evaluation/recognition"
  ]);
  assert.ok(routes.every((route) => route.handlers[0] === auth && route.handlers[1] === finance));
  const source = await readFile(new URL("../finance-payroll-evaluation.js", import.meta.url), "utf8");
  assert.match(source, /FOR UPDATE/);
  assert.match(source, /pg_advisory_xact_lock/);
  assert.match(source, /source_fingerprint/);
  assert.doesNotMatch(source, /UPDATE (?:finance_commission_events|time_clock_entries|schedule_events|finance_transactions)|stripe\.paymentIntents/);
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
if (!process.exitCode) console.log(`PASS finance payroll evaluation (${passed}/${tests.length})`);
