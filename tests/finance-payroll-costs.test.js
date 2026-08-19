import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  PayrollCostError,
  allocateExactCents,
  calculateBaseCompensationPreview,
  installFinancePayrollCostRoutes,
  installFinancePayrollCostSchema,
  parsePayrollCostRange,
  payrollEvidenceFingerprint,
  planPayrollRecognitionUpdate
} from "../finance-payroll-costs.js";

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

function pay(overrides = {}) {
  return {
    id: "pay_1",
    employee_id: "11111111-1111-4111-8111-111111111111",
    effective_from: "2026-01-01",
    effective_to: null,
    hourly_rate_cents: 1_800,
    daily_base_cents: 6_000,
    commission_tiers: [{ id: "base", threshold_cents: 0, percent_basis_points: 1_000 }],
    version: 2,
    ...overrides
  };
}

function entry(id, start, end, overrides = {}) {
  return {
    id,
    user_id: "11111111-1111-4111-8111-111111111111",
    employee_name: "Taylor Tech",
    start_at: start,
    end_at: end,
    break_seconds: 0,
    manual_status: "approved",
    work_date: start.slice(0, 10),
    allocation: null,
    ...overrides
  };
}

function preview(overrides = {}) {
  return {
    can_recognize: true,
    policy_version: "reviewed_base_compensation_v1",
    fingerprint: "fingerprint_1",
    blockers: [],
    ...overrides
  };
}

test("recognition periods are exact, company-current, and bounded", () => {
  assert.deepEqual(parsePayrollCostRange("2026-08-01", "2026-08-31", { companyToday: "2026-08-31" }), {
    start_date: "2026-08-01",
    end_date: "2026-08-31"
  });
  assert.throws(
    () => parsePayrollCostRange("2026-08-01", "2026-09-01", { companyToday: "2026-09-01" }),
    (error) => error.code === "payroll_cost_range_too_large"
  );
  assert.throws(
    () => parsePayrollCostRange("2026-08-01", "2026-08-20", { companyToday: "2026-08-19" }),
    (error) => error.code === "payroll_cost_future_period"
  );
  assert.throws(() => parsePayrollCostRange("2026-08-20", "2026-08-19"));
});

test("largest-remainder allocation preserves exact cents and stable ties", () => {
  const shares = allocateExactCents(2, [
    { key: "c", weight: 1 },
    { key: "a", weight: 1 },
    { key: "b", weight: 1 }
  ]);
  assert.deepEqual(Object.fromEntries(shares.map((share) => [share.key, share.cents])), { c: 0, a: 1, b: 1 });
  assert.equal(shares.reduce((sum, share) => sum + share.cents, 0), 2);
  assert.deepEqual(allocateExactCents(0, [{ key: "zero", weight: 0 }]).map((share) => share.cents), [0]);
});

test("hourly and once-daily base cents reconcile across reviewed targets", () => {
  const employeeId = pay().employee_id;
  const entries = [
    entry("entry_a", "2026-08-17T08:00:00.000Z", "2026-08-17T12:00:00.000Z", {
      allocation: {
        version: 3,
        source_current: true,
        mode: "split",
        targets: [
          { target_kind: "job", job_id: "job_1", job_title: "Exterior wash", job_exists: true, seconds: 10_800 },
          { target_kind: "travel", job_id: null, job_exists: true, seconds: 3_600 }
        ]
      }
    }),
    entry("entry_b", "2026-08-17T13:00:00.000Z", "2026-08-17T15:00:00.000Z"),
    entry("entry_c", "2026-08-18T08:00:00.000Z", "2026-08-18T16:00:00.000Z", {
      allocation: {
        version: 1,
        source_current: true,
        mode: "whole_job",
        targets: [{ target_kind: "job", job_id: "job_2", job_title: "Gutter clean", job_exists: true, seconds: 28_800 }]
      }
    })
  ];
  const result = calculateBaseCompensationPreview({
    range: { start_date: "2026-08-17", end_date: "2026-08-18" },
    entries,
    payStructures: [pay()],
    weekStart: 1,
    timezone: "UTC"
  });
  assert.equal(result.can_recognize, true);
  assert.equal(result.summary.work_seconds, 50_400);
  assert.equal(result.summary.hourly_base_cents, 25_200);
  assert.equal(result.summary.daily_base_cents, 12_000);
  assert.equal(result.summary.supported_base_pay_cents, 37_200);
  assert.equal(result.summary.job_base_pay_cents, 28_800);
  assert.equal(result.summary.travel_base_pay_cents, 2_800);
  assert.equal(result.summary.unallocated_base_pay_cents, 5_600);
  assert.equal(result.summary.commission_excluded_employee_count, 1);
  assert.equal(result.employees[0].employee_id, employeeId);
  assert.equal(result.lines.reduce((sum, line) => sum + line.daily_base_pay_cents, 0), 12_000);
  assert.equal(result.lines.flatMap((line) => line.allocations).reduce((sum, line) => sum + line.base_pay_cents, 0), 37_200);
  assert.equal("overtime_premium_cents" in result.summary, false);
  assert.equal("burden_cents" in result.summary, false);
});

test("half-cent hourly results round once per entry", () => {
  const result = calculateBaseCompensationPreview({
    range: { start_date: "2026-08-17", end_date: "2026-08-17" },
    entries: [entry("one_second", "2026-08-17T08:00:00.000Z", "2026-08-17T08:00:01.000Z")],
    payStructures: [pay({ hourly_rate_cents: 1_800, daily_base_cents: null, commission_tiers: [] })],
    weekStart: 1,
    timezone: "UTC"
  });
  assert.equal(result.summary.hourly_base_cents, 1);
  assert.equal(result.summary.supported_base_pay_cents, 1);
});

test("open, invalid, overlap, missing pay, and incomplete workweeks block recognition", () => {
  const entries = [
    entry("valid", "2026-08-17T08:00:00.000Z", "2026-08-17T12:00:00.000Z"),
    entry("overlap", "2026-08-17T11:00:00.000Z", "2026-08-17T13:00:00.000Z"),
    entry("open", "2026-08-18T08:00:00.000Z", null),
    entry("invalid", "2026-08-18T10:00:00.000Z", "2026-08-18T09:00:00.000Z"),
    entry("disapproved", "2026-08-18T13:00:00.000Z", "2026-08-18T14:00:00.000Z", { manual_status: "disapproved" })
  ];
  const result = calculateBaseCompensationPreview({
    range: { start_date: "2026-08-17", end_date: "2026-08-18" }, entries,
    payStructures: [], weekStart: 1, timezone: "UTC"
  });
  assert.equal(result.can_recognize, false);
  const codes = new Set(result.blockers.map((item) => item.code));
  assert.ok(codes.has("payroll_cost_open_time"));
  assert.ok(codes.has("payroll_cost_invalid_time"));
  assert.ok(codes.has("payroll_cost_overlapping_time"));
  assert.ok(codes.has("payroll_cost_missing_pay"));
  assert.ok(codes.has("payroll_cost_overtime_context_incomplete"));
  assert.equal(result.summary.disapproved_entry_count, 1);
});

test("effective-date history and workweek exposure are evaluated without premiums", () => {
  const entries = [entry("long", "2026-08-17T00:00:00.000Z", "2026-08-18T17:00:00.000Z")];
  const result = calculateBaseCompensationPreview({
    range: { start_date: "2026-08-17", end_date: "2026-08-17" },
    entries,
    payStructures: [pay({ daily_base_cents: null, commission_tiers: [] })],
    weekStart: 1,
    timezone: "UTC"
  });
  assert.equal(result.summary.overtime_exposure_employee_count, 1);
  assert.equal(result.can_recognize, true);
  assert.match(result.warnings.join(" "), /overtime premium remains unsupported/i);

  const overlapping = calculateBaseCompensationPreview({
    range: { start_date: "2026-08-17", end_date: "2026-08-17" }, entries,
    payStructures: [pay(), pay({ id: "pay_2", effective_from: "2026-08-01" })],
    weekStart: 1, timezone: "UTC"
  });
  assert.equal(overlapping.can_recognize, false);
  assert.equal(overlapping.summary.overlapping_pay_entry_count, 1);
  assert.ok(overlapping.blockers.some((item) => item.code === "payroll_cost_overlapping_pay"));
});

test("overlapping surrounding-workweek evidence blocks otherwise valid recognition", () => {
  const result = calculateBaseCompensationPreview({
    range: { start_date: "2026-08-18", end_date: "2026-08-18" },
    entries: [
      entry("period", "2026-08-18T08:00:00.000Z", "2026-08-18T12:00:00.000Z"),
      entry("context_a", "2026-08-17T08:00:00.000Z", "2026-08-17T12:00:00.000Z"),
      entry("context_b", "2026-08-17T11:00:00.000Z", "2026-08-17T13:00:00.000Z")
    ],
    payStructures: [pay({ daily_base_cents: null, commission_tiers: [] })],
    weekStart: 1,
    timezone: "UTC"
  });
  assert.equal(result.can_recognize, false);
  assert.equal(result.summary.overlapping_entry_count, 0);
  assert.equal(result.summary.overtime_context_incomplete_count, 2);
  assert.ok(result.blockers.some((item) => item.code === "payroll_cost_overtime_context_incomplete"));
});

test("fingerprints are canonical and change with material source evidence", () => {
  const left = payrollEvidenceFingerprint({ b: 2, a: [{ z: 3, y: 4 }] });
  const right = payrollEvidenceFingerprint({ a: [{ y: 4, z: 3 }], b: 2 });
  assert.equal(left, right);
  assert.notEqual(left, payrollEvidenceFingerprint({ a: [{ y: 5, z: 3 }], b: 2 }));
});

test("recognition planning supports create, replay, refresh, stale, overlap, and clear", () => {
  const create = planPayrollRecognitionUpdate({
    body: { expected_version: 0, action: "recognize", reason: "Reviewed period" }, preview: preview()
  });
  assert.equal(create.mode, "create");

  const current = { status: "recognized", policy_version: preview().policy_version, source_fingerprint: "fingerprint_1", version: 3 };
  assert.equal(planPayrollRecognitionUpdate({
    body: { expected_version: 3, action: "recognize", reason: "Retry" }, currentRecognition: current, preview: preview()
  }).mode, "replay");
  assert.equal(planPayrollRecognitionUpdate({
    body: { expected_version: 3, action: "recognize", reason: "Refresh" }, currentRecognition: current,
    preview: preview({ fingerprint: "fingerprint_2" })
  }).mode, "replace");
  assert.equal(planPayrollRecognitionUpdate({
    body: { expected_version: 3, action: "clear", reason: "Correct sources" }, currentRecognition: current, preview: preview()
  }).mode, "clear");
  assert.throws(
    () => planPayrollRecognitionUpdate({
      body: { expected_version: 2, action: "recognize", reason: "Stale" }, currentRecognition: current, preview: preview()
    }),
    (error) => error.code === "payroll_cost_stale" && error.current_version === 3
  );
  assert.throws(
    () => planPayrollRecognitionUpdate({
      body: { expected_version: 3, action: "recognize", reason: "Overlap" }, currentRecognition: current,
      preview: preview({ fingerprint: "fingerprint_2" }), overlappingRecognitionCount: 1
    }),
    (error) => error.code === "payroll_cost_period_overlap"
  );
  assert.throws(
    () => planPayrollRecognitionUpdate({
      body: { expected_version: 0, action: "recognize", reason: "Blocked" },
      preview: preview({ can_recognize: false, blockers: [{ code: "missing" }] })
    }),
    (error) => error.code === "payroll_cost_preview_blocked"
  );
});

test("schema is additive, exact, audited, and tenant indexed", async () => {
  const calls = [];
  await installFinancePayrollCostSchema({ async query(sql) { calls.push(sql); return { rows: [], rowCount: 0 }; } });
  assert.equal(calls.length, 1);
  assert.match(calls[0], /CREATE TABLE IF NOT EXISTS finance_payroll_cost_periods/);
  assert.match(calls[0], /CREATE TABLE IF NOT EXISTS finance_payroll_cost_lines/);
  assert.match(calls[0], /CREATE TABLE IF NOT EXISTS finance_payroll_cost_allocations/);
  assert.match(calls[0], /CREATE TABLE IF NOT EXISTS finance_payroll_cost_audit/);
  assert.match(calls[0], /UNIQUE\(company_id, start_date, end_date\)/);
  assert.doesNotMatch(calls[0], /DROP TABLE|TRUNCATE/);
});

test("routes are authenticated, accounting-gated, serialized, set-based, and audited", async () => {
  const routes = [];
  const app = {
    get(path, ...handlers) { routes.push({ method: "GET", path, handlers }); },
    put(path, ...handlers) { routes.push({ method: "PUT", path, handlers }); }
  };
  const auth = () => {};
  const finance = () => {};
  installFinancePayrollCostRoutes({ app, pool: {}, authRequired: auth, requireFinanceAccess: finance });
  assert.deepEqual(routes.map((route) => `${route.method} ${route.path}`), [
    "GET /api/finance/accounting/payroll-costs",
    "PUT /api/finance/accounting/payroll-costs/recognition"
  ]);
  assert.ok(routes.every((route) => route.handlers[0] === auth && route.handlers[1] === finance));

  const source = await readFile(new URL("../finance-payroll-costs.js", import.meta.url), "utf8");
  assert.match(source, /pg_advisory_xact_lock/);
  assert.match(source, /status = 'recognized'[\s\S]*start_date <= \$3::date AND end_date >= \$2::date/);
  assert.match(source, /jsonb_to_recordset/);
  assert.match(source, /INSERT INTO finance_payroll_cost_audit/);
  assert.doesNotMatch(source, /INSERT INTO finance_transactions|UPDATE finance_transactions/);
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
if (!process.exitCode) console.log(`PASS finance payroll costs (${passed}/${tests.length})`);
