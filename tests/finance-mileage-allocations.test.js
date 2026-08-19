import assert from "node:assert/strict";
import {
  MileageAllocationError,
  installFinanceMileageAllocationRoutes,
  installFinanceMileageAllocationSchema,
  mileageSourceSnapshot,
  parseMileageAllocationRange,
  planMileageAllocationUpdate,
  suggestMileageAllocationCents
} from "../finance-mileage-allocations.js";

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

function approvedLog(overrides = {}) {
  return {
    id: "mileage_1", employee_id: "employee_1", service_date: "2026-08-19",
    status: "approved", total_miles: "12.3", rate_cents_per_mile: "70",
    reimbursement_cents: "861", ...overrides
  };
}

function sourceLegs() {
  return [
    { id: "leg_a", sequence: 1, distance_miles: "4.100000", job_id: "job_1", manual_trip_id: null },
    { id: "leg_b", sequence: 2, distance_miles: "8.200000", job_id: null, manual_trip_id: "manual_1" }
  ];
}

function savedHeader(overrides = {}) {
  return {
    id: "header_1", mileage_log_id: "mileage_1", employee_id: "employee_1",
    source_service_date: "2026-08-19", source_reimbursement_cents: 861,
    source_rate_cents_per_mile: 70, source_total_miles_tenths: 123,
    source_leg_count: 2, version: 3, ...overrides
  };
}

function savedLines() {
  return [
    { source_leg_id: "leg_a", source_sequence: 1, source_distance_micromiles: 4_100_000,
      source_suggested_job_id: "job_1", source_manual_trip_id: null,
      target_kind: "job", job_id: "job_1", amount_cents: 287 },
    { source_leg_id: "leg_b", source_sequence: 2, source_distance_micromiles: 8_200_000,
      source_suggested_job_id: null, source_manual_trip_id: "manual_1",
      target_kind: "overhead", job_id: null, amount_cents: 574 }
  ];
}

function updateBody(overrides = {}) {
  return {
    expected_version: 0, reason: "Reviewed route and reimbursement",
    allocations: [
      { leg_id: "leg_a", target_kind: "job", job_id: "job_1", amount_cents: 287 },
      { leg_id: "leg_b", target_kind: "overhead", job_id: null, amount_cents: 574 }
    ], ...overrides
  };
}

test("approved mileage snapshots preserve exact cents and leg evidence", () => {
  assert.deepEqual(mileageSourceSnapshot(approvedLog(), sourceLegs()), {
    employee_id: "employee_1", source_service_date: "2026-08-19",
    source_reimbursement_cents: 861, source_rate_cents_per_mile: 70,
    source_total_miles_tenths: 123, source_leg_count: 2,
    legs: [
      { source_leg_id: "leg_a", source_sequence: 1, source_distance_micromiles: 4_100_000,
        source_suggested_job_id: "job_1", source_manual_trip_id: null },
      { source_leg_id: "leg_b", source_sequence: 2, source_distance_micromiles: 8_200_000,
        source_suggested_job_id: null, source_manual_trip_id: "manual_1" }
    ]
  });
  assert.throws(() => mileageSourceSnapshot(approvedLog({ status: "draft" }), sourceLegs()),
    (error) => error.code === "mileage_log_not_approved" && error.statusCode === 409);
  assert.throws(() => mileageSourceSnapshot(approvedLog(), [sourceLegs()[0], { ...sourceLegs()[1], sequence: 1 }]),
    (error) => error.code === "mileage_legs_invalid");
  assert.throws(() => mileageSourceSnapshot(approvedLog({ reimbursement_cents: 1 }), []),
    (error) => error.code === "mileage_allocation_legs_required");
});

test("largest-remainder suggestions reconcile exact cents deterministically", () => {
  assert.deepEqual(suggestMileageAllocationCents(861, [
    { leg_id: "leg_a", distance_micromiles: 4_100_000 },
    { leg_id: "leg_b", distance_micromiles: 8_200_000 }
  ]), [{ leg_id: "leg_a", amount_cents: 287 }, { leg_id: "leg_b", amount_cents: 574 }]);
  assert.deepEqual(suggestMileageAllocationCents(1, [
    { leg_id: "c", distance_micromiles: 1 }, { leg_id: "a", distance_micromiles: 1 },
    { leg_id: "b", distance_micromiles: 1 }
  ]), [{ leg_id: "c", amount_cents: 0 }, { leg_id: "a", amount_cents: 1 }, { leg_id: "b", amount_cents: 0 }]);
  assert.throws(() => suggestMileageAllocationCents(1, [{ leg_id: "a", distance_micromiles: 0 }]),
    (error) => error.code === "mileage_allocation_distance_required");
});

test("mileage allocations create, replay, reallocate, and clear with exact versions", () => {
  const create = planMileageAllocationUpdate({
    body: updateBody(), log: approvedLog(), legs: sourceLegs(), jobs: [{ id: "job_1" }]
  });
  assert.equal(create.mode, "create");
  assert.equal(create.action, "mileage_allocated");
  assert.equal(create.lines.reduce((sum, line) => sum + line.amount_cents, 0), 861);

  const replay = planMileageAllocationUpdate({
    body: updateBody({ expected_version: 3 }), log: approvedLog(), legs: sourceLegs(),
    currentHeader: savedHeader(), currentLines: savedLines(), jobs: [{ id: "job_1" }]
  });
  assert.equal(replay.mode, "replay");

  const reallocate = planMileageAllocationUpdate({
    body: updateBody({ expected_version: 3, allocations: [
      { leg_id: "leg_a", target_kind: "overhead", amount_cents: 287 },
      { leg_id: "leg_b", target_kind: "overhead", amount_cents: 574 }
    ] }), log: approvedLog(), legs: sourceLegs(), currentHeader: savedHeader(), currentLines: savedLines()
  });
  assert.equal(reallocate.mode, "update");
  assert.equal(reallocate.action, "mileage_reallocated");

  const clear = planMileageAllocationUpdate({
    body: { expected_version: 3, reason: "Remove reviewed allocation", allocations: [] },
    log: approvedLog({ status: "draft" }), legs: [], currentHeader: savedHeader(), currentLines: savedLines()
  });
  assert.equal(clear.mode, "clear");
  assert.equal(clear.action, "mileage_allocation_cleared");
});

test("mileage allocation validation fails closed for stale, foreign, incomplete, and unbalanced input", () => {
  assert.throws(() => planMileageAllocationUpdate({
    body: updateBody({ expected_version: 2 }), log: approvedLog(), legs: sourceLegs(),
    currentHeader: savedHeader(), currentLines: savedLines(), jobs: [{ id: "job_1" }]
  }), (error) => error.code === "mileage_allocation_stale" && error.current_version === 3);
  assert.throws(() => planMileageAllocationUpdate({
    body: updateBody(), log: approvedLog(), legs: sourceLegs(), jobs: []
  }), (error) => error.code === "accounting_job_not_found");
  assert.throws(() => planMileageAllocationUpdate({
    body: updateBody({ allocations: updateBody().allocations.slice(0, 1) }),
    log: approvedLog(), legs: sourceLegs(), jobs: [{ id: "job_1" }]
  }), (error) => error.code === "mileage_allocation_legs_incomplete");
  assert.throws(() => planMileageAllocationUpdate({
    body: updateBody({ allocations: updateBody().allocations.map((line) => ({ ...line, amount_cents: 1 })) }),
    log: approvedLog(), legs: sourceLegs(), jobs: [{ id: "job_1" }]
  }), (error) => error.code === "mileage_allocation_unbalanced" && error.allocated_cents === 2);
  assert.throws(() => planMileageAllocationUpdate({
    body: updateBody({ reason: " " }), log: approvedLog(), legs: sourceLegs(), jobs: [{ id: "job_1" }]
  }), (error) => error.code === "mileage_allocation_reason_required");
});

test("mileage allocation report dates are inclusive, valid, and bounded", () => {
  assert.deepEqual(parseMileageAllocationRange("2024-01-01", "2025-12-31"), {
    start_date: "2024-01-01", end_date: "2025-12-31"
  });
  assert.throws(() => parseMileageAllocationRange("2024-01-01", "2026-01-01"),
    (error) => error instanceof MileageAllocationError && error.code === "accounting_range_too_large");
  assert.throws(() => parseMileageAllocationRange("2026-12-31", "2026-01-01"),
    (error) => error.code === "accounting_range_invalid");
  assert.throws(() => parseMileageAllocationRange("2026-02-30", "2026-03-01"));
});

test("mileage allocation schema is additive, audited, exact, and tenant indexed", async () => {
  const calls = [];
  await installFinanceMileageAllocationSchema({ async query(sql) { calls.push(sql); return { rows: [] }; } });
  assert.equal(calls.length, 1);
  assert.match(calls[0], /CREATE TABLE IF NOT EXISTS finance_mileage_allocation_headers/);
  assert.match(calls[0], /CREATE TABLE IF NOT EXISTS finance_mileage_allocation_lines/);
  assert.match(calls[0], /CREATE TABLE IF NOT EXISTS finance_mileage_allocation_audit/);
  assert.match(calls[0], /source_distance_micromiles BIGINT/);
  assert.match(calls[0], /UNIQUE\(company_id, mileage_log_id\)/);
  assert.doesNotMatch(calls[0], /DROP TABLE|TRUNCATE/);
});

test("mileage allocation routes are authenticated and accounting-gated", () => {
  const routes = [];
  const app = {
    get(path, ...handlers) { routes.push({ method: "GET", path, handlers }); },
    put(path, ...handlers) { routes.push({ method: "PUT", path, handlers }); }
  };
  const auth = () => {};
  const finance = () => {};
  installFinanceMileageAllocationRoutes({ app, pool: {}, authRequired: auth, requireFinanceAccess: finance });
  assert.deepEqual(routes.map((route) => `${route.method} ${route.path}`), [
    "GET /api/finance/accounting/mileage-allocations",
    "GET /api/finance/accounting/mileage-allocations/:logId",
    "PUT /api/finance/accounting/mileage-allocations/:logId"
  ]);
  assert.ok(routes.every((route) => route.handlers[0] === auth && route.handlers[1] === finance));
});

test("mileage report returns exact job, overhead, and unallocated cents without posting money", async () => {
  let reportHandler;
  const app = {
    get(path, ...handlers) {
      if (path === "/api/finance/accounting/mileage-allocations") reportHandler = handlers.at(-1);
    }, put() {}
  };
  const pool = {
    async query(sql, values) {
      assert.equal(values[0], "company_1");
      if (sql.includes("review_row_count")) return { rows: [{
        eligible_log_count: "2", eligible_reimbursement_cents: "1800",
        job_allocated_cents: "800", company_overhead_cents: "400", unallocated_cents: "600",
        reviewed_log_count: "1", stale_allocation_count: "1", invalid_source_count: "1", review_row_count: "3"
      }] };
      if (sql.includes("SELECT * FROM evaluated")) return { rows: [{
        mileage_log_id: "mileage_1", employee_id: "employee_1", employee_name: "Taylor Tech",
        service_date: "2026-08-19", status: "approved", total_miles: "12.3",
        rate_cents_per_mile: "70", reimbursement_cents: "861", allocation_version: "3",
        line_count: "2", live_leg_count: "2", source_current: true, eligible_source: true,
        missing_job_count: "0", job_allocated_cents: "287", company_overhead_cents: "574",
        unallocated_cents: "0"
      }, {
        mileage_log_id: "mileage_2", employee_id: "employee_2", employee_name: "Morgan Tech",
        service_date: "2026-08-18", status: "paid", total_miles: "10.0",
        rate_cents_per_mile: "60", reimbursement_cents: "600", allocation_version: "2",
        line_count: "1", live_leg_count: "1", source_current: true, eligible_source: true,
        missing_job_count: "1", job_allocated_cents: "0", company_overhead_cents: "0",
        unallocated_cents: "600"
      }, {
        mileage_log_id: "mileage_3", employee_id: "employee_3", employee_name: "Legacy Tech",
        service_date: "2026-08-17", status: "approved", total_miles: "-1.0",
        rate_cents_per_mile: "60", reimbursement_cents: "-60", allocation_version: null,
        line_count: "0", live_leg_count: "0", source_current: false, eligible_source: false,
        missing_job_count: "0", job_allocated_cents: "0", company_overhead_cents: "0",
        unallocated_cents: "0"
      }] };
      throw new Error("unexpected query");
    }
  };
  installFinanceMileageAllocationRoutes({ app, pool, authRequired() {}, requireFinanceAccess() {} });
  let status = 200;
  let payload;
  await reportHandler(
    { companyId: "company_1", query: { start_date: "2026-08-01", end_date: "2026-08-31" } },
    { status(value) { status = value; return this; }, json(value) { payload = value; return this; } }
  );
  assert.equal(status, 200);
  assert.equal(payload.summary.job_allocated_cents, 800);
  assert.equal(payload.summary.company_overhead_cents, 400);
  assert.equal(payload.summary.unallocated_cents, 600);
  assert.equal(payload.logs[0].job_allocated_cents, 287);
  assert.equal(payload.logs[0].company_overhead_cents, 574);
  assert.equal(payload.logs[1].allocation_status, "stale");
  assert.equal(payload.logs[1].source_changed, false);
  assert.equal(payload.logs[1].unallocated_cents, 600);
  assert.equal(payload.logs[2].allocation_status, "invalid");
  assert.equal(payload.logs[2].total_miles_tenths, null);
  assert.equal("payroll_cents" in payload.summary, false);
  assert.equal("profit_loss_cents" in payload.summary, false);
  assert.match(payload.warnings.join(" "), /do not post payroll/i);
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
if (!process.exitCode) console.log(`PASS finance mileage allocations (${passed}/${tests.length})`);
