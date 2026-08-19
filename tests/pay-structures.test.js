import assert from "node:assert/strict";
import {
  installPayStructureSchema,
  installPayStructureSystem,
  normalizePayStructureInput,
  planCurrentPayStructureUpdate
} from "../pay-structures.js";

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("pay structure normalization keeps exact cents and basis points", () => {
  const normalized = normalizePayStructureInput({
    expected_version: "3",
    hourly_rate_cents: "2450",
    daily_base_cents: null,
    commission_tiers: [
      { id: "upper", threshold_cents: 100_000, percent_basis_points: 3000 },
      { id: "base", threshold_cents: "0", percent_basis_points: "2500" }
    ],
    notes: " Reviewed rate plan ",
    reason: "Annual compensation review"
  });
  assert.deepEqual(normalized, {
    expected_version: 3,
    hourly_rate_cents: 2450,
    daily_base_cents: null,
    commission_tiers: [
      { id: "base", threshold_cents: 0, percent_basis_points: 2500 },
      { id: "upper", threshold_cents: 100_000, percent_basis_points: 3000 }
    ],
    notes: "Reviewed rate plan",
    reason: "Annual compensation review"
  });
});

test("pay structure normalization rejects ambiguous or inexact compensation", () => {
  assert.throws(
    () => normalizePayStructureInput({ expected_version: 0, reason: " ", commission_tiers: [] }),
    (error) => error.code === "pay_structure_reason_required"
  );
  assert.throws(
    () => normalizePayStructureInput({ expected_version: 0, reason: "Review", hourly_rate_cents: -1 }),
    (error) => error.code === "hourly_rate_cents_invalid"
  );
  assert.throws(
    () => normalizePayStructureInput({
      expected_version: 0,
      reason: "Review",
      commission_tiers: [{ id: "only", threshold_cents: 10_000, percent_basis_points: 2500 }]
    }),
    (error) => error.code === "commission_first_threshold_invalid"
  );
  assert.throws(
    () => normalizePayStructureInput({
      expected_version: 0,
      reason: "Review",
      commission_tiers: [
        { id: "a", threshold_cents: 0, percent_basis_points: 2500 },
        { id: "b", threshold_cents: 0, percent_basis_points: 3000 }
      ]
    }),
    (error) => error.code === "commission_thresholds_invalid"
  );
  assert.throws(
    () => normalizePayStructureInput({
      expected_version: 0,
      reason: "Review",
      commission_tiers: [{ id: "base", threshold_cents: 0, percent_basis_points: 10_001 }]
    }),
    (error) => error.code === "commission_tier_1_percent_basis_points_invalid"
  );
});

test("first authoritative pay structure starts on the company day", () => {
  const update = normalizePayStructureInput({
    expected_version: 0,
    hourly_rate_cents: 2000,
    commission_tiers: [],
    reason: "Initial reviewed structure"
  });
  assert.deepEqual(planCurrentPayStructureUpdate({ today: "2026-08-19", rows: [], update }), {
    mode: "create",
    predecessor: null,
    effective_from: "2026-08-19",
    effective_to: null,
    current_version: 0
  });
});

test("a later company day closes the predecessor without overlap", () => {
  const predecessor = {
    id: "old",
    effective_from: "2026-01-01",
    effective_to: null,
    hourly_rate_cents: 2000,
    daily_base_cents: null,
    commission_tiers: [],
    notes: null,
    version: 4
  };
  const update = normalizePayStructureInput({
    expected_version: 4,
    hourly_rate_cents: 2250,
    commission_tiers: [],
    reason: "Rate increase"
  });
  const plan = planCurrentPayStructureUpdate({ today: "2026-08-19", rows: [predecessor], update });
  assert.equal(plan.mode, "create");
  assert.equal(plan.predecessor.id, "old");
  assert.equal(plan.effective_from, "2026-08-19");
  assert.equal(plan.effective_to, null);
});

test("same-day saves distinguish exact replay, correction, and stale edits", () => {
  const row = {
    id: "today",
    effective_from: "2026-08-19",
    effective_to: null,
    hourly_rate_cents: 2250,
    daily_base_cents: 5000,
    commission_tiers: [{ id: "base", threshold_cents: 0, percent_basis_points: 2500 }],
    notes: null,
    version: 2
  };
  const replay = normalizePayStructureInput({
    expected_version: 2,
    hourly_rate_cents: 2250,
    daily_base_cents: 5000,
    commission_tiers: row.commission_tiers,
    reason: "Retry save"
  });
  assert.equal(planCurrentPayStructureUpdate({ today: "2026-08-19", rows: [row], update: replay }).mode, "replay");

  const correction = { ...replay, hourly_rate_cents: 2300 };
  assert.equal(planCurrentPayStructureUpdate({ today: "2026-08-19", rows: [row], update: correction }).mode, "correct");
  assert.throws(
    () => planCurrentPayStructureUpdate({ today: "2026-08-19", rows: [row], update: { ...correction, expected_version: 1 } }),
    (error) => error.code === "pay_structure_stale" && error.current_version === 2
  );
});

test("overlapping active history fails closed", () => {
  const rows = [
    { id: "a", effective_from: "2026-01-01", effective_to: null, version: 1 },
    { id: "b", effective_from: "2026-02-01", effective_to: null, version: 1 }
  ];
  const update = normalizePayStructureInput({ expected_version: 1, commission_tiers: [], reason: "Review" });
  assert.throws(
    () => planCurrentPayStructureUpdate({ today: "2026-08-19", rows, update }),
    (error) => error.code === "pay_structure_history_invalid"
  );
});

test("overlapping historical pay periods fail closed", () => {
  assert.throws(
    () => planCurrentPayStructureUpdate({
      today: "2026-08-19",
      rows: [
        { id: "old", effective_from: "2026-01-01", effective_to: "2026-02-15", version: 1 },
        { id: "overlap", effective_from: "2026-02-01", effective_to: "2026-03-01", version: 1 }
      ],
      update: normalizePayStructureInput({ expected_version: 0, commission_tiers: [], reason: "Review" })
    }),
    (error) => error.code === "pay_structure_history_invalid"
  );
});

test("pay structure schema is additive and tenant indexed", async () => {
  const calls = [];
  await installPayStructureSchema({ async query(sql) { calls.push(sql); return { rows: [], rowCount: 0 }; } });
  assert.equal(calls.length, 1);
  assert.match(calls[0], /CREATE TABLE IF NOT EXISTS employee_pay_structures/);
  assert.match(calls[0], /UNIQUE\(company_id, employee_id, effective_from\)/);
  assert.match(calls[0], /CREATE TABLE IF NOT EXISTS employee_pay_structure_audit/);
  assert.doesNotMatch(calls[0], /DROP TABLE|TRUNCATE/);
});

test("pay structure routes keep reads authenticated and mutations pay-manage gated", async () => {
  const routes = [];
  const app = {
    get(path, ...handlers) { routes.push({ method: "GET", path, handlers }); },
    put(path, ...handlers) { routes.push({ method: "PUT", path, handlers }); }
  };
  const auth = () => {};
  const manage = () => {};
  await installPayStructureSystem({
    app,
    pool: { async query() { return { rows: [], rowCount: 0 }; } },
    authRequired: auth,
    requirePayManage: manage
  });
  assert.equal(routes.length, 3);
  const currentRead = routes.find((route) => route.path === "/api/pay-structures");
  const auditRead = routes.find((route) => route.path.endsWith("/audit"));
  const update = routes.find((route) => route.method === "PUT");
  assert.equal(currentRead.handlers[0], auth);
  assert.equal(currentRead.handlers.includes(manage), false);
  assert.equal(auditRead.handlers[1], manage);
  assert.equal(update.handlers[1], manage);
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
if (!process.exitCode) console.log(`PASS pay structures (${passed}/${tests.length})`);
