import assert from "node:assert/strict";
import { buildProjection, expandPlannedItemOccurrences } from "../finance.js";

function item(overrides = {}) {
  return {
    id: overrides.id || "item_test",
    account_id: overrides.account_id || null,
    account_name: overrides.account_name || null,
    title: overrides.title || "Test Item",
    direction: overrides.direction || "expense",
    amount_cents: overrides.amount_cents ?? 1000,
    scheduled_date: overrides.scheduled_date || "2026-08-15",
    category: overrides.category || "Other",
    recurrence: overrides.recurrence || "none",
    recurrence_end_date: overrides.recurrence_end_date || null,
    archived_at: overrides.archived_at || null
  };
}

function dates(occurrences) {
  return occurrences.map((occurrence) => occurrence.occurrence_date);
}

function run(name, fn) {
  try {
    fn();
    console.log(`PASS ${name}`);
  } catch (error) {
    console.error(`FAIL ${name}`);
    throw error;
  }
}

run("one-time event expands once", () => {
  const occurrences = expandPlannedItemOccurrences(item(), "2026-08-11", "2026-08-31");
  assert.deepEqual(dates(occurrences), ["2026-08-15"]);
});

run("weekly recurrence expands by seven days", () => {
  const occurrences = expandPlannedItemOccurrences(item({ recurrence: "weekly" }), "2026-08-11", "2026-08-31");
  assert.deepEqual(dates(occurrences), ["2026-08-15", "2026-08-22", "2026-08-29"]);
});

run("biweekly recurrence expands by fourteen days", () => {
  const occurrences = expandPlannedItemOccurrences(item({ recurrence: "biweekly" }), "2026-08-11", "2026-09-15");
  assert.deepEqual(dates(occurrences), ["2026-08-15", "2026-08-29", "2026-09-12"]);
});

run("monthly recurrence clamps Jan 31 to February last day", () => {
  const occurrences = expandPlannedItemOccurrences(
    item({ scheduled_date: "2027-01-31", recurrence: "monthly" }),
    "2027-01-01",
    "2027-03-31"
  );
  assert.deepEqual(dates(occurrences), ["2027-01-31", "2027-02-28", "2027-03-28"]);
});

run("monthly recurrence handles leap-year February", () => {
  const occurrences = expandPlannedItemOccurrences(
    item({ scheduled_date: "2028-01-31", recurrence: "monthly" }),
    "2028-01-01",
    "2028-03-31"
  );
  assert.deepEqual(dates(occurrences), ["2028-01-31", "2028-02-29", "2028-03-29"]);
});

run("yearly recurrence clamps leap day on non-leap years", () => {
  const occurrences = expandPlannedItemOccurrences(
    item({ scheduled_date: "2028-02-29", recurrence: "yearly" }),
    "2028-01-01",
    "2031-12-31"
  );
  assert.deepEqual(dates(occurrences), ["2028-02-29", "2029-02-28", "2030-02-28", "2031-02-28"]);
});

run("recurrence end date stops generated occurrences", () => {
  const occurrences = expandPlannedItemOccurrences(
    item({ recurrence: "weekly", recurrence_end_date: "2026-08-23" }),
    "2026-08-11",
    "2026-09-30"
  );
  assert.deepEqual(dates(occurrences), ["2026-08-15", "2026-08-22"]);
});

run("projection arithmetic, lowest balance, reserve, and safe-to-spend are exact cents", () => {
  const projection = buildProjection({
    startingBalanceCents: 1000000,
    minimumReserveCents: 200000,
    startDate: "2026-08-11",
    endDate: "2026-08-31",
    plannedItems: [
      item({ id: "payroll", title: "Payroll", direction: "expense", amount_cents: 300000, scheduled_date: "2026-08-15" }),
      item({ id: "income", title: "Customer Revenue", direction: "income", amount_cents: 200000, scheduled_date: "2026-08-16" }),
      item({ id: "insurance", title: "Insurance", direction: "expense", amount_cents: 40000, scheduled_date: "2026-08-18" })
    ]
  });
  assert.equal(projection.ending_balance_cents, 860000);
  assert.equal(projection.total_expected_income_cents, 200000);
  assert.equal(projection.total_planned_expenses_cents, 340000);
  assert.equal(projection.lowest_projected_balance_cents, 700000);
  assert.equal(projection.lowest_projected_balance_date, "2026-08-15");
  assert.equal(projection.safe_to_spend_cents, 500000);
  assert.equal(projection.reserve_shortfall_cents, 0);
});

run("same-day projection applies expenses before income conservatively", () => {
  const projection = buildProjection({
    startingBalanceCents: 100000,
    minimumReserveCents: 0,
    startDate: "2026-08-11",
    endDate: "2026-08-31",
    plannedItems: [
      item({ id: "income", title: "Customer Revenue", direction: "income", amount_cents: 100000, scheduled_date: "2026-08-15" }),
      item({ id: "rent", title: "Rent", direction: "expense", amount_cents: 150000, scheduled_date: "2026-08-15" })
    ]
  });
  assert.equal(projection.events[0].direction, "expense");
  assert.equal(projection.events[0].balance_after_cents, -50000);
  assert.equal(projection.lowest_projected_balance_cents, -50000);
  assert.equal(projection.ending_balance_cents, 50000);
});

run("negative projected balances and reserve shortfall are not hidden", () => {
  const projection = buildProjection({
    startingBalanceCents: 100000,
    minimumReserveCents: 200000,
    startDate: "2026-08-11",
    endDate: "2026-08-31",
    plannedItems: [
      item({ id: "large_expense", title: "Large Expense", direction: "expense", amount_cents: 200000, scheduled_date: "2026-08-15" })
    ]
  });
  assert.equal(projection.lowest_projected_balance_cents, -100000);
  assert.equal(projection.safe_to_spend_cents, 0);
  assert.equal(projection.reserve_shortfall_cents, 300000);
});

run("archived planned items are excluded", () => {
  const projection = buildProjection({
    startingBalanceCents: 100000,
    minimumReserveCents: 0,
    startDate: "2026-08-11",
    endDate: "2026-08-31",
    plannedItems: [
      item({ id: "archived", direction: "expense", amount_cents: 50000, archived_at: "2026-08-12T00:00:00Z" })
    ]
  });
  assert.equal(projection.ending_balance_cents, 100000);
  assert.equal(projection.events.length, 0);
});
