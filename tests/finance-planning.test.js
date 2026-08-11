import assert from "node:assert/strict";
import {
  estimateDebtPayoff,
  requiredPaymentForTarget,
  summarizeBudget,
  goalMetrics
} from "../finance-calculations.js";
import { buildProjection } from "../finance.js";

function run(name, fn) {
  try {
    fn();
    console.log(`PASS ${name}`);
  } catch (error) {
    console.error(`FAIL ${name}`);
    throw error;
  }
}

function planned(overrides = {}) {
  return {
    id: overrides.id || "planned_test",
    title: overrides.title || "Planned Expense",
    direction: overrides.direction || "expense",
    amount_cents: overrides.amount_cents ?? 10000,
    scheduled_date: overrides.scheduled_date || "2026-08-15",
    category: overrides.category || "Advertising",
    recurrence: overrides.recurrence || "none",
    recurrence_end_date: overrides.recurrence_end_date || null,
    archived_at: overrides.archived_at || null,
    debt_id: overrides.debt_id || null
  };
}

run("debt payoff principal-only exact division", () => {
  const result = estimateDebtPayoff({ balanceCents: 100000, paymentCents: 25000, startDate: "2026-08-01" });
  assert.equal(result.status, "payoff_capable");
  assert.equal(result.estimated_number_of_payments, 4);
  assert.equal(result.estimated_total_future_payments_cents, 100000);
  assert.equal(result.estimated_interest_paid_cents, null);
});

run("debt payoff principal-only final partial payment", () => {
  const result = estimateDebtPayoff({ balanceCents: 100000, paymentCents: 30000, startDate: "2026-08-01" });
  assert.equal(result.estimated_number_of_payments, 4);
  assert.equal(result.estimated_total_future_payments_cents, 100000);
});

run("debt payoff includes APR interest with basis-point precision", () => {
  const result = estimateDebtPayoff({ balanceCents: 100000, paymentCents: 10000, aprBasisPoints: 1899, startDate: "2026-08-01" });
  assert.equal(result.status, "payoff_capable");
  assert.equal(result.interest_included, true);
  assert.ok(result.estimated_interest_paid_cents > 0);
});

run("debt payoff detects payment too small to amortize", () => {
  const result = estimateDebtPayoff({ balanceCents: 100000, paymentCents: 100, aprBasisPoints: 2400, startDate: "2026-08-01" });
  assert.equal(result.status, "not_payoff_capable");
});

run("debt payoff handles zero balance", () => {
  const result = estimateDebtPayoff({ balanceCents: 0, paymentCents: 10000, aprBasisPoints: 1899, startDate: "2026-08-01" });
  assert.equal(result.status, "paid");
  assert.equal(result.estimated_number_of_payments, 0);
});

run("required target payment principal-only", () => {
  const result = requiredPaymentForTarget({
    balanceCents: 120000,
    startDate: "2026-08-01",
    targetDate: "2027-08-01"
  });
  assert.equal(result.status, "target_payment_available");
  assert.ok(result.required_payment_cents >= 10000);
});

run("required target payment includes APR", () => {
  const result = requiredPaymentForTarget({
    balanceCents: 120000,
    aprBasisPoints: 1200,
    startDate: "2026-08-01",
    targetDate: "2027-08-01"
  });
  assert.equal(result.status, "target_payment_available");
  assert.equal(result.interest_included, true);
  assert.ok(result.required_payment_cents > 10000);
});

run("required target rejects past or today target", () => {
  assert.equal(requiredPaymentForTarget({ balanceCents: 100000, startDate: "2026-08-01", targetDate: "2026-08-01" }).status, "invalid_target_date");
  assert.equal(requiredPaymentForTarget({ balanceCents: 100000, startDate: "2026-08-01", targetDate: "2026-07-31" }).status, "invalid_target_date");
});

run("budget monthly planned spend counts matching expense category", () => {
  const summary = summarizeBudget({
    budget: { id: "budget", name: "Ads", category: "Advertising", limit_cents: 200000 },
    occurrences: [
      { direction: "expense", category: "Advertising", amount_cents: 100000 },
      { direction: "expense", category: "Advertising", amount_cents: 60000 },
      { direction: "income", category: "Advertising", amount_cents: 50000 },
      { direction: "expense", category: "Fuel", amount_cents: 50000 }
    ]
  });
  assert.equal(summary.planned_spend_cents, 160000);
  assert.equal(summary.remaining_cents, 40000);
  assert.equal(summary.status, "on_plan");
});

run("budget detects over planned spending", () => {
  const summary = summarizeBudget({
    budget: { id: "budget", name: "Food", category: "Food", limit_cents: 50000 },
    occurrences: [
      { direction: "expense", category: "Food", amount_cents: 70000 }
    ]
  });
  assert.equal(summary.status, "over_plan");
  assert.equal(summary.overage_cents, 20000);
});

run("goal progress and remaining amount", () => {
  const metrics = goalMetrics({
    targetAmountCents: 1000000,
    currentAmountCents: 320000,
    targetDate: "2026-12-01",
    startDate: "2026-08-01"
  });
  assert.equal(metrics.progress_percent, 32);
  assert.equal(metrics.remaining_cents, 680000);
  assert.ok(metrics.required_weekly_cents > 0);
  assert.ok(metrics.required_monthly_cents > metrics.required_weekly_cents);
});

run("goal reaching target clamps progress at 100", () => {
  const metrics = goalMetrics({
    targetAmountCents: 100000,
    currentAmountCents: 125000,
    targetDate: "2026-12-01",
    startDate: "2026-08-01"
  });
  assert.equal(metrics.progress_percent, 100);
  assert.equal(metrics.remaining_cents, 0);
});

run("debt planned payment affects cash projection and safe-to-spend", () => {
  const base = buildProjection({
    startingBalanceCents: 500000,
    minimumReserveCents: 100000,
    startDate: "2026-08-01",
    endDate: "2026-08-31",
    plannedItems: []
  });
  const withDebt = buildProjection({
    startingBalanceCents: 500000,
    minimumReserveCents: 100000,
    startDate: "2026-08-01",
    endDate: "2026-08-31",
    plannedItems: [planned({ id: "debt_payment", title: "IRS Payment", category: "Taxes", amount_cents: 100000, debt_id: "debt_1" })]
  });
  assert.equal(withDebt.ending_balance_cents, 400000);
  assert.equal(withDebt.safe_to_spend_cents, base.safe_to_spend_cents - 100000);
});

run("increased debt payment lowers safe-to-spend further", () => {
  const lower = buildProjection({
    startingBalanceCents: 500000,
    minimumReserveCents: 100000,
    startDate: "2026-08-01",
    endDate: "2026-08-31",
    plannedItems: [planned({ amount_cents: 100000, category: "Taxes" })]
  });
  const higher = buildProjection({
    startingBalanceCents: 500000,
    minimumReserveCents: 100000,
    startDate: "2026-08-01",
    endDate: "2026-08-31",
    plannedItems: [planned({ amount_cents: 150000, category: "Taxes" })]
  });
  assert.equal(higher.safe_to_spend_cents, lower.safe_to_spend_cents - 50000);
});
