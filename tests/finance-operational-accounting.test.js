import assert from "node:assert/strict";
import {
  buildJobContributionSummary,
  buildReceivableSnapshot,
  claimStripeWebhookEvent,
  clockEntrySeconds,
  completeStripeWebhookEvent,
  failStripeWebhookEvent,
  isCollectedPaymentStatus,
  normalizePaymentJobLink,
  normalizeStripeRefundState,
  parseJobContributionRange,
  summarizeReceivables,
  syncOperationalAccountingSources
} from "../finance-operational-accounting.js";

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("Stripe refund state preserves partial and full cumulative cents", () => {
  assert.deepEqual(normalizeStripeRefundState({
    paymentAmountCents: 10_000,
    providerRefundedCents: 2_500,
    providerFullyRefunded: false
  }), {
    refunded_amount_cents: 2_500,
    refund_amount_known: true,
    status: "partially_refunded"
  });
  assert.equal(normalizeStripeRefundState({
    paymentAmountCents: 10_000,
    providerRefundedCents: 12_000,
    providerFullyRefunded: true
  }).refunded_amount_cents, 10_000);
  assert.equal(normalizeStripeRefundState({
    paymentAmountCents: 10_000,
    providerRefundedCents: 10_000
  }).status, "refunded");
});

test("collected status recognizes gross payment evidence without treating pending as cash", () => {
  for (const status of ["succeeded", "paid", "partially_refunded", "refunded"]) {
    assert.equal(isCollectedPaymentStatus(status), true);
  }
  for (const status of ["pending", "failed", "canceled", "action_required", "payment_method_required"]) {
    assert.equal(isCollectedPaymentStatus(status), false);
  }
});

test("receivables use explicit net linked payments and reopen after a partial refund", () => {
  const receivable = buildReceivableSnapshot({
    asOf: "2026-08-19",
    job: { id: "job_1", price_cents: 20_000, finished_at: "2026-08-01T15:00:00Z" },
    payments: [
      { status: "partially_refunded", amount_cents: 20_000, refunded_amount_cents: 5_000, refund_amount_known: true, paid_at: "2026-08-02T12:00:00Z" },
      { status: "pending", amount_cents: 5_000, refunded_amount_cents: 0, refund_amount_known: true }
    ]
  });
  assert.equal(receivable.gross_payment_cents, 20_000);
  assert.equal(receivable.refund_cents, 5_000);
  assert.equal(receivable.net_payment_cents, 15_000);
  assert.equal(receivable.outstanding_cents, 5_000);
  assert.equal(receivable.status, "partial");
  assert.equal(receivable.age_days, 18);
});

test("receivables disclose overpayment credit and never return negative outstanding", () => {
  const receivable = buildReceivableSnapshot({
    asOf: "2026-08-19",
    job: { id: "job_2", price_cents: 10_000, finished_at: "2026-08-19T10:00:00Z" },
    payments: [
      { status: "succeeded", amount_cents: 12_500, refunded_amount_cents: 0, refund_amount_known: true, paid_at: "2026-08-19T11:00:00Z" }
    ]
  });
  assert.equal(receivable.outstanding_cents, 0);
  assert.equal(receivable.credit_cents, 2_500);
  assert.equal(receivable.status, "credit");
});

test("legacy refunds with unknown amount fail closed instead of appearing paid", () => {
  const receivable = buildReceivableSnapshot({
    asOf: "2026-08-19",
    job: { id: "job_3", price_cents: 10_000, finished_at: "2026-08-10T10:00:00Z" },
    payments: [
      { status: "refunded", amount_cents: 10_000, refunded_amount_cents: 0, refund_amount_known: false, paid_at: null }
    ]
  });
  assert.equal(receivable.net_payment_cents, 0);
  assert.equal(receivable.outstanding_cents, 10_000);
  assert.equal(receivable.refund_amount_unknown_count, 1);
  assert.equal(receivable.status, "unpaid");
});

test("unpriced completed jobs remain visible without fabricated receivable cents", () => {
  const receivable = buildReceivableSnapshot({
    asOf: "2026-08-19",
    job: { id: "job_4", price_cents: null, finished_at: "2026-08-10T10:00:00Z" },
    payments: []
  });
  assert.equal(receivable.has_price, false);
  assert.equal(receivable.amount_cents, 0);
  assert.equal(receivable.status, "unpriced");
});

test("receivable summary keeps aging buckets, credits, and coverage exact", () => {
  const summary = summarizeReceivables([
    { has_price: true, amount_cents: 10_000, net_payment_cents: 0, outstanding_cents: 10_000, credit_cents: 0, age_days: 15, status: "unpaid", payment_timing_unknown_count: 0, refund_amount_unknown_count: 0 },
    { has_price: true, amount_cents: 20_000, net_payment_cents: 22_000, outstanding_cents: 0, credit_cents: 2_000, age_days: 70, status: "credit", payment_timing_unknown_count: 1, refund_amount_unknown_count: 0 },
    { has_price: false, amount_cents: 0, net_payment_cents: 0, outstanding_cents: 0, credit_cents: 0, age_days: 95, status: "unpriced", payment_timing_unknown_count: 0, refund_amount_unknown_count: 1 }
  ]);
  assert.equal(summary.receivable_cents, 30_000);
  assert.equal(summary.outstanding_cents, 10_000);
  assert.equal(summary.credit_cents, 2_000);
  assert.equal(summary.days_1_30_cents, 10_000);
  assert.equal(summary.credit_job_count, 1);
  assert.equal(summary.unpriced_job_count, 1);
  assert.equal(summary.payment_timing_unknown_count, 1);
  assert.equal(summary.refund_amount_unknown_count, 1);
});

test("payment job links enforce stale versions, same customer, and audited unlink reasons", () => {
  const payment = { contact_id: "contact_1", job_id: null, accounting_link_version: 2 };
  const job = { id: "job_1", contact_id: "contact_1" };
  assert.deepEqual(normalizePaymentJobLink({
    payment, job, body: { expected_version: 2, job_id: "job_1" }
  }), { expected_version: 2, job_id: "job_1", reason: null, changed: true });

  assert.throws(() => normalizePaymentJobLink({
    payment, job, body: { expected_version: 1, job_id: "job_1" }
  }), (error) => error.code === "payment_job_link_stale" && error.current_version === 2);

  assert.throws(() => normalizePaymentJobLink({
    payment, job: { id: "job_1", contact_id: "contact_2" }, body: { expected_version: 2, job_id: "job_1" }
  }), (error) => error.code === "payment_job_contact_mismatch");

  assert.throws(() => normalizePaymentJobLink({
    payment: { ...payment, job_id: "job_1" }, body: { expected_version: 2, job_id: null }
  }), (error) => error.code === "payment_job_link_reason_required");
});

test("operational source sync is company-scoped, stable, and skips unchanged writes", async () => {
  const calls = [];
  await syncOperationalAccountingSources({
    async query(sql, values) {
      calls.push({ sql, values });
      return { rows: [], rowCount: 0 };
    }
  }, "company_1");
  assert.equal(calls.length, 4);
  assert.ok(calls.every((call) => call.values[0] === "company_1"));
  assert.match(calls[0].sql, /'job_receivable'/);
  assert.match(calls[1].sql, /'payment'/);
  assert.match(calls[2].sql, /'refund'/);
  assert.match(calls[0].sql, /finished_at IS NOT NULL/);
  assert.match(calls[0].sql, /price_cents >= 0/);
  assert.match(calls[0].sql, /ON CONFLICT\(company_id, source_type, source_id\)/);
  assert.ok(calls.slice(0, 3).every((call) => /WHERE \(finance_operational_sources\.job_id/.test(call.sql)));
  assert.match(calls[3].sql, /status = 'removed'/);
});

test("Stripe webhook claims distinguish first processing, duplicates, failures, and retries", async () => {
  const state = new Map();
  const fakePool = {
    async query(sql, values) {
      const id = values[0];
      if (sql.includes("INSERT INTO stripe_webhook_events")) {
        const current = state.get(id);
        if (!current || current.processing_state === "failed") {
          const next = { processing_state: "processing", attempt_count: (current?.attempt_count || 0) + 1 };
          state.set(id, next);
          return { rowCount: 1, rows: [next] };
        }
        return { rowCount: 0, rows: [] };
      }
      if (sql.includes("SELECT processing_state")) {
        return { rowCount: state.has(id) ? 1 : 0, rows: state.has(id) ? [state.get(id)] : [] };
      }
      if (sql.includes("processing_state = 'processed'")) {
        state.set(id, { ...state.get(id), processing_state: "processed" });
        return { rowCount: 1, rows: [] };
      }
      if (sql.includes("processing_state = 'failed'")) {
        state.set(id, { ...state.get(id), processing_state: "failed" });
        return { rowCount: 1, rows: [] };
      }
      throw new Error("unexpected query");
    }
  };
  const event = { id: "evt_1", type: "payment_intent.succeeded", account: "acct_1" };
  assert.equal((await claimStripeWebhookEvent(fakePool, event)).claimed, true);
  assert.equal((await claimStripeWebhookEvent(fakePool, event)).in_progress, true);
  await completeStripeWebhookEvent(fakePool, event.id);
  assert.equal((await claimStripeWebhookEvent(fakePool, event)).duplicate, true);

  const failed = { id: "evt_2", type: "charge.refunded", account: "acct_1" };
  await claimStripeWebhookEvent(fakePool, failed);
  await failStripeWebhookEvent(fakePool, failed.id, new Error("temporary"));
  const retry = await claimStripeWebhookEvent(fakePool, failed);
  assert.equal(retry.claimed, true);
  assert.equal(retry.attempt_count, 2);
});

test("job contribution ranges use valid inclusive dates and stay bounded", () => {
  assert.deepEqual(parseJobContributionRange("2025-01-01", "2027-01-01"), {
    start_date: "2025-01-01",
    end_date: "2027-01-01"
  });
  assert.throws(
    () => parseJobContributionRange("2025-01-01", "2027-01-02"),
    (error) => error.code === "accounting_range_too_large"
  );
  assert.throws(
    () => parseJobContributionRange("2026-08-20", "2026-08-19"),
    (error) => error.code === "accounting_range_invalid"
  );
  assert.throws(
    () => parseJobContributionRange("2026-02-30", "2026-03-01"),
    (error) => error.code === "start_date_invalid"
  );
});

test("direct job contribution includes only comparable exact source cents", () => {
  const report = buildJobContributionSummary({
    jobs: [
      { price_cents: 50_000, material_cost_cents: 12_000 },
      { price_cents: 20_000, material_cost_cents: null },
      { price_cents: -1, material_cost_cents: 2_000 },
      { price_cents: 30_000, material_cost_cents: 35_000 }
    ]
  });
  assert.deepEqual(report.summary, {
    job_count: 4,
    price_known_count: 3,
    material_known_count: 3,
    comparable_job_count: 2,
    price_unknown_count: 1,
    material_unknown_count: 1,
    known_revenue_cents: 100_000,
    known_material_cents: 49_000,
    comparable_revenue_cents: 80_000,
    comparable_material_cents: 47_000,
    direct_contribution_cents: 33_000
  });
});

test("operational cost coverage excludes forecasts, invalid facts, open time, and disapproved time", () => {
  const report = buildJobContributionSummary({
    mileageLogs: [
      { status: "approved", reimbursement_cents: 4_200 },
      { status: "paid", reimbursement_cents: 1_800 },
      { status: "ready_for_review", reimbursement_cents: 2_000 },
      { status: "approved", reimbursement_cents: -500 }
    ],
    timeEntries: [
      { start_at: "2026-08-19T09:00:00Z", end_at: "2026-08-19T17:00:00Z", break_seconds: 3_600, manual_status: "approved" },
      { start_at: "2026-08-19T18:00:00Z", end_at: null, break_seconds: 0, manual_status: "approved" },
      { start_at: "2026-08-19T09:00:00Z", end_at: "2026-08-19T10:00:00Z", break_seconds: 0, manual_status: "disapproved" },
      { start_at: "2026-08-19T11:00:00Z", end_at: "2026-08-19T10:00:00Z", break_seconds: 0, manual_status: "approved" }
    ]
  });
  assert.equal(clockEntrySeconds({
    start_at: "2026-08-19T09:00:00Z",
    end_at: "2026-08-19T17:00:00Z",
    break_seconds: 3_600
  }), 25_200);
  assert.deepEqual(report.operational_costs, {
    approved_mileage_log_count: 2,
    approved_mileage_reimbursement_cents: 6_000,
    invalid_approved_mileage_log_count: 1,
    excluded_mileage_log_count: 1,
    completed_clock_entry_count: 1,
    completed_clock_seconds: 25_200,
    invalid_completed_clock_entry_count: 1,
    open_clock_entry_count: 1,
    disapproved_clock_entry_count: 1
  });
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
if (!process.exitCode) console.log(`PASS finance operational accounting (${passed}/${tests.length})`);
