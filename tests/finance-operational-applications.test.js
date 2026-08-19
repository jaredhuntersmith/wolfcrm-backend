import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import {
  buildOperationalApplicationJournalInput,
  evaluateCustomerCreditApplication,
  evaluatePaymentApplication,
  evaluateRefundApplication,
  normalizeApplicationAllocation,
  parseOperationalApplicationRange,
  planRefundRevision
} from "../finance-operational-applications.js";

const IDs = {
  source: "11111111-1111-4111-8111-111111111111",
  payment: "22222222-2222-4222-8222-222222222222",
  application: "33333333-3333-4333-8333-333333333333",
  revision: "44444444-4444-4444-8444-444444444444",
  ar: "55555555-5555-4555-8555-555555555555",
  credit: "66666666-6666-4666-8666-666666666666",
  clearing: "77777777-7777-4777-8777-777777777777",
  request: "88888888-8888-4888-8888-888888888888"
};

const accounts = {
  accountsReceivable: { id: IDs.ar, account_type: "asset", system_key: "accounts_receivable", active: true },
  customerCredits: { id: IDs.credit, account_type: "liability", system_key: "customer_credits", active: true },
  clearing: { id: IDs.clearing, account_type: "asset", system_key: "payment_clearing", active: true }
};

function paymentInput(overrides = {}) {
  const source = {
    id: IDs.source,
    source_type: "payment",
    source_id: IDs.payment,
    payment_record_id: IDs.payment,
    job_id: "job-1",
    status: "succeeded",
    amount_cents: 12_500,
    currency: "usd",
    occurred_at: "2026-08-18T15:00:00.000Z",
    entry_date: "2026-08-18",
    source_version: 2,
    removed_at: null
  };
  return {
    source,
    payment: { id: IDs.payment, job_id: "job-1" },
    accounts,
    receivableAuthority: { posted: true, open_cents: 10_000 },
    allocation: { accounts_receivable_cents: 10_000, customer_credit_cents: 2_500 },
    ...overrides
  };
}

test("refund revision planning preserves only positive cumulative deltas", () => {
  assert.deepEqual(planRefundRevision({ previousCumulativeCents: 2_500, nextCumulativeCents: 7_000 }), {
    cumulative_refunded_cents: 7_000,
    delta_refunded_cents: 4_500
  });
  assert.equal(planRefundRevision({ previousCumulativeCents: 7_000, nextCumulativeCents: 7_000 }), null);
  assert.equal(planRefundRevision({ previousCumulativeCents: 7_000, nextCumulativeCents: 6_000 }), null);
  assert.equal(planRefundRevision({ previousCumulativeCents: 0, nextCumulativeCents: 1_000, refundAmountKnown: false }), null);
});

test("allocation normalization requires exact reconciled cents", () => {
  assert.deepEqual(normalizeApplicationAllocation({ amountCents: 12_500, accountsReceivableCents: 10_000, customerCreditCents: 2_500 }), {
    amount_cents: 12_500,
    accounts_receivable_cents: 10_000,
    customer_credit_cents: 2_500
  });
  assert.throws(
    () => normalizeApplicationAllocation({ amountCents: 12_500, accountsReceivableCents: 10_000, customerCreditCents: 2_499 }),
    (error) => error.code === "operational_application_allocation_unbalanced"
  );
});

test("payment application debits clearing and explicitly credits A/R and customer credit", () => {
  const evaluation = evaluatePaymentApplication(paymentInput());
  assert.equal(evaluation.eligible, true);
  assert.deepEqual(evaluation.journal_preview.lines.map((line) => [line.chart_account_id, line.debit_cents, line.credit_cents]), [
    [IDs.clearing, 12_500, 0],
    [IDs.ar, 0, 10_000],
    [IDs.credit, 0, 2_500]
  ]);
  const journal = buildOperationalApplicationJournalInput({
    kind: "payment",
    evaluation,
    applicationID: IDs.application,
    version: 1,
    clientRequestID: IDs.request,
    reason: "Reviewed exact collection allocation"
  });
  assert.equal(journal.entry_kind, "payment_application");
  assert.equal(journal.source_type, "finance_operational_application");
  assert.equal(journal.source_id, IDs.application);
  assert.equal(journal.entry_date, "2026-08-18");
});

test("payment application fails closed for excess A/R and dependent allocation floors", () => {
  const excess = evaluatePaymentApplication(paymentInput({
    receivableAuthority: { posted: true, open_cents: 9_999 }
  }));
  assert.ok(excess.blockers.some((item) => item.code === "payment_ar_capacity_exceeded"));
  const dependent = evaluatePaymentApplication(paymentInput({
    application: {
      id: IDs.application, kind: "payment", status: "posted", journal_entry_id: IDs.request,
      version: 1, accounts_receivable_cents: 10_000, customer_credit_cents: 2_500,
      refund_ar_cents: 1_000, source_fingerprint: "old"
    },
    allocation: { accounts_receivable_cents: 500, customer_credit_cents: 12_000 },
    dependentRefundCents: 1_500,
    dependentCreditCents: 1_500,
    receivableAuthority: { posted: true, open_cents: 12_500 }
  }));
  assert.ok(dependent.blockers.some((item) => item.code === "payment_ar_dependency_floor"));
  assert.ok(dependent.blockers.some((item) => item.code === "payment_dependent_credit_invalid"));
  assert.equal(dependent.can_void, false);
});

test("source fingerprints ignore live remaining capacity but retain reviewed source authority", () => {
  const base = evaluatePaymentApplication(paymentInput());
  const laterCapacity = evaluatePaymentApplication(paymentInput({
    receivableAuthority: { posted: true, open_cents: 12_500 },
    dependentRefundCents: 500,
    dependentCreditCents: 250
  }));
  assert.equal(base.source_fingerprint, laterCapacity.source_fingerprint);
  const changedSource = evaluatePaymentApplication(paymentInput({
    source: { ...paymentInput().source, source_version: 3 }
  }));
  assert.notEqual(base.source_fingerprint, changedSource.source_fingerprint);
});

test("refund application posts only the revision delta with opposite clearing sides", () => {
  const evaluation = evaluateRefundApplication({
    revision: {
      id: IDs.revision, payment_record_id: IDs.payment, cumulative_refunded_cents: 4_000,
      delta_refunded_cents: 1_500, occurred_at: "2026-08-19T12:00:00Z", entry_date: "2026-08-19",
      event_coverage: "observed", version: 1
    },
    originApplication: {
      id: IDs.application, kind: "payment", job_id: "job-1", status: "posted",
      journal_entry_id: IDs.request, version: 1, accounts_receivable_cents: 10_000, customer_credit_cents: 2_500
    },
    accounts,
    allocation: { accounts_receivable_cents: 1_000, customer_credit_cents: 500 },
    priorRefundARCents: 2_000,
    priorRefundCreditCents: 500,
    usedCustomerCreditCents: 1_000,
    receivableAuthority: { posted: true, open_cents: 1_000 }
  });
  assert.equal(evaluation.eligible, true);
  assert.deepEqual(evaluation.journal_preview.lines.map((line) => [line.chart_account_id, line.debit_cents, line.credit_cents]), [
    [IDs.ar, 1_000, 0],
    [IDs.credit, 500, 0],
    [IDs.clearing, 0, 1_500]
  ]);
  assert.equal(evaluation.source_snapshot.cumulative_refunded_cents, 4_000);
  assert.equal(evaluation.source_snapshot.amount_cents, 1_500);
});

test("refund category capacity accounts for prior refunds and consumed credit", () => {
  const evaluation = evaluateRefundApplication({
    revision: { id: IDs.revision, payment_record_id: IDs.payment, cumulative_refunded_cents: 3_000, delta_refunded_cents: 1_000, occurred_at: "2026-08-19T12:00:00Z", entry_date: "2026-08-19", event_coverage: "observed", version: 1 },
    originApplication: { id: IDs.application, kind: "payment", job_id: "job-1", status: "posted", journal_entry_id: IDs.request, version: 1, accounts_receivable_cents: 10_000, customer_credit_cents: 2_500 },
    accounts,
    allocation: { accounts_receivable_cents: 0, customer_credit_cents: 1_000 },
    priorRefundCreditCents: 1_000,
    usedCustomerCreditCents: 1_000
  });
  assert.ok(evaluation.blockers.some((item) => item.code === "refund_credit_capacity_exceeded"));
});

test("refund source fingerprint stays stable as later revisions consume remaining capacity", () => {
  const input = {
    revision: { id: IDs.revision, payment_record_id: IDs.payment, cumulative_refunded_cents: 3_000, delta_refunded_cents: 1_000, occurred_at: "2026-08-19T12:00:00Z", entry_date: "2026-08-19", event_coverage: "observed", version: 1 },
    originApplication: { id: IDs.application, kind: "payment", job_id: "job-1", status: "posted", journal_entry_id: IDs.request, version: 1, accounts_receivable_cents: 10_000, customer_credit_cents: 2_500 },
    accounts,
    allocation: { accounts_receivable_cents: 1_000, customer_credit_cents: 0 },
    receivableAuthority: { posted: true, open_cents: 1_000 }
  };
  const first = evaluateRefundApplication(input);
  const later = evaluateRefundApplication({ ...input, priorRefundARCents: 2_000, usedCustomerCreditCents: 1_000, receivableAuthority: { posted: true, open_cents: 5_000 } });
  assert.equal(first.source_fingerprint, later.source_fingerprint);
});

test("customer credit moves liability to same-contact posted A/R without clearing", () => {
  const evaluation = evaluateCustomerCreditApplication({
    originApplication: { id: IDs.application, kind: "payment", status: "posted", journal_entry_id: IDs.request, version: 2, entry_date: "2026-08-18" },
    targetJob: { id: "job-2" },
    accounts,
    entryDate: "2026-08-19",
    amountCents: 2_000,
    availableCustomerCreditCents: 2_500,
    targetReceivableAuthority: { posted: true, open_cents: 3_000 },
    sameContact: true,
    companyToday: "2026-08-19"
  });
  assert.equal(evaluation.eligible, true);
  assert.deepEqual(evaluation.journal_preview.lines.map((line) => [line.chart_account_id, line.debit_cents, line.credit_cents]), [
    [IDs.credit, 2_000, 0],
    [IDs.ar, 0, 2_000]
  ]);
  assert.equal(evaluation.journal_preview.lines.some((line) => line.chart_account_id === IDs.clearing), false);
});

test("customer credit blocks mismatched contacts, future dates, and both capacity overruns", () => {
  const evaluation = evaluateCustomerCreditApplication({
    originApplication: { id: IDs.application, kind: "payment", status: "posted", journal_entry_id: IDs.request, version: 2, entry_date: "2026-08-18" },
    targetJob: { id: "job-2" }, accounts, entryDate: "2026-08-20", amountCents: 3_000,
    availableCustomerCreditCents: 2_000, targetReceivableAuthority: { posted: true, open_cents: 2_500 },
    sameContact: false, companyToday: "2026-08-19"
  });
  assert.deepEqual(new Set(evaluation.blockers.map((item) => item.code)), new Set([
    "credit_target_contact_mismatch", "credit_origin_capacity_exceeded", "credit_target_capacity_exceeded", "credit_date_future"
  ]));
});

test("application ranges are inclusive and bounded", () => {
  assert.deepEqual(parseOperationalApplicationRange("2025-01-01", "2027-01-01"), { start_date: "2025-01-01", end_date: "2027-01-01" });
  assert.throws(() => parseOperationalApplicationRange("2025-01-01", "2027-01-02"), (error) => error.code === "operational_application_range_too_large");
  assert.throws(() => parseOperationalApplicationRange("2026-02-30", "2026-03-01"), (error) => error.code === "start_date_invalid");
});

test("schema and routes preserve sources and keep settlement out of this phase", () => {
  const source = fs.readFileSync(new URL("../finance-operational-applications.js", import.meta.url), "utf8");
  const ledger = fs.readFileSync(new URL("../finance-general-ledger.js", import.meta.url), "utf8");
  const accounting = fs.readFileSync(new URL("../finance-accounting.js", import.meta.url), "utf8");
  const backend = fs.readFileSync(new URL("../index.js", import.meta.url), "utf8");
  assert.match(source, /finance_payment_refund_revisions/);
  assert.match(source, /delta_refunded_cents/);
  assert.match(source, /event_coverage IN \('observed','current_baseline'\)/);
  assert.match(source, /finance_payment_refund_revision_capture/);
  assert.match(source, /UNIQUE\(company_id, payment_record_id, cumulative_refunded_cents\)/);
  assert.match(source, /finance_operational_applications_payment_source_idx/);
  assert.match(source, /finance_operational_applications_refund_revision_idx/);
  assert.match(source, /SELECT id FROM companies WHERE id=\$1 FOR UPDATE/);
  assert.match(source, /\/api\/finance\/accounting\/operational-applications/);
  assert.doesNotMatch(source, /UPDATE finance_operational_sources\s+SET/);
  assert.doesNotMatch(source, /stripe\.(paymentIntents|charges|refunds|payouts)/);
  assert.doesNotMatch(source, /UPDATE finance_transactions\s+SET/);
  assert.match(ledger, /payment_application/);
  assert.match(ledger, /refund_application/);
  assert.match(ledger, /customer_credit_application/);
  assert.match(ledger, /finance_operational_application/);
  assert.match(accounting, /system_key: "payment_clearing"/);
  assert.match(backend, /refunded_at IS NULL AND \$4::timestamptz IS NOT NULL/);
});
