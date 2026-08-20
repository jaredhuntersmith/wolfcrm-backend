import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {
  buildStripeSettlementJournalInput,
  buildStripeSettlementReversalInput,
  canBindStripeRefundTransition,
  evaluateStripeSettlement,
  evaluateStripeSettlementBank,
  installFinanceStripeSettlementRoutes,
  normalizeStripeBalanceMembers,
  normalizeStripePayout,
  normalizeStripeSettlementPostRequest,
  normalizeStripeSettlementVoidRequest,
  parseStripeSettlementRange
} from "../finance-stripe-settlements.js";

const IDs = {
  settlement: "00000000-0000-4000-8000-000000000301",
  request: "00000000-0000-4000-8000-000000000302",
  transaction: "00000000-0000-4000-8000-000000000303",
  financeAccount: "00000000-0000-4000-8000-000000000304",
  mapping: "00000000-0000-4000-8000-000000000305",
  bankChart: "00000000-0000-4000-8000-000000000306",
  clearing: "00000000-0000-4000-8000-000000000307",
  fees: "00000000-0000-4000-8000-000000000308",
  receivable: "00000000-0000-4000-8000-000000000309",
  credits: "00000000-0000-4000-8000-00000000030a",
  paymentApp: "00000000-0000-4000-8000-00000000030b",
  refundApp: "00000000-0000-4000-8000-00000000030c",
  journal: "00000000-0000-4000-8000-00000000030d"
};

function providerPayout(overrides = {}) {
  return {
    id: "po_exact_123",
    amount: 7_700,
    currency: "usd",
    automatic: true,
    method: "standard",
    status: "paid",
    reconciliation_status: "completed",
    arrival_date: 1_776_038_400,
    created: 1_775_952_000,
    ...overrides
  };
}

function rawMembers(overrides = {}) {
  return [
    {
      id: "txn_charge_123", type: "charge", source: "ch_exact_123",
      amount: 10_000, fee: 300, net: 9_700, currency: "usd", status: "available",
      ...overrides.charge
    },
    {
      id: "txn_refund_123", type: "refund", source: "re_exact_123",
      amount: -2_000, fee: 0, net: -2_000, currency: "usd", status: "available",
      ...overrides.refund
    }
  ];
}

function accounts() {
  return {
    accountsReceivable: { id: IDs.receivable, account_type: "asset", system_key: "accounts_receivable", active: true },
    customerCredits: { id: IDs.credits, account_type: "liability", system_key: "customer_credits", active: true },
    clearing: { id: IDs.clearing, code: "1150", name: "Payment Clearing", account_type: "asset", system_key: "payment_clearing", active: true },
    fees: { id: IDs.fees, code: "6700", name: "Merchant & Bank Fees", account_type: "expense", system_key: "merchant_bank_fees", active: true }
  };
}

function bankEvidence(overrides = {}) {
  return {
    transaction: {
      id: IDs.transaction,
      account_id: IDs.financeAccount,
      finance_account_name: "Operating Checking",
      finance_account_currency: "usd",
      finance_account_archived_at: null,
      status: "posted",
      direction: "income",
      amount_cents: 7_700,
      transaction_date: "2026-04-15",
      pending: false,
      removed_at: null,
      reconciliation_status: "reconciled",
      accounting_version: 4,
      iso_currency_code: "USD",
      ...overrides.transaction
    },
    mapping: overrides.mapping === null ? null : {
      id: IDs.mapping,
      chart_account_id: IDs.bankChart,
      version: 2,
      code: "1010",
      name: "Operating Checking",
      account_type: "asset",
      system_key: null,
      active: true,
      ...overrides.mapping
    },
    splits: overrides.splits || [{
      chart_account_id: IDs.clearing,
      amount_cents: 7_700,
      account_type: "asset",
      system_key: "payment_clearing",
      active: true
    }],
    individualPosting: overrides.individualPosting || null,
    transferMembership: overrides.transferMembership || null,
    otherSettlement: overrides.otherSettlement || null
  };
}

function resolvedMembers(normalized) {
  return normalized.members.map((member) => ({
    ...member,
    payment_record_id: member.type === "charge" ? "00000000-0000-4000-8000-000000000311" : "00000000-0000-4000-8000-000000000311",
    refund_revision_id: member.type === "refund" ? "00000000-0000-4000-8000-000000000312" : null,
    application_id: member.type === "charge" ? IDs.paymentApp : IDs.refundApp,
    application_kind: member.type === "charge" ? "payment" : "refund",
    application_version: member.type === "charge" ? 2 : 1,
    eligible: true,
    blockers: []
  }));
}

test("only automatic standard paid completed USD payouts are eligible", () => {
  const payout = normalizeStripePayout(providerPayout());
  assert.equal(payout.eligible, true);
  assert.equal(payout.amount_cents, 7_700);
  const blocked = normalizeStripePayout(providerPayout({ automatic: false, method: "instant", status: "pending", reconciliation_status: "in_progress", currency: "eur" }));
  const codes = new Set(blocked.blockers.map((item) => item.code));
  for (const code of ["stripe_payout_not_automatic", "stripe_payout_method_unsupported", "stripe_payout_not_paid", "stripe_payout_reconciliation_incomplete", "stripe_payout_currency_unsupported"]) {
    assert.ok(codes.has(code), code);
  }
});

test("exact charge and refund membership reconciles signed gross fee and net", () => {
  const normalized = normalizeStripeBalanceMembers(rawMembers(), "usd");
  assert.equal(normalized.eligible, true);
  assert.equal(normalized.gross_cents, 8_000);
  assert.equal(normalized.fee_cents, 300);
  assert.equal(normalized.net_cents, 7_700);
  assert.deepEqual(normalized.members.map((item) => item.type), ["charge", "refund"]);
});

test("refund evidence binds only while observing the exact cumulative transition", () => {
  assert.equal(canBindStripeRefundTransition({
    observedCumulativeTransition: true,
    cumulativeRefundedCents: 2_000,
    refundAmountCents: 2_000
  }), true);
  assert.equal(canBindStripeRefundTransition({
    observedCumulativeTransition: false,
    cumulativeRefundedCents: 4_000,
    refundAmountCents: 2_000
  }), false);
});

test("unsupported types, unavailable items, currency, sign, and provider math fail closed", () => {
  const normalized = normalizeStripeBalanceMembers(rawMembers({
    charge: { type: "adjustment", status: "pending", currency: "eur", amount: -1, fee: 4, net: 2 }
  }), "usd");
  const codes = new Set(normalized.blockers.map((item) => item.code));
  for (const code of ["stripe_balance_type_unsupported", "stripe_balance_not_available", "stripe_balance_currency_mismatch", "stripe_balance_math_invalid"]) {
    assert.ok(codes.has(code), code);
  }
});

test("an explicit reconciled clearing deposit produces exact bank fee and clearing lines", () => {
  const payout = normalizeStripePayout(providerPayout());
  const normalized = normalizeStripeBalanceMembers(rawMembers(), "usd");
  const result = evaluateStripeSettlement({
    payout,
    normalizedMembers: normalized,
    members: resolvedMembers(normalized),
    bankEvidence: bankEvidence(),
    accounts: accounts()
  });
  assert.equal(result.eligible, true);
  assert.equal(result.review_state, "ready");
  assert.deepEqual(result.journal_preview.lines.map((line) => [line.chart_account_id, line.debit_cents, line.credit_cents]), [
    [IDs.bankChart, 7_700, 0],
    [IDs.fees, 300, 0],
    [IDs.clearing, 0, 8_000]
  ]);
  assert.equal(result.source_snapshot.members[1].operational_application_id, IDs.refundApp);
});

test("zero-fee payouts omit the fee line", () => {
  const payout = normalizeStripePayout(providerPayout({ amount: 10_000 }));
  const normalized = normalizeStripeBalanceMembers([{
    id: "txn_charge_zero_fee", type: "charge", source: "ch_zero_fee",
    amount: 10_000, fee: 0, net: 10_000, currency: "usd", status: "available"
  }], "usd");
  const result = evaluateStripeSettlement({
    payout,
    normalizedMembers: normalized,
    members: resolvedMembers(normalized),
    bankEvidence: bankEvidence({
      transaction: { amount_cents: 10_000 },
      splits: [{ chart_account_id: IDs.clearing, amount_cents: 10_000, account_type: "asset", system_key: "payment_clearing", active: true }]
    }),
    accounts: accounts()
  });
  assert.equal(result.eligible, true);
  assert.equal(result.journal_preview.lines.length, 2);
});

test("bank authority requires explicit exact clearing classification and no competing posting", () => {
  const payout = normalizeStripePayout(providerPayout());
  const result = evaluateStripeSettlementBank({
    payout,
    accounts: accounts(),
    bankEvidence: bankEvidence({
      transaction: { reconciliation_status: "cleared", amount_cents: 7_701 },
      splits: [{ chart_account_id: IDs.fees, amount_cents: 7_701, account_type: "expense", system_key: "merchant_bank_fees", active: true }],
      individualPosting: { status: "posted" },
      transferMembership: { pair_id: IDs.settlement },
      otherSettlement: { id: IDs.settlement }
    })
  });
  const codes = new Set(result.blockers.map((item) => item.code));
  for (const code of ["stripe_settlement_bank_not_reconciled", "stripe_settlement_bank_amount_mismatch", "stripe_settlement_bank_classification_invalid", "stripe_settlement_bank_individual_posting", "stripe_settlement_bank_transfer_membership", "stripe_settlement_bank_already_used"]) {
    assert.ok(codes.has(code), code);
  }
});

test("settlement journal and reversal retain source-owned authority", () => {
  const payout = normalizeStripePayout(providerPayout());
  const normalized = normalizeStripeBalanceMembers(rawMembers(), "usd");
  const evaluation = evaluateStripeSettlement({ payout, normalizedMembers: normalized, members: resolvedMembers(normalized), bankEvidence: bankEvidence(), accounts: accounts() });
  const journal = buildStripeSettlementJournalInput({ evaluation, settlementID: IDs.settlement, version: 1, clientRequestID: IDs.request, reason: "Reviewed exact payout" });
  assert.equal(journal.entry_kind, "stripe_settlement");
  assert.equal(journal.source_type, "finance_stripe_settlement");
  const reversal = buildStripeSettlementReversalInput({ original: { ...journal, id: IDs.journal }, originalLines: journal.lines, settlementID: IDs.settlement, version: 2, clientRequestID: IDs.request, reason: "Void exact payout" });
  assert.equal(reversal.reversal_of_entry_id, IDs.journal);
  assert.deepEqual(reversal.lines.map((line) => [line.debit_cents, line.credit_cents]), journal.lines.map((line) => [line.credit_cents, line.debit_cents]));
});

test("post and void requests require stable IDs, exact versions, fingerprints, and reasons", () => {
  const post = normalizeStripeSettlementPostRequest({
    client_request_id: IDs.request,
    bank_transaction_id: IDs.transaction,
    expected_settlement_version: 0,
    expected_bank_accounting_version: 4,
    expected_mapping_version: 2,
    expected_source_fingerprint: "a".repeat(64),
    reason: "Reviewed exact payout"
  }, "po_exact_123");
  assert.equal(post.request_fingerprint.length, 64);
  const voidRequest = normalizeStripeSettlementVoidRequest({ client_request_id: IDs.request, expected_settlement_version: 1, reason: "Void duplicate bank deposit" }, "po_exact_123");
  assert.equal(voidRequest.expected_settlement_version, 1);
  assert.throws(() => normalizeStripeSettlementPostRequest({ ...post, reason: "" }, "po_exact_123"), (error) => error.code === "stripe_settlement_reason_required");
});

test("settlement ranges are inclusive and bounded", () => {
  assert.deepEqual(parseStripeSettlementRange("2025-01-01", "2027-01-01"), { start_date: "2025-01-01", end_date: "2027-01-01" });
  assert.throws(() => parseStripeSettlementRange("2026-08-20", "2026-08-19"), (error) => error.code === "stripe_settlement_range_invalid");
  assert.throws(() => parseStripeSettlementRange("2025-01-01", "2027-01-02"), (error) => error.code === "stripe_settlement_range_too_large");
});

test("schema and routes are additive, tenant-scoped, bounded, audited, and never auto-post", () => {
  const source = fs.readFileSync(new URL("../finance-stripe-settlements.js", import.meta.url), "utf8");
  const accountingSource = fs.readFileSync(new URL("../finance-accounting.js", import.meta.url), "utf8");
  const bankSource = fs.readFileSync(new URL("../finance-bank-sources.js", import.meta.url), "utf8");
  const applicationsSource = fs.readFileSync(new URL("../finance-operational-applications.js", import.meta.url), "utf8");
  const journalSource = fs.readFileSync(new URL("../finance-general-ledger.js", import.meta.url), "utf8");
  const webhookSource = fs.readFileSync(new URL("../index.js", import.meta.url), "utf8");
  assert.match(source, /CREATE TABLE IF NOT EXISTS finance_stripe_refund_evidence/);
  assert.match(source, /CREATE TABLE IF NOT EXISTS finance_stripe_settlements/);
  assert.match(source, /CREATE TABLE IF NOT EXISTS finance_stripe_settlement_members/);
  assert.match(source, /CREATE TABLE IF NOT EXISTS finance_stripe_settlement_audit/);
  assert.match(source, /finance_stripe_settlement_members_active_balance_idx/);
  assert.match(source, /finance_stripe_settlement_members_active_application_idx/);
  assert.match(source, /stripe\.balanceTransactions\.list/);
  assert.match(source, /stripeAccount: connectedAccountID/);
  assert.match(source, /source_snapshot->'payout'->>'arrival_date'/);
  assert.match(source, /SELECT id FROM companies WHERE id=\$1 FOR UPDATE/);
  assert.doesNotMatch(source, /UPDATE finance_transactions\s+SET/);
  assert.doesNotMatch(source, /UPDATE finance_transaction_splits\s+SET/);
  assert.match(accountingSource, /stripe_settlement_bank_accounting_locked/);
  assert.match(bankSource, /stripe_settlement_bank_mapping_locked/);
  assert.match(applicationsSource, /stripe_settlement_application_locked/);
  assert.match(journalSource, /finance_stripe_settlement/);
  assert.match(webhookSource, /cumulative_transition_observed/);
  assert.match(webhookSource, /observedCumulativeTransition:/);
  const routes = [];
  installFinanceStripeSettlementRoutes({
    app: {
      get(path) { routes.push(["GET", path]); },
      post(path) { routes.push(["POST", path]); }
    },
    pool: {}, authRequired: () => {}, requireFinanceAccess: () => {}, ensureChartAccounts: async () => {}, getStripe: () => null
  });
  assert.deepEqual(routes, [
    ["GET", "/api/finance/accounting/stripe-settlements"],
    ["GET", "/api/finance/accounting/stripe-settlements/payouts/:payoutId"],
    ["POST", "/api/finance/accounting/stripe-settlements/payouts/:payoutId/post"],
    ["POST", "/api/finance/accounting/stripe-settlements/payouts/:payoutId/void"]
  ]);
});
