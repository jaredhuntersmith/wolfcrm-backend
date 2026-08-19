import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {
  buildOperationalReceivableJournalInput,
  buildOperationalReceivableReversalInput,
  evaluateOperationalReceivableSource,
  installFinanceOperationalJournalRoutes,
  normalizeOperationalReceivableActionRequest,
  parseOperationalReceivableJournalRange
} from "../finance-operational-journals.js";

const IDs = {
  source: "00000000-0000-4000-8000-000000000101",
  ar: "00000000-0000-4000-8000-000000000102",
  revenue: "00000000-0000-4000-8000-000000000103",
  request: "00000000-0000-4000-8000-000000000104",
  journal: "00000000-0000-4000-8000-000000000105"
};

function bundle(overrides = {}) {
  const source = {
    id: IDs.source,
    source_type: "job_receivable",
    source_id: "job_1",
    job_id: "job_1",
    status: "recognized",
    amount_cents: 25_000,
    currency: "usd",
    occurred_at: "2026-08-19T01:30:00.000Z",
    entry_date: "2026-08-18",
    evidence: { has_price: true },
    source_version: 3,
    removed_at: null,
    ...overrides.source
  };
  const job = overrides.job === null ? null : {
    id: "job_1",
    title: "Reviewed service",
    price_cents: 25_000,
    finished_at: "2026-08-19T01:30:00.000Z",
    ...overrides.job
  };
  const accountsReceivableAccount = overrides.accountsReceivableAccount === null ? null : {
    id: IDs.ar,
    code: "1100",
    name: "Accounts Receivable",
    account_type: "asset",
    system_key: "accounts_receivable",
    active: true,
    ...overrides.accountsReceivableAccount
  };
  const revenueAccount = overrides.revenueAccount === null ? null : {
    id: IDs.revenue,
    code: "4000",
    name: "Service Revenue",
    account_type: "income",
    active: true,
    ...overrides.revenueAccount
  };
  return { source, job, accountsReceivableAccount, revenueAccount, posting: overrides.posting || null };
}

test("completed-job source produces exact A/R debit and explicit revenue credit", () => {
  const result = evaluateOperationalReceivableSource(bundle());
  assert.equal(result.eligible, true);
  assert.equal(result.review_state, "ready");
  assert.equal(result.journal_preview.entry_date, "2026-08-18");
  assert.deepEqual(result.journal_preview.lines.map((line) => [line.chart_account_id, line.debit_cents, line.credit_cents]), [
    [IDs.ar, 25_000, 0],
    [IDs.revenue, 0, 25_000]
  ]);
});

test("queue candidacy waits for explicit revenue selection without guessing it", () => {
  const result = evaluateOperationalReceivableSource({ ...bundle({ revenueAccount: null }), requireRevenueAccount: false });
  assert.equal(result.candidate_eligible, true);
  assert.equal(result.eligible, false);
  assert.equal(result.review_state, "ready");
  assert.equal(result.journal_preview, null);
});

test("source eligibility fails closed for removed, changed, unpriced, zero, and invalid account facts", () => {
  const result = evaluateOperationalReceivableSource(bundle({
    source: { removed_at: "2026-08-19T03:00:00Z", amount_cents: 0, evidence: { has_price: false } },
    job: { price_cents: 1, finished_at: null },
    accountsReceivableAccount: { active: false },
    revenueAccount: { account_type: "expense" }
  }));
  const codes = result.blockers.map((item) => item.code);
  for (const code of [
    "operational_source_removed", "operational_source_unpriced", "operational_source_zero_amount",
    "operational_source_job_reopened", "operational_source_price_changed",
    "accounts_receivable_account_invalid", "revenue_account_invalid"
  ]) assert.ok(codes.includes(code), code);
});

test("source fingerprint detects source revisions and chart authority changes", () => {
  const first = evaluateOperationalReceivableSource(bundle());
  const sourceChanged = evaluateOperationalReceivableSource(bundle({ source: { source_version: 4 } }));
  const accountChanged = evaluateOperationalReceivableSource(bundle({ revenueAccount: { id: "00000000-0000-4000-8000-000000000106" } }));
  assert.notEqual(first.source_fingerprint, sourceChanged.source_fingerprint);
  assert.notEqual(first.source_fingerprint, accountChanged.source_fingerprint);
  const bankConflict = evaluateOperationalReceivableSource({ ...bundle(), activeBankIncomeAuthorityCount: 1 });
  assert.notEqual(first.source_fingerprint, bankConflict.source_fingerprint);
  assert.ok(bankConflict.blockers.some((item) => item.code === "bank_income_authority_active"));
  const current = evaluateOperationalReceivableSource(bundle({
    posting: {
      status: "posted",
      source_fingerprint: first.source_fingerprint,
      revenue_chart_account_id: IDs.revenue,
      journal_entry_id: IDs.journal,
      version: 1
    }
  }));
  assert.equal(current.source_current, true);
  assert.equal(current.review_state, "posted");
});

test("journal and exact reversal retain operational source authority", () => {
  const evaluation = evaluateOperationalReceivableSource(bundle());
  const journal = buildOperationalReceivableJournalInput({
    evaluation,
    operationalSourceID: IDs.source,
    postingVersion: 1,
    clientRequestID: IDs.request,
    reason: "Reviewed completed job"
  });
  assert.equal(journal.entry_kind, "job_receivable");
  assert.equal(journal.source_type, "finance_operational_source");
  assert.equal(journal.source_version, 1);
  const reversal = buildOperationalReceivableReversalInput({
    original: { ...journal, id: IDs.journal },
    originalLines: journal.lines,
    operationalSourceID: IDs.source,
    postingVersion: 2,
    clientRequestID: IDs.request,
    reason: "Correct the source"
  });
  assert.equal(reversal.reversal_of_entry_id, IDs.journal);
  assert.deepEqual(reversal.lines.map((line) => [line.debit_cents, line.credit_cents]), journal.lines.map((line) => [line.credit_cents, line.debit_cents]));
});

test("action requests require exact versions, income identity, and audit reason", () => {
  const request = normalizeOperationalReceivableActionRequest({
    body: {
      client_request_id: IDs.request,
      revenue_chart_account_id: IDs.revenue,
      expected_source_version: 3,
      expected_posting_version: 0,
      reason: "Reviewed revenue authority"
    },
    operationalSourceID: IDs.source,
    action: "post"
  });
  assert.equal(request.request_fingerprint.length, 64);
  assert.equal(request.expected_source_version, 3);
  const voidRequest = normalizeOperationalReceivableActionRequest({
    body: {
      client_request_id: IDs.request,
      expected_source_version: 3,
      expected_posting_version: 1,
      reason: "Reopened job"
    },
    operationalSourceID: IDs.source,
    action: "void"
  });
  assert.equal(voidRequest.revenue_chart_account_id, null);
  assert.throws(() => normalizeOperationalReceivableActionRequest({
    body: { ...request, reason: "" }, operationalSourceID: IDs.source, action: "post"
  }), (error) => error.code === "operational_journal_reason_required");
});

test("receivable journal ranges are exact, valid, and bounded", () => {
  assert.deepEqual(parseOperationalReceivableJournalRange("2025-01-01", "2027-01-01"), {
    start_date: "2025-01-01", end_date: "2027-01-01"
  });
  assert.throws(() => parseOperationalReceivableJournalRange("2026-08-20", "2026-08-19"), (error) => error.code === "operational_journal_range_invalid");
  assert.throws(() => parseOperationalReceivableJournalRange("2025-01-01", "2027-01-02"), (error) => error.code === "operational_journal_range_too_large");
});

test("schema, routes, locks, and source-preservation boundaries are explicit", () => {
  const source = fs.readFileSync(new URL("../finance-operational-journals.js", import.meta.url), "utf8");
  assert.match(source, /CREATE TABLE IF NOT EXISTS finance_operational_receivable_postings/);
  assert.match(source, /CREATE TABLE IF NOT EXISTS finance_operational_receivable_posting_audit/);
  assert.match(source, /finance_operational_sources\(company_id, id\)/);
  assert.match(source, /schedule_events\(company_id, id\)/);
  assert.match(source, /FOR UPDATE OF src/);
  assert.match(source, /FOR SHARE/);
  assert.match(source, /bank_income_authority_active/);
  assert.match(source, /SELECT id FROM companies WHERE id=\$1 FOR UPDATE/);
  assert.doesNotMatch(source, /UPDATE finance_operational_sources\s+SET/);
  assert.doesNotMatch(source, /UPDATE schedule_events\s+SET/);
  assert.doesNotMatch(source, /UPDATE payment_records\s+SET/);
  const routes = [];
  installFinanceOperationalJournalRoutes({
    app: {
      get(path) { routes.push(["GET", path]); },
      post(path) { routes.push(["POST", path]); }
    },
    pool: {},
    authRequired: () => {},
    requireFinanceAccess: () => {},
    ensureChartAccounts: async () => {}
  });
  assert.deepEqual(routes, [
    ["GET", "/api/finance/accounting/operational-journals/receivables"],
    ["GET", "/api/finance/accounting/operational-journals/receivables/:sourceId/preview"],
    ["GET", "/api/finance/accounting/operational-journals/receivables/:sourceId"],
    ["POST", "/api/finance/accounting/operational-journals/receivables/:sourceId/post"],
    ["POST", "/api/finance/accounting/operational-journals/receivables/:sourceId/void"]
  ]);
});
