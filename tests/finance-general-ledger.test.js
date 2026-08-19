import assert from "node:assert/strict";
import fs from "node:fs";
import {
  installFinanceGeneralLedgerRoutes,
  installFinanceGeneralLedgerSchema,
  journalFingerprint,
  normalizeJournalReversal,
  normalizeManualJournal,
  parseGeneralLedgerRange,
  reverseJournalLines,
  summarizeTrialBalanceRows
} from "../finance-general-ledger.js";

const REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000";
const REVERSAL_REQUEST_ID = "123e4567-e89b-42d3-a456-426614174001";

function account(id, accountType, active = true) {
  return { id, account_type: accountType, active };
}

function journalBody(overrides = {}) {
  return {
    client_request_id: REQUEST_ID,
    entry_date: "2026-08-19",
    entry_kind: "adjustment",
    description: "Record reviewed supplies",
    reference: "Close worksheet",
    reason: "Accountant-reviewed adjustment",
    lines: [
      { chart_account_id: "expense", debit_cents: 12_500, credit_cents: 0, memo: "Supplies" },
      { chart_account_id: "cash", debit_cents: 0, credit_cents: 12_500, memo: "Cash" }
    ],
    ...overrides
  };
}

const chart = [
  account("cash", "asset"),
  account("receivable", "asset"),
  account("loan", "liability"),
  account("equity", "equity"),
  account("revenue", "income"),
  account("expense", "expense")
];

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("manual journals normalize exact balanced cents and stable content", () => {
  const normalized = normalizeManualJournal({ body: journalBody(), chartAccounts: chart, companyToday: "2026-08-19" });
  assert.equal(normalized.entry_kind, "adjustment");
  assert.equal(normalized.total_debits_cents, 12_500);
  assert.equal(normalized.total_credits_cents, 12_500);
  assert.equal(normalized.lines[0].position, 0);
  assert.equal(normalized.lines[0].memo, "Supplies");
  assert.equal(normalized.source_type, "manual");
  assert.equal(normalized.source_id, null);
  assert.match(normalized.request_fingerprint, /^[0-9a-f]{64}$/);
  assert.equal(normalized.request_fingerprint, normalizeManualJournal({
    body: journalBody(), chartAccounts: [...chart].reverse(), companyToday: "2026-08-19"
  }).request_fingerprint);
});

test("unbalanced, duplicate, one-sided, inactive, and inexact journal lines fail closed", () => {
  assert.throws(() => normalizeManualJournal({
    body: journalBody({ lines: [
      { chart_account_id: "expense", debit_cents: 12_500, credit_cents: 0 },
      { chart_account_id: "cash", debit_cents: 0, credit_cents: 12_499 }
    ] }), chartAccounts: chart, companyToday: "2026-08-19"
  }), (error) => error.code === "journal_unbalanced" && error.difference_cents === 1);

  assert.throws(() => normalizeManualJournal({
    body: journalBody({ lines: [
      { chart_account_id: "cash", debit_cents: 100, credit_cents: 0 },
      { chart_account_id: "cash", debit_cents: 0, credit_cents: 100 }
    ] }), chartAccounts: chart, companyToday: "2026-08-19"
  }), (error) => error.code === "journal_chart_account_duplicate");

  assert.throws(() => normalizeManualJournal({
    body: journalBody({ lines: [
      { chart_account_id: "expense", debit_cents: 100, credit_cents: 1 },
      { chart_account_id: "cash", debit_cents: 0, credit_cents: 99 }
    ] }), chartAccounts: chart, companyToday: "2026-08-19"
  }), (error) => error.code === "journal_line_side_invalid");

  assert.throws(() => normalizeManualJournal({
    body: journalBody(), chartAccounts: chart.map((item) => item.id === "expense" ? { ...item, active: false } : item), companyToday: "2026-08-19"
  }), (error) => error.code === "journal_chart_account_not_found");

  const archivedReplay = normalizeManualJournal({
    body: journalBody(),
    chartAccounts: chart.map((item) => item.id === "expense" ? { ...item, active: false } : item),
    companyToday: "2026-08-19",
    allowInactiveAccounts: true
  });
  assert.equal(archivedReplay.request_fingerprint, normalizeManualJournal({
    body: journalBody(), chartAccounts: chart, companyToday: "2026-08-19"
  }).request_fingerprint);

  assert.throws(() => normalizeManualJournal({
    body: journalBody({ lines: [
      { chart_account_id: "expense", debit_cents: 1.25, credit_cents: 0 },
      { chart_account_id: "cash", debit_cents: 0, credit_cents: 1.25 }
    ] }), chartAccounts: chart, companyToday: "2026-08-19"
  }), (error) => error.code === "debit_cents_invalid");
});

test("entry kinds enforce opening, transfer, and owner-equity account boundaries", () => {
  assert.throws(() => normalizeManualJournal({
    body: journalBody({ entry_kind: "opening_balance" }), chartAccounts: chart, companyToday: "2026-08-19"
  }), (error) => error.code === "journal_opening_account_type_invalid");

  assert.throws(() => normalizeManualJournal({
    body: journalBody({ entry_kind: "transfer" }), chartAccounts: chart, companyToday: "2026-08-19"
  }), (error) => error.code === "journal_transfer_account_type_invalid");

  assert.throws(() => normalizeManualJournal({
    body: journalBody({ entry_kind: "owner_equity" }), chartAccounts: chart, companyToday: "2026-08-19"
  }), (error) => error.code === "journal_owner_equity_account_required");

  const owner = normalizeManualJournal({
    body: journalBody({
      entry_kind: "owner_equity",
      lines: [
        { chart_account_id: "cash", debit_cents: 50_000, credit_cents: 0 },
        { chart_account_id: "equity", debit_cents: 0, credit_cents: 50_000 }
      ]
    }),
    chartAccounts: chart,
    companyToday: "2026-08-19"
  });
  assert.equal(owner.total_debits_cents, 50_000);

  const transfer = normalizeManualJournal({
    body: journalBody({
      entry_kind: "transfer",
      lines: [
        { chart_account_id: "receivable", debit_cents: 20_000, credit_cents: 0 },
        { chart_account_id: "cash", debit_cents: 0, credit_cents: 20_000 }
      ]
    }),
    chartAccounts: chart,
    companyToday: "2026-08-19"
  });
  assert.equal(transfer.entry_kind, "transfer");
});

test("journal dates, descriptions, reasons, request IDs, and report ranges are strict", () => {
  assert.throws(() => normalizeManualJournal({
    body: journalBody({ entry_date: "2026-08-20" }), chartAccounts: chart, companyToday: "2026-08-19"
  }), (error) => error.code === "journal_future_date");
  assert.throws(() => normalizeManualJournal({
    body: journalBody({ client_request_id: "retry-me" }), chartAccounts: chart, companyToday: "2026-08-19"
  }), (error) => error.code === "journal_request_id_invalid");
  assert.throws(() => normalizeManualJournal({
    body: journalBody({ reason: "" }), chartAccounts: chart, companyToday: "2026-08-19"
  }), (error) => error.code === "journal_reason_required");
  assert.deepEqual(parseGeneralLedgerRange("2026-01-01", "2026-12-31"), { start_date: "2026-01-01", end_date: "2026-12-31" });
  assert.throws(() => parseGeneralLedgerRange("2024-01-01", "2026-01-01"), (error) => error.code === "general_ledger_range_too_large");
});

test("canonical fingerprints are order-stable for object keys and content-sensitive", () => {
  const left = journalFingerprint({ b: 2, a: { d: 4, c: 3 }, lines: [{ z: 1, a: 2 }] });
  const right = journalFingerprint({ lines: [{ a: 2, z: 1 }], a: { c: 3, d: 4 }, b: 2 });
  assert.equal(left, right);
  assert.notEqual(left, journalFingerprint({ b: 2, a: { d: 5, c: 3 }, lines: [{ z: 1, a: 2 }] }));
});

test("reversal swaps every exact side and preserves balance", () => {
  const reversed = reverseJournalLines([
    { chart_account_id: "expense", debit_cents: "12500", credit_cents: "0", memo: "Supplies" },
    { chart_account_id: "cash", debit_cents: "0", credit_cents: "12500", memo: "Cash" }
  ]);
  assert.deepEqual(reversed.lines.map((line) => [line.debit_cents, line.credit_cents]), [[0, 12_500], [12_500, 0]]);
  assert.equal(reversed.total_debits_cents, 12_500);
  assert.equal(reversed.total_credits_cents, 12_500);
});

test("reversal planning enforces date, reason, immutable root, and request identity", () => {
  const original = {
    id: "223e4567-e89b-42d3-a456-426614174000",
    entry_date: "2026-08-18",
    description: "Original adjustment",
    reference: "REF-1",
    reversal_of_entry_id: null
  };
  const lines = [
    { chart_account_id: "expense", debit_cents: 500, credit_cents: 0, memo: null },
    { chart_account_id: "cash", debit_cents: 0, credit_cents: 500, memo: null }
  ];
  const reversal = normalizeJournalReversal({
    body: { client_request_id: REVERSAL_REQUEST_ID, entry_date: "2026-08-19", reason: "Correct duplicate" },
    original,
    originalLines: lines,
    companyToday: "2026-08-19"
  });
  assert.equal(reversal.reversal_of_entry_id, original.id);
  assert.equal(reversal.entry_kind, "reversal");
  assert.equal(reversal.lines[0].credit_cents, 500);
  assert.throws(() => normalizeJournalReversal({
    body: { client_request_id: REVERSAL_REQUEST_ID, entry_date: "2026-08-17", reason: "Too early" },
    original, originalLines: lines, companyToday: "2026-08-19"
  }), (error) => error.code === "journal_reversal_date_before_original");
  assert.throws(() => normalizeJournalReversal({
    body: { client_request_id: REVERSAL_REQUEST_ID, entry_date: "2026-08-19", reason: "Again" },
    original: { ...original, reversal_of_entry_id: "another" }, originalLines: lines, companyToday: "2026-08-19"
  }), (error) => error.code === "journal_reversal_of_reversal");
});

test("trial balance reports exact period activity and debit/credit ending sides", () => {
  const summary = summarizeTrialBalanceRows([
    { chart_account_id: "cash", code: "1000", name: "Cash", account_type: "asset", period_debit_cents: "1500", period_credit_cents: "500", through_end_debit_cents: "3000", through_end_credit_cents: "500" },
    { chart_account_id: "equity", code: "3000", name: "Equity", account_type: "equity", period_debit_cents: "0", period_credit_cents: "1000", through_end_debit_cents: "0", through_end_credit_cents: "2500" }
  ]);
  assert.equal(summary.period_debits_cents, 1_500);
  assert.equal(summary.period_credits_cents, 1_500);
  assert.equal(summary.ending_debits_cents, 2_500);
  assert.equal(summary.ending_credits_cents, 2_500);
  assert.equal(summary.accounts[0].ending_debit_balance_cents, 2_500);
  assert.equal(summary.accounts[1].ending_credit_balance_cents, 2_500);
});

test("trial balance fails rather than presenting corrupt stored totals", () => {
  assert.throws(() => summarizeTrialBalanceRows([
    { chart_account_id: "cash", account_type: "asset", period_debit_cents: 100, period_credit_cents: 0, through_end_debit_cents: 100, through_end_credit_cents: 0 }
  ]), (error) => error.code === "general_ledger_unbalanced");
  assert.throws(() => summarizeTrialBalanceRows([
    { chart_account_id: "cash", account_type: "asset", period_debit_cents: "9007199254740992", period_credit_cents: 0, through_end_debit_cents: 0, through_end_credit_cents: 0 }
  ]), (error) => error.code === "general_ledger_amount_inexact");
});

test("schema is additive, tenant-indexed, immutable by API shape, and audit preserving", async () => {
  const calls = [];
  await installFinanceGeneralLedgerSchema({ async query(sql) { calls.push(sql); return { rows: [] }; } });
  const sql = calls.join("\n");
  assert.match(sql, /CREATE TABLE IF NOT EXISTS finance_journal_entries/);
  assert.match(sql, /CREATE TABLE IF NOT EXISTS finance_journal_lines/);
  assert.match(sql, /CREATE TABLE IF NOT EXISTS finance_journal_audit/);
  assert.match(sql, /finance_journal_entries_one_reversal_idx/);
  assert.match(sql, /UNIQUE\(entry_id, chart_account_id\)/);
  assert.match(sql, /FOREIGN KEY \(company_id, entry_id\)/);
  assert.match(sql, /FOREIGN KEY \(company_id, chart_account_id\)/);
  assert.match(sql, /entry_kind = 'reversal'.*reversal_of_entry_id IS NOT NULL/);
  assert.match(sql, /bank_transaction/);
  assert.match(sql, /bank_transfer/);
  assert.match(sql, /job_receivable/);
  assert.match(sql, /payment_application/);
  assert.match(sql, /refund_application/);
  assert.match(sql, /customer_credit_application/);
  assert.match(sql, /finance_transfer_pair/);
  assert.match(sql, /finance_operational_source/);
  assert.match(sql, /finance_operational_application/);
  assert.match(sql, /finance_journal_entries_source_identity_check/);
  assert.match(sql, /finance_journal_entries_company_source_idx/);
  assert.match(sql, /CHECK \(\(debit_cents > 0 AND credit_cents = 0\)/);
  assert.doesNotMatch(sql, /DROP TABLE|TRUNCATE/);
});

test("routes expose bounded reads and only append/reversal mutations", () => {
  const routes = [];
  const app = {
    get(path) { routes.push(["GET", path]); },
    post(path) { routes.push(["POST", path]); }
  };
  installFinanceGeneralLedgerRoutes({
    app,
    pool: {},
    authRequired: () => {},
    requireFinanceAccess: () => {},
    ensureChartAccounts: async () => {}
  });
  assert.deepEqual(routes, [
    ["GET", "/api/finance/accounting/general-ledger"],
    ["GET", "/api/finance/accounting/general-ledger/entries/:entryId"],
    ["POST", "/api/finance/accounting/general-ledger/entries"],
    ["POST", "/api/finance/accounting/general-ledger/entries/:entryId/reverse"]
  ]);
  const source = fs.readFileSync(new URL("../finance-general-ledger.js", import.meta.url), "utf8");
  assert.match(source, /original\.source_type \|\| "manual"/);
  assert.match(source, /journal_source_owned/);
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

if (!process.exitCode) console.log(`PASS finance general ledger (${passed}/${tests.length})`);
