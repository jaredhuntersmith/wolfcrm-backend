import assert from "node:assert/strict";
import {
  DEFAULT_CHART_ACCOUNTS,
  buildProfitAndLoss,
  ensureDefaultChartAccounts,
  normalizeAccountingUpdate,
  parseProfitAndLossRange
} from "../finance-accounting.js";

function account(id, accountType = "expense", active = true) {
  return { id, code: id, name: id, account_type: accountType, active };
}

function transaction(overrides = {}) {
  return {
    id: "tx_1",
    direction: "expense",
    amount_cents: 10_000,
    status: "posted",
    pending: false,
    removed_at: null,
    reconciliation_status: "unreconciled",
    accounting_version: 3,
    ...overrides
  };
}

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("default chart has stable unique codes and system keys", () => {
  assert.ok(DEFAULT_CHART_ACCOUNTS.length >= 20);
  assert.equal(new Set(DEFAULT_CHART_ACCOUNTS.map((item) => item.code)).size, DEFAULT_CHART_ACCOUNTS.length);
  assert.equal(new Set(DEFAULT_CHART_ACCOUNTS.map((item) => item.system_key)).size, DEFAULT_CHART_ACCOUNTS.length);
  assert.ok(DEFAULT_CHART_ACCOUNTS.some((item) => item.account_type === "income"));
  assert.ok(DEFAULT_CHART_ACCOUNTS.some((item) => item.account_type === "expense"));
  assert.ok(DEFAULT_CHART_ACCOUNTS.some((item) => item.system_key === "customer_credits" && item.account_type === "liability"));
  assert.ok(DEFAULT_CHART_ACCOUNTS.some((item) => item.system_key === "payment_clearing" && item.account_type === "asset"));
  assert.ok(DEFAULT_CHART_ACCOUNTS.some((item) => item.system_key === "opening_balance_equity" && item.account_type === "equity"));
});

test("default chart seeding is idempotent in one bounded query", async () => {
  const calls = [];
  await ensureDefaultChartAccounts({
    async query(sql, values) {
      calls.push({ sql, values });
      return { rows: [] };
    }
  }, "company_1", "user_1");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].values.length, DEFAULT_CHART_ACCOUNTS.length * 8);
  assert.match(calls[0].sql, /ON CONFLICT DO NOTHING/);
});

test("accounting update accepts an exact single classification", () => {
  const result = normalizeAccountingUpdate({
    transaction: transaction(),
    chartAccounts: [account("materials")],
    body: {
      expected_version: 3,
      accounting_note: "  Job materials  ",
      reconciliation_status: "cleared",
      splits: [{ chart_account_id: "materials", amount_cents: 10_000, memo: "Supplies" }]
    }
  });
  assert.equal(result.accounting_note, "Job materials");
  assert.equal(result.reconciliation_status, "cleared");
  assert.equal(result.splits[0].amount_cents, 10_000);
});

test("split totals must equal immutable transaction cents", () => {
  assert.throws(() => normalizeAccountingUpdate({
    transaction: transaction(),
    chartAccounts: [account("materials"), account("vehicle")],
    body: {
      expected_version: 3,
      splits: [
        { chart_account_id: "materials", amount_cents: 6_000 },
        { chart_account_id: "vehicle", amount_cents: 3_999 }
      ]
    }
  }), (error) => error.code === "accounting_splits_unbalanced" && error.remaining_cents === 1);
});

test("duplicate and wrong-type chart accounts fail closed", () => {
  assert.throws(() => normalizeAccountingUpdate({
    transaction: transaction(),
    chartAccounts: [account("materials")],
    body: {
      expected_version: 3,
      splits: [
        { chart_account_id: "materials", amount_cents: 5_000 },
        { chart_account_id: "materials", amount_cents: 5_000 }
      ]
    }
  }), (error) => error.code === "chart_account_duplicate");

  assert.throws(() => normalizeAccountingUpdate({
    transaction: transaction(),
    chartAccounts: [account("revenue", "income")],
    body: { expected_version: 3, splits: [{ chart_account_id: "revenue", amount_cents: 10_000 }] }
  }), (error) => error.code === "chart_account_type_mismatch");

  const liability = normalizeAccountingUpdate({
    transaction: transaction(),
    chartAccounts: [account("credit-card", "liability")],
    body: { expected_version: 3, splits: [{ chart_account_id: "credit-card", amount_cents: 10_000 }] }
  });
  assert.equal(liability.splits[0].chart_account_id, "credit-card");
});

test("stale edits and invalid reconciliation transitions are rejected", () => {
  assert.throws(() => normalizeAccountingUpdate({
    transaction: transaction(),
    chartAccounts: [],
    body: { expected_version: 2, splits: [] }
  }), (error) => error.code === "accounting_transaction_stale" && error.current_version === 3);

  assert.throws(() => normalizeAccountingUpdate({
    transaction: transaction({ pending: true, status: "pending" }),
    chartAccounts: [],
    body: { expected_version: 3, reconciliation_status: "reconciled", splits: [] }
  }), (error) => error.code === "transaction_not_reconcilable");

  assert.throws(() => normalizeAccountingUpdate({
    transaction: transaction({ reconciliation_status: "reconciled" }),
    chartAccounts: [],
    body: { expected_version: 3, reconciliation_status: "unreconciled", splits: [] }
  }), (error) => error.code === "reconciliation_reopen_reason_required");
});

test("profit and loss keeps exact totals and exposes incomplete classification", () => {
  const report = buildProfitAndLoss({
    startDate: "2026-08-01",
    endDate: "2026-08-31",
    transactions: [
      {
        id: "income_classified", direction: "income", amount_cents: 100_000,
        transaction_date: "2026-08-02", status: "posted", pending: false,
        splits: [{ chart_account_id: "service", chart_account_code: "4000", chart_account_name: "Service Revenue", account_type: "income", amount_cents: 100_000 }]
      },
      {
        id: "income_unclassified", direction: "income", amount_cents: 25_000,
        transaction_date: "2026-08-03", status: "posted", pending: false, splits: []
      },
      {
        id: "expense_split", direction: "expense", amount_cents: 70_000,
        transaction_date: "2026-08-04", status: "posted", pending: false,
        splits: [
          { chart_account_id: "materials", chart_account_code: "5000", chart_account_name: "Materials", account_type: "expense", amount_cents: 30_000 },
          { chart_account_id: "vehicle", chart_account_code: "6100", chart_account_name: "Vehicle", account_type: "expense", amount_cents: 20_000 },
          { chart_account_id: "loan", chart_account_code: "2200", chart_account_name: "Loans Payable", account_type: "liability", amount_cents: 20_000 }
        ]
      },
      {
        id: "expense_corrupt", direction: "expense", amount_cents: 10_000,
        transaction_date: "2026-08-05", status: "posted", pending: false,
        splits: [{ chart_account_id: "materials", chart_account_code: "5000", chart_account_name: "Materials", account_type: "expense", amount_cents: 5_000 }]
      },
      { id: "zero", direction: "expense", amount_cents: 0, transaction_date: "2026-08-05", status: "posted", pending: false, splits: [] },
      { id: "pending", direction: "expense", amount_cents: 9_000, transaction_date: "2026-08-06", status: "pending", pending: true, splits: [] },
      { id: "removed", direction: "income", amount_cents: 11_000, transaction_date: "2026-08-07", status: "posted", pending: false, removed_at: "2026-08-08", splits: [] }
    ]
  });

  assert.equal(report.income.total_cents, 100_000);
  assert.equal(report.income.cash_activity_cents, 125_000);
  assert.equal(report.income.classified_cents, 100_000);
  assert.equal(report.income.unclassified_cents, 25_000);
  assert.equal(report.expenses.total_cents, 50_000);
  assert.equal(report.expenses.cash_activity_cents, 80_000);
  assert.equal(report.expenses.classified_cents, 50_000);
  assert.equal(report.expenses.unclassified_cents, 10_000);
  assert.equal(report.expenses.unclassified_transaction_count, 1);
  assert.equal(report.expenses.non_profit_loss_cents, 20_000);
  assert.equal(report.net_income_cents, 50_000);
  assert.equal(report.classification_coverage_percent, 83);
  assert.equal(report.excluded.pending_transaction_count, 1);
  assert.equal(report.excluded.removed_transaction_count, 1);
  assert.equal(report.integrity_warning_count, 1);
});

test("profit and loss rejects inexact stored cents", () => {
  assert.throws(() => buildProfitAndLoss({
    startDate: "2026-08-01",
    endDate: "2026-08-31",
    transactions: [{
      id: "invalid", direction: "expense", amount_cents: -1,
      transaction_date: "2026-08-02", status: "posted", pending: false, splits: []
    }]
  }), (error) => error.code === "accounting_report_amount_invalid");
});

test("report range is inclusive, valid, and bounded", () => {
  assert.deepEqual(parseProfitAndLossRange("2026-01-01", "2026-12-31"), { start_date: "2026-01-01", end_date: "2026-12-31" });
  assert.deepEqual(parseProfitAndLossRange("2024-01-01", "2025-12-31"), { start_date: "2024-01-01", end_date: "2025-12-31" });
  assert.throws(() => parseProfitAndLossRange("2024-01-01", "2026-01-01"), (error) => error.code === "accounting_range_too_large");
  assert.throws(() => parseProfitAndLossRange("2026-12-31", "2026-01-01"), (error) => error.code === "accounting_range_invalid");
  assert.throws(() => parseProfitAndLossRange("2020-01-01", "2026-01-01"), (error) => error.code === "accounting_range_too_large");
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

if (!process.exitCode) console.log(`PASS finance accounting (${passed}/${tests.length})`);
