import {
  installOperationalAccountingRoutes,
  installOperationalAccountingSchema
} from "./finance-operational-accounting.js";
import {
  installFinanceCostAllocationRoutes,
  installFinanceCostAllocationSchema
} from "./finance-cost-allocations.js";
import {
  installFinanceMileageAllocationRoutes,
  installFinanceMileageAllocationSchema
} from "./finance-mileage-allocations.js";
import {
  installFinancePayrollCostRoutes,
  installFinancePayrollCostSchema
} from "./finance-payroll-costs.js";
import {
  installFinancePayrollAuthorityRoutes,
  installFinancePayrollAuthoritySchema
} from "./finance-payroll-authority.js";
import {
  installFinancePayrollEvaluationRoutes,
  installFinancePayrollEvaluationSchema
} from "./finance-payroll-evaluation.js";
import {
  installFinanceGeneralLedgerRoutes,
  installFinanceGeneralLedgerSchema
} from "./finance-general-ledger.js";

const ACCOUNT_TYPES = new Set(["asset", "liability", "equity", "income", "expense"]);
const RECONCILIATION_STATUSES = new Set(["unreconciled", "cleared", "reconciled"]);
const MAX_SPLITS = 20;
const MAX_REPORT_DAYS = 731;

export const DEFAULT_CHART_ACCOUNTS = Object.freeze([
  { code: "1000", name: "Cash & Bank Accounts", account_type: "asset", subtype: "cash", system_key: "cash" },
  { code: "1100", name: "Accounts Receivable", account_type: "asset", subtype: "accounts_receivable", system_key: "accounts_receivable" },
  { code: "1300", name: "Vehicles & Equipment", account_type: "asset", subtype: "fixed_assets", system_key: "vehicles_equipment" },
  { code: "2000", name: "Accounts Payable", account_type: "liability", subtype: "accounts_payable", system_key: "accounts_payable" },
  { code: "2100", name: "Credit Cards", account_type: "liability", subtype: "credit_card", system_key: "credit_cards" },
  { code: "2200", name: "Loans Payable", account_type: "liability", subtype: "loans_payable", system_key: "loans_payable" },
  { code: "2300", name: "Customer Credits", account_type: "liability", subtype: "customer_credits", system_key: "customer_credits" },
  { code: "3000", name: "Owner Equity", account_type: "equity", subtype: "owner_equity", system_key: "owner_equity" },
  { code: "3100", name: "Owner Distributions", account_type: "equity", subtype: "owner_distributions", system_key: "owner_distributions" },
  { code: "3200", name: "Opening Balance Equity", account_type: "equity", subtype: "opening_balance_equity", system_key: "opening_balance_equity" },
  { code: "4000", name: "Service Revenue", account_type: "income", subtype: "service_revenue", system_key: "service_revenue" },
  { code: "4100", name: "Recurring Service Revenue", account_type: "income", subtype: "recurring_revenue", system_key: "recurring_service_revenue" },
  { code: "4200", name: "Other Revenue", account_type: "income", subtype: "other_revenue", system_key: "other_revenue" },
  { code: "5000", name: "Materials & Supplies", account_type: "expense", subtype: "materials", system_key: "materials_supplies" },
  { code: "5100", name: "Direct Labor", account_type: "expense", subtype: "direct_labor", system_key: "direct_labor" },
  { code: "5200", name: "Subcontractors", account_type: "expense", subtype: "subcontractors", system_key: "subcontractors" },
  { code: "6000", name: "Advertising & Marketing", account_type: "expense", subtype: "advertising", system_key: "advertising_marketing" },
  { code: "6100", name: "Vehicle & Mileage", account_type: "expense", subtype: "vehicle", system_key: "vehicle_mileage" },
  { code: "6200", name: "Insurance", account_type: "expense", subtype: "insurance", system_key: "insurance" },
  { code: "6300", name: "Software & Subscriptions", account_type: "expense", subtype: "software", system_key: "software_subscriptions" },
  { code: "6400", name: "Rent & Utilities", account_type: "expense", subtype: "facilities", system_key: "rent_utilities" },
  { code: "6500", name: "Professional Services", account_type: "expense", subtype: "professional_services", system_key: "professional_services" },
  { code: "6600", name: "Taxes & Licenses", account_type: "expense", subtype: "taxes_licenses", system_key: "taxes_licenses" },
  { code: "6700", name: "Merchant & Bank Fees", account_type: "expense", subtype: "merchant_fees", system_key: "merchant_bank_fees" },
  { code: "6800", name: "Other Expense", account_type: "expense", subtype: "other_expense", system_key: "other_expense" }
]);

function accountingError(code, message, statusCode = 400, details = {}) {
  const error = new Error(message);
  error.code = code;
  error.statusCode = statusCode;
  Object.assign(error, details);
  return error;
}

function cleanString(value, maxLength = 200) {
  return (value || "").toString().trim().slice(0, maxLength);
}

function integerCents(value, field = "amount_cents") {
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (typeof value === "string" && /^-?\d+$/.test(value.trim())) {
    const parsed = Number(value.trim());
    if (Number.isSafeInteger(parsed)) return parsed;
  }
  throw accountingError(`${field}_invalid`, `${field.replaceAll("_", " ")} must be exact cents.`);
}

function dateOnly(value, field = "date") {
  const raw = cleanString(value, 20);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) throw accountingError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  const [year, month, day] = raw.split("-").map(Number);
  const parsed = new Date(Date.UTC(year, month - 1, day));
  if (parsed.getUTCFullYear() !== year || parsed.getUTCMonth() !== month - 1 || parsed.getUTCDate() !== day) {
    throw accountingError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return raw;
}

function addDays(dateString, days) {
  const [year, month, day] = dateString.split("-").map(Number);
  return new Date(Date.UTC(year, month - 1, day + days)).toISOString().slice(0, 10);
}

function chartPayload(row) {
  return {
    id: row.id,
    company_id: row.company_id,
    code: row.code,
    name: row.name,
    account_type: row.account_type,
    subtype: row.subtype || null,
    system_key: row.system_key || null,
    description: row.description || null,
    is_system_default: Boolean(row.is_system_default),
    active: row.active !== false,
    created_at: row.created_at || null,
    updated_at: row.updated_at || null
  };
}

function splitPayload(row) {
  return {
    id: row.id,
    transaction_id: row.transaction_id,
    chart_account_id: row.chart_account_id,
    chart_account_code: row.chart_account_code || row.code || null,
    chart_account_name: row.chart_account_name || row.name || null,
    account_type: row.account_type || null,
    amount_cents: Number(row.amount_cents || 0),
    memo: row.memo || null,
    job_id: row.job_id || null,
    created_at: row.created_at || null,
    updated_at: row.updated_at || null
  };
}

function auditPayload(row) {
  return {
    id: row.id,
    transaction_id: row.transaction_id,
    action: row.action,
    reason: row.reason || null,
    before: row.before_state || {},
    after: row.after_state || {},
    actor_user_id: row.actor_user_id || null,
    created_at: row.created_at || null
  };
}

function transactionAccountingSnapshot(transaction, splits = []) {
  return {
    accounting_note: transaction.accounting_note || null,
    reconciliation_status: transaction.reconciliation_status || "unreconciled",
    accounting_version: Number(transaction.accounting_version || 1),
    reconciled_at: transaction.reconciled_at || null,
    reconciled_by: transaction.reconciled_by || null,
    splits: splits.map((split) => ({
      chart_account_id: split.chart_account_id,
      amount_cents: Number(split.amount_cents || 0),
      memo: split.memo || null,
      job_id: split.job_id || null
    }))
  };
}

export function parseProfitAndLossRange(startValue, endValue) {
  const endDate = dateOnly(endValue, "end_date");
  const startDate = dateOnly(startValue, "start_date");
  if (startDate > endDate) throw accountingError("accounting_range_invalid", "Start date must be on or before end date.");
  if (addDays(startDate, MAX_REPORT_DAYS - 1) < endDate) {
    throw accountingError("accounting_range_too_large", `Profit & Loss ranges cannot exceed ${MAX_REPORT_DAYS} days.`);
  }
  return { start_date: startDate, end_date: endDate };
}

export function normalizeAccountingUpdate({ body = {}, transaction, chartAccounts = [] }) {
  const expectedVersion = integerCents(body.expected_version, "expected_version");
  const currentVersion = Number(transaction.accounting_version || 1);
  if (expectedVersion !== currentVersion) {
    throw accountingError("accounting_transaction_stale", "This transaction changed after it was loaded. Refresh before saving again.", 409, {
      current_version: currentVersion
    });
  }

  const reconciliationStatus = cleanString(body.reconciliation_status || "unreconciled", 30).toLowerCase();
  if (!RECONCILIATION_STATUSES.has(reconciliationStatus)) {
    throw accountingError("reconciliation_status_invalid", "Choose a valid reconciliation status.");
  }
  if ((transaction.pending || transaction.removed_at || transaction.status !== "posted") && reconciliationStatus !== "unreconciled") {
    throw accountingError("transaction_not_reconcilable", "Only active posted transactions can be cleared or reconciled.", 409);
  }

  const reason = cleanString(body.reason, 500) || null;
  if ((transaction.reconciliation_status || "unreconciled") === "reconciled" && reconciliationStatus !== "reconciled" && !reason) {
    throw accountingError("reconciliation_reopen_reason_required", "Add a reason before reopening a reconciled transaction.");
  }

  if (!Array.isArray(body.splits)) throw accountingError("accounting_splits_invalid", "Allocations must be a list.");
  if (body.splits.length > MAX_SPLITS) throw accountingError("accounting_splits_too_many", `A transaction can have at most ${MAX_SPLITS} allocations.`);

  const chartById = new Map(chartAccounts.map((account) => [String(account.id), account]));
  const seen = new Set();
  const allowedAccountTypes = transaction.direction === "income"
    ? new Set(["income", "asset", "liability", "equity"])
    : transaction.direction === "expense"
      ? new Set(["expense", "asset", "liability", "equity"])
      : null;
  if (!allowedAccountTypes) throw accountingError("transaction_direction_unsupported", "This transaction direction cannot be classified.", 409);

  const splits = body.splits.map((raw, index) => {
    const chartAccountId = cleanString(raw?.chart_account_id, 80);
    if (!chartAccountId) throw accountingError("chart_account_required", `Allocation ${index + 1} needs an account.`);
    if (seen.has(chartAccountId)) throw accountingError("chart_account_duplicate", "Use each chart account only once per transaction.");
    seen.add(chartAccountId);
    const account = chartById.get(chartAccountId);
    if (!account || account.active === false) throw accountingError("chart_account_not_found", "An allocation account is unavailable.", 404);
    if (!allowedAccountTypes.has(account.account_type)) {
      throw accountingError(
        "chart_account_type_mismatch",
        `${transaction.direction === "income" ? "Money-in" : "Money-out"} activity cannot use that account type.`
      );
    }
    const amountCents = integerCents(raw.amount_cents);
    if (amountCents <= 0) throw accountingError("split_amount_invalid", "Allocation amounts must be greater than zero.");
    return {
      chart_account_id: chartAccountId,
      amount_cents: amountCents,
      memo: cleanString(raw.memo, 500) || null,
      job_id: null
    };
  });

  const transactionAmount = Number(transaction.amount_cents || 0);
  const allocated = splits.reduce((sum, split) => sum + split.amount_cents, 0);
  if (splits.length && allocated !== transactionAmount) {
    throw accountingError("accounting_splits_unbalanced", `Allocations must total exactly ${transactionAmount} cents.`, 400, {
      transaction_amount_cents: transactionAmount,
      allocated_cents: allocated,
      remaining_cents: transactionAmount - allocated
    });
  }
  if (!splits.length && transactionAmount === 0) {
    // Zero-value activity remains explicitly unclassified.
  }

  return {
    expected_version: expectedVersion,
    accounting_note: cleanString(body.accounting_note, 2000) || null,
    reconciliation_status: reconciliationStatus,
    reason,
    splits
  };
}

function emptyReportSection() {
  return {
    total_cents: 0,
    cash_activity_cents: 0,
    classified_cents: 0,
    unclassified_cents: 0,
    non_profit_loss_cents: 0,
    transaction_count: 0,
    unclassified_transaction_count: 0,
    non_profit_loss_transaction_count: 0,
    lines: []
  };
}

export function buildProfitAndLoss({ transactions = [], startDate, endDate }) {
  const range = parseProfitAndLossRange(startDate, endDate);
  const income = emptyReportSection();
  const expenses = emptyReportSection();
  const lineMaps = { income: new Map(), expense: new Map() };
  let pendingExcluded = 0;
  let removedExcluded = 0;
  let integrityWarnings = 0;
  let fullyAllocatedCents = 0;

  for (const transaction of transactions) {
    const txDate = transaction.transaction_date instanceof Date
      ? transaction.transaction_date.toISOString().slice(0, 10)
      : String(transaction.transaction_date || "").slice(0, 10);
    if (txDate < range.start_date || txDate > range.end_date) continue;
    if (transaction.removed_at) {
      removedExcluded += 1;
      continue;
    }
    if (transaction.pending || transaction.status !== "posted") {
      pendingExcluded += 1;
      continue;
    }
    if (transaction.direction !== "income" && transaction.direction !== "expense") continue;

    const section = transaction.direction === "income" ? income : expenses;
    const amount = Number(transaction.amount_cents || 0);
    if (!Number.isSafeInteger(amount) || amount < 0) {
      throw accountingError("accounting_report_amount_invalid", "Stored transaction cents are invalid for an exact accounting report.", 409);
    }
    section.cash_activity_cents += amount;
    section.transaction_count += 1;
    const splits = Array.isArray(transaction.splits) ? transaction.splits : [];
    if (amount === 0 && splits.length === 0) continue;
    const requiredType = transaction.direction;
    const allowedTypes = requiredType === "income"
      ? new Set(["income", "asset", "liability", "equity"])
      : new Set(["expense", "asset", "liability", "equity"]);
    const splitTotal = splits.reduce((sum, split) => sum + Number(split.amount_cents || 0), 0);
    const splitsValid = splits.length > 0
      && Number.isSafeInteger(splitTotal)
      && splitTotal === amount
      && splits.every((split) => {
        const splitAmount = Number(split.amount_cents || 0);
        return Number.isSafeInteger(splitAmount) && splitAmount > 0 && allowedTypes.has(split.account_type);
      });

    if (!splitsValid) {
      section.unclassified_cents += amount;
      section.unclassified_transaction_count += 1;
      if (splits.length) integrityWarnings += 1;
      continue;
    }

    fullyAllocatedCents += amount;
    let transactionNonProfitLoss = 0;
    for (const split of splits) {
      if (split.account_type !== requiredType) {
        transactionNonProfitLoss += Number(split.amount_cents || 0);
        continue;
      }
      const key = String(split.chart_account_id);
      const current = lineMaps[requiredType].get(key) || {
        chart_account_id: key,
        code: split.chart_account_code || split.code || "",
        name: split.chart_account_name || split.name || "Account",
        amount_cents: 0,
        transaction_count: 0
      };
      current.amount_cents += Number(split.amount_cents || 0);
      current.transaction_count += 1;
      lineMaps[requiredType].set(key, current);
      section.classified_cents += Number(split.amount_cents || 0);
      section.total_cents += Number(split.amount_cents || 0);
    }
    section.non_profit_loss_cents += transactionNonProfitLoss;
    if (transactionNonProfitLoss > 0) section.non_profit_loss_transaction_count += 1;
  }

  income.lines = [...lineMaps.income.values()].sort((a, b) => a.code.localeCompare(b.code) || a.name.localeCompare(b.name));
  expenses.lines = [...lineMaps.expense.values()].sort((a, b) => a.code.localeCompare(b.code) || a.name.localeCompare(b.name));
  const activity = income.cash_activity_cents + expenses.cash_activity_cents;
  const warnings = [
    "Cash-basis report from posted Finance transactions only; it does not yet include unpaid receivables, unsupported payroll, or complete general-ledger balances."
  ];
  if (income.unclassified_transaction_count + expenses.unclassified_transaction_count > 0) {
    warnings.push("Unclassified cash activity is excluded from Profit & Loss totals until an accounting account is assigned.");
  }
  if (income.non_profit_loss_cents + expenses.non_profit_loss_cents > 0) {
    warnings.push("Transfers, debt principal, assets, and equity allocations are accounted for but excluded from Profit & Loss totals.");
  }
  if (pendingExcluded > 0) warnings.push("Pending bank activity is excluded until it posts.");
  if (integrityWarnings > 0) warnings.push("Some stored allocations were incomplete and are shown as unclassified.");

  return {
    basis: "cash_bank_activity",
    start_date: range.start_date,
    end_date: range.end_date,
    currency: "usd",
    income,
    expenses,
    net_income_cents: income.total_cents - expenses.total_cents,
    classification_coverage_percent: activity > 0 ? Math.round((fullyAllocatedCents / activity) * 100) : 100,
    excluded: {
      pending_transaction_count: pendingExcluded,
      removed_transaction_count: removedExcluded
    },
    integrity_warning_count: integrityWarnings,
    warnings
  };
}

export async function installFinanceAccountingSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS finance_chart_accounts (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      code TEXT NOT NULL,
      name TEXT NOT NULL,
      account_type TEXT NOT NULL CHECK (account_type IN ('asset','liability','equity','income','expense')),
      subtype TEXT,
      system_key TEXT,
      description TEXT,
      is_system_default BOOLEAN NOT NULL DEFAULT false,
      active BOOLEAN NOT NULL DEFAULT true,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, code)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS finance_chart_accounts_system_key_idx
      ON finance_chart_accounts(company_id, system_key) WHERE system_key IS NOT NULL;
    CREATE INDEX IF NOT EXISTS finance_chart_accounts_company_active_idx
      ON finance_chart_accounts(company_id, active, account_type, code);

    ALTER TABLE finance_transactions ADD COLUMN IF NOT EXISTS accounting_note TEXT;
    ALTER TABLE finance_transactions ADD COLUMN IF NOT EXISTS reconciliation_status TEXT NOT NULL DEFAULT 'unreconciled';
    ALTER TABLE finance_transactions ADD COLUMN IF NOT EXISTS reconciled_at TIMESTAMPTZ;
    ALTER TABLE finance_transactions ADD COLUMN IF NOT EXISTS reconciled_by UUID REFERENCES users(id) ON DELETE SET NULL;
    ALTER TABLE finance_transactions ADD COLUMN IF NOT EXISTS accounting_version INTEGER NOT NULL DEFAULT 1;
    ALTER TABLE finance_transactions ADD COLUMN IF NOT EXISTS accounting_updated_at TIMESTAMPTZ;
    ALTER TABLE finance_transactions ADD COLUMN IF NOT EXISTS accounting_updated_by UUID REFERENCES users(id) ON DELETE SET NULL;
    ALTER TABLE finance_transactions DROP CONSTRAINT IF EXISTS finance_transactions_reconciliation_status_check;
    ALTER TABLE finance_transactions ADD CONSTRAINT finance_transactions_reconciliation_status_check
      CHECK (reconciliation_status IN ('unreconciled','cleared','reconciled'));
    ALTER TABLE finance_transactions DROP CONSTRAINT IF EXISTS finance_transactions_accounting_version_check;
    ALTER TABLE finance_transactions ADD CONSTRAINT finance_transactions_accounting_version_check CHECK (accounting_version > 0);

    CREATE TABLE IF NOT EXISTS finance_transaction_splits (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      transaction_id UUID NOT NULL REFERENCES finance_transactions(id) ON DELETE CASCADE,
      chart_account_id UUID NOT NULL REFERENCES finance_chart_accounts(id) ON DELETE RESTRICT,
      amount_cents BIGINT NOT NULL CHECK (amount_cents > 0),
      memo TEXT,
      job_id TEXT,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(transaction_id, chart_account_id)
    );
    CREATE INDEX IF NOT EXISTS finance_transaction_splits_company_transaction_idx
      ON finance_transaction_splits(company_id, transaction_id);
    CREATE INDEX IF NOT EXISTS finance_transaction_splits_company_account_idx
      ON finance_transaction_splits(company_id, chart_account_id);

    CREATE TABLE IF NOT EXISTS finance_transaction_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      transaction_id UUID NOT NULL,
      actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      reason TEXT,
      before_state JSONB NOT NULL DEFAULT '{}'::jsonb,
      after_state JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS finance_transaction_audit_company_transaction_idx
      ON finance_transaction_audit(company_id, transaction_id, created_at DESC);
  `);
  await installFinanceGeneralLedgerSchema(pool);
  await installOperationalAccountingSchema(pool);
  await installFinanceCostAllocationSchema(pool);
  await installFinanceMileageAllocationSchema(pool);
  await installFinancePayrollCostSchema(pool);
  await installFinancePayrollAuthoritySchema(pool);
  await installFinancePayrollEvaluationSchema(pool);
}

export async function ensureDefaultChartAccounts(poolOrClient, companyId, userId = null) {
  const values = [];
  const tuples = DEFAULT_CHART_ACCOUNTS.map((account, index) => {
    const offset = index * 8;
    values.push(companyId, account.code, account.name, account.account_type, account.subtype, account.system_key, null, userId);
    return `($${offset + 1},$${offset + 2},$${offset + 3},$${offset + 4},$${offset + 5},$${offset + 6},$${offset + 7},true,true,$${offset + 8})`;
  });
  await poolOrClient.query(
    `INSERT INTO finance_chart_accounts (
       company_id, code, name, account_type, subtype, system_key,
       description, is_system_default, active, created_by
     ) VALUES ${tuples.join(",")}
     ON CONFLICT DO NOTHING`,
    values
  );
}

async function loadChartAccounts(poolOrClient, companyId, includeInactive = false) {
  await ensureDefaultChartAccounts(poolOrClient, companyId);
  const { rows } = await poolOrClient.query(
    `SELECT * FROM finance_chart_accounts
      WHERE company_id = $1 AND ($2::boolean OR active = true)
      ORDER BY account_type, code, name`,
    [companyId, includeInactive]
  );
  return rows.map(chartPayload);
}

async function loadTransactionAccounting(poolOrClient, companyId, transactionId, auditLimit = 30) {
  const txResult = await poolOrClient.query(
    `SELECT t.id, t.company_id, t.account_id, t.source, t.status, t.direction,
            t.amount_cents, t.transaction_date, t.pending, t.removed_at,
            t.merchant_name, t.original_name, t.accounting_note,
            t.reconciliation_status, t.reconciled_at, t.reconciled_by,
            t.accounting_version, t.accounting_updated_at, t.accounting_updated_by,
            a.name AS account_name, a.institution_name
       FROM finance_transactions t
       JOIN finance_accounts a ON a.id = t.account_id AND a.company_id = t.company_id
      WHERE t.company_id = $1 AND t.id = $2`,
    [companyId, transactionId]
  );
  const transaction = txResult.rows[0];
  if (!transaction) throw accountingError("finance_transaction_not_found", "Transaction was not found.", 404);
  const splitResult = await poolOrClient.query(
    `SELECT s.*, c.code AS chart_account_code, c.name AS chart_account_name, c.account_type
       FROM finance_transaction_splits s
       JOIN finance_chart_accounts c ON c.id = s.chart_account_id AND c.company_id = s.company_id
      WHERE s.company_id = $1 AND s.transaction_id = $2
      ORDER BY c.code, s.created_at`,
    [companyId, transactionId]
  );
  const auditResult = auditLimit > 0
    ? await poolOrClient.query(
      `SELECT * FROM finance_transaction_audit
        WHERE company_id = $1 AND transaction_id = $2
        ORDER BY created_at DESC LIMIT $3`,
      [companyId, transactionId, Math.min(Math.max(Number(auditLimit) || 30, 1), 100)]
    )
    : { rows: [] };
  const splits = splitResult.rows.map(splitPayload);
  const allocated = splits.reduce((sum, split) => sum + split.amount_cents, 0);
  return {
    transaction_id: transaction.id,
    company_id: transaction.company_id,
    direction: transaction.direction,
    amount_cents: Number(transaction.amount_cents || 0),
    transaction_date: transaction.transaction_date instanceof Date ? transaction.transaction_date.toISOString().slice(0, 10) : transaction.transaction_date,
    merchant_name: transaction.merchant_name || transaction.original_name || "Transaction",
    account_name: transaction.account_name,
    institution_name: transaction.institution_name || null,
    source: transaction.source,
    status: transaction.status,
    pending: Boolean(transaction.pending),
    removed_at: transaction.removed_at || null,
    accounting_note: transaction.accounting_note || null,
    reconciliation_status: transaction.reconciliation_status || "unreconciled",
    reconciled_at: transaction.reconciled_at || null,
    reconciled_by: transaction.reconciled_by || null,
    accounting_version: Number(transaction.accounting_version || 1),
    accounting_updated_at: transaction.accounting_updated_at || null,
    accounting_updated_by: transaction.accounting_updated_by || null,
    allocated_cents: allocated,
    unclassified_cents: Math.max(0, Number(transaction.amount_cents || 0) - allocated),
    splits,
    audit: auditResult.rows.map(auditPayload)
  };
}

function handleAccountingError(res, error, fallback) {
  if (error?.statusCode) {
    return res.status(error.statusCode).json({
      error: error.code || fallback,
      message: error.message,
      current_version: error.current_version,
      transaction_amount_cents: error.transaction_amount_cents,
      allocated_cents: error.allocated_cents,
      remaining_cents: error.remaining_cents
    });
  }
  if (error?.code === "23505") return res.status(409).json({ error: "accounting_duplicate", message: "That chart account code is already in use." });
  console.error("[finance-accounting]", fallback, { message: error?.message });
  return res.status(500).json({ error: fallback, message: "Accounting request failed." });
}

function requireCompany(req, res) {
  if (req.companyId) return true;
  res.status(400).json({ error: "company_required", message: "Accounting requires a company workspace." });
  return false;
}

function normalizeChartInput(body, existing = null) {
  const code = cleanString(body?.code ?? existing?.code, 20).toUpperCase();
  const name = cleanString(body?.name ?? existing?.name, 120);
  const accountType = cleanString(body?.account_type ?? existing?.account_type, 30).toLowerCase();
  const subtype = cleanString(body?.subtype ?? existing?.subtype, 80) || null;
  const description = cleanString(body?.description ?? existing?.description, 500) || null;
  if (body?.active !== undefined && typeof body.active !== "boolean") {
    throw accountingError("chart_account_active_invalid", "Active must be true or false.");
  }
  const active = body?.active === undefined ? existing?.active !== false : body.active;
  if (!/^[A-Z0-9][A-Z0-9.-]{1,19}$/.test(code)) throw accountingError("chart_account_code_invalid", "Use a 2–20 character account code.");
  if (!name) throw accountingError("chart_account_name_required", "Account name is required.");
  if (!ACCOUNT_TYPES.has(accountType)) throw accountingError("chart_account_type_invalid", "Choose a valid account type.");
  return { code, name, account_type: accountType, subtype, description, active };
}

export function installFinanceAccountingRoutes({ app, pool, authRequired, requireEmployer }) {
  app.get("/api/finance/accounting/chart-accounts", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      res.json({ accounts: await loadChartAccounts(pool, req.companyId, req.query.include_inactive === "true") });
    } catch (error) {
      handleAccountingError(res, error, "chart_accounts_failed");
    }
  });

  app.post("/api/finance/accounting/chart-accounts", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const input = normalizeChartInput(req.body);
      const { rows } = await pool.query(
        `INSERT INTO finance_chart_accounts (
           company_id, code, name, account_type, subtype, description, active, created_by
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
        [req.companyId, input.code, input.name, input.account_type, input.subtype, input.description, input.active, req.userId]
      );
      res.status(201).json(chartPayload(rows[0]));
    } catch (error) {
      handleAccountingError(res, error, "chart_account_create_failed");
    }
  });

  app.patch("/api/finance/accounting/chart-accounts/:id", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const existing = await pool.query(`SELECT * FROM finance_chart_accounts WHERE company_id = $1 AND id = $2`, [req.companyId, req.params.id]);
      if (!existing.rows.length) throw accountingError("chart_account_not_found", "Chart account was not found.", 404);
      const input = normalizeChartInput(req.body, existing.rows[0]);
      if (existing.rows[0].is_system_default && input.account_type !== existing.rows[0].account_type) {
        throw accountingError("system_chart_account_type_locked", "Default account type cannot be changed.", 409);
      }
      if (existing.rows[0].is_system_default && input.code !== existing.rows[0].code) {
        throw accountingError("system_chart_account_code_locked", "Default account code cannot be changed.", 409);
      }
      if (input.account_type !== existing.rows[0].account_type) {
        const usage = await pool.query(
          `SELECT 1 FROM finance_transaction_splits
            WHERE company_id = $1 AND chart_account_id = $2
            LIMIT 1`,
          [req.companyId, req.params.id]
        );
        if (usage.rows.length) {
          throw accountingError("chart_account_type_in_use", "An account type cannot change after transactions use it.", 409);
        }
      }
      const { rows } = await pool.query(
        `UPDATE finance_chart_accounts
            SET code = $3, name = $4, account_type = $5, subtype = $6,
                description = $7, active = $8, updated_at = now()
          WHERE company_id = $1 AND id = $2 RETURNING *`,
        [req.companyId, req.params.id, input.code, input.name, input.account_type, input.subtype, input.description, input.active]
      );
      res.json(chartPayload(rows[0]));
    } catch (error) {
      handleAccountingError(res, error, "chart_account_update_failed");
    }
  });

  app.get("/api/finance/accounting/transactions/:id", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      await ensureDefaultChartAccounts(pool, req.companyId, req.userId);
      res.json(await loadTransactionAccounting(pool, req.companyId, req.params.id, req.query.audit_limit || 30));
    } catch (error) {
      handleAccountingError(res, error, "transaction_accounting_failed");
    }
  });

  app.put("/api/finance/accounting/transactions/:id", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await ensureDefaultChartAccounts(client, req.companyId, req.userId);
      const txResult = await client.query(
        `SELECT * FROM finance_transactions WHERE company_id = $1 AND id = $2 FOR UPDATE`,
        [req.companyId, req.params.id]
      );
      const transaction = txResult.rows[0];
      if (!transaction) throw accountingError("finance_transaction_not_found", "Transaction was not found.", 404);
      const chartResult = await client.query(`SELECT * FROM finance_chart_accounts WHERE company_id = $1`, [req.companyId]);
      const existingSplits = await client.query(
        `SELECT * FROM finance_transaction_splits WHERE company_id = $1 AND transaction_id = $2 ORDER BY created_at`,
        [req.companyId, req.params.id]
      );
      const update = normalizeAccountingUpdate({ body: req.body, transaction, chartAccounts: chartResult.rows });
      const before = transactionAccountingSnapshot(transaction, existingSplits.rows);

      await client.query(`DELETE FROM finance_transaction_splits WHERE company_id = $1 AND transaction_id = $2`, [req.companyId, req.params.id]);
      for (const split of update.splits) {
        await client.query(
          `INSERT INTO finance_transaction_splits (
             company_id, transaction_id, chart_account_id, amount_cents, memo, job_id, created_by
           ) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
          [req.companyId, req.params.id, split.chart_account_id, split.amount_cents, split.memo, split.job_id, req.userId]
        );
      }

      const wasReconciled = (transaction.reconciliation_status || "unreconciled") === "reconciled";
      const isReconciled = update.reconciliation_status === "reconciled";
      const updatedResult = await client.query(
        `UPDATE finance_transactions
            SET accounting_note = $3,
                reconciliation_status = $4,
                reconciled_at = CASE WHEN $5::boolean THEN COALESCE(reconciled_at, now()) ELSE NULL END,
                reconciled_by = CASE WHEN $5::boolean THEN COALESCE(reconciled_by, $6) ELSE NULL END,
                accounting_version = accounting_version + 1,
                accounting_updated_at = now(),
                accounting_updated_by = $6,
                updated_at = now()
          WHERE company_id = $1 AND id = $2 RETURNING *`,
        [req.companyId, req.params.id, update.accounting_note, update.reconciliation_status, isReconciled, req.userId]
      );
      const updated = updatedResult.rows[0];
      const after = transactionAccountingSnapshot(updated, update.splits);
      const splitSignature = (snapshot) => JSON.stringify(
        snapshot.splits
          .map((split) => ({
            chart_account_id: split.chart_account_id,
            amount_cents: split.amount_cents,
            memo: split.memo,
            job_id: split.job_id
          }))
          .sort((left, right) => left.chart_account_id.localeCompare(right.chart_account_id))
      );
      const splitsChanged = splitSignature(before) !== splitSignature(after);
      const reconciliationChanged = before.reconciliation_status !== after.reconciliation_status;
      const action = wasReconciled && !isReconciled
        ? "reconciliation_reopened"
        : isReconciled && !wasReconciled
          ? "transaction_reconciled"
          : reconciliationChanged
            ? "reconciliation_status_changed"
            : splitsChanged && update.splits.length > 1
              ? "transaction_split"
              : splitsChanged && update.splits.length === 1
                ? "transaction_classified"
                : splitsChanged
                  ? "classification_cleared"
                  : "accounting_updated";
      await client.query(
        `INSERT INTO finance_transaction_audit (
           company_id, transaction_id, actor_user_id, action, reason, before_state, after_state
         ) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [req.companyId, req.params.id, req.userId, action, update.reason, JSON.stringify(before), JSON.stringify(after)]
      );
      await client.query("COMMIT");
      res.json(await loadTransactionAccounting(pool, req.companyId, req.params.id, 30));
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      handleAccountingError(res, error, "transaction_accounting_update_failed");
    } finally {
      client.release();
    }
  });

  app.get("/api/finance/accounting/reports/profit-loss", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const today = new Date().toISOString().slice(0, 10);
      const range = parseProfitAndLossRange(req.query.start_date || `${today.slice(0, 7)}-01`, req.query.end_date || today);
      const { rows } = await pool.query(
        `SELECT t.id, t.direction, t.amount_cents, t.transaction_date, t.status,
                t.pending, t.removed_at,
                COALESCE(
                  jsonb_agg(jsonb_build_object(
                    'chart_account_id', s.chart_account_id,
                    'amount_cents', s.amount_cents,
                    'chart_account_code', c.code,
                    'chart_account_name', c.name,
                    'account_type', c.account_type
                  ) ORDER BY c.code) FILTER (WHERE s.id IS NOT NULL),
                  '[]'::jsonb
                ) AS splits
           FROM finance_transactions t
           LEFT JOIN finance_transaction_splits s
             ON s.transaction_id = t.id AND s.company_id = t.company_id
           LEFT JOIN finance_chart_accounts c
             ON c.id = s.chart_account_id AND c.company_id = s.company_id
          WHERE t.company_id = $1
            AND t.transaction_date >= $2
            AND t.transaction_date <= $3
          GROUP BY t.id
          ORDER BY t.transaction_date, t.id`,
        [req.companyId, range.start_date, range.end_date]
      );
      res.json(buildProfitAndLoss({ transactions: rows, startDate: range.start_date, endDate: range.end_date }));
    } catch (error) {
      handleAccountingError(res, error, "profit_loss_report_failed");
    }
  });

  installFinanceGeneralLedgerRoutes({
    app,
    pool,
    authRequired,
    requireFinanceAccess: requireEmployer,
    ensureChartAccounts: ensureDefaultChartAccounts
  });

  installOperationalAccountingRoutes({ app, pool, authRequired, requireEmployer });
  installFinanceCostAllocationRoutes({
    app,
    pool,
    authRequired,
    requireFinanceAccess: requireEmployer
  });
  installFinanceMileageAllocationRoutes({
    app,
    pool,
    authRequired,
    requireFinanceAccess: requireEmployer
  });
  installFinancePayrollCostRoutes({
    app,
    pool,
    authRequired,
    requireFinanceAccess: requireEmployer
  });
  installFinancePayrollAuthorityRoutes({
    app,
    pool,
    authRequired,
    requireFinanceAccess: requireEmployer
  });
  installFinancePayrollEvaluationRoutes({
    app,
    pool,
    authRequired,
    requireFinanceAccess: requireEmployer
  });
}
