import {
  estimateDebtPayoff,
  requiredPaymentForTarget,
  summarizeBudget,
  goalMetrics
} from "./finance-calculations.js";

const VALID_ACCOUNT_TYPES = new Set(["cash", "checking", "savings", "other"]);
const VALID_CURRENCIES = new Set(["usd"]);
const VALID_DIRECTIONS = new Set(["income", "expense"]);
const VALID_RECURRENCES = new Set(["none", "weekly", "biweekly", "monthly", "yearly"]);
const VALID_DEBT_TYPES = new Set(["federal_tax", "state_tax", "local_tax", "credit_card", "personal_loan", "business_loan", "auto_loan", "medical", "other"]);
const VALID_DEBT_PRIORITIES = new Set(["high", "normal", "low"]);
const VALID_DEBT_STATUSES = new Set(["active", "paid"]);
const VALID_BUDGET_PERIODS = new Set(["weekly", "monthly", "yearly"]);
const VALID_GOAL_TYPES = new Set(["emergency_fund", "tax_payoff", "equipment_purchase", "vehicle_purchase", "moving_fund", "general_savings", "custom"]);
const VALID_GOAL_STATUSES = new Set(["active", "completed"]);

function cleanString(value, maxLength = 200) {
  return (value || "").toString().trim().slice(0, maxLength);
}

function parseCents(value, fieldName) {
  if (typeof value === "number" && Number.isInteger(value)) return value;
  if (typeof value === "string" && /^-?\d+$/.test(value.trim())) return Number(value.trim());
  const error = new Error(`${fieldName}_invalid`);
  error.statusCode = 400;
  error.code = `${fieldName}_invalid`;
  throw error;
}

function parseDateOnly(value, fieldName = "date") {
  const raw = cleanString(value, 20);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    const error = new Error(`${fieldName}_invalid`);
    error.statusCode = 400;
    error.code = `${fieldName}_invalid`;
    throw error;
  }
  const [year, month, day] = raw.split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) {
    const error = new Error(`${fieldName}_invalid`);
    error.statusCode = 400;
    error.code = `${fieldName}_invalid`;
    throw error;
  }
  return raw;
}

function dateOnlyFromDb(value) {
  if (value instanceof Date) return value.toISOString().slice(0, 10);
  return cleanString(value, 20);
}

function addDays(dateString, days) {
  const [year, month, day] = dateString.split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1, day + days));
  return date.toISOString().slice(0, 10);
}

function lastDayOfMonth(year, monthIndex) {
  return new Date(Date.UTC(year, monthIndex + 1, 0)).getUTCDate();
}

function addMonthsClamped(dateString, months) {
  const [year, month, day] = dateString.split("-").map(Number);
  const baseIndex = (year * 12) + (month - 1) + months;
  const nextYear = Math.floor(baseIndex / 12);
  const nextMonthIndex = baseIndex % 12;
  const clampedDay = Math.min(day, lastDayOfMonth(nextYear, nextMonthIndex));
  return new Date(Date.UTC(nextYear, nextMonthIndex, clampedDay)).toISOString().slice(0, 10);
}

function addYearsClamped(dateString, years) {
  const [year, month, day] = dateString.split("-").map(Number);
  const nextYear = year + years;
  const nextMonthIndex = month - 1;
  const clampedDay = Math.min(day, lastDayOfMonth(nextYear, nextMonthIndex));
  return new Date(Date.UTC(nextYear, nextMonthIndex, clampedDay)).toISOString().slice(0, 10);
}

function normalizeDirection(value) {
  const direction = cleanString(value, 20).toLowerCase();
  return VALID_DIRECTIONS.has(direction) ? direction : null;
}

function normalizeRecurrence(value) {
  const recurrence = cleanString(value || "none", 20).toLowerCase();
  return VALID_RECURRENCES.has(recurrence) ? recurrence : null;
}

function normalizeAccountType(value) {
  const type = cleanString(value, 40).toLowerCase();
  return VALID_ACCOUNT_TYPES.has(type) ? type : null;
}

function normalizeCurrency(value) {
  const currency = cleanString(value || "usd", 3).toLowerCase();
  return VALID_CURRENCIES.has(currency) ? currency : null;
}

function normalizeSet(value, validSet, fallback = null, maxLength = 40) {
  const normalized = cleanString(value || fallback || "", maxLength).toLowerCase();
  return validSet.has(normalized) ? normalized : null;
}

function parseOptionalCents(value, fieldName) {
  if (value === null || value === undefined || value === "") return null;
  return parseCents(value, fieldName);
}

function parseOptionalDateOnly(value, fieldName) {
  if (value === null || value === undefined || value === "") return null;
  return parseDateOnly(value, fieldName);
}

function parseOptionalAprBasisPoints(value) {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "number" && Number.isInteger(value)) return value;
  if (typeof value === "string" && /^-?\d+$/.test(value.trim())) return Number(value.trim());
  const error = new Error("apr_basis_points_invalid");
  error.statusCode = 400;
  error.code = "apr_basis_points_invalid";
  throw error;
}

function financeAccountPayload(row) {
  return {
    id: row.id,
    company_id: row.company_id,
    name: row.name,
    account_type: row.account_type,
    source: row.source,
    current_balance_cents: Number(row.current_balance_cents || 0),
    currency: row.currency,
    archived_at: row.archived_at,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

function financeEntryPayload(row) {
  return {
    id: row.id,
    company_id: row.company_id,
    account_id: row.account_id,
    entry_type: row.entry_type,
    amount_delta_cents: Number(row.amount_delta_cents || 0),
    previous_balance_cents: Number(row.previous_balance_cents || 0),
    resulting_balance_cents: Number(row.resulting_balance_cents || 0),
    currency: row.currency,
    note: row.note,
    created_by: row.created_by,
    effective_at: row.effective_at,
    created_at: row.created_at
  };
}

function financeSettingsPayload(row) {
  return {
    company_id: row.company_id,
    minimum_cash_reserve_cents: Number(row.minimum_cash_reserve_cents || 0),
    currency: row.currency || "usd",
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

function financePlannedItemPayload(row) {
  return {
    id: row.id,
    company_id: row.company_id,
    account_id: row.account_id,
    account_name: row.account_name || null,
    debt_id: row.debt_id || null,
    title: row.title,
    direction: row.direction,
    amount_cents: Number(row.amount_cents || 0),
    scheduled_date: row.scheduled_date instanceof Date ? row.scheduled_date.toISOString().slice(0, 10) : row.scheduled_date,
    category: row.category,
    recurrence: row.recurrence,
    recurrence_end_date: row.recurrence_end_date instanceof Date ? row.recurrence_end_date.toISOString().slice(0, 10) : row.recurrence_end_date,
    notes: row.notes,
    archived_at: row.archived_at,
    created_by: row.created_by,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

function isTaxDebt(type) {
  return type === "federal_tax" || type === "state_tax" || type === "local_tax";
}

function debtPayload(row) {
  return {
    id: row.id,
    company_id: row.company_id,
    name: row.name,
    debt_type: row.debt_type,
    current_balance_cents: Number(row.current_balance_cents || 0),
    original_balance_cents: row.original_balance_cents === null || row.original_balance_cents === undefined ? null : Number(row.original_balance_cents),
    minimum_payment_cents: Number(row.minimum_payment_cents || 0),
    planned_payment_cents: Number(row.planned_payment_cents || 0),
    apr_basis_points: row.apr_basis_points === null || row.apr_basis_points === undefined ? null : Number(row.apr_basis_points),
    next_due_date: row.next_due_date instanceof Date ? row.next_due_date.toISOString().slice(0, 10) : row.next_due_date,
    target_payoff_date: row.target_payoff_date instanceof Date ? row.target_payoff_date.toISOString().slice(0, 10) : row.target_payoff_date,
    status: row.status,
    priority: row.priority,
    notes: row.notes,
    planned_item_id: row.planned_item_id,
    archived_at: row.archived_at,
    created_by: row.created_by,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

function debtPaymentPayload(row) {
  return {
    id: row.id,
    company_id: row.company_id,
    debt_id: row.debt_id,
    amount_cents: Number(row.amount_cents || 0),
    payment_date: row.payment_date instanceof Date ? row.payment_date.toISOString().slice(0, 10) : row.payment_date,
    note: row.note,
    finance_account_id: row.finance_account_id,
    created_by: row.created_by,
    created_at: row.created_at
  };
}

function budgetPayload(row) {
  return {
    id: row.id,
    company_id: row.company_id,
    name: row.name,
    category: row.category,
    limit_cents: Number(row.limit_cents || 0),
    period: row.period,
    start_date: row.start_date instanceof Date ? row.start_date.toISOString().slice(0, 10) : row.start_date,
    end_date: row.end_date instanceof Date ? row.end_date.toISOString().slice(0, 10) : row.end_date,
    notes: row.notes,
    archived_at: row.archived_at,
    created_by: row.created_by,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

function goalPayload(row) {
  return {
    id: row.id,
    company_id: row.company_id,
    name: row.name,
    goal_type: row.goal_type,
    target_amount_cents: Number(row.target_amount_cents || 0),
    current_amount_cents: Number(row.current_amount_cents || 0),
    target_date: row.target_date instanceof Date ? row.target_date.toISOString().slice(0, 10) : row.target_date,
    status: row.status,
    notes: row.notes,
    archived_at: row.archived_at,
    created_by: row.created_by,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

function goalContributionPayload(row) {
  return {
    id: row.id,
    company_id: row.company_id,
    goal_id: row.goal_id,
    amount_cents: Number(row.amount_cents || 0),
    contribution_date: row.contribution_date instanceof Date ? row.contribution_date.toISOString().slice(0, 10) : row.contribution_date,
    note: row.note,
    created_by: row.created_by,
    created_at: row.created_at
  };
}

async function installFinanceSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS finance_accounts (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      account_type TEXT NOT NULL CHECK (account_type IN ('cash','checking','savings','other')),
      source TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual','plaid')),
      current_balance_cents BIGINT NOT NULL DEFAULT 0,
      currency TEXT NOT NULL DEFAULT 'usd',
      archived_at TIMESTAMPTZ,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS finance_accounts_company_active_idx
      ON finance_accounts(company_id, archived_at, account_type, name);

    CREATE TABLE IF NOT EXISTS finance_account_entries (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      account_id UUID NOT NULL REFERENCES finance_accounts(id) ON DELETE CASCADE,
      entry_type TEXT NOT NULL CHECK (entry_type IN ('initial_balance','manual_balance_adjustment','transaction','income','expense','transfer','receipt_cash_purchase','plaid_reconciliation')),
      amount_delta_cents BIGINT NOT NULL,
      previous_balance_cents BIGINT NOT NULL,
      resulting_balance_cents BIGINT NOT NULL,
      currency TEXT NOT NULL DEFAULT 'usd',
      note TEXT,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      effective_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS finance_entries_company_created_idx
      ON finance_account_entries(company_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS finance_entries_account_created_idx
      ON finance_account_entries(account_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS finance_settings (
      company_id UUID PRIMARY KEY REFERENCES companies(id) ON DELETE CASCADE,
      minimum_cash_reserve_cents BIGINT NOT NULL DEFAULT 0,
      currency TEXT NOT NULL DEFAULT 'usd',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS finance_planned_items (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      account_id UUID REFERENCES finance_accounts(id) ON DELETE SET NULL,
      debt_id UUID,
      title TEXT NOT NULL,
      direction TEXT NOT NULL CHECK (direction IN ('income','expense')),
      amount_cents BIGINT NOT NULL CHECK (amount_cents >= 0),
      scheduled_date DATE NOT NULL,
      category TEXT NOT NULL DEFAULT 'Other',
      recurrence TEXT NOT NULL DEFAULT 'none' CHECK (recurrence IN ('none','weekly','biweekly','monthly','yearly')),
      recurrence_end_date DATE,
      notes TEXT,
      archived_at TIMESTAMPTZ,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      CHECK (recurrence_end_date IS NULL OR recurrence_end_date >= scheduled_date)
    );
    CREATE INDEX IF NOT EXISTS finance_planned_items_company_date_idx
      ON finance_planned_items(company_id, scheduled_date);
    CREATE INDEX IF NOT EXISTS finance_planned_items_company_active_idx
      ON finance_planned_items(company_id, archived_at, scheduled_date);

    CREATE TABLE IF NOT EXISTS finance_debts (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      debt_type TEXT NOT NULL CHECK (debt_type IN ('federal_tax','state_tax','local_tax','credit_card','personal_loan','business_loan','auto_loan','medical','other')),
      current_balance_cents BIGINT NOT NULL CHECK (current_balance_cents >= 0),
      original_balance_cents BIGINT CHECK (original_balance_cents IS NULL OR original_balance_cents >= 0),
      minimum_payment_cents BIGINT NOT NULL DEFAULT 0 CHECK (minimum_payment_cents >= 0),
      planned_payment_cents BIGINT NOT NULL DEFAULT 0 CHECK (planned_payment_cents >= 0),
      apr_basis_points INTEGER CHECK (apr_basis_points IS NULL OR apr_basis_points >= 0),
      next_due_date DATE,
      target_payoff_date DATE,
      status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','paid')),
      priority TEXT NOT NULL DEFAULT 'normal' CHECK (priority IN ('high','normal','low')),
      notes TEXT,
      planned_item_id UUID,
      archived_at TIMESTAMPTZ,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS finance_debts_company_active_idx
      ON finance_debts(company_id, archived_at, status, priority);
    CREATE INDEX IF NOT EXISTS finance_debts_company_type_idx
      ON finance_debts(company_id, debt_type);

    CREATE TABLE IF NOT EXISTS finance_debt_payments (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      debt_id UUID NOT NULL REFERENCES finance_debts(id) ON DELETE RESTRICT,
      amount_cents BIGINT NOT NULL CHECK (amount_cents > 0),
      payment_date DATE NOT NULL,
      note TEXT,
      finance_account_id UUID REFERENCES finance_accounts(id) ON DELETE SET NULL,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS finance_debt_payments_debt_date_idx
      ON finance_debt_payments(company_id, debt_id, payment_date DESC);

    CREATE TABLE IF NOT EXISTS finance_budgets (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      limit_cents BIGINT NOT NULL CHECK (limit_cents >= 0),
      period TEXT NOT NULL CHECK (period IN ('weekly','monthly','yearly')),
      start_date DATE NOT NULL,
      end_date DATE,
      notes TEXT,
      archived_at TIMESTAMPTZ,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      CHECK (end_date IS NULL OR end_date >= start_date)
    );
    CREATE INDEX IF NOT EXISTS finance_budgets_company_active_idx
      ON finance_budgets(company_id, archived_at, period, category);

    CREATE TABLE IF NOT EXISTS finance_goals (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      goal_type TEXT NOT NULL CHECK (goal_type IN ('emergency_fund','tax_payoff','equipment_purchase','vehicle_purchase','moving_fund','general_savings','custom')),
      target_amount_cents BIGINT NOT NULL CHECK (target_amount_cents >= 0),
      current_amount_cents BIGINT NOT NULL DEFAULT 0 CHECK (current_amount_cents >= 0),
      target_date DATE,
      status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','completed')),
      notes TEXT,
      archived_at TIMESTAMPTZ,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS finance_goals_company_status_idx
      ON finance_goals(company_id, archived_at, status);

    CREATE TABLE IF NOT EXISTS finance_goal_contributions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      goal_id UUID NOT NULL REFERENCES finance_goals(id) ON DELETE RESTRICT,
      amount_cents BIGINT NOT NULL CHECK (amount_cents > 0),
      contribution_date DATE NOT NULL,
      note TEXT,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS finance_goal_contributions_goal_date_idx
      ON finance_goal_contributions(company_id, goal_id, contribution_date DESC);
  `);

  await pool.query(`ALTER TABLE finance_planned_items ADD COLUMN IF NOT EXISTS debt_id UUID`);
  await pool.query(`CREATE INDEX IF NOT EXISTS finance_planned_items_debt_idx ON finance_planned_items(company_id, debt_id)`);
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'finance_planned_items_debt_id_fkey'
      ) THEN
        ALTER TABLE finance_planned_items
          ADD CONSTRAINT finance_planned_items_debt_id_fkey
          FOREIGN KEY (debt_id) REFERENCES finance_debts(id) ON DELETE SET NULL;
      END IF;
    END $$;
  `);
}

function requireCompany(req, res) {
  if (!req.companyId) {
    res.status(400).json({ error: "company_required", message: "Finance requires a company workspace." });
    return false;
  }
  return true;
}

function handleFinanceError(res, error, fallback) {
  if (error?.statusCode) {
    return res.status(error.statusCode).json({
      error: error.code || fallback,
      message: error.message || "Finance request could not be completed."
    });
  }
  console.error("[finance]", fallback, error);
  return res.status(500).json({ error: fallback, message: "Finance request failed." });
}

async function loadActiveAccounts(pool, companyId) {
  const { rows } = await pool.query(
    `SELECT *
       FROM finance_accounts
      WHERE company_id = $1
        AND archived_at IS NULL
      ORDER BY account_type ASC, name ASC`,
    [companyId]
  );
  return rows.map(financeAccountPayload);
}

function overviewFromAccounts(accounts) {
  const total = accounts.reduce((sum, account) => sum + account.current_balance_cents, 0);
  const physicalCash = accounts
    .filter((account) => account.account_type === "cash")
    .reduce((sum, account) => sum + account.current_balance_cents, 0);
  return {
    total_liquid_cash_cents: total,
    physical_cash_cents: physicalCash,
    bank_balance_cents: 0,
    bank_accounts_connected: false,
    currency: "usd",
    active_account_count: accounts.length,
    manual_account_count: accounts.filter((account) => account.source === "manual").length,
    accounts
  };
}

async function ensureFinanceSettings(pool, companyId) {
  const { rows } = await pool.query(
    `INSERT INTO finance_settings (company_id)
     VALUES ($1)
     ON CONFLICT (company_id) DO UPDATE SET company_id = EXCLUDED.company_id
     RETURNING *`,
    [companyId]
  );
  return financeSettingsPayload(rows[0]);
}

function nextOccurrenceDate(dateString, recurrence) {
  switch (recurrence) {
  case "weekly": return addDays(dateString, 7);
  case "biweekly": return addDays(dateString, 14);
  case "monthly": return addMonthsClamped(dateString, 1);
  case "yearly": return addYearsClamped(dateString, 1);
  default: return null;
  }
}

export function expandPlannedItemOccurrences(item, startDate, endDate) {
  const occurrences = [];
  const recurrence = item.recurrence || "none";
  const recurrenceEnd = item.recurrence_end_date || null;
  let occurrenceDate = item.scheduled_date;
  let guard = 0;

  while (occurrenceDate && occurrenceDate <= endDate && guard < 500) {
    if ((!recurrenceEnd || occurrenceDate <= recurrenceEnd) && occurrenceDate >= startDate) {
      const signedAmount = item.direction === "income" ? item.amount_cents : -item.amount_cents;
      occurrences.push({
        planned_item_id: item.id,
        account_id: item.account_id || null,
        account_name: item.account_name || null,
        title: item.title,
        direction: item.direction,
        amount_cents: item.amount_cents,
        signed_amount_cents: signedAmount,
        category: item.category,
        recurrence,
        occurrence_date: occurrenceDate
      });
    }
    if (recurrence === "none") break;
    occurrenceDate = nextOccurrenceDate(occurrenceDate, recurrence);
    if (recurrenceEnd && occurrenceDate > recurrenceEnd) break;
    guard += 1;
  }
  return occurrences;
}

function compareProjectionOccurrences(a, b) {
  if (a.occurrence_date !== b.occurrence_date) return a.occurrence_date < b.occurrence_date ? -1 : 1;
  if (a.direction !== b.direction) return a.direction === "expense" ? -1 : 1;
  if (a.title !== b.title) return a.title.localeCompare(b.title);
  return String(a.planned_item_id).localeCompare(String(b.planned_item_id));
}

export function buildProjection({ startingBalanceCents, minimumReserveCents, plannedItems, startDate, endDate }) {
  const occurrences = plannedItems
    .filter((item) => !item.archived_at)
    .flatMap((item) => expandPlannedItemOccurrences(item, startDate, endDate))
    .sort(compareProjectionOccurrences);

  let runningBalance = startingBalanceCents;
  let totalIncome = 0;
  let totalExpenses = 0;
  let lowestBalance = startingBalanceCents;
  let lowestDate = startDate;
  const projectedEvents = [];

  for (const occurrence of occurrences) {
    if (occurrence.direction === "income") totalIncome += occurrence.amount_cents;
    else totalExpenses += occurrence.amount_cents;
    runningBalance += occurrence.signed_amount_cents;
    if (runningBalance < lowestBalance) {
      lowestBalance = runningBalance;
      lowestDate = occurrence.occurrence_date;
    }
    projectedEvents.push({
      ...occurrence,
      balance_after_cents: runningBalance
    });
  }

  const rawSafeToSpend = lowestBalance - minimumReserveCents;
  return {
    start_date: startDate,
    end_date: endDate,
    starting_balance_cents: startingBalanceCents,
    ending_balance_cents: runningBalance,
    total_expected_income_cents: totalIncome,
    total_planned_expenses_cents: totalExpenses,
    lowest_projected_balance_cents: lowestBalance,
    lowest_projected_balance_date: lowestDate,
    minimum_cash_reserve_cents: minimumReserveCents,
    safe_to_spend_cents: Math.max(0, rawSafeToSpend),
    reserve_shortfall_cents: Math.max(0, -rawSafeToSpend),
    currency: "usd",
    events: projectedEvents
  };
}

async function loadActivePlannedItems(pool, companyId) {
  const { rows } = await pool.query(
    `SELECT p.*, a.name AS account_name
       FROM finance_planned_items p
       LEFT JOIN finance_accounts a ON a.id = p.account_id AND a.company_id = p.company_id
      WHERE p.company_id = $1
        AND p.archived_at IS NULL
      ORDER BY p.scheduled_date ASC, p.created_at ASC`,
    [companyId]
  );
  return rows.map(financePlannedItemPayload);
}

async function loadProjection(pool, companyId, horizonDays = 30) {
  const days = Math.max(1, Math.min(Number(horizonDays) || 30, 366));
  const accounts = await loadActiveAccounts(pool, companyId);
  const settings = await ensureFinanceSettings(pool, companyId);
  const startDate = new Date().toISOString().slice(0, 10);
  const endDate = addDays(startDate, days);
  const plannedItems = await loadActivePlannedItems(pool, companyId);
  const startingBalanceCents = accounts.reduce((sum, account) => sum + account.current_balance_cents, 0);
  return buildProjection({
    startingBalanceCents,
    minimumReserveCents: settings.minimum_cash_reserve_cents,
    plannedItems,
    startDate,
    endDate
  });
}

function todayDateString() {
  return new Date().toISOString().slice(0, 10);
}

function periodBounds(period, anchorDate = todayDateString()) {
  const [year, month, day] = anchorDate.split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  if (period === "weekly") {
    const mondayOffset = (date.getUTCDay() + 6) % 7;
    const start = addDays(anchorDate, -mondayOffset);
    return { start_date: start, end_date: addDays(start, 6) };
  }
  if (period === "yearly") {
    return { start_date: `${year}-01-01`, end_date: `${year}-12-31` };
  }
  const start = `${year}-${String(month).padStart(2, "0")}-01`;
  const end = new Date(Date.UTC(year, month, 0)).toISOString().slice(0, 10);
  return { start_date: start, end_date: end };
}

function debtPaymentCategory(debtType) {
  return isTaxDebt(debtType) ? "Taxes" : "Debt Payment";
}

async function syncDebtPlannedItem(client, companyId, debt, userId) {
  const shouldSchedule = debt.archived_at === null && debt.status === "active" && Number(debt.planned_payment_cents || 0) > 0;
  if (!shouldSchedule) {
    await client.query(
      `UPDATE finance_planned_items
          SET archived_at = COALESCE(archived_at, now()),
              updated_at = now()
        WHERE company_id = $1
          AND debt_id = $2
          AND archived_at IS NULL`,
      [companyId, debt.id]
    );
    return null;
  }

  const scheduledDate = debt.next_due_date ? dateOnlyFromDb(debt.next_due_date) : todayDateString();
  const category = debtPaymentCategory(debt.debt_type);
  const existing = await client.query(
    `SELECT *
       FROM finance_planned_items
      WHERE company_id = $1
        AND debt_id = $2
      ORDER BY archived_at NULLS FIRST, created_at ASC
      LIMIT 1`,
    [companyId, debt.id]
  );

  if (existing.rows.length) {
    const { rows } = await client.query(
      `UPDATE finance_planned_items
          SET title = $3,
              direction = 'expense',
              amount_cents = $4,
              scheduled_date = $5,
              category = $6,
              recurrence = 'monthly',
              recurrence_end_date = NULL,
              archived_at = NULL,
              updated_at = now()
        WHERE id = $1
          AND company_id = $2
        RETURNING *`,
      [existing.rows[0].id, companyId, `${debt.name} Payment`, debt.planned_payment_cents, scheduledDate, category]
    );
    return rows[0];
  }

  const { rows } = await client.query(
    `INSERT INTO finance_planned_items (
       company_id, debt_id, title, direction, amount_cents, scheduled_date,
       category, recurrence, created_by
     ) VALUES ($1,$2,$3,'expense',$4,$5,$6,'monthly',$7)
     RETURNING *`,
    [companyId, debt.id, `${debt.name} Payment`, debt.planned_payment_cents, scheduledDate, category, userId]
  );
  await client.query(
    `UPDATE finance_debts
        SET planned_item_id = $3,
            updated_at = now()
      WHERE id = $1
        AND company_id = $2`,
    [debt.id, companyId, rows[0].id]
  );
  return rows[0];
}

async function loadDebts(pool, companyId, includeArchived = false) {
  const { rows } = await pool.query(
    `SELECT *
       FROM finance_debts
      WHERE company_id = $1
        AND ($2::boolean OR archived_at IS NULL)
      ORDER BY archived_at NULLS FIRST,
               CASE priority WHEN 'high' THEN 0 WHEN 'normal' THEN 1 ELSE 2 END,
               created_at DESC`,
    [companyId, includeArchived]
  );
  return rows.map(debtPayload);
}

function debtPayoffForPayload(debt, startDate = todayDateString()) {
  const payoff = estimateDebtPayoff({
    balanceCents: debt.current_balance_cents,
    paymentCents: debt.planned_payment_cents,
    aprBasisPoints: debt.apr_basis_points,
    startDate
  });
  const target = debt.target_payoff_date
    ? requiredPaymentForTarget({
      balanceCents: debt.current_balance_cents,
      aprBasisPoints: debt.apr_basis_points,
      startDate,
      targetDate: debt.target_payoff_date
    })
    : null;
  return {
    debt_id: debt.id,
    current_balance_cents: debt.current_balance_cents,
    planned_payment_cents: debt.planned_payment_cents,
    ...payoff,
    target_payoff_date: debt.target_payoff_date,
    target_required_payment_cents: target?.required_payment_cents ?? null,
    target_status: target?.status ?? null,
    target_payment_difference_cents: target?.required_payment_cents === null || target?.required_payment_cents === undefined
      ? null
      : target.required_payment_cents - debt.planned_payment_cents
  };
}

function buildDebtSummary(debts) {
  const active = debts.filter((debt) => !debt.archived_at && debt.status === "active");
  const taxDebt = active.filter((debt) => isTaxDebt(debt.debt_type));
  const otherDebt = active.filter((debt) => !isTaxDebt(debt.debt_type));
  const payoffDates = active.map((debt) => debtPayoffForPayload(debt).estimated_payoff_date).filter(Boolean);
  const incomplete = active.some((debt) => debt.current_balance_cents > 0 && debt.planned_payment_cents <= 0);
  return {
    total_debt_cents: active.reduce((sum, debt) => sum + debt.current_balance_cents, 0),
    tax_debt_cents: taxDebt.reduce((sum, debt) => sum + debt.current_balance_cents, 0),
    other_debt_cents: otherDebt.reduce((sum, debt) => sum + debt.current_balance_cents, 0),
    monthly_planned_payments_cents: active.reduce((sum, debt) => sum + debt.planned_payment_cents, 0),
    active_debt_count: active.length,
    payment_plan_incomplete: incomplete,
    estimated_debt_free_date: incomplete || payoffDates.length !== active.length ? null : payoffDates.sort().at(-1) || null,
    tax_debt_free_date: taxDebt.some((debt) => debt.current_balance_cents > 0 && debt.planned_payment_cents <= 0)
      ? null
      : taxDebt.map((debt) => debtPayoffForPayload(debt).estimated_payoff_date).filter(Boolean).sort().at(-1) || null
  };
}

async function loadBudgetSummary(pool, companyId, period = "monthly") {
  const bounds = periodBounds(period);
  const budgetsResult = await pool.query(
    `SELECT *
       FROM finance_budgets
      WHERE company_id = $1
        AND archived_at IS NULL
        AND period = $2
        AND start_date <= $4
        AND (end_date IS NULL OR end_date >= $3)
      ORDER BY category ASC, name ASC`,
    [companyId, period, bounds.start_date, bounds.end_date]
  );
  const plannedItems = await loadActivePlannedItems(pool, companyId);
  const occurrences = plannedItems.flatMap((item) => expandPlannedItemOccurrences(item, bounds.start_date, bounds.end_date));
  const budgets = budgetsResult.rows.map(budgetPayload);
  const summaries = budgets.map((budget) => ({
    ...summarizeBudget({ budget, occurrences }),
    period: budget.period,
    period_start_date: bounds.start_date,
    period_end_date: bounds.end_date
  }));
  return {
    period,
    period_start_date: bounds.start_date,
    period_end_date: bounds.end_date,
    total_limit_cents: summaries.reduce((sum, budget) => sum + budget.limit_cents, 0),
    total_planned_spend_cents: summaries.reduce((sum, budget) => sum + budget.planned_spend_cents, 0),
    on_plan_count: summaries.filter((budget) => budget.status === "on_plan").length,
    over_plan_count: summaries.filter((budget) => budget.status === "over_plan").length,
    budgets: summaries
  };
}

function buildGoalsSummary(goals, startDate = todayDateString()) {
  const active = goals.filter((goal) => !goal.archived_at && goal.status === "active");
  return {
    active_goal_count: active.length,
    total_target_cents: active.reduce((sum, goal) => sum + goal.target_amount_cents, 0),
    total_current_cents: active.reduce((sum, goal) => sum + goal.current_amount_cents, 0),
    goals: active.slice(0, 3).map((goal) => ({
      goal_id: goal.id,
      name: goal.name,
      goal_type: goal.goal_type,
      ...goalMetrics({
        targetAmountCents: goal.target_amount_cents,
        currentAmountCents: goal.current_amount_cents,
        targetDate: goal.target_date,
        startDate
      })
    }))
  };
}

export async function installFinanceSystem({ app, pool, authRequired, requireEmployer }) {
  if (!app || !pool || !authRequired || !requireEmployer) {
    throw new Error("finance_installer_missing_dependencies");
  }

  await installFinanceSchema(pool);

  app.get("/api/finance/health", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    res.json({
      ok: true,
      company_id: req.companyId,
      setup_complete: false
    });
  });

  app.get("/api/finance/overview", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const accounts = await loadActiveAccounts(pool, req.companyId);
      const projection = await loadProjection(pool, req.companyId, 30);
      const plannedItems = await loadActivePlannedItems(pool, req.companyId);
      const debts = await loadDebts(pool, req.companyId);
      const budgets = await loadBudgetSummary(pool, req.companyId, "monthly");
      const goalsResult = await pool.query(
        `SELECT *
           FROM finance_goals
          WHERE company_id = $1
            AND archived_at IS NULL
          ORDER BY created_at DESC`,
        [req.companyId]
      );
      const goals = goalsResult.rows.map(goalPayload);
      res.json({
        ...overviewFromAccounts(accounts),
        projection,
        upcoming: projection.events.slice(0, 8),
        planned_item_count: plannedItems.length,
        debt_summary: buildDebtSummary(debts),
        budget_summary: budgets,
        goals_summary: buildGoalsSummary(goals)
      });
    } catch (error) {
      handleFinanceError(res, error, "finance_overview_failed");
    }
  });

  app.get("/api/finance/settings", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      res.json(await ensureFinanceSettings(pool, req.companyId));
    } catch (error) {
      handleFinanceError(res, error, "finance_settings_failed");
    }
  });

  app.patch("/api/finance/settings", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const minimumReserveCents = parseCents(req.body?.minimum_cash_reserve_cents ?? 0, "minimum_cash_reserve_cents");
      if (minimumReserveCents < 0) return res.status(400).json({ error: "minimum_cash_reserve_invalid", message: "Minimum reserve cannot be negative." });
      const currency = normalizeCurrency(req.body?.currency || "usd");
      if (!currency) return res.status(400).json({ error: "invalid_currency", message: "Currency is not supported yet." });
      const { rows } = await pool.query(
        `INSERT INTO finance_settings (company_id, minimum_cash_reserve_cents, currency)
         VALUES ($1,$2,$3)
         ON CONFLICT (company_id) DO UPDATE
           SET minimum_cash_reserve_cents = EXCLUDED.minimum_cash_reserve_cents,
               currency = EXCLUDED.currency,
               updated_at = now()
         RETURNING *`,
        [req.companyId, minimumReserveCents, currency]
      );
      res.json(financeSettingsPayload(rows[0]));
    } catch (error) {
      handleFinanceError(res, error, "finance_settings_update_failed");
    }
  });

  app.get("/api/finance/projection", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      res.json(await loadProjection(pool, req.companyId, req.query.horizon_days || 30));
    } catch (error) {
      handleFinanceError(res, error, "finance_projection_failed");
    }
  });

  app.get("/api/finance/accounts", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const includeArchived = req.query.include_archived === "true";
      const { rows } = await pool.query(
        `SELECT *
           FROM finance_accounts
          WHERE company_id = $1
            AND ($2::boolean OR archived_at IS NULL)
          ORDER BY archived_at NULLS FIRST, account_type ASC, name ASC`,
        [req.companyId, includeArchived]
      );
      res.json(rows.map(financeAccountPayload));
    } catch (error) {
      handleFinanceError(res, error, "finance_accounts_failed");
    }
  });

  app.post("/api/finance/accounts", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    const client = await pool.connect();
    try {
      const name = cleanString(req.body?.name, 120);
      const accountType = normalizeAccountType(req.body?.account_type || "cash");
      const currency = normalizeCurrency(req.body?.currency || "usd");
      const startingBalanceCents = parseCents(req.body?.starting_balance_cents ?? 0, "starting_balance_cents");
      const note = cleanString(req.body?.note, 500) || null;

      if (!name) return res.status(400).json({ error: "account_name_required", message: "Account name is required." });
      if (!accountType) return res.status(400).json({ error: "invalid_account_type", message: "Choose a valid account type." });
      if (!currency) return res.status(400).json({ error: "invalid_currency", message: "Currency is not supported yet." });

      await client.query("BEGIN");
      const accountResult = await client.query(
        `INSERT INTO finance_accounts (
           company_id, name, account_type, source, current_balance_cents, currency, created_by
         ) VALUES ($1,$2,$3,'manual',$4,$5,$6)
         RETURNING *`,
        [req.companyId, name, accountType, startingBalanceCents, currency, req.userId]
      );
      const account = accountResult.rows[0];
      const entryResult = await client.query(
        `INSERT INTO finance_account_entries (
           company_id, account_id, entry_type, amount_delta_cents,
           previous_balance_cents, resulting_balance_cents, currency, note, created_by
         ) VALUES ($1,$2,'initial_balance',$3,0,$3,$4,$5,$6)
         RETURNING *`,
        [req.companyId, account.id, startingBalanceCents, currency, note, req.userId]
      );
      await client.query("COMMIT");
      res.status(201).json({
        account: financeAccountPayload(account),
        entry: financeEntryPayload(entryResult.rows[0])
      });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      handleFinanceError(res, error, "finance_account_create_failed");
    } finally {
      client.release();
    }
  });

  app.patch("/api/finance/accounts/:id", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const updates = [];
      const values = [req.params.id, req.companyId];
      if (Object.prototype.hasOwnProperty.call(req.body || {}, "name")) {
        const name = cleanString(req.body.name, 120);
        if (!name) return res.status(400).json({ error: "account_name_required", message: "Account name is required." });
        values.push(name);
        updates.push(`name = $${values.length}`);
      }
      if (Object.prototype.hasOwnProperty.call(req.body || {}, "account_type")) {
        const accountType = normalizeAccountType(req.body.account_type);
        if (!accountType) return res.status(400).json({ error: "invalid_account_type", message: "Choose a valid account type." });
        values.push(accountType);
        updates.push(`account_type = $${values.length}`);
      }
      if (!updates.length) return res.status(400).json({ error: "no_account_changes", message: "No account changes were provided." });
      const { rows } = await pool.query(
        `UPDATE finance_accounts
            SET ${updates.join(", ")}, updated_at = now()
          WHERE id = $1
            AND company_id = $2
            AND source = 'manual'
          RETURNING *`,
        values
      );
      if (!rows.length) return res.status(404).json({ error: "finance_account_not_found", message: "Finance account was not found." });
      res.json(financeAccountPayload(rows[0]));
    } catch (error) {
      handleFinanceError(res, error, "finance_account_update_failed");
    }
  });

  app.post("/api/finance/accounts/:id/archive", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const { rows } = await pool.query(
        `UPDATE finance_accounts
            SET archived_at = COALESCE(archived_at, now()),
                updated_at = now()
          WHERE id = $1
            AND company_id = $2
            AND source = 'manual'
          RETURNING *`,
        [req.params.id, req.companyId]
      );
      if (!rows.length) return res.status(404).json({ error: "finance_account_not_found", message: "Finance account was not found." });
      res.json(financeAccountPayload(rows[0]));
    } catch (error) {
      handleFinanceError(res, error, "finance_account_archive_failed");
    }
  });

  app.get("/api/finance/accounts/:id/history", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const owned = await pool.query(
        `SELECT id FROM finance_accounts WHERE id = $1 AND company_id = $2 LIMIT 1`,
        [req.params.id, req.companyId]
      );
      if (!owned.rows.length) return res.status(404).json({ error: "finance_account_not_found", message: "Finance account was not found." });
      const limit = Math.min(Math.max(Number(req.query.limit || 50), 1), 200);
      const { rows } = await pool.query(
        `SELECT *
           FROM finance_account_entries
          WHERE account_id = $1
            AND company_id = $2
          ORDER BY created_at DESC
          LIMIT $3`,
        [req.params.id, req.companyId, limit]
      );
      res.json(rows.map(financeEntryPayload));
    } catch (error) {
      handleFinanceError(res, error, "finance_account_history_failed");
    }
  });

  app.post("/api/finance/accounts/:id/balance-adjustments", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    const client = await pool.connect();
    try {
      const newBalanceCents = parseCents(req.body?.new_balance_cents, "new_balance_cents");
      const note = cleanString(req.body?.note, 500) || null;

      await client.query("BEGIN");
      const accountResult = await client.query(
        `SELECT *
           FROM finance_accounts
          WHERE id = $1
            AND company_id = $2
            AND source = 'manual'
            AND archived_at IS NULL
          FOR UPDATE`,
        [req.params.id, req.companyId]
      );
      const account = accountResult.rows[0];
      if (!account) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "finance_account_not_found", message: "Active finance account was not found." });
      }
      const previousBalanceCents = Number(account.current_balance_cents || 0);
      const amountDeltaCents = newBalanceCents - previousBalanceCents;
      const updated = await client.query(
        `UPDATE finance_accounts
            SET current_balance_cents = $3,
                updated_at = now()
          WHERE id = $1
            AND company_id = $2
          RETURNING *`,
        [req.params.id, req.companyId, newBalanceCents]
      );
      const entryResult = await client.query(
        `INSERT INTO finance_account_entries (
           company_id, account_id, entry_type, amount_delta_cents,
           previous_balance_cents, resulting_balance_cents, currency, note, created_by
         ) VALUES ($1,$2,'manual_balance_adjustment',$3,$4,$5,$6,$7,$8)
         RETURNING *`,
        [
          req.companyId,
          account.id,
          amountDeltaCents,
          previousBalanceCents,
          newBalanceCents,
          account.currency,
          note,
          req.userId
        ]
      );
      await client.query("COMMIT");
      res.json({
        account: financeAccountPayload(updated.rows[0]),
        entry: financeEntryPayload(entryResult.rows[0])
      });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      handleFinanceError(res, error, "finance_balance_adjustment_failed");
    } finally {
      client.release();
    }
  });

  app.get("/api/finance/planned-items", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const includeArchived = req.query.include_archived === "true";
      const { rows } = await pool.query(
        `SELECT p.*, a.name AS account_name
           FROM finance_planned_items p
           LEFT JOIN finance_accounts a ON a.id = p.account_id AND a.company_id = p.company_id
          WHERE p.company_id = $1
            AND ($2::boolean OR p.archived_at IS NULL)
          ORDER BY p.archived_at NULLS FIRST, p.scheduled_date ASC, p.created_at ASC`,
        [req.companyId, includeArchived]
      );
      res.json(rows.map(financePlannedItemPayload));
    } catch (error) {
      handleFinanceError(res, error, "finance_planned_items_failed");
    }
  });

  app.post("/api/finance/planned-items", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const title = cleanString(req.body?.title, 140);
      const direction = normalizeDirection(req.body?.direction);
      const amountCents = parseCents(req.body?.amount_cents, "amount_cents");
      const scheduledDate = parseDateOnly(req.body?.scheduled_date, "scheduled_date");
      const category = cleanString(req.body?.category || "Other", 80) || "Other";
      const recurrence = normalizeRecurrence(req.body?.recurrence || "none");
      const recurrenceEndDate = req.body?.recurrence_end_date ? parseDateOnly(req.body.recurrence_end_date, "recurrence_end_date") : null;
      const notes = cleanString(req.body?.notes, 1000) || null;
      const accountId = cleanString(req.body?.account_id, 80) || null;

      if (!title) return res.status(400).json({ error: "planned_item_title_required", message: "Name is required." });
      if (!direction) return res.status(400).json({ error: "invalid_direction", message: "Choose income or expense." });
      if (amountCents < 0) return res.status(400).json({ error: "amount_cents_invalid", message: "Amount cannot be negative." });
      if (!recurrence) return res.status(400).json({ error: "invalid_recurrence", message: "Choose a valid recurrence." });
      if (recurrenceEndDate && recurrenceEndDate < scheduledDate) return res.status(400).json({ error: "recurrence_end_before_start", message: "End date must be after the start date." });

      if (accountId) {
        const account = await pool.query(`SELECT id FROM finance_accounts WHERE id = $1 AND company_id = $2 LIMIT 1`, [accountId, req.companyId]);
        if (!account.rows.length) return res.status(404).json({ error: "finance_account_not_found", message: "Finance account was not found." });
      }

      const { rows } = await pool.query(
        `INSERT INTO finance_planned_items (
           company_id, account_id, title, direction, amount_cents, scheduled_date,
           category, recurrence, recurrence_end_date, notes, created_by
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
         RETURNING *`,
        [req.companyId, accountId, title, direction, amountCents, scheduledDate, category, recurrence, recurrenceEndDate, notes, req.userId]
      );
      res.status(201).json(financePlannedItemPayload(rows[0]));
    } catch (error) {
      handleFinanceError(res, error, "finance_planned_item_create_failed");
    }
  });

  app.patch("/api/finance/planned-items/:id", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const existing = await pool.query(`SELECT * FROM finance_planned_items WHERE id = $1 AND company_id = $2 LIMIT 1`, [req.params.id, req.companyId]);
      if (!existing.rows.length) return res.status(404).json({ error: "finance_planned_item_not_found", message: "Planned item was not found." });

      const next = {
        account_id: Object.prototype.hasOwnProperty.call(req.body || {}, "account_id") ? (cleanString(req.body.account_id, 80) || null) : existing.rows[0].account_id,
        title: Object.prototype.hasOwnProperty.call(req.body || {}, "title") ? cleanString(req.body.title, 140) : existing.rows[0].title,
        direction: Object.prototype.hasOwnProperty.call(req.body || {}, "direction") ? normalizeDirection(req.body.direction) : existing.rows[0].direction,
        amount_cents: Object.prototype.hasOwnProperty.call(req.body || {}, "amount_cents") ? parseCents(req.body.amount_cents, "amount_cents") : Number(existing.rows[0].amount_cents),
        scheduled_date: Object.prototype.hasOwnProperty.call(req.body || {}, "scheduled_date") ? parseDateOnly(req.body.scheduled_date, "scheduled_date") : dateOnlyFromDb(existing.rows[0].scheduled_date),
        category: Object.prototype.hasOwnProperty.call(req.body || {}, "category") ? cleanString(req.body.category || "Other", 80) || "Other" : existing.rows[0].category,
        recurrence: Object.prototype.hasOwnProperty.call(req.body || {}, "recurrence") ? normalizeRecurrence(req.body.recurrence) : existing.rows[0].recurrence,
        recurrence_end_date: Object.prototype.hasOwnProperty.call(req.body || {}, "recurrence_end_date")
          ? (req.body.recurrence_end_date ? parseDateOnly(req.body.recurrence_end_date, "recurrence_end_date") : null)
          : (existing.rows[0].recurrence_end_date ? dateOnlyFromDb(existing.rows[0].recurrence_end_date) : null),
        notes: Object.prototype.hasOwnProperty.call(req.body || {}, "notes") ? cleanString(req.body.notes, 1000) || null : existing.rows[0].notes
      };
      if (!next.title) return res.status(400).json({ error: "planned_item_title_required", message: "Name is required." });
      if (!next.direction) return res.status(400).json({ error: "invalid_direction", message: "Choose income or expense." });
      if (next.amount_cents < 0) return res.status(400).json({ error: "amount_cents_invalid", message: "Amount cannot be negative." });
      if (!next.recurrence) return res.status(400).json({ error: "invalid_recurrence", message: "Choose a valid recurrence." });
      if (next.recurrence_end_date && next.recurrence_end_date < next.scheduled_date) return res.status(400).json({ error: "recurrence_end_before_start", message: "End date must be after the start date." });
      if (next.account_id) {
        const account = await pool.query(`SELECT id FROM finance_accounts WHERE id = $1 AND company_id = $2 LIMIT 1`, [next.account_id, req.companyId]);
        if (!account.rows.length) return res.status(404).json({ error: "finance_account_not_found", message: "Finance account was not found." });
      }
      const { rows } = await pool.query(
        `UPDATE finance_planned_items
            SET account_id = $3,
                title = $4,
                direction = $5,
                amount_cents = $6,
                scheduled_date = $7,
                category = $8,
                recurrence = $9,
                recurrence_end_date = $10,
                notes = $11,
                updated_at = now()
          WHERE id = $1
            AND company_id = $2
          RETURNING *`,
        [req.params.id, req.companyId, next.account_id, next.title, next.direction, next.amount_cents, next.scheduled_date, next.category, next.recurrence, next.recurrence_end_date, next.notes]
      );
      res.json(financePlannedItemPayload(rows[0]));
    } catch (error) {
      handleFinanceError(res, error, "finance_planned_item_update_failed");
    }
  });

  app.post("/api/finance/planned-items/:id/archive", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const { rows } = await pool.query(
        `UPDATE finance_planned_items
            SET archived_at = COALESCE(archived_at, now()),
                updated_at = now()
          WHERE id = $1
            AND company_id = $2
          RETURNING *`,
        [req.params.id, req.companyId]
      );
      if (!rows.length) return res.status(404).json({ error: "finance_planned_item_not_found", message: "Planned item was not found." });
      res.json(financePlannedItemPayload(rows[0]));
    } catch (error) {
      handleFinanceError(res, error, "finance_planned_item_archive_failed");
    }
  });

  app.get("/api/finance/debts", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const debts = await loadDebts(pool, req.companyId, req.query.include_archived === "true");
      res.json({ debts, summary: buildDebtSummary(debts) });
    } catch (error) {
      handleFinanceError(res, error, "finance_debts_failed");
    }
  });

  app.post("/api/finance/debts", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    const client = await pool.connect();
    try {
      const name = cleanString(req.body?.name, 140);
      const debtType = normalizeSet(req.body?.debt_type, VALID_DEBT_TYPES, "other");
      const currentBalance = parseCents(req.body?.current_balance_cents ?? 0, "current_balance_cents");
      const originalBalance = parseOptionalCents(req.body?.original_balance_cents, "original_balance_cents");
      const minimumPayment = parseCents(req.body?.minimum_payment_cents ?? 0, "minimum_payment_cents");
      const plannedPayment = parseCents(req.body?.planned_payment_cents ?? 0, "planned_payment_cents");
      const aprBps = parseOptionalAprBasisPoints(req.body?.apr_basis_points);
      const nextDue = parseOptionalDateOnly(req.body?.next_due_date, "next_due_date");
      const targetPayoff = parseOptionalDateOnly(req.body?.target_payoff_date, "target_payoff_date");
      const priority = normalizeSet(req.body?.priority, VALID_DEBT_PRIORITIES, "normal");
      const notes = cleanString(req.body?.notes, 1000) || null;
      if (!name) return res.status(400).json({ error: "debt_name_required", message: "Debt name is required." });
      if (!debtType) return res.status(400).json({ error: "invalid_debt_type", message: "Choose a valid debt type." });
      if (!priority) return res.status(400).json({ error: "invalid_debt_priority", message: "Choose a valid priority." });
      if ([currentBalance, originalBalance ?? 0, minimumPayment, plannedPayment, aprBps ?? 0].some((value) => value < 0)) {
        return res.status(400).json({ error: "finance_amount_invalid", message: "Amounts cannot be negative." });
      }

      await client.query("BEGIN");
      const { rows } = await client.query(
        `INSERT INTO finance_debts (
           company_id, name, debt_type, current_balance_cents, original_balance_cents,
           minimum_payment_cents, planned_payment_cents, apr_basis_points,
           next_due_date, target_payoff_date, priority, notes, status, created_by
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
         RETURNING *`,
        [
          req.companyId,
          name,
          debtType,
          currentBalance,
          originalBalance,
          minimumPayment,
          plannedPayment,
          aprBps,
          nextDue,
          targetPayoff,
          priority,
          notes,
          currentBalance === 0 ? "paid" : "active",
          req.userId
        ]
      );
      await syncDebtPlannedItem(client, req.companyId, rows[0], req.userId);
      const refreshed = await client.query(`SELECT * FROM finance_debts WHERE id = $1 AND company_id = $2`, [rows[0].id, req.companyId]);
      await client.query("COMMIT");
      res.status(201).json(debtPayload(refreshed.rows[0]));
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      handleFinanceError(res, error, "finance_debt_create_failed");
    } finally {
      client.release();
    }
  });

  app.get("/api/finance/debts/:id", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const { rows } = await pool.query(`SELECT * FROM finance_debts WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId]);
      if (!rows.length) return res.status(404).json({ error: "finance_debt_not_found", message: "Debt was not found." });
      const debt = debtPayload(rows[0]);
      res.json({ debt, payoff: debtPayoffForPayload(debt) });
    } catch (error) {
      handleFinanceError(res, error, "finance_debt_failed");
    }
  });

  app.patch("/api/finance/debts/:id", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const existing = await client.query(`SELECT * FROM finance_debts WHERE id = $1 AND company_id = $2 FOR UPDATE`, [req.params.id, req.companyId]);
      if (!existing.rows.length) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "finance_debt_not_found", message: "Debt was not found." });
      }
      const current = existing.rows[0];
      const next = {
        name: Object.prototype.hasOwnProperty.call(req.body || {}, "name") ? cleanString(req.body.name, 140) : current.name,
        debt_type: Object.prototype.hasOwnProperty.call(req.body || {}, "debt_type") ? normalizeSet(req.body.debt_type, VALID_DEBT_TYPES) : current.debt_type,
        current_balance_cents: Object.prototype.hasOwnProperty.call(req.body || {}, "current_balance_cents") ? parseCents(req.body.current_balance_cents, "current_balance_cents") : Number(current.current_balance_cents),
        original_balance_cents: Object.prototype.hasOwnProperty.call(req.body || {}, "original_balance_cents") ? parseOptionalCents(req.body.original_balance_cents, "original_balance_cents") : current.original_balance_cents,
        minimum_payment_cents: Object.prototype.hasOwnProperty.call(req.body || {}, "minimum_payment_cents") ? parseCents(req.body.minimum_payment_cents, "minimum_payment_cents") : Number(current.minimum_payment_cents),
        planned_payment_cents: Object.prototype.hasOwnProperty.call(req.body || {}, "planned_payment_cents") ? parseCents(req.body.planned_payment_cents, "planned_payment_cents") : Number(current.planned_payment_cents),
        apr_basis_points: Object.prototype.hasOwnProperty.call(req.body || {}, "apr_basis_points") ? parseOptionalAprBasisPoints(req.body.apr_basis_points) : current.apr_basis_points,
        next_due_date: Object.prototype.hasOwnProperty.call(req.body || {}, "next_due_date") ? parseOptionalDateOnly(req.body.next_due_date, "next_due_date") : (current.next_due_date ? dateOnlyFromDb(current.next_due_date) : null),
        target_payoff_date: Object.prototype.hasOwnProperty.call(req.body || {}, "target_payoff_date") ? parseOptionalDateOnly(req.body.target_payoff_date, "target_payoff_date") : (current.target_payoff_date ? dateOnlyFromDb(current.target_payoff_date) : null),
        priority: Object.prototype.hasOwnProperty.call(req.body || {}, "priority") ? normalizeSet(req.body.priority, VALID_DEBT_PRIORITIES) : current.priority,
        notes: Object.prototype.hasOwnProperty.call(req.body || {}, "notes") ? cleanString(req.body.notes, 1000) || null : current.notes
      };
      if (!next.name) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "debt_name_required", message: "Debt name is required." });
      }
      if (!next.debt_type) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "invalid_debt_type", message: "Choose a valid debt type." });
      }
      if (!next.priority) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "invalid_debt_priority", message: "Choose a valid priority." });
      }
      if ([next.current_balance_cents, next.original_balance_cents ?? 0, next.minimum_payment_cents, next.planned_payment_cents, next.apr_basis_points ?? 0].some((value) => Number(value) < 0)) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "finance_amount_invalid", message: "Amounts cannot be negative." });
      }
      const status = next.current_balance_cents === 0 ? "paid" : "active";
      const { rows } = await client.query(
        `UPDATE finance_debts
            SET name = $3,
                debt_type = $4,
                current_balance_cents = $5,
                original_balance_cents = $6,
                minimum_payment_cents = $7,
                planned_payment_cents = $8,
                apr_basis_points = $9,
                next_due_date = $10,
                target_payoff_date = $11,
                priority = $12,
                notes = $13,
                status = $14,
                updated_at = now()
          WHERE id = $1
            AND company_id = $2
          RETURNING *`,
        [req.params.id, req.companyId, next.name, next.debt_type, next.current_balance_cents, next.original_balance_cents, next.minimum_payment_cents, next.planned_payment_cents, next.apr_basis_points, next.next_due_date, next.target_payoff_date, next.priority, next.notes, status]
      );
      await syncDebtPlannedItem(client, req.companyId, rows[0], req.userId);
      const refreshed = await client.query(`SELECT * FROM finance_debts WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId]);
      await client.query("COMMIT");
      res.json(debtPayload(refreshed.rows[0]));
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      handleFinanceError(res, error, "finance_debt_update_failed");
    } finally {
      client.release();
    }
  });

  app.post("/api/finance/debts/:id/payments", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    const client = await pool.connect();
    try {
      const amount = parseCents(req.body?.amount_cents, "amount_cents");
      const paymentDate = parseDateOnly(req.body?.payment_date || todayDateString(), "payment_date");
      const note = cleanString(req.body?.note, 1000) || null;
      const financeAccountId = cleanString(req.body?.finance_account_id, 80) || null;
      if (amount <= 0) return res.status(400).json({ error: "finance_amount_invalid", message: "Payment amount must be greater than zero." });
      await client.query("BEGIN");
      const debtResult = await client.query(
        `SELECT * FROM finance_debts WHERE id = $1 AND company_id = $2 AND archived_at IS NULL FOR UPDATE`,
        [req.params.id, req.companyId]
      );
      if (!debtResult.rows.length) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "finance_debt_not_found", message: "Debt was not found." });
      }
      const debt = debtResult.rows[0];
      if (financeAccountId) {
        const account = await client.query(`SELECT id FROM finance_accounts WHERE id = $1 AND company_id = $2 LIMIT 1`, [financeAccountId, req.companyId]);
        if (!account.rows.length) {
          await client.query("ROLLBACK");
          return res.status(404).json({ error: "finance_account_not_found", message: "Finance account was not found." });
        }
      }
      const currentBalance = Number(debt.current_balance_cents || 0);
      if (amount > currentBalance) {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "debt_payment_exceeds_balance", message: "Payment cannot exceed the current debt balance." });
      }
      const nextBalance = currentBalance - amount;
      const payment = await client.query(
        `INSERT INTO finance_debt_payments (
           company_id, debt_id, amount_cents, payment_date, note, finance_account_id, created_by
         ) VALUES ($1,$2,$3,$4,$5,$6,$7)
         RETURNING *`,
        [req.companyId, debt.id, amount, paymentDate, note, financeAccountId, req.userId]
      );
      const updatedDebt = await client.query(
        `UPDATE finance_debts
            SET current_balance_cents = $3,
                status = $4,
                updated_at = now()
          WHERE id = $1
            AND company_id = $2
          RETURNING *`,
        [debt.id, req.companyId, nextBalance, nextBalance === 0 ? "paid" : "active"]
      );
      await syncDebtPlannedItem(client, req.companyId, updatedDebt.rows[0], req.userId);
      await client.query("COMMIT");
      res.status(201).json({ debt: debtPayload(updatedDebt.rows[0]), payment: debtPaymentPayload(payment.rows[0]) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      handleFinanceError(res, error, "finance_debt_payment_failed");
    } finally {
      client.release();
    }
  });

  app.get("/api/finance/debts/:id/payments", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const owned = await pool.query(`SELECT id FROM finance_debts WHERE id = $1 AND company_id = $2 LIMIT 1`, [req.params.id, req.companyId]);
      if (!owned.rows.length) return res.status(404).json({ error: "finance_debt_not_found", message: "Debt was not found." });
      const { rows } = await pool.query(
        `SELECT * FROM finance_debt_payments WHERE debt_id = $1 AND company_id = $2 ORDER BY payment_date DESC, created_at DESC`,
        [req.params.id, req.companyId]
      );
      res.json(rows.map(debtPaymentPayload));
    } catch (error) {
      handleFinanceError(res, error, "finance_debt_payments_failed");
    }
  });

  app.post("/api/finance/debts/:id/archive", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const { rows } = await client.query(
        `UPDATE finance_debts
            SET archived_at = COALESCE(archived_at, now()),
                updated_at = now()
          WHERE id = $1
            AND company_id = $2
          RETURNING *`,
        [req.params.id, req.companyId]
      );
      if (!rows.length) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "finance_debt_not_found", message: "Debt was not found." });
      }
      await syncDebtPlannedItem(client, req.companyId, rows[0], req.userId);
      await client.query("COMMIT");
      res.json(debtPayload(rows[0]));
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      handleFinanceError(res, error, "finance_debt_archive_failed");
    } finally {
      client.release();
    }
  });

  app.post("/api/finance/debts/:id/mark-paid", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const { rows } = await client.query(
        `UPDATE finance_debts
            SET current_balance_cents = 0,
                status = 'paid',
                updated_at = now()
          WHERE id = $1
            AND company_id = $2
          RETURNING *`,
        [req.params.id, req.companyId]
      );
      if (!rows.length) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "finance_debt_not_found", message: "Debt was not found." });
      }
      await syncDebtPlannedItem(client, req.companyId, rows[0], req.userId);
      await client.query("COMMIT");
      res.json(debtPayload(rows[0]));
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      handleFinanceError(res, error, "finance_debt_mark_paid_failed");
    } finally {
      client.release();
    }
  });

  app.get("/api/finance/debts/:id/payoff", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const { rows } = await pool.query(`SELECT * FROM finance_debts WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId]);
      if (!rows.length) return res.status(404).json({ error: "finance_debt_not_found", message: "Debt was not found." });
      const debt = debtPayload(rows[0]);
      res.json(debtPayoffForPayload(debt));
    } catch (error) {
      handleFinanceError(res, error, "finance_debt_payoff_failed");
    }
  });

  app.post("/api/finance/debts/:id/payment-preview", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const previewPayment = parseCents(req.body?.planned_payment_cents, "planned_payment_cents");
      if (previewPayment < 0) return res.status(400).json({ error: "finance_amount_invalid", message: "Payment cannot be negative." });
      const { rows } = await pool.query(`SELECT * FROM finance_debts WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId]);
      if (!rows.length) return res.status(404).json({ error: "finance_debt_not_found", message: "Debt was not found." });
      const debt = debtPayload(rows[0]);
      const current = debtPayoffForPayload(debt);
      const preview = debtPayoffForPayload({ ...debt, planned_payment_cents: previewPayment });
      const currentProjection = await loadProjection(pool, req.companyId, 30);
      const plannedItems = await loadActivePlannedItems(pool, req.companyId);
      const previewItems = plannedItems.map((item) => item.debt_id === debt.id ? { ...item, amount_cents: previewPayment } : item);
      const accounts = await loadActiveAccounts(pool, req.companyId);
      const settings = await ensureFinanceSettings(pool, req.companyId);
      const startDate = todayDateString();
      const previewProjection = buildProjection({
        startingBalanceCents: accounts.reduce((sum, account) => sum + account.current_balance_cents, 0),
        minimumReserveCents: settings.minimum_cash_reserve_cents,
        plannedItems: previewItems,
        startDate,
        endDate: addDays(startDate, 30)
      });
      res.json({ current, preview, current_projection: currentProjection, preview_projection: previewProjection });
    } catch (error) {
      handleFinanceError(res, error, "finance_debt_payment_preview_failed");
    }
  });

  app.get("/api/finance/budgets", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const { rows } = await pool.query(
        `SELECT * FROM finance_budgets WHERE company_id = $1 AND ($2::boolean OR archived_at IS NULL) ORDER BY category ASC, name ASC`,
        [req.companyId, req.query.include_archived === "true"]
      );
      res.json(rows.map(budgetPayload));
    } catch (error) {
      handleFinanceError(res, error, "finance_budgets_failed");
    }
  });

  app.post("/api/finance/budgets", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const name = cleanString(req.body?.name, 140);
      const category = cleanString(req.body?.category, 80);
      const limit = parseCents(req.body?.limit_cents, "limit_cents");
      const period = normalizeSet(req.body?.period, VALID_BUDGET_PERIODS, "monthly");
      const startDate = parseDateOnly(req.body?.start_date || periodBounds(period || "monthly").start_date, "start_date");
      const endDate = parseOptionalDateOnly(req.body?.end_date, "end_date");
      const notes = cleanString(req.body?.notes, 1000) || null;
      if (!name) return res.status(400).json({ error: "budget_name_required", message: "Budget name is required." });
      if (!category) return res.status(400).json({ error: "budget_category_required", message: "Budget category is required." });
      if (!period) return res.status(400).json({ error: "invalid_budget_period", message: "Choose a valid budget period." });
      if (limit < 0) return res.status(400).json({ error: "finance_amount_invalid", message: "Budget limit cannot be negative." });
      if (endDate && endDate < startDate) return res.status(400).json({ error: "budget_end_before_start", message: "End date must be after the start date." });
      const { rows } = await pool.query(
        `INSERT INTO finance_budgets (company_id, name, category, limit_cents, period, start_date, end_date, notes, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         RETURNING *`,
        [req.companyId, name, category, limit, period, startDate, endDate, notes, req.userId]
      );
      res.status(201).json(budgetPayload(rows[0]));
    } catch (error) {
      handleFinanceError(res, error, "finance_budget_create_failed");
    }
  });

  app.get("/api/finance/budget-summary", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const period = normalizeSet(req.query.period, VALID_BUDGET_PERIODS, "monthly") || "monthly";
      res.json(await loadBudgetSummary(pool, req.companyId, period));
    } catch (error) {
      handleFinanceError(res, error, "finance_budget_summary_failed");
    }
  });

  app.get("/api/finance/budgets/:id", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const { rows } = await pool.query(`SELECT * FROM finance_budgets WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId]);
      if (!rows.length) return res.status(404).json({ error: "finance_budget_not_found", message: "Budget was not found." });
      const budget = budgetPayload(rows[0]);
      const summary = await loadBudgetSummary(pool, req.companyId, budget.period);
      res.json({ budget, summary: summary.budgets.find((item) => item.budget_id === budget.id) || null });
    } catch (error) {
      handleFinanceError(res, error, "finance_budget_failed");
    }
  });

  app.patch("/api/finance/budgets/:id", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const existing = await pool.query(`SELECT * FROM finance_budgets WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId]);
      if (!existing.rows.length) return res.status(404).json({ error: "finance_budget_not_found", message: "Budget was not found." });
      const current = existing.rows[0];
      const next = {
        name: Object.prototype.hasOwnProperty.call(req.body || {}, "name") ? cleanString(req.body.name, 140) : current.name,
        category: Object.prototype.hasOwnProperty.call(req.body || {}, "category") ? cleanString(req.body.category, 80) : current.category,
        limit_cents: Object.prototype.hasOwnProperty.call(req.body || {}, "limit_cents") ? parseCents(req.body.limit_cents, "limit_cents") : Number(current.limit_cents),
        period: Object.prototype.hasOwnProperty.call(req.body || {}, "period") ? normalizeSet(req.body.period, VALID_BUDGET_PERIODS) : current.period,
        start_date: Object.prototype.hasOwnProperty.call(req.body || {}, "start_date") ? parseDateOnly(req.body.start_date, "start_date") : dateOnlyFromDb(current.start_date),
        end_date: Object.prototype.hasOwnProperty.call(req.body || {}, "end_date") ? parseOptionalDateOnly(req.body.end_date, "end_date") : (current.end_date ? dateOnlyFromDb(current.end_date) : null),
        notes: Object.prototype.hasOwnProperty.call(req.body || {}, "notes") ? cleanString(req.body.notes, 1000) || null : current.notes
      };
      if (!next.name) return res.status(400).json({ error: "budget_name_required", message: "Budget name is required." });
      if (!next.category) return res.status(400).json({ error: "budget_category_required", message: "Budget category is required." });
      if (!next.period) return res.status(400).json({ error: "invalid_budget_period", message: "Choose a valid budget period." });
      if (next.limit_cents < 0) return res.status(400).json({ error: "finance_amount_invalid", message: "Budget limit cannot be negative." });
      if (next.end_date && next.end_date < next.start_date) return res.status(400).json({ error: "budget_end_before_start", message: "End date must be after the start date." });
      const { rows } = await pool.query(
        `UPDATE finance_budgets
            SET name = $3, category = $4, limit_cents = $5, period = $6,
                start_date = $7, end_date = $8, notes = $9, updated_at = now()
          WHERE id = $1 AND company_id = $2
          RETURNING *`,
        [req.params.id, req.companyId, next.name, next.category, next.limit_cents, next.period, next.start_date, next.end_date, next.notes]
      );
      res.json(budgetPayload(rows[0]));
    } catch (error) {
      handleFinanceError(res, error, "finance_budget_update_failed");
    }
  });

  app.post("/api/finance/budgets/:id/archive", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const { rows } = await pool.query(
        `UPDATE finance_budgets SET archived_at = COALESCE(archived_at, now()), updated_at = now() WHERE id = $1 AND company_id = $2 RETURNING *`,
        [req.params.id, req.companyId]
      );
      if (!rows.length) return res.status(404).json({ error: "finance_budget_not_found", message: "Budget was not found." });
      res.json(budgetPayload(rows[0]));
    } catch (error) {
      handleFinanceError(res, error, "finance_budget_archive_failed");
    }
  });

  app.get("/api/finance/goals", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const { rows } = await pool.query(
        `SELECT * FROM finance_goals WHERE company_id = $1 AND ($2::boolean OR archived_at IS NULL) ORDER BY status ASC, created_at DESC`,
        [req.companyId, req.query.include_archived === "true"]
      );
      const goals = rows.map(goalPayload);
      res.json({ goals, summary: buildGoalsSummary(goals) });
    } catch (error) {
      handleFinanceError(res, error, "finance_goals_failed");
    }
  });

  app.post("/api/finance/goals", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const name = cleanString(req.body?.name, 140);
      const goalType = normalizeSet(req.body?.goal_type, VALID_GOAL_TYPES, "custom");
      const targetAmount = parseCents(req.body?.target_amount_cents, "target_amount_cents");
      const currentAmount = parseCents(req.body?.current_amount_cents ?? 0, "current_amount_cents");
      const targetDate = parseOptionalDateOnly(req.body?.target_date, "target_date");
      const notes = cleanString(req.body?.notes, 1000) || null;
      if (!name) return res.status(400).json({ error: "goal_name_required", message: "Goal name is required." });
      if (!goalType) return res.status(400).json({ error: "invalid_goal_type", message: "Choose a valid goal type." });
      if (targetAmount < 0 || currentAmount < 0) return res.status(400).json({ error: "finance_amount_invalid", message: "Amounts cannot be negative." });
      const { rows } = await pool.query(
        `INSERT INTO finance_goals (company_id, name, goal_type, target_amount_cents, current_amount_cents, target_date, status, notes, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         RETURNING *`,
        [req.companyId, name, goalType, targetAmount, currentAmount, targetDate, currentAmount >= targetAmount && targetAmount > 0 ? "completed" : "active", notes, req.userId]
      );
      res.status(201).json(goalPayload(rows[0]));
    } catch (error) {
      handleFinanceError(res, error, "finance_goal_create_failed");
    }
  });

  app.get("/api/finance/goals/:id", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const { rows } = await pool.query(`SELECT * FROM finance_goals WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId]);
      if (!rows.length) return res.status(404).json({ error: "finance_goal_not_found", message: "Goal was not found." });
      const goal = goalPayload(rows[0]);
      res.json({ goal, metrics: goalMetrics({ targetAmountCents: goal.target_amount_cents, currentAmountCents: goal.current_amount_cents, targetDate: goal.target_date, startDate: todayDateString() }) });
    } catch (error) {
      handleFinanceError(res, error, "finance_goal_failed");
    }
  });

  app.patch("/api/finance/goals/:id", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const existing = await pool.query(`SELECT * FROM finance_goals WHERE id = $1 AND company_id = $2`, [req.params.id, req.companyId]);
      if (!existing.rows.length) return res.status(404).json({ error: "finance_goal_not_found", message: "Goal was not found." });
      const current = existing.rows[0];
      const next = {
        name: Object.prototype.hasOwnProperty.call(req.body || {}, "name") ? cleanString(req.body.name, 140) : current.name,
        goal_type: Object.prototype.hasOwnProperty.call(req.body || {}, "goal_type") ? normalizeSet(req.body.goal_type, VALID_GOAL_TYPES) : current.goal_type,
        target_amount_cents: Object.prototype.hasOwnProperty.call(req.body || {}, "target_amount_cents") ? parseCents(req.body.target_amount_cents, "target_amount_cents") : Number(current.target_amount_cents),
        current_amount_cents: Object.prototype.hasOwnProperty.call(req.body || {}, "current_amount_cents") ? parseCents(req.body.current_amount_cents, "current_amount_cents") : Number(current.current_amount_cents),
        target_date: Object.prototype.hasOwnProperty.call(req.body || {}, "target_date") ? parseOptionalDateOnly(req.body.target_date, "target_date") : (current.target_date ? dateOnlyFromDb(current.target_date) : null),
        status: Object.prototype.hasOwnProperty.call(req.body || {}, "status") ? normalizeSet(req.body.status, VALID_GOAL_STATUSES) : current.status,
        notes: Object.prototype.hasOwnProperty.call(req.body || {}, "notes") ? cleanString(req.body.notes, 1000) || null : current.notes
      };
      if (!next.name) return res.status(400).json({ error: "goal_name_required", message: "Goal name is required." });
      if (!next.goal_type) return res.status(400).json({ error: "invalid_goal_type", message: "Choose a valid goal type." });
      if (!next.status) return res.status(400).json({ error: "invalid_goal_status", message: "Choose a valid goal status." });
      if (next.target_amount_cents < 0 || next.current_amount_cents < 0) return res.status(400).json({ error: "finance_amount_invalid", message: "Amounts cannot be negative." });
      const { rows } = await pool.query(
        `UPDATE finance_goals
            SET name = $3, goal_type = $4, target_amount_cents = $5,
                current_amount_cents = $6, target_date = $7, status = $8,
                notes = $9, updated_at = now()
          WHERE id = $1 AND company_id = $2
          RETURNING *`,
        [req.params.id, req.companyId, next.name, next.goal_type, next.target_amount_cents, next.current_amount_cents, next.target_date, next.status, next.notes]
      );
      res.json(goalPayload(rows[0]));
    } catch (error) {
      handleFinanceError(res, error, "finance_goal_update_failed");
    }
  });

  app.post("/api/finance/goals/:id/contributions", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    const client = await pool.connect();
    try {
      const amount = parseCents(req.body?.amount_cents, "amount_cents");
      const contributionDate = parseDateOnly(req.body?.contribution_date || todayDateString(), "contribution_date");
      const note = cleanString(req.body?.note, 1000) || null;
      if (amount <= 0) return res.status(400).json({ error: "finance_amount_invalid", message: "Contribution amount must be greater than zero." });
      await client.query("BEGIN");
      const goalResult = await client.query(`SELECT * FROM finance_goals WHERE id = $1 AND company_id = $2 AND archived_at IS NULL FOR UPDATE`, [req.params.id, req.companyId]);
      if (!goalResult.rows.length) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "finance_goal_not_found", message: "Goal was not found." });
      }
      const goal = goalResult.rows[0];
      const contribution = await client.query(
        `INSERT INTO finance_goal_contributions (company_id, goal_id, amount_cents, contribution_date, note, created_by)
         VALUES ($1,$2,$3,$4,$5,$6)
         RETURNING *`,
        [req.companyId, goal.id, amount, contributionDate, note, req.userId]
      );
      const newCurrent = Number(goal.current_amount_cents || 0) + amount;
      const updated = await client.query(
        `UPDATE finance_goals
            SET current_amount_cents = $3,
                status = $4,
                updated_at = now()
          WHERE id = $1 AND company_id = $2
          RETURNING *`,
        [goal.id, req.companyId, newCurrent, newCurrent >= Number(goal.target_amount_cents || 0) && Number(goal.target_amount_cents || 0) > 0 ? "completed" : "active"]
      );
      await client.query("COMMIT");
      res.status(201).json({ goal: goalPayload(updated.rows[0]), contribution: goalContributionPayload(contribution.rows[0]) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      handleFinanceError(res, error, "finance_goal_contribution_failed");
    } finally {
      client.release();
    }
  });

  app.get("/api/finance/goals/:id/contributions", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const owned = await pool.query(`SELECT id FROM finance_goals WHERE id = $1 AND company_id = $2 LIMIT 1`, [req.params.id, req.companyId]);
      if (!owned.rows.length) return res.status(404).json({ error: "finance_goal_not_found", message: "Goal was not found." });
      const { rows } = await pool.query(
        `SELECT * FROM finance_goal_contributions WHERE goal_id = $1 AND company_id = $2 ORDER BY contribution_date DESC, created_at DESC`,
        [req.params.id, req.companyId]
      );
      res.json(rows.map(goalContributionPayload));
    } catch (error) {
      handleFinanceError(res, error, "finance_goal_contributions_failed");
    }
  });

  app.post("/api/finance/goals/:id/archive", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const { rows } = await pool.query(
        `UPDATE finance_goals SET archived_at = COALESCE(archived_at, now()), updated_at = now() WHERE id = $1 AND company_id = $2 RETURNING *`,
        [req.params.id, req.companyId]
      );
      if (!rows.length) return res.status(404).json({ error: "finance_goal_not_found", message: "Goal was not found." });
      res.json(goalPayload(rows[0]));
    } catch (error) {
      handleFinanceError(res, error, "finance_goal_archive_failed");
    }
  });

  app.post("/api/finance/goals/:id/complete", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const { rows } = await pool.query(
        `UPDATE finance_goals SET status = 'completed', updated_at = now() WHERE id = $1 AND company_id = $2 RETURNING *`,
        [req.params.id, req.companyId]
      );
      if (!rows.length) return res.status(404).json({ error: "finance_goal_not_found", message: "Goal was not found." });
      res.json(goalPayload(rows[0]));
    } catch (error) {
      handleFinanceError(res, error, "finance_goal_complete_failed");
    }
  });
}
