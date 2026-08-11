const VALID_ACCOUNT_TYPES = new Set(["cash", "checking", "savings", "other"]);
const VALID_CURRENCIES = new Set(["usd"]);
const VALID_DIRECTIONS = new Set(["income", "expense"]);
const VALID_RECURRENCES = new Set(["none", "weekly", "biweekly", "monthly", "yearly"]);

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
      res.json({
        ...overviewFromAccounts(accounts),
        projection,
        upcoming: projection.events.slice(0, 8),
        planned_item_count: plannedItems.length
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
}
