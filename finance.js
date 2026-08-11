const VALID_ACCOUNT_TYPES = new Set(["cash", "checking", "savings", "other"]);
const VALID_CURRENCIES = new Set(["usd"]);

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
      res.json(overviewFromAccounts(accounts));
    } catch (error) {
      handleFinanceError(res, error, "finance_overview_failed");
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
}
