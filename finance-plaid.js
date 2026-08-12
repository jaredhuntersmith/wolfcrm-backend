import {
  analyzeRecurringTransactionPatterns,
  decryptAccessToken,
  encryptAccessToken,
  collectPlaidSyncPages,
  getPlaidEnvironmentConfig,
  getPlaidConfig,
  isSafeLocalDisconnectProviderFailure,
  normalizePlaidEnvironment,
  monthlyEquivalentCents,
  plaidAccountToFinanceAccount,
  plaidSecretForEnvironment,
  providerAmountToCents,
  safePlaidItemPayload,
  transactionPayloadFromPlaid
} from "./finance-plaid-helpers.js";
import { matchUnmatchedReceiptsForTransactions } from "./finance-receipt-matching.js";

const SANDBOX_INSTITUTION_IDS = new Set([
  "ins_109508",
  "ins_130016",
  "ins_109509",
  "ins_109510",
  "ins_109511",
  "ins_109512",
  "ins_43"
]);

function cleanString(value, maxLength = 200) {
  return (value || "").toString().trim().slice(0, maxLength);
}

function handlePlaidError(res, error, fallback) {
  if (error?.code === "finance_plaid_environment_unavailable") {
    return res.status(503).json({
      error: "finance_plaid_environment_unavailable",
      message: "This bank connection was created in a different Plaid environment and that environment is not configured."
    });
  }
  if (error?.statusCode) {
    return res.status(error.statusCode).json({ error: error.code || fallback, message: error.message || "Plaid request failed." });
  }
  const plaidError = error?.response?.data;
  if (plaidError?.error_code === "ITEM_LOGIN_REQUIRED") {
    return res.status(409).json({ error: "plaid_login_required", message: "Bank connection needs attention." });
  }
  if (plaidError?.error_code) {
    return res.status(502).json({ error: "plaid_provider_error", code: plaidError.error_code, message: safePlaidMessage(plaidError) });
  }
  console.error("[finance-plaid]", fallback, {
    message: error?.message,
    request_id: plaidError?.request_id
  });
  return res.status(500).json({ error: fallback, message: "Bank connection request failed." });
}

function plaidEnvironmentUnavailableError(environment) {
  const error = new Error("finance_plaid_environment_unavailable");
  error.statusCode = 503;
  error.code = "finance_plaid_environment_unavailable";
  error.environment = normalizePlaidEnvironment(environment) || "unknown";
  return error;
}

function safePlaidFailureLog(label, error, extra = {}) {
  const plaidError = error?.response?.data || {};
  console.error("[finance-plaid]", label, {
    request_id: plaidError.request_id || extra.request_id || null,
    plaid_item_internal_id: extra.plaid_item_internal_id || null,
    item_environment: extra.item_environment || null,
    plaid_error_type: plaidError.error_type || null,
    plaid_error_code: plaidError.error_code || error?.code || null,
    http_status: error?.response?.status || error?.statusCode || null,
    message: error?.message
  });
}

function safePlaidMessage(plaidError) {
  switch (plaidError.error_code) {
  case "ITEM_LOGIN_REQUIRED": return "Bank connection needs attention.";
  case "INSTITUTION_DOWN": return "This institution is temporarily unavailable.";
  case "PRODUCTS_NOT_SUPPORTED": return "This bank account does not support the requested Finance data.";
  case "ACCESS_NOT_GRANTED": return "Bank access was not granted.";
  default: return "Plaid could not complete this request.";
  }
}

function requireCompany(req, res) {
  if (!req.companyId) {
    res.status(400).json({ error: "company_required", message: "Finance requires a company workspace." });
    return false;
  }
  return true;
}

function requirePlaidConfigured(res) {
  const status = getPlaidConfig();
  if (!status.configured) {
    res.status(503).json({ error: "plaid_not_configured", message: "Plaid is not configured on the backend." });
    return null;
  }
  if (!status.encryption_configured) {
    res.status(503).json({ error: "finance_token_encryption_key_missing", message: "Finance token encryption is not configured." });
    return null;
  }
  return status;
}

function requirePlaidEnvironmentConfigured(res, environment) {
  const config = getPlaidEnvironmentConfig(environment);
  if (!config.configured) {
    res.status(503).json({
      error: "finance_plaid_environment_unavailable",
      message: "This bank connection was created in a different Plaid environment and that environment is not configured."
    });
    return null;
  }
  const status = getPlaidConfig();
  if (!status.encryption_configured) {
    res.status(503).json({ error: "finance_token_encryption_key_missing", message: "Finance token encryption is not configured." });
    return null;
  }
  return config;
}

function plaidBasePath(PlaidEnvironments, environment) {
  if (environment === "production") return PlaidEnvironments.production;
  if (environment === "development") return PlaidEnvironments.development;
  return PlaidEnvironments.sandbox;
}

export async function plaidClientForEnvironment(environment) {
  const normalized = normalizePlaidEnvironment(environment);
  const secret = plaidSecretForEnvironment(normalized);
  if (!normalized || !process.env.PLAID_CLIENT_ID || !secret) {
    throw plaidEnvironmentUnavailableError(environment);
  }
  const { Configuration, PlaidApi, PlaidEnvironments } = await import("plaid");
  const configuration = new Configuration({
    basePath: plaidBasePath(PlaidEnvironments, normalized),
    baseOptions: {
      headers: {
        "PLAID-CLIENT-ID": process.env.PLAID_CLIENT_ID,
        "PLAID-SECRET": secret
      }
    }
  });
  return new PlaidApi(configuration);
}

async function plaidClient() {
  return plaidClientForEnvironment(getPlaidConfig().environment);
}

async function plaidClientForItem(item) {
  return plaidClientForEnvironment(item.environment || getPlaidConfig().environment);
}

export async function installPlaidSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS finance_plaid_items (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      plaid_item_id TEXT NOT NULL,
      institution_id TEXT,
      institution_name TEXT,
      access_token_ciphertext TEXT NOT NULL,
      access_token_iv TEXT NOT NULL,
      access_token_auth_tag TEXT NOT NULL,
      token_encryption_version INTEGER NOT NULL DEFAULT 1,
      environment TEXT NOT NULL CHECK (environment IN ('sandbox','development','production')),
      status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','login_required','error','syncing','disconnected')),
      transactions_cursor TEXT,
      last_successful_sync_at TIMESTAMPTZ,
      last_attempted_sync_at TIMESTAMPTZ,
      last_balance_refresh_at TIMESTAMPTZ,
      last_transaction_refresh_at TIMESTAMPTZ,
      last_webhook_at TIMESTAMPTZ,
      error_code TEXT,
      error_message TEXT,
      consent_expiration_time TIMESTAMPTZ,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      disconnected_at TIMESTAMPTZ,
      UNIQUE(environment, plaid_item_id)
    );
    CREATE INDEX IF NOT EXISTS finance_plaid_items_company_status_idx
      ON finance_plaid_items(company_id, status, disconnected_at);

    CREATE TABLE IF NOT EXISTS finance_transactions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      account_id UUID NOT NULL REFERENCES finance_accounts(id) ON DELETE RESTRICT,
      source TEXT NOT NULL DEFAULT 'plaid' CHECK (source IN ('plaid','manual')),
      status TEXT NOT NULL CHECK (status IN ('pending','posted')),
      direction TEXT NOT NULL CHECK (direction IN ('expense','income')),
      amount_cents BIGINT NOT NULL CHECK (amount_cents >= 0),
      transaction_date DATE NOT NULL,
      authorized_date DATE,
      merchant_name TEXT,
      original_name TEXT,
      category_primary TEXT,
      category_detailed TEXT,
      normalized_category TEXT,
      user_category_override TEXT,
      payment_channel TEXT,
      pending BOOLEAN NOT NULL DEFAULT false,
      merchant_entity_id TEXT,
      website TEXT,
      location_city TEXT,
      location_region TEXT,
      location_postal_code TEXT,
      location_country TEXT,
      iso_currency_code TEXT,
      provider_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      removed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS finance_transactions_company_date_idx
      ON finance_transactions(company_id, transaction_date DESC, created_at DESC);
    CREATE INDEX IF NOT EXISTS finance_transactions_budget_idx
      ON finance_transactions(company_id, normalized_category, transaction_date, status, removed_at);

    CREATE TABLE IF NOT EXISTS finance_transaction_provider_refs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      transaction_id UUID NOT NULL REFERENCES finance_transactions(id) ON DELETE RESTRICT,
      plaid_item_internal_id UUID NOT NULL REFERENCES finance_plaid_items(id) ON DELETE RESTRICT,
      provider TEXT NOT NULL DEFAULT 'plaid',
      provider_transaction_id TEXT NOT NULL,
      is_current BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(provider, provider_transaction_id)
    );
    CREATE INDEX IF NOT EXISTS finance_transaction_refs_transaction_idx
      ON finance_transaction_provider_refs(company_id, transaction_id, is_current);

    CREATE TABLE IF NOT EXISTS finance_plaid_recurring_streams (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      plaid_item_internal_id UUID NOT NULL REFERENCES finance_plaid_items(id) ON DELETE RESTRICT,
      plaid_stream_id TEXT NOT NULL,
      direction TEXT NOT NULL CHECK (direction IN ('expense','income')),
      merchant_name TEXT,
      description TEXT,
      category TEXT,
      frequency TEXT,
      last_amount_cents BIGINT,
      average_amount_cents BIGINT,
      first_date DATE,
      last_date DATE,
      is_active BOOLEAN NOT NULL DEFAULT true,
      status TEXT,
      confidence_level TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(plaid_item_internal_id, plaid_stream_id)
    );

    CREATE TABLE IF NOT EXISTS finance_recurring_candidates (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      merchant_normalized TEXT NOT NULL,
      display_name TEXT NOT NULL,
      direction TEXT NOT NULL CHECK (direction IN ('expense','income')),
      candidate_type TEXT NOT NULL CHECK (candidate_type IN ('subscription','recurring_bill','recurring_expense','recurring_income','debt_payment','repeated_merchant')),
      cadence TEXT NOT NULL CHECK (cadence IN ('weekly','biweekly','monthly','quarterly','yearly','irregular')),
      average_amount_cents BIGINT NOT NULL DEFAULT 0,
      median_amount_cents BIGINT NOT NULL DEFAULT 0,
      min_amount_cents BIGINT NOT NULL DEFAULT 0,
      max_amount_cents BIGINT NOT NULL DEFAULT 0,
      variability TEXT NOT NULL DEFAULT 'fixed' CHECK (variability IN ('fixed','mostly_fixed','variable')),
      variability_score_cents BIGINT NOT NULL DEFAULT 0,
      first_seen_date DATE,
      last_seen_date DATE,
      next_expected_date DATE,
      occurrence_count INTEGER NOT NULL DEFAULT 0,
      confidence_score INTEGER NOT NULL DEFAULT 0,
      confidence_label TEXT NOT NULL DEFAULT 'low' CHECK (confidence_label IN ('high','medium','low')),
      source TEXT NOT NULL DEFAULT 'wolfcrm_inferred' CHECK (source IN ('wolfcrm_inferred','plaid_detected','both')),
      status TEXT NOT NULL DEFAULT 'detected' CHECK (status IN ('detected','confirmed','ignored','ended')),
      category TEXT,
      account_id UUID REFERENCES finance_accounts(id) ON DELETE SET NULL,
      linked_planned_item_id UUID REFERENCES finance_planned_items(id) ON DELETE SET NULL,
      ignored_at TIMESTAMPTZ,
      confirmed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, merchant_normalized, direction, cadence)
    );
    CREATE INDEX IF NOT EXISTS finance_recurring_candidates_company_status_idx
      ON finance_recurring_candidates(company_id, status, updated_at DESC);

    CREATE TABLE IF NOT EXISTS finance_recurring_candidate_transactions (
      candidate_id UUID NOT NULL REFERENCES finance_recurring_candidates(id) ON DELETE CASCADE,
      transaction_id UUID NOT NULL REFERENCES finance_transactions(id) ON DELETE CASCADE,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY(candidate_id, transaction_id)
    );

    CREATE TABLE IF NOT EXISTS finance_plaid_item_events (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      plaid_item_internal_id UUID NOT NULL REFERENCES finance_plaid_items(id) ON DELETE RESTRICT,
      event_type TEXT NOT NULL,
      event_status TEXT NOT NULL,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS finance_plaid_item_events_company_idx
      ON finance_plaid_item_events(company_id, plaid_item_internal_id, created_at DESC);
  `);

  await pool.query(`ALTER TABLE finance_plaid_items ADD COLUMN IF NOT EXISTS environment TEXT`);
  await pool.query(
    `UPDATE finance_plaid_items
        SET environment = 'sandbox', updated_at = now()
      WHERE environment IS NULL
        AND institution_id = ANY($1::text[])`,
    [[...SANDBOX_INSTITUTION_IDS]]
  );
  await pool.query(`ALTER TABLE finance_plaid_items DROP CONSTRAINT IF EXISTS finance_plaid_items_environment_check`);
  await pool.query(`ALTER TABLE finance_plaid_items ADD CONSTRAINT finance_plaid_items_environment_check CHECK (environment IN ('sandbox','development','production'))`);
  await pool.query(`ALTER TABLE finance_accounts ADD COLUMN IF NOT EXISTS plaid_item_internal_id UUID REFERENCES finance_plaid_items(id) ON DELETE SET NULL`);
  await pool.query(`ALTER TABLE finance_accounts ADD COLUMN IF NOT EXISTS plaid_account_id TEXT`);
  await pool.query(`ALTER TABLE finance_accounts ADD COLUMN IF NOT EXISTS institution_name TEXT`);
  await pool.query(`ALTER TABLE finance_accounts ADD COLUMN IF NOT EXISTS official_name TEXT`);
  await pool.query(`ALTER TABLE finance_accounts ADD COLUMN IF NOT EXISTS mask TEXT`);
  await pool.query(`ALTER TABLE finance_accounts ADD COLUMN IF NOT EXISTS plaid_account_type TEXT`);
  await pool.query(`ALTER TABLE finance_accounts ADD COLUMN IF NOT EXISTS plaid_account_subtype TEXT`);
  await pool.query(`ALTER TABLE finance_accounts ADD COLUMN IF NOT EXISTS available_balance_cents BIGINT`);
  await pool.query(`ALTER TABLE finance_accounts ADD COLUMN IF NOT EXISTS iso_currency_code TEXT`);
  await pool.query(`ALTER TABLE finance_accounts ADD COLUMN IF NOT EXISTS include_in_liquid_cash BOOLEAN NOT NULL DEFAULT true`);
  await pool.query(`ALTER TABLE finance_accounts ADD COLUMN IF NOT EXISTS last_balance_update_at TIMESTAMPTZ`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS finance_accounts_plaid_account_unique_idx ON finance_accounts(company_id, plaid_account_id) WHERE source = 'plaid' AND plaid_account_id IS NOT NULL`);
}

export function plaidAccountPayload(row) {
  return {
    id: row.id,
    company_id: row.company_id,
    name: row.name,
    account_type: row.account_type,
    source: row.source,
    current_balance_cents: Number(row.current_balance_cents || 0),
    available_balance_cents: row.available_balance_cents === null || row.available_balance_cents === undefined ? null : Number(row.available_balance_cents),
    currency: row.currency,
    plaid_item_internal_id: row.plaid_item_internal_id || null,
    plaid_item_status: row.plaid_item_status || null,
    plaid_item_disconnected_at: row.plaid_item_disconnected_at || null,
    archived_at: row.archived_at,
    institution_name: row.institution_name,
    official_name: row.official_name,
    mask: row.mask,
    plaid_account_type: row.plaid_account_type,
    plaid_account_subtype: row.plaid_account_subtype,
    include_in_liquid_cash: row.include_in_liquid_cash,
    last_balance_update_at: row.last_balance_update_at,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

function transactionPayload(row) {
  return {
    id: row.id,
    company_id: row.company_id,
    account_id: row.account_id,
    account_name: row.account_name || null,
    institution_name: row.institution_name || null,
    source: row.source,
    status: row.status,
    direction: row.direction,
    amount_cents: Number(row.amount_cents || 0),
    transaction_date: row.transaction_date instanceof Date ? row.transaction_date.toISOString().slice(0, 10) : row.transaction_date,
    authorized_date: row.authorized_date instanceof Date ? row.authorized_date.toISOString().slice(0, 10) : row.authorized_date,
    merchant_name: row.merchant_name,
    original_name: row.original_name,
    category_primary: row.category_primary,
    category_detailed: row.category_detailed,
    normalized_category: row.normalized_category,
    user_category_override: row.user_category_override,
    payment_channel: row.payment_channel,
    pending: row.pending,
    merchant_entity_id: row.merchant_entity_id,
    website: row.website,
    location_city: row.location_city,
    location_region: row.location_region,
    location_postal_code: row.location_postal_code,
    location_country: row.location_country,
    iso_currency_code: row.iso_currency_code,
    removed_at: row.removed_at,
    receipt_count: Number(row.receipt_count || 0),
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

function dateOnlyPayload(value) {
  if (!value) return null;
  if (value instanceof Date) return value.toISOString().slice(0, 10);
  return String(value).slice(0, 10);
}

function recurringCandidatePayload(row) {
  const medianAmount = Number(row.median_amount_cents || 0);
  const cadence = row.cadence || "irregular";
  return {
    id: row.id,
    company_id: row.company_id,
    merchant_normalized: row.merchant_normalized,
    display_name: row.display_name,
    direction: row.direction,
    candidate_type: row.candidate_type,
    cadence,
    average_amount_cents: Number(row.average_amount_cents || 0),
    median_amount_cents: medianAmount,
    min_amount_cents: Number(row.min_amount_cents || 0),
    max_amount_cents: Number(row.max_amount_cents || 0),
    variability: row.variability,
    variability_score_cents: Number(row.variability_score_cents || 0),
    first_seen_date: dateOnlyPayload(row.first_seen_date),
    last_seen_date: dateOnlyPayload(row.last_seen_date),
    next_expected_date: dateOnlyPayload(row.next_expected_date),
    occurrence_count: Number(row.occurrence_count || 0),
    confidence_score: Number(row.confidence_score || 0),
    confidence_label: row.confidence_label || "low",
    source: row.source || "wolfcrm_inferred",
    status: row.status || "detected",
    category: row.category || null,
    account_id: row.account_id || null,
    account_name: row.account_name || null,
    linked_planned_item_id: row.linked_planned_item_id || null,
    ignored_at: row.ignored_at || null,
    confirmed_at: row.confirmed_at || null,
    created_at: row.created_at,
    updated_at: row.updated_at,
    monthly_equivalent_cents: monthlyEquivalentCents(medianAmount, cadence)
  };
}

function recurringCandidateSummary(candidates) {
  return candidates.reduce((summary, candidate) => {
    if (candidate.status !== "confirmed") return summary;
    const monthly = candidate.monthly_equivalent_cents || monthlyEquivalentCents(candidate.median_amount_cents || 0, candidate.cadence);
    if (candidate.direction === "income") {
      summary.confirmed_monthly_income_cents += monthly;
    } else {
      summary.confirmed_monthly_expense_cents += monthly;
    }
    summary.confirmed_count += 1;
    summary.net_monthly_cents = summary.confirmed_monthly_income_cents - summary.confirmed_monthly_expense_cents;
    return summary;
  }, {
    confirmed_monthly_expense_cents: 0,
    confirmed_monthly_income_cents: 0,
    net_monthly_cents: 0,
    confirmed_count: 0
  });
}

async function loadRecurringCandidates(pool, companyId, includeIgnored = false) {
  const { rows } = await pool.query(
    `SELECT c.*, a.name AS account_name
       FROM finance_recurring_candidates c
       LEFT JOIN finance_accounts a ON a.id = c.account_id AND a.company_id = c.company_id
      WHERE c.company_id = $1
        AND ($2::boolean OR c.status <> 'ignored')
      ORDER BY
        CASE c.status WHEN 'confirmed' THEN 0 WHEN 'detected' THEN 1 WHEN 'ended' THEN 2 ELSE 3 END,
        c.confidence_score DESC,
        c.next_expected_date ASC NULLS LAST,
        c.updated_at DESC`,
    [companyId, includeIgnored]
  );
  return rows.map(recurringCandidatePayload);
}

async function findMatchingPlannedItem(client, companyId, candidate) {
  const { rows } = await client.query(
    `SELECT *
       FROM finance_planned_items
      WHERE company_id = $1
        AND archived_at IS NULL
        AND direction = $2
        AND recurrence = $3
        AND (
          lower(title) = lower($4)
          OR lower(title) LIKE lower($5)
          OR lower($4) LIKE '%' || lower(title) || '%'
        )
      ORDER BY abs(amount_cents - $6) ASC, created_at DESC
      LIMIT 1`,
    [
      companyId,
      candidate.direction,
      candidate.cadence,
      candidate.display_name,
      `%${candidate.display_name}%`,
      Number(candidate.median_amount_cents || 0)
    ]
  );
  return rows[0] || null;
}

async function getPlaidItem(pool, companyId, id) {
  const { rows } = await pool.query(
    `SELECT * FROM finance_plaid_items WHERE id = $1 AND company_id = $2 AND disconnected_at IS NULL`,
    [id, companyId]
  );
  return rows[0] || null;
}

async function getPlaidItemIncludingDisconnected(pool, companyId, id) {
  const { rows } = await pool.query(
    `SELECT * FROM finance_plaid_items WHERE id = $1 AND company_id = $2`,
    [id, companyId]
  );
  return rows[0] || null;
}

async function accountsForPlaidItem(pool, companyId, itemId) {
  const { rows } = await pool.query(
    `SELECT a.*, pi.status AS plaid_item_status, pi.disconnected_at AS plaid_item_disconnected_at
       FROM finance_accounts a
       JOIN finance_plaid_items pi ON pi.id = a.plaid_item_internal_id AND pi.company_id = a.company_id
      WHERE a.company_id = $1
        AND a.plaid_item_internal_id = $2
      ORDER BY a.archived_at NULLS FIRST, a.account_type ASC, a.name ASC`,
    [companyId, itemId]
  );
  return rows.map(plaidAccountPayload);
}

async function markPlaidItemDisconnected(pool, companyId, item, userId, reason = "user_disconnect", providerCleanup = null) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const updated = await client.query(
      `UPDATE finance_plaid_items
          SET status = 'disconnected',
              disconnected_at = COALESCE(disconnected_at, now()),
              error_code = NULL,
              error_message = NULL,
              updated_at = now()
        WHERE id = $1 AND company_id = $2
        RETURNING *`,
      [item.id, companyId]
    );
    await client.query(
      `UPDATE finance_accounts
          SET include_in_liquid_cash = false,
              updated_at = now()
        WHERE plaid_item_internal_id = $1 AND company_id = $2 AND source = 'plaid'`,
      [item.id, companyId]
    );
    await client.query(
      `UPDATE finance_plaid_recurring_streams
          SET is_active = false,
              status = COALESCE(status, 'disconnected'),
              updated_at = now()
        WHERE plaid_item_internal_id = $1 AND company_id = $2`,
      [item.id, companyId]
    );
    await client.query(
      `INSERT INTO finance_plaid_item_events(company_id, plaid_item_internal_id, event_type, event_status, metadata, created_by)
       VALUES($1,$2,'disconnect_plaid_item','succeeded',$3,$4)`,
      [companyId, item.id, JSON.stringify({ institution_name: item.institution_name || null, reason, provider_cleanup: providerCleanup }), userId || null]
    );
    await client.query("COMMIT");
    return updated.rows[0] || { ...item, status: "disconnected", disconnected_at: item.disconnected_at || new Date().toISOString() };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function decryptItemToken(item) {
  return decryptAccessToken(item);
}

async function upsertAccounts(client, companyId, plaidItem, accounts) {
  const results = [];
  for (const account of accounts) {
    const mapped = plaidAccountToFinanceAccount(account, plaidItem);
    const { rows } = await client.query(
      `INSERT INTO finance_accounts (
         company_id, name, account_type, source, current_balance_cents, available_balance_cents,
         currency, plaid_item_internal_id, plaid_account_id, institution_name, official_name, mask,
         plaid_account_type, plaid_account_subtype, iso_currency_code, include_in_liquid_cash,
         last_balance_update_at
       ) VALUES ($1,$2,$3,'plaid',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,now())
       ON CONFLICT (company_id, plaid_account_id) WHERE source = 'plaid' AND plaid_account_id IS NOT NULL
       DO UPDATE SET
         name = EXCLUDED.name,
         account_type = EXCLUDED.account_type,
         current_balance_cents = EXCLUDED.current_balance_cents,
         available_balance_cents = EXCLUDED.available_balance_cents,
         currency = EXCLUDED.currency,
         institution_name = EXCLUDED.institution_name,
         official_name = EXCLUDED.official_name,
         mask = EXCLUDED.mask,
         plaid_account_type = EXCLUDED.plaid_account_type,
         plaid_account_subtype = EXCLUDED.plaid_account_subtype,
         iso_currency_code = EXCLUDED.iso_currency_code,
         include_in_liquid_cash = EXCLUDED.include_in_liquid_cash,
         archived_at = NULL,
         last_balance_update_at = now(),
         updated_at = now()
       RETURNING *`,
      [
        companyId,
        mapped.name,
        mapped.account_type,
        mapped.current_balance_cents,
        mapped.available_balance_cents,
        mapped.currency,
        mapped.plaid_item_internal_id,
        mapped.plaid_account_id,
        mapped.institution_name,
        mapped.official_name,
        mapped.mask,
        mapped.plaid_account_type,
        mapped.plaid_account_subtype,
        mapped.iso_currency_code,
        mapped.include_in_liquid_cash
      ]
    );
    results.push(rows[0]);
  }
  return results;
}

async function applyPlaidTransaction(client, companyId, plaidItem, tx) {
  const accountResult = await client.query(
    `SELECT id FROM finance_accounts WHERE company_id = $1 AND plaid_account_id = $2 AND source = 'plaid' LIMIT 1`,
    [companyId, tx.account_id]
  );
  if (!accountResult.rows.length) return null;

  const providerId = tx.transaction_id;
  const existingRef = await client.query(
    `SELECT * FROM finance_transaction_provider_refs WHERE provider = 'plaid' AND provider_transaction_id = $1 LIMIT 1`,
    [providerId]
  );
  const pendingRef = tx.pending_transaction_id
    ? await client.query(
      `SELECT * FROM finance_transaction_provider_refs WHERE provider = 'plaid' AND provider_transaction_id = $1 LIMIT 1`,
      [tx.pending_transaction_id]
    )
    : { rows: [] };
  const transactionId = pendingRef.rows[0]?.transaction_id || existingRef.rows[0]?.transaction_id || null;
  const payload = transactionPayloadFromPlaid(tx, accountResult.rows[0].id);

  let row;
  if (transactionId) {
    const update = await client.query(
      `UPDATE finance_transactions
          SET account_id = $3, status = $4, direction = $5, amount_cents = $6,
              transaction_date = $7, authorized_date = $8, merchant_name = $9,
              original_name = $10, category_primary = $11, category_detailed = $12,
              normalized_category = COALESCE(user_category_override, $13),
              payment_channel = $14, pending = $15, merchant_entity_id = $16,
              website = $17, location_city = $18, location_region = $19,
              location_postal_code = $20, location_country = $21, iso_currency_code = $22,
              provider_metadata = $23, removed_at = NULL, updated_at = now()
        WHERE id = $1 AND company_id = $2
        RETURNING *`,
      [
        transactionId,
        companyId,
        payload.account_id,
        payload.status,
        payload.direction,
        payload.amount_cents,
        payload.transaction_date,
        payload.authorized_date,
        payload.merchant_name,
        payload.original_name,
        payload.category_primary,
        payload.category_detailed,
        payload.normalized_category,
        payload.payment_channel,
        payload.pending,
        payload.merchant_entity_id,
        payload.website,
        payload.location_city,
        payload.location_region,
        payload.location_postal_code,
        payload.location_country,
        payload.iso_currency_code,
        JSON.stringify(payload.provider_metadata)
      ]
    );
    row = update.rows[0];
  } else {
    const insert = await client.query(
      `INSERT INTO finance_transactions (
         company_id, account_id, source, status, direction, amount_cents,
         transaction_date, authorized_date, merchant_name, original_name,
         category_primary, category_detailed, normalized_category, payment_channel,
         pending, merchant_entity_id, website, location_city, location_region,
         location_postal_code, location_country, iso_currency_code, provider_metadata
       ) VALUES ($1,$2,'plaid',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
       RETURNING *`,
      [
        companyId,
        payload.account_id,
        payload.status,
        payload.direction,
        payload.amount_cents,
        payload.transaction_date,
        payload.authorized_date,
        payload.merchant_name,
        payload.original_name,
        payload.category_primary,
        payload.category_detailed,
        payload.normalized_category,
        payload.payment_channel,
        payload.pending,
        payload.merchant_entity_id,
        payload.website,
        payload.location_city,
        payload.location_region,
        payload.location_postal_code,
        payload.location_country,
        payload.iso_currency_code,
        JSON.stringify(payload.provider_metadata)
      ]
    );
    row = insert.rows[0];
  }

  if (tx.pending_transaction_id && pendingRef.rows[0]) {
    await client.query(`UPDATE finance_transaction_provider_refs SET is_current = false WHERE id = $1`, [pendingRef.rows[0].id]);
  }
  await client.query(
    `INSERT INTO finance_transaction_provider_refs (
       company_id, transaction_id, plaid_item_internal_id, provider, provider_transaction_id, is_current
     ) VALUES ($1,$2,$3,'plaid',$4,true)
     ON CONFLICT (provider, provider_transaction_id)
     DO UPDATE SET transaction_id = EXCLUDED.transaction_id, is_current = true`,
    [companyId, row.id, plaidItem.id, providerId]
  );
  return row;
}

async function markRemovedTransaction(client, companyId, providerTransactionId) {
  const ref = await client.query(
    `SELECT * FROM finance_transaction_provider_refs WHERE provider = 'plaid' AND provider_transaction_id = $1 LIMIT 1`,
    [providerTransactionId]
  );
  if (!ref.rows.length) return;
  await client.query(
    `UPDATE finance_transactions
        SET removed_at = COALESCE(removed_at, now()),
            updated_at = now()
      WHERE id = $1 AND company_id = $2`,
    [ref.rows[0].transaction_id, companyId]
  );
  await client.query(`UPDATE finance_transaction_provider_refs SET is_current = false WHERE id = $1`, [ref.rows[0].id]);
}

export async function syncPlaidTransactions({ pool, plaid, item }) {
  if (item.status === "disconnected" || item.disconnected_at) {
    return { skipped: true, reason: "disconnected", added: 0, modified: 0, removed: 0, next_cursor: item.transactions_cursor || null };
  }
  const plaidForItem = plaid || await plaidClientForItem(item);
  const accessToken = await decryptItemToken(item);
  const originalCursor = item.transactions_cursor || null;
  const collected = await collectPlaidSyncPages(async (cursor) => {
    try {
      const response = await plaidForItem.transactionsSync({ access_token: accessToken, cursor, count: 500 });
      return response.data;
    } catch (error) {
      const code = error?.response?.data?.error_code;
      if (code === "TRANSACTIONS_SYNC_MUTATION_DURING_PAGINATION") {
        const normalized = new Error(code);
        normalized.code = code;
        throw normalized;
      }
      throw error;
    }
  }, originalCursor);

  const client = await pool.connect();
  const changedTransactions = [];
  try {
    await client.query("BEGIN");
    await client.query(`UPDATE finance_plaid_items SET last_attempted_sync_at = now(), status = 'syncing', updated_at = now() WHERE id = $1`, [item.id]);
    for (const tx of collected.added) {
      const row = await applyPlaidTransaction(client, item.company_id, item, tx);
      if (row) changedTransactions.push(row);
    }
    for (const tx of collected.modified) {
      const row = await applyPlaidTransaction(client, item.company_id, item, tx);
      if (row) changedTransactions.push(row);
    }
    for (const removed of collected.removed) await markRemovedTransaction(client, item.company_id, removed.transaction_id);
    await client.query(
      `UPDATE finance_plaid_items
          SET transactions_cursor = $2,
              last_successful_sync_at = now(),
              last_attempted_sync_at = now(),
              status = 'active',
              error_code = NULL,
              error_message = NULL,
              updated_at = now()
        WHERE id = $1`,
      [item.id, collected.next_cursor]
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
  if (changedTransactions.length) {
    await matchUnmatchedReceiptsForTransactions(pool, item.company_id, changedTransactions)
      .catch((error) => console.error("[finance-receipts] rematch after plaid sync failed", { company_id: item.company_id, message: error?.message }));
  }
  return { added: collected.added.length, modified: collected.modified.length, removed: collected.removed.length, next_cursor: collected.next_cursor };
}

async function refreshBalances(pool, plaid, item) {
  if (item.status === "disconnected" || item.disconnected_at) {
    return [];
  }
  const plaidForItem = plaid || await plaidClientForItem(item);
  const accessToken = await decryptItemToken(item);
  const response = await plaidForItem.accountsBalanceGet({ access_token: accessToken });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const accounts = await upsertAccounts(client, item.company_id, item, response.data.accounts || []);
    await client.query(`UPDATE finance_plaid_items SET last_balance_refresh_at = now(), status = 'active', updated_at = now() WHERE id = $1`, [item.id]);
    await client.query("COMMIT");
    return accounts.map(plaidAccountPayload);
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function syncRecurring(pool, plaid, item) {
  if (item.status === "disconnected" || item.disconnected_at) {
    return 0;
  }
  const plaidForItem = plaid || await plaidClientForItem(item);
  const accessToken = await decryptItemToken(item);
  const response = await plaidForItem.transactionsRecurringGet({ access_token: accessToken });
  const streams = [
    ...(response.data.inflow_streams || []).map((stream) => ({ ...stream, wolf_direction: "income" })),
    ...(response.data.outflow_streams || []).map((stream) => ({ ...stream, wolf_direction: "expense" }))
  ];
  for (const stream of streams) {
    const amount = stream.last_amount === null || stream.last_amount === undefined ? null : providerAmountToCents(Math.abs(stream.last_amount.amount || stream.last_amount));
    const average = stream.average_amount === null || stream.average_amount === undefined ? null : providerAmountToCents(Math.abs(stream.average_amount.amount || stream.average_amount));
    await pool.query(
      `INSERT INTO finance_plaid_recurring_streams (
         company_id, plaid_item_internal_id, plaid_stream_id, direction, merchant_name,
         description, category, frequency, last_amount_cents, average_amount_cents,
         first_date, last_date, is_active, status, confidence_level
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
       ON CONFLICT (plaid_item_internal_id, plaid_stream_id)
       DO UPDATE SET merchant_name = EXCLUDED.merchant_name,
                     description = EXCLUDED.description,
                     category = EXCLUDED.category,
                     frequency = EXCLUDED.frequency,
                     last_amount_cents = EXCLUDED.last_amount_cents,
                     average_amount_cents = EXCLUDED.average_amount_cents,
                     first_date = EXCLUDED.first_date,
                     last_date = EXCLUDED.last_date,
                     is_active = EXCLUDED.is_active,
                     status = EXCLUDED.status,
                     confidence_level = EXCLUDED.confidence_level,
                     updated_at = now()`,
      [
        item.company_id,
        item.id,
        stream.stream_id,
        stream.wolf_direction,
        stream.merchant_name || null,
        stream.description || stream.name || null,
        stream.personal_finance_category?.primary || null,
        stream.frequency || null,
        amount,
        average,
        stream.first_date || null,
        stream.last_date || null,
        stream.is_active !== false,
        stream.status || null,
        stream.confidence_level || null
      ]
    );
  }
  return streams.length;
}

export function installPlaidRoutes({ app, pool, authRequired, requireEmployer }) {
  app.get("/api/finance/plaid/status", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    const status = getPlaidConfig();
    res.json({
      configured: status.configured && status.encryption_configured,
      plaid_configured: status.configured,
      encryption_configured: status.encryption_configured,
      environment: status.environment,
      webhook_configured: Boolean(status.webhook_url),
      redirect_configured: Boolean(status.redirect_uri)
    });
  });

  app.post("/api/finance/plaid/link-token", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    const config = requirePlaidConfigured(res);
    if (!config) return;
    try {
      const request = {
        user: { client_user_id: `company_${req.companyId}_user_${req.userId}` },
        client_name: "WolfCRM",
        products: ["transactions"],
        country_codes: ["US"],
        language: "en",
        transactions: { days_requested: 180 },
        webhook: config.webhook_url || undefined,
        redirect_uri: config.redirect_uri || undefined
      };
      const response = await (await plaidClient()).linkTokenCreate(request);
      res.json({ link_token: response.data.link_token, expiration: response.data.expiration });
    } catch (error) {
      handlePlaidError(res, error, "plaid_link_token_failed");
    }
  });

  app.post("/api/finance/plaid/exchange", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    const config = requirePlaidConfigured(res);
    if (!config) return;
    const publicToken = cleanString(req.body?.public_token, 2048);
    if (!publicToken) return res.status(400).json({ error: "plaid_public_token_required", message: "Plaid public token is required." });
    const plaid = await plaidClient();
    try {
      const exchange = await plaid.itemPublicTokenExchange({ public_token: publicToken });
      const accessToken = exchange.data.access_token;
      const plaidItemId = exchange.data.item_id;
      const encrypted = encryptAccessToken(accessToken);
      const accountsResponse = await plaid.accountsBalanceGet({ access_token: accessToken });
      const itemData = accountsResponse.data.item || {};
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const itemInsert = await client.query(
          `INSERT INTO finance_plaid_items (
             company_id, plaid_item_id, institution_id, institution_name,
             access_token_ciphertext, access_token_iv, access_token_auth_tag,
             token_encryption_version, environment, status, created_by
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',$10)
           ON CONFLICT (environment, plaid_item_id)
           DO UPDATE SET institution_id = EXCLUDED.institution_id,
                         institution_name = EXCLUDED.institution_name,
                         access_token_ciphertext = EXCLUDED.access_token_ciphertext,
                         access_token_iv = EXCLUDED.access_token_iv,
                         access_token_auth_tag = EXCLUDED.access_token_auth_tag,
                         token_encryption_version = EXCLUDED.token_encryption_version,
                         status = 'active',
                         disconnected_at = NULL,
                         updated_at = now()
           RETURNING *`,
          [
            req.companyId,
            plaidItemId,
            itemData.institution_id || req.body?.institution_id || null,
            req.body?.institution_name || null,
            encrypted.access_token_ciphertext,
            encrypted.access_token_iv,
            encrypted.access_token_auth_tag,
            encrypted.token_encryption_version,
            config.environment,
            req.userId
          ]
        );
        const item = itemInsert.rows[0];
        const accounts = await upsertAccounts(client, req.companyId, item, accountsResponse.data.accounts || []);
        await client.query(`UPDATE finance_plaid_items SET last_balance_refresh_at = now(), updated_at = now() WHERE id = $1`, [item.id]);
        await client.query("COMMIT");
        const syncResult = await syncPlaidTransactions({ pool, plaid, item: { ...item, company_id: req.companyId } }).catch((error) => ({ error: safePlaidMessage(error?.response?.data || {}) }));
        res.status(201).json({
          item: safePlaidItemPayload(item),
          accounts: accounts.map(plaidAccountPayload),
          transaction_sync: syncResult
        });
      } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        throw error;
      } finally {
        client.release();
      }
    } catch (error) {
      handlePlaidError(res, error, "plaid_exchange_failed");
    }
  });

  app.get("/api/finance/plaid/items", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const { rows } = await pool.query(
        `SELECT * FROM finance_plaid_items WHERE company_id = $1 ORDER BY disconnected_at NULLS FIRST, created_at DESC`,
        [req.companyId]
      );
      res.json(rows.map(safePlaidItemPayload));
    } catch (error) {
      handlePlaidError(res, error, "plaid_items_failed");
    }
  });

  app.post("/api/finance/plaid/items/:id/refresh-balances", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const item = await getPlaidItem(pool, req.companyId, req.params.id);
      if (!item) return res.status(404).json({ error: "plaid_item_not_found", message: "Bank connection was not found." });
      if (!requirePlaidEnvironmentConfigured(res, item.environment)) return;
      res.json({ accounts: await refreshBalances(pool, await plaidClientForItem(item), item) });
    } catch (error) {
      handlePlaidError(res, error, "plaid_balance_refresh_failed");
    }
  });

  app.post("/api/finance/plaid/items/:id/refresh-transactions", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const item = await getPlaidItem(pool, req.companyId, req.params.id);
      if (!item) return res.status(404).json({ error: "plaid_item_not_found", message: "Bank connection was not found." });
      if (!requirePlaidEnvironmentConfigured(res, item.environment)) return;
      const plaid = await plaidClientForItem(item);
      await plaid.transactionsRefresh({ access_token: await decryptItemToken(item) });
      await pool.query(`UPDATE finance_plaid_items SET last_transaction_refresh_at = now(), updated_at = now() WHERE id = $1`, [item.id]);
      const sync = await syncPlaidTransactions({ pool, plaid, item });
      res.json({ requested: true, sync });
    } catch (error) {
      handlePlaidError(res, error, "plaid_transaction_refresh_failed");
    }
  });

  app.post("/api/finance/plaid/refresh-all", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const { rows } = await pool.query(`SELECT * FROM finance_plaid_items WHERE company_id = $1 AND status <> 'disconnected' AND disconnected_at IS NULL`, [req.companyId]);
      const results = [];
      for (const item of rows) {
        try {
          const plaid = await plaidClientForItem(item);
          const accounts = await refreshBalances(pool, plaid, item);
          await plaid.transactionsRefresh({ access_token: await decryptItemToken(item) }).catch(() => null);
          const sync = await syncPlaidTransactions({ pool, plaid, item });
          results.push({ item_id: item.id, environment: item.environment || null, account_count: accounts.length, sync });
        } catch (error) {
          safePlaidFailureLog("refresh_all_item_failed", error, {
            plaid_item_internal_id: item.id,
            item_environment: item.environment || null
          });
          results.push({
            item_id: item.id,
            environment: item.environment || null,
            error: error?.code === "finance_plaid_environment_unavailable" ? "finance_plaid_environment_unavailable" : "plaid_provider_error"
          });
        }
      }
      res.json({ items: results });
    } catch (error) {
      handlePlaidError(res, error, "plaid_refresh_all_failed");
    }
  });

  app.post("/api/finance/plaid/items/:id/update-link-token", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const item = await getPlaidItem(pool, req.companyId, req.params.id);
      if (!item) return res.status(404).json({ error: "plaid_item_not_found", message: "Bank connection was not found." });
      if (!requirePlaidEnvironmentConfigured(res, item.environment)) return;
      const activeConfig = getPlaidConfig();
      const response = await (await plaidClientForItem(item)).linkTokenCreate({
        user: { client_user_id: `company_${req.companyId}_user_${req.userId}` },
        client_name: "WolfCRM",
        country_codes: ["US"],
        language: "en",
        access_token: await decryptItemToken(item),
        webhook: activeConfig.webhook_url || undefined,
        redirect_uri: activeConfig.redirect_uri || undefined
      });
      res.json({ link_token: response.data.link_token, expiration: response.data.expiration });
    } catch (error) {
      handlePlaidError(res, error, "plaid_update_link_token_failed");
    }
  });

  app.post("/api/finance/plaid/items/:id/disconnect", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    let disconnectItemEnvironment = null;
    try {
      const item = await getPlaidItemIncludingDisconnected(pool, req.companyId, req.params.id);
      if (!item) return res.status(404).json({ error: "plaid_item_not_found", message: "Bank connection was not found." });
      disconnectItemEnvironment = item.environment || null;
      let providerCleanup = item.status === "disconnected" || item.disconnected_at
        ? { attempted: false, status: "already_disconnected" }
        : { attempted: false, status: "skipped" };
      if (item.status !== "disconnected" && !item.disconnected_at) {
        providerCleanup = { attempted: true, status: "pending" };
        try {
          const environmentConfig = getPlaidEnvironmentConfig(item.environment);
          const activeConfig = getPlaidConfig();
          if (!environmentConfig.configured || !activeConfig.encryption_configured) {
            throw plaidEnvironmentUnavailableError(item.environment);
          }
          await (await plaidClientForItem(item)).itemRemove({ access_token: await decryptItemToken(item) });
          providerCleanup = { attempted: true, status: "succeeded" };
        } catch (error) {
          const code = error?.response?.data?.error_code || error?.code || "provider_cleanup_failed";
          if (!isSafeLocalDisconnectProviderFailure(error)) throw error;
          providerCleanup = {
            attempted: true,
            status: code === "ITEM_NOT_FOUND" ? "already_removed" : "failed",
            code
          };
          safePlaidFailureLog("disconnect_provider_cleanup_failed", error, {
            plaid_item_internal_id: item.id,
            item_environment: item.environment || null
          });
        }
      }
      const updated = item.status === "disconnected" || item.disconnected_at
        ? item
        : await markPlaidItemDisconnected(pool, req.companyId, item, req.userId, "user_disconnect", providerCleanup);
      if (item.status === "disconnected" || item.disconnected_at) {
        await pool.query(
          `UPDATE finance_accounts SET include_in_liquid_cash = false, updated_at = now() WHERE plaid_item_internal_id = $1 AND company_id = $2 AND source = 'plaid'`,
          [item.id, req.companyId]
        );
        await pool.query(
          `UPDATE finance_plaid_recurring_streams SET is_active = false, status = COALESCE(status, 'disconnected'), updated_at = now() WHERE plaid_item_internal_id = $1 AND company_id = $2`,
          [item.id, req.companyId]
        );
      }
      const accounts = item.status === "disconnected" || item.disconnected_at
        ? await accountsForPlaidItem(pool, req.companyId, item.id)
        : await accountsForPlaidItem(pool, req.companyId, updated.id);
      res.json({
        disconnected: true,
        already_disconnected: Boolean(item.status === "disconnected" || item.disconnected_at),
        item: safePlaidItemPayload(updated),
        accounts,
        message: "Bank disconnected."
      });
    } catch (error) {
      safePlaidFailureLog("disconnect_failed", error, {
        plaid_item_internal_id: req.params.id,
        item_environment: disconnectItemEnvironment || error?.environment || null
      });
      handlePlaidError(res, error, "plaid_disconnect_failed");
    }
  });

  app.get("/api/finance/transactions", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const limit = Math.min(Math.max(Number(req.query.limit || 50), 1), 100);
      const offset = Math.max(Number(req.query.offset || 0), 0);
      const filter = cleanString(req.query.filter, 20);
      const conditions = ["t.company_id = $1", "t.removed_at IS NULL"];
      const values = [req.companyId];
      if (filter === "income" || filter === "expense") {
        values.push(filter);
        conditions.push(`t.direction = $${values.length}`);
      } else if (filter === "pending") {
        conditions.push("t.pending = true");
      } else if (filter === "missing_receipt") {
        conditions.push("t.direction = 'expense'");
        conditions.push("t.pending = false");
        conditions.push("NOT EXISTS (SELECT 1 FROM finance_receipts r WHERE r.company_id = t.company_id AND r.transaction_id = t.id AND r.archived_at IS NULL)");
      }
      values.push(limit, offset);
      const { rows } = await pool.query(
        `SELECT t.*, a.name AS account_name, a.institution_name,
                (SELECT COUNT(*)::int FROM finance_receipts r WHERE r.company_id = t.company_id AND r.transaction_id = t.id AND r.archived_at IS NULL) AS receipt_count
           FROM finance_transactions t
           JOIN finance_accounts a ON a.id = t.account_id AND a.company_id = t.company_id
          WHERE ${conditions.join(" AND ")}
          ORDER BY t.transaction_date DESC, t.created_at DESC
          LIMIT $${values.length - 1} OFFSET $${values.length}`,
        values
      );
      res.json({ transactions: rows.map(transactionPayload), limit, offset, has_more: rows.length === limit });
    } catch (error) {
      handlePlaidError(res, error, "finance_transactions_failed");
    }
  });

  app.get("/api/finance/transactions/:id", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const { rows } = await pool.query(
        `SELECT t.*, a.name AS account_name, a.institution_name,
                (SELECT COUNT(*)::int FROM finance_receipts r WHERE r.company_id = t.company_id AND r.transaction_id = t.id AND r.archived_at IS NULL) AS receipt_count
           FROM finance_transactions t
           JOIN finance_accounts a ON a.id = t.account_id AND a.company_id = t.company_id
          WHERE t.id = $1 AND t.company_id = $2`,
        [req.params.id, req.companyId]
      );
      if (!rows.length) return res.status(404).json({ error: "finance_transaction_not_found", message: "Transaction was not found." });
      res.json(transactionPayload(rows[0]));
    } catch (error) {
      handlePlaidError(res, error, "finance_transaction_failed");
    }
  });

  app.get("/api/finance/recurring-streams", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const { rows } = await pool.query(
        `SELECT * FROM finance_plaid_recurring_streams WHERE company_id = $1 ORDER BY is_active DESC, last_date DESC NULLS LAST`,
        [req.companyId]
      );
      res.json(rows.map((row) => ({
        id: row.id,
        merchant_name: row.merchant_name,
        description: row.description,
        direction: row.direction,
        category: row.category,
        frequency: row.frequency,
        last_amount_cents: row.last_amount_cents === null ? null : Number(row.last_amount_cents),
        average_amount_cents: row.average_amount_cents === null ? null : Number(row.average_amount_cents),
        first_date: row.first_date,
        last_date: row.last_date,
        is_active: row.is_active,
        status: row.status
      })));
    } catch (error) {
      handlePlaidError(res, error, "finance_recurring_streams_failed");
    }
  });

  app.get("/api/finance/recurring-candidates", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const candidates = await loadRecurringCandidates(pool, req.companyId, req.query.include_ignored === "true");
      res.json({ candidates, summary: recurringCandidateSummary(candidates) });
    } catch (error) {
      handlePlaidError(res, error, "finance_recurring_candidates_failed");
    }
  });

  app.post("/api/finance/recurring-candidates/analyze", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    const client = await pool.connect();
    try {
      const lookbackMonths = Math.min(12, Math.max(3, Number(req.body?.lookback_months || 6)));
      const { rows: txRows } = await pool.query(
        `SELECT t.*, a.name AS account_name
           FROM finance_transactions t
           JOIN finance_accounts a ON a.id = t.account_id AND a.company_id = t.company_id
          WHERE t.company_id = $1
            AND t.status = 'posted'
            AND t.pending = false
            AND t.removed_at IS NULL
            AND t.transaction_date >= (CURRENT_DATE - ($2::int || ' months')::interval)
          ORDER BY t.transaction_date ASC`,
        [req.companyId, lookbackMonths]
      );
      const detected = analyzeRecurringTransactionPatterns(txRows, { minimumConfidence: 35 });
      const updatedRows = [];

      await client.query("BEGIN");
      for (const candidate of detected) {
        const upsert = await client.query(
          `INSERT INTO finance_recurring_candidates (
             company_id, merchant_normalized, display_name, direction, candidate_type, cadence,
             average_amount_cents, median_amount_cents, min_amount_cents, max_amount_cents,
             variability, variability_score_cents, first_seen_date, last_seen_date, next_expected_date,
             occurrence_count, confidence_score, confidence_label, source, status, category, account_id
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,'detected',$20,$21)
           ON CONFLICT (company_id, merchant_normalized, direction, cadence)
           DO UPDATE SET
             display_name = EXCLUDED.display_name,
             candidate_type = EXCLUDED.candidate_type,
             average_amount_cents = EXCLUDED.average_amount_cents,
             median_amount_cents = EXCLUDED.median_amount_cents,
             min_amount_cents = EXCLUDED.min_amount_cents,
             max_amount_cents = EXCLUDED.max_amount_cents,
             variability = EXCLUDED.variability,
             variability_score_cents = EXCLUDED.variability_score_cents,
             first_seen_date = EXCLUDED.first_seen_date,
             last_seen_date = EXCLUDED.last_seen_date,
             next_expected_date = EXCLUDED.next_expected_date,
             occurrence_count = EXCLUDED.occurrence_count,
             confidence_score = EXCLUDED.confidence_score,
             confidence_label = EXCLUDED.confidence_label,
             source = CASE WHEN finance_recurring_candidates.source = 'plaid_detected' THEN 'both' ELSE finance_recurring_candidates.source END,
             category = EXCLUDED.category,
             account_id = EXCLUDED.account_id,
             status = CASE
               WHEN finance_recurring_candidates.status IN ('confirmed','ignored') THEN finance_recurring_candidates.status
               ELSE 'detected'
             END,
             updated_at = now()
           RETURNING *`,
          [
            req.companyId,
            candidate.merchant_normalized,
            candidate.display_name,
            candidate.direction,
            candidate.candidate_type,
            candidate.cadence,
            candidate.average_amount_cents,
            candidate.median_amount_cents,
            candidate.min_amount_cents,
            candidate.max_amount_cents,
            candidate.variability,
            candidate.variability_score_cents,
            candidate.first_seen_date,
            candidate.last_seen_date,
            candidate.next_expected_date,
            candidate.occurrence_count,
            candidate.confidence_score,
            candidate.confidence_label,
            candidate.source,
            candidate.category,
            candidate.account_id
          ]
        );
        const saved = upsert.rows[0];
        updatedRows.push(saved);
        await client.query(`DELETE FROM finance_recurring_candidate_transactions WHERE candidate_id = $1 AND company_id = $2`, [saved.id, req.companyId]);
        for (const transactionId of candidate.source_transaction_ids || []) {
          await client.query(
            `INSERT INTO finance_recurring_candidate_transactions(candidate_id, transaction_id, company_id)
             VALUES($1,$2,$3)
             ON CONFLICT DO NOTHING`,
            [saved.id, transactionId, req.companyId]
          );
        }
      }
      await client.query("COMMIT");

      const candidates = await loadRecurringCandidates(pool, req.companyId, false);
      res.json({
        analyzed_transaction_count: txRows.length,
        created_or_updated_count: updatedRows.length,
        candidates,
        summary: recurringCandidateSummary(candidates)
      });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      handlePlaidError(res, error, "finance_recurring_analysis_failed");
    } finally {
      client.release();
    }
  });

  app.post("/api/finance/recurring-candidates/:id/ignore", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    try {
      const { rows } = await pool.query(
        `UPDATE finance_recurring_candidates
            SET status = 'ignored',
                ignored_at = COALESCE(ignored_at, now()),
                updated_at = now()
          WHERE id = $1 AND company_id = $2
          RETURNING *`,
        [req.params.id, req.companyId]
      );
      if (!rows.length) return res.status(404).json({ error: "recurring_candidate_not_found", message: "Recurring item was not found." });
      res.json(recurringCandidatePayload(rows[0]));
    } catch (error) {
      handlePlaidError(res, error, "finance_recurring_ignore_failed");
    }
  });

  app.post("/api/finance/recurring-candidates/:id/confirm", authRequired, requireEmployer, async (req, res) => {
    if (!requireCompany(req, res)) return;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const existing = await client.query(
        `SELECT c.*, a.name AS account_name
           FROM finance_recurring_candidates c
           LEFT JOIN finance_accounts a ON a.id = c.account_id AND a.company_id = c.company_id
          WHERE c.id = $1 AND c.company_id = $2
          FOR UPDATE`,
        [req.params.id, req.companyId]
      );
      const candidate = existing.rows[0];
      if (!candidate) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "recurring_candidate_not_found", message: "Recurring item was not found." });
      }
      if (candidate.status === "confirmed" && candidate.linked_planned_item_id) {
        await client.query("COMMIT");
        return res.json({ candidate: recurringCandidatePayload(candidate), planned_item_id: candidate.linked_planned_item_id, linked_existing: true });
      }
      if (candidate.candidate_type === "repeated_merchant" || candidate.cadence === "irregular") {
        await client.query("ROLLBACK");
        return res.status(400).json({ error: "recurring_candidate_not_confirmable", message: "This looks like a repeated merchant, not a recurring bill or income source." });
      }

      let plannedItem = await findMatchingPlannedItem(client, req.companyId, candidate);
      let linkedExisting = Boolean(plannedItem);
      if (!plannedItem) {
        const notes = [
          "Created from WolfCRM recurring analysis.",
          candidate.variability === "variable" ? "Amount is based on the median observed transaction amount." : null
        ].filter(Boolean).join(" ");
        const inserted = await client.query(
          `INSERT INTO finance_planned_items (
             company_id, account_id, title, direction, amount_cents, scheduled_date,
             category, recurrence, recurrence_end_date, notes, created_by
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULL,$9,$10)
           RETURNING *`,
          [
            req.companyId,
            candidate.account_id || null,
            candidate.display_name,
            candidate.direction,
            Number(candidate.median_amount_cents || 0),
            dateOnlyPayload(candidate.next_expected_date) || dateOnlyPayload(candidate.last_seen_date),
            candidate.category || (candidate.direction === "income" ? "Other Income" : "Other"),
            candidate.cadence,
            notes,
            req.userId
          ]
        );
        plannedItem = inserted.rows[0];
        linkedExisting = false;
      }

      const updated = await client.query(
        `UPDATE finance_recurring_candidates
            SET status = 'confirmed',
                confirmed_at = COALESCE(confirmed_at, now()),
                linked_planned_item_id = $3,
                updated_at = now()
          WHERE id = $1 AND company_id = $2
          RETURNING *`,
        [candidate.id, req.companyId, plannedItem.id]
      );
      await client.query("COMMIT");
      res.json({
        candidate: recurringCandidatePayload(updated.rows[0]),
        planned_item_id: plannedItem.id,
        linked_existing: linkedExisting
      });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      handlePlaidError(res, error, "finance_recurring_confirm_failed");
    } finally {
      client.release();
    }
  });

  app.post("/api/finance/plaid/webhook", async (req, res) => {
    const itemId = cleanString(req.body?.item_id, 200);
    const webhookCode = cleanString(req.body?.webhook_code, 80);
    if (!itemId) return res.json({ ok: true });
    try {
      const { rows } = await pool.query(`SELECT * FROM finance_plaid_items WHERE plaid_item_id = $1 AND disconnected_at IS NULL LIMIT 1`, [itemId]);
      if (!rows.length) return res.json({ ok: true });
      const item = rows[0];
      await pool.query(`UPDATE finance_plaid_items SET last_webhook_at = now(), updated_at = now() WHERE id = $1`, [item.id]);
      res.json({ ok: true });
      if (webhookCode === "SYNC_UPDATES_AVAILABLE") {
        await syncPlaidTransactions({ pool, plaid: await plaidClientForItem(item), item }).catch((error) => console.error("[finance-plaid] webhook sync failed", { item_id: item.id, environment: item.environment || null, message: error?.message }));
      } else if (webhookCode === "RECURRING_TRANSACTIONS_UPDATE") {
        await syncRecurring(pool, await plaidClientForItem(item), item).catch((error) => console.error("[finance-plaid] recurring sync failed", { item_id: item.id, environment: item.environment || null, message: error?.message }));
      } else if (webhookCode === "ITEM_LOGIN_REQUIRED" || req.body?.error?.error_code === "ITEM_LOGIN_REQUIRED") {
        await pool.query(`UPDATE finance_plaid_items SET status = 'login_required', error_code = 'ITEM_LOGIN_REQUIRED', updated_at = now() WHERE id = $1`, [item.id]);
      }
    } catch (error) {
      console.error("[finance-plaid] webhook failed", { message: error?.message, webhook_code: webhookCode });
      if (!res.headersSent) res.json({ ok: true });
    }
  });
}
