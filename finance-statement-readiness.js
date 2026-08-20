import { createHash } from "node:crypto";
import { syncOperationalAccountingSources } from "./finance-operational-accounting.js";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const OPENING_METHODS = new Set(["company_inception_zero", "reviewed_journal"]);
const MAX_OPENING_CANDIDATES = 100;
const MAX_AUDIT_ROWS = 50;

export class FinanceStatementReadinessError extends Error {
  constructor(code, message, statusCode = 400, details = {}) {
    super(message);
    this.name = "FinanceStatementReadinessError";
    this.code = code;
    this.statusCode = statusCode;
    Object.assign(this, details);
  }
}

function cleanString(value, maxLength = 200) {
  return (value ?? "").toString().trim().slice(0, maxLength);
}

function exactInteger(value, field, minimum = 0) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value.trim()) ? Number(value.trim()) : value;
  if (!Number.isSafeInteger(parsed) || parsed < minimum) {
    throw new FinanceStatementReadinessError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return parsed;
}

function dateOnly(value, field = "date") {
  const raw = value instanceof Date ? value.toISOString().slice(0, 10) : cleanString(value, 20);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    throw new FinanceStatementReadinessError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  const [year, month, day] = raw.split("-").map(Number);
  const parsed = new Date(Date.UTC(year, month - 1, day));
  if (parsed.getUTCFullYear() !== year || parsed.getUTCMonth() !== month - 1 || parsed.getUTCDate() !== day) {
    throw new FinanceStatementReadinessError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return raw;
}

function uuid(value, field) {
  const raw = cleanString(value, 64).toLowerCase();
  if (!UUID_PATTERN.test(raw)) {
    throw new FinanceStatementReadinessError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return raw;
}

function optionalUUID(value, field) {
  if (value === null || value === undefined || value === "") return null;
  return uuid(value, field);
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
  }
  return value;
}

export function statementReadinessFingerprint(value) {
  return createHash("sha256").update(JSON.stringify(stableValue(value))).digest("hex");
}

function blocker(code, message, area) {
  return { code, message, area, severity: "blocking" };
}

function uniqueBlockers(items) {
  return [...new Map(items.map((item) => [item.code, item])).values()];
}

function dateValue(value) {
  if (value === null || value === undefined) return null;
  return value instanceof Date ? value.toISOString().slice(0, 10) : String(value).slice(0, 10);
}

function timestampValue(value) {
  return value || null;
}

export function normalizeStatementCoverageProfileRequest({ body = {}, companyToday }) {
  const today = dateOnly(companyToday, "company_today");
  const coverageStartDate = dateOnly(body.coverage_start_date, "coverage_start_date");
  if (coverageStartDate > today) {
    throw new FinanceStatementReadinessError("coverage_start_future", "Coverage cannot start after the company's current local day.");
  }
  const openingMethod = cleanString(body.opening_balance_method, 40).toLowerCase();
  if (!OPENING_METHODS.has(openingMethod)) {
    throw new FinanceStatementReadinessError("opening_balance_method_invalid", "Choose a supported opening-balance method.");
  }
  const openingJournalEntryID = optionalUUID(body.opening_journal_entry_id, "opening_journal_entry_id");
  if (openingMethod === "reviewed_journal" && !openingJournalEntryID) {
    throw new FinanceStatementReadinessError("opening_journal_required", "Choose the exact reviewed Opening Balance journal.");
  }
  if (openingMethod === "company_inception_zero" && openingJournalEntryID) {
    throw new FinanceStatementReadinessError("opening_journal_not_allowed", "A zero company-inception opening cannot also select a journal.");
  }
  const reason = (body.reason ?? "").toString().trim();
  if (!reason) throw new FinanceStatementReadinessError("statement_coverage_reason_required", "An audit reason is required.");
  if (reason.length > 500) throw new FinanceStatementReadinessError("statement_coverage_reason_too_long", "Audit reason must be 500 characters or fewer.");
  const input = {
    client_request_id: uuid(body.client_request_id, "client_request_id"),
    expected_version: exactInteger(body.expected_version ?? 0, "expected_version"),
    coverage_start_date: coverageStartDate,
    opening_balance_method: openingMethod,
    opening_journal_entry_id: openingJournalEntryID,
    reason
  };
  return { ...input, request_fingerprint: statementReadinessFingerprint(input) };
}

function storedCount(value, field) {
  const parsed = typeof value === "string" && /^\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new FinanceStatementReadinessError("statement_inventory_inexact", `${field.replaceAll("_", " ")} is invalid.`, 409);
  }
  return parsed;
}

export function normalizeStatementCoverageArea({ key, label, row = {}, blockerCode, blockerMessage, warnings = [] }) {
  const totalCount = storedCount(row.total_count ?? 0, `${key}_total_count`);
  const coveredCount = storedCount(row.covered_count ?? 0, `${key}_covered_count`);
  const blockingCount = storedCount(row.blocking_count ?? Math.max(0, totalCount - coveredCount), `${key}_blocking_count`);
  if (coveredCount > totalCount || coveredCount + blockingCount !== totalCount) {
    throw new FinanceStatementReadinessError("statement_inventory_inexact", `${label} coverage does not exactly partition its source count.`, 409);
  }
  const metrics = {};
  for (const [metricKey, rawValue] of Object.entries(row)) {
    if (!metricKey.endsWith("_count") || ["total_count", "covered_count", "blocking_count"].includes(metricKey)) continue;
    metrics[metricKey] = storedCount(rawValue ?? 0, `${key}_${metricKey}`);
  }
  return {
    key,
    label,
    status: blockingCount > 0 ? "blocked" : "covered",
    total_count: totalCount,
    covered_count: coveredCount,
    blocking_count: blockingCount,
    metrics,
    evidence_hash: cleanString(row.evidence_hash, 64) || statementReadinessFingerprint({ key, totalCount, coveredCount, blockingCount, metrics }),
    blockers: blockingCount > 0 ? [blocker(blockerCode, blockerMessage, key)] : [],
    warnings
  };
}

export function evaluateOpeningCoverage({ profile = null, permanentAccounts = [], earliestSourceDate = null, journal = null }) {
  if (!profile) {
    return {
      status: "unconfigured",
      source_current: false,
      live_fingerprint: null,
      blockers: [blocker("statement_coverage_profile_missing", "Review a coverage start and exact opening-balance method before evaluating formal statements.", "opening_balance")],
      snapshot: null
    };
  }
  const coverageStartDate = dateOnly(profile.coverage_start_date, "coverage_start_date");
  const method = cleanString(profile.opening_balance_method, 40);
  const blockers = [];
  if (permanentAccounts.length > 200) {
    blockers.push(blocker("opening_chart_too_large", "The active permanent chart exceeds the supported review bound.", "opening_balance"));
  }
  let journalSnapshot = null;
  if (method === "company_inception_zero") {
    if (earliestSourceDate && dateOnly(earliestSourceDate, "earliest_source_date") < coverageStartDate) {
      blockers.push(blocker("opening_zero_has_prior_activity", "Retained accounting activity exists before this proposed zero-opening start date.", "opening_balance"));
    }
  } else if (method === "reviewed_journal") {
    if (!journal) {
      blockers.push(blocker("opening_journal_missing", "The selected Opening Balance journal is unavailable in this company.", "opening_balance"));
    } else {
      const lines = Array.isArray(journal.lines) ? journal.lines : [];
      const debitCents = lines.reduce((sum, line) => sum + storedCount(line.debit_cents ?? 0, "opening_debit_cents"), 0);
      const creditCents = lines.reduce((sum, line) => sum + storedCount(line.credit_cents ?? 0, "opening_credit_cents"), 0);
      if (journal.entry_kind !== "opening_balance" || (journal.source_type || "manual") !== "manual") {
        blockers.push(blocker("opening_journal_kind_invalid", "The selected journal is not a manual Opening Balance journal.", "opening_balance"));
      }
      if (dateValue(journal.entry_date) !== coverageStartDate) {
        blockers.push(blocker("opening_journal_date_mismatch", "The Opening Balance journal date must equal the coverage start date.", "opening_balance"));
      }
      if (journal.reversed_by_entry_id) blockers.push(blocker("opening_journal_reversed", "The selected Opening Balance journal has been reversed.", "opening_balance"));
      if (lines.length < 2 || debitCents <= 0 || debitCents !== creditCents) {
        blockers.push(blocker("opening_journal_unbalanced", "The selected Opening Balance journal does not contain exact balanced lines.", "opening_balance"));
      }
      if (lines.some((line) => !["asset", "liability", "equity"].includes(line.account_type))) {
        blockers.push(blocker("opening_journal_account_type_invalid", "Opening evidence may contain only asset, liability, and equity accounts.", "opening_balance"));
      }
      if (!lines.some((line) => line.account_type === "asset" || line.account_type === "liability")) {
        blockers.push(blocker("opening_journal_permanent_balance_missing", "Opening evidence needs at least one asset or liability line.", "opening_balance"));
      }
      journalSnapshot = {
        id: String(journal.id),
        entry_date: dateValue(journal.entry_date),
        entry_kind: journal.entry_kind,
        source_type: journal.source_type || "manual",
        reversed_by_entry_id: journal.reversed_by_entry_id || null,
        lines: lines.map((line) => ({
          chart_account_id: String(line.chart_account_id),
          account_type: line.account_type,
          debit_cents: storedCount(line.debit_cents ?? 0, "opening_debit_cents"),
          credit_cents: storedCount(line.credit_cents ?? 0, "opening_credit_cents")
        })).sort((left, right) => left.chart_account_id.localeCompare(right.chart_account_id))
      };
    }
  } else {
    blockers.push(blocker("opening_balance_method_invalid", "The stored opening-balance method is invalid.", "opening_balance"));
  }
  const snapshot = {
    coverage_start_date: coverageStartDate,
    opening_balance_method: method,
    opening_journal: journalSnapshot,
    earliest_retained_source_date: earliestSourceDate ? dateOnly(earliestSourceDate, "earliest_source_date") : null,
    permanent_accounts: permanentAccounts.slice(0, 200).map((account) => ({
      id: String(account.id),
      code: account.code,
      account_type: account.account_type,
      system_key: account.system_key || null
    })).sort((left, right) => left.id.localeCompare(right.id))
  };
  const liveFingerprint = statementReadinessFingerprint(snapshot);
  const fingerprintCurrent = profile.evidence_fingerprint === liveFingerprint;
  if (blockers.length === 0 && profile.evidence_fingerprint && !fingerprintCurrent) {
    blockers.push(blocker("opening_evidence_changed", "The permanent chart or selected opening evidence changed after review.", "opening_balance"));
  }
  return {
    status: blockers.length > 0 ? "stale" : "current",
    source_current: blockers.length === 0 && fingerprintCurrent,
    live_fingerprint: liveFingerprint,
    blockers: uniqueBlockers(blockers),
    snapshot
  };
}

export function buildStatementReadiness({ profile = null, opening, areas = [], stripeConnected = false, asOfDate }) {
  const common = [...(opening?.blockers || []), ...areas.flatMap((area) => area.blockers || [])];
  if (areas.some((area) => (area.total_count || 0) > 0)) {
    common.push(blocker(
      "source_period_close_not_reviewed",
      "Source inventory exists, but Phase 4E1 does not yet retain a period-close attestation that revalidates every owning workflow's live fingerprint at the requested boundary.",
      "source_period_close"
    ));
  }
  const payrollArea = areas.find((area) => area.key === "payroll_accruals");
  if ((payrollArea?.total_count || 0) > 0 || (payrollArea?.metrics?.payroll_time_entry_count || 0) > 0) {
    common.push(blocker(
      "payroll_cash_settlement_unsupported",
      "Supported payroll has no stable provider-run, withholding/liability, net-pay, or bank-withdrawal settlement identity yet.",
      "payroll_accruals"
    ));
  }
  if (stripeConnected) {
    common.push(blocker(
      "stripe_provider_period_inventory_unavailable",
      "A connected Stripe account exists, but WolfCRM does not yet retain an exhaustive provider-period close proving every payout and balance member is represented.",
      "payment_clearing"
    ));
  }
  const balanceSheetBlockers = uniqueBlockers(common);
  const cashFlowBlockers = uniqueBlockers([
    ...common,
    blocker(
      "cash_flow_classification_unavailable",
      "Journal lines do not yet carry reviewed operating, investing, or financing classifications; account-type heuristics are not accounting authority.",
      "cash_flow_classification"
    )
  ]);
  const sourceInventoryFingerprint = statementReadinessFingerprint({
    coverage_start_date: profile?.coverage_start_date || null,
    as_of_date: asOfDate,
    opening_fingerprint: opening?.live_fingerprint || null,
    areas: areas.map((area) => ({ key: area.key, evidence_hash: area.evidence_hash, metrics: area.metrics })),
    stripe_connected: Boolean(stripeConnected)
  });
  const statementGate = (statement, blockers) => ({
    statement,
    status: blockers.length === 0 ? "coverage_ready" : "blocked",
    coverage_ready: blockers.length === 0,
    report_available: false,
    blocker_count: blockers.length,
    blockers
  });
  return {
    source_inventory_fingerprint: sourceInventoryFingerprint,
    areas,
    statements: {
      balance_sheet: statementGate("balance_sheet", balanceSheetBlockers),
      cash_flow: statementGate("cash_flow", cashFlowBlockers)
    }
  };
}

export async function installFinanceStatementReadinessSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS finance_statement_coverage_profiles (
      company_id UUID PRIMARY KEY REFERENCES companies(id) ON DELETE CASCADE,
      coverage_start_date DATE NOT NULL,
      opening_balance_method TEXT NOT NULL CHECK (opening_balance_method IN ('company_inception_zero','reviewed_journal')),
      opening_journal_entry_id UUID,
      version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
      evidence_fingerprint TEXT NOT NULL CHECK (char_length(evidence_fingerprint)=64),
      evidence_snapshot JSONB NOT NULL,
      reason TEXT NOT NULL,
      reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL,
      reviewed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      FOREIGN KEY (company_id, opening_journal_entry_id)
        REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT,
      CHECK (
        (opening_balance_method='company_inception_zero' AND opening_journal_entry_id IS NULL)
        OR (opening_balance_method='reviewed_journal' AND opening_journal_entry_id IS NOT NULL)
      )
    );
    CREATE INDEX IF NOT EXISTS finance_statement_coverage_profiles_company_date_idx
      ON finance_statement_coverage_profiles(company_id, coverage_start_date);

    CREATE TABLE IF NOT EXISTS finance_statement_coverage_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL CHECK (action IN ('opening_coverage_reviewed','opening_coverage_replaced')),
      reason TEXT NOT NULL,
      version INTEGER NOT NULL CHECK (version > 0),
      client_request_id UUID NOT NULL,
      request_fingerprint TEXT NOT NULL CHECK (char_length(request_fingerprint)=64),
      before_state JSONB,
      after_state JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, client_request_id)
    );
    CREATE INDEX IF NOT EXISTS finance_statement_coverage_audit_company_created_idx
      ON finance_statement_coverage_audit(company_id, created_at DESC);
  `);
}

async function loadCompanyContext(poolOrClient, companyID) {
  const { rows } = await poolOrClient.query(
    `SELECT c.id, c.owner_user_id, COALESCE(NULLIF(c.timezone,''),'America/New_York') AS timezone,
            (now() AT TIME ZONE COALESCE(NULLIF(c.timezone,''),'America/New_York'))::date::text AS company_today,
            (settings.stripe_account_id IS NOT NULL) AS stripe_connected
       FROM companies c
       LEFT JOIN business_settings settings ON settings.user_id=c.owner_user_id
      WHERE c.id=$1`,
    [companyID]
  );
  if (!rows.length) throw new FinanceStatementReadinessError("company_not_found", "Company workspace was not found.", 404);
  return rows[0];
}

function profilePayload(row) {
  if (!row) return null;
  return {
    company_id: String(row.company_id),
    coverage_start_date: dateValue(row.coverage_start_date),
    opening_balance_method: row.opening_balance_method,
    opening_journal_entry_id: row.opening_journal_entry_id || null,
    version: Number(row.version),
    evidence_fingerprint: row.evidence_fingerprint,
    reason: row.reason,
    reviewed_by: row.reviewed_by || null,
    reviewed_at: timestampValue(row.reviewed_at),
    updated_at: timestampValue(row.updated_at)
  };
}

function profileSnapshot(row) {
  const profile = profilePayload(row);
  if (!profile) return null;
  return {
    coverage_start_date: profile.coverage_start_date,
    opening_balance_method: profile.opening_balance_method,
    opening_journal_entry_id: profile.opening_journal_entry_id,
    version: profile.version,
    evidence_fingerprint: profile.evidence_fingerprint
  };
}

async function loadProfile(poolOrClient, companyID, { lock = false } = {}) {
  const { rows } = await poolOrClient.query(
    `SELECT * FROM finance_statement_coverage_profiles WHERE company_id=$1${lock ? " FOR UPDATE" : ""}`,
    [companyID]
  );
  return rows[0] || null;
}

async function loadOpeningEvidence(poolOrClient, companyID, profile) {
  const accountResult = await poolOrClient.query(
    `SELECT id, code, account_type, system_key
       FROM finance_chart_accounts
      WHERE company_id=$1 AND active=true AND account_type IN ('asset','liability','equity')
      ORDER BY id LIMIT 201`,
    [companyID]
  );
  const earliestResult = await poolOrClient.query(
    `SELECT MIN(source_date)::text AS earliest_source_date FROM (
       SELECT entry_date AS source_date FROM finance_journal_entries
        WHERE company_id=$1 AND entry_kind <> 'opening_balance'
       UNION ALL
       SELECT transaction_date FROM finance_transactions
        WHERE company_id=$1 AND status='posted' AND pending=false AND removed_at IS NULL AND amount_cents > 0
       UNION ALL
       SELECT (occurred_at AT TIME ZONE $2)::date FROM finance_operational_sources
        WHERE company_id=$1 AND removed_at IS NULL AND amount_cents > 0 AND occurred_at IS NOT NULL
       UNION ALL
       SELECT end_date FROM finance_payroll_evaluation_periods
        WHERE company_id=$1 AND status='recognized'
     ) retained`,
    [companyID, profile?.timezone || "America/New_York"]
  );
  let journal = null;
  if (profile?.opening_journal_entry_id) {
    const entryResult = await poolOrClient.query(
      `SELECT e.*, reversed.id AS reversed_by_entry_id
         FROM finance_journal_entries e
         LEFT JOIN finance_journal_entries reversed
           ON reversed.company_id=e.company_id AND reversed.reversal_of_entry_id=e.id
        WHERE e.company_id=$1 AND e.id=$2`,
      [companyID, profile.opening_journal_entry_id]
    );
    if (entryResult.rows[0]) {
      const lineResult = await poolOrClient.query(
        `SELECT l.chart_account_id, l.debit_cents, l.credit_cents, c.account_type
           FROM finance_journal_lines l
           JOIN finance_chart_accounts c ON c.company_id=l.company_id AND c.id=l.chart_account_id
          WHERE l.company_id=$1 AND l.entry_id=$2 ORDER BY l.line_order`,
        [companyID, profile.opening_journal_entry_id]
      );
      journal = { ...entryResult.rows[0], lines: lineResult.rows };
    }
  }
  return evaluateOpeningCoverage({
    profile,
    permanentAccounts: accountResult.rows,
    earliestSourceDate: earliestResult.rows[0]?.earliest_source_date || null,
    journal
  });
}

async function loadOpeningCandidates(poolOrClient, companyID) {
  const { rows } = await poolOrClient.query(
    `SELECT e.id, e.entry_date, e.description, reversed.id AS reversed_by_entry_id,
            COALESCE(SUM(l.debit_cents),0) AS total_debits_cents,
            COALESCE(SUM(l.credit_cents),0) AS total_credits_cents
       FROM finance_journal_entries e
       JOIN finance_journal_lines l ON l.company_id=e.company_id AND l.entry_id=e.id
       LEFT JOIN finance_journal_entries reversed
         ON reversed.company_id=e.company_id AND reversed.reversal_of_entry_id=e.id
      WHERE e.company_id=$1 AND e.entry_kind='opening_balance' AND e.source_type='manual'
      GROUP BY e.id, reversed.id
      ORDER BY e.entry_date DESC, e.created_at DESC LIMIT $2`,
    [companyID, MAX_OPENING_CANDIDATES + 1]
  );
  return {
    candidates: rows.slice(0, MAX_OPENING_CANDIDATES).map((row) => ({
      id: String(row.id),
      entry_date: dateValue(row.entry_date),
      description: row.description,
      reversed: Boolean(row.reversed_by_entry_id),
      total_debits_cents: storedCount(row.total_debits_cents, "opening_candidate_debits"),
      total_credits_cents: storedCount(row.total_credits_cents, "opening_candidate_credits")
    })),
    truncated: rows.length > MAX_OPENING_CANDIDATES
  };
}

async function loadAudit(poolOrClient, companyID, limit = MAX_AUDIT_ROWS) {
  const bounded = Math.min(Math.max(Number(limit) || MAX_AUDIT_ROWS, 1), 100);
  const { rows } = await poolOrClient.query(
    `SELECT id, action, reason, version, actor_user_id, created_at
       FROM finance_statement_coverage_audit
      WHERE company_id=$1 ORDER BY created_at DESC LIMIT $2`,
    [companyID, bounded]
  );
  return rows.map((row) => ({
    id: String(row.id),
    action: row.action,
    reason: row.reason,
    version: Number(row.version),
    actor_user_id: row.actor_user_id || null,
    created_at: timestampValue(row.created_at)
  }));
}

async function loadInventoryAreas(poolOrClient, companyID, startDate, asOfDate, timezone) {
  const accountResult = await poolOrClient.query(
    `SELECT COUNT(*)::int AS total_count,
            COUNT(*) FILTER (WHERE mapping.chart_account_id IS NOT NULL
                              AND chart.active=true AND chart.account_type IN ('asset','liability')
                              AND LOWER(COALESCE(account.currency,'usd'))='usd'
                              AND account.transaction_history_removed_at IS NULL
                              AND (account.source <> 'plaid' OR COALESCE(item.status,'disconnected')='active'))::int AS covered_count,
            COUNT(*) FILTER (WHERE NOT (mapping.chart_account_id IS NOT NULL
                              AND chart.active=true AND chart.account_type IN ('asset','liability')
                              AND LOWER(COALESCE(account.currency,'usd'))='usd'
                              AND account.transaction_history_removed_at IS NULL
                              AND (account.source <> 'plaid' OR COALESCE(item.status,'disconnected')='active')))::int AS blocking_count,
            COUNT(*) FILTER (WHERE mapping.chart_account_id IS NULL OR chart.id IS NULL OR chart.active=false OR chart.account_type NOT IN ('asset','liability'))::int AS unmapped_account_count,
            COUNT(*) FILTER (WHERE account.source='plaid' AND COALESCE(item.status,'disconnected') <> 'active')::int AS disconnected_account_count,
            COUNT(*) FILTER (WHERE account.transaction_history_removed_at IS NOT NULL)::int AS removed_history_account_count,
            COUNT(*) FILTER (WHERE LOWER(COALESCE(account.currency,'usd')) <> 'usd')::int AS unsupported_currency_account_count,
            md5(COALESCE(string_agg(concat_ws('|',account.id,mapping.version,mapping.chart_account_id,chart.active,item.status,account.transaction_history_removed_at),',' ORDER BY account.id),'')) AS evidence_hash
       FROM finance_accounts account
       LEFT JOIN finance_account_chart_mappings mapping ON mapping.company_id=account.company_id AND mapping.finance_account_id=account.id
       LEFT JOIN finance_chart_accounts chart ON chart.company_id=mapping.company_id AND chart.id=mapping.chart_account_id
       LEFT JOIN finance_plaid_items item ON item.company_id=account.company_id AND item.id=account.plaid_item_internal_id
      WHERE account.company_id=$1 AND account.archived_at IS NULL`,
    [companyID]
  );

  const bankResult = await poolOrClient.query(
    `WITH split_totals AS (
       SELECT company_id, transaction_id, SUM(amount_cents) AS allocated_cents
         FROM finance_transaction_splits GROUP BY company_id, transaction_id
     ), represented AS (
       SELECT tx.id, tx.accounting_version, tx.reconciliation_status, tx.amount_cents,
              LOWER(COALESCE(tx.iso_currency_code, account.currency, 'usd')) AS currency,
              COALESCE(split.allocated_cents,0) AS allocated_cents,
              (CASE WHEN bank.id IS NOT NULL AND bank.status='posted' AND bank_journal.id IS NOT NULL
                          AND bank_journal.source_type='finance_transaction' AND bank_journal.source_id=tx.id
                          AND bank_journal.source_version=bank.version THEN 1 ELSE 0 END
               + CASE WHEN member.id IS NOT NULL AND pair.status='posted' AND transfer_journal.id IS NOT NULL
                          AND transfer_journal.source_type='finance_transfer_pair' AND transfer_journal.source_id=pair.id
                          AND transfer_journal.source_version=pair.version THEN 1 ELSE 0 END
               + CASE WHEN settlement.id IS NOT NULL AND settlement.status='posted' AND settlement_journal.id IS NOT NULL
                          AND settlement_journal.source_type='finance_stripe_settlement' AND settlement_journal.source_id=settlement.id
                          AND settlement_journal.source_version=settlement.version THEN 1 ELSE 0 END) AS representation_count,
              mapping.version AS mapping_version, mapping.chart_account_id, chart.active AS chart_active,
              chart.account_type AS chart_account_type,
              bank.version AS bank_version, pair.version AS pair_version, settlement.version AS settlement_version
         FROM finance_transactions tx
         JOIN finance_accounts account ON account.company_id=tx.company_id AND account.id=tx.account_id
         LEFT JOIN split_totals split ON split.company_id=tx.company_id AND split.transaction_id=tx.id
         LEFT JOIN finance_account_chart_mappings mapping ON mapping.company_id=account.company_id AND mapping.finance_account_id=account.id
         LEFT JOIN finance_chart_accounts chart ON chart.company_id=mapping.company_id AND chart.id=mapping.chart_account_id
         LEFT JOIN finance_bank_transaction_postings bank ON bank.company_id=tx.company_id AND bank.finance_transaction_id=tx.id
         LEFT JOIN finance_journal_entries bank_journal ON bank_journal.company_id=bank.company_id AND bank_journal.id=bank.journal_entry_id
         LEFT JOIN finance_transfer_pair_members member ON member.company_id=tx.company_id AND member.finance_transaction_id=tx.id AND member.active=true
         LEFT JOIN finance_transfer_pairs pair ON pair.company_id=member.company_id AND pair.id=member.pair_id
         LEFT JOIN finance_journal_entries transfer_journal ON transfer_journal.company_id=pair.company_id AND transfer_journal.id=pair.journal_entry_id
         LEFT JOIN finance_stripe_settlements settlement ON settlement.company_id=tx.company_id AND settlement.bank_transaction_id=tx.id AND settlement.status='posted'
         LEFT JOIN finance_journal_entries settlement_journal ON settlement_journal.company_id=settlement.company_id AND settlement_journal.id=settlement.journal_entry_id
        WHERE tx.company_id=$1 AND tx.transaction_date BETWEEN $2::date AND $3::date
          AND tx.status='posted' AND tx.pending=false AND tx.removed_at IS NULL AND tx.amount_cents > 0
     )
     SELECT COUNT(*)::int AS total_count,
            COUNT(*) FILTER (WHERE reconciliation_status='reconciled' AND allocated_cents=amount_cents
                              AND currency='usd' AND chart_account_id IS NOT NULL AND chart_active=true
                              AND chart_account_type IN ('asset','liability') AND representation_count=1)::int AS covered_count,
            COUNT(*) FILTER (WHERE NOT (reconciliation_status='reconciled' AND allocated_cents=amount_cents
                              AND currency='usd' AND chart_account_id IS NOT NULL AND chart_active=true
                              AND chart_account_type IN ('asset','liability') AND representation_count=1))::int AS blocking_count,
            COUNT(*) FILTER (WHERE reconciliation_status <> 'reconciled')::int AS unreconciled_transaction_count,
            COUNT(*) FILTER (WHERE allocated_cents <> amount_cents)::int AS unclassified_transaction_count,
            COUNT(*) FILTER (WHERE representation_count=0)::int AS unrepresented_transaction_count,
            COUNT(*) FILTER (WHERE representation_count>1)::int AS multiply_represented_transaction_count,
            COUNT(*) FILTER (WHERE currency <> 'usd')::int AS unsupported_currency_transaction_count,
            md5(COALESCE(string_agg(concat_ws('|',id,accounting_version,reconciliation_status,amount_cents,allocated_cents,representation_count,mapping_version,chart_account_id,bank_version,pair_version,settlement_version),',' ORDER BY id),'')) AS evidence_hash
       FROM represented`,
    [companyID, startDate, asOfDate]
  );

  const receivableResult = await poolOrClient.query(
    `WITH sources AS (
       SELECT source.id, source.source_version, source.occurred_at,
              posting.id AS posting_id, posting.version AS posting_version,
              CASE WHEN posting.status='posted' AND journal.id IS NOT NULL
                         AND journal.source_type='finance_operational_source'
                         AND journal.source_id=source.id AND journal.source_version=posting.version
                   THEN true ELSE false END AS covered
         FROM finance_operational_sources source
         LEFT JOIN finance_operational_receivable_postings posting
           ON posting.company_id=source.company_id AND posting.operational_source_id=source.id
         LEFT JOIN finance_journal_entries journal
           ON journal.company_id=posting.company_id AND journal.id=posting.journal_entry_id
        WHERE source.company_id=$1 AND source.source_type='job_receivable'
          AND source.status='recognized' AND source.removed_at IS NULL
          AND (source.occurred_at IS NULL OR (source.occurred_at AT TIME ZONE $4)::date BETWEEN $2::date AND $3::date)
     )
     SELECT COUNT(*)::int AS total_count,
            COUNT(*) FILTER (WHERE covered)::int AS covered_count,
            COUNT(*) FILTER (WHERE NOT covered)::int AS blocking_count,
            COUNT(*) FILTER (WHERE occurred_at IS NULL)::int AS unknown_date_receivable_count,
            COUNT(*) FILTER (WHERE posting_id IS NULL)::int AS unposted_receivable_count,
            md5(COALESCE(string_agg(concat_ws('|',id,source_version,posting_id,posting_version,covered),',' ORDER BY id),'')) AS evidence_hash
       FROM sources`,
    [companyID, startDate, asOfDate, timezone]
  );

  const applicationResult = await poolOrClient.query(
    `WITH expected AS (
       SELECT 'payment'::text AS kind, source.id AS source_id, source.source_version AS source_version,
              source.occurred_at, application.id AS application_id, application.version AS application_version,
              CASE WHEN application.status='posted' AND journal.id IS NOT NULL
                         AND journal.source_type='finance_operational_application'
                         AND journal.source_id=application.id AND journal.source_version=application.version
                   THEN true ELSE false END AS covered
         FROM finance_operational_sources source
         LEFT JOIN finance_operational_applications application
           ON application.company_id=source.company_id AND application.kind='payment' AND application.operational_source_id=source.id
         LEFT JOIN finance_journal_entries journal
           ON journal.company_id=application.company_id AND journal.id=application.journal_entry_id
        WHERE source.company_id=$1 AND source.source_type='payment' AND source.removed_at IS NULL
          AND source.status IN ('succeeded','paid','partially_refunded','refunded')
          AND (source.occurred_at IS NULL OR (source.occurred_at AT TIME ZONE $4)::date BETWEEN $2::date AND $3::date)
       UNION ALL
       SELECT 'refund', revision.id, revision.version, revision.occurred_at,
              application.id, application.version,
              CASE WHEN application.status='posted' AND journal.id IS NOT NULL
                         AND journal.source_type='finance_operational_application'
                         AND journal.source_id=application.id AND journal.source_version=application.version
                   THEN true ELSE false END
         FROM finance_payment_refund_revisions revision
         LEFT JOIN finance_operational_applications application
           ON application.company_id=revision.company_id AND application.kind='refund' AND application.refund_revision_id=revision.id
         LEFT JOIN finance_journal_entries journal
           ON journal.company_id=application.company_id AND journal.id=application.journal_entry_id
        WHERE revision.company_id=$1
          AND (revision.occurred_at IS NULL OR (revision.occurred_at AT TIME ZONE $4)::date BETWEEN $2::date AND $3::date)
     )
     SELECT COUNT(*)::int AS total_count,
            COUNT(*) FILTER (WHERE covered)::int AS covered_count,
            COUNT(*) FILTER (WHERE NOT covered)::int AS blocking_count,
            COUNT(*) FILTER (WHERE occurred_at IS NULL)::int AS unknown_date_application_source_count,
            COUNT(*) FILTER (WHERE application_id IS NULL)::int AS unposted_application_count,
            md5(COALESCE(string_agg(concat_ws('|',kind,source_id,source_version,application_id,application_version,covered),',' ORDER BY kind,source_id),'')) AS evidence_hash
       FROM expected`,
    [companyID, startDate, asOfDate, timezone]
  );

  const payrollResult = await poolOrClient.query(
    `WITH periods AS (
       SELECT evaluation.id, evaluation.version, evaluation.source_fingerprint,
              posting.id AS posting_id, posting.version AS posting_version,
              CASE WHEN posting.status='posted' AND journal.id IS NOT NULL
                         AND journal.source_type='finance_payroll_evaluation'
                         AND journal.source_id=evaluation.id AND journal.source_version=posting.version
                   THEN true ELSE false END AS covered
         FROM finance_payroll_evaluation_periods evaluation
         LEFT JOIN finance_payroll_journal_postings posting
           ON posting.company_id=evaluation.company_id AND posting.evaluation_period_id=evaluation.id
         LEFT JOIN finance_journal_entries journal
           ON journal.company_id=posting.company_id AND journal.id=posting.journal_entry_id
        WHERE evaluation.company_id=$1 AND evaluation.status='recognized'
          AND evaluation.end_date BETWEEN $2::date AND $3::date
     ), time_coverage AS (
       SELECT COUNT(*)::int AS time_count,
              COUNT(*) FILTER (WHERE entry.end_at IS NULL OR NOT EXISTS (
                SELECT 1 FROM finance_payroll_evaluation_periods evaluation
                 WHERE evaluation.company_id=entry.company_id AND evaluation.status='recognized'
                   AND (entry.start_at AT TIME ZONE $4)::date BETWEEN evaluation.start_date AND evaluation.end_date
              ))::int AS uncovered_time_count
         FROM time_clock_entries entry
        WHERE entry.company_id=$1 AND entry.manual_status <> 'disapproved'
          AND (entry.start_at AT TIME ZONE $4)::date BETWEEN $2::date AND $3::date
     )
     SELECT (COUNT(periods.id) + MAX(time_coverage.uncovered_time_count))::int AS total_count,
            COUNT(periods.id) FILTER (WHERE periods.covered)::int AS covered_count,
            (COUNT(periods.id) FILTER (WHERE NOT periods.covered) + MAX(time_coverage.uncovered_time_count))::int AS blocking_count,
            COALESCE(MAX(time_coverage.time_count),0)::int AS payroll_time_entry_count,
            COALESCE(MAX(time_coverage.uncovered_time_count),0)::int AS uncovered_payroll_time_entry_count,
            COUNT(periods.id) FILTER (WHERE periods.posting_id IS NULL)::int AS unposted_payroll_period_count,
            md5(COALESCE(string_agg(concat_ws('|',periods.id,periods.version,periods.source_fingerprint,periods.posting_id,periods.posting_version,periods.covered),',' ORDER BY periods.id),'')
                || '|' || COALESCE(MAX(time_coverage.time_count),0)::text || '|' || COALESCE(MAX(time_coverage.uncovered_time_count),0)::text) AS evidence_hash
       FROM periods CROSS JOIN time_coverage`,
    [companyID, startDate, asOfDate, timezone]
  );

  const clearingResult = await poolOrClient.query(
    `WITH applications AS (
       SELECT application.id, application.version, application.kind, application.entry_date,
              member.id AS member_id, settlement.id AS settlement_id, settlement.version AS settlement_version,
              CASE WHEN member.active=true AND settlement.status='posted' AND journal.id IS NOT NULL
                         AND journal.source_type='finance_stripe_settlement'
                         AND journal.source_id=settlement.id AND journal.source_version=settlement.version
                   THEN true ELSE false END AS covered
         FROM finance_operational_applications application
         LEFT JOIN finance_stripe_settlement_members member
           ON member.company_id=application.company_id AND member.operational_application_id=application.id AND member.active=true
         LEFT JOIN finance_stripe_settlements settlement
           ON settlement.company_id=member.company_id AND settlement.id=member.settlement_id AND settlement.version=member.settlement_version
         LEFT JOIN finance_journal_entries journal
           ON journal.company_id=settlement.company_id AND journal.id=settlement.journal_entry_id
        WHERE application.company_id=$1 AND application.kind IN ('payment','refund') AND application.status='posted'
          AND application.entry_date BETWEEN $2::date AND $3::date
     )
     SELECT COUNT(*)::int AS total_count,
            COUNT(*) FILTER (WHERE covered)::int AS covered_count,
            COUNT(*) FILTER (WHERE NOT covered)::int AS blocking_count,
            COUNT(*) FILTER (WHERE member_id IS NULL)::int AS unsettled_application_count,
            COUNT(DISTINCT settlement_id) FILTER (WHERE covered)::int AS posted_settlement_count,
            md5(COALESCE(string_agg(concat_ws('|',id,version,kind,member_id,settlement_id,settlement_version,covered),',' ORDER BY id),'')) AS evidence_hash
       FROM applications`,
    [companyID, startDate, asOfDate]
  );

  return [
    normalizeStatementCoverageArea({
      key: "finance_accounts", label: "Finance account mapping",
      row: accountResult.rows[0], blockerCode: "finance_account_coverage_incomplete",
      blockerMessage: "Map every active Finance account to one active permanent chart account and resolve disconnection, history, or currency blockers."
    }),
    normalizeStatementCoverageArea({
      key: "bank_transactions", label: "Bank transaction journals",
      row: bankResult.rows[0], blockerCode: "bank_transaction_coverage_incomplete",
      blockerMessage: "Every positive posted bank transaction in the coverage period must be reconciled, exactly classified, and represented by exactly one current local journal authority.",
      warnings: ["Header and journal cardinality is checked set-wise; provider-period exhaustiveness remains a separate gate."]
    }),
    normalizeStatementCoverageArea({
      key: "receivables", label: "Completed-job receivables",
      row: receivableResult.rows[0], blockerCode: "receivable_coverage_incomplete",
      blockerMessage: "Every current completed-job receivable in the coverage period needs exact dated source evidence and a current source-owned journal."
    }),
    normalizeStatementCoverageArea({
      key: "operational_applications", label: "Payment and refund applications",
      row: applicationResult.rows[0], blockerCode: "operational_application_coverage_incomplete",
      blockerMessage: "Every collected payment and retained refund revision in the coverage period needs exact dated application authority and a current source-owned journal."
    }),
    normalizeStatementCoverageArea({
      key: "payroll_accruals", label: "Supported payroll accruals",
      row: payrollResult.rows[0], blockerCode: "payroll_accrual_coverage_incomplete",
      blockerMessage: "Every supported-payroll period and non-disapproved time entry needs reviewed period coverage and a current accrual journal."
    }),
    normalizeStatementCoverageArea({
      key: "payment_clearing", label: "Payment clearing settlement",
      row: clearingResult.rows[0], blockerCode: "payment_clearing_coverage_incomplete",
      blockerMessage: "Every posted payment/refund application in the period must be bound to an exact current settlement before Payment Clearing can be treated as settled."
    })
  ];
}

async function loadStatementReadiness(pool, companyID, asOfValue, auditLimit, ensureChartAccounts) {
  await ensureChartAccounts(pool, companyID);
  await syncOperationalAccountingSources(pool, companyID);
  const client = await pool.connect();
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    const context = await loadCompanyContext(client, companyID);
    const asOfDate = dateOnly(asOfValue || context.company_today, "as_of_date");
    if (asOfDate > context.company_today) {
      throw new FinanceStatementReadinessError("statement_as_of_future", "Statement readiness cannot be evaluated after the company's current local day.");
    }
    const profileRow = await loadProfile(client, companyID);
    const profile = profileRow ? { ...profilePayload(profileRow), timezone: context.timezone } : null;
    if (profile && asOfDate < profile.coverage_start_date) {
      throw new FinanceStatementReadinessError("statement_as_of_before_coverage", "As-of date must be on or after the reviewed coverage start.");
    }
    const opening = await loadOpeningEvidence(client, companyID, profile ? { ...profileRow, timezone: context.timezone } : null);
    const openingCandidates = await loadOpeningCandidates(client, companyID);
    const audit = await loadAudit(client, companyID, auditLimit);
    const areas = profile
      ? await loadInventoryAreas(client, companyID, profile.coverage_start_date, asOfDate, context.timezone)
      : [];
    const readiness = buildStatementReadiness({
      profile,
      opening,
      areas,
      stripeConnected: context.stripe_connected,
      asOfDate
    });
    await client.query("COMMIT");
    return {
      basis: "formal_statement_coverage_gate",
      timezone: context.timezone,
      company_today: context.company_today,
      as_of_date: asOfDate,
      currency: "usd",
      profile,
      opening: {
        status: opening.status,
        source_current: opening.source_current,
        live_fingerprint: opening.live_fingerprint,
        blockers: opening.blockers
      },
      opening_journal_candidates: openingCandidates.candidates,
      opening_journal_candidates_truncated: openingCandidates.truncated,
      audit,
      ...readiness,
      warnings: [
        "This screen inventories formal-statement coverage; it is not a Balance Sheet or Cash Flow report.",
        "A balanced trial balance does not prove opening balances, source completeness, provider-period completeness, payroll settlement, or cash-flow classification.",
        "Phase 1 cash-basis Profit & Loss remains a separate bank-activity report and is not recomputed here."
      ]
    };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

function sendError(res, error, fallback) {
  if (error instanceof FinanceStatementReadinessError || error?.statusCode) {
    return res.status(error.statusCode || 400).json({
      error: error.code || fallback,
      message: error.message,
      current_version: error.current_version,
      blockers: error.blockers
    });
  }
  if (error?.code === "23505") return res.status(409).json({ error: "statement_coverage_conflict", message: "That statement coverage request already exists." });
  console.error("[finance-statement-readiness]", fallback, { code: error?.code, message: error?.message });
  return res.status(500).json({ error: fallback, message: "Statement readiness request failed." });
}

export function installFinanceStatementReadinessRoutes({ app, pool, authRequired, requireFinanceAccess, ensureChartAccounts }) {
  app.get("/api/finance/accounting/statement-readiness", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Statement readiness requires a company workspace." });
    try {
      res.json(await loadStatementReadiness(pool, req.companyId, req.query.as_of_date, req.query.audit_limit, ensureChartAccounts));
    } catch (error) {
      sendError(res, error, "statement_readiness_load_failed");
    }
  });

  app.put("/api/finance/accounting/statement-readiness/profile", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Statement readiness requires a company workspace." });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(`SELECT pg_advisory_xact_lock(hashtext($1::text))`, [`${req.companyId}|accounting`]);
      const context = await loadCompanyContext(client, req.companyId);
      const request = normalizeStatementCoverageProfileRequest({ body: req.body, companyToday: context.company_today });
      const replay = await client.query(
        `SELECT request_fingerprint FROM finance_statement_coverage_audit
          WHERE company_id=$1 AND client_request_id=$2::uuid FOR UPDATE`,
        [req.companyId, request.client_request_id]
      );
      if (replay.rows.length) {
        if (replay.rows[0].request_fingerprint !== request.request_fingerprint) {
          throw new FinanceStatementReadinessError("statement_coverage_request_conflict", "That request ID was already used with different content.", 409);
        }
        await client.query("COMMIT");
        return res.json({ replayed: true, ...(await loadStatementReadiness(pool, req.companyId, req.body.as_of_date, req.query.audit_limit, ensureChartAccounts)) });
      }
      await ensureChartAccounts(client, req.companyId, req.userId);
      const current = await loadProfile(client, req.companyId, { lock: true });
      const currentVersion = Number(current?.version || 0);
      if (request.expected_version !== currentVersion) {
        throw new FinanceStatementReadinessError("statement_coverage_stale", "Statement coverage changed after it was loaded.", 409, { current_version: currentVersion });
      }
      const requestedProfile = {
        company_id: req.companyId,
        coverage_start_date: request.coverage_start_date,
        opening_balance_method: request.opening_balance_method,
        opening_journal_entry_id: request.opening_journal_entry_id,
        evidence_fingerprint: null,
        timezone: context.timezone
      };
      const opening = await loadOpeningEvidence(client, req.companyId, requestedProfile);
      const openingBlockers = opening.blockers.filter((item) => item.code !== "opening_evidence_changed");
      if (openingBlockers.length) {
        throw new FinanceStatementReadinessError("statement_opening_coverage_blocked", "Resolve the opening-evidence blockers before saving.", 409, { blockers: openingBlockers });
      }
      const nextVersion = currentVersion + 1;
      const profileResult = await client.query(
        `INSERT INTO finance_statement_coverage_profiles (
           company_id, coverage_start_date, opening_balance_method, opening_journal_entry_id,
           version, evidence_fingerprint, evidence_snapshot, reason, reviewed_by
         ) VALUES ($1,$2::date,$3,$4::uuid,$5,$6,$7,$8,$9)
         ON CONFLICT(company_id) DO UPDATE SET
           coverage_start_date=EXCLUDED.coverage_start_date,
           opening_balance_method=EXCLUDED.opening_balance_method,
           opening_journal_entry_id=EXCLUDED.opening_journal_entry_id,
           version=EXCLUDED.version,
           evidence_fingerprint=EXCLUDED.evidence_fingerprint,
           evidence_snapshot=EXCLUDED.evidence_snapshot,
           reason=EXCLUDED.reason,
           reviewed_by=EXCLUDED.reviewed_by,
           reviewed_at=now(), updated_at=now()
         RETURNING *`,
        [req.companyId, request.coverage_start_date, request.opening_balance_method, request.opening_journal_entry_id,
          nextVersion, opening.live_fingerprint, JSON.stringify(opening.snapshot), request.reason, req.userId]
      );
      const saved = profileResult.rows[0];
      await client.query(
        `INSERT INTO finance_statement_coverage_audit (
           company_id, actor_user_id, action, reason, version, client_request_id,
           request_fingerprint, before_state, after_state
         ) VALUES ($1,$2,$3,$4,$5,$6::uuid,$7,$8,$9)`,
        [req.companyId, req.userId, current ? "opening_coverage_replaced" : "opening_coverage_reviewed",
          request.reason, nextVersion, request.client_request_id, request.request_fingerprint,
          current ? JSON.stringify(profileSnapshot(current)) : null, JSON.stringify(profileSnapshot(saved))]
      );
      await client.query("COMMIT");
      res.json({ replayed: false, ...(await loadStatementReadiness(pool, req.companyId, req.body.as_of_date, req.query.audit_limit, ensureChartAccounts)) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendError(res, error, "statement_coverage_update_failed");
    } finally {
      client.release();
    }
  });
}
