import { createHash, randomUUID } from "node:crypto";
import {
  GeneralLedgerError,
  insertJournal,
  journalFingerprint,
  loadCompanyContext,
  loadJournalEntry,
  reverseJournalLines,
  snapshotInput
} from "./finance-general-ledger.js";
import { syncOperationalAccountingSources } from "./finance-operational-accounting.js";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_REPORT_DAYS = 731;
const MAX_REPORT_ROWS = 200;

export class FinanceOperationalJournalError extends Error {
  constructor(code, message, statusCode = 400, details = {}) {
    super(message);
    this.name = "FinanceOperationalJournalError";
    this.code = code;
    this.statusCode = statusCode;
    Object.assign(this, details);
  }
}

function cleanString(value, maxLength = 200) {
  return (value ?? "").toString().trim().slice(0, maxLength);
}

function uuid(value, field) {
  const normalized = cleanString(value, 64).toLowerCase();
  if (!UUID_PATTERN.test(normalized)) {
    throw new FinanceOperationalJournalError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return normalized;
}

function exactInteger(value, field, minimum = 0) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value.trim()) ? Number(value.trim()) : value;
  if (!Number.isSafeInteger(parsed) || parsed < minimum) {
    throw new FinanceOperationalJournalError(`${field}_invalid`, `${field.replaceAll("_", " ")} must be an exact integer.`);
  }
  return parsed;
}

function storedInteger(value, field) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(parsed)) {
    throw new FinanceOperationalJournalError("operational_journal_amount_inexact", `${field.replaceAll("_", " ")} exceeds the exact supported range.`, 409);
  }
  return parsed;
}

function dateOnly(value, field = "date") {
  const raw = value instanceof Date ? value.toISOString().slice(0, 10) : cleanString(value, 20);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    throw new FinanceOperationalJournalError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  const [year, month, day] = raw.split("-").map(Number);
  const parsed = new Date(Date.UTC(year, month - 1, day));
  if (parsed.getUTCFullYear() !== year || parsed.getUTCMonth() !== month - 1 || parsed.getUTCDate() !== day) {
    throw new FinanceOperationalJournalError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return raw;
}

function addDays(value, days) {
  const [year, month, day] = value.split("-").map(Number);
  return new Date(Date.UTC(year, month - 1, day + days)).toISOString().slice(0, 10);
}

function normalizedInstant(value) {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed.toISOString() : null;
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
  }
  return value;
}

function fingerprint(value) {
  return createHash("sha256").update(JSON.stringify(stableValue(value))).digest("hex");
}

function postingVersion(posting) {
  return posting ? Number(posting.version || 0) : 0;
}

function blocker(code, message) {
  return { code, message };
}

function evidenceObject(value) {
  if (value && typeof value === "object" && !Array.isArray(value)) return value;
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
    } catch {
      return {};
    }
  }
  return {};
}

function sourceSnapshot({
  source,
  job,
  accountsReceivableAccount,
  revenueAccount,
  activeBankIncomeAuthorityCount = 0
}) {
  return {
    operational_source_id: String(source.id),
    source_type: source.source_type,
    source_id: String(source.source_id),
    job_id: String(source.job_id || source.source_id),
    source_version: Number(source.source_version || 0),
    status: source.status,
    amount_cents: storedInteger(source.amount_cents ?? 0, "amount_cents"),
    currency: cleanString(source.currency || "usd", 10).toLowerCase(),
    occurred_at: normalizedInstant(source.occurred_at),
    entry_date: source.entry_date ? dateOnly(source.entry_date, "entry_date") : null,
    removed: Boolean(source.removed_at),
    active_bank_income_authority_count: Number(activeBankIncomeAuthorityCount || 0),
    evidence_has_price: evidenceObject(source.evidence).has_price === true,
    live_job: {
      exists: Boolean(job),
      finished_at: normalizedInstant(job?.finished_at),
      price_cents: job?.price_cents == null ? null : storedInteger(job.price_cents, "job_price_cents")
    },
    accounts_receivable: accountsReceivableAccount ? {
      chart_account_id: String(accountsReceivableAccount.id),
      account_type: accountsReceivableAccount.account_type,
      active: accountsReceivableAccount.active !== false,
      system_key: accountsReceivableAccount.system_key || null
    } : null,
    revenue: revenueAccount ? {
      chart_account_id: String(revenueAccount.id),
      account_type: revenueAccount.account_type,
      active: revenueAccount.active !== false
    } : null
  };
}

export function parseOperationalReceivableJournalRange(startValue, endValue) {
  const startDate = dateOnly(startValue, "start_date");
  const endDate = dateOnly(endValue, "end_date");
  if (startDate > endDate) {
    throw new FinanceOperationalJournalError("operational_journal_range_invalid", "Start date must be on or before end date.");
  }
  if (addDays(startDate, MAX_REPORT_DAYS - 1) < endDate) {
    throw new FinanceOperationalJournalError("operational_journal_range_too_large", `Receivable-journal ranges cannot exceed ${MAX_REPORT_DAYS} days.`);
  }
  return { start_date: startDate, end_date: endDate };
}

function boundedLimit(value) {
  if (value === undefined || value === null || value === "") return 100;
  return Math.min(exactInteger(value, "limit", 1), MAX_REPORT_ROWS);
}

export function evaluateOperationalReceivableSource({
  source,
  job = null,
  accountsReceivableAccount = null,
  revenueAccount = null,
  posting = null,
  requireRevenueAccount = true,
  activeBankIncomeAuthorityCount = 0
}) {
  if (!source) throw new FinanceOperationalJournalError("operational_receivable_source_not_found", "Receivable source was not found.", 404);
  const blockers = [];
  const evidence = evidenceObject(source.evidence);
  const amount = storedInteger(source.amount_cents ?? 0, "amount_cents");
  const sourceVersion = Number(source.source_version || 0);
  const occurredAt = normalizedInstant(source.occurred_at);
  const jobFinishedAt = normalizedInstant(job?.finished_at);
  const jobPrice = job?.price_cents == null ? null : storedInteger(job.price_cents, "job_price_cents");

  if (source.source_type !== "job_receivable") blockers.push(blocker("operational_source_type_invalid", "Only completed-job receivable sources can use this workflow."));
  if (source.status !== "recognized") blockers.push(blocker("operational_source_not_recognized", "The receivable source is not currently recognized."));
  if (source.removed_at) blockers.push(blocker("operational_source_removed", "This receivable source was removed or the job was reopened."));
  if (!Number.isSafeInteger(sourceVersion) || sourceVersion < 1) blockers.push(blocker("operational_source_version_invalid", "The receivable source version is invalid."));
  if (cleanString(source.currency || "usd", 10).toLowerCase() !== "usd") blockers.push(blocker("operational_source_currency_unsupported", "Receivable journals currently support USD only."));
  if (evidence.has_price !== true) blockers.push(blocker("operational_source_unpriced", "The completed job needs an exact stored price."));
  if (amount <= 0) blockers.push(blocker("operational_source_zero_amount", "A receivable journal needs a positive exact job price."));
  if (!occurredAt || !source.entry_date) blockers.push(blocker("operational_source_completion_invalid", "The completed job needs a valid company-local completion date."));
  if (!job || String(job.id) !== String(source.job_id || source.source_id)) {
    blockers.push(blocker("operational_source_job_unavailable", "The source job is unavailable in this company."));
  } else {
    if (!jobFinishedAt) blockers.push(blocker("operational_source_job_reopened", "The source job is no longer completed."));
    if (jobPrice == null || jobPrice < 0) blockers.push(blocker("operational_source_job_unpriced", "The live completed job no longer has an exact price."));
    if (jobPrice !== amount) blockers.push(blocker("operational_source_price_changed", "The live job price and synchronized source do not match."));
    if (jobFinishedAt !== occurredAt) blockers.push(blocker("operational_source_completion_changed", "The live completion instant and synchronized source do not match."));
  }
  if (!accountsReceivableAccount) {
    blockers.push(blocker("accounts_receivable_account_missing", "The company Accounts Receivable account is unavailable."));
  } else if (accountsReceivableAccount.active === false || accountsReceivableAccount.account_type !== "asset" || accountsReceivableAccount.system_key !== "accounts_receivable") {
    blockers.push(blocker("accounts_receivable_account_invalid", "The system Accounts Receivable account must be active and remain an asset."));
  }
  if (Number(activeBankIncomeAuthorityCount || 0) > 0) {
    blockers.push(blocker(
      "bank_income_authority_active",
      "Reviewed bank-income revenue already exists in the ledger. Void that cash-source authority before posting completed-job revenue; an exact settlement workflow is not available yet."
    ));
  }
  if (!revenueAccount && requireRevenueAccount) {
    blockers.push(blocker("revenue_account_required", "Choose an active company income account."));
  } else if (revenueAccount && (revenueAccount.active === false || revenueAccount.account_type !== "income")) {
    blockers.push(blocker("revenue_account_invalid", "Receivable revenue must use an active company income account."));
  }

  const snapshot = sourceSnapshot({
    source,
    job,
    accountsReceivableAccount,
    revenueAccount,
    activeBankIncomeAuthorityCount
  });
  const sourceFingerprint = fingerprint(snapshot);
  const baseBlockers = blockers.filter((item) => item.code !== "revenue_account_required");
  const candidateEligible = baseBlockers.length === 0;
  const eligible = blockers.length === 0 && Boolean(revenueAccount);
  const sourceCurrent = posting?.status === "posted"
    && posting.source_fingerprint === sourceFingerprint
    && String(posting.revenue_chart_account_id || "") === String(revenueAccount?.id || "");

  let reviewState = "blocked";
  if (sourceCurrent) reviewState = "posted";
  else if (posting?.status === "posted") reviewState = "stale";
  else if (posting?.status === "voided") reviewState = "voided";
  else if (candidateEligible) reviewState = "ready";

  const lines = eligible ? [
    {
      position: 0,
      chart_account_id: String(accountsReceivableAccount.id),
      debit_cents: amount,
      credit_cents: 0,
      memo: "Completed job receivable"
    },
    {
      position: 1,
      chart_account_id: String(revenueAccount.id),
      debit_cents: 0,
      credit_cents: amount,
      memo: "Reviewed completed-job revenue"
    }
  ] : [];

  return {
    eligible,
    candidate_eligible: candidateEligible,
    blockers: [...new Map(blockers.map((item) => [item.code, item])).values()],
    review_state: reviewState,
    source_current: sourceCurrent,
    can_post: candidateEligible && !sourceCurrent,
    can_void: posting?.status === "posted" && Boolean(posting.journal_entry_id),
    source_fingerprint: sourceFingerprint,
    source_snapshot: snapshot,
    journal_preview: eligible ? {
      entry_date: snapshot.entry_date,
      total_debits_cents: amount,
      total_credits_cents: amount,
      lines
    } : null
  };
}

export function normalizeOperationalReceivableActionRequest({ body = {}, operationalSourceID, action }) {
  const normalizedAction = cleanString(action, 20).toLowerCase();
  if (normalizedAction !== "post" && normalizedAction !== "void") {
    throw new FinanceOperationalJournalError("operational_journal_action_invalid", "Choose a valid receivable-journal action.");
  }
  const revenueID = normalizedAction === "post" ? uuid(body.revenue_chart_account_id, "revenue_chart_account_id") : null;
  const input = {
    client_request_id: uuid(body.client_request_id, "client_request_id"),
    operational_source_id: uuid(operationalSourceID, "operational_source_id"),
    action: normalizedAction,
    revenue_chart_account_id: revenueID,
    expected_source_version: exactInteger(body.expected_source_version, "expected_source_version", 1),
    expected_posting_version: exactInteger(body.expected_posting_version, "expected_posting_version"),
    reason: cleanString(body.reason, 500)
  };
  if (!input.reason) throw new FinanceOperationalJournalError("operational_journal_reason_required", "An audit reason is required.");
  return { ...input, request_fingerprint: fingerprint(input) };
}

export function buildOperationalReceivableJournalInput({ evaluation, operationalSourceID, postingVersion: version, clientRequestID, reason }) {
  if (!evaluation?.eligible || !evaluation.journal_preview) {
    throw new FinanceOperationalJournalError("operational_receivable_source_blocked", "Resolve every source blocker before posting.", 409, { blockers: evaluation?.blockers || [] });
  }
  const input = {
    client_request_id: uuid(clientRequestID, "client_request_id"),
    entry_date: evaluation.journal_preview.entry_date,
    entry_kind: "job_receivable",
    description: `Completed job receivable · ${evaluation.journal_preview.entry_date}`,
    reference: `AR-${String(evaluation.source_snapshot.job_id).slice(0, 12).toUpperCase()}`,
    reason: cleanString(reason, 500),
    reversal_of_entry_id: null,
    source_type: "finance_operational_source",
    source_id: uuid(operationalSourceID, "operational_source_id"),
    source_version: exactInteger(version, "source_version", 1),
    lines: evaluation.journal_preview.lines,
    total_debits_cents: evaluation.journal_preview.total_debits_cents,
    total_credits_cents: evaluation.journal_preview.total_credits_cents
  };
  return { ...input, request_fingerprint: journalFingerprint(input) };
}

export function buildOperationalReceivableReversalInput({ original, originalLines, operationalSourceID, postingVersion: version, clientRequestID, reason }) {
  if (!original || original.source_type !== "finance_operational_source" || String(original.source_id) !== String(operationalSourceID)) {
    throw new FinanceOperationalJournalError("operational_journal_relationship_invalid", "The current receivable journal relationship is invalid.", 409);
  }
  if (original.reversal_of_entry_id) {
    throw new FinanceOperationalJournalError("operational_journal_relationship_invalid", "A reversal cannot be current receivable authority.", 409);
  }
  const reversed = reverseJournalLines(originalLines);
  const input = {
    client_request_id: uuid(clientRequestID, "client_request_id"),
    entry_date: dateOnly(original.entry_date, "entry_date"),
    entry_kind: "reversal",
    description: `Reversal — ${cleanString(original.description, 180) || "Completed job receivable"}`,
    reference: cleanString(original.reference, 120) || null,
    reason: cleanString(reason, 500),
    reversal_of_entry_id: String(original.id),
    source_type: "finance_operational_source",
    source_id: uuid(operationalSourceID, "operational_source_id"),
    source_version: exactInteger(version, "source_version", 1),
    lines: reversed.lines,
    total_debits_cents: reversed.total_debits_cents,
    total_credits_cents: reversed.total_credits_cents
  };
  return { ...input, request_fingerprint: journalFingerprint(input) };
}

export async function installFinanceOperationalJournalSchema(pool) {
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS finance_operational_sources_company_id_idx
      ON finance_operational_sources(company_id, id);
    CREATE UNIQUE INDEX IF NOT EXISTS schedule_events_company_id_idx
      ON schedule_events(company_id, id);

    CREATE TABLE IF NOT EXISTS finance_operational_receivable_postings (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      operational_source_id UUID NOT NULL,
      job_id TEXT NOT NULL,
      revenue_chart_account_id UUID NOT NULL,
      journal_entry_id UUID,
      status TEXT NOT NULL CHECK (status IN ('posted','voided')),
      version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
      source_fingerprint TEXT NOT NULL CHECK (char_length(source_fingerprint) = 64),
      source_snapshot JSONB NOT NULL,
      reason TEXT NOT NULL,
      updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, id),
      UNIQUE(company_id, operational_source_id),
      FOREIGN KEY (company_id, operational_source_id) REFERENCES finance_operational_sources(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, job_id) REFERENCES schedule_events(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, revenue_chart_account_id) REFERENCES finance_chart_accounts(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, journal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT,
      CHECK ((status = 'posted' AND journal_entry_id IS NOT NULL) OR (status = 'voided' AND journal_entry_id IS NULL))
    );
    CREATE INDEX IF NOT EXISTS finance_operational_receivable_postings_company_status_idx
      ON finance_operational_receivable_postings(company_id, status, updated_at DESC);
    CREATE INDEX IF NOT EXISTS finance_operational_receivable_postings_company_job_idx
      ON finance_operational_receivable_postings(company_id, job_id);

    CREATE TABLE IF NOT EXISTS finance_operational_receivable_posting_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      posting_id UUID NOT NULL,
      operational_source_id UUID NOT NULL,
      job_id TEXT NOT NULL,
      revenue_chart_account_id UUID NOT NULL,
      actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      reason TEXT NOT NULL,
      version INTEGER NOT NULL CHECK (version > 0),
      client_request_id UUID NOT NULL,
      request_fingerprint TEXT NOT NULL CHECK (char_length(request_fingerprint) = 64),
      source_fingerprint TEXT NOT NULL CHECK (char_length(source_fingerprint) = 64),
      source_snapshot JSONB NOT NULL,
      previous_journal_entry_id UUID,
      journal_entry_id UUID,
      reversal_entry_id UUID,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, client_request_id),
      FOREIGN KEY (company_id, posting_id) REFERENCES finance_operational_receivable_postings(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, operational_source_id) REFERENCES finance_operational_sources(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, job_id) REFERENCES schedule_events(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, revenue_chart_account_id) REFERENCES finance_chart_accounts(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, previous_journal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, journal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, reversal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT
    );
    CREATE INDEX IF NOT EXISTS finance_operational_receivable_posting_audit_company_source_idx
      ON finance_operational_receivable_posting_audit(company_id, operational_source_id, created_at DESC);
  `);
}

function chartPayload(row) {
  if (!row) return null;
  return {
    id: String(row.id),
    code: row.code,
    name: row.name,
    account_type: row.account_type,
    system_key: row.system_key || null,
    active: row.active !== false
  };
}

function postingPayload(posting) {
  if (!posting) return null;
  return {
    id: String(posting.id),
    status: posting.status,
    version: Number(posting.version || 0),
    revenue_chart_account_id: String(posting.revenue_chart_account_id),
    journal_entry_id: posting.journal_entry_id || null,
    source_fingerprint: posting.source_fingerprint,
    reason: posting.reason,
    updated_by: posting.updated_by || null,
    updated_at: posting.updated_at || null
  };
}

function sourcePayload(bundle, { requireRevenueAccount = false } = {}) {
  const evaluation = evaluateOperationalReceivableSource({
    ...bundle,
    requireRevenueAccount: requireRevenueAccount || Boolean(bundle.posting?.revenue_chart_account_id)
  });
  return {
    operational_source_id: String(bundle.source.id),
    job_id: String(bundle.source.job_id || bundle.source.source_id),
    title: bundle.job?.title || "Completed job",
    finished_at: bundle.source.occurred_at,
    entry_date: bundle.source.entry_date,
    amount_cents: storedInteger(bundle.source.amount_cents, "amount_cents"),
    currency: cleanString(bundle.source.currency || "usd", 10).toLowerCase(),
    source_version: Number(bundle.source.source_version || 0),
    source_status: bundle.source.status,
    removed_at: bundle.source.removed_at || null,
    accounts_receivable_account: chartPayload(bundle.accountsReceivableAccount),
    revenue_account: chartPayload(bundle.revenueAccount),
    posting: postingPayload(bundle.posting),
    ...evaluation
  };
}

function bundleFromRow(row) {
  const posting = row.posting_id ? {
    id: row.posting_id,
    status: row.posting_status,
    version: row.posting_version,
    revenue_chart_account_id: row.posting_revenue_chart_account_id,
    journal_entry_id: row.posting_journal_entry_id,
    source_fingerprint: row.posting_source_fingerprint,
    reason: row.posting_reason,
    updated_by: row.posting_updated_by,
    updated_at: row.posting_updated_at
  } : null;
  return {
    source: {
      id: row.id,
      source_type: row.source_type,
      source_id: row.source_id,
      job_id: row.job_id,
      status: row.status,
      amount_cents: row.amount_cents,
      currency: row.currency,
      occurred_at: row.occurred_at,
      entry_date: row.entry_date,
      evidence: row.evidence,
      source_version: row.source_version,
      removed_at: row.removed_at
    },
    job: row.live_job_id ? {
      id: row.live_job_id,
      title: row.job_title,
      price_cents: row.job_price_cents,
      finished_at: row.job_finished_at
    } : null,
    accountsReceivableAccount: row.ar_account_id ? {
      id: row.ar_account_id,
      code: row.ar_code,
      name: row.ar_name,
      account_type: row.ar_account_type,
      system_key: row.ar_system_key,
      active: row.ar_active
    } : null,
    revenueAccount: row.revenue_account_id ? {
      id: row.revenue_account_id,
      code: row.revenue_code,
      name: row.revenue_name,
      account_type: row.revenue_account_type,
      system_key: row.revenue_system_key,
      active: row.revenue_active
    } : null,
    posting
  };
}

const BUNDLE_SELECT = `
  SELECT src.*,
         (src.occurred_at AT TIME ZONE COALESCE(NULLIF(company.timezone, ''), 'America/New_York'))::date::text AS entry_date,
         job.id AS live_job_id, job.title AS job_title, job.price_cents AS job_price_cents,
         job.finished_at AS job_finished_at,
         ar.id AS ar_account_id, ar.code AS ar_code, ar.name AS ar_name,
         ar.account_type AS ar_account_type, ar.system_key AS ar_system_key, ar.active AS ar_active,
         posting.id AS posting_id, posting.status AS posting_status, posting.version AS posting_version,
         posting.revenue_chart_account_id AS posting_revenue_chart_account_id,
         posting.journal_entry_id AS posting_journal_entry_id,
         posting.source_fingerprint AS posting_source_fingerprint,
         posting.reason AS posting_reason, posting.updated_by AS posting_updated_by,
         posting.updated_at AS posting_updated_at,
         revenue.id AS revenue_account_id, revenue.code AS revenue_code, revenue.name AS revenue_name,
         revenue.account_type AS revenue_account_type, revenue.system_key AS revenue_system_key,
         revenue.active AS revenue_active
    FROM finance_operational_sources src
    JOIN companies company ON company.id=src.company_id
    LEFT JOIN schedule_events job ON job.company_id=src.company_id AND job.id=src.job_id
    LEFT JOIN finance_operational_receivable_postings posting
      ON posting.company_id=src.company_id AND posting.operational_source_id=src.id
    LEFT JOIN finance_chart_accounts revenue
      ON revenue.company_id=posting.company_id AND revenue.id=posting.revenue_chart_account_id
    LEFT JOIN finance_chart_accounts ar
      ON ar.company_id=src.company_id AND ar.system_key='accounts_receivable'`;

async function loadReport(poolOrClient, companyID, range, limit) {
  const [countResult, rows, bankAuthorityResult] = await Promise.all([
    poolOrClient.query(
      `SELECT COUNT(*)::int AS count FROM finance_operational_sources src
        JOIN companies company ON company.id=src.company_id
       WHERE src.company_id=$1 AND src.source_type='job_receivable'
         AND (src.occurred_at AT TIME ZONE COALESCE(NULLIF(company.timezone, ''), 'America/New_York'))::date BETWEEN $2::date AND $3::date`,
      [companyID, range.start_date, range.end_date]
    ),
    poolOrClient.query(
      `${BUNDLE_SELECT}
       WHERE src.company_id=$1 AND src.source_type='job_receivable'
         AND (src.occurred_at AT TIME ZONE COALESCE(NULLIF(company.timezone, ''), 'America/New_York'))::date BETWEEN $2::date AND $3::date
       ORDER BY src.occurred_at DESC, src.id
       LIMIT $4`,
      [companyID, range.start_date, range.end_date, limit]
    ),
    poolOrClient.query(
      `SELECT COUNT(DISTINCT posting.id)::int AS count
         FROM finance_bank_transaction_postings posting
         JOIN finance_journal_lines line ON line.company_id=posting.company_id AND line.entry_id=posting.journal_entry_id
         JOIN finance_chart_accounts account ON account.company_id=line.company_id AND account.id=line.chart_account_id
        WHERE posting.company_id=$1 AND posting.status='posted'
          AND line.credit_cents > 0 AND account.account_type='income'`,
      [companyID]
    )
  ]);
  const activeBankIncomeAuthorityCount = Number(bankAuthorityResult.rows[0]?.count || 0);
  const sources = rows.rows.map((row) => sourcePayload({
    ...bundleFromRow(row),
    activeBankIncomeAuthorityCount
  }));
  const counts = { ready: 0, posted: 0, stale: 0, voided: 0, blocked: 0 };
  for (const source of sources) counts[source.review_state] = (counts[source.review_state] || 0) + 1;
  const total = Number(countResult.rows[0]?.count || 0);
  return {
    basis: "reviewed_completed_job_receivable_journal",
    start_date: range.start_date,
    end_date: range.end_date,
    currency: "usd",
    total_count: total,
    returned_count: sources.length,
    truncated: total > sources.length,
    summary: counts,
    warnings: [
      "Receivable journals recognize reviewed completed-job price only: debit Accounts Receivable and credit the explicitly selected income account.",
      "Payments, refunds, customer credits, Stripe/provider clearing, bank cash, material cost, and payroll are not posted by this workflow.",
      "A changed source is corrected only through an exact retained reversal and replacement; no job, payment, provider, or cash-P&L row is rewritten."
    ],
    sources
  };
}

async function loadBundle(poolOrClient, companyID, operationalSourceID) {
  const [result, bankAuthorityResult] = await Promise.all([
    poolOrClient.query(`${BUNDLE_SELECT} WHERE src.company_id=$1 AND src.id=$2`, [companyID, operationalSourceID]),
    poolOrClient.query(
      `SELECT COUNT(DISTINCT posting.id)::int AS count
         FROM finance_bank_transaction_postings posting
         JOIN finance_journal_lines line ON line.company_id=posting.company_id AND line.entry_id=posting.journal_entry_id
         JOIN finance_chart_accounts account ON account.company_id=line.company_id AND account.id=line.chart_account_id
        WHERE posting.company_id=$1 AND posting.status='posted'
          AND line.credit_cents > 0 AND account.account_type='income'`,
      [companyID]
    )
  ]);
  if (!result.rows.length) throw new FinanceOperationalJournalError("operational_receivable_source_not_found", "Receivable source was not found.", 404);
  return {
    ...bundleFromRow(result.rows[0]),
    activeBankIncomeAuthorityCount: Number(bankAuthorityResult.rows[0]?.count || 0)
  };
}

async function loadIncomeAccounts(poolOrClient, companyID) {
  const { rows } = await poolOrClient.query(
    `SELECT id, code, name, account_type, system_key, active
       FROM finance_chart_accounts WHERE company_id=$1 AND account_type='income' AND active=true
      ORDER BY code, name, id`,
    [companyID]
  );
  return rows.map(chartPayload);
}

async function loadAudit(poolOrClient, companyID, operationalSourceID) {
  const { rows } = await poolOrClient.query(
    `SELECT id, action, reason, version, revenue_chart_account_id, actor_user_id,
            previous_journal_entry_id, journal_entry_id, reversal_entry_id, created_at
       FROM finance_operational_receivable_posting_audit
      WHERE company_id=$1 AND operational_source_id=$2 ORDER BY created_at DESC LIMIT 50`,
    [companyID, operationalSourceID]
  );
  return rows.map((row) => ({
    id: String(row.id),
    action: row.action,
    reason: row.reason,
    version: Number(row.version),
    revenue_chart_account_id: String(row.revenue_chart_account_id),
    actor_user_id: row.actor_user_id || null,
    previous_journal_entry_id: row.previous_journal_entry_id || null,
    journal_entry_id: row.journal_entry_id || null,
    reversal_entry_id: row.reversal_entry_id || null,
    created_at: row.created_at || null
  }));
}

async function loadDetail(poolOrClient, companyID, operationalSourceID, requestedRevenueID = null) {
  const bundle = await loadBundle(poolOrClient, companyID, operationalSourceID);
  if (requestedRevenueID) {
    const accountResult = await poolOrClient.query(
      `SELECT id, code, name, account_type, system_key, active FROM finance_chart_accounts WHERE company_id=$1 AND id=$2`,
      [companyID, requestedRevenueID]
    );
    bundle.revenueAccount = accountResult.rows[0] || null;
  }
  const requireRevenue = Boolean(requestedRevenueID || bundle.posting?.revenue_chart_account_id);
  const [incomeAccounts, audit, journal] = await Promise.all([
    loadIncomeAccounts(poolOrClient, companyID),
    loadAudit(poolOrClient, companyID, operationalSourceID),
    bundle.posting?.journal_entry_id
      ? loadJournalEntry(poolOrClient, companyID, bundle.posting.journal_entry_id, 20)
      : Promise.resolve(null)
  ]);
  return {
    source: sourcePayload(bundle, { requireRevenueAccount: requireRevenue }),
    income_accounts: incomeAccounts,
    journal,
    audit
  };
}

async function loadLockedBundle(client, companyID, operationalSourceID, revenueAccountID = null) {
  const sourceResult = await client.query(
    `SELECT src.*,
            (src.occurred_at AT TIME ZONE COALESCE(NULLIF(company.timezone, ''), 'America/New_York'))::date::text AS entry_date
       FROM finance_operational_sources src
       JOIN companies company ON company.id=src.company_id
      WHERE src.company_id=$1 AND src.id=$2 FOR UPDATE OF src`,
    [companyID, operationalSourceID]
  );
  if (!sourceResult.rows.length) throw new FinanceOperationalJournalError("operational_receivable_source_not_found", "Receivable source was not found.", 404);
  const source = sourceResult.rows[0];
  const jobResult = await client.query(
    `SELECT id, title, price_cents, finished_at FROM schedule_events WHERE company_id=$1 AND id=$2 FOR SHARE`,
    [companyID, source.job_id]
  );
  const postingResult = await client.query(
    `SELECT * FROM finance_operational_receivable_postings WHERE company_id=$1 AND operational_source_id=$2 FOR UPDATE`,
    [companyID, operationalSourceID]
  );
  const arResult = await client.query(
    `SELECT id, code, name, account_type, system_key, active FROM finance_chart_accounts
      WHERE company_id=$1 AND system_key='accounts_receivable' FOR SHARE`,
    [companyID]
  );
  const revenueResult = revenueAccountID
    ? await client.query(
      `SELECT id, code, name, account_type, system_key, active FROM finance_chart_accounts
        WHERE company_id=$1 AND id=$2 FOR SHARE`,
      [companyID, revenueAccountID]
    )
    : { rows: [] };
  const bankAuthorityResult = await client.query(
    `SELECT COUNT(DISTINCT posting.id)::int AS count
       FROM finance_bank_transaction_postings posting
       JOIN finance_journal_lines line ON line.company_id=posting.company_id AND line.entry_id=posting.journal_entry_id
       JOIN finance_chart_accounts account ON account.company_id=line.company_id AND account.id=line.chart_account_id
      WHERE posting.company_id=$1 AND posting.status='posted'
        AND line.credit_cents > 0 AND account.account_type='income'`,
    [companyID]
  );
  return {
    source,
    job: jobResult.rows[0] || null,
    accountsReceivableAccount: arResult.rows[0] || null,
    revenueAccount: revenueResult.rows[0] || null,
    posting: postingResult.rows[0] || null,
    activeBankIncomeAuthorityCount: Number(bankAuthorityResult.rows[0]?.count || 0)
  };
}

function assertActionVersions(request, bundle) {
  const sourceVersion = Number(bundle.source.source_version || 0);
  const currentPostingVersion = postingVersion(bundle.posting);
  if (request.expected_source_version !== sourceVersion) {
    throw new FinanceOperationalJournalError("operational_receivable_source_stale", "The receivable source changed after it was loaded.", 409, { current_source_version: sourceVersion });
  }
  if (request.expected_posting_version !== currentPostingVersion) {
    throw new FinanceOperationalJournalError("operational_receivable_posting_stale", "The receivable posting changed after it was loaded.", 409, { current_posting_version: currentPostingVersion });
  }
}

async function replayedRequest(client, companyID, request) {
  const { rows } = await client.query(
    `SELECT request_fingerprint FROM finance_operational_receivable_posting_audit
      WHERE company_id=$1 AND client_request_id=$2::uuid FOR SHARE`,
    [companyID, request.client_request_id]
  );
  if (!rows.length) return false;
  if (rows[0].request_fingerprint !== request.request_fingerprint) {
    throw new FinanceOperationalJournalError("operational_journal_request_id_conflict", "That receivable-journal request ID was already used with different content.", 409);
  }
  return true;
}

async function insertLedgerAudit(client, companyID, userID, entry, relatedEntryID, action, reason, input) {
  await client.query(
    `INSERT INTO finance_journal_audit (company_id, entry_id, related_entry_id, actor_user_id, action, reason, entry_snapshot)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [companyID, entry.id, relatedEntryID || null, userID, action, reason, JSON.stringify(snapshotInput(input))]
  );
}

function sendOperationalJournalError(res, error, fallback) {
  if (error instanceof FinanceOperationalJournalError || error instanceof GeneralLedgerError || error?.statusCode) {
    return res.status(error.statusCode || 400).json({
      error: error.code || fallback,
      message: error.message,
      blockers: error.blockers,
      current_source_version: error.current_source_version,
      current_posting_version: error.current_posting_version
    });
  }
  if (error?.code === "23505") {
    return res.status(409).json({ error: "operational_journal_conflict", message: "That receivable-journal action already exists." });
  }
  console.error("[finance-operational-journals]", fallback, { code: error?.code, message: error?.message });
  return res.status(500).json({ error: fallback, message: "Receivable-journal request failed." });
}

export function installFinanceOperationalJournalRoutes({ app, pool, authRequired, requireFinanceAccess, ensureChartAccounts }) {
  const basePath = "/api/finance/accounting/operational-journals/receivables";

  app.get(basePath, authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Receivable journals require a company workspace." });
    try {
      const context = await loadCompanyContext(pool, req.companyId);
      const end = req.query.end_date || context.company_today;
      const start = req.query.start_date || `${end.slice(0, 7)}-01`;
      const range = parseOperationalReceivableJournalRange(start, end);
      await ensureChartAccounts(pool, req.companyId, req.userId);
      await syncOperationalAccountingSources(pool, req.companyId);
      res.json({ timezone: context.timezone, company_today: context.company_today, ...(await loadReport(pool, req.companyId, range, boundedLimit(req.query.limit))) });
    } catch (error) {
      sendOperationalJournalError(res, error, "operational_journal_report_failed");
    }
  });

  app.get(`${basePath}/:sourceId/preview`, authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Receivable journals require a company workspace." });
    try {
      await ensureChartAccounts(pool, req.companyId, req.userId);
      await syncOperationalAccountingSources(pool, req.companyId);
      const sourceID = uuid(req.params.sourceId, "operational_source_id");
      const revenueID = uuid(req.query.revenue_chart_account_id, "revenue_chart_account_id");
      res.json(await loadDetail(pool, req.companyId, sourceID, revenueID));
    } catch (error) {
      sendOperationalJournalError(res, error, "operational_journal_preview_failed");
    }
  });

  app.get(`${basePath}/:sourceId`, authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Receivable journals require a company workspace." });
    try {
      await ensureChartAccounts(pool, req.companyId, req.userId);
      await syncOperationalAccountingSources(pool, req.companyId);
      res.json(await loadDetail(pool, req.companyId, uuid(req.params.sourceId, "operational_source_id")));
    } catch (error) {
      sendOperationalJournalError(res, error, "operational_journal_detail_failed");
    }
  });

  const mutate = (action) => async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Receivable journals require a company workspace." });
    const client = await pool.connect();
    try {
      const request = normalizeOperationalReceivableActionRequest({ body: req.body, operationalSourceID: req.params.sourceId, action });
      await client.query("BEGIN");
      await client.query(`SELECT id FROM companies WHERE id=$1 FOR UPDATE`, [req.companyId]);
      await ensureChartAccounts(client, req.companyId, req.userId);
      await syncOperationalAccountingSources(client, req.companyId);
      if (await replayedRequest(client, req.companyId, request)) {
        await client.query("COMMIT");
        return res.json({ replayed: true, ...(await loadDetail(pool, req.companyId, request.operational_source_id)) });
      }
      const bundle = await loadLockedBundle(client, req.companyId, request.operational_source_id, request.revenue_chart_account_id);
      if (await replayedRequest(client, req.companyId, request)) {
        await client.query("COMMIT");
        return res.json({ replayed: true, ...(await loadDetail(pool, req.companyId, request.operational_source_id)) });
      }
      assertActionVersions(request, bundle);

      const evaluationRevenue = action === "post"
        ? bundle.revenueAccount
        : (bundle.posting?.revenue_chart_account_id
          ? (await client.query(
            `SELECT id, code, name, account_type, system_key, active FROM finance_chart_accounts
              WHERE company_id=$1 AND id=$2 FOR SHARE`,
            [req.companyId, bundle.posting.revenue_chart_account_id]
          )).rows[0] || null
          : null);
      const evaluation = evaluateOperationalReceivableSource({
        ...bundle,
        revenueAccount: evaluationRevenue,
        requireRevenueAccount: true
      });
      if (action === "post" && !evaluation.eligible) {
        throw new FinanceOperationalJournalError("operational_receivable_source_blocked", "Resolve every source blocker before posting.", 409, { blockers: evaluation.blockers });
      }
      if (action === "post" && evaluation.source_current) {
        await client.query(
          `INSERT INTO finance_operational_receivable_posting_audit (
             company_id, posting_id, operational_source_id, job_id, revenue_chart_account_id,
             actor_user_id, action, reason, version, client_request_id, request_fingerprint,
             source_fingerprint, source_snapshot, previous_journal_entry_id, journal_entry_id, reversal_entry_id
           ) VALUES ($1,$2,$3,$4,$5,$6,'source_reviewed',$7,$8,$9::uuid,$10,$11,$12,$13,$13,NULL)`,
          [req.companyId, bundle.posting.id, request.operational_source_id, bundle.source.job_id,
            bundle.posting.revenue_chart_account_id, req.userId, request.reason, bundle.posting.version,
            request.client_request_id, request.request_fingerprint, evaluation.source_fingerprint,
            JSON.stringify(evaluation.source_snapshot), bundle.posting.journal_entry_id]
        );
        await client.query("COMMIT");
        return res.json({ replayed: false, ...(await loadDetail(pool, req.companyId, request.operational_source_id)) });
      }
      if (action === "void" && (!bundle.posting || bundle.posting.status !== "posted" || !bundle.posting.journal_entry_id)) {
        throw new FinanceOperationalJournalError("operational_receivable_not_posted", "Only a currently posted receivable source can be voided.", 409);
      }

      const nextVersion = postingVersion(bundle.posting) + 1;
      const previousJournalID = bundle.posting?.status === "posted" ? bundle.posting.journal_entry_id : null;
      let reversal = null;
      if (previousJournalID) {
        const originalResult = await client.query(
          `SELECT * FROM finance_journal_entries WHERE company_id=$1 AND id=$2 FOR UPDATE`,
          [req.companyId, previousJournalID]
        );
        const original = originalResult.rows[0];
        const lineResult = await client.query(
          `SELECT chart_account_id, debit_cents, credit_cents, memo FROM finance_journal_lines
            WHERE company_id=$1 AND entry_id=$2 ORDER BY line_order FOR SHARE`,
          [req.companyId, previousJournalID]
        );
        const existingReversal = await client.query(
          `SELECT id FROM finance_journal_entries WHERE company_id=$1 AND reversal_of_entry_id=$2 FOR UPDATE`,
          [req.companyId, previousJournalID]
        );
        if (existingReversal.rows.length) {
          throw new FinanceOperationalJournalError("operational_receivable_already_reversed", "The current receivable journal already has a reversal.", 409);
        }
        const reversalInput = buildOperationalReceivableReversalInput({
          original,
          originalLines: lineResult.rows,
          operationalSourceID: request.operational_source_id,
          postingVersion: nextVersion,
          clientRequestID: action === "void" ? request.client_request_id : randomUUID(),
          reason: request.reason
        });
        reversal = await insertJournal(client, req.companyId, req.userId, reversalInput);
        await insertLedgerAudit(client, req.companyId, req.userId, reversal, original.id, "operational_receivable_reversal_posted", request.reason, reversalInput);
        await insertLedgerAudit(client, req.companyId, req.userId, original, reversal.id, "operational_receivable_reversed", request.reason, reversalInput);
      }

      let journal = null;
      if (action === "post") {
        const journalInput = buildOperationalReceivableJournalInput({
          evaluation,
          operationalSourceID: request.operational_source_id,
          postingVersion: nextVersion,
          clientRequestID: request.client_request_id,
          reason: request.reason
        });
        journal = await insertJournal(client, req.companyId, req.userId, journalInput);
        await insertLedgerAudit(client, req.companyId, req.userId, journal, reversal?.id || null, "operational_receivable_posted", request.reason, journalInput);
      }

      const revenueAccountID = action === "post" ? request.revenue_chart_account_id : bundle.posting.revenue_chart_account_id;
      let posting;
      if (!bundle.posting) {
        posting = (await client.query(
          `INSERT INTO finance_operational_receivable_postings (
             company_id, operational_source_id, job_id, revenue_chart_account_id, journal_entry_id,
             status, version, source_fingerprint, source_snapshot, reason, updated_by
           ) VALUES ($1,$2,$3,$4,$5,'posted',1,$6,$7,$8,$9) RETURNING *`,
          [req.companyId, request.operational_source_id, bundle.source.job_id, revenueAccountID,
            journal.id, evaluation.source_fingerprint, JSON.stringify(evaluation.source_snapshot), request.reason, req.userId]
        )).rows[0];
      } else {
        posting = (await client.query(
          `UPDATE finance_operational_receivable_postings
              SET revenue_chart_account_id=$3, journal_entry_id=$4, status=$5, version=version+1,
                  source_fingerprint=$6, source_snapshot=$7, reason=$8, updated_by=$9, updated_at=now()
            WHERE company_id=$1 AND operational_source_id=$2 RETURNING *`,
          [req.companyId, request.operational_source_id, revenueAccountID, journal?.id || null,
            action === "post" ? "posted" : "voided", evaluation.source_fingerprint,
            JSON.stringify(evaluation.source_snapshot), request.reason, req.userId]
        )).rows[0];
      }
      const auditAction = action === "void" ? "source_voided" : previousJournalID ? "source_replaced" : "source_posted";
      await client.query(
        `INSERT INTO finance_operational_receivable_posting_audit (
           company_id, posting_id, operational_source_id, job_id, revenue_chart_account_id,
           actor_user_id, action, reason, version, client_request_id, request_fingerprint,
           source_fingerprint, source_snapshot, previous_journal_entry_id, journal_entry_id, reversal_entry_id
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::uuid,$11,$12,$13,$14,$15,$16)`,
        [req.companyId, posting.id, request.operational_source_id, bundle.source.job_id, revenueAccountID,
          req.userId, auditAction, request.reason, posting.version, request.client_request_id,
          request.request_fingerprint, evaluation.source_fingerprint, JSON.stringify(evaluation.source_snapshot),
          previousJournalID, journal?.id || null, reversal?.id || null]
      );
      await client.query("COMMIT");
      res.status(201).json({ replayed: false, ...(await loadDetail(pool, req.companyId, request.operational_source_id)) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendOperationalJournalError(res, error, `operational_receivable_${action}_failed`);
    } finally {
      client.release();
    }
  };

  app.post(`${basePath}/:sourceId/post`, authRequired, requireFinanceAccess, mutate("post"));
  app.post(`${basePath}/:sourceId/void`, authRequired, requireFinanceAccess, mutate("void"));
}
