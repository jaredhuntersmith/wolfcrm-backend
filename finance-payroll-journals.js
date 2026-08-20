import { createHash, randomUUID } from "node:crypto";
import {
  GeneralLedgerError,
  insertJournal,
  journalFingerprint,
  loadJournalEntry,
  reverseJournalLines,
  snapshotInput
} from "./finance-general-ledger.js";
import {
  PayrollEvaluationError,
  loadCurrentPayrollEvaluationPeriod
} from "./finance-payroll-evaluation.js";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_REPORT_DAYS = 731;
const MAX_REPORT_ROWS = 100;

export class FinancePayrollJournalError extends Error {
  constructor(code, message, statusCode = 400, details = {}) {
    super(message);
    this.name = "FinancePayrollJournalError";
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
    throw new FinancePayrollJournalError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return normalized;
}

function exactInteger(value, field, minimum = 0) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value.trim()) ? Number(value.trim()) : value;
  if (!Number.isSafeInteger(parsed) || parsed < minimum) {
    throw new FinancePayrollJournalError(`${field}_invalid`, `${field.replaceAll("_", " ")} must be an exact integer.`);
  }
  return parsed;
}

function storedInteger(value, field) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(parsed)) {
    throw new FinancePayrollJournalError("payroll_journal_amount_inexact", `${field.replaceAll("_", " ")} exceeds the exact supported range.`, 409);
  }
  return parsed;
}

function dateOnly(value, field = "date") {
  const raw = value instanceof Date ? value.toISOString().slice(0, 10) : cleanString(value, 20);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    throw new FinancePayrollJournalError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  const [year, month, day] = raw.split("-").map(Number);
  const parsed = new Date(Date.UTC(year, month - 1, day));
  if (parsed.getUTCFullYear() !== year || parsed.getUTCMonth() !== month - 1 || parsed.getUTCDate() !== day) {
    throw new FinancePayrollJournalError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return raw;
}

function addDays(value, days) {
  const [year, month, day] = value.split("-").map(Number);
  return new Date(Date.UTC(year, month - 1, day + days)).toISOString().slice(0, 10);
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

function blocker(code, message) {
  return { code, message };
}

function summaryObject(value) {
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

function accountSnapshot(account) {
  if (!account) return null;
  return {
    chart_account_id: String(account.id),
    account_type: account.account_type,
    system_key: account.system_key || null,
    active: account.active !== false
  };
}

function sourceSnapshot({ recognition, preview, wagesAccount, burdenAccount, accrualAccount }) {
  const summary = summaryObject(preview?.summary || recognition?.summary);
  return {
    evaluation_period_id: String(recognition.id),
    evaluation_period_version: storedInteger(recognition.version, "evaluation_period_version"),
    start_date: dateOnly(recognition.start_date, "start_date"),
    end_date: dateOnly(recognition.end_date, "end_date"),
    status: recognition.status,
    policy_version: recognition.policy_version || null,
    source_fingerprint: recognition.source_fingerprint || null,
    source_current: recognition.source_current === true,
    preview_fingerprint: preview?.fingerprint || null,
    preview_can_recognize: preview?.can_recognize === true,
    supported_gross_compensation_cents: storedInteger(summary.supported_gross_compensation_cents ?? 0, "supported_gross_compensation_cents"),
    employer_burden_cents: storedInteger(summary.employer_burden_cents ?? 0, "employer_burden_cents"),
    supported_loaded_labor_cents: storedInteger(summary.supported_loaded_labor_cents ?? 0, "supported_loaded_labor_cents"),
    wages_account: accountSnapshot(wagesAccount),
    burden_account: accountSnapshot(burdenAccount),
    accrual_account: accountSnapshot(accrualAccount)
  };
}

export function parsePayrollJournalRange(startValue, endValue) {
  const startDate = dateOnly(startValue, "start_date");
  const endDate = dateOnly(endValue, "end_date");
  if (startDate > endDate) {
    throw new FinancePayrollJournalError("payroll_journal_range_invalid", "Start date must be on or before end date.");
  }
  if (addDays(startDate, MAX_REPORT_DAYS - 1) < endDate) {
    throw new FinancePayrollJournalError("payroll_journal_range_too_large", `Payroll-journal ranges cannot exceed ${MAX_REPORT_DAYS} days.`);
  }
  return { start_date: startDate, end_date: endDate };
}

function boundedLimit(value) {
  if (value === undefined || value === null || value === "") return 50;
  return Math.min(exactInteger(value, "limit", 1), MAX_REPORT_ROWS);
}

function validateSystemAccount(account, systemKey, accountType, blockers) {
  if (!account) {
    blockers.push(blocker(`${systemKey}_missing`, `The system ${systemKey.replaceAll("_", " ")} account is unavailable.`));
    return;
  }
  if (account.active === false || account.system_key !== systemKey || account.account_type !== accountType) {
    blockers.push(blocker(`${systemKey}_invalid`, `The system ${systemKey.replaceAll("_", " ")} account must be active and remain a ${accountType}.`));
  }
}

export function evaluatePayrollJournalSource({
  recognition,
  preview = null,
  wagesAccount = null,
  burdenAccount = null,
  accrualAccount = null,
  posting = null
}) {
  if (!recognition) {
    throw new FinancePayrollJournalError("payroll_evaluation_period_not_found", "The supported-payroll period was not found.", 404);
  }
  const blockers = [];
  const snapshot = sourceSnapshot({ recognition, preview, wagesAccount, burdenAccount, accrualAccount });
  const gross = snapshot.supported_gross_compensation_cents;
  const burden = snapshot.employer_burden_cents;
  const loaded = snapshot.supported_loaded_labor_cents;
  const expectedLoaded = gross + burden;

  if (recognition.status !== "recognized") blockers.push(blocker("payroll_recognition_not_active", "The supported-payroll period is not currently recognized."));
  if (recognition.source_current !== true) blockers.push(blocker("payroll_recognition_stale", "The supported-payroll recognition no longer matches current reviewed evidence."));
  if (!preview || preview.can_recognize !== true) blockers.push(blocker("payroll_preview_blocked", "The current supported-payroll preview is blocked."));
  if (preview && recognition.source_fingerprint !== preview.fingerprint) blockers.push(blocker("payroll_fingerprint_changed", "The supported-payroll evidence fingerprint changed."));
  if (preview && recognition.policy_version !== preview.policy_version) blockers.push(blocker("payroll_policy_changed", "The supported-payroll policy version changed."));
  if (gross < 0 || burden < 0 || loaded < 0) blockers.push(blocker("payroll_amount_negative", "Supported payroll contains a negative journal total."));
  if (!Number.isSafeInteger(expectedLoaded)) blockers.push(blocker("payroll_amount_overflow", "Supported payroll exceeds the exact journal range."));
  else if (expectedLoaded !== loaded) blockers.push(blocker("payroll_amount_unreconciled", "Supported gross plus employer burden does not equal supported loaded labor."));
  if (loaded <= 0) blockers.push(blocker("payroll_amount_zero", "A payroll accrual journal needs a positive supported loaded-labor total."));

  validateSystemAccount(wagesAccount, "payroll_wages_expense", "expense", blockers);
  validateSystemAccount(burdenAccount, "payroll_burden_expense", "expense", blockers);
  validateSystemAccount(accrualAccount, "payroll_accrual_clearing", "liability", blockers);

  const sourceFingerprint = fingerprint(snapshot);
  const sourceCurrent = posting?.status === "posted"
    && posting.source_fingerprint === sourceFingerprint
    && String(posting.wages_chart_account_id || "") === String(wagesAccount?.id || "")
    && String(posting.burden_chart_account_id || "") === String(burdenAccount?.id || "")
    && String(posting.accrual_chart_account_id || "") === String(accrualAccount?.id || "");
  let reviewState = "blocked";
  if (sourceCurrent) reviewState = "posted";
  else if (posting?.status === "posted") reviewState = "stale";
  else if (posting?.status === "voided") reviewState = "voided";
  else if (blockers.length === 0) reviewState = "ready";

  const lines = [];
  if (blockers.length === 0) {
    if (gross > 0) lines.push({
      position: lines.length,
      chart_account_id: String(wagesAccount.id),
      debit_cents: gross,
      credit_cents: 0,
      memo: "Supported gross compensation"
    });
    if (burden > 0) lines.push({
      position: lines.length,
      chart_account_id: String(burdenAccount.id),
      debit_cents: burden,
      credit_cents: 0,
      memo: "Configured employer payroll burden"
    });
    lines.push({
      position: lines.length,
      chart_account_id: String(accrualAccount.id),
      debit_cents: 0,
      credit_cents: loaded,
      memo: "Supported payroll accrual clearing"
    });
  }

  return {
    eligible: blockers.length === 0,
    blockers: [...new Map(blockers.map((item) => [item.code, item])).values()],
    review_state: reviewState,
    source_current: sourceCurrent,
    can_post: blockers.length === 0 && !sourceCurrent,
    can_void: posting?.status === "posted" && Boolean(posting.journal_entry_id),
    source_fingerprint: sourceFingerprint,
    source_snapshot: snapshot,
    journal_preview: blockers.length === 0 ? {
      entry_date: snapshot.end_date,
      total_debits_cents: loaded,
      total_credits_cents: loaded,
      lines
    } : null
  };
}

export function normalizePayrollJournalActionRequest({ body = {}, evaluationPeriodID, action }) {
  const normalizedAction = cleanString(action, 20).toLowerCase();
  if (!new Set(["post", "void"]).has(normalizedAction)) {
    throw new FinancePayrollJournalError("payroll_journal_action_invalid", "Choose a valid payroll-journal action.");
  }
  const input = {
    client_request_id: uuid(body.client_request_id, "client_request_id"),
    evaluation_period_id: uuid(evaluationPeriodID, "evaluation_period_id"),
    action: normalizedAction,
    expected_evaluation_version: exactInteger(body.expected_evaluation_version, "expected_evaluation_version", 1),
    expected_posting_version: exactInteger(body.expected_posting_version, "expected_posting_version"),
    reason: cleanString(body.reason, 500)
  };
  if (!input.reason) throw new FinancePayrollJournalError("payroll_journal_reason_required", "An audit reason is required.");
  return { ...input, request_fingerprint: fingerprint(input) };
}

export function buildPayrollJournalInput({ evaluation, evaluationPeriodID, evaluationVersion, clientRequestID, reason }) {
  if (!evaluation?.eligible || !evaluation.journal_preview) {
    throw new FinancePayrollJournalError("payroll_journal_source_blocked", "Resolve every supported-payroll blocker before posting.", 409, { blockers: evaluation?.blockers || [] });
  }
  const input = {
    client_request_id: uuid(clientRequestID, "client_request_id"),
    entry_date: evaluation.journal_preview.entry_date,
    entry_kind: "payroll_recognition",
    description: `Supported payroll accrual · ${evaluation.journal_preview.entry_date}`,
    reference: `PAY-${String(evaluationPeriodID).slice(0, 12).toUpperCase()}`,
    reason: cleanString(reason, 500),
    reversal_of_entry_id: null,
    source_type: "finance_payroll_evaluation",
    source_id: uuid(evaluationPeriodID, "evaluation_period_id"),
    source_version: exactInteger(evaluationVersion, "evaluation_version", 1),
    lines: evaluation.journal_preview.lines,
    total_debits_cents: evaluation.journal_preview.total_debits_cents,
    total_credits_cents: evaluation.journal_preview.total_credits_cents
  };
  return { ...input, request_fingerprint: journalFingerprint(input) };
}

export function buildPayrollJournalReversalInput({ original, originalLines, evaluationPeriodID, evaluationVersion, clientRequestID, reason }) {
  if (!original || original.source_type !== "finance_payroll_evaluation" || String(original.source_id) !== String(evaluationPeriodID) || original.reversal_of_entry_id) {
    throw new FinancePayrollJournalError("payroll_journal_relationship_invalid", "The current payroll journal relationship is invalid.", 409);
  }
  const reversed = reverseJournalLines(originalLines);
  const input = {
    client_request_id: uuid(clientRequestID, "client_request_id"),
    entry_date: dateOnly(original.entry_date, "entry_date"),
    entry_kind: "reversal",
    description: `Reversal — ${cleanString(original.description, 180) || "Supported payroll accrual"}`,
    reference: cleanString(original.reference, 120) || null,
    reason: cleanString(reason, 500),
    reversal_of_entry_id: String(original.id),
    source_type: "finance_payroll_evaluation",
    source_id: uuid(evaluationPeriodID, "evaluation_period_id"),
    source_version: exactInteger(evaluationVersion, "evaluation_version", 1),
    lines: reversed.lines,
    total_debits_cents: reversed.total_debits_cents,
    total_credits_cents: reversed.total_credits_cents
  };
  return { ...input, request_fingerprint: journalFingerprint(input) };
}

export async function installFinancePayrollJournalSchema(pool) {
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS finance_payroll_evaluation_periods_company_id_idx
      ON finance_payroll_evaluation_periods(company_id, id);

    CREATE TABLE IF NOT EXISTS finance_payroll_journal_postings (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      evaluation_period_id UUID NOT NULL,
      wages_chart_account_id UUID NOT NULL,
      burden_chart_account_id UUID NOT NULL,
      accrual_chart_account_id UUID NOT NULL,
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
      UNIQUE(company_id, evaluation_period_id),
      FOREIGN KEY (company_id, evaluation_period_id) REFERENCES finance_payroll_evaluation_periods(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, wages_chart_account_id) REFERENCES finance_chart_accounts(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, burden_chart_account_id) REFERENCES finance_chart_accounts(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, accrual_chart_account_id) REFERENCES finance_chart_accounts(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, journal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT,
      CHECK ((status = 'posted' AND journal_entry_id IS NOT NULL) OR (status = 'voided' AND journal_entry_id IS NULL)),
      CHECK (wages_chart_account_id <> burden_chart_account_id AND wages_chart_account_id <> accrual_chart_account_id AND burden_chart_account_id <> accrual_chart_account_id)
    );
    CREATE INDEX IF NOT EXISTS finance_payroll_journal_postings_company_status_idx
      ON finance_payroll_journal_postings(company_id, status, updated_at DESC);

    CREATE TABLE IF NOT EXISTS finance_payroll_journal_posting_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      posting_id UUID NOT NULL,
      evaluation_period_id UUID NOT NULL,
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
      FOREIGN KEY (company_id, posting_id) REFERENCES finance_payroll_journal_postings(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, evaluation_period_id) REFERENCES finance_payroll_evaluation_periods(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, previous_journal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, journal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, reversal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT
    );
    CREATE INDEX IF NOT EXISTS finance_payroll_journal_posting_audit_company_period_idx
      ON finance_payroll_journal_posting_audit(company_id, evaluation_period_id, created_at DESC);
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

function postingPayload(row) {
  if (!row) return null;
  return {
    id: String(row.id),
    status: row.status,
    version: Number(row.version),
    journal_entry_id: row.journal_entry_id || null,
    source_fingerprint: row.source_fingerprint,
    reason: row.reason,
    updated_by: row.updated_by || null,
    updated_at: row.updated_at || null
  };
}

async function loadSystemAccounts(poolOrClient, companyID, { lock = false } = {}) {
  const { rows } = await poolOrClient.query(
    `SELECT id, code, name, account_type, system_key, active FROM finance_chart_accounts
      WHERE company_id=$1 AND system_key=ANY($2::text[])${lock ? " FOR SHARE" : ""}`,
    [companyID, ["payroll_wages_expense", "payroll_burden_expense", "payroll_accrual_clearing"]]
  );
  const accounts = new Map(rows.map((row) => [row.system_key, row]));
  return {
    wagesAccount: accounts.get("payroll_wages_expense") || null,
    burdenAccount: accounts.get("payroll_burden_expense") || null,
    accrualAccount: accounts.get("payroll_accrual_clearing") || null
  };
}

async function loadPosting(poolOrClient, companyID, periodID, { lock = false } = {}) {
  const { rows } = await poolOrClient.query(
    `SELECT * FROM finance_payroll_journal_postings
      WHERE company_id=$1 AND evaluation_period_id=$2::uuid${lock ? " FOR UPDATE" : ""}`,
    [companyID, periodID]
  );
  return rows[0] || null;
}

async function loadAudit(poolOrClient, companyID, periodID) {
  const { rows } = await poolOrClient.query(
    `SELECT id, action, reason, version, actor_user_id, previous_journal_entry_id,
            journal_entry_id, reversal_entry_id, created_at
       FROM finance_payroll_journal_posting_audit
      WHERE company_id=$1 AND evaluation_period_id=$2::uuid
      ORDER BY created_at DESC, id DESC LIMIT 50`,
    [companyID, periodID]
  );
  return rows.map((row) => ({
    id: String(row.id),
    action: row.action,
    reason: row.reason,
    version: Number(row.version),
    actor_user_id: row.actor_user_id || null,
    previous_journal_entry_id: row.previous_journal_entry_id || null,
    journal_entry_id: row.journal_entry_id || null,
    reversal_entry_id: row.reversal_entry_id || null,
    created_at: row.created_at || null
  }));
}

async function loadDetail(poolOrClient, companyID, periodID) {
  const report = await loadCurrentPayrollEvaluationPeriod(poolOrClient, companyID, periodID);
  const [posting, accounts, audit] = await Promise.all([
    loadPosting(poolOrClient, companyID, periodID),
    loadSystemAccounts(poolOrClient, companyID),
    loadAudit(poolOrClient, companyID, periodID)
  ]);
  const evaluation = evaluatePayrollJournalSource({
    recognition: report.recognition,
    preview: report.preview,
    posting,
    ...accounts
  });
  const journal = posting?.journal_entry_id
    ? await loadJournalEntry(poolOrClient, companyID, posting.journal_entry_id, 20)
    : null;
  return {
    basis: "reviewed_supported_payroll_accrual",
    currency: "usd",
    source: {
      evaluation_period_id: String(report.recognition.id),
      start_date: report.start_date,
      end_date: report.end_date,
      evaluation_version: Number(report.recognition.version),
      recognition_status: report.recognition.status,
      recognition_source_current: report.recognition.source_current === true,
      summary: report.preview.summary,
      posting: postingPayload(posting),
      wages_account: chartPayload(accounts.wagesAccount),
      burden_account: chartPayload(accounts.burdenAccount),
      accrual_account: chartPayload(accounts.accrualAccount),
      ...evaluation
    },
    journal,
    audit,
    warnings: [
      "This journal recognizes supported gross compensation and configured employer burden into Payroll Accrual Clearing only.",
      "It does not calculate withholding, employee deductions, net pay, tax liabilities, a paycheck, a payroll-provider run, or cash settlement.",
      "Payroll Accrual Clearing remains a liability until a later workflow has exact provider and bank settlement identity."
    ]
  };
}

async function loadReport(poolOrClient, companyID, range, limit) {
  const [countResult, rowResult] = await Promise.all([
    poolOrClient.query(
      `SELECT COUNT(*)::int AS count FROM finance_payroll_evaluation_periods
        WHERE company_id=$1 AND end_date BETWEEN $2::date AND $3::date`,
      [companyID, range.start_date, range.end_date]
    ),
    poolOrClient.query(
      `SELECT period.id, period.start_date, period.end_date, period.status AS recognition_status,
              period.version AS evaluation_version, period.summary, period.updated_at AS recognition_updated_at,
              posting.id AS posting_id, posting.status AS posting_status, posting.version AS posting_version,
              posting.journal_entry_id, posting.reason AS posting_reason, posting.updated_at AS posting_updated_at
         FROM finance_payroll_evaluation_periods period
         LEFT JOIN finance_payroll_journal_postings posting
           ON posting.company_id=period.company_id AND posting.evaluation_period_id=period.id
        WHERE period.company_id=$1 AND period.end_date BETWEEN $2::date AND $3::date
        ORDER BY period.end_date DESC, period.start_date DESC, period.id
        LIMIT $4`,
      [companyID, range.start_date, range.end_date, limit]
    )
  ]);
  const sources = rowResult.rows.map((row) => {
    const summary = summaryObject(row.summary);
    return {
      evaluation_period_id: String(row.id),
      start_date: dateOnly(row.start_date, "start_date"),
      end_date: dateOnly(row.end_date, "end_date"),
      evaluation_version: Number(row.evaluation_version),
      recognition_status: row.recognition_status,
      supported_gross_compensation_cents: storedInteger(summary.supported_gross_compensation_cents ?? 0, "supported_gross_compensation_cents"),
      employer_burden_cents: storedInteger(summary.employer_burden_cents ?? 0, "employer_burden_cents"),
      supported_loaded_labor_cents: storedInteger(summary.supported_loaded_labor_cents ?? 0, "supported_loaded_labor_cents"),
      posting: row.posting_id ? {
        id: String(row.posting_id),
        status: row.posting_status,
        version: Number(row.posting_version),
        journal_entry_id: row.journal_entry_id || null,
        reason: row.posting_reason,
        updated_at: row.posting_updated_at || null
      } : null,
      review_state: row.posting_status === "posted" ? "posted_unverified" : row.posting_status === "voided" ? "voided" : row.recognition_status === "recognized" ? "review_required" : "blocked",
      live_review_required: true,
      recognition_updated_at: row.recognition_updated_at || null
    };
  });
  const total = Number(countResult.rows[0]?.count || 0);
  return {
    basis: "reviewed_supported_payroll_accrual",
    currency: "usd",
    start_date: range.start_date,
    end_date: range.end_date,
    total_count: total,
    returned_count: sources.length,
    truncated: total > sources.length,
    warnings: [
      "Open a period for a live source-fingerprint review before relying on its posting status or taking action.",
      "Payroll accrual journals never calculate withholding, net pay, a payroll-provider run, or bank settlement."
    ],
    sources
  };
}

async function replayedRequest(client, companyID, request) {
  const { rows } = await client.query(
    `SELECT request_fingerprint FROM finance_payroll_journal_posting_audit
      WHERE company_id=$1 AND client_request_id=$2::uuid FOR SHARE`,
    [companyID, request.client_request_id]
  );
  if (!rows.length) return false;
  if (rows[0].request_fingerprint !== request.request_fingerprint) {
    throw new FinancePayrollJournalError("payroll_journal_request_id_conflict", "That payroll-journal request ID was already used with different content.", 409);
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

function sendPayrollJournalError(res, error, fallback) {
  if (error instanceof FinancePayrollJournalError || error instanceof PayrollEvaluationError || error instanceof GeneralLedgerError || error?.statusCode) {
    return res.status(error.statusCode || 400).json({
      error: error.code || fallback,
      message: error.message,
      blockers: error.blockers,
      current_evaluation_version: error.current_evaluation_version,
      current_posting_version: error.current_posting_version
    });
  }
  if (error?.code === "23505") {
    return res.status(409).json({ error: "payroll_journal_conflict", message: "That payroll-journal action already exists." });
  }
  console.error("[finance-payroll-journals]", fallback, { code: error?.code, message: error?.message });
  return res.status(500).json({ error: fallback, message: "Payroll-journal request failed." });
}

export function installFinancePayrollJournalRoutes({ app, pool, authRequired, requireFinanceAccess, ensureChartAccounts }) {
  const basePath = "/api/finance/accounting/payroll-journals";

  app.get(basePath, authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Payroll journals require a company workspace." });
    try {
      const companyResult = await pool.query(
        `SELECT COALESCE(NULLIF(timezone, ''), 'America/New_York') AS timezone,
                (now() AT TIME ZONE COALESCE(NULLIF(timezone, ''), 'America/New_York'))::date::text AS company_today
           FROM companies WHERE id=$1`,
        [req.companyId]
      );
      if (!companyResult.rows.length) throw new FinancePayrollJournalError("company_not_found", "Company workspace was not found.", 404);
      const end = req.query.end_date || companyResult.rows[0].company_today;
      const start = req.query.start_date || `${end.slice(0, 7)}-01`;
      const range = parsePayrollJournalRange(start, end);
      await ensureChartAccounts(pool, req.companyId, req.userId);
      res.json({ timezone: companyResult.rows[0].timezone, company_today: companyResult.rows[0].company_today, ...(await loadReport(pool, req.companyId, range, boundedLimit(req.query.limit))) });
    } catch (error) {
      sendPayrollJournalError(res, error, "payroll_journal_report_failed");
    }
  });

  app.get(`${basePath}/:periodId`, authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Payroll journals require a company workspace." });
    try {
      await ensureChartAccounts(pool, req.companyId, req.userId);
      res.json(await loadDetail(pool, req.companyId, uuid(req.params.periodId, "evaluation_period_id")));
    } catch (error) {
      sendPayrollJournalError(res, error, "payroll_journal_detail_failed");
    }
  });

  const mutate = (action) => async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Payroll journals require a company workspace." });
    const client = await pool.connect();
    try {
      const request = normalizePayrollJournalActionRequest({ body: req.body, evaluationPeriodID: req.params.periodId, action });
      await client.query("BEGIN");
      await client.query(`SELECT pg_advisory_xact_lock(hashtext($1::text))`, [`${req.companyId}|supported-payroll`]);
      await client.query(`SELECT id FROM companies WHERE id=$1 FOR UPDATE`, [req.companyId]);
      await ensureChartAccounts(client, req.companyId, req.userId);
      if (await replayedRequest(client, req.companyId, request)) {
        await client.query("COMMIT");
        return res.json({ replayed: true, ...(await loadDetail(pool, req.companyId, request.evaluation_period_id)) });
      }

      const recognitionResult = await client.query(
        `SELECT * FROM finance_payroll_evaluation_periods WHERE company_id=$1 AND id=$2::uuid FOR UPDATE`,
        [req.companyId, request.evaluation_period_id]
      );
      const recognitionRow = recognitionResult.rows[0];
      if (!recognitionRow) throw new FinancePayrollJournalError("payroll_evaluation_period_not_found", "The supported-payroll period was not found.", 404);
      const posting = await loadPosting(client, req.companyId, request.evaluation_period_id, { lock: true });
      const accounts = await loadSystemAccounts(client, req.companyId, { lock: true });
      const evaluationVersion = Number(recognitionRow.version || 0);
      const postingVersion = Number(posting?.version || 0);
      if (request.expected_evaluation_version !== evaluationVersion) {
        throw new FinancePayrollJournalError("payroll_journal_source_stale", "Supported payroll changed after it was loaded.", 409, { current_evaluation_version: evaluationVersion });
      }
      if (request.expected_posting_version !== postingVersion) {
        throw new FinancePayrollJournalError("payroll_journal_posting_stale", "The payroll journal changed after it was loaded.", 409, { current_posting_version: postingVersion });
      }

      let evaluation = null;
      if (action === "post") {
        const report = await loadCurrentPayrollEvaluationPeriod(client, req.companyId, request.evaluation_period_id, { lock: true });
        evaluation = evaluatePayrollJournalSource({ recognition: report.recognition, preview: report.preview, posting, ...accounts });
        if (!evaluation.eligible) {
          throw new FinancePayrollJournalError("payroll_journal_source_blocked", "Resolve every supported-payroll blocker before posting.", 409, { blockers: evaluation.blockers });
        }
        if (evaluation.source_current) {
          await client.query(
            `INSERT INTO finance_payroll_journal_posting_audit (
               company_id, posting_id, evaluation_period_id, actor_user_id, action, reason, version,
               client_request_id, request_fingerprint, source_fingerprint, source_snapshot,
               previous_journal_entry_id, journal_entry_id, reversal_entry_id
             ) VALUES ($1,$2,$3,$4,'source_reviewed',$5,$6,$7::uuid,$8,$9,$10,$11,$11,NULL)`,
            [req.companyId, posting.id, request.evaluation_period_id, req.userId, request.reason,
              posting.version, request.client_request_id, request.request_fingerprint,
              evaluation.source_fingerprint, JSON.stringify(evaluation.source_snapshot), posting.journal_entry_id]
          );
          await client.query("COMMIT");
          return res.json({ replayed: false, ...(await loadDetail(pool, req.companyId, request.evaluation_period_id)) });
        }
      } else if (!posting || posting.status !== "posted" || !posting.journal_entry_id) {
        throw new FinancePayrollJournalError("payroll_journal_not_posted", "Only a currently posted payroll accrual can be voided.", 409);
      }

      const previousJournalID = posting?.status === "posted" ? posting.journal_entry_id : null;
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
        if (existingReversal.rows.length) throw new FinancePayrollJournalError("payroll_journal_already_reversed", "The current payroll journal already has a reversal.", 409);
        const reversalInput = buildPayrollJournalReversalInput({
          original,
          originalLines: lineResult.rows,
          evaluationPeriodID: request.evaluation_period_id,
          evaluationVersion: Number(original.source_version),
          clientRequestID: action === "void" ? request.client_request_id : randomUUID(),
          reason: request.reason
        });
        reversal = await insertJournal(client, req.companyId, req.userId, reversalInput);
        await insertLedgerAudit(client, req.companyId, req.userId, reversal, original.id, "payroll_accrual_reversal_posted", request.reason, reversalInput);
        await insertLedgerAudit(client, req.companyId, req.userId, original, reversal.id, "payroll_accrual_reversed", request.reason, reversalInput);
      }

      let journal = null;
      if (action === "post") {
        const journalInput = buildPayrollJournalInput({
          evaluation,
          evaluationPeriodID: request.evaluation_period_id,
          evaluationVersion,
          clientRequestID: request.client_request_id,
          reason: request.reason
        });
        journal = await insertJournal(client, req.companyId, req.userId, journalInput);
        await insertLedgerAudit(client, req.companyId, req.userId, journal, reversal?.id || null, "payroll_accrual_posted", request.reason, journalInput);
      }

      const nextVersion = postingVersion + 1;
      const retainedFingerprint = action === "post" ? evaluation.source_fingerprint : posting.source_fingerprint;
      const retainedSnapshot = action === "post" ? evaluation.source_snapshot : posting.source_snapshot;
      const wagesAccountID = action === "post" ? accounts.wagesAccount.id : posting.wages_chart_account_id;
      const burdenAccountID = action === "post" ? accounts.burdenAccount.id : posting.burden_chart_account_id;
      const accrualAccountID = action === "post" ? accounts.accrualAccount.id : posting.accrual_chart_account_id;
      let currentPosting;
      if (!posting) {
        currentPosting = (await client.query(
          `INSERT INTO finance_payroll_journal_postings (
             company_id, evaluation_period_id, wages_chart_account_id, burden_chart_account_id,
             accrual_chart_account_id, journal_entry_id, status, version, source_fingerprint,
             source_snapshot, reason, updated_by
           ) VALUES ($1,$2,$3,$4,$5,$6,'posted',1,$7,$8,$9,$10) RETURNING *`,
          [req.companyId, request.evaluation_period_id, wagesAccountID, burdenAccountID,
            accrualAccountID, journal.id, retainedFingerprint, JSON.stringify(retainedSnapshot), request.reason, req.userId]
        )).rows[0];
      } else {
        currentPosting = (await client.query(
          `UPDATE finance_payroll_journal_postings
              SET wages_chart_account_id=$3, burden_chart_account_id=$4, accrual_chart_account_id=$5,
                  journal_entry_id=$6, status=$7, version=version+1, source_fingerprint=$8,
                  source_snapshot=$9, reason=$10, updated_by=$11, updated_at=now()
            WHERE company_id=$1 AND evaluation_period_id=$2 RETURNING *`,
          [req.companyId, request.evaluation_period_id, wagesAccountID, burdenAccountID,
            accrualAccountID, journal?.id || null, action === "post" ? "posted" : "voided",
            retainedFingerprint, JSON.stringify(retainedSnapshot), request.reason, req.userId]
        )).rows[0];
      }
      const auditAction = action === "void" ? "source_voided" : previousJournalID ? "source_replaced" : "source_posted";
      await client.query(
        `INSERT INTO finance_payroll_journal_posting_audit (
           company_id, posting_id, evaluation_period_id, actor_user_id, action, reason, version,
           client_request_id, request_fingerprint, source_fingerprint, source_snapshot,
           previous_journal_entry_id, journal_entry_id, reversal_entry_id
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::uuid,$9,$10,$11,$12,$13,$14)`,
        [req.companyId, currentPosting.id, request.evaluation_period_id, req.userId, auditAction,
          request.reason, nextVersion, request.client_request_id, request.request_fingerprint,
          retainedFingerprint, JSON.stringify(retainedSnapshot), previousJournalID,
          journal?.id || null, reversal?.id || null]
      );
      await client.query("COMMIT");
      res.status(201).json({ replayed: false, ...(await loadDetail(pool, req.companyId, request.evaluation_period_id)) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendPayrollJournalError(res, error, `payroll_journal_${action}_failed`);
    } finally {
      client.release();
    }
  };

  app.post(`${basePath}/:periodId/post`, authRequired, requireFinanceAccess, mutate("post"));
  app.post(`${basePath}/:periodId/void`, authRequired, requireFinanceAccess, mutate("void"));
}
