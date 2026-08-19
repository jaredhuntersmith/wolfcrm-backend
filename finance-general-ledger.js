import { createHash } from "node:crypto";

const JOURNAL_KINDS = new Set(["opening_balance", "adjustment", "transfer", "owner_equity", "reclassification"]);
const MAX_JOURNAL_LINES = 50;
const MAX_REPORT_DAYS = 731;
const MAX_REPORT_ENTRIES = 200;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export class GeneralLedgerError extends Error {
  constructor(code, message, statusCode = 400, details = {}) {
    super(message);
    this.name = "GeneralLedgerError";
    this.code = code;
    this.statusCode = statusCode;
    Object.assign(this, details);
  }
}

function cleanString(value, maxLength = 200) {
  return (value ?? "").toString().trim().slice(0, maxLength);
}

function exactInteger(value, field, { minimum = Number.MIN_SAFE_INTEGER, maximum = Number.MAX_SAFE_INTEGER } = {}) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value.trim()) ? Number(value.trim()) : value;
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new GeneralLedgerError(`${field}_invalid`, `${field.replaceAll("_", " ")} must be exact cents.`);
  }
  return parsed;
}

function storedInteger(value, field) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(parsed)) {
    throw new GeneralLedgerError("general_ledger_amount_inexact", `${field.replaceAll("_", " ")} exceeds the exact supported range.`, 409);
  }
  return parsed;
}

function addExact(left, right, field) {
  const next = left + right;
  if (!Number.isSafeInteger(next)) {
    throw new GeneralLedgerError("general_ledger_amount_inexact", `${field.replaceAll("_", " ")} exceeds the exact supported range.`, 409);
  }
  return next;
}

function dateOnly(value, field = "date") {
  const raw = value instanceof Date ? value.toISOString().slice(0, 10) : cleanString(value, 20);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    throw new GeneralLedgerError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  const [year, month, day] = raw.split("-").map(Number);
  const parsed = new Date(Date.UTC(year, month - 1, day));
  if (parsed.getUTCFullYear() !== year || parsed.getUTCMonth() !== month - 1 || parsed.getUTCDate() !== day) {
    throw new GeneralLedgerError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return raw;
}

function addDays(value, days) {
  const [year, month, day] = value.split("-").map(Number);
  return new Date(Date.UTC(year, month - 1, day + days)).toISOString().slice(0, 10);
}

function requestID(value) {
  const raw = cleanString(value, 64).toLowerCase();
  if (!UUID_PATTERN.test(raw)) {
    throw new GeneralLedgerError("journal_request_id_invalid", "A valid journal request ID is required.");
  }
  return raw;
}

function journalEntryID(value) {
  const raw = cleanString(value, 64).toLowerCase();
  if (!UUID_PATTERN.test(raw)) {
    throw new GeneralLedgerError("journal_entry_id_invalid", "Journal entry ID is invalid.");
  }
  return raw;
}

function boundedLimit(value, fallback = 100) {
  if (value === undefined || value === null || value === "") return fallback;
  const parsed = typeof value === "string" && /^\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new GeneralLedgerError("general_ledger_limit_invalid", "General Ledger limit is invalid.");
  }
  return Math.min(parsed, MAX_REPORT_ENTRIES);
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
  }
  return value;
}

export function journalFingerprint(input) {
  return createHash("sha256").update(JSON.stringify(stableValue(input))).digest("hex");
}

export function parseGeneralLedgerRange(startValue, endValue) {
  const startDate = dateOnly(startValue, "start_date");
  const endDate = dateOnly(endValue, "end_date");
  if (startDate > endDate) throw new GeneralLedgerError("general_ledger_range_invalid", "Start date must be on or before end date.");
  if (addDays(startDate, MAX_REPORT_DAYS - 1) < endDate) {
    throw new GeneralLedgerError("general_ledger_range_too_large", `General Ledger ranges cannot exceed ${MAX_REPORT_DAYS} days.`);
  }
  return { start_date: startDate, end_date: endDate };
}

function normalizedLines(rawLines, chartAccounts, allowInactiveAccounts = false) {
  if (!Array.isArray(rawLines) || rawLines.length < 2) {
    throw new GeneralLedgerError("journal_lines_too_few", "A journal needs at least two account lines.");
  }
  if (rawLines.length > MAX_JOURNAL_LINES) {
    throw new GeneralLedgerError("journal_lines_too_many", `A journal can have at most ${MAX_JOURNAL_LINES} account lines.`);
  }
  const chartByID = new Map(chartAccounts.map((account) => [String(account.id), account]));
  const seen = new Set();
  let totalDebits = 0;
  let totalCredits = 0;
  const lines = rawLines.map((raw, position) => {
    const chartAccountID = cleanString(raw?.chart_account_id, 80);
    const account = chartByID.get(chartAccountID);
    if (!account || (!allowInactiveAccounts && account.active === false)) {
      throw new GeneralLedgerError("journal_chart_account_not_found", `Journal line ${position + 1} uses an unavailable chart account.`, 404);
    }
    if (seen.has(chartAccountID)) {
      throw new GeneralLedgerError("journal_chart_account_duplicate", "Use each chart account only once in a journal.");
    }
    seen.add(chartAccountID);
    const debitCents = exactInteger(raw?.debit_cents ?? 0, "debit_cents", { minimum: 0 });
    const creditCents = exactInteger(raw?.credit_cents ?? 0, "credit_cents", { minimum: 0 });
    if ((debitCents > 0) === (creditCents > 0)) {
      throw new GeneralLedgerError("journal_line_side_invalid", `Journal line ${position + 1} must have either a debit or a credit, not both.`);
    }
    totalDebits = addExact(totalDebits, debitCents, "total_debits_cents");
    totalCredits = addExact(totalCredits, creditCents, "total_credits_cents");
    return {
      position,
      chart_account_id: chartAccountID,
      account_type: account.account_type,
      debit_cents: debitCents,
      credit_cents: creditCents,
      memo: cleanString(raw?.memo, 500) || null
    };
  });
  if (totalDebits <= 0 || totalDebits !== totalCredits) {
    throw new GeneralLedgerError("journal_unbalanced", "Journal debits and credits must be equal and greater than zero.", 400, {
      total_debits_cents: totalDebits,
      total_credits_cents: totalCredits,
      difference_cents: totalDebits - totalCredits
    });
  }
  return { lines, total_debits_cents: totalDebits, total_credits_cents: totalCredits };
}

function validateKindRules(entryKind, lines) {
  const accountTypes = new Set(lines.map((line) => line.account_type));
  if (entryKind === "opening_balance" && [...accountTypes].some((type) => type === "income" || type === "expense")) {
    throw new GeneralLedgerError("journal_opening_account_type_invalid", "Opening balances can use only asset, liability, and equity accounts.");
  }
  if (entryKind === "transfer" && [...accountTypes].some((type) => type !== "asset" && type !== "liability")) {
    throw new GeneralLedgerError("journal_transfer_account_type_invalid", "Transfers can use only asset and liability accounts.");
  }
  if (entryKind === "owner_equity" && !accountTypes.has("equity")) {
    throw new GeneralLedgerError("journal_owner_equity_account_required", "Owner equity journals need at least one equity account.");
  }
}

export function normalizeManualJournal({ body = {}, chartAccounts = [], companyToday, allowInactiveAccounts = false }) {
  const clientRequestID = requestID(body.client_request_id);
  const entryDate = dateOnly(body.entry_date, "entry_date");
  const today = dateOnly(companyToday, "company_today");
  if (entryDate > today) throw new GeneralLedgerError("journal_future_date", "Journal entries cannot be dated in the future.");
  const entryKind = cleanString(body.entry_kind, 40).toLowerCase();
  if (!JOURNAL_KINDS.has(entryKind)) throw new GeneralLedgerError("journal_kind_invalid", "Choose a valid journal type.");
  const description = cleanString(body.description, 200);
  if (!description) throw new GeneralLedgerError("journal_description_required", "Journal description is required.");
  const reason = cleanString(body.reason, 500);
  if (!reason) throw new GeneralLedgerError("journal_reason_required", "An audit reason is required.");
  const normalized = normalizedLines(body.lines, chartAccounts, allowInactiveAccounts);
  validateKindRules(entryKind, normalized.lines);
  const input = {
    client_request_id: clientRequestID,
    entry_date: entryDate,
    entry_kind: entryKind,
    description,
    reference: cleanString(body.reference, 120) || null,
    reason,
    source_type: "manual",
    source_id: null,
    source_version: null,
    lines: normalized.lines.map(({ account_type: _accountType, ...line }) => line),
    total_debits_cents: normalized.total_debits_cents,
    total_credits_cents: normalized.total_credits_cents
  };
  return { ...input, request_fingerprint: journalFingerprint(input) };
}

export function reverseJournalLines(lines = []) {
  if (!Array.isArray(lines) || lines.length < 2 || lines.length > MAX_JOURNAL_LINES) {
    throw new GeneralLedgerError("journal_reversal_source_invalid", "The original journal does not have a valid line set.", 409);
  }
  let totalDebits = 0;
  let totalCredits = 0;
  const reversed = lines.map((line, position) => {
    const debit = storedInteger(line.debit_cents, "debit_cents");
    const credit = storedInteger(line.credit_cents, "credit_cents");
    if ((debit > 0) === (credit > 0)) {
      throw new GeneralLedgerError("journal_reversal_source_invalid", "The original journal contains an invalid line.", 409);
    }
    totalDebits = addExact(totalDebits, credit, "total_debits_cents");
    totalCredits = addExact(totalCredits, debit, "total_credits_cents");
    return {
      position,
      chart_account_id: String(line.chart_account_id),
      debit_cents: credit,
      credit_cents: debit,
      memo: cleanString(line.memo, 500) || null
    };
  });
  if (totalDebits <= 0 || totalDebits !== totalCredits) {
    throw new GeneralLedgerError("journal_reversal_source_unbalanced", "The original journal is not balanced and cannot be reversed.", 409);
  }
  return { lines: reversed, total_debits_cents: totalDebits, total_credits_cents: totalCredits };
}

export function normalizeJournalReversal({ body = {}, original, originalLines = [], companyToday }) {
  if (!original) throw new GeneralLedgerError("journal_entry_not_found", "Journal entry was not found.", 404);
  if (original.reversal_of_entry_id) {
    throw new GeneralLedgerError("journal_reversal_of_reversal", "A reversal cannot be reversed automatically. Post an explicit correcting journal instead.", 409);
  }
  const clientRequestID = requestID(body.client_request_id);
  const entryDate = dateOnly(body.entry_date, "entry_date");
  const originalDate = dateOnly(original.entry_date, "original_entry_date");
  const today = dateOnly(companyToday, "company_today");
  if (entryDate < originalDate) throw new GeneralLedgerError("journal_reversal_date_before_original", "A reversal cannot be dated before its original journal.");
  if (entryDate > today) throw new GeneralLedgerError("journal_future_date", "Journal entries cannot be dated in the future.");
  const reason = cleanString(body.reason, 500);
  if (!reason) throw new GeneralLedgerError("journal_reason_required", "An audit reason is required.");
  const reversed = reverseJournalLines(originalLines);
  const input = {
    client_request_id: clientRequestID,
    entry_date: entryDate,
    entry_kind: "reversal",
    description: cleanString(`Reversal — ${original.description || "Journal"}`, 200),
    reference: cleanString(body.reference ?? original.reference, 120) || null,
    reason,
    source_type: "manual",
    source_id: null,
    source_version: null,
    reversal_of_entry_id: String(original.id),
    lines: reversed.lines,
    total_debits_cents: reversed.total_debits_cents,
    total_credits_cents: reversed.total_credits_cents
  };
  return { ...input, request_fingerprint: journalFingerprint(input) };
}

export function summarizeTrialBalanceRows(rows = []) {
  let periodDebits = 0;
  let periodCredits = 0;
  let endingDebits = 0;
  let endingCredits = 0;
  const accounts = rows.map((row) => {
    const periodDebit = storedInteger(row.period_debit_cents ?? 0, "period_debit_cents");
    const periodCredit = storedInteger(row.period_credit_cents ?? 0, "period_credit_cents");
    const throughDebit = storedInteger(row.through_end_debit_cents ?? 0, "through_end_debit_cents");
    const throughCredit = storedInteger(row.through_end_credit_cents ?? 0, "through_end_credit_cents");
    periodDebits = addExact(periodDebits, periodDebit, "period_debits_cents");
    periodCredits = addExact(periodCredits, periodCredit, "period_credits_cents");
    const net = throughDebit - throughCredit;
    if (!Number.isSafeInteger(net)) throw new GeneralLedgerError("general_ledger_amount_inexact", "Account balance exceeds the exact supported range.", 409);
    const endingDebit = Math.max(net, 0);
    const endingCredit = Math.max(-net, 0);
    endingDebits = addExact(endingDebits, endingDebit, "ending_debits_cents");
    endingCredits = addExact(endingCredits, endingCredit, "ending_credits_cents");
    return {
      chart_account_id: String(row.chart_account_id || row.id),
      code: row.code || "",
      name: row.name || "Account",
      account_type: row.account_type,
      period_debit_cents: periodDebit,
      period_credit_cents: periodCredit,
      ending_debit_balance_cents: endingDebit,
      ending_credit_balance_cents: endingCredit
    };
  });
  if (periodDebits !== periodCredits || endingDebits !== endingCredits) {
    throw new GeneralLedgerError("general_ledger_unbalanced", "Stored journal totals are out of balance. The report was not produced.", 409, {
      period_debits_cents: periodDebits,
      period_credits_cents: periodCredits,
      ending_debits_cents: endingDebits,
      ending_credits_cents: endingCredits
    });
  }
  return {
    accounts,
    period_debits_cents: periodDebits,
    period_credits_cents: periodCredits,
    ending_debits_cents: endingDebits,
    ending_credits_cents: endingCredits
  };
}

export async function installFinanceGeneralLedgerSchema(pool) {
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS finance_chart_accounts_company_id_idx
      ON finance_chart_accounts(company_id, id);

    CREATE TABLE IF NOT EXISTS finance_journal_entries (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      entry_date DATE NOT NULL,
      entry_kind TEXT NOT NULL CHECK (entry_kind IN ('opening_balance','adjustment','transfer','owner_equity','reclassification','bank_transaction','bank_transfer','job_receivable','reversal')),
      status TEXT NOT NULL DEFAULT 'posted' CHECK (status = 'posted'),
      description TEXT NOT NULL,
      reference TEXT,
      reversal_of_entry_id UUID,
      client_request_id UUID NOT NULL,
      request_fingerprint TEXT NOT NULL CHECK (char_length(request_fingerprint) = 64),
      reason TEXT NOT NULL,
      source_type TEXT NOT NULL DEFAULT 'manual' CHECK (source_type IN ('manual','finance_transaction','finance_transfer_pair','finance_operational_source')),
      source_id UUID,
      source_version INTEGER,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, id),
      UNIQUE(company_id, client_request_id),
      FOREIGN KEY (company_id, reversal_of_entry_id)
        REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT,
      CHECK ((entry_kind = 'reversal') = (reversal_of_entry_id IS NOT NULL)),
      CONSTRAINT finance_journal_entries_source_identity_check CHECK (
        (source_type = 'manual' AND source_id IS NULL AND source_version IS NULL)
        OR (source_type IN ('finance_transaction','finance_transfer_pair','finance_operational_source') AND source_id IS NOT NULL AND source_version > 0)
      )
    );
    CREATE UNIQUE INDEX IF NOT EXISTS finance_journal_entries_one_reversal_idx
      ON finance_journal_entries(company_id, reversal_of_entry_id) WHERE reversal_of_entry_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS finance_journal_entries_company_date_idx
      ON finance_journal_entries(company_id, entry_date DESC, created_at DESC);

    CREATE TABLE IF NOT EXISTS finance_journal_lines (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      entry_id UUID NOT NULL,
      line_order INTEGER NOT NULL CHECK (line_order >= 0 AND line_order < 50),
      chart_account_id UUID NOT NULL,
      debit_cents BIGINT NOT NULL DEFAULT 0 CHECK (debit_cents >= 0),
      credit_cents BIGINT NOT NULL DEFAULT 0 CHECK (credit_cents >= 0),
      memo TEXT,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      CHECK ((debit_cents > 0 AND credit_cents = 0) OR (credit_cents > 0 AND debit_cents = 0)),
      UNIQUE(entry_id, line_order),
      UNIQUE(entry_id, chart_account_id),
      FOREIGN KEY (company_id, entry_id)
        REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, chart_account_id)
        REFERENCES finance_chart_accounts(company_id, id) ON DELETE RESTRICT
    );
    CREATE INDEX IF NOT EXISTS finance_journal_lines_company_entry_idx
      ON finance_journal_lines(company_id, entry_id, line_order);
    CREATE INDEX IF NOT EXISTS finance_journal_lines_company_account_idx
      ON finance_journal_lines(company_id, chart_account_id, entry_id);

    CREATE TABLE IF NOT EXISTS finance_journal_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      entry_id UUID NOT NULL,
      related_entry_id UUID,
      actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      reason TEXT NOT NULL,
      entry_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      FOREIGN KEY (company_id, entry_id)
        REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, related_entry_id)
        REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT
    );
    CREATE INDEX IF NOT EXISTS finance_journal_audit_company_entry_idx
      ON finance_journal_audit(company_id, entry_id, created_at DESC);
  `);
  await pool.query(`ALTER TABLE finance_journal_entries ADD COLUMN IF NOT EXISTS source_type TEXT NOT NULL DEFAULT 'manual'`);
  await pool.query(`ALTER TABLE finance_journal_entries ADD COLUMN IF NOT EXISTS source_id UUID`);
  await pool.query(`ALTER TABLE finance_journal_entries ADD COLUMN IF NOT EXISTS source_version INTEGER`);
  await pool.query(`ALTER TABLE finance_journal_entries DROP CONSTRAINT IF EXISTS finance_journal_entries_entry_kind_check`);
  await pool.query(`ALTER TABLE finance_journal_entries ADD CONSTRAINT finance_journal_entries_entry_kind_check CHECK (entry_kind IN ('opening_balance','adjustment','transfer','owner_equity','reclassification','bank_transaction','bank_transfer','job_receivable','reversal'))`);
  await pool.query(`ALTER TABLE finance_journal_entries DROP CONSTRAINT IF EXISTS finance_journal_entries_source_type_check`);
  await pool.query(`ALTER TABLE finance_journal_entries ADD CONSTRAINT finance_journal_entries_source_type_check CHECK (source_type IN ('manual','finance_transaction','finance_transfer_pair','finance_operational_source'))`);
  await pool.query(`ALTER TABLE finance_journal_entries DROP CONSTRAINT IF EXISTS finance_journal_entries_source_identity_check`);
  await pool.query(`ALTER TABLE finance_journal_entries ADD CONSTRAINT finance_journal_entries_source_identity_check CHECK (
    (source_type = 'manual' AND source_id IS NULL AND source_version IS NULL)
    OR (source_type IN ('finance_transaction','finance_transfer_pair','finance_operational_source') AND source_id IS NOT NULL AND source_version > 0)
  )`);
  await pool.query(`CREATE INDEX IF NOT EXISTS finance_journal_entries_company_source_idx ON finance_journal_entries(company_id, source_type, source_id, source_version) WHERE source_id IS NOT NULL`);
}

export async function loadCompanyContext(poolOrClient, companyID) {
  const { rows } = await poolOrClient.query(
    `SELECT COALESCE(NULLIF(timezone, ''), 'America/New_York') AS timezone,
            (now() AT TIME ZONE COALESCE(NULLIF(timezone, ''), 'America/New_York'))::date::text AS company_today
       FROM companies WHERE id = $1`,
    [companyID]
  );
  if (!rows.length) throw new GeneralLedgerError("company_not_found", "Company workspace was not found.", 404);
  return rows[0];
}

function entryDateValue(value) {
  return value instanceof Date ? value.toISOString().slice(0, 10) : String(value || "").slice(0, 10);
}

function entrySummaryPayload(row) {
  return {
    id: String(row.id),
    company_id: String(row.company_id),
    entry_date: entryDateValue(row.entry_date),
    entry_kind: row.entry_kind,
    status: row.status,
    description: row.description,
    reference: row.reference || null,
    reversal_of_entry_id: row.reversal_of_entry_id || null,
    reversed_by_entry_id: row.reversed_by_entry_id || null,
    source_type: row.source_type || "manual",
    source_id: row.source_id || null,
    source_version: row.source_version === null || row.source_version === undefined ? null : Number(row.source_version),
    total_debits_cents: storedInteger(row.total_debits_cents ?? 0, "total_debits_cents"),
    total_credits_cents: storedInteger(row.total_credits_cents ?? 0, "total_credits_cents"),
    created_by: row.created_by || null,
    created_at: row.created_at || null
  };
}

function linePayload(row) {
  return {
    id: String(row.id),
    line_order: Number(row.line_order),
    chart_account_id: String(row.chart_account_id),
    chart_account_code: row.chart_account_code || row.code || null,
    chart_account_name: row.chart_account_name || row.name || null,
    account_type: row.account_type || null,
    debit_cents: storedInteger(row.debit_cents, "debit_cents"),
    credit_cents: storedInteger(row.credit_cents, "credit_cents"),
    memo: row.memo || null
  };
}

function auditPayload(row) {
  return {
    id: String(row.id),
    entry_id: String(row.entry_id),
    related_entry_id: row.related_entry_id || null,
    action: row.action,
    reason: row.reason,
    actor_user_id: row.actor_user_id || null,
    created_at: row.created_at || null
  };
}

export async function loadJournalEntry(poolOrClient, companyID, entryID, auditLimit = 50) {
  const entryResult = await poolOrClient.query(
    `SELECT e.*,
            reversed.id AS reversed_by_entry_id,
            COALESCE(SUM(l.debit_cents), 0) AS total_debits_cents,
            COALESCE(SUM(l.credit_cents), 0) AS total_credits_cents
       FROM finance_journal_entries e
       LEFT JOIN finance_journal_entries reversed
         ON reversed.company_id=e.company_id AND reversed.reversal_of_entry_id=e.id
       LEFT JOIN finance_journal_lines l ON l.company_id=e.company_id AND l.entry_id=e.id
      WHERE e.company_id=$1 AND e.id=$2
      GROUP BY e.id, reversed.id`,
    [companyID, entryID]
  );
  if (!entryResult.rows.length) throw new GeneralLedgerError("journal_entry_not_found", "Journal entry was not found.", 404);
  const lines = await poolOrClient.query(
    `SELECT l.*, c.code AS chart_account_code, c.name AS chart_account_name, c.account_type
       FROM finance_journal_lines l
       JOIN finance_chart_accounts c ON c.company_id=l.company_id AND c.id=l.chart_account_id
      WHERE l.company_id=$1 AND l.entry_id=$2 ORDER BY l.line_order`,
    [companyID, entryID]
  );
  const audit = await poolOrClient.query(
    `SELECT id, entry_id, related_entry_id, actor_user_id, action, reason, created_at
       FROM finance_journal_audit WHERE company_id=$1 AND entry_id=$2
      ORDER BY created_at DESC LIMIT $3`,
    [companyID, entryID, Math.min(Math.max(Number(auditLimit) || 50, 1), 100)]
  );
  return {
    entry: entrySummaryPayload(entryResult.rows[0]),
    lines: lines.rows.map(linePayload),
    audit: audit.rows.map(auditPayload)
  };
}

export function snapshotInput(input) {
  return {
    entry_date: input.entry_date,
    entry_kind: input.entry_kind,
    description: input.description,
    reference: input.reference,
    reversal_of_entry_id: input.reversal_of_entry_id || null,
    source_type: input.source_type || "manual",
    source_id: input.source_id || null,
    source_version: input.source_version ?? null,
    total_debits_cents: input.total_debits_cents,
    total_credits_cents: input.total_credits_cents,
    lines: input.lines.map((line) => ({
      line_order: line.position,
      chart_account_id: line.chart_account_id,
      debit_cents: line.debit_cents,
      credit_cents: line.credit_cents,
      memo: line.memo
    }))
  };
}

export async function insertJournal(client, companyID, userID, input) {
  const entry = (await client.query(
    `INSERT INTO finance_journal_entries (
       company_id, entry_date, entry_kind, description, reference, reversal_of_entry_id,
       client_request_id, request_fingerprint, reason, source_type, source_id, source_version, created_by
     ) VALUES ($1,$2::date,$3,$4,$5,$6::uuid,$7::uuid,$8,$9,$10,$11::uuid,$12,$13) RETURNING *`,
    [companyID, input.entry_date, input.entry_kind, input.description, input.reference,
      input.reversal_of_entry_id || null, input.client_request_id, input.request_fingerprint, input.reason,
      input.source_type || "manual", input.source_id || null, input.source_version ?? null, userID]
  )).rows[0];
  await client.query(
    `INSERT INTO finance_journal_lines (
       company_id, entry_id, line_order, chart_account_id, debit_cents, credit_cents, memo, created_by
     ) SELECT $1,$2,x.line_order,x.chart_account_id::uuid,x.debit_cents,x.credit_cents,x.memo,$4
         FROM jsonb_to_recordset($3::jsonb) AS x(
           line_order integer, chart_account_id text, debit_cents bigint, credit_cents bigint, memo text
         )`,
    [companyID, entry.id, JSON.stringify(input.lines.map((line) => ({
      line_order: line.position,
      chart_account_id: line.chart_account_id,
      debit_cents: line.debit_cents,
      credit_cents: line.credit_cents,
      memo: line.memo
    }))), userID]
  );
  return entry;
}

async function replayedEntry(client, companyID, input, expectedReversalOf = null) {
  const { rows } = await client.query(
    `SELECT id, request_fingerprint, reversal_of_entry_id
       FROM finance_journal_entries WHERE company_id=$1 AND client_request_id=$2::uuid FOR UPDATE`,
    [companyID, input.client_request_id]
  );
  if (!rows.length) return null;
  const row = rows[0];
  if (row.request_fingerprint !== input.request_fingerprint || String(row.reversal_of_entry_id || "") !== String(expectedReversalOf || "")) {
    throw new GeneralLedgerError("journal_request_id_conflict", "That journal request ID was already used with different content.", 409, {
      existing_entry_id: row.id
    });
  }
  return row.id;
}

async function loadGeneralLedgerReport(poolOrClient, companyID, range, limit) {
  const integrity = await poolOrClient.query(
    `SELECT COUNT(*)::int AS invalid_count FROM (
       SELECT e.id
         FROM finance_journal_entries e
         LEFT JOIN finance_journal_lines l ON l.company_id=e.company_id AND l.entry_id=e.id
        WHERE e.company_id=$1 AND e.entry_date <= $2::date
        GROUP BY e.id
       HAVING COUNT(l.id) < 2 OR COALESCE(SUM(l.debit_cents),0) <= 0
          OR COALESCE(SUM(l.debit_cents),0) <> COALESCE(SUM(l.credit_cents),0)
     ) invalid`,
    [companyID, range.end_date]
  );
  if (Number(integrity.rows[0]?.invalid_count || 0) > 0) {
    throw new GeneralLedgerError("general_ledger_integrity_failed", "Stored journal integrity checks failed. The report was not produced.", 409);
  }

  const accountResult = await poolOrClient.query(
    `SELECT c.id AS chart_account_id, c.code, c.name, c.account_type,
            COALESCE(SUM(l.debit_cents) FILTER (WHERE e.entry_date >= $2::date),0) AS period_debit_cents,
            COALESCE(SUM(l.credit_cents) FILTER (WHERE e.entry_date >= $2::date),0) AS period_credit_cents,
            COALESCE(SUM(l.debit_cents),0) AS through_end_debit_cents,
            COALESCE(SUM(l.credit_cents),0) AS through_end_credit_cents
       FROM finance_chart_accounts c
       JOIN finance_journal_lines l ON l.company_id=c.company_id AND l.chart_account_id=c.id
       JOIN finance_journal_entries e ON e.company_id=l.company_id AND e.id=l.entry_id AND e.entry_date <= $3::date
      WHERE c.company_id=$1
      GROUP BY c.id
      ORDER BY c.code, c.name`,
    [companyID, range.start_date, range.end_date]
  );
  const trial = summarizeTrialBalanceRows(accountResult.rows);
  const countResult = await poolOrClient.query(
    `SELECT COUNT(*) FILTER (WHERE entry_date >= $2::date AND entry_date <= $3::date)::int AS period_count,
            COUNT(*) FILTER (WHERE entry_date <= $3::date)::int AS through_end_count
       FROM finance_journal_entries WHERE company_id=$1`,
    [companyID, range.start_date, range.end_date]
  );
  const totalCount = Number(countResult.rows[0]?.period_count || 0);
  const entryResult = await poolOrClient.query(
    `SELECT e.*, reversed.id AS reversed_by_entry_id,
            SUM(l.debit_cents) AS total_debits_cents, SUM(l.credit_cents) AS total_credits_cents
       FROM finance_journal_entries e
       JOIN finance_journal_lines l ON l.company_id=e.company_id AND l.entry_id=e.id
       LEFT JOIN finance_journal_entries reversed
         ON reversed.company_id=e.company_id AND reversed.reversal_of_entry_id=e.id
      WHERE e.company_id=$1 AND e.entry_date >= $2::date AND e.entry_date <= $3::date
      GROUP BY e.id, reversed.id
      ORDER BY e.entry_date DESC, e.created_at DESC
      LIMIT $4`,
    [companyID, range.start_date, range.end_date, limit + 1]
  );
  const truncated = entryResult.rows.length > limit;
  const entries = entryResult.rows.slice(0, limit).map(entrySummaryPayload);
  return {
    basis: "reviewed_double_entry_journal",
    start_date: range.start_date,
    end_date: range.end_date,
    currency: "usd",
    summary: {
      period_entry_count: totalCount,
      through_end_entry_count: Number(countResult.rows[0]?.through_end_count || 0),
      returned_entry_count: entries.length,
      truncated,
      period_debits_cents: trial.period_debits_cents,
      period_credits_cents: trial.period_credits_cents,
      ending_debits_cents: trial.ending_debits_cents,
      ending_credits_cents: trial.ending_credits_cents
    },
    accounts: trial.accounts,
    entries,
    warnings: [
      "This trial balance includes explicitly posted manual journals, reviewed bank-source journals, explicit bank-transfer pairs, and reviewed completed-job receivable journals.",
      "Unposted or blocked bank activity, unpaired transfers, Finance balances, operational payments/refunds/customer credits, Stripe settlement identity, mileage, and supported payroll are not posted here yet.",
      "Opening-balance and source coverage are not yet complete, so this is not a formal Balance Sheet or Cash Flow statement."
    ]
  };
}

function sendLedgerError(res, error, fallback) {
  if (error instanceof GeneralLedgerError || error?.statusCode) {
    return res.status(error.statusCode || 400).json({
      error: error.code || fallback,
      message: error.message,
      total_debits_cents: error.total_debits_cents,
      total_credits_cents: error.total_credits_cents,
      difference_cents: error.difference_cents,
      existing_entry_id: error.existing_entry_id
    });
  }
  if (error?.code === "23505") return res.status(409).json({ error: "journal_conflict", message: "That journal or reversal already exists." });
  console.error("[finance-general-ledger]", fallback, { code: error?.code, message: error?.message });
  return res.status(500).json({ error: fallback, message: "General Ledger request failed." });
}

export function installFinanceGeneralLedgerRoutes({ app, pool, authRequired, requireFinanceAccess, ensureChartAccounts }) {
  app.get("/api/finance/accounting/general-ledger", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "General Ledger requires a company workspace." });
    try {
      const context = await loadCompanyContext(pool, req.companyId);
      const end = req.query.end_date || context.company_today;
      const start = req.query.start_date || `${end.slice(0, 7)}-01`;
      const range = parseGeneralLedgerRange(start, end);
      const limit = boundedLimit(req.query.limit);
      res.json({ timezone: context.timezone, company_today: context.company_today, ...(await loadGeneralLedgerReport(pool, req.companyId, range, limit)) });
    } catch (error) {
      sendLedgerError(res, error, "general_ledger_load_failed");
    }
  });

  app.get("/api/finance/accounting/general-ledger/entries/:entryId", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "General Ledger requires a company workspace." });
    try {
      const entryID = journalEntryID(req.params.entryId);
      res.json(await loadJournalEntry(pool, req.companyId, entryID, req.query.audit_limit));
    } catch (error) {
      sendLedgerError(res, error, "journal_entry_load_failed");
    }
  });

  app.post("/api/finance/accounting/general-ledger/entries", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "General Ledger requires a company workspace." });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(`SELECT pg_advisory_xact_lock(hashtext($1::text))`, [`${req.companyId}|general-ledger`]);
      const context = await loadCompanyContext(client, req.companyId);
      await ensureChartAccounts(client, req.companyId, req.userId);
      const chart = await client.query(`SELECT id, account_type, active FROM finance_chart_accounts WHERE company_id=$1`, [req.companyId]);
      // An exact retry remains replayable if a referenced account was archived
      // after the first commit. A genuinely new post is validated again against
      // the active chart immediately below.
      const replayInput = normalizeManualJournal({
        body: req.body,
        chartAccounts: chart.rows,
        companyToday: context.company_today,
        allowInactiveAccounts: true
      });
      const replayID = await replayedEntry(client, req.companyId, replayInput);
      if (replayID) {
        await client.query("COMMIT");
        return res.json({ replayed: true, ...(await loadJournalEntry(pool, req.companyId, replayID)) });
      }
      const input = normalizeManualJournal({ body: req.body, chartAccounts: chart.rows, companyToday: context.company_today });
      const entry = await insertJournal(client, req.companyId, req.userId, input);
      await client.query(
        `INSERT INTO finance_journal_audit (company_id, entry_id, actor_user_id, action, reason, entry_snapshot)
         VALUES ($1,$2,$3,'journal_posted',$4,$5)`,
        [req.companyId, entry.id, req.userId, input.reason, JSON.stringify(snapshotInput(input))]
      );
      await client.query("COMMIT");
      res.status(201).json({ replayed: false, ...(await loadJournalEntry(pool, req.companyId, entry.id)) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendLedgerError(res, error, "journal_entry_create_failed");
    } finally {
      client.release();
    }
  });

  app.post("/api/finance/accounting/general-ledger/entries/:entryId/reverse", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "General Ledger requires a company workspace." });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(`SELECT pg_advisory_xact_lock(hashtext($1::text))`, [`${req.companyId}|general-ledger`]);
      const context = await loadCompanyContext(client, req.companyId);
      const entryID = journalEntryID(req.params.entryId);
      const originalResult = await client.query(
        `SELECT * FROM finance_journal_entries WHERE company_id=$1 AND id=$2 FOR UPDATE`,
        [req.companyId, entryID]
      );
      const original = originalResult.rows[0];
      if (!original) throw new GeneralLedgerError("journal_entry_not_found", "Journal entry was not found.", 404);
      if ((original.source_type || "manual") !== "manual") {
        throw new GeneralLedgerError(
          "journal_source_owned",
          "Source-owned journals can be corrected or voided only from their source review workflow.",
          409
        );
      }
      const originalLines = await client.query(
        `SELECT chart_account_id, debit_cents, credit_cents, memo
           FROM finance_journal_lines WHERE company_id=$1 AND entry_id=$2 ORDER BY line_order FOR SHARE`,
        [req.companyId, original.id]
      );
      const input = normalizeJournalReversal({ body: req.body, original, originalLines: originalLines.rows, companyToday: context.company_today });
      const replayID = await replayedEntry(client, req.companyId, input, original.id);
      if (replayID) {
        await client.query("COMMIT");
        return res.json({ replayed: true, ...(await loadJournalEntry(pool, req.companyId, replayID)) });
      }
      const existingReversal = await client.query(
        `SELECT id FROM finance_journal_entries WHERE company_id=$1 AND reversal_of_entry_id=$2 FOR UPDATE`,
        [req.companyId, original.id]
      );
      if (existingReversal.rows.length) {
        throw new GeneralLedgerError("journal_already_reversed", "This journal already has a posted reversal.", 409, {
          existing_entry_id: existingReversal.rows[0].id
        });
      }
      const reversal = await insertJournal(client, req.companyId, req.userId, input);
      const snapshot = JSON.stringify(snapshotInput(input));
      await client.query(
        `INSERT INTO finance_journal_audit (
           company_id, entry_id, related_entry_id, actor_user_id, action, reason, entry_snapshot
         ) VALUES
           ($1,$2,$3,$4,'journal_reversal_posted',$5,$6),
           ($1,$3,$2,$4,'journal_reversed',$5,$6)`,
        [req.companyId, reversal.id, original.id, req.userId, input.reason, snapshot]
      );
      await client.query("COMMIT");
      res.status(201).json({ replayed: false, ...(await loadJournalEntry(pool, req.companyId, reversal.id)) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendLedgerError(res, error, "journal_reversal_failed");
    } finally {
      client.release();
    }
  });
}
