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

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_REPORT_DAYS = 731;
const MAX_REPORT_ROWS = 200;

export class FinanceBankSourceError extends Error {
  constructor(code, message, statusCode = 400, details = {}) {
    super(message);
    this.name = "FinanceBankSourceError";
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
    throw new FinanceBankSourceError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return normalized;
}

function exactInteger(value, field, minimum = 0) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value.trim()) ? Number(value.trim()) : value;
  if (!Number.isSafeInteger(parsed) || parsed < minimum) {
    throw new FinanceBankSourceError(`${field}_invalid`, `${field.replaceAll("_", " ")} must be an exact integer.`);
  }
  return parsed;
}

function storedInteger(value, field) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(parsed)) {
    throw new FinanceBankSourceError("bank_source_amount_inexact", `${field.replaceAll("_", " ")} exceeds the exact supported range.`, 409);
  }
  return parsed;
}

function addExact(left, right, field) {
  const result = left + right;
  if (!Number.isSafeInteger(result)) {
    throw new FinanceBankSourceError("bank_source_amount_inexact", `${field.replaceAll("_", " ")} exceeds the exact supported range.`, 409);
  }
  return result;
}

function dateOnly(value, field = "date") {
  const raw = value instanceof Date ? value.toISOString().slice(0, 10) : cleanString(value, 20);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    throw new FinanceBankSourceError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  const [year, month, day] = raw.split("-").map(Number);
  const parsed = new Date(Date.UTC(year, month - 1, day));
  if (parsed.getUTCFullYear() !== year || parsed.getUTCMonth() !== month - 1 || parsed.getUTCDate() !== day) {
    throw new FinanceBankSourceError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
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

function mappingVersion(mapping) {
  return mapping ? Number(mapping.version || 0) : 0;
}

function postingVersion(posting) {
  return posting ? Number(posting.version || 0) : 0;
}

function mappingSnapshot(mapping, chartAccount = null) {
  if (!mapping) return null;
  return {
    mapping_id: String(mapping.id),
    finance_account_id: String(mapping.finance_account_id),
    chart_account_id: mapping.chart_account_id ? String(mapping.chart_account_id) : null,
    chart_account_type: chartAccount?.account_type || mapping.chart_account_type || null,
    version: Number(mapping.version || 0)
  };
}

export function parseBankSourceRange(startValue, endValue) {
  const startDate = dateOnly(startValue, "start_date");
  const endDate = dateOnly(endValue, "end_date");
  if (startDate > endDate) throw new FinanceBankSourceError("bank_source_range_invalid", "Start date must be on or before end date.");
  if (addDays(startDate, MAX_REPORT_DAYS - 1) < endDate) {
    throw new FinanceBankSourceError("bank_source_range_too_large", `Bank-source ranges cannot exceed ${MAX_REPORT_DAYS} days.`);
  }
  return { start_date: startDate, end_date: endDate };
}

function boundedLimit(value) {
  if (value === undefined || value === null || value === "") return 100;
  return Math.min(exactInteger(value, "limit", 1), MAX_REPORT_ROWS);
}

export function normalizeFinanceAccountMapping({
  body = {},
  financeAccount,
  currentMapping = null,
  chartAccounts = [],
  checkVersion = true,
  validateChart = true
}) {
  if (!financeAccount) throw new FinanceBankSourceError("finance_account_not_found", "Finance account was not found.", 404);
  const clientRequestID = uuid(body.client_request_id, "client_request_id");
  const expectedVersion = exactInteger(body.expected_version, "expected_version");
  const currentVersion = mappingVersion(currentMapping);
  if (checkVersion && expectedVersion !== currentVersion) {
    throw new FinanceBankSourceError("finance_account_mapping_stale", "This account mapping changed after it was loaded.", 409, {
      current_version: currentVersion
    });
  }
  const reason = cleanString(body.reason, 500);
  if (!reason) throw new FinanceBankSourceError("mapping_reason_required", "An audit reason is required.");
  const chartAccountID = body.chart_account_id === null || cleanString(body.chart_account_id, 80) === ""
    ? null
    : uuid(body.chart_account_id, "chart_account_id");
  const chartAccount = chartAccountID
    ? chartAccounts.find((account) => String(account.id) === chartAccountID)
    : null;
  if (validateChart && chartAccountID && (!chartAccount || chartAccount.active === false)) {
    throw new FinanceBankSourceError("mapping_chart_account_not_found", "Choose an active company chart account.", 404);
  }
  if (validateChart && chartAccount && chartAccount.account_type !== "asset" && chartAccount.account_type !== "liability") {
    throw new FinanceBankSourceError("mapping_chart_account_type_invalid", "Finance accounts can map only to asset or liability chart accounts.");
  }
  const changed = !currentMapping || String(currentMapping.chart_account_id || "") !== String(chartAccountID || "");
  const input = {
    client_request_id: clientRequestID,
    finance_account_id: String(financeAccount.id),
    expected_version: expectedVersion,
    chart_account_id: chartAccountID,
    reason
  };
  return {
    ...input,
    changed,
    current_version: currentVersion,
    next_version: changed ? currentVersion + 1 : currentVersion,
    request_fingerprint: fingerprint(input),
    chart_account: chartAccount
  };
}

function blocker(code, message) {
  return { code, message };
}

function sourceSnapshot({
  transaction,
  financeAccount,
  mapping,
  chartAccount,
  splits,
  activeTransferMembership = null,
  activeOperationalReceivableAuthorityCount = 0
}) {
  return {
    transaction_id: String(transaction.id),
    finance_account_id: String(financeAccount.id),
    source: transaction.source || "manual",
    status: transaction.status,
    direction: transaction.direction,
    amount_cents: storedInteger(transaction.amount_cents, "amount_cents"),
    transaction_date: dateOnly(transaction.transaction_date, "transaction_date"),
    pending: Boolean(transaction.pending),
    removed: Boolean(transaction.removed_at),
    reconciliation_status: transaction.reconciliation_status || "unreconciled",
    accounting_version: Number(transaction.accounting_version || 1),
    active_transfer_pair_id: activeTransferMembership?.pair_id ? String(activeTransferMembership.pair_id) : null,
    active_operational_receivable_authority_count: Number(activeOperationalReceivableAuthorityCount || 0),
    mapping: mappingSnapshot(mapping, chartAccount),
    allocations: splits.map((split) => ({
      chart_account_id: String(split.chart_account_id),
      account_type: split.account_type || null,
      amount_cents: storedInteger(split.amount_cents, "allocation_amount_cents")
    })).sort((left, right) => left.chart_account_id.localeCompare(right.chart_account_id))
  };
}

export function evaluateBankTransactionSource({
  transaction,
  financeAccount,
  mapping = null,
  chartAccount = null,
  splits = [],
  providerRefs = [],
  posting = null,
  activeTransferMembership = null,
  activeOperationalReceivableAuthorityCount = 0
}) {
  if (!transaction || !financeAccount) {
    throw new FinanceBankSourceError("bank_source_not_found", "Bank transaction source was not found.", 404);
  }
  const blockers = [];
  const amount = storedInteger(transaction.amount_cents ?? 0, "amount_cents");
  const direction = transaction.direction;
  const requiredAllocationType = direction === "income" ? "income" : direction === "expense" ? "expense" : null;
  if (transaction.status !== "posted" || transaction.pending) blockers.push(blocker("transaction_not_posted", "Only active posted transactions can enter the ledger."));
  if (transaction.removed_at) blockers.push(blocker("transaction_removed", "This provider transaction was removed and can only be voided if previously posted."));
  if ((transaction.reconciliation_status || "unreconciled") !== "reconciled") blockers.push(blocker("transaction_not_reconciled", "Mark the transaction Reconciled before posting it."));
  if (!requiredAllocationType) blockers.push(blocker("transaction_direction_invalid", "Transaction direction is not supported."));
  if (amount <= 0) blockers.push(blocker("transaction_amount_invalid", "A source journal needs a positive exact amount."));
  if (activeTransferMembership?.pair_id) {
    blockers.push(blocker("transaction_active_transfer_pair", "This source belongs to an active bank-transfer pair and cannot also post an individual journal."));
  }
  if (direction === "income" && Number(activeOperationalReceivableAuthorityCount || 0) > 0) {
    blockers.push(blocker(
      "operational_receivable_authority_active",
      "Reviewed completed-job revenue already exists in the ledger. Void that accrual authority before posting bank income; an exact settlement workflow is not available yet."
    ));
  }

  const accountCurrency = cleanString(financeAccount.currency || "usd", 10).toLowerCase();
  const transactionCurrency = cleanString(transaction.iso_currency_code || accountCurrency, 10).toLowerCase();
  if (accountCurrency !== "usd" || transactionCurrency !== "usd") {
    blockers.push(blocker("transaction_currency_unsupported", "Phase 4B source journals support USD activity only."));
  }
  if (!mapping || !mapping.chart_account_id) {
    blockers.push(blocker("finance_account_unmapped", "Map this Finance account to an asset or liability chart account."));
  } else if (!chartAccount || chartAccount.active === false) {
    blockers.push(blocker("mapped_chart_account_unavailable", "The mapped chart account is unavailable."));
  } else if (chartAccount.account_type !== "asset" && chartAccount.account_type !== "liability") {
    blockers.push(blocker("mapped_chart_account_type_invalid", "The mapped chart account must be an asset or liability."));
  }

  let allocationTotal = 0;
  const seen = new Set();
  if (!Array.isArray(splits) || splits.length === 0) {
    blockers.push(blocker("transaction_unclassified", "Classify the full transaction before posting it."));
  } else {
    for (const split of splits) {
      const splitID = String(split.chart_account_id || "");
      const splitAmount = storedInteger(split.amount_cents ?? 0, "allocation_amount_cents");
      allocationTotal = addExact(allocationTotal, splitAmount, "allocation_total_cents");
      if (!splitID || seen.has(splitID) || splitAmount <= 0) {
        blockers.push(blocker("transaction_allocations_invalid", "Stored allocations are not a valid exact set."));
        break;
      }
      seen.add(splitID);
      if (split.active === false) blockers.push(blocker("allocation_chart_account_inactive", "An allocation uses an inactive chart account."));
      if (requiredAllocationType && split.account_type !== requiredAllocationType) {
        blockers.push(blocker("transaction_non_profit_loss", "Transfers, assets, liabilities, equity, debt principal, owner activity, and customer credits wait for Phase 4C."));
      }
    }
    if (allocationTotal !== amount) blockers.push(blocker("transaction_allocations_unbalanced", "Allocations no longer total the exact transaction amount."));
  }

  const snapshot = sourceSnapshot({
    transaction,
    financeAccount,
    mapping,
    chartAccount,
    splits: Array.isArray(splits) ? splits : [],
    activeTransferMembership,
    activeOperationalReceivableAuthorityCount
  });
  const providerReferenceEvidence = [...providerRefs].map((ref) => ({
    provider: ref.provider || "plaid",
    provider_transaction_id: String(ref.provider_transaction_id || ""),
    is_current: Boolean(ref.is_current)
  })).sort((left, right) => `${left.provider}|${left.provider_transaction_id}`.localeCompare(`${right.provider}|${right.provider_transaction_id}`));
  const sourceFingerprint = fingerprint({ ...snapshot, provider_references: providerReferenceEvidence });
  const eligible = blockers.length === 0;

  let reviewState = "blocked";
  const postingStatus = posting?.status || null;
  const sourceCurrent = postingStatus === "posted" && posting?.source_fingerprint === sourceFingerprint;
  if (sourceCurrent) reviewState = "posted";
  else if (postingStatus === "posted") reviewState = "stale";
  else if (eligible) reviewState = "ready";
  else if (postingStatus === "voided") reviewState = "voided";

  let lines = [];
  if (eligible) {
    const sourceLine = {
      position: direction === "income" ? 0 : splits.length,
      chart_account_id: String(mapping.chart_account_id),
      debit_cents: direction === "income" ? amount : 0,
      credit_cents: direction === "expense" ? amount : 0,
      memo: "Finance account source"
    };
    const allocationLines = [...splits]
      .sort((left, right) => String(left.chart_account_id).localeCompare(String(right.chart_account_id)))
      .map((split, index) => ({
        position: direction === "income" ? index + 1 : index,
        chart_account_id: String(split.chart_account_id),
        debit_cents: direction === "expense" ? storedInteger(split.amount_cents, "allocation_amount_cents") : 0,
        credit_cents: direction === "income" ? storedInteger(split.amount_cents, "allocation_amount_cents") : 0,
        memo: cleanString(split.memo, 500) || null
      }));
    lines = direction === "income" ? [sourceLine, ...allocationLines] : [...allocationLines, sourceLine];
  }

  return {
    eligible,
    blockers: [...new Map(blockers.map((item) => [item.code, item])).values()],
    review_state: reviewState,
    source_current: sourceCurrent,
    can_post: eligible && !sourceCurrent,
    can_void: postingStatus === "posted",
    source_fingerprint: sourceFingerprint,
    source_snapshot: snapshot,
    journal_preview: eligible ? {
      entry_date: snapshot.transaction_date,
      total_debits_cents: amount,
      total_credits_cents: amount,
      lines
    } : null
  };
}

export function normalizeBankPostingRequest({ body = {}, transactionID, action }) {
  const normalizedAction = cleanString(action, 20).toLowerCase();
  if (normalizedAction !== "post" && normalizedAction !== "void") {
    throw new FinanceBankSourceError("bank_source_action_invalid", "Choose a valid bank-source action.");
  }
  const input = {
    client_request_id: uuid(body.client_request_id, "client_request_id"),
    transaction_id: uuid(transactionID, "transaction_id"),
    action: normalizedAction,
    expected_accounting_version: exactInteger(body.expected_accounting_version, "expected_accounting_version", 1),
    expected_mapping_version: exactInteger(body.expected_mapping_version, "expected_mapping_version"),
    expected_posting_version: exactInteger(body.expected_posting_version, "expected_posting_version"),
    reason: cleanString(body.reason, 500)
  };
  if (!input.reason) throw new FinanceBankSourceError("bank_source_reason_required", "An audit reason is required.");
  return { ...input, request_fingerprint: fingerprint(input) };
}

function assertActionVersions(request, bundle) {
  const currentAccounting = Number(bundle.transaction.accounting_version || 1);
  const currentMapping = mappingVersion(bundle.mapping);
  const currentPosting = postingVersion(bundle.posting);
  if (request.expected_accounting_version !== currentAccounting) {
    throw new FinanceBankSourceError("bank_source_accounting_stale", "Transaction accounting changed after this source was loaded.", 409, { current_accounting_version: currentAccounting });
  }
  if (request.expected_mapping_version !== currentMapping) {
    throw new FinanceBankSourceError("bank_source_mapping_stale", "Finance account mapping changed after this source was loaded.", 409, { current_mapping_version: currentMapping });
  }
  if (request.expected_posting_version !== currentPosting) {
    throw new FinanceBankSourceError("bank_source_posting_stale", "Source posting changed after this source was loaded.", 409, { current_posting_version: currentPosting });
  }
}

export function buildBankJournalInput({ evaluation, transactionID, postingVersion: version, clientRequestID, reason }) {
  if (!evaluation?.eligible || !evaluation.journal_preview) {
    throw new FinanceBankSourceError("bank_source_blocked", "Resolve every source blocker before posting.", 409, { blockers: evaluation?.blockers || [] });
  }
  const input = {
    client_request_id: uuid(clientRequestID, "client_request_id"),
    entry_date: evaluation.journal_preview.entry_date,
    entry_kind: "bank_transaction",
    description: `Finance transaction · ${evaluation.journal_preview.entry_date}`,
    reference: `FIN-${String(transactionID).slice(0, 8).toUpperCase()}`,
    reason: cleanString(reason, 500),
    reversal_of_entry_id: null,
    source_type: "finance_transaction",
    source_id: uuid(transactionID, "transaction_id"),
    source_version: exactInteger(version, "source_version", 1),
    lines: evaluation.journal_preview.lines,
    total_debits_cents: evaluation.journal_preview.total_debits_cents,
    total_credits_cents: evaluation.journal_preview.total_credits_cents
  };
  return { ...input, request_fingerprint: journalFingerprint(input) };
}

export function buildBankReversalInput({ original, originalLines, transactionID, postingVersion: version, clientRequestID, reason }) {
  if (!original || original.source_type !== "finance_transaction" || String(original.source_id) !== String(transactionID)) {
    throw new FinanceBankSourceError("bank_source_journal_invalid", "The current source journal relationship is invalid.", 409);
  }
  if (original.reversal_of_entry_id) throw new FinanceBankSourceError("bank_source_journal_invalid", "A reversal cannot be source authority.", 409);
  const reversed = reverseJournalLines(originalLines);
  const input = {
    client_request_id: uuid(clientRequestID, "client_request_id"),
    entry_date: dateOnly(original.entry_date, "entry_date"),
    entry_kind: "reversal",
    description: `Reversal — ${cleanString(original.description, 180) || "Finance transaction"}`,
    reference: cleanString(original.reference, 120) || null,
    reason: cleanString(reason, 500),
    reversal_of_entry_id: String(original.id),
    source_type: "finance_transaction",
    source_id: uuid(transactionID, "transaction_id"),
    source_version: exactInteger(version, "source_version", 1),
    lines: reversed.lines,
    total_debits_cents: reversed.total_debits_cents,
    total_credits_cents: reversed.total_credits_cents
  };
  return { ...input, request_fingerprint: journalFingerprint(input) };
}

export async function installFinanceBankSourceSchema(pool) {
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS finance_accounts_company_id_idx ON finance_accounts(company_id, id);
    CREATE UNIQUE INDEX IF NOT EXISTS finance_transactions_company_id_idx ON finance_transactions(company_id, id);

    CREATE TABLE IF NOT EXISTS finance_account_chart_mappings (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      finance_account_id UUID NOT NULL,
      chart_account_id UUID,
      version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
      reason TEXT NOT NULL,
      updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, id),
      UNIQUE(company_id, finance_account_id),
      FOREIGN KEY (company_id, finance_account_id) REFERENCES finance_accounts(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, chart_account_id) REFERENCES finance_chart_accounts(company_id, id) ON DELETE RESTRICT
    );
    CREATE INDEX IF NOT EXISTS finance_account_chart_mappings_company_chart_idx
      ON finance_account_chart_mappings(company_id, chart_account_id, finance_account_id);

    CREATE TABLE IF NOT EXISTS finance_account_chart_mapping_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      mapping_id UUID NOT NULL,
      finance_account_id UUID NOT NULL,
      actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      reason TEXT NOT NULL,
      version INTEGER NOT NULL CHECK (version > 0),
      client_request_id UUID NOT NULL,
      request_fingerprint TEXT NOT NULL CHECK (char_length(request_fingerprint) = 64),
      before_state JSONB,
      after_state JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, client_request_id),
      FOREIGN KEY (company_id, mapping_id) REFERENCES finance_account_chart_mappings(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, finance_account_id) REFERENCES finance_accounts(company_id, id) ON DELETE RESTRICT
    );
    CREATE INDEX IF NOT EXISTS finance_account_chart_mapping_audit_company_account_idx
      ON finance_account_chart_mapping_audit(company_id, finance_account_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS finance_bank_transaction_postings (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      finance_transaction_id UUID NOT NULL,
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
      UNIQUE(company_id, finance_transaction_id),
      FOREIGN KEY (company_id, finance_transaction_id) REFERENCES finance_transactions(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, journal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT,
      CHECK ((status = 'posted' AND journal_entry_id IS NOT NULL) OR (status = 'voided' AND journal_entry_id IS NULL))
    );
    CREATE INDEX IF NOT EXISTS finance_bank_transaction_postings_company_status_idx
      ON finance_bank_transaction_postings(company_id, status, updated_at DESC);

    CREATE TABLE IF NOT EXISTS finance_bank_transaction_posting_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      posting_id UUID NOT NULL,
      finance_transaction_id UUID NOT NULL,
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
      FOREIGN KEY (company_id, posting_id) REFERENCES finance_bank_transaction_postings(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, finance_transaction_id) REFERENCES finance_transactions(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, previous_journal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, journal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, reversal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT
    );
    CREATE INDEX IF NOT EXISTS finance_bank_transaction_posting_audit_company_transaction_idx
      ON finance_bank_transaction_posting_audit(company_id, finance_transaction_id, created_at DESC);
  `);
}

function financeAccountPayload(row) {
  return {
    id: String(row.id),
    name: row.name,
    account_type: row.account_type,
    source: row.source,
    currency: (row.currency || "usd").toLowerCase(),
    institution_name: row.institution_name || null,
    plaid_account_type: row.plaid_account_type || null,
    plaid_account_subtype: row.plaid_account_subtype || null,
    archived: Boolean(row.archived_at),
    mapping: row.mapping_id ? {
      id: String(row.mapping_id),
      finance_account_id: String(row.id),
      chart_account_id: row.mapped_chart_account_id || null,
      chart_account_code: row.mapped_chart_account_code || null,
      chart_account_name: row.mapped_chart_account_name || null,
      chart_account_type: row.mapped_chart_account_type || null,
      chart_account_active: row.mapped_chart_account_active === null || row.mapped_chart_account_active === undefined ? null : Boolean(row.mapped_chart_account_active),
      version: Number(row.mapping_version || 0),
      reason: row.mapping_reason || null,
      updated_by: row.mapping_updated_by || null,
      updated_at: row.mapping_updated_at || null
    } : null
  };
}

function postingPayload(posting) {
  if (!posting) return null;
  return {
    id: String(posting.id),
    status: posting.status,
    version: Number(posting.version || 0),
    source_fingerprint: posting.source_fingerprint,
    journal_entry_id: posting.journal_entry_id || null,
    reason: posting.reason || null,
    updated_by: posting.updated_by || null,
    updated_at: posting.updated_at || null
  };
}

function transactionPayload(bundle) {
  const evaluation = evaluateBankTransactionSource(bundle);
  return {
    transaction_id: String(bundle.transaction.id),
    transaction_date: dateOnly(bundle.transaction.transaction_date, "transaction_date"),
    merchant_name: bundle.transaction.merchant_name || bundle.transaction.original_name || "Transaction",
    direction: bundle.transaction.direction,
    amount_cents: storedInteger(bundle.transaction.amount_cents, "amount_cents"),
    status: bundle.transaction.status,
    pending: Boolean(bundle.transaction.pending),
    removed_at: bundle.transaction.removed_at || null,
    reconciliation_status: bundle.transaction.reconciliation_status || "unreconciled",
    accounting_version: Number(bundle.transaction.accounting_version || 1),
    finance_account: financeAccountPayload({
      ...bundle.financeAccount,
      mapping_id: bundle.mapping?.id,
      mapped_chart_account_id: bundle.mapping?.chart_account_id,
      mapped_chart_account_code: bundle.chartAccount?.code,
      mapped_chart_account_name: bundle.chartAccount?.name,
      mapped_chart_account_type: bundle.chartAccount?.account_type,
      mapped_chart_account_active: bundle.chartAccount?.active,
      mapping_version: bundle.mapping?.version,
      mapping_reason: bundle.mapping?.reason,
      mapping_updated_by: bundle.mapping?.updated_by,
      mapping_updated_at: bundle.mapping?.updated_at
    }),
    allocations: bundle.splits.map((split) => ({
      chart_account_id: String(split.chart_account_id),
      chart_account_code: split.code || split.chart_account_code || null,
      chart_account_name: split.name || split.chart_account_name || null,
      account_type: split.account_type,
      amount_cents: storedInteger(split.amount_cents, "allocation_amount_cents"),
      memo: split.memo || null
    })),
    posting: postingPayload(bundle.posting),
    ...evaluation
  };
}

async function loadFinanceAccounts(poolOrClient, companyID) {
  const { rows } = await poolOrClient.query(
    `SELECT a.*, m.id AS mapping_id, m.chart_account_id AS mapped_chart_account_id,
            m.version AS mapping_version, m.reason AS mapping_reason,
            m.updated_by AS mapping_updated_by, m.updated_at AS mapping_updated_at,
            c.code AS mapped_chart_account_code, c.name AS mapped_chart_account_name,
            c.account_type AS mapped_chart_account_type, c.active AS mapped_chart_account_active
       FROM finance_accounts a
       LEFT JOIN finance_account_chart_mappings m ON m.company_id=a.company_id AND m.finance_account_id=a.id
       LEFT JOIN finance_chart_accounts c ON c.company_id=m.company_id AND c.id=m.chart_account_id
      WHERE a.company_id=$1
      ORDER BY (a.archived_at IS NOT NULL), a.name, a.id`,
    [companyID]
  );
  return rows.map(financeAccountPayload);
}

async function loadTransactionBundles(poolOrClient, companyID, transactionRows) {
  if (!transactionRows.length) return [];
  const ids = transactionRows.map((row) => row.id);
  const [splitResult, refResult, mappingResult, postingResult, membershipResult, operationalAuthorityResult] = await Promise.all([
    poolOrClient.query(
      `SELECT s.*, c.code, c.name, c.account_type, c.active
         FROM finance_transaction_splits s
         JOIN finance_chart_accounts c ON c.company_id=s.company_id AND c.id=s.chart_account_id
        WHERE s.company_id=$1 AND s.transaction_id=ANY($2::uuid[])
        ORDER BY s.transaction_id, c.code, s.id`,
      [companyID, ids]
    ),
    poolOrClient.query(
      `SELECT transaction_id, provider, provider_transaction_id, is_current
         FROM finance_transaction_provider_refs
        WHERE company_id=$1 AND transaction_id=ANY($2::uuid[])
        ORDER BY transaction_id, provider, provider_transaction_id`,
      [companyID, ids]
    ),
    poolOrClient.query(
      `SELECT m.*, c.code, c.name, c.account_type, c.active
         FROM finance_account_chart_mappings m
         LEFT JOIN finance_chart_accounts c ON c.company_id=m.company_id AND c.id=m.chart_account_id
        WHERE m.company_id=$1 AND m.finance_account_id=ANY($2::uuid[])`,
      [companyID, [...new Set(transactionRows.map((row) => row.account_id))]]
    ),
    poolOrClient.query(
      `SELECT * FROM finance_bank_transaction_postings
        WHERE company_id=$1 AND finance_transaction_id=ANY($2::uuid[])`,
      [companyID, ids]
    ),
    poolOrClient.query(
      `SELECT pair_id, finance_transaction_id, role FROM finance_transfer_pair_members
        WHERE company_id=$1 AND finance_transaction_id=ANY($2::uuid[]) AND active`,
      [companyID, ids]
    ),
    poolOrClient.query(
      `SELECT COUNT(*)::int AS count FROM finance_operational_receivable_postings
        WHERE company_id=$1 AND status='posted'`,
      [companyID]
    )
  ]);
  const activeOperationalReceivableAuthorityCount = Number(operationalAuthorityResult.rows[0]?.count || 0);
  const byKey = (rows, field) => new Map(rows.map((row) => [String(row[field]), row]));
  const mappingByAccount = byKey(mappingResult.rows, "finance_account_id");
  const postingByTransaction = byKey(postingResult.rows, "finance_transaction_id");
  const membershipByTransaction = byKey(membershipResult.rows, "finance_transaction_id");
  const splitsByTransaction = new Map();
  for (const row of splitResult.rows) {
    const key = String(row.transaction_id);
    splitsByTransaction.set(key, [...(splitsByTransaction.get(key) || []), row]);
  }
  const refsByTransaction = new Map();
  for (const row of refResult.rows) {
    const key = String(row.transaction_id);
    refsByTransaction.set(key, [...(refsByTransaction.get(key) || []), row]);
  }
  return transactionRows.map((row) => {
    const mapping = mappingByAccount.get(String(row.account_id)) || null;
    const financeAccount = {
      id: row.account_id,
      name: row.finance_account_name,
      account_type: row.finance_account_type,
      source: row.finance_account_source,
      currency: row.currency,
      institution_name: row.institution_name,
      plaid_account_type: row.plaid_account_type,
      plaid_account_subtype: row.plaid_account_subtype,
      archived_at: row.archived_at
    };
    return {
      transaction: row,
      financeAccount,
      mapping,
      chartAccount: mapping?.chart_account_id ? {
        id: mapping.chart_account_id,
        code: mapping.code,
        name: mapping.name,
        account_type: mapping.account_type,
        active: mapping.active
      } : null,
      splits: splitsByTransaction.get(String(row.id)) || [],
      providerRefs: refsByTransaction.get(String(row.id)) || [],
      posting: postingByTransaction.get(String(row.id)) || null,
      activeTransferMembership: membershipByTransaction.get(String(row.id)) || null,
      activeOperationalReceivableAuthorityCount
    };
  });
}

async function loadBankSourceReport(poolOrClient, companyID, range, limit) {
  const totalResult = await poolOrClient.query(
    `SELECT COUNT(*)::int AS count FROM finance_transactions
      WHERE company_id=$1 AND transaction_date >= $2::date AND transaction_date <= $3::date`,
    [companyID, range.start_date, range.end_date]
  );
  const transactionResult = await poolOrClient.query(
    `SELECT t.*, a.name AS finance_account_name, a.account_type AS finance_account_type,
            a.source AS finance_account_source, a.currency, a.institution_name,
            a.plaid_account_type, a.plaid_account_subtype, a.archived_at
       FROM finance_transactions t
       JOIN finance_accounts a ON a.company_id=t.company_id AND a.id=t.account_id
      WHERE t.company_id=$1 AND t.transaction_date >= $2::date AND t.transaction_date <= $3::date
      ORDER BY t.transaction_date DESC, t.created_at DESC, t.id
      LIMIT $4`,
    [companyID, range.start_date, range.end_date, limit + 1]
  );
  const truncated = transactionResult.rows.length > limit;
  const bundles = await loadTransactionBundles(poolOrClient, companyID, transactionResult.rows.slice(0, limit));
  const transactions = bundles.map(transactionPayload);
  const counts = { ready: 0, posted: 0, stale: 0, blocked: 0, voided: 0 };
  transactions.forEach((transaction) => { counts[transaction.review_state] = (counts[transaction.review_state] || 0) + 1; });
  return {
    basis: "reviewed_finance_bank_sources",
    start_date: range.start_date,
    end_date: range.end_date,
    currency: "usd",
    summary: {
      source_transaction_count: Number(totalResult.rows[0]?.count || 0),
      returned_transaction_count: transactions.length,
      truncated,
      counts
    },
    accounts: await loadFinanceAccounts(poolOrClient, companyID),
    transactions,
    warnings: [
      "Posting is manual and limited to reconciled, fully classified USD income or expense bank sources.",
      "Transfer sides stay blocked from individual posting and require the explicit paired-transfer workflow. Current completed-job receivable authority blocks bank-income posting until it is explicitly voided. Debt principal, owner/equity activity, customer credits, Stripe settlement identity, and payroll remain blocked for later workflows.",
      "Posting or correction never changes the Phase 1 cash Profit & Loss report or provider data."
    ]
  };
}

async function loadMappingDetail(poolOrClient, companyID, financeAccountID) {
  const accountResult = await poolOrClient.query(
    `SELECT a.*, m.id AS mapping_id, m.chart_account_id AS mapped_chart_account_id,
            m.version AS mapping_version, m.reason AS mapping_reason,
            m.updated_by AS mapping_updated_by, m.updated_at AS mapping_updated_at,
            c.code AS mapped_chart_account_code, c.name AS mapped_chart_account_name,
            c.account_type AS mapped_chart_account_type, c.active AS mapped_chart_account_active
       FROM finance_accounts a
       LEFT JOIN finance_account_chart_mappings m ON m.company_id=a.company_id AND m.finance_account_id=a.id
       LEFT JOIN finance_chart_accounts c ON c.company_id=m.company_id AND c.id=m.chart_account_id
      WHERE a.company_id=$1 AND a.id=$2`,
    [companyID, financeAccountID]
  );
  if (!accountResult.rows.length) throw new FinanceBankSourceError("finance_account_not_found", "Finance account was not found.", 404);
  const auditResult = await poolOrClient.query(
    `SELECT id, action, reason, version, actor_user_id, before_state, after_state, created_at
       FROM finance_account_chart_mapping_audit
      WHERE company_id=$1 AND finance_account_id=$2 ORDER BY created_at DESC LIMIT 50`,
    [companyID, financeAccountID]
  );
  return {
    account: financeAccountPayload(accountResult.rows[0]),
    audit: auditResult.rows.map((row) => ({
      id: String(row.id), action: row.action, reason: row.reason, version: Number(row.version),
      actor_user_id: row.actor_user_id || null, before: row.before_state || null,
      after: row.after_state || {}, created_at: row.created_at || null
    }))
  };
}

async function loadLockedTransactionBundle(client, companyID, transactionID) {
  const transactionResult = await client.query(
    `SELECT t.*, a.name AS finance_account_name, a.account_type AS finance_account_type,
            a.source AS finance_account_source, a.currency, a.institution_name,
            a.plaid_account_type, a.plaid_account_subtype, a.archived_at
       FROM finance_transactions t
       JOIN finance_accounts a ON a.company_id=t.company_id AND a.id=t.account_id
      WHERE t.company_id=$1 AND t.id=$2 FOR UPDATE OF t, a`,
    [companyID, transactionID]
  );
  if (!transactionResult.rows.length) throw new FinanceBankSourceError("bank_source_not_found", "Bank transaction source was not found.", 404);
  const row = transactionResult.rows[0];
  // Keep transaction-scoped locks in one deterministic order. node-postgres uses
  // one connection here, so parallel promises add no throughput and obscure the
  // order other posting transactions must follow.
  const mappingResult = await client.query(
    `SELECT * FROM finance_account_chart_mappings WHERE company_id=$1 AND finance_account_id=$2 FOR UPDATE`,
    [companyID, row.account_id]
  );
  const splitResult = await client.query(
      `SELECT s.*, c.code, c.name, c.account_type, c.active
         FROM finance_transaction_splits s
         JOIN finance_chart_accounts c ON c.company_id=s.company_id AND c.id=s.chart_account_id
        WHERE s.company_id=$1 AND s.transaction_id=$2 ORDER BY c.code, s.id FOR SHARE OF s, c`,
      [companyID, transactionID]
  );
  const refResult = await client.query(
      `SELECT provider, provider_transaction_id, is_current FROM finance_transaction_provider_refs
        WHERE company_id=$1 AND transaction_id=$2 ORDER BY provider, provider_transaction_id FOR SHARE`,
      [companyID, transactionID]
  );
  const postingResult = await client.query(
    `SELECT * FROM finance_bank_transaction_postings WHERE company_id=$1 AND finance_transaction_id=$2 FOR UPDATE`,
    [companyID, transactionID]
  );
  const membershipResult = await client.query(
    `SELECT pair_id, finance_transaction_id, role FROM finance_transfer_pair_members
      WHERE company_id=$1 AND finance_transaction_id=$2 AND active FOR UPDATE`,
    [companyID, transactionID]
  );
  const operationalAuthorityResult = await client.query(
    `SELECT COUNT(*)::int AS count FROM finance_operational_receivable_postings
      WHERE company_id=$1 AND status='posted'`,
    [companyID]
  );
  const mapping = mappingResult.rows[0] || null;
  const chartResult = mapping?.chart_account_id
    ? await client.query(`SELECT id, code, name, account_type, active FROM finance_chart_accounts WHERE company_id=$1 AND id=$2 FOR SHARE`, [companyID, mapping.chart_account_id])
    : { rows: [] };
  return {
    transaction: row,
    financeAccount: {
      id: row.account_id,
      name: row.finance_account_name,
      account_type: row.finance_account_type,
      source: row.finance_account_source,
      currency: row.currency,
      institution_name: row.institution_name,
      plaid_account_type: row.plaid_account_type,
      plaid_account_subtype: row.plaid_account_subtype,
      archived_at: row.archived_at
    },
    mapping,
    chartAccount: chartResult.rows[0] || null,
    splits: splitResult.rows,
    providerRefs: refResult.rows,
    posting: postingResult.rows[0] || null,
    activeTransferMembership: membershipResult.rows[0] || null,
    activeOperationalReceivableAuthorityCount: Number(operationalAuthorityResult.rows[0]?.count || 0)
  };
}

async function loadTransactionDetail(poolOrClient, companyID, transactionID) {
  const result = await poolOrClient.query(
    `SELECT t.*, a.name AS finance_account_name, a.account_type AS finance_account_type,
            a.source AS finance_account_source, a.currency, a.institution_name,
            a.plaid_account_type, a.plaid_account_subtype, a.archived_at
       FROM finance_transactions t
       JOIN finance_accounts a ON a.company_id=t.company_id AND a.id=t.account_id
      WHERE t.company_id=$1 AND t.id=$2`,
    [companyID, transactionID]
  );
  if (!result.rows.length) throw new FinanceBankSourceError("bank_source_not_found", "Bank transaction source was not found.", 404);
  const bundle = (await loadTransactionBundles(poolOrClient, companyID, result.rows))[0];
  const audit = await poolOrClient.query(
    `SELECT id, action, reason, version, actor_user_id, previous_journal_entry_id,
            journal_entry_id, reversal_entry_id, created_at
       FROM finance_bank_transaction_posting_audit
      WHERE company_id=$1 AND finance_transaction_id=$2 ORDER BY created_at DESC LIMIT 50`,
    [companyID, transactionID]
  );
  return {
    transaction: transactionPayload(bundle),
    audit: audit.rows.map((row) => ({
      id: String(row.id), action: row.action, reason: row.reason, version: Number(row.version),
      actor_user_id: row.actor_user_id || null,
      previous_journal_entry_id: row.previous_journal_entry_id || null,
      journal_entry_id: row.journal_entry_id || null,
      reversal_entry_id: row.reversal_entry_id || null,
      created_at: row.created_at || null
    }))
  };
}

async function insertLedgerAudit(client, companyID, userID, entry, relatedEntry, action, reason, input) {
  await client.query(
    `INSERT INTO finance_journal_audit (company_id, entry_id, related_entry_id, actor_user_id, action, reason, entry_snapshot)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [companyID, entry.id, relatedEntry || null, userID, action, reason, JSON.stringify(snapshotInput(input))]
  );
}

async function replayedMappingRequest(client, companyID, input) {
  const { rows } = await client.query(
    `SELECT request_fingerprint FROM finance_account_chart_mapping_audit
      WHERE company_id=$1 AND client_request_id=$2::uuid FOR SHARE`,
    [companyID, input.client_request_id]
  );
  if (!rows.length) return false;
  if (rows[0].request_fingerprint !== input.request_fingerprint) {
    throw new FinanceBankSourceError("mapping_request_id_conflict", "That mapping request ID was already used with different content.", 409);
  }
  return true;
}

async function replayedPostingRequest(client, companyID, input) {
  const { rows } = await client.query(
    `SELECT request_fingerprint FROM finance_bank_transaction_posting_audit
      WHERE company_id=$1 AND client_request_id=$2::uuid FOR SHARE`,
    [companyID, input.client_request_id]
  );
  if (!rows.length) return false;
  if (rows[0].request_fingerprint !== input.request_fingerprint) {
    throw new FinanceBankSourceError("bank_source_request_id_conflict", "That source request ID was already used with different content.", 409);
  }
  return true;
}

function sendBankSourceError(res, error, fallback) {
  if (error instanceof FinanceBankSourceError || error instanceof GeneralLedgerError || error?.statusCode) {
    return res.status(error.statusCode || 400).json({
      error: error.code || fallback,
      message: error.message,
      blockers: error.blockers,
      current_version: error.current_version,
      current_accounting_version: error.current_accounting_version,
      current_mapping_version: error.current_mapping_version,
      current_posting_version: error.current_posting_version
    });
  }
  if (error?.code === "23505") return res.status(409).json({ error: "bank_source_conflict", message: "That source action already exists." });
  console.error("[finance-bank-sources]", fallback, { code: error?.code, message: error?.message });
  return res.status(500).json({ error: fallback, message: "Bank source request failed." });
}

export function installFinanceBankSourceRoutes({ app, pool, authRequired, requireFinanceAccess, ensureChartAccounts }) {
  app.get("/api/finance/accounting/bank-sources", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Bank source posting requires a company workspace." });
    try {
      const context = await loadCompanyContext(pool, req.companyId);
      const end = req.query.end_date || context.company_today;
      const start = req.query.start_date || `${end.slice(0, 7)}-01`;
      const range = parseBankSourceRange(start, end);
      await ensureChartAccounts(pool, req.companyId, req.userId);
      res.json({ timezone: context.timezone, company_today: context.company_today, ...(await loadBankSourceReport(pool, req.companyId, range, boundedLimit(req.query.limit))) });
    } catch (error) {
      sendBankSourceError(res, error, "bank_source_report_failed");
    }
  });

  app.get("/api/finance/accounting/bank-sources/accounts/:accountId/mapping", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Bank source posting requires a company workspace." });
    try {
      res.json(await loadMappingDetail(pool, req.companyId, uuid(req.params.accountId, "finance_account_id")));
    } catch (error) {
      sendBankSourceError(res, error, "finance_account_mapping_load_failed");
    }
  });

  app.put("/api/finance/accounting/bank-sources/accounts/:accountId/mapping", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Bank source posting requires a company workspace." });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const accountID = uuid(req.params.accountId, "finance_account_id");
      const accountResult = await client.query(`SELECT * FROM finance_accounts WHERE company_id=$1 AND id=$2 FOR UPDATE`, [req.companyId, accountID]);
      const financeAccount = accountResult.rows[0];
      if (!financeAccount) throw new FinanceBankSourceError("finance_account_not_found", "Finance account was not found.", 404);
      const mappingResult = await client.query(`SELECT * FROM finance_account_chart_mappings WHERE company_id=$1 AND finance_account_id=$2 FOR UPDATE`, [req.companyId, accountID]);
      const current = mappingResult.rows[0] || null;
      await ensureChartAccounts(client, req.companyId, req.userId);
      const chart = await client.query(`SELECT id, account_type, active FROM finance_chart_accounts WHERE company_id=$1`, [req.companyId]);
      // Normalize before version enforcement so an exact retry can be recognized
      // after its first request has advanced the mapping version.
      const replayInput = normalizeFinanceAccountMapping({
        body: req.body,
        financeAccount,
        currentMapping: current,
        chartAccounts: chart.rows,
        checkVersion: false,
        validateChart: false
      });
      if (await replayedMappingRequest(client, req.companyId, replayInput)) {
        await client.query("COMMIT");
        return res.json({ replayed: true, ...(await loadMappingDetail(pool, req.companyId, accountID)) });
      }
      const input = normalizeFinanceAccountMapping({
        body: req.body,
        financeAccount,
        currentMapping: current,
        chartAccounts: chart.rows
      });
      const before = mappingSnapshot(current, current?.chart_account_id ? chart.rows.find((item) => String(item.id) === String(current.chart_account_id)) : null);
      let mapping;
      if (!current) {
        mapping = (await client.query(
          `INSERT INTO finance_account_chart_mappings (company_id, finance_account_id, chart_account_id, version, reason, updated_by)
           VALUES ($1,$2,$3,1,$4,$5) RETURNING *`,
          [req.companyId, accountID, input.chart_account_id, input.reason, req.userId]
        )).rows[0];
      } else if (input.changed) {
        mapping = (await client.query(
          `UPDATE finance_account_chart_mappings
              SET chart_account_id=$3, version=version+1, reason=$4, updated_by=$5, updated_at=now()
            WHERE company_id=$1 AND finance_account_id=$2 RETURNING *`,
          [req.companyId, accountID, input.chart_account_id, input.reason, req.userId]
        )).rows[0];
      } else {
        mapping = (await client.query(
          `UPDATE finance_account_chart_mappings SET reason=$3, updated_by=$4, updated_at=now()
            WHERE company_id=$1 AND finance_account_id=$2 RETURNING *`,
          [req.companyId, accountID, input.reason, req.userId]
        )).rows[0];
      }
      const after = mappingSnapshot(mapping, input.chart_account);
      await client.query(
        `INSERT INTO finance_account_chart_mapping_audit (
           company_id, mapping_id, finance_account_id, actor_user_id, action, reason, version,
           client_request_id, request_fingerprint, before_state, after_state
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::uuid,$9,$10,$11)`,
        [req.companyId, mapping.id, accountID, req.userId,
          input.changed ? (input.chart_account_id ? "mapping_changed" : "mapping_cleared") : "mapping_reviewed",
          input.reason, mapping.version, input.client_request_id, input.request_fingerprint,
          before ? JSON.stringify(before) : null, JSON.stringify(after)]
      );
      await client.query("COMMIT");
      res.status(current ? 200 : 201).json({ replayed: false, ...(await loadMappingDetail(pool, req.companyId, accountID)) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendBankSourceError(res, error, "finance_account_mapping_update_failed");
    } finally {
      client.release();
    }
  });

  app.get("/api/finance/accounting/bank-sources/transactions/:transactionId", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Bank source posting requires a company workspace." });
    try {
      res.json(await loadTransactionDetail(pool, req.companyId, uuid(req.params.transactionId, "transaction_id")));
    } catch (error) {
      sendBankSourceError(res, error, "bank_source_detail_failed");
    }
  });

  const mutatePosting = (action) => async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Bank source posting requires a company workspace." });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(`SELECT id FROM companies WHERE id=$1 FOR UPDATE`, [req.companyId]);
      const request = normalizeBankPostingRequest({ body: req.body, transactionID: req.params.transactionId, action });
      if (await replayedPostingRequest(client, req.companyId, request)) {
        await client.query("COMMIT");
        return res.json({ replayed: true, ...(await loadTransactionDetail(pool, req.companyId, request.transaction_id)) });
      }
      const bundle = await loadLockedTransactionBundle(client, req.companyId, request.transaction_id);
      // A concurrent duplicate can commit while this request waits on source
      // locks. Re-check after locking so identical retries remain idempotent.
      if (await replayedPostingRequest(client, req.companyId, request)) {
        await client.query("COMMIT");
        return res.json({ replayed: true, ...(await loadTransactionDetail(pool, req.companyId, request.transaction_id)) });
      }
      assertActionVersions(request, bundle);
      const evaluation = evaluateBankTransactionSource(bundle);
      if (action === "post" && !evaluation.eligible) {
        throw new FinanceBankSourceError("bank_source_blocked", "Resolve every source blocker before posting.", 409, { blockers: evaluation.blockers });
      }
      if (action === "post" && evaluation.source_current) {
        await client.query(
          `INSERT INTO finance_bank_transaction_posting_audit (
             company_id, posting_id, finance_transaction_id, actor_user_id, action, reason, version,
             client_request_id, request_fingerprint, source_fingerprint, source_snapshot,
             previous_journal_entry_id, journal_entry_id, reversal_entry_id
           ) VALUES ($1,$2,$3,$4,'source_reviewed',$5,$6,$7::uuid,$8,$9,$10,$11,$11,NULL)`,
          [req.companyId, bundle.posting.id, request.transaction_id, req.userId, request.reason,
            bundle.posting.version, request.client_request_id, request.request_fingerprint,
            evaluation.source_fingerprint, JSON.stringify(evaluation.source_snapshot), bundle.posting.journal_entry_id]
        );
        await client.query("COMMIT");
        return res.json({ replayed: false, ...(await loadTransactionDetail(pool, req.companyId, request.transaction_id)) });
      }
      if (action === "void" && (!bundle.posting || bundle.posting.status !== "posted" || !bundle.posting.journal_entry_id)) {
        throw new FinanceBankSourceError("bank_source_not_posted", "Only a currently posted source can be voided.", 409);
      }

      const nextVersion = postingVersion(bundle.posting) + 1;
      const previousJournalID = bundle.posting?.status === "posted" ? bundle.posting.journal_entry_id : null;
      let reversal = null;
      if (previousJournalID) {
        const originalResult = await client.query(`SELECT * FROM finance_journal_entries WHERE company_id=$1 AND id=$2 FOR UPDATE`, [req.companyId, previousJournalID]);
        const original = originalResult.rows[0];
        const originalLines = await client.query(
          `SELECT chart_account_id, debit_cents, credit_cents, memo FROM finance_journal_lines
            WHERE company_id=$1 AND entry_id=$2 ORDER BY line_order FOR SHARE`,
          [req.companyId, previousJournalID]
        );
        const existingReversal = await client.query(`SELECT id FROM finance_journal_entries WHERE company_id=$1 AND reversal_of_entry_id=$2 FOR UPDATE`, [req.companyId, previousJournalID]);
        if (existingReversal.rows.length) throw new FinanceBankSourceError("bank_source_already_reversed", "The current source journal already has a reversal.", 409);
        const reversalInput = buildBankReversalInput({
          original,
          originalLines: originalLines.rows,
          transactionID: request.transaction_id,
          postingVersion: nextVersion,
          clientRequestID: action === "void" ? request.client_request_id : randomUUID(),
          reason: request.reason
        });
        reversal = await insertJournal(client, req.companyId, req.userId, reversalInput);
        await insertLedgerAudit(client, req.companyId, req.userId, reversal, original.id, "bank_source_reversal_posted", request.reason, reversalInput);
        await insertLedgerAudit(client, req.companyId, req.userId, original, reversal.id, "bank_source_reversed", request.reason, reversalInput);
      }

      let journal = null;
      if (action === "post") {
        const journalInput = buildBankJournalInput({
          evaluation,
          transactionID: request.transaction_id,
          postingVersion: nextVersion,
          clientRequestID: request.client_request_id,
          reason: request.reason
        });
        journal = await insertJournal(client, req.companyId, req.userId, journalInput);
        await insertLedgerAudit(client, req.companyId, req.userId, journal, reversal?.id || null, "bank_source_posted", request.reason, journalInput);
      }

      let posting;
      if (!bundle.posting) {
        posting = (await client.query(
          `INSERT INTO finance_bank_transaction_postings (
             company_id, finance_transaction_id, journal_entry_id, status, version,
             source_fingerprint, source_snapshot, reason, updated_by
           ) VALUES ($1,$2,$3,$4,1,$5,$6,$7,$8) RETURNING *`,
          [req.companyId, request.transaction_id, journal?.id || null, action === "post" ? "posted" : "voided",
            evaluation.source_fingerprint, JSON.stringify(evaluation.source_snapshot), request.reason, req.userId]
        )).rows[0];
      } else {
        posting = (await client.query(
          `UPDATE finance_bank_transaction_postings
              SET journal_entry_id=$3, status=$4, version=version+1, source_fingerprint=$5,
                  source_snapshot=$6, reason=$7, updated_by=$8, updated_at=now()
            WHERE company_id=$1 AND finance_transaction_id=$2 RETURNING *`,
          [req.companyId, request.transaction_id, journal?.id || null, action === "post" ? "posted" : "voided",
            evaluation.source_fingerprint, JSON.stringify(evaluation.source_snapshot), request.reason, req.userId]
        )).rows[0];
      }
      const auditAction = action === "void" ? "source_voided" : previousJournalID ? "source_replaced" : "source_posted";
      await client.query(
        `INSERT INTO finance_bank_transaction_posting_audit (
           company_id, posting_id, finance_transaction_id, actor_user_id, action, reason, version,
           client_request_id, request_fingerprint, source_fingerprint, source_snapshot,
           previous_journal_entry_id, journal_entry_id, reversal_entry_id
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::uuid,$9,$10,$11,$12,$13,$14)`,
        [req.companyId, posting.id, request.transaction_id, req.userId, auditAction, request.reason,
          posting.version, request.client_request_id, request.request_fingerprint,
          evaluation.source_fingerprint, JSON.stringify(evaluation.source_snapshot),
          previousJournalID, journal?.id || null, reversal?.id || null]
      );
      await client.query("COMMIT");
      res.status(201).json({ replayed: false, ...(await loadTransactionDetail(pool, req.companyId, request.transaction_id)) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendBankSourceError(res, error, `bank_source_${action}_failed`);
    } finally {
      client.release();
    }
  };

  app.post("/api/finance/accounting/bank-sources/transactions/:transactionId/post", authRequired, requireFinanceAccess, mutatePosting("post"));
  app.post("/api/finance/accounting/bank-sources/transactions/:transactionId/void", authRequired, requireFinanceAccess, mutatePosting("void"));
}
