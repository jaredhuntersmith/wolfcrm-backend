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
const MAX_RANGE_DAYS = 731;
const MAX_ROWS = 200;

export class FinanceBankTransferError extends Error {
  constructor(code, message, statusCode = 400, details = {}) {
    super(message);
    this.name = "FinanceBankTransferError";
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
    throw new FinanceBankTransferError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return normalized;
}

function exactInteger(value, field, minimum = 0) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value.trim()) ? Number(value.trim()) : value;
  if (!Number.isSafeInteger(parsed) || parsed < minimum) {
    throw new FinanceBankTransferError(`${field}_invalid`, `${field.replaceAll("_", " ")} must be an exact integer.`);
  }
  return parsed;
}

function storedInteger(value, field) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(parsed)) {
    throw new FinanceBankTransferError("bank_transfer_amount_inexact", `${field.replaceAll("_", " ")} exceeds the exact supported range.`, 409);
  }
  return parsed;
}

function dateOnly(value, field = "date") {
  const raw = value instanceof Date ? value.toISOString().slice(0, 10) : cleanString(value, 20);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    throw new FinanceBankTransferError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  const [year, month, day] = raw.split("-").map(Number);
  const parsed = new Date(Date.UTC(year, month - 1, day));
  if (parsed.getUTCFullYear() !== year || parsed.getUTCMonth() !== month - 1 || parsed.getUTCDate() !== day) {
    throw new FinanceBankTransferError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
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

function pairVersion(pair) {
  return pair ? Number(pair.version || 0) : 0;
}

function mappingVersion(bundle) {
  return bundle?.mapping ? Number(bundle.mapping.version || 0) : 0;
}

export function parseBankTransferRange(startValue, endValue) {
  const startDate = dateOnly(startValue, "start_date");
  const endDate = dateOnly(endValue, "end_date");
  if (startDate > endDate) throw new FinanceBankTransferError("bank_transfer_range_invalid", "Start date must be on or before end date.");
  if (addDays(startDate, MAX_RANGE_DAYS - 1) < endDate) {
    throw new FinanceBankTransferError("bank_transfer_range_too_large", `Transfer ranges cannot exceed ${MAX_RANGE_DAYS} days.`);
  }
  return { start_date: startDate, end_date: endDate };
}

function boundedLimit(value) {
  if (value === undefined || value === null || value === "") return 100;
  return Math.min(exactInteger(value, "limit", 1), MAX_ROWS);
}

function mappingSnapshot(bundle) {
  if (!bundle.mapping) return null;
  return {
    mapping_id: String(bundle.mapping.id),
    finance_account_id: String(bundle.financeAccount.id),
    chart_account_id: bundle.mapping.chart_account_id ? String(bundle.mapping.chart_account_id) : null,
    chart_account_type: bundle.chartAccount?.account_type || null,
    chart_account_active: bundle.chartAccount ? bundle.chartAccount.active !== false : null,
    version: Number(bundle.mapping.version || 0)
  };
}

function sourceSnapshot(bundle) {
  const transaction = bundle.transaction;
  return {
    transaction_id: String(transaction.id),
    finance_account_id: String(bundle.financeAccount.id),
    source: transaction.source || "manual",
    status: transaction.status,
    direction: transaction.direction,
    amount_cents: storedInteger(transaction.amount_cents, "amount_cents"),
    transaction_date: dateOnly(transaction.transaction_date, "transaction_date"),
    pending: Boolean(transaction.pending),
    removed: Boolean(transaction.removed_at),
    reconciliation_status: transaction.reconciliation_status || "unreconciled",
    accounting_version: Number(transaction.accounting_version || 1),
    individual_bank_posting: bundle.bankPosting ? {
      id: String(bundle.bankPosting.id),
      status: bundle.bankPosting.status,
      version: Number(bundle.bankPosting.version || 0),
      journal_entry_id: bundle.bankPosting.journal_entry_id || null
    } : null,
    mapping: mappingSnapshot(bundle),
    allocations: bundle.splits.map((split) => ({
      chart_account_id: String(split.chart_account_id),
      account_type: split.account_type || null,
      amount_cents: storedInteger(split.amount_cents, "allocation_amount_cents")
    })).sort((left, right) => left.chart_account_id.localeCompare(right.chart_account_id))
  };
}

function providerEvidence(bundle) {
  return [...bundle.providerRefs].map((ref) => ({
    provider: ref.provider || "plaid",
    provider_transaction_id: String(ref.provider_transaction_id || ""),
    is_current: Boolean(ref.is_current)
  })).sort((left, right) => `${left.provider}|${left.provider_transaction_id}`.localeCompare(`${right.provider}|${right.provider_transaction_id}`));
}

export function evaluateBankTransferCandidate(bundle) {
  if (!bundle?.transaction || !bundle?.financeAccount) {
    throw new FinanceBankTransferError("bank_transfer_source_not_found", "Transfer source was not found.", 404);
  }
  const transaction = bundle.transaction;
  const blockers = [];
  const amount = storedInteger(transaction.amount_cents ?? 0, "amount_cents");
  const role = transaction.direction === "expense" ? "outflow" : transaction.direction === "income" ? "inflow" : null;
  if (!role) blockers.push(blocker("transfer_direction_invalid", "A transfer side must be money out or money in."));
  if (transaction.status !== "posted" || transaction.pending) blockers.push(blocker("transfer_not_posted", "Only active posted transactions can be paired."));
  if (transaction.removed_at) blockers.push(blocker("transfer_removed", "A removed provider transaction cannot enter a new transfer pair."));
  if ((transaction.reconciliation_status || "unreconciled") !== "reconciled") blockers.push(blocker("transfer_not_reconciled", "Mark this transaction Reconciled before pairing it."));
  if (amount <= 0) blockers.push(blocker("transfer_amount_invalid", "A transfer side needs a positive exact amount."));
  if (bundle.bankPosting?.status === "posted") {
    blockers.push(blocker("transfer_source_posted_individually", "This source already owns an individual bank-source journal. Void that journal before pairing it."));
  }
  const accountCurrency = cleanString(bundle.financeAccount.currency || "usd", 10).toLowerCase();
  const transactionCurrency = cleanString(transaction.iso_currency_code || accountCurrency, 10).toLowerCase();
  if (accountCurrency !== "usd" || transactionCurrency !== "usd") blockers.push(blocker("transfer_currency_unsupported", "Phase 4C1 supports USD transfer sides only."));
  if (!bundle.mapping?.chart_account_id) {
    blockers.push(blocker("transfer_account_unmapped", "Map this Finance account before pairing its transfers."));
  } else if (!bundle.chartAccount || bundle.chartAccount.active === false) {
    blockers.push(blocker("transfer_mapping_unavailable", "The mapped chart account is unavailable."));
  } else if (bundle.chartAccount.account_type !== "asset" && bundle.chartAccount.account_type !== "liability") {
    blockers.push(blocker("transfer_mapping_type_invalid", "The mapped source must be an asset or liability chart account."));
  }
  if (bundle.splits.length !== 1) {
    blockers.push(blocker("transfer_allocation_count_invalid", "Classify the full transfer side to exactly one asset or liability counteraccount."));
  } else {
    const split = bundle.splits[0];
    const splitAmount = storedInteger(split.amount_cents ?? 0, "allocation_amount_cents");
    if (split.active === false) blockers.push(blocker("transfer_allocation_inactive", "The transfer allocation uses an inactive chart account."));
    if (split.account_type !== "asset" && split.account_type !== "liability") blockers.push(blocker("transfer_allocation_type_invalid", "Transfer allocations must use an asset or liability counteraccount."));
    if (splitAmount !== amount || splitAmount <= 0) blockers.push(blocker("transfer_allocation_unbalanced", "The transfer allocation must equal the exact source amount."));
  }
  const otherPairID = bundle.activeMembership?.pair_id ? String(bundle.activeMembership.pair_id) : null;
  return {
    role,
    eligible: blockers.length === 0,
    blockers,
    active_pair_id: otherPairID,
    source_snapshot: sourceSnapshot(bundle)
  };
}

export function evaluateBankTransferPair({ outflow, inflow, pair = null }) {
  const out = evaluateBankTransferCandidate(outflow);
  const incoming = evaluateBankTransferCandidate(inflow);
  const blockers = [
    ...out.blockers.map((item) => blocker(`outflow_${item.code}`, `Money out: ${item.message}`)),
    ...incoming.blockers.map((item) => blocker(`inflow_${item.code}`, `Money in: ${item.message}`))
  ];
  if (out.role !== "outflow") blockers.push(blocker("outflow_direction_invalid", "The selected money-out source has the wrong direction."));
  if (incoming.role !== "inflow") blockers.push(blocker("inflow_direction_invalid", "The selected money-in source has the wrong direction."));

  const outTransactionID = String(outflow.transaction.id);
  const inTransactionID = String(inflow.transaction.id);
  const currentPairID = pair?.id ? String(pair.id) : null;
  if (outTransactionID === inTransactionID) blockers.push(blocker("transfer_sources_same", "Choose two different transactions."));
  if (String(outflow.financeAccount.id) === String(inflow.financeAccount.id)) blockers.push(blocker("transfer_accounts_same", "Choose transactions from different Finance accounts."));
  if (outflow.mapping?.chart_account_id && String(outflow.mapping.chart_account_id) === String(inflow.mapping?.chart_account_id || "")) {
    blockers.push(blocker("transfer_mapped_accounts_same", "The two Finance accounts must map to different chart accounts."));
  }
  const outAmount = storedInteger(outflow.transaction.amount_cents ?? 0, "outflow_amount_cents");
  const inAmount = storedInteger(inflow.transaction.amount_cents ?? 0, "inflow_amount_cents");
  if (outAmount !== inAmount) blockers.push(blocker("transfer_amount_mismatch", "Money-out and money-in cents must match exactly."));
  if (outflow.splits.length === 1 && inflow.mapping?.chart_account_id && String(outflow.splits[0].chart_account_id) !== String(inflow.mapping.chart_account_id)) {
    blockers.push(blocker("outflow_counteraccount_mismatch", "The money-out allocation must target the money-in account mapping."));
  }
  if (inflow.splits.length === 1 && outflow.mapping?.chart_account_id && String(inflow.splits[0].chart_account_id) !== String(outflow.mapping.chart_account_id)) {
    blockers.push(blocker("inflow_counteraccount_mismatch", "The money-in allocation must target the money-out account mapping."));
  }
  if (out.active_pair_id && out.active_pair_id !== currentPairID) blockers.push(blocker("outflow_already_paired", "The money-out source already belongs to another active pair."));
  if (incoming.active_pair_id && incoming.active_pair_id !== currentPairID) blockers.push(blocker("inflow_already_paired", "The money-in source already belongs to another active pair."));

  const snapshot = { outflow: out.source_snapshot, inflow: incoming.source_snapshot };
  const sourceFingerprint = fingerprint({
    ...snapshot,
    provider_references: {
      outflow: providerEvidence(outflow),
      inflow: providerEvidence(inflow)
    }
  });
  const eligible = blockers.length === 0;
  const sourceCurrent = pair?.status === "posted" && pair.source_fingerprint === sourceFingerprint;
  let reviewState = "blocked";
  if (sourceCurrent) reviewState = "posted";
  else if (pair?.status === "posted") reviewState = "stale";
  else if (pair?.status === "voided") reviewState = "voided";
  else if (eligible) reviewState = "ready";
  const entryDate = [dateOnly(outflow.transaction.transaction_date), dateOnly(inflow.transaction.transaction_date)].sort().at(-1);
  const journalPreview = eligible ? {
    entry_date: entryDate,
    total_debits_cents: outAmount,
    total_credits_cents: outAmount,
    lines: [
      {
        position: 0,
        chart_account_id: String(inflow.mapping.chart_account_id),
        debit_cents: outAmount,
        credit_cents: 0,
        memo: "Transfer destination"
      },
      {
        position: 1,
        chart_account_id: String(outflow.mapping.chart_account_id),
        debit_cents: 0,
        credit_cents: outAmount,
        memo: "Transfer origin"
      }
    ]
  } : null;
  return {
    eligible,
    blockers: [...new Map(blockers.map((item) => [item.code, item])).values()],
    review_state: reviewState,
    source_current: sourceCurrent,
    can_post: eligible && pair?.status === "posted" && !sourceCurrent,
    can_void: pair?.status === "posted",
    source_fingerprint: sourceFingerprint,
    source_snapshot: snapshot,
    journal_preview: journalPreview
  };
}

export function normalizeTransferCreateRequest(body = {}) {
  const input = {
    client_request_id: uuid(body.client_request_id, "client_request_id"),
    outflow_transaction_id: uuid(body.outflow_transaction_id, "outflow_transaction_id"),
    inflow_transaction_id: uuid(body.inflow_transaction_id, "inflow_transaction_id"),
    expected_outflow_accounting_version: exactInteger(body.expected_outflow_accounting_version, "expected_outflow_accounting_version", 1),
    expected_inflow_accounting_version: exactInteger(body.expected_inflow_accounting_version, "expected_inflow_accounting_version", 1),
    expected_outflow_mapping_version: exactInteger(body.expected_outflow_mapping_version, "expected_outflow_mapping_version", 1),
    expected_inflow_mapping_version: exactInteger(body.expected_inflow_mapping_version, "expected_inflow_mapping_version", 1),
    reason: cleanString(body.reason, 500)
  };
  if (input.outflow_transaction_id === input.inflow_transaction_id) throw new FinanceBankTransferError("transfer_sources_same", "Choose two different transactions.");
  if (!input.reason) throw new FinanceBankTransferError("bank_transfer_reason_required", "An audit reason is required.");
  return { ...input, request_fingerprint: fingerprint(input) };
}

export function normalizeTransferActionRequest({ body = {}, pairID, action }) {
  const normalizedAction = cleanString(action, 20).toLowerCase();
  if (normalizedAction !== "post" && normalizedAction !== "void") throw new FinanceBankTransferError("bank_transfer_action_invalid", "Choose a valid transfer action.");
  const input = {
    client_request_id: uuid(body.client_request_id, "client_request_id"),
    pair_id: uuid(pairID, "pair_id"),
    action: normalizedAction,
    expected_pair_version: exactInteger(body.expected_pair_version, "expected_pair_version", 1),
    expected_outflow_accounting_version: exactInteger(body.expected_outflow_accounting_version, "expected_outflow_accounting_version", 1),
    expected_inflow_accounting_version: exactInteger(body.expected_inflow_accounting_version, "expected_inflow_accounting_version", 1),
    expected_outflow_mapping_version: exactInteger(body.expected_outflow_mapping_version, "expected_outflow_mapping_version", 1),
    expected_inflow_mapping_version: exactInteger(body.expected_inflow_mapping_version, "expected_inflow_mapping_version", 1),
    reason: cleanString(body.reason, 500)
  };
  if (!input.reason) throw new FinanceBankTransferError("bank_transfer_reason_required", "An audit reason is required.");
  return { ...input, request_fingerprint: fingerprint(input) };
}

function assertCreateVersions(request, outflow, inflow) {
  const checks = [
    [request.expected_outflow_accounting_version, Number(outflow.transaction.accounting_version || 1), "bank_transfer_outflow_accounting_stale", "Money-out accounting changed after it was loaded."],
    [request.expected_inflow_accounting_version, Number(inflow.transaction.accounting_version || 1), "bank_transfer_inflow_accounting_stale", "Money-in accounting changed after it was loaded."],
    [request.expected_outflow_mapping_version, mappingVersion(outflow), "bank_transfer_outflow_mapping_stale", "Money-out account mapping changed after it was loaded."],
    [request.expected_inflow_mapping_version, mappingVersion(inflow), "bank_transfer_inflow_mapping_stale", "Money-in account mapping changed after it was loaded."]
  ];
  for (const [expected, current, code, message] of checks) {
    if (expected !== current) throw new FinanceBankTransferError(code, message, 409, { current_version: current });
  }
}

function assertActionVersions(request, pair, outflow, inflow) {
  if (request.expected_pair_version !== pairVersion(pair)) {
    throw new FinanceBankTransferError("bank_transfer_pair_stale", "This transfer pair changed after it was loaded.", 409, { current_pair_version: pairVersion(pair) });
  }
  assertCreateVersions(request, outflow, inflow);
}

export function buildTransferJournalInput({ evaluation, pairID, version, clientRequestID, reason }) {
  if (!evaluation?.eligible || !evaluation.journal_preview) {
    throw new FinanceBankTransferError("bank_transfer_blocked", "Resolve every transfer blocker before posting.", 409, { blockers: evaluation?.blockers || [] });
  }
  const input = {
    client_request_id: uuid(clientRequestID, "client_request_id"),
    entry_date: evaluation.journal_preview.entry_date,
    entry_kind: "bank_transfer",
    description: `Paired bank transfer · ${evaluation.journal_preview.entry_date}`,
    reference: `XFER-${String(pairID).slice(0, 8).toUpperCase()}`,
    reason: cleanString(reason, 500),
    reversal_of_entry_id: null,
    source_type: "finance_transfer_pair",
    source_id: uuid(pairID, "pair_id"),
    source_version: exactInteger(version, "source_version", 1),
    lines: evaluation.journal_preview.lines,
    total_debits_cents: evaluation.journal_preview.total_debits_cents,
    total_credits_cents: evaluation.journal_preview.total_credits_cents
  };
  return { ...input, request_fingerprint: journalFingerprint(input) };
}

export function buildTransferReversalInput({ original, originalLines, pairID, version, clientRequestID, reason }) {
  if (!original || original.source_type !== "finance_transfer_pair" || String(original.source_id) !== String(pairID)) {
    throw new FinanceBankTransferError("bank_transfer_journal_invalid", "The current transfer journal relationship is invalid.", 409);
  }
  const reversed = reverseJournalLines(originalLines);
  const input = {
    client_request_id: uuid(clientRequestID, "client_request_id"),
    entry_date: dateOnly(original.entry_date, "entry_date"),
    entry_kind: "reversal",
    description: `Reversal — ${cleanString(original.description, 180) || "Paired bank transfer"}`,
    reference: cleanString(original.reference, 120) || null,
    reason: cleanString(reason, 500),
    reversal_of_entry_id: String(original.id),
    source_type: "finance_transfer_pair",
    source_id: uuid(pairID, "pair_id"),
    source_version: exactInteger(version, "source_version", 1),
    lines: reversed.lines,
    total_debits_cents: reversed.total_debits_cents,
    total_credits_cents: reversed.total_credits_cents
  };
  return { ...input, request_fingerprint: journalFingerprint(input) };
}

export async function installFinanceBankTransferSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS finance_transfer_pairs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      outflow_transaction_id UUID NOT NULL,
      inflow_transaction_id UUID NOT NULL,
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
      FOREIGN KEY (company_id, outflow_transaction_id) REFERENCES finance_transactions(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, inflow_transaction_id) REFERENCES finance_transactions(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, journal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT,
      CHECK (outflow_transaction_id <> inflow_transaction_id),
      CHECK ((status='posted' AND journal_entry_id IS NOT NULL) OR (status='voided' AND journal_entry_id IS NULL))
    );
    CREATE INDEX IF NOT EXISTS finance_transfer_pairs_company_status_idx
      ON finance_transfer_pairs(company_id, status, updated_at DESC);
    CREATE INDEX IF NOT EXISTS finance_transfer_pairs_company_sources_idx
      ON finance_transfer_pairs(company_id, outflow_transaction_id, inflow_transaction_id);

    CREATE TABLE IF NOT EXISTS finance_transfer_pair_members (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      pair_id UUID NOT NULL,
      finance_transaction_id UUID NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('outflow','inflow')),
      active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, id),
      UNIQUE(company_id, pair_id, role),
      UNIQUE(company_id, pair_id, finance_transaction_id),
      FOREIGN KEY (company_id, pair_id) REFERENCES finance_transfer_pairs(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, finance_transaction_id) REFERENCES finance_transactions(company_id, id) ON DELETE RESTRICT
    );
    CREATE UNIQUE INDEX IF NOT EXISTS finance_transfer_pair_members_active_source_idx
      ON finance_transfer_pair_members(company_id, finance_transaction_id) WHERE active;
    CREATE INDEX IF NOT EXISTS finance_transfer_pair_members_company_pair_idx
      ON finance_transfer_pair_members(company_id, pair_id, active);

    CREATE TABLE IF NOT EXISTS finance_transfer_pair_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      pair_id UUID NOT NULL,
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
      FOREIGN KEY (company_id, pair_id) REFERENCES finance_transfer_pairs(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, previous_journal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, journal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, reversal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT
    );
    CREATE INDEX IF NOT EXISTS finance_transfer_pair_audit_company_pair_idx
      ON finance_transfer_pair_audit(company_id, pair_id, created_at DESC);
  `);
}

function financeAccountPayload(bundle) {
  return {
    id: String(bundle.financeAccount.id),
    name: bundle.financeAccount.name,
    account_type: bundle.financeAccount.account_type,
    source: bundle.financeAccount.source,
    currency: (bundle.financeAccount.currency || "usd").toLowerCase(),
    institution_name: bundle.financeAccount.institution_name || null,
    archived: Boolean(bundle.financeAccount.archived_at),
    mapping: bundle.mapping ? {
      id: String(bundle.mapping.id),
      finance_account_id: String(bundle.financeAccount.id),
      chart_account_id: bundle.mapping.chart_account_id || null,
      chart_account_code: bundle.chartAccount?.code || null,
      chart_account_name: bundle.chartAccount?.name || null,
      chart_account_type: bundle.chartAccount?.account_type || null,
      chart_account_active: bundle.chartAccount ? bundle.chartAccount.active !== false : null,
      version: Number(bundle.mapping.version || 0),
      reason: bundle.mapping.reason || null,
      updated_by: bundle.mapping.updated_by || null,
      updated_at: bundle.mapping.updated_at || null
    } : null
  };
}

function candidatePayload(bundle, currentPairID = null) {
  const evaluation = evaluateBankTransferCandidate(bundle);
  const split = bundle.splits[0];
  const pairedElsewhere = evaluation.active_pair_id && evaluation.active_pair_id !== currentPairID;
  return {
    transaction_id: String(bundle.transaction.id),
    transaction_date: dateOnly(bundle.transaction.transaction_date),
    merchant_name: bundle.transaction.merchant_name || bundle.transaction.original_name || "Transaction",
    direction: bundle.transaction.direction,
    amount_cents: storedInteger(bundle.transaction.amount_cents, "amount_cents"),
    reconciliation_status: bundle.transaction.reconciliation_status || "unreconciled",
    accounting_version: Number(bundle.transaction.accounting_version || 1),
    finance_account: financeAccountPayload(bundle),
    allocation: split ? {
      chart_account_id: String(split.chart_account_id),
      chart_account_code: split.code || null,
      chart_account_name: split.name || null,
      account_type: split.account_type,
      amount_cents: storedInteger(split.amount_cents, "allocation_amount_cents")
    } : null,
    role: evaluation.role,
    eligible: evaluation.eligible && !pairedElsewhere,
    blockers: pairedElsewhere
      ? [...evaluation.blockers, blocker("transfer_already_paired", "This source already belongs to an active transfer pair.")]
      : evaluation.blockers,
    active_pair_id: evaluation.active_pair_id
  };
}

function pairHeaderPayload(pair) {
  return {
    id: String(pair.id),
    status: pair.status,
    version: Number(pair.version || 0),
    source_fingerprint: pair.source_fingerprint,
    journal_entry_id: pair.journal_entry_id || null,
    reason: pair.reason || null,
    updated_by: pair.updated_by || null,
    updated_at: pair.updated_at || null
  };
}

function pairPayload(pair, outflow, inflow) {
  const evaluation = evaluateBankTransferPair({ outflow, inflow, pair });
  return {
    ...pairHeaderPayload(pair),
    outflow: candidatePayload(outflow, String(pair.id)),
    inflow: candidatePayload(inflow, String(pair.id)),
    ...evaluation
  };
}

function groupRows(rows, field) {
  const result = new Map();
  for (const row of rows) {
    const key = String(row[field]);
    result.set(key, [...(result.get(key) || []), row]);
  }
  return result;
}

async function loadBundles(poolOrClient, companyID, transactionRows) {
  if (!transactionRows.length) return [];
  const ids = transactionRows.map((row) => row.id);
  const accountIDs = [...new Set(transactionRows.map((row) => row.account_id))];
  const [splitResult, refResult, mappingResult, membershipResult, postingResult] = await Promise.all([
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
      [companyID, accountIDs]
    ),
    poolOrClient.query(
      `SELECT pair_id, finance_transaction_id, role FROM finance_transfer_pair_members
        WHERE company_id=$1 AND finance_transaction_id=ANY($2::uuid[]) AND active`,
      [companyID, ids]
    ),
    poolOrClient.query(
      `SELECT * FROM finance_bank_transaction_postings
        WHERE company_id=$1 AND finance_transaction_id=ANY($2::uuid[])`,
      [companyID, ids]
    )
  ]);
  const splits = groupRows(splitResult.rows, "transaction_id");
  const refs = groupRows(refResult.rows, "transaction_id");
  const mappingByAccount = new Map(mappingResult.rows.map((row) => [String(row.finance_account_id), row]));
  const memberByTransaction = new Map(membershipResult.rows.map((row) => [String(row.finance_transaction_id), row]));
  const postingByTransaction = new Map(postingResult.rows.map((row) => [String(row.finance_transaction_id), row]));
  return transactionRows.map((row) => {
    const mapping = mappingByAccount.get(String(row.account_id)) || null;
    return {
      transaction: row,
      financeAccount: {
        id: row.account_id,
        name: row.finance_account_name,
        account_type: row.finance_account_type,
        source: row.finance_account_source,
        currency: row.currency,
        institution_name: row.institution_name,
        archived_at: row.archived_at
      },
      mapping,
      chartAccount: mapping?.chart_account_id ? {
        id: mapping.chart_account_id,
        code: mapping.code,
        name: mapping.name,
        account_type: mapping.account_type,
        active: mapping.active
      } : null,
      splits: splits.get(String(row.id)) || [],
      providerRefs: refs.get(String(row.id)) || [],
      activeMembership: memberByTransaction.get(String(row.id)) || null,
      bankPosting: postingByTransaction.get(String(row.id)) || null
    };
  });
}

const SOURCE_SELECT = `SELECT t.*, a.name AS finance_account_name, a.account_type AS finance_account_type,
                              a.source AS finance_account_source, a.currency, a.institution_name, a.archived_at
                         FROM finance_transactions t
                         JOIN finance_accounts a ON a.company_id=t.company_id AND a.id=t.account_id`;

async function loadBundleMap(poolOrClient, companyID, transactionIDs) {
  const ids = [...new Set(transactionIDs.map(String))];
  const result = await poolOrClient.query(
    `${SOURCE_SELECT} WHERE t.company_id=$1 AND t.id=ANY($2::uuid[]) ORDER BY t.id`,
    [companyID, ids]
  );
  if (result.rows.length !== ids.length) throw new FinanceBankTransferError("bank_transfer_source_not_found", "One or more transfer sources were not found.", 404);
  return new Map((await loadBundles(poolOrClient, companyID, result.rows)).map((bundle) => [String(bundle.transaction.id), bundle]));
}

async function loadLockedBundleMap(client, companyID, transactionIDs) {
  const ids = [...new Set(transactionIDs.map(String))].sort();
  const result = await client.query(
    `${SOURCE_SELECT} WHERE t.company_id=$1 AND t.id=ANY($2::uuid[]) ORDER BY t.id FOR UPDATE OF t, a`,
    [companyID, ids]
  );
  if (result.rows.length !== ids.length) throw new FinanceBankTransferError("bank_transfer_source_not_found", "One or more transfer sources were not found.", 404);
  const bundles = [];
  for (const row of result.rows) {
    const mappingResult = await client.query(
      `SELECT m.*, c.code, c.name, c.account_type, c.active
         FROM finance_account_chart_mappings m
         LEFT JOIN finance_chart_accounts c ON c.company_id=m.company_id AND c.id=m.chart_account_id
        WHERE m.company_id=$1 AND m.finance_account_id=$2 FOR UPDATE OF m`,
      [companyID, row.account_id]
    );
    if (mappingResult.rows[0]?.chart_account_id) {
      await client.query(
        `SELECT id FROM finance_chart_accounts WHERE company_id=$1 AND id=$2 FOR SHARE`,
        [companyID, mappingResult.rows[0].chart_account_id]
      );
    }
    const splitResult = await client.query(
      `SELECT s.*, c.code, c.name, c.account_type, c.active
         FROM finance_transaction_splits s
         JOIN finance_chart_accounts c ON c.company_id=s.company_id AND c.id=s.chart_account_id
        WHERE s.company_id=$1 AND s.transaction_id=$2 ORDER BY c.code, s.id FOR SHARE OF s, c`,
      [companyID, row.id]
    );
    const refResult = await client.query(
      `SELECT provider, provider_transaction_id, is_current FROM finance_transaction_provider_refs
        WHERE company_id=$1 AND transaction_id=$2 ORDER BY provider, provider_transaction_id FOR SHARE`,
      [companyID, row.id]
    );
    const postingResult = await client.query(
      `SELECT * FROM finance_bank_transaction_postings
        WHERE company_id=$1 AND finance_transaction_id=$2 FOR UPDATE`,
      [companyID, row.id]
    );
    const membershipResult = await client.query(
      `SELECT pair_id, finance_transaction_id, role FROM finance_transfer_pair_members
        WHERE company_id=$1 AND finance_transaction_id=$2 AND active FOR UPDATE`,
      [companyID, row.id]
    );
    const mapping = mappingResult.rows[0] || null;
    bundles.push({
      transaction: row,
      financeAccount: {
        id: row.account_id,
        name: row.finance_account_name,
        account_type: row.finance_account_type,
        source: row.finance_account_source,
        currency: row.currency,
        institution_name: row.institution_name,
        archived_at: row.archived_at
      },
      mapping,
      chartAccount: mapping?.chart_account_id ? {
        id: mapping.chart_account_id,
        code: mapping.code,
        name: mapping.name,
        account_type: mapping.account_type,
        active: mapping.active
      } : null,
      splits: splitResult.rows,
      providerRefs: refResult.rows,
      activeMembership: membershipResult.rows[0] || null,
      bankPosting: postingResult.rows[0] || null
    });
  }
  return new Map(bundles.map((bundle) => [String(bundle.transaction.id), bundle]));
}

async function loadPairDetail(poolOrClient, companyID, pairID) {
  const pairResult = await poolOrClient.query(`SELECT * FROM finance_transfer_pairs WHERE company_id=$1 AND id=$2`, [companyID, pairID]);
  const pair = pairResult.rows[0];
  if (!pair) throw new FinanceBankTransferError("bank_transfer_pair_not_found", "Transfer pair was not found.", 404);
  const bundles = await loadBundleMap(poolOrClient, companyID, [pair.outflow_transaction_id, pair.inflow_transaction_id]);
  const audit = await poolOrClient.query(
    `SELECT id, action, reason, version, actor_user_id, previous_journal_entry_id,
            journal_entry_id, reversal_entry_id, created_at
       FROM finance_transfer_pair_audit WHERE company_id=$1 AND pair_id=$2
      ORDER BY created_at DESC LIMIT 50`,
    [companyID, pairID]
  );
  return {
    pair: pairPayload(pair, bundles.get(String(pair.outflow_transaction_id)), bundles.get(String(pair.inflow_transaction_id))),
    audit: audit.rows.map((row) => ({
      id: String(row.id), action: row.action, reason: row.reason, version: Number(row.version),
      actor_user_id: row.actor_user_id || null, previous_journal_entry_id: row.previous_journal_entry_id || null,
      journal_entry_id: row.journal_entry_id || null, reversal_entry_id: row.reversal_entry_id || null,
      created_at: row.created_at || null
    }))
  };
}

async function loadTransferReport(poolOrClient, companyID, range, limit) {
  const candidateResult = await poolOrClient.query(
    `${SOURCE_SELECT}
      WHERE t.company_id=$1 AND t.transaction_date >= $2::date AND t.transaction_date <= $3::date
        AND EXISTS (
          SELECT 1 FROM finance_transaction_splits s
          JOIN finance_chart_accounts c ON c.company_id=s.company_id AND c.id=s.chart_account_id
          WHERE s.company_id=t.company_id AND s.transaction_id=t.id AND c.account_type IN ('asset','liability')
        )
      ORDER BY t.transaction_date DESC, t.created_at DESC, t.id LIMIT $4`,
    [companyID, range.start_date, range.end_date, limit + 1]
  );
  const candidatesTruncated = candidateResult.rows.length > limit;
  const candidateBundles = await loadBundles(poolOrClient, companyID, candidateResult.rows.slice(0, limit));
  const pairResult = await poolOrClient.query(
    `SELECT p.* FROM finance_transfer_pairs p
      JOIN finance_transactions out_tx ON out_tx.company_id=p.company_id AND out_tx.id=p.outflow_transaction_id
      JOIN finance_transactions in_tx ON in_tx.company_id=p.company_id AND in_tx.id=p.inflow_transaction_id
      WHERE p.company_id=$1 AND (
        out_tx.transaction_date BETWEEN $2::date AND $3::date OR in_tx.transaction_date BETWEEN $2::date AND $3::date
      ) ORDER BY p.updated_at DESC, p.id LIMIT $4`,
    [companyID, range.start_date, range.end_date, limit + 1]
  );
  const pairsTruncated = pairResult.rows.length > limit;
  const pairs = pairResult.rows.slice(0, limit);
  const pairBundles = pairs.length
    ? await loadBundleMap(poolOrClient, companyID, pairs.flatMap((pair) => [pair.outflow_transaction_id, pair.inflow_transaction_id]))
    : new Map();
  return {
    basis: "explicit_paired_bank_transfers",
    start_date: range.start_date,
    end_date: range.end_date,
    currency: "usd",
    candidates: candidateBundles.map(candidatePayload),
    candidates_truncated: candidatesTruncated,
    pairs: pairs.map((pair) => pairPayload(
      pair,
      pairBundles.get(String(pair.outflow_transaction_id)),
      pairBundles.get(String(pair.inflow_transaction_id))
    )),
    pairs_truncated: pairsTruncated,
    warnings: [
      "Transfer pairs are created only from two explicitly selected stable transaction IDs; WolfCRM never pairs by amount, date, or description.",
      "One pair creates one journal. The individual bank sides remain excluded from Phase 4B standalone posting and the Phase 1 cash Profit & Loss report is unchanged.",
      "Borrowing, owner activity, asset purchases, customer credits, operational settlements, Stripe, and payroll remain separate later workflows."
    ]
  };
}

async function replayedRequest(client, companyID, input) {
  const { rows } = await client.query(
    `SELECT pair_id, request_fingerprint FROM finance_transfer_pair_audit
      WHERE company_id=$1 AND client_request_id=$2::uuid FOR SHARE`,
    [companyID, input.client_request_id]
  );
  if (!rows.length) return null;
  if (rows[0].request_fingerprint !== input.request_fingerprint) {
    throw new FinanceBankTransferError("bank_transfer_request_id_conflict", "That transfer request ID was already used with different content.", 409);
  }
  return String(rows[0].pair_id);
}

async function insertLedgerAudit(client, companyID, userID, entry, relatedEntry, action, reason, input) {
  await client.query(
    `INSERT INTO finance_journal_audit (company_id, entry_id, related_entry_id, actor_user_id, action, reason, entry_snapshot)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [companyID, entry.id, relatedEntry || null, userID, action, reason, JSON.stringify(snapshotInput(input))]
  );
}

async function loadOriginalJournal(client, companyID, pair) {
  if (!pair.journal_entry_id) throw new FinanceBankTransferError("bank_transfer_journal_invalid", "The current transfer pair has no journal authority.", 409);
  const originalResult = await client.query(`SELECT * FROM finance_journal_entries WHERE company_id=$1 AND id=$2 FOR UPDATE`, [companyID, pair.journal_entry_id]);
  const original = originalResult.rows[0];
  const lineResult = await client.query(
    `SELECT chart_account_id, debit_cents, credit_cents, memo FROM finance_journal_lines
      WHERE company_id=$1 AND entry_id=$2 ORDER BY line_order FOR SHARE`,
    [companyID, pair.journal_entry_id]
  );
  const existingReversal = await client.query(`SELECT id FROM finance_journal_entries WHERE company_id=$1 AND reversal_of_entry_id=$2 FOR UPDATE`, [companyID, pair.journal_entry_id]);
  if (existingReversal.rows.length) throw new FinanceBankTransferError("bank_transfer_already_reversed", "The current transfer journal already has a reversal.", 409);
  return { original, lines: lineResult.rows };
}

function sendTransferError(res, error, fallback) {
  if (error instanceof FinanceBankTransferError || error instanceof GeneralLedgerError || error?.statusCode) {
    return res.status(error.statusCode || 400).json({
      error: error.code || fallback,
      message: error.message,
      blockers: error.blockers,
      current_version: error.current_version,
      current_pair_version: error.current_pair_version
    });
  }
  if (error?.code === "23505") return res.status(409).json({ error: "bank_transfer_conflict", message: "One of those sources already belongs to an active transfer pair." });
  console.error("[finance-bank-transfers]", fallback, { code: error?.code, message: error?.message });
  return res.status(500).json({ error: fallback, message: "Bank transfer request failed." });
}

export function installFinanceBankTransferRoutes({ app, pool, authRequired, requireFinanceAccess, ensureChartAccounts }) {
  app.get("/api/finance/accounting/transfers", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Transfer pairing requires a company workspace." });
    try {
      const context = await loadCompanyContext(pool, req.companyId);
      const end = req.query.end_date || context.company_today;
      const start = req.query.start_date || `${end.slice(0, 7)}-01`;
      await ensureChartAccounts(pool, req.companyId, req.userId);
      res.json({ timezone: context.timezone, company_today: context.company_today, ...(await loadTransferReport(pool, req.companyId, parseBankTransferRange(start, end), boundedLimit(req.query.limit))) });
    } catch (error) {
      sendTransferError(res, error, "bank_transfer_report_failed");
    }
  });

  app.get("/api/finance/accounting/transfers/preview", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Transfer pairing requires a company workspace." });
    try {
      const outflowID = uuid(req.query.outflow_transaction_id, "outflow_transaction_id");
      const inflowID = uuid(req.query.inflow_transaction_id, "inflow_transaction_id");
      if (outflowID === inflowID) throw new FinanceBankTransferError("transfer_sources_same", "Choose two different transactions.");
      const bundles = await loadBundleMap(pool, req.companyId, [outflowID, inflowID]);
      const outflow = bundles.get(outflowID);
      const inflow = bundles.get(inflowID);
      res.json({
        outflow: candidatePayload(outflow),
        inflow: candidatePayload(inflow),
        ...evaluateBankTransferPair({ outflow, inflow })
      });
    } catch (error) {
      sendTransferError(res, error, "bank_transfer_preview_failed");
    }
  });

  app.get("/api/finance/accounting/transfers/:pairId", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Transfer pairing requires a company workspace." });
    try {
      res.json(await loadPairDetail(pool, req.companyId, uuid(req.params.pairId, "pair_id")));
    } catch (error) {
      sendTransferError(res, error, "bank_transfer_detail_failed");
    }
  });

  app.post("/api/finance/accounting/transfers", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Transfer pairing requires a company workspace." });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const request = normalizeTransferCreateRequest(req.body);
      let replayPairID = await replayedRequest(client, req.companyId, request);
      if (replayPairID) {
        await client.query("COMMIT");
        return res.json({ replayed: true, ...(await loadPairDetail(pool, req.companyId, replayPairID)) });
      }
      const bundles = await loadLockedBundleMap(client, req.companyId, [request.outflow_transaction_id, request.inflow_transaction_id]);
      replayPairID = await replayedRequest(client, req.companyId, request);
      if (replayPairID) {
        await client.query("COMMIT");
        return res.json({ replayed: true, ...(await loadPairDetail(pool, req.companyId, replayPairID)) });
      }
      const outflow = bundles.get(request.outflow_transaction_id);
      const inflow = bundles.get(request.inflow_transaction_id);
      assertCreateVersions(request, outflow, inflow);
      const evaluation = evaluateBankTransferPair({ outflow, inflow });
      if (!evaluation.eligible) throw new FinanceBankTransferError("bank_transfer_blocked", "Resolve every transfer blocker before posting.", 409, { blockers: evaluation.blockers });
      const pairID = randomUUID();
      const journalInput = buildTransferJournalInput({ evaluation, pairID, version: 1, clientRequestID: request.client_request_id, reason: request.reason });
      const journal = await insertJournal(client, req.companyId, req.userId, journalInput);
      await insertLedgerAudit(client, req.companyId, req.userId, journal, null, "bank_transfer_posted", request.reason, journalInput);
      const pair = (await client.query(
        `INSERT INTO finance_transfer_pairs (
           id, company_id, outflow_transaction_id, inflow_transaction_id, journal_entry_id,
           status, version, source_fingerprint, source_snapshot, reason, updated_by
         ) VALUES ($1,$2,$3,$4,$5,'posted',1,$6,$7,$8,$9) RETURNING *`,
        [pairID, req.companyId, request.outflow_transaction_id, request.inflow_transaction_id, journal.id,
          evaluation.source_fingerprint, JSON.stringify(evaluation.source_snapshot), request.reason, req.userId]
      )).rows[0];
      await client.query(
        `INSERT INTO finance_transfer_pair_members (company_id, pair_id, finance_transaction_id, role)
         VALUES ($1,$2,$3,'outflow'),($1,$2,$4,'inflow')`,
        [req.companyId, pairID, request.outflow_transaction_id, request.inflow_transaction_id]
      );
      await client.query(
        `INSERT INTO finance_transfer_pair_audit (
           company_id, pair_id, actor_user_id, action, reason, version, client_request_id,
           request_fingerprint, source_fingerprint, source_snapshot, journal_entry_id
         ) VALUES ($1,$2,$3,'transfer_posted',$4,1,$5::uuid,$6,$7,$8,$9)`,
        [req.companyId, pairID, req.userId, request.reason, request.client_request_id,
          request.request_fingerprint, evaluation.source_fingerprint, JSON.stringify(evaluation.source_snapshot), journal.id]
      );
      await client.query("COMMIT");
      res.status(201).json({ replayed: false, ...(await loadPairDetail(pool, req.companyId, pair.id)) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendTransferError(res, error, "bank_transfer_create_failed");
    } finally {
      client.release();
    }
  });

  const mutatePair = (action) => async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Transfer pairing requires a company workspace." });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const request = normalizeTransferActionRequest({ body: req.body, pairID: req.params.pairId, action });
      let replayPairID = await replayedRequest(client, req.companyId, request);
      if (replayPairID) {
        if (replayPairID !== request.pair_id) throw new FinanceBankTransferError("bank_transfer_request_id_conflict", "That transfer request belongs to another pair.", 409);
        await client.query("COMMIT");
        return res.json({ replayed: true, ...(await loadPairDetail(pool, req.companyId, request.pair_id)) });
      }
      const unlockedPair = (await client.query(`SELECT * FROM finance_transfer_pairs WHERE company_id=$1 AND id=$2`, [req.companyId, request.pair_id])).rows[0];
      if (!unlockedPair) throw new FinanceBankTransferError("bank_transfer_pair_not_found", "Transfer pair was not found.", 404);
      const bundles = await loadLockedBundleMap(client, req.companyId, [unlockedPair.outflow_transaction_id, unlockedPair.inflow_transaction_id]);
      const pair = (await client.query(`SELECT * FROM finance_transfer_pairs WHERE company_id=$1 AND id=$2 FOR UPDATE`, [req.companyId, request.pair_id])).rows[0];
      replayPairID = await replayedRequest(client, req.companyId, request);
      if (replayPairID) {
        await client.query("COMMIT");
        return res.json({ replayed: true, ...(await loadPairDetail(pool, req.companyId, request.pair_id)) });
      }
      const outflow = bundles.get(String(pair.outflow_transaction_id));
      const inflow = bundles.get(String(pair.inflow_transaction_id));
      assertActionVersions(request, pair, outflow, inflow);
      if (pair.status !== "posted" || !pair.journal_entry_id) throw new FinanceBankTransferError("bank_transfer_not_posted", "Only a currently posted transfer pair can be changed.", 409);
      const evaluation = evaluateBankTransferPair({ outflow, inflow, pair });
      if (action === "post" && !evaluation.eligible) throw new FinanceBankTransferError("bank_transfer_blocked", "Resolve every transfer blocker before replacing this pair.", 409, { blockers: evaluation.blockers });
      if (action === "post" && evaluation.source_current) {
        await client.query(
          `INSERT INTO finance_transfer_pair_audit (
             company_id, pair_id, actor_user_id, action, reason, version, client_request_id,
             request_fingerprint, source_fingerprint, source_snapshot,
             previous_journal_entry_id, journal_entry_id
           ) VALUES ($1,$2,$3,'transfer_reviewed',$4,$5,$6::uuid,$7,$8,$9,$10,$10)`,
          [req.companyId, pair.id, req.userId, request.reason, pair.version, request.client_request_id,
            request.request_fingerprint, evaluation.source_fingerprint, JSON.stringify(evaluation.source_snapshot), pair.journal_entry_id]
        );
        await client.query("COMMIT");
        return res.json({ replayed: false, ...(await loadPairDetail(pool, req.companyId, pair.id)) });
      }
      const nextVersion = pairVersion(pair) + 1;
      const prior = await loadOriginalJournal(client, req.companyId, pair);
      const reversalInput = buildTransferReversalInput({
        original: prior.original,
        originalLines: prior.lines,
        pairID: pair.id,
        version: nextVersion,
        clientRequestID: action === "void" ? request.client_request_id : randomUUID(),
        reason: request.reason
      });
      const reversal = await insertJournal(client, req.companyId, req.userId, reversalInput);
      await insertLedgerAudit(client, req.companyId, req.userId, reversal, prior.original.id, "bank_transfer_reversal_posted", request.reason, reversalInput);
      await insertLedgerAudit(client, req.companyId, req.userId, prior.original, reversal.id, "bank_transfer_reversed", request.reason, reversalInput);
      let journal = null;
      if (action === "post") {
        const journalInput = buildTransferJournalInput({
          evaluation,
          pairID: pair.id,
          version: nextVersion,
          clientRequestID: request.client_request_id,
          reason: request.reason
        });
        journal = await insertJournal(client, req.companyId, req.userId, journalInput);
        await insertLedgerAudit(client, req.companyId, req.userId, journal, reversal.id, "bank_transfer_posted", request.reason, journalInput);
      }
      const updated = (await client.query(
        `UPDATE finance_transfer_pairs
            SET journal_entry_id=$3, status=$4, version=version+1, source_fingerprint=$5,
                source_snapshot=$6, reason=$7, updated_by=$8, updated_at=now()
          WHERE company_id=$1 AND id=$2 RETURNING *`,
        [req.companyId, pair.id, journal?.id || null, action === "post" ? "posted" : "voided",
          evaluation.source_fingerprint, JSON.stringify(evaluation.source_snapshot), request.reason, req.userId]
      )).rows[0];
      if (action === "void") {
        await client.query(
          `UPDATE finance_transfer_pair_members SET active=false, updated_at=now()
            WHERE company_id=$1 AND pair_id=$2 AND active`,
          [req.companyId, pair.id]
        );
      }
      await client.query(
        `INSERT INTO finance_transfer_pair_audit (
           company_id, pair_id, actor_user_id, action, reason, version, client_request_id,
           request_fingerprint, source_fingerprint, source_snapshot,
           previous_journal_entry_id, journal_entry_id, reversal_entry_id
         ) VALUES ($1,$2,$3,$4,$5,$6,$7::uuid,$8,$9,$10,$11,$12,$13)`,
        [req.companyId, pair.id, req.userId, action === "void" ? "transfer_voided" : "transfer_replaced",
          request.reason, updated.version, request.client_request_id, request.request_fingerprint,
          evaluation.source_fingerprint, JSON.stringify(evaluation.source_snapshot), pair.journal_entry_id,
          journal?.id || null, reversal.id]
      );
      await client.query("COMMIT");
      res.status(201).json({ replayed: false, ...(await loadPairDetail(pool, req.companyId, pair.id)) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendTransferError(res, error, `bank_transfer_${action}_failed`);
    } finally {
      client.release();
    }
  };

  app.post("/api/finance/accounting/transfers/:pairId/post", authRequired, requireFinanceAccess, mutatePair("post"));
  app.post("/api/finance/accounting/transfers/:pairId/void", authRequired, requireFinanceAccess, mutatePair("void"));
}
