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
const COLLECTED_STATUSES = new Set(["succeeded", "paid", "partially_refunded", "refunded"]);
const MAX_REPORT_DAYS = 731;
const MAX_REPORT_ROWS = 200;

export class FinanceOperationalApplicationError extends Error {
  constructor(code, message, statusCode = 400, details = {}) {
    super(message);
    this.name = "FinanceOperationalApplicationError";
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
    throw new FinanceOperationalApplicationError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return normalized;
}

function exactInteger(value, field, minimum = 0) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value.trim()) ? Number(value.trim()) : value;
  if (!Number.isSafeInteger(parsed) || parsed < minimum) {
    throw new FinanceOperationalApplicationError(`${field}_invalid`, `${field.replaceAll("_", " ")} must be an exact integer.`);
  }
  return parsed;
}

function storedInteger(value, field) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(parsed)) {
    throw new FinanceOperationalApplicationError("operational_application_amount_inexact", `${field.replaceAll("_", " ")} exceeds the exact supported range.`, 409);
  }
  return parsed;
}

function addExact(left, right, field) {
  const next = left + right;
  if (!Number.isSafeInteger(next)) {
    throw new FinanceOperationalApplicationError("operational_application_amount_inexact", `${field.replaceAll("_", " ")} exceeds the exact supported range.`, 409);
  }
  return next;
}

function dateOnly(value, field = "date") {
  const raw = value instanceof Date ? value.toISOString().slice(0, 10) : cleanString(value, 20);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    throw new FinanceOperationalApplicationError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  const [year, month, day] = raw.split("-").map(Number);
  const parsed = new Date(Date.UTC(year, month - 1, day));
  if (parsed.getUTCFullYear() !== year || parsed.getUTCMonth() !== month - 1 || parsed.getUTCDate() !== day) {
    throw new FinanceOperationalApplicationError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
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

const LIVE_CAPACITY_FIELDS = new Set([
  "target_open_ar_cents",
  "dependent_refund_ar_cents",
  "dependent_refund_credit_cents",
  "dependent_credit_cents",
  "dependent_earliest_date",
  "prior_refund_ar_cents",
  "prior_refund_credit_cents",
  "used_customer_credit_cents",
  "available_ar_cents",
  "available_customer_credit_cents"
]);

function sourceAuthorityFingerprint(snapshot) {
  return fingerprint(Object.fromEntries(
    Object.entries(snapshot).filter(([key]) => !LIVE_CAPACITY_FIELDS.has(key))
  ));
}

function blocker(code, message) {
  return { code, message };
}

function normalizedInstant(value) {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed.toISOString() : null;
}

function objectValue(value) {
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

function appVersion(application) {
  return application ? Number(application.version || 0) : 0;
}

function uniqueBlockers(items) {
  return [...new Map(items.map((item) => [item.code, item])).values()];
}

function accountSnapshot(account) {
  return account ? {
    chart_account_id: String(account.id),
    account_type: account.account_type,
    system_key: account.system_key || null,
    active: account.active !== false
  } : null;
}

function validSystemAccount(account, systemKey, accountType) {
  return Boolean(account && account.active !== false && account.system_key === systemKey && account.account_type === accountType);
}

export function parseOperationalApplicationRange(startValue, endValue) {
  const startDate = dateOnly(startValue, "start_date");
  const endDate = dateOnly(endValue, "end_date");
  if (startDate > endDate) {
    throw new FinanceOperationalApplicationError("operational_application_range_invalid", "Start date must be on or before end date.");
  }
  if (addDays(startDate, MAX_REPORT_DAYS - 1) < endDate) {
    throw new FinanceOperationalApplicationError("operational_application_range_too_large", `Payment-application ranges cannot exceed ${MAX_REPORT_DAYS} days.`);
  }
  return { start_date: startDate, end_date: endDate };
}

function boundedLimit(value) {
  if (value === undefined || value === null || value === "") return 100;
  return Math.min(exactInteger(value, "limit", 1), MAX_REPORT_ROWS);
}

export function planRefundRevision({ previousCumulativeCents = 0, nextCumulativeCents, refundAmountKnown = true }) {
  const previous = exactInteger(previousCumulativeCents, "previous_cumulative_cents");
  const next = exactInteger(nextCumulativeCents, "next_cumulative_cents");
  if (!refundAmountKnown || next <= previous) return null;
  return {
    cumulative_refunded_cents: next,
    delta_refunded_cents: next - previous
  };
}

export function normalizeApplicationAllocation({ amountCents, accountsReceivableCents = 0, customerCreditCents = 0 }) {
  const amount = exactInteger(amountCents, "amount_cents", 1);
  const accountsReceivable = exactInteger(accountsReceivableCents, "accounts_receivable_cents");
  const customerCredit = exactInteger(customerCreditCents, "customer_credit_cents");
  if (addExact(accountsReceivable, customerCredit, "allocation_cents") !== amount) {
    throw new FinanceOperationalApplicationError("operational_application_allocation_unbalanced", "Accounts Receivable and Customer Credits must equal the exact application amount.");
  }
  return {
    amount_cents: amount,
    accounts_receivable_cents: accountsReceivable,
    customer_credit_cents: customerCredit
  };
}

function applicationState(application, sourceFingerprint, eligible, hasDependencies = false) {
  const sourceCurrent = application?.status === "posted" && application.source_fingerprint === sourceFingerprint;
  let reviewState = "blocked";
  if (sourceCurrent) reviewState = "posted";
  else if (application?.status === "posted") reviewState = "stale";
  else if (application?.status === "voided") reviewState = "voided";
  else if (eligible) reviewState = "ready";
  return {
    review_state: reviewState,
    source_current: sourceCurrent,
    can_post: eligible && !sourceCurrent,
    can_void: application?.status === "posted" && Boolean(application.journal_entry_id) && !hasDependencies
  };
}

function applicationPreview(kind, snapshot, accounts, allocation) {
  const lines = [];
  if (kind === "payment") {
    lines.push({ position: 0, chart_account_id: String(accounts.clearing.id), debit_cents: allocation.amount_cents, credit_cents: 0, memo: "Payment provider clearing" });
    if (allocation.accounts_receivable_cents > 0) lines.push({ position: lines.length, chart_account_id: String(accounts.accountsReceivable.id), debit_cents: 0, credit_cents: allocation.accounts_receivable_cents, memo: "Payment applied to Accounts Receivable" });
    if (allocation.customer_credit_cents > 0) lines.push({ position: lines.length, chart_account_id: String(accounts.customerCredits.id), debit_cents: 0, credit_cents: allocation.customer_credit_cents, memo: "Payment retained as customer credit" });
  } else if (kind === "refund") {
    if (allocation.accounts_receivable_cents > 0) lines.push({ position: lines.length, chart_account_id: String(accounts.accountsReceivable.id), debit_cents: allocation.accounts_receivable_cents, credit_cents: 0, memo: "Refund returned to Accounts Receivable" });
    if (allocation.customer_credit_cents > 0) lines.push({ position: lines.length, chart_account_id: String(accounts.customerCredits.id), debit_cents: allocation.customer_credit_cents, credit_cents: 0, memo: "Refund consumed customer credit" });
    lines.push({ position: lines.length, chart_account_id: String(accounts.clearing.id), debit_cents: 0, credit_cents: allocation.amount_cents, memo: "Refund from payment provider clearing" });
  } else {
    lines.push({ position: 0, chart_account_id: String(accounts.customerCredits.id), debit_cents: allocation.amount_cents, credit_cents: 0, memo: "Customer credit applied" });
    lines.push({ position: 1, chart_account_id: String(accounts.accountsReceivable.id), debit_cents: 0, credit_cents: allocation.amount_cents, memo: "Customer credit applied to Accounts Receivable" });
  }
  return {
    entry_date: snapshot.entry_date,
    total_debits_cents: allocation.amount_cents,
    total_credits_cents: allocation.amount_cents,
    lines
  };
}

function validateAccounts(accounts, blockers, needsClearing = true) {
  if (!validSystemAccount(accounts?.accountsReceivable, "accounts_receivable", "asset")) {
    blockers.push(blocker("accounts_receivable_account_invalid", "The active system Accounts Receivable asset is unavailable."));
  }
  if (!validSystemAccount(accounts?.customerCredits, "customer_credits", "liability")) {
    blockers.push(blocker("customer_credits_account_invalid", "The active system Customer Credits liability is unavailable."));
  }
  if (needsClearing && !validSystemAccount(accounts?.clearing, "payment_clearing", "asset")) {
    blockers.push(blocker("payment_clearing_account_invalid", "The active system Payment Clearing asset is unavailable."));
  }
}

export function evaluatePaymentApplication({ source, payment = null, application = null, accounts = {}, receivableAuthority = null, allocation, dependentRefundCents = 0, dependentCreditCents = 0, dependentEarliestDate = null }) {
  if (!source) throw new FinanceOperationalApplicationError("payment_application_source_not_found", "Payment source was not found.", 404);
  const blockers = [];
  const amount = storedInteger(source.amount_cents ?? 0, "amount_cents");
  const sourceVersion = Number(source.source_version || 0);
  const targetOpen = storedInteger(receivableAuthority?.open_cents ?? 0, "target_open_ar_cents");
  const dependencies = addExact(storedInteger(dependentRefundCents, "dependent_refund_cents"), storedInteger(dependentCreditCents, "dependent_credit_cents"), "dependent_cents");
  let normalized = null;
  try {
    normalized = normalizeApplicationAllocation({
      amountCents: amount,
      accountsReceivableCents: allocation?.accounts_receivable_cents,
      customerCreditCents: allocation?.customer_credit_cents
    });
  } catch (error) {
    if (!(error instanceof FinanceOperationalApplicationError)) throw error;
    blockers.push(blocker(error.code, error.message));
  }
  if (source.source_type !== "payment") blockers.push(blocker("payment_source_type_invalid", "Only payment operational sources can use this workflow."));
  if (source.removed_at) blockers.push(blocker("payment_source_removed", "The payment source is unavailable."));
  if (!COLLECTED_STATUSES.has(source.status)) blockers.push(blocker("payment_source_not_collected", "The payment is not in a collected state."));
  if (!Number.isSafeInteger(sourceVersion) || sourceVersion < 1) blockers.push(blocker("payment_source_version_invalid", "The payment source version is invalid."));
  if (cleanString(source.currency || "usd", 10).toLowerCase() !== "usd") blockers.push(blocker("payment_currency_unsupported", "Payment applications currently support USD only."));
  if (amount <= 0) blockers.push(blocker("payment_amount_invalid", "The payment needs a positive exact gross amount."));
  if (!source.occurred_at || !source.entry_date) blockers.push(blocker("payment_date_unknown", "The payment needs an authoritative paid date."));
  if (!payment || String(payment.id) !== String(source.payment_record_id)) blockers.push(blocker("payment_record_unavailable", "The payment record is unavailable in this company."));
  if (!source.job_id || !payment?.job_id || String(source.job_id) !== String(payment.job_id)) blockers.push(blocker("payment_job_link_required", "Explicitly link the payment to one job before posting."));
  if (!receivableAuthority?.posted) blockers.push(blocker("payment_receivable_not_posted", "Post the target job receivable before applying its payment."));
  if (normalized && normalized.accounts_receivable_cents > targetOpen) blockers.push(blocker("payment_ar_capacity_exceeded", "The Accounts Receivable allocation exceeds the target job's current open ledger receivable."));
  if (application?.status === "posted") {
    if (storedInteger(application.accounts_receivable_cents, "stored_accounts_receivable_cents") < storedInteger(application.refund_ar_cents ?? 0, "refund_ar_cents")) blockers.push(blocker("payment_dependent_refund_invalid", "Posted refund applications exceed the stored payment allocation."));
    if (storedInteger(application.customer_credit_cents, "stored_customer_credit_cents") < dependencies) blockers.push(blocker("payment_dependent_credit_invalid", "Posted refund or customer-credit applications exceed the stored credit allocation."));
    if (normalized && normalized.accounts_receivable_cents < storedInteger(application.refund_ar_cents ?? 0, "refund_ar_cents")) blockers.push(blocker("payment_ar_dependency_floor", "Void dependent A/R refund applications before reducing this allocation."));
    if (normalized && normalized.customer_credit_cents < dependencies) blockers.push(blocker("payment_credit_dependency_floor", "Void dependent refund or customer-credit applications before reducing this credit allocation."));
    if (dependencies + storedInteger(application.refund_ar_cents ?? 0, "refund_ar_cents") > 0
        && application.job_id && String(application.job_id) !== String(source.job_id || "")) {
      blockers.push(blocker("payment_job_dependency", "Void dependent refund or customer-credit applications before moving this payment to another job."));
    }
    if (dependentEarliestDate && source.entry_date && source.entry_date > dependentEarliestDate) {
      blockers.push(blocker("payment_date_dependency", "Void dependent applications before moving the payment date after them."));
    }
  }
  validateAccounts(accounts, blockers, true);
  const snapshot = {
    application_kind: "payment",
    operational_source_id: String(source.id),
    payment_record_id: String(source.payment_record_id || ""),
    job_id: source.job_id ? String(source.job_id) : null,
    source_version: sourceVersion,
    status: source.status,
    amount_cents: amount,
    currency: cleanString(source.currency || "usd", 10).toLowerCase(),
    occurred_at: normalizedInstant(source.occurred_at),
    entry_date: source.entry_date || null,
    target_receivable_posted: Boolean(receivableAuthority?.posted),
    target_open_ar_cents: targetOpen,
    dependent_refund_ar_cents: storedInteger(application?.refund_ar_cents ?? 0, "dependent_refund_ar_cents"),
    dependent_refund_credit_cents: storedInteger(dependentRefundCents, "dependent_refund_credit_cents"),
    dependent_credit_cents: storedInteger(dependentCreditCents, "dependent_credit_cents"),
    dependent_earliest_date: dependentEarliestDate || null,
    allocation: normalized,
    accounts: {
      accounts_receivable: accountSnapshot(accounts.accountsReceivable),
      customer_credits: accountSnapshot(accounts.customerCredits),
      payment_clearing: accountSnapshot(accounts.clearing)
    }
  };
  const sourceFingerprint = sourceAuthorityFingerprint(snapshot);
  const eligible = blockers.length === 0 && Boolean(normalized);
  const state = applicationState(application, sourceFingerprint, eligible, dependencies > 0 || storedInteger(application?.refund_ar_cents ?? 0, "refund_ar_cents") > 0);
  return {
    eligible,
    blockers: uniqueBlockers(blockers),
    ...state,
    source_fingerprint: sourceFingerprint,
    source_snapshot: snapshot,
    journal_preview: eligible ? applicationPreview("payment", snapshot, accounts, normalized) : null
  };
}

export function evaluateRefundApplication({ revision, originApplication = null, application = null, accounts = {}, allocation, priorRefundARCents = 0, priorRefundCreditCents = 0, usedCustomerCreditCents = 0, receivableAuthority = null }) {
  if (!revision) throw new FinanceOperationalApplicationError("refund_revision_not_found", "Refund revision was not found.", 404);
  const blockers = [];
  const amount = storedInteger(revision.delta_refunded_cents ?? 0, "delta_refunded_cents");
  const priorAR = storedInteger(priorRefundARCents, "prior_refund_ar_cents");
  const priorCredit = storedInteger(priorRefundCreditCents, "prior_refund_credit_cents");
  const usedCredit = storedInteger(usedCustomerCreditCents, "used_customer_credit_cents");
  const originAR = storedInteger(originApplication?.accounts_receivable_cents ?? 0, "origin_ar_cents");
  const originCredit = storedInteger(originApplication?.customer_credit_cents ?? 0, "origin_credit_cents");
  const availableAR = Math.max(0, originAR - priorAR);
  const availableCredit = Math.max(0, originCredit - priorCredit - usedCredit);
  let normalized = null;
  try {
    normalized = normalizeApplicationAllocation({
      amountCents: amount,
      accountsReceivableCents: allocation?.accounts_receivable_cents,
      customerCreditCents: allocation?.customer_credit_cents
    });
  } catch (error) {
    if (!(error instanceof FinanceOperationalApplicationError)) throw error;
    blockers.push(blocker(error.code, error.message));
  }
  if (amount <= 0 || storedInteger(revision.cumulative_refunded_cents ?? 0, "cumulative_refunded_cents") < amount) blockers.push(blocker("refund_revision_amount_invalid", "The refund revision needs a positive exact incremental amount."));
  if (!revision.occurred_at || !revision.entry_date) blockers.push(blocker("refund_revision_date_unknown", "The refund revision needs an authoritative event date before posting."));
  if (!Number.isSafeInteger(Number(revision.version)) || Number(revision.version) < 1) blockers.push(blocker("refund_revision_version_invalid", "The refund revision version is invalid."));
  if (!originApplication || originApplication.kind !== "payment" || originApplication.status !== "posted" || !originApplication.journal_entry_id) blockers.push(blocker("refund_parent_payment_unposted", "Post the original payment allocation before applying this refund."));
  if (originApplication?.source_current === false) blockers.push(blocker("refund_parent_payment_stale", "Review the changed original payment allocation before applying this refund."));
  if (normalized?.accounts_receivable_cents > availableAR) blockers.push(blocker("refund_ar_capacity_exceeded", "The refund A/R allocation exceeds the remaining original payment A/R allocation."));
  if (normalized?.customer_credit_cents > availableCredit) blockers.push(blocker("refund_credit_capacity_exceeded", "The refund credit allocation exceeds unused original customer credit."));
  if ((normalized?.accounts_receivable_cents || 0) > 0 && !receivableAuthority?.posted) blockers.push(blocker("refund_receivable_not_current", "Review the original job receivable before returning this refund to Accounts Receivable."));
  validateAccounts(accounts, blockers, true);
  const snapshot = {
    application_kind: "refund",
    refund_revision_id: String(revision.id),
    payment_record_id: String(revision.payment_record_id),
    origin_application_id: originApplication ? String(originApplication.id) : null,
    job_id: originApplication?.job_id ? String(originApplication.job_id) : null,
    revision_version: Number(revision.version || 0),
    cumulative_refunded_cents: storedInteger(revision.cumulative_refunded_cents ?? 0, "cumulative_refunded_cents"),
    amount_cents: amount,
    occurred_at: normalizedInstant(revision.occurred_at),
    entry_date: revision.entry_date || null,
    event_coverage: revision.event_coverage,
    prior_refund_ar_cents: priorAR,
    prior_refund_credit_cents: priorCredit,
    used_customer_credit_cents: usedCredit,
    available_ar_cents: availableAR,
    available_customer_credit_cents: availableCredit,
    origin_application_version: Number(originApplication?.version || 0),
    origin_application_current: originApplication?.source_current !== false,
    target_receivable_posted: Boolean(receivableAuthority?.posted),
    target_open_ar_cents: storedInteger(receivableAuthority?.open_cents ?? 0, "target_open_ar_cents"),
    allocation: normalized,
    accounts: {
      accounts_receivable: accountSnapshot(accounts.accountsReceivable),
      customer_credits: accountSnapshot(accounts.customerCredits),
      payment_clearing: accountSnapshot(accounts.clearing)
    }
  };
  const sourceFingerprint = sourceAuthorityFingerprint(snapshot);
  const eligible = blockers.length === 0 && Boolean(normalized);
  return {
    eligible,
    blockers: uniqueBlockers(blockers),
    ...applicationState(application, sourceFingerprint, eligible),
    source_fingerprint: sourceFingerprint,
    source_snapshot: snapshot,
    journal_preview: eligible ? applicationPreview("refund", snapshot, accounts, normalized) : null
  };
}

export function evaluateCustomerCreditApplication({ originApplication, targetJob = null, application = null, accounts = {}, entryDate, amountCents, availableCustomerCreditCents = 0, targetReceivableAuthority = null, sameContact = false, companyToday }) {
  if (!originApplication) throw new FinanceOperationalApplicationError("credit_origin_not_found", "Origin payment application was not found.", 404);
  const blockers = [];
  let normalizedDate = null;
  let amount = 0;
  try {
    normalizedDate = dateOnly(entryDate, "entry_date");
  } catch (error) {
    blockers.push(blocker(error.code, error.message));
  }
  try {
    amount = exactInteger(amountCents, "amount_cents", 1);
  } catch (error) {
    blockers.push(blocker(error.code, error.message));
  }
  const availableCredit = storedInteger(availableCustomerCreditCents, "available_customer_credit_cents");
  const targetOpen = storedInteger(targetReceivableAuthority?.open_cents ?? 0, "target_open_ar_cents");
  if (originApplication.kind !== "payment" || originApplication.status !== "posted" || !originApplication.journal_entry_id) blockers.push(blocker("credit_origin_not_posted", "The origin payment allocation is not currently posted."));
  if (originApplication.source_current === false) blockers.push(blocker("credit_origin_stale", "Review the changed origin payment allocation before using its customer credit."));
  if (!targetJob) blockers.push(blocker("credit_target_job_not_found", "The target job is unavailable in this company."));
  if (!sameContact) blockers.push(blocker("credit_target_contact_mismatch", "Customer credit can be applied only to a job for the same contact."));
  if (!targetReceivableAuthority?.posted) blockers.push(blocker("credit_target_receivable_not_posted", "Post the target job receivable before applying customer credit."));
  if (amount > availableCredit) blockers.push(blocker("credit_origin_capacity_exceeded", "The application exceeds unused origin customer credit."));
  if (amount > targetOpen) blockers.push(blocker("credit_target_capacity_exceeded", "The application exceeds the target job's current open ledger receivable."));
  if (normalizedDate && companyToday && normalizedDate > companyToday) blockers.push(blocker("credit_date_future", "Customer credit cannot be applied in the future."));
  const originDate = originApplication.entry_date ? dateOnly(originApplication.entry_date, "origin_entry_date") : null;
  if (normalizedDate && originDate && normalizedDate < originDate) blockers.push(blocker("credit_date_before_origin", "Customer credit cannot be applied before the origin payment."));
  validateAccounts(accounts, blockers, false);
  const allocation = amount > 0 ? { amount_cents: amount, accounts_receivable_cents: amount, customer_credit_cents: 0 } : null;
  const snapshot = {
    application_kind: "customer_credit",
    origin_application_id: String(originApplication.id),
    origin_application_version: Number(originApplication.version || 0),
    origin_application_current: originApplication.source_current !== false,
    job_id: targetJob ? String(targetJob.id) : null,
    entry_date: normalizedDate,
    amount_cents: amount,
    same_contact: Boolean(sameContact),
    available_customer_credit_cents: availableCredit,
    target_receivable_posted: Boolean(targetReceivableAuthority?.posted),
    target_open_ar_cents: targetOpen,
    allocation,
    accounts: {
      accounts_receivable: accountSnapshot(accounts.accountsReceivable),
      customer_credits: accountSnapshot(accounts.customerCredits)
    }
  };
  const sourceFingerprint = sourceAuthorityFingerprint(snapshot);
  const eligible = blockers.length === 0 && Boolean(allocation);
  return {
    eligible,
    blockers: uniqueBlockers(blockers),
    ...applicationState(application, sourceFingerprint, eligible),
    source_fingerprint: sourceFingerprint,
    source_snapshot: snapshot,
    journal_preview: eligible ? applicationPreview("customer_credit", snapshot, accounts, allocation) : null
  };
}

export function buildOperationalApplicationJournalInput({ kind, evaluation, applicationID, version, clientRequestID, reason }) {
  if (!evaluation?.eligible || !evaluation.journal_preview) {
    throw new FinanceOperationalApplicationError("operational_application_blocked", "Resolve every application blocker before posting.", 409, { blockers: evaluation?.blockers || [] });
  }
  const labels = {
    payment: "Reviewed payment application",
    refund: "Reviewed refund application",
    customer_credit: "Reviewed customer credit application"
  };
  const kinds = {
    payment: "payment_application",
    refund: "refund_application",
    customer_credit: "customer_credit_application"
  };
  const input = {
    client_request_id: uuid(clientRequestID, "client_request_id"),
    entry_date: evaluation.journal_preview.entry_date,
    entry_kind: kinds[kind],
    description: `${labels[kind]} · ${evaluation.journal_preview.entry_date}`,
    reference: `${kind === "customer_credit" ? "CREDIT" : kind.toUpperCase()}-${String(applicationID).slice(0, 12).toUpperCase()}`,
    reason: cleanString(reason, 500),
    reversal_of_entry_id: null,
    source_type: "finance_operational_application",
    source_id: uuid(applicationID, "application_id"),
    source_version: exactInteger(version, "source_version", 1),
    lines: evaluation.journal_preview.lines,
    total_debits_cents: evaluation.journal_preview.total_debits_cents,
    total_credits_cents: evaluation.journal_preview.total_credits_cents
  };
  return { ...input, request_fingerprint: journalFingerprint(input) };
}

function buildApplicationReversalInput({ original, originalLines, applicationID, version, clientRequestID, reason }) {
  if (!original || original.source_type !== "finance_operational_application" || String(original.source_id) !== String(applicationID) || original.reversal_of_entry_id) {
    throw new FinanceOperationalApplicationError("operational_application_relationship_invalid", "The current application journal relationship is invalid.", 409);
  }
  const reversed = reverseJournalLines(originalLines);
  const input = {
    client_request_id: uuid(clientRequestID, "client_request_id"),
    entry_date: dateOnly(original.entry_date, "entry_date"),
    entry_kind: "reversal",
    description: `Reversal — ${cleanString(original.description, 180) || "Operational application"}`,
    reference: cleanString(original.reference, 120) || null,
    reason: cleanString(reason, 500),
    reversal_of_entry_id: String(original.id),
    source_type: "finance_operational_application",
    source_id: uuid(applicationID, "application_id"),
    source_version: exactInteger(version, "source_version", 1),
    lines: reversed.lines,
    total_debits_cents: reversed.total_debits_cents,
    total_credits_cents: reversed.total_credits_cents
  };
  return { ...input, request_fingerprint: journalFingerprint(input) };
}

export async function installFinanceOperationalApplicationSchema(pool) {
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS payment_records_company_id_idx ON payment_records(company_id, id);

    CREATE TABLE IF NOT EXISTS finance_payment_refund_revisions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      payment_record_id UUID NOT NULL,
      cumulative_refunded_cents BIGINT NOT NULL CHECK (cumulative_refunded_cents > 0),
      delta_refunded_cents BIGINT NOT NULL CHECK (delta_refunded_cents > 0 AND delta_refunded_cents <= cumulative_refunded_cents),
      occurred_at TIMESTAMPTZ,
      event_coverage TEXT NOT NULL CHECK (event_coverage IN ('observed','current_baseline')),
      version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, id),
      UNIQUE(company_id, payment_record_id, cumulative_refunded_cents),
      FOREIGN KEY (company_id, payment_record_id) REFERENCES payment_records(company_id, id) ON DELETE RESTRICT
    );
    CREATE INDEX IF NOT EXISTS finance_refund_revisions_company_date_idx
      ON finance_payment_refund_revisions(company_id, occurred_at, created_at, id);
    CREATE INDEX IF NOT EXISTS finance_refund_revisions_company_payment_idx
      ON finance_payment_refund_revisions(company_id, payment_record_id, cumulative_refunded_cents);

    INSERT INTO finance_payment_refund_revisions (
      company_id, payment_record_id, cumulative_refunded_cents, delta_refunded_cents, occurred_at, event_coverage
    )
    SELECT company_id, id, refunded_amount_cents, refunded_amount_cents, refunded_at, 'current_baseline'
      FROM payment_records
     WHERE company_id IS NOT NULL AND refund_amount_known=true AND refunded_amount_cents > 0
    ON CONFLICT(company_id, payment_record_id, cumulative_refunded_cents) DO NOTHING;

    CREATE OR REPLACE FUNCTION finance_capture_payment_refund_revision()
    RETURNS TRIGGER LANGUAGE plpgsql AS $$
    DECLARE prior_cumulative BIGINT;
    BEGIN
      IF NEW.company_id IS NULL OR NEW.refund_amount_known IS DISTINCT FROM true OR COALESCE(NEW.refunded_amount_cents, 0) <= 0 THEN
        RETURN NEW;
      END IF;
      prior_cumulative := CASE WHEN TG_OP = 'INSERT' THEN 0 ELSE CASE WHEN OLD.refund_amount_known THEN COALESCE(OLD.refunded_amount_cents, 0) ELSE 0 END END;
      IF NEW.refunded_amount_cents > prior_cumulative THEN
        INSERT INTO finance_payment_refund_revisions (
          company_id, payment_record_id, cumulative_refunded_cents, delta_refunded_cents, occurred_at, event_coverage
        ) VALUES (
          NEW.company_id, NEW.id, NEW.refunded_amount_cents, NEW.refunded_amount_cents - prior_cumulative, NEW.refunded_at,
          CASE WHEN NEW.refunded_at IS NULL THEN 'current_baseline' ELSE 'observed' END
        )
        ON CONFLICT(company_id, payment_record_id, cumulative_refunded_cents) DO UPDATE
          SET occurred_at=COALESCE(finance_payment_refund_revisions.occurred_at, EXCLUDED.occurred_at),
              event_coverage=CASE WHEN finance_payment_refund_revisions.event_coverage='observed' THEN 'observed' ELSE EXCLUDED.event_coverage END,
              version=CASE WHEN finance_payment_refund_revisions.occurred_at IS NULL AND EXCLUDED.occurred_at IS NOT NULL
                           THEN finance_payment_refund_revisions.version + 1 ELSE finance_payment_refund_revisions.version END,
              updated_at=CASE WHEN finance_payment_refund_revisions.occurred_at IS NULL AND EXCLUDED.occurred_at IS NOT NULL
                              THEN now() ELSE finance_payment_refund_revisions.updated_at END;
      END IF;
      RETURN NEW;
    END $$;
    DROP TRIGGER IF EXISTS finance_payment_refund_revision_capture ON payment_records;
    CREATE TRIGGER finance_payment_refund_revision_capture
      AFTER INSERT OR UPDATE ON payment_records
      FOR EACH ROW EXECUTE FUNCTION finance_capture_payment_refund_revision();

    CREATE TABLE IF NOT EXISTS finance_operational_applications (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      kind TEXT NOT NULL CHECK (kind IN ('payment','refund','customer_credit')),
      operational_source_id UUID,
      refund_revision_id UUID,
      origin_application_id UUID,
      job_id TEXT NOT NULL,
      entry_date DATE NOT NULL,
      amount_cents BIGINT NOT NULL CHECK (amount_cents > 0),
      accounts_receivable_cents BIGINT NOT NULL DEFAULT 0 CHECK (accounts_receivable_cents >= 0),
      customer_credit_cents BIGINT NOT NULL DEFAULT 0 CHECK (customer_credit_cents >= 0),
      journal_entry_id UUID,
      status TEXT NOT NULL CHECK (status IN ('draft','posted','voided')),
      version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
      source_fingerprint TEXT NOT NULL CHECK (char_length(source_fingerprint) = 64),
      source_snapshot JSONB NOT NULL,
      reason TEXT NOT NULL,
      updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, id),
      FOREIGN KEY (company_id, operational_source_id) REFERENCES finance_operational_sources(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, refund_revision_id) REFERENCES finance_payment_refund_revisions(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, origin_application_id) REFERENCES finance_operational_applications(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, job_id) REFERENCES schedule_events(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, journal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT,
      CHECK (accounts_receivable_cents + customer_credit_cents = amount_cents),
      CHECK ((status = 'posted' AND journal_entry_id IS NOT NULL) OR (status IN ('draft','voided') AND journal_entry_id IS NULL)),
      CHECK (
        (kind='payment' AND operational_source_id IS NOT NULL AND refund_revision_id IS NULL AND origin_application_id IS NULL)
        OR (kind='refund' AND operational_source_id IS NULL AND refund_revision_id IS NOT NULL AND origin_application_id IS NOT NULL)
        OR (kind='customer_credit' AND operational_source_id IS NULL AND refund_revision_id IS NULL AND origin_application_id IS NOT NULL AND customer_credit_cents=0)
      )
    );
    CREATE UNIQUE INDEX IF NOT EXISTS finance_operational_applications_payment_source_idx
      ON finance_operational_applications(company_id, operational_source_id) WHERE kind='payment';
    CREATE UNIQUE INDEX IF NOT EXISTS finance_operational_applications_refund_revision_idx
      ON finance_operational_applications(company_id, refund_revision_id) WHERE kind='refund';
    CREATE INDEX IF NOT EXISTS finance_operational_applications_company_status_date_idx
      ON finance_operational_applications(company_id, status, entry_date, kind);
    CREATE INDEX IF NOT EXISTS finance_operational_applications_company_origin_idx
      ON finance_operational_applications(company_id, origin_application_id, status, kind);
    CREATE INDEX IF NOT EXISTS finance_operational_applications_company_job_idx
      ON finance_operational_applications(company_id, job_id, status, kind);

    CREATE TABLE IF NOT EXISTS finance_operational_application_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      application_id UUID NOT NULL,
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
      FOREIGN KEY (company_id, application_id) REFERENCES finance_operational_applications(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, previous_journal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, journal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, reversal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT
    );
    CREATE INDEX IF NOT EXISTS finance_operational_application_audit_company_app_idx
      ON finance_operational_application_audit(company_id, application_id, created_at DESC);
  `);
}

async function loadSystemAccounts(poolOrClient, companyID) {
  const { rows } = await poolOrClient.query(
    `SELECT id, code, name, account_type, system_key, active
       FROM finance_chart_accounts
      WHERE company_id=$1 AND system_key IN ('accounts_receivable','customer_credits','payment_clearing')`,
    [companyID]
  );
  const byKey = new Map(rows.map((row) => [row.system_key, row]));
  return {
    accountsReceivable: byKey.get("accounts_receivable") || null,
    customerCredits: byKey.get("customer_credits") || null,
    clearing: byKey.get("payment_clearing") || null
  };
}

async function loadJobReceivableAuthority(poolOrClient, companyID, jobID, excludedApplicationID = null) {
  const { rows } = await poolOrClient.query(
    `SELECT rp.id AS receivable_posting_id,
            rp.status AS receivable_status,
            rp.source_snapshot AS receivable_source_snapshot,
            source.status AS operational_source_status,
            source.source_version AS operational_source_version,
            source.amount_cents AS operational_source_amount_cents,
            source.removed_at AS operational_source_removed_at,
            COALESCE((
              SELECT SUM(line.debit_cents - line.credit_cents)
                FROM finance_journal_lines line
                JOIN finance_chart_accounts account ON account.company_id=line.company_id AND account.id=line.chart_account_id
               WHERE line.company_id=rp.company_id AND line.entry_id=rp.journal_entry_id
                 AND account.system_key='accounts_receivable'
            ),0) AS recognized_cents,
            COALESCE(SUM(CASE
              WHEN app.kind='payment' THEN -app.accounts_receivable_cents
              WHEN app.kind='refund' THEN app.accounts_receivable_cents
              WHEN app.kind='customer_credit' THEN -app.amount_cents
              ELSE 0 END) FILTER (WHERE app.status='posted' AND ($3::uuid IS NULL OR app.id<>$3::uuid)),0) AS application_net_cents
       FROM finance_operational_receivable_postings rp
       JOIN finance_operational_sources source
         ON source.company_id=rp.company_id AND source.id=rp.operational_source_id AND source.source_type='job_receivable'
       LEFT JOIN finance_operational_applications app ON app.company_id=rp.company_id AND app.job_id=rp.job_id
      WHERE rp.company_id=$1 AND rp.job_id=$2
      GROUP BY rp.id`,
    [companyID, jobID, excludedApplicationID]
  );
  const row = rows[0];
  if (!row || row.receivable_status !== "posted") return { posted: false, recognized_cents: 0, open_cents: 0 };
  const recognized = storedInteger(row.recognized_cents, "recognized_cents");
  const net = storedInteger(row.application_net_cents, "application_net_cents");
  const retainedSnapshot = objectValue(row.receivable_source_snapshot);
  const current = row.operational_source_status === "recognized"
    && !row.operational_source_removed_at
    && Number(row.operational_source_version) === Number(retainedSnapshot.source_version || 0)
    && storedInteger(row.operational_source_amount_cents, "operational_source_amount_cents") === recognized;
  return { posted: current, recognized_cents: recognized, open_cents: Math.max(0, addExact(recognized, net, "open_cents")) };
}

function allocationFromValues(amount, arValue, creditValue) {
  if (arValue === undefined && creditValue === undefined) return null;
  return {
    accounts_receivable_cents: arValue ?? 0,
    customer_credit_cents: creditValue ?? Math.max(0, amount - Number(arValue || 0))
  };
}

async function loadPaymentBundle(poolOrClient, companyID, sourceID, requestedAllocation = null, lock = false) {
  const lockSql = lock ? " FOR UPDATE OF src" : "";
  const result = await poolOrClient.query(
    `SELECT src.*,
            (src.occurred_at AT TIME ZONE COALESCE(NULLIF(company.timezone,''),'America/New_York'))::date::text AS entry_date,
            p.id AS live_payment_id, p.job_id AS live_job_id, p.contact_id AS live_contact_id,
            app.id AS application_id, app.kind AS application_kind, app.job_id AS application_job_id,
            app.entry_date AS application_entry_date,
            app.amount_cents AS application_amount_cents, app.accounts_receivable_cents, app.customer_credit_cents,
            app.journal_entry_id, app.status AS application_status, app.version AS application_version,
            app.source_fingerprint AS application_source_fingerprint, app.source_snapshot AS application_source_snapshot
       FROM finance_operational_sources src
       JOIN companies company ON company.id=src.company_id
       LEFT JOIN payment_records p ON p.company_id=src.company_id AND p.id=src.payment_record_id
       LEFT JOIN finance_operational_applications app ON app.company_id=src.company_id AND app.kind='payment' AND app.operational_source_id=src.id
      WHERE src.company_id=$1 AND src.id=$2 AND src.source_type='payment'${lockSql}`,
    [companyID, sourceID]
  );
  if (!result.rows.length) throw new FinanceOperationalApplicationError("payment_application_source_not_found", "Payment source was not found.", 404);
  const row = result.rows[0];
  const application = row.application_id ? {
    id: row.application_id, kind: row.application_kind, job_id: row.application_job_id,
    entry_date: row.application_entry_date,
    amount_cents: row.application_amount_cents, accounts_receivable_cents: row.accounts_receivable_cents,
    customer_credit_cents: row.customer_credit_cents, journal_entry_id: row.journal_entry_id,
    status: row.application_status, version: row.application_version,
    source_fingerprint: row.application_source_fingerprint, source_snapshot: row.application_source_snapshot
  } : null;
  let refundAR = 0;
  let refundCredit = 0;
  let usedCredit = 0;
  let dependentEarliestDate = null;
  if (application) {
    const dependencies = await poolOrClient.query(
      `SELECT COALESCE(SUM(accounts_receivable_cents) FILTER (WHERE kind='refund' AND status='posted'),0) AS refund_ar,
              COALESCE(SUM(customer_credit_cents) FILTER (WHERE kind='refund' AND status='posted'),0) AS refund_credit,
              COALESCE(SUM(amount_cents) FILTER (WHERE kind='customer_credit' AND status='posted'),0) AS used_credit,
              (MIN(entry_date) FILTER (WHERE status='posted'))::text AS dependent_earliest_date
         FROM finance_operational_applications WHERE company_id=$1 AND origin_application_id=$2`,
      [companyID, application.id]
    );
    refundAR = storedInteger(dependencies.rows[0].refund_ar, "refund_ar_cents");
    refundCredit = storedInteger(dependencies.rows[0].refund_credit, "refund_credit_cents");
    usedCredit = storedInteger(dependencies.rows[0].used_credit, "used_credit_cents");
    dependentEarliestDate = dependencies.rows[0].dependent_earliest_date || null;
    application.refund_ar_cents = refundAR;
  }
  const amount = storedInteger(row.amount_cents, "amount_cents");
  const defaultAR = application ? storedInteger(application.accounts_receivable_cents, "accounts_receivable_cents") : null;
  const authority = row.job_id ? await loadJobReceivableAuthority(poolOrClient, companyID, row.job_id, application?.id || null) : { posted: false, open_cents: 0 };
  const allocation = requestedAllocation || (application ? {
    accounts_receivable_cents: defaultAR,
    customer_credit_cents: storedInteger(application.customer_credit_cents, "customer_credit_cents")
  } : {
    accounts_receivable_cents: Math.min(amount, authority.open_cents),
    customer_credit_cents: Math.max(0, amount - authority.open_cents)
  });
  const [accounts] = await Promise.all([loadSystemAccounts(poolOrClient, companyID)]);
  const source = { ...row, entry_date: row.entry_date };
  const payment = row.live_payment_id ? { id: row.live_payment_id, job_id: row.live_job_id, contact_id: row.live_contact_id } : null;
  const evaluation = evaluatePaymentApplication({
    source, payment, application, accounts, receivableAuthority: authority, allocation,
    dependentRefundCents: refundCredit, dependentCreditCents: usedCredit, dependentEarliestDate
  });
  return { source, payment, application, accounts, authority, evaluation, refundAR, refundCredit, usedCredit, dependentEarliestDate };
}

async function loadRefundBundle(poolOrClient, companyID, revisionID, requestedAllocation = null, lock = false) {
  const lockSql = lock ? " FOR UPDATE OF revision" : "";
  const result = await poolOrClient.query(
    `SELECT revision.*,
            (revision.occurred_at AT TIME ZONE COALESCE(NULLIF(company.timezone,''),'America/New_York'))::date::text AS entry_date,
            origin.id AS origin_id, origin.kind AS origin_kind, origin.job_id AS origin_job_id,
            origin.entry_date AS origin_entry_date, origin.accounts_receivable_cents AS origin_ar_cents,
            origin.customer_credit_cents AS origin_credit_cents, origin.journal_entry_id AS origin_journal_id,
            origin.status AS origin_status, origin.version AS origin_version, origin.source_snapshot AS origin_source_snapshot,
            payment_source.id AS payment_operational_source_id,
            payment_source.source_version AS payment_source_version,
            payment_source.status AS payment_source_status, payment_source.removed_at AS payment_source_removed_at,
            app.id AS application_id, app.kind AS application_kind, app.entry_date AS application_entry_date,
            app.amount_cents AS application_amount_cents, app.accounts_receivable_cents, app.customer_credit_cents,
            app.journal_entry_id, app.status AS application_status, app.version AS application_version,
            app.source_fingerprint AS application_source_fingerprint, app.source_snapshot AS application_source_snapshot
       FROM finance_payment_refund_revisions revision
       JOIN companies company ON company.id=revision.company_id
       LEFT JOIN finance_operational_sources payment_source
         ON payment_source.company_id=revision.company_id AND payment_source.payment_record_id=revision.payment_record_id AND payment_source.source_type='payment'
       LEFT JOIN finance_operational_applications origin
         ON origin.company_id=payment_source.company_id AND origin.operational_source_id=payment_source.id AND origin.kind='payment'
       LEFT JOIN finance_operational_applications app
         ON app.company_id=revision.company_id AND app.refund_revision_id=revision.id AND app.kind='refund'
      WHERE revision.company_id=$1 AND revision.id=$2${lockSql}`,
    [companyID, revisionID]
  );
  if (!result.rows.length) throw new FinanceOperationalApplicationError("refund_revision_not_found", "Refund revision was not found.", 404);
  const row = result.rows[0];
  const origin = row.origin_id ? {
    id: row.origin_id, kind: row.origin_kind, job_id: row.origin_job_id, entry_date: row.origin_entry_date,
    accounts_receivable_cents: row.origin_ar_cents, customer_credit_cents: row.origin_credit_cents,
    journal_entry_id: row.origin_journal_id, status: row.origin_status, version: row.origin_version,
    source_current: row.payment_source_status && COLLECTED_STATUSES.has(row.payment_source_status)
      && !row.payment_source_removed_at
      && Number(row.payment_source_version) === Number(objectValue(row.origin_source_snapshot).source_version || 0)
  } : null;
  if (origin && row.payment_operational_source_id) {
    const liveParent = await loadPaymentBundle(poolOrClient, companyID, row.payment_operational_source_id, null, lock);
    origin.source_current = liveParent.application?.id === origin.id && liveParent.evaluation.source_current;
  }
  const application = row.application_id ? {
    id: row.application_id, kind: row.application_kind, entry_date: row.application_entry_date,
    amount_cents: row.application_amount_cents, accounts_receivable_cents: row.accounts_receivable_cents,
    customer_credit_cents: row.customer_credit_cents, journal_entry_id: row.journal_entry_id,
    status: row.application_status, version: row.application_version,
    source_fingerprint: row.application_source_fingerprint, source_snapshot: row.application_source_snapshot
  } : null;
  let priorAR = 0;
  let priorCredit = 0;
  let usedCredit = 0;
  if (origin) {
    const consumed = await poolOrClient.query(
      `SELECT COALESCE(SUM(accounts_receivable_cents) FILTER (WHERE kind='refund' AND status='posted' AND ($3::uuid IS NULL OR id<>$3::uuid)),0) AS refund_ar,
              COALESCE(SUM(customer_credit_cents) FILTER (WHERE kind='refund' AND status='posted' AND ($3::uuid IS NULL OR id<>$3::uuid)),0) AS refund_credit,
              COALESCE(SUM(amount_cents) FILTER (WHERE kind='customer_credit' AND status='posted'),0) AS used_credit
         FROM finance_operational_applications WHERE company_id=$1 AND origin_application_id=$2`,
      [companyID, origin.id, application?.id || null]
    );
    priorAR = storedInteger(consumed.rows[0].refund_ar, "prior_refund_ar_cents");
    priorCredit = storedInteger(consumed.rows[0].refund_credit, "prior_refund_credit_cents");
    usedCredit = storedInteger(consumed.rows[0].used_credit, "used_credit_cents");
  }
  const amount = storedInteger(row.delta_refunded_cents, "delta_refunded_cents");
  const availableAR = Math.max(0, storedInteger(origin?.accounts_receivable_cents ?? 0, "origin_ar_cents") - priorAR);
  const allocation = requestedAllocation || (application ? {
    accounts_receivable_cents: storedInteger(application.accounts_receivable_cents, "accounts_receivable_cents"),
    customer_credit_cents: storedInteger(application.customer_credit_cents, "customer_credit_cents")
  } : {
    accounts_receivable_cents: Math.min(amount, availableAR),
    customer_credit_cents: Math.max(0, amount - availableAR)
  });
  const accounts = await loadSystemAccounts(poolOrClient, companyID);
  const receivableAuthority = origin?.job_id
    ? await loadJobReceivableAuthority(poolOrClient, companyID, origin.job_id, application?.id || null)
    : { posted: false, open_cents: 0 };
  const revision = { ...row, entry_date: row.entry_date };
  const evaluation = evaluateRefundApplication({
    revision, originApplication: origin, application, accounts, allocation,
    priorRefundARCents: priorAR, priorRefundCreditCents: priorCredit, usedCustomerCreditCents: usedCredit,
    receivableAuthority
  });
  return { revision, origin, application, accounts, evaluation, priorAR, priorCredit, usedCredit, receivableAuthority };
}

async function loadCreditBundle(poolOrClient, companyID, { applicationID = null, originApplicationID = null, jobID = null, entryDate = null, amountCents = null }, lock = false) {
  let application = null;
  if (applicationID) {
    const result = await poolOrClient.query(
      `SELECT * FROM finance_operational_applications WHERE company_id=$1 AND id=$2 AND kind='customer_credit'${lock ? " FOR UPDATE" : ""}`,
      [companyID, applicationID]
    );
    if (!result.rows.length) throw new FinanceOperationalApplicationError("customer_credit_application_not_found", "Customer credit application was not found.", 404);
    application = result.rows[0];
    originApplicationID = application.origin_application_id;
    jobID = application.job_id;
    entryDate = application.entry_date;
    amountCents = application.amount_cents;
  }
  const originResult = await poolOrClient.query(
    `SELECT app.*, src.contact_id AS origin_contact_id, src.source_version AS live_source_version,
            src.status AS live_source_status, src.removed_at AS live_source_removed_at
       FROM finance_operational_applications app
       LEFT JOIN finance_operational_sources src ON src.company_id=app.company_id AND src.id=app.operational_source_id
      WHERE app.company_id=$1 AND app.id=$2 AND app.kind='payment'${lock ? " FOR UPDATE OF app" : ""}`,
    [companyID, originApplicationID]
  );
  if (!originResult.rows.length) throw new FinanceOperationalApplicationError("credit_origin_not_found", "Origin payment application was not found.", 404);
  const origin = originResult.rows[0];
  const liveParent = await loadPaymentBundle(poolOrClient, companyID, origin.operational_source_id, null, lock);
  origin.source_current = liveParent.application?.id === origin.id && liveParent.evaluation.source_current;
  const targetResult = await poolOrClient.query(
    `SELECT id, contact_id FROM schedule_events WHERE company_id=$1 AND id=$2${lock ? " FOR SHARE" : ""}`,
    [companyID, jobID]
  );
  const targetJob = targetResult.rows[0] || null;
  const consumed = await poolOrClient.query(
    `SELECT COALESCE(SUM(customer_credit_cents) FILTER (WHERE kind='refund' AND status='posted'),0) AS refund_credit,
            COALESCE(SUM(amount_cents) FILTER (WHERE kind='customer_credit' AND status='posted' AND ($3::uuid IS NULL OR id<>$3::uuid)),0) AS used_credit
       FROM finance_operational_applications WHERE company_id=$1 AND origin_application_id=$2`,
    [companyID, origin.id, application?.id || null]
  );
  const refundCredit = storedInteger(consumed.rows[0].refund_credit, "refund_credit_cents");
  const usedCredit = storedInteger(consumed.rows[0].used_credit, "used_credit_cents");
  const availableCredit = Math.max(0, storedInteger(origin.customer_credit_cents, "origin_credit_cents") - refundCredit - usedCredit);
  const authority = targetJob ? await loadJobReceivableAuthority(poolOrClient, companyID, targetJob.id, application?.id || null) : { posted: false, open_cents: 0 };
  const [accounts, context] = await Promise.all([loadSystemAccounts(poolOrClient, companyID), loadCompanyContext(poolOrClient, companyID)]);
  const evaluation = evaluateCustomerCreditApplication({
    originApplication: origin,
    targetJob,
    application,
    accounts,
    entryDate,
    amountCents,
    availableCustomerCreditCents: availableCredit,
    targetReceivableAuthority: authority,
    sameContact: Boolean(targetJob && origin.origin_contact_id && String(targetJob.contact_id || "") === String(origin.origin_contact_id)),
    companyToday: context.company_today
  });
  return { application, origin, targetJob, accounts, authority, availableCredit, evaluation };
}

export async function loadOperationalApplicationCloseEvaluation(poolOrClient, companyID, applicationID) {
  const result = await poolOrClient.query(
    `SELECT id, kind, operational_source_id, refund_revision_id
       FROM finance_operational_applications WHERE company_id=$1 AND id=$2`,
    [companyID, applicationID]
  );
  const application = result.rows[0];
  if (!application) {
    throw new FinanceOperationalApplicationError("operational_application_not_found", "Operational application was not found.", 404);
  }
  let bundle;
  if (application.kind === "payment") {
    bundle = await loadPaymentBundle(poolOrClient, companyID, application.operational_source_id);
  } else if (application.kind === "refund") {
    bundle = await loadRefundBundle(poolOrClient, companyID, application.refund_revision_id);
  } else if (application.kind === "customer_credit") {
    bundle = await loadCreditBundle(poolOrClient, companyID, { applicationID });
  } else {
    throw new FinanceOperationalApplicationError("operational_application_kind_invalid", "Operational application kind is invalid.", 409);
  }
  if (String(bundle.application?.id || "") !== String(applicationID)) {
    throw new FinanceOperationalApplicationError("operational_application_authority_mismatch", "Operational application authority is inconsistent.", 409);
  }
  return {
    ...bundle.evaluation,
    authority_id: String(bundle.application.id),
    authority_version: Number(bundle.application.version),
    authority_kind: bundle.application.kind
  };
}

function applicationPayload(kind, bundle) {
  const evaluation = bundle.evaluation;
  const snapshot = evaluation.source_snapshot;
  const application = bundle.application;
  const sourceID = kind === "payment" ? String(bundle.source.id) : kind === "refund" ? String(bundle.revision.id) : String(application?.id || "");
  const sourceVersion = kind === "payment" ? Number(bundle.source.source_version) : kind === "refund" ? Number(bundle.revision.version) : Number(bundle.origin.version);
  return {
    id: sourceID,
    kind,
    payment_record_id: snapshot.payment_record_id || null,
    operational_source_id: snapshot.operational_source_id || null,
    refund_revision_id: snapshot.refund_revision_id || null,
    origin_application_id: snapshot.origin_application_id || null,
    job_id: snapshot.job_id || null,
    entry_date: snapshot.entry_date,
    occurred_at: snapshot.occurred_at || null,
    event_coverage: snapshot.event_coverage || null,
    amount_cents: snapshot.amount_cents,
    cumulative_refunded_cents: snapshot.cumulative_refunded_cents || null,
    source_version: sourceVersion,
    application: application ? {
      id: String(application.id),
      status: application.status,
      version: Number(application.version),
      entry_date: application.entry_date instanceof Date ? application.entry_date.toISOString().slice(0, 10) : String(application.entry_date).slice(0, 10),
      amount_cents: storedInteger(application.amount_cents, "application_amount_cents"),
      accounts_receivable_cents: storedInteger(application.accounts_receivable_cents, "accounts_receivable_cents"),
      customer_credit_cents: storedInteger(application.customer_credit_cents, "customer_credit_cents"),
      journal_entry_id: application.journal_entry_id || null
    } : null,
    suggested_accounts_receivable_cents: snapshot.allocation?.accounts_receivable_cents || 0,
    suggested_customer_credit_cents: snapshot.allocation?.customer_credit_cents || 0,
    target_open_ar_cents: snapshot.target_open_ar_cents ?? null,
    available_customer_credit_cents: kind === "payment" && application
      ? Math.max(0, storedInteger(application.customer_credit_cents, "customer_credit_cents") - bundle.refundCredit - bundle.usedCredit)
      : snapshot.available_customer_credit_cents ?? null,
    review_state: evaluation.review_state,
    source_current: evaluation.source_current,
    can_post: evaluation.can_post,
    can_void: evaluation.can_void,
    blockers: evaluation.blockers,
    journal_preview: evaluation.journal_preview
  };
}

async function loadAudit(poolOrClient, companyID, applicationID) {
  if (!applicationID) return [];
  const { rows } = await poolOrClient.query(
    `SELECT id, action, reason, version, actor_user_id, previous_journal_entry_id,
            journal_entry_id, reversal_entry_id, created_at
       FROM finance_operational_application_audit
      WHERE company_id=$1 AND application_id=$2 ORDER BY created_at DESC LIMIT 50`,
    [companyID, applicationID]
  );
  return rows.map((row) => ({ ...row, id: String(row.id), version: Number(row.version) }));
}

async function detailPayload(poolOrClient, companyID, kind, bundle) {
  const item = applicationPayload(kind, bundle);
  const applicationID = bundle.application?.id || null;
  const [audit, journal] = await Promise.all([
    loadAudit(poolOrClient, companyID, applicationID),
    bundle.application?.journal_entry_id ? loadJournalEntry(poolOrClient, companyID, bundle.application.journal_entry_id, 20) : Promise.resolve(null)
  ]);
  let creditCandidates = [];
  if (kind === "payment" && bundle.application?.status === "posted" && item.available_customer_credit_cents > 0) {
    const candidateRows = await poolOrClient.query(
      `SELECT se.id, se.title, se.finished_at
         FROM schedule_events se
         JOIN finance_operational_receivable_postings posting
           ON posting.company_id=se.company_id AND posting.job_id=se.id AND posting.status='posted'
        WHERE se.company_id=$1 AND se.contact_id::text=$2
        ORDER BY se.finished_at DESC NULLS LAST, se.id LIMIT 100`,
      [companyID, String(bundle.source.contact_id || "")]
    );
    for (const row of candidateRows.rows) {
      const authority = await loadJobReceivableAuthority(poolOrClient, companyID, row.id);
      if (authority.open_cents > 0) creditCandidates.push({
        job_id: String(row.id),
        title: row.title || "Untitled job",
        finished_at: row.finished_at || null,
        open_ar_cents: authority.open_cents
      });
    }
  }
  return { item, journal, audit, credit_candidates: creditCandidates };
}

async function loadReport(poolOrClient, companyID, range, limit) {
  const paymentIDs = await poolOrClient.query(
    `SELECT source.id FROM finance_operational_sources source
       JOIN companies company ON company.id=source.company_id
      WHERE source.company_id=$1 AND source.source_type='payment'
        AND source.occurred_at IS NOT NULL
        AND (source.occurred_at AT TIME ZONE COALESCE(NULLIF(company.timezone,''),'America/New_York'))::date BETWEEN $2::date AND $3::date
      ORDER BY source.occurred_at DESC, source.id LIMIT $4`,
    [companyID, range.start_date, range.end_date, limit + 1]
  );
  const revisionIDs = await poolOrClient.query(
    `SELECT revision.id FROM finance_payment_refund_revisions revision
       JOIN companies company ON company.id=revision.company_id
      WHERE revision.company_id=$1 AND (revision.occurred_at IS NULL OR
        (revision.occurred_at AT TIME ZONE COALESCE(NULLIF(company.timezone,''),'America/New_York'))::date BETWEEN $2::date AND $3::date)
      ORDER BY revision.occurred_at DESC NULLS FIRST, revision.created_at DESC, revision.id LIMIT $4`,
    [companyID, range.start_date, range.end_date, limit + 1]
  );
  const creditIDs = await poolOrClient.query(
    `SELECT id FROM finance_operational_applications
      WHERE company_id=$1 AND kind='customer_credit' AND entry_date BETWEEN $2::date AND $3::date
      ORDER BY entry_date DESC, created_at DESC, id LIMIT $4`,
    [companyID, range.start_date, range.end_date, limit + 1]
  );
  const truncated = paymentIDs.rows.length > limit || revisionIDs.rows.length > limit || creditIDs.rows.length > limit;
  const payments = [];
  for (const row of paymentIDs.rows.slice(0, limit)) payments.push(applicationPayload("payment", await loadPaymentBundle(poolOrClient, companyID, row.id)));
  const refunds = [];
  for (const row of revisionIDs.rows.slice(0, limit)) refunds.push(applicationPayload("refund", await loadRefundBundle(poolOrClient, companyID, row.id)));
  const customerCredits = [];
  for (const row of creditIDs.rows.slice(0, limit)) customerCredits.push(applicationPayload("customer_credit", await loadCreditBundle(poolOrClient, companyID, { applicationID: row.id })));
  const all = [...payments, ...refunds, ...customerCredits];
  return {
    basis: "reviewed_operational_payment_applications",
    start_date: range.start_date,
    end_date: range.end_date,
    truncated,
    summary: {
      ready_count: all.filter((item) => item.review_state === "ready").length,
      posted_count: all.filter((item) => item.review_state === "posted").length,
      review_required_count: all.filter((item) => item.review_state === "stale").length,
      blocked_count: all.filter((item) => item.review_state === "blocked").length,
      voided_count: all.filter((item) => item.review_state === "voided").length
    },
    warnings: [
      "Payment Clearing is provider-side accounting authority, not a bank balance or confirmed Stripe payout.",
      "Refund revisions are separately dated exact increases; current-baseline coverage does not invent missing intermediate refunds.",
      "No payment, refund, credit, provider fee, or bank settlement posts automatically."
    ],
    payments,
    refunds,
    customer_credits: customerCredits
  };
}

function normalizeMutation(body, action, fields = {}) {
  const reason = cleanString(body.reason, 500);
  if (!reason) throw new FinanceOperationalApplicationError("operational_application_reason_required", "An audit reason is required.");
  const input = {
    client_request_id: uuid(body.client_request_id, "client_request_id"),
    action,
    expected_application_version: exactInteger(body.expected_application_version ?? 0, "expected_application_version"),
    reason,
    ...fields
  };
  return { ...input, request_fingerprint: fingerprint(input) };
}

async function replayedRequest(client, companyID, request) {
  const { rows } = await client.query(
    `SELECT application_id, request_fingerprint FROM finance_operational_application_audit
      WHERE company_id=$1 AND client_request_id=$2::uuid FOR SHARE`,
    [companyID, request.client_request_id]
  );
  if (!rows.length) return null;
  if (rows[0].request_fingerprint !== request.request_fingerprint) {
    throw new FinanceOperationalApplicationError("operational_application_request_id_conflict", "That application request ID was already used with different content.", 409);
  }
  return rows[0].application_id;
}

async function insertLedgerAudit(client, companyID, userID, entry, relatedEntryID, action, reason, input) {
  await client.query(
    `INSERT INTO finance_journal_audit (company_id, entry_id, related_entry_id, actor_user_id, action, reason, entry_snapshot)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [companyID, entry.id, relatedEntryID || null, userID, action, reason, JSON.stringify(snapshotInput(input))]
  );
}

async function reverseCurrentApplication(client, companyID, userID, application, nextVersion, clientRequestID, reason) {
  if (!application?.journal_entry_id || application.status !== "posted") return null;
  const entryResult = await client.query(
    `SELECT * FROM finance_journal_entries WHERE company_id=$1 AND id=$2 FOR UPDATE`,
    [companyID, application.journal_entry_id]
  );
  const lineResult = await client.query(
    `SELECT chart_account_id, debit_cents, credit_cents, memo FROM finance_journal_lines
      WHERE company_id=$1 AND entry_id=$2 ORDER BY line_order FOR SHARE`,
    [companyID, application.journal_entry_id]
  );
  const reversed = await client.query(
    `SELECT id FROM finance_journal_entries WHERE company_id=$1 AND reversal_of_entry_id=$2 FOR UPDATE`,
    [companyID, application.journal_entry_id]
  );
  if (reversed.rows.length) throw new FinanceOperationalApplicationError("operational_application_already_reversed", "The current application journal already has a reversal.", 409);
  const input = buildApplicationReversalInput({
    original: entryResult.rows[0], originalLines: lineResult.rows, applicationID: application.id,
    version: nextVersion, clientRequestID, reason
  });
  const reversal = await insertJournal(client, companyID, userID, input);
  await insertLedgerAudit(client, companyID, userID, reversal, application.journal_entry_id, "operational_application_reversal_posted", reason, input);
  await insertLedgerAudit(client, companyID, userID, entryResult.rows[0], reversal.id, "operational_application_reversed", reason, input);
  return reversal;
}

async function commitApplication({ client, companyID, userID, request, kind, bundle, identity }) {
  const existing = bundle.application;
  if (request.expected_application_version !== appVersion(existing)) {
    throw new FinanceOperationalApplicationError("operational_application_stale", "The application changed after it was loaded.", 409, { current_application_version: appVersion(existing) });
  }
  if (!bundle.evaluation.eligible) {
    throw new FinanceOperationalApplicationError("operational_application_blocked", "Resolve every application blocker before posting.", 409, { blockers: bundle.evaluation.blockers });
  }
  if (bundle.evaluation.source_current) {
    await client.query(
      `INSERT INTO finance_operational_application_audit (
         company_id, application_id, actor_user_id, action, reason, version, client_request_id,
         request_fingerprint, source_fingerprint, source_snapshot, previous_journal_entry_id, journal_entry_id
       ) VALUES ($1,$2,$3,'source_reviewed',$4,$5,$6,$7,$8,$9,$10,$10)`,
      [companyID, existing.id, userID, request.reason, existing.version, request.client_request_id,
        request.request_fingerprint, bundle.evaluation.source_fingerprint, JSON.stringify(bundle.evaluation.source_snapshot), existing.journal_entry_id]
    );
    return existing;
  }
  const nextVersion = appVersion(existing) + 1;
  const applicationID = existing?.id || randomUUID();
  if (!existing) {
    await client.query(
      `INSERT INTO finance_operational_applications (
         id, company_id, kind, operational_source_id, refund_revision_id, origin_application_id, job_id,
         entry_date, amount_cents, accounts_receivable_cents, customer_credit_cents, status, version,
         source_fingerprint, source_snapshot, reason, updated_by
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::date,$9,$10,$11,'draft',1,$12,$13,$14,$15)`,
      [applicationID, companyID, kind, identity.operational_source_id || null, identity.refund_revision_id || null,
        identity.origin_application_id || null, identity.job_id, bundle.evaluation.journal_preview.entry_date,
        bundle.evaluation.journal_preview.total_debits_cents,
        bundle.evaluation.source_snapshot.allocation.accounts_receivable_cents,
        bundle.evaluation.source_snapshot.allocation.customer_credit_cents,
        bundle.evaluation.source_fingerprint, JSON.stringify(bundle.evaluation.source_snapshot), request.reason, userID]
    );
  }
  const reversal = existing ? await reverseCurrentApplication(client, companyID, userID, existing, nextVersion, randomUUID(), request.reason) : null;
  const journalInput = buildOperationalApplicationJournalInput({
    kind, evaluation: bundle.evaluation, applicationID, version: nextVersion,
    clientRequestID: request.client_request_id, reason: request.reason
  });
  const journal = await insertJournal(client, companyID, userID, journalInput);
  await insertLedgerAudit(client, companyID, userID, journal, reversal?.id || null, "operational_application_posted", request.reason, journalInput);
  const application = (await client.query(
    `UPDATE finance_operational_applications
        SET job_id=$3, entry_date=$4::date, amount_cents=$5, accounts_receivable_cents=$6, customer_credit_cents=$7,
            journal_entry_id=$8, status='posted', version=$9, source_fingerprint=$10, source_snapshot=$11,
            reason=$12, updated_by=$13, updated_at=now()
      WHERE company_id=$1 AND id=$2 RETURNING *`,
    [companyID, applicationID, identity.job_id, bundle.evaluation.journal_preview.entry_date,
      bundle.evaluation.journal_preview.total_debits_cents,
      bundle.evaluation.source_snapshot.allocation.accounts_receivable_cents,
      bundle.evaluation.source_snapshot.allocation.customer_credit_cents,
      journal.id, nextVersion, bundle.evaluation.source_fingerprint, JSON.stringify(bundle.evaluation.source_snapshot), request.reason, userID]
  )).rows[0];
  await client.query(
    `INSERT INTO finance_operational_application_audit (
       company_id, application_id, actor_user_id, action, reason, version, client_request_id,
       request_fingerprint, source_fingerprint, source_snapshot, previous_journal_entry_id, journal_entry_id, reversal_entry_id
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
    [companyID, applicationID, userID, existing ? "source_replaced" : "source_posted", request.reason,
      nextVersion, request.client_request_id, request.request_fingerprint, bundle.evaluation.source_fingerprint,
      JSON.stringify(bundle.evaluation.source_snapshot), existing?.journal_entry_id || null, journal.id, reversal?.id || null]
  );
  return application;
}

async function voidApplication({ client, companyID, userID, request, application, canVoid, sourceFingerprint, sourceSnapshot }) {
  if (!application || application.status !== "posted" || !application.journal_entry_id) {
    throw new FinanceOperationalApplicationError("operational_application_not_posted", "Only a currently posted application can be voided.", 409);
  }
  if (request.expected_application_version !== appVersion(application)) {
    throw new FinanceOperationalApplicationError("operational_application_stale", "The application changed after it was loaded.", 409, { current_application_version: appVersion(application) });
  }
  if (!canVoid) throw new FinanceOperationalApplicationError("operational_application_has_dependents", "Void dependent refund or customer-credit applications first.", 409);
  const nextVersion = appVersion(application) + 1;
  const reversal = await reverseCurrentApplication(client, companyID, userID, application, nextVersion, request.client_request_id, request.reason);
  const updated = (await client.query(
    `UPDATE finance_operational_applications
        SET journal_entry_id=NULL, status='voided', version=$3, source_fingerprint=$4, source_snapshot=$5,
            reason=$6, updated_by=$7, updated_at=now()
      WHERE company_id=$1 AND id=$2 RETURNING *`,
    [companyID, application.id, nextVersion, sourceFingerprint, JSON.stringify(sourceSnapshot), request.reason, userID]
  )).rows[0];
  await client.query(
    `INSERT INTO finance_operational_application_audit (
       company_id, application_id, actor_user_id, action, reason, version, client_request_id,
       request_fingerprint, source_fingerprint, source_snapshot, previous_journal_entry_id, reversal_entry_id
     ) VALUES ($1,$2,$3,'source_voided',$4,$5,$6,$7,$8,$9,$10,$11)`,
    [companyID, application.id, userID, request.reason, nextVersion, request.client_request_id,
      request.request_fingerprint, sourceFingerprint, JSON.stringify(sourceSnapshot), application.journal_entry_id, reversal.id]
  );
  return updated;
}

function sendError(res, error, fallback) {
  if (error instanceof FinanceOperationalApplicationError || error instanceof GeneralLedgerError || error?.statusCode) {
    return res.status(error.statusCode || 400).json({
      error: error.code || fallback,
      message: error.message,
      blockers: error.blockers,
      current_application_version: error.current_application_version
    });
  }
  if (error?.code === "23505") return res.status(409).json({ error: "operational_application_conflict", message: "That application action already exists." });
  console.error("[finance-operational-applications]", fallback, { code: error?.code, message: error?.message });
  return res.status(500).json({ error: fallback, message: "Operational application request failed." });
}

export function installFinanceOperationalApplicationRoutes({ app, pool, authRequired, requireFinanceAccess, ensureChartAccounts }) {
  const basePath = "/api/finance/accounting/operational-applications";

  async function prepare(poolOrClient, companyID, userID) {
    await ensureChartAccounts(poolOrClient, companyID, userID);
    await syncOperationalAccountingSources(poolOrClient, companyID);
  }

  async function assertApplicationMutationUnsettled(client, companyID, application, action, sourceCurrent) {
    if (!application?.id || (action === "post" && sourceCurrent)) return;
    const { rows } = await client.query(
      `SELECT member.settlement_id
         FROM finance_stripe_settlement_members member
        WHERE member.company_id=$1 AND member.operational_application_id=$2 AND member.active
        LIMIT 1 FOR SHARE`,
      [companyID, application.id]
    );
    if (rows.length) {
      throw new FinanceOperationalApplicationError(
        "stripe_settlement_application_locked",
        "Void the active Stripe settlement before replacing or voiding this payment/refund application.",
        409
      );
    }
  }

  app.get(basePath, authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Payment applications require a company workspace." });
    try {
      const context = await loadCompanyContext(pool, req.companyId);
      const end = req.query.end_date || context.company_today;
      const start = req.query.start_date || `${end.slice(0, 7)}-01`;
      const range = parseOperationalApplicationRange(start, end);
      await prepare(pool, req.companyId, req.userId);
      res.json({ timezone: context.timezone, company_today: context.company_today, ...(await loadReport(pool, req.companyId, range, boundedLimit(req.query.limit))) });
    } catch (error) {
      sendError(res, error, "operational_application_report_failed");
    }
  });

  app.get(`${basePath}/payments/:sourceId`, authRequired, requireFinanceAccess, async (req, res) => {
    try {
      await prepare(pool, req.companyId, req.userId);
      const sourceID = uuid(req.params.sourceId, "operational_source_id");
      const bundle = await loadPaymentBundle(pool, req.companyId, sourceID, allocationFromValues(0, req.query.accounts_receivable_cents, req.query.customer_credit_cents));
      res.json(await detailPayload(pool, req.companyId, "payment", bundle));
    } catch (error) { sendError(res, error, "payment_application_detail_failed"); }
  });

  app.get(`${basePath}/refunds/:revisionId`, authRequired, requireFinanceAccess, async (req, res) => {
    try {
      await prepare(pool, req.companyId, req.userId);
      const revisionID = uuid(req.params.revisionId, "refund_revision_id");
      const bundle = await loadRefundBundle(pool, req.companyId, revisionID, allocationFromValues(0, req.query.accounts_receivable_cents, req.query.customer_credit_cents));
      res.json(await detailPayload(pool, req.companyId, "refund", bundle));
    } catch (error) { sendError(res, error, "refund_application_detail_failed"); }
  });

  app.get(`${basePath}/customer-credits/:applicationId`, authRequired, requireFinanceAccess, async (req, res) => {
    try {
      await prepare(pool, req.companyId, req.userId);
      const bundle = await loadCreditBundle(pool, req.companyId, { applicationID: uuid(req.params.applicationId, "application_id") });
      res.json(await detailPayload(pool, req.companyId, "customer_credit", bundle));
    } catch (error) { sendError(res, error, "customer_credit_application_detail_failed"); }
  });

  app.get(`${basePath}/customer-credit-preview`, authRequired, requireFinanceAccess, async (req, res) => {
    try {
      await prepare(pool, req.companyId, req.userId);
      const bundle = await loadCreditBundle(pool, req.companyId, {
        originApplicationID: uuid(req.query.origin_application_id, "origin_application_id"),
        jobID: cleanString(req.query.job_id, 120),
        entryDate: req.query.entry_date,
        amountCents: req.query.amount_cents
      });
      res.json(await detailPayload(pool, req.companyId, "customer_credit", bundle));
    } catch (error) { sendError(res, error, "customer_credit_preview_failed"); }
  });

  const paymentMutation = (action) => async (req, res) => {
    const client = await pool.connect();
    try {
      const sourceID = uuid(req.params.sourceId, "operational_source_id");
      const allocation = action === "post" ? {
        accounts_receivable_cents: exactInteger(req.body.accounts_receivable_cents, "accounts_receivable_cents"),
        customer_credit_cents: exactInteger(req.body.customer_credit_cents, "customer_credit_cents")
      } : null;
      const request = normalizeMutation(req.body, action, {
        operational_source_id: sourceID,
        expected_source_version: exactInteger(req.body.expected_source_version, "expected_source_version", 1),
        allocation
      });
      await client.query("BEGIN");
      await client.query(`SELECT id FROM companies WHERE id=$1 FOR UPDATE`, [req.companyId]);
      await prepare(client, req.companyId, req.userId);
      const replayed = await replayedRequest(client, req.companyId, request);
      if (replayed) {
        await client.query("COMMIT");
        return res.json({ replayed: true, ...(await detailPayload(pool, req.companyId, "payment", await loadPaymentBundle(pool, req.companyId, sourceID))) });
      }
      const bundle = await loadPaymentBundle(client, req.companyId, sourceID, allocation, true);
      if (Number(bundle.source.source_version) !== request.expected_source_version) throw new FinanceOperationalApplicationError("payment_source_stale", "The payment source changed after it was loaded.", 409);
      await assertApplicationMutationUnsettled(client, req.companyId, bundle.application, action, bundle.evaluation.source_current);
      if (action === "post") {
        await commitApplication({ client, companyID: req.companyId, userID: req.userId, request, kind: "payment", bundle, identity: { operational_source_id: sourceID, job_id: bundle.source.job_id } });
      } else {
        await voidApplication({ client, companyID: req.companyId, userID: req.userId, request, application: bundle.application, canVoid: bundle.evaluation.can_void, sourceFingerprint: bundle.evaluation.source_fingerprint, sourceSnapshot: bundle.evaluation.source_snapshot });
      }
      await client.query("COMMIT");
      res.status(201).json({ replayed: false, ...(await detailPayload(pool, req.companyId, "payment", await loadPaymentBundle(pool, req.companyId, sourceID))) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendError(res, error, `payment_application_${action}_failed`);
    } finally { client.release(); }
  };

  const refundMutation = (action) => async (req, res) => {
    const client = await pool.connect();
    try {
      const revisionID = uuid(req.params.revisionId, "refund_revision_id");
      const allocation = action === "post" ? {
        accounts_receivable_cents: exactInteger(req.body.accounts_receivable_cents, "accounts_receivable_cents"),
        customer_credit_cents: exactInteger(req.body.customer_credit_cents, "customer_credit_cents")
      } : null;
      const request = normalizeMutation(req.body, action, { refund_revision_id: revisionID, expected_revision_version: exactInteger(req.body.expected_source_version, "expected_source_version", 1), allocation });
      await client.query("BEGIN");
      await client.query(`SELECT id FROM companies WHERE id=$1 FOR UPDATE`, [req.companyId]);
      await prepare(client, req.companyId, req.userId);
      const replayed = await replayedRequest(client, req.companyId, request);
      if (replayed) {
        await client.query("COMMIT");
        return res.json({ replayed: true, ...(await detailPayload(pool, req.companyId, "refund", await loadRefundBundle(pool, req.companyId, revisionID))) });
      }
      const bundle = await loadRefundBundle(client, req.companyId, revisionID, allocation, true);
      if (Number(bundle.revision.version) !== request.expected_revision_version) throw new FinanceOperationalApplicationError("refund_revision_stale", "The refund revision changed after it was loaded.", 409);
      await assertApplicationMutationUnsettled(client, req.companyId, bundle.application, action, bundle.evaluation.source_current);
      if (action === "post") {
        await commitApplication({ client, companyID: req.companyId, userID: req.userId, request, kind: "refund", bundle, identity: { refund_revision_id: revisionID, origin_application_id: bundle.origin?.id, job_id: bundle.origin?.job_id } });
      } else {
        await voidApplication({ client, companyID: req.companyId, userID: req.userId, request, application: bundle.application, canVoid: bundle.evaluation.can_void, sourceFingerprint: bundle.evaluation.source_fingerprint, sourceSnapshot: bundle.evaluation.source_snapshot });
      }
      await client.query("COMMIT");
      res.status(201).json({ replayed: false, ...(await detailPayload(pool, req.companyId, "refund", await loadRefundBundle(pool, req.companyId, revisionID))) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendError(res, error, `refund_application_${action}_failed`);
    } finally { client.release(); }
  };

  app.post(`${basePath}/payments/:sourceId/post`, authRequired, requireFinanceAccess, paymentMutation("post"));
  app.post(`${basePath}/payments/:sourceId/void`, authRequired, requireFinanceAccess, paymentMutation("void"));
  app.post(`${basePath}/refunds/:revisionId/post`, authRequired, requireFinanceAccess, refundMutation("post"));
  app.post(`${basePath}/refunds/:revisionId/void`, authRequired, requireFinanceAccess, refundMutation("void"));

  app.post(`${basePath}/customer-credits`, authRequired, requireFinanceAccess, async (req, res) => {
    const client = await pool.connect();
    try {
      const fields = {
        origin_application_id: uuid(req.body.origin_application_id, "origin_application_id"),
        expected_origin_version: exactInteger(req.body.expected_origin_version, "expected_origin_version", 1),
        job_id: cleanString(req.body.job_id, 120),
        entry_date: dateOnly(req.body.entry_date, "entry_date"),
        amount_cents: exactInteger(req.body.amount_cents, "amount_cents", 1)
      };
      const request = normalizeMutation(req.body, "post", fields);
      await client.query("BEGIN");
      await client.query(`SELECT id FROM companies WHERE id=$1 FOR UPDATE`, [req.companyId]);
      await prepare(client, req.companyId, req.userId);
      const replayed = await replayedRequest(client, req.companyId, request);
      if (replayed) {
        await client.query("COMMIT");
        return res.json({ replayed: true, ...(await detailPayload(pool, req.companyId, "customer_credit", await loadCreditBundle(pool, req.companyId, { applicationID: replayed }))) });
      }
      const bundle = await loadCreditBundle(client, req.companyId, { originApplicationID: fields.origin_application_id, jobID: fields.job_id, entryDate: fields.entry_date, amountCents: fields.amount_cents }, true);
      if (Number(bundle.origin.version) !== fields.expected_origin_version) throw new FinanceOperationalApplicationError("credit_origin_stale", "The origin payment application changed after it was loaded.", 409);
      await commitApplication({ client, companyID: req.companyId, userID: req.userId, request, kind: "customer_credit", bundle, identity: { origin_application_id: fields.origin_application_id, job_id: fields.job_id } });
      await client.query("COMMIT");
      const createdID = (await pool.query(`SELECT application_id FROM finance_operational_application_audit WHERE company_id=$1 AND client_request_id=$2`, [req.companyId, request.client_request_id])).rows[0].application_id;
      res.status(201).json({ replayed: false, ...(await detailPayload(pool, req.companyId, "customer_credit", await loadCreditBundle(pool, req.companyId, { applicationID: createdID }))) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendError(res, error, "customer_credit_application_post_failed");
    } finally { client.release(); }
  });

  app.post(`${basePath}/customer-credits/:applicationId/void`, authRequired, requireFinanceAccess, async (req, res) => {
    const client = await pool.connect();
    try {
      const applicationID = uuid(req.params.applicationId, "application_id");
      const request = normalizeMutation(req.body, "void", { application_id: applicationID });
      await client.query("BEGIN");
      await client.query(`SELECT id FROM companies WHERE id=$1 FOR UPDATE`, [req.companyId]);
      await prepare(client, req.companyId, req.userId);
      const replayed = await replayedRequest(client, req.companyId, request);
      if (replayed) {
        await client.query("COMMIT");
        return res.json({ replayed: true, ...(await detailPayload(pool, req.companyId, "customer_credit", await loadCreditBundle(pool, req.companyId, { applicationID }))) });
      }
      const bundle = await loadCreditBundle(client, req.companyId, { applicationID }, true);
      await voidApplication({ client, companyID: req.companyId, userID: req.userId, request, application: bundle.application, canVoid: bundle.evaluation.can_void, sourceFingerprint: bundle.evaluation.source_fingerprint, sourceSnapshot: bundle.evaluation.source_snapshot });
      await client.query("COMMIT");
      res.status(201).json({ replayed: false, ...(await detailPayload(pool, req.companyId, "customer_credit", await loadCreditBundle(pool, req.companyId, { applicationID }))) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendError(res, error, "customer_credit_application_void_failed");
    } finally { client.release(); }
  });
}
