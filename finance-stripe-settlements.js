import { createHash, randomUUID } from "node:crypto";
import {
  GeneralLedgerError,
  insertJournal,
  journalFingerprint,
  loadJournalEntry,
  reverseJournalLines,
  snapshotInput
} from "./finance-general-ledger.js";
import { syncOperationalAccountingSources } from "./finance-operational-accounting.js";
import { loadOperationalApplicationCloseEvaluation } from "./finance-operational-applications.js";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const STRIPE_ID_PATTERN = /^[A-Za-z]+_[A-Za-z0-9_]+$/;
const MAX_REPORT_DAYS = 731;
const MAX_PAYOUT_ROWS = 100;
const MAX_MEMBER_ROWS = 500;
const COLLECTED_STATUSES = new Set(["succeeded", "paid", "partially_refunded", "refunded"]);

export class FinanceStripeSettlementError extends Error {
  constructor(code, message, statusCode = 400, details = {}) {
    super(message);
    this.name = "FinanceStripeSettlementError";
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
    throw new FinanceStripeSettlementError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return normalized;
}

function stripeID(value, field, prefix = null) {
  const normalized = cleanString(value, 255);
  if (!STRIPE_ID_PATTERN.test(normalized) || (prefix && !normalized.startsWith(`${prefix}_`))) {
    throw new FinanceStripeSettlementError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return normalized;
}

function exactInteger(value, field, minimum = Number.MIN_SAFE_INTEGER) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value.trim()) ? Number(value.trim()) : value;
  if (!Number.isSafeInteger(parsed) || parsed < minimum) {
    throw new FinanceStripeSettlementError(`${field}_invalid`, `${field.replaceAll("_", " ")} must be an exact integer.`);
  }
  return parsed;
}

function storedInteger(value, field) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(parsed)) {
    throw new FinanceStripeSettlementError("stripe_settlement_amount_inexact", `${field.replaceAll("_", " ")} exceeds the exact supported range.`, 409);
  }
  return parsed;
}

function addExact(left, right, field) {
  const next = left + right;
  if (!Number.isSafeInteger(next)) {
    throw new FinanceStripeSettlementError("stripe_settlement_amount_inexact", `${field.replaceAll("_", " ")} exceeds the exact supported range.`, 409);
  }
  return next;
}

function dateOnly(value, field = "date") {
  const raw = value instanceof Date ? value.toISOString().slice(0, 10) : cleanString(value, 20);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    throw new FinanceStripeSettlementError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  const [year, month, day] = raw.split("-").map(Number);
  const parsed = new Date(Date.UTC(year, month - 1, day));
  if (parsed.getUTCFullYear() !== year || parsed.getUTCMonth() !== month - 1 || parsed.getUTCDate() !== day) {
    throw new FinanceStripeSettlementError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
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

function normalizedInstant(value) {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed.toISOString() : null;
}

function unixDate(value) {
  const seconds = exactInteger(value, "stripe_timestamp", 0);
  return new Date(seconds * 1000).toISOString().slice(0, 10);
}

function stripeObjectID(value) {
  if (typeof value === "string") return value;
  if (value && typeof value === "object") return value.id || null;
  return null;
}

function blocker(code, message) {
  return { code, message };
}

function uniqueBlockers(items) {
  return [...new Map(items.map((item) => [item.code, item])).values()];
}

export function parseStripeSettlementRange(startValue, endValue) {
  const startDate = dateOnly(startValue, "start_date");
  const endDate = dateOnly(endValue, "end_date");
  if (startDate > endDate) throw new FinanceStripeSettlementError("stripe_settlement_range_invalid", "Start date must be on or before end date.");
  if (addDays(startDate, MAX_REPORT_DAYS - 1) < endDate) {
    throw new FinanceStripeSettlementError("stripe_settlement_range_too_large", `Stripe settlement ranges cannot exceed ${MAX_REPORT_DAYS} days.`);
  }
  return { start_date: startDate, end_date: endDate };
}

function boundedLimit(value) {
  if (value === undefined || value === null || value === "") return 50;
  return Math.min(exactInteger(value, "limit", 1), MAX_PAYOUT_ROWS);
}

export function normalizeStripePayout(payout = {}) {
  const blockers = [];
  const id = cleanString(payout.id, 255);
  const amount = Number(payout.amount);
  const currency = cleanString(payout.currency, 10).toLowerCase();
  const automatic = payout.automatic === true;
  const method = cleanString(payout.method, 30).toLowerCase();
  const status = cleanString(payout.status, 30).toLowerCase();
  const reconciliationStatus = cleanString(payout.reconciliation_status, 40).toLowerCase();
  let arrivalDate = null;
  let createdAt = null;
  try { arrivalDate = unixDate(payout.arrival_date); } catch { blockers.push(blocker("stripe_payout_arrival_invalid", "Stripe payout arrival evidence is invalid.")); }
  try { createdAt = new Date(exactInteger(payout.created, "stripe_created", 0) * 1000).toISOString(); } catch { blockers.push(blocker("stripe_payout_created_invalid", "Stripe payout creation evidence is invalid.")); }
  if (!STRIPE_ID_PATTERN.test(id) || !id.startsWith("po_")) blockers.push(blocker("stripe_payout_id_invalid", "Stripe payout identity is missing or invalid."));
  if (!Number.isSafeInteger(amount) || amount <= 0) blockers.push(blocker("stripe_payout_amount_invalid", "Only positive exact Stripe payouts are supported."));
  if (currency !== "usd") blockers.push(blocker("stripe_payout_currency_unsupported", "Stripe settlement currently supports USD payouts only."));
  if (!automatic) blockers.push(blocker("stripe_payout_not_automatic", "Only automatic Stripe payouts expose supported exact membership."));
  if (method !== "standard") blockers.push(blocker("stripe_payout_method_unsupported", "Only standard Stripe payouts are supported; instant payouts remain blocked."));
  if (status !== "paid") blockers.push(blocker("stripe_payout_not_paid", "The Stripe payout must be paid before settlement."));
  if (reconciliationStatus !== "completed") blockers.push(blocker("stripe_payout_reconciliation_incomplete", "Stripe must report completed payout reconciliation before membership can settle."));
  return {
    stripe_payout_id: id || null,
    amount_cents: Number.isSafeInteger(amount) ? amount : 0,
    currency: currency || null,
    automatic,
    method: method || null,
    status: status || null,
    reconciliation_status: reconciliationStatus || null,
    arrival_date: arrivalDate,
    created_at: createdAt,
    eligible: blockers.length === 0,
    blockers: uniqueBlockers(blockers)
  };
}

export function normalizeStripeBalanceMembers(rawMembers = [], payoutCurrency = "usd") {
  if (!Array.isArray(rawMembers) || rawMembers.length === 0) {
    return {
      eligible: false,
      blockers: [blocker("stripe_payout_membership_empty", "Stripe returned no exact balance transactions for this payout.")],
      members: [], gross_cents: 0, fee_cents: 0, net_cents: 0
    };
  }
  if (rawMembers.length > MAX_MEMBER_ROWS) {
    return {
      eligible: false,
      blockers: [blocker("stripe_payout_membership_too_large", `Payout membership exceeds the supported ${MAX_MEMBER_ROWS}-item review bound.`)],
      members: [], gross_cents: 0, fee_cents: 0, net_cents: 0
    };
  }
  const blockers = [];
  const seenIDs = new Set();
  const seenSources = new Set();
  const members = [];
  let gross = 0;
  let fees = 0;
  let net = 0;
  for (const raw of rawMembers) {
    const id = cleanString(raw?.id, 255);
    const type = cleanString(raw?.type, 80).toLowerCase();
    const sourceID = cleanString(stripeObjectID(raw?.source), 255);
    const currency = cleanString(raw?.currency, 10).toLowerCase();
    const status = cleanString(raw?.status, 30).toLowerCase();
    const amount = Number(raw?.amount);
    const fee = Number(raw?.fee);
    const memberNet = Number(raw?.net);
    const itemBlockers = [];
    if (!STRIPE_ID_PATTERN.test(id) || !id.startsWith("txn_")) itemBlockers.push(blocker("stripe_balance_transaction_id_invalid", "A Stripe balance transaction has no stable identity."));
    if (!sourceID || !STRIPE_ID_PATTERN.test(sourceID)) itemBlockers.push(blocker("stripe_balance_source_id_invalid", "A Stripe balance transaction has no stable source identity."));
    if (id && seenIDs.has(id)) itemBlockers.push(blocker("stripe_balance_transaction_duplicate", "Stripe payout membership contains a duplicate balance transaction."));
    if (sourceID && seenSources.has(`${type}|${sourceID}`)) itemBlockers.push(blocker("stripe_balance_source_duplicate", "Stripe payout membership contains a duplicate provider source."));
    if (type !== "charge" && type !== "refund") itemBlockers.push(blocker("stripe_balance_type_unsupported", `Stripe balance type ${type || "unknown"} is not supported by exact settlement.`));
    if (status !== "available") itemBlockers.push(blocker("stripe_balance_not_available", "Every payout member must be available before settlement."));
    if (currency !== payoutCurrency || currency !== "usd") itemBlockers.push(blocker("stripe_balance_currency_mismatch", "Every payout member must use the exact supported payout currency."));
    if (!Number.isSafeInteger(amount) || !Number.isSafeInteger(fee) || !Number.isSafeInteger(memberNet)) {
      itemBlockers.push(blocker("stripe_balance_amount_inexact", "Stripe balance transaction amounts must be exact supported integers."));
    } else {
      if (fee < 0) itemBlockers.push(blocker("stripe_balance_fee_unsupported", "Negative provider-fee adjustments are not supported in this settlement slice."));
      if (amount - fee !== memberNet) itemBlockers.push(blocker("stripe_balance_math_invalid", "Stripe balance transaction amount minus fee does not equal net."));
      if (type === "charge" && amount <= 0) itemBlockers.push(blocker("stripe_charge_amount_invalid", "A supported charge balance transaction must have positive gross amount."));
      if (type === "refund" && amount >= 0) itemBlockers.push(blocker("stripe_refund_amount_invalid", "A supported refund balance transaction must have negative gross amount."));
    }
    if (id) seenIDs.add(id);
    if (sourceID) seenSources.add(`${type}|${sourceID}`);
    const normalized = {
      stripe_balance_transaction_id: id || null,
      type,
      stripe_source_id: sourceID || null,
      amount_cents: Number.isSafeInteger(amount) ? amount : 0,
      fee_cents: Number.isSafeInteger(fee) ? fee : 0,
      net_cents: Number.isSafeInteger(memberNet) ? memberNet : 0,
      currency: currency || null,
      status: status || null,
      eligible: itemBlockers.length === 0,
      blockers: uniqueBlockers(itemBlockers)
    };
    members.push(normalized);
    blockers.push(...itemBlockers);
    if (Number.isSafeInteger(amount)) gross = addExact(gross, amount, "gross_cents");
    if (Number.isSafeInteger(fee)) fees = addExact(fees, fee, "fee_cents");
    if (Number.isSafeInteger(memberNet)) net = addExact(net, memberNet, "net_cents");
  }
  if (gross - fees !== net) blockers.push(blocker("stripe_payout_member_math_invalid", "Stripe payout member totals do not reconcile exactly."));
  return {
    eligible: blockers.length === 0,
    blockers: uniqueBlockers(blockers),
    members: members.sort((left, right) => String(left.stripe_balance_transaction_id).localeCompare(String(right.stripe_balance_transaction_id))),
    gross_cents: gross,
    fee_cents: fees,
    net_cents: net
  };
}

export function canBindStripeRefundTransition({ observedCumulativeTransition, cumulativeRefundedCents, refundAmountCents }) {
  if (observedCumulativeTransition !== true) return false;
  const cumulative = exactInteger(cumulativeRefundedCents, "cumulative_refunded_cents", 0);
  const amount = exactInteger(refundAmountCents, "refund_amount_cents", 1);
  return cumulative >= amount;
}

function snapshotAccountMatches(snapshot, account, systemKey, accountType) {
  return Boolean(snapshot && account && account.active !== false
    && String(snapshot.chart_account_id || "") === String(account.id)
    && snapshot.system_key === systemKey
    && account.system_key === systemKey
    && snapshot.account_type === accountType
    && account.account_type === accountType
    && snapshot.active !== false);
}

function journalAuthorityCurrent(row, applicationID, applicationVersion) {
  return Boolean(row.journal_entry_id
    && row.journal_status === "posted"
    && row.journal_source_type === "finance_operational_application"
    && String(row.journal_source_id || "") === String(applicationID)
    && Number(row.journal_source_version || 0) === Number(applicationVersion || 0)
    && !row.journal_reversed_by_id);
}

function paymentApplicationCurrent(row, accounts) {
  if (!row?.application_id || row.application_kind !== "payment" || row.application_status !== "posted") return false;
  const snapshot = objectValue(row.application_source_snapshot);
  const allocation = objectValue(snapshot.allocation);
  const accountSnapshots = objectValue(snapshot.accounts);
  const amount = storedInteger(row.application_amount_cents ?? 0, "application_amount_cents");
  return journalAuthorityCurrent(row, row.application_id, row.application_version)
    && row.operational_source_id
    && !row.operational_source_removed_at
    && COLLECTED_STATUSES.has(row.operational_source_status)
    && Number(snapshot.source_version || 0) === Number(row.operational_source_version || 0)
    && String(snapshot.operational_source_id || "") === String(row.operational_source_id)
    && String(snapshot.payment_record_id || "") === String(row.payment_record_id)
    && snapshot.status === row.operational_source_status
    && storedInteger(snapshot.amount_cents ?? -1, "snapshot_amount_cents") === amount
    && storedInteger(row.operational_source_amount_cents ?? -1, "source_amount_cents") === amount
    && cleanString(snapshot.currency, 10).toLowerCase() === cleanString(row.operational_source_currency, 10).toLowerCase()
    && storedInteger(allocation.amount_cents ?? -1, "allocation_amount_cents") === amount
    && addExact(storedInteger(allocation.accounts_receivable_cents ?? 0, "allocation_ar_cents"), storedInteger(allocation.customer_credit_cents ?? 0, "allocation_credit_cents"), "allocation_total_cents") === amount
    && snapshotAccountMatches(accountSnapshots.accounts_receivable, accounts.accountsReceivable, "accounts_receivable", "asset")
    && snapshotAccountMatches(accountSnapshots.customer_credits, accounts.customerCredits, "customer_credits", "liability")
    && snapshotAccountMatches(accountSnapshots.payment_clearing, accounts.clearing, "payment_clearing", "asset");
}

function refundApplicationCurrent(row, accounts) {
  if (!row?.application_id || row.application_kind !== "refund" || row.application_status !== "posted") return false;
  const snapshot = objectValue(row.application_source_snapshot);
  const allocation = objectValue(snapshot.allocation);
  const accountSnapshots = objectValue(snapshot.accounts);
  const amount = storedInteger(row.application_amount_cents ?? 0, "refund_application_amount_cents");
  return journalAuthorityCurrent(row, row.application_id, row.application_version)
    && row.refund_revision_id
    && String(snapshot.refund_revision_id || "") === String(row.refund_revision_id)
    && String(snapshot.payment_record_id || "") === String(row.payment_record_id)
    && Number(snapshot.revision_version || 0) === Number(row.refund_revision_version || 0)
    && storedInteger(snapshot.amount_cents ?? -1, "refund_snapshot_amount_cents") === amount
    && storedInteger(row.delta_refunded_cents ?? -1, "refund_delta_cents") === amount
    && storedInteger(allocation.amount_cents ?? -1, "refund_allocation_amount_cents") === amount
    && addExact(storedInteger(allocation.accounts_receivable_cents ?? 0, "refund_allocation_ar_cents"), storedInteger(allocation.customer_credit_cents ?? 0, "refund_allocation_credit_cents"), "refund_allocation_total_cents") === amount
    && row.origin_application_id
    && row.origin_application_status === "posted"
    && Number(snapshot.origin_application_version || 0) === Number(row.origin_application_version || 0)
    && paymentApplicationCurrent({
      ...row,
      application_id: row.origin_application_id,
      application_kind: "payment",
      application_status: row.origin_application_status,
      application_version: row.origin_application_version,
      application_amount_cents: row.origin_application_amount_cents,
      application_source_snapshot: row.origin_application_source_snapshot,
      journal_entry_id: row.origin_journal_entry_id,
      journal_status: row.origin_journal_status,
      journal_source_type: row.origin_journal_source_type,
      journal_source_id: row.origin_journal_source_id,
      journal_source_version: row.origin_journal_source_version,
      journal_reversed_by_id: row.origin_journal_reversed_by_id
    }, accounts)
    && snapshotAccountMatches(accountSnapshots.accounts_receivable, accounts.accountsReceivable, "accounts_receivable", "asset")
    && snapshotAccountMatches(accountSnapshots.customer_credits, accounts.customerCredits, "customer_credits", "liability")
    && snapshotAccountMatches(accountSnapshots.payment_clearing, accounts.clearing, "payment_clearing", "asset");
}

function settlementPostingPayload(row) {
  if (!row) return null;
  return {
    id: String(row.id),
    stripe_payout_id: row.stripe_payout_id,
    bank_transaction_id: row.bank_transaction_id || null,
    journal_entry_id: row.journal_entry_id || null,
    status: row.status,
    version: Number(row.version || 0),
    source_fingerprint: row.source_fingerprint,
    reason: row.reason,
    updated_by: row.updated_by || null,
    updated_at: row.updated_at || null
  };
}

async function loadSystemAccounts(poolOrClient, companyID) {
  const { rows } = await poolOrClient.query(
    `SELECT id, code, name, account_type, system_key, active
       FROM finance_chart_accounts
      WHERE company_id=$1 AND system_key IN ('accounts_receivable','customer_credits','payment_clearing','merchant_bank_fees')`,
    [companyID]
  );
  const map = new Map(rows.map((row) => [row.system_key, row]));
  return {
    accountsReceivable: map.get("accounts_receivable") || null,
    customerCredits: map.get("customer_credits") || null,
    clearing: map.get("payment_clearing") || null,
    fees: map.get("merchant_bank_fees") || null
  };
}

async function loadStripeContext(poolOrClient, companyID) {
  const { rows } = await poolOrClient.query(
    `SELECT company.id AS company_id, company.owner_user_id,
            settings.stripe_account_id, settings.stripe_connect_status,
            settings.stripe_payouts_enabled, LOWER(COALESCE(settings.stripe_default_currency,'usd')) AS currency
       FROM companies company
       LEFT JOIN business_settings settings ON settings.user_id=company.owner_user_id
      WHERE company.id=$1`,
    [companyID]
  );
  if (!rows.length) throw new FinanceStripeSettlementError("company_not_found", "Company workspace was not found.", 404);
  const row = rows[0];
  if (!row.stripe_account_id) throw new FinanceStripeSettlementError("stripe_not_connected", "Connect the company Stripe account before reviewing settlements.", 409);
  if (row.currency !== "usd") throw new FinanceStripeSettlementError("stripe_account_currency_unsupported", "Stripe settlement currently supports USD connected accounts only.", 409);
  return { stripe_account_id: row.stripe_account_id, currency: row.currency };
}

function requireStripeClient(getStripe) {
  const stripe = typeof getStripe === "function" ? getStripe() : null;
  if (!stripe) throw new FinanceStripeSettlementError("stripe_not_configured", "Stripe is not configured for live settlement review.", 503);
  return stripe;
}

async function fetchPayout(stripe, connectedAccountID, payoutID) {
  try {
    return await stripe.payouts.retrieve(stripeID(payoutID, "stripe_payout_id", "po"), {}, { stripeAccount: connectedAccountID });
  } catch (error) {
    if (error instanceof FinanceStripeSettlementError) throw error;
    throw new FinanceStripeSettlementError("stripe_payout_unavailable", "Stripe payout evidence is temporarily unavailable.", 502);
  }
}

async function fetchPayoutMembers(stripe, connectedAccountID, payoutID) {
  const rows = [];
  let startingAfter;
  try {
    while (true) {
      const params = { payout: payoutID, limit: 100 };
      if (startingAfter) params.starting_after = startingAfter;
      const page = await stripe.balanceTransactions.list(params, { stripeAccount: connectedAccountID });
      if (!Array.isArray(page?.data)) throw new Error("invalid_stripe_page");
      rows.push(...page.data);
      if (rows.length > MAX_MEMBER_ROWS || (rows.length === MAX_MEMBER_ROWS && page.has_more)) {
        throw new FinanceStripeSettlementError("stripe_payout_membership_too_large", `Payout membership exceeds the supported ${MAX_MEMBER_ROWS}-item review bound.`, 409);
      }
      if (!page.has_more) break;
      startingAfter = page.data.at(-1)?.id;
      if (!startingAfter) throw new Error("invalid_stripe_cursor");
    }
    return rows;
  } catch (error) {
    if (error instanceof FinanceStripeSettlementError) throw error;
    throw new FinanceStripeSettlementError("stripe_payout_membership_unavailable", "Stripe payout membership is temporarily unavailable.", 502);
  }
}

async function loadPosting(poolOrClient, companyID, payoutID, lock = false) {
  const { rows } = await poolOrClient.query(
    `SELECT * FROM finance_stripe_settlements WHERE company_id=$1 AND stripe_payout_id=$2${lock ? " FOR UPDATE" : ""}`,
    [companyID, payoutID]
  );
  return rows[0] || null;
}

async function resolveMemberBindings(poolOrClient, companyID, connectedAccountID, normalized, accounts, currentSettlementID = null, lock = false) {
  const chargeIDs = normalized.members.filter((item) => item.type === "charge" && item.stripe_source_id).map((item) => item.stripe_source_id);
  const refundIDs = normalized.members.filter((item) => item.type === "refund" && item.stripe_source_id).map((item) => item.stripe_source_id);
  const chargeResult = chargeIDs.length ? await poolOrClient.query(
    `SELECT payment.id AS payment_record_id, payment.stripe_charge_id, payment.stripe_connected_account_id,
            payment.amount_cents AS payment_amount_cents, LOWER(COALESCE(payment.currency,'usd')) AS payment_currency,
            source.id AS operational_source_id, source.source_version AS operational_source_version,
            source.status AS operational_source_status, source.amount_cents AS operational_source_amount_cents,
            source.currency AS operational_source_currency, source.removed_at AS operational_source_removed_at,
            application.id AS application_id, application.kind AS application_kind,
            application.status AS application_status, application.version AS application_version,
            application.amount_cents AS application_amount_cents,
            application.source_snapshot AS application_source_snapshot,
            application.journal_entry_id,
            journal.status AS journal_status, journal.source_type AS journal_source_type,
            journal.source_id AS journal_source_id, journal.source_version AS journal_source_version,
            reversed.id AS journal_reversed_by_id
       FROM payment_records payment
       LEFT JOIN finance_operational_sources source
         ON source.company_id=payment.company_id AND source.payment_record_id=payment.id AND source.source_type='payment'
       LEFT JOIN finance_operational_applications application
         ON application.company_id=source.company_id AND application.operational_source_id=source.id AND application.kind='payment'
       LEFT JOIN finance_journal_entries journal
         ON journal.company_id=application.company_id AND journal.id=application.journal_entry_id
       LEFT JOIN finance_journal_entries reversed
         ON reversed.company_id=journal.company_id AND reversed.reversal_of_entry_id=journal.id
      WHERE payment.company_id=$1 AND payment.stripe_connected_account_id=$2
        AND payment.stripe_charge_id=ANY($3::text[])${lock ? " FOR UPDATE OF payment" : ""}`,
    [companyID, connectedAccountID, chargeIDs]
  ) : { rows: [] };
  const refundResult = refundIDs.length ? await poolOrClient.query(
    `SELECT evidence.id AS evidence_id, evidence.stripe_refund_id, evidence.stripe_charge_id,
            evidence.stripe_balance_transaction_id, evidence.amount_cents AS evidence_amount_cents,
            evidence.currency AS evidence_currency, evidence.status AS evidence_status,
            evidence.payment_record_id, evidence.refund_revision_id,
            revision.version AS refund_revision_version, revision.delta_refunded_cents,
            application.id AS application_id, application.kind AS application_kind,
            application.status AS application_status, application.version AS application_version,
            application.amount_cents AS application_amount_cents,
            application.source_snapshot AS application_source_snapshot,
            application.journal_entry_id,
            journal.status AS journal_status, journal.source_type AS journal_source_type,
            journal.source_id AS journal_source_id, journal.source_version AS journal_source_version,
            reversed.id AS journal_reversed_by_id,
            origin.id AS origin_application_id, origin.status AS origin_application_status,
            origin.version AS origin_application_version, origin.amount_cents AS origin_application_amount_cents,
            origin.source_snapshot AS origin_application_source_snapshot,
            origin.journal_entry_id AS origin_journal_entry_id,
            origin_journal.status AS origin_journal_status, origin_journal.source_type AS origin_journal_source_type,
            origin_journal.source_id AS origin_journal_source_id, origin_journal.source_version AS origin_journal_source_version,
            origin_reversed.id AS origin_journal_reversed_by_id,
            payment.stripe_connected_account_id, payment.stripe_charge_id AS payment_stripe_charge_id,
            source.id AS operational_source_id, source.source_version AS operational_source_version,
            source.status AS operational_source_status, source.amount_cents AS operational_source_amount_cents,
            source.currency AS operational_source_currency, source.removed_at AS operational_source_removed_at
       FROM finance_stripe_refund_evidence evidence
       LEFT JOIN finance_payment_refund_revisions revision
         ON revision.company_id=evidence.company_id AND revision.id=evidence.refund_revision_id
       LEFT JOIN finance_operational_applications application
         ON application.company_id=revision.company_id AND application.refund_revision_id=revision.id AND application.kind='refund'
       LEFT JOIN finance_journal_entries journal
         ON journal.company_id=application.company_id AND journal.id=application.journal_entry_id
       LEFT JOIN finance_journal_entries reversed
         ON reversed.company_id=journal.company_id AND reversed.reversal_of_entry_id=journal.id
       LEFT JOIN finance_operational_applications origin
         ON origin.company_id=application.company_id AND origin.id=application.origin_application_id AND origin.kind='payment'
       LEFT JOIN finance_journal_entries origin_journal
         ON origin_journal.company_id=origin.company_id AND origin_journal.id=origin.journal_entry_id
       LEFT JOIN finance_journal_entries origin_reversed
         ON origin_reversed.company_id=origin_journal.company_id AND origin_reversed.reversal_of_entry_id=origin_journal.id
       LEFT JOIN payment_records payment
         ON payment.company_id=evidence.company_id AND payment.id=evidence.payment_record_id
       LEFT JOIN finance_operational_sources source
         ON source.company_id=payment.company_id AND source.payment_record_id=payment.id AND source.source_type='payment'
      WHERE evidence.company_id=$1 AND evidence.stripe_connected_account_id=$2
        AND evidence.stripe_refund_id=ANY($3::text[])${lock ? " FOR UPDATE OF evidence" : ""}`,
    [companyID, connectedAccountID, refundIDs]
  ) : { rows: [] };
  const chargeByID = new Map();
  chargeResult.rows.forEach((row) => chargeByID.set(row.stripe_charge_id, [...(chargeByID.get(row.stripe_charge_id) || []), row]));
  const refundByID = new Map();
  refundResult.rows.forEach((row) => refundByID.set(row.stripe_refund_id, [...(refundByID.get(row.stripe_refund_id) || []), row]));
  const applicationIDs = [];
  const balanceIDs = normalized.members.map((item) => item.stripe_balance_transaction_id).filter(Boolean);
  const provisional = normalized.members.map((member) => {
    const rows = member.type === "charge" ? (chargeByID.get(member.stripe_source_id) || []) : (refundByID.get(member.stripe_source_id) || []);
    const itemBlockers = [...member.blockers];
    let row = null;
    if (rows.length !== 1) {
      itemBlockers.push(blocker(
        member.type === "charge" ? "stripe_charge_application_unresolved" : "stripe_refund_application_unresolved",
        `Stripe ${member.type} ${member.stripe_source_id || "source"} must resolve to exactly one current reviewed application.`
      ));
    } else {
      row = rows[0];
      if (member.type === "charge") {
        if (storedInteger(row.payment_amount_cents ?? -1, "payment_amount_cents") !== member.amount_cents
            || cleanString(row.payment_currency, 10).toLowerCase() !== member.currency) {
          itemBlockers.push(blocker("stripe_charge_payment_mismatch", "Stripe charge gross/currency does not equal the retained payment."));
        }
        if (!paymentApplicationCurrent(row, accounts)) itemBlockers.push(blocker("stripe_payment_application_not_current", "The exact Stripe charge payment application is not currently posted from current evidence."));
      } else {
        if (row.stripe_balance_transaction_id !== member.stripe_balance_transaction_id
            || row.stripe_charge_id !== row.payment_stripe_charge_id
            || storedInteger(row.evidence_amount_cents ?? -1, "refund_evidence_amount_cents") !== Math.abs(member.amount_cents)
            || cleanString(row.evidence_currency, 10).toLowerCase() !== member.currency
            || row.evidence_status !== "succeeded") {
          itemBlockers.push(blocker("stripe_refund_evidence_mismatch", "Stripe refund identity, success, amount, currency, Charge, or balance transaction is not exact."));
        }
        if (!row.refund_revision_id) itemBlockers.push(blocker("stripe_refund_revision_unbound", "This Stripe refund was not observed as one exact refund revision and cannot be inferred."));
        if (!refundApplicationCurrent(row, accounts)) itemBlockers.push(blocker("stripe_refund_application_not_current", "The exact Stripe refund application or its parent payment is not currently posted from current evidence."));
      }
    }
    if (row?.application_id) applicationIDs.push(String(row.application_id));
    return {
      ...member,
      payment_record_id: row?.payment_record_id ? String(row.payment_record_id) : null,
      refund_revision_id: row?.refund_revision_id ? String(row.refund_revision_id) : null,
      application_id: row?.application_id ? String(row.application_id) : null,
      application_kind: row?.application_kind || (member.type === "charge" ? "payment" : "refund"),
      application_version: row?.application_version ? Number(row.application_version) : null,
      eligible: itemBlockers.length === 0,
      blockers: uniqueBlockers(itemBlockers)
    };
  });
  const duplicateApplications = new Set(applicationIDs.filter((id, index) => applicationIDs.indexOf(id) !== index));
  const conflictResult = balanceIDs.length || applicationIDs.length ? await poolOrClient.query(
    `SELECT stripe_balance_transaction_id, operational_application_id
       FROM finance_stripe_settlement_members
      WHERE company_id=$1 AND active
        AND ($2::uuid IS NULL OR settlement_id<>$2::uuid)
        AND (stripe_balance_transaction_id=ANY($3::text[]) OR operational_application_id=ANY($4::uuid[]))${lock ? " FOR UPDATE" : ""}`,
    [companyID, currentSettlementID, balanceIDs.length ? balanceIDs : [""], applicationIDs.length ? applicationIDs : ["00000000-0000-0000-0000-000000000000"]]
  ) : { rows: [] };
  const conflictingBalances = new Set(conflictResult.rows.map((row) => row.stripe_balance_transaction_id));
  const conflictingApplications = new Set(conflictResult.rows.map((row) => String(row.operational_application_id)));
  return provisional.map((member) => {
    const itemBlockers = [...member.blockers];
    if (duplicateApplications.has(member.application_id)) itemBlockers.push(blocker("stripe_application_member_duplicate", "One operational application appears more than once in this payout."));
    if (conflictingBalances.has(member.stripe_balance_transaction_id)) itemBlockers.push(blocker("stripe_balance_transaction_already_settled", "This Stripe balance transaction already belongs to another active settlement."));
    if (conflictingApplications.has(member.application_id)) itemBlockers.push(blocker("stripe_application_already_settled", "This operational application already belongs to another active settlement."));
    return { ...member, eligible: itemBlockers.length === 0, blockers: uniqueBlockers(itemBlockers) };
  });
}

async function loadBankEvidence(poolOrClient, companyID, transactionID, currentSettlementID = null, lock = false) {
  if (!transactionID) return null;
  const transactionResult = await poolOrClient.query(
    `SELECT source_transaction.*, account.name AS finance_account_name, account.currency AS finance_account_currency,
            account.archived_at AS finance_account_archived_at
       FROM finance_transactions source_transaction
       JOIN finance_accounts account ON account.company_id=source_transaction.company_id AND account.id=source_transaction.account_id
      WHERE source_transaction.company_id=$1 AND source_transaction.id=$2${lock ? " FOR UPDATE OF source_transaction, account" : ""}`,
    [companyID, transactionID]
  );
  if (!transactionResult.rows.length) return null;
  const transaction = transactionResult.rows[0];
  const mappingResult = await poolOrClient.query(
    `SELECT mapping.*, chart.code, chart.name, chart.account_type, chart.system_key, chart.active
       FROM finance_account_chart_mappings mapping
       LEFT JOIN finance_chart_accounts chart ON chart.company_id=mapping.company_id AND chart.id=mapping.chart_account_id
      WHERE mapping.company_id=$1 AND mapping.finance_account_id=$2${lock ? " FOR UPDATE OF mapping" : ""}`,
    [companyID, transaction.account_id]
  );
  const splitsResult = await poolOrClient.query(
    `SELECT split.*, chart.code, chart.name, chart.account_type, chart.system_key, chart.active
       FROM finance_transaction_splits split
       JOIN finance_chart_accounts chart ON chart.company_id=split.company_id AND chart.id=split.chart_account_id
      WHERE split.company_id=$1 AND split.transaction_id=$2 ORDER BY chart.code, split.id${lock ? " FOR SHARE OF split, chart" : ""}`,
    [companyID, transactionID]
  );
  const postingResult = await poolOrClient.query(
    `SELECT id, status FROM finance_bank_transaction_postings WHERE company_id=$1 AND finance_transaction_id=$2${lock ? " FOR UPDATE" : ""}`,
    [companyID, transactionID]
  );
  const transferResult = await poolOrClient.query(
    `SELECT pair_id FROM finance_transfer_pair_members WHERE company_id=$1 AND finance_transaction_id=$2 AND active${lock ? " FOR UPDATE" : ""}`,
    [companyID, transactionID]
  );
  const settlementResult = await poolOrClient.query(
    `SELECT id, stripe_payout_id FROM finance_stripe_settlements
      WHERE company_id=$1 AND bank_transaction_id=$2 AND status='posted'
        AND ($3::uuid IS NULL OR id<>$3::uuid)${lock ? " FOR UPDATE" : ""}`,
    [companyID, transactionID, currentSettlementID]
  );
  return {
    transaction,
    mapping: mappingResult.rows[0] || null,
    splits: splitsResult.rows,
    individualPosting: postingResult.rows[0] || null,
    transferMembership: transferResult.rows[0] || null,
    otherSettlement: settlementResult.rows[0] || null
  };
}

export function evaluateStripeSettlementBank({ bankEvidence, payout, accounts }) {
  const blockers = [];
  if (!bankEvidence) {
    blockers.push(blocker("stripe_settlement_bank_required", "Explicitly select one eligible reconciled Finance deposit."));
    return { eligible: false, blockers, snapshot: null };
  }
  const { transaction, mapping, splits, individualPosting, transferMembership, otherSettlement } = bankEvidence;
  const amount = storedInteger(transaction.amount_cents ?? 0, "bank_amount_cents");
  const currency = cleanString(transaction.iso_currency_code || transaction.finance_account_currency || "usd", 10).toLowerCase();
  if (transaction.status !== "posted" || transaction.pending) blockers.push(blocker("stripe_settlement_bank_not_posted", "The selected bank transaction must be active and posted."));
  if (transaction.removed_at) blockers.push(blocker("stripe_settlement_bank_removed", "The selected bank transaction was removed by its provider."));
  if (transaction.finance_account_archived_at) blockers.push(blocker("stripe_settlement_bank_account_archived", "The selected Finance account is archived."));
  if (transaction.direction !== "income") blockers.push(blocker("stripe_settlement_bank_direction_invalid", "The selected bank transaction must be money in."));
  if ((transaction.reconciliation_status || "unreconciled") !== "reconciled") blockers.push(blocker("stripe_settlement_bank_not_reconciled", "Mark the selected bank transaction Reconciled first."));
  if (currency !== "usd" || cleanString(transaction.finance_account_currency || "usd", 10).toLowerCase() !== "usd") blockers.push(blocker("stripe_settlement_bank_currency_unsupported", "The selected bank transaction and Finance account must use USD."));
  if (amount !== payout.amount_cents) blockers.push(blocker("stripe_settlement_bank_amount_mismatch", "The selected bank transaction must equal the exact Stripe payout net."));
  if (!mapping?.chart_account_id || mapping.active === false || mapping.account_type !== "asset" || mapping.system_key === "payment_clearing") {
    blockers.push(blocker("stripe_settlement_bank_mapping_invalid", "Map the selected Finance account to one active bank asset account, not Payment Clearing."));
  }
  if (!Array.isArray(splits) || splits.length !== 1
      || splits[0].active === false
      || splits[0].system_key !== "payment_clearing"
      || String(splits[0].chart_account_id || "") !== String(accounts?.clearing?.id || "")
      || storedInteger(splits[0].amount_cents ?? 0, "bank_allocation_cents") !== amount) {
    blockers.push(blocker("stripe_settlement_bank_classification_invalid", "Classify the full selected deposit exactly to Payment Clearing before settlement."));
  }
  if (individualPosting?.status === "posted") blockers.push(blocker("stripe_settlement_bank_individual_posting", "Void the selected deposit's individual bank-source journal first."));
  if (transferMembership?.pair_id) blockers.push(blocker("stripe_settlement_bank_transfer_membership", "The selected deposit belongs to an active bank-transfer pair."));
  if (otherSettlement?.id) blockers.push(blocker("stripe_settlement_bank_already_used", "The selected deposit already belongs to another active Stripe settlement."));
  const snapshot = {
    finance_transaction_id: String(transaction.id),
    finance_account_id: String(transaction.account_id),
    finance_account_name: transaction.finance_account_name,
    transaction_date: dateOnly(transaction.transaction_date, "bank_transaction_date"),
    amount_cents: amount,
    currency,
    status: transaction.status,
    direction: transaction.direction,
    pending: Boolean(transaction.pending),
    removed: Boolean(transaction.removed_at),
    reconciliation_status: transaction.reconciliation_status || "unreconciled",
    accounting_version: Number(transaction.accounting_version || 1),
    mapping: mapping ? {
      mapping_id: String(mapping.id),
      version: Number(mapping.version || 0),
      chart_account_id: mapping.chart_account_id ? String(mapping.chart_account_id) : null,
      chart_account_type: mapping.account_type || null,
      chart_account_system_key: mapping.system_key || null,
      chart_account_active: mapping.active !== false
    } : null,
    allocations: (splits || []).map((split) => ({
      chart_account_id: String(split.chart_account_id),
      system_key: split.system_key || null,
      account_type: split.account_type || null,
      amount_cents: storedInteger(split.amount_cents, "bank_allocation_cents"),
      active: split.active !== false
    })),
    individual_posting_status: individualPosting?.status || null,
    active_transfer_pair_id: transferMembership?.pair_id ? String(transferMembership.pair_id) : null,
    active_other_settlement_id: otherSettlement?.id ? String(otherSettlement.id) : null
  };
  return { eligible: blockers.length === 0, blockers: uniqueBlockers(blockers), snapshot };
}

function settlementVersion(posting) {
  return posting ? Number(posting.version || 0) : 0;
}

function chartAccountPayload(account) {
  return account ? {
    id: String(account.id), code: account.code, name: account.name,
    account_type: account.account_type, system_key: account.system_key || null,
    active: account.active !== false
  } : null;
}

export function evaluateStripeSettlement({ payout, normalizedMembers, members, bankEvidence, accounts, posting = null }) {
  const blockers = [...(payout?.blockers || []), ...(normalizedMembers?.blockers || [])];
  for (const member of members || []) blockers.push(...(member.blockers || []));
  const bank = evaluateStripeSettlementBank({ bankEvidence, payout, accounts });
  blockers.push(...bank.blockers);
  if (!accounts?.clearing || accounts.clearing.active === false || accounts.clearing.system_key !== "payment_clearing" || accounts.clearing.account_type !== "asset") {
    blockers.push(blocker("payment_clearing_account_invalid", "The active system Payment Clearing asset is unavailable."));
  }
  if (!accounts?.fees || accounts.fees.active === false || accounts.fees.system_key !== "merchant_bank_fees" || accounts.fees.account_type !== "expense") {
    blockers.push(blocker("merchant_fee_account_invalid", "The active system Merchant & Bank Fees expense account is unavailable."));
  }
  const gross = storedInteger(normalizedMembers?.gross_cents ?? 0, "gross_cents");
  const fees = storedInteger(normalizedMembers?.fee_cents ?? 0, "fee_cents");
  const net = storedInteger(normalizedMembers?.net_cents ?? 0, "net_cents");
  if (gross <= 0 || net <= 0 || fees < 0 || gross - fees !== net || net !== payout.amount_cents) {
    blockers.push(blocker("stripe_settlement_totals_invalid", "Exact provider gross minus fees must equal the positive payout and selected bank net."));
  }
  const unique = uniqueBlockers(blockers);
  const memberSnapshots = (members || []).map((member) => ({
    stripe_balance_transaction_id: member.stripe_balance_transaction_id,
    type: member.type,
    stripe_source_id: member.stripe_source_id,
    amount_cents: member.amount_cents,
    fee_cents: member.fee_cents,
    net_cents: member.net_cents,
    currency: member.currency,
    status: member.status,
    payment_record_id: member.payment_record_id,
    refund_revision_id: member.refund_revision_id,
    operational_application_id: member.application_id,
    application_kind: member.application_kind,
    application_version: member.application_version
  })).sort((left, right) => left.stripe_balance_transaction_id.localeCompare(right.stripe_balance_transaction_id));
  const sourceSnapshot = {
    payout: {
      stripe_payout_id: payout.stripe_payout_id,
      automatic: payout.automatic,
      method: payout.method,
      status: payout.status,
      reconciliation_status: payout.reconciliation_status,
      amount_cents: payout.amount_cents,
      currency: payout.currency,
      arrival_date: payout.arrival_date,
      created_at: payout.created_at
    },
    totals: { gross_cents: gross, fee_cents: fees, net_cents: net },
    members: memberSnapshots,
    bank: bank.snapshot,
    accounts: {
      payment_clearing: chartAccountPayload(accounts?.clearing),
      merchant_bank_fees: chartAccountPayload(accounts?.fees)
    }
  };
  const sourceFingerprint = fingerprint(sourceSnapshot);
  const eligible = unique.length === 0;
  const sourceCurrent = eligible && posting?.status === "posted" && posting.source_fingerprint === sourceFingerprint;
  let reviewState = "blocked";
  if (sourceCurrent) reviewState = "posted";
  else if (posting?.status === "posted") reviewState = "stale";
  else if (posting?.status === "voided") reviewState = "voided";
  else if (eligible) reviewState = "ready";
  let journalPreview = null;
  if (eligible) {
    const lines = [{
      position: 0,
      chart_account_id: String(bankEvidence.mapping.chart_account_id),
      debit_cents: net,
      credit_cents: 0,
      memo: "Exact Stripe payout deposited"
    }];
    if (fees > 0) lines.push({
      position: lines.length,
      chart_account_id: String(accounts.fees.id),
      debit_cents: fees,
      credit_cents: 0,
      memo: "Exact Stripe provider fees"
    });
    lines.push({
      position: lines.length,
      chart_account_id: String(accounts.clearing.id),
      debit_cents: 0,
      credit_cents: gross,
      memo: "Exact settled payment clearing"
    });
    journalPreview = {
      entry_date: bank.snapshot.transaction_date,
      total_debits_cents: gross,
      total_credits_cents: gross,
      lines
    };
  }
  return {
    eligible,
    blockers: unique,
    review_state: reviewState,
    source_current: sourceCurrent,
    can_post: eligible && !sourceCurrent,
    can_void: posting?.status === "posted" && Boolean(posting.journal_entry_id),
    source_fingerprint: sourceFingerprint,
    source_snapshot: sourceSnapshot,
    journal_preview: journalPreview
  };
}

async function loadSettlementEvaluation(poolOrClient, companyID, connectedAccountID, payout, normalizedMembers, bankTransactionID, lock = false) {
  if (lock) await syncOperationalAccountingSources(poolOrClient, companyID);
  else await syncOperationalAccountingSources(poolOrClient, companyID);
  const posting = await loadPosting(poolOrClient, companyID, payout.stripe_payout_id, lock);
  const accounts = await loadSystemAccounts(poolOrClient, companyID);
  const members = await resolveMemberBindings(poolOrClient, companyID, connectedAccountID, normalizedMembers, accounts, posting?.id || null, lock);
  const selectedID = bankTransactionID || posting?.bank_transaction_id || null;
  const bankEvidence = selectedID ? await loadBankEvidence(poolOrClient, companyID, uuid(selectedID, "bank_transaction_id"), posting?.id || null, lock) : null;
  const evaluation = evaluateStripeSettlement({ payout, normalizedMembers, members, bankEvidence, accounts, posting });
  return { posting, accounts, members, bankEvidence, evaluation };
}

async function loadBankCandidates(poolOrClient, companyID, payout, accounts, currentSettlementID = null) {
  const { rows } = await poolOrClient.query(
    `SELECT id FROM finance_transactions
      WHERE company_id=$1 AND direction='income' AND amount_cents=$2 AND status='posted'
        AND pending=false AND removed_at IS NULL
      ORDER BY transaction_date DESC, created_at DESC LIMIT 100`,
    [companyID, payout.amount_cents]
  );
  const candidates = [];
  for (const row of rows) {
    const evidence = await loadBankEvidence(poolOrClient, companyID, row.id, currentSettlementID, false);
    const result = evaluateStripeSettlementBank({ bankEvidence: evidence, payout, accounts });
    if (!result.eligible) continue;
    candidates.push({
      transaction_id: result.snapshot.finance_transaction_id,
      transaction_date: result.snapshot.transaction_date,
      amount_cents: result.snapshot.amount_cents,
      currency: result.snapshot.currency,
      merchant_name: evidence.transaction.merchant_name || evidence.transaction.original_name || "Bank deposit",
      finance_account_id: result.snapshot.finance_account_id,
      finance_account_name: result.snapshot.finance_account_name,
      accounting_version: result.snapshot.accounting_version,
      mapping_version: result.snapshot.mapping?.version || 0,
      mapped_chart_account_id: result.snapshot.mapping?.chart_account_id || null,
      mapped_chart_account_name: evidence.mapping?.name || null
    });
  }
  return candidates;
}

async function loadAudit(poolOrClient, companyID, settlementID) {
  if (!settlementID) return [];
  const { rows } = await poolOrClient.query(
    `SELECT id, action, reason, version, actor_user_id, previous_journal_entry_id,
            journal_entry_id, reversal_entry_id, created_at
       FROM finance_stripe_settlement_audit
      WHERE company_id=$1 AND settlement_id=$2 ORDER BY created_at DESC LIMIT 50`,
    [companyID, settlementID]
  );
  return rows.map((row) => ({
    id: String(row.id), action: row.action, reason: row.reason, version: Number(row.version),
    actor_user_id: row.actor_user_id || null, previous_journal_entry_id: row.previous_journal_entry_id || null,
    journal_entry_id: row.journal_entry_id || null, reversal_entry_id: row.reversal_entry_id || null,
    created_at: row.created_at || null
  }));
}

async function detailPayload(poolOrClient, companyID, connectedAccountID, payout, rawMembers, bankTransactionID = null) {
  const normalizedMembers = normalizeStripeBalanceMembers(rawMembers, payout.currency);
  const bundle = await loadSettlementEvaluation(poolOrClient, companyID, connectedAccountID, payout, normalizedMembers, bankTransactionID, false);
  const candidates = await loadBankCandidates(poolOrClient, companyID, payout, bundle.accounts, bundle.posting?.id || null);
  return {
    basis: "exact_stripe_automatic_payout_settlement",
    currency: "usd",
    provider_available: true,
    payout,
    totals: {
      gross_cents: normalizedMembers.gross_cents,
      fee_cents: normalizedMembers.fee_cents,
      net_cents: normalizedMembers.net_cents
    },
    members: bundle.members,
    bank_candidates: candidates,
    selected_bank_transaction: bundle.evaluation.source_snapshot.bank,
    posting: settlementPostingPayload(bundle.posting),
    ...bundle.evaluation,
    journal: bundle.posting?.journal_entry_id ? await loadJournalEntry(poolOrClient, companyID, bundle.posting.journal_entry_id) : null,
    audit: await loadAudit(poolOrClient, companyID, bundle.posting?.id || null),
    warnings: [
      "Only automatic standard paid Stripe payouts with completed reconciliation and fully identified charge/refund membership can post.",
      "Bank selection is explicit. Amount, date, description, and arrival timing never create settlement identity.",
      "This journal moves reviewed Payment Clearing to bank cash and exact provider fees; it does not recognize revenue or change Phase 1 cash Profit & Loss."
    ]
  };
}

export async function loadStripeSettlementLocalCloseEvaluation(poolOrClient, companyID, settlementID) {
  const postingResult = await poolOrClient.query(
    `SELECT * FROM finance_stripe_settlements WHERE company_id=$1 AND id=$2`,
    [companyID, settlementID]
  );
  const posting = postingResult.rows[0];
  if (!posting) throw new FinanceStripeSettlementError("stripe_settlement_not_found", "Stripe settlement was not found.", 404);
  const retained = objectValue(posting.source_snapshot);
  const payout = { ...objectValue(retained.payout), blockers: [] };
  const totals = objectValue(retained.totals);
  const retainedMembers = Array.isArray(retained.members) ? retained.members : [];
  const memberResult = await poolOrClient.query(
    `SELECT * FROM finance_stripe_settlement_members
      WHERE company_id=$1 AND settlement_id=$2 AND settlement_version=$3 AND active=true
      ORDER BY stripe_balance_transaction_id`,
    [companyID, settlementID, posting.version]
  );
  const retainedByBalance = new Map(retainedMembers.map((member) => [String(member.stripe_balance_transaction_id), member]));
  const members = [];
  for (const row of memberResult.rows) {
    const retainedMember = retainedByBalance.get(String(row.stripe_balance_transaction_id)) || {};
    const applicationEvaluation = await loadOperationalApplicationCloseEvaluation(poolOrClient, companyID, row.operational_application_id);
    const memberBlockers = [];
    if (!retainedByBalance.has(String(row.stripe_balance_transaction_id))) {
      memberBlockers.push(blocker("stripe_settlement_member_not_retained", "A current local settlement member is absent from retained provider evidence."));
    }
    if (applicationEvaluation.source_current !== true
        || String(applicationEvaluation.authority_id || "") !== String(row.operational_application_id)
        || Number(applicationEvaluation.authority_version) !== Number(row.application_version)
        || Number(row.application_version) !== Number(retainedMember.application_version)
        || String(row.operational_application_id) !== String(retainedMember.operational_application_id || "")) {
      memberBlockers.push(blocker("stripe_settlement_application_stale", "A retained settlement member no longer matches its current reviewed application."));
    }
    members.push({
      stripe_balance_transaction_id: String(row.stripe_balance_transaction_id),
      type: row.member_type,
      stripe_source_id: row.stripe_source_id,
      amount_cents: storedInteger(row.amount_cents, "member_amount_cents"),
      fee_cents: storedInteger(row.fee_cents, "member_fee_cents"),
      net_cents: storedInteger(row.net_cents, "member_net_cents"),
      currency: row.currency,
      status: retainedMember.status || "available",
      payment_record_id: retainedMember.payment_record_id || null,
      refund_revision_id: retainedMember.refund_revision_id || null,
      application_id: String(row.operational_application_id),
      application_kind: retainedMember.application_kind || null,
      application_version: Number(row.application_version),
      blockers: memberBlockers
    });
  }
  const activeBalanceIDs = new Set(members.map((member) => member.stripe_balance_transaction_id));
  const missingRetainedCount = retainedMembers.filter((member) => !activeBalanceIDs.has(String(member.stripe_balance_transaction_id))).length;
  const normalizedMembers = {
    gross_cents: storedInteger(totals.gross_cents ?? 0, "gross_cents"),
    fee_cents: storedInteger(totals.fee_cents ?? 0, "fee_cents"),
    net_cents: storedInteger(totals.net_cents ?? 0, "net_cents"),
    blockers: missingRetainedCount > 0
      ? [blocker("stripe_settlement_member_missing", `${missingRetainedCount} retained settlement member${missingRetainedCount === 1 ? " is" : "s are"} no longer active.`)]
      : []
  };
  const [accounts, bankEvidence] = await Promise.all([
    loadSystemAccounts(poolOrClient, companyID),
    loadBankEvidence(poolOrClient, companyID, posting.bank_transaction_id, posting.id, false)
  ]);
  return evaluateStripeSettlement({ payout, normalizedMembers, members, bankEvidence, accounts, posting });
}

function storedDetailPayload(posting, journal, audit) {
  const snapshot = objectValue(posting.source_snapshot);
  const payoutSnapshot = objectValue(snapshot.payout);
  const totals = objectValue(snapshot.totals);
  const bank = objectValue(snapshot.bank);
  const members = Array.isArray(snapshot.members) ? snapshot.members : [];
  const previewLines = [];
  if (bank.mapping?.chart_account_id && Number(totals.net_cents) > 0) previewLines.push({
    position: 0, chart_account_id: bank.mapping.chart_account_id,
    debit_cents: Number(totals.net_cents), credit_cents: 0, memo: "Exact Stripe payout deposited"
  });
  if (snapshot.accounts?.merchant_bank_fees?.id && Number(totals.fee_cents) > 0) previewLines.push({
    position: previewLines.length, chart_account_id: snapshot.accounts.merchant_bank_fees.id,
    debit_cents: Number(totals.fee_cents), credit_cents: 0, memo: "Exact Stripe provider fees"
  });
  if (snapshot.accounts?.payment_clearing?.id && Number(totals.gross_cents) > 0) previewLines.push({
    position: previewLines.length, chart_account_id: snapshot.accounts.payment_clearing.id,
    debit_cents: 0, credit_cents: Number(totals.gross_cents), memo: "Exact settled payment clearing"
  });
  return {
    basis: "exact_stripe_automatic_payout_settlement",
    currency: "usd",
    provider_available: false,
    payout: { ...payoutSnapshot, eligible: false, blockers: [blocker("stripe_provider_unavailable", "Live Stripe payout evidence is temporarily unavailable.")] },
    totals,
    members: members.map((member) => ({ ...member, eligible: false, blockers: [] })),
    bank_candidates: [],
    selected_bank_transaction: bank,
    posting: settlementPostingPayload(posting),
    eligible: false,
    blockers: [blocker("stripe_provider_unavailable", "Live Stripe evidence is required before posting or replacement. The retained journal can still be voided exactly.")],
    review_state: posting.status === "posted" ? "posted_unverified" : "voided",
    source_current: false,
    can_post: false,
    can_void: posting.status === "posted" && Boolean(posting.journal_entry_id),
    source_fingerprint: posting.source_fingerprint,
    source_snapshot: snapshot,
    journal_preview: previewLines.length >= 2 ? {
      entry_date: bank.transaction_date,
      total_debits_cents: Number(totals.gross_cents || 0),
      total_credits_cents: Number(totals.gross_cents || 0),
      lines: previewLines
    } : null,
    journal,
    audit,
    warnings: [
      "Live Stripe evidence is unavailable. Posting and replacement are disabled, but the retained immutable settlement may be voided exactly.",
      "No provider, payment, refund, application, Finance, Plaid, classification, or cash Profit & Loss row is changed by a void."
    ]
  };
}

export function buildStripeSettlementJournalInput({ evaluation, settlementID, version, clientRequestID, reason }) {
  if (!evaluation?.eligible || !evaluation.journal_preview) {
    throw new FinanceStripeSettlementError("stripe_settlement_blocked", "Resolve every exact settlement blocker before posting.", 409, { blockers: evaluation?.blockers || [] });
  }
  const input = {
    client_request_id: uuid(clientRequestID, "client_request_id"),
    entry_date: evaluation.journal_preview.entry_date,
    entry_kind: "stripe_settlement",
    description: `Exact Stripe payout settlement · ${evaluation.journal_preview.entry_date}`,
    reference: `STRIPE-${String(evaluation.source_snapshot.payout.stripe_payout_id).slice(-12).toUpperCase()}`,
    reason: cleanString(reason, 500),
    reversal_of_entry_id: null,
    source_type: "finance_stripe_settlement",
    source_id: uuid(settlementID, "settlement_id"),
    source_version: exactInteger(version, "source_version", 1),
    lines: evaluation.journal_preview.lines,
    total_debits_cents: evaluation.journal_preview.total_debits_cents,
    total_credits_cents: evaluation.journal_preview.total_credits_cents
  };
  return { ...input, request_fingerprint: journalFingerprint(input) };
}

export function buildStripeSettlementReversalInput({ original, originalLines, settlementID, version, clientRequestID, reason }) {
  if (!original || original.source_type !== "finance_stripe_settlement" || String(original.source_id) !== String(settlementID) || original.reversal_of_entry_id) {
    throw new FinanceStripeSettlementError("stripe_settlement_journal_invalid", "The current settlement journal relationship is invalid.", 409);
  }
  const reversed = reverseJournalLines(originalLines);
  const input = {
    client_request_id: uuid(clientRequestID, "client_request_id"),
    entry_date: dateOnly(original.entry_date, "entry_date"),
    entry_kind: "reversal",
    description: `Reversal — ${cleanString(original.description, 180) || "Stripe settlement"}`,
    reference: cleanString(original.reference, 120) || null,
    reason: cleanString(reason, 500),
    reversal_of_entry_id: String(original.id),
    source_type: "finance_stripe_settlement",
    source_id: uuid(settlementID, "settlement_id"),
    source_version: exactInteger(version, "source_version", 1),
    lines: reversed.lines,
    total_debits_cents: reversed.total_debits_cents,
    total_credits_cents: reversed.total_credits_cents
  };
  return { ...input, request_fingerprint: journalFingerprint(input) };
}

export function normalizeStripeSettlementPostRequest(body, payoutID) {
  const input = {
    client_request_id: uuid(body?.client_request_id, "client_request_id"),
    stripe_payout_id: stripeID(payoutID, "stripe_payout_id", "po"),
    bank_transaction_id: uuid(body?.bank_transaction_id, "bank_transaction_id"),
    expected_settlement_version: exactInteger(body?.expected_settlement_version, "expected_settlement_version", 0),
    expected_bank_accounting_version: exactInteger(body?.expected_bank_accounting_version, "expected_bank_accounting_version", 1),
    expected_mapping_version: exactInteger(body?.expected_mapping_version, "expected_mapping_version", 1),
    expected_source_fingerprint: cleanString(body?.expected_source_fingerprint, 64),
    reason: cleanString(body?.reason, 500)
  };
  if (!/^[0-9a-f]{64}$/.test(input.expected_source_fingerprint)) throw new FinanceStripeSettlementError("stripe_settlement_fingerprint_invalid", "Refresh the exact settlement preview before posting.");
  if (!input.reason) throw new FinanceStripeSettlementError("stripe_settlement_reason_required", "An audit reason is required.");
  return { ...input, action: "post", request_fingerprint: fingerprint({ ...input, action: "post" }) };
}

export function normalizeStripeSettlementVoidRequest(body, payoutID) {
  const input = {
    client_request_id: uuid(body?.client_request_id, "client_request_id"),
    stripe_payout_id: stripeID(payoutID, "stripe_payout_id", "po"),
    expected_settlement_version: exactInteger(body?.expected_settlement_version, "expected_settlement_version", 1),
    reason: cleanString(body?.reason, 500)
  };
  if (!input.reason) throw new FinanceStripeSettlementError("stripe_settlement_reason_required", "An audit reason is required.");
  return { ...input, action: "void", request_fingerprint: fingerprint({ ...input, action: "void" }) };
}

async function replayedRequest(client, companyID, request) {
  const { rows } = await client.query(
    `SELECT request_fingerprint FROM finance_stripe_settlement_audit
      WHERE company_id=$1 AND client_request_id=$2::uuid FOR SHARE`,
    [companyID, request.client_request_id]
  );
  if (!rows.length) return false;
  if (rows[0].request_fingerprint !== request.request_fingerprint) {
    throw new FinanceStripeSettlementError("stripe_settlement_request_id_conflict", "That settlement request ID was already used with different content.", 409);
  }
  return true;
}

async function insertLedgerAudit(client, companyID, userID, entry, relatedEntry, action, reason, input) {
  await client.query(
    `INSERT INTO finance_journal_audit (company_id, entry_id, related_entry_id, actor_user_id, action, reason, entry_snapshot)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [companyID, entry.id, relatedEntry || null, userID, action, reason, JSON.stringify(snapshotInput(input))]
  );
}

export async function installFinanceStripeSettlementSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS finance_stripe_refund_evidence (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      payment_record_id UUID NOT NULL,
      refund_revision_id UUID,
      stripe_connected_account_id TEXT NOT NULL,
      stripe_refund_id TEXT NOT NULL,
      stripe_charge_id TEXT NOT NULL,
      stripe_balance_transaction_id TEXT,
      amount_cents BIGINT NOT NULL CHECK (amount_cents > 0),
      currency TEXT NOT NULL,
      status TEXT NOT NULL,
      stripe_event_id TEXT NOT NULL REFERENCES stripe_webhook_events(stripe_event_id) ON DELETE RESTRICT,
      observed_at TIMESTAMPTZ NOT NULL,
      version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, id),
      UNIQUE(stripe_connected_account_id, stripe_refund_id),
      FOREIGN KEY (company_id, payment_record_id) REFERENCES payment_records(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, refund_revision_id) REFERENCES finance_payment_refund_revisions(company_id, id) ON DELETE RESTRICT
    );
    CREATE UNIQUE INDEX IF NOT EXISTS finance_stripe_refund_evidence_balance_idx
      ON finance_stripe_refund_evidence(company_id, stripe_balance_transaction_id)
      WHERE stripe_balance_transaction_id IS NOT NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS finance_stripe_refund_evidence_revision_idx
      ON finance_stripe_refund_evidence(company_id, refund_revision_id)
      WHERE refund_revision_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS finance_stripe_refund_evidence_company_payment_idx
      ON finance_stripe_refund_evidence(company_id, payment_record_id, observed_at DESC);

    CREATE TABLE IF NOT EXISTS finance_stripe_settlements (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      stripe_connected_account_id TEXT NOT NULL,
      stripe_payout_id TEXT NOT NULL,
      bank_transaction_id UUID NOT NULL,
      journal_entry_id UUID,
      status TEXT NOT NULL CHECK (status IN ('posted','voided')),
      version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
      source_fingerprint TEXT NOT NULL CHECK (char_length(source_fingerprint)=64),
      source_snapshot JSONB NOT NULL,
      reason TEXT NOT NULL,
      updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, id),
      UNIQUE(company_id, stripe_payout_id),
      FOREIGN KEY (company_id, bank_transaction_id) REFERENCES finance_transactions(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, journal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT,
      CHECK ((status='posted' AND journal_entry_id IS NOT NULL) OR (status='voided' AND journal_entry_id IS NULL))
    );
    CREATE UNIQUE INDEX IF NOT EXISTS finance_stripe_settlements_active_bank_idx
      ON finance_stripe_settlements(company_id, bank_transaction_id) WHERE status='posted';
    CREATE INDEX IF NOT EXISTS finance_stripe_settlements_company_status_idx
      ON finance_stripe_settlements(company_id, status, updated_at DESC);

    CREATE TABLE IF NOT EXISTS finance_stripe_settlement_members (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      settlement_id UUID NOT NULL,
      settlement_version INTEGER NOT NULL CHECK (settlement_version > 0),
      stripe_balance_transaction_id TEXT NOT NULL,
      member_type TEXT NOT NULL CHECK (member_type IN ('charge','refund')),
      stripe_source_id TEXT NOT NULL,
      operational_application_id UUID NOT NULL,
      application_version INTEGER NOT NULL CHECK (application_version > 0),
      amount_cents BIGINT NOT NULL,
      fee_cents BIGINT NOT NULL CHECK (fee_cents >= 0),
      net_cents BIGINT NOT NULL,
      currency TEXT NOT NULL,
      active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, id),
      UNIQUE(company_id, settlement_id, settlement_version, stripe_balance_transaction_id),
      FOREIGN KEY (company_id, settlement_id) REFERENCES finance_stripe_settlements(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, operational_application_id) REFERENCES finance_operational_applications(company_id, id) ON DELETE RESTRICT,
      CHECK (amount_cents - fee_cents = net_cents),
      CHECK ((member_type='charge' AND amount_cents > 0) OR (member_type='refund' AND amount_cents < 0))
    );
    CREATE UNIQUE INDEX IF NOT EXISTS finance_stripe_settlement_members_active_balance_idx
      ON finance_stripe_settlement_members(company_id, stripe_balance_transaction_id) WHERE active;
    CREATE UNIQUE INDEX IF NOT EXISTS finance_stripe_settlement_members_active_application_idx
      ON finance_stripe_settlement_members(company_id, operational_application_id) WHERE active;
    CREATE INDEX IF NOT EXISTS finance_stripe_settlement_members_company_settlement_idx
      ON finance_stripe_settlement_members(company_id, settlement_id, settlement_version);

    CREATE TABLE IF NOT EXISTS finance_stripe_settlement_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      settlement_id UUID NOT NULL,
      actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      reason TEXT NOT NULL,
      version INTEGER NOT NULL CHECK (version > 0),
      client_request_id UUID NOT NULL,
      request_fingerprint TEXT NOT NULL CHECK (char_length(request_fingerprint)=64),
      source_fingerprint TEXT NOT NULL CHECK (char_length(source_fingerprint)=64),
      source_snapshot JSONB NOT NULL,
      previous_journal_entry_id UUID,
      journal_entry_id UUID,
      reversal_entry_id UUID,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, client_request_id),
      FOREIGN KEY (company_id, settlement_id) REFERENCES finance_stripe_settlements(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, previous_journal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, journal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT,
      FOREIGN KEY (company_id, reversal_entry_id) REFERENCES finance_journal_entries(company_id, id) ON DELETE RESTRICT
    );
    CREATE INDEX IF NOT EXISTS finance_stripe_settlement_audit_company_settlement_idx
      ON finance_stripe_settlement_audit(company_id, settlement_id, created_at DESC);
  `);
}

export async function captureStripeRefundEvidence(pool, {
  connectedAccountID,
  refund,
  charge,
  stripeEventID,
  observedAt,
  observedCumulativeTransition = false
}) {
  const accountID = stripeID(connectedAccountID, "stripe_connected_account_id", "acct");
  const refundID = stripeID(refund?.id, "stripe_refund_id", "re");
  const chargeID = stripeID(stripeObjectID(refund?.charge) || charge?.id, "stripe_charge_id", "ch");
  const paymentIntentID = stripeObjectID(refund?.payment_intent) || stripeObjectID(charge?.payment_intent);
  const balanceTransactionID = stripeObjectID(refund?.balance_transaction);
  const amount = exactInteger(refund?.amount, "refund_amount_cents", 1);
  const cumulative = exactInteger(charge?.amount_refunded, "cumulative_refunded_cents", 0);
  const currency = cleanString(refund?.currency || charge?.currency, 10).toLowerCase();
  const status = cleanString(refund?.status, 40).toLowerCase();
  const eventID = stripeID(stripeEventID, "stripe_event_id", "evt");
  const instant = normalizedInstant(observedAt) || (refund?.created ? new Date(exactInteger(refund.created, "refund_created", 0) * 1000).toISOString() : null);
  if (!paymentIntentID || currency !== "usd" || !status || !instant) {
    throw new FinanceStripeSettlementError("stripe_refund_evidence_invalid", "Stripe refund evidence is incomplete for exact accounting identity.", 409);
  }
  if (balanceTransactionID) stripeID(balanceTransactionID, "stripe_balance_transaction_id", "txn");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const paymentResult = await client.query(
      `SELECT id, company_id, stripe_charge_id FROM payment_records
        WHERE stripe_payment_intent_id=$1 AND stripe_connected_account_id=$2 FOR UPDATE`,
      [paymentIntentID, accountID]
    );
    if (paymentResult.rows.length !== 1) {
      throw new FinanceStripeSettlementError("stripe_refund_payment_unresolved", "Stripe refund evidence does not resolve to exactly one WolfCRM payment.", 409);
    }
    const payment = paymentResult.rows[0];
    if (payment.stripe_charge_id && payment.stripe_charge_id !== chargeID) {
      throw new FinanceStripeSettlementError("stripe_refund_charge_conflict", "Stripe refund Charge identity conflicts with the retained payment.", 409);
    }
    await client.query(
      `INSERT INTO finance_stripe_refund_evidence (
         company_id, payment_record_id, stripe_connected_account_id, stripe_refund_id,
         stripe_charge_id, stripe_balance_transaction_id, amount_cents, currency,
         status, stripe_event_id, observed_at
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       ON CONFLICT(stripe_connected_account_id, stripe_refund_id) DO NOTHING`,
      [payment.company_id, payment.id, accountID, refundID, chargeID, balanceTransactionID || null,
        amount, currency, status, eventID, instant]
    );
    const evidenceResult = await client.query(
      `SELECT * FROM finance_stripe_refund_evidence
        WHERE stripe_connected_account_id=$1 AND stripe_refund_id=$2 FOR UPDATE`,
      [accountID, refundID]
    );
    const evidence = evidenceResult.rows[0];
    if (!evidence || String(evidence.company_id) !== String(payment.company_id)
        || String(evidence.payment_record_id) !== String(payment.id)
        || evidence.stripe_charge_id !== chargeID
        || storedInteger(evidence.amount_cents, "stored_refund_amount_cents") !== amount
        || evidence.currency !== currency
        || (evidence.stripe_balance_transaction_id && balanceTransactionID && evidence.stripe_balance_transaction_id !== balanceTransactionID)) {
      throw new FinanceStripeSettlementError("stripe_refund_identity_conflict", "Stripe refund identity changed after it was retained.", 409);
    }
    let revisionID = evidence.refund_revision_id || null;
    if (!revisionID && canBindStripeRefundTransition({
      observedCumulativeTransition,
      cumulativeRefundedCents: cumulative,
      refundAmountCents: amount
    })) {
      const revisionResult = await client.query(
        `SELECT revision.id
           FROM finance_payment_refund_revisions revision
           LEFT JOIN finance_stripe_refund_evidence used
             ON used.company_id=revision.company_id AND used.refund_revision_id=revision.id
          WHERE revision.company_id=$1 AND revision.payment_record_id=$2
            AND revision.cumulative_refunded_cents=$3 AND revision.delta_refunded_cents=$4
            AND used.id IS NULL
          ORDER BY revision.created_at, revision.id FOR UPDATE OF revision`,
        [payment.company_id, payment.id, cumulative, amount]
      );
      if (revisionResult.rows.length === 1) revisionID = revisionResult.rows[0].id;
    }
    await client.query(
      `UPDATE finance_stripe_refund_evidence
          SET stripe_balance_transaction_id=COALESCE(stripe_balance_transaction_id,$3),
              status=CASE WHEN status='succeeded' THEN status WHEN $6 >= observed_at THEN $4 ELSE status END,
              stripe_event_id=CASE WHEN $6 >= observed_at THEN $5 ELSE stripe_event_id END,
              observed_at=GREATEST(observed_at,$6),
              refund_revision_id=COALESCE(refund_revision_id,$7),
              version=CASE WHEN (status IS DISTINCT FROM $4 AND status<>'succeeded')
                                OR (stripe_balance_transaction_id IS NULL AND $3::text IS NOT NULL)
                                OR (refund_revision_id IS NULL AND $7::uuid IS NOT NULL)
                           THEN version+1 ELSE version END,
              updated_at=CASE WHEN (status IS DISTINCT FROM $4 AND status<>'succeeded')
                                   OR (stripe_balance_transaction_id IS NULL AND $3::text IS NOT NULL)
                                   OR (refund_revision_id IS NULL AND $7::uuid IS NOT NULL)
                              THEN now() ELSE updated_at END
        WHERE stripe_connected_account_id=$1 AND stripe_refund_id=$2`,
      [accountID, refundID, balanceTransactionID || null, status, eventID, instant, revisionID]
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

function sendSettlementError(res, error, fallback) {
  if (error instanceof FinanceStripeSettlementError || error instanceof GeneralLedgerError || error?.statusCode) {
    return res.status(error.statusCode || 400).json({
      error: error.code || fallback,
      message: error.message,
      blockers: error.blockers,
      current_settlement_version: error.current_settlement_version,
      current_bank_accounting_version: error.current_bank_accounting_version,
      current_mapping_version: error.current_mapping_version
    });
  }
  if (error?.code === "23505") return res.status(409).json({ error: "stripe_settlement_conflict", message: "That provider, application, or bank identity already belongs to an active settlement." });
  console.error("[finance-stripe-settlements]", fallback, { code: error?.code, message: error?.message });
  return res.status(500).json({ error: fallback, message: "Stripe settlement request failed." });
}

export function installFinanceStripeSettlementRoutes({ app, pool, authRequired, requireFinanceAccess, ensureChartAccounts, getStripe }) {
  app.get("/api/finance/accounting/stripe-settlements", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Stripe settlement requires a company workspace." });
    try {
      const range = parseStripeSettlementRange(req.query.start_date, req.query.end_date);
      const limit = boundedLimit(req.query.limit);
      await ensureChartAccounts(pool, req.companyId, req.userId);
      const context = await loadStripeContext(pool, req.companyId);
      const postings = await pool.query(
        `SELECT * FROM finance_stripe_settlements
          WHERE company_id=$1
            AND COALESCE(source_snapshot->'payout'->>'arrival_date','') BETWEEN $2 AND $3
          ORDER BY updated_at DESC LIMIT $4`,
        [req.companyId, range.start_date, range.end_date, MAX_PAYOUT_ROWS + 1]
      );
      const retainedPostings = postings.rows.slice(0, MAX_PAYOUT_ROWS);
      const postingByPayout = new Map(retainedPostings.map((row) => [row.stripe_payout_id, row]));
      let providerAvailable = true;
      let providerTruncated = false;
      let providerRows = [];
      try {
        const stripe = requireStripeClient(getStripe);
        const startUnix = Math.floor(Date.parse(`${range.start_date}T00:00:00.000Z`) / 1000);
        const endUnix = Math.floor(Date.parse(`${addDays(range.end_date, 1)}T00:00:00.000Z`) / 1000) - 1;
        const result = await stripe.payouts.list({ arrival_date: { gte: startUnix, lte: endUnix }, limit }, { stripeAccount: context.stripe_account_id });
        if (!Array.isArray(result?.data)) throw new Error("invalid_stripe_payout_list");
        providerRows = result.data.map(normalizeStripePayout);
        providerTruncated = result.has_more === true;
      } catch {
        providerAvailable = false;
      }
      const byID = new Map(providerRows.map((payout) => [payout.stripe_payout_id, payout]));
      for (const posting of retainedPostings) {
        if (byID.has(posting.stripe_payout_id)) continue;
        const snapshot = objectValue(posting.source_snapshot);
        const payout = objectValue(snapshot.payout);
        if (payout.stripe_payout_id) byID.set(payout.stripe_payout_id, { ...payout, eligible: false, blockers: [] });
      }
      const payouts = [...byID.values()].map((payout) => {
        const posting = postingByPayout.get(payout.stripe_payout_id) || null;
        let state = payout.eligible ? "ready" : "blocked";
        if (posting?.status === "voided") state = "voided";
        else if (posting?.status === "posted") state = providerAvailable ? "posted_needs_detail_review" : "posted_unverified";
        return { ...payout, id: payout.stripe_payout_id, posting: settlementPostingPayload(posting), review_state: state };
      }).sort((left, right) => String(right.arrival_date || "").localeCompare(String(left.arrival_date || "")));
      res.json({
        basis: "exact_stripe_automatic_payout_settlement",
        currency: "usd", start_date: range.start_date, end_date: range.end_date,
        provider_available: providerAvailable, truncated: providerTruncated || postings.rows.length > MAX_PAYOUT_ROWS,
        warnings: providerAvailable ? [
          "Open every payout for a live exact-membership review. List status alone is never posting authority.",
          "No bank transaction is selected automatically; amount/date/description proximity is not settlement identity."
        ] : [
          "Stripe is temporarily unavailable. Retained posted settlements remain inspectable and exactly voidable; new posts and replacements are disabled."
        ],
        payouts
      });
    } catch (error) {
      sendSettlementError(res, error, "stripe_settlement_report_failed");
    }
  });

  app.get("/api/finance/accounting/stripe-settlements/payouts/:payoutId", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Stripe settlement requires a company workspace." });
    try {
      await ensureChartAccounts(pool, req.companyId, req.userId);
      const payoutID = stripeID(req.params.payoutId, "stripe_payout_id", "po");
      const context = await loadStripeContext(pool, req.companyId);
      let payout;
      let members;
      try {
        const stripe = requireStripeClient(getStripe);
        payout = normalizeStripePayout(await fetchPayout(stripe, context.stripe_account_id, payoutID));
        members = await fetchPayoutMembers(stripe, context.stripe_account_id, payoutID);
      } catch (providerError) {
        const posting = await loadPosting(pool, req.companyId, payoutID, false);
        if (!posting) throw providerError;
        const journal = posting.journal_entry_id ? await loadJournalEntry(pool, req.companyId, posting.journal_entry_id) : null;
        return res.json(storedDetailPayload(posting, journal, await loadAudit(pool, req.companyId, posting.id)));
      }
      return res.json(await detailPayload(pool, req.companyId, context.stripe_account_id, payout, members, req.query.bank_transaction_id || null));
    } catch (error) {
      sendSettlementError(res, error, "stripe_settlement_detail_failed");
    }
  });

  app.post("/api/finance/accounting/stripe-settlements/payouts/:payoutId/post", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Stripe settlement requires a company workspace." });
    let request;
    try { request = normalizeStripeSettlementPostRequest(req.body, req.params.payoutId); } catch (error) { return sendSettlementError(res, error, "stripe_settlement_post_failed"); }
    let provider;
    try {
      const context = await loadStripeContext(pool, req.companyId);
      const stripe = requireStripeClient(getStripe);
      const payout = normalizeStripePayout(await fetchPayout(stripe, context.stripe_account_id, request.stripe_payout_id));
      const rawMembers = await fetchPayoutMembers(stripe, context.stripe_account_id, request.stripe_payout_id);
      provider = { context, payout, normalizedMembers: normalizeStripeBalanceMembers(rawMembers, payout.currency) };
    } catch (error) {
      return sendSettlementError(res, error, "stripe_settlement_post_failed");
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(`SELECT id FROM companies WHERE id=$1 FOR UPDATE`, [req.companyId]);
      if (await replayedRequest(client, req.companyId, request)) {
        await client.query("COMMIT");
        return res.json({ replayed: true });
      }
      await ensureChartAccounts(client, req.companyId, req.userId);
      const bundle = await loadSettlementEvaluation(client, req.companyId, provider.context.stripe_account_id, provider.payout, provider.normalizedMembers, request.bank_transaction_id, true);
      if (await replayedRequest(client, req.companyId, request)) {
        await client.query("COMMIT");
        return res.json({ replayed: true });
      }
      const currentSettlementVersion = settlementVersion(bundle.posting);
      const currentBankVersion = Number(bundle.bankEvidence?.transaction?.accounting_version || 0);
      const currentMappingVersion = Number(bundle.bankEvidence?.mapping?.version || 0);
      if (request.expected_settlement_version !== currentSettlementVersion) throw new FinanceStripeSettlementError("stripe_settlement_stale", "Settlement authority changed after it was loaded.", 409, { current_settlement_version: currentSettlementVersion });
      if (request.expected_bank_accounting_version !== currentBankVersion) throw new FinanceStripeSettlementError("stripe_settlement_bank_stale", "Selected bank accounting changed after it was loaded.", 409, { current_bank_accounting_version: currentBankVersion });
      if (request.expected_mapping_version !== currentMappingVersion) throw new FinanceStripeSettlementError("stripe_settlement_mapping_stale", "Selected bank mapping changed after it was loaded.", 409, { current_mapping_version: currentMappingVersion });
      if (request.expected_source_fingerprint !== bundle.evaluation.source_fingerprint) throw new FinanceStripeSettlementError("stripe_settlement_source_stale", "Provider, application, or bank evidence changed after preview. Refresh before posting.", 409);
      if (!bundle.evaluation.eligible) throw new FinanceStripeSettlementError("stripe_settlement_blocked", "Resolve every exact settlement blocker before posting.", 409, { blockers: bundle.evaluation.blockers });
      const settlementID = bundle.posting?.id || randomUUID();
      if (bundle.evaluation.source_current) {
        await client.query(
          `INSERT INTO finance_stripe_settlement_audit (
             company_id, settlement_id, actor_user_id, action, reason, version,
             client_request_id, request_fingerprint, source_fingerprint, source_snapshot,
             previous_journal_entry_id, journal_entry_id, reversal_entry_id
           ) VALUES ($1,$2,$3,'source_reviewed',$4,$5,$6::uuid,$7,$8,$9,$10,$10,NULL)`,
          [req.companyId, settlementID, req.userId, request.reason, currentSettlementVersion,
            request.client_request_id, request.request_fingerprint, bundle.evaluation.source_fingerprint,
            JSON.stringify(bundle.evaluation.source_snapshot), bundle.posting.journal_entry_id]
        );
        await client.query("COMMIT");
        return res.json({ replayed: false });
      }
      const nextVersion = currentSettlementVersion + 1;
      const previousJournalID = bundle.posting?.status === "posted" ? bundle.posting.journal_entry_id : null;
      let reversal = null;
      if (previousJournalID) {
        const originalResult = await client.query(`SELECT * FROM finance_journal_entries WHERE company_id=$1 AND id=$2 FOR UPDATE`, [req.companyId, previousJournalID]);
        const original = originalResult.rows[0];
        const lines = await client.query(
          `SELECT chart_account_id, debit_cents, credit_cents, memo FROM finance_journal_lines
            WHERE company_id=$1 AND entry_id=$2 ORDER BY line_order FOR SHARE`,
          [req.companyId, previousJournalID]
        );
        const existingReversal = await client.query(`SELECT id FROM finance_journal_entries WHERE company_id=$1 AND reversal_of_entry_id=$2 FOR UPDATE`, [req.companyId, previousJournalID]);
        if (existingReversal.rows.length) throw new FinanceStripeSettlementError("stripe_settlement_already_reversed", "The current settlement journal already has a reversal.", 409);
        const reversalInput = buildStripeSettlementReversalInput({
          original, originalLines: lines.rows, settlementID, version: nextVersion,
          clientRequestID: randomUUID(), reason: request.reason
        });
        reversal = await insertJournal(client, req.companyId, req.userId, reversalInput);
        await insertLedgerAudit(client, req.companyId, req.userId, reversal, original.id, "stripe_settlement_reversal_posted", request.reason, reversalInput);
        await insertLedgerAudit(client, req.companyId, req.userId, original, reversal.id, "stripe_settlement_reversed", request.reason, reversalInput);
      }
      const journalInput = buildStripeSettlementJournalInput({
        evaluation: bundle.evaluation, settlementID, version: nextVersion,
        clientRequestID: request.client_request_id, reason: request.reason
      });
      const journal = await insertJournal(client, req.companyId, req.userId, journalInput);
      await insertLedgerAudit(client, req.companyId, req.userId, journal, reversal?.id || null, "stripe_settlement_posted", request.reason, journalInput);
      let posting;
      if (!bundle.posting) {
        posting = (await client.query(
          `INSERT INTO finance_stripe_settlements (
             id, company_id, stripe_connected_account_id, stripe_payout_id, bank_transaction_id,
             journal_entry_id, status, version, source_fingerprint, source_snapshot, reason, updated_by
           ) VALUES ($1,$2,$3,$4,$5,$6,'posted',1,$7,$8,$9,$10) RETURNING *`,
          [settlementID, req.companyId, provider.context.stripe_account_id, request.stripe_payout_id,
            request.bank_transaction_id, journal.id, bundle.evaluation.source_fingerprint,
            JSON.stringify(bundle.evaluation.source_snapshot), request.reason, req.userId]
        )).rows[0];
      } else {
        await client.query(
          `UPDATE finance_stripe_settlement_members SET active=false, updated_at=now()
            WHERE company_id=$1 AND settlement_id=$2 AND active`,
          [req.companyId, settlementID]
        );
        posting = (await client.query(
          `UPDATE finance_stripe_settlements
              SET stripe_connected_account_id=$3, bank_transaction_id=$4, journal_entry_id=$5,
                  status='posted', version=version+1, source_fingerprint=$6, source_snapshot=$7,
                  reason=$8, updated_by=$9, updated_at=now()
            WHERE company_id=$1 AND id=$2 RETURNING *`,
          [req.companyId, settlementID, provider.context.stripe_account_id, request.bank_transaction_id,
            journal.id, bundle.evaluation.source_fingerprint, JSON.stringify(bundle.evaluation.source_snapshot),
            request.reason, req.userId]
        )).rows[0];
      }
      for (const member of bundle.members) {
        await client.query(
          `INSERT INTO finance_stripe_settlement_members (
             company_id, settlement_id, settlement_version, stripe_balance_transaction_id,
             member_type, stripe_source_id, operational_application_id, application_version,
             amount_cents, fee_cents, net_cents, currency, active
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,true)`,
          [req.companyId, settlementID, posting.version, member.stripe_balance_transaction_id,
            member.type, member.stripe_source_id, member.application_id, member.application_version,
            member.amount_cents, member.fee_cents, member.net_cents, member.currency]
        );
      }
      await client.query(
        `INSERT INTO finance_stripe_settlement_audit (
           company_id, settlement_id, actor_user_id, action, reason, version,
           client_request_id, request_fingerprint, source_fingerprint, source_snapshot,
           previous_journal_entry_id, journal_entry_id, reversal_entry_id
         ) VALUES ($1,$2,$3,$4,$5,$6,$7::uuid,$8,$9,$10,$11,$12,$13)`,
        [req.companyId, settlementID, req.userId, previousJournalID ? "settlement_replaced" : "settlement_posted",
          request.reason, posting.version, request.client_request_id, request.request_fingerprint,
          bundle.evaluation.source_fingerprint, JSON.stringify(bundle.evaluation.source_snapshot),
          previousJournalID, journal.id, reversal?.id || null]
      );
      await client.query("COMMIT");
      res.status(201).json({ replayed: false });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendSettlementError(res, error, "stripe_settlement_post_failed");
    } finally {
      client.release();
    }
  });

  app.post("/api/finance/accounting/stripe-settlements/payouts/:payoutId/void", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Stripe settlement requires a company workspace." });
    let request;
    try { request = normalizeStripeSettlementVoidRequest(req.body, req.params.payoutId); } catch (error) { return sendSettlementError(res, error, "stripe_settlement_void_failed"); }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(`SELECT id FROM companies WHERE id=$1 FOR UPDATE`, [req.companyId]);
      if (await replayedRequest(client, req.companyId, request)) {
        await client.query("COMMIT");
        return res.json({ replayed: true });
      }
      const posting = await loadPosting(client, req.companyId, request.stripe_payout_id, true);
      if (!posting || posting.status !== "posted" || !posting.journal_entry_id) throw new FinanceStripeSettlementError("stripe_settlement_not_posted", "Only a currently posted Stripe settlement can be voided.", 409);
      if (request.expected_settlement_version !== Number(posting.version)) throw new FinanceStripeSettlementError("stripe_settlement_stale", "Settlement authority changed after it was loaded.", 409, { current_settlement_version: Number(posting.version) });
      const originalResult = await client.query(`SELECT * FROM finance_journal_entries WHERE company_id=$1 AND id=$2 FOR UPDATE`, [req.companyId, posting.journal_entry_id]);
      const original = originalResult.rows[0];
      const lines = await client.query(
        `SELECT chart_account_id, debit_cents, credit_cents, memo FROM finance_journal_lines
          WHERE company_id=$1 AND entry_id=$2 ORDER BY line_order FOR SHARE`,
        [req.companyId, posting.journal_entry_id]
      );
      const existingReversal = await client.query(`SELECT id FROM finance_journal_entries WHERE company_id=$1 AND reversal_of_entry_id=$2 FOR UPDATE`, [req.companyId, posting.journal_entry_id]);
      if (existingReversal.rows.length) throw new FinanceStripeSettlementError("stripe_settlement_already_reversed", "The current settlement journal already has a reversal.", 409);
      const nextVersion = Number(posting.version) + 1;
      const reversalInput = buildStripeSettlementReversalInput({
        original, originalLines: lines.rows, settlementID: posting.id,
        version: nextVersion, clientRequestID: request.client_request_id, reason: request.reason
      });
      const reversal = await insertJournal(client, req.companyId, req.userId, reversalInput);
      await insertLedgerAudit(client, req.companyId, req.userId, reversal, original.id, "stripe_settlement_void_reversal_posted", request.reason, reversalInput);
      await insertLedgerAudit(client, req.companyId, req.userId, original, reversal.id, "stripe_settlement_voided", request.reason, reversalInput);
      await client.query(
        `UPDATE finance_stripe_settlement_members SET active=false, updated_at=now()
          WHERE company_id=$1 AND settlement_id=$2 AND active`,
        [req.companyId, posting.id]
      );
      const updated = (await client.query(
        `UPDATE finance_stripe_settlements
            SET journal_entry_id=NULL, status='voided', version=version+1,
                reason=$3, updated_by=$4, updated_at=now()
          WHERE company_id=$1 AND id=$2 RETURNING *`,
        [req.companyId, posting.id, request.reason, req.userId]
      )).rows[0];
      await client.query(
        `INSERT INTO finance_stripe_settlement_audit (
           company_id, settlement_id, actor_user_id, action, reason, version,
           client_request_id, request_fingerprint, source_fingerprint, source_snapshot,
           previous_journal_entry_id, journal_entry_id, reversal_entry_id
         ) VALUES ($1,$2,$3,'settlement_voided',$4,$5,$6::uuid,$7,$8,$9,$10,NULL,$11)`,
        [req.companyId, posting.id, req.userId, request.reason, updated.version,
          request.client_request_id, request.request_fingerprint, posting.source_fingerprint,
          JSON.stringify(posting.source_snapshot), posting.journal_entry_id, reversal.id]
      );
      await client.query("COMMIT");
      res.status(201).json({ replayed: false });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendSettlementError(res, error, "stripe_settlement_void_failed");
    } finally {
      client.release();
    }
  });
}
