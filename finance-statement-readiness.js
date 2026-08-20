import { createHash } from "node:crypto";
import { loadBankSourceCloseEvaluation } from "./finance-bank-sources.js";
import { loadBankTransferCloseEvaluation } from "./finance-bank-transfers.js";
import { syncOperationalAccountingSources } from "./finance-operational-accounting.js";
import { loadOperationalApplicationCloseEvaluation } from "./finance-operational-applications.js";
import { loadOperationalReceivableCloseEvaluation } from "./finance-operational-journals.js";
import { loadPayrollJournalCloseEvaluation } from "./finance-payroll-journals.js";
import { loadStripeSettlementLocalCloseEvaluation } from "./finance-stripe-settlements.js";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const OPENING_METHODS = new Set(["company_inception_zero", "reviewed_journal"]);
const BALANCE_SHEET_EARNINGS_TREATMENT = "cumulative_since_coverage_start";
const STATEMENT_ACCOUNT_TYPES = new Set(["asset", "liability", "equity", "income", "expense"]);
const MAX_OPENING_CANDIDATES = 100;
const MAX_AUDIT_ROWS = 50;
const MAX_CLOSE_AUTHORITIES = 1000;
const MAX_STATEMENT_ACCOUNTS = 250;

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

export function normalizeStatementPeriodCloseRequest({ body = {}, companyToday }) {
  const today = dateOnly(companyToday, "company_today");
  const asOfDate = dateOnly(body.as_of_date, "as_of_date");
  if (asOfDate > today) {
    throw new FinanceStatementReadinessError("statement_as_of_future", "Statement readiness cannot be closed after the company's current local day.");
  }
  const sourceInventoryFingerprint = cleanString(body.source_inventory_fingerprint, 64).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(sourceInventoryFingerprint)) {
    throw new FinanceStatementReadinessError("source_inventory_fingerprint_invalid", "Source inventory fingerprint is invalid.");
  }
  const reason = (body.reason ?? "").toString().trim();
  if (!reason) throw new FinanceStatementReadinessError("statement_period_close_reason_required", "An audit reason is required.");
  if (reason.length > 500) throw new FinanceStatementReadinessError("statement_period_close_reason_too_long", "Audit reason must be 500 characters or fewer.");
  const input = {
    client_request_id: uuid(body.client_request_id, "client_request_id"),
    expected_profile_version: exactInteger(body.expected_profile_version ?? 0, "expected_profile_version"),
    expected_close_version: exactInteger(body.expected_close_version ?? 0, "expected_close_version"),
    as_of_date: asOfDate,
    source_inventory_fingerprint: sourceInventoryFingerprint,
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

function storedSignedInteger(value, field) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(parsed)) {
    throw new FinanceStatementReadinessError("balance_sheet_amount_inexact", `${field.replaceAll("_", " ")} exceeds the exact supported range.`, 409);
  }
  return parsed;
}

function addStatementExact(left, right, field) {
  const next = left + right;
  if (!Number.isSafeInteger(next)) {
    throw new FinanceStatementReadinessError("balance_sheet_amount_inexact", `${field.replaceAll("_", " ")} exceeds the exact supported range.`, 409);
  }
  return next;
}

export function normalizeBalanceSheetRuleReviewRequest({ body = {}, companyToday }) {
  const today = dateOnly(companyToday, "company_today");
  const asOfDate = dateOnly(body.as_of_date, "as_of_date");
  if (asOfDate > today) {
    throw new FinanceStatementReadinessError("statement_as_of_future", "Balance Sheet rules cannot be reviewed for a future statement boundary.");
  }
  const accountantReviewedOn = dateOnly(body.accountant_reviewed_on, "accountant_reviewed_on");
  if (accountantReviewedOn > today) {
    throw new FinanceStatementReadinessError("balance_sheet_accountant_review_future", "The accountant review date cannot be in the future.");
  }
  const accountantReference = (body.accountant_reference ?? "").toString().trim();
  if (!accountantReference) {
    throw new FinanceStatementReadinessError("balance_sheet_accountant_reference_required", "Enter a non-secret accountant review reference.");
  }
  if (accountantReference.length > 200) {
    throw new FinanceStatementReadinessError("balance_sheet_accountant_reference_too_long", "Accountant review reference must be 200 characters or fewer.");
  }
  if (body.accountant_review_confirmed !== true) {
    throw new FinanceStatementReadinessError("balance_sheet_accountant_confirmation_required", "Confirm that a qualified accountant reviewed the fixed Balance Sheet rules.");
  }
  const treatment = cleanString(body.earnings_treatment || BALANCE_SHEET_EARNINGS_TREATMENT, 80).toLowerCase();
  if (treatment !== BALANCE_SHEET_EARNINGS_TREATMENT) {
    throw new FinanceStatementReadinessError("balance_sheet_earnings_treatment_unsupported", "Choose the supported accumulated-earnings treatment.");
  }
  const reason = (body.reason ?? "").toString().trim();
  if (!reason) throw new FinanceStatementReadinessError("balance_sheet_rule_reason_required", "An audit reason is required.");
  if (reason.length > 500) throw new FinanceStatementReadinessError("balance_sheet_rule_reason_too_long", "Audit reason must be 500 characters or fewer.");
  const input = {
    client_request_id: uuid(body.client_request_id, "client_request_id"),
    expected_version: exactInteger(body.expected_version ?? 0, "expected_version"),
    as_of_date: asOfDate,
    earnings_treatment: treatment,
    accountant_reviewed_on: accountantReviewedOn,
    accountant_reference: accountantReference,
    accountant_review_confirmed: true,
    reason
  };
  return { ...input, request_fingerprint: statementReadinessFingerprint(input) };
}

export function balanceSheetChartSnapshot(accounts = []) {
  if (!Array.isArray(accounts)) {
    throw new FinanceStatementReadinessError("balance_sheet_chart_invalid", "The Balance Sheet chart evidence is invalid.", 409);
  }
  if (accounts.length > MAX_STATEMENT_ACCOUNTS) {
    throw new FinanceStatementReadinessError(
      "balance_sheet_chart_too_large",
      `The complete chart exceeds the exact ${MAX_STATEMENT_ACCOUNTS}-account Balance Sheet review bound.`,
      409
    );
  }
  const seen = new Set();
  return accounts.map((account) => {
    const id = cleanString(account?.id, 80);
    const code = cleanString(account?.code, 40);
    const name = cleanString(account?.name, 120);
    const accountType = cleanString(account?.account_type, 30).toLowerCase();
    if (!id || seen.has(id)) {
      throw new FinanceStatementReadinessError("balance_sheet_chart_duplicate", "The Balance Sheet chart contains a missing or duplicate account identity.", 409);
    }
    seen.add(id);
    if (!code || !name || !STATEMENT_ACCOUNT_TYPES.has(accountType)) {
      throw new FinanceStatementReadinessError("balance_sheet_chart_invalid", "The Balance Sheet chart contains an unsupported account definition.", 409);
    }
    return {
      id,
      code,
      name,
      account_type: accountType,
      active: account.active !== false,
      system_key: cleanString(account.system_key, 80) || null
    };
  }).sort((left, right) => left.id.localeCompare(right.id));
}

export function evaluateBalanceSheetRules({ profile = null, chartAccounts = [] }) {
  const chart = balanceSheetChartSnapshot(chartAccounts);
  const chartFingerprint = statementReadinessFingerprint(chart);
  if (!profile) {
    return {
      status: "unconfigured",
      source_current: false,
      live_fingerprint: null,
      chart_fingerprint: chartFingerprint,
      snapshot: null,
      blockers: [blocker(
        "balance_sheet_rules_not_reviewed",
        "Record a genuine qualified-accountant review of WolfCRM's fixed Balance Sheet presentation rules for the complete current chart.",
        "balance_sheet_rules"
      )]
    };
  }
  const snapshot = {
    earnings_treatment: cleanString(profile.earnings_treatment, 80),
    accountant_reviewed_on: dateValue(profile.accountant_reviewed_on),
    accountant_reference: cleanString(profile.accountant_reference, 200),
    accountant_review_confirmed: profile.accountant_review_confirmed === true,
    chart_fingerprint: chartFingerprint,
    chart
  };
  const liveFingerprint = statementReadinessFingerprint(snapshot);
  const blockers = [];
  if (snapshot.earnings_treatment !== BALANCE_SHEET_EARNINGS_TREATMENT || !snapshot.accountant_review_confirmed
      || !snapshot.accountant_reviewed_on || !snapshot.accountant_reference) {
    blockers.push(blocker(
      "balance_sheet_rules_invalid",
      "The stored Balance Sheet presentation-rule review is incomplete or unsupported.",
      "balance_sheet_rules"
    ));
  }
  if (profile.evidence_fingerprint !== liveFingerprint || profile.chart_fingerprint !== chartFingerprint) {
    blockers.push(blocker(
      "balance_sheet_rules_stale",
      "The company chart or fixed Balance Sheet presentation evidence changed after accountant review.",
      "balance_sheet_rules"
    ));
  }
  return {
    status: blockers.length === 0 ? "current" : "stale",
    source_current: blockers.length === 0,
    live_fingerprint: liveFingerprint,
    chart_fingerprint: chartFingerprint,
    snapshot,
    blockers: uniqueBlockers(blockers)
  };
}

export function summarizeBalanceSheetRows(rows = [], { coverageStartDate, asOfDate } = {}) {
  const startDate = dateOnly(coverageStartDate, "coverage_start_date");
  const endDate = dateOnly(asOfDate, "as_of_date");
  if (endDate < startDate) {
    throw new FinanceStatementReadinessError("balance_sheet_range_invalid", "Balance Sheet as-of date cannot precede reviewed coverage.");
  }
  if (!Array.isArray(rows) || rows.length > MAX_STATEMENT_ACCOUNTS) {
    throw new FinanceStatementReadinessError("balance_sheet_chart_too_large", `The Balance Sheet exceeds the exact ${MAX_STATEMENT_ACCOUNTS}-account bound.`, 409);
  }
  const seen = new Set();
  const assets = [];
  const liabilities = [];
  const postedEquity = [];
  let totalAssets = 0;
  let totalLiabilities = 0;
  let totalPostedEquity = 0;
  let totalIncome = 0;
  let totalExpenses = 0;
  for (const row of rows) {
    const id = cleanString(row.chart_account_id ?? row.id, 80);
    const type = cleanString(row.account_type, 30).toLowerCase();
    if (!id || seen.has(id)) {
      throw new FinanceStatementReadinessError("balance_sheet_account_duplicate", "The Balance Sheet contains a missing or duplicate account identity.", 409);
    }
    seen.add(id);
    if (!STATEMENT_ACCOUNT_TYPES.has(type)) {
      throw new FinanceStatementReadinessError("balance_sheet_account_type_invalid", "The Balance Sheet contains an unsupported account type.", 409);
    }
    const debit = storedSignedInteger(row.debit_cents ?? 0, "debit_cents");
    const credit = storedSignedInteger(row.credit_cents ?? 0, "credit_cents");
    if (debit < 0 || credit < 0) {
      throw new FinanceStatementReadinessError("balance_sheet_amount_invalid", "Stored Balance Sheet debits and credits must be nonnegative.", 409);
    }
    const debitNormal = debit - credit;
    const creditNormal = credit - debit;
    if (!Number.isSafeInteger(debitNormal) || !Number.isSafeInteger(creditNormal)) {
      throw new FinanceStatementReadinessError("balance_sheet_amount_inexact", "An account balance exceeds the exact supported range.", 409);
    }
    const account = {
      chart_account_id: id,
      code: cleanString(row.code, 40),
      name: cleanString(row.name, 120) || "Account",
      account_type: type,
      active: row.active !== false,
      balance_cents: type === "asset" || type === "expense" ? debitNormal : creditNormal
    };
    if (type === "asset") {
      if (account.balance_cents !== 0) assets.push(account);
      totalAssets = addStatementExact(totalAssets, account.balance_cents, "total_assets_cents");
    } else if (type === "liability") {
      if (account.balance_cents !== 0) liabilities.push(account);
      totalLiabilities = addStatementExact(totalLiabilities, account.balance_cents, "total_liabilities_cents");
    } else if (type === "equity") {
      if (account.balance_cents !== 0) postedEquity.push(account);
      totalPostedEquity = addStatementExact(totalPostedEquity, account.balance_cents, "posted_equity_cents");
    } else if (type === "income") {
      totalIncome = addStatementExact(totalIncome, account.balance_cents, "total_income_cents");
    } else {
      totalExpenses = addStatementExact(totalExpenses, account.balance_cents, "total_expenses_cents");
    }
  }
  const accumulatedEarnings = addStatementExact(totalIncome, -totalExpenses, "accumulated_earnings_cents");
  const totalEquity = addStatementExact(totalPostedEquity, accumulatedEarnings, "total_equity_cents");
  const totalLiabilitiesAndEquity = addStatementExact(totalLiabilities, totalEquity, "total_liabilities_and_equity_cents");
  const equationDifference = addStatementExact(totalAssets, -totalLiabilitiesAndEquity, "equation_difference_cents");
  if (equationDifference !== 0) {
    throw new FinanceStatementReadinessError(
      "balance_sheet_unbalanced",
      "The reviewed ledger does not satisfy Assets = Liabilities + Equity at this boundary. The Balance Sheet was not produced.",
      409,
      { difference_cents: equationDifference }
    );
  }
  const byCode = (left, right) => `${left.code}|${left.name}|${left.chart_account_id}`.localeCompare(`${right.code}|${right.name}|${right.chart_account_id}`);
  assets.sort(byCode);
  liabilities.sort(byCode);
  postedEquity.sort(byCode);
  return {
    assets,
    liabilities,
    posted_equity: postedEquity,
    total_assets_cents: totalAssets,
    total_liabilities_cents: totalLiabilities,
    posted_equity_cents: totalPostedEquity,
    income_cents: totalIncome,
    expense_cents: totalExpenses,
    accumulated_earnings_cents: accumulatedEarnings,
    total_equity_cents: totalEquity,
    total_liabilities_and_equity_cents: totalLiabilitiesAndEquity,
    equation_difference_cents: equationDifference
  };
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

export function normalizeStatementWorkflowEvidence(records = [], { truncated = false } = {}) {
  const normalized = records.map((record) => ({
    workflow: cleanString(record.workflow, 80),
    authority_id: cleanString(record.authority_id, 80),
    authority_version: exactInteger(record.authority_version ?? 0, "authority_version"),
    stored_fingerprint: cleanString(record.stored_fingerprint, 64) || null,
    live_fingerprint: cleanString(record.live_fingerprint, 64) || null,
    source_current: record.source_current === true,
    blocker_codes: [...new Set((record.blocker_codes || []).map((code) => cleanString(code, 100)).filter(Boolean))].sort()
  })).sort((left, right) => `${left.workflow}|${left.authority_id}`.localeCompare(`${right.workflow}|${right.authority_id}`));
  const seen = new Set();
  let duplicate = false;
  for (const record of normalized) {
    const key = `${record.workflow}|${record.authority_id}`;
    if (!record.workflow || !record.authority_id || seen.has(key)) duplicate = true;
    seen.add(key);
  }
  const blockers = [];
  if (truncated) blockers.push(blocker(
    "statement_close_evidence_too_large",
    `The local workflow set exceeds the exact ${MAX_CLOSE_AUTHORITIES}-authority close bound. Shorten the coverage period before closing.`,
    "source_period_close"
  ));
  if (duplicate) blockers.push(blocker(
    "statement_close_evidence_duplicate",
    "The local workflow evidence contains a missing or duplicate authority identity.",
    "source_period_close"
  ));
  const staleCount = normalized.filter((record) => !record.source_current).length;
  if (staleCount > 0) blockers.push(blocker(
    "statement_close_workflow_stale",
    `${staleCount} local workflow authorit${staleCount === 1 ? "y no longer matches" : "ies no longer match"} live reviewed evidence.`,
    "source_period_close"
  ));
  const byWorkflow = {};
  for (const record of normalized) {
    const summary = byWorkflow[record.workflow] || { total_count: 0, current_count: 0, blocking_count: 0 };
    summary.total_count += 1;
    if (record.source_current) summary.current_count += 1;
    else summary.blocking_count += 1;
    byWorkflow[record.workflow] = summary;
  }
  return {
    total_count: normalized.length,
    current_count: normalized.length - staleCount,
    blocking_count: staleCount,
    truncated: Boolean(truncated),
    by_workflow: byWorkflow,
    evidence_fingerprint: statementReadinessFingerprint(normalized),
    records: normalized,
    blockers: uniqueBlockers(blockers)
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

export function evaluateStatementPeriodClose({
  close = null,
  latestCloseVersion = 0,
  profile = null,
  opening,
  areas = [],
  workflows,
  sourceInventoryFingerprint,
  asOfDate
}) {
  const eligibilityBlockers = uniqueBlockers([
    ...(opening?.blockers || []),
    ...areas.flatMap((area) => area.blockers || []),
    ...(workflows?.blockers || [])
  ]);
  const eligible = Boolean(profile) && opening?.source_current === true && eligibilityBlockers.length === 0;
  const matches = Boolean(close)
    && dateValue(close.coverage_start_date) === profile?.coverage_start_date
    && dateValue(close.as_of_date) === asOfDate
    && Number(close.coverage_profile_version) === Number(profile?.version || 0)
    && close.opening_evidence_fingerprint === opening?.live_fingerprint
    && close.source_inventory_fingerprint === sourceInventoryFingerprint
    && close.workflow_evidence_fingerprint === workflows?.evidence_fingerprint;
  const sourceCurrent = eligible && matches;
  const localEvidenceExists = areas.some((area) => (area.total_count || 0) > 0) || (workflows?.total_count || 0) > 0;
  const blockers = [...eligibilityBlockers];
  if (localEvidenceExists && !sourceCurrent) {
    blockers.push(blocker(
      close ? "source_period_close_stale" : "source_period_close_not_reviewed",
      close
        ? "The latest retained local period close no longer matches the complete live source-workflow evidence at this boundary."
        : "Source inventory exists and needs one audited local period close that revalidates every owning workflow's live fingerprint at this boundary.",
      "source_period_close"
    ));
  }
  return {
    id: close?.id ? String(close.id) : null,
    status: sourceCurrent ? "current" : close ? "stale" : "not_reviewed",
    source_current: sourceCurrent,
    eligible,
    version: close ? Number(close.version) : null,
    latest_version: Number(latestCloseVersion || 0),
    coverage_start_date: close ? dateValue(close.coverage_start_date) : profile?.coverage_start_date || null,
    as_of_date: close ? dateValue(close.as_of_date) : asOfDate,
    source_inventory_fingerprint: close?.source_inventory_fingerprint || null,
    workflow_evidence_fingerprint: close?.workflow_evidence_fingerprint || null,
    reason: close?.reason || null,
    reviewed_by: close?.reviewed_by || null,
    reviewed_at: close?.created_at || null,
    blockers: uniqueBlockers(blockers)
  };
}

export function buildStatementReadiness({
  profile = null,
  opening,
  areas = [],
  workflows = normalizeStatementWorkflowEvidence([]),
  periodCloseRow = null,
  latestCloseVersion = 0,
  stripeConnected = false,
  balanceSheetRules = null,
  asOfDate
}) {
  const sourceInventoryFingerprint = statementReadinessFingerprint({
    coverage_start_date: profile?.coverage_start_date || null,
    as_of_date: asOfDate,
    opening_fingerprint: opening?.live_fingerprint || null,
    areas: areas.map((area) => ({ key: area.key, evidence_hash: area.evidence_hash, metrics: area.metrics })),
    workflow_evidence_fingerprint: workflows.evidence_fingerprint,
    stripe_connected: Boolean(stripeConnected)
  });
  const periodClose = evaluateStatementPeriodClose({
    close: periodCloseRow,
    latestCloseVersion,
    profile,
    opening,
    areas,
    workflows,
    sourceInventoryFingerprint,
    asOfDate
  });
  const common = uniqueBlockers([
    ...(opening?.blockers || []),
    ...areas.flatMap((area) => area.blockers || []),
    ...(workflows?.blockers || []),
    ...periodClose.blockers.filter((item) => item.code.startsWith("source_period_close_"))
  ]);
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
  const balanceCloseBlockers = periodClose.source_current || periodClose.blockers.some((item) => item.code.startsWith("source_period_close_"))
    ? []
    : [blocker(
      "source_period_close_not_reviewed",
      "A formal Balance Sheet requires one current audited local period close at this exact boundary, including when the retained local evidence set is empty.",
      "source_period_close"
    )];
  const balanceSheetBlockers = uniqueBlockers([
    ...common,
    ...balanceCloseBlockers,
    ...(balanceSheetRules?.blockers || [blocker(
      "balance_sheet_rules_not_reviewed",
      "Record a genuine qualified-accountant review of WolfCRM's fixed Balance Sheet presentation rules for the complete current chart.",
      "balance_sheet_rules"
    )])
  ]);
  const cashFlowBlockers = uniqueBlockers([
    ...common,
    blocker(
      "cash_flow_classification_unavailable",
      "Journal lines do not yet carry reviewed operating, investing, or financing classifications; account-type heuristics are not accounting authority.",
      "cash_flow_classification"
    )
  ]);
  const statementGate = (statement, blockers, implemented = false) => ({
    statement,
    status: blockers.length === 0 ? (implemented ? "available" : "coverage_ready") : "blocked",
    coverage_ready: blockers.length === 0,
    report_available: implemented && blockers.length === 0,
    blocker_count: blockers.length,
    blockers
  });
  return {
    source_inventory_fingerprint: sourceInventoryFingerprint,
    areas,
    workflows,
    period_close: periodClose,
    statements: {
      balance_sheet: statementGate("balance_sheet", balanceSheetBlockers, true),
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

    CREATE TABLE IF NOT EXISTS finance_statement_period_closes (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      version INTEGER NOT NULL CHECK (version > 0),
      coverage_profile_version INTEGER NOT NULL CHECK (coverage_profile_version > 0),
      coverage_start_date DATE NOT NULL,
      as_of_date DATE NOT NULL CHECK (as_of_date >= coverage_start_date),
      opening_evidence_fingerprint TEXT NOT NULL CHECK (char_length(opening_evidence_fingerprint)=64),
      source_inventory_fingerprint TEXT NOT NULL CHECK (char_length(source_inventory_fingerprint)=64),
      workflow_evidence_fingerprint TEXT NOT NULL CHECK (char_length(workflow_evidence_fingerprint)=64),
      evidence_snapshot JSONB NOT NULL,
      supersedes_close_id UUID,
      client_request_id UUID NOT NULL,
      request_fingerprint TEXT NOT NULL CHECK (char_length(request_fingerprint)=64),
      reason TEXT NOT NULL,
      reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, id),
      UNIQUE(company_id, version),
      UNIQUE(company_id, client_request_id),
      FOREIGN KEY (company_id, supersedes_close_id)
        REFERENCES finance_statement_period_closes(company_id, id) ON DELETE RESTRICT
    );
    CREATE INDEX IF NOT EXISTS finance_statement_period_closes_company_boundary_idx
      ON finance_statement_period_closes(company_id, coverage_start_date, as_of_date, version DESC);

    CREATE TABLE IF NOT EXISTS finance_statement_period_close_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      close_id UUID NOT NULL,
      version INTEGER NOT NULL CHECK (version > 0),
      coverage_start_date DATE NOT NULL,
      as_of_date DATE NOT NULL,
      source_inventory_fingerprint TEXT NOT NULL CHECK (char_length(source_inventory_fingerprint)=64),
      workflow_evidence_fingerprint TEXT NOT NULL CHECK (char_length(workflow_evidence_fingerprint)=64),
      actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL CHECK (action='local_period_closed'),
      reason TEXT NOT NULL,
      evidence_snapshot JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, close_id),
      FOREIGN KEY (company_id, close_id)
        REFERENCES finance_statement_period_closes(company_id, id) ON DELETE RESTRICT
    );
    CREATE INDEX IF NOT EXISTS finance_statement_period_close_audit_company_created_idx
      ON finance_statement_period_close_audit(company_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS finance_balance_sheet_rule_profiles (
      company_id UUID PRIMARY KEY REFERENCES companies(id) ON DELETE CASCADE,
      earnings_treatment TEXT NOT NULL CHECK (earnings_treatment='cumulative_since_coverage_start'),
      accountant_reviewed_on DATE NOT NULL,
      accountant_reference TEXT NOT NULL CHECK (char_length(accountant_reference) BETWEEN 1 AND 200),
      accountant_review_confirmed BOOLEAN NOT NULL CHECK (accountant_review_confirmed=true),
      version INTEGER NOT NULL CHECK (version > 0),
      chart_fingerprint TEXT NOT NULL CHECK (char_length(chart_fingerprint)=64),
      evidence_fingerprint TEXT NOT NULL CHECK (char_length(evidence_fingerprint)=64),
      evidence_snapshot JSONB NOT NULL,
      reason TEXT NOT NULL,
      reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL,
      reviewed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS finance_balance_sheet_rule_profiles_company_review_idx
      ON finance_balance_sheet_rule_profiles(company_id, accountant_reviewed_on, version DESC);

    CREATE TABLE IF NOT EXISTS finance_balance_sheet_rule_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL CHECK (action IN ('balance_sheet_rules_reviewed','balance_sheet_rules_replaced')),
      reason TEXT NOT NULL,
      version INTEGER NOT NULL CHECK (version > 0),
      client_request_id UUID NOT NULL,
      request_fingerprint TEXT NOT NULL CHECK (char_length(request_fingerprint)=64),
      before_state JSONB,
      after_state JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, client_request_id)
    );
    CREATE INDEX IF NOT EXISTS finance_balance_sheet_rule_audit_company_created_idx
      ON finance_balance_sheet_rule_audit(company_id, created_at DESC);
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

function balanceSheetRuleProfilePayload(row) {
  if (!row) return null;
  return {
    company_id: String(row.company_id),
    earnings_treatment: row.earnings_treatment,
    accountant_reviewed_on: dateValue(row.accountant_reviewed_on),
    accountant_reference: row.accountant_reference,
    accountant_review_confirmed: row.accountant_review_confirmed === true,
    version: Number(row.version),
    chart_fingerprint: row.chart_fingerprint,
    evidence_fingerprint: row.evidence_fingerprint,
    reason: row.reason,
    reviewed_by: row.reviewed_by || null,
    reviewed_at: timestampValue(row.reviewed_at),
    updated_at: timestampValue(row.updated_at)
  };
}

function balanceSheetRuleProfileSnapshot(row) {
  const profile = balanceSheetRuleProfilePayload(row);
  if (!profile) return null;
  return {
    earnings_treatment: profile.earnings_treatment,
    accountant_reviewed_on: profile.accountant_reviewed_on,
    accountant_reference: profile.accountant_reference,
    accountant_review_confirmed: profile.accountant_review_confirmed,
    version: profile.version,
    chart_fingerprint: profile.chart_fingerprint,
    evidence_fingerprint: profile.evidence_fingerprint
  };
}

async function loadBalanceSheetRuleProfile(poolOrClient, companyID, { lock = false } = {}) {
  const { rows } = await poolOrClient.query(
    `SELECT * FROM finance_balance_sheet_rule_profiles WHERE company_id=$1${lock ? " FOR UPDATE" : ""}`,
    [companyID]
  );
  return rows[0] || null;
}

async function loadBalanceSheetChart(poolOrClient, companyID) {
  const { rows } = await poolOrClient.query(
    `SELECT id, code, name, account_type, active, system_key
       FROM finance_chart_accounts WHERE company_id=$1
      ORDER BY id LIMIT $2`,
    [companyID, MAX_STATEMENT_ACCOUNTS + 1]
  );
  return rows;
}

async function loadBalanceSheetRuleState(poolOrClient, companyID, auditLimit = MAX_AUDIT_ROWS) {
  const [profileRow, chartAccounts, auditResult] = await Promise.all([
    loadBalanceSheetRuleProfile(poolOrClient, companyID),
    loadBalanceSheetChart(poolOrClient, companyID),
    poolOrClient.query(
      `SELECT id, action, reason, version, actor_user_id, created_at
         FROM finance_balance_sheet_rule_audit
        WHERE company_id=$1 ORDER BY created_at DESC LIMIT $2`,
      [companyID, Math.min(Math.max(Number(auditLimit) || MAX_AUDIT_ROWS, 1), 100)]
    )
  ]);
  const profile = balanceSheetRuleProfilePayload(profileRow);
  const evaluation = evaluateBalanceSheetRules({ profile, chartAccounts });
  return {
    state: {
      status: evaluation.status,
      source_current: evaluation.source_current,
      live_fingerprint: evaluation.live_fingerprint,
      chart_fingerprint: evaluation.chart_fingerprint,
      blockers: evaluation.blockers,
      profile
    },
    audit: auditResult.rows.map((row) => ({
      id: String(row.id), action: row.action, reason: row.reason, version: Number(row.version),
      actor_user_id: row.actor_user_id || null, created_at: timestampValue(row.created_at)
    }))
  };
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
       UNION ALL
       SELECT 'customer_credit', application.id, application.version, application.entry_date::timestamp,
              application.id, application.version,
              CASE WHEN application.status='posted' AND journal.id IS NOT NULL
                         AND journal.source_type='finance_operational_application'
                         AND journal.source_id=application.id AND journal.source_version=application.version
                   THEN true ELSE false END
         FROM finance_operational_applications application
         LEFT JOIN finance_journal_entries journal
           ON journal.company_id=application.company_id AND journal.id=application.journal_entry_id
        WHERE application.company_id=$1 AND application.kind='customer_credit' AND application.status='posted'
          AND application.entry_date BETWEEN $2::date AND $3::date
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
      key: "operational_applications", label: "Payment, refund, and customer-credit applications",
      row: applicationResult.rows[0], blockerCode: "operational_application_coverage_incomplete",
      blockerMessage: "Every collected payment, retained refund revision, and posted customer-credit application in the coverage period needs exact dated application authority and a current source-owned journal."
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

async function loadWorkflowEvidence(poolOrClient, companyID, startDate, asOfDate, timezone) {
  const { rows } = await poolOrClient.query(
    `WITH authorities AS (
       SELECT 'bank_transaction'::text AS workflow, posting.finance_transaction_id AS authority_id,
              posting.version AS authority_version, posting.source_fingerprint AS stored_source_fingerprint,
              posting.journal_entry_id, 'finance_transaction'::text AS expected_source_type,
              posting.finance_transaction_id AS expected_source_id
         FROM finance_bank_transaction_postings posting
         JOIN finance_transactions tx ON tx.company_id=posting.company_id AND tx.id=posting.finance_transaction_id
        WHERE posting.company_id=$1 AND posting.status='posted'
          AND tx.transaction_date BETWEEN $2::date AND $3::date
       UNION ALL
       SELECT 'bank_transfer', pair.id, pair.version, pair.source_fingerprint, pair.journal_entry_id,
              'finance_transfer_pair', pair.id
         FROM finance_transfer_pairs pair
         JOIN finance_journal_entries entry ON entry.company_id=pair.company_id AND entry.id=pair.journal_entry_id
        WHERE pair.company_id=$1 AND pair.status='posted' AND entry.entry_date BETWEEN $2::date AND $3::date
       UNION ALL
       SELECT 'job_receivable', posting.operational_source_id, posting.version, posting.source_fingerprint,
              posting.journal_entry_id, 'finance_operational_source', posting.operational_source_id
         FROM finance_operational_receivable_postings posting
         JOIN finance_operational_sources source
           ON source.company_id=posting.company_id AND source.id=posting.operational_source_id
        WHERE posting.company_id=$1 AND posting.status='posted'
          AND source.occurred_at IS NOT NULL
          AND (source.occurred_at AT TIME ZONE $4)::date BETWEEN $2::date AND $3::date
       UNION ALL
       SELECT 'operational_application', application.id, application.version, application.source_fingerprint,
              application.journal_entry_id, 'finance_operational_application', application.id
         FROM finance_operational_applications application
        WHERE application.company_id=$1 AND application.status='posted'
          AND application.entry_date BETWEEN $2::date AND $3::date
       UNION ALL
       SELECT 'payroll_accrual', posting.evaluation_period_id, posting.version, posting.source_fingerprint,
              posting.journal_entry_id, 'finance_payroll_evaluation', posting.evaluation_period_id
         FROM finance_payroll_journal_postings posting
         JOIN finance_payroll_evaluation_periods evaluation
           ON evaluation.company_id=posting.company_id AND evaluation.id=posting.evaluation_period_id
        WHERE posting.company_id=$1 AND posting.status='posted'
          AND evaluation.end_date BETWEEN $2::date AND $3::date
       UNION ALL
       SELECT 'stripe_settlement', settlement.id, settlement.version, settlement.source_fingerprint,
              settlement.journal_entry_id, 'finance_stripe_settlement', settlement.id
         FROM finance_stripe_settlements settlement
         JOIN finance_journal_entries entry
           ON entry.company_id=settlement.company_id AND entry.id=settlement.journal_entry_id
        WHERE settlement.company_id=$1 AND settlement.status='posted'
          AND entry.entry_date BETWEEN $2::date AND $3::date
     )
     SELECT authority.*, journal.source_type AS journal_source_type,
            journal.source_id AS journal_source_id, journal.source_version AS journal_source_version,
            reversed.id AS journal_reversed_by_entry_id
       FROM authorities authority
       LEFT JOIN finance_journal_entries journal
         ON journal.company_id=$1 AND journal.id=authority.journal_entry_id
       LEFT JOIN finance_journal_entries reversed
         ON reversed.company_id=journal.company_id AND reversed.reversal_of_entry_id=journal.id
      ORDER BY authority.workflow, authority.authority_id
      LIMIT $5`,
    [companyID, startDate, asOfDate, timezone, MAX_CLOSE_AUTHORITIES + 1]
  );
  const truncated = rows.length > MAX_CLOSE_AUTHORITIES;
  const records = [];
  for (const row of rows.slice(0, MAX_CLOSE_AUTHORITIES)) {
    let evaluation;
    try {
      switch (row.workflow) {
      case "bank_transaction":
        evaluation = await loadBankSourceCloseEvaluation(poolOrClient, companyID, row.authority_id);
        break;
      case "bank_transfer":
        evaluation = await loadBankTransferCloseEvaluation(poolOrClient, companyID, row.authority_id);
        break;
      case "job_receivable":
        evaluation = await loadOperationalReceivableCloseEvaluation(poolOrClient, companyID, row.authority_id);
        break;
      case "operational_application":
        evaluation = await loadOperationalApplicationCloseEvaluation(poolOrClient, companyID, row.authority_id);
        break;
      case "payroll_accrual":
        evaluation = await loadPayrollJournalCloseEvaluation(poolOrClient, companyID, row.authority_id);
        break;
      case "stripe_settlement":
        evaluation = await loadStripeSettlementLocalCloseEvaluation(poolOrClient, companyID, row.authority_id);
        break;
      default:
        throw new FinanceStatementReadinessError("statement_close_workflow_invalid", "Stored close workflow kind is invalid.", 409);
      }
    } catch (error) {
      if (!error?.statusCode) throw error;
      evaluation = {
        source_current: false,
        source_fingerprint: null,
        blockers: [{ code: error.code || "workflow_evaluation_failed" }]
      };
    }
    const journalCurrent = Boolean(row.journal_entry_id)
      && row.journal_source_type === row.expected_source_type
      && String(row.journal_source_id || "") === String(row.expected_source_id)
      && Number(row.journal_source_version) === Number(row.authority_version)
      && !row.journal_reversed_by_entry_id;
    const blockerCodes = (evaluation.blockers || []).map((item) => item.code).filter(Boolean);
    if (!journalCurrent) blockerCodes.push("workflow_journal_authority_invalid");
    records.push({
      workflow: row.workflow,
      authority_id: String(row.authority_id),
      authority_version: Number(row.authority_version),
      stored_fingerprint: row.stored_source_fingerprint,
      live_fingerprint: evaluation.source_fingerprint || null,
      source_current: evaluation.source_current === true && journalCurrent,
      blocker_codes: blockerCodes
    });
  }
  return normalizeStatementWorkflowEvidence(records, { truncated });
}

async function loadPeriodCloseState(poolOrClient, companyID, coverageStartDate, asOfDate, auditLimit = MAX_AUDIT_ROWS) {
  const [closeResult, versionResult, auditResult] = await Promise.all([
    poolOrClient.query(
      `SELECT * FROM finance_statement_period_closes
        WHERE company_id=$1 AND coverage_start_date=$2::date AND as_of_date=$3::date
        ORDER BY version DESC LIMIT 1`,
      [companyID, coverageStartDate, asOfDate]
    ),
    poolOrClient.query(
      `SELECT COALESCE(MAX(version),0)::int AS latest_version
         FROM finance_statement_period_closes WHERE company_id=$1`,
      [companyID]
    ),
    poolOrClient.query(
      `SELECT id, close_id, version, coverage_start_date, as_of_date, action, reason,
              source_inventory_fingerprint, workflow_evidence_fingerprint, actor_user_id, created_at
         FROM finance_statement_period_close_audit
        WHERE company_id=$1 ORDER BY created_at DESC LIMIT $2`,
      [companyID, Math.min(Math.max(Number(auditLimit) || MAX_AUDIT_ROWS, 1), 100)]
    )
  ]);
  return {
    close: closeResult.rows[0] || null,
    latest_version: Number(versionResult.rows[0]?.latest_version || 0),
    audit: auditResult.rows.map((row) => ({
      id: String(row.id), close_id: String(row.close_id), version: Number(row.version),
      coverage_start_date: dateValue(row.coverage_start_date), as_of_date: dateValue(row.as_of_date),
      action: row.action, reason: row.reason,
      source_inventory_fingerprint: row.source_inventory_fingerprint,
      workflow_evidence_fingerprint: row.workflow_evidence_fingerprint,
      actor_user_id: row.actor_user_id || null, created_at: timestampValue(row.created_at)
    }))
  };
}

async function loadStatementReadinessSnapshot(client, companyID, asOfValue, auditLimit) {
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
  const [opening, openingCandidates, audit, balanceSheetRuleState] = await Promise.all([
    loadOpeningEvidence(client, companyID, profile ? { ...profileRow, timezone: context.timezone } : null),
    loadOpeningCandidates(client, companyID),
    loadAudit(client, companyID, auditLimit),
    loadBalanceSheetRuleState(client, companyID, auditLimit)
  ]);
  const areas = profile
    ? await loadInventoryAreas(client, companyID, profile.coverage_start_date, asOfDate, context.timezone)
    : [];
  const workflows = profile
    ? await loadWorkflowEvidence(client, companyID, profile.coverage_start_date, asOfDate, context.timezone)
    : normalizeStatementWorkflowEvidence([]);
  const closeState = profile
    ? await loadPeriodCloseState(client, companyID, profile.coverage_start_date, asOfDate, auditLimit)
    : { close: null, latest_version: 0, audit: [] };
  const readiness = buildStatementReadiness({
    profile,
    opening,
    areas,
    workflows,
    periodCloseRow: closeState.close,
    latestCloseVersion: closeState.latest_version,
    stripeConnected: context.stripe_connected,
    balanceSheetRules: balanceSheetRuleState.state,
    asOfDate
  });
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
    period_close_audit: closeState.audit,
    balance_sheet_rules: balanceSheetRuleState.state,
    balance_sheet_rule_audit: balanceSheetRuleState.audit,
    ...readiness,
    warnings: [
      "This screen inventories formal-statement coverage. A Balance Sheet is available only after every live Balance Sheet gate and the accountant-reviewed presentation-rule authority are current; Cash Flow remains unavailable.",
      "A balanced trial balance does not prove opening balances, source completeness, provider-period completeness, payroll settlement, cash-flow classification, tax basis, or audit assurance.",
      "Phase 1 cash-basis Profit & Loss remains a separate bank-activity report and is not recomputed here."
    ]
  };
}

async function loadStatementReadiness(pool, companyID, asOfValue, auditLimit, ensureChartAccounts) {
  await ensureChartAccounts(pool, companyID);
  await syncOperationalAccountingSources(pool, companyID);
  const client = await pool.connect();
  try {
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    const payload = await loadStatementReadinessSnapshot(client, companyID, asOfValue, auditLimit);
    await client.query("COMMIT");
    return payload;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function loadBalanceSheetReport(client, companyID, readiness) {
  const coverageStartDate = readiness.profile?.coverage_start_date;
  if (!coverageStartDate || readiness.statements?.balance_sheet?.report_available !== true) {
    throw new FinanceStatementReadinessError(
      "balance_sheet_unavailable",
      "The Balance Sheet is unavailable until every live coverage and accountant-reviewed presentation-rule blocker is resolved.",
      409,
      { blockers: readiness.statements?.balance_sheet?.blockers || [] }
    );
  }
  const integrityResult = await client.query(
    `SELECT COUNT(*)::int AS invalid_count FROM (
       SELECT entry.id
         FROM finance_journal_entries entry
         LEFT JOIN finance_journal_lines line
           ON line.company_id=entry.company_id AND line.entry_id=entry.id
        WHERE entry.company_id=$1 AND entry.entry_date BETWEEN $2::date AND $3::date
        GROUP BY entry.id
       HAVING COUNT(line.id) < 2 OR COALESCE(SUM(line.debit_cents),0) <= 0
          OR COALESCE(SUM(line.debit_cents),0) <> COALESCE(SUM(line.credit_cents),0)
     ) invalid`,
    [companyID, coverageStartDate, readiness.as_of_date]
  );
  if (Number(integrityResult.rows[0]?.invalid_count || 0) > 0) {
    throw new FinanceStatementReadinessError(
      "balance_sheet_journal_integrity_failed",
      "Stored journal integrity checks failed inside the reviewed statement boundary. The Balance Sheet was not produced.",
      409
    );
  }
  const accountResult = await client.query(
    `WITH totals AS (
       SELECT line.chart_account_id,
              COALESCE(SUM(line.debit_cents),0) AS debit_cents,
              COALESCE(SUM(line.credit_cents),0) AS credit_cents
         FROM finance_journal_lines line
         JOIN finance_journal_entries entry
           ON entry.company_id=line.company_id AND entry.id=line.entry_id
        WHERE line.company_id=$1 AND entry.entry_date BETWEEN $2::date AND $3::date
        GROUP BY line.chart_account_id
     )
     SELECT account.id AS chart_account_id, account.code, account.name, account.account_type,
            account.active, COALESCE(totals.debit_cents,0) AS debit_cents,
            COALESCE(totals.credit_cents,0) AS credit_cents
       FROM finance_chart_accounts account
       LEFT JOIN totals ON totals.chart_account_id=account.id
      WHERE account.company_id=$1
      ORDER BY account.id
      LIMIT $4`,
    [companyID, coverageStartDate, readiness.as_of_date, MAX_STATEMENT_ACCOUNTS + 1]
  );
  const summary = summarizeBalanceSheetRows(accountResult.rows, {
    coverageStartDate,
    asOfDate: readiness.as_of_date
  });
  return {
    basis: "coverage_gated_accrual_double_entry",
    statement: "balance_sheet",
    title: "Balance Sheet",
    timezone: readiness.timezone,
    company_today: readiness.company_today,
    coverage_start_date: coverageStartDate,
    as_of_date: readiness.as_of_date,
    currency: readiness.currency,
    source_inventory_fingerprint: readiness.source_inventory_fingerprint,
    local_close_id: readiness.period_close?.id || null,
    local_close_version: readiness.period_close?.version || null,
    rule_version: readiness.balance_sheet_rules?.profile?.version || null,
    rule_evidence_fingerprint: readiness.balance_sheet_rules?.profile?.evidence_fingerprint || null,
    earnings_treatment: BALANCE_SHEET_EARNINGS_TREATMENT,
    sections: {
      assets: summary.assets,
      liabilities: summary.liabilities,
      posted_equity: summary.posted_equity
    },
    summary: {
      total_assets_cents: summary.total_assets_cents,
      total_liabilities_cents: summary.total_liabilities_cents,
      posted_equity_cents: summary.posted_equity_cents,
      income_cents: summary.income_cents,
      expense_cents: summary.expense_cents,
      accumulated_earnings_cents: summary.accumulated_earnings_cents,
      total_equity_cents: summary.total_equity_cents,
      total_liabilities_and_equity_cents: summary.total_liabilities_and_equity_cents,
      equation_difference_cents: summary.equation_difference_cents
    },
    warnings: [
      "This is an unclassified, single-date Balance Sheet from exact posted journal authority inside the reviewed coverage boundary.",
      "Accumulated Earnings Since Coverage Start combines income and expense accounts because WolfCRM has no reviewed fiscal-year or year-end closing authority. It is not labeled Retained Earnings or Current-Period Income and is never posted back to the ledger.",
      "Accountant review is a company-recorded assertion, not WolfCRM audit assurance, GAAP certification, tax advice, or provider completeness. Cash Flow remains unavailable."
    ]
  };
}

function sendError(res, error, fallback) {
  if (error instanceof FinanceStatementReadinessError || error?.statusCode) {
    return res.status(error.statusCode || 400).json({
      error: error.code || fallback,
      message: error.message,
      current_version: error.current_version,
      blockers: error.blockers,
      difference_cents: error.difference_cents
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

  app.post("/api/finance/accounting/statement-readiness/period-close", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Statement readiness requires a company workspace." });
    let client = null;
    try {
      await ensureChartAccounts(pool, req.companyId, req.userId);
      client = await pool.connect();
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ");
      await client.query(`SELECT pg_advisory_xact_lock(hashtext($1::text))`, [`${req.companyId}|accounting`]);
      await syncOperationalAccountingSources(client, req.companyId);
      const context = await loadCompanyContext(client, req.companyId);
      const request = normalizeStatementPeriodCloseRequest({ body: req.body, companyToday: context.company_today });
      const replay = await client.query(
        `SELECT request_fingerprint FROM finance_statement_period_closes
          WHERE company_id=$1 AND client_request_id=$2::uuid FOR UPDATE`,
        [req.companyId, request.client_request_id]
      );
      if (replay.rows.length) {
        if (replay.rows[0].request_fingerprint !== request.request_fingerprint) {
          throw new FinanceStatementReadinessError("statement_period_close_request_conflict", "That request ID was already used with different content.", 409);
        }
        await client.query("COMMIT");
        return res.json({ replayed: true, ...(await loadStatementReadiness(pool, req.companyId, request.as_of_date, req.query.audit_limit, ensureChartAccounts)) });
      }
      const profileRow = await loadProfile(client, req.companyId, { lock: true });
      if (!profileRow) {
        throw new FinanceStatementReadinessError("statement_coverage_profile_missing", "Review opening coverage before closing a local period.", 409);
      }
      const profile = { ...profilePayload(profileRow), timezone: context.timezone };
      if (request.as_of_date < profile.coverage_start_date) {
        throw new FinanceStatementReadinessError("statement_as_of_before_coverage", "As-of date must be on or after the reviewed coverage start.");
      }
      if (request.expected_profile_version !== profile.version) {
        throw new FinanceStatementReadinessError("statement_period_close_profile_stale", "Opening coverage changed after this close was loaded.", 409, { current_version: profile.version });
      }
      const [opening, areas, workflows, closeState] = await Promise.all([
        loadOpeningEvidence(client, req.companyId, { ...profileRow, timezone: context.timezone }),
        loadInventoryAreas(client, req.companyId, profile.coverage_start_date, request.as_of_date, context.timezone),
        loadWorkflowEvidence(client, req.companyId, profile.coverage_start_date, request.as_of_date, context.timezone),
        loadPeriodCloseState(client, req.companyId, profile.coverage_start_date, request.as_of_date, req.query.audit_limit)
      ]);
      if (request.expected_close_version !== closeState.latest_version) {
        throw new FinanceStatementReadinessError("statement_period_close_stale", "Local period-close authority changed after it was loaded.", 409, { current_version: closeState.latest_version });
      }
      const readiness = buildStatementReadiness({
        profile,
        opening,
        areas,
        workflows,
        periodCloseRow: closeState.close,
        latestCloseVersion: closeState.latest_version,
        stripeConnected: context.stripe_connected,
        asOfDate: request.as_of_date
      });
      if (request.source_inventory_fingerprint !== readiness.source_inventory_fingerprint) {
        throw new FinanceStatementReadinessError("statement_period_close_inventory_stale", "Source inventory changed after this close was loaded.", 409);
      }
      if (!readiness.period_close.eligible) {
        throw new FinanceStatementReadinessError(
          "statement_period_close_blocked",
          "Resolve every local opening, source-area, and workflow blocker before closing the period.",
          409,
          { blockers: readiness.period_close.blockers }
        );
      }
      const nextVersion = closeState.latest_version + 1;
      const evidenceSnapshot = {
        coverage_profile_version: profile.version,
        coverage_start_date: profile.coverage_start_date,
        as_of_date: request.as_of_date,
        opening_evidence_fingerprint: opening.live_fingerprint,
        source_inventory_fingerprint: readiness.source_inventory_fingerprint,
        workflow_evidence_fingerprint: workflows.evidence_fingerprint,
        areas: areas.map((area) => ({
          key: area.key,
          total_count: area.total_count,
          covered_count: area.covered_count,
          blocking_count: area.blocking_count,
          metrics: area.metrics,
          evidence_hash: area.evidence_hash
        })),
        workflows: workflows.records
      };
      const insertResult = await client.query(
        `INSERT INTO finance_statement_period_closes (
           company_id, version, coverage_profile_version, coverage_start_date, as_of_date,
           opening_evidence_fingerprint, source_inventory_fingerprint, workflow_evidence_fingerprint,
           evidence_snapshot, supersedes_close_id, client_request_id, request_fingerprint,
           reason, reviewed_by
         ) VALUES ($1,$2,$3,$4::date,$5::date,$6,$7,$8,$9,$10::uuid,$11::uuid,$12,$13,$14)
         RETURNING *`,
        [req.companyId, nextVersion, profile.version, profile.coverage_start_date, request.as_of_date,
          opening.live_fingerprint, readiness.source_inventory_fingerprint, workflows.evidence_fingerprint,
          JSON.stringify(evidenceSnapshot), closeState.close?.id || null, request.client_request_id,
          request.request_fingerprint, request.reason, req.userId]
      );
      const saved = insertResult.rows[0];
      await client.query(
        `INSERT INTO finance_statement_period_close_audit (
           company_id, close_id, version, coverage_start_date, as_of_date,
           source_inventory_fingerprint, workflow_evidence_fingerprint,
           actor_user_id, action, reason, evidence_snapshot
         ) VALUES ($1,$2,$3,$4::date,$5::date,$6,$7,$8,'local_period_closed',$9,$10)`,
        [req.companyId, saved.id, nextVersion, profile.coverage_start_date, request.as_of_date,
          readiness.source_inventory_fingerprint, workflows.evidence_fingerprint,
          req.userId, request.reason, JSON.stringify(evidenceSnapshot)]
      );
      await client.query("COMMIT");
      res.json({ replayed: false, ...(await loadStatementReadiness(pool, req.companyId, request.as_of_date, req.query.audit_limit, ensureChartAccounts)) });
    } catch (error) {
      await client?.query("ROLLBACK").catch(() => {});
      sendError(res, error, "statement_period_close_failed");
    } finally {
      client?.release();
    }
  });

  app.put("/api/finance/accounting/statements/balance-sheet/rules", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Balance Sheet rules require a company workspace." });
    await syncOperationalAccountingSources(pool, req.companyId);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(`SELECT pg_advisory_xact_lock(hashtext($1::text))`, [`${req.companyId}|accounting`]);
      const context = await loadCompanyContext(client, req.companyId);
      const request = normalizeBalanceSheetRuleReviewRequest({ body: req.body, companyToday: context.company_today });
      await ensureChartAccounts(client, req.companyId, req.userId);
      const replay = await client.query(
        `SELECT request_fingerprint FROM finance_balance_sheet_rule_audit
          WHERE company_id=$1 AND client_request_id=$2::uuid FOR UPDATE`,
        [req.companyId, request.client_request_id]
      );
      if (replay.rows.length) {
        if (replay.rows[0].request_fingerprint !== request.request_fingerprint) {
          throw new FinanceStatementReadinessError("balance_sheet_rule_request_conflict", "That request ID was already used with different content.", 409);
        }
        const payload = await loadStatementReadinessSnapshot(
          client, req.companyId, request.as_of_date, req.query.audit_limit
        );
        await client.query("COMMIT");
        return res.json({ replayed: true, ...payload });
      }
      const current = await loadBalanceSheetRuleProfile(client, req.companyId, { lock: true });
      const currentVersion = Number(current?.version || 0);
      if (request.expected_version !== currentVersion) {
        throw new FinanceStatementReadinessError(
          "balance_sheet_rule_stale",
          "Balance Sheet presentation rules changed after they were loaded.",
          409,
          { current_version: currentVersion }
        );
      }
      const chart = balanceSheetChartSnapshot(await loadBalanceSheetChart(client, req.companyId));
      const chartFingerprint = statementReadinessFingerprint(chart);
      const evidenceSnapshot = {
        earnings_treatment: request.earnings_treatment,
        accountant_reviewed_on: request.accountant_reviewed_on,
        accountant_reference: request.accountant_reference,
        accountant_review_confirmed: true,
        chart_fingerprint: chartFingerprint,
        chart
      };
      const evidenceFingerprint = statementReadinessFingerprint(evidenceSnapshot);
      const nextVersion = currentVersion + 1;
      const saved = (await client.query(
        `INSERT INTO finance_balance_sheet_rule_profiles (
           company_id, earnings_treatment, accountant_reviewed_on, accountant_reference,
           accountant_review_confirmed, version, chart_fingerprint, evidence_fingerprint,
           evidence_snapshot, reason, reviewed_by
         ) VALUES ($1,$2,$3::date,$4,true,$5,$6,$7,$8,$9,$10)
         ON CONFLICT(company_id) DO UPDATE SET
           earnings_treatment=EXCLUDED.earnings_treatment,
           accountant_reviewed_on=EXCLUDED.accountant_reviewed_on,
           accountant_reference=EXCLUDED.accountant_reference,
           accountant_review_confirmed=true,
           version=EXCLUDED.version,
           chart_fingerprint=EXCLUDED.chart_fingerprint,
           evidence_fingerprint=EXCLUDED.evidence_fingerprint,
           evidence_snapshot=EXCLUDED.evidence_snapshot,
           reason=EXCLUDED.reason,
           reviewed_by=EXCLUDED.reviewed_by,
           reviewed_at=now(), updated_at=now()
         RETURNING *`,
        [req.companyId, request.earnings_treatment, request.accountant_reviewed_on, request.accountant_reference,
          nextVersion, chartFingerprint, evidenceFingerprint, JSON.stringify(evidenceSnapshot), request.reason, req.userId]
      )).rows[0];
      await client.query(
        `INSERT INTO finance_balance_sheet_rule_audit (
           company_id, actor_user_id, action, reason, version, client_request_id,
           request_fingerprint, before_state, after_state
         ) VALUES ($1,$2,$3,$4,$5,$6::uuid,$7,$8,$9)`,
        [req.companyId, req.userId, current ? "balance_sheet_rules_replaced" : "balance_sheet_rules_reviewed",
          request.reason, nextVersion, request.client_request_id, request.request_fingerprint,
          current ? JSON.stringify(balanceSheetRuleProfileSnapshot(current)) : null,
          JSON.stringify(balanceSheetRuleProfileSnapshot(saved))]
      );
      const payload = await loadStatementReadinessSnapshot(
        client, req.companyId, request.as_of_date, req.query.audit_limit
      );
      await client.query("COMMIT");
      res.json({ replayed: false, ...payload });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendError(res, error, "balance_sheet_rule_review_failed");
    } finally {
      client.release();
    }
  });

  app.get("/api/finance/accounting/statements/balance-sheet", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Balance Sheet requires a company workspace." });
    await ensureChartAccounts(pool, req.companyId);
    await syncOperationalAccountingSources(pool, req.companyId);
    const client = await pool.connect();
    try {
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      const readiness = await loadStatementReadinessSnapshot(client, req.companyId, req.query.as_of_date, req.query.audit_limit);
      const report = await loadBalanceSheetReport(client, req.companyId, readiness);
      await client.query("COMMIT");
      res.json(report);
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendError(res, error, "balance_sheet_load_failed");
    } finally {
      client.release();
    }
  });
}
