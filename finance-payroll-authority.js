import { createHash } from "node:crypto";

const MAX_POLICY_HISTORY = 500;
const MAX_POLICY_AUDIT = 200;
const MAX_DAILY_RULES = 4;
const MAX_BURDEN_RULES = 20;
const MAX_COMMISSION_EVENTS = 300;
const MAX_SOURCE_CANDIDATES = 200;
const MAX_REPORT_DAYS = 31;

const POLICY_STATUSES = new Set(["draft", "reviewed"]);
const EXEMPTION_STATUSES = new Set(["undetermined", "nonexempt", "exempt"]);
const OVERTIME_METHODS = new Set(["undetermined", "weekly_regular_rate", "manual_premium", "not_applicable"]);
const STATE_OVERTIME_STATUSES = new Set(["undetermined", "none", "configured", "manual"]);
const BURDEN_STATUSES = new Set(["undetermined", "none", "configured"]);
const BURDEN_CATEGORIES = new Set(["employer_tax", "benefit", "workers_comp", "insurance", "other"]);
const BURDEN_BASES = new Set(["percent_of_wages", "fixed_per_hour", "fixed_per_workweek"]);
const COMMISSION_KINDS = new Set(["earning", "adjustment"]);
const COMMISSION_SOURCE_TYPES = new Set(["job", "quote", "manual"]);
const REGULAR_RATE_TREATMENTS = new Set(["included", "excluded"]);

export class PayrollAuthorityError extends Error {
  constructor(code, message, statusCode = 400, details = {}) {
    super(message);
    this.name = "PayrollAuthorityError";
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
    throw new PayrollAuthorityError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return parsed;
}

function optionalInteger(value, field, bounds = {}) {
  if (value == null || value === "") return null;
  return exactInteger(value, field, bounds);
}

function dateOnly(value, field = "date") {
  const raw = value instanceof Date ? value.toISOString().slice(0, 10) : cleanString(value, 20);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    throw new PayrollAuthorityError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  const [year, month, day] = raw.split("-").map(Number);
  const parsed = new Date(Date.UTC(year, month - 1, day));
  if (parsed.getUTCFullYear() !== year || parsed.getUTCMonth() !== month - 1 || parsed.getUTCDate() !== day) {
    throw new PayrollAuthorityError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return raw;
}

function addDays(value, days) {
  const [year, month, day] = value.split("-").map(Number);
  return new Date(Date.UTC(year, month - 1, day + days)).toISOString().slice(0, 10);
}

function inclusiveDayCount(startDate, endDate) {
  return Math.round((Date.parse(`${endDate}T00:00:00.000Z`) - Date.parse(`${startDate}T00:00:00.000Z`)) / 86_400_000) + 1;
}

function enumValue(value, allowed, field) {
  const normalized = cleanString(value, 60).toLowerCase();
  if (!allowed.has(normalized)) {
    throw new PayrollAuthorityError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return normalized;
}

function uuid(value, field) {
  const normalized = cleanString(value, 80).toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(normalized)) {
    throw new PayrollAuthorityError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return normalized;
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

function normalizeDailyRules(value) {
  if (value == null) return [];
  if (!Array.isArray(value) || value.length > MAX_DAILY_RULES) {
    throw new PayrollAuthorityError("daily_overtime_rules_invalid", `Use at most ${MAX_DAILY_RULES} daily overtime tiers.`);
  }
  const ids = new Set();
  const rules = value.map((raw, index) => {
    const id = cleanString(raw?.id, 80);
    if (!id || ids.has(id)) throw new PayrollAuthorityError("daily_overtime_rule_id_invalid", "Daily overtime rule IDs must be present and unique.");
    ids.add(id);
    return {
      id,
      threshold_seconds: exactInteger(raw?.threshold_seconds, `daily_rule_${index + 1}_threshold_seconds`, { minimum: 1, maximum: 86_400 }),
      multiplier_basis_points: exactInteger(raw?.multiplier_basis_points, `daily_rule_${index + 1}_multiplier_basis_points`, { minimum: 10_000, maximum: 30_000 })
    };
  }).sort((left, right) => left.threshold_seconds - right.threshold_seconds || left.id.localeCompare(right.id));
  for (let index = 1; index < rules.length; index += 1) {
    if (rules[index].threshold_seconds <= rules[index - 1].threshold_seconds) {
      throw new PayrollAuthorityError("daily_overtime_thresholds_invalid", "Daily overtime thresholds must increase without duplicates.");
    }
  }
  return rules;
}

function normalizeBurdenRules(value) {
  if (value == null) return [];
  if (!Array.isArray(value) || value.length > MAX_BURDEN_RULES) {
    throw new PayrollAuthorityError("burden_rules_invalid", `Use at most ${MAX_BURDEN_RULES} employer-burden rules.`);
  }
  const ids = new Set();
  return value.map((raw, index) => {
    const id = cleanString(raw?.id, 80);
    const label = cleanString(raw?.label, 120);
    if (!id || ids.has(id)) throw new PayrollAuthorityError("burden_rule_id_invalid", "Burden rule IDs must be present and unique.");
    if (!label) throw new PayrollAuthorityError("burden_rule_label_required", "Every burden rule needs a label.");
    ids.add(id);
    const category = enumValue(raw?.category, BURDEN_CATEGORIES, `burden_rule_${index + 1}_category`);
    const basis = enumValue(raw?.basis, BURDEN_BASES, `burden_rule_${index + 1}_basis`);
    const rateBasisPoints = optionalInteger(raw?.rate_basis_points, `burden_rule_${index + 1}_rate_basis_points`, { minimum: 0, maximum: 100_000 });
    const amountCents = optionalInteger(raw?.amount_cents, `burden_rule_${index + 1}_amount_cents`, { minimum: 0 });
    if (basis === "percent_of_wages" ? rateBasisPoints == null || amountCents != null : amountCents == null || rateBasisPoints != null) {
      throw new PayrollAuthorityError("burden_rule_value_invalid", "Each burden rule must provide the exact value required by its basis.");
    }
    return {
      id,
      label,
      category,
      basis,
      rate_basis_points: rateBasisPoints,
      amount_cents: amountCents,
      annual_wage_cap_cents: optionalInteger(raw?.annual_wage_cap_cents, `burden_rule_${index + 1}_annual_wage_cap_cents`, { minimum: 0 })
    };
  });
}

export function normalizePayrollPolicyInput(body = {}) {
  const reason = cleanString(body.reason, 500);
  if (!reason) throw new PayrollAuthorityError("payroll_policy_reason_required", "Add a reason for this payroll-policy change.");
  const status = enumValue(body.status, POLICY_STATUSES, "policy_status");
  const exemptionStatus = enumValue(body.exemption_status, EXEMPTION_STATUSES, "exemption_status");
  const overtimeMethod = enumValue(body.overtime_method, OVERTIME_METHODS, "overtime_method");
  const stateOvertimeStatus = enumValue(body.state_overtime_status, STATE_OVERTIME_STATUSES, "state_overtime_status");
  const burdenStatus = enumValue(body.burden_status, BURDEN_STATUSES, "burden_status");
  const jurisdictionCode = cleanString(body.jurisdiction_code, 32).toUpperCase();
  if (!jurisdictionCode) throw new PayrollAuthorityError("jurisdiction_code_required", "Add the reviewed work jurisdiction.");
  const dailyRules = normalizeDailyRules(body.daily_overtime_rules);
  const burdenRules = normalizeBurdenRules(body.burden_rules);
  const specialRuleNotes = cleanString(body.special_rule_notes, 1000) || null;
  const weeklyThresholdSeconds = optionalInteger(body.weekly_threshold_seconds, "weekly_threshold_seconds", { minimum: 1, maximum: 7 * 24 * 3_600 });
  const weeklyMultiplierBasisPoints = optionalInteger(body.weekly_multiplier_basis_points, "weekly_multiplier_basis_points", { minimum: 10_000, maximum: 30_000 });

  if (overtimeMethod === "weekly_regular_rate" && (weeklyThresholdSeconds == null || weeklyMultiplierBasisPoints == null)) {
    throw new PayrollAuthorityError("weekly_overtime_rule_incomplete", "Weekly regular-rate policies require an exact threshold and multiplier.");
  }
  if (overtimeMethod !== "weekly_regular_rate" && (weeklyThresholdSeconds != null || weeklyMultiplierBasisPoints != null)) {
    throw new PayrollAuthorityError("weekly_overtime_rule_unexpected", "Weekly threshold and multiplier apply only to the weekly regular-rate method.");
  }
  if (stateOvertimeStatus === "configured" && dailyRules.length === 0) {
    throw new PayrollAuthorityError("daily_overtime_rules_required", "Configured state overtime requires at least one exact daily tier.");
  }
  if (stateOvertimeStatus !== "configured" && dailyRules.length > 0) {
    throw new PayrollAuthorityError("daily_overtime_rules_unexpected", "Daily tiers require Configured state overtime.");
  }
  if (stateOvertimeStatus === "manual" && !specialRuleNotes) {
    throw new PayrollAuthorityError("special_rule_notes_required", "Manual state/local overtime requires a bounded explanation.");
  }
  if (overtimeMethod === "manual_premium" && !specialRuleNotes) {
    throw new PayrollAuthorityError("special_rule_notes_required", "Manual overtime-premium authority requires a bounded explanation.");
  }
  if (burdenStatus === "configured" && burdenRules.length === 0) {
    throw new PayrollAuthorityError("burden_rules_required", "Configured employer burden requires at least one exact rule.");
  }
  if (burdenStatus !== "configured" && burdenRules.length > 0) {
    throw new PayrollAuthorityError("burden_rules_unexpected", "Burden rules require Configured employer burden.");
  }
  if (exemptionStatus === "exempt" && overtimeMethod !== "not_applicable") {
    throw new PayrollAuthorityError("exempt_overtime_method_invalid", "An exempt policy must explicitly mark overtime Not Applicable.");
  }
  if (exemptionStatus === "nonexempt" && ["undetermined", "not_applicable"].includes(overtimeMethod)) {
    throw new PayrollAuthorityError("nonexempt_overtime_method_invalid", "A nonexempt policy needs a reviewed overtime method.");
  }
  if (status === "reviewed") {
    if (exemptionStatus === "undetermined" || overtimeMethod === "undetermined"
        || stateOvertimeStatus === "undetermined" || burdenStatus === "undetermined") {
      throw new PayrollAuthorityError("reviewed_policy_incomplete", "Reviewed payroll policies cannot retain undetermined rule coverage.");
    }
  }
  return {
    expected_version: exactInteger(body.expected_version, "expected_version", { minimum: 0 }),
    effective_from: dateOnly(body.effective_from, "effective_from"),
    status,
    jurisdiction_code: jurisdictionCode,
    exemption_status: exemptionStatus,
    overtime_method: overtimeMethod,
    weekly_threshold_seconds: weeklyThresholdSeconds,
    weekly_multiplier_basis_points: weeklyMultiplierBasisPoints,
    state_overtime_status: stateOvertimeStatus,
    daily_overtime_rules: dailyRules,
    burden_status: burdenStatus,
    burden_rules: burdenRules,
    special_rule_notes: specialRuleNotes,
    notes: cleanString(body.notes, 1000) || null,
    reason
  };
}

function policyFacts(row) {
  return {
    status: row.status,
    jurisdiction_code: row.jurisdiction_code,
    exemption_status: row.exemption_status,
    overtime_method: row.overtime_method,
    weekly_threshold_seconds: row.weekly_threshold_seconds == null ? null : Number(row.weekly_threshold_seconds),
    weekly_multiplier_basis_points: row.weekly_multiplier_basis_points == null ? null : Number(row.weekly_multiplier_basis_points),
    state_overtime_status: row.state_overtime_status,
    daily_overtime_rules: Array.isArray(row.daily_overtime_rules) ? row.daily_overtime_rules : [],
    burden_status: row.burden_status,
    burden_rules: Array.isArray(row.burden_rules) ? row.burden_rules : [],
    special_rule_notes: row.special_rule_notes || null,
    notes: row.notes || null
  };
}

function samePolicyFacts(row, update) {
  return JSON.stringify(stableValue(policyFacts(row))) === JSON.stringify(stableValue({
    status: update.status,
    jurisdiction_code: update.jurisdiction_code,
    exemption_status: update.exemption_status,
    overtime_method: update.overtime_method,
    weekly_threshold_seconds: update.weekly_threshold_seconds,
    weekly_multiplier_basis_points: update.weekly_multiplier_basis_points,
    state_overtime_status: update.state_overtime_status,
    daily_overtime_rules: update.daily_overtime_rules,
    burden_status: update.burden_status,
    burden_rules: update.burden_rules,
    special_rule_notes: update.special_rule_notes,
    notes: update.notes
  }));
}

export function planPayrollPolicyUpdate({ rows = [], update }) {
  const normalizedRows = rows.map((row) => ({
    ...row,
    effective_from: dateOnly(row.effective_from, "effective_from"),
    effective_to: row.effective_to == null ? null : dateOnly(row.effective_to, "effective_to"),
    version: exactInteger(Number(row.version), "version", { minimum: 1 })
  })).sort((left, right) => left.effective_from.localeCompare(right.effective_from));
  for (let index = 1; index < normalizedRows.length; index += 1) {
    const previous = normalizedRows[index - 1];
    if (!previous.effective_to || previous.effective_to >= normalizedRows[index].effective_from) {
      throw new PayrollAuthorityError("payroll_policy_history_invalid", "Overlapping payroll policies require review before another change.", 409);
    }
  }
  const sameDay = normalizedRows.find((row) => row.effective_from === update.effective_from) || null;
  const applicable = normalizedRows.filter((row) => row.effective_from <= update.effective_from
    && (!row.effective_to || row.effective_to >= update.effective_from));
  if (applicable.length > 1) throw new PayrollAuthorityError("payroll_policy_history_invalid", "Overlapping payroll policies require review before another change.", 409);
  const predecessor = sameDay ? null : applicable[0] || null;
  const expectedRecord = sameDay || predecessor;
  const currentVersion = expectedRecord?.version || 0;
  if (update.expected_version !== currentVersion) {
    throw new PayrollAuthorityError("payroll_policy_stale", "This payroll policy changed after it was loaded. Refresh before saving again.", 409, { current_version: currentVersion });
  }
  if (sameDay && samePolicyFacts(sameDay, update)) return { mode: "replay", current: sameDay, current_version: currentVersion };
  if (sameDay) return { mode: "correct", target: sameDay, current_version: currentVersion };
  const next = normalizedRows.find((row) => row.effective_from > update.effective_from) || null;
  return {
    mode: "create",
    predecessor,
    effective_from: update.effective_from,
    effective_to: next ? addDays(next.effective_from, -1) : null,
    current_version: currentVersion
  };
}

export function parsePayrollAuthorityRange(startValue, endValue, { companyToday = null } = {}) {
  const startDate = dateOnly(startValue, "start_date");
  const endDate = dateOnly(endValue, "end_date");
  if (startDate > endDate) throw new PayrollAuthorityError("payroll_authority_range_invalid", "Start date must be on or before end date.");
  if (inclusiveDayCount(startDate, endDate) > MAX_REPORT_DAYS) {
    throw new PayrollAuthorityError("payroll_authority_range_too_large", `Payroll authority reports cannot exceed ${MAX_REPORT_DAYS} days.`);
  }
  if (companyToday && endDate > companyToday) throw new PayrollAuthorityError("payroll_authority_future_period", "Payroll authority cannot be reviewed for a future company date.");
  return { start_date: startDate, end_date: endDate };
}

export function normalizeCommissionEventInput(body = {}) {
  const eventKind = enumValue(body.event_kind, COMMISSION_KINDS, "commission_event_kind");
  const reason = cleanString(body.reason, 500);
  if (!reason) throw new PayrollAuthorityError("commission_reason_required", "Add a reason for this commission entry.");
  const commissionCents = exactInteger(body.commission_cents, "commission_cents");
  if (eventKind === "earning" && commissionCents < 0) throw new PayrollAuthorityError("commission_earning_negative", "A commission earning cannot be negative.");
  if (eventKind === "adjustment" && commissionCents === 0) throw new PayrollAuthorityError("commission_adjustment_zero", "A commission adjustment cannot be zero.");
  const rootEventId = eventKind === "adjustment" ? uuid(body.root_event_id, "root_event_id") : null;
  if (eventKind === "earning" && body.root_event_id != null) throw new PayrollAuthorityError("commission_root_unexpected", "A commission earning cannot reference another earning.");
  const sourceType = eventKind === "earning" ? enumValue(body.source_type, COMMISSION_SOURCE_TYPES, "commission_source_type") : null;
  const sourceId = eventKind === "earning" && sourceType !== "manual" ? cleanString(body.source_id, 100) : null;
  const sourceLabel = eventKind === "earning" && sourceType === "manual" ? cleanString(body.source_label, 160) : null;
  if (eventKind === "earning" && sourceType !== "manual" && !sourceId) throw new PayrollAuthorityError("commission_source_id_required", "Choose the exact job or accepted quote source.");
  if (eventKind === "earning" && sourceType === "manual" && !sourceLabel) throw new PayrollAuthorityError("commission_source_label_required", "Describe the manual commission source.");
  const treatment = eventKind === "earning" ? enumValue(body.regular_rate_treatment, REGULAR_RATE_TREATMENTS, "regular_rate_treatment") : null;
  const treatmentBasis = eventKind === "earning" ? cleanString(body.regular_rate_basis, 500) || null : null;
  if (treatment === "excluded" && !treatmentBasis) {
    throw new PayrollAuthorityError("regular_rate_basis_required", "Explain the reviewed basis for excluding this commission from regular-rate remuneration.");
  }
  return {
    client_request_id: uuid(body.client_request_id, "client_request_id"),
    employee_id: uuid(body.employee_id, "employee_id"),
    event_kind: eventKind,
    root_event_id: rootEventId,
    earned_date: dateOnly(body.earned_date, "earned_date"),
    commission_cents: commissionCents,
    regular_rate_treatment: treatment,
    regular_rate_basis: treatmentBasis,
    source_type: sourceType,
    source_id: sourceId,
    source_label: sourceLabel,
    eligible_revenue_cents: eventKind === "earning" ? optionalInteger(body.eligible_revenue_cents, "eligible_revenue_cents", { minimum: 0 }) : null,
    job_id: eventKind === "earning" ? cleanString(body.job_id, 100) || null : null,
    notes: cleanString(body.notes, 1000) || null,
    reason
  };
}

export function commissionEventRequestFingerprint(input) {
  return fingerprint(input);
}

export function validateCommissionCorrectionFloor(rootCents, adjustmentCents, priorAdjustmentCents = []) {
  const root = exactInteger(rootCents, "root_commission_cents", { minimum: 0 });
  const adjustment = exactInteger(adjustmentCents, "commission_cents");
  const prior = priorAdjustmentCents.map((value) => exactInteger(value, "prior_adjustment_cents"));
  const total = root + prior.reduce((sum, value) => sum + value, 0) + adjustment;
  if (!Number.isSafeInteger(total) || total < 0) {
    throw new PayrollAuthorityError("commission_adjustment_below_zero", "This correction would reduce the reviewed earning below zero.", 409);
  }
  return total;
}

function dbInteger(value, field) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(parsed)) throw new PayrollAuthorityError("payroll_authority_source_inexact", `${field.replaceAll("_", " ")} exceeds the exact supported range.`, 500);
  return parsed;
}

function policyPayload(row) {
  if (!row) return null;
  return {
    id: String(row.id),
    employee_id: String(row.employee_id),
    effective_from: dateOnly(row.effective_from, "effective_from"),
    effective_to: row.effective_to == null ? null : dateOnly(row.effective_to, "effective_to"),
    ...policyFacts(row),
    version: dbInteger(row.version, "version"),
    created_by: row.created_by || null,
    updated_by: row.updated_by || null,
    created_at: row.created_at || null,
    updated_at: row.updated_at || null
  };
}

function policyAuditSnapshot(row) {
  if (!row) return null;
  const payload = policyPayload(row);
  return {
    id: payload.id,
    effective_from: payload.effective_from,
    effective_to: payload.effective_to,
    status: payload.status,
    jurisdiction_code: payload.jurisdiction_code,
    exemption_status: payload.exemption_status,
    overtime_method: payload.overtime_method,
    weekly_threshold_seconds: payload.weekly_threshold_seconds,
    weekly_multiplier_basis_points: payload.weekly_multiplier_basis_points,
    state_overtime_status: payload.state_overtime_status,
    daily_overtime_rules: payload.daily_overtime_rules,
    burden_status: payload.burden_status,
    burden_rules: payload.burden_rules,
    special_rule_notes: payload.special_rule_notes,
    notes: payload.notes,
    version: payload.version
  };
}

function normalizedStringArray(value) {
  return Array.isArray(value) ? [...new Set(value.map(String))].sort() : [];
}

function normalizedInstant(value) {
  if (value == null) return null;
  const parsed = value instanceof Date ? value : new Date(value);
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toISOString();
}

function commissionEventPayload(row) {
  const snapshot = row.source_snapshot && typeof row.source_snapshot === "object" ? row.source_snapshot : {};
  let sourceAvailable = row.source_type === "manual";
  let sourceChanged = false;
  if (row.source_type === "job") {
    sourceAvailable = Boolean(row.current_job_id);
    sourceChanged = sourceAvailable && (
      (snapshot.title || null) !== (row.current_source_title || null)
      || (snapshot.value_cents ?? null) !== (row.current_source_value_cents == null ? null : dbInteger(row.current_source_value_cents, "current_source_value_cents"))
      || normalizedInstant(snapshot.finished_at) !== normalizedInstant(row.current_job_finished_at)
      || JSON.stringify(normalizedStringArray(snapshot.sales_user_ids)) !== JSON.stringify(normalizedStringArray(row.current_sales_user_ids))
    );
  } else if (row.source_type === "quote") {
    sourceAvailable = Boolean(row.current_quote_id);
    sourceChanged = sourceAvailable && (
      (snapshot.title || null) !== (row.current_source_title || null)
      || (snapshot.value_cents ?? null) !== (row.current_source_value_cents == null ? null : dbInteger(row.current_source_value_cents, "current_source_value_cents"))
      || (snapshot.status || null) !== (row.current_quote_status || null)
      || normalizedInstant(snapshot.accepted_at) !== normalizedInstant(row.current_quote_accepted_at)
    );
  }
  return {
    id: String(row.id),
    employee_id: String(row.employee_id),
    employee_name: row.employee_name || row.employee_email || "Employee",
    event_kind: row.event_kind,
    root_event_id: row.root_event_id || null,
    earned_date: dateOnly(row.earned_date, "earned_date"),
    commission_cents: dbInteger(row.commission_cents, "commission_cents"),
    regular_rate_treatment: row.regular_rate_treatment,
    regular_rate_basis: row.regular_rate_basis || null,
    source_type: row.source_type,
    source_id: row.source_id || null,
    source_label: row.source_label,
    source_value_cents: row.source_value_cents == null ? null : dbInteger(row.source_value_cents, "source_value_cents"),
    eligible_revenue_cents: row.eligible_revenue_cents == null ? null : dbInteger(row.eligible_revenue_cents, "eligible_revenue_cents"),
    source_available: sourceAvailable,
    source_changed: sourceChanged,
    job_id: row.job_id || null,
    job_title: row.target_job_title || null,
    pay_structure_id: row.pay_structure_id || null,
    pay_structure_version: row.pay_structure_version == null ? null : dbInteger(row.pay_structure_version, "pay_structure_version"),
    commission_tiers: Array.isArray(row.commission_tiers) ? row.commission_tiers : [],
    reason: row.reason,
    notes: row.notes || null,
    created_by: row.created_by || null,
    created_at: row.created_at
  };
}

export async function installFinancePayrollAuthoritySchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS finance_payroll_policies (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      employee_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
      effective_from DATE NOT NULL,
      effective_to DATE,
      status TEXT NOT NULL DEFAULT 'draft',
      jurisdiction_code TEXT NOT NULL,
      exemption_status TEXT NOT NULL DEFAULT 'undetermined',
      overtime_method TEXT NOT NULL DEFAULT 'undetermined',
      weekly_threshold_seconds INTEGER,
      weekly_multiplier_basis_points INTEGER,
      state_overtime_status TEXT NOT NULL DEFAULT 'undetermined',
      daily_overtime_rules JSONB NOT NULL DEFAULT '[]'::jsonb,
      burden_status TEXT NOT NULL DEFAULT 'undetermined',
      burden_rules JSONB NOT NULL DEFAULT '[]'::jsonb,
      special_rule_notes TEXT,
      notes TEXT,
      version INTEGER NOT NULL DEFAULT 1,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, employee_id, effective_from),
      CHECK (effective_to IS NULL OR effective_to >= effective_from),
      CHECK (status IN ('draft','reviewed')),
      CHECK (exemption_status IN ('undetermined','nonexempt','exempt')),
      CHECK (overtime_method IN ('undetermined','weekly_regular_rate','manual_premium','not_applicable')),
      CHECK (weekly_threshold_seconds IS NULL OR weekly_threshold_seconds > 0),
      CHECK (weekly_multiplier_basis_points IS NULL OR weekly_multiplier_basis_points >= 10000),
      CHECK (state_overtime_status IN ('undetermined','none','configured','manual')),
      CHECK (burden_status IN ('undetermined','none','configured')),
      CHECK (jsonb_typeof(daily_overtime_rules) = 'array'),
      CHECK (jsonb_typeof(burden_rules) = 'array'),
      CHECK ((overtime_method = 'weekly_regular_rate' AND weekly_threshold_seconds IS NOT NULL AND weekly_multiplier_basis_points IS NOT NULL)
          OR (overtime_method <> 'weekly_regular_rate' AND weekly_threshold_seconds IS NULL AND weekly_multiplier_basis_points IS NULL)),
      CHECK ((state_overtime_status = 'configured' AND jsonb_array_length(daily_overtime_rules) > 0)
          OR (state_overtime_status <> 'configured' AND jsonb_array_length(daily_overtime_rules) = 0)),
      CHECK (state_overtime_status <> 'manual' OR NULLIF(BTRIM(special_rule_notes), '') IS NOT NULL),
      CHECK (overtime_method <> 'manual_premium' OR NULLIF(BTRIM(special_rule_notes), '') IS NOT NULL),
      CHECK ((burden_status = 'configured' AND jsonb_array_length(burden_rules) > 0)
          OR (burden_status <> 'configured' AND jsonb_array_length(burden_rules) = 0)),
      CHECK (exemption_status <> 'exempt' OR overtime_method = 'not_applicable'),
      CHECK (exemption_status <> 'nonexempt' OR overtime_method IN ('weekly_regular_rate','manual_premium')),
      CHECK (status <> 'reviewed' OR (
        exemption_status <> 'undetermined' AND overtime_method <> 'undetermined'
        AND state_overtime_status <> 'undetermined' AND burden_status <> 'undetermined'
      )),
      CHECK (version > 0)
    );
    CREATE INDEX IF NOT EXISTS finance_payroll_policies_company_employee_effective_idx
      ON finance_payroll_policies(company_id, employee_id, effective_from DESC, effective_to);

    CREATE TABLE IF NOT EXISTS finance_payroll_policy_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      employee_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
      policy_id UUID NOT NULL REFERENCES finance_payroll_policies(id) ON DELETE RESTRICT,
      actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      reason TEXT NOT NULL,
      before_state JSONB,
      after_state JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS finance_payroll_policy_audit_company_employee_idx
      ON finance_payroll_policy_audit(company_id, employee_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS finance_commission_events (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      employee_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
      event_kind TEXT NOT NULL,
      root_event_id UUID REFERENCES finance_commission_events(id) ON DELETE RESTRICT,
      earned_date DATE NOT NULL,
      commission_cents BIGINT NOT NULL,
      regular_rate_treatment TEXT NOT NULL,
      regular_rate_basis TEXT,
      source_type TEXT NOT NULL,
      source_id TEXT,
      source_label TEXT NOT NULL,
      source_value_cents BIGINT,
      eligible_revenue_cents BIGINT,
      source_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
      job_id TEXT,
      pay_structure_id UUID REFERENCES employee_pay_structures(id) ON DELETE RESTRICT,
      pay_structure_version INTEGER,
      commission_tiers JSONB NOT NULL DEFAULT '[]'::jsonb,
      client_request_id UUID NOT NULL,
      request_fingerprint TEXT NOT NULL,
      reason TEXT NOT NULL,
      notes TEXT,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, client_request_id),
      CHECK (event_kind IN ('earning','adjustment')),
      CHECK ((event_kind = 'earning' AND root_event_id IS NULL AND commission_cents >= 0)
          OR (event_kind = 'adjustment' AND root_event_id IS NOT NULL AND commission_cents <> 0)),
      CHECK (regular_rate_treatment IN ('included','excluded')),
      CHECK (regular_rate_treatment <> 'excluded' OR NULLIF(BTRIM(regular_rate_basis), '') IS NOT NULL),
      CHECK (source_type IN ('job','quote','manual')),
      CHECK ((source_type = 'manual' AND source_id IS NULL) OR (source_type <> 'manual' AND NULLIF(BTRIM(source_id), '') IS NOT NULL)),
      CHECK (source_value_cents IS NULL OR source_value_cents >= 0),
      CHECK (eligible_revenue_cents IS NULL OR eligible_revenue_cents >= 0),
      CHECK (pay_structure_version IS NULL OR pay_structure_version > 0),
      CHECK (jsonb_typeof(commission_tiers) = 'array')
    );
    CREATE INDEX IF NOT EXISTS finance_commission_events_company_date_employee_idx
      ON finance_commission_events(company_id, earned_date, employee_id, created_at);
    CREATE INDEX IF NOT EXISTS finance_commission_events_company_root_idx
      ON finance_commission_events(company_id, root_event_id, created_at) WHERE root_event_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS finance_commission_events_company_job_idx
      ON finance_commission_events(company_id, job_id) WHERE job_id IS NOT NULL;
  `);
}

async function companyContext(client, companyId) {
  const { rows } = await client.query(
    `SELECT COALESCE(NULLIF(timezone, ''), 'America/New_York') AS timezone,
            (now() AT TIME ZONE COALESCE(NULLIF(timezone, ''), 'America/New_York'))::date::text AS company_today
       FROM companies WHERE id = $1`,
    [companyId]
  );
  if (!rows[0]) throw new PayrollAuthorityError("company_not_found", "The company workspace was not found.", 404);
  return rows[0];
}

async function requireEmployee(client, companyId, employeeId, { active = true, lock = false } = {}) {
  const { rows } = await client.query(
    `SELECT id, email, display_name, role, deleted_at
       FROM users WHERE id = $1::uuid AND company_id = $2${active ? " AND deleted_at IS NULL" : ""}${lock ? " FOR UPDATE" : ""}`,
    [employeeId, companyId]
  );
  if (!rows[0]) throw new PayrollAuthorityError("payroll_employee_not_found", "The company employee was not found.", 404);
  return rows[0];
}

async function appendPolicyAudit(client, values) {
  await client.query(
    `INSERT INTO finance_payroll_policy_audit (
       company_id, employee_id, policy_id, actor_user_id, action, reason, before_state, after_state
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [values.companyId, values.employeeId, values.policyId, values.actorUserId, values.action, values.reason,
      JSON.stringify(values.before), JSON.stringify(values.after)]
  );
}

async function loadEmployeePolicyDetail(client, companyId, employeeId, asOf) {
  const employee = await requireEmployee(client, companyId, employeeId, { active: false });
  const currentResult = await client.query(
    `SELECT * FROM finance_payroll_policies
      WHERE company_id = $1 AND employee_id = $2::uuid
        AND effective_from <= $3::date AND (effective_to IS NULL OR effective_to >= $3::date)
      ORDER BY effective_from DESC, id DESC LIMIT 2`,
    [companyId, employeeId, asOf]
  );
  const historyResult = await client.query(
    `SELECT * FROM finance_payroll_policies
      WHERE company_id = $1 AND employee_id = $2::uuid
      ORDER BY effective_from DESC, id DESC LIMIT $3`,
    [companyId, employeeId, MAX_POLICY_HISTORY + 1]
  );
  const currentRows = currentResult.rows;
  const auditResult = await client.query(
    `SELECT id, actor_user_id, action, reason, before_state, after_state, created_at
      FROM finance_payroll_policy_audit
      WHERE company_id = $1 AND employee_id = $2::uuid
      ORDER BY created_at DESC, id DESC LIMIT $3`,
    [companyId, employeeId, MAX_POLICY_AUDIT + 1]
  );
  return {
    as_of: asOf,
    employee: {
      id: String(employee.id), email: employee.email, display_name: employee.display_name || null,
      role: employee.role, active: employee.deleted_at == null
    },
    coverage_status: currentRows.length > 1 ? "overlap" : currentRows[0]?.status || "missing",
    current: currentRows.length === 1 ? policyPayload(currentRows[0]) : null,
    history: historyResult.rows.slice(0, MAX_POLICY_HISTORY).map(policyPayload),
    history_truncated: historyResult.rows.length > MAX_POLICY_HISTORY,
    audit: auditResult.rows.slice(0, MAX_POLICY_AUDIT).map((row) => ({
      id: String(row.id), actor_user_id: row.actor_user_id || null, action: row.action, reason: row.reason,
      before: row.before_state || null, after: row.after_state || null, created_at: row.created_at
    })),
    audit_truncated: auditResult.rows.length > MAX_POLICY_AUDIT
  };
}

async function loadCommissionSource(client, companyId, input) {
  if (input.source_type === "manual") {
    return { source_label: input.source_label, source_value_cents: input.eligible_revenue_cents, source_snapshot: { label: input.source_label } };
  }
  if (input.source_type === "job") {
    const { rows } = await client.query(
      `SELECT id, title, price_cents, sales_user_ids, finished_at, updated_at FROM schedule_events
        WHERE company_id = $1 AND id = $2 AND finished_at IS NOT NULL FOR SHARE`,
      [companyId, input.source_id]
    );
    if (!rows[0]) throw new PayrollAuthorityError("commission_job_not_found", "The finished commission source job was not found.", 404);
    const value = rows[0].price_cents == null ? null : dbInteger(rows[0].price_cents, "job_price_cents");
    return {
      source_label: rows[0].title,
      source_value_cents: value,
      source_snapshot: {
        title: rows[0].title, value_cents: value, finished_at: rows[0].finished_at,
        sales_user_ids: normalizedStringArray(rows[0].sales_user_ids)
      }
    };
  }
  const { rows } = await client.query(
    `SELECT q.id, q.title, q.total_cents, q.status, q.accepted_at, q.user_id, q.updated_at
       FROM quotes q
       JOIN users owner ON owner.id = q.user_id
      WHERE q.id::text = $2 AND (q.company_id = $1 OR (q.company_id IS NULL AND owner.company_id = $1))
        AND (q.status = 'accepted' OR q.accepted_at IS NOT NULL)
      FOR SHARE OF q`,
    [companyId, input.source_id]
  );
  if (!rows[0]) throw new PayrollAuthorityError("commission_quote_not_found", "The accepted commission source quote was not found.", 404);
  const value = rows[0].total_cents == null ? null : dbInteger(rows[0].total_cents, "quote_total_cents");
  return {
    source_label: rows[0].title,
    source_value_cents: value,
    source_snapshot: { title: rows[0].title, value_cents: value, status: rows[0].status, accepted_at: rows[0].accepted_at, creator_user_id: rows[0].user_id }
  };
}

async function loadApplicablePay(client, companyId, employeeId, earnedDate) {
  const { rows } = await client.query(
    `SELECT id, version, commission_tiers FROM employee_pay_structures
      WHERE company_id = $1 AND employee_id = $2::uuid
        AND effective_from <= $3::date AND (effective_to IS NULL OR effective_to >= $3::date)
      ORDER BY effective_from, id FOR SHARE`,
    [companyId, employeeId, earnedDate]
  );
  if (rows.length > 1) throw new PayrollAuthorityError("commission_pay_history_invalid", "Overlapping effective pay structures must be corrected before recording commission.", 409);
  return rows[0] || null;
}

async function loadCommissionEventForPayload(client, companyId, eventId) {
  const { rows } = await client.query(
    `SELECT ce.*, COALESCE(NULLIF(u.display_name, ''), u.email) AS employee_name, u.email AS employee_email,
            sj.id AS current_job_id, q.id AS current_quote_id,
            CASE WHEN ce.source_type = 'quote' THEN q.title ELSE sj.title END AS current_source_title,
            CASE WHEN ce.source_type = 'quote' THEN q.total_cents ELSE sj.price_cents END AS current_source_value_cents,
            sj.finished_at AS current_job_finished_at, sj.sales_user_ids AS current_sales_user_ids,
            q.status AS current_quote_status, q.accepted_at AS current_quote_accepted_at,
            target.title AS target_job_title
       FROM finance_commission_events ce
       JOIN users u ON u.id = ce.employee_id AND u.company_id = ce.company_id
       LEFT JOIN schedule_events sj ON ce.source_type = 'job' AND sj.company_id = ce.company_id AND sj.id = ce.source_id
       LEFT JOIN quotes q ON ce.source_type = 'quote' AND q.id::text = ce.source_id
         AND (q.company_id = ce.company_id OR (q.company_id IS NULL AND EXISTS (
           SELECT 1 FROM users qo WHERE qo.id = q.user_id AND qo.company_id = ce.company_id
         )))
       LEFT JOIN schedule_events target ON target.company_id = ce.company_id AND target.id = ce.job_id
      WHERE ce.company_id = $1 AND ce.id = $2::uuid`,
    [companyId, eventId]
  );
  if (!rows[0]) throw new PayrollAuthorityError("commission_event_not_found", "The reviewed commission event was not found.", 404);
  return rows[0];
}

async function loadAuthorityReport(client, companyId, range, context) {
  const policyResult = await client.query(
    `SELECT p.*, u.id AS employee_id, u.email AS employee_email, u.display_name AS employee_name,
            u.role AS employee_role, COUNT(p.id) OVER (PARTITION BY u.id) AS active_policy_count
       FROM users u
       LEFT JOIN finance_payroll_policies p ON p.company_id = u.company_id AND p.employee_id = u.id
         AND p.effective_from <= $2::date AND (p.effective_to IS NULL OR p.effective_to >= $2::date)
      WHERE u.company_id = $1 AND u.deleted_at IS NULL
      ORDER BY COALESCE(NULLIF(u.display_name, ''), u.email), u.id, p.effective_from DESC`,
    [companyId, range.end_date]
  );
  const employees = [];
  const seen = new Set();
  for (const row of policyResult.rows) {
    const employeeId = String(row.employee_id);
    if (seen.has(employeeId)) continue;
    seen.add(employeeId);
    const count = Number(row.active_policy_count || 0);
    employees.push({
      employee_id: employeeId,
      employee_email: row.employee_email,
      employee_name: row.employee_name || null,
      employee_role: row.employee_role,
      coverage_status: count > 1 ? "overlap" : row.id ? row.status : "missing",
      current: count === 1 && row.id ? policyPayload(row) : null
    });
  }
  const eventResult = await client.query(
    `SELECT ce.*, COALESCE(NULLIF(u.display_name, ''), u.email) AS employee_name, u.email AS employee_email,
            sj.id AS current_job_id, sj.title AS current_source_title,
            sj.price_cents AS current_source_value_cents, sj.finished_at AS current_job_finished_at,
            sj.sales_user_ids AS current_sales_user_ids,
            q.id AS current_quote_id, q.title AS current_quote_title, q.total_cents AS current_quote_value_cents,
            q.status AS current_quote_status, q.accepted_at AS current_quote_accepted_at,
            target.title AS target_job_title
       FROM finance_commission_events ce
       JOIN users u ON u.id = ce.employee_id AND u.company_id = ce.company_id
       LEFT JOIN schedule_events sj ON ce.source_type = 'job' AND sj.company_id = ce.company_id AND sj.id = ce.source_id
       LEFT JOIN quotes q ON ce.source_type = 'quote' AND q.id::text = ce.source_id
         AND (q.company_id = ce.company_id OR (q.company_id IS NULL AND EXISTS (
           SELECT 1 FROM users qo WHERE qo.id = q.user_id AND qo.company_id = ce.company_id
         )))
       LEFT JOIN schedule_events target ON target.company_id = ce.company_id AND target.id = ce.job_id
      WHERE ce.company_id = $1 AND ce.earned_date >= $2::date AND ce.earned_date <= $3::date
      ORDER BY ce.earned_date DESC, ce.created_at DESC, ce.id DESC LIMIT $4`,
    [companyId, range.start_date, range.end_date, MAX_COMMISSION_EVENTS + 1]
  );
  const normalizedEventRows = eventResult.rows.map((row) => ({
    ...row,
    current_source_title: row.source_type === "quote" ? row.current_quote_title : row.current_source_title,
    current_source_value_cents: row.source_type === "quote" ? row.current_quote_value_cents : row.current_source_value_cents
  }));
  const events = normalizedEventRows.slice(0, MAX_COMMISSION_EVENTS).map(commissionEventPayload);
  const aggregateResult = await client.query(
    `SELECT COUNT(*)::integer AS commission_event_count,
            COALESCE(SUM(commission_cents) FILTER (WHERE event_kind = 'earning'), 0)::bigint AS commission_earning_cents,
            COALESCE(SUM(commission_cents) FILTER (WHERE event_kind = 'adjustment'), 0)::bigint AS commission_adjustment_cents,
            COALESCE(SUM(commission_cents), 0)::bigint AS net_commission_cents
       FROM finance_commission_events
      WHERE company_id = $1 AND earned_date >= $2::date AND earned_date <= $3::date`,
    [companyId, range.start_date, range.end_date]
  );
  const aggregate = aggregateResult.rows[0];
  const candidateResult = await client.query(
    `WITH candidates AS (
       SELECT 'job'::text AS source_type, se.id::text AS source_id, se.title AS label,
              se.price_cents AS value_cents, se.finished_at AS occurred_at,
              se.sales_user_ids AS attribution_user_ids
         FROM schedule_events se
        WHERE se.company_id = $1 AND se.finished_at IS NOT NULL
          AND se.finished_at >= ($2::date::timestamp AT TIME ZONE $4)
          AND se.finished_at < (($3::date + 1)::timestamp AT TIME ZONE $4)
       UNION ALL
       SELECT 'quote'::text, q.id::text, q.title, q.total_cents, q.accepted_at,
              jsonb_build_array(q.user_id::text)
         FROM quotes q JOIN users qo ON qo.id = q.user_id
        WHERE (q.company_id = $1 OR (q.company_id IS NULL AND qo.company_id = $1))
          AND (q.status = 'accepted' OR q.accepted_at IS NOT NULL)
          AND q.accepted_at >= ($2::date::timestamp AT TIME ZONE $4)
          AND q.accepted_at < (($3::date + 1)::timestamp AT TIME ZONE $4)
     )
     SELECT * FROM candidates ORDER BY occurred_at DESC, source_type, source_id LIMIT $5`,
    [companyId, range.start_date, range.end_date, context.timezone, MAX_SOURCE_CANDIDATES + 1]
  );
  return {
    basis: "reviewed_payroll_authority_v1",
    currency: "usd",
    start_date: range.start_date,
    end_date: range.end_date,
    as_of: range.end_date,
    timezone: context.timezone,
    summary: {
      employee_count: employees.length,
      reviewed_policy_count: employees.filter((item) => item.coverage_status === "reviewed").length,
      draft_policy_count: employees.filter((item) => item.coverage_status === "draft").length,
      missing_policy_count: employees.filter((item) => item.coverage_status === "missing").length,
      overlapping_policy_count: employees.filter((item) => item.coverage_status === "overlap").length,
      commission_event_count: dbInteger(aggregate.commission_event_count, "commission_event_count"),
      commission_earning_cents: dbInteger(aggregate.commission_earning_cents, "commission_earning_cents"),
      commission_adjustment_cents: dbInteger(aggregate.commission_adjustment_cents, "commission_adjustment_cents"),
      net_commission_cents: dbInteger(aggregate.net_commission_cents, "net_commission_cents"),
      source_warning_count: events.filter((item) => !item.source_available || item.source_changed).length
    },
    employees,
    commission_events: events,
    commission_events_truncated: eventResult.rows.length > MAX_COMMISSION_EVENTS,
    source_candidates: candidateResult.rows.slice(0, MAX_SOURCE_CANDIDATES).map((row) => ({
      id: `${row.source_type}:${row.source_id}`,
      source_type: row.source_type,
      source_id: row.source_id,
      label: row.label,
      value_cents: row.value_cents == null ? null : dbInteger(row.value_cents, "candidate_value_cents"),
      occurred_at: row.occurred_at,
      attribution_user_ids: normalizedStringArray(row.attribution_user_ids)
    })),
    source_candidates_truncated: candidateResult.rows.length > MAX_SOURCE_CANDIDATES,
    warnings: [
      "Payroll policies and commission events are reviewed configuration/evidence only. This report does not calculate overtime, withholding, employer taxes, benefits, workers' compensation, paychecks, cash P&L, or fully loaded margins.",
      "Job and quote attribution are suggestions only. Commission authority exists only in the exact append-only earning and adjustment rows shown here.",
      "Have a qualified payroll professional review effective jurisdiction, classification, overtime, regular-rate, tax, benefit, workers' compensation, and burden inputs before marking policies reviewed or using a later payroll evaluator.",
      ...(eventResult.rows.length > MAX_COMMISSION_EVENTS
        ? ["Commission totals cover the full period, but source-warning count covers only the displayed events. Choose a shorter period to inspect every source snapshot."]
        : [])
    ]
  };
}

function sendAuthorityError(res, error, fallback) {
  if (error instanceof PayrollAuthorityError || error?.statusCode) {
    return res.status(error.statusCode || 400).json({
      error: error.code || fallback,
      message: error.message,
      current_version: error.current_version
    });
  }
  console.error("[finance-payroll-authority]", fallback, { code: error?.code, message: error?.message });
  return res.status(500).json({ error: fallback, message: "Payroll authority request failed." });
}

export function installFinancePayrollAuthorityRoutes({ app, pool, authRequired, requireFinanceAccess }) {
  app.get("/api/finance/accounting/payroll-authority", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Payroll authority requires a company workspace." });
    try {
      const context = await companyContext(pool, req.companyId);
      const range = parsePayrollAuthorityRange(req.query.start_date, req.query.end_date, { companyToday: context.company_today });
      res.json(await loadAuthorityReport(pool, req.companyId, range, context));
    } catch (error) {
      sendAuthorityError(res, error, "payroll_authority_load_failed");
    }
  });

  app.get("/api/finance/accounting/payroll-authority/employees/:employeeId", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Payroll authority requires a company workspace." });
    try {
      const context = await companyContext(pool, req.companyId);
      const asOf = dateOnly(req.query.as_of || context.company_today, "as_of");
      res.json({ timezone: context.timezone, ...(await loadEmployeePolicyDetail(pool, req.companyId, req.params.employeeId, asOf)) });
    } catch (error) {
      sendAuthorityError(res, error, "payroll_policy_load_failed");
    }
  });

  app.put("/api/finance/accounting/payroll-authority/employees/:employeeId/policy", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Payroll authority requires a company workspace." });
    let client;
    try {
      client = await pool.connect();
      const update = normalizePayrollPolicyInput(req.body);
      await client.query("BEGIN");
      await requireEmployee(client, req.companyId, req.params.employeeId, { lock: true });
      const existing = await client.query(
        `SELECT * FROM finance_payroll_policies
          WHERE company_id = $1 AND employee_id = $2::uuid ORDER BY effective_from FOR UPDATE`,
        [req.companyId, req.params.employeeId]
      );
      const plan = planPayrollPolicyUpdate({ rows: existing.rows, update });
      if (plan.mode === "replay") {
        await client.query("COMMIT");
        const context = await companyContext(pool, req.companyId);
        return res.json({ replayed: true, timezone: context.timezone, ...(await loadEmployeePolicyDetail(pool, req.companyId, req.params.employeeId, update.effective_from)) });
      }
      let current;
      if (plan.mode === "correct") {
        const before = policyAuditSnapshot(plan.target);
        current = (await client.query(
          `UPDATE finance_payroll_policies SET
             status=$4, jurisdiction_code=$5, exemption_status=$6, overtime_method=$7,
             weekly_threshold_seconds=$8, weekly_multiplier_basis_points=$9, state_overtime_status=$10,
             daily_overtime_rules=$11, burden_status=$12, burden_rules=$13, special_rule_notes=$14,
             notes=$15, version=version+1, updated_by=$16, updated_at=now()
           WHERE company_id=$1 AND employee_id=$2::uuid AND id=$3 RETURNING *`,
          [req.companyId, req.params.employeeId, plan.target.id, update.status, update.jurisdiction_code,
            update.exemption_status, update.overtime_method, update.weekly_threshold_seconds,
            update.weekly_multiplier_basis_points, update.state_overtime_status,
            JSON.stringify(update.daily_overtime_rules), update.burden_status, JSON.stringify(update.burden_rules),
            update.special_rule_notes, update.notes, req.userId]
        )).rows[0];
        await appendPolicyAudit(client, {
          companyId: req.companyId, employeeId: req.params.employeeId, policyId: current.id,
          actorUserId: req.userId, action: "payroll_policy_corrected", reason: update.reason,
          before, after: policyAuditSnapshot(current)
        });
      } else {
        if (plan.predecessor) {
          const before = policyAuditSnapshot(plan.predecessor);
          const closed = (await client.query(
            `UPDATE finance_payroll_policies
                SET effective_to=$4::date, version=version+1, updated_by=$5, updated_at=now()
              WHERE company_id=$1 AND employee_id=$2::uuid AND id=$3 RETURNING *`,
            [req.companyId, req.params.employeeId, plan.predecessor.id, addDays(update.effective_from, -1), req.userId]
          )).rows[0];
          await appendPolicyAudit(client, {
            companyId: req.companyId, employeeId: req.params.employeeId, policyId: closed.id,
            actorUserId: req.userId, action: "payroll_policy_closed", reason: update.reason,
            before, after: policyAuditSnapshot(closed)
          });
        }
        current = (await client.query(
          `INSERT INTO finance_payroll_policies (
             company_id, employee_id, effective_from, effective_to, status, jurisdiction_code,
             exemption_status, overtime_method, weekly_threshold_seconds, weekly_multiplier_basis_points,
             state_overtime_status, daily_overtime_rules, burden_status, burden_rules,
             special_rule_notes, notes, created_by, updated_by
           ) VALUES ($1,$2,$3::date,$4::date,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$17)
           RETURNING *`,
          [req.companyId, req.params.employeeId, plan.effective_from, plan.effective_to, update.status,
            update.jurisdiction_code, update.exemption_status, update.overtime_method,
            update.weekly_threshold_seconds, update.weekly_multiplier_basis_points,
            update.state_overtime_status, JSON.stringify(update.daily_overtime_rules), update.burden_status,
            JSON.stringify(update.burden_rules), update.special_rule_notes, update.notes, req.userId]
        )).rows[0];
        await appendPolicyAudit(client, {
          companyId: req.companyId, employeeId: req.params.employeeId, policyId: current.id,
          actorUserId: req.userId, action: "payroll_policy_created", reason: update.reason,
          before: null, after: policyAuditSnapshot(current)
        });
      }
      await client.query("COMMIT");
      const context = await companyContext(pool, req.companyId);
      res.json({ replayed: false, timezone: context.timezone, ...(await loadEmployeePolicyDetail(pool, req.companyId, req.params.employeeId, update.effective_from)) });
    } catch (error) {
      await client?.query("ROLLBACK").catch(() => {});
      sendAuthorityError(res, error, "payroll_policy_update_failed");
    } finally {
      client?.release();
    }
  });

  app.post("/api/finance/accounting/payroll-authority/commission-events", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Payroll authority requires a company workspace." });
    let client;
    try {
      client = await pool.connect();
      const input = normalizeCommissionEventInput(req.body);
      const requestFingerprint = commissionEventRequestFingerprint(input);
      await client.query("BEGIN");
      const context = await companyContext(client, req.companyId);
      if (input.earned_date > context.company_today) {
        throw new PayrollAuthorityError("commission_future_date", "Commission evidence cannot be recorded for a future company date.");
      }
      await client.query(`SELECT pg_advisory_xact_lock(hashtext($1::text))`, [`${req.companyId}|commission-request|${input.client_request_id}`]);
      const replay = (await client.query(
        `SELECT ce.*, COALESCE(NULLIF(u.display_name, ''), u.email) AS employee_name, u.email AS employee_email,
                sj.id AS current_job_id, q.id AS current_quote_id,
                CASE WHEN ce.source_type='quote' THEN q.title ELSE sj.title END AS current_source_title,
                CASE WHEN ce.source_type='quote' THEN q.total_cents ELSE sj.price_cents END AS current_source_value_cents,
                sj.finished_at AS current_job_finished_at, sj.sales_user_ids AS current_sales_user_ids,
                q.status AS current_quote_status, q.accepted_at AS current_quote_accepted_at,
                target.title AS target_job_title
           FROM finance_commission_events ce JOIN users u ON u.id=ce.employee_id
           LEFT JOIN schedule_events sj ON ce.source_type='job' AND sj.company_id=ce.company_id AND sj.id=ce.source_id
           LEFT JOIN quotes q ON ce.source_type='quote' AND q.id::text=ce.source_id
             AND (q.company_id=ce.company_id OR (q.company_id IS NULL AND EXISTS (
               SELECT 1 FROM users qo WHERE qo.id=q.user_id AND qo.company_id=ce.company_id
             )))
           LEFT JOIN schedule_events target ON target.company_id=ce.company_id AND target.id=ce.job_id
          WHERE ce.company_id=$1 AND ce.client_request_id=$2::uuid FOR UPDATE OF ce`,
        [req.companyId, input.client_request_id]
      )).rows[0];
      if (replay) {
        if (replay.request_fingerprint !== requestFingerprint) {
          throw new PayrollAuthorityError("commission_idempotency_conflict", "This retry key was already used for different commission content.", 409);
        }
        await client.query("COMMIT");
        return res.json({ replayed: true, event: commissionEventPayload(replay) });
      }

      let employeeId = input.employee_id;
      let root = null;
      let source;
      let jobId = input.job_id;
      let treatment = input.regular_rate_treatment;
      let treatmentBasis = input.regular_rate_basis;
      let pay = null;
      if (input.event_kind === "adjustment") {
        root = (await client.query(
          `SELECT * FROM finance_commission_events
            WHERE company_id=$1 AND id=$2::uuid AND event_kind='earning' FOR UPDATE`,
          [req.companyId, input.root_event_id]
        )).rows[0];
        if (!root) throw new PayrollAuthorityError("commission_root_not_found", "The reviewed commission earning was not found.", 404);
        if (String(root.employee_id) !== input.employee_id) throw new PayrollAuthorityError("commission_employee_mismatch", "A correction must use the root earning's employee.", 409);
        if (input.earned_date < dateOnly(root.earned_date, "root_earned_date")) {
          throw new PayrollAuthorityError("commission_adjustment_date_invalid", "A correction cannot be dated before its original earning.");
        }
        employeeId = String(root.employee_id);
        const prior = await client.query(
          `SELECT commission_cents FROM finance_commission_events
            WHERE company_id=$1 AND root_event_id=$2::uuid ORDER BY created_at FOR UPDATE`,
          [req.companyId, root.id]
        );
        validateCommissionCorrectionFloor(root.commission_cents, input.commission_cents, prior.rows.map((row) => row.commission_cents));
        source = {
          source_label: root.source_label,
          source_value_cents: root.source_value_cents,
          source_snapshot: root.source_snapshot || {}
        };
        jobId = root.job_id || null;
        treatment = root.regular_rate_treatment;
        treatmentBasis = root.regular_rate_basis;
        pay = root.pay_structure_id ? {
          id: root.pay_structure_id,
          version: root.pay_structure_version,
          commission_tiers: root.commission_tiers || []
        } : null;
      } else {
        await requireEmployee(client, req.companyId, employeeId, { lock: true });
        source = await loadCommissionSource(client, req.companyId, input);
        pay = await loadApplicablePay(client, req.companyId, employeeId, input.earned_date);
      }
      if (jobId) {
        const target = await client.query(`SELECT id FROM schedule_events WHERE company_id=$1 AND id=$2 FOR SHARE`, [req.companyId, jobId]);
        if (!target.rowCount) throw new PayrollAuthorityError("commission_target_job_not_found", "The commission target job was not found.", 404);
      }
      const inserted = (await client.query(
        `INSERT INTO finance_commission_events (
           company_id, employee_id, event_kind, root_event_id, earned_date, commission_cents,
           regular_rate_treatment, regular_rate_basis, source_type, source_id, source_label,
           source_value_cents, eligible_revenue_cents, source_snapshot, job_id,
           pay_structure_id, pay_structure_version, commission_tiers, client_request_id,
           request_fingerprint, reason, notes, created_by
         ) VALUES ($1,$2,$3,$4,$5::date,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
         RETURNING *`,
        [req.companyId, employeeId, input.event_kind, root?.id || null, input.earned_date,
          input.commission_cents, treatment, treatmentBasis,
          root?.source_type || input.source_type, root?.source_id || input.source_id,
          source.source_label, source.source_value_cents, root ? root.eligible_revenue_cents : input.eligible_revenue_cents,
          JSON.stringify(source.source_snapshot), jobId, pay?.id || null, pay?.version || null,
          JSON.stringify(Array.isArray(pay?.commission_tiers) ? pay.commission_tiers : []),
          input.client_request_id, requestFingerprint, input.reason, input.notes, req.userId]
      )).rows[0];
      await client.query("COMMIT");
      res.status(201).json({
        replayed: false,
        event: commissionEventPayload(await loadCommissionEventForPayload(pool, req.companyId, inserted.id))
      });
    } catch (error) {
      await client?.query("ROLLBACK").catch(() => {});
      sendAuthorityError(res, error, "commission_event_create_failed");
    } finally {
      client?.release();
    }
  });
}
