import { createHash } from "node:crypto";
import {
  allocateExactCents,
  loadCompanyContext,
  parsePayrollCostRange,
  payrollCostReport
} from "./finance-payroll-costs.js";

const EVALUATION_POLICY_VERSION = "supported_loaded_labor_v1";
const MAX_COMMISSION_ALLOCATION_LINES = 50;
const MAX_EVALUATION_COMMISSION_EVENTS = 500;
const MAX_EVALUATION_POLICIES = 2_000;
const MAX_EVALUATION_TARGETS = 2_000;

export class PayrollEvaluationError extends Error {
  constructor(code, message, statusCode = 400, details = {}) {
    super(message);
    this.name = "PayrollEvaluationError";
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
    throw new PayrollEvaluationError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return parsed;
}

function dbInteger(value, field) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(parsed)) {
    throw new PayrollEvaluationError("payroll_evaluation_source_inexact", `${field.replaceAll("_", " ")} exceeds the exact supported range.`, 500);
  }
  return parsed;
}

function dateOnly(value, field = "date") {
  const raw = value instanceof Date ? value.toISOString().slice(0, 10) : cleanString(value, 20);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    throw new PayrollEvaluationError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  const [year, month, day] = raw.split("-").map(Number);
  const parsed = new Date(Date.UTC(year, month - 1, day));
  if (parsed.getUTCFullYear() !== year || parsed.getUTCMonth() !== month - 1 || parsed.getUTCDate() !== day) {
    throw new PayrollEvaluationError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return raw;
}

function addDays(value, days) {
  const [year, month, day] = value.split("-").map(Number);
  return new Date(Date.UTC(year, month - 1, day + days)).toISOString().slice(0, 10);
}

function dayOfWeek(value) {
  return new Date(`${value}T00:00:00.000Z`).getUTCDay();
}

export function payrollWorkweekStart(workDateValue, weekStartValue) {
  const workDate = dateOnly(workDateValue, "work_date");
  const weekStart = exactInteger(Number(weekStartValue), "week_start", { minimum: 0, maximum: 6 });
  return addDays(workDate, -((dayOfWeek(workDate) - weekStart + 7) % 7));
}

function companyDate(value, timezone) {
  const parsed = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(parsed.getTime())) throw new PayrollEvaluationError("payroll_evaluation_time_invalid", "Payroll source time is invalid.", 409);
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: timezone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).formatToParts(parsed);
  const lookup = Object.fromEntries(parts.map((part) => [part.type, part.value]));
  return `${lookup.year}-${lookup.month}-${lookup.day}`;
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
  }
  return value;
}

export function payrollEvaluationFingerprint(value) {
  return createHash("sha256").update(JSON.stringify(stableValue(value))).digest("hex");
}

function roundRatio(numerator, denominator) {
  const top = BigInt(numerator);
  const bottom = BigInt(denominator);
  if (top < 0n || bottom <= 0n) {
    throw new PayrollEvaluationError("payroll_evaluation_math_invalid", "Supported payroll math is invalid.", 500);
  }
  const rounded = (top + (bottom / 2n)) / bottom;
  const result = Number(rounded);
  if (!Number.isSafeInteger(result)) {
    throw new PayrollEvaluationError("payroll_evaluation_math_inexact", "Supported payroll exceeds the exact range.", 500);
  }
  return result;
}

function sameJSON(left, right) {
  return JSON.stringify(stableValue(left)) === JSON.stringify(stableValue(right));
}

function blocker(code, message, count = 1) {
  return { code, message, count };
}

function consolidatedBlockers(items) {
  const values = new Map();
  for (const item of items) {
    const key = `${item.code}|${item.message}`;
    const current = values.get(key);
    if (current) current.count += item.count;
    else values.set(key, { ...item });
  }
  return [...values.values()].sort((left, right) => left.code.localeCompare(right.code) || left.message.localeCompare(right.message));
}

export function parsePayrollEvaluationRange(startValue, endValue, { companyToday = null, weekStart = 1 } = {}) {
  const range = parsePayrollCostRange(startValue, endValue, { companyToday });
  const normalizedWeekStart = exactInteger(Number(weekStart), "week_start", { minimum: 0, maximum: 6 });
  const rangeStartWeek = payrollWorkweekStart(range.start_date, normalizedWeekStart);
  const rangeEndWeek = payrollWorkweekStart(range.end_date, normalizedWeekStart);
  const exactStart = range.start_date === rangeStartWeek;
  const exactEnd = range.end_date === addDays(rangeEndWeek, 6);
  let suggestedStart = exactStart ? range.start_date : addDays(rangeStartWeek, 7);
  let suggestedEnd = exactEnd ? range.end_date : addDays(rangeEndWeek, -1);
  if (suggestedStart > suggestedEnd) {
    suggestedStart = rangeEndWeek;
    suggestedEnd = addDays(rangeEndWeek, 6);
    if (companyToday && suggestedEnd > dateOnly(companyToday, "company_today")) {
      suggestedStart = addDays(suggestedStart, -7);
      suggestedEnd = addDays(suggestedEnd, -7);
    }
  }
  return {
    ...range,
    week_start: normalizedWeekStart,
    full_workweeks: exactStart && exactEnd,
    suggested_start_date: suggestedStart,
    suggested_end_date: suggestedEnd
  };
}

function normalizedAllocationLines(lines) {
  return [...lines].map((line) => ({
    workweek_start_date: dateOnly(line.workweek_start_date, "workweek_start_date"),
    commission_cents: exactInteger(line.commission_cents, "commission_cents")
  })).sort((left, right) => left.workweek_start_date.localeCompare(right.workweek_start_date));
}

export function normalizeCommissionAllocationInput({ body = {}, event, rootWorkweeks = [], weekStart = 1, companyToday }) {
  if (!event) throw new PayrollEvaluationError("commission_event_not_found", "The commission event was not found.", 404);
  const expectedVersion = exactInteger(body.expected_version, "expected_version", { minimum: 0 });
  const reason = cleanString(body.reason, 500);
  if (!reason) throw new PayrollEvaluationError("commission_allocation_reason_required", "Add a reason for this commission allocation change.");
  const sourceCents = exactInteger(Number(event.commission_cents), "source_commission_cents");
  const sourceKind = cleanString(event.event_kind, 20);
  const rawLines = body.allocations == null ? [] : body.allocations;
  if (!Array.isArray(rawLines) || rawLines.length > MAX_COMMISSION_ALLOCATION_LINES) {
    throw new PayrollEvaluationError("commission_allocation_lines_invalid", `Use at most ${MAX_COMMISSION_ALLOCATION_LINES} commission workweeks.`);
  }
  if (sourceCents !== 0 && rawLines.length === 0 && body.action !== "clear") {
    throw new PayrollEvaluationError("commission_allocation_required", "Allocate every nonzero commission cent or explicitly clear the review.");
  }
  const lines = normalizedAllocationLines(rawLines);
  const seen = new Set();
  const allowedRootWeeks = new Set(rootWorkweeks.map((value) => dateOnly(value, "root_workweek_start_date")));
  for (const line of lines) {
    if (seen.has(line.workweek_start_date)) {
      throw new PayrollEvaluationError("commission_allocation_duplicate_week", "Each commission workweek may appear once.");
    }
    seen.add(line.workweek_start_date);
    if (payrollWorkweekStart(line.workweek_start_date, weekStart) !== line.workweek_start_date) {
      throw new PayrollEvaluationError("commission_allocation_week_invalid", "Every allocation date must be the first company workweek date.");
    }
    if (companyToday && line.workweek_start_date > payrollWorkweekStart(companyToday, weekStart)) {
      throw new PayrollEvaluationError("commission_allocation_future_week", "Commission cannot be allocated to a future company workweek.");
    }
    if (sourceKind === "earning" && line.commission_cents < 0) {
      throw new PayrollEvaluationError("commission_allocation_sign_invalid", "Commission earning allocation cents cannot be negative.");
    }
    if (sourceKind === "adjustment" && sourceCents !== 0 && Math.sign(line.commission_cents) !== Math.sign(sourceCents)) {
      throw new PayrollEvaluationError("commission_allocation_sign_invalid", "Correction allocation cents must retain the correction sign.");
    }
    if (sourceKind === "adjustment" && !allowedRootWeeks.has(line.workweek_start_date)) {
      throw new PayrollEvaluationError("commission_allocation_root_week_invalid", "A correction may use only workweeks reviewed on its root earning.", 409);
    }
  }
  const total = lines.reduce((sum, line) => sum + line.commission_cents, 0);
  if (!Number.isSafeInteger(total) || total !== sourceCents) {
    throw new PayrollEvaluationError("commission_allocation_reconciliation_failed", "Commission workweek cents must equal the immutable event cents.");
  }
  return { expected_version: expectedVersion, reason, lines };
}

export function planCommissionAllocationUpdate({ currentHeader = null, currentLines = [], input }) {
  const currentVersion = currentHeader ? exactInteger(Number(currentHeader.version), "version", { minimum: 1 }) : 0;
  if (input.expected_version !== currentVersion) {
    throw new PayrollEvaluationError(
      "commission_allocation_stale",
      "This commission allocation changed after it was loaded. Refresh before saving again.",
      409,
      { current_version: currentVersion }
    );
  }
  const normalizedCurrent = normalizedAllocationLines(currentLines);
  if (input.lines.length === 0) {
    if (!currentHeader || currentHeader.status === "cleared") return { mode: "replay", action: "commission_allocation_cleared", current_version: currentVersion };
    return { mode: "clear", action: "commission_allocation_cleared", current_version: currentVersion };
  }
  if (currentHeader?.status === "reviewed" && sameJSON(normalizedCurrent, input.lines)) {
    return { mode: "replay", action: "commission_allocation_reviewed", current_version: currentVersion };
  }
  return {
    mode: currentHeader ? "replace" : "create",
    action: currentHeader ? "commission_allocation_revised" : "commission_allocation_reviewed",
    current_version: currentVersion
  };
}

function policyFacts(row) {
  return {
    id: String(row.id),
    employee_id: String(row.employee_id),
    effective_from: dateOnly(row.effective_from, "policy_effective_from"),
    effective_to: row.effective_to == null ? null : dateOnly(row.effective_to, "policy_effective_to"),
    status: row.status,
    jurisdiction_code: row.jurisdiction_code,
    exemption_status: row.exemption_status,
    overtime_method: row.overtime_method,
    weekly_threshold_seconds: row.weekly_threshold_seconds == null ? null : exactInteger(Number(row.weekly_threshold_seconds), "weekly_threshold_seconds", { minimum: 1 }),
    weekly_multiplier_basis_points: row.weekly_multiplier_basis_points == null ? null : exactInteger(Number(row.weekly_multiplier_basis_points), "weekly_multiplier_basis_points", { minimum: 10_000 }),
    state_overtime_status: row.state_overtime_status,
    overtime_combination_method: row.overtime_combination_method || "undetermined",
    special_rule_notes: cleanString(row.special_rule_notes, 1_000) || null,
    daily_overtime_rules: Array.isArray(row.daily_overtime_rules) ? row.daily_overtime_rules.map((rule) => ({
      id: cleanString(rule.id, 80),
      threshold_seconds: exactInteger(Number(rule.threshold_seconds), "daily_threshold_seconds", { minimum: 1, maximum: 86_400 }),
      multiplier_basis_points: exactInteger(Number(rule.multiplier_basis_points), "daily_multiplier_basis_points", { minimum: 10_000, maximum: 30_000 })
    })).sort((left, right) => left.threshold_seconds - right.threshold_seconds || left.id.localeCompare(right.id)) : [],
    burden_status: row.burden_status,
    burden_rules: Array.isArray(row.burden_rules) ? row.burden_rules.map((rule) => ({
      id: cleanString(rule.id, 80),
      label: cleanString(rule.label, 120),
      category: rule.category,
      basis: rule.basis,
      rate_basis_points: rule.rate_basis_points == null ? null : exactInteger(Number(rule.rate_basis_points), "burden_rate_basis_points", { minimum: 0 }),
      amount_cents: rule.amount_cents == null ? null : exactInteger(Number(rule.amount_cents), "burden_amount_cents", { minimum: 0 }),
      annual_wage_cap_cents: rule.annual_wage_cap_cents == null ? null : exactInteger(Number(rule.annual_wage_cap_cents), "burden_annual_wage_cap_cents", { minimum: 0 })
    })) : [],
    version: exactInteger(Number(row.version), "policy_version", { minimum: 1 })
  };
}

function policyForWorkweek(policies, employeeId, weekStartDate) {
  const weekEndDate = addDays(weekStartDate, 6);
  const complete = policies.filter((policy) => policy.employee_id === employeeId
    && policy.effective_from <= weekStartDate
    && (policy.effective_to == null || policy.effective_to >= weekEndDate));
  const overlapping = policies.filter((policy) => policy.employee_id === employeeId
    && policy.effective_from <= weekEndDate
    && (policy.effective_to == null || policy.effective_to >= weekStartDate));
  return { complete, overlapping };
}

function targetKey(targetKind, jobId = null) {
  return targetKind === "job" && jobId ? `job:${jobId}` : targetKind;
}

function createTarget(targetKind, jobId = null, jobTitle = null) {
  return {
    key: targetKey(targetKind, jobId),
    target_kind: targetKind,
    job_id: jobId,
    job_title: jobTitle,
    source_seconds: 0,
    base_compensation_cents: 0,
    commission_cents: 0,
    overtime_premium_cents: 0,
    employer_burden_cents: 0,
    supported_gross_compensation_cents: 0,
    supported_loaded_labor_cents: 0
  };
}

function addTarget(targets, values) {
  const key = targetKey(values.target_kind, values.job_id);
  const target = targets.get(key) || createTarget(values.target_kind, values.job_id || null, values.job_title || null);
  target.source_seconds += values.source_seconds || 0;
  target.base_compensation_cents += values.base_compensation_cents || 0;
  target.commission_cents += values.commission_cents || 0;
  target.overtime_premium_cents += values.overtime_premium_cents || 0;
  target.employer_burden_cents += values.employer_burden_cents || 0;
  targets.set(key, target);
}

function overtimeSegments(lines, policy, timezone) {
  const ordered = [...lines].sort((left, right) => String(left.source_start_at).localeCompare(String(right.source_start_at)) || left.time_entry_id.localeCompare(right.time_entry_id));
  const daySeconds = new Map();
  let weekSeconds = 0;
  const segments = [];
  for (const line of ordered) {
    const sourceSeconds = exactInteger(Number(line.source_work_seconds), "source_work_seconds", { minimum: 1 });
    const workDate = dateOnly(line.work_date, "work_date");
    if (policy.state_overtime_status === "configured"
        && (companyDate(line.source_start_at, timezone) !== workDate || companyDate(line.source_end_at, timezone) !== workDate)) {
      return { segments: [], cross_workday_entry_count: 1 };
    }
    const dayBefore = daySeconds.get(workDate) || 0;
    const boundaries = new Set([0, sourceSeconds]);
    if (policy.weekly_threshold_seconds > weekSeconds && policy.weekly_threshold_seconds < weekSeconds + sourceSeconds) {
      boundaries.add(policy.weekly_threshold_seconds - weekSeconds);
    }
    if (policy.state_overtime_status === "configured") {
      for (const rule of policy.daily_overtime_rules) {
        if (rule.threshold_seconds > dayBefore && rule.threshold_seconds < dayBefore + sourceSeconds) {
          boundaries.add(rule.threshold_seconds - dayBefore);
        }
      }
    }
    const points = [...boundaries].sort((left, right) => left - right);
    for (let index = 0; index < points.length - 1; index += 1) {
      const startOffset = points[index];
      const seconds = points[index + 1] - startOffset;
      const weeklyMultiplier = policy.exemption_status === "nonexempt"
        && weekSeconds + startOffset >= policy.weekly_threshold_seconds
        ? policy.weekly_multiplier_basis_points
        : 10_000;
      let dailyMultiplier = 10_000;
      if (policy.state_overtime_status === "configured") {
        for (const rule of policy.daily_overtime_rules) {
          if (dayBefore + startOffset >= rule.threshold_seconds) dailyMultiplier = Math.max(dailyMultiplier, rule.multiplier_basis_points);
        }
      }
      const multiplier = policy.exemption_status === "exempt"
        ? 10_000
        : policy.overtime_combination_method === "highest_applicable_multiplier"
          ? Math.max(weeklyMultiplier, dailyMultiplier)
          : weeklyMultiplier;
      segments.push({ time_entry_id: line.time_entry_id, seconds, multiplier_basis_points: multiplier });
    }
    weekSeconds += sourceSeconds;
    daySeconds.set(workDate, dayBefore + sourceSeconds);
  }
  return { segments, cross_workday_entry_count: 0 };
}

function workweekTargetTotals(lines, commissionItems, premiumByLine) {
  const targets = new Map();
  for (const line of lines) {
    for (const allocation of line.allocations || []) {
      addTarget(targets, {
        target_kind: allocation.target_kind,
        job_id: allocation.job_id || null,
        job_title: allocation.job_title || null,
        source_seconds: exactInteger(Number(allocation.source_seconds), "allocation_source_seconds", { minimum: 1 }),
        base_compensation_cents: exactInteger(Number(allocation.base_pay_cents), "allocation_base_pay_cents", { minimum: 0 })
      });
    }
    const premiumCents = premiumByLine.get(line.time_entry_id) || 0;
    if (premiumCents > 0) {
      const allocations = Array.isArray(line.allocations) ? line.allocations : [];
      const target = allocations.length === 1 ? allocations[0] : null;
      addTarget(targets, {
        target_kind: target?.target_kind || "unallocated",
        job_id: target?.job_id || null,
        job_title: target?.job_title || null,
        overtime_premium_cents: premiumCents
      });
    }
  }
  for (const item of commissionItems) {
    addTarget(targets, {
      target_kind: item.job_id ? "job" : "unallocated",
      job_id: item.job_id || null,
      job_title: item.job_title || null,
      commission_cents: item.allocated_cents
    });
  }
  return targets;
}

function allocateBurdenComponent(targets, amountCents, basis) {
  if (amountCents <= 0) return;
  const targetValues = [...targets.values()];
  const weights = targetValues.map((target) => ({
    key: target.key,
    weight: basis === "percent_of_wages"
      ? Math.max(0, target.base_compensation_cents + target.commission_cents + target.overtime_premium_cents)
      : target.source_seconds
  }));
  if (weights.reduce((sum, target) => sum + target.weight, 0) > 0) {
    const shares = new Map(allocateExactCents(amountCents, weights).map((share) => [share.key, share.cents]));
    for (const target of targetValues) target.employer_burden_cents += shares.get(target.key) || 0;
    return;
  }
  const unallocated = targets.get("unallocated") || createTarget("unallocated");
  unallocated.employer_burden_cents += amountCents;
  targets.set("unallocated", unallocated);
}

function evaluateWorkweek({ employeeId, employeeName, weekStartDate, lines, commissionItems, policy, timezone, blockers }) {
  const workSeconds = lines.reduce((sum, line) => sum + exactInteger(Number(line.source_work_seconds), "source_work_seconds", { minimum: 1 }), 0);
  const baseCents = lines.reduce((sum, line) => sum + exactInteger(Number(line.base_pay_cents), "base_pay_cents", { minimum: 0 }), 0);
  const includedCommissionCents = commissionItems.filter((item) => item.regular_rate_treatment === "included").reduce((sum, item) => sum + item.allocated_cents, 0);
  const excludedCommissionCents = commissionItems.filter((item) => item.regular_rate_treatment === "excluded").reduce((sum, item) => sum + item.allocated_cents, 0);
  const commissionCents = includedCommissionCents + excludedCommissionCents;
  const remunerationCents = baseCents + includedCommissionCents;
  if (!Number.isSafeInteger(remunerationCents) || remunerationCents < 0) {
    blockers.push(blocker("payroll_evaluation_regular_rate_negative", "Included remuneration cannot become negative in a supported workweek."));
  }
  if (policy.overtime_method === "manual_premium" || policy.state_overtime_status === "manual"
      || policy.overtime_combination_method === "manual" || policy.overtime_combination_method === "undetermined") {
    blockers.push(blocker("payroll_evaluation_manual_overtime", "Manual or undetermined overtime rules must be resolved outside the automatic evaluator."));
  }
  if (policy.exemption_status === "nonexempt" && policy.overtime_method !== "weekly_regular_rate") {
    blockers.push(blocker("payroll_evaluation_overtime_method_unsupported", "This nonexempt overtime method is not supported by the exact evaluator."));
  }
  if (policy.special_rule_notes) {
    blockers.push(blocker("payroll_evaluation_special_rule_unsupported", "A policy with special-rule notes requires manual payroll review before automatic evaluation."));
  }
  if (policy.exemption_status === "nonexempt" && commissionCents !== 0 && workSeconds === 0) {
    blockers.push(blocker("payroll_evaluation_regular_rate_hours_required", "Nonexempt commission requires exact work hours in its allocated workweek."));
  }
  const segmented = overtimeSegments(lines, policy, timezone);
  if (segmented.cross_workday_entry_count) {
    blockers.push(blocker("payroll_evaluation_daily_cross_workday", "Daily overtime cannot be evaluated while an entry spans company workdays without exact split evidence.", segmented.cross_workday_entry_count));
  }
  const premiumByLine = new Map();
  let overtimeSeconds = 0;
  let overtimePremiumCents = 0;
  if (remunerationCents >= 0 && workSeconds > 0 && segmented.cross_workday_entry_count === 0) {
    const byMultiplier = new Map();
    for (const segment of segmented.segments) {
      if (segment.multiplier_basis_points <= 10_000) continue;
      overtimeSeconds += segment.seconds;
      const list = byMultiplier.get(segment.multiplier_basis_points) || [];
      list.push(segment);
      byMultiplier.set(segment.multiplier_basis_points, list);
    }
    for (const [multiplier, segments] of byMultiplier) {
      const seconds = segments.reduce((sum, segment) => sum + segment.seconds, 0);
      const bucketCents = roundRatio(
        BigInt(remunerationCents) * BigInt(multiplier - 10_000) * BigInt(seconds),
        BigInt(workSeconds) * 10_000n
      );
      overtimePremiumCents += bucketCents;
      if (bucketCents > 0) {
        const byEntry = new Map();
        for (const segment of segments) byEntry.set(segment.time_entry_id, (byEntry.get(segment.time_entry_id) || 0) + segment.seconds);
        const shares = allocateExactCents(bucketCents, [...byEntry].map(([key, weight]) => ({ key, weight })));
        for (const share of shares) premiumByLine.set(share.key, (premiumByLine.get(share.key) || 0) + share.cents);
      }
    }
  }
  const grossCents = baseCents + commissionCents + overtimePremiumCents;
  if (!Number.isSafeInteger(grossCents) || grossCents < 0) {
    blockers.push(blocker("payroll_evaluation_gross_negative", "Supported gross compensation cannot become negative in a workweek."));
  }
  const targets = workweekTargetTotals(lines, commissionItems, premiumByLine);
  const targetValues = [...targets.values()];
  const targetGrossCents = targetValues.reduce((sum, target) => sum + target.base_compensation_cents + target.commission_cents + target.overtime_premium_cents, 0);
  if (targetGrossCents !== grossCents) {
    throw new PayrollEvaluationError("payroll_evaluation_target_gross_mismatch", "Target gross compensation did not reconcile.", 500);
  }
  const burdenComponents = [];
  let employerBurdenCents = 0;
  if (policy.burden_status === "configured") {
    for (const rule of policy.burden_rules) {
      if (rule.annual_wage_cap_cents != null) {
        blockers.push(blocker("payroll_evaluation_ytd_evidence_required", `${rule.label} requires exact prior year-to-date wage-basis evidence before its annual cap can be evaluated.`));
        continue;
      }
      let amountCents;
      if (rule.basis === "percent_of_wages") {
        amountCents = roundRatio(BigInt(Math.max(0, grossCents)) * BigInt(rule.rate_basis_points), 10_000n);
      } else if (rule.basis === "fixed_per_hour") {
        amountCents = roundRatio(BigInt(rule.amount_cents) * BigInt(workSeconds), 3_600n);
      } else if (rule.basis === "fixed_per_workweek") {
        amountCents = workSeconds > 0 ? rule.amount_cents : 0;
      } else {
        blockers.push(blocker("payroll_evaluation_burden_basis_unsupported", `${rule.label} uses an unsupported burden basis.`));
        continue;
      }
      employerBurdenCents += amountCents;
      allocateBurdenComponent(targets, amountCents, rule.basis);
      burdenComponents.push({
        rule_id: rule.id,
        label: rule.label,
        category: rule.category,
        basis: rule.basis,
        wage_basis_cents: rule.basis === "percent_of_wages" ? Math.max(0, grossCents) : null,
        amount_cents: amountCents
      });
    }
  }
  for (const target of targets.values()) {
    target.supported_gross_compensation_cents = target.base_compensation_cents + target.commission_cents + target.overtime_premium_cents;
    target.supported_loaded_labor_cents = target.supported_gross_compensation_cents + target.employer_burden_cents;
  }
  const loadedCents = grossCents + employerBurdenCents;
  if ([...targets.values()].reduce((sum, target) => sum + target.supported_loaded_labor_cents, 0) !== loadedCents) {
    throw new PayrollEvaluationError("payroll_evaluation_target_loaded_mismatch", "Target loaded labor did not reconcile.", 500);
  }
  return {
    employee_id: employeeId,
    employee_name: employeeName,
    workweek_start_date: weekStartDate,
    policy_id: policy.id,
    policy_version: policy.version,
    jurisdiction_code: policy.jurisdiction_code,
    exemption_status: policy.exemption_status,
    overtime_combination_method: policy.overtime_combination_method,
    work_seconds: workSeconds,
    base_compensation_cents: baseCents,
    included_commission_cents: includedCommissionCents,
    excluded_commission_cents: excludedCommissionCents,
    commission_cents: commissionCents,
    regular_rate_remuneration_cents: remunerationCents,
    regular_rate_work_seconds: workSeconds,
    overtime_seconds: overtimeSeconds,
    overtime_premium_cents: overtimePremiumCents,
    supported_gross_compensation_cents: grossCents,
    employer_burden_cents: employerBurdenCents,
    supported_loaded_labor_cents: loadedCents,
    burden_components: burdenComponents,
    targets: [...targets.values()].sort((left, right) => left.key.localeCompare(right.key))
  };
}

function aggregateRows(rows, idField, nameField) {
  const map = new Map();
  for (const row of rows) {
    const id = row[idField];
    const current = map.get(id) || {
      [idField]: id,
      [nameField]: row[nameField],
      work_seconds: 0,
      base_compensation_cents: 0,
      commission_cents: 0,
      overtime_premium_cents: 0,
      employer_burden_cents: 0,
      supported_gross_compensation_cents: 0,
      supported_loaded_labor_cents: 0
    };
    for (const field of ["work_seconds", "base_compensation_cents", "commission_cents", "overtime_premium_cents", "employer_burden_cents", "supported_gross_compensation_cents", "supported_loaded_labor_cents"]) {
      current[field] += row[field] || 0;
    }
    map.set(id, current);
  }
  return [...map.values()];
}

export function calculateSupportedPayrollPreview({
  range,
  weekStart = 1,
  timezone = "America/New_York",
  baseRecognition = null,
  baseLines = [],
  policies = [],
  commissionEvents = [],
  jobFacts = []
}) {
  const normalizedRange = parsePayrollEvaluationRange(range?.start_date, range?.end_date, { weekStart });
  const normalizedPolicies = policies.map(policyFacts).sort((left, right) => left.employee_id.localeCompare(right.employee_id) || left.effective_from.localeCompare(right.effective_from));
  const normalizedJobs = new Map(jobFacts.map((job) => [String(job.id || job.job_id), {
    id: String(job.id || job.job_id),
    title: job.title || "Job",
    price_cents: job.price_cents == null ? null : dbInteger(job.price_cents, "job_price_cents"),
    material_cost_cents: job.material_cost_cents == null ? null : dbInteger(job.material_cost_cents, "job_material_cost_cents"),
    service_names: Array.isArray(job.service_names) ? job.service_names.map((name) => cleanString(name, 120)).filter(Boolean) : []
  }]));
  const blockers = [];
  if (!normalizedRange.full_workweeks) {
    blockers.push(blocker("payroll_evaluation_full_workweeks_required", "Supported payroll periods must contain complete fixed company workweeks."));
  }
  const baseCurrent = Boolean(baseRecognition?.source_current)
    && baseRecognition.start_date === normalizedRange.start_date
    && baseRecognition.end_date === normalizedRange.end_date;
  if (!baseCurrent) {
    blockers.push(blocker("payroll_evaluation_base_recognition_required", "Recognize current base compensation for these exact dates before supported payroll."));
  }

  const eventEvidence = commissionEvents.map((event) => ({
    id: String(event.id),
    employee_id: String(event.employee_id),
    employee_name: event.employee_name || "Employee",
    event_kind: event.event_kind,
    root_event_id: event.root_event_id || null,
    earned_date: dateOnly(event.earned_date, "commission_earned_date"),
    commission_cents: dbInteger(event.commission_cents, "commission_cents"),
    regular_rate_treatment: event.regular_rate_treatment,
    regular_rate_basis: event.regular_rate_basis || null,
    job_id: event.job_id || null,
    job_title: event.job_title || normalizedJobs.get(String(event.job_id))?.title || null,
    allocation_status: event.allocation_status || "missing",
    allocation_version: event.allocation_version == null ? 0 : dbInteger(event.allocation_version, "commission_allocation_version"),
    allocations: Array.isArray(event.allocations) ? normalizedAllocationLines(event.allocations).map((line) => ({
      ...line,
      allocated_cents: line.commission_cents
    })) : []
  }));
  for (const event of eventEvidence) {
    if (event.commission_cents !== 0 && event.earned_date >= normalizedRange.start_date && event.earned_date <= normalizedRange.end_date
        && (event.allocation_status !== "reviewed" || event.allocations.reduce((sum, line) => sum + line.allocated_cents, 0) !== event.commission_cents)) {
      blockers.push(blocker("payroll_evaluation_commission_allocation_missing", "Every commission event earned in the period needs exact reviewed workweek allocation."));
    }
  }

  const baseByEmployeeWeek = new Map();
  for (const rawLine of baseLines) {
    const line = {
      ...rawLine,
      time_entry_id: String(rawLine.time_entry_id),
      employee_id: String(rawLine.employee_id),
      employee_name: rawLine.employee_name || "Employee",
      work_date: dateOnly(rawLine.work_date, "work_date"),
      source_work_seconds: exactInteger(Number(rawLine.source_work_seconds), "source_work_seconds", { minimum: 1 }),
      base_pay_cents: exactInteger(Number(rawLine.base_pay_cents), "base_pay_cents", { minimum: 0 })
    };
    const week = payrollWorkweekStart(line.work_date, normalizedRange.week_start);
    const key = `${line.employee_id}|${week}`;
    const list = baseByEmployeeWeek.get(key) || [];
    list.push(line);
    baseByEmployeeWeek.set(key, list);
  }
  const commissionByEmployeeWeek = new Map();
  for (const event of eventEvidence) {
    if (event.allocation_status !== "reviewed") continue;
    for (const allocation of event.allocations) {
      if (allocation.workweek_start_date < normalizedRange.start_date || allocation.workweek_start_date > normalizedRange.end_date) continue;
      const key = `${event.employee_id}|${allocation.workweek_start_date}`;
      const list = commissionByEmployeeWeek.get(key) || [];
      list.push({ ...event, allocated_cents: allocation.allocated_cents });
      commissionByEmployeeWeek.set(key, list);
    }
  }
  const keys = [...new Set([...baseByEmployeeWeek.keys(), ...commissionByEmployeeWeek.keys()])].sort();
  const workweeks = [];
  for (const key of keys) {
    const [employeeId, weekStartDate] = key.split("|");
    const lines = baseByEmployeeWeek.get(key) || [];
    const commissionItems = commissionByEmployeeWeek.get(key) || [];
    const employeeName = lines[0]?.employee_name || commissionItems[0]?.employee_name || "Employee";
    const policyCoverage = policyForWorkweek(normalizedPolicies, employeeId, weekStartDate);
    if (policyCoverage.complete.length !== 1) {
      blockers.push(blocker(
        policyCoverage.overlapping.length ? "payroll_evaluation_policy_boundary" : "payroll_evaluation_policy_missing",
        policyCoverage.overlapping.length
          ? "One reviewed payroll policy must cover each complete employee workweek without a midweek boundary."
          : "A payroll policy is missing for an employee workweek."
      ));
      continue;
    }
    const policy = policyCoverage.complete[0];
    if (policy.status !== "reviewed") {
      blockers.push(blocker("payroll_evaluation_policy_not_reviewed", "Every effective payroll policy must be reviewed before evaluation."));
      continue;
    }
    workweeks.push(evaluateWorkweek({ employeeId, employeeName, weekStartDate, lines, commissionItems, policy, timezone, blockers }));
  }

  const employeeRows = aggregateRows(workweeks, "employee_id", "employee_name")
    .sort((left, right) => left.employee_name.localeCompare(right.employee_name) || left.employee_id.localeCompare(right.employee_id));
  const combinedTargets = new Map();
  for (const workweek of workweeks) {
    for (const target of workweek.targets) {
      const current = combinedTargets.get(target.key) || { ...createTarget(target.target_kind, target.job_id, target.job_title), workweek_count: 0 };
      current.workweek_count += 1;
      for (const field of ["source_seconds", "base_compensation_cents", "commission_cents", "overtime_premium_cents", "employer_burden_cents", "supported_gross_compensation_cents", "supported_loaded_labor_cents"]) {
        current[field] += target[field] || 0;
      }
      combinedTargets.set(target.key, current);
    }
  }
  const targets = [...combinedTargets.values()].map((target) => {
    const job = target.job_id ? normalizedJobs.get(String(target.job_id)) : null;
    const comparable = Boolean(job && job.price_cents != null && job.price_cents >= 0 && job.material_cost_cents != null && job.material_cost_cents >= 0);
    return {
      ...target,
      job_title: target.job_title || job?.title || null,
      price_cents: job?.price_cents ?? null,
      material_cost_cents: job?.material_cost_cents ?? null,
      service_names: job?.service_names || [],
      supported_contribution_cents: comparable
        ? job.price_cents - job.material_cost_cents - target.supported_loaded_labor_cents
        : null
    };
  }).sort((left, right) => right.supported_loaded_labor_cents - left.supported_loaded_labor_cents || left.key.localeCompare(right.key));
  if (targets.length > MAX_EVALUATION_TARGETS) {
    throw new PayrollEvaluationError("payroll_evaluation_targets_too_many", "Supported payroll has too many target rows for one period.", 409);
  }
  const summary = {
    employee_count: employeeRows.length,
    workweek_count: workweeks.length,
    work_seconds: workweeks.reduce((sum, item) => sum + item.work_seconds, 0),
    base_compensation_cents: workweeks.reduce((sum, item) => sum + item.base_compensation_cents, 0),
    commission_cents: workweeks.reduce((sum, item) => sum + item.commission_cents, 0),
    included_commission_cents: workweeks.reduce((sum, item) => sum + item.included_commission_cents, 0),
    excluded_commission_cents: workweeks.reduce((sum, item) => sum + item.excluded_commission_cents, 0),
    overtime_seconds: workweeks.reduce((sum, item) => sum + item.overtime_seconds, 0),
    overtime_premium_cents: workweeks.reduce((sum, item) => sum + item.overtime_premium_cents, 0),
    supported_gross_compensation_cents: workweeks.reduce((sum, item) => sum + item.supported_gross_compensation_cents, 0),
    employer_burden_cents: workweeks.reduce((sum, item) => sum + item.employer_burden_cents, 0),
    supported_loaded_labor_cents: workweeks.reduce((sum, item) => sum + item.supported_loaded_labor_cents, 0),
    job_loaded_labor_cents: targets.filter((target) => target.target_kind === "job").reduce((sum, target) => sum + target.supported_loaded_labor_cents, 0),
    admin_loaded_labor_cents: targets.filter((target) => target.target_kind === "admin").reduce((sum, target) => sum + target.supported_loaded_labor_cents, 0),
    travel_loaded_labor_cents: targets.filter((target) => target.target_kind === "travel").reduce((sum, target) => sum + target.supported_loaded_labor_cents, 0),
    unallocated_loaded_labor_cents: targets.filter((target) => target.target_kind === "unallocated").reduce((sum, target) => sum + target.supported_loaded_labor_cents, 0),
    commission_event_count: eventEvidence.length,
    commission_unallocated_event_count: eventEvidence.filter((event) => event.commission_cents !== 0 && event.allocation_status !== "reviewed").length
  };
  const targetLoaded = summary.job_loaded_labor_cents + summary.admin_loaded_labor_cents + summary.travel_loaded_labor_cents + summary.unallocated_loaded_labor_cents;
  if (targetLoaded !== summary.supported_loaded_labor_cents) {
    throw new PayrollEvaluationError("payroll_evaluation_summary_reconciliation_failed", "Supported loaded labor summary did not reconcile.", 500);
  }
  const fingerprintEvidence = {
    policy_version: EVALUATION_POLICY_VERSION,
    range: normalizedRange,
    timezone,
    base_recognition: baseRecognition,
    base_lines: baseLines,
    policies: normalizedPolicies,
    commission_events: eventEvidence,
    job_facts: [...normalizedJobs.values()]
  };
  const consolidated = consolidatedBlockers(blockers);
  return {
    policy_version: EVALUATION_POLICY_VERSION,
    ...normalizedRange,
    timezone,
    can_recognize: consolidated.length === 0,
    fingerprint: payrollEvaluationFingerprint(fingerprintEvidence),
    summary,
    blockers: consolidated,
    warnings: [
      "Supported loaded labor includes current reviewed base, explicitly allocated commission, represented overtime premium, and configured employer burden only.",
      "This operational snapshot does not calculate withholding, employee taxes, net pay, a paycheck, cash P&L, a general-ledger journal, or a payroll-provider run.",
      "Job contribution compares current job price/material facts with this period's supported loaded labor; it is not formal net income or a lifetime job margin."
    ],
    employees: employeeRows,
    workweeks,
    targets,
    commission_events: eventEvidence
  };
}

function recognitionSnapshot(row) {
  if (!row) return null;
  return {
    id: String(row.id),
    start_date: dateOnly(row.start_date, "start_date"),
    end_date: dateOnly(row.end_date, "end_date"),
    status: row.status,
    policy_version: row.policy_version,
    source_fingerprint: row.source_fingerprint || null,
    summary: row.summary || {},
    version: dbInteger(row.version, "version")
  };
}

export function recognitionAuditSnapshot(row, preview = null) {
  const header = recognitionSnapshot(row);
  if (!header || !preview) return header;
  return {
    ...header,
    base_recognition_id: row.base_recognition_id || null,
    workweeks: preview.workweeks.map((item) => ({
      employee_id: item.employee_id,
      workweek_start_date: item.workweek_start_date,
      policy_id: item.policy_id,
      policy_version: item.policy_version,
      jurisdiction_code: item.jurisdiction_code,
      exemption_status: item.exemption_status,
      overtime_combination_method: item.overtime_combination_method,
      work_seconds: item.work_seconds,
      base_compensation_cents: item.base_compensation_cents,
      included_commission_cents: item.included_commission_cents,
      excluded_commission_cents: item.excluded_commission_cents,
      overtime_seconds: item.overtime_seconds,
      overtime_premium_cents: item.overtime_premium_cents,
      supported_gross_compensation_cents: item.supported_gross_compensation_cents,
      employer_burden_cents: item.employer_burden_cents,
      supported_loaded_labor_cents: item.supported_loaded_labor_cents,
      burden_components: item.burden_components,
      allocations: item.targets.map((target) => ({
        target_kind: target.target_kind,
        job_id: target.job_id,
        source_seconds: target.source_seconds,
        base_compensation_cents: target.base_compensation_cents,
        commission_cents: target.commission_cents,
        overtime_premium_cents: target.overtime_premium_cents,
        employer_burden_cents: target.employer_burden_cents,
        supported_gross_compensation_cents: target.supported_gross_compensation_cents,
        supported_loaded_labor_cents: target.supported_loaded_labor_cents
      }))
    }))
  };
}

export function planPayrollEvaluationRecognition({ body = {}, currentRecognition = null, preview, overlappingRecognitionCount = 0 }) {
  const expectedVersion = exactInteger(body.expected_version, "expected_version", { minimum: 0 });
  const reason = cleanString(body.reason, 500);
  if (!reason) throw new PayrollEvaluationError("payroll_evaluation_reason_required", "Add a reason for this supported-payroll change.");
  const action = cleanString(body.action, 30);
  if (!["recognize", "clear"].includes(action)) throw new PayrollEvaluationError("payroll_evaluation_action_invalid", "Choose Recognize or Clear.");
  const currentVersion = currentRecognition ? dbInteger(currentRecognition.version, "version") : 0;
  if (expectedVersion !== currentVersion) {
    throw new PayrollEvaluationError("payroll_evaluation_stale", "Supported payroll changed after it was loaded. Refresh before saving again.", 409, { current_version: currentVersion });
  }
  if (action === "clear") {
    if (!currentRecognition || currentRecognition.status === "cleared") return { mode: "replay", action: "supported_payroll_cleared", reason };
    return { mode: "clear", action: "supported_payroll_cleared", reason };
  }
  if (!preview?.can_recognize) {
    throw new PayrollEvaluationError("payroll_evaluation_preview_blocked", "Resolve every supported-payroll blocker before recognition.", 409, { blockers: preview?.blockers || [] });
  }
  if (overlappingRecognitionCount > 0) {
    throw new PayrollEvaluationError("payroll_evaluation_period_overlap", "Another active supported-payroll recognition overlaps these dates.", 409);
  }
  if (currentRecognition?.status === "recognized"
      && currentRecognition.policy_version === preview.policy_version
      && currentRecognition.source_fingerprint === preview.fingerprint) {
    return { mode: "replay", action: "supported_payroll_recognized", reason };
  }
  return {
    mode: currentRecognition ? "replace" : "create",
    action: currentRecognition ? "supported_payroll_refreshed" : "supported_payroll_recognized",
    reason
  };
}

export async function installFinancePayrollEvaluationSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS finance_commission_allocation_headers (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      commission_event_id UUID NOT NULL REFERENCES finance_commission_events(id) ON DELETE RESTRICT,
      employee_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
      source_event_kind TEXT NOT NULL,
      source_earned_date DATE NOT NULL,
      source_commission_cents BIGINT NOT NULL,
      status TEXT NOT NULL DEFAULT 'reviewed',
      version INTEGER NOT NULL DEFAULT 1,
      reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL,
      reason TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, commission_event_id),
      CHECK (source_event_kind IN ('earning','adjustment')),
      CHECK (status IN ('reviewed','cleared')),
      CHECK (version > 0)
    );
    CREATE INDEX IF NOT EXISTS finance_commission_allocation_headers_company_employee_idx
      ON finance_commission_allocation_headers(company_id, employee_id, source_earned_date, commission_event_id);

    CREATE TABLE IF NOT EXISTS finance_commission_allocation_lines (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      header_id UUID NOT NULL REFERENCES finance_commission_allocation_headers(id) ON DELETE CASCADE,
      commission_event_id UUID NOT NULL REFERENCES finance_commission_events(id) ON DELETE RESTRICT,
      line_order SMALLINT NOT NULL,
      workweek_start_date DATE NOT NULL,
      commission_cents BIGINT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, commission_event_id, workweek_start_date),
      UNIQUE(company_id, header_id, line_order),
      CHECK (line_order >= 0 AND line_order < 50)
    );
    CREATE INDEX IF NOT EXISTS finance_commission_allocation_lines_company_week_idx
      ON finance_commission_allocation_lines(company_id, workweek_start_date, commission_event_id);

    CREATE TABLE IF NOT EXISTS finance_commission_allocation_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      commission_event_id UUID NOT NULL REFERENCES finance_commission_events(id) ON DELETE RESTRICT,
      header_id UUID NOT NULL REFERENCES finance_commission_allocation_headers(id) ON DELETE RESTRICT,
      actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      reason TEXT NOT NULL,
      before_state JSONB,
      after_state JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS finance_commission_allocation_audit_company_event_idx
      ON finance_commission_allocation_audit(company_id, commission_event_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS finance_payroll_evaluation_periods (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      base_recognition_id UUID REFERENCES finance_payroll_cost_periods(id) ON DELETE RESTRICT,
      start_date DATE NOT NULL,
      end_date DATE NOT NULL,
      status TEXT NOT NULL DEFAULT 'recognized',
      policy_version TEXT NOT NULL,
      source_fingerprint TEXT,
      summary JSONB NOT NULL DEFAULT '{}'::jsonb,
      version INTEGER NOT NULL DEFAULT 1,
      recognized_by UUID REFERENCES users(id) ON DELETE SET NULL,
      recognized_at TIMESTAMPTZ,
      reason TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, start_date, end_date),
      CHECK (end_date >= start_date),
      CHECK (status IN ('recognized','cleared')),
      CHECK (version > 0)
    );
    CREATE INDEX IF NOT EXISTS finance_payroll_evaluation_periods_company_dates_idx
      ON finance_payroll_evaluation_periods(company_id, start_date, end_date, status);

    CREATE TABLE IF NOT EXISTS finance_payroll_evaluation_workweeks (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      period_id UUID NOT NULL REFERENCES finance_payroll_evaluation_periods(id) ON DELETE CASCADE,
      employee_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
      workweek_start_date DATE NOT NULL,
      policy_id UUID NOT NULL REFERENCES finance_payroll_policies(id) ON DELETE RESTRICT,
      policy_version INTEGER NOT NULL,
      jurisdiction_code TEXT NOT NULL,
      exemption_status TEXT NOT NULL,
      overtime_combination_method TEXT NOT NULL,
      work_seconds INTEGER NOT NULL,
      base_compensation_cents BIGINT NOT NULL,
      included_commission_cents BIGINT NOT NULL,
      excluded_commission_cents BIGINT NOT NULL,
      commission_cents BIGINT NOT NULL,
      regular_rate_remuneration_cents BIGINT NOT NULL,
      regular_rate_work_seconds INTEGER NOT NULL,
      overtime_seconds INTEGER NOT NULL,
      overtime_premium_cents BIGINT NOT NULL,
      supported_gross_compensation_cents BIGINT NOT NULL,
      employer_burden_cents BIGINT NOT NULL,
      supported_loaded_labor_cents BIGINT NOT NULL,
      burden_components JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, period_id, employee_id, workweek_start_date),
      CHECK (policy_version > 0),
      CHECK (work_seconds >= 0 AND regular_rate_work_seconds >= 0 AND overtime_seconds >= 0),
      CHECK (base_compensation_cents >= 0 AND overtime_premium_cents >= 0 AND employer_burden_cents >= 0),
      CHECK (base_compensation_cents + commission_cents + overtime_premium_cents = supported_gross_compensation_cents),
      CHECK (supported_gross_compensation_cents >= 0),
      CHECK (supported_gross_compensation_cents + employer_burden_cents = supported_loaded_labor_cents),
      CHECK (jsonb_typeof(burden_components) = 'array')
    );
    CREATE INDEX IF NOT EXISTS finance_payroll_evaluation_workweeks_company_employee_idx
      ON finance_payroll_evaluation_workweeks(company_id, employee_id, workweek_start_date);

    CREATE TABLE IF NOT EXISTS finance_payroll_evaluation_allocations (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      period_id UUID NOT NULL REFERENCES finance_payroll_evaluation_periods(id) ON DELETE CASCADE,
      workweek_id UUID NOT NULL REFERENCES finance_payroll_evaluation_workweeks(id) ON DELETE CASCADE,
      line_order SMALLINT NOT NULL,
      target_kind TEXT NOT NULL,
      job_id TEXT,
      source_seconds INTEGER NOT NULL,
      base_compensation_cents BIGINT NOT NULL,
      commission_cents BIGINT NOT NULL,
      overtime_premium_cents BIGINT NOT NULL,
      employer_burden_cents BIGINT NOT NULL,
      supported_gross_compensation_cents BIGINT NOT NULL,
      supported_loaded_labor_cents BIGINT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, workweek_id, line_order),
      CHECK (line_order >= 0 AND line_order < 100),
      CHECK (target_kind IN ('job','admin','travel','unallocated')),
      CHECK ((target_kind = 'job' AND job_id IS NOT NULL) OR (target_kind <> 'job' AND job_id IS NULL)),
      CHECK (source_seconds >= 0),
      CHECK (base_compensation_cents >= 0 AND overtime_premium_cents >= 0 AND employer_burden_cents >= 0),
      CHECK (base_compensation_cents + commission_cents + overtime_premium_cents = supported_gross_compensation_cents),
      CHECK (supported_gross_compensation_cents + employer_burden_cents = supported_loaded_labor_cents)
    );
    CREATE INDEX IF NOT EXISTS finance_payroll_evaluation_allocations_company_job_idx
      ON finance_payroll_evaluation_allocations(company_id, job_id) WHERE job_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS finance_payroll_evaluation_allocations_period_idx
      ON finance_payroll_evaluation_allocations(company_id, period_id, workweek_id, line_order);

    CREATE TABLE IF NOT EXISTS finance_payroll_evaluation_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      period_id UUID NOT NULL REFERENCES finance_payroll_evaluation_periods(id) ON DELETE RESTRICT,
      actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      reason TEXT NOT NULL,
      before_state JSONB,
      after_state JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS finance_payroll_evaluation_audit_company_period_idx
      ON finance_payroll_evaluation_audit(company_id, period_id, created_at DESC);
  `);
}

function allocationHeaderSnapshot(header, lines = []) {
  if (!header) return null;
  return {
    id: String(header.id),
    commission_event_id: String(header.commission_event_id),
    employee_id: String(header.employee_id),
    source_event_kind: header.source_event_kind,
    source_earned_date: dateOnly(header.source_earned_date, "source_earned_date"),
    source_commission_cents: dbInteger(header.source_commission_cents, "source_commission_cents"),
    status: header.status,
    version: dbInteger(header.version, "version"),
    allocations: normalizedAllocationLines(lines)
  };
}

async function loadCommissionAllocationDetail(client, companyId, eventId, { lock = false } = {}) {
  const eventResult = await client.query(
    `SELECT ce.*, COALESCE(NULLIF(u.display_name, ''), u.email) AS employee_name,
            target.title AS job_title
       FROM finance_commission_events ce
       JOIN users u ON u.id = ce.employee_id AND u.company_id = ce.company_id
       LEFT JOIN schedule_events target ON target.company_id = ce.company_id AND target.id = ce.job_id
      WHERE ce.company_id = $1 AND ce.id = $2::uuid${lock ? " FOR UPDATE OF ce" : ""}`,
    [companyId, eventId]
  );
  const event = eventResult.rows[0];
  if (!event) throw new PayrollEvaluationError("commission_event_not_found", "The commission event was not found.", 404);
  const headerResult = await client.query(
    `SELECT * FROM finance_commission_allocation_headers
      WHERE company_id = $1 AND commission_event_id = $2::uuid${lock ? " FOR UPDATE" : ""}`,
    [companyId, eventId]
  );
  const header = headerResult.rows[0] || null;
  const linesResult = header
    ? await client.query(
      `SELECT workweek_start_date, commission_cents
         FROM finance_commission_allocation_lines
        WHERE company_id = $1 AND header_id = $2
        ORDER BY line_order${lock ? " FOR UPDATE" : ""}`,
      [companyId, header.id]
    )
    : { rows: [] };
  const auditResult = header
    ? await client.query(
      `SELECT id, actor_user_id, action, reason, before_state, after_state, created_at
         FROM finance_commission_allocation_audit
        WHERE company_id = $1 AND commission_event_id = $2::uuid
        ORDER BY created_at DESC, id DESC LIMIT 100`,
      [companyId, eventId]
    )
    : { rows: [] };
  let rootWorkweeks = [];
  if (event.root_event_id) {
    const rootResult = await client.query(
      `SELECT l.workweek_start_date
         FROM finance_commission_allocation_headers h
         JOIN finance_commission_allocation_lines l ON l.company_id = h.company_id AND l.header_id = h.id
        WHERE h.company_id = $1 AND h.commission_event_id = $2::uuid AND h.status = 'reviewed'
        ORDER BY l.workweek_start_date${lock ? " FOR SHARE OF h, l" : ""}`,
      [companyId, event.root_event_id]
    );
    rootWorkweeks = rootResult.rows.map((row) => dateOnly(row.workweek_start_date, "root_workweek_start_date"));
  }
  return {
    event: {
      id: String(event.id),
      employee_id: String(event.employee_id),
      employee_name: event.employee_name,
      event_kind: event.event_kind,
      root_event_id: event.root_event_id || null,
      earned_date: dateOnly(event.earned_date, "earned_date"),
      commission_cents: dbInteger(event.commission_cents, "commission_cents"),
      regular_rate_treatment: event.regular_rate_treatment,
      regular_rate_basis: event.regular_rate_basis || null,
      source_label: event.source_label,
      job_id: event.job_id || null,
      job_title: event.job_title || null
    },
    header: header ? allocationHeaderSnapshot(header, linesResult.rows) : null,
    allocations: normalizedAllocationLines(linesResult.rows),
    root_workweeks: rootWorkweeks,
    audit: auditResult.rows.map((row) => ({
      id: String(row.id), actor_user_id: row.actor_user_id || null, action: row.action,
      reason: row.reason, before: row.before_state || null, after: row.after_state || null,
      created_at: row.created_at
    })),
    _event: event,
    _header: header,
    _lines: linesResult.rows
  };
}

function storedEvaluationPayload(row, preview) {
  if (!row) return null;
  const sourceCurrent = row.status === "recognized"
    && row.policy_version === preview?.policy_version
    && row.source_fingerprint === preview?.fingerprint;
  return {
    ...recognitionSnapshot(row),
    base_recognition_id: row.base_recognition_id || null,
    recognized_by: row.recognized_by || null,
    recognized_at: row.recognized_at || null,
    reason: row.reason,
    created_at: row.created_at || null,
    updated_at: row.updated_at || null,
    source_current: sourceCurrent,
    current_supported_loaded_labor_cents: sourceCurrent
      ? dbInteger(row.summary?.supported_loaded_labor_cents || 0, "supported_loaded_labor_cents")
      : 0
  };
}

function serviceNames(row) {
  const items = Array.isArray(row.service_items) ? row.service_items : [];
  const names = items.map((item) => cleanString(typeof item === "string" ? item : item?.name, 120)).filter(Boolean);
  if (names.length) return [...new Set(names)].sort();
  const services = Array.isArray(row.services) ? row.services.map((item) => cleanString(item, 120)).filter(Boolean) : [];
  return [...new Set(services)].sort();
}

async function loadEvaluationEvidence(client, companyId, range, context, { lock = false } = {}) {
  const baseReport = await payrollCostReport(client, companyId, range, context, { lock });
  const baseRow = baseReport._recognition || null;
  const baseCurrent = Boolean(baseRow)
    && baseRow.status === "recognized"
    && baseRow.policy_version === baseReport._preview.policy_version
    && baseRow.source_fingerprint === baseReport._preview.fingerprint;
  const baseRecognition = baseRow ? {
    id: String(baseRow.id),
    start_date: dateOnly(baseRow.start_date, "base_start_date"),
    end_date: dateOnly(baseRow.end_date, "base_end_date"),
    version: dbInteger(baseRow.version, "base_version"),
    source_fingerprint: baseRow.source_fingerprint,
    source_current: baseCurrent
  } : null;
  const policyResult = await client.query(
    `SELECT * FROM finance_payroll_policies
      WHERE company_id = $1 AND effective_from <= $3::date
        AND (effective_to IS NULL OR effective_to >= $2::date)
      ORDER BY employee_id, effective_from, id LIMIT $4${lock ? " FOR UPDATE" : ""}`,
    [companyId, range.start_date, range.end_date, MAX_EVALUATION_POLICIES + 1]
  );
  if (policyResult.rows.length > MAX_EVALUATION_POLICIES) {
    throw new PayrollEvaluationError("payroll_evaluation_policies_too_many", "Supported payroll has too many effective policy rows for one period.", 409);
  }
  const eventResult = await client.query(
    `SELECT ce.*, COALESCE(NULLIF(u.display_name, ''), u.email) AS employee_name,
            target.title AS job_title, h.status AS allocation_status,
            h.version AS allocation_version, h.id AS allocation_header_id
       FROM finance_commission_events ce
       JOIN users u ON u.id = ce.employee_id AND u.company_id = ce.company_id
       LEFT JOIN schedule_events target ON target.company_id = ce.company_id AND target.id = ce.job_id
       LEFT JOIN finance_commission_allocation_headers h
         ON h.company_id = ce.company_id AND h.commission_event_id = ce.id
      WHERE ce.company_id = $1 AND (
        (ce.earned_date >= $2::date AND ce.earned_date <= $3::date)
        OR EXISTS (
          SELECT 1 FROM finance_commission_allocation_lines al
           WHERE al.company_id = ce.company_id AND al.commission_event_id = ce.id
             AND al.workweek_start_date >= $2::date AND al.workweek_start_date <= $3::date
        )
      )
      ORDER BY ce.earned_date, ce.created_at, ce.id LIMIT $4${lock ? " FOR UPDATE OF ce" : ""}`,
    [companyId, range.start_date, range.end_date, MAX_EVALUATION_COMMISSION_EVENTS + 1]
  );
  if (eventResult.rows.length > MAX_EVALUATION_COMMISSION_EVENTS) {
    throw new PayrollEvaluationError("payroll_evaluation_commission_events_too_many", "Supported payroll has too many commission events for one period.", 409);
  }
  const headerIds = eventResult.rows.map((row) => row.allocation_header_id).filter(Boolean);
  const allocationResult = headerIds.length
    ? await client.query(
      `SELECT header_id, commission_event_id, workweek_start_date, commission_cents
         FROM finance_commission_allocation_lines
        WHERE company_id = $1 AND header_id = ANY($2::uuid[])
        ORDER BY commission_event_id, line_order${lock ? " FOR UPDATE" : ""}`,
      [companyId, headerIds]
    )
    : { rows: [] };
  const allocationsByEvent = new Map();
  for (const row of allocationResult.rows) {
    const key = String(row.commission_event_id);
    const list = allocationsByEvent.get(key) || [];
    list.push({ workweek_start_date: dateOnly(row.workweek_start_date, "workweek_start_date"), commission_cents: dbInteger(row.commission_cents, "commission_cents") });
    allocationsByEvent.set(key, list);
  }
  const commissionEvents = eventResult.rows.map((row) => ({
    ...row,
    allocations: allocationsByEvent.get(String(row.id)) || []
  }));
  const jobIds = new Set();
  for (const line of baseReport._preview.lines) for (const allocation of line.allocations || []) if (allocation.job_id) jobIds.add(String(allocation.job_id));
  for (const event of commissionEvents) if (event.job_id) jobIds.add(String(event.job_id));
  const jobResult = jobIds.size
    ? await client.query(
      `SELECT id, title, price_cents, material_cost_cents, services, service_items
         FROM schedule_events WHERE company_id = $1 AND id = ANY($2::text[])${lock ? " FOR SHARE" : ""}`,
      [companyId, [...jobIds]]
    )
    : { rows: [] };
  const jobFacts = jobResult.rows.map((row) => ({ ...row, service_names: serviceNames(row) }));
  return { baseReport, baseRecognition, policies: policyResult.rows, commissionEvents, jobFacts };
}

async function payrollEvaluationReport(client, companyId, range, context, { lock = false } = {}) {
  const evidence = await loadEvaluationEvidence(client, companyId, range, context, { lock });
  const preview = calculateSupportedPayrollPreview({
    range,
    weekStart: Number(context.week_start),
    timezone: context.timezone,
    baseRecognition: evidence.baseRecognition,
    baseLines: evidence.baseReport._preview.lines,
    policies: evidence.policies,
    commissionEvents: evidence.commissionEvents,
    jobFacts: evidence.jobFacts
  });
  const recognitionResult = await client.query(
    `SELECT * FROM finance_payroll_evaluation_periods
      WHERE company_id = $1 AND start_date = $2::date AND end_date = $3::date${lock ? " FOR UPDATE" : ""}`,
    [companyId, range.start_date, range.end_date]
  );
  const recognition = recognitionResult.rows[0] || null;
  const auditResult = recognition
    ? await client.query(
      `SELECT id, actor_user_id, action, reason, before_state, after_state, created_at
         FROM finance_payroll_evaluation_audit
        WHERE company_id = $1 AND period_id = $2
        ORDER BY created_at DESC, id DESC LIMIT 100`,
      [companyId, recognition.id]
    )
    : { rows: [] };
  return {
    basis: EVALUATION_POLICY_VERSION,
    currency: "usd",
    start_date: range.start_date,
    end_date: range.end_date,
    timezone: context.timezone,
    week_start: Number(context.week_start),
    recognition: storedEvaluationPayload(recognition, preview),
    preview,
    audit: auditResult.rows.map((row) => ({
      id: String(row.id), actor_user_id: row.actor_user_id || null, action: row.action,
      reason: row.reason, before: row.before_state || null, after: row.after_state || null,
      created_at: row.created_at
    })),
    _preview: preview,
    _recognition: recognition,
    _baseRecognition: evidence.baseRecognition
  };
}

function publicEvaluationReport(report, replayed = undefined) {
  const { _preview, _recognition, _baseRecognition, ...payload } = report;
  return replayed == null ? payload : { ...payload, replayed };
}

async function persistEvaluationSnapshots(client, companyId, periodId, preview) {
  await client.query(`DELETE FROM finance_payroll_evaluation_workweeks WHERE company_id = $1 AND period_id = $2`, [companyId, periodId]);
  if (!preview.workweeks.length) return;
  const rows = preview.workweeks.map((item) => ({
    employee_id: item.employee_id,
    workweek_start_date: item.workweek_start_date,
    policy_id: item.policy_id,
    policy_version: item.policy_version,
    jurisdiction_code: item.jurisdiction_code,
    exemption_status: item.exemption_status,
    overtime_combination_method: item.overtime_combination_method,
    work_seconds: item.work_seconds,
    base_compensation_cents: item.base_compensation_cents,
    included_commission_cents: item.included_commission_cents,
    excluded_commission_cents: item.excluded_commission_cents,
    commission_cents: item.commission_cents,
    regular_rate_remuneration_cents: item.regular_rate_remuneration_cents,
    regular_rate_work_seconds: item.regular_rate_work_seconds,
    overtime_seconds: item.overtime_seconds,
    overtime_premium_cents: item.overtime_premium_cents,
    supported_gross_compensation_cents: item.supported_gross_compensation_cents,
    employer_burden_cents: item.employer_burden_cents,
    supported_loaded_labor_cents: item.supported_loaded_labor_cents,
    burden_components: item.burden_components
  }));
  const inserted = await client.query(
    `INSERT INTO finance_payroll_evaluation_workweeks (
       company_id, period_id, employee_id, workweek_start_date, policy_id, policy_version,
       jurisdiction_code, exemption_status, overtime_combination_method, work_seconds,
       base_compensation_cents, included_commission_cents, excluded_commission_cents,
       commission_cents, regular_rate_remuneration_cents, regular_rate_work_seconds,
       overtime_seconds, overtime_premium_cents, supported_gross_compensation_cents,
       employer_burden_cents, supported_loaded_labor_cents, burden_components
     ) SELECT $1,$2,x.employee_id::uuid,x.workweek_start_date::date,x.policy_id::uuid,x.policy_version,
              x.jurisdiction_code,x.exemption_status,x.overtime_combination_method,x.work_seconds,
              x.base_compensation_cents,x.included_commission_cents,x.excluded_commission_cents,
              x.commission_cents,x.regular_rate_remuneration_cents,x.regular_rate_work_seconds,
              x.overtime_seconds,x.overtime_premium_cents,x.supported_gross_compensation_cents,
              x.employer_burden_cents,x.supported_loaded_labor_cents,x.burden_components
         FROM jsonb_to_recordset($3::jsonb) AS x(
           employee_id text, workweek_start_date text, policy_id text, policy_version integer,
           jurisdiction_code text, exemption_status text, overtime_combination_method text,
           work_seconds integer, base_compensation_cents bigint, included_commission_cents bigint,
           excluded_commission_cents bigint, commission_cents bigint,
           regular_rate_remuneration_cents bigint, regular_rate_work_seconds integer,
           overtime_seconds integer, overtime_premium_cents bigint,
           supported_gross_compensation_cents bigint, employer_burden_cents bigint,
           supported_loaded_labor_cents bigint, burden_components jsonb
         ) RETURNING id, employee_id, workweek_start_date`,
    [companyId, periodId, JSON.stringify(rows)]
  );
  const ids = new Map(inserted.rows.map((row) => [`${row.employee_id}|${dateOnly(row.workweek_start_date, "workweek_start_date")}`, String(row.id)]));
  const allocations = preview.workweeks.flatMap((workweek) => workweek.targets.map((target, lineOrder) => ({
    workweek_id: ids.get(`${workweek.employee_id}|${workweek.workweek_start_date}`),
    line_order: lineOrder,
    target_kind: target.target_kind,
    job_id: target.job_id,
    source_seconds: target.source_seconds,
    base_compensation_cents: target.base_compensation_cents,
    commission_cents: target.commission_cents,
    overtime_premium_cents: target.overtime_premium_cents,
    employer_burden_cents: target.employer_burden_cents,
    supported_gross_compensation_cents: target.supported_gross_compensation_cents,
    supported_loaded_labor_cents: target.supported_loaded_labor_cents
  })));
  if (!allocations.length) return;
  await client.query(
    `INSERT INTO finance_payroll_evaluation_allocations (
       company_id, period_id, workweek_id, line_order, target_kind, job_id, source_seconds,
       base_compensation_cents, commission_cents, overtime_premium_cents,
       employer_burden_cents, supported_gross_compensation_cents, supported_loaded_labor_cents
     ) SELECT $1,$2,x.workweek_id::uuid,x.line_order,x.target_kind,x.job_id,x.source_seconds,
              x.base_compensation_cents,x.commission_cents,x.overtime_premium_cents,
              x.employer_burden_cents,x.supported_gross_compensation_cents,x.supported_loaded_labor_cents
         FROM jsonb_to_recordset($3::jsonb) AS x(
           workweek_id text, line_order integer, target_kind text, job_id text, source_seconds integer,
           base_compensation_cents bigint, commission_cents bigint, overtime_premium_cents bigint,
           employer_burden_cents bigint, supported_gross_compensation_cents bigint,
           supported_loaded_labor_cents bigint
         )`,
    [companyId, periodId, JSON.stringify(allocations)]
  );
}

function sendEvaluationError(res, error, fallback) {
  if (error instanceof PayrollEvaluationError || error?.statusCode) {
    return res.status(error.statusCode || 400).json({
      error: error.code || fallback,
      message: error.message,
      current_version: error.current_version,
      blockers: error.blockers
    });
  }
  console.error("[finance-payroll-evaluation]", fallback, { code: error?.code, message: error?.message });
  return res.status(500).json({ error: fallback, message: "Supported payroll request failed." });
}

export function installFinancePayrollEvaluationRoutes({ app, pool, authRequired, requireFinanceAccess }) {
  app.get("/api/finance/accounting/payroll-evaluation", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Supported payroll requires a company workspace." });
    try {
      const context = await loadCompanyContext(pool, req.companyId);
      const range = parsePayrollEvaluationRange(req.query.start_date, req.query.end_date, {
        companyToday: context.company_today,
        weekStart: Number(context.week_start)
      });
      res.json(publicEvaluationReport(await payrollEvaluationReport(pool, req.companyId, range, context)));
    } catch (error) {
      sendEvaluationError(res, error, "payroll_evaluation_load_failed");
    }
  });

  app.get("/api/finance/accounting/payroll-evaluation/commission-events/:eventId/allocation", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Supported payroll requires a company workspace." });
    try {
      const context = await loadCompanyContext(pool, req.companyId);
      const detail = await loadCommissionAllocationDetail(pool, req.companyId, req.params.eventId);
      const { _event, _header, _lines, ...payload } = detail;
      res.json({ timezone: context.timezone, week_start: Number(context.week_start), company_today: context.company_today, ...payload });
    } catch (error) {
      sendEvaluationError(res, error, "commission_allocation_load_failed");
    }
  });

  app.put("/api/finance/accounting/payroll-evaluation/commission-events/:eventId/allocation", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Supported payroll requires a company workspace." });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const context = await loadCompanyContext(client, req.companyId);
      const detail = await loadCommissionAllocationDetail(client, req.companyId, req.params.eventId, { lock: true });
      const input = normalizeCommissionAllocationInput({
        body: req.body,
        event: detail._event,
        rootWorkweeks: detail.root_workweeks,
        weekStart: Number(context.week_start),
        companyToday: context.company_today
      });
      const plan = planCommissionAllocationUpdate({ currentHeader: detail._header, currentLines: detail._lines, input });
      if (plan.mode === "replay") {
        await client.query("COMMIT");
        const refreshed = await loadCommissionAllocationDetail(pool, req.companyId, req.params.eventId);
        const { _event, _header, _lines, ...payload } = refreshed;
        return res.json({ replayed: true, timezone: context.timezone, week_start: Number(context.week_start), company_today: context.company_today, ...payload });
      }
      const before = allocationHeaderSnapshot(detail._header, detail._lines);
      let header;
      if (plan.mode === "create") {
        header = (await client.query(
          `INSERT INTO finance_commission_allocation_headers (
             company_id, commission_event_id, employee_id, source_event_kind,
             source_earned_date, source_commission_cents, status, reviewed_by, reason
           ) VALUES ($1,$2::uuid,$3::uuid,$4,$5::date,$6,'reviewed',$7,$8) RETURNING *`,
          [req.companyId, detail._event.id, detail._event.employee_id, detail._event.event_kind,
            detail._event.earned_date, detail._event.commission_cents, req.userId, input.reason]
        )).rows[0];
      } else {
        header = (await client.query(
          `UPDATE finance_commission_allocation_headers
              SET source_event_kind=$3, source_earned_date=$4::date, source_commission_cents=$5,
                  status=$6, version=version+1, reviewed_by=$7, reason=$8, updated_at=now()
            WHERE company_id=$1 AND commission_event_id=$2::uuid RETURNING *`,
          [req.companyId, detail._event.id, detail._event.event_kind, detail._event.earned_date,
            detail._event.commission_cents, plan.mode === "clear" ? "cleared" : "reviewed", req.userId, input.reason]
        )).rows[0];
        await client.query(`DELETE FROM finance_commission_allocation_lines WHERE company_id=$1 AND header_id=$2`, [req.companyId, header.id]);
      }
      if (input.lines.length) {
        await client.query(
          `INSERT INTO finance_commission_allocation_lines (
             company_id, header_id, commission_event_id, line_order, workweek_start_date, commission_cents
           ) SELECT $1,$2,$3::uuid,x.line_order,x.workweek_start_date::date,x.commission_cents
               FROM jsonb_to_recordset($4::jsonb) AS x(line_order integer, workweek_start_date text, commission_cents bigint)`,
          [req.companyId, header.id, detail._event.id, JSON.stringify(input.lines.map((line, lineOrder) => ({ ...line, line_order: lineOrder })))]
        );
      }
      const after = allocationHeaderSnapshot(header, input.lines);
      await client.query(
        `INSERT INTO finance_commission_allocation_audit (
           company_id, commission_event_id, header_id, actor_user_id, action, reason, before_state, after_state
         ) VALUES ($1,$2::uuid,$3,$4,$5,$6,$7,$8)`,
        [req.companyId, detail._event.id, header.id, req.userId, plan.action, input.reason, JSON.stringify(before), JSON.stringify(after)]
      );
      await client.query("COMMIT");
      const refreshed = await loadCommissionAllocationDetail(pool, req.companyId, req.params.eventId);
      const { _event, _header, _lines, ...payload } = refreshed;
      res.json({ replayed: false, timezone: context.timezone, week_start: Number(context.week_start), company_today: context.company_today, ...payload });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendEvaluationError(res, error, "commission_allocation_update_failed");
    } finally {
      client.release();
    }
  });

  app.put("/api/finance/accounting/payroll-evaluation/recognition", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Supported payroll requires a company workspace." });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(`SELECT pg_advisory_xact_lock(hashtext($1::text))`, [`${req.companyId}|supported-payroll`]);
      const context = await loadCompanyContext(client, req.companyId);
      const range = parsePayrollEvaluationRange(req.body?.start_date, req.body?.end_date, {
        companyToday: context.company_today,
        weekStart: Number(context.week_start)
      });
      const report = await payrollEvaluationReport(client, req.companyId, range, context, { lock: true });
      const overlapResult = req.body?.action === "recognize"
        ? await client.query(
          `SELECT id FROM finance_payroll_evaluation_periods
            WHERE company_id=$1 AND status='recognized' AND id IS DISTINCT FROM $4::uuid
              AND start_date <= $3::date AND end_date >= $2::date FOR UPDATE`,
          [req.companyId, range.start_date, range.end_date, report._recognition?.id || null]
        )
        : { rowCount: 0 };
      const plan = planPayrollEvaluationRecognition({
        body: req.body,
        currentRecognition: report._recognition,
        preview: report._preview,
        overlappingRecognitionCount: overlapResult.rowCount
      });
      if (plan.mode === "replay") {
        await client.query("COMMIT");
        return res.json(publicEvaluationReport(report, true));
      }
      const before = recognitionSnapshot(report._recognition);
      let current;
      if (plan.mode === "clear") {
        current = (await client.query(
          `UPDATE finance_payroll_evaluation_periods
              SET status='cleared', version=version+1, recognized_by=$4, reason=$5, updated_at=now()
            WHERE company_id=$1 AND start_date=$2::date AND end_date=$3::date RETURNING *`,
          [req.companyId, range.start_date, range.end_date, req.userId, plan.reason]
        )).rows[0];
      } else if (plan.mode === "create") {
        current = (await client.query(
          `INSERT INTO finance_payroll_evaluation_periods (
             company_id, base_recognition_id, start_date, end_date, status, policy_version,
             source_fingerprint, summary, recognized_by, recognized_at, reason
           ) VALUES ($1,$2,$3::date,$4::date,'recognized',$5,$6,$7,$8,now(),$9) RETURNING *`,
          [req.companyId, report._baseRecognition?.id || null, range.start_date, range.end_date,
            report._preview.policy_version, report._preview.fingerprint, JSON.stringify(report._preview.summary), req.userId, plan.reason]
        )).rows[0];
        await persistEvaluationSnapshots(client, req.companyId, current.id, report._preview);
      } else {
        current = (await client.query(
          `UPDATE finance_payroll_evaluation_periods
              SET base_recognition_id=$4, status='recognized', policy_version=$5,
                  source_fingerprint=$6, summary=$7, version=version+1,
                  recognized_by=$8, recognized_at=now(), reason=$9, updated_at=now()
            WHERE company_id=$1 AND start_date=$2::date AND end_date=$3::date RETURNING *`,
          [req.companyId, range.start_date, range.end_date, report._baseRecognition?.id || null,
            report._preview.policy_version, report._preview.fingerprint, JSON.stringify(report._preview.summary), req.userId, plan.reason]
        )).rows[0];
        await persistEvaluationSnapshots(client, req.companyId, current.id, report._preview);
      }
      const after = recognitionAuditSnapshot(current, plan.mode === "clear" ? null : report._preview);
      await client.query(
        `INSERT INTO finance_payroll_evaluation_audit (
           company_id, period_id, actor_user_id, action, reason, before_state, after_state
         ) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [req.companyId, current.id, req.userId, plan.action, plan.reason, JSON.stringify(before), JSON.stringify(after)]
      );
      await client.query("COMMIT");
      res.json(publicEvaluationReport(await payrollEvaluationReport(pool, req.companyId, range, context), false));
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendEvaluationError(res, error, "payroll_evaluation_recognition_failed");
    } finally {
      client.release();
    }
  });
}
