import { createHash } from "node:crypto";
import { timeEntryAllocationSnapshot, timeLinkMatchesSnapshot } from "./finance-cost-allocations.js";

const POLICY_VERSION = "reviewed_base_compensation_v1";
const MAX_PERIOD_DAYS = 31;
const MAX_PERIOD_ENTRIES = 500;

export class PayrollCostError extends Error {
  constructor(code, message, statusCode = 400, details = {}) {
    super(message);
    this.name = "PayrollCostError";
    this.code = code;
    this.statusCode = statusCode;
    Object.assign(this, details);
  }
}

function cleanString(value, maxLength = 200) {
  return (value ?? "").toString().trim().slice(0, maxLength);
}

function exactInteger(value, field, { minimum = 0, maximum = Number.MAX_SAFE_INTEGER } = {}) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value.trim()) ? Number(value.trim()) : value;
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new PayrollCostError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return parsed;
}

function safeDbInteger(value, field) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(parsed)) {
    throw new PayrollCostError("payroll_cost_source_inexact", `${field.replaceAll("_", " ")} exceeds the exact supported range.`, 500);
  }
  return parsed;
}

function dateOnly(value, field) {
  const raw = value instanceof Date ? value.toISOString().slice(0, 10) : cleanString(value, 20);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    throw new PayrollCostError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  const [year, month, day] = raw.split("-").map(Number);
  const parsed = new Date(Date.UTC(year, month - 1, day));
  if (parsed.getUTCFullYear() !== year || parsed.getUTCMonth() !== month - 1 || parsed.getUTCDate() !== day) {
    throw new PayrollCostError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
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

export function parsePayrollCostRange(startValue, endValue, { companyToday = null } = {}) {
  const startDate = dateOnly(startValue, "start_date");
  const endDate = dateOnly(endValue, "end_date");
  if (startDate > endDate) {
    throw new PayrollCostError("payroll_cost_range_invalid", "Start date must be on or before end date.");
  }
  if (inclusiveDayCount(startDate, endDate) > MAX_PERIOD_DAYS) {
    throw new PayrollCostError("payroll_cost_range_too_large", `Base-compensation recognition periods cannot exceed ${MAX_PERIOD_DAYS} days.`);
  }
  if (companyToday && endDate > dateOnly(companyToday, "company_today")) {
    throw new PayrollCostError("payroll_cost_future_period", "Base compensation cannot be recognized for a future company date.");
  }
  return { start_date: startDate, end_date: endDate };
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
  }
  return value;
}

export function payrollEvidenceFingerprint(value) {
  return createHash("sha256").update(JSON.stringify(stableValue(value))).digest("hex");
}

function roundRatio(numerator, denominator) {
  const top = BigInt(numerator);
  const bottom = BigInt(denominator);
  if (top < 0n || bottom <= 0n) throw new PayrollCostError("payroll_cost_math_invalid", "Base-compensation math is invalid.", 500);
  const rounded = (top + (bottom / 2n)) / bottom;
  const result = Number(rounded);
  if (!Number.isSafeInteger(result)) throw new PayrollCostError("payroll_cost_math_inexact", "Base compensation exceeds the exact supported range.", 500);
  return result;
}

export function allocateExactCents(totalValue, weightedTargets = []) {
  const totalCents = exactInteger(totalValue, "total_cents");
  if (!Array.isArray(weightedTargets) || !weightedTargets.length) {
    if (totalCents === 0) return [];
    throw new PayrollCostError("payroll_cost_weights_invalid", "Exact cost allocation requires at least one source target.", 500);
  }
  const normalized = weightedTargets.map((target, index) => ({
    ...target,
    key: cleanString(target?.key, 300) || `target-${index}`,
    weight: exactInteger(target?.weight, "allocation_weight")
  }));
  const totalWeight = normalized.reduce((sum, target) => sum + target.weight, 0);
  if (totalWeight <= 0) {
    if (totalCents === 0) return normalized.map((target) => ({ ...target, cents: 0 }));
    throw new PayrollCostError("payroll_cost_weights_invalid", "Exact cost allocation requires positive source time.", 500);
  }
  const total = BigInt(totalCents);
  const denominator = BigInt(totalWeight);
  const shares = normalized.map((target) => {
    const product = total * BigInt(target.weight);
    return { ...target, cents: Number(product / denominator), remainder: product % denominator };
  });
  let remaining = totalCents - shares.reduce((sum, share) => sum + share.cents, 0);
  const order = shares.map((_, index) => index);
  order.sort((left, right) => {
    if (shares[left].remainder === shares[right].remainder) return shares[left].key.localeCompare(shares[right].key);
    return shares[left].remainder > shares[right].remainder ? -1 : 1;
  });
  for (const index of order) {
    if (remaining <= 0) break;
    shares[index].cents += 1;
    remaining -= 1;
  }
  if (remaining !== 0) throw new PayrollCostError("payroll_cost_allocation_inexact", "Base-compensation cents did not reconcile.", 500);
  return shares.map(({ remainder, ...share }) => share);
}

function timestamp(value, field) {
  const parsed = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(parsed.getTime())) throw new PayrollCostError("payroll_time_invalid", `${field.replaceAll("_", " ")} is invalid.`, 409);
  return parsed;
}

function workSeconds(entry) {
  if (!entry.end_at) return { kind: "open", seconds: null };
  const start = timestamp(entry.start_at, "start_at");
  const end = timestamp(entry.end_at, "end_at");
  const elapsed = Math.floor((end.getTime() - start.getTime()) / 1000);
  let breakSeconds;
  try { breakSeconds = exactInteger(entry.break_seconds == null ? 0 : Number(entry.break_seconds), "break_seconds"); }
  catch { return { kind: "invalid", seconds: null }; }
  if (elapsed <= 0 || breakSeconds >= elapsed) return { kind: "invalid", seconds: null };
  return { kind: "valid", seconds: elapsed - breakSeconds };
}

function workWeekStart(workDate, weekStart) {
  const date = new Date(`${workDate}T00:00:00.000Z`);
  const offset = (date.getUTCDay() - weekStart + 7) % 7;
  return addDays(workDate, -offset);
}

function payRowFacts(row) {
  return {
    id: String(row.id),
    employee_id: String(row.employee_id),
    effective_from: dateOnly(row.effective_from, "effective_from"),
    effective_to: row.effective_to == null ? null : dateOnly(row.effective_to, "effective_to"),
    hourly_rate_cents: row.hourly_rate_cents == null ? null : exactInteger(Number(row.hourly_rate_cents), "hourly_rate_cents"),
    daily_base_cents: row.daily_base_cents == null ? null : exactInteger(Number(row.daily_base_cents), "daily_base_cents"),
    commission_tiers: Array.isArray(row.commission_tiers) ? row.commission_tiers.map((tier) => ({
      id: cleanString(tier?.id, 80),
      threshold_cents: exactInteger(Number(tier?.threshold_cents), "commission_threshold_cents"),
      percent_basis_points: exactInteger(Number(tier?.percent_basis_points), "commission_percent_basis_points", { maximum: 10_000 })
    })) : [],
    version: exactInteger(Number(row.version), "pay_structure_version", { minimum: 1 })
  };
}

function applicablePayRows(rows, employeeId, workDate) {
  return rows.filter((row) => String(row.employee_id) === employeeId
    && dateOnly(row.effective_from, "effective_from") <= workDate
    && (row.effective_to == null || dateOnly(row.effective_to, "effective_to") >= workDate));
}

function allocationTargets(entry, seconds) {
  const allocation = entry.allocation || null;
  if (!allocation?.source_current) {
    return [{ key: "unallocated", target_kind: "unallocated", job_id: null, job_title: null, seconds }];
  }
  const targets = Array.isArray(allocation.targets) ? allocation.targets : [];
  if (!targets.length || targets.reduce((sum, target) => sum + Number(target.seconds || 0), 0) !== seconds) {
    return [{ key: "unallocated", target_kind: "unallocated", job_id: null, job_title: null, seconds }];
  }
  const normalized = [];
  for (const target of targets) {
    const sourceSeconds = exactInteger(Number(target.seconds), "target_seconds", { minimum: 1, maximum: seconds });
    const kind = cleanString(target.target_kind, 30);
    const jobExists = target.job_exists !== false;
    if (kind === "job" && target.job_id && jobExists) {
      normalized.push({ key: `job:${target.job_id}`, target_kind: "job", job_id: String(target.job_id), job_title: target.job_title || null, seconds: sourceSeconds });
    } else if (kind === "admin" || kind === "travel") {
      normalized.push({ key: kind, target_kind: kind, job_id: null, job_title: null, seconds: sourceSeconds });
    } else {
      normalized.push({ key: `unallocated:${normalized.length}`, target_kind: "unallocated", job_id: null, job_title: null, seconds: sourceSeconds });
    }
  }
  return normalized;
}

function blocker(code, message, count) {
  return { code, message, count };
}

export function calculateBaseCompensationPreview({ range, entries = [], payStructures = [], weekStart = 1, timezone = "America/New_York" }) {
  const normalizedRange = parsePayrollCostRange(range?.start_date, range?.end_date);
  const normalizedWeekStart = exactInteger(Number(weekStart), "week_start", { maximum: 6 });
  if (!Array.isArray(entries) || entries.length > MAX_PERIOD_ENTRIES + 20) {
    throw new PayrollCostError("payroll_cost_entries_too_many", `A recognition period supports at most ${MAX_PERIOD_ENTRIES} in-period entries.`, 409);
  }
  const structures = payStructures.map(payRowFacts).sort((left, right) =>
    left.employee_id.localeCompare(right.employee_id) || left.effective_from.localeCompare(right.effective_from) || left.id.localeCompare(right.id));
  const sourceEntries = entries.map((entry) => {
    const workDate = dateOnly(entry.work_date, "work_date");
    const duration = workSeconds(entry);
    const employeeId = String(entry.user_id);
    return {
      raw: entry,
      id: String(entry.id),
      employee_id: employeeId,
      employee_name: entry.employee_name || entry.user_email || "Employee",
      work_date: workDate,
      in_period: workDate >= normalizedRange.start_date && workDate <= normalizedRange.end_date,
      start: timestamp(entry.start_at, "start_at"),
      end: entry.end_at ? timestamp(entry.end_at, "end_at") : null,
      manual_status: entry.manual_status || "approved",
      duration_kind: duration.kind,
      work_seconds: duration.seconds
    };
  }).sort((left, right) => left.start - right.start || left.id.localeCompare(right.id));
  const periodEntries = sourceEntries.filter((entry) => entry.in_period);
  if (periodEntries.length > MAX_PERIOD_ENTRIES) {
    throw new PayrollCostError("payroll_cost_entries_too_many", `A recognition period supports at most ${MAX_PERIOD_ENTRIES} entries.`, 409);
  }

  const openPeriod = periodEntries.filter((entry) => entry.manual_status !== "disapproved" && entry.duration_kind === "open");
  const invalidPeriod = periodEntries.filter((entry) => entry.manual_status !== "disapproved" && entry.duration_kind === "invalid");
  const disapprovedPeriod = periodEntries.filter((entry) => entry.manual_status === "disapproved");
  const eligibleContext = sourceEntries.filter((entry) => entry.manual_status !== "disapproved" && entry.duration_kind === "valid");
  const eligiblePeriod = eligibleContext.filter((entry) => entry.in_period);

  const overlapIDs = new Set();
  const byEmployee = new Map();
  for (const entry of eligibleContext) {
    const list = byEmployee.get(entry.employee_id) || [];
    list.push(entry);
    byEmployee.set(entry.employee_id, list);
  }
  for (const list of byEmployee.values()) {
    list.sort((left, right) => left.start - right.start || left.id.localeCompare(right.id));
    let previous = null;
    for (const entry of list) {
      if (previous?.end && entry.start < previous.end) {
        overlapIDs.add(previous.id);
        overlapIDs.add(entry.id);
      }
      if (!previous?.end || (entry.end && entry.end > previous.end)) previous = entry;
    }
  }

  const periodEmployeeWeeks = new Set(eligiblePeriod.map((entry) => `${entry.employee_id}|${workWeekStart(entry.work_date, normalizedWeekStart)}`));
  const contextIncomplete = sourceEntries.filter((entry) => entry.manual_status !== "disapproved"
    && (entry.duration_kind !== "valid" || (!entry.in_period && overlapIDs.has(entry.id)))
    && periodEmployeeWeeks.has(`${entry.employee_id}|${workWeekStart(entry.work_date, normalizedWeekStart)}`));
  const weeklySeconds = new Map();
  for (const entry of eligibleContext) {
    const key = `${entry.employee_id}|${workWeekStart(entry.work_date, normalizedWeekStart)}`;
    weeklySeconds.set(key, (weeklySeconds.get(key) || 0) + entry.work_seconds);
  }

  const missingPay = [];
  const overlappingPay = [];
  const calculated = [];
  for (const entry of eligiblePeriod) {
    const matches = applicablePayRows(structures, entry.employee_id, entry.work_date);
    if (!matches.length) {
      missingPay.push(entry);
      continue;
    }
    if (matches.length > 1) {
      overlappingPay.push(entry);
      continue;
    }
    const pay = matches[0];
    const hourlyCents = pay.hourly_rate_cents == null
      ? 0
      : roundRatio(BigInt(pay.hourly_rate_cents) * BigInt(entry.work_seconds), 3_600n);
    const weekKey = `${entry.employee_id}|${workWeekStart(entry.work_date, normalizedWeekStart)}`;
    calculated.push({
      ...entry,
      pay,
      hourly_pay_cents: hourlyCents,
      daily_base_pay_cents: 0,
      overtime_exposure: (weeklySeconds.get(weekKey) || 0) > 40 * 3_600,
      overtime_context_incomplete: contextIncomplete.some((candidate) =>
        `${candidate.employee_id}|${workWeekStart(candidate.work_date, normalizedWeekStart)}` === weekKey),
      commission_excluded: pay.commission_tiers.length > 0
    });
  }

  const dailyGroups = new Map();
  for (const entry of calculated) {
    const key = `${entry.employee_id}|${entry.work_date}`;
    const list = dailyGroups.get(key) || [];
    list.push(entry);
    dailyGroups.set(key, list);
  }
  for (const list of dailyGroups.values()) {
    const dailyBaseCents = list[0].pay.daily_base_cents;
    if (dailyBaseCents == null) continue;
    const shares = allocateExactCents(dailyBaseCents, list.map((entry) => ({ key: entry.id, weight: entry.work_seconds })));
    const shareMap = new Map(shares.map((share) => [share.key, share.cents]));
    for (const entry of list) entry.daily_base_pay_cents = shareMap.get(entry.id) || 0;
  }

  const lines = calculated.map((entry) => {
    const basePayCents = entry.hourly_pay_cents + entry.daily_base_pay_cents;
    if (!Number.isSafeInteger(basePayCents)) throw new PayrollCostError("payroll_cost_math_inexact", "Base compensation exceeds the exact supported range.", 500);
    const targets = allocationTargets(entry.raw, entry.work_seconds);
    const targetShares = allocateExactCents(basePayCents, targets.map((target) => ({ ...target, key: target.key, weight: target.seconds })));
    return {
      time_entry_id: entry.id,
      employee_id: entry.employee_id,
      employee_name: entry.employee_name,
      work_date: entry.work_date,
      source_start_at: entry.start.toISOString(),
      source_end_at: entry.end.toISOString(),
      source_break_seconds: exactInteger(Number(entry.raw.break_seconds || 0), "break_seconds"),
      source_work_seconds: entry.work_seconds,
      pay_structure_id: entry.pay.id,
      pay_structure_version: entry.pay.version,
      hourly_rate_cents: entry.pay.hourly_rate_cents,
      daily_base_rate_cents: entry.pay.daily_base_cents,
      hourly_pay_cents: entry.hourly_pay_cents,
      daily_base_pay_cents: entry.daily_base_pay_cents,
      base_pay_cents: basePayCents,
      overtime_exposure: entry.overtime_exposure,
      overtime_context_incomplete: entry.overtime_context_incomplete,
      commission_excluded: entry.commission_excluded,
      allocations: targetShares.map((target, index) => ({
        line_order: index,
        target_kind: target.target_kind,
        job_id: target.job_id,
        job_title: target.job_title,
        source_seconds: target.seconds,
        base_pay_cents: target.cents
      }))
    };
  });

  const blockers = [];
  if (!eligiblePeriod.length) blockers.push(blocker("payroll_cost_no_eligible_time", "No eligible completed clock entries exist in this period.", 0));
  if (openPeriod.length) blockers.push(blocker("payroll_cost_open_time", "Clock out every open entry in the period before recognizing base compensation.", openPeriod.length));
  if (invalidPeriod.length) blockers.push(blocker("payroll_cost_invalid_time", "Correct invalid completed durations before recognizing base compensation.", invalidPeriod.length));
  const overlappingPeriodCount = periodEntries.filter((entry) => overlapIDs.has(entry.id)).length;
  if (overlappingPeriodCount) blockers.push(blocker("payroll_cost_overlapping_time", "Correct overlapping employee time entries before recognizing base compensation.", overlappingPeriodCount));
  if (missingPay.length) blockers.push(blocker("payroll_cost_missing_pay", "Configure an effective company pay structure for every eligible entry.", missingPay.length));
  if (overlappingPay.length) blockers.push(blocker("payroll_cost_overlapping_pay", "Correct overlapping effective pay structures before recognizing base compensation.", overlappingPay.length));
  if (contextIncomplete.length) blockers.push(blocker("payroll_cost_overtime_context_incomplete", "Complete or correct surrounding workweek entries so overtime exposure can be identified.", contextIncomplete.length));

  const employeeMap = new Map();
  const jobMap = new Map();
  const targetTotals = { job: 0, admin: 0, travel: 0, unallocated: 0 };
  for (const line of lines) {
    const employee = employeeMap.get(line.employee_id) || {
      employee_id: line.employee_id, employee_name: line.employee_name,
      work_seconds: 0, hourly_pay_cents: 0, daily_base_pay_cents: 0, supported_base_pay_cents: 0,
      job_base_pay_cents: 0, admin_base_pay_cents: 0, travel_base_pay_cents: 0, unallocated_base_pay_cents: 0,
      overtime_exposure: false, commission_excluded: false
    };
    employee.work_seconds += line.source_work_seconds;
    employee.hourly_pay_cents += line.hourly_pay_cents;
    employee.daily_base_pay_cents += line.daily_base_pay_cents;
    employee.supported_base_pay_cents += line.base_pay_cents;
    employee.overtime_exposure ||= line.overtime_exposure;
    employee.commission_excluded ||= line.commission_excluded;
    for (const allocation of line.allocations) {
      const field = `${allocation.target_kind}_base_pay_cents`;
      employee[field] += allocation.base_pay_cents;
      targetTotals[allocation.target_kind] += allocation.base_pay_cents;
      if (allocation.target_kind === "job") {
        const current = jobMap.get(allocation.job_id) || {
          job_id: allocation.job_id, job_title: allocation.job_title || "Job",
          work_seconds: 0, supported_base_pay_cents: 0
        };
        current.work_seconds += allocation.source_seconds;
        current.supported_base_pay_cents += allocation.base_pay_cents;
        jobMap.set(allocation.job_id, current);
      }
    }
    employeeMap.set(line.employee_id, employee);
  }

  const supportedBasePayCents = lines.reduce((sum, line) => sum + line.base_pay_cents, 0);
  if (supportedBasePayCents !== Object.values(targetTotals).reduce((sum, cents) => sum + cents, 0)) {
    throw new PayrollCostError("payroll_cost_target_reconciliation_failed", "Target base-compensation cents did not reconcile.", 500);
  }
  const employees = [...employeeMap.values()].sort((left, right) => left.employee_name.localeCompare(right.employee_name) || left.employee_id.localeCompare(right.employee_id));
  const jobs = [...jobMap.values()].sort((left, right) => right.supported_base_pay_cents - left.supported_base_pay_cents || left.job_id.localeCompare(right.job_id));
  const summary = {
    eligible_entry_count: eligiblePeriod.length,
    recognized_source_count: lines.length,
    employee_count: employees.length,
    work_seconds: lines.reduce((sum, line) => sum + line.source_work_seconds, 0),
    hourly_base_cents: lines.reduce((sum, line) => sum + line.hourly_pay_cents, 0),
    daily_base_cents: lines.reduce((sum, line) => sum + line.daily_base_pay_cents, 0),
    supported_base_pay_cents: supportedBasePayCents,
    job_base_pay_cents: targetTotals.job,
    admin_base_pay_cents: targetTotals.admin,
    travel_base_pay_cents: targetTotals.travel,
    unallocated_base_pay_cents: targetTotals.unallocated,
    open_entry_count: openPeriod.length,
    disapproved_entry_count: disapprovedPeriod.length,
    invalid_entry_count: invalidPeriod.length,
    overlapping_entry_count: overlappingPeriodCount,
    missing_pay_entry_count: missingPay.length,
    overlapping_pay_entry_count: overlappingPay.length,
    overtime_exposure_employee_count: employees.filter((employee) => employee.overtime_exposure).length,
    overtime_context_incomplete_count: contextIncomplete.length,
    commission_excluded_employee_count: employees.filter((employee) => employee.commission_excluded).length
  };
  const warnings = [
    "Supported base compensation includes reviewed hourly and daily-base cents only. Commission, overtime premiums, payroll taxes, withholding, benefits, reimbursements, and burden are unknown rather than zero.",
    "A fixed company workweek identifies possible federal overtime exposure only; exemption, regular-rate, jurisdiction, and state daily-overtime rules are not configured.",
    "Job, Administration, Travel, and Unallocated cents follow current reviewed time evidence. This operational snapshot does not post cash P&L, create a paycheck, or run provider payroll."
  ];
  if (summary.unallocated_base_pay_cents) warnings.push("Unallocated base compensation is recognized to the employee period but excluded from job labor attribution.");
  if (summary.overtime_exposure_employee_count) warnings.push("At least one employee exceeds 40 recorded hours in a company workweek; the required overtime premium remains unsupported and excluded.");
  if (summary.commission_excluded_employee_count) warnings.push("Configured commission tiers are snapshotted for coverage, but no commission earning or correction is recognized in this phase.");

  const fingerprintEvidence = {
    policy_version: POLICY_VERSION,
    range: normalizedRange,
    timezone,
    week_start: normalizedWeekStart,
    entries: sourceEntries.map((entry) => ({
      id: entry.id, employee_id: entry.employee_id, work_date: entry.work_date,
      start_at: entry.start.toISOString(), end_at: entry.end?.toISOString() || null,
      break_seconds: entry.raw.break_seconds == null ? 0 : entry.raw.break_seconds,
      manual_status: entry.manual_status,
      allocation: entry.raw.allocation || null
    })),
    pay_structures: structures
  };
  return {
    policy_version: POLICY_VERSION,
    ...normalizedRange,
    timezone,
    week_start: normalizedWeekStart,
    can_recognize: blockers.length === 0,
    fingerprint: payrollEvidenceFingerprint(fingerprintEvidence),
    summary,
    blockers,
    warnings,
    employees,
    jobs,
    lines
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
    version: safeDbInteger(row.version, "version")
  };
}

export function planPayrollRecognitionUpdate({ body = {}, currentRecognition = null, preview, overlappingRecognitionCount = 0 }) {
  const expectedVersion = exactInteger(body.expected_version, "expected_version");
  const reason = cleanString(body.reason, 500);
  if (!reason) throw new PayrollCostError("payroll_cost_reason_required", "Add a reason for this base-compensation change.");
  const action = cleanString(body.action, 40);
  if (!['recognize', 'clear'].includes(action)) throw new PayrollCostError("payroll_cost_action_invalid", "Choose Recognize or Clear.");
  const currentVersion = currentRecognition ? exactInteger(Number(currentRecognition.version), "version", { minimum: 1 }) : 0;
  if (expectedVersion !== currentVersion) {
    throw new PayrollCostError("payroll_cost_stale", "This base-compensation recognition changed after it was loaded. Refresh before saving again.", 409, { current_version: currentVersion });
  }
  if (action === "clear") {
    if (!currentRecognition || currentRecognition.status === "cleared") return { mode: "replay", action, reason, current_version: currentVersion };
    return { mode: "clear", action: "base_compensation_cleared", reason, current_version: currentVersion };
  }
  if (!preview?.can_recognize) {
    throw new PayrollCostError("payroll_cost_preview_blocked", "Resolve every blocking source issue before recognizing base compensation.", 409, { blockers: preview?.blockers || [] });
  }
  if (overlappingRecognitionCount > 0) {
    throw new PayrollCostError("payroll_cost_period_overlap", "Another active recognized period overlaps these dates. Clear or choose a non-overlapping period.", 409);
  }
  if (currentRecognition?.status === "recognized"
      && currentRecognition.policy_version === preview.policy_version
      && currentRecognition.source_fingerprint === preview.fingerprint) {
    return { mode: "replay", action, reason, current_version: currentVersion };
  }
  return {
    mode: currentRecognition ? "replace" : "create",
    action: currentRecognition ? "base_compensation_refreshed" : "base_compensation_recognized",
    reason,
    current_version: currentVersion
  };
}

export async function installFinancePayrollCostSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS finance_payroll_cost_periods (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
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
    CREATE INDEX IF NOT EXISTS finance_payroll_cost_periods_company_dates_idx
      ON finance_payroll_cost_periods(company_id, start_date, end_date, status);

    CREATE TABLE IF NOT EXISTS finance_payroll_cost_lines (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      period_id UUID NOT NULL REFERENCES finance_payroll_cost_periods(id) ON DELETE CASCADE,
      time_entry_id TEXT NOT NULL,
      employee_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
      work_date DATE NOT NULL,
      source_start_at TIMESTAMPTZ NOT NULL,
      source_end_at TIMESTAMPTZ NOT NULL,
      source_break_seconds INTEGER NOT NULL,
      source_work_seconds INTEGER NOT NULL,
      pay_structure_id UUID NOT NULL REFERENCES employee_pay_structures(id) ON DELETE RESTRICT,
      pay_structure_version INTEGER NOT NULL,
      hourly_rate_cents BIGINT,
      daily_base_rate_cents BIGINT,
      hourly_pay_cents BIGINT NOT NULL,
      daily_base_pay_cents BIGINT NOT NULL,
      base_pay_cents BIGINT NOT NULL,
      overtime_exposure BOOLEAN NOT NULL DEFAULT false,
      overtime_context_incomplete BOOLEAN NOT NULL DEFAULT false,
      commission_excluded BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, period_id, time_entry_id),
      CHECK (source_end_at > source_start_at),
      CHECK (source_break_seconds >= 0),
      CHECK (source_work_seconds > 0),
      CHECK (pay_structure_version > 0),
      CHECK (hourly_rate_cents IS NULL OR hourly_rate_cents >= 0),
      CHECK (daily_base_rate_cents IS NULL OR daily_base_rate_cents >= 0),
      CHECK (hourly_pay_cents >= 0 AND daily_base_pay_cents >= 0 AND base_pay_cents >= 0),
      CHECK (hourly_pay_cents + daily_base_pay_cents = base_pay_cents)
    );
    CREATE INDEX IF NOT EXISTS finance_payroll_cost_lines_company_employee_date_idx
      ON finance_payroll_cost_lines(company_id, employee_id, work_date);
    CREATE INDEX IF NOT EXISTS finance_payroll_cost_lines_period_idx
      ON finance_payroll_cost_lines(company_id, period_id, work_date, time_entry_id);

    CREATE TABLE IF NOT EXISTS finance_payroll_cost_allocations (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      period_id UUID NOT NULL REFERENCES finance_payroll_cost_periods(id) ON DELETE CASCADE,
      cost_line_id UUID NOT NULL REFERENCES finance_payroll_cost_lines(id) ON DELETE CASCADE,
      line_order SMALLINT NOT NULL,
      target_kind TEXT NOT NULL,
      job_id TEXT,
      source_seconds INTEGER NOT NULL,
      base_pay_cents BIGINT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, cost_line_id, line_order),
      CHECK (line_order >= 0 AND line_order <= 50),
      CHECK (target_kind IN ('job','admin','travel','unallocated')),
      CHECK ((target_kind = 'job' AND job_id IS NOT NULL) OR (target_kind <> 'job' AND job_id IS NULL)),
      CHECK (source_seconds > 0),
      CHECK (base_pay_cents >= 0)
    );
    CREATE INDEX IF NOT EXISTS finance_payroll_cost_allocations_company_job_idx
      ON finance_payroll_cost_allocations(company_id, job_id) WHERE job_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS finance_payroll_cost_allocations_period_idx
      ON finance_payroll_cost_allocations(company_id, period_id, cost_line_id, line_order);

    CREATE TABLE IF NOT EXISTS finance_payroll_cost_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      period_id UUID NOT NULL REFERENCES finance_payroll_cost_periods(id) ON DELETE RESTRICT,
      actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      reason TEXT NOT NULL,
      before_state JSONB,
      after_state JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS finance_payroll_cost_audit_company_period_idx
      ON finance_payroll_cost_audit(company_id, period_id, created_at DESC);
  `);
}

export async function loadCompanyContext(client, companyId) {
  const { rows } = await client.query(
    `SELECT COALESCE(NULLIF(c.timezone, ''), 'America/New_York') AS timezone,
            (now() AT TIME ZONE COALESCE(NULLIF(c.timezone, ''), 'America/New_York'))::date::text AS company_today,
            COALESCE(t.week_start, 1)::int AS week_start
       FROM companies c LEFT JOIN time_clock_settings t ON t.company_id = c.id
      WHERE c.id = $1`,
    [companyId]
  );
  if (!rows[0]) throw new PayrollCostError("company_not_found", "The company workspace was not found.", 404);
  return rows[0];
}

function surroundingWorkweekRange(range, weekStart) {
  const start = workWeekStart(range.start_date, weekStart);
  const endWeek = workWeekStart(range.end_date, weekStart);
  return { start_date: start, end_date: addDays(endWeek, 6) };
}

async function loadPayrollEvidence(client, companyId, range, context, { lock = false } = {}) {
  const extended = surroundingWorkweekRange(range, Number(context.week_start));
  const entryResult = await client.query(
    `SELECT e.id, e.user_id, e.start_at, e.end_at, COALESCE(e.break_seconds, 0) AS break_seconds,
            e.manual_status, e.manual_entry,
            COALESCE(NULLIF(u.display_name, ''), u.email) AS employee_name,
            to_char(e.start_at AT TIME ZONE $4, 'YYYY-MM-DD') AS work_date
       FROM time_clock_entries e
       JOIN users u ON u.id = e.user_id AND u.company_id = e.company_id
      WHERE e.company_id = $1
        AND e.start_at >= ($2::date::timestamp AT TIME ZONE $4)
        AND e.start_at < (($3::date + 1)::timestamp AT TIME ZONE $4)
      ORDER BY e.start_at, e.id
      LIMIT $5${lock ? " FOR UPDATE OF e" : ""}`,
    [companyId, extended.start_date, extended.end_date, context.timezone, MAX_PERIOD_ENTRIES + 21]
  );
  const inPeriodCount = entryResult.rows.filter((row) => row.work_date >= range.start_date && row.work_date <= range.end_date).length;
  if (inPeriodCount > MAX_PERIOD_ENTRIES || entryResult.rows.length > MAX_PERIOD_ENTRIES + 20) {
    throw new PayrollCostError("payroll_cost_entries_too_many", `A recognition period supports at most ${MAX_PERIOD_ENTRIES} time entries.`, 409);
  }
  const employeeIds = [...new Set(entryResult.rows.map((row) => String(row.user_id)))];
  const payResult = employeeIds.length
    ? await client.query(
      `SELECT * FROM employee_pay_structures
        WHERE company_id = $1 AND employee_id = ANY($2::uuid[])
          AND effective_from <= $4::date
          AND (effective_to IS NULL OR effective_to >= $3::date)
        ORDER BY employee_id, effective_from, id${lock ? " FOR UPDATE" : ""}`,
      [companyId, employeeIds, range.start_date, range.end_date]
    )
    : { rows: [] };
  const periodEntryIds = entryResult.rows
    .filter((row) => row.work_date >= range.start_date && row.work_date <= range.end_date)
    .map((row) => String(row.id));
  const headerResult = periodEntryIds.length
    ? await client.query(
      `SELECT l.*, sj.title AS whole_job_title, (sj.id IS NOT NULL) AS whole_job_exists
         FROM finance_time_job_links l
         LEFT JOIN schedule_events sj ON sj.company_id = l.company_id AND sj.id = l.job_id
        WHERE l.company_id = $1 AND l.time_entry_id = ANY($2::text[])
        ORDER BY l.time_entry_id${lock ? " FOR UPDATE OF l" : ""}`,
      [companyId, periodEntryIds]
    )
    : { rows: [] };
  const linkIds = headerResult.rows.map((row) => row.id);
  const allocationResult = linkIds.length
    ? await client.query(
      `SELECT al.*, sj.title AS job_title, (sj.id IS NOT NULL) AS job_exists
         FROM finance_time_allocation_lines al
         LEFT JOIN schedule_events sj ON sj.company_id = al.company_id AND sj.id = al.job_id
        WHERE al.company_id = $1 AND al.link_id = ANY($2::uuid[])
        ORDER BY al.time_entry_id, al.line_order${lock ? " FOR UPDATE OF al" : ""}`,
      [companyId, linkIds]
    )
    : { rows: [] };
  const headerMap = new Map(headerResult.rows.map((row) => [String(row.time_entry_id), row]));
  const linesByHeader = new Map();
  for (const row of allocationResult.rows) {
    const key = String(row.link_id);
    const list = linesByHeader.get(key) || [];
    list.push(row);
    linesByHeader.set(key, list);
  }
  const entries = entryResult.rows.map((entry) => {
    const header = headerMap.get(String(entry.id));
    if (!header) return { ...entry, allocation: null };
    let sourceCurrent = false;
    try { sourceCurrent = timeLinkMatchesSnapshot(header, timeEntryAllocationSnapshot(entry)); } catch { /* invalid source stays stale */ }
    const lines = linesByHeader.get(String(header.id)) || [];
    let targets;
    if (lines.length) {
      targets = lines.map((line) => ({
        target_kind: line.target_kind,
        job_id: line.job_id || null,
        job_title: line.job_title || null,
        job_exists: line.target_kind === "job" ? Boolean(line.job_exists) : true,
        seconds: safeDbInteger(line.allocated_seconds, "allocated_seconds")
      }));
    } else if (header.job_id) {
      targets = [{
        target_kind: "job", job_id: header.job_id, job_title: header.whole_job_title || null,
        job_exists: Boolean(header.whole_job_exists), seconds: safeDbInteger(header.source_work_seconds, "source_work_seconds")
      }];
    } else {
      targets = [];
    }
    return {
      ...entry,
      allocation: {
        version: safeDbInteger(header.version, "allocation_version"),
        source_current: sourceCurrent,
        mode: lines.length ? "split" : header.job_id ? "whole_job" : "unallocated",
        targets
      }
    };
  });
  return { entries, payStructures: payResult.rows };
}

function storedRecognitionPayload(row, preview = null) {
  if (!row) return null;
  const snapshot = recognitionSnapshot(row);
  const sourceCurrent = row.status === "recognized"
    && row.policy_version === preview?.policy_version
    && row.source_fingerprint === preview?.fingerprint;
  return {
    ...snapshot,
    recognized_by: row.recognized_by || null,
    recognized_at: row.recognized_at || null,
    reason: row.reason,
    created_at: row.created_at || null,
    updated_at: row.updated_at || null,
    source_current: sourceCurrent,
    current_recognized_base_pay_cents: sourceCurrent ? safeDbInteger(row.summary?.supported_base_pay_cents || 0, "supported_base_pay_cents") : 0
  };
}

function previewPayload(preview) {
  const { lines, fingerprint, ...safe } = preview;
  return safe;
}

export async function payrollCostReport(client, companyId, range, context, { lock = false } = {}) {
  const evidence = await loadPayrollEvidence(client, companyId, range, context, { lock });
  const preview = calculateBaseCompensationPreview({
    range,
    entries: evidence.entries,
    payStructures: evidence.payStructures,
    weekStart: Number(context.week_start),
    timezone: context.timezone
  });
  const recognitionResult = await client.query(
    `SELECT * FROM finance_payroll_cost_periods
      WHERE company_id = $1 AND start_date = $2::date AND end_date = $3::date${lock ? " FOR UPDATE" : ""}`,
    [companyId, range.start_date, range.end_date]
  );
  const recognition = recognitionResult.rows[0] || null;
  const auditResult = recognition
    ? await client.query(
      `SELECT id, actor_user_id, action, reason, before_state, after_state, created_at
         FROM finance_payroll_cost_audit
        WHERE company_id = $1 AND period_id = $2
        ORDER BY created_at DESC, id DESC LIMIT 100`,
      [companyId, recognition.id]
    )
    : { rows: [] };
  return {
    basis: POLICY_VERSION,
    currency: "usd",
    start_date: range.start_date,
    end_date: range.end_date,
    timezone: context.timezone,
    week_start: Number(context.week_start),
    recognition: storedRecognitionPayload(recognition, preview),
    preview: previewPayload(preview),
    audit: auditResult.rows.map((row) => ({
      id: String(row.id), actor_user_id: row.actor_user_id || null, action: row.action,
      reason: row.reason, before: row.before_state || null, after: row.after_state || null,
      created_at: row.created_at
    })),
    _preview: preview,
    _recognition: recognition
  };
}

function sendPayrollCostError(res, error, fallback) {
  if (error instanceof PayrollCostError || error?.statusCode) {
    return res.status(error.statusCode || 400).json({
      error: error.code || fallback,
      message: error.message,
      current_version: error.current_version,
      blockers: error.blockers
    });
  }
  console.error("[finance-payroll-costs]", fallback, { code: error?.code, message: error?.message });
  return res.status(500).json({ error: fallback, message: "Base-compensation request failed." });
}

function publicReport(report, replayed = undefined) {
  const { _preview, _recognition, ...payload } = report;
  return replayed == null ? payload : { ...payload, replayed };
}

async function persistPreviewLines(client, companyId, periodId, preview) {
  await client.query(`DELETE FROM finance_payroll_cost_lines WHERE company_id = $1 AND period_id = $2`, [companyId, periodId]);
  if (!preview.lines.length) return;
  const lineRows = preview.lines.map((line) => ({
    time_entry_id: line.time_entry_id, employee_id: line.employee_id, work_date: line.work_date,
    source_start_at: line.source_start_at, source_end_at: line.source_end_at,
    source_break_seconds: line.source_break_seconds, source_work_seconds: line.source_work_seconds,
    pay_structure_id: line.pay_structure_id, pay_structure_version: line.pay_structure_version,
    hourly_rate_cents: line.hourly_rate_cents, daily_base_rate_cents: line.daily_base_rate_cents,
    hourly_pay_cents: line.hourly_pay_cents, daily_base_pay_cents: line.daily_base_pay_cents,
    base_pay_cents: line.base_pay_cents, overtime_exposure: line.overtime_exposure,
    overtime_context_incomplete: line.overtime_context_incomplete, commission_excluded: line.commission_excluded
  }));
  const inserted = await client.query(
    `INSERT INTO finance_payroll_cost_lines (
       company_id, period_id, time_entry_id, employee_id, work_date, source_start_at, source_end_at,
       source_break_seconds, source_work_seconds, pay_structure_id, pay_structure_version,
       hourly_rate_cents, daily_base_rate_cents, hourly_pay_cents, daily_base_pay_cents,
       base_pay_cents, overtime_exposure, overtime_context_incomplete, commission_excluded
     )
     SELECT $1, $2, x.time_entry_id, x.employee_id::uuid, x.work_date::date,
            x.source_start_at::timestamptz, x.source_end_at::timestamptz,
            x.source_break_seconds, x.source_work_seconds, x.pay_structure_id::uuid,
            x.pay_structure_version, x.hourly_rate_cents, x.daily_base_rate_cents,
            x.hourly_pay_cents, x.daily_base_pay_cents, x.base_pay_cents,
            x.overtime_exposure, x.overtime_context_incomplete, x.commission_excluded
       FROM jsonb_to_recordset($3::jsonb) AS x(
         time_entry_id text, employee_id text, work_date text, source_start_at text, source_end_at text,
         source_break_seconds integer, source_work_seconds integer, pay_structure_id text,
         pay_structure_version integer, hourly_rate_cents bigint, daily_base_rate_cents bigint,
         hourly_pay_cents bigint, daily_base_pay_cents bigint, base_pay_cents bigint,
         overtime_exposure boolean, overtime_context_incomplete boolean, commission_excluded boolean
       )
     RETURNING id, time_entry_id`,
    [companyId, periodId, JSON.stringify(lineRows)]
  );
  const lineIds = new Map(inserted.rows.map((row) => [String(row.time_entry_id), String(row.id)]));
  const allocationRows = preview.lines.flatMap((line) => line.allocations.map((allocation) => ({
    cost_line_id: lineIds.get(line.time_entry_id),
    line_order: allocation.line_order,
    target_kind: allocation.target_kind,
    job_id: allocation.job_id,
    source_seconds: allocation.source_seconds,
    base_pay_cents: allocation.base_pay_cents
  })));
  await client.query(
    `INSERT INTO finance_payroll_cost_allocations (
       company_id, period_id, cost_line_id, line_order, target_kind, job_id, source_seconds, base_pay_cents
     )
     SELECT $1, $2, x.cost_line_id::uuid, x.line_order, x.target_kind, x.job_id,
            x.source_seconds, x.base_pay_cents
       FROM jsonb_to_recordset($3::jsonb) AS x(
         cost_line_id text, line_order integer, target_kind text, job_id text,
         source_seconds integer, base_pay_cents bigint
       )`,
    [companyId, periodId, JSON.stringify(allocationRows)]
  );
}

export function installFinancePayrollCostRoutes({ app, pool, authRequired, requireFinanceAccess }) {
  app.get("/api/finance/accounting/payroll-costs", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Accounting requires a company workspace." });
    try {
      const context = await loadCompanyContext(pool, req.companyId);
      const range = parsePayrollCostRange(req.query.start_date, req.query.end_date, { companyToday: context.company_today });
      const report = await payrollCostReport(pool, req.companyId, range, context);
      res.json(publicReport(report));
    } catch (error) {
      sendPayrollCostError(res, error, "payroll_costs_load_failed");
    }
  });

  app.put("/api/finance/accounting/payroll-costs/recognition", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Accounting requires a company workspace." });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(`SELECT pg_advisory_xact_lock(hashtext($1::text))`, [req.companyId]);
      const context = await loadCompanyContext(client, req.companyId);
      const range = parsePayrollCostRange(req.body?.start_date, req.body?.end_date, { companyToday: context.company_today });
      const report = await payrollCostReport(client, req.companyId, range, context, { lock: true });
      const overlapResult = req.body?.action === "recognize"
        ? await client.query(
          `SELECT id FROM finance_payroll_cost_periods
            WHERE company_id = $1 AND status = 'recognized'
              AND id IS DISTINCT FROM $4::uuid
              AND start_date <= $3::date AND end_date >= $2::date
            FOR UPDATE`,
          [req.companyId, range.start_date, range.end_date, report._recognition?.id || null]
        )
        : { rowCount: 0 };
      const plan = planPayrollRecognitionUpdate({
        body: req.body,
        currentRecognition: report._recognition,
        preview: report._preview,
        overlappingRecognitionCount: overlapResult.rowCount
      });
      if (plan.mode === "replay") {
        await client.query("COMMIT");
        return res.json(publicReport(report, true));
      }
      const before = recognitionSnapshot(report._recognition);
      let current;
      if (plan.mode === "clear") {
        current = (await client.query(
          `UPDATE finance_payroll_cost_periods
              SET status = 'cleared', version = version + 1, reason = $4,
                  recognized_by = $5, updated_at = now()
            WHERE company_id = $1 AND start_date = $2::date AND end_date = $3::date
            RETURNING *`,
          [req.companyId, range.start_date, range.end_date, plan.reason, req.userId]
        )).rows[0];
      } else if (plan.mode === "create") {
        current = (await client.query(
          `INSERT INTO finance_payroll_cost_periods (
             company_id, start_date, end_date, status, policy_version, source_fingerprint,
             summary, recognized_by, recognized_at, reason
           ) VALUES ($1,$2::date,$3::date,'recognized',$4,$5,$6,$7,now(),$8)
           RETURNING *`,
          [req.companyId, range.start_date, range.end_date, report._preview.policy_version,
            report._preview.fingerprint, JSON.stringify(report._preview.summary), req.userId, plan.reason]
        )).rows[0];
        await persistPreviewLines(client, req.companyId, current.id, report._preview);
      } else {
        current = (await client.query(
          `UPDATE finance_payroll_cost_periods
              SET status = 'recognized', policy_version = $4, source_fingerprint = $5,
                  summary = $6, version = version + 1, recognized_by = $7,
                  recognized_at = now(), reason = $8, updated_at = now()
            WHERE company_id = $1 AND start_date = $2::date AND end_date = $3::date
            RETURNING *`,
          [req.companyId, range.start_date, range.end_date, report._preview.policy_version,
            report._preview.fingerprint, JSON.stringify(report._preview.summary), req.userId, plan.reason]
        )).rows[0];
        await persistPreviewLines(client, req.companyId, current.id, report._preview);
      }
      const after = recognitionSnapshot(current);
      await client.query(
        `INSERT INTO finance_payroll_cost_audit (
           company_id, period_id, actor_user_id, action, reason, before_state, after_state
         ) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [req.companyId, current.id, req.userId, plan.action, plan.reason,
          JSON.stringify(before), JSON.stringify(after)]
      );
      await client.query("COMMIT");
      const refreshed = await payrollCostReport(pool, req.companyId, range, context);
      res.json(publicReport(refreshed, false));
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendPayrollCostError(res, error, "payroll_cost_recognition_failed");
    } finally {
      client.release();
    }
  });
}
