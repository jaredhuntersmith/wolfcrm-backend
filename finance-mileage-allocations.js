const MAX_REPORT_DAYS = 731;
const MAX_REPORT_ROWS = 500;
const MAX_ALLOCATION_LEGS = 100;
const MAX_CANDIDATE_JOBS = 100;
const ELIGIBLE_STATUSES = new Set(["approved", "paid"]);
const TARGET_KINDS = new Set(["job", "overhead"]);

export class MileageAllocationError extends Error {
  constructor(code, message, statusCode = 400, details = {}) {
    super(message);
    this.name = "MileageAllocationError";
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
    throw new MileageAllocationError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return parsed;
}

function dateOnly(value, field) {
  const raw = cleanString(value, 20);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    throw new MileageAllocationError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  const [year, month, day] = raw.split("-").map(Number);
  const parsed = new Date(Date.UTC(year, month - 1, day));
  if (parsed.getUTCFullYear() !== year || parsed.getUTCMonth() !== month - 1 || parsed.getUTCDate() !== day) {
    throw new MileageAllocationError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return raw;
}

function addDays(value, days) {
  const [year, month, day] = value.split("-").map(Number);
  return new Date(Date.UTC(year, month - 1, day + days)).toISOString().slice(0, 10);
}

export function parseMileageAllocationRange(startValue, endValue) {
  const startDate = dateOnly(startValue, "start_date");
  const endDate = dateOnly(endValue, "end_date");
  if (startDate > endDate) {
    throw new MileageAllocationError("accounting_range_invalid", "Start date must be on or before end date.");
  }
  if (addDays(startDate, MAX_REPORT_DAYS - 1) < endDate) {
    throw new MileageAllocationError(
      "accounting_range_too_large",
      `Mileage allocation ranges cannot exceed ${MAX_REPORT_DAYS} days.`
    );
  }
  return { start_date: startDate, end_date: endDate };
}

function scaledNumber(value, scale, field, maximum = Number.MAX_SAFE_INTEGER) {
  const parsed = Number(value);
  const scaled = Math.round(parsed * scale);
  if (!Number.isFinite(parsed) || parsed < 0 || !Number.isSafeInteger(scaled) || scaled > maximum) {
    throw new MileageAllocationError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`, 409);
  }
  return scaled;
}

function safeDbInteger(value, field) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(parsed)) {
    throw new MileageAllocationError("mileage_allocation_source_inexact", `${field.replaceAll("_", " ")} exceeds exact integer range.`, 500);
  }
  return parsed;
}

function optionalScaledNonnegative(value, scale, maximum = Number.MAX_SAFE_INTEGER) {
  const parsed = Number(value);
  const scaled = Math.round(parsed * scale);
  return Number.isFinite(parsed) && parsed >= 0 && Number.isSafeInteger(scaled) && scaled <= maximum
    ? scaled
    : null;
}

export function mileageSourceSnapshot(log = {}, legs = []) {
  if (!ELIGIBLE_STATUSES.has(log.status)) {
    throw new MileageAllocationError(
      "mileage_log_not_approved",
      "Only approved or paid mileage can be allocated in accounting.",
      409
    );
  }
  if (legs.length > MAX_ALLOCATION_LEGS) {
    throw new MileageAllocationError(
      "mileage_allocation_legs_too_many",
      `A mileage day can contain at most ${MAX_ALLOCATION_LEGS} allocation legs.`,
      409
    );
  }
  const reimbursementCents = exactInteger(Number(log.reimbursement_cents), "reimbursement_cents");
  const rateCents = exactInteger(Number(log.rate_cents_per_mile), "rate_cents_per_mile");
  const sorted = [...legs].sort((left, right) => Number(left.sequence) - Number(right.sequence) || String(left.id).localeCompare(String(right.id)));
  const seenIDs = new Set();
  const seenSequences = new Set();
  const normalizedLegs = sorted.map((leg) => {
    const id = cleanString(leg.id, 160);
    const sequence = exactInteger(Number(leg.sequence), "mileage_leg_sequence", { minimum: 1, maximum: MAX_ALLOCATION_LEGS });
    if (!id || seenIDs.has(id) || seenSequences.has(sequence)) {
      throw new MileageAllocationError("mileage_legs_invalid", "Mileage legs must have unique IDs and sequence values.", 409);
    }
    seenIDs.add(id);
    seenSequences.add(sequence);
    return {
      source_leg_id: id,
      source_sequence: sequence,
      source_distance_micromiles: scaledNumber(leg.distance_miles, 1_000_000, "mileage_leg_distance", 1_000_000_000_000),
      source_suggested_job_id: leg.job_id ? cleanString(leg.job_id, 120) || null : null,
      source_manual_trip_id: leg.manual_trip_id ? cleanString(leg.manual_trip_id, 160) || null : null
    };
  });
  if (reimbursementCents > 0 && !normalizedLegs.length) {
    throw new MileageAllocationError(
      "mileage_allocation_legs_required",
      "Positive mileage reimbursement requires at least one reviewed leg.",
      409
    );
  }
  return {
    employee_id: String(log.employee_id),
    source_service_date: dateOnly(
      log.service_date instanceof Date ? log.service_date.toISOString().slice(0, 10) : String(log.service_date).slice(0, 10),
      "service_date"
    ),
    source_reimbursement_cents: reimbursementCents,
    source_rate_cents_per_mile: rateCents,
    source_total_miles_tenths: scaledNumber(log.total_miles, 10, "total_miles", 10_000_000),
    source_leg_count: normalizedLegs.length,
    legs: normalizedLegs
  };
}

export function suggestMileageAllocationCents(reimbursementCentsValue, legs = []) {
  const reimbursementCents = exactInteger(reimbursementCentsValue, "reimbursement_cents");
  if (!Array.isArray(legs) || !legs.length) {
    if (reimbursementCents === 0) return [];
    throw new MileageAllocationError("mileage_allocation_legs_required", "Positive reimbursement requires mileage legs.");
  }
  const normalized = legs.map((leg) => ({
    leg_id: cleanString(leg.leg_id ?? leg.source_leg_id ?? leg.id, 160),
    weight: BigInt(exactInteger(
      leg.distance_micromiles ?? leg.source_distance_micromiles ?? scaledNumber(leg.distance_miles, 1_000_000, "mileage_leg_distance"),
      "mileage_leg_distance"
    ))
  }));
  if (normalized.some((leg) => !leg.leg_id) || new Set(normalized.map((leg) => leg.leg_id)).size !== normalized.length) {
    throw new MileageAllocationError("mileage_legs_invalid", "Mileage legs must have unique IDs.");
  }
  const totalWeight = normalized.reduce((sum, leg) => sum + leg.weight, 0n);
  if (totalWeight <= 0n) {
    if (reimbursementCents === 0) return normalized.map((leg) => ({ leg_id: leg.leg_id, amount_cents: 0 }));
    throw new MileageAllocationError("mileage_allocation_distance_required", "Positive reimbursement cannot be suggested from zero-distance legs.");
  }
  const cents = BigInt(reimbursementCents);
  const shares = normalized.map((leg) => {
    const numerator = cents * leg.weight;
    return {
      leg_id: leg.leg_id,
      amount_cents: Number(numerator / totalWeight),
      remainder: numerator % totalWeight
    };
  });
  let remaining = reimbursementCents - shares.reduce((sum, share) => sum + share.amount_cents, 0);
  const remainderOrder = [...shares].sort((left, right) => {
    if (left.remainder === right.remainder) return left.leg_id.localeCompare(right.leg_id);
    return left.remainder > right.remainder ? -1 : 1;
  });
  for (let index = 0; index < remaining; index += 1) remainderOrder[index].amount_cents += 1;
  return shares.map(({ leg_id, amount_cents }) => ({ leg_id, amount_cents }));
}

function headerSourceMatches(header, snapshot) {
  if (!header) return false;
  return String(header.employee_id) === snapshot.employee_id
    && String(header.source_service_date).slice(0, 10) === snapshot.source_service_date
    && Number(header.source_reimbursement_cents) === snapshot.source_reimbursement_cents
    && Number(header.source_rate_cents_per_mile) === snapshot.source_rate_cents_per_mile
    && Number(header.source_total_miles_tenths) === snapshot.source_total_miles_tenths
    && Number(header.source_leg_count) === snapshot.source_leg_count;
}

function lineSourceMatches(line, leg) {
  if (!line || !leg) return false;
  return String(line.source_leg_id) === leg.source_leg_id
    && Number(line.source_sequence) === leg.source_sequence
    && Number(line.source_distance_micromiles) === leg.source_distance_micromiles
    && (line.source_suggested_job_id || null) === leg.source_suggested_job_id
    && (line.source_manual_trip_id || null) === leg.source_manual_trip_id;
}

function normalizedAllocationSignature(lines) {
  return JSON.stringify([...lines].sort((left, right) => left.source_sequence - right.source_sequence).map((line) => ({
    source_leg_id: line.source_leg_id,
    source_sequence: line.source_sequence,
    source_distance_micromiles: line.source_distance_micromiles,
    source_suggested_job_id: line.source_suggested_job_id || null,
    source_manual_trip_id: line.source_manual_trip_id || null,
    target_kind: line.target_kind,
    job_id: line.job_id || null,
    amount_cents: line.amount_cents
  })));
}

export function planMileageAllocationUpdate({ body = {}, log, legs = [], currentHeader = null, currentLines = [], jobs = [] }) {
  const expectedVersion = exactInteger(body.expected_version, "expected_version");
  const reason = cleanString(body.reason, 500);
  if (!reason) throw new MileageAllocationError("mileage_allocation_reason_required", "Add a reason for this mileage allocation change.");
  const currentVersion = currentHeader ? exactInteger(Number(currentHeader.version), "version", { minimum: 1 }) : 0;
  if (expectedVersion !== currentVersion) {
    throw new MileageAllocationError(
      "mileage_allocation_stale",
      "This mileage allocation changed after it was loaded. Refresh before saving again.",
      409,
      { current_version: currentVersion }
    );
  }
  if (!Array.isArray(body.allocations) || body.allocations.length > MAX_ALLOCATION_LEGS) {
    throw new MileageAllocationError("mileage_allocations_invalid", `Provide at most ${MAX_ALLOCATION_LEGS} mileage allocation lines.`);
  }
  if (!body.allocations.length) {
    if (!currentLines.length) return { mode: "replay", current_version: currentVersion, reason, snapshot: null, lines: [] };
    return { mode: "clear", current_version: currentVersion, reason, snapshot: null, lines: [], action: "mileage_allocation_cleared" };
  }

  const snapshot = mileageSourceSnapshot(log, legs);
  const legByID = new Map(snapshot.legs.map((leg) => [leg.source_leg_id, leg]));
  const jobByID = new Map(jobs.map((job) => [String(job.id), job]));
  const seenLegs = new Set();
  const lines = body.allocations.map((raw) => {
    const legID = cleanString(raw.leg_id, 160);
    const source = legByID.get(legID);
    if (!source || seenLegs.has(legID)) {
      throw new MileageAllocationError("mileage_allocation_leg_invalid", "Every current mileage leg must appear exactly once.");
    }
    seenLegs.add(legID);
    const targetKind = cleanString(raw.target_kind, 20).toLowerCase();
    if (!TARGET_KINDS.has(targetKind)) {
      throw new MileageAllocationError("mileage_allocation_target_invalid", "Choose a job or Company Overhead for every mileage leg.");
    }
    const requestedJobID = raw.job_id == null ? null : cleanString(raw.job_id, 120) || null;
    if (targetKind === "job" && (!requestedJobID || !jobByID.has(requestedJobID))) {
      throw new MileageAllocationError("accounting_job_not_found", "A selected company job was not found.", 404);
    }
    if (targetKind === "overhead" && requestedJobID) {
      throw new MileageAllocationError("mileage_allocation_target_invalid", "Company Overhead lines cannot also target a job.");
    }
    return {
      ...source,
      target_kind: targetKind,
      job_id: requestedJobID,
      amount_cents: exactInteger(raw.amount_cents, "mileage_allocation_amount_cents")
    };
  }).sort((left, right) => left.source_sequence - right.source_sequence);
  if (seenLegs.size !== snapshot.legs.length) {
    throw new MileageAllocationError("mileage_allocation_legs_incomplete", "Every current mileage leg must be allocated exactly once.");
  }
  const allocatedCents = lines.reduce((sum, line) => sum + line.amount_cents, 0);
  if (!Number.isSafeInteger(allocatedCents) || allocatedCents !== snapshot.source_reimbursement_cents) {
    throw new MileageAllocationError(
      "mileage_allocation_unbalanced",
      "Mileage allocation cents must equal the exact daily reimbursement.",
      400,
      { reimbursement_cents: snapshot.source_reimbursement_cents, allocated_cents: allocatedCents }
    );
  }
  const currentComparable = currentLines.map((line) => ({
    source_leg_id: String(line.source_leg_id),
    source_sequence: Number(line.source_sequence),
    source_distance_micromiles: Number(line.source_distance_micromiles),
    source_suggested_job_id: line.source_suggested_job_id || null,
    source_manual_trip_id: line.source_manual_trip_id || null,
    target_kind: line.target_kind,
    job_id: line.job_id || null,
    amount_cents: Number(line.amount_cents)
  }));
  const sourceLinesCurrent = currentComparable.length === snapshot.legs.length
    && currentComparable.every((line) => lineSourceMatches(line, legByID.get(line.source_leg_id)));
  if (headerSourceMatches(currentHeader, snapshot)
      && sourceLinesCurrent
      && normalizedAllocationSignature(currentComparable) === normalizedAllocationSignature(lines)) {
    return { mode: "replay", current_version: currentVersion, reason, snapshot, lines };
  }
  const action = currentLines.length ? "mileage_reallocated" : "mileage_allocated";
  return { mode: currentHeader ? "update" : "create", current_version: currentVersion, reason, snapshot, lines, action };
}

export async function installFinanceMileageAllocationSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS finance_mileage_allocation_headers (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      mileage_log_id TEXT NOT NULL,
      employee_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
      source_service_date DATE NOT NULL,
      source_reimbursement_cents INTEGER NOT NULL CHECK (source_reimbursement_cents >= 0),
      source_rate_cents_per_mile INTEGER NOT NULL CHECK (source_rate_cents_per_mile >= 0),
      source_total_miles_tenths BIGINT NOT NULL CHECK (source_total_miles_tenths >= 0),
      source_leg_count INTEGER NOT NULL CHECK (source_leg_count >= 0 AND source_leg_count <= 100),
      version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
      allocated_by UUID REFERENCES users(id) ON DELETE SET NULL,
      allocated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, mileage_log_id)
    );
    CREATE INDEX IF NOT EXISTS finance_mileage_allocation_headers_company_date_idx
      ON finance_mileage_allocation_headers(company_id, source_service_date DESC);
    CREATE INDEX IF NOT EXISTS finance_mileage_allocation_headers_company_employee_idx
      ON finance_mileage_allocation_headers(company_id, employee_id, source_service_date DESC);

    CREATE TABLE IF NOT EXISTS finance_mileage_allocation_lines (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      header_id UUID NOT NULL REFERENCES finance_mileage_allocation_headers(id) ON DELETE CASCADE,
      source_leg_id TEXT NOT NULL,
      source_sequence INTEGER NOT NULL CHECK (source_sequence > 0 AND source_sequence <= 100),
      source_distance_micromiles BIGINT NOT NULL CHECK (source_distance_micromiles >= 0),
      source_suggested_job_id TEXT,
      source_manual_trip_id TEXT,
      target_kind TEXT NOT NULL CHECK (target_kind IN ('job','overhead')),
      job_id TEXT,
      amount_cents INTEGER NOT NULL CHECK (amount_cents >= 0),
      sort_order INTEGER NOT NULL CHECK (sort_order > 0 AND sort_order <= 100),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      CHECK ((target_kind = 'job' AND job_id IS NOT NULL) OR (target_kind = 'overhead' AND job_id IS NULL)),
      UNIQUE(header_id, source_leg_id),
      UNIQUE(header_id, source_sequence)
    );
    CREATE INDEX IF NOT EXISTS finance_mileage_allocation_lines_company_job_idx
      ON finance_mileage_allocation_lines(company_id, job_id) WHERE job_id IS NOT NULL;

    CREATE TABLE IF NOT EXISTS finance_mileage_allocation_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      mileage_log_id TEXT NOT NULL,
      header_id UUID NOT NULL REFERENCES finance_mileage_allocation_headers(id) ON DELETE RESTRICT,
      actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      reason TEXT NOT NULL,
      before_state JSONB,
      after_state JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS finance_mileage_allocation_audit_company_log_idx
      ON finance_mileage_allocation_audit(company_id, mileage_log_id, created_at DESC);
  `);
}

function sendMileageError(res, error, fallback) {
  if (error instanceof MileageAllocationError || error?.statusCode) {
    return res.status(error.statusCode || 400).json({
      error: error.code || fallback,
      message: error.message,
      current_version: error.current_version,
      reimbursement_cents: error.reimbursement_cents,
      allocated_cents: error.allocated_cents
    });
  }
  console.error("[finance-mileage-allocations]", fallback, { code: error?.code, message: error?.message });
  return res.status(500).json({ error: fallback, message: "Mileage allocation request failed." });
}

function headerPayload(row) {
  if (!row) return null;
  return {
    id: String(row.id),
    mileage_log_id: String(row.mileage_log_id),
    employee_id: String(row.employee_id),
    source_service_date: String(row.source_service_date).slice(0, 10),
    source_reimbursement_cents: safeDbInteger(row.source_reimbursement_cents, "source_reimbursement_cents"),
    source_rate_cents_per_mile: safeDbInteger(row.source_rate_cents_per_mile, "source_rate_cents_per_mile"),
    source_total_miles_tenths: safeDbInteger(row.source_total_miles_tenths, "source_total_miles_tenths"),
    source_leg_count: safeDbInteger(row.source_leg_count, "source_leg_count"),
    version: safeDbInteger(row.version, "version"),
    allocated_by: row.allocated_by || null,
    allocated_at: row.allocated_at || null,
    created_at: row.created_at || null,
    updated_at: row.updated_at || null
  };
}

function linePayload(row) {
  return {
    id: row.id ? String(row.id) : String(row.source_leg_id),
    source_leg_id: String(row.source_leg_id),
    source_sequence: safeDbInteger(row.source_sequence, "source_sequence"),
    source_distance_micromiles: safeDbInteger(row.source_distance_micromiles, "source_distance_micromiles"),
    source_suggested_job_id: row.source_suggested_job_id || null,
    source_manual_trip_id: row.source_manual_trip_id || null,
    target_kind: row.target_kind,
    job_id: row.job_id || null,
    job_title: row.job_title || null,
    job_missing: row.target_kind === "job" && row.job_exists === false,
    amount_cents: safeDbInteger(row.amount_cents, "amount_cents")
  };
}

function allocationSnapshot(header, lines) {
  if (!header) return null;
  return {
    header: {
      id: String(header.id), mileage_log_id: String(header.mileage_log_id), employee_id: String(header.employee_id),
      source_service_date: String(header.source_service_date).slice(0, 10),
      source_reimbursement_cents: Number(header.source_reimbursement_cents),
      source_rate_cents_per_mile: Number(header.source_rate_cents_per_mile),
      source_total_miles_tenths: Number(header.source_total_miles_tenths),
      source_leg_count: Number(header.source_leg_count), version: Number(header.version)
    },
    allocations: lines.map((line) => ({
      source_leg_id: String(line.source_leg_id), source_sequence: Number(line.source_sequence),
      source_distance_micromiles: Number(line.source_distance_micromiles),
      source_suggested_job_id: line.source_suggested_job_id || null,
      source_manual_trip_id: line.source_manual_trip_id || null,
      target_kind: line.target_kind, job_id: line.job_id || null, amount_cents: Number(line.amount_cents)
    }))
  };
}

const MILEAGE_ALLOCATION_CTE = `
  WITH scoped AS (
    SELECT ml.id AS mileage_log_id, ml.employee_id,
           COALESCE(NULLIF(u.display_name, ''), u.email) AS employee_name,
           ml.service_date, ml.status, ml.total_miles, ml.rate_cents_per_mile, ml.reimbursement_cents,
           h.id AS header_id, h.version AS allocation_version,
           h.employee_id AS reviewed_employee_id, h.source_service_date,
           h.source_reimbursement_cents, h.source_rate_cents_per_mile,
           h.source_total_miles_tenths, h.source_leg_count,
           (ml.status IN ('approved','paid') AND ml.reimbursement_cents >= 0
             AND ml.rate_cents_per_mile >= 0 AND ml.total_miles >= 0) AS eligible_source
      FROM mileage_daily_logs ml
      JOIN users u ON u.id = ml.employee_id AND u.company_id = ml.company_id
      LEFT JOIN finance_mileage_allocation_headers h
        ON h.company_id = ml.company_id AND h.mileage_log_id = ml.id
     WHERE ml.company_id = $1
       AND ml.service_date >= $2::date
       AND ml.service_date <= $3::date
       AND (ml.status IN ('approved','paid') OR h.id IS NOT NULL)
  ), facts AS (
    SELECT scoped.*,
           COALESCE(live.leg_count, 0)::bigint AS live_leg_count,
           COALESCE(alloc.line_count, 0)::bigint AS line_count,
           COALESCE(alloc.total_line_cents, 0)::bigint AS total_line_cents,
           COALESCE(alloc.job_existing_cents, 0)::bigint AS job_existing_cents,
           COALESCE(alloc.overhead_cents, 0)::bigint AS overhead_cents,
           COALESCE(alloc.missing_job_cents, 0)::bigint AS missing_job_cents,
           COALESCE(alloc.missing_job_count, 0)::bigint AS missing_job_count,
           COALESCE(alloc.source_mismatch_count, 0)::bigint AS source_mismatch_count,
           (scoped.header_id IS NOT NULL
             AND COALESCE(alloc.line_count, 0) > 0
             AND scoped.eligible_source
             AND scoped.reviewed_employee_id = scoped.employee_id
             AND scoped.source_service_date = scoped.service_date
             AND scoped.source_reimbursement_cents = scoped.reimbursement_cents
             AND scoped.source_rate_cents_per_mile = scoped.rate_cents_per_mile
             AND scoped.source_total_miles_tenths = ROUND(scoped.total_miles * 10)::bigint
             AND scoped.source_leg_count = COALESCE(live.leg_count, 0)
             AND COALESCE(alloc.line_count, 0) = COALESCE(live.leg_count, 0)
             AND COALESCE(alloc.source_mismatch_count, 0) = 0
             AND COALESCE(alloc.total_line_cents, 0) = scoped.reimbursement_cents) AS source_current
      FROM scoped
      LEFT JOIN LATERAL (
        SELECT COUNT(*)::bigint AS leg_count
          FROM mileage_legs leg WHERE leg.log_id = scoped.mileage_log_id
      ) live ON true
      LEFT JOIN LATERAL (
        SELECT COUNT(*)::bigint AS line_count,
               COALESCE(SUM(line.amount_cents), 0)::bigint AS total_line_cents,
               COALESCE(SUM(line.amount_cents) FILTER (WHERE line.target_kind = 'job' AND job.id IS NOT NULL), 0)::bigint AS job_existing_cents,
               COALESCE(SUM(line.amount_cents) FILTER (WHERE line.target_kind = 'overhead'), 0)::bigint AS overhead_cents,
               COALESCE(SUM(line.amount_cents) FILTER (WHERE line.target_kind = 'job' AND job.id IS NULL), 0)::bigint AS missing_job_cents,
               COUNT(*) FILTER (WHERE line.target_kind = 'job' AND job.id IS NULL)::bigint AS missing_job_count,
               COUNT(*) FILTER (WHERE leg.id IS NULL
                 OR line.source_sequence <> leg.sequence
                 OR line.source_distance_micromiles <> ROUND(leg.distance_miles * 1000000)::bigint
                 OR line.source_suggested_job_id IS DISTINCT FROM leg.job_id
                 OR line.source_manual_trip_id IS DISTINCT FROM leg.manual_trip_id)::bigint AS source_mismatch_count
          FROM finance_mileage_allocation_lines line
          LEFT JOIN mileage_legs leg
            ON leg.id = line.source_leg_id AND leg.log_id = scoped.mileage_log_id
          LEFT JOIN schedule_events job
            ON job.company_id = line.company_id AND job.id = line.job_id
         WHERE line.company_id = $1 AND line.header_id = scoped.header_id
      ) alloc ON true
  ), evaluated AS (
    SELECT facts.*,
           CASE WHEN source_current THEN job_existing_cents ELSE 0 END::bigint AS job_allocated_cents,
           CASE WHEN source_current THEN overhead_cents ELSE 0 END::bigint AS company_overhead_cents,
           CASE WHEN eligible_source THEN GREATEST(0, reimbursement_cents
             - CASE WHEN source_current THEN job_existing_cents + overhead_cents ELSE 0 END) ELSE 0 END::bigint
             AS unallocated_cents
      FROM facts
  )`;

function mileageStatus(row) {
  if (Number(row.line_count) > 0 && (!row.source_current || Number(row.missing_job_count) > 0)) return "stale";
  if (!row.eligible_source) return "invalid";
  if (Number(row.line_count) === 0) return "unallocated";
  if (Number(row.unallocated_cents) > 0) return "partially_allocated";
  return "allocated";
}

function reportEntryPayload(row) {
  return {
    mileage_log_id: String(row.mileage_log_id), employee_id: String(row.employee_id), employee_name: row.employee_name,
    service_date: String(row.service_date).slice(0, 10), status: row.status,
    total_miles_tenths: optionalScaledNonnegative(row.total_miles, 10, 10_000_000),
    rate_cents_per_mile: safeDbInteger(row.rate_cents_per_mile, "rate_cents_per_mile"),
    reimbursement_cents: safeDbInteger(row.reimbursement_cents, "reimbursement_cents"),
    allocation_version: row.allocation_version == null ? 0 : safeDbInteger(row.allocation_version, "allocation_version"),
    allocation_status: mileageStatus(row),
    job_allocated_cents: safeDbInteger(row.job_allocated_cents || 0, "job_allocated_cents"),
    company_overhead_cents: safeDbInteger(row.company_overhead_cents || 0, "company_overhead_cents"),
    unallocated_cents: safeDbInteger(row.unallocated_cents || 0, "unallocated_cents"),
    source_changed: Number(row.line_count) > 0 && !Boolean(row.source_current),
    missing_job_count: safeDbInteger(row.missing_job_count || 0, "missing_job_count"),
    leg_count: safeDbInteger(row.live_leg_count || 0, "leg_count")
  };
}

async function loadMileageReport(pool, companyId, range, limit) {
  const summaryResult = await pool.query(
    `${MILEAGE_ALLOCATION_CTE}
     SELECT COUNT(*) FILTER (WHERE eligible_source)::bigint AS eligible_log_count,
            COALESCE(SUM(reimbursement_cents) FILTER (WHERE eligible_source), 0)::bigint AS eligible_reimbursement_cents,
            COALESCE(SUM(job_allocated_cents), 0)::bigint AS job_allocated_cents,
            COALESCE(SUM(company_overhead_cents), 0)::bigint AS company_overhead_cents,
            COALESCE(SUM(unallocated_cents), 0)::bigint AS unallocated_cents,
            COUNT(*) FILTER (WHERE line_count > 0 AND source_current AND missing_job_count = 0)::bigint AS reviewed_log_count,
            COUNT(*) FILTER (WHERE line_count > 0 AND (NOT source_current OR missing_job_count > 0))::bigint AS stale_allocation_count,
            COUNT(*) FILTER (WHERE status IN ('approved','paid') AND NOT eligible_source)::bigint AS invalid_source_count,
            COUNT(*)::bigint AS review_row_count
       FROM evaluated`,
    [companyId, range.start_date, range.end_date]
  );
  const rowsResult = await pool.query(
    `${MILEAGE_ALLOCATION_CTE}
     SELECT * FROM evaluated
      ORDER BY service_date DESC, employee_name, mileage_log_id
      LIMIT $4`,
    [companyId, range.start_date, range.end_date, limit + 1]
  );
  return { summary: summaryResult.rows[0] || {}, rows: rowsResult.rows };
}

async function loadMileageDetail(client, companyId, logId, { lock = false } = {}) {
  const logResult = await client.query(
    `SELECT ml.*, COALESCE(NULLIF(u.display_name, ''), u.email) AS employee_name
       FROM mileage_daily_logs ml
       JOIN users u ON u.id = ml.employee_id AND u.company_id = ml.company_id
      WHERE ml.company_id = $1 AND ml.id = $2${lock ? " FOR UPDATE OF ml" : ""}`,
    [companyId, logId]
  );
  if (!logResult.rows[0]) throw new MileageAllocationError("mileage_log_not_found", "The company mileage log was not found.", 404);
  const legsResult = await client.query(
    `SELECT id, sequence, from_label, to_label, distance_miles, duration_seconds, job_id, manual_trip_id,
            calculation_status, error_message
       FROM mileage_legs WHERE log_id = $1 ORDER BY sequence, id LIMIT ${MAX_ALLOCATION_LEGS + 1}`,
    [logId]
  );
  const headerResult = await client.query(
    `SELECT * FROM finance_mileage_allocation_headers
      WHERE company_id = $1 AND mileage_log_id = $2${lock ? " FOR UPDATE" : ""}`,
    [companyId, logId]
  );
  const header = headerResult.rows[0] || null;
  const linesResult = header
    ? await client.query(
      `SELECT line.*, job.title AS job_title, (job.id IS NOT NULL) AS job_exists
         FROM finance_mileage_allocation_lines line
         LEFT JOIN schedule_events job ON job.company_id = line.company_id AND job.id = line.job_id
        WHERE line.company_id = $1 AND line.header_id = $2
        ORDER BY line.sort_order, line.source_sequence`,
      [companyId, header.id]
    )
    : { rows: [] };
  return { log: logResult.rows[0], legs: legsResult.rows, header, lines: linesResult.rows };
}

function evaluateDetail(detail) {
  let liveSnapshot = null;
  try { liveSnapshot = mileageSourceSnapshot(detail.log, detail.legs); } catch { /* invalid source remains reviewable */ }
  const liveByID = new Map((liveSnapshot?.legs || []).map((leg) => [leg.source_leg_id, leg]));
  const sourceLinesCurrent = Boolean(liveSnapshot)
    && detail.lines.length === liveSnapshot.legs.length
    && detail.lines.every((line) => lineSourceMatches(line, liveByID.get(String(line.source_leg_id))));
  const sourceCurrent = Boolean(detail.lines.length && liveSnapshot
    && headerSourceMatches(detail.header, liveSnapshot)
    && sourceLinesCurrent
    && detail.lines.reduce((sum, line) => sum + Number(line.amount_cents), 0) === liveSnapshot.source_reimbursement_cents);
  const missingJobCount = detail.lines.filter((line) => line.target_kind === "job" && !line.job_exists).length;
  const jobAllocatedCents = sourceCurrent
    ? detail.lines.filter((line) => line.target_kind === "job" && line.job_exists).reduce((sum, line) => sum + Number(line.amount_cents), 0)
    : 0;
  const overheadCents = sourceCurrent
    ? detail.lines.filter((line) => line.target_kind === "overhead").reduce((sum, line) => sum + Number(line.amount_cents), 0)
    : 0;
  const liveReimbursement = liveSnapshot?.source_reimbursement_cents ?? 0;
  const row = {
    line_count: detail.lines.length, source_current: sourceCurrent, missing_job_count: missingJobCount,
    eligible_source: Boolean(liveSnapshot), unallocated_cents: Math.max(0, liveReimbursement - jobAllocatedCents - overheadCents)
  };
  return {
    source_current: sourceCurrent, missing_job_count: missingJobCount,
    job_allocated_cents: jobAllocatedCents, company_overhead_cents: overheadCents,
    unallocated_cents: row.unallocated_cents, allocation_status: mileageStatus(row)
  };
}

async function mileageCandidateJobs(client, companyId, log, legs, lines) {
  const preferredJobIDs = [...new Set([
    ...legs.map((leg) => leg.job_id),
    ...lines.map((line) => line.job_id)
  ].filter(Boolean).map(String))].slice(0, MAX_CANDIDATE_JOBS);
  const { rows } = await client.query(
    `SELECT se.id AS job_id, se.title, se.start_at, se.end_at, se.finished_at,
            COALESCE(c.name, 'No customer name') AS contact_name,
            (se.id = ANY($3::text[])) AS source_suggested
       FROM schedule_events se
       LEFT JOIN contacts c ON c.company_id = se.company_id AND c.id::text = se.contact_id
      WHERE se.company_id = $1
        AND (se.id = ANY($3::text[])
          OR (se.start_at >= $2::date - interval '31 days'
            AND se.start_at < $2::date + interval '32 days'))
      ORDER BY (se.id = ANY($3::text[])) DESC,
               ABS(EXTRACT(EPOCH FROM (se.start_at - $2::date::timestamp))) ASC,
               se.id
      LIMIT $4`,
    [companyId, String(log.service_date).slice(0, 10), preferredJobIDs, MAX_CANDIDATE_JOBS]
  );
  return rows.map((row) => ({
    job_id: String(row.job_id), title: row.title, contact_name: row.contact_name,
    start_at: row.start_at, end_at: row.end_at, finished_at: row.finished_at || null,
    source_suggested: Boolean(row.source_suggested)
  }));
}

function detailLogPayload(detail) {
  let snapshot = null;
  let sourceError = null;
  try {
    snapshot = mileageSourceSnapshot(detail.log, detail.legs);
  } catch (error) {
    sourceError = error instanceof MileageAllocationError
      ? { code: error.code, message: error.message }
      : { code: "mileage_source_invalid", message: "The mileage source cannot be allocated." };
  }
  return {
    mileage_log_id: String(detail.log.id), employee_id: String(detail.log.employee_id),
    employee_name: detail.log.employee_name, service_date: String(detail.log.service_date).slice(0, 10),
    status: detail.log.status,
    total_miles_tenths: snapshot?.source_total_miles_tenths
      ?? optionalScaledNonnegative(detail.log.total_miles, 10, 10_000_000),
    rate_cents_per_mile: safeDbInteger(detail.log.rate_cents_per_mile, "rate_cents_per_mile"),
    reimbursement_cents: safeDbInteger(detail.log.reimbursement_cents, "reimbursement_cents"),
    eligible: Boolean(snapshot), source_error: sourceError,
    legs: detail.legs.map((leg) => ({
      leg_id: String(leg.id), sequence: safeDbInteger(leg.sequence, "sequence"),
      from_label: leg.from_label, to_label: leg.to_label,
      distance_micromiles: optionalScaledNonnegative(leg.distance_miles, 1_000_000, 1_000_000_000_000),
      duration_seconds: leg.duration_seconds == null ? null : Math.round(Number(leg.duration_seconds)),
      source_suggested_job_id: leg.job_id || null, manual_trip_id: leg.manual_trip_id || null,
      calculation_status: leg.calculation_status, error_message: leg.error_message || null
    }))
  };
}

async function mileageDetailResponse(client, companyId, logId, loaded = null) {
  const detail = loaded || await loadMileageDetail(client, companyId, logId);
  const candidates = await mileageCandidateJobs(client, companyId, detail.log, detail.legs, detail.lines);
  const auditResult = await client.query(
    `SELECT id, actor_user_id, action, reason, before_state, after_state, created_at
       FROM finance_mileage_allocation_audit
      WHERE company_id = $1 AND mileage_log_id = $2
      ORDER BY created_at DESC, id DESC LIMIT 100`,
    [companyId, logId]
  );
  return {
    log: detailLogPayload(detail), header: headerPayload(detail.header),
    allocations: detail.lines.map(linePayload), evaluation: evaluateDetail(detail), candidates,
    audit: auditResult.rows.map((row) => ({
      id: String(row.id), actor_user_id: row.actor_user_id || null, action: row.action,
      reason: row.reason, before: row.before_state || null, after: row.after_state || null,
      created_at: row.created_at
    })),
    warnings: [
      "Mileage cents count only after an owner or manager explicitly allocates every current leg to a company job or Company Overhead.",
      "A mileage leg's source job ID is only a suggestion. It never creates an accounting allocation automatically.",
      "Mileage allocations are operational cost evidence only and do not post payroll, reimbursements, P&L, or job-margin entries."
    ]
  };
}

export function installFinanceMileageAllocationRoutes({ app, pool, authRequired, requireFinanceAccess }) {
  app.get("/api/finance/accounting/mileage-allocations", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Accounting requires a company workspace." });
    try {
      const range = parseMileageAllocationRange(req.query.start_date, req.query.end_date);
      const requestedLimit = Number(req.query.limit || 200);
      const limit = Math.min(Math.max(Number.isSafeInteger(requestedLimit) ? requestedLimit : 200, 1), MAX_REPORT_ROWS);
      const loaded = await loadMileageReport(pool, req.companyId, range, limit);
      const totalCount = safeDbInteger(loaded.summary.review_row_count || 0, "review_row_count");
      const returnedRows = loaded.rows.slice(0, limit);
      const summary = {
        eligible_log_count: safeDbInteger(loaded.summary.eligible_log_count || 0, "eligible_log_count"),
        eligible_reimbursement_cents: safeDbInteger(loaded.summary.eligible_reimbursement_cents || 0, "eligible_reimbursement_cents"),
        job_allocated_cents: safeDbInteger(loaded.summary.job_allocated_cents || 0, "job_allocated_cents"),
        company_overhead_cents: safeDbInteger(loaded.summary.company_overhead_cents || 0, "company_overhead_cents"),
        unallocated_cents: safeDbInteger(loaded.summary.unallocated_cents || 0, "unallocated_cents"),
        reviewed_log_count: safeDbInteger(loaded.summary.reviewed_log_count || 0, "reviewed_log_count"),
        stale_allocation_count: safeDbInteger(loaded.summary.stale_allocation_count || 0, "stale_allocation_count"),
        invalid_source_count: safeDbInteger(loaded.summary.invalid_source_count || 0, "invalid_source_count")
      };
      const warnings = [
        "Only approved or paid daily mileage and explicitly reviewed exact-cent leg allocations are included.",
        "Source leg job IDs are suggestions only; no allocation is inferred from route calculation or scheduling.",
        "These values do not post payroll, employee reimbursement, P&L, or job-margin entries."
      ];
      if (summary.stale_allocation_count) warnings.push("Changed source mileage and deleted job targets are excluded until reviewed.");
      if (summary.invalid_source_count) warnings.push("Invalid approved mileage sources remain visible but are excluded from allocation totals.");
      res.json({
        basis: "explicit_reviewed_mileage_leg_cost_allocations", start_date: range.start_date,
        end_date: range.end_date, currency: "usd", summary, total_count: totalCount,
        returned_count: returnedRows.length, truncated: loaded.rows.length > limit, warnings,
        logs: returnedRows.map(reportEntryPayload)
      });
    } catch (error) {
      sendMileageError(res, error, "mileage_allocations_load_failed");
    }
  });

  app.get("/api/finance/accounting/mileage-allocations/:logId", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Accounting requires a company workspace." });
    try {
      res.json(await mileageDetailResponse(pool, req.companyId, req.params.logId));
    } catch (error) {
      sendMileageError(res, error, "mileage_allocation_detail_failed");
    }
  });

  app.put("/api/finance/accounting/mileage-allocations/:logId", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Accounting requires a company workspace." });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const detail = await loadMileageDetail(client, req.companyId, req.params.logId, { lock: true });
      const requestedAllocations = Array.isArray(req.body?.allocations) ? req.body.allocations : [];
      const requestedJobIDs = [...new Set(requestedAllocations
        .filter((line) => line?.target_kind === "job" && line.job_id)
        .map((line) => cleanString(line.job_id, 120)))];
      const jobs = requestedJobIDs.length
        ? (await client.query(
          `SELECT id, title FROM schedule_events
            WHERE company_id = $1 AND id = ANY($2::text[]) FOR UPDATE`,
          [req.companyId, requestedJobIDs]
        )).rows
        : [];
      const plan = planMileageAllocationUpdate({
        body: req.body, log: detail.log, legs: detail.legs,
        currentHeader: detail.header, currentLines: detail.lines, jobs
      });
      if (plan.mode === "replay") {
        await client.query("COMMIT");
        return res.json({ replayed: true, ...(await mileageDetailResponse(pool, req.companyId, req.params.logId)) });
      }
      const before = allocationSnapshot(detail.header, detail.lines);
      let header;
      if (plan.mode === "create") {
        header = (await client.query(
          `INSERT INTO finance_mileage_allocation_headers (
             company_id, mileage_log_id, employee_id, source_service_date, source_reimbursement_cents,
             source_rate_cents_per_mile, source_total_miles_tenths, source_leg_count, allocated_by
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
          [req.companyId, req.params.logId, plan.snapshot.employee_id, plan.snapshot.source_service_date,
            plan.snapshot.source_reimbursement_cents, plan.snapshot.source_rate_cents_per_mile,
            plan.snapshot.source_total_miles_tenths, plan.snapshot.source_leg_count, req.userId]
        )).rows[0];
      } else if (plan.mode === "clear") {
        header = (await client.query(
          `UPDATE finance_mileage_allocation_headers
              SET version = version + 1, allocated_by = $3, allocated_at = now(), updated_at = now()
            WHERE company_id = $1 AND mileage_log_id = $2 RETURNING *`,
          [req.companyId, req.params.logId, req.userId]
        )).rows[0];
      } else {
        header = (await client.query(
          `UPDATE finance_mileage_allocation_headers
              SET employee_id = $3, source_service_date = $4, source_reimbursement_cents = $5,
                  source_rate_cents_per_mile = $6, source_total_miles_tenths = $7,
                  source_leg_count = $8, version = version + 1, allocated_by = $9,
                  allocated_at = now(), updated_at = now()
            WHERE company_id = $1 AND mileage_log_id = $2 RETURNING *`,
          [req.companyId, req.params.logId, plan.snapshot.employee_id, plan.snapshot.source_service_date,
            plan.snapshot.source_reimbursement_cents, plan.snapshot.source_rate_cents_per_mile,
            plan.snapshot.source_total_miles_tenths, plan.snapshot.source_leg_count, req.userId]
        )).rows[0];
      }
      await client.query(
        `DELETE FROM finance_mileage_allocation_lines WHERE company_id = $1 AND header_id = $2`,
        [req.companyId, header.id]
      );
      const insertedLines = [];
      for (const [index, line] of plan.lines.entries()) {
        insertedLines.push((await client.query(
          `INSERT INTO finance_mileage_allocation_lines (
             company_id, header_id, source_leg_id, source_sequence, source_distance_micromiles,
             source_suggested_job_id, source_manual_trip_id, target_kind, job_id, amount_cents, sort_order
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
          [req.companyId, header.id, line.source_leg_id, line.source_sequence,
            line.source_distance_micromiles, line.source_suggested_job_id, line.source_manual_trip_id,
            line.target_kind, line.job_id, line.amount_cents, index + 1]
        )).rows[0]);
      }
      const after = allocationSnapshot(header, insertedLines);
      await client.query(
        `INSERT INTO finance_mileage_allocation_audit (
           company_id, mileage_log_id, header_id, actor_user_id, action, reason, before_state, after_state
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [req.companyId, req.params.logId, header.id, req.userId, plan.action, plan.reason,
          JSON.stringify(before), JSON.stringify(after)]
      );
      await client.query("COMMIT");
      res.json({ replayed: false, ...(await mileageDetailResponse(pool, req.companyId, req.params.logId)) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendMileageError(res, error, "mileage_allocation_update_failed");
    } finally {
      client.release();
    }
  });
}
