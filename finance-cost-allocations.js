const MAX_REPORT_DAYS = 731;
const MAX_REPORT_ROWS = 500;
const MAX_CANDIDATE_JOBS = 100;
const MAX_SPLIT_LINES = 50;
const MAX_SPLIT_MEMO_LENGTH = 240;

export class CostAllocationError extends Error {
  constructor(code, message, statusCode = 400, details = {}) {
    super(message);
    this.name = "CostAllocationError";
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
    throw new CostAllocationError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return parsed;
}

function dateOnly(value, field) {
  const raw = cleanString(value, 20);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    throw new CostAllocationError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  const [year, month, day] = raw.split("-").map(Number);
  const parsed = new Date(Date.UTC(year, month - 1, day));
  if (parsed.getUTCFullYear() !== year || parsed.getUTCMonth() !== month - 1 || parsed.getUTCDate() !== day) {
    throw new CostAllocationError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return raw;
}

function addDays(value, days) {
  const [year, month, day] = value.split("-").map(Number);
  return new Date(Date.UTC(year, month - 1, day + days)).toISOString().slice(0, 10);
}

export function parseTimeAllocationRange(startValue, endValue) {
  const startDate = dateOnly(startValue, "start_date");
  const endDate = dateOnly(endValue, "end_date");
  if (startDate > endDate) {
    throw new CostAllocationError("accounting_range_invalid", "Start date must be on or before end date.");
  }
  if (addDays(startDate, MAX_REPORT_DAYS - 1) < endDate) {
    throw new CostAllocationError(
      "accounting_range_too_large",
      `Clock allocation ranges cannot exceed ${MAX_REPORT_DAYS} days.`
    );
  }
  return { start_date: startDate, end_date: endDate };
}

function normalizedTimestamp(value, field) {
  const parsed = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(parsed.getTime())) {
    throw new CostAllocationError("time_entry_invalid", `The time entry ${field.replaceAll("_", " ")} is invalid.`, 409);
  }
  return parsed.toISOString();
}

export function timeEntryAllocationSnapshot(entry = {}) {
  if (!entry.end_at) {
    throw new CostAllocationError("time_entry_open", "Open time entries cannot be linked to a job.", 409);
  }
  if (entry.manual_status === "disapproved") {
    throw new CostAllocationError("time_entry_disapproved", "Disapproved time entries cannot be linked to a job.", 409);
  }
  const startAt = normalizedTimestamp(entry.start_at, "start_at");
  const endAt = normalizedTimestamp(entry.end_at, "end_at");
  const startMilliseconds = new Date(startAt).getTime();
  const endMilliseconds = new Date(endAt).getTime();
  const elapsedSeconds = Math.floor((endMilliseconds - startMilliseconds) / 1000);
  const breakSeconds = exactInteger(entry.break_seconds == null ? 0 : Number(entry.break_seconds), "break_seconds");
  if (elapsedSeconds <= 0 || breakSeconds >= elapsedSeconds) {
    throw new CostAllocationError("time_entry_duration_invalid", "The time entry must contain positive work time after breaks.", 409);
  }
  return {
    employee_id: String(entry.user_id),
    source_start_at: startAt,
    source_end_at: endAt,
    source_break_seconds: breakSeconds,
    source_work_seconds: elapsedSeconds - breakSeconds
  };
}

function timestampEqual(left, right) {
  if (!left || !right) return left == null && right == null;
  return new Date(left).getTime() === new Date(right).getTime();
}

export function timeLinkMatchesSnapshot(link, snapshot) {
  if (!link) return false;
  return String(link.employee_id) === snapshot.employee_id
    && timestampEqual(link.source_start_at, snapshot.source_start_at)
    && timestampEqual(link.source_end_at, snapshot.source_end_at)
    && Number(link.source_break_seconds) === snapshot.source_break_seconds
    && Number(link.source_work_seconds) === snapshot.source_work_seconds;
}

export function planTimeJobLinkUpdate({ body = {}, entry, currentLink = null, job = null }) {
  const expectedVersion = exactInteger(body.expected_version, "expected_version");
  const reason = cleanString(body.reason, 500);
  if (!reason) throw new CostAllocationError("time_job_link_reason_required", "Add a reason for this time allocation change.");
  const requestedJobId = body.job_id == null ? null : cleanString(body.job_id, 120) || null;
  if (requestedJobId && (!job || String(job.id) !== requestedJobId)) {
    throw new CostAllocationError("accounting_job_not_found", "The company job was not found.", 404);
  }
  const currentVersion = currentLink ? exactInteger(Number(currentLink.version), "version", { minimum: 1 }) : 0;
  if (expectedVersion !== currentVersion) {
    throw new CostAllocationError(
      "time_job_link_stale",
      "This time allocation changed after it was loaded. Refresh before saving again.",
      409,
      { current_version: currentVersion }
    );
  }
  const currentJobId = currentLink?.job_id ? String(currentLink.job_id) : null;
  if (!requestedJobId) {
    if (!currentJobId) {
      return { mode: "replay", current_version: currentVersion, requested_job_id: null, snapshot: null, reason };
    }
    const storedSnapshot = {
      employee_id: String(currentLink.employee_id),
      source_start_at: normalizedTimestamp(currentLink.source_start_at, "source_start_at"),
      source_end_at: normalizedTimestamp(currentLink.source_end_at, "source_end_at"),
      source_break_seconds: exactInteger(Number(currentLink.source_break_seconds), "source_break_seconds"),
      source_work_seconds: exactInteger(Number(currentLink.source_work_seconds), "source_work_seconds", { minimum: 1 })
    };
    return {
      mode: "update", current_version: currentVersion, requested_job_id: null,
      snapshot: storedSnapshot, reason, action: "time_job_unlinked"
    };
  }
  const snapshot = timeEntryAllocationSnapshot(entry);
  const sourceChanged = currentLink ? !timeLinkMatchesSnapshot(currentLink, snapshot) : false;
  if (currentJobId === requestedJobId && !sourceChanged) {
    return { mode: "replay", current_version: currentVersion, requested_job_id: requestedJobId, snapshot, reason };
  }
  let action = "time_job_link_refreshed";
  if (!currentJobId && requestedJobId) action = "time_job_linked";
  else if (currentJobId && !requestedJobId) action = "time_job_unlinked";
  else if (currentJobId !== requestedJobId) action = "time_job_relinked";
  return { mode: currentLink ? "update" : "create", current_version: currentVersion, requested_job_id: requestedJobId, snapshot, reason, action };
}

function storedTimeSnapshot(link) {
  if (!link) return null;
  return {
    employee_id: String(link.employee_id),
    source_start_at: normalizedTimestamp(link.source_start_at, "source_start_at"),
    source_end_at: normalizedTimestamp(link.source_end_at, "source_end_at"),
    source_break_seconds: exactInteger(Number(link.source_break_seconds), "source_break_seconds"),
    source_work_seconds: exactInteger(Number(link.source_work_seconds), "source_work_seconds", { minimum: 1 })
  };
}

function timeLineComparable(line, index = 0) {
  return {
    line_order: exactInteger(Number(line.line_order ?? index), "line_order", { maximum: MAX_SPLIT_LINES - 1 }),
    target_kind: String(line.target_kind),
    job_id: line.job_id ? String(line.job_id) : null,
    allocated_seconds: exactInteger(Number(line.allocated_seconds), "allocated_seconds", { minimum: 1 }),
    memo: cleanString(line.memo, MAX_SPLIT_MEMO_LENGTH) || null
  };
}

function timeLinesMatch(currentLines, requestedLines) {
  if (currentLines.length !== requestedLines.length) return false;
  const current = currentLines.map(timeLineComparable);
  return current.every((line, index) => JSON.stringify(line) === JSON.stringify(requestedLines[index]));
}

export function requestedTimeAllocationJobIds(body = {}) {
  const mode = cleanString(body.mode, 40);
  if (mode === "whole_job") {
    const jobId = cleanString(body.job_id, 120);
    return jobId ? [jobId] : [];
  }
  if (mode !== "split" || !Array.isArray(body.lines)) return [];
  return [...new Set(body.lines
    .filter((line) => cleanString(line?.target_kind, 40) === "job")
    .map((line) => cleanString(line?.job_id, 120))
    .filter(Boolean))];
}

function normalizeTimeSplitLines(lines, sourceWorkSeconds, jobs = []) {
  if (!Array.isArray(lines) || lines.length < 2 || lines.length > MAX_SPLIT_LINES) {
    throw new CostAllocationError(
      "time_split_lines_invalid",
      `Split time requires between 2 and ${MAX_SPLIT_LINES} explicit lines.`
    );
  }
  const jobMap = new Map(jobs.map((job) => [String(job.id), job]));
  const targets = new Set();
  let totalSeconds = 0;
  const normalized = lines.map((raw, index) => {
    const targetKind = cleanString(raw?.target_kind, 40);
    if (!["job", "admin", "travel"].includes(targetKind)) {
      throw new CostAllocationError("time_split_target_invalid", "Each split target must be a job, Administration, or Travel.");
    }
    const jobId = raw?.job_id == null ? null : cleanString(raw.job_id, 120) || null;
    if (targetKind === "job" && (!jobId || !jobMap.has(jobId))) {
      throw new CostAllocationError("accounting_job_not_found", "A company job in this split was not found.", 404);
    }
    if (targetKind !== "job" && jobId) {
      throw new CostAllocationError("time_split_target_invalid", "Administration and Travel lines cannot contain a job.");
    }
    const targetKey = targetKind === "job" ? `job:${jobId}` : targetKind;
    if (targets.has(targetKey)) {
      throw new CostAllocationError("time_split_target_duplicate", "Each job, Administration, and Travel target may appear only once.");
    }
    targets.add(targetKey);
    const allocatedSeconds = exactInteger(raw?.allocated_seconds, "allocated_seconds", {
      minimum: 1,
      maximum: sourceWorkSeconds
    });
    if (totalSeconds > Number.MAX_SAFE_INTEGER - allocatedSeconds) {
      throw new CostAllocationError("time_split_total_inexact", "Split time exceeds the exact supported range.");
    }
    totalSeconds += allocatedSeconds;
    const rawMemo = (raw?.memo ?? "").toString().trim();
    if (rawMemo.length > MAX_SPLIT_MEMO_LENGTH) {
      throw new CostAllocationError("time_split_memo_too_long", `Split notes cannot exceed ${MAX_SPLIT_MEMO_LENGTH} characters.`);
    }
    return {
      line_order: index,
      target_kind: targetKind,
      job_id: targetKind === "job" ? jobId : null,
      allocated_seconds: allocatedSeconds,
      memo: rawMemo || null
    };
  });
  if (totalSeconds !== sourceWorkSeconds) {
    throw new CostAllocationError(
      "time_split_unbalanced",
      `Split durations must total exactly ${sourceWorkSeconds} work seconds.`,
      400,
      { expected_seconds: sourceWorkSeconds, allocated_seconds: totalSeconds }
    );
  }
  return normalized;
}

export function planTimeAllocationUpdate({ body = {}, entry, currentLink = null, currentLines = [], jobs = [] }) {
  const expectedVersion = exactInteger(body.expected_version, "expected_version");
  const reason = cleanString(body.reason, 500);
  if (!reason) throw new CostAllocationError("time_allocation_reason_required", "Add a reason for this time allocation change.");
  const currentVersion = currentLink ? exactInteger(Number(currentLink.version), "version", { minimum: 1 }) : 0;
  if (expectedVersion !== currentVersion) {
    throw new CostAllocationError(
      "time_allocation_stale",
      "This time allocation changed after it was loaded. Refresh before saving again.",
      409,
      { current_version: currentVersion }
    );
  }
  const mode = cleanString(body.mode, 40);
  if (!["whole_job", "split", "unallocated"].includes(mode)) {
    throw new CostAllocationError("time_allocation_mode_invalid", "Choose Whole Job, Split, or Unallocated.");
  }
  const hasSplit = currentLines.length > 0;
  const currentJobId = currentLink?.job_id ? String(currentLink.job_id) : null;
  if (mode === "unallocated") {
    if (!currentJobId && !hasSplit) {
      return { mode: "replay", allocation_mode: "unallocated", current_version: currentVersion, snapshot: null, job_id: null, lines: [], reason };
    }
    return {
      mode: "update",
      allocation_mode: "unallocated",
      current_version: currentVersion,
      snapshot: storedTimeSnapshot(currentLink),
      job_id: null,
      lines: [],
      reason,
      action: "time_allocation_cleared"
    };
  }

  const snapshot = timeEntryAllocationSnapshot(entry);
  const sourceChanged = currentLink ? !timeLinkMatchesSnapshot(currentLink, snapshot) : false;
  if (mode === "whole_job") {
    const jobId = cleanString(body.job_id, 120);
    const job = jobs.find((candidate) => String(candidate.id) === jobId);
    if (!jobId || !job) {
      throw new CostAllocationError("accounting_job_not_found", "The company job was not found.", 404);
    }
    if (!hasSplit && currentJobId === jobId && !sourceChanged) {
      return { mode: "replay", allocation_mode: "whole_job", current_version: currentVersion, snapshot, job_id: jobId, lines: [], reason };
    }
    let action = "time_job_link_refreshed";
    if (hasSplit) action = "time_split_replaced_with_whole";
    else if (!currentJobId) action = "time_job_linked";
    else if (currentJobId !== jobId) action = "time_job_relinked";
    return {
      mode: currentLink ? "update" : "create",
      allocation_mode: "whole_job",
      current_version: currentVersion,
      snapshot,
      job_id: jobId,
      lines: [],
      reason,
      action
    };
  }

  const lines = normalizeTimeSplitLines(body.lines, snapshot.source_work_seconds, jobs);
  if (!currentJobId && hasSplit && !sourceChanged && timeLinesMatch(currentLines, lines)) {
    return { mode: "replay", allocation_mode: "split", current_version: currentVersion, snapshot, job_id: null, lines, reason };
  }
  let action = "time_split_replaced";
  if (currentJobId) action = "time_whole_replaced_with_split";
  else if (!hasSplit) action = "time_split_allocated";
  else if (sourceChanged && timeLinesMatch(currentLines, lines)) action = "time_split_refreshed";
  return {
    mode: currentLink ? "update" : "create",
    allocation_mode: "split",
    current_version: currentVersion,
    snapshot,
    job_id: null,
    lines,
    reason,
    action
  };
}

function safeDbInteger(value, field) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(parsed)) {
    throw new CostAllocationError("time_allocation_source_inexact", `${field.replaceAll("_", " ")} exceeds exact integer range.`, 500);
  }
  return parsed;
}

function linkPayload(row) {
  if (!row) return null;
  return {
    id: String(row.id),
    time_entry_id: String(row.time_entry_id),
    employee_id: String(row.employee_id),
    job_id: row.job_id || null,
    source_start_at: row.source_start_at,
    source_end_at: row.source_end_at,
    source_break_seconds: safeDbInteger(row.source_break_seconds, "source_break_seconds"),
    source_work_seconds: safeDbInteger(row.source_work_seconds, "source_work_seconds"),
    version: safeDbInteger(row.version, "version"),
    linked_by: row.linked_by || null,
    linked_at: row.linked_at || null,
    created_at: row.created_at || null,
    updated_at: row.updated_at || null
  };
}

function linkSnapshot(row) {
  const payload = linkPayload(row);
  if (!payload) return null;
  return {
    id: payload.id,
    time_entry_id: payload.time_entry_id,
    employee_id: payload.employee_id,
    job_id: payload.job_id,
    source_start_at: payload.source_start_at,
    source_end_at: payload.source_end_at,
    source_break_seconds: payload.source_break_seconds,
    source_work_seconds: payload.source_work_seconds,
    version: payload.version
  };
}

function splitLinePayload(row) {
  return {
    id: row.id ? String(row.id) : null,
    line_order: safeDbInteger(row.line_order, "line_order"),
    target_kind: String(row.target_kind),
    job_id: row.job_id || null,
    job_title: row.job_title || null,
    allocated_seconds: safeDbInteger(row.allocated_seconds, "allocated_seconds"),
    memo: row.memo || null,
    job_missing: row.target_kind === "job" && row.job_exists === false
  };
}

function allocationSnapshot(link, lines = []) {
  const header = linkSnapshot(link);
  if (!header) return null;
  const normalizedLines = lines.map(splitLinePayload).map((line) => ({
    id: line.id,
    line_order: line.line_order,
    target_kind: line.target_kind,
    job_id: line.job_id,
    allocated_seconds: line.allocated_seconds,
    memo: line.memo
  }));
  return {
    ...header,
    allocation_mode: normalizedLines.length ? "split" : header.job_id ? "whole_job" : "unallocated",
    lines: normalizedLines
  };
}

function allocationStatus(row) {
  if (!row.duration_valid) return row.job_id ? "stale" : "invalid";
  if (!row.job_id) return "unallocated";
  if (!row.source_current || !row.job_exists) return "stale";
  return "allocated";
}

function entryPayload(row) {
  const status = row.allocation_status || allocationStatus(row);
  const splitLineCount = safeDbInteger(row.split_line_count || 0, "split_line_count");
  const allocationMode = row.allocation_mode || (splitLineCount ? "split" : row.job_id ? "whole_job" : "unallocated");
  const jobAllocatedSeconds = row.job_allocated_seconds == null
    ? (status === "allocated" && allocationMode === "whole_job" ? safeDbInteger(row.work_seconds, "work_seconds") : 0)
    : safeDbInteger(row.job_allocated_seconds, "job_allocated_seconds");
  const adminAllocatedSeconds = safeDbInteger(row.admin_allocated_seconds || 0, "admin_allocated_seconds");
  const travelAllocatedSeconds = safeDbInteger(row.travel_allocated_seconds || 0, "travel_allocated_seconds");
  const allocatedSeconds = row.allocated_seconds == null
    ? jobAllocatedSeconds + adminAllocatedSeconds + travelAllocatedSeconds
    : safeDbInteger(row.allocated_seconds, "allocated_seconds");
  const workSeconds = row.work_seconds == null ? null : safeDbInteger(row.work_seconds, "work_seconds");
  return {
    time_entry_id: String(row.time_entry_id),
    employee_id: String(row.employee_id),
    employee_name: row.employee_name,
    start_at: row.start_at,
    end_at: row.end_at,
    break_seconds: safeDbInteger(row.break_seconds || 0, "break_seconds"),
    work_seconds: workSeconds,
    manual_entry: Boolean(row.manual_entry),
    manual_status: row.manual_status,
    job_id: row.job_id || null,
    job_title: row.job_title || null,
    link_version: row.link_version == null ? 0 : safeDbInteger(row.link_version, "link_version"),
    allocation_mode: allocationMode,
    split_line_count: splitLineCount,
    allocation_status: status,
    source_changed: Boolean(row.has_allocation ?? (row.job_id || splitLineCount)) && !Boolean(row.source_current),
    job_missing: (Boolean(row.job_id) && !Boolean(row.job_exists)) || safeDbInteger(row.missing_job_count || 0, "missing_job_count") > 0,
    missing_job_count: safeDbInteger(row.missing_job_count || 0, "missing_job_count"),
    allocated_seconds: allocatedSeconds,
    job_allocated_seconds: jobAllocatedSeconds,
    admin_allocated_seconds: adminAllocatedSeconds,
    travel_allocated_seconds: travelAllocatedSeconds,
    unallocated_seconds: row.unallocated_seconds == null
      ? Math.max((workSeconds || 0) - allocatedSeconds, 0)
      : safeDbInteger(row.unallocated_seconds, "unallocated_seconds")
  };
}

function sendCostError(res, error, fallback) {
  if (error instanceof CostAllocationError || error?.statusCode) {
    return res.status(error.statusCode || 400).json({
      error: error.code || fallback,
      message: error.message,
      current_version: error.current_version
    });
  }
  console.error("[finance-cost-allocations]", fallback, { code: error?.code, message: error?.message });
  return res.status(500).json({ error: fallback, message: "Clock allocation request failed." });
}

export async function installFinanceCostAllocationSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS finance_time_job_links (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      time_entry_id TEXT NOT NULL,
      employee_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
      job_id TEXT,
      source_start_at TIMESTAMPTZ NOT NULL,
      source_end_at TIMESTAMPTZ NOT NULL,
      source_break_seconds INTEGER NOT NULL,
      source_work_seconds INTEGER NOT NULL,
      version INTEGER NOT NULL DEFAULT 1,
      linked_by UUID REFERENCES users(id) ON DELETE SET NULL,
      linked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, time_entry_id),
      CHECK (source_end_at > source_start_at),
      CHECK (source_break_seconds >= 0),
      CHECK (source_work_seconds > 0),
      CHECK (version > 0)
    );
    CREATE INDEX IF NOT EXISTS finance_time_job_links_company_job_idx
      ON finance_time_job_links(company_id, job_id) WHERE job_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS finance_time_job_links_company_employee_idx
      ON finance_time_job_links(company_id, employee_id, source_start_at DESC);

    CREATE TABLE IF NOT EXISTS finance_time_allocation_lines (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      link_id UUID NOT NULL REFERENCES finance_time_job_links(id) ON DELETE RESTRICT,
      time_entry_id TEXT NOT NULL,
      line_order SMALLINT NOT NULL,
      target_kind TEXT NOT NULL,
      job_id TEXT,
      allocated_seconds INTEGER NOT NULL,
      memo TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, time_entry_id, line_order),
      CHECK (line_order >= 0 AND line_order < 50),
      CHECK (target_kind IN ('job', 'admin', 'travel')),
      CHECK ((target_kind = 'job' AND job_id IS NOT NULL) OR (target_kind IN ('admin', 'travel') AND job_id IS NULL)),
      CHECK (allocated_seconds > 0)
    );
    CREATE INDEX IF NOT EXISTS finance_time_allocation_lines_header_idx
      ON finance_time_allocation_lines(company_id, link_id, line_order);
    CREATE INDEX IF NOT EXISTS finance_time_allocation_lines_company_job_idx
      ON finance_time_allocation_lines(company_id, job_id) WHERE job_id IS NOT NULL;

    CREATE TABLE IF NOT EXISTS finance_time_job_link_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      time_entry_id TEXT NOT NULL,
      link_id UUID NOT NULL REFERENCES finance_time_job_links(id) ON DELETE RESTRICT,
      actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      reason TEXT NOT NULL,
      before_state JSONB,
      after_state JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS finance_time_job_link_audit_company_entry_idx
      ON finance_time_job_link_audit(company_id, time_entry_id, created_at DESC);
  `);
}

async function companyContext(client, companyId) {
  const { rows } = await client.query(
    `SELECT COALESCE(NULLIF(timezone, ''), 'America/New_York') AS timezone
       FROM companies WHERE id = $1`,
    [companyId]
  );
  if (!rows[0]) throw new CostAllocationError("company_not_found", "The company workspace was not found.", 404);
  return rows[0];
}

const ALLOCATION_CTE = `
  WITH company AS (
    SELECT COALESCE(NULLIF(timezone, ''), 'America/New_York') AS timezone FROM companies WHERE id = $1
  ), line_rollup AS (
    SELECT al.link_id,
           COUNT(*)::bigint AS split_line_count,
           COALESCE(SUM(al.allocated_seconds), 0)::bigint AS split_total_seconds,
           COALESCE(SUM(al.allocated_seconds) FILTER (WHERE al.target_kind = 'job' AND sj.id IS NOT NULL), 0)::bigint AS split_job_seconds,
           COALESCE(SUM(al.allocated_seconds) FILTER (WHERE al.target_kind = 'admin'), 0)::bigint AS split_admin_seconds,
           COALESCE(SUM(al.allocated_seconds) FILTER (WHERE al.target_kind = 'travel'), 0)::bigint AS split_travel_seconds,
           COUNT(*) FILTER (WHERE al.target_kind = 'job' AND sj.id IS NULL)::bigint AS missing_job_count
      FROM finance_time_allocation_lines al
      LEFT JOIN schedule_events sj ON sj.company_id = al.company_id AND sj.id = al.job_id
     WHERE al.company_id = $1
     GROUP BY al.link_id
  ), scoped AS (
    SELECT e.id AS time_entry_id, e.user_id AS employee_id,
           COALESCE(NULLIF(u.display_name, ''), u.email) AS employee_name,
           e.start_at, e.end_at, COALESCE(e.break_seconds, 0)::bigint AS break_seconds,
           e.manual_entry, e.manual_status,
           (e.end_at IS NOT NULL AND e.manual_status <> 'disapproved') AS eligible,
           CASE WHEN e.end_at > e.start_at
                  AND COALESCE(e.break_seconds, 0) >= 0
                  AND COALESCE(e.break_seconds, 0) < FLOOR(EXTRACT(EPOCH FROM (e.end_at - e.start_at)))
                THEN FLOOR(EXTRACT(EPOCH FROM (e.end_at - e.start_at)))::bigint - COALESCE(e.break_seconds, 0)::bigint
                ELSE NULL END AS work_seconds,
           l.id AS link_id, l.job_id, l.version AS link_version,
           (l.id IS NOT NULL
             AND e.end_at IS NOT NULL
             AND e.manual_status <> 'disapproved'
             AND l.employee_id = e.user_id
             AND l.source_start_at = e.start_at
             AND l.source_end_at = e.end_at
             AND l.source_break_seconds = COALESCE(e.break_seconds, 0)
             AND l.source_work_seconds = CASE WHEN e.end_at > e.start_at
               THEN FLOOR(EXTRACT(EPOCH FROM (e.end_at - e.start_at)))::bigint - COALESCE(e.break_seconds, 0)::bigint
               ELSE -1 END) AS source_current,
           (j.id IS NOT NULL) AS job_exists, j.title AS job_title,
           COALESCE(lr.split_line_count, 0)::bigint AS split_line_count,
           COALESCE(lr.split_total_seconds, 0)::bigint AS split_total_seconds,
           COALESCE(lr.split_job_seconds, 0)::bigint AS split_job_seconds,
           COALESCE(lr.split_admin_seconds, 0)::bigint AS split_admin_seconds,
           COALESCE(lr.split_travel_seconds, 0)::bigint AS split_travel_seconds,
           COALESCE(lr.missing_job_count, 0)::bigint AS missing_job_count,
           (l.job_id IS NOT NULL OR COALESCE(lr.split_line_count, 0) > 0) AS has_allocation,
           CASE WHEN COALESCE(lr.split_line_count, 0) > 0 THEN 'split'
                WHEN l.job_id IS NOT NULL THEN 'whole_job' ELSE 'unallocated' END AS allocation_mode,
           (e.end_at IS NOT NULL
             AND e.manual_status <> 'disapproved'
             AND e.end_at > e.start_at
             AND COALESCE(e.break_seconds, 0) >= 0
             AND COALESCE(e.break_seconds, 0) < FLOOR(EXTRACT(EPOCH FROM (e.end_at - e.start_at)))) AS duration_valid
      FROM time_clock_entries e
      JOIN users u ON u.id = e.user_id AND u.company_id = e.company_id
      CROSS JOIN company
      LEFT JOIN finance_time_job_links l ON l.company_id = e.company_id AND l.time_entry_id = e.id
      LEFT JOIN schedule_events j ON j.company_id = e.company_id AND j.id = l.job_id
      LEFT JOIN line_rollup lr ON lr.link_id = l.id
     WHERE e.company_id = $1
       AND e.start_at >= ($2::date::timestamp AT TIME ZONE company.timezone)
       AND e.start_at < (($3::date + 1)::timestamp AT TIME ZONE company.timezone)
  ), bucketed AS (
    SELECT scoped.*,
           CASE WHEN duration_valid AND source_current AND split_line_count > 0 AND split_total_seconds = work_seconds
                  THEN split_job_seconds
                WHEN duration_valid AND source_current AND split_line_count = 0 AND job_id IS NOT NULL AND job_exists
                  THEN work_seconds ELSE 0 END::bigint AS job_allocated_seconds,
           CASE WHEN duration_valid AND source_current AND split_line_count > 0 AND split_total_seconds = work_seconds
                  THEN split_admin_seconds ELSE 0 END::bigint AS admin_allocated_seconds,
           CASE WHEN duration_valid AND source_current AND split_line_count > 0 AND split_total_seconds = work_seconds
                  THEN split_travel_seconds ELSE 0 END::bigint AS travel_allocated_seconds
      FROM scoped
  ), evaluated AS (
    SELECT bucketed.*,
           (job_allocated_seconds + admin_allocated_seconds + travel_allocated_seconds)::bigint AS allocated_seconds,
           CASE WHEN duration_valid THEN GREATEST(
             work_seconds - job_allocated_seconds - admin_allocated_seconds - travel_allocated_seconds,
             0
           ) ELSE 0 END::bigint AS unallocated_seconds,
           CASE WHEN NOT duration_valid THEN CASE WHEN has_allocation THEN 'stale' ELSE 'invalid' END
                WHEN NOT has_allocation THEN 'unallocated'
                WHEN NOT source_current THEN 'stale'
                WHEN split_line_count > 0 AND split_total_seconds <> work_seconds THEN 'stale'
                WHEN job_allocated_seconds + admin_allocated_seconds + travel_allocated_seconds = work_seconds THEN 'allocated'
                WHEN job_allocated_seconds + admin_allocated_seconds + travel_allocated_seconds > 0 THEN 'partially_allocated'
                ELSE 'stale' END AS allocation_status
      FROM bucketed
  )`;

async function loadAllocationRows(pool, companyId, range, limit) {
  const summaryResult = await pool.query(
    `${ALLOCATION_CTE}
     SELECT COUNT(*) FILTER (WHERE eligible)::bigint AS completed_entry_count,
            COUNT(*) FILTER (WHERE duration_valid)::bigint AS valid_entry_count,
            COUNT(*) FILTER (WHERE duration_valid AND allocation_status = 'allocated')::bigint AS allocated_entry_count,
            COALESCE(SUM(allocated_seconds), 0)::bigint AS allocated_seconds,
            COUNT(*) FILTER (WHERE duration_valid AND unallocated_seconds > 0)::bigint AS unallocated_entry_count,
            COALESCE(SUM(unallocated_seconds), 0)::bigint AS unallocated_seconds,
            COUNT(*) FILTER (WHERE has_allocation AND allocation_status <> 'allocated')::bigint AS stale_link_count,
            COUNT(*) FILTER (WHERE eligible AND NOT duration_valid)::bigint AS invalid_entry_count,
            COUNT(*) FILTER (WHERE has_allocation AND allocation_mode = 'whole_job')::bigint AS whole_entry_count,
            COUNT(*) FILTER (WHERE has_allocation AND allocation_mode = 'split')::bigint AS split_entry_count,
            COALESCE(SUM(job_allocated_seconds), 0)::bigint AS job_allocated_seconds,
            COALESCE(SUM(admin_allocated_seconds), 0)::bigint AS admin_allocated_seconds,
            COALESCE(SUM(travel_allocated_seconds), 0)::bigint AS travel_allocated_seconds,
            COUNT(*) FILTER (WHERE eligible OR has_allocation)::bigint AS review_row_count
       FROM evaluated`,
    [companyId, range.start_date, range.end_date]
  );
  const coverageResult = await pool.query(
    `WITH company AS (
       SELECT COALESCE(NULLIF(timezone, ''), 'America/New_York') AS timezone FROM companies WHERE id = $1
     )
     SELECT COUNT(*) FILTER (WHERE e.end_at IS NULL AND e.manual_status <> 'disapproved')::bigint AS open_entry_count,
            COUNT(*) FILTER (WHERE e.manual_status = 'disapproved')::bigint AS disapproved_entry_count
       FROM time_clock_entries e CROSS JOIN company
      WHERE e.company_id = $1
        AND e.start_at >= ($2::date::timestamp AT TIME ZONE company.timezone)
        AND e.start_at < (($3::date + 1)::timestamp AT TIME ZONE company.timezone)`,
    [companyId, range.start_date, range.end_date]
  );
  const rowsResult = await pool.query(
    `${ALLOCATION_CTE}
     SELECT * FROM evaluated
      WHERE eligible OR has_allocation
      ORDER BY start_at DESC, time_entry_id
      LIMIT $4`,
    [companyId, range.start_date, range.end_date, limit + 1]
  );
  return { summary: summaryResult.rows[0] || {}, coverage: coverageResult.rows[0] || {}, rows: rowsResult.rows };
}

async function loadEntryDetail(client, companyId, entryId, { lock = false } = {}) {
  const entryResult = await client.query(
    `SELECT e.*, COALESCE(NULLIF(u.display_name, ''), u.email) AS employee_name
       FROM time_clock_entries e
       JOIN users u ON u.id = e.user_id AND u.company_id = e.company_id
      WHERE e.company_id = $1 AND e.id = $2${lock ? " FOR UPDATE OF e" : ""}`,
    [companyId, entryId]
  );
  if (!entryResult.rows[0]) throw new CostAllocationError("time_entry_not_found", "The company time entry was not found.", 404);
  const linkResult = await client.query(
    `SELECT * FROM finance_time_job_links WHERE company_id = $1 AND time_entry_id = $2${lock ? " FOR UPDATE" : ""}`,
    [companyId, entryId]
  );
  const lineResult = linkResult.rows[0]
    ? await client.query(
      `SELECT al.*, sj.title AS job_title, (sj.id IS NOT NULL) AS job_exists
         FROM finance_time_allocation_lines al
         LEFT JOIN schedule_events sj ON sj.company_id = al.company_id AND sj.id = al.job_id
        WHERE al.company_id = $1 AND al.link_id = $2
        ORDER BY al.line_order${lock ? " FOR UPDATE OF al" : ""}`,
      [companyId, linkResult.rows[0].id]
    )
    : { rows: [] };
  return { entry: entryResult.rows[0], link: linkResult.rows[0] || null, lines: lineResult.rows };
}

async function candidateJobs(client, companyId, entry, currentJobIds = []) {
  const { rows } = await client.query(
    `SELECT se.id AS job_id, se.title, se.start_at, se.end_at, se.finished_at,
            COALESCE(c.name, 'No customer name') AS contact_name,
            (se.worker_user_ids ? $5::text) AS worker_assigned,
            (se.start_at < $4::timestamptz AND se.end_at > $3::timestamptz) AS overlaps_entry
       FROM schedule_events se
       LEFT JOIN contacts c ON c.company_id = se.company_id AND c.id::text = se.contact_id
      WHERE se.company_id = $1
        AND (se.id = ANY($2::text[]) OR (se.start_at >= $3::timestamptz - interval '31 days'
          AND se.start_at <= $4::timestamptz + interval '31 days'))
      ORDER BY (se.id = ANY($2::text[])) DESC,
               (se.start_at < $4::timestamptz AND se.end_at > $3::timestamptz) DESC,
               (se.worker_user_ids ? $5::text) DESC,
               ABS(EXTRACT(EPOCH FROM (se.start_at - $3::timestamptz))) ASC,
               se.id
      LIMIT $6`,
    [companyId, currentJobIds, entry.start_at, entry.end_at || entry.start_at, String(entry.user_id), MAX_CANDIDATE_JOBS]
  );
  return rows.map((row) => ({
    job_id: String(row.job_id), title: row.title, contact_name: row.contact_name,
    start_at: row.start_at, end_at: row.end_at, finished_at: row.finished_at || null,
    worker_assigned: Boolean(row.worker_assigned), overlaps_entry: Boolean(row.overlaps_entry)
  }));
}

function detailEntryPayload(entry, link, job = null, lines = []) {
  let snapshot = null;
  try { snapshot = timeEntryAllocationSnapshot(entry); } catch { /* detail must still explain invalid evidence */ }
  const sourceCurrent = snapshot && link ? timeLinkMatchesSnapshot(link, snapshot) : false;
  const splitLineCount = lines.length;
  const allocationMode = splitLineCount ? "split" : link?.job_id ? "whole_job" : "unallocated";
  const hasAllocation = allocationMode !== "unallocated";
  const missingJobCount = splitLineCount
    ? lines.filter((line) => line.target_kind === "job" && !line.job_exists).length
    : link?.job_id && !job ? 1 : 0;
  const splitTotalSeconds = lines.reduce((sum, line) => sum + safeDbInteger(line.allocated_seconds, "allocated_seconds"), 0);
  const splitBalanced = Boolean(snapshot) && splitLineCount > 0 && splitTotalSeconds === snapshot.source_work_seconds;
  let jobAllocatedSeconds = 0;
  let adminAllocatedSeconds = 0;
  let travelAllocatedSeconds = 0;
  if (snapshot && sourceCurrent) {
    if (splitBalanced) {
      for (const line of lines) {
        const seconds = safeDbInteger(line.allocated_seconds, "allocated_seconds");
        if (line.target_kind === "job" && line.job_exists) jobAllocatedSeconds += seconds;
        else if (line.target_kind === "admin") adminAllocatedSeconds += seconds;
        else if (line.target_kind === "travel") travelAllocatedSeconds += seconds;
      }
    } else if (!splitLineCount && link?.job_id && job) {
      jobAllocatedSeconds = snapshot.source_work_seconds;
    }
  }
  const allocatedSeconds = jobAllocatedSeconds + adminAllocatedSeconds + travelAllocatedSeconds;
  const unallocatedSeconds = snapshot ? Math.max(snapshot.source_work_seconds - allocatedSeconds, 0) : 0;
  let status = "unallocated";
  if (!snapshot) status = hasAllocation ? "stale" : "invalid";
  else if (hasAllocation && !sourceCurrent) status = "stale";
  else if (splitLineCount && !splitBalanced) status = "stale";
  else if (allocatedSeconds === snapshot.source_work_seconds) status = "allocated";
  else if (allocatedSeconds > 0) status = "partially_allocated";
  else if (hasAllocation) status = "stale";
  return {
    time_entry_id: String(entry.id), employee_id: String(entry.user_id), employee_name: entry.employee_name,
    start_at: entry.start_at, end_at: entry.end_at || null,
    break_seconds: safeDbInteger(entry.break_seconds || 0, "break_seconds"),
    work_seconds: snapshot?.source_work_seconds ?? null,
    manual_entry: Boolean(entry.manual_entry), manual_status: entry.manual_status,
    job_id: link?.job_id || null, job_title: job?.title || null,
    link_version: link ? safeDbInteger(link.version, "version") : 0,
    allocation_mode: allocationMode, split_line_count: splitLineCount,
    allocation_status: status,
    source_changed: hasAllocation && !sourceCurrent,
    job_missing: missingJobCount > 0, missing_job_count: missingJobCount,
    allocated_seconds: allocatedSeconds,
    job_allocated_seconds: jobAllocatedSeconds,
    admin_allocated_seconds: adminAllocatedSeconds,
    travel_allocated_seconds: travelAllocatedSeconds,
    unallocated_seconds: unallocatedSeconds
  };
}

export function installFinanceCostAllocationRoutes({ app, pool, authRequired, requireFinanceAccess }) {
  app.get("/api/finance/accounting/time-allocations", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Accounting requires a company workspace." });
    try {
      const range = parseTimeAllocationRange(req.query.start_date, req.query.end_date);
      const requestedLimit = Number(req.query.limit || 200);
      const limit = Math.min(Math.max(Number.isSafeInteger(requestedLimit) ? requestedLimit : 200, 1), MAX_REPORT_ROWS);
      const context = await companyContext(pool, req.companyId);
      const loaded = await loadAllocationRows(pool, req.companyId, range, limit);
      const totalCount = safeDbInteger(loaded.summary.review_row_count || 0, "review_row_count");
      const returnedRows = loaded.rows.slice(0, limit);
      const summary = {
        completed_entry_count: safeDbInteger(loaded.summary.completed_entry_count || 0, "completed_entry_count"),
        valid_entry_count: safeDbInteger(loaded.summary.valid_entry_count || 0, "valid_entry_count"),
        allocated_entry_count: safeDbInteger(loaded.summary.allocated_entry_count || 0, "allocated_entry_count"),
        allocated_seconds: safeDbInteger(loaded.summary.allocated_seconds || 0, "allocated_seconds"),
        unallocated_entry_count: safeDbInteger(loaded.summary.unallocated_entry_count || 0, "unallocated_entry_count"),
        unallocated_seconds: safeDbInteger(loaded.summary.unallocated_seconds || 0, "unallocated_seconds"),
        stale_link_count: safeDbInteger(loaded.summary.stale_link_count || 0, "stale_link_count"),
        invalid_entry_count: safeDbInteger(loaded.summary.invalid_entry_count || 0, "invalid_entry_count"),
        open_entry_count: safeDbInteger(loaded.coverage.open_entry_count || 0, "open_entry_count"),
        disapproved_entry_count: safeDbInteger(loaded.coverage.disapproved_entry_count || 0, "disapproved_entry_count"),
        whole_entry_count: safeDbInteger(loaded.summary.whole_entry_count || 0, "whole_entry_count"),
        split_entry_count: safeDbInteger(loaded.summary.split_entry_count || 0, "split_entry_count"),
        job_allocated_seconds: safeDbInteger(loaded.summary.job_allocated_seconds || 0, "job_allocated_seconds"),
        admin_allocated_seconds: safeDbInteger(loaded.summary.admin_allocated_seconds || 0, "admin_allocated_seconds"),
        travel_allocated_seconds: safeDbInteger(loaded.summary.travel_allocated_seconds || 0, "travel_allocated_seconds")
      };
      const warnings = [
        "Only explicitly reviewed whole-job or exact split lines count as allocated clock evidence. Schedule overlap and worker assignment never choose a target or duration.",
        "Job, Administration, and Travel time are operational evidence only. No pay rate, overtime, burden, tax, benefit, mileage, payroll, P&L, or margin dollars are calculated.",
        "A changed source invalidates the full allocation. A missing split job returns only that line's seconds to unallocated while other current lines remain usable."
      ];
      if (summary.stale_link_count) warnings.push("Stale time links are excluded until the changed source entry or missing job is reviewed.");
      if (summary.invalid_entry_count) warnings.push("Invalid completed durations are excluded instead of becoming zero time.");
      res.json({
        basis: "explicit_reviewed_whole_and_split_time_allocations",
        start_date: range.start_date, end_date: range.end_date, timezone: context.timezone,
        summary, total_count: totalCount, returned_count: returnedRows.length,
        truncated: loaded.rows.length > limit, warnings,
        entries: returnedRows.map(entryPayload)
      });
    } catch (error) {
      sendCostError(res, error, "time_allocations_load_failed");
    }
  });

  app.get("/api/finance/accounting/time-allocations/:entryId", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Accounting requires a company workspace." });
    try {
      const detail = await loadEntryDetail(pool, req.companyId, req.params.entryId);
      const job = detail.link?.job_id
        ? (await pool.query(`SELECT id, title FROM schedule_events WHERE company_id = $1 AND id = $2`, [req.companyId, detail.link.job_id])).rows[0] || null
        : null;
      const currentJobIds = [detail.link?.job_id, ...detail.lines.map((line) => line.job_id)].filter(Boolean);
      const candidates = detail.entry.end_at
        ? await candidateJobs(pool, req.companyId, detail.entry, currentJobIds)
        : [];
      const auditResult = await pool.query(
        `SELECT id, actor_user_id, action, reason, before_state, after_state, created_at
           FROM finance_time_job_link_audit
          WHERE company_id = $1 AND time_entry_id = $2
          ORDER BY created_at DESC, id DESC LIMIT 100`,
        [req.companyId, req.params.entryId]
      );
      res.json({
        entry: detailEntryPayload(detail.entry, detail.link, job, detail.lines),
        lines: detail.lines.map(splitLinePayload),
        candidates,
        audit: auditResult.rows.map((row) => ({
          id: String(row.id), actor_user_id: row.actor_user_id || null, action: row.action,
          reason: row.reason, before: row.before_state || null, after: row.after_state || null,
          created_at: row.created_at
        }))
      });
    } catch (error) {
      sendCostError(res, error, "time_allocation_detail_failed");
    }
  });

  app.put("/api/finance/accounting/time-allocations/:entryId/allocation", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Accounting requires a company workspace." });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const detail = await loadEntryDetail(client, req.companyId, req.params.entryId, { lock: true });
      const requestedJobIds = requestedTimeAllocationJobIds(req.body);
      const jobs = requestedJobIds.length
        ? (await client.query(
          `SELECT id, title FROM schedule_events WHERE company_id = $1 AND id = ANY($2::text[]) FOR UPDATE`,
          [req.companyId, requestedJobIds]
        )).rows
        : [];
      const plan = planTimeAllocationUpdate({
        body: req.body,
        entry: detail.entry,
        currentLink: detail.link,
        currentLines: detail.lines,
        jobs
      });
      if (plan.mode === "replay") {
        await client.query("COMMIT");
        return res.json({ replayed: true, allocation: allocationSnapshot(detail.link, detail.lines) });
      }
      const before = allocationSnapshot(detail.link, detail.lines);
      let current;
      if (plan.mode === "create") {
        current = (await client.query(
          `INSERT INTO finance_time_job_links (
             company_id, time_entry_id, employee_id, job_id, source_start_at, source_end_at,
             source_break_seconds, source_work_seconds, linked_by
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
          [req.companyId, req.params.entryId, plan.snapshot.employee_id, plan.job_id,
            plan.snapshot.source_start_at, plan.snapshot.source_end_at, plan.snapshot.source_break_seconds,
            plan.snapshot.source_work_seconds, req.userId]
        )).rows[0];
      } else {
        current = (await client.query(
          `UPDATE finance_time_job_links
              SET employee_id = $3, job_id = $4, source_start_at = $5, source_end_at = $6,
                  source_break_seconds = $7, source_work_seconds = $8, version = version + 1,
                  linked_by = $9, linked_at = now(), updated_at = now()
            WHERE company_id = $1 AND time_entry_id = $2 RETURNING *`,
          [req.companyId, req.params.entryId, plan.snapshot.employee_id, plan.job_id,
            plan.snapshot.source_start_at, plan.snapshot.source_end_at, plan.snapshot.source_break_seconds,
            plan.snapshot.source_work_seconds, req.userId]
        )).rows[0];
      }
      await client.query(
        `DELETE FROM finance_time_allocation_lines WHERE company_id = $1 AND link_id = $2`,
        [req.companyId, current.id]
      );
      const savedLines = [];
      for (const line of plan.lines) {
        const saved = (await client.query(
          `INSERT INTO finance_time_allocation_lines (
             company_id, link_id, time_entry_id, line_order, target_kind, job_id, allocated_seconds, memo
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
          [req.companyId, current.id, req.params.entryId, line.line_order, line.target_kind,
            line.job_id, line.allocated_seconds, line.memo]
        )).rows[0];
        savedLines.push({
          ...saved,
          job_title: jobs.find((job) => String(job.id) === String(saved.job_id))?.title || null,
          job_exists: saved.target_kind === "job" ? true : null
        });
      }
      const after = allocationSnapshot(current, savedLines);
      await client.query(
        `INSERT INTO finance_time_job_link_audit (
           company_id, time_entry_id, link_id, actor_user_id, action, reason, before_state, after_state
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [req.companyId, req.params.entryId, current.id, req.userId, plan.action, plan.reason,
          JSON.stringify(before), JSON.stringify(after)]
      );
      await client.query("COMMIT");
      res.json({ replayed: false, allocation: after });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendCostError(res, error, "time_allocation_update_failed");
    } finally {
      client.release();
    }
  });

  app.put("/api/finance/accounting/time-allocations/:entryId/job-link", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Accounting requires a company workspace." });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const detail = await loadEntryDetail(client, req.companyId, req.params.entryId, { lock: true });
      if (detail.lines.length) {
        throw new CostAllocationError(
          "time_split_requires_current_client",
          "This entry has a reviewed split allocation. Use the current Time Allocation editor to replace or clear it.",
          409
        );
      }
      const requestedJobId = req.body?.job_id == null ? null : cleanString(req.body.job_id, 120) || null;
      const job = requestedJobId
        ? (await client.query(`SELECT id, title FROM schedule_events WHERE company_id = $1 AND id = $2 FOR UPDATE`, [req.companyId, requestedJobId])).rows[0]
        : null;
      const plan = planTimeJobLinkUpdate({ body: req.body, entry: detail.entry, currentLink: detail.link, job });
      if (plan.mode === "replay") {
        await client.query("COMMIT");
        return res.json({ replayed: true, link: linkPayload(detail.link) });
      }
      const before = allocationSnapshot(detail.link, detail.lines);
      let current;
      if (plan.mode === "create") {
        current = (await client.query(
          `INSERT INTO finance_time_job_links (
             company_id, time_entry_id, employee_id, job_id, source_start_at, source_end_at,
             source_break_seconds, source_work_seconds, linked_by
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
          [req.companyId, req.params.entryId, plan.snapshot.employee_id, plan.requested_job_id,
            plan.snapshot.source_start_at, plan.snapshot.source_end_at, plan.snapshot.source_break_seconds,
            plan.snapshot.source_work_seconds, req.userId]
        )).rows[0];
      } else {
        current = (await client.query(
          `UPDATE finance_time_job_links
              SET employee_id = $3, job_id = $4, source_start_at = $5, source_end_at = $6,
                  source_break_seconds = $7, source_work_seconds = $8, version = version + 1,
                  linked_by = $9, linked_at = now(), updated_at = now()
            WHERE company_id = $1 AND time_entry_id = $2 RETURNING *`,
          [req.companyId, req.params.entryId, plan.snapshot.employee_id, plan.requested_job_id,
            plan.snapshot.source_start_at, plan.snapshot.source_end_at, plan.snapshot.source_break_seconds,
            plan.snapshot.source_work_seconds, req.userId]
        )).rows[0];
      }
      await client.query(
        `INSERT INTO finance_time_job_link_audit (
           company_id, time_entry_id, link_id, actor_user_id, action, reason, before_state, after_state
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [req.companyId, req.params.entryId, current.id, req.userId, plan.action, plan.reason,
          JSON.stringify(before), JSON.stringify(allocationSnapshot(current, []))]
      );
      await client.query("COMMIT");
      res.json({ replayed: false, link: linkPayload(current) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendCostError(res, error, "time_job_link_failed");
    } finally {
      client.release();
    }
  });
}
