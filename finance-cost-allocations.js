const MAX_REPORT_DAYS = 731;
const MAX_REPORT_ROWS = 500;
const MAX_CANDIDATE_JOBS = 100;

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

function allocationStatus(row) {
  if (!row.duration_valid) return row.job_id ? "stale" : "invalid";
  if (!row.job_id) return "unallocated";
  if (!row.source_current || !row.job_exists) return "stale";
  return "allocated";
}

function entryPayload(row) {
  const status = allocationStatus(row);
  return {
    time_entry_id: String(row.time_entry_id),
    employee_id: String(row.employee_id),
    employee_name: row.employee_name,
    start_at: row.start_at,
    end_at: row.end_at,
    break_seconds: safeDbInteger(row.break_seconds || 0, "break_seconds"),
    work_seconds: row.work_seconds == null ? null : safeDbInteger(row.work_seconds, "work_seconds"),
    manual_entry: Boolean(row.manual_entry),
    manual_status: row.manual_status,
    job_id: row.job_id || null,
    job_title: row.job_title || null,
    link_version: row.link_version == null ? 0 : safeDbInteger(row.link_version, "link_version"),
    allocation_status: status,
    source_changed: Boolean(row.job_id) && !Boolean(row.source_current),
    job_missing: Boolean(row.job_id) && !Boolean(row.job_exists),
    allocated_seconds: status === "allocated" ? safeDbInteger(row.work_seconds, "work_seconds") : 0
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
     WHERE e.company_id = $1
       AND e.start_at >= ($2::date::timestamp AT TIME ZONE company.timezone)
       AND e.start_at < (($3::date + 1)::timestamp AT TIME ZONE company.timezone)
  )`;

async function loadAllocationRows(pool, companyId, range, limit) {
  const summaryResult = await pool.query(
    `${ALLOCATION_CTE}
     SELECT COUNT(*) FILTER (WHERE eligible)::bigint AS completed_entry_count,
            COUNT(*) FILTER (WHERE duration_valid)::bigint AS valid_entry_count,
            COUNT(*) FILTER (WHERE duration_valid AND job_id IS NOT NULL AND source_current AND job_exists)::bigint AS allocated_entry_count,
            COALESCE(SUM(work_seconds) FILTER (WHERE duration_valid AND job_id IS NOT NULL AND source_current AND job_exists), 0)::bigint AS allocated_seconds,
            COUNT(*) FILTER (WHERE duration_valid AND NOT (job_id IS NOT NULL AND source_current AND job_exists))::bigint AS unallocated_entry_count,
            COALESCE(SUM(work_seconds) FILTER (WHERE duration_valid AND NOT (job_id IS NOT NULL AND source_current AND job_exists)), 0)::bigint AS unallocated_seconds,
            COUNT(*) FILTER (WHERE job_id IS NOT NULL AND NOT (duration_valid AND source_current AND job_exists))::bigint AS stale_link_count,
            COUNT(*) FILTER (WHERE eligible AND NOT duration_valid)::bigint AS invalid_entry_count,
            COUNT(*) FILTER (WHERE eligible OR job_id IS NOT NULL)::bigint AS review_row_count
       FROM scoped`,
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
     SELECT * FROM scoped
      WHERE eligible OR job_id IS NOT NULL
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
  return { entry: entryResult.rows[0], link: linkResult.rows[0] || null };
}

async function candidateJobs(client, companyId, entry, currentJobId) {
  const { rows } = await client.query(
    `SELECT se.id AS job_id, se.title, se.start_at, se.end_at, se.finished_at,
            COALESCE(c.name, 'No customer name') AS contact_name,
            (se.worker_user_ids ? $5::text) AS worker_assigned,
            (se.start_at < $4::timestamptz AND se.end_at > $3::timestamptz) AS overlaps_entry
       FROM schedule_events se
       LEFT JOIN contacts c ON c.company_id = se.company_id AND c.id::text = se.contact_id
      WHERE se.company_id = $1
        AND (se.id = $2 OR (se.start_at >= $3::timestamptz - interval '31 days'
          AND se.start_at <= $4::timestamptz + interval '31 days'))
      ORDER BY (se.id = $2) DESC,
               (se.start_at < $4::timestamptz AND se.end_at > $3::timestamptz) DESC,
               (se.worker_user_ids ? $5::text) DESC,
               ABS(EXTRACT(EPOCH FROM (se.start_at - $3::timestamptz))) ASC,
               se.id
      LIMIT $6`,
    [companyId, currentJobId, entry.start_at, entry.end_at || entry.start_at, String(entry.user_id), MAX_CANDIDATE_JOBS]
  );
  return rows.map((row) => ({
    job_id: String(row.job_id), title: row.title, contact_name: row.contact_name,
    start_at: row.start_at, end_at: row.end_at, finished_at: row.finished_at || null,
    worker_assigned: Boolean(row.worker_assigned), overlaps_entry: Boolean(row.overlaps_entry)
  }));
}

function detailEntryPayload(entry, link, job = null) {
  let snapshot = null;
  try { snapshot = timeEntryAllocationSnapshot(entry); } catch { /* detail must still explain invalid evidence */ }
  const sourceCurrent = snapshot && link ? timeLinkMatchesSnapshot(link, snapshot) : false;
  const jobExists = Boolean(job);
  return {
    time_entry_id: String(entry.id), employee_id: String(entry.user_id), employee_name: entry.employee_name,
    start_at: entry.start_at, end_at: entry.end_at || null,
    break_seconds: safeDbInteger(entry.break_seconds || 0, "break_seconds"),
    work_seconds: snapshot?.source_work_seconds ?? null,
    manual_entry: Boolean(entry.manual_entry), manual_status: entry.manual_status,
    job_id: link?.job_id || null, job_title: job?.title || null,
    link_version: link ? safeDbInteger(link.version, "version") : 0,
    allocation_status: !snapshot ? (link?.job_id ? "stale" : "invalid") : !link?.job_id ? "unallocated" : sourceCurrent && jobExists ? "allocated" : "stale",
    source_changed: Boolean(link?.job_id) && !sourceCurrent,
    job_missing: Boolean(link?.job_id) && !jobExists,
    allocated_seconds: snapshot && link?.job_id && sourceCurrent && jobExists ? snapshot.source_work_seconds : 0
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
        completed_entry_count: totalCount,
        valid_entry_count: safeDbInteger(loaded.summary.valid_entry_count || 0, "valid_entry_count"),
        allocated_entry_count: safeDbInteger(loaded.summary.allocated_entry_count || 0, "allocated_entry_count"),
        allocated_seconds: safeDbInteger(loaded.summary.allocated_seconds || 0, "allocated_seconds"),
        unallocated_entry_count: safeDbInteger(loaded.summary.unallocated_entry_count || 0, "unallocated_entry_count"),
        unallocated_seconds: safeDbInteger(loaded.summary.unallocated_seconds || 0, "unallocated_seconds"),
        stale_link_count: safeDbInteger(loaded.summary.stale_link_count || 0, "stale_link_count"),
        invalid_entry_count: safeDbInteger(loaded.summary.invalid_entry_count || 0, "invalid_entry_count"),
        open_entry_count: safeDbInteger(loaded.coverage.open_entry_count || 0, "open_entry_count"),
        disapproved_entry_count: safeDbInteger(loaded.coverage.disapproved_entry_count || 0, "disapproved_entry_count")
      };
      const warnings = [
        "Only explicitly reviewed whole-entry links count as allocated clock evidence. Schedule overlap and worker assignment never create a link.",
        "Job-linked clock time is operational evidence only. No pay rate, overtime, burden, tax, benefit, mileage, payroll, P&L, or margin dollars are calculated.",
        "Previously linked entries that become open, disapproved, invalid, or point to a missing job stay visible for recovery but are excluded from allocated time."
      ];
      if (summary.stale_link_count) warnings.push("Stale time links are excluded until the changed source entry or missing job is reviewed.");
      if (summary.invalid_entry_count) warnings.push("Invalid completed durations are excluded instead of becoming zero time.");
      res.json({
        basis: "explicit_whole_time_entry_job_links",
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
      const candidates = detail.entry.end_at
        ? await candidateJobs(pool, req.companyId, detail.entry, detail.link?.job_id || null)
        : [];
      const auditResult = await pool.query(
        `SELECT id, actor_user_id, action, reason, before_state, after_state, created_at
           FROM finance_time_job_link_audit
          WHERE company_id = $1 AND time_entry_id = $2
          ORDER BY created_at DESC, id DESC LIMIT 100`,
        [req.companyId, req.params.entryId]
      );
      res.json({
        entry: detailEntryPayload(detail.entry, detail.link, job),
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

  app.put("/api/finance/accounting/time-allocations/:entryId/job-link", authRequired, requireFinanceAccess, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Accounting requires a company workspace." });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const detail = await loadEntryDetail(client, req.companyId, req.params.entryId, { lock: true });
      const requestedJobId = req.body?.job_id == null ? null : cleanString(req.body.job_id, 120) || null;
      const job = requestedJobId
        ? (await client.query(`SELECT id, title FROM schedule_events WHERE company_id = $1 AND id = $2 FOR UPDATE`, [req.companyId, requestedJobId])).rows[0]
        : null;
      const plan = planTimeJobLinkUpdate({ body: req.body, entry: detail.entry, currentLink: detail.link, job });
      if (plan.mode === "replay") {
        await client.query("COMMIT");
        return res.json({ replayed: true, link: linkPayload(detail.link) });
      }
      const before = linkSnapshot(detail.link);
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
          JSON.stringify(before), JSON.stringify(linkSnapshot(current))]
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
