import { hasCapability } from "./permissions.js";

const MAX_COMMISSION_TIERS = 20;
const MAX_HISTORY_ROWS = 500;

export class PayStructureError extends Error {
  constructor(code, message, statusCode = 400, details = {}) {
    super(message);
    this.name = "PayStructureError";
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
    throw new PayStructureError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return parsed;
}

function optionalCents(value, field) {
  if (value == null || value === "") return null;
  return exactInteger(value, field);
}

function dateOnly(value, field = "date") {
  const raw = value instanceof Date ? value.toISOString().slice(0, 10) : cleanString(value, 20);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    throw new PayStructureError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  const [year, month, day] = raw.split("-").map(Number);
  const parsed = new Date(Date.UTC(year, month - 1, day));
  if (parsed.getUTCFullYear() !== year || parsed.getUTCMonth() !== month - 1 || parsed.getUTCDate() !== day) {
    throw new PayStructureError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return raw;
}

function addDays(value, days) {
  const [year, month, day] = value.split("-").map(Number);
  return new Date(Date.UTC(year, month - 1, day + days)).toISOString().slice(0, 10);
}

function normalizeTiers(value) {
  if (value == null) return [];
  if (!Array.isArray(value)) throw new PayStructureError("commission_tiers_invalid", "Commission tiers must be a list.");
  if (value.length > MAX_COMMISSION_TIERS) {
    throw new PayStructureError("commission_tiers_too_many", `Use at most ${MAX_COMMISSION_TIERS} commission tiers.`);
  }
  const seenIDs = new Set();
  const tiers = value.map((raw, index) => {
    const id = cleanString(raw?.id, 80);
    if (!id) throw new PayStructureError("commission_tier_id_required", "Every commission tier needs a stable ID.");
    if (seenIDs.has(id)) throw new PayStructureError("commission_tier_id_duplicate", "Commission tier IDs must be unique.");
    seenIDs.add(id);
    return {
      id,
      threshold_cents: exactInteger(raw?.threshold_cents, `commission_tier_${index + 1}_threshold_cents`),
      percent_basis_points: exactInteger(raw?.percent_basis_points, `commission_tier_${index + 1}_percent_basis_points`, { maximum: 10_000 })
    };
  }).sort((left, right) => left.threshold_cents - right.threshold_cents || left.id.localeCompare(right.id));
  if (tiers.length && tiers[0].threshold_cents !== 0) {
    throw new PayStructureError("commission_first_threshold_invalid", "The first commission tier must start at $0.");
  }
  for (let index = 1; index < tiers.length; index += 1) {
    if (tiers[index].threshold_cents <= tiers[index - 1].threshold_cents) {
      throw new PayStructureError("commission_thresholds_invalid", "Commission thresholds must increase without duplicates.");
    }
  }
  return tiers;
}

export function normalizePayStructureInput(body = {}) {
  const reason = cleanString(body.reason, 500);
  if (!reason) throw new PayStructureError("pay_structure_reason_required", "Add a reason for this pay change.");
  return {
    expected_version: exactInteger(body.expected_version, "expected_version"),
    hourly_rate_cents: optionalCents(body.hourly_rate_cents, "hourly_rate_cents"),
    daily_base_cents: optionalCents(body.daily_base_cents, "daily_base_cents"),
    commission_tiers: normalizeTiers(body.commission_tiers),
    notes: cleanString(body.notes, 1000) || null,
    reason
  };
}

function rowDate(value, field) {
  return value == null ? null : dateOnly(value, field);
}

function structureFacts(row) {
  return {
    hourly_rate_cents: row.hourly_rate_cents == null ? null : Number(row.hourly_rate_cents),
    daily_base_cents: row.daily_base_cents == null ? null : Number(row.daily_base_cents),
    commission_tiers: Array.isArray(row.commission_tiers) ? row.commission_tiers : [],
    notes: row.notes || null
  };
}

function sameFacts(row, update) {
  return JSON.stringify(structureFacts(row)) === JSON.stringify({
    hourly_rate_cents: update.hourly_rate_cents,
    daily_base_cents: update.daily_base_cents,
    commission_tiers: update.commission_tiers,
    notes: update.notes
  });
}

export function planCurrentPayStructureUpdate({ today, rows = [], update }) {
  const companyToday = dateOnly(today, "company_today");
  const normalizedRows = rows.map((row) => ({
    ...row,
    effective_from: rowDate(row.effective_from, "effective_from"),
    effective_to: rowDate(row.effective_to, "effective_to"),
    version: exactInteger(Number(row.version), "version", { minimum: 1 })
  })).sort((left, right) => left.effective_from.localeCompare(right.effective_from));
  for (let index = 1; index < normalizedRows.length; index += 1) {
    const previous = normalizedRows[index - 1];
    if (!previous.effective_to || previous.effective_to >= normalizedRows[index].effective_from) {
      throw new PayStructureError("pay_structure_history_invalid", "Overlapping pay structures require review before another change.", 409);
    }
  }
  const active = normalizedRows.filter((row) => row.effective_from <= companyToday && (!row.effective_to || row.effective_to >= companyToday));
  if (active.length > 1) {
    throw new PayStructureError("pay_structure_history_invalid", "Overlapping pay structures require review before another change.", 409);
  }
  const current = active[0] || null;
  const sameDay = normalizedRows.find((row) => row.effective_from === companyToday) || null;
  const expectedRecord = sameDay || current;
  const currentVersion = expectedRecord?.version || 0;
  if (update.expected_version !== currentVersion) {
    throw new PayStructureError("pay_structure_stale", "This pay structure changed after it was loaded. Refresh before saving again.", 409, {
      current_version: currentVersion
    });
  }
  if (sameDay && sameFacts(sameDay, update)) {
    return { mode: "replay", current: sameDay, current_version: currentVersion };
  }
  if (sameDay) {
    return { mode: "correct", target: sameDay, current_version: currentVersion };
  }
  const next = normalizedRows.find((row) => row.effective_from > companyToday) || null;
  return {
    mode: "create",
    predecessor: current,
    effective_from: companyToday,
    effective_to: next ? addDays(next.effective_from, -1) : null,
    current_version: currentVersion
  };
}

function dbInteger(value, field) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(parsed)) {
    throw new PayStructureError("pay_structure_source_inexact", `${field.replaceAll("_", " ")} exceeds exact integer range.`, 500);
  }
  return parsed;
}

function payStructurePayload(row) {
  if (!row) return null;
  const tiers = Array.isArray(row.commission_tiers) ? row.commission_tiers : [];
  return {
    id: String(row.id),
    employee_id: String(row.employee_id),
    effective_from: rowDate(row.effective_from, "effective_from"),
    effective_to: rowDate(row.effective_to, "effective_to"),
    hourly_rate_cents: row.hourly_rate_cents == null ? null : dbInteger(row.hourly_rate_cents, "hourly_rate_cents"),
    daily_base_cents: row.daily_base_cents == null ? null : dbInteger(row.daily_base_cents, "daily_base_cents"),
    commission_tiers: tiers.map((tier, index) => ({
      id: cleanString(tier.id, 80) || `tier-${index + 1}`,
      threshold_cents: dbInteger(tier.threshold_cents, "threshold_cents"),
      percent_basis_points: dbInteger(tier.percent_basis_points, "percent_basis_points")
    })),
    notes: row.notes || null,
    version: dbInteger(row.version, "version"),
    created_by: row.created_by || null,
    updated_by: row.updated_by || null,
    created_at: row.created_at || null,
    updated_at: row.updated_at || null
  };
}

function auditSnapshot(row) {
  if (!row) return null;
  const payload = payStructurePayload(row);
  return {
    id: payload.id,
    effective_from: payload.effective_from,
    effective_to: payload.effective_to,
    hourly_rate_cents: payload.hourly_rate_cents,
    daily_base_cents: payload.daily_base_cents,
    commission_tiers: payload.commission_tiers,
    notes: payload.notes,
    version: payload.version
  };
}

async function companyToday(client, companyId) {
  const { rows } = await client.query(
    `SELECT COALESCE(NULLIF(timezone, ''), 'America/New_York') AS timezone,
            (now() AT TIME ZONE COALESCE(NULLIF(timezone, ''), 'America/New_York'))::date::text AS company_today
       FROM companies WHERE id = $1`,
    [companyId]
  );
  if (!rows[0]) throw new PayStructureError("company_not_found", "The company workspace was not found.", 404);
  return rows[0];
}

async function requireCompanyEmployee(client, companyId, employeeId, { lock = false } = {}) {
  const { rows } = await client.query(
    `SELECT id, email, display_name, role
       FROM users
      WHERE id::text = $1 AND company_id = $2 AND deleted_at IS NULL${lock ? " FOR UPDATE" : ""}`,
    [employeeId, companyId]
  );
  if (!rows[0]) throw new PayStructureError("pay_employee_not_found", "The active employee was not found.", 404);
  return rows[0];
}

async function appendAudit(client, { companyId, employeeId, structureId, actorUserId, action, reason, before, after }) {
  await client.query(
    `INSERT INTO employee_pay_structure_audit (
       company_id, employee_id, pay_structure_id, actor_user_id, action, reason, before_state, after_state
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [companyId, employeeId, structureId, actorUserId, action, reason, JSON.stringify(before), JSON.stringify(after)]
  );
}

function sendPayError(res, error, fallback) {
  if (error instanceof PayStructureError || error?.statusCode) {
    return res.status(error.statusCode || 400).json({
      error: error.code || fallback,
      message: error.message,
      current_version: error.current_version
    });
  }
  console.error("[pay-structures]", fallback, { code: error?.code, message: error?.message });
  return res.status(500).json({ error: fallback, message: "Employee pay request failed." });
}

export async function installPayStructureSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS employee_pay_structures (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      employee_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
      effective_from DATE NOT NULL,
      effective_to DATE,
      hourly_rate_cents BIGINT,
      daily_base_cents BIGINT,
      commission_tiers JSONB NOT NULL DEFAULT '[]'::jsonb,
      notes TEXT,
      version INTEGER NOT NULL DEFAULT 1,
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, employee_id, effective_from),
      CHECK (effective_to IS NULL OR effective_to >= effective_from),
      CHECK (hourly_rate_cents IS NULL OR hourly_rate_cents >= 0),
      CHECK (daily_base_cents IS NULL OR daily_base_cents >= 0),
      CHECK (jsonb_typeof(commission_tiers) = 'array'),
      CHECK (version > 0)
    );
    CREATE INDEX IF NOT EXISTS employee_pay_structures_company_employee_effective_idx
      ON employee_pay_structures(company_id, employee_id, effective_from DESC, effective_to);

    CREATE TABLE IF NOT EXISTS employee_pay_structure_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      employee_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
      pay_structure_id UUID NOT NULL REFERENCES employee_pay_structures(id) ON DELETE RESTRICT,
      actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      reason TEXT NOT NULL,
      before_state JSONB,
      after_state JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS employee_pay_structure_audit_company_employee_idx
      ON employee_pay_structure_audit(company_id, employee_id, created_at DESC);
  `);
}

export async function installPayStructureSystem({ app, pool, authRequired, requirePayManage }) {
  await installPayStructureSchema(pool);

  app.get("/api/pay-structures", authRequired, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Employee pay requires a company workspace." });
    try {
      const requestedEmployeeId = cleanString(req.query.employee_id, 80) || null;
      const canViewAll = hasCapability(req, "pay.view_all");
      const canViewSelf = hasCapability(req, "pay.view_self");
      if (!canViewAll && !canViewSelf) {
        return res.status(403).json({ error: "permission_denied", required_capability: "pay.view_self" });
      }
      if (requestedEmployeeId && requestedEmployeeId !== String(req.userId) && !canViewAll) {
        return res.status(403).json({ error: "permission_denied", required_capability: "pay.view_all" });
      }
      const employeeId = canViewAll ? requestedEmployeeId : String(req.userId);
      const context = await companyToday(pool, req.companyId);
      const currentResult = await pool.query(
        `SELECT u.id AS employee_id, u.email AS employee_email, u.display_name AS employee_name, u.role AS employee_role,
                pay.id, pay.effective_from, pay.effective_to, pay.hourly_rate_cents, pay.daily_base_cents,
                pay.commission_tiers, pay.notes, pay.version, pay.created_by, pay.updated_by, pay.created_at, pay.updated_at,
                (SELECT COUNT(*)::int FROM employee_pay_structures active
                  WHERE active.company_id = u.company_id AND active.employee_id = u.id
                    AND active.effective_from <= $2::date
                    AND (active.effective_to IS NULL OR active.effective_to >= $2::date)) AS active_count
           FROM users u
           LEFT JOIN LATERAL (
             SELECT p.* FROM employee_pay_structures p
              WHERE p.company_id = u.company_id AND p.employee_id = u.id
                AND p.effective_from <= $2::date
                AND (p.effective_to IS NULL OR p.effective_to >= $2::date)
              ORDER BY p.effective_from DESC LIMIT 1
           ) pay ON true
          WHERE u.company_id = $1 AND u.deleted_at IS NULL
            AND ($3::text IS NULL OR u.id::text = $3)
          ORDER BY COALESCE(NULLIF(u.display_name, ''), u.email), u.id`,
        [req.companyId, context.company_today, employeeId]
      );
      if (employeeId && !currentResult.rows.length) throw new PayStructureError("pay_employee_not_found", "The active employee was not found.", 404);
      if (currentResult.rows.some((row) => Number(row.active_count || 0) > 1)) {
        throw new PayStructureError("pay_structure_history_invalid", "Overlapping pay structures require review before pay data can be shown.", 409);
      }
      const includeHistory = req.query.include_history === "true";
      let history = undefined;
      let historyTruncated = false;
      if (includeHistory) {
        const historyResult = await pool.query(
          `SELECT p.* FROM employee_pay_structures p
            WHERE p.company_id = $1 AND ($2::text IS NULL OR p.employee_id::text = $2)
            ORDER BY p.employee_id, p.effective_from DESC LIMIT $3`,
          [req.companyId, employeeId, MAX_HISTORY_ROWS + 1]
        );
        historyTruncated = historyResult.rows.length > MAX_HISTORY_ROWS;
        history = historyResult.rows.slice(0, MAX_HISTORY_ROWS).map(payStructurePayload);
      }
      res.json({
        as_of: context.company_today,
        timezone: context.timezone,
        structures: currentResult.rows.map((row) => ({
          employee_id: String(row.employee_id),
          employee_email: row.employee_email,
          employee_name: row.employee_name || null,
          employee_role: row.employee_role,
          current: row.id ? payStructurePayload({ ...row, employee_id: row.employee_id }) : null
        })),
        ...(history ? { history, history_truncated: historyTruncated } : {})
      });
    } catch (error) {
      sendPayError(res, error, "pay_structures_load_failed");
    }
  });

  app.get("/api/pay-structures/employees/:employeeId/audit", authRequired, requirePayManage, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Employee pay requires a company workspace." });
    try {
      await requireCompanyEmployee(pool, req.companyId, req.params.employeeId);
      const requestedLimit = Number(req.query.limit || 100);
      const limit = Math.min(Math.max(Number.isSafeInteger(requestedLimit) ? requestedLimit : 100, 1), 200);
      const { rows } = await pool.query(
        `SELECT * FROM employee_pay_structure_audit
          WHERE company_id = $1 AND employee_id::text = $2
          ORDER BY created_at DESC, id DESC LIMIT $3`,
        [req.companyId, req.params.employeeId, limit]
      );
      res.json({ audit: rows.map((row) => ({
        id: String(row.id),
        employee_id: String(row.employee_id),
        pay_structure_id: String(row.pay_structure_id),
        actor_user_id: row.actor_user_id || null,
        action: row.action,
        reason: row.reason,
        before: row.before_state || null,
        after: row.after_state || null,
        created_at: row.created_at
      })) });
    } catch (error) {
      sendPayError(res, error, "pay_structure_audit_failed");
    }
  });

  app.put("/api/pay-structures/employees/:employeeId/current", authRequired, requirePayManage, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Employee pay requires a company workspace." });
    const client = await pool.connect();
    try {
      const update = normalizePayStructureInput(req.body);
      await client.query("BEGIN");
      await requireCompanyEmployee(client, req.companyId, req.params.employeeId, { lock: true });
      const context = await companyToday(client, req.companyId);
      const existingResult = await client.query(
        `SELECT * FROM employee_pay_structures
          WHERE company_id = $1 AND employee_id::text = $2
          ORDER BY effective_from FOR UPDATE`,
        [req.companyId, req.params.employeeId]
      );
      const plan = planCurrentPayStructureUpdate({ today: context.company_today, rows: existingResult.rows, update });
      if (plan.mode === "replay") {
        await client.query("COMMIT");
        return res.json({ as_of: context.company_today, timezone: context.timezone, replayed: true, current: payStructurePayload(plan.current) });
      }

      let current;
      if (plan.mode === "correct") {
        const before = auditSnapshot(plan.target);
        current = (await client.query(
          `UPDATE employee_pay_structures
              SET hourly_rate_cents = $4, daily_base_cents = $5, commission_tiers = $6,
                  notes = $7, version = version + 1, updated_by = $8, updated_at = now()
            WHERE company_id = $1 AND employee_id::text = $2 AND id = $3
            RETURNING *`,
          [req.companyId, req.params.employeeId, plan.target.id, update.hourly_rate_cents, update.daily_base_cents,
            JSON.stringify(update.commission_tiers), update.notes, req.userId]
        )).rows[0];
        await appendAudit(client, {
          companyId: req.companyId, employeeId: req.params.employeeId, structureId: current.id,
          actorUserId: req.userId, action: "pay_structure_corrected", reason: update.reason,
          before, after: auditSnapshot(current)
        });
      } else {
        if (plan.predecessor) {
          const before = auditSnapshot(plan.predecessor);
          const closed = (await client.query(
            `UPDATE employee_pay_structures
                SET effective_to = $4::date, version = version + 1, updated_by = $5, updated_at = now()
              WHERE company_id = $1 AND employee_id::text = $2 AND id = $3
              RETURNING *`,
            [req.companyId, req.params.employeeId, plan.predecessor.id, addDays(context.company_today, -1), req.userId]
          )).rows[0];
          await appendAudit(client, {
            companyId: req.companyId, employeeId: req.params.employeeId, structureId: closed.id,
            actorUserId: req.userId, action: "pay_structure_closed", reason: update.reason,
            before, after: auditSnapshot(closed)
          });
        }
        current = (await client.query(
          `INSERT INTO employee_pay_structures (
             company_id, employee_id, effective_from, effective_to, hourly_rate_cents, daily_base_cents,
             commission_tiers, notes, created_by, updated_by
           ) VALUES ($1,$2,$3::date,$4::date,$5,$6,$7,$8,$9,$9) RETURNING *`,
          [req.companyId, req.params.employeeId, plan.effective_from, plan.effective_to,
            update.hourly_rate_cents, update.daily_base_cents, JSON.stringify(update.commission_tiers),
            update.notes, req.userId]
        )).rows[0];
        await appendAudit(client, {
          companyId: req.companyId, employeeId: req.params.employeeId, structureId: current.id,
          actorUserId: req.userId, action: "pay_structure_created", reason: update.reason,
          before: null, after: auditSnapshot(current)
        });
      }
      await client.query("COMMIT");
      res.json({ as_of: context.company_today, timezone: context.timezone, replayed: false, current: payStructurePayload(current) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendPayError(res, error, "pay_structure_update_failed");
    } finally {
      client.release();
    }
  });
}
