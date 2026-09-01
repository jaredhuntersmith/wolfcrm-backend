import apn from "@parse/node-apn";
import { randomUUID } from "crypto";

export class RoutineGroupError extends Error {
  constructor(code, message, statusCode = 400) {
    super(message);
    this.name = "RoutineGroupError";
    this.code = code;
    this.statusCode = statusCode;
  }
}

export const ROUTINE_ENUMS = Object.freeze({
  markerStyles: new Set(["number", "checkmark"]),
  progressionModes: new Set(["time_based", "manual"]),
  timingModes: new Set(["keep_original", "recalculate"]),
  runStatuses: new Set(["scheduled", "active", "completed", "cancelled"]),
  stepStatuses: new Set(["upcoming", "active", "completed", "skipped"])
});

function cleanString(value, limit = 240) {
  if (value == null) return null;
  if (typeof value !== "string") throw new RoutineGroupError("invalid_string", "Expected a string value.");
  const trimmed = value.trim();
  return trimmed ? trimmed.slice(0, limit) : null;
}

function enumValue(value, allowed, fallback) {
  return allowed.has(value) ? value : fallback;
}

function positiveDuration(value, field = "planned_duration_seconds") {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0 || parsed > 24 * 60 * 60) {
    throw new RoutineGroupError("invalid_duration", `${field} must be a positive whole number of seconds.`);
  }
  return parsed;
}

export function normalizeRoutineSteps(steps = []) {
  if (!Array.isArray(steps)) throw new RoutineGroupError("invalid_steps", "Routine steps must be an array.");
  if (steps.length === 0) throw new RoutineGroupError("steps_required", "Add at least one routine step.");
  if (steps.length > 80) throw new RoutineGroupError("too_many_steps", "Routine groups support up to 80 steps.");
  return steps.map((step, index) => {
    const title = cleanString(step.title, 160);
    if (!title) throw new RoutineGroupError("step_title_required", "Every routine step needs a title.");
    return {
      id: cleanString(step.id, 80) || randomUUID(),
      routine_id: cleanString(step.routine_id ?? step.routineID, 80),
      title,
      notes: cleanString(step.notes, 1000),
      position: Number.isInteger(step.position) ? step.position : index,
      planned_duration_seconds: positiveDuration(step.planned_duration_seconds ?? step.plannedDurationSeconds ?? 300),
      linked_task_metadata: step.linked_task_metadata && typeof step.linked_task_metadata === "object" ? step.linked_task_metadata : null,
      milestone_notification: Boolean(step.milestone_notification)
    };
  }).sort((a, b) => a.position - b.position).map((step, index) => ({ ...step, position: index }));
}

function routineWeekdays(routine) {
  if (!routine) return [];
  if (Array.isArray(routine.weekdays)) return routine.weekdays.map(Number).filter(Boolean);
  if (typeof routine.weekdays === "string") {
    try {
      const parsed = JSON.parse(routine.weekdays);
      return Array.isArray(parsed) ? parsed.map(Number).filter(Boolean) : [];
    } catch {
      return [];
    }
  }
  return [];
}

function routineOccurrenceAfter(routine, afterDate, inclusive = true) {
  const after = dateFrom(afterDate, "after");
  const time = routine?.time ? dateFrom(routine.time, "routine.time") : after;
  const weekdays = routineWeekdays(routine);
  if (!weekdays.length) {
    const candidate = new Date(after);
    candidate.setUTCHours(time.getUTCHours(), time.getUTCMinutes(), 0, 0);
    return (inclusive ? candidate >= after : candidate > after) ? candidate : null;
  }

  const start = new Date(after);
  start.setUTCHours(0, 0, 0, 0);
  for (let offset = 0; offset < 14; offset += 1) {
    const day = new Date(start);
    day.setUTCDate(start.getUTCDate() + offset);
    const weekday = day.getUTCDay() + 1;
    if (!weekdays.includes(weekday)) continue;
    day.setUTCHours(time.getUTCHours(), time.getUTCMinutes(), 0, 0);
    if (inclusive ? day >= after : day > after) return day;
  }
  return null;
}

export function deriveRoutineStepDurations(steps = [], routineMap = new Map(), anchorDate = new Date()) {
  const ordered = normalizeRoutineSteps(steps);
  if (ordered.length < 2) return ordered.map((step) => ({ ...step, planned_duration_seconds: positiveDuration(step.planned_duration_seconds) }));

  const occurrences = [];
  let cursor = dateFrom(anchorDate, "anchorDate");
  for (let index = 0; index < ordered.length; index += 1) {
    const step = ordered[index];
    const routine = step.routine_id ? routineMap.get(String(step.routine_id)) : null;
    const occurrence = routine ? routineOccurrenceAfter(routine, cursor, index === 0) : null;
    const scheduledAt = occurrence || cursor;
    occurrences.push(scheduledAt);
    cursor = new Date(scheduledAt.getTime() + 60 * 1000);
  }

  return ordered.map((step, index) => {
    if (index >= ordered.length - 1) {
      return { ...step, planned_duration_seconds: positiveDuration(step.planned_duration_seconds) };
    }
    const gapSeconds = Math.round((occurrences[index + 1].getTime() - occurrences[index].getTime()) / 1000);
    return { ...step, planned_duration_seconds: Math.max(60, gapSeconds) };
  });
}

function dateFrom(value, field) {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) throw new RoutineGroupError("invalid_date", `${field} must be a valid date.`);
  return date;
}

export function buildRunTimeline({ template, steps, startAt = new Date(), status = "active" }) {
  const effectiveStartAt = dateFrom(startAt, "start_at");
  let cursorMs = effectiveStartAt.getTime();
  const runSteps = normalizeRoutineSteps(steps).map((step) => {
    const start = new Date(cursorMs);
    cursorMs += step.planned_duration_seconds * 1000;
    return {
      step_id: step.id,
      routine_id: step.routine_id || null,
      position: step.position,
      title_snapshot: step.title,
      planned_duration_seconds: step.planned_duration_seconds,
      effective_start_at: start,
      effective_end_at: new Date(cursorMs),
      status: step.position === 0 && status === "active" ? "active" : "upcoming",
      completed_at: null
    };
  });
  return {
    original_start_at: effectiveStartAt,
    effective_start_at: effectiveStartAt,
    original_estimated_end_at: new Date(cursorMs),
    effective_estimated_end_at: new Date(cursorMs),
    current_step_id: runSteps[0]?.step_id || null,
    current_step_index: 0,
    runSteps
  };
}

export function routineProgressSnapshot(run, steps, now = new Date()) {
  const start = dateFrom(run.effective_start_at, "effective_start_at").getTime();
  const end = dateFrom(run.effective_estimated_end_at, "effective_estimated_end_at").getTime();
  const current = dateFrom(now, "now").getTime();
  const total = Math.max(1, end - start);
  const progress = Math.max(0, Math.min(1, (current - start) / total));
  const ordered = [...steps].sort((a, b) => a.position - b.position);
  const ticks = ordered.map((step) => {
    const tick = (dateFrom(step.effective_start_at, "effective_start_at").getTime() - start) / total;
    return { step_id: step.step_id, position: step.position, offset: Math.max(0, Math.min(1, tick)) };
  });
  return { progress, ticks };
}

export function completeStepTimeline({ run, steps, expectedStepId = null, completedAt = new Date() }) {
  if (run.status === "completed" || run.status === "cancelled") return { run, steps, replayed: true };
  const ordered = [...steps].sort((a, b) => a.position - b.position);
  const index = Number(run.current_step_index || 0);
  const current = ordered[index];
  if (!current) return { run: { ...run, status: "completed", completed_at: completedAt }, steps: ordered, replayed: true };
  if (expectedStepId && String(current.step_id) !== String(expectedStepId)) {
    throw new RoutineGroupError("stale_current_step", "The routine step changed before this completion arrived.", 409);
  }
  if (current.status === "completed") return { run, steps: ordered, replayed: true };

  const doneAt = dateFrom(completedAt, "completed_at");
  ordered[index] = { ...current, status: "completed", completed_at: doneAt };
  const nextIndex = index + 1;
  if (nextIndex >= ordered.length) {
    return {
      run: { ...run, status: "completed", completed_at: doneAt, current_step_id: null, current_step_index: index, effective_estimated_end_at: doneAt },
      steps: ordered,
      replayed: false
    };
  }

  if (run.timing_mode === "recalculate") {
    let cursorMs = doneAt.getTime();
    for (let i = nextIndex; i < ordered.length; i += 1) {
      const step = ordered[i];
      const start = new Date(cursorMs);
      cursorMs += Number(step.planned_duration_seconds) * 1000;
      ordered[i] = {
        ...step,
        effective_start_at: start,
        effective_end_at: new Date(cursorMs),
        status: i === nextIndex ? "active" : "upcoming",
        completed_at: null
      };
    }
    return {
      run: { ...run, current_step_id: ordered[nextIndex].step_id, current_step_index: nextIndex, effective_estimated_end_at: new Date(cursorMs) },
      steps: ordered,
      replayed: false
    };
  }

  ordered[nextIndex] = { ...ordered[nextIndex], status: run.progression_mode === "manual" ? "active" : ordered[nextIndex].status };
  return {
    run: { ...run, current_step_id: ordered[nextIndex].step_id, current_step_index: nextIndex },
    steps: ordered,
    replayed: false
  };
}

function serializeRun(row, steps = []) {
  return {
    ...row,
    steps: steps.sort((a, b) => a.position - b.position)
  };
}

function compactActivityState(run, steps, template = {}) {
  const ordered = [...steps].sort((a, b) => a.position - b.position);
  const index = Number(run.current_step_index || 0);
  return {
    runID: String(run.id),
    routineGroupID: String(run.routine_group_id),
    routineName: template.name || run.routine_name_snapshot || "Routine",
    accentHex: template.accent_hex || run.accent_hex || "#3382EB",
    markerStyle: run.marker_style || "number",
    progressionMode: run.progression_mode || "manual",
    timingMode: run.timing_mode || "recalculate",
    currentStepID: ordered[index]?.step_id || null,
    currentStepIndex: index,
    stepCount: ordered.length,
    previousTitle: ordered[index - 1]?.title_snapshot || null,
    currentTitle: ordered[index]?.title_snapshot || "Complete",
    nextTitle: ordered[index + 1]?.title_snapshot || null,
    effectiveStartAt: new Date(run.effective_start_at).toISOString(),
    effectiveEstimatedEndAt: new Date(run.effective_estimated_end_at).toISOString(),
    updatedAt: new Date().toISOString(),
    ticks: routineProgressSnapshot(run, ordered).ticks.map((tick) => ({ position: tick.position, offset: tick.offset }))
  };
}

async function assertRoutineOwnership(client, userId, companyId, routineIds) {
  const unique = [...new Set((routineIds || []).filter(Boolean).map(String))];
  if (!unique.length) return new Map();
  const { rows } = await client.query(
    `SELECT id, title, time, weekdays FROM todo_routines
      WHERE user_id = $1 AND id = ANY($2::text[])
        AND ($3::uuid IS NULL OR company_id IS NULL OR company_id = $3)`,
    [userId, unique, companyId || null]
  );
  if (rows.length !== unique.length) {
    throw new RoutineGroupError("routine_reference_not_found", "One or more routines in this group no longer exist.", 404);
  }
  return new Map(rows.map((row) => [String(row.id), row]));
}

async function refreshRoutineStepTitles(client, userId, companyId, steps) {
  const routineIds = [...new Set(steps.map((step) => step.routine_id).filter(Boolean).map(String))];
  if (!routineIds.length) return steps;
  const { rows } = await client.query(
    `SELECT id, title FROM todo_routines
      WHERE user_id = $1 AND id = ANY($2::text[])
        AND ($3::uuid IS NULL OR company_id IS NULL OR company_id = $3)`,
    [userId, routineIds, companyId || null]
  );
  if (rows.length !== routineIds.length) {
    throw new RoutineGroupError("routine_reference_not_found", "One or more routines in this group no longer exist.", 404);
  }
  const titles = new Map(rows.map((row) => [String(row.id), row.title]));
  return steps.map((step) => step.routine_id ? { ...step, title: titles.get(String(step.routine_id)) || step.title } : step);
}

async function loadRun(client, companyId, userId, runId, lock = false) {
  const runResult = await client.query(
    `SELECT * FROM routine_runs
      WHERE id = $1 AND company_id = $2 AND user_id = $3${lock ? " FOR UPDATE" : ""}`,
    [runId, companyId, userId]
  );
  if (!runResult.rows.length) throw new RoutineGroupError("routine_run_not_found", "Routine run was not found.", 404);
  const stepsResult = await client.query(
    `SELECT * FROM routine_run_steps WHERE run_id = $1 AND company_id = $2 ORDER BY position${lock ? " FOR UPDATE" : ""}`,
    [runId, companyId]
  );
  return { run: runResult.rows[0], steps: stepsResult.rows };
}

async function notifyLiveActivity(pool, runId, event, state) {
  const topic = process.env.APNS_BUNDLE_ID ? `${process.env.APNS_BUNDLE_ID}.push-type.liveactivity` : null;
  if (!topic || !process.env.APNS_KEY_P8 || !process.env.APNS_KEY_ID || !process.env.APNS_TEAM_ID) {
    return { sent: 0, failed: 0, skipped: true, reason: "apns_not_configured" };
  }
  const { rows } = await pool.query(
    `SELECT token, environment FROM routine_live_activity_tokens
      WHERE run_id = $1 AND invalidated_at IS NULL`,
    [runId]
  );
  if (!rows.length) return { sent: 0, failed: 0, skipped: true, reason: "no_live_activity_tokens" };
  let key = process.env.APNS_KEY_P8;
  if (!key.includes("BEGIN PRIVATE KEY")) key = Buffer.from(key, "base64").toString("utf8");
  const groups = rows.reduce((acc, row) => {
    const env = row.environment === "production" ? "production" : "sandbox";
    acc[env] = acc[env] || [];
    acc[env].push(row.token);
    return acc;
  }, {});
  let sent = 0;
  let failed = 0;
  for (const [environment, tokens] of Object.entries(groups)) {
    const provider = new apn.Provider({ token: { key, keyId: process.env.APNS_KEY_ID, teamId: process.env.APNS_TEAM_ID }, production: environment === "production" });
    const note = new apn.Notification();
    note.topic = topic;
    note.pushType = "liveactivity";
    note.priority = 10;
    note.expiry = Math.floor(Date.now() / 1000) + 8 * 3600;
    note.payload = { aps: { timestamp: Math.floor(Date.now() / 1000), event, "content-state": state, "stale-date": Math.floor(Date.now() / 1000) + 900 } };
    const result = await provider.send(note, tokens);
    sent += (result.sent || []).length;
    failed += (result.failed || []).length;
    const bad = (result.failed || []).filter((item) => item.status === "410" || item.response?.reason === "Unregistered").map((item) => item.device);
    if (bad.length) {
      await pool.query(`UPDATE routine_live_activity_tokens SET invalidated_at = now(), last_error = 'Unregistered' WHERE token = ANY($1::text[])`, [bad]).catch(() => {});
    }
    provider.shutdown();
  }
  return { sent, failed };
}

export async function installRoutineGroupSystem({ app, pool, authRequired, requireView, requireManage, emitAutomationEvent = async () => {} }) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS routine_groups (
      id TEXT PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      description TEXT,
      accent_hex TEXT,
      schedule JSONB NOT NULL DEFAULT '{}'::jsonb,
      default_progression_mode TEXT NOT NULL DEFAULT 'manual',
      default_timing_mode TEXT NOT NULL DEFAULT 'recalculate',
      marker_style TEXT NOT NULL DEFAULT 'number',
      notifications_enabled BOOLEAN NOT NULL DEFAULT true,
      is_archived BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS routine_groups_owner_idx ON routine_groups(company_id, owner_user_id, is_archived, updated_at DESC);

    CREATE TABLE IF NOT EXISTS routine_steps (
      id TEXT PRIMARY KEY,
      routine_group_id TEXT NOT NULL REFERENCES routine_groups(id) ON DELETE CASCADE,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      notes TEXT,
      position INTEGER NOT NULL,
      planned_duration_seconds INTEGER NOT NULL,
      linked_task_metadata JSONB,
      routine_id TEXT,
      milestone_notification BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(routine_group_id, position)
    );
    CREATE INDEX IF NOT EXISTS routine_steps_group_idx ON routine_steps(company_id, routine_group_id, position);

    CREATE TABLE IF NOT EXISTS routine_runs (
      id TEXT PRIMARY KEY,
      routine_group_id TEXT NOT NULL REFERENCES routine_groups(id) ON DELETE CASCADE,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'active',
      routine_name_snapshot TEXT NOT NULL,
      accent_hex TEXT,
      original_start_at TIMESTAMPTZ NOT NULL,
      original_estimated_end_at TIMESTAMPTZ NOT NULL,
      effective_start_at TIMESTAMPTZ NOT NULL,
      effective_estimated_end_at TIMESTAMPTZ NOT NULL,
      current_step_id TEXT,
      current_step_index INTEGER NOT NULL DEFAULT 0,
      timing_mode TEXT NOT NULL DEFAULT 'recalculate',
      progression_mode TEXT NOT NULL DEFAULT 'manual',
      marker_style TEXT NOT NULL DEFAULT 'number',
      idempotency_key TEXT,
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      cancelled_at TIMESTAMPTZ,
      version INTEGER NOT NULL DEFAULT 1,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, user_id, idempotency_key)
    );
    CREATE INDEX IF NOT EXISTS routine_runs_active_idx ON routine_runs(company_id, user_id, status, effective_estimated_end_at);

    CREATE TABLE IF NOT EXISTS routine_run_steps (
      run_id TEXT NOT NULL REFERENCES routine_runs(id) ON DELETE CASCADE,
      step_id TEXT NOT NULL,
      routine_id TEXT,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      position INTEGER NOT NULL,
      title_snapshot TEXT NOT NULL,
      planned_duration_seconds INTEGER NOT NULL,
      effective_start_at TIMESTAMPTZ NOT NULL,
      effective_end_at TIMESTAMPTZ NOT NULL,
      status TEXT NOT NULL DEFAULT 'upcoming',
      completed_at TIMESTAMPTZ,
      PRIMARY KEY (run_id, step_id)
    );
    CREATE INDEX IF NOT EXISTS routine_run_steps_order_idx ON routine_run_steps(company_id, run_id, position);

    CREATE TABLE IF NOT EXISTS routine_mutations (
      company_id UUID NOT NULL,
      user_id UUID NOT NULL,
      idempotency_key TEXT NOT NULL,
      mutation_type TEXT NOT NULL,
      routine_run_id TEXT,
      response JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY(company_id, user_id, idempotency_key)
    );

    CREATE TABLE IF NOT EXISTS routine_live_activity_tokens (
      token TEXT PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      run_id TEXT REFERENCES routine_runs(id) ON DELETE CASCADE,
      token_kind TEXT NOT NULL,
      environment TEXT NOT NULL DEFAULT 'sandbox',
      invalidated_at TIMESTAMPTZ,
      last_error TEXT,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS routine_live_activity_tokens_owner_idx ON routine_live_activity_tokens(company_id, user_id, token_kind, updated_at DESC);
    ALTER TABLE routine_steps ADD COLUMN IF NOT EXISTS routine_id TEXT;
    ALTER TABLE routine_run_steps ADD COLUMN IF NOT EXISTS routine_id TEXT;
  `);

  app.get("/api/todo/routine-groups", authRequired, requireView, async (req, res) => {
    try {
      const { rows } = await pool.query(
        `SELECT * FROM routine_groups
          WHERE company_id = $1 AND owner_user_id = $2
            AND ($3::boolean OR is_archived = false)
          ORDER BY is_archived ASC, updated_at DESC`,
        [req.companyId, req.userId, req.query.include_archived === "true"]
      );
      const ids = rows.map((row) => row.id);
      const steps = ids.length ? (await pool.query(`SELECT * FROM routine_steps WHERE company_id = $1 AND routine_group_id = ANY($2::text[]) ORDER BY routine_group_id, position`, [req.companyId, ids])).rows : [];
      res.json(rows.map((row) => ({ ...row, steps: steps.filter((step) => step.routine_group_id === row.id) })));
    } catch (e) { console.error(e); res.status(500).json({ error: "failed_list_routine_groups" }); }
  });

  app.put("/api/todo/routine-groups/:id", authRequired, requireManage, async (req, res) => {
    const client = await pool.connect();
    try {
      let steps = normalizeRoutineSteps(req.body?.steps || []);
      const routineMap = await assertRoutineOwnership(client, req.userId, req.companyId, steps.map((step) => step.routine_id));
      steps = deriveRoutineStepDurations(steps, routineMap);
      const body = req.body || {};
      const name = cleanString(body.name ?? body.title, 180);
      if (!name) return res.status(400).json({ error: "name_required" });
      const firstRoutine = steps[0]?.routine_id ? routineMap.get(String(steps[0].routine_id)) : null;
      const derivedSchedule = firstRoutine
        ? { time: firstRoutine.time, weekdays: firstRoutine.weekdays || [], timezone_identifier: body.schedule?.timezone_identifier || body.schedule?.timezone || "UTC" }
        : (body.schedule || {});
      await client.query("BEGIN");
      const group = (await client.query(
          `INSERT INTO routine_groups
             (id, company_id, owner_user_id, name, description, accent_hex, schedule, default_progression_mode, default_timing_mode, marker_style, notifications_enabled, is_archived)
           VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$12)
           ON CONFLICT (id) DO UPDATE
             SET name = EXCLUDED.name, description = EXCLUDED.description, accent_hex = EXCLUDED.accent_hex,
                 schedule = EXCLUDED.schedule, default_progression_mode = EXCLUDED.default_progression_mode,
                 default_timing_mode = EXCLUDED.default_timing_mode, marker_style = EXCLUDED.marker_style,
                 notifications_enabled = EXCLUDED.notifications_enabled, is_archived = EXCLUDED.is_archived, updated_at = now()
           WHERE routine_groups.company_id = $2 AND routine_groups.owner_user_id = $3
           RETURNING *`,
          [
            req.params.id, req.companyId, req.userId, name, cleanString(body.description, 1200), cleanString(body.accent_hex ?? body.color_hex, 16),
            JSON.stringify(derivedSchedule), enumValue(body.default_progression_mode, ROUTINE_ENUMS.progressionModes, "time_based"),
            enumValue(body.default_timing_mode, ROUTINE_ENUMS.timingModes, "recalculate"), enumValue(body.marker_style, ROUTINE_ENUMS.markerStyles, "number"),
            body.notifications_enabled !== false, Boolean(body.is_archived)
          ]
      )).rows[0];
      await client.query(`DELETE FROM routine_steps WHERE routine_group_id = $1 AND company_id = $2`, [req.params.id, req.companyId]);
      for (const step of steps) {
        await client.query(
          `INSERT INTO routine_steps
             (id, routine_group_id, company_id, title, notes, position, planned_duration_seconds, linked_task_metadata, milestone_notification, routine_id)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10)`,
          [step.id, req.params.id, req.companyId, step.title, step.notes, step.position, step.planned_duration_seconds, JSON.stringify(step.linked_task_metadata), step.milestone_notification, step.routine_id]
        );
      }
      await client.query("COMMIT");
      const result = { ...group, steps };
      await emitAutomationEvent({ companyId: req.companyId, eventType: "routine_group.saved", subjectType: "routine_group", subjectId: req.params.id, actorUserId: req.userId, source: "routine-groups.api", payload: { routine_group_id: req.params.id, name } });
      res.json(result);
    } catch (e) {
      await client.query("ROLLBACK").catch(() => {});
      console.error(e);
      res.status(e.statusCode || 500).json({ error: e.code || "failed_save_routine_group", message: e.message });
    } finally {
      client.release();
    }
  });

  app.post("/api/todo/routine-groups/:id/duplicate", authRequired, requireManage, async (req, res) => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const groupResult = await client.query(`SELECT * FROM routine_groups WHERE id = $1 AND company_id = $2 AND owner_user_id = $3 FOR SHARE`, [req.params.id, req.companyId, req.userId]);
      if (!groupResult.rows.length) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "routine_group_not_found" });
      }
      const stepRows = (await client.query(`SELECT * FROM routine_steps WHERE routine_group_id = $1 AND company_id = $2 ORDER BY position`, [req.params.id, req.companyId])).rows;
      const nextId = randomUUID();
      const original = groupResult.rows[0];
      const group = (await client.query(
        `INSERT INTO routine_groups
          (id, company_id, owner_user_id, name, description, accent_hex, schedule, default_progression_mode, default_timing_mode, marker_style, notifications_enabled, is_archived)
         VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,false)
         RETURNING *`,
        [nextId, req.companyId, req.userId, `${original.name} Copy`, original.description, original.accent_hex, JSON.stringify(original.schedule || {}), original.default_progression_mode, original.default_timing_mode, original.marker_style, original.notifications_enabled]
      )).rows[0];
      const steps = [];
      for (const step of stepRows) {
        const copied = {
          ...step,
          id: randomUUID(),
          routine_group_id: nextId
        };
        await client.query(
          `INSERT INTO routine_steps
            (id, routine_group_id, company_id, title, notes, position, planned_duration_seconds, linked_task_metadata, milestone_notification, routine_id)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10)`,
          [copied.id, nextId, req.companyId, copied.title, copied.notes, copied.position, copied.planned_duration_seconds, JSON.stringify(copied.linked_task_metadata), copied.milestone_notification, copied.routine_id]
        );
        steps.push(copied);
      }
      await client.query("COMMIT");
      res.json({ ...group, steps });
    } catch (e) {
      await client.query("ROLLBACK").catch(() => {});
      console.error(e);
      res.status(500).json({ error: "failed_duplicate_routine_group" });
    } finally {
      client.release();
    }
  });

  app.post("/api/todo/routine-groups/:id/start", authRequired, requireManage, async (req, res) => {
    const idempotencyKey = cleanString(req.body?.idempotency_key, 120) || `${req.params.id}:${new Date().toISOString().slice(0, 10)}`;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const replay = await client.query(`SELECT response FROM routine_mutations WHERE company_id = $1 AND user_id = $2 AND idempotency_key = $3 FOR UPDATE`, [req.companyId, req.userId, idempotencyKey]);
      if (replay.rows.length) {
        await client.query("COMMIT");
        return res.json({ ...replay.rows[0].response, replayed: true });
      }
      const group = (await client.query(`SELECT * FROM routine_groups WHERE id = $1 AND company_id = $2 AND owner_user_id = $3 AND is_archived = false FOR SHARE`, [req.params.id, req.companyId, req.userId])).rows[0];
      if (!group) throw new RoutineGroupError("routine_group_not_found", "Routine group was not found.", 404);
      const steps = await refreshRoutineStepTitles(
        client,
        req.userId,
        req.companyId,
        (await client.query(`SELECT * FROM routine_steps WHERE routine_group_id = $1 AND company_id = $2 ORDER BY position`, [req.params.id, req.companyId])).rows
      );
      const timeline = buildRunTimeline({ template: group, steps, startAt: req.body?.start_at || new Date(), status: "active" });
      const runId = cleanString(req.body?.run_id, 80) || randomUUID();
      const run = (await client.query(
        `INSERT INTO routine_runs
          (id, routine_group_id, company_id, user_id, status, routine_name_snapshot, accent_hex, original_start_at, original_estimated_end_at,
           effective_start_at, effective_estimated_end_at, current_step_id, current_step_index, timing_mode, progression_mode, marker_style,
           idempotency_key, started_at)
         VALUES ($1,$2,$3,$4,'active',$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
         RETURNING *`,
        [runId, group.id, req.companyId, req.userId, group.name, group.accent_hex, timeline.original_start_at, timeline.original_estimated_end_at,
          timeline.effective_start_at, timeline.effective_estimated_end_at, timeline.current_step_id, timeline.current_step_index,
          enumValue(req.body?.timing_mode || group.default_timing_mode, ROUTINE_ENUMS.timingModes, "recalculate"),
          enumValue(req.body?.progression_mode || group.default_progression_mode, ROUTINE_ENUMS.progressionModes, "time_based"),
          enumValue(req.body?.marker_style || group.marker_style, ROUTINE_ENUMS.markerStyles, "number"), idempotencyKey, timeline.effective_start_at]
      )).rows[0];
      for (const step of timeline.runSteps) {
        await client.query(
          `INSERT INTO routine_run_steps (run_id, step_id, routine_id, company_id, position, title_snapshot, planned_duration_seconds, effective_start_at, effective_end_at, status, completed_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
          [run.id, step.step_id, step.routine_id, req.companyId, step.position, step.title_snapshot, step.planned_duration_seconds, step.effective_start_at, step.effective_end_at, step.status, step.completed_at]
        );
      }
      const response = serializeRun(run, timeline.runSteps);
      await client.query(`INSERT INTO routine_mutations (company_id, user_id, idempotency_key, mutation_type, routine_run_id, response) VALUES ($1,$2,$3,'start',$4,$5::jsonb)`, [req.companyId, req.userId, idempotencyKey, run.id, JSON.stringify(response)]);
      await client.query("COMMIT");
      res.json(response);
    } catch (e) {
      await client.query("ROLLBACK").catch(() => {});
      console.error(e);
      res.status(e.statusCode || 500).json({ error: e.code || "failed_start_routine_run", message: e.message });
    } finally {
      client.release();
    }
  });

  app.get("/api/todo/routine-runs", authRequired, requireView, async (req, res) => {
    try {
      const statuses = String(req.query.status || "active,scheduled").split(",").filter((status) => ROUTINE_ENUMS.runStatuses.has(status));
      const { rows } = await pool.query(
        `SELECT * FROM routine_runs WHERE company_id = $1 AND user_id = $2 AND status = ANY($3::text[]) ORDER BY effective_estimated_end_at ASC, updated_at DESC LIMIT 100`,
        [req.companyId, req.userId, statuses.length ? statuses : ["active", "scheduled"]]
      );
      const runIds = rows.map((row) => row.id);
      const steps = runIds.length ? (await pool.query(`SELECT * FROM routine_run_steps WHERE company_id = $1 AND run_id = ANY($2::text[]) ORDER BY run_id, position`, [req.companyId, runIds])).rows : [];
      res.json(rows.map((row) => serializeRun(row, steps.filter((step) => step.run_id === row.id))));
    } catch (e) { console.error(e); res.status(500).json({ error: "failed_list_routine_runs" }); }
  });

  app.post("/api/todo/routine-runs/:id/complete-step", authRequired, requireManage, async (req, res) => {
    const idempotencyKey = cleanString(req.body?.idempotency_key, 120) || `complete-step:${req.params.id}:${req.body?.expected_step_id || ""}`;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const replay = await client.query(`SELECT response FROM routine_mutations WHERE company_id = $1 AND user_id = $2 AND idempotency_key = $3 FOR UPDATE`, [req.companyId, req.userId, idempotencyKey]);
      if (replay.rows.length) {
        await client.query("COMMIT");
        return res.json({ ...replay.rows[0].response, replayed: true });
      }
      const { run, steps } = await loadRun(client, req.companyId, req.userId, req.params.id, true);
      const next = completeStepTimeline({ run, steps, expectedStepId: req.body?.expected_step_id || null, completedAt: req.body?.completed_at || new Date() });
      const completedStep = steps.sort((a, b) => a.position - b.position)[Number(run.current_step_index || 0)];
      const updatedRun = (await client.query(
        `UPDATE routine_runs
            SET status = $3, current_step_id = $4, current_step_index = $5, effective_estimated_end_at = $6,
                completed_at = $7, version = version + 1, updated_at = now()
          WHERE id = $1 AND company_id = $2
          RETURNING *`,
        [req.params.id, req.companyId, next.run.status, next.run.current_step_id, next.run.current_step_index, next.run.effective_estimated_end_at, next.run.completed_at || null]
      )).rows[0];
      for (const step of next.steps) {
        await client.query(
          `UPDATE routine_run_steps
              SET effective_start_at = $4, effective_end_at = $5, status = $6, completed_at = $7
            WHERE run_id = $1 AND company_id = $2 AND step_id = $3`,
          [req.params.id, req.companyId, step.step_id, step.effective_start_at, step.effective_end_at, step.status, step.completed_at || null]
        );
      }
      if (completedStep?.routine_id) {
        const dayKey = new Date(completedStep.effective_start_at).toISOString().slice(0, 10);
        await client.query(
          `INSERT INTO todo_routine_done (user_id, routine_id, day_key)
           VALUES ($1, $2, $3)
           ON CONFLICT DO NOTHING`,
          [req.userId, completedStep.routine_id, dayKey]
        );
      }
      const response = serializeRun(updatedRun, next.steps);
      await client.query(`INSERT INTO routine_mutations (company_id, user_id, idempotency_key, mutation_type, routine_run_id, response) VALUES ($1,$2,$3,'complete_step',$4,$5::jsonb)`, [req.companyId, req.userId, idempotencyKey, req.params.id, JSON.stringify(response)]);
      await client.query("COMMIT");
      notifyLiveActivity(pool, req.params.id, updatedRun.status === "completed" ? "end" : "update", compactActivityState(updatedRun, next.steps)).catch((e) => console.error("[routine-live-activity] update failed", e?.message || e));
      res.json(response);
    } catch (e) {
      await client.query("ROLLBACK").catch(() => {});
      console.error(e);
      res.status(e.statusCode || 500).json({ error: e.code || "failed_complete_routine_step", message: e.message });
    } finally {
      client.release();
    }
  });

  app.post("/api/todo/routine-runs/:id/complete", authRequired, requireManage, async (req, res) => {
    try {
      const { run, steps } = await loadRun(pool, req.companyId, req.userId, req.params.id, false);
      if (run.status === "completed") return res.json(serializeRun(run, steps));
      const completedAt = new Date();
      const updated = (await pool.query(
        `UPDATE routine_runs SET status = 'completed', completed_at = $3, effective_estimated_end_at = $3, version = version + 1, updated_at = now()
          WHERE id = $1 AND company_id = $2 AND user_id = $4 RETURNING *`,
        [req.params.id, req.companyId, completedAt, req.userId]
      )).rows[0];
      await pool.query(`UPDATE routine_run_steps SET status = CASE WHEN status = 'completed' THEN status ELSE 'completed' END, completed_at = COALESCE(completed_at, $3) WHERE run_id = $1 AND company_id = $2`, [req.params.id, req.companyId, completedAt]);
      const freshSteps = (await pool.query(`SELECT * FROM routine_run_steps WHERE run_id = $1 AND company_id = $2 ORDER BY position`, [req.params.id, req.companyId])).rows;
      for (const step of freshSteps) {
        if (!step.routine_id) continue;
        const dayKey = new Date(step.effective_start_at).toISOString().slice(0, 10);
        await pool.query(
          `INSERT INTO todo_routine_done (user_id, routine_id, day_key)
           VALUES ($1, $2, $3)
           ON CONFLICT DO NOTHING`,
          [req.userId, step.routine_id, dayKey]
        );
      }
      const response = serializeRun(updated, freshSteps);
      await emitAutomationEvent({ companyId: req.companyId, eventType: "routine_group.completed", subjectType: "routine_run", subjectId: req.params.id, actorUserId: req.userId, source: "routine-groups.api", payload: { routine_run_id: req.params.id, routine_group_id: run.routine_group_id } });
      notifyLiveActivity(pool, req.params.id, "end", compactActivityState(updated, freshSteps)).catch(() => {});
      res.json(response);
    } catch (e) { console.error(e); res.status(e.statusCode || 500).json({ error: e.code || "failed_complete_routine_run", message: e.message }); }
  });

  app.post("/api/todo/routine-runs/:id/cancel", authRequired, requireManage, async (req, res) => {
    try {
      const updated = (await pool.query(
        `UPDATE routine_runs SET status = 'cancelled', cancelled_at = now(), version = version + 1, updated_at = now()
          WHERE id = $1 AND company_id = $2 AND user_id = $3 AND status IN ('scheduled','active') RETURNING *`,
        [req.params.id, req.companyId, req.userId]
      )).rows[0];
      if (!updated) return res.status(404).json({ error: "routine_run_not_found" });
      const steps = (await pool.query(`SELECT * FROM routine_run_steps WHERE run_id = $1 AND company_id = $2 ORDER BY position`, [req.params.id, req.companyId])).rows;
      notifyLiveActivity(pool, req.params.id, "end", compactActivityState(updated, steps)).catch(() => {});
      res.json(serializeRun(updated, steps));
    } catch (e) { console.error(e); res.status(500).json({ error: "failed_cancel_routine_run" }); }
  });

  app.post("/api/todo/routine-live-activity-tokens", authRequired, requireManage, async (req, res) => {
    const token = cleanString(req.body?.token, 512);
    const tokenKind = req.body?.token_kind === "push_to_start" ? "push_to_start" : "update";
    const environment = req.body?.environment === "production" ? "production" : "sandbox";
    const runId = cleanString(req.body?.run_id, 80);
    if (!token) return res.status(400).json({ error: "token_required" });
    try {
      if (runId) await loadRun(pool, req.companyId, req.userId, runId, false);
      await pool.query(
        `INSERT INTO routine_live_activity_tokens (token, company_id, user_id, run_id, token_kind, environment, invalidated_at, last_error)
         VALUES ($1,$2,$3,$4,$5,$6,NULL,NULL)
         ON CONFLICT (token) DO UPDATE SET company_id = EXCLUDED.company_id, user_id = EXCLUDED.user_id, run_id = EXCLUDED.run_id, token_kind = EXCLUDED.token_kind, environment = EXCLUDED.environment, invalidated_at = NULL, last_error = NULL, updated_at = now()`,
        [token, req.companyId, req.userId, runId, tokenKind, environment]
      );
      res.json({ ok: true });
    } catch (e) { console.error(e); res.status(e.statusCode || 500).json({ error: e.code || "failed_register_routine_live_activity_token", message: e.message }); }
  });

  app.delete("/api/todo/routine-live-activity-tokens", authRequired, requireManage, async (req, res) => {
    const token = cleanString(req.body?.token || req.query?.token, 512);
    if (!token) return res.status(400).json({ error: "token_required" });
    await pool.query(`UPDATE routine_live_activity_tokens SET invalidated_at = now() WHERE token = $1 AND company_id = $2 AND user_id = $3`, [token, req.companyId, req.userId]);
    res.status(204).end();
  });
}
