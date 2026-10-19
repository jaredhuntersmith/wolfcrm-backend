import { randomUUID } from "node:crypto";
import { z } from "zod";
import { id, decimal, period, scaled, fault, mutation } from "./domain.js";
import { metrics, validateReport } from "./catalog.js";
const numericMetrics = metrics
  .filter((m) => m.unit !== "text" && m.action !== "*")
  .map((m) => m.key);
export const metricRule = z
  .object({
    account_id: id,
    level: z.enum(["account", "campaign", "adset", "ad"]).default("ad"),
    entity_ids: z.array(id).max(100).default([]),
    metric: z.enum(numericMetrics),
    operator: z.enum(["gt", "gte", "lt", "lte", "eq"]),
    threshold: decimal,
    period: period.default({ preset: "yesterday" }),
    interval_minutes: z.number().int().min(15).max(1440).default(60),
    cooldown_minutes: z.number().int().min(15).max(525600).default(1440),
    repeat: z.enum(["crossing", "repeat", "once"]).default("crossing"),
    max_fires: z.number().int().min(1).max(10000).default(1),
    min_spend: decimal.optional(),
    min_impressions: decimal.optional(),
    min_results: decimal.optional(),
    result_metric: z.enum(numericMetrics).default("actions:lead"),
    conditions: z
      .array(
        z
          .object({
            metric: z.enum(numericMetrics),
            operator: z.enum(["gt", "gte", "lt", "lte", "eq"]),
            threshold: decimal,
          })
          .strict(),
      )
      .max(10)
      .default([]),
    logic: z.enum(["all", "any"]).default("all"),
  })
  .strict();
export function validateMetricRule(input) {
  const r = metricRule.parse(input);
  validateReport({
    account_id: r.account_id,
    level: r.level,
    metrics: [
      ...new Set([
        r.metric,
        r.result_metric,
        ...r.conditions.map((c) => c.metric),
      ]),
    ],
    period: r.period,
  });
  return r;
}
export function validateAdsAction(config) {
  const a = z
    .object({
      target: z.enum(["matched", "selected"]).default("matched"),
      account_id: id.optional(),
      level: z.enum(["campaign", "adset", "ad"]).optional(),
      entity_id: id.optional(),
      status: z.enum(["PAUSED", "ACTIVE"]).optional(),
      budget_type: z.enum(["daily_budget", "lifetime_budget"]).optional(),
      mode: z.enum(["absolute", "percent"]).optional(),
      value: decimal.optional(),
      min: decimal.optional(),
      max: decimal.optional(),
    })
    .strict()
    .parse(config.ads);
  if (a.target === "selected" && (!a.account_id || !a.level || !a.entity_id))
    throw fault("selected_ads_target_required");
  const change =
    config.action_key === "facebook_ads.status"
      ? { kind: "status", value: a.status }
      : {
          kind: "budget",
          budget_type: a.budget_type,
          mode: a.mode,
          value: a.value,
          min: a.min,
          max: a.max,
        };
  mutation.shape.change.parse(change);
  if (change.kind === "budget" && change.mode === "percent" && !change.max)
    throw fault("automation_budget_max_required");
  return a;
}
const compare = (v, op, t) => {
  const a = scaled(v),
    b = scaled(t);
  return { gt: a > b, gte: a >= b, lt: a < b, lte: a <= b, eq: a === b }[op];
};
export function evaluateMetric(rule, row, state, now = new Date()) {
  const conditions = [
    { metric: rule.metric, operator: rule.operator, threshold: rule.threshold },
    ...rule.conditions,
  ];
  if (
    conditions.some(
      (c) =>
        row.values[c.metric] == null ||
        typeof row.values[c.metric] !== "string",
    )
  )
    return { fire: false, reason: "missing_metric", matched: null };
  for (const [key, minimum] of [
    ["spend", rule.min_spend],
    ["impressions", rule.min_impressions],
    [rule.result_metric, rule.min_results],
  ])
    if (
      minimum !== undefined &&
      (row.values[key] == null || scaled(row.values[key]) < scaled(minimum))
    )
      return { fire: false, reason: "minimum_data_not_met", matched: null };
  const checks = conditions.map((c) =>
      compare(row.values[c.metric], c.operator, c.threshold),
    ),
    matched =
      rule.logic === "all" ? checks.every(Boolean) : checks.some(Boolean);
  if (!matched)
    return { fire: false, reason: "condition_false_rearmed", matched: false };
  if (state?.fire_count >= rule.max_fires)
    return { fire: false, reason: "fire_limit", matched: true };
  if (rule.repeat === "once" && state?.last_fired_at)
    return { fire: false, reason: "already_fired", matched: true };
  if (rule.repeat === "crossing" && state?.matched)
    return { fire: false, reason: "waiting_for_rearm", matched: true };
  if (
    state?.last_fired_at &&
    now - new Date(state.last_fired_at) < rule.cooldown_minutes * 60000
  )
    return { fire: false, reason: "cooldown", matched: true };
  return { fire: true, reason: "matched", matched: true };
}
export async function evaluateAdsTriggers({
  pool,
  service,
  emitAutomationEvent,
  env = process.env,
  now = new Date(),
}) {
  if (
    env.FACEBOOK_ADS_ENABLED !== "true" ||
    env.FACEBOOK_ADS_WORKER_ENABLED !== "true" ||
    !service
  )
    return;
  const nodes = (
    await pool.query(
      `SELECT n.id,n.company_id,n.config,v.created_by_user_id FROM automation_nodes n JOIN automation_versions v ON v.id=n.version_id JOIN automation_definitions d ON d.active_version_id=v.id AND d.company_id=n.company_id JOIN companies c ON c.id=d.company_id LEFT JOIN facebook_ads_trigger_state s ON s.node_id=n.id AND s.company_id=n.company_id AND s.entity_id='*' WHERE d.status='published' AND v.status='published' AND c.automations_enabled AND c.automation_emergency_stopped_at IS NULL AND (d.pause_until IS NULL OR d.pause_until<=now()) AND n.node_type='trigger' AND n.config->>'trigger_key'='facebook_ads.metric' ORDER BY s.last_evaluated_at NULLS FIRST,n.id LIMIT 100`,
    )
  ).rows;
  for (const node of nodes) {
    const db = await pool.connect();
    let locked = false;
    try {
      locked = (
        await db.query(
          "SELECT pg_try_advisory_lock(hashtextextended($1,0)) AS locked",
          ["facebook-ads-trigger:" + node.id],
        )
      ).rows[0].locked;
      if (!locked) continue;
      const rule = validateMetricRule(node.config.ads),
        last = (
          await db.query(
            "SELECT * FROM facebook_ads_trigger_state WHERE company_id=$1 AND node_id=$2 AND entity_id='*'",
            [node.company_id, node.id],
          )
        ).rows[0];
      if (
        last &&
        now - new Date(last.last_evaluated_at) < rule.interval_minutes * 60000
      )
        continue;
      await db.query(
        "INSERT INTO facebook_ads_trigger_state(company_id,node_id,entity_id,last_evaluated_at) VALUES($1,$2,'*',$3) ON CONFLICT(company_id,node_id,entity_id) DO UPDATE SET last_evaluated_at=EXCLUDED.last_evaluated_at",
        [node.company_id, node.id, now],
      );
      const actor = {
        userId: node.created_by_user_id,
        companyId: node.company_id,
      };
      await service.authorize(actor, false, db);
      const config = {
        account_id: rule.account_id,
        level: rule.level,
        entity_ids: rule.entity_ids,
        metrics: [
          ...new Set([
            rule.metric,
            rule.result_metric,
            "spend",
            "impressions",
            ...rule.conditions.map((c) => c.metric),
          ]),
        ],
        period: rule.period,
      };
      const rows = [];
      let cursor, report;
      let pages = 0;
      do {
        report = await service.insights(actor, config, cursor);
        if (
          now - new Date(report.refreshed_at) > 5 * 60000 ||
          new Date(report.refreshed_at) - now > 60000
        )
          throw fault("stale_report");
        rows.push(...report.items);
        cursor = report.next_cursor;
        if (++pages >= 10 && cursor) throw fault("automation_report_too_large");
      } while (cursor);
      // No match events are emitted until every page is successfully read.
      if (!rows.length)
        await db.query(
          "INSERT INTO facebook_ads_evaluations(id,company_id,node_id,status,reason) VALUES($1,$2,$3,'skipped','no_report_rows')",
          [randomUUID(), node.company_id, node.id],
        );
      for (const row of rows) {
        await db.query("BEGIN");
        try {
          const active = (
            await db.query(
              "SELECT d.id FROM automation_definitions d JOIN automation_nodes n ON n.version_id=d.active_version_id WHERE n.id=$1 AND d.status='published' AND d.company_id=$2 FOR SHARE OF d",
              [node.id, node.company_id],
            )
          ).rowCount;
          if (!active) {
            await db.query("ROLLBACK");
            break;
          }
          const old = (
            await db.query(
              "SELECT * FROM facebook_ads_trigger_state WHERE company_id=$1 AND node_id=$2 AND entity_id=$3 FOR UPDATE",
              [node.company_id, node.id, row.entity_id],
            )
          ).rows[0];
          const decision = evaluateMetric(rule, row, old, now);
          const evaluationId = randomUUID();
          if (decision.fire) {
            await service.authorize(actor, false, db);
            const event = await emitAutomationEvent(
              {
                companyId: node.company_id,
                eventType: "facebook_ads.metric",
                subjectType: "facebook_ad",
                subjectId: row.entity_id,
                actorUserId: actor.userId,
                source: "facebook_ads",
                dedupeKey: `facebook-ads:${node.id}:${row.entity_id}:${(old?.fire_count || 0) + 1}`,
                payload: {
                  trigger_node_id: node.id,
                  account_id: rule.account_id,
                  level: rule.level,
                  entity_id: row.entity_id,
                  metrics: row.values,
                  metric: rule.metric,
                  value: row.values[rule.metric],
                  period: report.period,
                  currency: report.currency,
                  timezone: report.timezone,
                  evaluated_at: now.toISOString(),
                  evaluation_id: evaluationId,
                },
              },
              { db },
            );
            if (!event) throw fault("automation_event_not_persisted", 503);
          }
          await db.query(
            `INSERT INTO facebook_ads_trigger_state(company_id,node_id,entity_id,matched,last_fired_at,fire_count,last_evaluated_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(company_id,node_id,entity_id) DO UPDATE SET matched=EXCLUDED.matched,last_fired_at=EXCLUDED.last_fired_at,fire_count=EXCLUDED.fire_count,last_evaluated_at=EXCLUDED.last_evaluated_at`,
            [
              node.company_id,
              node.id,
              row.entity_id,
              decision.matched ?? old?.matched ?? false,
              decision.fire ? now : old?.last_fired_at || null,
              (old?.fire_count || 0) + (decision.fire ? 1 : 0),
              now,
            ],
          );
          await db.query(
            "INSERT INTO facebook_ads_evaluations(id,company_id,node_id,entity_id,status,reason,details) VALUES($1,$2,$3,$4,$5,$6,$7)",
            [
              evaluationId,
              node.company_id,
              node.id,
              row.entity_id,
              decision.fire ? "fired" : "skipped",
              decision.reason,
              JSON.stringify({
                values: row.values,
                period: report.period,
                currency: report.currency,
                refreshed_at: report.refreshed_at,
              }),
            ],
          );
          await db.query("COMMIT");
        } catch (e) {
          await db.query("ROLLBACK");
          throw e;
        }
      }
    } catch (e) {
      await db.query(
        "INSERT INTO facebook_ads_trigger_state(company_id,node_id,entity_id,last_evaluated_at) VALUES($1,$2,'*',$3) ON CONFLICT(company_id,node_id,entity_id) DO UPDATE SET last_evaluated_at=EXCLUDED.last_evaluated_at",
        [node.company_id, node.id, now],
      );
      await db.query(
        "INSERT INTO facebook_ads_evaluations(id,company_id,node_id,status,reason) VALUES($1,$2,$3,'error',$4)",
        [
          randomUUID(),
          node.company_id,
          node.id,
          /^[a-z_]{1,80}$/.test(e.code || "") ? e.code : "evaluation_failed",
        ],
      );
    } finally {
      if (locked)
        await db.query("SELECT pg_advisory_unlock(hashtextextended($1,0))", [
          "facebook-ads-trigger:" + node.id,
        ]);
      db.release();
    }
  }
  await pool.query(
    "DELETE FROM facebook_ads_evaluations WHERE created_at<now()-interval '90 days'",
  );
}
export async function executeAdsAutomation({
  pool,
  service,
  run,
  node,
  config,
  context,
  scopeKey,
}) {
  if (!service) throw fault("facebook_ads_disabled", 503);
  const active = (
    await pool.query(
      "SELECT d.id FROM automation_definitions d JOIN companies c ON c.id=d.company_id WHERE d.id=$1 AND d.company_id=$2 AND d.active_version_id=$3 AND d.status='published' AND c.automations_enabled AND c.automation_emergency_stopped_at IS NULL AND (d.pause_until IS NULL OR d.pause_until<=now())",
      [run.automation_id, run.company_id, run.automation_version_id],
    )
  ).rowCount;
  if (!active) throw fault("automation_no_longer_enabled", 409);
  const author = (
    await pool.query(
      "SELECT created_by_user_id FROM automation_versions WHERE id=$1 AND company_id=$2",
      [run.automation_version_id, run.company_id],
    )
  ).rows[0]?.created_by_user_id;
  if (!author) throw fault("automation_author_unavailable", 403);
  const actor = { userId: author, companyId: run.company_id };
  await service.authorize(actor, true);
  const event = context.event?.payload || {};
  if (
    event.evaluated_at &&
    Date.now() - Date.parse(event.evaluated_at) > 5 * 60000
  )
    throw fault("stale_metric_event", 409);
  const a = validateAdsAction(config),
    accountId = a.target === "selected" ? a.account_id : event.account_id,
    l = a.target === "selected" ? a.level : event.level,
    entityId = a.target === "selected" ? a.entity_id : event.entity_id;
  const item = (await service.entity(actor, accountId, l, entityId, true)).item;
  const change =
    config.action_key === "facebook_ads.status"
      ? { kind: "status", value: a.status }
      : {
          kind: "budget",
          budget_type: a.budget_type,
          mode: a.mode,
          value: a.value,
          min: a.min || undefined,
          max: a.max || undefined,
        };
  if (change.kind === "budget" && change.mode === "percent" && !change.max)
    throw fault(
      "automation_budget_max_required",
      400,
      "Configure an absolute maximum budget before percentage automation.",
    );
  const requestId = `automation:${run.id}:${node.node_key}:${scopeKey}`;
  const old = (
    await pool.query(
      "SELECT previous FROM facebook_ads_receipts WHERE company_id=$1 AND request_id=$2",
      [run.company_id, requestId],
    )
  ).rows[0];
  const result = await service.mutate(
    actor,
    {
      request_id: requestId,
      account_id: accountId,
      level: l,
      entity_id: entityId,
      expected_version: old?.previous?.version || item.version,
      change,
    },
    "automation",
  );
  if (result.status !== "confirmed")
    throw fault(
      "facebook_ads_action_" + result.status,
      409,
      "Advertising action is not confirmed; inspect its receipt.",
    );
  return result;
}
