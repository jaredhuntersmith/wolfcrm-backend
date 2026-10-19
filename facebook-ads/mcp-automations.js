import { randomUUID } from "node:crypto";
import { z } from "zod";
import { dispatch, transaction, digest, fault } from "../mcp/context.js";
import { metricRule } from "./automation.js";
export function registerAdsAutomationTools(tool, { actor, pool, app }) {
  const result = z.object({ data: z.json() }),
    empty = z.object({}).strict();
  async function check(id) {
    const row = (
      await pool.query(
        `SELECT d.id FROM automation_definitions d WHERE d.id=$1 AND d.company_id=$2 AND EXISTS(SELECT 1 FROM automation_nodes n WHERE n.version_id IN (d.active_version_id,d.draft_version_id) AND n.config->>'trigger_key'='facebook_ads.metric')`,
        [id, actor.companyId],
      )
    ).rows[0];
    if (!row) throw fault(404, "facebook_automation_not_found");
  }
  const add = (name, description, schema, handler, write = false) =>
    tool(
      name,
      description,
      schema,
      result,
      write ? "ads:write" : "ads:read",
      ["integrations.manage", "automations.manage"],
      async (i) => ({ data: await handler(i) }),
      write,
    );
  add(
    "facebook_ads_automations",
    "List existing company automation definitions with a Facebook metric trigger. Uses the canonical automation permission boundary.",
    empty,
    async () => {
      const all = await dispatch(app, actor, "GET", "/api/automations");
      const ids = (
        await pool.query(
          "SELECT DISTINCT v.automation_id FROM automation_nodes n JOIN automation_versions v ON v.id=n.version_id WHERE n.company_id=$1 AND n.config->>'trigger_key'='facebook_ads.metric'",
          [actor.companyId],
        )
      ).rows.map((x) => x.automation_id);
      return all.filter((x) => ids.includes(x.id));
    },
  );
  add(
    "facebook_ads_automation_get",
    "Read one company Facebook metric automation through the existing automation interface.",
    z.object({ id: z.uuid() }).strict(),
    async (i) => {
      await check(i.id);
      return dispatch(app, actor, "GET", "/api/automations/" + i.id);
    },
  );
  const graph = z
    .object({
      nodes: z.array(z.record(z.string(), z.json())).min(1).max(100),
      edges: z.array(z.record(z.string(), z.json())).max(200),
      settings: z.record(z.string(), z.json()).optional(),
    })
    .strict();
  const request = z.object({ request_id: z.uuid() });
  async function once(name, input, fn) {
    if (!actor.connectionId) throw fault(403, "oauth_connection_required");
    return transaction(pool, async (db) => {
      await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
        actor.connectionId + input.request_id,
      ]);
      const old = (
        await db.query(
          "SELECT * FROM mcp_operations WHERE connection_id=$1 AND request_id=$2",
          [actor.connectionId, input.request_id],
        )
      ).rows[0];
      if (old) {
        if (old.operation !== name || old.input_hash !== digest(input))
          throw fault(409, "idempotency_conflict");
        await check(old.result.id);
        return old.result;
      }
      const value = await fn();
      await db.query(
        "INSERT INTO mcp_operations(connection_id,request_id,operation,input_hash,result) VALUES($1,$2,$3,$4,$5)",
        [
          actor.connectionId,
          input.request_id,
          name,
          digest(input),
          JSON.stringify(value),
        ],
      );
      return value;
    });
  }
  add(
    "facebook_ads_automation_create",
    "Create a disabled draft with one configured metric trigger. Continue in the existing builder or update its draft graph; publishing is a separate configured-policy operation.",
    request
      .extend({ name: z.string().trim().min(1).max(120), rule: metricRule })
      .strict(),
    (i) =>
      once("facebook_ads_automation_create", i, async () => {
        const draft = await dispatch(app, actor, "POST", "/api/automations", {
          name: i.name,
        });
        const nodeId = randomUUID();
        await dispatch(
          app,
          actor,
          "PUT",
          `/api/automations/${draft.id}/draft/graph`,
          {
            nodes: [
              {
                id: nodeId,
                node_key: "facebook_metric",
                node_type: "trigger",
                title: "Facebook Ads metric",
                config: { trigger_key: "facebook_ads.metric", ads: i.rule },
                position_x: 0,
                position_y: 0,
              },
            ],
            edges: [],
          },
        );
        return { id: draft.id, status: "draft" };
      }),
    true,
  );
  add(
    "facebook_ads_automation_save",
    "Save a draft graph through canonical validation. Does not publish or enable it. Existing action/condition node contracts apply.",
    request.extend({ id: z.uuid(), graph }).strict(),
    (i) =>
      once("facebook_ads_automation_save", i, async () => {
        await check(i.id);
        if (
          !i.graph.nodes.some(
            (n) => n.config?.trigger_key === "facebook_ads.metric",
          )
        )
          throw fault(400, "facebook_metric_trigger_required");
        await dispatch(
          app,
          actor,
          "PUT",
          `/api/automations/${i.id}/draft/graph`,
          i.graph,
        );
        return { id: i.id, status: "draft_saved" };
      }),
    true,
  );
  add(
    "facebook_ads_automation_control",
    "Publish, pause, or resume an existing metric automation through canonical company permissions. Publishing/enabling can change real ads when its conditions match.",
    request
      .extend({ id: z.uuid(), action: z.enum(["publish", "pause", "resume"]) })
      .strict(),
    (i) =>
      once("facebook_ads_automation_control", i, async () => {
        await check(i.id);
        await dispatch(
          app,
          actor,
          "POST",
          `/api/automations/${i.id}/${i.action}`,
          {},
        );
        return { id: i.id, action: i.action };
      }),
    true,
  );
}
