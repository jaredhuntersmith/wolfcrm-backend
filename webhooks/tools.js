import { z } from "zod";
import { configSchema } from "./domain.js";
import { fault } from "../mcp/context.js";
export function registerWebhookTools(tool, { actor, app }) {
  const service = () => {
    if (!app.locals.webhooks) throw fault(503, "webhooks_unavailable");
    return app.locals.webhooks;
  };
  // The existing MCP transport extends top-level object schemas with approval
  // metadata. Business refinements still run in service.create/update.
  const inputConfig = z.object(configSchema.shape).strict();
  const patchConfig = z
    .object(
      Object.fromEntries(
        Object.entries(configSchema.shape).map(([key, schema]) => [
          key,
          (schema instanceof z.ZodDefault
            ? schema.removeDefault()
            : schema
          ).optional(),
        ]),
      ),
    )
    .strict();
  const page = {
    limit: z.number().int().min(1).max(5).default(5),
    offset: z.number().int().min(0).max(10000).default(0),
  };
  const summary = (c) =>
    Object.fromEntries(
      [
        "id",
        "company_id",
        "name",
        "direction",
        "enabled",
        "revision",
        "revoked_at",
        "automation_id",
      ].map((k) => [k, c[k] ?? null]),
    );
  const bounded = (value) => JSON.stringify(value).length < 5500;
  const current = async (id) => {
    const c = (await service().list(actor)).connections.find(
      (c) => c.id === id,
    );
    if (!c) throw fault(404, "webhook_not_found");
    return c;
  };
  const out = z.object({}).catchall(z.json()),
    caps = ["automations.manage", "integrations.manage"];
  tool(
    "webhooks_list",
    "List a page of company webhook status and supported event keys. Supply id for non-secret configuration; oversized configuration is explicitly omitted and can be edited natively or with a partial update. Never returns credentials.",
    z.object({ ...page, id: z.uuid().optional() }).strict(),
    out,
    "crm:read",
    caps,
    async (i) => {
      if (i.id) {
        const c = await current(i.id);
        return bounded(c)
          ? { connection: c }
          : {
              connection: summary(c),
              configuration_omitted: true,
              message:
                "Configuration exceeds the client response limit. Use native Settings or update selected fields only.",
            };
      }
      const result = await service().list(actor);
      return {
        connections: result.connections
          .slice(i.offset, i.offset + i.limit)
          .map(summary),
        next_offset:
          i.offset + i.limit < result.connections.length
            ? i.offset + i.limit
            : null,
        events: result.events.map((e) => e.key),
        actions: result.actions,
      };
    },
  );
  tool(
    "webhooks_create",
    "Create a disabled incoming or outgoing webhook with non-secret configuration. Credentials are generated or replaced only in native Settings → Webhooks.",
    inputConfig,
    out,
    "crm:write",
    caps,
    async (i) =>
      summary(await service().create(actor, { ...i, enabled: false })),
    true,
  );
  tool(
    "webhooks_update",
    "Partially update non-secret webhook configuration using an exact revision; omitted fields are preserved. Arrays/templates supplied replace that field. Does not generate/read credentials. Native sample validation is required before enabling incoming.",
    z
      .object({
        id: z.uuid(),
        expected_revision: z.number().int().positive(),
        config: patchConfig,
      })
      .strict(),
    out,
    "crm:write",
    caps,
    async (i) => {
      const c = await current(i.id);
      const config = Object.fromEntries(
        Object.keys(configSchema.shape).map((k) => [k, c[k]]),
      );
      return summary(
        await service().update(actor, i.id, i.expected_revision, {
          ...config,
          ...i.config,
        }),
      );
    },
    true,
  );
  tool(
    "webhooks_activity",
    "Read bounded receipt and delivery status without raw payloads, response bodies or credentials.",
    z.object({ id: z.uuid(), ...page }).strict(),
    out,
    "crm:read",
    caps,
    async (i) => {
      const result = await service().activity(actor, i.id);
      const receipts = result.receipts.slice(i.offset, i.offset + i.limit);
      const deliveries = result.deliveries
        .slice(i.offset, i.offset + i.limit)
        .map(({ history, ...d }) => d);
      return {
        receipts,
        deliveries,
        next_offset:
          i.offset + i.limit <
          Math.max(result.receipts.length, result.deliveries.length)
            ? i.offset + i.limit
            : null,
        history_note:
          "Recent 50 records per kind; individual attempt details are available in native Activity.",
      };
    },
  );
  tool(
    "webhooks_preview",
    "Validate a sample and preview mappings or a redacted outgoing body. Does not make an external request.",
    z.object({ id: z.uuid(), sample: z.json() }).strict(),
    out,
    "crm:write",
    caps,
    async (i) => {
      const result = await service().preview(actor, i.id, i.sample);
      return bounded(result)
        ? result
        : {
            valid: true,
            preview_omitted: true,
            message:
              "Preview exceeds the client response limit. Inspect the full preview in native Settings.",
          };
    },
    true,
  );
  tool(
    "webhooks_retry",
    "Retry an existing failed receipt or delivery with the same execution identity. Requires unchanged configuration and current access. May repeat an uncertain external request.",
    z
      .object({
        id: z.uuid(),
        kind: z.enum(["receipt", "delivery"]),
        item_id: z.uuid(),
      })
      .strict(),
    out,
    "crm:write",
    caps,
    (i) => service().retry(actor, i.id, i.kind, i.item_id),
    true,
  );
  tool(
    "webhooks_test",
    "Queue an explicitly approved outgoing test request. Same public HTTPS security as production. No secrets returned.",
    z.object({ id: z.uuid(), sample: z.json(), request_id: z.uuid() }).strict(),
    out,
    "crm:write",
    caps,
    async (i) => {
      const d = await service().enqueue(
        actor,
        i.id,
        "mcp-test:" + actor.connectionId + ":" + i.request_id,
        i.sample,
        { test: true },
      );
      return { delivery_id: d.id, state: d.state };
    },
    true,
  );
}
