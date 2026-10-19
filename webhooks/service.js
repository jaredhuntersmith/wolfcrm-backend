import { randomUUID, randomBytes } from "node:crypto";
import { z } from "zod";
import { getRecord } from "../mcp/registry.js";
import { loadPrincipal, rateLimit } from "../mcp/access.js";
import { transaction, digest, fault, internalActor } from "../mcp/context.js";
import { encrypt, decrypt } from "../retell/security.js";
import { withinHours } from "../mcp/hours.js";
import {
  configSchema,
  mapPayload,
  boundJSON,
  atPath,
  structure,
  authenticate,
  render,
  sign,
  retryDelay,
  actionPermissions,
  pureActions,
} from "./domain.js";
import { destinationURL, resolveDestination, sendHTTPS } from "./network.js";
import { installWebhookSchema } from "./schema.js";
import {adsWebhookFields,isAdsWebhookEvent,projectAdsWebhookEvent} from '../facebook-ads/webhook-events.js';
import {mapWebhookResponse} from './responses.js';

const aad = (r) => "wolf-webhook:" + r.company_id + ":" + r.id;
const fields =
  "id company_id revision validated_revision revoked_at created_at updated_at";
const clean = (r) =>
  Object.fromEntries(fields.split(" ").map((k) => [k, r[k] ?? null]));
const uuid = (v) => z.uuid().parse(v);
const eventFields = (key) =>
  isAdsWebhookEvent(key) ? adsWebhookFields[key] : key.startsWith("job.")
    ? ["id", "title", "contact_id", "start_at", "end_at"]
    : key === "sms.received"
      ? ["id", "conversation_id", "direction", "body"]
      : ["id", "name", "email", "phone", "source"];
const safeError = (e) =>
  e instanceof z.ZodError
    ? "invalid_configuration"
    : e.status
      ? e.code
      : "webhook_unavailable";
export async function installWebhooks({
  app,
  pool,
  authRequired,
  emitEvent,
  catalog,
  env = process.env,
  startWorker = true,
  transport = sendHTTPS,
}) {
  await installWebhookSchema(pool);
  const supportedEvents = new Set([
    "contact.created",
    "lead.created",
    "lead.received_webhook",
    "sms.received",
    "job.created",
    "job.updated",
    "job.rescheduled",
    "job.completed",
    "facebook_ads.changed",
    "facebook_ads.metric",
  ]);
  const eventCatalog = catalog
    .filter((c) => c.wired && supportedEvents.has(c.key))
    .map((c) => ({
      key: c.key,
      name: c.display_name,
      description: c.description,
      sample: {
        event: {
          id: "sample-event",
          type: c.key,
          timestamp: new Date(0).toISOString(),
          schema_version: 1,
          data: Object.fromEntries(
            eventFields(c.key).map((k) => [
              k,
              k.endsWith("_at") ? new Date(0).toISOString() : "sample-" + k,
            ]),
          ),
        },
      },
    }));
  const knownEvents = new Set(eventCatalog.map((c) => c.key));
  const audit = (db, actor, id, operation) =>
    db.query(
      "INSERT INTO wolf_webhook_audit(company_id,connection_id,user_id,operation) VALUES($1,$2,$3,$4)",
      [actor.companyId, id, actor.userId, operation],
    );
  async function principal(userId, companyId, db = pool) {
    const actor = await loadPrincipal(db, userId, companyId, {
      enforceOAuthRolePolicy: false,
    });
    if (
      !actor.isCompanyOwner ||
      !actor.permissions.capabilities["automations.manage"] ||
      !actor.permissions.capabilities["integrations.manage"]
    )
      throw fault(403, "webhook_owner_required");
    return actor;
  }
  async function row(id, cid, db = pool, lock = false) {
    const r = (
      await db.query(
        "SELECT * FROM wolf_webhook_connections WHERE id=$1 AND company_id=$2" +
          (lock ? " FOR UPDATE" : ""),
        [uuid(id), cid],
      )
    ).rows[0];
    if (!r) throw fault(404, "webhook_not_found");
    return r;
  }
  async function active(r, db = pool, { test = false } = {}) {
    const actor = await principal(r.user_id, r.company_id, db);
    const companyAutomation = (
      await db.query(
        "SELECT automations_enabled,automation_emergency_stopped_at FROM companies WHERE id=$1",
        [r.company_id],
      )
    ).rows[0];
    if (
      companyAutomation?.automations_enabled === false ||
      companyAutomation?.automation_emergency_stopped_at
    )
      throw fault(409, "company_automations_paused");
    if (r.revoked_at) throw fault(410, "webhook_revoked");
    if (!test && !r.config.enabled) throw fault(409, "webhook_paused");
    const company = (
      await db.query(
        "SELECT operating_hours FROM mcp_company_policy WHERE company_id=$1",
        [r.company_id],
      )
    ).rows[0];
    if (
      !withinHours(r.config.operating_hours) ||
      !withinHours(company?.operating_hours)
    )
      throw fault(409, "outside_operating_hours");
    return actor;
  }
  function secrets(r) {
    return JSON.parse(decrypt(r.secrets_ciphertext, aad(r), env));
  }
  function dto(r) {
    return {
      ...clean(r),
      ...r.config,
      endpoint:
        r.config.direction === "incoming"
          ? `${env.MCP_PUBLIC_ORIGIN || ""}/webhooks/incoming/${r.endpoint_key}`
          : null,
      secret_names: Object.keys(secrets(r)).filter(
        (k) => k !== "ingress" && k !== "signing",
      ),
    };
  }
  async function configuration(input) {
    const c = configSchema.parse(input);
    boundJSON(c);
    if (c.direction === "incoming") {
      let origin;
      try {
        origin = new URL(env.MCP_PUBLIC_ORIGIN);
      } catch {}
      if (
        !origin ||
        !["http:", "https:"].includes(origin.protocol) ||
        origin.username ||
        origin.password ||
        origin.pathname !== "/" ||
        origin.search ||
        origin.hash
      )
        throw fault(503, "webhook_public_origin_required");
    }
    if (c.direction === "outgoing") {
      destinationURL(c.url);
      if (c.subscriptions.some((k) => !knownEvents.has(k)))
        throw fault(400, "unsupported_event");
    }
    return c;
  }
  async function linked(c, cid, db = pool) {
    if (!c.automation_id) return null;
    const a = (
      await db.query(
        "SELECT * FROM automation_definitions WHERE id=$1 AND company_id=$2",
        [c.automation_id, cid],
      )
    ).rows[0];
    if (!a) throw fault(404, "automation_not_found");
    return a;
  }
  async function list(actor) {
    await principal(actor.userId, actor.companyId);
    return {
      connections: (
        await pool.query(
          "SELECT * FROM wolf_webhook_connections WHERE company_id=$1 ORDER BY created_at DESC LIMIT 100",
          [actor.companyId],
        )
      ).rows.map(dto),
      events: eventCatalog,
      actions: Object.keys(actionPermissions),
      automations: (
        await pool.query(
          "SELECT id,name,status FROM automation_definitions WHERE company_id=$1 AND status<>'archived' ORDER BY name LIMIT 200",
          [actor.companyId],
        )
      ).rows,
    };
  }
  async function create(actor, input) {
    await principal(actor.userId, actor.companyId);
    const c = await configuration(input);
    if (c.enabled) throw fault(400, "create_disabled_first");
    await linked(c, actor.companyId);
    return transaction(pool, async (db) => {
      await db.query("SELECT id FROM companies WHERE id=$1 FOR UPDATE", [
        actor.companyId,
      ]);
      if (
        (
          await db.query(
            "SELECT id FROM wolf_webhook_connections WHERE company_id=$1 AND revoked_at IS NULL OFFSET 49 LIMIT 1",
            [actor.companyId],
          )
        ).rowCount
      )
        throw fault(409, "webhook_limit");
      const r = { id: randomUUID(), company_id: actor.companyId };
      const saved = (
        await db.query(
          "INSERT INTO wolf_webhook_connections(id,company_id,user_id,endpoint_key,config,secrets_ciphertext) VALUES($1,$2,$3,$4,$5,$6) RETURNING *",
          [
            r.id,
            r.company_id,
            actor.userId,
            randomBytes(32).toString("hex"),
            JSON.stringify(c),
            encrypt("{}", aad(r), env),
          ],
        )
      ).rows[0];
      await audit(db, actor, r.id, "created");
      return dto(saved);
    });
  }
  async function update(actor, id, revision, input) {
    await principal(actor.userId, actor.companyId);
    const c = await configuration(input);
    await linked(c, actor.companyId);
    return transaction(pool, async (db) => {
      const old = await row(id, actor.companyId, db, true);
      if (old.revoked_at) throw fault(410, "webhook_revoked");
      if (old.revision !== revision) throw fault(409, "configuration_changed");
      if (c.direction !== old.config.direction)
        throw fault(400, "direction_immutable");
      const unchanged =
        digest({ ...c, enabled: false }) ===
        digest({ ...configSchema.parse(old.config), enabled: false });
      const validated = old.validated_revision === old.revision && unchanged;
      if (
        c.enabled &&
        c.direction === "incoming" &&
        (!validated || !secrets(old).ingress || !c.automation_id)
      )
        throw fault(409, "validate_before_enabling");
      if (
        c.enabled &&
        c.direction === "outgoing" &&
        c.sign_requests &&
        !secrets(old).signing
      )
        throw fault(409, "signing_secret_required");
      if (c.enabled && c.direction === "incoming") {
        const a = await linked(c, actor.companyId, db);
        if (a.status !== "published")
          throw fault(409, "publish_automation_first");
      }
      const saved = (
        await db.query(
          "UPDATE wolf_webhook_connections SET config=$2,revision=revision+1,policy_revision=policy_revision+$4,validated_revision=$3,updated_at=now() WHERE id=$1 RETURNING *",
          [
            old.id,
            JSON.stringify(c),
            validated ? old.revision + 1 : null,
            unchanged ? 0 : 1,
          ],
        )
      ).rows[0];
      await audit(
        db,
        actor,
        id,
        c.enabled ? "configured_enabled" : "configured_paused",
      );
      return dto(saved);
    });
  }
  async function credential(
    actor,
    id,
    revision,
    { name = "ingress", value, generate = true },
  ) {
    await principal(actor.userId, actor.companyId);
    if (
      !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(name) ||
      ["constructor", "prototype"].includes(name)
    )
      throw fault(400, "invalid_secret_name");
    return transaction(pool, async (db) => {
      const r = await row(id, actor.companyId, db, true);
      if (r.revoked_at) throw fault(410, "webhook_revoked");
      if (r.revision !== revision) throw fault(409, "configuration_changed");
      if (
        (r.config.direction === "incoming" && name !== "ingress") ||
        (r.config.direction === "outgoing" && name === "ingress")
      )
        throw fault(400, "invalid_secret_name");
      const secret = generate
        ? randomBytes(32).toString("base64url")
        : z.string().min(1).max(4000).parse(value);
      const s = secrets(r);
      s[name] = secret;
      await db.query(
        "UPDATE wolf_webhook_connections SET secrets_ciphertext=$2,revision=revision+1,policy_revision=policy_revision+CASE WHEN config->>'direction'='outgoing' THEN 1 ELSE 0 END,validated_revision=CASE WHEN validated_revision=revision THEN revision+1 END,updated_at=now() WHERE id=$1",
        [id, encrypt(JSON.stringify(s), aad(r), env)],
      );
      await audit(db, actor, id, "credential_rotated");
      return { secret: generate ? secret : null, shown_once: true };
    });
  }
  async function revoke(actor, id, revision) {
    await principal(actor.userId, actor.companyId);
    return transaction(pool, async (db) => {
      const r = await row(id, actor.companyId, db, true);
      if (r.revision !== revision) throw fault(409, "configuration_changed");
      await db.query(
        "UPDATE wolf_webhook_connections SET revoked_at=now(),revision=revision+1,secrets_ciphertext=$2 WHERE id=$1",
        [id, encrypt("{}", aad(r), env)],
      );
      await audit(db, actor, id, "revoked");
      return { saved: true };
    });
  }
  async function preview(actor, id, sample) {
    await principal(actor.userId, actor.companyId);
    const r = await row(id, actor.companyId);
    const mapped =
      r.config.direction === "incoming"
        ? mapPayload(sample, r.config.mappings)
        : render(r.config.body_template, sample, {}, true);
    await pool.query(
      "UPDATE wolf_webhook_connections SET validated_revision=revision WHERE id=$1 AND revision=$2",
      [id, r.revision],
    );
    return { mapped, structure: structure(sample), valid: true };
  }
  async function receive(key, raw, headers) {
    if (!/^[a-f0-9]{64}$/.test(key)) throw fault(401, "authentication_failed");
    if (
      !Buffer.isBuffer(raw) ||
      raw.length > 65536 ||
      !/^application\/json(?:\s*;|$)/i.test(headers["content-type"] || "") ||
      (headers["content-encoding"] &&
        headers["content-encoding"] !== "identity")
    )
      throw fault(415, "post_json_required");
    const candidate = (
      await pool.query(
        "SELECT * FROM wolf_webhook_connections WHERE endpoint_key=$1",
        [key],
      )
    ).rows[0];
    if (!candidate || candidate.config.direction !== "incoming")
      throw fault(401, "authentication_failed");
    const nonce = authenticate(
      candidate.config,
      secrets(candidate),
      headers,
      raw,
    );
    let payload;
    try {
      payload = boundJSON(JSON.parse(raw.toString("utf8")));
    } catch (e) {
      if (e.status) throw e;
      throw fault(400, "invalid_json");
    }
    const mapped = mapPayload(payload, candidate.config.mappings),
      identity =
        headers["x-event-id"] ||
        (candidate.config.dedupe_path
          ? atPath(payload, candidate.config.dedupe_path)
          : null);
    if (
      identity !== null &&
      identity !== undefined &&
      ((typeof identity !== "string" && typeof identity !== "number") ||
        String(identity).length > 200 ||
        String(identity).length < 1)
    )
      throw fault(400, "invalid_event_identity");
    const hash = digest(raw.toString("base64"));
    return transaction(pool, async (db) => {
      const r = await row(candidate.id, candidate.company_id, db, true);
      if (r.revision !== candidate.revision)
        throw fault(409, "configuration_changed");
      await active(r, db);
      if (
        nonce &&
        !(
          await db.query(
            "INSERT INTO wolf_webhook_nonces(connection_id,nonce) VALUES($1,$2) ON CONFLICT DO NOTHING RETURNING nonce",
            [r.id, nonce],
          )
        ).rowCount
      )
        throw fault(409, "signature_replayed");
      const sender =
        identity === null || identity === undefined ? null : String(identity);
      const prior = sender
        ? (
            await db.query(
              "SELECT * FROM wolf_webhook_receipts WHERE connection_id=$1 AND sender_id=$2",
              [r.id, sender],
            )
          ).rows[0]
        : null;
      if (prior) {
        if (prior.input_hash !== hash)
          throw fault(409, "event_identity_conflict");
        return {
          receipt_id: prior.id,
          state: "duplicate",
          original_state: prior.state,
        };
      }
      await rateLimit(db, "webhook:" + r.id, 60);
      if (
        (
          await db.query(
            "SELECT id FROM wolf_webhook_receipts WHERE connection_id=$1 AND state NOT IN ('completed','expired','rejected') OFFSET 999 LIMIT 1",
            [r.id],
          )
        ).rowCount
      )
        throw fault(429, "webhook_queue_full");
      const automation = await linked(r.config, r.company_id, db);
      if (
        !automation ||
        automation.status !== "published" ||
        !automation.active_version_id
      )
        throw fault(409, "automation_unavailable");
      const hasTrigger = (
        await db.query(
          "SELECT id FROM automation_nodes WHERE version_id=$1 AND config->>'trigger_key'='incoming.webhook' AND config->>'connection_id'=$2",
          [automation.active_version_id, r.id],
        )
      ).rowCount;
      if (!hasTrigger) throw fault(409, "automation_trigger_not_linked");
      const id = randomUUID(),
        state = r.config.require_approval ? "awaiting_approval" : "queued";
      if (
        z.uuid().safeParse(headers["x-wolf-delivery-id"]).success &&
        (
          await db.query(
            "SELECT 1 FROM wolf_webhook_deliveries WHERE id=$1 AND company_id=$2",
            [headers["x-wolf-delivery-id"], r.company_id],
          )
        ).rowCount
      )
        throw fault(409, "webhook_loop_detected");
      let correlation = id,
        depth = 0;
      const incomingCorrelation = headers["x-wolf-correlation-id"];
      if (z.uuid().safeParse(incomingCorrelation).success) {
        const root = (
          await db.query(
            "SELECT 1 FROM wolf_webhook_receipts WHERE id=$1 AND company_id=$2",
            [incomingCorrelation, r.company_id],
          )
        ).rowCount;
        if (root) {
          correlation = incomingCorrelation;
          const n = (
            await db.query(
              "SELECT count(*)::int n FROM automation_events WHERE company_id=$1 AND payload->>'correlation_id'=$2 AND created_at>now()-interval '1 hour'",
              [r.company_id, correlation],
            )
          ).rows[0].n;
          if (n >= 8) throw fault(429, "webhook_correlation_limit");
          depth = n;
        }
      }

      const event = await emitEvent(
        {
          companyId: r.company_id,
          eventType: "incoming.webhook",
          subjectType: "generic",
          subjectId: id,
          actorUserId: r.user_id,
          source: "incoming_webhook",
          dedupeKey: "webhook:" + id,
          payload: {
            webhook_connection_id: r.id,
            webhook_receipt_id: id,
            correlation_id: correlation,
            automation_event_depth: depth,
            variables: mapped,
          },
        },
        { db },
      );
      if (!event) throw fault(503, "event_not_recorded");
      if (state === "awaiting_approval")
        await db.query(
          "UPDATE automation_events SET processing_status='webhook_approval' WHERE id=$1",
          [event],
        );
      await db.query(
        "INSERT INTO wolf_webhook_receipts(id,connection_id,company_id,event_id,sender_id,input_hash,revision,automation_id,version_id,state,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now()+($11::int*interval '1 day'))",
        [
          id,
          r.id,
          r.company_id,
          event,
          sender,
          hash,
          r.policy_revision,
          automation.id,
          automation.active_version_id,
          state,
          r.config.retention_days,
        ],
      );
      return { receipt_id: id, state };
    });
  }
  async function receiptGuard(db, eventId, action) {
    const receipt = (
      await db.query(
        "SELECT * FROM wolf_webhook_receipts WHERE event_id=$1 FOR SHARE",
        [eventId],
      )
    ).rows[0];
    if (!receipt) return null;
    const r = (
      await db.query(
        "SELECT * FROM wolf_webhook_connections WHERE id=$1 AND company_id=$2 FOR SHARE",
        [receipt.connection_id, receipt.company_id],
      )
    ).rows[0];
    await db.query("SELECT id FROM companies WHERE id=$1 FOR UPDATE", [
      r.company_id,
    ]);
    await db.query("SELECT id FROM users WHERE id=$1 FOR SHARE", [r.user_id]);
    await db.query(
      "SELECT user_id FROM employee_permissions WHERE user_id=$1 FOR SHARE",
      [r.user_id],
    );
    const actor = await active(r, db);
    if (receipt.revision !== r.policy_revision)
      throw fault(409, "configuration_changed");
    if (
      receipt.state === "awaiting_approval" ||
      receipt.state === "rejected" ||
      receipt.state === "expired" ||
      new Date(receipt.expires_at) <= new Date()
    )
      throw fault(403, "receipt_not_authorized");
    if (
      action &&
      !pureActions.has(action) &&
      (!r.config.allowed_actions.includes(action) ||
        !actionPermissions[action] ||
        actionPermissions[action].some(
          (c) => !actor.permissions.capabilities[c],
        ))
    )
      throw fault(403, "webhook_action_denied");
    return { receipt, connection: r, actor };
  }
  async function runIdentity(event, automation, create) {
    return transaction(pool, async (db) => {
      const g = await receiptGuard(db, event.id);
      if (!g) return create();
      if (
        g.receipt.automation_id !== automation.id ||
        g.receipt.version_id !== automation.version_id
      )
        throw fault(409, "automation_version_changed");
      await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
        event.id + automation.id,
      ]);
      const existing = (
        await db.query(
          "SELECT run_id FROM wolf_webhook_run_identity WHERE event_id=$1 AND automation_id=$2",
          [event.id, automation.id],
        )
      ).rows[0];
      if (existing)
        return (
          await db.query("SELECT * FROM automation_runs WHERE id=$1", [
            existing.run_id,
          ])
        ).rows[0];
      const run = await create();
      await db.query(
        "INSERT INTO wolf_webhook_run_identity(event_id,automation_id,run_id) VALUES($1,$2,$3)",
        [event.id, automation.id, run.id],
      );
      return run;
    });
  }
  async function guardNode(run, node) {
    if (
      node.node_type === "sub_automation" &&
      (
        await pool.query(
          "SELECT 1 FROM wolf_webhook_receipts WHERE event_id=$1",
          [run.trigger_event_id],
        )
      ).rowCount
    )
      throw fault(403, "webhook_child_automation_denied");
  }
  async function action(run, node, scope, execute) {
    const receipt = (
      await pool.query(
        "SELECT 1 FROM wolf_webhook_receipts WHERE event_id=$1",
        [run.trigger_event_id],
      )
    ).rowCount;
    if (!receipt && node.config?.action_key !== "note.create") {
      const managed =
        Object.hasOwn(actionPermissions, node.config?.action_key) &&
        (
          await pool.query(
            "SELECT 1 FROM automation_nodes WHERE version_id=$1 AND config->>'action_key'='webhook.send' AND config->>'destination_id' IS NOT NULL LIMIT 1",
            [run.automation_version_id],
          )
        ).rowCount;
      if (!managed) return execute();
    }
    return transaction(pool, async (db) => {
      await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
        run.id + node.id + scope,
      ]);
      const g = await receiptGuard(
        db,
        run.trigger_event_id,
        node.config?.action_key,
      );
      if (g && g.receipt.version_id !== run.automation_version_id)
        throw fault(403, "automation_version_changed");
      const prior = (
        await db.query(
          "SELECT result FROM wolf_webhook_effects WHERE run_id=$1 AND node_id=$2 AND scope_key=$3",
          [run.id, node.id, scope],
        )
      ).rows[0];
      if (prior) return prior.result;
      const result = await execute(g?.actor);
      if (!result?.waiting)
        await db.query(
          "INSERT INTO wolf_webhook_effects(run_id,node_id,scope_key,result) VALUES($1,$2,$3,$4)",
          [run.id, node.id, scope, JSON.stringify(result || {})],
        );
      return result;
    });
  }
  async function enqueue(
    actor,
    id,
    identity,
    context,
    { test = false, db, sourceRef } = {},
  ) {
    if (!db)
      return transaction(pool, (client) =>
        enqueue(actor, id, identity, context, { test, db: client, sourceRef }),
      );
    const r = await row(id, actor.companyId, db, true);
    await active(r, db, { test });
    if (r.config.direction !== "outgoing")
      throw fault(400, "outgoing_required");
    boundJSON(context);
    const exists = (
      await db.query(
        "SELECT * FROM wolf_webhook_deliveries WHERE connection_id=$1 AND identity=$2",
        [id, identity],
      )
    ).rows[0];
    if (exists) return exists;
    if (
      (
        await db.query(
          "SELECT id FROM wolf_webhook_deliveries WHERE connection_id=$1 AND state IN ('queued','processing') OFFSET 999 LIMIT 1",
          [id],
        )
      ).rowCount
    )
      throw fault(429, "delivery_queue_full");
    const s = secrets(r),
      body = JSON.stringify(render(r.config.body_template, context, s));
    const headers = Object.fromEntries(
      r.config.headers.map((h) => [h.name, render(h.value, context, s)]),
    );
    if (
      Object.values(headers).some(
        (v) => typeof v !== "string" || /[\r\n]/.test(v),
      )
    )
      throw fault(422, "invalid_rendered_header");
    if (r.config.sign_requests && !s.signing)
      throw fault(409, "signing_secret_required");
    const delivery = randomUUID(),
      data = encrypt(
        JSON.stringify({
          body,
          headers,
          _test: test,
          source_ref: sourceRef || null,
          correlation_id: context.correlation_id || delivery,
        }),
        aad(r) + ":" + delivery,
        env,
      );
    return (
      await db.query(
        "INSERT INTO wolf_webhook_deliveries(id,company_id,connection_id,identity,revision,context_ciphertext,attempt_limit) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(connection_id,identity) DO UPDATE SET identity=EXCLUDED.identity RETURNING *",
        [
          delivery,
          r.company_id,
          id,
          identity,
          r.policy_revision,
          data,
          r.config.max_attempts,
        ],
      )
    ).rows[0];
  }
  async function executionPrincipal(run) {
    const receipt = run.trigger_event_id
      ? await receiptGuard(pool, run.trigger_event_id)
      : null;
    if (receipt) return receipt.actor;
    const version = (
      await pool.query(
        "SELECT created_by_user_id FROM automation_versions WHERE id=$1 AND company_id=$2",
        [run.automation_version_id, run.company_id],
      )
    ).rows[0];
    return principal(version?.created_by_user_id, run.company_id);
  }
  async function automationDelivery(run, node, context, scope) {
    const actor = await executionPrincipal(run);
    const delivery = await enqueue(
      actor,
      node.config.destination_id,
      `run:${run.id}:${node.id}:${scope}`,
      {
        ...context,
        event: {
          ...context.event,
          id: context.event?.id || run.id,
          type:
            context.event?.event_type ||
            context.event?.type ||
            "automation.request",
          timestamp: new Date().toISOString(),
          schema_version: 1,
          data: context.event?.payload || {},
        },
        request: render(node.config.request || {}, context),
        correlation_id: context.event?.payload?.correlation_id || run.id,
      },
    );
    if (delivery.state === "delivered" && delivery.error_code)
      throw fault(422, delivery.error_code);
    if (delivery.state === "delivered")
      return {
        delivery_id: delivery.id,
        http_status: delivery.http_status,
        response: delivery.response_mapped || {},
      };
    if (["failed", "blocked", "expired"].includes(delivery.state))
      throw fault(409, delivery.error_code || "delivery_failed");
    return { waiting: true, delivery_id: delivery.id };
  }
  let subscriptionCursor = null;
  async function subscriptions() {
    const rows = (
      await pool.query(
        "SELECT * FROM wolf_webhook_connections WHERE config->>'direction'='outgoing' AND config->>'enabled'='true' AND revoked_at IS NULL AND ($1::uuid IS NULL OR id>$1) ORDER BY id LIMIT 100",
        [subscriptionCursor],
      )
    ).rows;
    subscriptionCursor = rows.length === 100 ? rows.at(-1).id : null;
    for (const r of rows) {
      if (!r.config.subscriptions.length) continue;
      let actor;
      try {
        actor = await active(r);
      } catch {
        continue;
      }
      const events = (
        await pool.query(
          `SELECT e.* FROM automation_events e WHERE e.company_id=$1 AND e.event_type=ANY($2::text[]) AND e.created_at>=$3 AND e.created_at>now()-($4::int*interval '1 day') AND e.processing_status<>'webhook_approval' AND NOT EXISTS(SELECT 1 FROM wolf_webhook_deliveries d WHERE d.connection_id=$5 AND d.identity='event:'||e.id::text) ORDER BY e.created_at LIMIT 25`,
          [
            r.company_id,
            r.config.subscriptions,
            r.created_at,
            r.config.retention_days,
            r.id,
          ],
        )
      ).rows;
      for (const e of events) {
        let correlation = e.payload?.correlation_id || e.id;
        let depth = Number(e.payload?.automation_event_depth || 0);
        if (
          e.source === "automation" &&
          z.uuid().safeParse(e.payload?.origin_run_id).success
        ) {
          const parent = (
            await pool.query(
              "SELECT ev.payload FROM automation_runs ar JOIN automation_events ev ON ev.id=ar.trigger_event_id WHERE ar.id=$1 AND ar.company_id=$2",
              [e.payload.origin_run_id, r.company_id],
            )
          ).rows[0];
          correlation = parent?.payload?.correlation_id || correlation;
          depth = Math.max(
            depth,
            Number(parent?.payload?.automation_event_depth || 0) + 1,
          );
        }
        const meta = {
          id: e.id,
          type: e.event_type,
          timestamp: new Date(e.occurred_at).toISOString(),
          schema_version: 1,
        };
        try {
          if (depth > 5) throw fault(409, "webhook_correlation_limit");
          const entity = e.event_type.startsWith("job.")
            ? "jobs"
            : e.event_type === "sms.received"
              ? "customer_messages"
              : "contacts";
          const projected = isAdsWebhookEvent(e.event_type)
            ? await projectAdsWebhookEvent({pool,service:app.locals.facebookAds,actor,event:e}) : null;
          const record = projected ? null : await getRecord(
            pool,
            { ...actor, scopes: ["crm:read", "comms:read"] },
            entity,
            e.subject_id,
          );
          const allowed = eventFields(e.event_type);
          const data = projected?.data ?? Object.fromEntries(
            allowed.map((k) => [k, record[k] ?? null]),
          );
          await enqueue(
            actor,
            r.id,
            "event:" + e.id,
            {
              event: { ...meta, data },
              correlation_id: correlation,
            },
            { sourceRef: projected?.sourceRef ?? { entity, id: e.subject_id } },
          );
        } catch (error) {
          if (!error.status) throw error;
          await pool.query(
            "INSERT INTO wolf_webhook_deliveries(id,company_id,connection_id,identity,revision,state,error_code) VALUES($1,$2,$3,$4,$5,'blocked',$6) ON CONFLICT(connection_id,identity) DO NOTHING",
            [
              randomUUID(),
              r.company_id,
              r.id,
              "event:" + e.id,
              r.policy_revision,
              safeError(error),
            ],
          );
        }
      }
    }
  }
  async function deliverOne() {
    const d = await transaction(pool, async (db) => {
      const next = (
        await db.query(
          "SELECT * FROM wolf_webhook_deliveries WHERE (state='queued' AND next_attempt_at<=now()) OR (state='processing' AND lease_until<now()) ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED",
        )
      ).rows[0];
      if (!next) return null;
      return (
        await db.query(
          "UPDATE wolf_webhook_deliveries SET state='processing',attempts=attempts+1,lease_until=now()+interval '30 seconds',uncertain=uncertain OR state='processing' WHERE id=$1 RETURNING *",
          [next.id],
        )
      ).rows[0];
    });
    if (!d) return false;
    let status = null,
      code = null,
      response = {},
      retry = false,
      uncertain = d.uncertain,
      retryAfter = null,
      r;
    try {
      r = await row(d.connection_id, d.company_id);
      if (r.policy_revision !== d.revision)
        throw fault(409, "configuration_changed");
      if (d.attempts > d.attempt_limit)
        throw fault(409, "delivery_attempt_limit");
      const context = JSON.parse(
        decrypt(d.context_ciphertext, aad(r) + ":" + d.id, env),
      );
      const actor = await active(r, pool, { test: context._test === true });
      if (context.source_ref?.kind === 'facebook_ads_event') {
        const event=(await pool.query('SELECT * FROM automation_events WHERE id=$1 AND company_id=$2',[context.source_ref.id,actor.companyId])).rows[0];
        if(!event)throw fault(403,'ads_event_unavailable');
        await projectAdsWebhookEvent({pool,service:app.locals.facebookAds,actor,event});
      } else if (context.source_ref) await getRecord(
          pool,
          { ...actor, scopes: ["crm:read", "comms:read"] },
          context.source_ref.entity,
          context.source_ref.id,
        );
      const s = secrets(r);
      const body = context.body,
        timestamp = String(Math.floor(Date.now() / 1000));
      const headers = { ...context.headers };
      Object.assign(headers, {
        "Idempotency-Key": d.id,
        "X-Wolf-Delivery-ID": d.id,
        "X-Wolf-Timestamp": timestamp,
        "X-Wolf-Correlation-ID": String(context.correlation_id || d.id),
      });
      if (r.config.sign_requests) {
        if (!s.signing) throw fault(409, "signing_secret_required");
        headers["X-Wolf-Nonce"] = d.id;
        headers["X-Wolf-Signature"] =
          "v1=" + sign(s.signing, timestamp, d.id, Buffer.from(body));
      }
      const result = await transport({
        url: r.config.url,
        method: r.config.method,
        headers,
        body,
        timeout_ms: r.config.timeout_ms,
      });
      status = result.status;
      retryAfter = result.retryAfter;
      if (status >= 200 && status < 300) {
        if (r.config.response_mappings.length) {
          const mapped = mapWebhookResponse(result, r.config.response_mappings);
          const serialized = JSON.stringify(mapped);
          if (
            Object.values(s).some(
              (value) => value && serialized.includes(value),
            )
          )
            throw fault(422, "response_contains_secret");
          response = mapped;
        }
      } else {
        code =
          status >= 300 && status < 400
            ? "redirect_rejected"
            : "receiver_http_error";
        retry = [408, 425, 429].includes(status) || status >= 500;
      }
    } catch (e) {
      code = safeError(e);
      retry = [
        "delivery_timeout",
        "delivery_network_error",
        "response_interrupted",
        "destination_dns_failed",
      ].includes(code);
      uncertain ||= [
        "delivery_timeout",
        "delivery_network_error",
        "response_interrupted",
        "response_too_large",
      ].includes(code);
    }
    const blocked = [
      "webhook_paused",
      "company_automations_paused",
      "outside_operating_hours",
      "configuration_changed",
      "webhook_revoked",
      "webhook_owner_required",
      "membership_inactive",
      "ad_account_not_selected",
      "facebook_ads_disconnected",
      "facebook_ads_permission_required",
      "facebook_reauthorize_required",
      "ads_event_unavailable",
      "ads_receipt_unconfirmed",
      "ads_evaluation_unconfirmed",
    ].includes(code);
    const again = retry && d.attempts < d.attempt_limit,
      // A successful HTTP effect must not be resent because local response
      // parsing failed. Retain its mapping error separately; downstream steps
      // fail clearly and explicit retry cannot repeat this accepted request.
      state = !code || (status >= 200 && status < 300)
        ? "delivered"
        : blocked
          ? "blocked"
          : again
            ? "queued"
            : "failed";
    await transaction(pool, async (db) => {
      // A stale worker cannot overwrite a later attempt's lease/result.
      const updated = await db.query(
        "UPDATE wolf_webhook_deliveries SET state=$2,http_status=$3,error_code=$4,response_mapped=$5,uncertain=$6,next_attempt_at=$7,lease_until=NULL,completed_at=CASE WHEN $2 IN ('delivered','failed','blocked') THEN now() END,context_ciphertext=CASE WHEN $2='delivered' THEN NULL ELSE context_ciphertext END WHERE id=$1 AND attempts=$8 AND state='processing' RETURNING id",
        [
          d.id,
          state,
          status,
          code,
          JSON.stringify(response),
          uncertain,
          new Date(Date.now() + retryDelay(d.attempts, retryAfter)),
          d.attempts,
        ],
      );
      if (updated.rowCount)
        await db.query(
          "INSERT INTO wolf_webhook_attempts(delivery_id,attempt,http_status,error_code,uncertain) VALUES($1,$2,$3,$4,$5)",
          [d.id, d.attempts, status, code, uncertain],
        );
    });
    return true;
  }
  async function activity(actor, id) {
    await principal(actor.userId, actor.companyId);
    await row(id, actor.companyId);
    const receipts = (
      await pool.query(
        `SELECT r.id,r.state,r.created_at,r.error_code,r.revision,r.event_id,e.processing_status,COALESCE((SELECT jsonb_agg(jsonb_build_object('id',a.id,'status',a.status)) FROM automation_runs a WHERE a.trigger_event_id=r.event_id),'[]') AS runs FROM wolf_webhook_receipts r LEFT JOIN automation_events e ON e.id=r.event_id WHERE r.connection_id=$1 ORDER BY r.created_at DESC LIMIT 50`,
        [id],
      )
    ).rows;
    return {
      receipts,
      deliveries: (
        await pool.query(
          `SELECT d.id,d.state,d.attempts,d.http_status,d.error_code,d.uncertain,d.created_at,d.completed_at,COALESCE((SELECT jsonb_agg(jsonb_build_object('attempt',a.attempt,'http_status',a.http_status,'error_code',a.error_code,'uncertain',a.uncertain,'created_at',a.created_at) ORDER BY a.attempt) FROM wolf_webhook_attempts a WHERE a.delivery_id=d.id),'[]') AS history FROM wolf_webhook_deliveries d WHERE d.connection_id=$1 ORDER BY d.created_at DESC LIMIT 50`,
          [id],
        )
      ).rows,
    };
  }
  async function review(actor, id, receiptId, approve) {
    await principal(actor.userId, actor.companyId);
    return transaction(pool, async (db) => {
      const r = await row(id, actor.companyId, db, true);
      await active(r, db);
      const receipt = (
        await db.query(
          "SELECT * FROM wolf_webhook_receipts WHERE id=$1 AND connection_id=$2 FOR UPDATE",
          [uuid(receiptId), id],
        )
      ).rows[0];
      if (
        !receipt ||
        receipt.state !== "awaiting_approval" ||
        receipt.revision !== r.policy_revision ||
        new Date(receipt.expires_at) <= new Date()
      )
        throw fault(409, "receipt_not_reviewable");
      await db.query(
        "UPDATE wolf_webhook_receipts SET state=$2,approved_by=$3 WHERE id=$1",
        [receiptId, approve ? "queued" : "rejected", actor.userId],
      );
      await db.query(
        "UPDATE automation_events SET processing_status=$2 WHERE id=$1",
        [receipt.event_id, approve ? "pending" : "webhook_rejected"],
      );
      await audit(
        db,
        actor,
        id,
        approve ? "receipt_approved" : "receipt_rejected",
      );
      return { saved: true };
    });
  }
  async function retry(actor, id, kind, item) {
    await principal(actor.userId, actor.companyId);
    return transaction(pool, async (db) => {
      const r = await row(id, actor.companyId, db, true);
      await active(r, db);
      let changed;
      if (kind === "delivery")
        changed = await db.query(
          "UPDATE wolf_webhook_deliveries SET state='queued',next_attempt_at=now(),error_code=NULL,lease_until=NULL,attempt_limit=LEAST(attempts+$4,10) WHERE id=$1 AND connection_id=$2 AND revision=$3 AND state IN ('failed','blocked') AND context_ciphertext IS NOT NULL AND attempts<10 RETURNING id",
          [uuid(item), id, r.policy_revision, r.config.max_attempts],
        );
      else {
        const receipt = (
          await db.query(
            "SELECT * FROM wolf_webhook_receipts WHERE id=$1 AND connection_id=$2",
            [uuid(item), id],
          )
        ).rows[0];
        if (!receipt) throw fault(404, "receipt_not_found");
        await receiptGuard(db, receipt.event_id);
        changed = await db.query(
          "UPDATE automation_events SET processing_status='pending',processed_at=NULL,attempt_count=0,next_attempt_at=now(),locked_at=NULL,locked_by=NULL,error=NULL WHERE id=$1 AND processing_status IN ('dead_letter','failed','processed') RETURNING id",
          [receipt.event_id],
        );
        await db.query(
          "UPDATE automation_runs SET status='queued',error_code=NULL,error_message=NULL,completed_at=NULL,updated_at=now() WHERE trigger_event_id=$1 AND status='failed'",
          [receipt.event_id],
        );
      }
      if (!changed.rowCount) throw fault(409, "retry_unavailable");
      if (kind === "delivery")
        await db.query(
          "UPDATE automation_runs SET status='waiting',completed_at=NULL,error_code=NULL,error_message=NULL WHERE status='failed' AND error_code='webhook_delivery_failed' AND id IN (SELECT run_id FROM automation_waits WHERE event_filter->>'delivery_id'=$1 AND status IN ('waiting','ready'))",
          [item],
        );
      await audit(db, actor, id, kind + "_retry");
      return { saved: true };
    });
  }
  let running = false;
  async function drain() {
    if (running) return;
    running = true;
    try {
      await pool.query(
        "UPDATE wolf_webhook_receipts r SET state='completed' WHERE state='queued' AND EXISTS(SELECT 1 FROM automation_runs a WHERE a.trigger_event_id=r.event_id) AND NOT EXISTS(SELECT 1 FROM automation_runs a WHERE a.trigger_event_id=r.event_id AND a.status<>'completed')",
      );
      await pool.query(
        "DELETE FROM wolf_webhook_nonces WHERE created_at<now()-interval '10 minutes'",
      );
      await pool.query(
        "UPDATE automation_events e SET payload='{}',processing_status=CASE WHEN processing_status='webhook_approval' THEN 'webhook_expired' ELSE processing_status END FROM wolf_webhook_receipts r WHERE r.event_id=e.id AND r.expires_at<now()",
      );
      await pool.query(
        "UPDATE wolf_webhook_receipts SET state='expired' WHERE expires_at<now() AND state NOT IN ('completed','expired')",
      );
      await pool.query(
        "UPDATE wolf_webhook_deliveries d SET context_ciphertext=NULL,response_mapped=NULL,state=CASE WHEN state IN ('queued','processing','blocked','failed') THEN 'expired' ELSE state END FROM wolf_webhook_connections c WHERE c.id=d.connection_id AND d.created_at<now()-((c.config->>'retention_days')::int*interval '1 day')",
      );
      const expired =
        "SELECT a.id FROM automation_runs a JOIN wolf_webhook_receipts r ON r.event_id=a.trigger_event_id WHERE r.expires_at<now()";
      await pool.query(
        `DELETE FROM automation_variables WHERE run_id IN (${expired})`,
      );
      await pool.query(
        `UPDATE automation_run_nodes SET input_snapshot='{}',output_snapshot='{}' WHERE run_id IN (${expired}) AND (input_snapshot<>'{}' OR output_snapshot<>'{}')`,
      );
      await pool.query(
        `UPDATE wolf_webhook_effects SET result='{}' WHERE run_id IN (${expired}) AND result<>'{}'`,
      );
      for (const [table, column] of [
        ["automation_run_iterations", "item_data"],
        ["automation_action_effects", "result"],
        ["automation_run_goals", "metadata"],
        ["automation_run_node_attempts", "metadata"],
      ])
        await pool.query(
          `UPDATE ${table} SET ${column}='{}' WHERE run_id IN (${expired}) AND ${column}<>'{}'`,
        );
      await pool.query(
        `UPDATE automation_waits SET matched_event=NULL WHERE run_id IN (${expired}) AND matched_event IS NOT NULL`,
      );
      await pool.query(
        `UPDATE automation_logs SET metadata='{}' WHERE run_id IN (${expired}) AND metadata<>'{}'`,
      );
      await pool.query(
        `UPDATE automation_runs SET status='stopped',error_code='webhook_retention_expired',completed_at=now() WHERE id IN (${expired}) AND status IN ('queued','running','waiting','paused')`,
      );
      await pool.query(
        `UPDATE automation_waits SET status='canceled' WHERE run_id IN (${expired}) AND status IN ('waiting','ready')`,
      );
      await pool.query(
        "DELETE FROM wolf_webhook_attempts WHERE created_at<now()-interval '30 days'",
      );
      await pool.query(
        "DELETE FROM wolf_webhook_audit WHERE created_at<now()-interval '30 days'",
      );
      await subscriptions();
      for (let i = 0; i < 10 && (await deliverOne()); i++);
    } finally {
      running = false;
    }
  }
  const checkContact = (actor, id) =>
    getRecord(pool, { ...actor, scopes: ["crm:read"] }, "contacts", id);
  const isManagedRun = async (run) =>
    !!(
      await pool.query(
        "SELECT 1 WHERE EXISTS(SELECT 1 FROM wolf_webhook_receipts WHERE event_id=$1) OR EXISTS(SELECT 1 FROM automation_nodes WHERE version_id=$2 AND config->>'action_key'='webhook.send' AND config->>'destination_id' IS NOT NULL)",
        [run.trigger_event_id, run.automation_version_id],
      )
    ).rowCount;
  const api = {
    isManagedRun,
    executionPrincipal,
    checkContact,
    list,
    create,
    update,
    credential,
    revoke,
    preview,
    receive,
    receiptGuard,
    runIdentity,
    guardNode,
    action,
    enqueue,
    automationDelivery,
    activity,
    review,
    retry,
    drain,
    deliverOne,
    principal,
  };
  app.locals.webhooks = api;
  const safe = (fn) => async (req, res) => {
    res.set("Cache-Control", "no-store");
    try {
      if (req.get("origin") && req.get("origin") !== env.MCP_WEB_ORIGIN)
        throw fault(403, "origin_not_allowed");
      if (req[internalActor]) throw fault(403, "native_session_required");
      const actor = await principal(req.userId, req.companyId);
      await fn(req, res, actor);
    } catch (e) {
      res.status(e instanceof z.ZodError ? 400 : e.status || 503).json({
        error: safeError(e),
        ...(e.diagnostics
          ? {
              diagnostics: e.diagnostics,
              details: Object.fromEntries(
                e.diagnostics.map((d) => [d.field, d.path + ": " + d.code]),
              ),
            }
          : {}),
      });
    }
  };
  const base = "/api/webhook-connections";
  app.get(
    base,
    authRequired,
    safe(async (_q, s, a) => s.json(await list(a))),
  );
  app.post(
    base,
    authRequired,
    safe(async (q, s, a) => s.status(201).json(await create(a, q.body))),
  );
  app.put(
    base + "/:id",
    authRequired,
    safe(async (q, s, a) =>
      s.json(
        await update(a, q.params.id, q.body.expected_revision, q.body.config),
      ),
    ),
  );
  app.post(
    base + "/:id/credential",
    authRequired,
    safe(async (q, s, a) =>
      s.json(
        await credential(a, q.params.id, q.body.expected_revision, q.body),
      ),
    ),
  );
  app.post(
    base + "/:id/revoke",
    authRequired,
    safe(async (q, s, a) =>
      s.json(await revoke(a, q.params.id, q.body.expected_revision)),
    ),
  );
  app.post(
    base + "/:id/preview",
    authRequired,
    safe(async (q, s, a) =>
      s.json(await preview(a, q.params.id, q.body.sample)),
    ),
  );
  app.get(
    base + "/:id/activity",
    authRequired,
    safe(async (q, s, a) => s.json(await activity(a, q.params.id))),
  );
  app.post(
    base + "/:id/test",
    authRequired,
    safe(async (q, s, a) => {
      const r = await row(q.params.id, a.companyId);
      if (r.config.direction === "incoming")
        return s.json(await preview(a, r.id, q.body.sample));
      const d = await enqueue(a, r.id, "test:" + randomUUID(), q.body.sample, {
        test: true,
      });
      await audit(pool, a, r.id, "test_queued");
      s.status(202).json({ delivery_id: d.id, state: d.state });
    }),
  );
  app.get(
    base + "/:id/receipts/:receipt",
    authRequired,
    safe(async (q, s, a) => {
      await row(q.params.id, a.companyId);
      const r = (
        await pool.query(
          "SELECT r.id,e.payload,d.name AS automation_name FROM wolf_webhook_receipts r JOIN automation_events e ON e.id=r.event_id JOIN automation_definitions d ON d.id=r.automation_id WHERE r.id=$1 AND r.connection_id=$2 AND r.company_id=$3",
          [uuid(q.params.receipt), q.params.id, a.companyId],
        )
      ).rows[0];
      if (!r) throw fault(404, "receipt_not_found");
      const c = await row(q.params.id, a.companyId);
      s.json({
        id: r.id,
        mapped: r.payload.variables || {},
        automation_name: r.automation_name,
        actions: c.config.allowed_actions,
      });
    }),
  );
  app.post(
    base + "/:id/receipts/:receipt/review",
    authRequired,
    safe(async (q, s, a) =>
      s.json(
        await review(
          a,
          q.params.id,
          q.params.receipt,
          z.boolean().parse(q.body.approve),
        ),
      ),
    ),
  );
  app.post(
    base + "/:id/receipts/:receipt/replay",
    authRequired,
    safe(async (q, s, a) => {
      if (q.body.create_new_execution !== true)
        throw fault(400, "explicit_replay_required");
      const result = await transaction(pool, async (db) => {
        const r = await row(q.params.id, a.companyId, db, true);
        await active(r, db);
        const old = (
          await db.query(
            "SELECT r.*,e.payload FROM wolf_webhook_receipts r JOIN automation_events e ON e.id=r.event_id WHERE r.id=$1 AND r.connection_id=$2 AND r.company_id=$3",
            [uuid(q.params.receipt), r.id, a.companyId],
          )
        ).rows[0];
        if (
          !old ||
          old.revision !== r.policy_revision ||
          new Date(old.expires_at) <= new Date() ||
          !old.payload.variables
        )
          throw fault(409, "replay_unavailable");
        const automation = await linked(r.config, r.company_id, db);
        if (
          !automation ||
          automation.status !== "published" ||
          automation.active_version_id !== old.version_id
        )
          throw fault(409, "automation_version_changed");
        await rateLimit(db, "webhook:" + r.id, 60);
        if (
          (
            await db.query(
              "SELECT id FROM wolf_webhook_receipts WHERE connection_id=$1 AND state NOT IN ('completed','expired','rejected') OFFSET 999 LIMIT 1",
              [r.id],
            )
          ).rowCount
        )
          throw fault(429, "webhook_queue_full");
        const id = randomUUID(),
          state = r.config.require_approval ? "awaiting_approval" : "queued";
        const event = await emitEvent(
          {
            companyId: r.company_id,
            eventType: "incoming.webhook",
            subjectType: "generic",
            subjectId: id,
            actorUserId: r.user_id,
            source: "incoming_webhook",
            dedupeKey: "webhook:" + id,
            payload: {
              webhook_connection_id: r.id,
              webhook_receipt_id: id,
              correlation_id: id,
              replayed_from: old.id,
              automation_event_depth: 0,
              variables: old.payload.variables,
            },
          },
          { db },
        );
        if (!event) throw fault(503, "event_not_recorded");
        if (state === "awaiting_approval")
          await db.query(
            "UPDATE automation_events SET processing_status='webhook_approval' WHERE id=$1",
            [event],
          );
        await db.query(
          "INSERT INTO wolf_webhook_receipts(id,connection_id,company_id,event_id,sender_id,input_hash,revision,automation_id,version_id,state,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now()+($11::int*interval '1 day'))",
          [
            id,
            r.id,
            r.company_id,
            event,
            "replay:" + id,
            old.input_hash,
            r.policy_revision,
            old.automation_id,
            old.version_id,
            state,
            r.config.retention_days,
          ],
        );
        await audit(db, a, r.id, "receipt_replayed_new_execution");
        return { receipt_id: id, state };
      });
      s.status(202).json(result);
    }),
  );
  app.post(
    base + "/:id/retry",
    authRequired,
    safe(async (q, s, a) =>
      s.json(
        await retry(
          a,
          q.params.id,
          z.enum(["receipt", "delivery"]).parse(q.body.kind),
          q.body.id,
        ),
      ),
    ),
  );
  app.post("/webhooks/incoming/:key", async (q, s) => {
    s.set("Cache-Control", "no-store");
    try {
      s.status(202).json(await receive(q.params.key, q.body, q.headers));
    } catch (e) {
      if ([409, 429].includes(e.status)) s.set("Retry-After", "60");
      s.status(e.status || 503).json({
        error: safeError(e),
        ...(e.diagnostics
          ? {
              diagnostics: e.diagnostics,
              details: Object.fromEntries(
                e.diagnostics.map((d) => [d.field, d.path + ": " + d.code]),
              ),
            }
          : {}),
      });
    }
  });
  if (startWorker) {
    const timer = setInterval(
      () => drain().catch(() => console.warn("[webhooks] processing deferred")),
      5000,
    );
    timer.unref();
  }
  return api;
}
