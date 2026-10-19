import { randomBytes } from "node:crypto";
import { installFacebookLeadSchema } from "./schema.js";
import {
  FacebookGraph,
  hash,
  encrypt,
  secureEqual,
  validSignature,
  signedRequest,
} from "./provider.js";
import { FacebookLeadError, fail } from "./domain.js";
import { createFacebookLeadStore, transaction, safeError } from "./store.js";
import { createFacebookLeadWorker } from "./worker.js";
const base = "/api/integrations/facebook-leads";
const messages = {
  facebook_dedicated_meta_app_required:
    "Use one Facebook app for Leads and Ads, separate from the existing Focus/Instagram app.",
  facebook_setup_required:
    "Set up the Meta application and backend variables before connecting.",
  facebook_token_expired_reconnect:
    "Facebook authorization expired or was revoked. Reconnect Facebook.",
  facebook_permission_required:
    "Check Page tasks, Leads Access Manager and requested permissions in Meta, then reconnect.",
  facebook_form_already_routed_to_another_company:
    "This form belongs to another company's route. Release it there first.",
  facebook_authorization_changed_retry:
    "Facebook authorization changed during this request. Refresh and retry.",
  configuration_changed_reload:
    "Settings changed elsewhere. Reload before saving.",
  competing_mappings_require_rule:
    "Sources targeting one field need the same combination rule or distinct priorities.",
  competing_mappings_require_unique_priorities:
    "Give competing sources different priorities. Lower numbers win.",
  scalar_type_requires_priority:
    "Use priority for email, phone, numeric and date fields. Other answers are retained in Lead Info.",
  date_range_requires_past_90_days_or_less:
    "Choose a past range of at most 90 days. Meta may retain less history.",
  facebook_enable_form_before_backfill:
    "Enable this form for your company before importing its history.",
  lead_form_mismatch: "That lead does not belong to this form.",
  facebook_processing_failed:
    "The operation could not finish. Refresh and retry; import failures are visible in activity.",
};
export async function installFacebookLeads({
  app,
  pool,
  authRequired,
  requireCapability,
  emitAutomationEvent,
  markContactDirty,
  sendPushToUsers,
  env = process.env,
  graph = new FacebookGraph(env),
  startWorker = true,
}) {
  await installFacebookLeadSchema(pool);
  const store = createFacebookLeadStore({ pool, graph, env }),
    worker = createFacebookLeadWorker({
      pool,
      store,
      graph,
      emitAutomationEvent,
      markContactDirty,
      sendPushToUsers,
    });
  const manage = requireCapability("integrations.manage");
  const wrap = (fn) => async (req, res) => {
    res.set("Cache-Control", "no-store");
    try {
      await fn(req, res);
    } catch (e) {
      const known = e instanceof FacebookLeadError;
      res.status(known ? e.status : 503).json({
        error: known ? e.code : "facebook_processing_failed",
        message:
          messages[known ? e.code : "facebook_processing_failed"] ||
          e.code?.replaceAll("_", " ") ||
          messages.facebook_processing_failed,
      });
    }
  };
  const scoped = (method, path, fn) =>
    app[method](
      base + path,
      authRequired,
      manage,
      wrap(async (req, res) => {
        if (!req.companyId) fail("company_required", 403);
        await fn(req, res);
      }),
    );
  scoped("get", "", async (req, res) =>
    res.json(await store.status(req.companyId)),
  );
  scoped("post", "/refresh", async (req, res) =>
    res.json(
      app.locals.facebookConnection &&
        (await app.locals.facebookConnection.isUnified(req.companyId))
        ? (await app.locals.facebookConnection.refresh({
            userId: req.userId,
            companyId: req.companyId,
          }),
          await store.status(req.companyId))
        : await store.refresh(req.companyId),
    ),
  );
  scoped("post", "/oauth/start", async (req, res) => {
    if (app.locals.facebookConnection)
      return res.json(
        await app.locals.facebookConnection.start(req, {
          client: req.body?.client,
          destination: "leads",
        }),
      );
    const state = randomBytes(32).toString("base64url"),
      client = req.body?.client === "web" ? "web" : "ios";
    if (client === "web" && env.FACEBOOK_LEADS_WEB_RETURN_URL) {
      const u = new URL(env.FACEBOOK_LEADS_WEB_RETURN_URL);
      if (u.protocol !== "https:") fail("facebook_web_return_url_invalid", 503);
    }
    const url = graph.loginURL(state);
    await pool.query(
      "DELETE FROM facebook_lead_oauth_states WHERE expires_at<now()",
    );
    await pool.query(
      `INSERT INTO facebook_lead_oauth_states(state_hash,company_id,user_id,session_hash,client,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '10 minutes')`,
      [hash(state), req.companyId, req.userId, hash(req.sessionToken), client],
    );
    res.json({ url });
  });
  app.get(
    base + "/oauth/callback",
    wrap(async (req, res) => {
      if (
        await app.locals.facebookConnection?.callback(req, res, {
          allowMissing: true,
        })
      )
        return;
      const state = typeof req.query.state === "string" ? req.query.state : "";
      const identity = (
        await pool.query(
          "DELETE FROM facebook_lead_oauth_states WHERE state_hash=$1 AND expires_at>now() RETURNING *",
          [hash(state)],
        )
      ).rows[0];
      if (!identity) fail("facebook_oauth_state_expired_or_used", 400);
      if (await app.locals.facebookConnection?.isUnified(identity.company_id))
        fail("facebook_use_unified_reconnect", 409);
      let result = "authorized";
      try {
        // Re-run the real session and capability middleware. Losing access during OAuth cancels it.
        const sessions = (
          await pool.query("SELECT token FROM sessions WHERE user_id=$1", [
            identity.user_id,
          ])
        ).rows;
        const session = sessions.find((s) =>
          secureEqual(hash(s.token), identity.session_hash),
        );
        if (!session) fail("facebook_oauth_session_ended", 403);
        const probe = {
          headers: { authorization: `Bearer ${session.token}` },
          header: () => `Bearer ${session.token}`,
          method: "GET",
          path: base,
        };
        let rejected = false;
        const response = {
          status() {
            rejected = true;
            return this;
          },
          json() {
            return this;
          },
        };
        let authenticated = false;
        await authRequired(probe, response, () => {
          authenticated = true;
        });
        let allowed = false;
        if (authenticated)
          manage(probe, response, () => {
            allowed = true;
          });
        if (
          rejected ||
          !allowed ||
          probe.companyId !== identity.company_id ||
          probe.userId !== identity.user_id
        )
          fail("facebook_oauth_access_changed", 403);
        if (req.query.error || typeof req.query.code !== "string")
          fail("facebook_authorization_declined");
        const token = await graph.exchange(req.query.code),
          me = await graph.request("me", token, { fields: "id" });
        if (!me.id) fail("facebook_identity_unavailable", 502);
        await transaction(pool, async (db) => {
          await store.settings(db, identity.company_id, true);
          await db.query(
            `INSERT INTO facebook_lead_connections(company_id,user_id,meta_user_id,token,status) VALUES($1,$2,$3,$4,'authorized') ON CONFLICT(company_id) DO UPDATE SET user_id=EXCLUDED.user_id,meta_user_id=EXCLUDED.meta_user_id,token=EXCLUDED.token,status='authorized',error_code=NULL,updated_at=now()`,
            [
              identity.company_id,
              identity.user_id,
              String(me.id),
              encrypt(token, identity.company_id, env),
            ],
          );
        });
        await store.refresh(identity.company_id);
      } catch (e) {
        result = "attention";
        await pool.query(
          `INSERT INTO facebook_lead_connections(company_id,user_id,status,error_code) VALUES($1,$2,'attention',$3) ON CONFLICT(company_id) DO UPDATE SET status='attention',error_code=EXCLUDED.error_code,updated_at=now()`,
          [identity.company_id, identity.user_id, safeError(e)],
        );
      }
      if (identity.client === "ios")
        return res.redirect(`wolfcrm://facebook-leads?status=${result}`);
      if (env.FACEBOOK_LEADS_WEB_RETURN_URL) {
        const target = new URL(env.FACEBOOK_LEADS_WEB_RETURN_URL);
        target.searchParams.set("facebook_leads", result);
        return res.redirect(String(target));
      }
      res
        .type("html")
        .send(
          "<!doctype html><html><head><title>Facebook Leads</title></head><body><h1>Return to WolfCRM</h1><p>Close this window and refresh Facebook Leads settings to review authorization, permissions and subscriptions.</p></body></html>",
        );
    }),
  );
  scoped("post", "/pages/:id/select", async (req, res) =>
    res.json(await store.inspectPage(req.companyId, req.params.id, true)),
  );
  scoped("post", "/pages/:id/remove", async (req, res) => {
    await transaction(pool, async (db) => {
      await store.settings(db, req.companyId, true);
      await db.query(
        "UPDATE facebook_lead_pages SET selected=false WHERE company_id=$1 AND page_id=$2",
        [req.companyId, req.params.id],
      );
      await db.query(
        "UPDATE facebook_lead_forms SET enabled=false WHERE company_id=$1 AND page_id=$2",
        [req.companyId, req.params.id],
      );
    });
    res.json({ ok: true });
  });
  scoped("get", "/mapping/:id", async (req, res) =>
    res.json(await store.mapping(req.companyId, req.params.id)),
  );
  scoped("put", "/mapping/:id", async (req, res) =>
    res.json(await store.saveMapping(req.companyId, req.params.id, req.body)),
  );
  scoped("post", "/mapping/:id/reset", async (req, res) => {
    const current = await store.mapping(req.companyId, req.params.id);
    res.json(
      await store.saveMapping(req.companyId, req.params.id, {
        revision: req.body.revision,
        mappings: {},
        unknown_policy: current.settings.unknown_policy,
        overwrite: current.settings.overwrite,
      }),
    );
  });
  scoped("post", "/mapping/:id/copy", async (req, res) => {
    const source = await store.mapping(req.companyId, req.params.id),
      target = await store.mapping(
        req.companyId,
        String(req.body.target_form_id),
      );
    // Copy stable keys only; require target optimistic revision from the caller.
    const mappings = Object.fromEntries(
      source.sources.map((s) => [s.key, s.mapping]),
    );
    res.json(
      await store.saveMapping(req.companyId, target.form_id, {
        revision: req.body.target_revision,
        mappings,
        unknown_policy: target.settings.unknown_policy,
        overwrite: target.settings.overwrite,
      }),
    );
  });
  scoped("put", "/forms/:id", async (req, res) => {
    if (typeof req.body.enabled !== "boolean") fail("enabled_boolean_required");
    await transaction(pool, async (db) => {
      await store.settings(db, req.companyId, true);
      const f = await store.form(db, req.companyId, req.params.id);
      if (req.body.revision !== f.revision)
        fail("configuration_changed_reload", 409);
      if (req.body.enabled && (!f.selected || !f.token))
        fail("facebook_select_page_first", 409);
      // An explicit form enable claims the sole company route. Pause retains that route.
      try {
        await db.query(
          "UPDATE facebook_lead_forms SET enabled=$3,recovery_at=CASE WHEN $3 AND NOT routed THEN now() ELSE recovery_at END,import_since=CASE WHEN $3 AND NOT routed THEN now() ELSE import_since END,routed=CASE WHEN $3 THEN true ELSE routed END,revision=revision+1 WHERE company_id=$1 AND form_id=$2",
          [req.companyId, req.params.id, req.body.enabled],
        );
      } catch (e) {
        if (e.code === "23505")
          fail("facebook_form_already_routed_to_another_company", 409);
        throw e;
      }
    });
    res.json({ ok: true });
  });
  scoped("post", "/forms/:id/release", async (req, res) => {
    await transaction(pool, async (db) => {
      await store.settings(db, req.companyId, true);
      await db.query(
        "UPDATE facebook_lead_forms SET enabled=false,routed=false,revision=revision+1 WHERE company_id=$1 AND form_id=$2",
        [req.companyId, req.params.id],
      );
      await db.query(
        "UPDATE facebook_lead_jobs SET status='canceled',lease=NULL,lease_until=NULL WHERE company_id=$1 AND form_id=$2 AND status<>'succeeded'",
        [req.companyId, req.params.id],
      );
      await db.query(
        "UPDATE facebook_lead_scans SET status='canceled',lease=NULL,lease_until=NULL WHERE company_id=$1 AND form_id=$2 AND status<>'succeeded'",
        [req.companyId, req.params.id],
      );
    });
    res.json({ ok: true });
  });
  scoped("post", "/forms/:id/preview", async (req, res) =>
    res.json(
      await store.preview(req.companyId, req.params.id, req.body?.lead_id),
    ),
  );
  scoped("post", "/forms/:id/import-existing", async (req, res) =>
    res.json(await store.scan(req.companyId, req.params.id, req.body)),
  );
  scoped("get", "/activity", async (req, res) =>
    res.json(await store.activity(req.companyId, req.query.before)),
  );
  scoped("post", "/jobs/:id/retry", async (req, res) => {
    const row = (
      await pool.query(
        "UPDATE facebook_lead_jobs SET status='pending',attempts=0,available_at=now(),error_code=NULL,lease=NULL,lease_until=NULL WHERE company_id=$1 AND id::text=$2 AND status IN ('failed','review') RETURNING id",
        [req.companyId, req.params.id],
      )
    ).rows[0];
    if (!row) fail("retryable_job_not_found", 404);
    res.json({ ok: true });
  });
  scoped("post", "/scans/:id/retry", async (req, res) => {
    const row = (
      await pool.query(
        "UPDATE facebook_lead_scans SET status='pending',attempts=0,available_at=now(),error_code=NULL,lease=NULL,lease_until=NULL WHERE company_id=$1 AND id::text=$2 AND status='failed' RETURNING id",
        [req.companyId, req.params.id],
      )
    ).rows[0];
    if (!row) fail("retryable_scan_not_found", 404);
    res.json({ ok: true });
  });
  async function disconnect(db, company, purge = false) {
    await store.settings(db, company, true);
    await db.query(
      "UPDATE facebook_lead_connections SET token=NULL,permissions='[]',status='disconnected',error_code=NULL,updated_at=now() WHERE company_id=$1",
      [company],
    );
    await db.query(
      "UPDATE facebook_lead_pages SET token=NULL,selected=false,subscription='disconnected',retrieval='unchecked' WHERE company_id=$1",
      [company],
    );
    await db.query(
      "UPDATE facebook_lead_forms SET enabled=false,routed=false,revision=revision+1 WHERE company_id=$1",
      [company],
    );
    await db.query(
      "UPDATE facebook_lead_jobs SET status='canceled',lease=NULL,lease_until=NULL WHERE company_id=$1 AND status<>'succeeded'",
      [company],
    );
    await db.query(
      "UPDATE facebook_lead_scans SET status='canceled',lease=NULL,lease_until=NULL WHERE company_id=$1 AND status<>'succeeded'",
      [company],
    );
    await db.query(
      "DELETE FROM facebook_lead_oauth_states WHERE company_id=$1",
      [company],
    );
    if (purge) {
      await db.query("DELETE FROM facebook_lead_jobs WHERE company_id=$1", [
        company,
      ]);
      await db.query("DELETE FROM facebook_lead_scans WHERE company_id=$1", [
        company,
      ]);
      await db.query(
        "DELETE FROM facebook_lead_connections WHERE company_id=$1",
        [company],
      );
      await db.query("DELETE FROM facebook_lead_settings WHERE company_id=$1", [
        company,
      ]);
    }
  }
  scoped("post", "/disconnect", async (req, res) => {
    if (await app.locals.facebookConnection?.isUnified(req.companyId)) {
      await app.locals.facebookConnection.controls(
        { userId: req.userId, companyId: req.companyId },
        { lead_importing_paused: true },
      );
      return res.json({ ok: true });
    }
    await transaction(pool, (db) => disconnect(db, req.companyId));
    res.json({ ok: true });
  });
  app.get(
    "/webhooks/facebook-leads",
    wrap(async (req, res) => {
      if (
        req.query["hub.mode"] !== "subscribe" ||
        !env.FACEBOOK_LEADS_VERIFY_TOKEN ||
        env.FACEBOOK_LEADS_VERIFY_TOKEN === env.FACEBOOK_LEADS_APP_SECRET ||
        !secureEqual(
          req.query["hub.verify_token"],
          env.FACEBOOK_LEADS_VERIFY_TOKEN,
        ) ||
        typeof req.query["hub.challenge"] !== "string"
      )
        fail("invalid_webhook_verification", 403);
      res.type("text").send(req.query["hub.challenge"]);
    }),
  );
  app.post(
    "/webhooks/facebook-leads",
    wrap(async (req, res) => {
      if (
        !validSignature(
          req.body,
          req.get("x-hub-signature-256"),
          env.FACEBOOK_LEADS_APP_SECRET,
        )
      )
        fail("invalid_webhook_signature", 401);
      let body;
      try {
        body = JSON.parse(req.body.toString("utf8"));
      } catch {
        fail("invalid_webhook_json");
      }
      await store.webhook(body);
      res.sendStatus(200);
    }),
  );
  for (const action of ["deauthorize", "data-deletion"])
    app.post(
      base + "/" + action,
      wrap(async (req, res) => {
        const data = signedRequest(
            req.body?.signed_request,
            env.FACEBOOK_LEADS_APP_SECRET,
          ),
          code = randomBytes(24).toString("hex");
        await app.locals.facebookConnection?.revoke(
          String(data.user_id),
          env.FACEBOOK_LEADS_APP_ID,
          { deletion: action === "data-deletion" },
        );
        await transaction(pool, async (db) => {
          const rows = app.locals.facebookConnection
            ? []
            : (
                await db.query(
                  "SELECT company_id FROM facebook_lead_connections WHERE meta_user_id=$1 AND NOT unified",
                  [String(data.user_id)],
                )
              ).rows;
          for (const row of rows)
            // Revocation purges integration data as well: a later deletion callback
            // must not lose its identity-to-company lookup and leave retained history.
            await disconnect(db, row.company_id, true);
          if (action === "data-deletion")
            await db.query(
              "INSERT INTO facebook_lead_deletions(code) VALUES($1)",
              [code],
            );
        });
        if (action === "deauthorize") return res.json({ ok: true });
        const origin = new URL(env.FACEBOOK_LEADS_REDIRECT_URI).origin;
        res.json({
          url: `${origin}${base}/deletion-status/${code}`,
          confirmation_code: code,
        });
      }),
    );
  app.get(
    base + "/deletion-status/:code",
    wrap(async (req, res) => {
      const row = (
        await pool.query(
          "SELECT status FROM facebook_lead_deletions WHERE code=$1",
          [req.params.code],
        )
      ).rows[0];
      if (!row) fail("deletion_request_not_found", 404);
      res
        .type("text")
        .send(
          "Facebook connection identity, credentials and integration configuration/history have been deleted. Previously imported business contact records are retained by the CRM company; contact that company to request deletion of your contact data.",
        );
    }),
  );
  let stopped = false,
    timer;
  const loop = async () => {
    try {
      await worker.tick();
    } catch {
      /* No raw errors/provider payloads in operational logs. */
    } finally {
      if (!stopped) {
        timer = setTimeout(loop, 5000);
        timer.unref();
      }
    }
  };
  if (startWorker && env.FACEBOOK_LEADS_WORKER_ENABLED === "true") {
    timer = setTimeout(loop, 1000);
    timer.unref();
  }
  return {
    store,
    worker,
    stop() {
      stopped = true;
      clearTimeout(timer);
    },
  };
}
