import { randomBytes } from "node:crypto";
import { z } from "zod";
import {
  hash,
  secureEqual,
  signedRequest,
} from "../facebook-leads/provider.js";
import { AdsGraph } from "./provider.js";
import { installAdsSchema } from "./schema.js";
import { createAdsService } from "./service.js";
import { fault, mutation } from "./domain.js";
const base = "/api/facebook-ads";
export async function installFacebookAds({
  app,
  pool,
  authRequired,
  requireCapability,
  emitAutomationEvent,
  env = process.env,
  graph = new AdsGraph(env),
}) {
  await installAdsSchema(pool);
  const service = createAdsService({ pool, graph, env, emitAutomationEvent });
  app.locals.facebookAds = service;
  const actor = (req) => ({ userId: req.userId, companyId: req.companyId });
  const wrap =
    (fn, always = false) =>
    async (req, res) => {
      res.set({
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
      });
      try {
        if (!always && env.FACEBOOK_ADS_ENABLED !== "true")
          throw fault(
            "facebook_ads_disabled",
            503,
            "Facebook Ads is not enabled on this backend.",
          );
        await fn(req, res);
      } catch (e) {
        res.status(e instanceof z.ZodError ? 400 : e.status || 503).json({
          error:
            e instanceof z.ZodError
              ? "invalid_ads_input"
              : e.code || "facebook_ads_unavailable",
          message:
            e instanceof z.ZodError
              ? "Check the selected fields and configuration."
              : e.status
                ? e.message
                : "Facebook Ads is temporarily unavailable.",
        });
      }
    };
  const route = (method, path, fn) =>
    app[method](
      base + path,
      authRequired,
      requireCapability("integrations.manage"),
      wrap(async (req, res) => {
        await service.authorize(actor(req));
        res.json(await fn(req));
      }),
    );
  route("get", "", (req) => service.status(actor(req)));
  route("get", "/catalog", () => service.catalog());
  route("post", "/refresh", async (req) => {
    if (await app.locals.facebookConnection?.isUnified(req.companyId)) {
      await app.locals.facebookConnection.refresh(actor(req));
      return service.status(actor(req));
    }
    return service.refresh(actor(req));
  });
  route("post", "/accounts", (req) =>
    service.select(actor(req), req.body.account_ids),
  );
  route("post", "/disconnect", async (req) => {
    if (await app.locals.facebookConnection?.isUnified(req.companyId)) {
      await app.locals.facebookConnection.controls(actor(req), {
        ads_operations_enabled: false,
      });
      return service.status(actor(req));
    }
    return service.disconnect(actor(req));
  });
  route("post", "/entities", (req) => service.entities(actor(req), req.body));
  route(
    "get",
    "/accounts/:account/:level/:id",
    async (req) =>
      (
        await service.entity(
          actor(req),
          req.params.account,
          req.params.level,
          req.params.id,
        )
      ).item,
  );
  route("post", "/insights", (req) =>
    service.insights(actor(req), req.body.config, req.body.cursor),
  );
  route("get", "/reports", (req) => service.reports(actor(req)));
  route("post", "/reports", (req) => service.startReport(actor(req), req.body));
  route("get", "/reports/:id", (req) =>
    service.pollReport(actor(req), req.params.id, req.query.cursor),
  );
  route("delete", "/reports/:id", (req) =>
    service.cancelReport(actor(req), req.params.id),
  );
  route("post", "/actions", (req) => service.mutate(actor(req), req.body));
  route("post", "/bulk-actions", async (req) => {
    const input = z.array(mutation).min(1).max(25).parse(req.body.actions);
    const results = [];
    for (const i of input) {
      try {
        results.push({
          entity_id: i.entity_id,
          receipt: await service.mutate(actor(req), i, "native_bulk"),
        });
      } catch (e) {
        results.push({
          entity_id: i.entity_id,
          error: e.code || "action_failed",
          message: e.status
            ? e.message
            : "This action could not be completed. Reconcile before retrying.",
          // Validation/auth failures can be corrected with a new request; transport/server
          // failures retain their IDs because a write may already have been accepted.
          retryable: !(e.status >= 400 && e.status < 500 && e.status !== 429),
        });
      }
    }
    return { items: results };
  });
  route("post", "/receipts/:id/reconcile", (req) =>
    service.reconcile(actor(req), req.params.id),
  );
  route("get", "/receipts", (req) => service.receipts(actor(req)));
  route("get", "/views", (req) => service.views(actor(req)));
  route("post", "/views", (req) => service.saveView(actor(req), req.body));
  route("delete", "/views/:id", (req) =>
    service.deleteView(actor(req), req.params.id),
  );
  route("get", "/evaluations", async (req) => ({
    items: (
      await pool.query(
        "SELECT e.id,e.node_id,e.entity_id,e.status,e.reason,e.details,e.created_at,n.title FROM facebook_ads_evaluations e LEFT JOIN automation_nodes n ON n.id=e.node_id WHERE e.company_id=$1 ORDER BY e.created_at DESC LIMIT 100",
        [req.companyId],
      )
    ).rows,
  }));
  route("post", "/oauth/start", async (req) => {
    if (app.locals.facebookConnection)
      return app.locals.facebookConnection.start(req, { destination: "ads" });
    await service.authorize(actor(req), true);
    if (!req.sessionToken) throw fault("human_session_required", 403);
    const state = randomBytes(32).toString("base64url"),
      url = graph.loginURL(state);
    await pool.query(
      "DELETE FROM facebook_ads_oauth_states WHERE expires_at<now()",
    );
    await pool.query(
      "INSERT INTO facebook_ads_oauth_states(state_hash,company_id,user_id,session_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '10 minutes')",
      [hash(state), req.companyId, req.userId, hash(req.sessionToken)],
    );
    return { url };
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
          "DELETE FROM facebook_ads_oauth_states WHERE state_hash=$1 AND expires_at>now() RETURNING *",
          [hash(state)],
        )
      ).rows[0];
      if (!identity) throw fault("oauth_state_expired_or_used");
      if (await app.locals.facebookConnection?.isUnified(identity.company_id))
        throw fault("facebook_use_unified_reconnect", 409);
      let result = "attention";
      try {
        const sessions = (
          await pool.query("SELECT token FROM sessions WHERE user_id=$1", [
            identity.user_id,
          ])
        ).rows;
        const session = sessions.find((s) =>
          secureEqual(hash(s.token), identity.session_hash),
        );
        if (!session) throw fault("oauth_session_ended", 403);
        const probe = {
          headers: { authorization: `Bearer ${session.token}` },
          header: () => `Bearer ${session.token}`,
          method: "GET",
          path: base,
        };
        let okay = false;
        const response = {
          status() {
            return this;
          },
          json() {
            return this;
          },
        };
        await authRequired(probe, response, () => {
          okay = true;
        });
        if (
          !okay ||
          probe.companyId !== identity.company_id ||
          probe.userId !== identity.user_id
        )
          throw fault("oauth_access_changed", 403);
        await service.authorize(actor(probe), true);
        if (req.query.error || typeof req.query.code !== "string")
          throw fault("facebook_authorization_declined");
        const token = await graph.exchange(req.query.code),
          me = await graph.request("me", token, { fields: "id" }),
          permissions = (await graph.all("me/permissions", token))
            .filter((x) => x.status === "granted")
            .map((x) => x.permission);
        const debug = await graph.request(
          "debug_token",
          `${graph.env.FACEBOOK_LEADS_APP_ID}|${graph.env.FACEBOOK_LEADS_APP_SECRET}`,
          { input_token: token },
        );
        if (
          !debug.data?.is_valid ||
          String(debug.data.app_id) !== graph.env.FACEBOOK_LEADS_APP_ID ||
          String(debug.data.user_id) !== String(me.id) ||
          debug.data.type !== "USER"
        )
          throw fault("facebook_user_token_required", 403);
        if (
          !permissions.some((p) => ["ads_read", "ads_management"].includes(p))
        )
          throw fault("facebook_ads_permission_required", 403);
        await service.authorize(actor(probe), true);
        await service.connect(actor(probe), {
          token,
          metaUserId: String(me.id),
          permissions,
          expiresAt: debug.data.expires_at
            ? new Date(debug.data.expires_at * 1000)
            : null,
        });
        await service.refresh(actor(probe));
        result = "connected";
      } catch (e) {
        await pool.query(
          "INSERT INTO facebook_ads_connections(company_id,user_id,status,error_code) VALUES($1,$2,'attention',$3) ON CONFLICT(company_id) DO UPDATE SET error_code=EXCLUDED.error_code,updated_at=now()",
          [
            identity.company_id,
            identity.user_id,
            /^[a-z_]+$/.test(e.code || "") ? e.code : "oauth_connection_failed",
          ],
        );
      }
      res.redirect(`wolfcrm://facebook-ads?status=${result}`);
    }),
  );
  app.post(
    base + "/deauthorize",
    wrap(async (req, res) => {
      const data = signedRequest(
        req.body?.signed_request,
        graph.env.FACEBOOK_LEADS_APP_SECRET,
      );
      await app.locals.facebookConnection?.revoke(
        String(data.user_id),
        graph.env.FACEBOOK_LEADS_APP_ID,
      );
      await service.revoke(String(data.user_id));
      res.json({ ok: true });
    }, true),
  );
  return service;
}
