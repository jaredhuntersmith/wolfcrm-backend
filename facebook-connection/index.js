import { randomBytes } from "node:crypto";
import {
  hash,
  secureEqual,
  signedRequest,
} from "../facebook-leads/provider.js";
import { ConnectionGraph, connectionConfiguration } from "./provider.js";
import { installFacebookConnectionSchema } from "./schema.js";
import { createFacebookConnection, connectionError } from "./service.js";
export const FACEBOOK_CONNECTION_BASE = "/api/integrations/facebook";
export async function installFacebookConnection({
  app,
  pool,
  authRequired,
  requireCapability,
  env = process.env,
  graph = new ConnectionGraph(env),
}) {
  await installFacebookConnectionSchema(pool);
  const service = createFacebookConnection({
    pool,
    env,
    graph,
    leads: app.locals.facebookLeads,
    ads: app.locals.facebookAds,
  });
  const base = FACEBOOK_CONNECTION_BASE,
    actor = (req) => ({ userId: req.userId, companyId: req.companyId });
  const wrap = (fn) => async (req, res) => {
    res.set({ "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" });
    try {
      await fn(req, res);
    } catch (e) {
      res
        .status(e.status || 503)
        .json({
          error: /^facebook_[a-z_]+$/.test(e.code || "")
            ? e.code
            : "facebook_connection_unavailable",
          message: e.status
            ? e.message
            : "Facebook connection could not be updated. Refresh status and try again.",
        });
    }
  };
  const route = (method, path, fn) =>
    app[method](
      base + path,
      authRequired,
      requireCapability("integrations.manage"),
      wrap(async (req, res) => res.json(await fn(req))),
    );
  route("get", "", (req) => service.status(actor(req)));
  route("post", "/oauth/start", (req) =>
    service.start(req, { client: req.body?.client }),
  );
  route("post", "/refresh", (req) => service.refresh(actor(req)));
  route("put", "/controls", (req) => service.controls(actor(req), req.body));
  route("post", "/disconnect", (req) => service.disconnect(actor(req)));
  async function callback(req, res, { allowMissing = false } = {}) {
    const state = typeof req.query.state === "string" ? req.query.state : "";
    const identity = (
      await pool.query(
        "DELETE FROM facebook_connection_oauth_states WHERE state_hash=$1 AND expires_at>now() RETURNING *",
        [hash(state)],
      )
    ).rows[0];
    if (!identity) {
      if (allowMissing) return false;
      throw connectionError("facebook_oauth_state_expired_or_used", 400);
    }
    let result = "attention";
    try {
      if (
        identity.app_id !== connectionConfiguration(env).app_id ||
        identity.redirect_uri !== connectionConfiguration(env).redirect_uri
      )
        throw connectionError("facebook_oauth_configuration_changed");
      const sessions = (
        await pool.query("SELECT token FROM sessions WHERE user_id=$1", [
          identity.user_id,
        ])
      ).rows;
      const session = sessions.find((s) =>
        secureEqual(hash(s.token), identity.session_hash),
      );
      if (!session) throw connectionError("facebook_oauth_session_ended", 403);
      const probe = {
        headers: { authorization: `Bearer ${session.token}` },
        header: () => `Bearer ${session.token}`,
        method: "GET",
        path: base,
      };
      let allowed = false;
      const response = {
        status() {
          return this;
        },
        json() {
          return this;
        },
      };
      await authRequired(probe, response, () => {
        allowed = true;
      });
      if (
        !allowed ||
        probe.companyId !== identity.company_id ||
        probe.userId !== identity.user_id
      )
        throw connectionError("facebook_oauth_access_changed", 403);
      await service.authorize(actor(probe), true);
      if (req.query.error || typeof req.query.code !== "string")
        throw connectionError("facebook_authorization_declined", 400);
      const token = await graph.exchange(req.query.code),
        me = await graph.request("me", token, { fields: "id" });
      const debug = await graph.request(
        "debug_token",
        `${env.FACEBOOK_LEADS_APP_ID}|${env.FACEBOOK_LEADS_APP_SECRET}`,
        { input_token: token },
      );
      if (
        !debug.data?.is_valid ||
        String(debug.data.app_id) !== env.FACEBOOK_LEADS_APP_ID ||
        String(debug.data.user_id) !== String(me.id) ||
        debug.data.type !== "USER"
      )
        throw connectionError("facebook_user_token_required", 403);
      const permissions = (await graph.all("me/permissions", token))
        .filter((p) => p.status === "granted")
        .map((p) => p.permission);
      const expiry = [debug.data.expires_at, debug.data.data_access_expires_at]
        .map(Number)
        .filter((n) => n > 0);
      const expiresAt = expiry.length
        ? new Date(Math.min(...expiry) * 1000)
        : null;
      if (expiresAt && expiresAt <= new Date())
        throw connectionError("facebook_reauthorize_required");
      await service.accept(actor(probe), {
        token,
        metaUserId: String(me.id),
        permissions,
        expiresAt,
      });
      await service.refresh(actor(probe));
      result = "connected";
    } catch (e) {
      // Failed/canceled reconnect never discards a prior valid authorization or its saved settings.
      await pool.query(
        "UPDATE facebook_connections SET error_code=$2,updated_at=now() WHERE company_id=$1",
        [
          identity.company_id,
          /^facebook_[a-z_]+$/.test(e.code || "")
            ? e.code
            : "facebook_connection_unavailable",
        ],
      );
    }
    if (identity.client === "web") {
      if (env.FACEBOOK_LEADS_WEB_RETURN_URL) {
        const u = new URL(env.FACEBOOK_LEADS_WEB_RETURN_URL);
        if (u.protocol !== "https:")
          throw connectionError("facebook_web_return_url_invalid", 503);
        u.searchParams.set("facebook_status", result);
        res.redirect(String(u));
      } else
        res
          .type("html")
          .send(
            "<!doctype html><html><title>Facebook connection</title><h1>Return to WolfCRM</h1><p>Close this window and refresh Facebook connection settings to review access for Leads and Ads.</p></html>",
          );
    } else
      res.redirect(
        `wolfcrm://${identity.destination === "leads" ? "facebook-leads" : identity.destination === "ads" ? "facebook-ads" : "facebook"}?status=${result}`,
      );
    return true;
  }
  service.callback = callback;
  app.locals.facebookConnection = service;
  app.get(
    base + "/oauth/callback",
    wrap((req, res) => callback(req, res)),
  );
  for (const action of ["deauthorize", "data-deletion"])
    app.post(
      base + "/" + action,
      wrap(async (req, res) => {
        const data = signedRequest(
          req.body?.signed_request,
          env.FACEBOOK_LEADS_APP_SECRET,
        );
        await service.revoke(String(data.user_id), env.FACEBOOK_LEADS_APP_ID, {
          deletion: action === "data-deletion",
        });
        if (action === "deauthorize") return res.json({ ok: true });
        const code = randomBytes(24).toString("hex");
        await pool.query(
          "INSERT INTO facebook_connection_deletions(code) VALUES($1)",
          [code],
        );
        res.json({
          url: new URL(
            base + "/deletion-status/" + code,
            connectionConfiguration(env).redirect_uri,
          ).href,
          confirmation_code: code,
        });
      }),
    );
  app.get(
    base + "/deletion-status/:code",
    wrap(async (req, res) => {
      if (
        !(
          await pool.query(
            "SELECT code FROM facebook_connection_deletions WHERE code=$1",
            [req.params.code],
          )
        ).rowCount
      )
        throw connectionError("facebook_deletion_request_not_found", 404);
      res
        .type("text")
        .send(
          "Facebook authorization identity, credentials and lead-integration personal data were deleted. Company-owned imported contact records and advertising action audit records are retained by the CRM company; contact that company for business-record deletion requests.",
        );
    }),
  );
  return service;
}
