import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID, createHmac } from "node:crypto";
import { startLocalPostgres } from "./helpers/local-postgres.js";
import {
  installAutomationSystem,
  emitAutomationEvent,
} from "../automations.js";
import { installFacebookLeads } from "../facebook-leads/index.js";
import { installFacebookAds } from "../facebook-ads/index.js";
import {
  installFacebookConnection,
  FACEBOOK_CONNECTION_BASE as base,
} from "../facebook-connection/index.js";
import { installFacebookConnectionSchema } from "../facebook-connection/schema.js";
import {
  ConnectionGraph,
  COMBINED_PERMISSIONS,
} from "../facebook-connection/provider.js";
import {
  invalidateSharedAuthorization,
  syncSharedPermissions,
} from "../facebook-connection/state.js";
import { encrypt, decrypt } from "../facebook-leads/provider.js";
import { FacebookLeadError } from "../facebook-leads/domain.js";
test(
  "shared Facebook auth with canonical services and disposable PostgreSQL",
  { timeout: 120000 },
  async (t) => {
    const pg = startLocalPostgres();
    pg.configureEnvironment();
    let pool, server;
    try {
      const backend = await import("../index.js");
      pool = backend.rawPool;
      await backend.bootstrap();
      await installAutomationSystem({
        ...backend,
        pool,
        requireEmployer: backend.requireCapability("automations.manage"),
        disableProcessors: true,
      });
      const company = randomUUID(),
        owner = randomUUID(),
        other = randomUUID(),
        otherOwner = randomUUID(),
        employee = randomUUID();
      for (const [c, u] of [
        [company, owner],
        [other, otherOwner],
      ]) {
        await pool.query(
          "INSERT INTO companies(id,name,join_code,owner_user_id) VALUES($1,$2,$3,$4)",
          [c, "Facebook fixture", c, u],
        );
        await pool.query(
          "INSERT INTO users(id,email,role,company_id) VALUES($1,$2,'employer',$3)",
          [u, u + "@example.invalid", c],
        );
        await pool.query("INSERT INTO sessions(token,user_id) VALUES($1,$2)", [
          u,
          u,
        ]);
      }
      await pool.query(
        "INSERT INTO users(id,email,role,company_id) VALUES($1,$2,'employee',$3)",
        [employee, employee + "@example.invalid", company],
      );
      await pool.query("INSERT INTO sessions(token,user_id) VALUES($1,$2)", [
        employee,
        employee,
      ]);
      const env = {
        FACEBOOK_LEADS_APP_ID: "999",
        FACEBOOK_LEADS_APP_SECRET: "fixture-secret",
        FACEBOOK_LEADS_LOGIN_CONFIG_ID: "123",
        FACEBOOK_LEADS_REDIRECT_URI:
          "https://example.invalid/api/integrations/facebook-leads/oauth/callback",
        FACEBOOK_LEADS_VERIFY_TOKEN: "fixture-verify",
        FACEBOOK_LEADS_ENCRYPTION_KEY: Buffer.alloc(32, 3).toString("base64"),
        FACEBOOK_LEADS_WORKER_ENABLED: "true",
        FACEBOOK_ADS_ENABLED: "true",
      };
      let permissions = [...COMBINED_PERMISSIONS],
        debugApp = "999",
        failPermissions = false,
        leadFetches = 0;
      const metaId = "1000",
        graph = new ConnectionGraph(env);
      graph.exchange = async () => "fixture-user-token";
      graph.request = async (path) => {
        if (path === "debug_token")
          return {
            data: {
              is_valid: true,
              app_id: debugApp,
              user_id: metaId,
              type: "USER",
              expires_at: Math.floor(Date.now() / 1000) + 3600,
            },
          };
        if (path === "me") return { id: metaId };
        if (path === "act_10")
          return {
            account_id: "10",
            name: "Ads fixture",
            currency: "USD",
            timezone_name: "America/New_York",
            user_tasks: ["MANAGE"],
            account_status: 1,
          };
        if (path === "101")
          return {
            id: "101",
            account_id: "10",
            name: "Campaign",
            status: "PAUSED",
            effective_status: "PAUSED",
            daily_budget: "2500",
          };
        return { success: true };
      };
      graph.all = async (path, token) => {
        if (path === "me/permissions") {
          if (failPermissions)
            throw new FacebookLeadError(
              "facebook_token_expired_reconnect",
              409,
            );
          return permissions.map((permission) => ({
            permission,
            status: "granted",
          }));
        }
        if (path === "me/accounts") {
          assert.equal(token, "fixture-user-token");
          return [
            {
              id: "20",
              name: "Page fixture",
              access_token: "fixture-page-token",
            },
          ];
        }
        if (path === "me/adaccounts") {
          assert.equal(token, "fixture-user-token");
          return [await graph.request("act_10")];
        }
        if (path === "20/subscribed_apps") {
          assert.equal(token, "fixture-page-token");
          return [{ id: "999", subscribed_fields: ["leadgen"] }];
        }
        if (path === "20/leadgen_forms")
          return [
            {
              id: "30",
              name: "Form fixture",
              questions: [{ key: "full_name", label: "Full name" }],
            },
          ];
        throw Error("unexpected fixture path");
      };
      graph.page = async () => ({ data: [], cursor: null });
      graph.lead = async (id) => {
        leadFetches++;
        return {
          lead: {
            id,
            form_id: "30",
            created_time: new Date().toISOString(),
            field_data: [{ name: "full_name", values: ["Fixture contact"] }],
          },
          issues: [],
        };
      };
      graph.leads = async () => ({ data: [], cursor: null });
      backend.app.locals.facebookLeads = await installFacebookLeads({
        ...backend,
        pool,
        env,
        graph,
        startWorker: false,
        emitAutomationEvent,
        markContactDirty: async () => {},
        sendPushToUsers: async () => {},
      });
      await installFacebookAds({
        ...backend,
        pool,
        env,
        graph,
        emitAutomationEvent,
      });
      await installFacebookConnection({ ...backend, pool, env, graph });
      await installFacebookConnectionSchema(pool);
      server = await new Promise((resolve) => {
        const s = backend.app.listen(0, "127.0.0.1", () => resolve(s));
      });
      const origin = "http://127.0.0.1:" + server.address().port;
      async function request(path, body, method = "GET", user = owner) {
        const r = await fetch(origin + path, {
          method,
          headers: {
            authorization: "Bearer " + user,
            "content-type": "application/json",
          },
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
          redirect: "manual",
        });
        const raw = await r.text();
        let data;
        try {
          data = JSON.parse(raw);
        } catch {
          data = raw;
        }
        return {
          status: r.status,
          body: data,
          location: r.headers.get("location"),
        };
      }
      async function login(startPath = base + "/oauth/start") {
        const start = await request(startPath, {}, "POST");
        assert.equal(start.status, 200, JSON.stringify(start.body));
        const state = new URL(start.body.url).searchParams.get("state"),
          result = await request(
            "/api/integrations/facebook-leads/oauth/callback?state=" +
              state +
              "&code=fixture",
          );
        assert.equal(result.status, 302, JSON.stringify(result.body));
        return { state, result };
      }
      await t.test(
        "company/role authorization, app validation, replay rejection and distinct encrypted credentials",
        async () => {
          assert.equal(
            (await request(base + "/oauth/start", {}, "POST", employee)).status,
            403,
          );
          const absentControls = await request(
            base + "/controls",
            { lead_importing_paused: true },
            "PUT",
            otherOwner,
          );
          assert.equal(absentControls.status, 409);
          assert.equal(absentControls.body.error, "facebook_connect_first");
          debugApp = "wrong";
          await login();
          assert.equal(
            (await pool.query("SELECT * FROM facebook_connections")).rowCount,
            0,
          );
          debugApp = "999";
          const { state, result } = await login();
          assert.match(result.location, /status=connected/);
          assert.equal(
            (
              await request(
                "/api/integrations/facebook-leads/oauth/callback?state=" +
                  state +
                  "&code=fixture",
              )
            ).status,
            400,
          );
          for (const [table, scope] of [
            ["facebook_lead_connections", company],
            ["facebook_ads_connections", "ads:" + company],
            ["facebook_connections", "facebook:" + company],
          ]) {
            const c = (
              await pool.query(
                "SELECT token FROM " + table + " WHERE company_id=$1",
                [company],
              )
            ).rows[0];
            assert.equal(decrypt(c.token, scope, env), "fixture-user-token");
          }
          const status = (await request(base)).body;
          assert.equal(status.connection.unified, true);
          assert(!JSON.stringify(status).includes("fixture-user-token"));
          assert.equal(
            (await request(base, undefined, "GET", otherOwner)).body.accounts
              .length,
            0,
          );
        },
      );
      await t.test(
        "partial Ads-only reconnect preserves settings, saved views and selections",
        async () => {
          assert.equal(
            (
              await request(
                "/api/integrations/facebook-leads/pages/20/select",
                {},
                "POST",
              )
            ).status,
            200,
          );
          await pool.query(
            "UPDATE facebook_lead_forms SET enabled=true,routed=true WHERE company_id=$1",
            [company],
          );
          await pool.query(
            "UPDATE facebook_lead_settings SET configuration=configuration||'{\"overwrite\":true}' WHERE company_id=$1",
            [company],
          );
          const selected = await request(
            "/api/facebook-ads/accounts",
            { account_ids: ["10"] },
            "POST",
          );
          assert.equal(selected.status, 200, JSON.stringify(selected.body));
          await pool.query(
            "INSERT INTO facebook_ads_views(id,company_id,user_id,name,config) VALUES($1,$2,$3,'Preserved view','{}')",
            [randomUUID(), company, owner],
          );
          permissions = ["ads_read"];
          await login("/api/facebook-ads/oauth/start");
          const status = (await request(base)).body;
          assert.equal(
            status.readiness.find((x) => x.key === "ads_reporting").ready,
            true,
          );
          assert.equal(
            status.readiness.find((x) => x.key === "ads_editing").ready,
            false,
          );
          assert(
            status.readiness
              .find((x) => x.key === "ads_editing")
              .missing_permissions.includes("ads_management"),
          );
          assert.equal(status.pages[0].selected, true);
          assert.equal(status.forms[0].enabled, true);
          assert.equal(status.accounts[0].selected, true);
          assert.equal(
            (
              await pool.query(
                "SELECT configuration FROM facebook_lead_settings WHERE company_id=$1",
                [company],
              )
            ).rows[0].configuration.overwrite,
            true,
          );
          assert.equal(
            (
              await pool.query(
                "SELECT * FROM facebook_ads_views WHERE company_id=$1",
                [company],
              )
            ).rowCount,
            1,
          );
          assert.equal(
            (await request("/api/facebook-ads/accounts/10/campaign/101"))
              .status,
            200,
          );
          permissions = [...COMBINED_PERMISSIONS];
          assert.equal(
            (await request(base + "/refresh", {}, "POST")).status,
            200,
          );
        },
      );
      await t.test(
        "independent pause/disable holds pending work without losing credentials or duplicating imports",
        async () => {
          const store = backend.app.locals.facebookLeads.store;
          await store.enqueue(pool, company, "20", "30", "301");
          assert.equal(
            (
              await request(
                base + "/controls",
                { lead_importing_paused: true },
                "PUT",
              )
            ).status,
            200,
          );
          await backend.app.locals.facebookLeads.worker.tick();
          assert.equal(leadFetches, 0);
          assert.equal(
            (
              await pool.query(
                "SELECT status FROM facebook_lead_jobs WHERE lead_id='301'",
              )
            ).rows[0].status,
            "pending",
          );
          assert.equal(
            (await request("/api/facebook-ads/accounts/10/campaign/101"))
              .status,
            200,
          );
          await request(
            base + "/controls",
            { ads_operations_enabled: false },
            "PUT",
          );
          assert.equal(
            (await request("/api/facebook-ads/accounts/10/campaign/101"))
              .status,
            409,
          );
          assert.equal(
            (await request(base)).body.connection.status,
            "connected",
          );
          await request(
            base + "/controls",
            { lead_importing_paused: false, ads_operations_enabled: true },
            "PUT",
          );
          await backend.app.locals.facebookLeads.worker.tick();
          assert.equal(leadFetches, 1);
          await store.enqueue(pool, company, "20", "30", "301");
          await backend.app.locals.facebookLeads.worker.tick();
          assert.equal(leadFetches, 1);
          assert.equal(
            (
              await pool.query(
                "SELECT * FROM contacts WHERE company_id=$1 AND external_lead_id='301'",
                [company],
              )
            ).rowCount,
            1,
          );
        },
      );
      await t.test(
        "expiration is shared; reconnect preserves selected assets",
        async () => {
          failPermissions = true;
          assert.notEqual(
            (await request(base + "/refresh", {}, "POST")).status,
            200,
          );
          for (const table of [
            "facebook_connections",
            "facebook_lead_connections",
            "facebook_ads_connections",
          ])
            assert.equal(
              (
                await pool.query(
                  "SELECT status FROM " + table + " WHERE company_id=$1",
                  [company],
                )
              ).rows[0].status,
              "attention",
            );
          assert.equal(
            (await request("/api/facebook-ads/accounts/10/campaign/101"))
              .status,
            409,
          );
          failPermissions = false;
          await login();
          assert.equal((await request(base)).body.accounts[0].selected, true);
        },
      );
      await t.test(
        "legacy deauthorization callback revokes both and preserves configuration/history",
        async () => {
          const payload = Buffer.from(
              JSON.stringify({ algorithm: "HMAC-SHA256", user_id: metaId }),
            ).toString("base64url"),
            sig = createHmac("sha256", env.FACEBOOK_LEADS_APP_SECRET)
              .update(payload)
              .digest("base64url");
          assert.equal(
            (
              await request(
                "/api/integrations/facebook-leads/deauthorize",
                { signed_request: sig + "." + payload },
                "POST",
              )
            ).status,
            200,
          );
          const status = (await request(base)).body;
          assert.equal(status.connection.status, "revoked");
          assert.equal(status.forms[0].enabled, true);
          assert.equal(status.pages[0].selected, true);
          assert.equal(status.accounts[0].selected, true);
          for (const table of [
            "facebook_connections",
            "facebook_lead_connections",
            "facebook_ads_connections",
          ])
            assert.equal(
              (
                await pool.query(
                  "SELECT token FROM " + table + " WHERE company_id=$1",
                  [company],
                )
              ).rows[0].token,
              null,
            );
          assert.equal(
            (
              await pool.query(
                "SELECT * FROM facebook_lead_jobs WHERE company_id=$1",
                [company],
              )
            ).rowCount,
            1,
          );
          await login("/api/integrations/facebook-leads/oauth/start");
          assert.equal(
            (await request(base)).body.connection.status,
            "connected",
          );
        },
      );
      await t.test(
        "ended session and declined reconnect do not replace existing credentials",
        async () => {
          const start = await request(base + "/oauth/start", {}, "POST"),
            state = new URL(start.body.url).searchParams.get("state");
          await pool.query("DELETE FROM sessions WHERE user_id=$1", [owner]);
          await request(
            "/api/integrations/facebook-leads/oauth/callback?state=" +
              state +
              "&code=fixture",
          );
          await pool.query(
            "INSERT INTO sessions(token,user_id) VALUES($1,$2)",
            [owner, owner],
          );
          assert.equal(
            (await request(base)).body.connection.status,
            "connected",
          );
          const second = await request(base + "/oauth/start", {}, "POST"),
            s = new URL(second.body.url).searchParams.get("state");
          await request(
            "/api/integrations/facebook-leads/oauth/callback?state=" +
              s +
              "&error=access_denied",
          );
          assert.equal(
            (await request("/api/facebook-ads/accounts/10/campaign/101"))
              .status,
            200,
          );
        },
      );
      await t.test(
        "late responses from an old credential cannot overwrite a fresh reconnect",
        async () => {
          const previous = (
            await pool.query(
              "SELECT token FROM facebook_lead_connections WHERE company_id=$1",
              [company],
            )
          ).rows[0].token;
          await login();
          await invalidateSharedAuthorization(
            pool,
            company,
            "facebook_token_expired_reconnect",
            "leads",
            previous,
          );
          await syncSharedPermissions(pool, company, [], "leads", previous);
          const current = (await request(base)).body;
          assert.equal(current.connection.status, "connected");
          assert(current.connection.permissions.includes("ads_management"));
        },
      );
      await t.test(
        "provider pagination expiry also invalidates both modules",
        async () => {
          const page = graph.page;
          graph.page = async () => {
            throw new FacebookLeadError(
              "facebook_token_expired_reconnect",
              409,
            );
          };
          const response = await request(
            "/api/facebook-ads/entities",
            { account_id: "10", level: "campaign" },
            "POST",
          );
          assert.equal(response.status, 409);
          assert.equal(
            (await request(base)).body.connection.status,
            "attention",
          );
          graph.page = page;
          await login();
        },
      );
      await t.test(
        "lead worker expiry invalidates the shared authorization and records Page failure",
        async () => {
          const leads = backend.app.locals.facebookLeads;
          await leads.store.enqueue(pool, company, "20", "30", "302");
          const original = graph.lead;
          graph.lead = async () => {
            throw new FacebookLeadError(
              "facebook_token_expired_reconnect",
              409,
            );
          };
          try {
            await leads.worker.tick();
          } finally {
            graph.lead = original;
          }
          assert.equal(
            (await request(base)).body.connection.status,
            "attention",
          );
          assert.equal(
            (
              await pool.query(
                "SELECT retrieval FROM facebook_lead_pages WHERE company_id=$1 AND page_id='20'",
                [company],
              )
            ).rows[0].retrieval,
            "unavailable",
          );
          assert.equal(
            (
              await pool.query(
                "SELECT status FROM facebook_ads_connections WHERE company_id=$1",
                [company],
              )
            ).rows[0].status,
            "attention",
          );
          await login();
        },
      );
      await t.test(
        "canonical revocation supports legacy credentials and data deletion preserves company contacts",
        async () => {
          await pool.query(
            "INSERT INTO facebook_lead_connections(company_id,user_id,meta_user_id,token,permissions,status) VALUES($1,$2,$3,$4,'[]','authorized')",
            [other, otherOwner, metaId, encrypt("legacy-user", other, env)],
          );
          const payload = Buffer.from(
              JSON.stringify({ algorithm: "HMAC-SHA256", user_id: metaId }),
            ).toString("base64url"),
            sig = createHmac("sha256", env.FACEBOOK_LEADS_APP_SECRET)
              .update(payload)
              .digest("base64url");
          assert.equal(
            (
              await request(
                base + "/deauthorize",
                { signed_request: sig + "." + payload },
                "POST",
              )
            ).status,
            200,
          );
          assert.equal(
            (
              await pool.query(
                "SELECT token FROM facebook_lead_connections WHERE company_id=$1",
                [other],
              )
            ).rows[0].token,
            null,
          );
          const deleted = await request(
            base + "/data-deletion",
            { signed_request: sig + "." + payload },
            "POST",
          );
          assert.equal(deleted.status, 200);
          assert.match(deleted.body.url, /deletion-status/);
          assert.equal(
            (
              await pool.query(
                "SELECT * FROM facebook_lead_jobs WHERE company_id=$1",
                [company],
              )
            ).rowCount,
            0,
          );
          assert.equal(
            (
              await pool.query(
                "SELECT * FROM contacts WHERE company_id=$1 AND external_lead_id='301'",
                [company],
              )
            ).rowCount,
            1,
          );
        },
      );
    } finally {
      if (server) await new Promise((r) => server.close(r));
      if (pool) await pool.end();
      pg.stop();
    }
  },
);
