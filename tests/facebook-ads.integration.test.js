import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, randomUUID } from "node:crypto";
import {
  Client,
  StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";
import { installMCP } from "../mcp/index.js";
import { startLocalPostgres } from "./helpers/local-postgres.js";
import {
  installAutomationSystem,
  emitAutomationEvent,
  automationTestHooks,
  webhookEventCatalog,
} from "../automations.js";
import { installFacebookAds } from "../facebook-ads/index.js";
import { createAdsService } from "../facebook-ads/service.js";
import { installAdsSchema } from "../facebook-ads/schema.js";
import { installFacebookLeadSchema } from "../facebook-leads/schema.js";
import { encrypt } from "../facebook-leads/provider.js";
import { AdsGraph } from "../facebook-ads/provider.js";
import { evaluateAdsTriggers } from "../facebook-ads/automation.js";
import {installWebhooks} from '../webhooks/service.js';
import {configSchema as webhookConfigSchema} from '../webhooks/domain.js';
import {projectAdsWebhookEvent} from '../facebook-ads/webhook-events.js';
test(
  "Ads real PostgreSQL, auth/OAuth, reports, durable changes and automation events",
  { timeout: 120000 },
  async (t) => {
    const pg = startLocalPostgres();
    pg.configureEnvironment();
    let pool, server;
    try {
      const backend = await import("../index.js");
      pool = backend.rawPool;
      await backend.bootstrap();
      await installFacebookLeadSchema(pool);
      await installAutomationSystem({
        ...backend,
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
          [c, "Ads fixture", c, u],
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
        FACEBOOK_ADS_ENABLED: "true",
        FACEBOOK_ADS_WORKER_ENABLED: "true",
        FACEBOOK_LEADS_ENCRYPTION_KEY: Buffer.alloc(32, 8).toString("base64"),
        FACEBOOK_LEADS_APP_ID: "9",
        FACEBOOK_LEADS_APP_SECRET: "fixture",
        FACEBOOK_ADS_REDIRECT_URI:
          "https://example.invalid/api/facebook-ads/oauth/callback",
      };
      let roleTasks = ["MANAGE"];
      let grantedPermissions = ["ads_read", "ads_management"];
      let writes = 0,
        timeout = false,
        reportCalls = 0;
      const entity = {
        id: "101",
        name: "Fixture campaign",
        account_id: "10",
        status: "PAUSED",
        effective_status: "PAUSED",
        daily_budget: "1000",
      };
      const graph = new AdsGraph(env);
      graph.exchange = async () => "fixture-token";
      graph.all = async (path) =>
        path === "me/permissions"
          ? grantedPermissions.map((permission) => ({
              permission,
              status: "granted",
            }))
          : [
              {
                account_id: "10",
                name: "Fixture account",
                currency: "USD",
                timezone_name: "America/New_York",
                account_status: 1,
                min_daily_budget: "100",
                user_tasks: roleTasks,
              },
            ];
      graph.request = async (path, token, params = {}, method = "GET") => {
        if (path === "debug_token")
          return {
            data: {
              is_valid: true,
              app_id: "9",
              user_id: "100",
              type: "USER",
              expires_at: 0,
            },
          };
        if (path === "me") return { id: "100" };
        if (path === "act_10")
          return {
            account_id: "10",
            name: "Fixture account",
            currency: "USD",
            timezone_name: "America/New_York",
            account_status: 1,
            min_daily_budget: "100",
            user_tasks: roleTasks,
          };
        if (path === "act_10/insights" && method === "POST")
          return { report_run_id: "900" };
        if (path === "900")
          return {
            async_status: "Job Completed",
            async_percent_completion: 100,
          };
        if (path === "101" && method === "POST") {
          if (params.execution_options) return { success: true };
          writes++;
          Object.assign(entity, params);
          if (timeout)
            throw Object.assign(new Error("uncertain"), {
              code: "facebook_network_uncertain",
              status: 502,
            });
          return { success: true };
        }
        if (path === "101") return { ...entity };
        if (path === "202") return { ...entity, id: "202", account_id: "20" };
        throw new Error("unexpected fixture path " + path);
      };
      graph.page = async (path) => {
        if (path.endsWith("/insights")) {
          reportCalls++;
          return {
            data: [
              {
                account_id: "10",
                campaign_id: "101",
                campaign_name: "Fixture campaign",
                date_start: "2026-10-01",
                date_stop: "2026-10-01",
                spend: "25.00",
                impressions: "500",
                actions: [{ action_type: "lead", value: "0" }],
              },
            ],
            cursor: null,
          };
        }
        return { data: [{ ...entity }], cursor: null };
      };
      const service = await installFacebookAds({
        ...backend,
        pool,
        env,
        graph,
        emitAutomationEvent,
      });
      await installAdsSchema(pool);
      server = backend.app.listen(0, "127.0.0.1");
      await new Promise((r) => server.once("listening", r));
      const base = "http://127.0.0.1:" + server.address().port;
      const http = async (
        path,
        { user = owner, body, method = body ? "POST" : "GET" } = {},
      ) => {
        const r = await fetch(base + "/api/facebook-ads" + path, {
          method,
          headers: {
            authorization: "Bearer " + user,
            "Content-Type": "application/json",
          },
          body: body ? JSON.stringify(body) : undefined,
          redirect: "manual",
        });
        return {
          status: r.status,
          body: r.headers.get("content-type")?.includes("json")
            ? await r.json()
            : null,
          location: r.headers.get("location"),
        };
      };
      const actor = { userId: owner, companyId: company };
      await t.test(
        "OAuth single use, fixed callback, own-user token and safe DTO",
        async () => {
          const start = await http("/oauth/start", { body: {} });
          assert.equal(start.status, 200);
          const state = new URL(start.body.url).searchParams.get("state");
          const done = await http(
            "/oauth/callback?state=" + state + "&code=fixture",
          );
          assert.equal(
            done.location,
            "wolfcrm://facebook-ads?status=connected",
          );
          assert.equal(
            (await http("/oauth/callback?state=" + state + "&code=x")).status,
            400,
          );
          const status = await http("");
          assert.equal(status.body.connection.status, "connected");
          assert.ok(!JSON.stringify(status.body).includes("fixture-token"));
          assert.equal((await http("", { user: employee })).status, 403);
        },
      );
      assert.equal(
        (await http("/accounts", { body: { account_ids: ["10"] } })).status,
        200,
      );
      await t.test(
        "company, provider-object and saved view isolation",
        async () => {
          assert.equal(
            (await http("/accounts/10/campaign/101", { user: otherOwner }))
              .status,
            409,
          );
          assert.equal((await http("/accounts/10/campaign/202")).status, 404);
          const v = await http("/views", {
            body: {
              name: "Leads",
              config: { account_id: "10", metrics: ["spend"] },
            },
          });
          assert.equal(v.status, 200);
          assert.equal(
            (await http("/views", { user: otherOwner })).body.items.length,
            0,
          );
          assert.equal(
            (
              await http("/views", {
                body: {
                  id: v.body.items[0].id,
                  revision: 999,
                  name: "Old",
                  config: { account_id: "10", metrics: ["spend"] },
                },
              })
            ).status,
            409,
          );
        },
      );
      await t.test(
        "coalescing, selected fields, asynchronous jobs and cancel",
        async () => {
          const config = {
            account_id: "10",
            metrics: ["spend", "actions:lead"],
            level: "campaign",
          };
          const reports = await Promise.all([
            service.insights(actor, config),
            service.insights(actor, config),
          ]);
          assert.equal(reportCalls, 1);
          assert.equal(reports[0].items[0].values["actions:lead"], "0");
          const job = await service.startReport(actor, config);
          assert.equal(
            (await service.pollReport(actor, job.id)).status,
            "completed",
          );
          await assert.rejects(
            () =>
              service.pollReport(
                { userId: otherOwner, companyId: other },
                job.id,
              ),
            (e) => e.code === "report_not_found",
          );
          await service.cancelReport(actor, job.id);
          assert.equal(
            (await service.pollReport(actor, job.id)).status,
            "canceled",
          );
        },
      );
      await t.test("relative report cache expires across account-local midnight", async (t) => {
        t.mock.timers.enable({apis: ["Date"], now: new Date("2026-10-03T03:59:50Z")});
        try {
          const config = {account_id: "10", level: "campaign", metrics: ["spend"], period: {preset: "today"}};
          const before = await service.insights(actor, config);
          t.mock.timers.tick(20000);
          const after = await service.insights(actor, config);
          assert.equal(before.period.since, "2026-10-02");
          assert.equal(after.period.since, "2026-10-03");
        } finally {t.mock.timers.reset();}
      });
      await t.test(
        "concurrent percentage retries, stale state and timeout reconciliation",
        async () => {
          let item = (await service.entity(actor, "10", "campaign", "101"))
            .item;
          const input = {
            request_id: randomUUID(),
            account_id: "10",
            level: "campaign",
            entity_id: "101",
            expected_version: item.version,
            change: {
              kind: "budget",
              budget_type: "daily_budget",
              mode: "percent",
              value: "10",
            },
          };
          const result = await Promise.all(
            Array.from({ length: 12 }, () => service.mutate(actor, input)),
          );
          assert.ok(result.every((r) => r.status === "confirmed"));
          assert.equal(entity.daily_budget, "1100");
          assert.equal(writes, 1);
          const restarted = createAdsService({
            pool,
            graph,
            env,
            emitAutomationEvent,
          });
          assert.equal(
            (await restarted.mutate(actor, input)).status,
            "confirmed",
          );
          assert.equal(writes, 1);
          await assert.rejects(
            () => service.mutate(actor, { ...input, request_id: randomUUID() }),
            (e) => e.code === "entity_changed_reload",
          );
          await assert.rejects(
            () =>
              service.mutate(actor, {
                ...input,
                change: { kind: "status", value: "ACTIVE" },
              }),
            (e) => e.code === "idempotency_conflict",
          );
          item = (await service.entity(actor, "10", "campaign", "101")).item;
          const uncertain = {
            ...input,
            request_id: randomUUID(),
            expected_version: item.version,
            change: { kind: "status", value: "ACTIVE" },
          };
          timeout = true;
          assert.equal(
            (await service.mutate(actor, uncertain)).status,
            "uncertain",
          );
          timeout = false;
          assert.equal(
            (await service.mutate(actor, uncertain)).status,
            "confirmed",
          );
          assert.equal(writes, 2);
        },
      );
      await t.test(
        "draft rules do not evaluate; published exact-trigger events deduplicate workers",
        async () => {
          const aid = randomUUID(),
            vid = randomUUID(),
            nid = randomUUID();
          await pool.query(
            "INSERT INTO automation_definitions(id,company_id,name,status,created_by_user_id) VALUES($1,$2,'Ads rule','draft',$3)",
            [aid, company, owner],
          );
          await pool.query(
            "INSERT INTO automation_versions(id,company_id,automation_id,version_number,status,created_by_user_id) VALUES($1,$2,$3,1,'draft',$4)",
            [vid, company, aid, owner],
          );
          await pool.query(
            "INSERT INTO automation_nodes(id,company_id,version_id,node_key,node_type,title,config) VALUES($1,$2,$3,'trigger','trigger','Metric',$4)",
            [
              nid,
              company,
              vid,
              JSON.stringify({
                trigger_key: "facebook_ads.metric",
                ads: {
                  account_id: "10",
                  level: "campaign",
                  metric: "spend",
                  operator: "gte",
                  threshold: "20",
                  conditions: [
                    { metric: "actions:lead", operator: "lt", threshold: "1" },
                  ],
                },
              }),
            ],
          );
          await evaluateAdsTriggers({
            pool,
            service,
            emitAutomationEvent,
            env,
          });
          assert.equal(
            (await pool.query("SELECT * FROM facebook_ads_evaluations"))
              .rowCount,
            0,
          );
          await pool.query(
            "UPDATE automation_definitions SET status='published',active_version_id=$2 WHERE id=$1",
            [aid, vid],
          );
          await pool.query(
            "UPDATE automation_versions SET status='published' WHERE id=$1",
            [vid],
          );
          await pool.query(
            "UPDATE companies SET automations_enabled=false WHERE id=$1",
            [company],
          );
          await evaluateAdsTriggers({
            pool,
            service,
            emitAutomationEvent,
            env,
          });
          assert.equal(
            (await pool.query("SELECT * FROM facebook_ads_evaluations"))
              .rowCount,
            0,
          );
          await pool.query(
            "UPDATE companies SET automations_enabled=true WHERE id=$1",
            [company],
          );
          await Promise.all([
            evaluateAdsTriggers({ pool, service, emitAutomationEvent, env }),
            evaluateAdsTriggers({ pool, service, emitAutomationEvent, env }),
          ]);
          const events = (
            await pool.query(
              "SELECT * FROM automation_events WHERE event_type='facebook_ads.metric'",
            )
          ).rows;
          assert.equal(events.length, 1);
          assert.equal(events[0].payload.trigger_node_id, nid);
          const actionId = randomUUID();
          await pool.query(
            "INSERT INTO automation_nodes(id,company_id,version_id,node_key,node_type,title,config) VALUES($1,$2,$3,'pause','action','Pause ad',$4)",
            [
              actionId,
              company,
              vid,
              JSON.stringify({
                action_key: "facebook_ads.status",
                ads: { target: "matched", status: "PAUSED" },
              }),
            ],
          );
          await pool.query(
            "INSERT INTO automation_edges(id,company_id,version_id,source_node_id,target_node_id,source_port) VALUES($1,$2,$3,$4,$5,'default')",
            [randomUUID(), company, vid, nid, actionId],
          );
          const before = writes;
          await automationTestHooks.processAutomationEvents();
          assert.equal(entity.status, "PAUSED");
          assert.equal(writes, before + 1);
          await automationTestHooks.processAutomationEvents();
          assert.equal(writes, before + 1);
          assert.equal(
            (
              await pool.query(
                "SELECT status FROM facebook_ads_receipts WHERE source='automation'",
              )
            ).rows[0].status,
            "confirmed",
          );
        },
      );
      await t.test("bulk actions report each outcome and retain retry semantics", async () => {
        const item = (await service.entity(actor, "10", "campaign", "101")).item;
        const good = { request_id: randomUUID(), account_id: "10", level: "campaign", entity_id: "101", expected_version: item.version, change: {kind: "status", value: "ACTIVE"} };
        const foreign = {...good, request_id: randomUUID(), entity_id: "202"};
        const before = writes;
        const reply = await http("/bulk-actions", {body: {actions: [good, foreign]}});
        assert.equal(reply.status, 200);
        assert.equal(reply.body.items[0].receipt.status, "confirmed");
        assert.equal(reply.body.items[1].retryable, false);
        assert.ok(reply.body.items[1].error);
        assert.equal(writes, before + 1);
        await http("/bulk-actions", {body: {actions: [good, foreign]}});
        assert.equal(writes, before + 1);
      });
      await t.test(
        "OAuth decline/reconnect, ended session, current Meta role and revocation",
        async () => {
          const stateOf = async () =>
            new URL(
              (await http("/oauth/start", { body: {} })).body.url,
            ).searchParams.get("state");
          let state = await stateOf();
          assert.equal(
            (
              await http(
                "/oauth/callback?state=" + state + "&error=access_denied",
              )
            ).location,
            "wolfcrm://facebook-ads?status=attention",
          );
          assert.equal(
            (await service.status(actor)).connection.error_code,
            "facebook_authorization_declined",
          );
          state = await stateOf();
          await pool.query("DELETE FROM sessions WHERE user_id=$1", [owner]);
          await http("/oauth/callback?state=" + state + "&code=fixture");
          await pool.query(
            "INSERT INTO sessions(token,user_id) VALUES($1,$2)",
            [owner, owner],
          );
          assert.equal(
            (await service.status(actor)).connection.error_code,
            "oauth_session_ended",
          );
          state = await stateOf();
          await http("/oauth/callback?state=" + state + "&code=fixture");
          await service.select(actor, ["10"]);
          roleTasks = ["ANALYZE"];
          const item = (await service.entity(actor, "10", "campaign", "101"))
            .item;
          await assert.rejects(
            () =>
              service.mutate(actor, {
                request_id: randomUUID(),
                account_id: "10",
                level: "campaign",
                entity_id: "101",
                expected_version: item.version,
                change: { kind: "status", value: "PAUSED" },
              }),
            (e) => e.code === "facebook_ad_account_write_role_required",
          );
          roleTasks = ["MANAGE"];
          grantedPermissions = ["ads_read"];
          await service.refresh(actor);
          await assert.rejects(
            () => service.entity(actor, "10", "campaign", "101", true),
            (e) => e.code === "facebook_ads_permission_required",
          );
          grantedPermissions = ["ads_read", "ads_management"];
          await service.refresh(actor);
          const payload = Buffer.from(
            JSON.stringify({ algorithm: "HMAC-SHA256", user_id: "100" }),
          ).toString("base64url");
          const signature = createHmac("sha256", env.FACEBOOK_LEADS_APP_SECRET)
            .update(payload)
            .digest("base64url");
          env.FACEBOOK_ADS_ENABLED = "false";
          assert.equal(
            (
              await http("/deauthorize", {
                body: { signed_request: signature + "." + payload },
              })
            ).status,
            200,
          );
          env.FACEBOOK_ADS_ENABLED = "true";
          assert.equal(
            (await service.status(actor)).connection.status,
            "revoked",
          );
          state = await stateOf();
          await http("/oauth/callback?state=" + state + "&code=fixture");
          await service.select(actor, ["10"]);
        },
      );
      await t.test(
        "MCP Ads tools use configured policy, approval, hours and canonical automation drafts",
        async () => {
          await installMCP({
            ...backend,
            env: {
              ...env,
              MCP_ENABLED: "true",
              MCP_PUBLIC_ORIGIN: base,
              MCP_REDIRECT_URIS: '["https://client.example.invalid/callback"]',
              NODE_ENV: "test",
            },
            startMaintenance: false,
            verifyIdentity: async () => null,
          });
          const crm = async (path, method = "GET", body) => {
            const r = await fetch(base + path, {
              method,
              headers: {
                authorization: "Bearer " + owner,
                "Content-Type": "application/json",
              },
              body: body ? JSON.stringify(body) : undefined,
            });
            return { status: r.status, body: await r.json() };
          };
          const manager = "/api/ai-connections/manager";
          let row = (
            await crm(manager, "POST", {
              expected_company_id: company,
              name: "Ads QA assistant",
              description: "Fixture",
              provider: "Custom",
            })
          ).body;
          const fresh = async () => {
            row = (await crm(manager)).body.connections.find(
              (x) => x.id === row.id,
            );
          };
          const save = async (changes) => {
            const r = await crm(manager + "/" + row.id, "PUT", {
              expected_company_id: company,
              expected_revision: row.revision,
              name: row.name,
              description: row.description,
              provider: row.provider,
              enabled: row.enabled,
              paused_until: row.paused_until,
              operating_hours: row.operating_hours,
              tool_policy: row.tool_policy,
              automatic_booking: row.automatic_booking,
              ...changes,
            });
            assert.equal(r.status, 200, JSON.stringify(r.body));
            await fresh();
          };
          const key = await crm(manager + "/" + row.id + "/key", "POST", {
            expected_company_id: company,
            expected_revision: row.revision,
            valid_days: 1,
          });
          assert.equal(key.status, 200, JSON.stringify(key.body));
          await fresh();
          let client = new Client({ name: "Ads QA", version: "1" });
          await client.connect(
            new StreamableHTTPClientTransport(new URL(base + "/mcp"), {
              requestInit: {
                headers: { Authorization: key.body.authorization },
              },
            }),
          );
          const call = async (name, args = {}) => {
            const r = await client.callTool({ name, arguments: args });
            return r.structuredContent || JSON.parse(r.content[0].text);
          };
          try {
            assert.equal((await client.listTools()).tools.length, 0);
            const names = row.catalog
              .filter((x) => x.id.startsWith("facebook_ads_"))
              .map((x) => x.id);
            assert.equal(names.length, 15);
            const policy = Object.fromEntries(
              names.map((n) => [
                n,
                { allow: true, approval: n === "facebook_ads_set_status" },
              ]),
            );
            await save({ tool_policy: policy });
            await client.close();
            client = new Client({ name: "Ads QA", version: "1" });
            await client.connect(
              new StreamableHTTPClientTransport(new URL(base + "/mcp"), {
                requestInit: {
                  headers: { Authorization: key.body.authorization },
                },
              }),
            );
            assert.ok(
              (await client.listTools()).tools.some(
                (x) => x.name === "facebook_ads_set_budget",
              ),
            );
            assert.equal(
              (await call("facebook_ads_accounts")).data.accounts[0].account_id,
              "10",
            );
            const item = (await service.entity(actor, "10", "campaign", "101"))
              .item;
            const input = {
              request_id: randomUUID(),
              account_id: "10",
              level: "campaign",
              entity_id: "101",
              expected_version: item.version,
              change: { kind: "status", value: "ACTIVE" },
              _request_id: randomUUID(),
            };
            const before = writes,
              pending = await call("facebook_ads_set_status", input);
            assert.equal(pending.state, "pending");
            assert.equal(writes, before);
            const approval = (await crm(manager)).body.approvals.find(
              (a) => a.id === pending.approval_id,
            );
            assert.equal(
              (
                await crm(
                  "/api/ai-connections/approvals/" + approval.id,
                  "POST",
                  { expected_hash: approval.input_hash, decision: "approve" },
                )
              ).status,
              200,
            );
            const confirmed = await call("facebook_ads_set_status", input);
            assert.equal(
              confirmed.result.data.status,
              "confirmed",
              JSON.stringify(confirmed),
            );
            await call("facebook_ads_set_status", input);
            assert.equal(writes, before + 1);
            await save({
              operating_hours: {
                timezone: "America/New_York",
                mode: "allowed",
                windows: [],
                exceptions: [],
              },
            });
            assert.equal(
              (await call("facebook_ads_accounts")).error,
              "connection_hours",
            );
            await save({ operating_hours: null });
            const create = {
              request_id: randomUUID(),
              name: "MCP draft",
              rule: {
                account_id: "10",
                level: "campaign",
                metric: "spend",
                operator: "gte",
                threshold: "20",
              },
            };
            const draft = await call("facebook_ads_automation_create", create);
            assert.ok(draft.data?.id, JSON.stringify(draft));
            assert.equal(
              (await call("facebook_ads_automation_create", create)).data.id,
              draft.data.id,
            );
            assert.ok(
              (await call("facebook_ads_automations")).data.some(
                (x) => x.id === draft.data.id,
              ),
            );
            assert.equal(
              (
                await pool.query(
                  "SELECT status FROM automation_definitions WHERE id=$1",
                  [draft.data.id],
                )
              ).rows[0].status,
              "draft",
            );
            const triggerId = randomUUID(), actionId = randomUUID();
            const saved = await call("facebook_ads_automation_save", {
              request_id: randomUUID(), id: draft.data.id,
              graph: {
                nodes: [
                  {id: triggerId, node_key: "metric", node_type: "trigger", title: "Metric", config: {trigger_key: "facebook_ads.metric", ads: create.rule}, position_x: 0, position_y: 0},
                  {id: actionId, node_key: "task", node_type: "action", title: "Task", config: {action_key: "task.create", title: "Ads threshold"}, position_x: 200, position_y: 0},
                ],
                edges: [{id: randomUUID(), source_node_id: triggerId, target_node_id: actionId, source_port: "default"}],
              },
            });
            assert.equal(saved.data?.status, "draft_saved", JSON.stringify(saved));
            assert.ok((await call("facebook_ads_automation_get", {id: draft.data.id})).data);
            for (const [action, expected] of [["publish", "published"], ["pause", "paused"], ["resume", "published"]]) {
              const input = {request_id: randomUUID(), id: draft.data.id, action};
              const controlled = await call("facebook_ads_automation_control", input);
              assert.equal(controlled.data?.action, action, JSON.stringify(controlled));
              assert.deepEqual((await call("facebook_ads_automation_control", input)).data, controlled.data);
              assert.equal((await pool.query("SELECT status FROM automation_definitions WHERE id=$1",[draft.data.id])).rows[0].status, expected);
            }
            assert.equal((await call("facebook_ads_automation_get", {id: randomUUID()})).error, "facebook_automation_not_found");
            await save({ enabled: false });
            assert.equal(
              (await call("facebook_ads_accounts")).error,
              "disabled",
            );
          } finally {
            await client.close();
          }
        },
      );
      await t.test('confirmed Ads changes reach Webhooks once; uncertain/foreign receipts and revoked account access fail closed',async()=>{
        const requests=[];
        const wh=await installWebhooks({...backend,pool:backend.pool,emitEvent:emitAutomationEvent,catalog:webhookEventCatalog(),env:{MCP_PUBLIC_ORIGIN:base,MCP_WEB_ORIGIN:base,RETELL_ENCRYPTION_KEY:Buffer.alloc(32,7).toString('base64')},startWorker:false,transport:async req=>{requests.push(req);return {status:200,body:'{"ticket":{"id":"confirmed-ticket"}}',headers:{'x-request-id':'fixture-request'}};}});
        const catalog=(await wh.list(actor)).events;
        assert.ok(catalog.some(e=>e.key==='facebook_ads.changed'));
        assert.ok(catalog.some(e=>e.key==='facebook_ads.metric'));
        const config=webhookConfigSchema.parse({name:'Confirmed Ads receiver',direction:'outgoing',url:'https://example.com/events',subscriptions:['facebook_ads.changed'],response_mappings:[{name:'ticket',path:'/ticket/id',type:'text'},{name:'request',source:'headers',path:'/x-request-id',type:'text'}]});
        let destination=await wh.create(actor,config);
        destination=await wh.update(actor,destination.id,destination.revision,{...config,enabled:true});
        const item=(await service.entity(actor,'10','campaign','101')).item;
        const receipt=await service.mutate(actor,{request_id:randomUUID(),account_id:'10',level:'campaign',entity_id:'101',expected_version:item.version,change:{kind:'status',value:item.status==='ACTIVE'?'PAUSED':'ACTIVE'}});
        assert.equal(receipt.status,'confirmed');
        await wh.drain();await wh.drain();
        assert.equal(requests.length,1);
        const sentBody=JSON.parse(requests[0].body);
        const body={event:{id:sentBody.event_id,type:sentBody.event_type,timestamp:sentBody.timestamp,data:sentBody.data}};
        assert.equal(body.event.type,'facebook_ads.changed');assert.equal(body.event.data.status,'confirmed');
        assert.equal(body.event.data.account_id,'10');assert.equal(body.event.data.entity_id,'101');
        const event=(await pool.query('SELECT * FROM automation_events WHERE id=$1',[body.event.id])).rows[0];
        const delivery=(await pool.query('SELECT * FROM wolf_webhook_deliveries WHERE connection_id=$1 AND identity=$2',[destination.id,'event:'+event.id])).rows[0];
        assert.deepEqual(delivery.response_mapped,{ticket:'confirmed-ticket',request:'fixture-request'});
        assert.equal(delivery.context_ciphertext,null);
        await assert.rejects(()=>projectAdsWebhookEvent({pool,service,actor:{userId:otherOwner,companyId:other},event}),e=>e.code==='ads_event_unavailable');
        const pending=randomUUID();
        await pool.query("INSERT INTO facebook_ads_receipts SELECT $1,company_id,user_id,source,$2,input_hash,account_id,entity_id,level,requested,previous,target,NULL,'uncertain',NULL,now(),now() FROM facebook_ads_receipts WHERE id=$3",[pending,randomUUID(),body.event.data.receipt_id]);
        await assert.rejects(()=>projectAdsWebhookEvent({pool,service,actor,event:{...event,payload:{...event.payload,receipt_id:pending}}}),e=>e.code==='ads_receipt_unconfirmed');
        const queued=await wh.enqueue(actor,destination.id,'revocation-fixture',{event:body.event},{sourceRef:{kind:'facebook_ads_event',id:event.id}});
        await service.select(actor,[]);
        await wh.deliverOne();
        assert.equal((await pool.query('SELECT state FROM wolf_webhook_deliveries WHERE id=$1',[queued.id])).rows[0].state,'blocked');
        assert.equal(requests.length,1);
        await service.select(actor,['10']);
        const metric=(await pool.query("SELECT * FROM automation_events WHERE company_id=$1 AND event_type='facebook_ads.metric' ORDER BY created_at DESC LIMIT 1",[company])).rows[0];
        assert.ok(metric);
        const projection=await projectAdsWebhookEvent({pool,service,actor,event:metric});
        assert.equal(projection.data.evaluation_id,metric.payload.evaluation_id);
        assert.equal(projection.data.account_id,'10');
        assert.equal(projection.data.value,metric.payload.value);
        assert.deepEqual(projection.data.period,metric.payload.period);
        await pool.query("UPDATE automation_nodes SET config=jsonb_set(config,'{ads,account_id}','\"999\"'::jsonb) WHERE id=$1",[metric.payload.trigger_node_id]);
        assert.deepEqual((await projectAdsWebhookEvent({pool,service,actor,event:metric})).data,projection.data);
      });
      await t.test("Ads disconnect leaves lead imports connected", async () => {
        await pool.query(
          "INSERT INTO facebook_lead_connections(company_id,user_id,token,status) VALUES($1,$2,$3,'authorized')",
          [company, owner, encrypt("fixture-lead-token", company, env)],
        );
        await service.disconnect(actor);
        assert.equal(
          (
            await pool.query(
              "SELECT status FROM facebook_lead_connections WHERE company_id=$1",
              [company],
            )
          ).rows[0].status,
          "authorized",
        );
        await assert.rejects(
          () =>
            service.entities(actor, { account_id: "10", level: "campaign" }),
          (e) => e.code === "facebook_ads_disconnected",
        );
      });
    } finally {
      if (server) await new Promise((r) => server.close(r));
      if (pool) await pool.end();
      pg.stop();
    }
  },
);
