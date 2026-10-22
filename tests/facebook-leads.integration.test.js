import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID, createHmac } from "node:crypto";
import { startLocalPostgres } from "./helpers/local-postgres.js";
import { installFacebookLeads } from "../facebook-leads/index.js";
import { installFacebookLeadSchema } from "../facebook-leads/schema.js";
import {
  installAutomationSystem,
  emitAutomationEvent,
} from "../automations.js";
import { encrypt, hash } from "../facebook-leads/provider.js";
import { FacebookLeadError } from "../facebook-leads/domain.js";
test(
  "direct Facebook lead integration against disposable PostgreSQL and real auth/routes",
  { timeout: 90000 },
  async (t) => {
    const pg = startLocalPostgres();
    pg.configureEnvironment();
    let pool, server, system;
    try {
      const backend = await import("../index.js");
      pool = backend.pool;
      await backend.bootstrap();
      await installAutomationSystem({
        app: backend.app,
        pool,
        authRequired: backend.authRequired,
        requireEmployer: backend.requireCapability("integrations.manage"),
        disableProcessors: true,
      });
      const company = randomUUID(),
        owner = randomUUID(),
        other = randomUUID(),
        otherOwner = randomUUID(),
        employee = randomUUID();
      for (const [c, u, email] of [
        [company, owner, "fb-owner@example.invalid"],
        [other, otherOwner, "fb-other@example.invalid"],
      ]) {
        await pool.query(
          "INSERT INTO companies(id,name,join_code,owner_user_id) VALUES($1,$2,$3,$4)",
          [c, "Facebook fixture", c, u],
        );
        await pool.query(
          "INSERT INTO users(id,email,role,company_id) VALUES($1,$2,'employer',$3)",
          [u, email, c],
        );
        await pool.query("INSERT INTO sessions(token,user_id) VALUES($1,$2)", [
          u,
          u,
        ]);
      }
      await pool.query(
        "INSERT INTO users(id,email,role,company_id) VALUES($1,'fb-worker@example.invalid','employee',$2)",
        [employee, company],
      );
      await pool.query("INSERT INTO sessions(token,user_id) VALUES($1,$2)", [
        employee,
        employee,
      ]);
      const env = {
        FACEBOOK_LEADS_ENCRYPTION_KEY: Buffer.alloc(32, 3).toString("base64"),
        FACEBOOK_LEADS_APP_SECRET: "fixture-secret",
        FACEBOOK_LEADS_APP_ID: "999",
        FACEBOOK_LEADS_VERIFY_TOKEN: "fixture-verify",
        FACEBOOK_LEADS_REDIRECT_URI:
          "https://example.invalid/api/integrations/facebook-leads/oauth/callback",
        FACEBOOK_LEADS_WORKER_ENABLED: "true",
      };
      const leads = new Map(),
        fetchCount = new Map();
      let failure = null;
      const graph = {
        configured: () => true,
        loginURL: (s) => "https://www.facebook.com/oauth?state=" + s,
        exchange: async () => "fixture-token",
        request: async (path) =>
          path === "me" ? { id: "1000" } : { success: true },
        all: async (path) =>
          path === "me/accounts"
            ? [{ id: "10", name: "Fixture Page", access_token: "page-token" }]
            : path === "me/permissions"
              ? [{ permission: "leads_retrieval", status: "granted" }]
              : path.endsWith("/subscribed_apps")
                ? [{ id: "999", subscribed_fields: ["leadgen"] }]
                : [
                    {
                      id: "20",
                      name: "Fixture form",
                      questions: [
                        { key: "full_name", label: "Name" },
                        { key: "email", label: "Email" },
                        { key: "phone_number", label: "Phone" },
                        { key: "services", label: "Services?" },
                        { key: "private", label: "Do not retain" },
                      ],
                    },
                  ],
        page: async () => ({ data: [], cursor: null }),
        lead: async (id) => {
          fetchCount.set(id, (fetchCount.get(id) || 0) + 1);
          if (failure) throw failure;
          return { lead: leads.get(id), issues: [] };
        },
        leads: async (id, token, range, cursor) => ({
          data: cursor
            ? [{ id: "202", created_time: "2026-10-10T10:00:00Z" }]
            : [{ id: "201", created_time: "2026-10-10T09:00:00Z" }],
          cursor: cursor ? null : "next",
        }),
      };
      let dirty = 0,
        pushes = 0;
      system = await installFacebookLeads({
        ...backend,
        pool,
        env,
        graph,
        emitAutomationEvent,
        startWorker: false,
        markContactDirty: async () => {
          dirty++;
        },
        sendPushToUsers: async () => {
          pushes++;
        },
      });
      const { store, worker } = system;
      await installFacebookLeadSchema(pool); // Repeated startup preserves all existing rows.
      server = await new Promise((resolve) => {
        const s = backend.app.listen(0, "127.0.0.1", () => resolve(s));
      });
      const origin = `http://127.0.0.1:${server.address().port}`,
        base = "/api/integrations/facebook-leads";
      async function request(path, body, method = "GET", user = owner) {
        const response = await fetch(origin + path, {
          method,
          headers: {
            authorization: `Bearer ${user}`,
            "content-type": "application/json",
          },
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
          redirect: "manual",
        });
        const raw = await response.text();
        return {
          status: response.status,
          body: raw
            ? (() => {
                try {
                  return JSON.parse(raw);
                } catch {
                  return raw;
                }
              })()
            : null,
          headers: response.headers,
        };
      }
      await t.test(
        "OAuth state binds live administrator/session/company; expiry and replay are rejected",
        async () => {
          const start = await request(
            base + "/oauth/start",
            { client: "ios" },
            "POST",
          );
          assert.equal(start.status, 200);
          const state = new URL(start.body.url).searchParams.get("state");
          const callback = await request(
            base + "/oauth/callback?state=" + state + "&code=test",
          );
          assert.equal(callback.status, 302);
          assert.match(callback.headers.get("location"), /status=authorized/);
          assert.equal(
            (
              await request(
                base + "/oauth/callback?state=" + state + "&code=test",
              )
            ).status,
            400,
          );
          assert.equal(
            (await request(base, undefined, "GET", employee)).status,
            403,
          );
        },
      );
      await t.test(
        "select Page discovers form definitions without leads; scoped defaults and revisions",
        async () => {
          assert.equal(
            (await request(base + "/pages/10/select", {}, "POST")).status,
            200,
          );
          let m = (await request(base + "/mapping/20")).body;
          assert.equal(
            m.sources.find((s) => s.key === "field:services").label,
            "Services?",
          );
          assert.equal(
            (await store.mapping(company, "defaults")).sources.find(
              (s) => s.key === "field:services",
            ).label,
            "Services?",
          );
          const notReady = (await store.status(company)).forms[0];
          assert.equal(notReady.mapping_ready, false);
          assert.equal((await request(base + "/forms/20", { enabled: true, revision: notReady.revision }, "PUT")).body.error, "facebook_form_mapping_required");
          assert.equal(
            (
              await request(
                base + "/mapping/20",
                {
                  revision: m.revision,
                  mappings: {
                    "field:full_name": { destination: "name", origin: "manual" },
                    "field:email": { destination: "email", origin: "manual" },
                    "field:phone_number": { destination: "phone", origin: "manual" },
                    "field:services": { destination: "lead_info", origin: "manual" },
                    "field:private": {
                      destination: "ignore",
                      origin: "manual",
                    },
                  },
                  destination: { type: "contacts", stage_id: null },
                },
                "PUT",
              )
            ).status,
            200,
          );
          assert.equal(
            (
              await request(
                base + "/mapping/20",
                { revision: m.revision, mappings: {} },
                "PUT",
              )
            ).status,
            409,
          );
          assert.equal(
            (await request(base + "/mapping/20", undefined, "GET", otherOwner))
              .status,
            404,
          );
          const f = (await store.status(company)).forms[0];
          assert.equal(f.mapping_ready, true);
          assert.equal(
            (
              await request(
                base + "/forms/20",
                { enabled: true, revision: f.revision },
                "PUT",
              )
            ).status,
            200,
          );
          await pool.query(
            "INSERT INTO zapier_tokens(user_id,token,notifications_enabled) VALUES($1,$2,true)",
            [owner, "fixture-zapier-token-123456"],
          );
        },
      );
      const makeLead = (id, extra = []) =>
        leads.set(id, {
          id,
          form_id: "20",
          field_data: [
            { name: "full_name", values: ["Synthetic Facebook Customer"] },
            { name: "email", values: [`lead${id}@example.invalid`] },
            { name: "private", values: ["IGNORED_DURABLE_SENTINEL"] },
            {
              name: "services",
              values: ["Windows", "Gutters", "完整\nanswer"],
            },
            ...extra,
          ],
        });
      const webhook = async (ids, signature = true) => {
        const raw = JSON.stringify({
          object: "page",
          entry: [
            {
              id: "10",
              changes: ids.map((id) => ({
                field: "leadgen",
                value: {
                  page_id: "10",
                  form_id: "20",
                  leadgen_id: id,
                  private: "IGNORED_WEBHOOK_SENTINEL",
                },
              })),
            },
          ],
        });
        const r = await fetch(origin + "/webhooks/facebook-leads", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-hub-signature-256": signature
              ? "sha256=" +
                createHmac("sha256", env.FACEBOOK_LEADS_APP_SECRET)
                  .update(raw)
                  .digest("hex")
              : "sha256=wrong",
          },
          body: raw,
        });
        return r.status;
      };
      await t.test(
        "raw signature, batched durable acknowledgement, concurrent delivery and contact/event atomicity",
        async () => {
          makeLead("101");
          assert.equal(await webhook(["101"], false), 401);
          assert.equal(
            (await pool.query("SELECT * FROM facebook_lead_jobs")).rowCount,
            0,
          );
          assert.deepEqual(
            await Promise.all([webhook(["101", "101"]), webhook(["101"])]),
            [200, 200],
          );
          assert.equal(fetchCount.size, 0);
          const claimed = await Promise.all([
            worker.claim("facebook_lead_jobs"),
            worker.claim("facebook_lead_jobs"),
          ]);
          assert.equal(claimed.filter(Boolean).length, 1);
          await worker.processJob(claimed.find(Boolean));
          const jobs = (await store.activity(company)).jobs;
          assert.equal(jobs.length, 1);
          assert.equal(jobs[0].status, "succeeded", JSON.stringify(jobs));
          assert.equal(jobs[0].outcome, "created");
          const c = (
            await pool.query("SELECT * FROM contacts WHERE id=$1", [
              jobs[0].contact_id,
            ])
          ).rows[0];
          assert.match(c.lead_info.join(""), /Windows\nGutters\n完整/);
          assert.equal(c.source, "Facebook Lead");
          assert.equal(c.source_raw, "facebook_direct");
          assert.ok(c.lead_source_id);
          assert.equal(
            (
              await pool.query(
                "SELECT * FROM opportunities WHERE contact_id=$1",
                [c.id],
              )
            ).rowCount,
            0,
          );
          await webhook(["101"]);
          assert.equal(await worker.claim("facebook_lead_jobs"), undefined);
          assert.equal(
            (
              await pool.query("SELECT * FROM lead_notifications WHERE id=$1", [
                jobs[0].id,
              ])
            ).rowCount,
            1,
          );
          await worker.outbox();
          await worker.outbox();
          assert.equal(pushes, 1);
          assert.equal(dirty, 1);
          for (const table of [
            "contacts",
            "facebook_lead_jobs",
            "facebook_lead_forms",
            "automation_events",
            "lead_notifications",
            "lead_imports",
          ]) {
            const rows = (
              await pool.query(`SELECT row_to_json(t) FROM ${table} t`)
            ).rows;
            assert.ok(!JSON.stringify(rows).includes("IGNORED_"), table);
          }
        },
      );
      await t.test(
        "chosen stage creates a scoped opportunity and attributed lead list links to the saved contact",
        async () => {
          const stageID = randomUUID();
          await pool.query(
            "INSERT INTO stages(id,user_id,company_id,name) VALUES($1,$2,$3,'New Facebook leads')",
            [stageID, owner, company],
          );
          const before = await store.mapping(company, "20");
          await store.saveMapping(company, "20", {
            revision: before.revision,
            mappings: before.mappings,
            destination: { type: "contacts", stage_id: stageID },
          });
          assert.ok((await request(base + "/stages")).body.items.some((stage) => stage.id === stageID));
          makeLead("105");
          leads.set("105", { ...leads.get("105"), campaign_id: "901", adset_id: "902", ad_id: "903" });
          await webhook(["105"]);
          await worker.processJob(await worker.claim("facebook_lead_jobs"));
          const receipt = (await pool.query("SELECT * FROM facebook_lead_jobs WHERE company_id=$1 AND lead_id='105'", [company])).rows[0];
          assert.equal(receipt.status, "succeeded");
          assert.equal(receipt.campaign_id, "901");
          const opportunity = (await pool.query("SELECT * FROM opportunities WHERE company_id=$1 AND contact_id=$2", [company, receipt.contact_id])).rows[0];
          assert.equal(opportunity.stage_id, stageID);
          const list = await request(base + "/leads?campaign_id=901");
          assert.equal(list.status, 200);
          assert.equal(list.body.items[0].contact_id, receipt.contact_id);
          assert.equal(list.body.items[0].contact_name, "Synthetic Facebook Customer");
          assert.equal((await request(base + "/leads?adset_id=902")).body.items[0].lead_id, "105");
          assert.equal((await request(base + "/leads?ad_id=903")).body.items[0].lead_id, "105");
          assert.equal((await request(base + "/leads?campaign_id=901", undefined, "GET", otherOwner)).body.items.length, 0);
          assert.equal((await request(base + "/leads?campaign_id=901&ad_id=903")).status, 400);
          const latest = await store.mapping(company, "20");
          await store.saveMapping(company, "20", {
            revision: latest.revision,
            mappings: latest.mappings,
            destination: { type: "contacts", stage_id: null },
          });
        },
      );
      await t.test(
        "a new provider question holds the lead ID without importing answers until explicitly mapped",
        async () => {
          makeLead("106", [{ name: "new_question", values: ["SENSITIVE_NEW_ANSWER"] }]);
          await webhook(["106"]);
          await worker.processJob(await worker.claim("facebook_lead_jobs"));
          const receipt = (await pool.query("SELECT id,status,contact_id,error_code FROM facebook_lead_jobs WHERE company_id=$1 AND lead_id='106'", [company])).rows[0];
          assert.equal(receipt.status, "review");
          assert.equal(receipt.contact_id, null);
          assert.equal(receipt.error_code, "facebook_form_field_mapping_required");
          assert.equal((await store.status(company)).forms[0].mapping_ready, false);
          assert.equal(await worker.claim("facebook_lead_jobs"), undefined);
          assert.ok(!JSON.stringify((await pool.query("SELECT * FROM facebook_lead_jobs WHERE id=$1", [receipt.id])).rows).includes("SENSITIVE_NEW_ANSWER"));
          const current = await store.mapping(company, "20");
          assert.ok(current.missing_sources.includes("field:new_question"));
          await store.saveMapping(company, "20", {
            revision: current.revision,
            mappings: { ...current.mappings, "field:new_question": { destination: "lead_info:3", origin: "manual" } },
            destination: { type: "contacts", stage_id: null },
          });
          assert.equal((await request(base + "/jobs/" + receipt.id + "/retry", {}, "POST")).status, 200);
          await worker.processJob(await worker.claim("facebook_lead_jobs"));
          const completed = (await pool.query("SELECT status,contact_id FROM facebook_lead_jobs WHERE id=$1", [receipt.id])).rows[0];
          assert.equal(completed.status, "succeeded");
          const saved = (await pool.query("SELECT lead_info FROM contacts WHERE id=$1", [completed.contact_id])).rows[0];
          assert.match(saved.lead_info.join(""), /SENSITIVE_NEW_ANSWER/);
        },
      );
      await t.test(
        "fill empty matching, preserved fields, repeat Lead Info once, conflicting matches visible",
        async () => {
          const id = randomUUID();
          await pool.query(
            "INSERT INTO contacts(id,user_id,company_id,name,email,phone) VALUES($1,$2,$3,'Preserved','match@example.invalid','+1 (202) 555-0123')",
            [id, owner, company],
          );
          leads.set("102", {
            id: "102",
            form_id: "20",
            field_data: [
              { name: "full_name", values: ["Changed"] },
              { name: "email", values: ["MATCH@example.invalid"] },
              { name: "phone_number", values: ["2025550123"] },
              { name: "services", values: ["New answer"] },
            ],
          });
          await webhook(["102"]);
          await worker.processJob(await worker.claim("facebook_lead_jobs"));
          let row = (
            await pool.query("SELECT * FROM contacts WHERE id=$1", [id])
          ).rows[0];
          assert.equal(row.name, "Preserved");
          assert.match(row.lead_info.join(""), /Changed/);
          const duplicate = randomUUID();
          await pool.query(
            "INSERT INTO contacts(id,user_id,company_id,name,email) VALUES($1,$2,$3,'Another','match@example.invalid')",
            [duplicate, owner, company],
          );
          leads.set("103", { ...leads.get("102"), id: "103" });
          await webhook(["103"]);
          await worker.processJob(await worker.claim("facebook_lead_jobs"));
          assert.equal(
            (
              await pool.query(
                "SELECT status FROM facebook_lead_jobs WHERE lead_id='103'",
              )
            ).rows[0].status,
            "review",
          );
          assert.equal(
            (await request(base + "/activity", undefined, "GET", otherOwner))
              .body.jobs.length,
            0,
          );
        },
      );
      await t.test(
        "pause holds IDs, retry backoff, current Ignore on retry, expired lease recovers",
        async () => {
          makeLead("104");
          await pool.query(
            "UPDATE facebook_lead_forms SET enabled=false WHERE company_id=$1",
            [company],
          );
          await webhook(["104"]);
          assert.equal(await worker.claim("facebook_lead_jobs"), undefined);
          await pool.query(
            "UPDATE facebook_lead_forms SET enabled=true WHERE company_id=$1",
            [company],
          );
          failure = new FacebookLeadError(
            "facebook_rate_or_service_limit",
            502,
            true,
            60,
          );
          await worker.processJob(await worker.claim("facebook_lead_jobs"));
          let job = (
            await pool.query(
              "SELECT * FROM facebook_lead_jobs WHERE lead_id='104'",
            )
          ).rows[0];
          assert.equal(job.status, "retry");
          assert.ok(new Date(job.available_at) > Date.now());
          failure = null;
          await pool.query(
            "UPDATE facebook_lead_jobs SET status='processing',lease_until=now()-interval '1 second' WHERE id=$1",
            [job.id],
          );
          await pool.query(
            'UPDATE facebook_lead_forms SET mappings=mappings||\'{"field:services":{"destination":"ignore","origin":"manual"}}\'::jsonb WHERE company_id=$1',
            [company],
          );
          await worker.processJob(await worker.claim("facebook_lead_jobs"));
          job = (
            await pool.query("SELECT * FROM facebook_lead_jobs WHERE id=$1", [
              job.id,
            ])
          ).rows[0];
          assert.equal(job.status, "succeeded");
          const c = (
            await pool.query("SELECT * FROM contacts WHERE id=$1", [
              job.contact_id,
            ])
          ).rows[0];
          assert.ok(!JSON.stringify(c).includes("Gutters"));
        },
      );
      await t.test(
        "preview has exact merge but no durable answers/contact, backfill pagination retains IDs only",
        async () => {
          makeLead("201");
          makeLead("202");
          const before = (await pool.query("SELECT count(*) FROM contacts"))
            .rows[0].count;
          const preview = await request(
            base + "/forms/20/preview",
            { lead_id: "201" },
            "POST",
          );
          assert.equal(preview.status, 200);
          assert.ok(!JSON.stringify(preview.body).includes("IGNORED_"));
          assert.equal(
            (await pool.query("SELECT count(*) FROM contacts")).rows[0].count,
            before,
          );
          assert.equal(preview.headers.get("cache-control"), "no-store");
          const scan = await request(
            base + "/forms/20/import-existing",
            { from: "2026-10-09", to: "2026-10-11", preview: true },
            "POST",
          );
          assert.equal(scan.status, 200);
          await worker.processScan(await worker.claim("facebook_lead_scans"));
          await worker.processScan(await worker.claim("facebook_lead_scans"));
          let row = (
            await pool.query("SELECT * FROM facebook_lead_scans WHERE id=$1", [
              scan.body.id,
            ])
          ).rows[0];
          assert.equal(row.queued, 2);
          assert.equal(row.status, "succeeded");
          assert.equal(
            (
              await pool.query(
                "SELECT * FROM facebook_lead_jobs WHERE lead_id IN ('201','202')",
              )
            ).rowCount,
            0,
          );
          const importing = await request(
            base + "/forms/20/import-existing",
            { from: "2026-10-09", to: "2026-10-11", preview: false },
            "POST",
          );
          assert.equal(importing.status, 200);
          await worker.processScan(await worker.claim("facebook_lead_scans"));
          await worker.processScan(await worker.claim("facebook_lead_scans"));
          const importedJobs = await pool.query(
            "SELECT * FROM facebook_lead_jobs WHERE lead_id IN ('201','202')",
          );
          assert.equal(importedJobs.rowCount, 2);
          assert.ok(!JSON.stringify(importedJobs.rows).includes("IGNORED_"));
          for (let n = 0; n < 2; n++)
            await worker.processJob(await worker.claim("facebook_lead_jobs"));
          assert.equal(
            (
              await pool.query(
                "SELECT * FROM facebook_lead_jobs WHERE lead_id IN ('201','202') AND status='succeeded'",
              )
            ).rowCount,
            2,
          );
          assert.equal(
            (
              await pool.query(
                "SELECT queued FROM facebook_lead_scans WHERE id=$1",
                [importing.body.id],
              )
            ).rows[0].queued,
            2,
          );
        },
      );
      await t.test(
        "different leads for the same person serialize matching without duplicate contacts",
        async () => {
          for (const id of ["401", "402"])
            leads.set(id, {
              id,
              form_id: "20",
              field_data: [
                { name: "email", values: ["concurrent@example.invalid"] },
                { name: "full_name", values: ["Concurrent synthetic"] },
              ],
            });
          await webhook(["401", "402"]);
          const jobs = await Promise.all([
            worker.claim("facebook_lead_jobs"),
            worker.claim("facebook_lead_jobs"),
          ]);
          assert.ok(jobs.every(Boolean));
          await Promise.all(jobs.map((job) => worker.processJob(job)));
          assert.equal(
            (
              await pool.query(
                "SELECT id FROM contacts WHERE company_id=$1 AND email='concurrent@example.invalid'",
                [company],
              )
            ).rowCount,
            1,
          );
          assert.equal(
            (
              await pool.query(
                "SELECT DISTINCT contact_id FROM facebook_lead_jobs WHERE lead_id IN ('401','402')",
              )
            ).rowCount,
            1,
          );
        },
      );
      await t.test(
        "reconciliation never imports before activation and pause preserves the cutover",
        async () => {
          await pool.query(
            "UPDATE facebook_lead_forms SET recovery_at=now()-interval '20 minutes',import_since=now()-interval '20 minutes' WHERE company_id=$1 AND form_id='20'",
            [company],
          );
          const form = (await store.status(company)).forms.find(
            (f) => f.form_id === "20",
          );
          assert.equal(
            (
              await request(
                base + "/forms/20",
                { enabled: false, revision: form.revision },
                "PUT",
              )
            ).status,
            200,
          );
          await worker.recover();
          assert.equal(
            (
              await pool.query(
                "SELECT id FROM facebook_lead_scans WHERE status='pending'",
              )
            ).rowCount,
            0,
          );
          const paused = (await store.status(company)).forms.find(
            (f) => f.form_id === "20",
          );
          assert.equal(
            (
              await request(
                base + "/forms/20",
                { enabled: true, revision: paused.revision },
                "PUT",
              )
            ).status,
            200,
          );
          await worker.recover();
          const scan = (
            await pool.query(
              "SELECT s.*,s.from_time=f.import_since AS starts_at_activation FROM facebook_lead_scans s JOIN facebook_lead_forms f USING(company_id,form_id) WHERE s.status='pending' AND s.company_id=$1",
              [company],
            )
          ).rows[0];
          assert.equal(scan.starts_at_activation, true);
          await worker.processScan(await worker.claim("facebook_lead_scans"));
          await worker.processScan(await worker.claim("facebook_lead_scans"));
          assert.equal(
            (
              await pool.query(
                "SELECT queued FROM facebook_lead_scans WHERE id=$1",
                [scan.id],
              )
            ).rows[0].queued,
            0,
          );
        },
      );
      await t.test(
        "activity pagination preserves submillisecond batch timestamps",
        async () => {
          await pool.query(
            "INSERT INTO facebook_lead_jobs(company_id,page_id,form_id,lead_id,status,created_at) SELECT $1,'10','20',n::text,'canceled',now() FROM generate_series(1000,1105)n",
            [company],
          );
          const all = [];
          let cursor;
          do {
            const page = await store.activity(company, cursor);
            all.push(...page.jobs.map((j) => j.id));
            cursor = page.next_before;
          } while (cursor);
          assert.equal(
            new Set(all).size,
            Number(
              (
                await pool.query(
                  "SELECT count(*) FROM facebook_lead_jobs WHERE company_id=$1",
                  [company],
                )
              ).rows[0].count,
            ),
          );
        },
      );
      await t.test(
        "one explicit route per form, scoped retry and preview, copy/reset and company defaults",
        async () => {
          await pool.query(
            "INSERT INTO facebook_lead_connections(company_id,user_id,meta_user_id,token,status) VALUES($1,$2,'2000',$3,'authorized')",
            [other, otherOwner, encrypt("fixture-token", other, env)],
          );
          await store.refresh(other);
          await store.inspectPage(other, "10", true);
          const otherForm = (await store.status(other)).forms[0];
          assert.equal(
            (
              await request(
                base + "/forms/20",
                { enabled: true, revision: otherForm.revision },
                "PUT",
                otherOwner,
              )
            ).status,
            409,
          );
          const job = (
            await pool.query(
              "SELECT id FROM facebook_lead_jobs WHERE lead_id='103'",
            )
          ).rows[0];
          assert.equal(
            (
              await request(
                base + "/jobs/" + job.id + "/retry",
                {},
                "POST",
                otherOwner,
              )
            ).status,
            404,
          );
          const oldLead = leads.get("201");
          leads.set("201", { ...oldLead, form_id: "999" });
          assert.equal(
            (
              await request(
                base + "/forms/20/preview",
                { lead_id: "201" },
                "POST",
              )
            ).status,
            403,
          );
          leads.set("201", oldLead);
          const defaults = await store.mapping(company, "defaults");
          await assert.rejects(store.saveMapping(company, "defaults", {
            revision: defaults.revision,
            mappings: {
              "field:email": { destination: "lead_info:4", origin: "manual" },
            },
            unknown_policy: "ignore",
            overwrite: false,
          }), /facebook_company_defaults_retired/);
          assert.equal(
            (await store.mapping(company, "20")).sources.find(
              (s) => s.key === "field:email",
            ).mapping.destination,
            "email",
          );
          const current = await store.mapping(company, "20");
          await pool.query(
            "INSERT INTO facebook_lead_forms(company_id,page_id,form_id,name,sources) SELECT company_id,page_id,'21','Copy target',sources FROM facebook_lead_forms WHERE company_id=$1 AND form_id='20'",
            [company],
          );
          const target = await store.mapping(company, "21");
          assert.equal(
            (
              await request(
                base + "/mapping/20/copy",
                { target_form_id: "21", target_revision: target.revision },
                "POST",
              )
            ).status,
            200,
          );
          const copied = await store.mapping(company, "21");
          assert.equal(
            copied.sources.find((s) => s.key === "field:private").mapping
              .destination,
            "ignore",
          );
          assert.equal(
            copied.sources.find((s) => s.key === "field:email").mapping
              .destination,
            "email",
          );
          assert.equal(
            (
              await request(
                base + "/mapping/20/copy",
                { target_form_id: "21", target_revision: target.revision },
                "POST",
              )
            ).status,
            409,
          );
          assert.equal(
            (
              await request(
                base + "/mapping/20/copy",
                { target_form_id: "21", target_revision: copied.revision },
                "POST",
                otherOwner,
              )
            ).status,
            404,
          );
          assert.equal(
            (
              await request(
                base + "/mapping/20/reset",
                { revision: current.revision },
                "POST",
              )
            ).status,
            200,
          );
          assert.equal((await store.mapping(company, "20")).ready, false);
          // Restore the explicit retention mapping for the disconnect race test.
          const m = await store.mapping(company, "20");
          await store.saveMapping(company, "20", {
            revision: m.revision,
            mappings: current.mappings,
            destination: { type: "contacts", stage_id: null },
          });
        },
      );
      await t.test(
        "OAuth expiry rejects stale callbacks and revocation/deletion are signed and isolated",
        async () => {
          const expired = await request(
            base + "/oauth/start",
            { client: "ios" },
            "POST",
          );
          const state = new URL(expired.body.url).searchParams.get("state");
          await pool.query(
            "UPDATE facebook_lead_oauth_states SET expires_at=now()-interval '1 minute' WHERE state_hash=$1",
            [hash(state)],
          );
          assert.equal(
            (
              await request(
                base + "/oauth/callback?state=" + state + "&code=test",
              )
            ).status,
            400,
          );
          assert.equal(
            (
              await request(
                base + "/data-deletion",
                { signed_request: "invalid" },
                "POST",
              )
            ).status,
            401,
          );
          assert.equal(
            (
              await request(
                base + "/deauthorize",
                { signed_request: "invalid" },
                "POST",
              )
            ).status,
            401,
          );
          const payload = Buffer.from(
            JSON.stringify({ algorithm: "HMAC-SHA256", user_id: "2000" }),
          ).toString("base64url");
          const signed =
            createHmac("sha256", env.FACEBOOK_LEADS_APP_SECRET)
              .update(payload)
              .digest("base64url") +
            "." +
            payload;
          assert.equal(
            (
              await request(
                base + "/deauthorize",
                { signed_request: signed },
                "POST",
              )
            ).status,
            200,
          );
          for (const table of ["facebook_lead_connections", "facebook_lead_settings", "facebook_lead_pages", "facebook_lead_forms", "facebook_lead_jobs", "facebook_lead_scans", "facebook_lead_oauth_states"]) {
            assert.equal((await pool.query(`SELECT 1 FROM ${table} WHERE company_id=$1`, [other])).rowCount, 0, table);
          }
          // A real deletion callback commonly follows deauthorization with no reauthorization.
          const deleted = await request(
            base + "/data-deletion",
            { signed_request: signed },
            "POST",
          );
          assert.equal(deleted.status, 200);
          assert.ok(
            (
              await pool.query(
                "SELECT token FROM facebook_lead_connections WHERE company_id=$1",
                [company],
              )
            ).rows[0].token,
          );
          assert.equal(
            (
              await pool.query(
                "SELECT * FROM facebook_lead_connections WHERE company_id=$1",
                [other],
              )
            ).rowCount,
            0,
          );
          assert.equal(
            (
              await request(
                base + "/deletion-status/" + deleted.body.confirmation_code,
              )
            ).status,
            200,
          );
          assert.equal(
            (await request(base + "/deletion-status/unknown")).status,
            404,
          );
        },
      );
      await t.test(
        "disconnect cancels pending work and token access without altering unrelated CRM/Zapier",
        async () => {
          makeLead("301");
          await webhook(["301"]);
          const before = (await pool.query("SELECT count(*) FROM contacts"))
            .rows[0].count;
          const oldToken = (
            await pool.query(
              "SELECT token FROM facebook_lead_connections WHERE company_id=$1",
              [company],
            )
          ).rows[0].token;
          assert.equal(
            (await request(base + "/disconnect", {}, "POST")).status,
            200,
          );
          await assert.rejects(
            store.discoverPages(company, "fixture-token"),
            (e) => e.code === "facebook_authorization_changed_retry",
          );
          assert.ok(oldToken);
          assert.equal(
            (
              await pool.query(
                "SELECT token FROM facebook_lead_pages WHERE company_id=$1",
                [company],
              )
            ).rows[0].token,
            null,
          );
          assert.equal(await worker.claim("facebook_lead_jobs"), undefined);
          assert.equal(
            (await pool.query("SELECT count(*) FROM contacts")).rows[0].count,
            before,
          );
          assert.equal(
            (await pool.query("SELECT count(*) FROM zapier_tokens")).rows[0]
              .count,
            "1",
          );
        },
      );
    } finally {
      system?.stop();
      if (server) await new Promise((r) => server.close(r));
      if (pool) await pool.end();
      pg.stop();
    }
  },
);
