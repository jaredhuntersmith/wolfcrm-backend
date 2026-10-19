import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID, randomBytes } from "node:crypto";
import { startLocalPostgres } from "./helpers/local-postgres.js";
import {
  installAutomationSystem,
  emitAutomationEvent,
  webhookEventCatalog,
  automationTestHooks as hooks,
} from "../automations.js";
import { installMCPSchema } from "../mcp/schema.js";
import { installRetellSchema } from "../retell/schema.js";
import { installManagerSchema } from "../mcp/manager-schema.js";
import { installWebhookSchema } from "../webhooks/schema.js";
import { installWebhooks } from "../webhooks/service.js";
import { sign, configSchema } from "../webhooks/domain.js";
import { installStorageSchema } from "../media-storage/schema.js";
import { installCommsSchema } from "../company-comms/schema.js";
import { installCollaborationSchema } from "../company-comms/collaboration-schema.js";
import { installNotesSchema } from "../notes/schema.js";
import { createNotesWorkspace } from "../notes/pages.js";
import { registerWebhookTools } from "../webhooks/tools.js";
import { z } from "zod";
import {
  Client,
  StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";
import { installMCP } from "../mcp/index.js";

test(
  "native webhook API and durable automation integration",
  { timeout: 180000 },
  async (t) => {
    const pg = startLocalPostgres();
    pg.configureEnvironment();
    let backend, server;
    try {
      backend = await import("../index.js");
      await backend.bootstrap();
      const { app, pool, authRequired } = backend;
      await installAutomationSystem({
        app,
        pool,
        authRequired,
        requireEmployer: (_r, _s, n) => n(),
        disableProcessors: true,
      });
      await installMCPSchema(pool);
      await installRetellSchema(pool);
      await installManagerSchema(pool);
      await installStorageSchema(pool);
      await installCommsSchema(pool);
      await installCollaborationSchema(pool);
      await installNotesSchema(pool);
      app.locals.notes = createNotesWorkspace({ pool });
      const a = randomUUID(),
        b = randomUUID(),
        owner = randomUUID(),
        other = randomUUID(),
        employee = randomUUID();
      await pool.query(
        "INSERT INTO companies(id,name,join_code,owner_user_id,automations_enabled) VALUES($1,'Webhooks A','WHKA',$3,true),($2,'Webhooks B','WHKB',$4,true)",
        [a, b, owner, other],
      );
      for (const [id, cid, role] of [
        [owner, a, "employer"],
        [other, b, "employer"],
        [employee, a, "employee"],
      ]) {
        await pool.query(
          "INSERT INTO users(id,email,display_name,company_id,role) VALUES($1,$2,$3,$4,$5)",
          [id, id + "@example.invalid", "QA", cid, role],
        );
        await pool.query("INSERT INTO sessions(token,user_id) VALUES($1,$2)", [
          id,
          id,
        ]);
      }
      server = await new Promise((r) => {
        const s = app.listen(0, "127.0.0.1", () => r(s));
      });
      const origin = "http://127.0.0.1:" + server.address().port;
      const env = {
        MCP_PUBLIC_ORIGIN: origin,
        MCP_WEB_ORIGIN: origin,
        RETELL_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
      };
      let mode = "ok",
        sent = [];
      const transport = async (request) => {
        sent.push(request);
        if (mode === "timeout")
          throw Object.assign(new Error("delivery_timeout"), {
            code: "delivery_timeout",
            status: 504,
          });
        return {
          status: mode === "throttle" ? 429 : mode === "permanent" ? 400 : 200,
          body: mode === 'bad-json' ? 'accepted' : mode === 'reflect-secret' ? '{"result":"fixture-private-credential"}' : '{"result":"confirmed"}',
          retryAfter: "1",
        };
      };
      const service = await installWebhooks({
        app,
        pool,
        authRequired,
        emitEvent: emitAutomationEvent,
        catalog: webhookEventCatalog(),
        env,
        startWorker: false,
        transport,
      });
      await installWebhookSchema(pool);
      const http = async (path, method = "GET", body, user = owner) => {
        const r = await fetch(origin + path, {
          method,
          headers: {
            Authorization: "Bearer " + user,
            "Content-Type": "application/json",
          },
          body: body === undefined ? undefined : JSON.stringify(body),
        });
        return { status: r.status, body: await r.json() };
      };
      const root = "/api/webhook-connections";
      let c = (
        await http(root, "POST", {
          name: "Bot requests",
          direction: "incoming",
          mappings: [
            { name: "title", path: "/title", type: "text", required: true },
          ],
          dedupe_path: "/event_id",
          allowed_actions: ["task.create"],
        })
      ).body;
      const refresh = async () => {
        c = (await http(root)).body.connections.find((x) => x.id === c.id);
        return c;
      };
      const update = async (changes) => {
        const r = await http(root + "/" + c.id, "PUT", {
          expected_revision: c.revision,
          config: configSchema.parse({
            ...configSchema.parse(cConfig(c)),
            ...changes,
          }),
        });
        if (r.status === 200) c = r.body;
        return r;
      };
      function cConfig(c) {
        return Object.fromEntries(
          Object.keys(configSchema.shape ?? {}).map((k) => [k, c[k]]),
        );
      }
      // The refined Zod schema keeps its shape in this project's Zod version.
      const key = (
        await http(root + "/" + c.id + "/credential", "POST", {
          expected_revision: c.revision,
          name: "ingress",
          generate: true,
        })
      ).body.secret;
      await refresh();
      const workflow = randomUUID(),
        version = randomUUID();
      await pool.query(
        "INSERT INTO automation_definitions(id,company_id,name,status,created_by_user_id,draft_version_id) VALUES($1,$2,'Webhook task','draft',$3,$4)",
        [workflow, a, owner, version],
      );
      await pool.query(
        "INSERT INTO automation_versions(id,automation_id,company_id,version_number,status,created_by_user_id) VALUES($1,$2,$3,1,'draft',$4)",
        [version, workflow, a, owner],
      );
      const trigger = {
        id: randomUUID(),
        node_key: "incoming",
        node_type: "trigger",
        title: "Incoming",
        config: { trigger_key: "incoming.webhook", connection_id: c.id },
        position_x: 0,
        position_y: 0,
      };
      const task = {
        id: randomUUID(),
        node_key: "task",
        node_type: "action",
        title: "Task",
        config: { action_key: "task.create", title: "{{variables.title}}" },
        position_x: 0,
        position_y: 100,
      };
      const condition = {
        id: randomUUID(),
        node_key: "check_title",
        node_type: "condition",
        title: "Has title",
        config: {
          field: "variables.title",
          operator: "contains",
          value: "task",
        },
        position_x: 0,
        position_y: 50,
      };
      await hooks.saveDraftGraph(version, a, {
        nodes: [trigger, condition, task],
        edges: [
          {
            id: randomUUID(),
            source_node_id: trigger.id,
            target_node_id: condition.id,
            source_port: "default",
            priority: 0,
            config: {},
          },
          {
            id: randomUUID(),
            source_node_id: condition.id,
            target_node_id: task.id,
            source_port: "true",
            priority: 0,
            config: {},
          },
        ],
        settings: {},
      });
      const published = await hooks.publishAutomation(workflow, a, owner);
      assert.ok(published, JSON.stringify(published));
      assert.equal((await update({ automation_id: workflow })).status, 200);
      assert.equal(
        (
          await http(root + "/" + c.id + "/preview", "POST", {
            sample: { event_id: "one", title: "Create this task" },
          })
        ).status,
        200,
      );
      await refresh();
      const enabled = await update({ enabled: true });
      assert.equal(enabled.status, 200, JSON.stringify(enabled));
      const send = async (payload, headers = {}) => {
        const r = await fetch(c.endpoint, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: "Bearer " + key,
            ...headers,
          },
          body: JSON.stringify(payload),
        });
        return { status: r.status, body: await r.json() };
      };
      const ownerActor = { userId: owner, companyId: a };
      await t.test(
        "owner-only company isolation, no secret readback, raw auth and validation",
        async () => {
          assert.equal(
            (await http(root, "GET", undefined, employee)).status,
            403,
          );
          assert.equal(
            (
              await http(
                root + "/" + c.id + "/activity",
                "GET",
                undefined,
                other,
              )
            ).status,
            404,
          );
          assert.ok(!JSON.stringify((await http(root)).body).includes(key));
          assert.equal(
            (await send({ event_id: "bad", title: 12 })).status,
            422,
          );
          assert.equal(
            (await send({ title: "bad" }, { Authorization: "Bearer bad" }))
              .status,
            401,
          );
          assert.notEqual(
            (
              await pool.query(
                "SELECT secrets_ciphertext FROM wolf_webhook_connections WHERE id=$1",
                [c.id],
              )
            ).rows[0].secrets_ciphertext,
            key,
          );
        },
      );
      let receipt;
      await t.test(
        "concurrent identified acceptance commits exactly one receipt and holds approval",
        async () => {
          const pair = await Promise.all([
            send({ event_id: "same", title: "Create this task" }),
            send({ event_id: "same", title: "Create this task" }),
          ]);
          assert.ok(
            pair.every((r) => r.status === 202),
            JSON.stringify(pair),
          );
          assert.equal(pair[0].body.receipt_id, pair[1].body.receipt_id);
          receipt = pair[0].body.receipt_id;
          assert.equal(
            (
              await pool.query(
                "SELECT count(*)::int n FROM wolf_webhook_receipts",
              )
            ).rows[0].n,
            1,
          );
          assert.equal(
            (await send({ event_id: "same", title: "different" })).status,
            409,
          );
          await hooks.processAutomationEvents();
          assert.equal(
            (await pool.query("SELECT count(*)::int n FROM todo_tasks")).rows[0]
              .n,
            0,
          );
          const detail = await http(root + "/" + c.id + "/receipts/" + receipt);
          assert.equal(detail.body.mapped.title, "Create this task");
        },
      );
      await t.test(
        "approved receipt uses existing task action, same run and atomic effect on retry",
        async () => {
          assert.equal(
            (
              await http(
                root + "/" + c.id + "/receipts/" + receipt + "/review",
                "POST",
                { approve: true },
              )
            ).status,
            200,
          );
          await hooks.processAutomationEvents();
          const runs = (
            await pool.query(
              "SELECT * FROM automation_runs WHERE automation_id=$1",
              [workflow],
            )
          ).rows;
          assert.equal(runs.length, 1);
          assert.equal(runs[0].status, "completed", runs[0].error_message);
          const tasks = (await pool.query("SELECT title FROM todo_tasks")).rows;
          assert.deepEqual(
            tasks.map((x) => x.title),
            ["Create this task"],
          );
          await pool.query(
            "UPDATE automation_events SET processing_status='pending',processed_at=NULL WHERE id=$1",
            [runs[0].trigger_event_id],
          );
          await hooks.processAutomationEvents();
          assert.equal(
            (await pool.query("SELECT count(*)::int n FROM todo_tasks")).rows[0]
              .n,
            1,
          );
          assert.equal(
            (await pool.query("SELECT count(*)::int n FROM automation_runs"))
              .rows[0].n,
            1,
          );
          // Simulate a crash after effect commit but before node completion.
          await pool.query(
            "UPDATE automation_runs SET status='running' WHERE id=$1",
            [runs[0].id],
          );
          await pool.query(
            "UPDATE automation_run_nodes SET status='running' WHERE run_id=$1 AND node_key=$2",
            [runs[0].id, "task"],
          );
          await hooks.runAutomation(runs[0].id);
          assert.equal(
            (await pool.query("SELECT count(*)::int n FROM todo_tasks")).rows[0]
              .n,
            1,
          );
        },
      );
      await t.test(
        "identical submissions without IDs remain independent; pause and resume preserve accepted policy",
        async () => {
          const x = await send({ title: "Independent" }),
            y = await send({ title: "Independent" });
          assert.notEqual(x.body.receipt_id, y.body.receipt_id);
          assert.equal((await update({ enabled: false })).status, 200);
          assert.equal((await send({ title: "paused" })).status, 409);
          assert.equal((await update({ enabled: true })).status, 200);
          assert.equal(
            (
              await http(
                root +
                  "/" +
                  c.id +
                  "/receipts/" +
                  x.body.receipt_id +
                  "/review",
                "POST",
                { approve: true },
              )
            ).status,
            200,
          );
        },
      );
      await t.test(
        "outgoing stable IDs, bounded retries, uncertain outcomes, redaction and manual retry",
        async () => {
          let d = (
            await http(root, "POST", {
              name: "Receiver",
              direction: "outgoing",
              url: "https://example.com/hook",
              body_template: { title: "{{request.title}}" },
              response_mappings: [
                { name: "result", path: "/result", type: "text" },
              ],
            })
          ).body;
          const data = configSchema.parse(cConfig(d));
          d = (
            await http(root + "/" + d.id, "PUT", {
              expected_revision: d.revision,
              config: { ...data, enabled: true },
            })
          ).body;
          mode = "timeout";
          const first = await service.enqueue(ownerActor, d.id, "stable", {
            request: { title: "test" },
          });
          await service.deliverOne();
          let stored = (
            await pool.query(
              "SELECT * FROM wolf_webhook_deliveries WHERE id=$1",
              [first.id],
            )
          ).rows[0];
          assert.equal(stored.state, "queued");
          assert.equal(stored.uncertain, true);
          mode = "ok";
          await pool.query(
            "UPDATE wolf_webhook_deliveries SET next_attempt_at=now() WHERE id=$1",
            [first.id],
          );
          await service.deliverOne();
          stored = (
            await pool.query(
              "SELECT * FROM wolf_webhook_deliveries WHERE id=$1",
              [first.id],
            )
          ).rows[0];
          assert.equal(stored.state, "delivered", stored.error_code);
          assert.equal(stored.response_mapped.result, "confirmed");
          assert.equal(stored.context_ciphertext, null);
          assert.equal(
            sent[0].headers["Idempotency-Key"],
            sent[1].headers["Idempotency-Key"],
          );
          assert.equal(
            (
              await service.enqueue(ownerActor, d.id, "stable", {
                request: { title: "test" },
              })
            ).id,
            first.id,
          );
          const history = await http(root + "/" + d.id + "/activity");
          assert.ok(!JSON.stringify(history).includes("request"));
          assert.equal(history.body.deliveries[0].attempts, 2);
          assert.deepEqual(
            history.body.deliveries[0].history.map((x) => x.attempt),
            [1, 2],
          );
          mode = "permanent";
          const second = await service.enqueue(ownerActor, d.id, "fail", {
            request: { title: "test" },
          });
          await service.deliverOne();
          assert.equal(
            (
              await http(root + "/" + d.id + "/retry", "POST", {
                kind: "delivery",
                id: second.id,
              })
            ).status,
            200,
          );
          mode = "ok";
          await service.deliverOne();
        },
      );
      await t.test('HTTP acceptance survives response errors without retaining reflected credentials or resending',async()=>{
        for(const responseMode of ['bad-json','reflect-secret']){
          const config=configSchema.parse({name:'Response failure fixture',direction:'outgoing',url:'https://example.com/accepted',body_template:{kind:'fixture'},response_mappings:[{name:'result',path:'/result',type:'text'}]});
          let d=await service.create(ownerActor,config);
          await service.credential(ownerActor,d.id,d.revision,{name:'api_key',value:'fixture-private-credential',generate:false});
          d=(await service.list(ownerActor)).connections.find(c=>c.id===d.id);
          d=await service.update(ownerActor,d.id,d.revision,{...config,enabled:true});
          mode=responseMode;const before=sent.length;
          const queued=await service.enqueue(ownerActor,d.id,'response-failure',{});await service.deliverOne();
          const stored=(await pool.query('SELECT * FROM wolf_webhook_deliveries WHERE id=$1',[queued.id])).rows[0];
          assert.equal(stored.state,'delivered');assert.equal(stored.http_status,200);
          assert.equal(stored.error_code,responseMode==='bad-json'?'response_not_json':'response_contains_secret');
          assert.deepEqual(stored.response_mapped,{});assert.equal(stored.context_ciphertext,null);
          await assert.rejects(()=>service.retry(ownerActor,d.id,'delivery',queued.id));
          await service.deliverOne();assert.equal(sent.length,before+1);
        }
        mode='ok';
      });
      await t.test(
        "outgoing automation waits without blocking and maps a response into a later task",
        async () => {
          let d = (
            await http(root, "POST", {
              name: "Action receiver",
              direction: "outgoing",
              url: "https://example.com/action",
              body_template: { title: "{{request.title}}" },
              response_mappings: [
                { name: "result", path: "/result", type: "text" },
              ],
            })
          ).body;
          d = (
            await http(root + "/" + d.id, "PUT", {
              expected_revision: d.revision,
              config: { ...configSchema.parse(cConfig(d)), enabled: true },
            })
          ).body;
          const id = randomUUID(),
            v = randomUUID();
          await pool.query(
            "INSERT INTO automation_definitions(id,company_id,name,status,created_by_user_id,draft_version_id) VALUES($1,$2,'Outgoing automation','draft',$3,$4)",
            [id, a, owner, v],
          );
          await pool.query(
            "INSERT INTO automation_versions(id,automation_id,company_id,version_number,status,created_by_user_id) VALUES($1,$2,$3,1,'draft',$4)",
            [v, id, a, owner],
          );
          const n = (key, type, config) => ({
            id: randomUUID(),
            node_key: key,
            node_type: type,
            title: key,
            config,
            position_x: 0,
            position_y: 0,
          });
          const begin = n("manual", "trigger", { trigger_key: "manual" }),
            send = n("send", "action", {
              action_key: "webhook.send",
              destination_id: d.id,
              request: { title: "Mapped {{company.name}}" },
            }),
            after = n("after", "action", {
              action_key: "task.create",
              title: "Receiver {{nodes.send.output.response.result}}",
            });
          await hooks.saveDraftGraph(v, a, {
            nodes: [begin, send, after],
            edges: [begin, send].map((n, i) => ({
              id: randomUUID(),
              source_node_id: n.id,
              target_node_id: [send, after][i].id,
              source_port: "default",
              priority: 0,
              config: {},
            })),
            settings: {},
          });
          await hooks.publishAutomation(id, a, owner);
          const started = await hooks.startManualRun(id, a, owner, {
            subject_type: "generic",
          });
          await hooks.runAutomation(started.id);
          let run = (
            await pool.query("SELECT * FROM automation_runs WHERE id=$1", [
              started.id,
            ])
          ).rows[0];
          assert.equal(run.status, "waiting", run.error_message);
          // Another iteration of this node may still be waiting on a different
          // receiver request. Settling this response must not overwrite it.
          const otherScopeNode = randomUUID();
          await pool.query(
            "INSERT INTO automation_run_nodes(id,run_id,node_id,node_key,status,scope_key,output_snapshot) SELECT $2,run_id,node_id,node_key,'waiting','root/foreach:pending:item:1','{\"pending\":true}' FROM automation_run_nodes WHERE run_id=$1 AND node_key='send' AND status='waiting' LIMIT 1",
            [started.id, otherScopeNode],
          );
          mode = "ok";
          await service.deliverOne();
          await hooks.processDueWaits();
          const untouched = (
            await pool.query(
              "SELECT status,output_snapshot FROM automation_run_nodes WHERE id=$1",
              [otherScopeNode],
            )
          ).rows[0];
          assert.equal(untouched.status, "waiting");
          assert.deepEqual(untouched.output_snapshot, { pending: true });
          await pool.query("DELETE FROM automation_run_nodes WHERE id=$1", [
            otherScopeNode,
          ]);
          run = (
            await pool.query("SELECT * FROM automation_runs WHERE id=$1", [
              started.id,
            ])
          ).rows[0];
          assert.equal(run.status, "completed", run.error_message);
          assert.equal(
            (
              await pool.query(
                "SELECT count(*)::int n FROM todo_tasks WHERE title='Receiver confirmed'",
              )
            ).rows[0].n,
            1,
          );
          assert.equal(JSON.parse(sent.at(-1).body).title, "Mapped Webhooks A");
        },
      );
      await t.test(
        "delivery restart recovery, denied schedules and subscription uses canonical event ID",
        async () => {
          let d = (
            await http(root, "POST", {
              name: "Subscription receiver",
              direction: "outgoing",
              url: "https://example.com/events",
              subscriptions: ["contact.created"],
            })
          ).body;
          d = (
            await http(root + "/" + d.id, "PUT", {
              expected_revision: d.revision,
              config: { ...configSchema.parse(cConfig(d)), enabled: true },
            })
          ).body;
          const contact = randomUUID();
          await pool.query(
            "INSERT INTO contacts(id,company_id,user_id,name) VALUES($1,$2,$3,'Selected data only')",
            [contact, a, owner],
          );
          const e = await emitAutomationEvent({
            companyId: a,
            eventType: "contact.created",
            subjectType: "contact",
            subjectId: contact,
            payload: { name: "Selected data only" },
          });
          mode = "ok";
          await service.drain();
          const deliveries = (
            await pool.query(
              "SELECT * FROM wolf_webhook_deliveries WHERE connection_id=$1",
              [d.id],
            )
          ).rows;
          assert.equal(deliveries.length, 1);
          assert.equal(deliveries[0].identity, "event:" + e);
          await service.drain();
          assert.equal(
            (
              await pool.query(
                "SELECT count(*)::int n FROM wolf_webhook_deliveries WHERE connection_id=$1",
                [d.id],
              )
            ).rows[0].n,
            1,
          );
          const queued = await service.enqueue(ownerActor, d.id, "restart", {
            event: {
              id: "restart",
              type: "test",
              timestamp: new Date().toISOString(),
              data: {},
            },
          });
          await pool.query(
            "UPDATE wolf_webhook_deliveries SET state='processing',lease_until=now()-interval '1 minute' WHERE id=$1",
            [queued.id],
          );
          await service.deliverOne();
          const stored = (
            await pool.query(
              "SELECT * FROM wolf_webhook_deliveries WHERE id=$1",
              [queued.id],
            )
          ).rows[0];
          assert.equal(stored.state, "delivered");
          assert.equal(stored.uncertain, true);
          await http(root + "/" + d.id, "PUT", {
            expected_revision: d.revision,
            config: {
              ...configSchema.parse(cConfig(d)),
              operating_hours: {
                timezone: "UTC",
                mode: "allowed",
                windows: [],
                exceptions: [],
              },
            },
          });
          await assert.rejects(
            service.enqueue(ownerActor, d.id, "blocked", {}),
            (e) => e.code === "outside_operating_hours",
          );
        },
      );
      await t.test(
        "incoming shared contact, Note and scheduling actions; approval, access and replay",
        async () => {
          async function incoming(action, config, { allowed = [action] } = {}) {
            let connection = (
              await http(root, "POST", {
                name: "QA " + action,
                direction: "incoming",
                allowed_actions: allowed,
                mappings: [
                  {
                    name: "title",
                    path: "/title",
                    type: "text",
                    required: true,
                  },
                ],
              })
            ).body;
            const secret = (
              await http(root + "/" + connection.id + "/credential", "POST", {
                expected_revision: connection.revision,
                generate: true,
              })
            ).body.secret;
            connection = (await http(root)).body.connections.find(
              (x) => x.id === connection.id,
            );
            const workflow = randomUUID(),
              v = randomUUID(),
              begin = randomUUID(),
              step = randomUUID();
            await pool.query(
              "INSERT INTO automation_definitions(id,company_id,name,status,created_by_user_id,draft_version_id) VALUES($1,$2,'Action QA','draft',$3,$4)",
              [workflow, a, owner, v],
            );
            await pool.query(
              "INSERT INTO automation_versions(id,automation_id,company_id,version_number,status,created_by_user_id) VALUES($1,$2,$3,1,'draft',$4)",
              [v, workflow, a, owner],
            );
            const nodes = [
              {
                id: begin,
                node_key: "incoming",
                node_type: "trigger",
                title: "Incoming",
                config: {
                  trigger_key: "incoming.webhook",
                  connection_id: connection.id,
                },
                position_x: 0,
                position_y: 0,
              },
              {
                id: step,
                node_key: "action",
                node_type: "action",
                title: "Action",
                config: { action_key: action, ...config },
                position_x: 0,
                position_y: 100,
              },
            ];
            await hooks.saveDraftGraph(v, a, {
              nodes,
              edges: [
                {
                  id: randomUUID(),
                  source_node_id: begin,
                  target_node_id: step,
                  source_port: "default",
                  priority: 0,
                  config: {},
                },
              ],
              settings: {},
            });
            const published = await hooks.publishAutomation(workflow, a, owner);
            assert.ok(
              !published.validation || published.validation.valid,
              JSON.stringify(published),
            );
            connection = (
              await http(root + "/" + connection.id, "PUT", {
                expected_revision: connection.revision,
                config: {
                  ...configSchema.parse(cConfig(connection)),
                  automation_id: workflow,
                },
              })
            ).body;
            await http(root + "/" + connection.id + "/preview", "POST", {
              sample: { title: "QA action" },
            });
            const enabled = await http(root + "/" + connection.id, "PUT", {
              expected_revision: connection.revision,
              config: {
                ...configSchema.parse(cConfig(connection)),
                enabled: true,
              },
            });
            assert.equal(enabled.status, 200, JSON.stringify(enabled));
            connection = enabled.body;
            const response = await fetch(connection.endpoint, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Authorization: "Bearer " + secret,
              },
              body: JSON.stringify({ title: "QA action" }),
            });
            assert.equal(response.status, 202);
            const receipt = await response.json();
            await http(
              root +
                "/" +
                connection.id +
                "/receipts/" +
                receipt.receipt_id +
                "/review",
              "POST",
              { approve: true },
            );
            return { connection, receipt, workflow, step };
          }
          const contact = randomUUID();
          await pool.query(
            "INSERT INTO contacts(id,company_id,user_id,name) VALUES($1,$2,$3,'Before webhook')",
            [contact, a, owner],
          );
          const changed = await incoming("contact.update_fields", {
            target_mode: "specific_contact",
            contact_id: contact,
            name: "{{variables.title}}",
          });
          await hooks.processAutomationEvents();
          assert.equal(
            (
              await pool.query("SELECT name FROM contacts WHERE id=$1", [
                contact,
              ])
            ).rows[0].name,
            "QA action",
          );
          const note = await incoming("note.create", {
            title: "Webhook shared Note",
            text: "{{variables.title}}",
          });
          await hooks.processAutomationEvents();
          const noteRun = (
            await pool.query(
              "SELECT * FROM automation_runs WHERE automation_id=$1",
              [note.workflow],
            )
          ).rows[0];
          assert.equal(noteRun.status, "completed", noteRun.error_message);
          assert.equal(
            (
              await pool.query(
                "SELECT count(*)::int n FROM comms_notes WHERE title='Webhook shared Note'",
              )
            ).rows[0].n,
            1,
          );
          const start = "2031-06-03T15:00:00Z",
            end = "2031-06-03T16:00:00Z";
          const job = await incoming("job.create", {
            title: "Webhook approved booking",
            start_at: start,
            end_at: end,
            contact_id: contact,
          });
          await hooks.processAutomationEvents();
          const jobRun = (
            await pool.query(
              "SELECT * FROM automation_runs WHERE automation_id=$1",
              [job.workflow],
            )
          ).rows[0];
          assert.equal(jobRun.status, "completed", jobRun.error_message);
          assert.equal(
            (
              await pool.query(
                "SELECT count(*)::int n FROM schedule_events WHERE title='Webhook approved booking'",
              )
            ).rows[0].n,
            1,
          );
          const denied = await incoming(
            "contact.update_fields",
            {
              target_mode: "specific_contact",
              contact_id: contact,
              name: "Must not change",
            },
            { allowed: ["task.create"] },
          );
          await hooks.processAutomationEvents();
          assert.equal(
            (
              await pool.query("SELECT name FROM contacts WHERE id=$1", [
                contact,
              ])
            ).rows[0].name,
            "QA action",
          );
          assert.equal(
            (
              await pool.query(
                "SELECT status FROM automation_runs WHERE automation_id=$1",
                [denied.workflow],
              )
            ).rows[0].status,
            "failed",
          );
          const access = await incoming("task.create", {
            title: "Revoked worker must not create",
          });
          await pool.query(
            "UPDATE companies SET owner_user_id=$2 WHERE id=$1",
            [a, employee],
          );
          await hooks.processAutomationEvents();
          assert.equal(
            (
              await pool.query(
                "SELECT count(*)::int n FROM todo_tasks WHERE title='Revoked worker must not create'",
              )
            ).rows[0].n,
            0,
          );
          await pool.query(
            "UPDATE companies SET owner_user_id=$2 WHERE id=$1",
            [a, owner],
          );
          const replayPath =
            root +
            "/" +
            note.connection.id +
            "/receipts/" +
            note.receipt.receipt_id +
            "/replay";
          assert.equal((await http(replayPath, "POST", {})).status, 400);
          const replay = await http(replayPath, "POST", {
            create_new_execution: true,
          });
          assert.equal(replay.status, 202);
          assert.notEqual(replay.body.receipt_id, note.receipt.receipt_id);
          await hooks.processAutomationEvents();
          assert.equal(
            (
              await pool.query(
                "SELECT count(*)::int n FROM comms_notes WHERE title='Webhook shared Note'",
              )
            ).rows[0].n,
            1,
          );
          await http(
            root +
              "/" +
              note.connection.id +
              "/receipts/" +
              replay.body.receipt_id +
              "/review",
            "POST",
            { approve: true },
          );
          await hooks.processAutomationEvents();
          assert.equal(
            (
              await pool.query(
                "SELECT count(*)::int n FROM comms_notes WHERE title='Webhook shared Note'",
              )
            ).rows[0].n,
            2,
          );
          await pool.query(
            "UPDATE wolf_webhook_receipts SET expires_at=now()-interval '1 second' WHERE connection_id=$1",
            [note.connection.id],
          );
          await service.drain();
          assert.equal(
            (await http(replayPath, "POST", { create_new_execution: true }))
              .status,
            409,
          );
          assert.equal(
            (
              await pool.query(
                "SELECT count(*)::int n FROM automation_variables WHERE run_id=$1",
                [noteRun.id],
              )
            ).rows[0].n,
            0,
          );
        },
      );
      await t.test(
        "recovery preserves a completed condition branch and does not duplicate the task",
        async () => {
          const accepted = await send({
            event_id: "crash-branch",
            title: "Recovery task",
          });
          assert.equal(accepted.status, 202);
          await http(
            root +
              "/" +
              c.id +
              "/receipts/" +
              accepted.body.receipt_id +
              "/review",
            "POST",
            { approve: true },
          );
          const original = service.action;
          service.action = async (run, node, ...rest) => {
            if (node.node_key === "task" && run.automation_id === workflow)
              throw new Error("simulated_before_effect");
            return original(run, node, ...rest);
          };
          try {
            await hooks.processAutomationEvents();
          } finally {
            service.action = original;
          }
          const crashed = (
            await pool.query(
              "SELECT a.* FROM automation_runs a JOIN wolf_webhook_receipts r ON r.event_id=a.trigger_event_id WHERE r.id=$1",
              [accepted.body.receipt_id],
            )
          ).rows[0];
          assert.equal(crashed.status, "failed");
          await pool.query(
            "UPDATE automation_runs SET status='running',updated_at=now()-interval '1 minute' WHERE id=$1",
            [crashed.id],
          );
          await hooks.processDueWaits();
          assert.equal(
            (
              await pool.query(
                "SELECT count(*)::int n FROM todo_tasks WHERE title='Recovery task'",
              )
            ).rows[0].n,
            1,
          );
          assert.equal(
            (
              await pool.query(
                "SELECT status FROM automation_runs WHERE id=$1",
                [crashed.id],
              )
            ).rows[0].status,
            "completed",
          );
          await hooks.processDueWaits();
          assert.equal(
            (
              await pool.query(
                "SELECT count(*)::int n FROM todo_tasks WHERE title='Recovery task'",
              )
            ).rows[0].n,
            1,
          );
        },
      );
      await t.test(
        "record access is rechecked immediately before network delivery; HTTP parser bounds",
        async () => {
          const invalidManagement = await fetch(origin + root, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: "Bearer " + owner,
            },
            body: "{invalid}",
          });
          assert.equal(invalidManagement.status, 400);
          assert.deepEqual(await invalidManagement.json(), {
            error: "invalid_json",
          });
          const publicOrigin = env.MCP_PUBLIC_ORIGIN;
          delete env.MCP_PUBLIC_ORIGIN;
          assert.equal(
            (
              await http(root, "POST", {
                name: "Missing origin",
                direction: "incoming",
              })
            ).body.error,
            "webhook_public_origin_required",
          );
          env.MCP_PUBLIC_ORIGIN = publicOrigin;
          const tooLarge = await fetch(c.endpoint, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: "Bearer " + key,
            },
            body: JSON.stringify({ title: "x".repeat(65537) }),
          });
          assert.equal(tooLarge.status, 413);
          assert.equal((await tooLarge.json()).error, "payload_too_large");
          const invalidFormat = await fetch(c.endpoint, {
            method: "POST",
            headers: { "Content-Type": "text/plain" },
            body: "{}",
          });
          assert.equal(invalidFormat.status, 415);
          const record = randomUUID();
          await pool.query(
            "INSERT INTO contacts(id,company_id,user_id,name) VALUES($1,$2,$3,'Access checked again')",
            [record, a, owner],
          );
          let d = (
            await http(root, "POST", {
              name: "Live source access",
              direction: "outgoing",
              url: "https://example.com/events",
              body_template: { id: "{{event.data.id}}" },
            })
          ).body;
          d = (
            await http(root + "/" + d.id, "PUT", {
              expected_revision: d.revision,
              config: { ...configSchema.parse(cConfig(d)), enabled: true },
            })
          ).body;
          const queued = await service.enqueue(
            ownerActor,
            d.id,
            "private-source",
            { event: { data: { id: record } } },
            { sourceRef: { entity: "contacts", id: record } },
          );
          await pool.query("UPDATE contacts SET deleted_at=now() WHERE id=$1", [
            record,
          ]);
          const count = sent.length;
          await service.deliverOne();
          assert.equal(sent.length, count);
          assert.equal(
            (
              await pool.query(
                "SELECT state FROM wolf_webhook_deliveries WHERE id=$1",
                [queued.id],
              )
            ).rows[0].state,
            "failed",
          );
          await pool.query("UPDATE contacts SET deleted_at=NULL WHERE id=$1", [
            record,
          ]);
          await service.retry(ownerActor, d.id, "delivery", queued.id);
          await service.deliverOne();
          assert.equal(sent.length, count + 1);
          await pool.query(
            "UPDATE companies SET automations_enabled=false WHERE id=$1",
            [a],
          );
          await assert.rejects(
            service.enqueue(
              ownerActor,
              d.id,
              "company-paused",
              {},
              { test: true },
            ),
            (error) => error.code === "company_automations_paused",
          );
          assert.equal(
            (await send({ title: "company paused" })).body.error,
            "company_automations_paused",
          );
          await pool.query(
            "UPDATE companies SET automations_enabled=true,automation_emergency_stopped_at=now() WHERE id=$1",
            [a],
          );
          await assert.rejects(
            service.enqueue(
              ownerActor,
              d.id,
              "emergency-stop",
              {},
              { test: true },
            ),
            (error) => error.code === "company_automations_paused",
          );
          await pool.query(
            "UPDATE companies SET automation_emergency_stopped_at=NULL WHERE id=$1",
            [a],
          );
        },
      );
      await t.test(
        "HMAC replay and rotation, revocation and current owner membership",
        async () => {
          await update({ enabled: false, auth_mode: "hmac" });
          await http(root + "/" + c.id + "/preview", "POST", {
            sample: { title: "hmac" },
          });
          await refresh();
          await update({ enabled: true });
          const timestamp = String(Math.floor(Date.now() / 1000)),
            nonce = randomBytes(16).toString("hex"),
            raw = Buffer.from(JSON.stringify({ title: "signed" }));
          const headers = {
            "x-wolf-timestamp": timestamp,
            "x-wolf-nonce": nonce,
            "x-wolf-signature": "v1=" + sign(key, timestamp, nonce, raw),
          };
          assert.equal((await send({ title: "signed" }, headers)).status, 202);
          assert.equal((await send({ title: "signed" }, headers)).status, 409);
          await http(root + "/" + c.id + "/credential", "POST", {
            expected_revision: c.revision,
            name: "ingress",
            generate: true,
          });
          await refresh();
          assert.equal((await send({ title: "signed" }, headers)).status, 401);
          await pool.query(
            "UPDATE companies SET owner_user_id=$2 WHERE id=$1",
            [a, employee],
          );
          assert.equal((await http(root)).status, 403);
          await pool.query(
            "UPDATE companies SET owner_user_id=$2 WHERE id=$1",
            [a, owner],
          );
          assert.equal(
            (
              await http(root + "/" + c.id + "/revoke", "POST", {
                expected_revision: c.revision,
              })
            ).status,
            200,
          );
        },
      );
      await t.test(
        "MCP registry exposes configuration/status without credential capabilities",
        () => {
          const tools = [];
          registerWebhookTools((...args) => tools.push(args), {
            actor: ownerActor,
            app,
          });
          assert.equal(tools.length, 7);
          // Match the existing transport's object extension contract. A JSON
          // union output or refined top-level input breaks all MCP discovery.
          for (const [, , input, output] of tools) {
            assert.doesNotThrow(() =>
              input.extend({ _request_id: z.uuid().optional() }),
            );
            assert.doesNotThrow(() =>
              output.partial().extend({ approval_id: z.string().optional() }),
            );
          }
          assert.ok(
            tools.every(
              (x) => !x[0].includes("secret") && !x[0].includes("credential"),
            ),
          );
          assert.ok(
            tools
              .filter(
                (x) => !["webhooks_list", "webhooks_activity"].includes(x[0]),
              )
              .every((x) => x[7] === true),
          );
        },
      );
      await t.test(
        "MCP SDK discovery, native approval and retry use the shared webhook service",
        async () => {
          await installMCP({
            app,
            pool,
            rawPool: backend.rawPool,
            authRequired,
            env: {
              ...env,
              MCP_ENABLED: "true",
              NODE_ENV: "test",
              MCP_REDIRECT_URIS: '["https://client.example.invalid/callback"]',
            },
            startMaintenance: false,
            verifyIdentity: async () => null,
          });
          const base = "/api/ai-connections/manager";
          const created = await http(base, "POST", {
            expected_company_id: a,
            name: "Webhook SDK fixture",
            provider: "Generic",
          });
          assert.equal(created.status, 201);
          let connection = created.body;
          const guard = () => ({
            expected_company_id: a,
            expected_revision: connection.revision,
          });
          const refreshConnection = async () => {
            connection = (await http(base)).body.connections.find(
              (x) => x.id === connection.id,
            );
          };
          const keyResponse = await http(
            base + "/" + connection.id + "/key",
            "POST",
            { ...guard(), valid_days: 1 },
          );
          assert.equal(keyResponse.status, 200);
          await refreshConnection();
          const saved = await http(base + "/" + connection.id, "PUT", {
            ...guard(),
            name: connection.name,
            description: connection.description,
            provider: connection.provider,
            enabled: true,
            paused_until: null,
            operating_hours: connection.operating_hours,
            automatic_booking: false,
            tool_policy: {
              webhooks_list: { allow: true, approval: false },
              webhooks_create: { allow: true, approval: true },
              webhooks_update: { allow: true, approval: false },
            },
          });
          assert.equal(saved.status, 200);
          const client = new Client({
            name: "Webhook SDK verification",
            version: "1",
          });
          try {
            await client.connect(
              new StreamableHTTPClientTransport(new URL(origin + "/mcp"), {
                requestInit: {
                  headers: { Authorization: keyResponse.body.authorization },
                },
              }),
            );
            assert.deepEqual(
              (await client.listTools()).tools.map((x) => x.name).sort(),
              ["webhooks_create", "webhooks_list", "webhooks_update"],
            );
            const call = async (name, args = {}) => {
              const result = await client.callTool({ name, arguments: args });
              assert.ok(!result.isError, JSON.stringify(result));
              return (
                result.structuredContent || JSON.parse(result.content[0].text)
              );
            };
            const listing = await call("webhooks_list");
            assert.ok(
              listing.connections.every(
                (x) =>
                  x.company_id === a && !Object.hasOwn(x, "secrets_ciphertext"),
              ),
            );
            const args = {
              name: "Approved through MCP",
              direction: "incoming",
              enabled: true,
              auth_mode: "hmac",
              mappings: [
                { name: "title", path: "/title", type: "text", required: true },
              ],
              _request_id: randomUUID(),
            };
            const pending = await call("webhooks_create", args);
            assert.equal(pending.state, "pending");
            assert.ok(
              !(await http(root)).body.connections.some(
                (x) => x.name === args.name,
              ),
            );
            const approval = (await http(base)).body.approvals.find(
              (x) => x.id === pending.approval_id,
            );
            const accepted = await http(
              "/api/ai-connections/approvals/" + pending.approval_id,
              "POST",
              { expected_hash: approval.input_hash, decision: "approve" },
            );
            assert.equal(accepted.status, 200);
            assert.equal(accepted.body.result.enabled, false);
            const repeated = await call("webhooks_create", args);
            assert.equal(repeated.result.id, accepted.body.result.id);
            assert.equal(
              (await http(root)).body.connections.filter(
                (x) => x.name === args.name,
              ).length,
              1,
            );
            const updated = await call("webhooks_update", {
              id: accepted.body.result.id,
              expected_revision: accepted.body.result.revision,
              config: {
                description:
                  "Partial edit preserves mapping and authentication",
              },
              _request_id: randomUUID(),
            });
            const detail = await call("webhooks_list", { id: updated.id });
            assert.equal(detail.connection.auth_mode, "hmac");
            assert.equal(detail.connection.mappings.length, 1);
            assert.equal(detail.connection.enabled, false);
            assert.equal(
              detail.connection.description,
              "Partial edit preserves mapping and authentication",
            );
          } finally {
            await client.close();
          }
        },
      );
    } finally {
      if (server) await new Promise((r) => server.close(r));
      if (backend) await backend.pool.end();
      pg.stop();
    }
  },
);
