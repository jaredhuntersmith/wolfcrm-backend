// Disposable simulator fixture. No provider clients and no external HTTP transport.
import { randomUUID, randomBytes } from "node:crypto";
import { startLocalPostgres } from "./local-postgres.js";
import {
  installAutomationSystem,
  emitAutomationEvent,
  webhookEventCatalog,
} from "../../automations.js";
import { installMCPSchema } from "../../mcp/schema.js";
import { installRetellSchema } from "../../retell/schema.js";
import { installManagerSchema } from "../../mcp/manager-schema.js";
import { installWebhooks } from "../../webhooks/service.js";
const pg = startLocalPostgres();
pg.configureEnvironment();
const { app, pool, bootstrap, authRequired } = await import("../../index.js");
let server;
async function close() {
  if (server) await new Promise((r) => server.close(r));
  await pool.end();
  pg.stop();
}
try {
  await bootstrap();
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
  const companyId = randomUUID(),
    userId = randomUUID();
  await pool.query(
    "INSERT INTO companies(id,name,join_code,owner_user_id,automations_enabled) VALUES($1,'Webhook QA','WEBHOOK-QA',$2,true)",
    [companyId, userId],
  );
  await pool.query(
    "INSERT INTO users(id,email,display_name,company_id,role) VALUES($1,'webhook-qa@example.invalid','Webhook QA',$2,'employer')",
    [userId, companyId],
  );
  await pool.query(
    "INSERT INTO sessions(token,user_id) VALUES('webhook-native-fixture',$1)",
    [userId],
  );
  const service = await installWebhooks({
    app,
    pool,
    authRequired,
    emitEvent: emitAutomationEvent,
    catalog: webhookEventCatalog(),
    env: {
      MCP_PUBLIC_ORIGIN: "http://127.0.0.1:18657",
      RETELL_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
    },
    startWorker: true,
    transport: async () => ({
      status: 200,
      body: '{"accepted":true}',
      retryAfter: null,
    }),
  });
  await service.create(
    { companyId, userId },
    {
      name: "Bot task requests",
      description: "Local QA fixture",
      direction: "incoming",
      allowed_actions: ["task.create"],
      mappings: [
        { name: "title", path: "/title", type: "text", required: true },
      ],
    },
  );
  await service.create(
    { companyId, userId },
    {
      name: "Bot notifications",
      direction: "outgoing",
      url: "https://example.com/events",
      subscriptions: ["contact.created"],
    },
  );
  server = await new Promise((r) => {
    const s = app.listen(18657, "127.0.0.1", () => r(s));
  });
  process.on("SIGTERM", () => close().then(() => process.exit()));
  process.on("SIGINT", () => close().then(() => process.exit()));
  console.log(
    "Disposable native fixture ready on 127.0.0.1:18657. External transport is simulated.",
  );
} catch (error) {
  await close();
  throw error;
}
