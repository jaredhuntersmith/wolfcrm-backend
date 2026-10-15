// Local-only synthetic Meta provider + real disposable PostgreSQL, auth and import routes.
// Never loads .env/DATABASE_URL or contacts a provider. Used by Web Playwright QA.
import { randomUUID } from "node:crypto";
import { startLocalPostgres } from "../tests/helpers/local-postgres.js";
import { installFacebookLeads } from "../facebook-leads/index.js";
import { encrypt, PERMISSIONS } from "../facebook-leads/provider.js";
import {
  installAutomationSystem,
  emitAutomationEvent,
} from "../automations.js";
import {
  installGoogleSheetsSchema,
  installGoogleSheetsSystem,
} from "../google-sheets.js";
const pg = startLocalPostgres();
pg.configureEnvironment();
const backend = await import("../index.js");
const { pool, app } = backend;
await backend.bootstrap();
await installAutomationSystem({
  ...backend,
  requireEmployer: backend.requireCapability("integrations.manage"),
  disableProcessors: true,
});
await installGoogleSheetsSchema(pool);
installGoogleSheetsSystem({
  ...backend,
  requireEmployer: backend.requireCapability("integrations.manage"),
  requireIntegrationView: backend.requireCapability("integrations.view"),
});
const company = randomUUID(),
  owner = randomUUID();
await pool.query(
  "INSERT INTO companies(id,name,join_code,owner_user_id) VALUES($1,'Facebook Leads QA','FB-LOCAL',$2)",
  [company, owner],
);
await pool.query(
  "INSERT INTO users(id,email,role,company_id) VALUES($1,'facebook-qa@example.invalid','employer',$2)",
  [owner, company],
);
await pool.query(
  "INSERT INTO sessions(token,user_id) VALUES('facebook-local-fixture',$1)",
  [owner],
);
const env = {
  FACEBOOK_LEADS_APP_ID: "999",
  FACEBOOK_LEADS_APP_SECRET: "fixture-only",
  FACEBOOK_LEADS_VERIFY_TOKEN: "fixture-only-verify",
  FACEBOOK_LEADS_ENCRYPTION_KEY: Buffer.alloc(32, 8).toString("base64"),
  FACEBOOK_LEADS_WORKER_ENABLED: "true",
};
const graph = {
  configured: () => true,
  all: async (path) =>
    path === "me/accounts"
      ? [
          {
            id: "10",
            name: "Synthetic Window Company",
            access_token: "fixture-page",
          },
        ]
      : path === "me/permissions"
        ? PERMISSIONS.map((permission) => ({ permission, status: "granted" }))
        : path.endsWith("/subscribed_apps")
          ? [{ id: "999", subscribed_fields: ["leadgen"] }]
          : ["20", "21"].map((id) => ({
              id,
              name: id === "20" ? "Window Cleaning" : "Gutter Cleaning",
              questions: [
                { key: "full_name", label: "Full name" },
                { key: "email", label: "Email" },
                { key: "services", label: "Which services?" },
                { key: "private", label: "Private answer" },
              ],
            })),
  request: async () => ({ success: true }),
  page: async () => ({ data: [], cursor: null }),
  lead: async (id) => ({
    lead: {
      id,
      form_id: "20",
      created_time: new Date().toISOString(),
      field_data: [
        { name: "full_name", values: ["Synthetic Facebook Customer"] },
        { name: "email", values: ["synthetic@example.invalid"] },
        { name: "services", values: ["Windows", "Gutters", "こんにちは"] },
        { name: "private", values: ["DO_NOT_RETAIN_BROWSER_SENTINEL"] },
      ],
    },
    issues: [],
  }),
  leads: async () => ({
    data: [{ id: "101", created_time: new Date().toISOString() }],
    cursor: null,
  }),
};
const system = await installFacebookLeads({
  ...backend,
  env,
  graph,
  emitAutomationEvent,
  startWorker: false,
  markContactDirty: async () => {},
  sendPushToUsers: async () => {},
});
await pool.query(
  "INSERT INTO facebook_lead_connections(company_id,user_id,meta_user_id,token,status) VALUES($1,$2,'1000',$3,'authorized')",
  [company, owner, encrypt("fixture-user", company, env)],
);
await system.store.refresh(company);
await system.store.inspectPage(company, "10", true);
app.post("/__qa/import", async (_req, res) => {
  try {
    await system.store.webhook({
      object: "page",
      entry: [
        {
          id: "10",
          changes: [
            {
              field: "leadgen",
              value: { page_id: "10", form_id: "20", leadgen_id: "101" },
            },
          ],
        },
      ],
    });
    const job = await system.worker.claim("facebook_lead_jobs");
    if (job) await system.worker.processJob(job);
    res.json(await system.store.activity(company));
  } catch {
    res.sendStatus(500);
  }
});
app.get("/__qa/state", async (_req, res) =>
  res.json({
    ready: true,
    contacts: (
      await pool.query(
        "SELECT id,name,lead_info FROM contacts WHERE company_id=$1",
        [company],
      )
    ).rows,
  }),
);
const server = app.listen(4141, "127.0.0.1", () =>
  console.log("Facebook Leads synthetic QA ready on localhost:4141"),
);
async function stop() {
  system.stop();
  server.closeAllConnections();
  await new Promise((r) => server.close(r));
  await pool.end();
  pg.stop();
  process.exit(0);
}
process.on("SIGTERM", () => void stop());
process.on("SIGINT", () => void stop());
