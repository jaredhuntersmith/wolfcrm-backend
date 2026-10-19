// Disposable native QA server. All Meta traffic is a fixture; production env is never used.
import { randomUUID } from "node:crypto";
import { writeFileSync } from "node:fs";
import { startLocalPostgres } from "./local-postgres.js";
import {
  installAutomationSystem,
  emitAutomationEvent,
} from "../../automations.js";
import { installFacebookAds } from "../../facebook-ads/index.js";
import { AdsGraph } from "../../facebook-ads/provider.js";
import { encrypt } from "../../facebook-leads/provider.js";
import { installFacebookLeads } from "../../facebook-leads/index.js";
import { installFacebookConnection } from "../../facebook-connection/index.js";
import { COMBINED_PERMISSIONS } from "../../facebook-connection/provider.js";
const pg = startLocalPostgres();
pg.configureEnvironment();
const backend = await import("../../index.js");
await backend.bootstrap();
await installAutomationSystem({
  ...backend,
  requireEmployer: backend.requireCapability("automations.manage"),
  disableProcessors: true,
});
const { rawPool: pool, app } = backend;
const company = randomUUID(),
  user = randomUUID(),
  token = "facebook-ads-local-fixture";
await pool.query(
  "INSERT INTO companies(id,name,join_code,owner_user_id) VALUES($1,'Ads QA Company',$3,$2)",
  [company, user, company],
);
await pool.query(
  "INSERT INTO users(id,email,display_name,role,company_id) VALUES($1,'ads-qa@example.invalid','Ads QA','employer',$2)",
  [user, company],
);
await pool.query("INSERT INTO sessions(token,user_id) VALUES($1,$2)", [
  token,
  user,
]);
const env = {
  FACEBOOK_ADS_ENABLED: "true",
  FACEBOOK_LEADS_LOGIN_CONFIG_ID: "fixture-config",
  FACEBOOK_LEADS_REDIRECT_URI:
    "https://example.invalid/api/integrations/facebook-leads/oauth/callback",
  FACEBOOK_LEADS_VERIFY_TOKEN: "fixture-verify",
  FACEBOOK_ADS_WORKER_ENABLED: "false",
  FACEBOOK_LEADS_ENCRYPTION_KEY: Buffer.alloc(32, 3).toString("base64"),
  FACEBOOK_LEADS_APP_ID: "9",
  FACEBOOK_LEADS_APP_SECRET: "fixture",
  FACEBOOK_ADS_REDIRECT_URI:
    "https://example.invalid/api/facebook-ads/oauth/callback",
};
const account = {
  account_id: "10",
  name: "Local QA ad account",
  currency: "USD",
  timezone_name: "America/New_York",
  account_status: 1,
  min_daily_budget: "100",
  user_tasks: ["MANAGE"],
};
const entities = {
  campaign: [
    {
      id: "101",
      account_id: "10",
      name: "Autumn window cleaning",
      status: "PAUSED",
      effective_status: "PAUSED",
      daily_budget: "2500",
      objective: "OUTCOME_LEADS",
    },
    {
      id: "102",
      account_id: "10",
      name: "Retargeting homeowners",
      status: "ACTIVE",
      effective_status: "ACTIVE",
      daily_budget: "1500",
    },
  ],
  adset: [
    {
      id: "201",
      account_id: "10",
      name: "Local homeowners",
      status: "ACTIVE",
      effective_status: "CAMPAIGN_PAUSED",
      campaign_id: "101",
      daily_budget: "0",
      campaign: {
        id: "101",
        name: "Autumn window cleaning",
        daily_budget: "2500",
        status: "PAUSED",
      },
    },
  ],
  ad: [
    {
      id: "301",
      account_id: "10",
      name: "Fall exterior offer",
      status: "ACTIVE",
      effective_status: "CAMPAIGN_PAUSED",
      campaign_id: "101",
      adset_id: "201",
      creative: {
        id: "401",
        title: "Clear windows for fall",
        body: "Fixture creative. No real advertising delivery.",
      },
    },
  ],
};
const graph = new AdsGraph(env);
graph.loginURL = () => {
  throw new Error(
    "OAuth is not exercised against real Facebook in this fixture",
  );
};
graph.all = async (p) => {
  if (p === "me/permissions")
    return COMBINED_PERMISSIONS.map((permission) => ({
      permission,
      status: "granted",
    }));
  if (p === "me/adaccounts") return [account];
  if (p === "me/accounts")
    return [
      {
        id: "20",
        name: "Fixture Window Wolves Page",
        access_token: "fixture-page-token",
      },
    ];
  if (p === "20/subscribed_apps")
    return [{ id: "9", subscribed_fields: ["leadgen"] }];
  if (p === "20/leadgen_forms")
    return [
      {
        id: "30",
        name: "Fixture lead form",
        questions: [{ key: "full_name", label: "Full name" }],
      },
    ];
  throw Error("Unexpected local fixture discovery");
};
graph.request = async (p, t, params = {}, method = "GET") => {
  if (p === "act_10") return account;
  if (p === "act_10/insights") return { report_run_id: "900" };
  if (p === "900")
    return { async_status: "Job Completed", async_percent_completion: 100 };
  const item = Object.values(entities)
    .flat()
    .find((x) => x.id === p);
  if (!item) throw new Error("unknown fixture object");
  if (method === "POST" && !params.execution_options) {
    Object.assign(item, params);
    item.effective_status = item.status;
  }
  return method === "POST" ? { success: true } : { ...item };
};
let reportParams;
const request = graph.request;
graph.request = async (p, t, params = {}, method = "GET") => {
  if (p === "act_10/insights" && method === "POST") reportParams = params;
  return request(p, t, params, method);
};
graph.page = async (p, t, params = {}) => {
  if (p.endsWith("/insights")) {
    params = p === "900/insights" ? reportParams : params;
    const l = params.level || "campaign",
      range = params.time_range
        ? JSON.parse(params.time_range)
        : { since: "2026-10-01", until: "2026-10-18" };
    return {
      data: (l === "account"
        ? [{ id: "10", name: account.name }]
        : entities[l]
      ).map((e, i) => ({
        account_id: "10",
        account_currency: "USD",
        [l + "_id"]: e.id,
        [l + "_name"]: e.name,
        date_start: range.since,
        date_stop: range.until,
        spend: i ? "36.45" : "125.50",
        impressions: i ? "2400" : "6800",
        reach: i ? "1800" : "4200",
        clicks: i ? "42" : "107",
        inline_link_clicks: "65",
        actions: [{ action_type: "lead", value: i ? "0" : "8" }],
      })),
      cursor: null,
    };
  }
  const l = p.endsWith("/campaigns")
    ? "campaign"
    : p.endsWith("/adsets")
      ? "adset"
      : "ad";
  return { data: entities[l].map((x) => ({ ...x })), cursor: null };
};
const service = await installFacebookAds({
  ...backend,
  pool,
  env,
  graph,
  emitAutomationEvent,
});
await pool.query(
  "INSERT INTO facebook_ads_connections(company_id,user_id,token,permissions,status) VALUES($1,$2,$3,'[\"ads_read\",\"ads_management\"]','connected')",
  [company, user, encrypt("fixture-provider-token", `ads:${company}`, env)],
);
await service.select({ userId: user, companyId: company }, ["10"]);
app.locals.facebookLeads = await installFacebookLeads({
  ...backend,
  pool,
  env,
  graph,
  startWorker: false,
  emitAutomationEvent,
  markContactDirty: async () => {},
  sendPushToUsers: async () => {},
});
const connection = await installFacebookConnection({
  ...backend,
  pool,
  env,
  graph,
});
await connection.accept(
  { userId: user, companyId: company },
  {
    token: "fixture-provider-token",
    metaUserId: "1000",
    permissions: [...COMBINED_PERMISSIONS],
    expiresAt: new Date(Date.now() + 86400000),
  },
);
await connection.refresh({ userId: user, companyId: company });
// Settings fixtures use the same response shape as the production controller.
app.get(
  "/api/agreements/notification-rules",
  backend.authRequired,
  (req, res) =>
    res.json({
      version: 1,
      immediate_dashboard: true,
      immediate_push: false,
      events: [
        {
          key: "signed",
          label: "Agreement signed",
          dashboard: null,
          push: null,
        },
      ],
      rules: [
        {
          key: "unsigned",
          label: "Unsigned agreement",
          enabled: true,
          dashboard: true,
          push: false,
          delay_minutes: 1440,
        },
      ],
    }),
);
const server = app.listen(18607, "127.0.0.1", () => {
  writeFileSync(
    "/tmp/wolf-settings-fixture-ready.json",
    JSON.stringify({ url: "http://127.0.0.1:18607", company, user }),
  );
  console.log("Local Ads fixture ready on 18607; no external provider calls.");
});
let stopping = false;
async function stop() {
  if (stopping) return;
  stopping = true;
  server.close();
  await pool.end();
  pg.stop();
  process.exit(0);
}
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
