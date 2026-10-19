import test from "node:test";
import assert from "node:assert/strict";
import {
  moneyUnits,
  budgetTarget,
  dateWindow,
  versionOf,
} from "../facebook-ads/domain.js";
import {
  metrics,
  validateReport,
  valuesFor,
  fieldsFor,
} from "../facebook-ads/catalog.js";
import {
  validateMetricRule,
  evaluateMetric,
} from "../facebook-ads/automation.js";
import { AdsGraph } from "../facebook-ads/provider.js";
import { registerAdsTools } from "../facebook-ads/mcp.js";
test("exact monetary units, budget ownership, minimums and optimistic versions", () => {
  assert.equal(moneyUnits("10.01", "USD"), "1001");
  assert.throws(() => moneyUnits("1.001", "USD"), (e) => e.code === "currency_precision");
  assert.equal(moneyUnits("90071992547409.91", "USD"), "9007199254740991");
  const a = { currency: "USD", min_daily_budget: "100" },
    e = {
      id: "1",
      account_id: "2",
      level: "adset",
      status: "PAUSED",
      daily_budget: "1001",
      campaign: { daily_budget: "0" },
    };
  assert.equal(
    budgetTarget(
      { budget_type: "daily_budget", mode: "percent", value: "10" },
      e,
      a,
    ),
    "1101",
  );
  assert.throws(
    () =>
      budgetTarget(
        { budget_type: "daily_budget", mode: "absolute", value: "0.99" },
        e,
        a,
      ),
    (e) => e.code === "below_account_minimum",
  );
  assert.throws(
    () =>
      budgetTarget(
        { budget_type: "daily_budget", mode: "percent", value: "-100" },
        e,
        a,
      ),
    (e) => e.code === "percentage_out_of_range",
  );
  assert.throws(
    () =>
      budgetTarget(
        { budget_type: "daily_budget", mode: "absolute", value: "10" },
        { ...e, campaign: { daily_budget: "100" } },
        a,
      ),
    (e) => e.code === "budget_owned_by_campaign",
  );
  assert.throws(
    () =>
      budgetTarget(
        { budget_type: "lifetime_budget", mode: "absolute", value: "10" },
        e,
        a,
      ),
    (e) => e.code === "budget_kind_not_configured",
  );
  assert.notEqual(versionOf(e), versionOf({ ...e, status: "ACTIVE" }));
});
test("account calendar dates, DST and custom range validation", () => {
  assert.deepEqual(
    JSON.parse(
      dateWindow(
        { preset: "today" },
        "America/Los_Angeles",
        new Date("2026-03-09T02:00:00Z"),
      ).time_range,
    ),
    { since: "2026-03-08", until: "2026-03-08" },
  );
  assert.deepEqual(
    JSON.parse(
      dateWindow(
        { preset: "last_7d" },
        "America/New_York",
        new Date("2026-03-09T12:00:00Z"),
      ).time_range,
    ),
    { since: "2026-03-02", until: "2026-03-08" },
  );
  assert.throws(() =>
    dateWindow(
      { preset: "custom", since: "2026-02-30", until: "2026-03-01" },
      "UTC",
    ),
  );
  assert.throws(() =>
    dateWindow(
      { preset: "custom", since: "2020-01-01", until: "2026-01-01" },
      "UTC",
    ),
  );
});
test("broad versioned metrics; zero, missing, ratios and breakdown restrictions", () => {
  assert.ok(metrics.length >= 75);
  const r = validateReport({
    account_id: "1",
    metrics: ["spend", "cpc", "cost:lead", "actions:lead", "reach"],
  });
  const v = valuesFor(
    {
      spend: "10",
      clicks: "0",
      actions: [{ action_type: "lead", value: "0" }],
    },
    r,
  );
  assert.equal(v.values.cpc, null);
  assert.equal(v.values["actions:lead"], "0");
  assert.equal(v.values.reach, null);
  assert.equal(v.values["cost:lead"], null);
  assert.equal(
    valuesFor({ spend: "10", clicks: "3" }, r).values.cpc,
    "3.333333",
  );
  assert.ok(
    !fieldsFor(
      validateReport({ account_id: "1", metrics: ["spend"] }),
    ).includes("actions"),
  );
  assert.throws(
    () =>
      validateReport({
        account_id: "1",
        metrics: ["spend"],
        breakdowns: ["age", "country"],
      }),
    (e) => e.code === "unsupported_breakdown_combination",
  );
  assert.throws(
    () =>
      validateReport({
        account_id: "1",
        metrics: ["quality_ranking"],
        level: "account",
      }),
    (e) => e.code === "metric_level_unavailable",
  );
});
test("crossing, rearm, missing data, cooldown, max fires and multiple conditions", () => {
  const r = validateMetricRule({
      account_id: "1",
      metric: "spend",
      operator: "gte",
      threshold: "20",
      max_fires: 5,
      conditions: [{ metric: "actions:lead", operator: "lt", threshold: "1" }],
    }),
    row = { values: { spend: "21", "actions:lead": "0" } };
  assert.equal(evaluateMetric(r, row, null).fire, true);
  assert.equal(
    evaluateMetric(r, row, { matched: true, fire_count: 1 }).reason,
    "waiting_for_rearm",
  );
  assert.equal(
    evaluateMetric(
      r,
      { values: { spend: "10", "actions:lead": "0" } },
      { matched: true },
    ).matched,
    false,
  );
  assert.equal(
    evaluateMetric(r, { values: { spend: "30", "actions:lead": null } }, null)
      .reason,
    "missing_metric",
  );
  assert.equal(
    evaluateMetric({ ...r, repeat: "repeat" }, row, {
      last_fired_at: new Date(),
      fire_count: 1,
    }).reason,
    "cooldown",
  );
  assert.equal(evaluateMetric(r, row, { fire_count: 5 }).reason, "fire_limit");
  assert.throws(() => validateMetricRule({ ...r, interval_minutes: 1 }));
});
test("POST never retried; secrets redacted; page URLs never followed", async () => {
  let calls = 0;
  const env = { FACEBOOK_LEADS_APP_SECRET: "fixture-secret" },
    g = new AdsGraph(env, async () => {
      calls++;
      return new Response(
        JSON.stringify({ error: { code: 4, message: "SECRET TOKEN" } }),
        { status: 429 },
      );
    });
  await assert.rejects(
    () => g.request("1", "fixture", {}, "POST"),
    (e) => e.code === "facebook_rate_limit" && !e.message.includes("SECRET"),
  );
  assert.equal(calls, 1);
  const p = new AdsGraph(
    env,
    async () =>
      new Response(
        JSON.stringify({
          data: [{ id: "1" }],
          paging: {
            next: "https://attacker.invalid",
            cursors: { after: "next" },
          },
        }),
      ),
  );
  assert.deepEqual(await p.page("me/adaccounts", "fixture"), {
    data: [{ id: "1" }],
    cursor: "next",
    total: null,
  });
  await assert.rejects(
    () => g.request("../secret", "fixture"),
    (e) => e.code === "invalid_provider_path",
  );
});
test("MCP names and read/write scopes are explicit", () => {
  const d = [];
  registerAdsTools((...x) => d.push(x), { app: { locals: {} }, actor: null });
  assert.equal(d.length, 10);
  assert.equal(
    d.find((x) => x[0] === "facebook_ads_set_budget")[4],
    "ads:write",
  );
  assert.equal(d.find((x) => x[0] === "facebook_ads_insights")[4], "ads:read");
  assert.equal(d.find((x) => x[0] === "facebook_ads_set_budget")[7], true);
});

test("GET rate limit retries are bounded and paging keeps the selected fields", async () => {
  let calls = 0;
  const seen = [];
  const g = new AdsGraph(
    { FACEBOOK_LEADS_APP_SECRET: "fixture" },
    async (url) => {
      seen.push(new URL(url));
      calls++;
      return calls === 1
        ? new Response(JSON.stringify({ error: { code: 4 } }), { status: 429 })
        : new Response(JSON.stringify({ data: [{ id: "2" }] }));
    },
  );
  assert.deepEqual(
    (
      await g.page(
        "act_10/insights",
        "fixture",
        { fields: "spend", limit: "100" },
        "safe-cursor",
      )
    ).data,
    [{ id: "2" }],
  );
  assert.equal(calls, 2);
  assert.ok(
    seen.every(
      (x) =>
        x.hostname === "graph.facebook.com" &&
        x.searchParams.get("fields") === "spend" &&
        x.searchParams.get("after") === "safe-cursor",
    ),
  );
});
