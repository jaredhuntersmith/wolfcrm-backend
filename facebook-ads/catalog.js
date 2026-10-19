import { z } from "zod";
import { VERSION, level, id, period, fault, ratio } from "./domain.js";
const entries = [];
function add(
  key,
  label,
  unit,
  definition,
  {
    field = key,
    action = null,
    levels = ["account", "campaign", "adset", "ad"],
    additive = false,
    limitations = "Availability depends on attribution, privacy thresholds and account configuration; missing is not zero.",
  } = {},
) {
  entries.push({
    key,
    label,
    unit,
    definition,
    field,
    action,
    levels,
    additive,
    limitations,
    api_version: VERSION,
  });
}
for (const [key, label, unit, definition, additive] of [
  [
    "spend",
    "Amount spent",
    "currency",
    "Amount spent in the ad-account currency.",
    true,
  ],
  ["impressions", "Impressions", "count", "Number of ad impressions.", true],
  [
    "reach",
    "Reach",
    "count",
    "Estimated unique people reached; never sum across rows.",
    false,
  ],
  [
    "frequency",
    "Frequency",
    "ratio",
    "Impressions divided by reach for the requested period.",
    false,
  ],
  ["clicks", "Clicks (all)", "count", "All clicks on the ad.", true],
  [
    "inline_link_clicks",
    "Link clicks",
    "count",
    "Clicks on links to selected destinations.",
    true,
  ],
  [
    "ctr",
    "CTR (all)",
    "percent",
    "All clicks divided by impressions, times 100.",
    false,
  ],
  [
    "inline_link_click_ctr",
    "Link CTR",
    "percent",
    "Link clicks divided by impressions, times 100.",
    false,
  ],
  ["cpc", "CPC (all)", "currency", "Spend divided by all clicks.", false],
  [
    "cost_per_inline_link_click",
    "Cost per link click",
    "currency",
    "Spend divided by link clicks.",
    false,
  ],
  ["cpm", "CPM", "currency", "Spend per 1,000 impressions.", false],
  [
    "cpp",
    "Cost per 1,000 people reached",
    "currency",
    "Spend per 1,000 estimated unique people.",
    false,
  ],
  [
    "unique_clicks",
    "Unique clicks",
    "count",
    "Estimated people who clicked; nonadditive.",
    false,
  ],
  [
    "unique_ctr",
    "Unique CTR",
    "percent",
    "People who clicked divided by reach.",
    false,
  ],
  [
    "unique_inline_link_clicks",
    "Unique link clicks",
    "count",
    "Estimated people who clicked a link.",
    false,
  ],
  [
    "unique_inline_link_click_ctr",
    "Unique link CTR",
    "percent",
    "Unique link click rate.",
    false,
  ],
  [
    "inline_post_engagement",
    "Post engagements",
    "count",
    "Engagements with the ad post.",
    true,
  ],
  [
    "cost_per_inline_post_engagement",
    "Cost per post engagement",
    "currency",
    "Spend divided by post engagements.",
    false,
  ],
  [
    "social_spend",
    "Social spend",
    "currency",
    "Spend when an ad was shown with social information.",
    true,
  ],
  [
    "estimated_ad_recallers",
    "Estimated ad recall lift (people)",
    "count",
    "Estimated additional people likely to recall the ad.",
    false,
  ],
  [
    "estimated_ad_recall_rate",
    "Estimated ad recall lift rate",
    "percent",
    "Estimated additional recall rate.",
    false,
  ],
  [
    "cost_per_estimated_ad_recallers",
    "Cost per recall lift",
    "currency",
    "Cost per estimated additional person recalling the ad.",
    false,
  ],
  [
    "quality_ranking",
    "Quality ranking",
    "text",
    "Provider quality ranking compared to competing ads.",
    false,
  ],
  [
    "engagement_rate_ranking",
    "Engagement ranking",
    "text",
    "Provider engagement rate ranking.",
    false,
  ],
  [
    "conversion_rate_ranking",
    "Conversion ranking",
    "text",
    "Provider conversion rate ranking.",
    false,
  ],
])
  add(key, label, unit, definition, {
    additive,
    levels: key.endsWith("_ranking") ? ["ad"] : undefined,
  });
for (const [action, label] of [
  ["lead", "Leads (all lead actions)"],
  ["onsite_conversion.lead_grouped", "On-Facebook leads"],
  ["offsite_conversion.fb_pixel_lead", "Website leads"],
  ["omni_purchase", "Purchases (omni)"],
  ["offsite_conversion.fb_pixel_purchase", "Website purchases"],
  ["purchase", "Purchase actions"],
  ["link_click", "Link click actions"],
  ["landing_page_view", "Landing page views"],
  ["post_engagement", "Post engagement actions"],
  ["page_engagement", "Page engagement actions"],
  ["comment", "Comments"],
  ["post_reaction", "Post reactions"],
  ["post", "Shares"],
  ["video_view", "Video views"],
  ["offsite_conversion.fb_pixel_add_to_cart", "Website adds to cart"],
  ["offsite_conversion.fb_pixel_initiate_checkout", "Website checkouts"],
  [
    "offsite_conversion.fb_pixel_complete_registration",
    "Website registrations",
  ],
  [
    "onsite_conversion.messaging_conversation_started_7d",
    "Messaging conversations",
  ],
]) {
  add(
    `actions:${action}`,
    label,
    "count",
    `Attributed ${action} actions only. Overlapping action types must not be added together.`,
    { field: "actions", action },
  );
  add(
    `cost:${action}`,
    `Cost per ${label.toLowerCase()}`,
    "currency",
    `Spend divided by attributed ${action}; undefined with zero or missing actions.`,
    { field: "actions", action },
  );
}
for (const [action, label] of [
  ["omni_purchase", "Omni purchase value"],
  ["offsite_conversion.fb_pixel_purchase", "Website purchase value"],
  ["purchase", "Purchase action value"],
])
  add(
    `value:${action}`,
    label,
    "currency",
    `Attributed conversion value for ${action}; currency is the ad-account reporting currency.`,
    { field: "action_values", action },
  );
for (const field of [
  "outbound_clicks",
  "outbound_clicks_ctr",
  "cost_per_outbound_click",
  "unique_outbound_clicks",
  "unique_outbound_clicks_ctr",
  "cost_per_unique_outbound_click",
  "video_p25_watched_actions",
  "video_p50_watched_actions",
  "video_p75_watched_actions",
  "video_p95_watched_actions",
  "video_p100_watched_actions",
  "video_thruplay_watched_actions",
  "video_avg_time_watched_actions",
  "video_continuous_2_sec_watched_actions",
  "cost_per_thruplay",
  "website_purchase_roas",
  "purchase_roas",
  "mobile_app_purchase_roas",
])
  add(
    field,
    field.replaceAll("_", " ").replace(/^./, (c) => c.toUpperCase()),
    field.includes("roas")
      ? "ratio"
      : field.includes("cost")
        ? "currency"
        : field.includes("ctr")
          ? "percent"
          : field.includes("time")
            ? "seconds"
            : "count",
    `Provider ${field.replaceAll("_", " ")}. Action-keyed values are displayed separately; no implicit total.`,
    { action: "*" },
  );
export const metrics = Object.freeze(entries);
export const breakdownSets = [
  [],
  ["age"],
  ["gender"],
  ["age", "gender"],
  ["country"],
  ["region"],
  ["publisher_platform"],
  ["publisher_platform", "platform_position"],
  ["impression_device"],
  ["device_platform"],
];
export const reportSchema = z
  .object({
    account_id: id,
    level: level.default("campaign"),
    metrics: z
      .array(z.enum(metrics.map((m) => m.key)))
      .min(1)
      .max(40),
    period: period.default({ preset: "last_7d" }),
    compare: period.optional(),
    breakdowns: z.array(z.string()).max(2).default([]),
    granularity: z.enum(["all_days", "1", "7", "monthly"]).default("all_days"),
    attribution: z.enum(["account", "adset", "custom"]).default("adset"),
    windows: z
      .array(z.enum(["1d_click", "7d_click", "1d_view"]))
      .min(1)
      .max(3)
      .default(["7d_click", "1d_view"]),
    action_report_time: z
      .enum(["impression", "conversion", "mixed"])
      .default("impression"),
    entity_ids: z.array(id).max(100).default([]),
  })
  .strict();
export function validateReport(input) {
  const r = reportSchema.parse(input);
  if (new Set(r.metrics).size !== r.metrics.length)
    throw fault("duplicate_metrics");
  if (
    !breakdownSets.some(
      (x) =>
        JSON.stringify([...x].sort()) ===
        JSON.stringify([...r.breakdowns].sort()),
    )
  )
    throw fault("unsupported_breakdown_combination");
  for (const key of r.metrics) {
    const m = metrics.find((x) => x.key === key);
    if (!m.levels.includes(r.level))
      throw fault(
        "metric_level_unavailable",
        400,
        `${m.label} is only available at ${m.levels.join(", ")} level.`,
      );
    if (r.breakdowns.length && key.endsWith("_ranking"))
      throw fault("ranking_breakdown_unavailable");
  }
  return r;
}
export function fieldsFor(r) {
  const fields = new Set([
    "account_id",
    "account_currency",
    "date_start",
    "date_stop",
    ...(r.level === "account" ? [] : [r.level + "_id", r.level + "_name"]),
  ]);
  for (const key of r.metrics) {
    const m = metrics.find((x) => x.key === key);
    fields.add(m.field);
    if (key.startsWith("cost:")) fields.add("spend");
    if (
      [
        "cpc",
        "cpm",
        "ctr",
        "inline_link_click_ctr",
        "cost_per_inline_link_click",
        "frequency",
      ].includes(key)
    ) {
      for (const x of [
        "spend",
        "impressions",
        "clicks",
        "inline_link_clicks",
        "reach",
      ])
        fields.add(x);
    }
  }
  return [...fields].join(",");
}
export function valuesFor(row, r) {
  const values = {},
    unavailable = {};
  for (const key of r.metrics) {
    const m = metrics.find((x) => x.key === key);
    let v = row[m.field];
    if (m.action && m.action !== "*")
      v = Array.isArray(v)
        ? v.find((x) => x.action_type === m.action)?.value
        : null;
    if (m.action === "*")
      v = Array.isArray(v)
        ? v.map((x) => ({
            action_type: String(x.action_type),
            value: String(x.value),
          }))
        : null;
    if (key.startsWith("cost:")) v = ratio(row.spend, v);
    const rates = {
      cpc: ["spend", "clicks", 1n],
      cpm: ["spend", "impressions", 1000n],
      ctr: ["clicks", "impressions", 100n],
      inline_link_click_ctr: ["inline_link_clicks", "impressions", 100n],
      cost_per_inline_link_click: ["spend", "inline_link_clicks", 1n],
      frequency: ["impressions", "reach", 1n],
    };
    if (rates[key]) {
      const [a, b, n] = rates[key];
      v = ratio(row[a], row[b], n);
    }
    values[key] = v == null ? null : Array.isArray(v) ? v : String(v);
    if (v == null)
      unavailable[key] =
        "Not reported, privacy-limited, or denominator missing/zero; no zero is inferred.";
  }
  return { values, unavailable };
}
export const catalog = () => ({
  api_version: VERSION,
  catalog_version: "2026-10-18.1",
  metrics,
  breakdown_sets: breakdownSets,
  granularities: ["all_days", "1", "7", "monthly"],
  periods: [
    "today",
    "yesterday",
    "this_week",
    "this_month",
    "last_7d",
    "last_30d",
    "custom",
    "maximum",
  ],
  limitations: [
    "Conversion data can be delayed or revised after refresh.",
    "Reach, frequency, unique counts and rates are nonadditive. Request the account/parent aggregate instead of summing rows.",
    "Results means the explicitly selected action type; unrelated conversions are never combined.",
    "Arbitrary hourly rolling windows and every Ads Manager UI column are not supported.",
  ],
});
