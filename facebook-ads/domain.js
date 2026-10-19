import { createHash } from "node:crypto";
import { z } from "zod";
export const VERSION = "v26.0";
const messages = {
  currency_precision: "Use an amount with the decimal precision supported by this ad-account currency.",
  invalid_decimal: "Enter a decimal number using a period, without currency symbols or grouping separators.",
  budget_out_of_range: "Enter a positive budget within the supported range.",
  budget_owned_by_campaign: "This ad set uses its campaign budget. Open the campaign to change the budget.",
  ads_have_no_budget: "Ads do not own budgets. Open the owning ad set or campaign.",
  lifetime_budget_requires_future_end: "A lifetime ad-set budget requires an end time in the future. Update its schedule in Meta first.",
  percentage_out_of_range: "Enter a percentage greater than -100 and no greater than 1000.",
  owner_budget_limit: "The resulting budget would exceed the minimum or maximum you configured.",
  below_account_minimum: "The resulting daily budget is below the current Meta ad-account minimum.",
  ad_account_not_selected: "Select an authorized ad account in Facebook Ads connection settings first.",
  ad_account_unavailable: "This account is no longer available. Refresh access and select an authorized account.",
  facebook_ads_disconnected: "Connect or reauthorize Facebook Ads in connection settings.",
  facebook_ads_access_denied: "Your current company role cannot perform this advertising operation.",
  facebook_ads_permission_required: "Reauthorize Facebook Ads with the required ads_read or ads_management permission.",
  facebook_ad_account_write_role_required: "Your current Facebook account role can read this account but cannot change its ads.",
  facebook_reauthorize_required: "Facebook authorization expired or was revoked. Reauthorize in connection settings.",
  report_authorization_changed: "Account authorization changed after this report started. Start a new report.",
  view_changed_reload: "This saved view changed elsewhere. Reload it before saving again.",
  unsupported_breakdown_combination: "Choose one of the supported reporting breakdown combinations.",
  ranking_breakdown_unavailable: "Ad ranking metrics cannot be combined with demographic or placement breakdowns.",
};
export const fault = (code, status = 400, message = messages[code] || code.replaceAll("_", " ")) =>
  Object.assign(new Error(message), { code, status });
export const digest = (x) =>
  createHash("sha256").update(JSON.stringify(x)).digest("hex");
export const id = z.string().regex(/^\d{1,40}$/);
export const level = z.enum(["account", "campaign", "adset", "ad"]);
export const decimal = z.string().regex(/^-?\d{1,18}(?:\.\d{1,6})?$/);
export function scaled(value, places = 6) {
  if (!/^-?\d{1,18}(?:\.\d{1,6})?$/.test(String(value)))
    throw fault("invalid_decimal");
  const [whole, frac = ""] = String(value).replace("-", "").split(".");
  if (frac.length > places && /[1-9]/.test(frac.slice(places)))
    throw fault("currency_precision");
  return (
    (BigInt(whole) * 10n ** BigInt(places) +
      BigInt(frac.slice(0, places).padEnd(places, "0") || "0")) *
    (String(value).startsWith("-") ? -1n : 1n)
  );
}
export function unscaled(value, places = 6) {
  const sign = value < 0n ? "-" : "";
  const s = (value < 0n ? -value : value).toString().padStart(places + 1, "0");
  return places
    ? sign + s.slice(0, -places) + "." + s.slice(-places)
    : sign + s;
}
export function ratio(a, b, multiplier = 1n) {
  if (a == null || b == null) return null;
  const den = scaled(b);
  return den === 0n
    ? null
    : unscaled((scaled(a) * multiplier * 1000000n) / den);
}
export function currencyDigits(currency) {
  // Meta currencies documented in cents except zero-decimal currencies. Fail closed for unfamiliar codes.
  const zero = [
    "CLP",
    "COP",
    "CRC",
    "HUF",
    "IDR",
    "ISK",
    "JPY",
    "KRW",
    "PYG",
    "TWD",
    "VND",
  ];
  const two = [
    "AED",
    "ARS",
    "AUD",
    "BDT",
    "BGN",
    "BOB",
    "BRL",
    "CAD",
    "CHF",
    "CNY",
    "CZK",
    "DKK",
    "DZD",
    "EGP",
    "EUR",
    "GBP",
    "GTQ",
    "HKD",
    "HNL",
    "ILS",
    "INR",
    "KES",
    "LBP",
    "LKR",
    "MAD",
    "MOP",
    "MXN",
    "MYR",
    "NGN",
    "NIO",
    "NOK",
    "NZD",
    "PEN",
    "PHP",
    "PKR",
    "PLN",
    "QAR",
    "RON",
    "RSD",
    "RUB",
    "SAR",
    "SEK",
    "SGD",
    "THB",
    "TRY",
    "UAH",
    "USD",
    "UYU",
    "VEF",
    "ZAR",
  ];
  if (zero.includes(currency)) return 0;
  if (two.includes(currency)) return 2;
  throw fault(
    "currency_budget_units_unverified",
    422,
    "Budget controls are unavailable until provider units for this currency are verified.",
  );
}
export function moneyUnits(value, currency) {
  const n = scaled(value, currencyDigits(currency));
  if (n <= 0n || n > 9007199254740991n) throw fault("budget_out_of_range");
  return n.toString();
}
export const date = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/)
  .refine(
    (x) =>
      !isNaN(Date.parse(x)) && new Date(x).toISOString().slice(0, 10) === x,
    "Invalid calendar date",
  );
export const period = z
  .object({
    preset: z
      .enum([
        "today",
        "yesterday",
        "this_week",
        "this_month",
        "last_7d",
        "last_30d",
        "custom",
        "maximum",
      ])
      .default("last_7d"),
    since: date.optional(),
    until: date.optional(),
  })
  .strict();
export function dateWindow(input, timezone, now = new Date()) {
  const p = period.parse(input);
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: timezone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(now);
  const get = (k) => parts.find((x) => x.type === k).value;
  const today = `${get("year")}-${get("month")}-${get("day")}`;
  const shift = (d, n) =>
    new Date(Date.parse(d) + n * 86400000).toISOString().slice(0, 10);
  if (p.preset === "maximum") return { date_preset: "maximum" };
  let since = today,
    until = today;
  if (p.preset === "yesterday") since = until = shift(today, -1);
  if (p.preset === "last_7d" || p.preset === "last_30d") {
    until = shift(today, -1);
    since = shift(today, p.preset === "last_7d" ? -7 : -30);
  }
  if (p.preset === "this_week")
    since = shift(today, -((new Date(today).getUTCDay() + 6) % 7));
  if (p.preset === "this_month") since = today.slice(0, 8) + "01";
  if (p.preset === "custom") {
    since = p.since;
    until = p.until;
  }
  if (
    !since ||
    !until ||
    since > until ||
    until > today ||
    (Date.parse(until) - Date.parse(since)) / 86400000 > 365
  )
    throw fault(
      "invalid_reporting_period",
      400,
      "Select a valid period of at most 366 days ending no later than today in the ad-account timezone.",
    );
  return { time_range: JSON.stringify({ since, until }) };
}
export const mutation = z
  .object({
    request_id: z.string().min(8).max(160),
    account_id: id,
    level: z.enum(["campaign", "adset", "ad"]),
    entity_id: id,
    expected_version: z.string().length(64),
    change: z.discriminatedUnion("kind", [
      z
        .object({
          kind: z.literal("status"),
          value: z.enum(["ACTIVE", "PAUSED"]),
        })
        .strict(),
      z
        .object({
          kind: z.literal("budget"),
          budget_type: z.enum(["daily_budget", "lifetime_budget"]),
          mode: z.enum(["absolute", "percent"]),
          value: decimal,
          min: decimal.optional(),
          max: decimal.optional(),
        })
        .strict(),
    ]),
  })
  .strict();
export function versionOf(x) {
  return digest([
    x.id,
    x.account_id,
    x.status,
    x.daily_budget || "0",
    x.lifetime_budget || "0",
    x.campaign?.daily_budget || "0",
    x.campaign?.lifetime_budget || "0",
    x.start_time || null,
    x.end_time || x.stop_time || null,
  ]);
}
export function budgetTarget(change, entity, account, now = new Date()) {
  if (entity.level === "ad") throw fault("ads_have_no_budget");
  currencyDigits(account.currency);
  if (
    entity.level === "adset" &&
    (BigInt(entity.campaign?.daily_budget || "0") > 0n ||
      BigInt(entity.campaign?.lifetime_budget || "0") > 0n)
  )
    throw fault("budget_owned_by_campaign", 409);
  const current = BigInt(entity[change.budget_type] || "0");
  if (current <= 0n)
    throw fault(
      "budget_kind_not_configured",
      409,
      "Only the existing daily or lifetime budget can be edited.",
    );
  if (
    change.budget_type === "lifetime_budget" &&
    entity.level === "adset" &&
    (!entity.end_time || new Date(entity.end_time) <= now)
  )
    throw fault("lifetime_budget_requires_future_end", 409);
  let target;
  if (change.mode === "absolute")
    target = BigInt(moneyUnits(change.value, account.currency));
  else {
    const pct = scaled(change.value);
    if (pct <= -100000000n || pct > 1000000000n)
      throw fault("percentage_out_of_range");
    const product = current * (100000000n + pct);
    target = (product + 50000000n) / 100000000n;
  }
  if (target <= 0n || target > 9007199254740991n)
    throw fault("budget_out_of_range");
  if (
    (change.min && target < BigInt(moneyUnits(change.min, account.currency))) ||
    (change.max && target > BigInt(moneyUnits(change.max, account.currency)))
  )
    throw fault("owner_budget_limit");
  if (
    change.budget_type === "daily_budget" &&
    account.min_daily_budget &&
    target < BigInt(account.min_daily_budget)
  )
    throw fault("below_account_minimum");
  return target.toString();
}
