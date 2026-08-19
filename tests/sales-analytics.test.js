import test from "node:test";
import assert from "node:assert/strict";
import {
  SalesAnalyticsError,
  buildSalesSummary,
  normalizeSalesBreakdown,
  normalizeSalesTrend,
  validateSalesAnalyticsQuery
} from "../sales-analytics.js";

test("range validation is half-open bounded and chooses stable buckets", () => {
  const day = validateSalesAnalyticsQuery({ start: "2026-08-01T00:00:00Z", end: "2026-08-02T00:00:00Z" });
  assert.equal(day.bucket, "day");
  assert.equal(day.previous_start.toISOString(), "2026-07-31T00:00:00.000Z");
  assert.equal(validateSalesAnalyticsQuery({ start: "2026-01-01T00:00:00Z", end: "2026-05-01T00:00:00Z" }).bucket, "week");
  assert.equal(validateSalesAnalyticsQuery({ start: "2026-01-01T00:00:00Z", end: "2027-01-01T00:00:00Z" }).bucket, "month");
  assert.throws(() => validateSalesAnalyticsQuery({ start: "2026-08-02", end: "2026-08-01" }), (error) => error.code === "sales_range_invalid");
  assert.throws(() => validateSalesAnalyticsQuery({ start: "2025-01-01", end: "2027-01-01" }), (error) => error.code === "sales_range_too_large");
  assert.throws(() => validateSalesAnalyticsQuery({ start: "2026-08-01", end: "2026-08-02", bucket: "hour" }), (error) => error.code === "sales_bucket_invalid");
});

test("employee validation accepts only canonical UUID shapes", () => {
  const id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  assert.equal(validateSalesAnalyticsQuery({ start: "2026-08-01", end: "2026-08-02", employee_id: id }).employee_id, id);
  assert.throws(
    () => validateSalesAnalyticsQuery({ start: "2026-08-01", end: "2026-08-02", employee_id: "not-an-id" }),
    (error) => error instanceof SalesAnalyticsError && error.code === "sales_employee_invalid"
  );
});

test("summary keeps cents exact and rates null without a denominator", () => {
  const summary = buildSalesSummary({
    contacts: { new_contacts: "12", external_leads: "10", converted_leads: "4" },
    communications: { contacts_attempted: "8", leads_contacted: "6", speed_matched_count: "3", speed_total_seconds: "181", speed_median_seconds: "55" },
    quotes: { quotes_created: "7", quotes_sent: "6", quotes_accepted: "3", quotes_declined: "2", revenue_sold_cents: "10001" },
    outcomes: { won_opportunities: "4", lost_opportunities: "6" },
    appointments: { appointments_booked: "5" },
    jobs: { completed_jobs: "3", realized_revenue_cents: "10001" },
    salesCycle: { sales_cycle_matched_count: "2", sales_cycle_total_seconds: "361" }
  });
  assert.equal(summary.average_ticket_cents, 3334);
  assert.equal(summary.revenue_per_lead_cents, 1000);
  assert.equal(summary.close_rate_percent, 40);
  assert.equal(summary.lead_to_sale_conversion_percent, 40);
  assert.equal(summary.speed_to_lead_average_seconds, 60);
  assert.equal(summary.speed_to_lead_median_seconds, 55);
  assert.equal(summary.sales_cycle_average_seconds, 181);

  const unavailable = buildSalesSummary({ jobs: { completed_jobs: 0, realized_revenue_cents: 0 } });
  assert.equal(unavailable.average_ticket_cents, null);
  assert.equal(unavailable.close_rate_percent, null);
  assert.equal(unavailable.external_leads, null);
  assert.equal(unavailable.revenue_per_lead_cents, null);
  assert.equal(buildSalesSummary({ communications: { speed_matched_count: 0, speed_total_seconds: 0, speed_median_seconds: null } }).speed_to_lead_median_seconds, null);
});

test("trend and breakdown normalization are deterministic and bounded", () => {
  const trend = normalizeSalesTrend([{ bucket_start: "2026-08-19T04:00:00Z", new_contacts: "2", revenue_sold_cents: "4500" }]);
  assert.equal(trend[0].bucket_start, "2026-08-19T04:00:00.000Z");
  assert.equal(trend[0].revenue_sold_cents, 4500);

  const rows = normalizeSalesBreakdown([
    { user_id: "u1", display_name: "Alex", external_leads: "5", converted_leads: "2", won_opportunities: "2", lost_opportunities: "1", realized_revenue_cents: "5000" }
  ], { identityKey: "user_id", labelKey: "display_name" });
  assert.equal(rows[0].label, "Alex");
  assert.equal(rows[0].close_rate_percent, 66.7);
  assert.equal(rows[0].lead_to_sale_conversion_percent, 40);
});

test("unsafe aggregate numbers fail closed", () => {
  assert.throws(
    () => buildSalesSummary({ jobs: { completed_jobs: 1, realized_revenue_cents: "999999999999999999999" } }),
    (error) => error.code === "sales_numeric_fact_invalid" && error.statusCode === 500
  );
});
