export const SALES_ANALYTICS_LIMITS = Object.freeze({
  maximumRangeDays: 366,
  maximumTrendBuckets: 370,
  maximumBreakdownRows: 100
});

export const SALES_ANALYTICS_BUCKETS = Object.freeze(["day", "week", "month"]);

export class SalesAnalyticsError extends Error {
  constructor(code, message, statusCode = 400) {
    super(message);
    this.name = "SalesAnalyticsError";
    this.code = code;
    this.statusCode = statusCode;
  }
}

export function validateSalesAnalyticsQuery(raw = {}) {
  const start = requiredDate(raw.start, "start");
  const end = requiredDate(raw.end, "end");
  if (end <= start) {
    throw new SalesAnalyticsError("sales_range_invalid", "Sales report end must be after its start.");
  }
  const duration = end.getTime() - start.getTime();
  const maximum = SALES_ANALYTICS_LIMITS.maximumRangeDays * 86_400_000 + 7_200_000;
  if (duration > maximum) {
    throw new SalesAnalyticsError(
      "sales_range_too_large",
      `Sales report range cannot exceed ${SALES_ANALYTICS_LIMITS.maximumRangeDays} days.`
    );
  }
  const rawBucket = clean(raw.bucket).toLowerCase();
  const bucket = rawBucket || automaticBucket(duration);
  if (!SALES_ANALYTICS_BUCKETS.includes(bucket)) {
    throw new SalesAnalyticsError("sales_bucket_invalid", "Sales trend bucket must be day, week, or month.");
  }
  const employeeId = clean(raw.employee_id) || null;
  if (employeeId && !isUUID(employeeId)) {
    throw new SalesAnalyticsError("sales_employee_invalid", "The selected employee is invalid.");
  }
  return {
    start,
    end,
    bucket,
    employee_id: employeeId,
    previous_start: new Date(start.getTime() - duration),
    previous_end: new Date(start)
  };
}

export function buildSalesSummary({
  contacts = null,
  communications = null,
  quotes = null,
  outcomes = null,
  appointments = null,
  jobs = null,
  salesCycle = null
} = {}) {
  const newContacts = factInteger(contacts, "new_contacts");
  const externalLeads = factInteger(contacts, "external_leads");
  const convertedLeads = factInteger(contacts, "converted_leads");
  const attempts = factInteger(communications, "contacts_attempted");
  const leadsContacted = factInteger(communications, "leads_contacted");
  const speedMatched = factInteger(communications, "speed_matched_count");
  const speedTotal = factInteger(communications, "speed_total_seconds");
  const speedMedian = factNullableInteger(communications, "speed_median_seconds");
  const quotesCreated = factInteger(quotes, "quotes_created");
  const quotesSent = factInteger(quotes, "quotes_sent");
  const quotesAccepted = factInteger(quotes, "quotes_accepted");
  const quotesDeclined = factInteger(quotes, "quotes_declined");
  const soldRevenue = factInteger(quotes, "revenue_sold_cents");
  const wins = factInteger(outcomes, "won_opportunities");
  const losses = factInteger(outcomes, "lost_opportunities");
  const booked = factInteger(appointments, "appointments_booked");
  const completedJobs = factInteger(jobs, "completed_jobs");
  const realizedRevenue = factInteger(jobs, "realized_revenue_cents");
  const cycleMatched = factInteger(salesCycle, "sales_cycle_matched_count");
  const cycleTotal = factInteger(salesCycle, "sales_cycle_total_seconds");

  return {
    new_contacts: newContacts,
    external_leads: externalLeads,
    contacts_attempted: attempts,
    leads_contacted: leadsContacted,
    quotes_created: quotesCreated,
    quotes_sent: quotesSent,
    quotes_accepted: quotesAccepted,
    quotes_declined: quotesDeclined,
    appointments_booked: booked,
    won_opportunities: wins,
    lost_opportunities: losses,
    completed_jobs: completedJobs,
    revenue_sold_cents: soldRevenue,
    realized_revenue_cents: realizedRevenue,
    revenue_per_lead_cents: divideRounded(soldRevenue, externalLeads),
    average_ticket_cents: divideRounded(realizedRevenue, completedJobs),
    close_rate_percent: percentage(wins, nullableSum(wins, losses)),
    lead_to_sale_conversion_percent: percentage(convertedLeads, externalLeads),
    speed_to_lead_average_seconds: divideRounded(speedTotal, speedMatched),
    speed_to_lead_median_seconds: speedMedian,
    speed_to_lead_matched_count: speedMatched,
    sales_cycle_average_seconds: divideRounded(cycleTotal, cycleMatched),
    sales_cycle_matched_count: cycleMatched
  };
}

export function normalizeSalesBreakdown(rows, { identityKey, labelKey, maximum = SALES_ANALYTICS_LIMITS.maximumBreakdownRows } = {}) {
  if (!Array.isArray(rows)) throw new SalesAnalyticsError("sales_breakdown_invalid", "Sales breakdown rows are invalid.", 500);
  return rows.slice(0, maximum).map((row) => ({
    id: clean(row?.[identityKey]) || "unknown",
    label: clean(row?.[labelKey]) || "Unknown",
    new_contacts: safeInteger(row?.new_contacts),
    external_leads: safeInteger(row?.external_leads),
    quotes_created: safeInteger(row?.quotes_created),
    quotes_accepted: safeInteger(row?.quotes_accepted),
    won_opportunities: safeInteger(row?.won_opportunities),
    lost_opportunities: safeInteger(row?.lost_opportunities),
    completed_jobs: safeInteger(row?.completed_jobs),
    revenue_sold_cents: safeInteger(row?.revenue_sold_cents),
    realized_revenue_cents: safeInteger(row?.realized_revenue_cents),
    close_rate_percent: percentage(safeInteger(row?.won_opportunities), safeInteger(row?.won_opportunities) + safeInteger(row?.lost_opportunities)),
    lead_to_sale_conversion_percent: percentage(safeInteger(row?.converted_leads), safeInteger(row?.external_leads))
  }));
}

export function normalizeSalesTrend(rows) {
  if (!Array.isArray(rows) || rows.length > SALES_ANALYTICS_LIMITS.maximumTrendBuckets) {
    throw new SalesAnalyticsError("sales_trend_invalid", "Sales trend rows exceeded the supported bound.", 500);
  }
  return rows.map((row) => ({
    bucket_start: requiredDate(row.bucket_start, "bucket_start").toISOString(),
    new_contacts: safeInteger(row.new_contacts),
    external_leads: safeInteger(row.external_leads),
    quotes_created: safeInteger(row.quotes_created),
    quotes_accepted: safeInteger(row.quotes_accepted),
    won_opportunities: safeInteger(row.won_opportunities),
    lost_opportunities: safeInteger(row.lost_opportunities),
    completed_jobs: safeInteger(row.completed_jobs),
    revenue_sold_cents: safeInteger(row.revenue_sold_cents),
    realized_revenue_cents: safeInteger(row.realized_revenue_cents)
  }));
}

function automaticBucket(duration) {
  const days = duration / 86_400_000;
  if (days <= 45) return "day";
  if (days <= 180) return "week";
  return "month";
}

function factInteger(source, key) {
  return source == null ? null : safeInteger(source[key]);
}

function factNullableInteger(source, key) {
  return source == null || source[key] == null ? null : safeInteger(source[key]);
}

function safeInteger(value) {
  if (value == null || value === "") return 0;
  const number = Number(value);
  if (!Number.isSafeInteger(number)) {
    throw new SalesAnalyticsError("sales_numeric_fact_invalid", "A sales metric exceeded its supported numeric range.", 500);
  }
  return number;
}

function nullableSum(lhs, rhs) {
  return lhs == null || rhs == null ? null : lhs + rhs;
}

function divideRounded(numerator, denominator) {
  if (numerator == null || denominator == null || denominator <= 0) return null;
  return Math.round(numerator / denominator);
}

function percentage(numerator, denominator) {
  if (numerator == null || denominator == null || denominator <= 0) return null;
  return Math.round((numerator / denominator) * 1000) / 10;
}

function requiredDate(value, field) {
  const date = value instanceof Date ? new Date(value) : new Date(clean(value));
  if (!Number.isFinite(date.getTime())) {
    throw new SalesAnalyticsError("sales_range_invalid", `Sales report ${field} is invalid.`);
  }
  return date;
}

function isUUID(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function clean(value) {
  return value == null ? "" : String(value).trim();
}
