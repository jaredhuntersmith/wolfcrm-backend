import { randomUUID, createHash } from "node:crypto";

// All authoritative arithmetic uses integer ratios and half-up rounding. JSON
// numbers are converted to bounded decimal quantities before any multiplication.
export class QuoteContractError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.name = "QuoteContractError";
    this.code = code;
    this.status = status;
    this.statusCode = status;
  }
}

export const QUOTE_MONEY_LIMIT = 2_000_000_000;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const fail = (code, message) => { throw new QuoteContractError(code, message); };
const record = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

export function quoteInteger(value, label, max = QUOTE_MONEY_LIMIT, min = 0) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    fail("quote_value_invalid", `${label} must be an integer from ${min} to ${max}.`);
  }
  return value;
}

export function quoteText(value, label, max, fallback = "") {
  if (value == null) return fallback;
  if (typeof value !== "string" || value.length > max || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value)) {
    fail("quote_text_invalid", `${label} must contain at most ${max} characters without control characters.`);
  }
  return value.replace(/\r\n?/g, "\n");
}

function identifier(value, label) {
  if (typeof value !== "string" || !uuidPattern.test(value)) fail("quote_id_invalid", `${label} must be a UUID.`);
  return value.toLowerCase();
}

function quantityUnits(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0 || value > 100_000) {
    fail("quote_quantity_invalid", "Quantity must be positive and no greater than 100,000.");
  }
  const text = String(value);
  if (!/^\d+(?:\.\d{1,3})?$/.test(text)) fail("quote_quantity_invalid", "Quantity supports up to three decimal places.");
  const [whole, fraction = ""] = text.split(".");
  return BigInt(whole) * 1000n + BigInt(fraction.padEnd(3, "0"));
}

const roundRatio = (numerator, denominator) => (numerator * 2n + denominator) / (denominator * 2n);
const checkedMoney = (value, label) => quoteInteger(Number(value), label);
const percentOf = (value, basisPoints) => checkedMoney(roundRatio(BigInt(value) * BigInt(basisPoints), 10000n), "Calculated amount");

export function normalizeQuoteLines(raw) {
  if (!Array.isArray(raw) || raw.length > 200) fail("quote_lines_invalid", "A quote supports at most 200 line items.");
  const seen = new Set();
  return raw.map((item) => {
    if (!record(item)) fail("quote_line_invalid", "Each line must be an object.");
    const id = item.id == null ? randomUUID() : identifier(item.id, "Line ID");
    if (seen.has(id)) fail("quote_line_duplicate", "Each quote line must have its own ID.");
    seen.add(id);
    const name = quoteText(item.name, "Service name", 240).trim();
    if (!name) fail("quote_name_required", "Each quote line needs a service name.");
    const qty = item.qty ?? 1;
    quantityUnits(qty);
    const price = quoteInteger(item.price_cents, "Unit price");
    const result = {
      id,
      service_id: item.service_id == null ? null : identifier(item.service_id, "Service ID"),
      name,
      qty,
      price_cents: price,
      description: quoteText(item.description, "Service description", 20_000),
    };
    // New fields are deliberately allowlisted; clients cannot inject computed
    // prices, eligibility, tenant identifiers, or signing state into snapshots.
    if (item.taxable !== undefined) {
      if (typeof item.taxable !== "boolean") fail("quote_taxability_invalid", "Taxability must be true or false.");
      result.taxable = item.taxable;
    }
    return result;
  });
}

export function normalizeDeposit(raw = { type: "none", value: 0 }) {
  if (!record(raw) || !["none", "fixed", "percent"].includes(raw.type)) fail("quote_deposit_invalid", "Choose no deposit, a fixed amount, or a percentage.");
  const value = quoteInteger(raw.value ?? 0, "Deposit", raw.type === "percent" ? 10000 : QUOTE_MONEY_LIMIT);
  if (raw.type === "none" && value !== 0) fail("quote_deposit_invalid", "A disabled deposit must be zero.");
  return { type: raw.type, value };
}

export function normalizeQuoteDiscount(raw = { type: "none", value: 0 }) {
  if (!record(raw) || !["none","fixed","percent"].includes(raw.type)) fail("quote_discount_invalid","Choose no discount, a fixed amount, or a percentage.");
  const value=quoteInteger(raw.value??0,"Discount",raw.type==="percent"?10000:QUOTE_MONEY_LIMIT);
  if(raw.type==="none"&&value!==0)fail("quote_discount_invalid","A disabled discount must be zero.");
  return{type:raw.type,value};
}

export const QUOTE_TEMPLATE_OPTION_KEYS = [
  "deposit", "discount", "allow_customer_booking", "offer_service_plans", "customer_notes_enabled",
  "customer_notes_label", "customer_notes_help", "customer_notes_limit", "balance_payment_timing", "balance_due_days_after_service",
];

export function normalizeQuoteTemplateDefaults(raw = {}) {
  if (!record(raw)) fail("template_defaults_invalid", "Template quote settings must be an object.");
  // Duration belongs to the job. Use a sentinel only to validate booking settings.
  const normalized = normalizeQuoteOptions({ ...Object.fromEntries(QUOTE_TEMPLATE_OPTION_KEYS.filter(key => raw[key] !== undefined).map(key => [key, raw[key]])), duration_minutes: 1 });
  return Object.fromEntries(QUOTE_TEMPLATE_OPTION_KEYS.map(key => [key, normalized[key]]));
}

function normalizeQuoteTemplateSelection(raw) {
  if (raw == null) return null;
  if (!record(raw) || !record(raw.content)) fail("quote_template_invalid", "Select a quote template.");
  const id = identifier(raw.id, "Template ID");
  if (JSON.stringify(raw.content).length > 500000) fail("quote_template_invalid", "The template content is too large.");
  if (raw.is_customized != null && typeof raw.is_customized !== "boolean") fail("quote_template_invalid", "Template customization must be true or false.");
  return { id, version: quoteInteger(raw.version, "Template version", 2147483647, 1), name: quoteText(raw.name, "Template name", 200), content: raw.content, is_customized: raw.is_customized ?? false };
}

export function normalizeQuoteOptions(raw = {}) {
  if (!record(raw)) fail("quote_options_invalid", "Quote options must be an object.");
  const bool = (key) => {
    if (raw[key] !== undefined && typeof raw[key] !== "boolean") fail("quote_options_invalid", `${key} must be true or false.`);
    return raw[key] ?? false;
  };
  const duration = raw.duration_minutes == null ? null : quoteInteger(raw.duration_minutes, "Job duration in minutes", 10080, 1);
  const booking = bool("allow_customer_booking");
  const balanceTiming=raw.balance_payment_timing??"after_signing";
  if(!["after_signing","after_service"].includes(balanceTiming))fail("quote_balance_timing_invalid","Choose balance collection after signing or after completed service.");
  if (booking && duration === null) fail("quote_duration_required", "Enter the estimated job duration before enabling customer booking.");
  return {
    template: normalizeQuoteTemplateSelection(raw.template),
    duration_minutes: duration,
    deposit: normalizeDeposit(raw.deposit),
    discount: normalizeQuoteDiscount(raw.discount),
    allow_customer_booking: booking,
    offer_service_plans: bool("offer_service_plans"),
    customer_notes_enabled: bool("customer_notes_enabled"),
    customer_notes_label: quoteText(raw.customer_notes_label??"Property or access notes", "Customer notes label",120),
    customer_notes_help: quoteText(raw.customer_notes_help??"Share access instructions or a scheduling preference. A preferred time is not a confirmed appointment.", "Customer notes help",1000),
    customer_notes_limit: quoteInteger(raw.customer_notes_limit??5000,"Customer notes limit",5000,100),
    balance_payment_timing: balanceTiming,
    balance_due_days_after_service: raw.balance_due_days_after_service==null?null:quoteInteger(raw.balance_due_days_after_service,"Balance due days after service",365),
    public_notes: quoteText(raw.public_notes, "Customer-facing notes", 20_000),
    scope_exclusions: quoteText(raw.scope_exclusions, "Scope exclusions", 20_000),
    billing_address:quoteText(raw.billing_address,"Billing address override",2000).trim(),
    optional_addons: normalizeQuoteAddons(raw.optional_addons ?? []),
  };
}

export function normalizeQuoteAddons(raw) {
  if (!Array.isArray(raw) || raw.length > 50) fail("quote_addons_invalid", "Offer at most 50 optional services.");
  const lines = normalizeQuoteLines(raw);
  return lines.map((line, index) => {
    identifier(raw[index].id, "Optional line ID");
    if (!line.service_id) fail("quote_addon_service_required", "Choose a saved service for each optional add-on.");
    return { ...line, duration_minutes: quoteInteger(raw[index].duration_minutes ?? 0, "Additional job duration in minutes", 10080) };
  });
}

export function validateQuoteAddonScope(lineItems, options) {
  const all = [...lineItems, ...options.optional_addons];
  normalizeQuoteLines(all); // Combined size and distinct IDs use the base scope rules.
  if (options.optional_addons.length && options.duration_minutes != null) quoteInteger(options.duration_minutes + options.optional_addons.reduce((sum, item) => sum + item.duration_minutes, 0), "Maximum selected job duration in minutes", 10080, 1);
  calculateQuotePricing({ line_items: all }); // No offered combination may overflow money.
}

// Largest-remainder allocation guarantees the sum of line discounts equals the
// promised discount, including one-cent splits. Ties retain visible line order.
export function allocateQuoteAmount(amount, weights) {
  quoteInteger(amount, "Allocation amount");
  weights.forEach((weight) => quoteInteger(weight, "Allocation weight"));
  const total = weights.reduce((sum, value) => sum + BigInt(value), 0n);
  if (BigInt(amount) > total) fail("quote_discount_invalid", "Allocation exceeds the eligible subtotal.");
  if (total === 0n) return weights.map(() => 0);
  const entries = weights.map((weight, index) => ({
    index,
    value: Number(BigInt(amount) * BigInt(weight) / total),
    remainder: BigInt(amount) * BigInt(weight) % total,
  }));
  const remainder = amount - entries.reduce((sum, entry) => sum + entry.value, 0);
  const priority = [...entries].sort((a, b) => a.remainder === b.remainder ? a.index - b.index : a.remainder > b.remainder ? -1 : 1);
  for (let i = 0; i < remainder; i += 1) priority[i].value += 1;
  return entries.map((entry) => entry.value);
}

function discountAmount(discount, subtotal) {
  if (discount == null) return 0;
  if (record(discount) && discount.type === "none" && discount.value === 0) return 0;
  if (!record(discount) || !["fixed", "percent"].includes(discount.type)) fail("quote_discount_invalid", "Discount type must be fixed or percent.");
  const value = quoteInteger(discount.value, "Discount", discount.type === "percent" ? 10000 : QUOTE_MONEY_LIMIT);
  return discount.type === "percent" ? percentOf(subtotal, value) : Math.min(subtotal, value);
}

export function calculateQuotePricing({ line_items, tax_rate_basis_points = 0, tax_inclusive = false, discount = null, deposit = { type: "none", value: 0 }, payments_cents = 0, currency = "usd" }) {
  if (currency !== "usd") fail("quote_currency_unsupported", "This quote workflow currently supports USD. Select a supported currency before publishing.");
  const lines = normalizeQuoteLines(line_items);
  const taxRate = quoteInteger(tax_rate_basis_points, "Tax rate", 10000);
  if (typeof tax_inclusive !== "boolean") fail("quote_tax_invalid", "Tax treatment must be explicit.");
  const paid = quoteInteger(payments_cents, "Payments credited");
  const amounts = lines.map((line) => checkedMoney(roundRatio(BigInt(line.price_cents) * quantityUnits(line.qty), 1000n), "Line total"));
  const subtotal = checkedMoney(amounts.reduce((sum, value) => sum + BigInt(value), 0n), "Subtotal");
  const reduction = discountAmount(discount, subtotal);
  const discounts = allocateQuoteAmount(reduction, amounts);
  const priced = lines.map((line, index) => {
    const net = amounts[index] - discounts[index];
    const rate = line.taxable === false ? 0 : taxRate;
    const tax = tax_inclusive
      ? Number(roundRatio(BigInt(net) * BigInt(rate), BigInt(10000 + rate)))
      : percentOf(net, rate);
    return { ...line, line_total_cents: amounts[index], discount_cents: discounts[index], tax_cents: tax, total_cents: net + (tax_inclusive ? 0 : tax) };
  });
  const tax = checkedMoney(priced.reduce((sum, line) => sum + BigInt(line.tax_cents), 0n), "Tax total");
  const total = checkedMoney(priced.reduce((sum, line) => sum + BigInt(line.total_cents), 0n), "Quote total");
  const configuredDeposit = normalizeDeposit(deposit);
  const depositCents = configuredDeposit.type === "fixed" ? configuredDeposit.value : configuredDeposit.type === "percent" ? percentOf(total, configuredDeposit.value) : 0;
  if (depositCents > total) fail("quote_deposit_excess", "The required deposit cannot exceed the quote total.");
  return {
    currency, line_items: priced, subtotal_cents: subtotal, discount_cents: reduction,
    tax_cents: tax, total_cents: total, deposit_cents: depositCents, balance_after_deposit_cents: total - depositCents,
    balance_cents: Math.max(0, total - paid), credit_cents: Math.max(0, paid - total),
    tax_inclusive, tax_rate_basis_points: taxRate,
  };
}

export function calculatePlanOffer({ line_items, eligible_service_ids, tier, payments_cents = 0, tax_rate_basis_points = 0, tax_inclusive = false, quoted_pricing = null, discount_stacking_policy = "best_price" }) {
  if (!record(tier)) fail("plan_tier_invalid", "A plan tier is required.");
  const lines = normalizeQuoteLines(line_items);
  if (!Array.isArray(eligible_service_ids)) fail("plan_eligibility_invalid", "Service eligibility must come from the saved catalog.");
  const eligible = new Set(eligible_service_ids.map((id) => identifier(id, "Eligible service ID")));
  const restricted = tier.service_ids == null ? null : new Set(tier.service_ids.map((id) => identifier(id, "Tier service ID")));
  const scoped = lines.filter((line) => line.service_id && eligible.has(line.service_id) && (!restricted || restricted.has(line.service_id)));
  if (scoped.length === 0) return null;
  const pricingOptions = { tax_rate_basis_points, tax_inclusive };
  if(!["best_price","quote_then_plan"].includes(discount_stacking_policy))fail("quote_discount_policy_invalid","Choose a supported discount policy.");
  const original = quoted_pricing || calculateQuotePricing({ ...pricingOptions, line_items: lines, payments_cents });
  quoteInteger(original.total_cents,"Signed quote total");
  const future = calculateQuotePricing({ ...pricingOptions, line_items: scoped, discount: tier.discount });
  const chosenIDs=new Set(scoped.map(line=>line.id)),signedEligible=original.line_items.filter(line=>chosenIDs.has(line.id));
  if(signedEligible.length!==scoped.length)fail("plan_quote_scope_invalid","The signed quote scope does not match these plan services.");
  const eligibleTotal=signedEligible.reduce((sum,line)=>sum+quoteInteger(line.total_cents,"Signed line total"),0);
  // Exact allocated cents become one-unit calculation inputs only for the
  // incremental discount. The actual future scope retains its original qty.
  const stackedPricing=discount_stacking_policy==="quote_then_plan"?calculateQuotePricing({...pricingOptions,line_items:signedEligible.map(line=>({...line,qty:1,price_cents:quoteInteger(line.line_total_cents-line.discount_cents,"Remaining eligible line amount")})),discount:tier.discount}):future;
  const stacked=stackedPricing.total_cents;
  const adjustment = tier.discount_first_visit === true ? Math.max(0,eligibleTotal-stacked) : 0;
  const currentTotal = original.total_cents - adjustment;
  const currentLines = original.line_items.map(line => {
    const replacement = adjustment > 0 ? stackedPricing.line_items.find(candidate => candidate.id === line.id) : null;
    if (!replacement) return line;
    const net = replacement.line_total_cents - replacement.discount_cents;
    return { ...line, discount_cents: line.line_total_cents - net, tax_cents: replacement.tax_cents, total_cents: replacement.total_cents };
  });
  const currentPricing = { ...original, line_items: currentLines, total_cents: currentTotal,
    discount_cents: currentLines.reduce((sum,line) => sum + line.discount_cents, 0),
    tax_cents: currentLines.reduce((sum,line) => sum + line.tax_cents, 0),
    balance_cents: Math.max(0,currentTotal-payments_cents), credit_cents: Math.max(0,payments_cents-currentTotal) };
  return {
    current_pricing: currentPricing,
    eligible_line_ids: scoped.map((line) => line.id), future_visit: future,
    discount_stacking_policy, existing_quote_discount_cents: original.discount_cents,
    original_total_cents: original.total_cents, current_adjustment_cents: adjustment,
    current_total_cents: currentTotal, payments_cents,
    current_balance_cents: Math.max(0, currentTotal - payments_cents),
    credit_due_cents: Math.max(0, payments_cents - currentTotal),
    activation_required: true, // A preview is never an unconditional ledger entry.
  };
}

export function calculatePlanInstallments({ visit_price_cents, visit_count, installment_count, prior_credit_cents = 0, enrollment_fee_cents = 0 }) {
  const price = quoteInteger(visit_price_cents, "Visit price");
  const visits = quoteInteger(visit_count, "Visit count", 1000, 1);
  const count = quoteInteger(installment_count, "Installment count", 1200, 1);
  const credit = quoteInteger(prior_credit_cents, "Previously paid covered visit credit");
  const fee = quoteInteger(enrollment_fee_cents, "Enrollment fee");
  const commitment = checkedMoney(BigInt(price) * BigInt(visits) + BigInt(fee), "Plan commitment");
  if (credit > commitment) fail("plan_credit_excess", "Prior credits exceed this plan's commitment; record the surplus separately.");
  const remaining = commitment - credit;
  const base = Math.floor(remaining / count);
  const extras = remaining % count;
  return { commitment_cents: commitment, prior_credit_cents: credit, remaining_cents: remaining, installments_cents: Array.from({ length: count }, (_, index) => base + (index < extras ? 1 : 0)) };
}

export function stableQuoteJSON(value) {
  if (Array.isArray(value)) return `[${value.map(stableQuoteJSON).join(",")}]`;
  if (record(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableQuoteJSON(value[key])}`).join(",")}}`;
  if (value === undefined || (typeof value === "number" && !Number.isFinite(value))) fail("packet_value_invalid", "Snapshots cannot contain undefined or nonfinite values.");
  return JSON.stringify(value);
}

export const quoteContentHash = (value) => createHash("sha256").update(stableQuoteJSON(value)).digest("hex");

// Only durable submitted signer records and reconciled payment totals enter this
// calculation. Neither legacy quote status nor browser success flags are inputs.
export function deriveAgreementState({ decision = "published", required_signers = ["customer"], submitted_signers = [], deposit_cents = 0, confirmed_payment_cents = 0, payment_processing = false, payment_adjusted = false, allow_customer_booking = false, booking_id = null, expires_at = null, now = new Date() }) {
  const deposit = quoteInteger(deposit_cents, "Required deposit");
  const confirmed = quoteInteger(confirmed_payment_cents, "Confirmed payments");
  if (!Array.isArray(required_signers) || !required_signers.length) fail("agreement_signers_required", "At least one required signer is needed.");
  const signed = required_signers.every((role) => submitted_signers.includes(role));
  const expiration = expires_at == null ? null : new Date(expires_at);
  if (expiration && !Number.isFinite(expiration.getTime())) fail("agreement_expiry_invalid", "The agreement expiration must be a valid timestamp.");
  const expired = submitted_signers.length === 0 && expiration !== null && expiration <= now;
  const stopped = ["declined", "superseded", "revoked"].includes(decision) || expired;
  const depositSatisfied = deposit === 0 || (!payment_adjusted && confirmed >= deposit);
  const complete = signed && depositSatisfied;
  return {
    decision: expired ? "expired" : decision,
    signing: signed ? "submitted" : submitted_signers.length ? "required_signers_pending" : "not_started",
    deposit: deposit === 0 ? "not_required" : payment_adjusted ? "adjusted_review_required" : confirmed >= deposit ? "paid" : payment_processing ? "processing" : signed ? "outstanding" : "locked",
    booking: !allow_customer_booking ? "not_offered" : booking_id ? "booked" : stopped || !complete ? "locked" : "eligible",
    base_workflow_complete: complete,
    can_sign: !signed && !stopped,
    can_checkout: signed && !stopped && !depositSatisfied && !payment_adjusted,
    can_view_availability: allow_customer_booking && complete && !stopped && !booking_id,
  };
}
