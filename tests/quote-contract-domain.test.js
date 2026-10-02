import test from "node:test";
import assert from "node:assert/strict";
import { normalizeQuoteLines, normalizeQuoteOptions, calculateQuotePricing, calculatePlanOffer, calculatePlanInstallments, allocateQuoteAmount, deriveAgreementState, quoteContentHash } from "../quote-contract-domain.js";

const service = "11111111-1111-4111-8111-111111111111";
const other = "22222222-2222-4222-8222-222222222222";
const lines = () => [{ name: "Windows", service_id: service, qty: 1, price_cents: 30000 }, { name: "Pressure washing", service_id: other, qty: 1, price_cents: 40000 }];

test("current plan savings preserve signed promotions and explicit stacking without repeating them on future visits",()=>{
  for(const inclusive of [false,true]){
    const base=normalizeQuoteLines([{name:"Eligible",service_id:service,qty:2,price_cents:inclusive?5500:5000},{name:"One time",service_id:other,qty:1,price_cents:10000,taxable:false}]);
    const original=calculateQuotePricing({line_items:base,tax_rate_basis_points:1000,tax_inclusive:inclusive,discount:{type:"percent",value:2000}});
    const args={line_items:base,quoted_pricing:original,eligible_service_ids:[service],tier:{discount:{type:"percent",value:3000},discount_first_visit:true},tax_rate_basis_points:1000,tax_inclusive:inclusive};
    const best=calculatePlanOffer(args),stack=calculatePlanOffer({...args,discount_stacking_policy:"quote_then_plan"});
    assert.equal(original.total_cents,16800);assert.equal(best.original_total_cents,16800);assert.equal(best.current_adjustment_cents,1100);assert.equal(best.current_total_cents,15700);
    assert.equal(stack.current_adjustment_cents,2640);assert.equal(stack.current_total_cents,14160);assert.equal(stack.future_visit.total_cents,7700);assert.equal(stack.future_visit.line_items[0].qty,2);
    assert.equal(best.current_total_cents-7700,8000,"the noneligible discounted line stays intact");
    const betterQuote=calculateQuotePricing({line_items:base,tax_rate_basis_points:1000,tax_inclusive:inclusive,discount:{type:"percent",value:8000}});
    const retained=calculatePlanOffer({...args,quoted_pricing:betterQuote});assert.equal(retained.current_adjustment_cents,0);assert.equal(retained.current_total_cents,betterQuote.total_cents);
  }
});

test("stacked fixed discounts and fractional quantities use allocated cents without unit-price rounding",()=>{
  const base=normalizeQuoteLines([{name:"Fractional",service_id:service,qty:1.333,price_cents:1000},{name:"Other",service_id:other,qty:1,price_cents:1000,taxable:false}]);
  const quoted=calculateQuotePricing({line_items:base,tax_rate_basis_points:1000,discount:{type:"fixed",value:175}});
  assert.deepEqual(quoted.line_items.map(line=>line.discount_cents),[100,75]);
  const offer=calculatePlanOffer({line_items:base,quoted_pricing:quoted,eligible_service_ids:[service],tier:{discount:{type:"percent",value:1000},discount_first_visit:true},tax_rate_basis_points:1000,discount_stacking_policy:"quote_then_plan",payments_cents:3000});
  assert.equal(offer.current_adjustment_cents,135);assert.equal(offer.current_total_cents,2146);assert.equal(offer.credit_due_cents,854);assert.equal(offer.future_visit.line_items[0].qty,1.333);
  for(const discount of [{type:"none",value:1},{type:"percent",value:10001},{type:"fixed",value:-1}])assert.throws(()=>normalizeQuoteOptions({discount}));
});

test("historical lines gain independent stable IDs only in normalized output, no fabricated description or service reference", () => {
  const legacy = [{ name: "Same", qty: 1, price_cents: 10 }, { name: "Same", qty: 2, price_cents: 20 }];
  const normalized = normalizeQuoteLines(legacy);
  assert.notEqual(normalized[0].id, normalized[1].id);
  assert.equal(normalized[0].description, "");
  assert.equal(normalized[0].service_id, null);
  assert.equal(legacy[0].id, undefined);
  assert.deepEqual(normalizeQuoteLines(normalized), normalized);
});

test("duplicate line IDs and invalid IDs, money, quantities, booleans and oversized text fail explicitly", () => {
  const normalized = normalizeQuoteLines(lines());
  assert.throws(() => normalizeQuoteLines([normalized[0], normalized[0]]), /own ID/);
  for (const value of [-1, NaN, Infinity, 0.5, Number.MAX_SAFE_INTEGER]) {
    assert.throws(() => calculateQuotePricing({ line_items: [{ name: "Service", qty: 1, price_cents: value }] }));
  }
  for (const qty of [0, -1, 0.0001, "1", 100001, Infinity]) assert.throws(() => normalizeQuoteLines([{ name: "Service", price_cents: 2, qty }]));
  assert.throws(() => normalizeQuoteOptions({ allow_customer_booking: "false" }));
  assert.throws(() => normalizeQuoteOptions({ public_notes: "x".repeat(20001) }));
});

test("quantity decimals use exact half-up cent rounding, aggregate overflows are rejected", () => {
  const quote = calculateQuotePricing({ line_items: [{ name: "Half", qty: 0.5, price_cents: 101 }] });
  assert.equal(quote.total_cents, 51);
  assert.throws(() => calculateQuotePricing({ line_items: [{ name: "Too large", qty: 2, price_cents: 2_000_000_000 }] }));
});

test("deposit configuration validates boundaries and explicit zero without hidden defaults", () => {
  assert.equal(calculateQuotePricing({ line_items: lines() }).deposit_cents, 0);
  assert.equal(calculateQuotePricing({ line_items: lines(), deposit: { type: "percent", value: 2500 } }).deposit_cents, 17500);
  assert.equal(calculateQuotePricing({ line_items: lines(), deposit: { type: "fixed", value: 15000 } }).deposit_cents, 15000);
  for (const deposit of [{ type: "percent", value: 10001 }, { type: "fixed", value: 70001 }, { type: "none", value: 1 }, { type: "fixed", value: -1 }]) assert.throws(() => calculateQuotePricing({ line_items: lines(), deposit }));
  assert.throws(() => normalizeQuoteOptions({ allow_customer_booking: true }), /duration/);
  assert.equal(normalizeQuoteOptions({}).duration_minutes, null);
});

test("discounts allocate deterministically, cap before tax and do not lose cents", () => {
  assert.deepEqual(allocateQuoteAmount(2, [1, 1, 1]), [1, 1, 0]);
  assert.deepEqual(allocateQuoteAmount(5, [0, 10, 0]), [0, 5, 0]);
  const quote = calculateQuotePricing({ line_items: lines(), discount: { type: "fixed", value: 10000 }, tax_rate_basis_points: 1000 });
  assert.equal(quote.subtotal_cents, 70000);
  assert.equal(quote.discount_cents, 10000);
  assert.equal(quote.tax_cents, 6000);
  assert.equal(quote.total_cents, 66000);
  const free = calculateQuotePricing({ line_items: lines(), discount: { type: "fixed", value: 99999 }, tax_rate_basis_points: 1000 });
  assert.equal(free.total_cents, 0);
});

test("inclusive tax, non-taxable lines and overpayment credit remain explicit", () => {
  const quote = calculateQuotePricing({ line_items: [{ name: "Taxed", qty: 1, price_cents: 11000 }, { name: "Exempt", qty: 1, price_cents: 5000, taxable: false }], tax_rate_basis_points: 1000, tax_inclusive: true, payments_cents: 17000 });
  assert.equal(quote.tax_cents, 1000);
  assert.equal(quote.total_cents, 16000);
  assert.equal(quote.balance_cents, 0);
  assert.equal(quote.credit_cents, 1000);
});

test("required plan example credits deposit once, eligible scope only, optional first visit reduction", () => {
  const input = { line_items: lines(), eligible_service_ids: [service], payments_cents: 15000, tier: { discount: { type: "percent", value: 1500 }, discount_first_visit: false } };
  const futureOnly = calculatePlanOffer(input);
  assert.equal(futureOnly.future_visit.total_cents, 25500);
  assert.equal(futureOnly.current_total_cents, 70000);
  assert.equal(futureOnly.current_balance_cents, 55000);
  const withFirst = calculatePlanOffer({ ...input, tier: { ...input.tier, discount_first_visit: true } });
  assert.equal(withFirst.current_total_cents, 65500);
  assert.equal(withFirst.current_balance_cents, 50500);
  assert.equal(withFirst.activation_required, true);
  assert.equal(calculatePlanOffer({ ...input, eligible_service_ids: [] }), null);
});

test("fixed plan reduction applies once across eligible instances, cannot reduce ineligible scope; fully paid adjustment is credit", () => {
  const quoteLines = [...lines(), { name: "Second windows", service_id: service, price_cents: 1000, qty: 2 }];
  const offer = calculatePlanOffer({ line_items: quoteLines, eligible_service_ids: [service], tier: { discount: { type: "fixed", value: 99999 }, discount_first_visit: true }, payments_cents: 72000 });
  assert.equal(offer.future_visit.total_cents, 0);
  assert.equal(offer.current_total_cents, 40000);
  assert.equal(offer.credit_due_cents, 32000);
  assert.equal(offer.current_balance_cents, 0);
});

test("four $255 visits over twelve installments are $85 each, paid visit credits and rounding balance exactly", () => {
  assert.deepEqual(calculatePlanInstallments({ visit_price_cents: 25500, visit_count: 4, installment_count: 12 }).installments_cents, Array(12).fill(8500));
  const credited = calculatePlanInstallments({ visit_price_cents: 25500, visit_count: 4, installment_count: 12, prior_credit_cents: 25500 });
  assert.equal(credited.installments_cents.reduce((a, b) => a + b), 76500);
  assert.deepEqual(calculatePlanInstallments({ visit_price_cents: 100, visit_count: 1, installment_count: 3 }).installments_cents, [34, 33, 33]);
});

test("signing then confirmed deposit gates availability; processing and browser-like assertions do not unlock", () => {
  const input = { deposit_cents: 15000, allow_customer_booking: true };
  for (const state of [input, { ...input, submitted_signers: ["customer"] }, { ...input, submitted_signers: ["customer"], payment_processing: true }, { ...input, confirmed_payment_cents: 15000 }]) {
    assert.equal(deriveAgreementState(state).can_view_availability, false);
  }
  const complete = deriveAgreementState({ ...input, submitted_signers: ["customer"], confirmed_payment_cents: 15000 });
  assert.equal(complete.can_view_availability, true);
  assert.equal(complete.can_checkout, false);
  assert.equal(complete.base_workflow_complete, true);
  const unpaid = deriveAgreementState({ ...input, submitted_signers: ["customer"] });
  assert.equal(unpaid.signing, "submitted");
  assert.equal(unpaid.deposit, "outstanding");
});

test("no-booking/no-deposit completion, additional signers, expiry, revoked access and adjustments preserve evidence", () => {
  assert.equal(deriveAgreementState({ submitted_signers: ["customer"] }).base_workflow_complete, true);
  assert.equal(deriveAgreementState({ required_signers: ["customer", "business"], submitted_signers: ["customer"] }).signing, "required_signers_pending");
  assert.equal(deriveAgreementState({ required_signers: ["customer", "business"], submitted_signers: ["customer"], expires_at: "2020-01-01" }).can_sign, true);
  const signed = deriveAgreementState({ submitted_signers: ["customer"], expires_at: "2020-01-01" });
  assert.equal(signed.signing, "submitted");
  assert.equal(signed.decision, "published");
  assert.equal(deriveAgreementState({ expires_at: "2020-01-01" }).can_sign, false);
  assert.equal(deriveAgreementState({ submitted_signers: ["customer"], decision: "revoked", allow_customer_booking: true }).can_view_availability, false);
  assert.equal(deriveAgreementState({ submitted_signers: ["customer"], deposit_cents: 10, confirmed_payment_cents: 10, payment_adjusted: true }).can_checkout, false);
});

test("packet hashes ignore object key order, preserve line/text order and reject non-reproducible data", () => {
  assert.equal(quoteContentHash({ a: 1, b: [2, 3] }), quoteContentHash({ b: [2, 3], a: 1 }));
  assert.notEqual(quoteContentHash({ a: "First\nSecond" }), quoteContentHash({ a: "First Second" }));
  assert.throws(() => quoteContentHash({ a: undefined }));
});
