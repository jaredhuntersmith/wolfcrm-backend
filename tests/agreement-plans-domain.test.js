import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { normalizePlanTier, buildPlanOffer, advancePlanDate } from '../agreement-plans-domain.js';
import { calculateQuotePricing } from '../quote-contract-domain.js';
const windowID = randomUUID(), pressureID = randomUUID();
const lines = [{ id: randomUUID(), service_id: windowID, name: 'Windows', qty: 1, price_cents: 30000 }, { id: randomUUID(), service_id: pressureID, name: 'Pressure washing', qty: 1, price_cents: 40000 }];
const config = { name: 'Quarterly windows', discount: { type: 'percent', value: 1500 }, service_interval: { unit: 'month', count: 3 }, cancellation_policy: 'Cancel before renewal; changed pricing requires a new signed agreement.', agreement: { agreement_text: 'Quarterly service.', consent_text: 'I accept this plan.' } };
const agreement = { id: randomUUID(), packet_hash: 'immutable', snapshot: { pricing: calculateQuotePricing({ line_items: lines }) } };
const tier = (extra = {}) => ({ tier_id: randomUUID(), version: 1, configuration: { ...config, ...extra } });
const offer = (extra = {}) => buildPlanOffer({ agreement, tier: tier(extra), eligible_service_ids: [windowID], payments_cents: 15000, today: '2026-01-31' });

test('plan tiers reject unsupported or ambiguous billing and preserve explicit eligibility', () => {
  assert.throws(() => normalizePlanTier({ ...config, billing: { mode: 'calendar_installments', installment_count: 12 } }), /included visit count/);
  assert.throws(() => normalizePlanTier({ ...config, service_ids: [] }), /subset/);
  assert.throws(() => normalizePlanTier({ ...config, discount: { type: 'percent', value: 10001 } }));
  assert.throws(() => normalizePlanTier({ ...config, agreement: {} }), /agreement/);
  assert.equal(normalizePlanTier(config).discount_first_visit, false);
  assert.equal(normalizePlanTier(config).billing.mode, 'manual_per_visit');
  assert.equal(buildPlanOffer({ agreement, tier: tier(), eligible_service_ids: [], today: '2026-01-31' }), null);
  assert.equal(offer({discount:{type:'none',value:0}}).future_visit.total_cents,30000);
});

test('required 300+400 example yields 255 future and exact 550 or505 current balance', () => {
  const futureOnly = offer();
  assert.equal(futureOnly.future_visit.total_cents, 25500);
  assert.equal(futureOnly.current_total_cents, 70000);
  assert.equal(futureOnly.current_balance_cents, 55000);
  const current = offer({ discount_first_visit: true });
  assert.equal(current.current_total_cents, 65500);
  assert.equal(current.current_balance_cents, 50500);
  assert.deepEqual(current.eligible_line_ids, [lines[0].id]);
  assert.equal(current.future_visit.line_items[0].service_id, windowID);
  assert.equal(current.activation_required, true);
});

test('four255 visits over12 months are85 installments and initial allocation cannot bill twice', () => {
  const config = { term: { kind: 'finite', visit_count: 4 }, billing: { mode: 'calendar_installments', installment_count: 12, interval: { unit: 'month', count: 1 } } };
  const quarterly = offer(config);
  assert.equal(quarterly.installments.commitment_cents, 102000);
  assert.deepEqual(quarterly.billing_schedule.map((entry) => entry.amount_cents), Array(12).fill(8500));
  const initialCounts = offer({ ...config, current_visit_counts: true });
  assert.equal(initialCounts.future_visit_count, 3);
  assert.equal(initialCounts.installments.prior_credit_cents, 25500);
  assert.deepEqual(initialCounts.billing_schedule.map((entry) => entry.amount_cents), Array(12).fill(6375));
  assert.equal(initialCounts.current_total_cents, 70000);
  assert.match(initialCounts.financial_text, /remains billed on the original job/);
});

test('calendar cadence preserves month anchor, leap dates and rejects impossible dates', () => {
  assert.equal(advancePlanDate('2026-01-31', { unit: 'month', count: 1 }), '2026-02-28');
  assert.equal(advancePlanDate('2026-01-31', { unit: 'month', count: 1 }, 2), '2026-03-31');
  assert.equal(advancePlanDate('2024-02-29', { unit: 'year', count: 1 }), '2025-02-28');
  assert.throws(() => advancePlanDate('2026-02-30', { unit: 'month', count: 1 }));
});

test('paid current discounts become explicit credit obligations and offer hashes bind tier and ledger', () => {
  const chosen = tier({ discount_first_visit: true });
  const make = (payments) => buildPlanOffer({ agreement, tier: chosen, eligible_service_ids: [windowID], payments_cents: payments, today: '2026-01-31' });
  assert.equal(make(70000).credit_due_cents, 4500);
  assert.notEqual(make(15000).offer_hash, make(70000).offer_hash);
  assert.equal(make(15000).offer_hash, make(15000).offer_hash);
});

test('replacement terms never repeat an existing current-job discount or initial visit allocation',()=>{
  const chosen=tier({discount_first_visit:true,current_visit_counts:true,term:{kind:'finite',visit_count:4},billing:{mode:'calendar_installments',installment_count:12}});
  const replacement=buildPlanOffer({agreement,tier:chosen,eligible_service_ids:[windowID],payments_cents:15000,today:'2026-01-31',prior_adjustment_cents:4500,initial_visit_already_counted:true});
  assert.equal(replacement.current_adjustment_cents,0);assert.equal(replacement.current_total_cents,65500);assert.equal(replacement.current_balance_cents,50500);
  assert.equal(replacement.future_visit_count,4);assert.equal(replacement.installments.prior_credit_cents,0);assert.deepEqual(replacement.installments.installments_cents,Array(12).fill(8500));
  assert.match(replacement.financial_text,/not counted or credited again/);
  const improved=buildPlanOffer({agreement,tier:{...chosen,configuration:{...chosen.configuration,discount:{type:'percent',value:2000}}},eligible_service_ids:[windowID],today:'2026-01-31',prior_adjustment_cents:4500});
  assert.equal(improved.current_adjustment_cents,1500);assert.equal(improved.current_total_cents,64000);
});

test('hidden plan wording cannot satisfy required agreement but an attached contract can', () => {
  assert.throws(()=>normalizePlanTier({...config,agreement:{...config.agreement,show_agreement:false}}),error=>error.code==='plan_agreement_required');
  const withPDF=normalizePlanTier({...config,agreement:{...config.agreement,show_agreement:false,documents:[{asset_id:randomUUID(),fields:[]}]}});
  assert.equal(withPDF.agreement.show_agreement,false);
  assert.equal(withPDF.agreement.agreement_text,'Quarterly service.');
});
