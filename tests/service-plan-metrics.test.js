import test from 'node:test';
import assert from 'node:assert/strict';
import { monthlyPlanRevenueCents } from '../service-plan-metrics.js';
test('monthly estimates include four yearly visit charges and preserve actual billing cadence', () => {
  const plan = {status:'active',price_cents:25500,billing_interval:'per_visit',service_interval:'month',service_interval_count:3,billing_mode:'automatic_per_visit'};
  assert.equal(monthlyPlanRevenueCents(plan),8500);
  assert.equal(monthlyPlanRevenueCents({...plan,service_interval_count:6}),4250);
  assert.equal(monthlyPlanRevenueCents({...plan,status:'paused'}),0);
  assert.equal(monthlyPlanRevenueCents({...plan,remaining_visits:0}),0);
  assert.equal(monthlyPlanRevenueCents({status:'active',price_cents:120000,billing_interval:'year',billing_interval_count:1}),10000);
});
test('prepaid normalized revenue uses the covered visit, not the whole package every visit', () => {
  assert.equal(monthlyPlanRevenueCents({status:'active',price_cents:102000,billing_interval:'prepaid',billing_mode:'prepaid',plan_snapshot:{future_visit:{total_cents:25500},configuration:{service_interval:{unit:'month',count:3}}}}),8500);
});
test('finite installments exclude an enrollment fee from estimated recurring revenue', () => {
  assert.equal(monthlyPlanRevenueCents({status:'active',price_cents:13500,billing_interval:'month',billing_interval_count:1,plan_snapshot:{configuration:{billing:{mode:'calendar_installments',enrollment_fee_cents:5000}},billing_schedule:[{amount_cents:13500},{amount_cents:8500}]}}),8500);
});
