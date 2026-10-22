import assert from 'node:assert/strict';
import test from 'node:test';
import { mergeHistoricalQuoteCatalog } from '../quote-reuse.js';

const id = '11111111-1111-4111-8111-111111111111';
const component = '22222222-2222-4222-8222-222222222222';

test('historical line definitions restore without replacing current company rules', () => {
  const current = { questions: [], components: [], services: [], quote_minimum_cents: 5000 };
  const frozen = { questions: [], components: [{ id: component, name: 'Historical item', service_ids: [id], scope: 'service', unit: 'count', selection: 'default', decimal_quantity: false, money_enabled: true, time_enabled: false, fixed_cents: 1000, visible: true }], services: [{ service_id: id, crew_size: 1, elapsed_ratio_bp: 10000 }], quote_minimum_cents: 2000 };
  const first = mergeHistoricalQuoteCatalog(current, frozen, [id]);
  assert.equal(first.restored, 2);
  assert.equal(first.config.quote_minimum_cents, 5000);
  const next = mergeHistoricalQuoteCatalog(first.config, frozen, [id]);
  assert.equal(next.restored, 0);
  assert.deepEqual(next.config, first.config);
});
