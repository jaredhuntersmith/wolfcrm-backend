import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { calculateQuotePricing } from '../quote-contract-domain.js';
import { normalizeMaterialCatalog, normalizeQuoteMaterialLines, materialChargeLines,
  materialCostCents, publicMaterialPricing, assertMaterialReferences } from '../quote-materials.js';

test('unit and manual material amounts have independent internal cost and customer charge', () => {
  const unit = normalizeQuoteMaterialLines([{ id: randomUUID(), name: 'Stone', quantity: 2.375, unit: 'square feet',
    cost_mode: 'unit', cost_unit_cents: 107, charge_mode: 'unit', charge_unit_cents: 323 }])[0];
  assert.equal(unit.cost_cents, 254);
  assert.equal(unit.charge_cents, 767);
  const manual = normalizeQuoteMaterialLines([{ id: randomUUID(), name: 'Custom fitting',
    cost_mode: 'manual', cost_manual_cents: 3456, charge_mode: 'manual', charge_manual_cents: 7123 }])[0];
  assert.equal(manual.cost_cents, 3456);
  assert.equal(manual.charge_cents, 7123);
  assert.equal(materialCostCents([unit, manual]), 3710);
  assert.equal(materialChargeLines([unit, manual]).reduce((sum, row) => sum + Math.round(row.qty * row.price_cents), 0), 7890);
});

test('customer projections retain totals and never contain internal material costs', () => {
  const materials = normalizeQuoteMaterialLines([{ id: randomUUID(), name: 'Stone', quantity: 2, unit: 'bags',
    cost_mode: 'unit', cost_unit_cents: 1000, charge_mode: 'unit', charge_unit_cents: 2500 }]);
  const service = { id: randomUUID(), name: 'Installation', qty: 1, price_cents: 10000 };
  const pricing = calculateQuotePricing({ line_items: [service, ...materialChargeLines(materials)], tax_rate_basis_points: 1000 });
  assert.equal(pricing.subtotal_cents, 15000);
  for (const visibility of ['detailed', 'summary', 'hidden']) {
    const publicValue = publicMaterialPricing(pricing, materials, visibility);
    assert.equal(publicValue.subtotal_cents, 15000);
    assert.equal(publicValue.total_cents, 16500);
    assert.ok(!JSON.stringify(publicValue).includes('cost_cents'));
    if (visibility === 'detailed') assert.ok(publicValue.line_items.some(row => row.name === 'Stone'));
    if (visibility === 'summary') assert.ok(publicValue.line_items.some(row => row.name === 'Materials'));
    if (visibility === 'hidden') assert.ok(!publicValue.line_items.some(row => row.name === 'Stone'));
  }
});

test('invalid money, quantity and catalog references are rejected', async () => {
  for (const quantity of [0, -1, 1.0001, 100001]) assert.throws(() => normalizeQuoteMaterialLines([{ name: 'Stone', quantity }]), { code: 'material_quantity_invalid' });
  assert.throws(() => normalizeQuoteMaterialLines([{ name: 'Stone', cost_mode: 'unit', cost_unit_cents: -1 }]), { code: 'material_amount_invalid' });
  assert.throws(() => normalizeMaterialCatalog({ name: 'Stone', default_cost_per_unit_cents: '100' }), { code: 'material_amount_invalid' });
  const id = randomUUID(), line = normalizeQuoteMaterialLines([{ id: randomUUID(), material_id: id, name: 'Stone' }])[0];
  const db = { query: async () => ({ rows: [{ id, archived_at: new Date() }] }) };
  await assertMaterialReferences(db, randomUUID(), [line], [line]);
  await assert.rejects(assertMaterialReferences(db, randomUUID(), [line]), { code: 'material_archived' });
});
