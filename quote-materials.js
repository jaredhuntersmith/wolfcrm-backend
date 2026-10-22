import { randomUUID } from 'node:crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_CENTS = 2_000_000_000;

export class QuoteMaterialError extends Error {
  constructor(code, message, status = 400) { super(message); this.code = code; this.status = status; }
}

const fail = (code, message, status) => { throw new QuoteMaterialError(code, message, status); };
const uuid = (value, label) => typeof value === 'string' && UUID.test(value) ? value.toLowerCase() : fail('material_id_invalid', `${label} must be a UUID.`);
const text = (value, label, max, fallback = '') => {
  const result = value == null ? fallback : value;
  if (typeof result !== 'string' || result.length > max || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(result)) fail('material_text_invalid', `${label} must be text of at most ${max} characters.`);
  return result.trim();
};
const cents = (value, label, optional = false) => {
  if (optional && value == null) return null;
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_CENTS) fail('material_amount_invalid', `${label} must be a nonnegative whole number of cents.`);
  return value;
};
const quantityMillis = value => {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0 || value > 100_000 || !/^\d+(?:\.\d{1,3})?$/.test(String(value))) fail('material_quantity_invalid', 'Material quantity must be positive with at most three decimals.');
  const [whole, decimal = ''] = String(value).split('.');
  return BigInt(whole) * 1000n + BigInt(decimal.padEnd(3, '0'));
};
const lineAmount = (mode, unitCents, manualCents, quantity, label) => {
  if (mode === 'manual') return cents(manualCents, `${label} manual amount`);
  if (mode !== 'unit') fail('material_mode_invalid', `${label} must use a unit rate or manual amount.`);
  const rate = cents(unitCents, `${label} unit rate`);
  const result = (BigInt(rate) * quantity + 500n) / 1000n;
  return cents(Number(result), `${label} total`);
};

export function normalizeMaterialCatalog(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) fail('material_invalid', 'Enter a material.');
  const name = text(raw.name, 'Material name', 240);
  if (!name) fail('material_name_required', 'Enter a material name.');
  const unit = text(raw.unit, 'Unit', 60, 'each') || 'each';
  return { name, unit, default_cost_per_unit_cents: cents(raw.default_cost_per_unit_cents, 'Internal unit cost', true),
    default_charge_per_unit_cents: cents(raw.default_charge_per_unit_cents, 'Customer unit charge', true) };
}

export function normalizeQuoteMaterialLines(raw) {
  if (!Array.isArray(raw) || raw.length > 100) fail('material_lines_invalid', 'Use no more than 100 materials per quote.');
  const ids = new Set();
  return raw.map(item => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) fail('material_invalid', 'Each material must be an object.');
    const id = item.id == null ? randomUUID() : uuid(item.id, 'Material line ID');
    if (ids.has(id)) fail('material_line_duplicate', 'Each material line needs its own ID.');
    ids.add(id);
    const material_id = item.material_id == null ? null : uuid(item.material_id, 'Saved material ID');
    const name = text(item.name, 'Material name', 240);
    if (!name) fail('material_name_required', 'Each material needs a name.');
    const quantity = item.quantity ?? 1, units = quantityMillis(quantity);
    const unit = text(item.unit, 'Unit', 60, 'each') || 'each';
    const cost_mode = item.cost_mode ?? 'manual', charge_mode = item.charge_mode ?? 'manual';
    const cost_unit_cents = cost_mode === 'unit' ? cents(item.cost_unit_cents, 'Internal unit cost') : null;
    const charge_unit_cents = charge_mode === 'unit' ? cents(item.charge_unit_cents, 'Customer unit charge') : null;
    const cost_manual_cents = cost_mode === 'manual' ? cents(item.cost_manual_cents ?? 0, 'Internal manual amount') : null;
    const charge_manual_cents = charge_mode === 'manual' ? cents(item.charge_manual_cents ?? 0, 'Customer manual amount') : null;
    return { id, material_id, name, quantity, unit, cost_mode, cost_unit_cents, cost_manual_cents,
      charge_mode, charge_unit_cents, charge_manual_cents,
      cost_cents: lineAmount(cost_mode, cost_unit_cents, cost_manual_cents, units, 'Internal cost'),
      charge_cents: lineAmount(charge_mode, charge_unit_cents, charge_manual_cents, units, 'Customer charge') };
  });
}

export function materialChargeLines(materials = []) {
  return materials.map(item => ({ id: item.id, service_id: null, name: item.name,
    qty: item.charge_mode === 'unit' ? item.quantity : 1,
    price_cents: item.charge_mode === 'unit' ? item.charge_unit_cents : item.charge_cents,
    description: item.charge_mode === 'unit' ? item.unit : '' }));
}

export function materialCostCents(materials = []) {
  const total = materials.reduce((sum, item) => sum + BigInt(item.cost_cents), 0n);
  return cents(Number(total), 'Combined internal material cost');
}

export function publicMaterialPricing(pricing, materials = [], visibility = 'detailed') {
  if (!['detailed', 'summary', 'hidden'].includes(visibility)) fail('material_visibility_invalid', 'Choose detailed, summary, or hidden materials.');
  if (!materials.length || visibility === 'detailed') return pricing;
  const ids = new Set(materials.map(item => item.id));
  const materialRows = pricing.line_items.filter(item => ids.has(item.id));
  const serviceRows = pricing.line_items.filter(item => !ids.has(item.id));
  if (visibility === 'hidden') return { ...pricing, line_items: serviceRows };
  const sum = key => materialRows.reduce((total, item) => total + item[key], 0);
  return { ...pricing, line_items: [...serviceRows, { id: null, service_id: null, name: 'Materials', description: '', qty: 1,
    price_cents: sum('line_total_cents'), line_total_cents: sum('line_total_cents'), discount_cents: sum('discount_cents'),
    tax_cents: sum('tax_cents'), total_cents: sum('total_cents') }] };
}

export async function assertMaterialReferences(db, companyID, materials, existing = []) {
  const ids = [...new Set(materials.map(item => item.material_id).filter(Boolean))];
  if (!ids.length) return;
  if (!companyID) fail('company_required', 'Saved materials require a company workspace.', 403);
  const rows = (await db.query('SELECT id,archived_at FROM quote_material_catalog WHERE company_id=$1 AND id=ANY($2::uuid[])', [companyID, ids])).rows;
  const byID = new Map(rows.map(row => [row.id, row]));
  const historical = new Set(existing.map(item => `${item.id}:${item.material_id}`));
  for (const item of materials) {
    if (!item.material_id) continue;
    const row = byID.get(item.material_id);
    if (!row) fail('material_not_found', 'A selected material does not belong to this company.', 404);
    if (row.archived_at && !historical.has(`${item.id}:${item.material_id}`)) fail('material_archived', 'An archived material cannot be newly added to a quote.', 409);
  }
}

export async function installQuoteMaterialsSchema(pool) {
  await pool.query(`CREATE TABLE IF NOT EXISTS quote_material_catalog (
    id UUID PRIMARY KEY, company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
    name TEXT NOT NULL, unit TEXT NOT NULL DEFAULT 'each',
    default_cost_per_unit_cents INTEGER CHECK (default_cost_per_unit_cents >= 0),
    default_charge_per_unit_cents INTEGER CHECK (default_charge_per_unit_cents >= 0),
    archived_at TIMESTAMPTZ, version INTEGER NOT NULL DEFAULT 1,
    created_by UUID, updated_by UUID, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  CREATE INDEX IF NOT EXISTS quote_material_catalog_company_idx ON quote_material_catalog(company_id,lower(name),id) WHERE archived_at IS NULL;
  ALTER TABLE quotes ADD COLUMN IF NOT EXISTS materials JSONB NOT NULL DEFAULT '[]'::jsonb;
  ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS quote_material_estimate_cents INTEGER;
  `);
}

export function installQuoteMaterialCatalogRoutes({ app, pool, authRequired, requireCapability, requireAnyCapability }) {
  const handle = fn => async (req, res) => {
    if (!req.companyId) return res.status(403).json({ error: 'company_required' });
    try { await fn(req, res); }
    catch (error) {
      if (error instanceof QuoteMaterialError) return res.status(error.status).json({ error: error.code, message: error.message });
      console.error('[quote-materials] failed', { code: error?.code });
      res.status(500).json({ error: 'quote_materials_failed', message: 'Materials could not be loaded or saved.' });
    }
  };
  const columns = 'id,name,unit,default_cost_per_unit_cents,default_charge_per_unit_cents,archived_at,version';
  app.get('/api/quote-materials', authRequired, requireAnyCapability('quotes.view', 'settings.manage_company'), handle(async (req, res) => {
    const rows = (await pool.query(`SELECT ${columns} FROM quote_material_catalog WHERE company_id=$1 ${req.query.include_archived === 'true' ? '' : 'AND archived_at IS NULL'} ORDER BY lower(name),id`, [req.companyId])).rows;
    res.json(rows);
  }));
  app.put('/api/quote-materials/:id', authRequired, requireCapability('settings.manage_company'), handle(async (req, res) => {
    const id = uuid(req.params.id, 'Saved material ID'), value = normalizeMaterialCatalog(req.body);
    const expected = req.body?.expected_version;
    if (expected != null && (!Number.isSafeInteger(expected) || expected < 1)) fail('material_version_invalid', 'Refresh this material before saving.');
    const result = await pool.query(`INSERT INTO quote_material_catalog(id,company_id,name,unit,default_cost_per_unit_cents,default_charge_per_unit_cents,created_by,updated_by)
      VALUES($1,$2,$3,$4,$5,$6,$7,$7)
      ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,unit=EXCLUDED.unit,
        default_cost_per_unit_cents=EXCLUDED.default_cost_per_unit_cents,
        default_charge_per_unit_cents=EXCLUDED.default_charge_per_unit_cents,
        updated_by=EXCLUDED.updated_by,updated_at=now(),version=quote_material_catalog.version+1
      WHERE quote_material_catalog.company_id=$2 AND quote_material_catalog.archived_at IS NULL
        AND ($8::integer IS NULL OR quote_material_catalog.version=$8)
      RETURNING ${columns}`,
    [id, req.companyId, value.name, value.unit, value.default_cost_per_unit_cents, value.default_charge_per_unit_cents, req.userId, expected ?? null]);
    if (!result.rowCount) fail('material_changed', 'This material is unavailable or changed. Refresh it before saving.', 409);
    res.json(result.rows[0]);
  }));
  app.delete('/api/quote-materials/:id', authRequired, requireCapability('settings.manage_company'), handle(async (req, res) => {
    const id = uuid(req.params.id, 'Saved material ID');
    const row = (await pool.query(`UPDATE quote_material_catalog SET archived_at=COALESCE(archived_at,now()),
      version=CASE WHEN archived_at IS NULL THEN version+1 ELSE version END,updated_at=now(),updated_by=$3
      WHERE id=$1 AND company_id=$2 RETURNING ${columns}`, [id, req.companyId, req.userId])).rows[0];
    if (!row) fail('material_not_found', 'The material was not found.', 404);
    res.json(row);
  }));
}
