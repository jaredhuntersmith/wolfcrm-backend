const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export class ServiceCatalogError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export function serviceUUID(value) {
  if (typeof value !== "string" || !UUID.test(value)) {
    throw new ServiceCatalogError("service_id_invalid", "A valid saved service ID is required.");
  }
  return value.toLowerCase();
}

function text(value, field, maximum, fallback = "") {
  const result = value === undefined ? fallback : value;
  if (typeof result !== "string" || result.length > maximum || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(result)) {
    throw new ServiceCatalogError("service_field_invalid", `${field} must be text of at most ${maximum} characters.`);
  }
  return result.replace(/\r\n?/g, "\n");
}

export function normalizeSavedService(raw, { importing = false } = {}) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new ServiceCatalogError("service_invalid", "A saved service is required.");
  const name = text(raw.name, "Service name", 240).trim();
  if (!name) throw new ServiceCatalogError("service_name_required", "Enter a service name.");
  const price = raw.default_price_cents ?? null;
  if (price !== null && (!Number.isSafeInteger(price) || price < 0 || price > 2000000000)) {
    throw new ServiceCatalogError("service_price_invalid", "The default price must be a nonnegative whole number of cents.");
  }
  const presets = raw.description_presets ?? [];
  if (!Array.isArray(presets) || presets.length > 50) throw new ServiceCatalogError("service_presets_invalid", "Use no more than 50 description presets per service.");
  const ids = new Set();
  const description_presets = presets.map((preset) => {
    if (!preset || typeof preset !== "object") throw new ServiceCatalogError("service_presets_invalid", "Each preset must have a name and description.");
    const id = serviceUUID(preset.id);
    if (ids.has(id)) throw new ServiceCatalogError("service_presets_invalid", "Preset IDs must be unique within the service.");
    ids.add(id);
    const presetName = text(preset.name, "Preset name", 120).trim();
    if (!presetName) throw new ServiceCatalogError("service_presets_invalid", "Enter a name for each preset.");
    return { id, name: presetName, description: text(preset.description, "Preset description", 20000) };
  });
  const default_preset_id = raw.default_preset_id == null ? null : serviceUUID(raw.default_preset_id);
  if (default_preset_id && !ids.has(default_preset_id)) throw new ServiceCatalogError("service_default_preset_invalid", "The default preset must belong to this service.");
  if (raw.plan_eligible !== undefined && typeof raw.plan_eligible !== "boolean") throw new ServiceCatalogError("service_eligibility_invalid", "Service plan eligibility must be on or off.");
  return {
    name, default_price_cents: price,
    default_description: text(raw.default_description, "Default description", 20000),
    description_presets, default_preset_id,
    // Local catalogs never contained an eligibility opt-in. Import cannot enable it.
    plan_eligible: importing ? false : raw.plan_eligible === true
  };
}

export async function installServiceCatalogSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS saved_services (
      id UUID PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
      name TEXT NOT NULL,
      default_price_cents INTEGER CHECK (default_price_cents >= 0),
      default_description TEXT NOT NULL DEFAULT '',
      description_presets JSONB NOT NULL DEFAULT '[]'::jsonb,
      default_preset_id UUID,
      plan_eligible BOOLEAN NOT NULL DEFAULT false,
      archived_at TIMESTAMPTZ,
      version INTEGER NOT NULL DEFAULT 1,
      created_by UUID,
      updated_by UUID,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS saved_services_company_name_idx ON saved_services(company_id, name, id) WHERE archived_at IS NULL;
    ALTER TABLE quotes ADD COLUMN IF NOT EXISTS quote_options JSONB NOT NULL DEFAULT '{}'::jsonb;
  `);
}

const COLUMNS = "id, name, default_price_cents, default_description, description_presets, default_preset_id, plan_eligible, archived_at, version";

export async function assertQuoteReferences(pool, req, { contact_id, line_items = [], existing_lines = [] }) {
  if (contact_id !== undefined) {
    if (typeof contact_id !== "string" || !contact_id.trim()) throw new ServiceCatalogError("contact_id_required", "Select a customer for this quote.");
    const contact = await pool.query(
      `SELECT id FROM contacts WHERE id::text = $1 AND ${req.companyId ? "company_id" : "user_id"} = $2`,
      [contact_id, req.companyId || req.userId]
    );
    if (!contact.rowCount) throw new ServiceCatalogError("contact_not_found", "The customer was not found in this company.", 404);
  }
  const serviceIDs = [...new Set(line_items.map((item) => item.service_id).filter(Boolean))];
  if (!serviceIDs.length) return;
  if (!req.companyId) throw new ServiceCatalogError("company_required", "Saved services require a company workspace.", 403);
  const services = await pool.query(`SELECT id, archived_at FROM saved_services WHERE company_id = $1 AND id = ANY($2::uuid[])`, [req.companyId, serviceIDs]);
  const byID = new Map(services.rows.map((service) => [service.id, service]));
  const historicalLines = new Set(existing_lines.map((item) => `${item.id}:${item.service_id}`));
  for (const id of serviceIDs) {
    if (!byID.has(id)) throw new ServiceCatalogError("quote_service_not_found", "A selected service does not belong to this company.", 404);
    if (byID.get(id).archived_at && line_items.some((item) => item.service_id === id && !historicalLines.has(`${item.id}:${id}`))) throw new ServiceCatalogError("quote_service_archived", "An archived service cannot be added to a new quote line.", 409);
  }
}

export function installServiceCatalogRoutes({ app, pool, authRequired, requireCapability, requireAnyCapability }) {
  const route = (handler) => async (req, res) => {
    if (!req.companyId) return res.status(403).json({ error: "company_required", message: "Saved services require a company workspace." });
    try { await handler(req, res); }
    catch (error) {
      if (error instanceof ServiceCatalogError) return res.status(error.status).json({ error: error.code, message: error.message });
      console.error("[services] request failed", { code: error?.code });
      res.status(500).json({ error: "service_catalog_failed", message: "The saved services could not be updated. Please try again." });
    }
  };
  app.get("/api/services", authRequired, requireAnyCapability("quotes.view", "schedule.view"), route(async (req, res) => {
    const includeArchived = req.query.include_archived === "true";
    const result = await pool.query(`SELECT ${COLUMNS} FROM saved_services WHERE company_id = $1 ${includeArchived ? "" : "AND archived_at IS NULL"} ORDER BY lower(name), id`, [req.companyId]);
    res.json(result.rows);
  }));
  app.put("/api/services/:id", authRequired, requireCapability("settings.manage_company"), route(async (req, res) => {
    const id = serviceUUID(req.params.id);
    const service = normalizeSavedService(req.body);
    if (req.body.expected_version !== undefined && (!Number.isSafeInteger(req.body.expected_version) || req.body.expected_version < 1)) throw new ServiceCatalogError("service_version_invalid", "Refresh this service before saving.");
    const result = await pool.query(`INSERT INTO saved_services(id,company_id,name,default_price_cents,default_description,description_presets,default_preset_id,plan_eligible,created_by,updated_by)
      VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$9)
      ON CONFLICT(id) DO UPDATE SET name = EXCLUDED.name, default_price_cents = EXCLUDED.default_price_cents,
        default_description = EXCLUDED.default_description, description_presets = EXCLUDED.description_presets,
        default_preset_id = EXCLUDED.default_preset_id, plan_eligible = EXCLUDED.plan_eligible,
        updated_by = EXCLUDED.updated_by, updated_at = now(), version = saved_services.version + 1
      WHERE saved_services.company_id = $2 AND saved_services.archived_at IS NULL
        AND ($10::integer IS NULL OR saved_services.version = $10)
      RETURNING ${COLUMNS}`, [id, req.companyId, service.name, service.default_price_cents, service.default_description, JSON.stringify(service.description_presets), service.default_preset_id, service.plan_eligible, req.userId, req.body.expected_version ?? null]);
    if (!result.rowCount) throw new ServiceCatalogError("service_unavailable_or_changed", "The service is unavailable or has changed. Refresh before saving.", 409);
    res.json(result.rows[0]);
  }));
  app.post("/api/services/import", authRequired, requireAnyCapability("quotes.create", "schedule.create", "settings.manage_company"), route(async (req, res) => {
    if (!Array.isArray(req.body?.services) || req.body.services.length > 500) throw new ServiceCatalogError("service_import_invalid", "Import up to 500 saved services at a time.");
    const ids = new Set();
    const services = req.body.services.map((raw) => {
      const id = serviceUUID(raw?.id);
      if (ids.has(id)) throw new ServiceCatalogError("service_import_invalid", "Each imported service must have a unique ID.");
      ids.add(id);
      return { id, ...normalizeSavedService(raw, { importing: true }) };
    });
    const db = await pool.connect();
    try {
      await db.query("BEGIN");
      // Serialize catalog imports without conflating IDs or guessing from names.
      await db.query(`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, [`services-import:${req.companyId}`]);
      for (const service of services) {
        await db.query(`INSERT INTO saved_services(id,company_id,name,default_price_cents,default_description,description_presets,default_preset_id,created_by,updated_by)
          VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$8) ON CONFLICT(id) DO NOTHING`,
        [service.id, req.companyId, service.name, service.default_price_cents, service.default_description, JSON.stringify(service.description_presets), service.default_preset_id, req.userId]);
      }
      const owned = await db.query(`SELECT id FROM saved_services WHERE company_id = $1 AND id = ANY($2::uuid[])`, [req.companyId, services.map((service) => service.id)]);
      if (owned.rowCount !== services.length) throw new ServiceCatalogError("service_import_id_conflict", "An imported ID is unavailable. No services were imported.", 409);
      const result = await db.query(`SELECT ${COLUMNS} FROM saved_services WHERE company_id = $1 AND archived_at IS NULL ORDER BY lower(name), id`, [req.companyId]);
      await db.query("COMMIT");
      res.json(result.rows);
    } catch (error) { await db.query("ROLLBACK"); throw error; }
    finally { db.release(); }
  }));
  app.delete("/api/services/:id", authRequired, requireCapability("settings.manage_company"), route(async (req, res) => {
    const id = serviceUUID(req.params.id);
    const result = await pool.query(`UPDATE saved_services SET archived_at = COALESCE(archived_at, now()),
      version = CASE WHEN archived_at IS NULL THEN version + 1 ELSE version END, updated_by = $3, updated_at = now()
      WHERE id = $1 AND company_id = $2 RETURNING ${COLUMNS}`, [id, req.companyId, req.userId]);
    if (!result.rowCount) throw new ServiceCatalogError("service_not_found", "The saved service was not found.", 404);
    res.json(result.rows[0]);
  }));
}
