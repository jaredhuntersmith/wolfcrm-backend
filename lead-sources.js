import { randomUUID } from "node:crypto";

const defaults = new Map([
  ["facebook_zapier", { name: "Facebook Lead", key: "facebook" }],
  ["facebook_direct", { name: "Facebook Lead", key: "facebook" }],
  ["facebook lead", { name: "Facebook Lead", key: "facebook" }],
  ["zapier", { name: "Zapier Lead", key: "zapier" }],
  ["zapier lead", { name: "Zapier Lead", key: "zapier" }],
  ["map", { name: "Door-to-Door", key: "map" }],
  ["door-to-door", { name: "Door-to-Door", key: "map" }]
]);

export function normalizeLeadSource(raw) {
  const value = typeof raw === "string" ? raw.trim() : "";
  if (!value) return null;
  if (value.length > 100) throw new LeadSourceError("lead_source_name_invalid", "Lead source names must be 1–100 characters.");
  return defaults.get(value.toLowerCase()) || { name: value, key: null };
}

export class LeadSourceError extends Error {
  constructor(code, message, statusCode = 400) {
    super(message);
    this.code = code;
    this.statusCode = statusCode;
  }
}

export async function installLeadSourcesSchema(db) {
  await db.query(`
    CREATE TABLE IF NOT EXISTS lead_sources (
      id UUID PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id),
      name TEXT NOT NULL,
      system_key TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      archived_at TIMESTAMPTZ
    );
    CREATE UNIQUE INDEX IF NOT EXISTS lead_sources_active_name_unique
      ON lead_sources(company_id, lower(name)) WHERE archived_at IS NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS lead_sources_active_key_unique
      ON lead_sources(company_id, system_key) WHERE archived_at IS NULL AND system_key IS NOT NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS lead_sources_company_id_unique
      ON lead_sources(company_id, id);
    ALTER TABLE contacts ADD COLUMN IF NOT EXISTS lead_source_id UUID REFERENCES lead_sources(id);
    ALTER TABLE contacts ADD COLUMN IF NOT EXISTS source_raw TEXT;
    DO $lead_source_scope$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='contacts_lead_source_company_fk') THEN
        ALTER TABLE contacts ADD CONSTRAINT contacts_lead_source_company_fk
          FOREIGN KEY (company_id, lead_source_id) REFERENCES lead_sources(company_id, id);
      END IF;
    END $lead_source_scope$;
    CREATE INDEX IF NOT EXISTS contacts_lead_source_idx ON contacts(company_id, lead_source_id);
  `);
  // Preserve the exact source value as provenance. Only known creation-path labels
  // are canonicalized; every other stored value retains its own identity.
  await db.query(`
    WITH observed AS (
      SELECT DISTINCT company_id,
        CASE lower(trim(source))
          WHEN 'facebook_zapier' THEN 'Facebook Lead'
          WHEN 'facebook_direct' THEN 'Facebook Lead'
          WHEN 'facebook lead' THEN 'Facebook Lead'
          WHEN 'zapier' THEN 'Zapier Lead'
          WHEN 'zapier lead' THEN 'Zapier Lead'
          WHEN 'map' THEN 'Door-to-Door'
          WHEN 'door-to-door' THEN 'Door-to-Door'
          ELSE trim(source) END AS name,
        CASE lower(trim(source))
          WHEN 'facebook_zapier' THEN 'facebook'
          WHEN 'facebook_direct' THEN 'facebook'
          WHEN 'facebook lead' THEN 'facebook'
          WHEN 'zapier' THEN 'zapier'
          WHEN 'zapier lead' THEN 'zapier'
          WHEN 'map' THEN 'map'
          WHEN 'door-to-door' THEN 'map'
          ELSE NULL END AS system_key
      FROM contacts WHERE company_id IS NOT NULL AND lead_source_id IS NULL
        AND nullif(trim(source), '') IS NOT NULL
    ), distinct_names AS (
      SELECT DISTINCT ON (company_id, lower(name)) company_id, name, system_key
      FROM observed ORDER BY company_id, lower(name), name
    )
    INSERT INTO lead_sources(id, company_id, name, system_key)
    SELECT gen_random_uuid(), company_id, name, system_key FROM distinct_names
    ON CONFLICT DO NOTHING;
    UPDATE contacts c SET
      source_raw = COALESCE(c.source_raw, c.source),
      lead_source_id = ls.id,
      source = ls.name
    FROM lead_sources ls
    WHERE c.company_id = ls.company_id AND c.lead_source_id IS NULL
      AND ls.archived_at IS NULL AND (
        lower(ls.name) = lower(CASE lower(trim(c.source))
          WHEN 'facebook_zapier' THEN 'Facebook Lead'
          WHEN 'facebook_direct' THEN 'Facebook Lead'
          WHEN 'facebook lead' THEN 'Facebook Lead'
          WHEN 'zapier' THEN 'Zapier Lead'
          WHEN 'zapier lead' THEN 'Zapier Lead'
          WHEN 'map' THEN 'Door-to-Door'
          WHEN 'door-to-door' THEN 'Door-to-Door'
          ELSE trim(c.source) END)
      );
  `);
  // Integrations and automations still write contacts directly. Keep their new
  // records normalized without requiring every writer to change in lockstep.
  await db.query(`
    CREATE OR REPLACE FUNCTION wolf_contact_lead_source() RETURNS trigger
    LANGUAGE plpgsql AS $lead_source_trigger$
    DECLARE raw_name text; display_name text; source_key text; selected_id uuid;
    BEGIN
      IF NEW.company_id IS NULL THEN RETURN NEW; END IF;
      IF TG_OP='UPDATE' AND NEW.source IS DISTINCT FROM OLD.source
         AND NEW.lead_source_id IS NOT DISTINCT FROM OLD.lead_source_id THEN
        NEW.lead_source_id := NULL;
      END IF;
      IF NEW.lead_source_id IS NOT NULL THEN RETURN NEW; END IF;
      raw_name := nullif(trim(NEW.source), '');
      IF raw_name IS NULL THEN RETURN NEW; END IF;
      NEW.source_raw := COALESCE(NEW.source_raw, raw_name);
      CASE lower(raw_name)
        WHEN 'facebook_zapier' THEN display_name:='Facebook Lead'; source_key:='facebook';
        WHEN 'facebook_direct' THEN display_name:='Facebook Lead'; source_key:='facebook';
        WHEN 'facebook lead' THEN display_name:='Facebook Lead'; source_key:='facebook';
        WHEN 'zapier' THEN display_name:='Zapier Lead'; source_key:='zapier';
        WHEN 'zapier lead' THEN display_name:='Zapier Lead'; source_key:='zapier';
        WHEN 'map' THEN display_name:='Door-to-Door'; source_key:='map';
        WHEN 'door-to-door' THEN display_name:='Door-to-Door'; source_key:='map';
        ELSE display_name:=raw_name; source_key:=NULL;
      END CASE;
      SELECT id INTO selected_id FROM lead_sources
       WHERE company_id=NEW.company_id AND archived_at IS NULL
         AND ((source_key IS NOT NULL AND system_key=source_key) OR lower(name)=lower(display_name))
       ORDER BY CASE WHEN system_key=source_key THEN 0 ELSE 1 END LIMIT 1;
      IF selected_id IS NULL THEN
        INSERT INTO lead_sources(id,company_id,name,system_key)
        VALUES(gen_random_uuid(),NEW.company_id,display_name,source_key)
        ON CONFLICT DO NOTHING;
        SELECT id INTO selected_id FROM lead_sources
         WHERE company_id=NEW.company_id AND archived_at IS NULL
           AND ((source_key IS NOT NULL AND system_key=source_key) OR lower(name)=lower(display_name))
         ORDER BY CASE WHEN system_key=source_key THEN 0 ELSE 1 END LIMIT 1;
      END IF;
      NEW.lead_source_id := selected_id;
      IF selected_id IS NOT NULL THEN
        SELECT name INTO NEW.source FROM lead_sources WHERE id=selected_id;
      END IF;
      RETURN NEW;
    END $lead_source_trigger$;
    DO $lead_source_install$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='contacts'::regclass AND tgname='contacts_lead_source_sync') THEN
        CREATE TRIGGER contacts_lead_source_sync BEFORE INSERT OR UPDATE OF source,lead_source_id,company_id
          ON contacts FOR EACH ROW EXECUTE FUNCTION wolf_contact_lead_source();
      END IF;
    END $lead_source_install$;
  `);
}

export async function ensureLeadSource(db, companyId, raw) {
  if (!companyId) return null;
  const normalized = normalizeLeadSource(raw);
  if (!normalized) return null;
  const existing = (await db.query(
    `SELECT * FROM lead_sources WHERE company_id=$1 AND archived_at IS NULL
       AND (($2::text IS NOT NULL AND system_key=$2) OR lower(name)=lower($3))
       ORDER BY CASE WHEN system_key=$2 THEN 0 ELSE 1 END LIMIT 1`,
    [companyId, normalized.key, normalized.name]
  )).rows[0];
  if (existing) return existing;
  await db.query(
    `INSERT INTO lead_sources(id,company_id,name,system_key) VALUES($1,$2,$3,$4)
       ON CONFLICT DO NOTHING`,
    [randomUUID(), companyId, normalized.name, normalized.key]
  );
  return (await db.query(
    `SELECT * FROM lead_sources WHERE company_id=$1 AND archived_at IS NULL
       AND (($2::text IS NOT NULL AND system_key=$2) OR lower(name)=lower($3))
       ORDER BY CASE WHEN system_key=$2 THEN 0 ELSE 1 END LIMIT 1`,
    [companyId, normalized.key, normalized.name]
  )).rows[0] || null;
}

export async function selectedLeadSource(db, companyId, id) {
  if (id == null || id === "") return null;
  if (!companyId || typeof id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) {
    throw new LeadSourceError("lead_source_invalid", "Choose a valid company lead source.");
  }
  const row = (await db.query(
    "SELECT * FROM lead_sources WHERE id=$1 AND company_id=$2 AND archived_at IS NULL",
    [id, companyId]
  )).rows[0];
  if (!row) throw new LeadSourceError("lead_source_not_found", "That lead source is unavailable.", 404);
  return row;
}
