export async function installFacebookLeadSchema(db) {
  await db.query(`
    CREATE TABLE IF NOT EXISTS facebook_lead_settings (
      company_id UUID PRIMARY KEY REFERENCES companies(id) ON DELETE CASCADE,
      configuration JSONB NOT NULL DEFAULT '{"unknown_policy":"lead_info","overwrite":false,"mappings":{}}',
      revision INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS facebook_lead_connections (
      company_id UUID PRIMARY KEY REFERENCES companies(id) ON DELETE CASCADE,
      user_id UUID NOT NULL REFERENCES users(id), meta_user_id TEXT, token TEXT,
      status TEXT NOT NULL DEFAULT 'disconnected', permissions JSONB NOT NULL DEFAULT '[]',
      error_code TEXT, checked_at TIMESTAMPTZ, updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    ALTER TABLE facebook_lead_connections ADD COLUMN IF NOT EXISTS unified boolean NOT NULL DEFAULT false;
    ALTER TABLE facebook_lead_connections ADD COLUMN IF NOT EXISTS importing_paused boolean NOT NULL DEFAULT false;
    ALTER TABLE facebook_lead_connections ADD COLUMN IF NOT EXISTS expires_at timestamptz;
    CREATE INDEX IF NOT EXISTS facebook_lead_connection_user_idx ON facebook_lead_connections(user_id);
    CREATE INDEX IF NOT EXISTS facebook_lead_connection_meta_idx ON facebook_lead_connections(meta_user_id);
    CREATE TABLE IF NOT EXISTS facebook_lead_pages (
      company_id UUID NOT NULL REFERENCES facebook_lead_connections(company_id) ON DELETE CASCADE,
      page_id TEXT NOT NULL, name TEXT NOT NULL, token TEXT, selected BOOLEAN NOT NULL DEFAULT false,
      subscription TEXT NOT NULL DEFAULT 'unchecked', retrieval TEXT NOT NULL DEFAULT 'unchecked',
      error_code TEXT, checked_at TIMESTAMPTZ, PRIMARY KEY(company_id,page_id)
    );
    CREATE TABLE IF NOT EXISTS facebook_lead_forms (
      company_id UUID NOT NULL, page_id TEXT NOT NULL, form_id TEXT NOT NULL, name TEXT NOT NULL,
      sources JSONB NOT NULL DEFAULT '[]', mappings JSONB NOT NULL DEFAULT '{}',
      enabled BOOLEAN NOT NULL DEFAULT false, routed BOOLEAN NOT NULL DEFAULT false, revision INTEGER NOT NULL DEFAULT 1,
      last_success_at TIMESTAMPTZ, error_code TEXT, recovery_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      import_since TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY(company_id,form_id),
      FOREIGN KEY(company_id,page_id) REFERENCES facebook_lead_pages(company_id,page_id) ON DELETE CASCADE
    );
    ALTER TABLE facebook_lead_forms ADD COLUMN IF NOT EXISTS import_since TIMESTAMPTZ NOT NULL DEFAULT now();
    -- Existing forms remain discoverable, but no old automatic mapping is treated as configured.
    ALTER TABLE facebook_lead_forms ADD COLUMN IF NOT EXISTS destination JSONB;
    ALTER TABLE facebook_lead_forms ADD COLUMN IF NOT EXISTS mapping_ready BOOLEAN NOT NULL DEFAULT false;
    CREATE UNIQUE INDEX IF NOT EXISTS facebook_lead_forms_route_idx ON facebook_lead_forms(form_id) WHERE routed;
    CREATE INDEX IF NOT EXISTS facebook_lead_forms_page_idx ON facebook_lead_forms(company_id,page_id);
    CREATE TABLE IF NOT EXISTS facebook_lead_oauth_states (
      state_hash TEXT PRIMARY KEY, company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, session_hash TEXT NOT NULL,
      client TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS facebook_lead_oauth_company_idx ON facebook_lead_oauth_states(company_id);
    CREATE INDEX IF NOT EXISTS facebook_lead_oauth_user_idx ON facebook_lead_oauth_states(user_id);
    CREATE TABLE IF NOT EXISTS facebook_lead_jobs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(), company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      page_id TEXT NOT NULL, form_id TEXT NOT NULL, lead_id TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
      available_at TIMESTAMPTZ NOT NULL DEFAULT now(), lease UUID, lease_until TIMESTAMPTZ,
      contact_id UUID, outcome TEXT, issues JSONB NOT NULL DEFAULT '[]', error_code TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id,lead_id)
    );
    CREATE INDEX IF NOT EXISTS facebook_lead_jobs_ready_idx ON facebook_lead_jobs(available_at) WHERE status IN ('pending','retry','processing');
    CREATE INDEX IF NOT EXISTS facebook_lead_jobs_company_idx ON facebook_lead_jobs(company_id,created_at DESC);
    ALTER TABLE facebook_lead_jobs ADD COLUMN IF NOT EXISTS campaign_id TEXT;
    ALTER TABLE facebook_lead_jobs ADD COLUMN IF NOT EXISTS adset_id TEXT;
    ALTER TABLE facebook_lead_jobs ADD COLUMN IF NOT EXISTS ad_id TEXT;
    CREATE INDEX IF NOT EXISTS facebook_lead_jobs_campaign_idx ON facebook_lead_jobs(company_id,campaign_id,created_at DESC) WHERE status='succeeded' AND campaign_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS facebook_lead_jobs_adset_idx ON facebook_lead_jobs(company_id,adset_id,created_at DESC) WHERE status='succeeded' AND adset_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS facebook_lead_jobs_ad_idx ON facebook_lead_jobs(company_id,ad_id,created_at DESC) WHERE status='succeeded' AND ad_id IS NOT NULL;
    CREATE TABLE IF NOT EXISTS facebook_lead_scans (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(), company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      form_id TEXT NOT NULL, from_time TIMESTAMPTZ NOT NULL, to_time TIMESTAMPTZ NOT NULL,
      cursor TEXT, status TEXT NOT NULL DEFAULT 'pending', queued INTEGER NOT NULL DEFAULT 0,
      attempts INTEGER NOT NULL DEFAULT 0, available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      lease UUID, lease_until TIMESTAMPTZ, error_code TEXT, preview BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS facebook_lead_scans_company_idx ON facebook_lead_scans(company_id,created_at DESC);
    CREATE UNIQUE INDEX IF NOT EXISTS facebook_lead_scan_active_idx ON facebook_lead_scans(company_id,form_id,preview) WHERE status IN ('pending','processing','retry');
    CREATE TABLE IF NOT EXISTS facebook_lead_outbox (
      job_id UUID PRIMARY KEY REFERENCES facebook_lead_jobs(id) ON DELETE CASCADE,
      delivered_at TIMESTAMPTZ, push_attempted_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS facebook_lead_deletions (
      code TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT 'integration_data_deleted', created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS contacts_company_email_match_idx ON contacts(company_id,lower(trim(email))) WHERE deleted_at IS NULL;
    CREATE INDEX IF NOT EXISTS contacts_company_phone_match_idx ON contacts(company_id,(regexp_replace(phone,'[^0-9]','','g'))) WHERE deleted_at IS NULL;
  `);
}
