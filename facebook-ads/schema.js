// WOLF-059 additive/idempotent migration. Preserve tables on rollback.
export async function installAdsSchema(db) {
  await db.query(`
CREATE TABLE IF NOT EXISTS facebook_ads_connections(
 company_id uuid PRIMARY KEY REFERENCES companies(id), user_id uuid NOT NULL REFERENCES users(id),
 meta_user_id text, token text, permissions jsonb NOT NULL DEFAULT '[]', status text NOT NULL DEFAULT 'disconnected',
 error_code text, checked_at timestamptz, expires_at timestamptz, revision integer NOT NULL DEFAULT 1, updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS facebook_ads_oauth_states(
 state_hash text PRIMARY KEY,company_id uuid NOT NULL REFERENCES companies(id),user_id uuid NOT NULL REFERENCES users(id),session_hash text NOT NULL,expires_at timestamptz NOT NULL);
CREATE INDEX IF NOT EXISTS facebook_ads_oauth_expiry_idx ON facebook_ads_oauth_states(expires_at);
CREATE TABLE IF NOT EXISTS facebook_ads_accounts(
 company_id uuid NOT NULL REFERENCES companies(id),account_id text NOT NULL,name text NOT NULL,currency text NOT NULL,timezone_name text NOT NULL,
 account_status integer,selected boolean NOT NULL DEFAULT false,available boolean NOT NULL DEFAULT true,min_daily_budget text,user_tasks jsonb NOT NULL DEFAULT '[]',checked_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(company_id,account_id));
CREATE TABLE IF NOT EXISTS facebook_ads_views(
 id uuid PRIMARY KEY,company_id uuid NOT NULL REFERENCES companies(id),user_id uuid NOT NULL REFERENCES users(id),name text NOT NULL,config jsonb NOT NULL,revision integer NOT NULL DEFAULT 1,updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS facebook_ads_views_company_idx ON facebook_ads_views(company_id,user_id,updated_at);
CREATE TABLE IF NOT EXISTS facebook_ads_reports(
 id uuid PRIMARY KEY,company_id uuid NOT NULL REFERENCES companies(id),user_id uuid NOT NULL REFERENCES users(id),account_id text NOT NULL,connection_revision integer NOT NULL,
 config jsonb NOT NULL,provider_id text,status text NOT NULL DEFAULT 'starting',progress integer NOT NULL DEFAULT 0,error_code text,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS facebook_ads_reports_company_idx ON facebook_ads_reports(company_id,id);
CREATE TABLE IF NOT EXISTS facebook_ads_receipts(
 id uuid PRIMARY KEY,company_id uuid NOT NULL REFERENCES companies(id),user_id uuid NOT NULL REFERENCES users(id),source text NOT NULL,request_id text NOT NULL,input_hash text NOT NULL,
 account_id text NOT NULL,entity_id text NOT NULL,level text NOT NULL,requested jsonb NOT NULL,previous jsonb NOT NULL,target jsonb NOT NULL,result jsonb,
 status text NOT NULL,error_code text,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),UNIQUE(company_id,request_id));
CREATE INDEX IF NOT EXISTS facebook_ads_receipts_target_idx ON facebook_ads_receipts(company_id,entity_id,created_at DESC);
CREATE TABLE IF NOT EXISTS facebook_ads_trigger_state(
 company_id uuid NOT NULL REFERENCES companies(id),node_id uuid NOT NULL REFERENCES automation_nodes(id) ON DELETE CASCADE,entity_id text NOT NULL,
 matched boolean NOT NULL DEFAULT false,last_fired_at timestamptz,fire_count integer NOT NULL DEFAULT 0,last_evaluated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(company_id,node_id,entity_id));
CREATE TABLE IF NOT EXISTS facebook_ads_evaluations(
 id uuid PRIMARY KEY,company_id uuid NOT NULL REFERENCES companies(id),node_id uuid NOT NULL REFERENCES automation_nodes(id) ON DELETE CASCADE,entity_id text,
 status text NOT NULL,reason text NOT NULL,details jsonb NOT NULL DEFAULT '{}',created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS facebook_ads_evaluations_recent_idx ON facebook_ads_evaluations(company_id,node_id,created_at DESC);
`);
}
