// Additive tables; CRM records remain in the existing contacts/calendar/call tables.
export async function installRetellSchema(db) {
 await db.query(`CREATE TABLE IF NOT EXISTS retell_connections (
 id UUID PRIMARY KEY, company_id UUID NOT NULL REFERENCES companies(id), user_id UUID NOT NULL REFERENCES users(id),
 agent_id TEXT UNIQUE, key_hash TEXT UNIQUE, key_prefix TEXT, expires_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ,
 webhook_secret TEXT, config JSONB NOT NULL DEFAULT '{}', revision INTEGER NOT NULL DEFAULT 0,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), last_used_at TIMESTAMPTZ);
 ALTER TABLE retell_connections ADD COLUMN IF NOT EXISTS provider TEXT NOT NULL DEFAULT 'retell';
 ALTER TABLE retell_connections DROP CONSTRAINT IF EXISTS retell_connections_company_id_key;
 CREATE UNIQUE INDEX IF NOT EXISTS retell_connections_company_provider ON retell_connections(company_id,provider);
 CREATE TABLE IF NOT EXISTS retell_slots (
 id UUID PRIMARY KEY, connection_id UUID NOT NULL REFERENCES retell_connections(id), revision INTEGER NOT NULL,
 payload JSONB NOT NULL, expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
 CREATE INDEX IF NOT EXISTS retell_slots_expiry ON retell_slots(expires_at);
 CREATE TABLE IF NOT EXISTS retell_requests (
 id UUID PRIMARY KEY, connection_id UUID NOT NULL REFERENCES retell_connections(id), request_key TEXT NOT NULL,
 input_hash TEXT NOT NULL, payload JSONB NOT NULL, result JSONB NOT NULL, reviewed_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(connection_id,request_key));
 CREATE INDEX IF NOT EXISTS retell_pending ON retell_requests(connection_id,created_at) WHERE reviewed_at IS NULL;
 CREATE TABLE IF NOT EXISTS retell_call_events (
 id UUID PRIMARY KEY, connection_id UUID NOT NULL REFERENCES retell_connections(id), call_id TEXT NOT NULL,
 payload JSONB NOT NULL, state TEXT NOT NULL DEFAULT 'queued', attempts INTEGER NOT NULL DEFAULT 0,
 next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(), error_code TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 completed_at TIMESTAMPTZ, UNIQUE(connection_id,call_id));
 CREATE INDEX IF NOT EXISTS retell_events_due ON retell_call_events(next_attempt_at) WHERE state='queued';
 CREATE TABLE IF NOT EXISTS retell_audit (
 id BIGSERIAL PRIMARY KEY, connection_id UUID NOT NULL REFERENCES retell_connections(id), user_id UUID NOT NULL,
 operation TEXT NOT NULL, outcome TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
 CREATE INDEX IF NOT EXISTS retell_audit_connection ON retell_audit(connection_id,created_at DESC);
 ALTER TABLE phone_calls ADD COLUMN IF NOT EXISTS provider TEXT;
 ALTER TABLE phone_calls ADD COLUMN IF NOT EXISTS provider_call_id TEXT;
 CREATE UNIQUE INDEX IF NOT EXISTS phone_calls_provider_id ON phone_calls(company_id,provider,provider_call_id) WHERE provider_call_id IS NOT NULL;`);
}
