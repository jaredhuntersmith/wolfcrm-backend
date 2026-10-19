// WOLF-057 additive migration. Run after automation and MCP schema installers.
export async function installWebhookSchema(db) {
  await db.query(`
 CREATE TABLE IF NOT EXISTS wolf_webhook_connections (
  id uuid PRIMARY KEY, company_id uuid NOT NULL REFERENCES companies(id), user_id uuid NOT NULL REFERENCES users(id),
  endpoint_key text NOT NULL UNIQUE, config jsonb NOT NULL, secrets_ciphertext text NOT NULL,
  revision integer NOT NULL DEFAULT 1, policy_revision integer NOT NULL DEFAULT 1, validated_revision integer, revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
 );
 CREATE INDEX IF NOT EXISTS wolf_webhook_company ON wolf_webhook_connections(company_id,created_at DESC);
 CREATE TABLE IF NOT EXISTS wolf_webhook_receipts (
  id uuid PRIMARY KEY, connection_id uuid NOT NULL REFERENCES wolf_webhook_connections(id), company_id uuid NOT NULL REFERENCES companies(id),
  event_id uuid UNIQUE REFERENCES automation_events(id), sender_id text, input_hash text NOT NULL,
  revision integer NOT NULL, automation_id uuid REFERENCES automation_definitions(id), version_id uuid REFERENCES automation_versions(id),
  state text NOT NULL, approved_by uuid REFERENCES users(id), error_code text,
  created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
  UNIQUE(connection_id,sender_id)
 );
 CREATE INDEX IF NOT EXISTS wolf_webhook_receipt_connection ON wolf_webhook_receipts(connection_id,created_at DESC);
 CREATE INDEX IF NOT EXISTS wolf_webhook_receipt_expiry ON wolf_webhook_receipts(expires_at);
 CREATE INDEX IF NOT EXISTS wolf_webhook_receipt_pending ON wolf_webhook_receipts(connection_id) WHERE state NOT IN ('completed','expired','rejected');
 CREATE TABLE IF NOT EXISTS wolf_webhook_nonces (
  connection_id uuid NOT NULL REFERENCES wolf_webhook_connections(id), nonce text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(connection_id,nonce)
 );
 CREATE TABLE IF NOT EXISTS wolf_webhook_run_identity (
  event_id uuid NOT NULL REFERENCES automation_events(id), automation_id uuid NOT NULL REFERENCES automation_definitions(id),
  run_id uuid NOT NULL REFERENCES automation_runs(id), PRIMARY KEY(event_id,automation_id)
 );
 CREATE TABLE IF NOT EXISTS wolf_webhook_deliveries (
  id uuid PRIMARY KEY, company_id uuid NOT NULL REFERENCES companies(id), connection_id uuid NOT NULL REFERENCES wolf_webhook_connections(id),
  identity text NOT NULL, revision integer NOT NULL, context_ciphertext text, state text NOT NULL DEFAULT 'queued',
  attempts integer NOT NULL DEFAULT 0, attempt_limit integer NOT NULL DEFAULT 3, next_attempt_at timestamptz NOT NULL DEFAULT now(), lease_until timestamptz,
  http_status integer, error_code text, response_mapped jsonb, uncertain boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz, UNIQUE(connection_id,identity)
 );
 CREATE INDEX IF NOT EXISTS wolf_webhook_delivery_ready ON wolf_webhook_deliveries(next_attempt_at) WHERE state IN ('queued','processing');
 CREATE INDEX IF NOT EXISTS wolf_webhook_delivery_connection ON wolf_webhook_deliveries(connection_id,created_at DESC);
 CREATE TABLE IF NOT EXISTS wolf_webhook_attempts (
  id bigserial PRIMARY KEY, delivery_id uuid NOT NULL REFERENCES wolf_webhook_deliveries(id) ON DELETE CASCADE,
  attempt integer NOT NULL, http_status integer, error_code text, uncertain boolean NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
 );
 CREATE INDEX IF NOT EXISTS wolf_webhook_attempt_delivery ON wolf_webhook_attempts(delivery_id,id DESC);
 CREATE TABLE IF NOT EXISTS wolf_webhook_effects (
  run_id uuid NOT NULL REFERENCES automation_runs(id), node_id uuid NOT NULL, scope_key text NOT NULL,
  result jsonb NOT NULL, PRIMARY KEY(run_id,node_id,scope_key)
 );
 CREATE TABLE IF NOT EXISTS wolf_webhook_audit (
  id bigserial PRIMARY KEY, company_id uuid NOT NULL, connection_id uuid NOT NULL, user_id uuid,
  operation text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
 );
 CREATE INDEX IF NOT EXISTS wolf_webhook_audit_company ON wolf_webhook_audit(company_id,created_at DESC);
`);
}
