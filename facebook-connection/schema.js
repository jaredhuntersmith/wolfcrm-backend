// WOLF-060. Additive, after the existing Leads and Ads schemas. No data migration/copy of tokens.
export async function installFacebookConnectionSchema(db) {
  await db.query(`
    CREATE TABLE IF NOT EXISTS facebook_connections (
      company_id uuid PRIMARY KEY REFERENCES companies(id) ON DELETE CASCADE,
      user_id uuid NOT NULL REFERENCES users(id), app_id text NOT NULL, meta_user_id text,
      token text, permissions jsonb NOT NULL DEFAULT '[]', status text NOT NULL DEFAULT 'disconnected',
      expires_at timestamptz, error_code text, revision integer NOT NULL DEFAULT 1,
      checked_at timestamptz, updated_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS facebook_connections_identity_idx ON facebook_connections(app_id,meta_user_id);
    CREATE TABLE IF NOT EXISTS facebook_connection_oauth_states (
      state_hash text PRIMARY KEY, company_id uuid NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, session_hash text NOT NULL,
      client text NOT NULL, destination text NOT NULL, app_id text NOT NULL, redirect_uri text NOT NULL,
      expires_at timestamptz NOT NULL
    );
    CREATE INDEX IF NOT EXISTS facebook_connection_oauth_expiry_idx ON facebook_connection_oauth_states(expires_at);
    CREATE TABLE IF NOT EXISTS facebook_connection_deletions (
      code text PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now()
    );
  `);
}
