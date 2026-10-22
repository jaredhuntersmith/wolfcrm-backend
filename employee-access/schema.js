// Additive account state. The user row is retained permanently as the foreign-key
// identity for company work, payroll and participant-held communications.
export async function installEmployeeAccountSchema(db) {
  await db.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_at timestamptz;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_by uuid REFERENCES users(id);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_until timestamptz;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS private_data_state text NOT NULL DEFAULT 'active';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS private_purged_at timestamptz;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS account_revision bigint NOT NULL DEFAULT 1;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS operational_eligible boolean NOT NULL DEFAULT true;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS operational_review_required_at timestamptz;
    ALTER TABLE employee_permissions ADD COLUMN IF NOT EXISTS permission_windows jsonb NOT NULL DEFAULT '{}';
    CREATE INDEX IF NOT EXISTS employee_recovery_due ON users(recovery_until,id)
      WHERE private_data_state IN ('recoverable','purging');
    CREATE TABLE IF NOT EXISTS revoked_account_sessions (
      token_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id),
      reason text NOT NULL CHECK(reason IN ('account_locked','account_disabled')),
      expires_at timestamptz NOT NULL DEFAULT now()+interval '31 days'
    );
    CREATE INDEX IF NOT EXISTS revoked_account_sessions_expiry ON revoked_account_sessions(expires_at);
    CREATE TABLE IF NOT EXISTS employee_account_audit (
      id uuid PRIMARY KEY, company_id uuid NOT NULL REFERENCES companies(id),
      user_id uuid NOT NULL REFERENCES users(id), actor_user_id uuid REFERENCES users(id),
      action text NOT NULL, previous jsonb NOT NULL, current jsonb NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS employee_account_audit_history ON employee_account_audit(company_id,user_id,created_at DESC);
    CREATE TABLE IF NOT EXISTS employee_role_presets (
      id uuid PRIMARY KEY, company_id uuid NOT NULL REFERENCES companies(id), name text NOT NULL,
      base_preset text NOT NULL, overrides jsonb NOT NULL, permission_windows jsonb NOT NULL DEFAULT '{}',
      revision integer NOT NULL DEFAULT 1, created_by uuid NOT NULL REFERENCES users(id),
      updated_by uuid NOT NULL REFERENCES users(id), created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(company_id,name)
    );
    CREATE TABLE IF NOT EXISTS employee_private_purge_jobs (
      user_id uuid PRIMARY KEY REFERENCES users(id), company_id uuid NOT NULL REFERENCES companies(id),
      requested_by uuid REFERENCES users(id), requested_at timestamptz NOT NULL DEFAULT now(),
      attempts integer NOT NULL DEFAULT 0, completed_at timestamptz, last_error_code text, next_attempt_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS employee_private_purge_due ON employee_private_purge_jobs(next_attempt_at) WHERE completed_at IS NULL;
    CREATE OR REPLACE FUNCTION wolf_employee_operational(employee users) RETURNS boolean
      LANGUAGE sql STABLE AS $$ SELECT employee.deleted_at IS NULL AND employee.operational_eligible $$;
  `);
  // Older removed accounts have already lost credentials/photos under the old
  // implementation. Retain them for explicit review; never backfill an automatic
  // destructive deadline over data that predates this lifecycle.
  await db.query(`UPDATE users SET private_data_state='legacy_disabled',operational_eligible=false
    WHERE deleted_at IS NOT NULL AND private_data_state='active'`);
}
