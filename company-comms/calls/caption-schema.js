export async function installCaptionSchema(db) {
  await db.query(`
  ALTER TABLE comms_call_settings ADD COLUMN IF NOT EXISTS captions_enabled boolean NOT NULL DEFAULT false;
  ALTER TABLE comms_call_settings ADD COLUMN IF NOT EXISTS monthly_caption_minutes integer NOT NULL DEFAULT 1000 CHECK(monthly_caption_minutes BETWEEN 0 AND 1000000);
  CREATE TABLE IF NOT EXISTS comms_caption_runs(id uuid PRIMARY KEY,company_id uuid NOT NULL REFERENCES companies(id),call_id uuid NOT NULL REFERENCES comms_call_sessions(id),requested_by uuid NOT NULL REFERENCES users(id),agent_identity text NOT NULL UNIQUE,state text NOT NULL DEFAULT 'consent' CHECK(state IN('consent','starting','active','stopping','stopped','failed')),dispatch_id text,dispatch_claimed_at timestamptz,agent_joined_at timestamptz,worker_id uuid,error_code text,lease_expires_at timestamptz,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),ended_at timestamptz);
  ALTER TABLE comms_caption_runs ADD COLUMN IF NOT EXISTS dispatch_claimed_at timestamptz;
  ALTER TABLE comms_caption_runs ADD COLUMN IF NOT EXISTS agent_joined_at timestamptz;
  CREATE UNIQUE INDEX IF NOT EXISTS comms_caption_live_call ON comms_caption_runs(call_id) WHERE state IN('consent','starting','active','stopping');
  CREATE TABLE IF NOT EXISTS comms_caption_consents(run_id uuid NOT NULL REFERENCES comms_caption_runs(id),user_id uuid NOT NULL REFERENCES users(id),consented boolean NOT NULL,updated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(run_id,user_id));
  CREATE TABLE IF NOT EXISTS comms_caption_usage(run_id uuid PRIMARY KEY REFERENCES comms_caption_runs(id),company_id uuid NOT NULL REFERENCES companies(id),reserved_seconds double precision NOT NULL DEFAULT 0,created_at timestamptz NOT NULL DEFAULT now());
  CREATE INDEX IF NOT EXISTS comms_caption_usage_month ON comms_caption_usage(company_id,created_at);
  `);
}
