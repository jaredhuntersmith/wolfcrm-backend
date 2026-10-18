export async function installElevenLabsSchema(db){await db.query(`
 CREATE TABLE IF NOT EXISTS elevenlabs_reporting (
  connection_id uuid PRIMARY KEY REFERENCES mcp_connections(id) ON DELETE CASCADE,
  company_id uuid NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  agent_id text NOT NULL UNIQUE, secret_ciphertext text NOT NULL,
  enabled boolean NOT NULL DEFAULT false, updated_at timestamptz NOT NULL DEFAULT now()
 );
 CREATE TABLE IF NOT EXISTS elevenlabs_call_events (
  id uuid PRIMARY KEY, connection_id uuid NOT NULL REFERENCES elevenlabs_reporting(connection_id) ON DELETE CASCADE,
  conversation_id text NOT NULL, event_type text NOT NULL, input_hash text NOT NULL,
  payload jsonb NOT NULL, report jsonb, contact_id uuid, phone_call_id uuid,
  state text NOT NULL DEFAULT 'queued', attempts integer NOT NULL DEFAULT 0,
  error_code text, next_attempt_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz,
  UNIQUE(conversation_id,event_type)
 );
 CREATE INDEX IF NOT EXISTS elevenlabs_inbox_ready ON elevenlabs_call_events(next_attempt_at,created_at) WHERE state='queued';
 CREATE INDEX IF NOT EXISTS elevenlabs_inbox_connection ON elevenlabs_call_events(connection_id,created_at DESC);
`);}
