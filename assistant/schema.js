// WOLF-058 additive migration. Only run in isolated fixtures until integration.
export async function installAssistantSchema(db){await db.query(`
CREATE TABLE IF NOT EXISTS wolf_assistant_settings (
 company_id uuid NOT NULL REFERENCES companies(id), user_id uuid NOT NULL REFERENCES users(id),
 connection_id uuid NOT NULL REFERENCES mcp_connections(id), funding text NOT NULL DEFAULT 'owner',
 key_ciphertext text, model text, reasoning text, instructions text NOT NULL DEFAULT '',
 memory_enabled boolean NOT NULL DEFAULT true, monthly_limit_micros bigint NOT NULL DEFAULT 5000000 CHECK(monthly_limit_micros>=0),
 revision integer NOT NULL DEFAULT 1, PRIMARY KEY(company_id,user_id), UNIQUE(connection_id));
CREATE TABLE IF NOT EXISTS wolf_assistant_funding_allocations (
 company_id uuid NOT NULL REFERENCES companies(id), user_id uuid NOT NULL REFERENCES users(id),
 enabled boolean NOT NULL DEFAULT false, monthly_limit_micros bigint NOT NULL DEFAULT 0 CHECK(monthly_limit_micros BETWEEN 0 AND 1000000000),
 granted_by_user_id uuid NOT NULL REFERENCES users(id), revision integer NOT NULL DEFAULT 1,
 updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(company_id,user_id));
CREATE TABLE IF NOT EXISTS wolf_assistant_funding_revisions (
 company_id uuid NOT NULL REFERENCES companies(id), user_id uuid NOT NULL REFERENCES users(id), revision integer NOT NULL,
 enabled boolean NOT NULL, monthly_limit_micros bigint NOT NULL CHECK(monthly_limit_micros BETWEEN 0 AND 1000000000),
 author_id uuid NOT NULL REFERENCES users(id), created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(company_id,user_id,revision));
CREATE TABLE IF NOT EXISTS wolf_assistant_conversations (
 id uuid PRIMARY KEY, company_id uuid NOT NULL REFERENCES companies(id), user_id uuid NOT NULL REFERENCES users(id),
 title text NOT NULL DEFAULT 'New chat', memory_enabled boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), deleted_at timestamptz);
CREATE INDEX IF NOT EXISTS wolf_assistant_chats_owner ON wolf_assistant_conversations(company_id,user_id,updated_at DESC) WHERE deleted_at IS NULL;
CREATE TABLE IF NOT EXISTS wolf_assistant_runs (
 id uuid PRIMARY KEY, conversation_id uuid NOT NULL REFERENCES wolf_assistant_conversations(id),
 company_id uuid NOT NULL REFERENCES companies(id), user_id uuid NOT NULL REFERENCES users(id), connection_id uuid NOT NULL REFERENCES mcp_connections(id),
 request_key uuid NOT NULL, input_hash text NOT NULL, status text NOT NULL DEFAULT 'queued',
 model text NOT NULL, reasoning text, funding text NOT NULL, instructions text NOT NULL,
 context jsonb NOT NULL DEFAULT '{}', history jsonb NOT NULL DEFAULT '[]', loaded_tools jsonb NOT NULL DEFAULT '[]',
 allowed_tools jsonb, max_steps integer NOT NULL DEFAULT 24 CHECK(max_steps BETWEEN 1 AND 100),
 max_cost_micros bigint NOT NULL DEFAULT 1000000 CHECK(max_cost_micros BETWEEN 1 AND 100000000),
 steps integer NOT NULL DEFAULT 0, cost_micros bigint NOT NULL DEFAULT 0, reserved_micros bigint NOT NULL DEFAULT 0,
 usage jsonb NOT NULL DEFAULT '{}', output text NOT NULL DEFAULT '', error_code text,
 cancel_requested boolean NOT NULL DEFAULT false, lease_id uuid, lease_until timestamptz,
 automation_run_id uuid, correlation_key text, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(company_id,user_id,request_key), UNIQUE(company_id,correlation_key));
ALTER TABLE wolf_assistant_runs ADD COLUMN IF NOT EXISTS authorization_revision integer;
ALTER TABLE wolf_assistant_runs ADD COLUMN IF NOT EXISTS final_ready boolean NOT NULL DEFAULT false;
ALTER TABLE wolf_assistant_runs ADD COLUMN IF NOT EXISTS destination jsonb NOT NULL DEFAULT '{"type":"assistant_result"}';
CREATE INDEX IF NOT EXISTS wolf_assistant_runs_due ON wolf_assistant_runs(status,lease_until,created_at) WHERE status IN ('queued','running','waiting_approval','waiting_client');
CREATE INDEX IF NOT EXISTS wolf_assistant_runs_owner ON wolf_assistant_runs(company_id,user_id,created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS wolf_assistant_conversation_active ON wolf_assistant_runs(conversation_id) WHERE status IN ('queued','running','waiting_approval','waiting_client');
CREATE TABLE IF NOT EXISTS wolf_assistant_messages (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, conversation_id uuid NOT NULL REFERENCES wolf_assistant_conversations(id),
 run_id uuid REFERENCES wolf_assistant_runs(id), role text NOT NULL CHECK(role IN ('user','assistant')),
 body text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS wolf_assistant_messages_chat ON wolf_assistant_messages(conversation_id,id);
CREATE TABLE IF NOT EXISTS wolf_assistant_steps (
 run_id uuid NOT NULL REFERENCES wolf_assistant_runs(id), call_id text NOT NULL, request_id uuid NOT NULL,
 tool text NOT NULL, arguments jsonb NOT NULL, state text NOT NULL DEFAULT 'pending', result jsonb, approval_id uuid,
 started_at timestamptz, completed_at timestamptz, PRIMARY KEY(run_id,call_id));
CREATE TABLE IF NOT EXISTS wolf_assistant_events (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, run_id uuid NOT NULL REFERENCES wolf_assistant_runs(id),
 kind text NOT NULL, data jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS wolf_assistant_events_run ON wolf_assistant_events(run_id,id);
CREATE TABLE IF NOT EXISTS wolf_assistant_memories (
 id uuid PRIMARY KEY, company_id uuid NOT NULL REFERENCES companies(id), user_id uuid NOT NULL REFERENCES users(id),
 kind text NOT NULL CHECK(kind IN ('preference','inferred')), body text NOT NULL, provenance text NOT NULL,
 enabled boolean NOT NULL DEFAULT true, revision integer NOT NULL DEFAULT 1,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS wolf_assistant_memories_owner ON wolf_assistant_memories(company_id,user_id);
CREATE TABLE IF NOT EXISTS wolf_assistant_guidance (
 company_id uuid NOT NULL REFERENCES companies(id), revision integer NOT NULL, body text NOT NULL,
 author_id uuid NOT NULL REFERENCES users(id), created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(company_id,revision));
CREATE TABLE IF NOT EXISTS wolf_assistant_commands (
 id uuid PRIMARY KEY, run_id uuid NOT NULL REFERENCES wolf_assistant_runs(id), call_id text NOT NULL,
 device_id uuid NOT NULL, scene_id uuid NOT NULL, command jsonb NOT NULL, state text NOT NULL DEFAULT 'pending', result jsonb,
 expires_at timestamptz NOT NULL DEFAULT now()+interval '5 minutes', UNIQUE(run_id,call_id));
`);}
