import {installTaskTenancy} from './task-tenancy.js';
export async function installMCPSchema(db){await installTaskTenancy(db);await db.query(`
CREATE TABLE IF NOT EXISTS mcp_company_policy (
 company_id uuid PRIMARY KEY REFERENCES companies(id), roles jsonb NOT NULL DEFAULT '["owner"]',
 revision integer NOT NULL DEFAULT 1, updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS mcp_clients (
 id text PRIMARY KEY, name text NOT NULL, redirect_uris jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS mcp_connections (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id), company_id uuid NOT NULL REFERENCES companies(id),
 client_id text NOT NULL REFERENCES mcp_clients(id), scopes jsonb NOT NULL, audience text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL DEFAULT now()+interval '30 days',
 revoked_at timestamptz, last_used_at timestamptz);
CREATE INDEX IF NOT EXISTS mcp_connections_owner_idx ON mcp_connections(company_id,user_id,created_at DESC);
CREATE TABLE IF NOT EXISTS mcp_browser_requests (
 id uuid PRIMARY KEY, cookie_hash text NOT NULL, csrf_hash text NOT NULL, params jsonb NOT NULL,
 user_id uuid REFERENCES users(id), expires_at timestamptz NOT NULL DEFAULT now()+interval '10 minutes');
CREATE INDEX IF NOT EXISTS mcp_browser_expiry_idx ON mcp_browser_requests(expires_at);
CREATE TABLE IF NOT EXISTS mcp_codes (
 hash text PRIMARY KEY, connection_id uuid NOT NULL REFERENCES mcp_connections(id),
 redirect_uri text NOT NULL, challenge text NOT NULL, expires_at timestamptz NOT NULL, used_at timestamptz);
CREATE TABLE IF NOT EXISTS mcp_tokens (
 access_hash text PRIMARY KEY, refresh_hash text UNIQUE NOT NULL, connection_id uuid NOT NULL REFERENCES mcp_connections(id),
 scopes jsonb NOT NULL, access_expires_at timestamptz NOT NULL, refresh_expires_at timestamptz NOT NULL, used_at timestamptz);
CREATE INDEX IF NOT EXISTS mcp_tokens_connection_idx ON mcp_tokens(connection_id);
CREATE TABLE IF NOT EXISTS mcp_operations (
 connection_id uuid NOT NULL REFERENCES mcp_connections(id), request_id uuid NOT NULL, operation text NOT NULL,
 input_hash text NOT NULL, result jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(connection_id,request_id));
CREATE TABLE IF NOT EXISTS mcp_approvals (
 id uuid PRIMARY KEY, connection_id uuid NOT NULL REFERENCES mcp_connections(id), request_id uuid NOT NULL,
 operation text NOT NULL, input_hash text NOT NULL, payload jsonb, scopes jsonb NOT NULL,
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','completed','rejected')),
 result jsonb, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL DEFAULT now()+interval '15 minutes',
 UNIQUE(connection_id,request_id));
CREATE INDEX IF NOT EXISTS mcp_approvals_expiry_idx ON mcp_approvals(expires_at) WHERE state='pending';
CREATE TABLE IF NOT EXISTS mcp_audit (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, connection_id uuid REFERENCES mcp_connections(id),
 company_id uuid NOT NULL REFERENCES companies(id), user_id uuid NOT NULL REFERENCES users(id),
 operation text NOT NULL, record_id text, changed_fields jsonb NOT NULL DEFAULT '[]', outcome text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS mcp_audit_owner_idx ON mcp_audit(company_id,user_id,created_at DESC);
CREATE TABLE IF NOT EXISTS mcp_rate_limits (
 bucket text PRIMARY KEY, window_start timestamptz NOT NULL, count integer NOT NULL);
`);}
