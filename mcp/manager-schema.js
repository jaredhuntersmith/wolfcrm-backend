export async function installManagerSchema(db){await db.query(`
ALTER TABLE mcp_connections ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'oauth';
ALTER TABLE mcp_connections ADD COLUMN IF NOT EXISTS name text;
ALTER TABLE mcp_connections ADD COLUMN IF NOT EXISTS description text NOT NULL DEFAULT '';
ALTER TABLE mcp_connections ADD COLUMN IF NOT EXISTS provider text;
ALTER TABLE mcp_connections ADD COLUMN IF NOT EXISTS enabled boolean NOT NULL DEFAULT true;
ALTER TABLE mcp_connections ADD COLUMN IF NOT EXISTS paused_until timestamptz;
ALTER TABLE mcp_connections ADD COLUMN IF NOT EXISTS archived_at timestamptz;
ALTER TABLE mcp_connections ADD COLUMN IF NOT EXISTS operating_hours jsonb;
ALTER TABLE mcp_connections ADD COLUMN IF NOT EXISTS tool_policy jsonb;
ALTER TABLE mcp_connections ADD COLUMN IF NOT EXISTS revision integer NOT NULL DEFAULT 1;
ALTER TABLE mcp_company_policy ADD COLUMN IF NOT EXISTS operating_hours jsonb;
ALTER TABLE mcp_approvals ADD COLUMN IF NOT EXISTS policy_revision integer;
ALTER TABLE mcp_approvals ADD COLUMN IF NOT EXISTS tool_invocation boolean NOT NULL DEFAULT false;
ALTER TABLE retell_connections ADD COLUMN IF NOT EXISTS managed boolean NOT NULL DEFAULT false;
DROP INDEX IF EXISTS retell_connections_company_provider;
CREATE UNIQUE INDEX IF NOT EXISTS retell_connections_legacy_provider ON retell_connections(company_id,provider) WHERE NOT managed;
INSERT INTO mcp_clients(id,name,redirect_uris) VALUES('wolf-service','Service connection','[]') ON CONFLICT DO NOTHING;
INSERT INTO mcp_connections(id,user_id,company_id,client_id,scopes,audience,created_at,expires_at,revoked_at,last_used_at,kind,name,provider)
 SELECT id,user_id,company_id,'wolf-service','[]','service',created_at,COALESCE(expires_at,now()),revoked_at,last_used_at,'service',CASE WHEN provider='elevenlabs' THEN 'Jack' ELSE 'Riley' END,provider FROM retell_connections
 ON CONFLICT(id) DO NOTHING;
UPDATE mcp_connections g SET name=c.name FROM mcp_clients c WHERE c.id=g.client_id AND g.name IS NULL;
`);}
export async function lockConnectionSlot(db,companyId){
 await db.query('SELECT id FROM companies WHERE id=$1 FOR UPDATE',[companyId]);
 const {rows}=await db.query('SELECT count(*)::int AS count FROM mcp_connections WHERE company_id=$1 AND revoked_at IS NULL AND archived_at IS NULL',[companyId]);
 if(rows[0].count>=10){const e=new Error('This company already has 10 connections. Revoke or archive one first.');e.status=409;e.code='connection_limit';throw e;}
}
