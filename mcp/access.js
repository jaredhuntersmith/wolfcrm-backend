import {resolveAccess,legacyColumnsForCapabilities} from '../permissions.js';
import {digest,fault} from './context.js';
export const scopes=Object.freeze({
 'ads:read':'Read selected Facebook advertising accounts, campaigns and reporting',
 'ads:write':'Change authorized Facebook advertising delivery and budgets',
 'crm:read':'Read contacts, pipeline, schedules, tasks, quotes and payment status',
 'crm:write':'Create and edit contacts, tasks, appointments, pipeline stages and draft quotes; normal company automations may run',
 'notes:read':'Read notes that your account can access, including your private notes',
 'notes:write':'Create private or company notes within your existing permissions',
 'files:read':'Read permitted file metadata and supported file content, including your private files',
 'comms:read':'Read conversations and notifications your account can access',
 'team:read':'Read permitted team directory and availability',
 'finance:write':'Edit explicitly selected permitted financial spaces, accounting, receipts and planning through canonical validation; external payments are separate.',
 'finance:read':'Read your explicitly selected permitted financial space, including private spaces, reports and expenses'
});
export const roles=['owner','admin','manager','sales','technician','office','legacy_employee'];
export async function loadPrincipal(pool,userId,companyId,{enforceOAuthRolePolicy=true}={}){
 const row=(await pool.query(`SELECT u.id,u.email,u.display_name,u.role,u.company_id,c.name AS company_name,c.owner_user_id,c.timezone,
 to_jsonb(p) AS legacy,${enforceOAuthRolePolicy ? `COALESCE(policy.roles,'["owner"]'::jsonb)` : `'[]'::jsonb`} AS allowed_roles
 FROM users u JOIN companies c ON c.id=u.company_id
 LEFT JOIN employee_permissions p ON p.user_id=u.id AND p.company_id=u.company_id
 ${enforceOAuthRolePolicy ? 'LEFT JOIN mcp_company_policy policy ON policy.company_id=u.company_id' : ''}
 WHERE u.id=$1 AND u.deleted_at IS NULL AND ($2::uuid IS NULL OR u.company_id=$2)`,[userId,companyId||null])).rows[0];
 if(!row)throw fault(401,'membership_inactive');
 const owner=row.owner_user_id===row.id;
 const access=resolveAccess({role:owner?'employer':'employee',isOwner:owner,preset:row.legacy?.permission_preset,overrides:row.legacy?.permission_overrides,legacy:row.legacy||{}});
 const role=owner?'owner':access.preset;
 if(enforceOAuthRolePolicy&&!row.allowed_roles.includes(role))throw fault(403,'connection_role_disabled','Your company owner has not enabled AI connections for this role.');
 return {userId:row.id,companyId:row.company_id,userEmail:row.email,displayName:row.display_name,companyName:row.company_name,
 timezone:row.timezone,role:owner?'employer':'employee',isCompanyOwner:owner,ownerUserId:row.owner_user_id,
 permissions:{...Object.fromEntries(Object.entries(legacyColumnsForCapabilities(access.capabilities)).map(([k,v])=>[k.replace(/_([a-z])/g,(_,x)=>x.toUpperCase()),v])),preset:access.preset,capabilities:access.capabilities},notesReady:true};
}
export async function connection(pool,id){
 const row=(await pool.query('SELECT * FROM mcp_connections WHERE id=$1 AND revoked_at IS NULL AND expires_at>now()',[id])).rows[0];
 if(!row)throw fault(401,'connection_revoked');
 const actor=await loadPrincipal(pool,row.user_id,row.company_id,{enforceOAuthRolePolicy:row.kind==='oauth'});return {...actor,connectionId:row.id,scopes:row.scopes,audience:row.audience};
}
export async function authenticate(pool,token,audience){
 if(typeof token!=='string'||token.length<32||token.length>256)throw fault(401,'invalid_token');
 const row=(await pool.query('SELECT connection_id,scopes FROM mcp_tokens WHERE access_hash=$1 AND access_expires_at>now() AND used_at IS NULL',[digest(token)])).rows[0];
 if(!row)throw fault(401,'invalid_token');
 const actor=await connection(pool,row.connection_id);if(actor.audience!==audience)throw fault(401,'invalid_audience');
 return {...actor,scopes:row.scopes};
}
export function permit(actor,scope,capabilities=[]){
 if(!actor.scopes.includes(scope))throw Object.assign(fault(403,'insufficient_scope',`Required OAuth scope: ${scope}`),{requiredScope:scope});
 if(capabilities.some(c=>!actor.permissions.capabilities[c]))throw fault(403,'permission_denied');
}
export async function rateLimit(pool,key,limit=120){
 const row=(await pool.query(`INSERT INTO mcp_rate_limits(bucket,window_start,count) VALUES($1,date_trunc('minute',now()),1)
 ON CONFLICT(bucket) DO UPDATE SET window_start=date_trunc('minute',now()),count=CASE WHEN mcp_rate_limits.window_start=date_trunc('minute',now()) THEN mcp_rate_limits.count+1 ELSE 1 END RETURNING count`,[digest(key)])).rows[0];
 if(row.count>limit)throw fault(429,'rate_limited','Too many requests. Retry in one minute.');
}
