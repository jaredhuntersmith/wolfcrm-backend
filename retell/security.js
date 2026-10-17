import {createCipheriv,createDecipheriv,randomBytes} from 'node:crypto';
import {loadPrincipal} from '../mcp/access.js';
import {digest,fault} from '../mcp/context.js';
export const serviceScopes=Object.freeze(['availability:read','appointments:book','calls:report']);
export const keyPrefix='wolf_retell_';
function encryptionKey(env){const key=Buffer.from(env.RETELL_ENCRYPTION_KEY||'','base64');if(key.length!==32)throw fault(503,'retell_encryption_not_configured');return key;}
export function encrypt(secret,companyId,env){const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',encryptionKey(env),iv);cipher.setAAD(Buffer.from(companyId));return [iv,Buffer.concat([cipher.update(secret,'utf8'),cipher.final()]),cipher.getAuthTag()].map(b=>b.toString('base64')).join('.');}
export function decrypt(value,companyId,env){const [iv,data,tag]=value.split('.').map(s=>Buffer.from(s,'base64'));const cipher=createDecipheriv('aes-256-gcm',encryptionKey(env),iv);cipher.setAAD(Buffer.from(companyId));cipher.setAuthTag(tag);return Buffer.concat([cipher.update(data),cipher.final()]).toString('utf8');}
export async function principal(db,row,env){
 if(env.RETELL_ENABLED!=='true'||env.MCP_ENABLED!=='true')throw fault(503,'retell_disabled');
 if(!row||row.revoked_at||!row.key_hash||!row.expires_at||new Date(row.expires_at)<=new Date())throw fault(401,'retell_key_inactive');
 const actor=await loadPrincipal(db,row.user_id,row.company_id,{enforceOAuthRolePolicy:false});
 if(!actor.isCompanyOwner)throw fault(403,'retell_sponsor_inactive');
 for(const cap of ['schedule.view','schedule.create','schedule.manage_team','contacts.create','contacts.edit'])if(!actor.permissions.capabilities[cap])throw fault(403,'permission_denied');
 return {...actor,retell:row,scopes:serviceScopes};
}
export async function authenticateRetell(db,token,env){
 if(typeof token!=='string'||!/^wolf_retell_[A-Za-z0-9_-]{43}$/.test(token))throw fault(401,'invalid_service_key');
 const row=(await db.query('SELECT * FROM retell_connections WHERE key_hash=$1',[digest(token)])).rows[0];
 return principal(db,row,env);
}
export function newKey(){return keyPrefix+randomBytes(32).toString('base64url');}
