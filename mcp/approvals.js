import {randomUUID} from 'node:crypto';
import {actions,performAction} from './actions.js';
import {permit,connection} from './access.js';
import {digest,fault,transaction} from './context.js';
// Existing CRM workflows may trigger customer-facing automations. Therefore every
// write has an immutable, short-lived Wolf UI review, even when the immediate edit
// looks internal. No MCP tool can approve its own proposal.
export async function proposeAction({pool,actor,name,input,webOrigin}){
 const d=actions[name],payload=d.schema.parse(input);permit(actor,d.scope,d.caps);
 const hash=digest(payload),id=randomUUID();
 await pool.query(`INSERT INTO mcp_approvals(id,connection_id,request_id,operation,input_hash,payload,scopes)
 VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(connection_id,request_id) DO NOTHING`,[id,actor.connectionId,payload.request_id,name,hash,JSON.stringify(payload),JSON.stringify(actor.scopes)]);
 const row=(await pool.query('SELECT id,operation,input_hash,state,result,expires_at FROM mcp_approvals WHERE connection_id=$1 AND request_id=$2',[actor.connectionId,payload.request_id])).rows[0];
 if(row.operation!==name||row.input_hash!==hash)throw fault(409,'idempotency_conflict');
 return {approval_id:row.id,state:row.state==='pending'&&new Date(row.expires_at)<new Date()?'expired':row.state,expires_at:row.expires_at,review_url:webOrigin?webOrigin+'/settings':null,result:row.result||null,message:'Review the exact proposed changes in WolfCRM Settings → AI Connections. Only your authenticated WolfCRM session can approve. Configured notifications and automations may run.'};
}
export async function decideAction({pool,app,userId,companyId,id,expectedHash,decision}){
 return transaction(pool,async db=>{
  const p=(await db.query(`SELECT p.* FROM mcp_approvals p JOIN mcp_connections c ON c.id=p.connection_id
   WHERE p.id=$1 AND c.user_id=$2 AND c.company_id=$3 FOR UPDATE OF p`,[id,userId,companyId])).rows[0];
  if(!p)throw fault(404,'approval_not_found');if(p.input_hash!==expectedHash)throw fault(409,'approval_changed');
  if(p.state==='completed')return {state:p.state,result:p.result};
  if(p.state!=='pending'||new Date(p.expires_at)<=new Date())throw fault(409,'approval_expired');
  if(decision==='reject'){await db.query("UPDATE mcp_approvals SET state='rejected',payload=NULL WHERE id=$1",[id]);return {state:'rejected',result:null};}
  const actor=await connection(pool,p.connection_id);actor.scopes=p.scopes.filter(s=>actor.scopes.includes(s));
  if(app.locals.connectionManager)await app.locals.connectionManager.check(actor,p.operation);
  const result=await performAction({pool,app,actor,name:p.operation,input:p.payload});
  await db.query("UPDATE mcp_approvals SET state='completed',payload=NULL,result=$2 WHERE id=$1",[id,JSON.stringify(result)]);
  return {state:'completed',result};
 });
}
