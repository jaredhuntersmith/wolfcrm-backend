import {loadPrincipal} from './access.js';
import {canManage} from './manager.js';
import {transaction,fault} from './context.js';
import {z} from 'zod';
export async function controlConnectionFromAutomation(pool,{companyId,userId,connectionId,action,pauseUntil}){
 z.uuid().parse(connectionId);if(!['enable','disable','pause'].includes(action))throw fault(400,'invalid_connection_action');
 if(action==='pause')z.iso.datetime({offset:true}).parse(pauseUntil);
 return transaction(pool,async db=>{
  await db.query('SELECT id FROM companies WHERE id=$1 FOR UPDATE',[companyId]);
  const actor=await loadPrincipal(pool,userId,companyId,{enforceOAuthRolePolicy:false});if(!canManage(actor)||!actor.permissions.capabilities['automations.manage'])throw fault(403,'connection_automation_forbidden');
  const row=(await db.query('SELECT * FROM mcp_connections WHERE id=$1 AND company_id=$2 FOR UPDATE',[connectionId,companyId])).rows[0];
  if(!row||row.revoked_at||row.archived_at)throw fault(404,'connection_inactive');
  if(action==='pause'&&Date.parse(pauseUntil)<=Date.now())throw fault(400,'pause_must_be_future');
  await db.query('UPDATE mcp_connections SET enabled=$2,paused_until=$3,revision=revision+1 WHERE id=$1',[connectionId,action==='disable'?false:action==='enable'?true:row.enabled,action==='pause'?pauseUntil:null]);
  await db.query("UPDATE mcp_approvals SET state='rejected',payload=NULL WHERE connection_id=$1 AND state='pending'",[connectionId]);
  await db.query("INSERT INTO mcp_audit(connection_id,company_id,user_id,operation,outcome) VALUES($1,$2,$3,$4,'success')",[connectionId,companyId,userId,'automation.connection_'+action]);
  return {connection_id:connectionId,name:row.name,action};
 });
}
