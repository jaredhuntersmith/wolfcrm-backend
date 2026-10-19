import {z} from 'zod';
import {randomUUID} from 'node:crypto';
import {loadPrincipal} from '../mcp/access.js';
import {fault,transaction} from '../mcp/context.js';
import {modelFor} from './models.js';

export const aiTaskConfig=z.object({
 action_key:z.literal('assistant.task'),execution_user_id:z.uuid(),instructions:z.string().trim().min(1).max(12000),
 allowed_tools:z.array(z.string().regex(/^[a-z][a-z0-9_]*$/)).max(200),model:z.string(),reasoning:z.string().nullable(),
 max_steps:z.number().int().min(1).max(100).default(24),max_cost_micros:z.number().int().min(1).max(100000000).default(1000000),
 output_destination:z.enum(['assistant_result','private_note','company_note']).default('assistant_result'),output_title:z.string().trim().min(1).max(150).default('AI task result'),
 failure_behavior:z.enum(['stop','error_path']).default('stop')
}).strict().superRefine((v,ctx)=>{try{modelFor(v.model,v.reasoning);}catch{ctx.addIssue({code:'custom',message:'Choose a supported model and reasoning setting.'});}if(v.output_destination!=='assistant_result'&&!v.allowed_tools.includes('note_create'))ctx.addIssue({code:'custom',message:'Saving a Note requires note_create in allowed_tools.'});});

// Called by the existing automation engine, never exposed as arbitrary HTTP.
// A published version's author is the sponsor; config cannot impersonate a user.
export function automationBridge({app,pool,enqueue}){
 return async function startAutomation(run,node,raw,scopeKey='root'){
  const config=aiTaskConfig.parse(raw);
  const version=(await pool.query('SELECT created_by_user_id FROM automation_versions WHERE id=$1 AND company_id=$2',[run.automation_version_id,run.company_id])).rows[0];
  if(!version||version.created_by_user_id!==config.execution_user_id)throw fault(403,'automation_sponsor_mismatch');
  const a=await loadPrincipal(pool,config.execution_user_id,run.company_id,{enforceOAuthRolePolicy:false});
  if(!a.permissions.capabilities['ai.use']||!a.permissions.capabilities['automations.manage'])throw fault(403,'automation_sponsor_revoked');
  const catalog=app.locals.capabilityService.catalog;
  if(config.allowed_tools.some(id=>!catalog.some(c=>c.id===id)||id.startsWith('native_')||id==='assistant_execute'||id.startsWith('automation_')))throw fault(400,'automation_capability_unavailable');
  const correlation=`automation:${run.id}:${node.id}:${scopeKey}`;
  return transaction(pool,async db=>{
   await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[correlation]);
   const prior=(await db.query('SELECT * FROM wolf_assistant_runs WHERE company_id=$1 AND correlation_key=$2',[run.company_id,correlation])).rows[0];if(prior)return prior;
   const conversation=randomUUID();
   await db.query('INSERT INTO wolf_assistant_conversations(id,company_id,user_id,title,memory_enabled) VALUES($1,$2,$3,$4,false)',[conversation,a.companyId,a.userId,config.output_title]);
   const result=await enqueue(a,{conversation_id:conversation,request_key:randomUUID(),text:config.instructions+'\nScheduled task. Retrieve fresh authorized data. The system saves your final response to the configured destination; do not duplicate that delivery.',allowed_tools:config.allowed_tools,model:config.model,reasoning:config.reasoning,max_steps:config.max_steps,max_cost_micros:config.max_cost_micros},{correlationKey:correlation,automationRunId:run.id});
   await db.query('UPDATE wolf_assistant_runs SET destination=$2 WHERE id=$1',[result.id,JSON.stringify({type:config.output_destination,title:config.output_title})]);
   return result;
  });
 };
}
