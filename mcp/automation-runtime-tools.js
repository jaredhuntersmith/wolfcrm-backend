import {z} from 'zod';
import {dispatch,digest,fault} from './context.js';
import {assertAutomationGraphPublication,redactAutomation} from './automation-graph-tools.js';
const uuid=z.uuid(),hash=z.string().regex(/^[a-f0-9]{64}$/);
const subject=z.object({subject_type:z.enum(['generic','contact','job','task','quote','invoice','payment','service_plan','pin','list','route','employee','shift','measurement','conversation','message']).default('generic'),subject_id:z.string().min(1).max(160).nullable().default(null),input:z.record(z.string(),z.json()).default({})}).strict();

// Check the actual immutable execution version, including existing child flows.
// A runtime permission must not become a back door to human-only role/AI controls.
export async function assertAutomationRuntimePublication({app,pool,actor,graph,seen=new Set()}){
  assertAutomationGraphPublication(graph);
  if(seen.size>20)throw fault(400,'automation_dependency_limit');
  for(const n of graph.nodes||[]){
   if(n.node_type!=='sub_automation'&&n.config?.action_key!=='automation.start'&&n.config?.utility_key!=='automation.start')continue;
   const id=n.config?.automation_id;
   if(!uuid.safeParse(id).success)throw fault(403,'automation_dynamic_dependency_requires_human','A referenced automation must be a concrete authorized workflow before AI can execute it.');
   if(seen.has(id))continue;seen.add(id);
   const child=await dispatch(app,actor,'GET','/api/automations/'+id);
   if(!child.active)throw fault(409,'automation_child_not_published');
   await assertAutomationRuntimePublication({app,pool,actor,graph:child.active,seen});
  }
 }
export function registerAutomationRuntimeTools({read,write,actor,app,pool}){
 const graphAllowed=(graph,seen)=>assertAutomationRuntimePublication({app,pool,actor,graph,seen});
 async function definition(id){
  await pool.query('SELECT id FROM automation_definitions WHERE id=$1 AND company_id=$2 FOR UPDATE',[id,actor.companyId]);
  return dispatch(app,actor,'GET','/api/automations/'+id);
 }
 async function runDetail(id){return dispatch(app,actor,'GET','/api/automation-runs/'+id);}
 async function checkedRun(i){
  await pool.query('SELECT id FROM automation_runs WHERE id=$1 AND company_id=$2 FOR UPDATE',[i.id,actor.companyId]);
  const d=await runDetail(i.id);if(digest(d)!==i.expected_run_hash)throw fault(409,'automation_run_changed');return d;
 }
 read('automation_runs','Read recent canonical execution statuses for an authorized company automation. No execution is started.',z.object({id:uuid,limit:z.number().int().min(1).max(100).default(25),offset:z.number().int().min(0).max(10000).default(0)}).strict(),'crm:read',['automations.view'],null,async i=>{await dispatch(app,actor,'GET','/api/automations/'+i.id);const rows=await dispatch(app,actor,'GET',`/api/automations/${i.id}/runs`);return {items:redactAutomation(rows.slice(i.offset,i.offset+i.limit)),next_offset:i.offset+i.limit<rows.length?i.offset+i.limit:null};});
 read('automation_run','Read a canonical automation run, nodes, waits, iterations, goals and logs. Protected credentials are redacted. run_hash identifies the exact state required for cancellation/recovery.',z.object({id:uuid}).strict(),'crm:read',['automations.view'],null,async i=>{const d=await runDetail(i.id);return {...redactAutomation(d),run_hash:digest(d)};});
 for(const mode of ['start','test'])write('automation_'+(mode==='start'?'run_start':'test'),'Start '+(mode==='start'?'the exact reviewed published automation; dry_run defaults true, set false only for an explicitly requested live execution':'a canonical draft test that always uses dry_run and cannot execute customer effects')+'. Checks the reviewed graph and referenced workflows; current permissions and exact approval apply. Test inputs are untrusted data.',z.object({id:uuid,expected_graph_hash:hash,subject,...(mode==='start'?{dry_run:z.boolean().default(true)}:{trigger_key:z.string().min(1).max(160).optional()})}).strict(),'crm:write',['automations.run'],'POST',null,null,async i=>{
  if(Buffer.byteLength(JSON.stringify(i.subject.input))>20000)throw fault(413,'automation_input_too_large');
  const d=await definition(i.id),g=mode==='start'?d.active:d.draft;
  if(!g||digest(g)!==i.expected_graph_hash)throw fault(409,'automation_graph_changed');await graphAllowed(g,new Set([i.id]));
  if(mode==='test'&&i.trigger_key&&!g.nodes.some(n=>n.node_type==='trigger'&&n.config?.trigger_key===i.trigger_key))throw fault(400,'automation_trigger_unavailable');
  return redactAutomation(await dispatch(app,actor,'POST',`/api/automations/${i.id}/${mode==='start'?'manual-run':'draft/test'}`,{...i.subject,dry_run:mode==='test'||i.dry_run,...(i.trigger_key?{trigger_key:i.trigger_key}:{})}));
 });
 write('automation_run_cancel','Cancel an exact current automation run using the existing engine. Completed effects and their receipts remain recorded; this does not undo them.',z.object({id:uuid,expected_run_hash:hash}).strict(),'crm:write',['automations.run'],'POST',null,null,async i=>{await checkedRun(i);return redactAutomation(await dispatch(app,actor,'POST',`/api/automation-runs/${i.id}/cancel`,{}));});
 for(const mode of ['run','node','iteration'])write('automation_'+mode+'_retry','Recover a failed/stopped/canceled '+mode+' through the existing durable automation recovery engine. May resume external effects; exact current run state and approval apply. The original immutable graph must still pass the AI execution safety review.',z.object({id:uuid,expected_run_hash:hash,...(mode==='node'?{node_id:uuid}:mode==='iteration'?{iteration_id:uuid}:{})}).strict(),'crm:write',['automations.run'],'POST',null,null,async i=>{
  const d=await checkedRun(i);const nodes=(await pool.query('SELECT * FROM automation_nodes WHERE version_id=$1 AND company_id=$2',[d.run.automation_version_id,actor.companyId])).rows;await graphAllowed({nodes},new Set([d.run.automation_id]));
  const suffix=mode==='run'?'retry':mode==='node'?`nodes/${i.node_id}/retry`:`iterations/${i.iteration_id}/retry`;
  return redactAutomation(await dispatch(app,actor,'POST',`/api/automation-runs/${i.id}/${suffix}`,{}));
 });
}
