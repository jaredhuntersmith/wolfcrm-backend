import {z} from 'zod';
import {readFileSync} from 'node:fs';
import {dispatch,digest,fault} from './context.js';
import {evidenceHash} from '../assistant/context.js';
import {timeScheduleSchema} from '../automation-time-schedule.js';
import {aiTaskConfig} from '../assistant/automation.js';

const review=JSON.parse(readFileSync(new URL('../assistant/automation-authoring.json',import.meta.url),'utf8'));
const uuid=z.uuid(),hash=z.string().regex(/^[a-f0-9]{64}$/),text=z.string().max(20000),json=z.json();
const protectedKey=/authorization|cookie|password|credential|secret|private[_-]?key|api[_-]?key|access[_-]?token|refresh[_-]?token|join[_-]?code/i;
const protectedValue=v=>typeof v==='string'&&/\bsk-[a-zA-Z0-9_-]{16,}|Bearer\s+[a-zA-Z0-9_.-]{16,}|-----BEGIN[^\n]*PRIVATE KEY/i.test(v);
const hidden='[Human-managed protected value]';
export function redactAutomation(value){
 if(Array.isArray(value))return value.map(redactAutomation);
 if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,protectedKey.test(k)||protectedValue(v)?hidden:redactAutomation(v)]));
 return value;
}
function restoreProtected(old,next){
 if(Array.isArray(next))return next.map((v,i)=>restoreProtected(old?.[i],v));
 if(!next||typeof next!=='object')return next;
 const result={...next};
 for(const [k,v]of Object.entries(next)){
  if(protectedKey.test(k)||protectedValue(old?.[k])||protectedValue(v)){
   if(old?.[k]===undefined||v!==hidden)throw fault(403,'human_managed_automation_field','Credential and execution-permission fields use their normal authenticated human management flow.');
   result[k]=old[k];
  }else result[k]=restoreProtected(old?.[k],v);
 }
 for(const [k,v]of Object.entries(old||{}))if((protectedKey.test(k)||protectedValue(v))&&!Object.hasOwn(result,k))result[k]=v;
 return result;
}
const expression=z.string().max(20000),number=z.union([z.number().finite(),expression]),idList=z.array(z.string().max(300)).max(200);
function fieldSchema(field){
 if(['number','money'].includes(field.type))return number;
 if(field.type==='boolean')return z.boolean();
 if(['string_list','tag_list','source_list','stage_list','user_list'].includes(field.type))return idList;
 if(field.type==='number_list')return z.array(number).max(200);
 if(field.type==='select'&&field.options?.length)return z.enum(field.options.map(String));
 if(['json','condition','line_items','switch_cases','port_list','weighted_ports','event_list','duration'].includes(field.type))return json;
 return expression;
}
function configSchema(definition,kind){
 const shape={};if(definition.key==='time.schedule')shape.schedule=timeScheduleSchema;for(const f of definition.config_fields||[])if(!shape[f.key])shape[f.key]=fieldSchema(f).optional();
 const common={on_error:z.enum(['stop','continue','error_path']),retry_count:z.number().int().min(0).max(10),retry_initial_delay_seconds:z.number().min(0),retry_max_delay_seconds:z.number().positive(),retry_backoff_multiplier:z.number().min(1),timeout_seconds:z.number().positive(),missing_resource_policy:z.enum(['fail','skip']),repeatable:z.boolean(),condition:json,conditions:z.array(json).max(100)};
 for(const [k,v]of Object.entries(common))shape[k]=v.optional();
 for(const k of ['target_mode','target_id','contact_id','job_id','task_id','quote_id','invoice_id','payment_id','service_plan_id','pin_id','list_id','route_id','employee_id','shift_id','measurement_id','conversation_id','message_id','user_id','automation_id'])if(!shape[k])shape[k]=expression.optional();
 if(kind==='action')shape.action_key=z.literal(definition.key);if(kind==='trigger')shape.trigger_key=z.literal(definition.key);
 // Existing inline webhooks are preserved, while new credentials remain human-only.
 if(definition.key==='webhook.send')Object.assign(shape,{url:z.url().max(2000).optional(),method:z.enum(['GET','POST','PUT','PATCH','DELETE']).optional(),headers:z.record(z.string(),z.string().max(4000)).optional(),body:json.optional(),response_mappings:z.array(json).max(64).optional()});
 return z.object(shape).strict();
}
const node=z.object({id:uuid,node_key:z.string().regex(/^[A-Za-z0-9_]{1,80}$/),node_type:z.enum(['trigger','action','condition','wait','branch','sub_automation','utility','note','foreach','merge','parallel','switch','random_split','event_wait_multi','goal','stop','end','fail']),title:z.string().max(200),category:z.string().max(100).optional(),position_x:z.number().finite().default(0),position_y:z.number().finite().default(0),config:z.record(z.string(),json)}).strict();
const edge=z.object({id:uuid,source_node_id:uuid,target_node_id:uuid,source_port:z.string().max(80).default('default'),target_port:z.string().max(80).default('default'),label:z.string().max(200).nullable().optional(),priority:z.number().int().optional(),config:z.record(z.string(),json).default({})}).strict();
const graphSettings=z.object({timezone:z.string().max(100).optional(),reentry_mode:z.enum(['always','after_previous_completion','once_per_subject','cooldown']).optional(),cooldown_seconds:z.number().nonnegative().optional(),max_active_runs:z.number().int().positive().optional(),max_active_runs_per_subject:z.number().int().positive().optional(),maximum_node_executions:z.number().int().positive().optional(),max_customer_messages_per_run:z.number().int().nonnegative().optional(),max_webhook_actions_per_run:z.number().int().nonnegative().optional(),stop_conditions:z.array(json).max(100).optional(),goals:z.array(json).max(100).optional()}).strict();
export const graphSchema=z.object({id:uuid,expected_graph_hash:hash,nodes:z.array(node).min(1).max(200),edges:z.array(edge).max(500),settings:graphSettings.default({})}).strict();

export function assertAutomationGraphPublication(graph){
 for(const node of graph?.nodes||[]){
  if(!['action','trigger'].includes(node.node_type))continue;
  const key=node.config?.[node.node_type+'_key'],entry=review[node.node_type==='action'?'actions':'triggers'].find(x=>x.id===key);
  if(!entry||entry.status!=='supported')throw fault(403,entry?.status==='human_only'?'human_managed_automation_action':'automation_action_not_mapped',entry?.reason||'The new action/trigger requires an explicit authoring review.');
 }
}
export function registerAutomationGraphTools({read,write,actor,app,pool}){
 const catalog=()=>dispatch(app,actor,'GET','/api/automations/catalog');
 const authorable={
  triggers:new Set(review.triggers.filter(x=>x.status==='supported').map(x=>x.id)),
  actions:new Set(review.actions.filter(x=>x.status==='supported').map(x=>x.id))
 };
 read('automation_catalog_page','Browse the current automation engine in small, searchable pages before authoring. Triggers and actions include only explicitly reviewed AI-authorable entries. Use automation_node_schema for the exact trigger/action configuration; this does not grant write or publish access.',z.object({section:z.enum(['triggers','actions','logic_nodes','condition_fields','template_variables','sources']),query:z.string().trim().max(160).default(''),category:z.string().trim().max(100).optional(),offset:z.number().int().nonnegative().default(0),limit:z.number().int().min(1).max(20).default(20)}).strict(),'crm:read',['automations.view'],null,async i=>{
  const full=await catalog(),entries=full[i.section]||[];
  const allowed=authorable[i.section];
  const matches=entries.filter(entry=>{
   const key=typeof entry==='string'?entry:entry.key;
   if(allowed&&!allowed.has(key))return false;
   if(i.category&&String(entry.category||'').toLowerCase()!==i.category.toLowerCase())return false;
   return !i.query||[key,entry.display_name,entry.category,entry.description].filter(Boolean).join(' ').toLowerCase().includes(i.query.toLowerCase());
  });
  const project=entry=>{
   if(typeof entry==='string')return i.section==='template_variables'?{key:entry,token:`{{${entry}}}`}:{key:entry};
   if(i.section==='template_variables')return {key:entry.key,token:entry.token};
   if(i.section==='condition_fields')return {key:entry.key,display_name:entry.display_name,category:entry.category,value_type:entry.value_type,operators:entry.operators};
   return {key:entry.key,display_name:entry.display_name,category:entry.category,description:entry.description,authoring_status:allowed?'supported':'canonical_logic',outputs:entry.outputs||[],supported_subject_types:entry.supported_subject_types||[],config_field_keys:(entry.config_fields||[]).map(field=>field.key)};
  };
  // The assistant rejects tool results over 48 KB. Leave headroom for the MCP
  // wrapper and let a later page start at the first item that did not fit.
  const items=[];
  for(const entry of matches.slice(i.offset,i.offset+i.limit)){
   const item=project(entry);
   if(Buffer.byteLength(JSON.stringify({section:i.section,items:[...items,item],total:matches.length,next_offset:i.offset+items.length+1}))>40000){
    if(!items.length)throw fault(413,'automation_catalog_entry_too_large','The catalog entry cannot fit in an assistant result.');
    break;
   }
   items.push(item);
  }
  return {section:i.section,items,total:matches.length,next_offset:i.offset+items.length<matches.length?i.offset+items.length:null};
 });
 read('automation_folders','List company-owned automation workspaces/folders for optional draft placement. Results are scoped to the current company.',z.object({offset:z.number().int().nonnegative().default(0),limit:z.number().int().min(1).max(100).default(25)}).strict(),'crm:read',['automations.view'],null,async i=>{
  const rows=(await pool.query('SELECT id,name,sort_order FROM automation_folders WHERE company_id=$1 ORDER BY sort_order,name,id LIMIT $2 OFFSET $3',[actor.companyId,i.limit+1,i.offset])).rows;
  const items=[];
  for(const row of rows.slice(0,i.limit)){
   if(Buffer.byteLength(JSON.stringify({items:[...items,row],next_offset:i.offset+items.length+1}))>40000){
    if(!items.length)throw fault(413,'automation_folder_entry_too_large','The folder entry cannot fit in an assistant result.');
    break;
   }
   items.push(row);
  }
  return {items,next_offset:rows.length>items.length?i.offset+items.length:null};
 });
 async function definition(kind,key){
  const reviewed=review[kind==='action'?'actions':'triggers'].find(x=>x.id===key);
  if(!reviewed||reviewed.status!=='supported')throw fault(403,reviewed?.status==='human_only'?'human_managed_automation_action':'automation_action_not_mapped',reviewed?.reason||'This action/trigger must be explicitly reviewed before assistant authoring.');
  const actual=(await catalog())[kind==='action'?'actions':'triggers'].find(x=>x.key===key);
  if(!actual)throw fault(409,'automation_catalog_changed');return actual;
 }
 async function checkedGraph(i,old){
  if(Buffer.byteLength(JSON.stringify(i))>160000)throw fault(413,'automation_graph_too_large');
  const c=await catalog();
  return {...i,nodes:await Promise.all(i.nodes.map(async n=>{
   const prior=old.nodes.find(x=>x.id===n.id),config=restoreProtected(prior?.config,n.config);
   // Unchanged legacy config is retained byte-for-byte; it is not newly exposed.
   if(prior&&evidenceHash(config)===evidenceHash(prior.config)&&prior.node_type===n.node_type)return {...n,config};
   if(['action','trigger'].includes(n.node_type)){
    const key=config[n.node_type+'_key'],d=await definition(n.node_type,key);configSchema(d,n.node_type).parse(config);
    if(key==='assistant.task'){const task=aiTaskConfig.parse(config);if(task.execution_user_id!==actor.userId)throw fault(403,'automation_sponsor_mismatch');}
   }else{
    const key=n.node_type==='utility'?(config.utility_key||config.action_key):n.node_type==='sub_automation'?'automation.start':n.node_type;
    const d=c.logic_nodes.find(x=>x.key===key);if(!d)throw fault(400,'automation_logic_unsupported');
    // Flow-control configuration has documented mode-specific keys; canonical
    // graph validation enforces topology, port weights, waits and global limits.
    const allowed=new Set([...(d.config_fields||[]).map(f=>f.key),'mode','amount','unit','until','until_datetime','date','datetime','duration','min','max','minimum','maximum','event_type','event_types','subject_type','subject_id','timeout','timeout_amount','timeout_unit','condition','conditions','operator','field','value','input','branches','cases','paths','events','collection','execution_mode','parallelism','failure_policy','max_items','merge_id','name','utility_key','action_key','automation_id','wait_for_completion','reason','title','body','metadata','goal_key']);
    if(Object.keys(config).some(k=>!allowed.has(k)))throw fault(400,'unknown_automation_logic_field');
   }
   return {...n,config};
  }))};
 }
 async function current(id){await pool.query('SELECT id FROM automation_definitions WHERE id=$1 AND company_id=$2 FOR UPDATE',[id,actor.companyId]);return dispatch(app,actor,'GET','/api/automations/'+id);}
 read('automation_node_schema','Read the exact current typed authoring schema for one reviewed action/trigger. Hidden engine-reserved actions and human-only permission/credential controls are unavailable. Use with automation_graph_save.',z.object({kind:z.enum(['action','trigger']),key:z.string().max(160)}).strict(),'crm:read',['automations.view'],null,async i=>{const d=await definition(i.kind,i.key);return {definition:d,schema:z.toJSONSchema(configSchema(d,i.kind))};});
 write('automation_ensure_draft','Open or clone the normal current draft from an existing automation through the canonical engine. Returns its protected-field-redacted graph and exact graph hash.',z.object({id:uuid}).strict(),'crm:write',['automations.manage'],'GET',null,null,async i=>{await current(i.id);const graph=await dispatch(app,actor,'GET',`/api/automations/${i.id}/draft`);return {graph:redactAutomation(graph),graph_hash:digest(graph)};});
 write('automation_graph_save','Edit existing canonical automation graphs: reviewed triggers/actions, conditions, waits, branches, loops, ports, annotations and safety settings. Uses exact current graph_hash and runtime typed catalog schemas. Does not publish or execute. Protected legacy credentials are retained from the current revision; AI/role permission changes use the normal human manager.',graphSchema,'crm:write',['automations.manage'],'PUT',null,null,async i=>{
  const detail=await current(i.id),old=detail.draft;if(!old||digest(old)!==i.expected_graph_hash)throw fault(409,'automation_draft_changed');
  const checked=await checkedGraph(i,old),{nodes,edges,settings}=checked;
  const graph=await dispatch(app,actor,'PUT',`/api/automations/${i.id}/draft/graph`,{nodes,edges,settings});return {id:i.id,graph_hash:digest(graph),node_count:graph.nodes.length,edge_count:graph.edges.length};
 });
 const changes=z.object({name:z.string().trim().min(1).max(200).optional(),description:text.optional(),folder_id:uuid.nullable().optional(),allow_manual_trigger:z.boolean().optional(),max_parallel_runs_per_subject:z.number().int().min(1).max(100).optional(),max_active_runs:z.number().int().min(1).max(100).optional(),max_active_runs_per_subject:z.number().int().min(1).max(100).optional(),concurrency_policy:z.enum(['parallel','queue','skip','cancel_previous']).optional(),subject_concurrency_policy:z.enum(['parallel','queue','skip','cancel_previous']).optional(),reentry_mode:z.enum(['always','after_previous_completion','once_per_subject','cooldown']).optional(),cooldown_seconds:z.number().int().min(0).max(31536000).optional(),cooldown_basis:z.string().max(100).optional(),failure_auto_pause_enabled:z.boolean().optional(),failure_auto_pause_threshold:z.number().int().min(1).max(1000).optional(),failure_auto_pause_window_seconds:z.number().int().min(1).max(31536000).optional()}).strict().refine(i=>Object.keys(i).length>0);
 write('automation_metadata_save','Rename, organize and configure an automation’s existing concurrency/reentry/failure policies. Requires record_hash from automation_get; does not publish or run it.',z.object({id:uuid,expected_record_hash:hash,changes}).strict(),'crm:write',['automations.manage'],'PATCH',null,null,async i=>{const d=await current(i.id);if(digest(d)!==i.expected_record_hash)throw fault(409,'automation_changed');if(i.changes.folder_id&&!(await pool.query('SELECT id FROM automation_folders WHERE id=$1 AND company_id=$2',[i.changes.folder_id,actor.companyId])).rowCount)throw fault(404,'automation_folder_unavailable');return redactAutomation(await dispatch(app,actor,'PATCH','/api/automations/'+i.id,i.changes));});
 for(const [name,method,suffix]of[['duplicate','POST','/duplicate'],['archive','DELETE','']])write('automation_'+name,`${name==='duplicate'?'Duplicate':'Archive'} the exact reviewed automation through its canonical lifecycle. Requires record_hash from automation_get.`,z.object({id:uuid,expected_record_hash:hash}).strict(),'crm:write',['automations.manage'],method,null,null,async i=>{const d=await current(i.id);if(digest(d)!==i.expected_record_hash)throw fault(409,'automation_changed');const result=await dispatch(app,actor,method,'/api/automations/'+i.id+suffix,{});return redactAutomation(result||{id:i.id,archived:true});});
}
