import {nativeMapEditSchema,nativeLightingEditSchema,nativeBrowserEditSchema} from './native-geometry.js';
import {randomUUID} from 'node:crypto';
import {z} from 'zod';
import {getRecord,searchRecords} from '../mcp/registry.js';
import {restrictFields} from '../mcp/field-policy.js';
import {loadPrincipal,scopes,rateLimit} from '../mcp/access.js';
import {canManage} from '../mcp/manager.js';
import {lockConnectionSlot} from '../mcp/manager-schema.js';
import {fault,transaction,digest,internalActor,dispatch} from '../mcp/context.js';
import {installAssistantSchema} from './schema.js';
import {createProvider,encryptKey,modelFor,modelCatalog} from './models.js';
import {automationBridge} from './automation.js';
import {createEngine} from './engine.js';
import {createMemoryService} from './memory.js';
import {createFundingService} from './funding.js';

const uuid=z.uuid(),text=z.string().trim().min(1).max(30000);
const page=z.coerce.number().int().min(0).default(0);
const modules=['dashboard','schedule','contacts','stages','comms','map','messages','browser','notes','ideas','media','focus','todo','automations','routes','lighting','equipment','finance','settings','more','quotes'];
export const taskDraftChangesSchema=z.object({has_date:z.boolean().optional(),due_date:z.union([z.iso.date(),z.iso.datetime({offset:true})]).optional(),has_time:z.boolean().optional(),reminders:z.array(z.object({hour:z.number().int().min(0).max(23),minute:z.number().int().min(0).max(59)}).strict()).max(30).optional(),reminders_enabled:z.boolean().optional(),reminder_follows_task_time:z.boolean().optional(),if_not_completed_enabled:z.boolean().optional(),if_not_completed_minutes:z.union([z.literal(15),z.literal(30),z.literal(60),z.literal(120)]).optional(),alarm_enabled:z.boolean().optional(),alarm_sound:z.literal('default').optional(),alarm_snooze_minutes:z.union([z.literal(0),z.literal(5),z.literal(10),z.literal(15),z.literal(30)]).optional(),assignee_id:z.union([uuid,z.literal('unassigned')]).optional(),linked_contact_id:z.union([uuid,z.literal('none')]).optional(),linked_job_id:z.union([uuid,z.literal('none')]).optional(),linked_equipment_id:z.union([uuid,z.literal('none')]).optional(),linked_equipment_request_id:z.union([uuid,z.literal('none')]).optional(),linked_inventory_count_id:z.union([uuid,z.literal('none')]).optional(),subtasks:z.array(z.object({id:uuid.optional(),title:z.string().trim().min(1).max(200),completed:z.boolean()}).strict()).max(200).optional(),completion_note:z.string().max(12000).optional(),completion_note_required:z.boolean().optional(),completed:z.boolean().optional(),status:z.enum(['open','in_progress','cancelled','completed']).optional(),color_hex:z.string().regex(/^(?:|#[a-fA-F0-9]{6})$/).optional()}).strict();
const semanticText=z.string().max(2000).refine(v=>!sensitive.test(v),'Credential values are not screen context');
const semantics={labels:z.record(z.string().max(100),semanticText).refine(v=>Object.keys(v).length<=80).default({}),fields:z.array(z.string().regex(/^[a-zA-Z0-9_.-]{1,100}$/)).max(150).default([]),filters:z.record(z.string().max(100),semanticText).refine(v=>Object.keys(v).length<=40).default({}),provenance:z.record(z.string().max(100),semanticText).refine(v=>Object.keys(v).length<=80).default({}),scroll_anchor:z.string().max(160).optional()};
export const contextSchema=z.object({...semantics,device_id:uuid,scene_id:uuid,module:z.enum(modules),screen:z.string().regex(/^[a-zA-Z0-9_.-]{1,100}$/),timestamp:z.iso.datetime({offset:true}),path:z.array(z.string().regex(/^[a-zA-Z0-9_.-]{1,100}$/)).max(12).default([]),references:z.array(z.object({entity:z.string().regex(/^[a-z_]{1,40}$/),id:z.string().regex(/^[A-Za-z0-9_:-]{1,200}$/)}).strict()).max(10).default([]),section:z.string().regex(/^[a-zA-Z0-9_.-]{1,100}$/).optional(),state:z.enum(['ready','loading','error']).default('ready'),selected_date:z.iso.date().optional(),draft:z.object({id:uuid,revision:z.number().int().nonnegative(),kind:z.literal('todo_task'),properties:taskDraftChangesSchema.optional(),values:z.object({title:z.string().max(200),detail:z.string().max(12000),priority:z.enum(['low','normal','high','urgent'])}).strict().optional()}).strict().optional()}).strict();
export const commandSchema=z.object({route:z.enum(modules),entity:z.string().regex(/^[a-z_]{1,40}$/).optional(),id:z.string().regex(/^[A-Za-z0-9_:-]{1,200}$/).optional(),section:z.string().regex(/^[a-zA-Z0-9_.-]{1,100}$/).optional(),date:z.iso.date().optional()}).strict();
export const draftCommandSchema=z.object({route:z.literal('todo'),action:z.enum(['set_title','replace_detail','append_detail','set_priority','save','discard','update_fields']),changes:taskDraftChangesSchema.optional(),draft_id:uuid,expected_revision:z.number().int().nonnegative(),value:z.string().max(12000).optional()}).strict();
export const locationCommandSchema=z.object({route:z.literal('routes'),action:z.literal('resolve_location'),location_request:z.discriminatedUnion('kind',[z.object({kind:z.literal('contact'),contact_id:uuid,source_hash:z.string().optional()}).strict(),z.object({kind:z.literal('address'),address:z.string().trim().min(1).max(1000)}).strict(),z.object({kind:z.literal('current_location')}).strict()])}).strict();
export const refreshContextSchema=z.object({route:z.literal('more'),action:z.literal('refresh_context')}).strict();
const sensitive=/\b(?:sk-[a-zA-Z0-9_-]{16,}|Bearer\s+[a-zA-Z0-9_.-]{16,}|-----BEGIN[^\n]*PRIVATE KEY|password\s*[:=]|api[_ -]?key\s*[:=])/i;
const safeText=value=>{if(sensitive.test(value))throw fault(400,'secret_not_allowed','Credentials cannot be saved as instructions or memories.');return value;};
const publicSettings=s=>s?{connection_id:s.connection_id,funding:s.funding,key_configured:!!s.key_ciphertext,model:s.model,reasoning:s.reasoning,instructions:s.instructions,memory_enabled:s.memory_enabled,monthly_limit_micros:Number(s.monthly_limit_micros),revision:s.revision}:null;
export async function installAssistant({app,pool,authRequired,env=process.env,provider=createProvider({env}),startWorker=true,externalExecutor}){
 await installAssistantSchema(pool);const funding=createFundingService(pool,env);const engine=createEngine({app,pool,provider,env,externalExecutor,funding});const memory=createMemoryService(pool);await engine.purgeDeleted();
 async function settings(a){return (await pool.query('SELECT * FROM wolf_assistant_settings WHERE company_id=$1 AND user_id=$2',[a.companyId,a.userId])).rows[0];}
 async function chat(a,id){const r=(await pool.query('SELECT * FROM wolf_assistant_conversations WHERE id=$1 AND company_id=$2 AND user_id=$3 AND deleted_at IS NULL',[uuid.parse(id),a.companyId,a.userId])).rows[0];if(!r)throw fault(404,'conversation_not_found');return r;}
 async function run(a,id){const r=(await pool.query('SELECT r.* FROM wolf_assistant_runs r JOIN wolf_assistant_conversations c ON c.id=r.conversation_id WHERE r.id=$1 AND r.company_id=$2 AND r.user_id=$3 AND c.deleted_at IS NULL',[uuid.parse(id),a.companyId,a.userId])).rows[0];if(!r)throw fault(404,'run_not_found');return r;}
 const safe=fn=>async(req,res)=>{res.set('Cache-Control','no-store');try{
  if(req[internalActor])throw fault(403,'human_session_required');if(env.ASSISTANT_ENABLED!=='true')throw fault(503,'assistant_disabled');
  if(req.method!=='GET'&&req.headers.origin&&!new Set([env.MCP_WEB_ORIGIN,env.MCP_PUBLIC_ORIGIN]).has(req.headers.origin))throw fault(403,'origin_not_allowed');
  const a=await loadPrincipal(pool,req.userId,req.companyId,{enforceOAuthRolePolicy:false});if(!a.permissions.capabilities['ai.use'])throw fault(403,'assistant_access_denied');
  await rateLimit(pool,'assistant:'+a.userId,120);await fn(req,res,a);
 }catch(e){res.status(e instanceof z.ZodError?400:e.status||500).json({error:e instanceof z.ZodError?'invalid_assistant_input':e.code||'assistant_unavailable',message:e.status?e.message:'Assistant is unavailable. Your saved conversation is retained.'});}};
 const route=(method,path,fn)=>app[method]('/api/assistant'+path,authRequired,safe(fn));
 route('get','/status',async(req,res,a)=>{
  const s=await settings(a);const ownerFunding=await funding.own({company_id:a.companyId,user_id:a.userId});let models=[],model_error=null;if(s)try{await funding.authorize(s);models=await provider.models(s);}catch(e){model_error=e.code||'funding_unavailable';}
  const identity=s?(await pool.query('SELECT * FROM mcp_connections WHERE id=$1',[s.connection_id])).rows[0]:null;
  res.json({enabled:true,company_id:a.companyId,can_manage:canManage(a),can_allocate_funding:a.isCompanyOwner,owner_funding:ownerFunding,settings:publicSettings(s),connection:identity?await app.locals.connectionManager.snapshot(identity,a):null,models,model_error,funding_sources:[{id:'owner',name:'Wolf CRM owner API funding',available:ownerFunding.available},{id:'personal',name:'Your OpenAI API key',available:true}],cost_status:'estimate_only',chatgpt_plan:{available:false,reason:'Paid/remotely hosted app access requires OpenAI approval; existing ChatGPT OAuth is unchanged.',documentation:'https://developers.openai.com/siwc/token-sharing-open-source'}});
 });
 route('get','/usage',async(req,res,a)=>{
  const s=await settings(a);
  const totals=(await pool.query("SELECT COALESCE(sum(cost_micros),0)::float8 AS cost_micros,COALESCE(sum(reserved_micros),0)::float8 AS reserved_micros,COALESCE(sum((usage->>'input_tokens')::bigint),0)::float8 AS input_tokens,COALESCE(sum((usage->>'output_tokens')::bigint),0)::float8 AS output_tokens,COALESCE(sum((usage->>'cached_input_tokens')::bigint),0)::float8 AS cached_input_tokens,COALESCE(sum((usage->>'web_search_calls')::bigint),0)::float8 AS web_search_calls FROM wolf_assistant_runs WHERE company_id=$1 AND user_id=$2 AND created_at>=(date_trunc('month',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')",[a.companyId,a.userId])).rows[0];
  res.json({...totals,monthly_limit_micros:Number(s?.monthly_limit_micros||0),cost_status:'estimate_only',period:'Current UTC calendar month',alert:Number(s?.monthly_limit_micros)>0&&totals.cost_micros+totals.reserved_micros>=Number(s.monthly_limit_micros)*0.8?'near_limit':null});
 });
 route('post','/setup',async(req,res,a)=>{
  z.object({}).strict().parse(req.body);
  await transaction(pool,async db=>{await db.query('SELECT id FROM companies WHERE id=$1 FOR UPDATE',[a.companyId]);if(await settings(a))return;await lockConnectionSlot(db,a.companyId);const id=randomUUID();
   await db.query("INSERT INTO retell_connections(id,company_id,user_id,provider,managed,config,expires_at) VALUES($1,$2,$3,'wolf-assistant',true,'{\"quotes_enabled\":true,\"quote_duration_minutes\":null}',now()+interval '10 years')",[id,a.companyId,a.userId]);
   await db.query("INSERT INTO mcp_connections(id,user_id,company_id,client_id,scopes,audience,kind,name,description,provider,tool_policy,expires_at) VALUES($1,$2,$3,'wolf-service',$4,'native-assistant','assistant','Wolf Assistant','Native assistant execution identity','wolf-assistant','{}',now()+interval '10 years')",[id,a.userId,a.companyId,JSON.stringify(Object.keys(scopes))]);
   await db.query('INSERT INTO wolf_assistant_settings(company_id,user_id,connection_id) VALUES($1,$2,$3)',[a.companyId,a.userId,id]);
  });res.status(201).json({settings:publicSettings(await settings(a))});
 });
 route('post','/models',async(req,res,a)=>{const i=z.object({funding:z.enum(['owner','personal']),api_key:z.string().min(20).max(400).optional()}).strict().parse(req.body);const s=await settings(a);if(!s)throw fault(409,'assistant_setup_required');await funding.authorize({...s,funding:i.funding});res.json({models:await provider.models({...s,funding:i.funding,key_ciphertext:i.api_key?encryptKey(i.api_key,s,env):s.key_ciphertext})});});
 route('get','/funding/allocations',async(req,res,a)=>res.json(await funding.list(a)));
 route('put','/funding/allocations/:id',async(req,res,a)=>res.json(await funding.save(a,uuid.parse(req.params.id),req.body)));
 route('delete','/funding/personal',async(req,res,a)=>{await pool.query('UPDATE wolf_assistant_settings SET key_ciphertext=NULL,revision=revision+1 WHERE company_id=$1 AND user_id=$2',[a.companyId,a.userId]);res.json({removed:true});});
 route('put','/settings',async(req,res,a)=>{
  const i=z.object({expected_revision:z.number().int().positive(),funding:z.enum(['owner','personal']),api_key:z.string().min(20).max(400).optional(),model:z.string().max(100),reasoning:z.string().max(30).nullable(),instructions:z.string().max(12000),memory_enabled:z.boolean(),monthly_limit_micros:z.number().int().min(0).max(1000000000)}).strict().parse(req.body);modelFor(i.model,i.reasoning);safeText(i.instructions);
  const s=await settings(a);if(!s)throw fault(409,'assistant_setup_required');await funding.authorize({...s,funding:i.funding});
  const next={...s,...i,key_ciphertext:i.api_key?encryptKey(i.api_key,s,env):s.key_ciphertext};if(!(await provider.models(next)).some(m=>m.id===i.model))throw fault(400,'model_unavailable_for_funding');
  await funding.authorize(next);
  const saved=await pool.query('UPDATE wolf_assistant_settings SET funding=$3,key_ciphertext=$4,model=$5,reasoning=$6,instructions=$7,memory_enabled=$8,monthly_limit_micros=$9,revision=revision+1 WHERE company_id=$1 AND user_id=$2 AND revision=$10 RETURNING *',[a.companyId,a.userId,i.funding,next.key_ciphertext,i.model,i.reasoning,i.instructions,i.memory_enabled,i.monthly_limit_micros,i.expected_revision]);if(!saved.rowCount)throw fault(409,'settings_changed');res.json(publicSettings(saved.rows[0]));
 });
 route('get','/context-candidates',async(req,res,a)=>{
  const entity=z.enum(['contacts','notes','files']).parse(req.query.entity),query=z.string().max(200).parse(req.query.query||''),offset=page.parse(req.query.offset);const actor={...a,scopes:Object.keys(scopes)};
  if(entity==='notes'){const r=await app.locals.notes.list(actor,{search:query,limit:25,offset});return res.json({items:r.pages.map(p=>({entity,id:p.id,label:p.title})),next_offset:r.next_offset});}
  if(entity==='files'){
   if(!a.permissions.capabilities['storage.view']||!app.locals.mediaStorage)throw fault(403,'files_unavailable');
   const r=await app.locals.mediaStorage.list(actor,{search:query,limit:25,cursor:req.query.cursor});return res.json({items:r.files.map(f=>({entity,id:f.id,label:f.display_name})),next_cursor:r.next_cursor});
  }
  const r=await searchRecords(pool,actor,{entity,query,limit:25,offset},env.MCP_WEB_ORIGIN);res.json({items:r.items.map(r=>({entity,id:r.id,label:r.data.name})),next_offset:r.next_offset});
 });
 route('get','/conversations',async(req,res,a)=>{const offset=page.parse(req.query.offset),q=z.string().max(200).parse(req.query.query||'');const rows=(await pool.query("SELECT c.* FROM wolf_assistant_conversations c WHERE company_id=$1 AND user_id=$2 AND deleted_at IS NULL AND (title ILIKE $3 OR EXISTS(SELECT 1 FROM wolf_assistant_messages m WHERE m.conversation_id=c.id AND m.body ILIKE $3)) ORDER BY updated_at DESC,id LIMIT 51 OFFSET $4",[a.companyId,a.userId,'%'+q.replace(/[\\%_]/g,'\\$&')+'%',offset])).rows;res.json({items:rows.slice(0,50),next_offset:rows.length>50?offset+50:null});});
 route('post','/conversations',async(req,res,a)=>{const i=z.object({title:z.string().trim().min(1).max(200).default('New chat'),memory_enabled:z.boolean().default(true)}).strict().parse(req.body);res.status(201).json((await pool.query('INSERT INTO wolf_assistant_conversations(id,company_id,user_id,title,memory_enabled) VALUES($1,$2,$3,$4,$5) RETURNING *',[randomUUID(),a.companyId,a.userId,i.title,i.memory_enabled])).rows[0]);});
 route('get','/conversations/:id',async(req,res,a)=>{const c=await chat(a,req.params.id),before=z.coerce.number().int().positive().optional().parse(req.query.before);const messages=(await pool.query('SELECT *,id::text AS id FROM wolf_assistant_messages WHERE conversation_id=$1 AND ($2::bigint IS NULL OR id<$2) ORDER BY wolf_assistant_messages.id DESC LIMIT 101',[c.id,before||null])).rows;const active=(await pool.query('SELECT id,status,output,error_code,cost_micros::float8 AS cost_micros,usage FROM wolf_assistant_runs WHERE conversation_id=$1 ORDER BY created_at DESC LIMIT 1',[c.id])).rows[0];res.json({conversation:c,messages:messages.slice(0,100).reverse(),before:messages.length>100?messages[99].id:null,run:active||null});});
 route('patch','/conversations/:id',async(req,res,a)=>{const c=await chat(a,req.params.id),i=z.object({title:z.string().trim().min(1).max(200)}).strict().parse(req.body);await pool.query('UPDATE wolf_assistant_conversations SET title=$2,updated_at=now() WHERE id=$1',[c.id,i.title]);res.json({saved:true});});
 route('delete','/conversations/:id',async(req,res,a)=>{
  const c=await chat(a,req.params.id);
  await pool.query('UPDATE wolf_assistant_conversations SET deleted_at=now() WHERE id=$1',[c.id]);
  for(const r of (await pool.query("SELECT * FROM wolf_assistant_runs WHERE conversation_id=$1 AND status IN ('queued','running','waiting_approval','waiting_client')",[c.id])).rows)await engine.cancel(r);
  await engine.purgeDeleted(c.id);res.json({deleted:true,memories_deleted:false});
 });
 async function enqueue(a,i,{correlationKey=null,automationRunId=null}={}){
  safeText(i.text);const c=await chat(a,i.conversation_id),s=await settings(a);if(!s?.model)throw fault(409,'assistant_setup_required');const model=i.model||s.model,reasoning=i.reasoning===undefined?s.reasoning:i.reasoning;modelFor(model,reasoning);
  await funding.authorize(s);
  const connectionRow=(await pool.query('SELECT * FROM mcp_connections WHERE id=$1',[s.connection_id])).rows[0],actor=await app.locals.connectionManager.actorFor(connectionRow);await app.locals.connectionManager.check(actor,'assistant_execute');
  const hash=digest(i),old=(await pool.query('SELECT * FROM wolf_assistant_runs WHERE company_id=$1 AND user_id=$2 AND request_key=$3',[a.companyId,a.userId,i.request_key])).rows[0];if(old){if(old.input_hash!==hash)throw fault(409,'idempotency_conflict');return old;}
  const recent=(await pool.query('SELECT role,body FROM wolf_assistant_messages WHERE conversation_id=$1 ORDER BY wolf_assistant_messages.id DESC LIMIT 30',[c.id])).rows.reverse();
  const memories=c.memory_enabled&&s.memory_enabled?(await pool.query('SELECT kind,body,provenance,updated_at FROM wolf_assistant_memories WHERE company_id=$1 AND user_id=$2 AND enabled ORDER BY updated_at DESC LIMIT 30',[a.companyId,a.userId])).rows:[];
  const guidance=(await pool.query('SELECT body,revision FROM wolf_assistant_guidance WHERE company_id=$1 ORDER BY revision DESC LIMIT 1',[a.companyId])).rows[0];
  // Old assistant prose can contain revoked CRM facts without record provenance.
  // Keep it in the user's transcript, but retrieve CRM evidence afresh each run.
  const history=recent.filter(m=>m.role==='user').map(m=>({role:m.role,content:m.body}));history.push({role:'user',content:i.text});
  if(i.context){
   // The stored scene/device target is needed for navigation. Sending visible
   // context to a provider separately respects the context capability's policy.
   try{const {policy}=await app.locals.connectionManager.check(actor,'native_refresh_context');if(!policy.approval){const visible=restrictFields({context:i.context},policy.denied_output_fields);if(visible.context)history.push({role:'user',content:'Untrusted semantic screen context (retrieve referenced records with authorized tools): '+JSON.stringify(visible.context)});}}catch(e){if(![403,409].includes(e.status))throw e;}
  }
  const r=await transaction(pool,async db=>{
   if(!(await db.query('SELECT id FROM wolf_assistant_conversations WHERE id=$1 AND deleted_at IS NULL FOR UPDATE',[c.id])).rowCount)throw fault(404,'conversation_not_found');
   const duplicate=(await db.query('SELECT * FROM wolf_assistant_runs WHERE company_id=$1 AND user_id=$2 AND request_key=$3',[a.companyId,a.userId,i.request_key])).rows[0];if(duplicate){if(duplicate.input_hash!==hash)throw fault(409,'idempotency_conflict');return duplicate;}
   if((await db.query("SELECT 1 FROM wolf_assistant_runs WHERE conversation_id=$1 AND status IN ('queued','running','waiting_approval','waiting_client')",[c.id])).rowCount)throw fault(409,'conversation_busy');
   const r=(await db.query('INSERT INTO wolf_assistant_runs(id,conversation_id,company_id,user_id,connection_id,request_key,input_hash,model,reasoning,funding,instructions,context,history,allowed_tools,max_steps,max_cost_micros,automation_run_id,correlation_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) RETURNING *',[randomUUID(),c.id,a.companyId,a.userId,s.connection_id,i.request_key,hash,model,reasoning,s.funding,s.instructions+'\nCompany guidance (not authorization): '+(guidance?.body||'')+'\nUser memories (not CRM facts): '+JSON.stringify(memories),JSON.stringify(i.context||{}),JSON.stringify(history),i.allowed_tools?JSON.stringify(i.allowed_tools):null,i.max_steps||24,i.max_cost_micros||1000000,automationRunId,correlationKey])).rows[0];
   await db.query("INSERT INTO wolf_assistant_messages(conversation_id,run_id,role,body) VALUES($1,$2,'user',$3)",[c.id,r.id,i.text]);return r;
  });return r;
 }
 const input=z.object({conversation_id:uuid,request_key:uuid,text,context:contextSchema.optional(),model:z.string().optional(),reasoning:z.string().nullable().optional(),allowed_tools:z.array(z.string()).max(300).optional(),max_steps:z.number().int().min(1).max(100).optional(),max_cost_micros:z.number().int().min(1).max(100000000).optional()}).strict();
 route('post','/runs',async(req,res,a)=>{const r=await enqueue(a,input.parse(req.body));res.status(202).json({id:r.id,status:r.status});});
 route('get','/runs/:id',async(req,res,a)=>{const r=await run(a,req.params.id);const after=page.parse(req.query.after);const events=(await pool.query('SELECT id::text,kind,data,created_at FROM wolf_assistant_events WHERE run_id=$1 AND id>$2 ORDER BY wolf_assistant_events.id LIMIT 101',[r.id,after])).rows;res.json({id:r.id,status:r.status,output:r.output,error_code:r.error_code,cost_micros:Number(r.cost_micros),reserved_micros:Number(r.reserved_micros),cost_status:'estimate_only',usage:r.usage,actions:(await pool.query("SELECT call_id AS id,tool,state,completed_at,result->>'error' AS error FROM wolf_assistant_steps WHERE run_id=$1 AND tool NOT IN ('assistant_execute','discover_capabilities','load_capabilities') ORDER BY started_at NULLS FIRST,call_id",[r.id])).rows,events:events.slice(0,100),more:events.length>100});});
 route('post','/runs/:id/cancel',async(req,res,a)=>{await engine.cancel(await run(a,req.params.id));res.json({cancel_requested:true});});
 route('get','/memories',async(req,res,a)=>res.json(await memory.list(a)));
 route('post','/memories',async(req,res,a)=>res.status(201).json(await memory.save(a,req.body)));
 route('put','/memories/:id',async(req,res,a)=>{const i=z.object({body:text,enabled:z.boolean(),expected_revision:z.number().int().positive()}).strict().parse(req.body);safeText(i.body);const r=await pool.query('UPDATE wolf_assistant_memories SET body=$4,enabled=$5,revision=revision+1,updated_at=now() WHERE id=$1 AND company_id=$2 AND user_id=$3 AND revision=$6 RETURNING *',[uuid.parse(req.params.id),a.companyId,a.userId,i.body,i.enabled,i.expected_revision]);if(!r.rowCount)throw fault(409,'memory_changed');res.json(r.rows[0]);});
 route('delete','/memories/:id',async(req,res,a)=>res.json(await memory.remove(a,req.params.id)));
 route('get','/guidance',async(req,res,a)=>res.json({revisions:(await pool.query('SELECT * FROM wolf_assistant_guidance WHERE company_id=$1 ORDER BY revision DESC LIMIT 50',[a.companyId])).rows}));
 route('post','/guidance',async(req,res,a)=>{if(!canManage(a))throw fault(403,'guidance_manager_required');const i=z.object({body:text,expected_revision:z.number().int().nonnegative()}).strict().parse(req.body);safeText(i.body);await transaction(pool,async db=>{await db.query('SELECT id FROM companies WHERE id=$1 FOR UPDATE',[a.companyId]);const current=(await db.query('SELECT COALESCE(max(revision),0) AS revision FROM wolf_assistant_guidance WHERE company_id=$1',[a.companyId])).rows[0].revision;if(current!==i.expected_revision)throw fault(409,'guidance_changed');await db.query('INSERT INTO wolf_assistant_guidance(company_id,revision,body,author_id) VALUES($1,$2,$3,$4)',[a.companyId,current+1,i.body,a.userId]);});res.json({saved:true});});
 async function issueCommand(a,raw){
  const i=z.union([commandSchema,draftCommandSchema,refreshContextSchema,locationCommandSchema,nativeMapEditSchema,nativeLightingEditSchema,nativeBrowserEditSchema]).parse(raw),inv=a.assistantInvocation;if(!inv)throw fault(409,'native_scene_required');const r=await run(a,inv.runId),c=contextSchema.safeParse(r.context);if(!c.success||(i.action!=='refresh_context'&&Date.now()-Date.parse(c.data.timestamp)>300000))throw fault(409,'native_context_stale');
  if(i.action&& !['refresh_context','resolve_location','map_edit','lighting_edit','browser_edit'].includes(i.action)&&i.draft_id!==c.data.draft?.id)throw fault(409,'native_draft_changed');
  if(i.action==='browser_edit'&&(c.data.module!=='browser'||i.browser_edit.generation!==c.data.filters.browser_generation))throw fault(409,'native_browser_changed');
  if(['map_edit','lighting_edit'].includes(i.action)&&(i.draft_id!==c.data.filters.native_draft_id||String(i.expected_revision)!==c.data.filters.native_revision))throw fault(409,'native_draft_changed');
  if(i.action==='resolve_location'&&i.location_request.kind==='contact'){const contact=await getRecord(pool,a,'contacts',i.location_request.contact_id);i.location_request.source_hash=(await import('./context.js')).evidenceHash(contact);}
  if(i.id){if(!i.entity)throw fault(400,'entity_required');
   if(i.route==='browser'&&i.entity==='browser_links'){
    const [type,recordID,linkID,...extra]=i.id.split(':');if(extra.length||!['contact','job','quote'].includes(type)||!/^[A-Za-z0-9_-]{1,160}$/.test(recordID)||!uuid.safeParse(linkID).success)throw fault(400,'invalid_browser_link');
    const links=await dispatch(app,a,'GET',`/api/browser/records/${type}/${recordID}/links`);if(!(Array.isArray(links)?links:links.items||links.links||[]).some(l=>l.id===linkID))throw fault(404,'browser_link_unavailable');
   }else if(i.entity==='files'&&i.route==='media'){if(!a.permissions.capabilities['storage.view'])throw fault(403,'permission_denied');if(!app.locals.mediaStorage)throw fault(503,'storage_not_configured');await app.locals.mediaStorage.get(a,i.id);}else if(['measurements','lighting_projects'].includes(i.entity)){const rows=await dispatch(app,a,'GET',i.entity==='measurements'?'/api/measurements':'/api/lighting/projects');if(!(Array.isArray(rows)?rows:[]).some(r=>String(r.id).toLowerCase()===i.id.toLowerCase()))throw fault(404,'native_record_unavailable');}else if(i.entity==='routes'){await dispatch(app,a,'GET','/api/routes/'+i.id);}else if(i.entity==='notes')await app.locals.notes.get(a,i.id,{limit:1});else await getRecord(pool,a,i.entity,i.id);
  }
  const row=(await pool.query('INSERT INTO wolf_assistant_commands(id,run_id,call_id,device_id,scene_id,command) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(run_id,call_id) DO UPDATE SET run_id=EXCLUDED.run_id RETURNING *',[randomUUID(),r.id,inv.callId,c.data.device_id,c.data.scene_id,JSON.stringify(i)])).rows[0];return {command_id:row.id,state:row.state,message:'Waiting for the originating app scene to acknowledge navigation.'};
 }
 async function authorizeCommand(a,command){
  const current=await run(a,command.run_id), sponsor=await engine.actor(current);
  if(!['running','waiting_client','waiting_approval'].includes(current.status))throw fault(409,'command_unavailable');
  const step=(await pool.query('SELECT tool,arguments FROM wolf_assistant_steps WHERE run_id=$1 AND call_id=$2',[command.run_id,command.call_id])).rows[0];
  if(!step)throw fault(409,'command_unavailable');
  const {policy}=await app.locals.connectionManager.check(sponsor,step.tool);
  restrictFields(step.arguments,policy.denied_input_fields,{write:true});
 }
 route('get','/commands',async(req,res,a)=>{
  const device=uuid.parse(req.query.device_id),scene=uuid.parse(req.query.scene_id),items=[];
  const pending=(await pool.query("SELECT c.id,c.run_id,c.call_id,c.command,c.expires_at FROM wolf_assistant_commands c JOIN wolf_assistant_runs r ON r.id=c.run_id WHERE r.company_id=$1 AND r.user_id=$2 AND c.device_id=$3 AND c.scene_id=$4 AND c.state='pending' AND c.expires_at>now() AND NOT r.cancel_requested ORDER BY c.expires_at,c.id",[a.companyId,a.userId,device,scene])).rows;
  for(const command of pending){
   try{await authorizeCommand(a,command);items.push({id:command.id,command:command.command,expires_at:command.expires_at});}
   catch(e){if(![403,404,409].includes(e.status))throw e;await pool.query("UPDATE wolf_assistant_commands SET state='unavailable',result=$2 WHERE id=$1 AND state='pending'",[command.id,JSON.stringify({state:'unavailable',message:'Current authorization no longer permits this native command.'})]);}
  }
  res.json({items});
 });
 route('post','/commands/:id/ack',async(req,res,a)=>{const i=z.object({device_id:uuid,scene_id:uuid,state:z.enum(['completed','unavailable','conflict']),message:z.string().max(500),location:z.object({latitude:z.number().min(-90).max(90),longitude:z.number().min(-180).max(180),label:z.string().max(300)}).strict().optional(),context:contextSchema.optional()}).strict().parse(req.body);if(i.context&&(i.context.device_id!==i.device_id||i.context.scene_id!==i.scene_id))throw fault(409,'context_scene_mismatch');const original=(await pool.query('SELECT command FROM wolf_assistant_commands WHERE id=$1 AND device_id=$2 AND scene_id=$3',[uuid.parse(req.params.id),i.device_id,i.scene_id])).rows[0]?.command;
  if(i.state==='completed'&&i.context&&original&&!original.action){const c=i.context;if(c.state!=='ready'||c.module!==original.route||(original.section&&c.section!==original.section)||(original.date&&c.selected_date!==original.date)||(original.id&&!c.references.some(r=>r.entity===original.entity&&r.id.toLowerCase()===original.id.toLowerCase())))throw fault(409,'destination_context_mismatch');}
  if(i.location){const cmd=(await pool.query('SELECT command FROM wolf_assistant_commands WHERE id=$1 AND device_id=$2 AND scene_id=$3',[uuid.parse(req.params.id),i.device_id,i.scene_id])).rows[0];if(cmd?.command?.action!=='resolve_location'||i.state!=='completed')throw fault(400,'location_command_required');}
  const authorized=(await pool.query('SELECT run_id,call_id FROM wolf_assistant_commands WHERE id=$1 AND device_id=$2 AND scene_id=$3',[uuid.parse(req.params.id),i.device_id,i.scene_id])).rows[0];if(!authorized)throw fault(409,'command_unavailable');await authorizeCommand(a,authorized);
  const r=await pool.query("UPDATE wolf_assistant_commands c SET state=$5,result=$6 FROM wolf_assistant_runs r WHERE c.run_id=r.id AND c.id=$1 AND r.company_id=$2 AND r.user_id=$3 AND c.scene_id=$4 AND c.device_id=$7 AND c.state='pending' AND c.expires_at>now() AND NOT r.cancel_requested RETURNING c.id,c.run_id",[uuid.parse(req.params.id),a.companyId,a.userId,i.scene_id,i.state,JSON.stringify({state:i.state,message:i.message,...(i.location?{location:i.location}:{}),...(i.context?{context:i.context}:{})}),i.device_id]);if(!r.rowCount)throw fault(409,'command_unavailable');if(i.context)await pool.query('UPDATE wolf_assistant_runs SET context=$2 WHERE id=$1',[r.rows[0].run_id,JSON.stringify(i.context)]);res.json({saved:true});});
 const api={...engine,memory,enqueue,issueCommand,input,startAutomation:automationBridge({app,pool,enqueue})};app.locals.assistant=api;
 let timer;if(startWorker){timer=setInterval(()=>engine.tick().catch(()=>console.warn('[assistant] worker deferred')),1500);timer.unref();}api.stop=()=>clearInterval(timer);return api;
}
