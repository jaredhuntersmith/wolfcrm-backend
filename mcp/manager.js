import {configSchema,readConfig,missingRules} from '../retell/config.js';
import {validateBookingConfiguration} from '../retell/settings-validation.js';
import {randomUUID} from 'node:crypto';
import {z} from 'zod';
import {loadPrincipal,permit,scopes,rateLimit,connection} from './access.js';
import {digest,fault,transaction,internalActor} from './context.js';
import {installManagerSchema,lockConnectionSlot} from './manager-schema.js';
import {hoursSchema,accessStatus} from './hours.js';
import {newKey,principal as servicePrincipal} from '../retell/security.js';
const rule=z.object({allow:z.boolean(),approval:z.boolean()}).strict();
export const canManage=a=>a.isCompanyOwner||(a.permissions.preset==='admin'&&a.permissions.capabilities['ai.manage']&&a.permissions.capabilities['integrations.manage']);
const guard=z.object({expected_company_id:z.uuid(),expected_revision:z.number().int().positive()});
export async function installConnectionManager({app,pool,authRequired,env,catalog,execute}){
 await installManagerSchema(pool);
 const definitions=new Map(catalog.map(d=>[d.id,d]));
 const audit=(db,row,operation,outcome,userId=row.user_id)=>db.query('INSERT INTO mcp_audit(connection_id,company_id,user_id,operation,outcome) VALUES($1,$2,$3,$4,$5)',[row.id,row.company_id,userId,operation,outcome]);
 async function initialize(db,row){
  if(row.tool_policy!==null)return row;
  const service=row.kind==='service'?(await db.query('SELECT * FROM retell_connections WHERE id=$1',[row.id])).rows[0]:null;
  const policy=Object.fromEntries(catalog.filter(d=>row.kind==='oauth'?d.family==='crm'&&row.scopes.includes(d.scope):d.family==='service'&&(!d.id.includes('quote')||['check_quote_availability'].includes(d.id)||service?.config?.quotes_enabled)).map(d=>[d.id,{allow:true,approval:row.kind==='oauth'&&d.write}]));
  // Compare-and-set makes concurrent first reads safe and never overwrites explicit policy.
  return (await db.query('UPDATE mcp_connections SET tool_policy=$2 WHERE id=$1 AND tool_policy IS NULL RETURNING *',[row.id,JSON.stringify(policy)])).rows[0]||(await db.query('SELECT * FROM mcp_connections WHERE id=$1',[row.id])).rows[0];
 }
 for(const row of (await pool.query('SELECT * FROM mcp_connections WHERE tool_policy IS NULL')).rows)await initialize(pool,row);
 async function manager(uid,cid){const actor=await loadPrincipal(pool,uid,cid,{enforceOAuthRolePolicy:false});if(!canManage(actor))throw fault(403,'connection_manager_required','Only the owner or an administrator with AI and integration management access can manage connections.');return actor;}
 async function rowFor(db,id,cid){const row=(await db.query('SELECT * FROM mcp_connections WHERE id=$1 AND company_id=$2',[id,cid])).rows[0];if(!row)throw fault(404,'connection_not_found');return initialize(db,row);}
 async function check(actor,name,{revision}={}){
  if(env.MCP_ENABLED!=='true')throw fault(503,'mcp_disabled');
  const row=await rowFor(pool,actor.connectionId||actor.retell?.id,actor.companyId);
  if(row.kind==='service')await servicePrincipal(pool,(await pool.query('SELECT * FROM retell_connections WHERE id=$1',[row.id])).rows[0],env);
  else await connection(pool,row.id);
  const company=(await pool.query('SELECT operating_hours FROM mcp_company_policy WHERE company_id=$1',[row.company_id])).rows[0];
  const status=accessStatus(row,company?.operating_hours);
  if(!status.allowed)throw Object.assign(fault(403,status.reason,'This connection cannot access tools now.'),{access:status});
  const definition=definitions.get(name),policy=row.tool_policy?.[name];
  if(definition)permit(actor,definition.scope,definition.caps);
  if(!definition||!policy?.allow)throw fault(403,'tool_denied','This tool has not been authorized for this connection.');
  if(revision!==undefined&&revision!==row.revision)throw fault(409,'authorization_changed','Connection settings changed. Submit a new invocation.');
  if(!available(definition,row,actor))throw fault(403,'tool_not_available','The tool requires a different connection type, scope, or current user permission.');
  permit(actor,definition.scope,definition.caps);
  return {row,definition,policy};
 }
 function available(d,row,actor){
  if(d.family==='service'&&row.kind!=='service')return false;
  // Service agents must use the calculator and guarded booking workflow.
  if(row.kind==='service'&&['quote_draft','appointment_create','appointment_update'].includes(d.id))return false;
  return actor.scopes.includes(d.scope)&&d.caps.every(c=>actor.permissions.capabilities[c]);
 }
 async function actorFor(row){if(row.kind==='service')return servicePrincipal(pool,(await pool.query('SELECT * FROM retell_connections WHERE id=$1',[row.id])).rows[0],env);return connection(pool,row.id);}
 const envelope=p=>({approval_id:p.id,state:p.state==='pending'&&new Date(p.expires_at)<=new Date()?'expired':p.state,expires_at:new Date(p.expires_at).toISOString(),review_url:env.MCP_WEB_ORIGIN?env.MCP_WEB_ORIGIN+'/settings':null,result:p.state==='completed'?p.result:null,message:p.state==='completed'?'Approved invocation completed.':'Review this exact invocation in WolfCRM Settings → AI Connections. Retry with the same arguments and _request_id equal to approval_request_id.',approval_request_id:p.request_id});
 async function invoke(actor,name,input,requestId){
  const id=actor.connectionId||actor.retell?.id;
  try{
   const {row,policy}=await check(actor,name);await rateLimit(pool,'managed-tool:'+id,120);
   if(!policy.approval){const result=await execute(actor,name,input);await pool.query('UPDATE mcp_connections SET last_used_at=now() WHERE id=$1',[id]);await audit(pool,row,name,'success');return result;}
   const request=requestId||input.request_id||randomUUID(),hash=digest(input);
   const p=await transaction(pool,async db=>{
    await db.query('SELECT id FROM mcp_connections WHERE id=$1 FOR UPDATE',[id]);await check(actor,name,{revision:row.revision});
    await db.query(`INSERT INTO mcp_approvals(id,connection_id,request_id,operation,input_hash,payload,scopes,policy_revision,tool_invocation) VALUES($1,$2,$3,$4,$5,$6,$7,$8,true) ON CONFLICT(connection_id,request_id) DO NOTHING`,[randomUUID(),id,request,name,hash,JSON.stringify(input),JSON.stringify(actor.scopes),row.revision]);
    const proposal=(await db.query('SELECT * FROM mcp_approvals WHERE connection_id=$1 AND request_id=$2',[id,request])).rows[0];
    if(proposal.operation!==name||proposal.input_hash!==hash)throw fault(409,'idempotency_conflict');
    if(proposal.policy_revision!==row.revision)throw fault(409,'authorization_changed');
    return proposal;
   });await audit(pool,row,name,p.state==='pending'?'approval_requested':'approval_'+p.state);return envelope(p);
  }catch(e){const row=(await pool.query('SELECT * FROM mcp_connections WHERE id=$1',[id])).rows[0];if(row)await audit(pool,row,name,['company_hours','connection_hours','paused_until'].includes(e.code)?'schedule_block':e.status===403?'permission_denied:'+String(e.code||'denied').slice(0,80):'failure:'+(/^[a-z_]{1,80}$/.test(e.code||'')?e.code:'operation_unavailable'));throw e;}
 }
 async function decide({userId,companyId,id,expectedHash,decision}){
  return transaction(pool,async db=>{
   const p=(await db.query('SELECT p.* FROM mcp_approvals p JOIN mcp_connections g ON g.id=p.connection_id WHERE p.id=$1 AND g.company_id=$2 ',[id,companyId])).rows[0];
   if(!p||!p.tool_invocation)throw fault(404,'approval_unavailable');
   await db.query('SELECT id FROM mcp_connections WHERE id=$1 FOR UPDATE',[p.connection_id]);
   Object.assign(p,(await db.query('SELECT * FROM mcp_approvals WHERE id=$1 FOR UPDATE',[id])).rows[0]);
   const row=await rowFor(db,p.connection_id,companyId);
   // Approval arguments/results may contain sponsor-private notes or files.
   if(userId!==row.user_id)throw fault(404,'approval_unavailable');
   await loadPrincipal(db,userId,companyId,{enforceOAuthRolePolicy:false});
   if(p.input_hash!==expectedHash)throw fault(409,'proposal_changed');
   if(p.state==='completed'){const a=await actorFor(row);await check(a,p.operation,{revision:p.policy_revision});return {state:'completed',result:p.result};}
   if(p.state!=='pending'||new Date(p.expires_at)<=new Date())throw fault(409,'approval_inactive');
   if(decision==='reject'){await db.query("UPDATE mcp_approvals SET state='rejected',payload=NULL WHERE id=$1",[id]);await audit(db,row,p.operation,'approval_rejected',userId);return {state:'rejected'};}
   const actor=await actorFor(row);await check(actor,p.operation,{revision:p.policy_revision});
   const result=await execute(actor,p.operation,p.payload);
   await db.query("UPDATE mcp_approvals SET state='completed',payload=NULL,result=$2 WHERE id=$1",[id,JSON.stringify(result)]);await audit(db,row,p.operation,'approval_accepted',userId);return {state:'completed',result};
  });
 }
 const safe=fn=>async(req,res)=>{res.set({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});try{
  if(req[internalActor])throw fault(403,'human_session_required');
  if(req.method!=='GET'&&req.headers.origin&&!new Set([env.MCP_WEB_ORIGIN,env.MCP_PUBLIC_ORIGIN]).has(req.headers.origin))throw fault(403,'origin_not_allowed');
  req.manager=await manager(req.userId,req.companyId);await rateLimit(pool,'connection-manager:'+req.userId,90);await fn(req,res);
 }catch(e){res.status(e instanceof z.ZodError?400:e.status||500).json({error:e instanceof z.ZodError?'invalid_connection_settings':e.code||'connection_manager_unavailable',message:e.status?e.message:'Check the connection settings and try again.'});}};
 async function snapshot(row,actor){
  const company=(await pool.query('SELECT operating_hours FROM mcp_company_policy WHERE company_id=$1',[row.company_id])).rows[0];
  const r=row.kind==='service'?(await pool.query('SELECT config,key_hash,key_prefix,expires_at,revoked_at FROM retell_connections WHERE id=$1',[row.id])).rows[0]:null;
  const bookingConfig=r?readConfig(r.config):null;
  if(bookingConfig?.job_rules_acknowledged){const settings=(await pool.query('SELECT customer_booking_settings FROM companies WHERE id=$1',[row.company_id])).rows[0];if(r.config.job_rules_hash!==digest(settings?.customer_booking_settings))bookingConfig.job_rules_acknowledged=false;}
  const status=accessStatus({...row,revoked_at:row.revoked_at||r?.revoked_at},company?.operating_hours,new Date(),{next:true});
  let authentication=row.revoked_at||r?.revoked_at?'revoked':(row.kind==='service'&&!r?.key_hash)?'key_required':new Date(r?.expires_at||row.expires_at)<=new Date()?'expired':'configured';
  try{await loadPrincipal(pool,row.user_id,row.company_id,{enforceOAuthRolePolicy:row.kind==='oauth'});}catch{authentication='membership_inactive';}
  const sponsor=await loadPrincipal(pool,row.user_id,row.company_id,{enforceOAuthRolePolicy:false}).catch(()=>null);
  const effective=sponsor?{...sponsor,scopes:row.kind==='service'?Object.keys(scopes).concat(['availability:read','appointments:book','quotes:read','quotes:draft']):row.scopes}:null;
  return {...Object.fromEntries(['id','kind','name','description','provider','enabled','paused_until','archived_at','revoked_at','operating_hours','tool_policy','revision','created_at','last_used_at','expires_at'].map(k=>[k,row[k]??null])),company_id:row.company_id,authentication,access:status,key_prefix:r?.key_prefix||null,automatic_booking:r?.config?.automatic_booking||false,booking_config:bookingConfig,booking_workers:r?(await pool.query('SELECT id,display_name AS name FROM users WHERE company_id=$1 AND deleted_at IS NULL ORDER BY display_name LIMIT 200',[row.company_id])).rows:[],booking_services:r?(await pool.query('SELECT id,name FROM saved_services WHERE company_id=$1 AND archived_at IS NULL ORDER BY name LIMIT 500',[row.company_id])).rows:[],missing_booking_rules:r?{quote:missingRules(bookingConfig,'quote'),job:missingRules(bookingConfig,'job')}:null,catalog:catalog.map(d=>({...d,available:!!effective&&available(d,row,effective)&&d.caps.every(c=>actor.permissions.capabilities[c]),unavailable_reason:row.kind==='service'&&['quote_draft','appointment_create','appointment_update'].includes(d.id)?'Use the calculator draft tools and create_appointment to preserve pricing and booking rules.':null}))};
 }
 app.get('/api/ai-connections/manager',authRequired,safe(async(req,res)=>{
  const rows=(await pool.query('SELECT * FROM mcp_connections WHERE company_id=$1 ORDER BY created_at DESC LIMIT 200',[req.companyId])).rows;
  const connections=[];for(const row of rows)connections.push(await snapshot(await initialize(pool,row),req.manager));
  const company=(await pool.query('SELECT operating_hours,revision FROM mcp_company_policy WHERE company_id=$1',[req.companyId])).rows[0]||{operating_hours:null,revision:0};
  const approvals=(await pool.query(`SELECT p.id,p.connection_id,p.operation,p.input_hash,p.payload,p.expires_at,g.name AS client_name FROM mcp_approvals p JOIN mcp_connections g ON g.id=p.connection_id WHERE g.company_id=$1 AND g.user_id=$2 AND p.state='pending' AND p.expires_at>now() AND g.revoked_at IS NULL ORDER BY p.created_at LIMIT 100`,[req.companyId,req.userId])).rows.map(({payload,...p})=>({...p,preview:JSON.stringify(payload,null,2)}));
  const activity=(await pool.query('SELECT id::text,connection_id,operation,outcome,created_at FROM mcp_audit WHERE company_id=$1 ORDER BY id DESC LIMIT 200',[req.companyId])).rows;
  res.json({company_id:req.companyId,company_name:req.manager.companyName,mcp_url:env.MCP_PUBLIC_ORIGIN+'/mcp',enabled:env.MCP_ENABLED==='true',limit:10,active_count:rows.filter(r=>!r.revoked_at&&!r.archived_at).length,connections,company_schedule:company,approvals,activity,outbound_calling_enabled:false});
 }));
 app.post('/api/ai-connections/manager',authRequired,safe(async(req,res)=>{
  const i=z.object({expected_company_id:z.uuid(),name:z.string().trim().min(1).max(100),description:z.string().max(1000).default(''),provider:z.string().max(80).default('')}).strict().parse(req.body);if(i.expected_company_id!==req.companyId)throw fault(409,'account_changed');
  const row=await transaction(pool,async db=>{await lockConnectionSlot(db,req.companyId);await manager(req.userId,req.companyId);const id=randomUUID();
   await db.query("INSERT INTO retell_connections(id,company_id,user_id,provider,managed,config) VALUES($1,$2,$3,'generic',true,'{\"quotes_enabled\":true,\"quote_duration_minutes\":null}')",[id,req.companyId,req.userId]);
   const r=(await db.query("INSERT INTO mcp_connections(id,user_id,company_id,client_id,scopes,audience,kind,name,description,provider,tool_policy) VALUES($1,$2,$3,'wolf-service',$4,'service','service',$5,$6,$7,'{}') RETURNING *",[id,req.userId,req.companyId,JSON.stringify(Object.keys(scopes)),i.name,i.description,i.provider||null])).rows[0];await audit(db,r,'connection.created','success');return r;});res.status(201).json(await snapshot(row,req.manager));
 }));
 async function mutate(req,work){return transaction(pool,async db=>{const i=guard.parse(req.body);if(i.expected_company_id!==req.companyId)throw fault(409,'account_changed');await db.query('SELECT id FROM companies WHERE id=$1 FOR UPDATE',[req.companyId]);await manager(req.userId,req.companyId);const row=await rowFor(db,z.uuid().parse(req.params.id),req.companyId);if(row.revision!==i.expected_revision)throw fault(409,'connection_changed','Reload this connection before saving.');const result=await work(db,row);await db.query("UPDATE mcp_connections SET revision=revision+1 WHERE id=$1",[row.id]);await db.query("UPDATE mcp_approvals SET state='rejected',payload=NULL WHERE connection_id=$1 AND state='pending'",[row.id]);return result;});}
 app.put('/api/ai-connections/manager/:id',authRequired,safe(async(req,res)=>{
  const i=guard.extend({name:z.string().trim().min(1).max(100),description:z.string().max(1000),provider:z.string().max(80).nullable(),enabled:z.boolean(),paused_until:z.iso.datetime({offset:true}).nullable(),operating_hours:hoursSchema.nullable(),tool_policy:z.record(z.string(),rule),automatic_booking:z.boolean(),booking_config:configSchema.optional()}).strict().parse(req.body);
  res.json(await mutate(req,async(db,row)=>{
   if(row.revoked_at||row.archived_at)throw fault(409,'connection_inactive');
   const sponsor=await loadPrincipal(db,row.user_id,row.company_id,{enforceOAuthRolePolicy:false});const actor={...sponsor,scopes:row.kind==='service'?Object.keys(scopes).concat(['availability:read','appointments:book','quotes:read','quotes:draft']):row.scopes};
   for(const [id,r]of Object.entries(i.tool_policy)){const d=definitions.get(id),old=row.tool_policy?.[id];if(!d){if(JSON.stringify(r)!==JSON.stringify(old))throw fault(400,'unknown_tool');continue;}const expanding=r.allow&&(!old?.allow||(old.approval&&!r.approval));if(expanding&&(!available(d,row,actor)||d.caps.some(c=>!req.manager.permissions.capabilities[c])))throw fault(403,'tool_not_available');}
   await db.query('UPDATE mcp_connections SET name=$2,description=$3,provider=$4,enabled=$5,paused_until=$6,operating_hours=$7,tool_policy=$8 WHERE id=$1',[row.id,i.name,i.description,i.provider,i.enabled,i.paused_until,JSON.stringify(i.operating_hours),JSON.stringify(i.tool_policy)]);
   if(row.kind==='service'){
    if(i.booking_config){const config=await validateBookingConfiguration(db,req.companyId,{...i.booking_config,automatic_booking:i.automatic_booking});await db.query('UPDATE retell_connections SET config=$2,revision=revision+1 WHERE id=$1',[row.id,JSON.stringify(config)]);}
    else await db.query("UPDATE retell_connections SET config=jsonb_set(config,'{automatic_booking}',$2::jsonb),revision=revision+1 WHERE id=$1",[row.id,JSON.stringify(i.automatic_booking)]);
   }
   await audit(db,row,'connection.updated','success',req.userId);return {saved:true};
  }));
 }));
 app.post('/api/ai-connections/manager/:id/key',authRequired,safe(async(req,res)=>{
  const i=guard.extend({valid_days:z.number().int().min(1).max(365)}).strict().parse(req.body);res.json(await mutate(req,async(db,row)=>{
   if(row.kind!=='service'||row.revoked_at||row.archived_at)throw fault(409,'credential_unavailable');const key=newKey('elevenlabs');
   await db.query('UPDATE retell_connections SET key_hash=$2,key_prefix=$3,expires_at=now()+make_interval(days=>$4),revision=revision+1 WHERE id=$1',[row.id,digest(key),key.slice(0,20),i.valid_days]);
   await db.query('UPDATE mcp_connections SET expires_at=now()+make_interval(days=>$2) WHERE id=$1',[row.id,i.valid_days]);await audit(db,row,'credential.rotated','success',req.userId);return {authorization:'Bearer '+key,shown_once:true};
  }));
 }));
 for(const action of ['revoke','archive'])app.post('/api/ai-connections/manager/:id/'+action,authRequired,safe(async(req,res)=>{guard.strict().parse(req.body);res.json(await mutate(req,async(db,row)=>{await db.query(`UPDATE mcp_connections SET revoked_at=COALESCE(revoked_at,now()),enabled=false${action==='archive'?',archived_at=now()':''} WHERE id=$1`,[row.id]);if(row.kind==='service')await db.query('UPDATE retell_connections SET revoked_at=COALESCE(revoked_at,now()),revision=revision+1 WHERE id=$1',[row.id]);await audit(db,row,'connection.'+action,'success',req.userId);return {saved:true};}));}));
 app.put('/api/ai-connections/manager-company-hours',authRequired,safe(async(req,res)=>{
  const i=z.object({expected_company_id:z.uuid(),expected_revision:z.number().int().nonnegative(),operating_hours:hoursSchema.nullable()}).strict().parse(req.body);
  if(i.expected_company_id!==req.companyId)throw fault(409,'account_changed');
  await transaction(pool,async db=>{await db.query('SELECT id FROM companies WHERE id=$1 FOR UPDATE',[req.companyId]);await manager(req.userId,req.companyId);const old=(await db.query('SELECT revision FROM mcp_company_policy WHERE company_id=$1',[req.companyId])).rows[0];if((old?.revision||0)!==i.expected_revision)throw fault(409,'policy_changed');await db.query('INSERT INTO mcp_company_policy(company_id,operating_hours) VALUES($1,$2) ON CONFLICT(company_id) DO UPDATE SET operating_hours=$2,revision=mcp_company_policy.revision+1',[req.companyId,JSON.stringify(i.operating_hours)]);await db.query("UPDATE mcp_approvals SET state='rejected',payload=NULL WHERE state='pending' AND connection_id IN(SELECT id FROM mcp_connections WHERE company_id=$1)",[req.companyId]);await db.query("INSERT INTO mcp_audit(company_id,user_id,operation,outcome) VALUES($1,$2,'company.hours_changed','success')",[req.companyId,req.userId]);});res.json({saved:true});
 }));
 const api={check,invoke,decide,manager,initialize};app.locals.connectionManager=api;return api;
}
