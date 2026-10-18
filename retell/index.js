import {validateBookingConfiguration} from './settings-validation.js';
import {lockConnectionSlot} from '../mcp/manager-schema.js';
import {randomUUID} from 'node:crypto';
import {z} from 'zod';
import {installRetellSchema} from './schema.js';
import {authenticateRetell,encrypt,newKey,scopesFor,serviceEnabled,keyPrefix,serviceKeyPrefix} from './security.js';
import {configSchema,missingRules} from './config.js';
import {createRetellScheduling} from './scheduling.js';
import {installRetellWebhook} from './webhook.js';
import {digest,fault,transaction,internalActor} from '../mcp/context.js';
import {rateLimit} from '../mcp/access.js';
import {lockCompanySchedule} from '../schedule-booking-guard.js';
export async function installRetell({app,pool,authRequired,env=process.env,startWorker=true}){
 await installRetellSchema(pool);
 const scheduling=createRetellScheduling({app,pool,env});
 const webhook=installRetellWebhook({app,pool,env,startWorker});
 const safe=fn=>async(req,res)=>{res.set({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});try{
  if(req[internalActor]||!req.isCompanyOwner)throw fault(403,'owner_session_required');
  if(req.method!=='GET'&&req.headers.origin&&!new Set([env.MCP_WEB_ORIGIN,env.MCP_PUBLIC_ORIGIN]).has(req.headers.origin))throw fault(403,'origin_not_allowed');
  await rateLimit(pool,'retell-settings:'+req.userId,60);await fn(req,res);
 }catch(e){res.status(e instanceof z.ZodError?400:e.status||500).json({error:e instanceof z.ZodError?'invalid_settings':e.code||'retell_unavailable',message:e.status?e.message:'Service connection settings could not be saved.'});}};
 const providerKey=Symbol('serviceConnectionProvider');
 const provider=req=>req[providerKey];
 const route=(method,suffix,...handlers)=>{for(const provider of ['retell','elevenlabs'])app[method]('/api/ai-connections/'+provider+suffix,(req,_res,next)=>{req[providerKey]=provider;next();},...handlers);};
 const current=async(db,company,provider)=> (await db.query('SELECT * FROM retell_connections WHERE company_id=$1 AND provider=$2 AND NOT managed',[company,provider])).rows[0];
 const audit=(db,row,uid,operation)=>db.query("INSERT INTO retell_audit(connection_id,user_id,operation,outcome) VALUES($1,$2,$3,'success')",[row.id,uid,operation]);
 route('get','',authRequired,safe(async(req,res)=>{
  const row=await current(pool,req.companyId,provider(req)),configuration=configSchema.parse(Object.fromEntries(Object.entries(row?.config||(provider(req)==='elevenlabs'?{quotes_enabled:true}:{})).filter(([k])=>k!=='job_rules_hash')));
  const workers=(await pool.query('SELECT id,display_name FROM users WHERE company_id=$1 AND deleted_at IS NULL ORDER BY display_name LIMIT 200',[req.companyId])).rows;
  const services=(await pool.query('SELECT id,name FROM saved_services WHERE company_id=$1 AND archived_at IS NULL ORDER BY name LIMIT 500',[req.companyId])).rows;
  const pending=row?(await pool.query("SELECT id,payload,result,created_at FROM retell_requests WHERE connection_id=$1 AND reviewed_at IS NULL AND result->>'status'='pending_approval' ORDER BY created_at DESC LIMIT 50",[row.id])).rows:[];
  const calls=row?(await pool.query('SELECT call_id,state,error_code,created_at FROM retell_call_events WHERE connection_id=$1 ORDER BY created_at DESC LIMIT 30',[row.id])).rows:[];
  const activity=row?(await pool.query('SELECT operation,outcome,created_at FROM retell_audit WHERE connection_id=$1 ORDER BY id DESC LIMIT 30',[row.id])).rows:[];
  res.json({company_id:req.companyId,provider:provider(req),connection_name:provider(req)==='elevenlabs'?'Jack':'Riley',enabled:serviceEnabled(provider(req),env),mcp_url:env.MCP_PUBLIC_ORIGIN+'/mcp',webhook_url:provider(req)==='retell'?env.MCP_PUBLIC_ORIGIN+'/retell/webhook':null,revision:row?.revision||0,agent_id:row?.agent_id||'',webhook_key_configured:!!row?.webhook_secret,key_prefix:row?.key_prefix||null,expires_at:row?.expires_at||null,status:!row?.key_hash?'Not connected':row.revoked_at?'Revoked':new Date(row.expires_at)<=new Date()?'Expired':'Active',scopes:scopesFor({provider:provider(req),config:configuration}),config:configuration,missing_quote_rules:missingRules(configuration,'quote'),missing_job_rules:missingRules(configuration,'job'),workers,services,pending,calls,activity,outbound_calling_enabled:false});
 }));
 const guard=z.object({expected_company_id:z.uuid(),expected_revision:z.number().int().nonnegative()});
 async function mutate(req,work){return transaction(pool,async db=>{
  const input=guard.parse(req.body);if(input.expected_company_id!==req.companyId)throw fault(409,'account_changed');
  await lockCompanySchedule(db,req.companyId);
  // A session's owner role cannot be reused after ownership changes while it waits.
  if(!(await db.query('SELECT c.id FROM companies c JOIN users u ON u.id=c.owner_user_id AND u.company_id=c.id AND u.deleted_at IS NULL WHERE c.id=$1 AND c.owner_user_id=$2 FOR SHARE OF c,u',[req.companyId,req.userId])).rowCount)throw fault(403,'owner_required');
  let row=await current(db,req.companyId,provider(req));if((row?.revision||0)!==input.expected_revision)throw fault(409,'settings_changed');
  if(!row){if(app.locals.connectionManager)await lockConnectionSlot(db,req.companyId);row=(await db.query('INSERT INTO retell_connections(id,company_id,user_id,provider,config) VALUES($1,$2,$3,$4,$5) RETURNING *',[randomUUID(),req.companyId,req.userId,provider(req),JSON.stringify(provider(req)==='elevenlabs'?{quotes_enabled:true}:{})])).rows[0];}
  if(app.locals.connectionManager&&req.path.endsWith('/key')&&(row.revoked_at||(await db.query('SELECT revoked_at FROM mcp_connections WHERE id=$1',[row.id])).rows[0]?.revoked_at))await lockConnectionSlot(db,req.companyId);
  const result=await work(db,row);
  if(app.locals.connectionManager){
   await db.query(`INSERT INTO mcp_connections(id,user_id,company_id,client_id,scopes,audience,kind,name,provider,expires_at,revoked_at) SELECT id,user_id,company_id,'wolf-service','[]','service','service',CASE WHEN provider='elevenlabs' THEN 'Jack' ELSE 'Riley' END,provider,COALESCE(expires_at,now()),revoked_at FROM retell_connections WHERE id=$1 ON CONFLICT(id) DO UPDATE SET expires_at=EXCLUDED.expires_at,revoked_at=EXCLUDED.revoked_at,revision=mcp_connections.revision+1`,[row.id]);
   const updated=(await db.query('SELECT config FROM retell_connections WHERE id=$1',[row.id])).rows[0];
   const grant=(await db.query('SELECT * FROM mcp_connections WHERE id=$1',[row.id])).rows[0];
   await app.locals.connectionManager.initialize(db,grant);
   if(Boolean(updated.config.quotes_enabled)!==Boolean(row.config.quotes_enabled)){
    const names=['get_quote_context','get_quote_definitions','get_quote_draft','list_quote_options','calculate_quote','save_quote_draft','duplicate_quote_draft'];
    for(const name of names)await db.query("UPDATE mcp_connections SET tool_policy=jsonb_set(tool_policy,ARRAY[$2]::text[],$3::jsonb) WHERE id=$1",[row.id,name,JSON.stringify({allow:!!updated.config.quotes_enabled,approval:false})]);
   }
   await db.query("UPDATE mcp_approvals SET state='rejected',payload=NULL WHERE connection_id=$1 AND state='pending'",[row.id]);
  }
  await db.query('UPDATE retell_connections SET revision=revision+1,updated_at=now() WHERE id=$1',[row.id]);return result;
 });}
 route('put','',authRequired,safe(async(req,res)=>{
  const input=guard.extend({agent_id:z.string().max(150).default(''),webhook_api_key:z.string().min(8).max(500).optional(),config:configSchema}).strict().parse(req.body);
  res.json(await mutate(req,async(db,row)=>{
   const c=input.config;
   if(provider(req)==='elevenlabs'&&(input.agent_id||input.webhook_api_key))throw fault(400,'provider_credentials_not_supported');
   if(!/^(?:agent[-_][A-Za-z0-9_-]+)?$/.test(input.agent_id))throw fault(400,'invalid_agent_id');
   await validateBookingConfiguration(db,req.companyId,c);
   await db.query('UPDATE retell_connections SET agent_id=$2,webhook_secret=$3,config=$4 WHERE id=$1',[row.id,input.agent_id.trim()||null,input.webhook_api_key?encrypt(input.webhook_api_key,row.company_id,env):row.webhook_secret,JSON.stringify(c)]);
   await audit(db,row,req.userId,'settings.updated');return {saved:true};
  }));
 }));
 route('post','/key',authRequired,safe(async(req,res)=>{
  const input=guard.extend({valid_days:z.number().int().min(1).max(365)}).strict().parse(req.body);
  res.json(await mutate(req,async(db,row)=>{const key=newKey(provider(req));await db.query('UPDATE retell_connections SET key_hash=$2,key_prefix=$3,expires_at=now()+make_interval(days=>$4),revoked_at=NULL,user_id=$5 WHERE id=$1',[row.id,digest(key),key.slice(0,20),input.valid_days,req.userId]);await audit(db,row,req.userId,'key.rotated');return {key,shown_once:true};}));
 }));
 route('post','/revoke',authRequired,safe(async(req,res)=>{guard.strict().parse(req.body);res.json(await mutate(req,async(db,row)=>{await db.query('UPDATE retell_connections SET revoked_at=now() WHERE id=$1',[row.id]);await audit(db,row,req.userId,'connection.revoked');return {revoked:true};}));}));
 route('post','/requests/:id/reviewed',authRequired,safe(async(req,res)=>{const id=z.uuid().parse(req.params.id);guard.strict().parse(req.body);res.json(await mutate(req,async(db,row)=>{const r=await db.query('UPDATE retell_requests SET reviewed_at=now() WHERE id=$1 AND connection_id=$2 RETURNING id',[id,row.id]);if(!r.rowCount)throw fault(404,'request_unavailable');await audit(db,row,req.userId,'request.reviewed');return {reviewed:true};}));}));
 return {authenticate:token=>authenticateRetell(pool,token,env),accepts:token=>token?.startsWith(keyPrefix)||token?.startsWith(serviceKeyPrefix),scheduling,...webhook};
}
