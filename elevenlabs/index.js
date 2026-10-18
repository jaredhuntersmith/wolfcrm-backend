import {ElevenLabsClient} from '@elevenlabs/elevenlabs-js';
import {randomUUID} from 'node:crypto';
import {z} from 'zod';
import {installElevenLabsSchema} from './schema.js';
import {encrypt,decrypt,principal} from '../retell/security.js';
import {permit,rateLimit} from '../mcp/access.js';
import {digest,dispatch,fault,transaction} from '../mcp/context.js';
const sdk=new ElevenLabsClient({apiKey:'webhook-verification-only'});
const id=z.string().min(1).max(150), text=z.string().max(3000);
const eventSchema=z.object({type:z.enum(['post_call_transcription','call_initiation_failure']),event_timestamp:z.number().int().nonnegative(),data:z.object({
 agent_id:id,conversation_id:id,status:z.string().max(80).optional(),failure_reason:z.string().max(300).optional(),
 metadata:z.object({start_time_unix_secs:z.number().int().nonnegative().max(4102444800).optional(),call_duration_secs:z.number().int().min(0).max(86400).optional(),phone_call:z.object({direction:z.enum(['inbound','outbound']).optional(),external_number:z.string().max(40).optional(),agent_number:z.string().max(40).optional()}).nullable().optional()}).nullable().optional(),
 analysis:z.object({call_successful:z.string().max(80).optional(),transcript_summary:text.optional(),data_collection_results:z.record(z.string().max(100),z.unknown()).optional()}).nullable().optional(),
 conversation_initiation_client_data:z.object({dynamic_variables:z.object({lead_id:z.string().max(150).optional(),wolf_connection_id:z.string().max(150).optional()}).optional()}).optional()
})});
const fields=['call_outcome','customer_requests','services_requested','property_address','appointment_type','appointment_id','appointment_status','quote_id','quote_ids','call_summary'];
function extraction(data){const result={};for(const key of fields){let value=data?.[key]?.value;if(value===undefined)continue;if(typeof value==='string')result[key]=value.slice(0,key==='call_summary'?3000:1500);else if(Array.isArray(value))result[key]=value.filter(v=>typeof v==='string').slice(0,20).map(v=>v.slice(0,200));}return result;}
function compact(e){const d=e.data;return {type:e.type,agent_id:d.agent_id,conversation_id:d.conversation_id,lead_id:d.conversation_initiation_client_data?.dynamic_variables?.lead_id||null,connection_hint:d.conversation_initiation_client_data?.dynamic_variables?.wolf_connection_id||null,metadata:d.metadata||{},summary:d.analysis?.transcript_summary||'',reported:extraction(d.analysis?.data_collection_results),outcome:d.analysis?.call_successful||d.failure_reason||'unknown'};}
const reportCaps=['contacts.view','contacts.edit','customer.calls.view','quotes.view','schedule.view'];
const aad=r=>'elevenlabs:'+r.company_id+':'+r.connection_id;
export async function installElevenLabs({app,pool,authRequired,env,safe,mutate,audit,startWorker=true}){
 await installElevenLabsSchema(pool);
 const base='/api/ai-connections/manager/:id/elevenlabs';
 async function active(db,id){
  const sponsor=(await db.query('SELECT company_id,user_id FROM mcp_connections WHERE id=$1',[id])).rows[0];
  if(!sponsor)throw fault(403,'reporting_inactive');
  await db.query('SELECT id FROM companies WHERE id=$1 FOR SHARE',[sponsor.company_id]);
  await db.query('SELECT id FROM users WHERE id=$1 FOR SHARE',[sponsor.user_id]);
  await db.query('SELECT user_id FROM employee_permissions WHERE user_id=$1 FOR SHARE',[sponsor.user_id]);
  const r=(await db.query('SELECT r.*,g.name AS connection_name,g.enabled AS connection_enabled,g.paused_until,g.archived_at,g.expires_at AS grant_expires,g.revoked_at AS grant_revoked FROM elevenlabs_reporting r JOIN mcp_connections g ON g.id=r.connection_id WHERE r.connection_id=$1 FOR SHARE OF r,g',[id])).rows[0];
  if(!r||!r.enabled||!r.connection_enabled||new Date(r.grant_expires)<=new Date()||r.company_id!==sponsor.company_id||r.archived_at||r.grant_revoked||(r.paused_until&&new Date(r.paused_until)>new Date()))throw fault(403,'reporting_inactive');
  const service=(await db.query('SELECT * FROM retell_connections WHERE id=$1 FOR SHARE',[id])).rows[0];
  if(service?.user_id!==sponsor.user_id||service?.company_id!==sponsor.company_id)throw fault(403,'reporting_inactive');
  const actor=await principal(db,service,env);permit(actor,'crm:write',reportCaps);
  if(actor.companyId!==r.company_id)throw fault(403,'reporting_inactive');return {r,actor};
 }
 async function view(req){
  if(reportCaps.some(c=>!req.manager.permissions.capabilities[c]))throw fault(403,'permission_denied');
  const g=(await pool.query('SELECT id,kind,revision FROM mcp_connections WHERE id=$1 AND company_id=$2',[z.uuid().parse(req.params.id),req.companyId])).rows[0];if(!g||g.kind!=='service')throw fault(404,'connection_not_found');
  const r=(await pool.query('SELECT agent_id,enabled FROM elevenlabs_reporting WHERE connection_id=$1 AND company_id=$2',[g.id,req.companyId])).rows[0];
  const events=(await pool.query('SELECT id,conversation_id,event_type,state,error_code,attempts,created_at,completed_at,contact_id,phone_call_id,report FROM elevenlabs_call_events WHERE connection_id=$1 ORDER BY created_at DESC LIMIT 50',[g.id])).rows;
  return {connection_id:g.id,company_id:req.companyId,revision:g.revision,agent_id:r?.agent_id||'',enabled:r?.enabled||false,secret_configured:!!r,webhook_url:env.MCP_PUBLIC_ORIGIN+'/elevenlabs/webhook/'+g.id,events,outbound_calling_enabled:false};
 }
 app.get(base,authRequired,safe(async(req,res)=>res.json(await view(req))));
 app.put(base,authRequired,safe(async(req,res)=>{
  const i=z.object({expected_company_id:z.uuid(),expected_revision:z.number().int().positive(),agent_id:id,enabled:z.boolean(),webhook_secret:z.string().min(16).max(500).optional()}).strict().parse(req.body);
  res.json(await mutate(req,async(db,g)=>{
   if(g.kind!=='service'||g.revoked_at||g.archived_at)throw fault(409,'connection_inactive');
   const old=(await db.query('SELECT * FROM elevenlabs_reporting WHERE connection_id=$1',[g.id])).rows[0];
   if(!old&&!i.webhook_secret)throw fault(400,'webhook_secret_required');
   if(old?.agent_id!==i.agent_id&&old&&!i.webhook_secret)throw fault(400,'webhook_secret_required');
   if((await db.query('SELECT 1 FROM elevenlabs_reporting WHERE agent_id=$1 AND connection_id<>$2',[i.agent_id,g.id])).rowCount)throw fault(409,'agent_already_connected');
   const encrypted=i.webhook_secret?encrypt(i.webhook_secret,aad({company_id:g.company_id,connection_id:g.id}),env):old.secret_ciphertext;
   await db.query('INSERT INTO elevenlabs_reporting(connection_id,company_id,agent_id,enabled,secret_ciphertext) VALUES($1,$2,$3,$4,$5) ON CONFLICT(connection_id) DO UPDATE SET agent_id=$3,enabled=$4,secret_ciphertext=$5,updated_at=now()',[g.id,g.company_id,i.agent_id,i.enabled,encrypted]);
   await audit(db,g,'elevenlabs.reporting_configured','success',req.userId);return {saved:true};
  }));
 }));
 app.post(base+'/events/:event/retry',authRequired,safe(async(req,res)=>{
  res.json(await mutate(req,async(db,g)=>{
   await active(db,g.id);
   const event=(await db.query("UPDATE elevenlabs_call_events SET state='queued',attempts=0,error_code=NULL,next_attempt_at=now() WHERE id=$1 AND connection_id=$2 AND state IN ('review_required','blocked') RETURNING id",[z.uuid().parse(req.params.event),g.id])).rows[0];
   if(!event)throw fault(404,'report_unavailable');await audit(db,g,'elevenlabs.report_retry','success',req.userId);return {saved:true};
  }));
 }));
 app.post('/elevenlabs/webhook/:id',async(req,res)=>{
  res.set('Cache-Control','no-store');
  try{
   if(env.MCP_ENABLED!=='true'||env.MCP_SERVICE_KEYS_ENABLED==='false')throw fault(503,'reporting_disabled');
   const connectionId=z.uuid().parse(req.params.id);
   if(!Buffer.isBuffer(req.body))throw fault(415,'raw_json_required');
   const cfg=(await pool.query('SELECT * FROM elevenlabs_reporting WHERE connection_id=$1',[connectionId])).rows[0];if(!cfg)throw fault(401,'invalid_signature');
   const signature=req.get('elevenlabs-signature');if(!signature||signature.length>300)throw fault(401,'invalid_signature');
   // SDK checks old timestamps; also reject malformed/future values before its verifier.
   const timestamp=/^t=(\d+)(?:,|$)/.exec(signature)?.[1];if(!timestamp||Number(timestamp)>Date.now()/1000+60)throw fault(401,'invalid_signature');
   let verified;try{verified=await sdk.webhooks.constructEvent(req.body.toString('utf8'),signature,decrypt(cfg.secret_ciphertext,aad(cfg),env));}catch{throw fault(401,'invalid_signature');}
   if(verified.type==='post_call_audio')return res.status(200).json({ignored:true});
   const payload=compact(eventSchema.parse(verified));
   if(payload.agent_id!==cfg.agent_id||(payload.connection_hint&&payload.connection_hint!==connectionId))throw fault(403,'agent_mismatch');
   await transaction(pool,async db=>{
    await db.query("SET LOCAL statement_timeout='3s'; SET LOCAL lock_timeout='2s'");
    const {r}=await active(db,connectionId);if(r.secret_ciphertext!==cfg.secret_ciphertext||r.agent_id!==cfg.agent_id)throw fault(401,'invalid_signature');
    const hash=digest(payload),existing=(await db.query('SELECT connection_id,input_hash FROM elevenlabs_call_events WHERE conversation_id=$1 AND event_type=$2',[payload.conversation_id,payload.type])).rows[0];
    if(existing){if(existing.connection_id!==connectionId||existing.input_hash!==hash)throw fault(409,'event_conflict');return;}
    await rateLimit(db,'elevenlabs-inbox:'+connectionId,120);
    if((await db.query("SELECT 1 FROM elevenlabs_call_events WHERE connection_id=$1 AND state<>'completed' OFFSET 999 LIMIT 1",[connectionId])).rowCount)throw fault(429,'report_queue_full');
    await db.query('INSERT INTO elevenlabs_call_events(id,connection_id,conversation_id,event_type,input_hash,payload) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(conversation_id,event_type) DO NOTHING',[randomUUID(),connectionId,payload.conversation_id,payload.type,hash,JSON.stringify(payload)]);
    const saved=(await db.query('SELECT connection_id,input_hash FROM elevenlabs_call_events WHERE conversation_id=$1 AND event_type=$2',[payload.conversation_id,payload.type])).rows[0];if(saved.connection_id!==connectionId||saved.input_hash!==hash)throw fault(409,'event_conflict');
   });res.status(200).json({accepted:true});
  }catch(e){res.status(e instanceof z.ZodError?400:e.status||503).json({error:e instanceof z.ZodError?'invalid_event':e.status?e.code:'reporting_unavailable'});}
 });
 async function processOne(){return transaction(pool,async db=>{
  const event=(await db.query("SELECT * FROM elevenlabs_call_events WHERE state='queued' AND next_attempt_at<=now() ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED")).rows[0];if(!event)return false;
  try{await transaction(pool,async work=>{
   const {r,actor}=await active(work,event.connection_id),call=event.payload;
   if(r.agent_id!==call.agent_id)throw fault(403,'agent_changed');
   if(!z.uuid().safeParse(call.lead_id).success)throw fault(400,'lead_unavailable');
   const customer=(await work.query("SELECT * FROM contacts WHERE id=$1 AND company_id=$2 AND to_jsonb(contacts)->>'deleted_at' IS NULL FOR UPDATE",[call.lead_id,actor.companyId])).rows[0];if(!customer)throw fault(404,'lead_unavailable');
   const history=Array.isArray(customer.lead_info)?customer.lead_info:[];if(history.length>=1000)throw fault(409,'lead_history_review_required');
   const reported=call.reported,ids=[reported.quote_id,...(Array.isArray(reported.quote_ids)?reported.quote_ids:typeof reported.quote_ids==='string'?reported.quote_ids.split(',').map(s=>s.trim()):[])].filter(v=>z.uuid().safeParse(v).success).slice(0,20);
   const quotes=(await work.query('SELECT id,title,status,sent_at,accepted_at,calculation_revision FROM quotes WHERE company_id=$1 AND contact_id=$2 AND deleted_at IS NULL AND id=ANY($3::uuid[]) FOR SHARE',[actor.companyId,customer.id,ids])).rows;
   const claimedAppointment=z.uuid().safeParse(reported.appointment_id).success?reported.appointment_id:null;
   const receipts=(await work.query(`SELECT result FROM retell_requests WHERE connection_id=$1 AND (request_key=$2 OR left(request_key,length($2)+1)=$2||':' OR ($3::text IS NOT NULL AND result->>'appointment_id'=$3)) ORDER BY created_at DESC LIMIT 20`,[r.connection_id,event.conversation_id,claimedAppointment])).rows;
   const confirmed=receipts.filter(x=>x.result.status==='confirmed'&&z.uuid().safeParse(x.result.appointment_id).success).map(x=>x.result.appointment_id);
   const appointments=(await work.query('SELECT id,start_at,end_at,quote_id FROM schedule_events WHERE company_id=$1 AND contact_id=$2 AND id=ANY($3::text[]) FOR SHARE',[actor.companyId,customer.id,confirmed])).rows;
   const report={verified_at:new Date().toISOString(),content_trust:'untrusted_caller_and_agent_text',connection_id:r.connection_id,conversation_id:event.conversation_id,contact_id:customer.id,reported_outcome:reported.call_outcome||call.outcome,summary:reported.call_summary||call.summary,customer_requests:reported.customer_requests||reported.services_requested||null,reported,verified_quotes:quotes,verified_appointments:appointments,appointment_status:appointments.length?'confirmed':receipts.some(x=>x.result.status==='pending_approval')?'pending_approval':'unverified'};
   const m=call.metadata,started=m.start_time_unix_secs?new Date(m.start_time_unix_secs*1000):event.created_at,duration=m.call_duration_secs??null,phone=m.phone_call||{};
   // Web/preview conversations have no phone metadata. Label their transport accurately.
   const description=[`${r.connection_name} / ElevenLabs conversation ${event.conversation_id}`,`Connection: ${r.connection_id}`,`Reported outcome (unverified): ${report.reported_outcome}`,`Summary (untrusted caller/AI text): ${report.summary}`,`Customer requests (untrusted): ${Array.isArray(report.customer_requests)?report.customer_requests.join(', '):report.customer_requests||'Not provided'}`,`CRM verification at ${report.verified_at}:`,...quotes.map(q=>`Quote ${q.id} — ${q.title||'Quote'}: ${q.status||'saved'}; ${q.sent_at?'recorded sent '+new Date(q.sent_at).toISOString():'no recorded send'}`),...appointments.map(a=>`Appointment ${a.id}: ${new Date(a.start_at).toISOString()} to ${new Date(a.end_at).toISOString()}`),`Booking result: ${report.appointment_status}. Agent statements do not establish booking or delivery.`].join('\n');
   const saved=(await work.query(`INSERT INTO phone_calls(company_id,contact_id,direction,from_number,to_number,status,started_at,ended_at,duration_seconds,disposition,provider,provider_call_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'elevenlabs',$11) ON CONFLICT(company_id,provider,provider_call_id) WHERE provider_call_id IS NOT NULL DO NOTHING RETURNING id`,[actor.companyId,customer.id,phone.direction||'inbound',phone.direction==='outbound'?phone.agent_number||null:phone.external_number||null,phone.direction==='outbound'?phone.external_number||null:phone.agent_number||null,call.type==='call_initiation_failure'?'failed':'completed',started,duration===null?null:new Date(started.getTime()+duration*1000),duration,description,event.conversation_id])).rows[0];
   if(!saved)throw fault(409,'conversation_already_recorded');
   await dispatch(app,actor,'PUT','/api/contacts/'+customer.id,{lead_info:[...history,description]});
   await work.query("INSERT INTO mcp_audit(connection_id,company_id,user_id,operation,record_id,outcome) VALUES($1,$2,$3,'elevenlabs.call_report',$4,'success')",[r.connection_id,actor.companyId,actor.userId,saved.id]);
   await work.query("UPDATE elevenlabs_call_events SET state='completed',report=$2,contact_id=$3,phone_call_id=$4,completed_at=now(),error_code=NULL,payload='{}' WHERE id=$1",[event.id,JSON.stringify(report),customer.id,saved.id]);
  });}catch(e){const code=e.status?e.code:'processing_unavailable';await db.query("UPDATE elevenlabs_call_events SET attempts=attempts+1,error_code=$2,state=CASE WHEN $3 THEN 'blocked' WHEN attempts>=4 OR $2 IN ('lead_unavailable','lead_history_review_required','conversation_already_recorded','agent_changed') THEN 'review_required' ELSE 'queued' END,next_attempt_at=now()+interval '1 minute' WHERE id=$1",[event.id,code,[401,403].includes(e.status)]);}
  return true;
 });}
 let running=false;async function drain(){if(running)return;running=true;try{await pool.query("UPDATE elevenlabs_call_events SET state='expired',payload='{}',error_code='report_retention_expired' WHERE state NOT IN ('completed','expired') AND created_at<now()-interval '30 days'");for(let i=0;i<20&&await processOne();i++);}finally{running=false;}}
 if(startWorker){const timer=setInterval(()=>drain().catch(()=>console.warn('[elevenlabs] reporting retry deferred')),5000);timer.unref();}
 const api={drain};app.locals.elevenlabsReporting=api;return api;
}
