import {randomUUID} from 'node:crypto';
import {Retell} from 'retell-sdk';
import {z} from 'zod';
import {decrypt,principal} from './security.js';
import {dispatch,transaction,fault} from '../mcp/context.js';
import {lockCompanySchedule} from '../schedule-booking-guard.js';
const short=z.string().max(500).optional(),summary=z.string().max(3000).optional();
const analysis=z.object({call_outcome:short,services_requested:z.union([z.string().max(1500),z.array(z.string().max(120)).max(30)]).optional(),property_address:short,appointment_type:short,appointment_id:short,appointment_start:short,appointment_status:short,call_summary:summary});
const eventSchema=z.object({event:z.string(),call:z.object({call_id:z.string().min(1).max(150),agent_id:z.string().min(1).max(150),direction:z.enum(['inbound','outbound']).optional(),from_number:z.string().max(40).optional(),to_number:z.string().max(40).optional(),start_timestamp:z.number().int().nonnegative().max(8640000000000000).optional(),end_timestamp:z.number().int().nonnegative().max(8640000000000000).optional(),retell_llm_dynamic_variables:z.object({lead_id:z.string().max(150).optional()}).optional(),call_analysis:z.object({custom_analysis_data:analysis.optional()}).optional()})});
export function installRetellWebhook({app,pool,env,startWorker=true}){
 app.post('/retell/webhook',async(req,res)=>{
  res.set('Cache-Control','no-store');
  try{
   if(env.RETELL_ENABLED!=='true')throw fault(503,'retell_disabled');
   if(!Buffer.isBuffer(req.body))throw fault(415,'raw_json_required');
   const raw=req.body.toString('utf8');let parsed;try{parsed=JSON.parse(raw);}catch{throw fault(400,'invalid_json');}
   const agent=parsed?.call?.agent_id;if(typeof agent!=='string'||agent.length>150)throw fault(401,'invalid_signature');
   const connection=(await pool.query('SELECT * FROM retell_connections WHERE agent_id=$1',[agent])).rows[0];
   if(!connection?.webhook_secret)throw fault(401,'invalid_signature');
   const signature=req.get('x-retell-signature');
   if(!signature||signature.length>250||!await Retell.verify(raw,decrypt(connection.webhook_secret,connection.company_id,env),signature))throw fault(401,'invalid_signature');
   const event=eventSchema.parse(parsed);
   if(event.event!=='call_analyzed')return res.status(204).end();
   await transaction(pool,async db=>{
    await db.query("SET LOCAL statement_timeout='3s'; SET LOCAL lock_timeout='2s'");
    const current=(await db.query('SELECT * FROM retell_connections WHERE id=$1 FOR SHARE',[connection.id])).rows[0];
    if(current.webhook_secret!==connection.webhook_secret||current.agent_id!==agent)throw fault(401,'invalid_signature');
    await principal(db,current,env);
    await db.query('INSERT INTO retell_call_events(id,connection_id,call_id,payload) VALUES($1,$2,$3,$4) ON CONFLICT(connection_id,call_id) DO NOTHING',[randomUUID(),connection.id,event.call.call_id,JSON.stringify(event.call)]);
   });
   res.status(202).json({accepted:true});
  }catch(e){res.status(e instanceof z.ZodError?400:e.status||503).json({error:e instanceof z.ZodError?'invalid_event':e.status?e.code:'webhook_unavailable'});}
 });
 async function processOne(){return transaction(pool,async db=>{
  const event=(await db.query("SELECT * FROM retell_call_events WHERE state='queued' AND next_attempt_at<=now() ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED")).rows[0];if(!event)return false;
  const connection=(await db.query('SELECT * FROM retell_connections WHERE id=$1',[event.connection_id])).rows[0];
  await lockCompanySchedule(db,connection.company_id);
  await db.query('SELECT id FROM companies WHERE id=$1 FOR SHARE',[connection.company_id]);
  await db.query('SELECT id FROM users WHERE id=$1 FOR SHARE',[connection.user_id]);
  let actor;try{actor=await principal(db,(await db.query('SELECT * FROM retell_connections WHERE id=$1 FOR SHARE',[connection.id])).rows[0],env);}catch(e){await db.query("UPDATE retell_call_events SET state='blocked',error_code=$2 WHERE id=$1",[event.id,e.code||'connection_inactive']);return true;}
  try{await transaction(pool,async work=>{
   const call=event.payload,leadID=call.retell_llm_dynamic_variables?.lead_id;
   let customer=null;if(leadID){if(!z.uuid().safeParse(leadID).success)throw fault(400,'lead_unavailable');customer=(await work.query('SELECT * FROM contacts WHERE id=$1 AND company_id=$2 FOR UPDATE',[leadID,actor.companyId])).rows[0];if(!customer)throw fault(404,'lead_unavailable');}
   const data=call.call_analysis?.custom_analysis_data||{};
   const request=(await work.query('SELECT result FROM retell_requests WHERE connection_id=$1 AND request_key=$2',[connection.id,call.call_id])).rows[0];
   let appointmentStatus='unverified';
   if(request){appointmentStatus=request.result.status;if(appointmentStatus==='confirmed'){const exists=(await work.query('SELECT id FROM schedule_events WHERE id=$1 AND company_id=$2',[request.result.appointment_id,actor.companyId])).rowCount;appointmentStatus=exists?'confirmed':'no_longer_scheduled';}}
   const report={...data,reported_appointment_status:data.appointment_status||null,appointment_status:appointmentStatus,appointment_id:request?.result.appointment_id||null,call_id:call.call_id};
   const started=call.start_timestamp?new Date(call.start_timestamp):event.created_at,ended=call.end_timestamp?new Date(call.end_timestamp):null;
   await work.query(`INSERT INTO phone_calls(company_id,contact_id,direction,from_number,to_number,status,started_at,ended_at,duration_seconds,disposition,provider,provider_call_id)
    VALUES($1,$2,$3,$4,$5,'completed',$6,$7,$8,$9,'retell',$10) ON CONFLICT(company_id,provider,provider_call_id) WHERE provider_call_id IS NOT NULL DO NOTHING`,[actor.companyId,customer?.id||null,call.direction||'inbound',call.from_number||null,call.to_number||null,started,ended,ended?Math.max(0,Math.min(86400,Math.round((ended-started)/1000))):null,JSON.stringify(report),call.call_id]);
   if(customer){const history=Array.isArray(customer.lead_info)?customer.lead_info:[];
    if(history.length>=1000)throw fault(409,'lead_history_review_required');
    await dispatch(app,actor,'PUT','/api/contacts/'+customer.id,{lead_info:[...history,'Riley call result (untrusted caller/AI text): '+JSON.stringify(report)]});
   }
   await work.query("INSERT INTO retell_audit(connection_id,user_id,operation,outcome) VALUES($1,$2,'call_analyzed','success')",[connection.id,actor.userId]);
   await work.query("UPDATE retell_call_events SET state='completed',completed_at=now(),payload='{}' WHERE id=$1",[event.id]);
  });}catch(e){await db.query("UPDATE retell_call_events SET attempts=attempts+1,state=CASE WHEN attempts>=4 OR $2 IN ('lead_unavailable','lead_history_review_required') THEN 'review_required' ELSE 'queued' END,error_code=$2,next_attempt_at=now()+interval '1 minute' WHERE id=$1",[event.id,e.status?e.code:'processing_unavailable']);}
  return true;
 });}
 let running=false;
 async function drain(){if(running)return;running=true;try{for(let i=0;i<20&&await processOne();i++);}finally{running=false;}}
 if(startWorker){const timer=setInterval(()=>drain().catch(()=>console.warn('[retell] reporting retry deferred')),5000);timer.unref();}
 return {drain};
}
