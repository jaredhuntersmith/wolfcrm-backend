import {randomUUID} from 'node:crypto';
import {z} from 'zod';
import {bookingSlotFits,eligibleBookingBundles} from '../agreement-booking.js';
import {scheduleConflict,lockCompanySchedule} from '../schedule-booking-guard.js';
import {digest,dispatch,fault,transaction} from '../mcp/context.js';
import {principal} from './security.js';
import {readConfig,normalizeText,offsetISO} from './config.js';
import {evaluateEligibility,loadLead} from './eligibility.js';
const address=z.string().trim().min(5).max(500);
const services=z.array(z.string().trim().min(1).max(120)).max(30).default([]);
const range=z.object({start:z.iso.datetime({offset:true}),end:z.iso.datetime({offset:true})}).strict().refine(v=>Date.parse(v.end)>Date.parse(v.start)&&Date.parse(v.end)-Date.parse(v.start)<=14*86400000,'Request a date range of at most 14 days.');
const facts={services,stories:z.number().int().min(1).max(100).optional(),window_count:z.number().int().min(0).max(100000).optional(),property_type:z.enum(['residential','commercial']).optional(),lead_id:z.uuid().optional(),agreement_id:z.uuid().optional()};
export const quoteInput=z.object({address,preferred_date_range:range,...facts}).strict();
export const jobInput=quoteInput;
export const bookingInput=z.object({type:z.enum(['quote','job']),slot_id:z.uuid().optional(),customer:z.object({name:z.string().trim().min(1).max(200),phone:z.string().min(7).max(40),email:z.email().optional()}).strict(),address,...facts,notes:z.string().max(2000).default(''),idempotency_key:z.string().min(1).max(150)}).strict();
export const eligibilitySchema=z.object({quote_visit:z.object({eligible:z.boolean(),reason:z.string().nullable(),configuration_required:z.array(z.string())}),direct_job:z.object({eligible:z.boolean(),reason:z.string().nullable(),configuration_required:z.array(z.string())}),recommended_path:z.enum(['quote','job','none']),requires_quote_acceptance:z.boolean().nullable(),requires_deposit:z.boolean().nullable(),configuration_required:z.array(z.string())});
const slotOutput=z.object({slot_id:z.uuid(),start:z.string(),end:z.string(),assigned_workers:z.array(z.string())});
export const availabilityOutput=z.object({status:z.enum(['available','unavailable','configuration_required']),eligibility:eligibilitySchema,in_service_area:z.boolean(),slots:z.array(slotOutput).max(30),timezone:z.literal('America/New_York'),booking_enabled:z.boolean(),reason:z.string().optional(),estimated_duration_min:z.number().nullable().optional(),requires_quote_acceptance:z.boolean().nullable().optional(),requires_deposit:z.boolean().nullable().optional(),deposit_status:z.string().optional()});
export const bookingOutput=z.object({status:z.enum(['confirmed','pending_approval','failed']),eligibility:eligibilitySchema.optional(),request_id:z.uuid().optional(),appointment_id:z.string().optional(),start:z.string().optional(),end:z.string().optional(),assigned_workers:z.array(z.string()).optional(),reason:z.string().optional()});
const sameServices=(a,b)=>JSON.stringify(a.map(normalizeText).sort())===JSON.stringify(b.map(normalizeText).sort());
const phone=s=>String(s||'').replace(/\D/g,'').replace(/^1(?=\d{10}$)/,'');
export function createRetellScheduling({app,pool,env,now=()=>new Date()}){
 async function quoteContext(db,actor){
  const c=readConfig(actor.retell.config);
  const members=(await db.query('SELECT id FROM users WHERE company_id=$1 AND deleted_at IS NULL',[actor.companyId])).rows;
  if(c.quote_worker_ids.some(id=>!members.some(m=>m.id===id)))throw fault(409,'quote_workers_changed');
  const availability=(await db.query('SELECT * FROM employee_schedule_availability WHERE company_id=$1',[actor.companyId])).rows;
  const events=(await db.query('SELECT id,start_at,end_at,worker_user_ids,booking_buffer_before_minutes,booking_buffer_after_minutes FROM schedule_events WHERE company_id=$1 AND end_at>=$2 AND start_at<=$3 LIMIT 10001',[actor.companyId,new Date(now().getTime()-86400000),new Date(now().getTime()+(c.horizon_days+2)*86400000)])).rows;
  if(events.length>10000)throw fault(503,'calendar_too_large');
  return {settings:c,bundle:{worker_user_ids:c.quote_worker_ids},companyAvailability:{weekdays:c.quote_weekdays,start_time:c.quote_start,end_time:c.quote_end},availability:Object.fromEntries(availability.map(v=>[v.user_id,v])),events,zone:'America/New_York',now:now(),duration:c.quote_duration_minutes};
 }
 async function availability(actor,type,input){
  const evaluation=await evaluateEligibility({db:pool,app,actor,input}),c=evaluation.config,path=type==='job'?evaluation.eligibility.direct_job:evaluation.eligibility.quote_visit;
  const out={status:'unavailable',eligibility:evaluation.eligibility,in_service_area:evaluation.inside,slots:[],timezone:'America/New_York',booking_enabled:false,estimated_duration_min:type==='job'?evaluation.duration:c.quote_duration_minutes,requires_quote_acceptance:evaluation.eligibility.requires_quote_acceptance,requires_deposit:evaluation.eligibility.requires_deposit,deposit_status:evaluation.state?.deposit||'unknown'};
  if(!path.eligible)return {...out,status:path.reason==='configuration_required'?'configuration_required':'unavailable',reason:path.reason};
  const ctx=type==='job'?evaluation.jobContext:await quoteContext(pool,actor),duration=type==='job'?evaluation.duration:ctx.duration;
  const begin=Math.max(Date.parse(input.preferred_date_range.start),now().getTime()),end=Date.parse(input.preferred_date_range.end),candidates=[];
  const bundles=type==='job'?eligibleBookingBundles(ctx.settings,evaluation.lineItems,ctx.activeIDs).sort((a,b)=>a.id.localeCompare(b.id)):[ctx.bundle];
  if(type==='job'&&evaluation.row){
   const available=await app.locals.agreementBooking.availability(app.locals.agreements.makeToken(evaluation.row),{start_date:offsetISO(input.preferred_date_range.start).slice(0,10)});
   for(const slot of available.slots){const start=Date.parse(slot.start_at);if(start<begin||start+duration*60000>end)continue;const bundle=bundles.find(bundle=>bookingSlotFits({...ctx,bundle,start:slot.start_at,duration,now:now()}));if(bundle)candidates.push({start:slot.start_at,end:new Date(start+duration*60000).toISOString(),workers:bundle.worker_user_ids,canonical_slot:slot.slot_token,agreement_id:evaluation.row.id,packet_hash:evaluation.row.packet_hash});if(candidates.length===30)break;}
  }else for(let stamp=Math.ceil(begin/300000)*300000;stamp+duration*60000<=end&&candidates.length<30;stamp+=300000){const bundle=bundles.find(bundle=>bookingSlotFits({...ctx,bundle,start:new Date(stamp),duration,now:now()}));if(bundle)candidates.push({start:new Date(stamp).toISOString(),end:new Date(stamp+duration*60000).toISOString(),workers:bundle.worker_user_ids,profile_id:evaluation.profile?.id||null});}
  await pool.query('DELETE FROM retell_slots WHERE expires_at<now() AND connection_id=$1',[actor.retell.id]);
  for(const candidate of candidates){const id=randomUUID(),publicSlot={slot_id:id,start:offsetISO(candidate.start),end:offsetISO(candidate.end),assigned_workers:candidate.workers};if(JSON.stringify({...out,slots:[...out.slots,publicSlot]}).length>6000)break;await pool.query("INSERT INTO retell_slots(id,connection_id,revision,payload,expires_at) VALUES($1,$2,$3,$4,now()+interval '15 minutes')",[id,actor.retell.id,actor.retell.revision,JSON.stringify({...candidate,type,address:input.address,services:input.services||[],lead_id:input.lead_id||null,facts:{stories:input.stories,window_count:input.window_count,property_type:input.property_type}})]);out.slots.push(publicSlot);}
  out.booking_enabled=true;out.status=out.slots.length?'available':'unavailable';if(!out.slots.length)out.reason='no_available_slots_in_range';return out;
 }
 async function book(actor,input){return transaction(pool,async db=>{
  // Same ordering as all calendar writers. Configuration/revocation also takes this lock.
  await lockCompanySchedule(db,actor.companyId);
  const row=(await db.query('SELECT * FROM retell_connections WHERE id=$1 FOR UPDATE',[actor.retell.id])).rows[0];
  await db.query('SELECT id FROM companies WHERE id=$1 FOR SHARE',[actor.companyId]);
  await db.query('SELECT id FROM users WHERE id=$1 FOR SHARE',[actor.userId]);
  if(row.key_hash!==actor.retell.key_hash)throw fault(401,'service_key_rotated');
  actor=await principal(db,row,env);
  const old=(await db.query('SELECT * FROM retell_requests WHERE connection_id=$1 AND request_key=$2',[row.id,input.idempotency_key])).rows[0],hash=digest(input);
  if(old){if(old.input_hash!==hash)throw fault(409,'idempotency_conflict');return old.result;}
  const requestID=randomUUID();
  const save=async result=>{result.request_id=requestID;await db.query('INSERT INTO retell_requests(id,connection_id,request_key,input_hash,payload,result) VALUES($1,$2,$3,$4,$5,$6)',[requestID,row.id,input.idempotency_key,hash,JSON.stringify(input),JSON.stringify(result)]);return result;};
  let customer=input.lead_id?await loadLead(db,actor,input.lead_id):null;
  if(customer&&phone(customer.phone)!==phone(input.customer.phone))throw fault(409,'customer_phone_mismatch');
  const c=readConfig(row.config);
  const slot=input.slot_id?(await db.query('SELECT * FROM retell_slots WHERE id=$1 AND connection_id=$2',[input.slot_id,row.id])).rows[0]:null;
  const s=slot?.payload;
  if(input.slot_id&&(!slot||slot.revision!==row.revision||new Date(slot.expires_at)<=now()||s.type!==input.type||normalizeText(s.address)!==normalizeText(input.address)||s.lead_id!==(input.lead_id||null)||!sameServices(s.services,input.services)||['stories','window_count','property_type'].some(k=>input[k]!==undefined&&input[k]!==s.facts?.[k])))return save({status:'failed',reason:'Slot or request changed. Check availability again.'});
  const evaluation=await evaluateEligibility({db,app,actor,input:{...s?.facts,...input,agreement_id:s?.agreement_id||input.agreement_id}}),eligibility=evaluation.eligibility,path=input.type==='job'?eligibility.direct_job:eligibility.quote_visit;
  if(!path.eligible)return save({status:path.reason==='configuration_required'||!evaluation.inside||path.reason?.endsWith('_disabled')?'failed':'pending_approval',eligibility,reason:path.reason==='configuration_required'?'configuration_required: '+(input.type==='job'?evaluation.jobMissing:evaluation.quoteMissing).join(', '):path.reason});
  if(!c.automatic_booking)return save({status:'pending_approval',eligibility,reason:'Riley automatic booking has not been authorized. No appointment is reserved.'});
  if(!s)return save({status:'failed',eligibility,reason:'Check availability and supply an eligible slot. No appointment is reserved.'});
  try{return await transaction(pool,async()=>{
  let appointment;
  if(input.type==='job'&&evaluation.row){
   if(evaluation.row.packet_hash!==s.packet_hash)return save({status:'failed',eligibility,reason:'The agreement changed. Check availability again.'});
   const result=await app.locals.agreementBooking.book(app.locals.agreements.makeToken(evaluation.row),{request_id:requestID,slot_token:s.canonical_slot});
   await dispatch(app,actor,'POST',`/api/schedule/customer-bookings/${result.booking.booking_id}/confirm`,{review_version:1});
   appointment=result.booking.job_id;
  }else{
   const ctx=input.type==='job'?evaluation.jobContext:await quoteContext(db,actor),duration=input.type==='job'?evaluation.duration:ctx.duration;
   const bundle=input.type==='job'?eligibleBookingBundles(ctx.settings,evaluation.lineItems,ctx.activeIDs).find(b=>sameServices(b.worker_user_ids,s.workers)):ctx.bundle;
   if(!bundle||input.type==='job'&&evaluation.profile?.id!==s.profile_id||!bookingSlotFits({...ctx,bundle,duration,start:s.start,now:now()}))return save({status:'failed',eligibility,reason:'The slot was taken or eligibility changed. Check availability again.'});
   if(!customer){
    const matches=(await db.query("SELECT * FROM contacts WHERE company_id=$1 AND regexp_replace(COALESCE(phone,''),'[^0-9]','','g')=ANY($2::text[]) LIMIT 2",[actor.companyId,[phone(input.customer.phone),'1'+phone(input.customer.phone)]])).rows;
    if(matches.length>1)return save({status:'pending_approval',reason:'Multiple matching customers need business review.'});
    customer=matches[0]||await dispatch(app,actor,'POST','/api/contacts',{...input.customer,address:input.address,source:'retell'});
   }
   appointment=randomUUID();
   await dispatch(app,actor,'PUT','/api/schedule/'+appointment,{title:(input.type==='job'?'Job — ':'Quote visit — ')+input.customer.name,start:s.start,end:s.end,contact_id:customer.id,worker_user_ids:s.workers,sales_user_ids:[],notes:[input.address,input.notes].filter(Boolean).join('\n'),services:evaluation.lineItems?.map(l=>l.name)||input.services});
   await db.query('UPDATE schedule_events SET booking_buffer_before_minutes=$2,booking_buffer_after_minutes=$3 WHERE id=$1 AND company_id=$4',[appointment,ctx.settings.buffer_before_minutes,ctx.settings.buffer_after_minutes,actor.companyId]);
  }
  return save({status:'confirmed',eligibility,appointment_id:appointment,start:offsetISO(s.start),end:offsetISO(s.end),assigned_workers:s.workers});
  });}catch(e){if(e.status===409||scheduleConflict(e))return save({status:'failed',reason:'The slot, agreement or booking rules changed. Check availability again.'});throw e;}
 });}
 return {availability,book};
}
