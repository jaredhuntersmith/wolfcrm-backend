import {randomUUID} from 'node:crypto';
import {z} from 'zod';
import {bookingSlotFits,eligibleBookingBundles} from '../agreement-booking.js';
import {scheduleConflict,lockCompanySchedule} from '../schedule-booking-guard.js';
import {digest,dispatch,fault,transaction} from '../mcp/context.js';
import {principal} from './security.js';
import {configSchema,missingRules,inServiceArea,normalizeText,offsetISO} from './config.js';
const address=z.string().trim().min(5).max(500);
const services=z.array(z.string().trim().min(1).max(120)).max(30).default([]);
const range=z.object({start:z.iso.datetime({offset:true}),end:z.iso.datetime({offset:true})}).strict().refine(v=>Date.parse(v.end)>Date.parse(v.start)&&Date.parse(v.end)-Date.parse(v.start)<=14*86400000,'Request a date range of at most 14 days.');
export const quoteInput=z.object({address,preferred_date_range:range}).strict();
export const jobInput=z.object({address,services,stories:z.number().int().min(1).max(100).optional(),window_count:z.number().int().min(0).max(100000).optional(),property_type:z.enum(['residential','commercial']).optional(),preferred_date_range:range,lead_id:z.uuid().optional(),agreement_id:z.uuid().optional()}).strict();
export const bookingInput=z.object({type:z.enum(['quote','job']),slot_id:z.uuid().optional(),customer:z.object({name:z.string().trim().min(1).max(200),phone:z.string().min(7).max(40),email:z.email().optional()}).strict(),address,services,notes:z.string().max(2000).default(''),lead_id:z.uuid().optional(),idempotency_key:z.string().min(1).max(150)}).strict();
const slotOutput=z.object({slot_id:z.uuid(),start:z.string(),end:z.string(),assigned_workers:z.array(z.string())});
export const availabilityOutput=z.object({in_service_area:z.boolean(),slots:z.array(slotOutput).max(30),timezone:z.literal('America/New_York'),booking_enabled:z.boolean(),reason:z.string().optional(),estimated_duration_min:z.number().nullable().optional(),requires_quote_acceptance:z.boolean().optional(),requires_deposit:z.boolean().optional(),deposit_status:z.string().optional()});
export const bookingOutput=z.object({status:z.enum(['confirmed','pending_approval','failed']),request_id:z.uuid().optional(),appointment_id:z.string().optional(),start:z.string().optional(),end:z.string().optional(),assigned_workers:z.array(z.string()).optional(),reason:z.string().optional()});
const sameServices=(a,b)=>JSON.stringify(a.map(normalizeText).sort())===JSON.stringify(b.map(normalizeText).sort());
const phone=s=>String(s||'').replace(/\D/g,'').replace(/^1(?=\d{10}$)/,'');
export function createRetellScheduling({app,pool,env,now=()=>new Date()}){
 async function contact(db,actor,id){const row=(await db.query('SELECT * FROM contacts WHERE id=$1 AND company_id=$2',[id,actor.companyId])).rows[0];if(!row)throw fault(404,'lead_unavailable');return row;}
 async function agreement(db,actor,input){
  if(!input.lead_id)return null;
  const customer=await contact(db,actor,input.lead_id);
  if(normalizeText(customer.address||'')!==normalizeText(input.address))return null;
  const rows=(await db.query(`SELECT * FROM quote_agreements WHERE company_id=$1 AND contact_id=$2 AND revoked_at IS NULL AND ($3::uuid IS NULL OR id=$3) ORDER BY created_at DESC LIMIT 20`,[actor.companyId,input.lead_id,input.agreement_id||null])).rows;
  for(const row of rows){
   if(!sameServices(input.services,row.snapshot.pricing?.line_items?.map(l=>l.name)||[]))continue;
   const latest=(await db.query('SELECT id FROM quote_agreements WHERE company_id=$1 AND quote_id=$2 AND revoked_at IS NULL ORDER BY revision DESC LIMIT 1',[actor.companyId,row.quote_id])).rows[0];
   if(latest?.id===row.id)return row;
  }return null;
 }
 async function quoteContext(db,actor){
  const c=configSchema.parse(Object.fromEntries(Object.entries(actor.retell.config).filter(([k])=>k!=='job_rules_hash')));
  const members=(await db.query('SELECT id FROM users WHERE company_id=$1 AND deleted_at IS NULL',[actor.companyId])).rows;
  if(c.quote_worker_ids.some(id=>!members.some(m=>m.id===id)))throw fault(409,'quote_workers_changed');
  const availability=(await db.query('SELECT * FROM employee_schedule_availability WHERE company_id=$1',[actor.companyId])).rows;
  const events=(await db.query('SELECT id,start_at,end_at,worker_user_ids,booking_buffer_before_minutes,booking_buffer_after_minutes FROM schedule_events WHERE company_id=$1 AND end_at>=$2 AND start_at<=$3 LIMIT 10001',[actor.companyId,new Date(now().getTime()-86400000),new Date(now().getTime()+(c.horizon_days+2)*86400000)])).rows;
  if(events.length>10000)throw fault(503,'calendar_too_large');
  return {settings:c,bundle:{worker_user_ids:c.quote_worker_ids},companyAvailability:{weekdays:c.quote_weekdays,start_time:c.quote_start,end_time:c.quote_end},availability:Object.fromEntries(availability.map(v=>[v.user_id,v])),events,zone:'America/New_York',now:now(),duration:c.quote_duration_minutes};
 }
 async function jobContext(db,actor,row){
  if(!app.locals.agreementBooking||!app.locals.agreements)throw fault(503,'job_booking_unavailable');
  const company=(await db.query('SELECT customer_booking_settings,timezone FROM companies WHERE id=$1',[actor.companyId])).rows[0];
  const raw=company.customer_booking_settings||{};
  if(company.timezone!=='America/New_York')throw fault(409,'job_timezone_requires_review');
  for(const field of ['minimum_notice_minutes','horizon_days','start_increment_minutes','buffer_before_minutes','buffer_after_minutes'])if(raw[field]===undefined)throw fault(409,'job_rules_incomplete');
  if(actor.retell.config.job_rules_hash!==digest(raw))throw fault(409,'job_rules_changed');
  return app.locals.agreementBooking.validateBookingReadiness(db,actor.companyId,{duration_minutes:row.snapshot.duration_minutes,line_items:row.snapshot.pricing?.line_items});
 }
 async function availability(actor,type,input){
  const c=configSchema.parse(Object.fromEntries(Object.entries(actor.retell.config).filter(([k])=>k!=='job_rules_hash'))),inside=inServiceArea(input.address,c);
  const out={in_service_area:inside,slots:[],timezone:'America/New_York',booking_enabled:false,...(type==='job'?{estimated_duration_min:null,requires_quote_acceptance:true,requires_deposit:false,deposit_status:'unknown'}:{})};
  const missing=missingRules(c,type);if(missing.length||!c[type+'_enabled'])return {...out,reason:'Booking disabled: '+(missing.join(', ')||'this path is disabled in WolfCRM')};
  if(!inside)return {...out,reason:'Address must end in a configured service-area ZIP code.'};
  let ctx,row,token,available;
  if(type==='job'){
   row=await agreement(pool,actor,input);if(!row)return {...out,reason:'An existing matching published quote and customer are required; request a quote or human review.'};
   const state=await app.locals.agreements.state(pool,row);
   Object.assign(out,{estimated_duration_min:row.snapshot.duration_minutes??null,requires_quote_acceptance:true,requires_deposit:(row.snapshot.pricing?.deposit_cents||0)>0,deposit_status:state.deposit});
   if(!state.can_view_availability)return {...out,reason:'The agreement requires acceptance, confirmed payment, or business review before booking.'};
   ctx=await jobContext(pool,actor,row);token=app.locals.agreements.makeToken(row);
   available=await app.locals.agreementBooking.availability(token,{start_date:offsetISO(input.preferred_date_range.start).slice(0,10)});
  }else ctx=await quoteContext(pool,actor);
  const begin=Math.max(Date.parse(input.preferred_date_range.start),now().getTime()),end=Date.parse(input.preferred_date_range.end),candidates=[];
  if(type==='job'){
   const bundles=eligibleBookingBundles(ctx.settings,row.snapshot.pricing.line_items,ctx.activeIDs).sort((a,b)=>a.id.localeCompare(b.id));
   for(const slot of available.slots){const start=Date.parse(slot.start_at);if(start<begin||start>=end)continue;const bundle=bundles.find(bundle=>bookingSlotFits({...ctx,bundle,start:slot.start_at,duration:row.snapshot.duration_minutes,now:now()}));if(bundle)candidates.push({start:slot.start_at,end:new Date(start+row.snapshot.duration_minutes*60000).toISOString(),workers:bundle.worker_user_ids,canonical_slot:slot.slot_token,agreement_id:row.id,packet_hash:row.packet_hash});if(candidates.length===30)break;}
  }else for(let stamp=Math.ceil(begin/300000)*300000;stamp<end&&candidates.length<30;stamp+=300000)if(bookingSlotFits({...ctx,start:new Date(stamp)}))candidates.push({start:new Date(stamp).toISOString(),end:new Date(stamp+ctx.duration*60000).toISOString(),workers:c.quote_worker_ids});
  // Short-lived capabilities are opaque, bound to the authenticated connection and exact request.
  await pool.query('DELETE FROM retell_slots WHERE expires_at<now() AND connection_id=$1',[actor.retell.id]);
  for(const candidate of candidates){const id=randomUUID();await pool.query('INSERT INTO retell_slots(id,connection_id,revision,payload,expires_at) VALUES($1,$2,$3,$4,now()+interval \'15 minutes\')',[id,actor.retell.id,actor.retell.revision,JSON.stringify({...candidate,type,address:input.address,services:input.services||[],lead_id:input.lead_id||null})]);out.slots.push({slot_id:id,start:offsetISO(candidate.start),end:offsetISO(candidate.end),assigned_workers:candidate.workers});}
  out.booking_enabled=true;return out;
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
  let customer=input.lead_id?await contact(db,actor,input.lead_id):null;
  if(customer&&phone(customer.phone)!==phone(input.customer.phone))throw fault(409,'customer_phone_mismatch');
  const c=Object.fromEntries(Object.entries(row.config).filter(([k])=>k!=='job_rules_hash'));
  if(!row.config.automatic_booking)return save({status:'pending_approval',reason:'Riley automatic booking has not been authorized. No appointment is reserved.'});
  if(!c[input.type+'_enabled']||missingRules(c,input.type).length)return save({status:'pending_approval',reason:'Required booking settings are incomplete. No appointment is reserved.'});
  if(!inServiceArea(input.address,c))return save({status:'failed',reason:'Address is outside the configured service area or its ZIP is missing.'});
  const slot=input.slot_id?(await db.query('SELECT * FROM retell_slots WHERE id=$1 AND connection_id=$2',[input.slot_id,row.id])).rows[0]:null;
  if(!slot){if(input.type==='job'&&!input.slot_id)return save({status:'pending_approval',reason:'A matching accepted agreement and available slot are required. No appointment is reserved.'});return save({status:'failed',reason:'Slot unavailable. Check availability again.'});}
  const s=slot.payload;
  if(slot.revision!==row.revision||new Date(slot.expires_at)<=now()||s.type!==input.type||normalizeText(s.address)!==normalizeText(input.address)||s.lead_id!==(input.lead_id||null)||(input.type==='job'&&!sameServices(s.services,input.services)))return save({status:'failed',reason:'Slot or request changed. Check availability again.'});
  try{return await transaction(pool,async()=>{
  let appointment;
  if(input.type==='job'){
   const agreementRow=await agreement(db,actor,{...input,agreement_id:s.agreement_id});
   if(!agreementRow||agreementRow.packet_hash!==s.packet_hash)return save({status:'pending_approval',reason:'The agreement changed or requires review.'});
   const state=await app.locals.agreements.state(db,agreementRow);
   if(!state.can_view_availability)return save({status:'pending_approval',reason:'Required acceptance or confirmed deposit is missing, or the job is already arranged.'});
   await jobContext(db,actor,agreementRow);
   const result=await app.locals.agreementBooking.book(app.locals.agreements.makeToken(agreementRow),{request_id:requestID,slot_token:s.canonical_slot});
   // Explicit owner-authorized automatic booking still uses the normal review operation.
   await dispatch(app,actor,'POST',`/api/schedule/customer-bookings/${result.booking.booking_id}/confirm`,{review_version:1});
   appointment=result.booking.job_id;
  }else{
   const ctx=await quoteContext(db,actor);
   if(!bookingSlotFits({...ctx,start:s.start}))return save({status:'failed',reason:'The slot was taken or crew availability changed. Check availability again.'});
   if(!customer){
    const matches=(await db.query("SELECT * FROM contacts WHERE company_id=$1 AND regexp_replace(COALESCE(phone,''),'[^0-9]','','g')=ANY($2::text[]) LIMIT 2",[actor.companyId,[phone(input.customer.phone),'1'+phone(input.customer.phone)]])).rows;
    if(matches.length>1)return save({status:'pending_approval',reason:'Multiple matching customers need business review.'});
    customer=matches[0]||await dispatch(app,actor,'POST','/api/contacts',{...input.customer,address:input.address,source:'retell'});
   }
   appointment=randomUUID();
   await dispatch(app,actor,'PUT','/api/schedule/'+appointment,{title:'Quote visit — '+input.customer.name,start:s.start,end:s.end,contact_id:customer.id,worker_user_ids:s.workers,sales_user_ids:[],notes:[input.address,input.notes].filter(Boolean).join('\n'),services:input.services});
   await db.query('UPDATE schedule_events SET booking_buffer_before_minutes=$2,booking_buffer_after_minutes=$3 WHERE id=$1 AND company_id=$4',[appointment,c.buffer_before_minutes,c.buffer_after_minutes,actor.companyId]);
  }
  return save({status:'confirmed',appointment_id:appointment,start:offsetISO(s.start),end:offsetISO(s.end),assigned_workers:s.workers});
  });}catch(e){if(e.status===409||scheduleConflict(e))return save({status:'failed',reason:'The slot, agreement or booking rules changed. Check availability again.'});throw e;}
 });}
 return {availability,book};
}
