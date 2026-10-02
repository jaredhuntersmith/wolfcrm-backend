import { installBookingReview } from './agreement-booking-review.js';
import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { QuoteContractError } from "./quote-contract-domain.js";
import { installScheduleBookingGuard, lockCompanySchedule, scheduleConflict } from "./schedule-booking-guard.js";
const fail=(code,message,status=409)=>{throw new QuoteContractError(code,message,status);};
const uuid=(value)=>{if(typeof value!=="string"||! /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(value))fail("booking_id_invalid","Use a valid request or resource ID.",400);return value.toLowerCase();};
const hash=(value)=>createHash("sha256").update(JSON.stringify(value)).digest("hex");
const equal=(a,b)=>typeof a==="string"&&typeof b==="string"&&a.length===b.length&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
const defaults={enabled:false,minimum_notice_minutes:1440,horizon_days:60,start_increment_minutes:30,buffer_before_minutes:0,buffer_after_minutes:0,suggested_day_count:4,allow_customer_reschedule:false,allow_customer_cancel:false,change_cutoff_minutes:1440,resource_bundles:[]};
export function normalizeBookingSettings(raw={}) {
  const out={};
  if(!raw||typeof raw!=="object"||Array.isArray(raw))fail("booking_settings_invalid","Enter valid booking settings.",400);
  for(const key of ["enabled","allow_customer_reschedule","allow_customer_cancel"]){if(raw[key]!==undefined&&typeof raw[key]!=="boolean")fail("booking_settings_invalid",`${key} must be enabled or disabled.`,400);out[key]=raw[key]??defaults[key];}
  for(const [key,min,max] of [["minimum_notice_minutes",0,43200],["horizon_days",1,90],["start_increment_minutes",5,120],["buffer_before_minutes",0,240],["buffer_after_minutes",0,240],["suggested_day_count",1,14],["change_cutoff_minutes",0,43200]]){
    const value=raw[key]??defaults[key];if(!Number.isInteger(value)||value<min||value>max)fail("booking_settings_invalid",`${key} must be between ${min} and ${max}.`,400);out[key]=value;
  }
  if(out.start_increment_minutes%5)fail("booking_settings_invalid","Start increments must be a multiple of five minutes.",400);
  if(!Array.isArray(raw.resource_bundles??[])||(raw.resource_bundles??[]).length>25)fail("booking_settings_invalid","Configure at most 25 resource bundles.",400);
  out.resource_bundles=(raw.resource_bundles??[]).map((raw)=>{
    if(!raw||typeof raw!=="object"||typeof raw.name!=="string"||!raw.name.trim()||raw.name.length>120)fail("booking_resource_invalid","Give each crew a name.",400);
    if(!Array.isArray(raw.worker_user_ids)||!raw.worker_user_ids.length||raw.worker_user_ids.length>20||!Array.isArray(raw.service_ids??[])||(raw.service_ids??[]).length>200)fail("booking_resource_invalid","Select the workers who must be available together.",400);
    if(typeof raw.all_services!=="boolean"||typeof raw.enabled!=="boolean")fail("booking_resource_invalid","Explicitly configure crew qualification and availability.",400);
    const worker_user_ids=[...new Set(raw.worker_user_ids.map(uuid))].sort(),service_ids=[...new Set((raw.service_ids??[]).map(uuid))].sort();
    if(!raw.all_services&&!service_ids.length)fail("booking_resource_invalid","Select permitted saved services or explicitly enable all services.",400);
    return{id:uuid(raw.id),name:raw.name.trim(),worker_user_ids,service_ids,all_services:raw.all_services,enabled:raw.enabled};
  });
  if(new Set(out.resource_bundles.map(b=>b.id)).size!==out.resource_bundles.length)fail("booking_resource_invalid","Crew IDs must be unique.",400);
  if(out.enabled&&!out.resource_bundles.some(b=>b.enabled))fail("booking_resource_required","Enable at least one qualified crew before allowing booking.",400);
  return out;
}
const formatters=new Map();
function parts(date,zone){
  if(!formatters.has(zone))formatters.set(zone,new Intl.DateTimeFormat("en-CA",{timeZone:zone,year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",hourCycle:"h23"}));
  const p=Object.fromEntries(formatters.get(zone).formatToParts(date).filter(p=>p.type!=="literal").map(p=>[p.type,Number(p.value)]));
  return{date:`${p.year}-${String(p.month).padStart(2,"0")}-${String(p.day).padStart(2,"0")}`,minutes:p.hour*60+p.minute,weekday:((new Date(Date.UTC(p.year,p.month-1,p.day)).getUTCDay()+6)%7)+1};
}
function minutes(text){const [h,m]=String(text||"").split(":").map(Number);return h*60+m;}
function fits(start,end,profile,zone){
  const a=parts(start,zone),b=parts(end,zone);
  return a.date===b.date&&Array.isArray(profile.weekdays)&&profile.weekdays.map(Number).includes(a.weekday)&&a.minutes>=minutes(profile.start_time)&&b.minutes<=minutes(profile.end_time);
}
export function eligibleBookingBundles(settings,lineItems,activeIDs){
  return settings.resource_bundles.filter(b=>b.enabled&&b.worker_user_ids.every(id=>activeIDs.has(id))&&(b.all_services||lineItems.every(l=>l.service_id&&b.service_ids.includes(l.service_id))));
}
export function bookingSlotFits({start,duration,settings,bundle,companyAvailability,availability,events,zone,now=new Date(),excludeJobID=null}){
  const startAt=new Date(start),endAt=new Date(startAt.getTime()+duration*60000),occupiedStart=new Date(startAt.getTime()-settings.buffer_before_minutes*60000),occupiedEnd=new Date(endAt.getTime()+settings.buffer_after_minutes*60000);
  if(!Number.isFinite(startAt.getTime())||startAt.getUTCSeconds()||startAt.getUTCMilliseconds()||startAt<new Date(now.getTime()+settings.minimum_notice_minutes*60000)||startAt>new Date(now.getTime()+settings.horizon_days*86400000)||parts(startAt,zone).minutes%settings.start_increment_minutes)return false;
  if(!fits(occupiedStart,occupiedEnd,companyAvailability,zone))return false;
  for(const worker of bundle.worker_user_ids){const override=availability[worker];if(!fits(occupiedStart,occupiedEnd,override&&override.enabled!==false?override:companyAvailability,zone))return false;}
  return !events.some(e=>e.id!==excludeJobID&&new Date(e.start_at).getTime()-(e.booking_buffer_before_minutes||0)*60000<occupiedEnd.getTime()&&new Date(e.end_at).getTime()+(e.booking_buffer_after_minutes||0)*60000>occupiedStart.getTime()&&(!e.worker_user_ids?.length||e.worker_user_ids.some(id=>bundle.worker_user_ids.includes(id))));
}
export async function installAgreementBookingSchema(pool){
  await installScheduleBookingGuard(pool);
  await pool.query(`CREATE TABLE IF NOT EXISTS agreement_bookings(
    id UUID PRIMARY KEY,company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
    agreement_id UUID NOT NULL REFERENCES quote_agreements(id) ON DELETE RESTRICT,quote_id UUID NOT NULL,
    job_id TEXT NOT NULL UNIQUE,resource_bundle_id UUID NOT NULL,status TEXT NOT NULL CHECK(status IN ('booked','rescheduled','canceled')),
    job_snapshot JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT now(),updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
    CREATE UNIQUE INDEX IF NOT EXISTS agreement_booking_active_quote_idx ON agreement_bookings(company_id,quote_id) WHERE status<>'canceled';
    CREATE INDEX IF NOT EXISTS agreement_booking_quote_idx ON agreement_bookings(company_id,quote_id,created_at DESC);
    CREATE TABLE IF NOT EXISTS agreement_booking_history(id UUID PRIMARY KEY,booking_id UUID NOT NULL REFERENCES agreement_bookings(id) ON DELETE RESTRICT,operation TEXT NOT NULL,before_snapshot JSONB NOT NULL,after_snapshot JSONB,created_at TIMESTAMPTZ NOT NULL DEFAULT now());
    CREATE INDEX IF NOT EXISTS agreement_booking_history_booking_idx ON agreement_booking_history(booking_id,created_at);
    CREATE TABLE IF NOT EXISTS agreement_booking_requests(company_id UUID NOT NULL,request_id UUID NOT NULL,agreement_id UUID NOT NULL REFERENCES quote_agreements(id) ON DELETE RESTRICT,request_hash TEXT NOT NULL,result JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT now(),PRIMARY KEY(company_id,request_id));
    CREATE TABLE IF NOT EXISTS agreement_booking_outbox(id UUID PRIMARY KEY,company_id UUID NOT NULL,agreement_id UUID NOT NULL,job_id TEXT NOT NULL,operation TEXT NOT NULL,job_snapshot JSONB NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),completed_at TIMESTAMPTZ,error_code TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT now());
    CREATE INDEX IF NOT EXISTS agreement_booking_outbox_due_idx ON agreement_booking_outbox(next_attempt_at) WHERE completed_at IS NULL;
    ALTER TABLE agreement_bookings ADD COLUMN IF NOT EXISTS confirmed_at TIMESTAMPTZ;
    ALTER TABLE agreement_bookings ADD COLUMN IF NOT EXISTS confirmed_by UUID;
    ALTER TABLE agreement_bookings ADD COLUMN IF NOT EXISTS review_version INTEGER NOT NULL DEFAULT 1;
    CREATE INDEX IF NOT EXISTS agreement_booking_review_idx ON agreement_bookings(company_id,created_at) WHERE status<>'canceled' AND confirmed_at IS NULL;
    CREATE OR REPLACE FUNCTION wolfcrm_booking_history() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE booking agreement_bookings; payload jsonb; event_type text; saved schedule_events;
    BEGIN
      saved:=CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
      SELECT * INTO booking FROM agreement_bookings WHERE job_id=saved.id AND status<>'canceled';
      IF NOT FOUND THEN RETURN NULL; END IF;
      IF TG_OP='DELETE' THEN event_type:='booking_canceled';
      ELSIF (OLD.start_at,OLD.end_at,OLD.worker_user_ids) IS DISTINCT FROM (NEW.start_at,NEW.end_at,NEW.worker_user_ids) THEN event_type:='booking_rescheduled';
      ELSE RETURN NULL; END IF;
      payload:=jsonb_build_object('booking_id',booking.id,'job_id',saved.id,'start_at',saved.start_at,'previous_start_at',OLD.start_at);
      INSERT INTO agreement_booking_history(id,booking_id,operation,before_snapshot,after_snapshot) VALUES(gen_random_uuid(),booking.id,event_type,to_jsonb(OLD),CASE WHEN TG_OP='DELETE' THEN NULL ELSE to_jsonb(NEW) END);
      UPDATE agreement_bookings SET confirmed_at=NULL,confirmed_by=NULL,review_version=review_version+1,status=CASE WHEN TG_OP='DELETE' THEN 'canceled' ELSE 'rescheduled' END,job_snapshot=to_jsonb(saved),updated_at=now() WHERE id=booking.id;
      INSERT INTO agreement_events(id,agreement_id,type,actor_type,payload) VALUES(gen_random_uuid(),booking.agreement_id,event_type,'system',payload);
      INSERT INTO agreement_booking_outbox(id,company_id,agreement_id,job_id,operation,job_snapshot) VALUES(gen_random_uuid(),booking.company_id,booking.agreement_id,saved.id,event_type,to_jsonb(saved));
      RETURN NULL;
    END $$;
    DROP TRIGGER IF EXISTS wolfcrm_booking_history ON schedule_events;
    CREATE TRIGGER wolfcrm_booking_history AFTER UPDATE OR DELETE ON schedule_events FOR EACH ROW EXECUTE FUNCTION wolfcrm_booking_history();`);
}
async function transaction(pool,work){const db=await pool.connect();try{await db.query("BEGIN");const result=await work(db);await db.query("COMMIT");return result;}catch(error){await db.query("ROLLBACK");throw error;}finally{db.release();}}
export function createAgreementBooking({pool,service,env=service.env,now=()=>new Date(),onScheduleChange}){
  async function context(db,companyID){
    const company=(await db.query("SELECT * FROM companies WHERE id=$1",[companyID])).rows[0];if(!company)fail("company_not_found","The business was not found.",404);
    const settings=normalizeBookingSettings(company.customer_booking_settings),zone=company.timezone||"America/New_York";
    try{parts(now(),zone);}catch{fail("booking_timezone_invalid","The business must configure a valid schedule timezone.");}
    const members=await db.query("SELECT id FROM users WHERE company_id=$1 AND deleted_at IS NULL",[companyID]);
    const overrides=await db.query("SELECT * FROM employee_schedule_availability WHERE company_id=$1",[companyID]);
    const events=await db.query("SELECT id,start_at,end_at,worker_user_ids,booking_buffer_before_minutes,booking_buffer_after_minutes FROM schedule_events WHERE company_id=$1 AND end_at >= $2 AND start_at <= $3",[companyID,new Date(now().getTime()-86400000),new Date(now().getTime()+(settings.horizon_days+2)*86400000)]);
    return{company,settings,zone,version:company.customer_booking_version,activeIDs:new Set(members.rows.map(m=>m.id)),availability:Object.fromEntries(overrides.rows.map(v=>[v.user_id,v])),events:events.rows.map(e=>({...e,worker_user_ids:Array.isArray(e.worker_user_ids)&&e.worker_user_ids.every(id=>typeof id==="string")?e.worker_user_ids:[]})),
      companyAvailability:{weekdays:company.business_days??[1,2,3,4,5],start_time:company.business_open_time||"09:00",end_time:company.business_close_time||"17:00"}};
  }
  async function readiness(db,companyID,{duration_minutes,line_items,quote_id}={}){
    const ctx=await context(db,companyID);
    if(!ctx.settings.enabled)fail("booking_not_configured","Enable customer booking in Schedule settings.");
    if(!Number.isInteger(duration_minutes)||duration_minutes<1||duration_minutes>1440)fail("booking_duration_required","Enter a valid internal job duration.");
    if(!eligibleBookingBundles(ctx.settings,line_items??[],ctx.activeIDs).length)fail("booking_qualified_crew_required","Configure an active crew qualified for every quoted service in Schedule settings.");
    if(quote_id){
      const booked=(await db.query("SELECT e.* FROM agreement_bookings b JOIN schedule_events e ON e.id=b.job_id AND e.company_id=b.company_id WHERE b.company_id=$1 AND b.quote_id=$2 AND b.status<>'canceled'",[companyID,quote_id])).rows[0];
      const scope=lines=>hash((lines??[]).map(l=>({id:l.id,service_id:l.service_id??null,name:l.name,qty:l.qty,description:l.description??""})).sort((a,b)=>String(a.id).localeCompare(String(b.id))));
      if(booked&&((new Date(booked.end_at)-new Date(booked.start_at))/60000!==duration_minutes||scope(booked.service_items)!==scope(line_items)))fail("booking_scope_changed","Review the existing appointment's duration and service scope in Schedule before publishing this revision.");
    }
    return ctx;
  }
  async function summary(db,row){
    if(!row.quote_id)return null;
    const booking=(await db.query("SELECT b.*,e.start_at,e.end_at,e.finished_at,e.started_at FROM agreement_bookings b LEFT JOIN schedule_events e ON e.id=b.job_id AND e.company_id=b.company_id WHERE b.company_id=$1 AND b.quote_id=$2 ORDER BY b.created_at DESC LIMIT 1",[row.company_id,row.quote_id])).rows[0];
    if(!booking||booking.status==="canceled"){
      const scheduled=(await db.query("SELECT id,start_at,end_at,started_at,finished_at FROM schedule_events WHERE company_id=$1 AND quote_id=$2 ORDER BY finished_at IS NOT NULL,start_at LIMIT 25",[row.company_id,row.quote_id])).rows;
      if(scheduled.length){const company=(await db.query("SELECT timezone FROM companies WHERE id=$1",[row.company_id])).rows[0],first=scheduled[0];return{booking_id:first.id,id:first.id,job_id:first.id,status:"booked",start_at:first.start_at,end_at:first.end_at,timezone:company?.timezone||"America/New_York",service_state:first.finished_at?"completed":first.started_at?"in_progress":"upcoming",can_reschedule:false,can_cancel:false,arranged_by_business:true,appointments:scheduled.map(e=>({job_id:e.id,start_at:e.start_at,end_at:e.end_at,service_state:e.finished_at?"completed":e.started_at?"in_progress":"upcoming"}))};}
      if(!booking)return null;
    }
    const company=(await db.query("SELECT timezone,customer_booking_settings FROM companies WHERE id=$1",[row.company_id])).rows[0];
    const settings=normalizeBookingSettings(company?.customer_booking_settings),active=booking.status!=="canceled"&&booking.start_at!=null;
    const changeAllowed=active&&!booking.started_at&&!booking.finished_at&&new Date(booking.start_at).getTime()-now().getTime()>=settings.change_cutoff_minutes*60000;
    return{booking_id:active?booking.id:null,id:booking.id,job_id:booking.job_id,status:active?booking.status:"canceled",start_at:booking.start_at??booking.job_snapshot.start_at,end_at:booking.end_at??booking.job_snapshot.end_at,timezone:company?.timezone||"America/New_York",service_state:booking.finished_at?"completed":booking.started_at?"in_progress":active?"upcoming":"canceled",confirmed_at:booking.confirmed_at,can_reschedule:changeAllowed&&settings.enabled&&row.snapshot.customer_page?.show_manage_booking!==false&&(row.snapshot.customer_page?.allow_reschedule??settings.allow_customer_reschedule),can_cancel:changeAllowed&&row.snapshot.customer_page?.show_manage_booking!==false&&(row.snapshot.customer_page?.allow_cancel??settings.allow_customer_cancel)};
  }
  async function gate(db,row){
    if(!row.quote_id||!row.snapshot.allow_customer_booking)fail("booking_not_offered","The business will arrange scheduling for this agreement.");
    const state=await service.state(db,row);
    if(!state.base_workflow_complete||["declined","revoked","superseded","expired"].includes(state.decision)||state.deposit==="adjusted_review_required")fail("booking_prerequisites_required","Complete all required signatures and the confirmed deposit before viewing availability.");
  }
  function slotToken(row,ctx,bundle,start){const value=new Date(start).getTime().toString();return `${value}.${createHmac("sha256",typeof service.secret==="function"?service.secret():env.QUOTE_LINK_SECRET).update(`${row.id}:${row.packet_hash}:${ctx.version}:${hash(ctx.settings)}:${value}:${bundle.id}:${bundle.worker_user_ids.join(",")}`).digest("base64url")}`;}
  function resolveSlot(row,ctx,token,excludeJobID=null){
    if(typeof token!=="string"||token.length>160||!/^\d{12,14}\.[\w-]{43}$/.test(token))fail("booking_slot_invalid","Choose a current available time.",400);
    const start=new Date(Number(token.split(".")[0]));
    const bundles=eligibleBookingBundles(ctx.settings,row.snapshot.pricing.line_items,ctx.activeIDs);
    const bundle=bundles.find(b=>equal(slotToken(row,ctx,b,start),token));
    if(!bundle||!bookingSlotFits({...ctx,start,duration:row.snapshot.duration_minutes,bundle,now:now(),excludeJobID}))fail("booking_slot_changed","This time is no longer available. Refresh and choose another time.");
    return{bundle,start,end:new Date(start.getTime()+row.snapshot.duration_minutes*60000)};
  }
  async function availability(token,query={}){
    const {row}=await service.loadPublic(pool,token);await service.rate(pool,`booking-availability:${row.id}`,40,60);await gate(pool,row);
    const current=await summary(pool,row);
    if(current?.booking_id&&!(query.reschedule==="true"&&current.can_reschedule))fail("booking_already_booked","This agreement already has an appointment.");
    const ctx=await readiness(pool,row.company_id,{duration_minutes:row.snapshot.duration_minutes,line_items:row.snapshot.pricing?.line_items});
    const startDate=query.start_date;
    if(startDate&&(!/^\d{4}-\d{2}-\d{2}$/.test(startDate)||Number.isNaN(Date.parse(startDate))||new Date(startDate).toISOString().slice(0,10)!==startDate))fail("booking_date_invalid","Use a valid calendar date.",400);
    const slots=[],seen=new Set(),bundles=eligibleBookingBundles(ctx.settings,row.snapshot.pricing.line_items,ctx.activeIDs).sort((a,b)=>a.id.localeCompare(b.id));
    const clock=now(),begin=Math.ceil((clock.getTime()+ctx.settings.minimum_notice_minutes*60000)/300000)*300000,stop=clock.getTime()+ctx.settings.horizon_days*86400000;
    const label=new Intl.DateTimeFormat("en-US",{timeZone:ctx.zone,hour:"numeric",minute:"2-digit",timeZoneName:"short"});
    for(let stamp=begin;stamp<=stop&&slots.length<2000;stamp+=300000){
      const start=new Date(stamp),p=parts(start,ctx.zone);if((startDate&&p.date<startDate)||p.minutes%ctx.settings.start_increment_minutes)continue;
      const bundle=bundles.find(bundle=>bookingSlotFits({...ctx,start,duration:row.snapshot.duration_minutes,bundle,now:clock,excludeJobID:query.reschedule==="true"?current?.job_id:null}));
      if(!bundle)continue;
      slots.push({slot_token:slotToken(row,ctx,bundle,start),start_at:start.toISOString(),date:p.date,time_label:label.format(start)});seen.add(p.date);
    }
    const dates=[...seen];return{timezone:ctx.zone,slots,suggested_days:dates.slice(0,ctx.settings.suggested_day_count),next_start_date:slots.length===2000?dates.at(-1):null,can_request_help:true};
  }
  async function previous(db,row,requestID,requestHash){const existing=(await db.query("SELECT * FROM agreement_booking_requests WHERE company_id=$1 AND request_id=$2",[row.company_id,requestID])).rows[0];if(!existing)return null;if(existing.agreement_id!==row.id||existing.request_hash!==requestHash)fail("booking_request_conflict","This request ID was used for a different booking action.");return existing.result;}
  async function record(db,row,requestID,requestHash,result){await db.query("INSERT INTO agreement_booking_requests(company_id,request_id,agreement_id,request_hash,result) VALUES($1,$2,$3,$4,$5::jsonb)",[row.company_id,requestID,row.id,requestHash,JSON.stringify(result)]);return result;}
  async function book(token,raw={}){
    const requestID=uuid(raw.request_id),requestHash=hash({action:"book",slot_token:raw.slot_token});
    return transaction(pool,async db=>{
      let {row,role}=await service.loadPublic(db,token);if(role!=="customer")fail("booking_primary_customer_required","The primary customer manages this appointment.",403);await lockCompanySchedule(db,row.company_id);({row}=await service.loadPublic(db,token,true));
      const replay=await previous(db,row,requestID,requestHash);if(replay)return replay;
      await service.rate(db,`booking-write:${row.id}`,20,60);await gate(db,row);
      const current=await summary(db,row);if(current?.booking_id)return record(db,row,requestID,requestHash,{booking:current,replayed:true});
      if((await db.query("SELECT id FROM schedule_events WHERE company_id=$1 AND quote_id=$2 LIMIT 1",[row.company_id,row.quote_id])).rowCount)fail("booking_existing_job","The business already scheduled work for this quote. Contact them to confirm the appointment.");
      const ctx=await readiness(db,row.company_id,{duration_minutes:row.snapshot.duration_minutes,line_items:row.snapshot.pricing.line_items}),slot=resolveSlot(row,ctx,raw.slot_token);
      const bookingID=randomUUID(),jobID=randomUUID();
      const contact=(await db.query("SELECT id FROM contacts WHERE id=$1 AND company_id=$2",[row.contact_id,row.company_id])).rows[0];if(!contact)fail("booking_contact_unavailable","Contact the business to arrange this appointment.");
      const job=(await db.query(`INSERT INTO schedule_events(id,user_id,company_id,created_by,title,start_at,end_at,contact_id,quote_id,agreement_id,services,service_items,price_cents,sales_user_ids,worker_user_ids,booking_buffer_before_minutes,booking_buffer_after_minutes)
        VALUES($1,$2,$3,$2,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,'[]',$13::jsonb,$14,$15) RETURNING *`,[jobID,row.created_by,row.company_id,row.title,slot.start,slot.end,row.contact_id,row.quote_id,row.id,JSON.stringify(row.snapshot.pricing.line_items.map(l=>l.name)),JSON.stringify(row.snapshot.pricing.line_items),row.snapshot.pricing.total_cents,JSON.stringify(slot.bundle.worker_user_ids),ctx.settings.buffer_before_minutes,ctx.settings.buffer_after_minutes])).rows[0];
      job.customer_note_entries=(await db.query(`SELECT e.id,e.created_at,e.actor_id AS signer_role,e.payload->>'message' AS message FROM agreement_events e JOIN quote_agreements a ON a.id=e.agreement_id WHERE a.company_id=$1 AND a.quote_id=$2 AND e.type='customer_note' ORDER BY e.created_at,e.id`,[row.company_id,row.quote_id])).rows;
      await db.query('UPDATE schedule_events SET customer_note_entries=$2::jsonb WHERE id=$1',[jobID,JSON.stringify(job.customer_note_entries)]);
      await db.query("INSERT INTO agreement_bookings(id,company_id,agreement_id,quote_id,job_id,resource_bundle_id,status,job_snapshot) VALUES($1,$2,$3,$4,$5,$6,'booked',$7::jsonb)",[bookingID,row.company_id,row.id,row.quote_id,jobID,slot.bundle.id,JSON.stringify(job)]);
      await service.event(db,row.id,"booking_created",{actor_type:"customer",payload:{booking_id:bookingID,job_id:jobID,start_at:slot.start.toISOString()}});
      await db.query("INSERT INTO agreement_booking_outbox(id,company_id,agreement_id,job_id,operation,job_snapshot) VALUES($1,$2,$3,$4,'booking_created',$5::jsonb)",[randomUUID(),row.company_id,row.id,jobID,JSON.stringify(job)]);
      await db.query("UPDATE payment_records SET job_id=$3 WHERE company_id=$1 AND quote_id=$2 AND job_id IS NULL AND service_plan_id IS NULL",[row.company_id,row.quote_id,jobID]);
      return record(db,row,requestID,requestHash,{booking:await summary(db,row),replayed:false});
    });
  }
  async function change(token,raw={}){
    if(!["reschedule","cancel"].includes(raw.action))fail("booking_action_invalid","Choose reschedule or cancel.",400);
    const requestID=uuid(raw.request_id),requestHash=hash({action:raw.action,slot_token:raw.slot_token??null});
    return transaction(pool,async db=>{
      let {row,role}=await service.loadPublic(db,token);if(role!=="customer")fail("booking_primary_customer_required","The primary customer manages this appointment.",403);await lockCompanySchedule(db,row.company_id);({row}=await service.loadPublic(db,token,true));
      const replay=await previous(db,row,requestID,requestHash);if(replay)return replay;
      await service.rate(db,`booking-write:${row.id}`,20,60);await gate(db,row);
      const current=await summary(db,row);if(!current?.booking_id||!current[raw.action==="cancel"?"can_cancel":"can_reschedule"])fail("booking_change_not_allowed","Contact the business to change this appointment.");
      if(raw.action==="cancel")await db.query("DELETE FROM schedule_events WHERE id=$1 AND company_id=$2",[current.job_id,row.company_id]);
      else{
        const ctx=await readiness(db,row.company_id,{duration_minutes:row.snapshot.duration_minutes,line_items:row.snapshot.pricing.line_items}),slot=resolveSlot(row,ctx,raw.slot_token,current.job_id);
        await db.query("UPDATE schedule_events SET start_at=$3,end_at=$4,worker_user_ids=$5::jsonb,booking_buffer_before_minutes=$6,booking_buffer_after_minutes=$7,updated_at=now() WHERE id=$1 AND company_id=$2",[current.job_id,row.company_id,slot.start,slot.end,JSON.stringify(slot.bundle.worker_user_ids),ctx.settings.buffer_before_minutes,ctx.settings.buffer_after_minutes]);
        await db.query("UPDATE agreement_bookings SET resource_bundle_id=$2 WHERE id=$1",[current.id,slot.bundle.id]);
      }
      await service.event(db,row.id,"booking_change_requested",{actor_type:"customer",payload:{booking_id:current.id,action:raw.action}});
      return record(db,row,requestID,requestHash,{booking:await summary(db,row),replayed:false});
    });
  }
  async function help(token,raw={}){
    const {row}=await service.loadPublic(pool,token);await gate(pool,row);await service.rate(pool,`booking-help:${row.id}`,5,3600);
    const requestID=uuid(raw.request_id),message=String(raw.message??"").trim();if(message.length>4000)fail("booking_message_invalid","Use 4,000 characters or fewer.",400);
    await service.event(pool,row.id,"booking_help_requested",{request_id:requestID,request_hash:hash(message),actor_type:"customer",payload:{message}});return{requested:true};
  }
  async function settings(req,raw){
    if(!req.companyId)fail("company_required","Select a company.",403);
    if(raw===undefined){const ctx=await context(pool,req.companyId);return{...ctx.settings,version:ctx.version,timezone:ctx.zone};}
    const value=normalizeBookingSettings(raw);
    return transaction(pool,async db=>{await lockCompanySchedule(db,req.companyId);const ctx=await context(db,req.companyId);
      if(raw.expected_version!==ctx.version)fail("booking_settings_conflict","Settings changed. Refresh before saving.");
      for(const bundle of value.resource_bundles){if(bundle.worker_user_ids.some(id=>!ctx.activeIDs.has(id)))fail("booking_resource_invalid","Every crew member must be active in this company.",400);
        if(bundle.service_ids.length){const found=await db.query("SELECT id FROM saved_services WHERE company_id=$1 AND id=ANY($2::uuid[]) AND archived_at IS NULL",[req.companyId,bundle.service_ids]);if(found.rowCount!==bundle.service_ids.length)fail("booking_service_invalid","Select active saved services from this company.",400);}}
      const updated=(await db.query("UPDATE companies SET customer_booking_settings=$2::jsonb,customer_booking_version=customer_booking_version+1,updated_at=now() WHERE id=$1 RETURNING customer_booking_version",[req.companyId,JSON.stringify(value)])).rows[0];
      return{...value,version:updated.customer_booking_version,timezone:ctx.zone};});
  }
  async function processOutbox(){if(!onScheduleChange)return;
    const jobs=(await pool.query("UPDATE agreement_booking_outbox SET next_attempt_at=now()+interval '5 minutes',attempts=attempts+1 WHERE id IN (SELECT id FROM agreement_booking_outbox WHERE completed_at IS NULL AND next_attempt_at<=now() ORDER BY next_attempt_at LIMIT 20 FOR UPDATE SKIP LOCKED) RETURNING *")).rows;
    for(const job of jobs){try{await onScheduleChange(job);await pool.query("UPDATE agreement_booking_outbox SET completed_at=now(),error_code=NULL WHERE id=$1",[job.id]);}catch{await pool.query("UPDATE agreement_booking_outbox SET error_code='schedule_effect_retry' WHERE id=$1",[job.id]);}}
  }
  return{availability,book,change,help,settings,bookingSummary:summary,validateBookingReadiness:readiness,processOutbox};
}
export async function installAgreementBooking({app,pool,service,env=service.env,authRequired,requireCapability,onScheduleChange,startWorker=true,now}){
  await installAgreementBookingSchema(pool);const adapter=createAgreementBooking({pool,service,env,onScheduleChange,now});
  installBookingReview({app,pool,service,authRequired,requireCapability});
  service.bookingReady=true;service.bookingSummary=adapter.bookingSummary;service.validateBookingReadiness=adapter.validateBookingReadiness;app.locals.agreementBooking=adapter;
  const route=action=>async(req,res)=>{res.set({"Cache-Control":"private, no-store","Referrer-Policy":"no-referrer","X-Content-Type-Options":"nosniff"});
    if(req.method!=="GET"&&(!req.is("application/json")))return res.status(415).json({error:"json_required"});
    if(req.method!=="GET"&&req.headers.origin&&req.headers.origin!==env.QUOTE_PUBLIC_BASE_URL?.replace(/\/$/,""))return res.status(403).json({error:"origin_not_allowed"});
    try{res.json(await action(req));}catch(error){const conflict=scheduleConflict(error);if(conflict)return res.status(conflict.status).json(conflict);if(error instanceof QuoteContractError)return res.status(error.status).json({error:error.code,message:error.message});console.error("[agreement-booking] operation failed",{code:error?.code||"internal"});res.status(500).json({error:"booking_unavailable",message:"Scheduling is temporarily unavailable. Your agreement and payments are saved."});}};
  app.get("/api/public/agreements/:token/availability",route(req=>adapter.availability(req.params.token,req.query)));
  app.post("/api/public/agreements/:token/book",route(req=>adapter.book(req.params.token,req.body)));
  app.post("/api/public/agreements/:token/booking/change",route(req=>adapter.change(req.params.token,req.body)));
  app.post("/api/public/agreements/:token/booking/help",route(req=>adapter.help(req.params.token,req.body)));
  app.get("/api/schedule/booking/settings",authRequired,requireCapability("schedule.view"),route(req=>adapter.settings(req)));
  app.put("/api/schedule/booking/settings",authRequired,requireCapability("schedule.manage_team"),route(req=>adapter.settings(req,req.body)));
  if(startWorker)setInterval(()=>adapter.processOutbox().catch(()=>{}),30000).unref?.();
  return adapter;
}
