import assert from "node:assert/strict";
import test from "node:test";
import {randomUUID} from "node:crypto";
import {startLocalPostgres} from "./helpers/local-postgres.js";
import {installAgreementPaymentSchema} from "../agreement-payments.js";
import {installAgreementSchema,createAgreementService} from "../quote-agreements.js";
import {installAgreementBooking,installAgreementBookingSchema,createAgreementBooking,normalizeBookingSettings,bookingSlotFits} from "../agreement-booking.js";

const instant=new Date("2030-01-01T00:00:00Z");
test("booking duration, buffers, DST and explicit crew qualifications",()=>{
  const bundle={id:randomUUID(),name:"Crew",worker_user_ids:[randomUUID()],all_services:true,service_ids:[],enabled:true};
  const settings=normalizeBookingSettings({enabled:true,resource_bundles:[bundle],minimum_notice_minutes:0,horizon_days:90,start_increment_minutes:30,buffer_before_minutes:30,buffer_after_minutes:30});
  const base={settings,bundle,companyAvailability:{weekdays:[1,2,3,4,5,6,7],start_time:"09:00",end_time:"19:00"},availability:{},events:[],zone:"America/New_York",now:instant};
  assert.equal(bookingSlotFits({...base,start:"2030-01-02T21:00:00Z",duration:240}),false,"4 PM plus four hours and buffer does not fit 7 PM close");
  assert.equal(bookingSlotFits({...base,start:"2030-01-02T14:00:00Z",duration:60}),false,"before buffer must fit work hours");
  assert.equal(bookingSlotFits({...base,start:"2030-01-02T14:30:00Z",duration:60}),true);
  assert.equal(bookingSlotFits({...base,start:"2030-01-02T14:30:00Z",duration:120,events:[{id:"busy",start_at:"2030-01-02T16:00Z",end_at:"2030-01-02T16:30Z",worker_user_ids:bundle.worker_user_ids}]}),false);
  const dst={...base,settings:{...settings,buffer_before_minutes:0,buffer_after_minutes:0},companyAvailability:{...base.companyAvailability,start_time:"00:00",end_time:"04:00"},now:new Date("2030-03-01T00:00Z")};
  assert.equal(bookingSlotFits({...dst,start:"2030-03-10T06:30:00Z",duration:60}),true,"spring jump uses actual elapsed hour, ends at 3:30 local");
  assert.equal(bookingSlotFits({...dst,start:"2030-03-10T06:30:00Z",duration:120}),false);
  assert.throws(()=>normalizeBookingSettings({enabled:true,resource_bundles:[]}),/crew/);
});

test("real PostgreSQL calendar guard and public booking",{timeout:90000},async t=>{
  const pg=startLocalPostgres();pg.configureEnvironment();let pool,server;
  try{
    const backend=await import("../index.js");pool=backend.pool;await backend.bootstrap();await installAgreementSchema(pool);await installAgreementPaymentSchema(pool);
    const company=randomUUID(),owner=randomUUID(),worker=randomUUID(),otherWorker=randomUUID(),contact=randomUUID();
    await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id,timezone,business_days,business_open_time,business_close_time) VALUES($1,'Booking business','BOOK-TEST',$2,'America/New_York','[1,2,3,4,5,6,7]','09:00','17:00')",[company,owner]);
    for(const [id,email,role]of [[owner,"owner@example.invalid","employer"],[worker,"worker@example.invalid","employee"],[otherWorker,"worker2@example.invalid","employee"]])await pool.query("INSERT INTO users(id,email,role,company_id) VALUES($1,$2,$3,$4)",[id,email,role,company]);
    await pool.query("INSERT INTO contacts(id,user_id,company_id,name) VALUES($1,$2,$3,'Test customer')",[contact,owner,company]);
    await pool.query("INSERT INTO sessions(token,user_id) VALUES('booking-fixture',$1)",[owner]);
    const insertJob=async({id=randomUUID(),workers=[worker],start="2030-01-02T14:00:00Z",end="2030-01-02T15:00:00Z",db=pool,agreementID=null}={})=>(await db.query("INSERT INTO schedule_events(id,user_id,company_id,title,start_at,end_at,worker_user_ids,agreement_id) VALUES($1,$2,$3,'Private customer',$4,$5,$6::jsonb,$7) RETURNING *",[id,owner,company,start,end,JSON.stringify(workers),agreementID])).rows[0];
    // Old overlapping appointments are retained by the additive migration.
    await pool.query("ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS agreement_id UUID");
    const legacyA=await insertJob(),legacyB=await insertJob();
    const env={QUOTE_LINK_SECRET:"fixture-booking-link-secret-more-than-32-characters",QUOTE_PUBLIC_BASE_URL:"https://example.invalid"};
    const service=createAgreementService({pool,env});
    const effects=[];
    const adapter=await installAgreementBooking({app:backend.app,pool,service,env,now:()=>instant,onScheduleChange:async job=>effects.push(job),startWorker:false,authRequired:(req,res,next)=>{if(req.headers.authorization!=="Bearer booking-fixture")return res.sendStatus(401);req.companyId=company;req.userId=owner;next();},requireCapability:()=> (_req,_res,next)=>next()});
    const bundle={id:randomUUID(),name:"Qualified crew",worker_user_ids:[worker],service_ids:[],all_services:true,enabled:true};
    await adapter.settings({companyId:company},{expected_version:1,enabled:true,resource_bundles:[bundle],minimum_notice_minutes:0,horizon_days:10,start_increment_minutes:30,allow_customer_cancel:true,allow_customer_reschedule:true,change_cutoff_minutes:0});
    server=await new Promise(resolve=>{const listener=backend.app.listen(0,"127.0.0.1",()=>resolve(listener));});
    const base=`http://127.0.0.1:${server.address().port}`;
    async function request(path,{method="GET",body,staff=false}={}){const response=await fetch(base+path,{method,headers:{...(body?{"content-type":"application/json"}:{}),...(staff?{authorization:"Bearer booking-fixture"}:{})},body:body?JSON.stringify(body):undefined});let result;try{result=await response.json();}catch{result=null;}return{status:response.status,body:result};}
    let sequence=0;
    async function agreement({signed=true,deposit=0,paid=0,duration=60,roles=["customer"]}={}){
      const id=randomUUID(),quote=randomUUID();sequence++;
      const line={id:randomUUID(),service_id:null,name:"Windows",description:"Published scope",qty:1,price_cents:20000};
      await pool.query("INSERT INTO quotes(id,user_id,company_id,contact_id,line_items,total_cents) VALUES($1,$2,$3,$4,$5::jsonb,20000)",[quote,owner,company,contact,JSON.stringify([line])]);
      const snapshot={required_signers:roles,allow_customer_booking:true,duration_minutes:duration,pricing:{line_items:[line],total_cents:20000,deposit_cents:deposit},documents:[]};
      const row=(await pool.query("INSERT INTO quote_agreements(id,company_id,quote_id,contact_id,created_by,number,revision,request_id,title,snapshot,packet_hash) VALUES($1,$2,$3,$4,$5,$6,1,$7,'Window service',$8::jsonb,$9) RETURNING *",[id,company,quote,contact,owner,String(sequence),randomUUID(),JSON.stringify(snapshot),randomUUID()])).rows[0];
      if(signed)for(const role of roles)await sign(row,role);
      if(paid)await pool.query("INSERT INTO payment_records(id,company_id,agreement_id,contact_id,user_id,amount_cents,currency,status) VALUES($1,$2,$3,$4,$5,$6,'usd','succeeded')",[randomUUID(),company,id,contact,owner,paid]);
      return{row,token:service.makeToken(row)};
    }
    async function sign(row,role){const session=randomUUID();await pool.query("INSERT INTO agreement_signing_sessions(id,agreement_id,role,token_hash,token_generation,expires_at,verification_method) VALUES($1,$2,$3,$4,1,now()+interval '1 day','link')",[session,row.id,role,randomUUID()]);await pool.query("INSERT INTO agreement_signatures(id,agreement_id,session_id,role,request_id,request_hash,printed_name,consent_text,signature,field_values,packet_hash,verification_method,submitted_at) VALUES($1,$2,$3,$4,$5,'fixture','Signer','Consent','{}','{}',$6,'link',now())",[randomUUID(),row.id,session,role,randomUUID(),row.packet_hash]);}
    const slots=async item=>adapter.availability(item.token);
    const book=(item,slot,requestID=randomUUID())=>request(`/api/public/agreements/${item.token}/book`,{method:"POST",body:{request_id:requestID,slot_token:slot.slot_token}});
    await t.test("migration retains old overlap, unrelated edits work, new conflicting assignment fails",async()=>{
      assert.equal((await pool.query("SELECT count(*)::int AS n FROM schedule_events WHERE id=ANY($1::text[])",[[legacyA.id,legacyB.id]])).rows[0].n,2);
      await pool.query("UPDATE schedule_events SET notes='Retain original job' WHERE id=$1",[legacyA.id]);
      await assert.rejects(insertJob(),error=>error.code==="23P01");
      await installAgreementBookingSchema(pool);
      assert.equal((await pool.query("SELECT count(*)::int AS n FROM schedule_resource_reservations WHERE NOT enforced")).rows[0].n,2);
      await pool.query("DELETE FROM schedule_events WHERE id=ANY($1::text[])",[[legacyA.id,legacyB.id]]);
    });
    await t.test("availability and direct booking gated by all signatures and confirmed deposit",async()=>{
      const item=await agreement({signed:false,deposit:1000,roles:["customer","business"]});
      assert.equal((await request(`/api/public/agreements/${item.token}/availability`)).status,409);
      assert.equal((await book(item,{slot_token:"invalid"})).status,409);
      await sign(item.row,"customer");assert.equal((await request(`/api/public/agreements/${item.token}/availability`)).status,409);
      await sign(item.row,"business");assert.equal((await request(`/api/public/agreements/${item.token}/availability`)).status,409);
      await pool.query("INSERT INTO payment_records(id,company_id,agreement_id,contact_id,user_id,amount_cents,currency,status) VALUES($1,$2,$3,$4,$5,1000,'usd','processing')",[randomUUID(),company,item.row.id,contact,owner]);
      assert.equal((await request(`/api/public/agreements/${item.token}/availability`)).status,409);
      await pool.query("UPDATE payment_records SET status='succeeded' WHERE agreement_id=$1",[item.row.id]);
      const available=await slots(item);assert.ok(available.slots.length);assert.equal(available.suggested_days.length,4);
      assert.ok(!JSON.stringify(available).includes(worker));assert.ok(!JSON.stringify(available).includes("Private customer"));assert.ok(!JSON.stringify(available).includes("duration"));
    });
    await t.test("concurrent tabs create one actual job and replay across adapter restart",async()=>{
      const item=await agreement(),available=await slots(item),slot=available.slots[0],requestID=randomUUID();
      const results=await Promise.all(Array.from({length:8},()=>book(item,slot,requestID)));
      assert.ok(results.every(r=>r.status===200),JSON.stringify(results));
      assert.equal(new Set(results.map(r=>r.body.booking.job_id)).size,1);
      assert.equal((await pool.query("SELECT count(*)::int n FROM schedule_events WHERE quote_id=$1",[item.row.quote_id])).rows[0].n,1);
      assert.equal((await service.state(pool,item.row)).booking,"booked");
      const restart=createAgreementBooking({pool,service,env,now:()=>instant});assert.equal((await restart.book(item.token,{request_id:requestID,slot_token:slot.slot_token})).booking.job_id,results[0].body.booking.job_id);
      assert.equal((await book(item,available.slots[1],requestID)).status,409);
      await adapter.processOutbox();assert.equal(effects.length,1);await adapter.processOutbox();assert.equal(effects.length,1);
    });
    await t.test("actual staff route and public request racing the same worker admit exactly one",async()=>{
      const item=await agreement(),slot=(await slots(item)).slots.find(s=>s.date==="2030-01-03");
      const staff=request(`/api/schedule/${randomUUID()}`,{method:"PUT",staff:true,body:{title:"Staff appointment",start:slot.start_at,end:new Date(new Date(slot.start_at).getTime()+3600000).toISOString(),worker_user_ids:[worker],sales_user_ids:[]}});
      const results=await Promise.all([staff,book(item,slot)]);assert.deepEqual(results.map(r=>r.status).sort(),[200,409],JSON.stringify(results));
    });
    await t.test("automation-shaped direct SQL and multi-worker changes cannot bypass exclusion",async()=>{
      const time={start:"2030-01-04T14:00Z",end:"2030-01-04T15:00Z"};
      const results=await Promise.allSettled([insertJob({...time,workers:[worker,otherWorker]}),insertJob({...time,workers:[otherWorker]})]);
      assert.equal(results.filter(r=>r.status==="fulfilled").length,1);assert.equal(results.find(r=>r.status==="rejected").reason.code,"23P01");
      const busy=results.find(r=>r.status==="fulfilled").value;
      const target=await insertJob({start:"2030-01-04T16:00Z",end:"2030-01-04T17:00Z",workers:[otherWorker]});
      await assert.rejects(pool.query("UPDATE schedule_events SET start_at=$2,end_at=$3 WHERE id=$1",[target.id,time.start,time.end]),e=>e.code==="23P01");
      assert.equal(new Date((await pool.query("SELECT start_at FROM schedule_events WHERE id=$1",[target.id])).rows[0].start_at).toISOString(),"2030-01-04T16:00:00.000Z");
      await pool.query("DELETE FROM schedule_events WHERE id=ANY($1::text[])",[[target.id,busy.id]]);
    });
    await t.test("unassigned staff jobs and public bookings cannot race past each other",async()=>{
      const item=await agreement(),slot=(await slots(item)).slots.find(s=>s.date==="2030-01-05");
      const results=await Promise.allSettled([insertJob({workers:[],start:slot.start_at,end:new Date(new Date(slot.start_at).getTime()+3600000).toISOString()}),adapter.book(item.token,{request_id:randomUUID(),slot_token:slot.slot_token})]);
      assert.equal(results.filter(r=>r.status==="fulfilled").length,1,JSON.stringify(results));
    });
    await t.test("coordinated weather-shaped moves validate final state and rollback an invalid batch",async()=>{
      const a=await insertJob({start:"2030-01-06T14:00Z",end:"2030-01-06T15:00Z"}),b=await insertJob({start:"2030-01-06T15:00Z",end:"2030-01-06T16:00Z"});
      const db=await pool.connect();try{await db.query("BEGIN");await db.query("SET CONSTRAINTS schedule_resource_no_overlap, schedule_resource_legacy_guard DEFERRED");await db.query("UPDATE schedule_events SET start_at=start_at+interval '1 hour',end_at=end_at+interval '1 hour' WHERE id=ANY($1::text[])",[[a.id,b.id]]);await db.query("COMMIT");
      await db.query("BEGIN");await db.query("SET CONSTRAINTS schedule_resource_no_overlap, schedule_resource_legacy_guard DEFERRED");await db.query("UPDATE schedule_events SET start_at='2030-01-06T17:00Z',end_at='2030-01-06T18:00Z' WHERE id=ANY($1::text[])",[[a.id,b.id]]);await assert.rejects(db.query("COMMIT"),e=>e.code==="23P01");}finally{await db.query("ROLLBACK");db.release();}
      assert.equal(new Date((await pool.query("SELECT start_at FROM schedule_events WHERE id=$1",[a.id])).rows[0].start_at).toISOString(),"2030-01-06T15:00:00.000Z");
    });
    await t.test("settings, staff occupancy, forged tokens and disabled crew invalidate old choices",async()=>{
      const item=await agreement(),available=await slots(item),slot=available.slots.find(s=>s.date==="2030-01-07");
      assert.equal((await book(item,{slot_token:slot.slot_token.slice(0,-1)+"X"})).status,409);
      await insertJob({start:slot.start_at,end:new Date(new Date(slot.start_at).getTime()+3600000).toISOString()});assert.equal((await book(item,slot)).status,409);
      const old=(await slots(item)).slots[0],settings=await adapter.settings({companyId:company});await adapter.settings({companyId:company},{...settings,expected_version:settings.version,buffer_before_minutes:5});assert.equal((await book(item,old)).status,409);
      await assert.rejects(adapter.settings({companyId:company},{...settings,expected_version:settings.version}),e=>e.code==="booking_settings_conflict");
    });
    await t.test("reschedule/cancel preserve evidence, free resources and never change payment records",async()=>{
      const item=await agreement(),slot=(await slots(item)).slots.find(s=>s.date==="2030-01-08"),created=await book(item,slot);assert.equal(created.status,200,JSON.stringify(created));
      const next=(await adapter.availability(item.token,{reschedule:"true"})).slots.find(s=>s.date==="2030-01-09"),requestID=randomUUID();
      const changed=await adapter.change(item.token,{action:"reschedule",request_id:requestID,slot_token:next.slot_token});assert.equal(changed.booking.job_id,created.body.booking.job_id);assert.equal(changed.booking.status,"rescheduled");
      const before=(await pool.query("SELECT count(*)::int n FROM payment_records")).rows[0].n;
      const canceled=await adapter.change(item.token,{action:"cancel",request_id:randomUUID()});assert.equal(canceled.booking.status,"canceled");assert.equal(canceled.booking.booking_id,null);
      assert.equal((await pool.query("SELECT count(*)::int n FROM payment_records")).rows[0].n,before);
      assert.equal((await pool.query("SELECT count(*)::int n FROM schedule_events WHERE id=$1",[created.body.booking.job_id])).rows[0].n,0);
      const history=(await pool.query("SELECT type FROM agreement_events WHERE agreement_id=$1",[item.row.id])).rows.map(e=>e.type);assert.ok(history.includes("booking_created"));assert.ok(history.includes("booking_rescheduled"));assert.ok(history.includes("booking_canceled"));
      assert.equal((await pool.query("SELECT count(*)::int n FROM agreement_booking_history WHERE booking_id=$1",[created.body.booking.id])).rows[0].n,2);
    });
    await t.test("existing staff appointments appear without offering a duplicate customer booking",async()=>{
      const item=await agreement(),job=await insertJob({start:"2030-01-10T19:00Z",end:"2030-01-10T20:00Z"});
      await pool.query("UPDATE schedule_events SET quote_id=$2,contact_id=$3 WHERE id=$1",[job.id,item.row.quote_id,contact]);
      const summary=await adapter.bookingSummary(pool,item.row);assert.equal(summary.job_id,job.id);assert.equal(summary.arranged_by_business,true);assert.equal(summary.can_reschedule,false);
      assert.equal((await service.state(pool,item.row)).booking,"booked");await assert.rejects(slots(item),e=>e.code==="booking_already_booked");
    });
    await t.test("settings endpoint avoids legacy schedule id route, and foreign resources are rejected",async()=>{
      const current=await request("/api/schedule/booking/settings",{staff:true});assert.equal(current.status,200);
      const updated=await request("/api/schedule/booking/settings",{method:"PUT",staff:true,body:{...current.body,expected_version:current.body.version}});assert.equal(updated.status,200,JSON.stringify(updated));
      await assert.rejects(adapter.settings({companyId:company},{...updated.body,expected_version:updated.body.version,resource_bundles:[{...bundle,worker_user_ids:[randomUUID()]}]}),e=>e.code==="booking_resource_invalid");
    });
  }finally{if(server)await new Promise(resolve=>server.close(resolve));if(pool)await pool.end();pg.stop();}
});
