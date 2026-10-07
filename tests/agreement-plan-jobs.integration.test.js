import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {providerDouble} from './helpers/plan-provider-double.js';
import {installAgreementSchema,createAgreementService} from '../quote-agreements.js';
import {installAgreementPayments} from '../agreement-payments.js';
import {installAgreementPlanSchema,createAgreementPlans} from '../agreement-plans.js';
import {installAgreementPlanBilling} from '../agreement-plan-billing.js';
import {installAgreementBooking} from '../agreement-booking.js';
import {installGoogleSheetsSchema} from '../google-sheets.js';
import {installOperationalAccountingSchema} from '../finance-operational-accounting.js';
import {buildPlanOffer,normalizePlanTier} from '../agreement-plans-domain.js';
import {calculateQuotePricing} from '../quote-contract-domain.js';

test('contact membership owns full completed-job collection across real booking and staff routes',{timeout:90000},async t=>{
 const pg=startLocalPostgres();pg.configureEnvironment();process.env.STRIPE_SECRET_KEY='sk_test_fixture_local_only';let pool,server;
 try {
  const backend=await import('../index.js');pool=backend.pool;await backend.bootstrap();
  await installAgreementSchema(pool);await installGoogleSheetsSchema(pool);await installOperationalAccountingSchema(pool);
  const company=randomUUID(),owner=randomUUID(),serviceID=randomUUID(),extraID=randomUUID();
  await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id,timezone,business_days,business_open_time,business_close_time) VALUES($1,'Job billing','JOB-BILL',$2,'America/New_York','[1,2,3,4,5,6,7]','09:00','17:00')",[company,owner]);
  await pool.query("INSERT INTO users(id,email,role,company_id) VALUES($1,'job-owner@example.invalid','employer',$2)",[owner,company]);
  await pool.query("INSERT INTO sessions(token,user_id) VALUES('job-billing-fixture',$1)",[owner]);
  await pool.query("INSERT INTO business_settings(user_id,company_id,stripe_account_id) VALUES($1,$2,'acct_plan_fixture')",[owner,company]);
  for(const id of [serviceID,extraID]) await pool.query("INSERT INTO saved_services(id,company_id,name,plan_eligible,created_by,updated_by) VALUES($1,$2,$3,$4,$5,$5)",[id,company,id===serviceID?'Windows':'Pressure washing',id===serviceID,owner]);
  const stripe=providerDouble(),env={STRIPE_SECRET_KEY:'sk_test_fixture',QUOTE_LINK_SECRET:'test-job-billing-link-secret-longer-than32chars',QUOTE_PUBLIC_BASE_URL:'https://example.invalid'};
  const service=createAgreementService({pool,env,getStripe:()=>stripe});
  const payments=await installAgreementPayments({app:backend.app,pool,service,env,getStripe:()=>stripe,startWorker:false});
  await installAgreementPlanSchema(pool);
  const plans=createAgreementPlans({pool,service});
  const billing=await installAgreementPlanBilling({app:backend.app,pool,service,plans,env,getStripe:()=>stripe,startWorker:false});
  const booking=await installAgreementBooking({app:backend.app,pool,service,env,authRequired:backend.authRequired,requireCapability:backend.requireCapability,startWorker:false});
  backend.app.locals.agreementPlans=plans;
  await booking.settings({companyId:company},{expected_version:1,enabled:true,minimum_notice_minutes:0,resource_bundles:[{id:randomUUID(),name:'Crew',worker_user_ids:[owner],service_ids:[],all_services:true,enabled:true}]});
  server=await new Promise(resolve=>{const s=backend.app.listen(0,'127.0.0.1',()=>resolve(s));});const base=`http://127.0.0.1:${server.address().port}`;
  const request=async(path,body,method='POST')=>{const response=await fetch(base+path,{method,headers:{authorization:'Bearer job-billing-fixture','content-type':'application/json'},body:JSON.stringify(body)});return {status:response.status,body:await response.json()};};
  let number=0;
  async function packet(contact,snapshot,quote=null){return (await pool.query("INSERT INTO quote_agreements(id,company_id,quote_id,contact_id,created_by,number,revision,request_id,title,snapshot,packet_hash) VALUES($1,$2,$3,$4,$5,$6,1,$7,'Job',$8::jsonb,$9) RETURNING *",[randomUUID(),company,quote,contact,owner,String(++number),randomUUID(),JSON.stringify(snapshot),randomUUID()])).rows[0];}
  async function sign(row){const session=randomUUID();await pool.query("INSERT INTO agreement_signing_sessions(id,agreement_id,role,token_hash,token_generation,expires_at,verification_method) VALUES($1,$2,'customer',$3,1,now()+interval '1 day','link')",[session,row.id,randomUUID()]);await pool.query("INSERT INTO agreement_signatures(id,agreement_id,session_id,role,request_id,request_hash,printed_name,consent_text,signature,field_values,packet_hash,verification_method,submitted_at) VALUES($1,$2,$3,'customer',$4,'fixture','Synthetic customer','Fixture consent','{}','{}',$5,'link',now())",[randomUUID(),row.id,session,randomUUID(),row.packet_hash]);}
  const lines=(extras=false)=>[{id:randomUUID(),service_id:serviceID,name:'Windows',qty:1,price_cents:15000},...(extras?[{id:randomUUID(),service_id:extraID,name:'Pressure washing',qty:1,price_cents:50000}]:[])];
  async function fixture({extras=false,activate=true,legacy=false,discountFirst=true,windowPrice=15000,serviced=false}={}){
   const contact=randomUUID(),quote=randomUUID(),items=lines(extras).map(l=>l.service_id===serviceID?{...l,price_cents:windowPrice}:l),pricing=calculateQuotePricing({line_items:items});
   await pool.query("INSERT INTO contacts(id,user_id,company_id,name) VALUES($1,$2,$3,'Synthetic job customer')",[contact,owner,company]);
   await pool.query('INSERT INTO quotes(id,user_id,company_id,contact_id,line_items,total_cents) VALUES($1,$2,$3,$4,$5::jsonb,$6)',[quote,owner,company,contact,JSON.stringify(items),pricing.total_cents]);
   const row=await packet(contact,{kind:'quote',required_signers:['customer'],allow_customer_booking:true,duration_minutes:60,offer_service_plans:true,pricing},quote);await sign(row);
   const configuration=normalizePlanTier({name:'Bronze',discount:{type:'fixed',value:5000},discount_first_visit:discountFirst,service_interval:{unit:'month',count:6},term:{kind:'ongoing'},billing:{mode:'automatic_per_visit'},agreement:{agreement_text:'Care plan',consent_text:'I agree',required_signers:['customer']},cancellation_policy:'Cancel anytime'});
   const tier={tier_id:randomUUID(),version:1,configuration};await pool.query('INSERT INTO service_plan_tiers(tier_id,version,company_id,configuration,created_by) VALUES($1,1,$2,$3::jsonb,$4)',[tier.tier_id,company,JSON.stringify(configuration),owner]);
   const offer=buildPlanOffer({agreement:row,tier,eligible_service_ids:[serviceID],serviced,today:new Date().toISOString().slice(0,10)});if(legacy)delete offer.collection_model;
   const planAgreement=await packet(contact,{kind:'plan',required_signers:['customer'],pricing:null,financial_terms:offer});await sign(planAgreement);
   const enrollment=(await pool.query("INSERT INTO agreement_plan_enrollments(id,company_id,contact_id,base_agreement_id,plan_agreement_id,tier_id,tier_version,collection_key,request_id,request_hash,offer_hash,snapshot) VALUES($1,$2,$3,$4,$5,$6,1,$7,$8,'fixture',$9,$10::jsonb) RETURNING *",[randomUUID(),company,contact,row.id,planAgreement.id,tier.tier_id,`quote:${quote}`,randomUUID(),offer.offer_hash,JSON.stringify(offer)])).rows[0];
   const item={contact,quote,row,enrollment,token:service.makeToken(row),items};
   if(activate)await activatePlan(item);return item;
  }
  async function activatePlan(item){await billing.begin(item.token,item.enrollment.id,{request_id:randomUUID()});const setup=(await pool.query('SELECT session_id FROM agreement_plan_setups WHERE enrollment_id=$1',[item.enrollment.id])).rows[0];stripe.completeSetup(setup.session_id);await billing.begin(item.token,item.enrollment.id,{request_id:randomUUID()});}
  async function staffJob(item,{items=item.items,quote=false}={}){const id=randomUUID(),start=new Date(Date.now()+86400000+number*7200000);const result=await request(`/api/schedule/${id}`,{title:'Customer job',contact_id:item.contact,quote_id:quote?item.quote:null,start:start.toISOString(),end:new Date(+start+3600000).toISOString(),service_items:items,services:items.map(l=>l.name),price_cents:items.reduce((n,l)=>n+l.price_cents*(l.qty||1),0),worker_user_ids:[]},'PUT');assert.equal(result.status,200,JSON.stringify(result));return result.body;}
  const complete=job=>request(`/api/jobs/${job}/workflow/complete`,{snapshot:[]});
  const owed=async item=>(await pool.query('SELECT * FROM agreement_plan_billing_obligations WHERE enrollment_id=$1',[item.enrollment.id])).rows;
  await t.test('OFF retains $200 initial quote and charges $150 on the next covered appointment',async()=>{
   const item=await fixture({discountFirst:false,windowPrice:20000});
   assert.equal((await payments.paymentSummary(pool,item.row)).total_cents,20000);
   const available=await booking.availability(item.token),result=await booking.book(item.token,{request_id:randomUUID(),slot_token:available.slots[0].slot_token});
   const first=(await pool.query('SELECT * FROM schedule_events WHERE id=$1',[result.booking.job_id])).rows[0];assert.equal(first.price_cents,20000);
   const second=await staffJob(item);assert.equal(second.price_cents,15000);
   // Completion order cannot transfer a quoted initial price to another job.
   await complete(second.id);await complete(first.id);await complete(first.id);
   const amounts=(await owed(item)).map(o=>o.amount_cents).sort((a,b)=>a-b);assert.deepEqual(amounts,[15000,20000]);
   const summary=await payments.paymentSummary(pool,item.row);assert.equal(summary.total_cents,20000);assert.equal(summary.paid_cents,20000);assert.equal(summary.balance_cents,0);
  });
  await t.test('OFF mixed job includes all $700 initially and $650 on subsequent visits',async()=>{
   const item=await fixture({discountFirst:false,windowPrice:20000,extras:true}),first=await staffJob(item),second=await staffJob(item);
   assert.equal(first.price_cents,70000);assert.equal(second.price_cents,65000);
   const before=stripe.counts().pays;await complete(first.id);await complete(second.id);await complete(first.id);
   assert.deepEqual((await owed(item)).map(o=>o.amount_cents).sort((a,b)=>a-b),[65000,70000]);assert.equal(stripe.counts().pays,before+2);
  });
  await t.test('extra-only completion and cancellation do not consume the undiscounted first service',async()=>{
   const item=await fixture({discountFirst:false,windowPrice:20000});
   const extra=await staffJob(item,{items:lines(true).slice(1)});await complete(extra.id);
   const first=await staffJob(item);assert.equal(first.price_cents,20000);
   await pool.query('DELETE FROM schedule_events WHERE id=$1',[first.id]);
   const replacement=await staffJob(item);assert.equal(replacement.price_cents,20000);
   await complete(replacement.id);assert.equal((await staffJob(item)).price_cents,15000);
  });
  await t.test('ON discounts first service; enrollment after initial service does not restart first-service exclusion',async()=>{
   for(const options of [{discountFirst:true},{discountFirst:false,serviced:true}]){
    const item=await fixture({...options,windowPrice:20000}),job=await staffJob(item);assert.equal(job.price_cents,15000);
    await complete(job.id);assert.equal((await owed(item))[0].amount_cents,15000);
   }
  });
  await t.test('customer books the initial quote, confirms, completes: automatic $100 and no ordinary duplicate',async()=>{
   const item=await fixture(),available=await booking.availability(item.token);
   const result=await booking.book(item.token,{request_id:randomUUID(),slot_token:available.slots[0].slot_token}),jobID=result.booking.job_id;
   const job=(await pool.query('SELECT * FROM schedule_events WHERE id=$1',[jobID])).rows[0];assert.ok(job.service_plan_id);assert.equal(job.price_cents,10000);
   const detail=await plans.detail(pool,(await pool.query('SELECT * FROM agreement_plan_enrollments WHERE id=$1',[item.enrollment.id])).rows[0]);assert.equal(detail.visits[0].job_id,jobID);
   assert.equal((await owed(item)).length,0);
   await assert.rejects(payments.checkout(item.token,{request_id:randomUUID(),kind:'balance'}),e=>e.code==='payment_managed_by_plan');
   const replies=await Promise.all([complete(jobID),complete(jobID)]);assert.ok(replies.every(r=>r.status===200),JSON.stringify(replies));
   const rows=await owed(item);assert.equal(rows.length,1);assert.equal(rows[0].amount_cents,10000);assert.equal(rows[0].state,'succeeded');
   const summary=await payments.paymentSummary(pool,item.row);assert.equal(summary.total_cents,10000);assert.equal(summary.paid_cents,10000);assert.equal(summary.balance_cents,0);assert.equal(summary.can_pay_balance,false);
   await complete(jobID);assert.equal((await owed(item)).length,1);
  });
  await t.test('mixed completed job charges exactly $600, with server pricing and one frozen obligation',async()=>{
   const item=await fixture({extras:true}),job=await staffJob(item);assert.equal(job.price_cents,60000);
   const before=stripe.counts().pays;assert.equal((await complete(job.id)).status,200);
   assert.equal((await owed(item))[0].amount_cents,60000);assert.equal(stripe.counts().pays,before+1);
   await complete(job.id);assert.equal(stripe.counts().pays,before+1);
   await assert.rejects(pool.query('UPDATE schedule_events SET price_cents=1 WHERE id=$1',[job.id]),e=>e.message==='completed_plan_job_price_immutable');
  });
  await t.test('extra-only jobs collect once without consuming the covered service cycle',async()=>{
   const item=await fixture(),job=await staffJob(item,{items:lines(true).slice(1)});assert.equal(job.price_cents,50000);assert.equal((await complete(job.id)).status,200);
   const rows=await owed(item);assert.equal(rows.length,1);assert.equal(rows[0].kind,'job');assert.equal(rows[0].amount_cents,50000);
   assert.equal((await pool.query("SELECT count(*)::int n FROM agreement_plan_visits WHERE enrollment_id=$1 AND state='completed'",[item.enrollment.id])).rows[0].n,0);
  });
  await t.test('activation associates existing upcoming jobs, then a confirmed deposit is credited once',async()=>{
   const item=await fixture({activate:false}),job=await staffJob(item,{quote:true});assert.equal(job.price_cents,15000);
   await pool.query("INSERT INTO payment_records(id,user_id,company_id,contact_id,quote_id,job_id,amount_cents,currency,status) VALUES($1,$2,$3,$4,$5,$6,2500,'usd','succeeded')",[randomUUID(),owner,company,item.contact,item.quote,job.id]);
   await activatePlan(item);assert.equal((await pool.query('SELECT price_cents FROM schedule_events WHERE id=$1',[job.id])).rows[0].price_cents,10000);
   assert.equal((await complete(job.id)).status,200);assert.equal((await owed(item))[0].amount_cents,7500);assert.equal((await payments.paymentSummary(pool,item.row)).balance_cents,0);
  });
  await t.test('old covered-only consent does not silently authorize extras; completion and review remain visible',async()=>{
   const item=await fixture({legacy:true,extras:true}),job=await staffJob(item);const before=stripe.counts().pays;
   assert.equal((await complete(job.id)).status,200);assert.equal((await owed(item)).length,0);assert.equal(stripe.counts().pays,before);
   const summary=await billing.billingSummary(item.enrollment.id);assert.equal(summary.jobs[0].error_code,'plan_job_authorization_required');assert.equal(summary.needs_review,true);
  });
  await t.test('prior full payment produces no additional provider collection',async()=>{
   const item=await fixture(),job=await staffJob(item,{quote:true});await pool.query("INSERT INTO payment_records(id,user_id,company_id,contact_id,quote_id,job_id,amount_cents,currency,status) VALUES($1,$2,$3,$4,$5,$6,15000,'usd','succeeded')",[randomUUID(),owner,company,item.contact,item.quote,job.id]);
   const before=stripe.counts().pays;await complete(job.id);assert.equal((await owed(item))[0].amount_cents,0);assert.equal(stripe.counts().pays,before);
  });
  await t.test('a pending payment blocks collection, then reconciliation collects only after cancellation',async()=>{
   const item=await fixture(),job=await staffJob(item),payment=randomUUID();
   await pool.query("INSERT INTO payment_records(id,user_id,company_id,contact_id,job_id,amount_cents,currency,status) VALUES($1,$2,$3,$4,$5,10000,'usd','processing')",[payment,owner,company,item.contact,job.id]);
   const before=stripe.counts().pays;await complete(job.id);assert.equal((await owed(item)).length,0);assert.equal(stripe.counts().pays,before);
   await pool.query("UPDATE payment_records SET status='canceled' WHERE id=$1",[payment]);
   await billing.reconcileEnrollment(item.enrollment.id);assert.equal((await owed(item))[0].amount_cents,10000);assert.equal(stripe.counts().pays,before+1);
   await billing.reconcileEnrollment(item.enrollment.id);assert.equal(stripe.counts().pays,before+1);
  });
  await t.test('several upcoming covered jobs get different visits and cancellation releases the reservation',async()=>{
   const item=await fixture(),first=await staffJob(item);number++;
   const second=await staffJob(item);
   let visits=(await pool.query('SELECT * FROM agreement_plan_visits WHERE enrollment_id=$1 ORDER BY sequence',[item.enrollment.id])).rows;
   assert.equal(visits.length,2);assert.equal(visits[0].job_id,first.id);assert.equal(visits[1].job_id,second.id);
   await pool.query('DELETE FROM schedule_events WHERE id=$1',[first.id]);number++;
   const replacement=await staffJob(item);visits=(await pool.query('SELECT * FROM agreement_plan_visits WHERE enrollment_id=$1 ORDER BY sequence',[item.enrollment.id])).rows;
   assert.equal(visits.length,2);assert.equal(visits[0].job_id,replacement.id);
   assert.equal((await complete(second.id)).status,200);assert.equal((await complete(replacement.id)).status,200);
   assert.equal((await owed(item)).length,2);
  });
  await t.test('covered rates remain capped at the signed scope price and extras can be added before completion',async()=>{
   const item=await fixture(),job=await staffJob(item);
   const items=[{...item.items[0],price_cents:20000},...lines(true).slice(1)];
   const updated=await request(`/api/schedule/${job.id}`,{...job,service_items:items,services:items.map(l=>l.name),price_cents:70000},'PUT');
   assert.equal(updated.status,200,JSON.stringify(updated));assert.equal(updated.body.price_cents,60000);
   assert.equal((await complete(job.id)).status,200);assert.equal((await owed(item))[0].amount_cents,60000);
  });
  await t.test('approved extras added to a customer-booked quote job are included in its single full charge',async()=>{
   const item=await fixture(),available=await booking.availability(item.token),result=await booking.book(item.token,{request_id:randomUUID(),slot_token:available.slots.at(-1).slot_token});
   const row=(await pool.query('SELECT * FROM schedule_events WHERE id=$1',[result.booking.job_id])).rows[0];
   const updated=await request(`/api/schedule/${row.id}`,{title:row.title,start:row.start_at,end:row.end_at,contact_id:item.contact,quote_id:item.quote,service_items:[...item.items,...lines(true).slice(1)],services:['Windows','Pressure washing'],price_cents:65000,worker_user_ids:[owner]},'PUT');
   assert.equal(updated.status,200,JSON.stringify(updated));assert.equal(updated.body.price_cents,60000);
   assert.equal((await complete(row.id)).status,200);assert.equal((await owed(item))[0].amount_cents,60000);
   const summary=await payments.paymentSummary(pool,item.row);assert.equal(summary.total_cents,60000);assert.equal(summary.paid_cents,60000);assert.equal(summary.balance_cents,0);
  });
 }finally{if(server)await new Promise(r=>server.close(r));if(pool)await pool.end();pg.stop();}
});
