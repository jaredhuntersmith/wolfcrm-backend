import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {installAgreementSchema} from '../quote-agreements.js';
import {installAgreementPlanSchema} from '../agreement-plans.js';
import {installAgreementPlanBillingSchema} from '../agreement-plan-billing.js';
import {installServicePlanReview} from '../service-plan-review.js';
import {clearBusinessExceptions} from '../business-exceptions.js';
test('payment review preferences are private and ended obligations are opt-in; bulk exception dismissal preserves new and other-company records',{timeout:120000},async()=>{
 const local=startLocalPostgres();local.configureEnvironment();let pool,server;
 try{
  const backend=await import('../index.js');pool=backend.pool;await backend.bootstrap();await installAgreementSchema(pool);await installAgreementPlanSchema(pool);await installAgreementPlanBillingSchema(pool);
  const company=randomUUID(),other=randomUUID(),alice=randomUUID(),bob=randomUUID(),contact=randomUUID();
  await pool.query("INSERT INTO companies(id,name,join_code) VALUES($1,'A','REVIEWA'),($2,'B','REVIEWB')",[company,other]);
  for(const [id,name] of [[alice,'Alice'],[bob,'Bob']])await pool.query("INSERT INTO users(id,company_id,email,role) VALUES($1,$2,$3,'employer')",[id,company,name+'@example.invalid']);
  await pool.query("INSERT INTO contacts(id,user_id,company_id,name) VALUES($1,$2,$3,'Review customer')",[contact,alice,company]);
  const ids={};for(const status of ['payment_pending','past_due','failed','active','canceled']){const id=randomUUID();ids[status]=id;await pool.query("INSERT INTO service_plans(id,user_id,company_id,contact_id,plan_name,status,price_cents,billing_interval,service_interval) VALUES($1,$2,$3,$4,$5,$5,10000,'month','month')",[id,alice,company,contact,status]);}
  await pool.query("INSERT INTO payment_records(user_id,company_id,contact_id,service_plan_id,payment_type,status,amount_cents) VALUES($1,$2,$3,$4,'service_plan_recurring','pending',10000)",[alice,company,contact,ids.canceled]);
  const tier=randomUUID();await pool.query("INSERT INTO service_plan_tiers(tier_id,version,company_id,configuration,created_by) VALUES($1,1,$2,'{}',$3)",[tier,company,alice]);
  for(const canceled of [false,true]) {
   const agreement=randomUUID(),enrollment=randomUUID();
   await pool.query("INSERT INTO quote_agreements(id,company_id,contact_id,created_by,number,revision,request_id,title,snapshot,packet_hash) VALUES($1::uuid,$2,$3,$4,$1::uuid::text,1,$1,'Enrollment','{}',$5)",[agreement,company,contact,alice,'a'.repeat(64)]);
   await pool.query("INSERT INTO agreement_plan_enrollments(id,company_id,contact_id,base_agreement_id,plan_agreement_id,tier_id,tier_version,collection_key,request_id,request_hash,offer_hash,snapshot,state,canceled_at) VALUES($1::uuid,$2,$3,$4,$4,$5,1,$1::uuid::text,$1,$6,$6,$7,$8,$9)",[enrollment,company,contact,agreement,tier,'b'.repeat(64),JSON.stringify({configuration:{name:'Unactivated enrollment'}}),canceled?'canceled':'agreement_pending',canceled?new Date():null]);
   if(canceled)await pool.query("INSERT INTO payment_records(user_id,company_id,contact_id,enrollment_id,payment_type,status,amount_cents) VALUES($1,$2,$3,$4,'service_plan_recurring','processing',5000)",[alice,company,contact,enrollment]);
  }
  const app=express();app.use(express.json());await installServicePlanReview({app,pool,authRequired:(req,res,next)=>{req.userId=req.get('X-User')==='bob'?bob:alice;req.companyId=company;next();},requireCapability:()=>((req,res,next)=>next())});
  server=await new Promise(r=>{const s=app.listen(0,'127.0.0.1',()=>r(s));});
  const api=async(who,path='',body)=>{const r=await fetch(`http://127.0.0.1:${server.address().port}/api/service-plan-payment-review${path}`,{method:body?'PUT':'GET',headers:{'X-User':who,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});assert.equal(r.status,200,await r.clone().text());return r.json();};
  assert.deepEqual((await api('alice')).items.map(i=>i.status).sort(),['agreement_pending','payment_pending']);
  await api('alice','/settings',{include_pending:false,include_past_due:true,include_failed:true,include_ended:true});
  const reviewed=await api('alice');assert.equal(reviewed.items.find(i=>i.kind==='enrollment').amount_cents,'5000');assert.deepEqual(reviewed.items.map(i=>i.status).sort(),['canceled','canceled','failed','past_due']);assert.equal(reviewed.items.find(i=>i.plan_id===ids.canceled).amount_cents,'10000');
  assert.deepEqual((await api('bob')).items.map(i=>i.status).sort(),['agreement_pending','payment_pending']);assert.equal((await pool.query('SELECT status FROM payment_records')).rows[0].status,'pending','Review settings cannot change billing state');
  const reviewedAt=new Date(Date.now()-20000),older=new Date(reviewedAt-10000),newer=new Date(reviewedAt.getTime()+10000);
  for(const [name,c,status,detected,changed] of [['old',company,'open',older,older],['snoozed',company,'snoozed',older,older],['new',company,'open',newer,newer],['changed',company,'open',older,newer],['other',other,'open',older,older],['resolved',company,'resolved',older,older]])await pool.query("INSERT INTO business_exceptions(company_id,type,severity,source_type,source_id,fingerprint,title,explanation,recommended_action,status,detected_at,status_updated_at) VALUES($1,'test','low','test',$2,$2,$2,'test','review',$3,$4,$5)",[c,name,status,detected,changed]);
  assert.equal((await clearBusinessExceptions(pool,company,alice,{reviewed_before:reviewedAt.toISOString()})).cleared_count,2);
  assert.equal((await clearBusinessExceptions(pool,company,alice,{reviewed_before:reviewedAt.toISOString()})).cleared_count,0);
  const records=(await pool.query('SELECT source_id,status,status_updated_by FROM business_exceptions')).rows;assert.equal(records.length,6);assert.equal(records.find(r=>r.source_id==='old').status_updated_by,alice);for(const id of ['new','changed','other'])assert.equal(records.find(r=>r.source_id===id).status,'open');assert.equal(records.find(r=>r.source_id==='resolved').status,'resolved');
 }finally{if(server)await new Promise(r=>server.close(r));if(pool)await pool.end();local.stop();}
});
