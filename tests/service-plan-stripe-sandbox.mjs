// Explicit opt-in acceptance runner. Uses real Stripe TEST mode and disposable
// PostgreSQL only. Never run by npm test; no production DB connection is opened.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import Stripe from 'stripe';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {installOperationalAccountingSchema} from '../finance-operational-accounting.js';
import {installAgreementSchema,createAgreementService} from '../quote-agreements.js';
import {installAgreementPayments} from '../agreement-payments.js';
import {installAgreementPlanSchema,createAgreementPlans} from '../agreement-plans.js';
import {installAgreementPlanBilling} from '../agreement-plan-billing.js';
import {buildPlanOffer} from '../agreement-plans-domain.js';
import {calculateQuotePricing} from '../quote-contract-domain.js';
assert.equal(process.env.WOLF_PLAN_SANDBOX_ACCEPTANCE,'true');
const input=JSON.parse(fs.readFileSync(process.env.WOLF_PLAN_SANDBOX_CONFIG));
assert.ok(input.key.startsWith('sk_test_'));assert.ok(input.account.startsWith('acct_'));
const stripe=new Stripe(input.key,{apiVersion:'2024-06-20',timeout:20000,maxNetworkRetries:1});
const opts={stripeAccount:input.account};
const pg=startLocalPostgres();pg.configureEnvironment();
let pool;
const report={mode:'test',database:'disposable local PostgreSQL',customer_consent:'synthetic local test signatures; existing production Checkout consent verified separately',checks:[]};
try{
 const backend=await import('../index.js');pool=backend.pool;await backend.bootstrap();await installAgreementSchema(pool);await installOperationalAccountingSchema(pool);await installAgreementPlanSchema(pool);
 const company=randomUUID(),owner=randomUUID(),contact=randomUUID();
 await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id,timezone) VALUES($1,'Sandbox acceptance','SP-TEST',$2,'America/New_York')",[company,owner]);
 await pool.query("INSERT INTO users(id,email,role,company_id) VALUES($1,'sandbox@example.invalid','employer',$2)",[owner,company]);
 await pool.query("INSERT INTO contacts(id,user_id,company_id,name) VALUES($1,$2,$3,'Synthetic sandbox customer')",[contact,owner,company]);
 await pool.query("INSERT INTO business_settings(user_id,company_id,stripe_account_id) VALUES($1,$2,$3)",[owner,company,input.account]);
 const env={STRIPE_SECRET_KEY:input.key,QUOTE_LINK_SECRET:'sandbox-fixture-local-only-at-least32characters',QUOTE_PUBLIC_BASE_URL:'https://example.invalid'};
 const service=createAgreementService({pool,env,getStripe:()=>stripe});await installAgreementPayments({app:backend.app,pool,service,env,getStripe:()=>stripe,startWorker:false});
 const plans=createAgreementPlans({pool,service});const billing=await installAgreementPlanBilling({app:backend.app,pool,service,plans,env,getStripe:()=>stripe,startWorker:false});
 async function packet(snapshot){const id=randomUUID();const row=(await pool.query("INSERT INTO quote_agreements(id,company_id,contact_id,created_by,number,revision,request_id,title,snapshot,packet_hash) VALUES($1,$2,$3,$4,$5,1,$6,'Sandbox fixture',$7::jsonb,$8) RETURNING *",[id,company,contact,owner,id,randomUUID(),JSON.stringify(snapshot),randomUUID()])).rows[0];const session=randomUUID();await pool.query("INSERT INTO agreement_signing_sessions(id,agreement_id,role,token_hash,token_generation,expires_at,verification_method) VALUES($1,$2,'customer',$3,1,now()+interval '1 day','link')",[session,id,randomUUID()]);await pool.query("INSERT INTO agreement_signatures(id,agreement_id,session_id,role,request_id,request_hash,printed_name,consent_text,signature,field_values,packet_hash,verification_method,submitted_at) VALUES($1,$2,$3,'customer',$4,'fixture','Automated fixture','Synthetic fixture authorization','{}','{}',$5,'link',now())",[randomUUID(),id,session,randomUUID(),row.packet_hash]);return row;}
 for(const [fixture,expected] of [['pm_card_visa','succeeded'],['pm_card_chargeCustomerFail','failed'],['pm_card_authenticationRequired','requires_action']]){
  const tag=randomUUID();
  const customer=await stripe.customers.create({name:'WolfCRM automated sandbox acceptance',metadata:{wolfcrm_sandbox_acceptance:tag}}, {...opts,idempotencyKey:`acceptance-customer:${tag}`});assert.equal(customer.livemode,false);
  let method,setup;
  if(expected!=='requires_action'){
   setup=await stripe.setupIntents.create({customer:customer.id,payment_method:fixture,payment_method_types:['card'],usage:'off_session',confirm:true},{...opts,idempotencyKey:`acceptance-setup:${tag}`});assert.equal(setup.status,'succeeded');method=await stripe.paymentMethods.retrieve(setup.payment_method,{},opts);
  }else{
   // Always-authenticate fixture intentionally cannot complete browser 3DS here.
   // Attach it only to this isolated synthetic test customer to exercise failure.
   method=await stripe.paymentMethods.attach(fixture,{customer:customer.id},opts);
  }
  assert.equal(method.customer,customer.id);assert.equal(method.livemode,false);
  const line={id:randomUUID(),service_id:randomUUID(),name:'Covered service',qty:1,price_cents:5000};
  const base=await packet({kind:'quote',required_signers:['customer'],pricing:calculateQuotePricing({line_items:[line]})});
  const config={name:'Six month $50 sandbox',discount:{type:'none',value:0},service_interval:{unit:'month',count:6},term:{kind:'ongoing'},billing:{mode:'automatic_per_visit',collect_on:'completed'},cancellation_policy:'Cancel future work.',agreement:{agreement_text:'Sandbox terms',consent_text:'Authorize $50 after each completed visit',required_signers:['customer']}};
  const tier={tier_id:randomUUID(),version:1,configuration:config};const offer=buildPlanOffer({agreement:base,tier,eligible_service_ids:[line.service_id],today:'2026-10-06'});
  const agreement=await packet({kind:'plan',required_signers:['customer'],pricing:null,financial_terms:offer});
  await pool.query("INSERT INTO service_plan_tiers(tier_id,version,company_id,configuration,created_by) VALUES($1,1,$2,$3::jsonb,$4)",[tier.tier_id,company,JSON.stringify(config),owner]);
  const enrollment=(await pool.query("INSERT INTO agreement_plan_enrollments(id,company_id,contact_id,base_agreement_id,plan_agreement_id,tier_id,tier_version,collection_key,request_id,request_hash,offer_hash,snapshot,connected_account_id,stripe_livemode,stripe_customer_id,stripe_payment_method_id) VALUES($1,$2,$3,$4,$5,$6,1,$7,$8,'fixture',$9,$10::jsonb,$11,false,$12,$13) RETURNING *",[randomUUID(),company,contact,base.id,agreement.id,tier.tier_id,`agreement:${base.id}`,randomUUID(),offer.offer_hash,JSON.stringify(offer),input.account,customer.id,method.id])).rows[0];
  const detail=await plans.reconcileEnrollment(enrollment.id);assert.equal(detail.awaiting_first_appointment,true);
  const job=randomUUID(),req={companyId:company,userId:owner};
  await pool.query("INSERT INTO schedule_events(id,user_id,company_id,contact_id,title,start_at,end_at,service_items) VALUES($1,$2,$3,$4,'Covered sandbox service','2026-10-06T14:00:00-04:00','2026-10-06T15:00:00-04:00',$5::jsonb)",[job,owner,company,contact,JSON.stringify(offer.future_visit.line_items)]);
  await plans.linkVisit(req,enrollment.id,detail.visits[0].id,{job_id:job});
  await pool.query("UPDATE schedule_events SET finished_at='2026-10-06T15:00:00-04:00' WHERE id=$1",[job]);await plans.completeJob(req,job);
  const first=await billing.billingSummary(enrollment.id),owed=first.obligations[0];assert.equal(first.obligations.length,1);assert.equal(owed.amount_cents,5000);assert.equal(owed.payment_status,expected,JSON.stringify({expected,status:owed.payment_status,error:owed.error_code}));
  assert.ok(owed.hosted_invoice_url?.startsWith('https://invoice.stripe.com/'));
  const before=await stripe.paymentIntents.list({customer:customer.id,limit:100},opts);assert.equal(before.data.length,1);assert.equal(before.data[0].livemode,false);
  await plans.completeJob(req,job);await billing.reconcileEnrollment(enrollment.id);await billing.reconcileEnrollment(enrollment.id);
  const after=await stripe.paymentIntents.list({customer:customer.id,limit:100},opts);assert.equal(after.data.length,1);assert.equal(after.data[0].id,before.data[0].id);
  const plan=(await pool.query('SELECT first_visit_date::text,next_service_date::text FROM service_plans WHERE id=$1',[detail.service_plan_id])).rows[0];assert.equal(plan.first_visit_date,'2026-10-06');assert.equal(plan.next_service_date,'2027-04-06');
  const event={id:'evt_local_'+randomUUID(),account:input.account,livemode:false,type:expected==='succeeded'?'payment_intent.succeeded':'payment_intent.payment_failed',data:{object:after.data[0]}};
  assert.equal(await billing.handleWebhook(event),true);assert.equal(await billing.handleWebhook(event),true);
  assert.equal((await billing.billingSummary(enrollment.id)).obligations.length,1);
  report.checks.push({fixture,expected,result:'PASS',setup_intent:setup?.status||'3DS fixture attached for action-required test only',customer_exists:true,method_attached:true,first_visit:plan.first_visit_date,next_visit:plan.next_service_date,amount_cents:5000,payment_intents:1,payment_intent_id:after.data[0].id,provider_status:after.data[0].status,repeated_completion_and_webhook:'one obligation and PaymentIntent',hosted_recovery_link:true});
  console.log(JSON.stringify(report.checks.at(-1)));
 }
 report.status='PASS';
}catch(e){report.status='FAILED';report.error={code:e.code||e.type||'assertion',message:e.message};console.error(JSON.stringify(report.error));process.exitCode=1;}
finally{await pool?.end();pg.stop();fs.writeFileSync(process.env.WOLF_PLAN_SANDBOX_REPORT,JSON.stringify(report,null,2));}
