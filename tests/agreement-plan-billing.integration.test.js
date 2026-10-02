import assert from "node:assert/strict";
import test from "node:test";
import {randomUUID} from "node:crypto";
import {installOperationalAccountingSchema} from "../finance-operational-accounting.js";
import {startLocalPostgres} from "./helpers/local-postgres.js";
import {installAgreementSchema,createAgreementService} from "../quote-agreements.js";
import {installAgreementPayments} from "../agreement-payments.js";
import {installAgreementPlanSchema,createAgreementPlans} from "../agreement-plans.js";
import {installAgreementPlanBilling,createAgreementPlanBilling} from "../agreement-plan-billing.js";
import {normalizePlanTier,buildPlanOffer} from "../agreement-plans-domain.js";
import {calculateQuotePricing} from "../quote-contract-domain.js";
import {installAgreementPlanCancellation} from "../agreement-plan-cancellation.js";

function providerDouble(){
  const objects={customers:new Map(),sessions:new Map(),methods:new Map(),setups:new Map(),invoices:new Map(),items:new Map(),intents:new Map()},keys=new Map();
  let calls=0,pays=0,loseKind=null,actionNext=false,processingNext=false,held=null;
  const copy=value=>structuredClone(value);
  async function mutate(kind,params,options,create){assert.equal(params.email,undefined);assert.equal(params.customer_email,undefined);assert.equal(params.receipt_email,undefined);assert.notEqual(params.collection_method,"send_invoice");assert.equal(options.stripeAccount,"acct_plan_fixture");assert.ok(options.idempotencyKey);const key=`${options.stripeAccount}:${kind}:${options.idempotencyKey}`;if(!keys.has(key)){calls++;keys.set(key,create(params));}if(held?.kind===kind){const current=held;held=null;current.started();await current.wait;}if(loseKind===kind){loseKind=null;throw new Error("Provider persisted response lost");}return copy(keys.get(key));}
  function scope(options){assert.equal(options.stripeAccount,"acct_plan_fixture");}
  const api={
    accounts:{retrieve:async()=>({charges_enabled:true,capabilities:{card_payments:"active"}})},
    customers:{create:async(p,o)=>mutate("customer",p,o,p=>{const value={id:`cus_${objects.customers.size+1}`,livemode:false,...p};objects.customers.set(value.id,value);return value;}),retrieve:async(id,_p,o)=>{scope(o);return copy(objects.customers.get(id));}},
    checkout:{sessions:{create:async(p,o)=>mutate("setup",p,o,p=>{assert.equal(p.mode,"setup");assert.equal(p.line_items,undefined);const value={id:`cs_${objects.sessions.size+1}`,livemode:false,...p,status:"open",setup_intent:null,url:`https://checkout.stripe.com/fixture-${objects.sessions.size+1}`};objects.sessions.set(value.id,value);return value;}),retrieve:async(id,_p,o)=>{scope(o);return copy(objects.sessions.get(id));},expire:async(id,p,o)=>mutate("expire",{id,...p},o,()=>{const session=objects.sessions.get(id);if(session.status!=="open")throw new Error("Session not open");session.status="expired";return session;})}},
    setupIntents:{retrieve:async(id,_p,o)=>{scope(o);return copy(objects.setups.get(id));}},
    paymentMethods:{retrieve:async(id,_p,o)=>{scope(o);return copy(objects.methods.get(id));}},
    paymentIntents:{retrieve:async(id,_p,o)=>{scope(o);return copy(objects.intents.get(id));}},
    invoiceItems:{create:async(p,o)=>mutate("item",p,o,p=>{const value={id:`ii_${objects.items.size+1}`,livemode:false,...p};objects.items.set(value.id,value);const invoice=objects.invoices.get(p.invoice);assert.equal(invoice.status,"draft");invoice.total+=p.amount;invoice.amount_due+=p.amount;return value;}),retrieve:async(id,_p,o)=>{scope(o);return copy(objects.items.get(id));}},
    invoices:{
      create:async(p,o)=>mutate("invoice",p,o,p=>{assert.equal(p.auto_advance,false);assert.equal(p.pending_invoice_items_behavior,"exclude");const value={id:`in_${objects.invoices.size+1}`,livemode:false,...p,status:"draft",total:0,amount_due:0,amount_paid:0,payment_intent:null,hosted_invoice_url:null,invoice_pdf:null};objects.invoices.set(value.id,value);return value;}),
      retrieve:async(id,_p,o)=>{scope(o);return copy(objects.invoices.get(id));},
      finalizeInvoice:async(id,p,o)=>mutate("finalize",{id,...p},o,()=>{const value=objects.invoices.get(id);value.status=value.total?"open":"paid";value.hosted_invoice_url=`https://invoice.stripe.com/${id}`;value.invoice_pdf=`https://invoice.stripe.com/${id}.pdf`;return value;}),
      pay:async(id,p,o)=>mutate("pay",{id,...p},o,()=>{pays++;const invoice=objects.invoices.get(id);assert.equal(p.off_session,true);const intent={id:`pi_${objects.intents.size+1}`,livemode:false,amount:invoice.total,currency:invoice.currency,customer:invoice.customer,status:actionNext?"requires_action":processingNext?"processing":"succeeded",latest_charge:null};actionNext=false;processingNext=false;objects.intents.set(intent.id,intent);invoice.payment_intent=intent;if(intent.status==="succeeded")settle(id);return invoice;}),
      voidInvoice:async(id,p,o)=>mutate("void",{id,...p},o,()=>{const invoice=objects.invoices.get(id);if(invoice.payment_intent?.status==="processing")throw new Error("Already processing");if(invoice.status!=="open")throw new Error("Not open");invoice.status="void";return invoice;}),
      del:async(id,p,o)=>mutate("delete",{id,...p},o,()=>{objects.invoices.delete(id);return{id,deleted:true};})
    },
    completeSetup(id,{wrongCustomer=false}={}){const session=objects.sessions.get(id);const method={id:`pm_${objects.methods.size+1}`,livemode:false,customer:wrongCustomer?"cus_foreign":session.customer,type:"card",card:{brand:"visa",last4:"4242",exp_month:12,exp_year:2035}};objects.methods.set(method.id,method);const intent={id:`seti_${objects.setups.size+1}`,livemode:false,customer:session.customer,payment_method:method,status:"succeeded"};objects.setups.set(intent.id,intent);session.setup_intent=intent;session.status="complete";},
    settle,lose(kind){loseKind=kind;},hold(kind){let started,release;const ready=new Promise(resolve=>started=resolve),wait=new Promise(resolve=>release=resolve);held={kind,started,wait};return{ready,release};},requiresAction(){actionNext=true;},processing(){processingNext=true;},objects,counts:()=>({calls,pays})
  };
  function settle(id){const invoice=objects.invoices.get(id);if(!invoice.payment_intent){const intent={id:`pi_${objects.intents.size+1}`,livemode:false,amount:invoice.total,currency:invoice.currency,customer:invoice.customer,status:"succeeded"};objects.intents.set(intent.id,intent);invoice.payment_intent=intent;}const intent=invoice.payment_intent;intent.status="succeeded";intent.latest_charge={id:`ch_${intent.id}`,amount_refunded:0,disputed:false,receipt_url:`https://pay.stripe.com/receipts/${intent.id}`};invoice.status="paid";invoice.amount_paid=invoice.amount_due;}
  return api;
}

test("signed plan billing is durable, scoped and exact against PostgreSQL and fake provider boundary",{timeout:90000},async t=>{
  const postgres=startLocalPostgres();postgres.configureEnvironment();process.env.STRIPE_SECRET_KEY="sk_test_fixture_local_only";let pool,server;
  try{
    const backend=await import("../index.js");pool=backend.pool;await backend.bootstrap();await installAgreementSchema(pool);await installOperationalAccountingSchema(pool);
    const company=randomUUID(),owner=randomUUID(),contact=randomUUID(),serviceID=randomUUID();
    await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id,timezone) VALUES($1,'Plan business','PLAN-BILL',$2,'America/New_York')",[company,owner]);
    await pool.query("INSERT INTO agreement_number_sequences(company_id,last_number) VALUES($1,10000)",[company]);
    await pool.query("INSERT INTO users(id,email,role,company_id) VALUES($1,'plan-owner@example.invalid','employer',$2)",[owner,company]);
    await pool.query("INSERT INTO contacts(id,user_id,company_id,name,email) VALUES($1,$2,$3,'Customer','customer@example.invalid')",[contact,owner,company]);
    await pool.query("INSERT INTO business_settings(user_id,company_id,stripe_account_id) VALUES($1,$2,'acct_plan_fixture')",[owner,company]);
    await pool.query("INSERT INTO saved_services(id,company_id,name,plan_eligible,created_by,updated_by) VALUES($1,$2,'Windows',true,$3,$3)",[serviceID,company,owner]);
    await pool.query("INSERT INTO sessions(token,user_id) VALUES('plan-billing-fixture',$1)",[owner]);
    const env={QUOTE_LINK_SECRET:"fixture-plan-billing-link-secret-at-least32characters",QUOTE_PUBLIC_BASE_URL:"https://example.invalid",STRIPE_SECRET_KEY:"sk_test_fixture"};
    const stripe=providerDouble(),service=createAgreementService({pool,env,getStripe:()=>stripe});
    await installAgreementPayments({app:backend.app,pool,service,env,getStripe:()=>stripe,startWorker:false});await installAgreementPlanSchema(pool);
    const plans=createAgreementPlans({pool,service}),clock={date:new Date()};
    const adapter=await installAgreementPlanBilling({app:backend.app,pool,service,plans,env,getStripe:()=>stripe,startWorker:false,now:()=>clock.date});
    const cancellation=await installAgreementPlanCancellation({app:backend.app,pool,service,plans,billing:adapter,authRequired:backend.authRequired,requireCapability:backend.requireCapability,startWorker:false});
    backend.app.locals.agreementPlans=plans;
    server=await new Promise(resolve=>{const listener=backend.app.listen(0,"127.0.0.1",()=>resolve(listener));});const base=`http://127.0.0.1:${server.address().port}`;
    let sequence=0;
    const today=()=>new Intl.DateTimeFormat('en-CA',{timeZone:'America/New_York',year:'numeric',month:'2-digit',day:'2-digit'}).format(clock.date);
    async function sign(row){const session=randomUUID();await pool.query("INSERT INTO agreement_signing_sessions(id,agreement_id,role,token_hash,token_generation,expires_at,verification_method) VALUES($1,$2,'customer',$3,1,now()+interval '1 day','link')",[session,row.id,randomUUID()]);await pool.query("INSERT INTO agreement_signatures(id,agreement_id,session_id,role,request_id,request_hash,printed_name,consent_text,signature,field_values,packet_hash,verification_method,submitted_at) VALUES($1,$2,$3,'customer',$4,'fixture','Signer','Consent','{}','{}',$5,'link',now())",[randomUUID(),row.id,session,randomUUID(),row.packet_hash]);}
    async function packet(snapshot,quote=null){const id=randomUUID();sequence++;return(await pool.query("INSERT INTO quote_agreements(id,company_id,quote_id,contact_id,created_by,number,revision,request_id,title,snapshot,packet_hash) VALUES($1,$2,$3,$4,$5,$6,1,$7,'Service',$8::jsonb,$9) RETURNING *",[id,company,quote,contact,owner,String(sequence),randomUUID(),JSON.stringify(snapshot),randomUUID()])).rows[0];}
    async function enrollment({mode="calendar_installments",signed=true,fee=0,delay=0,term="finite",notice=0,saveCard=false,completion=false,interval=1}={}){
      const line={id:randomUUID(),service_id:serviceID,name:"Windows",qty:1,price_cents:30000,description:"All exterior windows"},quote=randomUUID();
      await pool.query("INSERT INTO quotes(id,user_id,company_id,contact_id,line_items,total_cents) VALUES($1,$2,$3,$4,$5::jsonb,30000)",[quote,owner,company,contact,JSON.stringify([line])]);
      const baseRow=await packet({kind:"quote",required_signers:["customer"],allow_customer_booking:false,offer_service_plans:true,pricing:calculateQuotePricing({line_items:[line]}),business:{name:"Plan business",address:"Business address",phone:"",email:"",logo_data_url:""},customer:{name:"Customer",address:"Service address",billing_address:"Billing address"}},quote);await sign(baseRow);
      const config=normalizePlanTier({name:"Quarterly care",agreement:{agreement_text:"Membership terms",consent_text:"I authorize the stated agreement.",required_signers:["customer"]},cancellation_policy:"Cancel under the stated notice. No automatic refund.",cancellation_notice_days:notice,allow_pause:true,discount:{type:"percent",value:1500},term:{kind:term,visit_count:4},service_interval:{unit:"month",count:3},billing:{mode,save_payment_method:saveCard,calendar_requires_completed_service:completion,interval:{unit:"month",count:interval},installment_count:12,first_charge_delay_days:delay,enrollment_fee_cents:fee}});
      const tier={tier_id:randomUUID(),version:1,configuration:config};await pool.query("INSERT INTO service_plan_tiers(tier_id,version,company_id,configuration,created_by) VALUES($1,1,$2,$3::jsonb,$4)",[tier.tier_id,company,JSON.stringify(config),owner]);
      const offer=buildPlanOffer({agreement:baseRow,tier,eligible_service_ids:[serviceID],today:today()});
      const planRow=await packet({kind:"plan",required_signers:["customer"],pricing:null,allow_customer_booking:false,financial_terms:offer});if(signed)await sign(planRow);
      const row=(await pool.query("INSERT INTO agreement_plan_enrollments(id,company_id,contact_id,base_agreement_id,plan_agreement_id,tier_id,tier_version,collection_key,request_id,request_hash,offer_hash,snapshot) VALUES($1,$2,$3,$4,$5,$6,1,$7,$8,'fixture',$9,$10::jsonb) RETURNING *",[randomUUID(),company,contact,baseRow.id,planRow.id,tier.tier_id,`quote:${quote}`,randomUUID(),offer.offer_hash,JSON.stringify(offer)])).rows[0];return{row,baseRow,planRow,token:service.makeToken(baseRow)};
    }
    const begin=(item,extra={})=>adapter.begin(item.token,item.row.id,{request_id:randomUUID(),...extra});
    const stored=async item=>(await pool.query("SELECT * FROM agreement_plan_enrollments WHERE id=$1",[item.row.id])).rows[0];
    const obligations=async item=>(await pool.query("SELECT *,due_date::text AS due_date FROM agreement_plan_billing_obligations WHERE enrollment_id=$1 ORDER BY sequence",[item.row.id])).rows;
    async function finishSetup(item){const setup=(await pool.query("SELECT * FROM agreement_plan_setups WHERE enrollment_id=$1 ORDER BY created_at DESC LIMIT 1",[item.row.id])).rows[0];stripe.completeSetup(setup.session_id);return begin(item);}
    await t.test("signatures and explicit recurring authorization are required before any provider call",async()=>{
      const item=await enrollment({signed:false}),before=stripe.counts().calls;
      await assert.rejects(begin(item),error=>error.code==="plan_signatures_required");assert.equal(stripe.counts().calls,before);
      await sign(item.planRow);await pool.query("UPDATE agreement_plan_enrollments SET snapshot=jsonb_set(snapshot,'{financial_text}','\"No automatic debit authorization\"'::jsonb) WHERE id=$1",[item.row.id]);
      // A free-form billing-body claim cannot replace signed packet authorization.
      await pool.query("UPDATE agreement_plan_enrollments SET snapshot=jsonb_set(snapshot,'{financial_text}','\"Terms only\"'::jsonb) WHERE id=$1",[item.row.id]);
      await assert.rejects(begin(item,{consent:true}),error=>error.code==="plan_automatic_authorization_missing");
    });
    await t.test("concurrent setup is one no-charge session; verified card enables exact first installment",async()=>{
      const item=await enrollment(),before=stripe.counts().pays,results=await Promise.all(Array.from({length:5},()=>begin(item)));
      assert.equal(new Set(results.map(r=>r.url)).size,1);assert.equal(stripe.counts().pays,before);
      assert.equal((await stored(item)).service_plan_id,null);
      const done=await finishSetup(item);assert.equal(done.enrollment.state,"active");
      const invoices=await obligations(item);assert.equal(invoices.length,12);assert.ok(invoices.every(i=>i.amount_cents===8500));assert.equal(invoices[0].state,"succeeded");assert.ok(invoices.slice(1).every(i=>i.state==="scheduled"));
      const records=(await pool.query("SELECT * FROM payment_records WHERE enrollment_id=$1",[item.row.id])).rows;assert.equal(records.length,1);assert.equal(records[0].amount_cents,8500);assert.equal(records[0].agreement_id,item.planRow.id);assert.equal(records[0].quote_id,null);
      assert.equal((await service.paymentSummary(pool,item.baseRow)).paid_cents,0,"future membership invoices cannot settle the base job");
      const count=stripe.counts().pays;await begin(item);await plans.reconcileEnrollment(item.row.id);assert.equal(stripe.counts().pays,count);
    });
    await t.test("lost setup response and process restart reuse the same durable provider command",async()=>{
      const item=await enrollment({delay:10});stripe.lose("setup");await assert.rejects(begin(item));const setup=(await pool.query("SELECT * FROM agreement_plan_setups WHERE enrollment_id=$1",[item.row.id])).rows[0];assert.equal(setup.session_id,null);
      const restarted=createAgreementPlanBilling({pool,service,plans,env,getStripe:()=>stripe,now:()=>clock.date});const result=await restarted.begin(item.token,item.row.id,{request_id:randomUUID()});assert.ok(result.url);
      assert.equal([...stripe.objects.sessions.values()].filter(s=>s.metadata.wolfcrm_enrollment_id===item.row.id).length,1);
      await finishSetup(item);assert.equal((await stored(item)).state,"active");assert.equal((await obligations(item))[0].state,"scheduled");
    });
    await t.test("pending activation cannot collect later installments even when their dates pass",async()=>{
      const item=await enrollment();await begin(item);
      const setup=(await pool.query("SELECT * FROM agreement_plan_setups WHERE enrollment_id=$1",[item.row.id])).rows[0];stripe.completeSetup(setup.session_id);
      const original=clock.date;clock.date=new Date(clock.date.getTime()+100*86400000);
      try{
        await adapter.reconcileEnrollment(item.row.id);await adapter.reconcileEnrollment(item.row.id);
        assert.equal((await stored(item)).service_plan_id,null);
        assert.equal((await obligations(item)).filter(o=>o.state==="succeeded").length,1);
        await plans.reconcileEnrollment(item.row.id);assert.ok((await stored(item)).service_plan_id);
        await adapter.reconcileEnrollment(item.row.id);
        assert.ok((await obligations(item)).filter(o=>o.state==="succeeded").length>1);
      }finally{clock.date=original;}
    });
    await t.test("wrong customer card cannot satisfy setup, stale unknown command cannot start a replacement",async()=>{
      const item=await enrollment();await begin(item);const setup=(await pool.query("SELECT * FROM agreement_plan_setups WHERE enrollment_id=$1",[item.row.id])).rows[0];stripe.completeSetup(setup.session_id,{wrongCustomer:true});await assert.rejects(begin(item),e=>e.code==="plan_method_scope_mismatch");assert.equal((await stored(item)).service_plan_id,null);
      const lost=await enrollment();stripe.lose("customer");await assert.rejects(begin(lost));await pool.query("UPDATE agreement_plan_provider_commands SET created_at=now()-interval '25 hours' WHERE enrollment_id=$1",[lost.row.id]);const count=stripe.counts().calls;await assert.rejects(begin(lost),e=>e.code==="plan_billing_review_required");assert.equal(stripe.counts().calls,count);
    });
    await t.test("additional authentication and asynchronous processing do not activate until actual paid",async()=>{
      const item=await enrollment();await begin(item);stripe.requiresAction();const result=await finishSetup(item);assert.equal(result.kind,"payment");assert.ok(result.url);assert.equal((await stored(item)).service_plan_id,null);
      const obligation=(await obligations(item))[0];
      assert.equal(obligation.payment_status,'requires_action');assert.ok(obligation.attention_since);
      const beforeAttention=await adapter.followupContext(pool,{id:item.row.base_agreement_id,company_id:company});assert.equal(beforeAttention.plan_payment_attention_occurrence,obligation.id);
      await adapter.reconcileEnrollment(item.row.id);
      assert.equal((await pool.query("SELECT count(*)::int n FROM agreement_events WHERE agreement_id=$1 AND type='plan_payment_failed' AND payload->>'obligation_id'=$2",[item.row.base_agreement_id,obligation.id])).rows[0].n,1);
      stripe.settle(obligation.invoice_id);await plans.reconcileEnrollment(item.row.id);assert.ok((await stored(item)).service_plan_id);
      assert.equal((await adapter.followupContext(pool,{id:item.row.base_agreement_id,company_id:company})).plan_payment_attention,undefined);
      const processing=await enrollment();await begin(processing);stripe.processing();await finishSetup(processing);assert.equal((await stored(processing)).service_plan_id,null);const pending=(await obligations(processing))[0];assert.equal(pending.state,"processing");stripe.settle(pending.invoice_id);await plans.reconcileEnrollment(processing.row.id);assert.ok((await stored(processing)).service_plan_id);
    });
    await t.test("manual membership without fee needs no card, prepaid and fee use hosted one-time invoices",async()=>{
      const free=await enrollment({mode:"manual_per_visit"}),before=stripe.counts().calls;assert.equal((await begin(free)).status,"ready");assert.equal(stripe.counts().calls,before);
      for(const mode of ["manual_per_visit","prepaid"]){const item=await enrollment({mode,fee:500});const result=await begin(item);assert.equal(result.kind,"payment");assert.ok(result.url);assert.equal((await stored(item)).stripe_payment_method_id,null);assert.equal((await stored(item)).service_plan_id,null);const due=(await obligations(item))[0];assert.equal(due.amount_cents,mode==="prepaid"?102500:500);stripe.settle(due.invoice_id);await plans.reconcileEnrollment(item.row.id);assert.ok((await stored(item)).service_plan_id);}
    });
    await t.test("manual plan saves a customer-authorized card without enabling automatic debits",async()=>{
      const item=await enrollment({mode:"manual_per_visit",saveCard:true});const before=stripe.counts().pays;
      const setup=await begin(item);assert.equal(setup.kind,"setup");assert.equal((await stored(item)).service_plan_id,null);
      const done=await finishSetup(item);assert.equal(done.enrollment.state,"active");assert.ok((await stored(item)).stripe_payment_method_id);assert.equal(stripe.counts().pays,before);
    });
    await t.test("ongoing calendar payments keep one future date and collect exactly once on each cadence",async()=>{
      const original=clock.date;
      try{
        const item=await enrollment({mode:"calendar_recurring",term:"ongoing",interval:6});await begin(item);await finishSetup(item);
        const first=await obligations(item);assert.equal(first.length,2);assert.equal(first[0].state,"succeeded");assert.equal(first[0].amount_cents,25500);
        for(let i=0;i<4;i++)await adapter.reconcileEnrollment(item.row.id);
        assert.equal((await obligations(item)).length,2,"polling must not append distant future charges");
        clock.date=new Date(first[1].due_date+"T18:00:00Z");await Promise.all([1,2,3].map(()=>adapter.reconcileEnrollment(item.row.id)));
        const after=await obligations(item);assert.equal(after.filter(row=>row.state==="succeeded").length,2);assert.equal(after.length,3);
      }finally{clock.date=original;}
    });
    await t.test("calendar completion gate waits for the corresponding finished job, then charges once",async()=>{
      const item=await enrollment({mode:"calendar_recurring",term:"ongoing",interval:3,completion:true});await begin(item);await finishSetup(item);
      const enrolled=await stored(item);assert.ok(enrolled.service_plan_id);assert.ok((await obligations(item)).every(row=>row.state==="scheduled"));
      const visit=(await pool.query('SELECT * FROM agreement_plan_visits WHERE enrollment_id=$1 ORDER BY sequence',[item.row.id])).rows[0],job=randomUUID();
      await pool.query("INSERT INTO schedule_events(id,user_id,company_id,contact_id,title,start_at,end_at,service_items) VALUES($1,$2,$3,$4,'Completed plan visit',now(),now()+interval '1 hour',$5::jsonb)",[job,owner,company,contact,JSON.stringify(enrolled.snapshot.future_visit.line_items)]);
      await plans.linkVisit({companyId:company,userId:owner},item.row.id,visit.id,{job_id:job});await adapter.reconcileEnrollment(item.row.id);assert.ok((await obligations(item)).every(row=>row.state==="scheduled"));
      await pool.query('UPDATE schedule_events SET finished_at=now() WHERE id=$1',[job]);await plans.processMemberships();
      await Promise.all([1,2,3].map(()=>adapter.reconcileEnrollment(item.row.id)));
      const after=await obligations(item);assert.equal(after.filter(row=>row.state==="succeeded").length,1);assert.equal(after[0].job_id,job);
    });
    await t.test("manual and automatic per-visit billing use one actual completed visit, including final expired entitlement",async()=>{
      for(const mode of ["manual_per_visit","automatic_per_visit"]){
        const item=await enrollment({mode});await begin(item);if(mode==="automatic_per_visit")await finishSetup(item);
        const enrolled=await stored(item),plan=(await pool.query("SELECT * FROM service_plans WHERE id=$1",[enrolled.service_plan_id])).rows[0];
        const visit=(await pool.query("SELECT * FROM agreement_plan_visits WHERE enrollment_id=$1 ORDER BY sequence LIMIT 1",[item.row.id])).rows[0];
        await adapter.reconcileEnrollment(item.row.id);assert.equal((await obligations(item)).length,0,"date-only visit never charges");
        const job=randomUUID();await pool.query("INSERT INTO schedule_events(id,user_id,company_id,contact_id,service_plan_id,title,start_at,end_at,finished_at,service_items) VALUES($1,$2,$3,$4,$5,'Plan visit',now()-interval '2 hours',now()-interval '1 hour',now()-interval '1 hour',$6::jsonb)",[job,owner,company,contact,plan.id,JSON.stringify(item.row.snapshot.future_visit.line_items)]);
        await pool.query("UPDATE agreement_plan_visits SET job_id=$2,state='completed',completed_at=now() WHERE id=$1",[visit.id,job]);
        await pool.query("UPDATE service_plans SET status='expired',remaining_visits=0 WHERE id=$1",[plan.id]);
        const before=stripe.counts().pays,result=await begin(item),owed=await obligations(item);assert.equal(owed.length,1);assert.equal(owed[0].job_id,job);assert.equal(owed[0].amount_cents,25500);
        if(mode==="manual_per_visit"){assert.equal(result.kind,"payment");assert.ok(result.url);assert.equal(stripe.counts().pays,before);stripe.settle(owed[0].invoice_id);}else assert.equal(owed[0].state,"succeeded");
        await plans.reconcileEnrollment(item.row.id);await begin(item);assert.equal((await pool.query("SELECT count(*)::int n FROM payment_records WHERE enrollment_id=$1",[item.row.id])).rows[0].n,1);
      }
    });
    await t.test("unknown invoice item and payment outcomes retry exact commands without duplicating invoice items or charges",async()=>{
      const item=await enrollment({mode:"prepaid"});stripe.lose("item");await assert.rejects(begin(item));const due=(await obligations(item))[0];assert.ok(due.invoice_id);const again=await begin(item);assert.ok(again.url);assert.equal([...stripe.objects.items.values()].filter(i=>i.invoice===due.invoice_id).length,1);
      const auto=await enrollment();await begin(auto);stripe.lose("pay");await finishSetup(auto);assert.equal((await obligations(auto))[0].state,"succeeded");const count=stripe.counts().pays;await begin(auto);assert.equal(stripe.counts().pays,count);
    });
    await t.test("renewals have separate ledger rows, exact twelve installments, and no thirteenth renewal",async()=>{
      const item=await enrollment();await begin(item);await finishSetup(item);const rows=await obligations(item);const original=clock.date;
      for(let i=1;i<12;i++){clock.date=new Date(`${String(rows[i].due_date).slice(0,10)}T17:00Z`);await plans.reconcileEnrollment(item.row.id);}
      const paid=(await pool.query("SELECT * FROM payment_records WHERE enrollment_id=$1 ORDER BY created_at",[item.row.id])).rows;assert.equal(paid.length,12);assert.equal(paid.reduce((sum,p)=>sum+p.amount_cents,0),102000);assert.equal(new Set(paid.map(p=>p.stripe_invoice_id)).size,12);assert.ok(paid.every(p=>p.status==="succeeded"));
      clock.date=new Date(clock.date.getTime()+400*86400000);await plans.reconcileEnrollment(item.row.id);assert.equal((await pool.query("SELECT count(*)::int n FROM payment_records WHERE enrollment_id=$1",[item.row.id])).rows[0].n,12);clock.date=original;
    });
    await t.test("refund/dispute review stops later invoices and wrong account/mode cannot mutate the ledger",async()=>{
      const item=await enrollment();await begin(item);await finishSetup(item);const due=(await obligations(item))[0],invoice=stripe.objects.invoices.get(due.invoice_id);invoice.payment_intent.latest_charge.amount_refunded=1000;
      assert.equal(await adapter.handleWebhook({account:"acct_wrong",livemode:false,type:"invoice.paid",data:{object:invoice}}),false);
      assert.equal(await adapter.handleWebhook({account:"acct_plan_fixture",livemode:true,type:"invoice.paid",data:{object:invoice}}),false);
      await adapter.handleWebhook({account:"acct_plan_fixture",livemode:false,type:"charge.refunded",data:{object:{object:"charge",id:invoice.payment_intent.latest_charge.id,payment_intent:invoice.payment_intent.id}}});
      assert.equal((await obligations(item))[0].state,"review");const before=stripe.counts().pays,original=clock.date;clock.date=new Date(clock.date.getTime()+40*86400000);await plans.reconcileEnrollment(item.row.id);assert.equal(stripe.counts().pays,before);clock.date=original;
    });
    await t.test("raw signed invoice callbacks retrieve provider truth and deduplicate delivery",async()=>{
      const item=await enrollment({mode:"prepaid"});await begin(item);const due=(await obligations(item))[0],invoice=stripe.objects.invoices.get(due.invoice_id);
      const {default:Stripe}=await import("stripe"),sdk=new Stripe("sk_test_fixture_local_only");process.env.STRIPE_WEBHOOK_SECRET="whsec_plan_fixture";
      async function callback(eventID){const event={id:eventID,object:"event",type:"invoice.payment_succeeded",created:Math.floor(Date.now()/1000),livemode:false,account:"acct_plan_fixture",data:{object:{...invoice,status:"paid",amount_paid:invoice.amount_due}}};const payload=JSON.stringify(event),signature=sdk.webhooks.generateTestHeaderString({payload,secret:process.env.STRIPE_WEBHOOK_SECRET});const response=await fetch(base+"/stripe/webhook",{method:"POST",headers:{"content-type":"application/json","stripe-signature":signature},body:payload});assert.equal(response.status,200,await response.text());}
      await callback("evt_plan_stale_fixture");assert.equal((await stored(item)).service_plan_id,null);
      stripe.settle(invoice.id);await callback("evt_plan_settled_fixture");await callback("evt_plan_settled_fixture");assert.ok((await stored(item)).service_plan_id);
      assert.equal((await pool.query("SELECT attempt_count FROM stripe_webhook_events WHERE stripe_event_id='evt_plan_settled_fixture'")).rows[0].attempt_count,1);
      assert.equal((await pool.query("SELECT count(*)::int n FROM payment_records WHERE enrollment_id=$1",[item.row.id])).rows[0].n,1);
    });
    await t.test("signed membership terms and legacy provider path cannot bypass preserved consent",async()=>{
      const item=await enrollment();await begin(item);await finishSetup(item);const plan=(await pool.query("SELECT * FROM service_plans WHERE enrollment_id=$1",[item.row.id])).rows[0];
      await assert.rejects(pool.query("UPDATE service_plans SET price_cents=1 WHERE id=$1",[plan.id]),e=>e.code==="23514");
      const response=await fetch(`${base}/api/service-plans/${plan.id}`,{method:"PUT",headers:{authorization:"Bearer plan-billing-fixture","content-type":"application/json"},body:JSON.stringify({price_cents:1})});assert.equal(response.status,409);
      await adapter.changeMembership({companyId:company,userId:owner},plan,"pause",{request_id:randomUUID()});const paid=stripe.counts().pays;await adapter.reconcileEnrollment(item.row.id);assert.equal(stripe.counts().pays,paid);
      const paused=(await pool.query("SELECT * FROM service_plans WHERE id=$1",[plan.id])).rows[0];await adapter.changeMembership({companyId:company,userId:owner},paused,"cancel",{request_id:randomUUID()});assert.ok((await stored(item)).canceled_at);assert.ok((await obligations(item)).slice(1).every(o=>o.state==="review"),"canceling membership must not silently forgive a finite payment commitment");
      await assert.rejects(adapter.changeMembership({companyId:company,userId:owner},plan,"resume",{request_id:randomUUID()}),e=>e.code==="plan_cannot_resume");
    });
    await t.test("pending cancellation preserves evidence, expires setup and voids unpaid invoices before reselection",async()=>{
      for(const mode of ['calendar_installments','prepaid']){
        const item=await enrollment({mode});await begin(item);const requestID=randomUUID();
        const results=await Promise.all(Array.from({length:3},()=>cancellation.publicCancel(item.token,item.row.id,{request_id:requestID})));assert.ok(results.every(result=>result.status==='canceled'),JSON.stringify(results));
        assert.ok((await stored(item)).canceled_at);assert.equal((await pool.query('SELECT count(*)::int n FROM agreement_signatures WHERE agreement_id=$1',[item.planRow.id])).rows[0].n,1);
        assert.equal((await service.state(pool,(await pool.query('SELECT * FROM quote_agreements WHERE id=$1',[item.planRow.id])).rows[0])).can_sign,false);
        assert.equal((await pool.query("SELECT count(*)::int n FROM agreement_events WHERE agreement_id=$1 AND type='plan_pending_canceled'",[item.planRow.id])).rows[0].n,1);
        if(mode==='calendar_installments'){const setup=(await pool.query('SELECT * FROM agreement_plan_setups WHERE enrollment_id=$1',[item.row.id])).rows[0];assert.equal(stripe.objects.sessions.get(setup.session_id).status,'expired');}
        else assert.ok((await obligations(item)).every(item=>item.state==='canceled'));
        const offered=(await plans.offers(pool,item.baseRow)).find(offer=>offer.tier_id!==item.row.tier_id);assert.ok(offered);
        const replacement=await plans.createEnrollment(item.token,{request_id:randomUUID(),tier_id:offered.tier_id,tier_version:offered.tier_version,offer_hash:offered.offer_hash});assert.notEqual(replacement.id,item.row.id);
      }
    });
    await t.test("unknown and already in-flight provider commands cannot be abandoned or replaced",async()=>{
      const unknown=await enrollment();stripe.lose('setup');await assert.rejects(begin(unknown));const before=stripe.counts().calls;
      assert.equal((await cancellation.publicCancel(unknown.token,unknown.row.id,{request_id:randomUUID()})).status,'cancellation_pending');assert.equal((await stored(unknown)).canceled_at,null);
      await assert.rejects(begin(unknown),error=>error.code==='plan_cancellation_pending');assert.equal(stripe.counts().calls,before);
      const item=await enrollment(),held=stripe.hold('setup'),pending=begin(item);await held.ready;
      assert.equal((await cancellation.publicCancel(item.token,item.row.id,{request_id:randomUUID()})).status,'cancellation_pending');assert.equal((await stored(item)).canceled_at,null);
      held.release();await pending;await cancellation.processPending();assert.ok((await stored(item)).canceled_at);assert.equal((await stored(item)).service_plan_id,null);
    });
    await t.test("processing or paid enrollment money retains its ledger and prevents reselection",async()=>{
      const item=await enrollment();await begin(item);stripe.processing();await finishSetup(item);
      const result=await cancellation.publicCancel(item.token,item.row.id,{request_id:randomUUID()});assert.equal(result.status,'cancellation_pending');assert.equal((await stored(item)).canceled_at,null);assert.equal((await obligations(item))[0].state,'processing');
      stripe.settle((await obligations(item))[0].invoice_id);await cancellation.processPending();assert.equal((await stored(item)).canceled_at,null);assert.equal((await obligations(item))[0].state,'succeeded');assert.equal((await stored(item)).service_plan_id,null);
    });
    await t.test("lost cancellation response and draft invoice creation converge without a replacement charge",async()=>{
      const item=await enrollment({mode:'prepaid'});await begin(item);stripe.lose('void');const result=await cancellation.publicCancel(item.token,item.row.id,{request_id:randomUUID()});assert.equal(result.status,'cancellation_pending');await cancellation.processPending();assert.ok((await stored(item)).canceled_at);
      const draft=await enrollment({mode:'prepaid'}),held=stripe.hold('invoice'),starting=begin(draft);await held.ready;await cancellation.publicCancel(draft.token,draft.row.id,{request_id:randomUUID()});held.release();await starting;
      stripe.lose('delete');await cancellation.processPending();assert.equal((await stored(draft)).canceled_at,null);await cancellation.processPending();assert.ok((await stored(draft)).canceled_at);assert.equal((await obligations(draft))[0].state,'canceled');
    });
    await t.test("active cancellation preserves unpaid completed-visit money for settlement",async()=>{
      const item=await enrollment({mode:'manual_per_visit'});await begin(item);const enrolled=await stored(item),plan=(await pool.query('SELECT * FROM service_plans WHERE id=$1',[enrolled.service_plan_id])).rows[0],visit=(await pool.query('SELECT * FROM agreement_plan_visits WHERE enrollment_id=$1 ORDER BY sequence LIMIT 1',[item.row.id])).rows[0],job=randomUUID();
      await pool.query("INSERT INTO schedule_events(id,user_id,company_id,contact_id,service_plan_id,title,start_at,end_at,finished_at,service_items) VALUES($1,$2,$3,$4,$5,'Earned visit',now()-interval '2 hours',now()-interval '1 hour',now()-interval '1 hour',$6::jsonb)",[job,owner,company,contact,plan.id,JSON.stringify(item.row.snapshot.future_visit.line_items)]);await pool.query("UPDATE agreement_plan_visits SET job_id=$2,state='completed',completed_at=now() WHERE id=$1",[visit.id,job]);
      await begin(item);const due=(await obligations(item))[0];assert.equal(due.state,'open');await adapter.changeMembership({companyId:company,userId:owner},plan,'cancel',{request_id:randomUUID()});
      assert.equal(stripe.objects.invoices.get(due.invoice_id).status,'open');assert.equal((await obligations(item))[0].state,'open');stripe.settle(due.invoice_id);await adapter.reconcileEnrollment(item.row.id);assert.equal((await obligations(item))[0].state,'succeeded');
    });
    await t.test("activation and pending cancellation share one lock and staff ownership is enforced",async()=>{
      const item=await enrollment({mode:'manual_per_visit'}),results=await Promise.allSettled([plans.reconcileEnrollment(item.row.id),cancellation.publicCancel(item.token,item.row.id,{request_id:randomUUID()})]);assert.ok(results.some(result=>result.status==='fulfilled'));
      const row=await stored(item);assert.notEqual(Boolean(row.service_plan_id),Boolean(row.canceled_at));
      await assert.rejects(cancellation.staffCancel({companyId:randomUUID(),userId:owner},item.row.id,{request_id:randomUUID()}),error=>error.code==='plan_enrollment_unavailable');
      const active=await enrollment({mode:'manual_per_visit'});await begin(active);await assert.rejects(cancellation.publicCancel(active.token,active.row.id,{request_id:randomUUID()}),error=>error.code==='plan_membership_active');
    });
  }finally{if(server)await new Promise(resolve=>server.close(resolve));if(pool)await pool.end();postgres.stop();}
});
