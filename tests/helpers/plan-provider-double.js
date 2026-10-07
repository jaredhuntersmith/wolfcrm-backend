import assert from "node:assert/strict";
export function providerDouble(){
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

