import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {PDFDocument} from "pdf-lib";
import {startLocalPostgres} from "./helpers/local-postgres.js";
import {installAgreementSystem} from "../quote-agreements.js";
import {normalizeQuoteOptions,validateQuoteAddonScope} from "../quote-contract-domain.js";
import {installScheduleBookingGuard} from "../schedule-booking-guard.js";

test("optional choices use bounded explicit stable scope",()=>{
  const addon={id:randomUUID(),service_id:randomUUID(),name:"Screens",description:"Detail",qty:1,price_cents:1000,duration_minutes:15};
  assert.equal(normalizeQuoteOptions({optional_addons:[addon]}).optional_addons[0].id,addon.id);
  assert.throws(()=>normalizeQuoteOptions({optional_addons:[{...addon,id:undefined}]}));
  assert.throws(()=>normalizeQuoteOptions({optional_addons:[{...addon,service_id:null}]}));
  assert.throws(()=>normalizeQuoteOptions({optional_addons:[{...addon,duration_minutes:-1}]}));
  assert.throws(()=>validateQuoteAddonScope([addon],normalizeQuoteOptions({optional_addons:[addon]})),/own ID/);
  assert.throws(()=>validateQuoteAddonScope([],normalizeQuoteOptions({duration_minutes:10080,optional_addons:[addon]})),/Maximum selected/);
});

test("optional services produce immutable exact revisions before every signer",{timeout:120000},async t=>{
  const postgres=startLocalPostgres();postgres.configureEnvironment();let pool,server;
  try{
    const backend=await import("../index.js");pool=backend.pool;await backend.bootstrap();
    const {installGoogleSheetsSchema}=await import("../google-sheets.js");await installGoogleSheetsSchema(pool);
    const service=await installAgreementSystem({app:backend.app,pool,authRequired:backend.authRequired,requireCapability:backend.requireCapability,getQuoteSettings:backend.getQuoteSettings,env:{NODE_ENV:"test",QUOTE_LINK_SECRET:"test-optional-services-secret-at-least-32-characters",QUOTE_PUBLIC_BASE_URL:"http://localhost:3000"},startWorker:false});
    await installScheduleBookingGuard(pool);
    const company=randomUUID(),otherCompany=randomUUID(),user=randomUUID(),contact=randomUUID(),savedService=randomUUID(),foreignService=randomUUID();
    await pool.query("INSERT INTO companies(id,name,join_code) VALUES($1,'Scope Company','ADDON'),($2,'Other','ADDONOTHER')",[company,otherCompany]);
    await pool.query("INSERT INTO users(id,email,company_id,role) VALUES($1,'addons@example.invalid',$2,'employer')",[user,company]);
    await pool.query("INSERT INTO sessions(token,user_id) VALUES('addon-fixture',$1)",[user]);
    await pool.query("INSERT INTO contacts(id,user_id,company_id,name,email,address) VALUES($1,$2,$3,'Original Customer','private@example.invalid','123 Original Street')",[contact,user,company]);
    await pool.query("INSERT INTO saved_services(id,company_id,name,created_by,updated_by) VALUES($1,$2,'Windows',$3,$3),($4,$5,'Foreign',$3,$3)",[savedService,company,user,foreignService,otherCompany]);
    await pool.query("INSERT INTO agreement_settings(company_id,content) VALUES($1,$2::jsonb)",[company,JSON.stringify({agreement_text:"{{customer_name}} at {{service_address}}: {{services}}. Total {{total}}; deposit {{deposit}}; balance {{balance}}.",terms_text:"Agreed scope: {{services}}",consent_text:"I accept this {{total}} estimate electronically.",required_signers:["customer","customer_2","business"]})]);
    server=await new Promise(resolve=>{const listener=backend.app.listen(0,"127.0.0.1",()=>resolve(listener));});const base=`http://127.0.0.1:${server.address().port}`;
    const req={companyId:company,userId:user};
    const request=async(path,body,method="POST")=>{const response=await fetch(base+path,{method,headers:{"content-type":"application/json",authorization:"Bearer addon-fixture"},...(body!==undefined?{body:JSON.stringify(body)}:{})});return{status:response.status,body:await response.json()};};
    const tokenOf=row=>new URL(row.customer_url).pathname.split("/").at(-1);
    async function packet({booking=false,deposit=false,content,discount,noAddons=false}={}){
      const quote=randomUUID(),line={id:randomUUID(),service_id:savedService,name:"Windows",description:"Outside only",qty:2,price_cents:10000},addon={id:randomUUID(),service_id:savedService,name:"Screens",description:"Remove and wash\nRinse frames",qty:1.5,price_cents:2000,duration_minutes:30};
      const options=normalizeQuoteOptions({duration_minutes:90,optional_addons:noAddons?[]:[addon],allow_customer_booking:booking,deposit:{type:deposit?"percent":"none",value:deposit?2500:0},...(discount?{discount}:{})});
      await pool.query("INSERT INTO quotes(id,user_id,company_id,contact_id,line_items,total_cents,quote_options) VALUES($1,$2,$3,$4,$5::jsonb,20000,$6::jsonb)",[quote,user,company,contact,JSON.stringify([line]),JSON.stringify(options)]);
      const published=await service.publish(req,quote,{request_id:randomUUID(),...(content?{content}:{})});return{quote,line,addon,published,token:tokenOf(published)};
    }
    const select=(item,ids=[item.addon.id],more={})=>service.selectAddons(item.token,{request_id:randomUUID(),packet_hash:item.published.packet_hash,selected_addon_ids:ids,...more});
    async function sign(item,role="customer"){
      const row=(await pool.query("SELECT * FROM quote_agreements WHERE id=$1",[item.published.id])).rows[0];
      const token=service.makeToken(row,role),session=role==="business"?null:await service.publicSession(token);
      return service.sign(role==="business"?row.id:token,{request_id:randomUUID(),packet_hash:row.packet_hash,session_token:session?.session_token,printed_name:"Original Customer",consent:true,signature:{type:"typed",text:"Original Customer"},values:{}},{},role==="business"?req:null);
    }
    await t.test("all signers must wait for explicit choice, including an empty selection",async()=>{
      const item=await packet();assert.equal(item.published.state.addon_selection_required,true);assert.equal(item.published.state.can_sign,false);assert.equal(item.published.state.can_decide,true);
      await assert.rejects(sign(item,"business"),e=>e.code==="agreement_not_signable");
      const result=await select(item,[]);assert.equal(result.agreement.snapshot.pricing.total_cents,20000);assert.equal(result.agreement.state.can_sign,true);assert.equal(result.agreement.snapshot.addon_selection_finalized,true);assert.equal(result.agreement.revision,2);
      assert.equal((await request(`/api/public/agreements/${item.token}`,undefined,"GET")).body.replacement_url,result.customer_url);
      const second=(await pool.query("SELECT * FROM quote_agreements WHERE id=$1",[item.published.id])).rows[0];const secondURL=(await request(`/api/public/agreements/${service.makeToken(second,"customer_2")}`,undefined,"GET")).body.replacement_url;assert.match(secondURL,/\.customer_2\./);
      await assert.rejects(service.selectAddons(service.makeToken(second,"customer_2"),{request_id:randomUUID(),packet_hash:item.published.packet_hash,selected_addon_ids:[]}),e=>e.code==="quote_addon_primary_customer_required");
    });
    await t.test("frozen offers reprice merges, tax, deposit and duration without mutable source leakage",async()=>{
      service.paymentReady=true;service.validatePaymentReadiness=async()=>{};let checked;
      service.bookingReady=true;service.validateBookingReadiness=async(_db,_company,scope)=>{checked=scope;};
      await pool.query("INSERT INTO quote_settings(company_id,tax_enabled,tax_rate_basis_points) VALUES($1,true,1000)",[company]);
      const item=await packet({booking:true,deposit:true}),original=(await pool.query("SELECT snapshot,packet_hash FROM quote_agreements WHERE id=$1",[item.published.id])).rows[0];
      await pool.query("UPDATE quote_settings SET tax_rate_basis_points=0 WHERE company_id=$1",[company]);
      await pool.query("UPDATE contacts SET name='Unrelated changed name' WHERE id=$1",[contact]);await pool.query("UPDATE quotes SET line_items='[]'::jsonb WHERE id=$1",[item.quote]);
      const result=await select(item),snapshot=result.agreement.snapshot;
      assert.equal(snapshot.pricing.total_cents,25300);assert.equal(snapshot.pricing.tax_cents,2300);assert.equal(snapshot.pricing.deposit_cents,6325);assert.equal(snapshot.pricing.balance_after_deposit_cents,18975);assert.equal(checked.duration_minutes,120);assert.equal(checked.line_items.length,2);
      assert.match(snapshot.agreement_text,/Original Customer/);assert.match(snapshot.agreement_text,/\$253\.00/);assert.match(snapshot.agreement_text,/Screens/);assert.match(snapshot.terms_text,/Screens/);assert.equal(snapshot.addon_source,undefined);assert.equal(snapshot.duration_minutes,undefined);assert.equal(snapshot.optional_addons[0].duration_minutes,undefined);assert.ok(!JSON.stringify(snapshot).includes("private@example.invalid"));
      const before=(await pool.query("SELECT snapshot,packet_hash FROM quote_agreements WHERE id=$1",[item.published.id])).rows[0];assert.deepEqual(before,original);
      const bytes=(await pool.query("SELECT bytes FROM agreement_artifacts WHERE agreement_id=$1 AND kind='quote'",[result.agreement.id])).rows[0].bytes;assert.ok((await PDFDocument.load(bytes)).getPageCount()>0);
      const stored=(await pool.query("SELECT * FROM quote_agreements WHERE id=$1",[result.agreement.id])).rows[0];assert.equal(stored.snapshot.duration_minutes,120);
      await pool.query("UPDATE contacts SET name='Original Customer' WHERE id=$1",[contact]);
      await pool.query("DELETE FROM quote_settings WHERE company_id=$1",[company]);
    });
    await t.test("concurrent exact retries issue one revision and stale or arbitrary payloads cannot alter it",async()=>{
      const item=await packet(),requestID=randomUUID();const replies=await Promise.all(Array.from({length:5},()=>select(item,[item.addon.id],{request_id:requestID})));assert.equal(new Set(replies.map(r=>r.agreement.id)).size,1);
      await assert.rejects(select(item,[],{request_id:requestID}),e=>e.code==="agreement_request_conflict");await assert.rejects(select(item),e=>e.code==="agreement_version_changed");
      const fresh=await packet();await assert.rejects(select(fresh,[randomUUID()]),e=>e.code==="quote_addon_not_offered");await assert.rejects(select(fresh,[],{price_cents:1}),e=>e.code==="quote_addon_selection_invalid");await assert.rejects(select(fresh,[],{packet_hash:"stale"}),e=>e.code==="agreement_version_changed");
      const newRow=replies[0].agreement;assert.equal((await pool.query("SELECT count(*)::int n FROM quote_agreements WHERE quote_id=$1",[item.quote])).rows[0].n,2);
      const current={...item,published:newRow,token:new URL(replies[0].customer_url).pathname.split("/").at(-1)};const cleared=await select(current,[]);assert.equal(cleared.agreement.snapshot.pricing.total_cents,20000);assert.equal(cleared.agreement.revision,3);
    });
    await t.test("partial countersignatures and customer signatures forbid changing scope",async()=>{
      for(const role of ["business","customer_2"]){const source=await packet(),chosen=await select(source);const item={...source,published:chosen.agreement,token:new URL(chosen.customer_url).pathname.split("/").at(-1)};await sign(item,role);await assert.rejects(select(item,[]),e=>e.code==="quote_addon_already_signed");}
    });
    await t.test("selection versus signature race either preserves signed scope or supersedes unsigned scope",async()=>{
      const source=await packet(),chosen=await select(source),item={...source,published:chosen.agreement,token:new URL(chosen.customer_url).pathname.split("/").at(-1)};
      const results=await Promise.allSettled([select(item,[]),sign(item,"business")]);assert.equal(results.filter(r=>r.status==="fulfilled").length,1);
      const signatures=(await pool.query("SELECT count(*)::int n FROM agreement_signatures WHERE agreement_id=$1",[item.published.id])).rows[0].n;
      const row=(await pool.query("SELECT decision,snapshot FROM quote_agreements WHERE id=$1",[item.published.id])).rows[0];assert.equal(row.snapshot.pricing.total_cents,23000);assert.equal(row.decision==="superseded",signatures===0);
    });
    await t.test("ownership and archival preserve existing options but reject new foreign or archived scope",async()=>{
      const item=await packet();await pool.query("UPDATE saved_services SET archived_at=now() WHERE id=$1",[savedService]);
      const update=await request(`/api/quotes/${item.quote}`,{quote_options:normalizeQuoteOptions({duration_minutes:90,optional_addons:[item.addon]})},"PUT");assert.equal(update.status,200,JSON.stringify(update.body));assert.equal((await select(item)).agreement.snapshot.pricing.total_cents,23000);
      const added=await request(`/api/quotes/${item.quote}`,{quote_options:normalizeQuoteOptions({duration_minutes:90,optional_addons:[{...item.addon,id:randomUUID()}]})},"PUT");assert.equal(added.status,409);
      const foreign=await request(`/api/quotes/${item.quote}`,{quote_options:normalizeQuoteOptions({duration_minutes:90,optional_addons:[{...item.addon,service_id:foreignService}]})},"PUT");assert.equal(foreign.status,404);
      await pool.query("UPDATE saved_services SET archived_at=NULL WHERE id=$1",[savedService]);
    });
    await t.test("decline remains available before optional services are finalized",async()=>{
      const item=await packet();const result=await service.decision(item.token,{request_id:randomUUID(),decision:"declined",message:"Not this time"});assert.equal(result.state.decision,"declined");await assert.rejects(select(item),e=>e.code==="quote_addon_selection_closed");
    });
    await t.test("PDF merge prefills and excluded scope integrity use the selected revision",async()=>{
      const pdf=await PDFDocument.create();pdf.addPage([612,792]);const upload=await request("/api/agreements/assets",{name:"Scope contract",base64:Buffer.from(await pdf.save()).toString("base64")});assert.equal(upload.status,201);
      const fields=[{id:"signature",page:0,type:"signature",role:"customer",required:true,x:.1,y:.5,width:.5,height:.1},{id:"total",page:0,type:"merge",source:"total",role:"staff",required:true,x:.1,y:.2,width:.5,height:.1}];
      const item=await packet({content:{documents:[{asset_id:upload.body.id,fields}],quote_position:"excluded"}}),before=item.published.snapshot.documents[0].prefilled_values.total;
      const selected=await select(item);assert.equal(before,"$200.00");assert.equal(selected.agreement.snapshot.documents[0].prefilled_values.total,"$230.00");assert.notEqual(selected.agreement.snapshot.scope_reference_hash,item.published.snapshot.scope_reference_hash);
      const source=(await pool.query("SELECT snapshot FROM quote_agreements WHERE id=$1",[item.published.id])).rows[0];assert.equal(source.snapshot.documents[0].prefilled_values.total,"$200.00");
    });
    await t.test("expired draft resumes only within its same signer role and packet",async()=>{
      const source=await packet(),chosen=await select(source),token=new URL(chosen.customer_url).pathname.split("/").at(-1),session=await service.publicSession(token);
      await pool.query("UPDATE agreement_signing_sessions SET draft_values=$2::jsonb,expires_at=now()-interval '1 minute' WHERE agreement_id=$1",[chosen.agreement.id,JSON.stringify({printed_name:"Saved name"})]);
      const restored=await service.publicSession(token,{session_token:session.session_token});assert.equal(restored.draft_values.printed_name,"Saved name");assert.notEqual(restored.session_token,session.session_token);
      const row=(await pool.query("SELECT * FROM quote_agreements WHERE id=$1",[chosen.agreement.id])).rows[0];const other=await service.publicSession(service.makeToken(row,"customer_2"),{session_token:session.session_token});assert.deepEqual(other.draft_values,{});
      await assert.rejects(service.session(pool,row,"customer_2",restored.session_token),error=>error.code==="agreement_session_expired");
      const another=await packet(),anotherChosen=await select(another),anotherToken=new URL(anotherChosen.customer_url).pathname.split("/").at(-1);
      assert.deepEqual((await service.publicSession(anotherToken,{session_token:restored.session_token})).draft_values,{});
      assert.equal(restored.verified,true);
    });
    await t.test("staff scheduling uses selected issued scope rather than an older client's draft",async()=>{
      const source=await packet(),chosen=await select(source),job=randomUUID(),start=new Date(Date.now()+86400000),shortEnd=new Date(start.getTime()+90*60000),end=new Date(start.getTime()+120*60000);
      await service.event(pool,source.published.id,"customer_note",{actor_type:"customer",actor_id:"customer",payload:{message:"Gate code supplied separately"}});
      const body={title:"Selected work",start:start.toISOString(),end:shortEnd.toISOString(),contact_id:contact,quote_id:source.quote,service_items:[source.line],services:[source.line.name],price_cents:20000,worker_user_ids:[]};
      const blocked=await request(`/api/schedule/${job}`,body,"PUT");assert.equal(blocked.status,409,JSON.stringify(blocked.body));assert.equal(blocked.body.error,"quote_job_duration_required");
      const result=await request(`/api/schedule/${job}`,{...body,end:end.toISOString()},"PUT");assert.equal(result.status,200,JSON.stringify(result.body));assert.equal(result.body.service_items.length,2);assert.equal(result.body.price_cents,23000);assert.equal(result.body.agreement_id,chosen.agreement.id);
      assert.equal(result.body.customer_note_entries[0].message,"Gate code supplied separately");
      const updated=await request(`/api/schedule/${job}`,{...body,end:end.toISOString(),notes:"Gate on left",price_cents:1},"PUT");assert.equal(updated.status,200,JSON.stringify(updated.body));assert.equal(updated.body.price_cents,23000);assert.equal(updated.body.service_items.length,2);
      const detached=await request(`/api/schedule/${job}`,{...body,end:end.toISOString(),quote_id:null},"PUT");assert.equal(detached.status,409);
    });
    await t.test("optional selection freezes quote discount, inclusive tax and plan stacking policy",async()=>{
      const settings=await request('/api/quotes/settings',{tax_enabled:true,tax_rate_basis_points:1000,tax_inclusive:true,discount_stacking_policy:'quote_then_plan'},'PATCH');assert.equal(settings.status,200);
      const item=await packet({deposit:true,discount:{type:'percent',value:1000}});assert.equal(item.published.snapshot.pricing.total_cents,18000);assert.equal(item.published.snapshot.discount_stacking_policy,'quote_then_plan');assert.equal(item.published.snapshot.tax_provenance.settings_updated_at,settings.body.updated_at);
      await request('/api/quotes/settings',{tax_rate_basis_points:5000,tax_inclusive:false,discount_stacking_policy:'best_price'},'PATCH');
      const selected=await select(item),pricing=selected.agreement.snapshot.pricing;assert.equal(pricing.subtotal_cents,23000);assert.equal(pricing.discount_cents,2300);assert.equal(pricing.total_cents,20700);assert.equal(pricing.tax_cents,1881);assert.equal(pricing.deposit_cents,5175);assert.equal(pricing.tax_inclusive,true);assert.equal(selected.agreement.snapshot.discount_stacking_policy,'quote_then_plan');
      await pool.query('DELETE FROM quote_settings WHERE company_id=$1',[company]);
    });
    await t.test("staff jobs for an issued quote without options retain its authoritative one-time discount",async()=>{
      const item=await packet({noAddons:true,discount:{type:'fixed',value:2500}}),start=new Date(Date.now()+7*86400000),end=new Date(start.getTime()+90*60000);
      const result=await request(`/api/schedule/${randomUUID()}`,{title:'Issued discounted work',start:start.toISOString(),end:end.toISOString(),contact_id:contact,quote_id:item.quote,service_items:[item.line],services:[item.line.name],price_cents:20000,worker_user_ids:[]},'PUT');assert.equal(result.status,200,JSON.stringify(result.body));assert.equal(result.body.price_cents,17500);assert.equal(result.body.agreement_id,item.published.id);
    });
  }finally{if(server)await new Promise(resolve=>server.close(resolve));if(pool)await pool.end();postgres.stop();}
});
