import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { PDFDocument } from 'pdf-lib';
import { startLocalPostgres } from './helpers/local-postgres.js';
import { drawnSignature } from './helpers/signatures.js';
import { installAgreementSystem } from '../quote-agreements.js';
import { installAgreementPayments } from '../agreement-payments.js';
import { installAgreementPlans } from '../agreement-plans.js';
import { installAgreementAuthoringSchema } from '../agreement-authoring.js';

test('customer PDF workflow preserves drafts, exact exports, signer evidence and stable revisions', {timeout:120000}, async t => {
  const pg = startLocalPostgres(); pg.configureEnvironment(); let pool, server, service;
  try {
    const backend = await import('../index.js'); pool=backend.pool; await backend.bootstrap();
    const {installGoogleSheetsSchema}=await import('../google-sheets.js'); await installGoogleSheetsSchema(pool);
    const company=randomUUID(), otherCompany=randomUUID(), owner=randomUUID(), otherOwner=randomUUID(), colleague=randomUUID(), worker=randomUUID(), contact=randomUUID();
    await pool.query("INSERT INTO companies(id,name,join_code) VALUES($1,'PDF Company','PDFWORK'),($2,'Other','PDFOTHER')",[company,otherCompany]);
    await pool.query("INSERT INTO users(id,email,company_id,role) VALUES($1,'pdfowner@example.invalid',$5,'employer'),($2,'pdfother@example.invalid',$6,'employer'),($3,'pdfcolleague@example.invalid',$5,'employer'),($4,'pdfworker@example.invalid',$5,'employee')",[owner,otherOwner,colleague,worker,company,otherCompany]);
    await pool.query("INSERT INTO sessions(token,user_id) VALUES('pdfowner',$1),('pdfother',$2),('pdfcolleague',$3),('pdfworker',$4)",[owner,otherOwner,colleague,worker]);
    await pool.query("INSERT INTO employee_permissions(user_id,company_id,permission_preset) VALUES($1,$2,'technician')",[worker,company]);
    await pool.query("INSERT INTO contacts(id,user_id,company_id,name,address,phone,email) VALUES($1,$2,$3,'PDF Customer','42 Main Street','5551234567','customer@example.invalid')",[contact,owner,company]);
    const env={NODE_ENV:'test',STRIPE_MODE:'test',QUOTE_PUBLIC_BASE_URL:'http://localhost:3000',QUOTE_LINK_SECRET:'customer-pdf-fixture-key-longer-than-thirty-two-characters'};
    service=await installAgreementSystem({app:backend.app,pool,authRequired:backend.authRequired,requireCapability:backend.requireCapability,getQuoteSettings:backend.getQuoteSettings,env,startWorker:false});
    await installAgreementPayments({app:backend.app,pool,service,env,getStripe:()=>null,authRequired:backend.authRequired,requireCapability:backend.requireCapability,startWorker:false});
    await installAgreementPlans({app:backend.app,pool,service,authRequired:backend.authRequired,requireCapability:backend.requireCapability,startWorker:false});
    server=await new Promise(resolve=>{const listener=backend.app.listen(0,'127.0.0.1',()=>resolve(listener));}); const base=`http://127.0.0.1:${server.address().port}`;
    const request=async(path,{method='GET',body,token='pdfowner'}={})=>{
      const response=await fetch(base+path,{method,headers:{'Content-Type':'application/json',...(token?{Authorization:`Bearer ${token}`}:{})},body:body===undefined?undefined:JSON.stringify(body)});
      return {status:response.status,body:response.status===204?null:response.headers.get('content-type')?.includes('application/pdf')?Buffer.from(await response.arrayBuffer()):await response.json()};
    };
    const post=(path,body,token='pdfowner')=>request(path,{method:'POST',body,token});
    const publicPath=packet=>`/api/public/agreements/${packet.customer_url.split('/').at(-1)}`;
    const expectStatus=(result,status)=>{assert.equal(result.status,status,JSON.stringify(result.body));return result.body;};
    const pdf=await PDFDocument.create(); pdf.addPage([612,792]).drawText('EXACT NATIVE QUOTE LAYOUT'); const pdfBytes=Buffer.from(await pdf.save());
    const asset=expectStatus(await post('/api/agreements/assets',{name:'Blank agreement.pdf',base64:pdfBytes.toString('base64')}),201);
    const baseContent={agreement_mode:'text',agreement_text:'Work for {{customer_name}}.',consent_text:'I agree electronically.',show_terms:true};
    const fields=[
      {id:'name',type:'merge',source:'customer_name',role:'staff',page:0,x:.1,y:.1,width:.6,height:.05,required:true},
      {id:'total',type:'merge',source:'total',role:'staff',page:0,x:.1,y:.2,width:.6,height:.05,required:true},
      {id:'initials',type:'initials',role:'customer',page:0,x:.1,y:.4,width:.2,height:.05,required:true},
      {id:'signature',type:'signature',role:'customer',page:0,x:.1,y:.55,width:.7,height:.12,required:true},
    ];
    const pdfContent={...baseContent,agreement_mode:'pdf',documents:[{asset_id:asset.id,fields}],terms_asset_id:asset.id,require_page_signature:false};
    const makeQuote=async()=>expectStatus(await post('/api/quotes',{contact_id:contact,title:'Window quote',line_items:[{id:randomUUID(),name:'Windows',qty:1,price_cents:20000}],quote_options:{duration_minutes:90}}),201);
    const prepare=async(quote,content=baseContent,extra={})=>{
      const preview=expectStatus(await post(`/api/quotes/${quote.id}/preview`,{content,...extra}),200);
      return {request_id:randomUUID(),content,...extra,expected_preview_hash:preview.preview_hash,expected_updated_at:preview.quote_updated_at,quote_pdf_base64:pdfBytes.toString('base64')};
    };
    const publish=async(quote,content=baseContent,extra={})=>expectStatus(await post(`/api/quotes/${quote.id}/publish`,await prepare(quote,content,extra)),201);
    const sign=async(packet,{role='customer',signature=drawnSignature(),values={},printed_name='PDF Customer'}={})=>{
      const row=(await pool.query('SELECT * FROM quote_agreements WHERE id=$1',[packet.id])).rows[0];
      const token=service.makeToken(row,role),session=expectStatus(await post(`/api/public/agreements/${token}/session`,{},null),200);
      return post(`/api/public/agreements/${token}/sign`,{request_id:randomUUID(),packet_hash:packet.packet_hash,session_token:session.session_token,printed_name,consent:true,...(signature===null?{}:{signature}),values},null);
    };

    await t.test('durable incomplete drafts are scoped, versioned, replayable and cleared without losing CAS history',async()=>{
      const id=randomUUID(),path=`/api/agreements/editor-drafts/template/${id}`;
      assert.deepEqual(expectStatus(await request(path),200),{revision:0,base_version:null,payload:null});
      const body={request_id:randomUUID(),expected_revision:0,base_version:1,payload:{schema:1,client:'ios',name:'',editor_state:{deposit:'1.',duration:'',agreement:'Still typing'}}};
      const results=await Promise.all(Array.from({length:4},()=>request(path,{method:'PUT',body})));
      for(const result of results){expectStatus(result,200);assert.equal(result.body.revision,1);assert.deepEqual(result.body.payload,body.payload);}
      assert.equal(expectStatus(await request(path,{token:'pdfother'}),200).payload,null);
      assert.equal(expectStatus(await request(path,{token:'pdfcolleague'}),200).payload,null);
      expectStatus(await request(path,{token:'pdfworker'}),403);
      assert.equal(expectStatus(await request(path,{method:'PUT',body:{...body,payload:{changed:true}}}),409).error,'editor_request_conflict');
      assert.equal(expectStatus(await request(path,{method:'PUT',body:{...body,request_id:randomUUID()}}),409).error,'editor_draft_changed');
      const clear=expectStatus(await request(path,{method:'PUT',body:{request_id:randomUUID(),expected_revision:1,base_version:2,payload:null}}),200);
      assert.equal(clear.revision,2);assert.equal(clear.payload,null);
      await installAgreementAuthoringSchema(pool);
      assert.equal(expectStatus(await request(path),200).revision,2);
    });
    await t.test('active template and tier save retries never duplicate versions',async()=>{
      const input={request_id:randomUUID(),name:'PDF template',content:pdfContent};
      const replies=await Promise.all([1,2,3].map(()=>post('/api/agreements/templates',input)));
      const template=expectStatus(replies[0],201); for(const result of replies)assert.equal(expectStatus(result,201).id,template.id);
      const update={...input,request_id:randomUUID(),template_id:template.template_id,expected_version:template.version,name:'Renamed template'};
      const updated=expectStatus(await post('/api/agreements/templates',update),201);
      assert.equal(expectStatus(await post('/api/agreements/templates',update),201).version,updated.version);
      assert.equal((await pool.query('SELECT count(*)::int n FROM agreement_templates WHERE template_id=$1',[template.template_id])).rows[0].n,2);
      expectStatus(await post('/api/agreements/templates',{...update,name:'Reused request wrong body'}),409);
      const configuration={name:'Quarterly',discount:{type:'percent',value:1000},service_interval:{unit:'month',count:3},cancellation_policy:'Cancel future visits with notice.',agreement:pdfContent};
      const tierInput={request_id:randomUUID(),configuration};
      const tier=expectStatus(await post('/api/service-plan-tiers',tierInput),201);
      assert.equal(expectStatus(await post('/api/service-plan-tiers',tierInput),201).tier_id,tier.tier_id);
      expectStatus(await post(`/api/service-plan-tiers/${tier.tier_id}/archive`,{}),200);
      expectStatus(await post('/api/service-plan-tiers',{request_id:randomUUID(),tier_id:tier.tier_id,expected_version:1,configuration}),409);
    });
    await t.test('selected content mode and PDF-only terms control publication; page signature off needs PDF signature',async()=>{
      const quote=await makeQuote();
      const text=await publish(quote,{...pdfContent,agreement_mode:'text',require_page_signature:true,terms_text:'No longer published'});
      assert.equal(text.snapshot.documents.length,0);assert.match(text.snapshot.agreement_text,/PDF Customer/);assert.equal(text.snapshot.terms_text,'');
      const terms=expectStatus(await request(`${publicPath(text)}/documents/terms`,{token:null}),200);
      assert.equal((await PDFDocument.load(terms)).getPageCount(),1);
      const rejected=await post(`/api/quotes/${quote.id}/preview`,{content:{...pdfContent,documents:[{asset_id:asset.id,fields:fields.filter(field=>field.type!=='signature')}]}});
      assert.equal(expectStatus(rejected,400).error,'agreement_pdf_signature_required');
      expectStatus(await post(`/api/quotes/${quote.id}/preview`,{content:{...pdfContent,show_agreement:false}}),400);
    });
    await t.test('PDF signature replaces only its own role page signature and printed name remains required',async()=>{
      const packet=await publish(await makeQuote(),{...pdfContent,required_signers:['customer','customer_2']});
      assert.equal(packet.snapshot.agreement_text,'');assert.equal(packet.snapshot.documents[0].prefilled_values.name,'PDF Customer');
      const values={initials:'PC',signature:drawnSignature()};
      assert.equal(expectStatus(await sign(packet,{signature:null,values,printed_name:''}),400).error,'agreement_signer_name_required');
      expectStatus(await sign(packet,{signature:null,values:{initials:'PC'}}),400);
      const primary=expectStatus(await sign(packet,{signature:null,values}),200);assert.equal(primary.signatures.length,1);
      expectStatus(await sign(packet,{role:'customer_2',signature:null}),400);
      expectStatus(await sign(packet,{role:'customer_2'}),200);
      await service.processDocumentJobs(20);
      const evidence=(await pool.query('SELECT signature,field_values FROM agreement_signatures WHERE agreement_id=$1 AND role=\'customer\'',[packet.id])).rows[0];
      assert.deepEqual(evidence.signature,drawnSignature());assert.equal(evidence.field_values.initials,'PC');
      expectStatus(await request(`${publicPath(packet)}/documents/signed`,{token:null}),200);
    });
    await t.test('client quote export bytes survive publication replay, role delivery and regenerated links',async()=>{
      const quote=await makeQuote(),body=await prepare(quote,{...baseContent,required_signers:['customer','customer_2']});
      const packet=expectStatus(await post(`/api/quotes/${quote.id}/publish`,body),201);
      assert.equal(expectStatus(await post(`/api/quotes/${quote.id}/publish`,body),201).id,packet.id);
      for(const link of packet.signer_links){assert.deepEqual(expectStatus(await request(`/api/public/agreements/${link.url.split('/').at(-1)}/documents/quote`,{token:null}),200),pdfBytes);}
      const refreshed=expectStatus(await post(`/api/agreements/${packet.id}/link`,{request_id:randomUUID(),action:'regenerate'}),200);
      expectStatus(await request(publicPath(packet),{token:null}),404);
      assert.deepEqual(expectStatus(await request(`${publicPath(refreshed)}/documents/quote`,{token:null}),200),pdfBytes);
    });
    await t.test('same link opens revisions, preserves signed history/payment and only applies explicit new template choices',async()=>{
      const quote=await makeQuote(),original=await publish(quote);
      expectStatus(await sign(original),200);await service.processDocumentJobs(20);
      const first=(await pool.query('SELECT snapshot,packet_hash FROM quote_agreements WHERE id=$1',[original.id])).rows[0];
      await pool.query("INSERT INTO payment_records(user_id,company_id,contact_id,quote_id,agreement_id,payment_type,status,amount_cents,currency) VALUES($1,$2,$3,$4,$5,'manual','succeeded',5000,'usd')",[owner,company,contact,quote.id,original.id]);
      const template=(await request('/api/agreements/templates')).body.find(row=>row.is_default);
      expectStatus(await post('/api/agreements/templates',{request_id:randomUUID(),template_id:template.template_id,expected_version:template.version,name:'Future only',content:{...baseContent,agreement_text:'Future wording'}}),201);
      const publicSnapshot=structuredClone(original.snapshot);delete publicSnapshot.duration_minutes;
      assert.deepEqual(expectStatus(await request(publicPath(original),{token:null}),200).snapshot,publicSnapshot);
      expectStatus(await request(`/api/quotes/${quote.id}`,{method:'PUT',body:{title:'Revised window quote'}}),200);
      const revised=await publish(quote,{...baseContent,agreement_text:'Changed once',required_signers:['customer','customer_2']},{predecessor_id:original.id});
      assert.equal(revised.customer_url,original.customer_url);assert.equal(revised.revision,2);
      const current=expectStatus(await request(publicPath(original),{token:null}),200);
      assert.equal(current.id,revised.id);assert.equal(current.signatures.length,0);assert.equal(current.payments.paid_cents,5000);assert.equal(current.payments.can_pay_balance,false);
      assert.equal(current.history[0].id,original.id);
      expectStatus(await request(`${publicPath(revised)}/history/${original.id}/documents/signed`,{token:null}),200);
      expectStatus(await request(`${publicPath(revised)}/history/${original.id}/documents/audit`,{token:null}),403);
      const second=revised.signer_links.find(link=>link.role==='customer_2').url.split('/').at(-1);
      expectStatus(await request(`/api/public/agreements/${second}`,{token:null}),200);
      expectStatus(await request(`/api/public/agreements/${second}/history/${original.id}/documents/quote`,{token:null}),404);
      assert.deepEqual((await pool.query('SELECT snapshot,packet_hash FROM quote_agreements WHERE id=$1',[original.id])).rows[0],first);
      expectStatus(await post(`/api/quotes/${quote.id}/preview`,{content:baseContent,predecessor_id:original.id}),409);
      const unrelated=await publish(await makeQuote());
      expectStatus(await request(`${publicPath(unrelated)}/history/${original.id}/documents/quote`,{token:null}),404);
      const removed=await request(`/api/quotes/${quote.id}`,{method:'DELETE'});expectStatus(removed,204);
      const retained=expectStatus(await request(publicPath(original),{token:null}),200);assert.equal(retained.id,original.id);
    });
    await t.test('revocation and regeneration invalidate every former revision URL together',async()=>{
      const quote=await makeQuote(),first=await publish(quote),second=await publish(quote,baseContent,{predecessor_id:first.id});
      const legacy=(await pool.query('SELECT * FROM quote_agreements WHERE id=$1',[second.id])).rows[0];
      const oldDirectToken=service.makeToken({...legacy,link_root_id:legacy.id});
      expectStatus(await post(`/api/agreements/${second.id}/link`,{request_id:randomUUID(),action:'revoke'}),200);
      for(const token of [first.customer_url.split('/').at(-1),oldDirectToken])expectStatus(await request(`/api/public/agreements/${token}`,{token:null}),404);
      const restored=expectStatus(await post(`/api/agreements/${second.id}/link`,{request_id:randomUUID(),action:'regenerate'}),200);
      assert.equal(expectStatus(await request(publicPath(restored),{token:null}),200).id,second.id);
    });
  } finally {service?.stop();if(server)await new Promise(resolve=>server.close(resolve));if(pool)await pool.end();pg.stop();}
});
