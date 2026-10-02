import { drawnSignature } from "./helpers/signatures.js";
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { PDFDocument } from 'pdf-lib';
import { startLocalPostgres } from './helpers/local-postgres.js';
import { installAgreementSystem, normalizeAgreementContent } from '../quote-agreements.js';

test('template presentation and commercial defaults validate',()=>{
  for(const input of [{deposit:{type:'none'}},{validity_days:0},{validity_days:366},{booking_preference:'yes'},{branding:{accent_color:'url(script)'}},{branding:{show_logo:'false'}},{estimate_label:'Arbitrary'}])assert.throws(()=>normalizeAgreementContent(input));
  const defaults=normalizeAgreementContent();assert.equal(defaults.validity_days,null);assert.equal(defaults.booking_preference,null);assert.equal(defaults.branding.show_logo,true);
});

test('template versions, frozen preferences, standalone revisions and private history',{timeout:120000},async(t)=>{
  const pg=startLocalPostgres();pg.configureEnvironment();let pool,server,service;
  try{
    const backend=await import('../index.js');pool=backend.pool;await backend.bootstrap();
    const company=randomUUID(),foreign=randomUUID(),owner=randomUUID(),other=randomUUID(),contact=randomUUID(),quote=randomUUID();
    await pool.query("INSERT INTO companies(id,name,join_code) VALUES($1,'Template Business','TPL-ONE'),($2,'Other','TPL-TWO')",[company,foreign]);
    await pool.query("INSERT INTO users(id,email,role,company_id) VALUES($1,'template@example.invalid','employer',$3),($2,'other-template@example.invalid','employer',$4)",[owner,other,company,foreign]);
    await pool.query("INSERT INTO sessions(token,user_id) VALUES('template-owner',$1),('template-other',$2)",[owner,other]);
    await pool.query("INSERT INTO contacts(id,user_id,company_id,name,address,email) VALUES($1,$2,$3,'Original Customer','123 Service Street','customer@example.invalid')",[contact,owner,company]);
    await pool.query("INSERT INTO quotes(id,user_id,company_id,contact_id,title,line_items,total_cents,quote_options) VALUES($1,$2,$3,$4,'Exterior service',$5::jsonb,30000,$6::jsonb)",[quote,owner,company,contact,JSON.stringify([{id:randomUUID(),name:'Windows',qty:1,price_cents:30000,description:'All exterior glass'}]),JSON.stringify({duration_minutes:60,scope_exclusions:'No roof work',deposit:{type:'none',value:0}})]);
    const env={NODE_ENV:'test',QUOTE_PUBLIC_BASE_URL:'http://localhost:3000',QUOTE_LINK_SECRET:'template-test-durable-link-secret-more-than32characters'};
    let settings={company_name:'Original business',valid_for_days:30,tax_enabled:false,company_logo_data_url:''};
    service=await installAgreementSystem({app:backend.app,pool,authRequired:backend.authRequired,requireCapability:backend.requireCapability,getQuoteSettings:async()=>settings,env,startWorker:false});
    server=await new Promise(resolve=>{const listener=backend.app.listen(0,'127.0.0.1',()=>resolve(listener));});const base=`http://127.0.0.1:${server.address().port}`;
    const request=async(path,{method='GET',body,token='template-owner'}={})=>{const response=await fetch(base+path,{method,headers:{'Content-Type':'application/json',...(token?{Authorization:`Bearer ${token}`}:{})},body:body===undefined?undefined:JSON.stringify(body)});return {status:response.status,body:response.headers.get('content-type')?.includes('application/json')?await response.json():Buffer.from(await response.arrayBuffer())};};
    const content={agreement_text:'Agreed scope for {{customer_name}}',consent_text:'I agree to electronic signing.',validity_days:7,estimate_label:'Quote',confirmation_text:'Your signed record is available below.',scope_exclusions:'No interior work',branding:{display_name:'Exterior Division',accent_color:'#336699',show_logo:false},booking_preference:false,plan_offer_preference:false};
    let template,issued,standalone;
    await t.test('template values freeze in packet while deposit and saved quote stay unchanged',async()=>{
      template=(await request('/api/agreements/templates',{method:'POST',body:{name:'Exterior template',content}})).body;assert.equal(template.version,1);
      const preview=await request(`/api/quotes/${quote}/preview`,{method:'POST',body:{template_id:template.template_id}});assert.equal(preview.status,200,JSON.stringify(preview.body));
      issued=(await request(`/api/quotes/${quote}/publish`,{method:'POST',body:{request_id:randomUUID(),template_id:template.template_id,expected_preview_hash:preview.body.preview_hash}})).body;
      assert.equal(issued.snapshot.business.name,'Exterior Division');assert.equal(issued.snapshot.business.logo_data_url,'');assert.equal(issued.snapshot.pricing.deposit_cents,0);assert.equal(issued.snapshot.estimate_label,'Quote');
      assert.equal(issued.snapshot.scope_exclusions, "");
      assert.equal(Math.round((new Date(issued.expires_at)-new Date(issued.snapshot.issued_at))/86400000),7);
      const version2=await request('/api/agreements/templates',{method:'POST',body:{template_id:template.template_id,expected_version:1,name:'Changed defaults',content:{...content,validity_days:14,branding:{display_name:'New brand'}}}});assert.equal(version2.status,201);
      settings={...settings,company_name:'Changed company'};
      const frozen=(await request(`/api/agreements/${issued.id}`)).body;assert.equal(frozen.snapshot.business.name,'Exterior Division');assert.equal(frozen.snapshot.validity_days,7);
      assert.equal((await pool.query('SELECT quote_options FROM quotes WHERE id=$1',[quote])).rows[0].quote_options.deposit.type,'none');
      const versions=await request(`/api/agreements/templates/${template.template_id}/versions`);assert.deepEqual(versions.body.map(item=>item.version),[2,1]);
      assert.equal((await request(`/api/agreements/templates/${template.template_id}/versions`,{token:'template-other'})).status,404);
      assert.equal((await request(`/api/agreements/templates/${template.template_id}/archive`,{method:'POST',body:{expected_version:1}})).status,409);
      const replacementDefault = (await request('/api/agreements/templates',{method:'POST',body:{name:'Replacement default',content}})).body;
      assert.equal((await request(`/api/agreements/templates/${replacementDefault.template_id}/default`,{method:'PUT',body:{expected_version:replacementDefault.version}})).status,200);
      assert.equal((await request(`/api/agreements/templates/${template.template_id}/archive`,{method:'POST',body:{expected_version:2}})).status,200);
      assert.equal((await request('/api/agreements/templates')).body.some(item => item.template_id === template.template_id),false);
      assert.equal((await request(`/api/agreements/templates/${template.template_id}/versions`)).body.length,2);
      assert.equal((await request(`/api/agreements/${issued.id}/documents/quote`)).status,200);
    });
    await t.test('template workflow overrides validate actual readiness and excluded packets preserve scope artifact',async()=>{
      assert.equal((await request(`/api/quotes/${quote}/preview`,{method:'POST',body:{content:{...content,booking_preference:true}}})).body.error,'agreement_booking_not_ready');
      const excluded=await request(`/api/quotes/${quote}/publish`,{method:'POST',body:{request_id:randomUUID(),content:{...content,quote_position:'excluded'}}});assert.equal(excluded.status,201,JSON.stringify(excluded.body));
      assert.equal(excluded.body.snapshot.quote_position,'excluded');assert.match(excluded.body.snapshot.scope_reference_hash,/^[a-f0-9]{64}$/);
      assert.equal(excluded.body.predecessor_id,issued.id);
      const old=(await request(`/api/agreements/${issued.id}`)).body;assert.equal(old.state.decision,'superseded');assert.equal(old.related_agreements.length,2);
      assert.equal((await request(`/api/agreements/${excluded.body.id}/documents/quote`)).status,200);
    });
    await t.test('standalone replacements keep signed evidence and expose tenant-protected revision history',async()=>{
      standalone=(await request('/api/agreements',{method:'POST',body:{contact_id:contact,title:'Standalone terms',request_id:randomUUID(),content}})).body;
      const token=standalone.customer_url.split('/').at(-1),session=(await request(`/api/public/agreements/${token}/session`,{method:'POST',token:null,body:{}})).body;
      assert.equal((await request(`/api/public/agreements/${token}/sign`,{method:'POST',token:null,body:{request_id:randomUUID(),session_token:session.session_token,packet_hash:standalone.packet_hash,printed_name:'Customer',consent:true,signature:drawnSignature(),values:{}}})).status,200);
      const replacement=await request('/api/agreements',{method:'POST',body:{contact_id:contact,title:'Revised standalone terms',predecessor_id:standalone.id,request_id:randomUUID(),content:{...content,agreement_text:'New reviewed terms'}}});assert.equal(replacement.status,201,JSON.stringify(replacement.body));
      assert.equal(replacement.body.number,standalone.number);assert.equal(replacement.body.revision,2);assert.equal(replacement.body.predecessor_id,standalone.id);
      const old=(await request(`/api/agreements/${standalone.id}`)).body;assert.equal(old.state.signing,'submitted');assert.notEqual(old.state.decision,'superseded');assert.equal(old.related_agreements.length,2);
      assert.equal((await request(`/api/agreements/${standalone.id}`,{token:'template-other'})).status,404);
      assert.equal((await request(`/api/public/agreements/${token}`,{token:null})).body.related_agreements,undefined);
      assert.equal((await request('/api/agreements',{method:'POST',body:{contact_id:contact,title:'Stale revision',predecessor_id:standalone.id,request_id:randomUUID(),content}})).status,409);
    });
    await t.test('staff checkbox prefills are real booleans and required false cannot be issued',async()=>{
      const pdf=await PDFDocument.create();pdf.addPage([612,792]);
      const asset=(await request('/api/agreements/assets',{method:'POST',body:{name:'Checkbox contract.pdf',base64:Buffer.from(await pdf.save()).toString('base64')}})).body;
      const signature={id:'sig',page:0,type:'signature',role:'customer',required:true,x:0.1,y:0.3,width:0.7,height:0.1};
      const checkbox={id:'staff_check',page:0,type:'checkbox',role:'staff',required:false,value:'false',x:0.1,y:0.1,width:0.1,height:0.1};
      const input={contact_id:contact,title:'Checkbox terms',content:{...content,documents:[{asset_id:asset.id,fields:[signature,checkbox]}]}};
      const preview=await request('/api/agreements/preview',{method:'POST',body:input});assert.equal(preview.status,200,JSON.stringify(preview.body));assert.equal(preview.body.snapshot.documents[0].prefilled_values.staff_check,false);
      input.content.documents[0].fields[1].required=true;
      assert.equal((await request('/api/agreements/preview',{method:'POST',body:input})).body.error,'agreement_staff_field_missing');
      input.content.documents[0].fields[1].value='true';assert.equal((await request('/api/agreements/preview',{method:'POST',body:input})).status,200);
    });
  }finally{service?.stop();if(server)await new Promise(resolve=>server.close(resolve));if(pool)await pool.end();pg.stop();}
});
