import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { startLocalPostgres } from './helpers/local-postgres.js';
import { drawnSignature } from './helpers/signatures.js';
import { installAgreementSystem } from '../quote-agreements.js';
import { selectedQuoteScheduleScope } from '../quote-addons.js';
import { validateAgreementSignature } from '../quote-agreement-documents.js';

test('template defaults, persisted overrides, visibility, drawing and removal work against PostgreSQL', {timeout:120000}, async t => {
  const pg = startLocalPostgres(); pg.configureEnvironment(); let pool, server, agreements;
  try {
    const backend = await import('../index.js'); pool = backend.pool; await backend.bootstrap();
    const {installGoogleSheetsSchema} = await import('../google-sheets.js'); await installGoogleSheetsSchema(pool);
    const company=randomUUID(), user=randomUUID(), otherCompany=randomUUID(), otherUser=randomUUID(), employee=randomUUID(), contact=randomUUID();
    await pool.query("INSERT INTO companies(id,name,join_code) VALUES($1,'Template workflow','TPLFLOW'),($2,'Other','TPLOTHER')",[company,otherCompany]);
    await pool.query("INSERT INTO users(id,email,role,company_id) VALUES($1,'workflow@example.invalid','employer',$4),($2,'other@example.invalid','employer',$5),($3,'worker@example.invalid','employee',$4)",[user,otherUser,employee,company,otherCompany]);
    await pool.query("INSERT INTO sessions(token,user_id) VALUES('owner',$1),('other',$2),('worker',$3)",[user,otherUser,employee]);
    await pool.query("INSERT INTO employee_permissions(user_id,company_id,permission_preset) VALUES($1,$2,'technician')",[employee,company]);
    await pool.query("INSERT INTO contacts(id,user_id,company_id,name,address) VALUES($1,$2,$3,'Customer','42 Main Street')",[contact,user,company]);
    agreements=await installAgreementSystem({app:backend.app,pool,authRequired:backend.authRequired,requireCapability:backend.requireCapability,getQuoteSettings:backend.getQuoteSettings,env:{NODE_ENV:'test',QUOTE_PUBLIC_BASE_URL:'http://localhost:3000',QUOTE_LINK_SECRET:'test-template-workflow-key-at-least-thirty-two-characters'},startWorker:false});
    server=await new Promise(resolve=>{const listener=backend.app.listen(0,'127.0.0.1',()=>resolve(listener));}); const base=`http://127.0.0.1:${server.address().port}`;
    const request=async(path,{method='GET',body,token='owner'}={})=>{const response=await fetch(base+path,{method,headers:{'Content-Type':'application/json',...(token?{Authorization:`Bearer ${token}`}:{})},body:body===undefined?undefined:JSON.stringify(body)});return{status:response.status,body:response.status===204?null:await response.json()};};
    const saveTemplate=body=>request('/api/agreements/templates',{method:'POST',body});
    const quoteBody={contact_id:contact,title:'Window service',line_items:[{id:randomUUID(),name:'Windows',qty:1,price_cents:20000}],quote_options:{duration_minutes:90}};
    const makeQuote=async options=>{const result=await request('/api/quotes',{method:'POST',body:{...quoteBody,quote_options:{...quoteBody.quote_options,...options}}});assert.equal(result.status,201,JSON.stringify(result.body));return result.body;};
    const publish=async quote=>{const preview=await request(`/api/quotes/${quote.id}/preview`,{method:'POST',body:{}});assert.equal(preview.status,200,JSON.stringify(preview.body));const issued=await request(`/api/quotes/${quote.id}/publish`,{method:'POST',body:{request_id:randomUUID(),expected_preview_hash:preview.body.preview_hash}});assert.equal(issued.status,201,JSON.stringify(issued.body));return issued.body;};
    let initial, custom, saved, issued;
    await t.test('concurrent first use seeds exactly one renameable default, isolated by company',async()=>{
      const lists=await Promise.all(Array.from({length:4},()=>request('/api/agreements/templates')));
      for(const result of lists){assert.equal(result.status,200);assert.equal(result.body.filter(row=>row.is_default).length,1);}
      initial=lists[0].body[0];assert.equal(new Set(lists.map(result=>result.body[0].template_id)).size,1);assert.equal(initial.content.estimate_label,'Quote');
      const foreign=(await request('/api/agreements/templates',{token:'other'})).body;assert.notEqual(foreign[0].template_id,initial.template_id);
      const renamed=await saveTemplate({template_id:initial.template_id,expected_version:initial.version,name:'My Main Quote',content:initial.content});assert.equal(renamed.status,201);assert.equal(renamed.body.is_default,true);initial=renamed.body;
      assert.equal((await request(`/api/agreements/templates/${initial.template_id}/archive`,{method:'POST',body:{expected_version:initial.version}})).body.error,'agreement_default_template_required');
    });
    await t.test('legacy company defaults seed independently of existing optional templates',async()=>{
      await pool.query('UPDATE agreement_settings SET default_template_id=NULL,content=$2::jsonb WHERE company_id=$1',[otherCompany,JSON.stringify({agreement_text:'Legacy company default',consent_text:'Legacy consent'})]);
      const rows=(await request('/api/agreements/templates',{token:'other'})).body;
      assert.equal(rows.filter(row=>row.is_default).length,1);assert.equal(rows.find(row=>row.is_default).content.agreement_text,'Legacy company default');
    });
    await t.test('template carries commercial/workflow settings and default selection enforces permissions/version',async()=>{
      custom=(await saveTemplate({name:'After Service',content:{...initial.content,agreement_text:'Visible agreement',terms_text:'Hidden terms',show_agreement:false,show_terms:false,quote_defaults:{...initial.content.quote_defaults,deposit:{type:'fixed',value:2500},discount:{type:'percent',value:1000},customer_notes_enabled:true,balance_payment_timing:'after_service'}}})).body;
      assert.equal((await request(`/api/agreements/templates/${custom.template_id}/default`,{method:'PUT',token:'worker',body:{expected_version:1}})).status,403);
      assert.equal((await request(`/api/agreements/templates/${custom.template_id}/default`,{method:'PUT',token:'other',body:{expected_version:1}})).status,404);
      assert.equal((await request(`/api/agreements/templates/${custom.template_id}/default`,{method:'PUT',body:{expected_version:100}})).status,409);
      assert.equal((await request(`/api/agreements/templates/${custom.template_id}/default`,{method:'PUT',body:{expected_version:1}})).status,200);
      const automatic=await makeQuote();assert.equal(automatic.quote_options.template.id,custom.template_id);assert.equal(automatic.quote_options.deposit.value,2500);assert.equal(automatic.quote_options.balance_payment_timing,'after_service');assert.equal(automatic.quote_options.template.is_customized,false);
    });
    await t.test('quote overrides retain duration, are normalized and never rewrite selected template',async()=>{
      const content={...custom.content,quote_defaults:{...custom.content.quote_defaults,deposit:{type:'none',value:0}},agreement_text:'Quote-only wording'};
      saved=await makeQuote({template:{id:custom.template_id,version:custom.version,name:'Forged display name',content,is_customized:false},optional_addons:[{not:'a service'}],public_notes:'REMOVE',scope_exclusions:'REMOVE',billing_address:'REMOVE'});
      assert.equal(saved.quote_options.template.name,'After Service');assert.equal(saved.quote_options.template.is_customized,true);assert.equal(saved.quote_options.duration_minutes,90);assert.equal(saved.quote_options.customer_notes_enabled,true);
      assert.deepEqual(saved.quote_options.optional_addons,[]);assert.equal(saved.quote_options.billing_address,'');assert.equal(saved.quote_options.public_notes,'');
      const source=(await request('/api/agreements/templates')).body.find(row=>row.template_id===custom.template_id);assert.equal(source.content.agreement_text,'Visible agreement');assert.equal(source.content.quote_defaults.deposit.value,2500);
      const previewPricing=await request('/api/quotes/pricing',{method:'POST',body:{line_items:quoteBody.line_items,quote_options:{...saved.quote_options,deposit:{type:'fixed',value:9999},discount:{type:'none',value:0}}}});
      assert.equal(previewPricing.status,200,JSON.stringify(previewPricing.body));assert.equal(previewPricing.body.total_cents,18000);assert.equal(previewPricing.body.deposit_cents,0);
      const foreign=(await request('/api/agreements/templates',{token:'other'})).body[0];
      assert.equal((await request(`/api/quotes/${saved.id}`,{method:'PUT',body:{quote_options:{template:{id:foreign.template_id,version:1,name:foreign.name,content:foreign.content}}}})).status,404);
      await saveTemplate({template_id:custom.template_id,expected_version:1,name:'Updated future quotes',content:{...custom.content,terms_text:'Future text'}});
      const reloaded=(await request('/api/quotes')).body.find(row=>row.id===saved.id);assert.deepEqual(reloaded.quote_options,saved.quote_options);
    });
    await t.test('publication uses saved override, omits hidden content, freezes exact preview, keeps customer notes',async()=>{
      assert.equal((await request(`/api/quotes/${saved.id}/publish`,{method:'POST',body:{request_id:randomUUID()}})).body.error,'agreement_preview_required');
      assert.equal((await request(`/api/quotes/${saved.id}/publish`,{method:'POST',body:{request_id:randomUUID(),expected_preview_hash:'stale'}})).body.error,'agreement_preview_changed');
      issued=await publish(saved);assert.equal(issued.snapshot.estimate_label,'Quote');assert.equal(issued.snapshot.agreement_text,'');assert.equal(issued.snapshot.terms_text,'');assert.equal(issued.snapshot.terms_document,null);assert.equal(issued.snapshot.customer_notes_enabled,true);assert.equal(issued.snapshot.pricing.deposit_cents,0);assert.equal(issued.snapshot.pricing.total_cents,18000);assert.equal(issued.snapshot.template.version,1);assert.equal(issued.snapshot.addon_selection_finalized,true);
      const token=issued.customer_url.split('/').at(-1);const session=(await request(`/api/public/agreements/${token}/session`,{token:null,method:'POST',body:{}})).body;
      const signBody={request_id:randomUUID(),packet_hash:issued.packet_hash,session_token:session.session_token,printed_name:'Customer',consent:true,signature:drawnSignature(),values:{}};
      const sign=body=>request(`/api/public/agreements/${token}/sign`,{token:null,method:'POST',body});
      assert.equal((await sign({...signBody,printed_name:''})).body.error,'agreement_signer_name_required');
      assert.equal((await sign({...signBody,printed_name:'  !! '})).body.error,'agreement_signer_name_required');
      assert.equal((await sign({...signBody,signature:{type:'typed',text:'Customer'}})).body.error,'signature_drawing_required');
      assert.equal((await sign({...signBody,signature:{type:'drawn',strokes:[]}})).status,400);
      const result=await sign(signBody);assert.equal(result.status,200,JSON.stringify(result.body));assert.equal(result.body.state.signing,'submitted');
      assert.equal((await sign(signBody)).status,200);assert.equal((await pool.query('SELECT count(*)::int n FROM agreement_signatures WHERE agreement_id=$1',[issued.id])).rows[0].n,1);
      assert.equal(validateAgreementSignature({type:'typed',text:'Historical signer'}).type,'typed');
    });
    await t.test('signed quote deletion hides active records but preserves signatures/customer access and is retry-safe',async()=>{
      const before=(await pool.query('SELECT packet_hash,snapshot FROM quote_agreements WHERE id=$1',[issued.id])).rows[0];
      assert.equal((await request(`/api/quotes/${saved.id}`,{method:'DELETE',token:'other'})).status,404);
      assert.equal((await request(`/api/quotes/${saved.id}`,{method:'DELETE',token:'worker'})).status,403);
      assert.equal((await request(`/api/quotes/${saved.id}`,{method:'DELETE'})).status,204);
      assert.equal((await request(`/api/quotes/${saved.id}`,{method:'DELETE'})).status,204);
      assert.equal((await request('/api/quotes')).body.some(row=>row.id===saved.id),false);
      assert.equal((await request(`/api/quotes/${saved.id}`,{method:'PUT',body:{title:'Bring it back'}})).status,404);
      assert.equal((await request(`/api/quotes/${saved.id}/preview`,{method:'POST',body:{}})).status,404);
      await assert.rejects(selectedQuoteScheduleScope(pool,{companyId:company,quoteId:saved.id,start:new Date(),end:new Date(Date.now()+5400000)}),error=>error.code==='quote_not_found');
      assert.equal((await request(`/api/public/agreements/${issued.customer_url.split('/').at(-1)}`,{token:null})).status,200);
      assert.deepEqual((await pool.query('SELECT packet_hash,snapshot FROM quote_agreements WHERE id=$1',[issued.id])).rows[0],before);
      assert.equal((await pool.query("SELECT count(*)::int n FROM agreement_events WHERE agreement_id=$1 AND type='quote_removed'",[issued.id])).rows[0].n,1);
    });
    await t.test('unsigned quote deletion revokes public link and retains document history',async()=>{
      const draft=await makeQuote({deposit:{type:'none',value:0}}), packet=await publish(draft);
      assert.equal((await request(`/api/quotes/${draft.id}`,{method:'DELETE'})).status,204);
      assert.equal((await request(`/api/public/agreements/${packet.customer_url.split('/').at(-1)}`,{token:null})).status,404);
      assert.equal((await request(`/api/agreements/${packet.id}`)).status,200);
      assert.equal((await pool.query('SELECT count(*)::int n FROM agreement_artifacts WHERE agreement_id=$1',[packet.id])).rows[0].n>0,true);
    });
  } finally {agreements?.stop();if(server)await new Promise(resolve=>server.close(resolve));if(pool)await pool.end();pg.stop();}
});
