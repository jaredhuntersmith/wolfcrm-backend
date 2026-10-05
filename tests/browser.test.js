import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {randomUUID} from 'node:crypto';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installBrowser} from '../browser.js';
import {safeWebpage,browserAIInput} from '../browser-contracts.js';
import {installRateLimits} from '../company-comms/rate-limits.js';
import {validateShares,messageCards} from '../company-comms/sources.js';
import {resolveTabNavigation,validateTabLayout} from '../navigation-tabs.js';
import {createConversationService} from '../company-comms/messages.js';
test('URL/AI boundaries reject credentials, schemes, oversized excerpts',()=>{
 for(const url of ['javascript:alert(1)','data:text/html,x','file:///tmp/a','https://u:secret@example.com','https://x.test/'+ 'a'.repeat(4100)])assert.throws(()=>safeWebpage({url}));
 assert.equal(safeWebpage({url:'https://example.com/a',title:' Reference '}).title,'Reference');
 assert.throws(()=>browserAIInput({action:'execute',pages:[]}));
 assert.throws(()=>browserAIInput({action:'compare',pages:[{url:'https://example.com',text:'visible'}]}));
 for(const action of ['pricing','contacts','products']) assert.equal(browserAIInput({action,pages:[{url:'https://example.com',text:'visible'}]}).action,action);
 assert.throws(()=>browserAIInput({action:'summarize',pages:[{url:'https://example.com',text:'a'.repeat(60001)}]}));
 assert.equal(browserAIInput({action:'summarize',pages:[{url:'https://example.com',text:'visible'}],cookies:'not forwarded'}).cookies,undefined);
});
test('old five-slot layout remains selected with Browser in overflow',()=>{
 const order=['schedule','contacts','dashboard','stages','company_comms','messages','map'],raw={order,hidden:['messages','map']};
 const result=resolveTabNavigation({role:'employer',userPreferences:raw});assert.deepEqual(result.effective.primary,order.slice(0,5));assert.ok(result.effective.overflow.includes('browser'));assert.equal(result.source,'user');assert.deepEqual(validateTabLayout(raw).hidden,['messages','map','browser']);
});
test('real HTTP browser auth, record isolation, idempotency and webpage cards',{timeout:120000},async()=>{
 const f=await createCommsFixture(),app=express();let server;
 try{
  await installRateLimits(f.pool);app.use(express.json());
  const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');if(!f.ids[who])return res.status(401).json({error:'unauthorized'});req.userId=f.ids[who];req.companyId=who==='foreign'?f.companies.b:f.companies.a;next();};
  const env = {}; let aiCalls=0;
  await installBrowser({app,pool:f.pool,authRequired:auth,env,aiClient:{responses:{create:async input=>{aiCalls++;assert.equal(input.store,false);assert.equal(input.max_output_tokens,1800);assert.equal(JSON.parse(input.input).pages[0].text,'visible');assert.equal(JSON.parse(input.input).cookies,undefined);return {output_text:'Fixture summary [source](https://example.com/)'};}}}});
  server=await new Promise(r=>{const s=app.listen(0,'127.0.0.1',()=>r(s));});const base='http://127.0.0.1:'+server.address().port+'/api/browser';
  async function request(path,{who='owner',method='GET',body}={}){const res=await fetch(base+path,{method,headers:{'X-Fixture-User':who,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});assert.match(res.headers.get('content-type'),/json/);return {status:res.status,body:await res.json()};}
  assert.equal((await request('/capabilities',{who:'nobody'})).status,401);assert.equal((await request('/capabilities',{who:'alice'})).status,403);assert.equal((await request('/capabilities')).body.ai_configured,false);
  const contact=randomUUID(),foreign=randomUUID(),job=randomUUID(),quote=randomUUID();
  await f.pool.query('INSERT INTO contacts(id,company_id,name) VALUES($1,$2,$3),($4,$5,$6)',[contact,f.companies.a,'Fixture',foreign,f.companies.b,'Foreign']);
  await f.pool.query('INSERT INTO schedule_events(id,company_id,title) VALUES($1,$2,$3)',[job,f.companies.a,'Fixture job']);await f.pool.query('INSERT INTO quotes(id,company_id,contact_id,title) VALUES($1,$2,$3,$4)',[quote,f.companies.a,contact,'Fixture quote']);
  for(const [type,id] of [['contact',contact],['job',job],['quote',quote]]){
   const body={id:randomUUID(),url:'https://example.com/reference',title:'Reference'};
   assert.equal((await request(`/records/${type}/${id}/links`,{method:'POST',body})).status,200);assert.equal((await request(`/records/${type}/${id}/links`,{method:'POST',body})).status,200);assert.equal((await request(`/records/${type}/${id}/links`)).body.links.length,1);assert.equal((await request(`/records/${type}/${id}/links`,{who:'foreign'})).status,404);
  }
  assert.equal((await request(`/records/contact/${foreign}/links`,{method:'POST',body:{id:randomUUID(),url:'https://example.com'}})).status,404);assert.equal((await request(`/records/contact/${contact}/links`,{method:'POST',who:'alice',body:{id:randomUUID(),url:'https://example.com'}})).status,403);
  assert.equal((await request('/ai',{method:'POST',body:{action:'summarize',pages:[{url:'https://example.com',text:'visible'}]}})).status,503);
  assert.equal(aiCalls,0); env.BROWSER_AI_ENABLED='true';env.OPENAI_API_KEY='fictional-test-only';env.BROWSER_AI_MODEL='fixture';
  const ai=await request('/ai',{method:'POST',body:{action:'summarize',pages:[{url:'https://example.com',text:'visible'}],cookies:'not sent'}});
  assert.equal(ai.status,200);assert.equal(ai.body.sources[0].url,'https://example.com/');assert.equal(aiCalls,1);
  assert.equal((await request('/ai',{who:'alice',method:'POST',body:{action:'summarize',pages:[{url:'https://example.com',text:'visible'}]}})).status,403);assert.equal(aiCalls,1);
  const actor=await f.actor('owner'),page={source_type:'webpage',source_id:'https://example.com/'+ 'a'.repeat(250),title:'Saved Page'};
  await assert.rejects(validateShares(f.pool,await f.actor('alice'),[page]),e=>e.status===403);assert.equal((await validateShares(f.pool,actor,[page]))[0].title,'Saved Page');
  const messages=createConversationService({pool:f.pool}),room=await messages.create(actor,{client_key:randomUUID(),member_ids:[f.ids.bob]});const sent=await messages.send(actor,room.id,{client_key:randomUUID(),cards:[page]});const cards=await messageCards(f.pool,await f.actor('bob'),[sent.id]);assert.equal(cards.get(sent.id)[0].title,'Saved Page');assert.equal(cards.get(sent.id)[0].url,page.source_id);
  await f.pool.query('UPDATE contacts SET deleted_at=now() WHERE id=$1',[contact]);assert.equal((await request(`/records/contact/${contact}/links`)).status,404);
 }finally{if(server)await new Promise(r=>server.close(r));await f.close();}
});
