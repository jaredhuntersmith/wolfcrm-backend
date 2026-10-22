import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining} from '../training/index.js';

test('mode C requires covered video and a version-pinned passing knowledge check',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express();let server;
  try{
    app.use(express.json());
    const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');req.userId=fixture.ids[who];req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
    const muxSigner={ready:true,signPlayback:()=>({url:'https://stream.mux.com/abc123DEF456.m3u8?token=test',expires_at:new Date(Date.now()+3600_000).toISOString()})};
    const muxCatalog={ready:true,verifyPlayback:async()=>({provider:'mux',playback_id:'abc123DEF456',asset_id:'asset-verified',duration_seconds:4,policy:'signed'})};
    await installTraining({app,pool:fixture.pool,authRequired:auth,muxSigner,muxCatalog});
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,{who='owner',method='GET',body}={})=>{const response=await fetch(base+path,{method,headers:{'X-Fixture-User':who,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});return {status:response.status,body:await response.json()};};
    const url='https://player.mux.com/abc123DEF456';
    assert.equal((await request('/video/assets/verify',{method:'POST',body:{url}})).status,200);
    const definition=await request('/definitions',{method:'POST',body:{kind:'task',title:'Safety lesson',blocks:[
      {id:'safety',type:'video',title:'Safety',video:{url,mode:'C',duration_seconds:4,knowledge_check:{
        passing_percent:100,max_attempts:2,show_results:'after_review',show_answers_after_grade:false,questions:[
          {id:'q1',type:'true_false',prompt:'Wear protection?',points:1,answer:true}
        ]}}}
    ]}});assert.equal(definition.status,200);
    assert.equal((await request(`/definitions/${definition.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).status,200);
    const assigned=await request('/assignments',{method:'POST',body:{definition_id:definition.body.id,recipient_ids:[fixture.ids.bob],request_key:'mode-c'}});
    const recipient=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===assigned.body.id);
    const path=`/recipients/${recipient.id}/videos/safety`;
    const learner=(await request(`/recipients/${recipient.id}`,{who:'bob'})).body;
    assert.equal(JSON.stringify(learner).includes('"answer":true'),false);
    assert.equal((await request(`${path}/check`,{who:'bob'})).body.error,'video_coverage_incomplete');
    const started=await request(`${path}/sessions`,{who:'bob',method:'POST'});assert.equal(started.status,200);
    const sessionPath=`/video/sessions/${started.body.id}`;
    assert.equal((await request(`${sessionPath}/events`,{who:'bob',method:'POST',body:{seq:1,type:'play',position_seconds:0}})).status,200);
    await fixture.pool.query(`UPDATE training_video_sessions SET last_receipt_at=now()-interval '4 seconds' WHERE id=$1`,[started.body.id]);
    const pulse=await request(`${sessionPath}/events`,{who:'bob',method:'POST',body:{seq:2,type:'pulse',position_seconds:4}});
    assert.equal(pulse.body.watched_seconds,4);
    assert.equal((await request(`${sessionPath}/finish`,{who:'bob',method:'POST'})).body.error,'video_knowledge_check_required');
    const check=await request(`${path}/check`,{who:'bob'});
    assert.equal(check.status,200);assert.equal(JSON.stringify(check.body).includes('"answer":true'),false);
    assert.equal((await request(`${path}/check`,{who:'owner'})).status,403);
    const wrong=await request(`${path}/check`,{who:'bob',method:'POST',body:{request_key:'attempt-1',responses:{q1:false}}});
    assert.equal(wrong.status,200);assert.equal(wrong.body.passed,false);
    assert.equal((await request(`${path}/check`,{who:'bob',method:'POST',body:{request_key:'attempt-1',responses:{q1:false}}})).body.id,wrong.body.id);
    assert.equal((await request(`${path}/check`,{who:'bob',method:'POST',body:{request_key:'attempt-1',responses:{q1:true}}})).body.error,'request_key_conflict');
    const right=await request(`${path}/check`,{who:'bob',method:'POST',body:{request_key:'attempt-2',responses:{q1:true}}});
    assert.equal(right.body.passed,true);
    assert.equal((await request(`${sessionPath}/finish`,{who:'bob',method:'POST'})).body.status,'completed');
    assert.equal((await request(`/recipients/${recipient.id}/submit`,{who:'bob',method:'POST',body:{expected_revision:1}})).status,200);
    const manualDefinition=await request('/definitions',{method:'POST',body:{kind:'task',title:'Explain the safety step',blocks:[
      {id:'manual',type:'video',title:'Safety explanation',video:{url,mode:'C',duration_seconds:4,knowledge_check:{
        passing_percent:100,max_attempts:1,questions:[{id:'explain',type:'short_answer',prompt:'What did you learn?',points:2}]
      }}}
    ]}});assert.equal(manualDefinition.status,200);
    assert.equal((await request(`/definitions/${manualDefinition.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).status,200);
    const manualAssignment=await request('/assignments',{method:'POST',body:{definition_id:manualDefinition.body.id,recipient_ids:[fixture.ids.bob],request_key:'manual-video-check'}});
    const manualRecipient=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===manualAssignment.body.id);
    const manualPath=`/recipients/${manualRecipient.id}/videos/manual`;
    const manualSession=(await request(`${manualPath}/sessions`,{who:'bob',method:'POST'})).body;
    const manualSessionPath=`/video/sessions/${manualSession.id}`;
    await request(`${manualSessionPath}/events`,{who:'bob',method:'POST',body:{seq:1,type:'play',position_seconds:0}});
    await fixture.pool.query(`UPDATE training_video_sessions SET last_receipt_at=now()-interval '4 seconds' WHERE id=$1`,[manualSession.id]);
    assert.equal((await request(`${manualSessionPath}/events`,{who:'bob',method:'POST',body:{seq:2,type:'pulse',position_seconds:4}})).body.watched_seconds,4);
    const pending=await request(`${manualPath}/check`,{who:'bob',method:'POST',body:{request_key:'manual-attempt',responses:{explain:'Keep the work area clear.'}}});
    assert.equal(pending.body.status,'awaiting_manual');assert.equal(pending.body.passed,null);
    const reviewQueue=await request('/video/reviews');
    assert.equal(reviewQueue.status,200);
    assert.equal(reviewQueue.body.items.find(item=>item.id===pending.body.id)?.kind,'knowledge_check');
    assert.equal((await request('/video/reviews',{who:'bob'})).status,403);
    assert.equal((await request('/video/reviews',{who:'foreign'})).body.items.length,0);
    assert.equal((await request(`${manualSessionPath}/finish`,{who:'bob',method:'POST'})).body.error,'video_knowledge_check_required');
    assert.equal((await request(`/video/checks/${pending.body.id}/grade`,{who:'bob'})).status,403);
    assert.equal((await request(`/video/checks/${pending.body.id}/grade`,{who:'foreign'})).status,404);
    const grader=await request(`/video/checks/${pending.body.id}/grade`);assert.equal(grader.status,200);
    assert.equal(grader.body.responses.explain,'Keep the work area clear.');
    const graded=await request(`/video/checks/${pending.body.id}/grade`,{method:'POST',body:{grades:{explain:{points:2,feedback:'Correct'}},feedback:'Passed'}});
    assert.equal((await request('/video/reviews')).body.items.some(item=>item.id===pending.body.id),false);
    assert.equal(graded.status,200);assert.equal(graded.body.passed,true);
    assert.equal((await request(`${manualSessionPath}/finish`,{who:'bob',method:'POST'})).body.status,'completed');
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
