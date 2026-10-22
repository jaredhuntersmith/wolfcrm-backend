import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining} from '../training/index.js';

test('interactive video pauses at checkpoints and requires replay after an incorrect answer',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express();let server;
  try{
    app.use(express.json());
    const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');req.userId=fixture.ids[who];req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
    const muxSigner={ready:true,signPlayback:()=>({url:'https://stream.mux.com/abc123DEF456.m3u8?token=test',expires_at:new Date(Date.now()+3600_000).toISOString()})};
    const muxCatalog={ready:true,verifyPlayback:async()=>({provider:'mux',playback_id:'abc123DEF456',asset_id:'asset-verified',duration_seconds:8,policy:'signed'})};
    await installTraining({app,pool:fixture.pool,authRequired:auth,muxSigner,muxCatalog});
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,{who='owner',method='GET',body}={})=>{const response=await fetch(base+path,{method,headers:{'X-Fixture-User':who,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});return {status:response.status,body:await response.json()};};
    const url='https://player.mux.com/abc123DEF456';
    assert.equal((await request('/video/assets/verify',{method:'POST',body:{url}})).status,200);
    const definition=await request('/definitions',{method:'POST',body:{kind:'task',title:'Interactive safety',blocks:[
      {id:'interactive',type:'video',title:'Interactive video',video:{url,mode:'D',duration_seconds:8,checkpoints:[
        {id:'notice',kind:'instruction',at_seconds:3,text:'Inspect your tool.'},
        {id:'question',kind:'question',at_seconds:6,question:{id:'q1',type:'true_false',prompt:'Is this safe?',points:1,answer:true},
          max_attempts:2,replay_seconds:2,require_correct:true}
      ]}}
    ]}});assert.equal(definition.status,200);
    assert.equal((await request(`/definitions/${definition.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).status,200);
    const assigned=await request('/assignments',{method:'POST',body:{definition_id:definition.body.id,recipient_ids:[fixture.ids.bob],request_key:'interactive-video'}});
    const recipient=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===assigned.body.id);
    const learner=(await request(`/recipients/${recipient.id}`,{who:'bob'})).body;
    assert.equal(JSON.stringify(learner).includes('"answer":true'),false);
    const path=`/recipients/${recipient.id}/videos/interactive`;
    const started=await request(`${path}/sessions`,{who:'bob',method:'POST'});assert.equal(started.status,200);
    const sessionPath=`/video/sessions/${started.body.id}`;
    const event=(seq,type,position_seconds)=>request(`${sessionPath}/events`,{who:'bob',method:'POST',body:{seq,type,position_seconds}});
    const elapsed=seconds=>fixture.pool.query(`UPDATE training_video_sessions SET last_receipt_at=now()-($2::text||' seconds')::interval WHERE id=$1`,[started.body.id,seconds]);
    assert.equal((await request(`${path}/checkpoints/notice`,{who:'bob',method:'POST',body:{request_key:'early',acknowledged:true}})).body.error,'video_checkpoint_not_reached');
    assert.equal((await request(`${sessionPath}/finish`,{who:'bob',method:'POST'})).body.error,'video_coverage_incomplete');
    assert.equal((await event(1,'play',0)).status,200);
    await elapsed(3);
    const first=await event(2,'pulse',3);assert.equal(first.body.reason,'checkpoint_required');assert.equal(first.body.watched_seconds,3);
    assert.equal((await event(3,'play',3)).body.reason,'checkpoint_required');
    assert.equal((await request(`${path}/checkpoints/question`,{who:'bob',method:'POST',body:{request_key:'premature',response:true}})).body.error,'video_prerequisite_checkpoint');
    const listed=await request(`${path}/checkpoints`,{who:'bob'});
    assert.equal(listed.body.next_checkpoint_id,'notice');assert.equal(listed.body.items[1].locked,true);
    const acknowledged=await request(`${path}/checkpoints/notice`,{who:'bob',method:'POST',body:{request_key:'ack-1',acknowledged:true}});
    assert.equal(acknowledged.body.unlocked,true);
    assert.equal((await request(`${path}/checkpoints/notice`,{who:'bob',method:'POST',body:{request_key:'ack-1',acknowledged:true}})).body.attempts_used,1);
    assert.equal((await event(4,'play',3)).status,200);
    await elapsed(3);
    const second=await event(5,'pulse',6);assert.equal(second.body.reason,'checkpoint_required');assert.equal(second.body.watched_seconds,6);
    const wrong=await request(`${path}/checkpoints/question`,{who:'bob',method:'POST',body:{request_key:'q-wrong',response:false}});
    assert.equal(wrong.body.unlocked,false);assert.equal(wrong.body.replay_required,true);assert.equal(wrong.body.replay_from,4);
    assert.equal((await request(`${path}/checkpoints/question`,{who:'bob',method:'POST',body:{request_key:'q-right',response:true}})).body.error,'checkpoint_replay_required');
    assert.equal((await event(6,'seek',4)).status,200);
    assert.equal((await event(7,'play',4)).status,200);
    await elapsed(2);
    const replay=await event(8,'pulse',6);assert.equal(replay.body.reason,'checkpoint_required');
    assert.equal((await request(`${path}/checkpoints`,{who:'bob'})).body.items[1].replay_required,false);
    const right=await request(`${path}/checkpoints/question`,{who:'bob',method:'POST',body:{request_key:'q-right',response:true}});
    assert.equal(right.body.unlocked,true);
    assert.equal((await event(9,'play',6)).status,200);
    await elapsed(2);
    assert.equal((await event(10,'pulse',8)).body.watched_seconds,8);
    assert.equal((await request(`${sessionPath}/finish`,{who:'bob',method:'POST'})).body.status,'completed');
    assert.equal((await request(`/recipients/${recipient.id}/submit`,{who:'bob',method:'POST',body:{expected_revision:1}})).status,200);
    const manualDefinition=await request('/definitions',{method:'POST',body:{kind:'task',title:'Interactive explanation',blocks:[
      {id:'manual',type:'video',title:'Explain the step',video:{url,mode:'D',duration_seconds:8,checkpoints:[
        {id:'written',kind:'question',at_seconds:2,question:{id:'q-written',type:'short_answer',prompt:'Explain the hazard.',points:2},
          max_attempts:1,require_correct:true}
      ]}}
    ]}});assert.equal(manualDefinition.status,200);
    assert.equal((await request(`/definitions/${manualDefinition.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).status,200);
    const manualAssignment=await request('/assignments',{method:'POST',body:{definition_id:manualDefinition.body.id,recipient_ids:[fixture.ids.bob],request_key:'interactive-manual'}});
    const manualRecipient=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===manualAssignment.body.id);
    const manualPath=`/recipients/${manualRecipient.id}/videos/manual`;
    const manualSession=(await request(`${manualPath}/sessions`,{who:'bob',method:'POST'})).body;
    const manualSessionPath=`/video/sessions/${manualSession.id}`;
    await request(`${manualSessionPath}/events`,{who:'bob',method:'POST',body:{seq:1,type:'play',position_seconds:0}});
    await fixture.pool.query(`UPDATE training_video_sessions SET last_receipt_at=now()-interval '2 seconds' WHERE id=$1`,[manualSession.id]);
    assert.equal((await request(`${manualSessionPath}/events`,{who:'bob',method:'POST',body:{seq:2,type:'pulse',position_seconds:2}})).body.reason,'checkpoint_required');
    const pending=await request(`${manualPath}/checkpoints/written`,{who:'bob',method:'POST',body:{request_key:'written-1',response:'Inspect the ladder.'}});
    assert.equal(pending.body.status,'awaiting_manual');assert.equal(pending.body.unlocked,false);
    const reviewQueue=await request('/video/reviews');
    assert.equal(reviewQueue.status,200);
    assert.equal(reviewQueue.body.items.find(item=>item.kind==='checkpoint'&&item.recipient_id===manualRecipient.id)?.checkpoint_id,'written');
    const attempt=(await fixture.pool.query(`SELECT id FROM training_video_checkpoint_attempts WHERE company_id=$1 AND recipient_id=$2`,
      [fixture.companies.a,manualRecipient.id])).rows[0];
    assert.equal((await request(`/video/checkpoints/${attempt.id}/grade`,{who:'bob'})).status,403);
    const grader=await request(`/video/checkpoints/${attempt.id}/grade`);
    assert.equal(grader.body.response,'Inspect the ladder.');
    assert.equal((await request(`/video/checkpoints/${attempt.id}/grade`,{method:'POST',body:{points:2,feedback:'Good explanation'}})).body.unlocked,true);
    assert.equal((await request('/video/reviews')).body.items.some(item=>item.id===attempt.id),false);
    assert.equal((await request(`${manualSessionPath}/events`,{who:'bob',method:'POST',body:{seq:3,type:'play',position_seconds:2}})).status,200);
    await fixture.pool.query(`UPDATE training_video_sessions SET last_receipt_at=now()-interval '3 seconds' WHERE id=$1`,[manualSession.id]);
    assert.equal((await request(`${manualSessionPath}/events`,{who:'bob',method:'POST',body:{seq:4,type:'pulse',position_seconds:5}})).body.watched_seconds,5);
    await fixture.pool.query(`UPDATE training_video_sessions SET last_receipt_at=now()-interval '3 seconds' WHERE id=$1`,[manualSession.id]);
    assert.equal((await request(`${manualSessionPath}/events`,{who:'bob',method:'POST',body:{seq:5,type:'pulse',position_seconds:8}})).body.watched_seconds,8);
    assert.equal((await request(`${manualSessionPath}/finish`,{who:'bob',method:'POST'})).body.status,'completed');
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
