import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining} from '../training/index.js';

test('high-assurance mode composes checkpoints, final check, minimum watch time and supervisor review',{timeout:120000},async()=>{
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
    const definition=await request('/definitions',{method:'POST',body:{kind:'task',title:'High-assurance safety',requires_review:false,blocks:[
      {id:'high',type:'video',title:'Safety',video:{url,mode:'E',duration_seconds:8,min_watch_seconds:9,supervisor_approval:true,
        checkpoints:[
          {id:'c1',kind:'question',at_seconds:2,question:{id:'q1',type:'true_false',prompt:'First safe step?',points:1,answer:true}},
          {id:'c2',kind:'question',at_seconds:5,question:{id:'q2',type:'true_false',prompt:'Second safe step?',points:1,answer:true}}
        ],knowledge_check:{passing_percent:100,max_attempts:1,questions:[
          {id:'final',type:'true_false',prompt:'Is the full procedure safe?',points:1,answer:true}
        ]}}}
    ]}});assert.equal(definition.status,200);assert.equal(definition.body.draft.requires_review,true);
    assert.equal((await request(`/definitions/${definition.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).status,200);
    const assigned=await request('/assignments',{method:'POST',body:{definition_id:definition.body.id,recipient_ids:[fixture.ids.bob],request_key:'high-assurance'}});
    const recipient=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===assigned.body.id);
    const path=`/recipients/${recipient.id}/videos/high`,started=(await request(`${path}/sessions`,{who:'bob',method:'POST'})).body;
    const sessionPath=`/video/sessions/${started.id}`;
    const event=(seq,type,position_seconds)=>request(`${sessionPath}/events`,{who:'bob',method:'POST',body:{seq,type,position_seconds}});
    const elapsed=seconds=>fixture.pool.query(`UPDATE training_video_sessions SET last_receipt_at=now()-($2::text||' seconds')::interval WHERE id=$1`,[started.id,seconds]);
    await event(1,'play',0);await elapsed(2);
    assert.equal((await event(2,'pulse',2)).body.reason,'checkpoint_required');
    assert.equal((await request(`${path}/checkpoints/c1`,{who:'bob',method:'POST',body:{request_key:'c1',response:true}})).body.unlocked,true);
    await event(3,'play',2);await elapsed(3);
    assert.equal((await event(4,'pulse',5)).body.reason,'checkpoint_required');
    assert.equal((await request(`${path}/checkpoints/c2`,{who:'bob',method:'POST',body:{request_key:'c2',response:true}})).body.unlocked,true);
    await event(5,'play',5);await elapsed(3);
    assert.equal((await event(6,'pulse',8)).body.watched_seconds,8);
    assert.equal((await request(`${sessionPath}/finish`,{who:'bob',method:'POST'})).body.error,'video_knowledge_check_required');
    assert.equal((await request(`${path}/check`,{who:'bob',method:'POST',body:{request_key:'final',responses:{final:true}}})).body.passed,true);
    assert.equal((await request(`${sessionPath}/finish`,{who:'bob',method:'POST'})).body.error,'minimum_watch_duration_incomplete');
    assert.equal((await event(7,'seek',7)).status,200);
    assert.equal((await event(8,'play',7)).status,200);
    await elapsed(1);
    assert.equal((await event(9,'pulse',8)).body.watch_time_seconds>=9,true);
    assert.equal((await request(`${sessionPath}/finish`,{who:'bob',method:'POST'})).body.status,'completed');
    const submitted=await request(`/recipients/${recipient.id}/submit`,{who:'bob',method:'POST',body:{expected_revision:1}});
    assert.equal(submitted.body.status,'awaiting_review');
    assert.equal((await request(`/recipients/${recipient.id}/review`,{method:'POST',body:{expected_revision:2,decision:'approve',feedback:'Observed'}})).body.status,'completed');
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
