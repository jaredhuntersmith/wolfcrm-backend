import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining} from '../training/index.js';

test('mandatory video credits elapsed foreground playback, rejects skips and gates submit',{timeout:120000},async()=>{
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
    const definition=await request('/definitions',{method:'POST',body:{kind:'task',title:'Watch the safety video',blocks:[
      {id:'video',type:'video',title:'Safety video',video:{url,mode:'B',duration_seconds:4}}
    ]}});assert.equal(definition.status,200);
    assert.equal((await request(`/definitions/${definition.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).status,200);
    const assigned=await request('/assignments',{method:'POST',body:{definition_id:definition.body.id,recipient_ids:[fixture.ids.bob],request_key:'video-session-test'}});
    assert.equal(assigned.status,200);
    const recipient=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===assigned.body.id);
    assert.ok(recipient);
    const path=`/recipients/${recipient.id}/videos/video`;
    assert.equal((await request(`${path}/progress`,{who:'owner'})).status,403);
    assert.equal((await request(`${path}/sessions`,{who:'owner',method:'POST'})).status,403);
    const started=await request(`${path}/sessions`,{who:'bob',method:'POST'});
    assert.equal(started.status,200);
    assert.match(started.body.playback_url,/stream\.mux\.com/);
    const sessionPath=`/video/sessions/${started.body.id}`;
    const send=async(seq,type,position_seconds,rate=1,extra={})=>request(`${sessionPath}/events`,{who:'bob',method:'POST',body:{seq,type,position_seconds,rate,...extra}});
    assert.equal((await request(sessionPath,{who:'owner'})).status,403);
    assert.equal((await request(`${sessionPath}/finish`,{who:'bob',method:'POST'})).body.error,'video_coverage_incomplete');
    const oversized=await send(1,'play',0,1,{padding:'x'.repeat(1024)});
    assert.equal(oversized.status,413);assert.equal(oversized.body.error,'video_event_too_large');
    assert.equal((await send(1,'play',0)).status,200);
    await fixture.pool.query(`INSERT INTO training_video_events
      (company_id,session_id,seq,event_hash,event_type,position_seconds,rate,accepted)
      SELECT $1,$2,n,'fixture-event-'||n,'pulse',0,1,true FROM generate_series(2,120) AS n`,
      [fixture.companies.a,started.body.id]);
    await fixture.pool.query(`UPDATE training_video_sessions SET last_seq=120 WHERE company_id=$1 AND id=$2`,
      [fixture.companies.a,started.body.id]);
    const throttled=await send(121,'pulse',0);
    assert.equal(throttled.status,429);assert.equal(throttled.body.error,'video_event_rate_limited');
    assert.equal((await send(1,'play',0)).status,200); // Idempotent retry remains safe at the limit.
    await fixture.pool.query(`DELETE FROM training_video_events WHERE company_id=$1 AND session_id=$2 AND seq BETWEEN 2 AND 120`,
      [fixture.companies.a,started.body.id]);
    await fixture.pool.query(`UPDATE training_video_sessions SET last_seq=1 WHERE company_id=$1 AND id=$2`,
      [fixture.companies.a,started.body.id]);
    await fixture.pool.query(`UPDATE training_video_sessions SET last_receipt_at=now()-interval '2 seconds' WHERE id=$1`,[started.body.id]);
    const first=await send(2,'pulse',2);assert.equal(first.body.watched_seconds,2);
    const skipped=await send(3,'seek',4);assert.equal(skipped.body.accepted,false);assert.equal(skipped.body.resume_position,2);
    const replay=await send(3,'seek',4);assert.equal(replay.status,200);assert.equal(replay.body.accepted,false);
    assert.equal((await send(3,'seek',3)).body.error,'video_event_replay_conflict');
    assert.equal((await send(4,'background',2)).status,200);
    await fixture.pool.query(`UPDATE training_video_sessions SET last_receipt_at=now()-interval '2 seconds' WHERE id=$1`,[started.body.id]);
    assert.equal((await send(5,'pulse',4)).body.watched_seconds,2);
    assert.equal((await send(6,'foreground',2)).status,200);
    assert.equal((await send(7,'play',2)).status,200);
    await fixture.pool.query(`UPDATE training_video_sessions SET last_receipt_at=now()-interval '2 seconds' WHERE id=$1`,[started.body.id]);
    assert.equal((await send(8,'pulse',4)).body.watched_seconds,4);
    assert.equal((await request(`${sessionPath}/finish`,{who:'bob',method:'POST'})).body.status,'completed');
    assert.equal((await request(`/recipients/${recipient.id}/submit`,{who:'bob',method:'POST',body:{expected_revision:1}})).status,200);
    const analytics=await request('/analytics?scope=self',{who:'bob'});
    assert.equal(analytics.status,200);assert.equal(analytics.body.video_coverage_seconds,4);
    assert.equal(analytics.body.time_spent_seconds,null);
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});

test('mandatory video resumes after replaced or expired sessions without trusting delayed events or client clocks',
  {timeout:120000},async()=>{
    const fixture=await createCommsFixture(),app=express();let server;
    try{
      app.use(express.json());
      const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');req.userId=fixture.ids[who];
        req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
      const muxSigner={ready:true,signPlayback:()=>({url:'https://stream.mux.com/abc123DEF456.m3u8?token=test',
        expires_at:new Date(Date.now()+3600_000).toISOString()})};
      const muxCatalog={ready:true,verifyPlayback:async()=>({provider:'mux',playback_id:'abc123DEF456',
        asset_id:'asset-verified',duration_seconds:4,policy:'signed'})};
      await installTraining({app,pool:fixture.pool,authRequired:auth,muxSigner,muxCatalog});
      server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
      const base=`http://127.0.0.1:${server.address().port}/api/training`;
      const request=async(path,{who='bob',method='GET',body}={})=>{const response=await fetch(base+path,{method,
        headers:{'X-Fixture-User':who,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
        return {status:response.status,body:await response.json()};};
      const url='https://player.mux.com/abc123DEF456';
      assert.equal((await request('/video/assets/verify',{who:'owner',method:'POST',body:{url}})).status,200);
      const definition=await request('/definitions',{who:'owner',method:'POST',body:{kind:'task',title:'Safe resume',blocks:[
        {id:'requires',type:'form_field',field_type:'yes_no',label:'Watch safety video?'},
        {id:'confirmed',type:'form_field',field_type:'yes_no',label:'Ready to watch?',
          visible_if:{block_id:'requires',equals:'true'}},
        {id:'video',type:'video',title:'Safety',video:{url,mode:'B',duration_seconds:4},
          visible_if:{block_id:'confirmed',equals:'true'}}]}});
      assert.equal(definition.status,200);
      assert.equal((await request(`/definitions/${definition.body.id}/publish`,{who:'owner',method:'POST',body:{expected_revision:1}})).status,200);
      const assignment=await request('/assignments',{who:'owner',method:'POST',body:{definition_id:definition.body.id,
        recipient_ids:[fixture.ids.bob],request_key:'video-resume-security'}});
      assert.equal(assignment.status,200);
      const recipient=(await request('/mine')).body.items.find(item=>item.assignment_id===assignment.body.id);
      const start=()=>request(`/recipients/${recipient.id}/videos/video/sessions`,{method:'POST'});
      const event=(id,seq,type,position_seconds,extra={})=>request(`/video/sessions/${id}/events`,{method:'POST',
        body:{seq,type,position_seconds,rate:1,...extra}});
      assert.equal((await start()).body.error,'video_block_hidden');
      assert.equal((await request(`/recipients/${recipient.id}/responses`,{method:'PUT',
        body:{expected_revision:1,responses:{requires:{value:true},confirmed:{value:true}}}})).status,200);
      const first=(await start()).body;
      assert.equal((await event(first.id,1,'play',0)).status,200);
      await fixture.pool.query(`UPDATE training_video_sessions SET last_receipt_at=now()-interval '2 seconds' WHERE id=$1`,[first.id]);
      assert.equal((await event(first.id,2,'pulse',2)).body.watched_seconds,2);
      const replacement=(await start()).body;
      assert.equal(replacement.resume_position,2);
      assert.equal((await event(first.id,3,'pulse',3)).body.error,'video_session_expired');
      assert.equal((await request(`/recipients/${recipient.id}/responses`,{method:'PUT',
        body:{expected_revision:2,responses:{requires:{value:false}}}})).status,200);
      assert.equal((await request(`/recipients/${recipient.id}/responses`,{method:'PUT',
        body:{expected_revision:3,responses:{requires:{value:false},confirmed:{value:true}}}})).body.error,'hidden_field_response');
      assert.equal((await event(replacement.id,1,'play',2)).body.error,'video_block_hidden');
      assert.equal((await start()).body.error,'video_block_hidden');
      assert.equal((await request(`/recipients/${recipient.id}/responses`,{method:'PUT',
        body:{expected_revision:3,responses:{requires:{value:true},confirmed:{value:true}}}})).status,200);
      assert.equal((await event(replacement.id,1,'play',2,{rate:2})).body.error,'video_rate_exceeded');
      assert.equal((await event(replacement.id,2,'play',2)).body.error,'video_event_sequence_gap');
      assert.equal((await request(`/video/sessions/${replacement.id}`,{who:'alice'})).status,403);
      assert.equal((await request(`/video/sessions/${replacement.id}`,{who:'foreign'})).status,404);
      await fixture.pool.query(`UPDATE training_video_sessions SET expires_at=now()-interval '1 second' WHERE id=$1`,[replacement.id]);
      assert.equal((await event(replacement.id,1,'play',2)).body.error,'video_session_expired');
      const resumed=(await start()).body;
      assert.equal(resumed.resume_position,2);
      assert.equal((await event(resumed.id,1,'play',2,{client_occurred_at:'2099-01-01T00:00:00Z'})).status,200);
      await fixture.pool.query(`UPDATE training_video_sessions SET last_receipt_at=now()-interval '10 seconds' WHERE id=$1`,[resumed.id]);
      assert.equal((await event(resumed.id,2,'pulse',4,{client_occurred_at:'2099-01-01T00:00:10Z'})).body.watched_seconds,2);
      assert.equal((await event(resumed.id,3,'seek',1)).body.accepted,true);
      assert.equal((await event(resumed.id,4,'play',1)).status,200);
      await fixture.pool.query(`UPDATE training_video_sessions SET last_receipt_at=now()-interval '1 second' WHERE id=$1`,[resumed.id]);
      assert.equal((await event(resumed.id,5,'pulse',2)).body.watched_seconds,2);
      await fixture.pool.query(`UPDATE training_video_sessions SET last_receipt_at=now()-interval '2 seconds' WHERE id=$1`,[resumed.id]);
      assert.equal((await event(resumed.id,6,'pulse',4)).body.watched_seconds,4);
      assert.equal((await request(`/video/sessions/${resumed.id}/finish`,{method:'POST'})).body.status,'completed');
    }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
  });
