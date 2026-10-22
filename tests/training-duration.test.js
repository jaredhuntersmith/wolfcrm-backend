import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining} from '../training/index.js';

// DB clock and row locks own the timer. No client timestamp is trusted.
test('task duration policy gates submission and accounts for server-timed pauses',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express();let server;
  try{
    app.use(express.json());
    const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');req.userId=fixture.ids[who];
      req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
    await installTraining({app,pool:fixture.pool,authRequired:auth});
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,{who='owner',method='GET',body}={})=>{
      const response=await fetch(base+path,{method,headers:{'X-Fixture-User':who,'Content-Type':'application/json'},
        body:body===undefined?undefined:JSON.stringify(body)});
      return {status:response.status,body:await response.json()};
    };
    const post=(path,body,who='owner')=>request(path,{who,method:'POST',body});
    const put=(path,body,who='bob')=>request(path,{who,method:'PUT',body});
    const create=async(timing,key,requiresReview=false)=>{
      const draft=await post('/definitions',{kind:'task',title:key,timing,requires_review:requiresReview});assert.equal(draft.status,200);
      assert.equal((await post(`/definitions/${draft.body.id}/publish`,{expected_revision:1})).status,200);
      const assigned=await post('/assignments',{definition_id:draft.body.id,recipient_ids:[fixture.ids.bob],request_key:key});
      assert.equal(assigned.status,200);
      return (await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===assigned.body.id).id;
    };
    for(const timing of [
      {minimum_seconds:20,maximum_seconds:10},
      {minimum_seconds:0},
      {maximum_seconds:604801},
      {estimated_minutes:1,pause_policy:'unknown'},
    ])assert.equal((await post('/definitions',{kind:'task',title:'Invalid timer',timing})).status,400);
    assert.equal((await post('/definitions',{kind:'quiz',title:'Quiz timer',timing:{minimum_seconds:1}})).body.error,'invalid_timing_policy');

    const id=await create({estimated_minutes:2,minimum_seconds:10,maximum_seconds:30,pause_policy:'allowed'},'duration-pauses');
    const path=`/recipients/${id}`;
    const initial=await request(path,{who:'bob'});
    assert.equal(initial.body.document.timing.minimum_seconds,10);
    assert.equal((await put(`${path}/responses`,{expected_revision:1,responses:{},timer_action:'rewind'})).body.error,'invalid_timer_action');
    assert.equal((await put(`${path}/responses`,{expected_revision:1,responses:{},timer_action:'start'},'foreign')).status,404);
    assert.equal((await post(`${path}/submit`,{expected_revision:1,client_now:'2099-01-01T00:00:00Z'},'bob')).body.error,'timer_not_started');
    const started=await put(`${path}/responses`,{expected_revision:1,responses:{},timer_action:'start',
      client_now:'2000-01-01T00:00:00Z'});
    assert.equal(started.status,200);assert.ok(started.body.timer_started_at);
    assert.equal((await put(`${path}/responses`,{expected_revision:1,responses:{},timer_action:'pause'})).body.error,'stale_revision');
    assert.equal((await post(`${path}/submit`,{expected_revision:2,client_elapsed_seconds:99999},'bob')).body.error,'minimum_duration_incomplete');
    await fixture.pool.query(`UPDATE training_recipients SET timer_running_since=clock_timestamp()-interval '5 seconds' WHERE id=$1`,[id]);
    const paused=await put(`${path}/responses`,{expected_revision:2,responses:{},timer_action:'pause'});
    assert.equal(paused.status,200);assert.equal(paused.body.timer_running_since,null);
    assert.ok(paused.body.timer_accumulated_seconds>=4.8&&paused.body.timer_accumulated_seconds<8);
    assert.equal((await post(`${path}/submit`,{expected_revision:3,client_elapsed_seconds:1000},'bob')).body.error,'minimum_duration_incomplete');
    const resumed=await put(`${path}/responses`,{expected_revision:3,responses:{},timer_action:'resume'});
    assert.equal(resumed.status,200);assert.ok(resumed.body.timer_running_since);
    await fixture.pool.query(`UPDATE training_recipients SET timer_running_since=clock_timestamp()-interval '7 seconds' WHERE id=$1`,[id]);
    const completed=await post(`${path}/submit`,{expected_revision:4},'bob');
    assert.equal(completed.status,200);assert.equal(completed.body.status,'completed');
    const completedRead=await request(path,{who:'bob'});
    assert.equal(completedRead.body.timer_running_since,null);
    assert.ok(completedRead.body.timer_accumulated_seconds>=11.8&&completedRead.body.timer_accumulated_seconds<18);

    const reviewID=await create({minimum_seconds:1,pause_policy:'allowed'},'duration-review',true);
    const reviewPath=`/recipients/${reviewID}`;
    assert.equal((await put(`${reviewPath}/responses`,{expected_revision:1,responses:{},timer_action:'start'})).status,200);
    await fixture.pool.query(`UPDATE training_recipients SET timer_running_since=clock_timestamp()-interval '3 seconds' WHERE id=$1`,[reviewID]);
    assert.equal((await post(`${reviewPath}/submit`,{expected_revision:2},'bob')).body.status,'awaiting_review');
    const reviewRead=await request(reviewPath,{who:'bob'});
    assert.equal(reviewRead.body.timer_running_since,null);
    assert.ok(reviewRead.body.timer_accumulated_seconds>=2.8&&reviewRead.body.timer_accumulated_seconds<8);

    const overrideID=await create({maximum_seconds:60,pause_policy:'allowed'},'duration-override');
    const overridePath=`/recipients/${overrideID}`;
    assert.equal((await put(`${overridePath}/responses`,{expected_revision:1,responses:{},timer_action:'start'})).status,200);
    await fixture.pool.query(`UPDATE training_recipients SET timer_running_since=clock_timestamp()-interval '4 seconds' WHERE id=$1`,[overrideID]);
    const overridden=await post(`${overridePath}/override`,{expected_revision:2,
      reason:'Supervisor verified completion on site after a device outage.'});
    assert.equal(overridden.body.status,'completed');
    const overrideRead=await request(overridePath,{who:'bob'});
    assert.equal(overrideRead.body.timer_running_since,null);
    assert.ok(overrideRead.body.timer_accumulated_seconds>=3.8&&overrideRead.body.timer_accumulated_seconds<8);

    const maxID=await create({maximum_seconds:5,pause_policy:'continuous'},'duration-max');
    const maxPath=`/recipients/${maxID}`;
    assert.equal((await put(`${maxPath}/responses`,{expected_revision:1,responses:{},timer_action:'start'})).status,200);
    assert.equal((await put(`${maxPath}/responses`,{expected_revision:2,responses:{},timer_action:'pause'})).body.error,'timer_pause_forbidden');
    await fixture.pool.query(`UPDATE training_recipients SET timer_running_since=clock_timestamp()-interval '10 seconds' WHERE id=$1`,[maxID]);
    assert.equal((await post(`${maxPath}/submit`,{expected_revision:2,client_now:'2000-01-01T00:00:00Z'},'bob')).body.error,'maximum_duration_exceeded');
    assert.equal((await put(`${maxPath}/responses`,{expected_revision:2,responses:{},timer_action:'resume'})).body.error,'timer_already_running');
    assert.equal((await put(`${maxPath}/responses`,{expected_revision:2,responses:{},timer_action:'start'})).body.error,'timer_already_started');
    const estimateID=await create({estimated_minutes:15},'duration-estimate-only');
    const estimatePath=`/recipients/${estimateID}`;
    assert.equal((await put(`${estimatePath}/responses`,{expected_revision:1,responses:{}})).status,200);
    assert.equal((await post(`${estimatePath}/submit`,{expected_revision:2},'bob')).body.status,'completed');
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
