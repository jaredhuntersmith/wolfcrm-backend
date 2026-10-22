import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining} from '../training/index.js';
import {drainTrainingEvents} from '../training/events.js';

test('training events are durable, deduped and dispatched transactionally',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express();let server;
  try{
    app.use(express.json());
    const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');req.userId=fixture.ids[who];req.companyId=fixture.companies.a;next();};
    await installTraining({app,pool:fixture.pool,authRequired:auth});
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,{who='owner',method='GET',body}={})=>{const response=await fetch(base+path,{method,headers:{'X-Fixture-User':who,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});return {status:response.status,body:await response.json()};};
    const draft=await request('/definitions',{method:'POST',body:{kind:'task',title:'Event task'}});
    await request(`/definitions/${draft.body.id}/publish`,{method:'POST',body:{expected_revision:1}});
    const first=await request('/assignments',{method:'POST',body:{definition_id:draft.body.id,recipient_ids:[fixture.ids.bob],request_key:'events-1'}});
    assert.equal(first.status,200);
    assert.equal((await request('/assignments',{method:'POST',body:{definition_id:draft.body.id,recipient_ids:[fixture.ids.bob],request_key:'events-1'}})).body.id,first.body.id);
    const recipient=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===first.body.id);
    await request(`/recipients/${recipient.id}/submit`,{who:'bob',method:'POST',body:{expected_revision:1}});
    const queued=(await fixture.pool.query('SELECT event_type,dedupe_key,payload FROM training_domain_events ORDER BY occurred_at,id')).rows;
    assert.deepEqual(queued.map(item=>item.event_type).sort(),['training.assignment_assigned','training.assignment_completed']);
    assert.equal(JSON.stringify(queued).includes('Event task'),false);
    assert.equal(new Set(queued.map(item=>item.dedupe_key)).size,queued.length);
    await assert.rejects(()=>drainTrainingEvents(fixture.pool,async()=>{throw new Error('engine down')}),/engine down/);
    await assert.rejects(()=>drainTrainingEvents(fixture.pool,async()=>null),/training_automation_enqueue_failed/);
    assert.equal((await fixture.pool.query('SELECT count(*)::integer AS count FROM training_domain_events WHERE dispatched_at IS NOT NULL')).rows[0].count,0);
    const emitted=[];const result=await drainTrainingEvents(fixture.pool,async(event,{db})=>{assert.ok(db);emitted.push(event);return '00000000-0000-4000-8000-000000000001';});
    assert.equal(result.dispatched,2);assert.equal(emitted.length,2);
    assert.equal((await drainTrainingEvents(fixture.pool,async()=>{})).dispatched,0);
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
