import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining,runTrainingRecurrences} from '../training/index.js';

test('recurrence creates one independent pinned assignment per local date across DST',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express();let server;
  try{
    app.use(express.json());
    const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');req.userId=fixture.ids[who];req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
    await installTraining({app,pool:fixture.pool,authRequired:auth});
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,{who='owner',method='GET',body}={})=>{const response=await fetch(base+path,{method,
      headers:{'X-Fixture-User':who,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
      return {status:response.status,body:await response.json()};};
    const definition=(await request('/definitions',{method:'POST',body:{kind:'task',title:'Daily truck check',blocks:[]}})).body;
    const version=(await request(`/definitions/${definition.id}/publish`,{method:'POST',body:{expected_revision:1}})).body;
    const body={definition_id:definition.id,recipient_ids:[fixture.ids.bob],time_zone:'America/New_York',
      interval_days:1,start_on:'2026-10-31',local_time:'09:00',due_after_hours:24,end_on:'2026-11-01',request_key:'truck-daily'};
    assert.equal((await request('/recurrences',{who:'bob',method:'POST',body})).status,403);
    assert.equal((await request('/recurrences',{method:'POST',body:{...body,time_zone:'Invalid/Zone'}})).body.error,'invalid_time_zone');
    const rule=await request('/recurrences',{method:'POST',body});assert.equal(rule.status,200);
    assert.equal(rule.body.version_id,version.id);
    assert.equal(new Date(rule.body.next_at).toISOString(),'2026-10-31T13:00:00.000Z');
    assert.equal((await request('/recurrences',{method:'POST',body})).body.id,rule.body.id);
    assert.equal((await request('/recurrences',{method:'POST',body:{...body,due_after_hours:48}})).body.error,'request_key_conflict');
    assert.deepEqual(await runTrainingRecurrences(fixture.pool,{now:'2026-10-31T13:00:01Z'}),{processed:1,assigned:1,skipped:0});
    assert.deepEqual(await runTrainingRecurrences(fixture.pool,{now:'2026-10-31T13:00:01Z'}),{processed:0,assigned:0,skipped:0});
    const afterFirst=(await request('/recurrences')).body.items.find(item=>item.id===rule.body.id);
    assert.equal(new Date(afterFirst.next_at).toISOString(),'2026-11-01T14:00:00.000Z');
    assert.deepEqual(await runTrainingRecurrences(fixture.pool,{now:'2026-11-01T14:00:01Z'}),{processed:1,assigned:1,skipped:0});
    const afterSecond=(await request('/recurrences')).body.items.find(item=>item.id===rule.body.id);
    assert.equal(afterSecond.active,false);
    const occurrences=(await fixture.pool.query(`SELECT o.local_date::text AS local_date,o.assignment_id,a.version_id
      FROM training_recurrence_occurrences o JOIN training_assignments a ON a.id=o.assignment_id
      WHERE o.company_id=$1 AND o.rule_id=$2 ORDER BY o.local_date`,[fixture.companies.a,rule.body.id])).rows;
    assert.deepEqual(occurrences.map(item=>item.local_date),['2026-10-31','2026-11-01']);
    assert.notEqual(occurrences[0].assignment_id,occurrences[1].assignment_id);
    assert.ok(occurrences.every(item=>item.version_id===version.id));
    assert.equal((await request('/mine',{who:'bob'})).body.items.filter(item=>occurrences.some(o=>o.assignment_id===item.assignment_id)).length,2);
    const skipBody={...body,start_on:'2026-11-02',end_on:'2026-11-02',request_key:'truck-skip'};
    const skipRule=await request('/recurrences',{method:'POST',body:skipBody});assert.equal(skipRule.status,200);
    await fixture.pool.query(`UPDATE users SET deleted_at=now() WHERE id=$1`,[fixture.ids.bob]);
    assert.deepEqual(await runTrainingRecurrences(fixture.pool,{now:'2026-11-02T14:00:01Z'}),{processed:1,assigned:0,skipped:1});
    assert.equal((await fixture.pool.query(`SELECT status FROM training_recurrence_occurrences WHERE rule_id=$1`,[skipRule.body.id])).rows[0].status,'no_active_recipients');
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
