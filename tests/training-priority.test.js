import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining} from '../training/index.js';
import {installTrainingSchema} from '../training/schema.js';

test('assignment priority is tenant-scoped, idempotent, and visible to recipients',{timeout:120000},async()=>{
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
    const draft=await post('/definitions',{kind:'task',title:'Priority inspection'});assert.equal(draft.status,200);
    assert.equal((await post(`/definitions/${draft.body.id}/publish`,{expected_revision:1})).status,200);
    const body={definition_id:draft.body.id,recipient_ids:[fixture.ids.bob],priority:'high',request_key:'priority-high'};
    assert.equal((await post('/assignments',{...body,priority:'immediate'})).body.error,'invalid_assignment_priority');
    const assigned=await post('/assignments',body);assert.equal(assigned.status,200);
    assert.equal((await post('/assignments',body)).body.id,assigned.body.id);
    assert.equal((await post('/assignments',{...body,priority:'low'})).body.error,'request_key_conflict');
    const mine=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===assigned.body.id);
    assert.equal(mine.priority,'high');
    assert.equal((await request(`/recipients/${mine.id}`,{who:'bob'})).body.priority,'high');
    assert.equal((await request(`/recipients/${mine.id}`,{who:'foreign'})).status,404);
    assert.equal((await request('/assignments')).body.items.find(item=>item.id===assigned.body.id).priority,'high');
    const event=(await fixture.pool.query(`SELECT payload FROM training_domain_events WHERE event_type='training.assignment_assigned'
      AND subject_id=$1`,[mine.id])).rows[0].payload;
    assert.equal(event.priority,'high');
    const quick=await post('/quick-tasks',{title:'Urgent cleanup',recipient_ids:[fixture.ids.bob],priority:'urgent',request_key:'priority-quick'});
    assert.equal(quick.status,200);
    const quickMine=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===quick.body.id);
    assert.equal(quickMine.priority,'urgent');
    const normal=await post('/quick-tasks',{title:'Routine cleanup',recipient_ids:[fixture.ids.bob],request_key:'priority-normal'});
    assert.equal(normal.status,200);
    const normalMine=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===normal.body.id);
    assert.equal(normalMine.priority,'normal');
    await installTrainingSchema(fixture.pool);
    const retained=(await fixture.pool.query(`SELECT priority FROM training_assignments WHERE id=$1`,[assigned.body.id])).rows[0];
    assert.equal(retained.priority,'high');
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
