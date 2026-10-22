import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining} from '../training/index.js';

test('completion override requires scope, reason, revision and satisfied prerequisites',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express();let server;
  try{
    app.use(express.json());
    const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');if(!fixture.ids[who])return res.sendStatus(401);
      req.userId=fixture.ids[who];req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
    await installTraining({app,pool:fixture.pool,authRequired:auth});
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,{who='owner',method='GET',body}={})=>{const response=await fetch(base+path,{method,
      headers:{'X-Fixture-User':who,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
      return {status:response.status,body:await response.json()};};
    const first=await request('/quick-tasks',{method:'POST',body:{title:'Complete safety briefing',recipient_ids:[fixture.ids.bob],request_key:'override-prior'}});
    const second=await request('/quick-tasks',{method:'POST',body:{title:'Check the equipment',recipient_ids:[fixture.ids.bob],request_key:'override-next',
      prerequisite_assignment_ids:[first.body.id]}});
    const mine=(await request('/mine',{who:'bob'})).body.items;
    const prior=mine.find(item=>item.assignment_id===first.body.id),later=mine.find(item=>item.assignment_id===second.body.id);
    const reason='Supervisor verified completion on site after a device outage.';
    const override=id=>request(`/recipients/${id}/override`,{method:'POST',body:{expected_revision:1,reason}});
    assert.equal((await override(later.id)).body.error,'assignment_prerequisite_incomplete');
    assert.equal((await request(`/recipients/${prior.id}/override`,{who:'bob',method:'POST',body:{expected_revision:1,reason}})).status,403);
    assert.equal((await request(`/recipients/${prior.id}/override`,{who:'foreign',method:'POST',body:{expected_revision:1,reason}})).status,404);
    assert.equal((await request(`/recipients/${prior.id}/override`,{method:'POST',body:{expected_revision:1,reason:'Done'}})).body.error,'override_reason_too_short');
    await fixture.pool.query('UPDATE employee_permissions SET permission_overrides=$2 WHERE user_id=$1',
      [fixture.ids.alice,JSON.stringify({'training.review':true,'training.override':true})]);
    assert.equal((await request('/managed',{who:'alice'})).body.items.length,0);
    assert.equal((await request(`/recipients/${prior.id}/override`,{who:'alice',method:'POST',body:{expected_revision:1,reason}})).status,404);
    assert.equal((await request(`/supervisors/${fixture.ids.alice}/employees/${fixture.ids.bob}`,{method:'PUT',body:{supervised:true}})).status,200);
    assert.equal((await request('/managed',{who:'alice'})).body.items.filter(item=>[prior.id,later.id].includes(item.id)).length,2);
    assert.equal((await request('/managed?status=completed',{who:'alice'})).body.items.length,0);
    assert.equal((await request('/managed',{who:'bob'})).status,403);
    assert.equal((await request('/managed',{who:'foreign'})).body.items.length,0);
    assert.equal((await request(`/recipients/${prior.id}/override`,{who:'alice',method:'POST',body:{expected_revision:2,reason}})).body.error,'stale_revision');
    const done=await request(`/recipients/${prior.id}/override`,{who:'alice',method:'POST',body:{expected_revision:1,reason}});
    assert.equal(done.status,200);assert.equal(done.body.status,'completed');
    assert.equal((await request('/managed?status=completed',{who:'alice'})).body.items[0].id,prior.id);
    assert.equal((await override(prior.id)).body.error,'stale_revision');
    const history=await request(`/recipients/${prior.id}/history`,{who:'bob'});
    assert.equal(history.body.items.find(item=>item.action==='assignment.completion_overridden').details.reason,reason);
    assert.equal((await override(later.id)).body.status,'completed');
    const draft=await request('/definitions',{method:'POST',body:{kind:'quiz',title:'Pass before work',quiz:{questions:[
      {id:'q',type:'true_false',prompt:'Wear protection?',answer:true}]}}});
    await request(`/definitions/${draft.body.id}/publish`,{method:'POST',body:{expected_revision:1}});
    const assigned=await request('/assignments',{method:'POST',body:{definition_id:draft.body.id,recipient_ids:[fixture.ids.bob],request_key:'quiz-override'}});
    const quiz=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===assigned.body.id);
    assert.equal((await override(quiz.id)).body.error,'completion_override_not_permitted');
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
