import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining} from '../training/index.js';

test('assignment prerequisites block direct response and quiz APIs until each recipient completes prior work',{timeout:120000},async()=>{
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
    const first=await request('/quick-tasks',{method:'POST',body:{title:'Safety briefing',recipient_ids:[fixture.ids.alice],request_key:'first'}});
    assert.equal(first.status,200);
    const secondBody={title:'Use equipment',recipient_ids:[fixture.ids.alice],request_key:'second',prerequisite_assignment_ids:[first.body.id]};
    const second=await request('/quick-tasks',{method:'POST',body:secondBody});assert.equal(second.status,200);
    assert.equal((await request('/quick-tasks',{method:'POST',body:secondBody})).body.id,second.body.id);
    assert.equal((await request('/quick-tasks',{method:'POST',body:{...secondBody,prerequisite_assignment_ids:[]}})).body.error,'request_key_conflict');
    const mine=(await request('/mine',{who:'alice'})).body.items;
    const prior=mine.find(item=>item.assignment_id===first.body.id),later=mine.find(item=>item.assignment_id===second.body.id);
    assert.ok(prior&&later);
    assert.equal(later.prerequisites_blocked,true);
    const detail=await request(`/recipients/${later.id}`,{who:'alice'});
    assert.equal(detail.body.prerequisites.blocked,true);
    assert.deepEqual(detail.body.prerequisites.items.map(item=>item.assignment_id),[first.body.id]);
    assert.equal((await request(`/recipients/${later.id}/responses`,{who:'alice',method:'PUT',body:{expected_revision:1,responses:{}}})).body.error,'assignment_prerequisite_incomplete');
    assert.equal((await request(`/recipients/${later.id}/submit`,{who:'alice',method:'POST',body:{expected_revision:1}})).body.error,'assignment_prerequisite_incomplete');
    assert.equal((await request(`/recipients/${prior.id}/submit`,{who:'alice',method:'POST',body:{expected_revision:1}})).body.status,'completed');
    assert.equal((await request(`/recipients/${later.id}`,{who:'alice'})).body.prerequisites.blocked,false);
    assert.equal((await request('/mine',{who:'alice'})).body.items.find(item=>item.id===later.id).prerequisites_blocked,false);
    assert.equal((await request(`/recipients/${later.id}/submit`,{who:'alice',method:'POST',body:{expected_revision:1}})).body.status,'completed');
    const quiz={kind:'quiz',title:'Safety assessment',quiz:{questions:[{id:'q',type:'true_false',prompt:'Safe?',answer:true}]},blocks:[]};
    const draft=await request('/definitions',{method:'POST',body:quiz});assert.equal(draft.status,200);
    assert.equal((await request(`/definitions/${draft.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).status,200);
    const third=await request('/quick-tasks',{method:'POST',body:{title:'Equipment inspection',recipient_ids:[fixture.ids.alice],request_key:'third'}});
    const quizAssignment=await request('/assignments',{method:'POST',body:{definition_id:draft.body.id,recipient_ids:[fixture.ids.alice],
      prerequisite_assignment_ids:[third.body.id],request_key:'quiz-locked'}});
    assert.equal(quizAssignment.status,200);
    const current=(await request('/mine',{who:'alice'})).body.items;
    const quizRecipient=current.find(item=>item.assignment_id===quizAssignment.body.id);
    assert.equal((await request(`/recipients/${quizRecipient.id}/quiz/attempts`,{who:'alice',method:'POST',body:{}})).body.error,'assignment_prerequisite_incomplete');
    const thirdRecipient=current.find(item=>item.assignment_id===third.body.id);
    assert.equal((await request(`/recipients/${thirdRecipient.id}/submit`,{who:'alice',method:'POST',body:{expected_revision:1}})).body.status,'completed');
    assert.equal((await request(`/recipients/${quizRecipient.id}/quiz/attempts`,{who:'alice',method:'POST',body:{}})).status,200);
    assert.equal((await request('/assignments',{method:'POST',body:{definition_id:draft.body.id,recipient_ids:[fixture.ids.bob],
      prerequisite_assignment_ids:[first.body.id],request_key:'missing-prior'}})).body.error,'assignment_prerequisite_recipient_missing');
    assert.equal((await request('/assignments',{method:'POST',body:{definition_id:draft.body.id,recipient_ids:[fixture.ids.alice],
      prerequisite_assignment_ids:[first.body.id,first.body.id],request_key:'duplicate'}})).body.error,'duplicate_assignment_prerequisite');
    assert.equal((await request('/quick-tasks',{who:'foreign',method:'POST',body:{title:'Foreign work',recipient_ids:[fixture.ids.foreign],
      prerequisite_assignment_ids:[first.body.id],request_key:'cross-company'}})).body.error,'assignment_prerequisite_not_found');
    const listed=await request('/assignments');assert.equal(listed.status,200);
    assert.ok(listed.body.items.some(item=>item.id===first.body.id));
    assert.equal((await request('/assignments',{who:'alice'})).status,403);
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
