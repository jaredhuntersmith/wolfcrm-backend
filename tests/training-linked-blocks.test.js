import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining} from '../training/index.js';
import {installTrainingSchema} from '../training/schema.js';

test('linked quiz and lesson runs are pinned, private, and gate parent completion',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express();let server;
  try{
    app.use(express.json());
    const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');req.userId=fixture.ids[who];
      req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
    await installTraining({app,pool:fixture.pool,authRequired:auth});
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,{who='owner',method='GET',body}={})=>{const response=await fetch(base+path,{method,
      headers:{'X-Fixture-User':who,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
      return {status:response.status,body:await response.json()};};
    const post=(path,body,who='owner')=>request(path,{who,method:'POST',body});
    const lesson=await post('/definitions',{kind:'task',title:'Inspect ladder'});
    const lessonVersion=await post(`/definitions/${lesson.body.id}/publish`,{expected_revision:1});
    const quiz=await post('/definitions',{kind:'quiz',title:'Ladder quiz',quiz:{passing_percent:100,max_attempts:1,
      questions:[{id:'safe',type:'true_false',prompt:'Inspect before use?',points:1,answer:true}]}});
    assert.equal(quiz.status,200);
    const quizVersion=await post(`/definitions/${quiz.body.id}/publish`,{expected_revision:1});
    assert.equal(quizVersion.status,200);
    const parentDocument={kind:'task',title:'Ladder onboarding',blocks:[
      {id:'lesson',type:'linked_lesson',title:'Practical inspection',definition_id:lesson.body.id,version_id:lessonVersion.body.id,required:true},
      {id:'quiz',type:'linked_quiz',title:'Knowledge check',definition_id:quiz.body.id,version_id:quizVersion.body.id,required:true}]};
    const parent=await post('/definitions',parentDocument);assert.equal(parent.status,200);
    const parentVersion=await post(`/definitions/${parent.body.id}/publish`,{expected_revision:1});assert.equal(parentVersion.status,200);
    const assigned=await post('/assignments',{definition_id:parent.body.id,version_id:parentVersion.body.id,
      recipient_ids:[fixture.ids.bob],request_key:'linked-1'});assert.equal(assigned.status,200);
    assert.equal((await post('/assignments',{definition_id:parent.body.id,version_id:parentVersion.body.id,
      recipient_ids:[fixture.ids.bob],request_key:'linked-1'})).body.id,assigned.body.id);
    const mine=(await request('/mine',{who:'bob'})).body.items;
    assert.equal(mine.filter(item=>item.assignment_id===assigned.body.id).length,1);
    const parentRun=await request(`/recipients/${mine.find(item=>item.assignment_id===assigned.body.id).id}`,{who:'bob'});
    assert.equal(parentRun.body.linked_runs.length,2);
    const children=Object.fromEntries(parentRun.body.linked_runs.map(item=>[item.block_id,item]));
    const revised=await request(`/definitions/${lesson.body.id}`,{method:'PUT',body:{kind:'task',title:'Inspect ladder again',
      expected_revision:1}});assert.equal(revised.status,200);
    assert.equal((await post(`/definitions/${lesson.body.id}/publish`,{expected_revision:2})).status,200);
    assert.equal((await request(`/recipients/${children.lesson.recipient_id}`,{who:'bob'})).body.version_number,1);
    assert.equal(mine.some(item=>Object.values(children).some(child=>child.recipient_id===item.id)),false);
    assert.equal((await request(`/recipients/${children.quiz.recipient_id}`,{who:'carol'})).status,404);
    assert.equal((await request(`/recipients/${children.quiz.recipient_id}`,{who:'foreign'})).status,404);
    assert.equal((await post(`/recipients/${parentRun.body.id}/submit`,{expected_revision:1},'bob')).body.error,'requirements_incomplete');
    assert.equal((await request(`/recipients/${parentRun.body.id}/responses`,{who:'bob',method:'PUT',body:{expected_revision:1,
      responses:{quiz:{value:true}}}})).body.error,'instruction_has_no_response');
    assert.equal((await post(`/recipients/${children.lesson.recipient_id}/submit`,{expected_revision:1},'bob')).body.status,'completed');
    const attempt=await post(`/recipients/${children.quiz.recipient_id}/quiz/attempts`,{},'bob');assert.equal(attempt.status,200);
    assert.equal((await request(`/quiz/attempts/${attempt.body.id}/responses`,{who:'bob',method:'PUT',body:{expected_revision:1,
      responses:{safe:true}}})).status,200);
    assert.equal((await post(`/quiz/attempts/${attempt.body.id}/submit`,{expected_revision:2},'bob')).status,200);
    const completed=await post(`/recipients/${parentRun.body.id}/submit`,{expected_revision:1},'bob');
    assert.equal(completed.body.status,'completed');
    const mapping=(await fixture.pool.query(`SELECT count(*)::integer AS count FROM training_linked_runs
      WHERE company_id=$1 AND parent_recipient_id=$2`,[fixture.companies.a,parentRun.body.id])).rows[0];
    assert.equal(mapping.count,2);
    const events=(await fixture.pool.query(`SELECT count(*)::integer AS count FROM training_domain_events
      WHERE company_id=$1 AND event_type='training.assignment_assigned' AND subject_id=ANY($2::text[])`,
    [fixture.companies.a,Object.values(children).map(child=>child.recipient_id)])).rows[0];
    assert.equal(events.count,0);
    await installTrainingSchema(fixture.pool);
    assert.equal((await request(`/recipients/${parentRun.body.id}`,{who:'bob'})).body.linked_runs.length,2);
    const invalid=await post('/definitions',{kind:'task',title:'Bad link',blocks:[{id:'bad',type:'linked_lesson',
      title:'Missing',definition_id:lesson.body.id,version_id:randomUUID()}]});
    assert.equal(invalid.status,200);
    assert.equal((await post(`/definitions/${invalid.body.id}/publish`,{expected_revision:1})).body.error,'linked_version_unavailable');
    const nested=await post('/definitions',{kind:'task',title:'Nested link',blocks:[{id:'nested',type:'linked_lesson',
      title:'Parent',definition_id:parent.body.id,version_id:parentVersion.body.id}]});
    assert.equal((await post(`/definitions/${nested.body.id}/publish`,{expected_revision:1})).body.error,'linked_version_unavailable');
    const personal=await post('/definitions',{kind:'task',title:'Private lesson',scope:'personal'});
    const personalVersion=await post(`/definitions/${personal.body.id}/publish`,{expected_revision:1});
    const options=(await request('/course-lesson-options')).body.items;
    assert.equal(options.find(item=>item.definition_id===parent.body.id).has_linked_blocks,true);
    assert.equal(options.find(item=>item.definition_id===personal.body.id).scope,'personal');
    const sharedWithPrivate=await post('/definitions',{kind:'task',title:'Shared with private content',scope:'company',blocks:[
      {id:'private',type:'linked_lesson',title:'Private',definition_id:personal.body.id,version_id:personalVersion.body.id}]});
    assert.equal((await post(`/definitions/${sharedWithPrivate.body.id}/publish`,{expected_revision:1})).body.error,
      'linked_version_unavailable');
    const earlier=await post('/assignments',{definition_id:lesson.body.id,version_id:lessonVersion.body.id,
      recipient_ids:[fixture.ids.bob],request_key:'linked-prior'});assert.equal(earlier.status,200);
    const gated=await post('/assignments',{definition_id:parent.body.id,version_id:parentVersion.body.id,
      recipient_ids:[fixture.ids.bob],prerequisite_assignment_ids:[earlier.body.id],request_key:'linked-gated'});
    assert.equal(gated.status,200);
    const gatedRun=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===gated.body.id);
    const gatedDetail=(await request(`/recipients/${gatedRun.id}`,{who:'bob'})).body;
    assert.equal(gatedDetail.linked_runs.length,2);
    assert.equal((await post(`/recipients/${gatedDetail.linked_runs.find(item=>item.block_id==='lesson').recipient_id}/submit`,
      {expected_revision:1},'bob')).body.error,'assignment_prerequisite_incomplete');
    const earlierRun=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===earlier.body.id);
    assert.equal((await post(`/recipients/${earlierRun.id}/submit`,{expected_revision:1},'bob')).body.status,'completed');
    assert.equal((await post(`/recipients/${gatedDetail.linked_runs.find(item=>item.block_id==='lesson').recipient_id}/submit`,
      {expected_revision:1},'bob')).body.status,'completed');
    const course=await post('/courses',{title:'Linked lesson course',modules:[{id:'module',title:'First module',
      lessons:[{id:'parent',title:'Onboarding',definition_id:parent.body.id,version_id:parentVersion.body.id}]}]});
    assert.equal(course.status,200);
    assert.equal((await post(`/courses/${course.body.id}/publish`,{expected_revision:1})).status,200);
    const enrolled=await post('/course-enrollments',{course_id:course.body.id,recipient_ids:[fixture.ids.bob],request_key:'linked-course'});
    assert.equal(enrolled.status,200);
    const started=await post(`/course-enrollments/${enrolled.body.enrollment_ids[0]}/lessons/parent/start`,{},'bob');
    assert.equal(started.status,200);
    assert.equal((await post(`/course-enrollments/${enrolled.body.enrollment_ids[0]}/lessons/parent/start`,{},'bob')).body.recipient_id,
      started.body.recipient_id);
    assert.equal((await request(`/recipients/${started.body.recipient_id}`,{who:'bob'})).body.linked_runs.length,2);
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
