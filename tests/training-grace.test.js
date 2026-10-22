import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining} from '../training/index.js';

test('assignment and course grace preserve nominal due time and use effective due for reporting',{timeout:120000},async()=>{
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
    const availableAt=new Date(Date.now()-7200000).toISOString();
    const dueAt=new Date(Date.now()-3600000).toISOString();
    const draft=await post('/definitions',{kind:'task',title:'Grace period check'});
    const version=await post(`/definitions/${draft.body.id}/publish`,{expected_revision:1});
    const payload={definition_id:draft.body.id,recipient_ids:[fixture.ids.bob],request_key:'grace-assignment',
      available_at:availableAt,due_at:dueAt,grace_seconds:7200};
    assert.equal((await post('/assignments',{...payload,due_at:undefined})).body.error,'grace_requires_due_date');
    assert.equal((await post('/assignments',{...payload,grace_seconds:604801})).body.error,'invalid_grace_seconds');
    const assigned=await post('/assignments',payload);assert.equal(assigned.status,200);
    assert.equal((await post('/assignments',payload)).body.id,assigned.body.id);
    assert.equal((await post('/assignments',{...payload,grace_seconds:3600})).body.error,'request_key_conflict');
    const recipient=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===assigned.body.id);
    assert.equal(recipient.grace_seconds,7200);
    assert.equal(new Date(recipient.effective_due_at)-new Date(recipient.due_at),7200000);
    assert.equal((await request('/analytics',{who:'bob'})).body.assignments.overdue,0);
    const event=(await fixture.pool.query(`SELECT payload FROM training_domain_events WHERE event_type='training.assignment_assigned'
      AND subject_id=$1`,[recipient.id])).rows[0].payload;
    assert.equal(event.grace_seconds,7200);assert.equal(event.effective_due_at,recipient.effective_due_at);
    assert.equal((await post(`/recipients/${recipient.id}/submit`,{expected_revision:1},'bob')).body.status,'completed');
    const after=(await request('/analytics',{who:'bob'})).body.assignments;
    assert.equal(after.on_time,1);assert.equal(after.on_time_percent,100);
    const course=await post('/courses',{title:'Grace course',modules:[{id:'m',title:'Module',lessons:[{
      id:'l',title:'Lesson',definition_id:draft.body.id,version_id:version.body.id}]}]});
    assert.equal((await post(`/courses/${course.body.id}/publish`,{expected_revision:1})).status,200);
    const enrolled=await post('/course-enrollments',{course_id:course.body.id,recipient_ids:[fixture.ids.bob],
      request_key:'grace-course',available_at:availableAt,due_at:dueAt,grace_seconds:7200});
    assert.equal(enrolled.status,200);
    const enrollment=(await request(`/course-enrollments/${enrolled.body.enrollment_ids[0]}`,{who:'bob'})).body;
    assert.equal(enrollment.grace_seconds,7200);
    assert.equal(new Date(enrollment.effective_due_at)-new Date(enrollment.due_at),7200000);
    const lesson=await post(`/course-enrollments/${enrollment.id}/lessons/l/start`,{},'bob');
    assert.equal(lesson.status,200);
    const inherited=(await request(`/recipients/${lesson.body.recipient_id}`,{who:'bob'})).body;
    assert.equal(inherited.grace_seconds,7200);
    assert.equal((await request('/analytics',{who:'bob'})).body.assignments.overdue,0);
    await fixture.pool.query(`UPDATE training_assignments SET available_at=now()-interval '4 hours',
      due_at=now()-interval '3 hours' WHERE id=$1`,[inherited.assignment_id]);
    assert.equal((await request('/analytics',{who:'bob'})).body.assignments.overdue,1);
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
