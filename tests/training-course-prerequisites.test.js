import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining} from '../training/index.js';

test('course prerequisites require the employee to complete the pinned earlier course version',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express();let server;
  try{
    app.use(express.json({limit:'256kb'}));
    const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');if(!fixture.ids[who])return res.sendStatus(401);
      req.userId=fixture.ids[who];req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
    await installTraining({app,pool:fixture.pool,authRequired:auth});
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,{who='owner',method='GET',body}={})=>{const response=await fetch(base+path,{method,
      headers:{'X-Fixture-User':who,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
      return {status:response.status,body:await response.json()};};
    const task=await request('/definitions',{method:'POST',body:{kind:'task',title:'Safety acknowledgment'}});
    const taskVersion=await request(`/definitions/${task.body.id}/publish`,{method:'POST',body:{expected_revision:1}});
    const lesson=(id,title)=>({id,title,definition_id:task.body.id,version_id:taskVersion.body.id});
    const safety=await request('/courses',{method:'POST',body:{title:'Safety basics',modules:[{id:'safety',title:'Safety',lessons:[lesson('ack','Acknowledge safety')]}]}});
    const safetyVersion=await request(`/courses/${safety.body.id}/publish`,{method:'POST',body:{expected_revision:1}});
    assert.equal(safetyVersion.status,200);
    const equipmentDoc={title:'Equipment training',prerequisite_course_version_ids:[safetyVersion.body.id],
      modules:[{id:'equipment',title:'Equipment',lessons:[lesson('gear','Inspect equipment')]}]};
    const equipment=await request('/courses',{method:'POST',body:equipmentDoc});
    assert.equal(equipment.status,200);
    assert.equal((await request('/course-version-options')).body.items.find(item=>item.course_id===safety.body.id).version_id,safetyVersion.body.id);
    assert.equal((await request('/course-version-options',{who:'foreign'})).body.items.length,0);
    assert.equal((await request(`/courses/${equipment.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).status,200);
    const b=await request('/course-enrollments',{method:'POST',body:{course_id:equipment.body.id,recipient_ids:[fixture.ids.bob],request_key:'equipment-first'}});
    const a=await request('/course-enrollments',{method:'POST',body:{course_id:safety.body.id,recipient_ids:[fixture.ids.bob],request_key:'safety-second'}});
    const equipmentEnrollment=b.body.enrollment_ids[0],safetyEnrollment=a.body.enrollment_ids[0];
    const locked=await request(`/course-enrollments/${equipmentEnrollment}`,{who:'bob'});
    assert.equal(locked.body.prerequisites_blocked,true);
    assert.equal(locked.body.prerequisite_courses[0].title,'Safety basics');
    assert.equal(locked.body.lessons[0].unlocked,false);
    assert.equal((await request(`/course-enrollments/${equipmentEnrollment}/lessons/gear/start`,{who:'bob',method:'POST'})).body.error,'lesson_locked');
    assert.equal((await request(`/course-enrollments/${equipmentEnrollment}/lessons/gear/start`,{who:'foreign',method:'POST'})).status,404);
    const started=await request(`/course-enrollments/${safetyEnrollment}/lessons/ack/start`,{who:'bob',method:'POST'});
    assert.equal(started.status,200);
    assert.equal((await request(`/recipients/${started.body.recipient_id}/submit`,{who:'bob',method:'POST',body:{expected_revision:1}})).body.status,'completed');
    const unlocked=await request(`/course-enrollments/${equipmentEnrollment}`,{who:'bob'});
    assert.equal(unlocked.body.prerequisites_blocked,false);assert.equal(unlocked.body.lessons[0].unlocked,true);
    assert.equal((await request(`/course-enrollments/${equipmentEnrollment}/lessons/gear/start`,{who:'bob',method:'POST'})).status,200);
    const invalid=await request('/courses',{method:'POST',body:{...equipmentDoc,title:'Missing course',
      prerequisite_course_version_ids:[randomUUID()]}});
    assert.equal(invalid.status,200);
    assert.equal((await request(`/courses/${invalid.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).body.error,
      'course_prerequisite_unavailable');
    const selfDoc={...equipmentDoc,title:'Self prerequisite',prerequisite_course_version_ids:[safetyVersion.body.id]};
    const revised=await request(`/courses/${safety.body.id}`,{method:'PUT',body:{...selfDoc,expected_revision:1}});
    assert.equal(revised.status,200);
    assert.equal((await request(`/courses/${safety.body.id}/publish`,{method:'POST',body:{expected_revision:2}})).body.error,
      'course_prerequisite_unavailable');
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
