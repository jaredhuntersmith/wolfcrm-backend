import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {enrollNewTrainingEmployee,installTraining,reconcileTrainingOnboarding} from '../training/index.js';
import {installTrainingSchema} from '../training/schema.js';

test('new-hire policy pins a version and enrolls each eligible employee once',{timeout:120000},async()=>{
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
    const definition=(await request('/definitions',{method:'POST',body:{kind:'task',title:'Welcome and safety',blocks:[
      {id:'ack',type:'checklist',items:[{id:'read',text:'Read the safety guide'}]}
    ]}})).body;
    const policyBody={definition_id:definition.id,due_after_days:7,request_key:'welcome-new-hires'};
    assert.equal((await request('/onboarding-policies',{method:'POST',body:policyBody})).body.error,'definition_unpublished');
    const published=(await request(`/definitions/${definition.id}/publish`,{method:'POST',body:{expected_revision:1}})).body;
    assert.equal((await request('/onboarding-policies',{who:'bob',method:'POST',body:policyBody})).status,403);
    const policy=await request('/onboarding-policies',{method:'POST',body:policyBody});
    assert.equal(policy.status,200);assert.equal(policy.body.version_id,published.id);
    assert.equal((await request('/onboarding-policies',{method:'POST',body:policyBody})).body.id,policy.body.id);
    assert.equal((await request('/onboarding-policies',{method:'POST',body:{...policyBody,due_after_days:8}})).body.error,'request_key_conflict');
    assert.equal((await enrollNewTrainingEmployee(fixture.pool,{companyId:fixture.companies.a,userId:fixture.ids.bob})).enrolled,0);
    const joinedAt=new Date(new Date(policy.body.created_at).getTime()+1000).toISOString();
    assert.equal((await enrollNewTrainingEmployee(fixture.pool,{companyId:fixture.companies.a,userId:fixture.ids.bob,eligibleAt:joinedAt})).enrolled,1);
    assert.equal((await enrollNewTrainingEmployee(fixture.pool,{companyId:fixture.companies.a,userId:fixture.ids.bob,eligibleAt:joinedAt})).enrolled,0);
    const joinedAssignment=(await fixture.pool.query(`SELECT a.available_at,a.due_at FROM training_onboarding_enrollments e
      JOIN training_assignments a ON a.id=e.assignment_id WHERE e.policy_id=$1 AND e.employee_id=$2`,
      [policy.body.id,fixture.ids.bob])).rows[0];
    assert.equal(new Date(joinedAssignment.available_at).toISOString(),joinedAt);
    assert.equal(new Date(joinedAssignment.due_at)-new Date(joinedAssignment.available_at),7*86400000);
    await fixture.pool.query(`INSERT INTO training_employee_eligibility(company_id,employee_id,eligible_at)
      VALUES($1,$2,$3)`,[fixture.companies.a,fixture.ids.carol,joinedAt]);
    assert.deepEqual(await reconcileTrainingOnboarding(fixture.pool),{employees:1,enrolled:1});
    const newHire=randomUUID();
    await fixture.pool.query(`INSERT INTO users(id,company_id,email,display_name,role,created_at)
      VALUES($1,$2,$3,$4,'employee',now()+interval '1 second')`,[newHire,fixture.companies.a,'newhire@example.invalid','New Hire']);
    assert.equal((await enrollNewTrainingEmployee(fixture.pool,{companyId:fixture.companies.a,userId:newHire})).enrolled,1);
    assert.equal((await enrollNewTrainingEmployee(fixture.pool,{companyId:fixture.companies.a,userId:newHire})).enrolled,0);
    const rows=(await fixture.pool.query(`SELECT a.version_id,a.available_at,a.due_at,r.employee_id
      FROM training_onboarding_enrollments e JOIN training_assignments a ON a.id=e.assignment_id
      JOIN training_recipients r ON r.assignment_id=a.id WHERE e.company_id=$1 AND e.employee_id=$2`,
      [fixture.companies.a,newHire])).rows;
    assert.equal(rows.length,1);assert.equal(rows[0].version_id,published.id);
    assert.equal(new Date(rows[0].due_at)-new Date(rows[0].available_at),7*86400000);
    assert.equal(rows[0].employee_id,newHire);
    assert.deepEqual(await reconcileTrainingOnboarding(fixture.pool),{employees:0,enrolled:0});
    const disabled=await request(`/onboarding-policies/${policy.body.id}/disable`,{method:'POST'});
    assert.equal(disabled.status,200);assert.equal(disabled.body.version_id,published.id);
    assert.equal(disabled.body.due_after_days,7);assert.ok(disabled.body.created_at);
    const secondHire=randomUUID();
    await fixture.pool.query(`INSERT INTO users(id,company_id,email,display_name,role,created_at)
      VALUES($1,$2,$3,$4,'employee',now()+interval '2 seconds')`,[secondHire,fixture.companies.a,'second@example.invalid','Second Hire']);
    assert.equal((await enrollNewTrainingEmployee(fixture.pool,{companyId:fixture.companies.a,userId:secondHire})).enrolled,0);
    assert.equal((await request('/onboarding-policies',{who:'foreign'})).body.items.length,0);
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});

test('new-hire course enrollment pins its version and unlocks only after a passing quiz',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express();let server,newHireID;
  try{
    app.use(express.json({limit:'256kb'}));
    const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');req.userId=who==='newhire'?newHireID:fixture.ids[who];
      req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
    await installTraining({app,pool:fixture.pool,authRequired:auth});
    await installTrainingSchema(fixture.pool);
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,{who='owner',method='GET',body}={})=>{const response=await fetch(base+path,{method,
      headers:{'X-Fixture-User':who,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
      return {status:response.status,body:await response.json()};};
    const quiz=await request('/definitions',{method:'POST',body:{kind:'quiz',title:'Safety first',quiz:{passing_percent:100,max_attempts:2,
      show_results:'immediate',questions:[{id:'q',type:'true_false',prompt:'Wear eye protection?',answer:true,points:1}]}}});
    const task=await request('/definitions',{method:'POST',body:{kind:'task',title:'Equipment orientation'}});
    const quizVersion=await request(`/definitions/${quiz.body.id}/publish`,{method:'POST',body:{expected_revision:1}});
    const taskVersion=await request(`/definitions/${task.body.id}/publish`,{method:'POST',body:{expected_revision:1}});
    const course=await request('/courses',{method:'POST',body:{title:'New-hire training',progression:'sequential',modules:[
      {id:'intro',title:'Safety',lessons:[{id:'safety',title:'Pass safety check',definition_id:quiz.body.id,version_id:quizVersion.body.id}]},
      {id:'equipment',title:'Equipment',lessons:[{id:'gear',title:'Equipment orientation',definition_id:task.body.id,
        version_id:taskVersion.body.id,prerequisites:['safety']}]}]}});
    assert.equal(course.status,200);
    const courseVersion=await request(`/courses/${course.body.id}/publish`,{method:'POST',body:{expected_revision:1}});
    assert.equal(courseVersion.status,200);
    const policyBody={course_id:course.body.id,due_after_days:14,request_key:'course-new-hires'};
    assert.equal((await request('/onboarding-policies',{method:'POST',body:{...policyBody,definition_id:task.body.id}})).body.error,'invalid_onboarding_target');
    const policy=await request('/onboarding-policies',{method:'POST',body:policyBody});
    assert.equal(policy.status,200);assert.equal(policy.body.course_version_id,courseVersion.body.id);
    assert.equal((await request('/onboarding-policies',{method:'POST',body:policyBody})).body.id,policy.body.id);
    assert.equal((await request('/onboarding-policies')).body.items.find(item=>item.id===policy.body.id).title,'New-hire training');
    newHireID=randomUUID();
    await fixture.pool.query(`INSERT INTO users(id,company_id,email,display_name,role,created_at)
      VALUES($1,$2,$3,$4,'employee',now())`,[newHireID,fixture.companies.a,'coursehire@example.invalid','Course Hire']);
    assert.equal((await enrollNewTrainingEmployee(fixture.pool,{companyId:fixture.companies.a,userId:newHireID})).enrolled,1);
    assert.equal((await enrollNewTrainingEmployee(fixture.pool,{companyId:fixture.companies.a,userId:newHireID})).enrolled,0);
    const enrollmentRow=(await fixture.pool.query(`SELECT course_enrollment_id,assignment_id FROM training_onboarding_enrollments
      WHERE company_id=$1 AND policy_id=$2 AND employee_id=$3`,[fixture.companies.a,policy.body.id,newHireID])).rows[0];
    assert.ok(enrollmentRow.course_enrollment_id);assert.equal(enrollmentRow.assignment_id,null);
    const enrollmentID=enrollmentRow.course_enrollment_id;
    const before=await request(`/course-enrollments/${enrollmentID}`,{who:'newhire'});
    assert.equal(before.body.version_id,courseVersion.body.id);
    assert.equal(before.body.lessons[0].unlocked,true);assert.equal(before.body.lessons[1].unlocked,false);
    assert.equal((await request(`/course-enrollments/${enrollmentID}/lessons/gear/start`,{who:'newhire',method:'POST'})).body.error,'lesson_locked');
    const started=await request(`/course-enrollments/${enrollmentID}/lessons/safety/start`,{who:'newhire',method:'POST'});
    assert.equal(started.status,200);
    const first=await request(`/recipients/${started.body.recipient_id}/quiz/attempts`,{who:'newhire',method:'POST'});
    await request(`/quiz/attempts/${first.body.id}/responses`,{who:'newhire',method:'PUT',body:{expected_revision:1,responses:{q:false}}});
    assert.equal((await request(`/quiz/attempts/${first.body.id}/submit`,{who:'newhire',method:'POST',body:{expected_revision:2}})).body.passed,false);
    assert.equal((await request(`/course-enrollments/${enrollmentID}`,{who:'newhire'})).body.lessons[1].unlocked,false);
    const second=await request(`/recipients/${started.body.recipient_id}/quiz/attempts`,{who:'newhire',method:'POST'});
    await request(`/quiz/attempts/${second.body.id}/responses`,{who:'newhire',method:'PUT',body:{expected_revision:1,responses:{q:true}}});
    assert.equal((await request(`/quiz/attempts/${second.body.id}/submit`,{who:'newhire',method:'POST',body:{expected_revision:2}})).body.passed,true);
    assert.equal((await request(`/course-enrollments/${enrollmentID}`,{who:'newhire'})).body.lessons[1].unlocked,true);
    assert.equal((await request(`/course-enrollments/${enrollmentID}/lessons/gear/start`,{who:'foreign',method:'POST'})).status,404);
    assert.equal((await request(`/course-enrollments/${enrollmentID}/lessons/gear/start`,{who:'newhire',method:'POST'})).status,200);
    assert.equal((await fixture.pool.query(`SELECT count(*)::integer AS n FROM training_course_enrollments
      WHERE company_id=$1 AND employee_id=$2`,[fixture.companies.a,newHireID])).rows[0].n,1);
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
