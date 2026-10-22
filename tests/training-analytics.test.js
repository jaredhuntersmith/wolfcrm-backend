import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining} from '../training/index.js';

test('analytics distinguishes self from explicitly supervised results',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express();let server;
  try{
    app.use(express.json());
    const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');req.userId=fixture.ids[who];req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
    await installTraining({app,pool:fixture.pool,authRequired:auth});
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,{who='owner',method='GET',body}={})=>{const response=await fetch(base+path,{method,headers:{'X-Fixture-User':who,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});return {status:response.status,body:await response.json()};};
    const draft=await request('/definitions',{method:'POST',body:{kind:'task',title:'Audit task'}});
    const version=await request(`/definitions/${draft.body.id}/publish`,{method:'POST',body:{expected_revision:1}});
    await request('/assignments',{method:'POST',body:{definition_id:draft.body.id,recipient_ids:[fixture.ids.bob],request_key:'analytics-task'}});
    const course=await request('/courses',{method:'POST',body:{title:'Audit course',modules:[{id:'module',title:'Work',lessons:[
      {id:'lesson',title:'Audit task',definition_id:draft.body.id,version_id:version.body.id}]}]}});
    assert.equal(course.status,200);
    assert.equal((await request(`/courses/${course.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).status,200);
    assert.equal((await request('/course-enrollments',{method:'POST',body:{course_id:course.body.id,
      recipient_ids:[fixture.ids.bob],request_key:'analytics-course'}})).status,200);
    const own=await request('/analytics',{who:'bob'});assert.equal(own.status,200);assert.equal(own.body.assignments.assigned,1);
    assert.equal((await request('/analytics/filters',{who:'bob'})).status,200);
    assert.equal(own.body.time_spent_seconds,null);
    assert.equal((await request('/analytics?scope=managed',{who:'alice'})).status,403);
    await fixture.pool.query('UPDATE employee_permissions SET permission_overrides=$2 WHERE user_id=$1',[fixture.ids.alice,JSON.stringify({'training.analytics':true})]);
    assert.equal((await request('/analytics?scope=managed',{who:'alice'})).body.assignments.assigned,0);
    assert.equal((await request(`/analytics?scope=managed&employee_id=${fixture.ids.bob}`,{who:'alice'})).status,404);
    const bobTeam=(await request('/audience-groups',{method:'POST',body:{kind:'team',name:'Field team',member_ids:[fixture.ids.bob]}})).body;
    const carolTeam=(await request('/audience-groups',{method:'POST',body:{kind:'team',name:'Other team',member_ids:[fixture.ids.carol]}})).body;
    assert.equal((await request(`/analytics?scope=managed&group_id=${bobTeam.id}`,{who:'alice'})).status,404);
    await request(`/supervisors/${fixture.ids.alice}/employees/${fixture.ids.bob}`,{method:'PUT',body:{supervised:true}});
    const managed=await request('/analytics?scope=managed',{who:'alice'});assert.equal(managed.body.assignments.assigned,1);
    const filters=await request('/analytics/filters',{who:'alice'});
    assert.equal(filters.status,200);
    assert.deepEqual(filters.body.groups.map(item=>item.id),[bobTeam.id]);
    assert.deepEqual(filters.body.courses.map(item=>item.id),[course.body.id]);
    assert.equal(filters.body.employees.some(item=>item.id===fixture.ids.carol),false);
    assert.equal((await request(`/analytics?scope=managed&group_id=${bobTeam.id}`,{who:'alice'})).body.assignments.assigned,1);
    assert.equal((await request(`/analytics?scope=managed&course_id=${course.body.id}`,{who:'alice'})).body.courses.enrolled,1);
    assert.equal((await request(`/analytics?scope=managed&group_id=${carolTeam.id}`,{who:'alice'})).status,404);
    assert.equal((await request(`/analytics?scope=self&group_id=${bobTeam.id}`,{who:'bob'})).status,403);
    assert.equal((await request(`/analytics?scope=managed&group_id=${carolTeam.id}`)).body.assignments.assigned,0);
    assert.equal((await request(`/analytics?scope=self&employee_id=${fixture.ids.bob}`,{who:'alice'})).status,403);
    assert.equal((await request(`/analytics?scope=managed&employee_id=${fixture.ids.bob}`,{who:'foreign'})).status,404);
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
