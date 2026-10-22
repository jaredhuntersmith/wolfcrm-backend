import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining} from '../training/index.js';
import {readTrainingWidget,TRAINING_WIDGET_KINDS} from '../training/dashboard.js';

test('training widgets scope rows and denominators to the current learner or managed roster',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express();let server;
  try{
    app.use(express.json());
    const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');req.userId=fixture.ids[who];
      req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
    await installTraining({app,pool:fixture.pool,authRequired:auth});
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const post=async(path,body)=>{const response=await fetch(base+path,{method:'POST',
      headers:{'X-Fixture-User':'owner','Content-Type':'application/json'},body:JSON.stringify(body)});
      const result=await response.json();assert.equal(response.status,200,`${path}: ${JSON.stringify(result)}`);return result;};
    const now=new Date('2026-10-22T15:00:00Z'),available='2026-10-20T12:00:00Z';
    const task=await post('/definitions',{kind:'task',title:'Safety inspection'});
    const version=await post(`/definitions/${task.id}/publish`,{expected_revision:1});
    const today=await post('/assignments',{definition_id:task.id,
      recipient_ids:[fixture.ids.bob,fixture.ids.carol],request_key:'widget-today',
      available_at:available,due_at:'2026-10-22T18:00:00Z'});
    const late=await post('/assignments',{definition_id:task.id,
      recipient_ids:[fixture.ids.bob],request_key:'widget-late',available_at:available,
      due_at:'2026-10-21T14:00:00Z',grace_seconds:3600});
    const recipientRows=(await fixture.pool.query(`SELECT id,employee_id,assignment_id FROM training_recipients
      WHERE company_id=$1`,[fixture.companies.a])).rows;
    const bobToday=recipientRows.find(row=>row.employee_id===fixture.ids.bob&&row.assignment_id===today.id);
    const bobLate=recipientRows.find(row=>row.employee_id===fixture.ids.bob&&row.assignment_id===late.id);
    const carolToday=recipientRows.find(row=>row.employee_id===fixture.ids.carol&&row.assignment_id===today.id);
    await fixture.pool.query(`UPDATE training_recipients SET status='completed',completed_at=$2 WHERE id=$1`,
      [bobToday.id,now]);
    await fixture.pool.query(`UPDATE training_recipients SET status='awaiting_review',submitted_at=$2 WHERE id=$1`,
      [carolToday.id,now]);
    const bob=await fixture.actor('bob'),alice=await fixture.actor('alice'),owner=await fixture.actor('owner');
    const read=(actor,kind,extra={})=>readTrainingWidget({pool:fixture.pool,actor,kind,now,...extra});
    assert.deepEqual(TRAINING_WIDGET_KINDS.length,9);
    assert.equal((await read(bob,'training_my_assignments')).count,1);
    assert.equal((await read(bob,'training_due_today')).count,0);
    assert.equal((await read(bob,'training_overdue')).rows[0].id,bobLate.id);
    assert.equal((await read(bob,'training_progress')).value,'1 / 2');
    assert.equal((await read(owner,'training_pending_reviews')).rows[0].id,carolToday.id);
    assert.equal((await read(owner,'training_team_performance')).value,'1 / 3');
    assert.equal((await read(alice,'training_pending_reviews')).state,'unavailable');
    assert.equal((await read(alice,'training_team_performance')).state,'unavailable');
    await fixture.pool.query(`UPDATE employee_permissions SET permission_overrides=$2 WHERE user_id=$1`,
      [fixture.ids.alice,JSON.stringify({'training.review':true,'training.analytics':true})]);
    const manager=await fixture.actor('alice');
    assert.equal((await read(manager,'training_pending_reviews')).count,0);
    assert.equal((await read(manager,'training_team_performance')).value,'0 / 0');
    await fixture.pool.query(`INSERT INTO training_supervisor_grants(company_id,supervisor_id,employee_id,granted_by)
      VALUES($1,$2,$3,$4)`,[fixture.companies.a,fixture.ids.alice,fixture.ids.carol,fixture.ids.owner]);
    assert.equal((await read(manager,'training_pending_reviews')).rows[0].id,carolToday.id);
    assert.equal((await read(manager,'training_team_performance')).value,'0 / 1');
    await fixture.pool.query(`DELETE FROM training_supervisor_grants WHERE supervisor_id=$1`,[fixture.ids.alice]);
    assert.equal((await read(manager,'training_pending_reviews')).count,0);
    assert.equal((await read(manager,'training_team_performance')).value,'0 / 0');
    const foreign=await fixture.actor('foreign');
    assert.equal((await read(foreign,'training_my_assignments')).count,0);
    assert.equal((await read(foreign,'training_team_performance')).value,'0 / 0');
    assert.equal((await read(bob,'training_my_assignments',{recordID:carolToday.id})).rows.length,0);
    assert.equal((await read(bob,'training_my_assignments',{recordID:bobLate.id})).rows.length,1);
    assert.equal((await read(bob,'training_course_completion')).value,'0 / 0');
    assert.equal((await read(bob,'training_recent_grades')).count,0);
    assert.equal((await read(bob,'training_certifications')).value,'0 valid');
    assert.equal(await read(bob,'unknown_widget'),null);
    await fixture.pool.query(`UPDATE training_recipients SET status='in_progress',completed_at=NULL WHERE id=$1`,
      [bobToday.id]);
    assert.equal((await read(bob,'training_due_today')).rows[0].id,bobToday.id);
    await fixture.pool.query(`UPDATE training_recipients SET status='completed',completed_at=$2 WHERE id=$1`,
      [bobToday.id,now]);
    await fixture.pool.query(`UPDATE training_assignments SET due_at=$2 WHERE id=$1`,
      [late.id,'2026-10-22T14:30:00Z']);
    assert.equal((await read(bob,'training_overdue')).count,0);
    await fixture.pool.query(`UPDATE training_assignments SET due_at=$2 WHERE id=$1`,
      [late.id,'2026-10-21T14:00:00Z']);

    const course=await post('/courses',{title:'Orientation',progression:'sequential',certificate_enabled:true,
      modules:[{id:'m1',title:'Basics',lessons:[{id:'l1',title:'Inspect',definition_id:task.id,version_id:version.id}]}]});
    await post(`/courses/${course.id}/publish`,{expected_revision:1});
    const enrollment=await post('/course-enrollments',{course_id:course.id,
      recipient_ids:[fixture.ids.bob],request_key:'widget-course'});
    const enrollmentID=enrollment.enrollment_ids[0];
    assert.equal((await read(bob,'training_course_completion')).value,'0 / 1');
    await fixture.pool.query(`UPDATE training_course_enrollments SET completed_at=$2 WHERE id=$1`,
      [enrollmentID,now]);
    const certID=randomUUID();
    const pinned=(await fixture.pool.query(`SELECT version_id FROM training_course_enrollments WHERE id=$1`,
      [enrollmentID])).rows[0].version_id;
    await fixture.pool.query(`INSERT INTO training_certificates(id,company_id,enrollment_id,employee_id,
      employee_name_snapshot,company_name_snapshot,course_title_snapshot,course_version_id,
      issued_at,expires_at,verification_code) VALUES($1,$2,$3,$4,'Bob','A','Orientation',$5,$6,$7,$8)`,
    [certID,fixture.companies.a,enrollmentID,fixture.ids.bob,pinned,now,
      '2026-10-23T15:00:00Z','WOLF-'+randomUUID().replaceAll('-','').slice(0,20).toUpperCase()]);
    assert.equal((await read(bob,'training_course_completion')).value,'1 / 1');
    assert.equal((await read(bob,'training_certifications')).value,'1 valid');
    assert.equal((await read(foreign,'training_certifications')).count,0);
    assert.equal((await read(bob,'training_certifications',{now:new Date('2026-10-24T15:00:00Z')})).value,'0 valid');

    for(const policy of ['immediate','after_review','never']){
      const draft=await post('/definitions',{kind:'quiz',title:`Quiz ${policy}`,quiz:{
        show_results:policy,passing_percent:50,max_attempts:1,questions:[
          {id:'q',type:'true_false',prompt:'Check the equipment?',answer:true,points:10}]}});
      const pinnedQuiz=await post(`/definitions/${draft.id}/publish`,{expected_revision:1});
      const assigned=await post('/assignments',{definition_id:draft.id,
        recipient_ids:[fixture.ids.bob],request_key:`widget-grade-${policy}`});
      const recipient=(await fixture.pool.query(`SELECT id FROM training_recipients
        WHERE company_id=$1 AND assignment_id=$2 AND employee_id=$3`,
      [fixture.companies.a,assigned.id,fixture.ids.bob])).rows[0].id;
      await fixture.pool.query(`UPDATE training_recipients SET status='awaiting_review' WHERE id=$1`,[recipient]);
      const attemptID=randomUUID();
      await fixture.pool.query(`INSERT INTO training_quiz_attempts(id,company_id,recipient_id,version_id,
        attempt_number,status,question_order,choice_orders,total_points,max_points,passed,graded_at)
        VALUES($1,$2,$3,$4,1,'graded','["q"]'::jsonb,'{}'::jsonb,8,10,true,$5)`,
      [attemptID,fixture.companies.a,recipient,pinnedQuiz.id,now]);
      const visible=(await read(bob,'training_recent_grades')).rows.map(row=>row.title);
      assert.equal(visible.includes(`Quiz ${policy}`),policy==='immediate');
      await fixture.pool.query(`UPDATE training_recipients SET status='completed' WHERE id=$1`,[recipient]);
      const rows=(await read(bob,'training_recent_grades')).rows;
      const released=rows.map(row=>row.title);
      assert.equal(released.includes(`Quiz ${policy}`),policy!=='never');
      if(policy!=='never'){
        const row=rows.find(item=>item.title===`Quiz ${policy}`);
        assert.equal(row.id,attemptID);
        assert.equal(row.reference,recipient);
      }
    }
    assert.equal((await read(bob,'training_recent_grades')).value,'2');
    assert.equal((await read(foreign,'training_recent_grades')).count,0);
    await fixture.pool.query(`UPDATE employee_permissions SET permission_overrides=$2 WHERE user_id=$1`,
      [fixture.ids.bob,JSON.stringify({'training.view_self':false})]);
    assert.equal((await read(await fixture.actor('bob'),'training_recent_grades')).state,'unavailable');
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
