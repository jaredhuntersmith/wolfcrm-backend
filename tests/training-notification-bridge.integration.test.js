import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining,queueExpiringCertificates,queueAssignmentReminders} from '../training/index.js';
import {drainTrainingEvents} from '../training/events.js';
import {installNotificationsSchema,createNotifications} from '../company-comms/notifications.js';
import {dispatchTrainingDomainEvent} from '../company-comms/training-events.js';

test('training events enter one inbox and stale certificates cannot push',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express(),sent=[],emitted=[];let server;
  try{
    app.use(express.json());
    const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');req.userId=fixture.ids[who];req.companyId=fixture.companies.a;next();};
    await installTraining({app,pool:fixture.pool,authRequired:auth});
    await installNotificationsSchema(fixture.pool);
    const notifications=createNotifications({pool:fixture.pool,sendPush:async(users,kind,options)=>{
      sent.push({users,kind,options});return {sent:1};
    }});
    const dispatch=(event,{db})=>dispatchTrainingDomainEvent(db,event,{notifications,
      emitAutomationEvent:async(value,{db:transaction})=>{assert.equal(transaction,db);emitted.push(value);return randomUUID();}});
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,{who='owner',method='GET',body}={})=>{
      const response=await fetch(base+path,{method,headers:{'X-Fixture-User':who,'Content-Type':'application/json'},
        body:body===undefined?undefined:JSON.stringify(body)});
      return {status:response.status,body:await response.json()};
    };
    const draft=await request('/definitions',{method:'POST',body:{kind:'task',title:'Safety step'}});
    assert.equal(draft.status,200);
    const version=await request(`/definitions/${draft.body.id}/publish`,{method:'POST',body:{expected_revision:1}});
    assert.equal(version.status,200);
    const assignment=await request('/assignments',{method:'POST',body:{definition_id:draft.body.id,
      recipient_ids:[fixture.ids.bob],request_key:'bridge-assignment'}});
    assert.equal(assignment.status,200);
    const course=await request('/courses',{method:'POST',body:{title:'Safety course',certificate_enabled:true,
      modules:[{id:'module',title:'Module',lessons:[{id:'lesson',title:'Step',definition_id:draft.body.id,
        version_id:version.body.id}]}]}});
    assert.equal(course.status,200);
    const courseVersion=await request(`/courses/${course.body.id}/publish`,{method:'POST',body:{expected_revision:1}});
    assert.equal(courseVersion.status,200);
    const enrollment=await request('/course-enrollments',{method:'POST',body:{course_id:course.body.id,
      recipient_ids:[fixture.ids.bob],request_key:'bridge-course'}});
    assert.equal(enrollment.status,200);
    await drainTrainingEvents(fixture.pool,dispatch);
    const inbox=await fixture.pool.query(`SELECT id,kind,user_id,company_id,event_key,requirements
      FROM notifications WHERE kind LIKE 'training.%' ORDER BY kind`);
    assert.deepEqual(inbox.rows.map(row=>row.kind),['training.assignment_assigned','training.course_assigned']);
    for(const row of inbox.rows){assert.equal(row.user_id,fixture.ids.bob);assert.equal(row.company_id,fixture.companies.a);
      assert.deepEqual(row.requirements,['training.view_self']);}
    assert.equal(emitted.filter(row=>row.eventType.endsWith('_assigned')).length,2);
    await notifications.deliver();
    assert.deepEqual(sent.map(row=>row.kind).sort(),['training.assignment_assigned','training.course_assigned']);
    assert.ok(sent.every(row=>row.options.inboxDelivery&&row.options.title==='WolfCRM notification'));
    assert.equal((await drainTrainingEvents(fixture.pool,dispatch)).dispatched,0);
    const assignedEvent=(await fixture.pool.query(`SELECT * FROM training_domain_events
      WHERE event_type='training.assignment_assigned'`)).rows[0];
    const retryKey=`rollback:${randomUUID()}`;
    const db=await fixture.pool.connect();
    try{
      await db.query('BEGIN');
      await assert.rejects(()=>dispatchTrainingDomainEvent(db,{companyId:assignedEvent.company_id,
        eventType:assignedEvent.event_type,subjectId:assignedEvent.subject_id,dedupeKey:retryKey,
        payload:assignedEvent.payload},{notifications,emitAutomationEvent:async()=>{throw new Error('automation unavailable');}}),
      /automation unavailable/);
      await db.query('ROLLBACK');
    }finally{db.release();}
    assert.equal((await fixture.pool.query('SELECT count(*)::integer AS count FROM notifications WHERE event_key=$1',
      [`training.assignment_assigned:${retryKey}`])).rows[0].count,0);

    const certificateID=randomUUID(),enrollmentID=enrollment.body.enrollment_ids[0];
    await fixture.pool.query(`INSERT INTO training_certificates
      (id,company_id,enrollment_id,employee_id,employee_name_snapshot,company_name_snapshot,
        course_title_snapshot,course_version_id,expires_at,verification_code)
      VALUES($1,$2,$3,$4,'Bob','A','Safety course',$5,now()+interval '2 days',$6)`,
      [certificateID,fixture.companies.a,enrollmentID,fixture.ids.bob,courseVersion.body.id,`WOLF-${randomUUID()}`]);
    assert.deepEqual(await queueExpiringCertificates(fixture.pool),{scanned:1,queued:1});
    await drainTrainingEvents(fixture.pool,dispatch);
    const expiry=(await fixture.pool.query(`SELECT id FROM notifications WHERE kind='training.certificate_expiring'`)).rows[0];
    assert.ok(expiry?.id);
    await fixture.pool.query('UPDATE training_certificates SET revoked_at=now() WHERE id=$1',[certificateID]);
    const count=sent.length;
    await notifications.deliver();
    assert.equal(sent.length,count);
    assert.equal((await fixture.pool.query('SELECT last_error FROM notification_delivery_outbox WHERE notification_id=$1',
      [expiry.id])).rows[0].last_error,'stale_training_certificate');
    const event=(await fixture.pool.query(`SELECT * FROM training_domain_events WHERE event_type='training.certificate_expiring'`)).rows[0];
    const before=emitted.length;
    const stale=await dispatchTrainingDomainEvent(fixture.pool,{companyId:event.company_id,eventType:event.event_type,
      subjectId:event.subject_id,dedupeKey:event.dedupe_key,payload:event.payload},{notifications,
      emitAutomationEvent:async()=>{throw new Error('stale certificate must not reach automations');}});
    assert.match(stale,/^stale:/);assert.equal(emitted.length,before);
    await fixture.pool.query('UPDATE users SET deleted_at=now() WHERE id=$1',[fixture.ids.bob]);
    const disabled=await dispatchTrainingDomainEvent(fixture.pool,{companyId:assignedEvent.company_id,
      eventType:assignedEvent.event_type,subjectId:assignedEvent.subject_id,dedupeKey:`disabled:${randomUUID()}`,
      payload:assignedEvent.payload},{notifications,emitAutomationEvent:async()=>{throw new Error('disabled user emitted');}});
    assert.match(disabled,/^stale:/);
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});

test('training outcomes and review requests use scoped fake inbox delivery',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express(),sent=[];let server;
  try{
    app.use(express.json());
    const auth=(req,res,next)=>{req.userId=fixture.ids[req.get('X-Fixture-User')];req.companyId=fixture.companies.a;next();};
    await installTraining({app,pool:fixture.pool,authRequired:auth});
    await installNotificationsSchema(fixture.pool);
    const notifications=createNotifications({pool:fixture.pool,sendPush:async(users,kind)=>{
      sent.push({users,kind});return {sent:1};
    }});
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,{method='GET',body}={})=>{
      const response=await fetch(base+path,{method,headers:{'X-Fixture-User':'owner','Content-Type':'application/json'},
        body:body===undefined?undefined:JSON.stringify(body)});
      assert.equal(response.status,200,path);return response.json();
    };
    const draft=await request('/definitions',{method:'POST',body:{kind:'task',title:'Review fixture'}});
    const version=await request(`/definitions/${draft.id}/publish`,{method:'POST',body:{expected_revision:1}});
    const assignment=await request('/assignments',{method:'POST',body:{definition_id:draft.id,
      recipient_ids:[fixture.ids.bob],request_key:'review-notification-fixture'}});
    const recipientID=(await fixture.pool.query(`SELECT id FROM training_recipients
      WHERE company_id=$1 AND assignment_id=$2 AND employee_id=$3`,
    [fixture.companies.a,assignment.id,fixture.ids.bob])).rows[0].id;
    const course=await request('/courses',{method:'POST',body:{title:'Review course',
      modules:[{id:'module',title:'Module',lessons:[{id:'lesson',title:'Step',definition_id:draft.id,
        version_id:version.id}]}]}});
    const courseVersion=await request(`/courses/${course.id}/publish`,{method:'POST',body:{expected_revision:1}});
    const enrollment=await request(`/course-enrollments`,{method:'POST',body:{course_id:course.id,
      recipient_ids:[fixture.ids.bob],request_key:'course-notification-fixture'}});
    const enrollmentID=enrollment.enrollment_ids[0];
    await fixture.pool.query(`UPDATE employee_permissions SET permission_overrides =
      permission_overrides || '{"training.view_self":true,"training.review":true,"notifications.view":true}'::jsonb
      WHERE user_id=$1 AND company_id=$2`,[fixture.ids.alice,fixture.companies.a]);
    await fixture.pool.query(`INSERT INTO training_supervisor_grants(company_id,supervisor_id,employee_id,granted_by)
      VALUES($1,$2,$3,$4)`,[fixture.companies.a,fixture.ids.alice,fixture.ids.bob,fixture.ids.owner]);
    const emitAutomationEvent=async()=>randomUUID();
    const dispatch=async(eventType,subjectId,payload,key=randomUUID())=>{
      const db=await fixture.pool.connect();
      try{
        await db.query('BEGIN');
        const result=await dispatchTrainingDomainEvent(db,{companyId:fixture.companies.a,
          eventType,subjectId,dedupeKey:key,payload},{notifications,emitAutomationEvent});
        await db.query('COMMIT');return result;
      }catch(error){await db.query('ROLLBACK');throw error;}finally{db.release();}
    };
    const assignmentPayload=(status,revision)=>({recipient_id:recipientID,employee_id:fixture.ids.bob,
      definition_id:draft.id,status,revision});
    await fixture.pool.query(`UPDATE training_recipients SET status='awaiting_review',revision=2 WHERE id=$1`,[recipientID]);
    const reviewKey=randomUUID();
    await dispatch('training.submission_pending_review',recipientID,assignmentPayload('awaiting_review',2),reviewKey);
    await dispatch('training.submission_pending_review',recipientID,assignmentPayload('awaiting_review',2),reviewKey);
    const requests=(await fixture.pool.query(`SELECT user_id,requirements FROM notifications
      WHERE kind='training.submission_pending_review' ORDER BY user_id`)).rows;
    assert.deepEqual(requests.map(row=>row.user_id).sort(),[fixture.ids.owner,fixture.ids.alice].sort());
    assert.ok(requests.every(row=>JSON.stringify(row.requirements)==='["training.review"]'));
    await fixture.pool.query(`UPDATE training_recipients SET status='completed',revision=3 WHERE id=$1`,[recipientID]);
    assert.match(await dispatch('training.submission_pending_review',recipientID,
      assignmentPayload('awaiting_review',2)),/^stale:/);
    await dispatch('training.submission_approved',recipientID,assignmentPayload('completed',3));
    await fixture.pool.query(`UPDATE training_recipients SET status='corrections_requested',revision=4 WHERE id=$1`,[recipientID]);
    await dispatch('training.submission_corrections_requested',recipientID,
      assignmentPayload('corrections_requested',4));
    await fixture.pool.query(`UPDATE training_course_enrollments SET completed_at=now() WHERE id=$1`,[enrollmentID]);
    await dispatch('training.course_completed',enrollmentID,{enrollment_id:enrollmentID,
      employee_id:fixture.ids.bob,course_id:course.id,version_id:courseVersion.id});
    for(const [number,status,passed,kind] of [
      [1,'graded',false,'training.quiz_failed'],[2,'graded',true,'training.quiz_passed'],
      [3,'awaiting_manual',null,'training.quiz_pending_grade']]){
      const attemptID=randomUUID();
      await fixture.pool.query(`INSERT INTO training_quiz_attempts
        (id,company_id,recipient_id,version_id,attempt_number,status,question_order,choice_orders,passed)
        VALUES($1,$2,$3,$4,$5,$6,'[]'::jsonb,'{}'::jsonb,$7)`,
      [attemptID,fixture.companies.a,recipientID,version.id,number,status,passed]);
      await dispatch(kind,attemptID,{attempt_id:attemptID,recipient_id:recipientID,
        employee_id:fixture.ids.bob,definition_id:draft.id,status,passed});
    }
    const kinds=(await fixture.pool.query(`SELECT kind,user_id FROM notifications
      WHERE kind LIKE 'training.%' AND kind NOT IN ('training.assignment_assigned','training.course_assigned')
      ORDER BY kind,user_id`)).rows;
    for(const kind of ['training.submission_approved','training.submission_corrections_requested',
      'training.course_completed','training.quiz_failed','training.quiz_passed']){
      assert.deepEqual(kinds.filter(row=>row.kind===kind).map(row=>row.user_id),[fixture.ids.bob],kind);
    }
    for(const kind of ['training.submission_pending_review','training.quiz_pending_grade']){
      assert.deepEqual(kinds.filter(row=>row.kind===kind).map(row=>row.user_id).sort(),
        [fixture.ids.owner,fixture.ids.alice].sort(),kind);
    }
    assert.ok(kinds.every(row=>row.user_id!==fixture.ids.foreign));
    await fixture.pool.query(`INSERT INTO notification_preferences(user_id,company_id,muted)
      VALUES($1,$2,true)`,[fixture.ids.bob,fixture.companies.a]);
    await notifications.deliver();
    assert.ok(sent.some(row=>row.kind==='training.submission_pending_review'));
    assert.ok(sent.some(row=>row.kind==='training.quiz_pending_grade'));
    assert.ok(sent.every(row=>!row.users.includes(fixture.ids.bob)));
    const muted=(await fixture.pool.query(`SELECT DISTINCT o.last_error FROM notification_delivery_outbox o
      JOIN notifications n ON n.id=o.notification_id WHERE n.user_id=$1 AND n.kind='training.quiz_passed'`,
      [fixture.ids.bob])).rows;
    assert.deepEqual(muted.map(row=>row.last_error),['delivery_muted']);
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});

test('assignment reminders recheck due time and completion before fake push',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express(),sent=[];let server;
  try{
    app.use(express.json());
    const auth=(req,res,next)=>{req.userId=fixture.ids[req.get('X-Fixture-User')];
      req.companyId=fixture.companies.a;next();};
    await installTraining({app,pool:fixture.pool,authRequired:auth});
    await installNotificationsSchema(fixture.pool);
    const notifications=createNotifications({pool:fixture.pool,sendPush:async(users,kind)=>{
      sent.push({users,kind});return {sent:1};
    }});
    const dispatch=(event,{db})=>dispatchTrainingDomainEvent(db,event,{notifications,
      emitAutomationEvent:async()=>randomUUID()});
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,body)=>{const response=await fetch(base+path,{method:'POST',
      headers:{'X-Fixture-User':'owner','Content-Type':'application/json'},body:JSON.stringify(body)});
      const result=await response.json();assert.equal(response.status,200,JSON.stringify(result));return result;};
    const origin=new Date(),dueAt=hours=>new Date(origin.getTime()+hours*3600000).toISOString();
    const definition=await request('/definitions',{kind:'task',title:'Reminder fixture'});
    await request(`/definitions/${definition.id}/publish`,{expected_revision:1});
    const assignment=await request('/assignments',{definition_id:definition.id,
      recipient_ids:[fixture.ids.bob],request_key:'bridge-reminder',
      available_at:dueAt(-72),due_at:dueAt(12),grace_seconds:3600});
    const recipientID=(await fixture.pool.query(`SELECT id FROM training_recipients
      WHERE company_id=$1 AND assignment_id=$2`,[fixture.companies.a,assignment.id])).rows[0].id;
    const reminders=async()=> (await fixture.pool.query(`SELECT n.id,n.kind,o.last_error FROM notifications n
      JOIN notification_delivery_outbox o ON o.notification_id=n.id
      WHERE n.kind IN ('training.assignment_due_soon','training.assignment_overdue')
      ORDER BY n.created_at,n.id`)).rows;
    const scan=async()=>{await queueAssignmentReminders(fixture.pool,{now:origin});
      await drainTrainingEvents(fixture.pool,dispatch);};
    await scan();
    await fixture.pool.query('UPDATE training_assignments SET due_at=$2 WHERE id=$1',
      [assignment.id,dueAt(16)]);
    await notifications.deliver();
    assert.equal((await reminders())[0].last_error,'stale_training_reminder');
    assert.equal(sent.filter(row=>row.kind==='training.assignment_due_soon').length,0);
    await scan();await notifications.deliver();
    assert.equal(sent.filter(row=>row.kind==='training.assignment_due_soon').length,1);
    await fixture.pool.query('UPDATE training_assignments SET due_at=$2 WHERE id=$1',
      [assignment.id,dueAt(-2)]);
    await scan();
    await fixture.pool.query(`INSERT INTO notification_preferences(user_id,company_id,muted)
      VALUES($1,$2,true) ON CONFLICT(user_id) DO UPDATE SET muted=true`,
    [fixture.ids.bob,fixture.companies.a]);
    await notifications.deliver();
    assert.equal(sent.filter(row=>row.kind==='training.assignment_overdue').length,0);
    assert.ok((await reminders()).some(row=>row.kind==='training.assignment_overdue'&&row.last_error==='delivery_muted'));
    await fixture.pool.query('UPDATE training_assignments SET due_at=$2 WHERE id=$1',
      [assignment.id,dueAt(-3)]);
    await scan();
    await fixture.pool.query("UPDATE training_recipients SET status='completed' WHERE id=$1",[recipientID]);
    await notifications.deliver();
    assert.ok((await reminders()).some(row=>row.kind==='training.assignment_overdue'&&row.last_error==='stale_training_reminder'));
    assert.equal(sent.filter(row=>row.kind==='training.assignment_overdue').length,0);
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
