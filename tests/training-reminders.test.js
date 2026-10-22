import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining,queueAssignmentReminders} from '../training/index.js';

test('assignment reminders queue once per eligible recipient and due stage without delivery',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express();let server;
  try{
    app.use(express.json());
    const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');req.userId=fixture.ids[who];
      req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
    await installTraining({app,pool:fixture.pool,authRequired:auth});
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,body)=>{const response=await fetch(base+path,{method:'POST',
      headers:{'X-Fixture-User':'owner','Content-Type':'application/json'},body:JSON.stringify(body)});
      const result=await response.json();assert.equal(response.status,200,`${path}: ${JSON.stringify(result)}`);
      return result;};
    const origin=new Date(),available=new Date(origin.getTime()-3600000).toISOString();
    const due=new Date(origin.getTime()+12*3600000).toISOString();
    const definition=await request('/definitions',{kind:'task',title:'Clean company truck'});
    await request(`/definitions/${definition.id}/publish`,{expected_revision:1});
    const assignment=await request('/assignments',{definition_id:definition.id,
      recipient_ids:[fixture.ids.bob,fixture.ids.alice,fixture.ids.carol],
      request_key:'reminder-test',available_at:available,due_at:due,grace_seconds:3600});
    const recipientRows=(await fixture.pool.query(`SELECT id,employee_id FROM training_recipients
      WHERE company_id=$1 AND assignment_id=$2`,[fixture.companies.a,assignment.id])).rows;
    const recipient=Object.fromEntries(recipientRows.map(row=>[row.employee_id,row.id]));
    await fixture.pool.query(`UPDATE training_recipients SET status='awaiting_review'
      WHERE id=$1`,[recipient[fixture.ids.alice]]);
    await fixture.pool.query(`UPDATE users SET deleted_at=now() WHERE id=$1`,[fixture.ids.carol]);
    await assert.rejects(()=>queueAssignmentReminders(fixture.pool,{hoursAhead:0}),
      error=>error.status===400&&error.code==='invalid_assignment_reminder_scan');
    const first=await Promise.all([queueAssignmentReminders(fixture.pool,{now:origin,limit:1}),
      queueAssignmentReminders(fixture.pool,{now:origin,limit:1})]);
    assert.equal(first.reduce((sum,item)=>sum+item.queued,0),1);
    assert.deepEqual(await queueAssignmentReminders(fixture.pool,{now:origin}),{scanned:0,queued:0});
    const events=async()=> (await fixture.pool.query(`SELECT event_type,subject_id,dedupe_key,payload
      FROM training_domain_events WHERE event_type IN
      ('training.assignment_due_soon','training.assignment_overdue') ORDER BY event_type`)).rows;
    assert.equal((await events())[0].subject_id,recipient[fixture.ids.bob]);
    assert.equal((await events())[0].payload.due_at,due);
    assert.equal((await events())[0].payload.effective_due_at,new Date(origin.getTime()+13*3600000).toISOString());
    assert.equal((await events()).length,1);
    assert.deepEqual(await queueAssignmentReminders(fixture.pool,{now:new Date(origin.getTime()+12.5*3600000)}),
      {scanned:0,queued:0});
    assert.deepEqual(await queueAssignmentReminders(fixture.pool,{now:new Date(origin.getTime()+13*3600000)}),
      {scanned:1,queued:1});
    assert.deepEqual((await events()).map(row=>row.event_type),
      ['training.assignment_due_soon','training.assignment_overdue']);
    assert.deepEqual(await queueAssignmentReminders(fixture.pool,{now:new Date(origin.getTime()+14*3600000)}),
      {scanned:0,queued:0});
    await fixture.pool.query(`UPDATE training_assignments SET due_at=$2 WHERE id=$1`,
      [assignment.id,new Date(origin.getTime()+16*3600000).toISOString()]);
    assert.deepEqual(await queueAssignmentReminders(fixture.pool,{now:origin}),{scanned:1,queued:1});
    assert.equal((await events()).filter(row=>row.event_type==='training.assignment_due_soon').length,2);
    await fixture.pool.query(`UPDATE training_recipients SET status='completed' WHERE id=$1`,
      [recipient[fixture.ids.bob]]);
    await fixture.pool.query(`UPDATE training_assignments SET due_at=$2 WHERE id=$1`,
      [assignment.id,new Date(origin.getTime()+20*3600000).toISOString()]);
    assert.deepEqual(await queueAssignmentReminders(fixture.pool,{now:origin}),{scanned:0,queued:0});
    assert.equal((await events()).length,3);
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
