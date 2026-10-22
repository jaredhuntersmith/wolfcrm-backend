import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining,queueExpiringCertificates} from '../training/index.js';
import {normalizeCourse} from '../training/course-contract.js';
import {certificatePDF} from '../training/certificates.js';

test('course contract rejects missing and circular prerequisites',()=>{
  const id='00000000-0000-4000-8000-000000000001';
  const course={title:'Safety',modules:[{id:'m1',title:'Basics',lessons:[
    {id:'a',title:'A',definition_id:id,version_id:id,prerequisites:['b']},
    {id:'b',title:'B',definition_id:id,version_id:id,prerequisites:['a']}
  ]}]};
  assert.throws(()=>normalizeCourse(course),{code:'circular_prerequisite'});
  assert.throws(()=>normalizeCourse({title:'Bad',modules:[null]}),{code:'invalid_course_module'});
  assert.throws(()=>normalizeCourse({...course,modules:[{...course.modules[0],lessons:[{...course.modules[0].lessons[0],prerequisites:['missing']}]}]}),{code:'unknown_prerequisite'});
});

test('certificate PDF renders Unicode identities without WinAnsi failure',async()=>{
  const pdf=await certificatePDF({employee_name:'Jos\u00e9 \ud83d\ude00',company_name:'M\u00fcnchen Co',course_title:'S\u00e9curit\u00e9',
    issued_at:new Date('2026-10-22T12:00:00Z'),expires_at:null,score_percent:93,verification_code:'WOLF-TEST',status:'valid'});
  assert.equal(pdf.subarray(0,5).toString(),'%PDF-');
});

test('course enrollment pins versions and server gates lesson starts',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express();let server;
  try{
    app.use(express.json({limit:'256kb'}));
    const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');if(!fixture.ids[who])return res.status(401).json({error:'unauthorized'});
      req.userId=fixture.ids[who];req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
    await installTraining({app,pool:fixture.pool,authRequired:auth});
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,{who='owner',method='GET',body}={})=>{const response=await fetch(base+path,{method,headers:{'X-Fixture-User':who,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});return {status:response.status,body:await response.json()};};
    const first=await request('/definitions',{method:'POST',body:{kind:'task',title:'First'}});
    const second=await request('/definitions',{method:'POST',body:{kind:'task',title:'Second'}});
    const firstVersion=await request(`/definitions/${first.body.id}/publish`,{method:'POST',body:{expected_revision:1}});
    const secondVersion=await request(`/definitions/${second.body.id}/publish`,{method:'POST',body:{expected_revision:1}});
    assert.equal(firstVersion.status,200);assert.equal(secondVersion.status,200);
    assert.equal((await request(`/definitions/${first.body.id}/versions`)).body.items[0].id,firstVersion.body.id);
    assert.equal((await request(`/definitions/${first.body.id}/versions`,{who:'foreign'})).status,404);
    assert.equal((await request('/course-lesson-options')).body.items.find(item=>item.definition_id===first.body.id).version_id,firstVersion.body.id);
    const document={title:'Orientation',progression:'sequential',certificate_enabled:true,recertification_days:365,modules:[{id:'m1',title:'Day one',lessons:[
      {id:'l1',title:'First step',definition_id:first.body.id,version_id:firstVersion.body.id},
      {id:'l2',title:'Second step',definition_id:second.body.id,version_id:secondVersion.body.id,prerequisites:['l1']}
    ]}]};
    const draft=await request('/courses',{method:'POST',body:document});assert.equal(draft.status,200);
    assert.equal((await request(`/courses/${draft.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).status,200);
    const assigned=await request('/course-enrollments',{method:'POST',body:{course_id:draft.body.id,recipient_ids:[fixture.ids.bob],request_key:'course-1'}});
    assert.equal(assigned.status,200);const enrollmentID=assigned.body.enrollment_ids[0];
    const duplicate=await request('/course-enrollments',{method:'POST',body:{course_id:draft.body.id,recipient_ids:[fixture.ids.bob],request_key:'course-1'}});
    assert.equal(duplicate.status,200);assert.deepEqual(duplicate.body.enrollment_ids,[enrollmentID]);
    assert.equal((await request(`/course-enrollments/${enrollmentID}`,{who:'foreign'})).status,404);
    assert.equal((await request(`/course-enrollments/${enrollmentID}`,{who:'carol'})).status,403);
    const before=await request(`/course-enrollments/${enrollmentID}`,{who:'bob'});
    assert.equal(before.body.lessons[0].unlocked,true);assert.equal(before.body.lessons[1].unlocked,false);
    assert.equal((await request(`/course-enrollments/${enrollmentID}/lessons/l2/start`,{who:'bob',method:'POST'})).body.error,'lesson_locked');
    const started=await request(`/course-enrollments/${enrollmentID}/lessons/l1/start`,{who:'bob',method:'POST'});
    assert.equal(started.status,200);assert.equal((await request(`/course-enrollments/${enrollmentID}/lessons/l1/start`,{who:'bob',method:'POST'})).body.recipient_id,started.body.recipient_id);
    assert.equal((await request(`/recipients/${started.body.recipient_id}/submit`,{who:'bob',method:'POST',body:{expected_revision:1}})).body.status,'completed');
    const after=await request(`/course-enrollments/${enrollmentID}`,{who:'bob'});
    assert.equal(after.body.completed_required,1);assert.equal(after.body.lessons[1].unlocked,true);
    const secondRun=await request(`/course-enrollments/${enrollmentID}/lessons/l2/start`,{who:'bob',method:'POST'});assert.equal(secondRun.status,200);
    assert.equal((await request(`/recipients/${secondRun.body.recipient_id}/submit`,{who:'bob',method:'POST',body:{expected_revision:1}})).body.status,'completed');
    const finished=await request(`/course-enrollments/${enrollmentID}`,{who:'bob'});assert.equal(finished.body.completed_required,2);assert.ok(finished.body.completed_at);
    const certificates=await request('/certificates/mine',{who:'bob'});assert.equal(certificates.body.items.length,1);
    const certificate=certificates.body.items[0];assert.equal(certificate.course_title,'Orientation');assert.equal(certificate.status,'valid');assert.ok(certificate.expires_at);
    assert.equal((await request(`/certificates/${certificate.id}`,{who:'carol'})).status,403);
    assert.equal((await request(`/certificates/${certificate.id}`,{who:'foreign'})).status,404);
    assert.equal((await request(`/certificates/verify/${certificate.verification_code}`,{who:'bob'})).body.status,'valid');
    assert.equal((await request(`/certificates/verify/${certificate.verification_code}`,{who:'carol'})).status,403);
    const pdf=await fetch(base+`/certificates/${certificate.id}/pdf`,{headers:{'X-Fixture-User':'bob'}});
    assert.equal(pdf.status,200);assert.equal(pdf.headers.get('content-type'),'application/pdf');
    assert.equal(Buffer.from(await pdf.arrayBuffer()).subarray(0,5).toString(),'%PDF-');
    assert.deepEqual(await queueExpiringCertificates(fixture.pool),{scanned:0,queued:0});
    await fixture.pool.query(`UPDATE training_certificates SET expires_at=now()+interval '2 days' WHERE id=$1`,[certificate.id]);
    assert.deepEqual(await queueExpiringCertificates(fixture.pool),{scanned:1,queued:1});
    assert.deepEqual(await queueExpiringCertificates(fixture.pool),{scanned:0,queued:0});
    const expiryEvent=(await fixture.pool.query(`SELECT * FROM training_domain_events
      WHERE company_id=$1 AND event_type='training.certificate_expiring'`,[fixture.companies.a])).rows;
    assert.equal(expiryEvent.length,1);assert.equal(expiryEvent[0].payload.employee_id,fixture.ids.bob);
    assert.equal((await request(`/certificates/${certificate.id}/revoke`,{who:'bob',method:'POST',body:{reason:'Correction'}})).status,403);
    assert.equal((await request(`/certificates/${certificate.id}/revoke`,{method:'POST',body:{reason:'Issued in error'}})).body.status,'revoked');
    assert.equal((await request(`/certificates/verify/${certificate.verification_code}`,{who:'bob'})).body.status,'revoked');
    assert.deepEqual(await queueExpiringCertificates(fixture.pool),{scanned:0,queued:0});
    assert.equal((await fixture.pool.query('SELECT count(*)::integer AS count FROM training_certificates WHERE enrollment_id=$1',[enrollmentID])).rows[0].count,1);
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
