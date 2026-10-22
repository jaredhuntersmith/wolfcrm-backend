import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining} from '../training/index.js';
import {normalizeDefinition} from '../training/contract.js';
import {gradeQuiz,learnerQuiz,normalizeQuizAnswers} from '../training/quiz-contract.js';

const objective={kind:'quiz',title:'Vehicle safety',quiz:{passing_percent:80,max_attempts:2,time_limit_seconds:30,shuffle_questions:true,shuffle_answers:true,show_results:'immediate',questions:[
  {id:'q1',type:'multiple_choice',prompt:'What comes first?',options:[{id:'a',label:'Inspect tires'},{id:'b',label:'Drive away'}],answer:'a',points:5,explanation:'Inspect before driving.'},
  {id:'q2',type:'true_false',prompt:'Check mirrors?',answer:true,points:5}
]}};

test('quiz contract keeps answer keys out of learner questions and grades objective responses',()=>{
  const document=normalizeDefinition(objective),again=normalizeDefinition(document);
  assert.deepEqual(again,document);
  const learner=learnerQuiz(document.quiz);
  assert.equal(JSON.stringify(learner).includes('Inspect before driving.'),false);
  assert.equal(JSON.stringify(learner).includes('"answer"'),false);
  assert.equal(gradeQuiz(document.quiz,normalizeQuizAnswers(document.quiz,{q1:'a',q2:true})).auto_points,10);
  assert.equal(gradeQuiz(document.quiz,normalizeQuizAnswers(document.quiz,{q1:'b',q2:false})).auto_points,0);
  assert.throws(()=>normalizeQuizAnswers(document.quiz,{q1:'forged'}),{code:'invalid_quiz_response'});
  assert.throws(()=>normalizeDefinition({...objective,quiz:{...objective.quiz,questions:[{id:'q1',type:'multiple_choice',prompt:'Bad',options:[{id:'a',label:'A'},{id:'b',label:'B'}],answer:'c'}]}}),{code:'invalid_correct_answer'});
});

test('HTTP quiz attempts are version-pinned, timed and server graded without leaking keys',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express();let server;
  try{
    app.use(express.json({limit:'256kb'}));
    const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');if(!fixture.ids[who])return res.status(401).json({error:'unauthorized'});
      req.userId=fixture.ids[who];req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
    await installTraining({app,pool:fixture.pool,authRequired:auth});
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,{who='owner',method='GET',body}={})=>{const response=await fetch(base+path,{method,headers:{'X-Fixture-User':who,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});return {status:response.status,body:await response.json()};};
    const draft=await request('/definitions',{method:'POST',body:objective});assert.equal(draft.status,200);
    const published=await request(`/definitions/${draft.body.id}/publish`,{method:'POST',body:{expected_revision:1}});assert.equal(published.status,200);
    const assigned=await request('/assignments',{method:'POST',body:{definition_id:draft.body.id,recipient_ids:[fixture.ids.bob],request_key:'safety-quiz'}});assert.equal(assigned.status,200);
    const recipient=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===assigned.body.id);assert.ok(recipient);
    const detail=await request(`/recipients/${recipient.id}`,{who:'bob'});assert.equal(detail.status,200);
    assert.deepEqual(detail.body.document.quiz.questions,[]);
    assert.equal(JSON.stringify(detail.body).includes('Inspect before driving.'),false);
    assert.equal((await request(`/recipients/${recipient.id}/submit`,{who:'bob',method:'POST',body:{expected_revision:1}})).body.error,'use_quiz_attempt_endpoint');
    const started=await request(`/recipients/${recipient.id}/quiz/attempts`,{who:'bob',method:'POST'});assert.equal(started.status,200);
    assert.equal(started.body.attempt_number,1);
    assert.ok(started.body.deadline_at);
    assert.equal(JSON.stringify(started.body).includes('"answer"'),false);
    assert.equal((await request(`/recipients/${recipient.id}/quiz/attempts`,{who:'bob',method:'POST'})).body.id,started.body.id);
    const attemptID=started.body.id;
    assert.equal((await request(`/quiz/attempts/${attemptID}`,{who:'carol'})).status,403);
    assert.equal((await request(`/quiz/attempts/${attemptID}`,{who:'foreign'})).status,404);
    assert.equal((await request(`/quiz/attempts/${attemptID}/responses`,{who:'bob',method:'PUT',body:{expected_revision:1,responses:{q1:'forged'}}})).status,400);
    const saved=await request(`/quiz/attempts/${attemptID}/responses`,{who:'bob',method:'PUT',body:{expected_revision:1,responses:{q1:'a',q2:true}}});assert.equal(saved.status,200);
    assert.equal((await request(`/quiz/attempts/${attemptID}/responses`,{who:'bob',method:'PUT',body:{expected_revision:1,responses:{q1:'b'}}})).status,409);
    await fixture.pool.query(`UPDATE training_quiz_attempts SET deadline_at=now()-interval '1 second' WHERE id=$1`,[attemptID]);
    assert.equal((await request(`/quiz/attempts/${attemptID}/responses`,{who:'bob',method:'PUT',body:{expected_revision:2,responses:{q1:'b'}}})).body.error,'exam_time_expired');
    const graded=await request(`/quiz/attempts/${attemptID}/submit`,{who:'bob',method:'POST',body:{expected_revision:2}});
    assert.equal(graded.status,200);assert.equal(graded.body.passed,true);assert.equal(graded.body.score_points,10);
    assert.equal((await request(`/quiz/attempts/${attemptID}/submit`,{who:'bob',method:'POST',body:{expected_revision:2}})).body.id,attemptID);
    assert.equal((await request(`/recipients/${recipient.id}`,{who:'bob'})).body.status,'completed');
    assert.equal((await request(`/recipients/${recipient.id}/quiz/attempts`,{who:'bob',method:'POST'})).status,409);
    const manual={kind:'quiz',title:'Safety explanation',requires_review:true,quiz:{passing_percent:50,max_attempts:1,questions:[
      {id:'explain',type:'essay',prompt:'Explain the safety check.',points:10}
    ]}};
    const manualDraft=await request('/definitions',{method:'POST',body:manual});assert.equal(manualDraft.status,200);
    assert.equal((await request(`/definitions/${manualDraft.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).status,200);
    const manualAssignment=await request('/assignments',{method:'POST',body:{definition_id:manualDraft.body.id,recipient_ids:[fixture.ids.bob],request_key:'manual-quiz'}});assert.equal(manualAssignment.status,200);
    const manualRecipient=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===manualAssignment.body.id);assert.ok(manualRecipient);
    const manualAttempt=await request(`/recipients/${manualRecipient.id}/quiz/attempts`,{who:'bob',method:'POST'});assert.equal(manualAttempt.status,200);
    assert.equal((await request(`/quiz/attempts/${manualAttempt.body.id}/responses`,{who:'bob',method:'PUT',body:{expected_revision:1,responses:{explain:'Inspect tires, lights, and mirrors.'}}})).status,200);
    const pending=await request(`/quiz/attempts/${manualAttempt.body.id}/submit`,{who:'bob',method:'POST',body:{expected_revision:2}});
    assert.equal(pending.body.status,'awaiting_manual');
    assert.equal((await request(`/recipients/${manualRecipient.id}/quiz/attempts`,{who:'bob',method:'POST'})).body.error,'review_pending');
    await fixture.pool.query('UPDATE employee_permissions SET permission_overrides=$2 WHERE user_id=$1',[fixture.ids.alice,JSON.stringify({'training.review':true})]);
    assert.equal((await request(`/quiz/attempts/${manualAttempt.body.id}/grade`,{who:'alice'})).status,404);
    assert.equal((await request(`/recipients/${manualRecipient.id}/review`,{who:'owner',method:'POST',body:{expected_revision:2,decision:'approve',feedback:'Premature'}})).body.error,'quiz_not_graded_or_passed');
    assert.equal((await request(`/supervisors/${fixture.ids.alice}/employees/${fixture.ids.bob}`,{method:'PUT',body:{supervised:true}})).status,200);
    const graderView=await request(`/quiz/attempts/${manualAttempt.body.id}/grade`,{who:'alice'});assert.equal(graderView.status,200);
    assert.equal(graderView.body.author_questions[0].id,'explain');
    assert.equal((await request(`/recipients/${manualRecipient.id}/quiz/review`,{who:'alice'})).body.id,manualAttempt.body.id);
    const manualGrade=await request(`/quiz/attempts/${manualAttempt.body.id}/grade`,{who:'alice',method:'POST',body:{expected_revision:3,grades:{explain:{points:8,feedback:'Good detail'}},feedback:'Passed'}});
    assert.equal(manualGrade.status,200);assert.equal(manualGrade.body.passed,true);
    assert.equal((await request(`/recipients/${manualRecipient.id}`,{who:'bob'})).body.status,'awaiting_review');
    const withheld=await request(`/quiz/attempts/${manualAttempt.body.id}`,{who:'bob'});
    assert.equal(withheld.body.passed,undefined);
    assert.equal(withheld.body.score_points,undefined);
    assert.equal((await request(`/recipients/${manualRecipient.id}/review`,{who:'alice',method:'POST',body:{expected_revision:3,decision:'approve',feedback:'Approved'}})).body.status,'completed');
    const released=await request(`/quiz/attempts/${manualAttempt.body.id}`,{who:'bob'});
    assert.equal(released.body.passed,true);
    assert.equal(released.body.score_points,8);
    const privateDraft=await request('/definitions',{method:'POST',body:{...objective,title:'Private score',quiz:{
      ...objective.quiz,show_results:'never',show_answers_after_grade:true}}});
    assert.equal(privateDraft.status,200);
    assert.equal((await request(`/definitions/${privateDraft.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).status,200);
    const privateAssignment=await request('/assignments',{method:'POST',body:{definition_id:privateDraft.body.id,
      recipient_ids:[fixture.ids.bob],request_key:'private-score'}});
    const privateRecipient=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===privateAssignment.body.id);
    const firstPrivate=await request(`/recipients/${privateRecipient.id}/quiz/attempts`,{who:'bob',method:'POST'});
    await request(`/quiz/attempts/${firstPrivate.body.id}/responses`,{who:'bob',method:'PUT',body:{expected_revision:1,responses:{q1:'b',q2:false}}});
    const hidden=await request(`/quiz/attempts/${firstPrivate.body.id}/submit`,{who:'bob',method:'POST',body:{expected_revision:2}});
    assert.equal(hidden.status,200);assert.equal(hidden.body.passed,undefined);
    assert.equal(hidden.body.score_points,undefined);assert.equal(hidden.body.answer_review,undefined);
    assert.equal((await request(`/recipients/${privateRecipient.id}`,{who:'bob'})).body.status,'in_progress');
    const retake=await request(`/recipients/${privateRecipient.id}/quiz/attempts`,{who:'bob',method:'POST'});
    assert.equal(retake.status,200);assert.equal(retake.body.attempt_number,2);
    assert.equal(JSON.stringify(retake.body).includes('Inspect before driving.'),false);
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
