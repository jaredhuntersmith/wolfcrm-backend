import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {createStorageService} from '../media-storage/service.js';
import {installTraining} from '../training/index.js';

test('20-question image assessment demo pins randomized choices and grades its passing threshold',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express();let server;
  try{
    app.use(express.json({limit:'256kb'}));
    const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');
      if(!fixture.ids[who])return res.status(401).json({error:'unauthorized'});
      req.userId=fixture.ids[who];req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
    const storage=createStorageService({pool:fixture.pool,bucket:{}});
    await installTraining({app,pool:fixture.pool,authRequired:auth,storage});
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,{who='owner',method='GET',body}={})=>{
      const response=await fetch(base+path,{method,headers:{'X-Fixture-User':who,'Content-Type':'application/json'},
        body:body===undefined?undefined:JSON.stringify(body)});
      return {status:response.status,body:await response.json()};
    };
    const imageID=randomUUID();
    const questions=Array.from({length:20},(_,i)=>({id:`q${i+1}`,
      type:i===0?'image_identification':'multiple_choice',prompt:`Identify safe action ${i+1}`,
      ...(i===0?{image_file_id:imageID}:{}),points:5,
      options:[{id:'safe',label:'Safe action'},{id:'unsafe',label:'Unsafe action'}],answer:'safe'}));
    const draft=await request('/definitions',{method:'POST',body:{kind:'quiz',title:'20-question safety assessment',
      quiz:{passing_percent:85,max_attempts:2,time_limit_seconds:1800,shuffle_questions:true,
        shuffle_answers:true,show_results:'immediate',questions}}});
    assert.equal(draft.status,200);
    assert.equal((await request('/assets/reserve',{method:'POST',body:{target_kind:'definition',target_id:draft.body.id,
      file:{id:imageID,original_filename:'safe-tool.jpg',mime_type:'image/jpeg',byte_size:100}}})).status,200);
    await fixture.pool.query(`UPDATE stored_files SET cloud_status='active' WHERE id=$1`,[imageID]);
    assert.equal((await request(`/definitions/${draft.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).status,200);
    const assigned=await request('/assignments',{method:'POST',body:{definition_id:draft.body.id,
      recipient_ids:[fixture.ids.bob],request_key:'demo-20-image-assessment'}});
    const recipient=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===assigned.body.id);
    const started=await request(`/recipients/${recipient.id}/quiz/attempts`,{who:'bob',method:'POST'});
    assert.equal(started.status,200);assert.equal(started.body.quiz.questions.length,20);
    assert.equal(JSON.stringify(started.body).includes('"answer"'),false);
    assert.ok(started.body.quiz.questions.some(question=>question.image_file_id===imageID));
    const resumed=await request(`/recipients/${recipient.id}/quiz/attempts`,{who:'bob',method:'POST'});
    assert.equal(resumed.body.id,started.body.id);
    assert.deepEqual(resumed.body.quiz.questions,started.body.quiz.questions);
    const snapshot=(await fixture.pool.query(`SELECT question_order,choice_orders FROM training_quiz_attempts WHERE id=$1`,
      [started.body.id])).rows[0];
    assert.equal(snapshot.question_order.length,20);
    assert.equal(Object.keys(snapshot.choice_orders).length,20);
    const answers=Object.fromEntries(questions.map((question,i)=>[question.id,i<18?'safe':'unsafe']));
    assert.equal((await request(`/quiz/attempts/${started.body.id}/responses`,{who:'bob',method:'PUT',
      body:{expected_revision:1,responses:answers}})).status,200);
    const graded=await request(`/quiz/attempts/${started.body.id}/submit`,{who:'bob',method:'POST',
      body:{expected_revision:2}});
    assert.equal(graded.status,200);assert.equal(graded.body.passed,true);
    assert.equal(graded.body.score_points,90);assert.equal(graded.body.max_points,100);
    assert.equal((await request(`/recipients/${recipient.id}`,{who:'bob'})).body.status,'completed');
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
