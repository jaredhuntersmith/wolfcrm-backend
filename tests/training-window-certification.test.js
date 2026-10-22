import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {createStorageService} from '../media-storage/service.js';
import {installTraining} from '../training/index.js';

// A local product fixture. Provider verification, playback signing, and storage
// activation are faked; this does not establish live Mux or device behavior.
test('Window Cleaning Certification demo pins six lessons and issues a certificate only after every gate',
  {timeout:120000},async()=>{
    const fixture=await createCommsFixture(),app=express();let server;
    try{
      app.use(express.json({limit:'256kb'}));
      const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');
        if(!fixture.ids[who])return res.status(401).json({error:'unauthorized'});
        req.userId=fixture.ids[who];req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
      const muxSigner={ready:true,signPlayback:()=>({url:'https://stream.mux.com/abc123DEF456.m3u8?token=fixture',
        expires_at:new Date(Date.now()+3600000).toISOString()})};
      const muxCatalog={ready:true,verifyPlayback:async()=>({provider:'mux',playback_id:'abc123DEF456',
        asset_id:'window-training-fixture',duration_seconds:8,policy:'signed'})};
      const storage=createStorageService({pool:fixture.pool,bucket:{}});
      await installTraining({app,pool:fixture.pool,authRequired:auth,muxSigner,muxCatalog,storage});
      server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
      const base=`http://127.0.0.1:${server.address().port}/api/training`;
      const request=async(path,{who='owner',method='GET',body}={})=>{
        const response=await fetch(base+path,{method,headers:{'X-Fixture-User':who,'Content-Type':'application/json'},
          body:body===undefined?undefined:JSON.stringify(body)});
        return {status:response.status,body:await response.json()};
      };
      const post=(path,body,who='owner')=>request(path,{who,method:'POST',body});
      const put=(path,body,who='bob')=>request(path,{who,method:'PUT',body});
      const publish=async document=>{
        const draft=await post('/definitions',document);assert.equal(draft.status,200,JSON.stringify(draft.body));
        const version=await post(`/definitions/${draft.body.id}/publish`,{expected_revision:1});
        assert.equal(version.status,200,JSON.stringify(version.body));
        return {definition_id:draft.body.id,version_id:version.body.id};
      };
      const videoURL='https://player.mux.com/abc123DEF456';
      assert.equal((await post('/video/assets/verify',{url:videoURL})).status,200);
      const intro=await publish({kind:'task',title:'Introduction and expectations',blocks:[
        {id:'welcome',type:'video',title:'Welcome',video:{url:'https://www.youtube.com/watch?v=abcdefghijk',mode:'A'}},
        {id:'expectations',type:'checklist',title:'Acknowledge expectations',items:[{id:'ack',text:'I understand the course expectations'}]}
      ]});
      const safetyQuestions=Array.from({length:10},(_,i)=>({id:`s${i+1}`,type:'true_false',
        prompt:`Safety rule ${i+1}: inspect equipment before use.`,points:1,answer:true}));
      const safety=await publish({kind:'task',title:'Safety and hazards',blocks:[
        {id:'safety-video',type:'video',title:'Safety demonstration',video:{url:videoURL,mode:'E',duration_seconds:8,
          min_watch_seconds:8,supervisor_approval:true,checkpoints:[2,4,6].map((at_seconds,i)=>({
            id:`safety-c${i+1}`,kind:'question',at_seconds,
            question:{id:`checkpoint-${i+1}`,type:'true_false',prompt:`Use a stable ladder at step ${i+1}?`,points:1,answer:true}})),
          knowledge_check:{passing_percent:90,max_attempts:2,questions:safetyQuestions}}}
      ]});
      const equipment=await publish({kind:'checklist',title:'Equipment inspection',blocks:[
        {id:'equipment-steps',type:'checklist',ordered:true,items:[
          {id:'ladder',text:'Check ladder rails and feet'},{id:'squeegee',text:'Inspect squeegee blade'}]}
      ]});
      const imageID=randomUUID();
      const imageQuizDraft=await post('/definitions',{kind:'quiz',title:'Identify safe equipment',quiz:{
        passing_percent:100,max_attempts:2,questions:[{id:'identify',type:'image_identification',
          prompt:'Which part needs replacement?',image_file_id:imageID,points:1,
          options:[{id:'blade',label:'Damaged squeegee blade'},{id:'handle',label:'Intact handle'}],answer:'blade'}]}});
      assert.equal(imageQuizDraft.status,200);
      assert.equal((await post('/assets/reserve',{target_kind:'definition',target_id:imageQuizDraft.body.id,
        file:{id:imageID,original_filename:'equipment.jpg',mime_type:'image/jpeg',byte_size:100}})).status,200);
      await fixture.pool.query(`UPDATE stored_files SET cloud_status='active' WHERE id=$1`,[imageID]);
      const imageQuizVersion=await post(`/definitions/${imageQuizDraft.body.id}/publish`,{expected_revision:1});
      assert.equal(imageQuizVersion.status,200);
      const equipmentQuiz={definition_id:imageQuizDraft.body.id,version_id:imageQuizVersion.body.id};
      const technique=await publish({kind:'task',title:'Technique and practical proof',blocks:[
        {id:'technique-video',type:'video',title:'Demonstration',video:{url:videoURL,mode:'D',duration_seconds:8,
          checkpoints:[2,5].map((at_seconds,i)=>({id:`tech-c${i+1}`,kind:'question',at_seconds,
            question:{id:`tech-q${i+1}`,type:'true_false',prompt:'Clean from the top downward?',points:1,answer:true}}))}},
        {id:'practice-photos',type:'photo_evidence',title:'Three practical photos',required:true,min_count:3}
      ]});
      const finalQuestions=Array.from({length:25},(_,i)=>({id:`f${i+1}`,type:'multiple_choice',
        prompt:`Final safety and technique question ${i+1}`,points:4,
        options:[{id:'safe',label:'Follow the safe procedure'},{id:'unsafe',label:'Skip the procedure'}],answer:'safe'}));
      const final=await publish({kind:'quiz',title:'Final assessment',requires_review:true,quiz:{
        passing_percent:85,max_attempts:2,shuffle_questions:true,shuffle_answers:true,
        show_results:'after_review',questions:finalQuestions}});
      const lessons=[
        ['intro','Introduction',intro,[]],['safety','Safety',safety,['intro']],
        ['equipment','Equipment check',equipment,['safety']],['equipment-quiz','Photo identification',equipmentQuiz,['equipment']],
        ['technique','Technique practice',technique,['equipment-quiz']],['final','Final exam',final,['technique']]
      ];
      const course=await post('/courses',{title:'Window Cleaning Certification',description:'Internal company training record',
        progression:'sequential',certificate_enabled:true,recertification_days:365,estimated_minutes:120,
        modules:[
          {id:'introduction',title:'Introduction',lessons:lessons.slice(0,1).map(lesson)},
          {id:'safety',title:'Safety',lessons:lessons.slice(1,2).map(lesson)},
          {id:'equipment',title:'Equipment',lessons:lessons.slice(2,4).map(lesson)},
          {id:'technique',title:'Technique',lessons:lessons.slice(4,5).map(lesson)},
          {id:'assessment',title:'Final assessment',lessons:lessons.slice(5).map(lesson)}
        ]});
      function lesson([id,title,definition,prerequisites]){return {id,title,...definition,prerequisites};}
      assert.equal(course.status,200,JSON.stringify(course.body));
      assert.equal((await post(`/courses/${course.body.id}/publish`,{expected_revision:1})).status,200);
      const enrolled=await post('/course-enrollments',{course_id:course.body.id,recipient_ids:[fixture.ids.bob],
        request_key:'window-certification-fixture'});assert.equal(enrolled.status,200);
      const enrollmentID=enrolled.body.enrollment_ids[0],start=id=>post(`/course-enrollments/${enrollmentID}/lessons/${id}/start`,{},'bob');
      assert.equal((await start('final')).body.error,'lesson_locked');
      const first=(await start('intro')).body;
      assert.equal((await post(`/recipients/${first.recipient_id}/submit`,{expected_revision:1},'bob')).body.error,'requirements_incomplete');
      assert.equal((await put(`/recipients/${first.recipient_id}/responses`,{expected_revision:1,
        responses:{expectations:{checked_item_ids:['ack']}}})).status,200);
      assert.equal((await post(`/recipients/${first.recipient_id}/submit`,{expected_revision:2},'bob')).body.status,'completed');
      const safetyRun=(await start('safety')).body;
      const safetyPath=`/recipients/${safetyRun.recipient_id}/videos/safety-video`;
      const safetySession=(await post(`${safetyPath}/sessions`,{},'bob')).body;
      await watch(request,fixture,safetySession.id,safetyPath,[2,4,6],['safety-c1','safety-c2','safety-c3']);
      assert.equal((await post(`${safetyPath}/check`,{request_key:'safety-final',
        responses:Object.fromEntries(safetyQuestions.map(question=>[question.id,true]))},'bob')).body.passed,true);
      assert.equal((await post(`/video/sessions/${safetySession.id}/finish`,{},'bob')).body.status,'completed');
      assert.equal((await post(`/recipients/${safetyRun.recipient_id}/submit`,{expected_revision:1},'bob')).body.status,'awaiting_review');
      assert.equal((await start('equipment')).body.error,'lesson_locked');
      assert.equal((await post(`/recipients/${safetyRun.recipient_id}/review`,{expected_revision:2,decision:'approve',feedback:'Safety approved'})).body.status,'completed');
      const equipmentRun=(await start('equipment')).body;
      assert.equal((await put(`/recipients/${equipmentRun.recipient_id}/responses`,{expected_revision:1,
        responses:{'equipment-steps':{checked_item_ids:['ladder','squeegee']}}})).status,200);
      assert.equal((await post(`/recipients/${equipmentRun.recipient_id}/submit`,{expected_revision:2},'bob')).body.status,'completed');
      const photoRun=(await start('equipment-quiz')).body;
      const photoAttempt=(await post(`/recipients/${photoRun.recipient_id}/quiz/attempts`,{},'bob')).body;
      assert.equal(JSON.stringify(photoAttempt).includes('"answer"'),false);
      assert.equal((await put(`/quiz/attempts/${photoAttempt.id}/responses`,{expected_revision:1,responses:{identify:'blade'}})).status,200);
      assert.equal((await post(`/quiz/attempts/${photoAttempt.id}/submit`,{expected_revision:2},'bob')).body.passed,true);
      const techniqueRun=(await start('technique')).body,techniquePath=`/recipients/${techniqueRun.recipient_id}/videos/technique-video`;
      const techniqueSession=(await post(`${techniquePath}/sessions`,{},'bob')).body;
      await watch(request,fixture,techniqueSession.id,techniquePath,[2,5],['tech-c1','tech-c2']);
      assert.equal((await post(`/video/sessions/${techniqueSession.id}/finish`,{},'bob')).body.status,'completed');
      assert.equal((await post(`/recipients/${techniqueRun.recipient_id}/submit`,{expected_revision:1},'bob')).body.error,'requirements_incomplete');
      for(let i=0;i<3;i++){
        const id=randomUUID();
        assert.equal((await post('/assets/reserve',{target_kind:'recipient',target_id:techniqueRun.recipient_id,
          block_id:'practice-photos',file:{id,original_filename:`practice-${i+1}.jpg`,mime_type:'image/jpeg',byte_size:100}},'bob')).status,200);
        await fixture.pool.query(`UPDATE stored_files SET cloud_status='active' WHERE id=$1`,[id]);
      }
      assert.equal((await post(`/recipients/${techniqueRun.recipient_id}/submit`,{expected_revision:1},'bob')).body.status,'completed');
      const finalRun=(await start('final')).body;
      assert.equal((await post(`/recipients/${finalRun.recipient_id}/submit`,{expected_revision:1},'bob')).body.error,'use_quiz_attempt_endpoint');
      const firstAttempt=(await post(`/recipients/${finalRun.recipient_id}/quiz/attempts`,{},'bob')).body;
      assert.equal((await put(`/quiz/attempts/${firstAttempt.id}/responses`,{expected_revision:1,
        responses:Object.fromEntries(finalQuestions.map(question=>[question.id,'unsafe']))})).status,200);
      assert.equal((await post(`/quiz/attempts/${firstAttempt.id}/submit`,{expected_revision:2},'bob')).body.passed,false);
      const secondAttempt=(await post(`/recipients/${finalRun.recipient_id}/quiz/attempts`,{},'bob')).body;
      assert.equal(secondAttempt.attempt_number,2);
      assert.equal((await put(`/quiz/attempts/${secondAttempt.id}/responses`,{expected_revision:1,
        responses:Object.fromEntries(finalQuestions.map((question,i)=>[question.id,i<22?'safe':'unsafe']))})).status,200);
      const passed=await post(`/quiz/attempts/${secondAttempt.id}/submit`,{expected_revision:2},'bob');
      assert.equal(passed.status,200);assert.equal(passed.body.passed,undefined);
      assert.equal((await request(`/course-enrollments/${enrollmentID}`,{who:'bob'})).body.completed_at,null);
      assert.equal((await post(`/recipients/${finalRun.recipient_id}/review`,{expected_revision:3,decision:'approve',feedback:'Final passed'})).body.status,'completed');
      const complete=(await request(`/course-enrollments/${enrollmentID}`,{who:'bob'})).body;
      assert.equal(complete.completed_required,6);assert.ok(complete.completed_at);
      const certificates=(await request('/certificates/mine',{who:'bob'})).body.items;
      assert.equal(certificates.length,1);assert.equal(certificates[0].course_title,'Window Cleaning Certification');
      assert.equal(certificates[0].score_percent,94); // Mean of the two required passing quizzes: 100% and 88%.
    }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
  });

async function watch(request,fixture,sessionID,path,checkpoints,ids){
  const event=(seq,type,position_seconds)=>request(`/video/sessions/${sessionID}/events`,{who:'bob',method:'POST',
    body:{seq,type,position_seconds}});
  const elapsed=seconds=>fixture.pool.query(`UPDATE training_video_sessions SET last_receipt_at=now()-($2::text||' seconds')::interval
    WHERE id=$1`,[sessionID,seconds]);
  let seq=1,position=0;
  for(let i=0;i<checkpoints.length;i++){
    assert.equal((await event(seq++,'play',position)).status,200);await elapsed(checkpoints[i]-position);
    assert.equal((await event(seq++,'pulse',checkpoints[i])).body.reason,'checkpoint_required');
    assert.equal((await request(`${path}/checkpoints/${ids[i]}`,{who:'bob',method:'POST',
      body:{request_key:`${sessionID}-${ids[i]}`,response:true}})).body.unlocked,true);
    position=checkpoints[i];
  }
  assert.equal((await event(seq++,'play',position)).status,200);await elapsed(8-position);
  assert.equal((await event(seq,'pulse',8)).body.watched_seconds,8);
}
