import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining} from '../training/index.js';
import {installTrainingSchema} from '../training/schema.js';

const question={id:'safe',type:'multiple_choice',prompt:'What comes first?',points:4,
  options:[{id:'inspect',label:'Inspect the truck'},{id:'drive',label:'Drive away'}],answer:'inspect'};

test('question banks protect personal keys and preserve published quiz snapshots',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express();let server;
  try{
    app.use(express.json({limit:'256kb'}));
    const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');if(!fixture.ids[who])return res.status(401).json({error:'unauthorized'});
      req.userId=fixture.ids[who];req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
    await installTraining({app,pool:fixture.pool,authRequired:auth});
    await installTrainingSchema(fixture.pool);
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,{who='owner',method='GET',body}={})=>{const response=await fetch(base+path,{method,headers:{'X-Fixture-User':who,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});return {status:response.status,body:await response.json()};};
    const personal=await request('/question-banks',{method:'POST',body:{title:'Truck start',scope:'personal',category:'Safety',question}});
    assert.equal(personal.status,200);assert.equal(personal.body.question.answer,'inspect');
    await fixture.pool.query('UPDATE employee_permissions SET permission_overrides=$2 WHERE user_id=$1',[fixture.ids.alice,JSON.stringify({'training.author':true})]);
    assert.equal((await request(`/question-banks/${personal.body.id}`,{who:'alice'})).status,404);
    assert.equal((await request('/question-banks',{who:'alice'})).body.items.length,0);
    const aliceDraft=await request('/definitions',{who:'alice',method:'POST',body:{kind:'quiz',title:'Private bank attempt',quiz:{questions:[question]}}});
    assert.equal(aliceDraft.status,200);
    assert.equal((await request(`/question-banks/${personal.body.id}/import`,{who:'alice',method:'POST',
      body:{definition_id:aliceDraft.body.id}})).status,404);
    assert.equal((await request('/question-banks',{who:'foreign'})).body.items.length,0);
    assert.equal((await request(`/question-banks/${personal.body.id}`,{who:'foreign'})).status,404);
    assert.equal((await request('/question-banks',{who:'bob'})).status,403);
    const invalidMedia=await request('/question-banks',{method:'POST',body:{title:'Bad media',question:{...question,image_file_id:fixture.ids.bob}}});
    assert.equal(invalidMedia.body.error,'bank_media_source_required');
    const draft=await request('/definitions',{method:'POST',body:{kind:'quiz',title:'Truck safety',quiz:{questions:[personal.body.question]}}});
    assert.equal(draft.status,200);
    assert.equal((await request(`/definitions/${draft.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).status,200);
    const edited=await request(`/question-banks/${personal.body.id}`,{method:'PUT',body:{title:'Truck start',scope:'personal',category:'Safety',expected_revision:1,
      question:{...question,prompt:'Updated bank prompt'}}});assert.equal(edited.status,200);
    assert.equal((await request(`/question-banks/${personal.body.id}`,{method:'PUT',body:{title:'Stale',question,expected_revision:1}})).body.error,'stale_revision');
    const versions=await fixture.pool.query(`SELECT document FROM training_versions WHERE company_id=$1 AND definition_id=$2`,[fixture.companies.a,draft.body.id]);
    assert.equal(versions.rows[0].document.quiz.questions[0].prompt,'What comes first?');
    assert.equal((await request(`/question-banks/${personal.body.id}/archive`,{method:'POST',body:{expected_revision:2}})).status,200);
    assert.equal((await request(`/question-banks/${personal.body.id}`)).status,404);
    const company=await request('/question-banks',{method:'POST',body:{title:'Shared safety',scope:'company',question}});
    assert.equal(company.status,200);
    assert.equal((await request('/question-banks',{who:'alice'})).body.items.some(item=>item.id===company.body.id),true);
    assert.equal((await request(`/question-banks/${personal.body.id}`,{who:'alice'})).status,404);
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
