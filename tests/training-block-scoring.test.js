import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining} from '../training/index.js';
import {installTrainingSchema} from '../training/schema.js';

test('scored form and checklist blocks require scoped manual grades with hidden blocks excluded',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express();let server;
  try{
    app.use(express.json());
    const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');req.userId=fixture.ids[who];
      req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
    await installTraining({app,pool:fixture.pool,authRequired:auth});
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,{who='owner',method='GET',body}={})=>{
      const response=await fetch(base+path,{method,headers:{'X-Fixture-User':who,'Content-Type':'application/json'},
        body:body===undefined?undefined:JSON.stringify(body)});
      return {status:response.status,body:await response.json()};
    };
    const post=(path,body,who='owner')=>request(path,{who,method:'POST',body});
    const put=(path,body,who='bob')=>request(path,{who,method:'PUT',body});
    const blocks=[
      {id:'a',type:'form_field',field_type:'yes_no',label:'Was damage found?',required:true},
      {id:'b',type:'checklist',title:'Document damage',items:[{id:'photo',text:'Take photo',required:true}],
        visible_if:{block_id:'a',equals:'true'},points:5},
      {id:'c',type:'form_field',field_type:'short_text',label:'Notes',required:true,points:3},
    ];
    for(const invalid of [0,101,1.5])assert.equal((await post('/definitions',{
      kind:'form',title:'Invalid points',blocks:[blocks[0],{...blocks[2],points:invalid}]})).body.error,'invalid_block_points');
    assert.equal((await post('/definitions',{kind:'task',title:'Unsupported scoring',blocks:[{
      id:'instruction',type:'instruction',text:'Read',points:1}]})).body.error,'unsupported_block_points');
    const draft=await post('/definitions',{kind:'form',title:'Scored inspection',blocks,requires_review:false});
    assert.equal(draft.status,200);assert.equal(draft.body.draft.requires_review,true);
    const published=await post(`/definitions/${draft.body.id}/publish`,{expected_revision:1});
    assert.equal(published.status,200);
    const assign=async(key)=>{
      const result=await post('/assignments',{definition_id:draft.body.id,recipient_ids:[fixture.ids.bob],request_key:key});
      assert.equal(result.status,200);
      return (await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===result.body.id).id;
    };
    const hiddenID=await assign('scored-hidden');
    const hiddenPath=`/recipients/${hiddenID}`;
    assert.equal((await put(`${hiddenPath}/responses`,{expected_revision:1,responses:{a:{value:false},c:{value:'No damage'}}})).status,200);
    assert.equal((await post(`${hiddenPath}/submit`,{expected_revision:2},'bob')).body.status,'awaiting_review');
    assert.equal((await request(hiddenPath,{who:'bob'})).body.score_points,null);
    assert.equal((await post(`${hiddenPath}/override`,{expected_revision:3,reason:'I personally verified all submitted work'},'owner')).body.error,
      'completion_override_not_permitted');
    assert.equal((await post(`${hiddenPath}/review`,{expected_revision:3,decision:'approve',feedback:'',scores:{c:2}},'bob')).status,403);
    assert.equal((await post(`${hiddenPath}/review`,{expected_revision:3,decision:'approve',feedback:'',scores:{c:2}},'foreign')).status,404);
    assert.equal((await post(`${hiddenPath}/review`,{expected_revision:3,decision:'approve',feedback:'',scores:{b:5,c:2}})).body.error,
      'assignment_scores_incomplete');
    assert.equal((await post(`${hiddenPath}/review`,{expected_revision:3,decision:'approve',feedback:'',scores:{c:4}})).body.error,
      'invalid_assignment_score');
    assert.equal((await post(`${hiddenPath}/review`,{expected_revision:3,decision:'approve',feedback:'',scores:{c:1.5}})).body.error,
      'invalid_assignment_score');
    assert.equal((await post(`${hiddenPath}/review`,{expected_revision:3,decision:'request_corrections',feedback:'Please clarify',scores:{c:2}})).body.error,
      'scores_only_on_approval');
    assert.equal((await post(`${hiddenPath}/review`,{expected_revision:3,decision:'approve',feedback:'',scores:{}})).body.error,
      'assignment_scores_incomplete');
    const approved=await post(`${hiddenPath}/review`,{expected_revision:3,decision:'approve',feedback:'Good',scores:{c:2}});
    assert.equal(approved.status,200);assert.equal(approved.body.score_points,2);assert.equal(approved.body.max_points,3);
    assert.equal((await request(hiddenPath,{who:'bob'})).body.score_points,2);
    assert.equal((await post(`${hiddenPath}/review`,{expected_revision:3,decision:'approve',feedback:'',scores:{c:2}})).body.error,
      'not_awaiting_review');
    const history=(await request(`${hiddenPath}/history`,{who:'bob'})).body.items;
    assert.deepEqual(history.find(item=>item.action==='assignment.reviewed').details.scores,{c:2});

    const visibleID=await assign('scored-visible');
    const visiblePath=`/recipients/${visibleID}`;
    assert.equal((await put(`${visiblePath}/responses`,{expected_revision:1,responses:{
      a:{value:true},b:{checked_item_ids:['photo']},c:{value:'Damage noted'}}})).status,200);
    assert.equal((await post(`${visiblePath}/submit`,{expected_revision:2},'bob')).body.status,'awaiting_review');
    const corrections=await post(`${visiblePath}/review`,{expected_revision:3,decision:'request_corrections',feedback:'Please check the photo step'});
    assert.equal(corrections.body.status,'corrections_requested');
    assert.equal((await request(visiblePath,{who:'bob'})).body.score_points,null);
    assert.equal((await post(`${visiblePath}/submit`,{expected_revision:4},'bob')).body.status,'awaiting_review');
    const visible=await post(`${visiblePath}/review`,{expected_revision:5,decision:'approve',feedback:'Complete',scores:{b:5,c:3}});
    assert.equal(visible.status,200);assert.equal(visible.body.score_points,8);assert.equal(visible.body.max_points,8);
    await installTrainingSchema(fixture.pool);
    const retained=(await fixture.pool.query(`SELECT score_points,max_points FROM training_recipients WHERE id=$1`,[visibleID])).rows[0];
    assert.equal(retained.score_points,8);assert.equal(retained.max_points,8);
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
