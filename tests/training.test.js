import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining} from '../training/index.js';
import {digest,normalizeDefinition,normalizeResponses,unmetRequirements} from '../training/contract.js';

test('versioned task contract rejects unsupported blocks and incomplete ordered checklists',()=>{
  const document=normalizeDefinition({kind:'checklist',title:'Truck inspection',blocks:[
    {id:'intro',type:'instruction',text:'Inspect before use.'},
    {id:'steps',type:'checklist',ordered:true,items:[{id:'tires',text:'Tires'},{id:'lights',text:'Lights'},{id:'glass',text:'Glass',required:false}]}
  ]});
  assert.deepEqual(unmetRequirements(document,{}),[{block_id:'steps',item_id:'tires'},{block_id:'steps',item_id:'lights'}]);
  assert.deepEqual(unmetRequirements(document,normalizeResponses(document,{steps:{checked_item_ids:['lights']}})),[
    {block_id:'steps',item_id:'tires'},{block_id:'steps',item_id:'lights',reason:'ordered'}
  ]);
  assert.deepEqual(unmetRequirements(document,normalizeResponses(document,{steps:{checked_item_ids:['tires','lights','tires']}})),[]);
  assert.throws(()=>normalizeResponses(document,{steps:{checked_item_ids:['forged']}}),{code:'unknown_checklist_item'});
  assert.throws(()=>normalizeResponses(document,{intro:{text:'done'}}),{code:'instruction_has_no_response'});
  assert.throws(()=>normalizeDefinition({kind:'task',title:'Unsupported',blocks:[{id:'unsupported',type:'custom_html',html:'<script>bad()</script>'}]}),{code:'unsupported_block_type'});
});

test('rich instructions preserve safe Markdown without executable links or remote images',()=>{
  const input={kind:'task',title:'Read the guide',blocks:[{id:'guide',type:'instruction',format:'markdown',
    text:'**Safety first**\n- Check tools\n[Company guide](https://example.com/safety)'}]};
  const document=normalizeDefinition(input);
  assert.equal(document.blocks[0].format,'markdown');
  assert.equal(document.blocks[0].text,input.blocks[0].text);
  assert.equal(normalizeDefinition({...input,blocks:[{...input.blocks[0],format:'plain'}]}).blocks[0].format,'plain');
  for(const text of ['[Bad](javascript:alert(1))','[Bad](http://example.com)',
    '[Bad](https://user:password@example.com)','![Remote](https://example.com/a.png)']){
    assert.throws(()=>normalizeDefinition({...input,blocks:[{...input.blocks[0],text}]}));
  }
  assert.throws(()=>normalizeDefinition({...input,blocks:[{...input.blocks[0],text:'<script>alert(1)</script>'}]}),
    {code:'instruction_html_unsupported'});
  assert.throws(()=>normalizeDefinition({...input,blocks:[{...input.blocks[0],format:'html'}]}),
    {code:'invalid_instruction_format'});
});

test('form contract validates typed answers and conditional required fields',()=>{
  const document=normalizeDefinition({kind:'inspection',title:'Truck inspection',requires_review:true,blocks:[
    {id:'condition',type:'form_field',field_type:'dropdown',label:'Condition',options:[{id:'good',label:'Good'},{id:'damage',label:'Damage'}]},
    {id:'detail',type:'form_field',field_type:'long_text',label:'Describe damage',visible_if:{block_id:'condition',equals:'damage'}},
    {id:'mileage',type:'form_field',field_type:'number',label:'Mileage',min:0},
    {id:'date',type:'form_field',field_type:'date',label:'Inspection date'}
  ]});
  assert.deepEqual(unmetRequirements(document,{}).map(item=>item.block_id),['condition','mileage','date']);
  const good=normalizeResponses(document,{condition:{value:'good'},mileage:{value:1324},date:{value:'2026-10-22'}});
  assert.deepEqual(unmetRequirements(document,good),[]);
  assert.throws(()=>normalizeResponses(document,{condition:{value:'good'},detail:{value:'Hidden'}}),{code:'hidden_field_response'});
  assert.deepEqual(unmetRequirements(document,normalizeResponses(document,{condition:{value:'damage'},mileage:{value:1324},date:{value:'2026-10-22'}})).map(item=>item.block_id),['detail']);
  assert.throws(()=>normalizeResponses(document,{condition:{value:'unknown'}}),{code:'invalid_option_answer'});
  assert.throws(()=>normalizeResponses(document,{mileage:{value:-1}}),{code:'field_out_of_range'});
  assert.throws(()=>normalizeDefinition({kind:'form',title:'Cycle',blocks:[{id:'a',type:'form_field',field_type:'yes_no',label:'A',visible_if:{block_id:'b',equals:'true'}},{id:'b',type:'form_field',field_type:'yes_no',label:'B'}]}),{code:'invalid_visibility_dependency'});
});

test('conditional content skips hidden requirements and rejects forged hidden checklist answers',()=>{
  const document=normalizeDefinition({kind:'inspection',title:'Damage follow-up',blocks:[
    {id:'damage',type:'form_field',field_type:'yes_no',label:'Is there damage?'},
    {id:'section',type:'heading',text:'Document damage',visible_if:{block_id:'damage',equals:'true'}},
    {id:'steps',type:'checklist',items:[{id:'inspect',text:'Inspect the panel'}],visible_if:{block_id:'damage',equals:'true'}},
    {id:'photo',type:'photo_evidence',title:'Damage photo',visible_if:{block_id:'damage',equals:'true'}},
    {id:'sign',type:'signature',title:'Sign inspection',visible_if:{block_id:'damage',equals:'true'}}
  ]});
  assert.equal(document.blocks[1].visible_if.block_id,'damage');
  const clear=normalizeResponses(document,{damage:{value:false}});
  assert.deepEqual(unmetRequirements(document,clear),[]);
  assert.throws(()=>normalizeResponses(document,{damage:{value:false},steps:{checked_item_ids:['inspect']}}),
    {code:'hidden_field_response'});
  const damaged=normalizeResponses(document,{damage:{value:true}});
  assert.deepEqual(unmetRequirements(document,damaged).map(item=>item.block_id),['steps','photo','sign']);
  assert.throws(()=>normalizeDefinition({kind:'task',title:'Invalid order',blocks:[
    {id:'early',type:'checklist',items:[{id:'item',text:'Step'}],visible_if:{block_id:'later',equals:'true'}},
    {id:'later',type:'form_field',field_type:'yes_no',label:'Later'}
  ]}),{code:'invalid_visibility_dependency'});
  const nested=normalizeDefinition({kind:'form',title:'Nested damage detail',blocks:[
    {id:'a',type:'form_field',field_type:'yes_no',label:'Damage?'},
    {id:'b',type:'form_field',field_type:'yes_no',label:'Needs photos?',visible_if:{block_id:'a',equals:'true'}},
    {id:'c',type:'checklist',items:[{id:'photo',text:'Take a photo'}],visible_if:{block_id:'b',equals:'true'}}
  ]});
  const hidden={a:{value:false},b:{value:true}};
  assert.deepEqual(unmetRequirements(nested,hidden),[]);
  assert.throws(()=>normalizeResponses(nested,hidden),{code:'hidden_field_response'});
  assert.throws(()=>normalizeResponses(nested,{...hidden,c:{checked_item_ids:['photo']}}),{code:'hidden_field_response'});
  assert.deepEqual(unmetRequirements(nested,normalizeResponses(nested,{a:{value:true},b:{value:true}}))
    .map(item=>item.block_id),['c']);
  const missingSource=normalizeDefinition({kind:'task',title:'Missing answer',blocks:[
    {id:'choice',type:'form_field',field_type:'dropdown',label:'Choose',required:false,
      options:[{id:'undefined',label:'First'},{id:'other',label:'Other'}]},
    {id:'required',type:'checklist',items:[{id:'step',text:'Step'}],visible_if:{block_id:'choice',equals:'undefined'}}
  ]});
  assert.deepEqual(unmetRequirements(missingSource,{}),[]);
});

test('HTTP training task lifecycle pins versions, isolates companies and blocks forged completion',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express();let server;
  try{
    app.use(express.json({limit:'256kb'}));
    const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');if(!fixture.ids[who])return res.status(401).json({error:'unauthorized'});
      req.userId=fixture.ids[who];req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
    await installTraining({app,pool:fixture.pool,authRequired:auth});
    await fixture.pool.query(`ALTER TABLE training_definitions DROP CONSTRAINT training_definitions_kind_check;
      ALTER TABLE training_definitions ADD CONSTRAINT training_definitions_kind_check CHECK (kind IN ('task','checklist'));
      ALTER TABLE training_versions DROP CONSTRAINT training_versions_kind_check;
      ALTER TABLE training_versions ADD CONSTRAINT training_versions_kind_check CHECK (kind IN ('task','checklist'));`);
    await installTraining({app:express(),pool:fixture.pool,authRequired:auth}); // upgrades the earlier task-only schema
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,{who='owner',method='GET',body}={})=>{const response=await fetch(base+path,{method,headers:{'X-Fixture-User':who,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});return {status:response.status,body:await response.json()};};
    const original={kind:'checklist',title:'Clean truck',requires_review:false,blocks:[{id:'steps',type:'checklist',ordered:true,items:[{id:'wash',text:'Wash truck'},{id:'dry',text:'Dry truck'}]}]};
    const preview=await request('/definitions/validate',{method:'POST',body:original});assert.equal(preview.status,200);
    assert.equal((await fixture.pool.query('SELECT count(*)::integer AS n FROM training_definitions')).rows[0].n,0);
    const eligible=await request('/eligible-recipients');assert.equal(eligible.status,200);
    assert.ok(eligible.body.items.some(item=>item.id===fixture.ids.alice));
    assert.ok(!eligible.body.items.some(item=>item.id===fixture.ids.foreign));
    const grantPath=`/supervisors/${fixture.ids.alice}/employees/${fixture.ids.bob}`;
    assert.equal((await request(grantPath,{method:'PUT',body:{supervised:true}})).body.supervised,true);
    assert.equal((await request(`/supervisors/${fixture.ids.alice}`)).body.items.find(item=>item.id===fixture.ids.bob).supervised,true);
    assert.equal((await request(`/supervisors/${fixture.ids.alice}/employees/${fixture.ids.foreign}`,{method:'PUT',body:{supervised:true}})).status,404);
    assert.equal((await request(grantPath,{method:'PUT',body:{}})).status,400);
    assert.equal((await request(grantPath,{method:'PUT',body:{supervised:false}})).body.supervised,false);
    const draft=await request('/definitions',{method:'POST',body:original});assert.equal(draft.status,200);
    const definitionID=draft.body.id;
    const published=await request(`/definitions/${definitionID}/publish`,{method:'POST',body:{expected_revision:1}});assert.equal(published.status,200);
    const versionID=published.body.id;
    const futureAt=new Date(Date.now()+86400000).toISOString(),laterAt=new Date(Date.now()+172800000).toISOString();
    const payload={definition_id:definitionID,recipient_ids:[fixture.ids.owner],request_key:'truck-test',due_at:futureAt};
    const assigned=await request('/assignments',{method:'POST',body:payload});assert.equal(assigned.status,200);
    assert.equal((await request('/assignments',{method:'POST',body:payload})).body.id,assigned.body.id);
    await fixture.pool.query(`UPDATE training_assignments SET input_sha256=$2 WHERE id=$1`,
      [assigned.body.id,digest({definitionID,versionID,recipientIDs:[fixture.ids.owner],availableAt:null,dueAt:futureAt,expiresAt:null})]);
    assert.equal((await request('/assignments',{method:'POST',body:{...payload,due_at:laterAt}})).status,409);
    const mine=await request('/mine');assert.equal(mine.status,200);assert.equal(mine.body.items.length,1);
    const recipientID=mine.body.items[0].id;
    assert.equal((await request(`/recipients/${recipientID}`,{who:'foreign'})).status,404);
    assert.equal((await request(`/recipients/${recipientID}/submit`,{method:'POST',body:{expected_revision:1}})).body.error,'requirements_incomplete');
    const saved=await request(`/recipients/${recipientID}/responses`,{method:'PUT',body:{expected_revision:1,responses:{steps:{checked_item_ids:['wash']}}}});assert.equal(saved.status,200);
    assert.equal((await request(`/recipients/${recipientID}/submit`,{method:'POST',body:{expected_revision:2}})).body.error,'requirements_incomplete');
    assert.equal((await request(`/recipients/${recipientID}/responses`,{method:'PUT',body:{expected_revision:1,responses:{steps:{checked_item_ids:['wash','dry']}}}})).status,409);
    const complete=await request(`/recipients/${recipientID}/responses`,{method:'PUT',body:{expected_revision:2,responses:{steps:{checked_item_ids:['wash','dry']}}}});assert.equal(complete.status,200);
    const submitted=await request(`/recipients/${recipientID}/submit`,{method:'POST',body:{expected_revision:3}});assert.equal(submitted.body.status,'completed');
    assert.equal((await request(`/recipients/${recipientID}/submit`,{method:'POST',body:{expected_revision:4}})).status,409);
    const changed=await request(`/definitions/${definitionID}`,{method:'PUT',body:{...original,title:'Clean truck and tools',expected_revision:1}});assert.equal(changed.status,200);
    const second=await request(`/definitions/${definitionID}/publish`,{method:'POST',body:{expected_revision:2}});assert.equal(second.status,200);
    assert.equal((await request('/assignments',{method:'POST',body:payload})).body.id,assigned.body.id);
    const pinned=await request(`/recipients/${recipientID}`);assert.equal(pinned.body.title,'Clean truck');assert.equal(pinned.body.version_number,1);
    const rows=(await fixture.pool.query('SELECT version_id FROM training_assignments WHERE id=$1',[assigned.body.id])).rows;assert.equal(rows[0].version_id,versionID);
    assert.equal((await request('/assignments',{method:'POST',body:{definition_id:definitionID,recipient_ids:[fixture.ids.foreign],request_key:'foreign'}})).status,400);
    const history=await request(`/recipients/${recipientID}/history`);assert.ok(history.body.items.some(e=>e.action==='assignment.submitted'));
    const quickBody={title:'Clean company truck by 5 PM',recipient_ids:[fixture.ids.owner],due_at:futureAt,request_key:'quick-truck'};
    const quick=await request('/quick-tasks',{method:'POST',body:quickBody});assert.equal(quick.status,200);
    assert.equal((await request('/quick-tasks',{method:'POST',body:quickBody})).body.id,quick.body.id);
    assert.equal((await request('/quick-tasks',{method:'POST',body:{...quickBody,title:'Different task'}})).status,409);
    assert.equal((await request('/definitions',{who:'alice',method:'POST',body:original})).status,403);
    const quickMine=(await request('/mine')).body.items.find(item=>item.assignment_id===quick.body.id);
    assert.ok(quickMine);assert.equal((await request(`/recipients/${quickMine.id}/submit`,{method:'POST',body:{expected_revision:1}})).body.status,'completed');
    const inspection={kind:'inspection',title:'Inspect work truck',requires_review:true,blocks:[
      {id:'condition',type:'form_field',field_type:'dropdown',label:'Condition',options:[{id:'good',label:'Good'},{id:'damage',label:'Damage'}]},
      {id:'detail',type:'form_field',field_type:'long_text',label:'Describe damage',visible_if:{block_id:'condition',equals:'damage'}}
    ]};
    const inspectionDraft=await request('/definitions',{method:'POST',body:inspection});assert.equal(inspectionDraft.status,200);
    assert.equal((await request(`/definitions/${inspectionDraft.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).status,200);
    const inspectionAssignment=await request('/assignments',{method:'POST',body:{definition_id:inspectionDraft.body.id,recipient_ids:[fixture.ids.owner],request_key:'inspection'}});assert.equal(inspectionAssignment.status,200);
    const inspectionRecipient=(await request('/mine')).body.items.find(item=>item.assignment_id===inspectionAssignment.body.id);
    assert.equal((await request(`/recipients/${inspectionRecipient.id}/submit`,{method:'POST',body:{expected_revision:1}})).body.error,'requirements_incomplete');
    const inspected=await request(`/recipients/${inspectionRecipient.id}/responses`,{method:'PUT',body:{expected_revision:1,responses:{condition:{value:'damage'},detail:{value:'Broken mirror'}}}});assert.equal(inspected.status,200);
    assert.equal((await request(`/recipients/${inspectionRecipient.id}/submit`,{method:'POST',body:{expected_revision:2}})).body.status,'awaiting_review');
    assert.equal((await request('/assignments',{method:'POST',body:{...payload,request_key:'wrong-version',version_id:second.body.id,definition_id:quick.body.definition_id}})).status,404);
    await fixture.pool.query('UPDATE users SET deleted_at=now() WHERE id=$1',[fixture.ids.disabled]);
    assert.equal((await request('/assignments',{method:'POST',body:{definition_id:definitionID,recipient_ids:[fixture.ids.disabled],request_key:'disabled'}})).status,400);
    await fixture.pool.query(`UPDATE employee_permissions SET permission_overrides=$2 WHERE user_id=$1`,[
      fixture.ids.alice,JSON.stringify({'training.author':true,'training.publish':true,'training.assign':true,'training.review':true,'training.analytics':true})
    ]);
    assert.equal((await request('/eligible-recipients',{who:'alice'})).body.items.length,0);
    assert.equal((await request('/quick-tasks',{who:'alice',method:'POST',body:{title:'Inspect truck',recipient_ids:[fixture.ids.bob],request_key:'alice-before'}})).body.error,'recipient_scope_denied');
    assert.equal((await request(grantPath,{method:'PUT',body:{supervised:true}})).status,200);
    assert.deepEqual((await request('/eligible-recipients',{who:'alice'})).body.items.map(item=>item.id),[fixture.ids.bob]);
    const delegated=await request('/quick-tasks',{who:'alice',method:'POST',body:{title:'Inspect company truck',recipient_ids:[fixture.ids.bob],requires_review:true,request_key:'alice-delegated'}});
    assert.equal(delegated.status,200);
    const bobItems=(await request('/mine',{who:'bob'})).body.items;
    const delegatedRecipient=bobItems.find(item=>item.assignment_id===delegated.body.id);assert.ok(delegatedRecipient);
    assert.equal((await request(`/recipients/${delegatedRecipient.id}`,{who:'carol'})).status,404);
    assert.equal((await request(`/recipients/${delegatedRecipient.id}/submit`,{who:'bob',method:'POST',body:{expected_revision:1}})).body.status,'awaiting_review');
    assert.equal((await request('/reviews',{who:'alice'})).body.items.length,1);
    assert.equal((await request(`/recipients/${delegatedRecipient.id}`,{who:'alice'})).status,200);
    assert.equal((await request(`/recipients/${delegatedRecipient.id}/review`,{who:'alice',method:'POST',body:{expected_revision:2,decision:'approve',feedback:'Done'}})).body.status,'completed');
    assert.equal((await request(grantPath,{method:'PUT',body:{supervised:false}})).status,200);
    assert.equal((await request(`/recipients/${delegatedRecipient.id}`,{who:'alice'})).status,404);
    assert.equal((await request('/quick-tasks',{who:'alice',method:'POST',body:{title:'Another task',recipient_ids:[fixture.ids.bob],request_key:'alice-after'}})).body.error,'recipient_scope_denied');
    const roleBody={definition_id:definitionID,audience:{kind:'role',role:'employee'},request_key:'all-employees'};
    const roleAssignment=await request('/assignments',{method:'POST',body:roleBody});
    assert.equal(roleAssignment.status,200);assert.equal(roleAssignment.body.recipient_count,4);
    assert.equal((await request('/assignments',{method:'POST',body:{...roleBody,audience:{kind:'role',role:'unknown'}}})).status,400);
    const lateEmployee=randomUUID();
    await fixture.pool.query(`INSERT INTO users(id,company_id,email,display_name,role)
      VALUES($1,$2,$3,$4,'employee')`,[lateEmployee,fixture.companies.a,'late@example.invalid','Late Employee']);
    const retryAudience=await request('/assignments',{method:'POST',body:roleBody});
    assert.equal(retryAudience.body.id,roleAssignment.body.id);
    assert.equal(retryAudience.body.recipient_count,4);
    assert.equal((await fixture.pool.query(`SELECT count(*)::integer AS n FROM training_recipients WHERE company_id=$1 AND assignment_id=$2 AND employee_id=$3`,
      [fixture.companies.a,roleAssignment.body.id,lateEmployee])).rows[0].n,0);
    assert.equal((await request('/audience-groups',{who:'alice',method:'POST',body:{kind:'team',name:'Drivers',member_ids:[fixture.ids.bob]}})).status,403);
    assert.equal((await request('/audience-groups',{method:'POST',body:{kind:'team',name:'Foreign',member_ids:[fixture.ids.foreign]}})).status,400);
    assert.equal((await request('/audience-groups',{method:'POST',body:{kind:'team',name:'Owners',member_ids:[fixture.ids.owner]}})).status,400);
    const group=(await request('/audience-groups',{method:'POST',body:{kind:'team',name:'Drivers',member_ids:[fixture.ids.bob]}})).body;
    assert.equal(group.revision,1);
    assert.equal((await request('/audience-groups')).body.items.find(item=>item.id===group.id).member_count,1);
    const teamBody={definition_id:definitionID,audience:{kind:'team',id:group.id},request_key:'drivers-first'};
    const teamAssignment=await request('/assignments',{method:'POST',body:teamBody});
    assert.equal(teamAssignment.status,200);assert.equal(teamAssignment.body.recipient_count,1);
    const changedGroup=await request(`/audience-groups/${group.id}`,{method:'PUT',body:{kind:'team',name:'Drivers and trainees',member_ids:[fixture.ids.bob,lateEmployee],expected_revision:1}});
    assert.equal(changedGroup.status,200);assert.equal(changedGroup.body.revision,2);
    assert.equal((await request('/assignments',{method:'POST',body:teamBody})).body.recipient_count,1);
    assert.equal((await request('/assignments',{method:'POST',body:{...teamBody,request_key:'drivers-second'}})).body.recipient_count,2);
    assert.equal((await request(`/audience-groups/${group.id}/archive`,{method:'POST',body:{expected_revision:2}})).status,200);
    assert.equal((await request('/assignments',{method:'POST',body:{...teamBody,request_key:'drivers-after-archive'}})).status,404);
    assert.equal((await request('/assignments',{method:'POST',body:teamBody})).body.id,teamAssignment.body.id);
    const copied=await request(`/definitions/${definitionID}/duplicate`,{method:'POST',body:{title:'Truck checklist template'}});
    assert.equal(copied.status,200);assert.equal(copied.body.draft.title,'Truck checklist template');
    assert.equal(copied.body.revision,1);assert.equal(copied.body.id===definitionID,false);
    assert.equal((await request(`/definitions/${definitionID}/archive`,{method:'POST',body:{expected_revision:1}})).status,409);
    assert.equal((await request(`/definitions/${definitionID}/archive`,{method:'POST',body:{expected_revision:2}})).status,200);
    assert.equal((await request('/definitions')).body.items.some(item=>item.id===definitionID),false);
    assert.equal((await request('/assignments',{method:'POST',body:{definition_id:definitionID,recipient_ids:[fixture.ids.bob],request_key:'archived'}})).body.error,'definition_archived');
    assert.equal((await request('/assignments',{method:'POST',body:roleBody})).body.id,roleAssignment.body.id);
    assert.equal((await request(`/recipients/${recipientID}`)).body.title,'Clean truck');
    assert.equal((await request(`/definitions/${definitionID}/versions`)).body.items.length,2);
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
