import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {createStorageService} from '../media-storage/service.js';
import {authorizeProtectedStorageAccess} from '../media-storage/protected-scopes.js';
import {installTraining} from '../training/index.js';

test('training content and evidence use retained scoped storage without company-wide file access',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),storage=createStorageService({pool:fixture.pool,bucket:{}}),app=express();
  let server,training;
  try{
    app.use(express.json({limit:'256kb'}));
    const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');if(!fixture.ids[who])return res.status(401).json({error:'unauthorized'});
      req.userId=fixture.ids[who];req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
    training=await installTraining({app,pool:fixture.pool,authRequired:auth,storage});
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,{who='owner',method='GET',body}={})=>{const response=await fetch(base+path,{method,headers:{'X-Fixture-User':who,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});return {status:response.status,body:await response.json()};};
    const imageID=randomUUID(),quiz={kind:'quiz',title:'Identify truck damage',quiz:{questions:[
      {id:'q1',type:'image_identification',prompt:'Identify the damaged area',image_file_id:imageID,
        options:[{id:'mirror',label:'Mirror'},{id:'tire',label:'Tire'}],answer:'mirror'}
    ]}};
    const draft=await request('/definitions',{method:'POST',body:quiz});assert.equal(draft.status,200);
    assert.equal((await request(`/definitions/${draft.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).body.error,'content_asset_unavailable');
    const image={id:imageID,original_filename:'truck.jpg',display_name:'Truck image',mime_type:'image/jpeg',byte_size:100};
    const reserve=await request('/assets/reserve',{method:'POST',body:{target_kind:'definition',target_id:draft.body.id,file:image}});
    assert.equal(reserve.status,200);assert.equal(reserve.body.file.source_scope,'training');
    assert.equal(reserve.body.file.source_protected,true);assert.equal(reserve.body.file.visibility,'private');
    assert.equal((await request('/assets/reserve',{who:'carol',method:'POST',body:{target_kind:'definition',target_id:draft.body.id,file:image}})).status,403);
    await fixture.pool.query(`UPDATE stored_files SET cloud_status='active' WHERE id=$1`,[imageID]);
    const version=await request(`/definitions/${draft.body.id}/publish`,{method:'POST',body:{expected_revision:1}});assert.equal(version.status,200);
    const assigned=await request('/assignments',{method:'POST',body:{definition_id:draft.body.id,recipient_ids:[fixture.ids.bob],request_key:'image-quiz'}});assert.equal(assigned.status,200);
    const recipient=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===assigned.body.id);assert.ok(recipient);
    assert.equal((await storage.get(await fixture.actor('bob'),imageID)).id,imageID);
    await assert.rejects(storage.get(await fixture.actor('carol'),imageID),{code:'file_not_found'});
    await assert.rejects(storage.get(await fixture.actor('foreign'),imageID),{code:'file_not_found'});
    const bank=await request('/question-banks',{method:'POST',body:{title:'Truck image question',scope:'company',
      question:quiz.quiz.questions[0],source_definition_id:draft.body.id}});
    assert.equal(bank.status,200);
    const reuse=await request('/definitions',{method:'POST',body:{kind:'quiz',title:'Reused image assessment',quiz:{questions:[
      {id:'placeholder',type:'true_false',prompt:'Ready?',answer:true}
    ]}}});
    assert.equal(reuse.status,200);
    assert.equal((await request(`/question-banks/${bank.body.id}/import`,{who:'foreign',method:'POST',body:{definition_id:reuse.body.id}})).status,404);
    const imported=await request(`/question-banks/${bank.body.id}/import`,{method:'POST',body:{definition_id:reuse.body.id}});
    assert.equal(imported.status,200);assert.equal(imported.body.question.image_file_id,imageID);
    const saved=await request(`/definitions/${reuse.body.id}`,{method:'PUT',body:{kind:'quiz',title:'Reused image assessment',
      expected_revision:1,quiz:{questions:[imported.body.question]}}});
    assert.equal(saved.status,200);
    assert.equal((await request(`/definitions/${reuse.body.id}/publish`,{method:'POST',body:{expected_revision:2}})).status,200);
    assert.equal((await fixture.pool.query(`SELECT count(*)::integer AS n FROM stored_files WHERE id=$1`,[imageID])).rows[0].n,1);
    assert.equal((await fixture.pool.query(`SELECT count(*)::integer AS n FROM training_asset_refs
      WHERE company_id=$1 AND file_id=$2 AND definition_id IS NOT NULL`,[fixture.companies.a,imageID])).rows[0].n,2);
    const pdfID=randomUUID(),mediaDraft=await request('/definitions',{method:'POST',body:{kind:'task',title:'Read safety guide',blocks:[
      {id:'guide',type:'pdf',file_id:pdfID,title:'Safety guide',caption:'Review before beginning.'}
    ]}});
    assert.equal(mediaDraft.status,200);
    assert.equal((await request(`/definitions/${mediaDraft.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).body.error,'content_asset_unavailable');
    assert.equal((await request('/assets/reserve',{method:'POST',body:{target_kind:'definition',target_id:mediaDraft.body.id,
      file:{id:pdfID,original_filename:'guide.pdf',mime_type:'image/jpeg',byte_size:100}}})).status,200);
    await fixture.pool.query(`UPDATE stored_files SET cloud_status='active' WHERE id=$1`,[pdfID]);
    assert.equal((await request(`/definitions/${mediaDraft.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).body.error,'content_asset_type_mismatch');
    await fixture.pool.query(`UPDATE stored_files SET mime_type='application/pdf' WHERE id=$1`,[pdfID]);
    assert.equal((await request(`/definitions/${mediaDraft.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).status,200);
    const mediaAssigned=await request('/assignments',{method:'POST',body:{definition_id:mediaDraft.body.id,
      recipient_ids:[fixture.ids.bob],request_key:'read-safety-guide'}});
    const mediaRecipient=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===mediaAssigned.body.id);
    assert.equal((await request(`/recipients/${mediaRecipient.id}`,{who:'bob'})).body.document.blocks[0].file_id,pdfID);
    assert.equal((await request(`/recipients/${mediaRecipient.id}/responses`,{who:'bob',method:'PUT',
      body:{expected_revision:1,responses:{guide:{value:true}}}})).body.error,'instruction_has_no_response');
    assert.equal((await storage.get(await fixture.actor('bob'),pdfID)).id,pdfID);
    await assert.rejects(storage.get(await fixture.actor('carol'),pdfID),{code:'file_not_found'});
    const coverID=randomUUID(),course=await request('/courses',{method:'POST',body:{title:'Photo safety',cover_file_id:coverID,
      modules:[{id:'intro',title:'Introduction',lessons:[{id:'first',title:'Identify damage',definition_id:draft.body.id,version_id:version.body.id}]}]}});
    assert.equal(course.status,200);
    assert.equal((await request(`/courses/${course.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).body.error,'course_cover_unavailable');
    const cover={id:coverID,original_filename:'course.jpg',mime_type:'image/jpeg',byte_size:100};
    assert.equal((await request('/assets/reserve',{method:'POST',body:{target_kind:'course',target_id:course.body.id,file:cover}})).status,200);
    await fixture.pool.query(`UPDATE stored_files SET cloud_status='active' WHERE id=$1`,[coverID]);
    assert.equal((await request(`/courses/${course.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).status,200);
    assert.equal((await request('/course-enrollments',{method:'POST',body:{course_id:course.body.id,recipient_ids:[fixture.ids.bob],request_key:'cover-course'}})).status,200);
    assert.equal((await storage.get(await fixture.actor('bob'),coverID)).id,coverID);
    await assert.rejects(storage.get(await fixture.actor('carol'),coverID),{code:'file_not_found'});
    const evidenceID=randomUUID(),evidence={id:evidenceID,original_filename:'proof.jpg',display_name:'Proof',mime_type:'image/jpeg',byte_size:100};
    const evidenceReserve=await request('/assets/reserve',{who:'bob',method:'POST',body:{target_kind:'recipient',target_id:recipient.id,file:evidence}});
    assert.equal(evidenceReserve.status,200);
    await fixture.pool.query(`UPDATE stored_files SET cloud_status='active' WHERE id=$1`,[evidenceID]);
    assert.equal((await storage.get(await fixture.actor('owner'),evidenceID)).id,evidenceID);
    await assert.rejects(storage.get(await fixture.actor('carol'),evidenceID),{code:'file_not_found'});
    const row=(await fixture.pool.query(`SELECT * FROM stored_files WHERE id=$1`,[evidenceID])).rows[0];
    await assert.rejects(authorizeProtectedStorageAccess(fixture.pool,await fixture.actor('bob'),row,'delete'),{code:'retained_training_asset'});
    const inspection={kind:'inspection',title:'Inspect work truck',requires_review:true,blocks:[
      {id:'condition',type:'form_field',field_type:'short_text',label:'Condition'},
      {id:'photo',type:'photo_evidence',title:'Damage photo',min_count:1},
      {id:'sign',type:'signature',title:'Employee signature'}
    ]};
    const inspectionDraft=await request('/definitions',{method:'POST',body:inspection});assert.equal(inspectionDraft.status,200);
    assert.equal((await request(`/definitions/${inspectionDraft.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).status,200);
    const inspectionAssignment=await request('/assignments',{method:'POST',body:{definition_id:inspectionDraft.body.id,recipient_ids:[fixture.ids.bob],request_key:'inspection-proof'}});assert.equal(inspectionAssignment.status,200);
    const inspectionRecipient=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===inspectionAssignment.body.id);
    assert.ok(inspectionRecipient);
    assert.equal((await request(`/recipients/${inspectionRecipient.id}/responses`,{who:'bob',method:'PUT',body:{expected_revision:1,responses:{photo:{value:true}}}})).body.error,'evidence_responses_server_only');
    assert.equal((await request(`/recipients/${inspectionRecipient.id}/responses`,{who:'bob',method:'PUT',body:{expected_revision:1,responses:{condition:{value:'Needs mirror repair'}}}})).status,200);
    assert.equal((await request(`/recipients/${inspectionRecipient.id}/submit`,{who:'bob',method:'POST',body:{expected_revision:2}})).body.error,'requirements_incomplete');
    const photoID=randomUUID(),photo={id:photoID,original_filename:'damage.jpg',mime_type:'image/jpeg',byte_size:100};
    assert.equal((await request('/assets/reserve',{who:'bob',method:'POST',body:{target_kind:'recipient',target_id:inspectionRecipient.id,block_id:'photo',file:{...photo,mime_type:'video/mp4'}}})).body.error,'invalid_evidence_type');
    assert.equal((await request('/assets/reserve',{who:'bob',method:'POST',body:{target_kind:'recipient',target_id:inspectionRecipient.id,block_id:'photo',file:photo}})).status,200);
    await fixture.pool.query(`UPDATE stored_files SET cloud_status='active' WHERE id=$1`,[photoID]);
    assert.equal((await request(`/recipients/${inspectionRecipient.id}/submit`,{who:'bob',method:'POST',body:{expected_revision:2}})).body.error,'requirements_incomplete');
    const signatureID=randomUUID(),signature={id:signatureID,original_filename:'signature.png',mime_type:'image/png',byte_size:100};
    assert.equal((await request('/assets/reserve',{who:'bob',method:'POST',body:{target_kind:'recipient',target_id:inspectionRecipient.id,block_id:'sign',file:signature}})).status,200);
    await fixture.pool.query(`UPDATE stored_files SET cloud_status='active' WHERE id=$1`,[signatureID]);
    assert.equal((await request(`/recipients/${inspectionRecipient.id}/assets`,{who:'bob'})).body.items.length,2);
    assert.equal((await request(`/recipients/${inspectionRecipient.id}/assets`,{who:'carol'})).status,403);
    assert.equal((await request(`/recipients/${inspectionRecipient.id}/submit`,{who:'bob',method:'POST',body:{expected_revision:2}})).body.status,'awaiting_review');
    await fixture.pool.query('UPDATE employee_permissions SET permission_overrides=$2 WHERE user_id=$1',
      [fixture.ids.alice,JSON.stringify({'training.author':true,'training.publish':true})]);
    assert.equal((await request('/question-banks',{who:'alice'})).body.items.some(item=>item.id===bank.body.id),true);
    const shared=await request('/definitions',{who:'alice',method:'POST',body:{kind:'quiz',title:'Shared image question',quiz:{questions:[
      {id:'starter',type:'true_false',prompt:'Prepared?',answer:true}]}}});
    assert.equal(shared.status,200);
    const sharedImport=await request(`/question-banks/${bank.body.id}/import`,{who:'alice',method:'POST',body:{definition_id:shared.body.id}});
    assert.equal(sharedImport.status,200);
    assert.equal((await request(`/definitions/${shared.body.id}`,{who:'alice',method:'PUT',body:{kind:'quiz',title:'Shared image question',
      expected_revision:1,quiz:{questions:[sharedImport.body.question]}}})).status,200);
    assert.equal((await request(`/definitions/${shared.body.id}/publish`,{who:'alice',method:'POST',body:{expected_revision:2}})).status,200);
    assert.equal((await fixture.pool.query(`SELECT count(*)::integer AS n FROM stored_files WHERE id=$1`,[imageID])).rows[0].n,1);
    await fixture.pool.query(`UPDATE users SET deleted_at=now() WHERE id=$1`,[fixture.ids.bob]);
    assert.equal((await storage.get(await fixture.actor('owner'),evidenceID)).id,evidenceID);
  }finally{training?.stop();if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});

test('conditional evidence cannot be uploaded while its section is hidden',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),storage=createStorageService({pool:fixture.pool,bucket:{}}),app=express();let server,training;
  try{
    app.use(express.json());
    const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');req.userId=fixture.ids[who];
      req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
    training=await installTraining({app,pool:fixture.pool,authRequired:auth,storage});
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,{who='owner',method='GET',body}={})=>{const response=await fetch(base+path,{method,
      headers:{'X-Fixture-User':who,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
      return {status:response.status,body:await response.json()};};
    const definition=await request('/definitions',{method:'POST',body:{kind:'inspection',title:'Conditional damage photo',blocks:[
      {id:'damage',type:'form_field',field_type:'yes_no',label:'Is there damage?'},
      {id:'needs_photo',type:'form_field',field_type:'yes_no',label:'Needs a photo?',visible_if:{block_id:'damage',equals:'true'}},
      {id:'proof',type:'photo_evidence',title:'Damage proof',visible_if:{block_id:'needs_photo',equals:'true'}}]}});
    assert.equal(definition.status,200);
    assert.equal((await request(`/definitions/${definition.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).status,200);
    const assignment=await request('/assignments',{method:'POST',body:{definition_id:definition.body.id,
      recipient_ids:[fixture.ids.bob],request_key:'conditional-evidence'}});
    assert.equal(assignment.status,200);
    const recipient=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===assignment.body.id);
    const photo={id:randomUUID(),original_filename:'damage.jpg',mime_type:'image/jpeg',byte_size:100};
    const reserve=()=>request('/assets/reserve',{who:'bob',method:'POST',body:{target_kind:'recipient',target_id:recipient.id,
      block_id:'proof',file:photo}});
    assert.equal((await reserve()).body.error,'evidence_block_hidden');
    assert.equal((await request(`/recipients/${recipient.id}/responses`,{who:'bob',method:'PUT',
      body:{expected_revision:1,responses:{damage:{value:false}}}})).status,200);
    assert.equal((await reserve()).body.error,'evidence_block_hidden');
    assert.equal((await request(`/recipients/${recipient.id}/responses`,{who:'bob',method:'PUT',
      body:{expected_revision:2,responses:{damage:{value:true},needs_photo:{value:true}}}})).status,200);
    assert.equal((await reserve()).status,200);
    assert.equal((await request(`/recipients/${recipient.id}/responses`,{who:'bob',method:'PUT',
      body:{expected_revision:3,responses:{damage:{value:false}}}})).status,200);
    assert.equal((await reserve()).body.error,'evidence_block_hidden');
  }finally{training?.stop();if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
