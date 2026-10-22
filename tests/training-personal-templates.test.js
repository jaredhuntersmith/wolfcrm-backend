import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining} from '../training/index.js';
import {createStorageService} from '../media-storage/service.js';

const content={kind:'task',title:'Private window setup',scope:'personal',category:'Window care',
  blocks:[{id:'instructions',type:'instruction',text:'Inspect the supplies.'}]};

test('personal templates stay author-only while company drafts remain shared and published history is retained',
  {timeout:120000},async()=>{
    const fixture=await createCommsFixture(),app=express();let server;
    const storage=createStorageService({pool:fixture.pool,bucket:{}});
    try{
      app.use(express.json());
      const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');if(!fixture.ids[who])return res.status(401).json({error:'unauthorized'});
        req.userId=fixture.ids[who];req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
      await installTraining({app,pool:fixture.pool,authRequired:auth,storage});
      await fixture.pool.query('UPDATE employee_permissions SET permission_overrides=$2 WHERE user_id=$1',
        [fixture.ids.alice,JSON.stringify({'training.author':true,'training.publish':true})]);
      server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
      const base=`http://127.0.0.1:${server.address().port}/api/training`;
      const request=async(path,{who='owner',method='GET',body}={})=>{const response=await fetch(base+path,{method,
        headers:{'X-Fixture-User':who,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
        return {status:response.status,body:await response.json()};};
      const privateDraft=await request('/definitions',{method:'POST',body:content});
      assert.equal(privateDraft.status,200);
      const id=privateDraft.body.id;
      assert.equal(privateDraft.body.draft.scope,'personal');
      assert.equal(privateDraft.body.draft.category,'Window care');
      assert.equal((await request('/definitions',{who:'alice'})).body.items.some(item=>item.id===id),false);
      for(const path of [`/definitions/${id}`,`/definitions/${id}/versions`])
        assert.equal((await request(path,{who:'alice'})).status,404);
      assert.equal((await request(`/definitions/${id}/duplicate`,{who:'alice',method:'POST',body:{title:'Copy'}})).status,404);
      assert.equal((await request(`/definitions/${id}/archive`,{who:'alice',method:'POST',body:{expected_revision:1}})).status,404);
      assert.equal((await request('/course-lesson-options',{who:'alice'})).body.items.some(item=>item.definition_id===id),false);
      assert.equal((await request(`/definitions/${id}`,{who:'foreign'})).status,404);
      const published=await request(`/definitions/${id}/publish`,{method:'POST',body:{expected_revision:1}});
      assert.equal(published.status,200);
      assert.equal((await request(`/definitions/${id}/versions/${published.body.id}`,{who:'alice'})).status,404);
      assert.equal((await request(`/definitions/${id}/versions/${published.body.id}`)).body.document.title,content.title);
      const editedVersion=await request(`/definitions/${id}`,{method:'PUT',body:{...content,title:'Revised setup',expected_revision:1}});
      assert.equal(editedVersion.status,200);
      assert.equal((await request(`/definitions/${id}/versions/${published.body.id}`)).body.document.title,content.title);
      assert.equal((await request('/course-lesson-options',{who:'alice'})).body.items.some(item=>item.definition_id===id),false);
      const forbiddenScope=await request(`/definitions/${id}`,{method:'PUT',body:{...content,scope:'company',expected_revision:2}});
      assert.equal(forbiddenScope.body.error,'published_scope_immutable');
      const companyDraft=await request('/definitions',{method:'POST',body:{...content,title:'Shared setup',scope:'company'}});
      assert.equal(companyDraft.status,200);
      assert.equal((await request('/definitions',{who:'alice'})).body.items.some(item=>item.id===companyDraft.body.id),true);
      const alicePrivate=await request('/definitions',{who:'alice',method:'POST',body:{...content,title:'Alice private'}});
      assert.equal(alicePrivate.status,200);
      const aliceVersion=await request(`/definitions/${alicePrivate.body.id}/publish`,{who:'alice',method:'POST',body:{expected_revision:1}});
      assert.equal(aliceVersion.status,200);
      assert.equal((await request(`/definitions/${alicePrivate.body.id}`)).status,404);
      assert.equal((await request('/onboarding-policies',{method:'POST',body:{definition_id:alicePrivate.body.id,
        due_after_days:1,request_key:'private-policy'}})).status,404);
      const leakingCourse=await request('/courses',{method:'POST',body:{title:'Should not include private lesson',
        modules:[{id:'start',title:'Start',lessons:[{id:'one',title:'Private',definition_id:alicePrivate.body.id,
          version_id:aliceVersion.body.id}]}]}});
      assert.equal(leakingCourse.status,200);
      assert.equal((await request(`/courses/${leakingCourse.body.id}/publish`,{method:'POST',
        body:{expected_revision:1}})).body.error,'lesson_version_unavailable');
      const fileID=randomUUID(),media=await request('/definitions',{method:'POST',body:{kind:'task',title:'Personal photo guide',scope:'personal',
        blocks:[{id:'photo',type:'image',file_id:fileID,title:'Guide',alt_text:'Worksite setup'}]}});
      assert.equal(media.status,200);
      assert.equal((await request('/assets/reserve',{who:'alice',method:'POST',body:{target_kind:'definition',target_id:media.body.id,
        file:{id:fileID,original_filename:'guide.jpg',mime_type:'image/jpeg',byte_size:100}}})).status,404);
      assert.equal((await request('/assets/reserve',{method:'POST',body:{target_kind:'definition',target_id:media.body.id,
        file:{id:fileID,original_filename:'guide.jpg',mime_type:'image/jpeg',byte_size:100}}})).status,200);
      await fixture.pool.query(`UPDATE stored_files SET cloud_status='active' WHERE id=$1`,[fileID]);
      assert.equal((await storage.get(await fixture.actor('owner'),fileID)).id,fileID);
      await assert.rejects(storage.get(await fixture.actor('alice'),fileID),{code:'file_not_found'});
      assert.equal((await request(`/definitions/${media.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).status,200);
      await assert.rejects(storage.get(await fixture.actor('alice'),fileID),{code:'file_not_found'});
      assert.equal((await request(`/definitions/${media.body.id}/export`)).body.error,'template_not_portable');
      const archive=await request(`/definitions/${companyDraft.body.id}/export`,{who:'alice'});
      assert.equal(archive.status,200);assert.equal(archive.body.format,'wolfcrm.training.template.v1');
      const imported=await request('/definitions/import',{who:'alice',method:'POST',body:archive.body});
      assert.equal(imported.status,200);assert.equal(imported.body.draft.scope,'personal');
      assert.equal((await request(`/definitions/${imported.body.id}`)).status,404);
      assert.equal((await request(`/definitions/${imported.body.id}`,{who:'alice'})).status,200);
      assert.equal((await request('/definitions/import',{who:'alice',method:'POST',body:{format:archive.body.format,
        document:media.body.draft}})).body.error,'template_not_portable');
      const row=(await fixture.pool.query('SELECT scope,category,latest_version FROM training_definitions WHERE id=$1',[id])).rows[0];
      assert.deepEqual([row.scope,row.category,row.latest_version],['personal','Window care',1]);
      assert.equal((await fixture.pool.query('SELECT count(*)::int AS count FROM training_versions WHERE definition_id=$1',[id])).rows[0].count,1);
      await fixture.pool.query('UPDATE users SET deleted_at=now() WHERE id=$1',[fixture.ids.owner]);
      assert.notEqual((await request(`/definitions/${id}`)).status,200);
    }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
  });
