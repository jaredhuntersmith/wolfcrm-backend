import test from 'node:test';import assert from 'node:assert/strict';import {randomUUID} from 'node:crypto';
import {createCompanyStorage} from '../employee-access/storage-usage.js';
import {createCommsFixture} from './helpers/comms-fixture.js';import {installNotesSchema} from '../notes/schema.js';
import {installEmployeeAccountSchema} from '../employee-access/schema.js';import {createEmployeeAccountService} from '../employee-access/service.js';
import {installPrivatePurgeSchema,createPrivatePurge} from '../employee-access/purge.js';import {createStorageService} from '../media-storage/service.js';

test('private purge keeps company/participant histories and retries provider deletion before releasing bytes',{timeout:120000},async()=>{
 const f=await createCommsFixture();const {pool,ids,companies}=f;let fail=true;const removed=[];
 try{
  await pool.query('ALTER TABLE users ADD COLUMN deleted_by uuid; ALTER TABLE users ADD COLUMN pre_delete_email text; CREATE TABLE sessions(token text PRIMARY KEY,user_id uuid);');
  await installNotesSchema(pool);await installEmployeeAccountSchema(pool);await installPrivatePurgeSchema(pool);
  const accounts=createEmployeeAccountService({pool}),owner={userId:ids.owner,companyId:companies.a};
  const bucket={abort:async()=>{},remove:async row=>{if(fail)throw Error('provider outage');removed.push(row.object_key);}};
  const storage=createStorageService({pool,bucket}),companyStorage=createCompanyStorage({pool,storage}),purge=createPrivatePurge({pool,storage,bucket});
  const row=async()=>(await pool.query('SELECT * FROM users WHERE id=$1',[ids.alice])).rows[0];
  const change=async action=>accounts.transition(owner,ids.alice,action,{expected_revision:Number((await row()).account_revision)});
  const privateFile=await f.asset(),shared=await f.asset(),protectedFile=await f.asset(),participant=await f.asset(),other=await f.asset('bob');
  const alreadyDeleted=await f.asset();await pool.query("UPDATE stored_files SET cloud_status='deleted',metadata_json='{\"privateCaption\":\"remove me\"}' WHERE id=$1",[alreadyDeleted]);
  for(const id of [privateFile,alreadyDeleted,shared]){
   await pool.query("INSERT INTO storage_access_receipts(id,file_id,user_id,company_id,was_public,file_name) VALUES($1,$2,$3,$4,$5,'Private filename')",[randomUUID(),id,ids.alice,companies.a,id===shared]);
   await pool.query("INSERT INTO storage_activity(id,file_id,actor_user_id,actor_name,company_id,event_type,file_name,byte_size,was_public) VALUES($1,$2,$3,'alice',$4,'uploaded','Private filename',100,$5)",[randomUUID(),id,ids.alice,companies.a,id===shared]);
  }

  await pool.query("UPDATE stored_files SET visibility='company' WHERE id=$1",[shared]);await pool.query("UPDATE stored_files SET source_protected=true,source_scope='training' WHERE id=$1",[protectedFile]);
  const conversation=randomUUID(),message=randomUUID();await pool.query('INSERT INTO conversations(id,company_id,title,created_by) VALUES($1,$2,$3,$4)',[conversation,companies.a,'Retained conversation',ids.alice]);await pool.query('INSERT INTO messages(id,conversation_id,sender_id,body) VALUES($1,$2,$3,$4)',[message,conversation,ids.alice,'Retain this message']);await pool.query('INSERT INTO comms_asset_refs(id,message_id,asset_id,company_id) VALUES($1,$2,$3,$4)',[randomUUID(),message,participant,companies.a]);
  const privateNote=randomUUID(),sharedNote=randomUUID(),child=randomUUID();
  for(const [id,visibility,parent,inherit] of [[privateNote,'private',null,false],[sharedNote,'company',null,false],[child,'private',sharedNote,true]])await pool.query('INSERT INTO comms_notes(id,company_id,creator_id,editor_id,owner_id,client_key,title,body,visibility,parent_id,inherit_access) VALUES($1::uuid,$2,$3,$3,$3,$1::text,$4,$4,$5,$6,$7)',[id,companies.a,ids.alice,'Private or shared content',visibility,parent,inherit]);
  const audio=randomUUID();await pool.query('INSERT INTO notes_audio(id,page_id,company_id,owner_user_id,byte_size,duration,sha256,object_key,ready) VALUES($1,$2,$3,$4,50,1,$5,$6,true)',[audio,privateNote,companies.a,ids.alice,'a'.repeat(64),'notes/test/'+audio]);
  let usage=await companyStorage.usage(owner);assert.equal(usage.totals.tracked_cloud_bytes,550);assert.equal(usage.totals.company_shared_bytes,100);assert.equal(JSON.stringify(usage).includes('PRIVATE-'),false);
  await assert.rejects(companyStorage.usage({userId:ids.admin,companyId:companies.a}),e=>e.status===403);
  await assert.rejects(purge.preview(owner,ids.alice),e=>e.code==='purge_unavailable');await change('disable');usage=await companyStorage.usage(owner);assert.equal(usage.totals.recoverable_private_bytes,150);assert.equal(usage.totals.retained_reference_bytes,200);
  await assert.rejects(purge.preview({userId:ids.bob,companyId:companies.a},ids.alice),e=>e.status===403);
  await assert.rejects(purge.preview({userId:ids.foreign,companyId:companies.b},ids.alice),e=>e.status===404);
  let preview=await purge.preview(owner,ids.alice);assert.equal(preview.private_files,1);assert.equal(preview.private_notes,1);assert.equal(preview.tracked_original_bytes,150);assert.equal(JSON.stringify(preview).includes('Private or shared content'),false);
  await pool.query('UPDATE stored_files SET version=version+1 WHERE id=$1',[privateFile]);
  await assert.rejects(purge.request(owner,ids.alice,{...preview,confirmation:'DELETE PRIVATE DATA'}),e=>e.code==='purge_preview_changed');
  preview=await purge.preview(owner,ids.alice);await purge.request(owner,ids.alice,{...preview,confirmation:'DELETE PRIVATE DATA'});

  for(const id of [privateFile,alreadyDeleted]){
   const file=(await pool.query('SELECT display_name,original_filename,metadata_json FROM stored_files WHERE id=$1',[id])).rows[0];
   assert.deepEqual(file,{display_name:'Deleted file',original_filename:'Deleted file',metadata_json:{}});
   assert.equal((await pool.query('SELECT 1 FROM storage_access_receipts WHERE file_id=$1',[id])).rowCount,0);
   assert.equal((await pool.query('SELECT file_name FROM storage_activity WHERE file_id=$1',[id])).rows[0].file_name,'Deleted file');
  }
  assert.equal((await pool.query('SELECT file_name FROM storage_access_receipts WHERE file_id=$1',[shared])).rows[0].file_name,'Private filename');
  assert.equal((await row()).private_data_state,'purging');usage=await companyStorage.usage(owner);assert.equal(usage.totals.tracked_cloud_bytes,550);await assert.rejects(change('restore'),e=>e.code==='recovery_unavailable');
  await purge.tick();assert.equal((await row()).private_data_state,'purging');assert.equal((await pool.query('SELECT cloud_status FROM stored_files WHERE id=$1',[privateFile])).rows[0].cloud_status,'deleting');
  assert.equal((await pool.query('SELECT body FROM messages WHERE id=$1',[message])).rows[0].body,'Retain this message');
  assert.equal((await pool.query('SELECT purged_at FROM comms_notes WHERE id=$1',[privateNote])).rows[0].purged_at instanceof Date,true);
  assert.equal((await pool.query('SELECT count(*)::int n FROM comms_notes WHERE id=ANY($1::uuid[]) AND purged_at IS NULL',[[sharedNote,child]])).rows[0].n,2);
  assert.equal((await pool.query("SELECT count(*)::int n FROM stored_files WHERE id=ANY($1::uuid[]) AND cloud_status='active'",[[shared,protectedFile,participant,other]])).rows[0].n,4);
  fail=false;await pool.query("UPDATE stored_files SET cleanup_after=now() WHERE id=$1",[privateFile]);await pool.query('UPDATE employee_private_objects SET next_attempt_at=now()');await purge.tick();await purge.tick();
  assert.equal((await row()).private_data_state,'purged');assert.equal((await row()).display_name,'alice');assert.equal((await pool.query('SELECT count(*)::int n FROM notes_audio WHERE id=$1',[audio])).rows[0].n,0);assert.equal(new Set(removed).size,2);usage=await companyStorage.usage(owner);assert.equal(usage.totals.tracked_cloud_bytes,400);assert.equal(usage.accounts.find(a=>a.id===ids.alice).disabled,true);
  await pool.query("UPDATE employee_permissions SET permission_preset='admin',permission_overrides='{\"storage.view_usage\":true}' WHERE user_id=$1",[ids.admin]);
  assert.equal((await companyStorage.usage({userId:ids.admin,companyId:companies.a})).totals.tracked_cloud_bytes,400);await assert.rejects(companyStorage.cleanupFiles({userId:ids.admin,companyId:companies.a}),e=>e.status===403);
  const clean=await companyStorage.cleanupPreview(owner,shared);assert.equal(clean.can_delete,true);await companyStorage.cleanup(owner,shared,{preview_token:clean.preview_token,confirmation:'DELETE COMPANY FILE'});assert.equal((await companyStorage.usage(owner)).totals.tracked_cloud_bytes,300);
 }finally{await f.close();}
});


test('competing restore and private purge commit one complete state without partial deletion',{timeout:120000},async()=>{
 const f=await createCommsFixture();const {pool,ids,companies}=f;
 try{
  await pool.query('ALTER TABLE users ADD COLUMN deleted_by uuid; ALTER TABLE users ADD COLUMN pre_delete_email text; CREATE TABLE sessions(token text PRIMARY KEY,user_id uuid);');
  await installNotesSchema(pool);await installEmployeeAccountSchema(pool);await installPrivatePurgeSchema(pool);
  const service=createEmployeeAccountService({pool}),purge=createPrivatePurge({pool,bucket:null});
  const owner={userId:ids.owner,companyId:companies.a};
  for(const [key,reverse] of [['alice',false],['bob',true]]){
   const id=ids[key],file=await f.asset(key);
   await service.transition(owner,id,'disable',{expected_revision:1});
   const preview=await purge.preview(owner,id);
   const restore=()=>service.transition(owner,id,'restore',{expected_revision:preview.expected_revision});
   const remove=()=>purge.request(owner,id,{...preview,confirmation:'DELETE PRIVATE DATA'});
   const outcomes=await Promise.allSettled(reverse?[remove(),restore()]:[restore(),remove()]);
   assert.equal(outcomes.filter(r=>r.status==='fulfilled').length,1);
   const state=(await pool.query('SELECT private_data_state,deleted_at FROM users WHERE id=$1',[id])).rows[0];
   const cloud=(await pool.query('SELECT cloud_status FROM stored_files WHERE id=$1',[file])).rows[0].cloud_status;
   const jobs=(await pool.query('SELECT user_id FROM employee_private_purge_jobs WHERE user_id=$1 AND data_deleted_at IS NOT NULL',[id])).rowCount;
   if(state.private_data_state==='active'){assert.equal(state.deleted_at,null);assert.equal(cloud,'active');assert.equal(jobs,0);}
   else{assert.equal(state.private_data_state,'purging');assert.ok(state.deleted_at);assert.equal(cloud,'deleting');assert.equal(jobs,1);}
  }
 }finally{await f.close();}
});

test('cloned Notes recordings retain shared object bytes until the last private reference is purged',{timeout:120000},async()=>{
 const f=await createCommsFixture();const {pool,ids,companies}=f;const removed=[];
 try{
  await pool.query('ALTER TABLE users ADD COLUMN deleted_by uuid; ALTER TABLE users ADD COLUMN pre_delete_email text; CREATE TABLE sessions(token text PRIMARY KEY,user_id uuid);');
  await installNotesSchema(pool);await installEmployeeAccountSchema(pool);await installPrivatePurgeSchema(pool);
  const service=createEmployeeAccountService({pool}),owner={userId:ids.owner,companyId:companies.a};
  const purge=createPrivatePurge({pool,bucket:{abort:async()=>{},remove:async row=>removed.push(row.object_key)}}),usage=createCompanyStorage({pool});
  for(const person of ['alice','bob']){
   const page=randomUUID();
   await pool.query("INSERT INTO comms_notes(id,company_id,creator_id,editor_id,owner_id,client_key,title,body,visibility) VALUES($1::uuid,$2,$3,$3,$3,$1::text,'Voice','Private','private')",[page,companies.a,ids[person]]);
   await pool.query("INSERT INTO notes_audio(id,page_id,company_id,owner_user_id,byte_size,duration,sha256,object_key,ready) VALUES($1,$2,$3,$4,75,1,$5,'notes/shared-copy',true)",[randomUUID(),page,companies.a,ids[person],'a'.repeat(64)]);
  }
  assert.equal((await usage.usage(owner)).totals.tracked_cloud_bytes,75);
  for(const person of ['alice','bob']){
   await service.transition(owner,ids[person],'disable',{expected_revision:1});
   const preview=await purge.preview(owner,ids[person]);assert.equal(preview.tracked_original_bytes,person==='alice'?0:75);
   await purge.request(owner,ids[person],{...preview,confirmation:'DELETE PRIVATE DATA'});await purge.tick();
   if(person==='alice'){assert.deepEqual(removed,[]);assert.equal((await pool.query('SELECT id FROM notes_audio WHERE owner_user_id=$1',[ids.bob])).rowCount,1);assert.equal((await usage.usage(owner)).totals.tracked_cloud_bytes,75);}
  }
  assert.deepEqual(removed,['notes/shared-copy']);assert.equal((await usage.usage(owner)).totals.tracked_cloud_bytes,0);
 }finally{await f.close();}
});

test('private Notes exports purge with their source while shared-source exports remain',{timeout:120000},async()=>{
 const f=await createCommsFixture();const {pool,ids,companies}=f;const removed=[];
 try{
  await pool.query('ALTER TABLE users ADD COLUMN deleted_by uuid; ALTER TABLE users ADD COLUMN pre_delete_email text; CREATE TABLE sessions(token text PRIMARY KEY,user_id uuid);');
  await installNotesSchema(pool);await installEmployeeAccountSchema(pool);await installPrivatePurgeSchema(pool);
  const files=[];
  for(const visibility of ['private','company']){
   const page=randomUUID(),file=await f.asset();files.push(file);
   await pool.query("INSERT INTO comms_notes(id,company_id,creator_id,editor_id,owner_id,client_key,title,body,visibility) VALUES($1::uuid,$2,$3,$3,$3,$1::text,'Export source','Content',$4)",[page,companies.a,ids.alice,visibility]);
   await pool.query('UPDATE stored_files SET source_protected=true WHERE id=$1',[file]);
   await pool.query("INSERT INTO comms_asset_provenance(asset_id,company_id,source_type,source_id,context_type) VALUES($1,$2,'note',$3,'note')",[file,companies.a,page]);
  }
  const bucket={abort:async()=>{},remove:async row=>removed.push(row.id)},storage=createStorageService({pool,bucket});
  const service=createEmployeeAccountService({pool}),purge=createPrivatePurge({pool,storage,bucket}),usage=createCompanyStorage({pool,storage}),owner={userId:ids.owner,companyId:companies.a};
  await service.transition(owner,ids.alice,'disable',{expected_revision:1});
  const totals=(await usage.usage(owner)).totals;assert.equal(totals.recoverable_private_bytes,100);assert.equal(totals.retained_reference_bytes,100);
  const preview=await purge.preview(owner,ids.alice);assert.equal(preview.private_files,1);
  await purge.request(owner,ids.alice,{...preview,confirmation:'DELETE PRIVATE DATA'});await purge.tick();
  assert.deepEqual(removed,[files[0]]);assert.equal((await usage.usage(owner)).totals.tracked_cloud_bytes,100);
  assert.equal((await pool.query('SELECT cloud_status FROM stored_files WHERE id=$1',[files[1]])).rows[0].cloud_status,'active');
 }finally{await f.close();}
});


test('permanent purge clears personal preferences and credentials while restore preserves them and company audit identity survives',{timeout:120000},async()=>{
 const f=await createCommsFixture();const {pool,ids,companies}=f;
 try{
  await pool.query(`ALTER TABLE users ADD COLUMN deleted_by uuid; ALTER TABLE users ADD COLUMN pre_delete_email text;
   ALTER TABLE users ADD COLUMN password_hash text; ALTER TABLE users ADD COLUMN tab_preferences jsonb DEFAULT '{}'; ALTER TABLE users ADD COLUMN dashboard_preferences jsonb DEFAULT '{}';
   CREATE TABLE sessions(token text PRIMARY KEY,user_id uuid);
   CREATE TABLE dashboard_dismissals(user_id uuid,company_id uuid,item_type text);
   CREATE TABLE service_plan_review_preferences(user_id uuid,preferences jsonb);
   CREATE TABLE tab_layout_audit(id uuid,company_id uuid,changed_by_user_id uuid,target_type text,target_id text,previous_layout jsonb,new_layout jsonb);
   CREATE TABLE dashboard_layout_audit(LIKE tab_layout_audit);`);
  await installNotesSchema(pool);await installEmployeeAccountSchema(pool);await installPrivatePurgeSchema(pool);
  const service=createEmployeeAccountService({pool}),purge=createPrivatePurge({pool,bucket:null}),owner={userId:ids.owner,companyId:companies.a};
  const state=async key=>(await pool.query('SELECT id,email,display_name,photo_url,password_hash,tab_preferences,dashboard_preferences,account_revision FROM users WHERE id=$1',[ids[key]])).rows[0];
  for(const key of ['alice','bob']){
   await pool.query(`UPDATE users SET photo_url='https://example.invalid/photo',password_hash='synthetic-hash',tab_preferences='{"personal":"tabs"}',dashboard_preferences='{"personal":"layout"}' WHERE id=$1`,[ids[key]]);
   await pool.query("INSERT INTO comms_preferences(user_id,company_id,subject_type,subject_id,settings) VALUES($1,$2,'conversation','personal','{\"draft\":\"private\"}')",[ids[key],companies.a]);
   await pool.query("INSERT INTO dashboard_dismissals VALUES($1,$2,'private-item');",[ids[key],companies.a]);
   await pool.query("INSERT INTO service_plan_review_preferences VALUES($1,'{\"private\":true}')",[ids[key]]);
   for(const table of ['tab_layout_audit','dashboard_layout_audit'])await pool.query(`INSERT INTO ${table} VALUES($1,$2,$3,'employee',$4,'{"private":"before"}','{"private":"after"}')`,[randomUUID(),companies.a,ids.owner,ids[key]]);
  }
  const original=await state('alice'),other=await state('bob');
  await service.transition(owner,ids.alice,'disable',{expected_revision:1});
  await service.transition(owner,ids.alice,'restore',{expected_revision:2});
  assert.deepEqual({...await state('alice'),account_revision:original.account_revision},original);
  await service.transition(owner,ids.alice,'disable',{expected_revision:3});
  const stale=await purge.preview(owner,ids.alice);
  await pool.query(`UPDATE users SET tab_preferences='{"changed":true}' WHERE id=$1`,[ids.alice]);
  await assert.rejects(purge.request(owner,ids.alice,{...stale,confirmation:'DELETE PRIVATE DATA'}),e=>e.code==='purge_preview_changed');
  const preview=await purge.preview(owner,ids.alice);await purge.request(owner,ids.alice,{...preview,confirmation:'DELETE PRIVATE DATA'});await purge.tick();
  assert.deepEqual(await state('alice'),{...original,password_hash:null,tab_preferences:{},dashboard_preferences:{},account_revision:'6'});
  assert.deepEqual(await state('bob'),other);
  for(const table of ['comms_preferences','dashboard_dismissals','service_plan_review_preferences']){
   assert.equal((await pool.query(`SELECT 1 FROM ${table} WHERE user_id=$1`,[ids.alice])).rowCount,0);
   assert.equal((await pool.query(`SELECT 1 FROM ${table} WHERE user_id=$1`,[ids.bob])).rowCount,1);
  }
  for(const table of ['tab_layout_audit','dashboard_layout_audit']){
   const a=(await pool.query(`SELECT * FROM ${table} WHERE target_id=$1`,[ids.alice])).rows[0];
   assert.equal(a.changed_by_user_id,ids.owner);assert.equal(a.company_id,companies.a);assert.deepEqual(a.previous_layout,{});assert.deepEqual(a.new_layout,{});
   assert.deepEqual((await pool.query(`SELECT new_layout FROM ${table} WHERE target_id=$1`,[ids.bob])).rows[0].new_layout,{private:'after'});
  }
 }finally{await f.close();}
});
