import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installNotesSchema} from '../notes/schema.js';
import {installEmployeeAccountSchema} from '../employee-access/schema.js';
import {createEmployeeAccountService} from '../employee-access/service.js';
import {installPrivatePurgeSchema,createPrivatePurge} from '../employee-access/purge.js';
import {createCompanyStorage} from '../employee-access/storage-usage.js';
import {createConversationService} from '../company-comms/messages.js';

async function setup(f){
 await f.pool.query('ALTER TABLE users ADD COLUMN deleted_by uuid; ALTER TABLE users ADD COLUMN pre_delete_email text; CREATE TABLE sessions(token text PRIMARY KEY,user_id uuid);');
 await installNotesSchema(f.pool);await installEmployeeAccountSchema(f.pool);await installPrivatePurgeSchema(f.pool);
}
function gate(){let release;const promise=new Promise(resolve=>{release=resolve;});return {promise,release};}
function pausedPool(pool,match){
 const entered=gate(),resume=gate();let pid;
 return {entered,resume,get pid(){return pid;},pool:{query:(...args)=>pool.query(...args),connect:async()=>{
  const db=await pool.connect();pid=(await db.query('SELECT pg_backend_pid() pid')).rows[0].pid;
  return {release:()=>db.release(),query:async(...args)=>{const result=await db.query(...args);if(match(args[0])){entered.release();await resume.promise;}return result;}};
 }}};
}
async function waitForLock(pool,pid){
 for(let i=0;i<200;i++){
  if((await pool.query("SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock'",[pid])).rowCount)return;
  await delay(10);
 }
 assert.fail('Competing transaction did not wait on the reference boundary');
}

test('Notes preview, database properties and retained versions protect stored files through private purge and company cleanup',{timeout:120000},async()=>{
 const f=await createCommsFixture(),{pool,ids,companies}=f;
 try{
  await setup(f);
  const owner={userId:ids.owner,companyId:companies.a};
  const accounts=createEmployeeAccountService({pool}),purge=createPrivatePurge({pool,bucket:null}),usage=createCompanyStorage({pool,storage:{cleanup:async()=>{}}});
  const retained=[],privateFiles=[];
  for(const visibility of ['private','company']){
   const note=randomUUID(),row=randomUUID();
   for(const [id,parent] of [[note,null],[row,note]])await pool.query("INSERT INTO comms_notes(id,company_id,creator_id,editor_id,owner_id,client_key,title,visibility,parent_id,inherit_access) VALUES($1::uuid,$2,$3,$3,$3,$1::text,'Retained source',$4,$5,$6)",[id,companies.a,ids.alice,visibility,parent,!!parent]);
   const files=await Promise.all(Array.from({length:7},()=>f.asset()));
   (visibility==='private'?privateFiles:retained).push(...files);
   await pool.query("INSERT INTO notes_blocks(id,page_id,type,payload,creator_id,editor_id) VALUES($1,$2,'drawing',$3,$4,$4)",[randomUUID(),note,JSON.stringify({asset_id:files[0],preview_id:files[1]}),ids.alice]);
   // No live column: retired property values remain available to restored versions.
   await pool.query("INSERT INTO notes_database_schemas(page_id,columns,views) VALUES($1,'[]','[]')",[note]);
   await pool.query('INSERT INTO notes_database_rows(id,database_id,values) VALUES($1,$2,$3)',[row,note,JSON.stringify({retired_file:files[2]})]);
   await pool.query('INSERT INTO notes_versions(page_id,revision,actor_id,snapshot) VALUES($1,1,$2,$3)',[note,ids.alice,JSON.stringify({page:{cover_id:files[3]},blocks:[{payload:{preview_id:files[4]}}],row_properties:{values:{old:files[5]}}})]);
   await pool.query("INSERT INTO comms_note_versions(note_id,revision,title,body,asset_ids,source_refs,editor_id,created_at) VALUES($1,2,'History','', $2,'[]',$3,now())",[note,JSON.stringify([files[6]]),ids.alice]);
  }
  await accounts.transition(owner,ids.alice,'disable',{expected_revision:1});
  const totals=(await usage.usage(owner)).totals;assert.equal(totals.retained_reference_bytes,700);assert.equal(totals.recoverable_private_bytes,700);
  const preview=await purge.preview(owner,ids.alice);assert.equal(preview.private_files,7);assert.equal(preview.private_notes,2);
  await purge.request(owner,ids.alice,{...preview,confirmation:'DELETE PRIVATE DATA'});
  const states=(await pool.query('SELECT id,cloud_status FROM stored_files')).rows;
  for(const id of privateFiles)assert.equal(states.find(r=>r.id===id).cloud_status,'deleting');
  for(const id of retained){
   assert.equal(states.find(r=>r.id===id).cloud_status,'active');
   await pool.query("UPDATE stored_files SET visibility='company' WHERE id=$1",[id]);
   assert.equal((await usage.cleanupPreview(owner,id)).can_delete,false);
   await assert.rejects(usage.cleanup(owner,id,{confirmation:'DELETE COMPANY FILE',preview_token:'stale'}),e=>e.code==='file_referenced');
  }
 }finally{await f.close();}
});

test('message attachment and company cleanup serialize in both orders without deleting newly retained bytes',{timeout:120000},async()=>{
 const f=await createCommsFixture(),{pool,ids,companies}=f;let writer,cleaner;
 try{
  await setup(f);const owner={userId:ids.owner,companyId:companies.a},alice=await f.actor('alice');
  const ordinary=createConversationService({pool}),room=await ordinary.create(alice,{client_key:randomUUID(),member_ids:[ids.bob]});
  for(const attachFirst of [true,false]){
   const file=await f.asset();await pool.query("UPDATE stored_files SET visibility='company' WHERE id=$1",[file]);
   writer=pausedPool(pool,sql=>sql.includes('f.id=ANY($3::uuid[])'));
   cleaner=pausedPool(pool,sql=>!attachFirst&&sql.startsWith("UPDATE stored_files SET cloud_status='deleting'"));
   const messages=createConversationService({pool:writer.pool}),storage=createCompanyStorage({pool:cleaner.pool,storage:{cleanup:async()=>{}}});
   const preview=await storage.cleanupPreview(owner,file);
   const send=()=>messages.send(alice,room.id,{client_key:randomUUID(),asset_ids:[file]});
   const cleanup=()=>storage.cleanup(owner,file,{preview_token:preview.preview_token,confirmation:'DELETE COMPANY FILE'});
   if(attachFirst){
    const sending=send();await writer.entered.promise;
    const deleting=cleanup().then(()=>({ok:true}),error=>({error}));
    while(!cleaner.pid)await delay(10);await waitForLock(pool,cleaner.pid);
    writer.resume.release();const message=await sending;const result=await deleting;
    assert.equal(result.error?.code,'file_referenced');
    assert.equal((await pool.query('SELECT asset_id FROM comms_asset_refs WHERE message_id=$1',[message.id])).rows[0].asset_id,file);
    assert.equal((await pool.query('SELECT cloud_status FROM stored_files WHERE id=$1',[file])).rows[0].cloud_status,'active');
   }else{
    const deleting=cleanup();await cleaner.entered.promise;
    const sending=send().then(()=>({ok:true}),error=>({error}));
    while(!writer.pid)await delay(10);await waitForLock(pool,writer.pid);
    cleaner.resume.release();await deleting;writer.resume.release();const result=await sending;
    assert.equal(result.error?.code,'attachment_unavailable');
    assert.equal((await pool.query('SELECT 1 FROM comms_asset_refs WHERE asset_id=$1',[file])).rowCount,0);
   }
  }
 }finally{writer?.resume.release();cleaner?.resume.release();await f.close();}
});

test('queued conversation attachments and retained workflow submissions block company file cleanup',{timeout:120000},async()=>{
 const f=await createCommsFixture(),{pool,ids,companies}=f;
 try{
  await setup(f);const owner={userId:ids.owner,companyId:companies.a},alice=await f.actor('alice');
  const messages=createConversationService({pool}),room=await messages.create(alice,{client_key:randomUUID(),member_ids:[ids.bob]});
  const files=await Promise.all([f.asset(),f.asset()]);await pool.query("UPDATE stored_files SET visibility='company' WHERE id=ANY($1::uuid[])",[files]);
  await pool.query("INSERT INTO comms_scheduled_messages(id,company_id,conversation_id,sender_id,client_key,payload,send_at) VALUES($1::uuid,$2,$3,$4,$1::uuid::text,$5,now()+interval '1 day')",[randomUUID(),companies.a,room.id,ids.alice,JSON.stringify({asset_ids:[files[0]]})]);
  const workflow=randomUUID();await pool.query("INSERT INTO comms_workflows(id,company_id,conversation_id,creator_id,name,definition) VALUES($1,$2,$3,$4,'Retained workflow','{}')",[workflow,companies.a,room.id,ids.alice]);
  await pool.query("INSERT INTO comms_workflow_runs(id,workflow_id,company_id,requester_id,client_key,definition_revision,fields,asset_ids,state) VALUES($1::uuid,$2,$3,$4,$1::uuid::text,1,'{}',$5,'pending')",[randomUUID(),workflow,companies.a,ids.alice,JSON.stringify([files[1]])]);
  const storage=createCompanyStorage({pool,storage:{cleanup:async()=>{}}});
  for(const id of files)assert.equal((await storage.cleanupPreview(owner,id)).can_delete,false);
  await pool.query("UPDATE comms_scheduled_messages SET status='canceled'");
  assert.equal((await storage.cleanupPreview(owner,files[0])).can_delete,true);
  assert.equal((await storage.cleanupPreview(owner,files[1])).can_delete,false);
 }finally{await f.close();}
});
