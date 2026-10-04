import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import express from 'express';
import pg from 'pg';
import { startLocalPostgres } from './helpers/local-postgres.js';
import { installMediaStorage } from '../media-storage/index.js';
import { PART_SIZE } from '../media-storage/bucket.js';

test('storage privacy and lifecycle against PostgreSQL', {timeout:120000}, async t=>{
 const local=startLocalPostgres(),pool=new pg.Pool(local.config),objects=new Map(),parts=new Map();let server,failDelete=false;
 const company=randomUUID(),otherCompany=randomUUID();
 const actors=Object.fromEntries(['a','b','owner','foreign'].map(key=>[key,{userId:randomUUID(),companyId:key==='foreign'?otherCompany:company,role:['owner','foreign'].includes(key)?'employer':'employee'}]));
 const bucket={begin:async f=>{parts.set(f.id,[]);return 'upload-'+f.id;},part:async(f,n,size)=>{parts.get(f.id)[n-1]={PartNumber:n,Size:size,ETag:'etag'+n};return 'https://example.invalid/part';},parts:async f=>parts.get(f.id)||[],complete:async f=>objects.set(f.id,{ContentLength:Number(f.byte_size),Metadata:{'wolf-file-id':f.id},ETag:'checksum'}),head:async f=>objects.get(f.id)||null,abort:async f=>parts.delete(f.id),remove:async f=>{if(failDelete)throw Error('outage');objects.delete(f.id);},access:async()=> 'https://example.invalid/private'};
 try{
  await pool.query('CREATE TABLE companies(id uuid PRIMARY KEY); CREATE TABLE users(id uuid PRIMARY KEY,email text,display_name text,role text,company_id uuid REFERENCES companies(id),deleted_at timestamptz)');
  await pool.query('INSERT INTO companies VALUES($1),($2)',[company,otherCompany]);
  for(const [key,a] of Object.entries(actors))await pool.query('INSERT INTO users(id,email,display_name,role,company_id) VALUES($1,$2,$2,$3,$4)',[a.userId,key,a.role,a.companyId]);
  const app=express();app.use(express.json());const auth=(req,res,next)=>{const actor=actors[req.headers.authorization];if(!actor)return res.sendStatus(401);Object.assign(req,actor);next();};
  const service=await installMediaStorage({app,pool,authRequired:auth,bucket,env:{STORAGE_DEFAULT_QUOTA_BYTES:String(3*PART_SIZE)},startWorker:false});
  server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});const base=`http://127.0.0.1:${server.address().port}/api/storage`;
  const req=async(path,method='GET',body,actor='a')=>{const r=await fetch(base+path,{method,headers:{Authorization:actor,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});return {status:r.status,data:await r.json()};};
  const upload=async(size=100,filename='Private.mp3')=>{const id=randomUUID();assert.equal((await req('/uploads','POST',{id,byte_size:size,original_filename:filename,mime_type:'audio/mpeg'})).status,200);for(let n=1;n<=Math.max(1,Math.ceil(size/PART_SIZE));n++)assert.equal((await req(`/files/${id}/parts`,'POST',{part_number:n})).status,200);const r=await req(`/files/${id}/complete`,'POST',{});assert.equal(r.status,200,JSON.stringify(r));return r.data;};
  let f;
  await t.test('private direct access, browse, search, state, delete and logs deny employer/peers',async()=>{
   f=await upload();assert.equal(f.cloud_status,'active');assert.equal(f.object_key,undefined);
   for(const actor of ['b','owner','foreign']) {assert.equal((await req(`/files/${f.id}`,'GET',undefined,actor)).status,404);assert.equal((await req(`/files/${f.id}/access`,'POST',{purpose:'stream'},actor)).status,404);assert.equal((await req(`/files/${f.id}/state`,'PUT',{favorite:true},actor)).status,404);assert.equal((await req(`/files/${f.id}`,'DELETE',undefined,actor)).status,404);assert.equal((await req('/files?search=Private','GET',undefined,actor)).data.files.length,0);}
   assert.equal((await req('/activity','GET',undefined,'owner')).data.events.length,0);
  });
  await t.test('public shares one object/charge; only owner edits; stale versions reject',async()=>{
   f=(await req(`/files/${f.id}`,'PATCH',{expected_version:f.version,visibility:'company'})).data;
   for(const actor of ['a','b','owner'])assert.equal((await req('/files?scope=public','GET',undefined,actor)).data.files.length,1);
   assert.equal((await req(`/files/${f.id}`,'GET',undefined,'foreign')).status,404);assert.equal((await req(`/files/${f.id}`,'DELETE',undefined,'b')).status,403);assert.equal((await req(`/files/${f.id}`,'PATCH',{expected_version:f.version,visibility:'private'},'b')).status,403);assert.equal((await req(`/files/${f.id}`,'PATCH',{expected_version:1,display_name:'stale'})).status,409);assert.equal((await req('/usage')).data.used_bytes,100);assert.equal(objects.size,1);
  });
  await t.test('stream never logs download; receipts are user-bound and deduplicated',async()=>{
   await req(`/files/${f.id}/access`,'POST',{purpose:'stream'},'b');assert.equal((await req('/activity?action=download','GET',undefined,'owner')).data.events.length,0);
   const receipt=(await req(`/files/${f.id}/access`,'POST',{purpose:'download'},'b')).data.receipt_id;
   await req(`/files/${f.id}/download-complete`,'POST',{receipt_id:receipt},'a');assert.equal((await req('/activity?action=download','GET',undefined,'owner')).data.events.length,0);
   for(let i=0;i<2;i++)await req(`/files/${f.id}/download-complete`,'POST',{receipt_id:receipt},'b');
   const events=(await req('/activity?action=download','GET',undefined,'owner')).data.events;assert.equal(events.length,1);assert.equal(events[0].actor_user_id,actors.b.userId);assert.equal((await req('/activity','GET',undefined,'b')).status,403);
  });
  await t.test('user favorites/progress isolated; removed owner public files disappear',async()=>{
   await req(`/files/${f.id}/state`,'PUT',{favorite:true,position_seconds:14.5,playback_rate:1.5},'b');assert.equal((await req('/files?scope=favorites','GET',undefined,'b')).data.files.length,1);assert.equal((await req('/files?scope=favorites')).data.files.length,0);
   await pool.query('UPDATE users SET deleted_at=now() WHERE id=$1',[actors.a.userId]);assert.equal((await req(`/files/${f.id}`,'GET',undefined,'owner')).status,404);assert.equal((await req('/files?scope=favorites','GET',undefined,'b')).data.files.length,0);await pool.query('UPDATE users SET deleted_at=NULL WHERE id=$1',[actors.a.userId]);
  });
  await t.test('folders reject cycles/nonempty; private folder search; stable keyset pages',async()=>{
   const folder=(await req('/folders','POST',{name:'Training'})).data,child=(await req('/folders','POST',{name:'Child',parent_folder_id:folder.id})).data;
   assert.equal((await req(`/folders/${folder.id}`,'PATCH',{name:'Cycle',parent_folder_id:child.id,expected_version:1})).status,409);f=(await req(`/files/${f.id}`,'PATCH',{folder_id:folder.id,expected_version:f.version})).data;assert.equal((await req(`/folders/${folder.id}`,'DELETE')).status,409);assert.equal((await req('/files?search=Training')).data.files.length,1);assert.equal((await req('/files?search=Training','GET',undefined,'b')).data.files.length,0);
   await upload(100,'Second.mp3');const page=(await req('/files?limit=1&sort=name')).data;assert.ok(page.next_cursor);const next=(await req('/files?limit=1&sort=name&cursor='+page.next_cursor)).data;assert.equal(next.files.length,1);assert.notEqual(next.files[0].id,page.files[0].id);assert.equal((await req('/files?limit=1&sort=size&cursor='+page.next_cursor)).status,400);
  });
  await t.test('concurrent reservations enforce quota and incomplete provider parts cannot finalize',async()=>{
   const payload=()=>({id:randomUUID(),original_filename:'Large.mp4',byte_size:2*PART_SIZE,mime_type:'video/mp4'});const attempts=await Promise.all([req('/uploads','POST',payload()),req('/uploads','POST',payload())]);assert.deepEqual(attempts.map(r=>r.status).sort(),[200,413]);const id=attempts.find(r=>r.status===200).data.file.id;
   await req(`/files/${id}/parts`,'POST',{part_number:1});assert.equal((await req(`/files/${id}/complete`,'POST',{})).status,409);await req(`/files/${id}`,'DELETE');assert.equal((await req('/usage')).data.reserved_bytes,0);
  });
  await t.test('company departure hides previous public sharing and never leaks subsequent private activity',async()=>{
   const before=(await req('/activity','GET',undefined,'owner')).data.events.length;
   const originalCompany=actors.a.companyId;actors.a.companyId=otherCompany;await pool.query('UPDATE users SET company_id=$2 WHERE id=$1',[actors.a.userId,otherCompany]);
   assert.equal((await req(`/files/${f.id}`)).data.visibility,'private');
   f=(await req(`/files/${f.id}`,'PATCH',{expected_version:f.version,display_name:'Private after departure'})).data;
   const receipt=(await req(`/files/${f.id}/access`,'POST',{purpose:'download'})).data.receipt_id;await req(`/files/${f.id}/download-complete`,'POST',{receipt_id:receipt});
   assert.equal((await req('/activity','GET',undefined,'owner')).data.events.length,before);assert.equal((await req('/activity','GET',undefined,'foreign')).data.events.length,0);
   actors.a.companyId=originalCompany;await pool.query('UPDATE users SET company_id=$2 WHERE id=$1',[actors.a.userId,originalCompany]);
  });
  await t.test('thumbnail access inherits original privacy; quota includes derivative once; replacement cleans old bytes',async()=>{
   const id=randomUUID();assert.equal((await req(`/files/${f.id}/thumbnail`,'POST',{id,byte_size:50},'b')).status,403);
   assert.equal((await req(`/files/${f.id}/thumbnail`,'POST',{id,byte_size:50})).status,200);
   f=(await req(`/files/${f.id}/thumbnail/complete`,'POST',{id})).data;assert.equal(f.thumbnail_id,id);assert.equal((await req('/usage')).data.used_bytes,250);
   assert.equal((await req(`/files/${f.id}/thumbnail`,'GET',undefined,'b')).status,200);
   f=(await req(`/files/${f.id}`,'PATCH',{expected_version:f.version,visibility:'private'})).data;
   assert.equal((await req(`/files/${f.id}/thumbnail`,'GET',undefined,'owner')).status,404);
   assert.equal((await req('/files/verify','POST',{ids:[f.id]},'b')).data.files.length,0);
   const replacement=randomUUID();await req(`/files/${f.id}/thumbnail`,'POST',{id:replacement,byte_size:25});f=(await req(`/files/${f.id}/thumbnail/complete`,'POST',{id:replacement})).data;
   assert.equal((await req('/usage')).data.reserved_bytes,50);await service.cleanup();assert.equal((await req('/usage')).data.used_bytes,225);assert.equal((await req('/usage')).data.reserved_bytes,0);assert.ok(!objects.has(id));
   f=(await req(`/files/${f.id}`,'PATCH',{expected_version:f.version,visibility:'company'})).data;
  });
  await t.test('employer moderation hides immediately; failed delete stays charged until retry',async()=>{
   failDelete=true;assert.equal((await req(`/files/${f.id}`,'DELETE',undefined,'owner')).status,200);assert.equal((await req(`/files/${f.id}`)).status,404);assert.equal((await req('/usage')).data.reserved_bytes,125);assert.ok(objects.has(f.id));failDelete=false;await pool.query('UPDATE stored_files SET cleanup_after=now() WHERE id=$1',[f.id]);await service.cleanup();assert.equal((await req('/usage')).data.reserved_bytes,0);assert.ok(!objects.has(f.id));
  });
  await t.test('empty originals remain uploadable; audit search and folder replay remain scoped',async()=>{
   const empty=await upload(0,'Empty.txt');assert.equal(empty.byte_size,0);assert.equal(empty.cloud_status,'active');
   const id=randomUUID(),body={id,name:'Replay folder'};const one=(await req('/folders','POST',body)).data;const two=(await req('/folders','POST',body)).data;assert.equal(one.id,two.id);assert.equal((await req('/folders','POST',body,'b')).status,404);
   assert.equal((await req('/activity?search=nonexistent','GET',undefined,'owner')).data.events.length,0);
  });
  await t.test('delete-everywhere tombstones reach only the owner; moderation never erases owner offline copies',async()=>{
   const owned=await upload(1,'Delete all.txt');await req(`/files/${owned.id}?everywhere=true`,'DELETE');
   assert.equal((await req('/files/verify','POST',{ids:[owned.id]})).data.deletions[0].delete_everywhere,true);
   assert.equal((await req('/files/verify','POST',{ids:[owned.id]},'owner')).data.deletions.length,0);
   let shared=await upload(1,'Moderated.txt');shared=(await req(`/files/${shared.id}`,'PATCH',{expected_version:shared.version,visibility:'company'})).data;await req(`/files/${shared.id}?everywhere=true`,'DELETE',undefined,'owner');
   assert.equal((await req('/files/verify','POST',{ids:[shared.id]})).data.deletions[0].delete_everywhere,false);
  });
  await t.test('duplicate start/finalize charge once; no upload URLs after finalization; expired cleanup',async()=>{
   const id=randomUUID(),body={id,original_filename:'retry.zip',mime_type:'application/zip',byte_size:10};for(let i=0;i<2;i++)assert.equal((await req('/uploads','POST',body)).status,200);await req(`/files/${id}/parts`,'POST',{part_number:1});for(let i=0;i<2;i++)assert.equal((await req(`/files/${id}/complete`,'POST',{})).status,200);assert.equal((await req(`/files/${id}/parts`,'POST',{part_number:1})).status,404);
   const pending=randomUUID();await req('/uploads','POST',{...body,id:pending});await pool.query("UPDATE stored_files SET upload_expires_at=now()-interval '1 day' WHERE id=$1",[pending]);await service.cleanup();assert.equal((await req('/usage')).data.reserved_bytes,0);
  });
 }finally{await new Promise(r=>server?server.close(r):r());await pool.end();local.stop();}
});
