import test from 'node:test';import assert from 'node:assert/strict';import {randomUUID} from 'node:crypto';
import {createCommsFixture} from './helpers/comms-fixture.js';import {installNotesSchema} from '../notes/schema.js';import {createNotesWorkspace} from '../notes/pages.js';import {createNotesAudio} from '../notes/audio.js';import {createNotesCollections} from '../notes/collections.js';
test('note-owned voice uploads: immutable retries, page ACL, template copies, no Media Storage',{timeout:120000},async()=>{
 const f=await createCommsFixture();try{
  await installNotesSchema(f.pool);await installNotesSchema(f.pool);
  const owner=await f.actor('owner'),foreign=await f.actor('foreign'),notes=createNotesWorkspace({pool:f.pool});
  let page=await notes.create(owner,{id:randomUUID(),title:'Voice'});const other=await notes.create(owner,{id:randomUUID(),title:'Other'});
  const objects=new Map(),uploads=new Map();let begins=0,completes=0;
  const bucket={begin:async row=>{begins++;uploads.set(row.id,[{PartNumber:1,Size:Number(row.byte_size),ETag:'test'}]);return row.id;},part:async()=> 'https://example.invalid/part',parts:async row=>{if(!uploads.has(row.id)){const error=new Error('expired upload');error.name='NoSuchUpload';throw error;}return uploads.get(row.id);},head:async row=>objects.get(row.object_key),complete:async row=>{completes++;objects.set(row.object_key,{ContentLength:Number(row.byte_size)});},access:async()=> 'https://example.invalid/voice'};
  const audio=createNotesAudio({pool:f.pool,bucket}),id=randomUUID(),body={id,byte_size:400,duration:2,sha256:'a'.repeat(64)};
  assert.equal((await audio.reserve(owner,page.page.id,body)).ready,false);await audio.reserve(owner,page.page.id,body);assert.equal(begins,1);
  uploads.delete(id);await audio.reserve(owner,page.page.id,body);assert.equal(begins,2,'expired multipart upload restarts under the same recording identity');
  await assert.rejects(audio.reserve(owner,page.page.id,{...body,sha256:'b'.repeat(64)}),e=>e.status===409);
  await assert.rejects(audio.reserve(foreign,page.page.id,body),e=>e.status===404);
  await assert.rejects(audio.part(owner,other.page.id,id,1),e=>e.status===404);await assert.rejects(audio.part(owner,page.page.id,id,2),e=>e.status===400);
  assert.ok((await audio.part(owner,page.page.id,id,1)).url);
  assert.equal((await audio.complete(owner,page.page.id,id)).ready,true);await audio.complete(owner,page.page.id,id);assert.equal(completes,1);
  const recovered=randomUUID();await audio.reserve(owner,page.page.id,{...body,id:recovered});
  const stored=(await f.pool.query('SELECT object_key FROM notes_audio WHERE id=$1',[recovered])).rows[0];objects.set(stored.object_key,{ContentLength:400});uploads.delete(recovered);
  assert.equal((await audio.reserve(owner,page.page.id,{...body,id:recovered})).ready,true,'object completion before a lost database acknowledgment is recovered without another upload');
  const block={id:randomUUID(),type:'audio',position:1,expected_revision:0,payload:{recording_id:id}};
  page=await notes.editBlocks(owner,page.page.id,{client_key:randomUUID(),operations:[block]});assert.equal(page.blocks.find(b=>b.id===block.id).recording.duration,2);
  assert.ok((await audio.access(owner,page.page.id,id)).url);await assert.rejects(audio.access(foreign,page.page.id,id),e=>e.status===404);
  await assert.rejects(notes.editBlocks(owner,other.page.id,{client_key:randomUUID(),operations:[{...block,id:randomUUID()}]}),e=>e.status===404);
  assert.equal((await f.pool.query('SELECT count(*)::int AS count FROM stored_files WHERE id=$1',[id])).rows[0].count,0);
  const collections=createNotesCollections({pool:f.pool,notes}),template=await collections.saveTemplate(owner,{page_id:page.page.id,title:'Voice template'});
  const copy=await collections.instantiate(owner,template.id,{id:randomUUID()}),cloned=await notes.get(owner,copy.id),voice=cloned.blocks.find(b=>b.type==='audio');
  assert.ok(voice.accessible);assert.notEqual(voice.payload.recording_id,id);assert.equal((await audio.access(owner,copy.id,voice.payload.recording_id)).duration,2);
  await notes.metadata(owner,page.page.id,{expected_revision:page.page.revision,trashed:true});await assert.rejects(audio.access(owner,page.page.id,id),e=>e.status===404);
 }finally{await f.close();}
});
test('main notes hide children and pin before pagination; Favorites is accessible',{timeout:120000},async()=>{
 const f=await createCommsFixture();try{
  await installNotesSchema(f.pool);const actor=await f.actor('owner'),notes=createNotesWorkspace({pool:f.pool});
  const root=await notes.create(actor,{id:randomUUID(),title:'Root'}),child=await notes.create(actor,{id:randomUUID(),title:'Child',parent_id:root.page.id}),recent=await notes.create(actor,{id:randomUUID(),title:'Recent'});
  await Promise.all([notes.personal(actor,root.page.id,{pinned:true}),notes.personal(actor,root.page.id,{favorite:true}),notes.personal(actor,root.page.id,{opened:true})]);assert.equal((await notes.list(actor,{main:'true',limit:'1'})).pages[0].id,root.page.id);
  const all=await notes.list(actor,{main:'true'});assert.ok(!all.pages.some(p=>p.id===child.page.id));assert.ok(all.pages.some(p=>p.id===recent.page.id));
  assert.deepEqual((await notes.list(actor,{scope:'favorites',main:'true'})).pages.map(p=>p.id),[root.page.id]);assert.equal((await notes.list(actor,{parent_id:root.page.id})).pages[0].id,child.page.id);
 }finally{await f.close();}
});
