import test from 'node:test';import assert from 'node:assert/strict';import {randomUUID} from 'node:crypto';
import {createCommsFixture} from './helpers/comms-fixture.js';import {installNotesSchema} from '../notes/schema.js';import {createNotesWorkspace} from '../notes/pages.js';
test('1,000-block pagination, concurrent writes and retry results beyond first page',{timeout:120000},async()=>{
 const f=await createCommsFixture();try{
  await installNotesSchema(f.pool);await f.pool.query(`UPDATE employee_permissions SET permission_overrides=permission_overrides||'{"notes.view":true}'::jsonb WHERE user_id=$1`,[f.ids.alice]);const owner=await f.actor('owner'),alice=await f.actor('alice'),notes=createNotesWorkspace({pool:f.pool});let page=await notes.create(owner,{title:'Large page',id:randomUUID()});const id=page.page.id;
  await notes.share(owner,id,{expected_revision:1,members:[{user_id:alice.userId,role:'editor'}]});
  const ids=Array.from({length:999},()=>randomUUID());for(let start=0;start<ids.length;start+=100)await notes.editBlocks(owner,id,{client_key:randomUUID(),operations:ids.slice(start,start+100).map((id,i)=>({id,type:'paragraph',position:start+i+1,expected_revision:0,payload:{text:'Block '+(start+i+1)}}))});
  const all=[];let offset=0;do{page=await notes.get(owner,id,{limit:250,offset});all.push(...page.blocks);offset=page.next_offset;}while(offset!==null);assert.equal(all.length,1000);assert.equal(new Set(all.map(b=>b.id)).size,1000);assert.equal(page.block_count,1000);
  const op=(block,text)=>({client_key:randomUUID(),operations:[{...block,payload:{text},expected_revision:block.revision}]});const a=op(all[998],'Writer one'),b=op(all[999],'Writer two');
  const [savedA,savedB]=await Promise.all([notes.editBlocks(owner,id,a),notes.editBlocks(alice,id,b)]);assert.equal(savedA.changed_blocks[0].payload.text,'Writer one');assert.equal(savedB.changed_blocks[0].payload.text,'Writer two');
  const retry=await notes.editBlocks(owner,id,a);assert.equal(retry.changed_blocks[0].payload.text,'Writer one');assert.equal(retry.changed_blocks[0].revision,2);
  const attempts=await Promise.allSettled([notes.editBlocks(owner,id,op(all[500],'Same A')),notes.editBlocks(alice,id,op(all[500],'Same B'))]);assert.equal(attempts.filter(r=>r.status==='fulfilled').length,1);assert.equal(attempts.find(r=>r.status==='rejected').reason.status,409);
  assert.equal((await notes.getBlock(owner,id,all[999].id)).payload.text,'Writer two');
 }finally{await f.close();}
});
test('OCR, filenames and previews never leak through a shared note or search after file access denial',{timeout:120000},async()=>{
 const f=await createCommsFixture();try{
  await installNotesSchema(f.pool);await f.pool.query(`UPDATE employee_permissions SET permission_overrides=permission_overrides||'{"notes.view":true}'::jsonb WHERE user_id=$1`,[f.ids.bob]);const owner=await f.actor('owner'),bob=await f.actor('bob'),notes=createNotesWorkspace({pool:f.pool});
  const asset=await f.asset('owner'),preview=await f.asset('owner','image');let page=await notes.create(owner,{title:'Shared drawing',id:randomUUID()});const block=randomUUID();
  page=await notes.editBlocks(owner,page.page.id,{client_key:randomUUID(),operations:[{id:block,type:'drawing',position:1,expected_revision:0,payload:{asset_id:asset,preview_id:preview,ocr:'PRIVATE OCR SENTINEL'}}]});
  assert.equal(page.changed_blocks[0].payload.preview_id,preview);assert.equal((await notes.list(owner,{search:'PRIVATE OCR SENTINEL'})).pages.length,1);
  await f.pool.query("UPDATE stored_files SET display_name='PRIVATE FILENAME SENTINEL' WHERE id=$1",[asset]);assert.equal((await notes.list(owner,{search:'PRIVATE FILENAME SENTINEL'})).pages.length,1);
  page=await notes.share(owner,page.page.id,{expected_revision:page.page.revision,members:[{user_id:bob.userId,role:'viewer'}]});
  const denied=await notes.getBlock(bob,page.page.id,block);assert.equal(denied.accessible,false);assert.deepEqual(denied.payload,{});assert.equal(JSON.stringify(denied).includes(asset),false);assert.equal((await notes.list(bob,{search:'PRIVATE OCR SENTINEL'})).pages.length,0);
  assert.equal((await notes.list(bob,{search:'PRIVATE FILENAME SENTINEL'})).pages.length,0);
  await f.pool.query("UPDATE stored_files SET visibility='company' WHERE id=ANY($1::uuid[])",[[asset,preview]]);const visible=await notes.getBlock(bob,page.page.id,block);assert.equal(visible.accessible,true);assert.equal(visible.payload.ocr,'PRIVATE OCR SENTINEL');
  await f.pool.query("UPDATE stored_files SET visibility='private' WHERE id=ANY($1::uuid[])",[[asset,preview]]);assert.equal((await notes.getBlock(bob,page.page.id,block)).accessible,false);
  const before=(await f.pool.query('SELECT count(*)::int n FROM stored_files')).rows[0].n;page=await notes.get(owner,page.page.id);await notes.editBlocks(owner,page.page.id,{client_key:randomUUID(),operations:[{id:block,delete:true,expected_revision:1}]});assert.equal((await f.pool.query('SELECT count(*)::int n FROM stored_files')).rows[0].n,before);
 }finally{await f.close();}
});
