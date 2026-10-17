import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installNotesSchema} from '../notes/schema.js';
import {createNotesWorkspace} from '../notes/pages.js';
import {createNotesCollections} from '../notes/collections.js';
import {noteAudience} from '../notes/events.js';

test('Nested notes have unbounded acyclic depth and keep inherited company permissions', {timeout:120000}, async()=>{
 const f=await createCommsFixture();
 try {
  await installNotesSchema(f.pool);
  await f.pool.query("UPDATE employee_permissions SET permission_overrides=permission_overrides||'{\"notes.view\":true}' WHERE user_id=$1",[f.ids.bob]);
  const owner=await f.actor('owner'),bob=await f.actor('bob'),foreign=await f.actor('foreign'),notes=createNotesWorkspace({pool:f.pool});
  let root=await notes.create(owner,{title:'Root'}),parent=root.page.id;
  root=await notes.share(owner,parent,{expected_revision:root.page.revision,members:[{user_id:f.ids.bob,role:'viewer'}]});
  for(let i=0;i<40;i++)parent=(await notes.create(owner,{parent_id:parent,title:'Level '+(i+1)})).page.id;
  assert.equal((await notes.get(bob,parent)).page.access_role,1);
  assert.equal((await notes.get(bob,parent)).page.is_shared,true);
  assert.ok((await noteAudience(f.pool,owner,parent)).includes(f.ids.bob));
  const collections=createNotesCollections({pool:f.pool,notes});
  const template=await collections.saveTemplate(owner,{page_id:root.page.id,title:'Deep template'});
  const clone=await collections.instantiate(owner,template.id,{id:randomUUID()});
  let cloned=clone.id;
  for(let i=0;i<40;i++){const result=await notes.list(owner,{parent_id:cloned});assert.equal(result.pages.length,1);cloned=result.pages[0].id;}
  assert.equal((await notes.get(owner,cloned)).page.title,'Level 40');
  await assert.rejects(notes.get(foreign,parent),e=>e.status===404);
  await assert.rejects(notes.metadata(owner,root.page.id,{parent_id:parent,expected_revision:root.page.revision}),e=>e.code==='invalid_page_parent'||e.status===400);
  await notes.share(owner,root.page.id,{expected_revision:root.page.revision,members:[]});
  await assert.rejects(notes.get(bob,parent),e=>e.status===404);
  assert.ok(!(await noteAudience(f.pool,owner,parent)).includes(f.ids.bob));
 } finally { await f.close(); }
});

test('Child buttons survive bulk edits and history; only confirmed trash removes them', {timeout:120000},async()=>{
 const f=await createCommsFixture();
 try {
  await installNotesSchema(f.pool);const owner=await f.actor('owner'),notes=createNotesWorkspace({pool:f.pool});
  let parent=await notes.create(owner,{title:'Parent'}),child=await notes.create(owner,{parent_id:parent.page.id,title:'Custom title'});
  const originalVersion=parent.page.revision,link={id:randomUUID(),type:'child_page',position:1,payload:{target_id:child.page.id},expected_revision:0};
  parent=await notes.editBlocks(owner,parent.page.id,{client_key:randomUUID(),operations:[link]});
  assert.equal(parent.blocks.find(b=>b.type==='child_page').card.preview,'');
  child=await notes.editBlocks(owner,child.page.id,{client_key:randomUUID(),operations:[{...child.blocks[0],expected_revision:1,payload:{text:'\n  Opening line\nSecond line'}}]});
  parent=await notes.get(owner,parent.page.id);assert.equal(parent.blocks.find(b=>b.type==='child_page').card.preview,'Opening line');
  const collections=createNotesCollections({pool:f.pool,notes});
  const template=await collections.saveTemplate(owner,{page_id:parent.page.id,title:'Inline template'});
  const clone=await collections.instantiate(owner,template.id,{id:randomUUID()});
  const cloned=await notes.get(owner,clone.id),clonedChild=cloned.blocks.find(b=>b.type==='child_page').payload.target_id;
  assert.notEqual(clonedChild,child.page.id);assert.equal((await notes.get(owner,clonedChild)).page.parent_id,clone.id);
  const current=parent.blocks.find(b=>b.id===link.id);
  for(const operation of [{id:link.id,delete:true,expected_revision:current.revision},{...current,type:'paragraph',payload:{text:'replace'},expected_revision:current.revision},{...current,payload:{target_id:parent.page.id},expected_revision:current.revision}]) {
   await assert.rejects(notes.editBlocks(owner,parent.page.id,{client_key:randomUUID(),operations:[operation]}),e=>e.status===409);
  }
  await assert.rejects(notes.editBlocks(owner,parent.page.id,{client_key:randomUUID(),operations:[{...link,id:randomUUID()}]}),e=>e.status===409);
  const moved=await notes.editBlocks(owner,parent.page.id,{client_key:randomUUID(),operations:[{...current,position:-1,expected_revision:current.revision}]});
  assert.equal(moved.blocks[0].id,link.id);
  parent=await notes.restore(owner,parent.page.id,{expected_revision:moved.page.revision,revision:originalVersion});
  assert.ok(parent.blocks.some(b=>b.id===link.id));
  await assert.rejects(notes.metadata(owner,child.page.id,{expected_revision:child.page.revision,trashed:true}),e=>e.status===409);
  child=await notes.metadata(owner,child.page.id,{expected_revision:child.page.revision,trashed:true,confirmed:true});
  parent=await notes.get(owner,parent.page.id);assert.ok(!parent.blocks.some(b=>b.id===link.id));
  const latest=await notes.versions(owner,parent.page.id);
  parent=await notes.restore(owner,parent.page.id,{expected_revision:parent.page.revision,revision:latest.versions[0].revision});
  assert.ok(!parent.blocks.some(b=>b.id===link.id));
  await notes.metadata(owner,child.page.id,{expected_revision:child.page.revision,trashed:false});
  parent=await notes.get(owner,parent.page.id);assert.ok(parent.blocks.some(b=>b.id===link.id));
  const restored=await notes.get(owner,child.page.id);
  assert.equal(restored.blocks[0].payload.text,'\n  Opening line\nSecond line');
  await notes.metadata(owner,child.page.id,{expected_revision:restored.page.revision,parent_id:null,inherit_access:false});
  parent=await notes.get(owner,parent.page.id);assert.equal(parent.blocks.find(b=>b.id===link.id).type,'page_link');
  assert.equal((await notes.get(owner,child.page.id)).page.parent_id,null);
 } finally { await f.close(); }
});
