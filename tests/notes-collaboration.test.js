import {createNotesActivity} from '../notes/activity.js';
import test from 'node:test';import assert from 'node:assert/strict';import {randomUUID} from 'node:crypto';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installNotesSchema} from '../notes/schema.js';import {createNotesWorkspace} from '../notes/pages.js';import {createNotesCollaboration} from '../notes/collaboration.js';
import {installNotificationsSchema,createNotifications} from '../company-comms/notifications.js';import {hydrateSources} from '../company-comms/sources.js';
import {createNotes} from '../company-comms/notes.js';import {createConversationService} from '../company-comms/messages.js';
test('comment roles, mentions, reply ownership, revision conflicts, presence and revocation',{timeout:120000},async()=>{
 const f=await createCommsFixture();try{
  await installNotesSchema(f.pool);await installNotificationsSchema(f.pool);
  for(const who of ['alice','bob','carol'])await f.pool.query(`UPDATE employee_permissions SET permission_overrides=permission_overrides||'{"notes.view":true,"notes.create":true,"notes.share":true}'::jsonb WHERE user_id=$1`,[f.ids[who]]);
  const [owner,alice,bob,carol]=await Promise.all(['owner','alice','bob','carol'].map(f.actor));const notifications=createNotifications({pool:f.pool}),notes=createNotesWorkspace({pool:f.pool,notifications}),collab=createNotesCollaboration({pool:f.pool,notifications});
  let page=await notes.create(alice,{title:'Confidential working note',id:randomUUID()});const id=page.page.id;
  page=await notes.share(alice,id,{expected_revision:page.page.revision,members:[{user_id:bob.userId,role:'commenter'},{user_id:carol.userId,role:'viewer'}]});
  assert.equal((await notifications.list(bob)).unread_count,1);assert.equal((await notifications.list(owner)).unread_count,0);
  const mentionBody={client_key:randomUUID(),operations:[{...page.blocks[0],expected_revision:1,payload:{text:'Please review @Bob',mentions:[{user_id:bob.userId,label:'Bob'}]}}]};
  page=await notes.editBlocks(alice,id,mentionBody);await notes.editBlocks(alice,id,mentionBody);
  assert.equal((await notifications.list(bob)).notifications.filter(n=>n.kind==='notes.mention').length,1);
  await assert.rejects(notes.editBlocks(alice,id,{client_key:randomUUID(),operations:[{...page.blocks[0],expected_revision:page.blocks[0].revision,payload:{text:'Hidden @Owner',mentions:[{user_id:owner.userId,label:'Owner'}]}}]}),e=>e.status===404);

  await assert.rejects(collab.save(carol,id,null,{body:'No',id:randomUUID()}),e=>e.status===403);
  await assert.rejects(collab.save(bob,id,null,{body:'No share escalation',mentions:[owner.userId]}),e=>e.status===404);
  await assert.rejects(collab.save(bob,id,null,{body:'Foreign',mentions:[f.ids.foreign]}),e=>e.status===403);
  const activity=createNotesActivity({pool:f.pool});await assert.rejects(activity.list(owner,id),e=>e.status===404);
  const comment=await collab.save(bob,id,null,{id:randomUUID(),body:'Please review',mentions:[alice.userId]});
  const duplicate=await collab.save(bob,id,null,{id:comment.id,body:'retry'});assert.equal(duplicate.revision,1);
  const reply=await collab.save(alice,id,null,{id:randomUUID(),body:'Reviewed',parent_id:comment.id});
  await assert.rejects(collab.save(alice,id,null,{body:'Too deep',parent_id:reply.id}),e=>e.status===404);
  await assert.rejects(collab.save(alice,id,comment.id,{body:'Cannot rewrite another author',expected_revision:1}),e=>e.status===403);
  await collab.save(alice,id,comment.id,{resolved:true,expected_revision:1});await assert.rejects(collab.save(bob,id,comment.id,{body:'Stale',expected_revision:1}),e=>e.status===409);
  assert.equal((await collab.list(bob,id)).comments.length,2);const audit=await activity.list(alice,id);assert.ok(audit.entries.some(e=>e.kind==='sharing_updated'));assert.ok(audit.entries.some(e=>e.kind==='comment_resolved'));assert.equal(JSON.stringify(audit).includes('Please review'),false);
  await collab.presence(bob,id,{block_id:page.blocks[0].id});assert.equal((await collab.presence(alice,id)).members.length,2);
  const card=(await hydrateSources(f.pool,bob,[{source_type:'note',source_id:id,id:'x'}])).get('x');assert.equal(card.title,'Confidential working note');
  page=await notes.share(alice,id,{expected_revision:page.page.revision,members:[]});
  assert.equal((await notifications.list(bob)).unread_count,0);assert.ok((await notifications.list(bob)).notifications.every(n=>n.accessible===false&&n.body==='No Access'));
  assert.equal((await notifications.list(bob,{search:'note'})).notifications.length,0);
  assert.equal((await hydrateSources(f.pool,bob,[{source_type:'note',source_id:id,id:'x'}])).get('x').accessible,false);
  assert.equal((await collab.presence(alice,id)).members.length,1);await assert.rejects(collab.list(bob,id),e=>e.status===404);await assert.rejects(activity.list(bob,id),e=>e.status===404);
 }finally{await f.close();}
});
test('legacy versions retain file and CRM references and restore canonical blocks',{timeout:120000},async()=>{
 const f=await createCommsFixture();try{
  await installNotesSchema(f.pool);const owner=await f.actor('owner'),notes=createNotesWorkspace({pool:f.pool}),legacy=createNotes({pool:f.pool}),conversations=createConversationService({pool:f.pool});
  const room=await conversations.create(owner,{client_key:randomUUID(),member_ids:[f.ids.alice]});const asset=await f.asset('owner');const contact=randomUUID();await f.pool.query('INSERT INTO contacts(id,company_id,name) VALUES($1,$2,$3)',[contact,f.companies.a,'Original Customer']);
  let old=await legacy.save(owner,room.id,null,{client_key:randomUUID(),title:'Old Title',body:'Old Body',asset_ids:[asset],source_refs:[{source_type:'contact',source_id:contact}]});
  old=await legacy.save(owner,null,old.id,{expected_revision:old.revision,title:'New Title',body:'New Body',asset_ids:[],source_refs:[]});
  const revisions=await notes.versions(owner,old.id);assert.equal(revisions.versions.length,1);const historical=await notes.version(owner,old.id,1);assert.equal(historical.blocks.length,3);assert.equal(historical.blocks[1].attachment.id,asset);assert.equal(historical.blocks[2].card.title,'Original Customer');
  const restored=await notes.restore(owner,old.id,{expected_revision:old.revision,revision:1});assert.equal(restored.page.title,'Old Title');assert.equal(restored.blocks.length,3);assert.equal(restored.blocks[0].payload.text,'Old Body');
  await f.pool.query('UPDATE contacts SET deleted_at=now() WHERE id=$1',[contact]);const revoked=await notes.version(owner,old.id,1);assert.equal(revoked.blocks[2].accessible,false);assert.equal(JSON.stringify(revoked).includes('Original Customer'),false);
 }finally{await f.close();}
});
test('Notes change feed follows inherited access and sends anonymous revocation invalidations',{timeout:120000},async()=>{
 const f=await createCommsFixture();try{
  await installNotesSchema(f.pool);
  for(const who of ['alice','bob','carol'])await f.pool.query(`UPDATE employee_permissions SET permission_overrides=permission_overrides||'{"notes.view":true,"notes.create":true,"notes.share":true}'::jsonb WHERE user_id=$1`,[f.ids[who]]);
  const alice=await f.actor('alice'),notes=createNotesWorkspace({pool:f.pool}),collab=createNotesCollaboration({pool:f.pool});
  let parent=await notes.create(alice,{title:'Private lineage'});
  parent=await notes.share(alice,parent.page.id,{expected_revision:parent.page.revision,members:[{user_id:f.ids.bob,role:'commenter'}]});
  const child=await notes.create(alice,{title:'Inherited',parent_id:parent.page.id});
  const restricted=await notes.create(alice,{title:'Restricted',parent_id:parent.page.id,inherit_access:false});
  await f.pool.query('DELETE FROM comms_events');
  await notes.editBlocks(alice,child.page.id,{client_key:randomUUID(),operations:[{...child.blocks[0],expected_revision:1,payload:{text:'Never broadcast this'}}]});
  await collab.save(alice,child.page.id,null,{body:'Private comment'});
  const events=(await f.pool.query('SELECT recipient_id,event_type,entity_id,payload FROM comms_events ORDER BY id')).rows;
  assert.equal(events.length,4);assert.deepEqual(new Set(events.map(e=>e.recipient_id)),new Set([alice.userId,f.ids.bob]));assert.ok(events.every(e=>e.entity_id===child.page.id&&JSON.stringify(e.payload)==='{}'));assert.ok(events.some(e=>e.event_type==='notes.comment.changed'));
  await f.pool.query('DELETE FROM comms_events');
  await notes.editBlocks(alice,restricted.page.id,{client_key:randomUUID(),operations:[{...restricted.blocks[0],expected_revision:1,payload:{text:'Only Alice'}}]});
  assert.deepEqual((await f.pool.query('SELECT recipient_id FROM comms_events')).rows.map(e=>e.recipient_id),[alice.userId]);
  await f.pool.query('DELETE FROM comms_events');
  await notes.share(alice,parent.page.id,{expected_revision:parent.page.revision,members:[{user_id:f.ids.carol,role:'viewer'}]});
  const revoked=(await f.pool.query("SELECT * FROM comms_events WHERE recipient_id=$1",[f.ids.bob])).rows;
  assert.equal(revoked.length,1);assert.equal(revoked[0].event_type,'notes.membership.changed');assert.equal(revoked[0].entity_id,'');assert.deepEqual(revoked[0].payload,{});
  assert.equal((await f.pool.query('SELECT 1 FROM comms_events WHERE recipient_id=$1',[f.ids.owner])).rowCount,0);
 }finally{await f.close();}
});
