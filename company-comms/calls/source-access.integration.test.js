import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {createCommsFixture} from '../../tests/helpers/comms-fixture.js';
import {authorizeConversation,publish,mutate} from '../access.js';
import {createGroupService} from '../groups.js';
import {createConversationService} from '../messages.js';
import {createNotes} from '../notes.js';
import {createCommsSearch} from '../search.js';
import {storagePredicate} from '../assets.js';
import {createTaskInTransaction,taskAccessSQL} from '../tasks.js';
import {installNotificationsSchema,createNotifications} from '../notifications.js';
import {installJobHuddles} from '../job-huddles.js';
import {installCallsSchema} from './schema.js';
import {createCallsService} from './service.js';

const denied=promise=>assert.rejects(promise,error=>[403,404].includes(error.status));
test('generated chat source ancestry protects every canonical read and mutation',{timeout:120000},async t=>{
 const f=await createCommsFixture(),{pool,ids,companies}=f;
 try {
  await installCallsSchema(pool);await installNotificationsSchema(pool);
  const messages=createConversationService({pool}),groups=createGroupService({pool}),notes=createNotes({pool}),search=createCommsSearch({pool}),notifications=createNotifications({pool});
  const calls=createCallsService({pool,provider:{configured:false},authorizeConversation,publish});
  const alice=await f.actor('alice'),bob=await f.actor('bob');
  const admit=async(conversation,user=ids.bob)=>pool.query("INSERT INTO conversation_participants(id,conversation_id,user_id,history_from) VALUES($1,$2,$3,'-infinity') ON CONFLICT(conversation_id,user_id) DO UPDATE SET left_at=NULL,history_from='-infinity'",[randomUUID(),conversation,user]);
  const meeting=async(source,title='Secret meeting',attendees=[ids.bob])=>calls.saveMeeting(alice,{id:randomUUID(),conversation_id:source,title,starts_at:'2026-11-02T14:00:00Z',duration_minutes:30,timezone:'America/New_York',attendee_ids:attendees});
  const call=async(m,createdAt=new Date())=>{const id=randomUUID();await pool.query("INSERT INTO comms_call_sessions(id,company_id,conversation_id,creator_user_id,host_user_id,kind,media,status,room_name,meeting_id,created_at,ended_at) VALUES($1::uuid,$2,$3,$4,$4,'meeting','audio','ended',$1::text,$5,$6,$6)",[id,companies.a,m.conversation_id,ids.alice,m.id,createdAt]);return id;};
  let group=await groups.create(alice,{name:'Crew',member_ids:[ids.bob,ids.carol]});
  for(const name of ['bob','carol'])await groups.membership(await f.actor(name),group.group.id,{action:'accept',accept_history:true});
  group=await groups.detail(alice,group.group.id);
  group=await groups.structure(alice,group.group.id,'section',null,{name:'Private source',restricted:true,member_ids:[ids.bob],expected_group_revision:group.group.revision});
  const section=group.sections.find(x=>x.name==='Private source');
  group=await groups.structure(alice,group.group.id,'thread',null,{name:'Private source thread',section_id:section.id,kind:'voice',expected_group_revision:group.group.revision});
  const source=group.threads.find(x=>x.name==='Private source thread').conversation_id;
  const first=await meeting(source);await admit(first.conversation_id);
  const nested=await meeting(first.conversation_id,'Secret nested meeting');await admit(nested.conversation_id);
  const waiting=await meeting(source,'Waiting meeting');
  const asset=await f.asset();const sent=await messages.send(alice,nested.conversation_id,{client_key:randomUUID(),body:'Secret inherited message',asset_ids:[asset]});
  const note=await notes.save(alice,nested.conversation_id,null,{client_key:randomUUID(),title:'Secret note',body:'Secret inherited content'});
  const task=await mutate(pool,alice,(db,a)=>createTaskInTransaction(db,a,sent.id,{client_key:randomUUID(),title:'Secret task',assignee_ids:[ids.bob]}));
  const notice=await notifications.enqueue(pool,{userId:ids.bob,companyId:companies.a,kind:'comms.message',title:'Secret inbox',body:'Secret inherited body',conversationId:nested.conversation_id});
  const callID=await call(nested);
  const assetReadable=async()=>{const a=await f.actor('bob'),acl=await storagePredicate(pool,a);return (await pool.query(`SELECT f.id FROM stored_files f WHERE f.id=$3 AND (${acl})`,[a.userId,a.companyId,asset])).rowCount;};
  const taskReadable=async()=>{const a=await f.actor('bob');return (await pool.query(`SELECT task.id FROM todo_tasks task WHERE task.id=$3 AND ${taskAccessSQL(a,'task')}`,[a.userId,a.companyId,task.id])).rowCount;};
  await t.test('source visibility never grants a waiting attendee generated chat admission',async()=>{
   await denied(messages.history(bob,waiting.conversation_id));
   assert.ok((await calls.meetings(bob)).meetings.some(x=>x.id===waiting.id));
   assert.equal((await search.search(bob,{type:'conversation'})).results.some(x=>x.id===waiting.conversation_id),false);
   assert.equal((await pool.query('SELECT source_kind,source_id FROM conversations WHERE id=$1',[nested.conversation_id])).rows[0].source_id,first.conversation_id);
  });
  await t.test('private source removal revokes nested history, snippets, writes, attachments, tasks and inbox without deleting history',async()=>{
   assert.equal((await notes.get(bob,note.id)).title,'Secret note');assert.equal(await assetReadable(),1);assert.equal(await taskReadable(),1);
   assert.ok((await calls.list(bob)).calls.some(x=>x.id===callID));
   const before=await search.search(bob,{search:'Secret'});for(const type of ['message','note','conversation','call'])assert.ok(before.results.some(x=>x.type===type),type);
   await messages.personal(bob,sent.id,{saved:true});
   await pool.query('DELETE FROM comms_section_members WHERE section_id=$1 AND user_id=$2',[section.id,ids.bob]);
   assert.equal((await pool.query('SELECT left_at FROM conversation_participants WHERE conversation_id=$1 AND user_id=$2',[nested.conversation_id,ids.bob])).rows[0].left_at,null);
   for(const m of [first,nested]){await denied(messages.history(bob,m.conversation_id));await denied(messages.send(bob,m.conversation_id,{client_key:randomUUID(),body:'Must not write'}));}
   await denied(notes.get(bob,note.id));assert.equal(await assetReadable(),0);assert.equal(await taskReadable(),0);
   assert.equal((await messages.list(bob)).some(x=>[first.conversation_id,nested.conversation_id].includes(x.id)),false);
   assert.equal((await messages.saved(bob)).some(x=>x.id===sent.id),false);
   for(const type of ['all','message','note','conversation','call'])assert.equal((await search.search(bob,{type,search:'Secret'})).results.length,0,type);
   assert.equal((await calls.list(bob)).calls.some(x=>x.id===callID),false);assert.equal((await calls.meetings(bob)).meetings.some(x=>x.id===nested.id),false);
   assert.equal((await notifications.get(bob,notice)).body,'No Access');assert.equal((await notifications.list(bob,{search:'Secret'})).notifications.length,0);
   assert.equal((await pool.query('SELECT body FROM messages WHERE id=$1',[sent.id])).rows[0].body,'Secret inherited message');
   await pool.query('INSERT INTO comms_section_members(section_id,user_id) VALUES($1,$2)',[section.id,ids.bob]);
   assert.equal((await messages.history(bob,nested.conversation_id)).messages[0].id,sent.id);
  });
  await t.test('denied source rows are filtered before call directory and search pagination',async()=>{
   const independent=await messages.create(alice,{client_key:randomUUID(),member_ids:[ids.bob],force_new:true,title:'Ordinary source'});
   const allowed=await meeting(independent.id,'Visible meeting');await admit(allowed.conversation_id);const allowedCall=await call(allowed,new Date('2020-01-01'));
   for(let i=0;i<103;i++)await call(nested,new Date(Date.now()+i));
   await pool.query('DELETE FROM comms_section_members WHERE section_id=$1 AND user_id=$2',[section.id,ids.bob]);
   const directory=await calls.list(bob);assert.deepEqual(directory.calls.map(x=>x.id),[allowedCall]);assert.equal(directory.next_cursor,null);
   const page=await search.search(bob,{type:'call',limit:1});assert.equal(page.results[0].id,allowedCall);assert.equal(page.next_cursor,null);
   await pool.query('INSERT INTO comms_section_members(section_id,user_id) VALUES($1,$2)',[section.id,ids.bob]);
  });
  await t.test('repeatable backfill preserves legacy IDs/history, allows explicit independent meetings, and denies unmapped/foreign links',async()=>{
   await pool.query('UPDATE conversations SET source_kind=NULL,source_id=NULL WHERE id=ANY($1::text[])',[[first.conversation_id,nested.conversation_id]]);
   const prior=(await pool.query('SELECT id,body,created_at FROM messages WHERE id=$1',[sent.id])).rows[0];
   await f.migrate();await installCallsSchema(pool);await f.migrate();await installCallsSchema(pool);
   assert.deepEqual((await pool.query('SELECT id,body,created_at FROM messages WHERE id=$1',[sent.id])).rows[0],prior);
   assert.equal((await authorizeConversation(pool,bob,nested.conversation_id)).source_id,first.conversation_id);
   const legacy=await meeting(source,'Legacy independent');await admit(legacy.conversation_id);
   await pool.query('UPDATE comms_meetings SET source_conversation_id=NULL WHERE id=$1',[legacy.id]);await pool.query('UPDATE conversations SET source_kind=NULL,source_id=NULL WHERE id=$1',[legacy.conversation_id]);
   await installCallsSchema(pool);await installCallsSchema(pool);assert.equal((await authorizeConversation(pool,bob,legacy.conversation_id)).source_kind,'independent');
   const unmapped=await messages.create(alice,{client_key:randomUUID(),member_ids:[ids.bob],force_new:true});await pool.query("UPDATE conversations SET scope='meeting' WHERE id=$1",[unmapped.id]);await denied(authorizeConversation(pool,bob,unmapped.id));
   const foreign={id:randomUUID()};await pool.query('INSERT INTO conversations(id,company_id,title,created_by) VALUES($1,$2,$3,$4)',[foreign.id,companies.b,'Foreign source',ids.foreign]);
   const corrupt=await messages.create(alice,{client_key:randomUUID(),member_ids:[ids.bob],force_new:true});
   for(const [kind,sourceID] of [['conversation',foreign.id],['conversation','missing-source'],['unknown',source],['conversation',null],['independent',source],[null,source]]){
    await pool.query('UPDATE conversations SET source_kind=$2,source_id=$3 WHERE id=$1',[corrupt.id,kind,sourceID]);await denied(authorizeConversation(pool,bob,corrupt.id));
   }
  });
  await t.test('cycles and over-depth ancestry deny without recursively exhausting SQL, and excessive meeting creation rolls back',async()=>{
   const one=await messages.create(alice,{client_key:randomUUID(),member_ids:[ids.bob],force_new:true}),two=await messages.create(alice,{client_key:randomUUID(),member_ids:[ids.bob],force_new:true});
   await pool.query("UPDATE conversations SET source_kind='conversation',source_id=CASE id WHEN $1 THEN $2 ELSE $1 END WHERE id=ANY($3::text[])",[one.id,two.id,[one.id,two.id]]);
   for(const room of [one,two])await denied(authorizeConversation(pool,bob,room.id));
   let deepest=source;for(let depth=0;depth<8;depth++)deepest=(await meeting(deepest,'Depth '+depth,[])).conversation_id;
   const count=(await pool.query('SELECT count(*)::int AS n FROM conversations')).rows[0].n;
   await denied(meeting(deepest,'Too deep',[]));assert.equal((await pool.query('SELECT count(*)::int AS n FROM conversations')).rows[0].n,count);
   await pool.query("UPDATE conversations SET source_kind='conversation',source_id=$2 WHERE id=$1",[one.id,deepest]);await denied(authorizeConversation(pool,alice,one.id));
  });
  await t.test('Job Huddle and meeting descendants require current Jobs and Schedule rights and live same-company source',async()=>{
   await pool.query("ALTER TABLE schedule_events ADD COLUMN worker_user_ids jsonb DEFAULT '[]',ADD COLUMN sales_user_ids jsonb DEFAULT '[]'");
   const job=randomUUID();await pool.query('INSERT INTO schedule_events(id,company_id,title,worker_user_ids) VALUES($1,$2,$3,$4)',[job,companies.a,'Protected job',JSON.stringify([ids.alice,ids.bob])]);
   const huddles=await installJobHuddles({app:express(),pool,authRequired:()=>{},messages,calls:{configured:false}}),huddle=await huddles.prepare(alice,job),derived=await meeting(huddle.conversation_id,'Job derived meeting');await admit(derived.conversation_id);const derivedCall=await call(derived);
   const standalone=await messages.create(alice,{client_key:randomUUID(),member_ids:[ids.bob],force_new:true}),ordinary=await meeting(standalone.id,'Ordinary meeting');await admit(ordinary.conversation_id);
   await pool.query('UPDATE conversations SET source_kind=NULL,source_id=NULL WHERE id=$1',[huddle.conversation_id]);
   await installJobHuddles({app:express(),pool,authRequired:()=>{},messages,calls:{configured:false}});await installJobHuddles({app:express(),pool,authRequired:()=>{},messages,calls:{configured:false}});
   assert.equal((await authorizeConversation(pool,bob,huddle.conversation_id)).source_id,job);
   const foreignMapping=await messages.create(alice,{client_key:randomUUID(),member_ids:[ids.bob],force_new:true});
   await pool.query('INSERT INTO comms_job_huddles(conversation_id,company_id,job_id,audience_key,created_by) VALUES($1,$2,$3,$4,$5)',[foreignMapping.id,companies.b,job,'corrupt-foreign-map',ids.foreign]);
   await installJobHuddles({app:express(),pool,authRequired:()=>{},messages,calls:{configured:false}});
   await denied(authorizeConversation(pool,bob,foreignMapping.id));
   for(const capability of ['jobs.view','schedule.view']){
    await pool.query('UPDATE employee_permissions SET permission_overrides=permission_overrides||$2::jsonb WHERE user_id=$1',[ids.bob,JSON.stringify({[capability]:false})]);
    for(const conversation of [huddle.conversation_id,derived.conversation_id])await denied(messages.history(bob,conversation));
    assert.equal((await search.search(bob,{type:'call'})).results.some(x=>x.id===derivedCall),false);assert.equal((await calls.list(bob)).calls.some(x=>x.id===derivedCall),false);
    assert.equal((await search.search(bob,{type:'conversation'})).results.some(x=>x.id===derived.conversation_id),false);
    assert.equal((await authorizeConversation(pool,bob,ordinary.conversation_id)).id,ordinary.conversation_id);
    await pool.query('UPDATE employee_permissions SET permission_overrides=permission_overrides||$2::jsonb WHERE user_id=$1',[ids.bob,JSON.stringify({[capability]:true})]);
   }
   await pool.query('UPDATE schedule_events SET deleted_at=now() WHERE id=$1',[job]);await denied(authorizeConversation(pool,bob,derived.conversation_id));
   await pool.query('UPDATE schedule_events SET deleted_at=NULL,company_id=$2 WHERE id=$1',[job,companies.b]);await denied(authorizeConversation(pool,bob,derived.conversation_id));
  });
  await t.test('generic conversation creation ignores client-forged source metadata',async()=>{
   const room=await messages.create(alice,{client_key:randomUUID(),member_ids:[ids.bob],force_new:true,source_kind:'independent',source_id:source,scope:'meeting'});
   const row=(await pool.query('SELECT scope,source_kind,source_id FROM conversations WHERE id=$1',[room.id])).rows[0];assert.deepEqual(row,{scope:'dm',source_kind:null,source_id:null});
  });
 } finally {await f.close();}
});
