import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {createGroupService} from '../company-comms/groups.js';
import {createConversationService} from '../company-comms/messages.js';
import {authorizeConversation,loadActor} from '../company-comms/access.js';
import {storagePredicate} from '../company-comms/assets.js';
import {hydrateSources} from '../company-comms/sources.js';

const rejects=(promise,codes=[403,404])=>assert.rejects(promise,e=>codes.includes(e.status)||codes.includes(e.code));
test('Company Comms migration, membership, conversation and source security on PostgreSQL',{timeout:120000},async t=>{
 const f=await createCommsFixture({migrate:false}),{pool,ids,companies}=f;let actors,group,general,privateThread,section,sharedFile,dm;
 const groups=createGroupService({pool}),messages=createConversationService({pool});
 const member=async who=>groups.membership(actors[who],group.group.id,{action:'accept',accept_history:true});
 const refresh=async()=>{group=await groups.detail(actors.alice,group.group.id);return group;};
 const visibleAsset=async(who,id)=>{const actor=await f.actor(who),acl=await storagePredicate(pool,actor);return (await pool.query(`SELECT f.id FROM stored_files f WHERE f.id=$3 AND (${acl})`,[actor.userId,actor.companyId,id])).rowCount>0;};
 try{
  await t.test('legacy mapping reruns without mixing same-name rooms or altering history/read cursors',async()=>{
   await pool.query(`INSERT INTO channels(id,company_id,name,created_by,created_at) VALUES('old-a',$1,'General',$2,'2020-01-01'),('old-b',$3,'General',$4,'2021-01-01')`,[companies.a,ids.alice,companies.b,ids.foreign]);
   await pool.query(`INSERT INTO conversations(id,company_id,created_by) VALUES('old-dm',$1,$2)`,[companies.a,ids.alice]);
   await pool.query(`INSERT INTO conversation_participants(id,conversation_id,user_id,last_read_at) VALUES('old-p','old-dm',$1,'2020-02-01T00:00:00Z')`,[ids.alice]);
   await pool.query(`INSERT INTO messages(id,channel_id,sender_id,body,created_at) VALUES('old-message','old-a',$1,'Historical original','2020-01-02')`,[ids.alice]);
   await pool.query(`INSERT INTO message_attachments(id,message_id,kind,file_name) VALUES('old-file','old-message','file','history.pdf')`);
   const old=(await pool.query("SELECT * FROM messages WHERE id='old-message'")).rows[0];await f.migrate();await f.migrate();
   actors=Object.fromEntries(await Promise.all(Object.keys(ids).map(async key=>[key,await f.actor(key)])));
   assert.equal(Number((await pool.query('SELECT count(*) FROM comms_groups')).rows[0].count),2);assert.equal(Number((await pool.query('SELECT count(*) FROM comms_threads')).rows[0].count),2);
   const after=(await pool.query("SELECT * FROM messages WHERE id='old-message'")).rows[0];assert.equal(after.body,old.body);assert.equal(after.created_at.toISOString(),old.created_at.toISOString());assert.equal(after.channel_id,'old-a');
   assert.equal((await pool.query("SELECT last_read_at FROM conversation_participants WHERE id='old-p'")).rows[0].last_read_at.toISOString(),'2020-02-01T00:00:00.000Z');
   assert.equal((await messages.history(actors.alice,'wolf-comms-legacy:old-a')).messages[0].id,'old-message');await rejects(messages.history(actors.foreign,'wolf-comms-legacy:old-a'));
   assert.equal((await messages.list(actors.alice)).find(x=>x.id==='wolf-comms-legacy:old-a').latest_body,'Historical original');
   assert.equal((await pool.query("SELECT file_name FROM message_attachments WHERE id='old-file'")).rows[0].file_name,'history.pdf');await messages.personal(actors.alice,'old-message',{saved:true});assert.ok((await messages.saved(actors.alice)).some(x=>x.id==='old-message'));
  });
  await t.test('ordinary member creates invite-only Channel; arbitrary/disabled company members cannot be injected',async()=>{
   await rejects(groups.create(actors.alice,{name:'bad',member_ids:[ids.foreign]}),[400]);await rejects(groups.create(actors.alice,{name:'bad',member_ids:[ids.disabled]}),[403]);
   group=await groups.create(actors.alice,{id:randomUUID(),name:'Crew',member_ids:[ids.bob,ids.carol,ids.admin]});general=group.threads.find(x=>x.kind==='general').conversation_id;
   assert.equal(group.group.visibility,'invite');await rejects(messages.history(actors.bob,general));await rejects(groups.detail(actors.owner,group.group.id));await member('bob');await member('carol');await member('admin');await refresh();
   const sent=await messages.send(actors.bob,general,{client_key:randomUUID(),body:'General is real'});assert.equal(sent.body,'General is real');
  });
  await t.test('conversation previews respect membership, deletion, history boundaries and source denial',async()=>{
   const room=await messages.create(actors.alice,{client_key:randomUUID(),member_ids:[ids.bob],force_new:true});const sent=await messages.send(actors.alice,room.id,{client_key:randomUUID(),body:'Current authorized preview'});assert.equal((await messages.list(actors.bob)).find(x=>x.id===room.id).latest_body,sent.body);assert.equal((await messages.list(actors.owner)).some(x=>x.id===room.id),false);
   await pool.query("UPDATE conversation_participants SET history_from=now()+interval '1 second' WHERE conversation_id=$1 AND user_id=$2",[room.id,ids.bob]);const limited=(await messages.list(actors.bob)).find(x=>x.id===room.id);assert.equal(limited.latest_body,null);assert.equal(limited.unread_count,0);await pool.query("UPDATE conversation_participants SET history_from='-infinity' WHERE conversation_id=$1 AND user_id=$2",[room.id,ids.bob]);
   const contact=randomUUID(),quote=randomUUID();await pool.query('INSERT INTO contacts(id,company_id,name) VALUES($1,$2,$3)',[contact,companies.a,'Preview customer']);await pool.query('INSERT INTO quotes(id,company_id,contact_id,title) VALUES($1,$2,$3,$4)',[quote,companies.a,contact,'Preview protected quote']);await pool.query(`UPDATE employee_permissions SET permission_overrides=permission_overrides||'{"quotes.share":true}' WHERE user_id=$1`,[ids.alice]);const card=await messages.send(actors.alice,room.id,{client_key:randomUUID(),cards:[{source_type:'quote',source_id:quote}]});assert.equal((await messages.list(actors.bob)).find(x=>x.id===room.id).latest_body,'Shared item');await pool.query(`UPDATE employee_permissions SET permission_overrides=permission_overrides||'{"quotes.view":false}' WHERE user_id=$1`,[ids.bob]);assert.equal((await messages.list(actors.bob)).find(x=>x.id===room.id).latest_body,'No Access');await pool.query(`UPDATE employee_permissions SET permission_overrides=permission_overrides||'{"quotes.view":true}' WHERE user_id=$1`,[ids.bob]);
   await messages.edit(actors.alice,card.id,{expected_revision:card.revision},true);assert.equal((await messages.list(actors.bob)).find(x=>x.id===room.id).latest_body,sent.body);await pool.query('UPDATE conversations SET archived_at=now() WHERE id=$1',[room.id]);
  });
  await t.test('creator-only structure, hidden private names/counts/assets and owner-only selection metadata',async()=>{
   for(const actor of [actors.bob,actors.admin,actors.owner])await rejects(groups.structure(actor,group.group.id,'section',null,{name:'Injected',expected_group_revision:group.group.revision}));
   group=await groups.structure(actors.alice,group.group.id,'section',null,{name:'Secret operations',restricted:true,member_ids:[ids.bob],expected_group_revision:group.group.revision});section=group.sections.find(x=>x.name==='Secret operations');assert.deepEqual(section.member_ids,[ids.bob]);
   group=await groups.structure(actors.alice,group.group.id,'thread',null,{name:'private-room',section_id:section.id,kind:'voice',expected_group_revision:group.group.revision});privateThread=group.threads.find(x=>x.name==='private-room');
   const bob=await groups.detail(actors.bob,group.group.id),carol=await groups.detail(actors.carol,group.group.id);assert.ok(bob.threads.some(x=>x.id===privateThread.id));assert.equal(bob.sections[0].member_ids,undefined);assert.ok(!JSON.stringify(carol).includes('private-room'));assert.ok(!JSON.stringify(carol).includes('Secret operations'));await rejects(messages.history(actors.carol,privateThread.conversation_id));
  });
  await t.test('personal collapse/favorite settings and retry-safe message/reaction/read state are independent',async()=>{
   await groups.preferences(actors.bob,{subject_type:'section',subject_id:section.id,favorite:true,muted:true,sort_order:7});await groups.preferences(actors.bob,{subject_type:'section',subject_id:section.id,collapsed:true});const preference=(await groups.detail(actors.bob,group.group.id)).sections[0];assert.equal(preference.favorite,true);assert.equal(preference.muted,true);assert.equal(preference.personal_order,7);assert.equal((await groups.detail(actors.bob,group.group.id)).sections[0].collapsed,true);assert.equal((await groups.detail(actors.alice,group.group.id)).sections[0].collapsed,false);
   const key=randomUUID(),sent=await messages.send(actors.alice,privateThread.conversation_id,{client_key:key,body:'Count once'}),retry=await messages.send(actors.alice,privateThread.conversation_id,{client_key:key,body:'Count once'});assert.equal(sent.id,retry.id);
   await messages.reaction(actors.bob,sent.id,{emoji:'👍'});await messages.reaction(actors.bob,sent.id,{emoji:'👍'});await messages.personal(actors.bob,sent.id,{saved:true});await messages.read(actors.bob,privateThread.conversation_id,{last_message_id:sent.id});
   const history=await messages.history(actors.bob,privateThread.conversation_id);assert.equal(history.messages[0].reactions[0].count,1);assert.equal(history.messages[0].saved,true);assert.equal((await groups.detail(actors.bob,group.group.id)).threads.find(x=>x.id===privateThread.id).unread_count,0);
   await rejects(messages.edit(actors.carol,sent.id,{expected_revision:1,body:'tamper'}));await rejects(messages.edit(actors.alice,sent.id,{expected_revision:99,body:'stale'}),[409]);
  });
  await t.test('private file grant is conversation-scoped; removal revokes grant while original remains',async()=>{
   sharedFile=await f.asset();const sent=await messages.send(actors.alice,privateThread.conversation_id,{client_key:randomUUID(),body:'Attachment',asset_ids:[sharedFile]});
   assert.equal(await visibleAsset('bob',sharedFile),true);assert.equal(await visibleAsset('carol',sharedFile),false);assert.equal(await visibleAsset('owner',sharedFile),false);assert.equal(await visibleAsset('foreign',sharedFile),false);assert.equal((await pool.query('SELECT visibility FROM stored_files WHERE id=$1',[sharedFile])).rows[0].visibility,'private');
   await messages.edit(actors.alice,sent.id,{expected_revision:sent.revision},true);assert.equal(await visibleAsset('bob',sharedFile),false);assert.equal(await visibleAsset('alice',sharedFile),true);
  });
  await t.test('group photo replacement revokes old audience grant and retains both originals',async()=>{
   const old=await f.asset('alice','image'),next=await f.asset('alice','image');await refresh();group=await groups.update(actors.alice,group.group.id,{photo_asset_id:old,expected_revision:group.group.revision});assert.equal(await visibleAsset('carol',old),true);
   group=await groups.update(actors.alice,group.group.id,{photo_asset_id:next,expected_revision:group.group.revision});assert.equal(await visibleAsset('carol',old),false);assert.equal(await visibleAsset('carol',next),true);assert.equal(await visibleAsset('alice',old),true);
  });
  await t.test('CRM cards hydrate per viewer and Stage origin never degrades to Contact',async()=>{
   const contact=randomUUID(),quote=randomUUID(),plan=randomUUID();await pool.query('INSERT INTO contacts(id,company_id,name,address) VALUES($1,$2,$3,$4)',[contact,companies.a,'SECRET CUSTOMER','SECRET ADDRESS']);await pool.query("INSERT INTO stages VALUES('stage',$1,'SECRET STAGE')",[companies.a]);await pool.query("INSERT INTO opportunities VALUES('lead',$1,$2,'stage')",[companies.a,contact]);await pool.query('INSERT INTO quotes VALUES($1,$2,$3,$4,2500,NULL)',[quote,companies.a,contact,'SECRET QUOTE']);await pool.query('INSERT INTO service_plans(id,company_id,plan_name) VALUES($1,$2,$3)',[plan,companies.a,'Real service plan']);
   const refs=[{id:'contact',source_type:'contact',source_id:contact,context_type:'contact'},{id:'stage',source_type:'stage_entry',source_id:'lead',context_type:'stages'},{id:'context',source_type:'contact',source_id:contact,context_type:'stages'},{id:'plan',source_type:'service_plan',source_id:plan}];
   const bob=await hydrateSources(pool,actors.bob,refs);assert.equal(bob.get('contact').title,'SECRET CUSTOMER');for(const key of ['stage','context'])assert.deepEqual(bob.get(key),{accessible:false,text:'No Access'});assert.equal(bob.get('plan').title,'Real service plan');
   const sent=await messages.send(actors.alice,general,{client_key:randomUUID(),body:'Work',cards:[refs[1],{source_type:'quote',source_id:quote}]});const before=(await messages.history(actors.bob,general)).messages.find(x=>x.id===sent.id);assert.deepEqual(before.cards[0],{accessible:false,text:'No Access'});assert.equal(before.cards[1].title,'SECRET QUOTE');
   await pool.query("UPDATE employee_permissions SET permission_overrides=permission_overrides||'{\"quotes.view\":false}'::jsonb WHERE user_id=$1",[ids.bob]);const revoked=(await messages.history(actors.bob,general)).messages.find(x=>x.id===sent.id);assert.deepEqual(revoked.cards[1],{accessible:false,text:'No Access'});
  });
  await t.test('group DM additions create a new history boundary; no employee/owner private bypass',async()=>{
   dm=await messages.create(actors.alice,{client_key:randomUUID(),member_ids:[ids.bob],title:'Private'});const old=await messages.send(actors.alice,dm.id,{client_key:randomUUID(),body:'Old private history'});
   await rejects(messages.history(actors.owner,dm.id));await rejects(messages.members(actors.alice,dm.id,{member_ids:[ids.carol],history_policy:'all'}),[400]);
   const expanded=await messages.members(actors.alice,dm.id,{member_ids:[ids.carol],history_policy:'new_conversation',client_key:randomUUID()});assert.notEqual(expanded.id,dm.id);assert.equal((await messages.history(actors.carol,expanded.id)).messages.length,0);await rejects(messages.history(actors.carol,dm.id));assert.equal((await messages.history(actors.bob,dm.id)).messages[0].id,old.id);
  });
  await t.test('timestamp-precise message pages, reply isolation and mark unread retain every message',async()=>{
   const room=await messages.create(actors.alice,{client_key:randomUUID(),member_ids:[ids.carol],force_new:true});const inserted=[];
   for(let i=0;i<8;i++){const sent=await messages.send(actors.alice,room.id,{client_key:randomUUID(),body:'Page '+i});inserted.push(sent.id);await pool.query("UPDATE messages SET created_at='2025-01-01T00:00:00Z'::timestamptz+($2::int*interval '1 microsecond') WHERE id=$1",[sent.id,Math.floor(i/2)]);}
   const seen=[];let before;do{const page=await messages.history(actors.carol,room.id,{limit:2,before});seen.push(...page.messages.map(x=>x.id));before=page.next_cursor;}while(before);assert.deepEqual([...seen].sort(),[...inserted].sort());
   const reply=await messages.send(actors.carol,room.id,{client_key:randomUUID(),body:'Separate reply',reply_root_id:inserted[0]});assert.equal((await messages.history(actors.alice,room.id)).messages.length,8);assert.equal((await messages.history(actors.alice,room.id,{reply_root_id:inserted[0]})).messages[0].id,reply.id);
   await rejects(messages.send(actors.alice,general,{client_key:randomUUID(),body:'wrong root',reply_root_id:inserted[0]}));await messages.read(actors.carol,room.id,{last_message_id:inserted[7]});assert.equal((await messages.list(actors.carol)).find(x=>x.id===room.id).unread_count,0);await messages.read(actors.carol,room.id,{before_message_id:inserted[7]},true);assert.equal((await messages.list(actors.carol)).find(x=>x.id===room.id).unread_count,2);
  });
  await t.test('owner safety governance lists repair metadata without granting private conversations',async()=>{
   await refresh();await groups.governance(actors.owner,group.group.id,{action:'suspend',reason:'Local test suspend',expected_revision:group.group.revision});assert.ok(!(await groups.list(actors.alice)).some(x=>x.id===group.group.id));
   const row=(await groups.governanceList(actors.owner)).find(x=>x.id===group.group.id);assert.ok(row.suspended_at);assert.equal(row.creator_active,true);assert.equal(row.description,undefined);await rejects(groups.governanceList(actors.admin));await rejects(messages.history(actors.owner,general));await groups.governance(actors.owner,group.group.id,{action:'restore',reason:'Local test restore',expected_revision:row.revision});await refresh();
  });
  await t.test('section deletion explicitly moves Threads with preserved private membership',async()=>{
   await refresh();const impact=await groups.structureLifecycle(actors.alice,group.group.id,'section',section.id,{action:'delete',preview:true,expected_group_revision:group.group.revision});assert.equal(impact.impact.thread_count,1);
   await rejects(groups.structureLifecycle(actors.alice,group.group.id,'section',section.id,{action:'delete',confirm_name:section.name,expected_group_revision:group.group.revision}),[400]);
   await groups.structureLifecycle(actors.alice,group.group.id,'section',section.id,{action:'delete',confirm_name:section.name,move_to_section_id:null,move_permissions:'preserve',expected_group_revision:group.group.revision});await refresh();privateThread=group.threads.find(x=>x.id===privateThread.id);assert.equal(privateThread.section_id,null);assert.equal(privateThread.permission_mode,'override');assert.deepEqual(privateThread.member_ids,[ids.bob]);await rejects(messages.history(actors.carol,privateThread.conversation_id));assert.ok((await messages.history(actors.bob,privateThread.conversation_id)).messages.length>0);
  });
  await t.test('archive preserves authorized reads, blocks writes, restores and confirmed deletion hides all routes',async()=>{
   await groups.structureLifecycle(actors.alice,group.group.id,'thread',privateThread.id,{action:'archive',expected_group_revision:group.group.revision});await refresh();assert.ok((await messages.history(actors.bob,privateThread.conversation_id)).messages.length>0);await rejects(messages.send(actors.bob,privateThread.conversation_id,{client_key:randomUUID(),body:'no'}),[409]);
   await groups.structureLifecycle(actors.alice,group.group.id,'thread',privateThread.id,{action:'restore',expected_group_revision:group.group.revision});await refresh();await messages.send(actors.bob,privateThread.conversation_id,{client_key:randomUUID(),body:'restored'});
   await groups.structureLifecycle(actors.alice,group.group.id,'thread',privateThread.id,{action:'delete',confirm_name:privateThread.name,expected_group_revision:group.group.revision});await rejects(messages.history(actors.bob,privateThread.conversation_id));assert.ok(!(await groups.detail(actors.bob,group.group.id)).threads.some(x=>x.id===privateThread.id));
  });
  await t.test('company departure and permission revocation deny old memberships; stale permission tenant cannot grant',async()=>{
   await pool.query('UPDATE users SET company_id=$2 WHERE id=$1',[ids.bob,companies.b]);await rejects(messages.history(actors.bob,dm.id));const moved=await loadActor(pool,{userId:ids.bob,companyId:companies.b});assert.equal(moved.permissions.preset,'technician');
   await pool.query("UPDATE employee_permissions SET permission_overrides='{\"communications.view\":false}' WHERE user_id=$1",[ids.carol]);await rejects(messages.history(actors.carol,general),[403]);
  });
 }finally{await f.close();}
});
