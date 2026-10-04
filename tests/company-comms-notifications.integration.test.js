import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installNotificationsSchema,createNotifications} from '../company-comms/notifications.js';
import {installCompanyComms} from '../company-comms/index.js';
import {createConversationService} from '../company-comms/messages.js';
import {loadActor} from '../company-comms/access.js';
import {enforceSensitiveRoute} from '../permission-routes.js';

const rejects=promise=>assert.rejects(promise,e=>[403,404].includes(e.status));
test('durable notification inbox preserves history and enforces live privacy',{timeout:120000},async t=>{
 const f=await createCommsFixture(),{pool,ids,companies}=f;let actors,notifications,legacyContact,privateDM,privateNotification,publicNotification;let server;
 try{
  actors=Object.fromEntries(await Promise.all(Object.keys(ids).map(async key=>[key,await f.actor(key)])));
  const enqueue=(who,overrides={})=>notifications.enqueue(pool,{userId:ids[who],companyId:who==='foreign'?companies.b:companies.a,kind:'test',title:'Readable update',eventKey:randomUUID(),...overrides});
  await t.test('existing duplicate events and legacy lead delivered/read history survive repeat migration',async()=>{
   legacyContact=randomUUID();await pool.query('INSERT INTO contacts(id,company_id,name) VALUES($1,$2,$3)',[legacyContact,companies.a,'Historic customer']);
   for(const name of ['historical-one','historical-two'])await pool.query(`INSERT INTO notifications(id,user_id,company_id,kind,title,body,data,created_at,read_at) VALUES($1,$2,$3,'sms','Old text','Preserved', '{"message_id":"old-event"}', '2020-01-01T00:00:00Z','2020-01-02T00:00:00Z')`,[name,ids.alice,companies.a]);
   await pool.query(`INSERT INTO lead_notifications(id,user_id,company_id,contact_id,title,body,created_at,delivered_at) VALUES($1,$2,$3,$4,'Old lead','Saved body','2020-02-01T00:00:00Z','2020-02-02T00:00:00Z')`,[randomUUID(),ids.alice,companies.a,legacyContact]);
   await installNotificationsSchema(pool);await installNotificationsSchema(pool);notifications=createNotifications({pool});
   assert.equal(Number((await pool.query('SELECT count(*) FROM notifications')).rows[0].count),3);
   const rows=(await notifications.list(actors.alice)).notifications;assert.equal(rows.length,3);assert.equal(rows.find(x=>x.title==='Old lead').read_at.toISOString(),'2020-02-02T00:00:00.000Z');assert.equal(rows.filter(x=>x.title==='Old text').length,2);
   assert.equal(Number((await pool.query('SELECT count(*) FROM notification_delivery_outbox WHERE delivered_at IS NULL')).rows[0].count),0);
  });
  await t.test('new legacy leads bridge once and deletion tombstones prevent duplicate events from returning',async()=>{
   const lead=randomUUID();await pool.query('INSERT INTO lead_notifications(id,user_id,company_id,contact_id,title) VALUES($1,$2,$3,$4,$5)',[lead,ids.alice,companies.a,legacyContact,'A new lead']);
   const n=(await notifications.list(actors.alice)).notifications.find(x=>x.title==='A new lead');assert.ok(n);await notifications.change(actors.alice,{ids:[n.id]},true);await installNotificationsSchema(pool);await rejects(notifications.get(actors.alice,n.id));
   const key=randomUUID(),first=await enqueue('alice',{eventKey:key});assert.ok(first);await notifications.change(actors.alice,{ids:[first]},true);assert.equal(await enqueue('alice',{eventKey:key}),null);await rejects(notifications.get(actors.alice,first));
  });
  await t.test('cursor pagination is complete for equal and sub-millisecond timestamps, with durable bulk read/unread',async()=>{
   const inserted=[];for(let i=0;i<9;i++){const n=await enqueue('carol');inserted.push(n);await pool.query("UPDATE notifications SET created_at='2025-01-01T00:00:00Z'::timestamptz+($2::int*interval '1 microsecond') WHERE id=$1",[n,Math.floor(i/2)]);}
   const seen=[];let cursor;do{const page=await notifications.list(actors.carol,{limit:2,cursor});seen.push(...page.notifications.map(x=>x.id));cursor=page.next_cursor;}while(cursor);assert.deepEqual([...seen].sort(),inserted.sort());assert.equal(new Set(seen).size,9);
   await notifications.change(actors.carol,{all:true,read:true});assert.equal((await notifications.list(actors.carol,{unread:'true'})).notifications.length,0);await notifications.change(actors.carol,{ids:[seen[0]],read:false});assert.equal((await notifications.list(actors.carol)).unread_count,1);
   await assert.rejects(notifications.change(actors.carol,{all:true},true),e=>e.status===400);await notifications.change(actors.carol,{all:true,confirm:true},true);assert.equal((await notifications.list(actors.carol)).notifications.length,0);
  });
  await t.test('owner and cross-company clients cannot read another personal inbox or mutate its rows',async()=>{
   const privateId=await enqueue('alice',{title:'PERSONAL SECRET'});for(const actor of [actors.owner,actors.bob,actors.foreign]){await rejects(notifications.get(actor,privateId));assert.equal((await notifications.change(actor,{ids:[privateId]},true)).changed,0);}
   assert.equal((await notifications.get(actors.alice,privateId)).title,'PERSONAL SECRET');assert.equal(await notifications.enqueue(pool,{userId:ids.foreign,companyId:companies.a,kind:'test',title:'bad tenant'}),null);
  });
  await t.test('revoked source and unknown capability rows become exact No Access without search, filter or badge leaks',async()=>{
   const n=await enqueue('bob',{title:'SECRET STAGE',body:'SECRET BODY',requirements:['pipeline.view'],sourceRefs:[{source_type:'contact',source_id:legacyContact,context_type:'stages'}]});
   const unknown=await enqueue('bob',{title:'Unknown future capability',requirements:['future.permission']});const safe=await enqueue('bob',{title:'Allowed general alert'});
   for(const key of [n,unknown]){const row=await notifications.get(actors.bob,key);assert.equal(row.accessible,false);assert.equal(row.body,'No Access');assert.equal(row.title,'');assert.equal(JSON.stringify(row).includes('SECRET'),false);}
   assert.equal((await notifications.list(actors.bob,{search:'SECRET'})).notifications.length,0);assert.equal((await notifications.list(actors.bob,{unread:'true'})).notifications.length,1);assert.equal((await notifications.list(actors.bob)).unread_count,1);assert.equal((await notifications.get(actors.bob,safe)).accessible,true);
   await pool.query('UPDATE contacts SET deleted_at=now() WHERE id=$1',[legacyContact]);const old=(await notifications.list(actors.alice)).notifications.find(x=>x.id.startsWith('legacy-lead:'));assert.equal(old.body,'No Access');
  });
  await t.test('private conversation notification forwarding preserves original membership provenance',async()=>{
   const messages=createConversationService({pool});privateDM=await messages.create(actors.alice,{client_key:randomUUID(),member_ids:[ids.bob]});
   privateNotification=await enqueue('alice',{kind:'comms.message',title:'Private conversation content',body:'CONFIDENTIAL',requirements:['communications.view'],conversationId:privateDM.id});
   const destination=await messages.create(actors.alice,{client_key:randomUUID(),member_ids:[ids.bob,ids.carol]});const sent=await messages.send(actors.alice,destination.id,{client_key:randomUUID(),cards:[{source_type:'notification',source_id:privateNotification}]});
   assert.equal((await messages.history(actors.bob,destination.id)).messages[0].cards[0].text.includes('CONFIDENTIAL'),true);assert.deepEqual((await messages.history(actors.carol,destination.id)).messages[0].cards[0],{accessible:false,text:'No Access'});
   await notifications.change(actors.alice,{ids:[privateNotification]},true);assert.equal((await messages.history(actors.bob,destination.id)).messages[0].cards[0].text.includes('CONFIDENTIAL'),true);
   const revision=Number((await pool.query('SELECT revision FROM conversations WHERE id=$1',[privateDM.id])).rows[0].revision);await messages.members(actors.bob,privateDM.id,{remove_user_ids:[ids.bob],expected_revision:revision});assert.deepEqual((await messages.history(actors.bob,destination.id)).messages.find(x=>x.id===sent.id).cards[0],{accessible:false,text:'No Access'});
  });
  await t.test('push delivery rechecks access, mute and provider failure without leaking content',async()=>{
   const sent=[];let failProvider=true;const delivery=createNotifications({pool,sendPush:async(users,kind,options)=>{sent.push({users,kind,options});return failProvider?{failed:1}:{sent:1};}});
   const n=await enqueue('carol',{title:'Sensitive push title',body:'Sensitive push body'});await delivery.deliver();const pending=(await pool.query('SELECT * FROM notification_delivery_outbox WHERE notification_id=$1',[n])).rows[0];assert.equal(pending.delivered_at,null);assert.equal(pending.attempts,1);assert.equal(JSON.stringify(sent).includes('Sensitive push'),false);assert.ok(sent.some(x=>x.options.inboxDelivery===true));
   failProvider=false;await pool.query('UPDATE notification_delivery_outbox SET next_attempt_at=now() WHERE notification_id=$1',[n]);await delivery.deliver();assert.ok((await pool.query('SELECT delivered_at FROM notification_delivery_outbox WHERE notification_id=$1',[n])).rows[0].delivered_at);
   const muted=await enqueue('carol');await notifications.preferences(actors.carol,{muted:true,timezone:'UTC'});const before=sent.length;await delivery.deliver();assert.equal(sent.length,before);assert.equal((await pool.query('SELECT last_error FROM notification_delivery_outbox WHERE notification_id=$1',[muted])).rows[0].last_error,'delivery_muted');
  });
  await t.test('installed raw HTTP inbox and invalidation routes survive Comms revocation; other Comms routes deny',async()=>{
   const app=express();app.use(express.json());const auth=async(req,res,next)=>{try{if(!ids[req.get('Authorization')])return res.status(401).json({error:'auth'});const actor=await f.actor(req.get('Authorization'));Object.assign(req,actor);if(enforceSensitiveRoute(req,res))next();}catch(e){res.status(e.status||503).json({error:e.code||'unavailable'});}};
   const api=await installCompanyComms({app,pool,authRequired:auth,startWorker:false});server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));const url='http://127.0.0.1:'+server.address().port;
   publicNotification=await enqueue('disabled',{title:'Inbox independent'});await api.permissionChanged({companyId:companies.a,userId:ids.disabled,id:randomUUID(),revision:12});
   const fetchAs=(path,who='disabled',options={})=>fetch(url+path,{...options,headers:{Authorization:who,'Content-Type':'application/json',...options.headers}});
   const inbox=await fetchAs('/api/comms/notifications');assert.equal(inbox.status,200);assert.ok((await inbox.json()).notifications.some(x=>x.id===publicNotification));assert.equal((await fetchAs('/api/comms/bootstrap')).status,403);
   const events=await fetchAs('/api/comms/events');assert.equal(events.status,200);assert.ok((await events.json()).events.some(x=>x.event_type==='permission.changed'));
   assert.equal((await fetchAs('/api/comms/notifications/'+publicNotification,'foreign')).status,404);assert.equal((await fetchAs('/api/comms/notifications/'+publicNotification,'owner')).status,404);api.stop();
  });
 }finally{if(server)await new Promise(resolve=>server.close(resolve));await f.close();}
});

test('HTTP removal events reach only former participants and clear derived-chat access',{timeout:120000},async()=>{
 const f=await createCommsFixture(),{pool,ids,companies}=f;let server,core;
 try{
  const app=express();app.use(express.json());
  const auth=async(req,res,next)=>{try{const who=req.get('Authorization');if(!ids[who])return res.status(401).json({error:'auth'});Object.assign(req,await f.actor(who));if(enforceSensitiveRoute(req,res))next();}catch(error){res.status(error.status||503).json({error:error.code||'unavailable'});}};
  core=await installCompanyComms({app,pool,authRequired:auth,startWorker:false});
  server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));const base='http://127.0.0.1:'+server.address().port;
  const request=async(who,path,{method='GET',body}={})=>{const response=await fetch(base+'/api/comms'+path,{method,headers:{Authorization:who,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});return {status:response.status,body:await response.json()};};
  const post=(who,path,body)=>request(who,path,{method:'POST',body});
  const revision=async conversation=>Number((await pool.query('SELECT revision FROM conversations WHERE id=$1',[conversation])).rows[0].revision);
  const cursor=async()=>Number((await pool.query('SELECT COALESCE(max(id),0) AS id FROM comms_events')).rows[0].id);
  const room=(await post('alice','/conversations',{client_key:randomUUID(),member_ids:[ids.bob,ids.carol],title:'CONFIDENTIAL GROUP'})).body;
  assert.ok(room.id);const message=(await post('alice',`/conversations/${room.id}/messages`,{client_key:randomUUID(),body:'CONFIDENTIAL SOURCE CONTENT'})).body;
  // This reproduces an admitted meeting's retained chat membership, the state
  // that previously allowed cached derived history to survive source removal.
  const {installCallsSchema}=await import('../company-comms/calls/schema.js');const {createCallsService}=await import('../company-comms/calls/service.js');const {authorizeConversation,publish}=await import('../company-comms/access.js');
  await installCallsSchema(pool);const calls=createCallsService({pool,provider:{configured:false},authorizeConversation,publish});
  const meeting=await calls.saveMeeting(await f.actor('alice'),{id:randomUUID(),conversation_id:room.id,title:'CONFIDENTIAL MEETING',starts_at:'2026-11-02T14:00:00Z',duration_minutes:30,timezone:'UTC',attendee_ids:[ids.bob,ids.carol]});
  for(const who of ['bob','carol'])await pool.query("INSERT INTO conversation_participants(id,conversation_id,user_id,history_from) VALUES($1,$2,$3,'-infinity')",[randomUUID(),meeting.conversation_id,ids[who]]);
  assert.equal((await post('alice',`/conversations/${meeting.conversation_id}/messages`,{client_key:randomUUID(),body:'CONFIDENTIAL DERIVED HISTORY'})).status,200);
  assert.equal((await request('bob',`/conversations/${room.id}/messages`)).status,200);assert.equal((await request('bob',`/conversations/${meeting.conversation_id}/messages`)).status,200);
  const before=await cursor(),expected=await revision(room.id);
  assert.equal((await post('alice',`/conversations/${room.id}/members`,{remove_user_ids:[ids.bob,ids.bob,ids.admin,ids.foreign],expected_revision:expected})).status,200);
  assert.equal((await request('bob',`/conversations/${room.id}/messages`)).status,404);assert.equal((await request('bob',`/conversations/${meeting.conversation_id}/messages`)).status,404);
  const bobEvents=await request('bob',`/events?after=${before}`);assert.equal(bobEvents.status,200);
  assert.equal(bobEvents.body.events.length,1);const event=bobEvents.body.events[0];
  assert.equal(event.event_type,'membership.changed');assert.equal(event.recipient_id,ids.bob);assert.equal(event.entity_id,room.id);assert.equal(event.conversation_id,null);assert.deepEqual(event.payload,{});assert.equal(JSON.stringify(event).includes('CONFIDENTIAL'),false);
  for(const who of ['admin','owner','foreign'])assert.equal((await request(who,`/events?after=${before}`)).body.events.some(x=>x.entity_id===room.id),false,who);
  for(const who of ['alice','carol'])assert.ok((await request(who,`/events?after=${before}`)).body.events.some(x=>x.event_type==='membership.changed'&&x.entity_id===room.id&&x.recipient_id===null),who);
  const leftAt=(await pool.query('SELECT left_at FROM conversation_participants WHERE conversation_id=$1 AND user_id=$2',[room.id,ids.bob])).rows[0].left_at;
  assert.equal((await post('alice',`/conversations/${room.id}/members`,{remove_user_ids:[ids.bob],expected_revision:expected})).status,409);
  assert.equal((await post('alice',`/conversations/${room.id}/members`,{remove_user_ids:[ids.bob],expected_revision:await revision(room.id)})).status,200);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM comms_events WHERE recipient_id=$1 AND entity_id=$2 AND event_type='membership.changed'",[ids.bob,room.id])).rows[0].n,1);
  assert.equal((await pool.query('SELECT left_at FROM conversation_participants WHERE conversation_id=$1 AND user_id=$2',[room.id,ids.bob])).rows[0].left_at.toISOString(),leftAt.toISOString());
  assert.equal((await request('bob',`/events?after=${bobEvents.body.cursor}`)).body.events.length,0);
  await pool.query('UPDATE employee_permissions SET permission_overrides=permission_overrides||\'{"communications.view":false}\'::jsonb WHERE user_id=$1',[ids.bob]);
  assert.equal((await request('bob',`/events?after=${before}`)).body.events.filter(x=>x.id===event.id).length,1);
  assert.equal((await post('alice',`/conversations/${room.id}/messages`,{client_key:randomUUID(),body:'Remaining members work'})).status,200);assert.equal((await request('carol',`/conversations/${room.id}/messages`)).status,200);
  const selfCursor=await cursor();assert.equal((await post('carol',`/conversations/${room.id}/members`,{remove_user_ids:[ids.carol],expected_revision:await revision(room.id)})).status,200);
  assert.equal((await request('carol',`/conversations/${meeting.conversation_id}/messages`)).status,404);
  const selfEvents=(await request('carol',`/events?after=${selfCursor}`)).body.events;assert.equal(selfEvents.filter(x=>x.recipient_id===ids.carol&&x.entity_id===room.id).length,1);
  const dm=(await post('alice','/conversations',{client_key:randomUUID(),member_ids:[ids.admin],force_new:true})).body,dmCursor=await cursor();
  assert.equal((await post('admin',`/conversations/${dm.id}/members`,{remove_user_ids:[ids.admin],expected_revision:await revision(dm.id)})).status,200);
  assert.equal((await request('admin',`/conversations/${dm.id}/messages`)).status,404);assert.equal((await request('admin',`/events?after=${dmCursor}`)).body.events.filter(x=>x.recipient_id===ids.admin&&x.entity_id===dm.id).length,1);
  assert.equal((await pool.query('SELECT body FROM messages WHERE id=$1',[message.id])).rows[0].body,'CONFIDENTIAL SOURCE CONTENT');
  assert.equal((await pool.query('SELECT left_at FROM conversation_participants WHERE conversation_id=$1 AND user_id=$2',[meeting.conversation_id,ids.bob])).rows[0].left_at,null);
 }finally{core?.stop();if(server)await new Promise(resolve=>server.close(resolve));await f.close();}
});
