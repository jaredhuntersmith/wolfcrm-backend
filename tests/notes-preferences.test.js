import test from 'node:test';import assert from 'node:assert/strict';import {randomUUID} from 'node:crypto';
import {createCommsFixture} from './helpers/comms-fixture.js';import {installNotesSchema} from '../notes/schema.js';import {createNotesWorkspace} from '../notes/pages.js';import {createNotesPreferences} from '../notes/preferences.js';import {installNotificationsSchema,createNotifications} from '../company-comms/notifications.js';
test('Notes preferences mute only selected push kinds and preserve the permanent inbox',{timeout:120000},async()=>{
 const f=await createCommsFixture();try{
  await installNotesSchema(f.pool);await installNotificationsSchema(f.pool);const owner=await f.actor('owner'),prefs=createNotesPreferences({pool:f.pool}),notes=createNotesWorkspace({pool:f.pool});const page=await notes.create(owner,{id:randomUUID(),title:'Preferences fixture'});const pushed=[];
  const notifications=createNotifications({pool:f.pool,sendPush:async(users,kind)=>{pushed.push(kind);return {sent:1};}});
  assert.deepEqual(await prefs.get(owner),{comment_push:true,mention_push:true});await prefs.save(owner,{comment_push:false});
  await assert.rejects(prefs.save(owner,{user_id:f.ids.bob,mention_push:false}),e=>e.status===400);
  for(const kind of ['notes.comment','notes.mention'])await notifications.enqueue(f.pool,{userId:owner.userId,companyId:owner.companyId,kind,title:'Note update',eventKey:randomUUID(),requirements:['notes.view'],sourceRefs:[{source_type:'note',source_id:page.page.id}]});
  await notifications.deliver();assert.deepEqual(pushed,['notes.mention']);assert.equal((await notifications.list(owner)).notifications.length,2);assert.equal((await notifications.list(owner)).unread_count,2);
  await prefs.save(owner,{mention_push:false});assert.deepEqual(await prefs.get(owner),{comment_push:false,mention_push:false});
  await notifications.enqueue(f.pool,{userId:owner.userId,companyId:owner.companyId,kind:'notes.mention',title:'Muted mention',eventKey:randomUUID(),requirements:['notes.view'],sourceRefs:[{source_type:'note',source_id:page.page.id}]});await notifications.deliver();assert.deepEqual(pushed,['notes.mention']);assert.equal((await notifications.list(owner)).unread_count,3);
 }finally{await f.close();}
});
