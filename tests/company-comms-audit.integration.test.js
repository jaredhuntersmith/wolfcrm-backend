import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installCommsAudit} from '../company-comms/audit.js';
import {installRateLimits,takeRateLimit} from '../company-comms/rate-limits.js';
import {createStorageService} from '../media-storage/service.js';
import {storagePredicate} from '../company-comms/assets.js';
import {createConversationService} from '../company-comms/messages.js';

test('Comms access audit distinguishes authorization, transfers and observable saves',{timeout:120000},async()=>{
 const f=await createCommsFixture(),{pool,ids}=f;let server;
 try{
  await installRateLimits(pool);
  const app=express();app.use(express.json());const auth=async(req,res,next)=>{try{Object.assign(req,await f.actor(req.get('Authorization')||'alice'));next();}catch(e){res.status(403).json({error:e.code});}};
  const audit=await installCommsAudit({app,pool,authRequired:auth}),storage=createStorageService({pool,bucket:{access:async()=> 'https://example.invalid/private'},accessPredicate:storagePredicate,onAccess:audit.record});
  const messages=createConversationService({pool}),alice=await f.actor('alice'),bob=await f.actor('bob'),file=await f.asset();
  const c=await messages.create(alice,{client_key:randomUUID(),member_ids:[ids.bob]});await messages.send(alice,c.id,{client_key:randomUUID(),asset_ids:[file]});
  for(let n=0;n<3;n++)await storage.access(bob,file,'preview');
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM comms_asset_access_events WHERE action='preview_authorized'")).rows[0].n,1);
  const unrelated=await messages.create(alice,{client_key:randomUUID(),member_ids:[ids.owner]});
  await assert.rejects(storage.access(alice,file,'preview',unrelated.id),e=>e.status===404);
  await assert.rejects(storage.access(bob,file,'preview',unrelated.id),e=>e.status===404);
  const {receipt_id}=await storage.access(bob,file,'download',c.id);
  await assert.rejects(storage.transferStarted(alice,file,receipt_id),e=>e.status===404);
  for(let n=0;n<2;n++){await storage.transferStarted(bob,file,receipt_id);await storage.acknowledge(bob,file,receipt_id);}
  const actions=(await pool.query('SELECT action FROM comms_asset_access_events ORDER BY action')).rows.map(r=>r.action);
  assert.deepEqual(actions,['download_authorized','preview_authorized','saved_reported','transfer_started_reported']);
  assert.ok((await pool.query('SELECT conversation_id FROM comms_asset_access_events WHERE receipt_id=$1',[receipt_id])).rows.every(r=>r.conversation_id===c.id));
  await pool.query(`UPDATE employee_permissions SET permission_overrides=permission_overrides||'{"communications.download":false}'::jsonb WHERE user_id=$1`,[ids.bob]);
  await assert.rejects(storage.access(bob,file,'download'),e=>e.status===403&&e.code==='download_denied');
  assert.ok((await storage.access(bob,file,'preview')).url);
  const audio=await f.asset('alice','audio');await pool.query(`UPDATE employee_permissions SET permission_overrides=permission_overrides||'{"audio.play":false}'::jsonb WHERE user_id=$1`,[ids.alice]);
  for(const purpose of ['stream','preview'])await assert.rejects(storage.access(alice,audio,purpose),e=>e.status===403&&e.code==='playback_denied');
  await assert.rejects(storage.access(await f.actor('foreign'),file,'preview'),e=>e.status===404);
  server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));const base='http://127.0.0.1:'+server.address().port;
  const req=(who,path='')=>fetch(base+'/api/comms/audit'+path,{headers:{Authorization:who}});
  for(const who of ['alice','bob','admin'])assert.equal((await req(who)).status,403);
  const page=await (await req('owner','?limit=2')).json();assert.equal(page.events.length,2);assert.ok(page.next_cursor);
  const next=await (await req('owner','?limit=2&cursor='+page.next_cursor)).json();assert.ok(next.events.every(r=>!page.events.some(p=>r.id===p.id)));
  const serialized=JSON.stringify(page);assert.ok(!serialized.includes('PRIVATE-'));assert.ok(!serialized.includes('object_key'));
  assert.equal((await (await req('foreign')).json()).events.length,0);
  await pool.query('UPDATE conversation_participants SET left_at=now() WHERE conversation_id=$1 AND user_id=$2',[c.id,ids.bob]);
  await assert.rejects(storage.access(bob,file,'preview'),e=>e.status===404);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM comms_asset_access_events WHERE action='saved_reported'")).rows[0].n,1);
 }finally{if(server)await new Promise(resolve=>server.close(resolve));await f.close();}
});

test('Rate limits are atomic, per user and enforce a bounded retry window',{timeout:120000},async()=>{
 const f=await createCommsFixture();try{await installRateLimits(f.pool);const a=await f.actor('alice'),b=await f.actor('bob');
  const outcomes=await Promise.allSettled(Array.from({length:8},()=>takeRateLimit(f.pool,a,{bucket:'test',limit:5})));
  assert.equal(outcomes.filter(r=>r.status==='fulfilled').length,5);assert.ok(outcomes.filter(r=>r.status==='rejected').every(r=>r.reason.status===429));
  await takeRateLimit(f.pool,b,{bucket:'test',limit:5});
  await f.pool.query("UPDATE comms_rate_limits SET window_at=window_at-interval '1 minute'");await takeRateLimit(f.pool,a,{bucket:'test',limit:5});
 }finally{await f.close();}
});
