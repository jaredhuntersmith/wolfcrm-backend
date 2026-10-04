import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {createConversationService} from '../company-comms/messages.js';
import {installJobHuddles,authorizeCommsCallConversation} from '../company-comms/job-huddles.js';

test('Job huddles use actual eligible assignments and preserve audience boundaries',{timeout:120000},async()=>{
 const f=await createCommsFixture(),{pool,ids,companies}=f;try{
  await pool.query("ALTER TABLE schedule_events ADD COLUMN worker_user_ids jsonb DEFAULT '[]',ADD COLUMN sales_user_ids jsonb DEFAULT '[]'");
  const job=randomUUID();await pool.query('INSERT INTO schedule_events(id,company_id,title,worker_user_ids) VALUES($1,$2,$3,$4)',[job,companies.a,'Private Job',JSON.stringify([ids.alice,ids.bob,ids.foreign,ids.disabled,'not-a-uuid'])]);
  const messages=createConversationService({pool}),service=await installJobHuddles({app:express(),pool,authRequired:()=>{},messages,calls:{configured:false}}),alice=await f.actor('alice');
  const [one,two]=await Promise.all([service.prepare(alice,job),service.prepare(alice,job)]);assert.equal(one.conversation_id,two.conversation_id);assert.equal(one.eligible_count,2);
  const participants=(await pool.query('SELECT user_id FROM conversation_participants WHERE conversation_id=$1 ORDER BY user_id',[one.conversation_id])).rows.map(r=>r.user_id);assert.deepEqual(participants,[ids.alice,ids.bob].sort());
  const history=await messages.history(await f.actor('bob'),one.conversation_id);assert.equal(history.messages.length,1);assert.equal(history.messages[0].cards[0].title,'Private Job');
  assert.equal((await service.context(await f.actor('bob'),one.conversation_id)).context.source_id,job);
  await assert.rejects(service.prepare(await f.actor('foreign'),job),e=>e.status===404);await assert.rejects(service.context(await f.actor('owner'),one.conversation_id),e=>e.status===404);
  await pool.query(`UPDATE employee_permissions SET permission_overrides=permission_overrides||'{"schedule.view":false}'::jsonb WHERE user_id=$1`,[ids.bob]);
  await assert.rejects(service.context(await f.actor('bob'),one.conversation_id),e=>e.status===404);
  await assert.rejects(authorizeCommsCallConversation(pool,await f.actor('bob'),one.conversation_id,{capability:'communications.calls'}),e=>e.status===404);
  const changed=await service.prepare(alice,job);assert.notEqual(changed.conversation_id,one.conversation_id);assert.equal(changed.eligible_count,1);
  await pool.query('UPDATE schedule_events SET worker_user_ids=$2 WHERE id=$1',[job,JSON.stringify([ids.alice,ids.carol])]);
  const next=await service.prepare(alice,job);assert.notEqual(next.conversation_id,one.conversation_id);await assert.rejects(messages.history(await f.actor('carol'),one.conversation_id),e=>e.status===404);
  const before=(await pool.query('SELECT * FROM schedule_events WHERE id=$1',[job])).rows[0];await service.prepare(alice,job);const after=(await pool.query('SELECT * FROM schedule_events WHERE id=$1',[job])).rows[0];assert.deepEqual(before,after);
  await pool.query('DELETE FROM schedule_events WHERE id=$1',[job]);await assert.rejects(authorizeCommsCallConversation(pool,alice,next.conversation_id,{capability:'communications.calls'}),e=>e.status===404);
 }finally{await f.close();}
});
