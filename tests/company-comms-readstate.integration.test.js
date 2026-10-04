import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installCompanyComms} from '../company-comms/index.js';
test('First-unread target uses current audience and exact database read boundary',{timeout:120000},async()=>{
 const f=await createCommsFixture();let server;try{
  const app=express();app.use(express.json());const auth=async(req,res,next)=>{Object.assign(req,await f.actor(req.get('Authorization')||'alice'));next();};
  const service=await installCompanyComms({app,pool:f.pool,authRequired:auth,startWorker:false});
  const alice=await f.actor('alice'),bob=await f.actor('bob'),c=await service.messages.create(alice,{client_key:randomUUID(),member_ids:[f.ids.bob]});
  const one=await service.messages.send(bob,c.id,{client_key:randomUUID(),body:'First',mention_user_ids:[f.ids.alice]}),two=await service.messages.send(bob,c.id,{client_key:randomUUID(),body:'Second',mention_user_ids:[f.ids.alice]});
  await f.pool.query("UPDATE messages SET created_at=CASE WHEN id=$1 THEN '2026-01-01T00:00:00.111111Z'::timestamptz ELSE '2026-01-01T00:00:00.111222Z'::timestamptz END WHERE id=ANY($2::text[])",[one.id,[one.id,two.id]]);
  server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));const endpoint='http://127.0.0.1:'+server.address().port+'/api/comms/conversations/'+c.id+'/unread-target';
  const get=(who='alice')=>fetch(endpoint,{headers:{Authorization:who}});
  assert.equal((await (await get()).json()).message.id,one.id);
  assert.equal((await service.messages.list(alice)).find(row=>row.id===c.id).mention_count,2);
  await service.messages.read(alice,c.id,{last_message_id:one.id});assert.equal((await (await get()).json()).message.id,two.id);
  assert.equal((await service.messages.list(alice)).find(row=>row.id===c.id).mention_count,1);
  await service.messages.read(alice,c.id,{last_message_id:two.id});assert.equal((await (await get()).json()).message,null);
  assert.equal((await service.messages.list(alice)).find(row=>row.id===c.id).mention_count,0);
  await f.pool.query("UPDATE conversation_participants SET last_read_at=NULL,history_from='2026-01-01T00:00:00.111222Z' WHERE conversation_id=$1 AND user_id=$2",[c.id,f.ids.alice]);
  assert.equal((await service.messages.list(alice)).find(row=>row.id===c.id).mention_count,1);
  assert.equal((await get('owner')).status,404);assert.equal((await get('foreign')).status,404);
 }finally{if(server)await new Promise(resolve=>server.close(resolve));await f.close();}
});
