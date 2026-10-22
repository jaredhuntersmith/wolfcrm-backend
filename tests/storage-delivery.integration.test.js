import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {Readable} from 'node:stream';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installMediaStorage} from '../media-storage/index.js';
import {randomUUID} from 'node:crypto';
import {installNotesSchema} from '../notes/schema.js';
import {createNotesWorkspace} from '../notes/pages.js';
import {createNotesAudio} from '../notes/audio.js';
import {storagePredicate} from '../company-comms/assets.js';

test('delivery tickets reauthorize bytes, ranges, sessions and in-flight revocation',{timeout:120000},async()=>{
 const f=await createCommsFixture(),{pool,ids}=f;let server,storage,release;
 try{
  await pool.query('CREATE TABLE sessions(token text PRIMARY KEY,user_id uuid REFERENCES users(id)); CREATE INDEX sessions_test_user ON sessions(user_id); ALTER TABLE users ADD COLUMN locked_at timestamptz');
  await pool.query("INSERT INTO sessions VALUES('alice-token',$1),('bob-token',$2)",[ids.alice,ids.bob]);
  const file=await f.asset('alice','document');let long=false;
  const bucket={open:async(row,range,signal)=>{
   if(signal.aborted)throw Error('revoked');
   if(long){const wait=new Promise(resolve=>release=resolve);const body=Readable.from((async function*(){yield Buffer.from('first');await wait;if(signal.aborted)throw Error('revoked');yield Buffer.from('last');})());signal.addEventListener('abort',()=>{release?.();body.destroy(Error('revoked'));},{once:true});return {Body:body};}
   const bytes=Buffer.from('0123456789');return range?{Body:Readable.from([bytes.subarray(2,5)]),ContentLength:3,ContentRange:'bytes 2-4/10'}:{Body:Readable.from([bytes]),ContentLength:10};
  }};
  const env={NODE_ENV:'test'};const app=express();app.use(express.json());
  const auth=async(req,res,next)=>{try{const key=req.get('Authorization')==='bob-token'?'bob':'alice';Object.assign(req,await f.actor(key),{sessionToken:key+'-token'});next();}catch{res.sendStatus(403);}};
  storage=await installMediaStorage({app,pool,authRequired:auth,bucket,accessPredicate:storagePredicate,startWorker:false,env});
  server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});const base='http://127.0.0.1:'+server.address().port;env.PUBLIC_BACKEND_URL=base;
  const issue=async(hostile=false)=>{const response=await fetch(base+'/api/storage/files/'+file+'/access',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'alice-token',...(hostile?{Host:'attacker.example.invalid','X-Forwarded-Host':'attacker.example.invalid','X-Forwarded-Proto':'https'}:{})},body:JSON.stringify({purpose:'preview'})});assert.equal(response.status,200);return (await response.json()).url;};
  await installNotesSchema(pool);
  await pool.query("UPDATE employee_permissions SET permission_overrides='{\"notes.create\":true,\"notes.view\":true}' WHERE user_id=$1",[ids.alice]);
  const notes=createNotesWorkspace({pool}),alice={...await f.actor('alice'),sessionToken:'alice-token'},owner={...await f.actor('owner'),sessionToken:'owner-token'};
  const page=await notes.create(alice,{id:randomUUID(),title:'Private voice note'}),recording=randomUUID();
  await pool.query("INSERT INTO notes_audio(id,page_id,company_id,owner_user_id,byte_size,duration,sha256,object_key,ready) VALUES($1,$2,$3,$4,10,1,$5,'notes/test',true)",[recording,page.page.id,alice.companyId,alice.userId,'a'.repeat(64)]);
  const audio=createNotesAudio({pool,bucket,storage});
  const voice=await audio.access(alice,page.page.id,recording);assert.ok(voice.url.startsWith(base+'/api/storage/delivery/'));assert.equal(await (await fetch(voice.url)).text(),'0123456789');
  await assert.rejects(audio.access(owner,page.page.id,recording),e=>e.status===404,'employer cannot issue private note playback');
  await pool.query("UPDATE employee_permissions SET permission_overrides='{\"notes.view\":false}' WHERE user_id=$1",[ids.alice]);assert.equal((await fetch(voice.url)).status,403);
  await pool.query("UPDATE employee_permissions SET permission_overrides='{}' WHERE user_id=$1",[ids.alice]);
  await pool.query('UPDATE users SET locked_at=now() WHERE id=$1',[ids.alice]);assert.equal((await fetch(voice.url)).status,403);
  await pool.query('UPDATE users SET locked_at=NULL WHERE id=$1',[ids.alice]);
  let url=await issue(true);assert.ok(url.startsWith(base+'/api/storage/delivery/'));assert.equal(url.includes('alice-token'),false);
  let result=await fetch(url,{headers:{Range:'bytes=2-4'}});assert.equal(result.status,206);assert.equal(result.headers.get('content-range'),'bytes 2-4/10');assert.equal(await result.text(),'234');assert.match(result.headers.get('cache-control'),/no-store/);
  assert.equal((await fetch(url,{headers:{Range:'bytes=0-1,3-4'}})).status,416);
  assert.equal((await fetch(url,{method:'HEAD'})).status,200);
  await pool.query('UPDATE users SET locked_at=now() WHERE id=$1',[ids.alice]);assert.equal((await fetch(url)).status,403);
  await pool.query('UPDATE users SET locked_at=NULL WHERE id=$1',[ids.alice]);
  await pool.query("UPDATE employee_permissions SET permission_overrides='{\"storage.view\":false}' WHERE user_id=$1",[ids.alice]);assert.equal((await fetch(url)).status,404);
  await pool.query("UPDATE employee_permissions SET permission_overrides='{}' WHERE user_id=$1",[ids.alice]);
  await pool.query("DELETE FROM sessions WHERE token='alice-token'");assert.equal((await fetch(url)).status,401);
  await pool.query("INSERT INTO sessions VALUES('alice-token',$1)",[ids.alice]);
  url=await issue();await pool.query("UPDATE storage_delivery_tickets SET expires_at=now()-interval '1 second'");assert.equal((await fetch(url)).status,404);
  url=await issue();long=true;const response=await fetch(url);const reader=response.body.getReader();assert.equal(Buffer.from((await reader.read()).value).toString(),'first');
  await storage.revokeDeliveryUser(ids.alice);await assert.rejects(reader.read());
  assert.equal((await fetch(url)).status,404);
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM stored_files WHERE id=$1',[file])).rows[0].n,1);
 }finally{release?.();storage?.stop();if(server){server.closeAllConnections?.();await new Promise(r=>server.close(r));}await f.close();}
});
