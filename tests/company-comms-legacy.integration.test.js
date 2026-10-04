import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {randomUUID} from 'node:crypto';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installCompanyComms} from '../company-comms/index.js';
import {installCommsCompatibility} from '../company-comms/compatibility.js';
import {installLegacyAssets} from '../company-comms/legacy-assets.js';
import {storagePredicate} from '../company-comms/assets.js';
import {enforceSensitiveRoute} from '../permission-routes.js';

test('legacy routes reuse canonical membership and additive legacy attachment adoption',{timeout:120000},async()=>{
 const f=await createCommsFixture({migrate:false}),{pool,ids,companies}=f;let server,service;
 try{
  await pool.query(`INSERT INTO conversations(id,company_id,title,created_by) VALUES('legacy-private',$1,'Private',$2)`,[companies.a,ids.alice]);for(const who of ['alice','bob'])await pool.query(`INSERT INTO conversation_participants(id,conversation_id,user_id) VALUES($1,'legacy-private',$2)`,[randomUUID(),ids[who]]);
  await pool.query(`INSERT INTO messages(id,conversation_id,sender_id,body) VALUES('legacy-message','legacy-private',$1,'Historical private')`,[ids.alice]);
  const safeKey=`companies/${companies.a}/messages/original.pdf`,otherKey=`companies/${companies.b}/messages/foreign.pdf`;
  await pool.query(`INSERT INTO message_attachments(id,message_id,kind,object_key,file_name,mime_type,byte_size) VALUES('valid-old','legacy-message','file',$1,'Original.pdf','application/pdf',300),('foreign-old','legacy-message','file',$2,'Foreign.pdf','application/pdf',500),('url-old','legacy-message','file',NULL,'External reference','text/html',100)`,[safeKey,otherKey]);
  await f.migrate();await installLegacyAssets(pool);await installLegacyAssets(pool);
  assert.equal(Number((await pool.query("SELECT count(*) FROM stored_files WHERE storage_provider='legacy_media'")).rows[0].count),1);assert.equal(Number((await pool.query('SELECT count(*) FROM comms_legacy_asset_map')).rows[0].count),3);assert.equal(Number((await pool.query('SELECT count(*) FROM message_attachments')).rows[0].count),3);assert.equal((await pool.query("SELECT object_key FROM message_attachments WHERE id='valid-old'")).rows[0].object_key,safeKey);
  const asset=(await pool.query("SELECT asset_id FROM comms_legacy_asset_map WHERE attachment_id='valid-old'")).rows[0].asset_id;assert.ok(asset);assert.ok((await pool.query("SELECT repair_reason FROM comms_legacy_asset_map WHERE attachment_id='foreign-old'")).rows[0].repair_reason);
  const app=express();app.use(express.json());const auth=async(req,res,next)=>{try{const who=req.get('Authorization');if(!ids[who])return res.status(401).json({error:'authentication_required'});Object.assign(req,await f.actor(who));if(enforceSensitiveRoute(req,res))next();}catch(error){res.status(error.status||500).json({error:error.code});}};
  // Signed transport is a deterministic local boundary. ACL is the real database implementation.
  app.locals.mediaStorage={access:async(actor,assetId)=>{const acl=await storagePredicate(pool,actor);if(!(await pool.query(`SELECT 1 FROM stored_files f WHERE f.id=$3 AND (${acl})`,[actor.userId,actor.companyId,assetId])).rowCount){const e=new Error('asset_denied');e.status=404;e.code='asset_denied';throw e;}return {url:'https://example.invalid/local-authorized-preview'};}};
  service=await installCompanyComms({app,pool,authRequired:auth,startWorker:false});app.locals.comms=service;installCommsCompatibility({app,pool,authRequired:auth});server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));const base='http://127.0.0.1:'+server.address().port;
  const request=(path,who='alice',body,method=body?'POST':'GET')=>fetch(base+'/api/internal'+path,{method,headers:{Authorization:who,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});
  const history=await request('/conversations/legacy-private/messages','bob');assert.equal(history.status,200);const rows=await history.json();assert.equal(rows[0].body,'Historical private');assert.equal(rows[0].attachments[0].file_name,'Original.pdf');
  for(const who of ['owner','carol','foreign']){assert.equal((await request('/conversations/legacy-private/messages',who)).status,404);assert.equal((await request('/media/download-url?object_key='+encodeURIComponent(safeKey),who)).status,404);}
  assert.equal((await request('/media/download-url?object_key='+encodeURIComponent(safeKey),'bob')).status,200);assert.equal((await request('/conversations/legacy-private/messages','bob',{body:'Preserved send',client_key:'legacy-retry'})).status,200);assert.equal((await request('/conversations/legacy-private/messages','bob',{body:'Preserved send',client_key:'legacy-retry'})).status,200);assert.equal(Number((await pool.query("SELECT count(*) FROM messages WHERE client_key='legacy-retry'")).rows[0].count),1);
  assert.equal((await request('/conversations/legacy-private/messages','bob',{body:'old upload',attachments:[{url:'https://example.invalid/arbitrary'}]})).status,426);
  const dm=await request('/conversations/private','carol',{user_id:ids.bob});assert.equal(dm.status,200);assert.ok((await dm.json()).id);assert.equal((await request('/conversations/private','carol',{user_id:ids.foreign})).status,400);
  assert.equal((await request('/conversations/legacy-private','bob',null,'DELETE')).status,200);assert.equal((await request('/conversations/legacy-private/messages','bob')).status,404);assert.equal((await request('/conversations/legacy-private/messages','alice')).status,200);
 }finally{service?.stop();if(server)await new Promise(resolve=>server.close(resolve));await f.close();}
});
