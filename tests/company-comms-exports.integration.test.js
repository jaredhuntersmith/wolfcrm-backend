import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installCommsQuoteExports} from '../company-comms/quote-exports.js';
import {createStorageService} from '../media-storage/service.js';
import {storagePredicate} from '../company-comms/assets.js';
import {createConversationService} from '../company-comms/messages.js';
test('Quote export reservations retain source ACL and original quote state',{timeout:120000},async()=>{
 const f=await createCommsFixture(),{pool,companies,ids}=f;let server;
 try{
  const contact=randomUUID(),quote=randomUUID();await pool.query('INSERT INTO contacts(id,company_id,name,address) VALUES($1,$2,$3,$4)',[contact,companies.a,'Private Customer','Private Address']);await pool.query('INSERT INTO quotes(id,company_id,contact_id,title,total_cents) VALUES($1,$2,$3,$4,3500)',[quote,companies.a,contact,'Original Quote']);
  for(const who of ['alice','bob'])await pool.query(`UPDATE employee_permissions SET permission_overrides=permission_overrides||'{"quotes.export":true,"quotes.share":true,"storage.share":true,"storage.upload":true,"communications.share":true}'::jsonb WHERE user_id=$1`,[ids[who]]);
  const app=express();app.use(express.json());const auth=async(req,res,next)=>{try{Object.assign(req,await f.actor(req.get('Authorization')||'alice'));next();}catch(e){res.status(403).json({error:e.code});}};
  const storage=createStorageService({pool,bucket:{},accessPredicate:storagePredicate});await installCommsQuoteExports({app,pool,authRequired:auth,storage});server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));const base='http://127.0.0.1:'+server.address().port;
  const request=(path,body,who='alice')=>fetch(base+'/api/comms/quotes/'+quote+path,{method:body?'POST':'GET',headers:{Authorization:who,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});
  const ctx=await request('/export-context');assert.equal(ctx.status,200);const context=await ctx.json();const asset=randomUUID(),body={id:randomUUID(),source_version:context.version,format:'pdf',files:[{id:asset,original_filename:'Quote.pdf',mime_type:'application/pdf',byte_size:100}]};
  const response=await request('/exports',body);assert.equal(response.status,200,await response.clone().text());const reservation=await response.json();assert.equal(reservation.files[0].source_protected,true);assert.equal(reservation.files[0].visibility,'private');assert.equal(reservation.files[0].cloud_status,'pending');assert.equal((await request('/exports',body)).status,200);
  assert.equal((await pool.query('SELECT source_id FROM comms_asset_provenance WHERE asset_id=$1',[asset])).rows[0].source_id,quote);assert.equal((await pool.query('SELECT title,total_cents FROM quotes WHERE id=$1',[quote])).rows[0].title,'Original Quote');
  await pool.query("UPDATE stored_files SET cloud_status='active' WHERE id=$1",[asset]);const alice=await f.actor('alice'),bob=await f.actor('bob');const messages=createConversationService({pool});const c=await messages.create(alice,{client_key:randomUUID(),member_ids:[ids.bob]});await messages.send(alice,c.id,{client_key:randomUUID(),body:'Protected PDF',asset_ids:[asset]});
  assert.equal((await storage.get(bob,asset)).id,asset);await assert.rejects(storage.get(await f.actor('foreign'),asset),e=>e.status===404);
  await pool.query(`UPDATE employee_permissions SET permission_overrides=permission_overrides||'{"quotes.view":false}'::jsonb WHERE user_id=ANY($1::uuid[])`,[[ids.alice,ids.bob]]);
  for(const who of ['alice','bob']){await assert.rejects(storage.get(await f.actor(who),asset),e=>e.status===404);assert.equal((await request('/export-context',undefined,who)).status,403);}
  assert.equal((await pool.query('SELECT cloud_status FROM stored_files WHERE id=$1',[asset])).rows[0].cloud_status,'active');
  await pool.query(`UPDATE employee_permissions SET permission_overrides=permission_overrides||'{"quotes.view":true}'::jsonb WHERE user_id=$1`,[ids.alice]);await pool.query('UPDATE quotes SET total_cents=4500 WHERE id=$1',[quote]);assert.equal((await request('/exports',{...body,id:randomUUID(),files:[{...body.files[0],id:randomUUID()}]})).status,409);
 }finally{if(server)await new Promise(resolve=>server.close(resolve));await f.close();}
});

test('multi-page export failures roll back quota, assets and provenance; in-flight reservations remain invisible',{timeout:120000},async()=>{
 const f=await createCommsFixture(),{pool,companies,ids}=f;let server,releaseReservation;
 try{
  const quote=randomUUID(),contact=randomUUID();await pool.query('INSERT INTO contacts(id,company_id,name) VALUES($1,$2,$3)',[contact,companies.a,'Atomic customer']);await pool.query('INSERT INTO quotes(id,company_id,contact_id,title,total_cents) VALUES($1,$2,$3,$4,3500)',[quote,companies.a,contact,'Atomic Quote']);
  await pool.query(`UPDATE employee_permissions SET permission_overrides=permission_overrides||'{"quotes.export":true,"quotes.share":true,"storage.share":true,"storage.upload":true,"communications.share":true}'::jsonb WHERE user_id=$1`,[ids.alice]);
  const actor=await f.actor('alice'),storage=createStorageService({pool,bucket:{},accessPredicate:storagePredicate});const initial=await storage.usage(actor);
  let pausedID,notifyReserved;const reserved=new Promise(resolve=>{notifyReserved=resolve;});const resume=new Promise(resolve=>{releaseReservation=resolve;});
  const instrumented={...storage,reserveInTransaction:async(...args)=>{const result=await storage.reserveInTransaction(...args);if(args[2].id===pausedID){notifyReserved();await resume;}return result;}};
  const app=express();app.use(express.json());const auth=async(req,res,next)=>{Object.assign(req,await f.actor('alice'));next();};await installCommsQuoteExports({app,pool,authRequired:auth,storage:instrumented});server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));const base='http://127.0.0.1:'+server.address().port+'/api/comms/quotes/'+quote;
  const version=(await (await fetch(base+'/export-context')).json()).version;
  const page=()=>({id:randomUUID(),original_filename:'Quote page.png',mime_type:'image/png',byte_size:100});
  const request=body=>fetch(base+'/exports',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const failed={id:randomUUID(),source_version:version,format:'images',files:[page(),{...page(),mime_type:'image/jpeg'}]};assert.equal((await request(failed)).status,400);
  assert.equal((await pool.query('SELECT id FROM stored_files WHERE id=ANY($1::uuid[])',[failed.files.map(x=>x.id)])).rowCount,0);
  assert.equal((await pool.query('SELECT asset_id FROM comms_asset_provenance WHERE asset_id=ANY($1::uuid[])',[failed.files.map(x=>x.id)])).rowCount,0);
  assert.equal((await pool.query('SELECT id FROM comms_quote_exports WHERE id=$1',[failed.id])).rowCount,0);
  assert.equal((await pool.query('SELECT id FROM storage_activity WHERE file_id=ANY($1::uuid[])',[failed.files.map(x=>x.id)])).rowCount,0);
  assert.equal((await storage.usage(actor)).reserved_bytes,initial.reserved_bytes);
  await pool.query('UPDATE storage_accounts SET quota_bytes=150 WHERE user_id=$1',[ids.alice]);
  const exceeds={id:randomUUID(),source_version:version,format:'images',files:[page(),page()]};assert.equal((await request(exceeds)).status,413);assert.equal((await storage.usage(actor)).reserved_bytes,0);assert.equal((await pool.query('SELECT id FROM stored_files WHERE id=ANY($1::uuid[])',[exceeds.files.map(x=>x.id)])).rowCount,0);
  await pool.query('UPDATE storage_accounts SET quota_bytes=$2 WHERE user_id=$1',[ids.alice,initial.quota_bytes]);
  const body={id:randomUUID(),source_version:version,format:'images',files:[page(),page()]};pausedID=body.files[0].id;const first=request(body);await reserved;
  // A second DB connection observes neither the pending asset nor quota/audit state
  // while the first page exists inside the unfinished export transaction.
  assert.equal((await pool.query('SELECT id FROM stored_files WHERE id=$1',[pausedID])).rowCount,0);assert.equal((await pool.query('SELECT id FROM comms_quote_exports WHERE id=$1',[body.id])).rowCount,0);
  assert.equal((await pool.query('SELECT COALESCE(sum(byte_size),0)::int AS bytes FROM stored_files WHERE owner_user_id=$1',[ids.alice])).rows[0].bytes,0);
  await assert.rejects(storage.get(actor,pausedID),e=>e.status===404);
  const retry=request(body);releaseReservation();const responses=await Promise.all([first,retry]);for(const response of responses)assert.equal(response.status,200,await response.clone().text());
  const records=(await pool.query('SELECT f.id,f.source_protected,p.source_id FROM stored_files f JOIN comms_asset_provenance p ON p.asset_id=f.id WHERE f.id=ANY($1::uuid[])',[body.files.map(x=>x.id)])).rows;assert.equal(records.length,2);assert.ok(records.every(x=>x.source_protected&&x.source_id===quote));assert.equal((await storage.usage(actor)).reserved_bytes,200);
  await pool.query("UPDATE stored_files SET cloud_status='active' WHERE id=ANY($1::uuid[])",[body.files.map(x=>x.id)]);const file=await storage.get(actor,pausedID);await assert.rejects(storage.patch(actor,pausedID,{expected_version:file.version,visibility:'company'}),e=>e.status===403&&e.code==='protected_visibility');
  await pool.query('DELETE FROM comms_asset_provenance WHERE asset_id=$1',[pausedID]);await assert.rejects(storage.get(actor,pausedID),e=>e.status===404);
 }finally{releaseReservation?.();if(server)await new Promise(resolve=>server.close(resolve));await f.close();}
});
