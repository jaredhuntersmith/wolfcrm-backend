import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {Readable} from 'node:stream';
import express from 'express';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {installFinanceSystem} from '../finance.js';
import {installPayStructureSchema} from '../pay-structures.js';
import {installMediaStorage} from '../media-storage/index.js';

test('receipt delivery rechecks Finance space, capability and account on every byte request',{timeout:120000},async()=>{
 const keep=new Set(['PATH','HOME','TMPDIR','LANG','LC_ALL','SHELL','USER','LOGNAME','TERM','TZ']);
 for(const key of Object.keys(process.env))if(!keep.has(key))delete process.env[key];process.env.NODE_ENV='test';
 const local=startLocalPostgres();local.configureEnvironment();let pool,server,storage;
 try{
  const backend=await import('../index.js');pool=backend.pool;await backend.bootstrap();await installPayStructureSchema(pool);
  const company=randomUUID(),owner=randomUUID(),employee=randomUUID(),peer=randomUUID();
  await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id) VALUES($1::uuid,'Receipt delivery fixture',$1::text,$2)",[company,owner]);
  for(const [id,name,role] of [[owner,'owner','employer'],[employee,'employee','employee'],[peer,'peer','employee']]){
   await pool.query('INSERT INTO users(id,email,display_name,role,company_id) VALUES($1,$2,$2,$3,$4)',[id,name+'@example.invalid',role,company]);
   await pool.query("INSERT INTO employee_permissions(user_id,company_id,permission_preset,permission_overrides) VALUES($1,$2,'manager','{\"finance.view\":true,\"finance.receipts.view\":true}')",[id,company]);
   await pool.query('INSERT INTO sessions(token,user_id) VALUES($1,$2)',[name+'-token',id]);
  }
  const app=express();app.use(express.json());const env={NODE_ENV:'test'};
  storage=await installMediaStorage({app,pool,authRequired:backend.authRequired,startWorker:false,env,bucket:{open:async file=>{assert.equal(file.storage_provider,'legacy_media');return {Body:Readable.from([Buffer.from('receipt')]),ContentLength:7};}}});
  app.locals.mediaStorage=storage;
  await installFinanceSystem({app,pool,authRequired:backend.authRequired,requireEmployer:(_r,_s,n)=>n(),getStripe:()=>null});
  const privateSpace=(await pool.query('SELECT id FROM finance_spaces WHERE owner_id=$1 AND is_default',[employee])).rows[0].id;
  const sharedSpace=randomUUID();await pool.query("INSERT INTO finance_spaces(id,company_id,owner_id,name,kind,audience) VALUES($1,$2,$3,'Selected space','business','selected')",[sharedSpace,company,employee]);
  await pool.query('INSERT INTO finance_space_members(space_id,user_id) VALUES($1,$2)',[sharedSpace,peer]);
  const receipts=[];
  for(const space of [privateSpace,sharedSpace]){const id=randomUUID();receipts.push(id);await pool.query("INSERT INTO finance_receipts(id,company_id,created_by,finance_space_id,object_key,thumbnail_object_key,status) VALUES($1,$2,$3,$4,$5,$6,'unmatched')",[id,company,employee,space,`companies/${company}/finance-receipts/${id}/original.jpg`,`companies/${company}/finance-receipts/${id}/thumbnail.jpg`]);}
  server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});const base='http://127.0.0.1:'+server.address().port;env.PUBLIC_BACKEND_URL=base;
  const issue=(name,id,space,thumbnail=false)=>fetch(`${base}/api/finance/receipts/${id}/download-url?thumbnail=${thumbnail}`,{headers:{Authorization:'Bearer '+name+'-token','X-Finance-Space':space}});
  let response=await issue('employee',receipts[0],privateSpace);assert.equal(response.status,200);const personal=(await response.json()).download_url;
  assert.ok(personal.startsWith(base+'/api/storage/delivery/'));assert.equal(await (await fetch(personal)).text(),'receipt');
  assert.equal((await issue('owner',receipts[0],privateSpace)).status,404,'employer has no private Finance override');
  response=await issue('peer',receipts[1],sharedSpace,true);assert.equal(response.status,200);const shared=(await response.json()).download_url;
  assert.equal(await (await fetch(shared)).text(),'receipt');
  await pool.query('DELETE FROM finance_space_members WHERE space_id=$1 AND user_id=$2',[sharedSpace,peer]);assert.equal((await fetch(shared)).status,404);
  await pool.query("UPDATE employee_permissions SET permission_overrides='{\"finance.view\":true,\"finance.receipts.view\":false}' WHERE user_id=$1",[employee]);assert.equal((await fetch(personal)).status,403);
  await pool.query("UPDATE employee_permissions SET permission_overrides='{\"finance.view\":true,\"finance.receipts.view\":true}' WHERE user_id=$1",[employee]);
  await pool.query('UPDATE users SET locked_at=now() WHERE id=$1',[employee]);assert.equal((await fetch(personal)).status,403);
  await pool.query('UPDATE users SET locked_at=NULL WHERE id=$1',[employee]);await pool.query("DELETE FROM sessions WHERE token='employee-token'");assert.equal((await fetch(personal)).status,401);
 }finally{storage?.stop();if(server){server.closeAllConnections?.();await new Promise(r=>server.close(r));}if(pool)await pool.end();local.stop();}
});
