import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import express from 'express';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {installPayStructureSchema} from '../pay-structures.js';
import {installFinanceSystem} from '../finance.js';
import {personalFinanceSpace,withFinanceSpace} from '../finance-spaces.js';
import {createEmployeeAccountService} from '../employee-access/service.js';

const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};};
test('Finance space changes serialize with disable and recheck account state after waiting',{timeout:120000},async()=>{
 const keep=new Set(['PATH','HOME','TMPDIR','LANG','LC_ALL','SHELL','USER','LOGNAME','TERM','TZ']);for(const key of Object.keys(process.env))if(!keep.has(key))delete process.env[key];process.env.NODE_ENV='test';
 const local=startLocalPostgres();local.configureEnvironment();let pool,server;
 const releases=[];
 try {
  const backend=await import('../index.js');pool=backend.pool;await backend.bootstrap();await installPayStructureSchema(pool);
  const company=randomUUID(),owner=randomUUID(),employee=randomUUID();
  await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id) VALUES($1::uuid,'Finance lifecycle',$1::text,$2)",[company,owner]);
  for(const [id,role] of [[owner,'employer'],[employee,'employee']]){
   await pool.query('INSERT INTO users(id,email,display_name,company_id,role) VALUES($1,$2,$2,$3,$4)',[id,id+'@example.invalid',company,role]);
   await pool.query("INSERT INTO employee_permissions(user_id,company_id,permission_preset) VALUES($1,$2,'manager')",[id,company]);
  }
  let hook=async()=>{};
  const observed={query:(...args)=>pool.query(...args),connect:async()=>{
   const client=await pool.connect(),pid=(await client.query('SELECT pg_backend_pid() pid')).rows[0].pid;
   return {query:async(...args)=>{await hook('before',args[0],pid);const result=await client.query(...args);await hook('after',args[0],pid);return result;},release:()=>client.release()};
  }};
  const app=express();app.use(express.json());
  // Deliberately emulate a request authenticated before a concurrent disable;
  // mutation boundaries must independently recheck the current account.
  await installFinanceSystem({app,pool:observed,authRequired:(req,_res,next)=>{req.userId=employee;req.companyId=company;next();},requireEmployer:(_req,_res,next)=>next(),getStripe:()=>null});
  server=await new Promise(r=>{const s=app.listen(0,'127.0.0.1',()=>r(s));});
  const api=async(path,body,method='POST')=>{
   const response=await fetch(`http://127.0.0.1:${server.address().port}/api/finance${path}`,{method,headers:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
   return {status:response.status,body:await response.json()};
  };
  const source=(await personalFinanceSpace(pool,employee,company)).id,destination=randomUUID(),account=randomUUID();
  await pool.query("INSERT INTO finance_spaces(id,company_id,owner_id,name,kind,audience) VALUES($1,$2,$3,'Other personal business','business','private')",[destination,company,employee]);
  await pool.query("INSERT INTO finance_accounts(id,company_id,created_by,finance_space_id,name,account_type) VALUES($1,$2,$3,$4,'Private account','checking')",[account,company,employee,source]);
  const service=createEmployeeAccountService({pool:observed}),context={userId:owner,companyId:company};
  const waitForLock=async pid=>{const limit=Date.now()+5000;while(!(await pool.query("SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock'",[pid])).rowCount){assert.ok(Date.now()<limit,'competing request must wait on the database lock');await delay(10);}};
  let transfer={kind:'accounts',record_id:account,source_space_id:source,destination_space_id:destination};
  let preview=await api('/spaces/transfer-preview',transfer);assert.equal(preview.status,200,JSON.stringify(preview));

  // Transfer wins: disable cannot invalidate the operation midway through its
  // connected evidence update. It waits, then revokes the employee afterward.
  const acquired=deferred(),releaseTransfer=deferred(),disableStarted=deferred();releases.push(releaseTransfer);
  let held=false;
  hook=async(phase,sql,pid)=>{
   if(phase==='after'&&sql==='SELECT id FROM companies WHERE id=$1 FOR KEY SHARE'&&!held){held=true;acquired.resolve();await releaseTransfer.promise;}
   if(phase==='before'&&sql==='SELECT id FROM companies WHERE id=$1 FOR UPDATE')disableStarted.resolve(pid);
  };
  const moving=api('/spaces/transfer',{...transfer,confirmation_token:preview.body.confirmation_token});await acquired.promise;
  const disabling=service.transition(context,employee,'disable',{expected_revision:1});await waitForLock(await disableStarted.promise);
  releaseTransfer.resolve();assert.equal((await moving).status,200);await disabling;hook=async()=>{};
  assert.equal((await pool.query('SELECT finance_space_id FROM finance_accounts WHERE id=$1',[account])).rows[0].finance_space_id,destination);
  await service.transition(context,employee,'restore',{expected_revision:2});
  transfer={...transfer,source_space_id:destination,destination_space_id:source};
  preview=await api('/spaces/transfer-preview',transfer);assert.equal(preview.status,200,JSON.stringify(preview));

  // Disable wins: a formerly authenticated transfer waits, then sees the current
  // disabled state and leaves the private records exactly where they were.
  const disabled=deferred(),releaseDisable=deferred(),transferStarted=deferred();releases.push(releaseDisable);
  hook=async(phase,sql,pid)=>{
   if(phase==='after'&&sql.includes('UPDATE users SET deleted_at=')){disabled.resolve();await releaseDisable.promise;}
   if(phase==='before'&&sql==='SELECT id FROM companies WHERE id=$1 FOR KEY SHARE')transferStarted.resolve(pid);
  };
  const disablingFirst=service.transition(context,employee,'disable',{expected_revision:3});await disabled.promise;
  const movingLate=api('/spaces/transfer',{...transfer,confirmation_token:preview.body.confirmation_token});await waitForLock(await transferStarted.promise);
  releaseDisable.resolve();await disablingFirst;const denied=await movingLate;hook=async()=>{};
  assert.equal(denied.status,401,JSON.stringify(denied));assert.equal(denied.body.message,'Your account has been disabled.');
  assert.equal((await pool.query('SELECT finance_space_id FROM finance_accounts WHERE id=$1',[account])).rows[0].finance_space_id,destination);
  assert.equal((await api('/spaces/'+destination,{name:'Should not change',kind:'business',audience:'private',member_ids:[],expected_revision:1},'PUT')).status,401);
  assert.equal((await api('/spaces',undefined,'GET')).status,401);
  // A delayed initializer may not recreate private spaces after a purge.
  await pool.query('DELETE FROM finance_space_audit WHERE space_id=$1',[source]);
  await pool.query('DELETE FROM finance_spaces WHERE id=$1',[source]);
  await assert.rejects(personalFinanceSpace(pool,employee,company),e=>e.status===401&&e.code==='account_disabled');
  assert.equal((await pool.query('SELECT id FROM finance_spaces WHERE owner_id=$1 AND is_default',[employee])).rowCount,0);
  await service.transition(context,employee,'restore',{expected_revision:4});
  // The database role may already be open when a lock arrives. RLS and the
  // narrow source-lock bridge must deny it independently of HTTP middleware.
  const existingSession=await pool.connect();
  try {
   await existingSession.query('BEGIN');
   await existingSession.query("SELECT set_config('wolf.finance_actor',$1,true),set_config('wolf.finance_company',$2,true),set_config('wolf.finance_space',$3,true)",[employee,company,destination]);
   await existingSession.query('SET LOCAL ROLE wolf_finance_request');
   assert.equal((await existingSession.query('SELECT id FROM finance_accounts WHERE id=$1',[account])).rowCount,1);
   await service.transition(context,employee,'lock',{expected_revision:5});
   const locked=await api('/spaces/transfer-preview',transfer);assert.equal(locked.status,401);assert.equal(locked.body.message,'Your account is locked by your administrator.');
   assert.equal((await existingSession.query('SELECT id FROM finance_accounts WHERE id=$1',[account])).rowCount,0);
   await assert.rejects(existingSession.query("SELECT wolf_finance_lock_source('users',$1,$2::text[])",[company,[employee]]),e=>e.code==='42501');
  }finally{await existingSession.query('ROLLBACK');existingSession.release();}
  const transition=async action=>service.transition(context,employee,action,{expected_revision:Number((await pool.query('SELECT account_revision FROM users WHERE id=$1',[employee])).rows[0].account_revision)});
  await transition('unlock');
  const update=['UPDATE finance_accounts SET current_balance_cents=current_balance_cents+1 WHERE id=$1 RETURNING current_balance_cents',[account]];
  for(const explicit of [false,true]) {
   await withFinanceSpace(observed,employee,company,destination,async scoped=>{
    const writer=await scoped.connect();
    try {
     const entered=deferred(),release=deferred(),competing=deferred();releases.push(release);let once=false;
     hook=async(phase,sql,pid)=>{
      if(phase==='after'&&sql==='SELECT public.wolf_finance_transaction_actor() AS actor'&&!once){once=true;entered.resolve();await release.promise;}
      if(phase==='before'&&sql==='SELECT id FROM companies WHERE id=$1 FOR UPDATE')competing.resolve(pid);
     };
     const writing=(async()=>{if(explicit)await writer.query('BEGIN');const result=await writer.query(...update);if(explicit)await writer.query('COMMIT');return result;})();
     await entered.promise;const disabling=transition('disable');await waitForLock(await competing.promise);
     release.resolve();assert.equal((await writing).rowCount,1,'winning Finance write commits before disable');await disabling;hook=async()=>{};
    }finally{await writer.release();}
   });
   await transition('restore');
   await withFinanceSpace(observed,employee,company,destination,async scoped=>{
    const writer=await scoped.connect();
    try {
     const before=Number((await pool.query('SELECT current_balance_cents FROM finance_accounts WHERE id=$1',[account])).rows[0].current_balance_cents);
     const entered=deferred(),release=deferred(),competing=deferred();releases.push(release);
     hook=async(phase,sql,pid)=>{
      if(phase==='after'&&sql.includes('UPDATE users SET deleted_at=')){entered.resolve();await release.promise;}
      if(phase==='before'&&sql==='SELECT public.wolf_finance_transaction_actor() AS actor')competing.resolve(pid);
     };
     const disabling=transition('disable');await entered.promise;
     const writing=(async()=>{if(explicit)await writer.query('BEGIN');const result=await writer.query(...update);if(explicit)await writer.query('COMMIT');return result;})();
     const denied=assert.rejects(writing,e=>e.status===401&&e.code==='account_disabled');
     await waitForLock(await competing.promise);release.resolve();await disabling;await denied;hook=async()=>{};
     assert.equal(Number((await pool.query('SELECT current_balance_cents FROM finance_accounts WHERE id=$1',[account])).rows[0].current_balance_cents),before,'late Finance write cannot change retained data');
    }finally{await writer.release();}
   });
   await transition('restore');
  }
  // Error rollback must restore the restricted role before a pooled connection
  // is reused, and normal single-statement writes must actually commit.
  await withFinanceSpace(observed,employee,company,destination,async scoped=>{
   const writer=await scoped.connect();try {
    await assert.rejects(writer.query('SELECT missing_fixture_column FROM finance_accounts'),e=>e.code==='42703');
    assert.equal((await writer.query('SELECT current_user AS name')).rows[0].name,'wolf_finance_request');
    await writer.query(...update);
   }finally{await writer.release();}
  });
  assert.equal((await pool.query('SELECT current_user=session_user AS clean')).rows[0].clean,true);
 }finally{for(const gate of releases)gate.resolve();if(server)await new Promise(r=>server.close(r));if(pool)await pool.end();local.stop();}
});
