import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import express from 'express';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {installPayStructureSchema} from '../pay-structures.js';
import {installFinanceSystem} from '../finance.js';
import {encryptAccessToken} from '../finance-plaid-helpers.js';
import {syncPlaidTransactions,syncRecurring} from '../finance-plaid.js';
import {withPlaidBackgroundItem} from '../finance-plaid-lifecycle.js';
import {createEmployeeAccountService} from '../employee-access/service.js';

const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};};
test('Plaid background writes obey private lifecycle after provider latency and retain scoped shared history',{timeout:120000},async()=>{
 const keep=new Set(['PATH','HOME','TMPDIR','LANG','LC_ALL','SHELL','USER','LOGNAME','TERM','TZ']);
 for(const key of Object.keys(process.env))if(!keep.has(key))delete process.env[key];
 process.env.NODE_ENV='test';process.env.FINANCE_TOKEN_ENCRYPTION_KEY='0123456789abcdef0123456789abcdef';
 const local=startLocalPostgres();local.configureEnvironment();let pool;const releases=[];
 try {
  const backend=await import('../index.js');pool=backend.pool;await backend.bootstrap();await installPayStructureSchema(pool);
  const company=randomUUID(),owner=randomUUID(),employee=randomUUID();
  await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id) VALUES($1::uuid,'Plaid lifecycle',$1::text,$2)",[company,owner]);
  for(const [id,role] of [[owner,'employer'],[employee,'employee']]){
   await pool.query('INSERT INTO users(id,email,display_name,company_id,role) VALUES($1,$2,$2,$3,$4)',[id,id+'@example.invalid',company,role]);
   await pool.query("INSERT INTO employee_permissions(user_id,company_id,permission_preset) VALUES($1,$2,'manager')",[id,company]);
  }
  const app=express();await installFinanceSystem({app,pool,authRequired:(_r,_s,n)=>n(),requireEmployer:(_r,_s,n)=>n(),getStripe:()=>null});
  const privateSpace=(await pool.query('SELECT id FROM finance_spaces WHERE owner_id=$1 AND is_default',[employee])).rows[0].id;
  const otherSpace=(await pool.query('SELECT id FROM finance_spaces WHERE owner_id=$1 AND is_default',[owner])).rows[0].id;
  const sharedSpace=randomUUID();await pool.query("INSERT INTO finance_spaces(id,company_id,owner_id,name,kind,audience) VALUES($1,$2,$3,'Shared history','business','company')",[sharedSpace,company,employee]);
  const encrypted=encryptAccessToken('synthetic-token');
  const createItem=async(space)=>{
   const item=(await pool.query("INSERT INTO finance_plaid_items(company_id,finance_space_id,created_by,plaid_item_id,environment,access_token_ciphertext,access_token_iv,access_token_auth_tag) VALUES($1,$2,$3,$4,'sandbox',$5,$6,$7) RETURNING *",[company,space,employee,randomUUID(),encrypted.access_token_ciphertext,encrypted.access_token_iv,encrypted.access_token_auth_tag])).rows[0];
   const account=(await pool.query("INSERT INTO finance_accounts(company_id,finance_space_id,created_by,name,account_type,source,plaid_item_internal_id,plaid_account_id,mask) VALUES($1,$2,$3,'Synthetic bank','checking','plaid',$4,$5,'1234') RETURNING *",[company,space,employee,item.id,randomUUID()])).rows[0];
   return {item,account};
  };
  const personal=await createItem(privateSpace),shared=await createItem(sharedSpace);
  const service=createEmployeeAccountService({pool}),context={userId:owner,companyId:company};
  const transition=async action=>service.transition(context,employee,action,{expected_revision:Number((await pool.query('SELECT account_revision FROM users WHERE id=$1',[employee])).rows[0].account_revision)});
  let calls=0;const emptyProvider={transactionsSync:async()=>{calls++;return {data:{added:[],modified:[],removed:[],has_more:false,next_cursor:'fresh'}};}};
  await transition('lock');
  assert.equal((await syncPlaidTransactions({pool,plaid:emptyProvider,item:personal.item,background:true})).reason,'account_locked');assert.equal(calls,0);
  await transition('unlock');
  const started=deferred(),response=deferred();releases.push(response);
  const delayed=syncPlaidTransactions({pool,item:personal.item,background:true,plaid:{transactionsSync:async()=>{started.resolve();await response.promise;return {data:{added:[],modified:[],removed:[],has_more:false,next_cursor:'must-not-save'}};}}});
  await started.promise;await transition('disable');response.resolve();
  assert.equal((await delayed).reason,'account_disabled');
  assert.equal((await pool.query('SELECT transactions_cursor FROM finance_plaid_items WHERE id=$1',[personal.item.id])).rows[0].transactions_cursor,null);
  assert.equal((await syncPlaidTransactions({pool,plaid:emptyProvider,item:personal.item,background:true})).reason,'account_disabled');assert.equal(calls,0);

  // Identical receipt data in another private space must not be touched by the
  // service-role rematcher. Shared company history continues after disable.
  const receipt=async(space)=>(await pool.query("INSERT INTO finance_receipts(company_id,finance_space_id,created_by,status,merchant_name,normalized_merchant_name,purchase_date,amount_cents,card_last_four,object_key) VALUES($1,$2,$3,'unmatched','Test Store','TEST STORE','2026-10-01',1234,'1234','synthetic/receipt') RETURNING *",[company,space,employee])).rows[0];
  const sharedReceipt=await receipt(sharedSpace),foreignReceipt=await receipt(otherSpace);
  const tx={account_id:shared.account.plaid_account_id,transaction_id:randomUUID(),date:'2026-10-01',amount:12.34,name:'Test Store',merchant_name:'Test Store',pending:false,iso_currency_code:'USD'};
  const synced=await syncPlaidTransactions({pool,item:shared.item,background:true,plaid:{transactionsSync:async()=>({data:{added:[tx],modified:[],removed:[],has_more:false,next_cursor:'shared-ok'}})}});
  assert.equal(synced.added,1);
  const saved=(await pool.query('SELECT * FROM finance_receipts WHERE id=$1',[sharedReceipt.id])).rows[0];assert.equal(saved.status,'matched');assert.ok(saved.transaction_id);
  assert.equal((await pool.query('SELECT status FROM finance_receipts WHERE id=$1',[foreignReceipt.id])).rows[0].status,'unmatched');
  assert.equal((await pool.query('SELECT finance_space_id FROM finance_transactions WHERE id=$1',[saved.transaction_id])).rows[0].finance_space_id,sharedSpace);
  await transition('restore');
  const recurringStarted=deferred(),recurringResponse=deferred();releases.push(recurringResponse);
  const stream={stream_id:randomUUID(),last_amount:{amount:10},average_amount:{amount:10},description:'Synthetic recurring',frequency:'MONTHLY'};
  const recurring=syncRecurring(pool,{transactionsRecurringGet:async()=>{recurringStarted.resolve();await recurringResponse.promise;return {data:{inflow_streams:[],outflow_streams:[stream]}};}},personal.item,{background:true});
  await recurringStarted.promise;await transition('disable');recurringResponse.resolve();assert.equal(await recurring,0);
  assert.equal((await pool.query('SELECT id FROM finance_plaid_recurring_streams WHERE plaid_item_internal_id=$1',[personal.item.id])).rowCount,0);
  assert.equal(await syncRecurring(pool,{transactionsRecurringGet:async()=>({data:{outflow_streams:[stream]}})},shared.item,{background:true}),1);

  // Observe real PostgreSQL blocking, not a timed assumption, in both orders.
  await transition('restore');
  let hook=async()=>{};
  const observed={connect:async()=>{const db=await pool.connect(),pid=(await db.query('SELECT pg_backend_pid() pid')).rows[0].pid;return {query:async(...args)=>{await hook('before',args[0],pid);const result=await db.query(...args);await hook('after',args[0],pid);return result;},release:()=>db.release()};},query:(...args)=>pool.query(...args)};
  const observedService=createEmployeeAccountService({pool:observed});
  const disable=async()=>observedService.transition(context,employee,'disable',{expected_revision:Number((await pool.query('SELECT account_revision FROM users WHERE id=$1',[employee])).rows[0].account_revision)});
  const waitForLock=async pid=>{const end=Date.now()+5000;while(!(await pool.query("SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock'",[pid])).rowCount){assert.ok(Date.now()<end,'competing operation must wait on PostgreSQL lock');await delay(10);}};
  const held=deferred(),releaseWrite=deferred(),disableStarted=deferred();releases.push(releaseWrite);
  hook=async(phase,sql,pid)=>{if(phase==='before'&&sql==='SELECT id FROM companies WHERE id=$1 FOR UPDATE')disableStarted.resolve(pid);};
  const writing=withPlaidBackgroundItem(observed,personal.item,async db=>{held.resolve();await releaseWrite.promise;await db.query("UPDATE finance_plaid_items SET transactions_cursor='write-won' WHERE id=$1",[personal.item.id]);});
  await held.promise;const disabling=disable();await waitForLock(await disableStarted.promise);releaseWrite.resolve();assert.equal((await writing).skipped,false);await disabling;
  assert.equal((await pool.query('SELECT transactions_cursor FROM finance_plaid_items WHERE id=$1',[personal.item.id])).rows[0].transactions_cursor,'write-won');
  hook=async()=>{};await transition('restore');
  const disabled=deferred(),releaseDisable=deferred(),writeStarted=deferred();releases.push(releaseDisable);
  hook=async(phase,sql,pid)=>{if(phase==='after'&&sql.includes('UPDATE users SET deleted_at=')){disabled.resolve();await releaseDisable.promise;}if(phase==='before'&&sql==='SELECT id FROM companies WHERE id=$1 FOR KEY SHARE')writeStarted.resolve(pid);};
  const disablingFirst=disable();await disabled.promise;
  const lateWrite=withPlaidBackgroundItem(observed,personal.item,async()=>assert.fail('disabled private write callback must not execute'));
  await waitForLock(await writeStarted.promise);releaseDisable.resolve();await disablingFirst;assert.equal((await lateWrite).reason,'account_disabled');hook=async()=>{};
  assert.equal((await withPlaidBackgroundItem(pool,{...shared.item,finance_space_id:null},()=>assert.fail())).reason,'space_unassigned');
  await pool.query("UPDATE finance_plaid_items SET status='disconnected',disconnected_at=now() WHERE id=$1",[shared.item.id]);
  assert.equal((await syncPlaidTransactions({pool,item:shared.item,plaid:emptyProvider,background:true})).reason,'disconnected');assert.equal(calls,0);
  assert.equal((await pool.query("SELECT nullif(current_setting('wolf.finance_space',true),'') space")).rows[0].space,null);
 }finally{for(const release of releases)release.resolve();if(pool)await pool.end();local.stop();}
});
