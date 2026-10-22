import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {installFinanceSystem} from '../finance.js';
import {installPayStructureSchema} from '../pay-structures.js';
import {createEmployeeAccountService} from '../employee-access/service.js';
import {installPrivatePurgeSchema,createPrivatePurge} from '../employee-access/purge.js';
import {installStorageSchema} from '../media-storage/schema.js';
import {createCompanyStorage} from '../employee-access/storage-usage.js';

test('mixed private Finance purge removes independent bundles, retains connected company evidence, and retries actual receipt bytes',{timeout:120000},async()=>{
 const keep=new Set(['PATH','HOME','TMPDIR','LANG','LC_ALL','SHELL','USER','LOGNAME','TERM','TZ']);for(const k of Object.keys(process.env))if(!keep.has(k))delete process.env[k];process.env.NODE_ENV='test';
 const local=startLocalPostgres();local.configureEnvironment();let pool;
 try{
  const backend=await import('../index.js');pool=backend.pool;await backend.bootstrap();await installPayStructureSchema(pool);await installStorageSchema(pool);await installPrivatePurgeSchema(pool);
  const company=randomUUID(),owner=randomUUID(),employee=randomUUID(),other=randomUUID();
  await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id) VALUES($1::uuid,'Mixed Finance',$1::text,$2)",[company,owner]);
  for(const [id,role] of [[owner,'employer'],[employee,'employee'],[other,'employee']]){await pool.query('INSERT INTO users(id,email,display_name,role,company_id) VALUES($1,$2,$2,$3,$4)',[id,id+'@example.invalid',role,company]);await pool.query("INSERT INTO employee_permissions(user_id,company_id,permission_preset) VALUES($1,$2,'manager')",[id,company]);}
  const app=express();await installFinanceSystem({app,pool,authRequired:(_r,_s,n)=>n(),requireEmployer:(_r,_s,n)=>n(),getStripe:()=>null});
  const mixed=(await pool.query('SELECT id FROM finance_spaces WHERE owner_id=$1 AND is_default',[employee])).rows[0].id;
  const shared=randomUUID(),business=randomUUID(),externalSpace=randomUUID();
  await pool.query("INSERT INTO finance_spaces(id,company_id,owner_id,name,kind,audience,includes_company_activity) VALUES($1,$3,$4,'Shared','business','company',false),($2,$3,$4,'Private company activity','business','private',true)",[shared,business,company,employee]);
  await pool.query("INSERT INTO finance_spaces(id,company_id,owner_id,name,kind,audience) VALUES($1,$2,$3,'External reference','business','private')",[externalSpace,company,employee]);
  const account=async(space=mixed)=>{const id=randomUUID();await pool.query("INSERT INTO finance_accounts(id,company_id,name,account_type,created_by,finance_space_id) VALUES($1,$2,'Account','checking',$3,$4)",[id,company,employee,space]);await pool.query("INSERT INTO finance_account_entries(company_id,account_id,entry_type,amount_delta_cents,previous_balance_cents,resulting_balance_cents,created_by,finance_space_id) VALUES($1,$2,'initial_balance',700,0,700,$3,$4)",[company,id,employee,space]);return id;};
  const closedSpace=randomUUID(),personalClosedSpace=randomUUID();
  for(const id of [closedSpace,personalClosedSpace])await pool.query("INSERT INTO finance_spaces(id,company_id,owner_id,name,kind,audience) VALUES($1,$2,$3,'Closed ledger','business','private')",[id,company,employee]);
  const closedAccount=await account(closedSpace),personalClosedAccount=await account(personalClosedSpace);
  const close=async space=>(await pool.query("INSERT INTO finance_statement_period_closes(company_id,version,coverage_profile_version,coverage_start_date,as_of_date,opening_evidence_fingerprint,source_inventory_fingerprint,workflow_evidence_fingerprint,evidence_snapshot,client_request_id,request_fingerprint,reason,reviewed_by,finance_space_id) VALUES($1,1,1,'2026-01-01','2026-10-01',$2,$2,$2,'{}',$3,$2,'Closed history',$4,$5) RETURNING id",[company,'b'.repeat(64),randomUUID(),employee,space])).rows[0].id;
  const closedStatement=await close(closedSpace),personalStatement=await close(personalClosedSpace);
  await pool.query("INSERT INTO finance_commission_events(company_id,employee_id,event_kind,earned_date,commission_cents,regular_rate_treatment,source_type,source_label,client_request_id,request_fingerprint,reason,created_by,finance_space_id) VALUES($1,$2,'earning','2026-10-01',700,'included','manual','Closed sale',$3,'fixture','History',$2,$4)",[company,employee,randomUUID(),closedSpace]);
  const privateAccount=await account(),historyAccount=await account(),unknownAccount=await account(),sharedAccount=await account(shared),businessAccount=await account(business),crossSpaceAccount=await account();
  // Real commission snapshots contain soft links, not FK declarations.
  const commission=(await pool.query("INSERT INTO finance_commission_events(company_id,employee_id,event_kind,earned_date,commission_cents,regular_rate_treatment,source_type,source_label,client_request_id,request_fingerprint,reason,created_by,finance_space_id,source_snapshot) VALUES($1,$2,'earning','2026-10-01',700,'included','manual','Completed sale',$3,'fixture','History',$2,$4,$5) RETURNING id",[company,employee,randomUUID(),mixed,JSON.stringify({finance_account_id:historyAccount})])).rows[0].id;
  // A polymorphic journal source must preserve both directions of the evidence
  // graph even though its source_id has no foreign key.
  const journal=(await pool.query("INSERT INTO finance_journal_entries(company_id,entry_date,entry_kind,description,client_request_id,request_fingerprint,reason,source_type,source_id,source_version,created_by,finance_space_id) VALUES($1,'2026-10-01','adjustment','Company evidence',$2,$3,'History','finance_transaction',$4,1,$5,$6) RETURNING id",[company,randomUUID(),'a'.repeat(64),commission,employee,mixed])).rows[0].id;
  const ai=async(content,scope='user',space=mixed)=>{const id=randomUUID();await pool.query('INSERT INTO finance_ai_conversations(id,company_id,title,owner_user_id,created_by,finance_space_id) VALUES($1,$2,$3,$4,$4,$5)',[id,company,content,employee,space]);await pool.query("INSERT INTO finance_ai_messages(company_id,conversation_id,role,content,created_by,finance_space_id) VALUES($1,$2,'user',$3,$4,$5)",[company,id,content,employee,space]);const memory=randomUUID();await pool.query('INSERT INTO finance_ai_memories(id,company_id,owner_user_id,memory_scope,content,source_conversation_id,created_by,finance_space_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[memory,company,scope==='user'?employee:null,scope,content,id,employee,space]);return {id,memory};};
  const outwardAI=await ai('Keep evidence for shared account '+sharedAccount);
  const closedPersonalAI=await ai('Private context outside the closed ledger','user',closedSpace);
  const personalAI=await ai('Delete my personal context'),companyAI=await ai('Retain approved company policy','company'),sharedAI=await ai('Retain shared soft link '+crossSpaceAccount,'company',shared);
  await pool.query('CREATE TABLE finance_future_history(id uuid PRIMARY KEY,company_id uuid,finance_space_id uuid REFERENCES finance_spaces(id),account_id uuid REFERENCES finance_accounts(id) ON DELETE CASCADE,payload jsonb)');
  const future=randomUUID();await pool.query("INSERT INTO finance_future_history VALUES($1,$2,$3,$4,'{}')",[future,company,mixed,unknownAccount]);
  const receipt=async(key,size,space=mixed)=>{const id=randomUUID();await pool.query("INSERT INTO finance_receipts(id,company_id,created_by,finance_space_id,object_key,file_size_bytes,status) VALUES($1,$2,$3,$4,$5,$6,'unmatched')",[id,company,employee,space,key,size]);return id;};
  const privateReceipt=await receipt('mixed/private',80),duplicateReceipt=await receipt('mixed/duplicate',100),sharedReceipt=await receipt('mixed/duplicate',100,shared),externalReceipt=await receipt('mixed/external',60,externalSpace);
  await pool.query('CREATE TABLE retained_external_receipt(id uuid PRIMARY KEY,receipt_id uuid REFERENCES finance_receipts(id) ON DELETE CASCADE)');await pool.query('INSERT INTO retained_external_receipt VALUES($1,$2)',[randomUUID(),externalReceipt]);
  const staleAccount=await account();
  const service=createEmployeeAccountService({pool}),context={userId:owner,companyId:company};await service.transition(context,employee,'disable',{expected_revision:1});
  let failure=true;const removed=[];const purge=createPrivatePurge({pool,bucket:{abort:async()=>{},remove:async row=>{if(failure)throw Error('fixture provider unavailable');removed.push(row.object_key);}}}),usage=createCompanyStorage({pool});
  const preview=await purge.preview(context,employee);assert.ok(preview.private_finance_records_in_retained_spaces>=8);assert.equal(preview.retained_finance_spaces,4);assert.equal(preview.tracked_original_bytes,80);
  // New retained evidence changes the exact plan even without an account revision.
  await pool.query('UPDATE finance_future_history SET payload=$2 WHERE id=$1',[future,JSON.stringify({late_account:staleAccount})]);
  await assert.rejects(purge.request(context,employee,{expected_revision:preview.expected_revision,preview_token:preview.preview_token,confirmation:'DELETE PRIVATE DATA'}),e=>e.code==='purge_preview_changed');
  assert.equal((await pool.query('SELECT id FROM finance_accounts WHERE id=$1',[privateAccount])).rowCount,1);
  const keepRows=[['finance_statement_period_closes',[closedStatement]],['finance_accounts',[closedAccount,historyAccount,unknownAccount,sharedAccount,businessAccount,crossSpaceAccount,staleAccount]],['finance_commission_events',[commission]],['finance_journal_entries',[journal]],['finance_ai_conversations',[companyAI.id,sharedAI.id,outwardAI.id]],['finance_ai_memories',[companyAI.memory,sharedAI.memory,outwardAI.memory]],['finance_receipts',[sharedReceipt,externalReceipt]],['finance_future_history',[future]]];
  const snapshots=new Map();for(const [table,ids] of keepRows)snapshots.set(table,(await pool.query(`SELECT row_to_json(t) data FROM ${table} t WHERE id=ANY($1::uuid[]) ORDER BY id`,[ids])).rows);
  assert.equal((await usage.usage(context)).totals.tracked_cloud_bytes,240);
  const current=await purge.preview(context,employee);await purge.request(context,employee,{expected_revision:current.expected_revision,preview_token:current.preview_token,confirmation:'DELETE PRIVATE DATA'});
  for(const [table,ids] of [['finance_statement_period_closes',[personalStatement]],['finance_accounts',[privateAccount,personalClosedAccount]],['finance_ai_conversations',[personalAI.id,closedPersonalAI.id]],['finance_ai_memories',[personalAI.memory,closedPersonalAI.memory]],['finance_receipts',[privateReceipt,duplicateReceipt]]])assert.equal((await pool.query(`SELECT id FROM ${table} WHERE id=ANY($1::uuid[])`,[ids])).rowCount,0,table+' eligible private rows removed');
  assert.equal((await pool.query('SELECT id FROM finance_account_entries WHERE account_id=$1',[privateAccount])).rowCount,0);
  assert.equal((await pool.query('SELECT id FROM finance_spaces WHERE id=$1',[personalClosedSpace])).rowCount,0);
  assert.equal((await pool.query('SELECT id FROM finance_ai_messages WHERE conversation_id=$1',[personalAI.id])).rowCount,0);
  for(const [table,ids] of keepRows)assert.deepEqual((await pool.query(`SELECT row_to_json(t) data FROM ${table} t WHERE id=ANY($1::uuid[]) ORDER BY id`,[ids])).rows,snapshots.get(table),table+' remains byte-for-byte identical');
  await purge.tick();assert.deepEqual(removed,[]);assert.equal((await usage.usage(context)).totals.tracked_cloud_bytes,240);assert.equal((await usage.usage(context)).totals.purging_private_bytes,80);
  failure=false;await pool.query("UPDATE employee_private_objects SET next_attempt_at=now()-interval '1 second'");await purge.tick();assert.deepEqual(removed,['mixed/private']);assert.equal((await usage.usage(context)).totals.tracked_cloud_bytes,160);assert.equal((await usage.usage(context)).totals.recoverable_private_bytes,0);assert.equal((await usage.usage(context)).totals.retained_reference_bytes,60);
  assert.equal((await pool.query('SELECT private_data_state FROM users WHERE id=$1',[employee])).rows[0].private_data_state,'purged');
 }finally{if(pool)await pool.end();local.stop();}
});
