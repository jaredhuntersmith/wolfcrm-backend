import test from 'node:test';import assert from 'node:assert/strict';import {randomUUID} from 'node:crypto';import express from 'express';
import {startLocalPostgres} from './helpers/local-postgres.js';import {installPayStructureSchema} from '../pay-structures.js';
import {installFinanceSystem} from '../finance.js';import {installStorageSchema} from '../media-storage/schema.js';
import {createCompanyStorage} from '../employee-access/storage-usage.js';
import {installFocusSchema} from '../focus.js';import {installIdeaParking} from '../idea-parking.js';
import {createEmployeeAccountService} from '../employee-access/service.js';import {installPrivatePurgeSchema,createPrivatePurge} from '../employee-access/purge.js';

test('expiration purges private Finance and personal domains while retaining shared and company financial attribution',{timeout:120000},async()=>{
 const keep=new Set(['PATH','HOME','TMPDIR','LANG','LC_ALL','SHELL','USER','LOGNAME','TERM','TZ']);for(const key of Object.keys(process.env))if(!keep.has(key))delete process.env[key];process.env.NODE_ENV='test';
 const local=startLocalPostgres();local.configureEnvironment();let pool;
 try{
  const backend=await import('../index.js');pool=backend.pool;await backend.bootstrap();await installPayStructureSchema(pool);await installStorageSchema(pool);await installPrivatePurgeSchema(pool);await installFocusSchema(pool);
  const company=randomUUID(),owner=randomUUID(),employee=randomUUID(),other=randomUUID();await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id) VALUES($1::uuid,'Purge finance fixture',$1::text,$2)",[company,owner]);
  for(const [id,role] of [[owner,'employer'],[employee,'employee'],[other,'employee']]){await pool.query('INSERT INTO users(id,email,display_name,role,company_id) VALUES($1,$2,$2,$3,$4)',[id,id+'@example.invalid',role,company]);await pool.query("INSERT INTO employee_permissions(user_id,company_id,permission_preset) VALUES($1,$2,'manager')",[id,company]);}
  const app=express();app.use(express.json());await installFinanceSystem({app,pool,authRequired:(_r,_s,n)=>n(),requireEmployer:(_r,_s,n)=>n(),getStripe:()=>null});await installIdeaParking({app,pool,authRequired:(_r,_s,n)=>n()});await installPrivatePurgeSchema(pool);
  const privateSpace=(await pool.query('SELECT id FROM finance_spaces WHERE owner_id=$1 AND is_default',[employee])).rows[0].id,otherSpace=(await pool.query('SELECT id FROM finance_spaces WHERE owner_id=$1 AND is_default',[other])).rows[0].id;
  const shared=randomUUID();await pool.query("INSERT INTO finance_spaces(id,company_id,owner_id,name,kind,audience,includes_company_activity) VALUES($1,$2,$3,'Retained business','business','company',true)",[shared,company,employee]);
  const privateAccount=randomUUID(),sharedAccount=randomUUID(),otherAccount=randomUUID();
  for(const [id,space] of [[privateAccount,privateSpace],[sharedAccount,shared],[otherAccount,otherSpace]]){await pool.query("INSERT INTO finance_accounts(id,company_id,name,account_type,created_by,finance_space_id) VALUES($1,$2,'Private or company account','checking',$3,$4)",[id,company,employee,space]);await pool.query("INSERT INTO finance_account_entries(company_id,account_id,entry_type,amount_delta_cents,previous_balance_cents,resulting_balance_cents,created_by,finance_space_id) VALUES($1,$2,'initial_balance',42,0,42,$3,$4)",[company,id,employee,space]);}
  await pool.query("INSERT INTO focus_settings(user_id,company_id,config) VALUES($1,$2,'{\"private\":true}')",[employee,company]);
  await pool.query("INSERT INTO idea_parking_lists(id,user_id,company_id,name,visibility) VALUES('private',$1,$2,'Personal ideas','private'),('shared',$1,$2,'Company ideas','company')",[employee,company]);await pool.query("INSERT INTO idea_parking_ideas(id,user_id,company_id,text,list_id) VALUES('privateidea',$1,$2,'Private idea','private'),('sharedidea',$1,$2,'Retain company idea','shared')",[employee,company]);
  // Real company history uses the retained user identity, even where legacy
  // Finance placed employee-created company records in a private workspace.
  await pool.query("UPDATE users SET photo_url='https://example.invalid/history-photo.jpg' WHERE id=$1",[employee]);
  const historicalSpace=randomUUID();await pool.query("INSERT INTO finance_spaces(id,company_id,owner_id,name,kind,audience) VALUES($1,$2,$3,'Historical ledger','business','private')",[historicalSpace,company,employee]);
  await pool.query("INSERT INTO finance_commission_events(company_id,employee_id,event_kind,earned_date,commission_cents,regular_rate_treatment,source_type,source_label,client_request_id,request_fingerprint,reason,created_by,finance_space_id) VALUES($1,$2,'earning','2026-10-01',700,'included','manual','Historical commission',$3,'fixture','Completed sale',$2,$4)",[company,employee,randomUUID(),historicalSpace]);
  await pool.query("INSERT INTO employee_pay_structures(company_id,employee_id,effective_from,hourly_rate_cents,created_by) VALUES($1,$2,'2026-01-01',2500,$2)",[company,employee]);
  await pool.query("INSERT INTO time_clock_entries(id,user_id,company_id,start_at,end_at,created_by) VALUES('history-hours',$1,$2,'2026-10-01T12:00:00Z','2026-10-01T20:00:00Z',$1)",[employee,company]);
  await pool.query("INSERT INTO schedule_events(id,user_id,company_id,title,start_at,end_at,finished_at,sales_user_ids,worker_user_ids) VALUES('history-job',$1,$2,'Completed job','2026-10-01T12:00:00Z','2026-10-01T20:00:00Z','2026-10-01T20:00:00Z',$3,$3)",[employee,company,JSON.stringify([employee])]);
  await pool.query("INSERT INTO mileage_daily_logs(id,company_id,employee_id,service_date,status,total_miles,rate_cents_per_mile,reimbursement_cents) VALUES('history-mileage',$1,$2,'2026-10-01','approved',10,70,700)",[company,employee]);
  const historyTables=['employee_pay_structures','time_clock_entries','schedule_events','mileage_daily_logs','finance_commission_events'];
  const beforeHistory={};for(const table of historyTables)beforeHistory[table]=(await pool.query(`SELECT row_to_json(t) data FROM ${table} t WHERE company_id=$1 ORDER BY id`,[company])).rows;
  for(const [space,key,size] of [[privateSpace,'receipt/private',80],[privateSpace,'receipt/shared',100],[shared,'receipt/shared',100]])await pool.query("INSERT INTO finance_receipts(company_id,created_by,finance_space_id,object_key,file_size_bytes,status) VALUES($1,$2,$3,$4,$5,'unmatched')",[company,employee,space,key,size]);
  const service=createEmployeeAccountService({pool}),context={userId:owner,companyId:company};await service.transition(context,employee,'disable',{expected_revision:1});await pool.query("UPDATE users SET recovery_until=now()-interval '1 second' WHERE id=$1",[employee]);
  const removed=[];const bucket={abort:async()=>{},remove:async row=>removed.push(row.object_key)};const purge=createPrivatePurge({pool,bucket});const usage=createCompanyStorage({pool});assert.equal((await usage.usage(context)).totals.tracked_cloud_bytes,180);
  await purge.tick();
  assert.equal((await pool.query('SELECT private_data_state FROM users WHERE id=$1',[employee])).rows[0].private_data_state,'purged',JSON.stringify((await pool.query('SELECT * FROM employee_private_purge_jobs')).rows));
  assert.equal((await pool.query('SELECT id FROM finance_accounts WHERE id=$1',[privateAccount])).rowCount,0);assert.equal((await pool.query('SELECT id FROM finance_accounts WHERE id=ANY($1::uuid[])',[[sharedAccount,otherAccount]])).rowCount,2);
  assert.equal((await pool.query('SELECT count(*)::int n FROM finance_account_entries WHERE account_id=$1 AND created_by=$2',[sharedAccount,employee])).rows[0].n,1);
  assert.equal((await pool.query('SELECT user_id FROM focus_settings WHERE user_id=$1',[employee])).rowCount,0);assert.equal((await pool.query("SELECT text FROM idea_parking_ideas WHERE id='sharedidea'")).rows[0].text,'Retain company idea');assert.equal((await pool.query("SELECT id FROM idea_parking_ideas WHERE id='privateidea'")).rowCount,0);
  await assert.rejects(pool.query("INSERT INTO focus_settings(user_id,company_id,config) VALUES($1,$2,'{}')",[employee,company]),e=>e.code==='42501');
  assert.deepEqual(removed,['receipt/private']);assert.equal((await usage.usage(context)).totals.tracked_cloud_bytes,100);
  for(const table of historyTables)assert.deepEqual((await pool.query(`SELECT row_to_json(t) data FROM ${table} t WHERE company_id=$1 ORDER BY id`,[company])).rows,beforeHistory[table],table+' must retain exact historical rows');
  assert.equal((await pool.query('SELECT photo_url FROM users WHERE id=$1',[employee])).rows[0].photo_url,'https://example.invalid/history-photo.jpg');
  assert.equal((await pool.query('SELECT display_name FROM users WHERE id=$1',[employee])).rows[0].display_name,employee+'@example.invalid');
 }finally{if(pool)await pool.end();local.stop();}
});
