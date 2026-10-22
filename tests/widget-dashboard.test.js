import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installCompanyComms} from '../company-comms/index.js';
import express from 'express';
import {createWidgetDashboard,commsUnreadSummary,validateWidgetSlots,widgetDateRange} from '../widget-dashboard.js';
import {loadProfitAndLoss,buildProfitAndLoss} from '../finance-accounting.js';
import {agreementAttention} from '../widget-dashboard-catalog.js';
import {paymentRecordCollection} from '../agreement-payments.js';

const slot=(kind,filters={},offset=0)=>({id:kind,kind,filters,offset});
test('filters reject ambiguous or silently unsupported combinations',()=>{
 for(const value of [null,{slots:[]},{slots:Array(9).fill(slot('tasks'))},{slots:[slot('tasks',{person:'all'})]},
  {slots:[slot('messages',{period:'week'})]},{slots:[slot('schedule',{period:'custom',start:'2026-02-30',end:'2026-03-01'})]},
  {slots:[slot('leads',{period:'custom',start:'2026-04-03',end:'2026-04-01'})]},
  {slots:[slot('tasks',{},-1)]},{slots:[slot('schedule',{companyID:randomUUID()})]},
  {slots:[slot('unknown')]},{slots:[slot('tasks'),slot('tasks')]}])assert.throws(()=>validateWidgetSlots(value));
 assert.equal(validateWidgetSlots({slots:[slot('schedule',{person:'me',period:'week'})]})[0].filters.person,'me');
 assert.equal(validateWidgetSlots({slots:[{...slot('tasks'),id:'a'},{...slot('tasks'),id:'b'}]}).length,2);
});

async function fixture(services={}){
 const f=await createCommsFixture();
 await f.pool.query(`ALTER TABLE companies ADD COLUMN timezone text DEFAULT 'America/New_York';
 ALTER TABLE schedule_events ADD COLUMN end_at timestamptz,ADD COLUMN price_cents integer,ADD COLUMN service_items jsonb DEFAULT '[]',ADD COLUMN created_by uuid,ADD COLUMN sales_user_ids jsonb DEFAULT '[]',ADD COLUMN worker_user_ids jsonb DEFAULT '[]',ADD COLUMN finished_at timestamptz;
 ALTER TABLE opportunities ADD COLUMN pipeline_id text;
 ALTER TABLE contacts ADD COLUMN user_id uuid,ADD COLUMN job_type text,ADD COLUMN lead_submitted_at timestamptz,ADD COLUMN lat double precision,ADD COLUMN lng double precision;
 ALTER TABLE todo_tasks ADD COLUMN company_id uuid,ADD COLUMN linked_contact_id text;
 ALTER TABLE stages ADD COLUMN pipeline_id text;
 CREATE TABLE pipelines(id text PRIMARY KEY,company_id uuid,name text);
 CREATE TABLE phone_calls(id uuid,company_id uuid,contact_id uuid,direction text,started_at timestamptz);
 CREATE TABLE time_clock_entries(id uuid,company_id uuid,user_id uuid,start_at timestamptz,end_at timestamptz,break_started_at timestamptz,manual_status text DEFAULT 'approved');
 CREATE TABLE quote_agreements(id uuid,company_id uuid,quote_id uuid,revision integer DEFAULT 1,revoked_at timestamptz,decision text DEFAULT 'published',created_at timestamptz DEFAULT now(),title text,number text,snapshot jsonb);
 ALTER TABLE quotes ADD COLUMN user_id uuid,ADD COLUMN status text,ADD COLUMN expires_at timestamptz,ADD COLUMN converted_job_id text,ADD COLUMN accepted_at timestamptz,ADD COLUMN created_at timestamptz DEFAULT now();
 CREATE TABLE automation_events(id uuid PRIMARY KEY,company_id uuid,event_type text,subject_id text,occurred_at timestamptz,payload jsonb);
 ALTER TABLE service_plans ADD COLUMN user_id uuid,ADD COLUMN contact_id uuid,ADD COLUMN status text,ADD COLUMN price_cents integer,ADD COLUMN billing_interval text,ADD COLUMN billing_interval_count integer;
 CREATE TABLE payment_records(id uuid PRIMARY KEY,company_id uuid,contact_id uuid,description text,amount_cents integer,currency text,paid_at timestamptz,status text,refunded_amount_cents bigint DEFAULT 0,refund_amount_known boolean DEFAULT true,stripe_dispute_status text,stripe_payment_intent_id text,stripe_connected_account_id text,stripe_livemode boolean);
 CREATE TABLE todo_customer_reminders(id text PRIMARY KEY,user_id uuid,title text,contact_id text,contact_name text,due_date timestamptz,completed boolean DEFAULT false);
 CREATE TABLE phone_lines(id uuid PRIMARY KEY,company_id uuid);
 CREATE TABLE sms_conversations(id uuid PRIMARY KEY,phone_line_id uuid,contact_id uuid,deleted_at timestamptz,last_read_at timestamptz);
 CREATE TABLE sms_messages(id uuid PRIMARY KEY,conversation_id uuid,body text,created_at timestamptz,direction text,deleted_at timestamptz);
 CREATE TABLE imessage_conversations(id uuid PRIMARY KEY,company_id uuid,contact_id uuid,deleted_at timestamptz,last_read_at timestamptz);
 CREATE TABLE imessage_messages(id uuid PRIMARY KEY,conversation_id uuid,body text,created_at timestamptz,provider_created_at timestamptz,direction text,deleted_at timestamptz);`);
 const app=express();const comms=await installCompanyComms({app,pool:f.pool,authRequired:(q,s,n)=>n(),startWorker:false});
 const failures=[];
 const pool={query:async(...args)=>{try{return await f.pool.query(...args);}catch(e){failures.push(e.message);throw e;}},connect:()=>f.pool.connect()};
 return {...f,comms,failures,service:createWidgetDashboard({pool,services})};
}
test('company-timezone boundaries honor both DST transitions and custom ranges',{timeout:120000},async()=>{
 const f=await fixture();try {
  const spring=await widgetDateRange(f.pool,f.companies.a,{},new Date('2026-03-08T12:00:00Z'));
  assert.equal((spring.end_at-spring.start_at)/3600000,23);
  const fall=await widgetDateRange(f.pool,f.companies.a,{},new Date('2026-11-01T12:00:00Z'));
  assert.equal((fall.end_at-fall.start_at)/3600000,25);
  const custom=await widgetDateRange(f.pool,f.companies.a,{period:'custom',start:'2026-03-07',end:'2026-03-09'});
  assert.equal((custom.end_at-custom.start_at)/3600000,71);assert.equal(custom.start_date,'2026-03-07');assert.equal(custom.end_date,'2026-03-09');
 }finally{await f.close();}
});
test('payments use the agreement collection rule, preserve gross/refund distinction; plans and accepted sale snapshots match canonical sources',{timeout:120000},async()=>{
 const f=await fixture();try {
  const owner=await f.actor('owner'),now=new Date('2026-10-17T16:00:00Z'),contact=randomUUID(),quote=randomUUID();
  await f.pool.query("INSERT INTO contacts(id,company_id,user_id,name) VALUES($1,$2,$3,'Customer')",[contact,f.companies.a,f.ids.owner]);
  await f.pool.query("INSERT INTO quotes(id,company_id,user_id,contact_id,title,total_cents,status,accepted_at) VALUES($1,$2,$3,$4,'Edited quote',99000,'accepted',$5)",[quote,f.companies.a,f.ids.owner,contact,now]);
  await f.pool.query("INSERT INTO automation_events VALUES($1,$2,'quote.accepted',$3,$4,'{\"total_cents\":12345}')",[randomUUID(),f.companies.a,quote,now]);
  await f.pool.query("INSERT INTO service_plans(id,company_id,user_id,contact_id,plan_name,status,price_cents,billing_interval,billing_interval_count) VALUES($1,$2,$3,$4,'Quarterly','active',9000,'month',3),($5,$6,$7,NULL,'Foreign','active',99999,'month',1)",[randomUUID(),f.companies.a,f.ids.owner,contact,randomUUID(),f.companies.b,f.ids.foreign]);
  await f.pool.query("INSERT INTO payment_records(id,company_id,contact_id,amount_cents,currency,paid_at,status,refunded_amount_cents) VALUES($1,$2,$3,10000,'usd',$4,'partially_refunded',2500),($5,$2,$3,5000,'usd',$4,'succeeded',0),($6,$2,$3,9999,'usd',NULL,'paid',0)",[randomUUID(),f.companies.a,contact,now,randomUUID(),randomUUID()]);
  const result=await f.service.summary(owner,{slots:[slot('booked_sales'),slot('plans'),slot('payments')]},now);
  assert.deepEqual(f.failures,[]);
  assert.equal(result.modules[0].value,'$123.45');assert.equal(result.modules[1].count,1);assert.match(result.modules[1].note,/\$30.00/);
  assert.equal(result.modules[2].value,'$150.00');assert.match(result.modules[2].note,/\$25.00 refunded/);assert.match(result.modules[2].note,/1 undated/);
  const records=(await f.pool.query('SELECT * FROM payment_records WHERE company_id=$1 AND paid_at IS NOT NULL',[f.companies.a])).rows;
  assert.equal(records.reduce((sum,p)=>sum+paymentRecordCollection(p,null).gross,0),15000);
  assert.equal(records.reduce((sum,p)=>sum+paymentRecordCollection(p,null).refunds,0),2500);
  await f.pool.query("UPDATE payment_records SET stripe_payment_intent_id='pi_fixture',stripe_connected_account_id='acct_fixture',stripe_livemode=true WHERE company_id=$1",[f.companies.a]);
  const noMode=createWidgetDashboard({pool:f.pool,env:{}});
  assert.equal((await noMode.summary(owner,{slots:[slot('payments')]},now)).modules[0].state,'unavailable');
 }finally{await f.close();}
});
test('unread is exact beyond 100 conversations, includes replies and mute, excludes self/deleted/history/revoked access',{timeout:120000},async()=>{
 const f=await fixture();try {
  const a=await f.actor('alice'),b=await f.actor('bob');
  await f.pool.query(`INSERT INTO conversations(id,company_id,created_by,title) SELECT 'bulk-'||i,$1,$2,'Bulk' FROM generate_series(1,121)i;
  `,[f.companies.a,f.ids.bob]);
  await f.pool.query(`INSERT INTO conversation_participants(id,conversation_id,user_id) SELECT 'participant-'||i,'bulk-'||i,$1 FROM generate_series(1,121)i`,[f.ids.alice]);
  await f.pool.query(`INSERT INTO messages(id,conversation_id,sender_id,company_id,body) SELECT 'message-'||i,'bulk-'||i,$1,$2,'Incoming' FROM generate_series(1,121)i`,[f.ids.bob,f.companies.a]);
  let summary=await commsUnreadSummary(f.pool,a);assert.equal(summary.count,121);assert.equal(summary.rows.length,50);assert.equal(summary.nextOffset,50);
  const c=await f.comms.messages.create(a,{client_key:randomUUID(),member_ids:[f.ids.bob]});
  const root=await f.comms.messages.send(b,c.id,{client_key:randomUUID(),body:'First',mention_user_ids:[f.ids.alice]});
  await f.comms.messages.send(b,c.id,{client_key:randomUUID(),body:'Reply',reply_root_id:root.id,mention_user_ids:[f.ids.alice]});
  await f.comms.messages.send(a,c.id,{client_key:randomUUID(),body:'Own'});
  await f.pool.query("INSERT INTO comms_preferences(user_id,company_id,subject_type,subject_id,muted) VALUES($1,$3,'conversation',$2,true)",[f.ids.alice,c.id,f.companies.a]);
  assert.equal((await commsUnreadSummary(f.pool,a)).count,123);
  assert.equal((await commsUnreadSummary(f.pool,a,true)).count,2);
  await f.comms.messages.read(a,c.id,{last_message_id:root.id});assert.equal((await commsUnreadSummary(f.pool,a,true)).count,1);
  await f.pool.query("UPDATE messages SET deleted_at=now() WHERE reply_root_id=$1",[root.id]);assert.equal((await commsUnreadSummary(f.pool,a)).count,121);
  await f.pool.query("UPDATE conversation_participants SET history_from=now()+interval '1 hour' WHERE conversation_id='bulk-1' AND user_id=$1",[f.ids.alice]);assert.equal((await commsUnreadSummary(f.pool,a)).count,120);
  await f.pool.query("UPDATE conversation_participants SET left_at=now() WHERE conversation_id='bulk-2' AND user_id=$1",[f.ids.alice]);assert.equal((await commsUnreadSummary(f.pool,a)).count,119);
  assert.equal((await commsUnreadSummary(f.pool,await f.actor('foreign'))).count,0);
  const result=await f.service.summary(a,{slots:[slot('company_comms'),slot('mentions')]});assert.equal(result.modules[0].badge,119);
  await f.pool.query(`UPDATE employee_permissions SET permission_overrides='{"communications.view":false}' WHERE user_id=$1`,[f.ids.alice]);
  assert.equal((await f.service.summary(a,{slots:[slot('company_comms')]})).modules[0].state,'unavailable');
  assert.deepEqual(f.failures,[]);
 }finally{await f.close();}
});
test('counts and rows use the same scoped predicates; revenue remains scheduled value; failures never become zero',{timeout:120000},async()=>{
 const f=await fixture();try {
  const owner=await f.actor('owner'),alice=await f.actor('alice'),now=new Date('2026-10-17T16:00:00Z');
  const own=randomUUID(),foreign=randomUUID();
  await f.pool.query("INSERT INTO contacts(id,company_id,user_id,name,lead_submitted_at) VALUES($1,$2,$3,'Current lead',$4),($5,$6,$7,'Foreign secret',$4)",[own,f.companies.a,f.ids.alice,now,foreign,f.companies.b,f.ids.foreign]);
  await f.pool.query(`INSERT INTO schedule_events(id,company_id,title,start_at,price_cents,created_by,contact_id,worker_user_ids) VALUES
  ('job-a',$1,'Cleaning',$4,12345,$3,$5,$7),('job-b',$1,'Repair',$4,5000,$2,NULL,'[]'),('job-foreign',$6,'Private',$4,99999,$2,NULL,'[]')`,[f.companies.a,f.ids.owner,f.ids.alice,now,own,f.companies.b,JSON.stringify([f.ids.alice])]);
  await f.pool.query(`INSERT INTO todo_tasks(id,user_id,title,due_date,company_id) SELECT 'task-'||i,$1,'Task '||i,$2,$3 FROM generate_series(1,73)i`,[f.ids.alice,now,f.companies.a]);
  await f.pool.query(`INSERT INTO todo_tasks(id,user_id,title,due_date,company_id) VALUES('foreign-task',$1,'Private',$2,$3)`,[f.ids.foreign,now,f.companies.b]);
  const payload=await f.service.summary(owner,{userID:f.ids.owner,companyID:f.companies.a,slots:[slot('schedule'),slot('revenue'),slot('leads')]},now);
  assert.deepEqual(f.failures,[]);assert.equal(payload.modules[0].count,2);assert.equal(payload.modules[1].value,'$173.45');assert.equal(payload.modules[2].badge,1);
  const personal=await f.service.summary(alice,{slots:[slot('schedule'),slot('revenue'),slot('due_tasks'),{...slot('due_tasks',{},50),id:'page'}]},now);
  assert.deepEqual(f.failures,[]);assert.equal(personal.modules[0].count,1);assert.equal(personal.modules[1].state,'unavailable');
  assert.equal(personal.modules[2].badge,73);assert.equal(personal.modules[2].rows.length,50);assert.equal(personal.modules[3].rows.length,23);
  const exact=await f.service.summary(alice,{slots:[{...slot('due_tasks'),recordID:'task-73'}]},now);assert.equal(exact.modules[0].rows[0].id,'task-73');
  assert.equal((await f.service.summary(alice,{slots:[{...slot('due_tasks'),recordID:'foreign-task'}]},now)).modules[0].rows.length,0);
  await assert.rejects(f.service.summary(owner,{userID:f.ids.foreign,slots:[slot('tasks')]},now),e=>e.status===403);
  assert.equal((await f.service.summary(alice,{slots:[slot('schedule',{person:'all'})]},now)).modules[0].state,'unavailable');
  await f.pool.query('DROP TABLE sms_messages'); // Disposable fixture only, never production.
  const failed=await f.service.summary(owner,{slots:[slot('messages')]},now);assert.equal(failed.modules[0].state,'error');assert.equal(failed.modules[0].value,undefined);
 }finally{await f.close();}
});
test('customer message and notification badges reconcile exact unread records without local arithmetic',{timeout:120000},async()=>{
 const f=await fixture();try {
  const alice=await f.actor('alice'),now=new Date('2026-10-17T16:00:00Z'),line=randomUUID(),conversation=randomUUID(),imessage=randomUUID();
  await f.pool.query('INSERT INTO phone_lines VALUES($1,$2)',[line,f.companies.a]);
  await f.pool.query("INSERT INTO sms_conversations(id,phone_line_id,last_read_at) VALUES($1,$2,'2026-10-17T14:00:00Z')",[conversation,line]);
  await f.pool.query("INSERT INTO sms_messages(id,conversation_id,body,created_at,direction) SELECT gen_random_uuid(),$1,'Incoming',$2,'inbound' FROM generate_series(1,3)",[conversation,now]);
  await f.pool.query("INSERT INTO sms_messages VALUES($1,$2,'Outgoing',$3,'outbound',NULL),($4,$2,'Old','2026-10-17T13:00:00Z','inbound',NULL),($5,$2,'Deleted',$3,'inbound',$3)",[randomUUID(),conversation,now,randomUUID(),randomUUID()]);
  await f.pool.query("INSERT INTO imessage_conversations(id,company_id,last_read_at) VALUES($1,$2,'2026-10-17T14:00:00Z')",[imessage,f.companies.a]);
  await f.pool.query("INSERT INTO imessage_messages(id,conversation_id,body,created_at,provider_created_at,direction) SELECT gen_random_uuid(),$1,'Incoming',$2,$2,'inbound' FROM generate_series(1,7)",[imessage,now]);
  await f.pool.query("INSERT INTO imessage_messages VALUES($1,$2,'Old provider message',$3,'2026-10-17T13:00:00Z','inbound',NULL)",[randomUUID(),imessage,now]);
  await f.pool.query("INSERT INTO notifications(id,user_id,company_id,title,created_at) SELECT 'notification-'||i,$1,$2,'Incoming notification',$3 FROM generate_series(1,10)i",[f.ids.alice,f.companies.a,now]);
  await f.pool.query("INSERT INTO notifications(id,user_id,company_id,title,created_at) VALUES('wrong-company',$1,$2,'Private',$3)",[f.ids.alice,f.companies.b,now]);
  let result=await f.service.summary(alice,{slots:[slot('messages'),slot('notifications')]},now);
  assert.deepEqual(f.failures,[]);assert.deepEqual(result.modules.map(m=>m.badge),[10,10]);
  // Cursor movement is authoritative and idempotent, not a counter decrement.
  for(let attempt=0;attempt<2;attempt++)await f.pool.query('UPDATE sms_conversations SET last_read_at=$1 WHERE id=$2',[now,conversation]);
  await f.pool.query("UPDATE notifications SET read_at=$1 WHERE id='notification-1'",[now]);
  await f.pool.query("UPDATE notifications SET deleted_at=$1 WHERE id='notification-2'",[now]);
  result=await f.service.summary(alice,{slots:[slot('messages'),slot('notifications')]},now);
  assert.deepEqual(result.modules.map(m=>m.badge),[7,8]);
  await f.pool.query('UPDATE imessage_conversations SET last_read_at=$1 WHERE id=$2',[now,imessage]);
  assert.equal((await f.service.summary(alice,{slots:[slot('messages')]},now)).modules[0].badge,0);
  await f.pool.query(`UPDATE employee_permissions SET permission_overrides=permission_overrides||'{"messaging.customer.view":false}'::jsonb WHERE user_id=$1`,[f.ids.alice]);
  assert.equal((await f.service.summary(alice,{slots:[slot('messages')]},now)).modules[0].state,'unavailable');
 }finally{await f.close();}
});
test('task ownership survives creator transfer; unknown legacy tasks and old schema fail closed',{timeout:120000},async()=>{
 const f=await fixture();try {
  const now=new Date('2026-10-17T16:00:00Z');
  await f.pool.query(`INSERT INTO todo_tasks(id,user_id,title,due_date,company_id,assignee_ids) VALUES
   ('durable',$1,'Company A task',$2,$3,$4),('unknown',$1,'Unverified legacy task',$2,NULL,'[]')`,[f.ids.alice,now,f.companies.a,JSON.stringify([f.ids.bob])]);
  const bob=await f.actor('bob');
  assert.equal((await f.service.summary(await f.actor('alice'),{slots:[slot('tasks')]},now)).modules[0].count,1);
  await f.pool.query('UPDATE users SET company_id=$1 WHERE id=$2',[f.companies.b,f.ids.alice]);
  await f.pool.query('UPDATE employee_permissions SET company_id=$1 WHERE user_id=$2',[f.companies.b,f.ids.alice]);
  const moved=await f.service.summary({userId:f.ids.alice,companyId:f.companies.b},{slots:[slot('tasks')]},now);
  assert.equal(moved.modules[0].count,0);
  const retained=await f.service.summary(bob,{slots:[slot('due_tasks')]},now);
  assert.equal(retained.modules[0].badge,1);assert.equal(retained.modules[0].rows[0].id,'durable');
  await f.pool.query('ALTER TABLE todo_tasks DROP COLUMN company_id'); // Legacy schema in this disposable database.
  const legacy=await f.service.summary(bob,{slots:[slot('tasks')]},now);
  assert.equal(legacy.modules[0].state,'unavailable');assert.equal(legacy.modules[0].count,undefined);
  assert.match(legacy.modules[0].reason,/Task widgets are not available yet/);
  assert.deepEqual(f.failures,[]);
 }finally{await f.close();}
});
test('shared cash P&L loader matches authoritative calculation, excludes pending and preserves negative profit',{timeout:120000},async()=>{
 const f=await fixture();try {
  await f.pool.query(`CREATE TABLE finance_transactions(id text PRIMARY KEY,company_id uuid,direction text,amount_cents bigint,transaction_date date,status text,pending boolean,removed_at timestamptz);
  CREATE TABLE finance_chart_accounts(id text PRIMARY KEY,company_id uuid,code text,name text,account_type text);
  CREATE TABLE finance_transaction_splits(id text PRIMARY KEY,company_id uuid,transaction_id text,chart_account_id text,amount_cents bigint);`);
  await f.pool.query("INSERT INTO finance_chart_accounts VALUES('e',$1,'500','Materials','expense')",[f.companies.a]);
  await f.pool.query("INSERT INTO finance_transactions VALUES('one',$1,'expense',2300,'2026-10-17','posted',false,NULL),('pending',$1,'income',99999,'2026-10-17','pending',true,NULL),('foreign',$2,'income',99999,'2026-10-17','posted',false,NULL)",[f.companies.a,f.companies.b]);
  await f.pool.query("INSERT INTO finance_transaction_splits VALUES('s',$1,'one','e',2300)",[f.companies.a]);
  const report=await loadProfitAndLoss(f.pool,f.companies.a,{start_date:'2026-10-17',end_date:'2026-10-17'});
  assert.equal(report.net_income_cents,-2300);assert.equal(report.excluded.pending_transaction_count,1);
  const expected=buildProfitAndLoss({startDate:'2026-10-17',endDate:'2026-10-17',transactions:[{direction:'expense',amount_cents:2300,transaction_date:'2026-10-17',status:'posted',splits:[{chart_account_id:'e',amount_cents:2300,account_type:'expense',chart_account_code:'500',chart_account_name:'Materials'}]}]});
  assert.deepEqual(report.expenses,expected.expenses);
 }finally{await f.close();}
});

test('first contact, pipeline stages, quote creation and customer tasks preserve record scopes',{timeout:120000},async()=>{
 const f=await fixture();try {
  const now=new Date('2026-10-17T16:00:00Z'),owner=await f.actor('owner'),c=randomUUID(),d=randomUUID();
  await f.pool.query("INSERT INTO contacts(id,company_id,user_id,name,lead_submitted_at) VALUES($1,$2,$3,'Waiting','2026-10-17T12:00Z'),($4,$2,$3,'Contacted','2026-10-17T12:00Z')",[c,f.companies.a,f.ids.owner,d]);
  await f.pool.query("INSERT INTO pipelines VALUES('p',$1,'Sales')",[f.companies.a]);
  await f.pool.query("INSERT INTO stages(id,company_id,pipeline_id,name) VALUES('s',$1,'p','New')",[f.companies.a]);
  await f.pool.query("INSERT INTO opportunities VALUES('o1',$1,$2,'s','p'),('o2',$1,$2,'s','p'),('o3',$1,$3,'s','p')",[f.companies.a,c,d]);
  await f.pool.query("INSERT INTO phone_calls VALUES($1,$2,$3,'outbound',$4)",[randomUUID(),f.companies.a,d,now]);
  await f.pool.query("INSERT INTO todo_tasks(id,user_id,title,company_id,linked_contact_id) VALUES('linked',$1,'Call',$2,$3),('personal',$1,'Private',$2,NULL)",[f.ids.owner,f.companies.a,c]);
  const result=await f.service.summary(owner,{slots:[slot('first_contact'),slot('pipeline_stages',{pipeline:'p'}),slot('pipeline',{stage:'s'}),slot('customer_tasks'),slot('create_quote')]},now);
  assert.deepEqual(f.failures,[]);assert.deepEqual(result.modules.map(m=>m.state),Array(5).fill('ready'));
  assert.equal(result.modules[0].badge,1);assert.equal(result.modules[0].rows[0].id,c);
  assert.equal(result.modules[1].rows[0].subtitle,'2 contacts');assert.equal(result.modules[2].count,2);
  assert.equal(result.modules[3].count,1);assert.equal(result.modules[4].count,2);
  await f.pool.query("UPDATE employee_permissions SET permission_overrides=permission_overrides||'{\"quotes.create\":false}' WHERE user_id=$1",[f.ids.alice]);
  assert.equal((await f.service.summary(await f.actor('alice'),{slots:[slot('create_quote')]})).modules[0].state,'unavailable');
 }finally{await f.close();}
});
test('directed replies require an accessible root authored by the reader',{timeout:120000},async()=>{
 const f=await fixture();try {
  const a=await f.actor('alice'),b=await f.actor('bob'),c=await f.comms.messages.create(a,{client_key:randomUUID(),member_ids:[f.ids.bob]});
  const mine=await f.comms.messages.send(a,c.id,{client_key:randomUUID(),body:'Question'}),theirs=await f.comms.messages.send(b,c.id,{client_key:randomUUID(),body:'Other root'});
  await f.comms.messages.send(b,c.id,{client_key:randomUUID(),body:'Answer',reply_root_id:mine.id});
  await f.comms.messages.send(b,c.id,{client_key:randomUUID(),body:'Other answer',reply_root_id:theirs.id});
  await f.comms.messages.send(a,c.id,{client_key:randomUUID(),body:'Own reply',reply_root_id:mine.id});
  assert.equal((await f.service.summary(a,{slots:[slot('replies')]})).modules[0].badge,1);assert.deepEqual(f.failures,[]);
  await f.pool.query('UPDATE messages SET deleted_at=now() WHERE id=$1',[mine.id]);
  assert.equal((await f.service.summary(a,{slots:[slot('replies')]})).modules[0].badge,0);
 }finally{await f.close();}
});
test('agreement adapters reuse reconciled actions and exclude prior revisions; excessive sets fail closed',{timeout:120000},async()=>{
 const states=new Map(),payments=new Map();let calls=0;
 const f=await fixture({getAgreementService:()=>({state:async(db,row)=>{calls++;return states.get(row.id);},paymentSummary:async(db,row)=>payments.get(row.id)})});try {
  const owner=await f.actor('owner'),quote=randomUUID(),latest=randomUUID(),review=randomUUID(),managed=randomUUID();
  for(const [id,q,revision]of[[randomUUID(),quote,1],[latest,quote,2],[review,null,1],[managed,null,1]]){
   await f.pool.query("INSERT INTO quote_agreements(id,company_id,quote_id,revision,title,snapshot) VALUES($1,$2,$3,$4,'Agreement','{\"pricing\":{}}')",[id,f.companies.a,q,revision]);
   states.set(id,{decision:'published',signing:'complete',deposit:'outstanding',can_checkout:true,booking:'blocked'});
   payments.set(id,{can_pay_balance:true,balance_cents:7654,deposit_due_cents:2000,processing:false,payment_review_required:false});
  }
  payments.set(review,{...payments.get(review),payment_review_required:true});
  payments.set(managed,{...payments.get(managed),can_pay_balance:false,deposit_due_cents:0});states.set(managed,{...states.get(managed),can_checkout:false});
  const result=await f.service.summary(owner,{slots:[slot('invoices'),slot('deposits'),slot('agreements')]});
  assert.deepEqual(f.failures,[]);assert.equal(calls,3);assert.equal(result.modules[0].value,'$76.54');assert.equal(result.modules[0].badge,1);assert.equal(result.modules[1].value,'$20.00');assert.equal(result.modules[2].badge,2);
  assert.deepEqual(agreementAttention({decision:'changes_requested',signing:'required_signers_pending',can_sign:true,booking:'eligible'},null),['Changes requested','Signatures pending','Ready to book']);
  await f.pool.query("INSERT INTO quote_agreements(id,company_id,title,snapshot) SELECT gen_random_uuid(),$1,'Overflow','{}' FROM generate_series(1,251)",[f.companies.a]);
  const full=(await f.service.summary(owner,{slots:[slot('invoices')]})).modules[0];assert.equal(full.state,'unavailable');assert.equal(full.badge,undefined);
 }finally{await f.close();}
});
test('saved weather module is explicitly retired without a provider call; clock status stays personal',{timeout:120000},async()=>{
 const now=new Date('2026-10-17T16:00:00Z');let providerCalls=0;
 const f=await fixture({weatherService:{status:()=>({configured:true}),lookup:async()=>{providerCalls++;throw Error('retired provider call');}}});try {
  const c=randomUUID(),owner=await f.actor('owner');
  await f.pool.query("INSERT INTO contacts(id,company_id,name,lat,lng) VALUES($1,$2,'Property',40,-75)",[c,f.companies.a]);
  await f.pool.query("INSERT INTO schedule_events(id,company_id,contact_id,start_at,title) VALUES('weather-job',$1,$2,'2026-10-17T16:30:00Z','Service')",[f.companies.a,c]);
  await f.pool.query("INSERT INTO time_clock_entries(id,company_id,user_id,start_at) VALUES($1,$2,$3,$4)",[randomUUID(),f.companies.a,f.ids.owner,now]);
  const result=await f.service.summary(owner,{slots:[slot('weather'),slot('crew'),slot('time_clock')]},now);
  assert.deepEqual(f.failures,[]);assert.equal(result.modules[0].state,'unavailable');assert.match(result.modules[0].reason,/retired/);assert.equal(providerCalls,0);assert.equal(result.modules[1].count,1);assert.equal(result.modules[2].value,'Clocked in');
  assert.equal((await f.service.summary(await f.actor('alice'),{slots:[slot('time_clock')]},now)).modules[0].value,'Clocked out');
  await f.pool.query('UPDATE contacts SET lat=NULL WHERE id=$1',[c]);assert.equal((await f.service.summary(owner,{slots:[slot('weather')]},now)).modules[0].state,'unavailable');
 }finally{await f.close();}
});

test('activity matches canonical exception source names and excludes other people’s private tasks',{timeout:120000},async()=>{
 let refreshes=0;const f=await fixture({refreshActivity:async()=>{refreshes++;}});try {
  await f.pool.query('CREATE TABLE business_exceptions(id uuid,company_id uuid,title text,explanation text,detected_at timestamptz DEFAULT now(),source_type text,source_id text,status text DEFAULT \'open\')');
  await f.pool.query("INSERT INTO todo_tasks(id,user_id,title,company_id) VALUES('mine',$1,'Mine',$3),('private',$2,'PRIVATE',$3)",[f.ids.owner,f.ids.alice,f.companies.a]);
  for(const[type,id]of[['todo_task','mine'],['todo_task','private'],['scheduled_job','job'],['automation_dead_letter','run'],['sms_message','message']])await f.pool.query("INSERT INTO business_exceptions(id,company_id,title,source_type,source_id) VALUES($1,$2,'Action',$3,$4)",[randomUUID(),f.companies.a,type,id]);
  const result=(await f.service.summary(await f.actor('owner'),{slots:[slot('activity')]})).modules[0];
  assert.deepEqual(f.failures,[]);assert.equal(result.badge,4);assert.equal(refreshes,1);
  assert.equal((await f.service.summary(await f.actor('alice'),{slots:[slot('activity')]})).modules[0].state,'unavailable');
 }finally{await f.close();}
});
