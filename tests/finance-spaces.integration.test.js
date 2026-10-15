import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {installPayStructureSchema} from '../pay-structures.js';
import {installFinanceSystem,installFinanceSchema} from '../finance.js';
import {installFinanceSpacesSchema,withFinanceSpace} from '../finance-spaces.js';

test('Finance spaces isolate same-company employers, settings, records, aggregates and pooled sessions',{timeout:120000},async()=>{
 const pg=startLocalPostgres();pg.configureEnvironment();let pool,server;
 try {
  const backend=await import('../index.js');pool=backend.pool;await backend.bootstrap();await installPayStructureSchema(pool);
  const company=randomUUID(),other=randomUUID(),alice=randomUUID(),bob=randomUUID(),outsider=randomUUID();
  await pool.query("INSERT INTO companies(id,name,join_code) VALUES($1,'Finance privacy','SPACES-A'),($2,'Other','SPACES-B')",[company,other]);
  for(const [id,c,name] of [[alice,company,'Alice'],[bob,company,'Bob'],[outsider,other,'Other']])await pool.query("INSERT INTO users(id,email,display_name,role,company_id) VALUES($1,$2,$3,'employer',$4)",[id,id+'@example.invalid',name,c]);
  await installFinanceSchema(pool);
  const legacy=randomUUID(),unknown=randomUUID();
  await pool.query("INSERT INTO finance_accounts(id,company_id,name,account_type,created_by) VALUES($1,$2,'LEGACY PRIVATE','checking',$3),($4,$2,'UNKNOWN OWNER','checking',NULL)",[legacy,company,alice,unknown]);
  await pool.query("INSERT INTO finance_account_entries(company_id,account_id,entry_type,amount_delta_cents,previous_balance_cents,resulting_balance_cents,created_by) VALUES($1,$2,'initial_balance',0,0,0,$3)",[company,legacy,bob]);
  const users={alice:{id:alice,company},bob:{id:bob,company},other:{id:outsider,company:other}};
  const app=express();app.use(express.json());
  await installFinanceSystem({app,pool,authRequired:(req,res,next)=>{const u=users[req.get('X-Test-User')];if(!u)return res.sendStatus(401);req.userId=u.id;req.companyId=u.company;next();},requireEmployer:(req,res,next)=>next(),getStripe:()=>null});
  await installFinanceSpacesSchema(pool);
  server=await new Promise(r=>{const s=app.listen(0,'127.0.0.1',()=>r(s));});
  const api=async(who,path,method='GET',body,space)=>{
   const response=await fetch(`http://127.0.0.1:${server.address().port}/api/finance${path}`,{method,headers:{'X-Test-User':who,'Content-Type':'application/json',...(space?{'X-Finance-Space':space}:{})},body:body===undefined?undefined:JSON.stringify(body)});
   const text=await response.text();assert.match(response.headers.get("content-type")||"",/json/,method+" "+path+": "+response.status+" "+text.slice(0,300));return {status:response.status,body:JSON.parse(text)};
  };
  const a=(await api('alice','/spaces')).body.default_space_id,b=(await api('bob','/spaces')).body.default_space_id;
  assert.notEqual(a,b);
  const migrated=(await pool.query('SELECT finance_space_id FROM finance_accounts WHERE id=$1',[legacy])).rows[0];assert.equal(migrated.finance_space_id,a);
  assert.equal((await pool.query('SELECT finance_space_id FROM finance_account_entries WHERE account_id=$1',[legacy])).rows[0].finance_space_id,a,'Account ownership overrides employee who entered evidence');
  assert.equal((await pool.query('SELECT finance_space_id FROM finance_accounts WHERE id=$1',[unknown])).rows[0].finance_space_id,null);
  assert.equal(JSON.stringify((await api('bob','/accounts')).body).includes('LEGACY PRIVATE'),false);
  assert.equal(JSON.stringify((await api('alice','/accounts')).body).includes('UNKNOWN OWNER'),false);
  let result=await api('alice','/accounts','POST',{name:'PRIVATE ACCOUNT',account_type:'checking',starting_balance_cents:75000});assert.equal(result.status,201,JSON.stringify(result));const account=result.body.account.id;
  await pool.query('CREATE POLICY unrelated_permissive_policy ON finance_accounts TO PUBLIC USING(true) WITH CHECK(true)');
  result=await api('bob','/accounts');assert.equal(JSON.stringify(result).includes('PRIVATE ACCOUNT'),false);
  assert.equal((await api('bob',`/accounts/${account}/history`)).status,404);
  assert.equal((await api('bob','/accounts','GET',undefined,a)).status,404);
  assert.equal((await api('other','/accounts','GET',undefined,a)).status,404);
  assert.equal((await api('bob','/spaces/combined')).body.total_balance_cents,0);
  assert.equal((await api('alice','/spaces/combined')).body.total_balance_cents,75000);
  const shared=randomUUID();
  result=await api('alice','/spaces/'+shared,'PUT',{name:'Business',kind:'business',audience:'selected',member_ids:[bob]});assert.equal(result.status,200,JSON.stringify(result));const revision=result.body.revision;
  result=await api('alice','/accounts','POST',{name:'BUSINESS ACCOUNT',account_type:'checking',starting_balance_cents:25000},shared);assert.equal(result.status,201,JSON.stringify(result));
  result=await api('bob','/accounts','GET',undefined,shared);assert.equal(JSON.stringify(result).includes('BUSINESS ACCOUNT'),true);assert.equal(JSON.stringify(result).includes('PRIVATE ACCOUNT'),false);
  const settings=await api('alice','/settings','PATCH',{minimum_cash_reserve_cents:12000,use_available_bank_balance:false},shared);assert.equal(settings.status,200,JSON.stringify(settings));
  assert.notEqual((await api('alice','/settings')).body.minimum_cash_reserve_cents,12000);
  for(const path of ['/overview','projection','projection/jobs','planned-items','debts','budgets','budget-summary','goals','transactions','receipts','accounting/chart-accounts','accounting/reports/profit-loss','accounting/statements/balance-sheet','accounting/statement-readiness'].map(p=>p.startsWith('/')?p:'/'+p)) {
   const result=await api('bob',path);assert.notEqual(result.status,500,path+' '+JSON.stringify(result));assert.equal(JSON.stringify(result.body).includes('PRIVATE ACCOUNT'),false,path);
  }
  const transfer={kind:'accounts',record_id:legacy,source_space_id:a,destination_space_id:shared};
  assert.equal((await api('bob','/spaces/transfer-preview','POST',transfer)).status,404);
  const preview=await api('alice','/spaces/transfer-preview','POST',transfer);assert.equal(preview.status,200,JSON.stringify(preview));assert.equal(preview.body.total_records,2);
  assert.equal((await api('alice','/spaces/transfer','POST',{...transfer,confirmation_token:'stale'})).status,409);
  const moved=await api('alice','/spaces/transfer','POST',{...transfer,confirmation_token:preview.body.confirmation_token});assert.equal(moved.status,200,JSON.stringify(moved));
  assert.equal(JSON.stringify((await api('bob','/accounts','GET',undefined,shared)).body).includes('LEGACY PRIVATE'),true);
  assert.equal((await pool.query('SELECT finance_space_id FROM finance_account_entries WHERE account_id=$1',[legacy])).rows[0].finance_space_id,shared);
  const collision=randomUUID(),races=await Promise.all(['alice','bob'].map(who=>api(who,'/spaces/'+collision,'PUT',{name:who,kind:'business',audience:'private',member_ids:[]})));assert.deepEqual(races.map(r=>r.status).sort(),[200,404]);
  await Promise.all(Array.from({length:20},(_,i)=>api(i%2?'alice':'bob','/accounts').then(r=>assert.equal(JSON.stringify(r).includes('PRIVATE ACCOUNT'),Boolean(i%2)))));
  result=await api('alice','/spaces/'+shared,'PUT',{name:'Business',kind:'business',audience:'private',member_ids:[],expected_revision:revision});assert.equal(result.status,200);
  assert.equal((await api('bob','/accounts','GET',undefined,shared)).status,404);
  assert.equal((await api('bob','/spaces/combined')).body.total_balance_cents,0);
  assert.equal((await api('alice','/accounts','POST',{name:'Wrong',account_type:'checking',current_balance_cents:0},'combined')).status,400);
  // New background evidence inherits its parent space, even without a request context.
  const inherited=(await pool.query("INSERT INTO finance_account_entries(company_id,account_id,entry_type,amount_delta_cents,previous_balance_cents,resulting_balance_cents) VALUES($1,$2,'manual_balance_adjustment',0,75000,75000) RETURNING finance_space_id",[company,account])).rows[0];assert.equal(inherited.finance_space_id,a);
  await assert.rejects(withFinanceSpace(pool,alice,company,shared,db=>db.query("INSERT INTO finance_account_entries(company_id,account_id,entry_type,amount_delta_cents,previous_balance_cents,resulting_balance_cents) VALUES($1,$2,'manual_balance_adjustment',0,0,0)",[company,account])),/finance_cross_space_reference/);
  const crm=randomUUID();await pool.query("INSERT INTO schedule_events(id,user_id,company_id,title,start_at,end_at,price_cents,finished_at) VALUES($1,$2,$3,'COMPANY JOB',now(),now()+interval '1 hour',15000,now())",[crm,alice,company]);
  assert.equal((await withFinanceSpace(pool,alice,company,a,db=>db.query('SELECT 1 FROM schedule_events WHERE id=$1',[crm]))).rowCount,0);
  const sharedCurrent=(await api('alice','/spaces')).body.spaces.find(s=>s.id===shared);
  result=await api('alice','/spaces/'+shared,'PUT',{name:'Business',kind:'business',audience:'private',member_ids:[],expected_revision:sharedCurrent.revision,includes_company_activity:true});assert.equal(result.status,200,JSON.stringify(result));
  assert.equal((await withFinanceSpace(pool,alice,company,shared,db=>db.query('SELECT 1 FROM schedule_events WHERE id=$1',[crm]))).rowCount,1);
  const receivables=await api('alice','/accounting/receivables','GET',undefined,shared);assert.equal(receivables.status,200,JSON.stringify(receivables));assert.equal(JSON.stringify(receivables).includes('COMPANY JOB'),true);
  assert.equal(JSON.stringify((await api('alice','/accounting/receivables')).body).includes('COMPANY JOB'),false);
  for(let i=(await api('alice','/spaces')).body.spaces.filter(s=>s.owner_id===alice).length;i<10;i++)assert.equal((await api('alice','/spaces/'+randomUUID(),'PUT',{name:'Portfolio '+i,kind:'portfolio',audience:'private',member_ids:[]})).status,200);
  assert.equal((await api('alice','/spaces/'+randomUUID(),'PUT',{name:'Overflow',kind:'portfolio',audience:'private',member_ids:[]})).status,409);
  await withFinanceSpace(pool,alice,company,a,async db=>{const c=await db.connect();try{await c.query('BEGIN');await c.query('SELECT 1');await c.query('COMMIT');}finally{await c.release();}});
  assert.equal((await pool.query('SELECT current_user=session_user AS clean')).rows[0].clean,true);
 } finally {if(server)await new Promise(r=>server.close(r));if(pool)await pool.end();pg.stop();}
});
