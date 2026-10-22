import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {installEmployeeAccountRoutes} from '../employee-access/routes.js';
import {installEmployeeAccountSchema} from '../employee-access/schema.js';
import {createPermissionGovernance} from '../permission-governance.js';
import {installScheduleBookingGuard} from '../schedule-booking-guard.js';
import {resolveAccess} from '../permissions.js';
import {permissionWindowOpen,validatePermissionWindows} from '../permission-windows.js';

test('permission windows enforce company timezone, boundaries, overnight and DST without granting',()=>{
 const w={days:[1],start:'22:00',end:'02:00'};
 assert.equal(permissionWindowOpen(w,'America/New_York',new Date('2026-10-20T03:00:00Z')),true);
 assert.equal(permissionWindowOpen(w,'America/New_York',new Date('2026-10-20T06:00:00Z')),false);
 assert.equal(permissionWindowOpen(w,'Bad/Zone',new Date()),false);
 const dst={days:[0],start:'01:00',end:'02:00'};
 assert.equal(permissionWindowOpen(dst,'America/New_York',new Date('2026-11-01T05:30:00Z')),true);
 assert.equal(permissionWindowOpen(dst,'America/New_York',new Date('2026-11-01T06:30:00Z')),true);
 assert.throws(()=>validatePermissionWindows({'jobs.view':{days:[1],start:'12:00',end:'12:00'}},new Set(['jobs.view'])),e=>e.code==='invalid_permission_windows');
 const access=resolveAccess({preset:'technician',permissionWindows:{'jobs.view':w},timeZone:'America/New_York',now:new Date('2026-10-20T16:00:00Z')});
 assert.equal(access.capabilities['jobs.view'],false);assert.equal(access.capabilities['jobs.work'],false);assert.equal(access.capabilities['jobs.complete'],false);
 for(const key of ['team.manage_accounts','team.purge_private','storage.view_usage','storage.cleanup_company','training.author'])assert.equal(resolveAccess({preset:'admin'}).capabilities[key],false);
});

test('real HTTP auth: lock/disable/recover preserve identity, grants, revisions and company boundaries',{timeout:120000},async t=>{
 const keep=new Set(['PATH','HOME','TMPDIR','LANG','LC_ALL','SHELL','USER','LOGNAME','TERM','TZ']);
 for(const key of Object.keys(process.env))if(!keep.has(key))delete process.env[key];
 process.env.NODE_ENV='test';
 const local=startLocalPostgres();local.configureEnvironment();
 let backend,server;
 try{
  backend=await import('../index.js');const {app,pool,authRequired,hashPassword}=backend;
  await backend.bootstrap();await installEmployeeAccountSchema(pool);await installScheduleBookingGuard(pool);
  const company=randomUUID(),foreign=randomUUID(),ids=Object.fromEntries(['owner','admin','peer','employee','foreign','legacy'].map(x=>[x,randomUUID()]));
  await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id,timezone) VALUES($1::uuid,'Lifecycle fixture',$1::text,$2,'America/New_York'),($3::uuid,'Foreign fixture',$3::text,$4,'UTC')",[company,ids.owner,foreign,ids.foreign]);
  const password='Synthetic-test-password!98';
  for(const [key,id] of Object.entries(ids)){
   await pool.query('INSERT INTO users(id,email,display_name,photo_url,role,company_id,password_hash) VALUES($1,$2,$3,$4,$5,$6,$7)',[id,key+'@example.invalid','Historic '+key,'https://example.invalid/photo/'+key,key==='owner'?'employer':'employee',key==='foreign'?foreign:company,hashPassword(password)]);
   await pool.query('INSERT INTO employee_permissions(user_id,company_id,permission_preset,permission_overrides) VALUES($1,$2,$3,$4)',[id,key==='foreign'?foreign:company,['admin','peer'].includes(key)?'admin':'technician',JSON.stringify({'contacts.delete':true})]);
   await pool.query('INSERT INTO sessions(token,user_id) VALUES($1,$2)',[key,id]);
  }
  const delivered=[];installEmployeeAccountRoutes({app,pool,authRequired,onChange:async e=>delivered.push(e)});
  server=await new Promise(r=>{const s=app.listen(0,'127.0.0.1',()=>r(s));});const base=`http://127.0.0.1:${server.address().port}`;
  const req=async(path,method='GET',body,token='owner')=>{const r=await fetch(base+path,{method,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});return {status:r.status,body:await r.json()};};
  const row=async key=>(await pool.query('SELECT * FROM users WHERE id=$1',[ids[key]])).rows[0];
  const change=async(key,action,token='owner',extra={})=>req(`/api/company/employees/${ids[key]}/${action}`,'POST',{expected_revision:Number((await row(key)).account_revision),...extra},token);
  const permissionsBefore=(await pool.query('SELECT * FROM employee_permissions WHERE user_id=$1',[ids.employee])).rows[0];
  await t.test('non-owner claims, self, owner, peer admin and foreign employee fail closed',async()=>{
   assert.equal((await change('employee','lock','admin')).status,403);
   assert.equal((await change('owner','disable')).status,403);
   assert.equal((await change('foreign','disable')).status,404);
   const governance=createPermissionGovernance({pool});
   await governance.update({userId:ids.owner,companyId:company},[{id:ids.admin,preset:'admin',overrides:{'team.manage_accounts':true,'team.purge_private':true},expected_revision:1}]);
   assert.equal((await change('peer','lock','admin')).status,403);
   assert.equal((await change('admin','lock','admin')).status,403);
  });
  await t.test('lock immediately denies old session and password login with exact message; unlock does not revive sessions',async()=>{
   assert.equal((await change('employee','lock','admin')).status,200);
   const locked=await row('employee');assert.ok(locked.locked_at);assert.equal(locked.deleted_at,null);assert.equal(locked.recovery_until,null);
   assert.deepEqual((await req('/me','GET',undefined,'employee')).body,{error:'account_locked',message:'Your account is locked by your administrator.'});
   assert.equal((await req('/auth/login','POST',{email:'employee@example.invalid',password})).body.message,'Your account is locked by your administrator.');
   assert.equal((await change('employee','unlock')).status,200);
   assert.equal((await req('/me','GET',undefined,'employee')).status,401);
   const login=await req('/auth/login','POST',{email:'employee@example.invalid',password});assert.equal(login.status,200);
   await pool.query('INSERT INTO sessions(token,user_id) VALUES($1,$2)',['current-employee',ids.employee]);
  });
  await t.test('disable moves directory, denies all sessions and preserves credentials/photo/grants',async()=>{
   const result=await change('employee','disable','admin');assert.equal(result.status,200);
   const disabled=await row('employee');assert.equal(disabled.private_data_state,'recoverable');assert.equal(disabled.operational_eligible,false);
   assert.equal(disabled.recovery_until-disabled.deleted_at,30*24*60*60*1000);
   assert.equal(disabled.display_name,'Historic employee');assert.equal(disabled.photo_url,'https://example.invalid/photo/employee');assert.ok(disabled.password_hash);
   assert.deepEqual((await pool.query('SELECT * FROM employee_permissions WHERE user_id=$1',[ids.employee])).rows[0],permissionsBefore);
   assert.equal((await req('/me','GET',undefined,'current-employee')).body.message,'Your account has been disabled.');
   assert.equal((await req('/auth/login','POST',{email:'employee@example.invalid',password})).body.message,'Your account has been disabled.');
   assert.equal((await req('/api/company/employee-accounts')).body.employees.some(e=>e.id===ids.employee),false);
   assert.equal((await req('/api/company/employee-accounts?disabled=true')).body.employees.some(e=>e.id===ids.employee),true);
   assert.equal((await pool.query('SELECT wolf_employee_operational(u) AS eligible FROM users u WHERE id=$1',[ids.employee])).rows[0].eligible,false);
  });
  await t.test('restore requires current state and unexpired server deadline, keeps eligibility held until reviewed',async()=>{
   const old=Number((await row('employee')).account_revision);
   assert.equal((await req(`/api/company/employees/${ids.employee}/restore`,'POST',{expected_revision:old-1})).status,409);
   const results=await Promise.all([req(`/api/company/employees/${ids.employee}/restore`,'POST',{expected_revision:old}),req(`/api/company/employees/${ids.employee}/restore`,'POST',{expected_revision:old})]);assert.deepEqual(results.map(x=>x.status).sort(),[200,409]);
   assert.equal((await row('employee')).operational_eligible,false);
   assert.equal((await change('employee','review-eligibility')).status,400);
   const bundle={id:randomUUID(),name:'Retained booking crew',worker_user_ids:[ids.employee],service_ids:[],all_services:true,enabled:true};
   await pool.query('UPDATE companies SET customer_booking_settings=$2,customer_booking_version=1 WHERE id=$1',[company,JSON.stringify({resource_bundles:[bundle]})]);
   let impact=(await req(`/api/company/employees/${ids.employee}/account`)).body.impact;
   assert.equal(impact.other_obligations.find(s=>s.name==='customer_booking_crews').records[0].name,'Retained booking crew');
   await pool.query('UPDATE companies SET customer_booking_version=2 WHERE id=$1',[company]);
   assert.equal((await change('employee','review-eligibility','owner',{confirm_reviewed:true,expected_impact:impact.review_token})).status,409,'Crew changes invalidate the reviewed snapshot');
   impact=(await req(`/api/company/employees/${ids.employee}/account`)).body.impact;
   assert.equal((await change('employee','review-eligibility','owner',{confirm_reviewed:true,expected_impact:'stale'})).status,409);
   assert.equal((await change('employee','review-eligibility','owner',{confirm_reviewed:true,expected_impact:impact.review_token})).status,200);
   assert.equal((await row('employee')).operational_eligible,true);
   await change('employee','disable');await pool.query("UPDATE users SET recovery_until=now()-interval '1 second' WHERE id=$1",[ids.employee]);
   assert.equal((await change('employee','restore')).body.error,'recovery_unavailable');
  });
  await t.test('custom role templates are owner-controlled snapshots, do not mutate existing grants, use optimistic versions',async()=>{
   assert.equal((await req('/api/company/employee-role-presets','POST',{name:'Field',base_preset:'technician',overrides:{}},'admin')).status,403);
   const made=await req('/api/company/employee-role-presets','POST',{name:'Field',base_preset:'technician',overrides:{'quotes.edit':true}});assert.equal(made.status,200);
   const id=made.body.preset.id;
   assert.equal((await req(`/api/company/employee-role-presets/${id}`,'PUT',{name:'Field updated',base_preset:'technician',overrides:{},expected_revision:0})).status,409);
   assert.deepEqual((await pool.query('SELECT * FROM employee_permissions WHERE user_id=$1',[ids.employee])).rows[0],permissionsBefore);
   assert.equal((await req(`/api/company/employees/${ids.legacy}/apply-role`,'POST',{role_id:id,role_revision:0,expected_revision:1})).status,409);
   assert.equal((await req(`/api/company/employees/${ids.legacy}/apply-role`,'POST',{role_id:id,role_revision:1,expected_revision:1},'admin')).status,403);
   const applied=await req(`/api/company/employees/${ids.legacy}/apply-role`,'POST',{role_id:id,role_revision:1,expected_revision:1});assert.equal(applied.status,200);assert.equal(applied.body.access.capabilities['quotes.edit'],true);
   assert.equal((await req(`/api/company/employees/${ids.legacy}/apply-role`,'POST',{role_id:id,role_revision:1,expected_revision:1})).status,409);
   assert.equal((await req(`/api/company/employee-role-presets/${id}`,'DELETE',{expected_revision:1})).status,200);
   assert.equal((await pool.query('SELECT permission_overrides FROM employee_permissions WHERE user_id=$1',[ids.legacy])).rows[0].permission_overrides['quotes.edit'],true);
  });
  await t.test('permission windows restrict effective actions, keep editable grants, and publish invalidation immediately',async()=>{
   const parts=new Intl.DateTimeFormat('en-US',{timeZone:'America/New_York',hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).formatToParts(new Date());
   const minutes=Number(parts.find(p=>p.type==='hour').value)*60+Number(parts.find(p=>p.type==='minute').value);
   const hhmm=n=>String(Math.floor((n%1440)/60)).padStart(2,'0')+':'+String(n%60).padStart(2,'0');
   const windows={'jobs.view':{days:[0,1,2,3,4,5,6],start:hhmm(minutes+60),end:hhmm(minutes+120)}};
   const before=delivered.length;
   assert.equal((await req(`/api/company/employees/${ids.legacy}/permission-windows`,'PUT',{windows,expected_revision:2},'admin')).status,403);
   assert.equal((await req(`/api/company/employees/${ids.legacy}/permission-windows`,'PUT',{windows,expected_revision:2})).status,200);
   assert.ok(delivered.length>before);assert.equal(delivered.at(-1).reason,'permission_windows_changed');
   const governance=createPermissionGovernance({pool});
   assert.equal((await governance.effective({userId:ids.legacy,companyId:company})).access.capabilities['jobs.work'],false);
   const editor=(await governance.employees({userId:ids.owner,companyId:company})).employees.find(e=>e.id===ids.legacy);
   assert.equal(editor.access.capabilities['jobs.work'],true);assert.deepEqual(editor.permission_windows,windows);
   assert.equal((await req(`/api/company/employees/${ids.legacy}/permission-windows`,'PUT',{windows:{},expected_revision:2})).status,409);
  });
  assert.ok(delivered.some(e=>e.reason==='account_lock'));assert.ok(delivered.some(e=>e.reason==='account_disable'));
  assert.ok(Number((await pool.query('SELECT count(*) FROM employee_account_audit')).rows[0].count)>=5);
 }finally{if(server)await new Promise(r=>server.close(r));await backend?.pool.end();local.stop();}
});
