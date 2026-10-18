import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {installGoogleSheetsSchema} from '../google-sheets.js';
import {installAutomationSystem,automationTestHooks} from '../automations.js';
import {installAgreementBookingSchema} from '../agreement-booking.js';
import {installMCP} from '../mcp/index.js';
import {withinHours,accessStatus,alwaysHours,hoursSchema} from '../mcp/hours.js';
import {controlConnectionFromAutomation} from '../mcp/automation.js';
const hours=(mode,windows,exceptions=[])=>({timezone:'America/New_York',mode,windows,exceptions});
test('operating hours: boundaries, overnight, DST, exceptions and intersection',()=>{
 const regular=hours('allowed',[{days:[1],start:'09:00',end:'17:00'}]);
 assert.equal(withinHours(regular,new Date('2026-10-19T08:59:59-04:00')),false);assert.equal(withinHours(regular,new Date('2026-10-19T09:00:00-04:00')),true);assert.equal(withinHours(regular,new Date('2026-10-19T17:00:00-04:00')),false);
 const overnight=hours('allowed',[{days:[1],start:'22:00',end:'02:00'}]);assert.equal(withinHours(overnight,new Date('2026-10-20T01:59:00-04:00')),true);assert.equal(withinHours(overnight,new Date('2026-10-20T22:30:00-04:00')),false);
 const dst=hours('allowed',[{days:[7],start:'01:00',end:'02:00'}]);assert.equal(withinHours(dst,new Date('2026-11-01T01:30:00-04:00')),true);assert.equal(withinHours(dst,new Date('2026-11-01T01:30:00-05:00')),true);assert.equal(withinHours(dst,new Date('2026-03-08T03:00:00-04:00')),false);
 const blocked=hours('blocked',[{days:[1],start:'09:00',end:'17:00'}]);assert.equal(withinHours(blocked,new Date('2026-10-19T09:00:00-04:00')),false);
 const start='2026-10-19T09:00:00-04:00',end='2026-10-19T11:00:00-04:00';const exceptions=hours('allowed',[],[{start,end,allow:true},{start,end,allow:false}]);assert.equal(withinHours(exceptions,new Date(start)),false);
 const row={enabled:true,operating_hours:regular};assert.equal(accessStatus(row,blocked,new Date(start)).reason,'company_hours');assert.equal(accessStatus({...row,enabled:false},null,new Date(start)).reason,'disabled');assert.equal(accessStatus({...row,revoked_at:start},null,new Date(start)).reason,'revoked');assert.equal(accessStatus(row,null,new Date('2026-10-19T08:59:00-04:00'),{next:true}).next_allowed_at,'2026-10-19T13:00:00.000Z');assert.throws(()=>hoursSchema.parse({...regular,timezone:'Not/AZone'}));
});

test('native manager with real PostgreSQL and SDK: policies, keys, approvals, cap and isolation',{timeout:180000},async t=>{
 const pg=startLocalPostgres();pg.configureEnvironment();let backend,server;const clients=[];
 try{
  backend=await import('../index.js');await backend.bootstrap();await installAgreementBookingSchema(backend.pool);const {pool,rawPool,app,authRequired}=backend;await installGoogleSheetsSchema(pool);await installAutomationSystem({app,pool,authRequired,requireEmployer:(_r,_s,n)=>n(),disableProcessors:true});
  const a=randomUUID(),b=randomUUID(),owner=randomUUID(),other=randomUUID(),employee=randomUUID(),admin=randomUUID();
  await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id) VALUES($1,'Manager QA A','MGA',$3),($2,'Manager QA B','MGB',$4)",[a,b,owner,other]);
  for(const [id,cid,role]of [[owner,a,'employer'],[other,b,'employer'],[employee,a,'employee'],[admin,a,'employee']])await pool.query('INSERT INTO users(id,email,display_name,company_id,role) VALUES($1,$2,$3,$4,$5)',[id,id+'@example.invalid','QA user',cid,role]);
  for(const [id,preset]of [[employee,'technician'],[admin,'admin']])await pool.query('INSERT INTO employee_permissions(user_id,company_id,permission_preset,permission_overrides) VALUES($1,$2,$3,$4)',[id,a,preset,JSON.stringify(preset==='admin'?{'ai.manage':false}:{})]);
  for(const id of [owner,other,employee,admin])await pool.query('INSERT INTO sessions(token,user_id) VALUES($1,$2)',[id,id]);
  server=await new Promise(r=>{const s=app.listen(0,'127.0.0.1',()=>r(s));});const origin='http://127.0.0.1:'+server.address().port;
  const env={MCP_ENABLED:'true',MCP_PUBLIC_ORIGIN:origin,MCP_REDIRECT_URIS:'["https://client.example.invalid/callback"]',NODE_ENV:'test'};
  await installMCP({app,pool,rawPool,authRequired,env,startMaintenance:false,verifyIdentity:async()=>null});
  const http=async(path,method='GET',body,user=owner)=>{const r=await fetch(origin+path,{method,headers:{Authorization:'Bearer '+user,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});return {status:r.status,body:await r.json()};};
  const base='/api/ai-connections/manager',get=async()=> (await http(base)).body;
  const create=async(name='QA Jack',user=owner,cid=a)=>http(base,'POST',{expected_company_id:cid,name,description:'Isolated test',provider:'ElevenLabs'},user);
  const created=await create();assert.equal(created.status,201,JSON.stringify(created.body));let row=created.body;
  const guard=()=>({expected_company_id:a,expected_revision:row.revision});
  const fresh=async()=>row=(await get()).connections.find(r=>r.id===row.id);
  const save=async changes=>{const r=await http(base+'/'+row.id,'PUT',{...guard(),name:row.name,description:row.description,provider:row.provider,enabled:row.enabled,paused_until:row.paused_until,operating_hours:row.operating_hours,tool_policy:row.tool_policy,automatic_booking:row.automatic_booking,...changes});if(r.status===200)await fresh();return r;};
  const issue=async()=>{const r=await http(base+'/'+row.id+'/key','POST',{...guard(),valid_days:1});assert.equal(r.status,200,JSON.stringify(r.body));await fresh();return r.body.authorization;};
  const connect=async authorization=>{const c=new Client({name:'Isolated native manager QA',version:'1'});await c.connect(new StreamableHTTPClientTransport(new URL(origin+'/mcp'),{requestInit:{headers:{Authorization:authorization}}}));clients.push(c);return c;};
  let authorization=await issue(),client=await connect(authorization);
  const call=async(name,args={})=>{const r=await client.callTool({name,arguments:args});return r.structuredContent||JSON.parse(r.content[0].text);};
  await t.test('owner/admin access, complete catalog, denied defaults and no secret in listing',async()=>{
   assert.equal((await http(base,'GET',undefined,employee)).status,403);assert.equal((await http(base,'GET',undefined,admin)).status,403);
   await pool.query("UPDATE employee_permissions SET permission_overrides='{\"ai.manage\":true}' WHERE user_id=$1",[admin]);assert.equal((await http(base,'GET',undefined,admin)).status,200);
   assert.equal((await client.listTools()).tools.length,0);assert.ok(row.catalog.length>=33);assert.equal(Object.keys(row.tool_policy).length,0);assert.ok(!JSON.stringify(await get()).includes(authorization));
   assert.equal((await http(base+'/'+row.id+'/key','POST',{...guard(),valid_days:1},other)).status,409);
   const foreign=(await create('Foreign',other,b)).body;assert.equal((await http(base+'/'+foreign.id+'/revoke','POST',guard())).status,404);
   assert.equal((await save({tool_policy:{future_tool:{allow:true,approval:false}}})).status,400);
   assert.equal((await save({tool_policy:{quote_draft:{allow:true,approval:false}}})).status,403);
  });
  await t.test('native booking configuration: no invented duration, isolated choices, incomplete paths and stale acknowledgement',async()=>{
   assert.equal(row.booking_config.quote_duration_minutes,null);assert.equal(row.booking_config.quote_enabled,false);
   assert.ok(row.booking_workers.every(w=>w.id!==other));
   const config={...row.booking_config,postal_codes:['10001']};
   assert.equal((await save({booking_config:config})).status,200);assert.deepEqual(row.booking_config.postal_codes,['10001']);
   assert.equal((await save({booking_config:{...config,quote_enabled:true}})).body.error,'booking_rules_incomplete');
   assert.equal((await save({booking_config:{...config,quote_worker_ids:[other]}})).body.error,'invalid_workers');
   const foreignService=randomUUID();await pool.query("INSERT INTO saved_services(id,company_id,name) VALUES($1,$2,'Foreign service')",[foreignService,b]);
   assert.ok(!row.booking_services.some(s=>s.id===foreignService));
   assert.equal((await save({booking_config:{...config,direct_job_profiles:[{id:randomUUID(),name:'QA',service_ids:[foreignService],property_type:'residential',max_stories:2,max_window_count:null,duration_minutes:60}]}})).body.error,'invalid_profile_services');
   assert.equal((await save({booking_config:{...config,job_rules_acknowledged:true},automatic_booking:true})).status,200);
   assert.equal(row.booking_config.job_rules_acknowledged,true);assert.equal(row.automatic_booking,true);
   await pool.query("UPDATE companies SET customer_booking_settings='{\"enabled\":false,\"qa_changed\":true}' WHERE id=$1",[a]);await fresh();
   assert.equal(row.booking_config.job_rules_acknowledged,false);assert.ok(row.missing_booking_rules.job.includes('review existing Schedule booking rules'));
   assert.equal((await save({name:'Renamed without rule consent'})).status,200);assert.equal(row.booking_config.job_rules_acknowledged,false);
   assert.equal((await save({booking_config:{...row.booking_config,job_enabled:true,job_rules_acknowledged:true,require_quote_acceptance:false,require_deposit:false}})).body.error,'configure_schedule_booking_first');
  });
  await t.test('per-call access and read approval exact arguments, rejection, expiry, no protected data',async()=>{
   assert.equal((await save({tool_policy:{crm_identity:{allow:true,approval:true}}})).status,200);
   const id=randomUUID(),p=await call('crm_identity',{_request_id:id});assert.equal(p.state,'pending');assert.equal(p.result,null);assert.ok(!JSON.stringify(p).includes('Manager QA A'));
   const proposal=(await get()).approvals.find(x=>x.id===p.approval_id);assert.ok(proposal);
   assert.equal((await http(base,'GET',undefined,admin)).body.approvals.length,0,'admin cannot see sponsor-private proposal arguments');
   assert.equal((await http('/api/ai-connections/approvals/'+p.approval_id,'POST',{expected_hash:proposal.input_hash,decision:'approve'},admin)).status,404);
   const approve=()=>http('/api/ai-connections/approvals/'+p.approval_id,'POST',{expected_hash:proposal.input_hash,decision:'approve'});
   assert.equal((await approve()).status,200);assert.equal((await approve()).status,200);assert.equal((await call('crm_identity',{_request_id:id})).result.company_id,a);
   await save({tool_policy:{crm_identity:{allow:true,approval:true},crm_get:{allow:true,approval:true}}});
   const guessed=randomUUID(),args={entity:'contacts',id:guessed,_request_id:randomUUID()},pending=await call('crm_get',args);assert.equal(pending.state,'pending');assert.equal((await call('crm_get',{...args,id:randomUUID()})).error,'idempotency_conflict');
   const pp=(await get()).approvals.find(x=>x.id===pending.approval_id);assert.equal((await http('/api/ai-connections/approvals/'+pp.id,'POST',{expected_hash:pp.input_hash,decision:'reject'})).status,200);assert.equal((await call('crm_get',args)).state,'rejected');
   const exp=await call('crm_identity',{_request_id:randomUUID()});await pool.query("UPDATE mcp_approvals SET expires_at=now()-interval '1 minute' WHERE id=$1",[exp.approval_id]);const xp=(await pool.query('SELECT input_hash FROM mcp_approvals WHERE id=$1',[exp.approval_id])).rows[0];assert.equal((await http('/api/ai-connections/approvals/'+exp.approval_id,'POST',{expected_hash:xp.input_hash,decision:'approve'})).status,409);
  });
  await t.test('no approval writes are idempotent, isolation and current policy govern existing transport',async()=>{
   await save({tool_policy:{contact_create:{allow:true,approval:false},crm_get:{allow:true,approval:false},crm_identity:{allow:true,approval:false}}});
   const input={request_id:randomUUID(),contact:{name:'Only isolated data'}};const first=await call('contact_create',input);assert.ok(first.id,JSON.stringify(first));assert.equal((await call('contact_create',input)).id,first.id);
   assert.equal((await pool.query('SELECT count(*)::int n FROM contacts WHERE company_id=$1 AND name=$2',[a,'Only isolated data'])).rows[0].n,1);
   const foreignID=randomUUID();await pool.query("INSERT INTO contacts(id,user_id,company_id,name) VALUES($1,$2,$3,'Foreign secret')",[foreignID,other,b]);assert.ok((await call('crm_get',{entity:'contacts',id:foreignID})).error);
   await save({enabled:false});assert.equal((await call('crm_identity')).error,'disabled');assert.ok((await (await connect(authorization)).listTools()).tools.length);
   await save({enabled:true,operating_hours:hours('allowed',[])});assert.equal((await call('crm_identity')).error,'connection_hours');
   await save({operating_hours:null});const settings=(await get()).company_schedule;await http('/api/ai-connections/manager-company-hours','PUT',{expected_company_id:a,expected_revision:settings.revision,operating_hours:hours('allowed',[])});assert.equal((await call('crm_identity')).error,'company_hours');
   const current=(await get()).company_schedule;await http('/api/ai-connections/manager-company-hours','PUT',{expected_company_id:a,expected_revision:current.revision,operating_hours:alwaysHours()});
   await save({tool_policy:{crm_identity:{allow:true,approval:true}}});const p=await call('crm_identity',{_request_id:randomUUID()}),pp=(await get()).approvals.find(x=>x.id===p.approval_id);await save({enabled:false});assert.equal((await http('/api/ai-connections/approvals/'+p.approval_id,'POST',{expected_hash:pp.input_hash,decision:'approve'})).status,409);
  });
  await t.test('internal automation operates while disabled, cannot cross tenant or restore revoked key',async()=>{
   const definition=randomUUID(),version=randomUUID();
   await pool.query("INSERT INTO automation_definitions(id,company_id,name,created_by_user_id) VALUES($1,$2,'MCP control QA',$3)",[definition,a,owner]);
   await pool.query("INSERT INTO automation_versions(id,automation_id,company_id,version_number,status,created_by_user_id) VALUES($1,$2,$3,1,'draft',$4)",[version,definition,a,owner]);
   assert.equal(automationTestHooks.actionCatalog().find(x=>x.key==='mcp.enable').visibility,'core');
   await automationTestHooks.actionExecutors()['mcp.enable']({company_id:a,automation_version_id:version},{},{action_key:'mcp.enable',connection_id:row.id});await fresh();assert.equal(row.enabled,true);
   await controlConnectionFromAutomation(pool,{companyId:a,userId:owner,connectionId:row.id,action:'pause',pauseUntil:new Date(Date.now()+3600000).toISOString()});assert.equal((await call('crm_identity')).error,'paused_until');
   await assert.rejects(()=>controlConnectionFromAutomation(pool,{companyId:b,userId:other,connectionId:row.id,action:'enable'}));
   await assert.rejects(()=>controlConnectionFromAutomation(pool,{companyId:a,userId:employee,connectionId:row.id,action:'enable'}));
   await controlConnectionFromAutomation(pool,{companyId:a,userId:owner,connectionId:row.id,action:'enable'});await fresh();
  });
  await t.test('rotation, removed sponsor, expiry and revoke invalidate credential',async()=>{
   const oldAuthorization=authorization;authorization=await issue();assert.notEqual(authorization,oldAuthorization);const denied=await fetch(origin+'/mcp',{method:'POST',headers:{Authorization:oldAuthorization,'Content-Type':'application/json',Accept:'application/json, text/event-stream'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list'})});assert.equal(denied.status,401);client=await connect(authorization);
   await pool.query('UPDATE users SET deleted_at=now() WHERE id=$1',[owner]);await assert.rejects(()=>client.listTools());await pool.query('UPDATE users SET deleted_at=NULL WHERE id=$1',[owner]);
   await pool.query("UPDATE retell_connections SET expires_at=now()-interval '1 second' WHERE id=$1",[row.id]);await assert.rejects(()=>client.listTools());authorization=await issue();client=await connect(authorization);
   assert.equal((await http(base+'/'+row.id+'/revoke','POST',guard())).status,200);await assert.rejects(()=>client.listTools());await assert.rejects(()=>controlConnectionFromAutomation(pool,{companyId:a,userId:owner,connectionId:row.id,action:'enable'}));
  });
  await t.test('concurrent creation capped at ten; paused counts, archived releases slot',async()=>{
   const results=await Promise.all(Array.from({length:13},(_,i)=>create('Cap '+i)));assert.equal(results.filter(r=>r.status===201).length,10);assert.equal(results.filter(r=>r.body.error==='connection_limit').length,3);
   const s=await get();assert.equal(s.active_count,10);row=s.connections.find(c=>c.active!==false&&!c.revoked_at);await save({enabled:false});assert.equal((await create('Paused still counts')).body.error,'connection_limit');
   assert.equal((await http(base+'/'+row.id+'/archive','POST',guard())).status,200);assert.equal((await create('Replacement')).status,201);assert.ok((await get()).connections.some(c=>c.id===row.id&&c.archived_at));
  });
 }finally{await Promise.all(clients.map(c=>c.close().catch(()=>{})));if(server){server.closeAllConnections();await new Promise(r=>server.close(r));}await backend?.rawPool.end();pg.stop();}
});
