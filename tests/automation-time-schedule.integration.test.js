import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import https from 'node:https';
import dns from 'node:dns/promises';
import {EventEmitter} from 'node:events';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {enqueueTimeSchedules,timeScheduleStillCurrent} from '../automation-time-schedule.js';
import {installAutomationSystem,automationTestHooks as hooks} from '../automations.js';

test('existing scheduler emits one exact published trigger; pause, stale version, leases and restart dedupe', {timeout:60000},async()=>{
 const pg=startLocalPostgres();pg.configureEnvironment();let pool;
 try{
  const backend=await import('../index.js');pool=backend.rawPool;await backend.bootstrap();
  await installAutomationSystem({...backend,pool,requireEmployer:backend.requireCapability('automations.manage'),disableProcessors:true});
  const company=randomUUID(),user=randomUUID(),definition=randomUUID(),version=randomUUID(),trigger=randomUUID();
  const now=new Date('2026-10-19T19:00:30Z');
  await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id,timezone,automations_enabled) VALUES($1,'Clock fixture',$3,$2,'UTC',true)",[company,user,company]);
  await pool.query("INSERT INTO users(id,email,role,company_id) VALUES($1,$2,'employer',$3)",[user,user+'@example.invalid',company]);
  await pool.query("INSERT INTO automation_definitions(id,company_id,name,status,created_by_user_id,updated_by_user_id) VALUES($1,$2,'Clock test','published',$3,$3)",[definition,company,user]);
  await pool.query("INSERT INTO automation_versions(id,automation_id,company_id,version_number,status,published_at) VALUES($1,$2,$3,1,'published','2026-10-18T00:00:00Z')",[version,definition,company]);
  await pool.query('UPDATE automation_definitions SET active_version_id=$2 WHERE id=$1',[definition,version]);
  const config={trigger_key:'time.schedule',schedule:{frequency:'daily',time:'19:00',timezone:'company'}};
  await pool.query("INSERT INTO automation_nodes(id,version_id,company_id,node_key,node_type,category,title,config) VALUES($1,$2,$3,'daily','trigger','Schedule','Daily',$4)",[trigger,version,company,config]);
  const otherDefinition=randomUUID(),otherVersion=randomUUID();
  await pool.query("INSERT INTO automation_definitions(id,company_id,name,status,created_by_user_id,updated_by_user_id) VALUES($1,$2,'Other clock','published',$3,$3)",[otherDefinition,company,user]);
  await pool.query("INSERT INTO automation_versions(id,automation_id,company_id,version_number,status,published_at) VALUES($1,$2,$3,1,'published','2026-10-18T00:00:00Z')",[otherVersion,otherDefinition,company]);
  await pool.query('UPDATE automation_definitions SET active_version_id=$2 WHERE id=$1',[otherDefinition,otherVersion]);
  await pool.query("INSERT INTO automation_nodes(id,version_id,company_id,node_key,node_type,category,title,config) VALUES($1,$2,$3,'other','trigger','Schedule','Other',$4)",[randomUUID(),otherVersion,company,{...config,schedule:{...config.schedule,time:'20:00'}}]);
  const invalid=hooks.validateGraphPayload({nodes:[{id:trigger,node_key:'daily',node_type:'trigger',config:{...config,schedule:{...config.schedule,time:'26:00'}}}],edges:[]});
  assert.ok(invalid.errors.includes('invalid_time_schedule:daily'));
  await Promise.all([enqueueTimeSchedules(pool,now),enqueueTimeSchedules(pool,now)]);
  const row=(await pool.query("SELECT * FROM automation_scheduled_events WHERE company_id=$1",[company])).rows;
  assert.equal(row.length,1);assert.equal(row[0].payload.trigger_node_id,trigger);
  assert.equal(await timeScheduleStillCurrent(pool,row[0],now),true);
  await pool.query("UPDATE companies SET automations_enabled=false WHERE id=$1",[company]);
  assert.equal(await timeScheduleStillCurrent(pool,row[0],now),false);
  await pool.query("UPDATE companies SET automations_enabled=true WHERE id=$1",[company]);
  assert.equal(await timeScheduleStillCurrent(pool,{...row[0],source_version:randomUUID()},now),false);
  // Simulate a worker crash after taking the lease. The existing processor must
  // recover it and emit the durable event once, without a new timer/daemon.
  await pool.query("UPDATE automation_scheduled_events SET status='firing',locked_at=now()-interval '5 minutes' WHERE id=$1",[row[0].id]);
  await hooks.processScheduledAutomationEvents(now);await hooks.processScheduledAutomationEvents(now);
  let events=(await pool.query("SELECT * FROM automation_events WHERE company_id=$1 AND event_type='time.schedule'",[company])).rows;
  assert.equal(events.length,1);assert.equal(events[0].payload.trigger_node_id,trigger);
  assert.equal(events[0].occurred_at.toISOString(),'2026-10-19T19:00:00.000Z');
  await hooks.processAutomationEvents();await hooks.processAutomationEvents();
  const runs=(await pool.query('SELECT automation_id,status FROM automation_runs WHERE company_id=$1',[company])).rows;
  assert.deepEqual(runs,[{automation_id:definition,status:'completed'}]);
  // Legacy inline actions also retain an accepted effect when JSON mapping
  // fails, so a resumed node cannot duplicate the external request.
  const action=randomUUID(),actionConfig={action_key:'webhook.send',url:'https://example.com/fixture',response_mappings:[{name:'result',path:'/result',type:'text'}]};
  await pool.query("INSERT INTO automation_nodes(id,version_id,company_id,node_key,node_type,category,title,config) VALUES($1,$2,$3,'legacy','action','Webhooks','Legacy',$4)",[action,version,company,actionConfig]);
  const run=(await pool.query('SELECT * FROM automation_runs WHERE company_id=$1',[company])).rows[0];
  const originalLookup=dns.lookup,originalRequest=https.request;let requests=0;
  try{
   dns.lookup=async()=>[{address:'93.184.216.34',family:4}];
   https.request=(_url,_options,callback)=>{const request=new EventEmitter();request.destroy=()=>{};request.end=()=>{requests++;queueMicrotask(()=>{const response=new EventEmitter();response.statusCode=200;response.headers={};response.destroy=()=>{};callback(response);response.emit('data',Buffer.from('accepted but not JSON'));response.emit('end');});};return request;};
   for(let retry=0;retry<2;retry++)await assert.rejects(()=>hooks.actionExecutors()['webhook.send'](run,{id:action},actionConfig),e=>e.code==='webhook_response_mapping_failed');
   assert.equal(requests,1);
   const effect=(await pool.query("SELECT status,result FROM automation_action_effects WHERE run_id=$1 AND node_id=$2",[run.id,action])).rows[0];
   assert.equal(effect.status,'confirmed');assert.equal(effect.result.response_mapping_error,'response_not_json');assert.deepEqual(effect.result.response,{});
  }finally{dns.lookup=originalLookup;https.request=originalRequest;}
  assert.equal((await pool.query('SELECT status FROM automation_scheduled_events WHERE id=$1',[row[0].id])).rows[0].status,'fired');
  // Recreate the scheduler service/retry the tick: unique date identity survives.
  assert.equal(await enqueueTimeSchedules(pool,now),0);
  await pool.query("UPDATE automation_definitions SET status='paused' WHERE id=$1",[definition]);
  assert.equal(await enqueueTimeSchedules(pool,new Date('2026-10-20T19:00:30Z')),0);
  await pool.query("UPDATE automation_definitions SET status='published' WHERE id=$1",[definition]);
  assert.equal(await enqueueTimeSchedules(pool,new Date('2026-10-20T21:00:00Z')),0);
  assert.equal(await enqueueTimeSchedules(pool,new Date('2026-10-21T19:00:30Z')),1);
  const next=(await pool.query("SELECT * FROM automation_scheduled_events WHERE company_id=$1 AND status='scheduled'",[company])).rows[0];
  assert.equal(await timeScheduleStillCurrent(pool,next,new Date('2026-10-21T19:16:00Z')),false);
  await pool.query("UPDATE automation_definitions SET status='archived' WHERE id=$1",[definition]);
  await hooks.processScheduledAutomationEvents(new Date('2026-10-21T19:00:30Z'));
  assert.equal((await pool.query('SELECT status FROM automation_scheduled_events WHERE id=$1',[next.id])).rows[0].status,'canceled');
  events=(await pool.query("SELECT * FROM automation_events WHERE company_id=$1 AND event_type='time.schedule'",[company])).rows;assert.equal(events.length,1);
 }finally{if(pool)await pool.end();pg.stop();}
});
