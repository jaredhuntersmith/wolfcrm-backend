import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {installAutomationSystem,emitAutomationEvent,automationTestHooks as hooks} from '../automations.js';

test('weather automations retire without rewriting unrelated published rules or history',{timeout:60000},async()=>{
 const pg=startLocalPostgres();pg.configureEnvironment();let pool,server;
 try{
  const backend=await import('../index.js');pool=backend.rawPool;await backend.bootstrap();
  await installAutomationSystem({...backend,pool,requireEmployer:backend.requireCapability('automations.manage'),disableProcessors:true});
  const company=randomUUID(),user=randomUUID(),weatherDefinition=randomUUID(),normalDefinition=randomUUID(),weatherVersion=randomUUID(),normalVersion=randomUUID(),eventID=randomUUID();
  await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id,timezone) VALUES($1,'Weather retirement',$3,$2,'UTC')",[company,user,company]);
  await pool.query("INSERT INTO users(id,email,role,company_id) VALUES($1,$2,'employer',$3)",[user,user+'@example.invalid',company]);
  for(const [id,version,name,key] of [[weatherDefinition,weatherVersion,'Old weather rule','weather.job_at_risk'],[normalDefinition,normalVersion,'Regular job rule','job.created']]){
   await pool.query("INSERT INTO automation_definitions(id,company_id,name,status,created_by_user_id) VALUES($1,$2,$3,'published',$4)",[id,company,name,user]);
   await pool.query("INSERT INTO automation_versions(id,automation_id,company_id,version_number,status) VALUES($1,$2,$3,1,'published')",[version,id,company]);
   await pool.query('UPDATE automation_definitions SET active_version_id=$2 WHERE id=$1',[id,version]);
   await pool.query("INSERT INTO automation_nodes(id,version_id,company_id,node_key,node_type,category,title,config) VALUES($1,$2,$3,'trigger','trigger','Schedule','Trigger',$4)",[randomUUID(),version,company,{trigger_key:key}]);
  }
  await pool.query("INSERT INTO automation_events(id,company_id,event_type,processing_status) VALUES($1,$2,'weather.job_at_risk','pending')",[eventID,company]);
  await pool.query("INSERT INTO automation_runs(id,company_id,automation_id,automation_version_id,trigger_event_id,status) VALUES($1,$2,$3,$4,$5,'queued')",[randomUUID(),company,weatherDefinition,weatherVersion,eventID]);
  await installAutomationSystem({...backend,pool,requireEmployer:backend.requireCapability('automations.manage'),disableProcessors:true});
  const rows=(await pool.query("SELECT id,status,pause_until,metadata FROM automation_definitions WHERE company_id=$1",[company])).rows;
  assert.equal(rows.find(r=>r.id===weatherDefinition).status,'paused');
  assert.equal(rows.find(r=>r.id===weatherDefinition).pause_until,null);
  assert.equal(rows.find(r=>r.id===weatherDefinition).metadata.retired_weather_trigger,true);
  assert.equal(rows.find(r=>r.id===normalDefinition).status,'published');
  assert.equal((await pool.query('SELECT processing_status FROM automation_events WHERE id=$1',[eventID])).rows[0].processing_status,'processed');
  assert.equal((await pool.query('SELECT status FROM automation_runs WHERE trigger_event_id=$1',[eventID])).rows[0].status,'canceled');
  assert.equal(await emitAutomationEvent({companyId:company,eventType:'weather.job_at_risk'}),null);
  assert.ok(hooks.validateGraphPayload({nodes:[{id:randomUUID(),node_key:'weather',node_type:'trigger',config:{trigger_key:'weather.job_at_risk'}}],edges:[]}).errors.includes('retired_weather_trigger:weather'));
  const member=randomUUID();
  await pool.query("INSERT INTO users(id,email,role,company_id) VALUES($1,$2,'employee',$3)",[member,member+'@example.invalid',company]);
  await pool.query("INSERT INTO employee_permissions(user_id,company_id,permission_preset,permission_overrides) VALUES($1,$2,'manager',$3)",[member,company,JSON.stringify({'schedule.view':false})]);
  await pool.query("INSERT INTO sessions(token,user_id) VALUES('weather-retirement-owner',$1),('weather-retirement-member',$2)",[user,member]);
  server=await new Promise(resolve=>{const listener=backend.app.listen(0,'127.0.0.1',()=>resolve(listener));});
  const origin='http://127.0.0.1:'+server.address().port;
  const request=(path,who='owner',method='GET')=>fetch(origin+path,{method,headers:{Authorization:'Bearer weather-retirement-'+who,'Content-Type':'application/json'},body:method==='GET'?undefined:'{}'});
  assert.equal((await request('/api/weather/status','member')).status,403);
  await pool.query('UPDATE employee_permissions SET permission_overrides=$2,permission_revision=permission_revision+1 WHERE user_id=$1',[member,JSON.stringify({'jobs.view':false})]);
  assert.equal((await request('/api/weather/status','member')).status,410);
  assert.equal((await request('/api/weather/risks','member')).status,403);
  for(const [path,method] of [['/api/weather/status','GET'],['/api/weather/settings','GET'],['/api/weather/settings','PUT'],['/api/weather/risks','GET'],['/api/weather/reschedule/preview','POST'],['/api/weather/reschedule','POST']]){
   const response=await request(path,'owner',method);
   assert.equal(response.status,410,path+' '+method);
   assert.equal((await response.json()).error,'weather_feature_retired');
  }
 }finally{if(server)await new Promise(resolve=>server.close(resolve));if(pool)await pool.end();pg.stop();}
});

