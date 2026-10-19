import test from 'node:test';import assert from 'node:assert/strict';import {randomUUID} from 'node:crypto';
import {digest} from '../mcp/context.js';
import {startLocalPostgres} from './helpers/local-postgres.js';import {installMCP} from '../mcp/index.js';import {installAssistant,commandSchema} from '../assistant/index.js';import {modelCatalog} from '../assistant/models.js';import {pinnedReadArguments,discoverCatalog,businessOutcome,clockContext} from '../assistant/reliability.js';
test('stable range, business status, discovery and company clock',()=>{
 const args=pinnedReadArguments('crm_availability',{},null,new Date('2026-10-19T20:43:22.964Z'));
 assert.deepEqual(pinnedReadArguments('crm_availability',args,null,new Date('2026-10-20')),args);
 assert.deepEqual(pinnedReadArguments('crm_availability',{}, {availability:{range_start:args.start,range_end:args.end}}),args);
 assert.equal(businessOutcome({status:'failed',reason:'outside_service_area_or_missing_zip'}).status,'failed');assert.equal(businessOutcome({data:{status:'pending_approval'}}).status,'pending');
 assert.match(clockContext('America/New_York',new Date('2026-10-19T20:43:22Z')),/Monday, October 19, 2026.*4:43:22 PM EDT/);
 assert.equal(discoverCatalog([{id:'native_navigate',name:'Navigate',description:'Open settings',category:'Native'}],'navigate schedule settings').length,1);
 assert.ok(commandSchema.safeParse({route:'settings',action:'discover_settings'}).success);assert.ok(!commandSchema.safeParse({route:'schedule',action:'discover_settings'}).success);
});
test('canonical owner jobs, exact approval, pinned evidence and native destinations',{timeout:180000},async t=>{
 const pg=startLocalPostgres();pg.configureEnvironment();let backend,server;
 try{
  backend=await import('../index.js');const {app,pool,authRequired}=backend;await backend.bootstrap();await (await import('../schedule-booking-guard.js')).installScheduleBookingGuard(pool);
  await (await import('../google-sheets.js')).installGoogleSheetsSchema(pool);
  await (await import('../automations.js')).installAutomationSystem({app,pool,authRequired,requireEmployer:(req,res,next)=>req.isCompanyOwner?next():res.sendStatus(403),disableProcessors:true});
  const company=randomUUID(),user=randomUUID(),foreignCompany=randomUUID(),foreign=randomUUID(),contact=randomUUID(),otherContact=randomUUID();
  for(const[c,u]of [[company,user],[foreignCompany,foreign]]){await pool.query('INSERT INTO companies(id,name,join_code,owner_user_id) VALUES($1,$2,$3,$4)',[c,'Repair fixture',c,u]);await pool.query("INSERT INTO users(id,email,display_name,company_id,role,password_hash) VALUES($1,$2,'Fixture owner',$3,'employer','fixture')",[u,u+'@example.invalid',c]);await pool.query('INSERT INTO sessions(token,user_id) VALUES($1,$2)',[u,u]);}
  for(const[id,c,u]of [[contact,company,user],[otherContact,foreignCompany,foreign]])await pool.query("INSERT INTO contacts(id,user_id,company_id,name,address) VALUES($1,$2,$3,'Jared Smith fixture','Partial street, no ZIP')",[id,u,c]);
  const env={MCP_ENABLED:'true',ASSISTANT_ENABLED:'true',ASSISTANT_OWNER_FUNDING:'true',MCP_PUBLIC_ORIGIN:'http://127.0.0.1',MCP_WEB_ORIGIN:'http://127.0.0.1',NODE_ENV:'test'};
  await installMCP({app,pool,authRequired,env,startMaintenance:false,verifyIdentity:async()=>null});
  const responses=[],requests=[];const provider={models:async()=>modelCatalog,respond:async(_s,request)=>{requests.push(request);assert.ok(responses.length,'Unexpected provider request');return responses.shift();}};
  const engine=await installAssistant({app,pool,authRequired,env,provider,startWorker:false});
  server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
  async function http(path,body,method=body?'POST':'GET',token=user){const r=await fetch('http://127.0.0.1:'+server.address().port+'/api/'+path,{method,headers:{authorization:'Bearer '+token,'content-type':'application/json'},body:body?JSON.stringify(body):undefined});return {status:r.status,data:await r.json()};}
  const connection=(await http('assistant/setup',{})).data.settings.connection_id;assert.deepEqual((await pool.query('SELECT tool_policy FROM mcp_connections WHERE id=$1',[connection])).rows[0].tool_policy,{});
  await http('assistant/settings',{expected_revision:1,funding:'owner',model:'gpt-6.1-sol',reasoning:'low',instructions:'Fixture only',memory_enabled:false,monthly_limit_micros:5000000},'PUT');
  const chat=(await http('assistant/conversations',{title:'Focused job repair'})).data.id;
  const grant=async(name,approval=false,extra={})=>pool.query('UPDATE mcp_connections SET tool_policy=jsonb_set(tool_policy,ARRAY[$2],$3::jsonb),revision=revision+1 WHERE id=$1',[connection,name,JSON.stringify({allow:true,approval,...extra})]);
  const tool=(name,args)=>({output:[{type:'function_call',call_id:randomUUID(),name,arguments:JSON.stringify(args)}],usage:{input_tokens:10,output_tokens:5}});
  const done=text=>({output:[{type:'message',role:'assistant',content:[{type:'output_text',text}]}],usage:{input_tokens:10,output_tokens:5}});
  async function start(text,context){const r=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text,context});assert.equal(r.status,202,JSON.stringify(r));await engine.tick();return (await http('assistant/runs/'+r.data.id)).data;}
  let jobRun;const actor=async()=>({...await app.locals.connectionManager.actorFor((await pool.query('SELECT * FROM mcp_connections WHERE id=$1',[connection])).rows[0]),assistantInvocation:{runId:jobRun||randomUUID(),callId:randomUUID()}});
  const invoke=async(name,args)=>app.locals.connectionManager.invoke(await actor(),name,args,randomUUID());
  t.beforeEach(async()=>pool.query('DELETE FROM mcp_rate_limits'));await grant('assistant_execute');
  const job={request_id:randomUUID(),contact_id:contact,title:'Exterior window cleaning',start:'2026-10-23T10:00:00-04:00',end:'2026-10-23T11:00:00-04:00',service_items:[{name:'Exterior window cleaning',qty:20}],worker_user_ids:[]};
  await t.test('new job creation defaults denied',async()=>{await assert.rejects(()=>invoke('assistant_job_create',job),e=>e.code==='tool_denied');assert.equal((await pool.query('SELECT count(*)::int n FROM schedule_events')).rows[0].n,0);});
  await t.test('availability survives repeated evidence validation',async()=>{
   await grant('crm_availability');responses.push(tool('load_capabilities',{ids:['crm_availability']}),tool('crm_availability',{}),done('Availability read.'));
   const run=await start('Read availability');assert.equal(run.status,'completed',JSON.stringify(run));const step=(await pool.query("SELECT arguments,result FROM wolf_assistant_steps WHERE run_id=$1 AND tool='crm_availability'",[run.id])).rows[0];assert.equal(step.arguments.start,step.result.availability.range_start);assert.equal(step.arguments.end,step.result.availability.range_end);assert.match(requests.at(-1).instructions,/Authoritative server clock:/);
  });
  await t.test('exact approval saves canonical time and quantity without customer booking config',async()=>{
   await grant('assistant_job_create',true);responses.push(tool('load_capabilities',{ids:['crm_availability','assistant_job_create']}),tool('crm_availability',{}),tool('assistant_job_create',job));const run=await start('Schedule fixture job for 20 windows Friday 10 to 11');jobRun=run.id;assert.equal(run.status,'waiting_approval',JSON.stringify(run));assert.equal((await pool.query('SELECT count(*)::int n FROM schedule_events')).rows[0].n,0);
   const p=(await pool.query("SELECT * FROM mcp_approvals WHERE connection_id=$1 AND operation='assistant_job_create' ORDER BY created_at DESC LIMIT 1",[connection])).rows[0];
   assert.equal((await http('ai-connections/approvals/'+p.id,{expected_hash:'0'.repeat(64),decision:'approve'})).status,409);assert.equal((await http('ai-connections/approvals/'+p.id,{expected_hash:p.input_hash,decision:'approve'},'POST',foreign)).status,404);
   const approved=await http('ai-connections/approvals/'+p.id,{expected_hash:p.input_hash,decision:'approve'});assert.equal(approved.status,200,JSON.stringify(approved));responses.push(done('Confirmed synthetic job.'));await engine.tick();const result=(await http('assistant/runs/'+run.id)).data;assert.equal(result.status,'completed',JSON.stringify(result));assert.equal(result.actions.find(a=>a.tool==='assistant_job_create').outcome.status,'succeeded');
   const saved=(await pool.query('SELECT * FROM schedule_events WHERE id=$1',[job.request_id])).rows[0];assert.equal(saved.service_items[0].qty,20);assert.equal(saved.start_at.toISOString(),'2026-10-23T14:00:00.000Z');assert.equal(saved.contact_id,contact);assert.equal((await pool.query('SELECT config FROM retell_connections WHERE id=$1',[connection])).rows[0].config.automatic_booking,undefined);
   const replay=await app.locals.capabilityService.execute(await actor(),'assistant_job_create',job);assert.equal(replay.data.id,job.request_id);assert.equal(replay.source_hash,digest(replay.data));assert.equal((await pool.query('SELECT count(*)::int n FROM schedule_events')).rows[0].n,1);
  });
  await t.test('tenant, denied fields and required interval stay enforced',async()=>{
   await grant('assistant_job_create');await pool.query('UPDATE wolf_assistant_runs SET automation_run_id=$2 WHERE id=$1',[jobRun,randomUUID()]);try{await assert.rejects(()=>invoke('assistant_job_create',{...job,request_id:randomUUID()}),e=>e.code==='owner_directed_assistant_required');}finally{await pool.query('UPDATE wolf_assistant_runs SET automation_run_id=NULL WHERE id=$1',[jobRun]);}await assert.rejects(()=>invoke('assistant_job_create',{...job,request_id:randomUUID(),contact_id:otherContact}),e=>e.status===404);
   await grant('assistant_job_create',false,{denied_input_fields:['service_items.*.qty']});await assert.rejects(()=>invoke('assistant_job_create',{...job,request_id:randomUUID()}),e=>e.status===403);
   assert.throws(()=>app.locals.capabilityService.definitions(null).find(d=>d.id==='assistant_job_create').inputSchema.parse({...job,end:undefined}));assert.equal((await pool.query('SELECT count(*)::int n FROM schedule_events')).rows[0].n,1);
  });
  await t.test('canonical worker conflicts, hours and revocation block owner job writes',async()=>{
   await grant('assistant_job_create');
   const assigned={...job,request_id:randomUUID(),worker_user_ids:[user]};await invoke('assistant_job_create',assigned);
   await assert.rejects(()=>invoke('assistant_job_create',{...assigned,request_id:randomUUID()}),e=>e.code==='schedule_resource_conflict');
   await pool.query('UPDATE mcp_connections SET paused_until=now()+interval \'1 hour\' WHERE id=$1',[connection]);await assert.rejects(()=>invoke('assistant_job_create',{...job,request_id:randomUUID()}),e=>e.code==='paused_until');
   await pool.query('UPDATE mcp_connections SET paused_until=NULL,enabled=false WHERE id=$1',[connection]);await assert.rejects(()=>invoke('assistant_job_create',{...job,request_id:randomUUID()}),e=>e.status===403);await pool.query('UPDATE mcp_connections SET enabled=true WHERE id=$1',[connection]);
   assert.equal((await pool.query('SELECT count(*)::int n FROM schedule_events')).rows[0].n,2);
  });
  await t.test('registry discovery does not acknowledge navigation; wrong subsection is rejected',async()=>{
   await grant('native_navigate');const device=randomUUID(),scene=randomUUID(),context={device_id:device,scene_id:scene,module:'dashboard',screen:'dashboard',timestamp:new Date().toISOString()};responses.push(tool('load_capabilities',{ids:['native_navigate']}),tool('native_navigate',{route:'settings',action:'discover_settings'}));const r=await start('Take me to those booking settings',context);assert.equal(r.status,'waiting_client',JSON.stringify(r));
   const command=(await http('assistant/commands?device_id='+device+'&scene_id='+scene)).data.items[0];assert.equal(command.command.action,'discover_settings');const registry=[{route:'settings',section:'customer_booking',page_id:'schedule.booking',label:'Customer Booking Rules',breadcrumb:'More › Settings › Team Availability › Customer Booking Rules'}];assert.equal((await http('assistant/commands/'+command.id+'/ack',{device_id:device,scene_id:scene,state:'completed',message:'Registry only; not opened',context:{...context,settings_destinations:registry}})).status,200);
   responses.push(tool('native_navigate',{route:'settings',section:'customer_booking'}));await engine.tick();const target=(await http('assistant/commands?device_id='+device+'&scene_id='+scene)).data.items[0];assert.equal((await http('assistant/commands/'+target.id+'/ack',{device_id:device,scene_id:scene,state:'completed',message:'Root only',context:{...context,module:'settings',screen:'settings'}})).status,409);assert.equal((await http('assistant/commands/'+target.id+'/ack',{device_id:device,scene_id:scene,state:'completed',message:'Correct screen appeared',context:{...context,module:'settings',screen:'settings.customer_booking',section:'customer_booking'}})).status,200);
   responses.push(done('Customer Booking Rules opened.'));await engine.tick();assert.equal((await http('assistant/runs/'+r.id)).data.status,'completed');responses.push(done('Use Team Availability then Customer Booking Rules.'));await start('How did I get there?');assert.match(JSON.stringify(requests.at(-1).input),/Prior conversational intent/);assert.doesNotMatch(JSON.stringify(requests.at(-1).input),/Confirmed synthetic job\./);
  });
 }finally{if(server)await new Promise(r=>server.close(r));if(backend)await backend.pool.end();pg.stop();}
});
