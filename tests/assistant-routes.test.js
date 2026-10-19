import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {installMCP} from '../mcp/index.js';
import {installAssistant} from '../assistant/index.js';
import {modelCatalog} from '../assistant/models.js';
import {digest} from '../mcp/context.js';

test('assistant constructs and recalculates routes with canonical metrics and durable receipts',{timeout:120000},async t=>{
 const pg=startLocalPostgres();pg.configureEnvironment();const realFetch=globalThis.fetch;let backend,server,providerCalls=0,duringRouting;
 process.env.GOOGLE_MAPS_PLATFORM_API_KEY='synthetic-routing-fixture';process.env.GOOGLE_ROUTE_OPTIMIZATION_ENABLED='false';process.env.GOOGLE_ROUTING_MAX_ATTEMPTS='1';
 globalThis.fetch=async(url,init)=>{
  if(String(url).startsWith('https://routes.googleapis.com/')){
   providerCalls++;const body=JSON.parse(init.body);
   if(duringRouting){const fn=duringRouting;duringRouting=null;await fn();}
   if(String(url).includes('computeRouteMatrix'))return {ok:true,status:200,json:async()=>body.origins.flatMap((_,originIndex)=>body.destinations.map((_,destinationIndex)=>({originIndex,destinationIndex,status:{},condition:'ROUTE_EXISTS',distanceMeters:1000,duration:'60s'})))};
   if(String(url).includes('computeRoutes'))return {ok:true,status:200,json:async()=>({routes:[{legs:Array.from({length:(body.intermediates||[]).length+1},()=>({distanceMeters:1000,duration:'60s'})),polyline:{encodedPolyline:'fixture'},warnings:[]}]})};
   throw new Error('Unexpected Google route endpoint');
  }
  return realFetch(url,init);
 };
 try{
  backend=await import('../index.js');await backend.bootstrap();const {app,pool,authRequired}=backend;
  const company=randomUUID(),owner=randomUUID(),foreignCompany=randomUUID(),foreign=randomUUID(),customer=randomUUID(),foreignContact=randomUUID();
  for(const [c,u]of[[company,owner],[foreignCompany,foreign]]){await pool.query('INSERT INTO companies(id,name,join_code,owner_user_id) VALUES($1,$2,$3,$4)',[c,'Routing fixture',c,u]);await pool.query("INSERT INTO users(id,email,company_id,role,password_hash) VALUES($1,$2,$3,'employer','test')",[u,u+'@example.invalid',c]);await pool.query('INSERT INTO sessions(token,user_id) VALUES($1,$2)',[u,u]);}
  for(const [id,c,u]of[[customer,company,owner],[foreignContact,foreignCompany,foreign]])await pool.query("INSERT INTO contacts(id,company_id,user_id,name,address,lat,lng) VALUES($1,$2,$3,'Synthetic route customer','100 Fixture Road',38.01,-85.01)",[id,c,u]);
  const env={MCP_ENABLED:'true',ASSISTANT_ENABLED:'true',ASSISTANT_OWNER_FUNDING:'true',MCP_PUBLIC_ORIGIN:'http://127.0.0.1',MCP_WEB_ORIGIN:'http://127.0.0.1',NODE_ENV:'test'};
  await installMCP({app,pool,authRequired,env,startMaintenance:false,verifyIdentity:async()=>null});
  const responses=[],tool=(name,args)=>({output:[{type:'function_call',call_id:randomUUID(),name,arguments:JSON.stringify(args)}],usage:{input_tokens:100,output_tokens:10}}),complete=()=>({output:[{type:'message',role:'assistant',content:[{type:'output_text',text:'Fixture result'}]}],usage:{input_tokens:100,output_tokens:10}});
  const engine=await installAssistant({app,pool,authRequired,env,startWorker:false,provider:{models:async()=>modelCatalog,respond:async()=>{const response=responses.shift();assert.ok(response,'Unexpected model request');return response;}}});
  server=await new Promise(r=>{const s=app.listen(0,'127.0.0.1',()=>r(s));});const origin='http://127.0.0.1:'+server.address().port;
  async function http(path,body,method=body?'POST':'GET'){const response=await realFetch(origin+'/api/'+path,{method,headers:{authorization:'Bearer '+owner,'content-type':'application/json'},...(body?{body:JSON.stringify(body)}:{})});return {status:response.status,data:await response.json()};}
  const setup=await http('assistant/setup',{}),connection=setup.data.settings.connection_id;
  const grant=async(name,approval=false)=>pool.query("UPDATE mcp_connections SET tool_policy=jsonb_set(tool_policy,ARRAY[$2],$3::jsonb),revision=revision+1 WHERE id=$1",[connection,name,JSON.stringify({allow:true,approval})]);await grant('assistant_execute');
  await http('assistant/settings',{expected_revision:1,funding:'owner',model:'gpt-6.1-sol',reasoning:'low',instructions:'',memory_enabled:false,monthly_limit_micros:100000000},'PUT');
  const build={request_id:randomUUID(),name:'Synthetic optimized route',status:'saved',start:{label:'Office',latitude:38,longitude:-85},ending_behavior:'finish_at_final_stop',end:null,departure_time:new Date(Date.now()+3600000).toISOString(),optimize_order:true,stops:[{id:randomUUID(),source_type:'contact',contact_id:customer,service_duration_seconds:300,locked_order:null},{id:randomUUID(),source_type:'custom',label:'Fixture custom stop',address:'200 Fixture Road',latitude:38.02,longitude:-85.02,service_duration_seconds:0,locked_order:null}]};
  async function enqueue(name,input,finish=true){const chat=(await http('assistant/conversations',{title:name})).data.id;responses.push(tool('load_capabilities',{ids:[name]}),tool(name,input));if(finish)responses.push(complete());const r=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:name});assert.equal(r.status,202,JSON.stringify(r));await engine.tick();return r.data.id;}
  async function result(id){return (await http('assistant/runs/'+id)).data;}
  let route;
  await t.test('disabled capability spends no routing provider request',async()=>{const run=await enqueue('assistant_route_build',build);assert.equal((await result(run)).status,'completed');assert.equal(providerCalls,0);assert.equal((await pool.query('SELECT count(*)::int n FROM crm_routes WHERE company_id=$1',[company])).rows[0].n,0);});
  await t.test('exact approved build uses canonical ordering/metrics and replay creates no duplicate',async()=>{
   await grant('assistant_route_build',true);const run=await enqueue('assistant_route_build',build,false);assert.equal((await result(run)).status,'waiting_approval');assert.equal(providerCalls,0);
   const approval=(await pool.query("SELECT * FROM mcp_approvals WHERE connection_id=$1 AND state='pending'",[connection])).rows[0];
   assert.equal((await http('ai-connections/approvals/'+approval.id,{expected_hash:'0'.repeat(64),decision:'approve'})).status,409);
   assert.equal((await http('ai-connections/approvals/'+approval.id,{expected_hash:approval.input_hash,decision:'approve'})).status,200);
   responses.push(complete());await engine.tick();assert.equal((await result(run)).status,'completed');
   const rows=(await http('routes')).data;assert.equal(rows.length,1);route=(await http('routes/'+rows[0].id)).data;assert.equal(route.routing_provider,'google');assert.equal(route.distance_meters,2000);assert.equal(route.travel_time_seconds,120);assert.equal(route.service_time_seconds,300);assert.equal(route.total_route_time_seconds,420);assert.equal(route.stops.find(s=>s.contact_id===customer).name,'Synthetic route customer');
   const calls=providerCalls;await grant('assistant_route_build');const replay=await enqueue('assistant_route_build',build);assert.equal((await result(replay)).status,'completed');assert.equal(providerCalls,calls);assert.equal((await http('routes')).data.length,1);
  });
  await t.test('recalculation rejects stale state/foreign contacts and preserves status with canonical metrics',async()=>{
   await grant('assistant_route_recalculate');await grant('assistant_route_build');
   let calls=providerCalls;
   await enqueue('assistant_route_recalculate',{request_id:randomUUID(),route_id:route.id,expected_source_hash:'0'.repeat(64),departure_time:build.departure_time,optimize_order:false});assert.equal(providerCalls,calls);
   await enqueue('assistant_route_build',{...build,request_id:randomUUID(),stops:[{...build.stops[0],contact_id:foreignContact}]});assert.equal(providerCalls,calls);
   await http('routes/'+route.id+'/stops/'+route.stops[0].id,{status:'completed'},'PATCH');route=(await http('routes/'+route.id)).data;
   const run=await enqueue('assistant_route_recalculate',{request_id:randomUUID(),route_id:route.id,expected_source_hash:digest(route),departure_time:build.departure_time,optimize_order:false});assert.equal((await result(run)).status,'completed');route=(await http('routes/'+route.id)).data;assert.equal(route.stops[0].status,'completed');assert.equal(route.routing_strategy,'fixed_order');assert.equal(route.distance_meters,2000);
  });
  await t.test('external route receipts honor output field restrictions and uncertain plans never retry',async()=>{
   await pool.query("UPDATE mcp_connections SET tool_policy=jsonb_set(tool_policy,'{assistant_route_recalculate,denied_output_fields}','[\"metrics.distance_meters\"]'),revision=revision+1 WHERE id=$1",[connection]);
   route=(await http('routes/'+route.id)).data;const run=await enqueue('assistant_route_recalculate',{request_id:randomUUID(),route_id:route.id,expected_source_hash:digest(route),departure_time:build.departure_time,optimize_order:false});
   const step=(await pool.query("SELECT result FROM wolf_assistant_steps WHERE run_id=$1 AND tool='assistant_route_recalculate'",[run])).rows[0];assert.equal(step.result.metrics.distance_meters,undefined);assert.equal(step.result.metrics.travel_time_seconds,120);
   const uncertain={...build,request_id:randomUUID(),departure_time:new Date(Date.now()+14400000).toISOString()};duringRouting=async()=>{throw new Error('Synthetic uncertain routing transport');};
   let failed=await enqueue('assistant_route_build',uncertain,false);assert.equal((await result(failed)).status,'interrupted');const calls=providerCalls;
   failed=await enqueue('assistant_route_build',uncertain,false);assert.equal((await result(failed)).status,'interrupted');assert.equal(providerCalls,calls);assert.equal((await http('routes')).data.length,1);
  });
  await t.test('uncached contact coordinates require a fresh exact native geocoding acknowledgement',async()=>{
   await grant('native_resolve_location');await grant('assistant_route_build');await pool.query('UPDATE contacts SET lat=NULL,lng=NULL,updated_at=now() WHERE id=$1',[customer]);
   const device=randomUUID(),scene=randomUUID(),chat=(await http('assistant/conversations',{title:'Native geocoding'})).data.id;
   responses.push(tool('load_capabilities',{ids:['native_resolve_location']}),tool('native_resolve_location',{route:'routes',action:'resolve_location',location_request:{kind:'contact',contact_id:customer}}));
   const queued=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Resolve this contact address',context:{device_id:device,scene_id:scene,module:'routes',screen:'routes.list',timestamp:new Date().toISOString()}});await engine.tick();assert.equal((await result(queued.data.id)).status,'waiting_client');
   const cmd=(await http('assistant/commands?device_id='+device+'&scene_id='+scene)).data.items[0];assert.ok(cmd.command.location_request.source_hash);
   assert.equal((await http('assistant/commands/'+cmd.id+'/ack',{device_id:device,scene_id:scene,state:'completed',message:'Resolved',location:{latitude:38.01,longitude:-85.01,label:'Synthetic contact'}})).status,200);responses.push(complete());await engine.tick();
   const before=(await http('routes')).data.length,stop={...build.stops[0],coordinate_command_id:cmd.id};await enqueue('assistant_route_build',{...build,request_id:randomUUID(),stops:[stop]});assert.equal((await http('routes')).data.length,before+1);
   await pool.query("UPDATE contacts SET address='Changed address',updated_at=now() WHERE id=$1",[customer]);const calls=providerCalls;await enqueue('assistant_route_build',{...build,request_id:randomUUID(),stops:[stop]});assert.equal(providerCalls,calls);
   await pool.query('UPDATE contacts SET lat=38.01,lng=-85.01,updated_at=now() WHERE id=$1',[customer]);
  });
  await t.test('record changes or permission revocation during routing cannot save stale routes',async()=>{
   let count=(await http('routes')).data.length;
   duringRouting=()=>pool.query("UPDATE contacts SET name='Changed during provider call',updated_at=now() WHERE id=$1",[customer]);
   const changed=await enqueue('assistant_route_build',{...build,request_id:randomUUID(),departure_time:new Date(Date.now()+7200000).toISOString()});assert.equal((await result(changed)).status,'completed');assert.equal((await http('routes')).data.length,count);
   const step=(await pool.query("SELECT result FROM wolf_assistant_steps WHERE run_id=$1 AND tool='assistant_route_build'",[changed])).rows[0];assert.equal(step.result.error,'route_contact_changed');
   duringRouting=()=>grant('assistant_route_build',false).then(()=>pool.query("UPDATE mcp_connections SET tool_policy=jsonb_set(tool_policy,'{assistant_route_build,allow}','false') WHERE id=$1",[connection]));
   // Revocation stops the run before another model request, so no final response is queued.
   const revoked=await enqueue('assistant_route_build',{...build,request_id:randomUUID(),departure_time:new Date(Date.now()+10800000).toISOString()},false);assert.equal((await result(revoked)).status,'failed');assert.equal((await http('routes')).data.length,count);
  });
 }finally{globalThis.fetch=realFetch;delete process.env.GOOGLE_MAPS_PLATFORM_API_KEY;if(server)await new Promise(r=>server.close(r));await backend?.pool.end();pg.stop();}
});
