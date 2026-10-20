import {enqueueTimeSchedules} from '../automation-time-schedule.js';
import {installAgreementBooking} from '../agreement-booking.js';
import {installAgreementSystem} from '../quote-agreements.js';
import {installGoogleSheetsSchema} from '../google-sheets.js';
import {createStorageService} from '../media-storage/service.js';
import {installStorageSchema} from '../media-storage/schema.js';
import {installCompanyComms} from '../company-comms/index.js';
import {installNotes} from '../notes/index.js';
import {installIdeaParking} from '../idea-parking.js';
import {installAutomationSystem,automationTestHooks} from '../automations.js';
import {PERMISSION_CAPABILITIES} from '../permissions.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {installMCP} from '../mcp/index.js';
import {installAssistant} from '../assistant/index.js';
import {modelCatalog} from '../assistant/models.js';
import {restrictFields} from '../mcp/field-policy.js';

test('assistant durable execution uses shared policy and real tenant boundaries',{timeout:180000},async t=>{
 const pg=startLocalPostgres();pg.configureEnvironment();let backend,server;
 try{
  backend=await import('../index.js');const {app,pool,authRequired}=backend;await backend.bootstrap();await installGoogleSheetsSchema(pool);await installStorageSchema(pool);await installCompanyComms({app,pool,authRequired,startWorker:false});app.locals.notes=await installNotes({app,pool,authRequired});await installIdeaParking({app,pool,authRequired});await installAutomationSystem({app,pool,authRequired,requireEmployer:(req,res,next)=>req.isCompanyOwner?next():res.sendStatus(403),disableProcessors:true});
  app.locals.agreements=await installAgreementSystem({app,pool,authRequired,requireCapability:backend.requireCapability,getQuoteSettings:backend.getQuoteSettings,env:{NODE_ENV:'test',QUOTE_LINK_SECRET:'assistant-fixture-only-non-production-secret',QUOTE_PUBLIC_BASE_URL:'http://127.0.0.1:3000'},startWorker:false});
  await installAgreementBooking({app,pool,service:app.locals.agreements,authRequired,requireCapability:backend.requireCapability,startWorker:false});
  const company=randomUUID(),otherCompany=randomUUID(),user=randomUUID(),other=randomUUID();
  for(const [c,u]of [[company,user],[otherCompany,other]]){await pool.query('INSERT INTO companies(id,name,join_code,owner_user_id) VALUES($1,$2,$3,$4)',[c,'Synthetic assistant company',c,u]);await pool.query("INSERT INTO users(id,email,display_name,company_id,role,password_hash) VALUES($1,$2,'Test owner',$3,'employer','not-a-password')",[u,u+'@example.invalid',c]);await pool.query('INSERT INTO sessions(token,user_id) VALUES($1,$2)',[u,u]);}
  const env={MCP_ENABLED:'true',ASSISTANT_ENABLED:'true',ASSISTANT_OWNER_FUNDING:'true',MCP_PUBLIC_ORIGIN:'http://127.0.0.1',MCP_WEB_ORIGIN:'http://127.0.0.1',NODE_ENV:'test'};
  await installMCP({app,pool,authRequired,env,startMaintenance:false,verifyIdentity:async()=>null});
  const fileBytes=new Map();app.locals.mediaStorage=createStorageService({pool,bucket:{readBytes:async row=>fileBytes.get(row.id),readText:async row=>fileBytes.get(row.id).toString('utf8')}});
  const responses=[];let calls=0,countCalls=0;const provider={models:async()=>modelCatalog,countInput:async(s,request)=>{countCalls++;assert.equal(s.user_id,user);assert.ok(request.input[0].content.some(c=>c.type==='input_file'||c.type==='input_image'));return 1200;},respond:async(s,request,opts)=>{calls++;assert.equal(s.user_id,user);const r=responses.shift();assert.ok(r,'Unexpected paid-provider attempt');await opts.onText?.('Synthetic response');return typeof r==='function'?r(request):r;}};
  let externalCalls=0,externalFails=false,externalAfter;const engine=await installAssistant({app,pool,authRequired,env,provider,startWorker:false,externalExecutor:async({input})=>{externalCalls++;if(externalFails)throw new Error('Synthetic ambiguous provider timeout');if(externalAfter){const callback=externalAfter;externalAfter=null;await callback();}return {id:randomUUID(),entity:'customer_messages',conversation_id:input.conversation_id,status:'submitted'};}});
  server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});const origin='http://127.0.0.1:'+server.address().port;
  async function http(path,body,method=body?'POST':'GET',actor=user){const response=await fetch(origin+'/api/'+path,{method,headers:{authorization:'Bearer '+actor,'content-type':'application/json'},...(body?{body:JSON.stringify(body)}:{})});return {status:response.status,data:await response.json()};}
  let id,chat;
  // Scenarios share one disposable identity. Keep the real per-operation limiter,
  // but do not let unrelated fast scenarios consume one another's minute budget.
  t.beforeEach(async()=>{await pool.query('DELETE FROM mcp_rate_limits');});
  await t.test('setup has no grants or reusable provider credential; deny before provider',async()=>{
   const setup=await http('assistant/setup',{});assert.equal(setup.status,201,JSON.stringify(setup.data));id=setup.data.settings.connection_id;
   const row=(await pool.query('SELECT * FROM mcp_connections WHERE id=$1',[id])).rows[0];assert.deepEqual(row.tool_policy,{});assert.equal(row.kind,'assistant');
   assert.equal((await pool.query('SELECT key_hash FROM retell_connections WHERE id=$1',[id])).rows[0].key_hash,null);
   const config=await http('assistant/settings',{expected_revision:1,funding:'owner',model:'gpt-6.1-sol',reasoning:'low',instructions:'Be concise.',memory_enabled:true,monthly_limit_micros:5000000},'PUT');assert.equal(config.status,200,JSON.stringify(config));
   chat=(await http('assistant/conversations',{title:'Controlled test'})).data.id;
   assert.equal((await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Test'})).status,403);assert.equal(calls,0);
  });
  const grant=async(tool,approval=false)=>pool.query("UPDATE mcp_connections SET tool_policy=jsonb_set(tool_policy,ARRAY[$2],$3::jsonb),revision=revision+1 WHERE id=$1",[id,tool,JSON.stringify({allow:true,approval})]);
  const complete=body=>({output:[{type:'message',role:'assistant',content:[{type:'output_text',text:body}]}],usage:{input_tokens:100,output_tokens:20}});
  const tool=(name,args,call=randomUUID())=>({output:[{type:'function_call',call_id:call,name,arguments:JSON.stringify(args)}],usage:{input_tokens:100,output_tokens:20}});
  await grant('assistant_execute');
  await t.test('persistent conversation, streamed events, exact request replay and isolation',async()=>{
   responses.push(complete('Ready.'));const input={conversation_id:chat,request_key:randomUUID(),text:'Hello'};const first=await http('assistant/runs',input);assert.equal(first.status,202,JSON.stringify(first));await engine.tick();
   const result=await http('assistant/runs/'+first.data.id);assert.equal(result.data.status,'completed',JSON.stringify(result));assert.ok(result.data.events.some(e=>e.kind==='text_delta'));assert.equal(result.data.output,'Ready.');assert.ok(result.data.cost_micros>0);
   assert.equal((await http('assistant/runs',input)).data.id,first.data.id);assert.equal((await http('assistant/runs',{...input,text:'different'})).status,409);
   assert.equal((await http('assistant/runs/'+first.data.id,undefined,'GET',other)).status,404);assert.equal((await http('assistant/conversations/'+chat,undefined,'GET',other)).status,404);
  });
  await t.test('owner-funded Luna selection persists and bills its own model rate',async()=>{
   const before=(await pool.query('SELECT revision,funding,monthly_limit_micros FROM wolf_assistant_settings WHERE user_id=$1',[user])).rows[0];
   const selected=await http('assistant/settings',{expected_revision:before.revision,funding:before.funding,model:'gpt-6-luna',reasoning:'low',instructions:'Be concise.',memory_enabled:true,monthly_limit_micros:Number(before.monthly_limit_micros)},'PUT');
   assert.equal(selected.status,200,JSON.stringify(selected));
   assert.equal(selected.data.model,'gpt-6-luna');assert.equal(selected.data.reasoning,'low');
   responses.push(request=>{assert.equal(request.model,'gpt-6-luna');assert.equal(request.reasoning.effort,'low');return complete('Luna ready.');});
   const queued=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Hello Luna'});assert.equal(queued.status,202,JSON.stringify(queued));await engine.tick();
   const run=(await http('assistant/runs/'+queued.data.id)).data;assert.equal(run.status,'completed',JSON.stringify(run));assert.equal(run.output,'Luna ready.');assert.equal((await pool.query('SELECT model,reasoning FROM wolf_assistant_runs WHERE id=$1',[run.id])).rows[0].model,'gpt-6-luna');assert.equal(Number(run.cost_micros),20);
   const restored=await http('assistant/settings',{expected_revision:selected.data.revision,funding:before.funding,model:'gpt-6.1-sol',reasoning:'low',instructions:'Be concise.',memory_enabled:true,monthly_limit_micros:Number(before.monthly_limit_micros)},'PUT');assert.equal(restored.status,200,JSON.stringify(restored));
  });
  await t.test('discovery and selected loading do not bypass a disabled operation',async()=>{
   responses.push(tool('load_capabilities',{ids:['contact_create']}),tool('contact_create',{request_id:randomUUID(),contact:{name:'Must not exist'}}),complete('Denied.'));
   const r=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Create denied contact'});await engine.tick();assert.equal((await http('assistant/runs/'+r.data.id)).data.status,'completed');assert.equal((await pool.query('SELECT count(*)::int n FROM contacts WHERE company_id=$1',[company])).rows[0].n,0);
   const steps=(await pool.query('SELECT result FROM wolf_assistant_steps WHERE run_id=$1 AND tool=\'contact_create\'',[r.data.id])).rows;assert.equal(steps[0].result.error,'tool_denied');
  });
  await t.test('exact approval resumes same durable task and creates one canonical record',async()=>{
   await grant('contact_create',true);responses.push(tool('load_capabilities',{ids:['contact_create']}),tool('contact_create',{request_id:randomUUID(),contact:{name:'Approved synthetic contact'}}));
   const r=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Create approved contact'});await engine.tick();assert.equal((await http('assistant/runs/'+r.data.id)).data.status,'waiting_approval');
   const p=(await pool.query('SELECT * FROM mcp_approvals WHERE connection_id=$1 AND state=\'pending\'',[id])).rows[0];assert.equal((await http('ai-connections/approvals/'+p.id,{expected_hash:'0'.repeat(64),decision:'approve'})).status,409);
   assert.equal((await http('ai-connections/approvals/'+p.id,{expected_hash:p.input_hash,decision:'approve'},'POST',other)).status,404);
   const approved=await http('ai-connections/approvals/'+p.id,{expected_hash:p.input_hash,decision:'approve'});assert.equal(approved.status,200,JSON.stringify(approved));responses.push(complete('Saved.'));await engine.tick();assert.equal((await http('assistant/runs/'+r.data.id)).data.status,'completed');
   assert.equal((await pool.query('SELECT count(*)::int n FROM contacts WHERE company_id=$1',[company])).rows[0].n,1);
  });
  await t.test('cancel rejects pending proposal and never performs later operations',async()=>{
   responses.push(tool('load_capabilities',{ids:['contact_create']}),tool('contact_create',{request_id:randomUUID(),contact:{name:'Cancelled'}}));const r=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Then cancel'});await engine.tick();
   const p=(await pool.query('SELECT * FROM mcp_approvals WHERE connection_id=$1 AND state=\'pending\'',[id])).rows[0];await http('assistant/runs/'+r.data.id+'/cancel',{});assert.equal((await http('ai-connections/approvals/'+p.id,{expected_hash:p.input_hash,decision:'approve'})).status,409);await engine.tick();assert.equal((await http('assistant/runs/'+r.data.id)).data.status,'cancelled');
  });
  await t.test('unique catalog IDs and real permission identifiers',()=>{
   const catalog=app.locals.capabilityService.catalog;assert.equal(new Set(catalog.map(x=>x.id)).size,catalog.length);const known=new Set(PERMISSION_CAPABILITIES.map(x=>x.key));for(const c of catalog)for(const cap of c.caps)assert.ok(known.has(cap),c.id+': '+cap);
  });
  await t.test('concurrent request retry queues exactly one task',async()=>{
   const input={conversation_id:chat,request_key:randomUUID(),text:'Concurrent retry'};const both=await Promise.all([http('assistant/runs',input),http('assistant/runs',input)]);assert.equal(both[0].status,202,JSON.stringify(both));assert.equal(both[1].status,202,JSON.stringify(both));assert.equal(both[0].data.id,both[1].data.id);responses.push(complete('One response'));await engine.tick();
  });
  await t.test('budget fails before a provider request',async()=>{
   const before=calls;const r=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Too expensive',max_cost_micros:1});await engine.tick();const result=(await http('assistant/runs/'+r.data.id)).data;assert.equal(result.status,'failed');assert.equal(result.error_code,'assistant_budget_exceeded');assert.equal(calls,before);
  });
  await t.test('permission revocation mid task stops subsequent writes',async()=>{
   responses.push(async()=>{await pool.query('UPDATE mcp_connections SET enabled=false WHERE id=$1',[id]);return complete('Must not be surfaced');});const r=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Revoke now'});await engine.tick();assert.equal((await http('assistant/runs/'+r.data.id)).data.status,'failed');await pool.query('UPDATE mcp_connections SET enabled=true WHERE id=$1',[id]);
  });
  await t.test('native navigation requires the originating scene acknowledgement',async()=>{
   await grant('native_navigate');const scene=randomUUID(),device=randomUUID();responses.push(tool('load_capabilities',{ids:['native_navigate']}),tool('native_navigate',{route:'schedule',date:'2026-10-20'}));const r=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Open Tuesday',context:{device_id:device,scene_id:scene,module:'dashboard',screen:'dashboard',timestamp:new Date().toISOString()}});await engine.tick();assert.equal((await http('assistant/runs/'+r.data.id)).data.status,'waiting_client');
   const commands=(await http('assistant/commands?device_id='+device+'&scene_id='+scene)).data.items;assert.equal(commands.length,1);assert.equal((await http('assistant/commands/'+commands[0].id+'/ack',{device_id:randomUUID(),scene_id:scene,state:'completed',message:'Wrong device'})).status,409);
   assert.equal((await http('assistant/commands/'+commands[0].id+'/ack',{device_id:device,scene_id:scene,state:'completed',message:'Schedule appeared'})).status,200);responses.push(complete('Opened Tuesday.'));await engine.tick();assert.equal((await http('assistant/runs/'+r.data.id)).data.status,'completed');
  });
  await t.test('queued native commands recheck revocation before delivery and acknowledgement',async()=>{
   for(const boundary of ['delivery','ack']){
    await grant('native_navigate');const scene=randomUUID(),device=randomUUID();
    responses.push(tool('load_capabilities',{ids:['native_navigate']}),tool('native_navigate',{route:'settings'}));
    const r=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Open guarded settings',context:{device_id:device,scene_id:scene,module:'dashboard',screen:'dashboard',timestamp:new Date().toISOString()}});await engine.tick();
    const command=(await http('assistant/commands?device_id='+device+'&scene_id='+scene)).data.items[0];assert.ok(command);
    await pool.query('UPDATE mcp_connections SET enabled=false WHERE id=$1',[id]);
    if(boundary==='delivery')assert.deepEqual((await http('assistant/commands?device_id='+device+'&scene_id='+scene)).data.items,[]);
    else assert.equal((await http('assistant/commands/'+command.id+'/ack',{device_id:device,scene_id:scene,state:'completed',message:'Must reject revoked acknowledgement'})).status,403);
    await http('assistant/runs/'+r.data.id+'/cancel',{});await pool.query('UPDATE mcp_connections SET enabled=true WHERE id=$1',[id]);
    assert.notEqual((await pool.query('SELECT state FROM wolf_assistant_commands WHERE id=$1',[command.id])).rows[0].state,'completed');
   }
  });
  await t.test('semantic context policy and typed acknowledgement reject mismatched destinations',async()=>{
   await grant('native_navigate');await grant('native_refresh_context');const scene=randomUUID(),device=randomUUID();
   await pool.query("UPDATE mcp_connections SET tool_policy=jsonb_set(tool_policy,'{native_refresh_context,denied_output_fields}','[\"context.filters.search\"]'),revision=revision+1 WHERE id=$1",[id]);
   const context={device_id:device,scene_id:scene,module:'contacts',screen:'contacts.list',timestamp:new Date().toISOString(),labels:{name:'Name'},fields:['name'],filters:{search:'Private search'},provenance:{name:'Canonical contacts'},scroll_anchor:'row-one'};
   responses.push(tool('load_capabilities',{ids:['native_navigate']}),tool('native_navigate',{route:'schedule',date:'2026-10-22'}));const r=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Open Thursday',context});await engine.tick();assert.equal((await http('assistant/runs/'+r.data.id)).data.status,'waiting_client');
   const history=(await pool.query('SELECT history FROM wolf_assistant_runs WHERE id=$1',[r.data.id])).rows[0].history;assert.ok(!JSON.stringify(history).includes('Private search'));
   const cmd=(await http('assistant/commands?device_id='+device+'&scene_id='+scene)).data.items[0];const payload={device_id:device,scene_id:scene,state:'completed',message:'Opened',context};assert.equal((await http('assistant/commands/'+cmd.id+'/ack',payload)).status,409);
   payload.context={...context,module:'schedule',screen:'schedule.calendar',selected_date:'2026-10-22'};assert.equal((await http('assistant/commands/'+cmd.id+'/ack',payload)).status,200);responses.push(complete('Opened verified Thursday.'));await engine.tick();assert.equal((await http('assistant/runs/'+r.data.id)).data.status,'completed');
  });
  await t.test('approved navigation still waits for the exact client acknowledgement',async()=>{
   await grant('native_navigate',true);const scene=randomUUID(),device=randomUUID();
   responses.push(tool('load_capabilities',{ids:['native_navigate']}),tool('native_navigate',{route:'schedule',date:'2026-10-21'}));
   const r=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Open Wednesday with approval',context:{device_id:device,scene_id:scene,module:'dashboard',screen:'dashboard',timestamp:new Date().toISOString()}});
   await engine.tick();assert.equal((await http('assistant/runs/'+r.data.id)).data.status,'waiting_approval');
   const approval=(await pool.query("SELECT * FROM mcp_approvals WHERE connection_id=$1 AND state='pending' ORDER BY created_at DESC LIMIT 1",[id])).rows[0];
   const decision=await http('ai-connections/approvals/'+approval.id,{decision:'approve',expected_hash:approval.input_hash});assert.equal(decision.status,200,JSON.stringify(decision));
   const before=calls;await engine.tick();assert.equal((await http('assistant/runs/'+r.data.id)).data.status,'waiting_client');assert.equal(calls,before);
   const command=(await http('assistant/commands?device_id='+device+'&scene_id='+scene)).data.items[0];assert.ok(command);
   await http('assistant/commands/'+command.id+'/ack',{device_id:device,scene_id:scene,state:'completed',message:'Wednesday appeared'});
   responses.push(complete('Opened after approval and acknowledgement.'));await engine.tick();assert.equal((await http('assistant/runs/'+r.data.id)).data.status,'completed');
  });
  await t.test('private PDF/image/Office extraction stages approval, preserves bytes privately and accounts usage',async()=>{
   await grant('assistant_file_extract',true);const file=randomUUID();fileBytes.set(file,Buffer.from('%PDF-1.4 synthetic extraction fixture'));
   await pool.query("INSERT INTO stored_files(id,owner_user_id,uploaded_by_user_id,company_id,display_name,original_filename,object_key,mime_type,category,byte_size,cloud_status) VALUES($1::uuid,$2,$2,$3,'Synthetic PDF','fixture.pdf',($1::uuid)::text,'application/pdf','document',$4,'active')",[file,user,company,fileBytes.get(file).length]);
   const args={id:file,expected_version:1,question:'Extract the fixture title.'},before=countCalls;
   responses.push(tool('load_capabilities',{ids:['assistant_file_extract']}),tool('assistant_file_extract',args));const run=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Read the private PDF'});await engine.tick();assert.equal((await http('assistant/runs/'+run.data.id)).data.status,'waiting_approval');assert.equal(countCalls,before);
   const approval=(await pool.query("SELECT * FROM mcp_approvals WHERE connection_id=$1 AND state='pending' AND operation='assistant_file_extract'",[id])).rows[0];assert.equal((await http('ai-connections/approvals/'+approval.id,{expected_hash:approval.input_hash,decision:'approve'})).status,200);
   responses.push(async request=>{assert.equal(request.model,'gpt-6.1-sol');assert.equal(request.input[0].content[1].type,'input_file');assert.equal(request.input[0].content[1].file_data,'data:application/pdf;base64,'+fileBytes.get(file).toString('base64'));assert.equal(request.tools,undefined);return complete('Synthetic PDF title; page 1.');},complete('Read the authorized fixture.'));await engine.tick();
   const final=(await http('assistant/runs/'+run.data.id)).data;assert.equal(final.status,'completed',JSON.stringify(final));assert.equal(countCalls,before+1);assert.ok(final.usage.input_tokens>=200);
   const retained=(await pool.query('SELECT history FROM wolf_assistant_runs WHERE id=$1',[run.data.id])).rows[0];assert.ok(!JSON.stringify(retained).includes('data:application/pdf;base64,'));
   await assert.rejects(app.locals.mediaStorage.readContent({userId:other,companyId:otherCompany},file),e=>e.status===404);
   await grant('assistant_file_extract');
   for(const [mime,name,kind,part] of [['image/png','fixture.png','image','input_image'],['application/vnd.openxmlformats-officedocument.wordprocessingml.document','fixture.docx','document','input_file']]){
    const f=randomUUID();fileBytes.set(f,Buffer.from('synthetic '+name));await pool.query("INSERT INTO stored_files(id,owner_user_id,uploaded_by_user_id,company_id,display_name,original_filename,object_key,mime_type,category,byte_size,cloud_status) VALUES($1::uuid,$2,$2,$3,$4,$4,($1::uuid)::text,$5,$6,$7,'active')",[f,user,company,name,mime,kind,fileBytes.get(f).length]);
    responses.push(tool('load_capabilities',{ids:['assistant_file_extract']}),tool('assistant_file_extract',{id:f,expected_version:1,question:'Read this fixture.'}),async request=>{assert.equal(request.input[0].content[1].type,part);return complete('Synthetic extracted content');},complete('Done'));const queued=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Read '+name});await engine.tick();assert.equal((await http('assistant/runs/'+queued.data.id)).data.status,'completed');
   }
  });
  await t.test('file revocation during inference accounts completed usage and never reuses revoked content',async()=>{
   await grant('assistant_file_extract');const file=randomUUID();fileBytes.set(file,Buffer.from('synthetic png'));await pool.query("INSERT INTO stored_files(id,owner_user_id,uploaded_by_user_id,company_id,display_name,original_filename,object_key,mime_type,category,byte_size,cloud_status) VALUES($1::uuid,$2,$2,$3,'Revoked PNG','revoked.png',($1::uuid)::text,'image/png','image',13,'active')",[file,user,company]);
   const before=calls;responses.push(tool('load_capabilities',{ids:['assistant_file_extract']}),tool('assistant_file_extract',{id:file,expected_version:1,question:'Read'}),async()=>{await pool.query("UPDATE stored_files SET cloud_status='deleted' WHERE id=$1",[file]);return complete('Must not return revoked file content');});
   const queued=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Revoke during file extraction'});await engine.tick();const result=(await http('assistant/runs/'+queued.data.id)).data;assert.equal(result.status,'failed');assert.equal(calls,before+3);assert.equal(result.reserved_micros,0);assert.ok(result.cost_micros>0);assert.ok(!result.events.some(e=>JSON.stringify(e).includes('Must not return revoked')));
  });
  await t.test('canonical Notes and Ideas preserve private boundaries',async()=>{
   const c=(await pool.query('SELECT * FROM mcp_connections WHERE id=$1',[id])).rows[0];const actor=await app.locals.connectionManager.actorFor(c);
   for(const name of ['notes_search_filtered','note_create','notes_page','notes_edit_blocks','ideas_save','ideas_search'])await grant(name);
   const created=await app.locals.connectionManager.invoke(actor,'note_create',{request_id:randomUUID(),title:'Egg recipe',text:'Egg recipe checklist',visibility:'private'},randomUUID());
   const search=await app.locals.connectionManager.invoke(actor,'notes_search_filtered',{search:'Egg recipe'},randomUUID());assert.equal(search.data.pages.length,1,JSON.stringify(search));
   const page=await app.locals.connectionManager.invoke(actor,'notes_page',{id:created.id},randomUUID());assert.ok(page.data.blocks.some(b=>b.payload.text==='Egg recipe checklist'));
   assert.equal((await http('notes/pages/'+created.id,undefined,'GET',other)).status,404);
   await app.locals.connectionManager.invoke(actor,'ideas_save',{id:randomUUID(),title:'Improve the follow-up checklist',list_id:null,request_id:randomUUID()},randomUUID());const ideas=await app.locals.connectionManager.invoke(actor,'ideas_search',{query:'follow-up'},randomUUID());assert.equal(ideas.data.items.length,1);
  });
  await t.test('confirmed Note edit retires its own stale page read and allows a fresh read',async()=>{
   const connection=(await pool.query('SELECT * FROM mcp_connections WHERE id=$1',[id])).rows[0],actor=await app.locals.connectionManager.actorFor(connection);
   for(const name of ['note_create','notes_page','notes_edit_blocks'])await grant(name);
   const note=await app.locals.connectionManager.invoke(actor,'note_create',{request_id:randomUUID(),title:'Self-edit evidence fixture',text:'Before edit',visibility:'private'},randomUUID());
   const before=(await app.locals.connectionManager.invoke(actor,'notes_page',{id:note.id},randomUUID())).data;
   const block=before.blocks.find(b=>b.payload.text==='Before edit');assert.ok(block);
   responses.push(tool('load_capabilities',{ids:['notes_page','notes_edit_blocks']}),tool('notes_page',{id:note.id}),tool('notes_edit_blocks',{request_id:randomUUID(),id:note.id,operations:[{id:block.id,expected_revision:block.revision,type:block.type,payload:{text:'After edit'},position:block.position}]}),tool('notes_page',{id:note.id}),complete('Verified fresh Note.'));
   const started=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Edit then verify the synthetic Note'});await engine.tick();
   const result=(await http('assistant/runs/'+started.data.id)).data;assert.equal(result.status,'completed',JSON.stringify(result));
   const pageSteps=(await pool.query("SELECT result FROM wolf_assistant_steps WHERE run_id=$1 AND tool='notes_page' ORDER BY started_at",[started.data.id])).rows;
   assert.equal(pageSteps.length,2);assert.ok(pageSteps[1].result.data.blocks.some(b=>b.payload.text==='After edit'));
   const history=(await pool.query('SELECT history FROM wolf_assistant_runs WHERE id=$1',[started.data.id])).rows[0].history;
   assert.ok(history.some(x=>x.type==='function_call_output'&&JSON.parse(x.output).evidence_retired===true));
   assert.ok(result.events.some(e=>e.kind==='evidence_retired'&&e.data.write_capability==='notes_edit_blocks'));
  });
  await t.test('Note sharing and revision restore preserve current audience and private boundaries',async()=>{
   const actor=await app.locals.connectionManager.actorFor((await pool.query('SELECT * FROM mcp_connections WHERE id=$1',[id])).rows[0]);
   const invoke=(name,input)=>app.locals.connectionManager.invoke(actor,name,input,randomUUID());
   for(const name of ['note_create','notes_page','notes_metadata','notes_share','notes_version','notes_restore_version'])await grant(name);
   const peer=randomUUID();await pool.query("INSERT INTO users(id,email,display_name,company_id,role,password_hash) VALUES($1,$2,'Note viewer',$3,'employee','not-a-password')",[peer,peer+'@example.invalid',company]);
   await pool.query("INSERT INTO employee_permissions(user_id,company_id,permission_overrides) VALUES($1,$2,'{\"notes.view\":true}')",[peer,company]);await pool.query('INSERT INTO sessions(token,user_id) VALUES($1,$2)',[peer,peer]);
   const created=await invoke('note_create',{request_id:randomUUID(),title:'Original private note',text:'Original content',visibility:'private'});
   let page=(await invoke('notes_page',{id:created.id})).data;
   assert.equal((await http('notes/pages/'+created.id,undefined,'GET',peer)).status,404);
   await assert.rejects(invoke('notes_share',{request_id:randomUUID(),id:created.id,expected_revision:page.page.revision,members:[{user_id:other,role:'viewer'}]}),e=>[403,404].includes(e.status));
   const original=page.page.revision;
   page=(await invoke('notes_metadata',{request_id:randomUUID(),id:created.id,expected_revision:original,title:'Renamed note'})).data;
   page=(await invoke('notes_share',{request_id:randomUUID(),id:created.id,expected_revision:page.page.revision,members:[{user_id:peer,role:'viewer'}]})).data;
   assert.equal((await http('notes/pages/'+created.id,undefined,'GET',peer)).status,200);
   assert.equal((await invoke('notes_version',{id:created.id,revision:original})).data.page.title,'Original private note');
   const restored=(await invoke('notes_restore_version',{request_id:randomUUID(),id:created.id,revision:original,expected_revision:page.page.revision})).data;
   assert.equal(restored.page.title,'Original private note');assert.equal(restored.page.visibility,'shared');
   await assert.rejects(invoke('notes_restore_version',{request_id:randomUUID(),id:created.id,revision:original,expected_revision:page.page.revision}),e=>e.status===409);
   assert.equal((await http('notes/pages/'+created.id,undefined,'GET',peer)).status,200);
   await invoke('notes_share',{request_id:randomUUID(),id:created.id,expected_revision:restored.page.revision,members:[]});
   assert.equal((await http('notes/pages/'+created.id,undefined,'GET',peer)).status,404);
  });
  await t.test('Notes database schemas and row edits enforce types, revisions and reference access',async()=>{
   const actor=await app.locals.connectionManager.actorFor((await pool.query('SELECT * FROM mcp_connections WHERE id=$1',[id])).rows[0]);
   const invoke=(name,input)=>app.locals.connectionManager.invoke(actor,name,input,randomUUID());
   for(const name of ['notes_create_page','notes_database_schema','notes_database_configure','notes_database_row_create','notes_database_row_update','notes_database_row','notes_database_rows'])await grant(name);
   const created=(await invoke('notes_create_page',{request_id:randomUUID(),title:'Fixture stock database',kind:'database',parent_id:null,visibility:'private',inherit_access:false,tags:[]})).data;
   const db=created.page.id;
   const columns=[{id:'title',name:'Item',type:'title',options:[]},{id:'count',name:'Count',type:'number',options:[]},{id:'related',name:'Related Note',type:'relation',options:[]}];
   const schema=(await invoke('notes_database_configure',{request_id:randomUUID(),id:db,expected_revision:0,columns,views:[{id:'all',name:'All',type:'table',direction:'asc',filter_value:'',visible_fields:['title','count']}]})).data;
   const row=(await invoke('notes_database_row_create',{request_id:randomUUID(),id:db,schema_revision:schema.revision,values:{title:'Synthetic ladders',count:3}})).data;
   const changed=(await invoke('notes_database_row_update',{request_id:randomUUID(),id:db,row_id:row.id,schema_revision:schema.revision,expected_revision:row.revision,values:{count:4}})).data;
   assert.equal(changed.values.title,'Synthetic ladders');assert.equal(changed.values.count,4);
   await assert.rejects(invoke('notes_database_row_update',{request_id:randomUUID(),id:db,row_id:row.id,schema_revision:schema.revision,expected_revision:row.revision,values:{count:99}}),e=>e.code==='database_row_conflict');
   await assert.rejects(invoke('notes_database_row_update',{request_id:randomUUID(),id:db,row_id:row.id,schema_revision:schema.revision,expected_revision:changed.revision,values:{missing:'ignored?'}}),e=>e.code==='unknown_database_property');
   await assert.rejects(invoke('notes_database_row_update',{request_id:randomUUID(),id:db,row_id:row.id,schema_revision:schema.revision,expected_revision:changed.revision,values:{count:'not a number'}}),e=>e.code==='invalid_number');
   const foreign=await http('notes/pages',{title:'Other company private Note'},'POST',other);assert.equal(foreign.status,200);
   await assert.rejects(invoke('notes_database_row_update',{request_id:randomUUID(),id:db,row_id:row.id,schema_revision:schema.revision,expected_revision:changed.revision,values:{related:foreign.data.page.id}}),e=>[403,404].includes(e.status));
   const found=(await invoke('notes_database_rows',{id:db,search:'ladders'})).data;assert.equal(found.rows[0].values.count,4);
   assert.equal((await http('notes/pages/'+db+'/rows',undefined,'GET',other)).status,404);
  });
  await t.test('Note checklist conversion and purge use canonical task and retention workflows',async()=>{
   const actor=await app.locals.connectionManager.actorFor((await pool.query('SELECT * FROM mcp_connections WHERE id=$1',[id])).rows[0]);
   const invoke=(name,input)=>app.locals.connectionManager.invoke(actor,name,input,randomUUID());
   for(const name of ['note_create','notes_page','notes_edit_blocks','notes_checklist_to_task','notes_metadata','notes_purge'])await grant(name);
   const note=await invoke('note_create',{request_id:randomUUID(),title:'Fixture checklist',text:'Inspect stock',visibility:'private'});
   let page=(await invoke('notes_page',{id:note.id})).data;const block=page.blocks[0];
   await invoke('notes_edit_blocks',{request_id:randomUUID(),id:note.id,operations:[{id:block.id,expected_revision:block.revision,type:'checklist',payload:{text:'Inspect stock'},position:0}]});
   page=(await invoke('notes_page',{id:note.id})).data;
   const args={request_id:randomUUID(),id:note.id,block_id:block.id,expected_revision:page.blocks[0].revision,title:'Inspect stock',detail:'Fixture task',assignee_ids:[user],due_date:null,priority:'normal'};
   const task=(await invoke('notes_checklist_to_task',args)).data;await invoke('notes_checklist_to_task',args);
   assert.equal((await pool.query('SELECT count(*)::int n FROM todo_tasks WHERE id=$1',[task.task_id])).rows[0].n,1);
   page=(await invoke('notes_page',{id:note.id})).data;assert.equal(page.blocks[0].type,'task');
   await assert.rejects(invoke('notes_purge',{request_id:randomUUID(),id:note.id,expected_revision:page.page.revision}),e=>e.code==='trash_confirmation_required');
   const trashed=(await invoke('notes_metadata',{request_id:randomUUID(),id:note.id,expected_revision:page.page.revision,trashed:true})).data;
   await invoke('notes_purge',{request_id:randomUUID(),id:note.id,expected_revision:trashed.page.revision});
   assert.equal((await http('notes/pages/'+note.id)).status,404);
   assert.equal((await pool.query('SELECT count(*)::int n FROM notes_versions WHERE page_id=$1',[note.id])).rows[0].n,0);
   assert.equal((await pool.query('SELECT count(*)::int n FROM todo_tasks WHERE id=$1',[task.task_id])).rows[0].n,1,'purging source leaves the task intact');
  });
  await t.test('equipment stock, repair and count tools use canonical accounting with exact state guards',async()=>{
   const actor=await app.locals.connectionManager.actorFor((await pool.query('SELECT * FROM mcp_connections WHERE id=$1',[id])).rows[0]);
   const invoke=(name,input)=>app.locals.connectionManager.invoke(actor,name,input,randomUUID());
   for(const tool of app.locals.capabilityService.catalog.filter(x=>x.id.startsWith('equipment_')))await grant(tool.id);
   const location=(await invoke('equipment_locations',{})).data[0].id,itemID=randomUUID();
   const values={name:'Synthetic soap',item_type:'material',tracking_mode:'quantity',category:null,unit:'litre',reorder_point:2,cost_per_unit_cents:500,status:'available',location_id:location,assigned_user_id:null,notes:null};
   const created=(await invoke('equipment_item_create',{request_id:itemID,...values})).data;assert.equal(created.quantity_on_hand,0);
   let item=await invoke('equipment_item',{id:itemID});
   await assert.rejects(invoke('equipment_item_update',{request_id:randomUUID(),id:itemID,expected_source_hash:item.source_hash,...values,assigned_user_id:other}),e=>e.code==='equipment_reference_unavailable');
   const receipt={request_id:randomUUID(),item_id:itemID,transaction_type:'received',quantity:10};
   await invoke('equipment_transaction',receipt);await invoke('equipment_transaction',receipt);
   assert.equal((await invoke('equipment_item',{id:itemID})).data.quantity_on_hand,10);
   const editable=await invoke('equipment_item',{id:itemID});
   await pool.query("UPDATE mcp_connections SET tool_policy=jsonb_set(tool_policy,'{equipment_item_update}', $2::jsonb),revision=revision+1 WHERE id=$1",[id,JSON.stringify({allow:true,approval:false,denied_input_fields:['cost_per_unit_cents']})]);
   const renamed=(await invoke('equipment_item_update',{request_id:randomUUID(),id:itemID,expected_source_hash:editable.source_hash,name:'Synthetic soap renamed'})).data;
   assert.equal(renamed.cost_per_unit_cents,500);assert.equal(renamed.quantity_on_hand,10);
   await assert.rejects(invoke('equipment_item_update',{request_id:randomUUID(),id:itemID,expected_source_hash:editable.source_hash,cost_per_unit_cents:1}),e=>e.code==='field_denied');
   await grant('equipment_item_update');
   await assert.rejects(invoke('equipment_item_update',{request_id:randomUUID(),id:itemID,expected_source_hash:item.source_hash,...values,name:'stale'}),e=>e.code==='stale_equipment_record');
   await assert.rejects(invoke('equipment_transaction',{request_id:randomUUID(),item_id:itemID,transaction_type:'disposed',quantity:11}),e=>e.code==='insufficient_inventory');
   const request=(await invoke('equipment_request_create',{request_id:randomUUID(),request_type:'report_broken',item_id:itemID,item_name:null,quantity:null,urgency:'normal',explanation:'Synthetic inspection'})).data;
   const repair=(await invoke('equipment_repair_create',{request_id:randomUUID(),item_id:itemID,equipment_request_id:request.id,assigned_user_id:null,vendor:null,problem:'Synthetic inspection',diagnosis:null,status:'reported',priority:'normal',estimated_cost_cents:null,actual_cost_cents:null,scheduled_at:null,resolution_notes:null})).data;
   assert.equal(repair.request_id,request.id);
   assert.equal((await invoke('equipment_item',{id:itemID})).data.status,'under_repair');
   const before=await invoke('equipment_repair',{id:repair.id});
   await invoke('equipment_repair_update',{request_id:randomUUID(),id:repair.id,expected_source_hash:before.source_hash,status:'completed',resolution_notes:'Fixture complete'});
   assert.equal((await invoke('equipment_item',{id:itemID})).data.status,'available');
   const schedule=(await invoke('equipment_count_schedule_create',{request_id:randomUUID(),name:'Fixture count',location_id:location,assigned_user_id:user,frequency:'weekly',due_date:'2026-10-20',due_time:'09:00',reminder_minutes:null,variance_threshold:0,approval_required:true,enabled:true})).data;
   const s=await invoke('equipment_count_schedule',{id:schedule.id});
   const count=(await invoke('equipment_count_generate',{request_id:randomUUID(),id:schedule.id,expected_source_hash:s.source_hash,due_date:'2026-10-20'})).data;
   const old=await invoke('equipment_count_submission',{id:count.id});
   await invoke('equipment_count_submit',{request_id:randomUUID(),id:count.id,items:[{item_id:itemID,counted_quantity:7,note:null}]});
   await assert.rejects(invoke('equipment_count_review',{request_id:randomUUID(),id:count.id,expected_source_hash:old.source_hash,action:'approve',note:null}),e=>e.code==='stale_equipment_record');
   const pending=await invoke('equipment_count_submission',{id:count.id});
   const approval={request_id:randomUUID(),id:count.id,expected_source_hash:pending.source_hash,action:'approve',note:'Synthetic counted quantity'};
   await invoke('equipment_count_review',approval);await invoke('equipment_count_review',approval);
   assert.equal((await invoke('equipment_item',{id:itemID})).data.quantity_on_hand,7);
   assert.equal((await pool.query("SELECT count(*)::int n FROM inventory_transactions WHERE item_id=$1 AND transaction_type='inventory_count_adjustment'",[itemID])).rows[0].n,1);
  });
  await t.test('schedule edits preserve omitted fields and enforce canonical conflicts, membership, stale state and lifecycle',async()=>{
   for(const name of ['schedule_event','schedule_event_update','schedule_event_complete','schedule_event_delete','schedule_member_availability','schedule_member_availability_save','schedule_member_availability_reset','schedule_booking_settings','schedule_booking_settings_save'])await grant(name);
   const actor=await app.locals.connectionManager.actorFor((await pool.query('SELECT * FROM mcp_connections WHERE id=$1',[id])).rows[0]);const invoke=(name,args)=>app.locals.connectionManager.invoke(actor,name,{request_id:randomUUID(),...args},randomUUID()),read=(name,args)=>app.locals.connectionManager.invoke(actor,name,args,randomUUID());
   const job=randomUUID(),conflict=randomUUID();for(const [target,start,end]of[[job,'2026-10-20T14:00:00Z','2026-10-20T15:00:00Z'],[conflict,'2026-10-20T15:00:00Z','2026-10-20T16:00:00Z']])await pool.query("INSERT INTO schedule_events(id,user_id,company_id,title,start_at,end_at,notes,price_cents,worker_user_ids,sales_user_ids) VALUES($1,$2,$3,'Synthetic editing job',$4,$5,'Keep these notes',4500,$6,$6)",[target,user,company,start,end,JSON.stringify([user])]);
   let current=(await read('schedule_event',{id:job})).data;const version=current.version;
   await invoke('schedule_event_update',{id:job,expected_version:version,changes:{title:'Renamed schedule job'}});const saved=(await read('schedule_event',{id:job})).data;assert.equal(saved.record.title,'Renamed schedule job');assert.equal(saved.record.notes,'Keep these notes');assert.equal(saved.record.price_cents,4500);
   await assert.rejects(invoke('schedule_event_update',{id:job,expected_version:version,changes:{notes:'Stale'}}),e=>e.code==='stale_schedule_event');
   await assert.rejects(invoke('schedule_event_update',{id:job,expected_version:saved.version,changes:{start:'2026-10-20T15:00:00Z',end:'2026-10-20T16:00:00Z'}}),e=>e.status===409);
   await assert.rejects(invoke('schedule_event_update',{id:job,expected_version:saved.version,changes:{worker_user_ids:[other]}}),e=>e.code==='invalid_assignment_users');
   await pool.query("UPDATE mcp_connections SET tool_policy=jsonb_set(tool_policy,'{schedule_event_update,denied_input_fields}','[\"changes.price_cents\"]'),revision=revision+1 WHERE id=$1",[id]);
   await assert.rejects(invoke('schedule_event_update',{id:job,expected_version:saved.version,changes:{price_cents:1}}),e=>e.code==='field_denied');
   await invoke('schedule_event_complete',{id:job,expected_version:saved.version,completed:true,completed_at:'2026-10-20T15:00:00Z'});current=(await read('schedule_event',{id:job})).data;assert.ok(current.record.finished_at);await invoke('schedule_event_complete',{id:job,expected_version:current.version,completed:false});current=(await read('schedule_event',{id:job})).data;assert.equal(current.record.finished_at,null);
   const member=(await read('schedule_member_availability',{user_id:user}));assert.equal((await invoke('schedule_member_availability_save',{user_id:user,expected_source_hash:member.source_hash,availability:{weekdays:[1,2,3,4,5],start_time:'08:00',end_time:'18:00',enabled:true}})).data.enabled,true);
   const updated=await read('schedule_member_availability',{user_id:user});await invoke('schedule_member_availability_reset',{user_id:user,expected_source_hash:updated.source_hash});assert.equal((await read('schedule_member_availability',{user_id:user})).data.inherits_company_availability,true);
   await assert.rejects(read('schedule_member_availability',{user_id:other}),e=>e.status===404);
   const booking=(await read('schedule_booking_settings',{})).data;const {version:bookingVersion,timezone,...settings}=booking;const changed=await invoke('schedule_booking_settings_save',{expected_version:bookingVersion,settings:{...settings,minimum_notice_minutes:60}});assert.equal(changed.data.minimum_notice_minutes,60);await assert.rejects(invoke('schedule_booking_settings_save',{expected_version:bookingVersion,settings}),e=>e.code==='booking_settings_conflict');
   assert.equal((await invoke('schedule_event_delete',{id:job,expected_version:current.version})).data.deleted,true);assert.equal((await pool.query('SELECT id FROM schedule_events WHERE id=$1',[job])).rowCount,0);
  });
  await t.test('safe company, weather and time settings preserve protected values and canonical validation',async()=>{
   for(const name of ['company_settings','company_settings_save','weather_settings','weather_settings_save','time_clock_settings','time_clock_settings_save','automation_settings','automation_settings_save'])await grant(name);
   const actor=await app.locals.connectionManager.actorFor((await pool.query('SELECT * FROM mcp_connections WHERE id=$1',[id])).rows[0]);const read=(name,args={})=>app.locals.connectionManager.invoke(actor,name,args,randomUUID()),write=(name,args)=>app.locals.connectionManager.invoke(actor,name,{request_id:randomUUID(),...args},randomUUID());
   const originalLogo=(await pool.query('SELECT logo_data_url FROM companies WHERE id=$1',[company])).rows[0].logo_data_url;const logo='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aHH0AAAAASUVORK5CYII=';await pool.query('UPDATE companies SET logo_data_url=$2 WHERE id=$1',[company,logo]);const before=await read('company_settings');assert.ok(!JSON.stringify(before).includes('join_code'));assert.ok(!JSON.stringify(before).includes(logo));
   const changed=await write('company_settings_save',{expected_record_hash:before.data.record_hash,changes:{name:'Synthetic configured company',website:'https://example.invalid',notify_all_members_on_jobs:false}});assert.equal(changed.data.company.name,'Synthetic configured company');assert.equal((await pool.query('SELECT logo_data_url FROM companies WHERE id=$1',[company])).rows[0].logo_data_url,logo);assert.ok(!JSON.stringify(changed).includes('join_code'));
   await assert.rejects(write('company_settings_save',{expected_record_hash:before.data.record_hash,changes:{name:'Stale name'}}),e=>e.code==='company_settings_changed');
   await assert.rejects(write('company_settings_save',{expected_record_hash:changed.data.record_hash,changes:{join_code:'Must never change'}}),e=>e.name==='ZodError');
   const weather=await read('weather_settings');const updated=await write('weather_settings_save',{expected_source_hash:weather.source_hash,changes:{wind_speed_mph:30}});assert.equal(updated.data.wind_speed_mph,30);assert.equal(updated.data.enabled,weather.data.enabled);
   const automationSettings=await read('automation_settings');const automationSaved=await write('automation_settings_save',{expected_source_hash:automationSettings.source_hash,changes:{automation_sms_max_per_contact_hour:3}});assert.equal(automationSaved.data.automation_sms_max_per_contact_hour,3);assert.equal(automationSaved.data.automated_customer_messages_enabled,automationSettings.data.automated_customer_messages_enabled);await assert.rejects(write('automation_settings_save',{expected_source_hash:automationSettings.source_hash,changes:{automation_sms_max_per_contact_hour:4}}),e=>e.code==='automation_settings_changed');
   const time=await read('time_clock_settings');assert.equal((await write('time_clock_settings_save',{expected_source_hash:time.source_hash,week_start:0})).data.week_start,0);await pool.query('UPDATE companies SET logo_data_url=$2 WHERE id=$1',[company,originalLogo]);
  });
  await t.test('existing automation graphs edit typed ordinary actions, logic and lifecycle without stale overwrites',async()=>{
   const names=['automation_create','automation_get','automation_draft','automation_node_schema','automation_graph_save','automation_publish','automation_duplicate','automation_archive','automation_ensure_draft','automation_metadata_save'];for(const name of names)await grant(name);
   const actor=await app.locals.connectionManager.actorFor((await pool.query('SELECT * FROM mcp_connections WHERE id=$1',[id])).rows[0]);const invoke=(name,args)=>app.locals.connectionManager.invoke(actor,name,{request_id:randomUUID(),...args},randomUUID());
   const created=(await invoke('automation_create',{name:'Typed graph fixture',description:'No real external effects'})).data;
   const first=(await app.locals.connectionManager.invoke(actor,'automation_draft',{id:created.id},randomUUID())).data;
   const trigger=randomUUID(),action=randomUUID(),end=randomUUID();
   const graph={id:created.id,expected_graph_hash:first.graph_hash,nodes:[{id:trigger,node_key:'manual',node_type:'trigger',title:'Manual',config:{trigger_key:'manual'}},{id:action,node_key:'task',node_type:'action',title:'Task',config:{action_key:'task.create',title:'Typed task from graph',notes:'Fixture detail',assigned_user_id:user}},{id:end,node_key:'end',node_type:'end',title:'End',config:{}}],edges:[{id:randomUUID(),source_node_id:trigger,target_node_id:action},{id:randomUUID(),source_node_id:action,target_node_id:end}],settings:{}};
   const saved=(await invoke('automation_graph_save',graph)).data;assert.equal(saved.node_count,3);
   await assert.rejects(invoke('automation_graph_save',graph),e=>e.code==='automation_draft_changed');
   const schema=(await app.locals.connectionManager.invoke(actor,'automation_node_schema',{kind:'action',key:'task.create'},randomUUID())).data;assert.equal(schema.schema.properties.title.type,'string');
   const live=(await app.locals.connectionManager.invoke(actor,'automation_draft',{id:created.id},randomUUID())).data;
   await assert.rejects(invoke('automation_graph_save',{...graph,expected_graph_hash:live.graph_hash,nodes:graph.nodes.map(n=>n.id===action?{...n,config:{...n.config,arbitrary_sql:'DROP TABLE users'}}:n)}),e=>e.name==='ZodError');
   await assert.rejects(invoke('automation_graph_save',{...graph,expected_graph_hash:live.graph_hash,nodes:graph.nodes.map(n=>n.id===action?{...n,config:{action_key:'mcp.enable',connection_id:id}}:n)}),e=>e.code==='human_managed_automation_action');
   await invoke('automation_publish',{id:created.id,expected_graph_hash:live.graph_hash});
   const started=await http('automations/'+created.id+'/manual-run',{});await automationTestHooks.runAutomation(started.data.id);assert.equal((await pool.query("SELECT count(*)::int n FROM todo_tasks WHERE company_id=$1 AND title='Typed task from graph'",[company])).rows[0].n,1);
   const draft=(await invoke('automation_ensure_draft',{id:created.id})).data;const minimal=n=>({id:n.id,node_key:n.node_key,node_type:n.node_type,title:n.title,position_x:n.position_x,position_y:n.position_y,config:n.config});
   const nodes=draft.graph.nodes.map(minimal),task=nodes.find(n=>n.node_key==='task'),ending=nodes.find(n=>n.node_key==='end');task.config.title='Revised ordinary action';const condition=randomUUID();nodes.push({id:condition,node_key:'branch',node_type:'condition',title:'Branch',config:{condition:{field:'event.source',operator:'equals',value:'manual'}}});
   const edges=draft.graph.edges.filter(e=>e.source_node_id!==task.id).map(e=>({id:e.id,source_node_id:e.source_node_id,target_node_id:e.target_node_id,source_port:e.source_port||'default',target_port:e.target_port||'default'}));edges.push({id:randomUUID(),source_node_id:task.id,target_node_id:condition},{id:randomUUID(),source_node_id:condition,target_node_id:ending.id,source_port:'true'},{id:randomUUID(),source_node_id:condition,target_node_id:ending.id,source_port:'false'});
   assert.equal((await invoke('automation_graph_save',{id:created.id,expected_graph_hash:draft.graph_hash,nodes,edges,settings:{timezone:'America/New_York'}})).data.node_count,4);
   const details=(await app.locals.connectionManager.invoke(actor,'automation_get',{id:created.id},randomUUID())).data;
   const changed=await invoke('automation_metadata_save',{id:created.id,expected_record_hash:details.record_hash,changes:{name:'Renamed typed graph',description:'Updated by fixture'}});assert.equal(changed.data.name,'Renamed typed graph');
   const record=(await app.locals.connectionManager.invoke(actor,'automation_get',{id:created.id},randomUUID())).data;
   const copy=(await invoke('automation_duplicate',{id:created.id,expected_record_hash:record.record_hash})).data;assert.notEqual(copy.id,created.id);const copied=(await app.locals.connectionManager.invoke(actor,'automation_get',{id:copy.id},randomUUID())).data;assert.equal((await invoke('automation_archive',{id:copy.id,expected_record_hash:copied.record_hash})).data.archived,true);
  });
  await t.test('legacy automation secrets are redacted and preserved while unrelated nodes change',async()=>{
   const created=(await http('automations',{name:'Protected legacy graph',description:'Fixture only'})).data;const trigger=randomUUID(),action=randomUUID(),end=randomUUID();
   const nodes=[{id:trigger,node_key:'manual',node_type:'trigger',title:'Manual',config:{trigger_key:'manual'}},{id:action,node_key:'legacy',node_type:'action',title:'Legacy webhook',config:{action_key:'webhook.send',url:'https://example.invalid/fixture',method:'POST',headers:{Authorization:'Bearer synthetic-only-fixture-value'},body:{purpose:'fixture'}}},{id:end,node_key:'end',node_type:'end',title:'End',config:{}}];const edges=[{id:randomUUID(),source_node_id:trigger,target_node_id:action},{id:randomUUID(),source_node_id:action,target_node_id:end}];assert.equal((await http('automations/'+created.id+'/draft/graph',{nodes,edges,settings:{}},'PUT')).status,200);
   const actor=await app.locals.connectionManager.actorFor((await pool.query('SELECT * FROM mcp_connections WHERE id=$1',[id])).rows[0]);const draft=(await app.locals.connectionManager.invoke(actor,'automation_draft',{id:created.id},randomUUID())).data;
   assert.ok(!JSON.stringify(draft).includes('synthetic-only-fixture-value'));const minimal=draft.graph.nodes.map(n=>({id:n.id,node_key:n.node_key,node_type:n.node_type,title:n.node_key==='end'?'Renamed annotation':n.title,position_x:n.position_x,position_y:n.position_y,config:n.config}));
   const saved=await app.locals.connectionManager.invoke(actor,'automation_graph_save',{id:created.id,expected_graph_hash:draft.graph_hash,nodes:minimal,edges,settings:{},request_id:randomUUID()},randomUUID());assert.equal(saved.data.node_count,3);
   const raw=(await http('automations/'+created.id)).data.draft.nodes.find(n=>n.node_key==='legacy');assert.equal(raw.config.headers.Authorization,'Bearer synthetic-only-fixture-value');
  });
  await t.test('AI automation queues once, waits durably and saves its final report as a Note',async()=>{
   await grant('note_create');const created=await http('automations',{name:'Synthetic daily report',description:'Test only'});assert.equal(created.status,201,JSON.stringify(created));const automation=created.data.id;
   const trigger=randomUUID(),task=randomUUID(),end=randomUUID(),config={action_key:'assistant.task',execution_user_id:user,instructions:'Return a short synthetic daily report.',allowed_tools:['note_create'],model:'gpt-6.1-sol',reasoning:'low',max_steps:4,max_cost_micros:1000000,output_destination:'private_note',output_title:'Synthetic daily report',failure_behavior:'stop'};
   const graph={nodes:[{id:trigger,node_key:'trigger',node_type:'trigger',config:{trigger_key:'time.schedule',schedule:{frequency:'daily',time:'19:00',timezone:'UTC'}}},{id:task,node_key:'report',node_type:'action',config},{id:end,node_key:'end',node_type:'end',config:{}}],edges:[{id:randomUUID(),source_node_id:trigger,target_node_id:task,source_port:'default',target_port:'default'},{id:randomUUID(),source_node_id:task,target_node_id:end,source_port:'default',target_port:'default'}],settings:{}};
   const save=await http('automations/'+automation+'/draft/graph',graph,'PUT');assert.equal(save.status,200,JSON.stringify(save));const publish=await http('automations/'+automation+'/publish',{});assert.equal(publish.status,200,JSON.stringify(publish));
   const scheduledAt=new Date(Date.now()+86400000);scheduledAt.setUTCHours(19,0,30,0);
   assert.equal(await enqueueTimeSchedules(pool,scheduledAt),1);await automationTestHooks.processScheduledAutomationEvents(scheduledAt);for(let tick=0;tick<20;tick++){await automationTestHooks.processAutomationEvents();if((await pool.query('SELECT id FROM automation_runs WHERE automation_id=$1',[automation])).rowCount)break;}
   const scheduledRun=(await pool.query('SELECT id FROM automation_runs WHERE automation_id=$1',[automation])).rows[0];assert.ok(scheduledRun,JSON.stringify((await pool.query("SELECT event_type,processing_status FROM automation_events WHERE company_id=$1 ORDER BY created_at DESC LIMIT 2",[company])).rows));const started={data:{id:scheduledRun.id}};
   assert.equal(await enqueueTimeSchedules(pool,scheduledAt),0);
   const runs=(await pool.query('SELECT * FROM wolf_assistant_runs WHERE automation_run_id=$1',[started.data.id])).rows;assert.equal(runs.length,1,JSON.stringify(started));const run=(await pool.query('SELECT * FROM automation_runs WHERE id=$1',[started.data.id])).rows[0];assert.equal((await engine.startAutomation(run,{id:(await pool.query("SELECT id FROM automation_nodes WHERE version_id=$1 AND node_key='report'",[run.automation_version_id])).rows[0].id},config,'root')).id,runs[0].id);
   responses.push(complete('Today: synthetic leads and jobs.'));await engine.tick();const result=(await pool.query('SELECT * FROM wolf_assistant_runs WHERE id=$1',[runs[0].id])).rows[0];assert.equal(result.status,'completed',JSON.stringify({status:result.status,error:result.error_code}));assert.equal((await pool.query("SELECT count(*)::int n FROM comms_notes WHERE company_id=$1 AND title='Synthetic daily report'",[company])).rows[0].n,1);
   await pool.query("UPDATE automation_waits SET resume_at=now()-interval '1 second' WHERE run_id=$1",[run.id]);await automationTestHooks.processDueWaits();assert.equal((await pool.query('SELECT status FROM automation_runs WHERE id=$1',[run.id])).rows[0].status,'completed');
  });
  await t.test('AI automation failure follows its error branch and recovers a claimed wait',async()=>{
   const created=await http('automations',{name:'Synthetic failure report',description:'Test only'}),automation=created.data.id;
   const trigger=randomUUID(),task=randomUUID(),success=randomUUID(),failure=randomUUID();
   const config={action_key:'assistant.task',execution_user_id:user,instructions:'Simulate an unavailable provider.',allowed_tools:[],model:'gpt-6.1-sol',reasoning:'low',max_steps:4,max_cost_micros:1000000,output_destination:'assistant_result',output_title:'Failure fixture',failure_behavior:'error_path'};
   const graph={nodes:[{id:trigger,node_key:'trigger',node_type:'trigger',config:{trigger_key:'manual'}},{id:task,node_key:'report',node_type:'action',config},{id:success,node_key:'success',node_type:'end',config:{}},{id:failure,node_key:'failure',node_type:'end',config:{}}],edges:[{id:randomUUID(),source_node_id:trigger,target_node_id:task,source_port:'default',target_port:'default'},{id:randomUUID(),source_node_id:task,target_node_id:success,source_port:'default',target_port:'default'},{id:randomUUID(),source_node_id:task,target_node_id:failure,source_port:'error',target_port:'default'}],settings:{}};
   assert.equal((await http('automations/'+automation+'/draft/graph',graph,'PUT')).status,200);assert.equal((await http('automations/'+automation+'/publish',{})).status,200);
   const started=await http('automations/'+automation+'/manual-run',{});await automationTestHooks.runAutomation(started.data.id);
   responses.push(()=>{throw new Error('Synthetic provider unavailable');});await engine.tick();
   await pool.query("UPDATE automation_waits SET status='ready',updated_at=now()-interval '4 minutes' WHERE run_id=$1",[started.data.id]);
   await automationTestHooks.processDueWaits();
   const completed=(await pool.query("SELECT n.node_key FROM automation_run_nodes rn JOIN automation_nodes n ON n.id=rn.node_id WHERE rn.run_id=$1 AND rn.status='completed'",[started.data.id])).rows.map(x=>x.node_key);
   assert.ok(completed.includes('failure'),JSON.stringify(completed));assert.ok(!completed.includes('success'));
   assert.equal((await pool.query('SELECT status FROM automation_runs WHERE id=$1',[started.data.id])).rows[0].status,'completed');
  });
  await t.test('execution-level ask-first policy prevents provider spend until approved',async()=>{
   await grant('assistant_execute',true);const before=calls;const r=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Approve paid execution first'});await engine.tick();assert.equal((await http('assistant/runs/'+r.data.id)).data.status,'waiting_approval');assert.equal(calls,before);const proposal=(await pool.query("SELECT * FROM mcp_approvals WHERE connection_id=$1 AND state='pending' AND operation='assistant_execute'",[id])).rows[0];assert.equal((await http('ai-connections/approvals/'+proposal.id,{expected_hash:proposal.input_hash,decision:'approve'})).status,200);responses.push(complete('Authorized run.'));await engine.tick();assert.equal((await http('assistant/runs/'+r.data.id)).data.status,'completed');await grant('assistant_execute');
  });
  await t.test('web research uses isolated query, citations, selected funding and separate cost',async()=>{
   await grant('assistant_web_research');responses.push(tool('load_capabilities',{ids:['assistant_web_research']}),tool('assistant_web_research',{query:'Synthetic public research'}),request=>{assert.equal(request.tools[0].type,'web_search');assert.equal(request.max_tool_calls,1);assert.deepEqual(request.input,[{role:'user',content:'Synthetic public research'}]);return {output:[{type:'web_search_call'},{type:'message',content:[{type:'output_text',text:'Public source.',annotations:[{type:'url_citation',title:'Example',url:'https://example.com'}]}]}],usage:{input_tokens:25,output_tokens:15}};},complete('Cited research result.'));
   const r=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Research public information'});await engine.tick();const result=(await http('assistant/runs/'+r.data.id)).data;assert.equal(result.status,'completed',JSON.stringify(result));assert.equal(result.usage.web_search_calls,1);assert.ok(result.cost_micros>=10000);const step=(await pool.query("SELECT result FROM wolf_assistant_steps WHERE run_id=$1 AND tool='assistant_web_research'",[r.data.id])).rows[0];assert.equal(step.result.sources[0].url,'https://example.com');
  });
  await t.test('typed contact fields, bulk atomicity and quote settings use canonical writers',async()=>{
   const c=(await pool.query('SELECT * FROM mcp_connections WHERE id=$1',[id])).rows[0],a=await app.locals.connectionManager.actorFor(c);
   for(const name of ['crm_get','contact_details','contact_details_update','contacts_bulk_update','quote_settings','quote_settings_save','task_create','task_update'])await grant(name);
   const call=(name,args)=>app.locals.connectionManager.invoke(a,name,args,randomUUID());
   const contact=(await pool.query('SELECT id FROM contacts WHERE company_id=$1 LIMIT 1',[company])).rows[0].id;
   const original=await call('crm_get',{entity:'contacts',id:contact});
   await call('contact_details_update',{request_id:randomUUID(),id:contact,expected_version:original.version,changes:{u1:'Synthetic gate code note',lead_info:['Synthetic lead requirement']}});
   const details=await call('contact_details',{id:contact});assert.equal(details.data.fields.u1,'Synthetic gate code note');
   await assert.rejects(call('contacts_bulk_update',{request_id:randomUUID(),items:[{request_id:randomUUID(),id:contact,expected_version:original.version,changes:{name:'Must not overwrite'}}]}),e=>e.code==='stale_record');
   await call('contacts_bulk_update',{request_id:randomUUID(),items:[{request_id:randomUUID(),id:contact,expected_version:details.data.version,changes:{tags:['Synthetic']}}]});
   const settings=await call('quote_settings',{});await call('quote_settings_save',{request_id:randomUUID(),expected_source_hash:settings.source_hash,changes:{valid_for_days:17}});assert.equal((await call('quote_settings',{})).data.valid_for_days,17);
   await assert.rejects(call('quote_settings_save',{request_id:randomUUID(),expected_source_hash:settings.source_hash,changes:{valid_for_days:22}}),e=>e.code==='stale_record');
   const task=await call('task_create',{request_id:randomUUID(),title:'Synthetic task',priority:'normal'});const before=await call('crm_get',{entity:'tasks',id:task.id});
   await call('task_update',{request_id:randomUUID(),id:task.id,expected_version:before.version,changes:{detail:'Edited canonical task',priority:'high'}});
   assert.equal((await call('crm_get',{entity:'tasks',id:task.id})).data.detail,'Edited canonical task');
  });
  await t.test('assistant creates and revises quote alternatives using canonical calculations',async()=>{
   const lead=randomUUID(),service=randomUUID();
   await pool.query("INSERT INTO contacts(id,user_id,company_id,name) VALUES($1,$2,$3,'Calculator fixture')",[lead,user,company]);
   await pool.query("INSERT INTO saved_services(id,company_id,name) VALUES($1,$2,'Synthetic windows')",[service,company]);
   const config={questions:[{id:'count',label:'Window count',type:'number',unit:'count',required:true,service_ids:[service]}],services:[{service_id:service,crew_size:1,elapsed_ratio_bp:10000}],components:[{id:'exterior',name:'Exterior',order:0,service_ids:[service],scope:'service',unit:'count',quantity_fact:'count',decimal_quantity:false,selection:'required',money_enabled:true,time_enabled:true,unit_cents:1000,unit_seconds:60,visible:true}]};
   assert.equal((await http('quote-calculator/config',{config,expected_revision:0},'PUT')).status,200);
   for(const name of ['get_quote_definitions','calculate_quote','save_quote_draft','duplicate_quote_draft','get_quote_draft','list_quote_options'])await grant(name);
   const connection=(await pool.query('SELECT * FROM mcp_connections WHERE id=$1',[id])).rows[0],actor=await app.locals.connectionManager.actorFor(connection);
   const invoke=(name,args)=>app.locals.connectionManager.invoke(actor,name,args,randomUUID());
   assert.ok(app.locals.capabilityService.catalog.some(c=>c.id==='calculate_quote'));
   const input={service_ids:[service],answers:{count:{value:20,source:'confirmed'}}};
   const calculated=await invoke('calculate_quote',{input});assert.equal(calculated.data.pricing.total_cents,20000);
   const initial=await invoke('save_quote_draft',{contact_id:lead,title:'Option A',input,request_key:randomUUID()});assert.equal(initial.data.calculation.pricing.total_cents,20000);
   const copy=await invoke('duplicate_quote_draft',{quote_id:initial.data.id,expected_revision:1,title:'Option B',request_key:randomUUID()});assert.notEqual(copy.data.id,initial.data.id);
   const revised=await invoke('save_quote_draft',{contact_id:lead,quote_id:copy.data.id,expected_revision:1,title:'Option B revised',input:{...input,answers:{count:{value:30,source:'confirmed'}}},request_key:randomUUID()});assert.equal(revised.data.calculation.pricing.total_cents,30000);
   const unchanged=await invoke('get_quote_draft',{quote_id:initial.data.id});assert.equal(unchanged.data.quote.calculation.pricing.total_cents,20000);
   const options=await invoke('list_quote_options',{lead_id:lead});assert.equal(options.data.items.length,2);
   await assert.rejects(()=>invoke('save_quote_draft',{contact_id:lead,quote_id:copy.data.id,expected_revision:1,title:'Stale',input,request_key:randomUUID()}),e=>e.code==='quote_revision_changed');
  });
  await t.test('quote publication uses an exact preview and creates no customer send',async()=>{
   const contact=randomUUID(),quote=randomUUID();
   await pool.query("INSERT INTO contacts(id,user_id,company_id,name,email) VALUES($1,$2,$3,'Publication fixture','customer@example.invalid')",[contact,user,company]);
   await pool.query("INSERT INTO quotes(id,user_id,company_id,contact_id,line_items,total_cents,quote_options) VALUES($1,$2,$3,$4,$5,25000,$6)",[quote,user,company,contact,JSON.stringify([{name:'Windows',qty:1,price_cents:25000,description:'Synthetic scope'}]),JSON.stringify({duration_minutes:60,deposit:{type:'none',value:0}})]);
   assert.equal((await http('agreements/settings',{expected_version:1,content:{consent_text:'I agree to electronic signing of this synthetic estimate.',agreement_text:'Work for {{customer_name}}. Total {{total}}.'}},'PUT')).status,200);
   const templates=(await http('agreements/templates')).data,defaults=(await http('agreements/settings')).data;
   assert.equal((await http('agreements/templates',{template_id:templates[0].template_id,expected_version:templates[0].version,name:templates[0].name,content:defaults.content})).status,201);
   for(const name of ['quote_delivery_preview','quote_publish_link'])await grant(name);
   const actor=await app.locals.connectionManager.actorFor((await pool.query('SELECT * FROM mcp_connections WHERE id=$1',[id])).rows[0]);
   const invoke=(name,args)=>app.locals.connectionManager.invoke(actor,name,args,randomUUID());
   const preview=await invoke('quote_delivery_preview',{quote_id:quote,request_id:randomUUID()});assert.ok(preview.data.preview_hash);assert.equal(preview.data.pdf_base64,undefined);
   await assert.rejects(()=>invoke('quote_publish_link',{quote_id:quote,expected_preview_hash:'0'.repeat(64),expected_updated_at:preview.data.quote_updated_at,request_id:randomUUID()}),e=>e.status===409);
   const published=await invoke('quote_publish_link',{quote_id:quote,expected_preview_hash:preview.data.preview_hash,expected_updated_at:preview.data.quote_updated_at,request_id:randomUUID()});
   assert.ok(published.data.customer_url);assert.equal((await pool.query('SELECT * FROM quote_agreements WHERE quote_id=$1',[quote])).rowCount,1);assert.equal(externalCalls,0);
  });
  await t.test('retained read evidence is reauthorized before subsequent model requests',async()=>{
   for(const name of ['notes_get','app_instructions'])await grant(name);
   const actor=await app.locals.connectionManager.actorFor((await pool.query('SELECT * FROM mcp_connections WHERE id=$1',[id])).rows[0]);
   const owner=randomUUID();await pool.query("INSERT INTO users(id,email,display_name,company_id,role,password_hash) VALUES($1,$2,'Note owner',$3,'employee','fixture')",[owner,owner+'@example.invalid',company]);
   const note=await app.locals.notes.create(actor,{id:randomUUID(),title:'Shared evidence',visibility:'private'});
   await pool.query("UPDATE comms_notes SET owner_id=$2,creator_id=$2,editor_id=$2,visibility='shared' WHERE id=$1",[note.page.id,owner]);await pool.query("INSERT INTO notes_members(page_id,user_id,role) VALUES($1,$2,1)",[note.page.id,user]);
   responses.push(tool('load_capabilities',{ids:['notes_get','app_instructions']}),tool('notes_get',{id:note.page.id}),async()=>{await pool.query('DELETE FROM notes_members WHERE page_id=$1',[note.page.id]);return tool('app_instructions',{query:'Notes'});});
   const beforeCalls=calls;const r=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Use the shared note'});await engine.tick();const result=(await http('assistant/runs/'+r.data.id)).data;assert.equal(result.status,'failed',JSON.stringify(result));assert.equal(result.error_code,'source_access_changed');assert.equal(calls,beforeCalls+3);assert.equal(responses.length,0);
   assert.ok(result.actions.some(x=>x.tool==='notes_get'&&x.state==='completed'));
  });
  await t.test('completed tasks remain completed when cancellation is retried',async()=>{
   responses.push(complete('Already complete.'));const r=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Complete once'});await engine.tick();await http('assistant/runs/'+r.data.id+'/cancel',{});assert.equal((await http('assistant/runs/'+r.data.id)).data.status,'completed');
   const usage=await http('assistant/usage');assert.equal(usage.status,200);assert.ok(usage.data.input_tokens>0);assert.equal(usage.data.cost_status,'estimate_only');
  });
  await t.test('customer messaging stages approval and never retries uncertain external effects',async()=>{
   await grant('assistant_customer_message',true);const line=randomUUID(),conversation=randomUUID();await pool.query("INSERT INTO phone_lines(id,company_id,phone_number) VALUES($1,$2,'+15555550100')",[line,company]);await pool.query("INSERT INTO sms_conversations(id,phone_line_id,external_phone_number) VALUES($1,$2,'+15555550101')",[conversation,line]);
   const args={request_id:randomUUID(),conversation_id:conversation,body:'Synthetic message - never transmitted'};
   responses.push(tool('load_capabilities',{ids:['assistant_customer_message']}),tool('assistant_customer_message',args));const r=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Send synthetic text'});await engine.tick();assert.equal(externalCalls,0);
   const approval=(await pool.query("SELECT * FROM mcp_approvals WHERE connection_id=$1 AND state='pending' AND operation='assistant_customer_message'",[id])).rows[0];assert.ok(approval);await http('ai-connections/approvals/'+approval.id,{expected_hash:approval.input_hash,decision:'approve'});assert.equal(externalCalls,0,'Approval transaction only stages the external effect');
   responses.push(complete('Submitted.'));await engine.tick();assert.equal(externalCalls,1);assert.equal((await http('assistant/runs/'+r.data.id)).data.status,'completed');
   await grant('assistant_customer_message');responses.push(tool('load_capabilities',{ids:['assistant_customer_message']}),tool('assistant_customer_message',args),complete('Previous receipt.'));const replay=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Retry the same request'});await engine.tick();const replayResult=(await http('assistant/runs/'+replay.data.id)).data;assert.equal(replayResult.status,'completed',JSON.stringify(replayResult));assert.equal(externalCalls,1);
   externalFails=true;const uncertain={...args,request_id:randomUUID()};responses.push(tool('load_capabilities',{ids:['assistant_customer_message']}),tool('assistant_customer_message',uncertain));const interrupted=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Simulate lost provider response'});await engine.tick();assert.equal((await http('assistant/runs/'+interrupted.data.id)).data.status,'interrupted');assert.equal(externalCalls,2);
   responses.push(tool('load_capabilities',{ids:['assistant_customer_message']}),tool('assistant_customer_message',uncertain));const again=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Retry uncertain request'});await engine.tick();assert.equal((await http('assistant/runs/'+again.data.id)).data.status,'interrupted');assert.equal(externalCalls,2);externalFails=false;
  });
  await t.test('cancellation during an accepted external effect records completion before stopping',async()=>{
   await grant('assistant_customer_message');const line=randomUUID(),conversation=randomUUID();await pool.query("INSERT INTO phone_lines(id,company_id,phone_number) VALUES($1,$2,'+15555550200')",[line,company]);await pool.query("INSERT INTO sms_conversations(id,phone_line_id,external_phone_number) VALUES($1,$2,'+15555550201')",[conversation,line]);
   const args={request_id:randomUUID(),conversation_id:conversation,body:'Synthetic accepted before cancellation'};const before=externalCalls;
   responses.push(tool('load_capabilities',{ids:['assistant_customer_message']}),tool('assistant_customer_message',args));
   const queued=await http('assistant/runs',{conversation_id:chat,request_key:randomUUID(),text:'Cancel while accepted'});externalAfter=async()=>{await http('assistant/runs/'+queued.data.id+'/cancel',{});};await engine.tick();
   const result=(await http('assistant/runs/'+queued.data.id)).data;assert.equal(result.status,'cancelled');assert.equal(externalCalls,before+1);assert.equal(result.actions.find(a=>a.tool==='assistant_customer_message').state,'completed');
   const receipt=(await pool.query('SELECT result FROM mcp_operations WHERE connection_id=$1 AND request_id=$2',[id,args.request_id])).rows[0];assert.equal(receipt.result.status,'submitted');assert.ok(receipt.result.id);
  });
  await t.test('assistant memory respects per-chat opt-out and exact approval policy',async()=>{
   await grant('assistant_memory_save');const noMemory=(await http('assistant/conversations',{title:'No learning',memory_enabled:false})).data.id;
   const args={request_id:randomUUID(),body:'Prefer concise answers',kind:'inferred',provenance:'Synthetic explicit preference in this test'};
   responses.push(tool('load_capabilities',{ids:['assistant_memory_save']}),tool('assistant_memory_save',args),complete('Memory is disabled.'));
   const denied=await http('assistant/runs',{conversation_id:noMemory,request_key:randomUUID(),text:'Remember my preference'});await engine.tick();assert.equal((await http('assistant/runs/'+denied.data.id)).data.actions.find(x=>x.tool==='assistant_memory_save').error,'memory_disabled');
   const withMemory=(await http('assistant/conversations',{title:'Learning',memory_enabled:true})).data.id;
   responses.push(tool('load_capabilities',{ids:['assistant_memory_save']}),tool('assistant_memory_save',{...args,request_id:randomUUID()}),complete('Preference saved.'));
   const saved=await http('assistant/runs',{conversation_id:withMemory,request_key:randomUUID(),text:'Remember my preference'});await engine.tick();const rows=(await http('assistant/memories')).data.items;const learned=rows.find(x=>x.body==='Prefer concise answers');assert.ok(learned);assert.equal(learned.kind,'inferred');await http('assistant/memories/'+learned.id,undefined,'DELETE');
  });
  await t.test('deletion during an in-flight provider response removes late chat data',async()=>{
   const deletedChat=(await http('assistant/conversations',{title:'Delete during response'})).data.id;
   responses.push(async()=>{assert.equal((await http('assistant/conversations/'+deletedChat,undefined,'DELETE')).status,200);return complete('Private late response');});
   const r=await http('assistant/runs',{conversation_id:deletedChat,request_key:randomUUID(),text:'This transcript must be purged'});await engine.tick();
   assert.equal((await http('assistant/runs/'+r.data.id)).status,404);
   const stored=(await pool.query('SELECT history,context,instructions,output FROM wolf_assistant_runs WHERE id=$1',[r.data.id])).rows[0];
   assert.deepEqual(stored,{history:[],context:{},instructions:'',output:''});
   assert.equal((await pool.query('SELECT * FROM wolf_assistant_events WHERE run_id=$1',[r.data.id])).rowCount,0);
   assert.equal((await pool.query('SELECT * FROM wolf_assistant_messages WHERE conversation_id=$1',[deletedChat])).rowCount,0);
   assert.equal((await pool.query("SELECT * FROM wolf_assistant_steps WHERE run_id=$1 AND (arguments<>'{}'::jsonb OR result IS NOT NULL)",[r.data.id])).rowCount,0);
  });
  await t.test('native identity field policy redacts canonical reads and rejects writes',async()=>{
   const contact=randomUUID();await pool.query("INSERT INTO contacts(id,user_id,company_id,name,phone) VALUES($1,$2,$3,'Field privacy','+15555550123')",[contact,user,company]);
   await pool.query("UPDATE mcp_connections SET tool_policy=tool_policy || $2::jsonb,revision=revision+1 WHERE id=$1",[id,JSON.stringify({crm_get:{allow:true,approval:false,denied_output_fields:['data.phone']},contact_update:{allow:true,approval:false,denied_input_fields:['changes.phone']}})]);
   const actor=await app.locals.connectionManager.actorFor((await pool.query('SELECT * FROM mcp_connections WHERE id=$1',[id])).rows[0]);
   const record=await app.locals.connectionManager.invoke(actor,'crm_get',{entity:'contacts',id:contact},randomUUID());assert.equal(record.data.name,'Field privacy');assert.equal(record.data.phone,undefined);
   await assert.rejects(()=>app.locals.connectionManager.invoke(actor,'contact_update',{id:contact,expected_version:record.version,changes:{phone:'+15555550999'},request_id:randomUUID()},randomUUID()),e=>e.code==='field_denied');
   assert.equal((await pool.query('SELECT phone FROM contacts WHERE id=$1',[contact])).rows[0].phone,'+15555550123');
  });
  await t.test('memory and guidance revisions, secrets and deletion semantics',async()=>{
   const m=await http('assistant/memories',{body:'Prefer short answers',kind:'preference',provenance:'User explicitly saved'});assert.equal(m.status,201);
   assert.equal((await http('assistant/memories/'+m.data.id,{body:'Changed',enabled:true,expected_revision:99},'PUT')).status,409);
   assert.equal((await http('assistant/memories',{body:'api_key=secret',kind:'inferred',provenance:'test'})).status,400);
   assert.equal((await http('assistant/memories',undefined,'GET',other)).data.items.length,0);
   assert.equal((await http('assistant/guidance',{body:'Our office opens at nine.',expected_revision:0})).status,200);
   assert.equal((await http('assistant/guidance',{body:'stale',expected_revision:0})).status,409);
   await http('assistant/conversations/'+chat,undefined,'DELETE');assert.equal((await http('assistant/conversations/'+chat)).status,404);assert.equal((await http('assistant/memories')).data.items.length,1);
  });
  await t.test('recursive field policy never silently ignores denied inputs',()=>{assert.throws(()=>restrictFields({changes:{phone:'1'}},['changes.phone'],{write:true}),e=>e.code==='field_denied');assert.deepEqual(restrictFields({items:[{data:{name:'ok',phone:'secret'}}]},['items.*.data.phone']),{items:[{data:{name:'ok'}}]});});
 }finally{if(server)await new Promise(r=>server.close(r));await backend?.pool.end();pg.stop();}
});
