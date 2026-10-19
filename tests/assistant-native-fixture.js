// Disposable, loopback-only acceptance fixture. All records and credentials are
// synthetic. No existing database, paid provider, customer channel or ad account
// is used. SIGINT/SIGTERM removes the Unix-socket-only PostgreSQL cluster.
import assert from 'node:assert/strict';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {randomUUID,randomBytes} from 'node:crypto';
import {writeFile,chmod} from 'node:fs/promises';
import {PDFDocument} from 'pdf-lib';
import {installGoogleSheetsSchema} from '../google-sheets.js';
import {installMediaStorage} from '../media-storage/index.js';
import {installCompanyComms} from '../company-comms/index.js';
import {installNotes} from '../notes/index.js';
import {installBrowser} from '../browser.js';
import {installIdeaParking} from '../idea-parking.js';
import {installFocusSystem} from '../focus.js';
import {installRoutineGroupSystem} from '../routine-groups.js';
import {installAgreementSystem} from '../quote-agreements.js';
import {installAgreementBooking} from '../agreement-booking.js';
import {installAutomationSystem,emitAutomationEvent,webhookEventCatalog} from '../automations.js';
import {installFacebookAds} from '../facebook-ads/index.js';
import {installWebhooks} from '../webhooks/service.js';
import {installWidgetDashboard} from '../widget-dashboard.js';
import {installMCP} from '../mcp/index.js';
import {installAssistant} from '../assistant/index.js';
import {modelCatalog} from '../assistant/models.js';

// Allowlist inherited environment before loading index.js. Production/provider
// credentials cannot become reachable through an unrelated optional service.
const keep=new Set(['PATH','HOME','TMPDIR','LANG','LC_ALL','SHELL','USER','LOGNAME','TERM','TZ']);
for(const key of Object.keys(process.env))if(!keep.has(key))delete process.env[key];
process.env.NODE_ENV='test';process.env.FOCUS_WORKER_ENABLED='false';
process.env.FACEBOOK_ADS_WORKER_ENABLED='false';process.env.RETELL_OUTBOUND_CALLING_ENABLED='false';
const pg=startLocalPostgres();pg.configureEnvironment();
const originalFetch=globalThis.fetch;let externalAttempts=0;
globalThis.fetch=async(input,options)=>{
 const url=new URL(typeof input==='string'?input:input.url||String(input));
 if(!['127.0.0.1','localhost','::1','[::1]'].includes(url.hostname)||url.protocol!=='http:'){
  externalAttempts++;throw new Error('Synthetic native fixture rejected non-loopback fetch');
 }
 return originalFetch(input,options);
};
let backend,server,assistant,stopping=false;
async function stop(code=0){
 if(stopping)return;stopping=true;assistant?.stop();
 if(server){server.closeAllConnections?.();await new Promise(r=>server.close(r));}
 await backend?.pool.end();pg.stop();globalThis.fetch=originalFetch;process.exit(code);
}
process.on('SIGINT',()=>void stop());process.on('SIGTERM',()=>void stop());
process.on('unhandledRejection',error=>{console.error('[fixture-unhandled]',error?.code||error?.name);void stop(1);});
try {
 backend=await import('../index.js');const {app,pool,authRequired,requireCapability}=backend;
 await backend.bootstrap();await installGoogleSheetsSchema(pool);
 const company=randomUUID(),user=randomUUID(),staff=randomUUID(),contact=randomUUID(),secondContact=randomUUID(),token='assistant-completion-native-fixture',staffToken='assistant-completion-staff-fixture';
 const note=randomUUID(),file=randomUUID(),browserLink=randomUUID(),ideaList=randomUUID(),idea=randomUUID(),task=randomUUID();
 const objects=new Map();let origin;
 const bucket={readBytes:async row=>objects.get(row.id),readText:async row=>objects.get(row.id)?.toString('utf8'),access:async row=>origin+'/__fixture/objects/'+row.id,head:async row=>({ContentLength:objects.get(row.id)?.length||0}),remove:async row=>objects.delete(row.id)};
 const env={NODE_ENV:'test',MCP_ENABLED:'true',ASSISTANT_ENABLED:'true',ASSISTANT_OWNER_FUNDING:'true',MCP_PUBLIC_ORIGIN:'http://127.0.0.1',MCP_WEB_ORIGIN:'http://127.0.0.1',RETELL_ENCRYPTION_KEY:randomBytes(32).toString('base64'),FACEBOOK_ADS_ENABLED:'true',FACEBOOK_ADS_WORKER_ENABLED:'false',QUOTE_LINK_SECRET:'synthetic-native-acceptance-secret-at-least-thirty-two-characters',QUOTE_PUBLIC_BASE_URL:'http://127.0.0.1:3000'};
 app.locals.mediaStorage=await installMediaStorage({app,pool,authRequired,bucket,env,startWorker:false});
 app.locals.comms=await installCompanyComms({app,pool,authRequired,startWorker:false});
 app.locals.notes=await installNotes({app,pool,authRequired,env,storage:app.locals.mediaStorage,notifications:app.locals.comms.notifications});
 app.locals.browser=await installBrowser({app,pool,authRequired,env});
 await installIdeaParking({app,pool,authRequired});
 await installFocusSystem({app,pool,authRequired,requireCapability});
 await installRoutineGroupSystem({app,pool,authRequired,requireView:requireCapability('tasks.view'),requireManage:requireCapability('tasks.manage'),emitAutomationEvent});
 await installAutomationSystem({app,pool,authRequired,requireEmployer:requireCapability('automations.manage'),disableProcessors:true});
 app.locals.agreements=await installAgreementSystem({app,pool,authRequired,requireCapability,getQuoteSettings:backend.getQuoteSettings,env,startWorker:false});
 app.locals.agreementBooking=await installAgreementBooking({app,pool,service:app.locals.agreements,authRequired,requireCapability,env,startWorker:false});
 installWidgetDashboard({app,pool,authRequired,services:{getAgreementService:()=>app.locals.agreements}});
 await installFacebookAds({app,pool,authRequired,requireCapability,emitAutomationEvent,env,graph:{configured:()=>false,all:async()=>{throw new Error('No Meta calls in native acceptance fixture');}}});
 await installWebhooks({app,pool,authRequired,emitEvent:emitAutomationEvent,catalog:webhookEventCatalog(),env,startWorker:false,transport:async()=>{throw new Error('No outbound webhook delivery in native acceptance fixture');}});
 await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id,timezone) VALUES($1,'Assistant UI fixture',$2,$3,'America/New_York')",[company,company,user]);
 await pool.query("INSERT INTO users(id,email,display_name,company_id,role,password_hash) VALUES($1,'assistant-fixture@example.invalid','Fixture owner',$3,'employer','not-a-password'),($2,'assistant-staff@example.invalid','Fixture staff',$3,'employee','not-a-password')",[user,staff,company]);
 await pool.query("INSERT INTO employee_permissions(user_id,company_id,permission_preset,permission_overrides) VALUES($1,$2,'manager','{\"ai.use\":true}')",[staff,company]);
 await pool.query('INSERT INTO sessions(token,user_id) VALUES($1,$2),($3,$4)',[token,user,staffToken,staff]);
 await pool.query("INSERT INTO contacts(id,user_id,company_id,name,address,lat,lng) VALUES($1,$2,$3,'Jennifer White — fixture','100 Synthetic Road',38.01,-85.01),($4,$2,$3,'Jennifer Adams — fixture','200 Synthetic Road',38.02,-85.02)",[contact,user,company,secondContact]);
 await installMCP({app,pool,authRequired,env,startMaintenance:false,verifyIdentity:async()=>null});
 const scenarios={};let providerCalls=0;
 const provider={models:async()=>modelCatalog,respond:async(_settings,request,{onText})=>{
  providerCalls++;
  const isHuman=x=>x.role==='user'&&typeof x.content==='string'&&!x.content.startsWith('Untrusted semantic');
  const latest=request.input.filter(isHuman).at(-1)?.content||'';
  const turnStart=request.input.findLastIndex(isHuman);
  const previous=request.input.slice(turnStart+1).filter(x=>x.type==='function_call').at(-1);
  const loaded=new Set((request.tools||[]).map(x=>x.name));
  const call=(name,args)=>({output:[{type:'function_call',call_id:randomUUID(),name,arguments:JSON.stringify(args)}],usage:{input_tokens:100,output_tokens:30}});
  let response='Synthetic fixture response. No paid provider, customer channel or ad mutation was called.';
  let navigation;
  if(/find jennifer/i.test(latest)){
   if(!loaded.has('crm_search'))return call('load_capabilities',{ids:['crm_search']});
   if(previous?.name!=='crm_search')return call('crm_search',{entity:'contacts',query:'Jennifer',limit:5});
   response=`Two contacts match: [Jennifer White](wolfcrm://assistant/contacts/${contact}) and [Jennifer Adams](wolfcrm://assistant/contacts/${secondContact}). Which one do you mean?`;
  }else{
   const scenario=Object.entries(scenarios).find(([key])=>latest.trim().toLowerCase()===key.toLowerCase())?.[1];
   if(scenario)navigation=scenario;
   else if(/open jennifer white/i.test(latest))navigation={route:'contacts',entity:'contacts',id:contact};
   else if(/open tuesday/i.test(latest))navigation={route:'schedule',date:'2026-10-20'};
   else if(/open settings/i.test(latest))navigation={route:'settings'};
   const refresh=/refresh fixture context|native_refresh_context/i.test(latest);
   if(navigation||refresh){
    const name=refresh?'native_refresh_context':'native_navigate';
    if(!loaded.has(name))return call('load_capabilities',{ids:[name]});
    if(previous?.name!==name)return call(name,refresh?{route:'more',action:'refresh_context'}:navigation);
    const output=request.input.filter(x=>x.type==='function_call_output'&&x.call_id===previous.call_id).at(-1);
    const receipt=output?JSON.parse(output.output):null;
    response=receipt?.state==='completed'?(refresh?'The originating app confirmed fresh semantic context.':'The originating app confirmed the destination appeared.'):'The app did not confirm navigation: '+(receipt?.message||receipt?.error||'missing receipt');
   }
  }
  for(const text of response.match(/.{1,24}/g)||[])await onText?.(text);
  return {output:[{type:'message',role:'assistant',content:[{type:'output_text',text:response}]}],usage:{input_tokens:100,output_tokens:30}};
 }};
 assistant=await installAssistant({app,pool,authRequired,env,provider});
 const control=(req,res,next)=>req.get('authorization')==='Bearer '+token?next():res.status(401).json({error:'fixture_owner_required'});
 app.get('/__fixture/reference',(_req,res)=>res.type('html').send('<!doctype html><html><head><title>Fixture reference</title></head><body><h1>Fixture reference</h1><p>Synthetic gutter-cleaning reference for native Browser acceptance.</p></body></html>'));
 app.get('/__fixture/objects/:id',(req,res)=>{const bytes=objects.get(req.params.id);if(!bytes)return res.sendStatus(404);res.type('pdf').send(bytes);});
 app.get('/__fixture/state',control,async(_req,res)=>{try{res.json({external_attempts:externalAttempts,provider_calls:providerCalls,runs:(await pool.query('SELECT id,conversation_id,status,output,error_code,context FROM wolf_assistant_runs WHERE company_id=$1 ORDER BY created_at DESC LIMIT 50',[company])).rows,commands:(await pool.query('SELECT id,run_id,command,state,result FROM wolf_assistant_commands ORDER BY expires_at DESC,id DESC LIMIT 100')).rows});}catch(error){console.error('[fixture-state]',error.code||error.name);res.status(503).json({error:'fixture_state_unavailable'});}});
 server=await new Promise(resolve=>{const s=app.listen(18658,'127.0.0.1',()=>resolve(s));});origin='http://127.0.0.1:'+server.address().port;
 async function http(path,body,method=body===undefined?'GET':'POST',session=token){
  const response=await fetch(origin+path,{method,headers:{authorization:'Bearer '+session,'content-type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});
  const data=response.status===204?null:await response.json();return {status:response.status,data};
 }
 async function ok(path,body,method,session){const result=await http(path,body,method,session);assert.ok(result.status>=200&&result.status<300,path+': '+JSON.stringify(result));return result.data;}
 for(const session of [token,staffToken]){
  const setup=await ok('/api/assistant/setup',{},'POST',session);
  if(session===token)await ok('/api/assistant/funding/allocations/'+staff,{expected_revision:0,enabled:true,monthly_limit_micros:50000000},'PUT');
  if(session===staffToken)await ok('/api/assistant/settings',{expected_revision:1,funding:'personal',api_key:'synthetic-native-fixture-not-a-real-api-key',model:'gpt-6.1-sol',reasoning:'low',instructions:'Synthetic UI fixture.',memory_enabled:true,monthly_limit_micros:50000000},'PUT',session);
  await ok('/api/assistant/settings',{expected_revision:session===staffToken?2:1,funding:'owner',model:'gpt-6.1-sol',reasoning:'low',instructions:'Synthetic UI fixture.',memory_enabled:true,monthly_limit_micros:50000000},'PUT',session);
  // Deliberate test identities receive only read/navigation capabilities. The
  // fixture does not enable provider mutations or credential operations.
  const grants=['assistant_execute','native_navigate','native_refresh_context','crm_search'];
  await pool.query('UPDATE mcp_connections SET tool_policy=$2,revision=revision+1 WHERE id=$1',[setup.settings.connection_id,JSON.stringify(Object.fromEntries(grants.map(id=>[id,{allow:true,approval:false}])))]);
 }
 const createdNote=await ok('/api/notes/pages',{id:note,title:'Fixture acceptance note',visibility:'private'});
 const block=createdNote.blocks[0];
 await ok('/api/notes/pages/'+note+'/blocks',{client_key:randomUUID(),operations:[{id:block.id,type:'paragraph',position:0,parent_id:null,expected_revision:block.revision,payload:{text:'Synthetic note content for assistant navigation and visible field context.'}}]});
 const conversation=await ok('/api/comms/conversations',{client_key:randomUUID(),title:'Fixture acceptance conversation',member_ids:[staff]});
 await ok('/api/comms/conversations/'+conversation.id+'/messages',{client_key:randomUUID(),body:'Synthetic internal fixture message. No customer channel is involved.'});
 const quote=await ok('/api/quotes',{contact_id:contact,title:'Fixture current quote',line_items:[{id:randomUUID(),name:'Fixture gutter cleaning',qty:1,price_cents:12500}],quote_options:{duration_minutes:60}});
 const route=await ok('/api/routes',{name:'Fixture saved route',status:'saved',start_mode:'custom_address',start_label:'Synthetic office',start_latitude:38,start_longitude:-85,ending_behavior:'finish_at_final_stop',stops:[{stop_order:1,name_snapshot:'Jennifer White — fixture',address_snapshot:'100 Synthetic Road',contact_id:contact,latitude:38.01,longitude:-85.01,source_type:'contact',service_duration_seconds:300}]});
 await ok('/api/browser/records/contact/'+contact+'/links',{id:browserLink,url:origin+'/__fixture/reference',title:'Fixture reference'});
 await ok('/api/idea-parking/lists/'+ideaList,{name:'Fixture ideas',visibility:'private',member_ids:[]},'PUT');
 await ok('/api/idea-parking/ideas/'+idea,{text:'Explore a synthetic service package for autumn customers',list_id:ideaList},'PUT');
 await ok('/api/todo/tasks/'+task,{title:'Fixture native task',detail:'Synthetic editable task',priority:'normal',status:'open',completed:false,assignee_ids:[user],subtasks:[],reminders:[],completion_note_required:false},'PUT');
 const document=await PDFDocument.create();document.addPage().drawText('Synthetic native acceptance file');objects.set(file,Buffer.from(await document.save()));
 await pool.query("INSERT INTO stored_files(id,owner_user_id,uploaded_by_user_id,company_id,display_name,original_filename,object_key,mime_type,category,byte_size,cloud_status) VALUES($1,$2,$2,$3,'Fixture acceptance PDF','fixture.pdf',$4,'application/pdf','document',$5,'active')",[file,user,company,'native-fixture/'+file,objects.get(file).length]);
 Object.assign(scenarios,{
  'Open fixture note':{route:'notes',entity:'notes',id:note},
  'Open fixture comms':{route:'comms',entity:'conversations',id:conversation.id},
  'Open fixture browser':{route:'browser',entity:'browser_links',id:'contact:'+contact+':'+browserLink},
  'Open fixture media':{route:'media',entity:'files',id:file,section:'file'},
  'Open fixture quote preview':{route:'quotes',entity:'quotes',id:quote.id,section:'preview'},
  'Open fixture quote editor':{route:'quotes',entity:'quotes',id:quote.id,section:'editor'},
  'Open fixture routes':{route:'routes',entity:'routes',id:route.id},
  'Open fixture focus':{route:'focus',section:'settings'},
  'Open fixture ideas':{route:'ideas'},
  'Open fixture Facebook Ads':{route:'settings',section:'facebook_ads'},
  'Open fixture Webhooks':{route:'settings',section:'webhooks'},
  'Open fixture staff funding':{route:'settings',section:'staff_funding'},
  'Open fixture task':{route:'todo',entity:'tasks',id:task},
 });
 const config={origin,token,company,user,staff,staffToken,pgSocket:pg.config.host,contact,secondContact,note,conversation:conversation.id,browserLink,browserCard:'contact:'+contact+':'+browserLink,file,quote:quote.id,route:route.id,task,ideaList,idea,scenarios};
 await writeFile('/tmp/wolf-assistant-fixture.json',JSON.stringify(config),{mode:0o600});
 await chmod('/tmp/wolf-assistant-fixture.json',0o600);
 if(process.argv.includes('--self-check')){
  const controlReport=await ok('/__fixture/state');assert.equal(controlReport.external_attempts,0);assert.ok(Array.isArray(controlReport.commands));
  for(const path of ['/me','/api/comms/bootstrap','/api/comms/notifications','/api/notes/pages/'+note,'/api/browser/capabilities','/api/browser/records/contact/'+contact+'/links','/api/storage/files/'+file,'/api/focus/settings','/api/focus/capabilities','/api/focus/creators','/api/todo/tasks','/api/todo/routine-groups','/api/todo/routine-runs','/api/idea-parking/lists','/api/routes/'+route.id,'/api/quotes?contact_id='+contact,'/api/agreements/settings','/api/schedule/booking/settings','/api/facebook-ads','/api/facebook-ads/catalog','/api/webhook-connections','/api/assistant/funding/allocations'])await ok(path);
  assert.equal((await http('/api/storage/files/'+file,undefined,'GET',staffToken)).status,404,'staff cannot open owner private file');
  assert.ok([403,404].includes((await http('/api/notes/pages/'+note,undefined,'GET',staffToken)).status),'staff cannot open owner private note');
  assert.equal((await http('/api/assistant/funding/allocations',undefined,'GET',staffToken)).status,403,'staff cannot allocate owner funding');
  const status=await ok('/api/assistant/status',undefined,'GET',staffToken);assert.equal(status.owner_funding.available,true);assert.equal(status.can_allocate_funding,false);assert.equal(status.settings.key_configured,true);assert.equal(status.settings.funding,'owner');
  const personal=(await pool.query('SELECT key_ciphertext FROM wolf_assistant_settings WHERE company_id=$1 AND user_id=$2',[company,staff])).rows[0];assert.ok(personal.key_ciphertext&&!personal.key_ciphertext.includes('synthetic-native-fixture'));
  const wait=async(runID,state)=>{const deadline=Date.now()+15000;while(Date.now()<deadline){await assistant.tick();const row=await ok('/api/assistant/runs/'+runID);if(row.status===state)return row;if(['completed','failed','interrupted','cancelled'].includes(row.status))throw new Error(JSON.stringify({row,steps:(await pool.query('SELECT tool,state,result FROM wolf_assistant_steps WHERE run_id=$1',[runID])).rows}));await new Promise(r=>setTimeout(r,100));}throw new Error('Fixture acknowledgement timeout: '+runID+' → '+state);};
  for(const [prompt,target] of [...Object.entries(scenarios),['Refresh fixture context',{route:'contacts',entity:'contacts',id:contact}]]){
   await pool.query('DELETE FROM mcp_rate_limits');
   const device=randomUUID(),scene=randomUUID(),initial={device_id:device,scene_id:scene,module:'dashboard',screen:'dashboard',timestamp:new Date().toISOString()};
   const chat=await ok('/api/assistant/conversations',{title:prompt});
   const queued=await ok('/api/assistant/runs',{conversation_id:chat.id,request_key:randomUUID(),text:prompt,context:initial});
   const waiting=await wait(queued.id,'waiting_client');assert.ok(!waiting.output,'no successful navigation text before acknowledgement');
   const command=(await ok('/api/assistant/commands?device_id='+device+'&scene_id='+scene)).items[0];assert.ok(command,prompt);
   const context={...initial,module:target.route,screen:'fixture.acknowledged',references:target.id?[{entity:target.entity,id:target.id}]:[],...(target.section?{section:target.section}:{}),state:'ready',labels:{fixture:'Fixture field'},fields:['fixture'],filters:{scope:'synthetic'},provenance:{source:'Simulated backend self-check acknowledgement; actual native UI validation is separate'}};
   if(prompt!=='Refresh fixture context'){const mismatch=await http('/api/assistant/commands/'+command.id+'/ack',{device_id:device,scene_id:scene,state:'completed',message:'Wrong destination',context:{...context,module:'dashboard'}});assert.equal(mismatch.status,409,prompt);}
   const bad=await http('/api/assistant/commands/'+command.id+'/ack',{device_id:randomUUID(),scene_id:scene,state:'completed',message:'Wrong originating device',context});assert.equal(bad.status,409,prompt);
   await ok('/api/assistant/commands/'+command.id+'/ack',{device_id:device,scene_id:scene,state:'completed',message:'Simulated fixture self-check acknowledgement; not native UI evidence',context});
   const completed=await wait(queued.id,'completed');assert.match(completed.output,/originating app confirmed/);assert.equal(completed.context,undefined);
   const saved=(await pool.query('SELECT context FROM wolf_assistant_runs WHERE id=$1',[queued.id])).rows[0];assert.equal(saved.context.provenance.source,context.provenance.source);
   console.log(JSON.stringify({simulated_ack:prompt,status:'PASS'}));
  }
  assert.equal(externalAttempts,0);
  console.log(JSON.stringify({self_check:'PASS',startup_and_acl_checks:true,simulated_acknowledgement_scenarios:Object.keys(scenarios).length+1,actual_native_ui_checked:false,external_attempts:externalAttempts,origin}));
 }
 console.log(JSON.stringify({fixture:'ready',origin,config:'/tmp/wolf-assistant-fixture.json',scenario_count:Object.keys(scenarios).length}));
 if(process.argv.includes('--exit-after-check'))await stop();
 setTimeout(()=>void stop(),45*60*1000).unref();
}catch(error){console.error('[assistant-native-fixture]',error);await stop(1);}
