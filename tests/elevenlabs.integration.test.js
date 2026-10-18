import test from 'node:test';
import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
import assert from 'node:assert/strict';
import {randomUUID,randomBytes,createHmac} from 'node:crypto';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {installMCP} from '../mcp/index.js';
import {installAgreementBookingSchema} from '../agreement-booking.js';
import {installGoogleSheetsSchema} from '../google-sheets.js';
import {installAutomationSystem} from '../automations.js';

test('ElevenLabs signed durable reporting, native manager and two-company isolation',{timeout:180000},async t=>{
 const pg=startLocalPostgres();pg.configureEnvironment();let backend,server;
 try{
  backend=await import('../index.js');await backend.bootstrap();const {app,pool,authRequired}=backend;
  await installAgreementBookingSchema(pool);await installGoogleSheetsSchema(pool);await installAutomationSystem({app,pool,authRequired,requireEmployer:(_r,_s,n)=>n(),disableProcessors:true});
  const a=randomUUID(),b=randomUUID(),owner=randomUUID(),other=randomUUID(),employee=randomUUID(),lead=randomUUID(),foreign=randomUUID();
  await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id) VALUES($1,'Eleven QA A','ELVA',$3),($2,'Eleven QA B','ELVB',$4)",[a,b,owner,other]);
  for(const [id,cid,role]of [[owner,a,'employer'],[other,b,'employer'],[employee,a,'employee']]){await pool.query('INSERT INTO users(id,email,display_name,company_id,role) VALUES($1,$2,$3,$4,$5)',[id,id+'@example.invalid','QA',cid,role]);await pool.query('INSERT INTO sessions(token,user_id) VALUES($1,$2)',[id,id]);}
  for(const [id,cid,uid]of [[lead,a,owner],[foreign,b,other]])await pool.query("INSERT INTO contacts(id,company_id,user_id,name,phone) VALUES($1,$2,$3,'Synthetic QA','+12025550199')",[id,cid,uid]);
  server=await new Promise(r=>{const s=app.listen(0,'127.0.0.1',()=>r(s));});const origin='http://127.0.0.1:'+server.address().port;
  const env={MCP_ENABLED:'true',MCP_PUBLIC_ORIGIN:origin,MCP_WEB_ORIGIN:origin,MCP_REDIRECT_URIS:'["https://example.invalid/callback"]',RETELL_ENCRYPTION_KEY:randomBytes(32).toString('base64'),NODE_ENV:'test'};
  await installMCP({app,pool,authRequired,env,startMaintenance:false,verifyIdentity:async()=>null});
  const http=async(path,method='GET',body,user=owner,extra={})=>{const r=await fetch(origin+path,{method,headers:{Authorization:'Bearer '+user,'Content-Type':'application/json',...extra},body:body===undefined?undefined:JSON.stringify(body)});return {status:r.status,body:await r.json()};};
  const root='/api/ai-connections/manager';
  const c=(await http(root,'POST',{expected_company_id:a,name:'Jack',description:'QA',provider:'ElevenLabs'})).body;
  let revision=c.revision;const guard=()=>({expected_company_id:a,expected_revision:revision});
  const refresh=async()=>revision=(await http(root)).body.connections.find(x=>x.id===c.id).revision;
  const issued=await http(root+'/'+c.id+'/key','POST',{...guard(),valid_days:1});assert.equal(issued.status,200);await refresh();
  const path=root+'/'+c.id+'/elevenlabs',secret=randomBytes(32).toString('hex'),agent='agent_isolated_qa';
  const configure=async(data={})=>{const r=await http(path,'PUT',{...guard(),agent_id:agent,enabled:true,...data});if(r.status===200)await refresh();return r;};
  const event=(conv='conv_'+randomUUID(),leadID=lead,analysis={})=>({type:'post_call_transcription',event_timestamp:Math.floor(Date.now()/1000),data:{agent_id:agent,conversation_id:conv,metadata:{start_time_unix_secs:Math.floor(Date.now()/1000)-20,call_duration_secs:20,phone_call:null},conversation_initiation_client_data:{dynamic_variables:{lead_id:leadID,wolf_connection_id:c.id}},analysis:{call_successful:'success',transcript_summary:'Customer asked for two options. Untrusted test text.',data_collection_results:Object.fromEntries(Object.entries(analysis).map(([k,value])=>[k,{value,rationale:'QA'}]))},transcript:[{message:'NEVER STORE RAW TRANSCRIPT'}]}});
  const deliver=async(e,{key=secret,timestamp=Math.floor(Date.now()/1000),signature,connection=c.id}={})=>{const raw=JSON.stringify(e),sig=signature??`t=${timestamp},v0=${createHmac('sha256',key).update(`${timestamp}.${raw}`).digest('hex')}`;const r=await fetch(origin+'/elevenlabs/webhook/'+connection,{method:'POST',headers:{'Content-Type':'application/json','ElevenLabs-Signature':sig},body:raw});return {status:r.status,body:await r.json()};};
  const drain=()=>app.locals.elevenlabsReporting.drain();
  const stored=async conv=>(await pool.query('SELECT * FROM elevenlabs_call_events WHERE conversation_id=$1',[conv])).rows[0];
  await t.test('owner UI configuration, encrypted write-only secret, revision and cross-company guards',async()=>{
   assert.equal((await http(path,'GET',undefined,employee)).status,403);assert.equal((await http(path,'GET',undefined,other)).status,404);
   assert.equal((await configure()).body.error,'webhook_secret_required');assert.equal((await configure({webhook_secret:secret})).status,200);
   const state=(await http(path)).body;assert.equal(state.enabled,true);assert.equal(state.secret_configured,true);assert.ok(!JSON.stringify(state).includes(secret));assert.ok(!JSON.stringify((await http(root)).body).includes(secret));
   assert.notEqual((await pool.query('SELECT secret_ciphertext FROM elevenlabs_reporting WHERE connection_id=$1',[c.id])).rows[0].secret_ciphertext,secret);
   assert.equal((await http(path,'PUT',{...guard(),expected_revision:1,agent_id:agent,enabled:false})).status,409);
   assert.equal((await http(path,'PUT',{...guard(),agent_id:agent,enabled:false},owner,{Origin:'https://evil.invalid'})).status,403);
   assert.equal((await http(path,'GET',undefined,issued.body.authorization.slice(7))).status,401);
  });
  await t.test('official HMAC verifier, wrong agent/route, tampering, old/future timestamps',async()=>{
   const e=event();assert.equal((await deliver(e,{key:'wrong-key'})).status,401);assert.equal((await deliver(e,{timestamp:Math.floor(Date.now()/1000)-1900})).status,401);assert.equal((await deliver(e,{timestamp:Math.floor(Date.now()/1000)+120})).status,401);
   assert.equal((await deliver(e,{signature:'t=NaN,v0=oops'})).status,401);assert.equal((await deliver(e,{connection:randomUUID()})).status,401);
   e.data.agent_id='another-agent';assert.equal((await deliver(e)).status,403);e.data.agent_id=agent;e.data.conversation_initiation_client_data.dynamic_variables.wolf_connection_id=randomUUID();assert.equal((await deliver(e)).status,403);
  });
  await t.test('duplicate deliveries complete once; claims do not create appointments or sent quotes',async()=>{
   const e=event(undefined,lead,{call_outcome:'booked_and_sent',appointment_status:'confirmed',appointment_id:randomUUID(),quote_id:randomUUID(),customer_requests:'Inside and outside plus exterior-only alternative'});
   const pair=await Promise.all([deliver(e),deliver(e)]);assert.ok(pair.every(x=>x.status===200),JSON.stringify(pair));await drain();
   let row=await stored(e.data.conversation_id);assert.equal(row.state,'completed',row.error_code);assert.equal(row.report.appointment_status,'unverified');assert.deepEqual(row.report.verified_quotes,[]);assert.deepEqual(row.report.verified_appointments,[]);assert.deepEqual(row.payload,{});assert.equal(row.report.customer_requests,'Inside and outside plus exterior-only alternative');
   assert.equal((await deliver(e)).status,200);await drain();assert.equal((await pool.query("SELECT count(*)::int n FROM phone_calls WHERE provider='elevenlabs'")).rows[0].n,1);assert.equal((await pool.query('SELECT lead_info FROM contacts WHERE id=$1',[lead])).rows[0].lead_info.length,1);
   const conflict=structuredClone(e);conflict.data.analysis.transcript_summary='changed';assert.equal((await deliver(conflict)).status,409);
   assert.equal((await pool.query('SELECT count(*)::int n FROM schedule_events')).rows[0].n,0);assert.ok(!JSON.stringify(await stored(e.data.conversation_id)).includes('NEVER STORE RAW TRANSCRIPT'));
  });
  await t.test('missing, invalid and guessed foreign contact IDs never fall back to matching phone',async()=>{
   for(const id of ['', 'not-a-uuid',foreign]){const e=event(undefined,id);e.data.metadata.phone_call={direction:'inbound',external_number:'+12025550199',agent_number:'+12025550101'};assert.equal((await deliver(e)).status,200);await drain();const row=await stored(e.data.conversation_id);assert.equal(row.state,'review_required');assert.equal(row.error_code,'lead_unavailable');assert.equal(row.contact_id,null);assert.equal((await http(path+'/events/'+row.id+'/retry','POST',{expected_company_id:b,expected_revision:1},other)).status,404);}
   assert.equal((await pool.query('SELECT lead_info FROM contacts WHERE id=$1',[foreign])).rows[0].lead_info,null);assert.equal((await pool.query("SELECT count(*)::int n FROM phone_calls WHERE provider='elevenlabs'")).rows[0].n,1);
  });
  await t.test('verify saved quotes and this connection booking receipts against company AND contact',async()=>{
   const quote=randomUUID(),foreignQuote=randomUUID(),appointment=randomUUID(),wrongContactAppointment=randomUUID();
   for(const [id,cid,contact,uid] of [[quote,a,lead,owner],[foreignQuote,b,foreign,other]])await pool.query("INSERT INTO quotes(id,user_id,company_id,contact_id,title,line_items,total_cents,status) VALUES($1,$2,$3,$4,'QA option','[]',0,'draft')",[id,uid,cid,contact]);
   for(const [id,contact] of [[appointment,lead],[wrongContactAppointment,foreign]])await pool.query("INSERT INTO schedule_events(id,company_id,user_id,title,start_at,end_at,contact_id) VALUES($1,$2,$3,'QA visit',now(),now()+interval '15 minutes',$4)",[id,a,owner,contact]);
   const e=event(undefined,lead,{quote_ids:[quote,foreignQuote],appointment_id:appointment,appointment_status:'confirmed'});
   await pool.query("INSERT INTO retell_requests(id,connection_id,request_key,input_hash,payload,result) VALUES($1,$2,$3,'qa','{}',$4)",[randomUUID(),c.id,e.data.conversation_id,JSON.stringify({status:'confirmed',appointment_id:appointment})]);
   assert.equal((await deliver(e)).status,200);await drain();const report=(await stored(e.data.conversation_id)).report;assert.equal(report.verified_quotes.length,1);assert.equal(report.verified_quotes[0].sent_at,null);assert.equal(report.verified_appointments.length,1);assert.equal(report.appointment_status,'confirmed');
   const bad=event(undefined,lead,{appointment_id:wrongContactAppointment});await pool.query("INSERT INTO retell_requests(id,connection_id,request_key,input_hash,payload,result) VALUES($1,$2,$3,'qa','{}',$4)",[randomUUID(),c.id,bad.data.conversation_id,JSON.stringify({status:'confirmed',appointment_id:wrongContactAppointment})]);await deliver(bad);await drain();assert.equal((await stored(bad.data.conversation_id)).report.appointment_status,'unverified');
  });
  await t.test('transaction rollback and durable retry do not duplicate call or lead history',async()=>{
   await pool.query("CREATE FUNCTION qa_report_fail() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'isolated failure'; END$$; CREATE TRIGGER qa_report_fail BEFORE UPDATE ON contacts FOR EACH ROW EXECUTE FUNCTION qa_report_fail()");
   const e=event();assert.equal((await deliver(e)).status,200);await drain();let row=await stored(e.data.conversation_id);assert.equal(row.state,'queued');assert.equal(row.attempts,1);assert.equal((await pool.query('SELECT count(*)::int n FROM phone_calls WHERE provider_call_id=$1',[e.data.conversation_id])).rows[0].n,0);
   await pool.query('DROP TRIGGER qa_report_fail ON contacts; DROP FUNCTION qa_report_fail()');await pool.query('UPDATE elevenlabs_call_events SET next_attempt_at=now() WHERE id=$1',[row.id]);await drain();row=await stored(e.data.conversation_id);assert.equal(row.state,'completed');assert.equal((await pool.query('SELECT count(*)::int n FROM phone_calls WHERE provider_call_id=$1',[e.data.conversation_id])).rows[0].n,1);
  });
  await t.test('real MCP 15-minute visit, retry, conflict and receipt-verified report',async()=>{
   const current=(await http(root)).body.connections.find(x=>x.id===c.id);
   const config={...current.booking_config,quote_enabled:true,automatic_booking:true,quote_duration_minutes:15,postal_codes:['10001'],quote_weekdays:[1,2,3,4,5,6,7],quote_start:'08:00',quote_end:'18:00',minimum_notice_minutes:0,horizon_days:30,start_increment_minutes:15,buffer_before_minutes:0,buffer_after_minutes:0,quote_worker_ids:[owner]};
   const changed=await http(root+'/'+c.id,'PUT',{...guard(),name:current.name,description:current.description,provider:current.provider,enabled:true,paused_until:null,operating_hours:null,automatic_booking:true,booking_config:config,tool_policy:{check_quote_availability:{allow:true,approval:false},create_appointment:{allow:true,approval:false}}});assert.equal(changed.status,200,JSON.stringify(changed.body));await refresh();
   const client=new Client({name:'Jack isolated reporting QA',version:'1'});try{
    await client.connect(new StreamableHTTPClientTransport(new URL(origin+'/mcp'),{requestInit:{headers:{Authorization:issued.body.authorization}}}));assert.equal((await client.listTools()).tools.length,2);
    const call=async(name,args)=>(await client.callTool({name,arguments:args})).structuredContent;
    const day=new Date(Date.now()+2*86400000).toISOString().slice(0,10),address='100 Synthetic Street NY 10001';
    const available=await call('check_quote_availability',{lead_id:lead,address,preferred_date_range:{start:day+'T08:00:00-04:00',end:day+'T10:00:00-04:00'}});assert.equal(available.booking_enabled,true);assert.ok(available.slots.length);
    const e=event(),slot=available.slots[0],input={type:'quote',slot_id:slot.slot_id,lead_id:lead,customer:{name:'Synthetic QA',phone:'+12025550199'},address,services:[],notes:'Isolated QA only',idempotency_key:e.data.conversation_id};
    const result=await call('create_appointment',input);assert.equal(result.status,'confirmed');assert.equal(new Date(result.end)-new Date(result.start),15*60000);assert.deepEqual(await call('create_appointment',input),result);
    assert.equal((await call('create_appointment',{...input,idempotency_key:'conflict_'+randomUUID()})).status,'failed');
    await deliver(e);await drain();const report=(await stored(e.data.conversation_id)).report;assert.equal(report.appointment_status,'confirmed');assert.equal(report.verified_appointments[0].id,result.appointment_id);
   }finally{await client.close();}
  });
  await t.test('current capability denial, deleted contacts, failure-event safety and retention',async()=>{
   await pool.query("INSERT INTO employee_permissions(user_id,company_id,permission_preset,permission_overrides) VALUES($1,$2,'admin','{\"quotes.view\":false}')",[employee,a]);
   await pool.query('UPDATE retell_connections SET user_id=$2 WHERE id=$1',[c.id,employee]);await pool.query('UPDATE mcp_connections SET user_id=$2 WHERE id=$1',[c.id,employee]);
   assert.equal((await deliver(event())).status,403);assert.equal((await http(path,'GET',undefined,employee)).status,403);
   await pool.query('UPDATE retell_connections SET user_id=$2 WHERE id=$1',[c.id,owner]);await pool.query('UPDATE mcp_connections SET user_id=$2 WHERE id=$1',[c.id,owner]);
   const deleted=event();await pool.query('UPDATE contacts SET deleted_at=now() WHERE id=$1',[lead]);await deliver(deleted);await drain();assert.equal((await stored(deleted.data.conversation_id)).error_code,'lead_unavailable');await pool.query('UPDATE contacts SET deleted_at=NULL WHERE id=$1',[lead]);
   const failure={type:'call_initiation_failure',event_timestamp:Math.floor(Date.now()/1000),data:{agent_id:agent,conversation_id:'failure_'+randomUUID(),failure_reason:'no-answer',metadata:{type:'twilio',body:{To:'+12025550199'}}}};
   assert.equal((await deliver(failure)).status,200);await drain();assert.equal((await stored(failure.data.conversation_id)).state,'review_required');assert.equal((await stored(failure.data.conversation_id)).phone_call_id,null);
   await pool.query("UPDATE elevenlabs_call_events SET created_at=now()-interval '31 days' WHERE conversation_id=$1",[failure.data.conversation_id]);await drain();assert.equal((await stored(failure.data.conversation_id)).state,'expired');assert.deepEqual((await stored(failure.data.conversation_id)).payload,{});
  });
  await t.test('membership, key expiry, revocation, pauses, disable and queued authorization rechecks',async()=>{
   const e=event();await deliver(e);await pool.query('UPDATE mcp_connections SET enabled=false WHERE id=$1',[c.id]);await drain();assert.equal((await stored(e.data.conversation_id)).state,'blocked');assert.equal((await deliver(event())).status,403);
   await pool.query('UPDATE mcp_connections SET enabled=true WHERE id=$1',[c.id]);const blocked=await stored(e.data.conversation_id);assert.equal((await http(path+'/events/'+blocked.id+'/retry','POST',guard())).status,200);await refresh();await drain();assert.equal((await stored(e.data.conversation_id)).state,'completed');
   await pool.query("UPDATE retell_connections SET expires_at=now()-interval '1 second' WHERE id=$1",[c.id]);assert.equal((await deliver(event())).status,401);await pool.query("UPDATE retell_connections SET expires_at=now()+interval '1 day' WHERE id=$1",[c.id]);
   await pool.query('UPDATE users SET company_id=$2 WHERE id=$1',[owner,b]);assert.equal((await deliver(event())).status,401);await pool.query('UPDATE users SET company_id=$2 WHERE id=$1',[owner,a]);
   await pool.query("UPDATE mcp_connections SET paused_until=now()+interval '1 hour' WHERE id=$1",[c.id]);assert.equal((await deliver(event())).status,403);await pool.query('UPDATE mcp_connections SET paused_until=NULL WHERE id=$1',[c.id]);
   env.MCP_ENABLED='false';assert.equal((await deliver(event())).status,503);env.MCP_ENABLED='true';
   await pool.query('UPDATE retell_connections SET revoked_at=now() WHERE id=$1',[c.id]);assert.equal((await deliver(event())).status,401);
  });
 }finally{if(server)await new Promise(r=>server.close(r));if(backend)await backend.pool.end();pg.stop();}
});
