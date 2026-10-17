import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,randomBytes,createHmac} from 'node:crypto';
import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {installMCP} from '../mcp/index.js';
import {installAgreementSchema,createAgreementService} from '../quote-agreements.js';
import {installAgreementPaymentSchema} from '../agreement-payments.js';
import {installAgreementBooking,normalizeBookingSettings,installAgreementBookingSchema} from '../agreement-booking.js';
import {installGoogleSheetsSchema} from '../google-sheets.js';
import {installAutomationSystem} from '../automations.js';
import {installRetell} from '../retell/index.js';
import {configSchema,offsetISO} from '../retell/config.js';
import {encrypt,decrypt} from '../retell/security.js';

test('Retell service credentials, isolated bookings and signed durable reporting',{timeout:180000},async t=>{
 const pg=startLocalPostgres();pg.configureEnvironment();let backend,server;const clients=[];
 try{
  backend=await import('../index.js');const {app,pool,authRequired}=backend;await backend.bootstrap();await installAgreementBookingSchema(pool);await installGoogleSheetsSchema(pool);
  await installAutomationSystem({app,pool,authRequired,requireEmployer:(_r,_s,n)=>n(),disableProcessors:true});
  const a=randomUUID(),b=randomUUID(),owner=randomUUID(),other=randomUUID(),worker=randomUUID();
  await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id,timezone) VALUES($1,'Retell QA A','RTA',$3,'America/New_York'),($2,'Retell QA B','RTB',$4,'America/New_York')",[a,b,owner,other]);
  for(const [id,company,role]of [[owner,a,'employer'],[other,b,'employer'],[worker,a,'employee']])await pool.query('INSERT INTO users(id,email,display_name,company_id,role) VALUES($1,$2,$3,$4,$5)',[id,id+'@example.invalid','QA '+role,company,role]);
  await pool.query("INSERT INTO sessions(token,user_id) VALUES('rt-owner',$1),('rt-other',$2),('rt-worker',$3)",[owner,other,worker]);
  server=await new Promise(r=>{const s=app.listen(0,'127.0.0.1',()=>r(s));});const origin='http://127.0.0.1:'+server.address().port;
  const env={MCP_ENABLED:'true',RETELL_ENABLED:'true',RETELL_ENCRYPTION_KEY:randomBytes(32).toString('base64'),MCP_PUBLIC_ORIGIN:origin,MCP_WEB_ORIGIN:'https://crm.example.invalid',MCP_REDIRECT_URIS:'["https://client.example.invalid/callback"]',NODE_ENV:'test'};
  await installMCP({app,pool,authRequired,env,startMaintenance:false,verifyIdentity:async()=>null});
  const request=async(path,method='GET',body,token='rt-owner')=>{const r=await fetch(origin+path,{method,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});return {status:r.status,body:await r.json()};};
  const settings=async()=> (await request('/api/ai-connections/retell')).body;
  const mutate=async(path,body={},method='POST',token='rt-owner')=>{const s=(await request('/api/ai-connections/retell','GET',undefined,token)).body;return request('/api/ai-connections/retell'+path,method,{expected_company_id:s.company_id,expected_revision:s.revision,...body},token);};
  const key=(await mutate('/key',{valid_days:30})).body.key;assert.ok(key?.startsWith('wolf_retell_'));
  const connect=async key=>{const c=new Client({name:'Riley QA',version:'1'});await c.connect(new StreamableHTTPClientTransport(new URL(origin+'/mcp'),{requestInit:{headers:{Authorization:'Bearer '+key}}}));clients.push(c);return c;};
  const client=await connect(key),call=async(name,input)=>{const r=await client.callTool({name,arguments:input});return r.structuredContent||JSON.parse(r.content[0].text);};
  const date=new Date(Date.now()+2*86400000).toISOString().slice(0,10),range={start:date+'T08:00:00-04:00',end:date+'T18:00:00-04:00'},addr='100 Test Street, Testville NY 10001';
  const available=()=>call('check_quote_availability',{address:addr,preferred_date_range:range});
  let slot,appointment,input;
  await t.test('three service-only tools, no CRM or financial tool access; settings owner only',async()=>{
   assert.deepEqual((await client.listTools()).tools.map(x=>x.name).sort(),['check_job_availability','check_quote_availability','create_appointment']);
   assert.equal((await request('/api/ai-connections/retell','GET',undefined,'rt-worker')).status,403);
   assert.equal((await available()).booking_enabled,false);
   await assert.rejects(()=>client.callTool({name:'crm_search',arguments:{entity:'contacts'}}));
   assert.ok(!JSON.stringify(await settings()).includes(key));
   const encrypted=encrypt('private-provider-key',a,env);assert.equal(decrypt(encrypted,a,env),'private-provider-key');assert.throws(()=>decrypt(encrypted,b,env));
  });
  const config=configSchema.parse({quote_enabled:true,postal_codes:['10001'],quote_weekdays:[1,2,3,4,5,6,7],quote_start:'08:00',quote_end:'18:00',quote_duration_minutes:30,minimum_notice_minutes:0,horizon_days:30,start_increment_minutes:30,buffer_before_minutes:15,buffer_after_minutes:15,quote_worker_ids:[worker]});
  await t.test('explicit settings, expiry offsets, service area and scope-bound slots',async()=>{
   assert.equal((await mutate('',{agent_id:'agent-test',webhook_api_key:'test-provider-webhook-key',config},'PUT')).status,200);
   const value=await available();assert.equal(value.booking_enabled,true);assert.ok(value.slots.length>0);slot=value.slots[0];assert.match(slot.start,/-0[45]:00$/);assert.ok(JSON.stringify(value).length<15000);
   assert.equal((await call('check_quote_availability',{address:'Elsewhere NY 99999',preferred_date_range:range})).in_service_area,false);
   const s=await settings();assert.equal(s.webhook_key_configured,true);assert.ok(!JSON.stringify(s).includes('test-provider-webhook-key'));
  });
  await t.test('automatic booking requires explicit owner authorization; retry returns original request',async()=>{
   input={type:'quote',slot_id:slot.slot_id,customer:{name:'Isolated QA',phone:'+12025550111'},address:addr,services:[],notes:'QA',idempotency_key:'call-pending'};
   const first=await call('create_appointment',input);assert.equal(first.status,'pending_approval');assert.deepEqual(await call('create_appointment',input),first);
   assert.equal((await pool.query('SELECT count(*)::int n FROM schedule_events WHERE company_id=$1',[a])).rows[0].n,0);
   config.automatic_booking=true;assert.equal((await mutate('',{agent_id:'agent-test',config},'PUT')).status,200);
   assert.equal((await call('create_appointment',{...input,idempotency_key:'old-slot'})).status,'failed');
  });
  await t.test('atomic canonical booking and retry; travel padding blocks overlap',async()=>{
   slot=(await available()).slots[0];input={...input,slot_id:slot.slot_id,idempotency_key:'call-book'};
   const results=await Promise.all([call('create_appointment',input),call('create_appointment',input)]);
   assert.equal(results[0].status,'confirmed',JSON.stringify(results));assert.deepEqual(results[0],results[1]);appointment=results[0].appointment_id;
   assert.equal((await call('create_appointment',{...input,notes:'changed'})).reason,'idempotency_conflict');
   assert.equal((await call('create_appointment',{...input,idempotency_key:'call-race'})).status,'failed');
   const saved=(await pool.query('SELECT * FROM schedule_events WHERE id=$1',[appointment])).rows[0];assert.equal(saved.booking_buffer_before_minutes,15);
   assert.ok(!(await available()).slots.some(s=>s.start===slot.start));
  });
  await t.test('cross-company lead and slot IDs fail; missing job agreement never confirms',async()=>{
   const foreign=randomUUID();await pool.query("INSERT INTO contacts(id,user_id,company_id,name,phone,address) VALUES($1,$2,$3,'Foreign QA','+12025550111',$4)",[foreign,other,b,addr]);
   assert.equal((await call('create_appointment',{...input,lead_id:foreign,idempotency_key:'guessed-lead'})).reason,'lead_unavailable');
   const keyB=(await mutate('/key',{valid_days:30},'POST','rt-other')).body.key;assert.equal((await mutate('',{agent_id:'agent-other',config:{...config,quote_worker_ids:[other]}},'PUT','rt-other')).status,200);const cb=await connect(keyB);
   const r=await cb.callTool({name:'create_appointment',arguments:{...input,idempotency_key:'other-company'}});assert.equal(r.structuredContent?.status,'failed');
   assert.equal((await request('/api/contacts','GET',undefined,key)).status,401);
   const job=await call('check_job_availability',{address:addr,services:['Window cleaning'],preferred_date_range:range});assert.equal(job.booking_enabled,false);assert.equal(job.estimated_duration_min,null);
  });
  await t.test('job path uses canonical acceptance, payment, duration and booking review',async()=>{
   await installAgreementSchema(pool);await installAgreementPaymentSchema(pool);
   const service=createAgreementService({pool,env:{QUOTE_LINK_SECRET:'isolated-retell-signing-secret-over-32-characters',QUOTE_PUBLIC_BASE_URL:'https://example.invalid'}});app.locals.agreements=service;
   await installAgreementBooking({app,pool,service,authRequired,requireCapability:backend.requireCapability,startWorker:false});
   const bookingSettings=normalizeBookingSettings({enabled:true,minimum_notice_minutes:0,horizon_days:30,start_increment_minutes:30,buffer_before_minutes:15,buffer_after_minutes:15,resource_bundles:[{id:randomUUID(),name:'QA crew',worker_user_ids:[worker],all_services:true,service_ids:[],enabled:true}]});
   await pool.query("UPDATE companies SET customer_booking_settings=$2,business_days='[1,2,3,4,5,6,7]',business_open_time='08:00',business_close_time='18:00' WHERE id=$1",[a,JSON.stringify(bookingSettings)]);
   config.job_enabled=true;config.job_rules_acknowledged=true;assert.equal((await mutate('',{agent_id:'agent-test',config},'PUT')).status,200);
   const contact=(await pool.query('SELECT contact_id FROM schedule_events WHERE id=$1',[appointment])).rows[0].contact_id;
   const quote=randomUUID(),agreement=randomUUID(),line={id:randomUUID(),service_id:null,name:'Windows',description:'QA',qty:1,price_cents:20000};
   await pool.query('INSERT INTO quotes(id,user_id,company_id,contact_id,line_items,total_cents) VALUES($1,$2,$3,$4,$5,20000)',[quote,owner,a,contact,JSON.stringify([line])]);
   const snapshot={required_signers:['customer'],allow_customer_booking:true,duration_minutes:90,pricing:{line_items:[line],total_cents:20000,deposit_cents:1000},documents:[]};
   await pool.query("INSERT INTO quote_agreements(id,company_id,quote_id,contact_id,created_by,number,revision,request_id,title,snapshot,packet_hash) VALUES($1,$2,$3,$4,$5,'RT-QA',1,$6,'QA windows',$7,'qa-packet')",[agreement,a,quote,contact,owner,randomUUID(),JSON.stringify(snapshot)]);
   const args={address:addr,services:['Windows'],lead_id:contact,preferred_date_range:range};
   let value=await call('check_job_availability',args);assert.equal(value.booking_enabled,false);assert.equal(value.estimated_duration_min,90);assert.equal(value.requires_deposit,true);
   const session=randomUUID();await pool.query("INSERT INTO agreement_signing_sessions(id,agreement_id,role,token_hash,token_generation,expires_at,verification_method) VALUES($1,$2,'customer',$3,1,now()+interval '1 day','link')",[session,agreement,randomUUID()]);
   await pool.query("INSERT INTO agreement_signatures(id,agreement_id,session_id,role,request_id,request_hash,printed_name,consent_text,signature,field_values,packet_hash,verification_method,submitted_at) VALUES($1,$2,$3,'customer',$4,'fixture','QA','Consent','{}','{}','qa-packet','link',now())",[randomUUID(),agreement,session,randomUUID()]);
   assert.equal((await call('check_job_availability',args)).booking_enabled,false);
   await pool.query("INSERT INTO payment_records(id,company_id,agreement_id,contact_id,user_id,amount_cents,currency,status) VALUES($1,$2,$3,$4,$5,1000,'usd','succeeded')",[randomUUID(),a,agreement,contact,owner]);
   value=await call('check_job_availability',args);assert.equal(value.booking_enabled,true,JSON.stringify(value));assert.ok(value.slots.length);
   await pool.query("UPDATE payment_records SET status='processing' WHERE agreement_id=$1",[agreement]);
   const pending=await call('create_appointment',{...input,type:'job',lead_id:contact,services:['Windows'],slot_id:value.slots[0].slot_id,idempotency_key:'deposit-changed'});assert.equal(pending.status,'pending_approval');
   assert.equal((await pool.query('SELECT count(*)::int n FROM agreement_bookings WHERE agreement_id=$1',[agreement])).rows[0].n,0);
   await pool.query("UPDATE payment_records SET status='succeeded' WHERE agreement_id=$1",[agreement]);
   const job=await call('create_appointment',{...input,type:'job',lead_id:contact,services:['Windows'],slot_id:value.slots[0].slot_id,idempotency_key:'call-job'});assert.equal(job.status,'confirmed',JSON.stringify(job));
   const saved=(await pool.query('SELECT * FROM agreement_bookings WHERE job_id=$1',[job.appointment_id])).rows[0];assert.ok(saved.confirmed_at);assert.equal(saved.confirmed_by,owner);
   assert.equal((await pool.query('SELECT count(*)::int n FROM agreement_booking_outbox WHERE job_id=$1',[job.appointment_id])).rows[0].n,1);
  });
  await t.test('signature uses raw bytes and timestamps; duplicate analyzed event is persisted once',async()=>{
   const contact=(await pool.query('SELECT contact_id FROM schedule_events WHERE id=$1',[appointment])).rows[0].contact_id;
   const event={event:'call_analyzed',call:{call_id:'call-book',agent_id:'agent-test',direction:'inbound',retell_llm_dynamic_variables:{lead_id:contact},call_analysis:{custom_analysis_data:{call_outcome:'booked',appointment_status:'confirmed',call_summary:'QA only'}}}};
   const raw=JSON.stringify(event),stamp=Date.now(),sig='v='+stamp+',d='+createHmac('sha256','test-provider-webhook-key').update(raw+stamp).digest('hex');
   const send=(body,signature)=>fetch(origin+'/retell/webhook',{method:'POST',headers:{'Content-Type':'application/json','x-retell-signature':signature},body});
   assert.equal((await send(raw,'bad')).status,401);assert.equal((await send(raw+' ',sig)).status,401);
   const old=stamp-600000,oldSig='v='+old+',d='+createHmac('sha256','test-provider-webhook-key').update(raw+old).digest('hex');assert.equal((await send(raw,oldSig)).status,401);
   assert.equal((await send(raw,sig)).status,202);assert.equal((await send(raw,sig)).status,202);
   assert.equal((await pool.query('SELECT count(*)::int n FROM retell_call_events')).rows[0].n,1);
   const workerAPI=await installRetell({app,pool,authRequired,env,startWorker:false});await workerAPI.drain();await workerAPI.drain();
   assert.equal((await pool.query("SELECT count(*)::int n FROM phone_calls WHERE provider='retell'")).rows[0].n,1);
   assert.equal((await pool.query('SELECT lead_info FROM contacts WHERE id=$1',[contact])).rows[0].lead_info.length,1);
   const foreign=(await pool.query('SELECT id FROM contacts WHERE company_id=$1 LIMIT 1',[b])).rows[0].id;
   event.call.call_id='foreign-report';event.call.retell_llm_dynamic_variables.lead_id=foreign;
   let body=JSON.stringify(event),timestamp=Date.now();let signature='v='+timestamp+',d='+createHmac('sha256','test-provider-webhook-key').update(body+timestamp).digest('hex');
   assert.equal((await send(body,signature)).status,202);await workerAPI.drain();
   assert.equal((await pool.query("SELECT state FROM retell_call_events WHERE call_id='foreign-report'")).rows[0].state,'review_required');
   assert.equal((await pool.query("SELECT count(*)::int n FROM phone_calls WHERE company_id=$1",[b])).rows[0].n,0);
   event.call.call_id='claimed-confirmation';event.call.retell_llm_dynamic_variables.lead_id=contact;
   body=JSON.stringify(event);timestamp=Date.now();signature='v='+timestamp+',d='+createHmac('sha256','test-provider-webhook-key').update(body+timestamp).digest('hex');
   assert.equal((await send(body,signature)).status,202);await workerAPI.drain();
   assert.equal(JSON.parse((await pool.query("SELECT disposition FROM phone_calls WHERE provider_call_id='claimed-confirmation'")).rows[0].disposition).appointment_status,'unverified');

  });
  await t.test('expired/revoked/rotated keys and removed membership fail',async()=>{
   await pool.query("UPDATE retell_connections SET expires_at=now()-interval '1 minute' WHERE company_id=$1",[a]);await assert.rejects(()=>connect(key));
   const next=(await mutate('/key',{valid_days:30})).body.key;await assert.rejects(()=>connect(key));const c=await connect(next);
   await pool.query('UPDATE users SET deleted_at=now() WHERE id=$1',[owner]);const r=await c.callTool({name:'check_quote_availability',arguments:{address:addr,preferred_date_range:range}}).catch(()=>null);assert.ok(!r||r.isError);await pool.query('UPDATE users SET deleted_at=NULL WHERE id=$1',[owner]);
   assert.equal((await mutate('/revoke')).status,200);await assert.rejects(()=>connect(next));
  });
 }finally{for(const c of clients)await c.close().catch(()=>{});if(server)await new Promise(r=>server.close(r));if(backend)await backend.pool.end();pg.stop();}
});
