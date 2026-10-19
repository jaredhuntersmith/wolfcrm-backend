import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,randomBytes} from 'node:crypto';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {installMCP} from '../mcp/index.js';
import {installAssistant} from '../assistant/index.js';
import {installAssistantSchema} from '../assistant/schema.js';
import {modelCatalog} from '../assistant/models.js';

test('owner allocations fund staff without changing identity, credentials, budgets or access',{timeout:120000},async t=>{
 const pg=startLocalPostgres();pg.configureEnvironment();let backend,server;
 try{
  backend=await import('../index.js');await backend.bootstrap();const {app,pool,authRequired}=backend;
  const company=randomUUID(),otherCompany=randomUUID(),owner=randomUUID(),staff=randomUUID(),other=randomUUID();
  for(const [c,u] of [[company,owner],[otherCompany,other]]){
   await pool.query('INSERT INTO companies(id,name,join_code,owner_user_id) VALUES($1,$2,$3,$4)',[c,'Synthetic funding company',c,u]);
   await pool.query("INSERT INTO users(id,email,company_id,role,password_hash) VALUES($1,$2,$3,'employer','test')",[u,u+'@example.invalid',c]);
   await pool.query('INSERT INTO sessions(token,user_id) VALUES($1,$2)',[u,u]);
  }
  await pool.query("INSERT INTO users(id,email,display_name,company_id,role,password_hash) VALUES($1,$2,'Fixture staff',$3,'employee','test')",[staff,staff+'@example.invalid',company]);
  await pool.query("INSERT INTO employee_permissions(user_id,company_id,permission_overrides) VALUES($1,$2,'{\"ai.use\":true}')",[staff,company]);
  await pool.query('INSERT INTO sessions(token,user_id) VALUES($1,$2)',[staff,staff]);
  const env={MCP_ENABLED:'true',ASSISTANT_ENABLED:'true',ASSISTANT_OWNER_FUNDING:'true',MCP_PUBLIC_ORIGIN:'http://127.0.0.1',MCP_WEB_ORIGIN:'http://127.0.0.1',RETELL_ENCRYPTION_KEY:randomBytes(32).toString('base64'),NODE_ENV:'test'};
  await installMCP({app,pool,authRequired,env,startMaintenance:false,verifyIdentity:async()=>null});
  let calls=0,modelCalls=0,onResponse;const provider={models:async()=>{modelCalls++;return modelCatalog;},respond:async()=>{calls++;if(onResponse)await onResponse();return {output:[{type:'message',role:'assistant',content:[{type:'output_text',text:'Synthetic staff response'}]}],usage:{input_tokens:100,output_tokens:20}};}};
  const engine=await installAssistant({app,pool,authRequired,env,provider,startWorker:false});await installAssistantSchema(pool);
  server=await new Promise(r=>{const s=app.listen(0,'127.0.0.1',()=>r(s));});const origin='http://127.0.0.1:'+server.address().port;
  async function http(path,body,actor=owner,method=body?'POST':'GET'){const response=await fetch(origin+'/api/assistant/'+path,{method,headers:{authorization:'Bearer '+actor,'content-type':'application/json'},...(body?{body:JSON.stringify(body)}:{})});return {status:response.status,data:await response.json()};}
  const config={funding:'owner',model:'gpt-6.1-sol',reasoning:'low',instructions:'',memory_enabled:false,monthly_limit_micros:5000000};let allocationRevision=0;
  const allocate=async(enabled,limit=5000000)=>{const r=await http('funding/allocations/'+staff,{expected_revision:allocationRevision,enabled,monthly_limit_micros:limit},owner,'PUT');if(r.status===200)allocationRevision=r.data.revision;return r;};
  const setup=await http('setup',{},staff);assert.equal(setup.status,201,JSON.stringify(setup));const connection=setup.data.settings.connection_id;
  await t.test('unallocated staff cannot verify or spend shared funding; allocation is owner-only and company scoped',async()=>{
   assert.equal((await http('models',{funding:'owner'},staff)).status,403);assert.equal(modelCalls,0);
   assert.equal((await http('settings',{...config,expected_revision:1},staff,'PUT')).status,403);
   assert.equal((await http('funding/allocations',undefined,staff)).status,403);
   assert.equal((await http('funding/allocations/'+staff,{expected_revision:0,enabled:true,monthly_limit_micros:5000000},staff,'PUT')).status,403);
   assert.equal((await http('funding/allocations/'+other,{expected_revision:0,enabled:true,monthly_limit_micros:5000000},owner,'PUT')).status,404);
   assert.equal((await allocate(true)).status,200);
   assert.equal((await http('funding/allocations/'+staff,{expected_revision:0,enabled:true,monthly_limit_micros:1},owner,'PUT')).status,409);
   const status=await http('status',undefined,staff);assert.equal(status.data.owner_funding.available,true);assert.equal(status.data.can_allocate_funding,false);
  });
  await t.test('allocation preserves encrypted personal key and grants no capabilities',async()=>{
   const personal=await http('settings',{...config,funding:'personal',api_key:'synthetic-fixture-key-not-a-real-credential',expected_revision:1},staff,'PUT');assert.equal(personal.status,200,JSON.stringify(personal));
   const before=(await pool.query('SELECT key_ciphertext FROM wolf_assistant_settings WHERE company_id=$1 AND user_id=$2',[company,staff])).rows[0].key_ciphertext;assert.ok(before);assert.ok(!before.includes('synthetic-fixture'));
   const saved=await http('settings',{...config,expected_revision:2},staff,'PUT');assert.equal(saved.status,200,JSON.stringify(saved));assert.equal(saved.data.key_configured,true);
   assert.equal((await pool.query('SELECT key_ciphertext FROM wolf_assistant_settings WHERE company_id=$1 AND user_id=$2',[company,staff])).rows[0].key_ciphertext,before);
   const chat=(await http('conversations',{title:'No grants'},staff)).data.id;
   assert.equal((await http('runs',{conversation_id:chat,request_key:randomUUID(),text:'Hello'},staff)).status,403);assert.equal(calls,0);
  });
  async function run(title){const chat=(await http('conversations',{title},staff)).data.id;const r=await http('runs',{conversation_id:chat,request_key:randomUUID(),text:title},staff);assert.equal(r.status,202,JSON.stringify(r));await engine.tick();return (await http('runs/'+r.data.id,undefined,staff)).data;}
  await pool.query("UPDATE mcp_connections SET tool_policy='{\"assistant_execute\":{\"allow\":true,\"approval\":false}}',revision=revision+1 WHERE id=$1",[connection]);
  await t.test('allocated staff can execute and owner sees only estimated owner-funded usage',async()=>{
   const result=await run('Funded staff run');assert.equal(result.status,'completed',JSON.stringify(result));assert.equal(calls,1);
   const list=await http('funding/allocations');assert.equal(list.status,200);const row=list.data.items.find(x=>x.user_id===staff);assert.ok(row.cost_micros>0);assert.equal(row.reserved_micros,0);assert.equal(list.data.cost_status,'estimate_only');assert.equal(list.data.items.length,1);
  });
  await t.test('allocation cap blocks before provider even when the personal limit is larger',async()=>{
   assert.equal((await allocate(true,1)).status,200);const result=await run('Allocation exhausted');assert.equal(result.error_code,'owner_funding_allocation_exceeded');assert.equal(calls,1);
  });
  await t.test('revocation during provider response stops subsequent effects without switching funding',async()=>{
   await allocate(true);onResponse=async()=>{assert.equal((await allocate(false)).status,200);};const result=await run('Revoke this allocation');assert.equal(result.status,'failed');assert.equal(result.error_code,'owner_funding_not_allocated');assert.equal(calls,2);
   const chat=(await http('conversations',{title:'Revoked'},staff)).data.id;assert.equal((await http('runs',{conversation_id:chat,request_key:randomUUID(),text:'Cannot restart'},staff)).status,403);assert.equal(calls,2);
   const status=await http('status',undefined,staff);assert.equal(status.data.settings.funding,'owner');assert.equal(status.data.settings.key_configured,true);assert.equal(status.data.owner_funding.available,false);assert.equal(status.data.model_error,'owner_funding_not_allocated');
   const list=(await http('funding/allocations')).data;assert.ok(list.items[0].reserved_micros>0);assert.equal(list.items[0].enabled,false);
   assert.equal((await pool.query('SELECT count(*)::int n FROM wolf_assistant_funding_revisions WHERE company_id=$1 AND user_id=$2',[company,staff])).rows[0].n,4);
  });
 }finally{if(server)await new Promise(r=>server.close(r));await backend?.pool.end();pg.stop();}
});
