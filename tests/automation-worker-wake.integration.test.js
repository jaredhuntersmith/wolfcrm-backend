import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {transaction} from '../mcp/context.js';
import {installAutomationSystem,automationTestHooks as hooks} from '../automations.js';

test('manual and recovery workers leave the MCP transaction only after commit; rollback and disabled processors never wake', {timeout:60000}, async()=>{
 const pg=startLocalPostgres();pg.configureEnvironment();let pool;
 try {
  const backend=await import('../index.js');pool=backend.rawPool;await backend.bootstrap();
  const options={...backend,pool:backend.pool,requireEmployer:backend.requireCapability('automations.manage'),disableProcessors:true};
  await installAutomationSystem(options);
  const company=randomUUID(),user=randomUUID(),definition=randomUUID(),version=randomUUID(),trigger=randomUUID(),end=randomUUID();
  await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id,automations_enabled) VALUES($1,'Worker fixture',$3,$2,true)",[company,user,company]);
  await pool.query("INSERT INTO users(id,email,role,company_id) VALUES($1,$2,'employer',$3)",[user,user+'@example.invalid',company]);
  await pool.query("INSERT INTO automation_definitions(id,company_id,name,status,allow_manual_trigger,created_by_user_id,updated_by_user_id) VALUES($1,$2,'Worker','published',true,$3,$3)",[definition,company,user]);
  await pool.query("INSERT INTO automation_versions(id,automation_id,company_id,version_number,status) VALUES($1,$2,$3,1,'published')",[version,definition,company]);
  await pool.query('UPDATE automation_definitions SET active_version_id=$2 WHERE id=$1',[definition,version]);
  for(const [id,key,type,config] of [[trigger,'manual','trigger',{trigger_key:'manual'}],[end,'end','end',{}]])
   await pool.query('INSERT INTO automation_nodes(id,version_id,company_id,node_key,node_type,title,config) VALUES($1,$2,$3,$4,$5,$4,$6)',[id,version,company,key,type,config]);
  await pool.query("INSERT INTO automation_edges(id,version_id,company_id,source_node_id,target_node_id,source_port,target_port) VALUES($1,$2,$3,$4,$5,'default','default')",[randomUUID(),version,company,trigger,end]);
  const status=async id=>(await pool.query('SELECT status FROM automation_runs WHERE id=$1',[id])).rows[0]?.status;
  const complete=async id=>{const deadline=Date.now()+5000;while(await status(id)==='queued'||await status(id)==='running'){assert.ok(Date.now()<deadline,'worker did not complete after transaction commit');await delay(10);}assert.equal(await status(id),'completed');};
  const disabled=await transaction(pool,()=>hooks.startManualRun(definition,company,user,{}));
  await new Promise(setImmediate);assert.equal(await status(disabled.id),'queued');
  // Enable only the immediate wake path; no periodic processor was started.
  options.disableProcessors=false;
  let rolledBack;
  await assert.rejects(transaction(pool,async()=>{rolledBack=await hooks.startManualRun(definition,company,user,{});await new Promise(setImmediate);throw new Error('rollback fixture');}),/rollback fixture/);
  assert.equal(await status(rolledBack.id),undefined);
  const run=await transaction(pool,async()=>{
   const pending=await hooks.startManualRun(definition,company,user,{});
   await new Promise(setImmediate);
   assert.equal(await status(pending.id),undefined,'outer transaction must still be invisible to the worker');
   return pending;
  });
  await complete(run.id);
  await pool.query("UPDATE automation_runs SET status='failed' WHERE id=$1",[run.id]);
  const recovered=await transaction(pool,()=>hooks.retryAutomationRun(run.id,company,user));await complete(recovered.id);
  options.disableProcessors=true;
  const held=await transaction(pool,()=>hooks.retryAutomationRun(run.id,company,user));
  await new Promise(setImmediate);assert.equal(await status(held.id),'queued');
 } finally {if(pool)await pool.end();pg.stop();}
});
