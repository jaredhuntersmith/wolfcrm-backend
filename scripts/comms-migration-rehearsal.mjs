// Run against a source snapshot under /tmp only. Never connects to a supplied DB URL.
import {spawn,spawnSync} from 'node:child_process';
import {once} from 'node:events';
import {createServer} from 'node:net';
import {fileURLToPath} from 'node:url';
import {readFileSync,writeFileSync,mkdtempSync,rmSync,realpathSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import pg from 'pg';
import assert from 'node:assert/strict';
import {startLocalPostgres} from '../tests/helpers/local-postgres.js';
const source=JSON.parse(readFileSync('/tmp/wolf-comms-migration-source.json'));
assert.match(realpathSync(source.source),/^\/private\/tmp\/wolf-comms-deployed-baseline-/);
const baseline=startLocalPostgres(),restored=startLocalPostgres();
const dumpDir=mkdtempSync('/tmp/wolf-comms-recovery-');let child,pool,origin;
const stop=async()=>{if(child&&child.exitCode===null&&child.signalCode===null){const closed=once(child,'close');child.kill('SIGTERM');await closed;}child=null;};
const start=async(cwd,config)=>{
 const probe=createServer();probe.listen(0,'127.0.0.1');await once(probe,'listening');const port=probe.address().port;await new Promise(resolve=>probe.close(resolve));
 child=spawn(process.execPath,['index.js'],{cwd,env:{PATH:process.env.PATH,HOME:process.env.HOME,TMPDIR:process.env.TMPDIR,NODE_ENV:'test',PORT:String(port),PGHOST:config.host,PGPORT:String(config.port),PGUSER:config.user,PGDATABASE:config.database,DB_SSL:'false',OWNER_EMAIL:''},stdio:['ignore','pipe','pipe']});
 let output='';for(const stream of [child.stdout,child.stderr])stream.on('data',x=>{output=(output+x).slice(-15000);});
 await new Promise((resolve,reject)=>{const timer=setTimeout(()=>{clearInterval(poll);reject(Error(output));},30000);const poll=setInterval(()=>{if(output.includes('API listening on '+port)){clearTimeout(timer);clearInterval(poll);resolve();}else if(child.exitCode!==null){clearTimeout(timer);clearInterval(poll);reject(Error(output));}},30);});origin='http://127.0.0.1:'+port;
};
const run=(cmd,args)=>{const result=spawnSync(cmd,args,{encoding:'utf8',env:{PATH:process.env.PATH,HOME:process.env.HOME},timeout:30000});assert.equal(result.status,0,result.stderr);};
try{
 await start(source.source,baseline.config);pool=new pg.Pool(baseline.config);
 const owner=randomUUID(),company=randomUUID(),message='pre-comms-message',channel='pre-comms-channel';
 await pool.query("INSERT INTO users(id,email,role) VALUES($1,'rehearsal@example.invalid','employer')",[owner]);
 await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id) VALUES($1,'Rehearsal only',$2,$3)",[company,randomUUID(),owner]);
 await pool.query('UPDATE users SET company_id=$2 WHERE id=$1',[owner,company]);
 await pool.query("INSERT INTO sessions(token,user_id) VALUES('local-rehearsal',$1)",[owner]);
 await pool.query("INSERT INTO channels(id,company_id,name,created_by) VALUES($1,$2,'Historical Channel',$3)",[channel,company,owner]);
 await pool.query("INSERT INTO messages(id,channel_id,sender_id,body,created_at,updated_at) VALUES($1,$2,$3,'Original historical message','2025-01-01T08:00:00.123456Z','2025-01-01T08:00:00.123456Z')",[message,channel,owner]);
 await pool.query("INSERT INTO message_attachments(id,message_id,kind,url,file_name) VALUES('old-attachment',$1,'file','https://example.invalid/old-private','Retained.pdf')",[message]);
 await pool.query("INSERT INTO notifications(id,user_id,company_id,kind,title,body,read_at) VALUES('old-inbox',$1,$2,'notice','Old read notice','Retained inbox','2025-01-02T00:00:00Z')",[owner,company]);
 const before=(await pool.query('SELECT id,body,sender_id,created_at::text,updated_at::text FROM messages WHERE id=$1',[message])).rows[0];
 const auth={Authorization:'Bearer local-rehearsal'};
 for(const path of ['/api/comms/bootstrap','/api/comms/notifications']){const response=await fetch(origin+path,{headers:auth});assert.equal(response.status,404);assert.match(response.headers.get('content-type'),/text\/html/);}
 await stop();await pool.end();pool=null;
 run('pg_dump',['-h',baseline.config.host,'-U',baseline.config.user,'-d','postgres','-Fc','-f',dumpDir+'/before.dump']);
 run('pg_restore',['-h',restored.config.host,'-U',restored.config.user,'-d','postgres','--no-owner','--no-privileges',dumpDir+'/before.dump']);
 pool=new pg.Pool(restored.config);const candidate=fileURLToPath(new URL('..',import.meta.url));
 let mapping;
 for(let pass=1;pass<=2;pass++){
  await start(candidate,restored.config);
  assert.deepEqual((await pool.query('SELECT id,body,sender_id,created_at::text,updated_at::text FROM messages WHERE id=$1',[message])).rows[0],before);
  assert.equal((await pool.query("SELECT url FROM message_attachments WHERE id='old-attachment'")).rows[0].url,'https://example.invalid/old-private');
  const current=(await pool.query('SELECT id,group_id,conversation_id FROM comms_threads WHERE legacy_channel_id=$1',[channel])).rows[0];assert.ok(current);if(mapping)assert.deepEqual(current,mapping);mapping=current;
  const boot=await fetch(origin+'/api/comms/bootstrap',{headers:auth});assert.equal(boot.status,200);assert.equal((await boot.json()).calls.configured,false);
  const inbox=await fetch(origin+'/api/comms/notifications',{headers:auth});assert.equal(inbox.status,200);assert.ok((await inbox.json()).notifications.find(x=>x.id==='old-inbox').read_at);
  await stop();
 }
 const report={status:'PASS',baseline_revision:source.revision,baseline_authenticated_html_404:true,pg_dump_restore:true,candidate_startups:2,history_ids_timestamps_attachments_preserved:true,inbox_read_state_preserved:true,live_database_access:false};
 writeFileSync('/tmp/wolf-comms-migration-rehearsal.json',JSON.stringify(report,null,2));console.log(JSON.stringify(report));
}finally{await stop();if(pool)await pool.end();baseline.stop();restored.stop();rmSync(dumpDir,{recursive:true,force:true});}
