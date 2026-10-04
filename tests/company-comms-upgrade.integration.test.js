import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {createServer} from 'node:net';
import {fileURLToPath} from 'node:url';
import {randomUUID} from 'node:crypto';
import pg from 'pg';
import {startLocalPostgres} from './helpers/local-postgres.js';

test('Complete backend restart reapplies additive Comms migration without rewriting old history',{timeout:90000},async()=>{
 const postgres=startLocalPostgres(),pool=new pg.Pool(postgres.config);let child;
 const stop=async()=>{if(child&&child.exitCode===null){const closed=once(child,'close');child.kill('SIGTERM');await closed;}};
 const start=async()=>{
  const probe=createServer();probe.listen(0,'127.0.0.1');await once(probe,'listening');const port=probe.address().port;await new Promise(resolve=>probe.close(resolve));const config=postgres.config;
  child=spawn(process.execPath,['index.js'],{cwd:fileURLToPath(new URL('..',import.meta.url)),env:{PATH:process.env.PATH,HOME:process.env.HOME,TMPDIR:process.env.TMPDIR,NODE_ENV:'test',PORT:String(port),PGHOST:config.host,PGPORT:String(config.port),PGUSER:config.user,PGDATABASE:config.database,DB_SSL:'false',OWNER_EMAIL:'',WOLFCRM_SKIP_SERVER_START:'false'},stdio:['ignore','pipe','pipe']});
  let output='';for(const stream of [child.stdout,child.stderr])stream.on('data',data=>{output=(output+data.toString()).slice(-20000);});
  await new Promise((resolve,reject)=>{const timeout=setTimeout(()=>{clearInterval(poll);reject(Error(output));},30000);const poll=setInterval(()=>{if(output.includes('API listening on '+port)){clearTimeout(timeout);clearInterval(poll);resolve();}else if(child.exitCode!==null){clearTimeout(timeout);clearInterval(poll);reject(Error(output));}},50);});
 };
 try{
  await start();await stop();
  const user=randomUUID(),company=randomUUID(),channel='old-channel-'+randomUUID(),message='old-message-'+randomUUID(),attachment='old-attachment-'+randomUUID();
  await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id) VALUES($1,'Legacy fixture',$2,$3)",[company,randomUUID(),user]);
  await pool.query("INSERT INTO users(id,email,role,company_id) VALUES($1,'legacy-restart@example.invalid','employer',$2)",[user,company]);
  await pool.query("INSERT INTO channels(id,company_id,name,created_by) VALUES($1,$2,'Original Channel',$3)",[channel,company,user]);
  await pool.query("INSERT INTO messages(id,channel_id,sender_id,body,created_at,updated_at) VALUES($1,$2,$3,'Historical body','2025-01-01T08:00:00.123456Z','2025-01-01T08:00:00.123456Z')",[message,channel,user]);
  await pool.query("INSERT INTO message_attachments(id,message_id,kind,url,file_name) VALUES($1,$2,'file','https://example.invalid/legacy-private','Retained original.pdf')",[attachment,message]);
  await start();await stop();
  const original=(await pool.query('SELECT id,channel_id,sender_id,body,created_at::text,updated_at::text FROM messages WHERE id=$1',[message])).rows[0];
  const mapping=(await pool.query('SELECT id,group_id,conversation_id FROM comms_threads WHERE legacy_channel_id=$1',[channel])).rows[0];assert.ok(mapping);
  const beforeCounts=(await pool.query(`SELECT (SELECT count(*) FROM comms_groups) AS groups,(SELECT count(*) FROM comms_threads) AS threads,(SELECT count(*) FROM comms_legacy_asset_map) AS legacy_assets`)).rows[0];
  await start();
  assert.deepEqual((await pool.query('SELECT id,channel_id,sender_id,body,created_at::text,updated_at::text FROM messages WHERE id=$1',[message])).rows[0],original);
  assert.deepEqual((await pool.query('SELECT id,group_id,conversation_id FROM comms_threads WHERE legacy_channel_id=$1',[channel])).rows[0],mapping);
  assert.deepEqual((await pool.query(`SELECT (SELECT count(*) FROM comms_groups) AS groups,(SELECT count(*) FROM comms_threads) AS threads,(SELECT count(*) FROM comms_legacy_asset_map) AS legacy_assets`)).rows[0],beforeCounts);
  assert.equal((await pool.query('SELECT url FROM message_attachments WHERE id=$1',[attachment])).rows[0].url,'https://example.invalid/legacy-private');
  assert.match((await pool.query('SELECT repair_reason FROM comms_legacy_asset_map WHERE attachment_id=$1',[attachment])).rows[0].repair_reason,/retained/);
 }finally{await stop();await pool.end();postgres.stop();}
});
