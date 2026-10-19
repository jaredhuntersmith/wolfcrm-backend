// Local Unix-socket restore only. Does not read credentials, start workers, or contact providers.
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import pg from 'pg';
import {startLocalPostgres} from '../tests/helpers/local-postgres.js';
import {installMCPSchema} from '../mcp/schema.js';
import {installRetellSchema} from '../retell/schema.js';
import {installManagerSchema} from '../mcp/manager-schema.js';
import {installElevenLabsSchema} from '../elevenlabs/schema.js';
import {installAdsSchema} from '../facebook-ads/schema.js';
import {installWebhookSchema} from '../webhooks/schema.js';
import {installAssistantSchema} from '../assistant/schema.js';
import {installCollaborationSchema} from '../company-comms/collaboration-schema.js';
import {installFinanceSourceLocks} from '../finance-source-locks.js';

const [backup,expectedHash,outputDir]=process.argv.slice(2);
if(!backup||!expectedHash||!outputDir)throw new Error('Provide backup, verified SHA-256, and evidence directory.');
const hash=createHash('sha256').update(readFileSync(backup)).digest('hex');
if(hash!==expectedHash)throw new Error('Backup hash mismatch.');
const local=startLocalPostgres(),pool=new pg.Pool(local.config);
const quote=s=>'"'+s.replaceAll('"','""')+'"';
try {
 await pool.query('CREATE ROLE wolf_finance_request NOLOGIN NOSUPERUSER NOBYPASSRLS');
 const restored=spawnSync('pg_restore',['--no-owner','--no-privileges','--exit-on-error','-h',local.config.host,'-U',local.config.user,'-d','postgres',backup],{encoding:'utf8',maxBuffer:2000000});
 if(restored.status!==0)throw new Error('Local pg_restore failed; exit '+restored.status+' '+restored.stderr.split('\n').filter(l=>l.startsWith('pg_restore: error:')).join(' '));
 const columns=(await pool.query("SELECT table_name,json_agg(column_name ORDER BY ordinal_position) AS names FROM information_schema.columns WHERE table_schema='public' AND table_name IN (SELECT tablename FROM pg_tables WHERE schemaname='public') GROUP BY table_name ORDER BY table_name")).rows;
 const fingerprints=async()=>{
  const result={};
  for(const {table_name,names} of columns){
   const data=(await pool.query(`SELECT count(*)::int AS rows,md5(COALESCE(string_agg(digest,'' ORDER BY digest),'')) AS digest FROM (SELECT md5(row_to_json(t)::text) AS digest FROM (SELECT ${names.map(quote).join(',')} FROM ${quote(table_name)}) t) hashed_rows`)).rows[0];
   result[table_name]=data;
  }
  return result;
 };
 const before=await fingerprints();
 const nodes=(await pool.query("SELECT id,version_id,node_key,config FROM automation_nodes")).rows;
 const inline=nodes.filter(n=>n.config?.action_key==='webhook.send'&&!n.config?.destination_id);
 const consumers=[];
 for(const source of inline){
  for(const node of nodes.filter(n=>n.version_id===source.version_id)){
   const paths=[...JSON.stringify(node.config).matchAll(/nodes\.([A-Za-z0-9_-]+)\.output\.(body|headers)(?:\.([A-Za-z0-9_.-]+))?/g)].filter(m=>m[1]===source.node_key).map(m=>m[0]);
   if(paths.length)consumers.push({source_node:source.id,consumer_node:node.id,version:source.version_id,paths:[...new Set(paths)]});
  }
 }
 const migrations=[installMCPSchema,installRetellSchema,installManagerSchema,installElevenLabsSchema,installAdsSchema,installWebhookSchema,installAssistantSchema,installCollaborationSchema,installFinanceSourceLocks];
 for(let pass=0;pass<2;pass++)for(const migrate of migrations)await migrate(pool);
 const after=await fingerprints(),changes=columns.filter(({table_name:t})=>JSON.stringify(before[t])!==JSON.stringify(after[t])).map(({table_name})=>table_name);
 const tablesAfter=Number((await pool.query("SELECT count(*) AS n FROM pg_tables WHERE schemaname='public'")).rows[0].n);
 mkdirSync(outputDir,{recursive:true});
 const report={status:changes.length?'FAIL':'PASS',backup_sha256:hash,restored:true,local_socket_only:true,workers_started:false,provider_requests:false,migration_passes:2,tables_before:columns.length,tables_after:tablesAfter,original_row_or_value_changes:changes,migrations:migrations.map(f=>f.name)};
 writeFileSync(outputDir+'/MIGRATION-REHEARSAL.json',JSON.stringify(report,null,2)+'\n');
 writeFileSync(outputDir+'/LEGACY-WEBHOOK-INVENTORY.json',JSON.stringify({source:'Verified local restoration; production not queried',inline_nodes:inline.length,raw_response_consumers:consumers,notes:'Raw response body/header consumers require explicit named mappings before release.'},null,2)+'\n');
 console.log(JSON.stringify({...report,inline_nodes:inline.length,raw_response_consumers:consumers.length}));
 if(changes.length)process.exitCode=1;
}finally{await pool.end();local.stop();}
