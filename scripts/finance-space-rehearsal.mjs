// Local-only rehearsal: never reads DATABASE_URL and never starts workers/providers.
import {spawnSync} from 'node:child_process';
import {writeFileSync,mkdirSync} from 'node:fs';
import pg from 'pg';
import {startLocalPostgres} from '../tests/helpers/local-postgres.js';
import {installFinanceSpacesSchema} from '../finance-spaces.js';
import {installFinanceSchema} from '../finance.js';
const backup=process.argv[2];if(!backup)throw new Error('Provide a local pg_dump archive.');
const local=startLocalPostgres();const pool=new pg.Pool(local.config);
try {
 const result=spawnSync('pg_restore',['--no-owner','--no-privileges','--exit-on-error','-h',local.config.host,'-U',local.config.user,'-d','postgres',backup],{encoding:'utf8',maxBuffer:2_000_000});if(result.status)throw new Error('Local restore failed: '+result.stderr.slice(-1000));
 const tables=(await pool.query("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")).rows.map(r=>r.tablename);
 const count=async()=>{const counts={};for(const t of tables)counts[t]=Number((await pool.query('SELECT count(*) AS n FROM "'+t.replaceAll('"','""')+'"')).rows[0].n);return counts;};
 const before=await count();await installFinanceSchema(pool);const first=await installFinanceSpacesSchema(pool);await installFinanceSchema(pool);await installFinanceSpacesSchema(pool);const after=await count();
 const changes=tables.filter(t=>before[t]!==after[t]).map(t=>({table:t,before:before[t],after:after[t]}));
 const finance=(await pool.query("SELECT table_name FROM information_schema.columns WHERE table_schema='public' AND column_name='finance_space_id' ORDER BY table_name")).rows;
 const ownership=[];for(const {table_name:t} of finance){const row=(await pool.query('SELECT count(*)::int AS total,count(*) FILTER(WHERE finance_space_id IS NULL)::int AS unassigned FROM "'+t+'"')).rows[0];if(row.total)ownership.push({table:t,...row});}
 const report={at:new Date().toISOString(),source:'Local restoration of previously verified production backup',migration_runs:2,original_tables:tables.length,finance_tables:first.tables,original_row_count_changes:changes,ownership};
 const target='/tmp/wolf043-finance-migration-rehearsal.json';writeFileSync(target,JSON.stringify(report,null,2),{mode:0o600});console.log(JSON.stringify(report));if(changes.length)process.exitCode=1;
}finally{await pool.end();local.stop();}
