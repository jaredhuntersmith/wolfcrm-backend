import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { startLocalPostgres } from './helpers/local-postgres.js';

// Runs the production startup composition, with no inherited provider secrets
// and a private, empty, disposable database. Service fixture tests cannot prove
// that every installer is actually connected to startServer in the right order.
test('actual API startup installs the complete quote workflow on an empty database', {timeout:90000}, async()=>{
  const postgres=startLocalPostgres();
  let child,pool,output='',probe;
  try{
    probe=createServer();probe.listen(0,'127.0.0.1');await once(probe,'listening');
    const port=probe.address().port;await new Promise(resolve=>probe.close(resolve));probe=null;
    const config=postgres.config;
    child=spawn(process.execPath,['index.js'],{
      cwd:fileURLToPath(new URL('..',import.meta.url)),
      env:{PATH:process.env.PATH,HOME:process.env.HOME,TMPDIR:process.env.TMPDIR,LANG:'en_US.UTF-8',
        NODE_ENV:'test',PORT:String(port),PGHOST:config.host,PGPORT:String(config.port),PGUSER:config.user,PGDATABASE:config.database,DB_SSL:'false',OWNER_EMAIL:'',WOLFCRM_SKIP_SERVER_START:'false'},
      stdio:['ignore','pipe','pipe']
    });
    child.stdout.on('data',chunk=>{output=(output+chunk.toString()).slice(-50000);});
    child.stderr.on('data',chunk=>{output=(output+chunk.toString()).slice(-50000);});
    await new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>{cleanup();reject(new Error(`API startup timed out: ${output}`));},45000);
      const check=()=>{if(output.includes(`API listening on ${port}`)){cleanup();resolve();}};
      const failed=code=>{cleanup();reject(new Error(`API startup exited ${code}: ${output}`));};
      const cleanup=()=>{clearTimeout(timer);child.stdout.off('data',check);child.off('exit',failed);};
      child.stdout.on('data',check);child.once('exit',failed);check();
    });
    const origin=`http://127.0.0.1:${port}`;
    for(const route of ['/api/agreements/settings','/api/service-plan-tiers','/api/schedule/booking/settings']){
      const response=await fetch(origin+route);assert.equal(response.status,401,`${route} must be installed and protected`);
    }
    const invalid=await fetch(origin+'/api/public/agreements/not-a-valid-token');
    assert.equal(invalid.status,404);assert.equal((await invalid.json()).error,'agreement_link_invalid');
    const receipt=await fetch(origin+'/api/agreements/00000000-0000-4000-8000-000000000001/payments/offline',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
    assert.equal(receipt.status,401);
    pool=new pg.Pool(config);
    for(const table of ['agreement_settings','agreement_assets','agreement_artifact_deliveries','agreement_archive_index','agreement_plan_enrollments','agreement_plan_cancellation_requests']){
      assert.equal((await pool.query('SELECT to_regclass($1)::text AS name',[table])).rows[0].name,table);
    }

    assert.equal((await pool.query("SELECT count(*)::integer AS n FROM payment_records")).rows[0].n,0);
  }finally{
    if(probe)await new Promise(resolve=>probe.close(resolve));
    if(child&&child.exitCode===null){const closed=once(child,'close');child.kill('SIGTERM');await closed;}
    if(pool)await pool.end();postgres.stop();
  }
});
