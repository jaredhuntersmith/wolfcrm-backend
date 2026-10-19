// Run the existing automation acceptance suite against a disposable Unix socket
// database. Inherited production DATABASE_URL is never passed to the child.
import {spawnSync} from 'node:child_process';
import {startLocalPostgres} from './helpers/local-postgres.js';
const pg=startLocalPostgres();
try {
 const url=new URL('postgresql://localhost/postgres');
 url.username=pg.config.user;url.searchParams.set('host',pg.config.host);url.searchParams.set('port',String(pg.config.port));
 const result=spawnSync(process.execPath,['tests/automation-core.integration.js'],{env:{...process.env,TEST_DATABASE_URL:url.href,DATABASE_URL:url.href},stdio:'inherit',timeout:180000});
 if(result.error)console.error('Automation fixture process failed:',result.error.code);
 process.exitCode=result.status??1;
} finally { pg.stop(); }
