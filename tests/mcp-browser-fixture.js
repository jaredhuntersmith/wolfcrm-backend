// Local browser QA only: disposable PostgreSQL, loopback HTTP, synthetic users,
// no background processors, no environment/production database reuse.
import {createServer} from 'node:http';
import {randomUUID} from 'node:crypto';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {installMCP} from '../mcp/index.js';
import {installCompanyComms} from '../company-comms/index.js';
import {installNotes} from '../notes/index.js';
import {installMediaStorage} from '../media-storage/index.js';
import {storagePredicate} from '../company-comms/assets.js';
import {installGoogleSheetsSchema} from '../google-sheets.js';
import {installAutomationSystem} from '../automations.js';
const pg=startLocalPostgres();pg.configureEnvironment();
const backend=await import('../index.js');const {app,pool,rawPool,authRequired}=backend;
let server,clientReceiver,stopping=false;
async function stop(){if(stopping)return;stopping=true;try{if(clientReceiver){clientReceiver.closeAllConnections();await new Promise(r=>clientReceiver.close(r));}if(server){server.closeAllConnections();await new Promise(r=>server.close(r));}await rawPool.end();}finally{pg.stop();}}
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>void stop().then(()=>process.exit(0)));
try {
 await backend.bootstrap();
 const company=randomUUID(),owner=randomUUID(),employee=randomUUID();
 await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id) VALUES($1,'MCP Browser QA','MCP-QA',$2)",[company,owner]);
 for(const [id,email,role]of [[owner,'mcp-owner@example.invalid','employer'],[employee,'mcp-tech@example.invalid','employee']])await pool.query('INSERT INTO users(id,email,display_name,company_id,role,password_hash) VALUES($1,$2,$3,$4,$5,$6)',[id,email,'QA '+role,company,role,backend.hashPassword('Synthetic-MCP-QA-428!')]);
 await pool.query("INSERT INTO employee_permissions(user_id,company_id,permission_preset,permission_overrides) VALUES($1,$2,'technician','{}')",[employee,company]);
 app.locals.mediaStorage=await installMediaStorage({app,pool,authRequired,accessPredicate:storagePredicate,startWorker:false,bucket:null});
 app.locals.comms=await installCompanyComms({app,pool,authRequired,startWorker:false,sendPush:async()=>{throw new Error('External push forbidden');}});
 app.locals.notes=await installNotes({app,pool,authRequired,notifications:app.locals.comms.notifications,storage:app.locals.mediaStorage});
 await installGoogleSheetsSchema(pool);
 await installAutomationSystem({app,pool,authRequired,requireEmployer:(req,res,next)=>req.isCompanyOwner?next():res.sendStatus(403),disableProcessors:true});
 await installMCP({app,pool,rawPool,authRequired,startMaintenance:false,env:{NODE_ENV:'test',MCP_ENABLED:'true',MCP_PUBLIC_ORIGIN:'http://127.0.0.1:18590',MCP_WEB_ORIGIN:'http://127.0.0.1:18589',MCP_REDIRECT_URIS:'["http://127.0.0.1:18591/callback"]'},verifyIdentity:async(email,password)=>{const u=(await pool.query('SELECT id,password_hash FROM users WHERE email=$1',[email])).rows[0];return u&&backend.verifyPassword(password,u.password_hash)?{id:u.id}:null;}});
 app.get('/__mcp_qa/ready',(_req,res)=>res.json({ready:true,company_id:company}));
 clientReceiver=createServer((_req,res)=>{res.writeHead(200,{'Content-Type':'text/html','Cache-Control':'no-store'});res.end('<h1>Client received authorization</h1>');}).listen(18591,'127.0.0.1');
 server=app.listen(18590,'127.0.0.1',()=>console.log('MCP disposable browser fixture ready on loopback 18590'));
}catch(e){await stop();throw e;}
