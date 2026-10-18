import {installAgreementSchema,installAgreementSystem} from '../quote-agreements.js';
import {validateCatalog} from '../quote-calculator/domain.js';
// Local browser QA only: disposable PostgreSQL, loopback HTTP, synthetic users,
// no background processors, no environment/production database reuse.
import {createServer} from 'node:http';
import {randomBytes,randomUUID} from 'node:crypto';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {installServiceCatalogSchema} from '../services-catalog.js';
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
 await backend.bootstrap();await installServiceCatalogSchema(pool);await installAgreementSchema(pool);
 await installAgreementSystem({app,pool,authRequired,requireCapability:backend.requireCapability,getQuoteSettings:backend.getQuoteSettings,env:{NODE_ENV:"test",QUOTE_LINK_SECRET:"synthetic-browser-quote-key-at-least-thirty-two-characters",QUOTE_PUBLIC_BASE_URL:"http://127.0.0.1:18589"},startWorker:false});
 const company=randomUUID(),owner=randomUUID(),employee=randomUUID();
 await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id) VALUES($1,'MCP Browser QA','MCP-QA',$2)",[company,owner]);
 for(const [id,email,role]of [[owner,'mcp-owner@example.invalid','employer'],[employee,'mcp-tech@example.invalid','employee']])await pool.query('INSERT INTO users(id,email,display_name,company_id,role,password_hash) VALUES($1,$2,$3,$4,$5,$6)',[id,email,'QA '+role,company,role,backend.hashPassword('Synthetic-MCP-QA-428!')]);
 const serviceID=randomUUID(),calculatorLead=randomUUID();
 await pool.query("INSERT INTO saved_services(id,company_id,name) VALUES($1,$2,'QA window service')",[serviceID,company]);
 await pool.query("INSERT INTO contacts(id,user_id,company_id,name,lead_info) VALUES($1,$2,$3,'Calculator browser customer',$4)",[calculatorLead,owner,company,JSON.stringify(['Facebook lead synthetic\nWindow count\n30'])]);
 const calculator=validateCatalog({questions:[{id:'windows',label:'Window count',type:'number',unit:'count',required:true,lead_field:'Window count',service_ids:[serviceID]}],services:[{service_id:serviceID,crew_size:1,elapsed_ratio_bp:10000}],components:[{id:'outside',order:0,name:'Exterior',service_ids:[serviceID],scope:'service',unit:'count',quantity_fact:'windows',decimal_quantity:false,selection:'required',money_enabled:true,time_enabled:true,unit_cents:1000,unit_seconds:60,visible:true},{id:'inside',order:1,name:'Interior',service_ids:[serviceID],scope:'service',unit:'count',quantity_fact:'windows',decimal_quantity:false,selection:'default',money_enabled:true,time_enabled:true,unit_cents:1500,unit_seconds:120,visible:true}]});
 await pool.query('INSERT INTO quote_calculator_catalog(company_id,config,updated_by) VALUES($1,$2,$3)',[company,JSON.stringify(calculator),owner]);
 await pool.query("INSERT INTO employee_permissions(user_id,company_id,permission_preset,permission_overrides) VALUES($1,$2,'technician','{}')",[employee,company]);
 app.locals.mediaStorage=await installMediaStorage({app,pool,authRequired,accessPredicate:storagePredicate,startWorker:false,bucket:null});
 app.locals.comms=await installCompanyComms({app,pool,authRequired,startWorker:false,sendPush:async()=>{throw new Error('External push forbidden');}});
 app.locals.notes=await installNotes({app,pool,authRequired,notifications:app.locals.comms.notifications,storage:app.locals.mediaStorage});
 await installGoogleSheetsSchema(pool);
 await installAutomationSystem({app,pool,authRequired,requireEmployer:(req,res,next)=>req.isCompanyOwner?next():res.sendStatus(403),disableProcessors:true});
 await installMCP({app,pool,rawPool,authRequired,startMaintenance:false,env:{RETELL_ENABLED:'true',RETELL_ENCRYPTION_KEY:randomBytes(32).toString('base64'),NODE_ENV:'test',MCP_ENABLED:'true',MCP_PUBLIC_ORIGIN:'http://127.0.0.1:18590',MCP_WEB_ORIGIN:'http://127.0.0.1:18589',MCP_REDIRECT_URIS:'["http://127.0.0.1:18591/callback"]'},verifyIdentity:async(email,password)=>{const u=(await pool.query('SELECT id,password_hash FROM users WHERE email=$1',[email])).rows[0];return u&&backend.verifyPassword(password,u.password_hash)?{id:u.id}:null;}});
 app.get('/__mcp_qa/ready',(_req,res)=>res.json({ready:true,company_id:company}));
 clientReceiver=createServer((_req,res)=>{res.writeHead(200,{'Content-Type':'text/html','Cache-Control':'no-store'});res.end('<h1>Client received authorization</h1>');}).listen(18591,'127.0.0.1');
 server=app.listen(18590,'127.0.0.1',()=>console.log('MCP disposable browser fixture ready on loopback 18590'));
}catch(e){await stop();throw e;}
