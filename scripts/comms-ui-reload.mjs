// Restarts only a verified disposable UI-fixture API, preserving its local DB/session.
// Stop this helper before stopping comms-ui-fixture.mjs, which owns DB cleanup.
import {readFileSync,writeFileSync,appendFileSync} from 'node:fs';
import {execFileSync,spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {once} from 'node:events';
const path='/tmp/wolf-comms-ui-session.json',state=JSON.parse(readFileSync(path));
const origin=new URL(state.origin),config=state.database,cwd=fileURLToPath(new URL('..',import.meta.url));
if(origin.hostname!=='127.0.0.1'||!origin.port||!/^\/tmp\/wolfcrm-test-pg-[^/]+\/socket$/.test(config.host)||config.database!=='postgres')throw Error('Not the disposable fixture');
const processes=execFileSync('ps',['-A','-o','pid=,ppid=,command='],{encoding:'utf8'}).split('\n').map(line=>line.trim().match(/^(\d+)\s+(\d+)\s+(.+)$/)).filter(Boolean);
const parents=processes.filter(row=>['node scripts/comms-ui-fixture.mjs','node scripts/comms-ui-reload.mjs'].includes(row[3]));
const candidates=processes.filter(row=>parents.some(parent=>parent[1]===row[2])&&row[3].endsWith('/node index.js'));
const matching=candidates.filter(row=>execFileSync('lsof',['-a','-p',row[1],'-d','cwd','-Fn'],{encoding:'utf8'}).split('\n').includes('n'+cwd.replace(/\/$/,'')));
if(matching.length!==1)throw Error('A unique verified local API child was not found');
const oldPID=Number(matching[0][1]);process.kill(oldPID,'SIGTERM');
for(let n=0;n<100;n++){try{process.kill(oldPID,0);}catch{break;}await new Promise(resolve=>setTimeout(resolve,50));if(n===99)throw Error('Previous local API did not exit');}
const child=spawn(process.execPath,['index.js'],{cwd,env:{PATH:process.env.PATH,HOME:process.env.HOME,TMPDIR:process.env.TMPDIR,NODE_ENV:'test',PORT:origin.port,PGHOST:config.host,PGPORT:String(config.port),PGUSER:config.user,PGDATABASE:config.database,DB_SSL:'false',OWNER_EMAIL:'',WOLFCRM_SKIP_SERVER_START:'false'},stdio:['ignore','pipe','pipe']});
let output='',ready=false,stopping=false;
writeFileSync(path,JSON.stringify({...state,reload_helper_pid:process.pid,reload_api_pid:child.pid},null,2),{mode:0o600});
for(const stream of [child.stdout,child.stderr])stream.on('data',data=>{appendFileSync('/tmp/wolf-comms-ui-backend.log',data);output=(output+data.toString()).slice(-100000);if(!ready&&output.includes('API listening on '+origin.port)){ready=true;console.log('Disposable UI API reloaded. Existing sessions, local records and port preserved.');}});
async function stop(){if(stopping)return;stopping=true;if(child.exitCode===null&&child.signalCode===null){const closed=once(child,'close');child.kill('SIGTERM');await closed;}writeFileSync(path,JSON.stringify(state,null,2),{mode:0o600});process.exit(0);}
process.on('SIGTERM',()=>void stop());process.on('SIGINT',()=>void stop());
child.on('exit',code=>{if(!stopping){console.error('Disposable UI API exited:',code);process.exitCode=code||1;}});
