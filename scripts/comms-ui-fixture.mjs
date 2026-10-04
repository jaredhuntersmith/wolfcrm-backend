// Local simulator QA only. Creates and later destroys its own PostgreSQL cluster.
// Child environment intentionally excludes all inherited credentials/providers.
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {createServer} from 'node:net';
import {writeFileSync,appendFileSync,unlinkSync} from 'node:fs';
import {randomUUID,randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import pg from 'pg';
import {startLocalPostgres} from '../tests/helpers/local-postgres.js';
const database=startLocalPostgres();let pool,child,stopping=false;
// Signal listeners alone do not keep Node alive after a reload replaces the API child.
// Retain this database owner until its explicit cleanup handler finishes.
const fixtureLifetime=setInterval(()=>{},60000);
const statePath='/tmp/wolf-comms-ui-session.json',logPath='/tmp/wolf-comms-ui-backend.log';
async function stop(exitCode=0){if(stopping)return;stopping=true;clearInterval(fixtureLifetime);if(child?.exitCode===null&&child.signalCode===null){const closed=once(child,'close');child.kill('SIGTERM');await closed;}if(pool)await pool.end();database.stop();try{unlinkSync(statePath);}catch{}process.exit(exitCode);}
process.on('SIGTERM',()=>void stop());process.on('SIGINT',()=>void stop());
try{
 const probe=createServer();probe.listen(0,'127.0.0.1');await once(probe,'listening');const port=probe.address().port;await new Promise(resolve=>probe.close(resolve));
 const config=database.config;writeFileSync(logPath,'',{mode:0o600});
 child=spawn(process.execPath,['index.js'],{cwd:fileURLToPath(new URL('..',import.meta.url)),env:{PATH:process.env.PATH,HOME:process.env.HOME,TMPDIR:process.env.TMPDIR,NODE_ENV:'test',PORT:String(port),PGHOST:config.host,PGPORT:String(config.port),PGUSER:config.user,PGDATABASE:config.database,DB_SSL:'false',OWNER_EMAIL:'',WOLFCRM_SKIP_SERVER_START:'false'},stdio:['ignore','pipe','pipe']});
 let startup='';for(const pipe of [child.stdout,child.stderr])pipe.on('data',data=>{appendFileSync(logPath,data);startup=(startup+data.toString()).slice(-100000);});
 await new Promise((resolve,reject)=>{const deadline=setTimeout(()=>{clearInterval(check);reject(Error('Local API startup timeout'));},45000);const check=setInterval(()=>{if(startup.includes('API listening on '+port)){clearTimeout(deadline);clearInterval(check);resolve();}else if(child.exitCode!==null){clearTimeout(deadline);clearInterval(check);reject(Error('Local API exited; inspect fixture log'));}},100);});
 pool=new pg.Pool(config);const company=randomUUID(),people={},tokens={};await pool.query("INSERT INTO companies(id,name,join_code) VALUES($1,'Local QA Crew','LOCAL-QA-COMMS')",[company]);
 for(const [key,name] of Object.entries({owner:'Riley Owner',alice:'Casey Crew',bob:'Morgan Field'})){
  const user=randomUUID(),token=randomBytes(32).toString('hex');people[key]=user;tokens[key]=token;
  await pool.query('INSERT INTO users(id,email,display_name,role,company_id) VALUES($1,$2,$3,$4,$5)',[user,key+'@local-fixture.invalid',name,key==='owner'?'employer':'employee',company]);
  await pool.query("INSERT INTO employee_permissions(user_id,company_id,permission_preset,permission_overrides) VALUES($1,$2,'manager',$3)",[user,company,JSON.stringify(key==='bob'?{'pipeline.view':false}:{})]);
  await pool.query('INSERT INTO sessions(token,user_id) VALUES($1,$2)',[token,user]);
 }
 await pool.query('UPDATE companies SET owner_user_id=$2 WHERE id=$1',[company,people.owner]);
 const origin='http://127.0.0.1:'+port;
 const request=async(path,body,who='alice',method=body?'POST':'GET')=>{const response=await fetch(origin+'/api/comms'+path,{method,headers:{Authorization:'Bearer '+tokens[who],'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});if(!response.ok)throw Error('Fixture request '+path+' returned '+response.status+': '+await response.text());return response.json();};
 const group=await request('/groups',{id:randomUUID(),name:'Field Operations',description:'Local QA fixture only',member_ids:[people.bob],visibility:'invite'});
 await request('/groups/'+group.group.id+'/membership',{action:'join',accept_history:true},'bob');
 const general=group.threads.find(t=>t.kind==='general').conversation_id;
 await request('/conversations/'+general+'/messages',{client_key:'fixture-welcome',body:'Today’s plan\n\nCheck equipment before heading out. Post a handoff when your job is complete.'});
 const replyRoot=await request('/conversations/'+general+'/messages',{client_key:'fixture-question',body:'Can someone confirm the ladder inspection?'},'bob');
 await request('/conversations/'+general+'/messages',{client_key:'fixture-reply',body:'Inspected and ready.',reply_root_id:replyRoot.id});
 await request('/conversations/'+general+'/notes',{client_key:'fixture-sop',title:'Morning equipment check',body:'## Before leaving\n\n- [ ] Inspect ladders\n- [ ] Charge batteries\n- [ ] Confirm the route\n\nReport equipment issues in this conversation.'});
 await request('/conversations/'+general+'/polls',{client_key:'fixture-poll',question:'Which time works for tomorrow’s huddle?',options:['7:30 AM','8:00 AM','8:30 AM']});
 const dm=await request('/conversations',{client_key:'fixture-dm',member_ids:[people.bob]});await request('/conversations/'+dm.id+'/messages',{client_key:'fixture-dm-message',body:'The supplies are ready for pickup.'},'bob');
 const contact=randomUUID(),job=randomUUID();await pool.query("INSERT INTO contacts(id,user_id,company_id,name,address) VALUES($1,$2,$3,'Local QA Customer','Fixture address')",[contact,people.alice,company]);
 await pool.query("INSERT INTO schedule_events(id,user_id,company_id,title,start_at,end_at,contact_id,worker_user_ids) VALUES($1,$2,$3,'Fixture service visit',now()+interval '2 hours',now()+interval '3 hours',$4,$5)",[job,people.alice,company,contact,JSON.stringify([people.alice,people.bob])]);
 await request('/conversations/'+general+'/messages',{client_key:'fixture-job-card',body:'Job context for the assigned team',cards:[{source_type:'job',source_id:job}]});
 await pool.query("INSERT INTO notifications(id,user_id,company_id,kind,title,body) VALUES($1,$2,$3,'comms.fixture','Local fixture notification','Tap to expand this text. This must never open a job or message.')",[randomUUID(),people.alice,company]);
 writeFileSync(statePath,JSON.stringify({origin,fixture_owner_pid:process.pid,company,people,tokens,group:group.group.id,general,dm:dm.id,job,database:config},null,2),{mode:0o600});
 console.log('Local UI fixture ready at '+origin+'; session and IDs saved privately in '+statePath+'. Providers are disabled.');
}catch(error){console.error(error.message);await stop(1);}
