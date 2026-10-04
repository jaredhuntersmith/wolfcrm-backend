import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {createServer} from 'node:net';
import {fileURLToPath} from 'node:url';
import {randomUUID} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import pg from 'pg';
import {startLocalPostgres} from './helpers/local-postgres.js';

test('real index startup: Comms and permanent inbox work without any optional provider', {timeout:90000}, async t => {
  const postgres = startLocalPostgres(), pool = new pg.Pool(postgres.config);
  let child, origin;
  const stop = async () => { if (child && child.exitCode === null) { const closed = once(child,'close'); child.kill('SIGTERM'); await closed; } };
  const start = async () => {
    const probe=createServer(); probe.listen(0,'127.0.0.1'); await once(probe,'listening');
    const port=probe.address().port; await new Promise(resolve=>probe.close(resolve));
    const config=postgres.config;
    // Allowlist, never spread process.env: excludes every production/provider credential.
    const env={PATH:process.env.PATH,HOME:process.env.HOME,TMPDIR:process.env.TMPDIR,NODE_ENV:'test',PORT:String(port),PGHOST:config.host,PGPORT:String(config.port),PGUSER:config.user,PGDATABASE:config.database,DB_SSL:'false',OWNER_EMAIL:'',WOLFCRM_SKIP_SERVER_START:'false'};
    assert.equal(Object.keys(env).some(k=>/LIVEKIT|APNS|OPENAI|COMMS_|S3|AWS/.test(k)),false);
    child=spawn(process.execPath,['index.js'],{cwd:fileURLToPath(new URL('..',import.meta.url)),env,stdio:['ignore','pipe','pipe']});
    let output=''; for(const stream of [child.stdout,child.stderr])stream.on('data',data=>{output=(output+data).slice(-15000);});
    await new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>{clearInterval(poll);reject(Error('API startup timeout: '+output));},30000);
      const poll=setInterval(()=>{if(output.includes('API listening on '+port)){clearTimeout(timer);clearInterval(poll);resolve();}else if(child.exitCode!==null){clearTimeout(timer);clearInterval(poll);reject(Error(output));}},30);
    }); origin='http://127.0.0.1:'+port;
  };
  const people={}, companies={};
  const request=async(path,who='owner',body,method=body?'POST':'GET')=>{
    const response=await fetch(origin+path,{method,headers:{...(who?{Authorization:'Bearer local-startup-'+who}:{}),'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
    assert.match(response.headers.get('content-type')||'',/^application\/json/,path);
    assert.match(response.headers.get('x-request-id')||'',/^[a-f0-9-]{36}$/);
    return {status:response.status,body:await response.json()};
  };
  const ok=async(...args)=>{const r=await request(...args);assert.equal(r.status,200,JSON.stringify(r));return r.body;};
  try {
    await start();
    for(const who of ['owner','peer','denied','foreign']){
      const company=who==='foreign'?randomUUID():(companies.main ||=randomUUID());companies[who]=company;
      if(who==='owner'||who==='foreign')await pool.query('INSERT INTO companies(id,name,join_code) VALUES($1,$2,$3)',[company,who+' fictional company',randomUUID()]);
      const user=randomUUID();people[who]=user;
      await pool.query('INSERT INTO users(id,email,role,company_id,display_name) VALUES($1,$2,$3,$4,$5)',[user,who+'@startup.invalid',['owner','foreign'].includes(who)?'employer':'employee',company,who]);
      if(['owner','foreign'].includes(who))await pool.query('UPDATE companies SET owner_user_id=$2 WHERE id=$1',[company,user]);
      else await pool.query("INSERT INTO employee_permissions(user_id,company_id,permission_preset,permission_overrides) VALUES($1,$2,'manager',$3)",[user,company,who==='denied'?JSON.stringify({'communications.view':false,'notifications.view':false}):'{}']);
      await pool.query('INSERT INTO sessions(token,user_id) VALUES($1,$2)',['local-startup-'+who,user]);
    }
    await t.test('both routes are installed, JSON and independently authorized',async()=>{
      for(const path of ['/api/comms/bootstrap','/api/comms/notifications']){
        assert.equal((await request(path,null)).status,401);
        assert.equal((await request(path,'invalid')).status,401);
        const denied=await request(path,'denied');assert.equal(denied.status,403);assert.doesNotMatch(JSON.stringify(denied.body),/fictional|local-startup/);
      }
      assert.equal((await ok('/api/comms/bootstrap')).calls.configured,false);
    });
    const group=await ok('/api/comms/groups','owner',{id:randomUUID(),name:'Startup Field Crew',visibility:'invite',member_ids:[]});
    const dm=await ok('/api/comms/conversations','owner',{client_key:'startup-dm',title:'Startup conversation',member_ids:[people.peer]});
    const message=await ok('/api/comms/conversations/'+dm.id+'/messages','owner',{client_key:'persisted-message',body:'Persisted startup message'});
    const notificationIDs=['one','two','three'].map(x=>'startup-notification-'+x);
    for(const id of notificationIDs)await pool.query("INSERT INTO notifications(id,user_id,company_id,kind,title,body,conversation_id) VALUES($1,$2,$3,'comms.message','Startup notification','Fictional stored inbox body',$4)",[id,people.owner,companies.main,dm.id]);
    await t.test('bootstrap returns real Channels and conversations; inbox matches native contract',async()=>{
      const bootstrap=await ok('/api/comms/bootstrap');assert.equal(bootstrap.version,1);assert.ok(bootstrap.groups.some(x=>x.id===group.group.id));assert.ok(bootstrap.conversations.some(x=>x.id===dm.id));assert.equal(typeof bootstrap.capabilities['communications.view'],'boolean');
      const inbox=await ok('/api/comms/notifications');assert.equal(typeof inbox.unread_count,'number');assert.ok(inbox.notifications.some(x=>x.id===notificationIDs[0]));
      for(const row of inbox.notifications){for(const key of ['id','kind','title','created_at'])assert.equal(typeof row[key],'string');assert.ok(Number.isFinite(Date.parse(row.created_at)));}
      const foreign=await ok('/api/comms/bootstrap','foreign');assert.equal(foreign.conversations.length,0);assert.equal(foreign.groups.length,0);assert.equal((await ok('/api/comms/notifications','foreign')).notifications.length,0);
      assert.equal((await request('/api/comms/conversations/'+dm.id+'/messages','foreign')).status,404);
      // Explicit opt-in writes only fictional HTTP responses, never tokens, for Swift decoder tests.
      if(process.env.COMMS_WRITE_NATIVE_FIXTURES==='true')writeFileSync(new URL('./fixtures/comms-startup-native.json',import.meta.url),JSON.stringify({bootstrap,inbox},null,2)+'\n');
    });
    await t.test('read, sharing, single and multi deletion persist with recipient isolation',async()=>{
      await ok('/api/comms/notifications/read','owner',{ids:[notificationIDs[0]],read:true});
      assert.ok((await ok('/api/comms/notifications')).notifications.find(x=>x.id===notificationIDs[0]).read_at);
      const shared=await ok('/api/comms/conversations/'+dm.id+'/messages','owner',{client_key:'share-notification',cards:[{source_type:'notification',source_id:notificationIDs[0]}]});
      assert.match(shared.cards[0].text,/Startup notification/);assert.equal(shared.cards[0].interactive,false);
      await ok('/api/comms/notifications/'+notificationIDs[0],'owner',undefined,'DELETE');
      await ok('/api/comms/notifications/delete','owner',{ids:notificationIDs.slice(1),confirm:true});
      assert.ok((await ok('/api/comms/notifications')).notifications.every(x=>!notificationIDs.includes(x.id)));
      assert.equal((await pool.query('SELECT count(*)::int AS n FROM notifications WHERE id=ANY($1::text[]) AND deleted_at IS NOT NULL',[notificationIDs])).rows[0].n,3);
      assert.ok((await ok('/api/comms/conversations/'+dm.id+'/messages','peer')).messages.some(x=>x.id===message.id));
      assert.equal((await request('/api/comms/notifications/'+notificationIDs[0],'foreign')).status,404);
    });
    await t.test('inbox remains independent from Comms feature permission and APNs',async()=>{
      await pool.query("UPDATE employee_permissions SET permission_overrides='{}' WHERE user_id=$1",[people.denied]);
      await pool.query("UPDATE employee_permissions SET permission_overrides='{\"communications.view\":false}' WHERE user_id=$1",[people.denied]);
      assert.equal((await request('/api/comms/bootstrap','denied')).status,403);
      assert.equal((await request('/api/comms/notifications','denied')).status,200);
      assert.equal((await ok('/api/comms/bootstrap')).calls.configured,false);
      const call=await request('/api/comms/calls','owner',{id:randomUUID(),conversation_id:dm.id,kind:'audio'});assert.equal(call.status,503);assert.equal(call.body.error,'calling_not_configured');
    });
    await t.test('JSON API fallbacks preserve real routes, public routes and customer/Media reads',async()=>{
      const missing=await request('/api/comms/no-such-route');assert.equal(missing.status,404);assert.equal(missing.body.error,'api_route_not_found');
      const malformed=await fetch(origin+'/api/comms/groups',{method:'POST',headers:{'Content-Type':'application/json'},body:'{private invalid body'});assert.equal(malformed.status,400);assert.deepEqual(await malformed.json(),{error:'invalid_json',message:'The request body is invalid.'});
      assert.equal((await request('/api/public/agreements/not-valid',null)).body.error,'agreement_link_invalid');
      for(const path of ['/api/phone/conversations','/api/phone/calls','/api/phone/voicemails','/api/storage/files'])assert.equal((await request(path)).status,200,path);
      const outside=await fetch(origin+'/not-an-api-route');assert.equal(outside.status,404);assert.match(outside.headers.get('content-type'),/text\/html/);
    });
    await stop();await start();
    await t.test('real restart preserves message, Channel identity and deletion tombstones',async()=>{
      assert.ok((await ok('/api/comms/bootstrap')).groups.some(x=>x.id===group.group.id));
      assert.ok((await ok('/api/comms/conversations/'+dm.id+'/messages')).messages.some(x=>x.id===message.id&&x.body==='Persisted startup message'));
      assert.ok((await ok('/api/comms/notifications')).notifications.every(x=>!notificationIDs.includes(x.id)));
      assert.equal((await pool.query('SELECT count(*)::int AS n FROM notifications WHERE id=ANY($1::text[]) AND deleted_at IS NOT NULL',[notificationIDs])).rows[0].n,3);
    });
  } finally {await stop();await pool.end();postgres.stop();}
});
