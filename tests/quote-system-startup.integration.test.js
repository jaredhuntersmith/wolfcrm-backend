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
    // Cached readiness must not be shown as verified after provider keys disappear/change.
    const owner=(await pool.query("INSERT INTO users(email,role) VALUES('stripe-status-owner@example.invalid','employer') RETURNING id")).rows[0].id;
    const company=(await pool.query("INSERT INTO companies(name,join_code) VALUES('Stripe status','STRIPESTAT') RETURNING id")).rows[0].id;
    await pool.query('UPDATE users SET company_id=$2 WHERE id=$1',[owner,company]);
    await pool.query('UPDATE companies SET owner_user_id=$2 WHERE id=$1',[company,owner]);
    await pool.query("INSERT INTO sessions(token,user_id) VALUES('stripe-status-local',$1)",[owner]);
    await pool.query("INSERT INTO business_settings(user_id,company_id,stripe_account_id,stripe_connect_status,stripe_charges_enabled) VALUES($1,$2,'acct_fixture','ready',true)",[owner,company]);
    const statusResponse=await fetch(origin+'/api/payments/connect/status',{headers:{Authorization:'Bearer stripe-status-local'}});
    assert.equal(statusResponse.status,200);
    const paymentSettings=(await statusResponse.json()).settings;
    assert.equal(paymentSettings.stripe_charges_enabled,false);
    assert.equal(paymentSettings.stripe_connect_status,'action_required');
    assert.match(paymentSettings.stripe_connection_error,/not configured/);

    // New Company Comms tasks must be actual To-Do tasks, with private source ACLs
    // applied even through the pre-existing canonical task endpoints.
    const people={};for(const name of ['alice','bob','outside']){
      const user=(await pool.query("INSERT INTO users(email,role,company_id,display_name) VALUES($1,'employee',$2,$3) RETURNING id",[name+'-task@example.invalid',company,name])).rows[0].id;people[name]=user;
      await pool.query("INSERT INTO employee_permissions(user_id,company_id,permission_preset) VALUES($1,$2,'manager')",[user,company]);await pool.query('INSERT INTO sessions(token,user_id) VALUES($1,$2)',[name+'-task',user]);
    }
    const request=async(path,who='alice',body,method=body?'POST':'GET')=>fetch(origin+path,{method,headers:{Authorization:'Bearer '+(who==='owner'?'stripe-status-local':who+'-task'),'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});
    const conversationResponse=await request('/api/comms/conversations','alice',{client_key:'startup-private',member_ids:[people.bob]});assert.equal(conversationResponse.status,200);const conversation=await conversationResponse.json();
    const sentResponse=await request('/api/comms/conversations/'+conversation.id+'/messages','alice',{client_key:'startup-task-source',body:'Private task source'});assert.equal(sentResponse.status,200);const sent=await sentResponse.json();
    const createdResponse=await request('/api/comms/messages/'+sent.id+'/task','alice',{client_key:'startup-task-once',title:'Private canonical task',assignee_ids:[people.bob]});assert.equal(createdResponse.status,200,await createdResponse.clone().text());const task=await createdResponse.json();assert.equal(task.comms_protected,true);assert.match(task.id,/^[0-9a-f-]{36}$/);
    for(const who of ['alice','bob','outside','owner']){const response=await request('/api/todo/tasks',who);assert.equal(response.status,200);const tasks=await response.json();assert.equal(tasks.some(item=>item.id===task.id),['alice','bob'].includes(who));if(['alice','bob'].includes(who))assert.equal(tasks.find(item=>item.id===task.id).comms_protected,true);}
    // Dashboard aggregates are source reads too: hide both content and counts when
    // feature access or private conversation membership is lost.
    const day='2026-10-04T00:00:00.000Z',end='2026-10-05T00:00:00.000Z',due='2026-10-04T12:00:00.000Z';
    await pool.query('UPDATE todo_tasks SET due_date=$2 WHERE id=$1',[task.id,due]);
    await pool.query(`INSERT INTO schedule_events(id,user_id,company_id,created_by,title,start_at,end_at,worker_user_ids,price_cents) VALUES('dashboard-source-job',$1,$2,$1,'Restricted dashboard job',$3,$4,$5,25000)`,[people.bob,company,due,'2026-10-04T13:00:00.000Z',JSON.stringify([people.bob])]);
    await pool.query(`INSERT INTO todo_customer_reminders(id,user_id,title,contact_name,due_date) VALUES('dashboard-reminder',$1,'Restricted customer reminder','Restricted customer',$2)`,[people.bob,due]);
    await pool.query(`INSERT INTO todo_routines(id,user_id,company_id,title,weekdays) VALUES('dashboard-routine',$1,$2,'Restricted routine','[1,2,3,4,5,6,7]')`,[people.bob,company]);
    await pool.query(`INSERT INTO notifications(id,user_id,company_id,kind,title,body,data) VALUES('dashboard-private-notification',$1,$2,'test','Private raw notification','Private raw notification body','{}')`,[people.bob,company]);
    const summaryPath='/api/dashboard/summary?'+new URLSearchParams({now:day,today_start:day,today_end:end,week_start:day,week_end:end,month_start:day,month_end:end,upcoming_end:end,jobs_past_start:day,jobs_upcoming_end:end});
    const dashboard=async(who='bob')=>{const response=await request(summaryPath,who);assert.equal(response.status,200);assert.equal(response.headers.get('cache-control'),'private, no-store');const result=await response.json();assert.equal(result.partial,false,JSON.stringify(result.failed_sources)+' '+output.slice(-5000));return result;};
    const baselineDashboard=await dashboard();assert.equal(baselineDashboard.metrics.jobs_today,1);assert.equal(baselineDashboard.metrics.tasks_today_total,3);assert.equal(baselineDashboard.items.some(row=>row.source_id===task.id),true);assert.match(JSON.stringify(baselineDashboard),/Restricted dashboard job/);assert.doesNotMatch(JSON.stringify(baselineDashboard),/Private raw notification/);
    const setOverrides=async(overrides)=>pool.query('UPDATE employee_permissions SET permission_overrides=$2,permission_revision=permission_revision+1 WHERE user_id=$1',[people.bob,JSON.stringify(overrides)]);
    // The canonical Schedule contains CRM jobs, while Comms meetings remain an
    // independent projection. Schedule-only rights must not expose job payloads,
    // counts or mutate jobs through related availability/weather/assignment APIs.
    const baselineSchedule=await request('/api/schedule','bob');assert.equal(baselineSchedule.status,200);assert.equal(baselineSchedule.headers.get('cache-control'),'private, no-store');assert.match(await baselineSchedule.text(),/Restricted dashboard job/);
    const teamPath='/api/schedule/team?'+new URLSearchParams({start:day,end});const baselineTeam=await request(teamPath,'bob');assert.equal(baselineTeam.status,200);assert.equal(baselineTeam.headers.get('cache-control'),'private, no-store');
    const meetingResponse=await request('/api/comms/meetings','alice',{id:'b1e85415-9a52-4a47-b7d9-b26c360610bb',conversation_id:conversation.id,title:'Independent employee meeting',starts_at:due,duration_minutes:30,timezone:'America/New_York',waiting_room:true,attendee_ids:[people.bob]});assert.equal(meetingResponse.status,200,await meetingResponse.clone().text());const meeting=await meetingResponse.json();
    for(const capability of ['jobs.view','schedule.view']){
      await setOverrides({[capability]:false});const denied=await dashboard();assert.equal(denied.metrics.jobs_today,0);assert.equal(denied.metrics.upcoming_jobs_count,0);assert.equal(denied.metrics.revenue_today_cents,0);assert.doesNotMatch(JSON.stringify(denied),/Restricted dashboard job/);
      for(const [path,method,body] of [
        ['/api/schedule','GET'],[teamPath,'GET'],['/api/schedule/dashboard-source-job','PUT',{title:'Denied overwrite',start:due,end}],['/api/schedule/dashboard-source-job','DELETE'],
        ['/api/schedule/team/'+people.bob+'/availability','PUT',{}],['/api/schedule/team/'+people.bob+'/availability','DELETE'],
        ['/api/weather/risks','GET'],['/api/weather/reschedule/preview','POST',{}],['/api/weather/reschedule','POST',{}],
        ['/api/jobs/dashboard-source-job/assignment-recommendations','GET'],['/api/jobs/dashboard-source-job/assignment-recommendations/apply','POST',{}]
      ]){const response=await request(path,'bob',body,method);assert.equal(response.status,403,capability+' '+path+' '+await response.clone().text());assert.doesNotMatch(await response.text(),/Restricted dashboard job|assigned_minutes|25000/);}
      const meetings=await request('/api/comms/meetings?id='+meeting.id,'bob');assert.equal(meetings.status,200);assert.equal((await meetings.json()).meetings.some(item=>item.id===meeting.id&&item.title==='Independent employee meeting'),true);
      assert.equal((await pool.query("SELECT title FROM schedule_events WHERE id='dashboard-source-job'")).rows[0].title,'Restricted dashboard job');
    }
    await setOverrides({'contacts.view':false});const contactsDenied=await dashboard();assert.equal(contactsDenied.metrics.tasks_today_total,2);assert.doesNotMatch(JSON.stringify(contactsDenied),/Restricted customer/);
    await setOverrides({'tasks.view':false});const tasksDenied=await dashboard();assert.equal(tasksDenied.metrics.tasks_today_total,0);assert.equal(tasksDenied.metrics.tasks_today_completed,0);assert.doesNotMatch(JSON.stringify(tasksDenied),/Private canonical task|Restricted customer|Restricted routine/);
    await setOverrides({});assert.equal((await dashboard()).metrics.tasks_today_total,3);
    assert.equal((await request('/api/todo/tasks/'+task.id,'outside',{title:'Unauthorized overwrite',assignee_ids:[people.outside]},'PUT')).status,403);
    assert.equal((await request('/api/todo/tasks/'+task.id,'alice',{title:'Unsafe audience',assignee_ids:[people.outside]},'PUT')).status,404);
    const updatedTask=await request('/api/todo/tasks/'+task.id,'bob',{title:'Authorized completion',assignee_ids:[people.bob],completed:true},'PUT');assert.equal(updatedTask.status,200,(await updatedTask.clone().text())+' '+output.slice(-5000));
    assert.equal((await updatedTask.json()).comms_protected,true);
    const logBody={kind:'taskCompleted',timestamp:new Date().toISOString(),task_id:task.id,note:'Private completed task title',comms_protected:false};const log=await request('/api/todo/logs/private-task-log','bob',logBody,'PUT');assert.equal(log.status,200,await log.clone().text());assert.equal((await log.json()).comms_protected,true);assert.equal((await (await request('/api/todo/logs','bob')).json()).find(item=>item.id==='private-task-log').note,logBody.note);assert.equal((await request('/api/todo/logs/outsider-task-log','outside',logBody,'PUT')).status,403);
    assert.equal(Number((await pool.query("SELECT count(*) FROM automation_events WHERE subject_id=$1 AND event_type IN ('task.created','task.updated','task.completed')",[task.id])).rows[0].count),0);
    assert.equal(Number((await pool.query("SELECT count(*) FROM comms_automation_outbox WHERE subject_id=$1 AND event_type='comms.task.completed'",[task.id])).rows[0].count),1);
    const current=(await pool.query('SELECT revision FROM conversations WHERE id=$1',[conversation.id])).rows[0];assert.equal((await request('/api/comms/conversations/'+conversation.id+'/members','bob',{expected_revision:current.revision,remove_user_ids:[people.bob]})).status,200);
    assert.equal((await (await request('/api/todo/tasks','bob')).json()).some(item=>item.id===task.id),false);assert.equal((await request('/api/todo/tasks/'+task.id,'bob',{title:'After removal',assignee_ids:[people.bob]},'PUT')).status,403);

    const revokedDashboard=await dashboard();assert.equal(revokedDashboard.metrics.tasks_today_total,2);assert.equal(revokedDashboard.metrics.tasks_today_completed,0);assert.equal(revokedDashboard.items.some(row=>row.source_id===task.id),false);assert.doesNotMatch(JSON.stringify(revokedDashboard),/Authorized completion/);
    assert.equal((await (await request('/api/todo/logs','bob')).json()).some(item=>item.id==='private-task-log'),false);assert.equal((await request('/api/todo/logs/after-revocation-log','bob',logBody,'PUT')).status,403);
    const ownLog=await request('/api/todo/logs/creator-task-log','alice',logBody,'PUT');assert.equal(ownLog.status,200);assert.equal((await request('/api/todo/tasks/'+task.id,'alice',undefined,'DELETE')).status,204);assert.equal((await (await request('/api/todo/logs','alice')).json()).some(item=>item.id==='creator-task-log'),false);assert.equal((await pool.query("SELECT comms_protected FROM todo_logs WHERE id='creator-task-log'")).rows[0].comms_protected,true);

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
