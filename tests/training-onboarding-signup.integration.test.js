import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {installTraining,reconcileTrainingOnboarding} from '../training/index.js';
import {installStorageSchema} from '../media-storage/schema.js';

test('signup enrolls new and joining employees; reconciliation recovers a deferred enrollment',{timeout:120000},async()=>{
  const keep=new Set(['PATH','HOME','TMPDIR','LANG','LC_ALL','SHELL','USER','LOGNAME','TERM','TZ']);
  for(const key of Object.keys(process.env))if(!keep.has(key))delete process.env[key];
  process.env.NODE_ENV='test';
  const local=startLocalPostgres();local.configureEnvironment();let backend,server;
  try{
    backend=await import('../index.js');
    const {app,pool,authRequired}=backend;
    await backend.bootstrap();
    await installStorageSchema(pool);
    const company=randomUUID(),owner=randomUUID();
    await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id,timezone) VALUES($1,'Onboarding fixture','WELCOME22',$2,'America/New_York')",[company,owner]);
    await pool.query("INSERT INTO users(id,email,role,company_id) VALUES($1,'owner-onboarding@example.invalid','employer',$2)",[owner,company]);
    await pool.query("INSERT INTO sessions(token,user_id) VALUES('onboarding-owner',$1)",[owner]);
    app.locals.training=await installTraining({app,pool,authRequired});
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}`;
    const request=async(path,body,ownerAuth=false)=>{
      const response=await fetch(base+path,{method:'POST',headers:{'Content-Type':'application/json',
        ...(ownerAuth?{Authorization:'Bearer onboarding-owner'}:{})},body:JSON.stringify(body)});
      return {status:response.status,body:await response.json()};
    };
    const definition=await request('/api/training/definitions',{kind:'task',title:'First-day safety',blocks:[
      {id:'read',type:'checklist',items:[{id:'safety',text:'Read safety guide'}]}
    ]},true);
    assert.equal(definition.status,200);
    const published=await request(`/api/training/definitions/${definition.body.id}/publish`,{expected_revision:1},true);
    assert.equal(published.status,200);
    const policy=await request('/api/training/onboarding-policies',{
      definition_id:definition.body.id,due_after_days:7,request_key:'first-day'
    },true);
    assert.equal(policy.status,200);
    const oldUser=randomUUID();
    await pool.query("INSERT INTO users(id,email,role,created_at) VALUES($1,'joining-onboarding@example.invalid','employee',now()-interval '30 days')",[oldUser]);
    const password='Synthetic-test-password!98';
    const join=await request('/auth/signup',{email:'joining-onboarding@example.invalid',password,
      role:'employee',join_code:'WELCOME22'});
    assert.equal(join.status,200,JSON.stringify(join.body));
    assert.equal(join.body.user.id,oldUser);
    const fresh=await request('/auth/signup',{email:'fresh-onboarding@example.invalid',password,
      role:'employee',join_code:'WELCOME22'});
    assert.equal(fresh.status,200,JSON.stringify(fresh.body));
    const assigned=await pool.query(`SELECT e.employee_id,a.version_id,a.available_at,a.due_at
      FROM training_onboarding_enrollments e JOIN training_assignments a ON a.id=e.assignment_id
      WHERE e.company_id=$1 ORDER BY e.employee_id`,[company]);
    assert.equal(assigned.rowCount,2);
    assert.deepEqual(assigned.rows.map(row=>row.employee_id).sort(),[oldUser,fresh.body.user.id].sort());
    for(const row of assigned.rows){
      assert.equal(row.version_id,published.body.id);
      assert.equal(new Date(row.due_at)-new Date(row.available_at),7*86400000);
    }
    app.locals.training=null;
    const deferred=await request('/auth/signup',{email:'deferred-onboarding@example.invalid',password,
      role:'employee',join_code:'WELCOME22'});
    assert.equal(deferred.status,200,JSON.stringify(deferred.body));
    assert.equal((await reconcileTrainingOnboarding(pool,{limit:50})).enrolled,1);
    assert.equal((await reconcileTrainingOnboarding(pool,{limit:50})).enrolled,0);
  }finally{
    if(server)await new Promise(resolve=>server.close(resolve));
    if(backend?.pool)await backend.pool.end();
    local.stop();
  }
});
