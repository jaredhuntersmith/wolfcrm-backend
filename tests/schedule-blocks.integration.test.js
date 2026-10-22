import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {startLocalPostgres} from './helpers/local-postgres.js';

test('time off approval, private visibility and the canonical job guard share one schedule',{timeout:60000},async()=>{
 const pg=startLocalPostgres();pg.configureEnvironment();let pool,server;
 try{
  const backend=await import('../index.js');pool=backend.pool;await backend.bootstrap();
  const company=randomUUID(),owner=randomUUID(),technician=randomUUID(),other=randomUUID();
  await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id,timezone) VALUES($1,'Blocks fixture',$3,$2,'America/New_York')",[company,owner,company]);
  for(const [id,role] of [[owner,'employer'],[technician,'employee'],[other,'employee']]){
   await pool.query('INSERT INTO users(id,email,role,company_id) VALUES($1,$2,$3,$4)',[id,id+'@example.invalid',role,company]);
   await pool.query('INSERT INTO sessions(token,user_id) VALUES($1,$2)',['blocks-'+id,id]);
  }
  for(const id of [technician,other])await pool.query("INSERT INTO employee_permissions(user_id,company_id,permission_preset) VALUES($1,$2,'technician')",[id,company]);
  server=await new Promise(resolve=>{const listener=backend.app.listen(0,'127.0.0.1',()=>resolve(listener));});
  const origin='http://127.0.0.1:'+server.address().port;
  const request=async(path,who,method='GET',body)=>{
   const response=await fetch(origin+path,{method,headers:{Authorization:'Bearer blocks-'+who,'Content-Type':'application/json'},body:body==null?undefined:JSON.stringify(body)});
   return {status:response.status,body:await response.json()};
  };
  const settings=await request('/api/schedule/time-off-settings',technician);
  assert.equal(settings.status,200);assert.equal(settings.body.time_off_approval_required,true);assert.equal(settings.body.can_review,false);
  const id=randomUUID(),start='2026-11-01T01:30:00-04:00',end='2026-11-01T02:30:00-05:00';
  const submit=await request('/api/schedule/blocks/'+id,technician,'PUT',{kind:'time_off',title:'Personal time off',start_at:start,end_at:end});
  assert.equal(submit.status,200,JSON.stringify(submit.body));assert.equal(submit.body.status,'pending');assert.equal(submit.body.affects_availability,false);
  assert.equal((await request('/api/schedule/blocks?scope=team&start=2026-11-01T00:00:00Z&end=2026-11-02T00:00:00Z',other)).body.blocks.length,0);
  const ownerBlocks=await request('/api/schedule/blocks?scope=team&start=2026-11-01T00:00:00Z&end=2026-11-02T00:00:00Z',owner);
  assert.equal(ownerBlocks.body.blocks.length,1);
  const jobID='block-test-job';
  await pool.query("INSERT INTO schedule_events(id,user_id,company_id,title,start_at,end_at,worker_user_ids) VALUES($1,$2,$3,'Existing job',$4,$5,$6::jsonb)",[jobID,owner,company,start,end,JSON.stringify([technician])]);
  const denied=await request('/api/schedule/blocks/'+id+'/decision',owner,'POST',{decision:'approved',expected_revision:1});
  assert.equal(denied.status,409);assert.equal((await pool.query('SELECT status FROM schedule_blocks WHERE id=$1',[id])).rows[0].status,'pending');
  await pool.query('DELETE FROM schedule_events WHERE id=$1',[jobID]);
  const approved=await request('/api/schedule/blocks/'+id+'/decision',owner,'POST',{decision:'approved',expected_revision:1});
  assert.equal(approved.status,200,JSON.stringify(approved.body));assert.equal(approved.body.affects_availability,true);
  await assert.rejects(()=>pool.query("INSERT INTO schedule_events(id,user_id,company_id,title,start_at,end_at,worker_user_ids) VALUES($1,$2,$3,'Blocked job',$4,$5,$6::jsonb)",[jobID,owner,company,start,end,JSON.stringify([technician])]),error=>error.code==='23P01');
  const eventID=randomUUID();
  const event=await request('/api/schedule/blocks/'+eventID,technician,'PUT',{kind:'event',title:'Training',start_at:start,end_at:end});
  assert.equal(event.status,200);assert.equal(event.body.affects_availability,false);
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM schedule_events WHERE company_id=$1',[company])).rows[0].n,0);
  assert.equal((await request('/api/schedule/blocks/'+id+'/decision',technician,'POST',{decision:'rejected',expected_revision:2})).status,403);
  assert.equal((await request('/api/schedule/blocks/'+id,technician,'DELETE')).status,200);
  assert.equal((await pool.query('SELECT count(*)::int AS n FROM schedule_block_decisions WHERE block_id=$1',[id])).rows[0].n,1);
  assert.equal((await request('/api/schedule/time-off-settings',technician,'PUT',{approval_required:false})).status,403);
  assert.equal((await request('/api/schedule/time-off-settings',owner,'PUT',{approval_required:false})).status,200);
  const direct=await request('/api/schedule/blocks/'+randomUUID(),technician,'PUT',{kind:'time_off',title:'No review needed',start_at:'2026-11-03T09:00:00-05:00',end_at:'2026-11-03T12:00:00-05:00'});
  assert.equal(direct.status,200);assert.equal(direct.body.status,'approved');assert.equal(direct.body.affects_availability,true);
 }finally{if(server)await new Promise(resolve=>server.close(resolve));if(pool)await pool.end();pg.stop();}
});
