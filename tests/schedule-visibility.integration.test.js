import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {startLocalPostgres} from './helpers/local-postgres.js';

test('assigned staff see only their jobs, while owner sees the team', {timeout:60000}, async () => {
  const pg=startLocalPostgres();pg.configureEnvironment();let pool,server;
  try {
    const backend=await import('../index.js');pool=backend.pool;await backend.bootstrap();
    const company=randomUUID(),owner=randomUUID(),worker=randomUUID(),other=randomUUID();
    await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id,timezone) VALUES($1,'Visibility fixture',$3,$2,'America/New_York')",[company,owner,company]);
    for(const [id,role] of [[owner,'employer'],[worker,'employee'],[other,'employee']]) {
      await pool.query('INSERT INTO users(id,email,role,company_id) VALUES($1,$2,$3,$4)',[id,id+'@example.invalid',role,company]);
      await pool.query('INSERT INTO sessions(token,user_id) VALUES($1,$2)',['visible-'+id,id]);
    }
    for(const id of [worker,other]) await pool.query("INSERT INTO employee_permissions(user_id,company_id,permission_preset) VALUES($1,$2,'technician')",[id,company]);
    const mine='visibility-mine',theirs='visibility-theirs',start='2026-11-10T14:00:00Z',end='2026-11-10T15:00:00Z';
    for(const [id,assignee] of [[mine,worker],[theirs,other]]) await pool.query(
      "INSERT INTO schedule_events(id,user_id,company_id,title,start_at,end_at,worker_user_ids) VALUES($1,$2,$3,$1,$4,$5,$6::jsonb)",
      [id,owner,company,start,end,JSON.stringify([assignee])]);
    server=await new Promise(resolve=>{const listener=backend.app.listen(0,'127.0.0.1',()=>resolve(listener));});
    const origin='http://127.0.0.1:'+server.address().port;
    const get=async(path,who)=>{
      const response=await fetch(origin+path,{headers:{Authorization:'Bearer visible-'+who}});
      return {status:response.status,body:await response.json()};
    };
    const own=await get('/api/schedule',worker);
    assert.equal(own.status,200,JSON.stringify(own.body));
    assert.deepEqual(own.body.map(job=>job.id),[mine]);
    assert.deepEqual((await get('/api/schedule',owner)).body.map(job=>job.id).sort(),[mine,theirs]);
    assert.equal((await get('/api/jobs/'+theirs+'/photos',worker)).status,404);
    assert.equal((await get('/api/jobs/'+mine+'/photos',worker)).status,200);
    const team=await get('/api/schedule/team?start=2026-11-10T00:00:00Z&end=2026-11-11T00:00:00Z',worker);
    assert.equal(team.status,200,JSON.stringify(team.body));
    assert.deepEqual(team.body.members.map(member=>member.id),[worker]);
    assert.equal((await get('/api/schedule/team?start=2026-11-10T00:00:00Z&end=2026-11-11T00:00:00Z',owner)).body.members.length,3);
    const solo=randomUUID();
    await pool.query("INSERT INTO users(id,email,role) VALUES($1,$2,'employer')",[solo,solo+'@example.invalid']);
    await pool.query('INSERT INTO sessions(token,user_id) VALUES($1,$2)',['visible-'+solo,solo]);
    await pool.query("INSERT INTO schedule_events(id,user_id,title,start_at,end_at) VALUES('visibility-solo',$1,'Solo job',$2,$3)",[solo,start,end]);
    const legacy=await get('/api/schedule',solo);
    assert.equal(legacy.status,200,JSON.stringify(legacy.body));
    assert.deepEqual(legacy.body.map(job=>job.id),['visibility-solo']);
  } finally {if(server)await new Promise(resolve=>server.close(resolve));if(pool)await pool.end();pg.stop();}
});
