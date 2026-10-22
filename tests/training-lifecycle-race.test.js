import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining} from '../training/index.js';

const draft={kind:'task',title:'Private onboarding note',scope:'personal',
  blocks:[{id:'intro',type:'instruction',text:'Read before starting.'}]};

async function blockedBy(pool,pid,fragment){
  for(let attempt=0;attempt<120;attempt++){
    const result=await pool.query(`SELECT 1 FROM pg_stat_activity
      WHERE pid<>pg_backend_pid() AND wait_event_type='Lock'
        AND ($1::integer=0 OR $1::integer=ANY(pg_blocking_pids(pid)))
        AND query LIKE $2 LIMIT 1`,[pid,`%${fragment}%`]);
    if(result.rowCount)return;
    await new Promise(resolve=>setTimeout(resolve,25));
  }
  throw new Error(`Expected blocked PostgreSQL query: ${fragment}`);
}

test('training personal writes serialize with account disable in either lock order',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express();let server;
  const company=fixture.companies.a,alice=fixture.ids.alice;
  try{
    app.use(express.json());
    const auth=(req,res,next)=>{req.userId=alice;req.companyId=company;next();};
    await installTraining({app,pool:fixture.pool,authRequired:auth});
    await fixture.pool.query('UPDATE employee_permissions SET permission_overrides=$2 WHERE user_id=$1',
      [alice,JSON.stringify({'training.author':true,'training.publish':true})]);
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,method,body)=>{const response=await fetch(base+path,{method,
      headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});return {status:response.status,body:await response.json()};};

    // Cleanup gets the company lock first: the request may already be in flight,
    // but it must reload the disabled actor after waiting and write no bank row.
    const cleanup=await fixture.pool.connect();
    try{
      await cleanup.query('BEGIN');
      await cleanup.query('SELECT id FROM companies WHERE id=$1 FOR UPDATE',[company]);
      const pending=request('/question-banks','POST',{title:'Late private bank',scope:'personal',
        question:{id:'q',type:'true_false',prompt:'Ready?',answer:true}});
      await blockedBy(fixture.pool,cleanup.processID,'FROM companies WHERE id=$1 FOR KEY SHARE');
      await cleanup.query('UPDATE users SET deleted_at=now() WHERE id=$1',[alice]);
      await cleanup.query('COMMIT');
      assert.equal((await pending).status,403);
      assert.equal((await fixture.pool.query(`SELECT count(*)::int AS n FROM training_question_banks
        WHERE company_id=$1 AND created_by=$2`,[company,alice])).rows[0].n,0);
    }finally{await cleanup.query('ROLLBACK').catch(()=>{});cleanup.release();}

    await fixture.pool.query('UPDATE users SET deleted_at=NULL WHERE id=$1',[alice]);
    const created=await request('/definitions','POST',draft);assert.equal(created.status,200);
    // The write gets the company lock first, then waits on its draft row. Disable
    // must wait for that write to commit and can purge it afterward.
    const rowBlocker=await fixture.pool.connect(),disabler=await fixture.pool.connect();
    try{
      await rowBlocker.query('BEGIN');
      await rowBlocker.query('SELECT id FROM training_definitions WHERE id=$1 FOR UPDATE',[created.body.id]);
      const pending=request(`/definitions/${created.body.id}`,'PUT',{...draft,title:'Edited before disable',expected_revision:1});
      await blockedBy(fixture.pool,rowBlocker.processID,'FROM training_definitions WHERE company_id');
      await disabler.query('BEGIN');
      const lockPromise=disabler.query('SELECT id FROM companies WHERE id=$1 FOR UPDATE',[company]);
      await blockedBy(fixture.pool,0,'FROM companies WHERE id=$1 FOR UPDATE');
      await rowBlocker.query('COMMIT');
      assert.equal((await pending).status,200);
      await lockPromise;
      await disabler.query('UPDATE users SET deleted_at=now() WHERE id=$1',[alice]);
      await disabler.query('COMMIT');
      assert.equal((await fixture.pool.query('SELECT title FROM training_definitions WHERE id=$1',[created.body.id])).rows[0].title,
        'Edited before disable');
      assert.equal((await request(`/definitions/${created.body.id}`,'PUT',{...draft,expected_revision:2})).status,403);
    }finally{
      await rowBlocker.query('ROLLBACK').catch(()=>{});rowBlocker.release();
      await disabler.query('ROLLBACK').catch(()=>{});disabler.release();
    }
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
