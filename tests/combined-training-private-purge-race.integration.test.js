import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installNotesSchema} from '../notes/schema.js';
import {installEmployeeAccountSchema} from '../employee-access/schema.js';
import {createEmployeeAccountService} from '../employee-access/service.js';
import {installPrivatePurgeSchema,createPrivatePurge} from '../employee-access/purge.js';
import {installTraining} from '../training/index.js';

const draft={kind:'task',title:'Personal draft during disable',scope:'personal',
  blocks:[{id:'intro',type:'instruction',text:'Read this first.'}]};

async function waitForBlocked(pool,queryFragment){
  for(let attempt=0;attempt<120;attempt++){
    const found=await pool.query(`SELECT 1 FROM pg_stat_activity
      WHERE pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE $1 LIMIT 1`,[`%${queryFragment}%`]);
    if(found.rowCount)return;
    await new Promise(resolve=>setTimeout(resolve,25));
  }
  throw new Error(`Expected PostgreSQL lock wait: ${queryFragment}`);
}

test('training writes and actual private purge serialize without losing or recreating personal drafts',
  {timeout:120000},async()=>{
    const fixture=await createCommsFixture(),{pool,ids,companies}=fixture,app=express();let server;
    const company=companies.a,owner={userId:ids.owner,companyId:company};
    const lock=await pool.connect();
    try{
      await pool.query('ALTER TABLE users ADD COLUMN deleted_by uuid; ALTER TABLE users ADD COLUMN pre_delete_email text; CREATE TABLE sessions(token text PRIMARY KEY,user_id uuid);');
      await installNotesSchema(pool);await installEmployeeAccountSchema(pool);await installPrivatePurgeSchema(pool);
      app.use(express.json());
      const auth=(req,res,next)=>{req.userId=req.get('X-Fixture-User')==='bob'?ids.bob:ids.alice;req.companyId=company;next();};
      await installTraining({app,pool,authRequired:auth});
      await pool.query('UPDATE employee_permissions SET permission_overrides=$2 WHERE user_id=ANY($1::uuid[])',
        [[ids.alice,ids.bob],JSON.stringify({'training.author':true})]);
      server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
      const request=async who=>{const response=await fetch(`http://127.0.0.1:${server.address().port}/api/training/definitions`,{
        method:'POST',headers:{'Content-Type':'application/json','X-Fixture-User':who},body:JSON.stringify(draft)});
        return {status:response.status,body:await response.json()};};
      const accounts=createEmployeeAccountService({pool});
      const purge=createPrivatePurge({pool,bucket:{abort:async()=>{},remove:async()=>{}}});

      // A write already holding the company key-share lock commits first. The
      // following disable and purge must see and remove that exact new draft.
      await lock.query('BEGIN');
      await lock.query('LOCK TABLE training_definitions IN SHARE MODE');
      const aliceWrite=request('alice');
      await waitForBlocked(pool,'INSERT INTO training_definitions');
      const disableAlice=accounts.transition(owner,ids.alice,'disable',{expected_revision:1});
      await waitForBlocked(pool,'FROM companies WHERE id=$1 FOR UPDATE');
      await lock.query('COMMIT');
      const created=await aliceWrite;assert.equal(created.status,200);
      await disableAlice;
      const alicePreview=await purge.preview(owner,ids.alice);
      assert.equal(alicePreview.private_training_drafts,1);
      await purge.request(owner,ids.alice,{...alicePreview,confirmation:'DELETE PRIVATE DATA'});
      assert.equal((await pool.query('SELECT 1 FROM training_definitions WHERE id=$1',[created.body.id])).rowCount,0);
      assert.notEqual((await request('alice')).status,200);

      // When cleanup holds the company lock first, a later request waits,
      // reloads the disabled actor, and creates no row to survive the purge.
      await lock.query('BEGIN');
      await lock.query('SELECT id FROM companies WHERE id=$1 FOR UPDATE',[company]);
      const bobWrite=request('bob');
      await waitForBlocked(pool,'FROM companies WHERE id=$1 FOR KEY SHARE');
      await lock.query("UPDATE users SET deleted_at=now(),private_data_state='recoverable' WHERE id=$1",[ids.bob]);
      await lock.query('COMMIT');
      assert.notEqual((await bobWrite).status,200);
      const bobPreview=await purge.preview(owner,ids.bob);
      assert.equal(bobPreview.private_training_drafts,0);
      await purge.request(owner,ids.bob,{...bobPreview,confirmation:'DELETE PRIVATE DATA'});
      assert.equal((await pool.query('SELECT count(*)::int AS n FROM training_definitions WHERE created_by=$1',[ids.bob])).rows[0].n,0);
    }finally{
      await lock.query('ROLLBACK').catch(()=>{});lock.release();
      if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();
    }
  });
