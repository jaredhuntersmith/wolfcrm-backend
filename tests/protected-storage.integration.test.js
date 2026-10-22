import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {createStorageService} from '../media-storage/service.js';
import {storagePredicate} from '../company-comms/assets.js';

test('registered protected files enforce domain audience and actions across storage paths',{timeout:120000},async()=>{
  const f=await createCommsFixture(),{pool,ids,companies}=f;let unregister;
  try{
    await pool.query('ALTER TABLE users ADD COLUMN locked_at timestamptz; CREATE TABLE test_training_refs(file_id uuid REFERENCES stored_files(id),company_id uuid,user_id uuid,allowed boolean DEFAULT true)');
    const service=createStorageService({pool,accessPredicate:storagePredicate,bucket:{access:async()=> 'https://example.invalid/private',begin:async()=> 'upload',part:async()=> 'https://example.invalid/part'}});
    unregister=service.registerProtectedStorageScope('training_test',{
      predicate:async()=>`EXISTS(SELECT 1 FROM test_training_refs r WHERE r.file_id=f.id AND r.company_id=$2 AND r.user_id=$1 AND r.allowed)`,
      authorizeAccess:async(db,actor,file,purpose)=>{
        const allowed=(await db.query('SELECT 1 FROM test_training_refs WHERE file_id=$1 AND user_id=$2 AND company_id=$3 AND allowed',[file.id,actor.userId,actor.companyId])).rowCount;
        if(!allowed||['download','edit','delete'].includes(purpose))throw Object.assign(new Error('Protected evidence cannot be changed or downloaded.'),{status:403,code:'training_asset_denied'});
      }
    });
    const alice=await f.actor('alice'),bob=await f.actor('bob'),owner=await f.actor('owner'),foreign=await f.actor('foreign');
    const id=randomUUID(),input={id,original_filename:'Evidence.pdf',mime_type:'application/pdf',byte_size:100};
    const db=await pool.connect();try{
      await db.query('BEGIN');
      const reservation=await service.reserveInTransaction(db,alice,input,{sourceProtected:true,sourceScope:'training_test'});
      assert.equal(reservation.file.visibility,'private');assert.equal(reservation.file.source_protected,true);
      await db.query('INSERT INTO test_training_refs(file_id,company_id,user_id) VALUES($1,$2,$3),($1,$2,$4)',[id,companies.a,ids.alice,ids.bob]);
      await db.query('COMMIT');
    }catch(e){await db.query('ROLLBACK');throw e;}finally{db.release();}
    assert.ok((await service.part(alice,id,1)).url);
    await assert.rejects(service.begin(alice,input),e=>e.code==='upload_scope_changed');
    await pool.query("UPDATE stored_files SET cloud_status='active' WHERE id=$1",[id]);
    assert.equal((await service.get(alice,id)).id,id);assert.equal((await service.get(bob,id)).id,id);
    for(const actor of [owner,foreign]){
      await assert.rejects(service.get(actor,id),e=>e.status===404);
      assert.equal((await service.list(actor)).files.length,0);
      assert.equal((await service.verify(actor,[id])).files.length,0);
    }
    assert.ok((await service.access(bob,id,'preview')).url);
    await assert.rejects(service.access(bob,id,'download'),e=>e.code==='training_asset_denied');
    await assert.rejects(service.patch(alice,id,{expected_version:1,visibility:'company'}),e=>e.code==='training_asset_denied');
    await assert.rejects(service.remove(alice,id),e=>e.code==='training_asset_denied');
    await pool.query('UPDATE test_training_refs SET allowed=false WHERE user_id=$1',[ids.bob]);
    await assert.rejects(service.get(bob,id),e=>e.status===404);
    assert.equal((await service.verify(bob,[id])).files.length,0);
    await pool.query('UPDATE users SET locked_at=now() WHERE id=$1',[ids.alice]);
    await assert.rejects(service.get(alice,id),e=>e.status===403);
    await pool.query('UPDATE users SET locked_at=NULL WHERE id=$1',[ids.alice]);
    unregister();unregister=null;
    await assert.rejects(service.get(alice,id),e=>e.status===404);
    await pool.query("UPDATE stored_files SET visibility='company' WHERE id=$1",[id]);
    await assert.rejects(service.get(owner,id),e=>e.status===404);
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM stored_files WHERE id=$1',[id])).rows[0].n,1);
  }finally{unregister?.();await f.close();}
});
