import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import pg from 'pg';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTrainingSchema} from '../training/schema.js';

test('training schema survives database restart and preserves pinned older assignment versions',{timeout:120000},async()=>{
  const fixture=await createCommsFixture();
  let reopened,poolEnded=false;
  try{
    await installTrainingSchema(fixture.pool);
    const definitionID=randomUUID(),versionOne=randomUUID(),versionTwo=randomUUID(),assignmentID=randomUUID();
    const companyID=fixture.companies.a,ownerID=fixture.ids.owner;
    await fixture.pool.query(`INSERT INTO training_definitions(id,company_id,created_by,kind,title,draft)
      VALUES($1,$2,$3,'task','Original task','{}'::jsonb)`,[definitionID,companyID,ownerID]);
    for(const [id,number,title] of [[versionOne,1,'Original task'],[versionTwo,2,'Revised task']]){
      await fixture.pool.query(`INSERT INTO training_versions
        (id,company_id,definition_id,version_number,schema_version,kind,title,document,content_sha256,published_by)
        VALUES($1,$2,$3,$4,1,'task',$5,'{}'::jsonb,$6,$7)`,
      [id,companyID,definitionID,number,title,`sha-${number}`,ownerID]);
    }
    await fixture.pool.query(`INSERT INTO training_assignments
      (id,company_id,definition_id,version_id,assigned_by,request_key,input_sha256)
      VALUES($1,$2,$3,$4,$5,'restart-check','sha-assignment')`,
    [assignmentID,companyID,definitionID,versionOne,ownerID]);
    await fixture.pool.query('UPDATE training_definitions SET archived_at=now(),latest_version=2 WHERE id=$1',[definitionID]);

    await fixture.pool.end();poolEnded=true;
    fixture.postgres.restart();
    reopened=new pg.Pool(fixture.postgres.config);
    await installTrainingSchema(reopened);
    await installTrainingSchema(reopened);
    const result=await reopened.query(`SELECT d.archived_at,a.version_id,v.version_number,v.title,
      (SELECT count(*)::integer FROM training_versions WHERE definition_id=d.id) AS version_count
      FROM training_definitions d JOIN training_assignments a ON a.definition_id=d.id
      JOIN training_versions v ON v.id=a.version_id WHERE a.id=$1`,[assignmentID]);
    assert.equal(result.rows.length,1);
    assert.ok(result.rows[0].archived_at);
    assert.equal(result.rows[0].version_id,versionOne);
    assert.equal(result.rows[0].version_number,1);
    assert.equal(result.rows[0].title,'Original task');
    assert.equal(result.rows[0].version_count,2);
  }finally{
    if(reopened)await reopened.end();
    if(!poolEnded)await fixture.pool.end();
    fixture.postgres.stop();
  }
});
