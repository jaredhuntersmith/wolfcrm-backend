import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {startLocalPostgres} from './helpers/local-postgres.js';

test('Lighting preserves native IDs and enforces company, linked record and asset boundaries', {timeout:60000},async t=>{
 const pg=startLocalPostgres();pg.configureEnvironment();let pool,server;
 try {
  const backend=await import('../index.js');pool=backend.rawPool;await backend.bootstrap();
  const company=randomUUID(),other=randomUUID(),owner=randomUUID(),foreign=randomUUID(),worker=randomUUID(),contact=randomUUID(),foreignContact=randomUUID(),job=randomUUID(),foreignJob=randomUUID(),project=randomUUID();
  await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id) VALUES($1,'Lighting','LIGHT-OWN',$3),($2,'Other lighting','LIGHT-OTHER',$4)",[company,other,owner,foreign]);
  for(const [id,tenant,role] of [[owner,company,'employer'],[foreign,other,'employer'],[worker,company,'employee']]){
   await pool.query('INSERT INTO users(id,email,role,company_id) VALUES($1,$2,$3,$4)',[id,id+'@example.invalid',role,tenant]);
   await pool.query('INSERT INTO sessions(token,user_id) VALUES($1,$2)',[id,id]);
  }
  await pool.query("INSERT INTO employee_permissions(user_id,company_id,permission_preset,permission_overrides) VALUES($1,$2,'technician',$3)",[worker,company,JSON.stringify({'operations.manage':true,'operations.view':true,'contacts.view':false,'jobs.view':false})]);
  await pool.query("INSERT INTO contacts(id,user_id,company_id,name) VALUES($1,$2,$3,'Own contact'),($4,$5,$6,'Foreign contact')",[contact,owner,company,foreignContact,foreign,other]);
  for(const [id,user,tenant] of [[job,owner,company],[foreignJob,foreign,other]])await pool.query("INSERT INTO schedule_events(id,user_id,company_id,title,start_at,end_at) VALUES($1,$2,$3,'Synthetic job',now(),now()+interval '1 hour')",[id,user,tenant]);
  server=await new Promise(resolve=>{const s=backend.app.listen(0,'127.0.0.1',()=>resolve(s));});const base='http://127.0.0.1:'+server.address().port;
  const request=async(method,path,body,user=owner)=>{const res=await fetch(base+'/api/lighting/projects'+path,{method,headers:{authorization:'Bearer '+user,'content-type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});return {status:res.status,data:res.status===204?null:await res.json()};};
  const payload={id:project,name:'Native local ID',document:{schemaVersion:1,layers:[]},contact_id:contact,job_id:job};
  await t.test('create, repeated save and patch retain the ID used by native uploads',async()=>{
   for(let i=0;i<2;i++){const r=await request('POST','',payload);assert.equal(r.status,201,JSON.stringify(r.data));assert.equal(r.data.id,project);}
   const updated=await request('PATCH','/'+project,{id:project.toUpperCase(),name:'Updated',source_object_key:`companies/${company}/lighting/${project}/source.jpg`});
   assert.equal(updated.status,200,JSON.stringify(updated.data));assert.equal(updated.data.id,project);
   assert.equal((await pool.query('SELECT count(*)::int n FROM lighting_projects WHERE company_id=$1',[company])).rows[0].n,1);
  });
  await t.test('foreign project collision cannot overwrite and PATCH cannot change identity',async()=>{
   const collision=await request('POST','',{...payload,contact_id:null,job_id:null,name:'Hijack'},foreign);assert.equal(collision.status,409);
   assert.equal((await pool.query('SELECT name FROM lighting_projects WHERE id=$1',[project])).rows[0].name,'Updated');
   assert.equal((await request('PATCH','/'+project,{id:randomUUID(),name:'Moved'})).data.error,'lighting_id_immutable');
   assert.equal((await request('PATCH','/'+project,{name:'Foreign'},foreign)).status,404);
  });
  await t.test('both creation and partial updates reject foreign or deleted linked records',async()=>{
   for(const links of [{contact_id:foreignContact},{job_id:foreignJob}]){
    assert.equal((await request('POST','',{...payload,id:randomUUID(),...links})).status,404);
    assert.equal((await request('PATCH','/'+project,links)).status,404);
   }
   await pool.query('UPDATE contacts SET deleted_at=now() WHERE id=$1',[contact]);
   assert.equal((await request('PATCH','/'+project,{contact_id:contact})).status,404);
   await pool.query('UPDATE contacts SET deleted_at=NULL WHERE id=$1',[contact]);
  });
  await t.test('operations permission does not grant linked contact or job access',async()=>{
   const plain=await request('POST','',{id:randomUUID(),name:'Unlinked',document:payload.document},worker);assert.equal(plain.status,201,JSON.stringify(plain.data));
   for(const links of [{contact_id:contact},{job_id:job}]){
    assert.equal((await request('POST','',{id:randomUUID(),name:'Denied link',document:payload.document,...links},worker)).status,403);
    assert.equal((await request('PATCH','/'+plain.data.id,links,worker)).status,403);
   }
  });
  await t.test('asset keys remain scoped and a missing ID still generates a valid server ID',async()=>{
   assert.equal((await request('PATCH','/'+project,{source_object_key:`companies/${other}/lighting/${project}/source.jpg`})).status,403);
   const generated=await request('POST','',{name:'Legacy client',document:payload.document});assert.equal(generated.status,201);assert.match(generated.data.id,/^[a-f0-9-]{36}$/);
  });
 }finally{if(server)await new Promise(r=>server.close(r));if(pool)await pool.end();pg.stop();}
});
