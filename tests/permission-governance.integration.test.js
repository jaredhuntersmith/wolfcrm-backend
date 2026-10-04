import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import pg from 'pg';
import express from 'express';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {installPermissionGovernanceSchema,createPermissionGovernance,installPermissionGovernanceRoutes,ownerIdentity} from '../permission-governance.js';
import {legacyColumnsForCapabilities,validateAccessUpdate} from '../permissions.js';

// Real isolated PostgreSQL: no DATABASE_URL, provider credentials or real users.
test('owner identity, scoped delegation, atomic access and durable invalidation', {timeout:120000},async t=>{
 const local=startLocalPostgres(),pool=new pg.Pool(local.config),company=randomUUID(),foreign=randomUUID();let server;
 const ids=Object.fromEntries(['owner','admin','peerAdmin','employee','employee2','spoof','foreign'].map(key=>[key,randomUUID()]));
 const ctx=key=>({userId:ids[key],companyId:key==='foreign'?foreign:company,role:'employer',isCompanyOwner:true});
 const service=createPermissionGovernance({pool,onChange:async()=>{throw Error('offline transport');}});
 try{
  await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto;CREATE TABLE companies(id uuid PRIMARY KEY,owner_user_id uuid);CREATE TABLE users(id uuid PRIMARY KEY,company_id uuid REFERENCES companies(id),email text,display_name text,role text,deleted_at timestamptz);
   CREATE TABLE employee_permissions(user_id uuid PRIMARY KEY REFERENCES users(id),company_id uuid REFERENCES companies(id),permission_preset text NOT NULL DEFAULT 'technician',permission_overrides jsonb NOT NULL DEFAULT '{}',updated_at timestamptz DEFAULT now(),${Object.keys(legacyColumnsForCapabilities({})).map(key=>key+' boolean DEFAULT false').join(',')});
   CREATE TABLE employee_permission_audit(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),company_id uuid,employee_user_id uuid,changed_by_user_id uuid,previous_preset text,previous_overrides jsonb,new_preset text,new_overrides jsonb,created_at timestamptz DEFAULT now());`);
  await pool.query('INSERT INTO companies VALUES($1,$2),($3,$4)',[company,ids.owner,foreign,ids.foreign]);
  for(const [key,id] of Object.entries(ids)){
   // The actual owner deliberately has a stale employee role; forged employer must still fail.
   await pool.query('INSERT INTO users(id,company_id,email,role) VALUES($1,$2,$3,$4)',[id,key==='foreign'?foreign:company,key+'@example.invalid',key==='spoof'?'employer':'employee']);
   await pool.query('INSERT INTO employee_permissions(user_id,company_id,permission_preset) VALUES($1,$2,$3)',[id,key==='foreign'?foreign:company,key.includes('Admin')||key==='admin'?'admin':'technician']);
  }
  await installPermissionGovernanceSchema(pool);await installPermissionGovernanceSchema(pool);
  const current=async(key)=>(await pool.query('SELECT * FROM employee_permissions WHERE user_id=$1',[ids[key]])).rows[0];
  const edit=async(actor,key,overrides,preset='technician',expected)=>service.update(ctx(actor),[{id:ids[key],preset,overrides,expected_revision:expected??Number((await current(key)).permission_revision)}]);
  await t.test('actual owner identity wins over stale or forged role labels',async()=>{
   assert.equal((await service.effective(ctx('owner'))).is_company_owner,true);
   assert.equal((await service.effective(ctx('spoof'))).is_company_owner,false);
   await assert.rejects(service.employees(ctx('spoof')),e=>e.code==='access_administration_denied');
   assert.equal(ownerIdentity({id:ids.owner,role:'employer',company_id:company,owner_user_id:ids.spoof}),false);
   assert.equal(ownerIdentity({id:ids.owner,role:'employer',company_id:null}),true);
  });
  await t.test('ordinary feature denial cannot resurrect dependent actions',async()=>{
   const next=validateAccessUpdate({preset:'admin',overrides:{'communications.view':false,'storage.view':false,'finance.view':false}});
   for(const key of ['communications.record','communications.transcribe','communications.ai','communications.screenshare','storage.upload','audio.play','media.play','finance.ai.use'])assert.equal(next.capabilities[key],false,key);
  });
  await t.test('owner delegates exact actions independently of Admin financial visibility',async()=>{
   await edit('owner','admin',{'finance.view':false,'team.view':false,'team.manage_access':false},'admin');
   assert.equal((await service.effective(ctx('admin'))).can_manage_access,false);
   const d=await service.delegation(ctx('owner'),ids.admin,{scope:['communications.create','storage.download'],expected_revision:0});assert.equal(d.delegation.revision,1);
   const effective=await service.effective(ctx('admin'));assert.equal(effective.can_manage_access,true);assert.equal(effective.access.capabilities['finance.view'],false);
   assert.ok((await service.employees(ctx('admin'))).employees.every(e=>e.id!==ids.owner&&e.id!==ids.admin&&e.id!==ids.peerAdmin));
   await edit('admin','employee',{'communications.create':false});assert.equal((await service.effective(ctx('employee'))).access.capabilities['communications.create'],false);
  });
  await t.test('admin cannot edit owner/self/peer/foreign, promote, change template or exceed scope',async()=>{
   for(const target of ['owner','admin','peerAdmin','foreign'])await assert.rejects(edit('admin',target,{}),e=>[403,404].includes(e.status));
   await assert.rejects(edit('admin','employee',{},'admin'),e=>e.code==='admin_boundary');
   await assert.rejects(edit('admin','employee',{},'manager'),e=>['preset_owner_required','delegation_scope_exceeded'].includes(e.code));
   await assert.rejects(edit('admin','employee',{'contacts.delete':true}),e=>e.code==='delegation_scope_exceeded');
   await assert.rejects(service.delegation(ctx('admin'),ids.peerAdmin,{scope:['contacts.delete'],expected_revision:0}),e=>e.code==='owner_required');
  });
  await t.test('forbidden whole batch rolls back allowed sibling; no audit/invalidations escape',async()=>{
   const before=await current('employee'),count=Number((await pool.query('SELECT count(*) FROM permission_governance_audit')).rows[0].count);
   await assert.rejects(service.update(ctx('admin'),[
    {id:ids.employee,preset:'technician',overrides:{'communications.create':false,'storage.download':false},expected_revision:Number(before.permission_revision)},
    {id:ids.employee2,preset:'technician',overrides:{'contacts.delete':true},expected_revision:Number((await current('employee2')).permission_revision)}
   ]),e=>e.code==='delegation_scope_exceeded');
   assert.deepEqual(await current('employee'),before);assert.equal(Number((await pool.query('SELECT count(*) FROM permission_governance_audit')).rows[0].count),count);
  });
  await t.test('stale revision and competing saves cannot silently overwrite',async()=>{
   const rev=Number((await current('employee2')).permission_revision);
   const attempts=await Promise.allSettled([edit('owner','employee2',{'storage.download':false},'technician',rev),edit('owner','employee2',{'communications.create':false},'technician',rev)]);
   assert.equal(attempts.filter(x=>x.status==='fulfilled').length,1);assert.equal(attempts.find(x=>x.status==='rejected').reason.code,'permissions_changed');
   await assert.rejects(service.update(ctx('owner'),[{id:ids.employee,preset:'technician',overrides:{}}]),e=>e.code==='permission_revision_required');
  });
  await t.test('legacy mutation preserves modern denial and rejects owner/forged admin bypass',async()=>{
   await assert.rejects(service.legacyUpdate(ctx('admin'),ids.employee,{can_delete_contacts:true}),e=>e.code==='owner_required');
   await assert.rejects(service.legacyUpdate(ctx('owner'),ids.owner,{can_delete_contacts:false}),e=>e.code==='owner_protected');
   await service.legacyUpdate(ctx('owner'),ids.employee,{can_delete_contacts:true});const effective=await service.effective(ctx('employee'));
   assert.equal(effective.access.capabilities['contacts.delete'],true);assert.equal(effective.access.capabilities['communications.create'],false);
   await assert.rejects(service.legacyUpdate(ctx('owner'),ids.employee,{can_delete_contacts:'false'}),e=>e.code==='invalid_permission_document');
  });
  await t.test('owner only Admin designation, demotion revokes delegation, scope CAS',async()=>{
   await assert.rejects(service.delegation(ctx('owner'),ids.admin,{scope:[],expected_revision:0}),e=>e.code==='delegation_changed');
   await edit('owner','admin',{},'technician');assert.equal((await service.effective(ctx('admin'))).can_manage_access,false);
   assert.deepEqual((await service.effective(ctx('admin'))).delegation_scope,[]);
  });
  await t.test('outbox survives unavailable realtime callback and drains idempotent identifiers',async()=>{
   const seen=new Set();const count=await service.drainInvalidations(async e=>{assert.deepEqual(Object.keys(e).sort(),['companyId','id','reason','revision','userId']);seen.add(e.id);});
   assert.ok(count>0);assert.equal(count,seen.size);assert.equal(await service.drainInvalidations(async()=>assert.fail()),0);
  });
  await t.test('HTTP ignores client owner/role/company claims; inactive and company-changed identities deny',async()=>{
   const app=express();app.use(express.json());installPermissionGovernanceRoutes({app,pool,authRequired:(req,res,next)=>{const key=req.headers.authorization;if(!ids[key])return res.sendStatus(401);Object.assign(req,ctx(key));next();}});
   server=await new Promise(r=>{const s=app.listen(0,'127.0.0.1',()=>r(s));});const url=`http://127.0.0.1:${server.address().port}`;
   const r=await fetch(url+'/api/company/employees/'+ids.employee+'/access',{method:'PUT',headers:{Authorization:'spoof','Content-Type':'application/json'},body:JSON.stringify({role:'employer',is_company_owner:true,company_id:company,preset:'admin',overrides:{},expected_revision:Number((await current('employee')).permission_revision)})});assert.equal(r.status,403);
   await pool.query('UPDATE users SET deleted_at=now() WHERE id=$1',[ids.employee]);await assert.rejects(service.effective(ctx('employee')),e=>e.code==='account_inactive');
   await pool.query('UPDATE users SET company_id=$2 WHERE id=$1',[ids.spoof,foreign]);await assert.rejects(service.employees(ctx('spoof')),e=>e.code==='account_inactive');
  });
 }finally{if(server)await new Promise(r=>server.close(r));await pool.end();local.stop();}
});
