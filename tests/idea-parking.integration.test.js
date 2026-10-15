import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installIdeaParking} from '../idea-parking.js';

test('Idea list privacy, selected members, company sharing, revoked access and retained unfiled ideas',{timeout:120000},async()=>{
 const f=await createCommsFixture();let server;
 try {
  const app=express();app.use(express.json());await installIdeaParking({app,pool:f.pool,authRequired:(req,res,next)=>{const key=req.get('X-User');if(!f.ids[key])return res.sendStatus(401);req.userId=f.ids[key];req.companyId=key==='foreign'?f.companies.b:f.companies.a;next();}});
  server=await new Promise(r=>{const s=app.listen(0,'127.0.0.1',()=>r(s));});
  const api=async(who,path,method='GET',body)=>{const response=await fetch(`http://127.0.0.1:${server.address().port}/api/idea-parking${path}`,{method,headers:{'Content-Type':'application/json','X-User':who},body:body===undefined?undefined:JSON.stringify(body)});return{status:response.status,body:response.status===204?null:await response.json()};};
  const list=randomUUID(),idea=randomUUID();let saved=await api('alice','/lists/'+list,'PUT',{name:'Private Ideas',visibility:'private',member_ids:[]});assert.equal(saved.status,200);
  assert.equal((await api('owner','/lists')).body.length,0);
  await api('alice','/ideas/'+idea,'PUT',{text:'Private idea content',list_id:list});
  assert.equal((await api('bob','/ideas')).body.length,0);
  saved=await api('alice','/lists/'+list,'PUT',{name:'Shared Ideas',visibility:'shared',member_ids:[f.ids.bob],expected_revision:saved.body.revision});assert.equal(saved.status,200);
  assert.equal((await api('bob','/ideas')).body.length,1);assert.equal((await api('owner','/ideas')).body.length,0);
  assert.equal((await api('bob','/lists/'+list,'PUT',{name:'Take over',visibility:'company',member_ids:[],expected_revision:saved.body.revision})).status,404);
  assert.equal((await api('foreign','/ideas/'+idea,'DELETE')).status,404);
  const contribution=randomUUID();assert.equal((await api('bob','/ideas/'+contribution,'PUT',{text:'Shared contribution',list_id:list})).status,200);
  assert.equal((await api('bob','/ideas/'+idea,'PUT',{text:'Overwrite'})).status,404);
  saved=await api('alice','/lists/'+list,'PUT',{name:'Company Ideas',visibility:'company',member_ids:[],expected_revision:saved.body.revision});assert.equal(saved.status,200);
  assert.equal((await api('owner','/ideas')).body.length,2);
  saved=await api('alice','/lists/'+list,'PUT',{name:'Private Again',visibility:'private',member_ids:[],expected_revision:saved.body.revision});assert.equal(saved.status,200);
  assert.equal((await api('bob','/ideas')).body.length,0);assert.equal((await api('bob','/ideas/'+contribution,'DELETE')).status,404);
  assert.equal((await api('alice','/lists/'+list,'DELETE')).status,204);
  assert.deepEqual((await api('bob','/ideas')).body.map(i=>i.id),[contribution]);
  assert.deepEqual((await api('alice','/ideas')).body.map(i=>i.id),[idea]);
 }finally{if(server)await new Promise(r=>server.close(r));await f.close();}
});
