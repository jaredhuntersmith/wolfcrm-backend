import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installRoutineGroupSystem} from '../routine-groups.js';

test('private routine lists return fresh 200 JSON across account switches even with a stale validator',
  {timeout:120000}, async()=>{
    const fixture=await createCommsFixture();
    const app=express();
    let server;
    try{
      // Express would turn the same [] body into a 304 when this validator is
      // sent with max-age=0, so it reproduces the conditional simulator GET.
      app.get('/etag-baseline',(_req,res)=>res.json([]));
      const auth=(req,_res,next)=>{
        const who=req.get('X-Fixture-User');
        req.userId=fixture.ids[who];
        req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;
        next();
      };
      await installRoutineGroupSystem({app,pool:fixture.pool,authRequired:auth,
        requireView:(_req,_res,next)=>next(),requireManage:(_req,_res,next)=>next()});
      server=await new Promise(resolve=>{
        const listener=app.listen(0,'127.0.0.1',()=>resolve(listener));
      });
      const base=`http://127.0.0.1:${server.address().port}`;
      const baseline=await fetch(base+'/etag-baseline');
      const etag=baseline.headers.get('etag');
      assert.ok(etag);
      for(const path of ['/api/todo/routine-groups','/api/todo/routine-runs']){
        for(const who of ['bob','foreign']){
          const response=await fetch(base+path,{headers:{
            'X-Fixture-User':who,'If-None-Match':etag,'Cache-Control':'max-age=0'
          }});
          assert.equal(response.status,200,`${who} ${path}`);
          assert.match(response.headers.get('cache-control')??'',/private, no-store/);
          assert.equal(response.headers.get('etag'),null);
          assert.deepEqual(await response.json(),[]);
        }
      }
    }finally{
      if(server)await new Promise(resolve=>server.close(resolve));
      await fixture.close();
    }
  });
