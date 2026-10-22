import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining} from '../training/index.js';

test('assignment pages preserve due ordering and recheck tenant, query and supervision scope',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express();let server;
  try{
    app.use(express.json());
    const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');req.userId=fixture.ids[who];
      req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
    await installTraining({app,pool:fixture.pool,authRequired:auth});
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,{who='owner',method='GET',body}={})=>{
      const response=await fetch(base+path,{method,headers:{'X-Fixture-User':who,'Content-Type':'application/json'},
        body:body===undefined?undefined:JSON.stringify(body)});
      return {status:response.status,body:await response.json()};
    };
    const draft=await request('/definitions',{method:'POST',body:{kind:'task',title:'Pagination safety task'}});
    assert.equal(draft.status,200);
    const published=await request(`/definitions/${draft.body.id}/publish`,{method:'POST',body:{expected_revision:1}});
    assert.equal(published.status,200);
    const insert=async(who,total)=>fixture.pool.query(`WITH inserted AS (
      INSERT INTO training_assignments(id,company_id,definition_id,version_id,assigned_by,request_key,input_sha256,
        available_at,due_at,created_at)
      SELECT gen_random_uuid(),$1,$2,$3,$4,$6||n::text,'page-fixture',
        '2026-10-20T00:00:00Z'::timestamptz,
        CASE WHEN n%3=0 THEN NULL WHEN n%3=1 THEN '2026-10-25T17:00:00Z'::timestamptz
          ELSE '2026-10-26T17:00:00Z'::timestamptz END,
        '2026-10-20T00:00:00Z'::timestamptz+n*interval '1 second'
      FROM generate_series(1,$7::integer) n RETURNING id,request_key
    ) INSERT INTO training_recipients(id,company_id,assignment_id,employee_id,employee_name_snapshot,
      created_at,updated_at)
      SELECT gen_random_uuid(),$1,id,$5,$8,
        '2026-10-20T00:00:00Z'::timestamptz+substring(request_key from '[0-9]+$')::integer*interval '1 second',
        '2026-10-20T00:00:00Z'::timestamptz+substring(request_key from '[0-9]+$')::integer*interval '1 second'
      FROM inserted`,[fixture.companies.a,draft.body.id,published.body.id,fixture.ids.owner,
      fixture.ids[who],`page-${who}-`,total,who]);
    await insert('bob',125);await insert('carol',5);
    await fixture.pool.query(`UPDATE training_assignments SET available_at=created_at,
      priority=CASE substring(request_key from '[0-9]+$')::integer%4
        WHEN 0 THEN 'urgent' WHEN 1 THEN 'high' WHEN 2 THEN 'normal' ELSE 'low' END
      WHERE company_id=$1 AND request_key LIKE 'page-bob-%'`,[fixture.companies.a]);
    await fixture.pool.query(`UPDATE training_recipients r SET created_at=
      '2026-10-20T00:00:00Z'::timestamptz+
        substring(a.request_key from '[0-9]+$')::integer%7*interval '1 second'
      FROM training_assignments a WHERE a.company_id=r.company_id AND a.id=r.assignment_id
        AND a.company_id=$1 AND a.request_key LIKE 'page-bob-%'`,[fixture.companies.a]);
    const page=async(path,who)=>request(path,{who});
    const first=await page('/mine','bob');
    assert.equal(first.status,200);assert.equal(first.body.items.length,50);
    assert.ok(first.body.next_cursor);
    const all=[];let cursor=null;
    do{
      const query=new URLSearchParams({limit:'17'});
      if(cursor)query.set('cursor',cursor);
      const result=await page(`/mine?${query}`,'bob');
      assert.equal(result.status,200,JSON.stringify(result.body));
      all.push(...result.body.items.map(item=>item.id));cursor=result.body.next_cursor;
    }while(cursor);
    assert.equal(all.length,125);assert.equal(new Set(all).size,125);
    const expected=(await fixture.pool.query(`SELECT r.id FROM training_recipients r
      JOIN training_assignments a ON a.company_id=r.company_id AND a.id=r.assignment_id
      WHERE r.company_id=$1 AND r.employee_id=$2
      ORDER BY a.due_at NULLS LAST,r.created_at DESC,r.id`,
    [fixture.companies.a,fixture.ids.bob])).rows.map(row=>row.id);
    assert.deepEqual(all,expected);
    const one=await page('/mine?limit=1&search=Pagination','bob');
    assert.equal(one.body.items.length,1);
    assert.equal((await page(`/mine?limit=1&search=missing&cursor=${one.body.next_cursor}`,'bob')).status,400);
    assert.equal((await page(`/mine?limit=1&cursor=${one.body.next_cursor}`,'carol')).status,400);
    assert.equal((await page(`/mine?limit=1&cursor=${one.body.next_cursor}`,'foreign')).status,400);
    assert.equal((await page('/mine?cursor=not-valid!','bob')).status,400);
    assert.equal((await page('/mine?search=no-such-title','bob')).body.items.length,0);
    const dayQuery=new URLSearchParams({limit:'17',filter:'today',day_start:'2026-10-25T00:00:00Z',
      day_end:'2026-10-26T00:00:00Z'});
    const dayIDs=[];let dayCursor=null;
    do{
      if(dayCursor)dayQuery.set('cursor',dayCursor);
      const result=await page(`/mine?${dayQuery}`,'bob');
      assert.equal(result.status,200,JSON.stringify(result.body));
      dayIDs.push(...result.body.items.map(item=>item.id));dayCursor=result.body.next_cursor;
    }while(dayCursor);
    assert.equal(dayIDs.length,42);assert.equal(new Set(dayIDs).size,42);
    const filteredFirst=await page(`/mine?${new URLSearchParams({limit:'1',filter:'today',
      day_start:'2026-10-25T00:00:00Z',day_end:'2026-10-26T00:00:00Z'})}`,'bob');
    assert.equal((await page(`/mine?limit=1&filter=upcoming&day_start=2026-10-25T00%3A00%3A00Z&day_end=2026-10-26T00%3A00%3A00Z&cursor=${filteredFirst.body.next_cursor}`,'bob')).status,400);
    assert.equal((await page('/mine?filter=today&day_start=2026-10-25T00:00:00Z','bob')).status,400);
    assert.equal((await page('/mine?filter=invalid','bob')).status,400);
    const calendar=await page('/mine?calendar_start=2026-10-25T00:00:00Z&calendar_end=2026-10-26T00:00:00Z&limit=100','bob');
    assert.equal(calendar.status,200);assert.equal(calendar.body.items.length,42);
    const upcoming=await page('/mine?filter=upcoming&day_start=2026-10-25T00:00:00Z&day_end=2026-10-26T00:00:00Z&limit=100','bob');
    assert.equal(upcoming.status,200);assert.equal(upcoming.body.items.length,42);
    for(const sort of ['priority','title','recent']){
      const IDs=[];let next=null;
      do{
        const query=new URLSearchParams({sort,limit:'17'});
        if(next)query.set('cursor',next);
        const result=await page(`/mine?${query}`,'bob');
        assert.equal(result.status,200,JSON.stringify(result.body));
        IDs.push(...result.body.items.map(item=>item.id));next=result.body.next_cursor;
      }while(next);
      assert.equal(IDs.length,125);assert.equal(new Set(IDs).size,125);
      const order=sort==='priority'?`CASE a.priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END,
          a.due_at NULLS LAST,r.created_at DESC,r.id`:sort==='title'?'lower(v.title),r.id':'a.available_at DESC,r.id';
      const expectedSorted=(await fixture.pool.query(`SELECT r.id FROM training_recipients r
        JOIN training_assignments a ON a.company_id=r.company_id AND a.id=r.assignment_id
        JOIN training_versions v ON v.company_id=a.company_id AND v.id=a.version_id
        WHERE r.company_id=$1 AND r.employee_id=$2 ORDER BY ${order}`,
      [fixture.companies.a,fixture.ids.bob])).rows.map(row=>row.id);
      assert.deepEqual(IDs,expectedSorted);
      const sortedFirst=await page(`/mine?sort=${sort}&limit=1`,'bob');
      assert.equal((await page(`/mine?sort=due&limit=1&cursor=${sortedFirst.body.next_cursor}`,'bob')).status,400);
    }
    assert.equal((await page('/mine?sort=unknown','bob')).status,400);

    await fixture.pool.query(`UPDATE employee_permissions SET permission_overrides=$2 WHERE user_id=$1`,
      [fixture.ids.alice,JSON.stringify({'training.review':true})]);
    assert.equal((await page('/managed?limit=2','alice')).body.items.length,0);
    await fixture.pool.query(`INSERT INTO training_supervisor_grants(company_id,supervisor_id,employee_id,granted_by)
      VALUES($1,$2,$3,$4)`,[fixture.companies.a,fixture.ids.alice,fixture.ids.bob,fixture.ids.owner]);
    const managed=await page('/managed?limit=2&status=assigned','alice');
    assert.equal(managed.status,200);assert.equal(managed.body.items.length,2);
    assert.ok(managed.body.next_cursor);
    const managedIDs=[];let managedCursor=null;
    do{
      const query=new URLSearchParams({limit:'19',status:'assigned'});
      if(managedCursor)query.set('cursor',managedCursor);
      const result=await page(`/managed?${query}`,'alice');
      assert.equal(result.status,200,JSON.stringify(result.body));
      managedIDs.push(...result.body.items.map(item=>item.id));managedCursor=result.body.next_cursor;
    }while(managedCursor);
    assert.equal(managedIDs.length,125);assert.equal(new Set(managedIDs).size,125);
    const expectedManaged=(await fixture.pool.query(`SELECT r.id FROM training_recipients r
      JOIN training_assignments a ON a.company_id=r.company_id AND a.id=r.assignment_id
      WHERE r.company_id=$1 AND r.employee_id=$2
      ORDER BY a.due_at NULLS LAST,r.updated_at DESC,r.id`,
    [fixture.companies.a,fixture.ids.bob])).rows.map(row=>row.id);
    assert.deepEqual(managedIDs,expectedManaged);
    assert.equal((await page(`/managed?limit=2&status=completed&cursor=${managed.body.next_cursor}`,'alice')).status,400);
    assert.equal((await page(`/managed?limit=2&status=assigned&cursor=${managed.body.next_cursor}`,'foreign')).status,400);
    await fixture.pool.query(`DELETE FROM training_supervisor_grants WHERE supervisor_id=$1`,[fixture.ids.alice]);
    const afterRevocation=await page(`/managed?limit=2&status=assigned&cursor=${managed.body.next_cursor}`,'alice');
    assert.equal(afterRevocation.status,200);assert.equal(afterRevocation.body.items.length,0);
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
