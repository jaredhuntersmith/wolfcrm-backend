import test from 'node:test';import assert from 'node:assert/strict';import {randomUUID} from 'node:crypto';
import {createCommsFixture} from './helpers/comms-fixture.js';import {installNotesSchema} from '../notes/schema.js';import {createNotesWorkspace} from '../notes/pages.js';import {createNotesDatabases,databaseColumns} from '../notes/databases.js';
test('database typed properties, live relations, row ACL, sorting, filters and optimistic conflicts',{timeout:120000},async()=>{
 const f=await createCommsFixture();try{
  await installNotesSchema(f.pool);const owner=await f.actor('owner');await f.pool.query(`UPDATE employee_permissions SET permission_overrides=permission_overrides||'{"notes.view":true,"notes.databases":true}'::jsonb WHERE user_id=$1`,[f.ids.bob]);const bob=await f.actor('bob');const notes=createNotesWorkspace({pool:f.pool}),db=createNotesDatabases({pool:f.pool,notes});const database=await notes.create(owner,{id:randomUUID(),title:'Site visits',kind:'database'}),id=database.page.id;
  const columns=[{id:'title',name:'Name',type:'title'},{id:'status',name:'Status',type:'select',options:['Open','Done']},{id:'cost',name:'Cost',type:'number'},{id:'day',name:'Day',type:'date'},{id:'linked',name:'Related Note',type:'relation'},{id:'done',name:'Done',type:'checkbox'}];
  assert.throws(()=>databaseColumns([...columns,{id:'cost',name:'Duplicate',type:'text'}]));
  const schema=await db.configure(owner,id,{expected_revision:0,columns,views:[{id:'board',name:'Status',type:'board',group_by:'status'}]});assert.equal(schema.revision,1);assert.equal(schema.views[0].group_by,'status');await assert.rejects(db.configure(owner,id,{expected_revision:0,columns}),e=>e.status===409);
  const privateNote=await notes.create(owner,{id:randomUUID(),title:'PRIVATE RELATION SENTINEL'});
  const first=await db.save(owner,id,null,{id:randomUUID(),schema_revision:1,values:{title:'First',status:'Open',cost:20,day:'2026-10-04',linked:privateNote.page.id,done:false}});const second=await db.save(owner,id,null,{id:randomUUID(),schema_revision:1,values:{title:'Second',status:'Done',cost:100,done:true}});
  assert.equal((await db.rows(owner,id,{search:'2026-10-04'})).rows[0].id,first.id);assert.ok((await notes.list(owner,{search:'2026-10-04'})).pages.some(p=>p.id===id));assert.equal((await db.rows(owner,id,{date_property:'day',date_value:'2026-10-04'})).rows.length,1);await assert.rejects(db.rows(owner,id,{date_property:'cost',date_value:'2026-10-04'}),e=>e.status===400);assert.equal((await db.rows(owner,id,{sort:'cost',direction:'asc'})).rows[0].id,first.id);assert.equal((await db.rows(owner,id,{filter_property:'status',filter_value:'Done'})).rows[0].id,second.id);
  const page=await notes.get(owner,id);await notes.share(owner,id,{expected_revision:page.page.revision,members:[{user_id:bob.userId,role:'viewer'}]});
  const bobRows=await db.rows(bob,id);assert.equal(bobRows.rows.length,2);assert.equal(JSON.stringify(bobRows).includes('PRIVATE RELATION SENTINEL'),false);assert.equal(bobRows.rows.find(r=>r.id===first.id).values.linked.accessible,false);
  await assert.rejects(db.save(bob,id,first.id,{schema_revision:1,expected_revision:1,values:{title:'Denied'}}),e=>e.status===403);
  await assert.rejects(db.save(owner,id,first.id,{schema_revision:1,expected_revision:1,values:{cost:'NaN'}}),e=>e.status===400);
  const saved=await db.save(owner,id,first.id,{schema_revision:1,expected_revision:1,values:{cost:21}});assert.equal(saved.values.cost,21);await assert.rejects(db.save(owner,id,first.id,{schema_revision:1,expected_revision:1,values:{cost:22}}),e=>e.status===409);
  const rowPage=await notes.get(owner,first.id);await notes.metadata(owner,first.id,{expected_revision:rowPage.page.revision,visibility:'private',inherit_access:false});assert.equal((await db.rows(bob,id)).rows.length,1);
 }finally{await f.close();}
});


test('database outbox replay is idempotent, reauthorized and never overwrites subsequent edits',{timeout:120000},async()=>{
 const f=await createCommsFixture();try{
  await installNotesSchema(f.pool);const owner=await f.actor('owner'),notes=createNotesWorkspace({pool:f.pool}),db=createNotesDatabases({pool:f.pool,notes});const {page}=await notes.create(owner,{id:randomUUID(),title:'Offline rows',kind:'database'}),id=page.id;
  const schemaBody={client_key:randomUUID(),expected_revision:0,columns:[{id:'title',name:'Name',type:'title'},{id:'day',name:'Date',type:'date'}],views:[{id:'dates',name:'Dates',type:'calendar',date_by:'day',sort_by:'title',direction:'desc',filter_property:'title',filter_value:'Review',visible_fields:['title','day','missing']}]};
  const schema=await db.configure(owner,id,schemaBody);assert.equal(schema.views[0].direction,'desc');assert.equal(schema.views[0].filter_value,'Review');assert.deepEqual(schema.views[0].visible_fields,['title','day']);assert.equal((await db.configure(owner,id,{views:schemaBody.views,columns:schemaBody.columns,expected_revision:0,client_key:schemaBody.client_key})).revision,schema.revision);
  await assert.rejects(db.configure(owner,id,{...schemaBody,columns:[{id:'title',name:'Changed',type:'title'}]}),e=>e.status===409);
  const body={id:randomUUID(),schema_revision:1,client_key:randomUUID(),values:{title:'Offline create'}};
  const created=await db.save(owner,id,null,body);assert.equal((await db.save(owner,id,null,body)).revision,created.revision);
  await assert.rejects(db.save(owner,id,created.id,{schema_revision:1,expected_revision:1,values:{day:'2026-02-31'}}),e=>e.status===400);
  const patch={schema_revision:1,expected_revision:1,client_key:randomUUID(),values:{title:'Offline edit'}};
  const edited=await db.save(owner,id,created.id,patch);assert.equal(edited.revision,2);
  await db.save(owner,id,created.id,{schema_revision:1,expected_revision:2,values:{title:'Newer remote edit'}});
  const retried=await db.save(owner,id,created.id,patch);assert.equal(retried.revision,3);assert.equal(retried.values.title,'Newer remote edit');
  await assert.rejects(db.save(owner,id,created.id,{...patch,values:{title:'Reused key'}}),e=>e.status===409);
  assert.equal((await db.getRow(owner,id,created.id)).values.title,'Newer remote edit');
  const current=await notes.get(owner,created.id);await notes.metadata(owner,created.id,{expected_revision:current.page.revision,trashed:true});
  await assert.rejects(db.getRow(owner,id,created.id),e=>[403,404].includes(e.status));await assert.rejects(db.save(owner,id,created.id,patch),e=>[403,404].includes(e.status));
 }finally{await f.close();}
});


test('database and row history restore values without reverting permissions or newly added fields',{timeout:120000},async()=>{
 const f=await createCommsFixture();try{
  await installNotesSchema(f.pool);const owner=await f.actor('owner'),notes=createNotesWorkspace({pool:f.pool}),db=createNotesDatabases({pool:f.pool,notes});const {page}=await notes.create(owner,{id:randomUUID(),title:'History database',kind:'database'}),id=page.id;
  let schema=await db.configure(owner,id,{expected_revision:0,columns:[{id:'title',name:'Name',type:'title'},{id:'cost',name:'Cost',type:'number'}]});
  const first=await db.save(owner,id,null,{id:randomUUID(),schema_revision:schema.revision,values:{title:'Before',cost:20}});const before=(await notes.get(owner,first.id)).page;
  await db.save(owner,id,first.id,{schema_revision:schema.revision,expected_revision:first.revision,values:{title:'After',cost:90}});
  const historical=await notes.version(owner,first.id,before.revision);assert.equal(historical.row_properties.values.cost,20);assert.equal(historical.property_columns[1].id,'cost');
  schema=await db.configure(owner,id,{expected_revision:schema.revision,columns:[...schema.columns,{id:'later',name:'New field',type:'text'}]});
  let current=await db.getRow(owner,id,first.id);await db.save(owner,id,first.id,{schema_revision:schema.revision,expected_revision:current.revision,values:{later:'Preserve new field'}});
  const now=await notes.get(owner,first.id);await notes.restore(owner,first.id,{expected_revision:now.page.revision,revision:before.revision});
  current=await db.getRow(owner,id,first.id);assert.equal(current.values.title,'Before');assert.equal(current.values.cost,20);assert.equal(current.values.later,'Preserve new field');
  const beforeSchema=(await notes.get(owner,id)).page;schema=await db.configure(owner,id,{expected_revision:schema.revision,columns:schema.columns.filter(c=>c.id!=='cost')});
  assert.equal((await notes.version(owner,id,beforeSchema.revision)).database_schema.columns.some(c=>c.id==='cost'),true);
  await assert.rejects(notes.restore(owner,first.id,{expected_revision:(await notes.get(owner,first.id)).page.revision,revision:before.revision}),e=>e.status===409);
  await notes.restore(owner,id,{expected_revision:(await notes.get(owner,id)).page.revision,revision:beforeSchema.revision});
  assert.ok((await db.get(owner,id)).revision>schema.revision);assert.equal((await db.getRow(owner,id,first.id)).values.cost,20);
  await f.pool.query(`UPDATE employee_permissions SET permission_overrides=permission_overrides||'{"notes.view":true,"notes.databases":true}'::jsonb WHERE user_id=$1`,[f.ids.bob]);const bob=await f.actor('bob');
  await notes.share(owner,id,{expected_revision:(await notes.get(owner,id)).page.revision,members:[{user_id:bob.userId,role:'editor'}]});
  schema=await db.get(owner,id);schema=await db.configure(owner,id,{expected_revision:schema.revision,columns:[...schema.columns,{id:'secret',name:'Related note',type:'relation'}]});
  const privateSource=await notes.create(owner,{id:randomUUID(),title:'HISTORY PRIVATE SENTINEL'});current=await db.getRow(owner,id,first.id);current=await db.save(owner,id,first.id,{schema_revision:schema.revision,expected_revision:current.revision,values:{secret:privateSource.page.id}});
  const linkedRevision=(await notes.get(owner,first.id)).page.revision;await db.save(owner,id,first.id,{schema_revision:schema.revision,expected_revision:current.revision,values:{secret:null}});
  const deniedHistory=await notes.version(bob,first.id,linkedRevision);assert.equal(deniedHistory.row_properties.values.secret.accessible,false);assert.equal(JSON.stringify(deniedHistory).includes('HISTORY PRIVATE SENTINEL'),false);
  await assert.rejects(notes.restore(bob,first.id,{expected_revision:(await notes.get(bob,first.id)).page.revision,revision:linkedRevision}),e=>[403,404].includes(e.status));
  assert.equal((await notes.members(owner,id)).members[0].role,3);assert.equal((await db.getRow(owner,id,first.id)).values.secret,null);

 }finally{await f.close();}
});
