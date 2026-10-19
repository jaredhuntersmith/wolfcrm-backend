import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {installMCP} from '../mcp/index.js';
import {installAssistant} from '../assistant/index.js';
import {installAutomationSystem} from '../automations.js';
import {measurementMetrics} from '../measurement-contract.js';
import {applyLightingEdits,lightingLayerSchema} from '../mcp/geometry-tools.js';
const style={fixture:'c9',pattern:{name:'Warm White',colors:[{hex:'#FFD69B'}]},density:.5,previewScale:1,brightness:.8,glowRadius:.6,glowStrength:.7,opacity:1,patternOffset:0};
const layer=()=>({kind:'roofline',payload:{metadata:{id:randomUUID(),name:'Front roof',isVisible:true,isLocked:false,opacity:1,createdAt:'2026-10-20T12:00:00Z',updatedAt:'2026-10-20T12:00:00Z'},points:[{x:.1,y:.2},{x:.9,y:.2}],style,overrides:[],reversed:false}});
test('canonical geometry adapters preserve measurements Lighting and map ownership',{timeout:180000},async t=>{
 const pg=startLocalPostgres();pg.configureEnvironment();let backend,server;
 try{
  backend=await import('../index.js');const {app,pool,authRequired}=backend;await backend.bootstrap();await installAutomationSystem({app,pool,authRequired,requireEmployer:(req,res,next)=>req.isCompanyOwner?next():res.sendStatus(403),disableProcessors:true});
  const company=randomUUID(),otherCompany=randomUUID(),user=randomUUID(),other=randomUUID();
  for(const[c,u]of[[company,user],[otherCompany,other]]){await pool.query('INSERT INTO companies(id,name,join_code,owner_user_id) VALUES($1,$2,$3,$4)',[c,'Synthetic geometry fixture',c,u]);await pool.query("INSERT INTO users(id,email,display_name,company_id,role,password_hash) VALUES($1,$2,'Fixture owner',$3,'employer','synthetic')",[u,u+'@example.invalid',c]);await pool.query('INSERT INTO sessions(token,user_id) VALUES($1,$2)',[u,u]);}
  const env={MCP_ENABLED:'true',ASSISTANT_ENABLED:'true',MCP_PUBLIC_ORIGIN:'http://127.0.0.1',MCP_WEB_ORIGIN:'http://127.0.0.1',NODE_ENV:'test'};
  await installMCP({app,pool,authRequired,env,startMaintenance:false,verifyIdentity:async()=>null});await installAssistant({app,pool,authRequired,env,startWorker:false,provider:{models:async()=>[],respond:async()=>{throw Error('No paid provider allowed');}}});
  server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});const origin='http://127.0.0.1:'+server.address().port;
  const response=await fetch(origin+'/api/assistant/setup',{method:'POST',headers:{authorization:'Bearer '+user,'content-type':'application/json'},body:'{}'});assert.equal(response.status,201);const connection=(await response.json()).settings.connection_id;
  const names=['measurements_list','measurement_get','measurement_save','measurement_delete','lighting_project_get','lighting_project_create','lighting_design_edit','map_pins','map_pin_get','map_pin_save','map_pin_delete','map_statistics'];
  await pool.query('UPDATE mcp_connections SET tool_policy=$2,revision=revision+1 WHERE id=$1',[connection,JSON.stringify(Object.fromEntries(names.map(n=>[n,{allow:true,approval:false}])))]);
  const actor=await app.locals.connectionManager.actorFor((await pool.query('SELECT * FROM mcp_connections WHERE id=$1',[connection])).rows[0]);
  const invoke=(name,input)=>app.locals.connectionManager.invoke(actor,name,{...input,...(['measurement_save','measurement_delete','lighting_project_create','lighting_design_edit','map_pin_save','map_pin_delete'].includes(name)?{request_id:randomUUID()}:{})},randomUUID());
  t.beforeEach(async()=>pool.query('DELETE FROM mcp_rate_limits'));
  await t.test('measurement quantities derive from canonical points and stale writes cannot overwrite',async()=>{
   const id=randomUUID(),points=[{lat:0,lng:0},{lat:0,lng:.001},{lat:.001,lng:.001},{lat:.001,lng:0}];
   const made=(await invoke('measurement_save',{id,expected_record_hash:null,changes:{name:'Lot boundary',points,units:'feet'}})).data;
   const metrics=measurementMetrics(points);assert.equal(made.metrics.distance,metrics.distance);assert.equal(made.metrics.area,metrics.area);assert.equal(made.metrics.distance_unit,'meters');assert.ok(made.metrics.area>12000&&made.metrics.area<13000);
   const current=(await invoke('measurement_get',{id})).data;const saved=(await invoke('measurement_save',{id,expected_record_hash:current.record_hash,changes:{name:'Renamed'}})).data;assert.deepEqual(saved.measurement.points,points);assert.equal(saved.measurement.units,'feet');
   await assert.rejects(invoke('measurement_save',{id,expected_record_hash:current.record_hash,changes:{name:'Stale'}}),e=>e.status===409);
   await assert.rejects(invoke('measurement_save',{id:randomUUID(),expected_record_hash:null,changes:{points,distance:999}}));
   const foreign=randomUUID();await pool.query("INSERT INTO measurements(id,user_id,name,points,units) VALUES($1,$2,'Foreign','[]','feet')",[foreign,other]);await assert.rejects(invoke('measurement_get',{id:foreign}),e=>e.status===404);
   await invoke('measurement_delete',{id,expected_record_hash:saved.record_hash});await assert.rejects(invoke('measurement_get',{id}),e=>e.status===404);
  });
  await t.test('native Lighting document persists and edits preserve unselected assets and layers',async()=>{
   const id=randomUUID();const made=(await invoke('lighting_project_create',{id,name:'Editable property plan'})).data;assert.equal(made.project.id,id,'canonical route must retain native project ID');
   const first=layer();const saved=(await invoke('lighting_design_edit',{id,expected_record_hash:made.record_hash,edits:[{action:'upsert_layer',layer:first},{action:'scene',scene:{mode:'night',nightAmount:1}}]})).data;assert.equal(saved.project.document.layers[0].payload.metadata.id,first.payload.metadata.id);assert.equal(saved.project.document.scene.mode,'night');assert.deepEqual(saved.project.document.assets,{});
   const chat=await fetch(origin+'/api/assistant/conversations',{method:'POST',headers:{authorization:'Bearer '+user,'content-type':'application/json'},body:'{}'});assert.equal(chat.status,201);const chatID=(await chat.json()).id;
   const runID=randomUUID();await pool.query("INSERT INTO wolf_assistant_runs(id,company_id,user_id,conversation_id,connection_id,model,reasoning,funding,status,request_key,input_hash,instructions,context) VALUES($1,$2,$3,$4,$5,'gpt-5-mini','low','owner','queued',$6,$7,'Synthetic geometry guard',$8)",[runID,company,user,chatID,connection,randomUUID(),'fixture',JSON.stringify({module:'lighting',references:[{entity:'lighting_projects',id}],provenance:{save_state:'local_draft'}})]);
   actor.assistantInvocation={runId:runID};
   try{await assert.rejects(invoke('lighting_design_edit',{id,expected_record_hash:saved.record_hash,edits:[{action:'scene',scene:{mode:'day',nightAmount:0}}]}),e=>e.code==='native_unsaved_design_use_editor');}finally{delete actor.assistantInvocation;}
   const copy=randomUUID();const duplicated=(await invoke('lighting_design_edit',{id,expected_record_hash:saved.record_hash,edits:[{action:'duplicate_layer',layer_id:first.payload.metadata.id,new_layer_id:copy,name:'Back roof'}]})).data;
   assert.equal(duplicated.project.document.layers.length,2);assert.deepEqual(duplicated.project.document.layers[0],first);assert.deepEqual(duplicated.project.document.layers[1].payload.points,first.payload.points);
   await assert.rejects(invoke('lighting_design_edit',{id,expected_record_hash:saved.record_hash,edits:[{action:'delete_layer',layer_id:copy}]}),e=>e.status===409);
   const reordered=(await invoke('lighting_design_edit',{id,expected_record_hash:duplicated.record_hash,edits:[{action:'reorder_layers',layer_ids:[copy,first.payload.metadata.id]}]})).data;assert.equal(reordered.project.document.layers[0].payload.metadata.id,copy);
   const invalid={...first,payload:{...first.payload,points:[{x:999,y:.2},{x:1,y:1}]}};await assert.rejects(invoke('lighting_design_edit',{id,expected_record_hash:reordered.record_hash,edits:[{action:'upsert_layer',layer:invalid}]}));
   const foreign=randomUUID();await pool.query("INSERT INTO lighting_projects(id,company_id,name,document,created_by) VALUES($1,$2,'Foreign',$3,$4)",[foreign,otherCompany,JSON.stringify({schemaVersion:1,layers:[]}),other]);await assert.rejects(invoke('lighting_project_get',{id:foreign}),e=>e.status===404);
  });
  await t.test('pin partial edits preserve coordinates canonical statistics and source protection',async()=>{
   const id=randomUUID();await invoke('map_pin_save',{id,expected_record_hash:null,changes:{latitude:40,longitude:-75,name:'Fixture home',status:'lead',notes:'Keep note'}});
   const before=(await invoke('map_pin_get',{id})).data;await invoke('map_pin_save',{id,expected_record_hash:before.record_hash,changes:{status:'won'}});const after=(await invoke('map_pin_get',{id})).data;assert.equal(after.pin.latitude,40);assert.equal(after.pin.notes,'Keep note');assert.equal(after.pin.status,'won');
   await assert.rejects(invoke('map_pin_save',{id,expected_record_hash:before.record_hash,changes:{status:'lost'}}),e=>e.status===409);
   const stats=(await invoke('map_statistics',{period:'all'})).data;assert.equal(stats.total_pins,1);assert.equal(stats.sold,1);
   const foreign=randomUUID();await pool.query("INSERT INTO map_pins(id,user_id,latitude,longitude,name) VALUES($1,$2,1,1,'Foreign')",[foreign,other]);await assert.rejects(invoke('map_pin_get',{id:foreign}),e=>e.status===404);
   await invoke('map_pin_delete',{id,expected_record_hash:after.record_hash});await assert.rejects(invoke('map_pin_get',{id}),e=>e.status===404);
  });
  await t.test('exact ask-first approval and request replay perform one canonical save',async()=>{
   await pool.query("UPDATE mcp_connections SET tool_policy=jsonb_set(tool_policy,'{measurement_save,approval}','true'),revision=revision+1 WHERE id=$1",[connection]);
   const id=randomUUID(),request=randomUUID(),args={id,expected_record_hash:null,changes:{name:'Approved fixture',points:[{lat:41,lng:-75},{lat:41.001,lng:-75}]},request_id:randomUUID()};
   const pending=await app.locals.connectionManager.invoke(actor,'measurement_save',args,request);assert.equal(pending.state,'pending');assert.equal((await pool.query('SELECT count(*)::int n FROM measurements WHERE id=$1',[id])).rows[0].n,0);
   const approval=(await pool.query('SELECT * FROM mcp_approvals WHERE id=$1',[pending.approval_id])).rows[0];
   const decide=await fetch(origin+'/api/ai-connections/approvals/'+approval.id,{method:'POST',headers:{authorization:'Bearer '+user,'content-type':'application/json'},body:JSON.stringify({expected_hash:approval.input_hash,decision:'approve'})});assert.equal(decide.status,200,await decide.text());
   await app.locals.connectionManager.invoke(actor,'measurement_save',args,request);await app.locals.connectionManager.invoke(actor,'measurement_save',args,request);
   assert.equal((await pool.query('SELECT count(*)::int n FROM measurements WHERE id=$1',[id])).rows[0].n,1);
   await pool.query("UPDATE mcp_connections SET tool_policy=jsonb_set(tool_policy,'{measurement_save,approval}','false'),revision=revision+1 WHERE id=$1",[connection]);
  });
  await t.test('field restrictions remain manager enforced',async()=>{
   await pool.query("UPDATE mcp_connections SET tool_policy=jsonb_set(tool_policy,'{measurement_save,denied_input_fields}','[\"changes.points\"]'),revision=revision+1 WHERE id=$1",[connection]);
   await assert.rejects(invoke('measurement_save',{id:randomUUID(),expected_record_hash:null,changes:{points:[{lat:1,lng:1}]}}),e=>e.code==='field_denied');
  });
 }finally{if(server)await new Promise(r=>server.close(r));await backend?.pool.end();pg.stop();}
});
test('all actual native Lighting layer types have a strict typed editing schema',()=>{
 const base=layer().payload,{metadata,style}=base,point={x:.5,y:.5},path=[{x:0,y:0},{x:1,y:1}];
 const payloads={roofline:base,fill:{metadata,style,maskStrokes:[[point]],erasedStrokes:[],brushSize:.06,layout:'organic',angle:0,seed:1},wrap:{metadata,style,path,width:.12,turns:7,reversed:false},garland:{metadata,style,path},wreath:{metadata,style,center:point,radius:.12,rotation:0},fixture:{metadata,style,position:point,fixtureName:'Snowflake',scale:1,rotation:0},bulb:{metadata,style,position:point}};
 for(const[kind,payload]of Object.entries(payloads))assert.deepEqual(lightingLayerSchema.parse({kind,payload}),{kind,payload});
 const moved=layer();moved.payload.overrides=[{position:.5,isHidden:false,positionAdjustment:{x:-.01,y:0}}];assert.deepEqual(lightingLayerSchema.parse(moved),moved);
 assert.throws(()=>lightingLayerSchema.parse({kind:'roofline',payload:{...base,total_feet:100}}));
 assert.throws(()=>applyLightingEdits({schemaVersion:1,layers:[layer()]},[{action:'reorder_layers',layer_ids:[]}]),e=>e.code==='lighting_layer_order_invalid');
});
