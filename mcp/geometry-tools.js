import {z} from 'zod';
import {dispatch,digest,fault} from './context.js';
import {getRecord} from './registry.js';
import {measurementMetrics} from '../measurement-contract.js';

const id=z.string().regex(/^[A-Za-z0-9_-]{1,128}$/),uuid=z.uuid(),hash=z.string().regex(/^[a-f0-9]{64}$/),empty=z.object({}).strict();
const date=z.iso.datetime({offset:true}),unit=z.enum(['feet','meters']);
const point=z.object({lat:z.number().min(-90).max(90),lng:z.number().min(-180).max(180)}).strict();
const xy=z.object({x:z.number().min(0).max(1),y:z.number().min(0).max(1)}).strict();
const color=z.object({hex:z.string().regex(/^#[0-9a-fA-F]{6}$/)}).strict();
const pattern=z.object({name:z.string().max(160).nullable().optional(),colors:z.array(color).min(1).max(10)}).strict();
const style=z.object({fixture:z.enum(['c9','mini','globe','icicle']),pattern,density:z.number().min(0).max(1),previewScale:z.number().min(.1).max(4),brightness:z.number().min(0).max(1),glowRadius:z.number().min(0).max(1),glowStrength:z.number().min(0).max(1),opacity:z.number().min(0).max(1),patternOffset:z.number().int().min(-1000).max(1000)}).strict();
const metadata=z.object({id:uuid,name:z.string().trim().min(1).max(160),isVisible:z.boolean(),isLocked:z.boolean(),opacity:z.number().min(0).max(1),createdAt:date,updatedAt:date}).strict();
const base={metadata,style},path=z.array(xy).min(2).max(1000);
const override=z.object({position:z.number().min(0).max(1),color:color.nullable().optional(),previewScale:z.number().min(.1).max(4).nullable().optional(),brightness:z.number().min(0).max(1).nullable().optional(),isHidden:z.boolean(),positionAdjustment:z.object({x:z.number().min(-1).max(1),y:z.number().min(-1).max(1)}).strict().nullable().optional()}).strict();
const layer=(kind,shape)=>z.object({kind:z.literal(kind),payload:z.object({...base,...shape}).strict()}).strict();
export const lightingLayerSchema=z.discriminatedUnion('kind',[
 layer('roofline',{points:path,overrides:z.array(override).max(500),reversed:z.boolean()}),
 layer('fill',{maskStrokes:z.array(z.array(xy).min(1).max(1000)).max(500),erasedStrokes:z.array(z.array(xy).min(1).max(1000)).max(500).nullable().optional(),brushSize:z.number().positive().max(1),layout:z.enum(['organic','horizontal','vertical','diagonal','grid','spiral']),angle:z.number().min(-360).max(360),seed:z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)}),
 layer('wrap',{path,width:z.number().positive().max(1),turns:z.number().min(0).max(1000),reversed:z.boolean()}),
 layer('garland',{path}),layer('wreath',{center:xy,radius:z.number().positive().max(1),rotation:z.number().min(-360).max(360)}),
 layer('fixture',{position:xy,fixtureName:z.string().trim().min(1).max(160),scale:z.number().positive().max(10),rotation:z.number().min(-360).max(360)}),layer('bulb',{position:xy})
]);
const scene=z.object({mode:z.enum(['day','dusk','night']),nightAmount:z.number().min(0).max(1)}).strict();
const edit=z.discriminatedUnion('action',[
 z.object({action:z.literal('upsert_layer'),layer:lightingLayerSchema}).strict(),
 z.object({action:z.literal('delete_layer'),layer_id:uuid}).strict(),
 z.object({action:z.literal('duplicate_layer'),layer_id:uuid,new_layer_id:uuid,name:z.string().trim().min(1).max(160)}).strict(),
 z.object({action:z.literal('reorder_layers'),layer_ids:z.array(uuid).max(500)}).strict(),
 z.object({action:z.literal('scene'),scene}).strict()
]);
const layerID=l=>String(l.payload?.metadata?.id??l.id).toLowerCase();
export function applyLightingEdits(document,edits){
 const result=structuredClone(document);result.layers??=[];
 for(const e of edits){
  if(e.action==='scene'){result.scene=e.scene;continue;}
  if(e.action==='reorder_layers'){
   if(new Set(e.layer_ids.map(id=>id.toLowerCase())).size!==result.layers.length||e.layer_ids.length!==result.layers.length||e.layer_ids.some(id=>!result.layers.some(l=>layerID(l)===id.toLowerCase())))throw fault(400,'lighting_layer_order_invalid');
   result.layers=e.layer_ids.map(id=>result.layers.find(l=>layerID(l)===id.toLowerCase()));continue;
  }
  if(e.action==='upsert_layer'){
   const index=result.layers.findIndex(l=>layerID(l)===layerID(e.layer));
   if(index<0)result.layers.push(e.layer);else result.layers[index]=e.layer;
  }else{
   const index=result.layers.findIndex(l=>layerID(l)===e.layer_id.toLowerCase());if(index<0)throw fault(404,'lighting_layer_not_found');
   if(e.action==='delete_layer')result.layers.splice(index,1);
   else{if(result.layers.some(l=>layerID(l)===e.new_layer_id.toLowerCase()))throw fault(409,'lighting_layer_exists');const copy=structuredClone(result.layers[index]);if(!copy.payload?.metadata)throw fault(409,'lighting_legacy_layer_requires_native_conversion');copy.payload.metadata={...copy.payload.metadata,id:e.new_layer_id,name:e.name,createdAt:new Date().toISOString(),updatedAt:new Date().toISOString()};result.layers.splice(index+1,0,copy);}
  }
 }
 if(result.layers.length>500||Buffer.byteLength(JSON.stringify(result))>1000000)throw fault(413,'lighting_document_too_large');
 return result;
}
export function registerGeometryTools({read,write,actor,app,pool}){
 const canonical=(method,path,body)=>dispatch(app,actor,method,path,body);
 const get=(rows,wanted,code)=>{const row=rows.find(x=>String(x.id).toLowerCase()===wanted.toLowerCase());if(!row)throw fault(404,code);return row;};
 const measurement=m=>({measurement:m,record_hash:digest(m),metrics:{...measurementMetrics(m.points),distance_unit:'meters',area_unit:'square_meters',provenance:'measurement-contract.js measurementMetrics; display feet uses native conversion'}});
 async function lock(table,key,ownerColumn,owner){await pool.query(`SELECT id FROM ${table} WHERE id=$1 AND ${ownerColumn}=$2 FOR UPDATE`,[key,owner]);}
 async function linked(contact_id,job_id){if(contact_id)await getRecord(pool,actor,'contacts',contact_id);if(job_id)await getRecord(pool,actor,'jobs',job_id);}
 read('measurements_list','Read your saved geographic measurements and their canonical computed distance/perimeter and area. Metrics are meters/square meters regardless of display units. Drawn boundaries are estimates, never surveyed dimensions.',empty,'crm:read',['operations.view'],null,async()=>({items:(await canonical('GET','/api/measurements')).map(measurement)}));
 read('measurement_get','Read one of your saved measurements, exact record_hash, source points, contact links and canonical metrics.',z.object({id}).strict(),'crm:read',['operations.view'],null,async i=>measurement(get(await canonical('GET','/api/measurements'),i.id,'measurement_not_found')));
 const changes=z.object({name:z.string().trim().max(160).optional(),points:z.array(point).max(250).optional(),linked_contact_ids:z.array(id).max(50).optional(),units:unit.optional()}).strict().refine(i=>Object.keys(i).length>0);
 write('measurement_save','Create or partially edit your saved geographic measurement. New records require null expected_record_hash and explicit points; existing ones require the hash from measurement_get. Supplied geometry is authoritative input; quantities are recomputed by the canonical service. Never infer property boundaries from an address.',z.object({id,expected_record_hash:hash.nullable(),changes}).strict(),'crm:write',['operations.view','operations.manage'],'PUT',null,null,async i=>{
  await lock('measurements',i.id,'user_id',actor.userId);const old=(await canonical('GET','/api/measurements')).find(x=>x.id===i.id);
  if(old?digest(old)!==i.expected_record_hash:i.expected_record_hash!==null)throw fault(409,'measurement_changed');
  if(!old&&!i.changes.points)throw fault(400,'measurement_points_required');
  for(const contact of i.changes.linked_contact_ids??[])await getRecord(pool,actor,'contacts',contact);
  const body={name:'',points:[],linked_contact_ids:[],units:'feet',...old,...i.changes};
  return measurement(await canonical('PUT','/api/measurements/'+i.id,body));
 });
 write('measurement_delete','Delete your saved measurement with its exact current record_hash. Canonical deletion events apply.',z.object({id,expected_record_hash:hash}).strict(),'crm:write',['operations.view','operations.manage'],'DELETE',null,null,async i=>{await lock('measurements',i.id,'user_id',actor.userId);const old=get(await canonical('GET','/api/measurements'),i.id,'measurement_not_found');if(digest(old)!==i.expected_record_hash)throw fault(409,'measurement_changed');await canonical('DELETE','/api/measurements/'+i.id);return {id:i.id,deleted:true};});
 read('lighting_project_get','Read one company Lighting project, full editable design and exact record_hash. Normalized photo coordinates, density and rendered bulb placement are visual design settings, not physical measurements or a material estimate.',z.object({id:uuid}).strict(),'crm:read',['operations.view'],null,async i=>{const project=get(await canonical('GET','/api/lighting/projects'),i.id,'lighting_project_not_found');return {project,record_hash:digest(project),provenance:'Stored canonical Lighting document; render/export and bulb sampling use native LightingGeometry'};});
 write('lighting_project_create','Create a company Lighting project through the canonical service using an explicit name and optional authorized contact/job. Starts an editable blank design; does not import or invent a property photo. A human can supply a source image through the normal native photo workflow.',z.object({id:uuid,name:z.string().trim().min(1).max(160),property_address:z.string().max(500).nullable().optional(),contact_id:uuid.nullable().optional(),job_id:uuid.nullable().optional()}).strict(),'crm:write',['operations.view','operations.manage'],'POST',null,null,async i=>{
  await linked(i.contact_id,i.job_id);if((await canonical('GET','/api/lighting/projects')).some(p=>p.id===i.id))throw fault(409,'lighting_project_exists');
  const project=await canonical('POST','/api/lighting/projects',{...i,document:{schemaVersion:1,assets:{},scene:{mode:'day',nightAmount:0},layers:[]}});return {project,record_hash:digest(project)};
 });
 write('lighting_design_edit','Edit stored Lighting scene and the seven actual native layer types: roofline paths/bulb overrides, fill paint/erase/layout, wrap, garland, wreath, fixture and individual bulb. Supports replace/add/delete/duplicate/reorder with exact source hash; preserves source assets and untouched layers. All positions are normalized photo geometry; rendered quantities stay native, never model arithmetic.',z.object({id:uuid,expected_record_hash:hash,edits:z.array(edit).min(1).max(100)}).strict(),'crm:write',['operations.view','operations.manage'],'PATCH',null,null,async i=>{
  // An active native draft can be newer than the stored project. Route its
  // edits through the exact native revision contract instead of replacing it.
  if(actor.assistantInvocation?.runId){
   const active=(await pool.query('SELECT context FROM wolf_assistant_runs WHERE id=$1 AND company_id=$2 AND user_id=$3',[actor.assistantInvocation.runId,actor.companyId,actor.userId])).rows[0]?.context;
   if(active?.module==='lighting'&&active.provenance?.save_state==='local_draft'&&active.references?.some(r=>r.entity==='lighting_projects'&&r.id.toLowerCase()===i.id.toLowerCase()))throw fault(409,'native_unsaved_design_use_editor','Use native_lighting_edit with the current draft revision; the open design has unsaved changes.');
  }
  await lock('lighting_projects',i.id,'company_id',actor.companyId);const old=get(await canonical('GET','/api/lighting/projects'),i.id,'lighting_project_not_found');if(digest(old)!==i.expected_record_hash)throw fault(409,'lighting_project_changed');const document=applyLightingEdits(old.document,i.edits);const project=await canonical('PATCH','/api/lighting/projects/'+i.id,{document});return {project,record_hash:digest(project)};});
 const scope=z.enum(['mine','company']).default('mine');
 read('map_pins','Read normal map pins with current workspace access; company scope remains canonical. Filter client results by status/address/owner using returned data.',z.object({scope}).strict(),'crm:read',['operations.view'],i=>'/api/map-pins?scope='+i.scope);
 async function pin(id){return get(await canonical('GET','/api/map-pins?scope=company'),id,'map_pin_not_found');}
 async function lockPin(id){await pool.query('SELECT p.id FROM map_pins p JOIN users u ON u.id=p.user_id WHERE p.id=$1 AND u.company_id=$2 FOR UPDATE OF p',[id,actor.companyId]);}
 read('map_pin_get','Read one authorized map pin and exact record_hash.',z.object({id:uuid}).strict(),'crm:read',['operations.view'],null,async i=>{const p=await pin(i.id);return {pin:p,record_hash:digest(p)};});
 const pinChanges=z.object({latitude:z.number().min(-90).max(90).optional(),longitude:z.number().min(-180).max(180).optional(),name:z.string().max(500).optional(),address:z.string().max(2000).optional(),notes:z.string().max(20000).optional(),status:z.enum(['lead','won','lost','reloop','later']).optional(),phone:z.string().max(100).nullable().optional(),email:z.string().max(320).nullable().optional(),contact_id:uuid.nullable().optional()}).strict().refine(x=>Object.keys(x).length>0);
 write('map_pin_save','Create/edit a map pin through canonical ownership, status events and explicit real coordinates. Setting won stores pin status; use map_pin_contact separately to create/link the Contact. This does not create an appointment. Partial edits preserve other fields. New pins require null expected_record_hash; updates require exact current hash.',z.object({id:uuid,expected_record_hash:hash.nullable(),changes:pinChanges}).strict(),'crm:write',['operations.view','operations.manage'],'PUT',null,null,async i=>{await lockPin(i.id);const old=(await canonical('GET','/api/map-pins?scope=company')).find(p=>p.id===i.id);if(old?digest(old)!==i.expected_record_hash:i.expected_record_hash!==null)throw fault(409,'map_pin_changed');if(!old&&(i.changes.latitude===undefined||i.changes.longitude===undefined))throw fault(400,'map_pin_coordinates_required');await linked(i.changes.contact_id);const p=await canonical('PUT','/api/map-pins/'+i.id,{...old,...i.changes});return {pin:p,record_hash:digest(await pin(p.id))};});
 write('map_pin_delete','Delete an authorized map pin with its current exact hash. Canonical ownership and automation events remain in effect.',z.object({id:uuid,expected_record_hash:hash}).strict(),'crm:write',['operations.view','operations.manage'],'DELETE',null,null,async i=>{await lockPin(i.id);if(digest(await pin(i.id))!==i.expected_record_hash)throw fault(409,'map_pin_changed');await canonical('DELETE','/api/map-pins/'+i.id);return {id:i.id,deleted:true};});
 write('map_canvass_contacts','Import explicit authorized Contacts into canvassing pins using their existing canonical coordinates; unavailable coordinates are reported by the normal service. No geocoding or invented locations.',z.object({contact_ids:z.array(uuid).min(1).max(100)}).strict(),'crm:write',['operations.manage','contacts.view'],'POST','/api/map-pins/canvass',i=>i);
 write('map_pin_contact','Convert an authorized map pin to a Contact, or prepare its Contact for scheduling with canonical validations. This does not create an appointment. Requires exact pin hash and normal Contact creation/edit permissions.',z.object({id:uuid,expected_record_hash:hash,intent:z.enum(['convert','schedule'])}).strict(),'crm:write',['operations.view','operations.manage','contacts.view','contacts.create','contacts.edit'],'POST',null,null,async i=>{await lockPin(i.id);if(digest(await pin(i.id))!==i.expected_record_hash)throw fault(409,'map_pin_changed');return canonical('POST','/api/map-pins/'+i.id+'/contact',{intent:i.intent});});
 read('map_statistics','Read canonical canvassing statistics. Conversion and totals come from existing SQL, never model arithmetic.',z.object({period:z.enum(['day','week','month','all']),date:z.iso.date().optional(),user_id:uuid.optional()}).strict(),'crm:read',['operations.view'],i=>'/api/map-stats?'+new URLSearchParams(Object.entries(i).filter(([,v])=>v!==undefined)).toString());
}
