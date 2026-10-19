import {z} from 'zod';
import {dispatch,digest,fault,transaction} from '../mcp/context.js';
import {permit} from '../mcp/access.js';
import {getRecord} from '../mcp/registry.js';
import {evidenceHash} from './context.js';

const uuid=z.uuid(),hash=z.string().regex(/^[a-f0-9]{64}$/);
const point=z.object({label:z.string().trim().min(1).max(300),latitude:z.number().min(-90).max(90),longitude:z.number().min(-180).max(180)}).strict();
const stopFields={id:uuid,service_duration_seconds:z.number().min(0).max(86400).default(0),locked_order:z.number().int().min(1).max(100).nullable().default(null)};
const contact=z.object({...stopFields,source_type:z.literal('contact'),contact_id:uuid,coordinate_command_id:uuid.optional()}).strict();
const custom=point.extend({...stopFields,source_type:z.literal('custom'),address:z.string().trim().min(1).max(1000)}).strict();
export const routeBuildSchema=z.object({request_id:uuid,name:z.string().trim().min(1).max(200),status:z.enum(['saved','active']).default('saved'),start:point,ending_behavior:z.enum(['finish_at_final_stop','return_to_start','custom_address']),end:point.nullable(),departure_time:z.iso.datetime({offset:true}),optimize_order:z.boolean(),stops:z.array(z.discriminatedUnion('source_type',[contact,custom])).min(1).max(100)}).strict();
export const routeRecalculateSchema=z.object({request_id:uuid,route_id:uuid,expected_source_hash:hash,departure_time:z.iso.datetime({offset:true}),optimize_order:z.boolean(),start:point.optional()}).strict();
export const routeResultShape={id:uuid.optional(),entity:z.literal('routes').optional(),source_hash:hash.optional(),metrics:z.object({distance_meters:z.number(),travel_time_seconds:z.number(),service_time_seconds:z.number(),total_route_time_seconds:z.number(),estimated_start_at:z.string(),estimated_finish_at:z.string()}).strict().optional(),warnings:z.array(z.string()).optional(),message:z.string().optional(),content_trust:z.literal('untrusted_record_data').optional()};
const finitePoint=(lat,lng)=>lat!=null&&lng!=null&&Number.isFinite(Number(lat))&&Number.isFinite(Number(lng))&&Math.abs(Number(lat))<=90&&Math.abs(Number(lng))<=180;

export async function prepareRoute({app,pool,actor,input,recalculate=false}){
 permit(actor,'crm:write',['routes.view',recalculate?'routes.edit':'routes.create','contacts.view']);
 const status=await dispatch(app,actor,'GET','/api/routing/status');if(!status.configured)throw fault(503,'google_routing_not_configured','Configure the existing Google routing service before route calculation.');
 let value=input,old=null;
 if(recalculate){
  old=await dispatch(app,actor,'GET','/api/routes/'+input.route_id);
  if(digest(old)!==input.expected_source_hash)throw fault(409,'stale_route');
  value={...input,name:old.name,status:old.status,start:input.start||{label:old.start_label||'Start',latitude:old.start_latitude,longitude:old.start_longitude},ending_behavior:old.ending_behavior,end:old.ending_behavior==='custom_address'?{label:old.end_label||'Endpoint',latitude:old.end_latitude,longitude:old.end_longitude}:null,stops:old.stops.map(s=>({...s,label:s.name}))};
 }
 if(!finitePoint(value.start.latitude,value.start.longitude))throw fault(400,'route_start_required','Choose a real starting coordinate. Device location is available only through its authorized native location workflow.');
 if(value.ending_behavior==='custom_address'&&(!value.end||!finitePoint(value.end.latitude,value.end.longitude)))throw fault(400,'route_endpoint_required');
 if(value.ending_behavior!=='custom_address'&&value.end)throw fault(400,'route_endpoint_not_applicable');
 if(new Set(value.stops.map(s=>s.id)).size!==value.stops.length)throw fault(400,'duplicate_route_stop');
 const records=new Map(),stops=[];
 for(const s of value.stops){
  let name=s.label,address=s.address,latitude=s.latitude,longitude=s.longitude;
  if(s.source_type==='contact'||s.contact_id){
   const c=await getRecord(pool,actor,'contacts',s.contact_id);records.set(c.id,evidenceHash(c));
   name=c.name;address=c.address;
   if(!recalculate){latitude=c.lat;longitude=c.lng;
    if(s.coordinate_command_id){
     const command=(await pool.query(`SELECT c.* FROM wolf_assistant_commands c JOIN wolf_assistant_runs r ON r.id=c.run_id WHERE c.id=$1 AND r.company_id=$2 AND r.user_id=$3 AND c.state='completed' AND c.expires_at>now()`,[s.coordinate_command_id,actor.companyId,actor.userId])).rows[0];
     if(command?.command?.action!=='resolve_location'||command.command.location_request?.contact_id!==c.id||command.command.location_request.source_hash!==evidenceHash(c)||!command.result?.location)throw fault(409,'route_coordinate_receipt_stale');
     latitude=command.result.location.latitude;longitude=command.result.location.longitude;
    }
   }
  }
  if(!finitePoint(latitude,longitude))throw fault(409,'route_coordinates_required','This stop needs geocoding through the existing native Routes geocoder before it can be routed. No coordinates were guessed.');
  stops.push({id:s.id,name,address,latitude:Number(latitude),longitude:Number(longitude),contact_id:s.contact_id||null,source_type:s.contact_id?'contact':s.source_type,status:recalculate?s.status:'not_visited',service_duration_seconds:s.service_duration_seconds??0,locked_order:s.locked_order??null});
 }
 return {value,old,stops,records};
}

export async function executeRoute({app,pool,actor,tool,input,revalidate}){
 const recalculate=tool==='assistant_route_recalculate';
 const parsed=(recalculate?routeRecalculateSchema:routeBuildSchema).parse(input);
 const prepared=await prepareRoute({app,pool,actor,input:parsed,recalculate}),{value,stops,records}=prepared;
 // All times/distances/order come from the existing routing service. The input
 // schema has no metrics fields, and the model cannot supply a replacement plan.
 const plan=await dispatch(app,actor,'POST','/api/routing/route-plan',{start:{id:'route-start',...value.start},stops:stops.map(s=>({id:s.id,label:s.name,latitude:s.latitude,longitude:s.longitude,service_duration_seconds:s.service_duration_seconds,locked_order:s.locked_order})),ending_behavior:value.ending_behavior,end:value.end?{id:'route-end',...value.end}:null,departure_time:value.departure_time,optimize_order:value.optimize_order});
 if(plan.provider!=='google'||plan.ordered_stop_ids?.length!==stops.length||new Set(plan.ordered_stop_ids).size!==stops.length||plan.ordered_stop_ids.some(id=>!stops.some(s=>s.id===id)))throw fault(502,'invalid_canonical_route_plan');
 return transaction(pool,async db=>{
  await db.query('SELECT id FROM mcp_connections WHERE id=$1 FOR UPDATE',[actor.connectionId]);
  actor=await revalidate();
  if(recalculate){await db.query('SELECT id FROM crm_routes WHERE id=$1 AND company_id=$2 FOR UPDATE',[parsed.route_id,actor.companyId]);const current=await dispatch(app,actor,'GET','/api/routes/'+parsed.route_id);if(digest(current)!==parsed.expected_source_hash)throw fault(409,'stale_route');}
  for(const [id,version]of records)if(evidenceHash(await getRecord(pool,actor,'contacts',id,{lock:true}))!==version)throw fault(409,'route_contact_changed');
  const ordered=plan.ordered_stop_ids.map((id,index)=>{
   const stop=stops.find(s=>s.id===id),leg=plan.legs.find(l=>l.to_id===id);
   if(!leg)throw fault(502,'invalid_canonical_route_plan');
   return {...stop,stop_order:index+1,batch_number:Math.floor(index/14)+1,leg_distance_meters:leg.distance_meters,leg_travel_time_seconds:leg.travel_time_seconds,estimated_arrival_at:leg.estimated_arrival_at,estimated_departure_at:leg.estimated_departure_at};
  });
  const route=await dispatch(app,actor,recalculate?'PUT':'POST','/api/routes'+(recalculate?'/'+parsed.route_id:''),{name:value.name,status:value.status,start_label:value.start.label,start_latitude:value.start.latitude,start_longitude:value.start.longitude,start_mode:'custom_address',ending_behavior:value.ending_behavior,end_label:value.end?.label,end_latitude:value.end?.latitude,end_longitude:value.end?.longitude,...Object.fromEntries(['distance_meters','travel_time_seconds','service_time_seconds','total_route_time_seconds','estimated_start_at','estimated_finish_at'].map(k=>[k,plan[k]])),routing_provider:plan.provider,routing_strategy:plan.strategy,routing_calculated_at:plan.calculated_at,stops:ordered});
  const result={id:route.id,entity:'routes',metrics:Object.fromEntries(['distance_meters','travel_time_seconds','service_time_seconds','total_route_time_seconds','estimated_start_at','estimated_finish_at'].map(k=>[k,route[k]])),source_hash:digest(route),warnings:plan.warnings||[],message:'Saved using canonical Google routing metrics. Provider routing charges are separate from model estimates.',content_trust:'untrusted_record_data'};
  // Commit the saved route and receipt atomically. Recovery never recalculates or
  // creates another route after an uncertain provider/save outcome.
  await db.query('UPDATE mcp_operations SET result=$3 WHERE connection_id=$1 AND request_id=$2',[actor.connectionId,parsed.request_id,JSON.stringify(result)]);
  return result;
 });
}
