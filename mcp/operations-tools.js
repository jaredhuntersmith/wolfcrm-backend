import {z} from 'zod';
import {dispatch,digest,fault} from './context.js';
import {repairStatusValues,repairPriorityValues} from '../operations-repairs.js';

const id=z.string().regex(/^[A-Za-z0-9_:-]{1,160}$/),uuid=z.uuid(),empty=z.object({}).strict();
const hash=z.string().regex(/^[a-f0-9]{64}$/),text=z.string().max(4000),money=z.number().int().min(0).max(100000000000).nullable();
const amount=z.number().min(0).max(1000000000),time=z.iso.datetime({offset:true}).nullable();
const view=['operations.view'],manage=['operations.view','operations.manage'],request=['operations.view','operations.request'];

export function registerOperationsTools({read,write,app,pool,actor}) {
  const paths={item:'/api/operations/inventory/items',request:'/api/operations/requests',repair:'/api/operations/repairs',count_schedule:'/api/operations/inventory-counts/schedules',count_submission:'/api/operations/inventory-counts/submissions'};
  const tables={item:'inventory_items',request:'equipment_requests',repair:'equipment_repairs',count_schedule:'inventory_count_schedules',count_submission:'inventory_count_submissions'};
  // This fixed internal map supplies concurrency checks, never arbitrary model SQL.
  async function current(kind,target,lock=false) {
    if(lock)await pool.query(`SELECT id FROM ${tables[kind]} WHERE id=$1 AND company_id=$2 FOR UPDATE`,[target,actor.companyId]);
    const rows=await dispatch(app,actor,'GET',paths[kind]);
    const value=rows.find(row=>row.id===target);
    if(!value)throw fault(404,'equipment_record_unavailable');
    return value;
  }
  async function guard(kind,target,expected) {
    const row=await current(kind,target,true);
    if(digest(row)!==expected)throw fault(409,'stale_equipment_record');
    return row;
  }
  async function reference(table,target) {
    if(target==null)return;
    const allowed=new Set(['inventory_items','inventory_locations','users','schedule_events','inventory_transactions']);
    if(!allowed.has(table))throw new Error('Invalid internal equipment reference type');
    if(!(await pool.query(`SELECT id FROM ${table} WHERE id=$1 AND company_id=$2${table==='users'?' AND deleted_at IS NULL':''}`,[target,actor.companyId])).rowCount)throw fault(404,'equipment_reference_unavailable');
  }
  read('equipment_locations','Read company inventory locations. Use these IDs when assigning or moving stock.',empty,'crm:read',view,'/api/operations/inventory/locations');
  for(const kind of Object.keys(paths))read('equipment_'+kind,'Read one accessible equipment '+kind.replaceAll('_',' ')+' with the source_hash required for updates.',z.object({id}).strict(),'crm:read',view,null,i=>current(kind,i.id));
  const item=z.object({name:z.string().trim().min(1).max(200),item_type:z.enum(['material','equipment']),tracking_mode:z.enum(['quantity','serialized']),category:z.string().max(100).nullable(),unit:z.string().trim().min(1).max(60),reorder_point:amount.nullable(),cost_per_unit_cents:money,status:z.enum(['available','in_use','under_repair','broken','lost','retired','needs_inspection']),location_id:id.nullable(),assigned_user_id:uuid.nullable(),notes:text.nullable()}).strict();
  async function saveItem(target,body) {
    await reference('inventory_locations',body.location_id);await reference('users',body.assigned_user_id);
    return dispatch(app,actor,'PUT',paths.item+'/'+target,body);
  }
  write('equipment_item_create','Create inventory metadata. Stock starts at zero; receive stock with equipment_transaction. The request ID becomes the stable item ID.',item,'crm:write',manage,'PUT',null,null,async(i,key)=>{
    if((await pool.query('SELECT id FROM inventory_items WHERE id=$1',[key])).rowCount)throw fault(409,'equipment_id_in_use');
    return saveItem(key,i);
  });
  write('equipment_item_update','Update supplied inventory metadata after reading equipment_item; omitted fields are preserved. Quantities and history cannot be overwritten; current assignment and location must belong to this company.',item.partial().extend({id,expected_source_hash:hash}).refine(i=>Object.keys(i).length>2),'crm:write',manage,'PUT',null,null,async({id:target,expected_source_hash,...body})=>{const old=await guard('item',target,expected_source_hash);return saveItem(target,{...Object.fromEntries(Object.keys(item.shape).map(k=>[k,old[k]])),...body});});
  write('equipment_transaction','Record receipt, return, job usage, damage, loss, disposal or positive recount correction through canonical stock accounting. Negative stock is rejected and job material cost is calculated by the service. Use the count-review workflow for a full recount.',z.object({item_id:id,transaction_type:z.enum(['received','returned','used_on_job','damaged','lost','disposed','recount_correction']),quantity:amount.positive(),from_location_id:id.nullable().optional(),to_location_id:id.nullable().optional(),job_id:id.nullable().optional(),note:text.nullable().optional(),reverses_transaction_id:id.nullable().optional()}).strict(),'crm:write',request,'POST',null,null,async(i,key)=>{
    await reference('inventory_items',i.item_id);await reference('inventory_locations',i.from_location_id);await reference('inventory_locations',i.to_location_id);await reference('schedule_events',i.job_id);await reference('inventory_transactions',i.reverses_transaction_id);
    return dispatch(app,actor,'POST','/api/operations/inventory/transactions',{...i,idempotency_key:key});
  });
  write('equipment_request_create','Request material/equipment or report a problem through the normal request workflow. Does not place an external order.',z.object({request_type:z.enum(['request_material','request_equipment','report_broken','report_damaged','report_lost','needs_inspection','stock_discrepancy']),item_id:id.nullable(),item_name:z.string().max(200).nullable(),quantity:amount.nullable(),urgency:z.enum(['normal','high','urgent']),explanation:text.min(1)}).strict(),'crm:write',request,'POST',null,null,async i=>{await reference('inventory_items',i.item_id);return dispatch(app,actor,'POST',paths.request,i);});
  write('equipment_request_update','Review an existing equipment request with its current source_hash. This records an internal decision; it does not buy or send anything.',z.object({id,expected_source_hash:hash,status:z.enum(['pending','under_review','approved','denied','fulfilled','cancelled']),owner_response:text.nullable()}).strict(),'crm:write',manage,'PATCH',null,null,async({id:target,expected_source_hash,...body})=>{await guard('request',target,expected_source_hash);return dispatch(app,actor,'PATCH',paths.request+'/'+target,body);});
  const repair=z.object({assigned_user_id:uuid.nullable(),vendor:z.string().max(200).nullable(),problem:z.string().trim().min(1).max(2000),diagnosis:text.nullable(),status:z.enum(repairStatusValues()),priority:z.enum(repairPriorityValues()),estimated_cost_cents:money,actual_cost_cents:money,scheduled_at:time,resolution_notes:text.nullable()}).strict();
  write('equipment_repair_create','Create a repair through the canonical lifecycle; related asset status and history are updated by the service. equipment_request_id optionally links the existing equipment request.',repair.extend({item_id:id,equipment_request_id:uuid.nullable()}),'crm:write',manage,'POST',paths.repair,({equipment_request_id,...i})=>({...i,request_id:equipment_request_id}));
  write('equipment_repair_update','Revise an equipment repair using its source_hash. Canonical lifecycle timestamps, asset status and history are preserved.',repair.partial().extend({id:uuid,expected_source_hash:hash}).refine(i=>Object.keys(i).length>2),'crm:write',manage,'PATCH',null,null,async({id:target,expected_source_hash,...body})=>{await guard('repair',target,expected_source_hash);return dispatch(app,actor,'PATCH',paths.repair+'/'+target,body);});
  read('equipment_count_schedules','Read inventory count schedules with assignment and approval configuration.',empty,'crm:read',view,paths.count_schedule);
  read('equipment_count_assignees','Read active company users eligible for count assignment.',empty,'team:read',manage,'/api/operations/inventory-counts/assignees');
  const schedule=z.object({name:z.string().trim().min(1).max(160),location_id:id,assigned_user_id:uuid.nullable(),frequency:z.enum(['weekly','biweekly','monthly','quarterly']),due_date:z.iso.date().nullable(),due_time:z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/).nullable(),reminder_minutes:z.number().int().min(0).max(10080).nullable(),variance_threshold:amount,approval_required:z.boolean(),enabled:z.boolean()}).strict();
  write('equipment_count_schedule_create','Create a count schedule through canonical location, assignment and recurrence validation. Uses the request ID as schedule ID.',schedule,'crm:write',manage,'PUT',null,null,async(i,key)=>{if((await pool.query('SELECT id FROM inventory_count_schedules WHERE id=$1',[key])).rowCount)throw fault(409,'equipment_id_in_use');return dispatch(app,actor,'PUT',paths.count_schedule+'/'+key,i);});
  write('equipment_count_schedule_update','Update a current inventory count schedule using its source_hash. This does not change an existing submitted count.',schedule.extend({id,expected_source_hash:hash}),'crm:write',manage,'PUT',null,null,async({id:target,expected_source_hash,...body})=>{await guard('count_schedule',target,expected_source_hash);return dispatch(app,actor,'PUT',paths.count_schedule+'/'+target,body);});
  write('equipment_count_generate','Generate a count snapshot for the exact reviewed schedule/date. The canonical schedule/date deduplication still applies.',z.object({id,expected_source_hash:hash,due_date:z.iso.date().nullable()}).strict(),'crm:write',manage,'POST',null,null,async({id:target,expected_source_hash,...body})=>{await guard('count_schedule',target,expected_source_hash);return dispatch(app,actor,'POST',paths.count_schedule+'/'+target+'/generate',body);});
  read('equipment_count_submissions','Read permitted count snapshots, item quantities and review status.',empty,'crm:read',view,'/api/operations/inventory-counts/submissions');
  write('equipment_count_submit','Submit actual counted quantities for every item in an assigned snapshot. Canonical completeness and assignment checks apply; only a schedule already configured for automatic approval may reconcile immediately.',z.object({id,items:z.array(z.object({item_id:id,counted_quantity:amount,note:z.string().max(1000).nullable()}).strict()).min(1).max(500)}).strict(),'crm:write',request,'POST',i=>'/api/operations/inventory-counts/submissions/'+i.id+'/submit',({id,...i})=>i);
  write('equipment_count_review','Approve or reject the exact reviewed submitted count through canonical reconciliation. Approval records the actual inventory adjustment once; changed quantities invalidate the source_hash.',z.object({id,expected_source_hash:hash,action:z.enum(['approve','reject']),note:z.string().max(2000).nullable()}).strict(),'crm:write',manage,'POST',null,null,async({id:target,expected_source_hash,...body})=>{await guard('count_submission',target,expected_source_hash);return dispatch(app,actor,'POST',paths.count_submission+'/'+target+'/review',body);});
}
