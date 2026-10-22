import {z} from 'zod';
import {notificationAccessSQL} from '../company-comms/notifications.js';
import {taskAccessSQL} from '../company-comms/tasks.js';
import {conversationJoins,conversationAccessSQL} from '../company-comms/access.js';
import {permit} from './access.js';
import {digest,fault} from './context.js';
const company=()=> "r.company_id=$2 AND to_jsonb(r)->>'deleted_at' IS NULL";
const definition=(table,cap,fields,options={})=>Object.freeze({table,scope:'crm:read',caps:[cap],fields:fields.split(' '),where:company,search:'title',date:'created_at',section:'contacts',...options});
const ownedFinancial=actor=>`r.company_id=$2 AND r.user_id=(SELECT owner_user_id FROM companies WHERE id=$2) ${actor.isCompanyOwner?'':'AND r.created_by_user_id=$1'}`;
// This is the exposure boundary. Additions require an explicit field/permission review.
export const registry=Object.freeze({
 contacts:definition('contacts','contacts.view','id name phone email address tags job_type source value_cents created_at updated_at',{search:'name',section:'contacts'}),
 leads:definition('contacts','contacts.view','id name phone email address tags source lead_info lead_submitted_at created_at updated_at',{search:'name',date:'lead_submitted_at'}),
 stages:definition('stages','pipeline.view','id name pipeline_id order_idx updated_at',{search:'name',section:'stages'}),
 pipelines:definition('pipelines','pipeline.view','id name is_default order_idx created_at updated_at',{search:'name',section:'stages'}),
 opportunities:definition('opportunities','pipeline.view','id contact_id state stage_id pipeline_id stage_entered_at created_at updated_at',{search:'state',related:'contact_id',section:'stages'}),
 jobs:definition('schedule_events','jobs.view','id title start_at end_at notes contact_id quote_id services service_items price_cents material_cost_cents worker_user_ids sales_user_ids started_at finished_at created_at updated_at',{caps:['jobs.view','schedule.view'],where:actor=>`${company()} AND (${actor.isCompanyOwner||actor.permissions?.capabilities?.['schedule.manage_team']?'true':'false'} OR r.worker_user_ids ? $1::text OR r.sales_user_ids ? $1::text)`,date:'start_at',related:'contact_id',section:'schedule'}),
 tasks:definition('todo_tasks','tasks.view','id title detail assignee_ids due_date priority status linked_contact_id linked_job_id completed completed_at completion_note completion_note_required created_at updated_at',{
 where:actor=>`r.company_id=$2 AND ${taskAccessSQL(actor,'r')}`,related:'linked_contact_id',date:'due_date',section:'tasks'}),
 quotes:definition('quotes','quotes.view','id contact_id title line_items total_cents notes status expires_at sent_at accepted_at declined_at converted_job_id created_at updated_at',{where:()=>"r.company_id=$2 AND r.deleted_at IS NULL",related:'contact_id',section:'contacts'}),
 agreements:definition('quote_agreements','quotes.view','id contact_id quote_id number revision title decision revoked_at expires_at signed_at documents_ready created_at updated_at',{related:'contact_id',section:'agreements'}),
 invoices:definition('invoices','invoices.view','id contact_id job_id quote_id status line_items subtotal_cents total_cents currency due_at issued_at paid_at created_at updated_at',{related:'contact_id',date:'due_at',search:'status',section:'contacts'}),
 payments:definition('payment_records','payments.view','id contact_id job_id agreement_id amount_cents refunded_amount_cents currency status paid_at created_at updated_at',{where:ownedFinancial,related:'contact_id',search:'status',date:'paid_at'}),
 service_plans:definition('service_plans','service_plans.view','id contact_id plan_name status price_cents currency billing_interval billing_interval_count service_interval service_interval_count first_service_date next_service_date last_service_date included_services notes created_at updated_at',{where:ownedFinancial,caps:['service_plans.view','payments.view'],related:'contact_id',search:'plan_name'}),
 team:definition('users','team.view','id display_name role',{scope:'team:read',where:()=> 'r.company_id=$2 AND r.deleted_at IS NULL',search:'display_name',section:'settings'}),
 expenses:definition('finance_transactions','finance.transactions.view','id amount_cents transaction_date merchant_name direction status pending currency normalized_category created_at updated_at',{scope:'finance:read',where:actor=>actor.isCompanyOwner?"r.company_id=$2 AND r.direction='expense' AND r.removed_at IS NULL AND r.finance_space_id IS NOT NULL":'false',search:'merchant_name',date:'transaction_date',section:'finance'}),
 notifications:definition('notifications','notifications.view','id kind title body created_at read_at',{scope:'comms:read',where:actor=> `r.company_id=$2 AND r.user_id=$1 AND r.deleted_at IS NULL AND EXISTS(SELECT 1 FROM notifications n WHERE n.id=r.id AND ${notificationAccessSQL(actor)})`,section:'messages'}),
 customer_conversations:definition('sms_conversations','messaging.customer.view','id contact_id external_phone_number last_message_at created_at updated_at',{scope:'comms:read',where:()=>"r.deleted_at IS NULL AND EXISTS(SELECT 1 FROM phone_lines line WHERE line.id=r.phone_line_id AND line.company_id=$2)",related:'contact_id',search:'external_phone_number',date:'last_message_at',section:'messages'}),
 customer_messages:definition('sms_messages','messaging.customer.view','id conversation_id direction from_number to_number body message_status media_count created_at updated_at',{scope:'comms:read',where:()=>"r.deleted_at IS NULL AND EXISTS(SELECT 1 FROM sms_conversations sc JOIN phone_lines pl ON pl.id=sc.phone_line_id WHERE sc.id=r.conversation_id AND sc.deleted_at IS NULL AND pl.company_id=$2 AND (sc.contact_id IS NULL OR EXISTS(SELECT 1 FROM contacts parent WHERE parent.id=sc.contact_id AND parent.company_id=$2 AND parent.deleted_at IS NULL)))",search:'body',section:'messages'}),
 conversations:definition('conversations','communications.view','id title scope created_at updated_at',{scope:'comms:read',where:actor=>`r.company_id=$2 AND EXISTS(SELECT 1 FROM conversations c ${conversationJoins} WHERE c.id=r.id AND ${conversationAccessSQL(actor)})`,section:'messages'})
});
export const entityNames=Object.keys(registry);
export const idSchema=z.string().min(1).max(160).regex(/^[A-Za-z0-9_-]+$/);
export const searchSchema=z.object({entity:z.enum(entityNames),query:z.string().max(200).default(''),limit:z.number().int().min(1).max(50).default(25),finance_space_id:z.uuid().optional(),offset:z.number().int().min(0).max(10000).default(0),contact_id:idSchema.optional(),conversation_id:idSchema.optional(),status:z.string().max(60).optional(),from:z.iso.datetime({offset:true}).optional(),to:z.iso.datetime({offset:true}).optional()}).strict();
const safeNested=(key,value)=>{
 if(['line_items','service_items'].includes(key)&&Array.isArray(value))return value.slice(0,200).map(item=>Object.fromEntries(['id','service_id','name','description','qty','price_cents','duration_minutes','unit'].filter(k=>Object.hasOwn(item,k)).map(k=>[k,item[k]])));
 if(key==='lead_info'&&Array.isArray(value))return value.slice(0,25).map(item=>typeof item==='string'?item.slice(0,4000):Object.fromEntries(['label','value','question','answer'].filter(k=>Object.hasOwn(item,k)).map(k=>[k,String(item[k]).slice(0,4000)])));
 return value??null;
};
export function record(entity,row,webOrigin){
 const config=registry[entity];const data=Object.fromEntries(config.fields.map(k=>[k,safeNested(k,row[k])]));
 return {entity,id:String(row.id),version:digest(row),data,web_url:webOrigin?`${webOrigin}/${config.section}`:null,link_kind:'module',content_trust:'untrusted_record_data'};
}
export function checkEntity(actor,entity){const config=registry[entity];if(!config)throw fault(400,'unknown_entity');permit(actor,config.scope,config.caps);if(entity==='expenses'&&!actor.isCompanyOwner)throw fault(403,'owner_required');return config;}
// Explicit relationships prevent a corrupt/legacy foreign link from broadening
// access. This is a reviewed allowlist, never foreign-key introspection.
const relatedOwnership={stages:{pipeline_id:'pipelines'},opportunities:{stage_id:'stages',pipeline_id:'pipelines'},jobs:{quote_id:'quotes'},tasks:{linked_job_id:'schedule_events'},quotes:{converted_job_id:'schedule_events'},agreements:{quote_id:'quotes'},invoices:{job_id:'schedule_events',quote_id:'quotes'},payments:{job_id:'schedule_events',agreement_id:'quote_agreements'}};
function ownershipPredicates(entity,config){
 const refs={...(config.related?{[config.related]:'contacts'}:{}),...relatedOwnership[entity]};
 return Object.entries(refs).map(([field,table])=>`(to_jsonb(r)->>'${field}' IS NULL OR EXISTS(SELECT 1 FROM ${table} parent WHERE parent.id::text=to_jsonb(r)->>'${field}' AND parent.company_id=$2 AND to_jsonb(parent)->>'deleted_at' IS NULL))`);
}
export async function getRecord(pool,actor,entity,id,{lock=false}={}){
 const config=checkEntity(actor,entity);
 const predicates=ownershipPredicates(entity,config);const parent=predicates.length?' AND '+predicates.join(' AND '):'';
 const row=(await pool.query(`SELECT to_jsonb(r) AS data FROM ${config.table} r WHERE $1::uuid IS NOT NULL AND ${config.where(actor)}${parent} AND r.id::text=$3 ${lock?'FOR UPDATE OF r':''}`,[actor.userId,actor.companyId,id])).rows[0]?.data;
 if(!row)throw fault(404,'record_not_found');return row;
}
export async function searchRecords(pool,actor,input,webOrigin){
 const c=checkEntity(actor,input.entity),values=[actor.userId,actor.companyId],where=[c.where(actor)];
 // Always bind both actor parameters, including company-only predicates.
 where.push('$1::uuid IS NOT NULL');
 where.push(...ownershipPredicates(input.entity,c));
 const add=v=>{values.push(v);return '$'+values.length;};
 if(input.query){const term=add('%'+input.query.replace(/[\\%_]/g,'\\$&')+'%');const fields=['contacts','leads'].includes(input.entity)?['name','email','phone','address']: [c.search];where.push('('+fields.map(f=>`COALESCE(to_jsonb(r)->>'${f}','') ILIKE ${term}`).join(' OR ')+')');}
 if(input.contact_id){if(!c.related)throw fault(400,'unsupported_contact_filter');await getRecord(pool,actor,'contacts',input.contact_id);where.push(`r.${c.related}::text=${add(input.contact_id)}`);}
 if(input.conversation_id){if(input.entity!=='customer_messages')throw fault(400,'unsupported_conversation_filter');await getRecord(pool,actor,'customer_conversations',input.conversation_id);where.push('r.conversation_id::text='+add(input.conversation_id));}
 if(input.status){const field=input.entity==='opportunities'?'state':'status';if(!c.fields.includes(field))throw fault(400,'unsupported_status_filter');where.push(`to_jsonb(r)->>'${field}'=${add(input.status)}`);}
 if(input.from||input.to){if(input.from&&input.to&&Date.parse(input.from)>=Date.parse(input.to))throw fault(400,'invalid_date_range');if(input.from)where.push(`(to_jsonb(r)->>'${c.date}')::timestamptz>=${add(input.from)}::timestamptz`);if(input.to)where.push(`(to_jsonb(r)->>'${c.date}')::timestamptz<${add(input.to)}::timestamptz`);}
 const rows=(await pool.query(`SELECT to_jsonb(r) AS data FROM ${c.table} r WHERE ${where.join(' AND ')} ORDER BY r.id LIMIT ${add(input.limit+1)} OFFSET ${add(input.offset)}`,values)).rows;
 return {items:rows.slice(0,input.limit).map(r=>record(input.entity,r.data,webOrigin)),next_offset:rows.length>input.limit?input.offset+input.limit:null,time_zone:actor.timezone,date_semantics:'from inclusive, to exclusive; timestamps include UTC offset',catalog_version:'2026-10-17.1'};
}
