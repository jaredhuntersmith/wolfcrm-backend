import {z} from 'zod';
import {randomUUID} from 'node:crypto';
import {permit,connection} from './access.js';
import {digest,dispatch,fault,transaction} from './context.js';
import {getRecord,idSchema} from './registry.js';
const text=z.string().trim().min(1).max(200),memo=z.string().max(10000);
const request={request_id:z.uuid().describe('Generate once for this intended write and reuse exactly on retries.')};
const update={...request,id:idSchema,expected_version:z.string().regex(/^[0-9a-f]{64}$/).describe('Exact version from crm_get. A stale version fails without applying changes.')};
const contact=z.object({name:text,phone:z.string().max(80).optional(),email:z.union([z.email(),z.literal('')]).optional(),address:z.string().max(500).optional(),tags:z.array(z.string().max(80)).max(30).optional(),job_type:z.string().max(120).optional()}).strict();
const appointment=z.object({title:text,start:z.iso.datetime({offset:true}),end:z.iso.datetime({offset:true}),notes:memo.optional(),contact_id:idSchema,quote_id:idSchema,worker_user_ids:z.array(z.uuid()).min(1).max(20),sales_user_ids:z.array(z.uuid()).min(1).max(20)}).strict();
const line=z.object({id:z.uuid(),service_id:z.uuid().nullable().optional(),name:text,description:z.string().max(2000).optional(),qty:z.number().positive().max(10000),price_cents:z.number().int().min(0).max(100000000)}).strict();
export const actions=Object.freeze({
 contact_create:{scope:'crm:write',caps:['contacts.create','contacts.view'],schema:z.object({...request,contact}).strict(),entity:'contacts',method:'POST',path:'/api/contacts',body:i=>i.contact},
 contact_details_update:{scope:'crm:write',caps:['contacts.edit','contacts.view'],schema:z.object({...update,changes:z.object({u1:memo.nullable().optional(),u2:memo.nullable().optional(),u3:memo.nullable().optional(),u4:memo.nullable().optional(),u5:memo.nullable().optional(),lead_info:z.array(z.string().max(4000)).max(25).optional(),source:z.string().max(200).nullable().optional(),lead_submitted_at:z.iso.datetime({offset:true}).nullable().optional(),value_cents:z.number().int().min(0).max(1000000000).nullable().optional()}).strict().refine(v=>Object.keys(v).length>0)}).strict(),entity:'contacts',method:'PUT',path:i=>'/api/contacts/'+i.id,body:i=>i.changes},
 task_update:{scope:'crm:write',caps:['tasks.manage','tasks.view'],schema:z.object({...update,changes:z.object({title:text.optional(),detail:memo.nullable().optional(),due_date:z.iso.datetime({offset:true}).nullable().optional(),priority:z.enum(['low','normal','high','urgent']).optional(),linked_contact_id:idSchema.nullable().optional(),linked_job_id:idSchema.nullable().optional(),completed:z.boolean().optional(),completion_note:memo.optional(),completion_note_required:z.boolean().optional(),color_hex:z.string().regex(/^#[0-9a-fA-F]{6}$/).nullable().optional(),subtasks:z.array(z.object({id:z.uuid(),title:text,completed:z.boolean()}).strict()).max(200).optional()}).strict().refine(v=>Object.keys(v).length>0)}).strict(),entity:'tasks',method:'PUT',path:i=>'/api/todo/tasks/'+i.id,body:(i,_id,old)=>({...old,...i.changes,...(i.changes.completed===false?{status:'open',completed_at:null,completed_by:null}:{})})},
 contact_update:{scope:'crm:write',caps:['contacts.edit','contacts.view'],schema:z.object({...update,changes:contact.partial().refine(v=>Object.keys(v).length>0)}).strict(),entity:'contacts',method:'PUT',path:i=>'/api/contacts/'+i.id,body:i=>i.changes},
 task_create:{scope:'crm:write',caps:['tasks.manage','tasks.view'],schema:z.object({...request,title:text,detail:memo.optional(),due_date:z.iso.datetime({offset:true}).optional(),priority:z.enum(['low','normal','high']).default('normal'),linked_contact_id:idSchema.optional(),linked_job_id:idSchema.optional()}).strict(),entity:'tasks',method:'PUT',path:(_i,id)=>'/api/todo/tasks/'+id,body:({request_id,...rest})=>rest},
 task_complete:{scope:'crm:write',caps:['tasks.manage','tasks.view'],schema:z.object({...update,completion_note:memo.optional()}).strict(),entity:'tasks',method:'PUT',path:i=>'/api/todo/tasks/'+i.id,body:(i,_id,old)=>({...old,completed:true,completed_at:new Date().toISOString(),completion_note:i.completion_note??old.completion_note})},
 lead_change_stage:{scope:'crm:write',caps:['pipeline.manage','pipeline.view','contacts.view'],schema:z.object({...update,stage_id:idSchema}).strict(),entity:'opportunities',method:'PUT',path:i=>'/api/opportunities/'+i.id,body:(i,_id,old)=>({...old,stage_id:i.stage_id,state:'stage'})},
 appointment_create:{scope:'crm:write',caps:['schedule.create','schedule.view','jobs.view','schedule.manage_team'],schema:z.object({...request,appointment}).strict(),entity:'jobs',method:'PUT',path:(_i,id)=>'/api/schedule/'+id,body:i=>i.appointment},
 appointment_update:{scope:'crm:write',caps:['schedule.edit','schedule.view','jobs.view','schedule.manage_team'],schema:z.object({...update,changes:appointment.partial().refine(v=>Object.keys(v).length>0)}).strict(),entity:'jobs',method:'PUT',path:i=>'/api/schedule/'+i.id,body:(i,_id,old)=>({...old,start:old.start_at,end:old.end_at,...i.changes})},
 quote_draft:{scope:'crm:write',caps:['quotes.create','quotes.view','contacts.view'],schema:z.object({...request,contact_id:idSchema,title:text,line_items:z.array(line).min(1).max(100),notes:memo.optional(),expires_at:z.iso.datetime({offset:true}).optional(),duration_minutes:z.number().int().min(1).max(1440).optional()}).strict(),entity:'quotes',method:'POST',path:'/api/quotes',body:({request_id,duration_minutes,...rest})=>({...rest,status:'draft',...(duration_minutes?{quote_options:{duration_minutes}}:{})})},
 note_create:{scope:'notes:write',caps:['notes.create','notes.view'],schema:z.object({...request,title:text.max(150),text:memo,visibility:z.enum(['private','company']).default('private'),contact_id:idSchema.optional()}).strict(),entity:'notes'}
});
export async function performAction({pool,app,actor,name,input,webOrigin}){
 const definition=actions[name];if(!definition)throw fault(400,'unknown_action');const i=definition.schema.parse(input);
 return transaction(pool,async db=>{
  await db.query('SELECT id FROM mcp_connections WHERE id=$1 FOR UPDATE',[actor.connectionId]);

  // Serialize permission changes/removal with this mutation; next calls always reload.
  if(!(await db.query('SELECT id FROM users WHERE id=$1 AND company_id=$2 AND deleted_at IS NULL FOR SHARE',[actor.userId,actor.companyId])).rowCount)throw fault(401,'membership_inactive');
  await db.query('SELECT id FROM companies WHERE id=$1 FOR SHARE',[actor.companyId]);
  await db.query('SELECT user_id FROM employee_permissions WHERE user_id=$1 AND company_id=$2 FOR SHARE',[actor.userId,actor.companyId]);
  const fresh=await connection(pool,actor.connectionId);actor={...fresh,scopes:actor.scopes};permit(actor,definition.scope,definition.caps);
  const prior=(await db.query('SELECT * FROM mcp_operations WHERE connection_id=$1 AND request_id=$2',[actor.connectionId,i.request_id])).rows[0];
  const hash=digest(i);if(prior&&(prior.operation!==name||prior.input_hash!==hash))throw fault(409,'idempotency_conflict');
  if(prior){if(definition.entity==='notes')await app.locals.notes.get(actor,prior.result.id,{limit:1});else await getRecord(pool,actor,definition.entity,prior.result.id);return {...prior.result,replayed:true};}
  let old=null;if(i.id){old=await getRecord(pool,actor,definition.entity,i.id,{lock:true});if(digest(old)!==i.expected_version)throw fault(409,'stale_record','This record changed. Retrieve it again before editing.');}
  const id=i.id||randomUUID();let body=definition.body?.(i,id,old);
  for(const contactID of [i.contact_id,body?.contact_id,body?.linked_contact_id].filter(Boolean))await getRecord(pool,actor,'contacts',contactID);
  if(body?.quote_id)await getRecord(pool,actor,'quotes',body.quote_id);
  if(body?.linked_job_id)await getRecord(pool,actor,'jobs',body.linked_job_id);
  const people=[...new Set([...(body?.assignee_ids||[]),...(body?.worker_user_ids||[]),...(body?.sales_user_ids||[])])];
  if(people.length&&(await db.query('SELECT id FROM users WHERE company_id=$1 AND deleted_at IS NULL AND id=ANY($2::uuid[])',[actor.companyId,people])).rowCount!==people.length)throw fault(403,'team_member_unavailable');
  if((name==='task_complete'||name==='task_update'&&i.changes.completed===true)&&old.completion_note_required&&!(i.completion_note||i.changes?.completion_note)?.trim())throw fault(400,'completion_note_required');
  if(name==='lead_change_stage'){const stage=await getRecord(pool,actor,'stages',i.stage_id);body.pipeline_id=stage.pipeline_id;}
  let result;
  if(name==='note_create'){
   if(!app.locals.notes)throw fault(503,'notes_unavailable');
   const created=await app.locals.notes.create(actor,{id,title:i.title,visibility:i.visibility});
   const first=created.blocks[0];const operations=[{id:first.id,expected_revision:first.revision,type:'paragraph',payload:{text:i.text}}];
   if(i.contact_id)operations.push({id:randomUUID(),expected_revision:0,type:'contact',payload:{source_id:i.contact_id},position:1});
   await app.locals.notes.editBlocks(actor,id,{client_key:i.request_id,operations});result={id,entity:'notes'};
  }else{
   const saved=await dispatch(app,actor,definition.method,typeof definition.path==='function'?definition.path(i,id):definition.path,body);
   const target=await getRecord(pool,actor,definition.entity,saved.id);result={id:String(saved.id),entity:definition.entity,version:digest(target)};
  }
  const changed=name==='task_complete'?{completed:1,completed_at:1,completed_by:1,completion_note:1,status:1}:name==='lead_change_stage'?{stage_id:1,pipeline_id:1,state:1}:i.changes||body||i;
  const fields=Object.keys(changed).filter(k=>!['request_id','expected_version'].includes(k));
  await db.query('INSERT INTO mcp_operations(connection_id,request_id,operation,input_hash,result) VALUES($1,$2,$3,$4,$5)',[actor.connectionId,i.request_id,name,hash,JSON.stringify(result)]);
  await db.query("INSERT INTO mcp_audit(connection_id,company_id,user_id,operation,record_id,changed_fields,outcome) VALUES($1,$2,$3,$4,$5,$6,'success')",[actor.connectionId,actor.companyId,actor.userId,name,result.id,JSON.stringify(fields)]);
  return {...result,replayed:false};
 });
}
