import {z} from 'zod';
import {dispatch,digest,fault} from './context.js';
import {getRecord} from './registry.js';
import {performAction} from './actions.js';
import {memoryInput} from '../assistant/memory.js';

const uuid=z.uuid(),id=z.string().regex(/^[A-Za-z0-9_-]{1,160}$/),empty=z.object({}).strict();
const title=z.string().trim().min(1).max(150),text=z.string().max(10000),hash=z.string().regex(/^[a-f0-9]{64}$/);
const revision=z.number().int().positive(),page={offset:z.number().int().nonnegative().default(0),limit:z.number().int().min(1).max(100).default(25)};
const query=i=>new URLSearchParams(Object.entries(i).filter(([,v])=>v!==undefined&&v!==null).map(([k,v])=>[k,String(v)])).toString();

// Each operation is a specific canonical workflow. New capabilities are denied
// by default even where an existing OAuth connection has the broader scope.
export function registerExpandedTools({read,write,actor,app,pool}){
 read('assistant_memories','Inspect your private saved preferences and inferred memories, including provenance and current revision. Memories are not authoritative CRM data.',empty,'crm:read',['ai.use'],null,()=>app.locals.assistant.memory.list(actor));
 write('assistant_memory_save','Save or revise a personal preference or a clearly labelled inference with provenance. Never save credentials, hidden reasoning or CRM record contents. Both global and conversation memory must be enabled; exact revisions protect edits.',memoryInput,'crm:write',['ai.use'],'POST',null,null,i=>app.locals.assistant.memory.save(actor,i,{fromAssistant:true}));
 write('assistant_memory_delete','Forget one of your saved memories. Does not delete the chat transcript or change CRM facts.',z.object({id:uuid}).strict(),'crm:write',['ai.use'],'DELETE',null,null,i=>app.locals.assistant.memory.remove(actor,i.id));
 read('contact_details','Read authorized custom contact fields, Lead Info boxes, attribution and their exact record version. These are editable source values, not calculated revenue.',z.object({id}).strict(),'crm:read',['contacts.view'],null,async i=>{
  const row=await getRecord(pool,actor,'contacts',i.id);
  return {id:row.id,version:digest(row),fields:Object.fromEntries(['u1','u2','u3','u4','u5','lead_info','source','lead_submitted_at','value_cents'].map(k=>[k,row[k]??null]))};
 });
 const bulkContact=z.object({id,expected_version:hash,changes:z.object({name:z.string().trim().min(1).max(200).optional(),phone:z.string().max(80).optional(),email:z.union([z.email(),z.literal('')]).optional(),address:z.string().max(500).optional(),tags:z.array(z.string().max(80)).max(30).optional(),job_type:z.string().max(120).optional()}).strict().refine(v=>Object.keys(v).length>0),request_id:uuid}).strict();
 write('contacts_bulk_update','Atomically update up to 20 explicitly selected contacts. Each record needs its current crm_get version and a unique request_id. Any conflict rolls back the whole batch.',z.object({items:z.array(bulkContact).min(1).max(20)}).strict(),'crm:write',['contacts.edit','contacts.view'],'PUT',null,null,async i=>{
  if(new Set(i.items.map(x=>x.id)).size!==i.items.length||new Set(i.items.map(x=>x.request_id)).size!==i.items.length)throw fault(400,'duplicate_bulk_identity');
  const items=[];for(const input of [...i.items].sort((a,b)=>a.id.localeCompare(b.id)))items.push(await performAction({pool,app,actor,name:'contact_update',input}));return {items};
 });
 write('task_delete','Delete your own task after checking its exact crm_get version. Company access alone does not grant deletion of another person’s task.',z.object({id,expected_version:hash}).strict(),'crm:write',['tasks.manage','tasks.view'],'DELETE',null,null,async i=>{
  const row=await getRecord(pool,actor,'tasks',i.id,{lock:true});if(row.user_id!==actor.userId)throw fault(403,'task_owner_required');if(digest(row)!==i.expected_version)throw fault(409,'stale_record');await dispatch(app,actor,'DELETE','/api/todo/tasks/'+i.id,{});return {id:i.id,deleted:true};
 });
 read('notes_members','Read the explicit audience of a Note you own or manage.',z.object({id:uuid}).strict(),'notes:read',['notes.view','notes.share'],i=>`/api/notes/pages/${i.id}/members`);
 write('notes_share','Replace the explicit Note audience with exact members and roles. Requires the current page revision and full page access. The existing service validates every recipient and does not permit changing a conversation Note audience.',z.object({id:uuid,expected_revision:revision,members:z.array(z.object({user_id:uuid,role:z.enum(['viewer','commenter','editor','full'])}).strict()).max(100)}).strict(),'notes:write',['notes.view','notes.share'],'PUT',i=>`/api/notes/pages/${i.id}/members`,({id,...i})=>i);
 read('notes_version','Read an authorized historical Note revision. Referenced records/files are rehydrated under current access.',z.object({id:uuid,revision}).strict(),'notes:read',['notes.view'],i=>`/api/notes/pages/${i.id}/versions/${i.revision}`);
 write('notes_restore_version','Restore Note content from one revision while retaining current ownership/access and live child pages. Requires the current page revision; stale edits fail.',z.object({id:uuid,revision,expected_revision:revision}).strict(),'notes:write',['notes.view'],'POST',i=>`/api/notes/pages/${i.id}/restore`,({id,...i})=>i);
 read('notes_people','Find authorized company people for Note sharing and mentions.',z.object({search:z.string().max(100).default('')}).strict(),'notes:read',['notes.view'],i=>'/api/notes/people?'+query(i));
 read('notes_block','Read one authorized Note block with current referenced-record access checks.',z.object({id:uuid,block_id:uuid}).strict(),'notes:read',['notes.view'],i=>`/api/notes/pages/${i.id}/blocks/${i.block_id}`);
 read('notes_comments','Read bounded authorized Note comments, threads and resolution state.',z.object({id:uuid,...page}).strict(),'notes:read',['notes.view'],i=>`/api/notes/pages/${i.id}/comments?${query(i)}`);
 write('notes_comment_create','Add an authorized Note comment or reply with canonical mention and membership checks.',z.object({page_id:uuid,body:text.min(1),parent_id:uuid.optional(),block_id:uuid.optional(),mentions:z.array(uuid).max(30).default([])}).strict(),'notes:write',['notes.view'],'POST',i=>`/api/notes/pages/${i.page_id}/comments`,({page_id,...i},key)=>({...i,id:key}));
 write('notes_comment_update','Edit, resolve, reopen or delete a Note comment with its exact revision. Only the author may edit its text.',z.object({page_id:uuid,id:uuid,expected_revision:revision,body:text.min(1).optional(),resolved:z.boolean().optional(),deleted:z.boolean().optional(),mentions:z.array(uuid).max(30).optional()}).strict(),'notes:write',['notes.view'],'PATCH',i=>`/api/notes/pages/${i.page_id}/comments/${i.id}`,({page_id,id,...i})=>i);
 write('notes_template_save','Save an owned Note as a reusable template. Does not widen its audience.',z.object({id:uuid,page_id:uuid,title}).strict(),'notes:write',['notes.view','notes.templates'],'POST','/api/notes/templates',i=>i);
 write('notes_template_create','Instantiate an authorized built-in or saved template as a private Note, preserving supported blocks and relationships.',z.object({template_id:id,id:uuid}).strict(),'notes:write',['notes.view','notes.create'],'POST',i=>`/api/notes/templates/${i.template_id}/create`,i=>({id:i.id}));
 const filters=z.object({tag:z.string().max(60).optional(),creator_id:uuid.optional(),owner_id:uuid.optional(),scope:z.enum(['all','private','company','shared','favorites','archive']).optional(),contains:z.enum(['checklist','file','crm','unresolved_comments']).optional(),updated_days:z.number().int().min(1).max(3650).optional()}).strict();
 write('notes_smart_folder_save','Save or delete your own smart folder using the existing Notes filter engine.',z.object({id:uuid,title,filters,deleted:z.boolean().default(false)}).strict(),'notes:write',['notes.view'],'POST','/api/notes/smart-folders',i=>i);
 read('notes_smart_folder_pages','Read an authorized saved smart folder with pagination.',z.object({id:uuid,...page}).strict(),'notes:read',['notes.view'],i=>`/api/notes/smart-folders/${i.id}/pages?${query(i)}`);
 read('notes_preferences','Read your Note comment and mention notification preferences.',empty,'notes:read',['notes.view'],'/api/notes/preferences');
 write('notes_preferences_save','Update your own Note notification preferences.',z.object({comment_push:z.boolean().optional(),mention_push:z.boolean().optional()}).strict(),'notes:write',['notes.view'],'PUT','/api/notes/preferences',i=>i);
 read('equipment_inventory','Read authorized inventory metadata, stock and assignments. Quantity is derived from inventory transactions.',empty,'crm:read',['operations.view'],'/api/operations/inventory/items');
 read('equipment_history','Read a company equipment item’s activity and custody history.',z.object({id}).strict(),'crm:read',['operations.view'],i=>`/api/operations/inventory/items/${i.id}/history`);
 read('equipment_requests','Read company equipment/material requests.',empty,'crm:read',['operations.view'],'/api/operations/requests');
 read('equipment_repairs','Read company equipment repairs and status.',empty,'crm:read',['operations.view'],'/api/operations/repairs');
 write('route_stop_update','Update the status or order of an existing route stop. The route’s source_hash must match route_get. Changing order does not recompute driving estimates; recalculate in Routes before relying on timings.',z.object({route_id:uuid,stop_id:uuid,expected_source_hash:hash,status:z.enum(['not_visited','arrived','completed','skipped']).optional(),stop_order:z.number().int().min(0).max(1000).optional()}).strict(),'crm:write',['routes.view','routes.edit'],'PATCH',null,null,async i=>{
  await pool.query('SELECT id FROM crm_routes WHERE id=$1 AND company_id=$2 FOR UPDATE',[i.route_id,actor.companyId]);
  const route=await dispatch(app,actor,'GET',`/api/routes/${i.route_id}`);if(digest(route)!==i.expected_source_hash)throw fault(409,'stale_record');
  return dispatch(app,actor,'PATCH',`/api/routes/${i.route_id}/stops/${i.stop_id}`,{status:i.status,stop_order:i.stop_order});
 });
 write('quote_settings_save','Change quote presentation, tax configuration and validity using the existing validated settings. Requires the exact source_hash from quote_settings.',z.object({expected_source_hash:hash,changes:z.object({tagline:z.string().max(400).nullable().optional(),phone:z.string().max(80).nullable().optional(),email:z.string().max(160).nullable().optional(),website:z.string().max(200).nullable().optional(),notes:z.string().max(3000).nullable().optional(),tax_enabled:z.boolean().optional(),tax_rate_basis_points:z.number().int().min(0).max(5000).optional(),valid_for_days:z.number().int().min(1).max(365).optional(),tax_inclusive:z.boolean().optional(),discount_stacking_policy:z.enum(['best_price','quote_then_plan']).optional()}).strict().refine(v=>Object.keys(v).length>0)}).strict(),'crm:write',['settings.manage_company'],'PATCH',null,null,async i=>{
  await pool.query('SELECT company_id FROM quote_settings WHERE company_id=$1 FOR UPDATE',[actor.companyId]);
  const current=await dispatch(app,actor,'GET','/api/quotes/settings');if(digest(current)!==i.expected_source_hash)throw fault(409,'stale_record');return dispatch(app,actor,'PATCH','/api/quotes/settings',i.changes);
 });
 write('quote_delivery_preview','Prepare the canonical customer-facing quote/agreement preview using the quote’s saved template and options. Returns the exact preview hash, pricing and scope; does not send anything or accept/sign for the customer.',z.object({quote_id:uuid,template_id:uuid.optional(),template_version:revision.optional()}).strict(),'crm:write',['quotes.view'],'POST',null,null,async i=>{
  await getRecord(pool,actor,'quotes',i.quote_id);
  const {quote_id,...options}=i;
  const result=await dispatch(app,actor,'POST',`/api/quotes/${quote_id}/preview`,options);
  return {preview_hash:result.preview_hash,quote_updated_at:result.quote_updated_at,validation:result.validation,snapshot:result.snapshot};
 });
 write('quote_publish_link','Publish the exact canonical quote preview as a customer link. Requires the preview hash and quote timestamp. Does not send, sign, charge or accept it; use the separately authorized messaging workflow for delivery.',z.object({quote_id:uuid,expected_preview_hash:hash,expected_updated_at:z.iso.datetime({offset:true}),template_id:uuid.optional(),template_version:revision.optional()}).strict(),'crm:write',['quotes.create','quotes.view'],'POST',null,null,async(i,key)=>{
  await getRecord(pool,actor,'quotes',i.quote_id);const {quote_id,...options}=i;
  return dispatch(app,actor,'POST',`/api/quotes/${quote_id}/publish`,{...options,request_id:key});
 });
 read('focus_creator','Read one accessible Focus creator.',z.object({id:uuid}).strict(),'crm:read',['focus.view'],i=>`/api/focus/creators/${i.id}`);
 write('focus_like','Save a Focus item as liked through the existing personal workspace service.',z.object({id:uuid}).strict(),'crm:write',['focus.view'],'PUT',i=>`/api/focus/likes/${i.id}`,()=>({}));
 write('focus_unlike','Remove a personal Focus like.',z.object({id:uuid}).strict(),'crm:write',['focus.view'],'DELETE',i=>`/api/focus/likes/${i.id}`,()=>({}));
 write('focus_block_creator','Block a Focus creator in your own feed.',z.object({id:uuid,reason:z.string().max(300).optional()}).strict(),'crm:write',['focus.view'],'POST',i=>`/api/focus/creators/${i.id}/block`,({id,...i})=>i);
 write('focus_unblock_creator','Remove a creator block from your own Focus feed.',z.object({id:uuid}).strict(),'crm:write',['focus.view'],'DELETE',i=>`/api/focus/creators/${i.id}/block`,()=>({}));
}
