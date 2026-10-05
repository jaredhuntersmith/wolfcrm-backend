import {randomUUID} from 'node:crypto';
import {mutate,loadActor,requireCapability,uuid,text,fail} from '../company-comms/access.js';
import {authorizePage,noteRoleSQL} from './access.js';
import {validateBlockReferences} from './blocks.js';
export const BUILTIN_TEMPLATES = [
 ['blank','Blank',[]],['meeting','Meeting Notes',['Date: {{date}}','Attendees','Agenda','Notes','Decisions','Action Items']],
 ['daily','Daily Plan',['{{date}} · {{creator}}','Priorities','Schedule','Checklist','Reflection']],
 ['weekly','Weekly Plan',['Week of {{date}}','Goals','Monday','Tuesday','Wednesday','Thursday','Friday','Review']],
 ['sop','SOP',['{{company}}','Purpose','Safety','Equipment','Procedure','Quality Checks','Revision Notes']],
 ['training','Training Guide',['Objective','Prerequisites','Lesson','Practice','Knowledge Check']],
 ['project','Project Plan',['Objective','Scope','Milestones','Responsibilities','Risks','Next Actions']],
 ['brainstorm','Brainstorm',['Question','Ideas','Constraints','Promising Directions','Next Experiment']],
 ['sales','Sales Script',['Opening','Discovery','Value','Objections','Next Step']],
 ['equipment','Equipment Research',['Requirements','Options','Comparison','Questions','Decision']],
 ['job','Job Notes',['Preparation','Site Observations','Work Performed','Follow-up']],
 ['content','Content Plan',['Audience','Message','Channels','Draft','Review','Publishing Checklist']]
].map(([id,title,sections])=>({id,title,sections,builtin:true}));
export function smartFilters(value={}) {
 if(!value||typeof value!=='object'||Array.isArray(value))fail(400,'invalid_filters');const out={};
 if(value.tag)out.tag=text(value.tag,60).replace(/^#/,'');
 for(const key of ['creator_id','owner_id'])if(value[key])out[key]=uuid(value[key]);
 if(value.scope){if(!['all','private','company','shared','favorites','archive'].includes(value.scope))fail(400,'invalid_scope');out.scope=value.scope;}
 if(value.contains){if(!['checklist','file','crm','unresolved_comments'].includes(value.contains))fail(400,'invalid_contains');out.contains=value.contains;}
 if(value.updated_days!==undefined&&value.updated_days!==''){const days=Number(value.updated_days);if(!Number.isInteger(days)||days<1||days>3650)fail(400,'invalid_days');out.updated_days=days;}
 return out;
}
export function createNotesCollections({pool,notes}) {
 async function folders(input){const actor=await loadActor(pool,input);requireCapability(actor,'notes.view');return {folders:(await pool.query('SELECT id,title,filters FROM notes_smart_folders WHERE user_id=$1 AND company_id=$2 ORDER BY title,id',[actor.userId,actor.companyId])).rows};}
 async function saveFolder(input,body){return mutate(pool,input,async(db,actor)=>{requireCapability(actor,'notes.view');const id=uuid(body.id||randomUUID());const prior=(await db.query('SELECT user_id,company_id FROM notes_smart_folders WHERE id=$1',[id])).rows[0];if(prior&&(prior.user_id!==actor.userId||prior.company_id!==actor.companyId))fail(404,'folder_unavailable');if(body.deleted){await db.query('DELETE FROM notes_smart_folders WHERE id=$1 AND user_id=$2',[id,actor.userId]);return {ok:true};}const filters=smartFilters(body.filters);await db.query('INSERT INTO notes_smart_folders(id,company_id,user_id,title,filters) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET title=$4,filters=$5',[id,actor.companyId,actor.userId,text(body.title,100),JSON.stringify(filters)]);return {id,title:body.title,filters};});}
 async function folderPages(input,id,q){const actor=await loadActor(pool,input);requireCapability(actor,'notes.view');const folder=(await pool.query('SELECT filters FROM notes_smart_folders WHERE id=$1 AND user_id=$2 AND company_id=$3',[uuid(id),actor.userId,actor.companyId])).rows[0];if(!folder)fail(404,'folder_unavailable');return notes.list(actor,{...q,...smartFilters(folder.filters)});}
 async function backlinks(input,id){const {actor}=await authorizePage(pool,input,id);return {pages:(await pool.query(`SELECT DISTINCT n.id,n.title,n.kind FROM comms_notes n JOIN notes_blocks b ON b.page_id=n.id WHERE n.company_id=$2 AND n.deleted_at IS NULL AND b.deleted_at IS NULL AND (${noteRoleSQL(actor)})>0 AND ((b.type='page_link' AND b.payload->>'target_id'=$3) OR (b.type='synced' AND EXISTS(SELECT 1 FROM notes_blocks target WHERE target.id::text=b.payload->>'target_id' AND target.page_id::text=$3 AND target.deleted_at IS NULL))) ORDER BY n.title,n.id LIMIT 100`,[actor.userId,actor.companyId,id])).rows};}
 async function related(input,id){
  const {actor,page}=await authorizePage(pool,input,id);
  return {pages:(await pool.query(`SELECT n.id,n.title,n.kind FROM comms_notes n WHERE n.company_id=$2 AND n.id<>$3 AND n.deleted_at IS NULL AND n.archived_at IS NULL AND n.purged_at IS NULL AND (${noteRoleSQL(actor)})>0 AND (n.parent_id=$3 OR ($4::uuid IS NOT NULL AND n.parent_id=$4) OR n.tags ?| $5::text[]) ORDER BY n.updated_at DESC,n.id LIMIT 30`,[actor.userId,actor.companyId,id,page.parent_id,page.tags||[]])).rows};
 }
 async function templates(input){const actor=await loadActor(pool,input);requireCapability(actor,'notes.view');const saved=(await pool.query(`SELECT t.id,t.title,false AS builtin,t.page_id FROM notes_templates t JOIN comms_notes n ON n.id=t.page_id WHERE t.company_id=$2 AND n.deleted_at IS NULL AND (${noteRoleSQL(actor)})>0 ORDER BY t.title,t.id`,[actor.userId,actor.companyId])).rows;return {templates:[...BUILTIN_TEMPLATES.map(({sections,...item})=>item),...saved]};}
 async function saveTemplate(input,body){return mutate(pool,input,async(db,actor)=>{requireCapability(actor,'notes.templates');const {page}=await authorizePage(db,actor,body.page_id,{level:4});const id=uuid(body.id||randomUUID());const prior=(await db.query('SELECT * FROM notes_templates WHERE id=$1',[id])).rows[0];if(prior&&(prior.creator_id!==actor.userId||prior.company_id!==actor.companyId))fail(404,'template_unavailable');await db.query('INSERT INTO notes_templates(id,company_id,creator_id,page_id,title) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET title=$5,page_id=$4',[id,actor.companyId,actor.userId,page.id,text(body.title||page.title,100)]);return {id};});}
 async function instantiate(input,templateId,body){return mutate(pool,input,async(db,actor)=>{
  requireCapability(actor,'notes.view');requireCapability(actor,'notes.create');const id=uuid(body.id);const prior=(await db.query('SELECT creator_id FROM comms_notes WHERE id=$1',[id])).rows[0];if(prior){if(prior.creator_id!==actor.userId)fail(409,'idempotency_conflict');await authorizePage(db,actor,id);return {id};}
  const builtin=BUILTIN_TEMPLATES.find(t=>t.id===templateId);let sourcePages=[],sourceBlocks=[],schemas=[],rows=[];
  if(!builtin){const template=(await db.query('SELECT * FROM notes_templates WHERE id=$1 AND company_id=$2',[uuid(templateId),actor.companyId])).rows[0];if(!template)fail(404,'template_unavailable');await authorizePage(db,actor,template.page_id);
   sourcePages=(await db.query(`WITH RECURSIVE children AS (SELECT n.*,0 depth FROM comms_notes n WHERE id=$1 AND deleted_at IS NULL UNION ALL SELECT n.*,c.depth+1 FROM comms_notes n JOIN children c ON n.parent_id=c.id WHERE c.depth<15 AND n.deleted_at IS NULL AND n.company_id=$2) SELECT * FROM children ORDER BY depth,position,id LIMIT 51`,[template.page_id,actor.companyId])).rows;if(sourcePages.length>50)fail(413,'template_too_large');
   for(const page of sourcePages){await authorizePage(db,actor,page.id);if(page.kind==='database')requireCapability(actor,'notes.databases');}
   const ids=sourcePages.map(p=>p.id);sourceBlocks=(await db.query('SELECT * FROM notes_blocks WHERE page_id=ANY($1::uuid[]) AND deleted_at IS NULL ORDER BY position,id LIMIT 1001',[ids])).rows;if(sourceBlocks.length>1000)fail(413,'template_too_large');for(const b of sourceBlocks)await validateBlockReferences(db,actor,b);
   schemas=(await db.query('SELECT * FROM notes_database_schemas WHERE page_id=ANY($1::uuid[])',[ids])).rows;rows=(await db.query('SELECT * FROM notes_database_rows WHERE id=ANY($1::uuid[])',[ids])).rows;
   for(const row of rows){const schema=schemas.find(s=>s.page_id===row.database_id);if(!schema||!ids.includes(row.database_id))fail(409,'template_row_requires_database','Save the database as a template to include its row properties.');for(const column of schema.columns){const value=row.values[column.id];if(value==null)continue;if(column.type==='file')await validateBlockReferences(db,actor,{id:randomUUID(),type:'asset',payload:{asset_id:value}});if(column.type==='relation')await authorizePage(db,actor,value);}}

  }
  const info=(await db.query('SELECT u.display_name,c.name AS company FROM users u JOIN companies c ON c.id=u.company_id WHERE u.id=$1',[actor.userId])).rows[0];const variables={date:new Date().toISOString().slice(0,10),creator:info?.display_name||'',company:info?.company||''};const expand=s=>String(s||'').replace(/\{\{(date|creator|company)\}\}/g,(_,k)=>variables[k]);
  if(builtin){sourcePages=[{id:'root',title:builtin.title,kind:'page',tags:[],icon:''}];for(const section of builtin.sections){sourceBlocks.push({id:randomUUID(),page_id:'root',type:'heading2',position:sourceBlocks.length,payload:{text:section}});sourceBlocks.push({id:randomUUID(),page_id:'root',type:section==='Action Items'||section==='Checklist'?'checklist':'paragraph',position:sourceBlocks.length,payload:{text:''}});}if(!sourceBlocks.length)sourceBlocks.push({id:randomUUID(),page_id:'root',type:'paragraph',position:0,payload:{text:''}});}
  const pageIDs=new Map(sourcePages.map((p,i)=>[p.id,i===0?id:randomUUID()])),blockIDs=new Map(sourceBlocks.map(b=>[b.id,randomUUID()]));
  for(const p of sourcePages)await db.query(`INSERT INTO comms_notes(id,company_id,creator_id,owner_id,editor_id,client_key,title,kind,parent_id,inherit_access,visibility,content_format,tags,icon) VALUES($1::uuid,$2,$3,$3,$3,$1::uuid::text,$4,$5,$6,$7,'private','blocks',$8,$9)`,[pageIDs.get(p.id),actor.companyId,actor.userId,text(expand(p.title),150),p.kind,pageIDs.get(p.parent_id)||null,pageIDs.has(p.parent_id),JSON.stringify(p.tags||[]),p.icon||'']);
  for(const b of sourceBlocks){const payload={...b.payload};if(typeof payload.text==='string'){const expanded=expand(payload.text);if(expanded!==payload.text)delete payload.runs;payload.text=expanded;}if(b.type==='page_link'&&pageIDs.has(payload.target_id))payload.target_id=pageIDs.get(payload.target_id);if(b.type==='synced'&&blockIDs.has(payload.target_id))payload.target_id=blockIDs.get(payload.target_id);await db.query('INSERT INTO notes_blocks(id,page_id,type,position,payload,creator_id,editor_id) VALUES($1,$2,$3,$4,$5,$6,$6)',[blockIDs.get(b.id),pageIDs.get(b.page_id),b.type,b.position,JSON.stringify(payload),actor.userId]);}
  for(const b of sourceBlocks)if(blockIDs.has(b.parent_id))await db.query('UPDATE notes_blocks SET parent_id=$2 WHERE id=$1',[blockIDs.get(b.id),blockIDs.get(b.parent_id)]);
  for(const s of schemas)await db.query('INSERT INTO notes_database_schemas(page_id,columns,views) VALUES($1,$2,$3)',[pageIDs.get(s.page_id),JSON.stringify(s.columns),JSON.stringify(s.views)]);
  for(const row of rows){const schema=schemas.find(s=>s.page_id===row.database_id),values={...row.values};for(const column of schema.columns){const value=values[column.id];if(column.type==='relation'&&pageIDs.has(value))values[column.id]=pageIDs.get(value);else if(['title','text'].includes(column.type)&&typeof value==='string')values[column.id]=expand(value);}await db.query('INSERT INTO notes_database_rows(id,database_id,values) VALUES($1,$2,$3)',[pageIDs.get(row.id),pageIDs.get(row.database_id),JSON.stringify(values)]);}
  for(const pageId of pageIDs.values())await db.query(`UPDATE comms_notes SET body=COALESCE((SELECT string_agg(payload->>'text',E'\n' ORDER BY position,id) FROM notes_blocks WHERE page_id=$1),'') WHERE id=$1`,[pageId]);return {id};
 });}
 return {folders,saveFolder,folderPages,backlinks,related,templates,saveTemplate,instantiate};
}
