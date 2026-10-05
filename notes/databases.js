import {randomUUID,createHash} from 'node:crypto';
import {mutate,requireCapability,can,loadActor,uuid,text,fail} from '../company-comms/access.js';
import {authorizePage,noteRoleSQL} from './access.js';
import {hydrateBlock,validateBlockReferences} from './blocks.js';
export const PROPERTY_TYPES=['title','text','number','checkbox','date','person','select','multi_select','url','email','phone','file','relation'];
const canonical=value=>JSON.stringify(value,(_,v)=>v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v);
const defaults=[{id:'title',name:'Name',type:'title',options:[]}];
export function databaseColumns(input){
 if(!Array.isArray(input)||!input.length||input.length>50)fail(400,'invalid_properties');const ids=new Set();let titles=0;
 const columns=input.map(c=>{if(typeof c.id!=='string'||!/^[a-zA-Z0-9_-]{1,60}$/.test(c.id)||ids.has(c.id)||!PROPERTY_TYPES.includes(c.type))fail(400,'invalid_property');ids.add(c.id);if(c.type==='title')titles++;
  const options=c.options||[];if(!Array.isArray(options)||options.length>100)fail(400,'invalid_options');return {id:c.id,name:text(c.name,80),type:c.type,options:[...new Set(options.map(v=>text(v,80)))],...(c.type==='relation'?{target_type:'note'}:{})};
 });if(titles!==1)fail(400,'one_title_required');return columns;
}
export function createNotesDatabases({pool,notes}){
 async function authorize(db,actor,pageId,level=1){const result=await authorizePage(db,actor,pageId,{level,lock:level>=3});requireCapability(result.actor,'notes.databases');if(result.page.kind!=='database')fail(400,'not_database');if(level>=3&&result.page.archived_at)fail(409,'note_archived');return result;}
 async function schema(db,pageId){return (await db.query('SELECT columns,views,revision FROM notes_database_schemas WHERE page_id=$1',[pageId])).rows[0]||{columns:defaults,views:[{id:'all',name:'All Items',type:'table'}],revision:0};}
 async function get(input,pageId){await authorize(pool,input,pageId);return schema(pool,pageId);}
 async function priorOperation(db,actor,pageId,body,kind){
  if(!body.client_key)return null;
  const key=uuid(body.client_key),fingerprint=createHash('sha256').update(canonical({kind,body})).digest('hex');
  const prior=(await db.query('SELECT result FROM notes_operations WHERE page_id=$1 AND actor_id=$2 AND client_key=$3',[pageId,actor.userId,key])).rows[0];
  if(prior&&prior.result.fingerprint!==fingerprint)fail(409,'operation_key_reused');
  return {key,fingerprint,prior:!!prior};
 }
 async function recordOperation(db,actor,pageId,operation){if(operation&&!operation.prior)await db.query('INSERT INTO notes_operations(page_id,actor_id,client_key,result) VALUES($1,$2,$3,$4)',[pageId,actor.userId,operation.key,JSON.stringify({fingerprint:operation.fingerprint})]);}
 async function row(db,actor,pageId,rowId,columns){
  await authorizePage(db,actor,uuid(rowId));const result=(await db.query('SELECT * FROM notes_database_rows WHERE id=$1 AND database_id=$2',[rowId,pageId])).rows[0];if(!result)fail(404,'row_unavailable');return hydrate(db,actor,result,columns);
 }
 async function getRow(input,pageId,rowId){const {actor}=await authorize(pool,input,pageId);return row(pool,actor,pageId,rowId,(await schema(pool,pageId)).columns);}
 async function configure(input,pageId,body){return mutate(pool,input,async(db,actor)=>{
  const {page}=await authorize(db,actor,pageId,3);const old=await schema(db,pageId),operation=await priorOperation(db,actor,pageId,body,'schema');if(operation?.prior)return old;if(body.expected_revision!==old.revision)fail(409,'database_schema_conflict');const columns=databaseColumns(body.columns??old.columns);if(columns.some(c=>old.columns.some(p=>p.id===c.id&&p.type!==c.type)))fail(409,'property_type_immutable','Create a new property to change its type and preserve existing values.');
  const views=body.views??old.views;if(!Array.isArray(views)||views.length>20||views.some(v=>!['table','list','board','calendar'].includes(v.type)))fail(400,'invalid_views');
  const primitive=columns.filter(c=>!['file','person','relation'].includes(c.type));const safeViews=views.map(v=>({id:text(v.id,60),name:text(v.name,80),type:v.type,group_by:columns.some(c=>c.id===v.group_by&&c.type==='select')?v.group_by:null,date_by:columns.some(c=>c.id===v.date_by&&c.type==='date')?v.date_by:null,sort_by:primitive.some(c=>c.id===v.sort_by)?v.sort_by:null,direction:v.direction==='desc'?'desc':'asc',filter_property:primitive.some(c=>c.id===v.filter_property)?v.filter_property:null,filter_value:typeof v.filter_value==='string'?v.filter_value.slice(0,200):'',visible_fields:Array.isArray(v.visible_fields)?[...new Set(v.visible_fields.filter(id=>columns.some(c=>c.id===id)))]:columns.map(c=>c.id)}));if(new Set(safeViews.map(v=>v.id)).size!==safeViews.length)fail(400,'duplicate_view');
  await notes.snapshot(db,page,actor);await db.query(`INSERT INTO notes_database_schemas(page_id,columns,views,revision) VALUES($1,$2,$3,1) ON CONFLICT(page_id) DO UPDATE SET columns=$2,views=$3,revision=notes_database_schemas.revision+1`,[pageId,JSON.stringify(columns),JSON.stringify(safeViews)]);await notes.changed(db,actor,pageId,'database_properties_updated');await recordOperation(db,actor,pageId,operation);return schema(db,pageId);
 });}
 async function values(db,actor,columns,input){
  if(!input||typeof input!=='object'||Array.isArray(input))fail(400,'invalid_values');const out={};
  for(const c of columns){let value=input[c.id];if(value==null){out[c.id]=null;continue;}
   switch(c.type){
    case 'title':case 'text':case 'phone':out[c.id]=text(value,c.type==='text'?10000:200,false);break;
    case 'number':if(typeof value!=='number'||!Number.isFinite(value)||Math.abs(value)>1e15)fail(400,'invalid_number');out[c.id]=value;break;
    case 'checkbox':if(typeof value!=='boolean')fail(400,'invalid_checkbox');out[c.id]=value;break;
    case 'date':if(typeof value!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(value)||Number.isNaN(Date.parse(value))||new Date(value).toISOString().slice(0,10)!==value)fail(400,'invalid_date');out[c.id]=value;break;
    case 'url':{let url;try{url=new URL(value);}catch{fail(400,'invalid_url');}if(!['http:','https:'].includes(url.protocol)||url.username||url.password)fail(400,'invalid_url');out[c.id]=url.href;break;}
    case 'email':if(typeof value!=='string'||value.length>320||!/^\S+@\S+\.\S+$/.test(value))fail(400,'invalid_email');out[c.id]=value;break;
    case 'select':if(!c.options.includes(value))fail(400,'invalid_option');out[c.id]=value;break;
    case 'multi_select':if(!Array.isArray(value)||value.length>100||value.some(v=>!c.options.includes(v)))fail(400,'invalid_option');out[c.id]=[...new Set(value)];break;
    case 'person':{const target=await loadActor(db,{userId:uuid(value),companyId:actor.companyId});out[c.id]=target.userId;break;}
    case 'file':await validateBlockReferences(db,actor,{id:randomUUID(),type:'asset',payload:{asset_id:uuid(value)}});out[c.id]=value;break;
    case 'relation':await authorizePage(db,actor,uuid(value));out[c.id]=value;break;
   }
  }return out;
 }
 async function hydrate(db,actor,row,columns){
  const safe={};for(const c of columns){const value=row.values[c.id];if(value==null){safe[c.id]=null;continue;}
   if(c.type==='file'){const block=await hydrateBlock(db,actor,{id:row.id,page_id:row.database_id,type:'asset',payload:{asset_id:value}});safe[c.id]=block.accessible?{id:value,title:block.attachment.display_name}: {accessible:false,text:'No Access'};}
   else if(c.type==='relation'){try{const {page}=await authorizePage(db,actor,value);safe[c.id]={id:page.id,title:page.title};}catch(e){if(![403,404].includes(e.status))throw e;safe[c.id]={accessible:false,text:'No Access'};}}
   else if(c.type==='person'){const user=(await db.query('SELECT id,display_name FROM users WHERE id=$1 AND company_id=$2 AND deleted_at IS NULL',[value,actor.companyId])).rows[0];safe[c.id]=user?{id:user.id,title:user.display_name}:null;}
   else safe[c.id]=value;
  }return {id:row.id,values:safe,revision:row.revision,created_at:row.created_at};
 }
 async function rows(input,pageId,q={}){
  const {actor}=await authorize(pool,input,pageId),definition=await schema(pool,pageId);const columns=definition.columns;const params=[actor.userId,actor.companyId,pageId];const add=v=>{params.push(v);return '$'+params.length;};const conditions=['r.database_id=$3','n.company_id=$2','n.deleted_at IS NULL',`(${noteRoleSQL(actor)})>0`];
  const primitive=columns.filter(c=>!['file','person','relation'].includes(c.type));
  if(q.filter_property){const column=primitive.find(c=>c.id===q.filter_property);if(!column)fail(400,'invalid_filter');conditions.push(`r.values->>${add(column.id)}=${add(String(q.filter_value||''))}`);}
  if(q.date_property){if(!columns.some(c=>c.id===q.date_property&&c.type==='date')||!/^\d{4}-\d{2}-\d{2}$/.test(q.date_value||''))fail(400,'invalid_date_filter');conditions.push(`r.values->>${add(q.date_property)}=${add(q.date_value)}`);}
  if(q.search){conditions.push(`EXISTS(SELECT 1 FROM jsonb_each_text(r.values) field WHERE field.key=ANY(${add(primitive.map(c=>c.id))}::text[]) AND field.value ILIKE ${add('%'+text(q.search,100).replace(/[\\%_]/g,'\\$&')+'%')})`);}
  const column=primitive.find(c=>c.id===q.sort),direction=q.direction==='asc'?'ASC':'DESC';const expression=column?`r.values->>${add(column.id)}`:'r.created_at';const order=column?.type==='number'?`(${expression})::numeric`:expression;
  const limit=100,offset=Math.max(0,Number.parseInt(q.offset,10)||0);const data=(await pool.query(`SELECT r.* FROM notes_database_rows r JOIN comms_notes n ON n.id=r.id WHERE ${conditions.join(' AND ')} ORDER BY ${order} ${direction} NULLS LAST,r.id LIMIT 101 OFFSET ${add(offset)}`,params)).rows;
  const output=[];for(const row of data.slice(0,limit))output.push(await hydrate(pool,actor,row,columns));return {rows:output,next_offset:data.length>limit?offset+limit:null};
 }
 async function save(input,pageId,rowId,body){return mutate(pool,input,async(db,actor)=>{
  await authorize(db,actor,pageId,3);const definition=await schema(db,pageId),id=uuid(rowId||body.id||randomUUID());const operation=await priorOperation(db,actor,pageId,body,'row:'+id);if(operation?.prior)return row(db,actor,pageId,id,definition.columns);if(body.schema_revision!==definition.revision)fail(409,'database_schema_conflict');
  const old=(await db.query('SELECT * FROM notes_database_rows WHERE id=$1 FOR UPDATE',[id])).rows[0];if(old&&old.database_id!==pageId)fail(404,'row_unavailable');
  if(rowId){await authorizePage(db,actor,id,{level:3});if(!old)fail(404,'row_unavailable');if(old.revision!==body.expected_revision)fail(409,'database_row_conflict');}
  else if(old){await authorizePage(db,actor,id);return hydrate(db,actor,old,definition.columns);}
  const validated={...old?.values,...await values(db,actor,old?definition.columns.filter(c=>Object.hasOwn(body.values||{},c.id)):definition.columns,body.values||{})},title=validated[definition.columns.find(c=>c.type==='title').id]||'Untitled';
  if(!old)await db.query(`INSERT INTO comms_notes(id,company_id,creator_id,owner_id,editor_id,client_key,title,parent_id,inherit_access,content_format) VALUES($1::uuid,$2,$3,$3,$3,$1::uuid::text,$4,$5,true,'blocks')`,[id,actor.companyId,actor.userId,title,pageId]);
  else {const {page}=await authorizePage(db,actor,id,{level:3});await notes.snapshot(db,page,actor);await db.query('UPDATE comms_notes SET title=$2 WHERE id=$1',[id,title]);await notes.changed(db,actor,id,'database_row_updated');}
  const saved=(await db.query(`INSERT INTO notes_database_rows(id,database_id,values) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET values=$3,revision=notes_database_rows.revision+1 RETURNING *`,[id,pageId,JSON.stringify(validated)])).rows[0];await notes.changed(db,actor,pageId,'database_row_updated');await recordOperation(db,actor,pageId,operation);return hydrate(db,actor,saved,definition.columns);
 });}
 async function snapshotState(db,page){
  if(page.kind==='database')return {database_schema:await schema(db,page.id)};
  const record=(await db.query('SELECT * FROM notes_database_rows WHERE id=$1',[page.id])).rows[0];
  return record?{row_properties:{...record,columns:(await schema(db,record.database_id)).columns}}:{};
 }
 async function hydrateHistory(db,actor,snapshot){
  if(!can(actor,'notes.databases'))return {};
  if(snapshot.database_schema)return {database_schema:snapshot.database_schema};
  if(snapshot.row_properties){const record=snapshot.row_properties;try{await authorize(db,actor,record.database_id);}catch(e){if([403,404].includes(e.status))return {properties_unavailable:true};throw e;}return {row_properties:await hydrate(db,actor,record,record.columns),property_columns:record.columns};}
  return {};
 }
 async function restoreState(db,actor,page,snapshot){
  if(snapshot.database_schema){
   await authorize(db,actor,page.id,3);const old=snapshot.database_schema,columns=databaseColumns(old.columns);
   // Retired field values remain on their rows, so restoring a schema never
   // deletes business content. Bump the live revision to invalidate stale edits.
   await db.query(`INSERT INTO notes_database_schemas(page_id,columns,views,revision) VALUES($1,$2,$3,1) ON CONFLICT(page_id) DO UPDATE SET columns=$2,views=$3,revision=notes_database_schemas.revision+1`,[page.id,JSON.stringify(columns),JSON.stringify(old.views)]);
  }
  if(snapshot.row_properties){
   const record=snapshot.row_properties;await authorize(db,actor,record.database_id,3);const current=await schema(db,record.database_id);
   const compatible=record.columns.filter(c=>current.columns.some(now=>now.id===c.id&&now.type===c.type));
   if(compatible.length!==record.columns.length)fail(409,'history_schema_changed','Restore the database properties before restoring this row version.');
   const validated=await values(db,actor,current.columns.filter(c=>compatible.some(old=>old.id===c.id)),record.values);
   const updated=await db.query('UPDATE notes_database_rows SET values=values||$3::jsonb,revision=revision+1 WHERE id=$1 AND database_id=$2',[page.id,record.database_id,JSON.stringify(validated)]);
   if(!updated.rowCount)fail(409,'row_unavailable');await notes.changed(db,actor,record.database_id);
  }
 }
 return {get,getRow,configure,rows,save,snapshotState,hydrateHistory,restoreState};
}
