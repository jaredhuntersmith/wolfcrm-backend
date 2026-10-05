import {referenceSearchSQL,inlineTagPattern} from './search.js';
import {noteAudience,publishNoteChange} from './events.js';
import {recordNoteActivity} from './activity.js';
import {storagePredicate} from '../company-comms/assets.js';
import {createNotesDatabases} from './databases.js';
import {readSnapshot} from './history.js';
import {randomUUID} from 'node:crypto';
import {mutate,loadActor,requireCapability,can,fail,uuid,text,checkRevision,authorizeConversation} from '../company-comms/access.js';
import {authorizePage,noteRoleSQL,validateParent,roles} from './access.js';
import {blockInput,hydrateBlock,validateBlockReferences} from './blocks.js';
const pageFields=['id','company_id','creator_id','owner_id','editor_id','conversation_id','parent_id','title','kind','visibility','inherit_access','icon','cover_id','tags','revision','created_at','updated_at','deleted_at','archived_at','template_id','position','access_role'];
export function pageDTO(page){return Object.fromEntries(pageFields.map(k=>[k,page[k]??null]));}
function tags(value){if(!Array.isArray(value)||value.length>30)fail(400,'invalid_tags');return [...new Set(value.map(v=>text(v,60).replace(/^#/,'')))];}
function limit(value,max=100){return Math.min(max,Math.max(1,Number.parseInt(value,10)||50));}
export function createNotesWorkspace({pool,notifications}){
 const databases=createNotesDatabases({pool,notes:{snapshot,changed}});
 async function snapshot(db,page,actor){const blocks=(await db.query('SELECT * FROM notes_blocks WHERE page_id=$1 AND deleted_at IS NULL ORDER BY position,id',[page.id])).rows;await db.query('INSERT INTO notes_versions(page_id,revision,actor_id,snapshot) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING',[page.id,page.revision,page.editor_id||actor.userId,JSON.stringify({page:pageDTO(page),blocks,...await databases.snapshotState(db,page)})]);}
 async function changed(db,actor,pageId,kind='edited'){
  await recordNoteActivity(db,actor,pageId,kind);
  await db.query('UPDATE comms_notes SET revision=revision+1,updated_at=now(),editor_id=$2 WHERE id=$1',[pageId,actor.userId]);
  const note=(await db.query('SELECT * FROM comms_notes WHERE id=$1',[pageId])).rows[0];
  await publishNoteChange(db,actor,pageId);
  return note;
 }
 async function detail(db,input,pageId,query={}){
  const {actor,page}=await authorizePage(db,input,pageId,{trash:query.trash==='true'});
  const size=limit(query.limit,250),offset=Math.max(0,Number.parseInt(query.offset,10)||0);
  const rows=(await db.query('SELECT * FROM notes_blocks WHERE page_id=$1 AND deleted_at IS NULL ORDER BY position,id LIMIT $2 OFFSET $3',[page.id,size+1,offset])).rows;
  const blocks=[];for(const row of rows.slice(0,size))blocks.push(await hydrateBlock(db,actor,row));
  const personal=(await db.query('SELECT favorite,pinned,opened_at,collapsed FROM notes_personal WHERE page_id=$1 AND user_id=$2',[page.id,actor.userId])).rows[0]||{};
  const count=(await db.query('SELECT count(*)::int AS count FROM notes_blocks WHERE page_id=$1 AND deleted_at IS NULL',[page.id])).rows[0].count;
  const names=(await db.query('SELECT id,display_name FROM users WHERE company_id=$1 AND id=ANY($2::uuid[])',[actor.companyId,[page.owner_id,page.creator_id,page.editor_id].filter(Boolean)])).rows;const name=id=>names.find(u=>u.id===id)?.display_name||null;
  const literal=page.body||'';const statistics={words:(literal.match(/[\p{L}\p{N}]+/gu)||[]).length,characters:[...literal].length};
  const cover=page.cover_id?await hydrateBlock(db,actor,{id:page.id,page_id:page.id,type:'image',position:0,revision:page.revision,payload:{asset_id:page.cover_id}}):null;
  return {page:{...pageDTO(page),owner_name:name(page.owner_id),creator_name:name(page.creator_id),editor_name:name(page.editor_id)},blocks,personal,statistics,cover,block_count:count,next_offset:rows.length>size?offset+size:null};
 }
 async function list(input,q={}){
  const actor=await loadActor(pool,input);requireCapability(actor,'notes.view');const values=[actor.userId,actor.companyId];const add=v=>{values.push(v);return '$'+values.length;};
  const where=['n.company_id=$2','n.purged_at IS NULL',`(${noteRoleSQL(actor)})>0`,q.scope==='trash'?'n.deleted_at IS NOT NULL':'n.deleted_at IS NULL'];
  if(q.scope==='archive')where.push('n.archived_at IS NOT NULL');else if(q.scope!=='trash'&&q.include_archive!=='true')where.push('n.archived_at IS NULL');
  if(q.scope==='private')where.push("n.owner_id=$1 AND n.visibility='private' AND n.conversation_id IS NULL AND NOT n.inherit_access");
  if(q.scope==='company')where.push("n.visibility='company'");
  if(q.scope==='shared')where.push('EXISTS(SELECT 1 FROM notes_members m WHERE m.page_id=n.id AND m.user_id=$1)');
  if(q.scope==='favorites')where.push('COALESCE(p.favorite,false)');if(q.scope==='pinned')where.push('COALESCE(p.pinned,false)');
  if(q.roots==='true')where.push(`(n.parent_id IS NULL OR NOT EXISTS(SELECT 1 FROM comms_notes p WHERE p.id=n.parent_id AND p.deleted_at IS NULL AND p.archived_at IS NULL AND p.purged_at IS NULL AND (${noteRoleSQL(actor,'p')})>0))`);
  if(q.scope==='databases')where.push("n.kind='database'");if(q.parent_id)where.push('n.parent_id='+add(uuid(q.parent_id)));if(q.creator_id)where.push('n.creator_id='+add(uuid(q.creator_id)));if(q.tag){const tag=text(q.tag,60).replace(/^#/,'');where.push('(n.tags ? '+add(tag)+' OR n.body ~* '+add(inlineTagPattern(tag))+')');}
  if(q.owner_id)where.push('n.owner_id='+add(uuid(q.owner_id)));
  if(q.updated_days){const days=Number(q.updated_days);if(!Number.isInteger(days)||days<1||days>3650)fail(400,'invalid_days');where.push('n.updated_at >= now()-('+add(days)+"::int * interval '1 day')");}
  if(q.contains==='unresolved_comments')where.push('EXISTS(SELECT 1 FROM notes_comments c WHERE c.page_id=n.id AND c.deleted_at IS NULL AND NOT c.resolved)');
  const kinds={checklist:['checklist'],file:['asset','image','video','audio','drawing','scan'],crm:['contact','job','quote_card','stage_entry','service_plan','task']}[q.contains];
  if(kinds)where.push('EXISTS(SELECT 1 FROM notes_blocks b WHERE b.page_id=n.id AND b.deleted_at IS NULL AND b.type=ANY('+add(kinds)+'::text[]))');
  if(q.search){const term=add('%'+text(q.search,200).replace(/[\\%_]/g,'\\$&')+'%');const properties=can(actor,'notes.databases')?` OR EXISTS(SELECT 1 FROM notes_database_rows r JOIN comms_notes rn ON rn.id=r.id JOIN notes_database_schemas ds ON ds.page_id=r.database_id CROSS JOIN LATERAL jsonb_each_text(r.values) field WHERE (r.id=n.id OR r.database_id=n.id) AND rn.deleted_at IS NULL AND rn.purged_at IS NULL AND (${noteRoleSQL(actor,'rn')})>0 AND EXISTS(SELECT 1 FROM jsonb_array_elements(ds.columns) col WHERE col->>'id'=field.key AND col->>'type' NOT IN ('file','relation','person')) AND field.value ILIKE ${term})`:'';where.push(`(n.title ILIKE ${term} OR ${referenceSearchSQL(actor,term)} OR n.body ILIKE ${term} OR n.tags::text ILIKE ${term} OR EXISTS(SELECT 1 FROM notes_blocks nb JOIN stored_files f ON f.id::text=nb.payload->>'asset_id' WHERE nb.page_id=n.id AND nb.deleted_at IS NULL AND f.cloud_status='active' AND (${await storagePredicate(pool,actor)}) AND (nb.payload->>'ocr' ILIKE ${term} OR f.display_name ILIKE ${term})) OR EXISTS(SELECT 1 FROM notes_comments nc WHERE nc.page_id=n.id AND nc.deleted_at IS NULL AND nc.body ILIKE ${term})${properties})`);}
  const order={title:'n.title,n.id',created:'n.created_at DESC,n.id',manual:'n.position,n.id',creator:'n.creator_id,n.updated_at DESC,n.id',recent:'p.opened_at DESC NULLS LAST,n.updated_at DESC,n.id'}[q.scope==='recent'?'recent':q.sort]||'n.updated_at DESC,n.id';
  const size=limit(q.limit),offset=Math.max(0,Number.parseInt(q.offset,10)||0);const rows=(await pool.query(`SELECT n.*,${noteRoleSQL(actor)} AS access_role,COALESCE(p.favorite,false) AS favorite,COALESCE(p.pinned,false) AS pinned,p.opened_at FROM comms_notes n LEFT JOIN notes_personal p ON p.page_id=n.id AND p.user_id=$1 WHERE ${where.join(' AND ')} ORDER BY ${order} LIMIT ${add(size+1)} OFFSET ${add(offset)}`,values)).rows;
  return {pages:rows.slice(0,size).map(n=>({...pageDTO(n),favorite:n.favorite,pinned:n.pinned,opened_at:n.opened_at,preview:[...(n.body||'')].slice(0,200).join('')})),next_offset:rows.length>size?offset+size:null};
 }
 async function create(input,body){return mutate(pool,input,async(db,actor)=>{
  requireCapability(actor,'notes.create');requireCapability(actor,'notes.view');const pageId=uuid(body.id||randomUUID());
  const prior=(await db.query('SELECT creator_id FROM comms_notes WHERE id=$1',[pageId])).rows[0];if(prior){if(prior.creator_id!==actor.userId)fail(409,'idempotency_conflict');return detail(db,actor,pageId);}
  await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',['notes-tree:'+actor.companyId]);
  const parent=body.parent_id?uuid(body.parent_id):null;await validateParent(db,actor,pageId,parent);
  const visibility=body.visibility||'private';if(!['private','shared','company'].includes(visibility))fail(400,'invalid_visibility');if(visibility==='company')requireCapability(actor,'notes.company');
  const kind=body.kind||'page';if(!['page','folder','space','database'].includes(kind))fail(400,'invalid_page_kind');if(kind==='database')requireCapability(actor,'notes.databases');
  let conversation=null;if(body.conversation_id){const c=await authorizeConversation(db,actor,body.conversation_id,{write:true});requireCapability(actor,'communications.notes');conversation=c.id;}
  await db.query(`INSERT INTO comms_notes(id,company_id,conversation_id,creator_id,owner_id,editor_id,client_key,title,kind,parent_id,visibility,inherit_access,content_format,tags) VALUES($1::uuid,$2,$3,$4,$4,$4,$1::uuid::text,$5,$6,$7,$8,$9,'blocks',$10)`,[pageId,actor.companyId,conversation,actor.userId,text(body.title||'Untitled',150),kind,parent,visibility,!!parent&&body.inherit_access!==false,JSON.stringify(tags(body.tags||[]))]);
  if(!['folder','space','database'].includes(kind))await db.query(`INSERT INTO notes_blocks(id,page_id,type,payload,creator_id,editor_id) VALUES($1,$2,'paragraph','{"text":""}',$3,$3)`,[body.first_block_id?uuid(body.first_block_id):randomUUID(),pageId,actor.userId]);
  await recordNoteActivity(db,actor,pageId,'created');await publishNoteChange(db,actor,pageId);return detail(db,actor,pageId);
 });}
 async function metadata(input,pageId,body){return mutate(pool,input,async(db,actor)=>{
  await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',['notes-tree:'+actor.companyId]);
  const governance=['parent_id','visibility','inherit_access','archived','trashed','cover_id','tags','icon','position'].some(k=>Object.hasOwn(body,k));
  const {page}=await authorizePage(db,actor,pageId,{level:governance?4:3,trash:true,lock:true});const oldAudience=governance?await noteAudience(db,actor,pageId):[];checkRevision(page,body.expected_revision);await snapshot(db,page,actor);
  const parent=body.parent_id===undefined?page.parent_id:body.parent_id?uuid(body.parent_id):null;await validateParent(db,actor,pageId,parent);
  const visibility=body.visibility??page.visibility;if(!['private','shared','company'].includes(visibility))fail(400,'invalid_visibility');if(visibility==='company')requireCapability(actor,'notes.company');
  const title=body.title===undefined?page.title:text(body.title||'Untitled',150);const newTags=body.tags===undefined?page.tags:tags(body.tags);
  if(page.conversation_id&&(body.visibility!==undefined||body.parent_id!==undefined||body.inherit_access!==undefined))fail(409,'conversation_note_access','Conversation notes retain their conversation access.');
  if(body.cover_id){await validateBlockReferences(db,actor,{id:randomUUID(),page_id:pageId,type:'image',payload:{asset_id:uuid(body.cover_id)}});}
  await db.query(`UPDATE comms_notes SET title=$2,parent_id=$3,visibility=$4,inherit_access=$5,tags=$6,icon=$7,cover_id=$8,position=$9,archived_at=$10,deleted_at=$11 WHERE id=$1`,[pageId,title,parent,visibility,!!parent&&(body.inherit_access??page.inherit_access),JSON.stringify(newTags),body.icon===undefined?page.icon:text(body.icon,32,false),body.cover_id===undefined?page.cover_id:body.cover_id||null,Number.isFinite(body.position)?body.position:page.position,body.archived===undefined?page.archived_at:body.archived?new Date():null,body.trashed===undefined?page.deleted_at:body.trashed?new Date():null]);
  await changed(db,actor,pageId,body.trashed!==undefined?(body.trashed?'trashed':'restored'):body.archived!==undefined?(body.archived?'archived':'unarchived'):body.parent_id!==undefined?'moved':'edited');if(governance)await publishNoteChange(db,actor,pageId,'notes.membership.changed',[...oldAudience,...await noteAudience(db,actor,pageId)]);return detail(db,actor,pageId,{trash:'true'});
 });}
 async function editBlocks(input,pageId,body){return mutate(pool,input,async(db,actor)=>{
  const {page}=await authorizePage(db,actor,pageId,{level:3,lock:true});if(page.archived_at)fail(409,'note_archived');const key=uuid(body.client_key);
  const prior=(await db.query('SELECT result FROM notes_operations WHERE page_id=$1 AND actor_id=$2 AND client_key=$3',[pageId,actor.userId,key])).rows[0];if(prior){const response=await detail(db,actor,pageId);response.changed_blocks=[];for(const block of (await db.query('SELECT * FROM notes_blocks WHERE page_id=$1 AND id=ANY($2::uuid[])',[pageId,prior.result.block_ids||[]])).rows)response.changed_blocks.push(await hydrateBlock(db,actor,block));return response;}
  if(!Array.isArray(body.operations)||!body.operations.length||body.operations.length>100)fail(400,'invalid_operations');await snapshot(db,page,actor);
  const seen=new Set();for(const op of body.operations){const blockId=uuid(op.id);if(seen.has(blockId))fail(400,'duplicate_block_operation');seen.add(blockId);
   const old=(await db.query('SELECT * FROM notes_blocks WHERE id=$1',[blockId])).rows[0];if(old&&old.page_id!==pageId)fail(404,'block_unavailable');
   if((old?.revision||0)!==op.expected_revision)fail(409,'block_conflict','This block changed. Your local draft has been preserved.');
   if(op.delete){if(!old)fail(404,'block_unavailable');const children=(await db.query('SELECT 1 FROM notes_blocks WHERE parent_id=$1 AND deleted_at IS NULL',[blockId])).rowCount;if(children)fail(409,'block_has_children','Move or remove nested blocks first.');await db.query('UPDATE notes_blocks SET deleted_at=now(),revision=revision+1,editor_id=$2,updated_at=now() WHERE id=$1',[blockId,actor.userId]);continue;}
   const block=blockInput(op);await validateBlockReferences(db,actor,block);
   const priorMentions=new Set((old?.payload?.mentions||[]).map(m=>m.user_id));const newMentions=[...new Set((block.payload.mentions||[]).map(m=>m.user_id))].filter(id=>!priorMentions.has(id));
   for(const userId of newMentions)await authorizePage(db,{userId,companyId:actor.companyId},pageId);
   if(block.parent_id){const parents=(await db.query(`WITH RECURSIVE tree AS (SELECT id,parent_id,ARRAY[id] path,0 depth FROM notes_blocks WHERE id=$1 AND page_id=$2 AND deleted_at IS NULL UNION ALL SELECT p.id,p.parent_id,t.path||p.id,t.depth+1 FROM tree t JOIN notes_blocks p ON p.id=t.parent_id AND p.page_id=$2 WHERE t.depth<8 AND NOT p.id=ANY(t.path)) SELECT * FROM tree`,[block.parent_id,pageId])).rows;if(!parents.length||parents.some(p=>p.id===blockId||p.depth>=7))fail(400,'invalid_block_parent');}
   await db.query(`INSERT INTO notes_blocks(id,page_id,type,parent_id,position,payload,creator_id,editor_id) VALUES($1,$2,$3,$4,$5,$6,$7,$7) ON CONFLICT(id) DO UPDATE SET type=$3,parent_id=$4,position=$5,payload=$6,editor_id=$7,revision=notes_blocks.revision+1,updated_at=now(),deleted_at=NULL`,[blockId,pageId,block.type,block.parent_id,block.position,JSON.stringify(block.payload),actor.userId]);
   for(const userId of newMentions)if(userId!==actor.userId)await notifications?.enqueue(db,{userId,companyId:actor.companyId,kind:'notes.mention',title:'You were mentioned in a note',eventKey:pageId+':'+blockId+':'+((old?.revision||0)+1)+':'+userId,requirements:['notes.view'],sourceRefs:[{source_type:'note',source_id:pageId}],data:{note_id:pageId,block_id:blockId}});
  }
  const count=(await db.query('SELECT count(*)::int AS n FROM notes_blocks WHERE page_id=$1 AND deleted_at IS NULL',[pageId])).rows[0].n;if(count>5000)fail(413,'too_many_blocks');
  await db.query(`UPDATE comms_notes SET body=COALESCE((SELECT string_agg(left(payload->>'text',50000),E'\n' ORDER BY position,id) FROM notes_blocks WHERE page_id=$1 AND deleted_at IS NULL),''),content_format='blocks' WHERE id=$1`,[pageId]);
  const saved=await changed(db,actor,pageId,'blocks_edited');await db.query('INSERT INTO notes_operations(page_id,actor_id,client_key,result) VALUES($1,$2,$3,$4)',[pageId,actor.userId,key,JSON.stringify({revision:saved.revision,block_ids:[...seen]})]);const response=await detail(db,actor,pageId);response.changed_blocks=[];for(const block of (await db.query('SELECT * FROM notes_blocks WHERE page_id=$1 AND id=ANY($2::uuid[])',[pageId,[...seen]])).rows)response.changed_blocks.push(await hydrateBlock(db,actor,block));return response;
 });}
 async function personal(input,pageId,body){return mutate(pool,input,async(db,actor)=>{await authorizePage(db,actor,pageId);const old=(await db.query('SELECT * FROM notes_personal WHERE page_id=$1 AND user_id=$2',[pageId,actor.userId])).rows[0]||{};const collapsed=body.collapsed??old.collapsed??[];if(!Array.isArray(collapsed)||collapsed.length>5000)fail(400,'invalid_collapsed');await db.query(`INSERT INTO notes_personal(page_id,user_id,favorite,pinned,opened_at,collapsed) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(page_id,user_id) DO UPDATE SET favorite=$3,pinned=$4,opened_at=$5,collapsed=$6`,[pageId,actor.userId,body.favorite??old.favorite??false,body.pinned??old.pinned??false,body.opened===true?new Date():old.opened_at||null,JSON.stringify(collapsed.map(uuid))]);return {ok:true};});}
 async function share(input,pageId,body){return mutate(pool,input,async(db,actor)=>{
  requireCapability(actor,'notes.share');const {page}=await authorizePage(db,actor,pageId,{level:4,lock:true});checkRevision(page,body.expected_revision);if(page.conversation_id)fail(409,'conversation_note_access');
  if(!Array.isArray(body.members)||body.members.length>100)fail(400,'invalid_members');const members=body.members.map(m=>({user_id:uuid(m.user_id),role:roles[m.role]}));if(members.some(m=>!m.role))fail(400,'invalid_role');
  for(const member of members){const recipient=await loadActor(db,{userId:member.user_id,companyId:actor.companyId});requireCapability(recipient,'notes.view');}
  const oldAudience=await noteAudience(db,actor,pageId);await snapshot(db,page,actor);await db.query('DELETE FROM notes_members WHERE page_id=$1',[pageId]);
  for(const member of members)await db.query('INSERT INTO notes_members(page_id,user_id,role) VALUES($1,$2,$3) ON CONFLICT(page_id,user_id) DO UPDATE SET role=$3',[pageId,member.user_id,member.role]);
  await db.query("UPDATE comms_notes SET visibility='shared',inherit_access=false WHERE id=$1",[pageId]);const saved=await changed(db,actor,pageId,'sharing_updated');await publishNoteChange(db,actor,pageId,'notes.membership.changed',[...oldAudience,...await noteAudience(db,actor,pageId)]);
  for(const member of members)if(member.user_id!==actor.userId)await notifications?.enqueue(db,{userId:member.user_id,companyId:actor.companyId,kind:'notes.shared',title:'A note was shared with you',eventKey:pageId+':'+saved.revision+':'+member.user_id,requirements:['notes.view'],sourceRefs:[{source_type:'note',source_id:pageId}],data:{note_id:pageId}});return detail(db,actor,pageId);
 });}
 async function members(input,pageId){const {actor}=await authorizePage(pool,input,pageId,{level:4});return {members:(await pool.query('SELECT m.user_id,m.role,u.display_name FROM notes_members m JOIN users u ON u.id=m.user_id AND u.company_id=$2 AND u.deleted_at IS NULL WHERE m.page_id=$1',[pageId,actor.companyId])).rows};}
 async function versions(input,pageId){await authorizePage(pool,input,pageId);return {versions:(await pool.query(`SELECT DISTINCT ON (revision) revision,actor_id,created_at FROM (SELECT revision,actor_id,created_at,1 priority FROM notes_versions WHERE page_id=$1 UNION ALL SELECT revision,editor_id AS actor_id,created_at,0 priority FROM comms_note_versions WHERE note_id=$1) v ORDER BY revision DESC,priority DESC LIMIT 100`,[pageId])).rows};}
 async function version(input,pageId,revision){const {actor,page}=await authorizePage(pool,input,pageId);const snapshot=await readSnapshot(pool,page,revision);const blocks=[];for(const block of snapshot.blocks)blocks.push(await hydrateBlock(pool,actor,block));return {page:{id:pageId,title:snapshot.page.title,revision},blocks,...await databases.hydrateHistory(pool,actor,snapshot)};}
 async function restore(input,pageId,body){return mutate(pool,input,async(db,actor)=>{
  const parentDatabase=(await db.query('SELECT database_id FROM notes_database_rows WHERE id=$1',[uuid(pageId)])).rows[0];if(parentDatabase)await authorizePage(db,actor,parentDatabase.database_id,{level:3,lock:true});
  const {page}=await authorizePage(db,actor,pageId,{level:3,lock:true});checkRevision(page,body.expected_revision);const row={snapshot:await readSnapshot(db,page,body.revision)};await snapshot(db,page,actor);
  for(const block of row.snapshot.blocks)await validateBlockReferences(db,actor,block);
  await databases.restoreState(db,actor,page,row.snapshot);
  await db.query('UPDATE notes_blocks SET deleted_at=now(),revision=revision+1 WHERE page_id=$1',[pageId]);
  // Keep original block IDs, never resurrect access settings or another owner from history.
  for(const block of row.snapshot.blocks)await db.query(`INSERT INTO notes_blocks(id,page_id,type,payload,position,creator_id,editor_id) VALUES($1,$6,$2,$3,$4,$5,$5) ON CONFLICT(id) DO UPDATE SET type=$2,payload=$3,position=$4,parent_id=NULL,deleted_at=NULL,editor_id=$5,updated_at=now() WHERE notes_blocks.page_id=$6`,[block.id,block.type,JSON.stringify(block.payload),block.position,actor.userId,pageId]);
  for(const block of row.snapshot.blocks)if(block.parent_id)await db.query('UPDATE notes_blocks SET parent_id=$2 WHERE id=$1 AND page_id=$3',[block.id,block.parent_id,pageId]);
  await db.query("UPDATE comms_notes SET title=$2,body=$3,content_format='blocks' WHERE id=$1",[pageId,row.snapshot.page.title,row.snapshot.blocks.map(b=>b.payload.text||'').join('\n')]);await changed(db,actor,pageId,'version_restored');return detail(db,actor,pageId);
 });}
 async function purge(input,pageId,body){return mutate(pool,input,async(db,actor)=>{
  await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',['notes-tree:'+actor.companyId]);const {page}=await authorizePage(db,actor,pageId,{level:4,trash:true,lock:true});checkRevision(page,body.expected_revision);
  if(page.owner_id!==actor.userId||page.conversation_id)fail(403,'owner_required');if(!page.deleted_at||body.confirmed!==true)fail(409,'trash_confirmation_required');
  if((await db.query('SELECT 1 FROM comms_notes WHERE parent_id=$1 AND purged_at IS NULL LIMIT 1',[pageId])).rowCount)fail(409,'page_has_children','Move or permanently delete child pages first.');
  await db.query('DELETE FROM notes_comments WHERE page_id=$1',[pageId]);await db.query('UPDATE notes_blocks SET parent_id=NULL WHERE page_id=$1',[pageId]);await db.query('DELETE FROM notes_blocks WHERE page_id=$1',[pageId]);
  for(const table of ['notes_versions','notes_activity','notes_personal','notes_operations','notes_presence','notes_members','notes_database_schemas'])await db.query('DELETE FROM '+table+' WHERE page_id=$1',[pageId]);
  await db.query('DELETE FROM comms_note_versions WHERE note_id=$1',[pageId]);await db.query('DELETE FROM notes_database_rows WHERE id=$1',[pageId]);await db.query('DELETE FROM notes_templates WHERE page_id=$1',[pageId]);
  await db.query("UPDATE notes_ai_results SET body='',source_blocks='[]' WHERE $1=ANY(page_ids)",[pageId]);
  // Keep an empty identity tombstone for historical links; never delete originals
  // from Media/Storage or cascade into unrelated CRM records.
  await db.query("UPDATE comms_notes SET title='Deleted Note',body='',asset_ids='[]',source_refs='[]',tags='[]',icon='',cover_id=NULL,purged_at=now(),revision=revision+1 WHERE id=$1",[pageId]);return {ok:true};
 });}
 async function getBlock(input,pageId,blockId){const {actor}=await authorizePage(pool,input,pageId);const block=(await pool.query('SELECT * FROM notes_blocks WHERE id=$1 AND page_id=$2 AND deleted_at IS NULL',[uuid(blockId),pageId])).rows[0];if(!block)fail(404,'block_unavailable');return hydrateBlock(pool,actor,block);}
 return {purge,getBlock,list,create,get:(a,id,q)=>detail(pool,a,id,q),metadata,editBlocks,personal,share,members,versions,version,restore,snapshot,changed};
}
