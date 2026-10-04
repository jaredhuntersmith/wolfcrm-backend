import {randomUUID} from 'node:crypto';
import {authorizeGroup,authorizeConversation,conversationJoins,conversationAccessSQL,loadActor,requireCapability,eligibleMembers,mutate,audit,publish,checkRevision,fail,text,uuid,ids} from './access.js';
export function createGroupService({pool}) {
 async function validatePhoto(db,actor,asset){if(!asset)return null;requireCapability(actor,'storage.share');const file=(await db.query(`SELECT id FROM stored_files WHERE id=$1 AND owner_user_id=$2 AND cloud_status='active' AND category='image'`,[uuid(asset),actor.userId])).rows[0];if(!file)fail(404,'photo_unavailable');return file.id;}
 async function list(actor,{directory=false}={}){
  actor=await loadActor(pool,actor);requireCapability(actor,'communications.view');
  return (await pool.query(`SELECT g.*,m.status AS membership_status,COALESCE(p.favorite,false) AS favorite,COALESCE(p.muted,false) AS muted,COALESCE(p.sort_order,0) AS personal_order FROM comms_groups g LEFT JOIN comms_group_members m ON m.group_id=g.id AND m.user_id=$1 LEFT JOIN comms_preferences p ON p.user_id=$1 AND p.subject_type='group' AND p.subject_id=g.id::text WHERE g.company_id=$2 AND g.deleted_at IS NULL AND g.suspended_at IS NULL AND (m.status IN ('active','invited') OR ($3 AND g.visibility='company' AND g.archived_at IS NULL)) ORDER BY COALESCE(p.favorite,false) DESC,COALESCE(p.sort_order,0),g.name,g.id LIMIT 100`,[actor.userId,actor.companyId,directory])).rows;
 }
 async function create(actor,body){return mutate(pool,actor,async(db,actor)=>{
  requireCapability(actor,'communications.create');const groupId=body.id?uuid(body.id):randomUUID();
  const existing=(await db.query('SELECT id,owner_user_id FROM comms_groups WHERE id=$1 AND company_id=$2',[groupId,actor.companyId])).rows[0];if(existing){if(existing.owner_user_id!==actor.userId)fail(404,'group_unavailable');return detail(actor,groupId,db);}
  const name=text(body.name,100),description=text(body.description||'',2000,false),members=await eligibleMembers(db,actor,body.member_ids||[]),photo=await validatePhoto(db,actor,body.photo_asset_id);
  if(!['invite','company'].includes(body.visibility||'invite'))fail(400,'invalid_visibility');
  await db.query(`INSERT INTO comms_groups(id,company_id,name,description,photo_asset_id,original_creator_id,owner_user_id,visibility) VALUES($1,$2,$3,$4,$5,$6,$6,$7)`,[groupId,actor.companyId,name,description,photo,actor.userId,body.visibility||'invite']);
  for(const member of [...new Set([actor.userId,...members])])await db.query(`INSERT INTO comms_group_members(group_id,company_id,user_id,status,invited_by,joined_at) VALUES($1,$2,$3,$4,$5,CASE WHEN $3::uuid=$5::uuid THEN now() END)`,[groupId,actor.companyId,member,member===actor.userId?'active':'invited',actor.userId]);
  const conversation=randomUUID();await db.query(`INSERT INTO conversations(id,company_id,title,is_group,created_by,scope) VALUES($1,$2,'General Chat',true,$3,'general')`,[conversation,actor.companyId,actor.userId]);
  await db.query(`INSERT INTO comms_threads(id,company_id,group_id,name,conversation_id,kind) VALUES($1,$2,$3,'General Chat',$4,'general')`,[randomUUID(),actor.companyId,groupId,conversation]);
  if(photo)await db.query(`INSERT INTO comms_asset_grants(asset_id,conversation_id,company_id,granted_by,source_type,source_id) VALUES($1,$2,$3,$4,'group_photo',$5)`,[photo,conversation,actor.companyId,actor.userId,groupId]);
  await audit(db,actor,'group_created','group',groupId,{visibility:body.visibility||'invite'});await publish(db,actor,null,'group.changed',groupId);return detail(actor,groupId,db);
 });}
 async function detail(actor,groupId,db=pool){
  const group=await authorizeGroup(db,actor,groupId);actor=group.actor;delete group.actor;
  const sections=(await db.query(`SELECT s.*,COALESCE(p.collapsed,false) AS collapsed,COALESCE(p.favorite,false) AS favorite,COALESCE(p.muted,false) AS muted,COALESCE(p.sort_order,0) AS personal_order FROM comms_sections s LEFT JOIN comms_preferences p ON p.user_id=$1 AND p.subject_type='section' AND p.subject_id=s.id::text WHERE s.group_id=$2 AND s.deleted_at IS NULL AND (NOT s.restricted OR $3 OR EXISTS(SELECT 1 FROM comms_section_members sm WHERE sm.section_id=s.id AND sm.user_id=$1)) ORDER BY s.sort_order,s.id`,[actor.userId,groupId,group.owner_user_id===actor.userId])).rows;
  const threads=(await db.query(`SELECT t.*,COALESCE(tp.favorite,false) AS favorite,COALESCE(tp.muted,false) AS muted,COALESCE(tp.sort_order,0) AS personal_order,COALESCE(cp.last_read_at,'-infinity') AS last_read_at,(SELECT count(*)::int FROM messages m WHERE (m.conversation_id=c.id OR m.channel_id=t.legacy_channel_id) AND m.sender_id<>$1 AND m.deleted_at IS NULL AND m.created_at>=COALESCE(cp.history_from,'-infinity') AND m.created_at>COALESCE(cp.last_read_at,'-infinity')) AS unread_count,(SELECT count(*)::int FROM comms_mentions mm JOIN messages m ON m.id=mm.message_id WHERE mm.user_id=$1 AND (m.conversation_id=c.id OR m.channel_id=t.legacy_channel_id) AND m.deleted_at IS NULL AND m.created_at>=COALESCE(cp.history_from,'-infinity') AND m.created_at>COALESCE(cp.last_read_at,'-infinity')) AS mention_count FROM conversations c ${conversationJoins} LEFT JOIN comms_preferences tp ON tp.user_id=$1 AND tp.subject_type='thread' AND tp.subject_id=t.id::text WHERE t.group_id=$3 AND ${conversationAccessSQL(actor)} ORDER BY CASE WHEN t.kind='general' THEN 0 ELSE 1 END,t.sort_order,t.id`,[actor.userId,actor.companyId,groupId])).rows;
  if(group.owner_user_id===actor.userId){
   const sectionMembers=await db.query('SELECT sm.section_id,sm.user_id FROM comms_section_members sm JOIN comms_sections s ON s.id=sm.section_id WHERE s.group_id=$1',[groupId]);
   const threadMembers=await db.query('SELECT tm.thread_id,tm.user_id FROM comms_thread_members tm JOIN comms_threads t ON t.id=tm.thread_id WHERE t.group_id=$1',[groupId]);
   for(const section of sections)section.member_ids=sectionMembers.rows.filter(row=>row.section_id===section.id).map(row=>row.user_id);
   for(const thread of threads)thread.member_ids=threadMembers.rows.filter(row=>row.thread_id===thread.id).map(row=>row.user_id);
  }
  const visibleSections=new Set(sections.map(s=>s.id));for(const t of threads){if(t.section_id&&!visibleSections.has(t.section_id))t.section_id=null;if(t.last_read_at===-Infinity)t.last_read_at=null;}
  const members=(await db.query(`SELECT u.id,u.display_name,u.photo_url,m.status,m.joined_at FROM comms_group_members m JOIN users u ON u.id=m.user_id AND u.company_id=m.company_id AND u.deleted_at IS NULL WHERE m.group_id=$1 AND m.status IN ('active','invited') ORDER BY u.display_name,u.id`,[groupId])).rows;
  return {group,sections,threads,members,history_policy:'Joining gives access to authorized Channel history. Private Threads still require separate access.'};
 }
 async function update(actor,groupId,body){return mutate(pool,actor,async(db,actor)=>{
  await db.query('SELECT id FROM comms_groups WHERE id=$1 FOR UPDATE',[uuid(groupId)]);const g=await authorizeGroup(db,actor,groupId,{owner:true});checkRevision(g,body.expected_revision);
  const photo=body.photo_asset_id===undefined?g.photo_asset_id:await validatePhoto(db,actor,body.photo_asset_id);
  const visibility=body.visibility??g.visibility;if(!['invite','company'].includes(visibility))fail(400,'invalid_visibility');
  await db.query(`UPDATE comms_groups SET name=$2,description=$3,photo_asset_id=$4,visibility=$5,revision=revision+1 WHERE id=$1`,[groupId,body.name===undefined?g.name:text(body.name,100),body.description===undefined?g.description:text(body.description,2000,false),photo,visibility]);
  if(photo!==g.photo_asset_id){
   await db.query("UPDATE comms_asset_grants SET revoked_at=now() WHERE source_type='group_photo' AND source_id=$1 AND company_id=$2 AND revoked_at IS NULL",[groupId,actor.companyId]);
   if(photo){const general=(await db.query("SELECT conversation_id FROM comms_threads WHERE group_id=$1 AND kind='general'",[groupId])).rows[0];
    await db.query(`INSERT INTO comms_asset_grants(asset_id,conversation_id,company_id,granted_by,source_type,source_id) VALUES($1,$2,$3,$4,'group_photo',$5) ON CONFLICT(asset_id,conversation_id,source_type,source_id) DO UPDATE SET revoked_at=NULL,granted_by=EXCLUDED.granted_by`,[photo,general.conversation_id,actor.companyId,actor.userId,groupId]);
   }
  }
  await audit(db,actor,'group_updated' ,'group',groupId);await publish(db,actor,null,'group.changed',groupId);return detail(actor,groupId,db);
 });}
 async function membership(actor,groupId,body){return mutate(pool,actor,async(db,actor)=>{
  const action=body.action;
  await db.query('SELECT id FROM comms_groups WHERE id=$1 FOR UPDATE',[uuid(groupId)]);
  if(['accept','join'].includes(action)){
   if(body.accept_history!==true)fail(400,'history_consent_required');
   const g=(await db.query(`SELECT g.*,m.status FROM comms_groups g LEFT JOIN comms_group_members m ON m.group_id=g.id AND m.user_id=$2 WHERE g.id=$1 AND g.company_id=$3 AND g.deleted_at IS NULL AND g.archived_at IS NULL AND g.suspended_at IS NULL`,[groupId,actor.userId,actor.companyId])).rows[0];
   requireCapability(actor,'communications.view');if(!g||!(g.status==='invited'||g.visibility==='company'&&g.status!=='removed'))fail(404,'invitation_unavailable');
   await db.query(`INSERT INTO comms_group_members(group_id,company_id,user_id,status,joined_at) VALUES($1,$2,$3,'active',now()) ON CONFLICT(group_id,user_id) DO UPDATE SET status='active',joined_at=now(),updated_at=now()`,[groupId,actor.companyId,actor.userId]);
  }else{
   const g=await authorizeGroup(db,actor,groupId,{owner:action!=='leave'});if(action==='leave'&&g.owner_user_id===actor.userId)fail(409,'transfer_or_archive_required');
   if(action==='leave')await db.query(`UPDATE comms_group_members SET status='left',updated_at=now() WHERE group_id=$1 AND user_id=$2`,[groupId,actor.userId]);
   else if(action==='invite'){checkRevision(g,body.expected_revision);for(const member of await eligibleMembers(db,actor,body.user_ids||[])){if(member===actor.userId)continue;await db.query(`INSERT INTO comms_group_members(group_id,company_id,user_id,status,invited_by) VALUES($1,$2,$3,'invited',$4) ON CONFLICT(group_id,user_id) DO UPDATE SET status=CASE WHEN comms_group_members.status='active' THEN 'active' ELSE 'invited' END,invited_by=$4,updated_at=now()`,[groupId,actor.companyId,member,actor.userId]);}}
   else if(action==='remove'){checkRevision(g,body.expected_revision);const targets=ids(body.user_ids);if(targets.includes(g.owner_user_id))fail(409,'owner_transfer_required');await db.query(`UPDATE comms_group_members SET status='removed',updated_at=now() WHERE group_id=$1 AND user_id=ANY($2::uuid[])`,[groupId,targets]);}
   else if(action==='transfer'){checkRevision(g,body.expected_revision);const target=uuid(body.user_id);if(!(await db.query(`SELECT 1 FROM comms_group_members m JOIN users u ON u.id=m.user_id WHERE m.group_id=$1 AND m.user_id=$2 AND m.status='active' AND u.company_id=$3 AND u.deleted_at IS NULL`,[groupId,target,actor.companyId])).rowCount)fail(400,'invalid_owner');await db.query('UPDATE comms_groups SET owner_user_id=$2 WHERE id=$1',[groupId,target]);}
   else fail(400,'invalid_membership_action');
  }
  await db.query('UPDATE comms_groups SET revision=revision+1 WHERE id=$1',[groupId]);await audit(db,actor,'group_membership_'+action,'group',groupId,{user_ids:body.user_ids||[]});await publish(db,actor,null,'membership.changed',groupId);return {ok:true};
 });}
 async function structure(actor,groupId,type,entityId,body){return mutate(pool,actor,async(db,actor)=>{
  await db.query('SELECT id FROM comms_groups WHERE id=$1 FOR UPDATE',[uuid(groupId)]);const g=await authorizeGroup(db,actor,groupId,{owner:true});if(g.archived_at)fail(409,'group_archived');checkRevision(g,body.expected_group_revision);
  const table=type==='section'?'comms_sections':type==='thread'?'comms_threads':null;if(!table)fail(400,'invalid_structure');
  const old=entityId?(await db.query(`SELECT * FROM ${table} WHERE id=$1 AND group_id=$2 AND deleted_at IS NULL`,[uuid(entityId),groupId])).rows[0]:null;if(entityId&&!old)fail(404,'structure_unavailable');
  const entity=old?.id||randomUUID();if(old?.kind==='general')fail(409,'general_chat_is_required');
  const members=body.member_ids===undefined?null:await eligibleMembers(db,actor,body.member_ids);if(members?.length){const valid=(await db.query(`SELECT user_id FROM comms_group_members WHERE group_id=$1 AND user_id=ANY($2::uuid[]) AND status='active'`,[groupId,members])).rows;if(valid.length!==members.length)fail(400,'members_must_join_first');}
  const order=body.sort_order??old?.sort_order??0;if(!Number.isInteger(order)||Math.abs(order)>1000000)fail(400,'invalid_order');
  if(type==='section'){
   await db.query(`INSERT INTO comms_sections(id,company_id,group_id,name,sort_order,restricted) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO UPDATE SET name=$4,sort_order=$5,restricted=$6,revision=comms_sections.revision+1`,[entity,actor.companyId,groupId,text(body.name??old?.name,100),order,body.restricted??old?.restricted??false]);
  }else{
   const section=body.section_id===undefined?old?.section_id:body.section_id;if(section&&!(await db.query('SELECT 1 FROM comms_sections WHERE id=$1 AND group_id=$2 AND archived_at IS NULL AND deleted_at IS NULL',[uuid(section),groupId])).rowCount)fail(400,'invalid_section');
   if(old&&section!==old.section_id&&!['preserve','adopt'].includes(body.move_permissions))fail(400,'choose_move_permissions');
   let mode=body.permission_mode??old?.permission_mode??'inherit',restricted=body.restricted??old?.restricted??false;
   let copiedMembers=members;
   if(old&&section!==old.section_id&&body.move_permissions==='preserve'&&old.permission_mode==='inherit'){
    const source=old.section_id?(await db.query('SELECT restricted FROM comms_sections WHERE id=$1',[old.section_id])).rows[0]:null;mode='override';restricted=source?.restricted??false;copiedMembers=source?.restricted?(await db.query('SELECT user_id FROM comms_section_members WHERE section_id=$1',[old.section_id])).rows.map(r=>r.user_id):[];
   }else if(body.move_permissions==='adopt'){mode='inherit';restricted=false;}
   if(!['inherit','override'].includes(mode))fail(400,'invalid_permission_mode');const kind=body.kind??old?.kind??'text';if(!['text','voice','announcement','forum'].includes(kind))fail(400,'invalid_thread_kind');
   const conversation=old?.conversation_id||randomUUID();if(!old)await db.query(`INSERT INTO conversations(id,company_id,title,is_group,created_by,scope) VALUES($1,$2,$3,true,$4,'thread')`,[conversation,actor.companyId,text(body.name,100),actor.userId]);
   await db.query(`INSERT INTO comms_threads(id,company_id,group_id,section_id,name,conversation_id,kind,sort_order,permission_mode,restricted) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(id) DO UPDATE SET section_id=$4,name=$5,kind=$7,sort_order=$8,permission_mode=$9,restricted=$10,revision=comms_threads.revision+1`,[entity,actor.companyId,groupId,section||null,text(body.name??old?.name,100),conversation,kind,order,mode,restricted]);
   if(copiedMembers!==null){await db.query('DELETE FROM comms_thread_members WHERE thread_id=$1',[entity]);for(const user of copiedMembers||[])await db.query('INSERT INTO comms_thread_members(thread_id,user_id) VALUES($1,$2)',[entity,user]);}
  }
  if(type==='section'&&members!==null){await db.query('DELETE FROM comms_section_members WHERE section_id=$1',[entity]);for(const user of members)await db.query('INSERT INTO comms_section_members(section_id,user_id) VALUES($1,$2)',[entity,user]);}
  await db.query('UPDATE comms_groups SET revision=revision+1 WHERE id=$1',[groupId]);await audit(db,actor,'structure_saved',type,entity);await publish(db,actor,null,'group.changed',groupId);return detail(actor,groupId,db);
 });}
 async function structureLifecycle(actor,groupId,type,entityId,body){return mutate(pool,actor,async(db,actor)=>{
  await db.query('SELECT id FROM comms_groups WHERE id=$1 FOR UPDATE',[uuid(groupId)]);
  const group=await authorizeGroup(db,actor,groupId,{owner:true});checkRevision(group,body.expected_group_revision);
  if(group.archived_at)fail(409,'group_archived');
  const table=type==='section'?'comms_sections':type==='thread'?'comms_threads':null;if(!table)fail(400,'invalid_structure');
  const row=(await db.query(`SELECT * FROM ${table} WHERE id=$1 AND group_id=$2 AND deleted_at IS NULL`,[uuid(entityId),groupId])).rows[0];if(!row)fail(404,'structure_unavailable');
  if(row.kind==='general')fail(409,'general_chat_is_required');
  const threads=type==='section'?(await db.query('SELECT * FROM comms_threads WHERE section_id=$1 AND deleted_at IS NULL',[entityId])).rows:[row];
  const count=(await db.query(`SELECT count(*)::int AS count FROM messages WHERE conversation_id=ANY($1::text[]) AND deleted_at IS NULL`,[threads.map(t=>t.conversation_id)])).rows[0].count;
  const impact={name:row.name,thread_count:threads.length,message_count:count,action:body.action,history_retained_for_archive:true};
  if(body.preview===true)return {impact};
  if(!['archive','restore','delete'].includes(body.action))fail(400,'invalid_action');
  if(body.action==='delete'&&body.confirm_name!==row.name)fail(400,'deletion_confirmation_required');
  if(type==='section'&&body.action==='delete'){
   if(!Object.hasOwn(body,'move_to_section_id')||!['preserve','adopt'].includes(body.move_permissions))fail(400,'thread_destination_required','Choose where the section Threads go and whether their permissions are preserved or inherited.');
   const destination=body.move_to_section_id;
   if(destination){if(destination===entityId)fail(400,'invalid_section');if(!(await db.query('SELECT 1 FROM comms_sections WHERE id=$1 AND group_id=$2 AND archived_at IS NULL AND deleted_at IS NULL',[uuid(destination),groupId])).rowCount)fail(400,'invalid_section');}
   for(const thread of threads){
    if(body.move_permissions==='preserve'&&thread.permission_mode==='inherit'){
     await db.query("UPDATE comms_threads SET permission_mode='override',restricted=$2 WHERE id=$1",[thread.id,row.restricted]);
     await db.query('DELETE FROM comms_thread_members WHERE thread_id=$1',[thread.id]);
     if(row.restricted)await db.query('INSERT INTO comms_thread_members(thread_id,user_id) SELECT $1,user_id FROM comms_section_members WHERE section_id=$2',[thread.id,entityId]);
    }else if(body.move_permissions==='adopt'){
     await db.query("UPDATE comms_threads SET permission_mode='inherit',restricted=false WHERE id=$1",[thread.id]);
     await db.query('DELETE FROM comms_thread_members WHERE thread_id=$1',[thread.id]);
    }
    await db.query('UPDATE comms_threads SET section_id=$2,revision=revision+1 WHERE id=$1',[thread.id,destination||null]);
   }
  }
  await db.query(`UPDATE ${table} SET archived_at=CASE WHEN $2='restore' THEN NULL ELSE now() END,deleted_at=CASE WHEN $2='delete' THEN now() ELSE deleted_at END,revision=revision+1 WHERE id=$1`,[entityId,body.action]);
  if(type==='thread')await db.query(`UPDATE conversations SET archived_at=CASE WHEN $2='restore' THEN NULL ELSE now() END,revision=revision+1 WHERE id=$1`,[row.conversation_id,body.action]);
  await db.query('UPDATE comms_groups SET revision=revision+1 WHERE id=$1',[groupId]);
  await audit(db,actor,type+'_'+body.action,type,entityId,impact);await publish(db,actor,null,'group.changed',groupId);return {ok:true,impact};
 });}
 async function lifecycle(actor,groupId,body){return mutate(pool,actor,async(db,actor)=>{
  await db.query('SELECT id FROM comms_groups WHERE id=$1 FOR UPDATE',[uuid(groupId)]);const g=await authorizeGroup(db,actor,groupId,{owner:true});checkRevision(g,body.expected_revision);
  if(!['archive','restore','delete'].includes(body.action))fail(400,'invalid_action');if(body.action==='delete'&&body.confirm_name!==g.name)fail(400,'deletion_confirmation_required');
  await db.query(`UPDATE comms_groups SET archived_at=CASE WHEN $2='restore' THEN NULL ELSE now() END,deleted_at=CASE WHEN $2='delete' THEN now() ELSE deleted_at END,revision=revision+1 WHERE id=$1`,[groupId,body.action]);await audit(db,actor,'group_'+body.action,'group',groupId);await publish(db,actor,null,'group.changed',groupId);return {ok:true};
 });}
 async function governanceList(input){
  const actor=await loadActor(pool,input);if(!actor.isCompanyOwner)fail(403,'owner_required');
  return (await pool.query(`SELECT g.id,g.name,g.revision,g.owner_user_id,u.display_name AS owner_name,g.archived_at,g.suspended_at,(g.ownership_repair_required OR u.deleted_at IS NOT NULL OR u.company_id IS DISTINCT FROM g.company_id) AS ownership_repair_required,(u.deleted_at IS NULL AND u.company_id=g.company_id) AS creator_active FROM comms_groups g LEFT JOIN users u ON u.id=g.owner_user_id WHERE g.company_id=$1 AND g.deleted_at IS NULL ORDER BY g.name,g.id LIMIT 500`,[actor.companyId])).rows;
 }
 async function governance(actor,groupId,body){return mutate(pool,actor,async(db,actor)=>{
  if(!actor.isCompanyOwner)fail(403,'owner_required');const g=(await db.query('SELECT * FROM comms_groups WHERE id=$1 AND company_id=$2 FOR UPDATE',[uuid(groupId),actor.companyId])).rows[0];if(!g)fail(404,'group_unavailable');checkRevision(g,body.expected_revision);text(body.reason,500);
  if(body.action==='suspend'||body.action==='restore')await db.query('UPDATE comms_groups SET suspended_at=CASE WHEN $2 THEN now() ELSE NULL END,revision=revision+1 WHERE id=$1',[groupId,body.action==='suspend']);
  else if(body.action==='reassign'){
   if((await db.query('SELECT 1 FROM users WHERE id=$1 AND company_id=$2 AND deleted_at IS NULL',[g.owner_user_id,actor.companyId])).rowCount)fail(409,'creator_is_active');const member=(await eligibleMembers(db,actor,[body.user_id]))[0];
   await db.query('UPDATE comms_groups SET owner_user_id=$2,ownership_repair_required=false,revision=revision+1 WHERE id=$1',[groupId,member]);await db.query(`INSERT INTO comms_group_members(group_id,company_id,user_id,status,joined_at) VALUES($1,$2,$3,'active',now()) ON CONFLICT(group_id,user_id) DO UPDATE SET status='active'`,[groupId,actor.companyId,member]);
  }else fail(400,'invalid_governance');await audit(db,actor,'governance_'+body.action,'group',groupId,{reason:body.reason});await publish(db,actor,null,'membership.changed',groupId);return {ok:true};
 });}
 async function preferences(actor,body){return mutate(pool,actor,async(db,actor)=>{
  const type=body.subject_type,subject=body.subject_id;
  if(type==='group')await authorizeGroup(db,actor,subject);else if(type==='conversation')await authorizeConversation(db,actor,subject);else if(['section','thread'].includes(type)){
   const row=(await db.query(`SELECT group_id FROM ${type==='section'?'comms_sections':'comms_threads'} WHERE id=$1 AND company_id=$2`,[uuid(subject),actor.companyId])).rows[0];if(!row)fail(404,'subject_unavailable');const tree=await detail(actor,row.group_id,db);if(!(type==='section'?tree.sections:tree.threads).some(x=>x.id===subject))fail(404,'subject_unavailable');
  }else fail(400,'invalid_subject');
  const order=body.sort_order??null;if(order!==null&&(!Number.isInteger(order)||Math.abs(order)>1000000))fail(400,'invalid_order');
  for(const key of ['favorite','muted','collapsed'])if(body[key]!==undefined&&typeof body[key]!=='boolean')fail(400,'invalid_preference');
  return (await db.query(`INSERT INTO comms_preferences(user_id,company_id,subject_type,subject_id,favorite,muted,collapsed,sort_order) VALUES($1,$2,$3,$4,COALESCE($5,false),COALESCE($6,false),COALESCE($7,false),COALESCE($8,0)) ON CONFLICT(user_id,subject_type,subject_id) DO UPDATE SET favorite=COALESCE($5,comms_preferences.favorite),muted=COALESCE($6,comms_preferences.muted),collapsed=COALESCE($7,comms_preferences.collapsed),sort_order=COALESCE($8,comms_preferences.sort_order),revision=comms_preferences.revision+1 RETURNING *`,[actor.userId,actor.companyId,type,subject,body.favorite??null,body.muted??null,body.collapsed??null,order])).rows[0];
 });}
 return {list,create,detail,update,membership,structure,structureLifecycle,lifecycle,governance,governanceList,preferences};
}
