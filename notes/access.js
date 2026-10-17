import {can,requireCapability,loadActor,fail,uuid,conversationJoins,conversationAccessSQL,authorizeConversation} from '../company-comms/access.js';
export const roles=Object.freeze({viewer:1,commenter:2,editor:3,full:4});
// $1 actor, $2 company. This expression executes before search, count or pagination.
export function noteRoleSQL(actor,alias='n') {
 if(!can(actor,'notes.view'))return '0';
 const conversation=can(actor,'communications.view')?`EXISTS(SELECT 1 FROM conversations c ${conversationJoins} WHERE c.id=a.conversation_id AND ${conversationAccessSQL(actor)})`:'false';
 return `(WITH RECURSIVE lineage AS (
 SELECT ${alias}.id,${alias}.parent_id,${alias}.inherit_access,${alias}.owner_id,${alias}.visibility,${alias}.conversation_id,${alias}.company_id,${alias}.deleted_at,ARRAY[${alias}.id] AS path,0 AS depth
 UNION ALL SELECT p.id,p.parent_id,p.inherit_access,p.owner_id,p.visibility,p.conversation_id,p.company_id,p.deleted_at,l.path||p.id,l.depth+1 FROM lineage l JOIN comms_notes p ON p.id=l.parent_id WHERE l.inherit_access AND NOT p.id=ANY(l.path)
 ) SELECT COALESCE(max(CASE WHEN a.company_id<>$2 THEN 0
 WHEN a.conversation_id IS NOT NULL THEN CASE WHEN ${conversation} THEN ${can(actor,'communications.notes')&&can(actor,'communications.send')?3:1} ELSE 0 END
 WHEN a.owner_id=$1 THEN 4
 WHEN a.visibility='company' THEN 1
 WHEN a.visibility='shared' THEN COALESCE((SELECT m.role FROM notes_members m WHERE m.page_id=a.id AND m.user_id=$1),0)
 ELSE 0 END),0)::int FROM lineage a WHERE (NOT a.inherit_access OR a.parent_id IS NULL) AND (a.id=${alias}.id OR a.deleted_at IS NULL) AND a.company_id=$2 AND NOT EXISTS(SELECT 1 FROM lineage broken WHERE broken.company_id<>$2 OR (broken.id<>${alias}.id AND broken.deleted_at IS NOT NULL)))`;
}
// Resolve the effective audience through inherited folders, not the child's stale local flag.
export function noteSharedSQL(alias='n') {
 return `(WITH RECURSIVE audience AS (
 SELECT ${alias}.id,${alias}.parent_id,${alias}.inherit_access,${alias}.visibility,${alias}.conversation_id,ARRAY[${alias}.id] path,0 depth
 UNION ALL SELECT p.id,p.parent_id,p.inherit_access,p.visibility,p.conversation_id,a.path||p.id,a.depth+1
 FROM audience a JOIN comms_notes p ON p.id=a.parent_id AND p.company_id=${alias}.company_id AND p.deleted_at IS NULL
 WHERE a.inherit_access AND NOT p.id=ANY(a.path)
 ) SELECT COALESCE(bool_or(visibility IN ('shared','company') OR conversation_id IS NOT NULL),false) FROM audience WHERE NOT inherit_access OR parent_id IS NULL)`;
}
export async function authorizePage(db,input,pageId,{level=1,trash=false,lock=false}={}) {
 const actor=await loadActor(db,input);requireCapability(actor,'notes.view');
 if(lock)await db.query('SELECT id FROM comms_notes WHERE id=$1 AND company_id=$2 FOR UPDATE',[uuid(pageId),actor.companyId]);
 const page=(await db.query(`SELECT n.*,${noteSharedSQL()} AS is_shared,${noteRoleSQL(actor)} AS access_role FROM comms_notes n WHERE n.id=$3 AND n.company_id=$2 AND n.purged_at IS NULL ${trash?'':'AND n.deleted_at IS NULL'}`,[actor.userId,actor.companyId,uuid(pageId)])).rows[0];
 if(!page||page.access_role===0)fail(404,'note_unavailable','No Access');
 if(page.access_role<level)fail(403,'note_role_denied','This note is read-only for this action.');
 if(level>=3&&page.conversation_id)await authorizeConversation(db,actor,page.conversation_id,{write:true});
 return {actor,page};
}
export async function validateParent(db,actor,pageId,parentId) {
 if(!parentId)return;
 await authorizePage(db,actor,parentId,{level:3});
 const result=await db.query(`WITH RECURSIVE tree AS (
  SELECT id,parent_id,ARRAY[id] AS path,false AS cycle FROM comms_notes WHERE id=$1 AND company_id=$2
  UNION ALL SELECT p.id,p.parent_id,t.path||p.id,p.id=ANY(t.path) FROM tree t
  JOIN comms_notes p ON p.id=t.parent_id AND p.company_id=$2 WHERE NOT t.cycle
 ) SELECT bool_or(id=$3 OR cycle) AS cycle FROM tree`,[uuid(parentId),actor.companyId,uuid(pageId)]);
 if(result.rows[0].cycle)fail(400,'invalid_page_parent','Notes cannot be moved inside themselves or their descendants.');
}
