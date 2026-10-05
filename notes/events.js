import {authorizePage} from './access.js';
// Follow the same bounded inheritance chain as authorization. A child owner does
// not gain access to a private inherited parent merely by creating the child.
export async function noteAudience(db,actor,pageId) {
 const root=(await db.query(`WITH RECURSIVE lineage AS (
  SELECT n.*,ARRAY[n.id] path,0 depth FROM comms_notes n WHERE n.id=$1 AND n.company_id=$2 AND n.purged_at IS NULL
  UNION ALL SELECT p.*,l.path||p.id,l.depth+1 FROM lineage l JOIN comms_notes p ON p.id=l.parent_id AND p.company_id=$2 AND p.purged_at IS NULL
  WHERE l.inherit_access AND l.depth<16 AND NOT p.id=ANY(l.path)
 ) SELECT * FROM lineage WHERE NOT inherit_access OR parent_id IS NULL LIMIT 1`,[pageId,actor.companyId])).rows[0];
 if(!root)return [];
 const candidates=(await db.query(`SELECT u.id FROM users u WHERE u.company_id=$1 AND u.deleted_at IS NULL AND (
 $2='company' OR u.id=$3 OR ($2='shared' AND EXISTS(SELECT 1 FROM notes_members m WHERE m.page_id=$4 AND m.user_id=u.id))
 OR ($5::text IS NOT NULL AND (EXISTS(SELECT 1 FROM conversation_participants cp WHERE cp.conversation_id=$5 AND cp.user_id=u.id AND cp.left_at IS NULL)
 OR EXISTS(SELECT 1 FROM comms_threads t JOIN comms_group_members gm ON gm.group_id=t.group_id WHERE t.conversation_id=$5 AND gm.user_id=u.id AND gm.status='active'))))`,[actor.companyId,root.visibility,root.owner_id,root.id,root.conversation_id])).rows;
 const recipients=[];
 for(const user of candidates){try{await authorizePage(db,{userId:user.id,companyId:actor.companyId},pageId,{trash:true});recipients.push(user.id);}catch(error){if(![403,404].includes(error.status))throw error;}}
 return recipients;
}
export async function publishNoteChange(db,actor,pageId,type='notes.changed',recipients=null) {
 const audience=recipients??await noteAudience(db,actor,pageId);
 if(!audience.length)return;
 // Invalidation events contain no title, text, actor, or newly private page ID.
 const entity=type==='notes.membership.changed'?'':pageId;
 await db.query(`INSERT INTO comms_events(company_id,recipient_id,event_type,entity_id,payload) SELECT $1,id,$2,$3,'{}'::jsonb FROM unnest($4::uuid[]) id`,[actor.companyId,type,entity,[...new Set(audience)]]);
}
