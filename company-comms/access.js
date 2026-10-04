import { resolveAccess } from '../permissions.js';
import { randomUUID } from 'node:crypto';
export class CommsError extends Error { constructor(status,code,message=code){super(message);this.status=status;this.code=code;} }
export function fail(status,code,message){throw new CommsError(status,code,message);}
export function text(value,max=200,required=true){if(typeof value!=='string'||value.length>max||(required&&!value.trim()))fail(400,'invalid_text');return value.trim();}
export function id(value){if(typeof value!=='string'||!value.length||value.length>160)fail(400,'invalid_id');return value;}
export function uuid(value){if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value||''))fail(400,'invalid_id');return value;}
export function ids(value,max=100){if(!Array.isArray(value)||value.length>max)fail(400,'invalid_members');return [...new Set(value.map(uuid))];}
export function can(actor,key){return actor.permissions?.capabilities?.[key]===true;}
export function requireCapability(actor,key){if(!can(actor,key))fail(403,'permission_denied','This action is not allowed.');}
export async function loadActor(db, actor) {
 const row=(await db.query(`SELECT u.*,c.owner_user_id,row_to_json(p) AS permission_record FROM users u JOIN companies c ON c.id=u.company_id LEFT JOIN employee_permissions p ON p.user_id=u.id AND p.company_id=u.company_id WHERE u.id=$1 AND u.company_id=$2 AND u.deleted_at IS NULL`,[actor.userId,actor.companyId])).rows[0];
 if(!row)fail(403,'account_unavailable');
 const owner=row.owner_user_id===row.id, p=row.permission_record||{};
 const access=resolveAccess({role:owner?'employer':'employee',isCompanyOwner:owner,userId:row.id,ownerUserId:row.owner_user_id,preset:p.permission_preset,overrides:p.permission_overrides,legacy:p});
 return {...actor,userId:row.id,companyId:row.company_id,role:owner?'employer':'employee',isCompanyOwner:owner,displayName:row.display_name||'Team member',permissions:{...p,capabilities:access.capabilities,preset:access.preset}};
}
// Parameters $1=current user, $2=current company. Apply before snippets, counts and joins.
export const conversationJoins=`LEFT JOIN comms_threads t ON t.conversation_id=c.id LEFT JOIN comms_groups g ON g.id=t.group_id LEFT JOIN comms_sections s ON s.id=t.section_id LEFT JOIN conversation_participants cp ON cp.conversation_id=c.id AND cp.user_id=$1`;
const conversationPredicate=`c.company_id=$2 AND c.deleted_at IS NULL AND (
 (t.id IS NULL AND cp.user_id=$1 AND cp.left_at IS NULL)
 OR (t.id IS NOT NULL AND t.deleted_at IS NULL AND g.deleted_at IS NULL AND g.suspended_at IS NULL
   AND EXISTS(SELECT 1 FROM comms_group_members gm WHERE gm.group_id=g.id AND gm.user_id=$1 AND gm.status='active')
   AND (g.owner_user_id=$1 OR CASE WHEN t.permission_mode='override' THEN NOT t.restricted OR EXISTS(SELECT 1 FROM comms_thread_members tm WHERE tm.thread_id=t.id AND tm.user_id=$1)
     ELSE s.id IS NULL OR NOT s.restricted OR EXISTS(SELECT 1 FROM comms_section_members sm WHERE sm.section_id=s.id AND sm.user_id=$1) END))
)`;
// Generated chats inherit all source access, without granting admission to a
// target merely because its source is readable. Eight links bound corrupt or
// unexpectedly deep graphs; cycles, dangling links and foreign tenants deny.
export function conversationAccessSQL(actor) {
 const sourceAliases=value=>value.replace(/\b(c|t|g|s|cp)\./g,(_,alias)=>'source_'+alias+'.');
 const sourceJoins=conversationJoins.replace(/\b(c|t|g|s|cp)\b/g,alias=>'source_'+alias);
 const jobsAllowed=can(actor,'jobs.view')&&can(actor,'schedule.view');
 return `(${conversationPredicate}) AND NOT EXISTS (
  WITH RECURSIVE ancestry AS (
   SELECT c.id,c.source_kind,c.source_id,ARRAY[c.id]::text[] AS visited,0 AS depth,false AS cycle
   UNION ALL
   SELECT parent.id,parent.source_kind,parent.source_id,ancestry.visited||parent.id,ancestry.depth+1,parent.id=ANY(ancestry.visited)
   FROM ancestry JOIN conversations parent ON parent.id=ancestry.source_id
   WHERE ancestry.source_kind='conversation' AND ancestry.depth<8 AND NOT ancestry.cycle
  )
  SELECT 1 FROM ancestry JOIN conversations source_c ON source_c.id=ancestry.id ${sourceJoins}
  WHERE (${sourceAliases(conversationPredicate)}) IS NOT TRUE OR ancestry.cycle
   OR (source_c.scope='meeting' AND ancestry.source_kind IS NULL)
   OR (ancestry.source_kind IS NULL AND ancestry.source_id IS NOT NULL)
   OR (ancestry.source_kind IS NOT NULL AND ancestry.source_kind NOT IN('conversation','job','independent'))
   OR (ancestry.source_kind='independent' AND ancestry.source_id IS NOT NULL)
   OR (ancestry.source_kind='conversation' AND (ancestry.depth>=8 OR ancestry.source_id IS NULL OR NOT EXISTS(SELECT 1 FROM conversations parent WHERE parent.id=ancestry.source_id AND parent.company_id=$2 AND parent.deleted_at IS NULL)))
   OR (ancestry.source_kind='job' AND (NOT ${jobsAllowed?'true':'false'} OR ancestry.source_id IS NULL OR NOT EXISTS(SELECT 1 FROM schedule_events source_job WHERE source_job.id=ancestry.source_id AND source_job.company_id=$2 AND to_jsonb(source_job)->>'deleted_at' IS NULL)))
 )`;
}
export async function authorizeConversation(db,actor,conversationId,{write=false,capability='communications.view'}={}){
 actor=await loadActor(db,actor);requireCapability(actor,capability);requireCapability(actor,'communications.view');
 const row=(await db.query(`SELECT c.*,t.id AS thread_id,t.kind AS thread_kind,t.group_id,t.legacy_channel_id,t.archived_at AS thread_archived,s.archived_at AS section_archived,g.archived_at AS group_archived,g.owner_user_id,cp.last_read_at,cp.history_from FROM conversations c ${conversationJoins} WHERE c.id=$3 AND ${conversationAccessSQL(actor)}`,[actor.userId,actor.companyId,id(conversationId)])).rows[0];
 if(!row)fail(404,'conversation_unavailable');
 if(write){requireCapability(actor,'communications.send');if(row.archived_at||row.thread_archived||row.section_archived||row.group_archived)fail(409,'conversation_archived');if(row.thread_kind==='announcement'&&row.owner_user_id!==actor.userId)fail(403,'restricted_posting');}
 return {...row,actor};
}
export async function authorizeGroup(db,actor,groupId,{owner=false,allowInvited=false}={}){
 actor=await loadActor(db,actor);requireCapability(actor,'communications.view');
 const group=(await db.query(`SELECT g.*,m.status AS membership_status FROM comms_groups g JOIN comms_group_members m ON m.group_id=g.id AND m.user_id=$1 WHERE g.id=$3 AND g.company_id=$2 AND g.deleted_at IS NULL AND g.suspended_at IS NULL AND (m.status='active' OR ($4 AND m.status='invited'))`,[actor.userId,actor.companyId,uuid(groupId),allowInvited])).rows[0];
 if(!group)fail(404,'group_unavailable');if(owner&&group.owner_user_id!==actor.userId)fail(403,'creator_required');return {...group,actor};
}
export async function eligibleMembers(db,actor,userIds){
 const unique=ids(userIds);
 const rows=(await db.query(`SELECT u.id FROM users u WHERE u.id=ANY($1::uuid[]) AND u.company_id=$2 AND u.deleted_at IS NULL`,[unique,actor.companyId])).rows;
 if(rows.length!==unique.length)fail(400,'invalid_members');
 for(const row of rows){const member=await loadActor(db,{userId:row.id,companyId:actor.companyId});requireCapability(member,'communications.view');}
 return unique;
}
export async function transact(pool,fn){const db=await pool.connect();try{await db.query('BEGIN');const result=await fn(db);await db.query('COMMIT');return result;}catch(e){await db.query('ROLLBACK');throw e;}finally{db.release();}}
export async function audit(db,actor,action,subjectType,subjectId,details={}){await db.query(`INSERT INTO comms_audit(id,company_id,actor_id,action,subject_type,subject_id,details) VALUES($1,$2,$3,$4,$5,$6,$7)`,[randomUUID(),actor.companyId,actor.userId,action,subjectType,subjectId,JSON.stringify(details)]);}
export async function publish(db,actor,conversationId,type,entityId,payload={}){const result=await db.query(`INSERT INTO comms_events(company_id,conversation_id,event_type,entity_id,payload) VALUES($1,$2,$3,$4,$5) RETURNING id`,[actor.companyId,conversationId,type,entityId,JSON.stringify(payload)]);return result.rows[0].id;}
export function checkRevision(row,expected){if(!Number.isInteger(expected)||row.revision!==expected)fail(409,'stale_revision','This item changed. Refresh before saving.');}
export function pageLimit(value){return Math.max(1,Math.min(100,Number(value)||50));}
export function cursor(value){if(!value)return null;try{const v=JSON.parse(Buffer.from(value,'base64url').toString());if(!v.at||!v.id||!Number.isFinite(Date.parse(v.at)))throw Error();return v;}catch{fail(400,'invalid_cursor');}}
export function encodeCursor(row){return Buffer.from(JSON.stringify({at:row.cursor_created_at||row.created_at,id:row.id})).toString('base64url');}
export async function mutate(pool,actor,fn){return transact(pool,async db=>{await db.query(`SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,['comms-permissions:'+actor.userId]);const current=await loadActor(db,actor);return fn(db,current);});}
