import {publishNoteChange} from './events.js';
import {recordNoteActivity} from './activity.js';
import {randomUUID} from 'node:crypto';
import {mutate,loadActor,can,fail,uuid,text} from '../company-comms/access.js';
import {authorizePage} from './access.js';
export function createNotesCollaboration({pool,notifications}){
 async function people(input,search=''){
  const actor=await loadActor(pool,input);if(!can(actor,'notes.share'))fail(403,'permission_denied');
  const rows=(await pool.query("SELECT id,display_name FROM users WHERE company_id=$1 AND deleted_at IS NULL AND COALESCE(display_name,'') ILIKE $2 ORDER BY display_name,id LIMIT 100",[actor.companyId,'%'+text(search,100,false).replace(/[\\%_]/g,'\\$&')+'%'])).rows;
  const people=[];for(const row of rows)if(can(await loadActor(pool,{userId:row.id,companyId:actor.companyId}),'notes.view'))people.push(row);return {people};
 }
 async function pagePeople(input,pageId){const {actor}=await authorizePage(pool,input,pageId);const rows=(await pool.query('SELECT id,display_name FROM users WHERE company_id=$1 AND deleted_at IS NULL ORDER BY display_name,id LIMIT 200',[actor.companyId])).rows;const people=[];for(const row of rows){try{await authorizePage(pool,{userId:row.id,companyId:actor.companyId},pageId);people.push(row);}catch(e){if(![403,404].includes(e.status))throw e;}}return {people};}
 async function list(input,pageId,q={}){
  await authorizePage(pool,input,pageId);const offset=Math.max(0,Number.parseInt(q.offset,10)||0);
  const rows=(await pool.query(`SELECT c.id,c.page_id,c.block_id,c.parent_id,c.author_id,c.body,c.mentions,c.resolved,c.revision,c.created_at,c.updated_at,u.display_name FROM notes_comments c JOIN users u ON u.id=c.author_id WHERE c.page_id=$1 AND c.deleted_at IS NULL ORDER BY c.created_at,c.id LIMIT 101 OFFSET $2`,[pageId,offset])).rows;
  return {comments:rows.slice(0,100),next_offset:rows.length>100?offset+100:null};
 }
 async function save(input,pageId,commentId,body){return mutate(pool,input,async(db,actor)=>{
  const {page}=await authorizePage(db,actor,pageId,{level:2,lock:true});if(page.archived_at)fail(409,'note_archived');const id=uuid(commentId||body.id||randomUUID());
  const old=(await db.query('SELECT * FROM notes_comments WHERE id=$1',[id])).rows[0];
  if(old&&(old.page_id!==pageId||old.author_id!==actor.userId&&page.access_role<4))fail(404,'comment_unavailable');
  if(!commentId&&old){if(old.author_id!==actor.userId)fail(409,'idempotency_conflict');return {id,revision:old.revision};}
  if(commentId&&(!old||old.deleted_at))fail(404,'comment_unavailable');
  if(old&&body.expected_revision!==old.revision)fail(409,'comment_conflict');
  if(old&&old.author_id!==actor.userId&&body.body!==undefined)fail(403,'comment_author_required');
  const content=body.body===undefined?old?.body:text(body.body,10000);if(!content)fail(400,'comment_body_required');
  const parent=old?.parent_id||(body.parent_id?uuid(body.parent_id):null),block=old?.block_id||(body.block_id?uuid(body.block_id):null);
  if(parent&&!(await db.query('SELECT 1 FROM notes_comments WHERE id=$1 AND page_id=$2 AND parent_id IS NULL AND deleted_at IS NULL',[parent,pageId])).rowCount)fail(404,'comment_unavailable');
  if(block&&!(await db.query('SELECT 1 FROM notes_blocks WHERE id=$1 AND page_id=$2 AND deleted_at IS NULL',[block,pageId])).rowCount)fail(404,'block_unavailable');
  const mentions=body.mentions??old?.mentions??[];if(!Array.isArray(mentions)||mentions.length>30)fail(400,'invalid_mentions');const recipients=[...new Set(mentions.map(uuid))];
  for(const userId of recipients)await authorizePage(db,{userId,companyId:actor.companyId},pageId);
  const saved=(await db.query(`INSERT INTO notes_comments(id,page_id,block_id,parent_id,author_id,body,mentions,resolved) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO UPDATE SET body=$6,mentions=$7,resolved=$8,deleted_at=CASE WHEN $9 THEN now() ELSE NULL END,updated_at=now(),revision=notes_comments.revision+1 RETURNING id,revision`,[id,pageId,block,parent,actor.userId,content,JSON.stringify(recipients),body.resolved??old?.resolved??false,body.deleted===true])).rows[0];
  await recordNoteActivity(db,actor,pageId,body.deleted===true?'comment_deleted':body.resolved!==undefined?(body.resolved?'comment_resolved':'comment_reopened'):old?'comment_updated':'commented');await publishNoteChange(db,actor,pageId,'notes.comment.changed');
  if(body.deleted!==true){const interested=new Set(recipients);if(parent){const author=(await db.query('SELECT author_id FROM notes_comments WHERE id=$1',[parent])).rows[0].author_id;interested.add(author);}else interested.add(page.owner_id);
   for(const userId of interested){if(userId===actor.userId)continue;try{await authorizePage(db,{userId,companyId:actor.companyId},pageId);}catch(e){if([403,404].includes(e.status))continue;throw e;}await notifications?.enqueue(db,{userId,companyId:actor.companyId,kind:recipients.includes(userId)?'notes.mention':'notes.comment',title:recipients.includes(userId)?'You were mentioned in a note':'A note has a new comment',eventKey:id+':'+saved.revision+':'+userId,requirements:['notes.view'],sourceRefs:[{source_type:'note',source_id:pageId}],data:{note_id:pageId,comment_id:id}});}
  }return saved;
 });}
 async function presence(input,pageId,body={}){return mutate(pool,input,async(db,actor)=>{
  await authorizePage(db,actor,pageId);let block=body.block_id?uuid(body.block_id):null;if(block&&!(await db.query('SELECT 1 FROM notes_blocks WHERE id=$1 AND page_id=$2 AND deleted_at IS NULL',[block,pageId])).rowCount)fail(404,'block_unavailable');
  if(body.leave===true)await db.query('DELETE FROM notes_presence WHERE page_id=$1 AND user_id=$2',[pageId,actor.userId]);else await db.query(`INSERT INTO notes_presence(page_id,user_id,block_id) VALUES($1,$2,$3) ON CONFLICT(page_id,user_id) DO UPDATE SET block_id=$3,updated_at=now()`,[pageId,actor.userId,block]);
  const rows=(await db.query(`SELECT p.user_id,p.block_id,u.display_name FROM notes_presence p JOIN users u ON u.id=p.user_id AND u.company_id=$2 AND u.deleted_at IS NULL WHERE p.page_id=$1 AND p.updated_at>now()-interval '45 seconds' ORDER BY u.display_name LIMIT 100`,[pageId,actor.companyId])).rows;
  const members=[];for(const row of rows){try{await authorizePage(db,{userId:row.user_id,companyId:actor.companyId},pageId);members.push(row);}catch(e){if(![403,404].includes(e.status))throw e;}}return {members};
 });}
 return {people,pagePeople,list,save,presence};
}
