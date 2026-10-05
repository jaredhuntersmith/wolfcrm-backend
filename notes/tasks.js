import {randomUUID} from 'node:crypto';
import {mutate,requireCapability,uuid,ids,text,fail,loadActor} from '../company-comms/access.js';
import {authorizePage} from './access.js';
export function createNotesTasks({pool,notes,notifications}) {
 async function convert(input,pageId,blockId,body){return mutate(pool,input,async(db,actor)=>{
  requireCapability(actor,'tasks.manage');requireCapability(actor,'tasks.view');const {page}=await authorizePage(db,actor,pageId,{level:3,lock:true});if(page.archived_at)fail(409,'note_archived');const key=uuid(body.client_key);
  const prior=(await db.query('SELECT task_id,source_id,source_type FROM comms_task_links WHERE created_by=$1 AND client_key=$2 AND company_id=$3',[actor.userId,key,actor.companyId])).rows[0];if(prior){if(prior.source_type!=='note'||prior.source_id!==pageId)fail(409,'idempotency_conflict');return {task_id:prior.task_id};}
  const block=(await db.query('SELECT * FROM notes_blocks WHERE id=$1 AND page_id=$2 AND deleted_at IS NULL',[uuid(blockId),pageId])).rows[0];if(!block||block.type!=='checklist')fail(400,'checklist_required');if(block.revision!==body.expected_revision)fail(409,'block_conflict');if(body.confirmed!==true)fail(400,'task_confirmation_required');
  const assignees=ids(body.assignee_ids||[actor.userId],20);if(!assignees.length)fail(400,'task_assignee_required');for(const id of assignees){const recipient=await loadActor(db,{userId:id,companyId:actor.companyId});requireCapability(recipient,'tasks.view');await authorizePage(db,recipient,pageId);}
  const due=body.due_date?new Date(body.due_date):null;if(due&&!Number.isFinite(due.getTime()))fail(400,'invalid_due_date');const taskId=randomUUID(),title=text(body.title||block.payload.text,300),detail=text(body.detail||'',10000,false);await notes.snapshot(db,page,actor);
  await db.query(`INSERT INTO todo_tasks(id,user_id,title,detail,creator_id,assignee_ids,due_date,priority,status) VALUES($1,$2,$3,$4,$2,$5,$6,$7,'open')`,[taskId,actor.userId,title,detail,JSON.stringify(assignees),due,['high','normal','low'].includes(body.priority)?body.priority:'normal']);
  await db.query(`INSERT INTO comms_task_links(task_id,company_id,conversation_id,source_type,source_id,source_refs,requirements,created_by,client_key) VALUES($1,$2,NULL,'note',$3,$4,'["notes.view"]',$5,$6)`,[taskId,actor.companyId,pageId,JSON.stringify([{source_type:'note',source_id:pageId}]),actor.userId,key]);
  await db.query("UPDATE notes_blocks SET type='task',payload=$2,revision=revision+1,editor_id=$3,updated_at=now() WHERE id=$1",[block.id,JSON.stringify({source_type:'task',source_id:taskId,context_type:'task'}),actor.userId]);await db.query(`UPDATE comms_notes SET body=COALESCE((SELECT string_agg(payload->>'text',E'\n' ORDER BY position,id) FROM notes_blocks WHERE page_id=$1 AND deleted_at IS NULL),'') WHERE id=$1`,[pageId]);await notes.changed(db,actor,pageId,'checklist_converted');
  for(const id of assignees)if(id!==actor.userId)await notifications?.enqueue(db,{userId:id,companyId:actor.companyId,kind:'notes.task',title:'A note task was assigned to you',eventKey:taskId+':'+id,requirements:['notes.view','tasks.view'],sourceRefs:[{source_type:'note',source_id:pageId},{source_type:'task',source_id:taskId}],data:{task_id:taskId,note_id:pageId}});
  return {task_id:taskId};
 });}
 return {convert};
}
