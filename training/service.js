import {randomUUID} from 'node:crypto';
import {loadActor,transact} from '../company-comms/access.js';
import {hasCapability} from '../permissions.js';
import {assignmentPriority,blockVisible,date,digest,fail,graceSeconds,normalizeDefinition,normalizeResponses,string,unmetRequirements,uuid} from './contract.js';
import {maybeCompleteCourse} from './certificates.js';
import {recordTrainingEvent} from './events.js';
import {learnerCheckpoint} from './video-checkpoints-contract.js';
import {prerequisiteIDs,validatePrerequisites,attachPrerequisites,prerequisiteState,requirePrerequisites} from './prerequisites.js';

export function requireTraining(actor,key){if(!actor.isCompanyOwner&&!hasCapability(actor,key))fail(403,'permission_denied','This training action is not allowed.');}
function revision(value){if(!Number.isInteger(value)||value<1)fail(400,'invalid_revision');return value;}
function recipients(value){
  if(!Array.isArray(value)||value.length<1||value.length>100)fail(400,'invalid_recipients');
  return [...new Set(value.map(uuid))].sort();
}
function audience(value){
  if(!value||typeof value!=='object'||Array.isArray(value))fail(400,'invalid_audience');
  if(value.kind==='company')return {kind:'company'};
  if(value.kind==='role'&&['employee','employer'].includes(value.role))return {kind:'role',role:value.role};
  if(['team','department','group'].includes(value.kind))return {kind:value.kind,id:uuid(value.id)};
  fail(400,'invalid_audience');
}
async function audienceRecipients(db,actor,target){
  if(target.id){
    const group=(await db.query(`SELECT id FROM training_audience_groups WHERE company_id=$1 AND id=$2 AND kind=$3 AND archived_at IS NULL`,
      [actor.companyId,target.id,target.kind])).rows[0];
    if(!group)fail(404,'audience_not_found');
    const rows=(await db.query(`SELECT u.id FROM training_audience_members m JOIN users u ON u.id=m.employee_id AND u.company_id=m.company_id
      WHERE m.company_id=$1 AND m.group_id=$2 AND u.deleted_at IS NULL AND u.role='employee' ORDER BY u.id LIMIT 501`,
      [actor.companyId,target.id])).rows;
    if(rows.length>500)fail(400,'audience_too_large');
    return rows.map(row=>row.id);
  }
  const rows=(await db.query(`SELECT id FROM users WHERE company_id=$1 AND deleted_at IS NULL
    AND role=$2 ORDER BY id LIMIT 501`,[actor.companyId,target.kind==='company'?'employee':target.role])).rows;
  if(rows.length>500)fail(400,'audience_too_large');
  return rows.map(row=>row.id);
}
function requestKey(value){return string(value,120);}
function cursorTime(value){return typeof value==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value)&&
  Number.isFinite(Date.parse(value))&&new Date(value).toISOString()===value;}
function listCursor(value,scope,sort='due'){
  if(value==null||value==='')return null;
  if(typeof value!=='string'||value.length>1024||!/^[A-Za-z0-9_-]+$/.test(value))fail(400,'invalid_training_cursor');
  let item;
  try{item=JSON.parse(Buffer.from(value,'base64url').toString('utf8'));}catch{fail(400,'invalid_training_cursor');}
  if(item?.v!==1||item.scope!==scope||item.due!==null&&!cursorTime(item.due)||
    !cursorTime(item.at)||typeof item.id!=='string'||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(item.id)||
    sort==='priority'&&(!Number.isInteger(item.key)||item.key<0||item.key>3)||
    sort==='title'&&(typeof item.key!=='string'||item.key.length>300))
    fail(400,'invalid_training_cursor');
  return {due:item.due,at:item.at,id:item.id,key:item.key??null};
}
function listPage(rows,limit,scope){
  const more=rows.length>limit,selected=rows.slice(0,limit);
  const tail=selected.at(-1);
  const next_cursor=more?Buffer.from(JSON.stringify({v:1,scope,
    due:tail.due_at?.toISOString()??null,at:tail.cursor_at.toISOString(),id:tail.id,
    key:tail.cursor_sort??null})).toString('base64url'):null;
  return {items:selected.map(({cursor_at,cursor_sort,...item})=>item),next_cursor};
}
function listDayRange(start,end,required=false){
  if(start==null&&end==null&&!required)return [null,null];
  if(start==null||end==null)fail(400,'invalid_training_day_range');
  const from=date(start,{required:true}),until=date(end,{required:true});
  const hours=(Date.parse(until)-Date.parse(from))/3600000;
  if(hours<22||hours>26)fail(400,'invalid_training_day_range');
  return [from,until];
}
function afterCursor(timeColumn,dueParam,atParam,idParam){
  return `($${idParam}::uuid IS NULL OR CASE WHEN $${dueParam}::timestamptz IS NULL THEN
    a.due_at IS NULL AND (${timeColumn}<$${atParam}::timestamptz OR
      ${timeColumn}=$${atParam}::timestamptz AND r.id>$${idParam}::uuid)
    ELSE a.due_at>$${dueParam}::timestamptz OR a.due_at IS NULL OR
      a.due_at=$${dueParam}::timestamptz AND (${timeColumn}<$${atParam}::timestamptz OR
        ${timeColumn}=$${atParam}::timestamptz AND r.id>$${idParam}::uuid) END)`;
}
const priorityOrder="CASE a.priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 ELSE 3 END";
function mineSort(sort){
  switch(sort){
    case 'priority':return {select:`${priorityOrder} AS cursor_sort`,
      after:`($12::uuid IS NULL OR ${priorityOrder}>$13::integer OR
        ${priorityOrder}=$13::integer AND ${afterCursor('r.created_at',10,11,12)})`,
      order:`${priorityOrder},a.due_at NULLS LAST,r.created_at DESC,r.id`};
    case 'title':return {select:'lower(v.title) AS cursor_sort',
      after:`($10::uuid IS NULL OR lower(v.title)>$11::text OR lower(v.title)=$11::text AND r.id>$10::uuid)`,
      order:'lower(v.title),r.id'};
    case 'recent':return {select:'NULL::text AS cursor_sort',
      after:`($11::uuid IS NULL OR a.available_at<$10::timestamptz OR
        a.available_at=$10::timestamptz AND r.id>$11::uuid)`,
      order:'a.available_at DESC,r.id'};
    default:return {select:'NULL::text AS cursor_sort',
      after:afterCursor('r.created_at',10,11,12),
      order:'a.due_at NULLS LAST,r.created_at DESC,r.id'};
  }
}
function elapsedTimerSeconds(row,now){
  const saved=Number(row.timer_accumulated_seconds??0);
  return saved+(row.timer_running_since?Math.max(0,(now-new Date(row.timer_running_since))/1000):0);
}
function hasActiveTimer(policy){return policy&&(policy.minimum_seconds!=null||policy.maximum_seconds!=null);}
function reviewScores(row,decision,input){
  const scored=row.document.blocks.filter(block=>block.points!=null&&blockVisible(row.document,block,row.responses));
  if(input!=null&&(!input||typeof input!=='object'||Array.isArray(input)))fail(400,'invalid_assignment_scores');
  const supplied=input??{};
  if(decision!=='approve'){
    if(Object.keys(supplied).length)fail(400,'scores_only_on_approval');
    return {scores:null,scorePoints:null,maxPoints:null};
  }
  if(Object.keys(supplied).length!==scored.length||Object.keys(supplied).some(id=>!scored.some(block=>block.id===id)))
    fail(400,'assignment_scores_incomplete');
  let scorePoints=0,maxPoints=0;
  for(const block of scored){
    const value=supplied[block.id];
    if(!Number.isInteger(value)||value<0||value>block.points)fail(400,'invalid_assignment_score');
    scorePoints+=value;maxPoints+=block.points;
  }
  return {scores:scored.length?supplied:null,scorePoints:scored.length?scorePoints:null,maxPoints:scored.length?maxPoints:null};
}
function nextTimer(row,action,now){
  const policy=row.document.timing;
  if(!hasActiveTimer(policy)){if(action!=null)fail(400,'timer_not_configured');return null;}
  if(action!=null&&!['start','pause','resume'].includes(action))fail(400,'invalid_timer_action');
  const started=row.timer_started_at!=null,running=row.timer_running_since!=null;
  if(action==='start'){
    if(started)fail(409,'timer_already_started');
    return {startedAt:now,runningSince:now,accumulated:0};
  }
  if(!started)fail(409,'timer_not_started');
  if(action==='pause'){
    if(policy.pause_policy!=='allowed')fail(409,'timer_pause_forbidden');
    if(!running)fail(409,'timer_not_running');
    return {startedAt:row.timer_started_at,runningSince:null,accumulated:elapsedTimerSeconds(row,now)};
  }
  if(action==='resume'){
    if(running)fail(409,'timer_already_running');
    if(policy.maximum_seconds!=null&&elapsedTimerSeconds(row,now)>=policy.maximum_seconds)fail(409,'maximum_duration_exceeded');
    return {startedAt:row.timer_started_at,runningSince:now,accumulated:Number(row.timer_accumulated_seconds)};
  }
  return {startedAt:row.timer_started_at,runningSince:row.timer_running_since,accumulated:Number(row.timer_accumulated_seconds)};
}
export async function actorFor(pool,req){return loadActor(pool,req);}
export async function trainingMutation(pool,req,capabilities,fn){
  return transact(pool,async db=>{
    // Match lifecycle cleanup's lock order. A disabled account waiting here is
    // reloaded after cleanup commits, before any private data or refs are written.
    await db.query(`SELECT id FROM companies WHERE id=$1 FOR KEY SHARE`,[req.companyId]);
    await db.query(`SELECT id FROM users WHERE company_id=$1 AND id=$2 FOR SHARE`,[req.companyId,req.userId]);
    const actor=await actorFor(db,req);
    for(const capability of capabilities)requireTraining(actor,capability);
    return fn(db,actor);
  });
}
export async function audit(db,actor,action,{recipientID=null,definitionID=null,details={}}={}){
  await db.query(`INSERT INTO training_audit_events(id,company_id,actor_id,recipient_id,definition_id,action,details)
    VALUES($1,$2,$3,$4,$5,$6,$7)`, [randomUUID(),actor.companyId,actor.userId,recipientID,definitionID,action,JSON.stringify(details)]);
}
async function definitionFor(db,actor,id,{lock=false}={}){
  const row=(await db.query(`SELECT * FROM training_definitions WHERE company_id=$1 AND id=$2
    AND (scope='company' OR created_by=$3) ${lock?'FOR UPDATE':''}`,[actor.companyId,uuid(id),actor.userId])).rows[0];
  if(!row)fail(404,'definition_not_found');return row;
}
export async function recipientFor(db,actor,id,{lock=false}={}){
  const row=(await db.query(`SELECT r.*,a.definition_id,a.version_id,a.available_at,a.due_at,a.expires_at,a.grace_seconds,a.priority,
       a.due_at+make_interval(secs => a.grace_seconds) AS effective_due_at,
       v.title,v.kind,v.document,v.version_number
    FROM training_recipients r
    JOIN training_assignments a ON a.company_id=r.company_id AND a.id=r.assignment_id
    JOIN training_versions v ON v.company_id=a.company_id AND v.id=a.version_id
    WHERE r.company_id=$1 AND r.id=$2 ${lock?'FOR UPDATE OF r':''}`,[actor.companyId,uuid(id)])).rows[0];
  if(!row)fail(404,'assignment_not_found');return row;
}
function requireRecipientAccess(actor,row,{write=false}={}){
  if(actor.userId===row.employee_id){requireTraining(actor,'training.view_self');return;}
  if(write)fail(403,'recipient_only');
  if(!actor.isCompanyOwner&&!hasCapability(actor,'training.review'))fail(404,'assignment_not_found');
}
export function checkAvailability(row){
  const now=Date.now();if(new Date(row.available_at).getTime()>now)fail(409,'assignment_not_available');
  if(row.expires_at&&new Date(row.expires_at).getTime()<now)fail(409,'assignment_expired');
}
async function hasSupervision(db,actor,employeeID){
  if(actor.isCompanyOwner)return true;
  const result=await db.query(`SELECT 1 FROM training_supervisor_grants
    WHERE company_id=$1 AND supervisor_id=$2 AND employee_id=$3`,[actor.companyId,actor.userId,employeeID]);
  return result.rowCount>0;
}
export async function requireSupervision(db,actor,employeeID){
  if(!await hasSupervision(db,actor,employeeID))fail(404,'assignment_not_found');
}
export async function eligibleAssignees(db,actor,recipientIDs){
  const users=(await db.query(`SELECT id,COALESCE(NULLIF(display_name,''),email) AS name FROM users
    WHERE company_id=$1 AND id=ANY($2::uuid[]) AND deleted_at IS NULL`,[actor.companyId,recipientIDs])).rows;
  if(users.length!==recipientIDs.length)fail(400,'invalid_recipients');
  if(!actor.isCompanyOwner){
    const scoped=(await db.query(`SELECT employee_id FROM training_supervisor_grants
      WHERE company_id=$1 AND supervisor_id=$2 AND employee_id=ANY($3::uuid[])`,[actor.companyId,actor.userId,recipientIDs])).rows;
    if(scoped.length!==recipientIDs.length)fail(403,'recipient_scope_denied');
  }
  return users;
}
function recipientDTO(row){
  const document=row.kind==='quiz'?{...row.document,quiz:{passing_percent:row.document.quiz.passing_percent,
    max_attempts:row.document.quiz.max_attempts,time_limit_seconds:row.document.quiz.time_limit_seconds,
    question_count:row.document.quiz.questions.length,questions:[]}}:{...row.document,blocks:row.document.blocks.map(block=>
      block.type==='video'?{...block,video:{...block.video,
        ...(block.video.checkpoints?{checkpoints:block.video.checkpoints.map(learnerCheckpoint)}:{}),
        ...(block.video.knowledge_check?{knowledge_check:{
        passing_percent:block.video.knowledge_check.passing_percent,max_attempts:block.video.knowledge_check.max_attempts,
        question_count:block.video.knowledge_check.questions.length,questions:[]}}:{})}}:block)};
  return {id:row.id,assignment_id:row.assignment_id,employee_id:row.employee_id,
    employee_name:row.employee_name_snapshot,title:row.title,kind:row.kind,version_number:row.version_number,
    document,status:row.status,responses:row.responses,revision:row.revision,
    available_at:row.available_at,due_at:row.due_at,expires_at:row.expires_at,
    grace_seconds:row.grace_seconds,effective_due_at:row.effective_due_at,priority:row.priority,
    submitted_at:row.submitted_at,completed_at:row.completed_at,updated_at:row.updated_at,
    timer_started_at:row.timer_started_at,timer_running_since:row.timer_running_since,
    timer_accumulated_seconds:Number(row.timer_accumulated_seconds??0),
    score_points:row.score_points,max_points:row.max_points};
}
function portableDefinition(value){
  if(Array.isArray(value))return value.every(portableDefinition);
  if(value&&typeof value==='object'){
    if(value.provider==='mux')return false;
    if(['linked_quiz','linked_lesson'].includes(value.type))return false;
    return Object.entries(value).every(([key,item])=>
      !(item!=null&&(key==='file_id'||key.endsWith('_file_id')))&&portableDefinition(item));
  }
  return true;
}
async function createDefinitionRow(db,actor,document){
  const id=randomUUID();await db.query(`INSERT INTO training_definitions(id,company_id,created_by,kind,title,draft,scope,category)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,[id,actor.companyId,actor.userId,document.kind,document.title,JSON.stringify(document),document.scope,document.category]);
  await audit(db,actor,'definition.created',{definitionID:id});return id;
}
async function publishRow(db,actor,definition,videoCapabilities){
  const document=normalizeDefinition(definition.draft,{videoCapabilities});const next=definition.latest_version+1,id=randomUUID();
  const links=document.blocks.filter(block=>['linked_quiz','linked_lesson'].includes(block.type));
  if(links.length>20)fail(400,'too_many_linked_blocks');
  if(links.length){
    const versions=(await db.query(`SELECT v.id,v.definition_id,v.kind,v.document,d.scope,d.created_by
      FROM training_versions v JOIN training_definitions d ON d.company_id=v.company_id AND d.id=v.definition_id
      WHERE v.company_id=$1 AND v.id=ANY($2::uuid[])`,
    [actor.companyId,[...new Set(links.map(block=>block.version_id))]])).rows;
    const byID=new Map(versions.map(version=>[version.id,version]));
    for(const block of links){
      const target=byID.get(block.version_id);
      if(!target||target.definition_id!==block.definition_id||target.definition_id===definition.id||
         target.scope==='personal'&&target.created_by!==actor.userId||
         target.scope==='personal'&&definition.scope==='company'||
         (block.type==='linked_quiz'&&target.kind!=='quiz')||
         (block.type==='linked_lesson'&&target.kind==='quiz')||
         target.document.blocks.some(child=>['linked_quiz','linked_lesson'].includes(child.type)))
        fail(409,'linked_version_unavailable');
    }
  }
  for(const block of document.blocks.filter(item=>item.type==='video'&&item.video.provider==='mux')){
    const asset=(await db.query(`SELECT duration_seconds,policy FROM training_video_assets WHERE company_id=$1 AND playback_id=$2`,
      [actor.companyId,block.video.external_id])).rows[0];
    if(!asset||asset.policy!=='signed'||(block.video.duration_seconds!=null&&asset.duration_seconds!==block.video.duration_seconds))fail(409,'video_asset_unverified');
    block.video.duration_seconds=asset.duration_seconds;
  }
  const contentQuestions=[...(document.kind==='quiz'?document.quiz.questions:[]),
    ...document.blocks.filter(block=>block.type==='video'&&block.video.knowledge_check)
      .flatMap(block=>block.video.knowledge_check.questions),
    ...document.blocks.filter(block=>block.type==='video'&&block.video.checkpoints)
      .flatMap(block=>block.video.checkpoints.filter(checkpoint=>checkpoint.kind==='question').map(checkpoint=>checkpoint.question))];
  const mediaBlocks=document.blocks.filter(block=>['image','audio','pdf','file'].includes(block.type));
  const referencedFiles=[...new Set([...mediaBlocks.map(block=>block.file_id),...contentQuestions.flatMap(question=>[
    question.image_file_id,...question.options.map(option=>option.image_file_id)
  ])].filter(Boolean))];
  let contentRefs=[];
  if(referencedFiles.length){
    contentRefs=(await db.query(`SELECT ar.file_id,ar.created_by,f.mime_type FROM training_asset_refs ar
      JOIN stored_files f ON f.id=ar.file_id AND f.company_id=ar.company_id
      WHERE ar.company_id=$1 AND ar.definition_id=$2 AND ar.file_id=ANY($3::uuid[])
        AND f.source_scope='training' AND f.source_protected AND f.visibility='private' AND f.cloud_status='active'`,
      [actor.companyId,definition.id,referencedFiles])).rows;
    if(contentRefs.length!==referencedFiles.length)fail(409,'content_asset_unavailable');
    const mimeByID=new Map(contentRefs.map(ref=>[ref.file_id,ref.mime_type]));
    const imageIDs=contentQuestions.flatMap(question=>[question.image_file_id,...question.options.map(option=>option.image_file_id)]).filter(Boolean);
    for(const id of imageIDs)if(!mimeByID.get(id)?.startsWith('image/'))fail(409,'content_asset_type_mismatch');
    for(const block of mediaBlocks){
      const mime=mimeByID.get(block.file_id)??'';
      const valid=block.type==='image'?mime.startsWith('image/'):
        block.type==='audio'?mime.startsWith('audio/'):
        block.type==='pdf'?mime==='application/pdf':
        ['application/pdf','text/plain','application/vnd.openxmlformats-officedocument.wordprocessingml.document'].includes(mime);
      if(!valid)fail(409,'content_asset_type_mismatch');
    }
  }
  await db.query(`INSERT INTO training_versions(id,company_id,definition_id,version_number,schema_version,kind,title,document,content_sha256,published_by)
    VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$9)`,[id,actor.companyId,definition.id,next,document.kind,document.title,JSON.stringify(document),digest(document),actor.userId]);
  for(const ref of contentRefs){
    await db.query(`INSERT INTO training_asset_refs(id,company_id,file_id,created_by,purpose,version_id)
      VALUES($1,$2,$3,$4,'content',$5)`,[randomUUID(),actor.companyId,ref.file_id,ref.created_by,id]);
  }
  await db.query(`UPDATE training_definitions SET latest_version=$3,updated_at=now() WHERE company_id=$1 AND id=$2`,[actor.companyId,definition.id,next]);
  await audit(db,actor,'definition.published',{definitionID:definition.id,details:{version_id:id,version_number:next}});
  return {id,definition_id:definition.id,version_number:next,content_sha256:digest(document),document};
}
export async function assignRow(db,actor,{definitionID,versionID,recipientIDs,availableAt,dueAt,expiresAt,grace=0,priority='normal',key,inputHash}){
  await db.query(`SELECT pg_advisory_xact_lock(hashtext($1))`,[`${actor.companyId}:${actor.userId}:${key}`]);
  const existing=(await db.query(`SELECT * FROM training_assignments WHERE company_id=$1 AND assigned_by=$2 AND request_key=$3`,[actor.companyId,actor.userId,key])).rows[0];
  if(existing){if(existing.input_sha256!==inputHash)fail(409,'request_key_conflict');return existing;}
  if(recipientIDs.length<1||recipientIDs.length>500)fail(400,'invalid_recipients');
  const users=await eligibleAssignees(db,actor,recipientIDs);
  const version=(await db.query(`SELECT id,definition_id,document FROM training_versions WHERE company_id=$1 AND id=$2 AND definition_id=$3`,[actor.companyId,versionID,definitionID])).rows[0];
  if(!version)fail(404,'version_not_found');
  const id=randomUUID();
  await db.query(`INSERT INTO training_assignments(id,company_id,definition_id,version_id,assigned_by,request_key,input_sha256,available_at,due_at,expires_at,grace_seconds,priority)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,[id,actor.companyId,definitionID,versionID,actor.userId,key,inputHash,availableAt,dueAt,expiresAt,grace,priority]);
  const effectiveDueAt=dueAt?new Date(new Date(dueAt).getTime()+grace*1000).toISOString():null;
  const parentRecipients=[];
  for(const user of users){
    const recipientID=randomUUID();
    parentRecipients.push({id:recipientID,employee_id:user.id,employee_name_snapshot:user.name});
    await db.query(`INSERT INTO training_recipients(id,company_id,assignment_id,employee_id,employee_name_snapshot)
      VALUES($1,$2,$3,$4,$5)`,[recipientID,actor.companyId,id,user.id,user.name]);
    await audit(db,actor,'assignment.created',{definitionID,recipientID,details:{assignment_id:id,version_id:versionID}});
    await recordTrainingEvent(db,actor,{type:'training.assignment_assigned',subjectType:'training_recipient',subjectID:recipientID,
      key:`assignment:${recipientID}:assigned`,payload:{recipient_id:recipientID,employee_id:user.id,assignment_id:id,definition_id:definitionID,version_id:versionID,
        due_at:dueAt,grace_seconds:grace,effective_due_at:effectiveDueAt,priority}});
  }
  await createLinkedRuns(db,actor,{assignmentID:id,document:version.document,recipients:parentRecipients,
    assignedBy:actor.userId,availableAt,dueAt,expiresAt,grace,priority});
  return {id,company_id:actor.companyId,definition_id:definitionID,version_id:versionID,available_at:availableAt,
    due_at:dueAt,expires_at:expiresAt,grace_seconds:grace,effective_due_at:effectiveDueAt,priority};
}

export async function createLinkedRuns(db,actor,{assignmentID,document,recipients,assignedBy,availableAt,dueAt,expiresAt,grace=0,priority='normal'}){
  const links=document.blocks.filter(block=>['linked_quiz','linked_lesson'].includes(block.type));
  for(const block of links){
    const target=(await db.query(`SELECT v.id,v.definition_id,v.kind,v.document,d.scope,d.created_by
      FROM training_versions v JOIN training_definitions d ON d.company_id=v.company_id AND d.id=v.definition_id
      WHERE v.company_id=$1 AND v.id=$2 AND v.definition_id=$3`,
    [actor.companyId,block.version_id,block.definition_id])).rows[0];
    if(!target||(block.type==='linked_quiz'&&target.kind!=='quiz')||
       (block.type==='linked_lesson'&&target.kind==='quiz')||
       target.scope==='personal'&&target.created_by!==assignedBy||
       target.document.blocks.some(item=>['linked_quiz','linked_lesson'].includes(item.type)))
      fail(409,'linked_version_unavailable');
    const childAssignmentID=randomUUID(),childKey=`linked:${assignmentID}:${block.id}`;
    await db.query(`INSERT INTO training_assignments(id,company_id,definition_id,version_id,assigned_by,request_key,input_sha256,
      available_at,due_at,expires_at,grace_seconds,priority)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
    [childAssignmentID,actor.companyId,target.definition_id,target.id,assignedBy,childKey,
      digest({assignmentID,block_id:block.id,version_id:target.id}),availableAt,dueAt,expiresAt,grace,priority]);
    for(const parent of recipients){
      const childRecipientID=randomUUID();
      await db.query(`INSERT INTO training_recipients(id,company_id,assignment_id,employee_id,employee_name_snapshot)
        VALUES($1,$2,$3,$4,$5)`,
      [childRecipientID,actor.companyId,childAssignmentID,parent.employee_id,parent.employee_name_snapshot]);
      await db.query(`INSERT INTO training_linked_runs(company_id,parent_recipient_id,block_id,child_recipient_id)
        VALUES($1,$2,$3,$4)`,[actor.companyId,parent.id,block.id,childRecipientID]);
      await audit(db,actor,'assignment.linked_child_created',{recipientID:childRecipientID,
        details:{parent_recipient_id:parent.id,block_id:block.id,assignment_id:childAssignmentID}});
    }
  }
}

export function createTrainingService({pool,videoCapabilities}){
  return {
    async validateDefinition(req,body){const actor=await actorFor(pool,req);requireTraining(actor,'training.author');return {document:normalizeDefinition(body,{videoCapabilities})};},
    async createDefinition(req,body){const document=normalizeDefinition(body,{videoCapabilities});
      return trainingMutation(pool,req,['training.author'],async(db,actor)=>{const id=await createDefinitionRow(db,actor,document);return {id,revision:1,draft:document};});},
    async updateDefinition(req,id,body){const expected=revision(body?.expected_revision);
      return trainingMutation(pool,req,['training.author'],async(db,actor)=>{const row=await definitionFor(db,actor,id,{lock:true});if(row.created_by!==actor.userId&&!actor.isCompanyOwner)fail(403,'author_only');if(row.archived_at)fail(409,'definition_archived');if(row.draft_revision!==expected)fail(409,'stale_revision');
        const document=normalizeDefinition({...body,scope:body.scope??row.scope,category:body.category===undefined?row.category:body.category},{videoCapabilities});
        if(document.scope==='personal'&&row.created_by!==actor.userId)fail(403,'personal_author_only');
        if(row.latest_version>0&&document.scope!==row.scope)fail(409,'published_scope_immutable');
        const result=(await db.query(`UPDATE training_definitions SET draft=$3,kind=$4,title=$5,scope=$6,category=$7,
          draft_revision=draft_revision+1,updated_at=now() WHERE company_id=$1 AND id=$2 RETURNING draft_revision`,
        [actor.companyId,id,JSON.stringify(document),document.kind,document.title,document.scope,document.category])).rows[0];
        await audit(db,actor,'definition.updated',{definitionID:id,details:{draft_revision:result.draft_revision}});return {id,revision:result.draft_revision,draft:document};});},
    async publish(req,id,body){const expected=revision(body?.expected_revision);
      return trainingMutation(pool,req,['training.publish'],async(db,actor)=>{
        const row=await definitionFor(db,actor,id,{lock:true});if(row.archived_at)fail(409,'definition_archived');if(row.draft_revision!==expected)fail(409,'stale_revision');
        if(row.scope==='personal'&&row.created_by!==actor.userId)fail(404,'definition_not_found');
        if(row.latest_version){const latest=(await db.query(`SELECT content_sha256 FROM training_versions WHERE company_id=$1 AND definition_id=$2 AND version_number=$3`,[actor.companyId,id,row.latest_version])).rows[0];if(latest?.content_sha256===digest(normalizeDefinition(row.draft,{videoCapabilities})))fail(409,'unchanged_definition');}
        return publishRow(db,actor,row,videoCapabilities);});},
    async listDefinitions(req,query){const actor=await actorFor(pool,req);requireTraining(actor,'training.author');const limit=Math.max(1,Math.min(100,Number(query?.limit)||50));
      const rows=(await pool.query(`SELECT id,kind,title,scope,category,draft_revision,latest_version,archived_at,updated_at
        FROM training_definitions WHERE company_id=$1 AND archived_at IS NULL AND (scope='company' OR created_by=$3)
        ORDER BY updated_at DESC,id LIMIT $2`,[actor.companyId,limit,actor.userId])).rows;return {items:rows};},
    async getDefinition(req,id){const actor=await actorFor(pool,req);requireTraining(actor,'training.author');const row=await definitionFor(pool,actor,id);return {id:row.id,kind:row.kind,title:row.title,scope:row.scope,category:row.category,draft:row.draft,revision:row.draft_revision,latest_version:row.latest_version,archived_at:row.archived_at};},
    async exportDefinition(req,id){const actor=await actorFor(pool,req);requireTraining(actor,'training.author');const row=await definitionFor(pool,actor,id);
      if(row.archived_at)fail(404,'definition_not_found');
      const document=normalizeDefinition(row.draft,{videoCapabilities});
      if(!portableDefinition(document))fail(409,'template_not_portable');
      return {format:'wolfcrm.training.template.v1',document};},
    async importDefinition(req,body){
      if(body?.format!=='wolfcrm.training.template.v1')fail(400,'invalid_template_format');
      const document=normalizeDefinition({...body.document,scope:'personal'},{videoCapabilities});
      if(!portableDefinition(document))fail(400,'template_not_portable');
      return trainingMutation(pool,req,['training.author'],async(db,actor)=>{const id=await createDefinitionRow(db,actor,document);
        await audit(db,actor,'definition.imported',{definitionID:id});return {id,revision:1,draft:document};});},
    async duplicateDefinition(req,id,body){
      return trainingMutation(pool,req,['training.author'],async(db,actor)=>{const source=await definitionFor(db,actor,id);
        const title=string(body?.title??`${source.title} copy`,200);
        const document=normalizeDefinition({...source.draft,title},{videoCapabilities});
        const copyID=await createDefinitionRow(db,actor,document);
        await audit(db,actor,'definition.duplicated',{definitionID:copyID,details:{source_definition_id:source.id}});
        return {id:copyID,revision:1,draft:document};});},
    async archiveDefinition(req,id,body){
      const expected=revision(body?.expected_revision);
      return trainingMutation(pool,req,['training.author'],async(db,actor)=>{const row=await definitionFor(db,actor,id,{lock:true});
        if(row.created_by!==actor.userId&&!actor.isCompanyOwner)fail(403,'author_only');
        if(row.draft_revision!==expected)fail(409,'stale_revision');
        if(row.archived_at)fail(409,'definition_archived');
        const archived=(await db.query(`UPDATE training_definitions SET archived_at=now(),updated_at=now()
          WHERE company_id=$1 AND id=$2 RETURNING archived_at`,[actor.companyId,row.id])).rows[0];
        await audit(db,actor,'definition.archived',{definitionID:row.id});
        return {id:row.id,archived_at:archived.archived_at};});},
    async listDefinitionVersions(req,id){const actor=await actorFor(pool,req);requireTraining(actor,'training.author');await definitionFor(pool,actor,id);
      const rows=(await pool.query(`SELECT id,definition_id,version_number,title,kind,published_at,content_sha256
        FROM training_versions WHERE company_id=$1 AND definition_id=$2 ORDER BY version_number DESC LIMIT 100`,[actor.companyId,id])).rows;
      return {items:rows};},
    async getDefinitionVersion(req,id,versionID){const actor=await actorFor(pool,req);requireTraining(actor,'training.author');
      await definitionFor(pool,actor,id);
      const row=(await pool.query(`SELECT id,definition_id,version_number,title,kind,published_at,content_sha256,document
        FROM training_versions WHERE company_id=$1 AND definition_id=$2 AND id=$3`,
      [actor.companyId,uuid(id),uuid(versionID)])).rows[0];
      if(!row)fail(404,'version_not_found');return row;},
    async listAssignments(req){const actor=await actorFor(pool,req);requireTraining(actor,'training.assign');
      const rows=(await pool.query(`SELECT a.id,v.title,v.kind,a.created_at,a.due_at,a.priority,
        count(r.id)::integer AS recipient_count
        FROM training_assignments a JOIN training_versions v ON v.company_id=a.company_id AND v.id=a.version_id
        JOIN training_recipients r ON r.company_id=a.company_id AND r.assignment_id=a.id
        WHERE a.company_id=$1 AND ($2::boolean OR a.assigned_by=$3)
          AND NOT EXISTS (SELECT 1 FROM training_recipients child JOIN training_linked_runs lr
            ON lr.company_id=child.company_id AND lr.child_recipient_id=child.id
            WHERE child.company_id=a.company_id AND child.assignment_id=a.id)
        GROUP BY a.id,v.title,v.kind ORDER BY a.created_at DESC,a.id DESC LIMIT 100`,
      [actor.companyId,actor.isCompanyOwner,actor.userId])).rows;return {items:rows};},
    async lessonOptions(req){const actor=await actorFor(pool,req);requireTraining(actor,'training.author');
      const rows=(await pool.query(`SELECT DISTINCT ON (d.id) d.id AS definition_id,d.title,d.scope,v.id AS version_id,v.version_number,v.kind,
        EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(v.document->'blocks','[]'::jsonb)) AS block(value)
          WHERE block.value->>'type' IN ('linked_quiz','linked_lesson')) AS has_linked_blocks
        FROM training_definitions d JOIN training_versions v ON v.company_id=d.company_id AND v.definition_id=d.id
        WHERE d.company_id=$1 AND d.archived_at IS NULL AND (d.scope='company' OR d.created_by=$2)
        ORDER BY d.id,v.version_number DESC LIMIT 200`,[actor.companyId,actor.userId])).rows;
      return {items:rows.sort((a,b)=>a.title.localeCompare(b.title))};},
    async assign(req,body){
      const definitionID=uuid(body?.definition_id),key=requestKey(body?.request_key);
      const requiredAssignments=prerequisiteIDs(body?.prerequisite_assignment_ids);
      if(body?.audience!=null&&body?.recipient_ids!=null)fail(400,'ambiguous_audience');
      const target=body?.audience!=null?audience(body.audience):null;
      const explicit=target?null:recipients(body?.recipient_ids);
      const requestedVersion=body?.version_id?uuid(body.version_id):null;
      const availableAt=date(body?.available_at)||new Date().toISOString(),dueAt=date(body?.due_at),expiresAt=date(body?.expires_at);
      const grace=graceSeconds(body?.grace_seconds);
      const priority=assignmentPriority(body?.priority);
      if(grace&&!dueAt)fail(400,'grace_requires_due_date');
      if(dueAt&&dueAt<availableAt||expiresAt&&expiresAt<availableAt)fail(400,'invalid_date_range');
      const hash=digest({definitionID,requestedVersion,audience:target,recipientIDs:explicit,availableAt:body?.available_at?availableAt:null,dueAt,expiresAt,
        ...(grace?{graceSeconds:grace}:{}),
        ...(priority!=='normal'?{priority}:{}),
        ...(requiredAssignments?.length?{prerequisiteAssignmentIDs:requiredAssignments}:{})});
      return trainingMutation(pool,req,['training.assign'],async(db,actor)=>{
        await db.query(`SELECT pg_advisory_xact_lock(hashtext($1))`,[`${actor.companyId}:${actor.userId}:${key}`]);
        const prior=(await db.query(`SELECT id,version_id,input_sha256 FROM training_assignments
          WHERE company_id=$1 AND assigned_by=$2 AND request_key=$3`,[actor.companyId,actor.userId,key])).rows[0];
        if(prior){
          const legacyHash=target||requiredAssignments?.length||grace||priority!=='normal'?null:digest({definitionID,versionID:prior.version_id,recipientIDs:explicit,
            availableAt:body?.available_at?availableAt:null,dueAt,expiresAt});
          if(prior.input_sha256!==hash&&prior.input_sha256!==legacyHash)fail(409,'request_key_conflict');
          const count=(await db.query(`SELECT count(*)::integer AS n FROM training_recipients WHERE company_id=$1 AND assignment_id=$2`,[actor.companyId,prior.id])).rows[0].n;
          return {id:prior.id,version_id:prior.version_id,recipient_count:count};}
        const definition=await definitionFor(db,actor,definitionID);if(definition.archived_at)fail(409,'definition_archived');
        const versionID=requestedVersion??(await db.query(`SELECT id FROM training_versions WHERE company_id=$1 AND definition_id=$2 AND version_number=$3`,[actor.companyId,definitionID,definition.latest_version])).rows[0]?.id;
        if(!versionID)fail(409,'definition_unpublished');
        const recipientIDs=target?await audienceRecipients(db,actor,target):explicit;
        await validatePrerequisites(db,actor,requiredAssignments,recipientIDs);
        const row=await assignRow(db,actor,{definitionID,versionID,recipientIDs,availableAt,dueAt,expiresAt,grace,priority,key,inputHash:hash});
        await attachPrerequisites(db,actor,row.id,requiredAssignments);
        const count=(await db.query(`SELECT count(*)::integer AS n FROM training_recipients WHERE company_id=$1 AND assignment_id=$2`,[actor.companyId,row.id])).rows[0].n;
        return {id:row.id,version_id:row.version_id,recipient_count:count};});},
    async quickTask(req,body){
      const recipientIDs=recipients(body?.recipient_ids),key=requestKey(body?.request_key),title=string(body?.title,200);
      const requiredAssignments=prerequisiteIDs(body?.prerequisite_assignment_ids);
      if(body?.steps!==undefined&&!Array.isArray(body.steps))fail(400,'invalid_checklist');
      const document=normalizeDefinition({kind:'task',title,blocks:body?.steps?.length?[{id:'steps',type:'checklist',items:body.steps.map((step,i)=>({id:`step-${i+1}`,text:step,required:true}))}]:[],requires_review:body?.requires_review===true},{videoCapabilities});
      const availableAt=date(body?.available_at)||new Date().toISOString(),dueAt=date(body?.due_at),expiresAt=date(body?.expires_at);
      const grace=graceSeconds(body?.grace_seconds);
      const priority=assignmentPriority(body?.priority);
      if(grace&&!dueAt)fail(400,'grace_requires_due_date');
      if(dueAt&&dueAt<availableAt||expiresAt&&expiresAt<availableAt)fail(400,'invalid_date_range');
      return trainingMutation(pool,req,['training.author','training.publish','training.assign'],async(db,actor)=>{
        await db.query(`SELECT pg_advisory_xact_lock(hashtext($1))`,[`${actor.companyId}:${actor.userId}:${key}`]);
        await eligibleAssignees(db,actor,recipientIDs);
        const hash=digest({document,recipientIDs,availableAt:body?.available_at?availableAt:null,dueAt,expiresAt,
          ...(grace?{graceSeconds:grace}:{}),
          ...(priority!=='normal'?{priority}:{}),
          ...(requiredAssignments?.length?{prerequisiteAssignmentIDs:requiredAssignments}:{})});
        const existing=(await db.query(`SELECT id,input_sha256,definition_id,version_id FROM training_assignments WHERE company_id=$1 AND assigned_by=$2 AND request_key=$3`,[actor.companyId,actor.userId,key])).rows[0];
        if(existing){if(existing.input_sha256!==hash)fail(409,'request_key_conflict');return {id:existing.id,definition_id:existing.definition_id,version_id:existing.version_id,recipient_count:recipientIDs.length};}
        await validatePrerequisites(db,actor,requiredAssignments,recipientIDs);
        const definitionID=await createDefinitionRow(db,actor,document);const definition=await definitionFor(db,actor,definitionID,{lock:true});const version=await publishRow(db,actor,definition,videoCapabilities);
        const row=await assignRow(db,actor,{definitionID,versionID:version.id,recipientIDs,availableAt,dueAt,expiresAt,grace,priority,key,inputHash:hash});
        await attachPrerequisites(db,actor,row.id,requiredAssignments);
        return {id:row.id,definition_id:definitionID,version_id:version.id,recipient_count:recipientIDs.length};
      });},
    async listMine(req,query){const actor=await actorFor(pool,req);requireTraining(actor,'training.view_self');const limit=Math.max(1,Math.min(100,Number(query?.limit)||50));
      const search=query?.search==null?null:string(query.search,100,{required:false})||null;
      const filter=query?.filter==null?'all':string(query.filter,30);
      if(!['all','open','today','upcoming','in_progress','overdue','review','completed'].includes(filter))fail(400,'invalid_training_filter');
      const sort=query?.sort==null?'due':string(query.sort,20);
      if(!['due','priority','title','recent'].includes(sort))fail(400,'invalid_training_sort');
      const ordering=mineSort(sort);
      const [dayStart,dayEnd]=listDayRange(query?.day_start,query?.day_end,['today','upcoming'].includes(filter));
      const [calendarStart,calendarEnd]=listDayRange(query?.calendar_start,query?.calendar_end);
      const scope=JSON.stringify(['mine',actor.companyId,actor.userId,search,filter,sort,dayStart,dayEnd,calendarStart,calendarEnd]);
      const cursor=listCursor(query?.cursor,scope,sort);
      const rows=(await pool.query(`SELECT r.id,r.assignment_id,r.status,r.revision,r.submitted_at,r.completed_at,a.available_at,a.due_at,a.expires_at,a.priority,
        ${sort==='recent'?'a.available_at':'r.created_at'} AS cursor_at,${ordering.select},
        a.grace_seconds,a.due_at+make_interval(secs => a.grace_seconds) AS effective_due_at,v.title,v.kind,v.version_number,
        EXISTS (SELECT 1 FROM training_assignment_prerequisites p
          LEFT JOIN training_recipients prior ON prior.company_id=p.company_id AND prior.assignment_id=p.prerequisite_assignment_id
            AND prior.employee_id=r.employee_id
          WHERE p.company_id=r.company_id AND p.assignment_id=r.assignment_id
            AND prior.status IS DISTINCT FROM 'completed') AS prerequisites_blocked
        FROM training_recipients r JOIN training_assignments a ON a.company_id=r.company_id AND a.id=r.assignment_id
        JOIN training_versions v ON v.company_id=a.company_id AND v.id=a.version_id
        WHERE r.company_id=$1 AND r.employee_id=$2
          AND NOT EXISTS (SELECT 1 FROM training_linked_runs lr WHERE lr.company_id=r.company_id AND lr.child_recipient_id=r.id)
          AND ($3::text IS NULL OR v.title ILIKE '%'||$3||'%')
          AND ($4::text='all' OR $4='open' AND r.status!='completed'
            OR $4='today' AND r.status!='completed' AND a.due_at >= $5::timestamptz AND a.due_at < $6::timestamptz
            OR $4='upcoming' AND r.status!='completed' AND a.due_at >= $6::timestamptz
            OR $4='in_progress' AND r.status IN ('in_progress','corrections_requested')
            OR $4='overdue' AND r.status!='completed' AND
              a.due_at+make_interval(secs => a.grace_seconds) < now()
            OR $4='review' AND r.status='awaiting_review'
            OR $4='completed' AND r.status='completed')
          AND ($7::timestamptz IS NULL OR a.due_at >= $7::timestamptz AND a.due_at < $8::timestamptz)
          AND ${ordering.after}
        ORDER BY ${ordering.order} LIMIT $9`,
      [actor.companyId,actor.userId,search,filter,dayStart,dayEnd,calendarStart,calendarEnd,
        limit+1,...(sort==='title'
          ?[cursor?.id??null,cursor?.key??null]
          :sort==='recent'?[cursor?.at??null,cursor?.id??null]
          :[cursor?.due??null,cursor?.at??null,cursor?.id??null,...(sort==='priority'?[cursor?.key??null]:[])])])).rows;
      return listPage(rows,limit,scope);},
    async getRecipient(req,id){const actor=await actorFor(pool,req);const row=await recipientFor(pool,actor,id);requireRecipientAccess(actor,row);if(actor.userId!==row.employee_id)await requireSupervision(pool,actor,row.employee_id);
      const linked=(await pool.query(`SELECT lr.block_id,child.id AS recipient_id,child.status,v.title,v.kind
        FROM training_linked_runs lr JOIN training_recipients child
          ON child.company_id=lr.company_id AND child.id=lr.child_recipient_id
        JOIN training_assignments a ON a.company_id=child.company_id AND a.id=child.assignment_id
        JOIN training_versions v ON v.company_id=a.company_id AND v.id=a.version_id
        WHERE lr.company_id=$1 AND lr.parent_recipient_id=$2 ORDER BY lr.block_id`,
      [actor.companyId,row.id])).rows;
      return {...recipientDTO(row),prerequisites:await prerequisiteState(pool,actor,row),linked_runs:linked};},
    async saveResponses(req,id,body){const expected=revision(body?.expected_revision);
      return trainingMutation(pool,req,[],async(db,actor)=>{const row=await recipientFor(db,actor,id,{lock:true});requireRecipientAccess(actor,row,{write:true});checkAvailability(row);await requirePrerequisites(db,actor,row);
        if(row.kind==='quiz')fail(409,'use_quiz_attempt_endpoint');
        if(!['assigned','in_progress','corrections_requested'].includes(row.status))fail(409,'assignment_not_editable');if(row.revision!==expected)fail(409,'stale_revision');
        const responses=normalizeResponses(row.document,body?.responses);
        const serverNow=(await db.query(`SELECT clock_timestamp() AS now`)).rows[0].now;
        const timer=nextTimer(row,body?.timer_action,serverNow);
        const updated=(await db.query(`UPDATE training_recipients SET responses=$3,status='in_progress',revision=revision+1,updated_at=$4,
          timer_started_at=$5,timer_running_since=$6,timer_accumulated_seconds=$7
          WHERE company_id=$1 AND id=$2 RETURNING revision,status,updated_at,timer_started_at,timer_running_since,timer_accumulated_seconds`,
        [actor.companyId,id,JSON.stringify(responses),serverNow,timer?.startedAt??row.timer_started_at,
          timer?.runningSince??null,timer?.accumulated??Number(row.timer_accumulated_seconds??0)])).rows[0];
        await audit(db,actor,'responses.saved',{recipientID:id,definitionID:row.definition_id,
          details:{revision:updated.revision,...(body?.timer_action?{timer_action:body.timer_action}:{} )}});
        return {id,revision:updated.revision,status:updated.status,responses,updated_at:updated.updated_at,
          timer_started_at:updated.timer_started_at,timer_running_since:updated.timer_running_since,
          timer_accumulated_seconds:Number(updated.timer_accumulated_seconds)};});},
    async submit(req,id,body){const expected=revision(body?.expected_revision);
      return trainingMutation(pool,req,[],async(db,actor)=>{const row=await recipientFor(db,actor,id,{lock:true});requireRecipientAccess(actor,row,{write:true});checkAvailability(row);await requirePrerequisites(db,actor,row);
        if(row.kind==='quiz')fail(409,'use_quiz_attempt_endpoint');
        if(!['assigned','in_progress','corrections_requested'].includes(row.status))fail(409,'assignment_not_submittable');if(row.revision!==expected)fail(409,'stale_revision');
        let submittedTimerSeconds=Number(row.timer_accumulated_seconds??0);
        if(row.timer_running_since){
          const serverNow=(await db.query(`SELECT clock_timestamp() AS now`)).rows[0].now;
          submittedTimerSeconds=elapsedTimerSeconds(row,serverNow);
        }
        if(hasActiveTimer(row.document.timing)&&row.status!=='corrections_requested'){
          if(!row.timer_started_at)fail(409,'timer_not_started');
          if(row.document.timing.minimum_seconds!=null&&submittedTimerSeconds<row.document.timing.minimum_seconds)fail(409,'minimum_duration_incomplete');
          if(row.document.timing.maximum_seconds!=null&&submittedTimerSeconds>row.document.timing.maximum_seconds)fail(409,'maximum_duration_exceeded');
        }
        const evidence=(await db.query(`SELECT ar.block_id,count(*)::integer AS count FROM training_asset_refs ar
          JOIN stored_files f ON f.id=ar.file_id AND f.company_id=ar.company_id
          WHERE ar.company_id=$1 AND ar.recipient_id=$2 AND ar.block_id IS NOT NULL
            AND f.cloud_status='active' AND f.source_scope='training' AND f.source_protected
          GROUP BY ar.block_id`,[actor.companyId,row.id])).rows;
        const evidenceCounts=Object.fromEntries(evidence.map(item=>[item.block_id,item.count]));
        const videos=(await db.query(`SELECT block_id FROM training_video_progress WHERE company_id=$1 AND recipient_id=$2
          AND version_id=$3 AND completed_at IS NOT NULL`,[actor.companyId,row.id,row.version_id])).rows;
        const videoCompletions=Object.fromEntries(videos.map(item=>[item.block_id,true]));
        const linked=(await db.query(`SELECT lr.block_id,child.status FROM training_linked_runs lr
          JOIN training_recipients child ON child.company_id=lr.company_id AND child.id=lr.child_recipient_id
          WHERE lr.company_id=$1 AND lr.parent_recipient_id=$2`,[actor.companyId,row.id])).rows;
        const linkedCompletions=Object.fromEntries(linked.map(item=>[item.block_id,item.status==='completed']));
        const missing=unmetRequirements(row.document,row.responses,{evidenceCounts,videoCompletions,linkedCompletions});if(missing.length)fail(409,'requirements_incomplete');
        const status=row.document.requires_review?'awaiting_review':'completed';const updated=(await db.query(`UPDATE training_recipients SET status=$3,submitted_at=now(),completed_at=CASE WHEN $3='completed' THEN now() ELSE NULL END,
          timer_running_since=NULL,timer_accumulated_seconds=$4,revision=revision+1,updated_at=now()
          WHERE company_id=$1 AND id=$2 RETURNING revision,status,submitted_at,completed_at`,[actor.companyId,id,status,submittedTimerSeconds])).rows[0];
        if(status==='completed')await maybeCompleteCourse(db,actor,id);
        await audit(db,actor,'assignment.submitted',{recipientID:id,definitionID:row.definition_id,details:{status}});
        await recordTrainingEvent(db,actor,{type:status==='completed'?'training.assignment_completed':'training.submission_pending_review',
          subjectType:'training_recipient',subjectID:id,key:`assignment:${id}:submitted:${updated.revision}`,
          payload:{recipient_id:id,employee_id:row.employee_id,definition_id:row.definition_id,status,revision:updated.revision}});
        return {id,...updated};});},
    async review(req,id,body){const expected=revision(body?.expected_revision),decision=string(body?.decision,40),feedback=string(body?.feedback??'',2000,{required:false});
      if(!['approve','request_corrections'].includes(decision))fail(400,'invalid_review_decision');if(decision==='request_corrections'&&!feedback)fail(400,'feedback_required');
      return trainingMutation(pool,req,['training.review'],async(db,actor)=>{const row=await recipientFor(db,actor,id,{lock:true});if(row.employee_id===actor.userId)fail(403,'self_review_forbidden');await requireSupervision(db,actor,row.employee_id);if(row.status!=='awaiting_review')fail(409,'not_awaiting_review');if(row.revision!==expected)fail(409,'stale_revision');
        if(row.kind==='quiz'){
          const attempt=(await db.query(`SELECT status,passed FROM training_quiz_attempts WHERE company_id=$1 AND recipient_id=$2 ORDER BY attempt_number DESC LIMIT 1`,[actor.companyId,row.id])).rows[0];
          if(!attempt||attempt.status!=='graded'||attempt.passed!==true)fail(409,'quiz_not_graded_or_passed');
        }
        const grading=reviewScores(row,decision,body?.scores);
        const status=decision==='approve'?'completed':'corrections_requested';const updated=(await db.query(`UPDATE training_recipients SET status=$3,completed_at=CASE WHEN $3='completed' THEN now() ELSE NULL END,
          score_points=$4,max_points=$5,revision=revision+1,updated_at=now()
          WHERE company_id=$1 AND id=$2 RETURNING revision,status,completed_at,score_points,max_points`,
        [actor.companyId,id,status,grading.scorePoints,grading.maxPoints])).rows[0];
        if(status==='completed')await maybeCompleteCourse(db,actor,id);
        await audit(db,actor,'assignment.reviewed',{recipientID:id,definitionID:row.definition_id,
          details:{decision,feedback,...(grading.scores?{scores:grading.scores,score_points:grading.scorePoints,max_points:grading.maxPoints}:{})}});
        await recordTrainingEvent(db,actor,{type:decision==='approve'?'training.submission_approved':'training.submission_corrections_requested',
          subjectType:'training_recipient',subjectID:id,key:`assignment:${id}:review:${updated.revision}`,
          payload:{recipient_id:id,employee_id:row.employee_id,definition_id:row.definition_id,status,revision:updated.revision,
            ...(grading.scores?{score_points:grading.scorePoints,max_points:grading.maxPoints}:{})}});
        return {id,...updated,feedback};});},
    async overrideCompletion(req,id,body){
      const expected=revision(body?.expected_revision),reason=string(body?.reason,2000);
      if(reason.length<15)fail(400,'override_reason_too_short');
      return trainingMutation(pool,req,['training.override'],async(db,actor)=>{const row=await recipientFor(db,actor,id,{lock:true});
        if(row.employee_id===actor.userId)fail(403,'self_review_forbidden');
        await requireSupervision(db,actor,row.employee_id);
        if(row.revision!==expected)fail(409,'stale_revision');
        if(row.status==='completed')fail(409,'assignment_completed');
        checkAvailability(row);await requirePrerequisites(db,actor,row);
        if(row.kind==='quiz'||row.document.blocks.some(block=>block.points!=null||
          ['linked_quiz','linked_lesson'].includes(block.type)&&block.required||block.type==='video'&&block.video.required))
          fail(409,'completion_override_not_permitted');
        let overriddenTimerSeconds=Number(row.timer_accumulated_seconds??0);
        if(row.timer_running_since){
          const serverNow=(await db.query(`SELECT clock_timestamp() AS now`)).rows[0].now;
          overriddenTimerSeconds=elapsedTimerSeconds(row,serverNow);
        }
        const updated=(await db.query(`UPDATE training_recipients SET status='completed',completed_at=now(),
          submitted_at=COALESCE(submitted_at,now()),timer_running_since=NULL,timer_accumulated_seconds=$3,
          revision=revision+1,updated_at=now()
          WHERE company_id=$1 AND id=$2 RETURNING revision,status,completed_at`,[actor.companyId,row.id,overriddenTimerSeconds])).rows[0];
        await maybeCompleteCourse(db,actor,row.id);
        await audit(db,actor,'assignment.completion_overridden',{recipientID:row.id,definitionID:row.definition_id,
          details:{reason,previous_status:row.status,revision:updated.revision}});
        await recordTrainingEvent(db,actor,{type:'training.assignment_completed',subjectType:'training_recipient',subjectID:row.id,
          key:`assignment:${row.id}:override:${updated.revision}`,payload:{recipient_id:row.id,employee_id:row.employee_id,
            definition_id:row.definition_id,status:'completed',revision:updated.revision,override:true}});
        return {id:row.id,...updated,reason};});},
    async listReviews(req,query){const actor=await actorFor(pool,req);requireTraining(actor,'training.review');const limit=Math.max(1,Math.min(100,Number(query?.limit)||50));
      const rows=(await pool.query(`SELECT r.id,r.employee_id,r.employee_name_snapshot,r.status,r.revision,r.submitted_at,a.due_at,v.title,v.kind
        FROM training_recipients r JOIN training_assignments a ON a.company_id=r.company_id AND a.id=r.assignment_id
        JOIN training_versions v ON v.company_id=a.company_id AND v.id=a.version_id
        WHERE r.company_id=$1 AND r.status='awaiting_review'
          AND ($3::boolean OR EXISTS (SELECT 1 FROM training_supervisor_grants g
            WHERE g.company_id=r.company_id AND g.supervisor_id=$4 AND g.employee_id=r.employee_id))
        ORDER BY r.submitted_at,r.id LIMIT $2`,[actor.companyId,limit,actor.isCompanyOwner,actor.userId])).rows;return {items:rows};},
    async listManaged(req,query){const actor=await actorFor(pool,req);requireTraining(actor,'training.review');
      const limit=Math.max(1,Math.min(100,Number(query?.limit)||50));
      const status=query?.status==null?null:string(query.status,40);
      if(status&&!['assigned','in_progress','awaiting_review','corrections_requested','completed'].includes(status))fail(400,'invalid_status');
      const search=query?.search==null?null:string(query.search,100,{required:false})||null;
      const scope=JSON.stringify(['managed',actor.companyId,actor.userId,status,search]);
      const cursor=listCursor(query?.cursor,scope);
      const rows=(await pool.query(`SELECT r.id,r.assignment_id,r.employee_id,r.employee_name_snapshot,r.status,r.revision,
          r.updated_at,r.updated_at AS cursor_at,r.completed_at,a.due_at,a.priority,v.title,v.kind,v.version_number
        FROM training_recipients r JOIN training_assignments a ON a.company_id=r.company_id AND a.id=r.assignment_id
        JOIN training_versions v ON v.company_id=a.company_id AND v.id=a.version_id
        WHERE r.company_id=$1 AND ($3::boolean OR EXISTS (SELECT 1 FROM training_supervisor_grants g
          WHERE g.company_id=r.company_id AND g.supervisor_id=$4 AND g.employee_id=r.employee_id))
          AND ($5::text IS NULL OR r.status=$5)
          AND ($6::text IS NULL OR v.title ILIKE '%'||$6||'%' OR r.employee_name_snapshot ILIKE '%'||$6||'%')
          AND ${afterCursor('r.updated_at',7,8,9)}
        ORDER BY a.due_at ASC NULLS LAST,r.updated_at DESC,r.id LIMIT $2`,
      [actor.companyId,limit+1,actor.isCompanyOwner,actor.userId,status,search,
        cursor?.due??null,cursor?.at??null,cursor?.id??null])).rows;
      return listPage(rows,limit,scope);},
    async history(req,id){const actor=await actorFor(pool,req);const row=await recipientFor(pool,actor,id);requireRecipientAccess(actor,row);if(actor.userId!==row.employee_id)await requireSupervision(pool,actor,row.employee_id);
      const events=(await pool.query(`SELECT actor_id,action,details,created_at FROM training_audit_events WHERE company_id=$1 AND recipient_id=$2 ORDER BY created_at,id`,[actor.companyId,row.id])).rows;
      return {items:events};},
    async eligibleRecipients(req){const actor=await actorFor(pool,req);requireTraining(actor,'training.assign');
      const rows=(await pool.query(`SELECT u.id,COALESCE(NULLIF(u.display_name,''),u.email) AS display_name,u.email
        FROM users u WHERE u.company_id=$1 AND u.deleted_at IS NULL
        AND ($2::boolean OR EXISTS (SELECT 1 FROM training_supervisor_grants g
          WHERE g.company_id=$1 AND g.supervisor_id=$3 AND g.employee_id=u.id))
        ORDER BY display_name,u.id LIMIT 500`,[actor.companyId,actor.isCompanyOwner,actor.userId])).rows;
      return {items:rows};},
    async listSupervision(req,supervisorID){const actor=await actorFor(pool,req);if(!actor.isCompanyOwner)fail(403,'owner_required');
      const target=uuid(supervisorID);
      const member=(await pool.query(`SELECT 1 FROM users WHERE company_id=$1 AND id=$2 AND deleted_at IS NULL`,[actor.companyId,target])).rowCount;
      if(!member)fail(404,'employee_not_found');
      const rows=(await pool.query(`SELECT u.id,u.display_name,u.email,(g.employee_id IS NOT NULL) AS supervised
        FROM users u LEFT JOIN training_supervisor_grants g ON g.company_id=u.company_id AND g.employee_id=u.id AND g.supervisor_id=$2
        WHERE u.company_id=$1 AND u.deleted_at IS NULL AND u.id<>$2 ORDER BY u.display_name,u.id`,[actor.companyId,target])).rows;
      return {items:rows};},
    async setSupervision(req,supervisorID,employeeID,enabled){if(typeof enabled!=='boolean')fail(400,'invalid_supervision');
      const supervisor=uuid(supervisorID),employee=uuid(employeeID);if(supervisor===employee)fail(400,'self_supervision_forbidden');
      return trainingMutation(pool,req,[],async(db,actor)=>{if(!actor.isCompanyOwner)fail(403,'owner_required');
        const members=(await db.query(`SELECT id FROM users WHERE company_id=$1 AND id=ANY($2::uuid[]) AND deleted_at IS NULL`,[actor.companyId,[supervisor,employee]])).rows;
        if(members.length!==2)fail(404,'employee_not_found');
        if(enabled)await db.query(`INSERT INTO training_supervisor_grants(company_id,supervisor_id,employee_id,granted_by)
          VALUES($1,$2,$3,$4) ON CONFLICT(company_id,supervisor_id,employee_id) DO NOTHING`,[actor.companyId,supervisor,employee,actor.userId]);
        else await db.query(`DELETE FROM training_supervisor_grants WHERE company_id=$1 AND supervisor_id=$2 AND employee_id=$3`,[actor.companyId,supervisor,employee]);
        await audit(db,actor,enabled?'supervision.granted':'supervision.revoked',{details:{supervisor_id:supervisor,employee_id:employee}});
        return {supervisor_id:supervisor,employee_id:employee,supervised:enabled};
      });}
  };
}
