import {randomUUID} from 'node:crypto';
import {date,digest,fail,graceSeconds,string,uuid} from './contract.js';
import {flattenLessons,normalizeCourse} from './course-contract.js';
import {actorFor,createLinkedRuns,eligibleAssignees,requireSupervision,requireTraining,trainingMutation} from './service.js';
import {recordTrainingEvent} from './events.js';

function revision(value){if(!Number.isInteger(value)||value<1)fail(400,'invalid_revision');return value;}
function recipientIDs(value){if(!Array.isArray(value)||!value.length||value.length>100)fail(400,'invalid_recipients');return [...new Set(value.map(uuid))].sort();}
async function courseFor(db,actor,id,{lock=false}={}){
  const row=(await db.query(`SELECT * FROM training_courses WHERE company_id=$1 AND id=$2 ${lock?'FOR UPDATE':''}`,[actor.companyId,uuid(id)])).rows[0];
  if(!row)fail(404,'course_not_found');return row;
}
async function enrollmentFor(db,actor,id,{lock=false}={}){
  const row=(await db.query(`SELECT e.*,v.document,v.version_number FROM training_course_enrollments e
    JOIN training_course_versions v ON v.company_id=e.company_id AND v.id=e.version_id
    WHERE e.company_id=$1 AND e.id=$2 ${lock?'FOR UPDATE OF e':''}`,[actor.companyId,uuid(id)])).rows[0];
  if(!row)fail(404,'enrollment_not_found');return row;
}
async function requireEnrollmentAccess(db,actor,row){
  if(actor.userId===row.employee_id){requireTraining(actor,'training.view_self');return;}
  requireTraining(actor,'training.review');await requireSupervision(db,actor,row.employee_id);
}
async function progress(db,actor,row){
  const lessons=flattenLessons(row.document);
  const prerequisiteIDs=row.document.prerequisite_course_version_ids??[];
  const prerequisites=prerequisiteIDs.length?(await db.query(`SELECT v.id AS version_id,v.document->>'title' AS title,
      EXISTS (SELECT 1 FROM training_course_enrollments prior WHERE prior.company_id=v.company_id
        AND prior.employee_id=$3 AND prior.version_id=v.id AND prior.completed_at IS NOT NULL) AS completed
    FROM training_course_versions v WHERE v.company_id=$1 AND v.id=ANY($2::uuid[])`,
  [actor.companyId,prerequisiteIDs,row.employee_id])).rows:[];
  const prerequisiteByID=new Map(prerequisites.map(item=>[item.version_id,item]));
  const courseBlocked=prerequisiteIDs.some(id=>!prerequisiteByID.get(id)?.completed);
  const runs=(await db.query(`SELECT lr.lesson_id,lr.recipient_id,r.status,r.completed_at
    FROM training_course_lesson_runs lr JOIN training_recipients r ON r.company_id=lr.company_id AND r.id=lr.recipient_id
    WHERE lr.company_id=$1 AND lr.enrollment_id=$2`,[actor.companyId,row.id])).rows;
  const byID=new Map(runs.map(run=>[run.lesson_id,run]));
  const completed=new Set(runs.filter(run=>run.status==='completed').map(run=>run.lesson_id));
  const now=Date.now(),available=new Date(row.available_at).getTime()<=now&&(!row.expires_at||new Date(row.expires_at).getTime()>=now);
  const items=lessons.map((lesson,index)=>{
    const run=byID.get(lesson.id);
    const prereqsMet=lesson.prerequisites.every(id=>completed.has(id));
    const sequentialMet=row.document.progression!=='sequential'||lessons.slice(0,index).filter(item=>item.required).every(item=>completed.has(item.id));
    return {id:lesson.id,title:lesson.title,module_id:lesson.module_id,module_title:lesson.module_title,
      definition_id:lesson.definition_id,version_id:lesson.version_id,required:lesson.required,ordinal:lesson.ordinal,
      prerequisites:lesson.prerequisites,recipient_id:run?.recipient_id??null,status:run?.status??'not_started',
      unlocked:!!run||available&&!courseBlocked&&prereqsMet&&sequentialMet};
  });
  const required=items.filter(item=>item.required),done=required.filter(item=>item.status==='completed').length;
  return {id:row.id,course_id:row.course_id,version_id:row.version_id,version_number:row.version_number,
    title:row.document.title,description:row.document.description,cover_file_id:row.document.cover_file_id,
    modules:row.document.modules.map(module=>({id:module.id,title:module.title})),
    progression:row.document.progression,employee_id:row.employee_id,employee_name:row.employee_name_snapshot,
    prerequisite_courses:prerequisiteIDs.map(id=>prerequisiteByID.get(id)??{version_id:id,title:'Required course',completed:false}),
    prerequisites_blocked:courseBlocked,
    available_at:row.available_at,due_at:row.due_at,expires_at:row.expires_at,grace_seconds:row.grace_seconds,
    effective_due_at:row.due_at?new Date(new Date(row.due_at).getTime()+row.grace_seconds*1000).toISOString():null,
    completed_at:row.completed_at,
    completed_required:done,total_required:required.length,lessons:items};
}

export function createCourseService({pool}){
  return {
    async validate(req,body){const actor=await actorFor(pool,req);requireTraining(actor,'training.author');return {document:normalizeCourse(body)};},
    async create(req,body){const document=normalizeCourse(body),id=randomUUID();
      return trainingMutation(pool,req,['training.author'],async(db,actor)=>{
        await db.query(`INSERT INTO training_courses(id,company_id,created_by,title,draft) VALUES($1,$2,$3,$4,$5)`,
          [id,actor.companyId,actor.userId,document.title,JSON.stringify(document)]);return {id,revision:1,draft:document};});},
    async list(req){const actor=await actorFor(pool,req);requireTraining(actor,'training.author');
      return {items:(await pool.query(`SELECT id,title,draft_revision,latest_version,updated_at FROM training_courses
        WHERE company_id=$1 AND archived_at IS NULL ORDER BY updated_at DESC,id LIMIT 100`,[actor.companyId])).rows};},
    async versionOptions(req){const actor=await actorFor(pool,req);requireTraining(actor,'training.author');
      const rows=(await pool.query(`SELECT DISTINCT ON (v.course_id) v.course_id,v.id AS version_id,
        v.version_number,v.document->>'title' AS title
        FROM training_course_versions v WHERE v.company_id=$1
        ORDER BY v.course_id,v.version_number DESC LIMIT 200`,[actor.companyId])).rows;
      return {items:rows.sort((a,b)=>a.title.localeCompare(b.title))};},
    async get(req,id){const actor=await actorFor(pool,req);requireTraining(actor,'training.author');const row=await courseFor(pool,actor,id);
      return {id:row.id,revision:row.draft_revision,latest_version:row.latest_version,draft:row.draft};},
    async update(req,id,body){const document=normalizeCourse(body),expected=revision(body.expected_revision);
      return trainingMutation(pool,req,['training.author'],async(db,actor)=>{const row=await courseFor(db,actor,id,{lock:true});if(row.created_by!==actor.userId&&!actor.isCompanyOwner)fail(403,'author_only');
        if(row.archived_at)fail(409,'course_archived');if(row.draft_revision!==expected)fail(409,'stale_revision');
        const updated=(await db.query(`UPDATE training_courses SET draft=$3,title=$4,draft_revision=draft_revision+1,updated_at=now()
          WHERE company_id=$1 AND id=$2 RETURNING draft_revision`,[actor.companyId,id,JSON.stringify(document),document.title])).rows[0];
        return {id,revision:updated.draft_revision,draft:document};});},
    async publish(req,id,body){const expected=revision(body?.expected_revision);
      return trainingMutation(pool,req,['training.publish'],async(db,actor)=>{
        const row=await courseFor(db,actor,id,{lock:true});if(row.archived_at)fail(409,'course_archived');if(row.draft_revision!==expected)fail(409,'stale_revision');
        const document=normalizeCourse(row.draft),lessons=flattenLessons(document),versions=await db.query(`SELECT v.id,v.definition_id
          FROM training_versions v JOIN training_definitions d ON d.company_id=v.company_id AND d.id=v.definition_id
          WHERE v.company_id=$1 AND v.id=ANY($2::uuid[]) AND (d.scope='company' OR d.created_by=$3)`,
        [actor.companyId,lessons.map(lesson=>lesson.version_id),actor.userId]);
        const byVersion=new Map(versions.rows.map(version=>[version.id,version.definition_id]));
        for(const lesson of lessons)if(byVersion.get(lesson.version_id)!==lesson.definition_id)fail(409,'lesson_version_unavailable');
        if(document.prerequisite_course_version_ids.length){
          const earlier=(await db.query(`SELECT id,course_id FROM training_course_versions
            WHERE company_id=$1 AND id=ANY($2::uuid[])`,[actor.companyId,document.prerequisite_course_version_ids])).rows;
          if(earlier.length!==document.prerequisite_course_version_ids.length||earlier.some(item=>item.course_id===row.id))
            fail(409,'course_prerequisite_unavailable');
        }
        let coverRef=null;
        if(document.cover_file_id){coverRef=(await db.query(`SELECT cr.file_id,cr.created_by FROM training_course_asset_refs cr
          JOIN stored_files f ON f.id=cr.file_id AND f.company_id=cr.company_id
          WHERE cr.company_id=$1 AND cr.course_id=$2 AND cr.file_id=$3 AND f.source_scope='training'
            AND f.source_protected AND f.visibility='private' AND f.cloud_status='active'`,
          [actor.companyId,row.id,document.cover_file_id])).rows[0];
          if(!coverRef)fail(409,'course_cover_unavailable');}
        if(row.latest_version){const latest=(await db.query(`SELECT content_sha256 FROM training_course_versions WHERE company_id=$1 AND course_id=$2 AND version_number=$3`,[actor.companyId,id,row.latest_version])).rows[0];
          if(latest?.content_sha256===digest(document))fail(409,'unchanged_course');}
        const versionID=randomUUID(),next=row.latest_version+1;
        await db.query(`INSERT INTO training_course_versions(id,company_id,course_id,version_number,document,content_sha256,published_by)
          VALUES($1,$2,$3,$4,$5,$6,$7)`,[versionID,actor.companyId,id,next,JSON.stringify(document),digest(document),actor.userId]);
        if(coverRef)await db.query(`INSERT INTO training_course_asset_refs(id,company_id,file_id,created_by,version_id)
          VALUES($1,$2,$3,$4,$5)`,[randomUUID(),actor.companyId,coverRef.file_id,coverRef.created_by,versionID]);
        await db.query(`UPDATE training_courses SET latest_version=$3,updated_at=now() WHERE company_id=$1 AND id=$2`,[actor.companyId,id,next]);
        return {id:versionID,course_id:id,version_number:next,content_sha256:digest(document),document};});},
    async assign(req,body){const courseID=uuid(body?.course_id),ids=recipientIDs(body?.recipient_ids),key=string(body?.request_key,120);
      const availableAt=date(body?.available_at)||new Date().toISOString(),dueAt=date(body?.due_at),expiresAt=date(body?.expires_at);
      const grace=graceSeconds(body?.grace_seconds);
      if(grace&&!dueAt)fail(400,'grace_requires_due_date');
      if(dueAt&&dueAt<availableAt||expiresAt&&expiresAt<availableAt)fail(400,'invalid_date_range');
      return trainingMutation(pool,req,['training.assign'],async(db,actor)=>{await db.query(`SELECT pg_advisory_xact_lock(hashtext($1))`,[`course:${actor.companyId}:${actor.userId}:${key}`]);
        const course=await courseFor(db,actor,courseID);if(course.archived_at)fail(409,'course_archived');
        const versionID=body?.version_id?uuid(body.version_id):(await db.query(`SELECT id FROM training_course_versions WHERE company_id=$1 AND course_id=$2 AND version_number=$3`,[actor.companyId,courseID,course.latest_version])).rows[0]?.id;
        if(!versionID)fail(409,'course_unpublished');
        const version=(await db.query(`SELECT id FROM training_course_versions WHERE company_id=$1 AND course_id=$2 AND id=$3`,[actor.companyId,courseID,versionID])).rows[0];
        if(!version)fail(404,'course_version_not_found');
        const users=await eligibleAssignees(db,actor,ids),hash=digest({courseID,versionID,ids,availableAt:body?.available_at?availableAt:null,dueAt,expiresAt,
          ...(grace?{graceSeconds:grace}:{})});
        const existing=(await db.query(`SELECT employee_id,input_sha256,id FROM training_course_enrollments
          WHERE company_id=$1 AND assigned_by=$2 AND request_key=$3`,[actor.companyId,actor.userId,key])).rows;
        if(existing.length){if(existing.length!==ids.length||existing.some(item=>item.input_sha256!==hash||!ids.includes(item.employee_id)))fail(409,'request_key_conflict');
          return {enrollment_ids:existing.map(item=>item.id),recipient_count:ids.length,version_id:versionID};}
        const enrollmentIDs=[];
        for(const user of users){const id=randomUUID();enrollmentIDs.push(id);
          await db.query(`INSERT INTO training_course_enrollments(id,company_id,course_id,version_id,employee_id,employee_name_snapshot,assigned_by,request_key,input_sha256,available_at,due_at,expires_at,grace_seconds)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,[id,actor.companyId,courseID,versionID,user.id,user.name,actor.userId,key,hash,availableAt,dueAt,expiresAt,grace]);
          const effectiveDueAt=dueAt?new Date(new Date(dueAt).getTime()+grace*1000).toISOString():null;
          await recordTrainingEvent(db,actor,{type:'training.course_assigned',subjectType:'training_course_enrollment',subjectID:id,
            key:`course:${id}:assigned`,payload:{enrollment_id:id,employee_id:user.id,course_id:courseID,version_id:versionID,
              due_at:dueAt,grace_seconds:grace,effective_due_at:effectiveDueAt}});}
        return {enrollment_ids:enrollmentIDs,recipient_count:ids.length,version_id:versionID};});},
    async mine(req){const actor=await actorFor(pool,req);requireTraining(actor,'training.view_self');
      const rows=(await pool.query(`SELECT e.*,v.document,v.version_number FROM training_course_enrollments e
        JOIN training_course_versions v ON v.company_id=e.company_id AND v.id=e.version_id
        WHERE e.company_id=$1 AND e.employee_id=$2 ORDER BY e.created_at DESC LIMIT 100`,[actor.companyId,actor.userId])).rows;
      return {items:await Promise.all(rows.map(row=>progress(pool,actor,row)))};},
    async enrollment(req,id){const actor=await actorFor(pool,req),row=await enrollmentFor(pool,actor,id);await requireEnrollmentAccess(pool,actor,row);return progress(pool,actor,row);},
    async startLesson(req,enrollmentID,lessonID){const selected=string(lessonID,80);
      return trainingMutation(pool,req,['training.view_self'],async(db,actor)=>{const row=await enrollmentFor(db,actor,enrollmentID,{lock:true});if(row.employee_id!==actor.userId)fail(403,'recipient_only');
        const state=await progress(db,actor,row),lesson=state.lessons.find(item=>item.id===selected);if(!lesson)fail(404,'lesson_not_found');
        if(lesson.recipient_id)return {recipient_id:lesson.recipient_id,enrollment_id:row.id,lesson_id:selected};
        if(!lesson.unlocked)fail(409,'lesson_locked');
        const assignmentID=randomUUID(),recipientID=randomUUID(),requestKey=`course:${row.id}:${selected}`;
        await db.query(`INSERT INTO training_assignments(id,company_id,definition_id,version_id,assigned_by,request_key,input_sha256,available_at,due_at,expires_at,grace_seconds)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,[assignmentID,actor.companyId,lesson.definition_id,lesson.version_id,row.assigned_by,requestKey,digest({enrollment_id:row.id,lesson_id:selected}),row.available_at,row.due_at,row.expires_at,row.grace_seconds]);
        await db.query(`INSERT INTO training_recipients(id,company_id,assignment_id,employee_id,employee_name_snapshot)
          VALUES($1,$2,$3,$4,$5)`,[recipientID,actor.companyId,assignmentID,row.employee_id,row.employee_name_snapshot]);
        await db.query(`INSERT INTO training_course_lesson_runs(company_id,enrollment_id,lesson_id,recipient_id)
          VALUES($1,$2,$3,$4)`,[actor.companyId,row.id,selected,recipientID]);
        const document=(await db.query(`SELECT document FROM training_versions WHERE company_id=$1 AND id=$2`,
          [actor.companyId,lesson.version_id])).rows[0].document;
        await createLinkedRuns(db,actor,{assignmentID,document,recipients:[{id:recipientID,employee_id:row.employee_id,
          employee_name_snapshot:row.employee_name_snapshot}],assignedBy:row.assigned_by,
          availableAt:row.available_at,dueAt:row.due_at,expiresAt:row.expires_at,grace:row.grace_seconds});
        return {recipient_id:recipientID,enrollment_id:row.id,lesson_id:selected};});}
  };
}
