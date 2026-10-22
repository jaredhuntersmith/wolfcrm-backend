import {randomUUID} from 'node:crypto';
import {transact} from '../company-comms/access.js';
import {digest,fail,string,uuid} from './contract.js';
import {actorFor,assignRow,audit,requireTraining,trainingMutation} from './service.js';
import {recordTrainingEvent} from './events.js';

function owner(actor){requireTraining(actor,'training.assign');if(!actor.isCompanyOwner)fail(403,'owner_required');}
function days(value){if(!Number.isInteger(value)||value<0||value>365)fail(400,'invalid_due_after_days');return value;}

export function createOnboardingService({pool}){
  return {
    async list(req){const actor=await actorFor(pool,req);owner(actor);
      const rows=(await pool.query(`SELECT p.id,p.definition_id,p.version_id,p.course_id,p.course_version_id,
          p.due_after_days,p.active,p.created_at,p.disabled_at,COALESCE(v.title,cv.document->>'title') AS title
        FROM training_onboarding_policies p
        LEFT JOIN training_versions v ON v.company_id=p.company_id AND v.id=p.version_id
        LEFT JOIN training_course_versions cv ON cv.company_id=p.company_id AND cv.id=p.course_version_id
        WHERE p.company_id=$1 ORDER BY p.created_at DESC,p.id LIMIT 100`,[actor.companyId])).rows;
      return {items:rows};},
    async create(req,body){
      if((body?.definition_id==null)===(body?.course_id==null))fail(400,'invalid_onboarding_target');
      if(body?.course_id!=null&&body?.version_id!=null||body?.definition_id!=null&&body?.course_version_id!=null)fail(400,'invalid_onboarding_target');
      const definitionID=body?.definition_id==null?null:uuid(body.definition_id),courseID=body?.course_id==null?null:uuid(body.course_id);
      const dueAfter=days(body?.due_after_days),key=string(body?.request_key,120);
      const requestedVersion=body?.version_id?uuid(body.version_id):null;
      const requestedCourseVersion=body?.course_version_id?uuid(body.course_version_id):null;
      const inputHash=courseID?digest({courseID,dueAfter,requestedCourseVersion}):digest({definitionID,dueAfter,requestedVersion});
      return trainingMutation(pool,req,['training.assign'],async(db,actor)=>{owner(actor);
        await db.query(`SELECT pg_advisory_xact_lock(hashtext($1))`,[`${actor.companyId}:${actor.userId}:onboarding:${key}`]);
        const prior=(await db.query(`SELECT id,definition_id,version_id,course_id,course_version_id,due_after_days,active,created_at,input_sha256
          FROM training_onboarding_policies WHERE company_id=$1 AND created_by=$2 AND request_key=$3`,
          [actor.companyId,actor.userId,key])).rows[0];
        if(prior){if(prior.input_sha256!==inputHash)fail(409,'request_key_conflict');delete prior.input_sha256;return prior;}
        let versionID=null,courseVersionID=null;
        if(courseID){
          const course=(await db.query(`SELECT id,latest_version FROM training_courses
            WHERE company_id=$1 AND id=$2 AND archived_at IS NULL`,[actor.companyId,courseID])).rows[0];
          if(!course)fail(404,'course_not_found');
          courseVersionID=requestedCourseVersion??(await db.query(`SELECT id FROM training_course_versions
            WHERE company_id=$1 AND course_id=$2 AND version_number=$3`,[actor.companyId,courseID,course.latest_version])).rows[0]?.id;
          if(!courseVersionID)fail(409,'course_unpublished');
          if(!(await db.query(`SELECT 1 FROM training_course_versions WHERE company_id=$1 AND course_id=$2 AND id=$3`,
            [actor.companyId,courseID,courseVersionID])).rowCount)fail(404,'course_version_not_found');
        }else{
          const definition=(await db.query(`SELECT id,latest_version FROM training_definitions
            WHERE company_id=$1 AND id=$2 AND archived_at IS NULL AND (scope='company' OR created_by=$3)`,
          [actor.companyId,definitionID,actor.userId])).rows[0];
          if(!definition)fail(404,'definition_not_found');
          versionID=requestedVersion??
            (await db.query(`SELECT id FROM training_versions WHERE company_id=$1 AND definition_id=$2 AND version_number=$3`,
              [actor.companyId,definitionID,definition.latest_version])).rows[0]?.id;
          if(!versionID)fail(409,'definition_unpublished');
          if(!(await db.query(`SELECT 1 FROM training_versions WHERE company_id=$1 AND definition_id=$2 AND id=$3`,
            [actor.companyId,definitionID,versionID])).rowCount)fail(404,'version_not_found');
        }
        const id=randomUUID();
        const row=(await db.query(`INSERT INTO training_onboarding_policies
          (id,company_id,definition_id,version_id,course_id,course_version_id,created_by,request_key,input_sha256,due_after_days)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
          RETURNING id,definition_id,version_id,course_id,course_version_id,due_after_days,active,created_at`,
          [id,actor.companyId,definitionID,versionID,courseID,courseVersionID,actor.userId,key,inputHash,dueAfter])).rows[0];
        await audit(db,actor,'onboarding.policy_created',{definitionID,details:{policy_id:id,version_id:versionID,course_id:courseID,
          course_version_id:courseVersionID,due_after_days:dueAfter}});
        return row;
      });},
    async disable(req,id){const policyID=uuid(id);
      return trainingMutation(pool,req,['training.assign'],async(db,actor)=>{owner(actor);
        const row=(await db.query(`UPDATE training_onboarding_policies SET active=false,disabled_at=COALESCE(disabled_at,now())
          WHERE company_id=$1 AND id=$2 RETURNING id,definition_id,version_id,course_id,course_version_id,
            due_after_days,active,created_at,disabled_at`,[actor.companyId,policyID])).rows[0];
        if(!row)fail(404,'onboarding_policy_not_found');
        await audit(db,actor,'onboarding.policy_disabled',{definitionID:row.definition_id,details:{policy_id:policyID}});
        return row;
      });}
  };
}

// Call from the existing employee-created/joined event path and a bounded retry job.
// Each occurrence has its own assignment/version snapshot and employee deadline.
export async function enrollNewTrainingEmployee(pool,{companyId,userId,eligibleAt=null}){
  const companyID=uuid(companyId),employeeID=uuid(userId);
  return transact(pool,async db=>{
    const employee=(await db.query(`SELECT id,created_at FROM users
      WHERE company_id=$1 AND id=$2 AND role='employee' AND deleted_at IS NULL`,[companyID,employeeID])).rows[0];
    if(!employee)return {enrolled:0};
    if(eligibleAt!=null){
      const occurred=new Date(eligibleAt);
      if(Number.isNaN(occurred.getTime())||occurred.getTime()>Date.now()+300000)fail(400,'invalid_eligibility_time');
      await db.query(`INSERT INTO training_employee_eligibility(company_id,employee_id,eligible_at)
        VALUES($1,$2,$3) ON CONFLICT(company_id,employee_id)
        DO UPDATE SET eligible_at=GREATEST(training_employee_eligibility.eligible_at,EXCLUDED.eligible_at)`,
        [companyID,employeeID,occurred.toISOString()]);
    }
    const recorded=(await db.query(`SELECT eligible_at FROM training_employee_eligibility
      WHERE company_id=$1 AND employee_id=$2`,[companyID,employeeID])).rows[0];
    const effectiveAt=new Date(Math.max(new Date(employee.created_at).getTime(),
      recorded?new Date(recorded.eligible_at).getTime():0));
    const sponsor=(await db.query(`SELECT u.id FROM companies c JOIN users u ON u.id=c.owner_user_id
      WHERE c.id=$1 AND u.company_id=$1 AND u.deleted_at IS NULL`,[companyID])).rows[0];
    if(!sponsor)throw new Error('training_onboarding_owner_unavailable');
    const actor={companyId:companyID,userId:sponsor.id,isCompanyOwner:true};
    const policies=(await db.query(`SELECT p.* FROM training_onboarding_policies p
      WHERE p.company_id=$1 AND p.active AND p.created_at<=$2
      ORDER BY p.created_at,p.id FOR UPDATE`,[companyID,effectiveAt])).rows;
    let enrolled=0;
    for(const policy of policies){
      const prior=(await db.query(`SELECT assignment_id,course_enrollment_id FROM training_onboarding_enrollments
        WHERE company_id=$1 AND policy_id=$2 AND employee_id=$3`,[companyID,policy.id,employeeID])).rows[0];
      if(prior)continue;
      const availableAt=effectiveAt.toISOString();
      const dueAt=new Date(effectiveAt.getTime()+policy.due_after_days*86400000).toISOString();
      const key=`onboarding:${policy.id}:${employeeID}`;
      let assignmentID=null,courseEnrollmentID=null;
      if(policy.course_id){
        const name=(await db.query(`SELECT COALESCE(NULLIF(display_name,''),email) AS name FROM users
          WHERE company_id=$1 AND id=$2`,[companyID,employeeID])).rows[0].name;
        courseEnrollmentID=randomUUID();
        const inputHash=digest({policyID:policy.id,employeeID,courseVersionID:policy.course_version_id,availableAt,dueAt});
        await db.query(`INSERT INTO training_course_enrollments
          (id,company_id,course_id,version_id,employee_id,employee_name_snapshot,assigned_by,request_key,input_sha256,available_at,due_at)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,[courseEnrollmentID,companyID,policy.course_id,policy.course_version_id,
          employeeID,name,actor.userId,key,inputHash,availableAt,dueAt]);
        await recordTrainingEvent(db,actor,{type:'training.course_assigned',subjectType:'training_course_enrollment',subjectID:courseEnrollmentID,
          key:`course:${courseEnrollmentID}:assigned`,payload:{enrollment_id:courseEnrollmentID,employee_id:employeeID,
            course_id:policy.course_id,version_id:policy.course_version_id,due_at:dueAt}});
      }else{
        const inputHash=digest({policyID:policy.id,employeeID,versionID:policy.version_id,availableAt,dueAt});
        const assignment=await assignRow(db,actor,{definitionID:policy.definition_id,versionID:policy.version_id,
          recipientIDs:[employeeID],availableAt,dueAt,expiresAt:null,key,inputHash});
        assignmentID=assignment.id;
      }
      await db.query(`INSERT INTO training_onboarding_enrollments(company_id,policy_id,employee_id,assignment_id,course_enrollment_id)
        VALUES($1,$2,$3,$4,$5) ON CONFLICT(company_id,policy_id,employee_id) DO NOTHING`,
        [companyID,policy.id,employeeID,assignmentID,courseEnrollmentID]);
      await audit(db,actor,'onboarding.employee_enrolled',{definitionID:policy.definition_id,
        details:{policy_id:policy.id,assignment_id:assignmentID,course_enrollment_id:courseEnrollmentID,employee_id:employeeID}});
      enrolled++;
    }
    return {enrolled};
  });
}

export async function reconcileTrainingOnboarding(pool,{limit=100}={}){
  const batch=Math.max(1,Math.min(100,Number(limit)||100));
  const rows=(await pool.query(`SELECT DISTINCT p.company_id,u.id AS user_id
    FROM training_onboarding_policies p JOIN users u ON u.company_id=p.company_id
      AND u.role='employee' AND u.deleted_at IS NULL
    LEFT JOIN training_employee_eligibility g ON g.company_id=u.company_id AND g.employee_id=u.id
    LEFT JOIN training_onboarding_enrollments e ON e.company_id=p.company_id AND e.policy_id=p.id AND e.employee_id=u.id
    WHERE p.active AND GREATEST(u.created_at,COALESCE(g.eligible_at,u.created_at))>=p.created_at
      AND e.employee_id IS NULL ORDER BY p.company_id,u.id LIMIT $1`,[batch])).rows;
  let enrolled=0;
  for(const row of rows)enrolled+=(await enrollNewTrainingEmployee(pool,{companyId:row.company_id,userId:row.user_id})).enrolled;
  return {employees:rows.length,enrolled};
}
