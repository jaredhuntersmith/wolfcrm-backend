import {can} from '../company-comms/access.js';
import {fail} from './contract.js';

export const TRAINING_WIDGET_KINDS=Object.freeze([
  'training_my_assignments','training_due_today','training_overdue','training_pending_reviews',
  'training_progress','training_course_completion','training_recent_grades',
  'training_certifications','training_team_performance'
]);

const recipientSource=`FROM training_recipients r
  JOIN training_assignments a ON a.company_id=r.company_id AND a.id=r.assignment_id
  JOIN training_versions v ON v.company_id=a.company_id AND v.id=a.version_id
  WHERE r.company_id=$1 AND r.employee_id=$2
    AND NOT EXISTS (SELECT 1 FROM training_linked_runs linked
      WHERE linked.company_id=r.company_id AND linked.child_recipient_id=r.id)`;
const pending="r.status IN ('assigned','in_progress','corrections_requested')";
const reviewScope=`r.company_id=$1 AND r.employee_id<>$2 AND r.status='awaiting_review'
  AND ($3::boolean OR EXISTS (SELECT 1 FROM training_supervisor_grants grant_row
    WHERE grant_row.company_id=r.company_id AND grant_row.supervisor_id=$2
      AND grant_row.employee_id=r.employee_id))`;
const teamScope=`u.company_id=$1 AND u.id<>$2 AND u.deleted_at IS NULL
  AND ($3::boolean OR EXISTS (SELECT 1 FROM training_supervisor_grants grant_row
    WHERE grant_row.company_id=u.company_id AND grant_row.supervisor_id=$2
      AND grant_row.employee_id=u.id))`;

function unavailable(){return {state:'unavailable',reason:'Your role does not allow this module.',rows:[]};}
async function page(pool,sql,values,offset,recordID,{order='date DESC NULLS LAST,id'}={}){
  const result=(await pool.query(`WITH items AS (${sql}), selected AS (
    SELECT * FROM items WHERE ($${values.length+2}::text IS NULL OR id=$${values.length+2})
    ORDER BY ${order} LIMIT 50 OFFSET $${values.length+1}
  ) SELECT (SELECT count(*)::integer FROM items) AS count,
    COALESCE((SELECT jsonb_agg(to_jsonb(selected) ORDER BY ${order}) FROM selected),'[]'::jsonb) AS rows`,
  [...values,offset,recordID])).rows[0];
  return {count:result.count,rows:result.rows,
    nextOffset:!recordID&&offset+result.rows.length<result.count?offset+result.rows.length:null};
}
function ready(result,{value,badge,note}){return {state:'ready',...result,value,badge,note};}
function row(kind){return `SELECT r.id::text AS id,v.title AS title,
  (replace(r.status,'_',' ')||' · '||v.kind) AS subtitle,
  COALESCE(a.due_at,r.updated_at) AS date,'training_assignment' AS destination,
  r.id::text AS reference ${recipientSource} ${kind}`;}

// `actor` must come from the existing widget-dashboard loadActor, never request
// query parameters. The shared catalog owns slot validation and navigation.
export async function readTrainingWidget({pool,actor,kind,offset=0,recordID=null,now=new Date()}){
  if(!TRAINING_WIDGET_KINDS.includes(kind))return null;
  if(!Number.isSafeInteger(offset)||offset<0||offset>1000000||
    recordID!==null&&(typeof recordID!=='string'||recordID.length<1||recordID.length>160))
    fail(400,'invalid_training_widget_page');
  const instant=new Date(now);
  if(Number.isNaN(instant.getTime()))fail(400,'invalid_training_widget_time');
  const manager=kind==='training_pending_reviews'||kind==='training_team_performance';
  if(!can(actor,manager?(kind==='training_pending_reviews'?'training.review':'training.analytics'):'training.view_self'))
    return unavailable();
  const self=[actor.companyId,actor.userId];
  if(kind==='training_my_assignments'){
    const result=await page(pool,row("AND r.status<>'completed'"),self,offset,recordID);
    return ready(result,{value:String(result.count),badge:result.count,
      note:'Open recipient runs, including work awaiting review; linked child runs are counted through their parent.'});
  }
  if(kind==='training_due_today'){
    const sql=row(`AND ${pending} AND a.due_at IS NOT NULL AND
      (a.due_at AT TIME ZONE (SELECT COALESCE(NULLIF(to_jsonb(c)->>'timezone',''),'America/New_York')
        FROM companies c WHERE c.id=$1))::date =
      ($3::timestamptz AT TIME ZONE (SELECT COALESCE(NULLIF(to_jsonb(c)->>'timezone',''),'America/New_York')
        FROM companies c WHERE c.id=$1))::date`);
    const result=await page(pool,sql,[...self,instant],offset,recordID,{order:'date,id'});
    return ready(result,{value:String(result.count),badge:result.count,
      note:'Employee-actionable assignments with a nominal due date today in the company time zone.'});
  }
  if(kind==='training_overdue'){
    const result=await page(pool,row(`AND ${pending} AND a.due_at IS NOT NULL AND
      a.due_at+make_interval(secs => a.grace_seconds)<$3`),[...self,instant],offset,recordID,
    {order:'date,id'});
    return ready(result,{value:String(result.count),badge:result.count,
      note:'Employee-actionable assignments after due time plus configured grace; server clock.'});
  }
  if(kind==='training_pending_reviews'){
    const sql=`SELECT r.id::text AS id,v.title AS title,
      (r.employee_name_snapshot||' · awaiting review') AS subtitle,
      r.submitted_at AS date,'training_review' AS destination,r.id::text AS reference
      FROM training_recipients r
      JOIN training_assignments a ON a.company_id=r.company_id AND a.id=r.assignment_id
      JOIN training_versions v ON v.company_id=a.company_id AND v.id=a.version_id
      WHERE ${reviewScope}`;
    const result=await page(pool,sql,[actor.companyId,actor.userId,actor.isCompanyOwner],offset,recordID,
    {order:'date NULLS LAST,id'});
    return ready(result,{value:String(result.count),badge:result.count,
      note:'Current pending submissions from employees this manager may review; self review excluded.'});
  }
  if(kind==='training_progress'){
    const summary=(await pool.query(`SELECT count(*)::integer AS assigned,
      count(*) FILTER (WHERE r.status='completed')::integer AS completed ${recipientSource}`,self)).rows[0];
    const result=await page(pool,row(''),self,offset,recordID,{order:'date DESC NULLS LAST,id'});
    return ready(result,{value:`${summary.completed} / ${summary.assigned}`,
      badge:summary.assigned-summary.completed,
      note:'Completed recipient runs / all assigned recipient runs; linked child runs excluded.'});
  }
  if(kind==='training_course_completion'){
    const source=`FROM training_course_enrollments e
      JOIN training_course_versions v ON v.company_id=e.company_id AND v.id=e.version_id
      WHERE e.company_id=$1 AND e.employee_id=$2`;
    const summary=(await pool.query(`SELECT count(*)::integer AS enrolled,
      count(*) FILTER (WHERE e.completed_at IS NOT NULL)::integer AS completed ${source}`,self)).rows[0];
    const result=await page(pool,`SELECT e.id::text AS id,v.document->>'title' AS title,
      CASE WHEN e.completed_at IS NULL THEN 'In progress' ELSE 'Completed' END AS subtitle,
      COALESCE(e.completed_at,e.created_at) AS date,'training_course' AS destination,
      e.id::text AS reference ${source}`,self,offset,recordID);
    return ready(result,{value:`${summary.completed} / ${summary.enrolled}`,
      badge:summary.enrolled-summary.completed,
      note:'Completed course enrollments / all pinned course enrollments for this employee.'});
  }
  if(kind==='training_recent_grades'){
    const sql=`SELECT q.id::text AS id,v.title AS title,
      (round(100*q.total_points/NULLIF(q.max_points,0),1)::text||'% · '||
        CASE WHEN q.passed THEN 'Passed' ELSE 'Not passed' END) AS subtitle,
      q.graded_at AS date,'training_quiz_attempt' AS destination,
      r.id::text AS reference
      FROM training_quiz_attempts q
      JOIN training_recipients r ON r.company_id=q.company_id AND r.id=q.recipient_id
      JOIN training_versions v ON v.company_id=q.company_id AND v.id=q.version_id
      WHERE q.company_id=$1 AND r.employee_id=$2 AND q.status='graded' AND q.max_points>0
        AND (v.document->'quiz'->>'show_results'='immediate' OR
          v.document->'quiz'->>'show_results'='after_review' AND r.status<>'awaiting_review')`;
    const result=await page(pool,sql,self,offset,recordID);
    return ready(result,{value:String(result.count),badge:result.count,
      note:'Released graded quiz attempts; retakes count separately, unreleased results are hidden.'});
  }
  if(kind==='training_certifications'){
    const source=`FROM training_certificates c WHERE c.company_id=$1 AND c.employee_id=$2`;
    const valid=(await pool.query(`SELECT count(*)::integer AS count ${source}
      AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>$3)`,[...self,instant])).rows[0].count;
    const result=await page(pool,`SELECT c.id::text AS id,c.course_title_snapshot AS title,
      CASE WHEN c.revoked_at IS NOT NULL THEN 'Revoked'
        WHEN c.expires_at IS NOT NULL AND c.expires_at<=$3 THEN 'Expired'
        ELSE 'Valid' END AS subtitle,
      c.issued_at AS date,'training_certificate' AS destination,c.id::text AS reference
      ${source}`,[...self,instant],offset,recordID);
    return ready(result,{value:`${valid} valid`,badge:valid,
      note:'Valid company-issued certificates; list also shows expired and revoked records.'});
  }
  const members=`WITH members AS (
    SELECT u.id,COALESCE(NULLIF(u.display_name,''),u.email) AS name FROM users u
    WHERE ${teamScope}
  ), scored AS (
    SELECT members.id,members.name,count(r.id)::integer AS assigned,
      count(r.id) FILTER (WHERE r.status='completed')::integer AS completed
    FROM members LEFT JOIN training_recipients r ON r.company_id=$1 AND r.employee_id=members.id
      AND NOT EXISTS (SELECT 1 FROM training_linked_runs linked
        WHERE linked.company_id=r.company_id AND linked.child_recipient_id=r.id)
    GROUP BY members.id,members.name
  )`;
  const values=[actor.companyId,actor.userId,actor.isCompanyOwner];
  const summary=(await pool.query(`${members} SELECT COALESCE(sum(assigned),0)::integer AS assigned,
    COALESCE(sum(completed),0)::integer AS completed FROM scored`,values)).rows[0];
  const result=await page(pool,`${members} SELECT id::text AS id,name AS title,
    (completed::text||' / '||assigned::text||' complete') AS subtitle,
    NULL::timestamptz AS date,'training_team_analytics' AS destination,
    id::text AS reference FROM scored`,values,offset,recordID,{order:'title,id'});
  return ready(result,{value:`${summary.completed} / ${summary.assigned}`,
    badge:summary.assigned-summary.completed,
    note:'Completed / assigned recipient runs for the current active managed employee roster, excluding the manager and linked child runs.'});
}
