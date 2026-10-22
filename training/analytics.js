import {date,fail,string,uuid} from './contract.js';
import {actorFor,requireSupervision,requireTraining} from './service.js';
import {hasCapability} from '../permissions.js';

function integer(row,key){return Number(row?.[key]??0);}
export async function trainingAnalyticsFilters(pool,req){
  const actor=await actorFor(pool,req);
  if(!actor.isCompanyOwner&&!hasCapability(actor,'training.analytics')){
    requireTraining(actor,'training.view_self');
    const courses=(await pool.query(`SELECT DISTINCT c.id,c.title FROM training_course_enrollments e
      JOIN training_courses c ON c.company_id=e.company_id AND c.id=e.course_id
      WHERE e.company_id=$1 AND e.employee_id=$2 ORDER BY c.title,c.id LIMIT 200`,
    [actor.companyId,actor.userId])).rows;
    return {employees:[],groups:[],courses,team_filter:'Current group membership; historical assignment recipients are retained independently.'};
  }
  const args=[actor.companyId,actor.userId,actor.isCompanyOwner];
  const employees=(await pool.query(`SELECT u.id,COALESCE(NULLIF(u.display_name,''),u.email) AS name
    FROM users u WHERE u.company_id=$1 AND u.deleted_at IS NULL AND
      ($3::boolean OR EXISTS (SELECT 1 FROM training_supervisor_grants g
        WHERE g.company_id=u.company_id AND g.supervisor_id=$2 AND g.employee_id=u.id))
    ORDER BY name,u.id LIMIT 500`,args)).rows;
  const groups=(await pool.query(`SELECT DISTINCT g.id,g.name,g.kind FROM training_audience_groups g
    JOIN training_audience_members m ON m.company_id=g.company_id AND m.group_id=g.id
    WHERE g.company_id=$1 AND g.archived_at IS NULL AND
      ($3::boolean OR EXISTS (SELECT 1 FROM training_supervisor_grants s
        WHERE s.company_id=m.company_id AND s.supervisor_id=$2 AND s.employee_id=m.employee_id))
    ORDER BY g.name,g.id LIMIT 200`,args)).rows;
  const courses=(await pool.query(`SELECT DISTINCT c.id,c.title FROM training_course_enrollments e
    JOIN training_courses c ON c.company_id=e.company_id AND c.id=e.course_id
    WHERE e.company_id=$1 AND ($3::boolean OR EXISTS (SELECT 1 FROM training_supervisor_grants s
      WHERE s.company_id=e.company_id AND s.supervisor_id=$2 AND s.employee_id=e.employee_id))
    ORDER BY title,c.id LIMIT 200`,args)).rows;
  return {employees,groups,courses,team_filter:'Current group membership; historical assignment recipients are retained independently.'};
}
export async function trainingAnalytics(pool,req,query){
  const actor=await actorFor(pool,req),scope=query?.scope??'self';
  if(!['self','managed'].includes(scope))fail(400,'invalid_analytics_scope');
  if(scope==='self')requireTraining(actor,'training.view_self');else requireTraining(actor,'training.analytics');
  const employeeID=query?.employee_id?uuid(query.employee_id):null;
  if(employeeID){const member=(await pool.query(`SELECT 1 FROM users WHERE company_id=$1 AND id=$2 AND deleted_at IS NULL`,[actor.companyId,employeeID])).rowCount;
    if(!member)fail(404,'employee_not_found');}
  if(employeeID&&employeeID!==actor.userId){requireTraining(actor,'training.analytics');await requireSupervision(pool,actor,employeeID);}
  if(scope==='self'&&employeeID&&employeeID!==actor.userId)fail(403,'recipient_scope_denied');
  const kind=query?.kind?string(query.kind,30):null;
  if(kind&&!['task','checklist','form','inspection','quiz'].includes(kind))fail(400,'invalid_analytics_kind');
  const courseID=query?.course_id?uuid(query.course_id):null;
  const groupID=query?.group_id?uuid(query.group_id):null;
  if(groupID){
    if(scope!=='managed')fail(403,'group_filter_requires_managed_scope');
    const group=(await pool.query(`SELECT 1 FROM training_audience_groups g WHERE g.company_id=$1 AND g.id=$2
      AND g.archived_at IS NULL AND ($3::boolean OR EXISTS (SELECT 1 FROM training_audience_members m
        JOIN training_supervisor_grants s ON s.company_id=m.company_id AND s.employee_id=m.employee_id
        WHERE m.company_id=g.company_id AND m.group_id=g.id AND s.supervisor_id=$4))`,
    [actor.companyId,groupID,actor.isCompanyOwner,actor.userId])).rowCount;
    if(!group)fail(404,'group_not_found');
  }
  const from=date(query?.from),to=date(query?.to);
  if(from&&to&&from>to)fail(400,'invalid_date_range');
  const target=scope==='self'?actor.userId:employeeID;
  const args=[actor.companyId,actor.userId,actor.isCompanyOwner,target,kind,from,to,courseID,groupID];
  const base=`FROM training_recipients r
    JOIN training_assignments a ON a.company_id=r.company_id AND a.id=r.assignment_id
    JOIN training_versions v ON v.company_id=a.company_id AND v.id=a.version_id
    WHERE r.company_id=$1
      AND NOT EXISTS (SELECT 1 FROM training_linked_runs linked
        WHERE linked.company_id=r.company_id AND linked.child_recipient_id=r.id)
      AND ($4::uuid IS NULL OR r.employee_id=$4)
      AND ($5::text IS NULL OR v.kind=$5)
      AND ($6::timestamptz IS NULL OR r.created_at >= $6)
      AND ($7::timestamptz IS NULL OR r.created_at <= $7)
      AND ($8::uuid IS NULL OR EXISTS (
        SELECT 1 FROM training_course_lesson_runs lr
        JOIN training_course_enrollments ce ON ce.company_id=lr.company_id AND ce.id=lr.enrollment_id
        WHERE lr.company_id=r.company_id AND lr.recipient_id=r.id AND ce.course_id=$8))
      AND ($9::uuid IS NULL OR EXISTS (SELECT 1 FROM training_audience_members m
        WHERE m.company_id=r.company_id AND m.group_id=$9 AND m.employee_id=r.employee_id))
      AND ($4::uuid IS NOT NULL OR $3::boolean OR EXISTS (
        SELECT 1 FROM training_supervisor_grants g WHERE g.company_id=r.company_id AND g.supervisor_id=$2 AND g.employee_id=r.employee_id))`;
  const totals=(await pool.query(`SELECT count(*)::integer AS assigned,
    count(*) FILTER (WHERE r.status='completed')::integer AS completed,
    count(*) FILTER (WHERE r.status<>'completed' AND a.due_at IS NOT NULL
      AND a.due_at+make_interval(secs => a.grace_seconds)<now())::integer AS overdue,
    count(*) FILTER (WHERE r.status='awaiting_review')::integer AS pending_review,
    count(*) FILTER (WHERE r.status='completed' AND a.due_at IS NOT NULL
      AND r.completed_at<=a.due_at+make_interval(secs => a.grace_seconds))::integer AS on_time,
    count(*) FILTER (WHERE r.status='completed' AND a.due_at IS NOT NULL)::integer AS completed_with_due
    ${base}` ,args)).rows[0];
  const quiz=(await pool.query(`SELECT count(*)::integer AS attempts,
    count(*) FILTER (WHERE q.status='graded')::integer AS graded,
    count(*) FILTER (WHERE q.status='graded' AND q.passed=true)::integer AS passed,
    count(*) FILTER (WHERE q.status='graded' AND q.passed=false)::integer AS failed,
    round(avg(CASE WHEN q.status='graded' AND q.max_points>0 THEN 100*q.total_points/q.max_points END),2) AS average_score_percent
    FROM training_quiz_attempts q JOIN training_recipients r ON r.company_id=q.company_id AND r.id=q.recipient_id
    JOIN training_assignments a ON a.company_id=r.company_id AND a.id=r.assignment_id
    JOIN training_versions v ON v.company_id=a.company_id AND v.id=a.version_id
    WHERE r.company_id=$1 AND ($4::uuid IS NULL OR r.employee_id=$4)
      AND ($5::text IS NULL OR v.kind=$5) AND ($6::timestamptz IS NULL OR r.created_at >= $6)
      AND ($7::timestamptz IS NULL OR r.created_at <= $7)
      AND ($8::uuid IS NULL OR EXISTS (SELECT 1 FROM training_course_lesson_runs lr JOIN training_course_enrollments ce
        ON ce.company_id=lr.company_id AND ce.id=lr.enrollment_id WHERE lr.company_id=r.company_id AND lr.recipient_id=r.id AND ce.course_id=$8))
      AND ($9::uuid IS NULL OR EXISTS (SELECT 1 FROM training_audience_members m
        WHERE m.company_id=r.company_id AND m.group_id=$9 AND m.employee_id=r.employee_id))
      AND ($4::uuid IS NOT NULL OR $3::boolean OR EXISTS (SELECT 1 FROM training_supervisor_grants g
        WHERE g.company_id=r.company_id AND g.supervisor_id=$2 AND g.employee_id=r.employee_id))`,args)).rows[0];
  const courses=(await pool.query(`SELECT count(*)::integer AS enrolled,count(*) FILTER (WHERE e.completed_at IS NOT NULL)::integer AS completed
    FROM training_course_enrollments e WHERE e.company_id=$1 AND $5::text IS NULL AND ($4::uuid IS NULL OR e.employee_id=$4)
      AND ($6::timestamptz IS NULL OR e.created_at >= $6) AND ($7::timestamptz IS NULL OR e.created_at <= $7)
      AND ($8::uuid IS NULL OR e.course_id=$8)
      AND ($9::uuid IS NULL OR EXISTS (SELECT 1 FROM training_audience_members m
        WHERE m.company_id=e.company_id AND m.group_id=$9 AND m.employee_id=e.employee_id))
      AND ($4::uuid IS NOT NULL OR $3::boolean OR EXISTS (SELECT 1 FROM training_supervisor_grants g
        WHERE g.company_id=e.company_id AND g.supervisor_id=$2 AND g.employee_id=e.employee_id))`,args)).rows[0];
  const certificates=(await pool.query(`SELECT count(*)::integer AS issued,
    count(*) FILTER (WHERE revoked_at IS NOT NULL)::integer AS revoked,
    count(*) FILTER (WHERE revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at<now())::integer AS expired
    FROM training_certificates c WHERE c.company_id=$1 AND $5::text IS NULL AND ($4::uuid IS NULL OR c.employee_id=$4)
      AND ($6::timestamptz IS NULL OR c.issued_at >= $6) AND ($7::timestamptz IS NULL OR c.issued_at <= $7)
      AND ($8::uuid IS NULL OR EXISTS (SELECT 1 FROM training_course_enrollments e WHERE e.company_id=c.company_id AND e.id=c.enrollment_id AND e.course_id=$8))
      AND ($9::uuid IS NULL OR EXISTS (SELECT 1 FROM training_audience_members m
        WHERE m.company_id=c.company_id AND m.group_id=$9 AND m.employee_id=c.employee_id))
      AND ($4::uuid IS NOT NULL OR $3::boolean OR EXISTS (SELECT 1 FROM training_supervisor_grants g
        WHERE g.company_id=c.company_id AND g.supervisor_id=$2 AND g.employee_id=c.employee_id))`,args)).rows[0];
  const coverage=(await pool.query(`WITH scoped AS (SELECT r.id ${base})
    SELECT round(COALESCE(sum((segment.value->>1)::numeric-(segment.value->>0)::numeric),0),1) AS seconds
    FROM scoped JOIN training_video_progress p ON p.recipient_id=scoped.id AND p.company_id=$1
    CROSS JOIN LATERAL jsonb_array_elements(p.intervals) AS segment(value)`,args)).rows[0];
  const assigned=integer(totals,'assigned'),completed=integer(totals,'completed'),due=integer(totals,'completed_with_due');
  return {scope,filters:{employee_id:target,group_id:groupID,kind,course_id:courseID,from,to},definitions:{
    overdue:'Incomplete assignment after due_at plus its configured grace period, using server time.',
    on_time:'Completed assignment at or before due_at plus its configured grace period; excludes assignments without a due date.',
    quiz_score:'Arithmetic mean of graded attempt percentages; repeated attempts count separately.',
    time_spent:'Unavailable: total attentive time cannot be established from client playback events.',
    video_coverage:'Unique timeline seconds credited by server-validated Mux playback sessions; replayed sections count once and this is not proof of attention.',
    team_filter:'Current team/group membership; assignment and completion history remains pinned to the original recipient.'},
    assignments:{assigned,completed,overdue:integer(totals,'overdue'),pending_review:integer(totals,'pending_review'),
      completion_percent:assigned?Math.round(10000*completed/assigned)/100:null,
      on_time:integer(totals,'on_time'),completed_with_due:due,on_time_percent:due?Math.round(10000*integer(totals,'on_time')/due)/100:null},
    quizzes:{attempts:integer(quiz,'attempts'),graded:integer(quiz,'graded'),passed:integer(quiz,'passed'),failed:integer(quiz,'failed'),
      average_score_percent:quiz.average_score_percent==null?null:Number(quiz.average_score_percent)},
    courses:{enrolled:integer(courses,'enrolled'),completed:integer(courses,'completed')},
    certificates:{issued:integer(certificates,'issued'),revoked:integer(certificates,'revoked'),expired:integer(certificates,'expired')},
    time_spent_seconds:null,video_coverage_seconds:Number(coverage.seconds??0)};
}
