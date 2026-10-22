import {randomUUID} from 'node:crypto';
import {transact} from '../company-comms/access.js';
import {fail} from './contract.js';

const pendingStatuses=['assigned','in_progress','corrections_requested'];

// The scheduler calls this producer. It only records durable domain events;
// shared notification preferences and delivery belong to the inbox bridge.
export async function queueAssignmentReminders(pool,{now=new Date(),hoursAhead=24,limit=100}={}){
  const instant=new Date(now);
  if(Number.isNaN(instant.getTime())||!Number.isInteger(hoursAhead)||hoursAhead<1||hoursAhead>168||
    !Number.isInteger(limit)||limit<1||limit>100)fail(400,'invalid_assignment_reminder_scan');
  return transact(pool,async db=>{
    let scanned=0,queued=0;
    // Reserve capacity for both stages so a backlog of old overdue work cannot
    // starve upcoming due dates. At limit=1, allow one row per stage.
    for(const [stage,stageLimit] of [['overdue',Math.max(1,Math.ceil(limit/2))],
      ['due_soon',Math.max(1,Math.floor(limit/2))]]){
      const rows=(await db.query(`SELECT r.id AS recipient_id,r.company_id,r.employee_id,r.assignment_id,
          a.definition_id,a.version_id,a.due_at,a.due_at+make_interval(secs => a.grace_seconds) AS effective_due_at,
          a.priority,k.dedupe_key
        FROM training_recipients r
        JOIN training_assignments a ON a.company_id=r.company_id AND a.id=r.assignment_id
        JOIN users u ON u.id=r.employee_id AND u.company_id=r.company_id
        CROSS JOIN LATERAL (SELECT 'assignment:'||r.id::text||':'||$3::text||':'||
          to_char(a.due_at AT TIME ZONE 'UTC','YYYYMMDDHH24MISSUS') AS dedupe_key) k
        WHERE a.due_at IS NOT NULL AND a.available_at<=$1
          AND (a.expires_at IS NULL OR a.expires_at>$1)
          AND r.status=ANY($4::text[])
          AND u.deleted_at IS NULL AND to_jsonb(u)->>'locked_at' IS NULL
          AND COALESCE((to_jsonb(u)->>'operational_eligible')::boolean,true)
          AND NOT EXISTS (SELECT 1 FROM training_linked_runs l
            WHERE l.company_id=r.company_id AND l.child_recipient_id=r.id)
          AND (($3='due_soon' AND a.due_at>$1 AND a.due_at<=$1+make_interval(hours => $5::integer))
            OR ($3='overdue' AND a.due_at+make_interval(secs => a.grace_seconds)<=$1))
          AND NOT EXISTS (SELECT 1 FROM training_domain_events prior
            WHERE prior.company_id=r.company_id AND prior.dedupe_key=k.dedupe_key)
        ORDER BY a.due_at,r.id LIMIT $2 FOR UPDATE OF r SKIP LOCKED`,
      [instant,stageLimit,stage,pendingStatuses,hoursAhead])).rows;
      scanned+=rows.length;
      for(const row of rows){
        const payload={recipient_id:row.recipient_id,assignment_id:row.assignment_id,
          definition_id:row.definition_id,version_id:row.version_id,employee_id:row.employee_id,
          due_at:row.due_at,effective_due_at:row.effective_due_at,priority:row.priority};
        const result=await db.query(`INSERT INTO training_domain_events
          (id,company_id,actor_id,event_type,subject_type,subject_id,dedupe_key,payload)
          VALUES($1,$2,NULL,$3,'training_recipient',$4,$5,$6)
          ON CONFLICT(company_id,dedupe_key) DO NOTHING RETURNING id`,
        [randomUUID(),row.company_id,`training.assignment_${stage}`,row.recipient_id,
          row.dedupe_key,JSON.stringify(payload)]);
        queued+=result.rowCount;
      }
    }
    return {scanned,queued};
  });
}
