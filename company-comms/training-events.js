import {can,loadActor} from './access.js';

// Training owns the durable domain events; this bridge owns the shared inbox.
// The caller supplies the domain-event transaction so validation, inbox enqueue,
// automation enqueue, and the domain-event dispatch marker commit together.
const kinds = new Set([
  'training.assignment_assigned',
  'training.assignment_due_soon',
  'training.assignment_overdue',
  'training.course_assigned',
  'training.certificate_expiring',
  'training.quiz_pending_grade',
  'training.quiz_passed',
  'training.quiz_failed',
  'training.course_completed',
  'training.submission_pending_review',
  'training.submission_approved',
  'training.submission_corrections_requested',
]);
const reviewKinds = new Set(['training.quiz_pending_grade','training.submission_pending_review']);
const titles = {
  'training.assignment_assigned':'Assignment assigned',
  'training.assignment_due_soon':'Assignment due soon',
  'training.assignment_overdue':'Assignment overdue',
  'training.course_assigned':'Course assigned',
  'training.certificate_expiring':'Training certificate expiring',
  'training.quiz_pending_grade':'Quiz needs grading',
  'training.quiz_passed':'Quiz passed',
  'training.quiz_failed':'Quiz not passed',
  'training.course_completed':'Course completed',
  'training.submission_pending_review':'Training ready for review',
  'training.submission_approved':'Training submission approved',
  'training.submission_corrections_requested':'Training corrections requested',
};

// Recheck the pinned due time and live recipient state both when creating the
// inbox row and immediately before a push. Reassigned, completed, expired or
// rescheduled work must not emit a stale reminder.
export async function assignmentReminderStillCurrent(db,{companyId,recipientId,assignmentId,
  definitionId,versionId,employeeId,dueAt,effectiveDueAt,kind}) {
  if (!['training.assignment_due_soon','training.assignment_overdue'].includes(kind)) return false;
  const result=await db.query(`SELECT r.employee_id FROM training_recipients r
    JOIN training_assignments a ON a.company_id=r.company_id AND a.id=r.assignment_id
    JOIN users u ON u.id=r.employee_id AND u.company_id=r.company_id
    WHERE r.company_id=$1 AND r.id=$2 AND r.employee_id=$3
      AND a.id=$4 AND a.definition_id=$5 AND a.version_id=$6
      AND date_trunc('milliseconds',a.due_at)=$7::timestamptz
      AND date_trunc('milliseconds',a.due_at+make_interval(secs => a.grace_seconds))=$8::timestamptz
      AND r.status IN ('assigned','in_progress','corrections_requested')
      AND a.available_at<=now() AND (a.expires_at IS NULL OR a.expires_at>now())
      AND u.deleted_at IS NULL AND to_jsonb(u)->>'locked_at' IS NULL
      AND COALESCE((to_jsonb(u)->>'operational_eligible')::boolean,true)
      AND NOT EXISTS (SELECT 1 FROM training_linked_runs l
        WHERE l.company_id=r.company_id AND l.child_recipient_id=r.id)
      AND (($9='training.assignment_due_soon' AND a.due_at>now())
        OR ($9='training.assignment_overdue' AND a.due_at+make_interval(secs => a.grace_seconds)<=now()))
    FOR SHARE OF r,a`,
  [companyId,recipientId,employeeId,assignmentId,definitionId,versionId,dueAt,effectiveDueAt,kind]);
  return result.rowCount>0;
}

async function currentRecipient(db, event) {
  const payload = event.payload || {};
  // Employee disable/purge takes the company FOR UPDATE. Hold a compatible
  // company-first lock until the outboxes commit so disable cannot pass between
  // the active-user check and notification creation.
  const company = await db.query('SELECT id FROM companies WHERE id=$1 FOR KEY SHARE', [event.companyId]);
  if (!company.rowCount) return null;
  if (event.eventType === 'training.assignment_due_soon' || event.eventType === 'training.assignment_overdue') {
    const current=await assignmentReminderStillCurrent(db,{companyId:event.companyId,
      recipientId:payload.recipient_id,assignmentId:payload.assignment_id,
      definitionId:payload.definition_id,versionId:payload.version_id,
      employeeId:payload.employee_id,dueAt:payload.due_at,
      effectiveDueAt:payload.effective_due_at,kind:event.eventType});
    return event.subjectId===payload.recipient_id && current ? payload.employee_id : null;
  }
  if (event.eventType === 'training.assignment_assigned') {
    const result = await db.query(`SELECT r.employee_id FROM training_recipients r
      JOIN training_assignments a ON a.company_id=r.company_id AND a.id=r.assignment_id
      JOIN users u ON u.id=r.employee_id AND u.company_id=r.company_id
      WHERE r.company_id=$1 AND r.id=$2 AND r.id=$3 AND r.employee_id=$4
        AND a.id=$5 AND a.definition_id=$6 AND a.version_id=$7
        AND u.deleted_at IS NULL AND to_jsonb(u)->>'locked_at' IS NULL
        AND COALESCE((to_jsonb(u)->>'operational_eligible')::boolean,true)`,
      [event.companyId,event.subjectId,payload.recipient_id,payload.employee_id,
        payload.assignment_id,payload.definition_id,payload.version_id]);
    return result.rows[0]?.employee_id || null;
  }
  if (event.eventType === 'training.course_assigned') {
    const result = await db.query(`SELECT e.employee_id FROM training_course_enrollments e
      JOIN users u ON u.id=e.employee_id AND u.company_id=e.company_id
      WHERE e.company_id=$1 AND e.id=$2 AND e.id=$3 AND e.employee_id=$4
        AND e.course_id=$5 AND e.version_id=$6
        AND u.deleted_at IS NULL AND to_jsonb(u)->>'locked_at' IS NULL
        AND COALESCE((to_jsonb(u)->>'operational_eligible')::boolean,true)`,
      [event.companyId,event.subjectId,payload.enrollment_id,payload.employee_id,
        payload.course_id,payload.version_id]);
    return result.rows[0]?.employee_id || null;
  }
  if (event.eventType === 'training.course_completed') {
    const result = await db.query(`SELECT e.employee_id FROM training_course_enrollments e
      JOIN users u ON u.id=e.employee_id AND u.company_id=e.company_id
      WHERE e.company_id=$1 AND e.id=$2 AND e.id=$3 AND e.employee_id=$4
        AND e.course_id=$5 AND e.version_id=$6 AND e.completed_at IS NOT NULL
        AND u.deleted_at IS NULL AND to_jsonb(u)->>'locked_at' IS NULL
        AND COALESCE((to_jsonb(u)->>'operational_eligible')::boolean,true)`,
      [event.companyId,event.subjectId,payload.enrollment_id,payload.employee_id,
        payload.course_id,payload.version_id]);
    return result.rows[0]?.employee_id || null;
  }
  if (event.eventType.startsWith('training.quiz_')) {
    const pending = event.eventType === 'training.quiz_pending_grade';
    const result = await db.query(`SELECT r.employee_id FROM training_quiz_attempts q
      JOIN training_recipients r ON r.company_id=q.company_id AND r.id=q.recipient_id
      JOIN training_assignments a ON a.company_id=r.company_id AND a.id=r.assignment_id
      JOIN users u ON u.id=r.employee_id AND u.company_id=r.company_id
      WHERE q.company_id=$1 AND q.id=$2 AND q.id=$3 AND q.recipient_id=$4
        AND r.employee_id=$5 AND a.definition_id=$6 AND q.status=$7
        AND ($8::boolean IS NULL OR q.passed=$8)
        AND u.deleted_at IS NULL AND to_jsonb(u)->>'locked_at' IS NULL
        AND COALESCE((to_jsonb(u)->>'operational_eligible')::boolean,true)
      FOR SHARE OF q`,
      [event.companyId,event.subjectId,payload.attempt_id,payload.recipient_id,
        payload.employee_id,payload.definition_id,pending?'awaiting_manual':'graded',
        pending?null:event.eventType==='training.quiz_passed']);
    return result.rows[0]?.employee_id || null;
  }
  if (event.eventType.startsWith('training.submission_')) {
    const expectedStatus = event.eventType === 'training.submission_pending_review' ? 'awaiting_review'
      : event.eventType === 'training.submission_approved' ? 'completed' : 'corrections_requested';
    const result = await db.query(`SELECT r.employee_id FROM training_recipients r
      JOIN training_assignments a ON a.company_id=r.company_id AND a.id=r.assignment_id
      JOIN users u ON u.id=r.employee_id AND u.company_id=r.company_id
      WHERE r.company_id=$1 AND r.id=$2 AND r.id=$3 AND r.employee_id=$4
        AND a.definition_id=$5 AND r.status=$6 AND r.revision=$7
        AND u.deleted_at IS NULL AND to_jsonb(u)->>'locked_at' IS NULL
        AND COALESCE((to_jsonb(u)->>'operational_eligible')::boolean,true)
      FOR SHARE OF r`,
      [event.companyId,event.subjectId,payload.recipient_id,payload.employee_id,
        payload.definition_id,expectedStatus,payload.revision]);
    return result.rows[0]?.employee_id || null;
  }
  const result = await db.query(`SELECT c.employee_id FROM training_certificates c
    JOIN training_course_enrollments e ON e.company_id=c.company_id AND e.id=c.enrollment_id
    JOIN users u ON u.id=c.employee_id AND u.company_id=c.company_id
    WHERE c.company_id=$1 AND c.id=$2 AND c.id=$3 AND c.enrollment_id=$4
      AND c.employee_id=$5 AND e.course_id=$6 AND date_trunc('milliseconds',c.expires_at)=$7::timestamptz
      AND c.revoked_at IS NULL AND c.expires_at>now()
      AND u.deleted_at IS NULL AND to_jsonb(u)->>'locked_at' IS NULL
      AND COALESCE((to_jsonb(u)->>'operational_eligible')::boolean,true)
    FOR SHARE OF c`,
    [event.companyId,event.subjectId,payload.certificate_id,payload.enrollment_id,
      payload.employee_id,payload.course_id,payload.expires_at]);
  return result.rows[0]?.employee_id || null;
}

async function currentReviewers(db,event,employeeId) {
  const candidates = (await db.query(`SELECT DISTINCT u.id FROM users u
    JOIN companies c ON c.id=u.company_id
    WHERE u.company_id=$1 AND u.id<>$2 AND u.deleted_at IS NULL
      AND to_jsonb(u)->>'locked_at' IS NULL
      AND COALESCE((to_jsonb(u)->>'operational_eligible')::boolean,true)
      AND (u.id=c.owner_user_id OR EXISTS (SELECT 1 FROM training_supervisor_grants g
        WHERE g.company_id=u.company_id AND g.supervisor_id=u.id AND g.employee_id=$2))`,
    [event.companyId,employeeId])).rows;
  const reviewers=[];
  for (const candidate of candidates) {
    try {
      const actor=await loadActor(db,{userId:candidate.id,companyId:event.companyId});
      if (can(actor,'training.review') && can(actor,'notifications.view')) reviewers.push(candidate.id);
    } catch (error) {
      if (!error.status) throw error;
    }
  }
  return reviewers;
}

export async function dispatchTrainingDomainEvent(db, event, {notifications, emitAutomationEvent}) {
  if (!kinds.has(event.eventType)) return emitAutomationEvent(event,{db});
  if (!notifications?.enqueue) throw new Error('training_notification_inbox_unavailable');
  const employeeId = await currentRecipient(db,event);
  // A revoked/expired certificate or disabled/reassigned recipient is stale.
  // Mark the domain event dispatched without creating either downstream event.
  if (!employeeId) return `stale:${event.dedupeKey}`;
  const payload = event.payload || {};
  const data = event.eventType === 'training.assignment_assigned'
    ? {recipient_id:payload.recipient_id,assignment_id:payload.assignment_id}
    : event.eventType === 'training.assignment_due_soon' || event.eventType === 'training.assignment_overdue'
      ? {recipient_id:payload.recipient_id,assignment_id:payload.assignment_id,
          definition_id:payload.definition_id,version_id:payload.version_id,
          due_at:payload.due_at,effective_due_at:payload.effective_due_at}
    : event.eventType === 'training.course_assigned' || event.eventType === 'training.course_completed'
      ? {enrollment_id:payload.enrollment_id,course_id:payload.course_id}
      : event.eventType === 'training.certificate_expiring'
        ? {certificate_id:payload.certificate_id,enrollment_id:payload.enrollment_id,
            expires_at:payload.expires_at}
        : event.eventType.startsWith('training.quiz_')
          ? {attempt_id:payload.attempt_id,recipient_id:payload.recipient_id}
          : {recipient_id:payload.recipient_id};
  const reviewers = reviewKinds.has(event.eventType)
    ? await currentReviewers(db,event,employeeId) : [employeeId];
  for (const userId of reviewers) {
    await notifications.enqueue(db,{userId,companyId:event.companyId,
      kind:event.eventType,title:titles[event.eventType],body:'Open your training to see the details.',
      data,eventKey:event.dedupeKey,
      requirements:[reviewKinds.has(event.eventType)?'training.review':'training.view_self']});
  }
  return emitAutomationEvent(event,{db});
}
