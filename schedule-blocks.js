import { randomUUID } from 'node:crypto';
import { lockCompanySchedule, scheduleConflict } from './schedule-booking-guard.js';

const UUID = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i;
const maxBlockMs = 31 * 86400000;

function invalid(res, error, message) { return res.status(400).json({ error, message }); }
function parseBlockInput(input, res) {
  const kind = input?.kind;
  const title = typeof input?.title === 'string' ? input.title.trim() : '';
  const start = new Date(input?.start_at);
  const end = new Date(input?.end_at);
  if (!['event','time_off'].includes(kind)) return invalid(res, 'invalid_schedule_block_kind', 'Choose Event or Time Off.');
  if (!title || title.length > 200) return invalid(res, 'invalid_schedule_block_title', 'Enter a title up to 200 characters.');
  if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || end <= start || end - start > maxBlockMs) {
    return invalid(res, 'invalid_schedule_block_interval', 'Choose a valid time range of 31 days or fewer.');
  }
  const notes = input?.notes == null ? null : String(input.notes);
  if (notes && notes.length > 4000) return invalid(res, 'invalid_schedule_block_notes', 'Notes must be 4,000 characters or fewer.');
  return { kind, title, start_at: start, end_at: end, notes };
}

export async function installScheduleBlockSchema(pool) {
  await pool.query(`ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS booking_buffer_before_minutes INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS booking_buffer_after_minutes INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE companies ADD COLUMN IF NOT EXISTS time_off_approval_required BOOLEAN NOT NULL DEFAULT true;
    CREATE TABLE IF NOT EXISTS schedule_blocks (
      id UUID PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      kind TEXT NOT NULL CHECK(kind IN ('event','time_off')),
      title TEXT NOT NULL,
      notes TEXT,
      start_at TIMESTAMPTZ NOT NULL,
      end_at TIMESTAMPTZ NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected')),
      affects_availability BOOLEAN NOT NULL DEFAULT false,
      created_by UUID NOT NULL REFERENCES users(id),
      decided_by UUID REFERENCES users(id),
      decided_at TIMESTAMPTZ,
      revision INTEGER NOT NULL DEFAULT 1,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      deleted_at TIMESTAMPTZ,
      CHECK(end_at > start_at),
      CHECK(kind='time_off' OR affects_availability=false),
      CHECK(affects_availability=false OR status='approved')
    );
    CREATE INDEX IF NOT EXISTS schedule_blocks_company_range_idx ON schedule_blocks(company_id,start_at,end_at) WHERE deleted_at IS NULL;
    CREATE INDEX IF NOT EXISTS schedule_blocks_user_range_idx ON schedule_blocks(company_id,user_id,start_at,end_at) WHERE deleted_at IS NULL;
    CREATE TABLE IF NOT EXISTS schedule_block_decisions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      block_id UUID NOT NULL REFERENCES schedule_blocks(id),
      company_id UUID NOT NULL REFERENCES companies(id),
      actor_user_id UUID NOT NULL REFERENCES users(id),
      before_status TEXT NOT NULL,
      after_status TEXT NOT NULL,
      reason TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS schedule_block_decisions_block_idx ON schedule_block_decisions(company_id,block_id,created_at);
    CREATE OR REPLACE FUNCTION wolfcrm_schedule_block_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      PERFORM pg_advisory_xact_lock(hashtextextended('schedule:'||NEW.company_id::text,0));
      IF NEW.affects_availability AND NEW.deleted_at IS NULL AND EXISTS (
        SELECT 1 FROM schedule_events e
        WHERE e.company_id=NEW.company_id AND e.worker_user_ids ? NEW.user_id::text
          AND tstzrange(e.start_at-make_interval(mins=>e.booking_buffer_before_minutes),
              e.end_at+make_interval(mins=>e.booking_buffer_after_minutes),'[)')
              && tstzrange(NEW.start_at,NEW.end_at,'[)')
      ) THEN RAISE EXCEPTION USING ERRCODE='23P01',MESSAGE='schedule_time_off_conflict'; END IF;
      RETURN NEW;
    END $$;
    DROP TRIGGER IF EXISTS wolfcrm_schedule_block_guard ON schedule_blocks;
    CREATE TRIGGER wolfcrm_schedule_block_guard BEFORE INSERT OR UPDATE ON schedule_blocks
      FOR EACH ROW EXECUTE FUNCTION wolfcrm_schedule_block_guard();
    CREATE OR REPLACE FUNCTION wolfcrm_job_time_off_guard() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF NEW.company_id IS NULL THEN RETURN NEW; END IF;
      IF TG_OP='UPDATE' AND (OLD.start_at,OLD.end_at,OLD.worker_user_ids,OLD.booking_buffer_before_minutes,OLD.booking_buffer_after_minutes)
        IS NOT DISTINCT FROM (NEW.start_at,NEW.end_at,NEW.worker_user_ids,NEW.booking_buffer_before_minutes,NEW.booking_buffer_after_minutes) THEN RETURN NEW; END IF;
      PERFORM pg_advisory_xact_lock(hashtextextended('schedule:'||NEW.company_id::text,0));
      IF EXISTS (SELECT 1 FROM schedule_blocks b WHERE b.company_id=NEW.company_id
        AND b.deleted_at IS NULL AND b.affects_availability AND b.status='approved'
        AND NEW.worker_user_ids ? b.user_id::text
        AND tstzrange(NEW.start_at-make_interval(mins=>NEW.booking_buffer_before_minutes),
            NEW.end_at+make_interval(mins=>NEW.booking_buffer_after_minutes),'[)')
            && tstzrange(b.start_at,b.end_at,'[)')
      ) THEN RAISE EXCEPTION USING ERRCODE='23P01',MESSAGE='schedule_time_off_conflict'; END IF;
      RETURN NEW;
    END $$;
    DROP TRIGGER IF EXISTS z_wolfcrm_job_time_off_guard ON schedule_events;
    CREATE TRIGGER z_wolfcrm_job_time_off_guard BEFORE INSERT OR UPDATE ON schedule_events
      FOR EACH ROW EXECUTE FUNCTION wolfcrm_job_time_off_guard();`);
}

export function installScheduleBlockRoutes({ app, pool, authRequired, requireCapability, hasCapability }) {
  const mayReview = req => req.isCompanyOwner || hasCapability(req, 'schedule.manage_team');
  const companyRequired = (req,res) => req.companyId ? false : (res.status(403).json({error:'company_required'}), true);
  const sendError = (res,error) => {
    const conflict = scheduleConflict(error);
    if (conflict) return res.status(conflict.status).json(conflict);
    console.error('[schedule-blocks] request failed', {code:error?.code,message:error?.message});
    return res.status(500).json({error:'schedule_block_failed'});
  };

  app.get('/api/schedule/time-off-settings', authRequired, requireCapability('schedule.view'), async (req,res) => {
    if (companyRequired(req,res)) return;
    try {
      const row=(await pool.query('SELECT timezone,time_off_approval_required FROM companies WHERE id=$1',[req.companyId])).rows[0];
      if (!row) return res.status(404).json({error:'company_not_found'});
      res.set('Cache-Control','private, no-store');
      res.json({...row,can_review:mayReview(req)});
    } catch(error) { sendError(res,error); }
  });
  app.put('/api/schedule/time-off-settings', authRequired, requireCapability('schedule.manage_team'), async (req,res) => {
    if (companyRequired(req,res)) return;
    if (typeof req.body?.approval_required !== 'boolean') return invalid(res,'invalid_time_off_setting','Choose whether time off requires approval.');
    try {
      const row=(await pool.query('UPDATE companies SET time_off_approval_required=$2,updated_at=now() WHERE id=$1 RETURNING timezone,time_off_approval_required',[req.companyId,req.body.approval_required])).rows[0];
      res.json({...row,can_review:true});
    } catch(error) { sendError(res,error); }
  });
  app.get('/api/schedule/blocks', authRequired, requireCapability('schedule.view'), async(req,res) => {
    if (companyRequired(req,res)) return;
    const start=new Date(req.query.start||Date.now()),end=new Date(req.query.end||start.getTime()+7*86400000);
    if (!Number.isFinite(start.getTime())||!Number.isFinite(end.getTime())||end<=start||end-start>93*86400000) return invalid(res,'invalid_schedule_range','Choose a range of 93 days or fewer.');
    const showTeam=mayReview(req)&&req.query.scope==='team';
    try {
      const rows=(await pool.query(`SELECT id,company_id,user_id,kind,title,notes,start_at,end_at,status,affects_availability,
          created_by,decided_by,decided_at,revision,created_at,updated_at
        FROM schedule_blocks WHERE company_id=$1 AND deleted_at IS NULL AND start_at<$3 AND end_at>$2
          AND ($4::boolean OR user_id=$5) ORDER BY start_at,id`,[req.companyId,start,end,showTeam,req.userId])).rows;
      res.set('Cache-Control','private, no-store');res.json({blocks:rows,scope:showTeam?'team':'mine'});
    } catch(error) { sendError(res,error); }
  });
  app.put('/api/schedule/blocks/:id', authRequired, requireCapability('schedule.view'), async(req,res) => {
    if (companyRequired(req,res)) return;
    if (!UUID.test(req.params.id)) return invalid(res,'invalid_schedule_block_id','Use a valid event ID.');
    const input=parseBlockInput(req.body,res);
    if (!input || input.statusCode) return;
    const owner=req.body?.user_id||req.userId;
    if (!UUID.test(owner)) return invalid(res,'invalid_schedule_block_owner','Choose a valid team member.');
    if (owner!==req.userId&&!mayReview(req)) return res.status(403).json({error:'permission_denied'});
    const db=await pool.connect();
    try {
      await db.query('BEGIN');await lockCompanySchedule(db,req.companyId);
      const member=await db.query('SELECT 1 FROM users WHERE id=$1 AND company_id=$2 AND deleted_at IS NULL',[owner,req.companyId]);
      if (!member.rowCount) {await db.query('ROLLBACK');return res.status(404).json({error:'employee_not_found'});}
      const prior=(await db.query('SELECT * FROM schedule_blocks WHERE id=$1 AND company_id=$2 FOR UPDATE',[req.params.id,req.companyId])).rows[0];
      if (prior?.deleted_at) {await db.query('ROLLBACK');return res.status(409).json({error:'schedule_block_deleted'});}
      if (prior && (prior.user_id!==owner||prior.kind!==input.kind)) {await db.query('ROLLBACK');return res.status(409).json({error:'schedule_block_identity_immutable'});}
      if (prior && prior.user_id!==req.userId&&!mayReview(req)) {await db.query('ROLLBACK');return res.status(403).json({error:'permission_denied'});}
      if (prior && Number(req.body?.expected_revision)!==prior.revision) {await db.query('ROLLBACK');return res.status(409).json({error:'schedule_block_changed'});}
      const approval=(await db.query('SELECT time_off_approval_required FROM companies WHERE id=$1',[req.companyId])).rows[0]?.time_off_approval_required!==false;
      const approved=input.kind==='event'||!approval||mayReview(req);
      const status=approved?'approved':'pending';
      const row=(await db.query(`INSERT INTO schedule_blocks(id,company_id,user_id,kind,title,notes,start_at,end_at,status,affects_availability,created_by)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        ON CONFLICT(id) DO UPDATE SET title=EXCLUDED.title,notes=EXCLUDED.notes,start_at=EXCLUDED.start_at,end_at=EXCLUDED.end_at,
          status=EXCLUDED.status,affects_availability=EXCLUDED.affects_availability,decided_by=NULL,decided_at=NULL,
          revision=schedule_blocks.revision+1,updated_at=now()
        WHERE schedule_blocks.company_id=EXCLUDED.company_id AND schedule_blocks.deleted_at IS NULL
        RETURNING *`,[req.params.id,req.companyId,owner,input.kind,input.title,input.notes,input.start_at,input.end_at,status,input.kind==='time_off'&&approved,req.userId])).rows[0];
      if (!row) {await db.query('ROLLBACK');return res.status(404).json({error:'schedule_block_not_found'});}
      await db.query('COMMIT');res.json(row);
    } catch(error) {await db.query('ROLLBACK').catch(()=>{});sendError(res,error);} finally {db.release();}
  });
  app.post('/api/schedule/blocks/:id/decision', authRequired, requireCapability('schedule.manage_team'), async(req,res) => {
    if (companyRequired(req,res)) return;
    if (!UUID.test(req.params.id)) return invalid(res,'invalid_schedule_block_id','Use a valid request ID.');
    if (!['approved','rejected'].includes(req.body?.decision)) return invalid(res,'invalid_time_off_decision','Approve or reject the request.');
    const db=await pool.connect();
    try {
      await db.query('BEGIN');await lockCompanySchedule(db,req.companyId);
      const prior=(await db.query('SELECT * FROM schedule_blocks WHERE id=$1 AND company_id=$2 AND deleted_at IS NULL FOR UPDATE',[req.params.id,req.companyId])).rows[0];
      if (!prior) {await db.query('ROLLBACK');return res.status(404).json({error:'schedule_block_not_found'});}
      if (prior.kind!=='time_off'||prior.status!=='pending') {await db.query('ROLLBACK');return res.status(409).json({error:'time_off_not_pending'});}
      if (Number(req.body?.expected_revision)!==prior.revision) {await db.query('ROLLBACK');return res.status(409).json({error:'schedule_block_changed'});}
      const row=(await db.query(`UPDATE schedule_blocks SET status=$3,affects_availability=($3='approved'),
        decided_by=$4,decided_at=now(),revision=revision+1,updated_at=now()
        WHERE id=$1 AND company_id=$2 RETURNING *`,[prior.id,req.companyId,req.body.decision,req.userId])).rows[0];
      await db.query(`INSERT INTO schedule_block_decisions(block_id,company_id,actor_user_id,before_status,after_status,reason)
        VALUES($1,$2,$3,$4,$5,$6)`,[prior.id,req.companyId,req.userId,prior.status,row.status,req.body?.reason?.slice(0,1000)||null]);
      await db.query('COMMIT');res.json(row);
    } catch(error) {await db.query('ROLLBACK').catch(()=>{});sendError(res,error);} finally {db.release();}
  });
  app.delete('/api/schedule/blocks/:id', authRequired, requireCapability('schedule.view'), async(req,res) => {
    if (companyRequired(req,res)) return;
    if (!UUID.test(req.params.id)) return invalid(res,'invalid_schedule_block_id','Use a valid event ID.');
    try {
      const result=await pool.query(`UPDATE schedule_blocks SET deleted_at=now(),affects_availability=false,updated_at=now(),revision=revision+1
        WHERE id=$1 AND company_id=$2 AND deleted_at IS NULL AND ($3::boolean OR user_id=$4) RETURNING id`,[req.params.id,req.companyId,mayReview(req),req.userId]);
      if (!result.rowCount) return res.status(404).json({error:'schedule_block_not_found'});
      res.json({deleted:true,id:req.params.id});
    } catch(error) {sendError(res,error);}
  });
}
