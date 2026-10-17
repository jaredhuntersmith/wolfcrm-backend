// Tasks historically followed the creator's current company. Capture ownership
// once so moving a user cannot move old task data into another MCP account.
// Current membership alone is not proof of historical ownership: ambiguous old
// tasks stay NULL and are excluded from MCP until a reviewed mapping exists.
export async function installTaskTenancy(pool) {
 const db=await pool.connect();
 try {
  await db.query('BEGIN');
  await db.query("SET LOCAL lock_timeout='5s'; SELECT pg_advisory_xact_lock(hashtextextended('wolf-task-tenancy-v1',0))");
  await db.query(`DO $$ BEGIN
   IF NOT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='todo_tasks' AND column_name='company_id') THEN
    ALTER TABLE todo_tasks ADD COLUMN company_id uuid REFERENCES companies(id);
    WITH evidence AS (
     SELECT task.id,contact.company_id FROM todo_tasks task JOIN contacts contact ON contact.id::text=task.linked_contact_id::text WHERE contact.company_id IS NOT NULL
     UNION ALL SELECT task.id,job.company_id FROM todo_tasks task JOIN schedule_events job ON job.id::text=task.linked_job_id::text WHERE job.company_id IS NOT NULL
    ), resolved AS (SELECT id,(array_agg(DISTINCT company_id))[1] AS company_id FROM evidence GROUP BY id HAVING count(DISTINCT company_id)=1)
    UPDATE todo_tasks task SET company_id=resolved.company_id FROM resolved WHERE task.id=resolved.id
     AND (task.linked_contact_id IS NULL OR EXISTS(SELECT 1 FROM contacts c WHERE c.id::text=task.linked_contact_id::text AND c.company_id=resolved.company_id))
     AND (task.linked_job_id IS NULL OR EXISTS(SELECT 1 FROM schedule_events j WHERE j.id::text=task.linked_job_id::text AND j.company_id=resolved.company_id));
    IF to_regclass('public.comms_task_links') IS NOT NULL THEN
     -- Conflicting durable sources remain unknown, including cross-tenant legacy links.
     UPDATE todo_tasks task SET company_id=CASE
      WHEN task.company_id IS NULL AND task.linked_contact_id IS NULL AND task.linked_job_id IS NULL THEN link.company_id
      WHEN task.company_id=link.company_id THEN task.company_id ELSE NULL END
     FROM comms_task_links link WHERE link.task_id=task.id;
    END IF;
   END IF;
  END $$;
  CREATE INDEX IF NOT EXISTS todo_tasks_company_id_idx ON todo_tasks(company_id,id);
  CREATE OR REPLACE FUNCTION wolf_task_company_guard() RETURNS trigger LANGUAGE plpgsql AS $$
  DECLARE owner_company uuid;
  BEGIN
   IF TG_OP='INSERT' THEN
    SELECT company_id INTO owner_company FROM users WHERE id=NEW.user_id AND deleted_at IS NULL FOR SHARE;
    IF NEW.company_id IS NOT NULL AND NEW.company_id IS DISTINCT FROM owner_company THEN
     RAISE EXCEPTION 'task company does not match creator' USING ERRCODE='23514';
    END IF;
    NEW.company_id:=owner_company;
   ELSIF NEW.company_id IS DISTINCT FROM OLD.company_id THEN
    RAISE EXCEPTION 'task company cannot be changed implicitly' USING ERRCODE='23514';
   END IF;
   RETURN NEW;
  END $$;
  DROP TRIGGER IF EXISTS wolf_task_company_guard ON todo_tasks;
  CREATE TRIGGER wolf_task_company_guard BEFORE INSERT OR UPDATE OF company_id ON todo_tasks
   FOR EACH ROW EXECUTE FUNCTION wolf_task_company_guard();`);
  await db.query('COMMIT');
 } catch(e) {await db.query('ROLLBACK');throw e;} finally {db.release();}
}
