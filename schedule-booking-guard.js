// Every calendar writer shares this database guard; reservations are a derived
// index of Schedule, never another editable calendar.
export async function lockCompanySchedule(db, companyId) {
  await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [`schedule:${companyId}`]);
}
export function scheduleConflict(error) {
  if (["23P01", "40P01", "40001"].includes(error?.code)) return { status: 409, error: "schedule_resource_conflict", message: "That appointment conflicts with a calendar change. Refresh availability and choose another time." };
  if (error?.code === "23514" && /^schedule_/.test(error?.message || "")) return { status: 400, error: error.message, message: "Choose a valid interval and active workers from this company." };
  return null;
}
export async function installScheduleBookingGuard(pool) {
  const db = await pool.connect();
  try {
    await db.query("BEGIN");
    await db.query(`CREATE EXTENSION IF NOT EXISTS btree_gist;
      ALTER TABLE companies ADD COLUMN IF NOT EXISTS customer_booking_settings JSONB NOT NULL DEFAULT '{}';
      ALTER TABLE companies ADD COLUMN IF NOT EXISTS customer_booking_version INTEGER NOT NULL DEFAULT 1;
      ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS agreement_id UUID;
      ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS booking_buffer_before_minutes INTEGER NOT NULL DEFAULT 0;
      ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS booking_buffer_after_minutes INTEGER NOT NULL DEFAULT 0;
      LOCK TABLE schedule_events IN SHARE ROW EXCLUSIVE MODE;
      CREATE INDEX IF NOT EXISTS schedule_company_interval_idx ON schedule_events(company_id,start_at,end_at);
      CREATE TABLE IF NOT EXISTS schedule_resource_reservations (
        event_id TEXT NOT NULL REFERENCES schedule_events(id) ON DELETE CASCADE,
        company_id UUID NOT NULL, worker_id TEXT NOT NULL, occupied TSTZRANGE NOT NULL,
        enforced BOOLEAN NOT NULL DEFAULT true, PRIMARY KEY(event_id,worker_id),
        CONSTRAINT schedule_resource_no_overlap EXCLUDE USING gist
          (company_id WITH =,worker_id WITH =,occupied WITH &&) WHERE (enforced) DEFERRABLE INITIALLY IMMEDIATE
      );
      CREATE INDEX IF NOT EXISTS schedule_resource_legacy_idx ON schedule_resource_reservations USING gist(company_id,occupied) WHERE NOT enforced;
      INSERT INTO schedule_resource_reservations(event_id,company_id,worker_id,occupied,enforced)
        SELECT e.id,e.company_id,w.value,tstzrange(e.start_at,e.end_at,'[)'),false
        FROM schedule_events e CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN jsonb_typeof(e.worker_user_ids)='array' THEN e.worker_user_ids ELSE '[]' END) w
        WHERE e.company_id IS NOT NULL AND e.end_at>e.start_at ON CONFLICT(event_id,worker_id) DO NOTHING;
      CREATE OR REPLACE FUNCTION wolfcrm_schedule_changed(a schedule_events,b schedule_events) RETURNS boolean
      LANGUAGE sql IMMUTABLE AS $$ SELECT (a.company_id,a.start_at,a.end_at,a.worker_user_ids,a.booking_buffer_before_minutes,a.booking_buffer_after_minutes)
        IS DISTINCT FROM (b.company_id,b.start_at,b.end_at,b.worker_user_ids,b.booking_buffer_before_minutes,b.booking_buffer_after_minutes) $$;
      CREATE OR REPLACE FUNCTION wolfcrm_schedule_lock() RETURNS trigger LANGUAGE plpgsql AS $$
      DECLARE scope uuid;
      BEGIN
        scope:=CASE WHEN TG_OP='DELETE' THEN OLD.company_id ELSE NEW.company_id END;
        IF scope IS NOT NULL THEN PERFORM pg_advisory_xact_lock(hashtextextended('schedule:'||scope::text,0)); END IF;
        IF TG_OP='DELETE' THEN RETURN OLD; END IF;
        IF TG_OP='UPDATE' AND OLD.company_id IS NOT NULL AND OLD.company_id IS DISTINCT FROM NEW.company_id THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='schedule_company_immutable'; END IF;
        IF TG_OP='UPDATE' AND NOT wolfcrm_schedule_changed(OLD,NEW) THEN RETURN NEW; END IF;
        IF NEW.end_at<=NEW.start_at OR NEW.booking_buffer_before_minutes NOT BETWEEN 0 AND 240 OR NEW.booking_buffer_after_minutes NOT BETWEEN 0 AND 240 THEN
          RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='schedule_invalid_interval'; END IF;
        IF jsonb_typeof(NEW.worker_user_ids)<>'array' OR EXISTS (
          SELECT 1 FROM jsonb_array_elements_text(NEW.worker_user_ids) w WHERE NOT EXISTS
            (SELECT 1 FROM users u WHERE u.id::text=w.value AND (u.company_id=NEW.company_id OR (NEW.company_id IS NULL AND u.id=NEW.user_id)) AND u.deleted_at IS NULL)
        ) THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='schedule_invalid_workers'; END IF;
        RETURN NEW;
      END $$;
      CREATE OR REPLACE FUNCTION wolfcrm_schedule_project() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        IF TG_OP='UPDATE' AND NOT wolfcrm_schedule_changed(OLD,NEW) THEN RETURN NEW; END IF;
        DELETE FROM schedule_resource_reservations WHERE event_id=NEW.id;
        IF NEW.company_id IS NOT NULL THEN
          INSERT INTO schedule_resource_reservations(event_id,company_id,worker_id,occupied,enforced)
          SELECT NEW.id,NEW.company_id,w.value,tstzrange(NEW.start_at-make_interval(mins=>NEW.booking_buffer_before_minutes),NEW.end_at+make_interval(mins=>NEW.booking_buffer_after_minutes),'[)'),true
          FROM (SELECT DISTINCT value FROM jsonb_array_elements_text(NEW.worker_user_ids)) w;
        END IF;
        RETURN NEW;
      END $$;
      CREATE OR REPLACE FUNCTION wolfcrm_schedule_check_legacy() RETURNS trigger LANGUAGE plpgsql AS $$
      DECLARE current_event schedule_events;
      BEGIN
        IF TG_OP='UPDATE' AND NOT wolfcrm_schedule_changed(OLD,NEW) THEN RETURN NULL; END IF;
        SELECT * INTO current_event FROM schedule_events WHERE id=NEW.id;
        IF NOT FOUND OR current_event.company_id IS NULL THEN RETURN NULL; END IF;
        IF EXISTS (SELECT 1 FROM schedule_resource_reservations n JOIN schedule_resource_reservations l ON
          l.company_id=n.company_id AND l.worker_id=n.worker_id AND l.occupied && n.occupied AND l.event_id<>n.event_id
          WHERE n.event_id=NEW.id AND NOT l.enforced) OR EXISTS (
          SELECT 1 FROM schedule_events e WHERE e.company_id=current_event.company_id AND e.id<>current_event.id
          AND (CASE WHEN e.end_at>e.start_at THEN tstzrange(e.start_at-make_interval(mins=>e.booking_buffer_before_minutes),e.end_at+make_interval(mins=>e.booking_buffer_after_minutes),'[)') ELSE 'empty'::tstzrange END) &&
            tstzrange(current_event.start_at-make_interval(mins=>current_event.booking_buffer_before_minutes),current_event.end_at+make_interval(mins=>current_event.booking_buffer_after_minutes),'[)')
          AND ((current_event.agreement_id IS NOT NULL AND (e.worker_user_ids='[]'::jsonb OR jsonb_typeof(e.worker_user_ids)<>'array')) OR
            (e.agreement_id IS NOT NULL AND current_event.worker_user_ids='[]'::jsonb))
        ) THEN RAISE EXCEPTION USING ERRCODE='23P01',MESSAGE='schedule_resource_conflict'; END IF;
        RETURN NULL;
      END $$;
      DROP TRIGGER IF EXISTS wolfcrm_schedule_lock ON schedule_events;
      CREATE TRIGGER wolfcrm_schedule_lock BEFORE INSERT OR UPDATE OR DELETE ON schedule_events FOR EACH ROW EXECUTE FUNCTION wolfcrm_schedule_lock();
      DROP TRIGGER IF EXISTS wolfcrm_schedule_project ON schedule_events;
      DROP TRIGGER IF EXISTS a_wolfcrm_schedule_project ON schedule_events;
      CREATE TRIGGER a_wolfcrm_schedule_project AFTER INSERT OR UPDATE ON schedule_events FOR EACH ROW EXECUTE FUNCTION wolfcrm_schedule_project();
      DROP TRIGGER IF EXISTS schedule_resource_legacy_guard ON schedule_events;
      CREATE CONSTRAINT TRIGGER schedule_resource_legacy_guard AFTER INSERT OR UPDATE ON schedule_events DEFERRABLE INITIALLY IMMEDIATE FOR EACH ROW EXECUTE FUNCTION wolfcrm_schedule_check_legacy();
      CREATE OR REPLACE FUNCTION wolfcrm_schedule_settings_lock() RETURNS trigger LANGUAGE plpgsql AS $$
      DECLARE scope uuid;
      BEGIN
        IF TG_TABLE_NAME='companies' THEN scope:=NEW.id;
        ELSIF TG_OP='DELETE' THEN scope:=OLD.company_id; ELSE scope:=NEW.company_id; END IF;
        IF scope IS NOT NULL THEN PERFORM pg_advisory_xact_lock(hashtextextended('schedule:'||scope::text,0)); END IF;
        IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
      END $$;
      DROP TRIGGER IF EXISTS wolfcrm_booking_company_lock ON companies;
      CREATE TRIGGER wolfcrm_booking_company_lock BEFORE UPDATE OF timezone,business_days,business_open_time,business_close_time,customer_booking_settings ON companies FOR EACH ROW EXECUTE FUNCTION wolfcrm_schedule_settings_lock();
      DROP TRIGGER IF EXISTS wolfcrm_booking_availability_lock ON employee_schedule_availability;
      CREATE TRIGGER wolfcrm_booking_availability_lock BEFORE INSERT OR UPDATE OR DELETE ON employee_schedule_availability FOR EACH ROW EXECUTE FUNCTION wolfcrm_schedule_settings_lock();
      DROP TRIGGER IF EXISTS wolfcrm_booking_members_lock ON users;
      CREATE TRIGGER wolfcrm_booking_members_lock BEFORE UPDATE OF company_id,deleted_at ON users FOR EACH ROW EXECUTE FUNCTION wolfcrm_schedule_settings_lock();
    `);
    await db.query("COMMIT");
  } catch (error) { await db.query("ROLLBACK"); throw error; }
  finally { db.release(); }
}
