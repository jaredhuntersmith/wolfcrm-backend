export async function installTrainingSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS training_definitions (
      id uuid PRIMARY KEY,
      company_id uuid NOT NULL REFERENCES companies(id),
      created_by uuid NOT NULL REFERENCES users(id),
      kind text NOT NULL CHECK (kind IN ('task','checklist','form','inspection','quiz')),
      title text NOT NULL,
      draft jsonb NOT NULL,
      draft_revision integer NOT NULL DEFAULT 1 CHECK (draft_revision > 0),
      latest_version integer NOT NULL DEFAULT 0 CHECK (latest_version >= 0),
      archived_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(company_id,id)
    );
    CREATE INDEX IF NOT EXISTS training_definitions_company_updated_idx
      ON training_definitions(company_id,updated_at DESC,id) WHERE archived_at IS NULL;
    ALTER TABLE training_definitions ADD COLUMN IF NOT EXISTS scope text NOT NULL DEFAULT 'company'
      CHECK (scope IN ('company','personal'));
    ALTER TABLE training_definitions ADD COLUMN IF NOT EXISTS category text
      CHECK (category IS NULL OR length(category) <= 100);
    CREATE INDEX IF NOT EXISTS training_definitions_personal_author_idx
      ON training_definitions(company_id,created_by,updated_at DESC,id) WHERE scope='personal' AND archived_at IS NULL;
    CREATE TABLE IF NOT EXISTS training_versions (
      id uuid PRIMARY KEY,
      company_id uuid NOT NULL,
      definition_id uuid NOT NULL,
      version_number integer NOT NULL CHECK (version_number > 0),
      schema_version integer NOT NULL CHECK (schema_version = 1),
      kind text NOT NULL CHECK (kind IN ('task','checklist','form','inspection','quiz')),
      title text NOT NULL,
      document jsonb NOT NULL,
      content_sha256 text NOT NULL,
      published_by uuid NOT NULL REFERENCES users(id),
      published_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(company_id,id),
      UNIQUE(company_id,definition_id,id),
      UNIQUE(company_id,definition_id,version_number),
      FOREIGN KEY (company_id,definition_id) REFERENCES training_definitions(company_id,id)
    );
    CREATE INDEX IF NOT EXISTS training_versions_definition_idx
      ON training_versions(company_id,definition_id,version_number DESC);
    CREATE TABLE IF NOT EXISTS training_assignments (
      id uuid PRIMARY KEY,
      company_id uuid NOT NULL,
      definition_id uuid NOT NULL,
      version_id uuid NOT NULL,
      assigned_by uuid NOT NULL REFERENCES users(id),
      request_key text NOT NULL,
      input_sha256 text NOT NULL,
      available_at timestamptz NOT NULL DEFAULT now(),
      due_at timestamptz,
      expires_at timestamptz,
      grace_seconds integer NOT NULL DEFAULT 0 CHECK (grace_seconds BETWEEN 0 AND 604800),
      priority text NOT NULL DEFAULT 'normal' CHECK (priority IN ('low','normal','high','urgent')),
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(company_id,id),
      UNIQUE(company_id,assigned_by,request_key),
      FOREIGN KEY (company_id,definition_id) REFERENCES training_definitions(company_id,id),
      FOREIGN KEY (company_id,definition_id,version_id) REFERENCES training_versions(company_id,definition_id,id),
      CHECK (due_at IS NULL OR due_at >= available_at),
      CHECK (expires_at IS NULL OR expires_at >= available_at)
    );
    CREATE INDEX IF NOT EXISTS training_assignments_version_idx
      ON training_assignments(company_id,version_id);
    CREATE INDEX IF NOT EXISTS training_assignments_due_idx
      ON training_assignments(company_id,due_at,id);
    CREATE TABLE IF NOT EXISTS training_assignment_prerequisites (
      company_id uuid NOT NULL,
      assignment_id uuid NOT NULL,
      prerequisite_assignment_id uuid NOT NULL,
      PRIMARY KEY(company_id,assignment_id,prerequisite_assignment_id),
      FOREIGN KEY (company_id,assignment_id) REFERENCES training_assignments(company_id,id),
      FOREIGN KEY (company_id,prerequisite_assignment_id) REFERENCES training_assignments(company_id,id),
      CHECK (assignment_id <> prerequisite_assignment_id)
    );
    CREATE INDEX IF NOT EXISTS training_assignment_prerequisites_reverse_idx
      ON training_assignment_prerequisites(company_id,prerequisite_assignment_id,assignment_id);
    CREATE TABLE IF NOT EXISTS training_audience_groups (
      id uuid PRIMARY KEY,
      company_id uuid NOT NULL REFERENCES companies(id),
      name text NOT NULL,
      kind text NOT NULL CHECK(kind IN ('team','department','group')),
      revision integer NOT NULL DEFAULT 1 CHECK(revision > 0),
      created_by uuid NOT NULL REFERENCES users(id),
      archived_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(company_id,id)
    );
    CREATE INDEX IF NOT EXISTS training_audience_groups_active_idx
      ON training_audience_groups(company_id,kind,name,id) WHERE archived_at IS NULL;
    CREATE TABLE IF NOT EXISTS training_audience_members (
      company_id uuid NOT NULL,
      group_id uuid NOT NULL,
      employee_id uuid NOT NULL REFERENCES users(id),
      PRIMARY KEY(company_id,group_id,employee_id),
      FOREIGN KEY(company_id,group_id) REFERENCES training_audience_groups(company_id,id)
    );
    CREATE INDEX IF NOT EXISTS training_audience_members_employee_idx
      ON training_audience_members(company_id,employee_id,group_id);
    CREATE TABLE IF NOT EXISTS training_onboarding_policies (
      id uuid PRIMARY KEY,
      company_id uuid NOT NULL REFERENCES companies(id),
      definition_id uuid,
      version_id uuid,
      course_id uuid,
      course_version_id uuid,
      created_by uuid NOT NULL REFERENCES users(id),
      request_key text NOT NULL,
      input_sha256 text NOT NULL,
      due_after_days integer NOT NULL CHECK(due_after_days BETWEEN 0 AND 365),
      active boolean NOT NULL DEFAULT true,
      created_at timestamptz NOT NULL DEFAULT now(),
      disabled_at timestamptz,
      UNIQUE(company_id,id),
      UNIQUE(company_id,created_by,request_key),
      FOREIGN KEY(company_id,definition_id,version_id) REFERENCES training_versions(company_id,definition_id,id),
      CONSTRAINT training_onboarding_policy_target_check CHECK ((definition_id IS NOT NULL AND version_id IS NOT NULL AND course_id IS NULL AND course_version_id IS NULL)
        OR (definition_id IS NULL AND version_id IS NULL AND course_id IS NOT NULL AND course_version_id IS NOT NULL))
    );
    CREATE INDEX IF NOT EXISTS training_onboarding_active_idx
      ON training_onboarding_policies(company_id,created_at) WHERE active;
    CREATE TABLE IF NOT EXISTS training_employee_eligibility (
      company_id uuid NOT NULL REFERENCES companies(id),
      employee_id uuid NOT NULL REFERENCES users(id),
      eligible_at timestamptz NOT NULL,
      PRIMARY KEY(company_id,employee_id)
    );
    CREATE TABLE IF NOT EXISTS training_onboarding_enrollments (
      company_id uuid NOT NULL,
      policy_id uuid NOT NULL,
      employee_id uuid NOT NULL REFERENCES users(id),
      assignment_id uuid,
      course_enrollment_id uuid,
      enrolled_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY(company_id,policy_id,employee_id),
      UNIQUE(company_id,assignment_id),
      FOREIGN KEY(company_id,policy_id) REFERENCES training_onboarding_policies(company_id,id),
      FOREIGN KEY(company_id,assignment_id) REFERENCES training_assignments(company_id,id),
      CONSTRAINT training_onboarding_enrollment_target_check CHECK (num_nonnulls(assignment_id,course_enrollment_id)=1)
    );
    CREATE TABLE IF NOT EXISTS training_recurrence_rules (
      id uuid PRIMARY KEY,
      company_id uuid NOT NULL REFERENCES companies(id),
      definition_id uuid NOT NULL,
      version_id uuid NOT NULL,
      created_by uuid NOT NULL REFERENCES users(id),
      request_key text NOT NULL,
      input_sha256 text NOT NULL,
      recipient_ids uuid[] NOT NULL,
      time_zone text NOT NULL,
      interval_days integer NOT NULL CHECK(interval_days IN (1,7)),
      local_time time NOT NULL,
      next_local_date date NOT NULL,
      next_at timestamptz NOT NULL,
      due_after_hours integer NOT NULL CHECK(due_after_hours BETWEEN 0 AND 8760),
      end_on date,
      active boolean NOT NULL DEFAULT true,
      created_at timestamptz NOT NULL DEFAULT now(),
      disabled_at timestamptz,
      UNIQUE(company_id,id),
      UNIQUE(company_id,created_by,request_key),
      FOREIGN KEY(company_id,definition_id,version_id) REFERENCES training_versions(company_id,definition_id,id),
      CHECK(NOT active OR end_on IS NULL OR end_on>=next_local_date)
    );
    CREATE INDEX IF NOT EXISTS training_recurrence_due_idx
      ON training_recurrence_rules(next_at,id) WHERE active;
    CREATE TABLE IF NOT EXISTS training_recurrence_occurrences (
      company_id uuid NOT NULL,
      rule_id uuid NOT NULL,
      local_date date NOT NULL,
      assignment_id uuid,
      status text NOT NULL CHECK(status IN ('assigned','no_active_recipients')),
      created_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY(company_id,rule_id,local_date),
      UNIQUE(company_id,assignment_id),
      FOREIGN KEY(company_id,rule_id) REFERENCES training_recurrence_rules(company_id,id),
      FOREIGN KEY(company_id,assignment_id) REFERENCES training_assignments(company_id,id)
    );
    CREATE TABLE IF NOT EXISTS training_recipients (
      id uuid PRIMARY KEY,
      company_id uuid NOT NULL,
      assignment_id uuid NOT NULL,
      employee_id uuid NOT NULL REFERENCES users(id),
      employee_name_snapshot text NOT NULL,
      status text NOT NULL DEFAULT 'assigned'
        CHECK (status IN ('assigned','in_progress','awaiting_review','corrections_requested','completed')),
      responses jsonb NOT NULL DEFAULT '{}'::jsonb,
      revision integer NOT NULL DEFAULT 1 CHECK (revision > 0),
      timer_started_at timestamptz,
      timer_running_since timestamptz,
      timer_accumulated_seconds numeric(12,3) NOT NULL DEFAULT 0 CHECK (timer_accumulated_seconds >= 0),
      score_points integer CHECK (score_points >= 0),
      max_points integer CHECK (max_points >= 0),
      submitted_at timestamptz,
      completed_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(company_id,id),
      UNIQUE(assignment_id,employee_id),
      FOREIGN KEY (company_id,assignment_id) REFERENCES training_assignments(company_id,id)
    );
    CREATE INDEX IF NOT EXISTS training_recipients_employee_idx
      ON training_recipients(company_id,employee_id,status,created_at DESC,id);
    CREATE INDEX IF NOT EXISTS training_recipients_employee_page_idx
      ON training_recipients(company_id,employee_id,created_at DESC,id);
    CREATE INDEX IF NOT EXISTS training_recipients_managed_page_idx
      ON training_recipients(company_id,updated_at DESC,id);
    CREATE INDEX IF NOT EXISTS training_recipients_pending_idx
      ON training_recipients(company_id,status,updated_at DESC,id)
      WHERE status IN ('awaiting_review','corrections_requested');
    CREATE TABLE IF NOT EXISTS training_linked_runs (
      company_id uuid NOT NULL,
      parent_recipient_id uuid NOT NULL,
      block_id text NOT NULL,
      child_recipient_id uuid NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY(company_id,parent_recipient_id,block_id),
      UNIQUE(company_id,child_recipient_id),
      FOREIGN KEY(company_id,parent_recipient_id) REFERENCES training_recipients(company_id,id),
      FOREIGN KEY(company_id,child_recipient_id) REFERENCES training_recipients(company_id,id)
    );
    CREATE INDEX IF NOT EXISTS training_linked_runs_child_idx
      ON training_linked_runs(company_id,child_recipient_id);
    CREATE TABLE IF NOT EXISTS training_quiz_attempts (
      id uuid PRIMARY KEY,
      company_id uuid NOT NULL,
      recipient_id uuid NOT NULL,
      version_id uuid NOT NULL,
      attempt_number integer NOT NULL CHECK (attempt_number > 0),
      status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','awaiting_manual','graded')),
      question_order jsonb NOT NULL,
      choice_orders jsonb NOT NULL,
      responses jsonb NOT NULL DEFAULT '{}'::jsonb,
      grade_details jsonb NOT NULL DEFAULT '{}'::jsonb,
      auto_points numeric(10,2),
      total_points numeric(10,2),
      max_points numeric(10,2),
      passed boolean,
      revision integer NOT NULL DEFAULT 1 CHECK (revision > 0),
      started_at timestamptz NOT NULL DEFAULT now(),
      deadline_at timestamptz,
      submitted_at timestamptz,
      graded_at timestamptz,
      graded_by uuid REFERENCES users(id),
      feedback text,
      UNIQUE(company_id,id),
      UNIQUE(company_id,recipient_id,attempt_number),
      FOREIGN KEY (company_id,recipient_id) REFERENCES training_recipients(company_id,id),
      FOREIGN KEY (company_id,version_id) REFERENCES training_versions(company_id,id)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS training_quiz_one_active_idx
      ON training_quiz_attempts(company_id,recipient_id) WHERE status='active';
    CREATE INDEX IF NOT EXISTS training_quiz_recipient_idx
      ON training_quiz_attempts(company_id,recipient_id,attempt_number DESC);
    CREATE TABLE IF NOT EXISTS training_question_banks (
      id uuid PRIMARY KEY,
      company_id uuid NOT NULL REFERENCES companies(id),
      created_by uuid NOT NULL REFERENCES users(id),
      scope text NOT NULL CHECK (scope IN ('personal','company')),
      category text NOT NULL DEFAULT '',
      title text NOT NULL,
      question jsonb NOT NULL,
      source_definition_id uuid,
      revision integer NOT NULL DEFAULT 1 CHECK (revision > 0),
      archived_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(company_id,id),
      CONSTRAINT training_question_bank_source_fk FOREIGN KEY(company_id,source_definition_id)
        REFERENCES training_definitions(company_id,id)
    );
    CREATE INDEX IF NOT EXISTS training_question_banks_visible_idx
      ON training_question_banks(company_id,scope,created_by,updated_at DESC,id) WHERE archived_at IS NULL;
    ALTER TABLE training_question_banks ADD COLUMN IF NOT EXISTS source_definition_id uuid;
    CREATE TABLE IF NOT EXISTS training_asset_refs (
      id uuid PRIMARY KEY,
      company_id uuid NOT NULL REFERENCES companies(id),
      file_id uuid NOT NULL REFERENCES stored_files(id),
      created_by uuid NOT NULL REFERENCES users(id),
      purpose text NOT NULL CHECK (purpose IN ('content','evidence','certificate')),
      block_id text,
      definition_id uuid,
      version_id uuid,
      recipient_id uuid,
      attempt_id uuid,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(company_id,id),
      UNIQUE(company_id,file_id,definition_id,version_id,recipient_id,attempt_id),
      FOREIGN KEY (company_id,definition_id) REFERENCES training_definitions(company_id,id),
      FOREIGN KEY (company_id,version_id) REFERENCES training_versions(company_id,id),
      FOREIGN KEY (company_id,recipient_id) REFERENCES training_recipients(company_id,id),
      FOREIGN KEY (company_id,attempt_id) REFERENCES training_quiz_attempts(company_id,id),
      CHECK (num_nonnulls(definition_id,version_id,recipient_id,attempt_id)=1)
    );
    CREATE INDEX IF NOT EXISTS training_asset_file_idx ON training_asset_refs(company_id,file_id);
    ALTER TABLE training_asset_refs ADD COLUMN IF NOT EXISTS block_id text;
    CREATE INDEX IF NOT EXISTS training_asset_recipient_idx ON training_asset_refs(company_id,recipient_id);
    CREATE TABLE IF NOT EXISTS training_video_assets (
      company_id uuid NOT NULL REFERENCES companies(id),
      playback_id text NOT NULL,
      asset_id text NOT NULL,
      duration_seconds integer NOT NULL CHECK(duration_seconds BETWEEN 1 AND 86400),
      policy text NOT NULL CHECK(policy='signed'),
      verified_by uuid NOT NULL REFERENCES users(id),
      verified_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY(company_id,playback_id)
    );
    CREATE TABLE IF NOT EXISTS training_video_progress (
      company_id uuid NOT NULL,
      recipient_id uuid NOT NULL,
      version_id uuid NOT NULL,
      block_id text NOT NULL,
      intervals jsonb NOT NULL DEFAULT '[]'::jsonb,
      watch_time_seconds numeric(12,2) NOT NULL DEFAULT 0,
      completed_at timestamptz,
      updated_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY(company_id,recipient_id,block_id),
      FOREIGN KEY(company_id,recipient_id) REFERENCES training_recipients(company_id,id),
      FOREIGN KEY(company_id,version_id) REFERENCES training_versions(company_id,id)
    );
    ALTER TABLE training_video_progress ADD COLUMN IF NOT EXISTS watch_time_seconds numeric(12,2) NOT NULL DEFAULT 0;
    CREATE TABLE IF NOT EXISTS training_video_sessions (
      id uuid PRIMARY KEY,
      company_id uuid NOT NULL,
      recipient_id uuid NOT NULL,
      version_id uuid NOT NULL,
      block_id text NOT NULL,
      status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','replaced','expired','completed')),
      last_seq integer NOT NULL DEFAULT 0 CHECK(last_seq>=0),
      last_event_hash text,
      last_receipt_at timestamptz,
      last_position numeric(10,2) NOT NULL DEFAULT 0,
      playback_state text NOT NULL DEFAULT 'paused' CHECK(playback_state IN ('paused','playing','buffering')),
      foreground boolean NOT NULL DEFAULT true,
      anomaly_count integer NOT NULL DEFAULT 0,
      started_at timestamptz NOT NULL DEFAULT now(),
      expires_at timestamptz NOT NULL,
      UNIQUE(company_id,id),
      FOREIGN KEY(company_id,recipient_id,block_id) REFERENCES training_video_progress(company_id,recipient_id,block_id),
      FOREIGN KEY(company_id,version_id) REFERENCES training_versions(company_id,id)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS training_video_one_active_idx
      ON training_video_sessions(company_id,recipient_id,block_id) WHERE status='active';
    CREATE TABLE IF NOT EXISTS training_video_events (
      company_id uuid NOT NULL,
      session_id uuid NOT NULL,
      seq integer NOT NULL CHECK(seq>0),
      event_hash text NOT NULL,
      event_type text NOT NULL,
      position_seconds numeric(10,2) NOT NULL,
      rate numeric(4,2) NOT NULL,
      accepted boolean NOT NULL,
      reason text,
      received_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY(company_id,session_id,seq),
      FOREIGN KEY(company_id,session_id) REFERENCES training_video_sessions(company_id,id)
    );
    CREATE TABLE IF NOT EXISTS training_video_checks (
      id uuid PRIMARY KEY,
      company_id uuid NOT NULL,
      recipient_id uuid NOT NULL,
      version_id uuid NOT NULL,
      block_id text NOT NULL,
      attempt_number integer NOT NULL CHECK(attempt_number>0),
      request_key text NOT NULL,
      input_sha256 text NOT NULL,
      status text NOT NULL CHECK(status IN ('graded','awaiting_manual')),
      responses jsonb NOT NULL,
      grade_details jsonb NOT NULL,
      auto_points numeric(10,2) NOT NULL,
      total_points numeric(10,2),
      max_points numeric(10,2) NOT NULL,
      passed boolean,
      feedback text,
      submitted_at timestamptz NOT NULL DEFAULT now(),
      graded_at timestamptz,
      graded_by uuid REFERENCES users(id),
      UNIQUE(company_id,id),
      UNIQUE(company_id,recipient_id,block_id,attempt_number),
      UNIQUE(company_id,recipient_id,block_id,request_key),
      FOREIGN KEY(company_id,recipient_id,block_id) REFERENCES training_video_progress(company_id,recipient_id,block_id),
      FOREIGN KEY(company_id,version_id) REFERENCES training_versions(company_id,id)
    );
    CREATE INDEX IF NOT EXISTS training_video_checks_recipient_idx ON training_video_checks(company_id,recipient_id,block_id,attempt_number DESC);
    CREATE TABLE IF NOT EXISTS training_video_checkpoint_attempts (
      id uuid PRIMARY KEY,
      company_id uuid NOT NULL,
      recipient_id uuid NOT NULL,
      version_id uuid NOT NULL,
      block_id text NOT NULL,
      checkpoint_id text NOT NULL,
      attempt_number integer NOT NULL CHECK(attempt_number>0),
      request_key text NOT NULL,
      input_sha256 text NOT NULL,
      status text NOT NULL CHECK(status IN ('acknowledged','graded','awaiting_manual')),
      response jsonb,
      auto_points numeric(10,2) NOT NULL DEFAULT 0,
      total_points numeric(10,2),
      max_points numeric(10,2) NOT NULL DEFAULT 0,
      passed boolean,
      unlocked boolean NOT NULL DEFAULT false,
      grade_details jsonb NOT NULL DEFAULT '{}'::jsonb,
      feedback text,
      replay_intervals jsonb NOT NULL DEFAULT '[]'::jsonb,
      replay_completed_at timestamptz,
      submitted_at timestamptz NOT NULL DEFAULT now(),
      graded_at timestamptz,
      graded_by uuid REFERENCES users(id),
      UNIQUE(company_id,id),
      UNIQUE(company_id,recipient_id,block_id,checkpoint_id,attempt_number),
      UNIQUE(company_id,recipient_id,block_id,checkpoint_id,request_key),
      FOREIGN KEY(company_id,recipient_id,block_id) REFERENCES training_video_progress(company_id,recipient_id,block_id),
      FOREIGN KEY(company_id,version_id) REFERENCES training_versions(company_id,id)
    );
    CREATE INDEX IF NOT EXISTS training_video_checkpoint_latest_idx ON training_video_checkpoint_attempts(company_id,recipient_id,block_id,checkpoint_id,attempt_number DESC);
    CREATE UNIQUE INDEX IF NOT EXISTS training_asset_definition_unique_idx ON training_asset_refs(company_id,file_id,definition_id) WHERE definition_id IS NOT NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS training_asset_version_unique_idx ON training_asset_refs(company_id,file_id,version_id) WHERE version_id IS NOT NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS training_asset_recipient_unique_idx ON training_asset_refs(company_id,file_id,recipient_id) WHERE recipient_id IS NOT NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS training_asset_attempt_unique_idx ON training_asset_refs(company_id,file_id,attempt_id) WHERE attempt_id IS NOT NULL;
    CREATE TABLE IF NOT EXISTS training_supervisor_grants (
      company_id uuid NOT NULL REFERENCES companies(id),
      supervisor_id uuid NOT NULL REFERENCES users(id),
      employee_id uuid NOT NULL REFERENCES users(id),
      granted_by uuid NOT NULL REFERENCES users(id),
      created_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY(company_id,supervisor_id,employee_id),
      CHECK(supervisor_id <> employee_id)
    );
    CREATE INDEX IF NOT EXISTS training_supervisor_employee_idx
      ON training_supervisor_grants(company_id,employee_id,supervisor_id);
    CREATE TABLE IF NOT EXISTS training_courses (
      id uuid PRIMARY KEY,
      company_id uuid NOT NULL REFERENCES companies(id),
      created_by uuid NOT NULL REFERENCES users(id),
      title text NOT NULL,
      draft jsonb NOT NULL,
      draft_revision integer NOT NULL DEFAULT 1 CHECK (draft_revision > 0),
      latest_version integer NOT NULL DEFAULT 0 CHECK (latest_version >= 0),
      archived_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(company_id,id)
    );
    CREATE INDEX IF NOT EXISTS training_courses_company_idx ON training_courses(company_id,updated_at DESC,id);
    CREATE TABLE IF NOT EXISTS training_course_versions (
      id uuid PRIMARY KEY,
      company_id uuid NOT NULL,
      course_id uuid NOT NULL,
      version_number integer NOT NULL CHECK (version_number > 0),
      document jsonb NOT NULL,
      content_sha256 text NOT NULL,
      published_by uuid NOT NULL REFERENCES users(id),
      published_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(company_id,id),
      UNIQUE(company_id,course_id,id),
      UNIQUE(company_id,course_id,version_number),
      FOREIGN KEY (company_id,course_id) REFERENCES training_courses(company_id,id)
    );
    CREATE TABLE IF NOT EXISTS training_course_enrollments (
      id uuid PRIMARY KEY,
      company_id uuid NOT NULL,
      course_id uuid NOT NULL,
      version_id uuid NOT NULL,
      employee_id uuid NOT NULL REFERENCES users(id),
      employee_name_snapshot text NOT NULL,
      assigned_by uuid NOT NULL REFERENCES users(id),
      request_key text NOT NULL,
      input_sha256 text NOT NULL,
      available_at timestamptz NOT NULL DEFAULT now(),
      due_at timestamptz,
      expires_at timestamptz,
      grace_seconds integer NOT NULL DEFAULT 0 CHECK (grace_seconds BETWEEN 0 AND 604800),
      completed_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(company_id,id),
      UNIQUE(company_id,assigned_by,request_key,employee_id),
      FOREIGN KEY (company_id,course_id,version_id) REFERENCES training_course_versions(company_id,course_id,id),
      CHECK (due_at IS NULL OR due_at >= available_at),
      CHECK (expires_at IS NULL OR expires_at >= available_at)
    );
    CREATE INDEX IF NOT EXISTS training_course_employee_idx ON training_course_enrollments(company_id,employee_id,created_at DESC);
    CREATE TABLE IF NOT EXISTS training_course_lesson_runs (
      company_id uuid NOT NULL,
      enrollment_id uuid NOT NULL,
      lesson_id text NOT NULL,
      recipient_id uuid NOT NULL,
      started_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY(company_id,enrollment_id,lesson_id),
      UNIQUE(company_id,recipient_id),
      FOREIGN KEY (company_id,enrollment_id) REFERENCES training_course_enrollments(company_id,id),
      FOREIGN KEY (company_id,recipient_id) REFERENCES training_recipients(company_id,id)
    );
    CREATE TABLE IF NOT EXISTS training_course_asset_refs (
      id uuid PRIMARY KEY,
      company_id uuid NOT NULL REFERENCES companies(id),
      file_id uuid NOT NULL REFERENCES stored_files(id),
      created_by uuid NOT NULL REFERENCES users(id),
      course_id uuid,
      version_id uuid,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(company_id,id),
      FOREIGN KEY (company_id,course_id) REFERENCES training_courses(company_id,id),
      FOREIGN KEY (company_id,version_id) REFERENCES training_course_versions(company_id,id),
      CHECK(num_nonnulls(course_id,version_id)=1)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS training_course_asset_draft_unique_idx
      ON training_course_asset_refs(company_id,file_id,course_id) WHERE course_id IS NOT NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS training_course_asset_version_unique_idx
      ON training_course_asset_refs(company_id,file_id,version_id) WHERE version_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS training_course_asset_file_idx ON training_course_asset_refs(company_id,file_id);
    CREATE TABLE IF NOT EXISTS training_certificates (
      id uuid PRIMARY KEY,
      company_id uuid NOT NULL,
      enrollment_id uuid NOT NULL,
      employee_id uuid NOT NULL REFERENCES users(id),
      employee_name_snapshot text NOT NULL,
      company_name_snapshot text NOT NULL,
      course_title_snapshot text NOT NULL,
      course_version_id uuid NOT NULL,
      issued_at timestamptz NOT NULL DEFAULT now(),
      expires_at timestamptz,
      score_percent numeric(5,2),
      verification_code text NOT NULL UNIQUE,
      revoked_at timestamptz,
      revoked_by uuid REFERENCES users(id),
      revocation_reason text,
      UNIQUE(company_id,id),
      UNIQUE(company_id,enrollment_id),
      FOREIGN KEY (company_id,enrollment_id) REFERENCES training_course_enrollments(company_id,id),
      FOREIGN KEY (company_id,course_version_id) REFERENCES training_course_versions(company_id,id)
    );
    CREATE INDEX IF NOT EXISTS training_certificates_employee_idx ON training_certificates(company_id,employee_id,issued_at DESC);
    CREATE TABLE IF NOT EXISTS training_audit_events (
      id uuid PRIMARY KEY,
      company_id uuid NOT NULL REFERENCES companies(id),
      actor_id uuid NOT NULL REFERENCES users(id),
      recipient_id uuid,
      definition_id uuid,
      action text NOT NULL,
      details jsonb NOT NULL DEFAULT '{}'::jsonb,
      created_at timestamptz NOT NULL DEFAULT now(),
      FOREIGN KEY (company_id,recipient_id) REFERENCES training_recipients(company_id,id),
      FOREIGN KEY (company_id,definition_id) REFERENCES training_definitions(company_id,id)
    );
    CREATE INDEX IF NOT EXISTS training_audit_recipient_idx
      ON training_audit_events(company_id,recipient_id,created_at DESC);
    CREATE TABLE IF NOT EXISTS training_domain_events (
      id uuid PRIMARY KEY,
      company_id uuid NOT NULL REFERENCES companies(id),
      actor_id uuid REFERENCES users(id),
      event_type text NOT NULL,
      subject_type text NOT NULL,
      subject_id text NOT NULL,
      dedupe_key text NOT NULL,
      payload jsonb NOT NULL DEFAULT '{}'::jsonb,
      occurred_at timestamptz NOT NULL DEFAULT now(),
      dispatched_at timestamptz,
      UNIQUE(company_id,dedupe_key)
    );
    CREATE INDEX IF NOT EXISTS training_domain_events_pending_idx
      ON training_domain_events(occurred_at,id) WHERE dispatched_at IS NULL;
    ALTER TABLE training_assignments ADD COLUMN IF NOT EXISTS grace_seconds integer NOT NULL DEFAULT 0
      CHECK (grace_seconds BETWEEN 0 AND 604800);
    ALTER TABLE training_assignments ADD COLUMN IF NOT EXISTS priority text NOT NULL DEFAULT 'normal'
      CHECK (priority IN ('low','normal','high','urgent'));
    ALTER TABLE training_recipients ADD COLUMN IF NOT EXISTS timer_started_at timestamptz;
    ALTER TABLE training_recipients ADD COLUMN IF NOT EXISTS timer_running_since timestamptz;
    ALTER TABLE training_recipients ADD COLUMN IF NOT EXISTS timer_accumulated_seconds numeric(12,3) NOT NULL DEFAULT 0
      CHECK (timer_accumulated_seconds >= 0);
    ALTER TABLE training_recipients ADD COLUMN IF NOT EXISTS score_points integer CHECK (score_points >= 0);
    ALTER TABLE training_recipients ADD COLUMN IF NOT EXISTS max_points integer CHECK (max_points >= 0);
    ALTER TABLE training_course_enrollments ADD COLUMN IF NOT EXISTS grace_seconds integer NOT NULL DEFAULT 0
      CHECK (grace_seconds BETWEEN 0 AND 604800);
    ALTER TABLE training_onboarding_policies ADD COLUMN IF NOT EXISTS course_id uuid;
    ALTER TABLE training_onboarding_policies ADD COLUMN IF NOT EXISTS course_version_id uuid;
    ALTER TABLE training_onboarding_policies ALTER COLUMN definition_id DROP NOT NULL;
    ALTER TABLE training_onboarding_policies ALTER COLUMN version_id DROP NOT NULL;
    ALTER TABLE training_onboarding_enrollments ADD COLUMN IF NOT EXISTS course_enrollment_id uuid;
    ALTER TABLE training_onboarding_enrollments ALTER COLUMN assignment_id DROP NOT NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS training_onboarding_course_enrollment_unique_idx
      ON training_onboarding_enrollments(company_id,course_enrollment_id) WHERE course_enrollment_id IS NOT NULL;
    DO $migration$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='training_question_banks'::regclass
        AND conname='training_question_bank_source_fk') THEN
        ALTER TABLE training_question_banks ADD CONSTRAINT training_question_bank_source_fk
          FOREIGN KEY(company_id,source_definition_id) REFERENCES training_definitions(company_id,id);
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='training_onboarding_policies'::regclass
        AND conname='training_onboarding_policy_target_check') THEN
        ALTER TABLE training_onboarding_policies ADD CONSTRAINT training_onboarding_policy_target_check
          CHECK ((definition_id IS NOT NULL AND version_id IS NOT NULL AND course_id IS NULL AND course_version_id IS NULL)
            OR (definition_id IS NULL AND version_id IS NULL AND course_id IS NOT NULL AND course_version_id IS NOT NULL));
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='training_onboarding_policies'::regclass
        AND conname='training_onboarding_course_version_fk') THEN
        ALTER TABLE training_onboarding_policies ADD CONSTRAINT training_onboarding_course_version_fk
          FOREIGN KEY(company_id,course_id,course_version_id) REFERENCES training_course_versions(company_id,course_id,id);
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='training_onboarding_enrollments'::regclass
        AND conname='training_onboarding_enrollment_target_check') THEN
        ALTER TABLE training_onboarding_enrollments ADD CONSTRAINT training_onboarding_enrollment_target_check
          CHECK (num_nonnulls(assignment_id,course_enrollment_id)=1);
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='training_onboarding_enrollments'::regclass
        AND conname='training_onboarding_course_enrollment_fk') THEN
        ALTER TABLE training_onboarding_enrollments ADD CONSTRAINT training_onboarding_course_enrollment_fk
          FOREIGN KEY(company_id,course_enrollment_id) REFERENCES training_course_enrollments(company_id,id);
      END IF;
      IF EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='training_definitions'::regclass
        AND conname='training_definitions_kind_check' AND pg_get_constraintdef(oid) NOT LIKE '%quiz%') THEN
        ALTER TABLE training_definitions DROP CONSTRAINT training_definitions_kind_check;
        ALTER TABLE training_definitions ADD CONSTRAINT training_definitions_kind_check
          CHECK (kind IN ('task','checklist','form','inspection','quiz'));
      END IF;
      IF EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='training_versions'::regclass
        AND conname='training_versions_kind_check' AND pg_get_constraintdef(oid) NOT LIKE '%quiz%') THEN
        ALTER TABLE training_versions DROP CONSTRAINT training_versions_kind_check;
        ALTER TABLE training_versions ADD CONSTRAINT training_versions_kind_check
          CHECK (kind IN ('task','checklist','form','inspection','quiz'));
      END IF;
    END $migration$;
  `);
}
