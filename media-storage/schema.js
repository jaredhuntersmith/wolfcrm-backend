// Additive, repeatable migration. Original bytes never enter PostgreSQL.
export async function installStorageSchema(db) {
  await db.query(`
    CREATE TABLE IF NOT EXISTS storage_accounts (
      user_id uuid PRIMARY KEY REFERENCES users(id),
      quota_bytes bigint NOT NULL CHECK(quota_bytes>=0),
      plan_id text NOT NULL DEFAULT 'base', paid_allowance_bytes bigint NOT NULL DEFAULT 0 CHECK(paid_allowance_bytes>=0),
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS storage_folders (
      id uuid PRIMARY KEY, owner_user_id uuid NOT NULL REFERENCES users(id),
      parent_folder_id uuid REFERENCES storage_folders(id), name text NOT NULL,
      version integer NOT NULL DEFAULT 1, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS storage_folders_owner_parent ON storage_folders(owner_user_id,parent_folder_id);
    CREATE TABLE IF NOT EXISTS stored_files (
      id uuid PRIMARY KEY, owner_user_id uuid NOT NULL REFERENCES users(id), uploaded_by_user_id uuid NOT NULL REFERENCES users(id),
      company_id uuid REFERENCES companies(id), folder_id uuid REFERENCES storage_folders(id),
      display_name text NOT NULL, original_filename text NOT NULL, object_key text NOT NULL UNIQUE,
      mime_type text NOT NULL, type_identifier text, extension text NOT NULL DEFAULT '',
      category text NOT NULL CHECK(category IN ('audio','image','video','document','archive','other')),
      audio_subtype text NOT NULL DEFAULT 'music' CHECK(audio_subtype IN ('music','audiobook')),
      byte_size bigint NOT NULL CHECK(byte_size>=0), visibility text NOT NULL DEFAULT 'private' CHECK(visibility IN ('private','company')),
      cloud_status text NOT NULL DEFAULT 'pending' CHECK(cloud_status IN ('pending','active','deleting','deleted')),
      upload_id text, upload_expires_at timestamptz, metadata_json jsonb NOT NULL DEFAULT '{}',
      version integer NOT NULL DEFAULT 1, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      uploaded_at timestamptz, deleted_at timestamptz, cleanup_after timestamptz, checksum text
    );
    ALTER TABLE stored_files ADD COLUMN IF NOT EXISTS thumbnail_id uuid;
    ALTER TABLE stored_files ADD COLUMN IF NOT EXISTS source_protected boolean NOT NULL DEFAULT false;
    ALTER TABLE stored_files ADD COLUMN IF NOT EXISTS delete_everywhere boolean NOT NULL DEFAULT false;
    CREATE TABLE IF NOT EXISTS storage_thumbnails (
      id uuid PRIMARY KEY, file_id uuid NOT NULL REFERENCES stored_files(id), owner_user_id uuid NOT NULL REFERENCES users(id),
      object_key text NOT NULL UNIQUE, byte_size bigint NOT NULL CHECK(byte_size BETWEEN 1 AND 524288),
      mime_type text NOT NULL DEFAULT 'image/jpeg', cloud_status text NOT NULL DEFAULT 'pending', upload_id text,
      created_at timestamptz NOT NULL DEFAULT now(), upload_expires_at timestamptz NOT NULL DEFAULT now()+interval '24 hours'
    );
    CREATE INDEX IF NOT EXISTS storage_thumbnails_file ON storage_thumbnails(file_id,cloud_status);
    CREATE INDEX IF NOT EXISTS stored_files_owner_state ON stored_files(owner_user_id,cloud_status,created_at DESC,id);
    CREATE INDEX IF NOT EXISTS stored_files_company_public ON stored_files(company_id,category,created_at DESC,id) WHERE visibility='company' AND cloud_status='active';
    CREATE INDEX IF NOT EXISTS stored_files_folder ON stored_files(owner_user_id,folder_id);
    CREATE INDEX IF NOT EXISTS stored_files_cleanup ON stored_files(cloud_status,upload_expires_at,cleanup_after);
    CREATE INDEX IF NOT EXISTS stored_files_search ON stored_files USING gin(to_tsvector('simple',display_name || ' ' || original_filename || ' ' || metadata_json::text));
    CREATE TABLE IF NOT EXISTS storage_file_state (
      user_id uuid NOT NULL REFERENCES users(id), file_id uuid NOT NULL REFERENCES stored_files(id),
      favorite boolean NOT NULL DEFAULT false, last_accessed_at timestamptz,
      position_seconds double precision NOT NULL DEFAULT 0, playback_rate double precision NOT NULL DEFAULT 1,
      completed boolean NOT NULL DEFAULT false, updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(user_id,file_id)
    );
    CREATE TABLE IF NOT EXISTS storage_access_receipts (
      id uuid PRIMARY KEY, file_id uuid NOT NULL REFERENCES stored_files(id), user_id uuid NOT NULL REFERENCES users(id),
      company_id uuid REFERENCES companies(id), was_public boolean NOT NULL, file_name text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz
    );
    CREATE TABLE IF NOT EXISTS storage_activity (
      id uuid PRIMARY KEY, file_id uuid NOT NULL REFERENCES stored_files(id), actor_user_id uuid REFERENCES users(id),
      actor_name text NOT NULL, company_id uuid REFERENCES companies(id), event_type text NOT NULL,
      file_name text NOT NULL, byte_size bigint NOT NULL, was_public boolean NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS storage_activity_company_time ON storage_activity(company_id,created_at DESC,id) WHERE was_public;
  `);
}
