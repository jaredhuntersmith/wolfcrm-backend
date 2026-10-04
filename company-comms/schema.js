import {installMentionsSchema} from './mentions.js';
export async function installCommsSchema(db) {
  await db.query(`
    ALTER TABLE conversations ADD COLUMN IF NOT EXISTS scope text NOT NULL DEFAULT 'dm';
    -- Canonical source links are server-owned. Keep dangling references explicit
    -- so missing sources fail closed instead of becoming independent on deletion.
    ALTER TABLE conversations ADD COLUMN IF NOT EXISTS source_kind text;
    ALTER TABLE conversations ADD COLUMN IF NOT EXISTS source_id text;
    ALTER TABLE conversations ADD COLUMN IF NOT EXISTS revision integer NOT NULL DEFAULT 1;
    ALTER TABLE conversations ADD COLUMN IF NOT EXISTS photo_asset_id uuid REFERENCES stored_files(id);
    ALTER TABLE conversations ADD COLUMN IF NOT EXISTS archived_at timestamptz;
    UPDATE conversations SET scope='group_dm' WHERE is_group AND scope='dm';
    ALTER TABLE conversation_participants ADD COLUMN IF NOT EXISTS left_at timestamptz;
    ALTER TABLE conversation_participants ADD COLUMN IF NOT EXISTS history_from timestamptz NOT NULL DEFAULT '-infinity';
    CREATE TABLE IF NOT EXISTS comms_groups (
      id uuid PRIMARY KEY, company_id uuid NOT NULL REFERENCES companies(id), name text NOT NULL, description text NOT NULL DEFAULT '',
      photo_asset_id uuid REFERENCES stored_files(id), original_creator_id uuid NOT NULL REFERENCES users(id), owner_user_id uuid NOT NULL REFERENCES users(id),
      visibility text NOT NULL DEFAULT 'invite' CHECK(visibility IN ('invite','company')), legacy_channel_id text UNIQUE REFERENCES channels(id),
      revision integer NOT NULL DEFAULT 1, created_at timestamptz NOT NULL DEFAULT now(), archived_at timestamptz, suspended_at timestamptz, deleted_at timestamptz,
      ownership_repair_required boolean NOT NULL DEFAULT false, UNIQUE(company_id,id)
    );
    CREATE TABLE IF NOT EXISTS comms_group_members (
      group_id uuid NOT NULL, company_id uuid NOT NULL, user_id uuid NOT NULL REFERENCES users(id),
      status text NOT NULL CHECK(status IN ('invited','active','left','removed')), invited_by uuid REFERENCES users(id),
      joined_at timestamptz, updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(group_id,user_id),
      FOREIGN KEY(company_id,group_id) REFERENCES comms_groups(company_id,id)
    );
    CREATE INDEX IF NOT EXISTS comms_members_user ON comms_group_members(company_id,user_id,status,group_id);
    CREATE TABLE IF NOT EXISTS comms_sections (
      id uuid PRIMARY KEY, company_id uuid NOT NULL, group_id uuid NOT NULL, name text NOT NULL, sort_order integer NOT NULL DEFAULT 0,
      restricted boolean NOT NULL DEFAULT false, revision integer NOT NULL DEFAULT 1, archived_at timestamptz,
      FOREIGN KEY(company_id,group_id) REFERENCES comms_groups(company_id,id), UNIQUE(company_id,group_id,id)
    );
    CREATE TABLE IF NOT EXISTS comms_section_members (
      section_id uuid NOT NULL REFERENCES comms_sections(id), user_id uuid NOT NULL REFERENCES users(id), PRIMARY KEY(section_id,user_id)
    );
    CREATE TABLE IF NOT EXISTS comms_threads (
      id uuid PRIMARY KEY, company_id uuid NOT NULL, group_id uuid NOT NULL, section_id uuid, name text NOT NULL,
      conversation_id text NOT NULL UNIQUE REFERENCES conversations(id), kind text NOT NULL CHECK(kind IN ('general','text','voice','announcement','forum')),
      sort_order integer NOT NULL DEFAULT 0, permission_mode text NOT NULL DEFAULT 'inherit' CHECK(permission_mode IN ('inherit','override')),
      restricted boolean NOT NULL DEFAULT false, revision integer NOT NULL DEFAULT 1, archived_at timestamptz, legacy_channel_id text UNIQUE REFERENCES channels(id),
      FOREIGN KEY(company_id,group_id) REFERENCES comms_groups(company_id,id), FOREIGN KEY(company_id,group_id,section_id) REFERENCES comms_sections(company_id,group_id,id)
    );
    ALTER TABLE comms_sections ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
    ALTER TABLE comms_threads ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
    CREATE UNIQUE INDEX IF NOT EXISTS comms_general_one ON comms_threads(group_id) WHERE kind='general';
    CREATE INDEX IF NOT EXISTS comms_thread_tree ON comms_threads(group_id,section_id,sort_order,id);
    CREATE TABLE IF NOT EXISTS comms_thread_members (
      thread_id uuid NOT NULL REFERENCES comms_threads(id), user_id uuid NOT NULL REFERENCES users(id), PRIMARY KEY(thread_id,user_id)
    );
    CREATE TABLE IF NOT EXISTS comms_preferences (
      user_id uuid NOT NULL REFERENCES users(id), company_id uuid NOT NULL REFERENCES companies(id), subject_type text NOT NULL, subject_id text NOT NULL,
      favorite boolean NOT NULL DEFAULT false, muted boolean NOT NULL DEFAULT false, collapsed boolean NOT NULL DEFAULT false, sort_order integer NOT NULL DEFAULT 0,
      settings jsonb NOT NULL DEFAULT '{}', revision integer NOT NULL DEFAULT 1, PRIMARY KEY(user_id,subject_type,subject_id)
    );
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS company_id uuid REFERENCES companies(id);
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS client_key text;
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS revision integer NOT NULL DEFAULT 1;
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_root_id text REFERENCES messages(id);
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS edited_at timestamptz;
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS message_kind text NOT NULL DEFAULT 'text';
    UPDATE messages m SET company_id=c.company_id FROM conversations c WHERE m.conversation_id=c.id AND m.company_id IS NULL;
    UPDATE messages m SET company_id=c.company_id FROM channels c WHERE m.channel_id=c.id AND m.company_id IS NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS comms_send_once ON messages(company_id,sender_id,client_key) WHERE client_key IS NOT NULL;
    CREATE INDEX IF NOT EXISTS comms_message_page ON messages(conversation_id,created_at DESC,id DESC);
    CREATE INDEX IF NOT EXISTS comms_message_replies ON messages(reply_root_id,created_at,id);
    CREATE INDEX IF NOT EXISTS comms_message_search ON messages USING gin(to_tsvector('simple',body)) WHERE deleted_at IS NULL;
    CREATE TABLE IF NOT EXISTS comms_message_versions (message_id text NOT NULL REFERENCES messages(id), revision integer NOT NULL, body text NOT NULL, actor_id uuid NOT NULL REFERENCES users(id), created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(message_id,revision));
    CREATE TABLE IF NOT EXISTS comms_reactions (message_id text NOT NULL REFERENCES messages(id), user_id uuid NOT NULL REFERENCES users(id), emoji text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(message_id,user_id,emoji));
    CREATE TABLE IF NOT EXISTS comms_mentions (message_id text NOT NULL REFERENCES messages(id), user_id uuid NOT NULL REFERENCES users(id), PRIMARY KEY(message_id,user_id));
    CREATE TABLE IF NOT EXISTS comms_message_personal (message_id text NOT NULL REFERENCES messages(id), user_id uuid NOT NULL REFERENCES users(id), saved boolean NOT NULL DEFAULT false, followed boolean NOT NULL DEFAULT false, remind_at timestamptz, PRIMARY KEY(message_id,user_id));
    CREATE TABLE IF NOT EXISTS comms_pins (message_id text PRIMARY KEY REFERENCES messages(id), pinned_by uuid NOT NULL REFERENCES users(id), created_at timestamptz NOT NULL DEFAULT now());
    CREATE TABLE IF NOT EXISTS comms_asset_refs (id uuid PRIMARY KEY, message_id text NOT NULL REFERENCES messages(id), asset_id uuid NOT NULL REFERENCES stored_files(id), company_id uuid NOT NULL REFERENCES companies(id), created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(message_id,asset_id));
    ALTER TABLE comms_asset_refs ADD COLUMN IF NOT EXISTS sort_order integer NOT NULL DEFAULT 0;
    CREATE INDEX IF NOT EXISTS comms_asset_lookup ON comms_asset_refs(asset_id,message_id);
    CREATE TABLE IF NOT EXISTS comms_cards (id uuid PRIMARY KEY, message_id text NOT NULL REFERENCES messages(id), company_id uuid NOT NULL REFERENCES companies(id), source_type text NOT NULL, source_id text NOT NULL, context_type text NOT NULL, context_id text, provenance jsonb NOT NULL DEFAULT '{}', snapshot jsonb, created_at timestamptz NOT NULL DEFAULT now());
    ALTER TABLE comms_cards ADD COLUMN IF NOT EXISTS sort_order integer NOT NULL DEFAULT 0;
    CREATE TABLE IF NOT EXISTS comms_asset_provenance (asset_id uuid PRIMARY KEY REFERENCES stored_files(id), company_id uuid NOT NULL REFERENCES companies(id), source_type text NOT NULL, source_id text NOT NULL, context_type text NOT NULL, context_id text, source_version text, created_at timestamptz NOT NULL DEFAULT now());
    CREATE TABLE IF NOT EXISTS comms_audit (id uuid PRIMARY KEY, company_id uuid NOT NULL REFERENCES companies(id), actor_id uuid REFERENCES users(id), action text NOT NULL, subject_type text NOT NULL, subject_id text NOT NULL, details jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now());
    CREATE INDEX IF NOT EXISTS comms_audit_time ON comms_audit(company_id,created_at DESC,id);
    CREATE TABLE IF NOT EXISTS comms_events (id bigserial PRIMARY KEY, company_id uuid NOT NULL REFERENCES companies(id), conversation_id text REFERENCES conversations(id), recipient_id uuid REFERENCES users(id), event_type text NOT NULL, entity_id text NOT NULL, payload jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(), delivered_at timestamptz);
    CREATE INDEX IF NOT EXISTS comms_events_catchup ON comms_events(company_id,id);
    CREATE TABLE IF NOT EXISTS comms_presence (user_id uuid PRIMARY KEY REFERENCES users(id), company_id uuid NOT NULL REFERENCES companies(id), availability text NOT NULL DEFAULT 'available', status_text text NOT NULL DEFAULT '', expires_at timestamptz NOT NULL, conversation_id text REFERENCES conversations(id), typing_until timestamptz, updated_at timestamptz NOT NULL DEFAULT now());
    CREATE TABLE IF NOT EXISTS comms_mutations (company_id uuid NOT NULL REFERENCES companies(id), actor_id uuid NOT NULL REFERENCES users(id), mutation_key text NOT NULL, kind text NOT NULL, entity_id text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(company_id,actor_id,mutation_key));
  `);
  // Flat legacy rooms retain original IDs/relationships and exactly one compatibility mapping.
  await db.query(`
    INSERT INTO comms_groups(id,company_id,name,description,original_creator_id,owner_user_id,visibility,legacy_channel_id,created_at,archived_at,ownership_repair_required)
      SELECT md5('wolf-comms-group:'||c.id)::uuid,c.company_id,c.name,COALESCE(c.description,''),c.created_by,c.created_by,'company',c.id,c.created_at,c.archived_at,
        NOT EXISTS(SELECT 1 FROM users u WHERE u.id=c.created_by AND u.company_id=c.company_id AND u.deleted_at IS NULL)
      FROM channels c JOIN companies co ON co.id=c.company_id ON CONFLICT(legacy_channel_id) DO NOTHING;
    INSERT INTO conversations(id,company_id,title,is_group,created_by,created_at,updated_at,scope,archived_at)
      SELECT 'wolf-comms-legacy:'||g.legacy_channel_id,g.company_id,'General Chat',true,g.original_creator_id,g.created_at,g.created_at,'general',g.archived_at
      FROM comms_groups g WHERE g.legacy_channel_id IS NOT NULL ON CONFLICT(id) DO NOTHING;
    INSERT INTO comms_threads(id,company_id,group_id,name,conversation_id,kind,legacy_channel_id,archived_at)
      SELECT md5('wolf-comms-general:'||g.legacy_channel_id)::uuid,g.company_id,g.id,'General Chat','wolf-comms-legacy:'||g.legacy_channel_id,'general',g.legacy_channel_id,g.archived_at
      FROM comms_groups g WHERE g.legacy_channel_id IS NOT NULL ON CONFLICT(legacy_channel_id) DO NOTHING;
    INSERT INTO comms_group_members(group_id,company_id,user_id,status,joined_at)
      SELECT g.id,g.company_id,u.id,'active',g.created_at FROM comms_groups g JOIN users u ON u.company_id=g.company_id AND u.deleted_at IS NULL
      WHERE g.legacy_channel_id IS NOT NULL ON CONFLICT(group_id,user_id) DO NOTHING;
  `);
  await installMentionsSchema(db);
}
export async function installAssetGrants(db) {
 await db.query(`CREATE TABLE IF NOT EXISTS comms_asset_conversation_sources (
 asset_id uuid PRIMARY KEY REFERENCES stored_files(id),company_id uuid NOT NULL REFERENCES companies(id),conversation_id text NOT NULL REFERENCES conversations(id),capability text NOT NULL
 );CREATE TABLE IF NOT EXISTS comms_asset_grants (
  asset_id uuid NOT NULL REFERENCES stored_files(id), conversation_id text NOT NULL REFERENCES conversations(id), company_id uuid NOT NULL REFERENCES companies(id),
  granted_by uuid NOT NULL REFERENCES users(id), source_type text NOT NULL, source_id text NOT NULL, revoked_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(asset_id,conversation_id,source_type,source_id)
 ); CREATE INDEX IF NOT EXISTS comms_grants_lookup ON comms_asset_grants(asset_id,conversation_id) WHERE revoked_at IS NULL;`);
}
