// Canonical page identities remain in comms_notes; this migration never copies or deletes a note.
export async function installNotesSchema(db) {
 await db.query(`
 ALTER TABLE comms_notes ALTER COLUMN conversation_id DROP NOT NULL;
 ALTER TABLE comms_task_links ALTER COLUMN conversation_id DROP NOT NULL;
 ALTER TABLE comms_notes ADD COLUMN IF NOT EXISTS owner_id uuid REFERENCES users(id);
 ALTER TABLE comms_notes ADD COLUMN IF NOT EXISTS parent_id uuid REFERENCES comms_notes(id);
 ALTER TABLE comms_notes ADD COLUMN IF NOT EXISTS visibility text NOT NULL DEFAULT 'private';
 ALTER TABLE comms_notes ADD COLUMN IF NOT EXISTS inherit_access boolean NOT NULL DEFAULT false;
 ALTER TABLE comms_notes ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'page';
 ALTER TABLE comms_notes ADD COLUMN IF NOT EXISTS icon text NOT NULL DEFAULT '';
 ALTER TABLE comms_notes ADD COLUMN IF NOT EXISTS cover_id uuid REFERENCES stored_files(id);
 ALTER TABLE comms_notes ADD COLUMN IF NOT EXISTS tags jsonb NOT NULL DEFAULT '[]';
 ALTER TABLE comms_notes ADD COLUMN IF NOT EXISTS archived_at timestamptz;
 ALTER TABLE comms_notes ADD COLUMN IF NOT EXISTS purged_at timestamptz;
 ALTER TABLE comms_notes ADD COLUMN IF NOT EXISTS template_id uuid;
 ALTER TABLE comms_notes ADD COLUMN IF NOT EXISTS position double precision NOT NULL DEFAULT 0;
 ALTER TABLE comms_notes ADD COLUMN IF NOT EXISTS content_format text NOT NULL DEFAULT 'legacy';
 UPDATE comms_notes SET owner_id=creator_id WHERE owner_id IS NULL;
 CREATE INDEX IF NOT EXISTS notes_parent_idx ON comms_notes(company_id,parent_id,position,id);
 CREATE INDEX IF NOT EXISTS notes_owner_idx ON comms_notes(company_id,owner_id,updated_at DESC,id);
 CREATE TABLE IF NOT EXISTS notes_members(page_id uuid NOT NULL REFERENCES comms_notes(id),user_id uuid NOT NULL REFERENCES users(id),role integer NOT NULL CHECK(role BETWEEN 1 AND 4),PRIMARY KEY(page_id,user_id));
 CREATE INDEX IF NOT EXISTS notes_members_user_idx ON notes_members(user_id,page_id);
 CREATE TABLE IF NOT EXISTS notes_blocks(id uuid PRIMARY KEY,page_id uuid NOT NULL REFERENCES comms_notes(id),parent_id uuid REFERENCES notes_blocks(id),type text NOT NULL,position double precision NOT NULL DEFAULT 0,payload jsonb NOT NULL DEFAULT '{}',revision integer NOT NULL DEFAULT 1,creator_id uuid NOT NULL REFERENCES users(id),editor_id uuid NOT NULL REFERENCES users(id),created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),deleted_at timestamptz);
 CREATE INDEX IF NOT EXISTS notes_blocks_page_idx ON notes_blocks(page_id,position,id) WHERE deleted_at IS NULL;
 CREATE INDEX IF NOT EXISTS notes_blocks_parent_idx ON notes_blocks(parent_id);
 CREATE TABLE IF NOT EXISTS notes_versions(page_id uuid NOT NULL REFERENCES comms_notes(id),revision integer NOT NULL,actor_id uuid NOT NULL REFERENCES users(id),snapshot jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(page_id,revision));
 CREATE TABLE IF NOT EXISTS notes_personal(page_id uuid NOT NULL REFERENCES comms_notes(id),user_id uuid NOT NULL REFERENCES users(id),favorite boolean NOT NULL DEFAULT false,pinned boolean NOT NULL DEFAULT false,opened_at timestamptz,collapsed jsonb NOT NULL DEFAULT '[]',PRIMARY KEY(page_id,user_id));
 CREATE INDEX IF NOT EXISTS notes_personal_user_idx ON notes_personal(user_id,opened_at DESC);
 CREATE TABLE IF NOT EXISTS notes_operations(page_id uuid NOT NULL REFERENCES comms_notes(id),actor_id uuid NOT NULL REFERENCES users(id),client_key uuid NOT NULL,result jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(page_id,actor_id,client_key));
 CREATE TABLE IF NOT EXISTS notes_comments(id uuid PRIMARY KEY,page_id uuid NOT NULL REFERENCES comms_notes(id),block_id uuid REFERENCES notes_blocks(id),parent_id uuid REFERENCES notes_comments(id),author_id uuid NOT NULL REFERENCES users(id),body text NOT NULL,mentions jsonb NOT NULL DEFAULT '[]',resolved boolean NOT NULL DEFAULT false,deleted_at timestamptz,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now());
 ALTER TABLE notes_comments ADD COLUMN IF NOT EXISTS revision integer NOT NULL DEFAULT 1;
 CREATE INDEX IF NOT EXISTS notes_comments_page_idx ON notes_comments(page_id,created_at,id);
 CREATE TABLE IF NOT EXISTS notes_database_schemas(page_id uuid PRIMARY KEY REFERENCES comms_notes(id),columns jsonb NOT NULL,views jsonb NOT NULL DEFAULT '[]',revision integer NOT NULL DEFAULT 1);
 CREATE TABLE IF NOT EXISTS notes_database_rows(id uuid PRIMARY KEY REFERENCES comms_notes(id),database_id uuid NOT NULL REFERENCES comms_notes(id),values jsonb NOT NULL DEFAULT '{}',revision integer NOT NULL DEFAULT 1,created_at timestamptz NOT NULL DEFAULT now());
 CREATE INDEX IF NOT EXISTS notes_database_rows_page ON notes_database_rows(database_id,created_at,id);
 CREATE TABLE IF NOT EXISTS notes_ai_results(id uuid PRIMARY KEY,company_id uuid NOT NULL REFERENCES companies(id),creator_id uuid NOT NULL REFERENCES users(id),page_ids uuid[] NOT NULL,source_blocks jsonb NOT NULL,body text NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
 CREATE TABLE IF NOT EXISTS notes_templates(id uuid PRIMARY KEY,company_id uuid NOT NULL REFERENCES companies(id),creator_id uuid NOT NULL REFERENCES users(id),page_id uuid NOT NULL REFERENCES comms_notes(id),title text NOT NULL);
 CREATE TABLE IF NOT EXISTS notes_activity(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),page_id uuid NOT NULL REFERENCES comms_notes(id),actor_id uuid NOT NULL REFERENCES users(id),kind text NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
 CREATE INDEX IF NOT EXISTS notes_activity_page_idx ON notes_activity(page_id,created_at DESC,id DESC);
 CREATE TABLE IF NOT EXISTS notes_preferences(user_id uuid PRIMARY KEY REFERENCES users(id),settings jsonb NOT NULL DEFAULT '{}');
 CREATE TABLE IF NOT EXISTS notes_smart_folders(id uuid PRIMARY KEY,company_id uuid NOT NULL REFERENCES companies(id),user_id uuid NOT NULL REFERENCES users(id),title text NOT NULL,filters jsonb NOT NULL DEFAULT '{}');
 CREATE TABLE IF NOT EXISTS notes_presence(page_id uuid NOT NULL REFERENCES comms_notes(id),user_id uuid NOT NULL REFERENCES users(id),block_id uuid,updated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(page_id,user_id));
 INSERT INTO notes_blocks(id,page_id,type,payload,creator_id,editor_id,created_at,updated_at)
 SELECT md5('wolf-notes-body:'||id)::uuid,id,'paragraph',jsonb_build_object('text',body),creator_id,editor_id,created_at,updated_at FROM comms_notes WHERE content_format='legacy' ON CONFLICT(id) DO NOTHING;
 `);
 await migrateLegacyReferences(db);
}
// Called by the existing conversation-note writer inside its transaction.
export async function syncLegacyNote(db,note) {
 const installed=(await db.query("SELECT to_regclass('public.notes_blocks') AS name")).rows[0].name;
 if(!installed)return;
 await db.query(`UPDATE comms_notes SET owner_id=COALESCE(owner_id,creator_id) WHERE id=$1`,[note.id]);
 await db.query(`INSERT INTO notes_blocks(id,page_id,type,payload,creator_id,editor_id) VALUES(md5('wolf-notes-body:'||$1::text)::uuid,$1::uuid,'paragraph',$2,$3,$4) ON CONFLICT(id) DO UPDATE SET payload=$2,editor_id=$4,revision=notes_blocks.revision+1,updated_at=now()`,[note.id,JSON.stringify({text:note.body}),note.creator_id,note.editor_id]);
 await migrateLegacyReferences(db,note.id);
}

async function migrateLegacyReferences(db,pageId=null) {
 const restriction=pageId?' AND n.id=$1::uuid':'';const params=pageId?[pageId]:[];
 if(pageId)await db.query("UPDATE notes_blocks SET deleted_at=now() WHERE page_id=$1 AND type IN ('asset','contact','job','quote_card','stage_entry','service_plan','task','webpage')",[pageId]);
 await db.query(`INSERT INTO notes_blocks(id,page_id,type,position,payload,creator_id,editor_id)
 SELECT md5('wolf-notes-asset:'||n.id::text||':'||a.value)::uuid,n.id,'asset',a.ordinality,jsonb_build_object('asset_id',a.value),n.creator_id,n.editor_id
 FROM comms_notes n CROSS JOIN LATERAL jsonb_array_elements_text(n.asset_ids) WITH ORDINALITY a(value,ordinality) WHERE n.content_format='legacy' ${restriction}
 ON CONFLICT(id) DO UPDATE SET deleted_at=NULL,payload=EXCLUDED.payload,position=EXCLUDED.position,editor_id=EXCLUDED.editor_id`,params);
 await db.query(`INSERT INTO notes_blocks(id,page_id,type,position,payload,creator_id,editor_id)
 SELECT md5('wolf-notes-source:'||n.id::text||':'||s.ordinality::text)::uuid,n.id,CASE WHEN s.value->>'source_type'='quote' THEN 'quote_card' ELSE s.value->>'source_type' END,100+s.ordinality,s.value,n.creator_id,n.editor_id
 FROM comms_notes n CROSS JOIN LATERAL jsonb_array_elements(n.source_refs) WITH ORDINALITY s(value,ordinality) WHERE n.content_format='legacy' ${restriction}
 ON CONFLICT(id) DO UPDATE SET deleted_at=NULL,payload=EXCLUDED.payload,position=EXCLUDED.position,editor_id=EXCLUDED.editor_id`,params);
}
