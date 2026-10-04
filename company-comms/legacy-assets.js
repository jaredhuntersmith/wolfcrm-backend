// Metadata-only adoption preserves legacy bytes and keys. No provider calls in migrations.
export async function installLegacyAssets(db){
 await db.query(`
 ALTER TABLE stored_files ADD COLUMN IF NOT EXISTS storage_provider text NOT NULL DEFAULT 'canonical';
 CREATE TABLE IF NOT EXISTS comms_legacy_asset_map(attachment_id text PRIMARY KEY REFERENCES message_attachments(id),asset_id uuid REFERENCES stored_files(id),repair_reason text);
 INSERT INTO stored_files(id,owner_user_id,uploaded_by_user_id,company_id,display_name,original_filename,object_key,mime_type,category,byte_size,cloud_status,storage_provider,created_at,updated_at,uploaded_at)
 SELECT DISTINCT ON(a.object_key) md5('wolf-legacy-asset:'||m.company_id::text||':'||a.object_key)::uuid,m.sender_id,m.sender_id,m.company_id,COALESCE(NULLIF(a.file_name,''),'Attachment'),COALESCE(NULLIF(a.file_name,''),'Attachment'),a.object_key,COALESCE(NULLIF(a.mime_type,''),'application/octet-stream'),CASE WHEN a.mime_type LIKE 'audio/%' THEN 'audio' WHEN a.mime_type LIKE 'video/%' OR a.kind='video' THEN 'video' WHEN a.mime_type LIKE 'image/%' OR a.kind='photo' THEN 'image' WHEN a.mime_type LIKE '%pdf%' OR a.mime_type LIKE 'text/%' THEN 'document' ELSE 'other' END,GREATEST(COALESCE(a.byte_size,0),0),'active','legacy_media',m.created_at,m.created_at,m.created_at
 FROM message_attachments a JOIN messages m ON m.id=a.message_id
 WHERE m.company_id IS NOT NULL AND a.object_key LIKE 'companies/'||m.company_id::text||'/messages/%' AND a.object_key NOT LIKE '%..%'
 ORDER BY a.object_key,m.created_at,m.id ON CONFLICT(object_key) DO NOTHING;
 INSERT INTO comms_legacy_asset_map(attachment_id,asset_id,repair_reason)
 SELECT a.id,f.id,CASE WHEN f.id IS NULL THEN 'Legacy attachment needs verified storage mapping; original reference retained.' END FROM message_attachments a JOIN messages m ON m.id=a.message_id LEFT JOIN stored_files f ON f.object_key=a.object_key AND f.company_id=m.company_id AND f.storage_provider='legacy_media' ON CONFLICT(attachment_id) DO NOTHING;
 INSERT INTO comms_asset_refs(id,message_id,asset_id,company_id,created_at)
 SELECT md5('wolf-legacy-ref:'||a.id)::uuid,a.message_id,l.asset_id,m.company_id,m.created_at FROM comms_legacy_asset_map l JOIN message_attachments a ON a.id=l.attachment_id JOIN messages m ON m.id=a.message_id WHERE l.asset_id IS NOT NULL ON CONFLICT(message_id,asset_id) DO NOTHING;
 `);
}
