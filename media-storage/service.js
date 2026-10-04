import { randomUUID, createHash } from 'node:crypto';
import { PART_SIZE } from './bucket.js';
import { fail, uuid, name, integer, metadata, fileInput, readableSQL, canDelete, publicFile } from './domain.js';

export function createStorageService({pool,bucket,env=process.env}) {
  const defaultQuota=Number(env.STORAGE_DEFAULT_QUOTA_BYTES || 25*1024**3);
  const maxSize=Number(env.STORAGE_MAX_FILE_BYTES || 100*1024**3);
  integer(defaultQuota,0,Number.MAX_SAFE_INTEGER); integer(maxSize,1,PART_SIZE*10000);
  async function transaction(fn) { const db=await pool.connect(); try { await db.query('BEGIN'); const result=await fn(db); await db.query('COMMIT'); return result; } catch(e) { await db.query('ROLLBACK'); throw e; } finally { db.release(); } }
  function cloud() { if(!bucket) fail(503,'storage_not_configured','Cloud storage is not configured. Local files remain available.'); return bucket; }
  async function account(db,user) { await db.query('INSERT INTO storage_accounts(user_id,quota_bytes) VALUES($1,$2) ON CONFLICT DO NOTHING',[user,defaultQuota]); return (await db.query('SELECT * FROM storage_accounts WHERE user_id=$1 FOR UPDATE',[user])).rows[0]; }
  async function file(db,actor,id,lock=false,states=['active']) {
    const row=(await db.query(`SELECT f.* FROM stored_files f WHERE ${readableSQL} AND f.id=$3 AND f.cloud_status=ANY($4::text[]) ${lock?'FOR UPDATE OF f':''}`,[actor.userId,actor.companyId,uuid(id),states])).rows[0];
    if(!row) fail(404,'file_not_found','This file is unavailable or access was removed.'); return row;
  }
  function owner(row,actor) { if(row.owner_user_id!==actor.userId) fail(403,'file_owner_required','Only the file owner can change this file.'); }
  async function folder(db,actor,id) { if(!id) return null; const row=(await db.query('SELECT * FROM storage_folders WHERE id=$1 AND owner_user_id=$2',[uuid(id),actor.userId])).rows[0]; if(!row) fail(404,'folder_not_found','Folder not found.'); return row.id; }
  async function audit(db,row,actor,event,wasPublic=row.visibility==='company',snapshotName=row.display_name) {
    await db.query(`INSERT INTO storage_activity(id,file_id,actor_user_id,actor_name,company_id,event_type,file_name,byte_size,was_public) SELECT $1,$2,$3,COALESCE(NULLIF(display_name,''),email),$4,$5,$6,$7,$8 FROM users WHERE id=$3`,[randomUUID(),row.id,actor.userId,row.company_id,event,snapshotName,row.byte_size,wasPublic]);
  }
  async function usage(actor) {
    await pool.query('INSERT INTO storage_accounts(user_id,quota_bytes) VALUES($1,$2) ON CONFLICT DO NOTHING',[actor.userId,defaultQuota]);
    const a=(await pool.query('SELECT * FROM storage_accounts WHERE user_id=$1',[actor.userId])).rows[0];
    const rows=(await pool.query(`SELECT category,COALESCE(sum(byte_size) FILTER(WHERE cloud_status='active'),0)::text AS bytes,count(*) FILTER(WHERE cloud_status='active')::int AS file_count,COALESCE(sum(byte_size) FILTER(WHERE cloud_status IN ('pending','deleting')),0)::text AS reserved_bytes FROM stored_files WHERE owner_user_id=$1 AND cloud_status<>'deleted' GROUP BY category`,[actor.userId])).rows;
    const categories=rows.map(r=>({...r,bytes:Number(r.bytes),reserved_bytes:Number(r.reserved_bytes)}));
    return {configured:!!bucket,quota_bytes:Number(a.quota_bytes)+Number(a.paid_allowance_bytes),used_bytes:categories.reduce((n,r)=>n+r.bytes,0),reserved_bytes:categories.reduce((n,r)=>n+r.reserved_bytes,0),file_count:categories.reduce((n,r)=>n+r.file_count,0),categories,plan_id:a.plan_id,max_file_bytes:maxSize};
  }
  async function list(actor,q={}) {
    const limit=integer(Number(q.limit||100),1,200),params=[actor.userId,actor.companyId];
    const add=x=>{params.push(x);return '$'+params.length;};
    const where=[readableSQL,"f.cloud_status='active'"];
    if(q.scope==='mine') where.push('f.owner_user_id=$1');
    if(q.scope==='public') where.push("f.visibility='company' AND f.company_id=$2");
    if(q.scope==='favorites') where.push('COALESCE(s.favorite,false)');
    if(q.scope==='recent') where.push('s.last_accessed_at IS NOT NULL');
    if(q.category) { const cats=String(q.category).split(','); if(cats.some(c=>!['audio','image','video','document','archive','other'].includes(c))) fail(400,'invalid_category','Invalid category.'); where.push(`f.category=ANY(${add(cats)}::text[])`); }
    if(q.folder_id!==undefined) { where.push('f.owner_user_id=$1');where.push(`f.folder_id IS NOT DISTINCT FROM ${add(q.folder_id?uuid(q.folder_id):null)}::uuid`); }
    if(q.search) { const term=String(q.search).slice(0,200),p=add(term),like=add('%'+term.replace(/[\\%_]/g,'\\$&')+'%'); where.push(`(to_tsvector('simple',f.display_name || ' ' || f.original_filename || ' ' || f.metadata_json::text) @@ plainto_tsquery('simple',${p}) OR f.display_name ILIKE ${like} OR f.original_filename ILIKE ${like} OR f.mime_type ILIKE ${like} OR (f.owner_user_id=$1 AND folder.name ILIKE ${like}))`); }
    const sorts={name:['lower(f.display_name)','ASC'],added:['f.created_at','DESC'],modified:['f.updated_at','DESC'],size:['f.byte_size','DESC'],type:['f.mime_type','ASC'],recent:["COALESCE(s.last_accessed_at,f.created_at)",'DESC']};
    const sort=sorts[q.sort]||sorts[q.scope==='recent'?'recent':'added'],[column,direction]=sort;
    const fingerprint=createHash('sha256').update(JSON.stringify([q.scope,q.category,q.folder_id,q.search,sort])).digest('hex');
    if(q.cursor) { let c;try {c=JSON.parse(Buffer.from(String(q.cursor),'base64url').toString());}catch{fail(400,'invalid_cursor','Invalid page cursor.');}if(c.fingerprint!==fingerprint)fail(400,'invalid_cursor','Refresh the file list.'); where.push(`(${column},f.id) ${direction==='ASC'?'>':'<'} (${add(c.value)},${add(uuid(c.id))}::uuid)`); }
    const result=await pool.query(`SELECT f.*,COALESCE(s.favorite,false) AS favorite,s.last_accessed_at,s.position_seconds,s.playback_rate,s.completed,${column} AS sort_value FROM stored_files f LEFT JOIN storage_file_state s ON s.file_id=f.id AND s.user_id=$1 LEFT JOIN storage_folders folder ON folder.id=f.folder_id WHERE ${where.join(' AND ')} ORDER BY ${column} ${direction},f.id ${direction} LIMIT ${add(limit+1)}`,params);
    const more=result.rows.length>limit,rows=result.rows.slice(0,limit),last=rows.at(-1);
    return {files:rows.map(row=>{const {sort_value,...value}=row;return publicFile(value,actor);}),next_cursor:more?Buffer.from(JSON.stringify({fingerprint,value:last.sort_value,id:last.id})).toString('base64url'):null};
  }
  async function begin(actor,body) {
    cloud(); const input=fileInput(body,maxSize);
    return transaction(async db=>{
      const a=await account(db,actor.userId);
      const existing=(await db.query('SELECT * FROM stored_files WHERE id=$1',[input.id])).rows[0];
      if(existing) {
        owner(existing,actor);
        if(existing.byte_size!=input.byte_size||existing.original_filename!==input.original_filename)fail(409,'upload_conflict','The upload identifier belongs to another file.');
        if(existing.cloud_status==='deleted'||existing.cloud_status==='deleting')fail(409,'upload_deleted','This upload was deleted. Import it again.');
        if(existing.cloud_status==='pending' && new Date(existing.upload_expires_at)<=new Date())fail(409,'upload_expired','This upload expired. Cancel it and upload again.');
        return {file:publicFile(existing,actor),part_size:PART_SIZE};
      }
      const used=Number((await db.query("SELECT COALESCE(sum(byte_size),0)::text AS bytes FROM stored_files WHERE owner_user_id=$1 AND cloud_status<>'deleted'",[actor.userId])).rows[0].bytes);
      if(used+input.byte_size>Number(a.quota_bytes)+Number(a.paid_allowance_bytes))fail(413,'storage_quota_exceeded','This file exceeds your available cloud storage.');
      const folderID=await folder(db,actor,body.folder_id),key=`storage/${actor.userId}/${input.id}/${randomUUID()}`;
      const row=(await db.query(`INSERT INTO stored_files(id,owner_user_id,uploaded_by_user_id,company_id,folder_id,display_name,original_filename,object_key,mime_type,type_identifier,extension,category,audio_subtype,byte_size,metadata_json,upload_expires_at) VALUES($1,$2,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,now()+interval '24 hours') RETURNING *`,[input.id,actor.userId,actor.companyId,folderID,input.display_name,input.original_filename,key,input.mime_type,input.type_identifier,input.extension,input.category,input.audio_subtype,input.byte_size,input.metadata_json])).rows[0];
      // Creation of provider session happens after durable reservation, on first part request.
      await audit(db,row,actor,'upload_started'); return {file:publicFile(row,actor),part_size:PART_SIZE};
    });
  }
  async function part(actor,id,number) {
    cloud(); return transaction(async db=>{
      const row=await file(db,actor,id,true,['pending']);owner(row,actor);
      if(new Date(row.upload_expires_at)<=new Date())fail(409,'upload_expired','Upload expired; cancel and retry.');
      integer(number,1,Math.ceil(Number(row.byte_size)/PART_SIZE));
      if(!row.upload_id) { row.upload_id=await bucket.begin(row); await db.query('UPDATE stored_files SET upload_id=$2 WHERE id=$1',[row.id,row.upload_id]); }
      const size=Math.min(PART_SIZE,Number(row.byte_size)-(number-1)*PART_SIZE);
      return {url:await bucket.part(row,number,size),byte_size:size,part_number:number};
    });
  }
  async function complete(actor,id) {
    cloud(); return transaction(async db=>{
      const row=await file(db,actor,id,true,['pending','active']);owner(row,actor);if(row.cloud_status==='active')return publicFile(row,actor);
      let head=await bucket.head(row);
      if(!head) {
        if(!row.upload_id)fail(409,'upload_incomplete','No uploaded parts found.');
        const parts=await bucket.parts(row),expected=Math.ceil(Number(row.byte_size)/PART_SIZE);
        if(parts.length!==expected||parts.some((p,i)=>p.PartNumber!==i+1||Number(p.Size)!==Math.min(PART_SIZE,Number(row.byte_size)-i*PART_SIZE)))fail(409,'upload_incomplete','Uploaded parts do not match the reserved file size. Retry the upload.');
        await bucket.complete(row,parts);head=await bucket.head(row);
      }
      if(!head||Number(head.ContentLength)!==Number(row.byte_size)||head.Metadata?.['wolf-file-id']!==row.id)fail(409,'upload_integrity_failed','Uploaded object could not be verified.');
      const saved=(await db.query("UPDATE stored_files SET cloud_status='active',upload_id=NULL,uploaded_at=now(),updated_at=now(),version=version+1,checksum=$2 WHERE id=$1 RETURNING *",[row.id,head.ETag||null])).rows[0];
      await audit(db,saved,actor,'upload_completed');return publicFile(saved,actor);
    });
  }
  async function patch(actor,id,body) {
    return transaction(async db=>{
      await account(db,actor.userId);const row=await file(db,actor,id,true);owner(row,actor);
      if(integer(body.expected_version,1,Number.MAX_SAFE_INTEGER)!==row.version)fail(409,'stale_file','This file changed. Refresh before saving.');
      let event='metadata_updated',wasPublic=row.visibility==='company';
      if(body.display_name!==undefined) {row.display_name=name(body.display_name);event='renamed';}
      if(body.folder_id!==undefined) {row.folder_id=await folder(db,actor,body.folder_id);event='moved';}
      if(body.metadata_json!==undefined)row.metadata_json=metadata(body.metadata_json);
      if(body.audio_subtype!==undefined) {if(!['music','audiobook'].includes(body.audio_subtype))fail(400,'invalid_subtype','Choose Music or Audiobook.');row.audio_subtype=body.audio_subtype;}
      if(body.visibility!==undefined) {if(!['private','company'].includes(body.visibility))fail(400,'invalid_visibility','Invalid visibility.');if(body.visibility==='company'&&!actor.companyId)fail(409,'company_required','Join a company before sharing.');row.visibility=body.visibility;row.company_id=actor.companyId;event=row.visibility==='company'?'public_enabled':'public_disabled';wasPublic=wasPublic||row.visibility==='company';}
      const saved=(await db.query(`UPDATE stored_files SET display_name=$2,folder_id=$3,metadata_json=$4,audio_subtype=$5,visibility=$6,company_id=$7,updated_at=now(),version=version+1 WHERE id=$1 RETURNING *`,[row.id,row.display_name,row.folder_id,row.metadata_json,row.audio_subtype,row.visibility,row.company_id])).rows[0];
      await audit(db,saved,actor,event,wasPublic);return publicFile(saved,actor);
    });
  }
  async function access(actor,id,purpose) {
    cloud();if(!['stream','preview','download'].includes(purpose))fail(400,'invalid_purpose','Choose stream, preview or download.');
    return transaction(async db=>{
      const row=await file(db,actor,id,true);const url=await bucket.access(row,purpose==='download');let receipt=null;
      if(purpose==='download') {receipt=randomUUID();await db.query('INSERT INTO storage_access_receipts(id,file_id,user_id,company_id,was_public,file_name) VALUES($1,$2,$3,$4,$5,$6)',[receipt,row.id,actor.userId,row.company_id,row.visibility==='company',row.display_name]);}
      await db.query('INSERT INTO storage_file_state(user_id,file_id,last_accessed_at) VALUES($1,$2,now()) ON CONFLICT(user_id,file_id) DO UPDATE SET last_accessed_at=now()',[actor.userId,row.id]);
      return {url,receipt_id:receipt,expires_in:300};
    });
  }
  async function acknowledge(actor,id,receipt) {
    return transaction(async db=>{
      const row=await file(db,actor,id,true);const r=(await db.query('UPDATE storage_access_receipts SET completed_at=now() WHERE id=$1 AND file_id=$2 AND user_id=$3 AND completed_at IS NULL RETURNING *',[uuid(receipt),row.id,actor.userId])).rows[0];
      if(r)await audit(db,{...row,company_id:r.company_id},actor,'download',r.was_public,r.file_name);
      return {ok:true};
    });
  }
  async function state(actor,id,body) {
    return transaction(async db=>{
      await file(db,actor,id,true);
      if(body.favorite!==undefined&&typeof body.favorite!=='boolean')fail(400,'invalid_state','Invalid favorite.');
      if(body.position_seconds!==undefined&&(!Number.isFinite(body.position_seconds)||body.position_seconds<0||body.position_seconds>1e8))fail(400,'invalid_state','Invalid playback position.');
      if(body.playback_rate!==undefined&&(!Number.isFinite(body.playback_rate)||body.playback_rate<0.5||body.playback_rate>3))fail(400,'invalid_state','Invalid playback rate.');
      if(body.completed!==undefined&&typeof body.completed!=='boolean')fail(400,'invalid_state','Invalid completion state.');
      await db.query(`INSERT INTO storage_file_state(user_id,file_id) VALUES($1,$2) ON CONFLICT DO NOTHING`,[actor.userId,id]);
      const fields=['favorite','position_seconds','playback_rate','completed'],params=[actor.userId,id],set=['updated_at=now()','last_accessed_at=now()'];
      for(const key of fields)if(body[key]!==undefined){params.push(body[key]);set.push(`${key}=$${params.length}`);}
      return (await db.query(`UPDATE storage_file_state SET ${set.join(',')} WHERE user_id=$1 AND file_id=$2 RETURNING *`,params)).rows[0];
    });
  }
  async function remove(actor,id) {
    cloud();await transaction(async db=>{
      const row=await file(db,actor,id,true,['pending','active','deleting','deleted']);if(!canDelete(row,actor))fail(403,'delete_denied','Only the owner or company employer can delete this shared file.');
      if(row.cloud_status==='deleted'||row.cloud_status==='deleting')return;
      await db.query("UPDATE stored_files SET cloud_status='deleting',deleted_at=now(),updated_at=now(),cleanup_after=now(),version=version+1 WHERE id=$1",[row.id]);await audit(db,row,actor,'deleted');
    });
    await cleanup(id);return {ok:true};
  }
  async function cleanup(id=null) {
    if(!bucket)return;
    return transaction(async db=>{
      const rows=(await db.query(`SELECT * FROM stored_files WHERE ($1::uuid IS NULL OR id=$1) AND ((cloud_status='deleting' AND cleanup_after<=now()) OR (cloud_status='pending' AND upload_expires_at<now())) ORDER BY updated_at LIMIT 20 FOR UPDATE SKIP LOCKED`,[id])).rows;
      for(const row of rows) {
        try {await bucket.abort(row);await bucket.remove(row);await db.query("UPDATE stored_files SET cloud_status='deleted',upload_id=NULL,deleted_at=COALESCE(deleted_at,now()),updated_at=now() WHERE id=$1",[row.id]);}
        catch {await db.query("UPDATE stored_files SET cloud_status='deleting',cleanup_after=now()+interval '5 minutes' WHERE id=$1",[row.id]);}
      }
      await db.query("DELETE FROM storage_access_receipts WHERE created_at<now()-interval '7 days'");
    });
  }
  async function folders(actor) { return (await pool.query('SELECT * FROM storage_folders WHERE owner_user_id=$1 ORDER BY lower(name),id',[actor.userId])).rows; }
  async function saveFolder(actor,id,body) {
    return transaction(async db=>{
      await account(db,actor.userId);const parent=await folder(db,actor,body.parent_folder_id);
      if(!id)return (await db.query('INSERT INTO storage_folders(id,owner_user_id,parent_folder_id,name) VALUES($1,$2,$3,$4) RETURNING *',[randomUUID(),actor.userId,parent,name(body.name)])).rows[0];
      await folder(db,actor,id);const cycle=parent?(await db.query('WITH RECURSIVE ancestors AS (SELECT id,parent_folder_id FROM storage_folders WHERE id=$1 UNION ALL SELECT p.id,p.parent_folder_id FROM storage_folders p JOIN ancestors a ON p.id=a.parent_folder_id) SELECT 1 FROM ancestors WHERE id=$2',[parent,id])).rowCount:0;
      if(cycle)fail(409,'folder_cycle','A folder cannot be moved into itself or its descendants.');
      const saved=(await db.query('UPDATE storage_folders SET name=$3,parent_folder_id=$4,version=version+1,updated_at=now() WHERE id=$1 AND owner_user_id=$2 AND version=$5 RETURNING *',[id,actor.userId,name(body.name),parent,integer(body.expected_version,1,1e9)])).rows[0];if(!saved)fail(409,'stale_folder','Folder changed. Refresh and retry.');return saved;
    });
  }
  async function removeFolder(actor,id) { return transaction(async db=>{await account(db,actor.userId);await folder(db,actor,id);if((await db.query("SELECT 1 FROM storage_folders WHERE parent_folder_id=$1 UNION ALL SELECT 1 FROM stored_files WHERE folder_id=$1 AND cloud_status<>'deleted'",[id])).rowCount)fail(409,'folder_not_empty','Move or delete the contents first.');await db.query('UPDATE stored_files SET folder_id=NULL WHERE folder_id=$1',[id]);await db.query('DELETE FROM storage_folders WHERE id=$1 AND owner_user_id=$2',[id,actor.userId]);return {ok:true};}); }
  async function activity(actor,q={}) {
    if(actor.role!=='employer'||!actor.companyId)fail(403,'employer_required','Company activity is available to the employer.');
    const params=[actor.companyId],where=['was_public','company_id=$1'];
    const add=v=>{params.push(v);return '$'+params.length;};
    if(q.user_id)where.push(`actor_user_id=${add(uuid(q.user_id))}`);
    if(q.file_id)where.push(`file_id=${add(uuid(q.file_id))}`);
    if(q.action)where.push(`event_type=${add(String(q.action).slice(0,50))}`);
    for(const [key,op] of [['from','>='],['to','<=']])if(q[key]){const d=new Date(q[key]);if(!Number.isFinite(d.getTime()))fail(400,'invalid_date','Invalid activity date.');where.push(`created_at${op}${add(d)}`);}
    if(q.before){let c;try{c=JSON.parse(Buffer.from(q.before,'base64url').toString());}catch{fail(400,'invalid_cursor','Invalid cursor.');}where.push(`(created_at,id)<(${add(c.at)}::timestamptz,${add(uuid(c.id))}::uuid)`);}
    const rows=(await pool.query(`SELECT * FROM storage_activity WHERE ${where.join(' AND ')} ORDER BY created_at DESC,id DESC LIMIT 101`,params)).rows,last=rows[99];
    return {events:rows.slice(0,100).map(r=>({...r,byte_size:Number(r.byte_size)})),next_cursor:rows.length>100?Buffer.from(JSON.stringify({at:last.created_at,id:last.id})).toString('base64url'):null};
  }
  async function verify(actor,ids) {
    if(!Array.isArray(ids)||ids.length>200)fail(400,'invalid_ids','Verify up to 200 files at a time.');
    return {files:(await pool.query(`SELECT f.* FROM stored_files f WHERE ${readableSQL} AND f.cloud_status='active' AND f.id=ANY($3::uuid[])`,[actor.userId,actor.companyId,ids.map(uuid)])).rows.map(r=>publicFile(r,actor))};
  }
  return {verify,usage,list,begin,part,complete,patch,access,acknowledge,state,remove,cleanup,folders,saveFolder,removeFolder,activity,get:async(actor,id)=>publicFile(await file(pool,actor,id),actor)};
}
