export class StorageError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}
export const fail = (status, code, message) => { throw new StorageError(status, code, message); };
export function uuid(value) { if (typeof value !== 'string' || !/^[\da-f]{8}(-[\da-f]{4}){3}-[\da-f]{12}$/i.test(value)) fail(400,'invalid_id','Invalid file or folder identifier.'); return value.toLowerCase(); }
export function name(value) { if (typeof value !== 'string') fail(400,'invalid_name','A name is required.'); const result=value.replace(/[\x00-\x1f\x7f/\\]/g,' ').trim(); if (!result || result.length>255 || result==='.' || result==='..') fail(400,'invalid_name','Use a name between 1 and 255 characters.'); return result; }
export function integer(value, min, max) { if (!Number.isSafeInteger(value) || value<min || value>max) fail(400,'invalid_number','The file size or version is invalid.'); return value; }
export function metadata(value = {}) {
  if (!value || typeof value!=='object' || Array.isArray(value)) fail(400,'invalid_metadata','Invalid metadata.');
  const out={};
  for(const key of ['title','artist','author','album','book']) if(value[key]!=null) { if(typeof value[key]!=='string'||value[key].length>500) fail(400,'invalid_metadata','Metadata text is too long.'); out[key]=value[key]; }
  for(const key of ['duration','width','height','track_number']) if(value[key]!=null) { if(!Number.isFinite(value[key])||value[key]<0||value[key]>1e8) fail(400,'invalid_metadata','Invalid media dimensions or duration.'); out[key]=value[key]; }
  if(value.chapters!=null) { if(!Array.isArray(value.chapters)||value.chapters.length>1000) fail(400,'invalid_metadata','Invalid chapters.'); out.chapters=value.chapters.map(c=>({title:name(c.title),start:integer(c.start,0,1e8)})); }
  return out;
}
export function fileInput(body, maxSize) {
  const original=name(body.original_filename), mime=body.mime_type || 'application/octet-stream';
  if(typeof mime!=='string'||mime.length>150||!/^[-\w.+]+\/[-\w.+]+$/.test(mime)) fail(400,'invalid_mime','Invalid file type.');
  const ext=original.includes('.') ? original.split('.').pop().toLowerCase().slice(0,20) : '';
  let category=mime.startsWith('audio/')?'audio':mime.startsWith('video/')?'video':mime.startsWith('image/')?'image':mime.startsWith('text/')||/pdf|officedocument|msword|excel|opendocument/.test(mime)?'document':/zip|compressed|tar|archive/.test(mime)?'archive':'other';
  if(mime==='application/octet-stream') category=/^(mp3|m4a|m4b|aac|wav|aiff|flac)$/.test(ext)?'audio':/^(mp4|mov|m4v|hevc)$/.test(ext)?'video':/^(jpg|jpeg|png|heic|gif|webp)$/.test(ext)?'image':/^(zip|gz|tar|7z)$/.test(ext)?'archive':'other';
  if(body.audio_subtype!=null&&!['music','audiobook'].includes(body.audio_subtype)) fail(400,'invalid_subtype','Choose Music or Audiobook.');
  return {id:uuid(body.id),original_filename:original,display_name:name(body.display_name||original),mime_type:mime,extension:ext,category,byte_size:integer(body.byte_size,0,maxSize),audio_subtype:body.audio_subtype||(ext==='m4b'?'audiobook':'music'),metadata_json:metadata(body.metadata_json),type_identifier:typeof body.type_identifier==='string'?body.type_identifier.slice(0,150):null};
}
// Used identically for browse, direct access, progress, downloads and every mutation.
export const readableSQL = `(f.owner_user_id=$1 OR (f.visibility='company' AND f.company_id=$2 AND $2::uuid IS NOT NULL AND EXISTS(SELECT 1 FROM users owner WHERE owner.id=f.owner_user_id AND owner.company_id=f.company_id AND owner.deleted_at IS NULL)))`;
export function canDelete(file, actor) { return file.owner_user_id===actor.userId || (actor.role==='employer' && file.visibility==='company' && actor.companyId && file.company_id===actor.companyId); }
export function publicFile(file, actor) {
  const {object_key,upload_id,upload_expires_at,cleanup_after,sharing_active,storage_provider,...safe}=file;
  if(sharing_active===false)safe.visibility='private';
  safe.byte_size=Number(file.byte_size); safe.can_edit=file.owner_user_id===actor.userId; safe.can_delete=Boolean(canDelete(file,actor));
  return safe;
}
