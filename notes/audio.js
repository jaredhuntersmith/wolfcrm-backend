import {createStorageBucket,PART_SIZE} from '../media-storage/bucket.js';
import {mutate,uuid,fail,requireCapability} from '../company-comms/access.js';
import {authorizePage} from './access.js';

// Immutable, page-owned recordings. They deliberately never enter stored_files.
export function createNotesAudio({pool,bucket=createStorageBucket(),storage}) {
 const dto=row=>({id:row.id,page_id:row.page_id,duration:Number(row.duration),byte_size:Number(row.byte_size),ready:row.ready,part_size:PART_SIZE});
 const requireBucket=()=>{if(!bucket)fail(503,'notes_audio_unavailable');};
 async function authorized(db,input,pageId,id,write=false) {
  const {actor,page}=await authorizePage(db,input,pageId,{level:write?3:1});
  if(write&&page.archived_at)fail(409,'note_archived');
  const row=(await db.query('SELECT * FROM notes_audio WHERE id=$1 AND page_id=$2 AND company_id=$3',[uuid(id),page.id,actor.companyId])).rows[0];
  if(!row)fail(404,'recording_unavailable');return {actor,row};
 }
 async function reserve(input,pageId,body) {
  requireBucket();
  return mutate(pool,input,async(db,actor)=>{
   const {page}=await authorizePage(db,actor,pageId,{level:3});if(page.archived_at)fail(409,'note_archived');
   const id=uuid(body.id),size=Number(body.byte_size),duration=Number(body.duration),hash=body.sha256;
   if(!Number.isSafeInteger(size)||size<1||size>268435456||!Number.isFinite(duration)||duration<=0||duration>86400||!/^[a-f0-9]{64}$/.test(hash||''))fail(400,'invalid_recording');
   await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',['notes-audio:'+id]);
   let row=(await db.query('SELECT * FROM notes_audio WHERE id=$1',[id])).rows[0];
   if(row){
    if(row.page_id!==page.id||row.company_id!==actor.companyId||Number(row.byte_size)!==size||row.sha256!==hash)fail(409,'recording_identity_conflict');
    if(!row.ready){
     const head=await bucket.head(row);
     if(head){
      if(Number(head.ContentLength)!==size)fail(409,'recording_size_mismatch');
      await db.query('UPDATE notes_audio SET ready=true WHERE id=$1',[id]);row.ready=true;
     }else{
      try{await bucket.parts(row);}catch(error){
       if(error.name!=='NoSuchUpload'&&error.code!=='NoSuchUpload')throw error;
       row.upload_id=await bucket.begin(row);await db.query('UPDATE notes_audio SET upload_id=$2 WHERE id=$1',[id,row.upload_id]);
      }
     }
    }
    return dto(row);
   }
   row={id,page_id:page.id,company_id:actor.companyId,owner_user_id:actor.userId,byte_size:size,duration,sha256:hash,mime_type:'audio/mp4',original_filename:'Voice Note.m4a',object_key:`notes/${actor.companyId}/${page.id}/${id}.m4a`,ready:false};
   row.upload_id=await bucket.begin(row);
   await db.query(`INSERT INTO notes_audio(id,page_id,company_id,owner_user_id,byte_size,duration,sha256,object_key,upload_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[id,page.id,actor.companyId,actor.userId,size,duration,hash,row.object_key,row.upload_id]);
   return dto(row);
  });
 }
 async function part(input,pageId,id,number) {
  requireBucket();const {row}=await authorized(pool,input,pageId,id,true);
  const count=Math.ceil(Number(row.byte_size)/PART_SIZE);
  if(!Number.isInteger(number)||number<1||number>count)fail(400,'invalid_part');
  if(row.ready)return {ready:true};
  return {url:await bucket.part(row,number,Math.min(PART_SIZE,Number(row.byte_size)-(number-1)*PART_SIZE))};
 }
 async function complete(input,pageId,id) {
  requireBucket();
  return mutate(pool,input,async(db,actor)=>{
   await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',['notes-audio:'+uuid(id)]);
   const {row}=await authorized(db,actor,pageId,id,true);if(row.ready)return dto(row);
   let head=await bucket.head(row);
   if(!head){
    const parts=await bucket.parts(row),count=Math.ceil(Number(row.byte_size)/PART_SIZE);
    if(parts.length!==count||parts.some((part,index)=>part.PartNumber!==index+1||Number(part.Size)!==Math.min(PART_SIZE,Number(row.byte_size)-index*PART_SIZE)))fail(409,'recording_upload_incomplete');
    await bucket.complete(row,parts);head=await bucket.head(row);
   }
   if(!head||Number(head.ContentLength)!==Number(row.byte_size))fail(409,'recording_size_mismatch');
   await db.query('UPDATE notes_audio SET ready=true WHERE id=$1',[row.id]);return dto({...row,ready:true});
  });
 }
 async function access(input,pageId,id) {
  requireBucket();const {row}=await authorized(pool,input,pageId,id);if(!row.ready)fail(409,'recording_upload_incomplete');
  if(!storage?.issueSourceDelivery)fail(503,'notes_audio_delivery_unavailable','Recording playback is temporarily unavailable.');
  return {url:await storage.issueSourceDelivery(input,'notes_audio',row.id,{purpose:'stream'}),expires_in:300,...dto(row)};
 }
 if(storage?.registerDeliverySource)storage.registerDeliverySource('notes_audio',{bucket,authorize:async(actor,id)=>{
  const row=(await pool.query('SELECT page_id FROM notes_audio WHERE id=$1 AND company_id=$2',[uuid(id),actor.companyId])).rows[0];
  if(!row)fail(404,'recording_unavailable');
  const result=await authorized(pool,actor,row.page_id,id);requireCapability(result.actor,'audio.play');if(!result.row.ready)fail(409,'recording_upload_incomplete');
  return {...result.row,original_filename:'Voice Note.m4a',mime_type:'audio/mp4'};
 }});
 return {reserve,part,complete,access};
}
