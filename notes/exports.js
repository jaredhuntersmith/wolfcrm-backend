import {publicFile} from '../media-storage/domain.js';
import {createHash} from 'node:crypto';
import {mutate,requireCapability,uuid,fail} from '../company-comms/access.js';
import {authorizePage} from './access.js';
import {hydrateBlock} from './blocks.js';
export function createNotesExports({pool,storage}) {
 async function prepare(db,input,pageId,mode='share') {
  const {actor,page}=await authorizePage(db,input,pageId);requireCapability(actor,'notes.export');const rows=(await db.query('SELECT * FROM notes_blocks WHERE page_id=$1 AND deleted_at IS NULL ORDER BY position,id',[pageId])).rows;const blocks=[];let size=0;
  for(const row of rows){const hydrated=await hydrateBlock(db,actor,row);let block=hydrated;
   // A cloud copy currently retains note-owned text and reference links only.
   // Never freeze independently protected CRM/file/AI/synced details behind just
   // the page's ACL. Full embedded-media export is available through device share.
   if(mode==='storage'&&hydrated.accessible!==false){block={id:row.id,page_id:row.page_id,type:row.type,position:row.position,revision:row.revision,parent_id:row.parent_id,payload:row.payload,accessible:true};if(['asset','file','image','drawing','scan','video','audio'].includes(row.type))block.payload={asset_id:row.payload.asset_id};if(['ai_result','synced'].includes(row.type))block.payload={};}
   size+=JSON.stringify(block).length;if(size>4_000_000)fail(413,'export_too_large','Export currently supports up to 4 MB of note text.');blocks.push(block);
  }
  const data={page:{id:page.id,title:page.title,revision:page.revision},blocks,mode};return {...data,version:createHash('sha256').update(JSON.stringify(data)).digest('hex')};
 }
 async function context(input,id,mode){return prepare(pool,input,id,mode==='storage'?'storage':'share');}
 async function reserve(input,pageId,body){return mutate(pool,input,async(db,actor)=>{
  if(!storage)fail(503,'storage_unavailable');requireCapability(actor,'storage.upload');const snapshot=await prepare(db,actor,pageId,'storage');if(snapshot.version!==body.version)fail(409,'export_changed','The note changed. Prepare a new export.');const expected={pdf:'application/pdf',md:'text/markdown',txt:'text/plain'}[body.format];if(!expected||body.file?.mime_type!==expected)fail(400,'invalid_export_format');const id=uuid(body.file.id);
  const prior=(await db.query('SELECT f.*,p.source_id,p.source_version FROM stored_files f LEFT JOIN comms_asset_provenance p ON p.asset_id=f.id WHERE f.id=$1',[id])).rows[0];if(prior){if(prior.owner_user_id!==actor.userId||prior.source_id!==pageId||prior.source_version!==snapshot.version||prior.mime_type!==expected||Number(prior.byte_size)!==Number(body.file.byte_size))fail(409,'export_exists');return {file:publicFile(prior,actor)};}const reserved=await storage.reserveInTransaction(db,actor,{...body.file,visibility:'private'},{sourceProtected:true});await db.query("INSERT INTO comms_asset_provenance(asset_id,company_id,source_type,source_id,context_type,source_version) VALUES($1,$2,'note',$3,'note',$4)",[id,actor.companyId,pageId,snapshot.version]);return {file:{...reserved.file,source_protected:true}};
 });}
 return {context,reserve};
}
