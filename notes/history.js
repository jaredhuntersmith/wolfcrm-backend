import {createHash} from 'node:crypto';
import {fail} from '../company-comms/access.js';
function stableID(value){const hex=createHash('md5').update(value).digest('hex');return [hex.slice(0,8),hex.slice(8,12),hex.slice(12,16),hex.slice(16,20),hex.slice(20)].join('-');}
// Read the original version table in place. No copied history or lost attachment identities.
export async function readSnapshot(db,page,revision){
 if(!Number.isInteger(revision)||revision<1)fail(400,'invalid_revision');
 const current=(await db.query('SELECT snapshot FROM notes_versions WHERE page_id=$1 AND revision=$2',[page.id,revision])).rows[0];if(current)return current.snapshot;
 const legacy=(await db.query('SELECT * FROM comms_note_versions WHERE note_id=$1 AND revision=$2',[page.id,revision])).rows[0];if(!legacy)fail(404,'version_unavailable');
 const block=(key,type,payload,position)=>({id:stableID(key),page_id:page.id,parent_id:null,type,payload,position,revision:1,creator_id:page.creator_id,editor_id:legacy.editor_id});
 const blocks=[block('wolf-notes-body:'+page.id,'paragraph',{text:legacy.body},0)];
 for(const [i,id] of (legacy.asset_ids||[]).entries())blocks.push(block('wolf-notes-asset:'+page.id+':'+id,'asset',{asset_id:id},i+1));
 for(const [i,ref] of (legacy.source_refs||[]).entries())blocks.push(block('wolf-notes-source:'+page.id+':'+(i+1),ref.source_type==='quote'?'quote_card':ref.source_type,{...ref},101+i));
 return {page:{id:page.id,title:legacy.title,revision},blocks};
}
