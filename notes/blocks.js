import {fail,uuid,text,authorizeConversation} from '../company-comms/access.js';
import {hydrateSources} from '../company-comms/sources.js';
import {storagePredicate} from '../company-comms/assets.js';
import {publicFile} from '../media-storage/domain.js';
import {authorizePage} from './access.js';
import {safeWebpage} from '../browser-contracts.js';
export const BLOCK_TYPES=Object.freeze(['paragraph','heading1','heading2','heading3','bullet','numbered','checklist','toggle','quote','callout','divider','code','toc','image','video','audio','file','drawing','scan','child_page','group','table','database','contact','job','quote_card','stage_entry','service_plan','task','asset','message','conversation','webpage','page_link','synced','template','ai_result']);
const sourceTypes={contact:'contact',job:'job',quote_card:'quote',stage_entry:'stage_entry',service_plan:'service_plan',task:'task'};
export function blockInput(raw) {
 if(!raw||!BLOCK_TYPES.includes(raw.type))fail(400,'invalid_block_type');
 const input=raw.payload||{};if(JSON.stringify(input).length>160000)fail(413,'block_too_large');
 let payload={};
 if(sourceTypes[raw.type])payload={source_type:sourceTypes[raw.type],source_id:text(input.source_id,160),context_type:text(input.context_type||sourceTypes[raw.type],40),...(input.context_id?{context_id:text(input.context_id,160)}:{})};
 else if(['image','video','audio','file','drawing','scan','asset'].includes(raw.type))payload={asset_id:uuid(input.asset_id),...(input.preview_id?{preview_id:uuid(input.preview_id)}:{}),...(typeof input.ocr==='string'?{ocr:input.ocr.slice(0,50000)}:{})};
 else if(['page_link','child_page','database','synced','message','conversation','ai_result'].includes(raw.type))payload={target_id:text(input.target_id,160)};
 else if(raw.type==='webpage')payload={...safeWebpage(input),captured_at:text(input.captured_at||new Date().toISOString(),50)};
 else {
  payload={text:typeof input.text==='string'?input.text.slice(0,50000):''};
  if(input.runs!==undefined){if(!Array.isArray(input.runs)||input.runs.length>3000)fail(400,'invalid_rich_text');payload.runs=input.runs.map(r=>{if(!Number.isInteger(r.start)||!Number.isInteger(r.length)||r.start<0||r.length<0||r.start+r.length>payload.text.length)fail(400,'invalid_rich_range');return {start:r.start,length:r.length,bold:r.bold===true,italic:r.italic===true,underline:r.underline===true,strike:r.strike===true,code:r.code===true,highlight:r.highlight===true,...(r.link?{link:safeWebpage({url:r.link}).url}:{}),...(r.color&&/^#[0-9a-f]{6}$/i.test(r.color)?{color:r.color}:{})};});}
  if(input.mentions!==undefined){if(!Array.isArray(input.mentions)||input.mentions.length>30)fail(400,'invalid_mentions');payload.mentions=input.mentions.map(m=>({user_id:uuid(m.user_id),label:text(m.label,100)})).filter(m=>payload.text.includes('@'+m.label));}
  if(raw.type==='checklist')payload.checked=input.checked===true;
  if(raw.type==='callout')payload.icon=String(input.icon||'💡').slice(0,12);
  if(raw.type==='code')payload.language=String(input.language||'plain').slice(0,40);
  if(raw.type==='table'){if(!Array.isArray(input.cells)||input.cells.length>200||input.cells.some(r=>!Array.isArray(r)||r.length>20||r.some(v=>typeof v!=='string'||v.length>2000)))fail(400,'invalid_table');payload.cells=input.cells;}
 }
 const position=Number(raw.position??0);if(!Number.isFinite(position)||Math.abs(position)>1e9)fail(400,'invalid_position');
 return {id:uuid(raw.id),type:raw.type,parent_id:raw.parent_id?uuid(raw.parent_id):null,position,payload};
}
export async function hydrateBlock(db,actor,block,depth=0) {
 const denied={id:block.id,page_id:block.page_id,parent_id:block.parent_id,position:block.position,type:block.type,revision:block.revision,payload:{},accessible:false,text:'No Access'};
 const p=block.payload;
 try{
  if(sourceTypes[block.type]) {const card=(await hydrateSources(db,actor,[{...p,id:'block'}])).get('block');return card?.accessible&&card.text!=='Unavailable'?{...block,card,accessible:true}:denied;}
  if(['image','video','audio','file','drawing','scan','asset'].includes(block.type)) {
   const acl=await storagePredicate(db,actor);const rows=(await db.query(`SELECT f.* FROM stored_files f WHERE f.id=$3 AND f.company_id=$2 AND f.cloud_status='active' AND (${acl})`,[actor.userId,actor.companyId,p.asset_id])).rows;
   if(!rows.length)return denied;const safePayload={asset_id:p.asset_id,...(p.ocr?{ocr:p.ocr}:{})};let preview;
   if(p.preview_id){const result=await db.query(`SELECT f.* FROM stored_files f WHERE f.id=$3 AND f.company_id=$2 AND f.cloud_status='active' AND (${acl})`,[actor.userId,actor.companyId,p.preview_id]);if(result.rows.length){safePayload.preview_id=p.preview_id;preview=publicFile(result.rows[0],actor);}}
   return {...block,payload:safePayload,attachment:publicFile(rows[0],actor),preview,accessible:true};
  }
  if(['child_page','page_link','database'].includes(block.type)){const {page}=await authorizePage(db,actor,p.target_id);return {...block,card:{accessible:true,interactive:true,title:page.title,source_id:page.id,source_type:'note',revision:page.revision},accessible:true};}
  if(block.type==='ai_result'){
   if(depth>=4)return denied;const result=(await db.query('SELECT * FROM notes_ai_results WHERE id=$1 AND company_id=$2',[uuid(p.target_id),actor.companyId])).rows[0];if(!result)return denied;
   for(const pageId of result.page_ids)await authorizePage(db,actor,pageId);
   for(const source of result.source_blocks)if((await hydrateBlock(db,actor,source,depth+1)).accessible===false)return denied;
   return {...block,text:result.body,accessible:true};
  }
  if(block.type==='synced'){
   if(depth>=4)return denied;const target=(await db.query('SELECT * FROM notes_blocks WHERE id=$1 AND deleted_at IS NULL',[uuid(p.target_id)])).rows[0];if(!target)return denied;await authorizePage(db,actor,target.page_id);const source=await hydrateBlock(db,actor,target,depth+1);return source.accessible===false?denied:{...block,synced:source,accessible:true};
  }
  if(block.type==='conversation'){const room=await authorizeConversation(db,actor,p.target_id);return {...block,card:{title:room.title||'Conversation',conversation_id:room.id},accessible:true};}
  if(block.type==='message'){const m=(await db.query('SELECT m.id,m.body,COALESCE(m.conversation_id,t.conversation_id) AS conversation_id,m.sender_id FROM messages m LEFT JOIN comms_threads t ON t.legacy_channel_id=m.channel_id WHERE m.id=$1 AND m.company_id=$2 AND m.deleted_at IS NULL',[p.target_id,actor.companyId])).rows[0];if(!m)return denied;const c=await authorizeConversation(db,actor,m.conversation_id);if(c.history_from){const valid=(await db.query('SELECT 1 FROM messages WHERE id=$1 AND created_at >= $2',[m.id,c.history_from])).rowCount;if(!valid)return denied;}return {...block,card:{title:m.body,conversation_id:m.conversation_id,message_id:m.id},accessible:true};}
  return {...block,accessible:true};
 }catch(e){if(e.status)return denied;throw e;}
}
export async function validateBlockReferences(db,actor,block) {const safe=await hydrateBlock(db,actor,block);if(safe.accessible===false||block.payload?.preview_id&&!safe.payload?.preview_id)fail(404,'source_unavailable','No Access');}
