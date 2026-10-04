import {readableSQL,publicFile} from '../media-storage/domain.js';
import {can,loadActor,conversationJoins,conversationAccessSQL,requireCapability,fail,uuid,authorizeConversation} from './access.js';
import {SOURCE_CAPABILITIES,sourceAccessSQL} from './sources.js';
export async function storagePredicate(db,input){
 const actor=await loadActor(db,input);if(!can(actor,'storage.view'))return 'false';
 const provenance=`NOT EXISTS(SELECT 1 FROM comms_asset_provenance p WHERE p.asset_id=f.id AND (p.company_id IS DISTINCT FROM $2 OR NOT ${sourceAccessSQL(actor,'p')}))`;
 const allowedCapabilities=Object.entries(actor.permissions.capabilities).filter(([,value])=>value===true).map(([key])=>"'"+key.replaceAll("'","''")+"'").join(',');
 const conversationSource=`NOT EXISTS(SELECT 1 FROM comms_asset_conversation_sources src WHERE src.asset_id=f.id AND (src.company_id IS DISTINCT FROM $2 OR NOT src.capability=ANY(ARRAY[${allowedCapabilities}]::text[]) OR NOT EXISTS(SELECT 1 FROM conversations c ${conversationJoins} WHERE c.id=src.conversation_id AND ${conversationAccessSQL(actor)})))`;
 const grant=can(actor,'communications.view')?`EXISTS(SELECT 1 FROM (
 SELECT COALESCE(m.conversation_id,lt.conversation_id) AS conversation_id FROM comms_asset_refs r JOIN messages m ON m.id=r.message_id LEFT JOIN comms_threads lt ON lt.legacy_channel_id=m.channel_id WHERE r.asset_id=f.id AND r.company_id=$2 AND m.deleted_at IS NULL
 UNION SELECT gr.conversation_id FROM comms_asset_grants gr WHERE gr.asset_id=f.id AND gr.company_id=$2 AND gr.revoked_at IS NULL
 ) allowed JOIN conversations c ON c.id=allowed.conversation_id ${conversationJoins} WHERE ${conversationAccessSQL(actor)})`:'false';
 const category=`(f.category<>'audio' OR ${can(actor,'audio.view')?'true':'false'}) AND (f.category NOT IN ('image','video') OR ${can(actor,'media.view')?'true':'false'})`;
 const protectedSource=`(NOT f.source_protected OR EXISTS(SELECT 1 FROM comms_asset_provenance p WHERE p.asset_id=f.id) OR EXISTS(SELECT 1 FROM comms_asset_conversation_sources s WHERE s.asset_id=f.id))`;
 return `((${readableSQL}) OR (${grant})) AND (${protectedSource}) AND (${provenance}) AND (${conversationSource}) AND (${category})`;
}
export async function authorizeAssets(db,actor,assetIds){
 if(!Array.isArray(assetIds)||assetIds.length>20)fail(400,'invalid_attachments');const unique=[...new Set(assetIds.map(uuid))];if(!unique.length)return [];
 requireCapability(actor,'storage.share');const acl=await storagePredicate(db,actor);
 const files=(await db.query(`SELECT f.* FROM stored_files f WHERE f.id=ANY($3::uuid[]) AND f.cloud_status='active' AND (${acl})`,[actor.userId,actor.companyId,unique])).rows;
 if(files.length!==unique.length)fail(403,'attachment_unavailable','A selected file is not available. Finish uploading or refresh your selection.');return unique.map(id=>files.find(file=>file.id===id));
}
export async function hydrateMessageAssets(db,actor,messageIds){
 const acl=await storagePredicate(db,actor),rows=(await db.query(`SELECT r.message_id,r.asset_id,f.source_protected,CASE WHEN (${acl}) AND f.cloud_status='active' THEN to_jsonb(f)-'object_key'-'upload_id'-'upload_expires_at'-'cleanup_after' END AS file FROM comms_asset_refs r JOIN stored_files f ON f.id=r.asset_id WHERE r.message_id=ANY($3::text[]) AND r.company_id=$2 ORDER BY r.sort_order,r.created_at,r.id`,[actor.userId,actor.companyId,messageIds])).rows;
 const result=new Map();for(const row of rows){if(!result.has(row.message_id))result.set(row.message_id,[]);result.get(row.message_id).push(row.file?publicFile(row.file,actor):row.source_protected?{accessible:false,text:'No Access'}:{unavailable:true});}
 // Keep a visible repair placeholder for original URL-only or unmapped attachments.
 // Never forward an unverified historic URL or disclose its filename to the client.
 const unmapped=(await db.query(`SELECT a.message_id FROM message_attachments a JOIN messages m ON m.id=a.message_id WHERE a.message_id=ANY($1::text[]) AND m.company_id=$2 AND NOT EXISTS(SELECT 1 FROM comms_asset_refs r JOIN stored_files f ON f.id=r.asset_id WHERE r.message_id=a.message_id AND f.object_key=a.object_key AND r.company_id=$2) ORDER BY a.created_at,a.id`,[messageIds,actor.companyId])).rows;
 for(const row of unmapped){if(!result.has(row.message_id))result.set(row.message_id,[]);result.get(row.message_id).push({unavailable:true,repair_required:true});}return result;
}
