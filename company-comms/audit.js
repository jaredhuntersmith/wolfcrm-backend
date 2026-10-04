import {takeRateLimit} from './rate-limits.js';
import {randomUUID} from 'node:crypto';
import {loadActor,requireCapability,fail,pageLimit,cursor,encodeCursor,audit} from './access.js';
export async function installCommsAudit({app,pool,authRequired}){
 await pool.query(`CREATE TABLE IF NOT EXISTS comms_asset_access_events(id uuid PRIMARY KEY,company_id uuid NOT NULL REFERENCES companies(id),asset_id uuid NOT NULL REFERENCES stored_files(id),actor_id uuid NOT NULL REFERENCES users(id),conversation_id text REFERENCES conversations(id),receipt_id uuid REFERENCES storage_access_receipts(id),action text NOT NULL,window_at timestamptz NOT NULL DEFAULT date_trunc('minute',now()),created_at timestamptz NOT NULL DEFAULT now());
 CREATE UNIQUE INDEX IF NOT EXISTS comms_access_receipt_action ON comms_asset_access_events(receipt_id,action) WHERE receipt_id IS NOT NULL;
 CREATE UNIQUE INDEX IF NOT EXISTS comms_preview_audit_context_once ON comms_asset_access_events(asset_id,actor_id,action,COALESCE(conversation_id,''),window_at) WHERE receipt_id IS NULL;
 DROP INDEX IF EXISTS comms_preview_audit_once;
 CREATE INDEX IF NOT EXISTS comms_access_company_page ON comms_asset_access_events(company_id,created_at DESC,id DESC);`);
 async function record(db,actor,file,action,receipt=null){
  if(!file.company_id)return;
  const scoped=(await db.query(`SELECT 1 FROM comms_asset_refs WHERE asset_id=$1 UNION ALL SELECT 1 FROM comms_asset_grants WHERE asset_id=$1 UNION ALL SELECT 1 FROM comms_asset_provenance WHERE asset_id=$1 UNION ALL SELECT 1 FROM comms_asset_conversation_sources WHERE asset_id=$1 LIMIT 1`,[file.id])).rowCount;if(!scoped&&!actor.commsConversationId)return;
  // A source context is accepted only after independently checking the visible conversation.
  let context=actor.commsConversationId||null;
  if(receipt&&!context){context=(await db.query("SELECT conversation_id FROM comms_asset_access_events WHERE receipt_id=$1 AND action='download_authorized'",[receipt])).rows[0]?.conversation_id||null;}
  if(context){
   const {authorizeConversation}=await import('./access.js');const c=await authorizeConversation(db,actor,context);
   const linked=(await db.query(`SELECT 1 FROM comms_asset_refs r JOIN messages m ON m.id=r.message_id LEFT JOIN conversation_participants cp ON cp.conversation_id=$2 AND cp.user_id=$4 WHERE r.asset_id=$1 AND m.deleted_at IS NULL AND (m.conversation_id=$2 OR m.channel_id=$3) AND m.created_at>=COALESCE(cp.history_from,'-infinity') UNION ALL SELECT 1 FROM comms_asset_grants gr WHERE gr.asset_id=$1 AND gr.conversation_id=$2 AND gr.revoked_at IS NULL LIMIT 1`,[file.id,c.id,c.legacy_channel_id,actor.userId])).rowCount;
   if(!linked)fail(404,'attachment_unavailable');
  }
  await db.query(`INSERT INTO comms_asset_access_events(id,company_id,asset_id,actor_id,conversation_id,receipt_id,action) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,[randomUUID(),file.company_id,file.id,actor.userId,context,receipt,action]);
 }
 app.get('/api/comms/audit',authRequired,async(req,res)=>{res.set('Cache-Control','private, no-store');try{
  await takeRateLimit(pool,req);const actor=await loadActor(pool,req);requireCapability(actor,'communications.audit');if(!actor.isCompanyOwner)fail(403,'owner_required');
  const limit=pageLimit(req.query.limit),before=cursor(req.query.cursor),values=[actor.companyId];let range='';if(before){values.push(before.at,before.id);range='AND (created_at,id)<($2::timestamptz,$3::uuid)';}values.push(limit+1);
  const rows=(await pool.query(`SELECT *,to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS cursor_at FROM (SELECT id,actor_id,action,subject_type,subject_id,created_at,NULL::text AS conversation_id FROM comms_audit WHERE company_id=$1 UNION ALL SELECT id,actor_id,action,'asset',asset_id::text,created_at,conversation_id FROM comms_asset_access_events WHERE company_id=$1) events WHERE true ${range} ORDER BY created_at DESC,id DESC LIMIT $${values.length}`,values)).rows;
  await audit(pool,actor,'audit_viewed','company',actor.companyId);
  res.json({events:rows.slice(0,limit).map(({cursor_at,...row})=>row),next_cursor:rows.length>limit?encodeCursor({...rows[limit-1],created_at:rows[limit-1].cursor_at}):null,privacy:'Audit entries identify actors, assets and actions. They do not grant access to private conversation content. Transfer started and saved are client-reported events; exported copies cannot be recalled.'});
 }catch(e){res.status(e.status||503).json({error:e.code||'audit_unavailable',message:e.status?e.message:'Audit is temporarily unavailable.'});}});
 return {record};
}
