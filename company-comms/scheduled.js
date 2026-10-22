import {randomUUID} from 'node:crypto';
import {internalActor,digest} from '../mcp/context.js';
import {evidenceHash} from '../assistant/context.js';
import {restrictFields} from '../mcp/field-policy.js';
import {authorizeConversation,mutate,loadActor,requireCapability,checkRevision,fail,id,uuid,text,audit,publish} from './access.js';
import {authorizeAssets} from './assets.js';
import {hydrateSources,validateShares} from './sources.js';
export function createScheduled({pool,messages,getConnectionManager=()=>null}){
 async function originFor(db,input,actor,old,effect){
  const principal=input[internalActor],invocation=principal?.scheduledInvocation;
  if(!principal){
   if(old?.ai_origin&&input.body?.confirm_ai_takeover===true){await audit(db,actor,'scheduled_ai_human_takeover','scheduled',old.id,{original_connection_id:old.ai_origin.guards?.[0]?.connection_id});return null;}
   return old?.ai_origin||null;
  }
  if(!invocation||!['communications_scheduled_create','communications_scheduled_update'].includes(invocation.operation))fail(403,'scheduled_ai_origin_required');
  const manager=getConnectionManager();if(!manager)fail(503,'connection_manager_unavailable');const checked=await manager.check(principal,invocation.operation);
  restrictFields(invocation.input,checked.policy.denied_input_fields,{write:true});
  const inputHash=digest(invocation.input);let approval=null;
  if(checked.policy.approval){approval=(await db.query("SELECT id FROM mcp_approvals WHERE connection_id=$1 AND operation=$2 AND input_hash=$3 AND policy_revision=$4 AND state IN ('pending','completed') ORDER BY created_at DESC LIMIT 1",[checked.row.id,invocation.operation,inputHash,checked.row.revision])).rows[0]?.id;if(!approval)fail(403,'scheduled_exact_approval_required');}
  const guard={connection_id:checked.row.id,operation:invocation.operation,revision:checked.row.revision,input_hash:inputHash,input_evidence_hash:evidenceHash(invocation.input),input:invocation.input,approval_id:approval};
  const first=old?.ai_origin?.guards?.[0];return {version:1,effect_hash:evidenceHash(effect),guards:first&&first.input_hash!==guard.input_hash?[first,guard]:[guard]};
 }
 async function checkOrigin(db,row){
  if(!row.ai_origin)return;
  const origin=row.ai_origin;if(origin.version!==1||!Array.isArray(origin.guards)||!origin.guards.length||origin.guards.length>2)fail(403,'scheduled_ai_origin_invalid');
  if(origin.effect_hash!==evidenceHash({conversation_id:row.conversation_id,payload:row.payload,send_at:new Date(row.send_at).toISOString(),timezone:row.timezone}))fail(409,'scheduled_ai_content_changed');
  const manager=getConnectionManager();if(!manager)fail(503,'connection_manager_unavailable');
  for(const guard of origin.guards){
   // Lock before delivery so a concurrent revocation cannot pass the check and
   // commit before the atomic internal message effect. Same lock as manager edits. NOWAIT avoids inverting the outer MCP
   // connection → Comms-user lock order; a busy authorization retries next tick.
   const connection=(await db.query('SELECT * FROM mcp_connections WHERE id=$1 AND company_id=$2 AND user_id=$3 FOR UPDATE NOWAIT',[guard.connection_id,row.company_id,row.sender_id])).rows[0];if(!connection)fail(403,'scheduled_ai_connection_unavailable');if(!connection.tool_policy)fail(403,'scheduled_ai_policy_unavailable');
   const principal=await manager.actorFor(connection),checked=await manager.check(principal,guard.operation,{revision:guard.revision});
   if(evidenceHash(guard.input)!==guard.input_evidence_hash)fail(409,'scheduled_ai_input_changed');
   restrictFields(guard.input,checked.policy.denied_input_fields,{write:true});
   // Recheck fields of the actual queued effect as well as the reviewed input.
   restrictFields({...guard.input,body:row.payload.body,asset_ids:row.payload.asset_ids,cards:row.payload.cards,mention_scope:row.payload.mention_scope,mention_user_ids:row.payload.mention_user_ids,reply_root_id:row.payload.reply_root_id,send_at:new Date(row.send_at).toISOString(),timezone:row.timezone},checked.policy.denied_input_fields,{write:true});
   if(checked.policy.approval){const approval=(await db.query("SELECT id FROM mcp_approvals WHERE id=$1 AND connection_id=$2 AND operation=$3 AND input_hash=$4 AND policy_revision=$5 AND state='completed'",[guard.approval_id,guard.connection_id,guard.operation,guard.input_hash,guard.revision])).rows[0];if(!approval)fail(403,'scheduled_ai_approval_unavailable');}
  }
 }

 const validDate=value=>{const stamp=new Date(value);if(!Number.isFinite(stamp.getTime())||stamp.getTime()<Date.now()+1000||stamp.getTime()>Date.now()+366*86400000)fail(400,'invalid_send_time');return stamp;};
 const zone=value=>{try{new Intl.DateTimeFormat('en',{timeZone:value}).format();return value;}catch{fail(400,'invalid_timezone');}};
 async function hydrate(db,actor,row){const {payload,ai_origin,...safe}=row;return {...safe,ai_managed:!!ai_origin,body:payload.body,mention_scope:payload.mention_scope||null,mention_user_ids:payload.mention_user_ids||[],reply_root_id:payload.reply_root_id||null,cards:[...(await hydrateSources(db,actor,(payload.cards||[]).map((r,i)=>({...r,id:String(i)})))).values()],asset_ids:payload.asset_ids||[]};}
 async function list(input,conversationId){const c=await authorizeConversation(pool,input,conversationId);const rows=(await pool.query('SELECT * FROM comms_scheduled_messages WHERE conversation_id=$1 AND sender_id=$2 ORDER BY send_at,id LIMIT 100',[c.id,c.actor.userId])).rows;const out=[];for(const r of rows)out.push(await hydrate(pool,c.actor,r));return out;}
 async function save(input,conversationId,scheduleId,body){return mutate(pool,input,async(db,actor)=>{
  let old;if(scheduleId){old=(await db.query('SELECT * FROM comms_scheduled_messages WHERE id=$1 AND sender_id=$2 AND company_id=$3 FOR UPDATE',[uuid(scheduleId),actor.userId,actor.companyId])).rows[0];if(!old)fail(404,'scheduled_unavailable');checkRevision(old,body.expected_revision);if(old.status!=='scheduled')fail(409,'schedule_not_editable');conversationId=old.conversation_id;}
  const c=await authorizeConversation(db,actor,conversationId,{write:true});const payload={body:text(body.body??old?.payload.body??'',20000,false),asset_ids:body.asset_ids??old?.payload.asset_ids??[],cards:body.cards??old?.payload.cards??[],mention_scope:Object.hasOwn(body,'mention_scope')?body.mention_scope:old?.payload.mention_scope??null,mention_user_ids:body.mention_user_ids??old?.payload.mention_user_ids??[],reply_root_id:Object.hasOwn(body,'reply_root_id')?body.reply_root_id:old?.payload.reply_root_id??null};Object.assign(payload,await messages.validateMentions(db,c.actor,c,{...payload,mention_all:body.mention_all}));if(payload.reply_root_id){const parent=await messages.message(db,c.actor,payload.reply_root_id,c.id);if(parent.deleted_at||parent.reply_root_id)fail(400,'invalid_reply_root');}await authorizeAssets(db,actor,payload.asset_ids);await validateShares(db,actor,payload.cards);if(!payload.body&&!payload.asset_ids.length&&!payload.cards.length)fail(400,'empty_message');
  const when=validDate(body.send_at??old?.send_at),timezone=zone(body.timezone??old?.timezone??'UTC'),key=old?.client_key||id(body.client_key);const aiOrigin=await originFor(db,input,actor,old,{conversation_id:c.id,payload,send_at:when.toISOString(),timezone});
  const row=(await db.query(`INSERT INTO comms_scheduled_messages(id,company_id,conversation_id,sender_id,client_key,payload,send_at,timezone,ai_origin) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$10) ON CONFLICT(company_id,sender_id,client_key) DO UPDATE SET payload=CASE WHEN $9 THEN EXCLUDED.payload ELSE comms_scheduled_messages.payload END,send_at=CASE WHEN $9 THEN EXCLUDED.send_at ELSE comms_scheduled_messages.send_at END,timezone=CASE WHEN $9 THEN EXCLUDED.timezone ELSE comms_scheduled_messages.timezone END,ai_origin=CASE WHEN $9 THEN EXCLUDED.ai_origin ELSE comms_scheduled_messages.ai_origin END,revision=comms_scheduled_messages.revision+CASE WHEN $9 THEN 1 ELSE 0 END,updated_at=now() RETURNING *`,[old?.id||randomUUID(),actor.companyId,c.id,actor.userId,key,JSON.stringify(payload),when,timezone,!!old,aiOrigin?JSON.stringify(aiOrigin):null])).rows[0];if(row.conversation_id!==c.id)fail(409,'idempotency_conflict');await audit(db,actor,old?'scheduled_updated':'scheduled_created','scheduled',row.id);return hydrate(db,actor,row);
 });}
 async function cancel(input,scheduleId,body){return mutate(pool,input,async(db,actor)=>{const row=(await db.query('SELECT * FROM comms_scheduled_messages WHERE id=$1 AND sender_id=$2 AND company_id=$3 FOR UPDATE',[uuid(scheduleId),actor.userId,actor.companyId])).rows[0];if(!row)fail(404,'scheduled_unavailable');checkRevision(row,body.expected_revision);if(row.status==='sent')fail(409,'already_sent');await db.query("UPDATE comms_scheduled_messages SET status='canceled',revision=revision+1,updated_at=now() WHERE id=$1",[scheduleId]);await audit(db,actor,'scheduled_canceled','scheduled',scheduleId);return {ok:true};});}
 async function tick(){const pending=(await pool.query("SELECT id,sender_id,company_id FROM comms_scheduled_messages WHERE status='scheduled' AND send_at<=now() ORDER BY send_at,id LIMIT 20")).rows;for(const p of pending){const db=await pool.connect();try{await db.query('BEGIN');await db.query('SELECT id FROM companies WHERE id=$1 FOR KEY SHARE',[p.company_id]);await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',['comms-permissions:'+p.sender_id]);const row=(await db.query("SELECT * FROM comms_scheduled_messages WHERE id=$1 AND status='scheduled' AND send_at<=now() FOR UPDATE",[p.id])).rows[0];if(!row){await db.query('COMMIT');continue;}await db.query('SAVEPOINT scheduled_send');try{await checkOrigin(db,row);const actor=await loadActor(db,{userId:p.sender_id,companyId:p.company_id});const sent=await messages.sendInTransaction(db,actor,row.conversation_id,{...row.payload,client_key:'scheduled:'+row.id});await db.query("UPDATE comms_scheduled_messages SET status='sent',message_id=$2,revision=revision+1,updated_at=now() WHERE id=$1",[row.id,sent.id]);await audit(db,actor,'scheduled_sent','scheduled',row.id);}catch(error){await db.query('ROLLBACK TO SAVEPOINT scheduled_send');if(error.code!=='55P03')await db.query("UPDATE comms_scheduled_messages SET status='failed',error_code=$2,revision=revision+1,updated_at=now() WHERE id=$1",[row.id,error.status?error.code:'send_unavailable']);}await db.query('COMMIT');}catch(error){await db.query('ROLLBACK');throw error;}finally{db.release();}}}
 return {list,save,cancel,tick};
}
