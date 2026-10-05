import {randomUUID,createHash} from 'node:crypto';
import {loadActor,can,requireCapability,conversationJoins,conversationAccessSQL,mutate,publish,fail,id,text,cursor,encodeCursor,pageLimit} from './access.js';
import {sourceAccessSQL} from './sources.js';
export async function installNotificationsSchema(db){
 await db.query(`
 ALTER TABLE notifications ADD COLUMN IF NOT EXISTS requirements jsonb NOT NULL DEFAULT '[]';
 ALTER TABLE notifications ADD COLUMN IF NOT EXISTS source_refs jsonb NOT NULL DEFAULT '[]';
 ALTER TABLE notifications ADD COLUMN IF NOT EXISTS conversation_id text REFERENCES conversations(id);
 ALTER TABLE notifications ADD COLUMN IF NOT EXISTS event_key text;
 ALTER TABLE notifications ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
 CREATE UNIQUE INDEX IF NOT EXISTS notifications_event_recipient ON notifications(user_id,event_key) WHERE event_key IS NOT NULL;
 CREATE INDEX IF NOT EXISTS notifications_inbox_page ON notifications(user_id,company_id,created_at DESC,id DESC) WHERE deleted_at IS NULL;
 CREATE TABLE IF NOT EXISTS notification_delivery_outbox(notification_id text PRIMARY KEY REFERENCES notifications(id),attempts integer NOT NULL DEFAULT 0,next_attempt_at timestamptz NOT NULL DEFAULT now(),delivered_at timestamptz,last_error text);
 CREATE TABLE IF NOT EXISTS notification_preferences(user_id uuid PRIMARY KEY REFERENCES users(id),company_id uuid NOT NULL REFERENCES companies(id),muted boolean NOT NULL DEFAULT false,quiet_start integer CHECK(quiet_start BETWEEN 0 AND 1439),quiet_end integer CHECK(quiet_end BETWEEN 0 AND 1439),timezone text NOT NULL DEFAULT 'UTC');
 CREATE OR REPLACE FUNCTION comms_prepare_notification() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN
  IF TG_OP='INSERT' AND NEW.event_key IS NULL THEN
   NEW.event_key := COALESCE(NEW.data->>'event_id',NEW.data->>'message_id',NEW.data->>'submission_id',NEW.data->>'call_id',NEW.data->>'voicemail_id');
   IF NEW.event_key IS NOT NULL THEN NEW.event_key:=NEW.kind||':'||NEW.event_key; END IF;
  END IF;
  IF NEW.requirements='[]'::jsonb THEN
   NEW.requirements := CASE WHEN NEW.kind IN ('internal_message','channel_message') OR NEW.kind LIKE 'comms.%' THEN '["communications.view"]'::jsonb
   WHEN NEW.kind IN ('job_assignment','job_scheduled','weather_risk') THEN '["schedule.view","jobs.view"]'::jsonb
   WHEN NEW.kind IN ('new_lead','lead') THEN '["contacts.view"]'::jsonb
   WHEN NEW.kind='agreement' THEN '["quotes.view","contacts.view"]'::jsonb
   WHEN NEW.kind IN ('missed_call','voicemail') THEN '["customer.calls.view"]'::jsonb
   WHEN NEW.kind IN ('cellular_sms','imessage','sms') THEN '["messaging.customer.view"]'::jsonb ELSE '[]'::jsonb END;
  END IF;
  IF NEW.source_refs='[]'::jsonb THEN
   IF NEW.data ? 'schedule_event_id' THEN NEW.source_refs:=jsonb_build_array(jsonb_build_object('source_type','job','source_id',NEW.data->>'schedule_event_id','context_type','job'));
   ELSIF NEW.data ? 'quote_id' THEN NEW.source_refs:=jsonb_build_array(jsonb_build_object('source_type','quote','source_id',NEW.data->>'quote_id','context_type','quote'));
   ELSIF NEW.data ? 'contact_id' THEN NEW.source_refs:=jsonb_build_array(jsonb_build_object('source_type','contact','source_id',NEW.data->>'contact_id','context_type','contact')); END IF;
  END IF;
  IF NEW.conversation_id IS NULL AND NEW.kind IN ('internal_message','channel_message') THEN
   IF NEW.data ? 'conversation_id' THEN SELECT c.id INTO NEW.conversation_id FROM conversations c WHERE c.id=NEW.data->>'conversation_id' AND c.company_id=NEW.company_id;
   ELSIF NEW.data ? 'channel_id' THEN SELECT t.conversation_id INTO NEW.conversation_id FROM comms_threads t WHERE t.legacy_channel_id=NEW.data->>'channel_id' AND t.company_id=NEW.company_id; END IF;
  END IF;
  RETURN NEW;
 END $$;
 DROP TRIGGER IF EXISTS comms_prepare_notification ON notifications;
 CREATE TRIGGER comms_prepare_notification BEFORE INSERT OR UPDATE OF requirements ON notifications FOR EACH ROW EXECUTE FUNCTION comms_prepare_notification();
 UPDATE notifications SET requirements=requirements WHERE requirements='[]'::jsonb AND event_key IS NULL;
 CREATE OR REPLACE FUNCTION comms_dispatch_notification() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  INSERT INTO notification_delivery_outbox(notification_id) VALUES(NEW.id) ON CONFLICT DO NOTHING;
  INSERT INTO comms_events(company_id,recipient_id,event_type,entity_id) SELECT NEW.company_id,NEW.user_id,'notification.created',NEW.id WHERE NEW.company_id IS NOT NULL;
  RETURN NEW; END $$;
 DROP TRIGGER IF EXISTS comms_dispatch_notification ON notifications;
 CREATE TRIGGER comms_dispatch_notification AFTER INSERT ON notifications FOR EACH ROW EXECUTE FUNCTION comms_dispatch_notification();
 CREATE OR REPLACE FUNCTION comms_bridge_lead_notification() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  INSERT INTO notifications(id,user_id,company_id,kind,title,body,data,created_at,event_key)
  VALUES('legacy-lead:'||NEW.id::text,NEW.user_id,NEW.company_id,CASE WHEN NEW.title='Agreement update' THEN 'agreement' ELSE 'new_lead' END,NEW.title,NEW.body,jsonb_build_object('contact_id',NEW.contact_id),NEW.created_at,'lead:'||NEW.id::text) ON CONFLICT DO NOTHING;
  RETURN NEW; END $$;
 DROP TRIGGER IF EXISTS comms_bridge_lead_notification ON lead_notifications;
 CREATE TRIGGER comms_bridge_lead_notification AFTER INSERT ON lead_notifications FOR EACH ROW EXECUTE FUNCTION comms_bridge_lead_notification();
 INSERT INTO notifications(id,user_id,company_id,kind,title,body,data,created_at,event_key,read_at)
 SELECT 'legacy-lead:'||l.id::text,l.user_id,l.company_id,CASE WHEN l.title='Agreement update' THEN 'agreement' ELSE 'new_lead' END,l.title,l.body,jsonb_build_object('contact_id',l.contact_id),l.created_at,'lead:'||l.id::text,l.delivered_at FROM lead_notifications l ON CONFLICT DO NOTHING;
 `);
 // Backfill is retained in inbox but deliberately does not resend years of historical pushes.
 await db.query(`UPDATE notification_delivery_outbox o SET delivered_at=now(),last_error='historical_backfill' FROM notifications n WHERE n.id=o.notification_id AND n.created_at<now()-interval '5 minutes' AND o.delivered_at IS NULL`);
}
export function notificationAccessSQL(actor){
 const denied=Object.entries(actor.permissions.capabilities).filter(([,allowed])=>!allowed).map(([key])=>key);
 const capabilities=denied.length?`NOT (n.requirements ?| ARRAY[${denied.map(k=>"'"+k.replaceAll("'","''")+"'").join(',')}]::text[])`:'true';
 // Unknown requirements fail closed as well: only capabilities explicitly true are accepted.
 const allowed=Object.entries(actor.permissions.capabilities).filter(([,v])=>v).map(([k])=>k);
 const known=`NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(n.requirements) k WHERE NOT (k=ANY(ARRAY[${allowed.map(k=>"'"+k.replaceAll("'","''")+"'").join(',')}]::text[])))`;
 const refs=`NOT EXISTS(SELECT 1 FROM jsonb_to_recordset(n.source_refs) AS r(source_type text,source_id text,context_type text,context_id text) WHERE NOT ${sourceAccessSQL(actor,'r')})`;
 const conversation=can(actor,'communications.view')?`EXISTS(SELECT 1 FROM conversations c ${conversationJoins} WHERE c.id=n.conversation_id AND ${conversationAccessSQL(actor)})`:'false';
 return `(${capabilities} AND ${known} AND ${refs} AND (n.conversation_id IS NULL OR ${conversation}))`;
}
export function createNotifications({pool,sendPush}){
 async function enqueue(db,{userId,companyId,kind,title,body='',data={},eventKey,requirements=[],sourceRefs=[],conversationId=null}){
  if(!userId||!companyId)return null;
  const key=eventKey||data.event_id||data.message_id||data.submission_id||data.call_id||data.voicemail_id;
  const result=await db.query(`INSERT INTO notifications(id,user_id,company_id,kind,title,body,data,event_key,requirements,source_refs,conversation_id) SELECT $1,u.id,u.company_id,$4,$5,$6,$7,$8,$9,$10,$11 FROM users u WHERE u.id=$2 AND u.company_id=$3 AND u.deleted_at IS NULL ON CONFLICT DO NOTHING RETURNING id`,[randomUUID(),userId,companyId,kind,title,body,JSON.stringify(data),key?kind+':'+key:null,JSON.stringify(requirements),JSON.stringify(sourceRefs),conversationId]);
  return result.rows[0]?.id||null;
 }
 async function notify(db,actor,event){for(const userId of [...new Set(event.recipients)])await enqueue(db,{userId,companyId:actor.companyId,kind:event.kind,title:event.title,body:event.body,eventKey:event.key,requirements:['communications.view'],sourceRefs:[],conversationId:event.conversation_id,data:{message_id:event.message_id}});}
 async function list(input,q={}){
  const actor=await loadActor(pool,input);requireCapability(actor,'notifications.view');const acl=notificationAccessSQL(actor),values=[actor.userId,actor.companyId],conditions=['n.user_id=$1','n.company_id=$2','n.deleted_at IS NULL'];const add=v=>{values.push(v);return '$'+values.length;};
  if(q.unread==='true')conditions.push('n.read_at IS NULL',acl);if(q.kind){conditions.push('n.kind='+add(text(q.kind,80)),acl);}
  if(q.search){conditions.push(acl,`(n.title||' '||COALESCE(n.body,'')) ILIKE ${add('%'+text(q.search,200).replace(/[\\%_]/g,'\\$&')+'%')}`);}
  const before=cursor(q.cursor);if(before)conditions.push(`(n.created_at,n.id)<(${add(before.at)}::timestamptz,${add(before.id)})`);
  const limit=pageLimit(q.limit),rows=(await pool.query(`SELECT n.id,n.kind,n.title,n.body,n.created_at,n.created_at::text AS cursor_created_at,n.read_at,${acl} AS accessible FROM notifications n WHERE ${conditions.join(' AND ')} ORDER BY n.created_at DESC,n.id DESC LIMIT ${add(limit+1)}`,values)).rows;
  const count=(await pool.query(`SELECT count(*)::int AS count FROM notifications n WHERE n.user_id=$1 AND n.company_id=$2 AND n.deleted_at IS NULL AND n.read_at IS NULL AND ${acl}`,[actor.userId,actor.companyId])).rows[0].count;
  return {notifications:rows.slice(0,limit).map(({cursor_created_at,...r})=>r.accessible?r:{id:r.id,kind:'notification',title:'',body:'No Access',created_at:r.created_at,read_at:r.read_at,accessible:false}),next_cursor:rows.length>limit?encodeCursor(rows[limit-1]):null,unread_count:count};
 }
 async function get(input,notificationId){const actor=await loadActor(pool,input);requireCapability(actor,'notifications.view');const row=(await pool.query(`SELECT n.id,n.kind,n.title,n.body,n.created_at,n.read_at,${notificationAccessSQL(actor)} AS accessible FROM notifications n WHERE n.user_id=$1 AND n.company_id=$2 AND n.id=$3 AND n.deleted_at IS NULL`,[actor.userId,actor.companyId,id(notificationId)])).rows[0];if(!row)fail(404,'notification_unavailable');return row.accessible?row:{id:row.id,kind:'notification',title:'',body:'No Access',created_at:row.created_at,read_at:row.read_at,accessible:false};}
 async function change(input,body,remove=false){return mutate(pool,input,async(db,actor)=>{requireCapability(actor,'notifications.view');if(body.all!==true&&(!Array.isArray(body.ids)||!body.ids.length||body.ids.length>100))fail(400,'notification_ids_required');if(remove&&body.all&&body.confirm!==true)fail(400,'confirm_deletion_required');const params=[actor.userId,actor.companyId],where=body.all?'true':'id=ANY($3::text[])';if(!body.all)params.push(body.ids.map(id));
  const assignment=remove?'deleted_at=now()':body.read===false?'read_at=NULL':'read_at=COALESCE(read_at,now())';const result=await db.query(`UPDATE notifications SET ${assignment} WHERE user_id=$1 AND company_id=$2 AND deleted_at IS NULL AND ${where}`,params);await db.query(`INSERT INTO comms_events(company_id,recipient_id,event_type,entity_id) VALUES($1,$2::uuid,'notification.changed',$2::text)`,[actor.companyId,actor.userId]);return {ok:true,changed:result.rowCount};});}
 async function preferences(input,body){return mutate(pool,input,async(db,actor)=>{requireCapability(actor,'notifications.view');try{new Intl.DateTimeFormat('en',{timeZone:body.timezone||'UTC'}).format();}catch{fail(400,'invalid_timezone');}for(const key of ['quiet_start','quiet_end'])if(body[key]!=null&&(!Number.isInteger(body[key])||body[key]<0||body[key]>1439))fail(400,'invalid_quiet_hours');return (await db.query(`INSERT INTO notification_preferences(user_id,company_id,muted,quiet_start,quiet_end,timezone) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(user_id) DO UPDATE SET muted=$3,quiet_start=$4,quiet_end=$5,timezone=$6 RETURNING *`,[actor.userId,actor.companyId,body.muted===true,body.quiet_start??null,body.quiet_end??null,body.timezone||'UTC'])).rows[0];});}
 async function deliver(){
  if(!sendPush)return;const db=await pool.connect();try{await db.query('BEGIN');const rows=(await db.query(`SELECT o.*,n.user_id,n.company_id,n.conversation_id,n.kind,n.deleted_at FROM notification_delivery_outbox o JOIN notifications n ON n.id=o.notification_id WHERE o.delivered_at IS NULL AND o.next_attempt_at<=now() ORDER BY o.next_attempt_at LIMIT 20 FOR UPDATE OF o SKIP LOCKED`)).rows;
   for(const row of rows){await db.query('SAVEPOINT notification_attempt');try{
    let permitted=false,actor;try{actor=await loadActor(db,{userId:row.user_id,companyId:row.company_id});permitted=can(actor,'notifications.view')&&!row.deleted_at&&(await db.query(`SELECT 1 FROM notifications n WHERE n.id=$3 AND ${notificationAccessSQL(actor)}`,[row.user_id,row.company_id,row.notification_id])).rowCount>0;}catch(e){if(!e.status)throw e;}
    const prefs=(await db.query('SELECT * FROM notification_preferences WHERE user_id=$1',[row.user_id])).rows[0];let quiet=prefs?.muted;if(row.kind.startsWith('comms.'))quiet||=(await db.query("SELECT 1 FROM comms_presence WHERE user_id=$1 AND availability='dnd' AND expires_at>now()",[row.user_id])).rowCount>0;
    if(actor?.notesReady&&['notes.comment','notes.mention'].includes(row.kind)){const setting=row.kind==='notes.mention'?'mention_push':'comment_push';const notePrefs=(await db.query('SELECT settings FROM notes_preferences WHERE user_id=$1',[row.user_id])).rows[0]?.settings;quiet ||= notePrefs?.[setting]===false;}
    if(prefs?.quiet_start!=null&&prefs.quiet_end!=null){const parts=new Intl.DateTimeFormat('en-GB',{timeZone:prefs.timezone,hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).formatToParts();const minute=Number(parts.find(x=>x.type==='hour')?.value)*60+Number(parts.find(x=>x.type==='minute')?.value);quiet ||= prefs.quiet_start<=prefs.quiet_end?minute>=prefs.quiet_start&&minute<prefs.quiet_end:minute>=prefs.quiet_start||minute<prefs.quiet_end;}
    if(row.conversation_id){const muted=(await db.query(`SELECT 1 FROM comms_preferences p WHERE p.user_id=$1 AND p.muted AND (p.subject_type='conversation' AND p.subject_id=$2 OR p.subject_type IN ('group','section','thread') AND EXISTS(SELECT 1 FROM comms_threads t WHERE t.conversation_id=$2 AND CASE p.subject_type WHEN 'group' THEN t.group_id::text WHEN 'section' THEN t.section_id::text ELSE t.id::text END=p.subject_id))`,[row.user_id,row.conversation_id])).rowCount;quiet ||= muted>0;}
    if(permitted&&!quiet){const result=await sendPush([row.user_id],row.kind,{title:'WolfCRM notification',body:'Open your notification inbox to read this update.',payload:{type:'notification',notification_id:row.notification_id},threadId:'wolf-inbox',collapseId:row.notification_id,inboxDelivery:true});if(result?.failed>0||result?.skipped&&['not_configured','provider_unavailable'].includes(result.reason))throw new Error('push_pending');}
    await db.query(`UPDATE notification_delivery_outbox SET delivered_at=now(),last_error=$2 WHERE notification_id=$1`,[row.notification_id,!permitted?'access_unavailable':quiet?'delivery_muted':null]);
   }catch(e){await db.query('ROLLBACK TO SAVEPOINT notification_attempt');await db.query(`UPDATE notification_delivery_outbox SET attempts=attempts+1,next_attempt_at=now()+least(3600,power(2,least(attempts+1,12))) * interval '1 second',last_error='delivery_retry' WHERE notification_id=$1`,[row.notification_id]);}finally{await db.query('RELEASE SAVEPOINT notification_attempt');}}
   await db.query('COMMIT');
  }catch(e){await db.query('ROLLBACK');throw e;}finally{db.release();}
 }
 async function fromPush(userIds,kind,options={}){const rows=(await pool.query('SELECT id,company_id FROM users WHERE id=ANY($1::uuid[]) AND deleted_at IS NULL',[userIds])).rows;for(const user of rows){const data={...(options.payload||{})};if(options.contactId)data.contact_id=options.contactId;const eventKey=options.collapseId||data.event_id||data.message_id||data.call_id||data.voicemail_id;await enqueue(pool,{userId:user.id,companyId:user.company_id,kind,title:options.title||'WolfCRM',body:options.body||'',data,eventKey});}return {queued:true};}
 return {enqueue,notify,list,get,change,preferences,deliver,fromPush};
}
