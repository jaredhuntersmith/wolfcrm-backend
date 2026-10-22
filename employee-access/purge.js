import {randomUUID} from 'node:crypto';
import {createStorageBucket} from '../media-storage/bucket.js';
import {accountActor,accountTransaction,loadAccount,requireAccountAuthority,requireRevision,recordAccountChange,reject} from './service.js';
import {privateDataPlan,deletePrivateRows,schemaTables,identifier} from './private-data.js';

export async function installPrivatePurgeSchema(db){await db.query(`
 ALTER TABLE employee_private_purge_jobs ADD COLUMN IF NOT EXISTS data_deleted_at timestamptz;
 ALTER TABLE employee_private_purge_jobs ADD COLUMN IF NOT EXISTS file_ids uuid[] NOT NULL DEFAULT '{}';
 ALTER TABLE employee_private_purge_jobs ADD COLUMN IF NOT EXISTS summary jsonb NOT NULL DEFAULT '{}';
 CREATE TABLE IF NOT EXISTS employee_private_objects (
  id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id),company_id uuid NOT NULL REFERENCES companies(id),
  object_key text NOT NULL,storage_provider text NOT NULL,upload_id text,byte_size bigint,category text NOT NULL,
  source_type text NOT NULL,source_id uuid,deleted_at timestamptz,attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),UNIQUE(storage_provider,object_key)
 );
 CREATE INDEX IF NOT EXISTS employee_private_objects_due ON employee_private_objects(next_attempt_at) WHERE deleted_at IS NULL;
 CREATE INDEX IF NOT EXISTS employee_private_objects_user ON employee_private_objects(user_id) WHERE deleted_at IS NULL;
 `);
 // A provider response may arrive after its account was purged. Guard private
 // background writes at the database boundary so stale work cannot recreate it.
 await db.query(`CREATE OR REPLACE FUNCTION wolf_private_write_guard() RETURNS trigger LANGUAGE plpgsql AS $$
 DECLARE account uuid; state text; BEGIN
  account := (to_jsonb(NEW)->>TG_ARGV[0])::uuid;
  IF account IS NULL THEN RETURN NEW; END IF;
  SELECT private_data_state INTO state FROM users WHERE id=account FOR SHARE;
  IF state IN ('purging','purged') AND COALESCE(current_setting('wolf.private_purge_user',true),'')<>account::text
   THEN RAISE EXCEPTION 'private_account_data_unavailable' USING ERRCODE='42501'; END IF;
  RETURN NEW;
 END $$;`);
 const tables=await schemaTables(db);
 for(const [table,columns] of tables){
  const guarded=(table.startsWith('focus_')&&table!=='focus_cost_ledger')||['wolf_assistant_runs','wolf_assistant_conversations','wolf_assistant_memories','wolf_assistant_settings','notes_preferences','notes_smart_folders'].includes(table);
  const column=columns.has('user_id')?'user_id':columns.has('owner_user_id')?'owner_user_id':null;
  if(guarded&&column)await db.query(`DROP TRIGGER IF EXISTS wolf_private_account_guard ON ${identifier(table)}; CREATE TRIGGER wolf_private_account_guard BEFORE INSERT OR UPDATE ON ${identifier(table)} FOR EACH ROW EXECUTE FUNCTION wolf_private_write_guard('${column}')`);
 }
}
export function purgeSummary(plan){return {private_notes:plan.notes.length,private_training_drafts:plan.trainingDrafts?.length||0,private_training_question_banks:plan.trainingBanks?.length||0,private_files:plan.files.length,private_finance_spaces:plan.spaces.length,retained_finance_spaces:plan.retainedFinanceSpaces,private_finance_records_in_retained_spaces:plan.mixedPrivateFinanceRecords||0,private_records:plan.counts.reduce((n,c)=>n+c.count,0),tracked_original_bytes:plan.files.reduce((n,f)=>n+Number(f.byte_size),0)+plan.audioObjects.reduce((n,f)=>n+Number(f.byte_size),0)+plan.receiptObjects.reduce((n,r)=>n+Number(r.byte_size||0),0),retained:'Company-activity Finance workspaces, company history and their connected financial evidence remain restricted and retained. Independent personal Finance records are removed, including eligible records inside retained legacy private workspaces. Unknown relationships remain for review. Employee identity and photo; jobs, hours, pay, commissions, reimbursements; company/shared notes and files; participant-held conversations and referenced training content.',limitations:'Cloud deletion retries until confirmed. Previously downloaded device copies and external providers or backups follow their own retention policies; the app cannot promise remote erasure from those systems.'};}
export function createPrivatePurge({pool,storage,bucket=createStorageBucket(),onChange}){
 async function preview(context,id){return accountTransaction(pool,context,id,async(db,actor,target)=>{
  requireAccountAuthority(actor,target,'team.purge_private');
  if(!target.deleted_at||target.private_data_state!=='recoverable')reject(409,'purge_unavailable','Only disabled accounts with recoverable private data can be permanently deleted.');
  const plan=await privateDataPlan(db,target);return {expected_revision:Number(target.account_revision),preview_token:plan.token,server_time:new Date().toISOString(),recovery_until:target.recovery_until,...purgeSummary(plan)};
 });}
 async function prepare(db,actor,target,input,automatic=false){
  if(!target.deleted_at||target.private_data_state!=='recoverable')reject(409,'purge_unavailable','The account is no longer eligible for private-data deletion.');
  if(automatic&&!(await db.query('SELECT 1 FROM users WHERE id=$1 AND recovery_until<=now()',[target.id])).rowCount)return null;
  // Serialize note tree edits and file sharing with the same locks used by those domains.
  await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))",['notes-tree:'+target.company_id]);
  await db.query('SELECT id FROM stored_files WHERE owner_user_id=$1 AND company_id=$2 ORDER BY id FOR UPDATE',[target.id,target.company_id]);
  const plan=await privateDataPlan(db,target);
  if(!automatic){requireRevision(target,input.expected_revision);if(input.confirmation!=='DELETE PRIVATE DATA'||input.preview_token!==plan.token)reject(409,'purge_preview_changed','Review the current preview and type DELETE PRIVATE DATA to confirm.');}
  await db.query("SELECT set_config('wolf.private_purge_user',$1,true)",[target.id]);
  await db.query("UPDATE users SET private_data_state='purging',operational_eligible=false,account_revision=account_revision+1 WHERE id=$1",[target.id]);
  const objects=[...plan.audioObjects.map(a=>({...a,storage_provider:'storage',source_type:'notes_audio',source_id:a.id,category:'audio'})),...plan.receiptObjects.map(o=>({...o,storage_provider:'legacy_media',source_type:'finance_receipt',category:'image'}))];
  for(const object of objects)await db.query(`INSERT INTO employee_private_objects(id,user_id,company_id,object_key,storage_provider,upload_id,byte_size,category,source_type,source_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(storage_provider,object_key) DO NOTHING`,[randomUUID(),target.id,target.company_id,object.object_key,object.storage_provider,object.upload_id||null,object.byte_size,object.category,object.source_type,object.source_id]);
  await deletePrivateRows(db,plan,target);
  const fileIDs=plan.files.map(f=>f.id);
  await db.query("UPDATE stored_files SET cloud_status='deleting',deleted_at=COALESCE(deleted_at,now()),cleanup_after=now(),version=version+1 WHERE id=ANY($1::uuid[])",[fileIDs]);
  await db.query("UPDATE storage_thumbnails SET cloud_status='deleting' WHERE file_id=ANY($1::uuid[]) AND cloud_status<>'deleted'",[fileIDs]);
  await db.query(`INSERT INTO employee_private_purge_jobs(user_id,company_id,requested_by,data_deleted_at,file_ids,summary) VALUES($1,$2,$3,now(),$4,$5)
   ON CONFLICT(user_id) DO UPDATE SET data_deleted_at=now(),file_ids=EXCLUDED.file_ids,summary=EXCLUDED.summary,next_attempt_at=now(),completed_at=NULL`,[target.id,target.company_id,actor?.id||null,fileIDs,JSON.stringify({...purgeSummary(plan),retained_finance_receipt_ids:plan.retainedFinanceReceiptIDs||[]})]);
  return recordAccountChange(db,actor,target,automatic?'private_purge_expired':'private_purge_requested');
 }
 async function request(context,id,input){const result=await accountTransaction(pool,context,id,async(db,actor,target)=>{requireAccountAuthority(actor,target,'team.purge_private');return prepare(db,actor,target,input);});if(onChange)try{await onChange({id:result.event.id,companyId:result.event.company_id,userId:id,revision:Number(result.event.permission_revision),reason:'private_purge_requested'});}catch{}return {success:true,state:'purging',message:'Private records are unavailable. Cloud cleanup is queued and will retry until confirmed.'};}
 async function expire(id,company){const db=await pool.connect();try{
  await db.query('BEGIN');await db.query('SELECT id FROM companies WHERE id=$1 FOR UPDATE',[company]);await db.query("SELECT pg_advisory_xact_lock(hashtextextended('comms-permissions:'||$1,0))",[id]);await db.query('SELECT id FROM users WHERE id=$1 AND company_id=$2 FOR UPDATE',[id,company]);
  const target=await loadAccount(db,id);if(target.company_id===company&&target.private_data_state==='recoverable')await prepare(db,null,target,{},true);await db.query('COMMIT');
 }catch(error){await db.query('ROLLBACK');await pool.query(`INSERT INTO employee_private_purge_jobs(user_id,company_id,attempts,last_error_code,next_attempt_at) VALUES($1,$2,1,$3,now()+interval '5 minutes') ON CONFLICT(user_id) DO UPDATE SET attempts=employee_private_purge_jobs.attempts+1,last_error_code=$3,next_attempt_at=now()+interval '5 minutes'`,[id,company,error.code||'purge_retry']);}finally{db.release();}}
 async function cleanObjects(){if(!bucket)return;const db=await pool.connect();try{await db.query('BEGIN');const rows=(await db.query('SELECT * FROM employee_private_objects WHERE deleted_at IS NULL AND next_attempt_at<=now() ORDER BY next_attempt_at LIMIT 20 FOR UPDATE SKIP LOCKED')).rows;
  for(const row of rows)try{await bucket.abort(row);await bucket.remove(row);await db.query('UPDATE employee_private_objects SET deleted_at=now(),upload_id=NULL WHERE id=$1',[row.id]);if(row.source_type==='notes_audio')await db.query('DELETE FROM notes_audio WHERE id=$1',[row.source_id]);}catch{await db.query("UPDATE employee_private_objects SET attempts=attempts+1,next_attempt_at=now()+interval '5 minutes' WHERE id=$1",[row.id]);}
  await db.query('COMMIT');}catch(error){await db.query('ROLLBACK');throw error;}finally{db.release();}}
 async function finish(){const jobs=(await pool.query(`SELECT j.* FROM employee_private_purge_jobs j WHERE j.completed_at IS NULL AND j.data_deleted_at IS NOT NULL AND NOT EXISTS(SELECT 1 FROM stored_files f WHERE f.id=ANY(j.file_ids) AND f.cloud_status<>'deleted') AND NOT EXISTS(SELECT 1 FROM storage_thumbnails t WHERE t.file_id=ANY(j.file_ids) AND t.cloud_status<>'deleted') AND NOT EXISTS(SELECT 1 FROM employee_private_objects o WHERE o.user_id=j.user_id AND o.deleted_at IS NULL) LIMIT 20`)).rows;
  for(const job of jobs){const db=await pool.connect();try{await db.query('BEGIN');await db.query('SELECT id FROM companies WHERE id=$1 FOR UPDATE',[job.company_id]);const target=(await db.query("SELECT id FROM users WHERE id=$1 AND private_data_state='purging' FOR UPDATE",[job.user_id])).rows[0];if(target){await db.query("UPDATE users SET private_data_state='purged',private_purged_at=now(),account_revision=account_revision+1 WHERE id=$1",[job.user_id]);await db.query("UPDATE stored_files SET display_name='Deleted file',original_filename='Deleted file',metadata_json='{}',folder_id=NULL WHERE id=ANY($1::uuid[])",[job.file_ids]);await db.query("UPDATE storage_activity SET file_name='Deleted file' WHERE file_id=ANY($1::uuid[]) AND NOT was_public",[job.file_ids]);await db.query('UPDATE employee_private_purge_jobs SET completed_at=now(),last_error_code=NULL WHERE user_id=$1',[job.user_id]);}await db.query('COMMIT');}catch(error){await db.query('ROLLBACK');throw error;}finally{db.release();}}
 }
 let running=false;
 async function tick(){if(running)return;running=true;try{
  const rows=(await pool.query(`SELECT u.id,u.company_id FROM users u LEFT JOIN employee_private_purge_jobs j ON j.user_id=u.id WHERE u.deleted_at IS NOT NULL AND u.private_data_state='recoverable' AND u.recovery_until<=now() AND (j.next_attempt_at IS NULL OR j.next_attempt_at<=now()) ORDER BY u.recovery_until,u.id LIMIT 10`)).rows;
  for(const row of rows)await expire(row.id,row.company_id);
  await cleanObjects();if(storage)await storage.cleanup();await finish();await pool.query('DELETE FROM revoked_account_sessions WHERE expires_at<now()');
 }finally{running=false;}}
 return {preview,request,tick};
}
export async function installPrivatePurge({app,pool,authRequired,storage,bucket,onChange}){await installPrivatePurgeSchema(pool);const service=createPrivatePurge({pool,storage,bucket,onChange});
 for(const [method,path,work] of [['get','/api/company/employees/:id/private-purge-preview',r=>service.preview(r,r.params.id)],['post','/api/company/employees/:id/private-purge',r=>service.request(r,r.params.id,r.body)]])app[method](path,authRequired,async(req,res)=>{res.set('Cache-Control','private, no-store');try{res.json(await work(req));}catch(e){res.status(e.status||503).json({error:e.code||'purge_unavailable',message:e.status?e.message:'Private-data cleanup is temporarily unavailable.'});}});
 return service;
}
