import {createHash} from 'node:crypto';
import {privateFinancePlan,financeHistoryTable} from './finance-private.js';
import {noteSharedSQL} from '../notes/access.js';
import {privateTrainingDraftSQL,privateTrainingBankSQL,privateTrainingBankAuditActions} from './training-private.js';

export const identifier=value=>'"'+value.replaceAll('"','""')+'"';
export async function schemaTables(db){return new Map((await db.query("SELECT table_name,array_agg(column_name::text) columns FROM information_schema.columns WHERE table_schema='public' GROUP BY table_name")).rows.map(r=>[r.table_name,new Set(r.columns)]));}

// The same boundary drives both deletion and the storage breakdown. Broken
// legacy trees and any retained descendant keep the containing note intact.
export function privateNoteSQL(user='$1',company='$2'){
 return `n.owner_id=${user} AND n.company_id=${company} AND n.purged_at IS NULL AND n.conversation_id IS NULL AND NOT ${noteSharedSQL()}
 AND NOT EXISTS(WITH RECURSIVE children AS (
  SELECT c.*,ARRAY[n.id,c.id] path,c.id=n.id cycle FROM comms_notes c WHERE c.parent_id=n.id
  UNION ALL SELECT c.*,p.path||c.id,c.id=ANY(p.path) FROM comms_notes c JOIN children p ON c.parent_id=p.id WHERE NOT p.cycle
 ) SELECT 1 FROM children c WHERE c.cycle OR c.company_id<>${company} OR c.owner_id<>${user} OR c.visibility IN ('shared','company') OR c.conversation_id IS NOT NULL)`;
}

export function retainedFinanceSQL(tables,alias='s'){
 const operational=[...tables.keys()].filter(t=>t.startsWith('finance_')&&financeHistoryTable(t)&&tables.get(t)?.has('finance_space_id'));
 const companyMemories=tables.get('finance_ai_memories')?.has('memory_scope')&&tables.get('finance_ai_memories')?.has('finance_space_id')?[`EXISTS(SELECT 1 FROM finance_ai_memories memory WHERE memory.finance_space_id=${alias}.id AND memory.memory_scope='company')`]:[];
 return '('+[`${alias}.includes_company_activity`,...companyMemories,...operational.map(t=>`EXISTS(SELECT 1 FROM ${identifier(t)} history WHERE history.finance_space_id=${alias}.id)`)].join(' OR ')+')';
}

// Referenced assets belong to their retained source/participants. Source-protected
// files are conservatively retained even when their optional domain is offline.
export async function retainedFileSQL(db,{privateNoteIDs=[],privateTrainingDefinitionIDs=[],classifyOwnerPrivate=false}={}){
 const tables=await schemaTables(db);
 // UUID literals come exclusively from database rows and are validated here.
 const excluded=privateNoteIDs.filter(id=>/^[\da-f-]{36}$/i.test(id)).map(id=>`'${id}'::uuid`).join(',');
 const privateSource=classifyOwnerPrivate?`EXISTS(SELECT 1 FROM comms_notes n WHERE n.id::text=p.source_id AND ${privateNoteSQL('f.owner_user_id','f.company_id')})`:excluded?`p.source_id=ANY(ARRAY[${excluded}]::text[])`:'false';
 const privateExport=tables.has('comms_asset_provenance')&&tables.has('comms_notes')?`EXISTS(SELECT 1 FROM comms_asset_provenance p WHERE p.asset_id=f.id AND p.company_id=f.company_id AND p.source_type='note' AND ${privateSource})`:'false';
 const draftIDs=privateTrainingDefinitionIDs.filter(id=>/^[\da-f-]{36}$/i.test(id)).map(id=>`'${id}'::uuid`).join(',');
 const draftBoundary=classifyOwnerPrivate?await privateTrainingDraftSQL(db,tables,{user:'f.owner_user_id',company:'f.company_id'}):draftIDs?`d.id IN (${draftIDs}) AND d.created_by=f.owner_user_id AND d.company_id=f.company_id`:'false';
 const privateTraining=tables.get('training_definitions')?.has('scope')&&tables.get('training_asset_refs')?.has('definition_id')?`(f.source_scope IS NOT DISTINCT FROM 'training'
  AND EXISTS(SELECT 1 FROM training_asset_refs ref JOIN training_definitions d ON d.id=ref.definition_id WHERE ref.file_id=f.id AND ${draftBoundary})
  AND NOT EXISTS(SELECT 1 FROM training_asset_refs ref WHERE ref.file_id=f.id AND NOT EXISTS(SELECT 1 FROM training_definitions d WHERE d.id=ref.definition_id AND ${draftBoundary})))`:'false';
 const clauses=["f.visibility='company'",`(f.source_protected AND NOT (${privateExport}) AND NOT (${privateTraining}))`,`(f.source_scope IS NOT NULL AND NOT (${privateTraining}))`];
 const foreign=(await db.query(`SELECT child.relname AS child,a.attname AS column_name FROM pg_constraint c JOIN pg_class child ON child.oid=c.conrelid
 JOIN pg_attribute a ON a.attrelid=child.oid AND a.attnum=ANY(c.conkey)
 WHERE c.contype='f' AND c.confrelid='stored_files'::regclass AND child.relnamespace='public'::regnamespace AND array_length(c.conkey,1)=1`)).rows;
 const personal=new Set(['storage_thumbnails','storage_file_state','storage_access_receipts','storage_activity','storage_delivery_tickets']);
 for(const row of foreign)if(!personal.has(row.child)&&row.child!=='comms_notes')clauses.push(`(EXISTS(SELECT 1 FROM ${identifier(row.child)} ref WHERE ref.${identifier(row.column_name)}=f.id)${row.child==='comms_asset_provenance'?` AND NOT (${privateExport})`:row.child==='training_asset_refs'?` AND NOT (${privateTraining})`:''})`);
 if(tables.has('comms_scheduled_messages'))clauses.push("EXISTS(SELECT 1 FROM comms_scheduled_messages s WHERE s.status='scheduled' AND s.payload->'asset_ids' ? f.id::text)");
 if(tables.has('comms_workflow_runs'))clauses.push('EXISTS(SELECT 1 FROM comms_workflow_runs w WHERE w.asset_ids ? f.id::text)');
 const noteBoundary=classifyOwnerPrivate?`NOT (${privateNoteSQL('f.owner_user_id','f.company_id')}) AND `:excluded?`n.id NOT IN (${excluded}) AND `:'';
 if(tables.has('comms_notes')){
  const noteRefs=['n.cover_id=f.id','n.asset_ids ? f.id::text'];
  if(tables.has('notes_blocks'))noteRefs.push("EXISTS(SELECT 1 FROM notes_blocks b WHERE b.page_id=n.id AND (b.payload->>'asset_id'=f.id::text OR b.payload->>'preview_id'=f.id::text))");
  // A retired database property still holds recoverable values. Retain matching
  // UUID values even when its former file-column definition is no longer live.
  if(tables.has('notes_database_rows'))noteRefs.push("EXISTS(SELECT 1 FROM notes_database_rows r CROSS JOIN LATERAL jsonb_each_text(r.values) v WHERE r.id=n.id AND v.value=f.id::text)");
  if(tables.has('comms_note_versions'))noteRefs.push('EXISTS(SELECT 1 FROM comms_note_versions v WHERE v.note_id=n.id AND v.asset_ids ? f.id::text)');
  if(tables.has('notes_versions'))noteRefs.push(`EXISTS(SELECT 1 FROM notes_versions v WHERE v.page_id=n.id AND (
   v.snapshot->'page'->>'cover_id'=f.id::text
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(COALESCE(v.snapshot->'blocks','[]')) b WHERE b->'payload'->>'asset_id'=f.id::text OR b->'payload'->>'preview_id'=f.id::text)
   OR EXISTS(SELECT 1 FROM jsonb_each_text(COALESCE(v.snapshot->'row_properties'->'values','{}')) value WHERE value.value=f.id::text)))`);
  clauses.push(`EXISTS(SELECT 1 FROM comms_notes n WHERE ${noteBoundary}n.purged_at IS NULL AND (${noteRefs.join(' OR ')}))`);
 }
 return '('+clauses.join(' OR ')+')';
}

export async function privateDataPlan(db,target){
 const tables=await schemaTables(db),args=[target.id,target.company_id],operations=[];
 const add=(table,where,values=args)=>{if(tables.has(table))operations.push({table,where,values});};
 let notes=[];
 if(tables.has('notes_blocks'))notes=(await db.query(`SELECT n.id,n.revision FROM comms_notes n WHERE ${privateNoteSQL()} ORDER BY n.id`,args)).rows;
 const bankBoundary=await privateTrainingBankSQL(db,tables);
 const trainingBanks=bankBoundary==='false'?[]:(await db.query(`SELECT b.id,b.revision FROM training_question_banks b WHERE ${bankBoundary} ORDER BY b.id`,args)).rows;
 const bankIDs=trainingBanks.map(b=>b.id);
 if(bankIDs.length){
  add('training_audit_events',"company_id=$1 AND actor_id=$2 AND details->>'bank_id'=ANY($3::text[]) AND action=ANY($4::text[]) AND recipient_id IS NULL AND definition_id IS NULL",[target.company_id,target.id,bankIDs,privateTrainingBankAuditActions]);
  add('training_question_banks','id=ANY($1::uuid[])',[bankIDs]);
 }
 const trainingBoundary=await privateTrainingDraftSQL(db,tables);
 const trainingDrafts=trainingBoundary==='false'?[]:(await db.query(`SELECT d.id,d.draft_revision FROM training_definitions d WHERE ${trainingBoundary} ORDER BY d.id`,args)).rows;
 const trainingIDs=trainingDrafts.map(d=>d.id);
 if(trainingIDs.length){
  add('training_asset_refs','definition_id=ANY($1::uuid[])',[trainingIDs]);
  add('training_audit_events','definition_id=ANY($1::uuid[])',[trainingIDs]);
  add('training_definitions','id=ANY($1::uuid[])',[trainingIDs]);
 }
 const noteIDs=notes.map(r=>r.id),retained=await retainedFileSQL(db,{privateNoteIDs:noteIDs,privateTrainingDefinitionIDs:trainingIDs});
 const files=(await db.query(`SELECT f.id,f.version,f.byte_size,f.cloud_status FROM stored_files f WHERE f.owner_user_id=$1 AND f.company_id=$2 AND f.cloud_status<>'deleted' AND NOT ${retained} ORDER BY f.id`,args)).rows;
 const metadataFiles=(await db.query(`SELECT f.id,f.version FROM stored_files f WHERE f.owner_user_id=$1 AND f.company_id=$2 AND NOT ${retained} ORDER BY f.id`,args)).rows;
 const metadataFileIDs=metadataFiles.map(f=>f.id);
 add('storage_access_receipts','file_id=ANY($1::uuid[]) AND NOT was_public',[metadataFileIDs]);
 const audio=noteIDs.length?(await db.query('SELECT * FROM notes_audio WHERE page_id=ANY($1::uuid[]) ORDER BY id',[noteIDs])).rows:[];
 const audioObjects=[];
 for(const recording of audio){
  if(audioObjects.some(a=>a.object_key===recording.object_key))continue;
  const retained=(await db.query('SELECT 1 FROM notes_audio WHERE object_key=$1 AND NOT (page_id=ANY($2::uuid[])) LIMIT 1',[recording.object_key,noteIDs])).rowCount;
  if(!retained)audioObjects.push(recording);
 }
 for(const table of ['notes_comments','notes_blocks','notes_versions','notes_activity','notes_personal','notes_operations','notes_presence','notes_members','notes_database_schemas'])add(table,'page_id=ANY($1::uuid[])',[noteIDs]);
 add('notes_database_rows','id=ANY($1::uuid[]) OR database_id=ANY($1::uuid[])',[noteIDs]);add('comms_note_versions','note_id=ANY($1::uuid[])',[noteIDs]);add('notes_templates','page_id=ANY($1::uuid[])',[noteIDs]);
 add('notes_ai_results','creator_id=$1 AND company_id=$2');
 for(const table of ['notes_preferences','notes_smart_folders','notes_personal','notes_presence','storage_file_state','comms_preferences','service_plan_review_preferences','dashboard_dismissals','comms_message_personal','notification_preferences','notifications','lead_notifications'])if(tables.get(table)?.has('user_id'))add(table,'user_id=$1',[target.id]);
 add('idea_parking_ideas',"user_id=$1 AND (company_id=$2 OR company_id IS NULL) AND (list_id IS NULL OR EXISTS(SELECT 1 FROM idea_parking_lists l WHERE l.id=idea_parking_ideas.list_id AND l.user_id=$1 AND l.visibility='private'))");
 add('idea_parking_lists',"user_id=$1 AND (company_id=$2 OR company_id IS NULL) AND visibility='private'");
 // Retain Focus content referenced by another user; remove personal views/settings.
 for(const table of ['focus_settings','focus_settings_history','focus_connections','focus_oauth_states','focus_creator_nominations','focus_hashtag_discovery','focus_creator_follows','focus_creator_blocks','focus_content_state','focus_likes','focus_interactions','focus_feed_entries','focus_jobs','focus_probe_runs','focus_conversations'])add(table,'user_id=$1 AND (company_id=$2 OR company_id IS NULL)');
 if(tables.has('focus_content'))add('focus_content',`owner_user_id=$1 AND company_id=$2 AND NOT EXISTS(SELECT 1 FROM focus_content_state x WHERE x.content_id=focus_content.id AND x.user_id<>$1) AND NOT EXISTS(SELECT 1 FROM focus_feed_entries x WHERE x.content_id=focus_content.id AND x.user_id<>$1) AND NOT EXISTS(SELECT 1 FROM focus_likes x WHERE x.content_id=focus_content.id AND x.user_id<>$1) AND NOT EXISTS(SELECT 1 FROM focus_interactions x WHERE x.content_id=focus_content.id AND x.user_id<>$1)`);
 add('focus_creators','owner_user_id=$1 AND company_id=$2 AND NOT EXISTS(SELECT 1 FROM focus_content c WHERE c.creator_id=focus_creators.id) AND NOT EXISTS(SELECT 1 FROM focus_creator_follows f WHERE f.creator_id=focus_creators.id AND f.user_id<>$1)');
 // Billing totals/audits survive; private assistant content is redacted below.
 add('wolf_assistant_messages','conversation_id IN (SELECT id FROM wolf_assistant_conversations WHERE user_id=$1 AND company_id=$2)');
 for(const table of ['wolf_assistant_steps','wolf_assistant_events','wolf_assistant_commands'])add(table,'run_id IN (SELECT id FROM wolf_assistant_runs WHERE user_id=$1 AND company_id=$2)');
 add('wolf_assistant_memories','user_id=$1 AND company_id=$2');add('wolf_assistant_settings','user_id=$1 AND company_id=$2');
 for(const table of ['mcp_tokens','mcp_codes'])add(table,'connection_id IN (SELECT id FROM mcp_connections WHERE user_id=$1 AND company_id=$2)');
 add('mcp_browser_requests','user_id=$1',[target.id]);
 // W2's personal task boundary: never remove an assignment or a shared-note task.
 if(tables.has('todo_tasks'))add('todo_tasks',`user_id=$1${tables.has('comms_task_links')?' AND NOT EXISTS(SELECT 1 FROM comms_task_links link WHERE link.task_id=todo_tasks.id)':''}${tables.get('todo_tasks').has('assignee_ids')?" AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(assignee_ids) a WHERE a<>$1::text)":''}${tables.get('todo_tasks').has('owner_user_id')?' AND owner_user_id=$1':''}${tables.get('todo_tasks').has('conversation_id')?' AND conversation_id IS NULL':''}${tables.get('todo_tasks').has('source_note_id')?' AND (source_note_id IS NULL OR source_note_id=ANY($2::uuid[]))':''}`,tables.get('todo_tasks').has('source_note_id')?[target.id,noteIDs]:[target.id]);
 for(const table of ['todo_routines','todo_routine_done','todo_customer_reminders','todo_logs'])add(table,'user_id=$1',[target.id]);
 const finance=await privateFinancePlan(db,tables,target),spaces=finance.spaces,retainedFinanceSpaces=finance.retainedSpaces;
 operations.push(...finance.operations);
 const spaceIDs=spaces.map(r=>r.id),receiptIDs=finance.receiptIDs;
 const receipts=receiptIDs.length?(await db.query('SELECT id,object_key,thumbnail_object_key,file_size_bytes FROM finance_receipts WHERE id=ANY($1::uuid[]) ORDER BY id',[receiptIDs])).rows:[];
 // Legacy receipt objects can be referenced more than once. Preserve bytes still
 // used by any receipt outside this exact deletion set, including another company.
 const receiptObjects=[];
 for(const receipt of receipts)for(const [key,size] of [[receipt.object_key,receipt.file_size_bytes],[receipt.thumbnail_object_key,null]]){
  if(!key||receiptObjects.some(o=>o.object_key===key))continue;
  const retained=(await db.query('SELECT 1 FROM finance_receipts WHERE NOT (id=ANY($1::uuid[])) AND (object_key=$2 OR thumbnail_object_key=$2) LIMIT 1',[receiptIDs,key])).rowCount;
  if(!retained)receiptObjects.push({object_key:key,byte_size:size,source_id:receipt.id});
 }
 add('finance_space_audit','space_id=ANY($1::uuid[])',[spaceIDs]);add('finance_spaces','id=ANY($1::uuid[])',[spaceIDs]);
 const counts=[];
 for(const operation of operations){const row=(await db.query(`SELECT count(*)::int AS count,md5(COALESCE(string_agg(md5(row_to_json(${identifier(operation.table)})::text),'' ORDER BY md5(row_to_json(${identifier(operation.table)})::text)),'')) AS digest FROM ${identifier(operation.table)} WHERE ${operation.where}`,operation.values)).rows[0];counts.push({table:operation.table,...row});}
 const personalColumns=['tab_preferences','dashboard_preferences','password_hash'].filter(column=>tables.get('users')?.has(column));
 const personalAccount=personalColumns.length?(await db.query(`SELECT ${personalColumns.map(identifier).join(',')} FROM users WHERE id=$1 AND company_id=$2`,args)).rows[0]:{};
 const token=createHash('sha256').update(JSON.stringify({personalAccount,revision:Number(target.account_revision),notes,files,metadataFiles,audio:audio.map(a=>[a.id,a.byte_size,a.ready]),audioObjects:audioObjects.map(a=>a.object_key),spaces,retainedFinanceSpaces,mixedPrivateFinanceRecords:finance.mixedPrivateRecords,receiptObjects,counts})).digest('hex');
 return {notes,noteIDs,trainingDrafts,trainingBanks,files,metadataFileIDs,audio,audioObjects,spaces,retainedFinanceSpaces,mixedPrivateFinanceRecords:finance.mixedPrivateRecords,retainedFinanceReceiptIDs:finance.retainedReceiptIDs,receipts,receiptObjects,operations,counts,token};
}

export async function deletePrivateRows(db,plan,target){
 // Clear self links before deleting private-only note payloads. Tombstones retain
 // link identity without content; shared descendants/ancestors are excluded.
 if(plan.noteIDs.length){await db.query('UPDATE notes_blocks SET parent_id=NULL WHERE page_id=ANY($1::uuid[])',[plan.noteIDs]);await db.query('UPDATE notes_comments SET parent_id=NULL WHERE page_id=ANY($1::uuid[])',[plan.noteIDs]);}
 let pending=[...plan.operations],last;
 while(pending.length){let changed=false;const retry=[];
  for(const op of pending){await db.query('SAVEPOINT private_delete');try{await db.query(`DELETE FROM ${identifier(op.table)} WHERE ${op.where}`,op.values);await db.query('RELEASE SAVEPOINT private_delete');changed=true;}catch(error){await db.query('ROLLBACK TO SAVEPOINT private_delete');await db.query('RELEASE SAVEPOINT private_delete');if(error.code!=='23503')throw error;last=error;retry.push(op);}}
  if(!changed)throw Object.assign(new Error('Private records have a retained dependency requiring review.'),{code:'private_dependency_retained',cause:last});pending=retry;
 }
 if(plan.noteIDs.length)await db.query("UPDATE comms_notes SET title='Deleted Note',body='',asset_ids='[]',source_refs='[]',tags='[]',icon='',cover_id=NULL,purged_at=now(),deleted_at=COALESCE(deleted_at,now()),revision=revision+1 WHERE id=ANY($1::uuid[])",[plan.noteIDs]);
 // The durable object queue carries bytes until deletion is confirmed. Remove
 // every private recording row, but never queue a key held by another page.
 if(plan.audio.length)await db.query('DELETE FROM notes_audio WHERE id=ANY($1::uuid[])',[plan.audio.map(a=>a.id)]);
 if(plan.metadataFileIDs.length){
  await db.query("UPDATE stored_files SET display_name='Deleted file',original_filename='Deleted file',metadata_json='{}',folder_id=NULL WHERE id=ANY($1::uuid[])",[plan.metadataFileIDs]);
  await db.query("UPDATE storage_activity SET file_name='Deleted file' WHERE file_id=ANY($1::uuid[]) AND NOT was_public",[plan.metadataFileIDs]);
 }
 const tables=await schemaTables(db);
 // Permanent purge clears personal preferences and credentials, never identity,
 // grants or company history. Disable/restore intentionally preserves these.
 const reset=['tab_preferences','dashboard_preferences'].filter(column=>tables.get('users')?.has(column)).map(column=>`${identifier(column)}='{}'::jsonb`);
 if(tables.get('users')?.has('password_hash'))reset.push('password_hash=NULL');
 if(reset.length)await db.query(`UPDATE users SET ${reset.join(',')} WHERE id=$1 AND company_id=$2`,[target.id,target.company_id]);
 for(const table of ['tab_layout_audit','dashboard_layout_audit'])if(tables.has(table))await db.query(`UPDATE ${identifier(table)} SET previous_layout='{}',new_layout='{}' WHERE company_id=$1 AND target_type='employee' AND target_id=$2`,[target.company_id,target.id]);
 if(tables.has('wolf_assistant_runs'))await db.query("UPDATE wolf_assistant_runs SET cancel_requested=true,status='cancelled',instructions='',context='{}',history='[]',loaded_tools='[]',allowed_tools=NULL,output='',destination='{}' WHERE user_id=$1 AND company_id=$2",[target.id,target.company_id]);
 if(tables.has('wolf_assistant_conversations'))await db.query("UPDATE wolf_assistant_conversations SET title='Deleted chat',deleted_at=COALESCE(deleted_at,now()) WHERE user_id=$1 AND company_id=$2",[target.id,target.company_id]);
 if(tables.has('mcp_operations'))await db.query("UPDATE mcp_operations SET result='{\"private_data_purged\":true}' WHERE connection_id IN (SELECT id FROM mcp_connections WHERE user_id=$1 AND company_id=$2)",[target.id,target.company_id]);
 if(tables.has('mcp_approvals'))await db.query("UPDATE mcp_approvals SET payload=NULL,result=NULL,state=CASE WHEN state='pending' THEN 'rejected' ELSE state END WHERE connection_id IN (SELECT id FROM mcp_connections WHERE user_id=$1 AND company_id=$2)",[target.id,target.company_id]);
 if(tables.has('mcp_connections'))await db.query("UPDATE mcp_connections SET revoked_at=COALESCE(revoked_at,now()) WHERE user_id=$1 AND company_id=$2",[target.id,target.company_id]);
 if(tables.has('storage_folders'))await db.query("UPDATE storage_folders SET name='Deleted folder',version=version+1 WHERE owner_user_id=$1",[target.id]);
 if(tables.has('focus_cost_ledger'))await db.query("UPDATE focus_cost_ledger SET metadata='{}' WHERE user_id=$1 AND company_id=$2",[target.id,target.company_id]);
}
