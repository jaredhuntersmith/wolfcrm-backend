import {randomUUID} from 'node:crypto';
import {hasCapability} from '../permissions.js';
import {blockVisible,fail,string,uuid} from './contract.js';
import {actorFor,audit,checkAvailability,recipientFor,requireSupervision,requireTraining,trainingMutation} from './service.js';
import {requirePrerequisites} from './prerequisites.js';

function accessSQL(actor){
  const owner=actor.isCompanyOwner?'true':'false';
  const author=hasCapability(actor,'training.author')?'true':'false';
  const review=hasCapability(actor,'training.review')?'true':'false';
  const self=hasCapability(actor,'training.view_self')?'true':'false';
  const supervised=`(${owner} OR (${review} AND EXISTS (SELECT 1 FROM training_supervisor_grants g
    WHERE g.company_id=$2 AND g.supervisor_id=$1 AND g.employee_id=r.employee_id)))`;
  return `(EXISTS (SELECT 1 FROM training_asset_refs ar WHERE ar.company_id=$2 AND ar.file_id=f.id AND (
    (ar.created_by=$1 AND f.owner_user_id=$1 AND f.cloud_status='pending'
      AND ((ar.purpose='content' AND ${author}) OR (ar.purpose='evidence' AND ${self})))
    OR (ar.definition_id IS NOT NULL AND ${author} AND EXISTS (
      SELECT 1 FROM training_definitions d WHERE d.company_id=ar.company_id AND d.id=ar.definition_id
        AND (d.scope='company' OR d.created_by=$1)))
    OR (ar.version_id IS NOT NULL AND ((${author} AND EXISTS (
      SELECT 1 FROM training_versions v JOIN training_definitions d
        ON d.company_id=v.company_id AND d.id=v.definition_id
      WHERE v.company_id=ar.company_id AND v.id=ar.version_id
        AND (d.scope='company' OR d.created_by=$1))) OR EXISTS (
      SELECT 1 FROM training_assignments a JOIN training_recipients r ON r.company_id=a.company_id AND r.assignment_id=a.id
      WHERE a.company_id=$2 AND a.version_id=ar.version_id AND (
        (${self} AND r.employee_id=$1) OR ${supervised}
      )
    )))
    OR (ar.recipient_id IS NOT NULL AND EXISTS (
      SELECT 1 FROM training_recipients r WHERE r.company_id=$2 AND r.id=ar.recipient_id
      AND ((${self} AND r.employee_id=$1) OR ${supervised})
    ))
    OR (ar.attempt_id IS NOT NULL AND EXISTS (
      SELECT 1 FROM training_quiz_attempts t JOIN training_recipients r ON r.company_id=t.company_id AND r.id=t.recipient_id
      WHERE t.company_id=$2 AND t.id=ar.attempt_id
      AND ((${self} AND r.employee_id=$1) OR ${supervised})
    ))
  )) OR EXISTS (SELECT 1 FROM training_course_asset_refs cr WHERE cr.company_id=$2 AND cr.file_id=f.id AND (
    (cr.course_id IS NOT NULL AND ${author} AND (f.cloud_status='active' OR (cr.created_by=$1 AND f.owner_user_id=$1)))
    OR (cr.version_id IS NOT NULL AND (${author} OR EXISTS (
      SELECT 1 FROM training_course_enrollments e WHERE e.company_id=$2 AND e.version_id=cr.version_id
      AND ((${self} AND e.employee_id=$1) OR (${owner} OR (${review} AND EXISTS (
        SELECT 1 FROM training_supervisor_grants g WHERE g.company_id=$2 AND g.supervisor_id=$1 AND g.employee_id=e.employee_id
      ))))
    )))
  )))`;
}

export function trainingAssetScope(){
  return {
    async predicate(db,actor){const current=await actorFor(db,actor);return accessSQL(current);},
    async authorizeAccess(db,actor,file,purpose){
      const current=await actorFor(db,actor);
      if(purpose==='edit'||purpose==='delete')fail(403,'retained_training_asset','Training records retain this file.');
      if(purpose==='upload'){
        const refs=(await db.query(`SELECT purpose FROM training_asset_refs WHERE company_id=$1 AND file_id=$2 AND created_by=$3`,[current.companyId,file.id,current.userId])).rows;
        const courseRef=(await db.query(`SELECT 1 FROM training_course_asset_refs WHERE company_id=$1 AND file_id=$2 AND created_by=$3`,[current.companyId,file.id,current.userId])).rowCount>0;
        const allowed=refs.some(ref=>ref.purpose==='content'&&hasCapability(current,'training.author')||ref.purpose==='evidence'&&hasCapability(current,'training.view_self'))
          ||courseRef&&hasCapability(current,'training.author');
        if(!allowed||file.owner_user_id!==current.userId)fail(404,'training_asset_not_found');return;
      }
      if(!['preview','stream','download'].includes(purpose))fail(403,'invalid_training_asset_action');
      const predicate=accessSQL(current);
      const allowed=(await db.query(`SELECT 1 FROM stored_files f WHERE f.id=$3 AND f.company_id=$2 AND (${predicate})`,[current.userId,current.companyId,file.id])).rowCount>0;
      if(!allowed)fail(404,'training_asset_not_found');
    }
  };
}

export function createTrainingAssetService({pool,storage}){
  return {
    async reserve(req,body){
      if(!storage?.reserveInTransaction)fail(503,'storage_unavailable');
      const targetKind=body?.target_kind,targetID=uuid(body?.target_id);
      if(!['definition','recipient','course'].includes(targetKind))fail(400,'invalid_asset_target');
      return trainingMutation(pool,req,[],async(db,actor)=>{
        let purpose,definitionID=null,recipientID=null,courseID=null,blockID=null;
        if(targetKind==='definition'){
          requireTraining(actor,'training.author');
          const row=(await db.query(`SELECT id,created_by,scope,archived_at FROM training_definitions WHERE company_id=$1 AND id=$2 FOR UPDATE`,[actor.companyId,targetID])).rows[0];
          if(!row)fail(404,'definition_not_found');
          if(row.archived_at)fail(409,'definition_archived');
          if(row.scope==='personal'&&row.created_by!==actor.userId)fail(404,'definition_not_found');
          if(row.created_by!==actor.userId&&!actor.isCompanyOwner)fail(403,'author_only');
          purpose='content';definitionID=targetID;
        }else if(targetKind==='course'){
          requireTraining(actor,'training.author');
          const row=(await db.query(`SELECT id,created_by,archived_at FROM training_courses WHERE company_id=$1 AND id=$2 FOR UPDATE`,[actor.companyId,targetID])).rows[0];
          if(!row)fail(404,'course_not_found');if(row.archived_at)fail(409,'course_archived');
          if(row.created_by!==actor.userId&&!actor.isCompanyOwner)fail(403,'author_only');
          if(!body.file?.mime_type?.startsWith('image/'))fail(400,'invalid_course_cover_type');
          purpose='content';courseID=targetID;
        }else{
          const row=await recipientFor(db,actor,targetID,{lock:true});
          requireTraining(actor,'training.view_self');if(row.employee_id!==actor.userId)fail(403,'recipient_only');
          if(!['assigned','in_progress','corrections_requested'].includes(row.status))fail(409,'assignment_not_editable');
          checkAvailability(row);await requirePrerequisites(db,actor,row);purpose='evidence';recipientID=targetID;
          if(body.block_id!=null){
            blockID=string(body.block_id,80);
            const block=row.document.blocks.find(candidate=>candidate.id===blockID);
            if(!block||!['photo_evidence','video_evidence','signature'].includes(block.type))fail(400,'invalid_evidence_block');
            if(!blockVisible(row.document,block,row.responses))fail(409,'evidence_block_hidden');
            const mime=body.file?.mime_type??'';
            if(block.type==='video_evidence'?!mime.startsWith('video/'):!mime.startsWith('image/'))fail(400,'invalid_evidence_type');
          }
        }
        const upload=await storage.reserveInTransaction(db,actor,body.file,{sourceProtected:true,sourceScope:'training'});
        if(courseID){
          const existing=(await db.query(`SELECT id FROM training_course_asset_refs WHERE company_id=$1 AND file_id=$2 AND course_id=$3`,[actor.companyId,upload.file.id,courseID])).rows[0];
          if(!existing)await db.query(`INSERT INTO training_course_asset_refs(id,company_id,file_id,created_by,course_id)
            VALUES($1,$2,$3,$4,$5)`,[randomUUID(),actor.companyId,upload.file.id,actor.userId,courseID]);
          return upload;
        }
        const existing=(await db.query(`SELECT id,block_id FROM training_asset_refs WHERE company_id=$1 AND file_id=$2 AND ${definitionID?'definition_id':'recipient_id'}=$3`,[actor.companyId,upload.file.id,targetID])).rows[0];
        if(existing&&existing.block_id!==blockID)fail(409,'asset_block_conflict');
        if(!existing){
          await db.query(`INSERT INTO training_asset_refs(id,company_id,file_id,created_by,purpose,block_id,definition_id,recipient_id)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,[randomUUID(),actor.companyId,upload.file.id,actor.userId,purpose,blockID,definitionID,recipientID]);
          await audit(db,actor,'asset.reserved',{recipientID,definitionID,details:{file_id:upload.file.id,purpose,block_id:blockID}});
        }
        return upload;
      });
    },
    async listRecipient(req,recipientID){const actor=await actorFor(pool,req);const row=await recipientFor(pool,actor,recipientID);
      if(actor.userId===row.employee_id)requireTraining(actor,'training.view_self');
      else{requireTraining(actor,'training.review');await requireSupervision(pool,actor,row.employee_id);}
      const rows=(await pool.query(`SELECT ar.file_id,ar.block_id,ar.purpose,f.original_filename,f.mime_type,f.byte_size,f.cloud_status,f.created_at
        FROM training_asset_refs ar JOIN stored_files f ON f.id=ar.file_id AND f.company_id=ar.company_id
        WHERE ar.company_id=$1 AND ar.recipient_id=$2 AND f.source_scope='training' AND f.source_protected
        ORDER BY ar.created_at,ar.id`,[actor.companyId,row.id])).rows;
      return {items:rows.map(item=>({...item,byte_size:Number(item.byte_size)}))};}
  };
}
