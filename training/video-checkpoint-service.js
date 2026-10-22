import {randomUUID} from 'node:crypto';
import {digest,fail,string,uuid} from './contract.js';
import {gradeQuiz,normalizeQuizAnswers} from './quiz-contract.js';
import {actorFor,audit,checkAvailability,recipientFor,requireSupervision,requireTraining,trainingMutation} from './service.js';
import {recordTrainingEvent} from './events.js';
import {contiguousPosition} from './video-progress.js';
import {checkpointState} from './video-checkpoint-gates.js';
import {learnerCheckpoint} from './video-checkpoints-contract.js';

function blockFor(document,id){const block=document.blocks.find(item=>item.id===id&&item.type==='video'&&['D','E'].includes(item.video.mode));
  if(!block)fail(404,'video_checkpoints_not_found');return block;}
function employee(actor,row){requireTraining(actor,'training.view_self');if(row.employee_id!==actor.userId)fail(403,'recipient_only');}
function checkpointDTO(checkpoint,attempt,{grader=false}={}){
  const result={...learnerCheckpoint(checkpoint),attempts_used:attempt?.attempt_number??0,
    status:attempt?.status??'not_started',passed:attempt?.passed??null,unlocked:attempt?.unlocked??false,
    replay_required:!!(attempt&&!attempt.unlocked&&checkpoint.replay_seconds>0&&!attempt.replay_completed_at),
    replay_from:attempt&&!attempt.unlocked&&checkpoint.replay_seconds>0&&!attempt.replay_completed_at?
      checkpoint.at_seconds-checkpoint.replay_seconds:null};
  if(grader&&attempt){result.response=attempt.response;result.author_question=checkpoint.question;
    result.auto_points=Number(attempt.auto_points);result.max_points=Number(attempt.max_points);
    result.grade_details=attempt.grade_details;result.feedback=attempt.feedback;}
  return result;
}
async function attemptFor(db,actor,id,{lock=false}={}){
  const row=(await db.query(`SELECT t.*,r.employee_id,a.definition_id,v.document FROM training_video_checkpoint_attempts t
    JOIN training_recipients r ON r.company_id=t.company_id AND r.id=t.recipient_id
    JOIN training_assignments a ON a.company_id=r.company_id AND a.id=r.assignment_id
    JOIN training_versions v ON v.company_id=t.company_id AND v.id=t.version_id
    WHERE t.company_id=$1 AND t.id=$2 ${lock?'FOR UPDATE OF t':''}`,[actor.companyId,uuid(id)])).rows[0];
  if(!row)fail(404,'video_checkpoint_attempt_not_found');return row;
}
export function createVideoCheckpointService({pool}){
  return {
    async list(req,recipientID,blockID){const actor=await actorFor(pool,req),row=await recipientFor(pool,actor,recipientID);
      employee(actor,row);const block=blockFor(row.document,string(blockID,80));
      const progress=(await pool.query(`SELECT intervals FROM training_video_progress WHERE company_id=$1 AND recipient_id=$2 AND block_id=$3 AND version_id=$4`,
        [actor.companyId,row.id,block.id,row.version_id])).rows[0];
      const position=contiguousPosition(progress?.intervals??[]),state=await checkpointState(pool,actor,row,block);
      return {recipient_id:row.id,block_id:block.id,position_seconds:position,
        next_checkpoint_id:state.gate?.id??null,
        items:block.video.checkpoints.map(checkpoint=>position>=checkpoint.at_seconds-0.5?
          checkpointDTO(checkpoint,state.latest.get(checkpoint.id)):
          {id:checkpoint.id,kind:checkpoint.kind,at_seconds:checkpoint.at_seconds,locked:true,
            unlocked:state.latest.get(checkpoint.id)?.unlocked??false})};},
    async submit(req,recipientID,blockID,checkpointID,body){
      const selected=string(blockID,80),checkID=string(checkpointID,80),key=string(body?.request_key,80);
      return trainingMutation(pool,req,['training.view_self'],async (db,actor)=>{
        const row=await recipientFor(db,actor,recipientID,{lock:true});employee(actor,row);
        const block=blockFor(row.document,selected),checkpoint=block.video.checkpoints.find(item=>item.id===checkID);
        if(!checkpoint)fail(404,'video_checkpoint_not_found');
        const response=checkpoint.kind==='instruction'?(body?.acknowledged===true?true:null):
          normalizeQuizAnswers({questions:[checkpoint.question]}, {[checkpoint.question.id]:body?.response})[checkpoint.question.id];
        if(response==null)fail(400,'video_checkpoint_response_required');
        const hash=digest(response);
        const prior=(await db.query(`SELECT * FROM training_video_checkpoint_attempts WHERE company_id=$1 AND recipient_id=$2 AND block_id=$3 AND checkpoint_id=$4 AND request_key=$5`,
          [actor.companyId,row.id,block.id,checkID,key])).rows[0];
        if(prior){if(prior.input_sha256!==hash)fail(409,'request_key_conflict');return checkpointDTO(checkpoint,prior);}
        checkAvailability(row);if(row.status==='completed')fail(409,'assignment_completed');
        const state=await checkpointState(db,actor,row,block);
        if(state.gate?.id!==checkID){if(state.latest.get(checkID)?.unlocked)fail(409,'video_checkpoint_completed');
          fail(409,'video_prerequisite_checkpoint');}
        const progress=(await db.query(`SELECT intervals FROM training_video_progress WHERE company_id=$1 AND recipient_id=$2 AND block_id=$3 AND version_id=$4`,
          [actor.companyId,row.id,block.id,row.version_id])).rows[0];
        if(contiguousPosition(progress?.intervals??[])<checkpoint.at_seconds-0.5)fail(409,'video_checkpoint_not_reached');
        const attempts=(await db.query(`SELECT * FROM training_video_checkpoint_attempts WHERE company_id=$1 AND recipient_id=$2 AND block_id=$3 AND checkpoint_id=$4 ORDER BY attempt_number DESC FOR UPDATE`,
          [actor.companyId,row.id,block.id,checkID])).rows;
        if(checkpoint.kind==='question'&&attempts.length>=checkpoint.max_attempts)fail(409,'checkpoint_attempt_limit');
        if(attempts[0]?.status==='awaiting_manual'&&!attempts[0].unlocked)fail(409,'checkpoint_review_pending');
        if(attempts[0]&&!attempts[0].unlocked&&checkpoint.replay_seconds>0&&!attempts[0].replay_completed_at)fail(409,'checkpoint_replay_required');
        const quiz=checkpoint.kind==='question'?{questions:[checkpoint.question]}:null;
        const grade=quiz?gradeQuiz(quiz,{[checkpoint.question.id]:response}):null;
        const status=checkpoint.kind==='instruction'?'acknowledged':grade.requires_manual?'awaiting_manual':'graded';
        const passed=checkpoint.kind==='instruction'?true:grade.requires_manual?null:grade.auto_points>=checkpoint.question.points;
        const unlocked=checkpoint.kind==='instruction'||passed===true||checkpoint.kind==='question'&&!checkpoint.require_correct&&
          (!grade.requires_manual||checkpoint.progression_policy==='after_response');
        const id=randomUUID(),saved=(await db.query(`INSERT INTO training_video_checkpoint_attempts
          (id,company_id,recipient_id,version_id,block_id,checkpoint_id,attempt_number,request_key,input_sha256,status,response,
            auto_points,total_points,max_points,passed,unlocked,grade_details,graded_at)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
            CASE WHEN $10='graded' THEN now() ELSE NULL END) RETURNING *`,
          [id,actor.companyId,row.id,row.version_id,block.id,checkID,attempts.length+1,key,hash,status,JSON.stringify(response),
            grade?.auto_points??0,grade?.requires_manual?null:grade?.auto_points??0,grade?.max_points??0,passed,unlocked,
            JSON.stringify(grade?.details??{})])).rows[0];
        await audit(db,actor,'video.checkpoint_submitted',{recipientID:row.id,definitionID:row.definition_id,
          details:{attempt_id:id,block_id:block.id,checkpoint_id:checkID,status,passed,unlocked}});
        await recordTrainingEvent(db,actor,{type:unlocked?'training.video_checkpoint_unlocked':status==='awaiting_manual'?'training.video_checkpoint_pending_grade':'training.video_checkpoint_failed',
          subjectType:'training_video_checkpoint_attempt',subjectID:id,key:`video-checkpoint:${id}:submitted`,
          payload:{attempt_id:id,recipient_id:row.id,employee_id:row.employee_id,block_id:block.id,checkpoint_id:checkID,status,unlocked}});
        return checkpointDTO(checkpoint,saved);
      });},
    async graderView(req,id){const actor=await actorFor(pool,req);requireTraining(actor,'training.review');
      const row=await attemptFor(pool,actor,id);if(row.employee_id===actor.userId)fail(403,'self_review_forbidden');
      await requireSupervision(pool,actor,row.employee_id);
      const checkpoint=blockFor(row.document,row.block_id).video.checkpoints.find(item=>item.id===row.checkpoint_id);
      if(!checkpoint)fail(404,'video_checkpoint_not_found');return checkpointDTO(checkpoint,row,{grader:true});},
    async grade(req,id,body){
      return trainingMutation(pool,req,['training.review'],async (db,actor)=>{const row=await attemptFor(db,actor,id,{lock:true});
        if(row.employee_id===actor.userId)fail(403,'self_review_forbidden');await requireSupervision(db,actor,row.employee_id);
        if(row.status!=='awaiting_manual')fail(409,'manual_grade_not_pending');
        const checkpoint=blockFor(row.document,row.block_id).video.checkpoints.find(item=>item.id===row.checkpoint_id);
        if(!checkpoint||checkpoint.kind!=='question')fail(404,'video_checkpoint_not_found');
        const points=body?.points;if(typeof points!=='number'||!Number.isFinite(points)||points<0||points>checkpoint.question.points)fail(400,'invalid_manual_grade');
        const passed=points>=checkpoint.question.points,unlocked=passed||!checkpoint.require_correct;
        const feedback=string(body?.feedback??'',2000,{required:false});
        const details={...row.grade_details,[checkpoint.question.id]:{manual_points:points,feedback,requires_manual:false}};
        const saved=(await db.query(`UPDATE training_video_checkpoint_attempts SET status='graded',total_points=$3,passed=$4,unlocked=$5,
          feedback=$6,grade_details=$7,graded_at=now(),graded_by=$8 WHERE company_id=$1 AND id=$2 RETURNING *`,
          [actor.companyId,row.id,points,passed,unlocked,feedback,JSON.stringify(details),actor.userId])).rows[0];
        await audit(db,actor,'video.checkpoint_graded',{recipientID:row.recipient_id,definitionID:row.definition_id,
          details:{attempt_id:row.id,block_id:row.block_id,checkpoint_id:row.checkpoint_id,points,passed,unlocked}});
        await recordTrainingEvent(db,actor,{type:unlocked?'training.video_checkpoint_unlocked':'training.video_checkpoint_failed',
          subjectType:'training_video_checkpoint_attempt',subjectID:row.id,key:`video-checkpoint:${row.id}:graded`,
          payload:{attempt_id:row.id,recipient_id:row.recipient_id,employee_id:row.employee_id,block_id:row.block_id,
            checkpoint_id:row.checkpoint_id,status:'graded',unlocked}});
        return checkpointDTO(checkpoint,saved,{grader:true});
      });}
  };
}
