import {randomUUID} from 'node:crypto';
import {digest,fail,string,uuid} from './contract.js';
import {gradeQuiz,learnerQuiz,normalizeQuizAnswers} from './quiz-contract.js';
import {actorFor,audit,checkAvailability,recipientFor,requireSupervision,requireTraining,trainingMutation} from './service.js';
import {recordTrainingEvent} from './events.js';
import {contiguousPosition,coveredSeconds} from './video-progress.js';

function checkBlock(document,id){const block=document.blocks.find(item=>item.id===id&&item.type==='video'&&['C','E'].includes(item.video.mode));
  if(!block)fail(404,'video_check_not_found');return block;}
function employee(actor,row){requireTraining(actor,'training.view_self');if(row.employee_id!==actor.userId)fail(403,'recipient_only');}
async function covered(db,actor,row,block){
  const progress=(await db.query(`SELECT intervals FROM training_video_progress WHERE company_id=$1 AND recipient_id=$2 AND block_id=$3 AND version_id=$4`,
    [actor.companyId,row.id,block.id,row.version_id])).rows[0];
  const duration=block.video.duration_seconds;
  if(!progress||coveredSeconds(progress.intervals)<duration-0.5||contiguousPosition(progress.intervals)<duration-0.5)fail(409,'video_coverage_incomplete');
}
function checkDTO(row,quiz,{grader=false}={}){
  const result={id:row.id,recipient_id:row.recipient_id,block_id:row.block_id,attempt_number:row.attempt_number,
    status:row.status,passed:row.passed,submitted_at:row.submitted_at,quiz:learnerQuiz(quiz)};
  if(grader){result.responses=row.responses;result.author_questions=quiz.questions;result.auto_points=Number(row.auto_points);
    result.max_points=Number(row.max_points);result.grade_details=row.grade_details;result.feedback=row.feedback;}
  else if(row.status==='graded'&&quiz.show_results!=='never'){
    result.total_points=Number(row.total_points);result.max_points=Number(row.max_points);
    if(quiz.show_answers_after_grade)result.answer_review=quiz.questions.map(question=>({id:question.id,answer:question.answer,explanation:question.explanation}));
  }
  return result;
}
async function attemptFor(db,actor,id,{lock=false}={}){
  const row=(await db.query(`SELECT c.*,r.employee_id,a.definition_id,v.document FROM training_video_checks c
    JOIN training_recipients r ON r.company_id=c.company_id AND r.id=c.recipient_id
    JOIN training_assignments a ON a.company_id=r.company_id AND a.id=r.assignment_id
    JOIN training_versions v ON v.company_id=c.company_id AND v.id=c.version_id
    WHERE c.company_id=$1 AND c.id=$2 ${lock?'FOR UPDATE OF c':''}`,[actor.companyId,uuid(id)])).rows[0];
  if(!row)fail(404,'video_check_not_found');return row;
}
export function createVideoCheckService({pool}){
  return {
    async get(req,recipientID,blockID){const actor=await actorFor(pool,req),row=await recipientFor(pool,actor,recipientID);
      employee(actor,row);const block=checkBlock(row.document,string(blockID,80));await covered(pool,actor,row,block);
      const checks=(await pool.query(`SELECT * FROM training_video_checks WHERE company_id=$1 AND recipient_id=$2 AND block_id=$3 ORDER BY attempt_number DESC`,
        [actor.companyId,row.id,block.id])).rows;
      return {recipient_id:row.id,block_id:block.id,quiz:learnerQuiz(block.video.knowledge_check),
        attempts_used:checks.length,max_attempts:block.video.knowledge_check.max_attempts,
        latest:checks[0]?checkDTO(checks[0],block.video.knowledge_check):null};},
    async submit(req,recipientID,blockID,body){
      const key=string(body?.request_key,80),selected=string(blockID,80);
      return trainingMutation(pool,req,['training.view_self'],async (db,actor)=>{
        const row=await recipientFor(db,actor,recipientID,{lock:true});employee(actor,row);
        const block=checkBlock(row.document,selected),quiz=block.video.knowledge_check;
        const responses=normalizeQuizAnswers(quiz,body?.responses);
        if(Object.keys(responses).length!==quiz.questions.length)fail(400,'video_check_incomplete');
        const hash=digest(responses);
        const prior=(await db.query(`SELECT * FROM training_video_checks WHERE company_id=$1 AND recipient_id=$2 AND block_id=$3 AND request_key=$4`,
          [actor.companyId,row.id,block.id,key])).rows[0];
        if(prior){if(prior.input_sha256!==hash)fail(409,'request_key_conflict');return checkDTO(prior,quiz);}
        checkAvailability(row);if(row.status==='completed')fail(409,'assignment_completed');
        await covered(db,actor,row,block);
        const checks=(await db.query(`SELECT * FROM training_video_checks WHERE company_id=$1 AND recipient_id=$2 AND block_id=$3 ORDER BY attempt_number DESC`,
          [actor.companyId,row.id,block.id])).rows;
        if(checks[0]?.passed)fail(409,'video_check_passed');
        if(checks[0]?.status==='awaiting_manual')fail(409,'video_check_review_pending');
        if(checks.length>=quiz.max_attempts)fail(409,'attempt_limit_reached');
        if(checks[0]&&quiz.cooldown_seconds>0&&new Date(checks[0].submitted_at).getTime()+quiz.cooldown_seconds*1000>Date.now())fail(409,'attempt_cooldown');
        const grade=gradeQuiz(quiz,responses),status=grade.requires_manual?'awaiting_manual':'graded';
        const passed=grade.requires_manual?null:grade.max_points>0&&grade.auto_points*100/grade.max_points>=quiz.passing_percent;
        const id=randomUUID(),attempt=(await db.query(`INSERT INTO training_video_checks
          (id,company_id,recipient_id,version_id,block_id,attempt_number,request_key,input_sha256,status,responses,grade_details,auto_points,total_points,max_points,passed,graded_at)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,CASE WHEN $9='graded' THEN now() ELSE NULL END) RETURNING *`,
          [id,actor.companyId,row.id,row.version_id,block.id,checks.length+1,key,hash,status,JSON.stringify(responses),
            JSON.stringify(grade.details),grade.auto_points,grade.requires_manual?null:grade.auto_points,grade.max_points,passed])).rows[0];
        await audit(db,actor,'video.check_submitted',{recipientID:row.id,definitionID:row.definition_id,
          details:{attempt_id:id,block_id:block.id,status,passed}});
        await recordTrainingEvent(db,actor,{type:status==='awaiting_manual'?'training.video_check_pending_grade':passed?'training.video_check_passed':'training.video_check_failed',
          subjectType:'training_video_check',subjectID:id,key:`video-check:${id}:submitted`,
          payload:{attempt_id:id,recipient_id:row.id,employee_id:row.employee_id,block_id:block.id,status,passed}});
        return checkDTO(attempt,quiz);
      });},
    async graderView(req,id){const actor=await actorFor(pool,req);requireTraining(actor,'training.review');
      const row=await attemptFor(pool,actor,id);if(row.employee_id===actor.userId)fail(403,'self_review_forbidden');
      await requireSupervision(pool,actor,row.employee_id);const block=checkBlock(row.document,row.block_id);
      return checkDTO(row,block.video.knowledge_check,{grader:true});},
    async grade(req,id,body){
      return trainingMutation(pool,req,['training.review'],async (db,actor)=>{const row=await attemptFor(db,actor,id,{lock:true});
        if(row.employee_id===actor.userId)fail(403,'self_review_forbidden');await requireSupervision(db,actor,row.employee_id);
        if(row.status!=='awaiting_manual')fail(409,'manual_grade_not_pending');
        const block=checkBlock(row.document,row.block_id),quiz=block.video.knowledge_check;
        const required=quiz.questions.filter(q=>['short_answer','essay'].includes(q.type)&&row.responses[q.id]!=null);
        if(!body?.grades||typeof body.grades!=='object'||Array.isArray(body.grades)||Object.keys(body.grades).length!==required.length)fail(400,'invalid_manual_grades');
        const details={...row.grade_details};let manual=0;
        for(const question of required){const grade=body.grades[question.id];
          if(!grade||typeof grade.points!=='number'||!Number.isFinite(grade.points)||grade.points<0||grade.points>question.points)fail(400,'invalid_manual_grade');
          const feedback=string(grade.feedback??'',2000,{required:false});manual+=grade.points;
          details[question.id]={...details[question.id],manual_points:grade.points,feedback,requires_manual:false};}
        const total=Math.max(0,Math.round((Number(row.auto_points)+manual)*100)/100),passed=total*100/Number(row.max_points)>=quiz.passing_percent;
        const feedback=string(body.feedback??'',2000,{required:false});
        const updated=(await db.query(`UPDATE training_video_checks SET status='graded',total_points=$3,passed=$4,
          grade_details=$5,graded_at=now(),graded_by=$6,feedback=$7 WHERE company_id=$1 AND id=$2 RETURNING *`,
          [actor.companyId,row.id,total,passed,JSON.stringify(details),actor.userId,feedback])).rows[0];
        await audit(db,actor,'video.check_graded',{recipientID:row.recipient_id,definitionID:row.definition_id,
          details:{attempt_id:row.id,block_id:row.block_id,passed,total_points:total,feedback}});
        await recordTrainingEvent(db,actor,{type:passed?'training.video_check_passed':'training.video_check_failed',
          subjectType:'training_video_check',subjectID:row.id,key:`video-check:${row.id}:graded`,
          payload:{attempt_id:row.id,recipient_id:row.recipient_id,employee_id:row.employee_id,block_id:row.block_id,status:'graded',passed}});
        return checkDTO(updated,quiz,{grader:true});
      });}
  };
}
