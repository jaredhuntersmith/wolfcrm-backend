import {randomInt,randomUUID} from 'node:crypto';
import {fail,string,uuid} from './contract.js';
import {gradeQuiz,learnerQuiz,normalizeQuizAnswers} from './quiz-contract.js';
import {actorFor,audit,checkAvailability,recipientFor,requireSupervision,requireTraining,trainingMutation} from './service.js';
import {maybeCompleteCourse} from './certificates.js';
import {recordTrainingEvent} from './events.js';
import {requirePrerequisites} from './prerequisites.js';

function revision(value){if(!Number.isInteger(value)||value<1)fail(400,'invalid_revision');return value;}
function shuffle(input){const values=[...input];for(let i=values.length-1;i>0;i--){const j=randomInt(i+1);[values[i],values[j]]=[values[j],values[i]];}return values;}
function quizRecipient(actor,row){
  if(actor.userId!==row.employee_id)fail(403,'recipient_only');
  requireTraining(actor,'training.view_self');
  if(row.kind!=='quiz')fail(409,'not_a_quiz');
}
async function attemptFor(db,actor,id,{lock=false}={}){
  const row=(await db.query(`SELECT t.*,r.employee_id,r.assignment_id,r.status AS recipient_status,
      a.definition_id,a.available_at,a.due_at,a.expires_at,v.kind,v.document
    FROM training_quiz_attempts t
    JOIN training_recipients r ON r.company_id=t.company_id AND r.id=t.recipient_id
    JOIN training_assignments a ON a.company_id=r.company_id AND a.id=r.assignment_id
    JOIN training_versions v ON v.company_id=t.company_id AND v.id=t.version_id
    WHERE t.company_id=$1 AND t.id=$2 ${lock?'FOR UPDATE OF t,r':''}`,[actor.companyId,uuid(id)])).rows[0];
  if(!row)fail(404,'attempt_not_found');return row;
}
function attemptDTO(row,{grader=false}={}){
  const quiz=row.document.quiz;
  const reveal=row.status==='graded'&&(quiz.show_results==='immediate'||
    quiz.show_results==='after_review'&&row.recipient_status!=='awaiting_review');
  const result={id:row.id,recipient_id:row.recipient_id,version_id:row.version_id,
    attempt_number:row.attempt_number,status:row.status,revision:row.revision,
    started_at:row.started_at,deadline_at:row.deadline_at,submitted_at:row.submitted_at,
    responses:row.responses,quiz:learnerQuiz(quiz,{questionOrder:row.question_order,choiceOrders:row.choice_orders})};
  if(reveal||grader){result.score_points=Number(row.total_points);result.max_points=Number(row.max_points);result.passed=row.passed;result.grade_details=row.grade_details;result.feedback=row.feedback;}
  if(reveal&&quiz.show_answers_after_grade)result.answer_review=quiz.questions.map(question=>({id:question.id,answer:question.answer,explanation:question.explanation}));
  if(grader)result.author_questions=quiz.questions;
  return result;
}
function resultStatus(document,passed,manualPending=false){
  if(manualPending)return 'awaiting_review';
  if(!passed)return 'in_progress';
  return document.requires_review?'awaiting_review':'completed';
}
async function setRecipientResult(db,actor,row,status){
  await db.query(`UPDATE training_recipients SET status=$3,
    completed_at=CASE WHEN $3='completed' THEN now() ELSE NULL END,
    submitted_at=now(),revision=revision+1,updated_at=now()
    WHERE company_id=$1 AND id=$2`,[actor.companyId,row.recipient_id,status]);
  if(status==='completed')await maybeCompleteCourse(db,actor,row.recipient_id);
}
function scorePassed(points,maxPoints,requiredPercent){return maxPoints>0&&points*100/maxPoints>=requiredPercent;}

export function createQuizService({pool}){
  return {
    async start(req,recipientID){
      return trainingMutation(pool,req,[],async (db,actor)=>{
        const recipient=await recipientFor(db,actor,recipientID,{lock:true});quizRecipient(actor,recipient);checkAvailability(recipient);await requirePrerequisites(db,actor,recipient);
        if(recipient.status==='completed')fail(409,'quiz_completed');
        const attempts=(await db.query(`SELECT * FROM training_quiz_attempts WHERE company_id=$1 AND recipient_id=$2 ORDER BY attempt_number DESC`,[actor.companyId,recipient.id])).rows;
        const active=attempts.find(item=>item.status==='active');
        if(active)return attemptDTO({...active,document:recipient.document,recipient_status:recipient.status});
        if(attempts.some(item=>item.status==='awaiting_manual')||recipient.status==='awaiting_review')fail(409,'review_pending');
        const quiz=recipient.document.quiz;
        if(attempts.length>=quiz.max_attempts)fail(409,'attempt_limit_reached');
        const last=attempts[0];
        if(last&&quiz.cooldown_seconds>0&&new Date(last.submitted_at??last.started_at).getTime()+quiz.cooldown_seconds*1000>Date.now())fail(409,'attempt_cooldown');
        const questionIDs=quiz.questions.map(question=>question.id);
        const questionOrder=quiz.shuffle_questions?shuffle(questionIDs):questionIDs;
        const choiceOrders=Object.fromEntries(quiz.questions.map(question=>[question.id,quiz.shuffle_answers?shuffle(question.options.map(option=>option.id)):question.options.map(option=>option.id)]));
        const expiry=quiz.time_limit_seconds==null?null:new Date(Date.now()+quiz.time_limit_seconds*1000);
        const deadline=recipient.expires_at&&expiry?new Date(Math.min(new Date(recipient.expires_at),expiry)):(expiry??recipient.expires_at);
        const id=randomUUID();
        const row=(await db.query(`INSERT INTO training_quiz_attempts(id,company_id,recipient_id,version_id,attempt_number,question_order,choice_orders,deadline_at)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,[id,actor.companyId,recipient.id,recipient.version_id,attempts.length+1,JSON.stringify(questionOrder),JSON.stringify(choiceOrders),deadline])).rows[0];
        await audit(db,actor,'quiz.attempt_started',{recipientID:recipient.id,definitionID:recipient.definition_id,details:{attempt_id:id,attempt_number:row.attempt_number}});
        return attemptDTO({...row,document:recipient.document,recipient_status:recipient.status});
      });},
    async list(req,recipientID){const actor=await actorFor(pool,req);const recipient=await recipientFor(pool,actor,recipientID);quizRecipient(actor,recipient);
      const rows=(await pool.query(`SELECT * FROM training_quiz_attempts WHERE company_id=$1 AND recipient_id=$2 ORDER BY attempt_number DESC`,[actor.companyId,recipient.id])).rows;
      return {items:rows.map(row=>attemptDTO({...row,document:recipient.document,recipient_status:recipient.status}))};},
    async get(req,attemptID){const actor=await actorFor(pool,req);const row=await attemptFor(pool,actor,attemptID);quizRecipient(actor,row);return attemptDTO(row);},
    async save(req,attemptID,body){const expected=revision(body?.expected_revision);
      return trainingMutation(pool,req,[],async (db,actor)=>{const row=await attemptFor(db,actor,attemptID,{lock:true});quizRecipient(actor,row);
        if(row.status!=='active')fail(409,'attempt_not_active');
        if(row.revision!==expected)fail(409,'stale_revision');
        if(row.deadline_at&&new Date(row.deadline_at).getTime()<Date.now())fail(409,'exam_time_expired');
        const responses=normalizeQuizAnswers(row.document.quiz,body?.responses);
        const updated=(await db.query(`UPDATE training_quiz_attempts SET responses=$3,revision=revision+1
          WHERE company_id=$1 AND id=$2 RETURNING *`,[actor.companyId,row.id,JSON.stringify(responses)])).rows[0];
        await audit(db,actor,'quiz.responses_saved',{recipientID:row.recipient_id,definitionID:row.definition_id,details:{attempt_id:row.id,revision:updated.revision}});
        return attemptDTO({...updated,document:row.document});
      });},
    async submit(req,attemptID,body){const expected=revision(body?.expected_revision);
      return trainingMutation(pool,req,[],async (db,actor)=>{const row=await attemptFor(db,actor,attemptID,{lock:true});quizRecipient(actor,row);
        if(row.status!=='active')return attemptDTO(row);
        if(row.revision!==expected)fail(409,'stale_revision');
        const grade=gradeQuiz(row.document.quiz,row.responses);
        const passed=grade.requires_manual?null:scorePassed(grade.auto_points,grade.max_points,row.document.quiz.passing_percent);
        const status=grade.requires_manual?'awaiting_manual':'graded';
        const updated=(await db.query(`UPDATE training_quiz_attempts SET status=$3,auto_points=$4,total_points=$4,max_points=$5,
          grade_details=$6,passed=$7,submitted_at=now(),graded_at=CASE WHEN $3='graded' THEN now() ELSE NULL END,revision=revision+1
          WHERE company_id=$1 AND id=$2 RETURNING *`,[actor.companyId,row.id,status,grade.auto_points,grade.max_points,JSON.stringify(grade.details),passed])).rows[0];
        const recipientStatus=resultStatus(row.document,passed,grade.requires_manual);
        await setRecipientResult(db,actor,row,recipientStatus);
        await audit(db,actor,'quiz.attempt_submitted',{recipientID:row.recipient_id,definitionID:row.definition_id,details:{attempt_id:row.id,status,passed}});
        await recordTrainingEvent(db,actor,{type:grade.requires_manual?'training.quiz_pending_grade':passed?'training.quiz_passed':'training.quiz_failed',
          subjectType:'training_quiz_attempt',subjectID:row.id,key:`quiz:${row.id}:submitted`,
          payload:{attempt_id:row.id,recipient_id:row.recipient_id,employee_id:row.employee_id,definition_id:row.definition_id,status,passed}});
        return attemptDTO({...updated,document:row.document,recipient_status:recipientStatus});
      });},
    async graderView(req,attemptID){const actor=await actorFor(pool,req);requireTraining(actor,'training.review');const row=await attemptFor(pool,actor,attemptID);
      if(row.employee_id===actor.userId)fail(403,'self_review_forbidden');await requireSupervision(pool,actor,row.employee_id);return attemptDTO(row,{grader:true});},
    async reviewForRecipient(req,recipientID){const actor=await actorFor(pool,req);requireTraining(actor,'training.review');
      const recipient=await recipientFor(pool,actor,recipientID);
      if(recipient.kind!=='quiz')fail(409,'not_a_quiz');if(recipient.employee_id===actor.userId)fail(403,'self_review_forbidden');
      await requireSupervision(pool,actor,recipient.employee_id);
      const attempt=(await pool.query(`SELECT * FROM training_quiz_attempts WHERE company_id=$1 AND recipient_id=$2 ORDER BY attempt_number DESC LIMIT 1`,[actor.companyId,recipient.id])).rows[0];
      if(!attempt)fail(404,'attempt_not_found');return attemptDTO({...attempt,document:recipient.document},{grader:true});},
    async grade(req,attemptID,body){const expected=revision(body?.expected_revision);
      return trainingMutation(pool,req,['training.review'],async (db,actor)=>{const row=await attemptFor(db,actor,attemptID,{lock:true});
        if(row.employee_id===actor.userId)fail(403,'self_review_forbidden');await requireSupervision(db,actor,row.employee_id);
        if(row.status!=='awaiting_manual')fail(409,'manual_grade_not_pending');if(row.revision!==expected)fail(409,'stale_revision');
        const required=row.document.quiz.questions.filter(question=>['short_answer','essay'].includes(question.type)&&row.responses[question.id]!=null);
        if(!body?.grades||typeof body.grades!=='object'||Array.isArray(body.grades)||Object.keys(body.grades).length!==required.length)fail(400,'invalid_manual_grades');
        const details={...row.grade_details};let manual=0;
        for(const question of required){
          const grade=body.grades[question.id];if(!grade||typeof grade!=='object'||typeof grade.points!=='number'||!Number.isFinite(grade.points)||grade.points<0||grade.points>question.points)fail(400,'invalid_manual_grade');
          const feedback=string(grade.feedback??'',2000,{required:false});manual+=grade.points;
          details[question.id]={...details[question.id],manual_points:grade.points,feedback,requires_manual:false};
        }
        const total=Math.max(0,Math.round((Number(row.auto_points)+manual)*100)/100),passed=scorePassed(total,Number(row.max_points),row.document.quiz.passing_percent);
        const feedback=string(body.feedback??'',2000,{required:false});
        const updated=(await db.query(`UPDATE training_quiz_attempts SET status='graded',total_points=$3,passed=$4,
          grade_details=$5,graded_at=now(),graded_by=$6,feedback=$7,revision=revision+1
          WHERE company_id=$1 AND id=$2 RETURNING *`,[actor.companyId,row.id,total,passed,JSON.stringify(details),actor.userId,feedback])).rows[0];
        await setRecipientResult(db,actor,row,resultStatus(row.document,passed));
        await audit(db,actor,'quiz.manual_graded',{recipientID:row.recipient_id,definitionID:row.definition_id,details:{attempt_id:row.id,passed,total_points:total,feedback}});
        await recordTrainingEvent(db,actor,{type:passed?'training.quiz_passed':'training.quiz_failed',
          subjectType:'training_quiz_attempt',subjectID:row.id,key:`quiz:${row.id}:graded`,
          payload:{attempt_id:row.id,recipient_id:row.recipient_id,employee_id:row.employee_id,definition_id:row.definition_id,status:'graded',passed}});
        return attemptDTO({...updated,document:row.document},{grader:true});
      });}
  };
}
