import {randomBytes,randomUUID} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import fontkit from '@pdf-lib/fontkit';
import {PDFDocument,rgb} from 'pdf-lib';
import {flattenLessons} from './course-contract.js';
import {fail,string,uuid} from './contract.js';
import {transact} from '../company-comms/access.js';
import {actorFor,audit,requireSupervision,requireTraining,trainingMutation} from './service.js';
import {recordTrainingEvent} from './events.js';

export async function maybeCompleteCourse(db,actor,recipientID){
  const enrollments=(await db.query(`SELECT e.*,v.document FROM training_course_lesson_runs lr
    JOIN training_course_enrollments e ON e.company_id=lr.company_id AND e.id=lr.enrollment_id
    JOIN training_course_versions v ON v.company_id=e.company_id AND v.id=e.version_id
    WHERE lr.company_id=$1 AND lr.recipient_id=$2 FOR UPDATE OF e`,[actor.companyId,recipientID])).rows;
  for(const enrollment of enrollments){
    if(enrollment.completed_at)continue;
    const required=flattenLessons(enrollment.document).filter(lesson=>lesson.required).map(lesson=>lesson.id);
    const states=(await db.query(`SELECT lr.lesson_id,r.status,r.id AS recipient_id,v.kind
      FROM training_course_lesson_runs lr JOIN training_recipients r ON r.company_id=lr.company_id AND r.id=lr.recipient_id
      JOIN training_assignments a ON a.company_id=r.company_id AND a.id=r.assignment_id
      JOIN training_versions v ON v.company_id=a.company_id AND v.id=a.version_id
      WHERE lr.company_id=$1 AND lr.enrollment_id=$2`,[actor.companyId,enrollment.id])).rows;
    const completed=new Map(states.filter(item=>item.status==='completed').map(item=>[item.lesson_id,item]));
    if(!required.every(id=>completed.has(id)))continue;
    const done=(await db.query(`UPDATE training_course_enrollments SET completed_at=now()
      WHERE company_id=$1 AND id=$2 AND completed_at IS NULL RETURNING completed_at`,[actor.companyId,enrollment.id])).rows[0];
    if(!done)continue;
    await recordTrainingEvent(db,actor,{type:'training.course_completed',subjectType:'training_course_enrollment',subjectID:enrollment.id,
      key:`course:${enrollment.id}:completed`,payload:{enrollment_id:enrollment.id,employee_id:enrollment.employee_id,
        course_id:enrollment.course_id,version_id:enrollment.version_id,completed_at:done.completed_at}});
    if(!enrollment.document.certificate_enabled)continue;
    const quizRecipients=required.map(id=>completed.get(id)).filter(item=>item.kind==='quiz').map(item=>item.recipient_id);
    let score=null;
    if(quizRecipients.length){const scores=(await db.query(`SELECT DISTINCT ON (recipient_id) recipient_id,total_points,max_points
      FROM training_quiz_attempts WHERE company_id=$1 AND recipient_id=ANY($2::uuid[]) AND status='graded' AND passed=true
      ORDER BY recipient_id,attempt_number DESC`,[actor.companyId,quizRecipients])).rows;
      if(scores.length===quizRecipients.length)score=Math.round(scores.reduce((sum,item)=>sum+100*Number(item.total_points)/Number(item.max_points),0)/scores.length*100)/100;}
    const company=(await db.query('SELECT name FROM companies WHERE id=$1',[actor.companyId])).rows[0];
    const expires=enrollment.document.recertification_days==null?null:new Date(new Date(done.completed_at).getTime()+enrollment.document.recertification_days*86400000);
    const certificateID=randomUUID();
    const issued=(await db.query(`INSERT INTO training_certificates(id,company_id,enrollment_id,employee_id,employee_name_snapshot,company_name_snapshot,
      course_title_snapshot,course_version_id,issued_at,expires_at,score_percent,verification_code)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(company_id,enrollment_id) DO NOTHING RETURNING id`,
      [certificateID,actor.companyId,enrollment.id,enrollment.employee_id,enrollment.employee_name_snapshot,company?.name||'Company',
        enrollment.document.title,enrollment.version_id,done.completed_at,expires,score,`WOLF-${randomBytes(10).toString('hex').toUpperCase()}`])).rows[0];
    if(issued)await recordTrainingEvent(db,actor,{type:'training.certificate_issued',subjectType:'training_certificate',subjectID:certificateID,
      key:`certificate:${certificateID}:issued`,payload:{certificate_id:certificateID,enrollment_id:enrollment.id,
        employee_id:enrollment.employee_id,course_id:enrollment.course_id,expires_at:expires}});
  }
}

function dto(row){return {id:row.id,enrollment_id:row.enrollment_id,employee_id:row.employee_id,employee_name:row.employee_name_snapshot,
  company_name:row.company_name_snapshot,course_title:row.course_title_snapshot,course_version_id:row.course_version_id,
  issued_at:row.issued_at,expires_at:row.expires_at,score_percent:row.score_percent==null?null:Number(row.score_percent),
  verification_code:row.verification_code,status:row.revoked_at?'revoked':row.expires_at&&new Date(row.expires_at).getTime()<Date.now()?'expired':'valid'};}
export async function certificateFor(pool,req,id){const actor=await actorFor(pool,req);
  const row=(await pool.query('SELECT * FROM training_certificates WHERE company_id=$1 AND id=$2',[actor.companyId,uuid(id)])).rows[0];
  if(!row)fail(404,'certificate_not_found');
  if(row.employee_id===actor.userId)requireTraining(actor,'training.view_self');
  else{requireTraining(actor,'training.certificates');await requireSupervision(pool,actor,row.employee_id);}
  return dto(row);
}
export async function certificateList(pool,req){const actor=await actorFor(pool,req);requireTraining(actor,'training.view_self');
  const rows=(await pool.query(`SELECT * FROM training_certificates WHERE company_id=$1 AND employee_id=$2 ORDER BY issued_at DESC,id LIMIT 100`,[actor.companyId,actor.userId])).rows;
  return {items:rows.map(dto)};
}
export async function verifyCertificate(pool,req,code){
  if(typeof code!=='string'||!/^WOLF-[A-F0-9]{20}$/.test(code))fail(400,'invalid_verification_code');
  const actor=await actorFor(pool,req);
  const row=(await pool.query('SELECT id FROM training_certificates WHERE company_id=$1 AND verification_code=$2',[actor.companyId,code])).rows[0];
  if(!row)fail(404,'certificate_not_found');return certificateFor(pool,req,row.id);
}
export async function revokeCertificate(pool,req,id,body){
  const reason=string(body?.reason,1000);
  return trainingMutation(pool,req,['training.certificates'],async (db,actor)=>{
    const row=(await db.query('SELECT * FROM training_certificates WHERE company_id=$1 AND id=$2 FOR UPDATE',[actor.companyId,uuid(id)])).rows[0];
    if(!row)fail(404,'certificate_not_found');
    if(row.employee_id===actor.userId)fail(403,'self_revoke_forbidden');
    await requireSupervision(db,actor,row.employee_id);
    if(row.revoked_at)return dto(row);
    const updated=(await db.query(`UPDATE training_certificates SET revoked_at=now(),revoked_by=$3,revocation_reason=$4
      WHERE company_id=$1 AND id=$2 RETURNING *`,[actor.companyId,id,actor.userId,reason])).rows[0];
    await audit(db,actor,'certificate.revoked',{details:{certificate_id:id,reason}});
    await recordTrainingEvent(db,actor,{type:'training.certificate_revoked',subjectType:'training_certificate',subjectID:id,
      key:`certificate:${id}:revoked`,payload:{certificate_id:id,enrollment_id:row.enrollment_id,employee_id:row.employee_id}});
    return dto(updated);
  });
}
export async function queueExpiringCertificates(pool,{daysAhead=30,limit=100}={}){
  if(!Number.isInteger(daysAhead)||daysAhead<1||daysAhead>365||!Number.isInteger(limit)||limit<1||limit>100)
    fail(400,'invalid_expiry_scan');
  return transact(pool,async db=>{
    const rows=(await db.query(`SELECT c.id,c.company_id,c.employee_id,c.enrollment_id,c.expires_at,e.course_id
      FROM training_certificates c
      JOIN users u ON u.id=c.employee_id AND u.company_id=c.company_id AND u.deleted_at IS NULL
      JOIN training_course_enrollments e ON e.company_id=c.company_id AND e.id=c.enrollment_id
      WHERE c.revoked_at IS NULL AND c.expires_at>now()
        AND c.expires_at<=now()+make_interval(days => $1::integer)
        AND NOT EXISTS (SELECT 1 FROM training_domain_events prior WHERE prior.company_id=c.company_id
          AND prior.event_type='training.certificate_expiring' AND prior.subject_type='training_certificate'
          AND prior.subject_id=c.id::text)
      ORDER BY c.expires_at,c.id LIMIT $2 FOR UPDATE OF c SKIP LOCKED`,[daysAhead,limit])).rows;
    let queued=0;
    for(const row of rows){
      const key=`certificate:${row.id}:expiring:${new Date(row.expires_at).toISOString()}`;
      const inserted=await db.query(`INSERT INTO training_domain_events
        (id,company_id,actor_id,event_type,subject_type,subject_id,dedupe_key,payload)
        VALUES($1,$2,NULL,'training.certificate_expiring','training_certificate',$3,$4,$5)
        ON CONFLICT(company_id,dedupe_key) DO NOTHING RETURNING id`,[randomUUID(),row.company_id,row.id,key,
          JSON.stringify({certificate_id:row.id,enrollment_id:row.enrollment_id,employee_id:row.employee_id,
            course_id:row.course_id,expires_at:row.expires_at})]);
      queued+=inserted.rowCount;
    }
    return {scanned:rows.length,queued};
  });
}
export async function certificatePDF(certificate){
  const pdf=await PDFDocument.create();pdf.registerFontkit(fontkit);
  const fontBytes=await readFile(new URL('../assets/NotoSans.ttf',import.meta.url));
  const font=await pdf.embedFont(fontBytes,{subset:true}),bold=font,page=pdf.addPage([792,612]);
  const limited=(value,count)=>Array.from(value).slice(0,count).join('');
  const ink=rgb(0.10,0.16,0.21),accent=rgb(0.07,0.37,0.42);
  page.drawRectangle({x:22,y:22,width:748,height:568,borderWidth:2,borderColor:accent});
  page.drawText('CERTIFICATE OF COMPLETION',{x:82,y:495,size:26,font:bold,color:accent});
  if(certificate.status==='revoked'||certificate.status==='expired'){
    const revoked=certificate.status==='revoked';
    const label=revoked?'REVOKED':'EXPIRED';
    const statusColor=revoked?rgb(0.63,0.12,0.12):rgb(0.55,0.30,0.05);
    page.drawRectangle({x:570,y:486,width:150,height:52,borderWidth:2,borderColor:statusColor});
    page.drawText(label,{x:645-font.widthOfTextAtSize(label,19)/2,y:503,size:19,font:bold,color:statusColor});
    page.drawText(revoked?'This certificate has been revoked.':'This certificate has expired.',
      {x:82,y:465,size:13,font,color:statusColor});
  }
  page.drawText('This company-issued training record certifies that',{x:82,y:442,size:14,font,color:ink});
  page.drawText(limited(certificate.employee_name,60),{x:82,y:390,size:25,font:bold,color:ink});
  page.drawText(limited(`completed ${certificate.course_title}`,85),{x:82,y:340,size:17,font,color:ink});
  page.drawText(limited(`Issued by ${certificate.company_name}`,90),{x:82,y:296,size:14,font,color:ink});
  page.drawText(`Completed ${new Date(certificate.issued_at).toISOString().slice(0,10)}`,{x:82,y:254,size:12,font,color:ink});
  if(certificate.score_percent!=null)page.drawText(`Score ${certificate.score_percent}%`,{x:82,y:231,size:12,font,color:ink});
  if(certificate.expires_at)page.drawText(`Expires ${new Date(certificate.expires_at).toISOString().slice(0,10)}`,{x:82,y:208,size:12,font,color:ink});
  page.drawText(`ID ${certificate.verification_code}`,{x:82,y:103,size:12,font:bold,color:accent});
  page.drawText(`Status: ${certificate.status}`,{x:82,y:81,size:11,font,color:ink});
  page.drawText('Internal company training record',{x:520,y:81,size:9,font,color:ink});
  return Buffer.from(await pdf.save());
}
