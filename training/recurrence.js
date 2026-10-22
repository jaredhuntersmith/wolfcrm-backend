import {randomUUID} from 'node:crypto';
import {transact} from '../company-comms/access.js';
import {digest,fail,string,uuid} from './contract.js';
import {actorFor,assignRow,audit,eligibleAssignees,requireTraining,trainingMutation} from './service.js';
import {recordTrainingEvent} from './events.js';

function owner(actor){requireTraining(actor,'training.assign');if(!actor.isCompanyOwner)fail(403,'owner_required');}
function localDate(value){const parsed=typeof value==='string'?new Date(`${value}T00:00:00Z`):null;
  if(typeof value!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(value)||
    Number.isNaN(parsed.getTime())||parsed.toISOString().slice(0,10)!==value)fail(400,'invalid_local_date');return value;}
function localTime(value){if(typeof value!=='string'||!/^([01]\d|2[0-3]):[0-5]\d$/.test(value))fail(400,'invalid_local_time');return value;}
function recipients(value){if(!Array.isArray(value)||value.length<1||value.length>100)fail(400,'invalid_recipients');
  const ids=[...new Set(value.map(uuid))].sort();if(ids.length<1)fail(400,'invalid_recipients');return ids;}
function days(value){if(![1,7].includes(value))fail(400,'invalid_recurrence_interval');return value;}
function dueHours(value){if(!Number.isInteger(value)||value<0||value>8760)fail(400,'invalid_due_after_hours');return value;}

export function createRecurrenceService({pool}){
  return {
    async list(req){const actor=await actorFor(pool,req);owner(actor);
      const rows=(await pool.query(`SELECT id,definition_id,version_id,recipient_ids,time_zone,interval_days,
        local_time::text AS local_time,next_local_date::text AS next_local_date,next_at,due_after_hours,
        end_on::text AS end_on,active,created_at,disabled_at
        FROM training_recurrence_rules WHERE company_id=$1 ORDER BY created_at DESC,id LIMIT 100`,[actor.companyId])).rows;
      return {items:rows};},
    async create(req,body){
      const definitionID=uuid(body?.definition_id),requestedVersion=body?.version_id?uuid(body.version_id):null;
      const recipientIDs=recipients(body?.recipient_ids),timeZone=string(body?.time_zone,100),intervalDays=days(body?.interval_days);
      const startOn=localDate(body?.start_on),atTime=localTime(body?.local_time),dueAfter=dueHours(body?.due_after_hours);
      const endOn=body?.end_on==null?null:localDate(body.end_on),key=string(body?.request_key,120);
      if(endOn&&endOn<startOn)fail(400,'invalid_date_range');
      const hash=digest({definitionID,requestedVersion,recipientIDs,timeZone,intervalDays,startOn,atTime,dueAfter,endOn});
      return trainingMutation(pool,req,['training.assign'],async(db,actor)=>{owner(actor);
        await db.query(`SELECT pg_advisory_xact_lock(hashtext($1))`,[`${actor.companyId}:${actor.userId}:recurrence:${key}`]);
        const prior=(await db.query(`SELECT id,definition_id,version_id,recipient_ids,time_zone,interval_days,
          local_time::text AS local_time,next_local_date::text AS next_local_date,next_at,due_after_hours,
          end_on::text AS end_on,active,created_at,input_sha256 FROM training_recurrence_rules
          WHERE company_id=$1 AND created_by=$2 AND request_key=$3`,[actor.companyId,actor.userId,key])).rows[0];
        if(prior){if(prior.input_sha256!==hash)fail(409,'request_key_conflict');delete prior.input_sha256;return prior;}
        const zone=(await db.query(`SELECT 1 FROM pg_timezone_names WHERE name=$1`,[timeZone])).rowCount;
        if(!zone)fail(400,'invalid_time_zone');
        const definition=(await db.query(`SELECT latest_version FROM training_definitions
          WHERE company_id=$1 AND id=$2 AND archived_at IS NULL AND (scope='company' OR created_by=$3)`,
        [actor.companyId,definitionID,actor.userId])).rows[0];
        if(!definition)fail(404,'definition_not_found');
        const versionID=requestedVersion??(await db.query(`SELECT id FROM training_versions
          WHERE company_id=$1 AND definition_id=$2 AND version_number=$3`,
          [actor.companyId,definitionID,definition.latest_version])).rows[0]?.id;
        if(!versionID)fail(409,'definition_unpublished');
        if(!(await db.query(`SELECT 1 FROM training_versions WHERE company_id=$1 AND definition_id=$2 AND id=$3`,
          [actor.companyId,definitionID,versionID])).rowCount)fail(404,'version_not_found');
        await eligibleAssignees(db,actor,recipientIDs);
        const instant=(await db.query(`SELECT (($1::date+$2::time) AT TIME ZONE $3) AS next_at`,
          [startOn,atTime,timeZone])).rows[0].next_at;
        if(new Date(instant).getTime()<Date.now()-86400000)fail(400,'recurrence_start_too_old');
        const id=randomUUID();
        const row=(await db.query(`INSERT INTO training_recurrence_rules
          (id,company_id,definition_id,version_id,created_by,request_key,input_sha256,recipient_ids,
            time_zone,interval_days,local_time,next_local_date,next_at,due_after_hours,end_on)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
          RETURNING id,definition_id,version_id,recipient_ids,time_zone,interval_days,
            local_time::text AS local_time,next_local_date::text AS next_local_date,next_at,due_after_hours,
            end_on::text AS end_on,active,created_at`,
          [id,actor.companyId,definitionID,versionID,actor.userId,key,hash,recipientIDs,timeZone,
            intervalDays,atTime,startOn,instant,dueAfter,endOn])).rows[0];
        await audit(db,actor,'recurrence.created',{definitionID,details:{rule_id:id,version_id:versionID}});
        return row;
      });},
    async disable(req,id){
      return trainingMutation(pool,req,['training.assign'],async(db,actor)=>{owner(actor);
        const row=(await db.query(`UPDATE training_recurrence_rules
          SET active=false,disabled_at=COALESCE(disabled_at,now())
          WHERE company_id=$1 AND id=$2 RETURNING id,definition_id,active,disabled_at`,
          [actor.companyId,uuid(id)])).rows[0];
        if(!row)fail(404,'recurrence_not_found');
        await audit(db,actor,'recurrence.disabled',{definitionID:row.definition_id,details:{rule_id:row.id}});
        return row;
      });}
  };
}

// Invoke from the existing maintenance scheduler. A rule row lock and occurrence key
// make each civil-date dispatch atomic and safe to retry after interruption.
export async function runTrainingRecurrences(pool,{now=new Date(),limit=25}={}){
  const instant=new Date(now),batch=Math.max(1,Math.min(100,Number(limit)||25));
  if(Number.isNaN(instant.getTime()))fail(400,'invalid_run_time');
  return transact(pool,async db=>{
    const rules=(await db.query(`SELECT *,next_local_date::text AS local_date
      FROM training_recurrence_rules WHERE active AND next_at<=$1
      ORDER BY next_at,id LIMIT $2 FOR UPDATE SKIP LOCKED`,[instant,batch])).rows;
    let assigned=0,skipped=0;
    for(const rule of rules){
      const sponsor=(await db.query(`SELECT u.id FROM companies c JOIN users u ON u.id=c.owner_user_id
        WHERE c.id=$1 AND u.company_id=$1 AND u.deleted_at IS NULL`,[rule.company_id])).rows[0];
      if(!sponsor)throw new Error('training_recurrence_owner_unavailable');
      const actor={companyId:rule.company_id,userId:sponsor.id,isCompanyOwner:true};
      const eligible=(await db.query(`SELECT id FROM users WHERE company_id=$1 AND id=ANY($2::uuid[])
        AND deleted_at IS NULL ORDER BY id`,[rule.company_id,rule.recipient_ids])).rows.map(row=>row.id);
      let assignmentID=null,status='no_active_recipients';
      if(eligible.length){
        const availableAt=new Date(rule.next_at).toISOString();
        const dueAt=new Date(new Date(rule.next_at).getTime()+rule.due_after_hours*3600000).toISOString();
        const key=`recurrence:${rule.id}:${rule.local_date}`;
        const inputHash=digest({ruleID:rule.id,localDate:rule.local_date,versionID:rule.version_id,
          recipientIDs:eligible,availableAt,dueAt});
        const assignment=await assignRow(db,actor,{definitionID:rule.definition_id,versionID:rule.version_id,
          recipientIDs:eligible,availableAt,dueAt,expiresAt:null,key,inputHash});
        assignmentID=assignment.id;status='assigned';assigned++;
      }else{
        await recordTrainingEvent(db,actor,{type:'training.recurrence_skipped',subjectType:'training_recurrence',
          subjectID:rule.id,key:`recurrence:${rule.id}:${rule.local_date}:skipped`,
          payload:{rule_id:rule.id,local_date:rule.local_date,reason:'no_active_recipients'}});
        skipped++;
      }
      await db.query(`INSERT INTO training_recurrence_occurrences(company_id,rule_id,local_date,assignment_id,status)
        VALUES($1,$2,$3,$4,$5) ON CONFLICT(company_id,rule_id,local_date) DO NOTHING`,
        [rule.company_id,rule.id,rule.local_date,assignmentID,status]);
      await db.query(`UPDATE training_recurrence_rules SET
        next_at=((next_local_date+interval_days+local_time) AT TIME ZONE time_zone),
        active=CASE WHEN end_on IS NOT NULL AND next_local_date+interval_days>end_on THEN false ELSE active END,
        next_local_date=next_local_date+interval_days WHERE company_id=$1 AND id=$2`,
        [rule.company_id,rule.id]);
    }
    return {processed:rules.length,assigned,skipped};
  });
}
