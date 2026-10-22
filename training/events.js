import {randomUUID} from 'node:crypto';
import {transact} from '../company-comms/access.js';

export async function recordTrainingEvent(db,actor,{type,subjectType,subjectID,key,payload={}}){
  const id=randomUUID();
  await db.query(`INSERT INTO training_domain_events(id,company_id,actor_id,event_type,subject_type,subject_id,dedupe_key,payload)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(company_id,dedupe_key) DO NOTHING`,
    [id,actor.companyId,actor.userId,type,subjectType,String(subjectID),key,JSON.stringify(payload)]);
}

// The caller owns the scheduler. emit must insert into the existing automation
// outbox using the supplied transaction, so dispatch and marking are atomic.
export async function drainTrainingEvents(pool,emit,{batchSize=50}={}){
  const limit=Math.max(1,Math.min(100,batchSize));
  return transact(pool,async db=>{
    const rows=(await db.query(`SELECT * FROM training_domain_events WHERE dispatched_at IS NULL
      ORDER BY occurred_at,id LIMIT $1 FOR UPDATE SKIP LOCKED`,[limit])).rows;
    for(const row of rows){
      const automationEventID=await emit({companyId:row.company_id,eventType:row.event_type,subjectType:row.subject_type,
        subjectId:row.subject_id,actorUserId:row.actor_id,source:'training',
        dedupeKey:`training:${row.dedupe_key}`,payload:row.payload,occurredAt:row.occurred_at},{db});
      if(!automationEventID)throw new Error('training_automation_enqueue_failed');
      await db.query(`UPDATE training_domain_events SET dispatched_at=now() WHERE id=$1`,[row.id]);
    }
    return {dispatched:rows.length};
  });
}
