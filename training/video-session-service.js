import {randomUUID} from 'node:crypto';
import {blockVisible,digest,fail,string,uuid} from './contract.js';
import {actorFor,audit,checkAvailability,recipientFor,requireTraining,trainingMutation} from './service.js';
import {recordTrainingEvent} from './events.js';
import {addCoveredInterval,contiguousPosition,coveredSeconds} from './video-progress.js';
import {checkpointState} from './video-checkpoint-gates.js';
import {requirePrerequisites} from './prerequisites.js';

function sequence(value){if(!Number.isInteger(value)||value<1||value>10000)fail(400,'invalid_video_sequence');return value;}
const MAX_EVENT_BYTES=1024;
const MAX_EVENTS_PER_MINUTE=120;
function blockFor(document,id){const block=document.blocks.find(item=>item.id===id&&item.type==='video');if(!block)fail(404,'video_not_found');return block;}
function authorize(actor,row){requireTraining(actor,'training.view_self');if(row.employee_id!==actor.userId)fail(403,'recipient_only');}
function statusDTO(row,block,{playbackURL=null,accepted=true,reason=null}={}){
  const intervals=row.intervals??[];
  return {id:row.id??null,recipient_id:row.recipient_id,version_id:row.version_id,block_id:block.id,
    status:row.status??(row.completed_at?'completed':'not_started'),mode:block.video.mode,
    duration_seconds:block.video.duration_seconds,max_rate:block.video.max_rate,
    watched_seconds:coveredSeconds(intervals),resume_position:contiguousPosition(intervals),
    watch_time_seconds:Number(row.watch_time_seconds??0),
    completed_at:row.completed_at??null,expires_at:row.expires_at??null,
    last_seq:row.last_seq??0,anomaly_count:row.anomaly_count??0,accepted,reason,
    ...(playbackURL?{playback_url:playbackURL}:{})};
}

export function createVideoSessionService({pool,signer}){
  async function sessionFor(db,actor,id,{lock=false}={}){
    const row=(await db.query(`SELECT s.*,r.employee_id,r.status AS recipient_status,r.responses,a.available_at,
      a.expires_at AS assignment_expires_at,v.document,p.intervals,p.completed_at,p.watch_time_seconds
      FROM training_video_sessions s
      JOIN training_recipients r ON r.company_id=s.company_id AND r.id=s.recipient_id
      JOIN training_assignments a ON a.company_id=r.company_id AND a.id=r.assignment_id
      JOIN training_versions v ON v.company_id=s.company_id AND v.id=s.version_id
      JOIN training_video_progress p ON p.company_id=s.company_id AND p.recipient_id=s.recipient_id AND p.block_id=s.block_id
      WHERE s.company_id=$1 AND s.id=$2 ${lock?'FOR UPDATE OF s,p':''}`,[actor.companyId,uuid(id)])).rows[0];
    if(!row)fail(404,'video_session_not_found');return row;
  }
  return {
    async progress(req,recipientID,blockID){const actor=await actorFor(pool,req),recipient=await recipientFor(pool,actor,recipientID);
      authorize(actor,recipient);const block=blockFor(recipient.document,string(blockID,80));
      const row=(await pool.query(`SELECT recipient_id,version_id,block_id,intervals,completed_at,watch_time_seconds FROM training_video_progress
        WHERE company_id=$1 AND recipient_id=$2 AND block_id=$3 AND version_id=$4`,
        [actor.companyId,recipient.id,block.id,recipient.version_id])).rows[0];
      return statusDTO(row??{recipient_id:recipient.id,version_id:recipient.version_id,intervals:[]},block);},
    async start(req,recipientID,blockID){
      if(!signer?.ready)fail(503,'mux_not_configured');const selected=string(blockID,80);
      return trainingMutation(pool,req,['training.view_self'],async (db,actor)=>{
        const recipient=await recipientFor(db,actor,recipientID,{lock:true});authorize(actor,recipient);checkAvailability(recipient);await requirePrerequisites(db,actor,recipient);
        if(recipient.status==='completed')fail(409,'assignment_completed');
        const block=blockFor(recipient.document,selected);
        if(!blockVisible(recipient.document,block,recipient.responses))fail(409,'video_block_hidden');
        if(block.video.provider!=='mux')fail(409,'video_session_not_available');
        const asset=(await db.query(`SELECT duration_seconds FROM training_video_assets WHERE company_id=$1 AND playback_id=$2 AND policy='signed'`,
          [actor.companyId,block.video.external_id])).rows[0];
        if(!asset||asset.duration_seconds!==block.video.duration_seconds)fail(409,'video_asset_unverified');
        await db.query(`INSERT INTO training_video_progress(company_id,recipient_id,version_id,block_id)
          VALUES($1,$2,$3,$4) ON CONFLICT(company_id,recipient_id,block_id) DO NOTHING`,
          [actor.companyId,recipient.id,recipient.version_id,block.id]);
        const progress=(await db.query(`SELECT * FROM training_video_progress WHERE company_id=$1 AND recipient_id=$2 AND block_id=$3 FOR UPDATE`,
          [actor.companyId,recipient.id,block.id])).rows[0];
        if(progress.version_id!==recipient.version_id)fail(409,'video_version_conflict');
        if(progress.completed_at)fail(409,'video_completed');
        await db.query(`UPDATE training_video_sessions SET status='replaced' WHERE company_id=$1 AND recipient_id=$2 AND block_id=$3 AND status='active'`,
          [actor.companyId,recipient.id,block.id]);
        const id=randomUUID(),signed=signer.signPlayback(block.video.external_id,
          {durationSeconds:block.video.duration_seconds,sessionID:id});
        const expires=new Date(signed.expires_at);
        if(!Number.isFinite(expires.getTime())||expires.getTime()<=Date.now())fail(503,'invalid_mux_token_expiry');
        const row=(await db.query(`INSERT INTO training_video_sessions(id,company_id,recipient_id,version_id,block_id,last_position,expires_at)
          VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
          [id,actor.companyId,recipient.id,recipient.version_id,block.id,contiguousPosition(progress.intervals),expires])).rows[0];
        await audit(db,actor,'video.session_started',{recipientID:recipient.id,definitionID:recipient.definition_id,
          details:{session_id:id,block_id:block.id}});
        return statusDTO({...row,intervals:progress.intervals,completed_at:progress.completed_at,
          watch_time_seconds:progress.watch_time_seconds},block,{playbackURL:signed.url});
      });},
    async get(req,id){const actor=await actorFor(pool,req),row=await sessionFor(pool,actor,id);authorize(actor,row);
      return statusDTO(row,blockFor(row.document,row.block_id));},
    async event(req,id,body){
      if(Buffer.byteLength(JSON.stringify(body??{}),'utf8')>MAX_EVENT_BYTES)fail(413,'video_event_too_large');
      const seq=sequence(body?.seq),type=string(body?.type,20);
      if(!['play','pulse','pause','seek','buffering','background','foreground'].includes(type))fail(400,'invalid_video_event');
      const position=Number(body?.position_seconds),rate=Number(body?.rate??1);
      if(!Number.isFinite(position)||position<0||!Number.isFinite(rate)||rate<0.5)fail(400,'invalid_video_position');
      return trainingMutation(pool,req,['training.view_self'],async (db,actor)=>{
        const row=await sessionFor(db,actor,id,{lock:true});authorize(actor,row);
        const block=blockFor(row.document,row.block_id),duration=block.video.duration_seconds;
        if(!blockVisible(row.document,block,row.responses))fail(409,'video_block_hidden');
        const gateState=['D','E'].includes(block.video.mode)?await checkpointState(db,actor,row,block):null;
        const gate=gateState?.gate,gateAt=gate?.at_seconds??duration;
        if(position>duration+0.5)fail(400,'invalid_video_position');
        if(rate>block.video.max_rate+0.01)fail(409,'video_rate_exceeded');
        if(row.status!=='active'||new Date(row.expires_at).getTime()<Date.now())fail(409,'video_session_expired');
        if(row.completed_at)fail(409,'video_completed');
        const hash=digest({seq,type,position,rate});
        if(seq<=row.last_seq){const prior=(await db.query(`SELECT event_hash,accepted,reason FROM training_video_events WHERE company_id=$1 AND session_id=$2 AND seq=$3`,
          [actor.companyId,row.id,seq])).rows[0];
          if(prior?.event_hash!==hash)fail(409,'video_event_replay_conflict');return statusDTO(row,block,{accepted:prior.accepted,reason:prior.reason});}
        if(seq!==row.last_seq+1)fail(409,'video_event_sequence_gap');
        const recent=(await db.query(`SELECT count(*)::integer AS count FROM training_video_events
          WHERE company_id=$1 AND session_id=$2 AND received_at>now()-interval '1 minute'`,
          [actor.companyId,row.id])).rows[0];
        if(recent.count>=MAX_EVENTS_PER_MINUTE)fail(429,'video_event_rate_limited','Too many playback events. Wait a minute and retry.');
        const now=(await db.query('SELECT now() AS now')).rows[0].now;
        const elapsed=row.last_receipt_at?Math.max(0,(new Date(now)-new Date(row.last_receipt_at))/1000):0;
        const eligible=contiguousPosition(row.intervals);
        let intervals=row.intervals,newPosition=position,playbackState=row.playback_state,foreground=row.foreground,watchDelta=0;
        let accepted=true,reason=null,anomalies=row.anomaly_count;
        if(type==='play'){
          if(!foreground)fail(409,'video_foreground_required');
          if(position>eligible+0.5){accepted=false;reason='forward_seek_rejected';newPosition=eligible;anomalies++;playbackState='paused';}
          else if(gate&&position>=gateAt-0.25&&eligible>=gateAt-0.5){accepted=false;reason='checkpoint_required';newPosition=gateAt;playbackState='paused';}
          else playbackState='playing';
        }else if(type==='pulse'){
          const delta=position-Number(row.last_position);
          if(delta< -0.5){playbackState='paused';}
          else if(playbackState==='playing'&&foreground&&elapsed>0&&elapsed<=6){
            if(delta>elapsed*rate+1.5){accepted=false;reason='implausible_progress';newPosition=eligible;anomalies++;playbackState='paused';}
            else if(delta>0){const credit=Math.min(delta,elapsed*rate,Math.max(0,gateAt-Number(row.last_position)));
              intervals=addCoveredInterval(intervals,Number(row.last_position),Number(row.last_position)+credit,duration);
              watchDelta=credit/rate;
              if(credit<delta-0.25){accepted=false;reason=gate&&position>gateAt-0.25?'checkpoint_required':'uncredited_progress';
                newPosition=contiguousPosition(intervals);playbackState='paused';}
              if(gate&&position>=gateAt-0.25&&contiguousPosition(intervals)>=gateAt-0.5){
                accepted=false;reason='checkpoint_required';newPosition=gateAt;playbackState='paused';}
              const previous=gateState?.latest.get(gate?.id);
              if(gate?.kind==='question'&&previous&&!previous.unlocked&&gate.replay_seconds>0&&!previous.replay_completed_at&&credit>0){
                const from=gateAt-gate.replay_seconds,spanStart=Math.max(from,Number(row.last_position));
                const spanEnd=Math.min(gateAt,Number(row.last_position)+credit);
                if(spanEnd>spanStart){const replay=addCoveredInterval(previous.replay_intervals,spanStart,spanEnd,duration);
                  const completed=replay.length===1&&replay[0][0]<=from+0.25&&replay[0][1]>=gateAt-0.5;
                  await db.query(`UPDATE training_video_checkpoint_attempts SET replay_intervals=$3,
                    replay_completed_at=CASE WHEN $4 THEN now() ELSE replay_completed_at END WHERE company_id=$1 AND id=$2`,
                  [actor.companyId,previous.id,JSON.stringify(replay),completed]);}
              }
            }
          }
        }else if(type==='seek'){
          playbackState='paused';
          if(position>eligible+0.5){accepted=false;reason='forward_seek_rejected';newPosition=eligible;anomalies++;}
        }else if(type==='background'){foreground=false;playbackState='paused';}
        else if(type==='foreground'){foreground=true;playbackState='paused';}
        else playbackState=type==='buffering'?'buffering':'paused';
        await db.query(`UPDATE training_video_progress SET intervals=$4,watch_time_seconds=watch_time_seconds+$5,updated_at=now()
          WHERE company_id=$1 AND recipient_id=$2 AND block_id=$3`,
          [actor.companyId,row.recipient_id,row.block_id,JSON.stringify(intervals),watchDelta]);
        await db.query(`UPDATE training_video_sessions SET last_seq=$3,last_event_hash=$4,last_receipt_at=$5,
          last_position=$6,playback_state=$7,foreground=$8,anomaly_count=$9 WHERE company_id=$1 AND id=$2`,
          [actor.companyId,row.id,seq,hash,now,newPosition,playbackState,foreground,anomalies]);
        await db.query(`INSERT INTO training_video_events(company_id,session_id,seq,event_hash,event_type,position_seconds,rate,accepted,reason)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[actor.companyId,row.id,seq,hash,type,position,rate,accepted,reason]);
        return statusDTO({...row,intervals,watch_time_seconds:Number(row.watch_time_seconds)+watchDelta,
          last_seq:seq,last_position:newPosition,playback_state:playbackState,
          foreground,anomaly_count:anomalies},block,{accepted,reason});
      });},
    async finish(req,id){
      return trainingMutation(pool,req,['training.view_self'],async (db,actor)=>{const row=await sessionFor(db,actor,id,{lock:true});authorize(actor,row);
        const block=blockFor(row.document,row.block_id),duration=block.video.duration_seconds;
        if(!blockVisible(row.document,block,row.responses))fail(409,'video_block_hidden');
        if(row.completed_at)return statusDTO(row,block);
        if(row.status!=='active'||new Date(row.expires_at).getTime()<Date.now())fail(409,'video_session_expired');
        if(!['B','C','D','E'].includes(block.video.mode))fail(409,'video_checks_pending');
        if(coveredSeconds(row.intervals)<duration-0.5||contiguousPosition(row.intervals)<duration-0.5)fail(409,'video_coverage_incomplete');
        if(['C','E'].includes(block.video.mode)){
          const check=(await db.query(`SELECT passed FROM training_video_checks WHERE company_id=$1 AND recipient_id=$2 AND block_id=$3 AND version_id=$4 ORDER BY attempt_number DESC LIMIT 1`,
            [actor.companyId,row.recipient_id,row.block_id,row.version_id])).rows[0];
          if(check?.passed!==true)fail(409,'video_knowledge_check_required');
        }
        if(['D','E'].includes(block.video.mode)&&(await checkpointState(db,actor,row,block)).gate)fail(409,'video_checkpoint_required');
        if(block.video.mode==='E'&&block.video.min_watch_seconds!=null&&Number(row.watch_time_seconds)<block.video.min_watch_seconds-0.5)
          fail(409,'minimum_watch_duration_incomplete');
        const progress=(await db.query(`UPDATE training_video_progress SET completed_at=now(),updated_at=now()
          WHERE company_id=$1 AND recipient_id=$2 AND block_id=$3 AND version_id=$4 AND completed_at IS NULL RETURNING *`,
          [actor.companyId,row.recipient_id,row.block_id,row.version_id])).rows[0];
        await db.query(`UPDATE training_video_sessions SET status='completed' WHERE company_id=$1 AND id=$2`,[actor.companyId,row.id]);
        if(progress){await audit(db,actor,'video.completed',{recipientID:row.recipient_id,details:{session_id:row.id,block_id:row.block_id}});
          await recordTrainingEvent(db,actor,{type:'training.video_completed',subjectType:'training_recipient',subjectID:row.recipient_id,
            key:`video:${row.recipient_id}:${row.block_id}:completed`,payload:{recipient_id:row.recipient_id,employee_id:row.employee_id,
              version_id:row.version_id,block_id:row.block_id}});}
        return statusDTO({...row,status:'completed',completed_at:progress?.completed_at??row.completed_at},block);
      });}
  };
}
