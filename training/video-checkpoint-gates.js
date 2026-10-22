export async function checkpointState(db,actor,row,block){
  const checkpoints=block.video.checkpoints??[];
  if(!checkpoints.length)return {checkpoints:[],latest:new Map(),gate:null};
  const attempts=(await db.query(`SELECT id,checkpoint_id,attempt_number,status,passed,unlocked,replay_intervals,replay_completed_at
    FROM training_video_checkpoint_attempts WHERE company_id=$1 AND recipient_id=$2 AND block_id=$3 AND version_id=$4
    ORDER BY checkpoint_id,attempt_number DESC`,[actor.companyId,row.recipient_id??row.id,block.id,row.version_id])).rows;
  const latest=new Map();for(const attempt of attempts)if(!latest.has(attempt.checkpoint_id))latest.set(attempt.checkpoint_id,attempt);
  return {checkpoints,latest,gate:checkpoints.find(checkpoint=>!latest.get(checkpoint.id)?.unlocked)??null};
}
