import {hasCapability} from '../permissions.js';
import {fail} from './contract.js';
import {actorFor,requireTraining,trainingMutation} from './service.js';
import {parseTrainingVideoURL} from './video-providers.js';

export function createVideoCatalogService({pool,catalog,signer,capabilities}){
  return {
    async detect(req,body){const actor=await actorFor(pool,req);requireTraining(actor,'training.author');
      const video=parseTrainingVideoURL(body?.url);
      return {...video,capabilities:capabilities[video.provider]};},
    async list(req){const actor=await actorFor(pool,req);
      if(!actor.isCompanyOwner&&!hasCapability(actor,'training.author')&&!hasCapability(actor,'training.providers'))fail(403,'permission_denied');
      return {items:(await pool.query(`SELECT playback_id,asset_id,duration_seconds,policy,verified_at FROM training_video_assets
        WHERE company_id=$1 ORDER BY verified_at DESC,playback_id LIMIT 100`,[actor.companyId])).rows};},
    async verify(req,body){
      if(!catalog?.ready||!signer?.ready)fail(503,'mux_not_configured');
      const media=parseTrainingVideoURL(body?.url);
      if(media.provider!=='mux')fail(400,'mux_video_required');
      const verified=await catalog.verifyPlayback(media.external_id);
      if(verified.policy!=='signed'||verified.playback_id!==media.external_id)fail(409,'mux_signed_asset_required');
      return trainingMutation(pool,req,['training.providers'],async (db,actor)=>{
      const existing=(await db.query(`SELECT asset_id,duration_seconds FROM training_video_assets WHERE company_id=$1 AND playback_id=$2`,
        [actor.companyId,verified.playback_id])).rows[0];
      if(existing&&(existing.asset_id!==verified.asset_id||existing.duration_seconds!==verified.duration_seconds))fail(409,'video_asset_metadata_changed');
      const row=(await db.query(`INSERT INTO training_video_assets(company_id,playback_id,asset_id,duration_seconds,policy,verified_by)
        VALUES($1,$2,$3,$4,'signed',$5) ON CONFLICT(company_id,playback_id) DO UPDATE SET verified_at=now(),verified_by=$5
        RETURNING playback_id,asset_id,duration_seconds,policy,verified_at`,
        [actor.companyId,verified.playback_id,verified.asset_id,verified.duration_seconds,actor.userId])).rows[0];
      return row;});}
  };
}
