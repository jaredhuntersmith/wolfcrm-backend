import {fail} from './contract.js';

export function createMuxCatalogAdapter({tokenID=process.env.MUX_TOKEN_ID,tokenSecret=process.env.MUX_TOKEN_SECRET,
  fetchImpl=fetch}={}){
  if(!tokenID||!tokenSecret)return {ready:false};
  const authorization=`Basic ${Buffer.from(`${tokenID}:${tokenSecret}`).toString('base64')}`;
  async function read(path){
    let response;
    try{response=await fetchImpl(`https://api.mux.com/video/v1/${path}`,{headers:{Authorization:authorization,Accept:'application/json'},signal:AbortSignal.timeout(10_000)});}
    catch{fail(503,'mux_unavailable');}
    if(!response.ok)fail(response.status===404?404:503,response.status===404?'mux_asset_not_found':'mux_unavailable');
    try{return (await response.json()).data;}
    catch{fail(503,'mux_invalid_response');}
  }
  return {ready:true,async verifyPlayback(playbackID){
    if(typeof playbackID!=='string'||!(/^[A-Za-z0-9]{8,128}$/.test(playbackID)))fail(400,'invalid_mux_playback_id');
    const playback=await read(`playback-ids/${playbackID}`);
    if(playback?.policy!=='signed'||playback?.object?.type!=='asset'||!playback.object.id)fail(409,'mux_signed_asset_required');
    const asset=await read(`assets/${playback.object.id}`);
    if(asset?.status!=='ready'||!Array.isArray(asset.playback_ids)||!asset.playback_ids.some(item=>item.id===playbackID&&item.policy==='signed'))
      fail(409,'mux_asset_not_ready');
    const duration=Number(asset.duration);
    if(!Number.isFinite(duration)||duration<1||duration>86400)fail(409,'mux_duration_unavailable');
    return {provider:'mux',playback_id:playbackID,asset_id:playback.object.id,duration_seconds:Math.ceil(duration),policy:'signed'};
  }};
}
