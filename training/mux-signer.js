import {createPrivateKey,sign} from 'node:crypto';
import {fail,uuid} from './contract.js';

const encode=value=>Buffer.from(JSON.stringify(value)).toString('base64url');

export function createMuxSigner({keyID=process.env.MUX_SIGNING_KEY_ID,privateKeyBase64=process.env.MUX_SIGNING_PRIVATE_KEY}={}){
  if(!keyID||!privateKeyBase64)return {ready:false};
  if(typeof keyID!=='string'||!(/^[A-Za-z0-9_-]{8,128}$/.test(keyID)))fail(500,'invalid_mux_signing_key_id');
  let key;
  try{key=createPrivateKey(Buffer.from(privateKeyBase64,'base64'));if(key.asymmetricKeyType!=='rsa')throw new Error('RSA required');}
  catch{fail(500,'invalid_mux_signing_private_key');}
  return {ready:true,signPlayback(playbackID,{durationSeconds,sessionID,now=Date.now(),restrictionID=null}={}){
    if(typeof playbackID!=='string'||!(/^[A-Za-z0-9]{8,128}$/.test(playbackID)))fail(400,'invalid_mux_playback_id');
    const session=uuid(sessionID);
    if(!Number.isInteger(durationSeconds)||durationSeconds<1||durationSeconds>86400)fail(400,'invalid_video_duration');
    const issued=Math.floor(now/1000),expires=issued+Math.min(86400,durationSeconds+900);
    const claims={sub:playbackID,aud:'v',exp:expires,kid:keyID,custom:{session_id:session}};
    if(restrictionID!=null){if(typeof restrictionID!=='string'||!(/^[A-Za-z0-9_-]{8,128}$/.test(restrictionID)))fail(400,'invalid_mux_restriction');claims.playback_restriction_id=restrictionID;}
    const unsigned=`${encode({alg:'RS256',typ:'JWT'})}.${encode(claims)}`;
    const signature=sign('RSA-SHA256',Buffer.from(unsigned),key).toString('base64url');
    const token=`${unsigned}.${signature}`;
    return {url:`https://stream.mux.com/${playbackID}.m3u8?token=${token}`,expires_at:new Date(expires*1000).toISOString(),token};
  }};
}
