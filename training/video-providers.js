import {fail,string} from './contract.js';
import {normalizeQuiz} from './quiz-contract.js';
import {normalizeCheckpoints} from './video-checkpoints-contract.js';

const youtubeHosts=new Set(['youtube.com','www.youtube.com','m.youtube.com','www.youtube-nocookie.com','youtube-nocookie.com','youtu.be','www.youtu.be']);
const vimeoHosts=new Set(['vimeo.com','www.vimeo.com','player.vimeo.com']);
const muxHosts=new Set(['player.mux.com','stream.mux.com']);
const modeNames={A:'Optional video',B:'Watch to completion',C:'Video and knowledge check',D:'Interactive video',E:'High assurance'};

export function parseTrainingVideoURL(value){
  const raw=string(value,2048),url=(()=>{try{return new URL(raw);}catch{fail(400,'invalid_video_url');}})();
  if(url.protocol!=='https:'||url.username||url.password||url.hash)fail(400,'invalid_video_url');
  const host=url.hostname.toLowerCase();let provider,id;
  if(youtubeHosts.has(host)){
    provider='youtube';
    if(host.endsWith('youtu.be'))id=url.pathname.slice(1);
    else if(url.pathname==='/watch')id=url.searchParams.get('v');
    else if(url.pathname.startsWith('/embed/'))id=url.pathname.slice(7);
    if(!id||!(/^[A-Za-z0-9_-]{11}$/.test(id)))fail(400,'invalid_youtube_video');
  }else if(vimeoHosts.has(host)){
    provider='vimeo';const parts=url.pathname.split('/').filter(Boolean);
    id=host==='player.vimeo.com'&&parts[0]==='video'?parts[1]:parts[0];
    if(!id||!/^[0-9]{6,20}$/.test(id))fail(400,'invalid_vimeo_video');
  }else if(muxHosts.has(host)){
    provider='mux';if(url.search)fail(400,'provider_url_contains_credentials');
    const parts=url.pathname.split('/').filter(Boolean);
    id=host==='stream.mux.com'?parts[0]?.replace(/\.m3u8$/,''):parts[0];
    if(!id||!(/^[A-Za-z0-9]{8,128}$/.test(id))||parts.length!==1)fail(400,'invalid_mux_playback_id');
  }else fail(400,'unsupported_video_provider');
  return {provider,external_id:id,canonical_url:provider==='youtube'?`https://www.youtube.com/embed/${id}`:
    provider==='vimeo'?`https://player.vimeo.com/video/${id}`:`https://player.mux.com/${id}`};
}

export function providerCapabilities({muxSigningReady=false,vimeoControlsVerified=false,knowledgeCheckReady=false,interactiveReady=false,highAssuranceReady=false}={}){
  return {
    youtube:{provider:'youtube',supported_modes:['A'],reason:'YouTube embeds cannot support the required mandatory no-skip controls under its player policies.'},
    vimeo:{provider:'vimeo',supported_modes:vimeoControlsVerified?['A','B','C','D']:['A'],
      reason:vimeoControlsVerified?null:'Verify account plan, embed permissions, and player controls before mandatory modes.'},
    mux:{provider:'mux',supported_modes:muxSigningReady?['A','B',...(knowledgeCheckReady?['C']:[]),...(interactiveReady?['D']:[]),...(highAssuranceReady?['E']:[])]:[],
      reason:muxSigningReady?'Interactive and high assurance modes require validated checkpoints and assessments.':'Configure Mux signed playback and verify provider metadata before mandatory modes.'}
  };
}

export function normalizeVideo(input,{capabilities=providerCapabilities()}={}){
  if(!input||typeof input!=='object'||Array.isArray(input))fail(400,'invalid_video');
  const media=parseTrainingVideoURL(input.url??input.canonical_url),mode=string(input.mode??'A',1);
  if(!Object.hasOwn(modeNames,mode))fail(400,'invalid_video_mode');
  const provider=capabilities[media.provider];
  if(!provider?.supported_modes.includes(mode))fail(409,'unsupported_video_mode',provider?.reason??'Provider mode unavailable.');
  const maxRate=input.max_rate??1;
  if(![1,1.25,1.5,2].includes(maxRate))fail(400,'invalid_video_rate');
  if(media.provider==='youtube'&&maxRate!==1)fail(400,'unsupported_video_rate');
  const duration=input.duration_seconds==null?null:Number(input.duration_seconds);
  if(duration!=null&&(!Number.isInteger(duration)||duration<1||duration>86400))fail(400,'invalid_video_duration');
  if(mode!=='A'&&duration==null)fail(409,'verified_duration_required');
  if(!['C','E'].includes(mode)&&input.knowledge_check!=null)fail(400,'unexpected_video_check');
  if(!['D','E'].includes(mode)&&input.checkpoints!=null)fail(400,'unexpected_video_checkpoints');
  if(['C','E'].includes(mode)&&(input.knowledge_check?.time_limit_seconds!=null||input.knowledge_check?.shuffle_questions===true||input.knowledge_check?.shuffle_answers===true))
    fail(409,'video_check_timing_or_shuffle_unavailable');
  const knowledge_check=['C','E'].includes(mode)?normalizeQuiz({...input.knowledge_check,time_limit_seconds:null,shuffle_questions:false,shuffle_answers:false}):null;
  const checkpoints=['D','E'].includes(mode)?normalizeCheckpoints(input.checkpoints,duration):null;
  if(mode==='E'&&(checkpoints.filter(checkpoint=>checkpoint.kind==='question').length<2||
    checkpoints[0].at_seconds>duration/2||checkpoints.at(-1).at_seconds<duration/2))fail(400,'high_assurance_checkpoints_required');
  const supervisor_approval=mode==='E'&&input.supervisor_approval===true;
  const min_watch_seconds=mode==='E'&&input.min_watch_seconds!=null?Number(input.min_watch_seconds):null;
  if(mode==='E'&&min_watch_seconds!=null&&(!Number.isInteger(min_watch_seconds)||min_watch_seconds<1||min_watch_seconds>duration*2))fail(400,'invalid_min_watch_duration');
  if(mode!=='E'&&(input.supervisor_approval!=null||input.min_watch_seconds!=null))fail(400,'unexpected_high_assurance_config');
  return {provider:media.provider,external_id:media.external_id,canonical_url:media.canonical_url,
    mode,max_rate:maxRate,duration_seconds:duration,required:mode!=='A',
    ...(knowledge_check?{knowledge_check}:{}),...(checkpoints?{checkpoints}:{}),
    ...(mode==='E'?{supervisor_approval,min_watch_seconds}:{})};
}
