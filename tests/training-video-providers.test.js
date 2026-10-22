import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeVideo,parseTrainingVideoURL,providerCapabilities} from '../training/video-providers.js';
import {normalizeDefinition} from '../training/contract.js';
import {generateKeyPairSync,verify} from 'node:crypto';
import {createMuxSigner} from '../training/mux-signer.js';
import {createMuxCatalogAdapter} from '../training/mux-catalog.js';

test('video provider parser only accepts supported HTTPS IDs and strips optional YouTube parameters',()=>{
  assert.deepEqual(parseTrainingVideoURL('https://youtu.be/dQw4w9WgXcQ?t=30'),
    {provider:'youtube',external_id:'dQw4w9WgXcQ',canonical_url:'https://www.youtube.com/embed/dQw4w9WgXcQ'});
  assert.equal(parseTrainingVideoURL('https://vimeo.com/123456789').provider,'vimeo');
  assert.equal(parseTrainingVideoURL('https://player.mux.com/abc123DEF456').provider,'mux');
  assert.throws(()=>parseTrainingVideoURL('http://youtube.com/watch?v=dQw4w9WgXcQ'),{code:'invalid_video_url'});
  assert.throws(()=>parseTrainingVideoURL('https://evil.example/embed/dQw4w9WgXcQ'),{code:'unsupported_video_provider'});
  assert.throws(()=>parseTrainingVideoURL('https://stream.mux.com/abc123DEF456.m3u8?token=secret'),{code:'provider_url_contains_credentials'});
});

test('video mode matrix rejects unsupported enforcement instead of downgrading',()=>{
  assert.deepEqual(providerCapabilities().mux.supported_modes,[]);
  const capabilities=providerCapabilities({muxSigningReady:true});
  assert.deepEqual(capabilities.youtube.supported_modes,['A']);
  assert.throws(()=>normalizeVideo({url:'https://youtu.be/dQw4w9WgXcQ',mode:'B',duration_seconds:60},{capabilities}),{code:'unsupported_video_mode'});
  assert.throws(()=>normalizeVideo({url:'https://player.mux.com/abc123DEF456',mode:'E',duration_seconds:360},{capabilities}),{code:'unsupported_video_mode'});
  assert.equal(normalizeVideo({url:'https://player.mux.com/abc123DEF456',mode:'B',duration_seconds:360,max_rate:1.25},{capabilities}).mode,'B');
  const withCheck=providerCapabilities({muxSigningReady:true,knowledgeCheckReady:true});
  assert.deepEqual(withCheck.mux.supported_modes,['A','B','C']);
  const interactive=providerCapabilities({muxSigningReady:true,interactiveReady:true});
  assert.deepEqual(interactive.mux.supported_modes,['A','B','D']);
  assert.equal(normalizeVideo({url:'https://player.mux.com/abc123DEF456',mode:'D',duration_seconds:360,
    checkpoints:[{id:'stop',kind:'instruction',at_seconds:150,text:'Pause and inspect the tool.'}]},
    {capabilities:interactive}).checkpoints[0].at_seconds,150);
  const high=providerCapabilities({muxSigningReady:true,knowledgeCheckReady:true,interactiveReady:true,highAssuranceReady:true});
  assert.deepEqual(high.mux.supported_modes,['A','B','C','D','E']);
  assert.throws(()=>normalizeVideo({url:'https://player.mux.com/abc123DEF456',mode:'E',duration_seconds:360,
    knowledge_check:{questions:[{id:'final',type:'true_false',prompt:'Safe?',points:1,answer:true}]},
    checkpoints:[{id:'only',kind:'question',at_seconds:180,question:{id:'q1',type:'true_false',prompt:'Safe?',points:1,answer:true}}]},
    {capabilities:high}),{code:'high_assurance_checkpoints_required'});
  assert.equal(normalizeVideo({url:'https://player.mux.com/abc123DEF456',mode:'C',duration_seconds:360,
    knowledge_check:{passing_percent:80,max_attempts:2,questions:[{id:'q1',type:'true_false',prompt:'Safe?',points:1,answer:true}]}},{capabilities:withCheck}).knowledge_check.questions.length,1);
  assert.throws(()=>normalizeVideo({url:'https://player.mux.com/abc123DEF456',mode:'C',duration_seconds:360,
    knowledge_check:{time_limit_seconds:60,questions:[{id:'q1',type:'true_false',prompt:'Safe?',points:1,answer:true}]}},
    {capabilities:withCheck}),{code:'video_check_timing_or_shuffle_unavailable'});
  assert.throws(()=>normalizeVideo({url:'https://vimeo.com/123456789',mode:'D'},{capabilities}),{code:'unsupported_video_mode'});
});

test('optional video blocks retain canonical provider references and accept no forged completion response',()=>{
  const document=normalizeDefinition({kind:'task',title:'Introduction',blocks:[{id:'v',type:'video',title:'Watch if useful',
    video:{url:'https://youtu.be/dQw4w9WgXcQ?t=30',mode:'A'}}]});
  assert.equal(document.blocks[0].video.canonical_url,'https://www.youtube.com/embed/dQw4w9WgXcQ');
  assert.equal(JSON.stringify(document).includes('t=30'),false);
  assert.throws(()=>normalizeDefinition({kind:'task',title:'Bad',blocks:[{id:'v',type:'video',video:{url:'https://youtu.be/dQw4w9WgXcQ',mode:'B',duration_seconds:60}}]}),
    {code:'unsupported_video_mode'});
});

test('Mux signer emits server-signed, session-bound playback URL without personal identifiers',()=>{
  const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  const signer=createMuxSigner({keyID:'training-key-1',privateKeyBase64:Buffer.from(privateKey.export({type:'pkcs8',format:'pem'})).toString('base64')});
  const sessionID='00000000-0000-4000-8000-000000000001';
  const result=signer.signPlayback('abc123DEF456',{durationSeconds:300,sessionID,now:Date.parse('2026-10-22T12:00:00Z')});
  const token=new URL(result.url).searchParams.get('token'),[header,payload,signature]=token.split('.');
  assert.equal(verify('RSA-SHA256',Buffer.from(`${header}.${payload}`),publicKey,Buffer.from(signature,'base64url')),true);
  assert.deepEqual(JSON.parse(Buffer.from(payload,'base64url').toString()),{
    sub:'abc123DEF456',aud:'v',exp:Math.floor(Date.parse('2026-10-22T12:00:00Z')/1000)+1200,kid:'training-key-1',custom:{session_id:sessionID}
  });
  assert.equal(result.url.includes('email'),false);
  assert.throws(()=>signer.signPlayback('bad',{durationSeconds:300,sessionID}),{code:'invalid_mux_playback_id'});
});

test('Mux catalog verifies signed ready asset and server duration before mandatory use',async()=>{
  const seen=[];const fetchImpl=async(url,options)=>{
    seen.push({url,authorization:options.headers.Authorization});
    return {ok:true,json:async()=>({data:url.includes('playback-ids/')?
      {policy:'signed',object:{type:'asset',id:'asset123'}}:
      {status:'ready',duration:302.2,playback_ids:[{id:'abc123DEF456',policy:'signed'}]}})};
  };
  const adapter=createMuxCatalogAdapter({tokenID:'token',tokenSecret:'secret',fetchImpl});
  assert.deepEqual(await adapter.verifyPlayback('abc123DEF456'),
    {provider:'mux',playback_id:'abc123DEF456',asset_id:'asset123',duration_seconds:303,policy:'signed'});
  assert.equal(seen.length,2);assert.equal(seen[0].url,'https://api.mux.com/video/v1/playback-ids/abc123DEF456');
  assert.equal(seen[0].authorization.startsWith('Basic '),true);
  const publicAdapter=createMuxCatalogAdapter({tokenID:'a',tokenSecret:'b',fetchImpl:async()=>({ok:true,json:async()=>({data:{policy:'public',object:{type:'asset',id:'asset123'}}})})});
  await assert.rejects(()=>publicAdapter.verifyPlayback('abc123DEF456'),{code:'mux_signed_asset_required'});
});
