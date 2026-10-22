import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {createCommsFixture} from './helpers/comms-fixture.js';
import {installTraining} from '../training/index.js';

test('mandatory Mux video publish requires provider-verified signed asset metadata',{timeout:120000},async()=>{
  const fixture=await createCommsFixture(),app=express();let server;
  try{
    app.use(express.json());
    const auth=(req,res,next)=>{const who=req.get('X-Fixture-User');req.userId=fixture.ids[who];req.companyId=who==='foreign'?fixture.companies.b:fixture.companies.a;next();};
    const muxSigner={ready:true,signPlayback:()=>({url:'https://stream.mux.com/abc123DEF456.m3u8?token=test',expires_at:new Date(Date.now()+3600_000).toISOString()})},muxCatalog={ready:true,verifyPlayback:async playbackID=>({provider:'mux',playback_id:playbackID,
      asset_id:'asset-verified',duration_seconds:120,policy:'signed'})};
    await installTraining({app,pool:fixture.pool,authRequired:auth,muxSigner,muxCatalog});
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
    const base=`http://127.0.0.1:${server.address().port}/api/training`;
    const request=async(path,{who='owner',method='GET',body}={})=>{const response=await fetch(base+path,{method,headers:{'X-Fixture-User':who,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});return {status:response.status,body:await response.json()};};
    const url='https://player.mux.com/abc123DEF456';
    assert.deepEqual((await request('/video/providers')).body.mux.supported_modes,['A','B','C','D','E']);
    assert.equal((await request('/video/detect',{method:'POST',body:{url}})).body.provider,'mux');
    const definition=await request('/definitions',{method:'POST',body:{kind:'task',title:'Mandatory video',blocks:[
      {id:'video',type:'video',title:'Watch',video:{url,mode:'B',duration_seconds:120}}
    ]}});assert.equal(definition.status,200);
    assert.equal((await request(`/definitions/${definition.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).body.error,'video_asset_unverified');
    assert.equal((await request('/video/assets/verify',{who:'bob',method:'POST',body:{url}})).status,403);
    assert.equal((await request('/video/assets/verify',{method:'POST',body:{url}})).body.duration_seconds,120);
    assert.equal((await request(`/definitions/${definition.body.id}/publish`,{method:'POST',body:{expected_revision:1}})).status,200);
    const assigned=await request('/assignments',{method:'POST',body:{definition_id:definition.body.id,recipient_ids:[fixture.ids.bob],request_key:'mandatory-video'}});
    const recipient=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===assigned.body.id);
    assert.equal((await request(`/recipients/${recipient.id}/submit`,{who:'bob',method:'POST',body:{expected_revision:1}})).body.error,'requirements_incomplete');
    assert.equal((await request('/video/assets',{who:'foreign'})).body.items.length,0);
    assert.equal((await request('/video/assets',{who:'bob'})).status,403);
    assert.equal((await request('/video/assets')).body.items.length,1);
    const optional=await request('/definitions',{method:'POST',body:{kind:'task',title:'Optional intro video',blocks:[
      {id:'intro',type:'video',title:'Introduction',video:{url,mode:'A'}}
    ]}});assert.equal(optional.status,200);
    const publishedOptional=await request(`/definitions/${optional.body.id}/publish`,{method:'POST',body:{expected_revision:1}});
    assert.equal(publishedOptional.status,200);assert.equal(publishedOptional.body.document.blocks[0].video.duration_seconds,120);
    const optionalAssignment=await request('/assignments',{method:'POST',body:{definition_id:optional.body.id,recipient_ids:[fixture.ids.bob],request_key:'optional-video'}});
    const optionalRecipient=(await request('/mine',{who:'bob'})).body.items.find(item=>item.assignment_id===optionalAssignment.body.id);
    assert.equal((await request(`/recipients/${optionalRecipient.id}/videos/intro/sessions`,{who:'bob',method:'POST'})).status,200);
    assert.equal((await request(`/recipients/${optionalRecipient.id}/submit`,{who:'bob',method:'POST',body:{expected_revision:1}})).status,200);
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await fixture.close();}
});
