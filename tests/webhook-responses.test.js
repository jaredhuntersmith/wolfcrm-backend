import test from 'node:test';
import assert from 'node:assert/strict';
import {mapWebhookResponse,responseMappingsSchema} from '../webhooks/responses.js';

test('response maps retain selected JSON/header values without raw payloads',()=>{
 const result={body:'{"ticket":{"id":"123"},"secret":"unselected"}',headers:{'X-Request-ID':'request-1','Set-Cookie':'credential','Authorization':'credential'}};
 assert.deepEqual(mapWebhookResponse(result,[{name:'ticket',path:'/ticket/id',type:'text'},{name:'request',source:'headers',path:'/X-Request-ID',type:'text'}]),{ticket:'123',request:'request-1'});
 assert.deepEqual(mapWebhookResponse(result,[]),{});
});
test('header-only maps accept non-JSON bodies and reject credential headers/whole-header capture',()=>{
 assert.deepEqual(mapWebhookResponse({body:'OK',headers:{'x-job-id':'j1'}},[{name:'job',source:'headers',path:'/x-job-id',type:'text'}]),{job:'j1'});
 for(const path of ['/set-cookie','/Authorization','/x-api-key',''])assert.equal(responseMappingsSchema.safeParse([{name:'leak',source:'headers',path,type:'text'}]).success,false);
 assert.throws(()=>mapWebhookResponse({body:'OK'},[{name:'id',path:'/id',type:'text'}]),e=>e.code==='response_not_json');
});
test('response mapping names are unique and required mapped values fail clearly',()=>{
 assert.equal(responseMappingsSchema.safeParse([{name:'id',path:'/a',type:'text'},{name:'id',path:'/b',type:'text'}]).success,false);
 assert.throws(()=>mapWebhookResponse({body:'{}'},[{name:'id',path:'/id',type:'text',required:true}]));
});
