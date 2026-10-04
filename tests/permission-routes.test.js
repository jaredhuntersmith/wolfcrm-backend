import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,readdirSync} from 'node:fs';
import {sensitiveRoutePolicy,enforceSensitiveRoute,validateSensitiveRegistry} from '../permission-routes.js';
import {PERMISSION_CAPABILITIES,hasCapability,resolveAccess} from '../permissions.js';

test('all newly declared sensitive features and actions use the central capability catalog',()=>{
 assert.equal(validateSensitiveRegistry(),true);
 const keys=new Set(PERMISSION_CAPABILITIES.map(x=>x.key));
 for(const key of ['communications.calls','communications.record','communications.transcribe','communications.screenshare','communications.guests','communications.ai','communications.audit','storage.download','audio.play','media.play','customer.calls.place','service_plans.view','invoices.view','quotes.export','notifications.share','team.manage_access'])assert.ok(keys.has(key),key);
});
test('actual index authenticated routes must declare permission middleware or a reviewed self/service policy',()=>{
 const source=readFileSync(new URL('../index.js',import.meta.url),'utf8');
 const self=new Set(['/api/profile','/api/permissions/catalog','/api/navigation/tabs','/api/integrations/device-token']);
 const routes=[...source.matchAll(/app\.(get|post|put|patch|delete)\("(\/api\/[^"\n]*)", authRequired, ([^\n]+)/g)];
 assert.ok(routes.length>150);
 for(const [,method,path,middleware] of routes){
  assert.ok(middleware.startsWith('require')||self.has(path)||sensitiveRoutePolicy(method.toUpperCase(),path).id,`Declare feature/record authorization for ${method} ${path}`);
 }
});
test('storage original/derivative/upload/audit gates do not grant ownership or public sharing',()=>{
 for(const [method,path,body,key] of [
  ['GET','/api/storage/files',{},'storage.view'],['POST','/api/storage/uploads',{},'storage.upload'],['POST','/api/storage/files/:id/thumbnail',{},'storage.upload'],['PATCH','/api/storage/files/:id',{visibility:'company'},'storage.share'],['POST','/api/storage/files/:id/access',{purpose:'download'},'storage.download'],['GET','/api/storage/activity',{},'storage.manage']
 ])assert.ok(sensitiveRoutePolicy(method,path,body).capabilities.includes(key));
 const denied=resolveAccess({preset:'admin',overrides:{'storage.view':false}});
 let status;assert.equal(enforceSensitiveRoute({method:'POST',path:'/api/storage/files/id/access',body:{purpose:'stream'},permissions:denied},{status:n=>{status=n;return {json:()=>{}};}}),false);assert.equal(status,403);
});
test('customer call access remains distinct from customer SMS and internal Comms',()=>{
 assert.deepEqual(sensitiveRoutePolicy('GET','/api/phone/conversations').capabilities,[]);
 assert.deepEqual(sensitiveRoutePolicy('POST','/api/phone/messages').capabilities,[]);
 assert.deepEqual(sensitiveRoutePolicy('GET','/api/voice/token').capabilities,['customer.calls.view','customer.calls.place']);
 const access=resolveAccess({preset:'office',overrides:{'communications.view':false,'customer.calls.view':false}});
 assert.equal(access.capabilities['messaging.customer.send'],true);assert.equal(access.capabilities['customer.calls.place'],false);
 assert.equal(hasCapability({role:'employer'},'customer.calls.place'),false);
 const source=readFileSync(new URL('../index.js',import.meta.url),'utf8');const preview=source.slice(source.indexOf('\"/api/smart-contact-lists/actions/sms/preview\"'),source.indexOf('async function finalizeSmartContactSMSBatch'));assert.match(preview,/requireCapability\(\"messaging.customer.send\"\)/);assert.doesNotMatch(preview,/communications\.view/);
});
test('owner credential boundary does not prevent employees registering their own device or preferences',()=>{
 assert.equal(sensitiveRoutePolicy('POST','/api/integrations/zapier/token/rotate').ownerOnly,true);
 assert.equal(sensitiveRoutePolicy('POST','/api/integrations/device-token').ownerOnly,false);
 assert.equal(sensitiveRoutePolicy('DELETE','/api/integrations/device-token').ownerOnly,false);
 assert.equal(sensitiveRoutePolicy('PUT','/api/integrations/zapier/notifications').ownerOnly,false);
 assert.equal(sensitiveRoutePolicy('GET','/api/agreements/:id/documents/:kind').capabilities.includes('quotes.export'),true);
});

test('inbox and invalidation remain available after Company Comms feature revocation',()=>{
 assert.deepEqual(sensitiveRoutePolicy('GET','/api/comms/notifications').capabilities,['notifications.view']);
 assert.deepEqual(sensitiveRoutePolicy('PATCH','/api/comms/notifications/id').capabilities,['notifications.view']);
 assert.deepEqual(sensitiveRoutePolicy('GET','/api/comms/events').capabilities,[]);
 assert.deepEqual(sensitiveRoutePolicy('GET','/api/comms/conversations').capabilities,['communications.view']);
});

test('service plan adjacent modules honor feature denial and folder creation requires edit',()=>{
 for(const path of ['/api/service-plan-tiers','/api/service-plan-operations','/api/service-plan-enrollments/id'])assert.ok(sensitiveRoutePolicy('GET',path).capabilities.includes('service_plans.view'));
 assert.ok(sensitiveRoutePolicy('POST','/api/service-plan-tiers/id/archive').capabilities.includes('service_plans.delete'));
 assert.ok(sensitiveRoutePolicy('POST','/api/storage/folders').capabilities.includes('storage.edit'));
});

test('installed module route declarations retain authenticated or explicit public provider boundaries',()=>{
 const root=new URL('../',import.meta.url),files=[];for(const directory of ['','company-comms/','company-comms/calls/','media-storage/'])for(const name of readdirSync(new URL(directory,root)))if(name.endsWith('.js')&&!name.endsWith('.test.js'))files.push(directory+name);
 const publicEndpoints=new Set(['/api/health','/api/integrations/google-sheets/oauth/callback','/api/focus/connections/meta/callback','/api/focus/webhooks/meta','/api/finance/plaid/webhook','/api/comms/livekit/webhook']);
 let count=0;
 for(const file of files){const source=readFileSync(new URL(file,root),'utf8');for(const [,method,,path,policy] of source.matchAll(/app\.(get|post|put|patch|delete)\(\s*(['"])(\/api\/.*?)\2\s*,\s*([^\n]{0,180})/g)){count++;if(path.startsWith('/api/public/')||publicEndpoints.has(path))continue;assert.ok(/authRequired|staff\(|\.\.\.auth/.test(policy),`${file}: ${method} ${path} must declare authentication or an explicit reviewed external boundary`);}}
 assert.ok(count>=600,`Inventory unexpectedly omitted installed literal routes (${count}).`);
 for(const file of ['company-comms/index.js','company-comms/compatibility.js','company-comms/collaboration.js','company-comms/calls/index.js','company-comms/job-huddles.js','media-storage/index.js']){const source=readFileSync(new URL(file,root),'utf8');assert.match(source,/app\[method\]\([^,]+,\s*authRequired/,`${file} must authenticate its staff route wrapper`);}
 // These are distinct public capability-token/provider routes, never employee-route bypasses.
 const calls=readFileSync(new URL('company-comms/calls/index.js',root),'utf8');assert.match(calls,/guestToken/);assert.match(calls,/service\.webhook\(/);
});
