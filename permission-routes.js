import { hasCapability, isKnownCapability } from './permissions.js';
// Supplemental gates for sensitive legacy families. Their existing record/company
// authorization remains mandatory; these declarations never grant record access.
export const SENSITIVE_ROUTE_REGISTRY = Object.freeze([
  {id:'storage',prefix:'/api/storage',feature:'storage.view'},
  {id:'customer_calls',prefix:'/api/phone/calls',feature:'customer.calls.view'},
  {id:'customer_voicemail',prefix:'/api/phone/voicemails',feature:'customer.calls.view'},
  {id:'customer_voice',prefix:'/api/voice',feature:'customer.calls.view'},
  {id:'invoices',prefix:'/api/invoices',feature:'invoices.view'},
  {id:'service_plans',prefix:'/api/service-plans',feature:'service_plans.view'},
  {id:'service_plan_tiers',prefix:'/api/service-plan-tiers',feature:'service_plans.view'},
  {id:'service_plan_operations',prefix:'/api/service-plan-operations',feature:'service_plans.view'},
  {id:'service_plan_enrollments',prefix:'/api/service-plan-enrollments',feature:'service_plans.view'},
  {id:'comms_notifications',prefix:'/api/comms/notifications',feature:'notifications.view'},
  {id:'comms_events',prefix:'/api/comms/events',feature:null},
  {id:'comms',prefix:'/api/comms',feature:'communications.view'},
  {id:'legacy_comms',prefix:'/api/internal',feature:'communications.view'},
  {id:'notifications',prefix:'/api/notifications',feature:'notifications.view'},
  {id:'map',prefix:'/api/map',feature:'map.view'},
  {id:'quotes',prefix:'/api/quotes',feature:'quotes.view'},
  {id:'agreements',prefix:'/api/agreements',feature:'quotes.view'},
]);
const isRead=method=>['GET','HEAD','OPTIONS'].includes(method);
export function sensitiveRoutePolicy(method,path,body={}) {
  const route=SENSITIVE_ROUTE_REGISTRY.find(rule=>path===rule.prefix||path.startsWith(rule.prefix+'/'));
  const capabilities=route?.feature?[route.feature]:[];
  const add=key=>capabilities.push(key);
  if(route?.id==='storage'){
    if(/\/activity(?:\/|$)/.test(path))add('storage.manage');
    else if(method==='POST'&&/\/folders$/.test(path))add('storage.edit');
    else if(/\/uploads(?:\/|$)|\/parts$|\/complete$/.test(path)||method==='POST'&&/\/thumbnail$/.test(path))add('storage.upload');
    else if(method==='DELETE')add('storage.delete');
    else if(method==='PATCH') {add('storage.edit');if(body.visibility!==undefined)add('storage.share');}
    else if(/\/access$/.test(path)&&body.purpose==='download'||/\/(?:download-complete|transfer-started)$/.test(path))add('storage.download');
  }
  if(route?.id==='customer_voice'&&/\/token$/.test(path))add('customer.calls.place');
  if(['customer_calls','customer_voicemail'].includes(route?.id)&&method==='DELETE')add('customer.calls.delete');
  if(['invoices','service_plans'].includes(route?.id)&&!isRead(method))add(route.id+'.'+(method==='DELETE'?'delete':method==='POST'&&path===route.prefix?'create':'edit'));
  if(['service_plan_tiers','service_plan_operations','service_plan_enrollments'].includes(route?.id)&&!isRead(method))add('service_plans.'+(method==='DELETE'||/\/archive$/.test(path)?'delete':method==='POST'&&path===route.prefix?'create':'edit'));
  if(['quotes','agreements'].includes(route?.id)&&/\/documents\/|\/export(?:\/|$)|\/pdf$/.test(path))add('quotes.export');
  // Owner credential/billing operations cannot be obtained from an Admin preset.
  const ownerOnly=!isRead(method)&&(/^\/api\/company\/join-code$/.test(path)||/^\/api\/(?:integrations|twilio)\/.*(?:token\/rotate|credentials|connect|disconnect)(?:\/|$)/.test(path)||/^\/api\/payments\/connect(?:\/|$)/.test(path));
  return {id:route?.id||null,capabilities:[...new Set(capabilities)],ownerOnly};
}
export function enforceSensitiveRoute(req,res) {
  const policy=sensitiveRoutePolicy(req.method,req.route?.path||req.path,req.body);
  if(policy.ownerOnly && !req.isCompanyOwner){res.status(403).json({error:'owner_required'});return false;}
  const missing=policy.capabilities.filter(key=>!hasCapability(req,key));
  if(missing.length){res.status(403).json({error:'permission_denied',missing_capabilities:missing});return false;}
  return true;
}
export function validateSensitiveRegistry(){return SENSITIVE_ROUTE_REGISTRY.every(rule=>rule.feature===null||isKnownCapability(rule.feature));}
