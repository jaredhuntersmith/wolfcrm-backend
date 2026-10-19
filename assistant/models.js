import OpenAI from 'openai';
import {decrypt,encrypt} from '../retell/security.js';
import {fault} from '../mcp/context.js';

// Reviewed official metadata, 2026-10-18. Availability is separately checked with
// the selected funding account; an alias never silently selects another model.
export const modelCatalog=Object.freeze([
 {id:'gpt-6.1-sol',name:'GPT-6.1 Sol',reasoning:['low','medium','high','xhigh','max'],input_per_million:2,cached_per_million:0.1,output_per_million:10,web_search:true,image_input:true,file_input:true,source:'https://developers.openai.com/api/docs/models/gpt-6.1-sol',reviewed:'2026-10-18'}
]);
export function modelFor(id,reasoning){const m=modelCatalog.find(m=>m.id===id);if(!m)throw fault(400,'unsupported_model');if(reasoning&&!m.reasoning.includes(reasoning))throw fault(400,'unsupported_reasoning');return m;}
export function estimateMicros(model,usage={}){
 const m=modelFor(model);const input=Number(usage.input_tokens||0),cached=Math.min(input,Number(usage.input_tokens_details?.cached_tokens||0)),output=Number(usage.output_tokens||0);
 return Math.ceil((input-cached)*m.input_per_million+cached*m.cached_per_million+output*m.output_per_million);
}
const aad=s=>`wolf-assistant:${s.company_id}:${s.user_id}`;
export const encryptKey=(key,s,env)=>encrypt(key,aad(s),env);
export function createProvider({env=process.env,clientFactory}={}){
 function client(settings){
  const key=settings.funding==='owner'?env.OPENAI_API_KEY:settings.key_ciphertext?decrypt(settings.key_ciphertext,aad(settings),env):null;
  if(!key&&!clientFactory)throw fault(503,'assistant_funding_unconfigured','Configure this funding source in Assistant settings.');
  if(settings.funding==='owner'&&env.ASSISTANT_OWNER_FUNDING!=='true'&&!clientFactory)throw fault(403,'owner_funding_disabled');
  return clientFactory?clientFactory(settings):new OpenAI({apiKey:key,timeout:90000,maxRetries:0});
 }
 async function models(settings){
  const c=client(settings),available=new Set();
  try{for await(const m of c.models.list())available.add(m.id);}
  catch{throw fault(503,'funding_verification_failed','The selected API funding source could not be verified. Check its credentials and provider access.');}
  return modelCatalog.filter(m=>available.has(m.id));
 }
 async function countInput(settings,request,{signal}={}){
  const body=Object.fromEntries(['model','instructions','input','reasoning','tools','tool_choice','parallel_tool_calls'].filter(k=>request[k]!==undefined).map(k=>[k,request[k]]));
  try {const result=await client(settings).responses.inputTokens.count(body,{signal});if(!Number.isSafeInteger(result.input_tokens)||result.input_tokens<0)throw new Error('Invalid token count');return result.input_tokens;}
  catch {throw fault(503,'file_token_count_unavailable','The selected funding account could not preflight this file. No generation request was made.');}
 }
 async function respond(settings,request,{signal,onText}={}){
  modelFor(request.model,request.reasoning?.effort);const stream=await client(settings).responses.create({...request,store:false,stream:true},{signal});let result;
  for await(const event of stream){if(event.type==='response.output_text.delta')await onText?.(event.delta);if(event.type==='response.completed')result=event.response;if(event.type==='response.failed'||event.type==='error')throw fault(502,'provider_failed');}
  if(!result)throw fault(502,'provider_incomplete');return result;
 }
 return {models,respond,countInput};
}
