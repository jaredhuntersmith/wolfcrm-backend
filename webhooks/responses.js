import {z} from 'zod';
import {fault} from '../mcp/context.js';
import {mapPayload,responseMappingSchema,boundJSON} from './domain.js';

export const responseMappingsSchema=z.array(responseMappingSchema).max(16).refine(xs=>new Set(xs.map(x=>x.name)).size===xs.length,'Mapping names must be unique');
export function safeResponseHeaders(headers={}){
 return Object.fromEntries(Object.entries(headers).filter(([key])=>!(/authorization|cookie|password|secret|token|api[_-]?key/i.test(key))).map(([key,value])=>[key.toLowerCase(),String(value).slice(0,2000)]));
}
export function mapWebhookResponse(result,mappings=[]){
 const selected=responseMappingsSchema.parse(mappings);
 let body;
 if(selected.some(m=>m.source==='body')){
  try{body=JSON.parse(result.body);}catch{throw fault(422,'response_not_json');}
 }
 const headers=safeResponseHeaders(result.headers),mapped={};
 for(const {source,...mapping} of selected){
  if(source==='headers')mapping.path=mapping.path.toLowerCase();
  Object.assign(mapped,mapPayload(source==='headers'?headers:body,[mapping]));
 }
 boundJSON(mapped);
 return mapped;
}
