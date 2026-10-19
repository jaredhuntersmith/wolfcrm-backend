import {fault} from './context.js';

export function schemaFieldPaths(schema,prefix=''){
 const paths=[];
 for(const [key,value]of Object.entries(schema?.properties||{})){
  const path=prefix?prefix+'.'+key:key;paths.push(path,...schemaFieldPaths(value,path));
 }
 if(schema?.items)paths.push(...schemaFieldPaths(schema.items,prefix+'.*'));
 for(const branch of schema?.anyOf||schema?.oneOf||[])paths.push(...schemaFieldPaths(branch,prefix));
 return [...new Set(paths)];
}
export function validFieldPath(schema,path){
 const visit=(node,parts)=>{
  if(!parts.length)return true;
  if(node===true||node?.$ref)return true; // Deliberately open JSON value.
  if(!node||node===false)return false;
  if(node.anyOf||node.oneOf)return (node.anyOf||node.oneOf).some(x=>visit(x,parts));
  const [head,...tail]=parts;
  if(head==='*'&&node.items)return visit(node.items,tail);
  if(head==='*'&&node.properties)return Object.values(node.properties).some(x=>visit(x,tail));
  if(node.properties?.[head])return visit(node.properties[head],tail);
  return !!node.additionalProperties&&visit(node.additionalProperties,tail);
 };
 return visit(schema,path.split('.'));
}

// Paths are schema paths (array elements use *). Denial is recursive and applies
// to tools, approvals and assistant execution, never just to prompt text.
const matches=(pattern,path)=>pattern.split('.').length<=path.length&&pattern.split('.').every((v,i)=>v==='*'||v===path[i]);
export function restrictFields(value,denied=[],{write=false}={}){
 const visit=(v,path)=>{
  if(denied.some(p=>matches(p,path))){if(write)throw fault(403,'field_denied','An input field is disabled for this connection.');return undefined;}
  if(Array.isArray(v))return v.map(x=>visit(x,[...path,'*'])).filter(x=>x!==undefined);
  if(v&&typeof v==='object')return Object.fromEntries(Object.entries(v).map(([k,x])=>[k,visit(x,[...path,k])]).filter(([,x])=>x!==undefined));
  return v;
 };return visit(value,[]);
}
