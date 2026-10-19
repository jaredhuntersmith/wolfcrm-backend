import {digest} from '../mcp/context.js';

// JSONB reorders object keys. Evidence and new external receipts must compare
// semantic JSON, while legacy MCP operation hashes remain unchanged.
export function canonicalJSON(value){
 if(Array.isArray(value))return value.map(canonicalJSON);
 if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonicalJSON(value[k])]));
 return value;
}
export const evidenceHash=value=>digest(canonicalJSON(value));

// Deterministic summaries retain call IDs and receipts, so compacting never
// makes an already completed write look like a pending call to the worker.
export function compactHistory(history,steps,maximum=120000){
 if(Buffer.byteLength(JSON.stringify(history))<=maximum)return {history,compacted:false};
 const outputs=history.filter(x=>x.type==='function_call_output');
 const keep=new Set(outputs.slice(-2).map(x=>x.call_id));
 const users=history.filter(x=>x.role==='user');const newest=users.at(-1);
 const result=history.map(item=>{
  if(item.type==='function_call_output'&&!keep.has(item.call_id)){
   const step=steps.find(x=>x.call_id===item.call_id);
   return {...item,output:JSON.stringify({context_summary:true,capability:step?.tool,status:step?.state,error:step?.result?.error,record_id:step?.result?.id||step?.result?.data?.id,note:'Full output omitted from working context. Retrieve fresh authorized records before relying on their contents. This is not permission to repeat a completed change.'})};
  }
  if(item.role==='user'&&item!==newest&&typeof item.content==='string'&&item.content.length>1500)return {...item,content:item.content.slice(0,1500)+'\n[Earlier user message excerpt; consult conversation history for the full request.]'};
  return item;
 });
 return {history:result,compacted:true};
}
