import {safeWebpage} from '../browser-contracts.js';
import {taskAccessSQL} from './tasks.js';
import {randomUUID} from 'node:crypto';
import {can,loadActor,authorizeConversation,requireCapability,fail,id,text} from './access.js';
export const NO_ACCESS=Object.freeze({accessible:false,text:'No Access'});
export const SOURCE_CAPABILITIES=Object.freeze({webpage:[],contact:['contacts.view'],stage_entry:['contacts.view','pipeline.view'],job:['schedule.view','jobs.view'],quote:['quotes.view','contacts.view'],task:['tasks.view'],service_plan:['service_plans.view'],notification:['notifications.view']});
export function sourceAllowed(actor,type,context=type){const keys=SOURCE_CAPABILITIES[type];return !!keys&&keys.every(k=>can(actor,k))&&(!['stages','stage_entry','pipeline'].includes(context)||can(actor,'pipeline.view'));}
function descriptor(raw){if(raw?.source_type==='webpage'){const page=safeWebpage(raw);return {source_type:'webpage',source_id:page.url,context_type:'webpage',context_id:null,title:page.title};}const source_type=text(raw.source_type,40),source_id=id(raw.source_id),context_type=text(raw.context_type||source_type,40,false),context_id=raw.context_id==null?null:id(raw.context_id);if(!SOURCE_CAPABILITIES[source_type])fail(400,'unsupported_source');if(['stages','stage_entry','pipeline'].includes(context_type)&&source_type!=='stage_entry')fail(400,'stage_context_requires_stage_entry');return {source_type,source_id,context_type,context_id};}
async function originalConversationAccessible(db,actor,conversationId){
 if(!conversationId)return true;
 try{await authorizeConversation(db,actor,conversationId);return true;}catch(error){if([403,404].includes(error.status))return false;throw error;}
}
export async function hydrateSources(db,actor,references){
 const output=new Map(),groups=new Map();
 for(const raw of references){const key=raw.id||JSON.stringify(raw),type=raw.source_type;if(!sourceAllowed(actor,type,raw.context_type)){output.set(key,NO_ACCESS);continue;}if(!groups.has(type))groups.set(type,[]);groups.get(type).push({...raw,key});}
 for(const [type,items] of groups){
  if(type==='webpage'){for(const item of items){try{const page=safeWebpage({source_id:item.source_id,title:item.title||item.snapshot?.title});output.set(item.key,{accessible:true,interactive:true,source_type:'webpage',source_id:page.url,title:page.title,subtitle:page.domain,url:page.url});}catch{output.set(item.key,{accessible:true,interactive:false,text:'Unavailable'});}}continue;}
  const values=[items.map(x=>x.source_id),actor.companyId,actor.userId];let query;
  switch(type){
   case 'contact':query=`SELECT id::text,name AS title,address AS subtitle FROM contacts WHERE id::text=ANY($1::text[]) AND company_id=$2 AND deleted_at IS NULL`;break;
   case 'stage_entry':query=`SELECT o.id,o.contact_id,c.name AS title,s.name AS subtitle,o.stage_id AS context_id FROM opportunities o JOIN contacts c ON c.id::text=o.contact_id AND c.company_id=o.company_id AND c.deleted_at IS NULL LEFT JOIN stages s ON s.id=o.stage_id AND s.company_id=o.company_id WHERE o.id=ANY($1::text[]) AND o.company_id=$2`;break;
   case 'job':query=`SELECT e.id,e.title,e.start_at,e.contact_id FROM schedule_events e WHERE e.id=ANY($1::text[]) AND e.company_id=$2 AND to_jsonb(e)->>'deleted_at' IS NULL`;break;
   case 'quote':query=`SELECT q.id::text,COALESCE(q.title,'Quote') AS title,q.total_cents AS amount_cents,q.contact_id FROM quotes q JOIN contacts c ON c.id::text=q.contact_id AND c.company_id=q.company_id AND c.deleted_at IS NULL WHERE q.id::text=ANY($1::text[]) AND q.company_id=$2 AND to_jsonb(q)->>'deleted_at' IS NULL`;break;
   case 'task':query=`SELECT t.id,t.title,t.due_date FROM todo_tasks t JOIN users u ON u.id=t.user_id WHERE t.id=ANY($1::text[]) AND u.company_id=$2 AND (t.user_id=$3 OR t.assignee_ids ? $3::text OR t.creator_id=$3) AND ${taskAccessSQL(actor,'t','$3','$2')}`;break;
   case 'service_plan':query=`SELECT p.id::text,p.plan_name AS title FROM service_plans p WHERE p.id::text=ANY($1::text[]) AND p.company_id=$2`;break;
   case 'notification':query=`SELECT n.id::text,n.title,n.body,n.created_at AS original_at,n.requirements,n.source_refs,n.conversation_id FROM notifications n WHERE n.id::text=ANY($1::text[]) AND n.company_id=$2 AND n.user_id=$3 AND n.deleted_at IS NULL`;break;
  }
  const usesUser=query.includes('$3'),rows=(await db.query(query,usesUser?values:values.slice(0,2))).rows,map=new Map(rows.map(r=>[r.id,r]));
  for(const item of items){const row=map.get(item.source_id);if(!row){output.set(item.key,{accessible:true,text:'Unavailable',interactive:false});continue;}
   if(type==='notification'){
    if(!(row.requirements||[]).every(key=>can(actor,key))||!(await originalConversationAccessible(db,actor,row.conversation_id))){output.set(item.key,NO_ACCESS);continue;}
    const refs=row.source_refs||[];if(refs.length){const nested=await hydrateSources(db,actor,refs);if([...nested.values()].some(v=>!v.accessible||v.text==='Unavailable')){output.set(item.key,NO_ACCESS);continue;}}
    output.set(item.key,{accessible:true,source_type:type,text:[row.title,row.body].filter(Boolean).join('\n'),original_at:row.original_at,interactive:false});
   }else{const {id:recordId,...fields}=row;output.set(item.key,{accessible:true,source_type:type,source_id:recordId,context_type:item.context_type||type,context_id:item.context_id||row.context_id||null,...fields,interactive:true});}
  }
 }
 return output;
}
export async function validateShares(db,actor,input){
 if(!Array.isArray(input)||input.length>10)fail(400,'invalid_cards');if(input.length)requireCapability(actor,'communications.share');for(const ref of input){if(ref.source_type==='webpage'){requireCapability(actor,'browser.view');requireCapability(actor,'browser.companyCommsShare');}if(ref.source_type==='notification')requireCapability(actor,'notifications.share');if(ref.source_type==='quote')requireCapability(actor,'quotes.share');}const descriptors=input.map(descriptor),mapped=descriptors.map((d,i)=>({...d,id:String(i)}));const hydrated=await hydrateSources(db,actor,mapped);
 const denied=mapped.filter(x=>!hydrated.get(x.id)?.accessible||hydrated.get(x.id)?.text==='Unavailable');if(denied.length)fail(403,'source_unavailable','One or more selected items are unavailable. Refresh your selection.');
 return descriptors;
}
export async function insertShares(db,actor,messageId,input){
 for(const [sortOrder,ref] of (await validateShares(db,actor,input)).entries()){
  let snapshot=ref.source_type==='webpage'?{title:ref.title}:null,provenance={};
  if(ref.source_type==='notification'){
   const row=(await db.query('SELECT title,body,created_at,requirements,source_refs,conversation_id FROM notifications WHERE id=$1 AND user_id=$2',[ref.source_id,actor.userId])).rows[0];snapshot={title:row.title,body:row.body,original_at:row.created_at};provenance={requirements:row.requirements||[],source_refs:row.source_refs||[],conversation_id:row.conversation_id||null};
  }
  await db.query(`INSERT INTO comms_cards(id,message_id,company_id,source_type,source_id,context_type,context_id,provenance,snapshot,sort_order) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,[randomUUID(),messageId,actor.companyId,ref.source_type,ref.source_id,ref.context_type,ref.context_id,JSON.stringify(provenance),snapshot?JSON.stringify(snapshot):null,sortOrder]);
 }
}
export async function messageCards(db,actor,messageIds){
 const rows=(await db.query('SELECT * FROM comms_cards WHERE message_id=ANY($1::text[]) AND company_id=$2 ORDER BY sort_order,created_at,id',[messageIds,actor.companyId])).rows;
 const ordinary=rows.filter(r=>r.source_type!=='notification'),hydrated=await hydrateSources(db,actor,ordinary),result=new Map();
 for(const row of rows){let card=hydrated.get(row.id);
  if(row.source_type==='notification'){
   const allowed=can(actor,'notifications.view')&&(row.provenance.requirements||[]).every(k=>can(actor,k))&&await originalConversationAccessible(db,actor,row.provenance.conversation_id);const nested=allowed?await hydrateSources(db,actor,row.provenance.source_refs||[]):new Map();
   card=allowed&&[...nested.values()].every(v=>v.accessible&&v.text!=='Unavailable')?{accessible:true,source_type:'notification',text:[row.snapshot?.title,row.snapshot?.body].filter(Boolean).join('\n'),original_at:row.snapshot?.original_at,interactive:false}:NO_ACCESS;
  }
  if(!result.has(row.message_id))result.set(row.message_id,[]);result.get(row.message_id).push(card||NO_ACCESS);
 }
 return result;
}
export async function searchSources(db,actor,type,query){
 actor=await loadActor(db,actor);if(!sourceAllowed(actor,type))return [];
 const term='%'+text(query||'',100,false).replace(/[\\%_]/g,'\\$&')+'%';let sql;
 switch(type){case 'contact':sql=`SELECT id::text FROM contacts WHERE company_id=$1 AND deleted_at IS NULL AND name ILIKE $2`;break;
 case 'stage_entry':sql=`SELECT o.id FROM opportunities o JOIN contacts c ON c.id::text=o.contact_id AND c.company_id=o.company_id WHERE o.company_id=$1 AND c.deleted_at IS NULL AND c.name ILIKE $2`;break;
 case 'job':sql=`SELECT id FROM schedule_events WHERE company_id=$1 AND title ILIKE $2`;break;
 case 'quote':sql=`SELECT id::text FROM quotes WHERE company_id=$1 AND COALESCE(title,'Quote') ILIKE $2`;break;
 default:return [];}
 const rows=(await db.query(sql+' ORDER BY id LIMIT 30',[actor.companyId,term])).rows;return [...(await hydrateSources(db,actor,rows.map(r=>({...r,source_type:type,source_id:r.id,context_type:type})))).values()];
}

// SQL predicates share the same source policy for inbox filtering and derived asset bytes.
// alias is always an internal SQL alias, never request input. $1=user, $2=company.
export function sourceAccessSQL(actor, alias='r', includeTaskProvenance=true) {
 const ref=`${alias}.source_id`,company='$2',user='$1';
 const conditions={
  webpage:`true`,
  contact:`EXISTS(SELECT 1 FROM contacts x WHERE x.id::text=${ref} AND x.company_id=${company} AND x.deleted_at IS NULL)`,
  stage_entry:`EXISTS(SELECT 1 FROM opportunities x JOIN contacts cx ON cx.id::text=x.contact_id AND cx.company_id=x.company_id AND cx.deleted_at IS NULL WHERE x.id=${ref} AND x.company_id=${company})`,
  job:`EXISTS(SELECT 1 FROM schedule_events x WHERE x.id=${ref} AND x.company_id=${company} AND to_jsonb(x)->>'deleted_at' IS NULL)`,
  quote:`EXISTS(SELECT 1 FROM quotes x JOIN contacts cx ON cx.id::text=x.contact_id AND cx.company_id=x.company_id AND cx.deleted_at IS NULL WHERE x.id::text=${ref} AND x.company_id=${company} AND to_jsonb(x)->>'deleted_at' IS NULL)`,
  task:`EXISTS(SELECT 1 FROM todo_tasks x JOIN users ux ON ux.id=x.user_id WHERE x.id=${ref} AND ux.company_id=${company} AND (x.user_id=${user} OR x.creator_id=${user} OR x.assignee_ids ? ${user}::text) AND ${includeTaskProvenance?taskAccessSQL(actor,'x',user,company):'true'})`,
  service_plan:`EXISTS(SELECT 1 FROM service_plans x WHERE x.id::text=${ref} AND x.company_id=${company})`,
 };
 const clauses=Object.entries(conditions).filter(([type])=>sourceAllowed(actor,type)).map(([type,predicate])=>`(${alias}.source_type='${type}' AND ${predicate})`);
 const context=can(actor,'pipeline.view')?'true':`COALESCE(${alias}.context_type,'') NOT IN ('stages','stage_entry','pipeline')`;
 return `((${clauses.join(' OR ')||'false'}) AND ${context})`;
}
