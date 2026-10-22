import {createHash} from 'node:crypto';
import {normalizeQuiz} from './quiz-contract.js';
import {normalizeVideo,providerCapabilities} from './video-providers.js';

export class TrainingError extends Error {
  constructor(status,code,message=code){super(message);this.status=status;this.code=code;}
}
export function fail(status,code,message){throw new TrainingError(status,code,message);}
export function uuid(value){if(typeof value!=='string'||!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value))fail(400,'invalid_id');return value;}
export function string(value,max=200,{required=true}={}){
  if(typeof value!=='string'||value.length>max||/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value))fail(400,'invalid_text');
  const result=value.trim();if(required&&!result)fail(400,'invalid_text');return result;
}
export function date(value,{required=false}={}){
  if(value==null&&!required)return null;
  if(typeof value!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/.test(value))fail(400,'invalid_date');
  const result=new Date(value);if(!Number.isFinite(result.getTime()))fail(400,'invalid_date');return result.toISOString();
}
export function digest(value){return createHash('sha256').update(JSON.stringify(value)).digest('hex');}
export function graceSeconds(value){
  if(value==null)return 0;
  if(!Number.isInteger(value)||value<0||value>604800)fail(400,'invalid_grace_seconds');
  return value;
}
export function assignmentPriority(value){
  const priority=value??'normal';
  if(!['low','normal','high','urgent'].includes(priority))fail(400,'invalid_assignment_priority');
  return priority;
}
function timingPolicy(value,kind){
  if(value==null)return null;
  if(kind==='quiz'||!value||typeof value!=='object'||Array.isArray(value))fail(400,'invalid_timing_policy');
  const estimated_minutes=value.estimated_minutes??null;
  const minimum_seconds=value.minimum_seconds??null;
  const maximum_seconds=value.maximum_seconds??null;
  const pause_policy=value.pause_policy??'allowed';
  if(estimated_minutes!=null&&(!Number.isInteger(estimated_minutes)||estimated_minutes<1||estimated_minutes>10080))fail(400,'invalid_estimated_duration');
  for(const [name,seconds] of [['minimum',minimum_seconds],['maximum',maximum_seconds]])
    if(seconds!=null&&(!Number.isInteger(seconds)||seconds<1||seconds>604800))fail(400,`invalid_${name}_duration`);
  if(minimum_seconds!=null&&maximum_seconds!=null&&minimum_seconds>maximum_seconds)fail(400,'invalid_duration_bounds');
  if(!['allowed','continuous'].includes(pause_policy))fail(400,'invalid_pause_policy');
  if(estimated_minutes==null&&minimum_seconds==null&&maximum_seconds==null)fail(400,'empty_timing_policy');
  return {estimated_minutes,minimum_seconds,maximum_seconds,pause_policy};
}
const kinds=new Set(['task','checklist','form','inspection','quiz']);
const fieldTypes=new Set(['short_text','long_text','number','date','time','dropdown','multiple_choice','multiple_selection','rating','yes_no']);
function bound(value,{min,max,integer=false}={}){
  if(value==null)return null;
  if(typeof value!=='number'||!Number.isFinite(value)||value<min||value>max||(integer&&!Number.isInteger(value)))fail(400,'invalid_field_bound');
  return value;
}
function blockPoints(value){
  if(value==null)return null;
  if(!Number.isInteger(value)||value<1||value>100)fail(400,'invalid_block_points');
  return value;
}
function visibility(input,priorFields){
  if(input==null)return null;
  const source=string(input.block_id,80),equals=string(input.equals,80);
  const prior=priorFields.get(source);
  if(prior?.type!=='form_field'||!['dropdown','multiple_choice','yes_no'].includes(prior.field_type))fail(400,'invalid_visibility_dependency');
  if(prior.field_type==='yes_no'?!['true','false'].includes(equals):!prior.options.some(option=>option.id===equals))
    fail(400,'invalid_visibility_value');
  return {block_id:source,equals};
}
export function normalizeDefinition(input,{videoCapabilities=providerCapabilities()}={}){
  if(!input||typeof input!=='object'||Array.isArray(input))fail(400,'invalid_definition');
  const kind=string(input.kind,30);if(!kinds.has(kind))fail(400,'unsupported_definition_kind');
  const title=string(input.title,200);
  const scope=input.scope??'company';if(!['company','personal'].includes(scope))fail(400,'invalid_template_scope');
  const category=input.category==null?null:string(input.category,100,{required:false})||null;
  const blocks=Array.isArray(input.blocks)?input.blocks:[];
  if(blocks.length>100)fail(400,'too_many_blocks');
  const seen=new Set(),priorFields=new Map();let totalItems=0;
  const normalized=blocks.map((block,index)=>{
    if(!block||typeof block!=='object'||Array.isArray(block))fail(400,'invalid_block');
    const id=string(block.id,80);if(seen.has(id))fail(400,'duplicate_block_id');seen.add(id);
    const type=string(block.type,30);
    if(block.points!=null&&!['checklist','form_field','photo_evidence','video_evidence','signature'].includes(type))
      fail(400,'unsupported_block_points');
    const visibleIf=visibility(block.visible_if,priorFields),conditional=visibleIf?{visible_if:visibleIf}:{};
    if(['linked_quiz','linked_lesson'].includes(type)){
      if(visibleIf)fail(400,'conditional_link_unsupported');
      return {id,type,order:index,title:string(block.title,200),definition_id:uuid(block.definition_id),
        version_id:uuid(block.version_id),required:block.required!==false};
    }
    if(type==='instruction'){
      const text=string(block.text,5000),format=block.format??'plain';
      if(!['plain','markdown'].includes(format))fail(400,'invalid_instruction_format');
      if(format==='markdown'){
        if(/<\/?[a-z][^>]*>/i.test(text))fail(400,'instruction_html_unsupported');
        for(const match of text.matchAll(/(!?)\[[^\]]*\]\(([^)]*)\)/g)){
          if(match[1])fail(400,'instruction_remote_image_unsupported');
          let url;try{url=new URL(match[2]);}catch{fail(400,'invalid_instruction_link');}
          if(url.protocol!=='https:'||!url.hostname||url.username||url.password)fail(400,'invalid_instruction_link');
        }
      }
      return {id,type,order:index,text,format,...conditional};
    }
    if(type==='checklist'){
      if(!Array.isArray(block.items)||block.items.length<1||block.items.length>100)fail(400,'invalid_checklist');
      totalItems+=block.items.length;if(totalItems>200)fail(400,'too_many_checklist_items');
      const itemIDs=new Set();const items=block.items.map(item=>{
        if(!item||typeof item!=='object'||Array.isArray(item))fail(400,'invalid_checklist_item');
        const itemID=string(item.id,80);if(itemIDs.has(itemID))fail(400,'duplicate_item_id');itemIDs.add(itemID);
        return {id:itemID,text:string(item.text,300),required:item.required!==false};
      });
      const points=blockPoints(block.points);
      return {id,type,order:index,title:string(block.title??'Checklist',200),ordered:block.ordered===true,items,
        ...(points!=null?{points}:{}),...conditional};
    }
    if(type==='heading')return {id,type,order:index,text:string(block.text,200),...conditional};
    if(type==='divider')return {id,type,order:index,...conditional};
    if(['image','audio','pdf','file'].includes(type)){
      const content={id,type,order:index,file_id:uuid(block.file_id),title:string(block.title??type.toUpperCase(),200),
        caption:string(block.caption??'',1000,{required:false})};
      if(type==='image')content.alt_text=string(block.alt_text,500);
      if(type==='audio')content.transcript=string(block.transcript,5000);
      return {...content,...conditional};
    }
    if(type==='video')return {id,type,order:index,title:string(block.title??'Video',200),video:normalizeVideo(block.video,{capabilities:videoCapabilities}),...conditional};
    if(['photo_evidence','video_evidence','signature'].includes(type)){
      const min_count=block.required===false?0:bound(block.min_count??1,{min:1,max:type==='signature'?1:10,integer:true});
      const points=blockPoints(block.points);
      return {id,type,order:index,title:string(block.title??(type==='signature'?'Signature':'Evidence'),200),
        instructions:string(block.instructions??'',1000,{required:false}),required:block.required!==false,min_count,
        ...(points!=null?{points}:{}),...conditional};
    }
    if(type==='form_field'){
      const fieldType=string(block.field_type,30);if(!fieldTypes.has(fieldType))fail(400,'unsupported_field_type');
      const optionType=['dropdown','multiple_choice','multiple_selection'].includes(fieldType);
      let options=[];
      if(optionType){
        if(!Array.isArray(block.options)||block.options.length<2||block.options.length>40)fail(400,'invalid_field_options');
        const optionIDs=new Set();options=block.options.map(option=>{
          const optionID=string(option?.id,80);if(optionIDs.has(optionID))fail(400,'duplicate_option_id');optionIDs.add(optionID);
          return {id:optionID,label:string(option?.label,200)};
        });
      }else if(block.options!=null&&(!Array.isArray(block.options)||block.options.length>0))fail(400,'unexpected_field_options');
      const min=bound(block.min,{min:fieldType==='number'?-1000000000:0,max:1000000000,integer:fieldType!=='number'});
      const max=bound(block.max,{min:fieldType==='number'?-1000000000:0,max:1000000000,integer:fieldType!=='number'});
      if(min!=null&&max!=null&&min>max)fail(400,'invalid_field_bounds');
      const points=blockPoints(block.points);
      const field={id,type,order:index,field_type:fieldType,label:string(block.label,300),help_text:string(block.help_text??'',1000,{required:false}),required:block.required!==false,options,min,max,visible_if:visibleIf,
        ...(points!=null?{points}:{})};
      priorFields.set(id,field);return field;
    }
    fail(400,'unsupported_block_type');
  });
  if(kind==='checklist'&&!normalized.some(b=>b.type==='checklist'))fail(400,'checklist_required');
  if(['form','inspection'].includes(kind)&&!normalized.some(b=>b.type==='form_field'))fail(400,'form_field_required');
  if(kind==='quiz'&&normalized.some(b=>!['instruction','heading','divider'].includes(b.type)))fail(400,'invalid_quiz_block');
  if(kind!=='quiz'&&input.quiz!=null)fail(400,'unexpected_quiz');
  const timing=timingPolicy(input.timing,kind);
  return {schema_version:1,kind,title,scope,category,blocks:normalized,
    ...(timing?{timing}:{}),
    requires_review:input.requires_review===true||normalized.some(block=>block.points!=null||block.type==='video'&&block.video.mode==='E'&&block.video.supervisor_approval),
    ...(kind==='quiz'?{quiz:normalizeQuiz(input.quiz)}:{})};
}
export function normalizeResponses(document,input){
  if(!input||typeof input!=='object'||Array.isArray(input))fail(400,'invalid_responses');
  if(Object.keys(input).length>100)fail(400,'too_many_responses');
  const output={};const allowed=new Set(document.blocks.map(b=>b.id));
  for(const [blockID,value] of Object.entries(input)){
    if(!allowed.has(blockID))fail(400,'unknown_block');
    const block=document.blocks.find(b=>b.id===blockID);
    if(['instruction','heading','divider','image','audio','pdf','file','video','linked_quiz','linked_lesson'].includes(block.type))fail(400,'instruction_has_no_response');
    if(['photo_evidence','video_evidence','signature'].includes(block.type))fail(400,'evidence_responses_server_only');
    if(!value||typeof value!=='object'||Array.isArray(value))fail(400,'invalid_response');
    if(block.type==='form_field'){
      const answer=value.value;if(answer==null||answer==='')continue;
      switch(block.field_type){
        case 'short_text':case 'long_text': {
          const limit=block.field_type==='short_text'?500:5000;
          const cleaned=string(answer,limit);
          if(block.min!=null&&cleaned.length<block.min||block.max!=null&&cleaned.length>block.max)fail(400,'field_out_of_range');
          output[blockID]={value:cleaned};break;
        }
        case 'number':case 'rating': {
          if(typeof answer!=='number'||!Number.isFinite(answer)||Math.abs(answer)>1000000000)fail(400,'invalid_number_answer');
          if(block.field_type==='rating'&&(!Number.isInteger(answer)||answer<1||answer>5))fail(400,'invalid_rating_answer');
          if(block.min!=null&&answer<block.min||block.max!=null&&answer>block.max)fail(400,'field_out_of_range');
          output[blockID]={value:answer};break;
        }
        case 'yes_no': {if(typeof answer!=='boolean')fail(400,'invalid_boolean_answer');output[blockID]={value:answer};break;}
        case 'date':case 'time': {
          const pattern=block.field_type==='date'?/^\d{4}-\d{2}-\d{2}$/:/^\d{2}:\d{2}$/;
          if(typeof answer!=='string'||!pattern.test(answer))fail(400,'invalid_date_answer');
          if(block.field_type==='date'&&Number.isNaN(Date.parse(`${answer}T00:00:00Z`)))fail(400,'invalid_date_answer');
          if(block.field_type==='time'&&(Number(answer.slice(0,2))>23||Number(answer.slice(3))>59))fail(400,'invalid_date_answer');
          output[blockID]={value:answer};break;
        }
        case 'dropdown':case 'multiple_choice': {
          if(typeof answer!=='string'||!block.options.some(option=>option.id===answer))fail(400,'invalid_option_answer');
          output[blockID]={value:answer};break;
        }
        case 'multiple_selection': {
          if(!Array.isArray(answer)||answer.length>block.options.length||!answer.every(item=>typeof item==='string'&&block.options.some(option=>option.id===item)))fail(400,'invalid_option_answer');
          output[blockID]={value:[...new Set(answer)]};break;
        }
      }
      continue;
    }
    const checked=Array.isArray(value.checked_item_ids)?value.checked_item_ids:[];
    if(checked.length>block.items.length)fail(400,'invalid_checklist_response');
    const valid=new Set(block.items.map(i=>i.id));
    for(const id of checked)if(typeof id!=='string'||!valid.has(id))fail(400,'unknown_checklist_item');
    output[blockID]={checked_item_ids:[...new Set(checked)],note:value.note==null?'':string(value.note,2000,{required:false})};
  }
  for(const block of document.blocks){
    if(!block.visible_if||!Object.hasOwn(output,block.id))continue;
    if(!blockVisible(document,block,output))fail(400,'hidden_field_response');
  }
  return output;
}
export function blockVisible(document,block,responses,visited=new Set()){
  if(!block.visible_if)return true;
  if(visited.has(block.id))return false;
  visited.add(block.id);
  const source=document.blocks.find(candidate=>candidate.id===block.visible_if.block_id);
  if(!source||!blockVisible(document,source,responses,visited))return false;
  const answer=responses[block.visible_if.block_id]?.value;
  return answer!=null&&String(answer)===block.visible_if.equals;
}
export function unmetRequirements(document,responses,{evidenceCounts={},videoCompletions={},linkedCompletions={}}={}){
  const missing=[];
  for(const block of document.blocks){
    if(!blockVisible(document,block,responses))continue;
    if(['linked_quiz','linked_lesson'].includes(block.type)){
      if(block.required&&!linkedCompletions[block.id])missing.push({block_id:block.id,reason:'linked_assignment_incomplete'});
      continue;
    }
    if(block.type==='video'){
      if(block.video.required&&!videoCompletions[block.id])missing.push({block_id:block.id,reason:'video_not_completed'});
      continue;
    }
    if(['photo_evidence','video_evidence','signature'].includes(block.type)){
      if((evidenceCounts[block.id]??0)<block.min_count)missing.push({block_id:block.id,reason:'evidence_required',required_count:block.min_count});
      continue;
    }
    if(block.type==='form_field'){
      if(block.required){
        const value=responses[block.id]?.value;
        if(value==null||value===''||Array.isArray(value)&&!value.length)missing.push({block_id:block.id,reason:'required_field'});
      }
      continue;
    }
    if(block.type!=='checklist')continue;
    const done=new Set(responses[block.id]?.checked_item_ids||[]);
    for(const item of block.items)if(item.required&&!done.has(item.id))missing.push({block_id:block.id,item_id:item.id});
    if(block.ordered){let gap=false;for(const item of block.items){if(!done.has(item.id))gap=true;else if(gap)missing.push({block_id:block.id,item_id:item.id,reason:'ordered'});}}
  }
  return missing;
}
