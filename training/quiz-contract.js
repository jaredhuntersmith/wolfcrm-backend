import {fail,string,uuid} from './contract.js';

const objectiveTypes=new Set(['multiple_choice','multiple_selection','true_false','matching','ordering','fill_blank','numeric','image_identification','image_multiple_choice']);
const subjectiveTypes=new Set(['short_answer','essay']);
const optionTypes=new Set(['multiple_choice','multiple_selection','ordering','image_identification','image_multiple_choice']);
const types=new Set([...objectiveTypes,...subjectiveTypes]);
function integer(value,min,max,code){if(!Number.isInteger(value)||value<min||value>max)fail(400,code);return value;}
function option(input){
  if(!input||typeof input!=='object'||Array.isArray(input))fail(400,'invalid_quiz_option');
  return {id:string(input.id,80),label:string(input.label,500),image_file_id:input.image_file_id==null?null:uuid(input.image_file_id)};
}
export function normalizeQuiz(input){
  if(!input||typeof input!=='object'||Array.isArray(input))fail(400,'invalid_quiz');
  if(!Array.isArray(input.questions)||input.questions.length<1||input.questions.length>100)fail(400,'invalid_quiz_questions');
  const seen=new Set();
  const questions=input.questions.map(raw=>{
    if(!raw||typeof raw!=='object'||Array.isArray(raw))fail(400,'invalid_quiz_question');
    const id=string(raw.id,80),type=string(raw.type,40),prompt=string(raw.prompt,2000);
    if(seen.has(id))fail(400,'duplicate_question_id');seen.add(id);
    if(!types.has(type))fail(400,'unsupported_question_type');
    const points=integer(raw.points??1,1,100,'invalid_question_points');
    const negative_points=integer(raw.negative_points??0,0,points,'invalid_negative_points');
    const image_file_id=raw.image_file_id==null?null:uuid(raw.image_file_id);
    const explanation=string(raw.explanation??'',2000,{required:false});
    let options=[];
    if(optionTypes.has(type)){
      if(!Array.isArray(raw.options)||raw.options.length<2||raw.options.length>12)fail(400,'invalid_quiz_options');
      options=raw.options.map(option);if(new Set(options.map(o=>o.id)).size!==options.length)fail(400,'duplicate_option_id');
      if(type==='image_identification'&&!image_file_id)fail(400,'question_image_required');
      if(type==='image_multiple_choice'&&!options.some(o=>o.image_file_id))fail(400,'option_image_required');
    }else if(type!=='matching'&&raw.options!=null&&(!Array.isArray(raw.options)||raw.options.length))fail(400,'unexpected_quiz_options');
    const optionIDs=new Set(options.map(o=>o.id));
    let answer=null;
    if(type==='multiple_choice'||type==='image_identification'||type==='image_multiple_choice'){
      answer=string(raw.answer,80);if(!optionIDs.has(answer))fail(400,'invalid_correct_answer');
    }else if(type==='multiple_selection'){
      if(!Array.isArray(raw.answer)||raw.answer.length<1||raw.answer.length>options.length||raw.answer.some(id=>!optionIDs.has(id)))fail(400,'invalid_correct_answer');
      if(new Set(raw.answer).size!==raw.answer.length)fail(400,'invalid_correct_answer');answer=raw.answer;
    }else if(type==='true_false'){
      if(typeof raw.answer!=='boolean')fail(400,'invalid_correct_answer');answer=raw.answer;
    }else if(type==='ordering'){
      if(!Array.isArray(raw.answer)||raw.answer.length!==options.length||new Set(raw.answer).size!==options.length||raw.answer.some(id=>!optionIDs.has(id)))fail(400,'invalid_correct_answer');answer=raw.answer;
    }else if(type==='matching'){
      const pairs=raw.pairs??raw.options?.map(item=>({id:item.id,left:item.label,right:item.right}));
      if(!Array.isArray(pairs)||pairs.length<2||pairs.length>12)fail(400,'invalid_matching_pairs');
      options=pairs.map((pair,index)=>({id:string(pair.id??`pair-${index+1}`,80),label:string(pair.left,500),right:string(pair.right,500)}));
      if(new Set(options.map(o=>o.id)).size!==options.length)fail(400,'duplicate_option_id');
      answer=Object.fromEntries(options.map(pair=>[pair.id,pair.right]));
    }else if(type==='fill_blank'){
      if(!Array.isArray(raw.answer)||raw.answer.length<1||raw.answer.length>20)fail(400,'invalid_correct_answer');
      answer=[...new Set(raw.answer.map(value=>string(value,200).toLocaleLowerCase('en-US')))];
    }else if(type==='numeric'){
      if(typeof raw.answer!=='number'||!Number.isFinite(raw.answer)||Math.abs(raw.answer)>1000000000)fail(400,'invalid_correct_answer');
      const tolerance=raw.tolerance??0;if(typeof tolerance!=='number'||!Number.isFinite(tolerance)||tolerance<0||tolerance>1000000)fail(400,'invalid_numeric_tolerance');
      answer=raw.answer;
      return {id,type,prompt,points,negative_points,image_file_id,explanation,options,answer,tolerance};
    }
    return {id,type,prompt,points,negative_points,image_file_id,explanation,options,answer};
  });
  const passing_percent=integer(input.passing_percent??80,0,100,'invalid_passing_percent');
  const max_attempts=integer(input.max_attempts??1,1,20,'invalid_attempt_limit');
  const time_limit_seconds=input.time_limit_seconds==null?null:integer(input.time_limit_seconds,30,86400,'invalid_time_limit');
  const cooldown_seconds=integer(input.cooldown_seconds??0,0,2592000,'invalid_cooldown');
  const show_results=input.show_results??'after_review';if(!['immediate','after_review','never'].includes(show_results))fail(400,'invalid_result_policy');
  return {passing_percent,max_attempts,time_limit_seconds,cooldown_seconds,show_results,show_answers_after_grade:input.show_answers_after_grade===true,
    shuffle_questions:input.shuffle_questions!==false,shuffle_answers:input.shuffle_answers!==false,questions};
}

export function learnerQuiz(quiz,{questionOrder,choiceOrders}={}){
  const byID=new Map(quiz.questions.map(question=>[question.id,question]));
  const ids=questionOrder??quiz.questions.map(question=>question.id);
  return {passing_percent:quiz.passing_percent,max_attempts:quiz.max_attempts,time_limit_seconds:quiz.time_limit_seconds,
    questions:ids.map(id=>{
      const question=byID.get(id);if(!question)fail(409,'invalid_attempt_snapshot');
      const order=choiceOrders?.[id];const choices=order?order.map(choiceID=>question.options.find(o=>o.id===choiceID)).filter(Boolean):question.options;
      return {id:question.id,type:question.type,prompt:question.prompt,points:question.points,image_file_id:question.image_file_id,
        options:choices.map(({id,label,image_file_id})=>({id,label,image_file_id}))};
    })};
}

export function normalizeQuizAnswers(quiz,input){
  if(!input||typeof input!=='object'||Array.isArray(input)||Object.keys(input).length>quiz.questions.length)fail(400,'invalid_quiz_responses');
  const byID=new Map(quiz.questions.map(question=>[question.id,question]));const output={};
  for(const [id,value] of Object.entries(input)){
    const question=byID.get(id);if(!question)fail(400,'unknown_question');
    if(value==null||value==='')continue;
    const optionIDs=new Set(question.options.map(option=>option.id));
    switch(question.type){
    case 'multiple_choice':case 'image_identification':case 'image_multiple_choice':
      if(typeof value!=='string'||!optionIDs.has(value))fail(400,'invalid_quiz_response');output[id]=value;break;
    case 'multiple_selection':case 'ordering':
      if(!Array.isArray(value)||value.length>optionIDs.size||value.some(choice=>typeof choice!=='string'||!optionIDs.has(choice))||new Set(value).size!==value.length)fail(400,'invalid_quiz_response');
      output[id]=value;break;
    case 'matching':
      if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length>optionIDs.size||Object.entries(value).some(([key,match])=>!optionIDs.has(key)||typeof match!=='string'||match.length>500))fail(400,'invalid_quiz_response');
      output[id]=value;break;
    case 'true_false':
      if(typeof value!=='boolean')fail(400,'invalid_quiz_response');output[id]=value;break;
    case 'numeric':
      if(typeof value!=='number'||!Number.isFinite(value)||Math.abs(value)>1000000000)fail(400,'invalid_quiz_response');output[id]=value;break;
    case 'fill_blank':case 'short_answer':case 'essay':
      output[id]=string(value,question.type==='essay'?10000:2000);break;
    }
  }
  return output;
}

export function gradeQuiz(quiz,responses){
  let awarded=0,total=0;const details={};let manual=false;
  for(const question of quiz.questions){
    total+=question.points;const response=responses[question.id],answer=question.answer;
    let points=0,requiresManual=false;
    if(subjectiveTypes.has(question.type))requiresManual=response!=null;
    else if(response!=null){
      switch(question.type){
      case 'multiple_choice':case 'image_identification':case 'image_multiple_choice':case 'true_false':points=response===answer?question.points:-question.negative_points;break;
      case 'multiple_selection': {
        const correct=new Set(answer),selected=new Set(response);
        const hits=[...selected].filter(id=>correct.has(id)).length,wrong=[...selected].filter(id=>!correct.has(id)).length;
        points=Math.max(-question.negative_points,question.points*(hits/correct.size-wrong/(question.options.length-correct.size||1)));break;
      }
      case 'ordering':points=question.points*response.filter((id,index)=>answer[index]===id).length/answer.length;break;
      case 'matching':points=question.points*Object.entries(answer).filter(([key,match])=>response[key]?.trim().toLocaleLowerCase('en-US')===match.toLocaleLowerCase('en-US')).length/Object.keys(answer).length;break;
      case 'fill_blank':points=answer.includes(response.trim().toLocaleLowerCase('en-US'))?question.points:-question.negative_points;break;
      case 'numeric':points=Math.abs(response-answer)<=question.tolerance?question.points:-question.negative_points;break;
      }
    }
    if(requiresManual)manual=true;
    awarded+=points;details[question.id]={auto_points:Math.round(points*100)/100,requires_manual:requiresManual};
  }
  return {auto_points:Math.max(0,Math.round(awarded*100)/100),max_points:total,requires_manual:manual,details};
}
