import {fail,string} from './contract.js';
import {learnerQuiz,normalizeQuiz} from './quiz-contract.js';

export function normalizeCheckpoints(input,duration){
  if(!Array.isArray(input)||input.length<1||input.length>30)fail(400,'invalid_video_checkpoints');
  const seen=new Set();let previous=0;
  return input.map(raw=>{
    if(!raw||typeof raw!=='object'||Array.isArray(raw))fail(400,'invalid_video_checkpoint');
    const id=string(raw.id,80),at_seconds=raw.at_seconds,kind=string(raw.kind,20);
    if(seen.has(id))fail(400,'duplicate_video_checkpoint');seen.add(id);
    if(!Number.isInteger(at_seconds)||at_seconds<1||at_seconds>=duration||at_seconds<=previous)fail(400,'invalid_checkpoint_time');
    previous=at_seconds;
    if(kind==='instruction')return {id,kind,at_seconds,text:string(raw.text,2000),require_acknowledgment:true};
    if(kind!=='question')fail(400,'invalid_checkpoint_kind');
    const question=normalizeQuiz({questions:[raw.question],passing_percent:100,max_attempts:1,
      shuffle_questions:false,shuffle_answers:false}).questions[0];
    const max_attempts=raw.max_attempts??3;
    if(!Number.isInteger(max_attempts)||max_attempts<1||max_attempts>20)fail(400,'invalid_checkpoint_attempts');
    const replay_seconds=raw.replay_seconds??0;
    if(!Number.isInteger(replay_seconds)||replay_seconds<0||replay_seconds>Math.min(at_seconds,300))fail(400,'invalid_checkpoint_replay');
    const require_correct=raw.require_correct!==false;
    const progression_policy=raw.progression_policy??'await_review';
    if(!['await_review','after_response'].includes(progression_policy))fail(400,'invalid_checkpoint_progression');
    return {id,kind,at_seconds,question,max_attempts,replay_seconds,require_correct,progression_policy};
  });
}

export function learnerCheckpoint(checkpoint){
  if(checkpoint.kind==='instruction')return checkpoint;
  return {...checkpoint,question:learnerQuiz({questions:[checkpoint.question],passing_percent:100,
    max_attempts:checkpoint.max_attempts,time_limit_seconds:null}).questions[0]};
}
