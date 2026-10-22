import {fail} from './contract.js';

export function coveredSeconds(intervals){return Math.round(intervals.reduce((sum,[start,end])=>sum+end-start,0)*10)/10;}
export function contiguousPosition(intervals){
  let position=0;
  for(const [start,end] of intervals){if(start>position+0.25)break;position=Math.max(position,end);}
  return Math.round(position*10)/10;
}
export function addCoveredInterval(intervals,start,end,duration){
  if(!Array.isArray(intervals)||intervals.length>1000||![start,end,duration].every(value=>typeof value==='number'&&Number.isFinite(value)))fail(409,'invalid_video_progress');
  const from=Math.max(0,Math.min(duration,Math.round(start*10)/10));
  const to=Math.max(0,Math.min(duration,Math.round(end*10)/10));
  if(to<=from)return intervals;
  const sorted=[...intervals,[from,to]].sort((a,b)=>a[0]-b[0]),merged=[];
  for(const item of sorted){
    if(!Array.isArray(item)||item.length!==2||item[0]<0||item[1]>duration||item[1]<item[0])fail(409,'invalid_video_progress');
    const last=merged.at(-1);
    if(last&&item[0]<=last[1]+0.25)last[1]=Math.max(last[1],item[1]);
    else merged.push([...item]);
  }
  return merged;
}
