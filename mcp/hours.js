import {z} from 'zod';
const clock=z.string().regex(/^(?:[01]\d|2[0-3]):[0-5]\d$/);
export const hoursSchema=z.object({
 timezone:z.string().max(100).refine(v=>{try{new Intl.DateTimeFormat('en',{timeZone:v});return true;}catch{return false;}},'Choose an IANA timezone'),
 mode:z.enum(['always','allowed','blocked']),
 windows:z.array(z.object({days:z.array(z.number().int().min(1).max(7)).min(1).max(7),start:clock,end:clock}).strict()).max(100),
 exceptions:z.array(z.object({start:z.iso.datetime({offset:true}),end:z.iso.datetime({offset:true}),allow:z.boolean()}).strict().refine(v=>Date.parse(v.end)>Date.parse(v.start))).max(100)
}).strict();
export const alwaysHours=(timezone='America/New_York')=>({timezone,mode:'always',windows:[],exceptions:[]});
const minute=s=>Number(s.slice(0,2))*60+Number(s.slice(3));
const formats=new Map();
export function withinHours(hours,date=new Date()){
 if(!hours)return true;
 const active=hours.exceptions.filter(v=>Date.parse(v.start)<=date.getTime()&&date.getTime()<Date.parse(v.end));
 // An explicit block always wins over a simultaneous allow exception.
 if(active.some(v=>!v.allow))return false;if(active.some(v=>v.allow))return true;
 if(hours.mode==='always')return true;
 let format=formats.get(hours.timezone);if(!format){format=new Intl.DateTimeFormat('en-US',{timeZone:hours.timezone,weekday:'short',hour:'2-digit',minute:'2-digit',hourCycle:'h23'});formats.set(hours.timezone,format);}
 const parts=Object.fromEntries(format.formatToParts(date).map(p=>[p.type,p.value]));
 const day=['Mon','Tue','Wed','Thu','Fri','Sat','Sun'].indexOf(parts.weekday)+1,t=Number(parts.hour)*60+Number(parts.minute),previous=day===1?7:day-1;
 const hit=hours.windows.some(w=>{const a=minute(w.start),b=minute(w.end);return a<b?w.days.includes(day)&&t>=a&&t<b:(w.days.includes(day)&&t>=a)||(w.days.includes(previous)&&t<b);});
 return hours.mode==='allowed'?hit:!hit;
}
export function accessStatus(row,companyHours,date=new Date(),{next=false}={}){
 const reason=row.revoked_at?'revoked':row.archived_at?'archived':!row.enabled?'disabled':row.paused_until&&Date.parse(row.paused_until)>date.getTime()?'paused_until':!withinHours(companyHours,date)?'company_hours':!withinHours(row.operating_hours,date)?'connection_hours':null;
 let next_allowed_at=null;
 if(next&&reason&&['paused_until','company_hours','connection_hours'].includes(reason)){
  const start=Math.max(date.getTime(),row.paused_until?Date.parse(row.paused_until):0);
  // Bound work to eight days; null explicitly means no opening computed in this horizon.
  for(let t=Math.ceil(start/60000)*60000;t<start+8*86400000;t+=60000){const d=new Date(t);if(withinHours(companyHours,d)&&withinHours(row.operating_hours,d)){next_allowed_at=d.toISOString();break;}}
 }
 return {allowed:reason===null,reason,next_allowed_at};
}
