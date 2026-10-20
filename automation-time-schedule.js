import {z} from 'zod';

const validZone=value=>{try{new Intl.DateTimeFormat('en-US',{timeZone:value}).format();return true;}catch{return false;}};
const secondsOfDay=value=>{const [hour,minute,second]=value.split(':').map(Number);return hour*3600+minute*60+second;};
const clockTime=z.string().regex(/^(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d$/,'Use HH:mm:ss (24-hour time).');
const onceWindow=z.object({
 kind:z.literal('once'),
 start_at:z.string().datetime({offset:true}).optional(),
 end_at:z.string().datetime({offset:true}).optional(),
}).strict().superRefine((value,context)=>{
 if(!value.start_at&&!value.end_at)context.addIssue({code:'custom',message:'Choose a start or end time.'});
 if(value.start_at&&value.end_at&&Date.parse(value.start_at)>=Date.parse(value.end_at))context.addIssue({code:'custom',message:'End must be after start.'});
});
const weeklyWindow=z.object({
 kind:z.literal('weekly'),
 weekdays:z.array(z.number().int().min(1).max(7)).min(1,'Choose at least one weekday.').max(7).refine(days=>new Set(days).size===days.length,'Choose each weekday once.'),
 start_time:clockTime,
 end_time:clockTime,
}).strict();
export const activationScheduleSchema=z.object({
 timezone:z.string().max(100).refine(value=>value==='company'||validZone(value),'Choose a valid time zone.'),
 windows:z.array(z.union([onceWindow,weeklyWindow])).min(1).max(32),
}).strict();
const activationFormatters=new Map();
function activationParts(date,zone){
 if(!activationFormatters.has(zone))activationFormatters.set(zone,new Intl.DateTimeFormat('en-CA',{timeZone:zone,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23'}));
 return Object.fromEntries(activationFormatters.get(zone).formatToParts(date).filter(part=>part.type!=='literal').map(part=>[part.type,Number(part.value)]));
}
export function activationScheduleAllows(raw,companyZone,at=new Date()){
 if(raw==null)return true;
 const parsed=activationScheduleSchema.safeParse(raw);
 if(!parsed.success)return false;
 const schedule=parsed.data;
 if(schedule.windows.length===0)return true;
 const zone=schedule.timezone==='company'?(companyZone||'UTC'):schedule.timezone;
 if(!validZone(zone))return false;
 let local;
 for(const window of schedule.windows){
  if(window.kind==='once'){
   if((!window.start_at||at>=new Date(window.start_at))&&(!window.end_at||at<new Date(window.end_at)))return true;
   continue;
  }
  local ||= activationParts(at,zone);
  const day=new Date(Date.UTC(local.year,local.month-1,local.day)).getUTCDay()||7;
  const previousDay=day===1?7:day-1;
  const second=local.hour*3600+local.minute*60+local.second;
  const start=secondsOfDay(window.start_time),end=secondsOfDay(window.end_time);
  if(start<end&&window.weekdays.includes(day)&&second>=start&&second<end)return true;
  if(start>end&&((window.weekdays.includes(day)&&second>=start)||(window.weekdays.includes(previousDay)&&second<end)))return true;
  if(start===end&&window.weekdays.includes(day))return true;
 }
 return false;
}
export const timeScheduleSchema=z.object({
 frequency:z.enum(['daily','weekly','monthly']),
 time:z.string().regex(/^(?:[01]\d|2[0-3]):[0-5]\d$/),
 timezone:z.string().max(100).refine(v=>v==='company'||validZone(v)).default('company'),
 weekdays:z.array(z.number().int().min(1).max(7)).max(7).default([]),
 month_day:z.number().int().min(1).max(31).optional(),
 missed_run_window_minutes:z.number().int().min(1).max(120).default(15),
}).strict().superRefine((v,c)=>{
 if(v.frequency==='weekly'&&!v.weekdays.length)c.addIssue({code:'custom',message:'Select at least one weekday (Monday=1).'});
 if(v.frequency==='monthly'&&!v.month_day)c.addIssue({code:'custom',message:'Select a day of month.'});
});
const formatters=new Map();
function parts(date,zone){
 if(!formatters.has(zone))formatters.set(zone,new Intl.DateTimeFormat('en-CA',{timeZone:zone,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hourCycle:'h23'}));
 return Object.fromEntries(formatters.get(zone).formatToParts(date).filter(p=>p.type!=='literal').map(p=>[p.type,Number(p.value)]));
}
const wallStamp=p=>Date.UTC(p.year,p.month-1,p.day,p.hour||0,p.minute||0);
// Enumerate nearby offsets, then round-trip the wall clock. This skips missing
// spring-forward times and selects the first instant when fall-back repeats.
export function localScheduleInstant(date,time,zone){
 const [year,month,day]=date.split('-').map(Number),[hour,minute]=time.split(':').map(Number);
 const target={year,month,day,hour,minute},wall=wallStamp(target),offsets=new Set();
 for(let h=-36;h<=36;h+=6){const instant=wall+h*3600000;offsets.add(wallStamp(parts(new Date(instant),zone))-instant);}
 const matches=[...offsets].map(o=>wall-o).filter(t=>wallStamp(parts(new Date(t),zone))===wall).sort((a,b)=>a-b);
 return matches.length?new Date(matches[0]):null;
}
export function dueTimeSchedule(raw,companyZone,now=new Date(),activeSince=new Date(0)){
 const config=timeScheduleSchema.parse(raw),zone=config.timezone==='company'?(companyZone||'UTC'):config.timezone;
 if(!validZone(zone))return null;
 const today=parts(now,zone),midnight=Date.UTC(today.year,today.month-1,today.day),candidates=[];
 for(const shift of [-1,0]){
  const calendar=new Date(midnight+shift*86400000),date=calendar.toISOString().slice(0,10),weekday=calendar.getUTCDay()||7;
  if(config.frequency==='weekly'&&!config.weekdays.includes(weekday))continue;
  if(config.frequency==='monthly'&&calendar.getUTCDate()!==config.month_day)continue;
  const instant=localScheduleInstant(date,config.time,zone);
  if(!instant||instant<new Date(activeSince)||instant>now||now-instant>config.missed_run_window_minutes*60000)continue;
  candidates.push({date,timezone:zone,scheduled_for:instant});
 }
 return candidates.sort((a,b)=>b.scheduled_for-a.scheduled_for)[0]||null;
}

const activeRules=`SELECT n.id,n.node_key,n.config,n.version_id,d.id AS automation_id,d.company_id,d.metadata,v.published_at,c.timezone
 FROM automation_nodes n JOIN automation_versions v ON v.id=n.version_id AND v.company_id=n.company_id
 JOIN automation_definitions d ON d.id=v.automation_id AND d.company_id=n.company_id AND d.active_version_id=v.id
 JOIN companies c ON c.id=d.company_id
 WHERE n.node_type='trigger' AND n.config->>'trigger_key'='time.schedule'
 AND v.status='published' AND (d.status='published' OR (d.status='paused' AND d.pause_until<=$1))
 AND (d.pause_until IS NULL OR d.pause_until<=$1) AND c.automations_enabled=true
 AND c.automation_emergency_stopped_at IS NULL`;

export async function enqueueTimeSchedules(pool,now=new Date()){
 let cursor=null,queued=0;
 // Keyset pages bound each read without starving later rules.
 for(;;){
  const rules=(await pool.query(activeRules+' AND ($2::uuid IS NULL OR n.id>$2) ORDER BY n.id LIMIT 200',[now,cursor])).rows;
  for(const rule of rules){
   if(!activationScheduleAllows(rule.metadata?.activation_schedule,rule.timezone,now))continue;
   const parsed=timeScheduleSchema.safeParse(rule.config.schedule);if(!parsed.success)continue;
   const due=dueTimeSchedule(parsed.data,rule.timezone,now,rule.published_at);if(!due)continue;
   const key=`time.schedule:${rule.automation_id}:${rule.node_key}:${due.date}`;
   const result=await pool.query(`INSERT INTO automation_scheduled_events(company_id,event_type,subject_type,subject_id,scheduled_for,schedule_key,source_version,payload)
    VALUES($1,'time.schedule','automation',$2,$3,$4,$5,$6) ON CONFLICT(company_id,schedule_key) DO NOTHING`,
    [rule.company_id,rule.automation_id,due.scheduled_for,key,rule.version_id,JSON.stringify({trigger_node_id:rule.id,automation_id:rule.automation_id,local_date:due.date,local_time:parsed.data.time,timezone:due.timezone})]);
   queued+=result.rowCount;
  }
  if(rules.length<200)break;cursor=rules.at(-1).id;
 }
 return queued;
}
export async function timeScheduleStillCurrent(pool,row,now=new Date()){
 const rule=(await pool.query(activeRules+' AND n.id=$2 AND d.company_id=$3 AND n.version_id::text=$4',[now,row.payload?.trigger_node_id,row.company_id,row.source_version])).rows[0];
 if(!rule)return false;
 if(!activationScheduleAllows(rule.metadata?.activation_schedule,rule.timezone,now))return false;
 const parsed=timeScheduleSchema.safeParse(rule.config.schedule);if(!parsed.success)return false;
 const due=dueTimeSchedule(parsed.data,rule.timezone,now,rule.published_at);
 return !!due&&due.date===row.payload.local_date&&due.scheduled_for.getTime()===new Date(row.scheduled_for).getTime();
}
