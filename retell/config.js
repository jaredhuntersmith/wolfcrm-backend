import {z} from 'zod';
export const time=z.string().regex(/^(?:[01]\d|2[0-3]):[0-5]\d$/);
export const directProfileSchema=z.object({id:z.uuid(),name:z.string().trim().min(1).max(120),service_ids:z.array(z.uuid()).min(1).max(30),property_type:z.enum(['residential','commercial']),max_stories:z.number().int().min(1).max(100),max_window_count:z.number().int().min(0).max(100000).nullable(),duration_minutes:z.number().int().min(5).max(1440)}).strict();
export const configSchema=z.object({
 quotes_enabled:z.boolean().default(false),
 require_quote_acceptance:z.boolean().nullable().default(null),require_deposit:z.boolean().nullable().default(null),direct_job_profiles:z.array(directProfileSchema).max(20).default([]),
 quote_enabled:z.boolean().default(false),job_enabled:z.boolean().default(false),automatic_booking:z.boolean().default(false),
 postal_codes:z.array(z.string().regex(/^\d{5}$/)).max(500).default([]),
 quote_weekdays:z.array(z.number().int().min(1).max(7)).max(7).default([]),quote_start:time.nullable().default(null),quote_end:time.nullable().default(null),
 quote_duration_minutes:z.number().int().min(5).max(480).nullable().default(15),
 minimum_notice_minutes:z.number().int().min(0).max(43200).nullable().default(null),
 horizon_days:z.number().int().min(1).max(90).nullable().default(null),
 start_increment_minutes:z.number().int().min(5).max(120).multipleOf(5).nullable().default(null),
 buffer_before_minutes:z.number().int().min(0).max(240).nullable().default(null),buffer_after_minutes:z.number().int().min(0).max(240).nullable().default(null),
 quote_worker_ids:z.array(z.uuid()).max(20).default([]),job_rules_acknowledged:z.boolean().default(false)
}).strict();
export function missingRules(config,type){const c=configSchema.parse(config),missing=[];
 if(!c.postal_codes.length)missing.push('service-area ZIP codes');
 if(type==='quote'){
  for(const k of ['quote_duration_minutes','minimum_notice_minutes','horizon_days','start_increment_minutes','buffer_before_minutes','buffer_after_minutes'])if(c[k]===null)missing.push(k);
  if(!c.quote_weekdays.length||!c.quote_start||!c.quote_end||c.quote_start>=c.quote_end)missing.push('quote visit hours');
  if(!c.quote_worker_ids.length)missing.push('quote visit workers');
 }else{if(!c.job_rules_acknowledged)missing.push('review existing Schedule booking rules');if(c.require_quote_acceptance===null)missing.push('Riley quote-acceptance policy');if(c.require_deposit===null)missing.push('Riley deposit policy');}
 return missing;
}
export const normalizeText=s=>s.trim().replace(/\s+/g,' ').toLowerCase();
export function inServiceArea(address,c){const zip=address.match(/\b(\d{5})(?:-\d{4})?(?:\s*,?\s*(?:USA|US|United States))?\s*$/i)?.[1];return !!zip&&c.postal_codes.includes(zip);}
export function offsetISO(date){const d=new Date(date),parts=Object.fromEntries(new Intl.DateTimeFormat('en-CA',{timeZone:'America/New_York',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23',timeZoneName:'longOffset'}).formatToParts(d).map(p=>[p.type,p.value]));return `${parts.year}-${parts.month}-${parts.day}T${parts.hour}:${parts.minute}:${parts.second}${parts.timeZoneName.replace('GMT','')||'+00:00'}`;}

export const readConfig=value=>configSchema.parse(Object.fromEntries(Object.entries(value||{}).filter(([k])=>k!=='job_rules_hash')));
