import {readdirSync,readFileSync} from 'node:fs';
// Repository-maintained guidance is versioned Markdown; company guidance lives
// in wolf_assistant_guidance. Neither source can grant execution permission.
const folder=new URL('./guides/',import.meta.url);
export const productGuides=Object.freeze(readdirSync(folder).filter(x=>x.endsWith('.md')).sort().map(name=>{
 const content=readFileSync(new URL(name,folder),'utf8');
 const match=/^<!-- guide:([a-z_]+) version:(\d+) -->\n# ([^\n]+)\n\n([\s\S]+)$/.exec(content);
 if(!match)throw new Error('Invalid product guide: '+name);
 return {id:match[1],version:Number(match[2]),title:match[3],text:match[4].trim(),source:'assistant/guides/'+name};
}));
export function capabilityCategory(d){
 const keys=[['facebook_ads','Facebook Ads'],['webhook','Webhooks'],['map_','Map'],['measurement','Map'],['receipt','Finance'],['accounting','Finance'],['notes','Notes'],['note_','Notes'],['ideas','Ideas'],['todo','To-Do'],['task','To-Do'],['automation','Automations'],['dashboard','Dashboard'],['navigation','Settings'],['native','Native navigation'],['assistant_customer','Messages'],['assistant_route','Routes'],['assistant','Assistant'],['communications','Comms'],['files','Media'],['focus','Focus'],['browser','Browser'],['lighting','Lighting'],['equipment','Equipment'],['service','Services'],['quote','Quotes'],['finance','Finance'],['route','Routes'],['stage','Stages'],['pipeline','Stages'],['schedule','Schedule'],['contact','Contacts'],['lead_change_stage','Stages']];
 return keys.find(([prefix])=>d.id.startsWith(prefix))?.[1]||(d.family==='service'?(d.id.includes('availability')||d.id==='create_appointment'?'Schedule':'Quotes'):'CRM');
}
