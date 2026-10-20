// Focused execution context. No record values or prior assistant prose are carried.
export function pinnedReadArguments(tool,args,result,now=new Date()){
 if(tool!=='crm_availability')return args;
 const start=args.start||result?.availability?.range_start||now.toISOString();
 const end=args.end||result?.availability?.range_end||new Date(Date.parse(start)+7*86400000).toISOString();
 return {...args,start,end};
}
export function discoverCatalog(catalog,query){
 const terms=query.toLowerCase().match(/[a-z0-9_]+/g)||[];
 const ignored=new Set(['a','an','the','and','or','to','for','in','of','open','please']);
 const words=terms.filter(t=>!ignored.has(t));
 return catalog.map((entry,index)=>{const text=`${entry.id} ${entry.name} ${entry.category} ${entry.description}`.toLowerCase();const score=words.reduce((n,w)=>n+(text.includes(w)?1:0),0);return {entry,index,score};})
  .filter(x=>!words.length||x.score>0).sort((a,b)=>b.score-a.score||a.index-b.index).map(x=>x.entry);
}
export function clockContext(timezone,now=new Date()){
 let zone=timezone||'UTC';try{new Intl.DateTimeFormat('en',{timeZone:zone}).format(now);}catch{zone='UTC';}
 return 'Authoritative server clock: '+now.toISOString()+'. Company time zone: '+zone+'. Company local date/time: '+new Intl.DateTimeFormat('en-US',{timeZone:zone,dateStyle:'full',timeStyle:'long'}).format(now)+'. Resolve relative dates against this clock in the company time zone, including daylight saving. State the resolved calendar date; clarify ambiguous dates/times. Never derive the clock from screen content.';
}
export function businessOutcome(result){
 const value=result?.data??result;
 const status=value?.status||value?.state;
 if(result?.error)return {status:'failed',reason:result.error};
 if(['failed','unavailable','conflict','rejected','expired'].includes(status))return {status:'failed',reason:value.reason||status};
 if(['pending','pending_approval','approval_required','waiting_approval','queued'].includes(status))return {status:'pending',reason:value.reason||status};
 return {status:'succeeded',reason:null};
}

// Ignore only presentation metadata that changes on every canonical read.
// All business values, coverage, and warning fields remain part of the check.
export function comparableReadEvidence(tool,result){
 if(tool!=='sales_report'||!result?.report||!Object.hasOwn(result.report,'generated_at'))return result;
 const {generated_at,...report}=result.report;
 return {...result,report};
}

// A confirmed write can invalidate earlier reads in this run. Keep original
// step receipts intact, but remove those values from provider context. The
// assistant must retrieve fresh authorized data before relying on them again.
export function retireReadEvidence(history,steps){
 const reads=new Map(steps.map(s=>[s.call_id,s]));
 return history.map(item=>item.type==='function_call_output'&&reads.has(item.call_id)?{...item,output:JSON.stringify({evidence_retired:true,capability:reads.get(item.call_id).tool,note:'A confirmed change superseded this read. Retrieve fresh authorized data before relying on it.'})}:item);
}
