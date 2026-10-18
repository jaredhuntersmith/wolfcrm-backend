import {z} from 'zod';
import {fault} from '../mcp/context.js';
const id=z.string().regex(/^[a-zA-Z0-9_-]{1,80}$/),amount=z.union([z.string().regex(/^\d{1,9}(\.\d{1,6})?$/),z.number().finite().min(0).max(1e9)]);
const cents=z.number().int().min(0).max(2e9),seconds=z.number().int().min(0).max(604800);
export const units=['count','second','minute','hour','inch','foot','yard','mm','cm','m','sq_in','sq_ft','sq_cm','sq_m'];
const unit=z.string().refine(v=>units.includes(v)||/^custom:[a-zA-Z0-9 _-]{1,40}$/.test(v),'Select a compatible standard or custom unit.');
const scalar=z.union([z.string().max(1000),z.number().finite(),z.boolean(),z.null()]);
const condition=z.object({kind:z.enum(['answer','component','service']),ref:id,op:z.enum(['eq','ne','gte','lte','known']),value:scalar.optional()}).strict();
const conditions=z.array(condition).max(12).default([]);
const question=z.object({id,label:z.string().min(1).max(160),help:z.string().max(500).default(''),type:z.enum(['number','boolean','choice','text']),unit:unit.optional(),choices:z.array(z.string().max(100)).max(30).default([]),min:amount.nullable().default(null),max:amount.nullable().default(null),required:z.boolean().default(false),required_when:conditions,lead_field:z.string().max(160).nullable().default(null),service_ids:z.array(z.uuid()).max(50)}).strict();
const adjustment=z.object({id,label:z.string().min(1).max(160),when:conditions,add_cents:cents.nullable().default(null),add_seconds:seconds.nullable().default(null),money_factor_bp:z.number().int().min(0).max(100000).nullable().default(null),time_factor_bp:z.number().int().min(0).max(100000).nullable().default(null)}).strict();
const component=z.object({id,name:z.string().min(1).max(160),description:z.string().max(2000).default(''),order:z.number().int().min(0).max(10000).default(0),service_ids:z.array(z.uuid()).min(1).max(50),scope:z.enum(['service','visit']),unit,quantity_fact:id.nullable().default(null),default_quantity:amount.nullable().default(null),min_quantity:amount.nullable().default(null),max_quantity:amount.nullable().default(null),decimal_quantity:z.boolean(),selection:z.enum(['optional','default','required']),disabled_when:conditions,required_when:conditions,money_enabled:z.boolean(),time_enabled:z.boolean(),fixed_cents:cents.nullable().default(null),unit_cents:cents.nullable().default(null),fixed_seconds:seconds.nullable().default(null),unit_seconds:seconds.nullable().default(null),minimum_cents:cents.nullable().default(null),visible:z.boolean(),show_price:z.boolean().default(false),adjustments:z.array(adjustment).max(12).default([])}).strict();
const service=z.object({service_id:z.uuid(),minimum_cents:cents.nullable().default(null),crew_size:z.number().int().min(1).max(30).nullable().default(null),elapsed_ratio_bp:z.number().int().min(1).max(100000).nullable().default(null)}).strict();
export const catalogSchema=z.object({questions:z.array(question).max(100).default([]),components:z.array(component).max(150).default([]),services:z.array(service).max(100).default([]),quote_minimum_cents:cents.nullable().default(null)}).strict();
export const answerSchema=z.object({value:scalar,source:z.enum(['confirmed','lead_form','inferred']),unit:unit.optional()}).strict();
const selection=z.object({selected:z.boolean().optional(),quantity_mode:z.enum(['linked','override']).default('linked'),quantity:amount.nullable().optional(),unit:unit.optional()}).strict();
export const inputSchema=z.object({service_ids:z.array(z.uuid()).max(20),answers:z.record(id,answerSchema).default({}),components:z.record(z.string().max(170),selection).default({})}).strict();
export const overrideSchema=z.object({reason:z.string().min(3).max(300),service_cents:z.record(z.uuid(),cents).default({}),elapsed_seconds:seconds.optional()}).strict();
const error=(code,message)=>{throw fault(400,code,message);};
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
function unique(rows,key='id'){const ids=new Set();for(const r of rows){if(ids.has(r[key]))error('duplicate_definition',`Duplicate ${key}: ${r[key]}`);ids.add(r[key]);}return ids;}
function possible(rules){
 const groups=new Map();for(const r of rules){const key=r.kind+':'+r.ref;if(!groups.has(key))groups.set(key,[]);groups.get(key).push(r);}
 for(const rules of groups.values()){
  const equal=rules.filter(r=>r.op==='eq').map(r=>r.value),not=rules.filter(r=>r.op==='ne').map(r=>r.value);
  const low=Math.max(-Infinity,...rules.filter(r=>r.op==='gte').map(r=>Number(r.value))),high=Math.min(Infinity,...rules.filter(r=>r.op==='lte').map(r=>Number(r.value)));
  if(low>high||equal.length&&(equal.some(v=>!same(v,equal[0]))||not.some(v=>same(v,equal[0]))||typeof equal[0]==='number'&&(equal[0]<low||equal[0]>high))||low===high&&not.includes(low))return false;
 }
 return true;
}
export function validateCatalog(raw){
 const c=catalogSchema.parse(raw),questions=unique(c.questions),components=unique(c.components),services=unique(c.services,'service_id'),edges=new Map(c.components.map(v=>[v.id,new Set()]));
 for(const q of c.questions){if(q.type==='choice'&&!q.choices.length)error('choices_required',q.label);if(q.min!==null&&q.max!==null&&Number(q.min)>Number(q.max))error('invalid_limits',q.label);}
 const check=(rules,owner)=>{if(!possible(rules))error('incompatible_conditions','These conditions can never match.');for(const r of rules){if(r.kind==='answer'&&!questions.has(r.ref)||r.kind==='component'&&!components.has(r.ref)||r.kind==='service'&&!services.has(r.ref))error('unknown_rule_reference',r.ref);if(r.op!=='known'&&r.value===undefined)error('rule_value_required',r.ref);if(r.kind!=='answer'&&!['eq','ne','known'].includes(r.op))error('invalid_selection_rule',r.ref);if(owner&&r.kind==='component')edges.get(owner).add(r.ref);}};
 for(const q of c.questions)check(q.required_when);
 for(const v of c.components){if(v.quantity_fact&&!questions.has(v.quantity_fact))error('unknown_quantity_source',v.name);if(v.quantity_fact){const q=c.questions.find(q=>q.id===v.quantity_fact);if(q.type!=='number')error('numeric_quantity_source_required',v.name);if(q.unit)convertQuantity(1,q.unit,v.unit);}if(v.min_quantity!==null&&v.max_quantity!==null&&Number(v.min_quantity)>Number(v.max_quantity))error('invalid_limits',v.name);for(const s of v.service_ids)if(!services.has(s))error('missing_service_policy',s);check(v.disabled_when,v.id);check(v.required_when,v.id);for(const r of v.adjustments)check(r.when,v.id);if(v.disabled_when.length&&v.required_when.length&&possible([...v.disabled_when,...v.required_when]))error('contradictory_rules',v.name);}
 const visited=new Set(),active=new Set();function visit(key){if(active.has(key))error('circular_component_rules',key);if(visited.has(key))return;active.add(key);for(const next of edges.get(key))visit(next);active.delete(key);visited.add(key);}for(const k of components)visit(k);
 return c;
}
const rational=v=>{const s=String(v);if(!/^\d{1,9}(\.\d{1,6})?$/.test(s))error('invalid_quantity','Use a nonnegative quantity with up to six decimals.');const [a,b='']=s.split('.');return [BigInt(a+b),10n**BigInt(b.length)];};
const factors={count:['count',1n,1n],second:['time',1n,1n],minute:['time',60n,1n],hour:['time',3600n,1n],inch:['length',127n,5000n],foot:['length',381n,1250n],yard:['length',1143n,1250n],mm:['length',1n,1000n],cm:['length',1n,100n],m:['length',1n,1n],sq_in:['area',16129n,25000000n],sq_ft:['area',145161n,1562500n],sq_cm:['area',1n,10000n],sq_m:['area',1n,1n]};
export function convertQuantity(value,from,to){let [n,d]=rational(value);const a=factors[from]||[from,1n,1n],b=factors[to]||[to,1n,1n];if(a[0]!==b[0])error('incompatible_units',`Cannot convert ${from} to ${to}.`);return [n*a[1]*b[2],d*a[2]*b[1]];}
const rounded=(n,d=1n)=>{const v=(n*2n+d)/(2n*d);if(v>2000000000n)error('calculation_limit','Calculated value exceeds the supported limit.');return Number(v);};
const mul=(a,b)=>rounded(BigInt(a)*BigInt(b),10000n);
function matches(rules,answers,selected,services){if(!rules.length)return false;let unknown=false;for(const r of rules){const value=r.kind==='answer'?answers[r.ref]?.value:r.kind==='component'?selected[r.ref]:services.includes(r.ref);if(r.op==='known'){if(value===undefined||value===null)return false;continue;}if(value===undefined||value===null){unknown=true;continue;}let yes=r.op==='eq'?same(value,r.value):r.op==='ne'?!same(value,r.value):typeof value==='number'&&typeof r.value==='number'&&(r.op==='gte'?value>=r.value:value<=r.value);if(!yes)return false;}return unknown?null:true;}
export const calculationOrder=['Convert quantity and apply minimum quantity','Base plus per-unit charges/time','Conditional additions, then multipliers in configured order','Line minimum','Service minimum','Quote minimum','Existing quote tax, discount and deposit'];
export function calculate({catalog,services,input,manual=null,previous=null}){
 const c=validateCatalog(catalog),i=inputSchema.parse(input);if(manual)manual=overrideSchema.parse(manual);
 if(new Set(i.service_ids).size!==i.service_ids.length)error('duplicate_service','Select each service once.');
 i.service_ids.sort();
 const serviceMap=new Map(services.map(s=>[s.id,s])),policies=new Map(c.services.map(s=>[s.service_id,s])),missing=[],changes=[],applied=[],lines=[],selected={},used=new Set();
 const issue=(key,label,kind='input')=>{if(!missing.some(x=>x.key===key&&x.kind===kind))missing.push({key,label,kind});};
 for(const [key,a]of Object.entries(i.answers)){const q=c.questions.find(q=>q.id===key);if(!q)error('unknown_answer',key);if(a.value===null)continue;if(q.type==='number'&&(typeof a.value!=='number'||!Number.isFinite(a.value)||q.min!==null&&a.value<Number(q.min)||q.max!==null&&a.value>Number(q.max))||q.type==='boolean'&&typeof a.value!=='boolean'||q.type==='choice'&&!q.choices.includes(a.value)||q.type==='text'&&typeof a.value!=='string')error('invalid_answer',q.label);if(a.source==='inferred')issue(key,`${q.label}: confirmation required`);}
 const relevant=c.components.filter(v=>v.service_ids.some(s=>i.service_ids.includes(s))).sort((a,b)=>a.order-b.order||a.id.localeCompare(b.id));
 // Resolve selection dependencies before arithmetic; no charge survives a disabled rule.
 const resolving=new Set();function resolve(v){if(Object.hasOwn(selected,v.id))return selected[v.id];resolving.add(v.id);for(const r of [...v.disabled_when,...v.required_when])if(r.kind==='component'){const dep=relevant.find(x=>x.id===r.ref);if(dep&&!resolving.has(dep.id))resolve(dep);}
 const disabled=matches(v.disabled_when,i.answers,selected,i.service_ids),required=matches(v.required_when,i.answers,selected,i.service_ids),keys=v.scope==='visit'?[v.id]:i.service_ids.filter(s=>v.service_ids.includes(s)).map(s=>s+':'+v.id);
 if(disabled===null||required===null)issue(v.id,`${v.name}: answer the selection rule questions`);
 const wanted=keys.some(k=>i.components[k]?.selected??v.selection!=='optional');selected[v.id]=disabled===true?false:required===true||v.selection==='required'||wanted;resolving.delete(v.id);
 if(disabled===true&&required===true)issue(v.id,`${v.name}: conflicting required/disabled rules`,'configuration');return selected[v.id];}
 relevant.forEach(resolve);
 for(const q of c.questions.filter(q=>q.service_ids.some(s=>i.service_ids.includes(s)))){const need=q.required||matches(q.required_when,i.answers,selected,i.service_ids);if(need!==false&&(i.answers[q.id]?.value===null||i.answers[q.id]?.value===undefined||i.answers[q.id]?.value===''))issue(q.id,q.label);}
 for(const serviceID of i.service_ids){const svc=serviceMap.get(serviceID);if(!svc)error('service_unavailable','Select an active service in this company.');const policy=policies.get(serviceID);if(!policy)issue(serviceID,`${svc.name}: calculator configuration`,'configuration');
  const serviceLines=[];
  for(const v of relevant.filter(v=>v.service_ids.includes(serviceID))){const key=v.scope==='visit'?v.id:serviceID+':'+v.id;if(used.has(key))continue;used.add(key);
   const state=i.components[key]||{quantity_mode:'linked'},disabled=matches(v.disabled_when,i.answers,selected,i.service_ids),required=v.selection==='required'||matches(v.required_when,i.answers,selected,i.service_ids)===true;
   const enabled=disabled!==true&&(required||(state.selected??v.selection!=='optional'));
   if(!enabled){if(state.selected===true||previous?.lines?.some(l=>l.key===key))changes.push({key,message:`${v.name} removed: ${disabled?'unavailable under current answers':'not selected'}`});continue;}
   if(required&&state.selected===false)changes.push({key,message:`${v.name} selected because it is required`});
   let quantity=state.quantity_mode==='override'?state.quantity:i.answers[v.quantity_fact]?.value??v.default_quantity;
   const sourceUnit=state.quantity_mode==='override'?state.unit||v.unit:i.answers[v.quantity_fact]?.unit||c.questions.find(q=>q.id===v.quantity_fact)?.unit||v.unit;
   const needsQty=(v.money_enabled&&v.unit_cents!==null)||(v.time_enabled&&v.unit_seconds!==null);let fraction=null;
   if(quantity!==null&&quantity!==undefined){fraction=convertQuantity(quantity,sourceUnit,v.unit);if(!v.decimal_quantity&&fraction[0]%fraction[1]!==0n)error('whole_quantity_required',v.name);if(v.max_quantity!==null&&fraction[0]*rational(v.max_quantity)[1]>rational(v.max_quantity)[0]*fraction[1])error('quantity_limit',v.name);if(v.min_quantity!==null){const [n,d]=rational(v.min_quantity);if(fraction[0]*d<n*fraction[1]){fraction=[n,d];applied.push(`${v.name}: minimum quantity ${v.min_quantity}`);}}}
   if(needsQty&&!fraction)issue(key,`${v.name}: quantity`);
   if(v.money_enabled&&v.fixed_cents===null&&v.unit_cents===null)issue(key,`${v.name}: price rates`,'configuration');
   if(v.time_enabled&&v.fixed_seconds===null&&v.unit_seconds===null)issue(key,`${v.name}: time rates`,'configuration');
   let money=(v.fixed_cents||0)+(fraction&&v.unit_cents!==null?rounded(fraction[0]*BigInt(v.unit_cents),fraction[1]):0),time=(v.fixed_seconds||0)+(fraction&&v.unit_seconds!==null?rounded(fraction[0]*BigInt(v.unit_seconds),fraction[1]):0);
   for(const rule of v.adjustments){const hit=matches(rule.when,i.answers,selected,i.service_ids);if(hit===null)issue(rule.id,`${rule.label}: required answers`);if(hit){money+=rule.add_cents||0;time+=rule.add_seconds||0;if(rule.money_factor_bp!==null)money=mul(money,rule.money_factor_bp);if(rule.time_factor_bp!==null)time=mul(time,rule.time_factor_bp);applied.push(rule.label);}}
   const minimumAdjustment=v.money_enabled?Math.max(0,(v.minimum_cents||0)-money):0;money=v.money_enabled?money+minimumAdjustment:0;time=v.time_enabled?time:0;
   const line={key,component_id:v.id,service_id:serviceID,name:v.name,description:v.description,quantity:fraction?Number(fraction[0])/Number(fraction[1]):null,unit:v.unit,quantity_mode:state.quantity_mode,visible:v.visible,show_price:v.show_price,scope:v.scope,cents:money,labor_seconds:time,minimum_adjustment_cents:minimumAdjustment};lines.push(line);serviceLines.push(line);
  }
  if(!relevant.some(v=>v.service_ids.includes(serviceID)))issue(serviceID,`${svc.name}: configure components`,'configuration');
 }
 for(const key of Object.keys(i.components))if(!used.has(key))changes.push({key,message:'Selection does not belong to the current service scope and is not charged'});
 const groups=i.service_ids.map(serviceID=>{const svc=serviceMap.get(serviceID),policy=policies.get(serviceID),rows=lines.filter(l=>l.service_id===serviceID),base=rows.reduce((n,l)=>n+l.cents,0),minimum=Math.max(0,(policy?.minimum_cents||0)-base),labor=rows.reduce((n,l)=>n+l.labor_seconds,0);return {service_id:serviceID,name:svc.name,description:svc.default_description||'',cents:manual?.service_cents[serviceID]??base+minimum,labor_seconds:labor,elapsed_seconds:policy?.crew_size&&policy?.elapsed_ratio_bp?mul(labor,policy.elapsed_ratio_bp):null,crew_size:policy?.crew_size||null,minimum_adjustment_cents:minimum};});
 if(manual)for(const k of Object.keys(manual.service_cents))if(!i.service_ids.includes(k))error('override_service_unselected',k);
 const subtotal=groups.reduce((n,l)=>n+l.cents,0),quoteAdjustment=Math.max(0,(c.quote_minimum_cents||0)-subtotal);if(groups.length)groups[0].cents+=quoteAdjustment;
 if(!i.service_ids.length)issue('services','Choose services');
 for(const g of groups)if(g.elapsed_seconds===null)issue(g.service_id,`${g.name}: crew size and elapsed-time ratio`,'staffing');
 if(new Set(groups.map(g=>g.crew_size).filter(Boolean)).size>1)issue('crew','Selected services need one compatible configured crew size','staffing');
 if(groups.length&&groups.every(g=>g.labor_seconds===0)&&!manual?.elapsed_seconds)issue('duration','Configure positive estimated work time before scheduling','staffing');
 const complete=!missing.some(x=>x.kind!=='staffing'),scheduled=complete&&!missing.length;
 const labor=lines.reduce((n,l)=>n+l.labor_seconds,0),elapsed=manual?.elapsed_seconds??(scheduled?groups.reduce((n,g)=>n+g.elapsed_seconds,0):null);
 const total=subtotal+quoteAdjustment;if(!Number.isSafeInteger(total)||total>2e9)error('calculation_limit','Quote exceeds supported limit.');
 return {currency:'USD',input:i,lines,services:groups,subtotal_cents:total,labor_seconds:labor,elapsed_seconds:elapsed,crew_size:scheduled?groups[0]?.crew_size||null:null,minimum_adjustment_cents:quoteAdjustment,missing,changes,applied_rules:applied,assumptions:manual?[`Human override: ${manual.reason}`]:[],complete_for_presentation:complete,complete_for_scheduling:scheduled&&elapsed>0,order:calculationOrder};
}
