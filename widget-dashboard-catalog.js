import {can, fail} from './company-comms/access.js';
import {taskAccessSQL} from './company-comms/tasks.js';
import {withFinanceSpace} from './finance-spaces.js';
import {goalMetrics} from './finance-calculations.js';
import {outboundContactActivitySQL} from './sales-analytics.js';

const money=(cents,currency='USD')=>new Intl.NumberFormat('en-US',{style:'currency',currency}).format(cents/100);
const page=(rows,offset,recordID)=>({count:rows.length,rows:rows.filter(r=>!recordID||r.id===recordID).slice(offset,offset+50),nextOffset:!recordID&&offset+50<rows.length?offset+50:null});
const safeSum=values=>{const sum=values.reduce((a,b)=>a+Number(b),0);if(!Number.isSafeInteger(sum))fail(409,'widget_amount_out_of_range');return sum;};

export function agreementAttention(state,payments) {
 const reasons=[];
 if(state.decision==='changes_requested')reasons.push('Changes requested');
 if(state.signing==='required_signers_pending'&&state.can_sign)reasons.push('Signatures pending');
 if(payments?.payment_review_required)reasons.push('Payment review');
 if(state.deposit==='outstanding'&&state.can_checkout)reasons.push('Deposit outstanding');
 if(state.booking==='eligible')reasons.push('Ready to book');
 return reasons;
}

// These are read adapters over established business sources. All writes continue
// in the existing native flows and their canonical APIs.
export async function readCatalogModule({pool,actor,slot,range,now,person,aggregate,services,memo}) {
 const {kind,filters:f,offset,recordID}=slot;
 const base={state:'ready',startDate:range.start_date,endDate:range.end_date,rows:[]};
 const unavailable=reason=>({state:'unavailable',reason,rows:[]});
 if(kind==='first_contact') {
  const result=await aggregate(pool,`WITH activity AS (${outboundContactActivitySQL('$1','$4')})
   SELECT c.id::text,c.name AS title,c.job_type AS subtitle,c.lead_submitted_at AS date,'contact' AS destination,c.id::text AS reference,NULL::bigint AS amount
   FROM contacts c WHERE c.company_id=$1 AND c.deleted_at IS NULL AND ($2::uuid IS NULL OR c.user_id=$2)
   AND c.lead_submitted_at >= $3 AND c.lead_submitted_at < $4
   AND NOT EXISTS(SELECT 1 FROM activity a WHERE a.contact_id=c.id AND a.occurred_at>=c.lead_submitted_at)
   AND ($5::text IS NULL OR EXISTS(SELECT 1 FROM opportunities o WHERE o.company_id=$1 AND o.contact_id=c.id::text AND o.pipeline_id=$5 AND ($6::text IS NULL OR o.stage_id=$6)))
   AND ($6::text IS NULL OR EXISTS(SELECT 1 FROM opportunities o WHERE o.company_id=$1 AND o.contact_id=c.id::text AND o.stage_id=$6))`,[actor.companyId,person,range.start_at,range.end_at,f.pipeline||null,f.stage||null],offset,recordID);
  return {...base,...result,value:String(result.count),badge:result.count,note:'No recorded outbound SMS, iMessage or call attempt since lead receipt in this period.'};
 }
 if(kind==='pipeline_stages') {
  const result=await aggregate(pool,`SELECT s.id,s.name AS title,(count(DISTINCT o.contact_id)::text||' contacts') AS subtitle,NULL::timestamptz AS date,'pipeline_stage' AS destination,s.id AS reference,NULL::bigint AS amount
   FROM stages s JOIN pipelines p ON p.id=s.pipeline_id AND p.company_id=s.company_id
   LEFT JOIN opportunities o ON o.stage_id=s.id AND o.pipeline_id=p.id AND o.company_id=$1
    AND EXISTS(SELECT 1 FROM contacts c WHERE c.id::text=o.contact_id AND c.company_id=$1 AND c.deleted_at IS NULL AND ($2::uuid IS NULL OR c.user_id=$2))
   WHERE s.company_id=$1 AND ($3::text IS NULL OR s.pipeline_id=$3) AND ($4::text IS NULL OR s.id=$4)
   GROUP BY s.id,s.name`,[actor.companyId,person,f.pipeline||null,f.stage||null],offset,recordID);
  return {...base,...result,value:String(result.count),note:'Stages with distinct contact counts; open a stage to see matching contacts.'};
 }
 if(kind==='create_quote') {
  const result=await aggregate(pool,`SELECT id::text,name AS title,address AS subtitle,NULL::timestamptz AS date,'create_quote' AS destination,id::text AS reference,NULL::bigint AS amount
   FROM contacts WHERE company_id=$1 AND deleted_at IS NULL`,[actor.companyId],offset,recordID);
  return {...base,...result,value:'Choose contact',note:'Choose the customer, then create a quote in the existing editor.'};
 }
 if(kind==='time_clock') {
  const rows=(await pool.query("SELECT id::text,start_at,break_started_at FROM time_clock_entries WHERE company_id=$1 AND user_id=$2 AND end_at IS NULL AND manual_status<>'disapproved' ORDER BY start_at DESC,id LIMIT 1",[actor.companyId,actor.userId])).rows;
  const entry=rows[0];
  return {...base,value:entry?(entry.break_started_at?'On break':'Clocked in'):'Clocked out',note:'Open Time Clock to review and change your shift.',rows:entry?[{id:entry.id,title:entry.break_started_at?'Break started':'Shift started',date:entry.break_started_at||entry.start_at,destination:'time_clock',reference:entry.id}]:[]};
 }
 if(kind==='goals') {
  if(!f.financeSpace)return unavailable('Choose a Finance Space in this module’s settings.');
  return withFinanceSpace(pool,actor.userId,actor.companyId,f.financeSpace,async db=>{
   const goals=(await db.query("SELECT * FROM finance_goals WHERE company_id=$1 AND archived_at IS NULL AND status='active' AND ($2::text IS NULL OR id::text=$2) ORDER BY target_date NULLS LAST,id",[actor.companyId,f.goal||null])).rows;
   const target=safeSum(goals.map(g=>g.target_amount_cents)),current=safeSum(goals.map(g=>g.current_amount_cents));
   const rows=goals.map(g=>{const metrics=goalMetrics({targetAmountCents:Number(g.target_amount_cents),currentAmountCents:Number(g.current_amount_cents),targetDate:g.target_date instanceof Date?g.target_date.toISOString().slice(0,10):g.target_date,startDate:range.start_date});return {id:String(g.id),title:g.name,subtitle:`${money(metrics.current_amount_cents)} / ${money(metrics.target_amount_cents)} · ${metrics.progress_percent}%`,destination:'finance_goal',reference:g.id};});
   return {...base,...page(rows,offset,recordID),value:`${money(current)} / ${money(target)}`,note:'Recorded Finance goal contributions; not a sales revenue target.'};
  });
 }
 if(kind==='log_expense') {
  if(!f.financeSpace)return unavailable('Choose the Finance Space where this receipt belongs.');
  await withFinanceSpace(pool,actor.userId,actor.companyId,f.financeSpace,async db=>db.query('SELECT 1'));
  return {...base,value:'Capture receipt',note:'Review the receipt and classification in Finance before posting an expense.'};
 }
 if(['invoices','deposits','agreements'].includes(kind)) {
  const service=services.getAgreementService?.();
  if(!service?.state||!service?.paymentSummary)return unavailable('Agreement summaries are not available yet. Open Agreements in WolfCRM.');
  const key='agreement-actions';
  if(!memo.has(key))memo.set(key,(async()=>{
   const records=(await pool.query(`SELECT a.* FROM quote_agreements a WHERE a.company_id=$1 AND a.revoked_at IS NULL AND a.decision NOT IN ('declined','superseded')
    AND (a.quote_id IS NULL OR NOT EXISTS(SELECT 1 FROM quote_agreements newer WHERE newer.company_id=a.company_id AND newer.quote_id=a.quote_id AND newer.revoked_at IS NULL AND newer.revision>a.revision)) ORDER BY a.created_at,a.id LIMIT 251`,[actor.companyId])).rows;
   if(records.length>250)return null;
   const result=[];
   for(let i=0;i<records.length;i+=5)result.push(...await Promise.all(records.slice(i,i+5).map(async row=>({row,state:await service.state(pool,row),payments:row.snapshot?.pricing?await service.paymentSummary(pool,row):null}))));
   return result;
  })());
  const items=await memo.get(key);
  if(!items)return unavailable('This account has more than 250 active agreements. Open Agreements to filter the full collection.');
  const actionable=items.filter(({state,payments:p})=>kind==='agreements'?agreementAttention(state,p).length:kind==='deposits'?state.can_checkout&&state.deposit==='outstanding'&&p&&!p.processing&&!p.payment_review_required&&p.deposit_due_cents>0:p?.can_pay_balance&&!p.processing&&!p.payment_review_required&&p.balance_cents>0);
  const total=kind==='agreements'?0:safeSum(actionable.map(({payments:p})=>kind==='deposits'?p.deposit_due_cents:p.balance_cents));
  const rows=actionable.map(({row,state,payments:p})=>({id:String(row.id),title:row.title||`Agreement ${row.number}`,subtitle:kind==='agreements'?agreementAttention(state,p).join(' · '):money(kind==='deposits'?p.deposit_due_cents:p.balance_cents),date:row.created_at,destination:'agreement',reference:String(row.id)}));
  return {...base,...page(rows,offset,recordID),badge:rows.length,value:kind==='agreements'?String(rows.length):money(total),note:kind==='invoices'?'Actionable published agreement balances; no invoice due-date aging is available.':kind==='deposits'?'Payable deposits after signatures, adjustments and plan collection rules.':'Agreements awaiting signatures, changes, payment review/deposit or booking.'};
 }
 if(kind==='weather') {
  if(!services.weatherService?.status().configured)return unavailable('Property weather is not configured. Open the appointment for available weather options.');
  const job=(await pool.query(`SELECT se.id,se.start_at,c.name,c.lat,c.lng FROM schedule_events se JOIN contacts c ON c.id::text=se.contact_id AND c.company_id=se.company_id AND c.deleted_at IS NULL
   WHERE se.company_id=$1 AND ($2::uuid IS NULL OR se.created_by=$2 OR se.sales_user_ids ? $2::text OR se.worker_user_ids ? $2::text)
   AND se.finished_at IS NULL AND se.start_at>=GREATEST($3,$5::timestamptz) AND se.start_at<$4
   AND ($6::text IS NULL OR EXISTS(SELECT 1 FROM jsonb_array_elements(se.service_items) si WHERE COALESCE(si->>'service_id',si->>'serviceId',si->>'id')=$6)) ORDER BY se.start_at,se.id LIMIT 1`,[actor.companyId,person,range.start_at,range.end_at,now,f.service||null])).rows[0];
  if(!job)return {...base,value:'No appointment',note:'No upcoming property in this filter.'};
  if(job.lat==null||job.lng==null)return unavailable('The next property needs a verified map location before a forecast can be shown.');
  const forecast=await services.weatherService.lookup({latitude:Number(job.lat),longitude:Number(job.lng),hours:24});
  const hour=forecast.hours.find(h=>new Date(h.start_at)<=new Date(job.start_at)&&new Date(h.end_at)>new Date(job.start_at));
  if(!hour)return unavailable('The next appointment is outside the available forecast.');
  return {...base,value:hour.temperature_f==null?'Forecast':`${Math.round(hour.temperature_f)}°F`,note:[hour.condition_description,hour.precipitation_probability_percent==null?null:`${hour.precipitation_probability_percent}% precipitation`,...(forecast.warnings||[]).map(w=>w.message)].filter(Boolean).join(' · '),nextTransitionAt:new Date(Math.min(new Date(forecast.fetched_at).getTime()+900000,new Date(hour.end_at).getTime())).toISOString(),rows:[{id:job.id,title:job.name,subtitle:hour.condition_description,date:job.start_at,destination:'schedule',reference:job.id}]};
 }
 if(kind==='activity') {
  if(!services.refreshActivity)return unavailable('Activity summaries are not available yet. Open the Command Center.');
  await services.refreshActivity(actor.companyId);
  const source=[];
  if(can(actor,'schedule.view')&&can(actor,'jobs.view'))source.push("x.source_type IN ('scheduled_job','worker_job_pair')");
  if(can(actor,'automations.view'))source.push("x.source_type='automation_dead_letter'");
  if(can(actor,'messaging.customer.view'))source.push("x.source_type IN ('sms_message','sms_delivery_unknown')");
  if(can(actor,'tasks.view'))source.push(`(x.source_type='todo_task' AND EXISTS(SELECT 1 FROM todo_tasks t WHERE t.id=x.source_id AND to_jsonb(t)->>'company_id'=$2::text AND (t.user_id=$1 OR t.assignee_ids ? $1::text) AND ${taskAccessSQL(actor,'t','$1','$2')}))`);
  const result=await aggregate(pool,`SELECT x.id::text,x.title,x.explanation AS subtitle,x.detected_at AS date,'activity' AS destination,x.id::text AS reference,NULL::bigint AS amount
   FROM business_exceptions x WHERE x.company_id=$2 AND x.status='open' AND (${source.length?source.join(' OR '):'false'})`,[actor.userId,actor.companyId],offset,recordID);
  return {...base,...result,value:String(result.count),badge:result.count,note:'Open business exceptions in sources you may access; private tasks remain personal.'};
 }
 return null;
}
