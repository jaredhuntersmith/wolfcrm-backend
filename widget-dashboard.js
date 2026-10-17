import {loadActor, can, conversationJoins, conversationAccessSQL, fail} from './company-comms/access.js';
import {notificationAccessSQL} from './company-comms/notifications.js';
import {taskAccessSQL} from './company-comms/tasks.js';
import {loadProfitAndLoss} from './finance-accounting.js';
import {withFinanceSpace} from './finance-spaces.js';
import {acceptedQuoteValueSQL} from './sales-analytics.js';
import {monthlyPlanRevenueCents} from './service-plan-metrics.js';
import {paymentRecordCollection, stripePaymentMode} from './agreement-payments.js';
import {readCatalogModule} from './widget-dashboard-catalog.js';

// Public keys are stable and shared with DashboardModuleKind in the native client.
const definitions = {
 schedule: ['schedule.view','jobs.view'], next_appointment: ['schedule.view','jobs.view'], jobs_completed: ['schedule.view','jobs.view'],
 revenue: ['schedule.view','jobs.view'], profit: ['finance.view','accounting.view'], expenses: ['finance.view','accounting.view'],
 tasks: ['tasks.view'], due_tasks: ['tasks.view'], customer_tasks: ['tasks.view','contacts.view'], follow_ups: ['tasks.view','contacts.view'],
 notifications: ['notifications.view'], messages: ['messaging.customer.view'], company_comms: ['communications.view'], mentions: ['communications.view'], replies: ['communications.view'],
 leads: ['contacts.view'], quotes: ['quotes.view','contacts.view'], accepted_quotes: ['quotes.view','contacts.view'],
 pipeline: ['pipeline.view','contacts.view'], pipeline_stages: ['pipeline.view','contacts.view'], first_contact: ['contacts.view','sales.view_self'], search_contacts: ['contacts.view'], add_contact: ['contacts.create'], create_quote: ['quotes.create','contacts.view'],
 add_task: ['tasks.manage'], schedule_appointment: ['schedule.create','jobs.view'],
 open_messages: ['messaging.customer.view'], open_comms: ['communications.view'],
 payments: ['payments.view'], invoices: ['payments.view','quotes.view'], deposits: ['payments.view','quotes.view'], booked_sales: ['sales.view_self','quotes.view','contacts.view'],
 plans: ['payments.view','contacts.view'], goals: ['finance.view'], weather: ['schedule.view','jobs.view','contacts.view'], crew: ['schedule.view','jobs.view'],
 unscheduled_jobs: ['jobs.view'], quote_visits: ['schedule.view'], service_jobs: ['schedule.view'],
 directions: ['schedule.view','jobs.view'], activity: ['dashboard.exceptions.view'], agreements: ['quotes.view','contacts.view'], time_clock: ['time.view_self'], log_expense: ['finance.view','finance.manage']
};
const unsupported = {
 unscheduled_jobs: 'The current schedule requires start/end times; there is no canonical unscheduled-job queue.',
 quote_visits: 'Legacy schedule records do not have a reliable quote-visit versus service-job discriminator.',
 service_jobs: 'Legacy schedule records do not have a reliable quote-visit versus service-job discriminator.',
};
const financial = new Set(['revenue','profit','expenses','payments','invoices','deposits','goals','log_expense','activity']);
const scheduleKinds = new Set(['schedule','next_appointment','jobs_completed','revenue','directions','crew','weather']);
const personKinds = new Set([...scheduleKinds,'leads','quotes','accepted_quotes','pipeline','booked_sales','first_contact','pipeline_stages']);
const periodKinds = new Set([...scheduleKinds,'profit','expenses','payments','leads','booked_sales','first_contact']);
export const BADGE_KINDS = ['notifications','messages','company_comms','mentions','replies','due_tasks','follow_ups','leads','quotes','accepted_quotes','first_contact','invoices','deposits','agreements','activity'];

export function validateWidgetSlots(body) {
 if (!body || !Array.isArray(body.slots) || !body.slots.length || body.slots.length > 8) fail(400,'invalid_widget_slots');
 const seen = new Set();
 return body.slots.map(slot => {
  if (!slot || typeof slot.id !== 'string' || !/^[A-Za-z0-9_-]{1,80}$/.test(slot.id) || seen.has(slot.id) || !definitions[slot.kind]) fail(400,'invalid_widget_slot');
  seen.add(slot.id);
  const f = slot.filters || {};
  if (!f || typeof f !== 'object' || Array.isArray(f) || Object.keys(f).some(k=>!['person','service','pipeline','stage','period','start','end','financeSpace','goal'].includes(k))) fail(400,'invalid_widget_filter');
  for (const [k,v] of Object.entries(f)) if (v != null && (typeof v !== 'string' || v.length > 160)) fail(400,'invalid_widget_filter');
  const filters = Object.fromEntries(Object.entries(f).filter(([,v])=>v != null && v !== ''));
  if (filters.person && !['me','all'].includes(filters.person) && !/^[0-9a-f-]{36}$/i.test(filters.person)) fail(400,'invalid_widget_person');
  if (filters.person && !personKinds.has(slot.kind)) fail(400,'unsupported_widget_filter');
  if (filters.service && !scheduleKinds.has(slot.kind)) fail(400,'unsupported_widget_filter');
  if ((filters.pipeline || filters.stage) && !['leads','pipeline','first_contact','pipeline_stages'].includes(slot.kind)) fail(400,'unsupported_widget_filter');
  if (filters.financeSpace && !['profit','expenses','goals','log_expense'].includes(slot.kind)) fail(400,'unsupported_widget_filter');
  if (filters.goal && slot.kind!=='goals')fail(400,'unsupported_widget_filter');
  if (filters.period && (!periodKinds.has(slot.kind) || !['today','week','month','custom'].includes(filters.period))) fail(400,'unsupported_widget_period');
  if (filters.start || filters.end || filters.period === 'custom') {
   if (filters.period !== 'custom' || !/^\d{4}-\d{2}-\d{2}$/.test(filters.start || '') || !/^\d{4}-\d{2}-\d{2}$/.test(filters.end || '') || filters.start > filters.end || (Date.parse(filters.end)-Date.parse(filters.start))/86400000 > 366) fail(400,'invalid_widget_dates');
   for (const v of [filters.start,filters.end]) if (!Number.isFinite(Date.parse(v)) || new Date(v).toISOString().slice(0,10)!==v) fail(400,'invalid_widget_dates');
  }
  const offset = slot.offset ?? 0;
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > 1000000) fail(400,'invalid_widget_page');
  if(slot.recordID!=null && (typeof slot.recordID!=='string'||!slot.recordID.length||slot.recordID.length>160))fail(400,'invalid_widget_record');
  return {id:slot.id,kind:slot.kind,filters,offset,recordID:slot.recordID||null};
 });
}

// PostgreSQL owns local-day arithmetic, including 23/25-hour days. End is exclusive.
export async function widgetDateRange(db, companyId, filters = {}, now = new Date()) {
 const {rows} = await db.query(`WITH zone AS (
  SELECT COALESCE(NULLIF(timezone,''),'America/New_York') AS tz FROM companies WHERE id=$1
 ), day AS (SELECT tz,($2::timestamptz AT TIME ZONE tz)::date AS today FROM zone), dates AS (
  SELECT tz,today,CASE $3 WHEN 'week' THEN date_trunc('week',today)::date WHEN 'month' THEN date_trunc('month',today)::date WHEN 'custom' THEN $4::date ELSE today END AS first,
   CASE $3 WHEN 'week' THEN date_trunc('week',today)::date+7 WHEN 'month' THEN (date_trunc('month',today)+interval '1 month')::date WHEN 'custom' THEN $5::date+1 ELSE today+1 END AS last FROM day
 ) SELECT tz AS timezone,first::text AS start_date,(last-1)::text AS end_date,
  first::timestamp AT TIME ZONE tz AS start_at,last::timestamp AT TIME ZONE tz AS end_at,
  (today+1)::timestamp AT TIME ZONE tz AS midnight FROM dates`,[companyId,now,filters.period || 'today',filters.start || null,filters.end || null]);
 if (!rows[0]) fail(403,'account_unavailable');
 return rows[0];
}

// One exact query reused by widgets and the Comms tab; no conversation-page limit.
export async function commsUnreadSummary(db, actor, mentionsOnly = false, offset = 0, recordID = null, repliesOnly = false) {
 const predicate = `${conversationAccessSQL(actor)} AND m.sender_id<>$1 AND m.deleted_at IS NULL
  AND m.created_at>=COALESCE(cp.history_from,'-infinity') AND m.created_at>COALESCE(cp.last_read_at,'-infinity')
  ${mentionsOnly ? 'AND EXISTS(SELECT 1 FROM comms_mentions mm WHERE mm.message_id=m.id AND mm.user_id=$1)' : ''}
  ${repliesOnly ? "AND EXISTS(SELECT 1 FROM messages root WHERE root.id=m.reply_root_id AND root.sender_id=$1 AND root.company_id=$2 AND root.deleted_at IS NULL AND root.created_at>=COALESCE(cp.history_from,'-infinity') AND (root.conversation_id=c.id OR root.channel_id=t.legacy_channel_id))" : ''}`;
 return aggregate(db,`SELECT m.id,COALESCE(t.name,c.title,'Company Comms') AS title,left(m.body,160) AS subtitle,m.created_at AS date,
  'comms' AS destination,c.id AS reference,NULL::bigint AS amount FROM conversations c ${conversationJoins}
  JOIN messages m ON (m.conversation_id=c.id OR m.channel_id=t.legacy_channel_id) WHERE ${predicate}`,[actor.userId,actor.companyId],offset,recordID);
}

async function aggregate(db, sql, values, offset=0, recordID=null) {
 const result=(await db.query(`WITH items AS (${sql}), page AS (
  SELECT * FROM items WHERE ($${values.length+2}::text IS NULL OR id::text=$${values.length+2}) ORDER BY date NULLS LAST,id LIMIT 50 OFFSET $${values.length+1}
 ) SELECT (SELECT count(*)::int FROM items) AS count,(SELECT COALESCE(sum(amount),0)::bigint FROM items) AS amount,
  COALESCE((SELECT jsonb_agg(to_jsonb(page) ORDER BY date NULLS LAST,id) FROM page),'[]'::jsonb) AS rows`,[...values,offset,recordID])).rows[0];
 if(!Number.isSafeInteger(Number(result.amount)))fail(409,'widget_amount_out_of_range');
 return {...result,amount:Number(result.amount),nextOffset:!recordID&&offset+result.rows.length<result.count?offset+result.rows.length:null};
}

export function createWidgetDashboard({pool,env=process.env,services={}}) {
 async function summary(input, body, now = new Date()) {
  const slots=validateWidgetSlots(body),actor=await loadActor(pool,input);
  // The context is an assertion, never a way to select another tenant.
  if (body.userID && body.userID!==actor.userId || body.companyID && body.companyID!==actor.companyId) fail(403,'widget_account_changed');
  const day=await widgetDateRange(pool,actor.companyId,{},now);
  const company=(await pool.query('SELECT name FROM companies WHERE id=$1',[actor.companyId])).rows[0];
  const cache=new Map(),memo=new Map();
  const modules=await Promise.all(slots.map(async slot=>{
   const key=JSON.stringify([slot.kind,slot.filters,slot.offset,slot.recordID]);
   if(!cache.has(key)) cache.set(key,module(actor,slot,now,memo));
   return {id:slot.id,kind:slot.kind,...await cache.get(key)};
  }));
  return {version:1,userID:actor.userId,companyID:actor.companyId,companyName:company?.name || 'WolfCRM',timezone:day.timezone,
   generatedAt:now.toISOString(),expiresAt:new Date(Math.min(new Date(day.midnight).getTime(),now.getTime()+6*3600000)).toISOString(),modules};
 }
 async function module(actor,slot,now,memo) {
  const {kind,filters:f,offset,recordID}=slot;
  const unavailable=reason=>({state:'unavailable',reason,rows:[]});
  if(!definitions[kind].every(key=>can(actor,key)) || financial.has(kind)&&!actor.isCompanyOwner) return unavailable('Your role does not allow this module.');
  if(unsupported[kind])return unavailable(unsupported[kind]);
  try {
   const range=await widgetDateRange(pool,actor.companyId,f,now);
   const resultBase={state:'ready',startDate:range.start_date,endDate:range.end_date,rows:[]};
   let person=f.person === 'all' ? null : f.person && f.person !== 'me' ? f.person : f.person === 'me' || !actor.isCompanyOwner ? actor.userId : null;
   // Team filtering never widens existing non-owner schedule/contact scope.
   if(!actor.isCompanyOwner && person!==actor.userId) return unavailable('Only your own work is available for this module.');
   if(person && !(await pool.query('SELECT 1 FROM users WHERE id=$1 AND company_id=$2 AND deleted_at IS NULL',[person,actor.companyId])).rowCount) return unavailable('This team member is no longer available.');
   const catalog=await readCatalogModule({pool,actor,slot,range,now,person,aggregate,services,memo});
   if(catalog)return catalog;
   if(scheduleKinds.has(kind)) {
    const values=[actor.companyId,person,range.start_at,range.end_at,f.service || null];
    const showContacts=can(actor,'contacts.view');
    const source=`FROM schedule_events se LEFT JOIN contacts c ON c.id::text=se.contact_id AND c.company_id=se.company_id AND c.deleted_at IS NULL AND ${showContacts}
     WHERE se.company_id=$1 AND ($2::uuid IS NULL OR se.created_by=$2 OR se.sales_user_ids ? $2::text OR se.worker_user_ids ? $2::text)
     AND se.start_at >= $3 AND se.start_at < $4 AND ($5::text IS NULL OR EXISTS(SELECT 1 FROM jsonb_array_elements(se.service_items) si WHERE COALESCE(si->>'service_id',si->>'serviceId',si->>'id')=$5))`;
    const result=await aggregate(pool,`SELECT se.id,COALESCE(c.name,se.title) AS title,
     concat_ws(' · ',to_char(se.start_at AT TIME ZONE '${range.timezone.replaceAll("'","''")}','HH24:MI'),NULLIF(se.title,''),CASE WHEN se.finished_at IS NULL THEN 'Scheduled' ELSE 'Completed' END,
      (SELECT string_agg(u.display_name,', ' ORDER BY u.display_name) FROM users u WHERE u.company_id=se.company_id AND se.worker_user_ids ? u.id::text)) AS subtitle,
     se.start_at AS date,'schedule' AS destination,se.id AS reference,se.price_cents::bigint AS amount ${source}
     ${kind==='next_appointment'||kind==='directions'?'AND se.finished_at IS NULL AND se.start_at>= $6':''}`,
     kind==='next_appointment'||kind==='directions'?[...values,now]:values,offset,recordID);
    if(kind==='revenue')return {...resultBase,...result,value:money(result.amount,'USD'),note:'Estimated scheduled value; not collected payments. Missing prices excluded.'};
    if(kind==='jobs_completed') {
     const completed=(await pool.query(`SELECT count(*)::int AS count ${source} AND se.finished_at IS NOT NULL`,values)).rows[0].count;
     return {...resultBase,...result,value:`${completed} / ${result.count}`,note:'Completed / scheduled'};
    }
    if(kind==='next_appointment'||kind==='directions') {
     const next=result.rows[0];
     return {...resultBase,...result,value:next?new Intl.DateTimeFormat('en-US',{timeZone:range.timezone,hour:'numeric',minute:'2-digit'}).format(new Date(next.date)):'None',note:next?.title||'No upcoming appointments in this period',rows:result.rows.slice(0,1),nextOffset:null,nextTransitionAt:next?.date||null};
    }
    return {...resultBase,...result,value:String(result.count),...(kind==='crew'?{note:'Scheduled jobs and their assigned crew; not a measure of availability.'}:{})};
   }
   if(['profit','expenses'].includes(kind)) {
    if(!f.financeSpace) return unavailable('Choose an authorized Finance Space in this module’s settings.');
    const report=await withFinanceSpace(pool,actor.userId,actor.companyId,f.financeSpace,db=>loadProfitAndLoss(db,actor.companyId,{start_date:range.start_date,end_date:range.end_date}));
    const lines=kind==='expenses'?report.expenses.lines:[...report.income.lines,...report.expenses.lines.map(x=>({...x,amount_cents:-x.amount_cents}))];
    return {...resultBase,value:money(kind==='profit'?report.net_income_cents:report.expenses.total_cents,report.currency),
     note:`Cash P&L · ${report.classification_coverage_percent}% classified · incomplete as job profit`,
     reason:report.warnings.join(' '),count:lines.length,rows:lines.slice(offset,offset+50).map(l=>({id:l.chart_account_id,title:l.name,subtitle:money(l.amount_cents,report.currency),destination:'finance',reference:f.financeSpace,amount:l.amount_cents})),
     nextOffset:offset+50<lines.length?offset+50:null};
   }
   let result;
   if(kind==='tasks'||kind==='due_tasks'||kind==='customer_tasks') {
    // Personal is always current user; never infer private task ownership from company membership.
    const schema=(await pool.query("SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='todo_tasks' AND column_name='company_id') AS ready")).rows[0];
    if(!schema.ready)return unavailable('Task widgets are not available yet. You can still use your To-do list in WolfCRM.');
    result=await aggregate(pool,`SELECT t.id,t.title,t.priority AS subtitle,t.due_date AS date,'task' AS destination,t.id AS reference,NULL::bigint AS amount
     FROM todo_tasks t
     WHERE t.company_id=$2 AND (t.user_id=$1 OR t.assignee_ids ? $1::text) AND NOT t.completed AND ${taskAccessSQL(actor,'t','$1','$2')}
     ${kind==='customer_tasks'?"AND EXISTS(SELECT 1 FROM contacts c WHERE c.id::text=to_jsonb(t)->>'linked_contact_id' AND c.company_id=$2 AND c.deleted_at IS NULL)":''}
     ${kind==='due_tasks'?'AND t.due_date < $3':'AND ($3::timestamptz IS NOT NULL)'}`,[actor.userId,actor.companyId,range.end_at],offset,recordID);
    result.note='Personal and assigned tasks; legacy tasks without verified company ownership are excluded.';
   } else if(kind==='follow_ups') {
    result=await aggregate(pool,`SELECT r.id,r.title,r.contact_name AS subtitle,r.due_date AS date,'reminder' AS destination,r.id AS reference,NULL::bigint AS amount
     FROM todo_customer_reminders r JOIN contacts c ON c.id::text=r.contact_id AND c.company_id=$2 AND c.deleted_at IS NULL
     WHERE r.user_id=$1 AND NOT r.completed AND r.due_date < $3`,[actor.userId,actor.companyId,range.end_at],offset,recordID);
   } else if(kind==='notifications') {
    result=await aggregate(pool,`SELECT n.id,n.title,left(n.body,160) AS subtitle,n.created_at AS date,'notification' AS destination,n.id AS reference,NULL::bigint AS amount
     FROM notifications n WHERE n.user_id=$1 AND n.company_id=$2 AND n.deleted_at IS NULL AND n.read_at IS NULL AND ${notificationAccessSQL(actor)}`,[actor.userId,actor.companyId],offset,recordID);
   } else if(kind==='company_comms'||kind==='mentions'||kind==='replies') {
    result=await commsUnreadSummary(pool,actor,kind==='mentions',offset,recordID,kind==='replies');
   } else if(kind==='messages') {
    result=await aggregate(pool,`SELECT sm.id::text, 'Customer message'::text AS title,left(sm.body,160) AS subtitle,sm.created_at AS date,'sms' AS destination,sc.id::text AS reference,NULL::bigint AS amount
     FROM sms_messages sm JOIN sms_conversations sc ON sc.id=sm.conversation_id JOIN phone_lines pl ON pl.id=sc.phone_line_id
     WHERE pl.company_id=$1 AND sc.deleted_at IS NULL AND sm.deleted_at IS NULL AND sm.direction='inbound' AND sm.created_at>COALESCE(sc.last_read_at,'epoch')
     UNION ALL SELECT im.id::text,'Customer message',left(im.body,160),COALESCE(im.provider_created_at,im.created_at),'imessage',ic.id::text,NULL::bigint
     FROM imessage_messages im JOIN imessage_conversations ic ON ic.id=im.conversation_id
     WHERE ic.company_id=$1 AND ic.deleted_at IS NULL AND im.deleted_at IS NULL AND im.direction='inbound' AND COALESCE(im.provider_created_at,im.created_at)>COALESCE(ic.last_read_at,'epoch')`,[actor.companyId],offset,recordID);
   } else if(kind==='leads'||kind==='pipeline') {
    result=await aggregate(pool,`SELECT c.id::text,c.name AS title,c.job_type AS subtitle,c.lead_submitted_at AS date,'contact' AS destination,c.id::text AS reference,NULL::bigint AS amount
     FROM contacts c WHERE c.company_id=$1 AND c.deleted_at IS NULL AND ($2::uuid IS NULL OR c.user_id=$2)
     AND ($3::text IS NULL OR EXISTS(SELECT 1 FROM opportunities o WHERE o.company_id=$1 AND o.contact_id=c.id::text AND o.pipeline_id=$3 AND ($4::text IS NULL OR o.stage_id=$4)))
     AND ($4::text IS NULL OR EXISTS(SELECT 1 FROM opportunities o WHERE o.company_id=$1 AND o.contact_id=c.id::text AND o.stage_id=$4))
     AND ${kind==='leads'?'c.lead_submitted_at >= $5 AND c.lead_submitted_at < $6':'($5::timestamptz IS NOT NULL AND $6::timestamptz IS NOT NULL)'}`,[actor.companyId,person,f.pipeline||null,f.stage||null,range.start_at,range.end_at],offset,recordID);
   } else if(kind==='payments') {
    const records=(await pool.query(`SELECT p.*,c.name AS contact_name FROM payment_records p LEFT JOIN contacts c ON c.id=p.contact_id AND c.company_id=$1 AND c.deleted_at IS NULL
     WHERE p.company_id=$1 AND p.paid_at >= $2 AND p.paid_at < $3 AND p.status IN ('succeeded','paid','partially_refunded','refunded','disputed') ORDER BY p.paid_at,p.id`,[actor.companyId,range.start_at,range.end_at])).rows;
    let mode=null;try{mode=stripePaymentMode(env);}catch{/* Unknown provider mode must remain unavailable. */}
    const collections=records.map(p=>({record:p,...paymentRecordCollection(p,mode)}));
    if(collections.some(p=>!p.included))return unavailable('Some payments cannot be verified in the configured Stripe environment. Review Payments before using this total.');
    const currencies=[...new Set(records.map(p=>(p.currency||'usd').toUpperCase()))];
    if(currencies.length>1)return unavailable('This period has multiple currencies. Open Payments to review each currency separately.');
    const currency=currencies[0]||'USD',gross=collections.reduce((sum,p)=>sum+p.gross,0),refunds=collections.reduce((sum,p)=>sum+p.refunds,0);
    if(!Number.isSafeInteger(gross)||!Number.isSafeInteger(refunds))fail(409,'widget_amount_out_of_range');
    const undated=(await pool.query("SELECT count(*)::int AS count FROM payment_records WHERE company_id=$1 AND paid_at IS NULL AND status IN ('succeeded','paid','partially_refunded','refunded','disputed')",[actor.companyId])).rows[0].count;
    const note=`Gross collected · ${money(refunds,currency)} refunded against these payments (all dates)${undated?' · '+undated+' undated legacy records excluded':''}${collections.some(p=>p.review)?' · review refunds/disputes':''}`;
    return {...resultBase,value:money(gross,currency),count:records.length,note,
     rows:records.filter(p=>!recordID||String(p.id)===recordID).slice(offset,offset+50).map(p=>({id:String(p.id),title:p.contact_name||p.description||'Collected payment',subtitle:money(Number(p.amount_cents),p.currency||'usd'),date:p.paid_at,destination:p.contact_id?'contact':'payment',reference:p.contact_id?String(p.contact_id):null,amount:Number(p.amount_cents)})),nextOffset:!recordID&&offset+50<records.length?offset+50:null};
   } else if(kind==='plans') {
    const plans=(await pool.query(`SELECT sp.*,c.name AS contact_name FROM service_plans sp LEFT JOIN contacts c ON c.id=sp.contact_id AND c.company_id=$1 AND c.deleted_at IS NULL
     WHERE (sp.company_id=$1 OR sp.company_id IS NULL AND sp.user_id=(SELECT owner_user_id FROM companies WHERE id=$1)) AND sp.status='active' ORDER BY sp.id`,[actor.companyId])).rows;
    const mrr=Math.round(plans.reduce((sum,p)=>sum+monthlyPlanRevenueCents(p),0));
    if(!Number.isSafeInteger(mrr))fail(409,'widget_amount_out_of_range');
    const rows=plans.filter(p=>!recordID||String(p.id)===recordID).slice(offset,offset+50).map(p=>({id:String(p.id),title:p.plan_name,subtitle:p.contact_name,destination:'contact',reference:String(p.contact_id)}));
    return {...resultBase,count:plans.length,value:String(plans.length),note:`${money(mrr,'usd')} monthly equivalent · not collections`,rows,nextOffset:!recordID&&offset+50<plans.length?offset+50:null};
   } else if(kind==='booked_sales') {
    result=await aggregate(pool,`SELECT q.id::text,COALESCE(q.title,c.name,'Accepted quote') AS title,c.name AS subtitle,q.accepted_at AS date,'contact' AS destination,q.contact_id AS reference,${acceptedQuoteValueSQL()} AS amount
     FROM quotes q LEFT JOIN contacts c ON c.id::text=q.contact_id AND c.company_id=$1 AND c.deleted_at IS NULL
     WHERE (q.company_id=$1 OR q.company_id IS NULL AND EXISTS(SELECT 1 FROM users u WHERE u.id=q.user_id AND u.company_id=$1))
     AND ($2::uuid IS NULL OR q.user_id=$2) AND q.accepted_at >= $3 AND q.accepted_at < $4`,[actor.companyId,person,range.start_at,range.end_at],offset,recordID);
    return {...resultBase,...result,value:money(result.amount,'usd'),note:'Accepted quote value at acceptance · not collections'};
   } else if(kind==='quotes'||kind==='accepted_quotes') {
    result=await aggregate(pool,`SELECT q.id::text,COALESCE(q.title,c.name,'Quote') AS title,c.name AS subtitle,q.created_at AS date,'contact' AS destination,q.contact_id AS reference,q.total_cents::bigint AS amount
     FROM quotes q JOIN contacts c ON c.id::text=q.contact_id AND c.company_id=$1 AND c.deleted_at IS NULL
     WHERE q.company_id=$1 AND q.deleted_at IS NULL AND ($2::uuid IS NULL OR q.user_id=$2)
     AND ${kind==='quotes'?"q.status='sent' AND (q.expires_at IS NULL OR q.expires_at>$3)":"q.status='accepted' AND q.converted_job_id IS NULL AND $3::timestamptz IS NOT NULL"}`,[actor.companyId,person,now],offset,recordID);
   } else return {...resultBase,value:'Open',note:'Continue in WolfCRM'};
   return {...resultBase,...result,value:String(result.count),badge:BADGE_KINDS.includes(kind)?result.count:null};
  } catch(error) {
   // Isolate unavailable sources without falsifying a zero. Never expose SQL or secrets.
   if([403,404].includes(error.status))return unavailable('This source is no longer accessible.');
   console.warn('[widget-dashboard] source unavailable',{kind,code:error.code||'internal'});
   return {state:'error',reason:'Could not refresh this module. Open WolfCRM and retry.',rows:[]};
  }
 }
 return {summary};
}
function money(cents,currency){return new Intl.NumberFormat('en-US',{style:'currency',currency:currency.toUpperCase(),maximumFractionDigits:2}).format(cents/100);}

export function installWidgetDashboard({app,pool,authRequired,services={}}) {
 const service=createWidgetDashboard({pool,services});
 app.get('/api/widget-dashboard/options',authRequired,async(req,res)=>{
  res.set('Cache-Control','private, no-store');
  try {
   const actor=await loadActor(pool,req),company=[actor.companyId];
   const options={people:[],services:[],pipelines:[],stages:[],spaces:[],goals:[]};
   if(actor.isCompanyOwner) options.people=(await pool.query("SELECT id::text,COALESCE(NULLIF(display_name,''),'Team member') AS name FROM users WHERE company_id=$1 AND deleted_at IS NULL ORDER BY name,id",company)).rows;
   if(can(actor,'schedule.view'))options.services=(await pool.query('SELECT id::text,name FROM saved_services WHERE company_id=$1 AND archived_at IS NULL ORDER BY name,id',company)).rows;
   if(can(actor,'pipeline.view')) {
    options.pipelines=(await pool.query('SELECT id,name FROM pipelines WHERE company_id=$1 ORDER BY name,id',company)).rows;
    options.stages=(await pool.query('SELECT s.id,concat_ws(\' · \',p.name,s.name) AS name FROM stages s JOIN pipelines p ON p.id=s.pipeline_id AND p.company_id=s.company_id WHERE s.company_id=$1 ORDER BY p.name,s.order_idx,s.id',company)).rows;
   }
   if(actor.isCompanyOwner&&can(actor,'finance.view'))options.spaces=(await pool.query(`SELECT id::text,name FROM finance_spaces s WHERE company_id=$1 AND (owner_id=$2 OR audience='company' OR audience='selected' AND EXISTS(SELECT 1 FROM finance_space_members m WHERE m.space_id=s.id AND m.user_id=$2)) ORDER BY name,id`,[actor.companyId,actor.userId])).rows;
   if(req.query.financeSpace&&actor.isCompanyOwner&&can(actor,'finance.view'))options.goals=await withFinanceSpace(pool,actor.userId,actor.companyId,String(req.query.financeSpace),async db=>(await db.query("SELECT id::text,name FROM finance_goals WHERE company_id=$1 AND archived_at IS NULL AND status='active' ORDER BY name,id",company)).rows);
   res.json(options);
  }catch(error){res.status(error.status||500).json({error:error.status?error.code:'widget_options_failed'});}
 });
 app.post('/api/widget-dashboard/summary',authRequired,async(req,res)=>{
  res.set('Cache-Control','private, no-store');
  try {res.json(await service.summary(req,req.body));}
  catch(error){res.status(error.status||500).json({error:error.status?error.code:'widget_summary_failed'});}
 });
 app.get('/api/comms/unread-summary',authRequired,async(req,res)=>{
  res.set('Cache-Control','private, no-store');
  try {const actor=await loadActor(pool,req);if(!can(actor,'communications.view'))fail(403,'permission_denied');const result=await commsUnreadSummary(pool,actor);res.json({count:result.count});}
  catch(error){res.status(error.status||500).json({error:error.status?error.code:'unread_summary_failed'});}
 });
 return service;
}
