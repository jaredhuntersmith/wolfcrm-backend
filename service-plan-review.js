const defaults={include_pending:true,include_past_due:false,include_failed:false,include_ended:false};
export async function installServicePlanReview({app,pool,authRequired,requireCapability}) {
 await pool.query(`CREATE TABLE IF NOT EXISTS service_plan_review_preferences(user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,preferences jsonb NOT NULL DEFAULT '{}'::jsonb,updated_at timestamptz NOT NULL DEFAULT now())`);
 const auth=[authRequired,requireCapability('payments.view')];
 const wrap=fn=>async(req,res)=>{res.set('Cache-Control','private, no-store');try{res.json(await fn(req));}catch(e){res.status(e.status||500).json({error:'plan_review_failed',message:e.status?e.message:'Payment review could not be loaded or saved.'});}};
 const settings=async user=>({...defaults,...(await pool.query('SELECT preferences FROM service_plan_review_preferences WHERE user_id=$1',[user])).rows[0]?.preferences});
 app.put('/api/service-plan-payment-review/settings',...auth,wrap(async req=>{
  const value={};for(const key of Object.keys(defaults)){if(typeof req.body[key]!=='boolean')throw Object.assign(new Error('Choose valid payment review settings.'),{status:400});value[key]=req.body[key];}
  await pool.query('INSERT INTO service_plan_review_preferences(user_id,preferences) VALUES($1,$2) ON CONFLICT(user_id) DO UPDATE SET preferences=$2,updated_at=now()',[req.userId,JSON.stringify(value)]);return value;
 }));
 app.get('/api/service-plan-payment-review',...auth,wrap(async req=>{
  const preferences=await settings(req.userId);
  const items=(await pool.query(`SELECT sp.id::text,sp.id::text AS plan_id,sp.enrollment_id::text,sp.contact_id::text,sp.plan_name AS title,c.name AS contact_name,sp.status,
    coalesce((SELECT sum(p.amount_cents) FROM payment_records p WHERE p.service_plan_id=sp.id AND p.status IN ('pending','failed','processing','action_required')),0)::text AS amount_cents,sp.currency,'plan' AS kind
   FROM service_plans sp LEFT JOIN contacts c ON c.id::text=sp.contact_id::text
   WHERE (sp.company_id=$1 OR (sp.company_id IS NULL AND sp.user_id=$2)) AND (
    ($3 AND sp.status='payment_pending') OR ($4 AND sp.status='past_due') OR ($5 AND sp.status='failed') OR
    ($6 AND sp.status IN ('canceled','expired') AND EXISTS(SELECT 1 FROM payment_records p WHERE p.service_plan_id=sp.id AND p.status IN ('pending','failed','processing','action_required'))))
   ORDER BY sp.created_at DESC`,[req.companyId,req.userId,preferences.include_pending,preferences.include_past_due,preferences.include_failed,preferences.include_ended])).rows;
  if(preferences.include_pending||preferences.include_ended)items.push(...(await pool.query(`SELECT e.id::text,NULL::text AS plan_id,e.id::text AS enrollment_id,e.contact_id::text,e.snapshot#>>'{configuration,name}' AS title,c.name AS contact_name,CASE WHEN e.canceled_at IS NOT NULL THEN 'canceled' ELSE e.state END AS status,
    coalesce((SELECT sum(p.amount_cents) FROM payment_records p WHERE p.enrollment_id=e.id AND p.status IN ('pending','failed','processing','action_required')),0)::text AS amount_cents,'usd' AS currency,'enrollment' AS kind
    FROM agreement_plan_enrollments e LEFT JOIN contacts c ON c.id::text=e.contact_id::text WHERE e.company_id=$1 AND e.service_plan_id IS NULL AND (
     ($2 AND e.canceled_at IS NULL) OR ($3 AND e.canceled_at IS NOT NULL AND EXISTS(SELECT 1 FROM payment_records p WHERE p.enrollment_id=e.id AND p.status IN ('pending','failed','processing','action_required')))) ORDER BY e.created_at DESC`,[req.companyId,preferences.include_pending,preferences.include_ended])).rows);
  if(preferences.include_ended)items.push(...(await pool.query(`SELECT p.id::text,NULL::text AS plan_id,p.enrollment_id::text,p.contact_id::text,coalesce(p.description,'Retained plan payment') AS title,c.name AS contact_name,p.status,p.amount_cents::text,p.currency,'retained_payment' AS kind FROM payment_records p LEFT JOIN contacts c ON c.id::text=p.contact_id::text
   WHERE p.company_id=$1 AND p.service_plan_id IS NULL AND p.enrollment_id IS NULL AND p.payment_type LIKE 'service_plan%' AND p.status IN ('pending','failed','processing','action_required') ORDER BY p.created_at DESC`,[req.companyId])).rows);
  return {preferences,items};
 }));
}
