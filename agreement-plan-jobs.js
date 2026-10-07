import { randomUUID } from 'node:crypto';
import { QuoteContractError, calculateQuotePricing, calculatePlanOffer, quoteContentHash } from './quote-contract-domain.js';
import { advancePlanDate } from './agreement-plans-domain.js';

const fail = (code, message) => { throw new QuoteContractError(code, message, 409); };
const scope = lines => lines.map(l => ({ service_id: l.service_id || null, qty: Number(l.qty ?? 1) })).sort((a,b) => String(a.service_id).localeCompare(String(b.service_id)) || a.qty-b.qty);
const normalized = lines => lines.map(l => ({ ...l, price_cents: l.price_cents ?? l.priceCents, qty: l.qty ?? 1, service_id: l.service_id ?? l.serviceID ?? null }));
const automatic = e => e.snapshot.configuration.billing.mode === 'automatic_per_visit';
const fullJobConsent = e => e.snapshot.collection_model === 'contact_completed_job_v1';

export async function installPlanJobSchema(pool) {
  await pool.query(`ALTER TABLE agreement_plan_enrollments ADD COLUMN IF NOT EXISTS cancel_requested_at TIMESTAMPTZ;
  ALTER TABLE agreement_plan_enrollments ADD COLUMN IF NOT EXISTS cancellation_effective_at TIMESTAMPTZ;
  CREATE TABLE IF NOT EXISTS agreement_plan_jobs (
    job_id TEXT PRIMARY KEY, company_id UUID NOT NULL REFERENCES companies(id), contact_id UUID NOT NULL,
    enrollment_id UUID NOT NULL REFERENCES agreement_plan_enrollments(id),
    visit_id UUID REFERENCES agreement_plan_visits(id), quote_id UUID,
    original_pricing JSONB NOT NULL, pricing JSONB NOT NULL, amount_cents INTEGER NOT NULL CHECK(amount_cents>=0),
    credited_cents INTEGER NOT NULL DEFAULT 0 CHECK(credited_cents>=0), state TEXT NOT NULL DEFAULT 'scheduled', error_code TEXT,
    frozen_at TIMESTAMPTZ, completed_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  CREATE INDEX IF NOT EXISTS agreement_plan_jobs_enrollment_idx ON agreement_plan_jobs(enrollment_id,created_at);
  CREATE INDEX IF NOT EXISTS agreement_plan_jobs_quote_idx ON agreement_plan_jobs(company_id,quote_id) WHERE quote_id IS NOT NULL;
  CREATE OR REPLACE FUNCTION wolfcrm_plan_job_prices(items JSONB) RETURNS JSONB LANGUAGE sql IMMUTABLE AS $$
    SELECT COALESCE(jsonb_agg(jsonb_build_object('service_id',line->>'service_id','qty',COALESCE((line->>'qty')::numeric,1),'price',COALESCE(line->'price_cents',line->'priceCents')) ORDER BY line->>'service_id',line->>'id'),'[]'::jsonb)
    FROM jsonb_array_elements(COALESCE(items,'[]'::jsonb)) AS line
  $$;
  CREATE OR REPLACE FUNCTION wolfcrm_preserve_plan_job_scope() RETURNS trigger LANGUAGE plpgsql AS $$
  BEGIN
    IF EXISTS(SELECT 1 FROM agreement_plan_jobs WHERE job_id=OLD.id AND frozen_at IS NOT NULL) AND
      (OLD.company_id,OLD.contact_id,OLD.service_plan_id,OLD.quote_id,to_jsonb(OLD)->'agreement_id',wolfcrm_plan_job_prices(OLD.service_items),OLD.price_cents)
      IS DISTINCT FROM (NEW.company_id,NEW.contact_id,NEW.service_plan_id,NEW.quote_id,to_jsonb(NEW)->'agreement_id',wolfcrm_plan_job_prices(NEW.service_items),NEW.price_cents)
    THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='completed_plan_job_price_immutable'; END IF;
    IF EXISTS(SELECT 1 FROM agreement_plan_visits WHERE job_id=OLD.id) AND NOT EXISTS(SELECT 1 FROM agreement_plan_jobs WHERE job_id=OLD.id) AND (
      (OLD.company_id,OLD.contact_id,OLD.service_plan_id,OLD.quote_id) IS DISTINCT FROM (NEW.company_id,NEW.contact_id,NEW.service_plan_id,NEW.quote_id)
      OR wolfcrm_plan_job_scope(OLD.service_items) IS DISTINCT FROM wolfcrm_plan_job_scope(NEW.service_items))
    THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='signed_plan_job_scope_immutable'; END IF;
    IF EXISTS(SELECT 1 FROM agreement_plan_jobs WHERE job_id=OLD.id) AND
      (OLD.company_id,OLD.contact_id,OLD.quote_id) IS DISTINCT FROM (NEW.company_id,NEW.contact_id,NEW.quote_id)
    THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='plan_job_customer_immutable'; END IF;
    RETURN NEW;
  END $$;
  CREATE OR REPLACE FUNCTION wolfcrm_cancel_plan_job() RETURNS trigger LANGUAGE plpgsql AS $$
  BEGIN
    UPDATE agreement_plan_jobs SET state='canceled',error_code=NULL,updated_at=now() WHERE job_id=OLD.id AND frozen_at IS NULL;
    RETURN OLD;
  END $$;
  DROP TRIGGER IF EXISTS wolfcrm_cancel_plan_job ON schedule_events;
  CREATE TRIGGER wolfcrm_cancel_plan_job AFTER DELETE ON schedule_events FOR EACH ROW EXECUTE FUNCTION wolfcrm_cancel_plan_job();`);
}

// The original signed quote and the plan snapshot remain immutable. This is
// the operational job price; clients never calculate the amount to collect.
export function pricePlanJob(enrollment, original, { visitSequence = 1 } = {}) {
  // The choice is signed with new offers. Old snapshots and frozen claims are
  // never reinterpreted using a newly edited tier or a new pricing policy.
  const initialExempt = enrollment.snapshot.pricing_model === 'initial_visit_choice_v1'
    && enrollment.snapshot.initial_service_completed !== true && visitSequence === 1
    && enrollment.snapshot.configuration.discount_first_visit !== true;
  const included = enrollment.snapshot.future_visit.line_items;
  const ids = included.map(l => l.service_id).filter(Boolean);
  const offer = calculatePlanOffer({ line_items: original.line_items.map(line => { const agreed=included.find(l=>l.service_id===line.service_id); return agreed ? {...line,price_cents:agreed.price_cents} : line; }), quoted_pricing: original,
    eligible_service_ids: ids, tier: { ...enrollment.snapshot.configuration, discount_first_visit: !initialExempt },
    tax_rate_basis_points: original.tax_rate_basis_points, tax_inclusive: original.tax_inclusive,
    discount_stacking_policy: enrollment.snapshot.discount_stacking_policy || 'best_price' });
  const pricing = offer?.current_pricing || original;
  const covered = original.line_items.filter(l => ids.includes(l.service_id));
  const sameCoveredScope = quoteContentHash(scope(original.line_items)) === quoteContentHash(scope(included));
  const authorized = fullJobConsent(enrollment) || (sameCoveredScope && pricing.total_cents <= enrollment.snapshot.future_visit.total_cents);
  return { pricing, covered: covered.length > 0, authorized };
}

export function createPlanJobBilling({ pool, service, anchorFirstVisit, now = () => new Date() }) {
  async function paymentLock(db, job) {
    if (job.quote_id) await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [`payment:${job.company_id}:quote:${job.quote_id}`]);
  }
  async function candidates(db, job) {
    return (await db.query(`SELECT e.* FROM agreement_plan_enrollments e JOIN service_plans p ON p.id=e.service_plan_id
      WHERE e.company_id=$1 AND e.contact_id=$2 AND p.status='active' AND e.canceled_at IS NULL AND e.cancel_requested_at IS NULL
      AND e.snapshot#>>'{configuration,billing,mode}'='automatic_per_visit'
      AND (e.cancellation_effective_at IS NULL OR $3::timestamptz<e.cancellation_effective_at)
      ORDER BY e.activated_at,e.id`, [job.company_id,job.contact_id,job.start_at || now()])).rows;
  }
  function choose(rows, lines) {
    const ids = new Set(normalized(lines).map(l=>l.service_id));
    const matched = rows.filter(e=>e.snapshot.future_visit.line_items.some(l=>ids.has(l.service_id)));
    const choices = matched.length ? matched : rows;
    if (choices.length>1) fail('plan_job_membership_ambiguous','More than one active membership can pay for this job. Review the customer’s memberships before completing it.');
    return choices[0];
  }
  async function associate(db, companyID, jobID, { allowFinished = false } = {}) {
    let job = (await db.query('SELECT * FROM schedule_events WHERE id=$1 AND company_id=$2 FOR UPDATE',[jobID,companyID])).rows[0];
    if (!job?.contact_id || (job.finished_at && !allowFinished)) return null;
    const prior = (await db.query('SELECT * FROM agreement_plan_jobs WHERE job_id=$1',[job.id])).rows[0];
    if (prior?.frozen_at) return prior;
    const bound=job.service_plan_id ? (await db.query('SELECT * FROM agreement_plan_enrollments WHERE service_plan_id=$1 AND company_id=$2 AND contact_id=$3',[job.service_plan_id,companyID,job.contact_id])).rows[0] : null;
    const enrollment = prior ? (await db.query('SELECT * FROM agreement_plan_enrollments WHERE id=$1',[prior.enrollment_id])).rows[0] : bound || choose(await candidates(db,job),job.service_items || []);
    if (!enrollment || !automatic(enrollment)) return null;
    if (job.service_plan_id && job.service_plan_id !== enrollment.service_plan_id) fail('plan_job_membership_changed','This job already belongs to another membership.');
    // A previously paid/consumed legacy visit keeps its existing collection ID.
    const legacyVisit = (await db.query('SELECT * FROM agreement_plan_visits WHERE job_id=$1',[job.id])).rows[0];
    if (!prior && legacyVisit && (legacyVisit.state==='completed' || (await db.query("SELECT 1 FROM agreement_plan_billing_obligations WHERE enrollment_id=$1 AND obligation_key=$2",[enrollment.id,`visit:${legacyVisit.id}`])).rowCount)) return null;
    await paymentLock(db,job);
    await db.query('SELECT id FROM agreement_plan_enrollments WHERE id=$1 FOR UPDATE',[enrollment.id]);
    const plan = (await db.query('SELECT * FROM service_plans WHERE id=$1 FOR UPDATE',[enrollment.service_plan_id])).rows[0];
    if (plan.status!=='active' || enrollment.canceled_at || enrollment.cancel_requested_at) return prior || null;
    let original;
    const agreement = job.agreement_id ? (await db.query('SELECT * FROM quote_agreements WHERE id=$1 AND company_id=$2 AND contact_id=$3',[job.agreement_id,companyID,job.contact_id])).rows[0] : null;
    if (agreement?.snapshot.pricing) {
      original=agreement.snapshot.pricing;
      const ids=new Set(original.line_items.map(l=>l.id));
      const extras=normalized(job.service_items || []).filter(l=>!ids.has(l.id));
      if(extras.length) {
        const extra=calculateQuotePricing({line_items:extras,tax_rate_basis_points:original.tax_rate_basis_points,tax_inclusive:original.tax_inclusive});
        original={...original,line_items:[...original.line_items,...extra.line_items],subtotal_cents:original.subtotal_cents+extra.subtotal_cents,tax_cents:original.tax_cents+extra.tax_cents,total_cents:original.total_cents+extra.total_cents};
      }
    }
    else {
      const lines = normalized(job.service_items || []);
      if (!lines.length || lines.some(l=>!Number.isSafeInteger(l.price_cents))) fail('plan_job_prices_required','Enter a price for each service so the full job can be billed correctly.');
      original=calculateQuotePricing({line_items:lines});
      if (!prior && job.price_cents!=null && Number(job.price_cents)!==original.total_cents) fail('plan_job_total_mismatch','The job total must match its priced services before automatic billing.');
    }
    const covered=original.line_items.some(line=>enrollment.snapshot.future_visit.line_items.some(included=>included.service_id===line.service_id));
    let visit=legacyVisit;
    if (covered && !visit) {
      visit=(await db.query("SELECT * FROM agreement_plan_visits WHERE enrollment_id=$1 AND state='due' AND job_id IS NULL ORDER BY sequence LIMIT 1 FOR UPDATE",[enrollment.id])).rows[0];
      if (!visit && plan.remaining_visits===null) {
        const sequence=Number((await db.query('SELECT COALESCE(max(sequence),0)+1 AS n FROM agreement_plan_visits WHERE enrollment_id=$1',[enrollment.id])).rows[0].n);
        visit=(await db.query('INSERT INTO agreement_plan_visits(id,enrollment_id,service_plan_id,sequence,due_date) VALUES($1,$2,$3,$4,$5) RETURNING *',[randomUUID(),enrollment.id,plan.id,sequence,advancePlanDate(plan.first_visit_date ? new Date(plan.first_visit_date).toISOString().slice(0,10) : enrollment.snapshot.next_service_date,enrollment.snapshot.configuration.service_interval,sequence-1)])).rows[0];
      }
      if (!visit) fail('plan_visits_exhausted','All covered visits are already scheduled. Review this finite membership before adding another covered job.');
    }
    if (!covered && visit) {
      await db.query("UPDATE agreement_plan_visits SET job_id=NULL,state='due' WHERE id=$1 AND completed_at IS NULL",[visit.id]);visit=null;
    }
    const { pricing, authorized }=pricePlanJob(enrollment,original,{visitSequence:visit?.sequence || 0});
    const state=authorized?'scheduled':'review',error=authorized?null:'plan_job_authorization_required';
    const claim=(await db.query(`INSERT INTO agreement_plan_jobs(job_id,company_id,contact_id,enrollment_id,visit_id,quote_id,original_pricing,pricing,amount_cents,state,error_code)
      VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9,$10,$11)
      ON CONFLICT(job_id) DO UPDATE SET visit_id=EXCLUDED.visit_id,original_pricing=EXCLUDED.original_pricing,pricing=EXCLUDED.pricing,amount_cents=EXCLUDED.amount_cents,state=EXCLUDED.state,error_code=EXCLUDED.error_code,updated_at=now() RETURNING *`,
      [job.id,companyID,job.contact_id,enrollment.id,visit?.id || null,job.quote_id,JSON.stringify(original),JSON.stringify(pricing),pricing.total_cents,state,error])).rows[0];
    await db.query('UPDATE schedule_events SET service_plan_id=$2,price_cents=$3 WHERE id=$1',[job.id,plan.id,pricing.total_cents]);
    if (visit) {
      await db.query("UPDATE agreement_plan_visits SET job_id=$2,state='scheduled' WHERE id=$1 AND completed_at IS NULL",[visit.id,job.id]);
      await anchorFirstVisit(db,enrollment,plan,visit,job);
    }
    if (!prior) await service.event(db,enrollment.base_agreement_id,'plan_job_associated',{payload:{enrollment_id:enrollment.id,job_id:job.id,visit_id:visit?.id || null,amount_cents:pricing.total_cents,automatic:true}});
    else if (quoteContentHash(prior.pricing)!==quoteContentHash(pricing)) await service.event(db,enrollment.base_agreement_id,'plan_job_price_updated',{payload:{enrollment_id:enrollment.id,job_id:job.id,previous_amount_cents:prior.amount_cents,amount_cents:pricing.total_cents,previous_pricing_hash:quoteContentHash(prior.pricing),pricing_hash:quoteContentHash(pricing)}});
    return claim;
  }
  async function reserve(db, jobID) {
    const claim=(await db.query('SELECT b.*,j.finished_at,j.service_plan_id FROM agreement_plan_jobs b JOIN schedule_events j ON j.id=b.job_id AND j.company_id=b.company_id WHERE b.job_id=$1 FOR UPDATE OF b',[jobID])).rows[0];
    if (!claim?.finished_at) return null;
    await paymentLock(db,claim);
    const existing=(await db.query('SELECT * FROM agreement_plan_billing_obligations WHERE enrollment_id=$1 AND job_id=$2',[claim.enrollment_id,jobID])).rows[0];
    if (existing) return existing;
    const enrollment=(await db.query('SELECT * FROM agreement_plan_enrollments WHERE id=$1',[claim.enrollment_id])).rows[0];
    const visit=claim.visit_id?(await db.query('SELECT sequence FROM agreement_plan_visits WHERE id=$1',[claim.visit_id])).rows[0]:null;
    let error=pricePlanJob(enrollment,claim.original_pricing,{visitSequence:visit?.sequence || 0}).authorized ? null : 'plan_job_authorization_required';
    const plan=(await db.query('SELECT status FROM service_plans WHERE id=$1',[claim.service_plan_id])).rows[0];
    if (!['active','expired'].includes(plan?.status) || enrollment.canceled_at || enrollment.cancel_requested_at) error='plan_not_active';
    const records=(await db.query(`SELECT * FROM payment_records WHERE company_id=$1 AND contact_id=$2 AND (job_id=$3 OR ($4::uuid IS NOT NULL AND quote_id=$4))`,[claim.company_id,claim.contact_id,jobID,claim.quote_id])).rows;
    let credit=0;
    for (const payment of records) {
      const manual=!payment.stripe_connected_account_id&&!payment.stripe_payment_intent_id;
      if ((!manual && payment.stripe_livemode!==enrollment.stripe_livemode) || payment.stripe_dispute_status || Number(payment.refunded_amount_cents)>0 || payment.refund_amount_known===false || ['refunded','partially_refunded','disputed'].includes(payment.status)) error='plan_job_payment_review';
      if (['succeeded','paid'].includes(payment.status)) credit+=Number(payment.amount_cents);
      if (['pending','processing'].includes(payment.status)) error='plan_job_payment_in_progress';
    }
    if (claim.quote_id) {
      if ((await db.query("SELECT 1 FROM agreement_payment_attempts WHERE company_id=$1 AND collection_key=$2 AND state IN ('creating','open','processing','review')",[claim.company_id,`quote:${claim.quote_id}`])).rowCount) error='plan_job_checkout_open';
      if ((await db.query('SELECT 1 FROM schedule_events WHERE company_id=$1 AND quote_id=$2 AND id<>$3',[claim.company_id,claim.quote_id,jobID])).rowCount) error='plan_job_shared_quote_review';
    }
    const amount=Math.max(0,claim.amount_cents-credit);
    if (amount>0 && amount<50) error='plan_amount_below_minimum';
    await db.query("UPDATE agreement_plan_jobs SET frozen_at=COALESCE(frozen_at,now()),completed_at=$2,credited_cents=$3,state=$4,error_code=$5,updated_at=now() WHERE job_id=$1",[jobID,claim.finished_at,credit,error?'review':'completed',error]);
    if (error) return null;
    return (await db.query(`INSERT INTO agreement_plan_billing_obligations(id,enrollment_id,obligation_key,kind,sequence,due_date,amount_cents,job_id,state,payment_status)
      VALUES($1,$2,$3,$4,$5,CURRENT_DATE,$6,$7,$8,$8) ON CONFLICT(enrollment_id,obligation_key) DO NOTHING RETURNING *`,[randomUUID(),enrollment.id,`job:${jobID}`,visit?'visit':'job',visit?.sequence || 0,amount,jobID,amount===0?'succeeded':'scheduled'])).rows[0];
  }
  async function collectionSummary(db,row) {
    if (!row.quote_id || !row.snapshot.pricing) return null;
    const claims=(await db.query("SELECT * FROM agreement_plan_jobs WHERE company_id=$1 AND quote_id=$2 AND state<>'canceled' ORDER BY created_at",[row.company_id,row.quote_id])).rows;
    if (claims.length) return { managed:true,total_cents:claims[0].amount_cents,review:claims.length>1 || claims.some(c=>c.state==='review'),frozen:claims.some(c=>c.frozen_at),enrollment_id:claims[0].enrollment_id, defer_deposit:true };
    // Before an appointment exists, an active automatic membership still owns
    // collection, so a second ordinary checkout cannot race the booking.
    const rows=await candidates(db,{company_id:row.company_id,contact_id:row.contact_id});
    let enrollment;
    try { enrollment=choose(rows,row.snapshot.pricing.line_items); }
    catch(error) { if(error.code!=='plan_job_membership_ambiguous') throw error; return {managed:true,total_cents:row.snapshot.pricing.total_cents,review:true,frozen:false}; }
    if (!enrollment) return null;
    // Preview the next reservable visit; booking recomputes under the company
    // schedule/enrollment locks before reserving the actual visit and price.
    const next=(await db.query(`SELECT COALESCE(min(sequence) FILTER (WHERE state='due' AND job_id IS NULL),max(sequence)+1,1) AS sequence
      FROM agreement_plan_visits WHERE enrollment_id=$1`,[enrollment.id])).rows[0];
    const result=pricePlanJob(enrollment,row.snapshot.pricing,{visitSequence:Number(next.sequence)});
    return {managed:true,total_cents:result.pricing.total_cents,review:!result.authorized,frozen:false,defer_deposit:fullJobConsent(enrollment),enrollment_id:enrollment.id};
  }
  return { associate, reserve, collectionSummary };
}
