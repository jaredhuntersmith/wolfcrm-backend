import { installPlanJobSchema, createPlanJobBilling } from "./agreement-plan-jobs.js";
import { installPlanQuotePublication } from "./plan-quote-publication.js";
import { authoringRequest } from "./agreement-authoring.js";
import { randomUUID } from 'node:crypto';
import { QuoteContractError, quoteContentHash, quoteText } from './quote-contract-domain.js';
import { normalizePlanTier, buildPlanOffer, advancePlanDate } from './agreement-plans-domain.js';
import { resolveAgreementText, generateQuoteAgreementPDF, combineAgreementPDFs } from './quote-agreement-documents.js';
import { lockCompanySchedule } from './schedule-booking-guard.js';

const fail = (code, message, status = 409) => { throw new QuoteContractError(code, message, status); };
const id = (value) => { if (typeof value !== 'string' || !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(value)) fail('plan_id_invalid', 'Choose a valid plan record.', 400); return value.toLowerCase(); };
const money = (value) => new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(value / 100);
const key = (row) => row.quote_id ? `quote:${row.quote_id}` : `agreement:${row.id}`;
const txn = async (pool, work) => { const db = await pool.connect(); try { await db.query('BEGIN'); const result = await work(db); await db.query('COMMIT'); return result; } catch (error) { await db.query('ROLLBACK'); throw error; } finally { db.release(); } };

export async function installAgreementPlanSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS service_plan_tiers (
      tier_id UUID NOT NULL, version INTEGER NOT NULL, company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
      configuration JSONB NOT NULL, archived_at TIMESTAMPTZ, created_by UUID NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY(tier_id,version)
    );
    CREATE INDEX IF NOT EXISTS service_plan_tiers_company_idx ON service_plan_tiers(company_id,created_at DESC);
    CREATE TABLE IF NOT EXISTS agreement_plan_enrollments (
      id UUID PRIMARY KEY, company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT, contact_id UUID NOT NULL,
      base_agreement_id UUID NOT NULL REFERENCES quote_agreements(id) ON DELETE RESTRICT,
      plan_agreement_id UUID NOT NULL UNIQUE REFERENCES quote_agreements(id) ON DELETE RESTRICT,
      tier_id UUID NOT NULL, tier_version INTEGER NOT NULL, collection_key TEXT NOT NULL,
      request_id UUID NOT NULL, request_hash TEXT NOT NULL, offer_hash TEXT NOT NULL, snapshot JSONB NOT NULL,
      state TEXT NOT NULL DEFAULT 'agreement_pending', service_plan_id UUID UNIQUE REFERENCES service_plans(id) ON DELETE RESTRICT,
      connected_account_id TEXT, stripe_livemode BOOLEAN, stripe_customer_id TEXT, stripe_payment_method_id TEXT,
      card_metadata JSONB, activated_at TIMESTAMPTZ, canceled_at TIMESTAMPTZ, next_reconcile_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id,request_id), FOREIGN KEY(tier_id,tier_version) REFERENCES service_plan_tiers(tier_id,version) ON DELETE RESTRICT
    );
    CREATE UNIQUE INDEX IF NOT EXISTS agreement_plan_enrollment_scope_idx ON agreement_plan_enrollments(company_id,collection_key) WHERE canceled_at IS NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS agreement_plan_replacement_once_idx ON agreement_plan_enrollments((snapshot#>>'{replaces,enrollment_id}')) WHERE canceled_at IS NULL AND snapshot#>>'{replaces,enrollment_id}' IS NOT NULL;
    CREATE INDEX IF NOT EXISTS agreement_plan_enrollments_due_idx ON agreement_plan_enrollments(next_reconcile_at);
    CREATE TABLE IF NOT EXISTS agreement_quote_adjustments (
      id UUID PRIMARY KEY, company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT, collection_key TEXT NOT NULL,
      base_agreement_id UUID NOT NULL REFERENCES quote_agreements(id) ON DELETE RESTRICT,
      enrollment_id UUID NOT NULL UNIQUE REFERENCES agreement_plan_enrollments(id) ON DELETE RESTRICT,
      discount_cents INTEGER NOT NULL CHECK(discount_cents>=0), original_total_cents INTEGER NOT NULL, adjusted_total_cents INTEGER NOT NULL,
      signed_agreement_id UUID NOT NULL REFERENCES quote_agreements(id) ON DELETE RESTRICT, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS agreement_quote_adjustments_scope_idx ON agreement_quote_adjustments(company_id,collection_key);
    ALTER TABLE service_plans ADD COLUMN IF NOT EXISTS enrollment_id UUID REFERENCES agreement_plan_enrollments(id) ON DELETE RESTRICT;
    ALTER TABLE service_plans ADD COLUMN IF NOT EXISTS plan_snapshot JSONB;
    ALTER TABLE service_plans ADD COLUMN IF NOT EXISTS billing_mode TEXT;
    ALTER TABLE service_plans ADD COLUMN IF NOT EXISTS remaining_visits INTEGER;
    ALTER TABLE service_plans ADD COLUMN IF NOT EXISTS first_visit_date DATE;
    CREATE UNIQUE INDEX IF NOT EXISTS service_plans_enrollment_unique ON service_plans(enrollment_id) WHERE enrollment_id IS NOT NULL;
    CREATE TABLE IF NOT EXISTS agreement_plan_visits (
      id UUID PRIMARY KEY, enrollment_id UUID NOT NULL REFERENCES agreement_plan_enrollments(id) ON DELETE RESTRICT,
      service_plan_id UUID NOT NULL REFERENCES service_plans(id) ON DELETE RESTRICT, sequence INTEGER NOT NULL,
      due_date DATE NOT NULL, job_id TEXT, state TEXT NOT NULL DEFAULT 'due', completed_at TIMESTAMPTZ,
      UNIQUE(enrollment_id,sequence), UNIQUE(service_plan_id,job_id)
    );
    ALTER TABLE agreement_plan_enrollments ADD COLUMN IF NOT EXISTS activation_dispatched_at TIMESTAMPTZ;
    ALTER TABLE agreement_plan_visits ADD COLUMN IF NOT EXISTS job_history JSONB NOT NULL DEFAULT '[]'::jsonb;
    ALTER TABLE agreement_plan_visits ADD COLUMN IF NOT EXISTS schedule_offset INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS service_plan_id UUID REFERENCES service_plans(id) ON DELETE RESTRICT;
    CREATE INDEX IF NOT EXISTS schedule_events_active_plan_idx ON schedule_events(company_id,service_plan_id,start_at) WHERE service_plan_id IS NOT NULL AND finished_at IS NULL;
    CREATE TABLE IF NOT EXISTS agreement_plan_visit_actions (
      company_id UUID NOT NULL, request_id UUID NOT NULL, request_hash TEXT NOT NULL, result JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(company_id,request_id)
    );
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS enrollment_id UUID REFERENCES agreement_plan_enrollments(id) ON DELETE RESTRICT;
    CREATE OR REPLACE FUNCTION wolfcrm_plan_job_scope(items JSONB) RETURNS JSONB LANGUAGE sql IMMUTABLE AS $$
      SELECT COALESCE(jsonb_agg(jsonb_build_object('service_id',line->>'service_id','qty',COALESCE((line->>'qty')::numeric,1)) ORDER BY line->>'service_id',COALESCE((line->>'qty')::numeric,1)),'[]'::jsonb)
      FROM jsonb_array_elements(COALESCE(items,'[]'::jsonb)) AS line
    $$;
    CREATE OR REPLACE FUNCTION wolfcrm_preserve_plan_job_scope() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF EXISTS(SELECT 1 FROM agreement_plan_visits WHERE job_id=OLD.id) AND (
        (OLD.company_id,OLD.contact_id,OLD.service_plan_id,OLD.quote_id) IS DISTINCT FROM (NEW.company_id,NEW.contact_id,NEW.service_plan_id,NEW.quote_id)
        OR wolfcrm_plan_job_scope(OLD.service_items) IS DISTINCT FROM wolfcrm_plan_job_scope(NEW.service_items)
      ) THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='signed_plan_job_scope_immutable',DETAIL='Keep the enrolled services, quantities and customer on this job. Put other work on a separate job.'; END IF;
      RETURN NEW;
    END $$;
    DROP TRIGGER IF EXISTS wolfcrm_preserve_plan_job_scope ON schedule_events;
    CREATE TRIGGER wolfcrm_preserve_plan_job_scope BEFORE UPDATE ON schedule_events FOR EACH ROW EXECUTE FUNCTION wolfcrm_preserve_plan_job_scope();
    CREATE OR REPLACE FUNCTION wolfcrm_restore_canceled_plan_visit() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE visit_record RECORD;
    BEGIN
      FOR visit_record IN UPDATE agreement_plan_visits SET state='due',job_id=NULL,job_history=job_history||jsonb_build_array(jsonb_build_object('action','appointment_deleted','job_id',OLD.id,'at',now()))
        WHERE job_id=OLD.id AND state='scheduled' RETURNING id,enrollment_id
      LOOP
        INSERT INTO agreement_events(id,agreement_id,type,actor_type,payload)
          SELECT gen_random_uuid(),e.base_agreement_id,'plan_visit_unscheduled','system',jsonb_build_object('enrollment_id',e.id,'visit_id',visit_record.id,'job_id',OLD.id)
          FROM agreement_plan_enrollments e WHERE e.id=visit_record.enrollment_id;
      END LOOP;
      RETURN OLD;
    END $$;
    DROP TRIGGER IF EXISTS wolfcrm_restore_canceled_plan_visit ON schedule_events;
    CREATE TRIGGER wolfcrm_restore_canceled_plan_visit AFTER DELETE ON schedule_events FOR EACH ROW EXECUTE FUNCTION wolfcrm_restore_canceled_plan_visit();
  `);
  await installPlanJobSchema(pool);
}

export function createAgreementPlans({ pool, service, now = () => new Date(), onPlanActivated = async () => {}, supportedBillingModes = ['manual_per_visit'] }) {
  const jobs = createPlanJobBilling({pool,service,anchorFirstVisit,now});
  service.planJobCollectionSummary = jobs.collectionSummary;
  service.associatePlanJob = jobs.associate;
  service.refreshCompletedPlanJobs = async enrollmentID => txn(pool,async db=>{
    const enrollment=(await db.query('SELECT company_id FROM agreement_plan_enrollments WHERE id=$1',[enrollmentID])).rows[0];
    if(!enrollment)return;
    await lockCompanySchedule(db,enrollment.company_id);
    const completed=(await db.query(`SELECT b.job_id FROM agreement_plan_jobs b JOIN schedule_events j ON j.id=b.job_id AND j.company_id=b.company_id
      WHERE b.enrollment_id=$1 AND j.finished_at IS NOT NULL AND b.completed_at IS NOT NULL
      AND NOT EXISTS(SELECT 1 FROM agreement_plan_billing_obligations o WHERE o.enrollment_id=b.enrollment_id AND o.job_id=b.job_id) ORDER BY j.finished_at LIMIT 50`,[enrollmentID])).rows;
    for(const row of completed)await jobs.reserve(db,row.job_id);
  });
  async function tiers(db, companyID, includeArchived = false) {
    return (await db.query(`SELECT * FROM (SELECT DISTINCT ON(tier_id) * FROM service_plan_tiers WHERE company_id=$1 ORDER BY tier_id,version DESC) latest WHERE ($2 OR archived_at IS NULL) ORDER BY (configuration->>'sort_order')::integer,created_at,tier_id`, [companyID, includeArchived])).rows;
  }
  async function saveTier(req, raw) {
    const configuration = normalizePlanTier(raw.configuration), tierID = raw.tier_id ? id(raw.tier_id) : randomUUID();
    return txn(pool, async (db) => authoringRequest(db, req, "tier", raw, async () => {
      await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [`plan-tier:${tierID}`]);
      const prior = (await db.query('SELECT * FROM service_plan_tiers WHERE tier_id=$1 ORDER BY version DESC LIMIT 1', [tierID])).rows[0];
      if (prior && (prior.company_id !== req.companyId || prior.version !== raw.expected_version)) fail('plan_tier_changed', 'This tier changed or is unavailable. Reload before saving.', 409);
      if (prior?.archived_at) fail('plan_tier_archived', 'This tier was archived. Copy its settings into a new tier instead.', 409);
      if (configuration.service_ids) {
        const services = (await db.query('SELECT id FROM saved_services WHERE company_id=$1 AND id=ANY($2::uuid[]) AND archived_at IS NULL', [req.companyId, configuration.service_ids])).rows;
        if (services.length !== configuration.service_ids.length) fail('plan_service_unavailable', 'A selected service is archived or belongs to another company.');
      }
      await service.validateDocuments(db, req.companyId, configuration.agreement);
      return (await db.query('INSERT INTO service_plan_tiers(tier_id,version,company_id,configuration,created_by) VALUES($1,$2,$3,$4::jsonb,$5) RETURNING *', [tierID, (prior?.version || 0) + 1, req.companyId, JSON.stringify(configuration), req.userId])).rows[0];
    }));
  }
  async function currentMemberships(db,row) {
    const rows=(await db.query(`SELECT e.* FROM agreement_plan_enrollments e JOIN service_plans p ON p.id=e.service_plan_id
      WHERE e.company_id=$1 AND e.contact_id=$2 AND e.canceled_at IS NULL AND p.status IN ('active','paused','past_due')
      ORDER BY e.activated_at DESC,e.id`,[row.company_id,row.contact_id])).rows;
    return rows;
  }
  async function withReplacement(db,row,offer,memberships = null) {
    const existing=(memberships || await currentMemberships(db,row)).filter(enrollment=>enrollment.snapshot.future_visit.line_items.some(line=>offer.future_visit.line_items.some(candidate=>candidate.service_id===line.service_id)));
    if(existing.length>1) return {...offer,switch_unavailable:'Multiple memberships cover these services. Ask the business to reconcile them before switching.'};
    if(!existing.length)return offer;
    const current=existing[0];
    if(current.tier_id===offer.tier_id) return null;
    const replacement={enrollment_id:current.id,plan_name:current.snapshot.configuration.name,cancellation_notice_days:current.snapshot.configuration.cancellation_notice_days || 0};
    const financial_text=offer.financial_text+`\n\nThis replaces your ${replacement.plan_name} membership after the new agreement and payment requirements are completed and the current plan’s ${replacement.cancellation_notice_days}-day cancellation notice has elapsed. The current plan remains active until then. Existing appointments and amounts owed remain recorded; unused prepaid benefits and any policy credits require the business’s review. No automatic refund or duplicate renewal is created.`;
    const result={...offer,replaces:replacement,financial_text};delete result.offer_hash;
    return {...result,offer_hash:quoteContentHash(result)};
  }
  async function offers(db, row) {
    if (!row.snapshot.offer_service_plans || !row.snapshot.pricing || row.snapshot.kind === 'plan' || row.revoked_at || ['declined', 'superseded'].includes(row.decision)) return [];
    const state = await service.state(db, row);
    if (state.signing !== 'submitted') return [];
    const catalog = (await db.query('SELECT id FROM saved_services WHERE company_id=$1 AND plan_eligible AND archived_at IS NULL', [row.company_id])).rows;
    const payments = await service.paymentSummary(db, row);
    if (payments.payment_review_required) return [];
    const previouslyCounted=(await db.query("SELECT 1 FROM agreement_plan_enrollments WHERE company_id=$1 AND collection_key=$2 AND service_plan_id IS NOT NULL AND snapshot->'configuration'->>'current_visit_counts'='true' AND snapshot->'configuration'->'term'->>'kind'='finite' LIMIT 1",[row.company_id,key(row)])).rowCount>0;
    const serviced = Boolean((await db.query('SELECT 1 FROM schedule_events WHERE company_id=$1 AND quote_id=$2 AND finished_at IS NOT NULL LIMIT 1', [row.company_id, row.quote_id])).rowCount);
    const timezone = (await db.query('SELECT timezone FROM companies WHERE id=$1', [row.company_id])).rows[0]?.timezone || 'America/New_York';
    let today;
    try { today = new Intl.DateTimeFormat('en-CA', { timeZone: timezone, year: 'numeric', month: '2-digit', day: '2-digit' }).format(now()); } catch { today = now().toISOString().slice(0, 10); }
    const offered=(await tiers(db, row.company_id)).filter((tier) => supportedBillingModes.includes(tier.configuration.billing.mode)).map((tier) => buildPlanOffer({ agreement: row, tier, eligible_service_ids: catalog.map((item) => item.id), payments_cents: payments.paid_cents, today, serviced,prior_adjustment_cents:payments.adjustment_cents||0,initial_visit_already_counted:previouslyCounted })).filter(Boolean);
    const current=await currentMemberships(db,row);
    return (await Promise.all(offered.map(offer=>withReplacement(db,row,offer,current)))).filter(Boolean);
  }
  async function load(db, row, enrollmentID, lock = false) {
    const result = (await db.query(`SELECT * FROM agreement_plan_enrollments WHERE id=$1 AND company_id=$2 AND (base_agreement_id=$3 OR plan_agreement_id=$3) ${lock ? 'FOR UPDATE' : ''}`, [id(enrollmentID), row.company_id, row.id])).rows[0];
    if (!result) fail('plan_enrollment_unavailable', 'This enrollment is unavailable.', 404);
    return result;
  }
  async function summary(db, row,options={}) {
    const enrollment = (await db.query('SELECT * FROM agreement_plan_enrollments WHERE company_id=$1 AND (base_agreement_id=$2 OR plan_agreement_id=$2) ORDER BY created_at DESC LIMIT 1', [row.company_id, row.id])).rows[0];
    return enrollment ? detail(db, enrollment,options) : null;
  }
  async function detail(db, enrollment,{publicRole='customer'}={}) {
    const agreement = (await db.query('SELECT * FROM quote_agreements WHERE id=$1', [enrollment.plan_agreement_id])).rows[0];
    const base = (await db.query('SELECT * FROM quote_agreements WHERE id=$1 AND company_id=$2', [enrollment.base_agreement_id, enrollment.company_id])).rows[0];
    const membership=enrollment.service_plan_id?(await db.query('SELECT status,remaining_visits,first_visit_date::text FROM service_plans WHERE id=$1 AND company_id=$2',[enrollment.service_plan_id,enrollment.company_id])).rows[0]:null;
    const visits = (await db.query('SELECT id,sequence,due_date,job_id,state,completed_at FROM agreement_plan_visits WHERE enrollment_id=$1 ORDER BY sequence', [enrollment.id])).rows;
    return { awaiting_first_appointment: enrollment.snapshot.schedule_model === 'appointment_anchored_v1' && !membership?.first_visit_date, first_visit_date: membership?.first_visit_date || null, return_url: base?.snapshot.required_signers.includes(publicRole) ? service.customerURL(base, publicRole) : null, id: enrollment.id, state: membership?.status || enrollment.state, enrollment_state:enrollment.state,cancellation_effective_at:enrollment.cancellation_effective_at||null, remaining_visits:membership?.remaining_visits??null, service_plan_id: enrollment.service_plan_id, plan_agreement_id: agreement.id, plan_agreement_url: agreement.snapshot.required_signers.includes(publicRole)?service.customerURL(agreement,publicRole):null, signed_state: await service.state(db, agreement), snapshot: enrollment.snapshot, card: enrollment.card_metadata || null, activated_at: enrollment.activated_at, visits };
  }
  async function createEnrollment(token, raw) {
    const { row,role } = await service.loadPublic(pool, token);
    if(role!=='customer')fail('plan_primary_customer_required','The primary customer chooses service-plan enrollment.',403);
    await service.rate(pool,`plan-enrollment:${row.id}`,20,3600);
    const requestID = id(raw.request_id), requestHash = quoteContentHash({ tier_id: id(raw.tier_id), tier_version: raw.tier_version, offer_hash: raw.offer_hash });
    return txn(pool, async (db) => {
      await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [`payment:${row.company_id}:${key(row)}`]);
      const priorRequest = (await db.query('SELECT * FROM agreement_plan_enrollments WHERE company_id=$1 AND request_id=$2', [row.company_id, requestID])).rows[0];
      if (priorRequest) { if (priorRequest.request_hash !== requestHash || priorRequest.base_agreement_id !== row.id) fail('plan_request_conflict', 'This enrollment request was already used for different terms.'); return detail(db, priorRequest); }
      await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`plan-contact:${row.company_id}:${row.contact_id}`]);
      const existing = (await db.query('SELECT * FROM agreement_plan_enrollments WHERE company_id=$1 AND base_agreement_id=$2 AND service_plan_id IS NULL AND canceled_at IS NULL', [row.company_id, row.id])).rows[0];
      if (existing) { if (existing.offer_hash !== raw.offer_hash) fail('plan_enrollment_exists', 'Resume or cancel the existing enrollment before choosing another tier.'); return detail(db, existing); }
      const offer = (await offers(db, row)).find((entry) => entry.tier_id === raw.tier_id && entry.tier_version === raw.tier_version);
      if (offer?.switch_unavailable) fail('plan_switch_review_required',offer.switch_unavailable);
      if (!offer || offer.offer_hash !== raw.offer_hash) fail('plan_offer_changed', 'The eligible services, tier, payment balance or offer date changed. Review the current offer before signing.');
      const enrollmentID = randomUUID(), planAgreementID = randomUUID();
      const number = String((await db.query('INSERT INTO agreement_number_sequences(company_id,last_number) VALUES($1,1) ON CONFLICT(company_id) DO UPDATE SET last_number=agreement_number_sequences.last_number+1 RETURNING last_number', [row.company_id])).rows[0].last_number);
      const config = offer.configuration, content = config.agreement;
      const privateContact = (await db.query('SELECT * FROM contacts WHERE id=$1 AND company_id=$2', [row.contact_id, row.company_id])).rows[0];
      if (!privateContact) fail('plan_contact_unavailable', 'The customer is unavailable.');
      const expiresAt=new Date(now().getTime()+(content.validity_days??30)*86400000).toISOString();
      const merge = { customer_name: privateContact.name, service_address: privateContact.address, billing_address: row.snapshot.customer.billing_address||privateContact.address, customer_phone: privateContact.phone, customer_email: privateContact.email,
        business_name: row.snapshot.business.name, business_address: row.snapshot.business.address, business_phone: row.snapshot.business.phone, business_email: row.snapshot.business.email,
        quote_number: number, issue_date: now().toISOString(), expires_at: expiresAt, services: offer.future_visit.line_items.map((line) => `${line.name}: ${line.description}`).join('\n'),
        subtotal: money(offer.future_visit.subtotal_cents), tax: money(offer.future_visit.tax_cents), total: money(offer.current_total_cents), deposit: money(row.snapshot.pricing.deposit_cents), deposit_percentage: row.snapshot.deposit?.type === 'percent' ? `${row.snapshot.deposit.value / 100}%` : '', balance: money(offer.current_balance_cents),
        plan_name: config.name, service_frequency: `Every ${config.service_interval.count} ${config.service_interval.unit}`, contract_term: config.term.kind === 'finite' ? `${config.term.visit_count} visits` : 'Ongoing', plan_price: money(offer.future_visit.total_cents), billing_information: offer.financial_text };
      const termsAsset = content.show_terms && content.terms_asset_id ? (await db.query('SELECT * FROM agreement_assets WHERE id=$1 AND company_id=$2', [content.terms_asset_id, row.company_id])).rows[0] : null;
      if (content.show_terms && content.terms_asset_id && !termsAsset) fail('plan_terms_missing', 'The plan terms PDF is unavailable.');
      merge.business_name=content.branding.display_name||row.snapshot.business.name;
      const snapshot = { kind: 'plan', title: config.name, number, revision: 1, issued_at: now().toISOString(), expires_at: expiresAt,
        business: {...row.snapshot.business,name:merge.business_name,logo_data_url:content.branding.show_logo?row.snapshot.business.logo_data_url||'':''}, customer: { name: privateContact.name, address: privateContact.address, billing_address:merge.billing_address, phone: content.show_customer_phone ? privateContact.phone : null, email: content.show_customer_email ? privateContact.email : null },
        pricing: null, allow_customer_booking: false, offer_service_plans: false, customer_notes_enabled: false, duration_minutes: null,
        ...content, show_agreement: true, agreement_text: `${offer.financial_text}\n\n${content.show_agreement && content.agreement_mode === "text" ? resolveAgreementText(content.agreement_text, merge) : ""}`, terms_text: "", consent_text: resolveAgreementText(content.consent_text, merge),
        documents: await service.validateDocuments(db, row.company_id, content, merge),
        terms_document: termsAsset ? { asset_id: termsAsset.id, name: termsAsset.name, sha256: termsAsset.normalized_sha256 } : null,
        plan_enrollment_id: enrollmentID, base_agreement_id: row.id, financial_terms: offer,
      };
      const agreement = (await db.query(`INSERT INTO quote_agreements(id,company_id,contact_id,created_by,number,revision,request_id,title,snapshot,packet_hash,expires_at) VALUES($1,$2,$3,$4,$5,1,$6,$7,$8::jsonb,$9,$10) RETURNING *`, [planAgreementID, row.company_id, row.contact_id, row.created_by, number, randomUUID(), config.name, JSON.stringify(snapshot), quoteContentHash(snapshot), snapshot.expires_at])).rows[0];
      await service.storeArtifact(db, agreement.id, 'quote', await generateQuoteAgreementPDF(snapshot, { customer_url: service.customerURL(agreement) }));
      if (snapshot.terms_text || termsAsset) {
        const cover = await generateQuoteAgreementPDF({ ...snapshot, title: 'Plan Terms & Conditions', agreement_text: '', documents: [], consent_text: '' }, { customer_url: service.customerURL(agreement) });
        await service.storeArtifact(db, agreement.id, 'terms', termsAsset ? termsAsset.normalized_bytes : cover);
      }
      const enrollment = (await db.query(`INSERT INTO agreement_plan_enrollments(id,company_id,contact_id,base_agreement_id,plan_agreement_id,tier_id,tier_version,collection_key,request_id,request_hash,offer_hash,snapshot) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb) RETURNING *`, [enrollmentID, row.company_id, row.contact_id, row.id, planAgreementID, offer.tier_id, offer.tier_version, offer.replaces ? `switch:${offer.replaces.enrollment_id}:${row.id}` : key(row), requestID, requestHash, offer.offer_hash, JSON.stringify(offer)])).rows[0];
      await service.event(db, row.id, 'plan_enrollment_started', { payload: { enrollment_id: enrollmentID, plan_agreement_id: planAgreementID } });
      await service.event(db, agreement.id, 'link_created', { payload: { enrollment_id: enrollmentID, base_agreement_id: row.id } });
      return detail(db, enrollment);
    });
  }
  async function reconcileEnrollment(enrollmentID) {
    const preliminary = (await pool.query('SELECT * FROM agreement_plan_enrollments WHERE id=$1', [id(enrollmentID)])).rows[0];
    if (!preliminary) fail('plan_enrollment_unavailable', 'This enrollment is unavailable.', 404);
    if(preliminary.cancel_requested_at)return detail(pool,preliminary);
    if (service.reconcilePlanBilling) await service.reconcilePlanBilling(preliminary.id);
    if (service.preparePlanReplacement) await service.preparePlanReplacement(preliminary);
    let activated;
    const result = await txn(pool, async (db) => {
      await lockCompanySchedule(db,preliminary.company_id);
      const source=(await db.query('SELECT * FROM quote_agreements WHERE id=$1',[preliminary.base_agreement_id])).rows[0];
      await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [`payment:${preliminary.company_id}:${key(source)}`]);
      const enrollment = (await db.query('SELECT * FROM agreement_plan_enrollments WHERE id=$1 FOR UPDATE', [preliminary.id])).rows[0];
      if (enrollment.service_plan_id || enrollment.canceled_at || enrollment.cancel_requested_at) return detail(db, enrollment);
      const planAgreement = (await db.query('SELECT * FROM quote_agreements WHERE id=$1', [enrollment.plan_agreement_id])).rows[0];
      const base = (await db.query('SELECT * FROM quote_agreements WHERE id=$1', [enrollment.base_agreement_id])).rows[0];
      const planState = await service.state(db, planAgreement), offer = enrollment.snapshot, config = offer.configuration;
      let state = 'agreement_pending';
      if (planState.signing === 'submitted') {
        state = 'setup_pending';
        const prerequisite = service.planActivationPrerequisites ? await service.planActivationPrerequisites(db, enrollment) : { ready: config.billing.mode === 'manual_per_visit' && config.billing.enrollment_fee_cents === 0 };
        const priorPlan=offer.replaces ? (await db.query('SELECT canceled_at FROM agreement_plan_enrollments WHERE id=$1 AND company_id=$2',[offer.replaces.enrollment_id,enrollment.company_id])).rows[0] : null;
        if (offer.replaces && !priorPlan?.canceled_at) state='replacement_pending';
        if (prerequisite.ready && (!offer.replaces || priorPlan?.canceled_at)) {
          const activeAttempt = (await db.query(`SELECT id FROM agreement_payment_attempts WHERE company_id=$1 AND collection_key=$2 AND state IN ('creating','open','processing','review') LIMIT 1`, [enrollment.company_id, key(base)])).rows[0];
          if (offer.current_adjustment_cents > 0 && activeAttempt) state = 'payment_conflict';
          else {
            const baseState = await service.state(db, base);
            if (baseState.signing !== 'submitted' || ['revoked','declined','superseded','expired'].includes(baseState.decision)) state = 'base_review_required';
            else {
              const owner = (await db.query('SELECT owner_user_id FROM companies WHERE id=$1', [enrollment.company_id])).rows[0]?.owner_user_id;
              if (!owner) fail('plan_business_owner_missing', 'Configure the business owner before activating a membership.');
              const membershipID = randomUUID();
              const price = config.billing.mode === 'calendar_installments' ? offer.billing_schedule[0].amount_cents : config.billing.mode === 'prepaid' ? offer.installments.remaining_cents : offer.future_visit.total_cents;
              const plan = (await db.query(`INSERT INTO service_plans(id,user_id,company_id,created_by_user_id,contact_id,plan_name,status,price_cents,currency,billing_interval,billing_interval_count,service_interval,service_interval_count,first_service_date,next_service_date,included_services,notes,enrollment_id,plan_snapshot,billing_mode,remaining_visits,stripe_connected_account_id,stripe_customer_id)
                VALUES($1,$2,$3,$4,$5,$6,'active',$7,'usd',$8,$9,$10,$11,$12,$12,$13,$14,$15,$16::jsonb,$17,$18,$19,$20) RETURNING *`, [membershipID, owner, enrollment.company_id, base.created_by, enrollment.contact_id, config.name, price, ['manual_per_visit','automatic_per_visit'].includes(config.billing.mode) ? 'per_visit' : config.billing.mode === 'prepaid' ? 'prepaid' : config.billing.interval.unit,
                config.billing.interval.count, config.service_interval.unit, config.service_interval.count, offer.next_service_date, offer.future_visit.line_items.map((line) => `${line.qty} × ${line.name}: ${line.description}`).join('\n'), 'Signed plan enrollment; see linked agreement for the preserved terms.', enrollment.id, JSON.stringify(offer), config.billing.mode, offer.future_visit_count, enrollment.connected_account_id, enrollment.stripe_customer_id])).rows[0];
              const count = offer.future_visit_count === null ? 1 : offer.future_visit_count;
              for (let visit = 0; visit < count; visit++) await db.query('INSERT INTO agreement_plan_visits(id,enrollment_id,service_plan_id,sequence,due_date) VALUES($1,$2,$3,$4,$5)', [randomUUID(), enrollment.id, membershipID, visit + 1, advancePlanDate(offer.next_service_date, config.service_interval, visit)]);
              if (offer.current_adjustment_cents > 0 && !offer.price_in_quote) await db.query(`INSERT INTO agreement_quote_adjustments(id,company_id,collection_key,base_agreement_id,enrollment_id,discount_cents,original_total_cents,adjusted_total_cents,signed_agreement_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [randomUUID(), enrollment.company_id, key(base), base.id, enrollment.id, offer.current_adjustment_cents, offer.original_total_cents, offer.current_total_cents, planAgreement.id]);
              await db.query(`INSERT INTO service_plan_events(user_id,company_id,created_by_user_id,service_plan_id,contact_id,event_type,notes) VALUES($1,$2,$3,$4,$5,'created','Activated from a separately signed plan enrollment')`, [owner,enrollment.company_id,base.created_by,membershipID,enrollment.contact_id]);
              await db.query(`UPDATE agreement_plan_enrollments SET service_plan_id=$2,state='active',activated_at=now(),updated_at=now() WHERE id=$1`, [enrollment.id,membershipID]);
              await db.query('UPDATE payment_records SET service_plan_id=$2 WHERE enrollment_id=$1',[enrollment.id,membershipID]);
              await service.event(db, base.id, 'plan_activated', { payload: { enrollment_id: enrollment.id, service_plan_id: membershipID, plan_agreement_id: planAgreement.id, current_adjustment_cents: offer.current_adjustment_cents } });
              activated = plan;
              return detail(db, { ...enrollment, service_plan_id: membershipID, state: 'active', activated_at: now() });
            }
          }
        }
      }
      await db.query('UPDATE agreement_plan_enrollments SET state=$2,next_reconcile_at=now()+interval \'1 minute\',updated_at=now() WHERE id=$1', [enrollment.id,state]);
      return detail(db, { ...enrollment, state });
    });
    // Membership is durable before automation scheduling. A retryable event
    // remains in the agreement outbox even if the existing scheduler is offline.
    if (activated) {
      await dispatchActivation(activated);
      await txn(pool,async db=>{
        await lockCompanySchedule(db,activated.company_id);
        const upcoming=(await db.query('SELECT id FROM schedule_events WHERE company_id=$1 AND contact_id=$2 AND finished_at IS NULL ORDER BY start_at,id',[activated.company_id,activated.contact_id])).rows;
        for(const job of upcoming) await jobs.associate(db,activated.company_id,job.id);
      });
    }
    return result;
  }
  async function dispatchActivation(plan) {
    try { await onPlanActivated(plan); await pool.query('UPDATE agreement_plan_enrollments SET activation_dispatched_at=now() WHERE service_plan_id=$1', [plan.id]); }
    catch { /* Persisted null dispatch timestamp keeps scheduler recovery pending. */ }
  }
  async function anchorFirstVisit(db, enrollment, plan, visit, job) {
    if (visit.sequence !== 1 || !['automatic_per_visit','manual_per_visit'].includes(enrollment.snapshot.configuration.billing.mode)) return;
    const date = (await db.query("SELECT ($1::timestamptz AT TIME ZONE COALESCE(timezone,'America/New_York'))::date::text AS day FROM companies WHERE id=$2", [job.start_at, enrollment.company_id])).rows[0].day;
    const visits = (await db.query("SELECT * FROM agreement_plan_visits WHERE enrollment_id=$1 ORDER BY sequence FOR UPDATE", [enrollment.id])).rows;
    for (const pending of visits) {
      if (pending.state === 'completed' || (pending.job_id && pending.id !== visit.id)) continue;
      const due = advancePlanDate(date, enrollment.snapshot.configuration.service_interval, pending.sequence - 1 + pending.schedule_offset);
      await db.query('UPDATE agreement_plan_visits SET due_date=$2 WHERE id=$1', [pending.id, due]);
    }
    await db.query("UPDATE service_plans SET first_visit_date=$2,next_service_date=(SELECT min(due_date) FROM agreement_plan_visits WHERE enrollment_id=$3 AND state IN ('due','scheduled')),updated_at=now() WHERE id=$1", [plan.id, date, enrollment.id]);
  }
  async function linkVisit(req, enrollmentID, visitID, raw) {
    return txn(pool, async (db) => {
      await lockCompanySchedule(db, req.companyId);
      const enrollment = (await db.query('SELECT * FROM agreement_plan_enrollments WHERE id=$1 AND company_id=$2 FOR UPDATE', [id(enrollmentID),req.companyId])).rows[0];
      if (!enrollment?.service_plan_id) fail('plan_enrollment_unavailable','Choose an active membership.',404);
      if (enrollment.canceled_at) fail('plan_canceled','This membership is canceled. Its evidence and payments remain preserved.');
      const plan = (await db.query('SELECT * FROM service_plans WHERE id=$1', [enrollment.service_plan_id])).rows[0];
      if (plan.status !== 'active') fail('plan_not_active','This membership must be active before scheduling a covered visit.');
      const visit = (await db.query('SELECT * FROM agreement_plan_visits WHERE id=$1 AND enrollment_id=$2 FOR UPDATE', [id(visitID),enrollment.id])).rows[0];
      if (!visit || !['due','scheduled'].includes(visit.state)) fail('plan_visit_unavailable','Choose an uncompleted plan visit.');
      const job = (await db.query('SELECT * FROM schedule_events WHERE id=$1 AND company_id=$2 AND contact_id=$3 FOR UPDATE', [String(raw.job_id),req.companyId,enrollment.contact_id])).rows[0];
      if (!job || job.quote_id || job.finished_at || (job.service_plan_id && job.service_plan_id !== plan.id)) fail('plan_job_unavailable','Choose an unfinished job for this customer that is not billed under an initial quote or another membership.');
      if(enrollment.cancellation_effective_at&&new Date(job.start_at)>=new Date(enrollment.cancellation_effective_at))fail('plan_cancellation_scheduled','This appointment falls after the membership cancellation takes effect.');
      if (visit.job_id === job.id && visit.state === 'scheduled') { await anchorFirstVisit(db,enrollment,plan,visit,job); return detail(db,enrollment); }
      const expected = enrollment.snapshot.future_visit.line_items;
      const scope = (lines) => lines.map((line) => ({service_id:line.service_id||null,qty:Number(line.qty??1)})).sort((a,b)=>String(a.service_id).localeCompare(String(b.service_id))||a.qty-b.qty);
      if (quoteContentHash(scope(job.service_items||[])) !== quoteContentHash(scope(expected))) fail('plan_job_scope_mismatch','The job must contain exactly the enrolled services and quantities. Keep unrelated one-time work on a separate job.');
      if (visit.job_id && visit.job_id !== job.id && (await db.query('SELECT 1 FROM schedule_events WHERE id=$1',[visit.job_id])).rowCount) fail('plan_visit_already_scheduled','Reschedule the existing appointment or cancel it before linking a replacement.');
      if ((await db.query('SELECT 1 FROM agreement_plan_visits WHERE job_id=$1 AND id<>$2',[job.id,visit.id])).rowCount) fail('plan_job_already_used','This job already covers another plan visit.');
      await db.query('UPDATE schedule_events SET service_plan_id=$2,updated_at=now() WHERE id=$1',[job.id,plan.id]);
      await db.query(`UPDATE agreement_plan_visits SET job_id=$2,state='scheduled',job_history=job_history||$3::jsonb WHERE id=$1`,[visit.id,job.id,JSON.stringify([{action:'scheduled',job_id:job.id,start_at:job.start_at,actor_id:req.userId,at:now().toISOString()}])]);
      await anchorFirstVisit(db,enrollment,plan,visit,job);
      await service.event(db,enrollment.base_agreement_id,'plan_visit_scheduled',{actor_type:'staff',actor_id:req.userId,payload:{enrollment_id:enrollment.id,visit_id:visit.id,job_id:job.id}});
      return detail(db,enrollment);
    });
  }
  async function deferVisit(req,enrollmentID,visitID,raw) {
    const requestID=id(raw.request_id),reason=quoteText(raw.reason,'Reason for deferring',1000).trim();
    const requestHash=quoteContentHash({action:'defer',enrollment_id:id(enrollmentID),visit_id:id(visitID),reason});
    return txn(pool,async(db)=>{
      await lockCompanySchedule(db,req.companyId);
      const enrollment=(await db.query('SELECT * FROM agreement_plan_enrollments WHERE id=$1 AND company_id=$2 FOR UPDATE',[enrollmentID,req.companyId])).rows[0];
      if(!enrollment?.service_plan_id)fail('plan_enrollment_unavailable','Choose an active membership.',404);
      const replay=(await db.query('SELECT * FROM agreement_plan_visit_actions WHERE company_id=$1 AND request_id=$2',[req.companyId,requestID])).rows[0];
      if(replay){if(replay.request_hash!==requestHash)fail('plan_visit_request_conflict','This request belongs to another visit change.');return detail(db,enrollment);}
      const plan=(await db.query('SELECT * FROM service_plans WHERE id=$1 FOR UPDATE',[enrollment.service_plan_id])).rows[0];
      if(plan.status!=='active'||enrollment.canceled_at||enrollment.cancellation_effective_at)fail('plan_not_active','Review this membership before changing its service cadence.');
      if(enrollment.snapshot.schedule_model==='appointment_anchored_v1'&&!plan.first_visit_date)fail('plan_first_appointment_required','Schedule the first covered visit before deferring its recurrence.');
      if(!enrollment.snapshot.configuration.allow_skip)fail('plan_skip_not_allowed','The signed membership does not allow skipping a service cycle.');
      const visits=(await db.query("SELECT * FROM agreement_plan_visits WHERE enrollment_id=$1 AND state IN ('due','scheduled') ORDER BY due_date,sequence FOR UPDATE",[enrollment.id])).rows;
      if(visits[0]?.id!==visitID)fail('plan_visit_unavailable','Choose the next uncompleted visit to defer the service cycle.');
      if(visits.some(visit=>visit.state==='scheduled'))fail('plan_appointments_exist','Reschedule or cancel existing plan appointments before deferring a service cycle.');
      for(const visit of visits){
        const offset=visit.schedule_offset+1,date=advancePlanDate(plan.first_visit_date ? new Date(plan.first_visit_date).toISOString().slice(0,10) : enrollment.snapshot.next_service_date,enrollment.snapshot.configuration.service_interval,visit.sequence-1+offset);
        await db.query('UPDATE agreement_plan_visits SET due_date=$2,schedule_offset=$3,job_history=job_history||$4::jsonb WHERE id=$1',[visit.id,date,offset,JSON.stringify([{action:'cycle_deferred',from:visit.due_date,to:date,reason,actor_id:req.userId,at:now().toISOString()}])]);
      }
      await db.query('UPDATE service_plans SET next_service_date=(SELECT min(due_date) FROM agreement_plan_visits WHERE enrollment_id=$2 AND state=\'due\'),updated_at=now() WHERE id=$1',[plan.id,enrollment.id]);
      await service.event(db,enrollment.base_agreement_id,'plan_visit_deferred',{actor_type:'staff',actor_id:req.userId,payload:{enrollment_id:enrollment.id,visit_id:visitID,reason,remaining_visits:plan.remaining_visits,billing_unchanged:true}});
      const result=await detail(db,enrollment);
      await db.query('INSERT INTO agreement_plan_visit_actions(company_id,request_id,request_hash,result) VALUES($1,$2,$3,$4::jsonb)',[req.companyId,requestID,requestHash,JSON.stringify({enrollment_id:enrollment.id,action:'defer'})]);
      return result;
    });
  }
  async function markServiced(req, suppliedPlan, raw) {
    const requestID=id(raw.request_id), jobID=String(raw.job_id||''), requestHash=quoteContentHash({plan_id:suppliedPlan.id,job_id:jobID});
    const result = await txn(pool, async(db)=>{
      await lockCompanySchedule(db,req.companyId);
      const plan=(await db.query('SELECT * FROM service_plans WHERE id=$1 AND company_id=$2 FOR UPDATE',[suppliedPlan.id,req.companyId])).rows[0];
      if(!plan?.enrollment_id)fail('plan_membership_unavailable','This enrolled membership is unavailable.',404);
      const replay=(await db.query('SELECT * FROM agreement_plan_visit_actions WHERE company_id=$1 AND request_id=$2',[req.companyId,requestID])).rows[0];
      if(replay){if(replay.request_hash!==requestHash)fail('plan_visit_request_conflict','This request was used for a different completed visit.');return replay.result;}
      const visit=(await db.query('SELECT * FROM agreement_plan_visits WHERE service_plan_id=$1 AND job_id=$2 FOR UPDATE',[plan.id,jobID])).rows[0];
      const job=(await db.query('SELECT * FROM schedule_events WHERE id=$1 AND company_id=$2 AND contact_id=$3',[jobID,req.companyId,plan.contact_id])).rows[0];
      if(!visit||!job?.finished_at||job.service_plan_id!==plan.id)fail('plan_visit_completion_required','Link this membership visit to its actual job and finish that job before marking service complete.');
      if(visit.state==='completed'){ await jobs.reserve(db,jobID); return plan; }
      if(!['active','past_due'].includes(plan.status))fail('plan_not_active','Review this membership before consuming another visit.');
      const enrollment=(await db.query('SELECT * FROM agreement_plan_enrollments WHERE id=$1',[plan.enrollment_id])).rows[0];
      await anchorFirstVisit(db,enrollment,plan,visit,job);
      const anchor=(await db.query('SELECT first_visit_date::text AS day FROM service_plans WHERE id=$1',[plan.id])).rows[0].day || enrollment.snapshot.next_service_date;
      await db.query(`UPDATE agreement_plan_visits SET state='completed',completed_at=$2,job_history=job_history||$3::jsonb WHERE id=$1`,[visit.id,job.finished_at,JSON.stringify([{action:'completed',job_id:job.id,actor_id:req.userId,at:now().toISOString()}])]);
      if(plan.remaining_visits===null){const nextSequence=visit.sequence+1;await db.query('INSERT INTO agreement_plan_visits(id,enrollment_id,service_plan_id,sequence,due_date,schedule_offset) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(enrollment_id,sequence) DO NOTHING',[randomUUID(),enrollment.id,plan.id,nextSequence,advancePlanDate(anchor,enrollment.snapshot.configuration.service_interval,nextSequence-1+visit.schedule_offset),visit.schedule_offset]);}
      const next=(await db.query("SELECT min(due_date) AS due FROM agreement_plan_visits WHERE service_plan_id=$1 AND state<>'completed'",[plan.id])).rows[0].due;
      const updated=(await db.query(`UPDATE service_plans SET remaining_visits=CASE WHEN remaining_visits IS NULL THEN NULL ELSE GREATEST(0,remaining_visits-1) END,last_service_date=($2::timestamptz AT TIME ZONE (SELECT COALESCE(timezone,'America/New_York') FROM companies WHERE id=$4))::date,next_service_date=$3,status=CASE WHEN remaining_visits=1 THEN 'expired' ELSE status END,updated_at=now() WHERE id=$1 RETURNING *`,[plan.id,job.finished_at,next,req.companyId])).rows[0];
      await db.query(`INSERT INTO service_plan_events(user_id,company_id,created_by_user_id,service_plan_id,contact_id,event_type,completed_date,notes) VALUES($1,$2,$3,$4,$5,'serviced',$6::date,$7)`,[plan.user_id,req.companyId,req.userId,plan.id,plan.contact_id,job.finished_at,`Completed visit ${visit.sequence}; job ${job.id}`]);
      await jobs.reserve(db,jobID);
      if(service.reserveCompletedPlanBilling) await service.reserveCompletedPlanBilling(db,enrollment);
      await db.query('UPDATE agreement_plan_enrollments SET next_reconcile_at=now() WHERE id=$1',[enrollment.id]);
      await service.event(db,enrollment.base_agreement_id,'plan_visit_completed',{actor_type:'staff',actor_id:req.userId,payload:{enrollment_id:enrollment.id,service_plan_id:plan.id,visit_id:visit.id,job_id:job.id}});
      await db.query('INSERT INTO agreement_plan_visit_actions(company_id,request_id,request_hash,result) VALUES($1,$2,$3,$4::jsonb)',[req.companyId,requestID,requestHash,JSON.stringify(updated)]);
      return updated;
    });
    // Completion is durable even when Stripe is unavailable. The due worker
    // retries the same reserved obligation and provider command.
    try { await service.reconcilePlanBilling?.(suppliedPlan.enrollment_id); }
    catch { console.error('[plan-billing] completed visit queued for reconciliation', {enrollment_id:suppliedPlan.enrollment_id}); }
    return result;
  }
  async function completeJob(req, jobID) {
    const claim=await txn(pool,async db=>{
      await lockCompanySchedule(db,req.companyId);
      const claim=await jobs.associate(db,req.companyId,jobID,{allowFinished:true});
      if(claim && !claim.visit_id) await jobs.reserve(db,jobID);
      return claim;
    });
    const plan=(await pool.query('SELECT p.* FROM service_plans p JOIN agreement_plan_visits v ON v.service_plan_id=p.id JOIN schedule_events j ON j.id=v.job_id WHERE v.job_id=$1 AND p.company_id=$2 AND j.finished_at IS NOT NULL',[jobID,req.companyId])).rows[0];
    if(plan) return markServiced(req,plan,{request_id:randomUUID(),job_id:jobID});
    if(claim) try { await service.reconcilePlanBilling?.(claim.enrollment_id); }
    catch { console.error('[plan-billing] completed job queued for reconciliation',{job_id:jobID}); }
  }
  async function processMemberships() {
    const ready=(await pool.query(`SELECT b.job_id,b.company_id,j.created_by FROM agreement_plan_jobs b JOIN schedule_events j ON j.id=b.job_id AND j.company_id=b.company_id
      WHERE j.finished_at IS NOT NULL AND b.completed_at IS NULL ORDER BY j.finished_at LIMIT 50`)).rows;
    for(const row of ready) try { await completeJob({companyId:row.company_id,userId:row.created_by},row.job_id); } catch { console.error('[plans] job reconciliation pending',{job_id:row.job_id}); }

    const pending=(await pool.query('SELECT p.* FROM service_plans p JOIN agreement_plan_enrollments e ON e.id=p.enrollment_id WHERE e.activation_dispatched_at IS NULL LIMIT 20')).rows;
    for(const plan of pending)await dispatchActivation(plan);
    const completed=(await pool.query(`SELECT v.id AS visit_id,v.job_id,p.* FROM agreement_plan_visits v JOIN service_plans p ON p.id=v.service_plan_id JOIN schedule_events j ON j.id=v.job_id AND j.company_id=p.company_id WHERE v.state='scheduled' AND j.finished_at IS NOT NULL AND p.status IN ('active','past_due') LIMIT 50`)).rows;
    for(const plan of completed)await markServiced({companyId:plan.company_id,userId:plan.created_by_user_id||plan.user_id},plan,{request_id:plan.visit_id,job_id:plan.job_id});
  }
  async function paymentAdjustmentSummary(db, row) {
    const rows = (await db.query('SELECT id,discount_cents FROM agreement_quote_adjustments WHERE company_id=$1 AND collection_key=$2', [row.company_id,key(row)])).rows;
    return { discount_cents: rows.reduce((sum, row) => sum + row.discount_cents,0), adjustment_ids: rows.map((row) => row.id) };
  }
  async function followupContext(db,row) {
    const enrollment=(await db.query('SELECT e.*,a.signed_at FROM agreement_plan_enrollments e JOIN quote_agreements a ON a.id=e.plan_agreement_id WHERE e.base_agreement_id=$1 AND e.company_id=$2 AND e.canceled_at IS NULL ORDER BY e.created_at DESC LIMIT 1',[row.id,row.company_id])).rows[0];
    if(!enrollment)return {};
    const due=enrollment.service_plan_id?(await db.query(`SELECT v.id,v.due_date FROM agreement_plan_visits v JOIN service_plans p ON p.id=v.service_plan_id WHERE v.enrollment_id=$1 AND v.state IN ('due','scheduled') AND p.status='active' AND (v.job_id IS NULL OR NOT EXISTS(SELECT 1 FROM schedule_events WHERE id=v.job_id)) ORDER BY v.due_date,v.sequence LIMIT 1`,[enrollment.id])).rows[0]:null;
    return {plan_setup_pending:!enrollment.service_plan_id?enrollment.signed_at:null,plan_setup_pending_occurrence:enrollment.id,plan_service_due:due?.due_date,plan_service_due_occurrence:due?.id};
  }
  return { tiers, saveTier, offers, currentMemberships, withReplacement, load, summary, detail, createEnrollment, reconcileEnrollment, paymentAdjustmentSummary, supportedBillingModes, associateJob:jobs.associate, linkVisit, deferVisit,markServiced, completeJob, processMemberships, followupContext };
}

export async function installAgreementPlans({ app, pool, service, authRequired, requireCapability, onPlanActivated, startWorker = true, ...options }) {
  await installAgreementPlanSchema(pool);
  const plans = createAgreementPlans({ pool, service, onPlanActivated, ...options });
  installPlanQuotePublication(service, plans.supportedBillingModes, plans);
  service.plansReady = true; service.planSummary = plans.summary; service.paymentAdjustmentSummary = plans.paymentAdjustmentSummary;
  service.planFollowupContext = plans.followupContext;
  service.currentPlanPresence = async (db,row) => (await plans.currentMemberships(db,row)).length > 0;
  const wrap = (fn) => async (req,res) => { res.set({ 'Cache-Control':'private, no-store','Referrer-Policy':'no-referrer' }); try { await fn(req,res); } catch(error) { if(error instanceof QuoteContractError) return res.status(error.status).json({error:error.code,message:error.message}); console.error('[plans] operation failed',{code:error.code||'internal'}); res.status(500).json({error:'plan_operation_failed',message:'The plan could not be updated. Your existing agreement remains saved.'}); } };
  const staff=(capability)=>[authRequired,requireCapability(capability),(req,res,next)=>req.companyId?next():res.status(403).json({error:'company_required'})];
  const publicWrite=(req,res,next)=>{if(!req.is('application/json'))return res.status(415).json({error:'json_required'});if(req.headers.origin&&req.headers.origin!==service.env.QUOTE_PUBLIC_BASE_URL?.replace(/\/$/,''))return res.status(403).json({error:'origin_not_allowed'});next();};
  app.get('/api/service-plan-tiers',...staff('payments.view'),wrap(async(req,res)=>res.json({tiers:await plans.tiers(pool,req.companyId),supported_billing_modes:plans.supportedBillingModes})));
  app.post('/api/service-plan-tiers',...staff('settings.manage_company'),wrap(async(req,res)=>res.status(201).json(await plans.saveTier(req,req.body))));
  app.post('/api/service-plan-tiers/:id/archive',...staff('settings.manage_company'),wrap(async(req,res)=>{const result=await pool.query('UPDATE service_plan_tiers SET archived_at=now() WHERE tier_id=$1 AND company_id=$2 RETURNING tier_id',[id(req.params.id),req.companyId]);if(!result.rowCount)fail('plan_tier_unavailable','This tier is unavailable.',404);res.json({archived:true});}));
  app.get('/api/service-plan-operations',...staff('payments.view'),requireCapability('schedule.view'),wrap(async(req,res)=>{
    const rows=(await pool.query(`SELECT p.id AS service_plan_id,p.enrollment_id,p.contact_id,p.plan_name,c.name AS customer_name,
      v.id AS visit_id,COALESCE(v.due_date,p.next_service_date)::text AS due_date
      FROM service_plans p JOIN contacts c ON c.id=p.contact_id AND c.company_id=p.company_id
      LEFT JOIN LATERAL (SELECT id,due_date FROM agreement_plan_visits WHERE service_plan_id=p.id AND state IN ('due','scheduled') ORDER BY due_date,sequence LIMIT 1) v ON true
      WHERE p.company_id=$1 AND p.status='active' AND (p.remaining_visits IS NULL OR p.remaining_visits>0)
      AND (p.enrollment_id IS NULL OR v.id IS NOT NULL)
      AND NOT EXISTS(SELECT 1 FROM schedule_events j WHERE j.company_id=p.company_id AND j.service_plan_id=p.id AND j.finished_at IS NULL)
      ORDER BY COALESCE(v.due_date,p.next_service_date) NULLS LAST,c.name,p.id`,[req.companyId])).rows;
    res.json({unscheduled:rows});
  }));
  app.get('/api/service-plan-enrollments/:id' ,...staff('payments.view'),wrap(async(req,res)=>{const enrollment=(await pool.query('SELECT * FROM agreement_plan_enrollments WHERE id=$1 AND company_id=$2',[id(req.params.id),req.companyId])).rows[0];if(!enrollment)fail('plan_enrollment_unavailable','This enrollment is unavailable.',404);res.json(await plans.detail(pool,enrollment));}));
  app.post('/api/service-plan-enrollments/:id/visits/:visitId/schedule',...staff('schedule.edit'),wrap(async(req,res)=>res.json(await plans.linkVisit(req,req.params.id,req.params.visitId,req.body))));
  app.post('/api/service-plan-enrollments/:id/visits/:visitId/defer',...staff('schedule.edit'),wrap(async(req,res)=>res.json(await plans.deferVisit(req,req.params.id,req.params.visitId,req.body))));
  app.get('/api/public/agreements/:token/plan-offers',wrap(async(req,res)=>{const {row,role}=await service.loadPublic(pool,req.params.token);res.json({offers:role==='customer'?await plans.offers(pool,row):[],enrollment:await plans.summary(pool,row,{publicRole:role}),current_memberships:role==='customer' ? await Promise.all((await plans.currentMemberships(pool,row)).map(item=>plans.detail(pool,item))) : []});}));
  app.post('/api/public/agreements/:token/enrollments',publicWrite,wrap(async(req,res)=>res.status(201).json(await plans.createEnrollment(req.params.token,req.body))));
  app.get('/api/public/agreements/:token/enrollments/:id',wrap(async(req,res)=>{const {row,role}=await service.loadPublic(pool,req.params.token);res.json(await plans.detail(pool,await plans.load(pool,row,req.params.id),{publicRole:role}));}));
  app.post('/api/public/agreements/:token/enrollments/:id/reconcile',publicWrite,wrap(async(req,res)=>{const {row,role}=await service.loadPublic(pool,req.params.token);if(role!=='customer')fail('plan_primary_customer_required','The primary customer completes enrollment.',403);await plans.load(pool,row,req.params.id);await service.rate(pool,`plan-reconcile:${req.params.id}`,60,3600);res.json(await plans.reconcileEnrollment(req.params.id));}));
  let running=false,timer;
  const tick=async()=>{if(running)return;running=true;try{const rows=(await pool.query(`UPDATE agreement_plan_enrollments SET next_reconcile_at=now()+interval '1 minute' WHERE id IN (SELECT id FROM agreement_plan_enrollments WHERE service_plan_id IS NULL AND canceled_at IS NULL AND next_reconcile_at<=now() ORDER BY next_reconcile_at LIMIT 20 FOR UPDATE SKIP LOCKED) RETURNING id`)).rows;for(const row of rows){try{await plans.reconcileEnrollment(row.id);}catch{console.error('[plans] enrollment retry pending',{enrollment_id:row.id});}}await plans.processMemberships();}finally{running=false;}};
  if(startWorker){timer=setInterval(()=>tick().catch(()=>console.error('[plans] worker failed')),30000);timer.unref();}
  return {...plans,stop:()=>clearInterval(timer)};
}
