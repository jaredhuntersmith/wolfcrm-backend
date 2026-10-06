import { randomUUID } from "node:crypto";
import { QuoteContractError, quoteContentHash } from "./quote-contract-domain.js";
import { advancePlanDate } from "./agreement-plans-domain.js";
import { stripePaymentMode } from "./agreement-payments.js";

const fail = (code, message, status = 409) => { throw new QuoteContractError(code, message, status); };
const objectID = value => typeof value === "string" ? value : value?.id || null;
const uuid = value => { if (typeof value !== "string" || !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(value)) fail("plan_request_invalid", "Use a valid plan request ID.", 400); return value.toLowerCase(); };
const automatic = enrollment => ["automatic_per_visit", "calendar_installments", "calendar_recurring"].includes(enrollment.snapshot.configuration.billing.mode);
const requiresCard = enrollment => automatic(enrollment) || enrollment.snapshot.configuration.billing.save_payment_method === true;
const transaction = async (pool, work) => {
  const db = await pool.connect();
  try { await db.query("BEGIN"); const result = await work(db); await db.query("COMMIT"); return result; }
  catch (error) { await db.query("ROLLBACK"); throw error; }
  finally { db.release(); }
};

export async function installAgreementPlanBillingSchema(pool) {
  await pool.query(`
    ALTER TABLE agreement_plan_enrollments ADD COLUMN IF NOT EXISTS cancellation_effective_at TIMESTAMPTZ;
    ALTER TABLE agreement_plan_enrollments ADD COLUMN IF NOT EXISTS cancel_requested_at TIMESTAMPTZ;
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS enrollment_id UUID REFERENCES agreement_plan_enrollments(id) ON DELETE RESTRICT;
    CREATE INDEX IF NOT EXISTS payment_records_enrollment_idx ON payment_records(enrollment_id,created_at);
    CREATE TABLE IF NOT EXISTS agreement_plan_provider_commands (
      id UUID PRIMARY KEY, enrollment_id UUID NOT NULL REFERENCES agreement_plan_enrollments(id) ON DELETE RESTRICT,
      command_key TEXT NOT NULL, kind TEXT NOT NULL, parameters JSONB NOT NULL, parameters_hash TEXT NOT NULL,
      connected_account_id TEXT NOT NULL, livemode BOOLEAN NOT NULL, result_id TEXT,
      state TEXT NOT NULL DEFAULT 'pending', error_code TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(), completed_at TIMESTAMPTZ,
      UNIQUE(enrollment_id,command_key)
    );
    CREATE TABLE IF NOT EXISTS agreement_plan_setups (
      id UUID PRIMARY KEY, enrollment_id UUID NOT NULL REFERENCES agreement_plan_enrollments(id) ON DELETE RESTRICT,
      request_id UUID NOT NULL, connected_account_id TEXT NOT NULL, livemode BOOLEAN NOT NULL,
      customer_id TEXT NOT NULL, session_id TEXT, setup_intent_id TEXT, url TEXT,
      state TEXT NOT NULL DEFAULT 'creating', created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(enrollment_id,request_id), UNIQUE(connected_account_id,livemode,session_id)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS agreement_plan_setup_active_idx ON agreement_plan_setups(enrollment_id) WHERE state IN ('creating','open','processing');
    CREATE TABLE IF NOT EXISTS agreement_plan_billing_obligations (
      id UUID PRIMARY KEY, enrollment_id UUID NOT NULL REFERENCES agreement_plan_enrollments(id) ON DELETE RESTRICT,
      obligation_key TEXT NOT NULL, kind TEXT NOT NULL, sequence INTEGER NOT NULL, due_date DATE NOT NULL,
      amount_cents INTEGER NOT NULL CHECK(amount_cents>=0), currency TEXT NOT NULL DEFAULT 'usd',
      job_id TEXT, payment_record_id UUID UNIQUE REFERENCES payment_records(id) ON DELETE RESTRICT,
      invoice_id TEXT, invoice_item_id TEXT, payment_intent_id TEXT, hosted_invoice_url TEXT, invoice_pdf TEXT,
      state TEXT NOT NULL DEFAULT 'scheduled', error_code TEXT, attempted_at TIMESTAMPTZ,
      next_reconcile_at TIMESTAMPTZ NOT NULL DEFAULT now(), created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(enrollment_id,obligation_key)
    );
    CREATE INDEX IF NOT EXISTS agreement_plan_billing_due_idx ON agreement_plan_billing_obligations(next_reconcile_at,due_date) WHERE state NOT IN ('succeeded','canceled');
    ALTER TABLE agreement_plan_billing_obligations ADD COLUMN IF NOT EXISTS payment_status TEXT;
    ALTER TABLE agreement_plan_billing_obligations ADD COLUMN IF NOT EXISTS attention_since TIMESTAMPTZ;
    ALTER TABLE agreement_plan_enrollments ADD COLUMN IF NOT EXISTS billing_error_code TEXT;
    ALTER TABLE agreement_plan_enrollments ADD COLUMN IF NOT EXISTS billing_error_since TIMESTAMPTZ;
    CREATE UNIQUE INDEX IF NOT EXISTS agreement_plan_invoice_idx ON agreement_plan_billing_obligations(enrollment_id,invoice_id) WHERE invoice_id IS NOT NULL;
    CREATE OR REPLACE FUNCTION wolfcrm_signed_membership_terms() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF OLD.enrollment_id IS NOT NULL AND (OLD.enrollment_id,OLD.plan_name,OLD.price_cents,OLD.currency,OLD.billing_interval,OLD.billing_interval_count,OLD.service_interval,OLD.service_interval_count,OLD.first_service_date,OLD.included_services,OLD.plan_snapshot,OLD.billing_mode,OLD.stripe_subscription_id)
        IS DISTINCT FROM (NEW.enrollment_id,NEW.plan_name,NEW.price_cents,NEW.currency,NEW.billing_interval,NEW.billing_interval_count,NEW.service_interval,NEW.service_interval_count,NEW.first_service_date,NEW.included_services,NEW.plan_snapshot,NEW.billing_mode,NEW.stripe_subscription_id)
      THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='signed_plan_terms_immutable'; END IF;
      RETURN NEW;
    END $$;
    DROP TRIGGER IF EXISTS wolfcrm_signed_membership_terms ON service_plans;
    CREATE TRIGGER wolfcrm_signed_membership_terms BEFORE UPDATE ON service_plans FOR EACH ROW EXECUTE FUNCTION wolfcrm_signed_membership_terms();
    CREATE TABLE IF NOT EXISTS agreement_plan_lifecycle_requests (
      enrollment_id UUID NOT NULL REFERENCES agreement_plan_enrollments(id) ON DELETE RESTRICT,
      request_id UUID NOT NULL, action TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(enrollment_id,request_id)
    );
  `);
}

export function createAgreementPlanBilling({ pool, service, plans, getStripe = service.getStripe, env = service.env, now = () => new Date() }) {
  const stripe = () => { const client = getStripe(); if (!client) fail("stripe_not_configured", "Payments are not configured for this business.", 503); return client; };
  const options = enrollment => ({ stripeAccount: enrollment.connected_account_id });
  async function lock(db, enrollment) { await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [`plan-billing:${enrollment.id}`]); }
  async function load(enrollmentID, db = pool) {
    const row = (await db.query("SELECT * FROM agreement_plan_enrollments WHERE id=$1", [uuid(enrollmentID)])).rows[0];
    if (!row) fail("plan_enrollment_unavailable", "The plan enrollment was not found.", 404);
    return row;
  }
  async function today(enrollment, db = pool) {
    const zone = (await db.query("SELECT timezone FROM companies WHERE id=$1", [enrollment.company_id])).rows[0]?.timezone || "America/New_York";
    return new Intl.DateTimeFormat("en-CA", { timeZone: zone, year: "numeric", month: "2-digit", day: "2-digit" }).format(now());
  }
  async function gate(enrollment, db = pool) {
    if (enrollment.canceled_at) fail("plan_canceled", "This enrollment has been canceled.");
    if (enrollment.cancel_requested_at) fail("plan_cancellation_pending", "Cancellation is being reconciled. No new payment will be started.");
    const agreement = (await db.query("SELECT * FROM quote_agreements WHERE id=$1 AND company_id=$2", [enrollment.plan_agreement_id, enrollment.company_id])).rows[0];
    if (!agreement) fail("plan_agreement_unavailable", "The signed plan agreement was not found.");
    const state = await service.state(db, agreement);
    if (state.signing !== "submitted" || ["revoked", "declined", "superseded", "expired"].includes(state.decision)) fail("plan_signatures_required", "Complete every required plan signature before payment setup.");
    // Authorization is the preserved signed plan packet, never a checkbox in a
    // billing request. The parent builds this text into every automatic offer.
    if (automatic(enrollment) && !/authoriz/i.test(enrollment.snapshot.financial_text || "")) fail("plan_automatic_authorization_missing", "The plan agreement must explicitly authorize automatic payments.");
    return agreement;
  }
  async function bindAccount(enrollment) {
    const ready = await service.validatePaymentReadiness(pool, enrollment.company_id);
    if (enrollment.connected_account_id && (enrollment.connected_account_id !== ready.account_id || enrollment.stripe_livemode !== ready.livemode)) fail("plan_account_changed", "The plan payment account or environment changed. Staff must review it before continuing.");
    await pool.query("UPDATE agreement_plan_enrollments SET connected_account_id=$2,stripe_livemode=$3 WHERE id=$1 AND connected_account_id IS NULL", [enrollment.id, ready.account_id, ready.livemode]);
    return load(enrollment.id);
  }
  async function command(enrollment, key, kind, parameters, create, retrieve) {
    const parameterHash = quoteContentHash(parameters);
    const row = await transaction(pool, async db => {
      await lock(db, enrollment);
      const current=await load(enrollment.id,db);
      if((current.cancel_requested_at||current.canceled_at)&&!["invoice.void","invoice.delete","checkout.expire"].includes(kind)) fail("plan_cancellation_pending","Cancellation is being reconciled. No new provider request will be started.");
      await db.query(`INSERT INTO agreement_plan_provider_commands(id,enrollment_id,command_key,kind,parameters,parameters_hash,connected_account_id,livemode,created_at)
        VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9) ON CONFLICT(enrollment_id,command_key) DO NOTHING`, [randomUUID(), enrollment.id, key, kind, JSON.stringify(parameters), parameterHash, enrollment.connected_account_id, enrollment.stripe_livemode, now()]);
      const saved = (await db.query("SELECT * FROM agreement_plan_provider_commands WHERE enrollment_id=$1 AND command_key=$2", [enrollment.id, key])).rows[0];
      if (saved.parameters_hash !== parameterHash || saved.connected_account_id !== enrollment.connected_account_id || saved.livemode !== enrollment.stripe_livemode) fail("plan_billing_command_changed", "The saved payment request changed. Staff must review it.");
      return saved;
    });
    if (row.result_id) return retrieve(row.result_id);
    if (row.state === "review" || now().getTime() - new Date(row.created_at).getTime() > 23 * 3600000) {
      await pool.query("UPDATE agreement_plan_provider_commands SET state='review',error_code='provider_outcome_unknown' WHERE id=$1", [row.id]);
      fail("plan_billing_review_required", "A prior payment setup result needs staff review. No replacement charge was created.");
    }
    let result;
    try { result = await create(row.parameters, { ...options(enrollment), idempotencyKey: `wolfcrm-plan:${row.livemode ? "live" : "test"}:${row.id}` }); }
    catch (error) {
      await pool.query("UPDATE agreement_plan_provider_commands SET error_code=$2 WHERE id=$1", [row.id, error?.type === "StripeCardError" ? "customer_action_required" : "provider_retry"]);
      throw error;
    }
    if (!result?.id || (typeof result.livemode === "boolean" && result.livemode !== enrollment.stripe_livemode)) fail("plan_provider_scope_mismatch", "The provider returned a different payment environment.");
    await pool.query("UPDATE agreement_plan_provider_commands SET result_id=$2,state='complete',completed_at=now(),error_code=NULL WHERE id=$1", [row.id, result.id]);
    return result;
  }
  async function customer(enrollment) {
    if (enrollment.stripe_customer_id) return enrollment;
    const value = await command(enrollment, "customer", "customer.create", { metadata: { wolfcrm_enrollment_id: enrollment.id, company_id: enrollment.company_id } },
      (params, opts) => stripe().customers.create(params, opts), customerID => stripe().customers.retrieve(customerID, {}, options(enrollment)));
    if (value.deleted) fail("plan_customer_unavailable", "This plan's saved payment customer is unavailable.");
    await pool.query("UPDATE agreement_plan_enrollments SET stripe_customer_id=$2 WHERE id=$1 AND stripe_customer_id IS NULL", [enrollment.id, value.id]);
    return load(enrollment.id);
  }
  async function reconcileSetup(enrollment, setup) {
    if (!setup.session_id) return setup;
    const session = await stripe().checkout.sessions.retrieve(setup.session_id, { expand: ["setup_intent.payment_method"] }, options(enrollment));
    if (session.livemode !== enrollment.stripe_livemode || objectID(session.customer) !== enrollment.stripe_customer_id || session.mode !== "setup") fail("plan_setup_scope_mismatch", "Payment setup did not match the signed plan.");
    let intent = session.setup_intent;
    if (typeof intent === "string") intent = await stripe().setupIntents.retrieve(intent, { expand: ["payment_method"] }, options(enrollment));
    let state = session.status === "expired" ? "expired" : "open";
    if (intent?.status === "processing") state = "processing";
    if (intent?.status === "succeeded") {
      const method = typeof intent.payment_method === "string" ? await stripe().paymentMethods.retrieve(intent.payment_method, {}, options(enrollment)) : intent.payment_method;
      if (intent.livemode !== enrollment.stripe_livemode || objectID(intent.customer) !== enrollment.stripe_customer_id || !method || objectID(method.customer) !== enrollment.stripe_customer_id || method.livemode !== enrollment.stripe_livemode || method.type !== "card") fail("plan_method_scope_mismatch", "The authorized card must belong to this plan's connected payment customer.");
      state = "succeeded";
      await transaction(pool, async db => {
        await lock(db, enrollment);
        await db.query("UPDATE agreement_plan_enrollments SET stripe_payment_method_id=$2,card_metadata=$3::jsonb,updated_at=now() WHERE id=$1", [enrollment.id, method.id, JSON.stringify({ brand: method.card?.brand || null, last4: method.card?.last4 || null, exp_month: method.card?.exp_month || null, exp_year: method.card?.exp_year || null })]);
        await service.event(db, enrollment.plan_agreement_id, "plan_card_authorized", { request_id: setup.id, request_hash: method.id, payload: { enrollment_id: enrollment.id, setup_id: setup.id, brand: method.card?.brand || null, last4: method.card?.last4 || null } });
      });
    }
    return (await pool.query("UPDATE agreement_plan_setups SET state=$2,setup_intent_id=$3,updated_at=now() WHERE id=$1 RETURNING *", [setup.id, state, objectID(intent)])).rows[0];
  }
  async function setupCard(enrollment, requestID, update = false) {
    let setup = (await pool.query("SELECT * FROM agreement_plan_setups WHERE enrollment_id=$1 AND state IN ('creating','open','processing') ORDER BY created_at DESC LIMIT 1", [enrollment.id])).rows[0];
    if (setup?.session_id) setup = await reconcileSetup(enrollment, setup);
    if (!update && (await load(enrollment.id)).stripe_payment_method_id) return { status: "succeeded", url: null };
    if (!setup || !["creating", "open", "processing"].includes(setup.state)) setup = await transaction(pool, async db => {
      await lock(db, enrollment);
      const active = (await db.query("SELECT * FROM agreement_plan_setups WHERE enrollment_id=$1 AND state IN ('creating','open','processing')", [enrollment.id])).rows[0];
      if (active) return active;
      const prior = (await db.query("SELECT * FROM agreement_plan_setups WHERE enrollment_id=$1 AND request_id=$2", [enrollment.id, requestID])).rows[0];
      if (prior) return prior;
      return (await db.query("INSERT INTO agreement_plan_setups(id,enrollment_id,request_id,connected_account_id,livemode,customer_id) VALUES($1,$2,$3,$4,$5,$6) RETURNING *", [randomUUID(), enrollment.id, requestID, enrollment.connected_account_id, enrollment.stripe_livemode, enrollment.stripe_customer_id])).rows[0];
    });
    if (!setup.session_id) {
      const agreement = (await pool.query("SELECT * FROM quote_agreements WHERE id=$1", [enrollment.base_agreement_id])).rows[0];
      const url = service.customerURL(agreement);
      const params = { mode: "setup", currency: "usd", customer: enrollment.stripe_customer_id, payment_method_types: ["card"], success_url: `${url}?plan_return=1`, cancel_url: url,
        metadata: { wolfcrm_enrollment_id: enrollment.id, wolfcrm_plan_setup_id: setup.id }, setup_intent_data: { metadata: { wolfcrm_enrollment_id: enrollment.id, wolfcrm_plan_setup_id: setup.id } } };
      const session = await command(enrollment, `setup:${setup.id}`, "checkout.setup", params, (p, o) => stripe().checkout.sessions.create(p, o), sessionID => stripe().checkout.sessions.retrieve(sessionID, {}, options(enrollment)));
      setup = (await pool.query("UPDATE agreement_plan_setups SET session_id=$2,url=$3,state='open',updated_at=now() WHERE id=$1 RETURNING *", [setup.id, session.id, session.url])).rows[0];
    }
    setup = await reconcileSetup(enrollment, setup);
    return { status: setup.state, url: setup.state === "open" ? setup.url : null, kind: "setup" };
  }
  async function ensureObligations(enrollment, existingDB = null) {
    const offer = enrollment.snapshot, billing = offer.configuration.billing;
    const reserve = async db => {
      await lock(db, enrollment);
      const entries = ["calendar_installments", "prepaid"].includes(billing.mode) ? offer.billing_schedule.map(item => ({ ...item, kind: billing.mode, key: `installment:${item.sequence}` }))
        : billing.enrollment_fee_cents > 0 ? [{ sequence: 0, due_date: offer.effective_date, amount_cents: billing.enrollment_fee_cents, kind: "enrollment_fee", key: "enrollment_fee" }] : [];
      if (billing.mode === "calendar_recurring") {
        const last = (await db.query("SELECT COALESCE(max(sequence),0)::integer AS sequence, max(due_date)::text AS last_due FROM agreement_plan_billing_obligations WHERE enrollment_id=$1 AND kind='calendar_recurring'",[enrollment.id])).rows[0];
        const date=await today(enrollment,db);
        for(let sequence=last.sequence+1;(!last.last_due || last.last_due<=date) && sequence<=Math.min(last.sequence+90,3650);sequence++) {
          const due=advancePlanDate(offer.first_charge_date,billing.interval,sequence-1);
          entries.push({sequence,due_date:due,amount_cents:offer.future_visit.total_cents,kind:"calendar_recurring",key:`calendar:${sequence}`});
          if(due>date) break;
        }
      }
      if (entries.some(item => item.amount_cents > 0 && item.amount_cents < 50)) fail("plan_amount_below_minimum", "Online plan charges must be at least $0.50, or exactly zero. Update the tier before offering it.");
      for (const item of entries) await db.query("INSERT INTO agreement_plan_billing_obligations(id,enrollment_id,obligation_key,kind,sequence,due_date,amount_cents) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(enrollment_id,obligation_key) DO NOTHING", [randomUUID(), enrollment.id, item.key, item.kind, item.sequence, item.due_date, item.amount_cents]);
      if (enrollment.service_plan_id && ["automatic_per_visit", "manual_per_visit"].includes(billing.mode)) {
        const visits = (await db.query(`SELECT v.*,j.finished_at FROM agreement_plan_visits v JOIN schedule_events j ON j.id=v.job_id AND j.company_id=$2 AND j.contact_id=$3 AND j.service_plan_id=v.service_plan_id
          WHERE v.enrollment_id=$1 AND v.state<>'skipped' AND ($4='scheduled' OR (v.completed_at IS NOT NULL AND j.finished_at IS NOT NULL))`, [enrollment.id, enrollment.company_id, enrollment.contact_id, billing.collect_on])).rows;
        for (const visit of visits) await db.query("INSERT INTO agreement_plan_billing_obligations(id,enrollment_id,obligation_key,kind,sequence,due_date,amount_cents,job_id) VALUES($1,$2,$3,'visit',$4,$5,$6,$7) ON CONFLICT(enrollment_id,obligation_key) DO NOTHING", [randomUUID(), enrollment.id, `visit:${visit.id}`, visit.sequence, await today(enrollment, db), offer.future_visit.total_cents, visit.job_id]);
      }
    };
    if(existingDB) await reserve(existingDB); else await transaction(pool,reserve);
  }
  async function reservePayment(enrollment, obligation) {
    if (obligation.payment_record_id) return obligation;
    return transaction(pool, async db => {
      await lock(db, enrollment);
      const current = (await db.query("SELECT * FROM agreement_plan_billing_obligations WHERE id=$1 FOR UPDATE", [obligation.id])).rows[0];
      if (current.payment_record_id) return current;
      const owner = (await db.query("SELECT owner_user_id FROM companies WHERE id=$1", [enrollment.company_id])).rows[0]?.owner_user_id;
      const paymentID = randomUUID();
      await db.query(`INSERT INTO payment_records(id,user_id,company_id,contact_id,service_plan_id,enrollment_id,agreement_id,job_id,payment_type,status,amount_cents,currency,stripe_connected_account_id,stripe_customer_id,stripe_livemode,description)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,'service_plan','pending',$9,'usd',$10,$11,$12,$13)`, [paymentID, owner, enrollment.company_id, enrollment.contact_id, enrollment.service_plan_id, enrollment.id, enrollment.plan_agreement_id, current.job_id, current.amount_cents, enrollment.connected_account_id, enrollment.stripe_customer_id, enrollment.stripe_livemode, `${enrollment.snapshot.configuration.name}: ${current.kind} ${current.sequence}`]);
      return (await db.query("UPDATE agreement_plan_billing_obligations SET payment_record_id=$2 WHERE id=$1 RETURNING *", [current.id, paymentID])).rows[0];
    });
  }
  async function reconcileInvoice(enrollment, obligation) {
    if (!obligation.invoice_id) return obligation;
    const invoice = await stripe().invoices.retrieve(obligation.invoice_id, { expand: ["payment_intent.latest_charge"] }, options(enrollment));
    if (invoice.livemode !== enrollment.stripe_livemode || objectID(invoice.customer) !== enrollment.stripe_customer_id || invoice.currency !== "usd" || (invoice.status !== "draft" && (invoice.total !== obligation.amount_cents || invoice.amount_due !== obligation.amount_cents))) fail("plan_invoice_scope_mismatch", "The provider invoice differs from the signed plan amount. Staff must review it.");
    let intent = invoice.payment_intent;
    if (typeof intent === "string") intent = await stripe().paymentIntents.retrieve(intent, { expand: ["latest_charge"] }, options(enrollment));
    if (intent && (intent.livemode !== enrollment.stripe_livemode || intent.amount !== obligation.amount_cents || intent.currency !== "usd" || objectID(intent.customer) !== enrollment.stripe_customer_id)) fail("plan_payment_scope_mismatch", "Payment confirmation differs from the signed invoice.");
    const charge = intent?.latest_charge, refund = Number(typeof charge === "object" ? charge?.amount_refunded || 0 : 0), disputed = Boolean(typeof charge === "object" && charge?.disputed);
    if (!Number.isSafeInteger(refund) || refund < 0 || refund > obligation.amount_cents) fail("plan_refund_amount_invalid", "The provider refund amount needs review.");
    let state = invoice.status === "draft" ? "creating" : invoice.status === "void" ? "canceled" : invoice.status === "uncollectible" ? "review" : intent?.status === "processing" ? "processing" : "open";
    if (invoice.status === "paid" && invoice.amount_paid === obligation.amount_cents && (obligation.amount_cents === 0 || intent?.status === "succeeded")) state = "succeeded";
    if (refund > 0 || disputed) state = "review";
    return transaction(pool, async db => {
      await lock(db, enrollment);
      const old = (await db.query("SELECT * FROM agreement_plan_billing_obligations WHERE id=$1", [obligation.id])).rows[0];
      const payment = (await db.query("SELECT * FROM payment_records WHERE id=$1", [obligation.payment_record_id])).rows[0];
      if (old.state === "review" || payment?.stripe_dispute_status || Number(payment?.refunded_amount_cents || 0) > 0) state = "review";
      if (old.state === "succeeded" && !["succeeded", "review"].includes(state)) state = "succeeded";
      const effectiveRefund = Math.max(refund, Number(payment?.refunded_amount_cents || 0));
      const status = disputed || payment?.stripe_dispute_status ? "disputed" : effectiveRefund >= obligation.amount_cents && effectiveRefund > 0 ? "refunded" : effectiveRefund > 0 ? "partially_refunded" : state === "succeeded" ? "succeeded" : state === "processing" ? "processing" : state === "canceled" ? "cancelled" : intent?.status === "requires_payment_method" && obligation.attempted_at ? "failed" : "pending";
      await db.query(`UPDATE payment_records SET stripe_invoice_id=$2,stripe_payment_intent_id=COALESCE($3,stripe_payment_intent_id),stripe_charge_id=COALESCE($4,stripe_charge_id),status=CASE WHEN status IN ('succeeded','refunded','partially_refunded','disputed') AND $5 IN ('pending','failed','cancelled','processing') THEN status ELSE $5 END,
        refunded_amount_cents=GREATEST(refunded_amount_cents,$6),refund_amount_known=true,stripe_dispute_status=CASE WHEN $7 THEN COALESCE(stripe_dispute_status,'needs_review') ELSE stripe_dispute_status END,
        paid_at=CASE WHEN $8 THEN COALESCE(paid_at,now()) ELSE paid_at END,receipt_url=COALESCE($9,receipt_url),updated_at=now() WHERE id=$1`, [obligation.payment_record_id, invoice.id, objectID(intent), objectID(charge), status, refund, disputed, state === "succeeded", typeof charge === "object" ? charge?.receipt_url : null]);
      const actionRequired=intent?.status==='requires_action'||intent?.last_payment_error?.code==='authentication_required'||intent?.last_payment_error?.decline_code==='authentication_required';
      const paymentStatus=state==='review'?'review':state==='succeeded'?'succeeded':actionRequired?'requires_action':intent?.status==='requires_payment_method'&&old.attempted_at?'failed':state;
      const attention=['review','requires_action','failed'].includes(paymentStatus);
      const updated = (await db.query("UPDATE agreement_plan_billing_obligations SET state=$2,payment_intent_id=COALESCE($3,payment_intent_id),hosted_invoice_url=$4,invoice_pdf=$5,payment_status=$6,error_code=$8,attention_since=CASE WHEN $7 THEN COALESCE(attention_since,now()) ELSE NULL END,next_reconcile_at=now()+interval '5 minutes',updated_at=now() WHERE id=$1 RETURNING *,due_date::text AS due_date", [obligation.id, state, objectID(intent), invoice.hosted_invoice_url || null, invoice.invoice_pdf || null,paymentStatus,attention,attention ? (actionRequired ? 'authentication_required' : intent?.last_payment_error?.decline_code || intent?.last_payment_error?.code || paymentStatus) : null])).rows[0];
      if (state !== old.state || paymentStatus!==old.payment_status) await service.event(db, enrollment.base_agreement_id, state === "succeeded" ? "plan_payment_succeeded" : state === "review" ? "plan_payment_review_required" : attention ? "plan_payment_failed" : "plan_payment_updated", { payload: { enrollment_id: enrollment.id, obligation_id: obligation.id, payment_record_id: obligation.payment_record_id, amount_cents: obligation.amount_cents, state,payment_status:paymentStatus } });
      return updated;
    });
  }
  async function createInvoice(enrollment, obligation) {
    const currentEnrollment = await load(enrollment.id);
    const currentObligation = (await pool.query("SELECT * FROM agreement_plan_billing_obligations WHERE id=$1",[obligation.id])).rows[0];
    if (currentEnrollment.canceled_at || currentEnrollment.cancel_requested_at || currentObligation.state === "canceled") return currentObligation;
    obligation = await reservePayment(enrollment, currentObligation);
    const metadata = { wolfcrm_enrollment_id: enrollment.id, wolfcrm_plan_obligation_id: obligation.id };
    const retrieve = invoiceID => stripe().invoices.retrieve(invoiceID, {}, options(enrollment));
    if (!obligation.invoice_id) {
      const params = { customer: enrollment.stripe_customer_id, currency: "usd", auto_advance: false, collection_method: "charge_automatically", pending_invoice_items_behavior: "exclude", automatic_tax: { enabled: false }, discounts: [], default_tax_rates: [], metadata };
      const feeBasisPoints=Math.max(0,Math.min(10000,parseInt(env.STRIPE_PLATFORM_FEE_BPS||"0",10)||0));
      if(feeBasisPoints>0)params.application_fee_amount=Math.floor(obligation.amount_cents*feeBasisPoints/10000);
      if (automatic(enrollment) && enrollment.stripe_payment_method_id) params.default_payment_method = enrollment.stripe_payment_method_id;
      const invoice = await command(enrollment, `invoice:${obligation.id}`, "invoice.create", params, (p, o) => stripe().invoices.create(p, o), retrieve);
      obligation = (await pool.query("UPDATE agreement_plan_billing_obligations SET invoice_id=$2,state='creating' WHERE id=$1 RETURNING *", [obligation.id, invoice.id])).rows[0];
    }
    const afterCreate = await load(enrollment.id);
    if (afterCreate.canceled_at || afterCreate.cancel_requested_at) return (await pool.query("SELECT * FROM agreement_plan_billing_obligations WHERE id=$1",[obligation.id])).rows[0];
    let invoice = await retrieve(obligation.invoice_id);
    if (invoice.status === "draft") {
      if (!obligation.invoice_item_id) {
        const item = await command(enrollment, `item:${obligation.id}`, "invoice_item.create", { customer: enrollment.stripe_customer_id, invoice: invoice.id, amount: obligation.amount_cents, currency: "usd", discountable: false, description: `${enrollment.snapshot.configuration.name} — ${obligation.kind} ${obligation.sequence}`, metadata }, (p, o) => stripe().invoiceItems.create(p, o), itemID => stripe().invoiceItems.retrieve(itemID, {}, options(enrollment)));
        obligation = (await pool.query("UPDATE agreement_plan_billing_obligations SET invoice_item_id=$2 WHERE id=$1 RETURNING *", [obligation.id, item.id])).rows[0];
      }
      invoice = await retrieve(obligation.invoice_id);
      if (invoice.total !== obligation.amount_cents) fail("plan_invoice_total_changed", "The invoice total changed before finalization. No automatic charge was started.");
      await command(enrollment, `finalize:${obligation.id}`, "invoice.finalize", { invoice_id: invoice.id, auto_advance: false }, (p, o) => stripe().invoices.finalizeInvoice(p.invoice_id, { auto_advance: false }, o), retrieve);
    }
    return reconcileInvoice(enrollment, obligation);
  }
  async function collect(enrollment, obligation, { retry = false } = {}) {
    obligation = await createInvoice(enrollment, obligation);
    if (!automatic(enrollment) || !enrollment.stripe_payment_method_id || obligation.state !== "open") return obligation;
    if (obligation.attempted_at && !retry) {
      const pending = (await pool.query("SELECT state,error_code FROM agreement_plan_provider_commands WHERE enrollment_id=$1 AND command_key=$2", [enrollment.id, `pay:${obligation.id}:${enrollment.stripe_payment_method_id}`])).rows[0];
      if (pending?.state === "complete" || pending?.error_code === "customer_action_required") return obligation;
    }
    const fresh = await load(enrollment.id);
    const membership = fresh.service_plan_id ? (await pool.query("SELECT status FROM service_plans WHERE id=$1", [fresh.service_plan_id])).rows[0] : null;
    if (fresh.canceled_at || fresh.cancel_requested_at || membership && !["active", "expired"].includes(membership.status)) return obligation;
    const paymentMethod = await stripe().paymentMethods.retrieve(fresh.stripe_payment_method_id, {}, options(fresh));
    if (objectID(paymentMethod.customer) !== fresh.stripe_customer_id || paymentMethod.livemode !== fresh.stripe_livemode) fail("plan_card_unavailable", "Update the authorized card before continuing.");
    const params = { invoice_id: obligation.invoice_id, off_session: true, payment_method: fresh.stripe_payment_method_id };
    // One automatic attempt per invoice/card. Further authentication/retry uses
    // the same invoice, never another collectible obligation.
    await pool.query("UPDATE agreement_plan_billing_obligations SET attempted_at=COALESCE(attempted_at,now()) WHERE id=$1", [obligation.id]);
    try { await command(fresh, `pay:${obligation.id}:${fresh.stripe_payment_method_id}`, "invoice.pay", params, (p, o) => stripe().invoices.pay(p.invoice_id, { off_session: true, payment_method: p.payment_method }, o), invoiceID => stripe().invoices.retrieve(invoiceID, {}, options(fresh))); }
    catch (error) { if (error instanceof QuoteContractError) throw error; /* Canonical invoice tells action-required/failed/processing truth. */ }
    return reconcileInvoice(fresh, obligation);
  }
  async function prerequisites(db, enrollment) {
    const billing = enrollment.snapshot.configuration.billing;
    if (billing.mode === "manual_per_visit" && !requiresCard(enrollment) && billing.enrollment_fee_cents === 0) return { ready: true };
    if (!enrollment.connected_account_id || enrollment.stripe_livemode !== stripePaymentMode(env)) return { ready: false };
    if (requiresCard(enrollment) && !enrollment.stripe_payment_method_id) return { ready: false };
    const problems = (await db.query("SELECT 1 FROM agreement_plan_provider_commands WHERE enrollment_id=$1 AND state='review' LIMIT 1", [enrollment.id])).rowCount;
    if (problems) return { ready: false };
    const date = await today(enrollment, db);
    const obligations = (await db.query("SELECT *,due_date::text AS due_date FROM agreement_plan_billing_obligations WHERE enrollment_id=$1 ORDER BY sequence", [enrollment.id])).rows;
    if (["calendar_installments", "prepaid"].includes(billing.mode) && !obligations.length) return { ready: false };
    if (!automatic(enrollment) && billing.mode === "prepaid") return { ready: obligations.every(item => item.state === "succeeded") };
    if (billing.mode === "calendar_recurring" && billing.calendar_requires_completed_service) return {ready: obligations.filter(item=>item.kind === "enrollment_fee").every(item=>item.state === "succeeded")};
    return { ready: obligations.filter(item => item.kind === "enrollment_fee" || (item.sequence <= 1 && String(item.due_date).slice(0,10) <= date)).every(item => item.state === "succeeded") && (billing.enrollment_fee_cents === 0 || obligations.length > 0) };
  }
  async function reconcileEnrollmentCore(enrollmentID, { collectDue = true, retry = false } = {}) {
    let enrollment = await load(enrollmentID);
    if(enrollment.cancel_requested_at&&!enrollment.canceled_at)return;
    if (enrollment.canceled_at) {
      for (const obligation of (await pool.query("SELECT * FROM agreement_plan_billing_obligations WHERE enrollment_id=$1 AND invoice_id IS NOT NULL", [enrollment.id])).rows) await reconcileInvoice(enrollment, obligation);
      return;
    }
    try { await gate(enrollment); } catch (error) { if (error.code === "plan_signatures_required") return; throw error; }
    const billing = enrollment.snapshot.configuration.billing;
    if (billing.mode === "manual_per_visit" && !requiresCard(enrollment) && billing.enrollment_fee_cents === 0 && !enrollment.service_plan_id) return;
    await ensureObligations(enrollment);
    if (!enrollment.connected_account_id || !enrollment.stripe_customer_id) return;
    for (const setup of (await pool.query("SELECT * FROM agreement_plan_setups WHERE enrollment_id=$1 AND state IN ('open','processing')", [enrollment.id])).rows) await reconcileSetup(enrollment, setup);
    enrollment = await load(enrollment.id);
    const date = await today(enrollment), membership = enrollment.service_plan_id ? (await pool.query("SELECT status FROM service_plans WHERE id=$1", [enrollment.service_plan_id])).rows[0] : null;
    const obligations = (await pool.query("SELECT *,due_date::text AS due_date FROM agreement_plan_billing_obligations WHERE enrollment_id=$1 ORDER BY sequence", [enrollment.id])).rows;
    const reconciled = [];
    for (const obligation of obligations) reconciled.push(obligation.invoice_id ? await reconcileInvoice(enrollment, obligation) : obligation);
    const reviewRequired = reconciled.some(obligation => obligation.state === "review");
    for (const obligation of reconciled) {
      if (obligation.kind === "calendar_recurring" && billing.calendar_requires_completed_service) {
        const completed = (await pool.query("SELECT v.job_id FROM agreement_plan_visits v JOIN schedule_events j ON j.id=v.job_id AND j.company_id=$2 AND j.service_plan_id=v.service_plan_id WHERE v.enrollment_id=$1 AND v.sequence=$3 AND v.state='completed' AND j.finished_at IS NOT NULL",[enrollment.id,enrollment.company_id,obligation.sequence])).rows[0];
        if(!completed) continue;
        await pool.query("UPDATE agreement_plan_billing_obligations SET job_id=$2 WHERE id=$1 AND job_id IS NULL",[obligation.id,completed.job_id]);
        obligation.job_id=completed.job_id;
      }
      if (!reviewRequired && collectDue && (membership || obligation.sequence <= 1) && String(obligation.due_date).slice(0,10) <= date && ["scheduled", "creating", "open"].includes(obligation.state) && (!membership || ["active", "expired"].includes(membership.status)) && (!automatic(enrollment) || enrollment.stripe_payment_method_id)) await collect(enrollment, obligation, { retry });
    }
    if (enrollment.service_plan_id) {
      await pool.query("UPDATE payment_records SET service_plan_id=$2 WHERE enrollment_id=$1 AND service_plan_id IS NULL",[enrollment.id,enrollment.service_plan_id]);
      const review = (await pool.query("SELECT 1 FROM agreement_plan_billing_obligations WHERE enrollment_id=$1 AND state='review' LIMIT 1", [enrollment.id])).rowCount;
      if (review) await pool.query("UPDATE service_plans SET status='past_due',updated_at=now() WHERE id=$1 AND status='active'", [enrollment.service_plan_id]);
    }
  }
  async function reconcileEnrollment(enrollmentID,options) {
    try {
      const result=await reconcileEnrollmentCore(enrollmentID,options);
      await pool.query('UPDATE agreement_plan_enrollments SET billing_error_code=NULL,billing_error_since=NULL WHERE id=$1 AND (cancel_requested_at IS NULL OR canceled_at IS NOT NULL)',[enrollmentID]);
      return result;
    } catch(error) {
      await pool.query('UPDATE agreement_plan_enrollments SET billing_error_code=$2,billing_error_since=COALESCE(billing_error_since,now()) WHERE id=$1',[enrollmentID,error instanceof QuoteContractError?error.code:'provider_reconciliation_failed']);
      throw error;
    }
  }
  async function followupContext(db,row) {
    const issue=(await db.query(`SELECT occurrence,started FROM (
      SELECT o.id::text AS occurrence,o.attention_since AS started FROM agreement_plan_billing_obligations o JOIN agreement_plan_enrollments e ON e.id=o.enrollment_id WHERE e.company_id=$1 AND e.base_agreement_id=$2 AND o.attention_since IS NOT NULL
      UNION ALL SELECT c.id::text,c.created_at FROM agreement_plan_provider_commands c JOIN agreement_plan_enrollments e ON e.id=c.enrollment_id WHERE e.company_id=$1 AND e.base_agreement_id=$2 AND c.state='review'
      UNION ALL SELECT e.id::text||':reconcile',e.billing_error_since FROM agreement_plan_enrollments e WHERE e.company_id=$1 AND e.base_agreement_id=$2 AND e.billing_error_since IS NOT NULL
    ) issues ORDER BY started,occurrence LIMIT 1`,[row.company_id,row.id])).rows[0];
    return {plan_payment_attention:issue?.started,plan_payment_attention_occurrence:issue?.occurrence};
  }
  async function billingSummary(enrollmentID) {
    const enrollment = await load(enrollmentID);
    const obligations = (await pool.query("SELECT id,kind,sequence,due_date::text,amount_cents,state,payment_status,attention_since,hosted_invoice_url,invoice_pdf,payment_record_id,job_id,attempted_at,error_code,payment_intent_id FROM agreement_plan_billing_obligations WHERE enrollment_id=$1 ORDER BY sequence", [enrollment.id])).rows;
    const commandReview=(await pool.query("SELECT 1 FROM agreement_plan_provider_commands WHERE enrollment_id=$1 AND state='review' LIMIT 1",[enrollment.id])).rowCount>0;
    const visits = (await pool.query("SELECT id,sequence,due_date::text,job_id,state,completed_at FROM agreement_plan_visits WHERE enrollment_id=$1 ORDER BY sequence",[enrollment.id])).rows.map(visit=>{
      const obligation=obligations.find(item=>item.kind==='visit'&&item.sequence===visit.sequence);
      return {...visit,amount_cents:enrollment.snapshot.future_visit.total_cents,payment_status:obligation?.payment_status || obligation?.state || (visit.state==='completed'?'pending':'not_due'),obligation_id:obligation?.id || null};
    });
    return { visits, enrollment_id: enrollment.id, card: enrollment.card_metadata || null, obligations, next_due_date: obligations.find(item => item.state === "scheduled")?.due_date || null, needs_review: commandReview || !!enrollment.billing_error_since || obligations.some(item => item.attention_since!=null) };
  }
  async function begin(token, enrollmentID, raw = {}) {
    const { row,role } = await service.loadPublic(pool, token);
    if(role!=="customer")fail("plan_primary_customer_required","The primary customer manages this plan's billing.",403);
    let enrollment = await plans.load(pool, row, enrollmentID);
    const requestID = uuid(raw.request_id);
    if (raw.action !== undefined && !["continue", "update_card"].includes(raw.action)) fail("plan_billing_action_invalid", "Choose payment setup or update card.", 400);
    await service.rate(pool, `plan-billing:${enrollment.id}`, 30, 60); await gate(enrollment);
    const billing = enrollment.snapshot.configuration.billing;
    if (billing.mode === "manual_per_visit" && !requiresCard(enrollment) && billing.enrollment_fee_cents === 0 && raw.action !== "update_card") {
      await ensureObligations(enrollment);
      const due = (await pool.query("SELECT 1 FROM agreement_plan_billing_obligations WHERE enrollment_id=$1 AND due_date<=$2 AND state NOT IN ('succeeded','canceled') LIMIT 1",[enrollment.id,await today(enrollment)])).rowCount;
      if (!enrollment.service_plan_id || !due) { await plans.reconcileEnrollment(enrollment.id); return { status: "ready", url: null, billing: await billingSummary(enrollment.id) }; }
    }
    enrollment = await customer(await bindAccount(enrollment));
    if (requiresCard(enrollment) && (!enrollment.stripe_payment_method_id || raw.action === "update_card")) {
      const setup = await setupCard(enrollment, requestID, raw.action === "update_card");
      if (setup.status !== "succeeded") return { ...setup, billing: await billingSummary(enrollment.id) };
    } else if (raw.action === "update_card") fail("plan_card_not_required", "This plan does not authorize automatic card charges.");
    await reconcileEnrollment(enrollment.id);
    const detail = await plans.reconcileEnrollment(enrollment.id), summary = await billingSummary(enrollment.id);
    const payable = summary.obligations.find(item => ["open", "processing"].includes(item.state));
    return { status: payable?.state || (detail.state === "active" ? "ready" : "scheduled"), kind: payable ? "payment" : null, url: payable?.state === "open" ? payable.hosted_invoice_url : null, enrollment: detail, billing: summary };
  }
  async function handleWebhook(event) {
    if (!event.account || typeof event.livemode !== "boolean") return false;
    const object = event.data?.object; if (!object) return false;
    const enrollmentID = object.metadata?.wolfcrm_enrollment_id;
    const piID = object.object === "payment_intent" ? object.id : objectID(object.payment_intent);
    const invoiceID = object.object === "invoice" ? object.id : objectID(object.invoice);
    const sessionID = object.object === "checkout.session" ? object.id : null;
    const enrollments = (await pool.query(`SELECT DISTINCT e.* FROM agreement_plan_enrollments e LEFT JOIN agreement_plan_billing_obligations o ON o.enrollment_id=e.id LEFT JOIN agreement_plan_setups s ON s.enrollment_id=e.id
      WHERE e.connected_account_id=$1 AND e.stripe_livemode=$2 AND (($3::text IS NOT NULL AND e.id::text=$3) OR ($4::text IS NOT NULL AND o.payment_intent_id=$4) OR ($5::text IS NOT NULL AND o.invoice_id=$5) OR ($6::text IS NOT NULL AND s.session_id=$6))`, [event.account,event.livemode,enrollmentID||null,piID,invoiceID,sessionID])).rows;
    for (const enrollment of enrollments) {
      if (event.type.startsWith("charge.dispute.") && piID) await pool.query("UPDATE payment_records SET stripe_dispute_status=$3,status='disputed' WHERE enrollment_id=$1 AND stripe_payment_intent_id=$2", [enrollment.id,piID,object.status||"needs_review"]);
      await reconcileEnrollment(enrollment.id, { collectDue: false });
      await plans.reconcileEnrollment(enrollment.id);
    }
    return enrollments.length > 0;
  }
  async function stopUnpaidInvoices(enrollment, cancel) {
    if(cancel&&enrollment.service_plan_id){
      // Ending service is not a credit note. Materialize earned visit charges
      // and retain every issued invoice for settlement; future finite-plan
      // proration needs business review because free-form policy is not math.
      await ensureObligations(enrollment);
      for(const obligation of (await pool.query("SELECT * FROM agreement_plan_billing_obligations WHERE enrollment_id=$1 AND state NOT IN ('succeeded','canceled')",[enrollment.id])).rows){
        if(obligation.invoice_id)await reconcileInvoice(enrollment,obligation);
        else await pool.query("UPDATE agreement_plan_billing_obligations SET state='review',payment_status='cancellation_review_required',attention_since=COALESCE(attention_since,now()),error_code='cancellation_policy_review',updated_at=now() WHERE id=$1",[obligation.id]);
      }
      return;
    }
    const obligations = (await pool.query("SELECT * FROM agreement_plan_billing_obligations WHERE enrollment_id=$1 AND state NOT IN ('succeeded','canceled')", [enrollment.id])).rows;
    for (let obligation of obligations) {
      if (!obligation.invoice_id) {
        if (cancel) await pool.query("UPDATE agreement_plan_billing_obligations SET state='canceled',updated_at=now() WHERE id=$1", [obligation.id]);
        continue;
      }
      obligation = await reconcileInvoice(enrollment, obligation);
      if (["succeeded", "review", "canceled"].includes(obligation.state) || !cancel) continue;
      const invoice = await stripe().invoices.retrieve(obligation.invoice_id, {}, options(enrollment));
      try {
        if (invoice.status === "draft") {
          await command(enrollment, `delete:${obligation.id}`, "invoice.delete", { invoice_id: invoice.id }, (p,o)=>stripe().invoices.del(p.invoice_id,{},o), async invoiceID=>({id:invoiceID,deleted:true}));
          await pool.query("UPDATE agreement_plan_billing_obligations SET state='canceled',invoice_id=NULL WHERE id=$1",[obligation.id]);
          await pool.query("UPDATE payment_records SET status='cancelled' WHERE id=$1 AND status='pending'",[obligation.payment_record_id]);
        } else if (invoice.status === "open") {
          await command(enrollment, `void:${obligation.id}`, "invoice.void", { invoice_id: invoice.id }, (p,o)=>stripe().invoices.voidInvoice(p.invoice_id,{},o), invoiceID=>stripe().invoices.retrieve(invoiceID,{},options(enrollment)));
          await reconcileInvoice(enrollment, obligation);
        }
      } catch {
        // Processing payments are not refunded/canceled by an app state change.
        // Preserve the outcome and keep reconciling, even after membership end.
        await pool.query("UPDATE agreement_plan_billing_obligations SET error_code='cancellation_reconcile_pending',next_reconcile_at=now() WHERE id=$1",[obligation.id]);
      }
    }
  }
  async function changeMembership(req, suppliedPlan, action, raw = {}) {
    if (!req.companyId || suppliedPlan.company_id !== req.companyId) fail("plan_unavailable","The membership was not found.",404);
    if (!["pause","resume","cancel"].includes(action)) fail("plan_action_invalid","Choose an available membership action.",400);
    const requestID = raw.request_id ? uuid(raw.request_id) : randomUUID();
    const result = await transaction(pool, async db => {
      const enrollment = await load(suppliedPlan.enrollment_id, db); await lock(db,enrollment);
      const plan = (await db.query("SELECT * FROM service_plans WHERE id=$1 AND company_id=$2 FOR UPDATE",[suppliedPlan.id,req.companyId])).rows[0];
      if (action === "cancel" && (enrollment.canceled_at || enrollment.cancellation_effective_at)) return {plan,enrollment};
      if (action === "pause" && plan.status === "paused") return {plan,enrollment};
      if (action === "pause" && (!["active","past_due"].includes(plan.status) || plan.remaining_visits === 0)) fail("plan_cannot_pause","A canceled or exhausted membership cannot be paused and reactivated.");
      const prior = (await db.query("SELECT action FROM agreement_plan_lifecycle_requests WHERE enrollment_id=$1 AND request_id=$2",[enrollment.id,requestID])).rows[0];
      if (prior) { if(prior.action!==action)fail("plan_request_conflict","This request was used for a different membership action."); return {plan,enrollment}; }
      if (action === "pause" && !enrollment.snapshot.configuration.allow_pause) fail("plan_pause_not_allowed","The signed plan does not allow pausing. Arrange a new agreement first.");
      if (action === "resume" && plan.status !== "paused") { if(plan.status==="active")return {plan,enrollment}; fail("plan_cannot_resume","A canceled or exhausted membership requires a new signed enrollment."); }
      if (action === "resume" && automatic(enrollment)) {
        const count=(await db.query("SELECT count(*)::int AS n FROM agreement_plan_billing_obligations WHERE enrollment_id=$1 AND due_date<$2 AND state NOT IN ('succeeded','canceled')",[enrollment.id,await today(enrollment,db)])).rows[0].n;
        if(count&&!raw.confirm_overdue_collection)fail("plan_overdue_confirmation_required",`Review ${count} overdue plan invoices before resuming automatic collection.`);
      }
      let status=action==="pause"?"paused":action==="resume"?"active":"canceled";
      const notice=action==="cancel"?enrollment.snapshot.configuration.cancellation_notice_days:0;
      const effective=action==="cancel"?new Date(now().getTime()+notice*86400000):null;
      if(notice>0)status=plan.status;
      const updated=(await db.query("UPDATE service_plans SET status=$3,updated_at=now() WHERE id=$1 AND company_id=$2 RETURNING *",[plan.id,req.companyId,status])).rows[0];
      if(action==="cancel")await db.query("UPDATE agreement_plan_enrollments SET cancellation_effective_at=$2,canceled_at=CASE WHEN $3=0 THEN now() ELSE NULL END,state=CASE WHEN $3=0 THEN 'canceled' ELSE 'cancellation_scheduled' END,updated_at=now() WHERE id=$1",[enrollment.id,effective,notice]);
      await db.query("INSERT INTO agreement_plan_lifecycle_requests(enrollment_id,request_id,action) VALUES($1,$2,$3)",[enrollment.id,requestID,action]);
      await db.query("INSERT INTO service_plan_events(user_id,company_id,created_by_user_id,service_plan_id,contact_id,event_type,notes) VALUES($1,$2,$3,$4,$5,$6,$7)",[plan.user_id,req.companyId,req.userId,plan.id,plan.contact_id,action==='pause'?'paused':action==='resume'?'resumed':notice?'cancellation_scheduled':'canceled',notice?`Cancellation effective ${effective.toISOString()}`:'Updated under the signed membership policy']);
      await service.event(db,enrollment.base_agreement_id,`plan_${action}`,{actor_type:req.actorType || "staff",actor_id:req.actorType === "customer" ? "customer" : req.userId,payload:{enrollment_id:enrollment.id,service_plan_id:plan.id,cancellation_effective_at:effective?.toISOString()||null}});
      return {plan:updated,enrollment:{...enrollment,canceled_at:action==='cancel'&&!notice?now():enrollment.canceled_at,cancellation_effective_at:effective}};
    });
    if(action==='cancel'&&result.enrollment.canceled_at)await stopUnpaidInvoices(result.enrollment,true);
    return {...result.plan,cancellation_effective_at:result.enrollment.cancellation_effective_at};
  }
  async function prepareReplacement(enrollment) {
    if(!enrollment.snapshot.replaces || enrollment.service_plan_id || enrollment.canceled_at || enrollment.cancel_requested_at)return;
    try { await gate(enrollment); } catch(error) { if(error.code === "plan_signatures_required")return; throw error; }
    if(!(await prerequisites(pool,await load(enrollment.id))).ready)return;
    const prior=(await pool.query("SELECT e.*,p.id AS membership_id FROM agreement_plan_enrollments e JOIN service_plans p ON p.id=e.service_plan_id WHERE e.id=$1 AND e.company_id=$2 AND e.contact_id=$3",[enrollment.snapshot.replaces.enrollment_id,enrollment.company_id,enrollment.contact_id])).rows[0];
    if(!prior)fail("plan_replacement_unavailable","The membership being replaced needs business review.");
    if(prior.canceled_at)return;
    const plan=(await pool.query('SELECT * FROM service_plans WHERE id=$1',[prior.membership_id])).rows[0];
    await changeMembership({companyId:enrollment.company_id,userId:plan.user_id,actorType:"customer"},plan,"cancel",{request_id:enrollment.id});
  }
  async function staffSummary(req,enrollmentID) {
    const enrollment=await load(enrollmentID);
    if(enrollment.company_id!==req.companyId)fail("plan_enrollment_unavailable","The enrollment was not found.",404);
    return billingSummary(enrollment.id);
  }
  async function beginStaff(req,enrollmentID,raw) {
    const enrollment=await load(enrollmentID);
    if(enrollment.company_id!==req.companyId)fail("plan_enrollment_unavailable","The enrollment was not found.",404);
    const base=await service.loadStaff(pool,req,enrollment.base_agreement_id);
    return begin(service.makeToken(base),enrollment.id,raw);
  }
  async function processDue() {
    const ending=(await pool.query("UPDATE agreement_plan_enrollments SET canceled_at=now(),state='canceled',updated_at=now() WHERE canceled_at IS NULL AND cancellation_effective_at<=$1 RETURNING *",[now()])).rows;
    for(const enrollment of ending){await pool.query("UPDATE service_plans SET status='canceled',updated_at=now() WHERE id=$1",[enrollment.service_plan_id]);await stopUnpaidInvoices(enrollment,true);}
    const rows = (await pool.query("UPDATE agreement_plan_enrollments SET next_reconcile_at=now()+interval '5 minutes' WHERE id IN (SELECT id FROM agreement_plan_enrollments WHERE (canceled_at IS NULL OR EXISTS(SELECT 1 FROM agreement_plan_billing_obligations o WHERE o.enrollment_id=agreement_plan_enrollments.id AND o.state IN ('creating','open','processing'))) AND next_reconcile_at<=now() ORDER BY next_reconcile_at LIMIT 20 FOR UPDATE SKIP LOCKED) RETURNING id")).rows;
    for (const row of rows) { try { await reconcileEnrollment(row.id); await plans.reconcileEnrollment(row.id); } catch { await pool.query("UPDATE agreement_plan_enrollments SET next_reconcile_at=now()+interval '5 minutes' WHERE id=$1", [row.id]); } }
  }
  async function preparePendingCancellation(enrollmentID) {
    const enrollment=await load(enrollmentID);
    if(!enrollment.cancel_requested_at||enrollment.service_plan_id)fail("plan_cancel_not_pending","Request cancellation of an unactivated enrollment first.");
    const unresolved=(await pool.query("SELECT 1 FROM agreement_plan_provider_commands WHERE enrollment_id=$1 AND state<>'complete' AND kind NOT IN ('invoice.void','invoice.delete','checkout.expire') LIMIT 1",[enrollment.id])).rowCount;
    if(unresolved)return{ready:false,message:"A provider request is still unresolved. Recheck cancellation; staff must review a lost or unknown payment result."};
    for(let setup of (await pool.query("SELECT * FROM agreement_plan_setups WHERE enrollment_id=$1 AND state NOT IN ('expired','succeeded','canceled')",[enrollment.id])).rows){
      if(!setup.session_id){
        const commandResult=(await pool.query("SELECT result_id FROM agreement_plan_provider_commands WHERE enrollment_id=$1 AND command_key=$2",[enrollment.id,`setup:${setup.id}`])).rows[0];
        if(!commandResult?.result_id){await pool.query("UPDATE agreement_plan_setups SET state='canceled' WHERE id=$1",[setup.id]);continue;}
        setup=(await pool.query("UPDATE agreement_plan_setups SET session_id=$2 WHERE id=$1 RETURNING *",[setup.id,commandResult.result_id])).rows[0];
      }
      setup=await reconcileSetup(enrollment,setup);
      if(setup.state==='open'){
        await command(enrollment,`expire:${setup.id}`,"checkout.expire",{session_id:setup.session_id},(p,o)=>stripe().checkout.sessions.expire(p.session_id,{},o),sessionID=>stripe().checkout.sessions.retrieve(sessionID,{},options(enrollment)));
        setup=await reconcileSetup(enrollment,setup);
      }
      if(!['expired','succeeded','canceled'].includes(setup.state))return{ready:false,message:"Card setup is still processing. Recheck after Stripe confirms its outcome."};
    }
    for(let obligation of (await pool.query("SELECT * FROM agreement_plan_billing_obligations WHERE enrollment_id=$1 AND state<>'canceled'",[enrollment.id])).rows){
      const deletion=(await pool.query("SELECT * FROM agreement_plan_provider_commands WHERE enrollment_id=$1 AND command_key=$2",[enrollment.id,`delete:${obligation.id}`])).rows[0];
      if(deletion){
        await command(enrollment,`delete:${obligation.id}`,'invoice.delete',deletion.parameters,(p,o)=>stripe().invoices.del(p.invoice_id,{},o),async()=>({id:deletion.parameters.invoice_id}));
        await pool.query("UPDATE agreement_plan_billing_obligations SET state='canceled',invoice_id=NULL,updated_at=now() WHERE id=$1",[obligation.id]);
        if(obligation.payment_record_id)await pool.query("UPDATE payment_records SET status='cancelled' WHERE id=$1 AND status IN ('pending','failed')",[obligation.payment_record_id]);
        continue;
      }
      if(!obligation.invoice_id){
        const commandResult=(await pool.query("SELECT result_id FROM agreement_plan_provider_commands WHERE enrollment_id=$1 AND command_key=$2",[enrollment.id,`invoice:${obligation.id}`])).rows[0];
        if(commandResult?.result_id)obligation=(await pool.query("UPDATE agreement_plan_billing_obligations SET invoice_id=$2 WHERE id=$1 RETURNING *",[obligation.id,commandResult.result_id])).rows[0];
      }
      if(!obligation.invoice_id){await pool.query("UPDATE agreement_plan_billing_obligations SET state='canceled',updated_at=now() WHERE id=$1",[obligation.id]);continue;}
      const invoice=await stripe().invoices.retrieve(obligation.invoice_id,{expand:['payment_intent.latest_charge']},options(enrollment));
      if(invoice.livemode!==enrollment.stripe_livemode||objectID(invoice.customer)!==enrollment.stripe_customer_id)fail("plan_provider_scope_mismatch","The invoice belongs to a different payment customer or environment.");
      if(invoice.status==='draft'){
        await command(enrollment,`delete:${obligation.id}`,'invoice.delete',{invoice_id:invoice.id},(p,o)=>stripe().invoices.del(p.invoice_id,{},o),async()=>({id:invoice.id}));
        await pool.query("UPDATE agreement_plan_billing_obligations SET state='canceled',invoice_id=NULL,updated_at=now() WHERE id=$1",[obligation.id]);
        if(obligation.payment_record_id)await pool.query("UPDATE payment_records SET status='cancelled' WHERE id=$1 AND status IN ('pending','failed')",[obligation.payment_record_id]);
        continue;
      }
      obligation=await reconcileInvoice(enrollment,obligation);
      if(['succeeded','review','processing'].includes(obligation.state))return{ready:false,message:"This enrollment has paid, processing or adjusted money. The business must review it; no refund was made."};
      if(obligation.state!=='canceled'){
        await command(enrollment,`void:${obligation.id}`,'invoice.void',{invoice_id:invoice.id},(p,o)=>stripe().invoices.voidInvoice(p.invoice_id,{},o),invoiceID=>stripe().invoices.retrieve(invoiceID,{},options(enrollment)));
        obligation=await reconcileInvoice(enrollment,obligation);
        if(obligation.state!=='canceled')return{ready:false,message:"Stripe has not confirmed that the unpaid invoice is closed. Recheck cancellation."};
      }
    }
    return{ready:true};
  }
  return { reserveCompletedPlanBilling: ensureObligations, begin, reconcileEnrollment, prepareReplacement, planActivationPrerequisites: prerequisites, billingSummary, handleWebhook, processDue, reconcileInvoice, changeMembership, beginStaff, staffSummary,followupContext,preparePendingCancellation };
}

export async function installAgreementPlanBilling({ app,pool,service,plans,getStripe=service.getStripe,env=service.env,authRequired,requireCapability,startWorker=true,now }) {
  await installAgreementPlanBillingSchema(pool);
  const adapter = createAgreementPlanBilling({ pool,service,plans,getStripe,env,now });
  service.planActivationPrerequisites = adapter.planActivationPrerequisites;
  service.reconcilePlanBilling = adapter.reconcileEnrollment;
  service.reserveCompletedPlanBilling = (db,enrollment) => adapter.reserveCompletedPlanBilling(enrollment,db);
  service.preparePlanReplacement = adapter.prepareReplacement;
  service.planBillingFollowupContext=adapter.followupContext;
  for (const mode of ["manual_per_visit","automatic_per_visit","calendar_installments","calendar_recurring","prepaid"]) if (!plans.supportedBillingModes.includes(mode)) plans.supportedBillingModes.push(mode);
  app.locals.agreementPlanBilling = adapter;
  const route = action => async (req,res) => {
    res.set({"Cache-Control":"private, no-store","Referrer-Policy":"no-referrer"});
    if (req.method!=="GET" && !req.is("application/json")) return res.status(415).json({error:"json_required"});
    if (req.method!=="GET" && req.headers.origin && req.headers.origin!==env.QUOTE_PUBLIC_BASE_URL?.replace(/\/$/,"")) return res.status(403).json({error:"origin_not_allowed"});
    try { res.json(await action(req)); }
    catch(error) { if(error instanceof QuoteContractError) return res.status(error.status).json({error:error.code,message:error.message}); console.error("[plan-billing] operation pending",{code:error?.code||"provider_unavailable"}); res.status(502).json({error:"plan_billing_unavailable",message:"Payment setup could not be confirmed. Your signed agreement is saved; please try again."}); }
  };
  app.post("/api/public/agreements/:token/enrollments/:id/billing",route(req=>adapter.begin(req.params.token,req.params.id,req.body)));
  app.get("/api/public/agreements/:token/enrollments/:id/billing",route(async req=>{const {row}=await service.loadPublic(pool,req.params.token);await plans.load(pool,row,req.params.id);return adapter.billingSummary(req.params.id);}));
  if(authRequired && requireCapability) {
    app.post("/api/service-plan-enrollments/:id/billing",authRequired,requireCapability("payments.collect"),route(req=>adapter.beginStaff(req,req.params.id,req.body)));
    app.get("/api/service-plan-enrollments/:id/billing",authRequired,requireCapability("payments.view"),route(req=>adapter.staffSummary(req,req.params.id)));
  }
  if(startWorker)setInterval(()=>adapter.processDue().catch(()=>{}),60000).unref?.();
  return adapter;
}
