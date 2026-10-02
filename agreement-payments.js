import { randomUUID } from "node:crypto";
import { QuoteContractError } from "./quote-contract-domain.js";
import { createAgreementOfflineRecorder, installAgreementOfflinePaymentSchema } from "./agreement-offline-payments.js";

const fail = (code, message, status = 409) => { throw new QuoteContractError(code, message, status); };
const activeStates = ["creating", "open", "processing", "review"];
const settledStates = ["succeeded", "paid", "partially_refunded", "refunded"];
const id = (value) => {
  if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) fail("payment_request_invalid", "Use a valid payment request ID.", 400);
  return value.toLowerCase();
};
const objectID = (value) => typeof value === "string" ? value : value?.id || null;
const scopeKey = (row) => row.quote_id ? `quote:${row.quote_id}` : `agreement:${row.id}`;
const providerError = () => new QuoteContractError("payment_provider_unavailable", "Payment confirmation is temporarily unavailable. Your records are saved; please try again.", 502);

export function stripePaymentMode(env) {
  const keyMode = /^(?:sk|rk)_(test|live)_/.exec(env.STRIPE_SECRET_KEY || "")?.[1];
  const mode = env.STRIPE_MODE || keyMode;
  if (!["test", "live"].includes(mode) || (keyMode && keyMode !== mode)) fail("stripe_mode_not_configured", "Configure a consistent Stripe test or live environment before collecting payments.", 503);
  return mode === "live";
}

export async function installAgreementPaymentSchema(pool) {
  await pool.query(`
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS agreement_id UUID;
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS quote_id UUID;
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS job_id TEXT;
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS paid_at TIMESTAMPTZ;
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS refunded_amount_cents BIGINT NOT NULL DEFAULT 0;
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS refunded_at TIMESTAMPTZ;
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS refund_amount_known BOOLEAN NOT NULL DEFAULT true;
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS stripe_charge_id TEXT;
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS stripe_livemode BOOLEAN;
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS stripe_dispute_status TEXT;
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS receipt_url TEXT;
    CREATE INDEX IF NOT EXISTS payment_records_quote_idx ON payment_records(company_id,quote_id) WHERE quote_id IS NOT NULL;
    CREATE TABLE IF NOT EXISTS agreement_payment_obligations (
      id UUID PRIMARY KEY, company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
      agreement_id UUID NOT NULL REFERENCES quote_agreements(id) ON DELETE RESTRICT,
      kind TEXT NOT NULL CHECK(kind IN ('deposit','balance')), amount_cents INTEGER NOT NULL CHECK(amount_cents >= 0),
      currency TEXT NOT NULL CHECK(currency='usd'), packet_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(agreement_id,kind)
    );
    CREATE TABLE IF NOT EXISTS agreement_payment_attempts (
      id UUID PRIMARY KEY, company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
      agreement_id UUID NOT NULL REFERENCES quote_agreements(id) ON DELETE RESTRICT,
      obligation_id UUID NOT NULL REFERENCES agreement_payment_obligations(id) ON DELETE RESTRICT,
      payment_record_id UUID NOT NULL UNIQUE REFERENCES payment_records(id) ON DELETE RESTRICT,
      collection_key TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('deposit','balance')),
      transport TEXT NOT NULL CHECK(transport IN ('checkout','payment_sheet')),
      connected_account_id TEXT NOT NULL, livemode BOOLEAN NOT NULL,
      amount_cents INTEGER NOT NULL CHECK(amount_cents > 0), currency TEXT NOT NULL CHECK(currency='usd'),
      state TEXT NOT NULL CHECK(state IN ('creating','open','processing','succeeded','expired','failed','canceled','review')),
      create_parameters JSONB NOT NULL, checkout_session_id TEXT, payment_intent_id TEXT,
      checkout_url TEXT, expires_at TIMESTAMPTZ, failure_code TEXT,
      reconcile_after TIMESTAMPTZ NOT NULL DEFAULT now(), reconciled_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS agreement_payment_active_scope_idx ON agreement_payment_attempts(company_id,collection_key)
      WHERE state IN ('creating','open','processing');
    CREATE UNIQUE INDEX IF NOT EXISTS agreement_payment_session_idx ON agreement_payment_attempts(connected_account_id,livemode,checkout_session_id) WHERE checkout_session_id IS NOT NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS agreement_payment_intent_idx ON agreement_payment_attempts(connected_account_id,livemode,payment_intent_id) WHERE payment_intent_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS agreement_payment_reconcile_idx ON agreement_payment_attempts(reconcile_after) WHERE state IN ('creating','open','processing','review');
    CREATE INDEX IF NOT EXISTS agreement_payment_agreement_idx ON agreement_payment_attempts(agreement_id,created_at);
    CREATE TABLE IF NOT EXISTS agreement_payment_requests (
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT, request_id UUID NOT NULL,
      agreement_id UUID NOT NULL REFERENCES quote_agreements(id) ON DELETE RESTRICT,
      kind TEXT NOT NULL, transport TEXT NOT NULL,
      attempt_id UUID NOT NULL REFERENCES agreement_payment_attempts(id) ON DELETE RESTRICT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(company_id,request_id)
    );
  `);
  await installAgreementOfflinePaymentSchema(pool);
}

async function transaction(pool, work) {
  const db = await pool.connect();
  try { await db.query("BEGIN"); const result = await work(db); await db.query("COMMIT"); return result; }
  catch (error) { await db.query("ROLLBACK"); throw error; }
  finally { db.release(); }
}

export function createAgreementPayments({ pool, service, getStripe = service.getStripe, env = service.env, now = () => new Date() }) {
  const mode = () => stripePaymentMode(env);
  function stripe() { const client = getStripe(); if (!client) fail("stripe_not_configured", "Payments are not configured. Contact the business.", 503); return client; }
  const providerOptions = (attempt) => ({ stripeAccount: attempt.connected_account_id });
  const createOptions = (attempt, suffix = "") => ({ ...providerOptions(attempt), idempotencyKey: `wolfcrm-agreement:${attempt.livemode ? "live" : "test"}:${attempt.id}${suffix}` });
  async function paymentReadiness(db, companyId, amountCents = null) {
    if (amountCents !== null && amountCents > 0 && amountCents < 50) fail("payment_below_minimum", "The required online deposit must be at least $0.50. Adjust this quote's deposit before publishing.");
    const settings = (await db.query(`SELECT bs.*,c.owner_user_id FROM companies c JOIN business_settings bs ON bs.user_id=c.owner_user_id AND bs.company_id=c.id WHERE c.id=$1`, [companyId])).rows[0];
    if (!settings?.stripe_account_id) fail("stripe_not_connected", "Connect the business's Stripe account in Payments before requiring online payment.");
    const account = await stripe().accounts.retrieve(settings.stripe_account_id);
    if (!account.charges_enabled || account.capabilities?.card_payments === "inactive") fail("stripe_charges_not_enabled", "Complete Stripe onboarding and payment verification before collecting this payment.");
    return { account_id: settings.stripe_account_id, livemode: mode(), owner_user_id: settings.owner_user_id };
  }
  async function ledger(db, row) {
    return (await db.query(`SELECT p.*,r.method AS offline_method,r.reference AS offline_reference,r.recorded_at AS offline_recorded_at
      FROM payment_records p LEFT JOIN agreement_offline_payment_receipts r ON r.payment_record_id=p.id AND r.company_id=p.company_id
      WHERE p.company_id=$1 AND p.service_plan_id IS NULL
      AND (p.agreement_id=$2 OR ($3::uuid IS NOT NULL AND p.quote_id=$3)
        OR ($3::uuid IS NOT NULL AND p.job_id IN (SELECT id FROM schedule_events WHERE company_id=$1 AND quote_id=$3 AND contact_id=$4)))
      ORDER BY p.created_at,p.id`, [row.company_id, row.id, row.quote_id, row.contact_id])).rows;
  }
  async function paymentSummary(db, row) {
    if (!row.snapshot.pricing) return null;
    const records = await ledger(db, row);
    let gross = 0, refunds = 0, review = false;
    let currentMode;
    try { currentMode = mode(); } catch { currentMode = null; }
    const receipts = [];
    for (const payment of records) {
      // Unknown environment is never silently credited as a verified payment.
      const environmentMatches = payment.stripe_livemode === currentMode && currentMode !== null;
      const manual = !payment.stripe_payment_intent_id && !payment.stripe_connected_account_id;
      if (!manual && !environmentMatches) { review = true; continue; }
      if (payment.refunded_amount_cents > 0 || payment.refund_amount_known === false || payment.stripe_dispute_status || ["refunded", "partially_refunded", "disputed"].includes(payment.status)) review = true;
      if (settledStates.includes(payment.status) || payment.status === "disputed") {
        gross += Number(payment.amount_cents);
        refunds += Number(payment.refunded_amount_cents || 0);
      }
      receipts.push({ id: payment.id, kind: payment.payment_type, amount_cents: Number(payment.amount_cents), status: payment.status,
        paid_at: payment.paid_at, refunded_amount_cents: Number(payment.refunded_amount_cents || 0), receipt_url: payment.receipt_url || null,
        method: payment.offline_method || null, reference: payment.offline_reference || null, recorded_at: payment.offline_recorded_at || null });
    }
    const originalTotal = Number(row.snapshot.pricing.total_cents);
    const adjustment = service.paymentAdjustmentSummary ? await service.paymentAdjustmentSummary(db, row) : { discount_cents: 0, adjustment_ids: [] };
    const total = Math.max(0, originalTotal - adjustment.discount_cents), deposit = Math.min(total, Number(row.snapshot.pricing.deposit_cents || 0));
    const paid = Math.max(0, gross - refunds);
    const attempts = (await db.query(`SELECT id,payment_record_id,kind,state,transport FROM agreement_payment_attempts WHERE company_id=$1 AND collection_key=$2 AND state=ANY($3::text[]) ORDER BY created_at DESC`, [row.company_id, scopeKey(row), activeStates])).rows;
    if (attempts.some((attempt) => attempt.state === "review")) review = true;
    const roles = (await db.query("SELECT role FROM agreement_signatures WHERE agreement_id=$1", [row.id])).rows.map((signature) => signature.role);
    const signed = row.snapshot.required_signers.every((role) => roles.includes(role));
    let afterService = true;
    if (row.snapshot.balance_payment_timing === "after_service") {
      afterService = Boolean((await db.query(`SELECT count(*)>0 AND bool_and(finished_at IS NOT NULL) AS completed FROM schedule_events WHERE company_id=$1 AND quote_id=$2 AND contact_id=$3`, [row.company_id, row.quote_id, row.contact_id])).rows[0].completed);
    }
    return { total_cents: total, original_total_cents: originalTotal, adjustment_cents: adjustment.discount_cents, adjustment_ids: adjustment.adjustment_ids, gross_paid_cents: gross, refunded_cents: refunds, paid_cents: paid,
      balance_cents: Math.max(0, total - paid), credit_cents: Math.max(0, paid - total), deposit_due_cents: Math.max(0, deposit - paid),
      payment_review_required: review, processing: attempts.some((attempt) => attempt.state === "processing"), receipts,
      active_checkout: attempts.find((attempt) => ["creating", "open", "processing"].includes(attempt.state)) || null,
      can_pay_balance: signed && paid >= deposit && paid < total && !review && afterService && !row.revoked_at && !["declined", "superseded"].includes(row.decision) };
  }
  async function reserve(row, { request_id, kind, transport, actor_id = null, expected_amount = null }, readiness) {
    if (!row.snapshot.pricing) fail("agreement_has_no_payment", "This standalone agreement has no payment obligation.");
    const requestId = id(request_id);
    if (!["deposit", "balance"].includes(kind)) fail("payment_kind_invalid", "Choose a deposit or remaining balance payment.", 400);
    return transaction(pool, async (db) => {
      await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [`payment:${row.company_id}:${scopeKey(row)}`]);
      row = (await db.query("SELECT * FROM quote_agreements WHERE id=$1 AND company_id=$2 FOR UPDATE", [row.id, row.company_id])).rows[0];
      const request = (await db.query("SELECT * FROM agreement_payment_requests WHERE company_id=$1 AND request_id=$2", [row.company_id, requestId])).rows[0];
      if (request) {
        if (request.agreement_id !== row.id || request.kind !== kind || request.transport !== transport) fail("payment_request_conflict", "This payment request was already used for a different action.");
        return (await db.query("SELECT * FROM agreement_payment_attempts WHERE id=$1", [request.attempt_id])).rows[0];
      }
      const summary = await paymentSummary(db, row);
      const roles = (await db.query("SELECT role FROM agreement_signatures WHERE agreement_id=$1", [row.id])).rows.map((signature) => signature.role);
      if (!row.snapshot.required_signers.every((role) => roles.includes(role))) fail("payment_signatures_required", "Complete all required signatures before payment.");
      if (row.revoked_at || ["declined", "superseded"].includes(row.decision)) fail("payment_agreement_unavailable", "This estimate is no longer available for payment. Contact the business.");
      if (summary.payment_review_required) fail("payment_adjustment_review_required", "A payment adjustment needs the business's review before another charge.");
      if (kind === "balance" && summary.deposit_due_cents > 0) fail("payment_deposit_required", "Complete the required deposit before paying the remaining balance.");
      if (kind === "balance" && summary.balance_cents > 0 && !summary.can_pay_balance) fail("payment_balance_not_due", "The remaining balance is not yet available for payment.");
      const amount = kind === "deposit" ? Math.min(summary.deposit_due_cents, summary.balance_cents) : summary.balance_cents;
      if (amount === 0) return { state: "succeeded", amount_cents: 0, already_paid: true };
      if (amount < 50) fail("payment_below_minimum", "This amount is below the online payment minimum. Contact the business to settle it.");
      if (expected_amount !== null && expected_amount !== amount) fail("payment_amount_changed", "The amount due changed. Refresh the agreement before collecting payment.");
      let existing = (await db.query(`SELECT * FROM agreement_payment_attempts WHERE company_id=$1 AND collection_key=$2 AND state=ANY($3::text[])`, [row.company_id, scopeKey(row), activeStates])).rows[0];
      if (existing && (existing.amount_cents !== amount || existing.kind !== kind || existing.transport !== transport || existing.agreement_id !== row.id)) {
        fail("payment_already_in_progress", "Another checkout is already available for this estimate. Complete or cancel it before starting another payment.");
      }
      if (!existing) {
        const obligation = (await db.query(`INSERT INTO agreement_payment_obligations(id,company_id,agreement_id,kind,amount_cents,currency,packet_hash)
          VALUES($1,$2,$3,$4,$5,'usd',$6) ON CONFLICT(agreement_id,kind) DO UPDATE SET agreement_id=EXCLUDED.agreement_id RETURNING *`,
        [randomUUID(), row.company_id, row.id, kind, kind === "deposit" ? row.snapshot.pricing.deposit_cents : row.snapshot.pricing.total_cents, row.packet_hash])).rows[0];
        const attemptID = randomUUID(), recordID = randomUUID();
        const metadata = { wolfcrm_attempt_id: attemptID, wolfcrm_agreement_id: row.id, wolfcrm_quote_id: row.quote_id || "", wolfcrm_payment_record_id: recordID, wolfcrm_company_id: row.company_id, wolfcrm_payment_kind: kind };
        const description = `${kind === "deposit" ? "Deposit" : "Balance"} for estimate #${row.number}`;
        const feeBPS = Math.min(10000, Math.max(0, Number.parseInt(env.STRIPE_PLATFORM_FEE_BPS || "0", 10) || 0));
        const fee = Math.min(amount - 1, Math.floor(amount * feeBPS / 10000));
        const parameters = transport === "checkout" ? {
          mode: "payment", line_items: [{ price_data: { currency: "usd", unit_amount: amount, product_data: { name: description } }, quantity: 1 }],
          payment_intent_data: { metadata, description, ...(fee > 0 ? { application_fee_amount: fee } : {}) }, metadata,
          success_url: service.customerURL(row), cancel_url: service.customerURL(row), client_reference_id: attemptID,
        } : { amount, currency: "usd", description, automatic_payment_methods: { enabled: true }, metadata, ...(fee > 0 ? { application_fee_amount: fee } : {}) };
        const jobs = (await db.query("SELECT id FROM schedule_events WHERE company_id=$1 AND quote_id=$2 AND contact_id=$3", [row.company_id, row.quote_id, row.contact_id])).rows;
        const jobID = jobs.length === 1 ? jobs[0].id : null;
        await db.query(`INSERT INTO payment_records(id,user_id,company_id,created_by_user_id,contact_id,agreement_id,quote_id,job_id,payment_type,status,amount_cents,currency,description,stripe_connected_account_id,stripe_livemode)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',$10,'usd',$11,$12,$13)`,
        [recordID, readiness.owner_user_id, row.company_id, actor_id, row.contact_id, row.id, row.quote_id, jobID, `agreement_${kind}`, amount, description, readiness.account_id, readiness.livemode]);
        existing = (await db.query(`INSERT INTO agreement_payment_attempts(id,company_id,agreement_id,obligation_id,payment_record_id,collection_key,kind,transport,connected_account_id,livemode,amount_cents,currency,state,create_parameters)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'usd','creating',$12::jsonb) RETURNING *`,
        [attemptID, row.company_id, row.id, obligation.id, recordID, scopeKey(row), kind, transport, readiness.account_id, readiness.livemode, amount, JSON.stringify(parameters)])).rows[0];
        await service.event(db, row.id, "payment_started", { actor_type: actor_id ? "staff" : "customer", actor_id,
          payload: { attempt_id: attemptID, payment_record_id: recordID, kind, amount_cents: amount } });
      }
      await db.query(`INSERT INTO agreement_payment_requests(company_id,request_id,agreement_id,kind,transport,attempt_id) VALUES($1,$2,$3,$4,$5,$6)`, [row.company_id, requestId, row.id, kind, transport, existing.id]);
      return existing;
    });
  }
  async function markReview(attempt, code) {
    await pool.query(`UPDATE agreement_payment_attempts SET state='review',failure_code=$2,reconcile_after=now()+interval '30 minutes',updated_at=now() WHERE id=$1`, [attempt.id, code]);
  }
  async function provision(attempt) {
    if (attempt.state !== "creating") return attempt;
    if (attempt.livemode !== mode()) { await markReview(attempt, "environment_changed"); fail("payment_environment_changed", "This payment belongs to a different Stripe environment. Contact the business."); }
    // Stripe only promises idempotency retention for at least 24 hours. Never
    // create again after that bound when the original provider outcome is unknown.
    if (now().getTime() - new Date(attempt.created_at).getTime() >= 23 * 3600000) {
      await markReview(attempt, "provider_create_outcome_unknown");
      fail("payment_recovery_required", "The earlier payment request needs the business's review before retrying.");
    }
    let object;
    try {
      if (attempt.transport === "payment_sheet" && !attempt.create_parameters.customer) {
        const customer = await stripe().customers.create({ metadata: { wolfcrm_company_id: attempt.company_id, wolfcrm_agreement_id: attempt.agreement_id } }, createOptions(attempt, ":customer"));
        attempt.create_parameters = { ...attempt.create_parameters, customer: customer.id };
        await pool.query("UPDATE agreement_payment_attempts SET create_parameters=$2::jsonb WHERE id=$1", [attempt.id, JSON.stringify(attempt.create_parameters)]);
        await pool.query("UPDATE payment_records SET stripe_customer_id=$2 WHERE id=$1", [attempt.payment_record_id, customer.id]);
      }
      object = attempt.transport === "checkout"
        ? await stripe().checkout.sessions.create(attempt.create_parameters, createOptions(attempt))
        : await stripe().paymentIntents.create(attempt.create_parameters, createOptions(attempt));
    } catch (error) {
      await pool.query(`UPDATE agreement_payment_attempts SET failure_code=$2,reconcile_after=now()+interval '1 minute',updated_at=now() WHERE id=$1`, [attempt.id, error?.code === "idempotency_key_in_use" ? "provider_request_in_progress" : "provider_create_unconfirmed"]);
      throw providerError();
    }
    if (object.livemode !== attempt.livemode) { await markReview(attempt, "provider_environment_mismatch"); fail("payment_environment_mismatch", "Payment setup returned an unexpected environment. Contact the business."); }
    const piID = attempt.transport === "checkout" ? objectID(object.payment_intent) : object.id;
    await transaction(pool, async (db) => {
      await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [`payment:${attempt.company_id}:${attempt.collection_key}`]);
      await db.query(`UPDATE agreement_payment_attempts SET state=CASE WHEN state='creating' THEN 'open' ELSE state END,
        checkout_session_id=COALESCE(checkout_session_id,$2),payment_intent_id=COALESCE(payment_intent_id,$3),checkout_url=COALESCE($4,checkout_url),
        expires_at=COALESCE($5,expires_at),failure_code=NULL,reconcile_after=now()+interval '1 minute',updated_at=now() WHERE id=$1`,
      [attempt.id, attempt.transport === "checkout" ? object.id : null, piID, attempt.transport === "checkout" ? object.url : null, object.expires_at ? new Date(object.expires_at * 1000) : null]);
      await db.query(`UPDATE payment_records SET stripe_payment_intent_id=COALESCE(stripe_payment_intent_id,$2),updated_at=now() WHERE id=$1`, [attempt.payment_record_id, piID]);
    });
    return (await pool.query("SELECT * FROM agreement_payment_attempts WHERE id=$1", [attempt.id])).rows[0];
  }
  async function reconcileAttempt(attempt) {
    if (attempt.livemode !== mode()) { await markReview(attempt, "environment_changed"); return; }
    if (attempt.state === "creating") attempt = await provision(attempt);
    if (attempt.state === "review" && !attempt.checkout_session_id && !attempt.payment_intent_id) return;
    let session = null, intent = null;
    try {
      if (attempt.checkout_session_id) {
        session = await stripe().checkout.sessions.retrieve(attempt.checkout_session_id, { expand: ["payment_intent.latest_charge"] }, providerOptions(attempt));
        intent = session.payment_intent && typeof session.payment_intent === "object" ? session.payment_intent : null;
      }
      const intentID = objectID(session?.payment_intent) || attempt.payment_intent_id;
      if (intentID && !intent) intent = await stripe().paymentIntents.retrieve(intentID, { expand: ["latest_charge"] }, providerOptions(attempt));
    } catch { throw providerError(); }
    if ((session && (session.livemode !== attempt.livemode || session.amount_total !== attempt.amount_cents || session.currency !== attempt.currency))
      || (intent && (intent.livemode !== attempt.livemode || intent.amount !== attempt.amount_cents || intent.currency !== attempt.currency))) {
      await markReview(attempt, "provider_amount_or_scope_mismatch");
      fail("payment_reconciliation_mismatch", "Payment details need the business's review before proceeding.");
    }
    const charge = intent?.latest_charge && typeof intent.latest_charge === "object" ? intent.latest_charge : null;
    const refund = Math.max(0, Math.min(attempt.amount_cents, Number(charge?.amount_refunded || 0)));
    const disputed = Boolean(charge?.disputed);
    let status = intent?.status === "succeeded" ? "succeeded" : intent?.status === "processing" ? "processing" : intent?.status === "canceled" ? "canceled" : intent?.last_payment_error ? "failed" : "pending";
    let state = status === "succeeded" ? "succeeded" : status === "processing" ? "processing" : status === "canceled" ? "canceled" : "open";
    if (session?.status === "expired" && !["succeeded", "processing"].includes(status)) { state = "expired"; status = "canceled"; }
    if (session?.status === "expired" && intent && !["succeeded", "processing", "canceled"].includes(intent.status)) {
      // An expired browser session alone is not proof its intent cannot settle.
      // Confirm cancellation before freeing this obligation for replacement.
      try {
        const canceled = await stripe().paymentIntents.cancel(intent.id, {}, providerOptions(attempt));
        if (canceled.status !== "canceled") { state = "processing"; status = "processing"; }
      } catch { state = "processing"; status = "processing"; }
    }
    if (session?.status === "complete" && status === "failed") state = "failed";
    if (refund > 0 || disputed) { state = "review"; status = disputed ? "disputed" : refund >= attempt.amount_cents ? "refunded" : "partially_refunded"; }
    if (session?.payment_status === "paid" && !intent) { state = "processing"; status = "processing"; }
    await transaction(pool, async (db) => {
      await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [`payment:${attempt.company_id}:${attempt.collection_key}`]);
      const current = (await db.query("SELECT * FROM payment_records WHERE id=$1 FOR UPDATE", [attempt.payment_record_id])).rows[0];
      // Observations cannot erase settled money or a recorded adjustment. A
      // disputed payment remains held until an explicit staff review operation.
      if (current.stripe_dispute_status) { status = "disputed"; state = "review"; }
      else if (Number(current.refunded_amount_cents) > refund) { status = Number(current.refunded_amount_cents) >= current.amount_cents ? "refunded" : "partially_refunded"; state = "review"; }
      else if (settledStates.includes(current.status) && !settledStates.includes(status) && status !== "disputed") { status = current.status; state = "succeeded"; }
      const piID = intent?.id || attempt.payment_intent_id;
      await db.query(`UPDATE payment_records SET status=$2,stripe_payment_intent_id=COALESCE(stripe_payment_intent_id,$3),
        stripe_customer_id=COALESCE(stripe_customer_id,$4),stripe_charge_id=COALESCE($5,stripe_charge_id),
        paid_at=CASE WHEN $2 IN ('succeeded','refunded','partially_refunded','disputed') THEN COALESCE(paid_at,$6,now()) ELSE paid_at END,
        refunded_amount_cents=GREATEST(refunded_amount_cents,$7),refund_amount_known=true,
        refunded_at=CASE WHEN $7>0 THEN COALESCE(refunded_at,now()) ELSE refunded_at END,
        stripe_dispute_status=CASE WHEN $8 THEN COALESCE(stripe_dispute_status,'needs_review') ELSE stripe_dispute_status END,
        receipt_url=COALESCE($9,receipt_url),updated_at=now() WHERE id=$1`,
      [attempt.payment_record_id, status, piID, objectID(intent?.customer || session?.customer), charge?.id || null, charge?.created ? new Date(charge.created * 1000) : null, refund, disputed, charge?.receipt_url || null]);
      await db.query(`UPDATE agreement_payment_attempts SET state=$2,payment_intent_id=COALESCE(payment_intent_id,$3),
        checkout_url=CASE WHEN $2='open' THEN checkout_url ELSE NULL END,failure_code=NULL,reconciled_at=now(),reconcile_after=now()+interval '5 minutes',updated_at=now() WHERE id=$1`, [attempt.id, state, piID]);
      if (attempt.state !== state || current.status !== status || Number(current.refunded_amount_cents) < refund) await service.event(db, attempt.agreement_id, `payment_${status}`, { payload: { payment_record_id: current.id, attempt_id: attempt.id, kind: attempt.kind, amount_cents: current.amount_cents, refunded_amount_cents: Math.max(refund, Number(current.refunded_amount_cents)) } });
    });
    if (state === "review") {
      const otherAttempts = (await pool.query(`SELECT * FROM agreement_payment_attempts WHERE company_id=$1 AND collection_key=$2 AND id<>$3 AND state='open'`, [attempt.company_id, attempt.collection_key, attempt.id])).rows;
      for (const other of otherAttempts) {
        try {
          if (other.checkout_session_id) await stripe().checkout.sessions.expire(other.checkout_session_id, {}, providerOptions(other));
          else if (other.payment_intent_id) await stripe().paymentIntents.cancel(other.payment_intent_id, {}, providerOptions(other));
          await reconcileAttempt(other);
        } catch {
          await pool.query("UPDATE agreement_payment_attempts SET failure_code='adjustment_cancel_retry',reconcile_after=now()+interval '1 minute' WHERE id=$1", [other.id]);
        }
      }
    }
    return (await pool.query("SELECT * FROM agreement_payment_attempts WHERE id=$1", [attempt.id])).rows[0];
  }
  async function reconcileRow(row) {
    const attempts = (await pool.query(`SELECT * FROM agreement_payment_attempts WHERE company_id=$1 AND collection_key=$2 AND state<>ALL($3::text[]) ORDER BY created_at`, [row.company_id, scopeKey(row), ["expired", "canceled", "failed"]])).rows;
    for (const attempt of attempts) await reconcileAttempt(attempt);
  }
  async function checkout(token, raw) {
    const { row,role } = await service.loadPublic(pool, token);
    if(role!=="customer")fail("payment_primary_customer_required","The primary customer manages payments for this estimate.",403);
    if (!row.snapshot.pricing) fail("agreement_has_no_payment", "This standalone agreement has no payment obligation.");
    await service.rate(pool, `checkout:${row.id}`, 30, 3600);
    // Check signatures before any provider creation or visible payment flow.
    const state = await service.state(pool, row);
    if (state.signing !== "submitted") fail("payment_signatures_required", "Complete all required signatures before payment.");
    const saved = await paymentSummary(pool, row);
    if (!saved.payment_review_required && ((raw.kind === "deposit" && saved.deposit_due_cents === 0) || (raw.kind === "balance" && saved.balance_cents === 0))) return { url: null, status: "succeeded" };
    await reconcileRow(row);
    const readiness = await paymentReadiness(pool, row.company_id);
    let attempt = await reserve(row, { request_id: raw.request_id, kind: raw.kind, transport: "checkout" }, readiness);
    if (attempt.already_paid) return { url: null, status: "succeeded" };
    attempt = await provision(attempt);
    attempt = await reconcileAttempt(attempt) || attempt;
    return { url: attempt.state === "open" ? attempt.checkout_url : null, status: attempt.state, payment_record_id: attempt.payment_record_id };
  }
  async function reconcile(token) {
    const { row } = await service.loadPublic(pool, token);
    await service.rate(pool, `payment-reconcile:${row.id}`, 60, 3600);
    await reconcileRow(row);
    return { ...await service.state(pool, row), payments: await paymentSummary(pool, row) };
  }
  async function startStaffPayment(req) {
    const raw = req.body || {};
    if (!raw.agreement_id && !raw.quote_id && !raw.job_id) return null;
    if (!req.companyId) fail("company_required", "Agreement payments require a company workspace.", 403);
    let quoteID = raw.quote_id || null;
    if (raw.job_id) {
      const job = (await pool.query("SELECT quote_id FROM schedule_events WHERE id=$1 AND company_id=$2 AND contact_id=$3", [raw.job_id, req.companyId, req.params.contactId])).rows[0];
      if (!job?.quote_id || (quoteID && quoteID !== job.quote_id)) fail("payment_job_unavailable", "Select the quoted job for this customer.", 404);
      quoteID = job.quote_id;
    }
    const row = raw.agreement_id ? await service.loadStaff(pool, req, raw.agreement_id)
      : (await pool.query("SELECT * FROM quote_agreements WHERE quote_id=$1 AND company_id=$2 ORDER BY revision DESC LIMIT 1", [id(quoteID), req.companyId])).rows[0];
    if (!row || row.contact_id !== req.params.contactId || (quoteID && row.quote_id !== quoteID)) fail("payment_agreement_unavailable", "The customer's issued agreement was not found.", 404);
    if (!row.snapshot.pricing) fail("agreement_has_no_payment", "This standalone agreement has no payment obligation.");
    if (!env.STRIPE_PUBLISHABLE_KEY) fail("publishable_key_missing", "Configure Stripe's public key for in-app payments.", 503);
    await reconcileRow(row);
    const readiness = await paymentReadiness(pool, row.company_id);
    const summary = await paymentSummary(pool, row);
    const kind = raw.kind || (summary.deposit_due_cents > 0 ? "deposit" : "balance");
    let attempt = await reserve(row, { request_id: raw.request_id, kind, transport: "payment_sheet", actor_id: req.userId, expected_amount: raw.amount_cents ?? null }, readiness);
    if (attempt.already_paid) fail("payment_already_paid", "This obligation is already paid. Refresh the agreement.");
    attempt = await provision(attempt);
    attempt = await reconcileAttempt(attempt) || attempt;
    if (attempt.state !== "open") fail("payment_not_collectible", "This payment is already processing or complete. Refresh its status.");
    const intent = await stripe().paymentIntents.retrieve(attempt.payment_intent_id, {}, providerOptions(attempt));
    // No saved-card/recurring authorization is implied by a one-time payment.
    const customerID = objectID(intent.customer);
    const ephemeral = await stripe().ephemeralKeys.create({ customer: customerID }, { ...providerOptions(attempt), apiVersion: "2024-06-20" });
    return { publishable_key: env.STRIPE_PUBLISHABLE_KEY, connected_account_id: attempt.connected_account_id,
      payment_intent_client_secret: intent.client_secret, payment_record_id: attempt.payment_record_id,
      customer_id: customerID, ephemeral_key_secret: ephemeral.secret, agreement_id: row.id, amount_cents: attempt.amount_cents };
  }
  async function handleWebhook(event) {
    const object = event.data?.object;
    if (!event.account || typeof event.livemode !== "boolean" || !object) return false;
    const attemptID = object.metadata?.wolfcrm_attempt_id;
    const piID = object.object === "payment_intent" ? object.id : objectID(object.payment_intent);
    const sessionID = object.object === "checkout.session" ? object.id : null;
    const attempts = (await pool.query(`SELECT * FROM agreement_payment_attempts WHERE connected_account_id=$1 AND livemode=$2
      AND (($3::text IS NOT NULL AND id::text=$3) OR ($4::text IS NOT NULL AND payment_intent_id=$4) OR ($5::text IS NOT NULL AND checkout_session_id=$5))`, [event.account, event.livemode, attemptID || null, piID, sessionID])).rows;
    for (const attempt of attempts) {
      if (event.type.startsWith("charge.dispute.")) {
        await pool.query("UPDATE payment_records SET stripe_dispute_status=$2,status='disputed',updated_at=now() WHERE id=$1", [attempt.payment_record_id, object.status || "needs_review"]);
      }
      await reconcileAttempt(attempt);
    }
    return attempts.length > 0;
  }
  async function reconcilePayment(payment) {
    const attempt = (await pool.query("SELECT * FROM agreement_payment_attempts WHERE payment_record_id=$1", [payment.id])).rows[0];
    if (!attempt) return null;
    await reconcileAttempt(attempt);
    return (await pool.query("SELECT * FROM payment_records WHERE id=$1", [payment.id])).rows[0];
  }
  async function reconcileStaff(req, agreementID) {
    const row = await service.loadStaff(pool, req, agreementID);
    await reconcileRow(row);
    return service.detail(pool, row, { staff: true, includeActivity: true });
  }
  async function cancelStaffAttempt(req, agreementID, raw) {
    const row = await service.loadStaff(pool, req, agreementID);
    let attempt = (await pool.query(`SELECT * FROM agreement_payment_attempts WHERE id=$1 AND company_id=$2 AND collection_key=$3`, [id(raw.attempt_id), row.company_id, scopeKey(row)])).rows[0];
    if (!attempt) fail("payment_attempt_unavailable", "This checkout was not found in this company.", 404);
    const requestID = id(raw.request_id);
    const prior = (await pool.query("SELECT type,request_hash FROM agreement_events WHERE agreement_id=$1 AND request_id=$2", [row.id, requestID])).rows[0];
    if (prior && (prior.type !== "unpaid_checkout_canceled" || prior.request_hash !== attempt.id)) fail("payment_request_conflict", "This request was already used for a different action.");
    if (attempt.state === "creating") attempt = await provision(attempt);
    if (["open", "processing"].includes(attempt.state)) {
      try {
        if (attempt.checkout_session_id) await stripe().checkout.sessions.expire(attempt.checkout_session_id, {}, providerOptions(attempt));
        else if (attempt.payment_intent_id) await stripe().paymentIntents.cancel(attempt.payment_intent_id, {}, providerOptions(attempt));
      } catch {
        await reconcileAttempt(attempt);
        fail("payment_cannot_cancel", "This payment may already be processing or complete. Refresh before taking another payment.");
      }
      attempt = await reconcileAttempt(attempt) || attempt;
    }
    if (!["expired", "canceled", "failed"].includes(attempt.state)) fail("payment_cannot_cancel", "Only an unpaid checkout can be canceled here. No refund was issued.");
    await service.event(pool, row.id, "unpaid_checkout_canceled", { request_id: requestID, request_hash: attempt.id, actor_type: "staff", actor_id: req.userId, payload: { attempt_id: attempt.id, payment_record_id: attempt.payment_record_id } });
    return { status: attempt.state, payments: await paymentSummary(pool, row) };
  }
  async function processReconciliation() {
    const due = (await pool.query(`UPDATE agreement_payment_attempts SET reconcile_after=now()+interval '5 minutes'
      WHERE id IN (SELECT id FROM agreement_payment_attempts WHERE state=ANY($1::text[]) AND reconcile_after<=now() ORDER BY reconcile_after LIMIT 20 FOR UPDATE SKIP LOCKED) RETURNING *`, [activeStates])).rows;
    for (const attempt of due) {
      try { await reconcileAttempt(attempt); }
      catch { await pool.query("UPDATE agreement_payment_attempts SET failure_code=COALESCE(failure_code,'reconcile_retry'),reconcile_after=now()+interval '5 minutes' WHERE id=$1", [attempt.id]); }
    }
  }
  const recordOffline = createAgreementOfflineRecorder({ pool, service, paymentSummary, now });
  return { checkout, reconcile, paymentSummary, recordOffline, validatePaymentReadiness: paymentReadiness, startStaffPayment, handleWebhook, reconcilePayment, reconcileStaff, cancelStaffAttempt, processReconciliation, reconcileAttempt };
}

export async function installAgreementPayments({ app, pool, service, getStripe = service.getStripe, env = service.env, authRequired, requireCapability, startWorker = true }) {
  await installAgreementPaymentSchema(pool);
  const adapter = createAgreementPayments({ pool, service, getStripe, env });
  service.paymentReady = true;
  service.validatePaymentReadiness = adapter.validatePaymentReadiness;
  service.paymentSummary = adapter.paymentSummary;
  app.locals.agreementPayments = adapter;
  const write = (action) => async (req, res) => {
    res.set({ "Cache-Control": "private, no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff" });
    if (!req.is("application/json")) return res.status(415).json({ error: "json_required" });
    if (req.headers.origin && req.headers.origin !== env.QUOTE_PUBLIC_BASE_URL?.replace(/\/$/, "")) return res.status(403).json({ error: "origin_not_allowed" });
    try { res.json(await action(req)); }
    catch (error) {
      if (error instanceof QuoteContractError) return res.status(error.status).json({ error: error.code, message: error.message });
      console.error("[agreement-payments] operation failed", { code: error?.code || "internal" });
      res.status(502).json({ error: "payment_unavailable", message: "The payment could not be confirmed. Your existing agreement is saved; please try again." });
    }
  };
  app.post("/api/public/agreements/:token/checkout", write((req) => adapter.checkout(req.params.token, req.body)));
  app.post("/api/public/agreements/:token/reconcile", write((req) => adapter.reconcile(req.params.token)));
  if (authRequired && requireCapability) {
    app.post("/api/agreements/:id/payments/offline", authRequired, requireCapability("payments.collect"), write((req) => adapter.recordOffline(req, req.params.id, req.body)));
    app.post("/api/agreements/:id/payments/cancel-checkout", authRequired, requireCapability("payments.collect"), write((req) => adapter.cancelStaffAttempt(req, req.params.id, req.body)));
    app.post("/api/agreements/:id/payments/reconcile", authRequired, requireCapability("payments.collect"), write((req) => adapter.reconcileStaff(req, req.params.id)));
  }
  if (startWorker) setInterval(() => adapter.processReconciliation().catch(() => {}), 60000).unref?.();
  return adapter;
}
