import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { startLocalPostgres } from "./helpers/local-postgres.js";
import { installAgreementSchema, createAgreementService } from "../quote-agreements.js";
import { installAgreementPayments, createAgreementPayments, stripePaymentMode } from "../agreement-payments.js";

// Provider boundary double: calls use real SDK method shapes and account/mode
// scopes, but no Stripe network request or customer payment occurs in this test.
function fakeStripe() {
  const sessions = new Map(), intents = new Map(), keys = new Map();
  let createdSessions = 0, createdIntents = 0, loseNextResponse = false;
  function key(options, prefix) { assert.equal(options.stripeAccount, "acct_test_business"); return `${prefix}:${options.stripeAccount}:${options.idempotencyKey}`; }
  function intent(params) {
    assert.equal(params.receipt_email, undefined);
    createdIntents++;
    const object = { id: `pi_test_${createdIntents}`, object: "payment_intent", livemode: false, amount: params.amount, currency: params.currency,
      customer: params.customer || null, metadata: params.metadata || {}, status: "requires_payment_method", client_secret: "fixture_client_secret", latest_charge: null };
    intents.set(object.id, object); return object;
  }
  const api = {
    accounts: { retrieve: async () => ({ charges_enabled: true, capabilities: { card_payments: "active" } }) },
    customers: { create: async (params, options) => { assert.equal(params.email,undefined); const k = key(options, "customer"); if (!keys.has(k)) keys.set(k, { id: `cus_test_${keys.size}` }); return keys.get(k); } },
    ephemeralKeys: { create: async ({ customer }, options) => { assert.ok(customer); assert.equal(options.stripeAccount, "acct_test_business"); return { secret: "fixture_ephemeral_secret" }; } },
    checkout: { sessions: {
      create: async (params, options) => {
        assert.equal(params.customer_email,undefined);assert.equal(params.payment_intent_data?.receipt_email,undefined);assert.notEqual(params.invoice_creation?.enabled,true);
        const k = key(options, "checkout");
        if (!keys.has(k)) {
          createdSessions++;
          const object = { id: `cs_test_${createdSessions}`, object: "checkout.session", livemode: false, metadata: params.metadata,
            amount_total: params.line_items[0].price_data.unit_amount, currency: params.line_items[0].price_data.currency,
            status: "open", payment_status: "unpaid", payment_intent: null, url: `https://checkout.stripe.com/test-${createdSessions}`, expires_at: Math.floor(Date.now() / 1000) + 86400 };
          sessions.set(object.id, object); keys.set(k, object);
        }
        if (loseNextResponse) { loseNextResponse = false; throw new Error("Simulated response lost after provider persisted session"); }
        return structuredClone(keys.get(k));
      },
      retrieve: async (sessionID, _params, options) => {
        assert.equal(options.stripeAccount, "acct_test_business");
        const object = structuredClone(sessions.get(sessionID));
        if (typeof object.payment_intent === "string") object.payment_intent = structuredClone(intents.get(object.payment_intent));
        return object;
      },
      expire: async (sessionID, _params, options) => { assert.equal(options.stripeAccount, "acct_test_business"); const object = sessions.get(sessionID); if (object.status !== "open") throw new Error("Not open"); object.status = "expired"; return structuredClone(object); }
    } },
    paymentIntents: {
      create: async (params, options) => { const k = key(options, "intent"); if (!keys.has(k)) keys.set(k, intent(params)); return structuredClone(keys.get(k)); },
      retrieve: async (intentID, _params, options) => { assert.equal(options.stripeAccount, "acct_test_business"); return structuredClone(intents.get(intentID)); },
      cancel: async (intentID) => { const object = intents.get(intentID); if (["succeeded", "processing"].includes(object.status)) throw new Error("Already in flight"); object.status = "canceled"; return structuredClone(object); }
    },
    begin(sessionID, status = "processing") {
      const session = sessions.get(sessionID);
      const payment = intent({ amount: session.amount_total, currency: session.currency, metadata: session.metadata });
      payment.status = status;
      session.status = "complete"; session.payment_intent = payment.id; session.payment_status = status === "succeeded" ? "paid" : "unpaid";
      if (status === "succeeded") api.settle(payment.id);
      return payment;
    },
    settle(intentID) {
      const payment = intents.get(intentID); payment.status = "succeeded";
      payment.latest_charge = { id: `ch_${intentID}`, created: Math.floor(Date.now() / 1000), amount_refunded: 0, disputed: false, receipt_url: "https://pay.stripe.com/receipts/test" };
      return payment;
    },
    sessions, intents,
    loseResponse() { loseNextResponse = true; },
    counts() { return { sessions: createdSessions, intents: createdIntents }; }
  };
  return api;
}

test("agreement payments enforce durable gates, idempotency and provider reconciliation against PostgreSQL", { timeout: 60000 }, async (t) => {
  const postgres = startLocalPostgres(); postgres.configureEnvironment();
  process.env.STRIPE_SECRET_KEY = "sk_test_fixture_not_a_real_key";
  let pool, server;
  try {
    const backend = await import("../index.js"); pool = backend.pool;
    await backend.bootstrap(); await installAgreementSchema(pool);
    const { installOperationalAccountingSchema } = await import("../finance-operational-accounting.js");
    await installOperationalAccountingSchema(pool);
    const companyID = randomUUID(), ownerID = randomUUID(), contactID = randomUUID();
    await pool.query("INSERT INTO companies(id,name,join_code,owner_user_id) VALUES($1,'Fixture business','PAY-TEST',$2)", [companyID, ownerID]);
    await pool.query("INSERT INTO users(id,email,role,company_id) VALUES($1,'payment@example.invalid','employer',$2)", [ownerID, companyID]);
    await pool.query("INSERT INTO contacts(id,user_id,company_id,name) VALUES($1,$2,$3,'Fixture customer')", [contactID, ownerID, companyID]);
    await pool.query("INSERT INTO business_settings(user_id,company_id,stripe_account_id) VALUES($1,$2,'acct_test_business')", [ownerID, companyID]);
    await pool.query("INSERT INTO sessions(token,user_id) VALUES('payment-fixture',$1)", [ownerID]);
    const env = { QUOTE_LINK_SECRET: "test-only-quote-link-secret-at-least-32-characters", QUOTE_PUBLIC_BASE_URL: "https://example.invalid", STRIPE_SECRET_KEY: "sk_test_fixture_not_a_real_key", STRIPE_PUBLISHABLE_KEY: "pk_test_fixture" };
    const stripe = fakeStripe();
    const service = createAgreementService({ pool, env, getStripe: () => stripe });
    const adapter = await installAgreementPayments({ app: backend.app, pool, service, getStripe: () => stripe, env, authRequired: backend.authRequired, requireCapability: backend.requireCapability, startWorker: false });
    server = await new Promise((resolve) => { const listener = backend.app.listen(0, "127.0.0.1", () => resolve(listener)); });
    const base = `http://127.0.0.1:${server.address().port}`;
    const request = async (url, body, staff = false) => {
      const response = await fetch(base + url, { method: "POST", headers: { "content-type": "application/json", ...(staff ? { authorization: "Bearer payment-fixture" } : {}) }, body: JSON.stringify(body) });
      return { status: response.status, body: await response.json() };
    };
    let number = 0;
    async function agreement({ deposit = 15000, total = 70000, signed = true, roles = ["customer"], quoteID = randomUUID(), revision = 1 } = {}) {
      const agreementID = randomUUID(); number++;
      await pool.query("INSERT INTO quotes(id,user_id,company_id,contact_id,line_items,total_cents) VALUES($1,$2,$3,$4,'[]',$5) ON CONFLICT DO NOTHING", [quoteID, ownerID, companyID, contactID, total]);
      const snapshot = { pricing: { total_cents: total, deposit_cents: deposit }, required_signers: roles, allow_customer_booking: true, documents: [], business: { name: "Fixture" }, customer: { name: "Customer" } };
      const row = (await pool.query(`INSERT INTO quote_agreements(id,company_id,quote_id,contact_id,created_by,number,revision,request_id,title,snapshot,packet_hash)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,'Estimate',$9::jsonb,'fixture_hash') RETURNING *`, [agreementID, companyID, quoteID, contactID, ownerID, `${number}`, revision, randomUUID(), JSON.stringify(snapshot)])).rows[0];
      if (signed) for (const role of roles) await sign(row, role);
      return { row, token: service.makeToken(row) };
    }
    async function sign(row, role) {
      const sessionID = randomUUID();
      await pool.query(`INSERT INTO agreement_signing_sessions(id,agreement_id,role,token_hash,token_generation,expires_at,verification_method) VALUES($1,$2,$3,$4,1,now()+interval '1 day','link')`, [sessionID, row.id, role, randomUUID()]);
      await pool.query(`INSERT INTO agreement_signatures(id,agreement_id,session_id,role,request_id,request_hash,printed_name,consent_text,signature,field_values,packet_hash,verification_method,submitted_at)
        VALUES($1,$2,$3,$4,$5,'fixture','Fixture signer','Fixture consent','{}','{}','fixture_hash','link',now())`, [randomUUID(), row.id, sessionID, role, randomUUID()]);
      await pool.query("UPDATE quote_agreements SET signed_at=now() WHERE id=$1", [row.id]);
    }
    const checkout = (item, kind = "deposit", requestID = randomUUID()) => request(`/api/public/agreements/${item.token}/checkout`, { request_id: requestID, kind });
    const attemptFor = async (row) => (await pool.query("SELECT * FROM agreement_payment_attempts WHERE agreement_id=$1 ORDER BY created_at DESC", [row.id])).rows[0];
    await t.test("staff can reconcile a public agreement with company ownership, without customer access tokens", async () => {
      const item = await agreement();
      const result = await adapter.reconcileStaff({ companyId: companyID, userId: ownerID }, item.row.id);
      assert.equal(result.id, item.row.id);
      await assert.rejects(adapter.reconcileStaff({ companyId: randomUUID(), userId: ownerID }, item.row.id), (error) => error.status === 404);
    });
    await t.test("no checkout before every required signature, or through a forged token", async () => {
      const item = await agreement({ signed: false, roles: ["customer", "business"] });
      assert.equal((await checkout(item)).status, 409);
      await sign(item.row, "customer");
      assert.equal((await checkout(item)).status, 409);
      assert.equal((await checkout({ ...item, token: item.token.slice(0, -1) + "X" })).status, 404);
      assert.equal(stripe.counts().sessions, 0);
      await sign(item.row, "business");
      assert.equal((await checkout(item)).status, 200);
    });
    const item = await agreement();
    await t.test("concurrent tabs reserve one collectible deposit and one ledger payment", async () => {
      const before = stripe.counts().sessions;
      const results = await Promise.all(Array.from({ length: 8 }, () => checkout(item)));
      assert.ok(results.every((result) => result.status === 200), JSON.stringify(results));
      assert.equal(new Set(results.map((result) => result.body.url)).size, 1);
      assert.equal(stripe.counts().sessions - before, 1);
      assert.equal(Number((await pool.query("SELECT count(*) AS count FROM payment_records WHERE agreement_id=$1", [item.row.id])).rows[0].count), 1);
      assert.equal((await checkout(item, "balance")).body.error, "payment_already_in_progress");
    });
    await t.test("processing and a browser-like success claim never count as paid", async () => {
      const attempt = await attemptFor(item.row);
      const intent = stripe.begin(attempt.checkout_session_id);
      stripe.sessions.get(attempt.checkout_session_id).payment_status = "paid";
      const processing = await request(`/api/public/agreements/${item.token}/reconcile`, { status: "succeeded" });
      assert.equal(processing.status, 200);
      assert.equal(processing.body.deposit, "processing");
      assert.equal(processing.body.can_view_availability, false);
      assert.equal(processing.body.payments.paid_cents, 0);
      stripe.settle(intent.id);
      const paid = await request(`/api/public/agreements/${item.token}/reconcile`, {});
      assert.equal(paid.body.deposit, "paid");
      assert.equal(paid.body.payments.paid_cents, 15000);
      assert.equal(paid.body.payments.balance_cents, 55000);
      assert.equal(paid.body.can_view_availability, true);
      const reopened = createAgreementPayments({ pool, service, getStripe: () => stripe, env });
      const previousCount = stripe.counts().sessions;
      const resume = await reopened.checkout(item.token, { request_id: randomUUID(), kind: "deposit" });
      assert.equal(resume.status, "succeeded");
      assert.equal(resume.url, null);
      assert.equal(stripe.counts().sessions, previousCount);
    });
    await t.test("same quote revisions credit the deposit and staff/public collection serialize", async () => {
      const revision = await agreement({ quoteID: item.row.quote_id, revision: 2 });
      assert.equal((await adapter.paymentSummary(pool, revision.row)).paid_cents, 15000);
      const outcomes = await Promise.all([
        checkout(revision, "balance"),
        request(`/api/contacts/${contactID}/payments/start`, { agreement_id: revision.row.id, request_id: randomUUID(), kind: "balance", amount_cents: 55000 }, true)
      ]);
      assert.deepEqual(outcomes.map((result) => result.status).sort(), [200, 409], JSON.stringify(outcomes));
      const winner = await attemptFor(revision.row);
      if (winner.transport === "checkout") stripe.begin(winner.checkout_session_id, "succeeded");
      else stripe.settle(winner.payment_intent_id);
      await adapter.reconcileAttempt(winner);
      const summary = await adapter.paymentSummary(pool, revision.row);
      assert.equal(summary.paid_cents, 70000);
      assert.equal(summary.balance_cents, 0);
      assert.equal(summary.credit_cents, 0);
    });
    await t.test("lost provider creation response resumes the same persisted attempt after restart", async () => {
      const retryItem = await agreement(); const before = stripe.counts().sessions;
      stripe.loseResponse();
      assert.equal((await checkout(retryItem)).status, 502);
      assert.equal((await attemptFor(retryItem.row)).state, "creating");
      const restarted = createAgreementPayments({ pool, service, getStripe: () => stripe, env });
      const recovered = await restarted.checkout(retryItem.token, { request_id: randomUUID(), kind: "deposit" });
      assert.equal(recovered.status, "open");
      assert.equal(stripe.counts().sessions - before, 1);
      assert.equal(Number((await pool.query("SELECT count(*) AS count FROM agreement_payment_attempts WHERE agreement_id=$1", [retryItem.row.id])).rows[0].count), 1);
    });
    await t.test("full balance can be prepaid after signing before deposit, booking or service completion",async()=>{
      const later=await agreement();later.row.snapshot.balance_payment_timing='after_service';
      await pool.query('UPDATE quote_agreements SET snapshot=$2::jsonb WHERE id=$1',[later.row.id,JSON.stringify(later.row.snapshot)]);
      assert.equal((await adapter.paymentSummary(pool,later.row)).can_pay_balance,true);
      const full=await checkout(later,'balance');assert.equal(full.status,200);
      const attempt=await attemptFor(later.row);assert.equal(attempt.amount_cents,70000);
      stripe.begin(attempt.checkout_session_id,'succeeded');await adapter.reconcileAttempt(attempt);
      const paid=await adapter.paymentSummary(pool,later.row);
      assert.equal(paid.balance_cents,0);assert.equal(paid.deposit_due_cents,0);assert.equal(paid.can_pay_balance,false);
      assert.equal((await pool.query('SELECT count(*)::integer AS count FROM schedule_events WHERE quote_id=$1',[later.row.quote_id])).rows[0].count,0);
    });
    await t.test("unknown creation beyond provider idempotency retention blocks recharging", async () => {
      const old = await agreement(); stripe.loseResponse(); await checkout(old);
      await pool.query("UPDATE agreement_payment_attempts SET created_at=now()-interval '25 hours' WHERE agreement_id=$1", [old.row.id]);
      const before = stripe.counts().sessions;
      const retry = await checkout(old);
      assert.equal(retry.status, 409);
      assert.equal(retry.body.error, "payment_recovery_required");
      assert.equal((await attemptFor(old.row)).state, "review");
      assert.equal(stripe.counts().sessions, before);
    });
    await t.test("expired unpaid checkout replaces safely, but processing checkout never does", async () => {
      const expired = await agreement(); await checkout(expired);
      const old = await attemptFor(expired.row); stripe.sessions.get(old.checkout_session_id).status = "expired";
      const before = stripe.counts().sessions;
      assert.equal((await checkout(expired)).status, 200);
      assert.equal(stripe.counts().sessions, before + 1);
      const current = await attemptFor(expired.row); stripe.begin(current.checkout_session_id);
      const inFlight = await checkout(expired);
      assert.equal(inFlight.body.status, "processing");
      assert.equal(stripe.counts().sessions, before + 1);
    });
    await t.test("cancel unpaid checkout allows a different collection channel without two charges", async () => {
      const cancelItem = await agreement(); await checkout(cancelItem);
      const previous = await attemptFor(cancelItem.row);
      const result = await adapter.cancelStaffAttempt({ companyId: companyID, userId: ownerID }, cancelItem.row.id, { attempt_id: previous.id, request_id: randomUUID() });
      assert.equal(result.status, "expired");
      const paidSheet = await request(`/api/contacts/${contactID}/payments/start`, { agreement_id: cancelItem.row.id, request_id: randomUUID(), kind: "deposit", amount_cents: 15000 }, true);
      assert.equal(paidSheet.status, 200, JSON.stringify(paidSheet.body));
      assert.ok(paidSheet.body.customer_id);
      assert.ok(paidSheet.body.ephemeral_key_secret);
      assert.ok(paidSheet.body.payment_intent_client_secret);
      const record = (await pool.query("SELECT * FROM payment_records WHERE id=$1", [paidSheet.body.payment_record_id])).rows[0];
      assert.equal(record.agreement_id, cancelItem.row.id);
      assert.equal(record.quote_id, cancelItem.row.quote_id);
      assert.equal(record.stripe_livemode, false);
    });
    await t.test("a refund pauses and expires a separately open balance checkout", async () => {
      const adjusted = await agreement(); await checkout(adjusted);
      const deposit = await attemptFor(adjusted.row);
      const intent = stripe.begin(deposit.checkout_session_id, "succeeded");
      await adapter.reconcileAttempt(deposit);
      await checkout(adjusted, "balance");
      const balance = await attemptFor(adjusted.row);
      assert.equal(balance.kind, "balance");
      intent.latest_charge.amount_refunded = 3000;
      await adapter.reconcileAttempt({ ...deposit, state: "succeeded" });
      assert.equal(stripe.sessions.get(balance.checkout_session_id).status, "expired");
      assert.equal((await pool.query("SELECT state FROM agreement_payment_attempts WHERE id=$1", [balance.id])).rows[0].state, "expired");
      assert.equal((await checkout(adjusted, "balance")).body.error, "payment_adjustment_review_required");
    });
    await t.test("account/mode mismatches cannot apply webhooks and refunds preserve history", async () => {
      const attempt = await attemptFor(item.row);
      const intent = stripe.intents.get(attempt.payment_intent_id);
      const event = { id: "evt_fixture", type: "payment_intent.succeeded", account: "acct_wrong", livemode: false, data: { object: structuredClone(intent) } };
      assert.equal(await adapter.handleWebhook(event), false);
      assert.equal(await adapter.handleWebhook({ ...event, account: "acct_test_business", livemode: true }), false);
      intent.latest_charge.amount_refunded = 5000;
      await adapter.handleWebhook({ ...event, account: "acct_test_business" });
      await adapter.handleWebhook({ ...event, account: "acct_test_business" });
      const summary = await adapter.paymentSummary(pool, item.row);
      assert.equal(summary.refunded_cents, 5000);
      assert.equal(summary.payment_review_required, true);
      const before = stripe.counts().sessions;
      const attemptMore = await checkout(item, "balance");
      assert.equal(attemptMore.status, 409);
      assert.equal(attemptMore.body.error, "payment_adjustment_review_required");
      assert.equal(stripe.counts().sessions, before);
      assert.equal((await pool.query("SELECT status FROM payment_records WHERE id=$1", [attempt.payment_record_id])).rows[0].status, "partially_refunded");
    });
    await t.test("verified recurring invoice callbacks update only the exact invoice and replay once", async () => {
      const previousID = randomUUID(), currentID = randomUUID();
      await pool.query(`INSERT INTO payment_records(id,user_id,company_id,contact_id,payment_type,status,amount_cents,currency,stripe_connected_account_id,stripe_invoice_id,stripe_subscription_id)
        VALUES($1,$3,$4,$5,'service_plan_first_payment','failed',5000,'usd','acct_test_business','in_old','sub_same'),
        ($2,$3,$4,$5,'service_plan_renewal','pending',5000,'usd','acct_test_business','in_current','sub_same')`, [previousID, currentID, ownerID, companyID, contactID]);
      process.env.STRIPE_WEBHOOK_SECRET = "whsec_fixture_only";
      const { default: Stripe } = await import("stripe");
      const sdk = new Stripe("sk_test_fixture_not_a_real_key");
      const pending = (await pool.query("SELECT * FROM payment_records WHERE agreement_id IS NOT NULL AND stripe_payment_intent_id IS NOT NULL AND status='pending' LIMIT 1")).rows[0];
      for (const livemode of [true, false]) {
        const callback = JSON.stringify({ id: `evt_scope_${livemode}`, object: "event", type: "payment_intent.succeeded", created: Math.floor(Date.now() / 1000), livemode, account: "acct_test_business", data: { object: { ...stripe.intents.get(pending.stripe_payment_intent_id), status: "succeeded" } } });
        const header = sdk.webhooks.generateTestHeaderString({ payload: callback, secret: process.env.STRIPE_WEBHOOK_SECRET });
        const response = await fetch(`${base}/stripe/webhook`, { method: "POST", headers: { "content-type": "application/json", "stripe-signature": header }, body: callback });
        assert.equal(response.status, 200, await response.text());
        // Neither wrong environment nor stale event payload overrides retrieval.
        assert.equal((await pool.query("SELECT status FROM payment_records WHERE id=$1", [pending.id])).rows[0].status, "pending");
      }
      const event = { id: "evt_invoice_fixture", object: "event", type: "invoice.payment_succeeded", created: Math.floor(Date.now() / 1000), livemode: false, account: "acct_test_business", data: { object: { object: "invoice", id: "in_current", subscription: "sub_same" } } };
      const payload = JSON.stringify(event);
      const signature = sdk.webhooks.generateTestHeaderString({ payload, secret: process.env.STRIPE_WEBHOOK_SECRET });
      for (let i = 0; i < 2; i++) {
        const response = await fetch(`${base}/stripe/webhook`, { method: "POST", headers: { "content-type": "application/json", "stripe-signature": signature }, body: payload });
        assert.equal(response.status, 200, await response.text());
      }
      const rows = (await pool.query("SELECT id,status FROM payment_records WHERE id=ANY($1::uuid[])", [[previousID, currentID]])).rows;
      assert.equal(rows.find((row) => row.id === previousID).status, "failed");
      assert.equal(rows.find((row) => row.id === currentID).status, "succeeded");
      assert.equal((await pool.query("SELECT processing_state,attempt_count FROM stripe_webhook_events WHERE stripe_event_id='evt_invoice_fixture'")).rows[0].attempt_count, 1);
    });
    const staff = { companyId: companyID, userId: ownerID };
    const offlineBody = (amount = 15000, balance = 70000) => ({ request_id: randomUUID(), amount_cents: amount, expected_balance_cents: balance, method: "check", reference: "Check 123", received_at: "2026-09-01T12:00:00.000Z", note: "Internal receipt note" });
    await t.test("offline cash/check receipts require company ownership, capability, and complete signatures", async () => {
      const offline = await agreement(), body = offlineBody();
      assert.equal((await request(`/api/agreements/${offline.row.id}/payments/offline`, body)).status, 401);
      await assert.rejects(adapter.recordOffline({ ...staff, companyId: randomUUID() }, offline.row.id, body), { status: 404 });
      const deniedID = randomUUID();
      await pool.query("INSERT INTO users(id,email,role,company_id) VALUES($1,'offline-denied@example.invalid','employee',$2)", [deniedID, companyID]);
      await pool.query(`INSERT INTO employee_permissions(user_id,company_id,permission_overrides) VALUES($1,$2,'{"payments.collect":false}')`, [deniedID, companyID]);
      await pool.query("INSERT INTO sessions(token,user_id) VALUES('offline-denied',$1)", [deniedID]);
      const denied = await fetch(`${base}/api/agreements/${offline.row.id}/payments/offline`, { method: "POST", headers: { "content-type": "application/json", authorization: "Bearer offline-denied" }, body: JSON.stringify(body) });
      assert.equal(denied.status, 403, await denied.text());
      const unsigned = await agreement({ signed: false });
      await assert.rejects(adapter.recordOffline(staff, unsigned.row.id, body), { code: "payment_signatures_required" });
      const invalid = [ { amount_cents: 0 }, { amount_cents: 1.5 }, { amount_cents: "100" }, { method: "stripe" }, { reference: "" }, { received_at: "2040-01-01T00:00:00Z" }, { received_at: "2026-09-01" }, { received_at: "2026-02-30T12:00:00Z" }, { note: "x".repeat(1001) }, { quote_id: randomUUID() } ];
      for (const patch of invalid) await assert.rejects(adapter.recordOffline(staff, offline.row.id, { ...body, ...patch }), error => error.status === 400);
      await assert.rejects(adapter.recordOffline(staff, offline.row.id, { ...body, expected_balance_cents: 1 }), { code: "payment_amount_changed" });
      await assert.rejects(adapter.recordOffline(staff, offline.row.id, { ...body, amount_cents: 70001 }), { code: "offline_payment_exceeds_balance" });
      assert.equal(Number((await pool.query("SELECT count(*) n FROM payment_records WHERE agreement_id=$1", [offline.row.id])).rows[0].n), 0);
    });
    await t.test("concurrent exact offline retries insert one manual payment, audit, and accounting source", async () => {
      const offline = await agreement(), body = offlineBody(), before = stripe.counts(), jobID = randomUUID();
      await pool.query("INSERT INTO schedule_events(id,user_id,company_id,contact_id,quote_id,title,start_at,end_at,finished_at,price_cents) VALUES($1,$2,$3,$4,$5,'Offline receipt service',now()-interval '2 hours',now()-interval '1 hour',now(),70000)", [jobID, ownerID, companyID, contactID, offline.row.quote_id]);
      const responses = await Promise.all(Array.from({ length: 6 }, () => request(`/api/agreements/${offline.row.id}/payments/offline`, body, true)));
      assert.ok(responses.every(result => result.status === 200), JSON.stringify(responses));
      assert.equal(new Set(responses.map(result => result.body.payment_record_id)).size, 1);
      const result = responses[0].body;
      assert.equal(result.status, "recorded"); assert.equal(result.payments.paid_cents, 15000); assert.equal(result.payments.balance_cents, 55000); assert.equal(result.payments.deposit_due_cents, 0);
      assert.deepEqual(stripe.counts(), before);
      const record = (await pool.query("SELECT * FROM payment_records WHERE id=$1", [result.payment_record_id])).rows[0];
      assert.equal(record.payment_type, "manual"); assert.equal(record.status, "succeeded"); assert.equal(record.created_by_user_id, ownerID); assert.equal(record.job_id, jobID); assert.equal(record.stripe_payment_intent_id, null); assert.equal(record.stripe_connected_account_id, null); assert.equal(record.paid_at.toISOString(), body.received_at);
      const receipt = (await pool.query("SELECT * FROM agreement_offline_payment_receipts WHERE payment_record_id=$1", [record.id])).rows[0];
      assert.equal(receipt.recorded_by, ownerID); assert.equal(receipt.reference, body.reference); assert.equal(receipt.note, body.note); assert.ok(receipt.recorded_at > receipt.received_at);
      assert.equal((await pool.query("SELECT count(*) n FROM agreement_events WHERE agreement_id=$1 AND type='payment_succeeded'", [offline.row.id])).rows[0].n, "1");
      assert.equal(result.payments.receipts[0].method, "check"); assert.equal(result.payments.receipts[0].reference, "Check 123"); assert.equal(result.payments.receipts[0].note, undefined); assert.equal(result.payments.receipts[0].recorded_by, undefined); assert.equal(result.payments.receipts[0].receipt_url, null);
      const state = await service.state(pool, offline.row); assert.equal(state.deposit, "paid"); assert.equal(state.can_view_availability, true);
      const { syncOperationalAccountingSources, buildReceivableSnapshot } = await import("../finance-operational-accounting.js");
      await syncOperationalAccountingSources(pool, companyID); await syncOperationalAccountingSources(pool, companyID);
      const sources = (await pool.query("SELECT * FROM finance_operational_sources WHERE company_id=$1 AND source_type='payment' AND source_id=$2", [companyID, record.id])).rows;
      assert.equal(sources.length, 1); assert.equal(Number(sources[0].amount_cents), 15000); assert.equal(sources[0].occurred_at.toISOString(), body.received_at); assert.equal(sources[0].job_id, jobID);
      const snapshot = buildReceivableSnapshot({ job: { id: jobID, price_cents: 70000, finished_at: new Date().toISOString() }, payments: [{ ...record, paid_at: record.paid_at.toISOString() }], asOf: "2040-01-01" });
      assert.equal(snapshot.net_payment_cents, 15000); assert.equal(snapshot.outstanding_cents, 55000);
      const restarted = createAgreementPayments({ pool, service, getStripe: () => stripe, env });
      assert.equal((await restarted.recordOffline(staff, offline.row.id, body)).payment_record_id, record.id);
      for (const patch of [{ amount_cents: 16000 }, { method: "cash" }, { reference: "Changed" }, { note: "Changed" }, { received_at: "2026-09-02T12:00:00.000Z" }, { expected_balance_cents: 55000 }]) await assert.rejects(adapter.recordOffline(staff, offline.row.id, { ...body, ...patch }), { code: "payment_request_conflict" });
      const other = await agreement(); await assert.rejects(adapter.recordOffline(staff, other.row.id, body), { code: "payment_request_conflict" });
      const revision = await agreement({ quoteID: offline.row.quote_id, revision: 2 });
      assert.equal((await adapter.paymentSummary(pool, revision.row)).paid_cents, 15000);
      const remainder = await adapter.recordOffline(staff, revision.row.id, { ...offlineBody(55000, 55000), method: "cash", reference: "" });
      assert.equal(remainder.payments.balance_cents, 0); assert.equal(remainder.payments.paid_cents, 70000);
      assert.equal((await adapter.recordOffline(staff, offline.row.id, body)).payments.balance_cents, 0);
    });
    await t.test("offline collection serializes with checkout and does not overwrite processing or unknown provider outcomes", async () => {
      for (const status of ["open", "creating", "processing", "review"]) {
        const offline = await agreement(); await checkout(offline); const attempt = await attemptFor(offline.row);
        if (status === "processing") { stripe.begin(attempt.checkout_session_id); await adapter.reconcileAttempt(attempt); }
        else if (status !== "open") await pool.query("UPDATE agreement_payment_attempts SET state=$2 WHERE id=$1", [attempt.id, status]);
        await assert.rejects(adapter.recordOffline(staff, offline.row.id, offlineBody()), { code: status === "review" ? "payment_adjustment_review_required" : "payment_already_in_progress" });
        assert.equal(Number((await pool.query("SELECT count(*) n FROM agreement_offline_payment_receipts WHERE agreement_id=$1", [offline.row.id])).rows[0].n), 0);
      }
      const canceled = await agreement(); await checkout(canceled); const attempt = await attemptFor(canceled.row);
      await adapter.cancelStaffAttempt(staff, canceled.row.id, { attempt_id: attempt.id, request_id: randomUUID() });
      assert.equal((await adapter.recordOffline(staff, canceled.row.id, offlineBody())).payments.paid_cents, 15000);
      const race = await agreement();
      const result = await Promise.all([checkout(race), request(`/api/agreements/${race.row.id}/payments/offline`, offlineBody(), true)]);
      const paid = await adapter.paymentSummary(pool, race.row);
      assert.ok(result.every(item => [200, 409].includes(item.status)), JSON.stringify(result));
      assert.ok(!(paid.paid_cents > 0 && paid.active_checkout), JSON.stringify(paid));
      const full = await agreement();
      const attempts = await Promise.all(Array.from({ length: 5 }, () => request(`/api/agreements/${full.row.id}/payments/offline`, offlineBody(70000), true)));
      assert.equal(attempts.filter(result => result.status === 200).length, 1); assert.equal((await adapter.paymentSummary(pool, full.row)).paid_cents, 70000);
    });
    assert.equal(stripePaymentMode(env), false);
    assert.throws(() => stripePaymentMode({ STRIPE_SECRET_KEY: "sk_live_fixture", STRIPE_MODE: "test" }), { code: "stripe_mode_not_configured" });
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
    if (pool) await pool.end(); postgres.stop();
  }
});
