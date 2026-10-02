import { randomBytes, createHash } from 'node:crypto';
import { calculateStripeConnectReadiness } from './stripe-connect-status.js';

const digest = value => createHash('sha256').update(value).digest('hex');
const fail = (code, message, status = 409) => { throw Object.assign(new Error(message), { code, status }); };
export function stripeConnectionMode(env = process.env) {
  return /^(?:sk|rk)_(test|live)_/.exec(env.STRIPE_SECRET_KEY || '')?.[1] || 'unconfigured';
}
export function stripeConnectionOptions(env = process.env) {
  return { stripe_mode: stripeConnectionMode(env), stripe_existing_account_available: /^ca_[A-Za-z0-9]+$/.test(env.STRIPE_CONNECT_CLIENT_ID || '') };
}
export async function installStripeAccountManagementSchema(pool) {
  await pool.query(`CREATE TABLE IF NOT EXISTS stripe_connection_authorizations (
    state_hash TEXT PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE, expected_account_id TEXT,
    mode TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  CREATE INDEX IF NOT EXISTS stripe_connection_authorizations_expiry_idx ON stripe_connection_authorizations(expires_at);
  CREATE TABLE IF NOT EXISTS stripe_connection_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), company_id UUID NOT NULL REFERENCES companies(id),
    user_id UUID NOT NULL REFERENCES users(id), previous_account_id TEXT, account_id TEXT,
    mode TEXT NOT NULL, action TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );`);
}
export async function assertStripeConnectionChangeAllowed(db, companyId, accountId) {
  if (!accountId) return;
  const result = await db.query(`SELECT
    EXISTS(SELECT 1 FROM service_plans WHERE company_id=$1 AND stripe_connected_account_id=$2
      AND status NOT IN ('canceled','cancelled','completed','expired')) AS plans,
    EXISTS(SELECT 1 FROM agreement_plan_enrollments WHERE company_id=$1 AND connected_account_id=$2
      AND canceled_at IS NULL AND state NOT IN ('completed','expired','failed','canceled')) AS enrollments,
    EXISTS(SELECT 1 FROM agreement_payment_attempts WHERE company_id=$1 AND connected_account_id=$2
      AND state IN ('creating','open','processing','review')) AS checkout`, [companyId, accountId]);
  const row = result.rows[0];
  if (row.plans || row.enrollments) fail('stripe_account_has_plans', 'This Stripe account has active or unfinished service plans. End those plans or finish their pending enrollment before changing accounts. Saved cards cannot transfer between Stripe accounts.');
  if (row.checkout) fail('stripe_account_has_checkout', 'A customer checkout is still open or processing. Finish or cancel that checkout before changing Stripe accounts.');
}
export function installStripeAccountManagement({ app, pool, authRequired, requireEmployer, requireCapability, getStripe, ensureBusinessSettings, sanitizeBusinessSettings, env = process.env }) {
  const auth = [authRequired, requireEmployer, requireCapability('payments.manage')];
  const callback = () => env.STRIPE_CONNECT_OAUTH_REDIRECT_URL || new URL('/stripe/connect/oauth/callback', env.STRIPE_CONNECT_RETURN_URL || 'https://wolfcrm-backend-production.up.railway.app').href;
  const options = () => stripeConnectionOptions(env);
  const privateHeaders = res => res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Robots-Tag': 'noindex, nofollow' });
  const sendError = (res, error) => res.status(error.status || 502).json({ error: error.status ? error.code : 'stripe_connection_failed', message: error.status ? error.message : 'Stripe could not complete this account change. Your existing connection has been preserved. Please retry.' });
  const page = (res, message, status = 200) => {
    privateHeaders(res); res.status(status).type('html').send(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>WolfCRM Stripe connection</title></head><body style="font-family:system-ui;text-align:center;padding:60px 24px"><h1>Stripe connection</h1><p>${message.replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]))}</p><p>Close this window and return to Payments in WolfCRM.</p></body></html>`);
  };
  app.post('/api/payments/connect/existing-account', ...auth, async (req, res) => {
    privateHeaders(res);
    try {
      if (!getStripe() || !options().stripe_existing_account_available) fail('stripe_oauth_setup_required', 'Existing-account sign-in needs the platform Stripe Connect OAuth client ID and redirect URL configured. Your current connection is unchanged.', 503);
      const settings = await ensureBusinessSettings(req.userId, req.companyId);
      await assertStripeConnectionChangeAllowed(pool, req.companyId, settings.stripe_account_id);
      const state = randomBytes(32).toString('hex');
      await pool.query('DELETE FROM stripe_connection_authorizations WHERE expires_at < now()');
      await pool.query(`INSERT INTO stripe_connection_authorizations(state_hash,user_id,company_id,expected_account_id,mode,expires_at)
        VALUES($1,$2,$3,$4,$5,now()+interval '15 minutes')`, [digest(state), req.userId, req.companyId, settings.stripe_account_id, stripeConnectionMode(env)]);
      const start = new URL('/stripe/connect/oauth/start', callback()); start.searchParams.set('state', state);
      res.json({ url: start.href, settings: { ...sanitizeBusinessSettings(settings), ...options() } });
    } catch (error) { sendError(res, error); }
  });
  // Establish a short-lived browser binding before leaving for Stripe. The API
  // is authenticated through either native bearer auth or the Web session proxy.
  app.get('/stripe/connect/oauth/start', async (req, res) => {
    privateHeaders(res);
    const state = typeof req.query.state === 'string' ? req.query.state : '';
    try {
      if (!/^[a-f0-9]{64}$/.test(state)) return page(res, 'This connection link is invalid. Start again from Payments.', 400);
      const row = (await pool.query('SELECT state_hash FROM stripe_connection_authorizations WHERE state_hash=$1 AND used_at IS NULL AND expires_at>now()', [digest(state)])).rows[0];
      if (!row) return page(res, 'This connection link has expired. Start again from Payments.', 400);
      res.cookie('wolf_stripe_connect', digest(state), { httpOnly: true, secure: callback().startsWith('https:'), sameSite: 'lax', maxAge: 15 * 60 * 1000, path: '/stripe/connect/oauth' });
      const url = new URL('https://connect.stripe.com/oauth/authorize');
      for (const [key, value] of Object.entries({ response_type: 'code', scope: 'read_write', client_id: env.STRIPE_CONNECT_CLIENT_ID, redirect_uri: callback(), state, always_prompt: 'true' })) url.searchParams.set(key, value);
      res.redirect(303, url.href);
    } catch { page(res, 'Stripe sign-in is temporarily unavailable. Retry from Payments.', 503); }
  });
  app.get('/stripe/connect/oauth/callback', async (req, res) => {
    privateHeaders(res);
    const state = typeof req.query.state === 'string' ? req.query.state : '';
    const cookie = /(?:^|;\s*)wolf_stripe_connect=([^;]*)/.exec(req.headers.cookie || '')?.[1];
    if (!/^[a-f0-9]{64}$/.test(state) || cookie !== digest(state)) return page(res, 'The sign-in session does not match. Start again from Payments.', 400);
    res.clearCookie('wolf_stripe_connect', { path: '/stripe/connect/oauth', secure: callback().startsWith('https:'), sameSite: 'lax' });
    let db;
    try {
      const intent = (await pool.query(`UPDATE stripe_connection_authorizations SET used_at=now()
        WHERE state_hash=$1 AND used_at IS NULL AND expires_at>now() RETURNING *`, [digest(state)])).rows[0];
      if (!intent) return page(res, 'This sign-in has already finished or expired. Start again from Payments.', 400);
      if (req.query.error) return page(res, 'Sign-in was canceled. Your existing Stripe connection is unchanged.');
      if (typeof req.query.code !== 'string' || !req.query.code || intent.mode !== stripeConnectionMode(env)) fail('stripe_signin_invalid', 'The payment environment changed or Stripe did not return an authorization. Start again.', 400);
      db = await pool.connect(); await db.query('BEGIN');
      const user = (await db.query(`SELECT id FROM users WHERE id=$1 AND company_id=$2 AND role='employer' AND deleted_at IS NULL FOR UPDATE`, [intent.user_id, intent.company_id])).rows[0];
      if (!user) fail('stripe_owner_changed', 'The company owner changed. Sign in to WolfCRM again.', 403);
      const settings = (await db.query('SELECT * FROM business_settings WHERE user_id=$1 AND company_id=$2 FOR UPDATE', [intent.user_id, intent.company_id])).rows[0];
      if (!settings || settings.stripe_account_id !== intent.expected_account_id) fail('stripe_connection_changed', 'The connected account changed while you were signing in. Start again from Payments.');
      await assertStripeConnectionChangeAllowed(db, intent.company_id, settings.stripe_account_id);
      const stripe = getStripe();
      const token = await stripe.oauth.token({ grant_type: 'authorization_code', code: req.query.code });
      if (token.livemode !== (intent.mode === 'live') || token.scope !== 'read_write' || !/^acct_[A-Za-z0-9]+$/.test(token.stripe_user_id || '')) fail('stripe_mode_mismatch', 'Stripe returned an account for a different payment environment. Your old connection is unchanged.');
      const account = await stripe.accounts.retrieve(token.stripe_user_id);
      // One Stripe merchant must not silently mix unrelated WolfCRM companies.
      await db.query('SELECT pg_advisory_xact_lock(hashtext($1))', ['stripe-account:' + account.id]);
      if ((await db.query('SELECT 1 FROM business_settings WHERE stripe_account_id=$1 AND company_id<>$2 LIMIT 1', [account.id, intent.company_id])).rows.length) fail('stripe_account_in_use', 'That Stripe account is already connected to another WolfCRM company.');
      const readiness = calculateStripeConnectReadiness(account);
      await db.query(`UPDATE business_settings SET stripe_account_id=$2,stripe_connect_status=$3,stripe_charges_enabled=$4,stripe_payouts_enabled=$5,stripe_details_submitted=$6,stripe_default_currency=COALESCE($7,stripe_default_currency),updated_at=now() WHERE user_id=$1`, [intent.user_id, account.id, readiness.stripe_connect_status, readiness.stripe_charges_enabled, readiness.stripe_payouts_enabled, readiness.stripe_details_submitted, readiness.stripe_default_currency]);
      await db.query(`INSERT INTO stripe_connection_history(company_id,user_id,previous_account_id,account_id,mode,action) VALUES($1,$2,$3,$4,$5,'connect')`, [intent.company_id, intent.user_id, settings.stripe_account_id, account.id, intent.mode]);
      await db.query('COMMIT');
      page(res, intent.mode === 'test' ? 'Your Stripe test account is connected. Test mode does not accept real payments.' : 'Your Stripe account is connected. Return to WolfCRM to check payment readiness.');
    } catch (error) { if (db) await db.query('ROLLBACK').catch(() => {}); page(res, error.status ? error.message : 'Stripe sign-in could not finish. Your previous connection remains in place; retry from Payments.', error.status || 502); }
    finally { db?.release(); }
  });
  app.post('/api/payments/connect/disconnect', ...auth, async (req, res) => {
    privateHeaders(res); let db;
    try {
      await ensureBusinessSettings(req.userId, req.companyId);
      db = await pool.connect(); await db.query('BEGIN');
      const settings = (await db.query('SELECT * FROM business_settings WHERE user_id=$1 AND company_id=$2 FOR UPDATE', [req.userId, req.companyId])).rows[0];
      if (!settings || !Object.hasOwn(req.body || {}, 'expected_account_id') || settings.stripe_account_id !== req.body.expected_account_id) fail('stripe_connection_changed', 'The Stripe connection changed. Refresh Payments and try again.');
      await assertStripeConnectionChangeAllowed(db, req.companyId, settings.stripe_account_id);
      if (settings.stripe_account_id) await db.query(`INSERT INTO stripe_connection_history(company_id,user_id,previous_account_id,mode,action) VALUES($1,$2,$3,$4,'disconnect')`, [req.companyId, req.userId, settings.stripe_account_id, stripeConnectionMode(env)]);
      const updated = (await db.query(`UPDATE business_settings SET stripe_account_id=NULL,stripe_connect_status='not_connected',stripe_charges_enabled=false,stripe_payouts_enabled=false,stripe_details_submitted=false,updated_at=now() WHERE user_id=$1 RETURNING *`, [req.userId])).rows[0];
      // Do not delete/deauthorize the merchant: historical refunds, reconciliation
      // and retained account-scoped records must remain accessible.
      await db.query('COMMIT'); res.json({ settings: { ...sanitizeBusinessSettings(updated), ...options() } });
    } catch (error) { if (db) await db.query('ROLLBACK').catch(() => {}); sendError(res, error); }
    finally { db?.release(); }
  });
}
