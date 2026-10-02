import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import pg from 'pg';
import { randomUUID, createHash } from 'node:crypto';
import { startLocalPostgres } from './helpers/local-postgres.js';
import { installStripeAccountManagementSchema, installStripeAccountManagement, stripeConnectionOptions } from '../stripe-account-management.js';

test('Stripe account replacement: authenticated, one-use, tenant-bound, preserves old connection on failure', { timeout: 60000 }, async t => {
  const local = startLocalPostgres(), pool = new pg.Pool(local.config);
  let server;
  try {
    await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto;
      CREATE TABLE companies(id UUID PRIMARY KEY);
      CREATE TABLE users(id UUID PRIMARY KEY,company_id UUID,role TEXT,deleted_at TIMESTAMPTZ);
      CREATE TABLE business_settings(user_id UUID PRIMARY KEY,company_id UUID,stripe_account_id TEXT,stripe_connect_status TEXT,stripe_charges_enabled BOOL,stripe_payouts_enabled BOOL,stripe_details_submitted BOOL,stripe_default_currency TEXT,updated_at TIMESTAMPTZ);
      CREATE TABLE service_plans(company_id UUID,stripe_connected_account_id TEXT,status TEXT);
      CREATE TABLE agreement_plan_enrollments(company_id UUID,connected_account_id TEXT,canceled_at TIMESTAMPTZ,state TEXT);
      CREATE TABLE agreement_payment_attempts(company_id UUID,connected_account_id TEXT,state TEXT);`);
    await installStripeAccountManagementSchema(pool); await installStripeAccountManagementSchema(pool);
    const company = randomUUID(), user = randomUUID(), otherCompany = randomUUID();
    await pool.query('INSERT INTO companies VALUES($1),($2)', [company, otherCompany]);
    await pool.query("INSERT INTO users VALUES($1,$2,'employer',NULL)", [user, company]);
    await pool.query("INSERT INTO business_settings(user_id,company_id,stripe_account_id) VALUES($1,$2,'acct_old')", [user, company]);
    const env = { STRIPE_SECRET_KEY: 'sk_test_fixture', STRIPE_CONNECT_CLIENT_ID: 'ca_fixture', STRIPE_CONNECT_OAUTH_REDIRECT_URL: 'http://localhost/stripe/connect/oauth/callback' };
    let tokenCalls = 0, tokenMode = false, providerFail = false;
    const stripe = { oauth: { token: async () => { tokenCalls++; if (providerFail) throw new Error('provider private details'); return { stripe_user_id: 'acct_new', scope: 'read_write', livemode: tokenMode }; } }, accounts: { retrieve: async id => ({id,details_submitted:true,charges_enabled:true,payouts_enabled:true,default_currency:'usd'}) } };
    const app = express(); app.use(express.json());
    const authRequired = (req,res,next) => { if (!req.headers.authorization) return res.sendStatus(401); req.userId=user;req.companyId=company;req.role=req.headers.authorization;next(); };
    const requireEmployer = (req,res,next) => req.role==='owner'?next():res.sendStatus(403);
    const ensureBusinessSettings = async () => (await pool.query('SELECT * FROM business_settings WHERE user_id=$1',[user])).rows[0];
    installStripeAccountManagement({ app,pool,authRequired,requireEmployer,requireCapability:()=> (_req,_res,next)=>next(),getStripe:()=>stripe,ensureBusinessSettings,sanitizeBusinessSettings:row=>row,env });
    server = app.listen(0,'127.0.0.1'); await new Promise(resolve=>server.once('listening',resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    const post = (path,body={},auth='owner') => fetch(base+'/api/payments/connect/'+path,{method:'POST',headers:{'Content-Type':'application/json',...(auth?{Authorization:auth}:{})},body:JSON.stringify(body)});
    const current = async () => (await ensureBusinessSettings()).stripe_account_id;
    const begin = async () => { const response=await post('existing-account');assert.equal(response.status,200); const {url}=await response.json();const state=new URL(url).searchParams.get('state');const start=await fetch(base+new URL(url).pathname+'?state='+state,{redirect:'manual'});assert.equal(start.status,303);assert.match(start.headers.get('location'),/^https:\/\/connect.stripe.com\/oauth\/authorize/);return {state,cookie:start.headers.get('set-cookie').split(';')[0]}; };
    const callback = ({state,cookie},extra='code=fixture')=>fetch(base+'/stripe/connect/oauth/callback?state='+state+'&'+extra,{headers:cookie?{Cookie:cookie}:{}});
    await t.test('status exposes mode and OAuth availability without secrets',()=>{assert.deepEqual(stripeConnectionOptions(env),{stripe_mode:'test',stripe_existing_account_available:true});});
    await t.test('authentication and owner role required', async()=> {assert.equal((await post('disconnect',{},null)).status,401);assert.equal((await post('existing-account',{},'employee')).status,403);});
    await t.test('missing configuration is actionable and preserves account', async()=>{delete env.STRIPE_CONNECT_CLIENT_ID;const response=await post('existing-account');assert.equal(response.status,503);assert.equal(await current(),'acct_old');env.STRIPE_CONNECT_CLIENT_ID='ca_fixture';});
    await t.test('active plans and in-flight checkout block changes',async()=>{
      await pool.query("INSERT INTO service_plans VALUES($1,'acct_old','active')",[company]);assert.equal((await post('disconnect',{expected_account_id:'acct_old'})).status,409);await pool.query('DELETE FROM service_plans');
      await pool.query("INSERT INTO agreement_payment_attempts VALUES($1,'acct_old','processing')",[company]);assert.equal((await post('existing-account')).status,409);await pool.query('DELETE FROM agreement_payment_attempts');
      assert.equal(await current(),'acct_old');
    });
    await t.test('cookie binding, cancellation, replay and failed provider preserve connection',async()=>{
      const session=await begin();assert.equal((await callback({...session,cookie:null})).status,400);assert.equal(tokenCalls,0);
      assert.equal((await callback(session,'error=access_denied')).status,200);assert.equal((await callback(session)).status,400);
      providerFail=true;const failed=await callback(await begin());assert.equal(failed.status,502);assert.doesNotMatch(await failed.text(),/private details/);providerFail=false;assert.equal(await current(),'acct_old');
    });
    await t.test('expired authorization, changed owner and stale account fail closed',async()=>{
      let session=await begin();await pool.query('UPDATE stripe_connection_authorizations SET expires_at=now()-interval \'1 minute\' WHERE state_hash=$1',[createHash('sha256').update(session.state).digest('hex')]);assert.equal((await callback(session)).status,400);
      session=await begin();await pool.query("UPDATE users SET role='employee' WHERE id=$1",[user]);assert.equal((await callback(session)).status,403);await pool.query("UPDATE users SET role='employer' WHERE id=$1",[user]);
      session=await begin();await pool.query("UPDATE business_settings SET stripe_account_id='acct_changed'");assert.equal((await callback(session)).status,409);await pool.query("UPDATE business_settings SET stripe_account_id='acct_old'");
    });
    await t.test('cross-company account and mode mismatch fail without replacement',async()=>{
      const other=randomUUID();await pool.query("INSERT INTO users VALUES($1,$2,'employer',NULL)",[other,otherCompany]);await pool.query("INSERT INTO business_settings(user_id,company_id,stripe_account_id) VALUES($1,$2,'acct_new')",[other,otherCompany]);
      assert.equal((await callback(await begin())).status,409);await pool.query('DELETE FROM business_settings WHERE user_id=$1',[other]);
      tokenMode=true;assert.equal((await callback(await begin())).status,409);tokenMode=false;assert.equal(await current(),'acct_old');
    });
    await t.test('successful replacement audited once and disconnect retains history',async()=>{
      const session=await begin();assert.equal(await current(),'acct_old');assert.equal((await callback(session)).status,200);assert.equal(await current(),'acct_new');assert.equal((await callback(session)).status,400);
      assert.equal((await post('disconnect',{expected_account_id:'acct_old'})).status,409);
      const disconnected=await post('disconnect',{expected_account_id:'acct_new'});assert.equal(disconnected.status,200);assert.equal(await current(),null);
      assert.equal((await pool.query('SELECT count(*)::int AS n FROM stripe_connection_history')).rows[0].n,2);
      assert.equal((await post('disconnect',{expected_account_id:null})).status,200);
    });
  } finally { if(server) await new Promise(resolve=>server.close(resolve));await pool.end();local.stop(); }
});
