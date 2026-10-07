import assert from "node:assert/strict";
import test from "node:test";
import { FOCUS_META_DEFAULT_GRAPH_VERSION, FOCUS_META_DEFAULT_SCOPES, buildFocusCapabilityMatrix, fixtureProbeObservations, focusProviderFailureCode, installFocusSchema, installFocusSystem, normalizeHashtag } from "./focus.js";

test("Focus schema installer is additive and contains tenant-scoped persistence", async () => {
  const statements = [];
  const pool = { query: async (statement) => { statements.push(statement); return { rows: [] }; } };
  await installFocusSchema(pool);
  assert.equal(statements.length, 1);
  const schema = statements[0];
  for (const table of [
    "focus_settings", "focus_settings_history", "focus_connections", "focus_creators",
    "focus_creator_nominations", "focus_hashtag_discovery", "focus_content", "focus_content_assets", "focus_content_state",
    "focus_likes", "focus_feed_entries", "focus_jobs", "focus_cost_ledger", "focus_probe_runs",
    "focus_comments", "focus_conversations", "focus_messages", "focus_webhook_receipts"
  ]) assert.match(schema, new RegExp(`CREATE TABLE IF NOT EXISTS ${table}`));
  assert.match(schema, /CREATE INDEX IF NOT EXISTS focus_content_candidate_idx/);
  assert.match(schema, /user_id UUID NOT NULL REFERENCES users/);
  assert.doesNotMatch(schema, /DROP\s+/i);
});

test("Meta hashtag discovery accepts a bounded tag and rejects a profile or URL", () => {
  assert.equal(normalizeHashtag("#WindowWashing"), "windowwashing");
  assert.throws(() => normalizeHashtag("@creator"), { code: "invalid_instagram_hashtag" });
  assert.throws(() => normalizeHashtag("https://instagram.com/tag"), { code: "invalid_instagram_hashtag" });
});

test("Meta defaults follow the current Facebook Login contract and provider failures remain sanitized", () => {
  assert.equal(FOCUS_META_DEFAULT_GRAPH_VERSION, "v26.0");
  assert.equal(FOCUS_META_DEFAULT_SCOPES, "instagram_basic,pages_show_list,pages_read_engagement");
  assert.equal(focusProviderFailureCode("meta_oauth_exchange_failed"), "meta_oauth_exchange_failed_provider_rejected");
  assert.match(focusProviderFailureCode("meta failure: 190"), /^[a-z0-9_]+$/);
  const metaOAuth = buildFocusCapabilityMatrix({ FOCUS_META_APP_ID: "app", FOCUS_META_APP_SECRET: "secret", FOCUS_META_REDIRECT_URI: "https://example.test/callback", FOCUS_TOKEN_ENCRYPTION_KEY: "key" }).meta_oauth;
  assert.equal(metaOAuth.setup_error, "meta_login_configuration_required");
  assert.deepEqual(metaOAuth.authorization_parameters, ["client_id", "redirect_uri", "state", "response_type"]);
  assert.deepEqual(metaOAuth.required_configuration_permissions, ["instagram_basic", "pages_show_list", "pages_read_engagement"]);
});

test("Supply Probe fixture records every required measurement without claiming live evidence", () => {
  const observations = fixtureProbeObservations();
  const keys = new Set(observations.map((item) => item.metric_key));
  for (const key of [
    "professional_creators_discovered", "creator_profile_availability", "follower_count_eligibility",
    "native_playable_percentage", "playback_rejection_reasons", "relevant_content_yield",
    "fresh_content_yield", "eligible_posts", "candidate_supply_per_day", "ready_bank_sustainability"
  ]) assert.ok(keys.has(key), `missing ${key}`);
  assert.ok(observations.every((item) => item.metric_value.fixture_only === true));
});

test("Facebook Login for Business OAuth uses config_id, never conflicting scopes, and preserves provider errors", async () => {
  const original = Object.fromEntries([
    "FOCUS_META_APP_ID", "FOCUS_META_APP_SECRET", "FOCUS_META_REDIRECT_URI", "FOCUS_TOKEN_ENCRYPTION_KEY", "FOCUS_META_SCOPES", "FOCUS_META_LOGIN_CONFIG_ID"
  ].map((key) => [key, process.env[key]]));
  Object.assign(process.env, {
    FOCUS_META_APP_ID: "test-meta-app-id",
    FOCUS_META_APP_SECRET: "test-meta-app-secret",
    FOCUS_META_REDIRECT_URI: "https://example.test/api/focus/connections/meta/callback",
    FOCUS_TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 7).toString("base64"),
    FOCUS_META_SCOPES: "instagram_basic,pages_show_list,pages_read_engagement",
    FOCUS_META_LOGIN_CONFIG_ID: "test-business-login-configuration"
  });

  try {
    const routes = new Map();
    const register = (method) => (path, ...handlers) => routes.set(`${method} ${path}`, handlers);
    const app = { get: register("GET"), post: register("POST"), put: register("PUT"), delete: register("DELETE") };
    const queries = [];
    const pool = {
      query: async (statement, values) => {
        queries.push({ statement, values });
        if (statement.startsWith("DELETE FROM focus_oauth_states WHERE state_hash")) return { rows: [{ user_id: "user-id", company_id: "company-id" }] };
        return { rows: [] };
      }
    };
    const pass = (_req, _res, next) => next();
    await installFocusSystem({ app, pool, authRequired: pass, requireCapability: () => pass });

    const req = { userId: "user-id", companyId: "company-id" };
    const res = { json(payload) { this.payload = payload; } };
    for (const handler of routes.get("GET /api/focus/connections/meta/start")) {
      const result = handler(req, res, (error) => { if (error) throw error; });
      if (result?.then) await result;
    }

    const stateQueries = queries.slice(1);
    assert.equal(stateQueries.length, 2);
    assert.match(stateQueries[0].statement, /^DELETE FROM focus_oauth_states WHERE expires_at < now\(\)$/);
    assert.equal(stateQueries[0].values, undefined);
    assert.match(stateQueries[1].statement, /^INSERT INTO focus_oauth_states/);
    assert.equal(stateQueries[1].values.length, 4);
    const authorizationURL = new URL(res.payload.authorization_url);
    assert.equal(authorizationURL.origin, "https://www.facebook.com");
    assert.equal(authorizationURL.pathname, "/v26.0/dialog/oauth");
    assert.equal(authorizationURL.searchParams.get("config_id"), "test-business-login-configuration");
    assert.equal(authorizationURL.searchParams.has("scope"), false);

    const callbackRes = { redirect(url) { this.url = url; } };
    await routes.get("GET /api/focus/connections/meta/callback")[0]({ query: { state: authorizationURL.searchParams.get("state"), error: "invalid_scope", error_description: "Invalid Scopes: instagram_basic" } }, callbackRes);
    assert.match(callbackRes.url, /status=failed/);
    assert.match(callbackRes.url, /reason=meta_oauth_invalid_scope/);
    const failure = queries.find((query) => query.statement.includes("capability_snapshot,status,last_error_code"));
    assert.deepEqual(failure.values.slice(0, 3), ["user-id", "company-id", "meta_graph"]);
    assert.equal(failure.values[4], "meta_oauth_invalid_scope");
  } finally {
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

test("OAuth callback persists a sanitized exchange failure after it consumes a valid state", async () => {
  const original = Object.fromEntries([
    "FOCUS_META_APP_ID", "FOCUS_META_APP_SECRET", "FOCUS_META_REDIRECT_URI", "FOCUS_TOKEN_ENCRYPTION_KEY", "FOCUS_META_LOGIN_CONFIG_ID"
  ].map((key) => [key, process.env[key]]));
  const originalFetch = globalThis.fetch;
  Object.assign(process.env, {
    FOCUS_META_APP_ID: "test-meta-app-id",
    FOCUS_META_APP_SECRET: "test-meta-app-secret",
    FOCUS_META_REDIRECT_URI: "https://example.test/api/focus/connections/meta/callback",
    FOCUS_TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 9).toString("base64"),
    FOCUS_META_LOGIN_CONFIG_ID: "test-business-login-configuration"
  });
  globalThis.fetch = async () => ({ ok: false, status: 400, json: async () => ({ error: { code: 100 } }) });

  try {
    const routes = new Map();
    const register = (method) => (path, ...handlers) => routes.set(`${method} ${path}`, handlers);
    const app = { get: register("GET"), post: register("POST"), put: register("PUT"), delete: register("DELETE") };
    const queries = [];
    const pool = {
      query: async (statement, values) => {
        queries.push({ statement, values });
        if (statement.startsWith("DELETE FROM focus_oauth_states WHERE state_hash")) return { rows: [{ user_id: "user-id", company_id: "company-id" }] };
        return { rows: [] };
      }
    };
    const pass = (_req, _res, next) => next();
    await installFocusSystem({ app, pool, authRequired: pass, requireCapability: () => pass });
    const response = { redirect(url) { this.url = url; } };
    await routes.get("GET /api/focus/connections/meta/callback")[0]({ query: { state: "state", code: "one-time-code" } }, response);
    assert.match(response.url, /status=failed/);
    assert.match(response.url, /reason=meta_oauth_exchange_failed_provider_rejected/);
    const failure = queries.find((query) => query.statement.includes("capability_snapshot,status,last_error_code"));
    assert.deepEqual(failure.values.slice(0, 3), ["user-id", "company-id", "meta_graph"]);
    assert.equal(failure.values[4], "meta_oauth_exchange_failed_provider_rejected");
  } finally {
    globalThis.fetch = originalFetch;
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

test("OAuth keeps an encrypted token and exposes Page-link diagnostics when Meta returns no eligible Page asset", async () => {
  const original = Object.fromEntries([
    "FOCUS_META_APP_ID", "FOCUS_META_APP_SECRET", "FOCUS_META_REDIRECT_URI", "FOCUS_TOKEN_ENCRYPTION_KEY", "FOCUS_META_LOGIN_CONFIG_ID"
  ].map((key) => [key, process.env[key]]));
  const originalFetch = globalThis.fetch;
  Object.assign(process.env, {
    FOCUS_META_APP_ID: "test-meta-app-id",
    FOCUS_META_APP_SECRET: "test-meta-app-secret",
    FOCUS_META_REDIRECT_URI: "https://example.test/api/focus/connections/meta/callback",
    FOCUS_TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 3).toString("base64"),
    FOCUS_META_LOGIN_CONFIG_ID: "test-business-login-configuration"
  });
  const responses = [
    { ok: true, status: 200, json: async () => ({ access_token: "test-access-token", expires_in: 3600 }) },
    { ok: true, status: 200, json: async () => ({ data: [] }) }
  ];
  globalThis.fetch = async () => responses.shift();

  try {
    const routes = new Map();
    const register = (method) => (path, ...handlers) => routes.set(`${method} ${path}`, handlers);
    const app = { get: register("GET"), post: register("POST"), put: register("PUT"), delete: register("DELETE") };
    const queries = [];
    const pool = {
      query: async (statement, values) => {
        queries.push({ statement, values });
        if (statement.startsWith("DELETE FROM focus_oauth_states WHERE state_hash")) return { rows: [{ user_id: "user-id", company_id: "company-id" }] };
        return { rows: [] };
      }
    };
    const pass = (_req, _res, next) => next();
    await installFocusSystem({ app, pool, authRequired: pass, requireCapability: () => pass });
    const response = { redirect(url) { this.url = url; } };
    await routes.get("GET /api/focus/connections/meta/callback")[0]({ query: { state: "state", code: "one-time-code" } }, response);

    assert.match(response.url, /status=failed/);
    assert.match(response.url, /reason=meta_page_access_not_granted/);
    const persistedToken = queries.find((query) => query.statement.startsWith("INSERT INTO focus_connections(user_id,company_id,provider,token_ciphertext"));
    assert.ok(persistedToken, "token persistence must happen before Page-account resolution");
    assert.deepEqual(persistedToken.values.slice(0, 3), ["user-id", "company-id", "meta_graph"]);
    assert.ok(typeof persistedToken.values[3] === "string" && persistedToken.values[3].length > 0);
    assert.ok(typeof persistedToken.values[4] === "string" && persistedToken.values[4].length > 0);
    assert.ok(typeof persistedToken.values[5] === "string" && persistedToken.values[5].length > 0);

    const failure = queries.find((query) => query.statement.includes("capability_snapshot,status,last_error_code"));
    assert.equal(failure.values[4], "meta_page_access_not_granted");
    assert.deepEqual(JSON.parse(failure.values[3]).oauth.diagnostic, { managed_pages_returned: 0, linked_professional_accounts: 0 });
  } finally {
    globalThis.fetch = originalFetch;
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

test("missing encrypted connection material is a connection error, never a false token expiry", async () => {
  const routes = new Map();
  const register = (method) => (path, ...handlers) => routes.set(`${method} ${path}`, handlers);
  const app = { get: register("GET"), post: register("POST"), put: register("PUT"), delete: register("DELETE") };
  const queries = [];
  const pool = {
    query: async (statement, values) => {
      queries.push({ statement, values });
      if (statement.startsWith("SELECT * FROM focus_connections")) return { rows: [{ id: "connection-id", provider: "meta_graph", status: "verifying", token_ciphertext: null, token_iv: null, token_tag: null }] };
      return { rows: [] };
    }
  };
  const pass = (_req, _res, next) => next();
  await installFocusSystem({ app, pool, authRequired: pass, requireCapability: () => pass });
  const response = {
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.payload = payload; }
  };

  await routes.get("POST /api/focus/connections/meta/verify").at(-1)({ userId: "user-id", companyId: "company-id" }, response);
  const update = queries.find((query) => query.statement.startsWith("UPDATE focus_connections SET status='error'"));
  assert.deepEqual(update.values, ["connection-id", "focus_connection_token_missing"]);
  assert.equal(response.statusCode, 409);
  assert.equal(response.payload.error, "focus_connection_token_missing");
});
