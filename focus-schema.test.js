import assert from "node:assert/strict";
import test from "node:test";
import { FOCUS_META_DEFAULT_GRAPH_VERSION, FOCUS_META_DEFAULT_SCOPES, fixtureProbeObservations, focusProviderFailureCode, installFocusSchema, installFocusSystem, normalizeHashtag } from "./focus.js";

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
  assert.equal(FOCUS_META_DEFAULT_SCOPES, "instagram_basic,pages_show_list");
  assert.equal(focusProviderFailureCode("meta_oauth_exchange_failed"), "meta_oauth_exchange_failed_provider_rejected");
  assert.match(focusProviderFailureCode("meta failure: 190"), /^[a-z0-9_]+$/);
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

test("Meta OAuth start issues cleanup and state insertion as separate PostgreSQL queries", async () => {
  const original = Object.fromEntries([
    "FOCUS_META_APP_ID", "FOCUS_META_APP_SECRET", "FOCUS_META_REDIRECT_URI", "FOCUS_TOKEN_ENCRYPTION_KEY"
  ].map((key) => [key, process.env[key]]));
  Object.assign(process.env, {
    FOCUS_META_APP_ID: "test-meta-app-id",
    FOCUS_META_APP_SECRET: "test-meta-app-secret",
    FOCUS_META_REDIRECT_URI: "https://example.test/api/focus/connections/meta/callback",
    FOCUS_TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 7).toString("base64")
  });

  try {
    const routes = new Map();
    const register = (method) => (path, ...handlers) => routes.set(`${method} ${path}`, handlers);
    const app = { get: register("GET"), post: register("POST"), put: register("PUT"), delete: register("DELETE") };
    const queries = [];
    const pool = { query: async (statement, values) => { queries.push({ statement, values }); return { rows: [] }; } };
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
    assert.match(res.payload.authorization_url, /^https:\/\/www\.facebook\.com\/v26\.0\/dialog\/oauth\?/);
  } finally {
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});
