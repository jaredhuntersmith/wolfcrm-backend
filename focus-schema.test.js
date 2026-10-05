import assert from "node:assert/strict";
import test from "node:test";
import { FOCUS_META_DEFAULT_GRAPH_VERSION, FOCUS_META_DEFAULT_SCOPES, fixtureProbeObservations, focusProviderFailureCode, installFocusSchema, normalizeHashtag } from "./focus.js";

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
