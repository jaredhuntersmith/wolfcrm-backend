import test from "node:test";
import assert from "node:assert/strict";
import {
  ConnectionGraph,
  connectionConfiguration,
  COMBINED_PERMISSIONS,
} from "../facebook-connection/provider.js";
const env = {
  FACEBOOK_LEADS_APP_ID: "999",
  FACEBOOK_LEADS_APP_SECRET: "fixture",
  FACEBOOK_LEADS_LOGIN_CONFIG_ID: "123",
  FACEBOOK_LEADS_REDIRECT_URI:
    "https://example.invalid/api/integrations/facebook-leads/oauth/callback",
  FACEBOOK_LEADS_ENCRYPTION_KEY: Buffer.alloc(32, 3).toString("base64"),
};
test("combined login uses existing Leads app, approved config and combined permissions", () => {
  const u = new URL(new ConnectionGraph(env).loginURL("bound-state"));
  assert.equal(u.searchParams.get("client_id"), "999");
  assert.equal(u.searchParams.get("config_id"), "123");
  assert.equal(u.searchParams.get("state"), "bound-state");
  assert.deepEqual(
    new Set(u.searchParams.get("scope").split(",")),
    new Set(COMBINED_PERMISSIONS),
  );
  assert(COMBINED_PERMISSIONS.includes("ads_read"));
  assert(COMBINED_PERMISSIONS.includes("leads_retrieval"));
});
test("conflicting app IDs/secrets, Focus reuse and unsafe redirects fail closed", () => {
  for (const patch of [
    { FACEBOOK_ADS_APP_ID: "different" },
    { FACEBOOK_ADS_APP_SECRET: "different" },
    { FOCUS_META_APP_ID: "999" },
    {
      FACEBOOK_CONNECTION_REDIRECT_URI:
        "https://example.invalid/redirect?to=evil",
    },
    {
      FACEBOOK_CONNECTION_REDIRECT_URI:
        "http://example.invalid/api/integrations/facebook/oauth/callback",
    },
  ])
    assert.equal(
      connectionConfiguration({ ...env, ...patch }).configured,
      false,
    );
  assert.equal(
    connectionConfiguration({
      ...env,
      FACEBOOK_ADS_APP_ID: "999",
      FACEBOOK_ADS_APP_SECRET: "fixture",
    }).configured,
    true,
  );
  assert(!JSON.stringify(connectionConfiguration(env)).includes('"fixture"'));
});
