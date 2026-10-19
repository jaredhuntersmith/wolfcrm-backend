import {
  FacebookGraph,
  encryptionKey,
  PERMISSIONS,
} from "../facebook-leads/provider.js";
export const COMBINED_PERMISSIONS = Object.freeze([
  ...new Set([...PERMISSIONS, "ads_read"]),
]);
export const CALLBACK_PATHS = [
  "/api/integrations/facebook/oauth/callback",
  "/api/integrations/facebook-leads/oauth/callback",
  "/api/facebook-ads/oauth/callback",
];
export function connectionConfiguration(env) {
  const missing = [];
  const appId = env.FACEBOOK_LEADS_APP_ID;
  const redirect =
    env.FACEBOOK_CONNECTION_REDIRECT_URI || env.FACEBOOK_LEADS_REDIRECT_URI;
  const config =
    env.FACEBOOK_CONNECTION_LOGIN_CONFIG_ID ||
    env.FACEBOOK_LEADS_LOGIN_CONFIG_ID;
  for (const key of ["FACEBOOK_LEADS_APP_ID", "FACEBOOK_LEADS_APP_SECRET"])
    if (!env[key]) missing.push(key);
  if (!config)
    missing.push(
      "FACEBOOK_CONNECTION_LOGIN_CONFIG_ID (or FACEBOOK_LEADS_LOGIN_CONFIG_ID)",
    );
  let publicRedirect = null;
  try {
    const u = new URL(redirect);
    if (
      u.protocol !== "https:" ||
      u.username ||
      u.password ||
      u.search ||
      u.hash ||
      !CALLBACK_PATHS.includes(u.pathname)
    )
      throw Error();
    publicRedirect = u.href;
  } catch {
    missing.push(
      "FACEBOOK_CONNECTION_REDIRECT_URI: HTTPS URL with a supported Facebook callback path",
    );
  }
  try {
    encryptionKey(env);
  } catch {
    missing.push("FACEBOOK_LEADS_ENCRYPTION_KEY: base64 32-byte key");
  }
  if (appId && appId === env.FOCUS_META_APP_ID)
    missing.push("Use a Facebook app separate from the Focus/Instagram app");
  if (env.FACEBOOK_ADS_APP_ID && env.FACEBOOK_ADS_APP_ID !== appId)
    missing.push(
      "FACEBOOK_ADS_APP_ID conflicts with the Leads app; remove the override or use the same app ID",
    );
  if (
    env.FACEBOOK_ADS_APP_SECRET &&
    env.FACEBOOK_ADS_APP_SECRET !== env.FACEBOOK_LEADS_APP_SECRET
  )
    missing.push(
      "FACEBOOK_ADS_APP_SECRET conflicts with the Leads app; remove the override or use its matching secret",
    );
  return {
    configured: !missing.length,
    app_id: appId || null,
    redirect_uri: publicRedirect,
    login_configured: !!config,
    missing,
    required_permissions: COMBINED_PERMISSIONS,
    webhook_configured:
      !!env.FACEBOOK_LEADS_VERIFY_TOKEN &&
      env.FACEBOOK_LEADS_VERIFY_TOKEN !== env.FACEBOOK_LEADS_APP_SECRET,
    app_source: "FACEBOOK_LEADS_APP_ID",
    focus_separate: !appId || appId !== env.FOCUS_META_APP_ID,
  };
}
export class ConnectionGraph extends FacebookGraph {
  constructor(env = process.env, fetcher = fetch) {
    super(
      {
        ...env,
        FACEBOOK_LEADS_REDIRECT_URI:
          env.FACEBOOK_CONNECTION_REDIRECT_URI ||
          env.FACEBOOK_LEADS_REDIRECT_URI,
      },
      fetcher,
    );
    this.connectionEnv = env;
  }
  configured() {
    return connectionConfiguration(this.connectionEnv).configured;
  }
  loginURL(state) {
    if (!this.configured())
      throw Object.assign(
        new Error(
          "Complete the listed Facebook app configuration before signing in.",
        ),
        { code: "facebook_connection_setup_required", status: 503 },
      );
    const url = new URL(
      `https://www.facebook.com/${this.version()}/dialog/oauth`,
    );
    url.search = new URLSearchParams({
      client_id: this.env.FACEBOOK_LEADS_APP_ID,
      redirect_uri: this.env.FACEBOOK_LEADS_REDIRECT_URI,
      config_id:
        this.connectionEnv.FACEBOOK_CONNECTION_LOGIN_CONFIG_ID ||
        this.env.FACEBOOK_LEADS_LOGIN_CONFIG_ID,
      scope: COMBINED_PERMISSIONS.join(","),
      response_type: "code",
      auth_type: "rerequest",
      state,
    }).toString();
    return String(url);
  }
}
