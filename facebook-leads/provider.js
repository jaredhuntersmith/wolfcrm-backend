import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  createHmac,
  timingSafeEqual,
  createHash,
} from "node:crypto";
import { FacebookLeadError, fail } from "./domain.js";
export const PERMISSIONS = [
  "leads_retrieval",
  "pages_show_list",
  "pages_read_engagement",
  "pages_manage_ads",
  "pages_manage_metadata",
  "ads_management",
];
export const hash = (value) => createHash("sha256").update(value).digest("hex");
export function secureEqual(a, b) {
  const x = Buffer.from(String(a || "")),
    y = Buffer.from(String(b || ""));
  return x.length === y.length && x.length > 0 && timingSafeEqual(x, y);
}
export function encryptionKey(env) {
  const key = Buffer.from(env.FACEBOOK_LEADS_ENCRYPTION_KEY || "", "base64");
  if (key.length !== 32) fail("facebook_encryption_key_required", 503);
  return key;
}
export function encrypt(value, scope, env) {
  const iv = randomBytes(12),
    cipher = createCipheriv("aes-256-gcm", encryptionKey(env), iv);
  cipher.setAAD(Buffer.from(scope));
  return [iv, cipher.update(value, "utf8"), cipher.final(), cipher.getAuthTag()]
    .map((b) => b.toString("base64"))
    .join(".");
}
export function decrypt(value, scope, env) {
  try {
    const [iv, data, final, tag] = value
      .split(".")
      .map((s) => Buffer.from(s, "base64"));
    const cipher = createDecipheriv("aes-256-gcm", encryptionKey(env), iv);
    cipher.setAAD(Buffer.from(scope));
    cipher.setAuthTag(tag);
    return Buffer.concat([
      cipher.update(data),
      cipher.update(final),
      cipher.final(),
    ]).toString();
  } catch {
    fail("facebook_token_unavailable_reconnect", 409);
  }
}
export function validSignature(raw, signature, secret) {
  return (
    Buffer.isBuffer(raw) &&
    !!secret &&
    secureEqual(
      signature,
      `sha256=${createHmac("sha256", secret).update(raw).digest("hex")}`,
    )
  );
}
export function signedRequest(input, secret) {
  if (!secret || typeof input !== "string") fail("invalid_signed_request", 401);
  const [sig, payload, extra] = input.split(".");
  if (!sig || !payload || extra) fail("invalid_signed_request", 401);
  const expected = createHmac("sha256", secret)
    .update(payload)
    .digest("base64url");
  if (!secureEqual(sig.replace(/=+$/, ""), expected))
    fail("invalid_signed_request", 401);
  let data;
  try {
    data = JSON.parse(Buffer.from(payload, "base64url").toString());
  } catch {
    fail("invalid_signed_request", 401);
  }
  if (data.algorithm !== "HMAC-SHA256" || !data.user_id)
    fail("invalid_signed_request", 401);
  return data;
}
export class FacebookGraph {
  constructor(env = process.env, fetcher = fetch) {
    this.env = env;
    this.fetcher = fetcher;
  }
  configured() {
    try {
      encryptionKey(this.env);
      return !!(
        this.env.FACEBOOK_LEADS_APP_ID &&
        this.env.FACEBOOK_LEADS_APP_ID !== this.env.FOCUS_META_APP_ID &&
        this.env.FACEBOOK_LEADS_APP_SECRET &&
        this.env.FACEBOOK_LEADS_LOGIN_CONFIG_ID &&
        this.env.FACEBOOK_LEADS_REDIRECT_URI &&
        this.env.FACEBOOK_LEADS_VERIFY_TOKEN &&
        this.env.FACEBOOK_LEADS_VERIFY_TOKEN !==
          this.env.FACEBOOK_LEADS_APP_SECRET &&
        new URL(this.env.FACEBOOK_LEADS_REDIRECT_URI).protocol === "https:"
      );
    } catch {
      return false;
    }
  }
  version() {
    const v = this.env.FACEBOOK_LEADS_GRAPH_VERSION || "v25.0";
    if (!/^v\d+\.0$/.test(v)) fail("facebook_graph_version_invalid", 503);
    return v;
  }
  loginURL(state) {
    if (
      this.env.FACEBOOK_LEADS_APP_ID &&
      this.env.FACEBOOK_LEADS_APP_ID === this.env.FOCUS_META_APP_ID
    )
      fail("facebook_dedicated_meta_app_required", 503);
    if (!this.configured()) fail("facebook_setup_required", 503);
    const url = new URL(
      `https://www.facebook.com/${this.version()}/dialog/oauth`,
    );
    url.search = new URLSearchParams({
      client_id: this.env.FACEBOOK_LEADS_APP_ID,
      redirect_uri: this.env.FACEBOOK_LEADS_REDIRECT_URI,
      config_id: this.env.FACEBOOK_LEADS_LOGIN_CONFIG_ID,
      response_type: "code",
      state,
    }).toString();
    return String(url);
  }
  async request(path, token, params = {}, method = "GET") {
    const url = new URL(`https://graph.facebook.com/${this.version()}/${path}`);
    const search = new URLSearchParams(params);
    if (token)
      search.set(
        "appsecret_proof",
        createHmac("sha256", this.env.FACEBOOK_LEADS_APP_SECRET)
          .update(token)
          .digest("hex"),
      );
    const headers = { ...(token ? { Authorization: `Bearer ${token}` } : {}) };
    let body;
    if (method === "GET") url.search = search.toString();
    else {
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      body = search.toString();
    }
    let response, data;
    try {
      response = await this.fetcher(url, {
        method,
        headers,
        body,
        signal: AbortSignal.timeout(20000),
        redirect: "error",
      });
      data = await response.json();
    } catch {
      throw new FacebookLeadError("facebook_network_error", 502, true);
    }
    if (!response.ok || data.error) {
      const code = Number(data.error?.code),
        retry =
          response.status === 429 ||
          response.status >= 500 ||
          [1, 2, 4, 17, 32, 613, 80004].includes(code) ||
          data.error?.is_transient === true;
      const reason =
        code === 190
          ? "facebook_token_expired_reconnect"
          : [10, 200, 294].includes(code)
            ? "facebook_permission_required"
            : retry
              ? "facebook_rate_or_service_limit"
              : "facebook_request_rejected";
      // Do not expose/store Meta messages or response bodies: they can echo answers/tokens.
      throw new FacebookLeadError(
        reason,
        502,
        retry,
        Math.min(86400, Number(response.headers.get("retry-after")) || 0),
      );
    }
    return data;
  }
  async exchange(code) {
    const short = await this.request("oauth/access_token", null, {
      client_id: this.env.FACEBOOK_LEADS_APP_ID,
      client_secret: this.env.FACEBOOK_LEADS_APP_SECRET,
      redirect_uri: this.env.FACEBOOK_LEADS_REDIRECT_URI,
      code,
    });
    if (!short.access_token) fail("facebook_token_exchange_failed", 502);
    const long = await this.request("oauth/access_token", null, {
      grant_type: "fb_exchange_token",
      client_id: this.env.FACEBOOK_LEADS_APP_ID,
      client_secret: this.env.FACEBOOK_LEADS_APP_SECRET,
      fb_exchange_token: short.access_token,
    });
    if (!long.access_token) fail("facebook_token_exchange_failed", 502);
    return long.access_token;
  }
  async page(path, token, params = {}, cursor) {
    const data = await this.request(path, token, {
      limit: "100",
      ...params,
      ...(cursor ? { after: cursor } : {}),
    });
    if (data.paging?.next && !data.paging?.cursors?.after)
      fail("facebook_pagination_cursor_missing", 502);
    return {
      data: Array.isArray(data.data) ? data.data : [],
      cursor: data.paging?.next ? data.paging?.cursors?.after || null : null,
      total: data.summary?.total_count ?? null,
    };
  }
  async all(path, token, params = {}) {
    const rows = [];
    let cursor;
    const seen = new Set();
    do {
      const result = await this.page(path, token, params, cursor);
      rows.push(...result.data);
      cursor = result.cursor;
      if (cursor && seen.has(cursor)) fail("facebook_pagination_stalled", 502);
      if (cursor) seen.add(cursor);
      if (seen.size > 500) fail("facebook_discovery_too_large", 422);
    } while (cursor);
    return rows;
  }
  async lead(id, token) {
    const lead = await this.request(id, token, {
      fields: "id,form_id,created_time,field_data",
    });
    // Optional data must not cause a lost contact. Record explicit availability issues.
    const issues = [];
    for (const [fields, code] of [
      ["custom_disclaimer_responses", "consent_responses_unavailable"],
      [
        "ad_id,ad_name,adset_id,adset_name,campaign_id,campaign_name,is_organic,platform",
        "optional_attribution_unavailable",
      ],
      [
        "partner_name,retailer_item_id,home_listing,vehicle,post,post_submission_check_result",
        "optional_context_unavailable",
      ],
    ]) {
      try {
        Object.assign(lead, await this.request(id, token, { fields }));
      } catch (error) {
        if (error.code === "facebook_token_expired_reconnect") throw error;
        issues.push({ code });
      }
    }
    return { lead, issues };
  }
  async leads(form, token, range, cursor) {
    return this.page(
      `${form}/leads`,
      token,
      {
        fields: "id,created_time",
        summary: "true",
        filtering: JSON.stringify([
          {
            field: "time_created",
            operator: "GREATER_THAN_OR_EQUAL",
            value: Math.floor(new Date(range.from) / 1000),
          },
          {
            field: "time_created",
            operator: "LESS_THAN",
            value: Math.floor(new Date(range.to) / 1000),
          },
        ]),
      },
      cursor,
    );
  }
}
