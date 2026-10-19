import { createHmac } from "node:crypto";
import { FacebookGraph, encryptionKey } from "../facebook-leads/provider.js";
import { VERSION, fault } from "./domain.js";
export class AdsGraph extends FacebookGraph {
  constructor(env = process.env, fetcher = fetch) {
    super(
      {
        ...env,
        FACEBOOK_LEADS_APP_ID:
          env.FACEBOOK_ADS_APP_ID || env.FACEBOOK_LEADS_APP_ID,
        FACEBOOK_LEADS_APP_SECRET:
          env.FACEBOOK_ADS_APP_SECRET || env.FACEBOOK_LEADS_APP_SECRET,
        FACEBOOK_LEADS_REDIRECT_URI: env.FACEBOOK_ADS_REDIRECT_URI,
      },
      fetcher,
    );
    this.adsEnv = env;
    this.usage = null;
  }
  version() {
    if (
      this.adsEnv.FACEBOOK_ADS_GRAPH_VERSION &&
      this.adsEnv.FACEBOOK_ADS_GRAPH_VERSION !== VERSION
    )
      throw fault("ads_catalog_version_mismatch", 503);
    return VERSION;
  }
  configured() {
    try {
      encryptionKey(this.env);
      const u = new URL(this.env.FACEBOOK_LEADS_REDIRECT_URI);
      return !!(
        this.env.FACEBOOK_LEADS_APP_ID &&
        this.env.FACEBOOK_LEADS_APP_SECRET &&
        u.protocol === "https:" &&
        !u.search &&
        !u.hash &&
        u.pathname === "/api/facebook-ads/oauth/callback" &&
        this.version()
      );
    } catch {
      return false;
    }
  }
  loginURL(state) {
    if (!this.configured())
      throw fault(
        "facebook_ads_setup_required",
        503,
        "Configure the Meta app, Ads callback and encrypted-secret key before connecting.",
      );
    const url = new URL(
      `https://www.facebook.com/${this.version()}/dialog/oauth`,
    );
    url.search = new URLSearchParams({
      client_id: this.env.FACEBOOK_LEADS_APP_ID,
      redirect_uri: this.env.FACEBOOK_LEADS_REDIRECT_URI,
      response_type: "code",
      state,
      ...(this.adsEnv.FACEBOOK_ADS_LOGIN_CONFIG_ID
        ? { config_id: this.adsEnv.FACEBOOK_ADS_LOGIN_CONFIG_ID }
        : { scope: "ads_read,ads_management", auth_type: "rerequest" }),
    }).toString();
    return String(url);
  }
  async request(path, token, params = {}, method = "GET", signal) {
    if (!/^[a-zA-Z0-9_\/-]+$/.test(path) || path.includes(".."))
      throw fault("invalid_provider_path");
    for (let attempt = 0; attempt < 3; attempt++) {
      const url = new URL(
          `https://graph.facebook.com/${this.version()}/${path}`,
        ),
        search = new URLSearchParams(params);
      if (token)
        search.set(
          "appsecret_proof",
          createHmac("sha256", this.env.FACEBOOK_LEADS_APP_SECRET)
            .update(token)
            .digest("hex"),
        );
      const headers = {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      };
      let body;
      if (method === "GET") url.search = search;
      else {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
        body = String(search);
      }
      let response, data;
      try {
        response = await this.fetcher(url, {
          method,
          headers,
          body,
          redirect: "error",
          signal: signal
            ? AbortSignal.any([signal, AbortSignal.timeout(20000)])
            : AbortSignal.timeout(20000),
        });
        data = await response.json();
      } catch {
        if (signal?.aborted) throw fault("report_canceled", 499);
        throw fault(
          "facebook_network_uncertain",
          502,
          "Facebook did not return a definitive response. Refresh the receipt before retrying.",
        );
      }
      let usage;
      try {
        usage = JSON.parse(response.headers.get("x-app-usage") || "null");
      } catch {}
      this.usage = usage
        ? {
            call_count: usage.call_count,
            total_cputime: usage.total_cputime,
            total_time: usage.total_time,
          }
        : null;
      if (response.ok && !data.error) return data;
      const code = Number(data.error?.code),
        retry =
          response.status === 429 ||
          response.status >= 500 ||
          [1, 2, 4, 17, 32, 613, 80004].includes(code) ||
          data.error?.is_transient === true;
      if (method === "GET" && retry && attempt < 2) {
        const seconds = Math.min(
          30,
          Math.max(
            Number(response.headers.get("retry-after")) || 0,
            2 ** attempt + Math.random(),
          ),
        );
        await new Promise((r, j) => {
          const timer = setTimeout(r, seconds * 1000);
          signal?.addEventListener(
            "abort",
            () => {
              clearTimeout(timer);
              j(fault("report_canceled", 499));
            },
            { once: true },
          );
        });
        continue;
      }
      const reason =
        code === 190
          ? "facebook_reauthorize_required"
          : [10, 200, 294].includes(code)
            ? "facebook_ads_permission_required"
            : retry
              ? "facebook_rate_limit"
              : "facebook_request_rejected";
      throw Object.assign(
        fault(
          reason,
          retry ? 429 : code === 190 ? 409 : 422,
          "Facebook rejected this operation. Check permissions, account restrictions, selected fields or budget constraints.",
        ),
        { provider_code: code, retryable: retry, definitive: !retry },
      );
    }
  }
}
