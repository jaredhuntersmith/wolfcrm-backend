import { randomBytes } from "node:crypto";
import { loadPrincipal } from "../mcp/access.js";
import { encrypt, decrypt, hash } from "../facebook-leads/provider.js";
import { transaction } from "../facebook-leads/store.js";
import { connectionConfiguration, COMBINED_PERMISSIONS } from "./provider.js";
import {
  expiredAuthorization,
  invalidateSharedAuthorization,
} from "./state.js";
const one = async (db, sql, values) => (await db.query(sql, values)).rows[0];
export const connectionError = (
  code,
  status = 409,
  message = code.replaceAll("_", " "),
) => Object.assign(new Error(message), { code, status });
const safeCode = (e) =>
  /^facebook_[a-z_]{3,80}$/.test(e?.code || "")
    ? e.code
    : "facebook_connection_unavailable";
const usable = (c) =>
  !!c?.token &&
  !["disconnected", "revoked"].includes(c.status) &&
  !expiredAuthorization(c.error_code) &&
  (!c.expires_at || new Date(c.expires_at) > new Date());
export function createFacebookConnection({ pool, env, graph, leads, ads }) {
  async function authorize(actor, write = false, db = pool) {
    const principal = await loadPrincipal(db, actor.userId, actor.companyId, {
      enforceOAuthRolePolicy: false,
    });
    if (
      !principal.permissions.capabilities["integrations.manage"] ||
      (write &&
        !(principal.isCompanyOwner || principal.permissions.preset === "admin"))
    )
      throw connectionError("facebook_connection_access_denied", 403);
    return principal;
  }
  async function change(company, operation) {
    return transaction(pool, async (db) => {
      // Same exclusive gate used by Ads changes, then the existing Lead config/connection order.
      await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
        "facebook-ads-connection:" + company,
      ]);
      await leads.store.settings(db, company, true);
      await db.query(
        "SELECT company_id FROM facebook_lead_connections WHERE company_id=$1 FOR UPDATE",
        [company],
      );
      await db.query(
        "SELECT company_id FROM facebook_connections WHERE company_id=$1 FOR UPDATE",
        [company],
      );
      return operation(db);
    });
  }
  async function isUnified(company) {
    return !!(await one(
      pool,
      "SELECT company_id FROM facebook_connections WHERE company_id=$1",
      [company],
    ));
  }
  async function status(actor) {
    await authorize(actor);
    const c = await one(
      pool,
      "SELECT * FROM facebook_connections WHERE company_id=$1",
      [actor.companyId],
    );
    const l = await one(
      pool,
      "SELECT * FROM facebook_lead_connections WHERE company_id=$1",
      [actor.companyId],
    );
    const a = await one(
      pool,
      "SELECT * FROM facebook_ads_connections WHERE company_id=$1",
      [actor.companyId],
    );
    const pages = (
      await pool.query(
        "SELECT page_id,name,selected,subscription,retrieval,error_code FROM facebook_lead_pages WHERE company_id=$1 ORDER BY name,page_id",
        [actor.companyId],
      )
    ).rows;
    const accounts = (
      await pool.query(
        "SELECT account_id,name,currency,timezone_name,selected,available,user_tasks FROM facebook_ads_accounts WHERE company_id=$1 ORDER BY name,account_id",
        [actor.companyId],
      )
    ).rows;
    const forms = (
      await pool.query(
        "SELECT form_id,page_id,name,enabled,routed,revision FROM facebook_lead_forms WHERE company_id=$1 ORDER BY name,form_id",
        [actor.companyId],
      )
    ).rows;
    const setup = connectionConfiguration(env),
      lp = l?.permissions || [],
      ap = a?.permissions || [];
    const readiness = [];
    const add = (key, title, required, granted, ready, reasons = []) => {
      const missing = required.filter((p) => !granted.includes(p));
      readiness.push({
        key,
        title,
        ready: ready && !missing.length,
        missing_permissions: missing,
        reasons: [
          ...reasons,
          ...missing.map((p) => "Grant " + p + " when reconnecting Facebook."),
        ],
      });
    };
    const leadReady = usable(l),
      adsReady =
        usable(a) &&
        env.FACEBOOK_ADS_ENABLED === "true" &&
        a.operations_enabled;
    add(
      "lead_retrieval",
      "Lead retrieval",
      [
        "leads_retrieval",
        "pages_show_list",
        "pages_read_engagement",
        "pages_manage_ads",
      ],
      lp,
      leadReady && pages.some((p) => p.selected && p.retrieval === "verified"),
      [
        ...(!leadReady
          ? ["Reconnect Facebook to restore lead authorization."]
          : []),
        ...(!pages.some((p) => p.selected) ? ["Select a Page in Leads."] : []),
        ...(pages.some((p) => p.selected && p.retrieval !== "verified")
          ? [
              "Check Page tasks and Leads Access Manager; at least one selected Page has not verified retrieval.",
            ]
          : []),
      ],
    );
    add(
      "lead_subscriptions",
      "Lead subscriptions",
      ["pages_manage_metadata"],
      lp,
      leadReady &&
        setup.webhook_configured &&
        pages.some((p) => p.selected && p.subscription === "subscribed"),
      [
        ...(!setup.webhook_configured
          ? [
              "Set a distinct FACEBOOK_LEADS_VERIFY_TOKEN and verify the Page leadgen webhook in Meta.",
            ]
          : []),
        ...(!pages.some((p) => p.selected && p.subscription === "subscribed")
          ? ["Select a Page and confirm its leadgen subscription in Leads."]
          : []),
      ],
    );
    add(
      "lead_processing",
      "Lead import processing",
      [],
      lp,
      leadReady &&
        !l.importing_paused &&
        env.FACEBOOK_LEADS_WORKER_ENABLED === "true" &&
        forms.some((f) => f.enabled) &&
        readiness[0].ready,
      [
        ...(l?.importing_paused ? ["Lead importing is paused."] : []),
        ...(env.FACEBOOK_LEADS_WORKER_ENABLED !== "true"
          ? ["Enable FACEBOOK_LEADS_WORKER_ENABLED on the backend."]
          : []),
        ...(!forms.some((f) => f.enabled)
          ? ["Enable the intended forms in Leads."]
          : []),
        ...(!readiness[0].ready
          ? ["Resolve lead retrieval readiness first."]
          : []),
      ],
    );
    const readGrant = ap.includes("ads_read") || ap.includes("ads_management");
    const adReasons = [
      ...(!usable(a)
        ? ["Reconnect Facebook to restore Ads authorization."]
        : []),
      ...(env.FACEBOOK_ADS_ENABLED !== "true"
        ? ["Enable FACEBOOK_ADS_ENABLED on the backend."]
        : []),
      ...(a?.operations_enabled === false
        ? ["Ads operations are disabled for this company."]
        : []),
      ...(!accounts.some((x) => x.selected && x.available)
        ? ["Select an authorized ad account."]
        : []),
    ];
    add(
      "ads_reporting",
      "Ads reporting",
      readGrant ? [] : ["ads_read"],
      ap,
      adsReady && accounts.some((x) => x.selected && x.available),
      adReasons,
    );
    add(
      "ads_editing",
      "Ads editing",
      ["ads_management"],
      ap,
      adsReady &&
        accounts.some(
          (x) =>
            x.selected &&
            x.available &&
            (x.user_tasks || []).some((t) =>
              ["MANAGE", "ADVERTISE"].includes(t),
            ),
        ),
      [
        ...adReasons,
        ...(!accounts.some(
          (x) =>
            x.selected &&
            x.available &&
            (x.user_tasks || []).some((t) =>
              ["MANAGE", "ADVERTISE"].includes(t),
            ),
        )
          ? ["The selected ad account must grant MANAGE or ADVERTISE access."]
          : []),
      ],
    );
    const expires = c?.expires_at && new Date(c.expires_at) <= new Date();
    return {
      setup,
      connection: {
        status: expires
          ? "expired"
          : c?.status || (l?.token || a?.token ? "legacy" : "disconnected"),
        unified: !!c,
        permissions: c?.permissions || [],
        expires_at: c?.expires_at || null,
        error_code: c?.error_code || null,
        checked_at: c?.checked_at || null,
      },
      lead_importing_paused: l?.importing_paused || false,
      ads_operations_enabled: a?.operations_enabled ?? true,
      readiness,
      pages,
      forms,
      accounts,
      transition:
        !c && (l?.token || a?.token)
          ? "Existing authorizations and saved configuration are preserved. Connect Facebook once to grant combined access; no old token is copied between apps."
          : null,
      required_permissions: COMBINED_PERMISSIONS,
    };
  }
  async function start(req, { client = "ios", destination = "facebook" } = {}) {
    await authorize({ userId: req.userId, companyId: req.companyId }, true);
    if (!req.sessionToken)
      throw connectionError("facebook_human_session_required", 403);
    const state = randomBytes(32).toString("base64url"),
      url = graph.loginURL(state),
      setup = connectionConfiguration(env);
    await pool.query(
      "DELETE FROM facebook_connection_oauth_states WHERE expires_at<now()",
    );
    await pool.query(
      `INSERT INTO facebook_connection_oauth_states(state_hash,company_id,user_id,session_hash,client,destination,app_id,redirect_uri,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,now()+interval '10 minutes')`,
      [
        hash(state),
        req.companyId,
        req.userId,
        hash(req.sessionToken),
        client === "web" ? "web" : "ios",
        destination,
        setup.app_id,
        setup.redirect_uri,
      ],
    );
    return { url };
  }
  async function accept(actor, { token, metaUserId, permissions, expiresAt }) {
    await change(actor.companyId, async (db) => {
      await authorize(actor, true, db);
      await db.query(
        `INSERT INTO facebook_connections(company_id,user_id,app_id,meta_user_id,token,permissions,status,expires_at,checked_at) VALUES($1,$2,$3,$4,$5,$6,'connected',$7,now()) ON CONFLICT(company_id) DO UPDATE SET user_id=EXCLUDED.user_id,app_id=EXCLUDED.app_id,meta_user_id=EXCLUDED.meta_user_id,token=EXCLUDED.token,permissions=EXCLUDED.permissions,status='connected',expires_at=EXCLUDED.expires_at,error_code=NULL,revision=facebook_connections.revision+1,checked_at=now(),updated_at=now()`,
        [
          actor.companyId,
          actor.userId,
          env.FACEBOOK_LEADS_APP_ID,
          metaUserId,
          encrypt(token, "facebook:" + actor.companyId, env),
          JSON.stringify(permissions),
          expiresAt,
        ],
      );
      await db.query(
        `INSERT INTO facebook_lead_connections(company_id,user_id,meta_user_id,token,permissions,status,unified,expires_at) VALUES($1,$2,$3,$4,$5,'authorized',true,$6) ON CONFLICT(company_id) DO UPDATE SET user_id=EXCLUDED.user_id,meta_user_id=EXCLUDED.meta_user_id,token=EXCLUDED.token,permissions=EXCLUDED.permissions,status='authorized',unified=true,expires_at=EXCLUDED.expires_at,error_code=NULL,updated_at=now()`,
        [
          actor.companyId,
          actor.userId,
          metaUserId,
          encrypt(token, actor.companyId, env),
          JSON.stringify(permissions),
          expiresAt,
        ],
      );
      await db.query(
        `INSERT INTO facebook_ads_connections(company_id,user_id,meta_user_id,token,permissions,status,unified,expires_at) VALUES($1,$2,$3,$4,$5,'connected',true,$6) ON CONFLICT(company_id) DO UPDATE SET user_id=EXCLUDED.user_id,meta_user_id=EXCLUDED.meta_user_id,token=EXCLUDED.token,permissions=EXCLUDED.permissions,status='connected',unified=true,expires_at=EXCLUDED.expires_at,error_code=NULL,revision=facebook_ads_connections.revision+1,updated_at=now()`,
        [
          actor.companyId,
          actor.userId,
          metaUserId,
          encrypt(token, "ads:" + actor.companyId, env),
          JSON.stringify(permissions),
          expiresAt,
        ],
      );
      // Retain explicit choices/configuration, but never retain old Page credentials across grants.
      await db.query(
        "UPDATE facebook_lead_pages SET token=NULL,retrieval='unchecked',subscription='unchecked' WHERE company_id=$1",
        [actor.companyId],
      );
      await db.query(
        "UPDATE facebook_ads_accounts SET available=false WHERE company_id=$1",
        [actor.companyId],
      );
      await db.query(
        "UPDATE facebook_ads_reports SET status='canceled' WHERE company_id=$1 AND status IN ('starting','running')",
        [actor.companyId],
      );
    });
  }
  async function refresh(actor) {
    await authorize(actor, true);
    const c = await one(
      pool,
      "SELECT * FROM facebook_connections WHERE company_id=$1",
      [actor.companyId],
    );
    if (!c?.token) throw connectionError("facebook_reconnect_required");
    if (
      c.app_id !== env.FACEBOOK_LEADS_APP_ID ||
      !connectionConfiguration(env).configured
    )
      throw connectionError(
        "facebook_connection_setup_required",
        503,
        "The configured app changed. Review setup and reconnect; existing tokens are not moved between apps.",
      );
    if (c.expires_at && new Date(c.expires_at) <= new Date()) {
      await invalidateSharedAuthorization(
        pool,
        actor.companyId,
        "facebook_reauthorize_required",
        "facebook",
        c.token,
      );
      throw connectionError("facebook_reauthorize_required");
    }
    let permissions;
    try {
      permissions = (
        await graph.all(
          "me/permissions",
          decrypt(c.token, "facebook:" + actor.companyId, env),
        )
      )
        .filter((p) => p.status === "granted")
        .map((p) => p.permission);
    } catch (e) {
      if (expiredAuthorization(e.code))
        await invalidateSharedAuthorization(
          pool,
          actor.companyId,
          e.code,
          "facebook",
          c.token,
        );
      throw e;
    }
    await change(actor.companyId, async (db) => {
      const current = await one(
        db,
        "SELECT revision FROM facebook_connections WHERE company_id=$1",
        [actor.companyId],
      );
      if (current?.revision !== c.revision)
        throw connectionError("facebook_authorization_changed_retry");
      await db.query(
        "UPDATE facebook_connections SET permissions=$2,status='connected',error_code=NULL,checked_at=now() WHERE company_id=$1",
        [actor.companyId, JSON.stringify(permissions)],
      );
      await db.query(
        "UPDATE facebook_lead_connections SET permissions=$2,status='authorized',error_code=NULL,checked_at=now() WHERE company_id=$1 AND unified",
        [actor.companyId, JSON.stringify(permissions)],
      );
      await db.query(
        "UPDATE facebook_ads_connections SET revision=revision+CASE WHEN permissions<>$2::jsonb THEN 1 ELSE 0 END,permissions=$2,status='connected',error_code=NULL,checked_at=now() WHERE company_id=$1 AND unified",
        [actor.companyId, JSON.stringify(permissions)],
      );
      if (!permissions.includes("pages_show_list"))
        await db.query(
          "UPDATE facebook_lead_pages SET token=NULL,retrieval='unavailable',error_code='facebook_permission_required' WHERE company_id=$1",
          [actor.companyId],
        );
      if (
        !permissions.includes("ads_read") &&
        !permissions.includes("ads_management")
      )
        await db.query(
          "UPDATE facebook_ads_accounts SET available=false WHERE company_id=$1",
          [actor.companyId],
        );
    });
    // Discovery fails independently: an Ads-only grant must remain usable if Pages are denied.
    if (permissions.includes("pages_show_list"))
      try {
        await leads.store.refresh(actor.companyId);
      } catch (e) {
        if (expiredAuthorization(e.code)) {
          await invalidateSharedAuthorization(
            pool,
            actor.companyId,
            e.code,
            "facebook",
            c.token,
          );
          throw e;
        }
      }
    if (
      env.FACEBOOK_ADS_ENABLED === "true" &&
      permissions.some((p) => ["ads_read", "ads_management"].includes(p))
    )
      try {
        await ads.refresh(actor);
      } catch (e) {
        if (expiredAuthorization(e.code)) {
          await invalidateSharedAuthorization(
            pool,
            actor.companyId,
            e.code,
            "facebook",
            c.token,
          );
          throw e;
        }
        await pool.query(
          "UPDATE facebook_ads_connections SET error_code=$2 WHERE company_id=$1 AND unified AND EXISTS(SELECT 1 FROM facebook_connections c WHERE c.company_id=$1 AND c.token=$3)",
          [actor.companyId, safeCode(e), c.token],
        );
      }
    return status(actor);
  }
  async function controls(actor, input) {
    await authorize(actor, true);
    if (
      !input ||
      Object.keys(input).some(
        (k) => !["lead_importing_paused", "ads_operations_enabled"].includes(k),
      ) ||
      Object.values(input).some((v) => typeof v !== "boolean")
    )
      throw connectionError("facebook_invalid_module_controls", 400);
    await change(actor.companyId, async (db) => {
      await authorize(actor, true, db);
      if (input.lead_importing_paused !== undefined) {
        const result = await db.query(
          "UPDATE facebook_lead_connections SET importing_paused=$2 WHERE company_id=$1",
          [actor.companyId, input.lead_importing_paused],
        );
        if (!result.rowCount)
          throw connectionError(
            "facebook_connect_first",
            409,
            "Connect Facebook before changing lead import controls.",
          );
      }
      if (input.ads_operations_enabled !== undefined) {
        const result = await db.query(
          "UPDATE facebook_ads_connections SET operations_enabled=$2,revision=revision+1 WHERE company_id=$1",
          [actor.companyId, input.ads_operations_enabled],
        );
        if (!result.rowCount)
          throw connectionError(
            "facebook_connect_first",
            409,
            "Connect Facebook before changing Ads controls.",
          );
      }
    });
    return status(actor);
  }
  async function clear(db, company, state = "disconnected") {
    await db.query(
      "UPDATE facebook_connections SET token=NULL,status=$2,permissions='[]',revision=revision+1,error_code=NULL,updated_at=now() WHERE company_id=$1",
      [company, state],
    );
    await db.query(
      "UPDATE facebook_lead_connections SET token=NULL,status=$2,permissions='[]',error_code=NULL,updated_at=now() WHERE company_id=$1",
      [company, state],
    );
    await db.query(
      "UPDATE facebook_ads_connections SET token=NULL,status=$2,permissions='[]',revision=revision+1,error_code=NULL,updated_at=now() WHERE company_id=$1",
      [company, state],
    );
    await db.query(
      "UPDATE facebook_lead_pages SET token=NULL,subscription='disconnected',retrieval='unchecked' WHERE company_id=$1",
      [company],
    );
    await db.query(
      "UPDATE facebook_ads_accounts SET available=false WHERE company_id=$1",
      [company],
    );
    await db.query(
      "UPDATE facebook_ads_reports SET status='canceled' WHERE company_id=$1 AND status IN ('starting','running')",
      [company],
    );
    for (const table of [
      "facebook_connection_oauth_states",
      "facebook_lead_oauth_states",
      "facebook_ads_oauth_states",
    ])
      await db.query(`DELETE FROM ${table} WHERE company_id=$1`, [company]);
  }
  async function disconnect(actor) {
    await authorize(actor, true);
    await change(actor.companyId, async (db) => {
      await authorize(actor, true, db);
      await clear(db, actor.companyId);
    });
    return status(actor);
  }
  async function revoke(metaId, appId, { deletion = false } = {}) {
    // Newly configured callback URLs must also honor unconverted legacy authorizations.
    // App-scoped user IDs are only compared within the app configured for that module.
    if (appId === env.FACEBOOK_LEADS_APP_ID) {
      const legacy = (
        await pool.query(
          "SELECT company_id FROM facebook_lead_connections WHERE meta_user_id=$1 AND NOT unified",
          [metaId],
        )
      ).rows;
      for (const row of legacy)
        await change(row.company_id, async (db) => {
          const current = await one(
            db,
            "SELECT meta_user_id,unified FROM facebook_lead_connections WHERE company_id=$1",
            [row.company_id],
          );
          if (current?.unified || current?.meta_user_id !== metaId) return;
          await db.query(
            "UPDATE facebook_lead_connections SET token=NULL,status='revoked',permissions='[]',error_code=NULL WHERE company_id=$1",
            [row.company_id],
          );
          await db.query(
            "UPDATE facebook_lead_pages SET token=NULL,subscription='disconnected',retrieval='unchecked' WHERE company_id=$1",
            [row.company_id],
          );
          if (deletion) {
            await db.query(
              "DELETE FROM facebook_lead_jobs WHERE company_id=$1",
              [row.company_id],
            );
            await db.query(
              "DELETE FROM facebook_lead_scans WHERE company_id=$1",
              [row.company_id],
            );
            await db.query(
              "DELETE FROM facebook_lead_connections WHERE company_id=$1",
              [row.company_id],
            );
            await db.query(
              "DELETE FROM facebook_lead_settings WHERE company_id=$1",
              [row.company_id],
            );
          }
        });
    }
    if (appId === (env.FACEBOOK_ADS_APP_ID || env.FACEBOOK_LEADS_APP_ID)) {
      const legacy = (
        await pool.query(
          "SELECT company_id FROM facebook_ads_connections WHERE meta_user_id=$1 AND NOT unified",
          [metaId],
        )
      ).rows;
      for (const row of legacy)
        await change(row.company_id, async (db) => {
          const current = await one(
            db,
            "SELECT meta_user_id,unified FROM facebook_ads_connections WHERE company_id=$1 FOR UPDATE",
            [row.company_id],
          );
          if (current?.unified || current?.meta_user_id !== metaId) return;
          await db.query(
            "UPDATE facebook_ads_connections SET token=NULL,status='revoked',permissions='[]',error_code=NULL,revision=revision+1 WHERE company_id=$1",
            [row.company_id],
          );
          await db.query(
            "UPDATE facebook_ads_accounts SET available=false WHERE company_id=$1",
            [row.company_id],
          );
          if (deletion)
            await db.query(
              "UPDATE facebook_ads_connections SET meta_user_id=NULL WHERE company_id=$1",
              [row.company_id],
            );
        });
    }
    const companies = (
      await pool.query(
        "SELECT company_id FROM facebook_connections WHERE app_id=$1 AND meta_user_id=$2 ORDER BY company_id",
        [appId, metaId],
      )
    ).rows;
    for (const row of companies)
      await change(row.company_id, async (db) => {
        const c = await one(
          db,
          "SELECT meta_user_id,app_id FROM facebook_connections WHERE company_id=$1",
          [row.company_id],
        );
        if (c?.meta_user_id !== metaId || c?.app_id !== appId) return;
        await clear(db, row.company_id, "revoked");
        if (deletion) {
          await db.query("DELETE FROM facebook_lead_jobs WHERE company_id=$1", [
            row.company_id,
          ]);
          await db.query(
            "DELETE FROM facebook_lead_scans WHERE company_id=$1",
            [row.company_id],
          );
          await db.query(
            "DELETE FROM facebook_lead_connections WHERE company_id=$1",
            [row.company_id],
          );
          await db.query(
            "DELETE FROM facebook_lead_settings WHERE company_id=$1",
            [row.company_id],
          );
          await db.query(
            "UPDATE facebook_ads_connections SET meta_user_id=NULL WHERE company_id=$1",
            [row.company_id],
          );
          await db.query(
            "DELETE FROM facebook_connections WHERE company_id=$1",
            [row.company_id],
          );
        }
      });
  }
  return {
    authorize,
    status,
    start,
    accept,
    refresh,
    controls,
    disconnect,
    revoke,
    isUnified,
    graph,
  };
}
