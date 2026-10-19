import {
  expiredAuthorization,
  invalidateSharedAuthorization,
  syncSharedPermissions,
} from "../facebook-connection/state.js";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { encrypt, decrypt } from "../facebook-leads/provider.js";
import { loadPrincipal } from "../mcp/access.js";
import {
  fault,
  id,
  level,
  mutation,
  versionOf,
  budgetTarget,
  digest,
  dateWindow,
  VERSION,
  currencyDigits,
} from "./domain.js";
import { catalog, validateReport, fieldsFor, valuesFor } from "./catalog.js";
const one = async (db, sql, args) => (await db.query(sql, args)).rows[0];
const safeError = (e) =>
  /^facebook_[a-z_]+$|^[a-z_]{3,80}$/.test(e.code || "")
    ? e.code
    : "facebook_ads_unavailable";
const accountFields =
  "account_id,name,currency,timezone_name,account_status,min_daily_budget,user_tasks";
const entityFields = {
  campaign:
    "id,account_id,name,status,effective_status,daily_budget,lifetime_budget,objective,start_time,stop_time",
  adset:
    "id,account_id,name,status,effective_status,daily_budget,lifetime_budget,campaign_id,campaign{id,name,daily_budget,lifetime_budget,status},start_time,end_time,billing_event,optimization_goal",
  ad: "id,account_id,name,status,effective_status,campaign_id,adset_id,creative{id,name,title,body,thumbnail_url,image_url,object_story_spec}",
};
export function createAdsService({
  pool,
  graph,
  env = process.env,
  emitAutomationEvent,
}) {
  const cache = new Map(),
    inflight = new Map();
  async function authorize(actor, write = false, db = pool) {
    if (env.FACEBOOK_ADS_ENABLED !== "true")
      throw fault("facebook_ads_disabled", 503);
    const a = await loadPrincipal(db, actor.userId, actor.companyId, {
      enforceOAuthRolePolicy: false,
    });
    if (
      !a.permissions.capabilities["integrations.manage"] ||
      (write && !(a.isCompanyOwner || a.permissions.preset === "admin"))
    )
      throw fault("facebook_ads_access_denied", 403);
    return a;
  }
  async function connection(actor, db = pool) {
    await authorize(actor, false, db);
    const c = await one(
      db,
      "SELECT * FROM facebook_ads_connections WHERE company_id=$1",
      [actor.companyId],
    );
    if (!c?.token || !["connected", "attention"].includes(c.status))
      throw fault("facebook_ads_disconnected", 409);
    if (c.unified && expiredAuthorization(c.error_code))
      throw fault("facebook_reauthorize_required", 409);
    if (c.expires_at && new Date(c.expires_at) <= new Date()) {
      if (c.unified)
        await invalidateSharedAuthorization(
          db,
          actor.companyId,
          "facebook_reauthorize_required",
          "ads",
          c.token,
        );
      await db.query(
        "UPDATE facebook_ads_connections SET status='attention',error_code='facebook_reauthorize_required' WHERE company_id=$1 AND token=$2",
        [actor.companyId, c.token],
      );
      throw fault("facebook_reauthorize_required", 409);
    }
    return {
      ...c,
      accessToken: decrypt(c.token, `ads:${actor.companyId}`, env),
    };
  }
  async function request(c, path, params = {}, method = "GET", db = pool) {
    return provider(
      c,
      () => graph.request(path, c.accessToken, params, method),
      db,
    );
  }
  function providerGraph(c) {
    return {
      all: (...args) => provider(c, () => graph.all(...args)),
      page: (...args) => provider(c, () => graph.page(...args)),
    };
  }
  async function provider(c, work, db = pool) {
    try {
      return await work();
    } catch (e) {
      if (c.unified && expiredAuthorization(e.code))
        await invalidateSharedAuthorization(
          db,
          c.company_id,
          e.code,
          "ads",
          c.token,
        );
      if (
        [
          "facebook_reauthorize_required",
          "facebook_ads_permission_required",
        ].includes(e.code)
      )
        await db.query(
          "UPDATE facebook_ads_connections SET status='attention',error_code=$2,updated_at=now() WHERE company_id=$1 AND token=$3",
          [c.company_id, e.code, c.token],
        );
      throw e;
    }
  }
  async function account(
    actor,
    accountId,
    { write = false, selected = true, db = pool } = {},
  ) {
    id.parse(accountId);
    await authorize(actor, write, db);
    const c = await connection(actor, db),
      a = await one(
        db,
        "SELECT * FROM facebook_ads_accounts WHERE company_id=$1 AND account_id=$2 AND available=true",
        [actor.companyId, accountId],
      );
    if (c.operations_enabled === false)
      throw fault(
        "facebook_ads_operations_disabled",
        409,
        "Ads operations are disabled for this company. Enable them in Facebook connection settings.",
      );
    if (!a || (selected && !a.selected))
      throw fault("ad_account_not_selected", 404);
    if (
      !c.permissions.includes(write ? "ads_management" : "ads_read") &&
      !(!write && c.permissions.includes("ads_management"))
    )
      throw fault("facebook_ads_permission_required", 403);
    const live = await request(
      c,
      "act_" + accountId,
      { fields: accountFields },
      "GET",
      db,
    );
    if (String(live.account_id) !== accountId)
      throw fault("provider_account_mismatch", 403);
    if (
      write &&
      !(live.user_tasks || []).some((t) => ["MANAGE", "ADVERTISE"].includes(t))
    )
      throw fault("facebook_ad_account_write_role_required", 403);
    return { c, a: { ...a, ...live, account_id: accountId } };
  }
  async function status(actor) {
    await authorize(actor);
    const c = await one(
      pool,
      "SELECT status,permissions,error_code,checked_at,expires_at,revision,unified,operations_enabled FROM facebook_ads_connections WHERE company_id=$1",
      [actor.companyId],
    );
    return {
      configured: graph.configured(),
      api_version: VERSION,
      connection: c || { status: "disconnected", permissions: [], revision: 0 },
      accounts: (
        await pool.query(
          "SELECT account_id,name,currency,timezone_name,account_status,selected,available,user_tasks,checked_at FROM facebook_ads_accounts WHERE company_id=$1 ORDER BY name,account_id",
          [actor.companyId],
        )
      ).rows,
      worker_enabled: env.FACEBOOK_ADS_WORKER_ENABLED === "true",
    };
  }
  async function refresh(actor) {
    const c = await connection(actor),
      permissions = (
        await providerGraph(c).all("me/permissions", c.accessToken)
      )
        .filter((x) => x.status === "granted")
        .map((x) => x.permission);
    const accounts = await providerGraph(c).all(
      "me/adaccounts",
      c.accessToken,
      {
        fields: accountFields,
      },
    );
    const db = await pool.connect();
    try {
      await db.query("BEGIN");
      await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
        "facebook-ads-connection:" + actor.companyId,
      ]);
      await db.query(
        "SELECT company_id FROM facebook_ads_connections WHERE company_id=$1 FOR UPDATE",
        [actor.companyId],
      );
      const current = await one(
        db,
        "SELECT revision FROM facebook_ads_connections WHERE company_id=$1",
        [actor.companyId],
      );
      if (current.revision !== c.revision)
        throw fault("connection_changed", 409);
      await db.query(
        "UPDATE facebook_ads_accounts SET available=false WHERE company_id=$1",
        [actor.companyId],
      );
      for (const a of accounts) {
        id.parse(String(a.account_id));
        await db.query(
          `INSERT INTO facebook_ads_accounts(company_id,account_id,name,currency,timezone_name,account_status,min_daily_budget,user_tasks) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(company_id,account_id) DO UPDATE SET name=EXCLUDED.name,currency=EXCLUDED.currency,timezone_name=EXCLUDED.timezone_name,account_status=EXCLUDED.account_status,min_daily_budget=EXCLUDED.min_daily_budget,user_tasks=EXCLUDED.user_tasks,available=true,checked_at=now()`,
          [
            actor.companyId,
            String(a.account_id),
            a.name,
            a.currency,
            a.timezone_name,
            a.account_status,
            a.min_daily_budget || null,
            JSON.stringify(a.user_tasks || []),
          ],
        );
      }
      await db.query(
        "UPDATE facebook_ads_connections SET revision=revision+CASE WHEN permissions<>$2::jsonb THEN 1 ELSE 0 END,permissions=$2,status=$3,error_code=NULL,checked_at=now() WHERE company_id=$1",
        [
          actor.companyId,
          JSON.stringify(permissions),
          permissions.some((x) => ["ads_read", "ads_management"].includes(x))
            ? "connected"
            : "attention",
        ],
      );
      if (c.unified)
        await syncSharedPermissions(
          db,
          actor.companyId,
          permissions,
          "ads",
          c.token,
        );
      await db.query("COMMIT");
    } catch (e) {
      await db.query("ROLLBACK");
      throw e;
    } finally {
      db.release();
    }
    return status(actor);
  }
  async function select(actor, ids) {
    await authorize(actor, true);
    z.array(id).max(100).parse(ids);
    await refresh(actor);
    await connectionChange(actor.companyId, async (db) => {
      await authorize(actor, true, db);
      await connection(actor, db);
      const result = await db.query(
        "SELECT account_id FROM facebook_ads_accounts WHERE company_id=$1 AND available AND account_id=ANY($2::text[])",
        [actor.companyId, ids],
      );
      if (result.rowCount !== new Set(ids).size)
        throw fault("ad_account_unavailable");
      await db.query(
        "UPDATE facebook_ads_accounts SET selected=account_id=ANY($2::text[]) WHERE company_id=$1",
        [actor.companyId, ids],
      );
      await db.query(
        "UPDATE facebook_ads_connections SET revision=revision+1 WHERE company_id=$1",
        [actor.companyId],
      );
    });
    cache.clear();
    return status(actor);
  }
  async function connectionChange(companyId, operation) {
    const db = await pool.connect();
    try {
      await db.query("BEGIN");
      await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
        "facebook-ads-connection:" + companyId,
      ]);
      const result = await operation(db);
      await db.query("COMMIT");
      cache.clear();
      return result;
    } catch (e) {
      await db.query("ROLLBACK");
      throw e;
    } finally {
      db.release();
    }
  }
  async function connect(actor, { token, metaUserId, permissions, expiresAt }) {
    return connectionChange(actor.companyId, async (db) => {
      await authorize(actor, true, db);
      await db.query(
        `INSERT INTO facebook_ads_connections(company_id,user_id,meta_user_id,token,permissions,status,expires_at) VALUES($1,$2,$3,$4,$5,'connected',$6) ON CONFLICT(company_id) DO UPDATE SET user_id=EXCLUDED.user_id,meta_user_id=EXCLUDED.meta_user_id,token=EXCLUDED.token,permissions=EXCLUDED.permissions,status='connected',error_code=NULL,expires_at=EXCLUDED.expires_at,revision=facebook_ads_connections.revision+1,updated_at=now()`,
        [
          actor.companyId,
          actor.userId,
          metaUserId,
          encrypt(token, `ads:${actor.companyId}`, env),
          JSON.stringify(permissions),
          expiresAt,
        ],
      );
      // A different Facebook identity must explicitly select its own accounts.
      await db.query(
        "UPDATE facebook_ads_accounts SET selected=false,available=false WHERE company_id=$1",
        [actor.companyId],
      );
    });
  }
  async function revoke(metaUserId) {
    const rows = (
      await pool.query(
        "SELECT company_id FROM facebook_ads_connections WHERE meta_user_id=$1 ORDER BY company_id",
        [metaUserId],
      )
    ).rows;
    for (const row of rows)
      await connectionChange(row.company_id, async (db) => {
        await db.query(
          "UPDATE facebook_ads_connections SET token=NULL,status='revoked',permissions='[]',revision=revision+1,updated_at=now() WHERE company_id=$1 AND meta_user_id=$2",
          [row.company_id, metaUserId],
        );
      });
  }
  async function confirmReceipt(db, receiptId, item) {
    await db.query("BEGIN");
    try {
      const r = await one(
        db,
        "UPDATE facebook_ads_receipts SET status='confirmed',result=$2,error_code=NULL,updated_at=now() WHERE id=$1 RETURNING *",
        [receiptId, JSON.stringify(item)],
      );
      if (emitAutomationEvent)
        await emitAutomationEvent(
          {
            companyId: r.company_id,
            eventType: "facebook_ads.changed",
            subjectType: "facebook_ad",
            subjectId: r.entity_id,
            actorUserId: r.user_id,
            source: r.source,
            dedupeKey: `facebook-ads-receipt:${r.id}`,
            payload: {
              receipt_id: r.id,
              account_id: r.account_id,
              level: r.level,
              target: r.target,
            },
          },
          { db },
        );
      await db.query("COMMIT");
    } catch (e) {
      await db.query("ROLLBACK");
      throw e;
    }
  }
  async function disconnect(actor) {
    await authorize(actor, true);
    const db = await pool.connect();
    try {
      await db.query("BEGIN");
      await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
        "facebook-ads-connection:" + actor.companyId,
      ]);
      await authorize(actor, true, db);
      await db.query(
        "UPDATE facebook_ads_connections SET token=NULL,status='disconnected',permissions='[]',revision=revision+1,updated_at=now() WHERE company_id=$1",
        [actor.companyId],
      );
      await db.query(
        "UPDATE facebook_ads_accounts SET selected=false WHERE company_id=$1",
        [actor.companyId],
      );
      await db.query(
        "UPDATE facebook_ads_reports SET status='canceled' WHERE company_id=$1 AND status NOT IN ('completed','failed')",
        [actor.companyId],
      );
      await db.query("COMMIT");
    } catch (e) {
      await db.query("ROLLBACK");
      throw e;
    } finally {
      db.release();
    }
    cache.clear();
    return status(actor);
  }
  async function entity(
    actor,
    accountId,
    l,
    entityId,
    write = false,
    db = pool,
  ) {
    id.parse(entityId);
    level.exclude(["account"]).parse(l);
    const { c, a } = await account(actor, accountId, { write, db });
    const x = await request(
      c,
      entityId,
      { fields: entityFields[l] },
      "GET",
      db,
    );
    if (String(x.account_id) !== accountId)
      throw fault("provider_object_not_in_account", 404);
    const item = {
      ...x,
      end_time: x.end_time || x.stop_time || null,
      level: l,
      version: versionOf({ ...x, end_time: x.end_time || x.stop_time || null }),
      currency: a.currency,
      budget_owner:
        l === "ad"
          ? "adset_or_campaign"
          : l === "adset" &&
              (BigInt(x.campaign?.daily_budget || 0) > 0n ||
                BigInt(x.campaign?.lifetime_budget || 0) > 0n)
            ? "campaign"
            : l,
    };
    try {
      item.currency_digits = currencyDigits(a.currency);
    } catch {
      item.currency_digits = null;
    }
    return { item, c, a };
  }
  async function entities(actor, input) {
    const i = z
      .object({
        account_id: id,
        level: level.exclude(["account"]),
        parent_id: id.optional(),
        query: z.string().max(200).default(""),
        status: z.enum(["ALL", "ACTIVE", "PAUSED"]).default("ALL"),
        sort: z
          .enum(["name_ascending", "name_descending"])
          .default("name_ascending"),
        cursor: z.string().max(4096).optional(),
      })
      .strict()
      .parse(input);
    const { c, a } = await account(actor, i.account_id);
    let path = "act_" + i.account_id;
    if (i.parent_id) {
      await entity(
        actor,
        i.account_id,
        i.level === "adset" ? "campaign" : "adset",
        i.parent_id,
      );
      path = i.parent_id;
    }
    const filtering = [];
    if (i.query)
      filtering.push({ field: "name", operator: "CONTAIN", value: i.query });
    if (i.status !== "ALL")
      filtering.push({
        field: "effective_status",
        operator: "IN",
        value: [i.status],
      });
    const p = await providerGraph(c).page(
      `${path}/${i.level === "campaign" ? "campaigns" : i.level === "adset" ? "adsets" : "ads"}`,
      c.accessToken,
      {
        fields: entityFields[i.level],
        limit: "50",
        filtering: JSON.stringify(filtering),
      },
      i.cursor,
    );
    const rows = p.data
      .filter((x) => String(x.account_id) === i.account_id)
      .map((x) => ({
        ...x,
        level: i.level,
        currency: a.currency,
        end_time: x.end_time || x.stop_time || null,
        version: versionOf({
          ...x,
          end_time: x.end_time || x.stop_time || null,
        }),
      }));
    rows.sort(
      (a, b) =>
        a.name.localeCompare(b.name) * (i.sort === "name_ascending" ? 1 : -1),
    );
    return {
      items: rows,
      next_cursor: p.cursor,
      sort_scope: "Within this provider page",
      account: a,
    };
  }
  async function mutate(actor, input, source = "native") {
    const i = mutation.parse(input);
    await authorize(actor, true);
    const db = await pool.connect();
    let locked = false,
      connectionLocked = false;
    try {
      await db.query("SELECT pg_advisory_lock(hashtextextended($1,0))", [
        `facebook-ads:${actor.companyId}:${i.entity_id}`,
      ]);
      locked = true;
      await db.query("SELECT pg_advisory_lock_shared(hashtextextended($1,0))", [
        "facebook-ads-connection:" + actor.companyId,
      ]);
      connectionLocked = true;
      const prior = await one(
        db,
        "SELECT * FROM facebook_ads_receipts WHERE company_id=$1 AND request_id=$2",
        [actor.companyId, i.request_id],
      );
      if (prior && prior.input_hash !== digest(i))
        throw fault("idempotency_conflict", 409);
      const { item, c, a } = await entity(
        actor,
        i.account_id,
        i.level,
        i.entity_id,
        true,
        db,
      );
      if (prior) {
        if (
          ["confirmed", "rejected", "closed_unconfirmed"].includes(prior.status)
        )
          return receiptDTO(prior);
        const matched = Object.entries(prior.target).every(
          ([k, v]) => String(item[k]) === String(v),
        );
        if (matched) {
          await confirmReceipt(db, prior.id, item);
        }
        return receiptDTO(
          await one(
            db,
            "SELECT * FROM facebook_ads_receipts WHERE company_id=$1 AND request_id=$2",
            [actor.companyId, i.request_id],
          ),
        );
      }
      if (versionOf(item) !== i.expected_version)
        throw fault(
          "entity_changed_reload",
          409,
          "Delivery or budget changed. Refresh this object before submitting a new action.",
        );
      const pending = await one(
        db,
        "SELECT id FROM facebook_ads_receipts WHERE company_id=$1 AND entity_id=$2 AND status IN ('pending','uncertain') LIMIT 1",
        [actor.companyId, i.entity_id],
      );
      if (pending)
        throw fault(
          "previous_mutation_unresolved",
          409,
          "Reconcile the previous receipt before submitting another change.",
        );
      const target =
        i.change.kind === "status"
          ? { status: i.change.value }
          : { [i.change.budget_type]: budgetTarget(i.change, item, a) };
      if (i.change.kind === "budget")
        await request(
          c,
          i.entity_id,
          { ...target, execution_options: JSON.stringify(["validate_only"]) },
          "POST",
          db,
        );
      const rid = randomUUID();
      await db.query(
        `INSERT INTO facebook_ads_receipts(id,company_id,user_id,source,request_id,input_hash,account_id,entity_id,level,requested,previous,target,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pending')`,
        [
          rid,
          actor.companyId,
          actor.userId,
          source,
          i.request_id,
          digest(i),
          i.account_id,
          i.entity_id,
          i.level,
          JSON.stringify(i.change),
          JSON.stringify(item),
          JSON.stringify(target),
        ],
      );
      let sent = false;
      try {
        await authorize(actor, true, db);
        const still = await one(
          db,
          "SELECT c.revision,a.selected,a.available FROM facebook_ads_connections c JOIN facebook_ads_accounts a USING(company_id) WHERE c.company_id=$1 AND a.account_id=$2",
          [actor.companyId, i.account_id],
        );
        if (
          still?.revision !== c.revision ||
          !still?.selected ||
          !still?.available
        )
          throw fault("connection_changed", 409);
        sent = true;
        const accepted = await request(c, i.entity_id, target, "POST", db);
        if (accepted.success !== true)
          throw fault("facebook_mutation_acceptance_uncertain", 502);
        const verified = (
          await entity(actor, i.account_id, i.level, i.entity_id, true, db)
        ).item;
        const matched = Object.entries(target).every(
          ([k, v]) => String(verified[k]) === String(v),
        );
        if (matched) await confirmReceipt(db, rid, verified);
        else
          await db.query(
            "UPDATE facebook_ads_receipts SET status='uncertain',result=$2,updated_at=now() WHERE id=$1",
            [rid, JSON.stringify(verified)],
          );
      } catch (e) {
        await db.query(
          "UPDATE facebook_ads_receipts SET status=$2,error_code=$3,updated_at=now() WHERE id=$1",
          [rid, !sent || e.definitive ? "rejected" : "uncertain", safeError(e)],
        );
      }
      cache.clear();
      const receipt = await one(
        db,
        "SELECT * FROM facebook_ads_receipts WHERE id=$1",
        [rid],
      );
      return receiptDTO(receipt);
    } finally {
      if (connectionLocked)
        await db.query(
          "SELECT pg_advisory_unlock_shared(hashtextextended($1,0))",
          ["facebook-ads-connection:" + actor.companyId],
        );
      if (locked)
        await db.query("SELECT pg_advisory_unlock(hashtextextended($1,0))", [
          `facebook-ads:${actor.companyId}:${i.entity_id}`,
        ]);
      db.release();
    }
  }
  const receiptDTO = (r) =>
    Object.fromEntries(
      [
        "id",
        "request_id",
        "account_id",
        "entity_id",
        "level",
        "source",
        "requested",
        "previous",
        "target",
        "result",
        "status",
        "error_code",
        "created_at",
        "updated_at",
      ].map((k) => [k, r[k]]),
    );
  async function reconcile(actor, rid) {
    await authorize(actor, true);
    const r = await one(
      pool,
      "SELECT * FROM facebook_ads_receipts WHERE id=$1 AND company_id=$2",
      [z.uuid().parse(rid), actor.companyId],
    );
    if (!r) throw fault("receipt_not_found", 404);
    return mutate(
      actor,
      {
        request_id: r.request_id,
        account_id: r.account_id,
        level: r.level,
        entity_id: r.entity_id,
        expected_version: r.previous.version,
        change: r.requested,
      },
      r.source,
    );
  }
  async function receipts(actor) {
    await authorize(actor);
    return {
      items: (
        await pool.query(
          "SELECT * FROM facebook_ads_receipts WHERE company_id=$1 ORDER BY created_at DESC LIMIT 100",
          [actor.companyId],
        )
      ).rows.map(receiptDTO),
    };
  }
  async function reportContext(actor, input) {
    const r = validateReport(input),
      { c, a } = await account(actor, r.account_id);
    const params = {
      ...dateWindow(r.period, a.timezone_name),
      level: r.level,
      fields: fieldsFor(r),
      time_increment: r.granularity,
      action_report_time: r.action_report_time,
      limit: "100",
    };
    if (r.breakdowns.length) params.breakdowns = r.breakdowns.join(",");
    if (r.entity_ids.length) {
      if (r.level === "account")
        throw fault("account_entity_filter_unsupported");
      for (const eid of r.entity_ids)
        await entity(actor, r.account_id, r.level, eid);
      params.filtering = JSON.stringify([
        { field: r.level + ".id", operator: "IN", value: r.entity_ids },
      ]);
    }
    if (r.attribution === "custom")
      params.action_attribution_windows = JSON.stringify(r.windows);
    else
      params[
        r.attribution === "adset"
          ? "use_unified_attribution_setting"
          : "use_account_attribution_setting"
      ] = "true";
    return { r, c, a, params };
  }
  function reportDTO(data, context, cursor) {
    const { r, a, params } = context;
    return {
      items: data.map((row) => ({
        entity_id: String(row[r.level + "_id"] || row.account_id),
        name: row[r.level + "_name"] || a.name,
        date_start: row.date_start,
        date_stop: row.date_stop,
        breakdowns: Object.fromEntries(
          r.breakdowns.map((k) => [k, row[k] ?? null]),
        ),
        ...valuesFor(row, r),
      })),
      next_cursor: cursor || null,
      account_id: r.account_id,
      currency: a.currency,
      timezone: a.timezone_name,
      api_version: VERSION,
      period: params.time_range
        ? JSON.parse(params.time_range)
        : { preset: "maximum" },
      attribution: r.attribution,
      windows: r.attribution === "custom" ? r.windows : null,
      action_report_time: r.action_report_time,
      refreshed_at: new Date().toISOString(),
      data_delay_note:
        "Provider data may be delayed or revised; refresh time is not conversion finality.",
      rate_usage: graph.usage,
    };
  }
  async function insights(actor, input, cursor) {
    const context = await reportContext(actor, input),
      key = digest([
        actor.companyId,
        context.c.revision,
        context.r,
        context.params.time_range || context.params.date_preset,
        context.r.compare
          ? dateWindow(context.r.compare, context.a.timezone_name)
          : null,
        cursor || null,
      ]);
    const hit = cache.get(key);
    if (hit && Date.now() - hit.time < 60000)
      return { ...hit.value, cached: true };
    if (inflight.has(key)) return inflight.get(key);
    const work = (async () => {
      const p = await providerGraph(context.c).page(
        `act_${context.r.account_id}/insights`,
        context.c.accessToken,
        context.params,
        cursor,
      );
      const dto = reportDTO(p.data, context, p.cursor);
      if (context.r.compare) {
        const other = await reportContext(actor, {
          ...context.r,
          period: context.r.compare,
          compare: undefined,
        });
        const page = await providerGraph(other.c).page(
          `act_${context.r.account_id}/insights`,
          other.c.accessToken,
          other.params,
        );
        dto.comparison = reportDTO(page.data, other, page.cursor);
      }
      if (cache.size > 100) cache.delete(cache.keys().next().value);
      cache.set(key, { time: Date.now(), value: dto });
      return dto;
    })();
    inflight.set(key, work);
    try {
      return await work;
    } finally {
      inflight.delete(key);
    }
  }
  async function startReport(actor, input) {
    const context = await reportContext(actor, input);
    if (context.r.compare)
      throw fault(
        "async_comparison_separate_jobs",
        400,
        "Start separate async reports for the two comparison periods.",
      );
    const rid = randomUUID();
    const job = await request(
      context.c,
      `act_${context.r.account_id}/insights`,
      context.params,
      "POST",
    );
    if (!job.report_run_id) throw fault("report_job_missing", 502);
    await pool.query(
      `INSERT INTO facebook_ads_reports(id,company_id,user_id,account_id,connection_revision,config,provider_id,status) VALUES($1,$2,$3,$4,$5,$6,$7,'running')`,
      [
        rid,
        actor.companyId,
        actor.userId,
        context.r.account_id,
        context.c.revision,
        JSON.stringify({
          ...context.r,
          period: context.params.time_range
            ? { preset: "custom", ...JSON.parse(context.params.time_range) }
            : context.r.period,
        }),
        String(job.report_run_id),
      ],
    );
    return { id: rid, status: "running", progress: 0 };
  }
  async function pollReport(actor, rid, cursor) {
    z.uuid().parse(rid);
    await authorize(actor);
    const row = await one(
      pool,
      "SELECT * FROM facebook_ads_reports WHERE id=$1 AND company_id=$2",
      [rid, actor.companyId],
    );
    if (!row) throw fault("report_not_found", 404);
    if (row.status === "canceled")
      return { id: rid, status: "canceled", progress: row.progress };
    const context = await reportContext(actor, row.config);
    if (row.connection_revision !== context.c.revision)
      throw fault("report_authorization_changed", 409);
    const progress = await request(context.c, row.provider_id, {
      fields: "async_status,async_percent_completion",
    });
    const status =
      progress.async_status === "Job Completed"
        ? "completed"
        : ["Job Failed", "Job Skipped"].includes(progress.async_status)
          ? "failed"
          : "running";
    const changed = await pool.query(
      "UPDATE facebook_ads_reports SET status=$2,progress=$3,updated_at=now() WHERE id=$1 AND status<>'canceled' RETURNING id",
      [rid, status, progress.async_percent_completion || 0],
    );
    if (!changed.rowCount)
      return { id: rid, status: "canceled", progress: row.progress };
    const result = {
      id: rid,
      status,
      progress: progress.async_percent_completion || 0,
    };
    if (status === "completed") {
      const p = await providerGraph(context.c).page(
        `${row.provider_id}/insights`,
        context.c.accessToken,
        { limit: "100" },
        cursor,
      );
      result.report = reportDTO(p.data, context, p.cursor);
    }
    return result;
  }
  async function reports(actor) {
    await authorize(actor);
    return {
      items: (
        await pool.query(
          "SELECT id,status,progress,created_at,config FROM facebook_ads_reports WHERE company_id=$1 ORDER BY created_at DESC LIMIT 30",
          [actor.companyId],
        )
      ).rows,
    };
  }
  async function cancelReport(actor, rid) {
    await authorize(actor);
    await pool.query(
      "UPDATE facebook_ads_reports SET status='canceled',updated_at=now() WHERE id=$1 AND company_id=$2",
      [z.uuid().parse(rid), actor.companyId],
    );
    return { id: rid, status: "canceled" };
  }
  async function views(actor) {
    await authorize(actor);
    return {
      items: (
        await pool.query(
          "SELECT id,name,config,revision FROM facebook_ads_views WHERE company_id=$1 AND user_id=$2 ORDER BY updated_at DESC",
          [actor.companyId, actor.userId],
        )
      ).rows,
    };
  }
  async function saveView(actor, input) {
    await authorize(actor);
    const i = z
        .object({
          id: z.uuid().optional(),
          name: z.string().trim().min(1).max(100),
          revision: z.number().int().min(1).optional(),
          config: z.any(),
        })
        .strict()
        .parse(input),
      config = validateReport(i.config);
    await account(actor, config.account_id);
    const rid = i.id || randomUUID();
    if (i.id) {
      const r = await pool.query(
        "UPDATE facebook_ads_views SET name=$4,config=$5,revision=revision+1,updated_at=now() WHERE id=$1 AND company_id=$2 AND user_id=$3 AND revision=$6 RETURNING id",
        [
          rid,
          actor.companyId,
          actor.userId,
          i.name,
          JSON.stringify(config),
          i.revision || 0,
        ],
      );
      if (!r.rowCount) throw fault("view_changed_reload", 409);
    } else
      await pool.query(
        "INSERT INTO facebook_ads_views(id,company_id,user_id,name,config) VALUES($1,$2,$3,$4,$5)",
        [rid, actor.companyId, actor.userId, i.name, JSON.stringify(config)],
      );
    return views(actor);
  }
  async function deleteView(actor, rid) {
    await authorize(actor);
    await pool.query(
      "DELETE FROM facebook_ads_views WHERE id=$1 AND company_id=$2 AND user_id=$3",
      [z.uuid().parse(rid), actor.companyId, actor.userId],
    );
    return views(actor);
  }
  return {
    authorize,
    connection,
    account,
    status,
    refresh,
    select,
    disconnect,
    connect,
    revoke,
    entity,
    entities,
    mutate,
    reconcile,
    receipts,
    insights,
    startReport,
    pollReport,
    reports,
    cancelReport,
    views,
    saveView,
    deleteView,
    catalog,
    request,
  };
}
