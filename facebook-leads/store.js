import {
  expiredAuthorization,
  invalidateSharedAuthorization,
  syncSharedPermissions,
} from "../facebook-connection/state.js";
import { randomUUID } from "node:crypto";
import {
  DEFAULT_SETTINGS,
  DESTINATIONS,
  METADATA,
  fail,
  definitionSources,
  validateMappings,
  effectiveMapping,
  mapLead,
  mergeContact,
  normalizeEmail,
  normalizePhone,
  dateRange,
} from "./domain.js";
import { encrypt, decrypt, PERMISSIONS } from "./provider.js";
export async function transaction(pool, work) {
  const db = await pool.connect();
  try {
    await db.query("BEGIN");
    const value = await work(db);
    await db.query("COMMIT");
    return value;
  } catch (e) {
    await db.query("ROLLBACK");
    throw e;
  } finally {
    db.release();
  }
}
const one = async (db, sql, values) => (await db.query(sql, values)).rows[0];
export function createFacebookLeadStore({ pool, graph, env = process.env }) {
  async function settings(db, company, lock = false) {
    await db.query(
      "INSERT INTO facebook_lead_settings(company_id) VALUES($1) ON CONFLICT DO NOTHING",
      [company],
    );
    return one(
      db,
      `SELECT * FROM facebook_lead_settings WHERE company_id=$1${lock ? " FOR UPDATE" : ""}`,
      [company],
    );
  }
  async function page(db, company, id) {
    const row = await one(
      db,
      "SELECT * FROM facebook_lead_pages WHERE company_id=$1 AND page_id=$2",
      [company, id],
    );
    if (!row) fail("facebook_page_not_found", 404);
    return row;
  }
  async function form(db, company, id) {
    const row = await one(
      db,
      "SELECT f.*,p.name AS page_name,p.token,p.selected,p.subscription FROM facebook_lead_forms f JOIN facebook_lead_pages p ON p.company_id=f.company_id AND p.page_id=f.page_id WHERE f.company_id=$1 AND f.form_id=$2",
      [company, id],
    );
    if (!row) fail("facebook_form_not_found", 404);
    return row;
  }
  const pageToken = (row) => {
    if (!row.token) fail("facebook_reconnect_required", 409);
    return decrypt(row.token, `${row.company_id}:${row.page_id}`, env);
  };
  async function status(company) {
    const s = await settings(pool, company),
      connection = await one(
        pool,
        "SELECT status,permissions,error_code,checked_at,updated_at,unified,importing_paused,expires_at FROM facebook_lead_connections WHERE company_id=$1",
        [company],
      );
    const pages = (
      await pool.query(
        "SELECT page_id,name,selected,subscription,retrieval,error_code,checked_at FROM facebook_lead_pages WHERE company_id=$1 ORDER BY name,page_id",
        [company],
      )
    ).rows;
    const forms = (
      await pool.query(
        "SELECT form_id,page_id,name,enabled,routed,revision,last_success_at,error_code,sources FROM facebook_lead_forms WHERE company_id=$1 ORDER BY name,form_id",
        [company],
      )
    ).rows;
    return {
      configured: graph.configured(),
      worker_enabled: env.FACEBOOK_LEADS_WORKER_ENABLED === "true",
      company_id: company,
      connection: connection || { status: "disconnected", permissions: [] },
      pages,
      forms,
      settings: s.configuration,
      revision: s.revision,
      destinations: DESTINATIONS,
      required_permissions: PERMISSIONS,
      limitations: [
        "Use one Facebook app for Leads and Ads; keep Focus/Instagram and its callback separate.",
        "Contact notes are device-local and are not a shared writable contact field. Use labeled Lead Info.",
        "Legacy custom fields are Lead Info 1–5. Name and address use combined contact fields.",
        "Optional attribution and export columns depend on Meta permissions and availability.",
        "Lead/Page/form IDs and processing status are retained for routing and duplicate prevention, even when their optional contact mappings are ignored.",
        "Ignore applies to future processing. It does not erase existing contacts or old Zapier archives.",
        "Pause holds queued leads. Resume catches up within Meta availability; old leads may expire.",
      ],
    };
  }
  async function discoverPages(company, token) {
    const pages = await graph.all("me/accounts", token, {
      fields: "id,name,access_token,tasks",
    });
    await transaction(pool, async (db) => {
      const current = await one(
        db,
        "SELECT token FROM facebook_lead_connections WHERE company_id=$1 FOR UPDATE",
        [company],
      );
      if (!current?.token || decrypt(current.token, company, env) !== token)
        fail("facebook_authorization_changed_retry", 409);
      for (const p of pages)
        if (p.id && p.access_token)
          await db.query(
            `INSERT INTO facebook_lead_pages(company_id,page_id,name,token) VALUES($1,$2,$3,$4) ON CONFLICT(company_id,page_id) DO UPDATE SET name=EXCLUDED.name,token=EXCLUDED.token,subscription='unchecked',retrieval='unchecked'`,
            [
              company,
              String(p.id),
              p.name || String(p.id),
              encrypt(p.access_token, `${company}:${p.id}`, env),
            ],
          );
      // Removed Page access cannot keep a stale usable credential.
      await db.query(
        "UPDATE facebook_lead_pages SET token=NULL,retrieval='unavailable',error_code='facebook_page_access_removed' WHERE company_id=$1 AND NOT(page_id=ANY($2::text[]))",
        [company, pages.filter((p) => p.access_token).map((p) => String(p.id))],
      );
    });
    return pages.length;
  }
  async function refresh(company) {
    const c = await one(
      pool,
      "SELECT * FROM facebook_lead_connections WHERE company_id=$1",
      [company],
    );
    if (!c?.token) fail("facebook_reconnect_required", 409);
    const token = decrypt(c.token, company, env);
    try {
      const permissions = await graph.all("me/permissions", token),
        granted = permissions
          .filter((p) => p.status === "granted")
          .map((p) => p.permission);
      await discoverPages(company, token);
      await pool.query(
        "UPDATE facebook_lead_connections SET permissions=$2::jsonb,status='authorized',error_code=NULL,checked_at=now() WHERE company_id=$1 AND token=$3",
        [company, JSON.stringify(granted), c.token],
      );
      if (c.unified)
        await syncSharedPermissions(pool, company, granted, "leads", c.token);
      const pages = (
        await pool.query(
          "SELECT * FROM facebook_lead_pages WHERE company_id=$1 AND selected AND token IS NOT NULL",
          [company],
        )
      ).rows;
      for (const p of pages) await inspectPage(company, p.page_id);
    } catch (e) {
      if (c.unified && expiredAuthorization(e.code))
        await invalidateSharedAuthorization(
          pool,
          company,
          e.code,
          "leads",
          c.token,
        );
      await pool.query(
        "UPDATE facebook_lead_connections SET status='attention',error_code=$2,checked_at=now() WHERE company_id=$1 AND token=$3",
        [company, safeError(e), c.token],
      );
      throw e;
    }
    return status(company);
  }
  async function inspectPage(company, id, subscribe = false) {
    const p = await page(pool, company, id),
      token = pageToken(p);
    try {
      let subscriptions = await graph.all(`${id}/subscribed_apps`, token, {
        fields: "id,subscribed_fields",
      });
      if (subscribe) {
        const prior = subscriptions.find(
          (a) => String(a.id) === env.FACEBOOK_LEADS_APP_ID,
        );
        await graph.request(
          `${id}/subscribed_apps`,
          token,
          {
            subscribed_fields: [
              ...new Set([...(prior?.subscribed_fields || []), "leadgen"]),
            ].join(","),
          },
          "POST",
        );
        subscriptions = await graph.all(`${id}/subscribed_apps`, token, {
          fields: "id,subscribed_fields",
        });
      }
      const subscribed = subscriptions.some(
        (a) =>
          String(a.id) === env.FACEBOOK_LEADS_APP_ID &&
          a.subscribed_fields?.includes("leadgen"),
      );
      let forms,
        definitionIssue = null;
      try {
        forms = await graph.all(`${id}/leadgen_forms`, token, {
          fields: "id,name,questions,status,legal_content",
        });
      } catch (error) {
        if (error.code !== "facebook_request_rejected") throw error;
        forms = await graph.all(`${id}/leadgen_forms`, token, {
          fields: "id,name,questions,status",
        });
        definitionIssue = "facebook_consent_definitions_unavailable";
      }
      await transaction(pool, async (db) => {
        const current = await one(
          db,
          "SELECT token FROM facebook_lead_connections WHERE company_id=$1 FOR UPDATE",
          [company],
        );
        const currentPage = await page(db, company, id);
        if (!current?.token || currentPage.token !== p.token)
          fail("facebook_authorization_changed_retry", 409);
        for (const f of forms) {
          const old = await one(
            db,
            "SELECT sources FROM facebook_lead_forms WHERE company_id=$1 AND form_id=$2",
            [company, String(f.id)],
          );
          const defs = definitionSources(f.questions, f.legal_content),
            oldSources = new Map((old?.sources || []).map((s) => [s.key, s])),
            known = new Map(
              defs.map((s) => [
                s.key,
                {
                  ...s,
                  review: old ? (oldSources.get(s.key)?.review ?? true) : false,
                },
              ]),
            );
          for (const s of old?.sources || [])
            if (!known.has(s.key)) known.set(s.key, s);
          await db.query(
            `INSERT INTO facebook_lead_forms(company_id,page_id,form_id,name,sources) VALUES($1,$2,$3,$4,$5::jsonb) ON CONFLICT(company_id,form_id) DO UPDATE SET name=EXCLUDED.name,sources=EXCLUDED.sources`,
            [
              company,
              id,
              String(f.id),
              f.name || String(f.id),
              JSON.stringify([...known.values()]),
            ],
          );
        }
        await db.query(
          "UPDATE facebook_lead_pages SET selected=true,subscription=$3,error_code=$4,checked_at=now() WHERE company_id=$1 AND page_id=$2",
          [company, id, subscribed ? "subscribed" : "missing", definitionIssue],
        );
      });
      // Probe ID-only access independently from listing forms and OAuth.
      try {
        for (const f of forms.slice(0, 1))
          await graph.page(`${f.id}/leads`, token, {
            fields: "id",
            limit: "1",
          });
        await pool.query(
          "UPDATE facebook_lead_pages SET retrieval=$3 WHERE company_id=$1 AND page_id=$2",
          [company, id, forms.length ? "verified" : "no_forms"],
        );
      } catch (e) {
        await pool.query(
          "UPDATE facebook_lead_pages SET retrieval='unavailable',error_code=$3 WHERE company_id=$1 AND page_id=$2",
          [company, id, safeError(e)],
        );
      }
    } catch (e) {
      await pool.query(
        "UPDATE facebook_lead_pages SET error_code=$3,checked_at=now() WHERE company_id=$1 AND page_id=$2",
        [company, id, safeError(e)],
      );
      throw e;
    }
    return status(company);
  }
  async function mapping(company, id) {
    const f = id === "defaults" ? null : await form(pool, company, id),
      s = await settings(pool, company);
    const sources = f
      ? [...f.sources, ...METADATA]
      : [
          ...definitionSources(
            [
              "full_name",
              "first_name",
              "last_name",
              "email",
              "phone_number",
              "street_address",
              "city",
              "state",
              "postal_code",
              "country",
            ].map((key) => ({ key, label: key.replaceAll("_", " ") })),
          ),
          ...METADATA,
        ];
    // Company defaults may address any discovered question, including consent.
    if (!f) {
      const forms = (
        await pool.query(
          "SELECT sources FROM facebook_lead_forms WHERE company_id=$1 ORDER BY form_id",
          [company],
        )
      ).rows;
      for (const row of forms)
        for (const source of row.sources)
          if (!sources.some((s) => s.key === source.key)) sources.push(source);
    }
    // Include company-specific defaults and observed overrides not in a current definition.
    for (const key of Object.keys({
      ...s.configuration.mappings,
      ...f?.mappings,
    }))
      if (!sources.some((x) => x.key === key))
        sources.push({
          key,
          label: key.replace(/^[^:]+:/, ""),
          type: "text",
          review: true,
        });
    return {
      form_id: id,
      revision: f?.revision ?? s.revision,
      sources: sources.map((source) => ({
        ...source,
        mapping: effectiveMapping(source, s.configuration, f?.mappings),
      })),
      mappings: f?.mappings || s.configuration.mappings,
      settings: s.configuration,
      destinations: DESTINATIONS,
    };
  }
  async function saveMapping(company, id, body) {
    return transaction(pool, async (db) => {
      const s = await settings(db, company, true);
      const f =
        id === "defaults"
          ? null
          : await one(
              db,
              "SELECT * FROM facebook_lead_forms WHERE company_id=$1 AND form_id=$2 FOR UPDATE",
              [company, id],
            );
      if (id !== "defaults" && !f) fail("facebook_form_not_found", 404);
      if (body.revision !== (f?.revision ?? s.revision))
        fail("configuration_changed_reload", 409);
      const config = { ...s.configuration };
      if (id === "defaults") {
        if (
          !["lead_info", "ignore"].includes(body.unknown_policy) ||
          typeof body.overwrite !== "boolean"
        )
          fail("invalid_import_policy");
        config.unknown_policy = body.unknown_policy;
        config.overwrite = body.overwrite;
      }
      const sources = [...(f?.sources || []), ...METADATA];
      for (const key of Object.keys(body.mappings || {}))
        if (!sources.some((s) => s.key === key))
          sources.push({ key, label: key, type: "text" });
      const clean = validateMappings(body.mappings, sources, config);
      if (f)
        await db.query(
          "UPDATE facebook_lead_forms SET mappings=$3::jsonb,sources=$4::jsonb,revision=revision+1 WHERE company_id=$1 AND form_id=$2",
          [
            company,
            id,
            JSON.stringify(clean),
            JSON.stringify(
              f.sources.map((source) =>
                clean[source.key] ? { ...source, review: false } : source,
              ),
            ),
          ],
        );
      else {
        config.mappings = clean;
        await db.query(
          "UPDATE facebook_lead_settings SET configuration=$2::jsonb,revision=revision+1 WHERE company_id=$1",
          [company, JSON.stringify(config)],
        );
      }
      return { ok: true };
    });
  }
  async function enqueue(db, company, pageID, formID, leadID) {
    if (
      ![pageID, formID, leadID].every(
        (v) => typeof v === "string" && /^\d{1,100}$/.test(v),
      )
    )
      fail("invalid_meta_identifiers");
    return db.query(
      "INSERT INTO facebook_lead_jobs(company_id,page_id,form_id,lead_id) VALUES($1,$2,$3,$4) ON CONFLICT(company_id,lead_id) DO UPDATE SET status='pending',attempts=0,available_at=now(),page_id=EXCLUDED.page_id,form_id=EXCLUDED.form_id,error_code=NULL WHERE facebook_lead_jobs.status='canceled'",
      [company, pageID, formID, leadID],
    );
  }
  async function webhook(body) {
    if (body.object !== "page") return;
    await transaction(pool, async (db) => {
      for (const entry of Array.isArray(body.entry) ? body.entry : [])
        for (const change of Array.isArray(entry.changes)
          ? entry.changes
          : []) {
          if (change.field !== "leadgen") continue;
          const v = change.value || {},
            pageID = String(v.page_id || entry.id),
            formID = String(v.form_id),
            leadID = String(v.leadgen_id);
          if (String(entry.id) !== pageID) fail("webhook_page_mismatch");
          const f = await one(
            db,
            `SELECT f.* FROM facebook_lead_forms f JOIN facebook_lead_pages p USING(company_id,page_id) JOIN facebook_lead_connections c USING(company_id) WHERE f.form_id=$1 AND f.page_id=$2 AND f.routed AND p.selected AND p.token IS NOT NULL AND c.token IS NOT NULL FOR SHARE OF c,p,f`,
            [formID, pageID],
          );
          if (f) await enqueue(db, f.company_id, pageID, formID, leadID);
        }
    });
  }
  async function preview(company, id, leadID) {
    const f = await form(pool, company, id);
    let lead,
      providerIssues = [];
    if (leadID) {
      if (!/^\d{1,100}$/.test(leadID)) fail("invalid_meta_lead_id");
      const result = await graph.lead(leadID, pageToken(f));
      lead = result.lead;
      providerIssues = result.issues;
      if (String(lead.form_id) !== id) fail("lead_form_mismatch", 403);
    } else
      lead = {
        id: "sample",
        form_id: id,
        field_data: f.sources
          .filter((s) => s.key.startsWith("field:"))
          .map((s) => ({
            name: s.key.slice(6),
            values: [
              s.key === "field:email"
                ? "sample@example.invalid"
                : s.key === "field:phone_number"
                  ? "+12025550123"
                  : `Sample ${s.label}`,
            ],
          })),
      };
    return transaction(pool, async (db) => {
      const s = await settings(db, company, true);
      const current = await form(db, company, id);
      if (leadID && (!current.token || current.token !== f.token))
        fail("facebook_authorization_changed_retry", 409);
      const mapped = mapLead(lead, current, s.configuration);
      const matches = await findMatches(db, company, mapped.contact);
      const existing = matches.length === 1 ? matches[0] : null;
      return {
        sample: !leadID,
        contact: projectContact(
          mergeContact(existing, mapped, s.configuration, leadID || "sample"),
        ),
        rows: mapped.rows,
        ignored: mapped.ignored,
        issues: [
          ...mapped.issues,
          ...providerIssues,
          ...(matches.length > 1
            ? [{ code: "conflicting_contact_matches" }]
            : []),
        ],
        matched_contact_id: existing?.id || null,
      };
    });
  }

  async function scan(company, id, body) {
    const range = dateRange(body.from, body.to);
    return transaction(pool, async (db) => {
      await settings(db, company, true);
      const f = await form(db, company, id);
      pageToken(f);
      if (!f.routed || !f.selected)
        fail("facebook_enable_form_before_backfill", 409);
      const row = await one(
        db,
        `INSERT INTO facebook_lead_scans(company_id,form_id,from_time,to_time,preview) VALUES($1,$2,$3,$4,$5) ON CONFLICT(company_id,form_id,preview) WHERE status IN ('pending','processing','retry') DO UPDATE SET company_id=EXCLUDED.company_id RETURNING *`,
        [company, id, range.from, range.to, body.preview === true],
      );
      return {
        id: row.id,
        status: row.status,
        queued: row.queued,
        preview: row.preview,
      };
    });
  }
  async function activity(company, before) {
    let cursor;
    try {
      cursor = before
        ? JSON.parse(Buffer.from(before, "base64url").toString())
        : null;
    } catch {
      fail("invalid_activity_cursor");
    }
    if (
      cursor &&
      (!Number.isFinite(Date.parse(cursor.at)) ||
        !/^[-a-f0-9]{36}$/.test(cursor.id))
    )
      fail("invalid_activity_cursor");
    const date = cursor ? cursor.at : new Date(Date.now() + 1000),
      lastID = cursor?.id || "ffffffff-ffff-ffff-ffff-ffffffffffff";
    const jobs = (
      await pool.query(
        `SELECT j.id,j.form_id,f.name AS form_name,j.lead_id,j.contact_id,j.status,j.attempts,j.outcome,j.issues,j.error_code,j.created_at,j.created_at::text AS cursor_time,j.updated_at,j.available_at FROM facebook_lead_jobs j LEFT JOIN facebook_lead_forms f ON f.company_id=j.company_id AND f.form_id=j.form_id WHERE j.company_id=$1 AND (j.created_at,j.id)<($2::timestamptz,$3::uuid) ORDER BY j.created_at DESC,j.id DESC LIMIT 100`,
        [company, date, lastID],
      )
    ).rows;
    const scans = (
      await pool.query(
        "SELECT id,form_id,status,queued,preview,from_time,to_time,attempts,error_code FROM facebook_lead_scans WHERE company_id=$1 ORDER BY created_at DESC LIMIT 25",
        [company],
      )
    ).rows;
    return {
      jobs,
      scans,
      next_before:
        jobs.length === 100
          ? Buffer.from(
              JSON.stringify({
                at: jobs.at(-1).cursor_time,
                id: jobs.at(-1).id,
              }),
            ).toString("base64url")
          : null,
    };
  }
  return {
    settings,
    page,
    form,
    pageToken,
    status,
    discoverPages,
    refresh,
    inspectPage,
    mapping,
    saveMapping,
    enqueue,
    webhook,
    preview,
    scan,
    activity,
  };
}
export function safeError(error) {
  return error?.code?.startsWith("facebook_") ||
    [
      "contact_matches_conflict",
      "lead_form_mismatch",
      "configuration_changed_reload",
      "webhook_page_mismatch",
    ].includes(error?.code)
    ? error.code
    : "facebook_processing_failed";
}
export function projectContact(c) {
  return Object.fromEntries(
    [
      "name",
      "email",
      "phone",
      "address",
      "job_type",
      "source",
      "lead_submitted_at",
      "lead_info",
    ]
      .filter((k) => c[k] !== undefined)
      .map((k) => [k, c[k]]),
  );
}
export async function findMatches(db, company, contact, lock = false) {
  const email = normalizeEmail(contact.email),
    phone = normalizePhone(contact.phone);
  if (!email && !phone) return [];
  return (
    await db.query(
      `SELECT * FROM contacts WHERE company_id=$1 AND deleted_at IS NULL AND (($2<>'' AND lower(trim(email))=$2) OR ($3<>'' AND (regexp_replace(phone,'[^0-9]','','g')=$3 OR (length($3)=10 AND regexp_replace(phone,'[^0-9]','','g')='1'||$3)))) ORDER BY id LIMIT 3${lock ? " FOR UPDATE" : ""}`,
      [company, email, phone],
    )
  ).rows;
}
