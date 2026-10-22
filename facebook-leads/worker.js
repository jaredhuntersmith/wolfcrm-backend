import {
  expiredAuthorization,
  invalidateSharedAuthorization,
} from "../facebook-connection/state.js";
import { randomUUID } from "node:crypto";
import { mapLead, mergeContact, fail, FacebookLeadError } from "./domain.js";
import { transaction, findMatches, safeError } from "./store.js";
import { ensureLeadSource } from "../lead-sources.js";
const one = async (db, sql, args) => (await db.query(sql, args)).rows[0];
export function createFacebookLeadWorker({
  pool,
  store,
  graph,
  emitAutomationEvent,
  markContactDirty,
  sendPushToUsers,
}) {
  async function claim(table) {
    const scan = table === "facebook_lead_scans";
    return one(
      pool,
      `UPDATE ${table} j SET status='processing',lease=$1,lease_until=now()+interval '5 minutes',attempts=attempts+1 WHERE j.id=(SELECT q.id FROM ${table} q JOIN facebook_lead_forms f ON f.company_id=q.company_id AND f.form_id=q.form_id JOIN facebook_lead_pages p ON p.company_id=f.company_id AND p.page_id=f.page_id JOIN facebook_lead_connections c ON c.company_id=f.company_id WHERE (q.status IN ('pending','retry') AND q.available_at<=now() OR q.status='processing' AND q.lease_until<now()) AND q.attempts<8 AND p.selected AND p.token IS NOT NULL AND c.token IS NOT NULL AND NOT c.importing_paused AND (c.expires_at IS NULL OR c.expires_at>now()) AND (NOT c.unified OR (c.status='authorized' AND c.permissions ? 'leads_retrieval')) ${scan ? "AND (q.preview OR f.mapping_ready)" : "AND f.enabled AND f.mapping_ready"} ORDER BY q.available_at,q.id FOR UPDATE OF q SKIP LOCKED LIMIT 1) RETURNING j.*`,
      [randomUUID()],
    );
  }
  async function failed(table, job, error, credential) {
    if (credential?.unified && expiredAuthorization(error.code)) {
      await invalidateSharedAuthorization(
        pool,
        job.company_id,
        error.code,
        "leads",
        credential.token,
      );
    }
    const retry =
      (error.retryable === true || !(error instanceof FacebookLeadError)) &&
      job.attempts < 8;
    const delay =
      Math.max(
        Number(error.retryAfter) || 0,
        Math.min(21600, 30 * 2 ** Math.min(job.attempts, 10)),
      ) + Math.floor(Math.random() * 10);
    await pool.query(
      `UPDATE ${table} SET status=$3,error_code=$4,available_at=now()+$5*interval '1 second',lease=NULL,lease_until=NULL WHERE id=$1 AND lease=$2`,
      [job.id, job.lease, retry ? "retry" : "failed", safeError(error), delay],
    );
    await pool.query(
      "UPDATE facebook_lead_forms SET error_code=$3 WHERE company_id=$1 AND form_id=$2",
      [job.company_id, job.form_id, safeError(error)],
    );
    if (
      [
        "facebook_token_expired_reconnect",
        "facebook_permission_required",
      ].includes(error.code)
    ) {
      await pool.query(
        "UPDATE facebook_lead_connections SET status='attention',error_code=$2 WHERE company_id=$1 AND token=$3",
        [job.company_id, error.code, credential?.token || null],
      );
      await pool.query(
        "UPDATE facebook_lead_pages SET retrieval='unavailable',error_code=$3 WHERE company_id=$1 AND page_id=(SELECT f.page_id FROM facebook_lead_forms f WHERE f.company_id=$1 AND f.form_id=$2) AND EXISTS(SELECT 1 FROM facebook_lead_connections c WHERE c.company_id=$1 AND c.token=$4)",
        [job.company_id, job.form_id, error.code, credential?.token || null],
      );
    }
  }
  async function processJob(job) {
    const credential = await one(
      pool,
      "SELECT token,unified FROM facebook_lead_connections WHERE company_id=$1",
      [job.company_id],
    );
    try {
      const initial = await store.form(pool, job.company_id, job.form_id);
      const fetched = await graph.lead(job.lead_id, store.pageToken(initial));
      if (
        String(fetched.lead.id) !== job.lead_id ||
        String(fetched.lead.form_id) !== job.form_id
      )
        fail("lead_form_mismatch", 403);
      await transaction(pool, async (db) => {
        // Serialize matching within a company and serialize config updates/disconnect.
        const s = await store.settings(db, job.company_id, true);
        const c = await one(
          db,
          "SELECT * FROM facebook_lead_connections WHERE company_id=$1 FOR UPDATE",
          [job.company_id],
        );
        const current = await one(
          db,
          "SELECT * FROM facebook_lead_jobs WHERE id=$1 AND company_id=$2 AND lease=$3 FOR UPDATE",
          [job.id, job.company_id, job.lease],
        );
        if (!current || current.status !== "processing") return;
        const f = await store.form(db, job.company_id, job.form_id);
        if (
          !c?.token ||
          c.importing_paused ||
          (c.expires_at && new Date(c.expires_at) <= new Date()) ||
          (c.unified &&
            (c.status !== "authorized" ||
              !c.permissions.includes("leads_retrieval"))) ||
          !f.token ||
          !f.selected ||
          !f.enabled ||
          !f.mapping_ready
        ) {
          await db.query(
            "UPDATE facebook_lead_jobs SET status='pending',lease=NULL,lease_until=NULL,attempts=GREATEST(0,attempts-1) WHERE id=$1",
            [job.id],
          );
          return;
        }
        const mapped = mapLead(fetched.lead, f, s.configuration);
        const known = new Map(f.sources.map((s) => [s.key, s]));
        for (const d of mapped.discovered)
          if (!known.has(d.key)) known.set(d.key, d);
        await db.query(
          "UPDATE facebook_lead_forms SET sources=$3::jsonb,revision=revision+CASE WHEN sources<>$3::jsonb THEN 1 ELSE 0 END WHERE company_id=$1 AND form_id=$2",
          [job.company_id, job.form_id, JSON.stringify([...known.values()])],
        );
        if (mapped.issues.some((issue) => issue.code === "facebook_form_field_mapping_required")) {
          await db.query(
            "UPDATE facebook_lead_forms SET mapping_ready=false,error_code='facebook_form_field_mapping_required' WHERE company_id=$1 AND form_id=$2",
            [job.company_id, job.form_id],
          );
          await db.query(
            "UPDATE facebook_lead_jobs SET status='review',error_code='facebook_form_field_mapping_required',lease=NULL,lease_until=NULL,updated_at=now() WHERE id=$1",
            [job.id],
          );
          return;
        }
        let targetStage = null;
        if (f.destination?.stage_id) {
          targetStage = await one(db,
            `SELECT s.id,s.pipeline_id FROM stages s
             WHERE s.id=$1 AND (s.company_id=$2 OR (s.company_id IS NULL AND s.user_id=$3))`,
            [f.destination.stage_id, job.company_id, c.user_id]);
          if (!targetStage) fail("facebook_lead_stage_unavailable", 409);
        }
        const prior = (
          await db.query(
            "SELECT * FROM contacts WHERE company_id=$1 AND external_lead_id=$2 AND (source_raw IN ('facebook_zapier','facebook_direct') OR source IN ('facebook_zapier','facebook_direct')) ORDER BY id LIMIT 2",
            [job.company_id, job.lead_id],
          )
        ).rows;
        if (prior.length === 1) {
          await finish(db, job, prior[0].id, "already_imported", [], fetched.lead);
          return;
        }
        const matches =
          prior.length > 1
            ? prior
            : await findMatches(db, job.company_id, mapped.contact, true);
        if (matches.length > 1) {
          await db.query(
            "UPDATE facebook_lead_jobs SET status='review',error_code='contact_matches_conflict',lease=NULL,lease_until=NULL,updated_at=now() WHERE id=$1",
            [job.id],
          );
          return;
        }
        let existing = matches[0];
        if (existing)
          existing = await one(
            db,
            "SELECT * FROM contacts WHERE company_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE",
            [job.company_id, existing.id],
          );
        const contact = mergeContact(
            existing,
            mapped,
            s.configuration,
            job.lead_id,
          ),
          id = existing?.id || randomUUID();
        const leadSource = existing?.lead_source_id
          ? null
          : await ensureLeadSource(db, job.company_id, existing?.source || "facebook_direct");
        if (existing) {
          await db.query(
            `UPDATE contacts SET name=$3,email=$4,phone=$5,address=$6,job_type=$7,source=$8,lead_submitted_at=$9,lead_info=$10::jsonb,value_cents=$11,lat=$12,lng=$13,tags=$14,lead_source_id=COALESCE(lead_source_id,$15),source_raw=COALESCE(source_raw,source),updated_at=now() WHERE company_id=$1 AND id=$2`,
            [
              job.company_id,
              id,
              contact.name,
              contact.email || null,
              contact.phone || null,
              contact.address || null,
              contact.job_type || null,
              existing.lead_source_id ? existing.source : (leadSource?.name || contact.source || existing.source),
              contact.lead_submitted_at || null,
              JSON.stringify(contact.lead_info),
              contact.value_cents ?? null,
              contact.lat ?? null,
              contact.lng ?? null,
              contact.tags ?? [],
              leadSource?.id || null,
            ],
          );
        } else {
          await db.query(
            `INSERT INTO contacts(id,user_id,company_id,name,email,phone,address,job_type,source,lead_submitted_at,lead_info,external_lead_id,lead_form_id,lead_page_id,tags,value_cents,lat,lng,lead_source_id,source_raw) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
            [
              id,
              c.user_id,
              job.company_id,
              contact.name,
              contact.email || null,
              contact.phone || null,
              contact.address || null,
              contact.job_type || null,
              leadSource?.name || "Facebook Lead",
              contact.lead_submitted_at || null,
              JSON.stringify(contact.lead_info),
              job.lead_id,
              job.form_id,
              job.page_id,
              contact.tags ?? ["lead", "facebook"],
              contact.value_cents ?? null,
              contact.lat ?? null,
              contact.lng ?? null,
              leadSource?.id || null,
              "facebook_direct",
            ],
          );
        }
        if (targetStage) {
          const priorOpportunity = await one(db,
            `SELECT id FROM opportunities WHERE contact_id=$1 AND
             (company_id=$2 OR (company_id IS NULL AND user_id=$3))
             ORDER BY updated_at DESC LIMIT 1 FOR UPDATE`,
            [id, job.company_id, c.user_id]);
          if (!priorOpportunity) {
            const opportunityID = randomUUID();
            await db.query(
              `INSERT INTO opportunities(id,user_id,company_id,contact_id,state,stage_id,pipeline_id)
               VALUES($1,$2,$3,$4,'stage',$5,$6)`,
              [opportunityID, c.user_id, job.company_id, id, targetStage.id, targetStage.pipeline_id],
            );
            for (const eventType of ["pipeline.opportunity_created", "pipeline.stage_entered"])
              await emitAutomationEvent({
                companyId: job.company_id,
                eventType,
                subjectType: "opportunity",
                subjectId: opportunityID,
                actorUserId: c.user_id,
                source: "facebook_direct",
                dedupeKey: `${eventType}:facebook_direct:${job.lead_id}`,
                payload: { opportunity_id: opportunityID, contact_id: id, stage_id: targetStage.id, source: "facebook_direct" },
              }, { db });
          }
        }
        // Use existing event writer against this transaction. Payload is identifiers only.
        for (const eventType of [
          existing ? "contact.updated" : "contact.created",
          ...(existing ? [] : ["lead.created"]),
          "lead.received_external",
          "lead.received_webhook",
          "lead.received_meta",
          "lead.external_form_received",
        ]) {
          await emitAutomationEvent(
            {
              companyId: job.company_id,
              eventType,
              subjectType: "contact",
              subjectId: id,
              actorUserId: c.user_id,
              source: "facebook_direct",
              dedupeKey: `${eventType}:facebook_direct:${job.lead_id}`,
              payload: {
                contact_id: id,
                source: "facebook_direct",
                external_lead_id: job.lead_id,
                form_id: job.form_id,
                page_id: job.page_id,
              },
            },
            { db },
          );
        }
        const pref = await one(
          db,
          "SELECT notifications_enabled FROM zapier_tokens WHERE user_id=$1",
          [c.user_id],
        );
        if (pref?.notifications_enabled)
          await db.query(
            `INSERT INTO lead_notifications(id,user_id,company_id,contact_id,title,body) VALUES($1,$2,$3,$4,'New Facebook lead','Open the contact to review the imported lead.') ON CONFLICT(id) DO NOTHING`,
            [job.id, c.user_id, job.company_id, id],
          );
        await finish(db, job, id, existing ? "matched" : "created", [
          ...mapped.issues,
          ...fetched.issues,
        ], fetched.lead);
        await db.query(
          "INSERT INTO facebook_lead_outbox(job_id) VALUES($1) ON CONFLICT DO NOTHING",
          [job.id],
        );
      });
    } catch (e) {
      await failed("facebook_lead_jobs", job, e, credential);
    }
  }
  async function finish(db, job, contactID, outcome, issues, lead) {
    const metaID = (value) => /^\d{1,100}$/.test(String(value || "")) ? String(value) : null;
    await db.query(
      "UPDATE facebook_lead_jobs SET status='succeeded',contact_id=$2,outcome=$3,issues=$4::jsonb,campaign_id=$5,adset_id=$6,ad_id=$7,error_code=NULL,lease=NULL,lease_until=NULL,updated_at=now() WHERE id=$1",
      [job.id, contactID, outcome, JSON.stringify(issues), metaID(lead?.campaign_id), metaID(lead?.adset_id), metaID(lead?.ad_id)],
    );
    await db.query(
      "UPDATE facebook_lead_forms SET last_success_at=now(),error_code=NULL WHERE company_id=$1 AND form_id=$2",
      [job.company_id, job.form_id],
    );
  }
  async function processScan(job) {
    const credential = await one(
      pool,
      "SELECT token,unified FROM facebook_lead_connections WHERE company_id=$1",
      [job.company_id],
    );
    try {
      const f = await store.form(pool, job.company_id, job.form_id),
        result = await graph.leads(
          job.form_id,
          store.pageToken(f),
          { from: job.from_time, to: job.to_time },
          job.cursor,
        );
      if (result.cursor && result.cursor === job.cursor)
        fail("facebook_pagination_stalled", 502);
      await transaction(pool, async (db) => {
        await store.settings(db, job.company_id, true);
        const current = await one(
          db,
          "SELECT * FROM facebook_lead_scans WHERE id=$1 AND lease=$2 FOR UPDATE",
          [job.id, job.lease],
        );
        if (!current || current.status !== "processing") return;
        const c = await one(
          db,
          "SELECT * FROM facebook_lead_connections WHERE company_id=$1 FOR UPDATE",
          [job.company_id],
        );
        if (
          !c?.token ||
          c.importing_paused ||
          (c.expires_at && new Date(c.expires_at) <= new Date()) ||
          (c.unified &&
            (c.status !== "authorized" ||
              !c.permissions.includes("leads_retrieval")))
        ) {
          await db.query(
            "UPDATE facebook_lead_scans SET status='pending',lease=NULL,lease_until=NULL,attempts=GREATEST(0,attempts-1) WHERE id=$1",
            [job.id],
          );
          return;
        }
        const active = await store.form(db, job.company_id, job.form_id);
        if (!active.routed || !active.selected || !active.token) {
          await db.query(
            "UPDATE facebook_lead_scans SET status='canceled',lease=NULL,lease_until=NULL WHERE id=$1",
            [job.id],
          );
          return;
        }
        if (!job.preview && !active.mapping_ready) {
          await db.query(
            "UPDATE facebook_lead_scans SET status='pending',lease=NULL,lease_until=NULL,attempts=GREATEST(0,attempts-1) WHERE id=$1",
            [job.id],
          );
          return;
        }
        // No lead answers are fetched or cached by a scan, even in count preview mode.
        const ids = result.data.filter(
          (r) =>
            Number.isFinite(Date.parse(r.created_time)) &&
            new Date(r.created_time) >= new Date(job.from_time) &&
            new Date(r.created_time) < new Date(job.to_time),
        );
        let queued = job.preview ? ids.length : 0;
        if (!job.preview)
          for (const lead of ids)
            queued += (
              await store.enqueue(
                db,
                job.company_id,
                f.page_id,
                job.form_id,
                String(lead.id),
              )
            ).rowCount;
        await db.query(
          "UPDATE facebook_lead_scans SET status=$3,cursor=$4,queued=queued+$5,attempts=0,error_code=NULL,lease=NULL,lease_until=NULL WHERE id=$1 AND lease=$2",
          [
            job.id,
            job.lease,
            result.cursor ? "pending" : "succeeded",
            result.cursor,
            queued,
          ],
        );
      });
    } catch (e) {
      await failed("facebook_lead_scans", job, e, credential);
    }
  }
  async function recover() {
    // Fixed overlapping windows, persisted cursors. No unbounded initial historical import.
    await transaction(pool, async (db) => {
      const forms = (
        await db.query(
          "SELECT f.* FROM facebook_lead_forms f JOIN facebook_lead_pages p USING(company_id,page_id) JOIN facebook_lead_connections c ON c.company_id=f.company_id WHERE NOT c.importing_paused AND c.token IS NOT NULL AND (c.expires_at IS NULL OR c.expires_at>now()) AND (NOT c.unified OR (c.status='authorized' AND c.permissions ? 'leads_retrieval')) AND f.enabled AND f.mapping_ready AND f.routed AND p.selected AND p.token IS NOT NULL AND f.recovery_at<now()-interval '15 minutes' ORDER BY f.recovery_at FOR UPDATE OF f SKIP LOCKED LIMIT 10",
        )
      ).rows;
      for (const f of forms) {
        await db.query(
          `INSERT INTO facebook_lead_scans(company_id,form_id,from_time,to_time) SELECT company_id,form_id,GREATEST(recovery_at-interval '1 hour',import_since,now()-interval '90 days'),now() FROM facebook_lead_forms WHERE company_id=$1 AND form_id=$2 ON CONFLICT DO NOTHING`,
          [f.company_id, f.form_id],
        );
        // Advance only if an active scan covers this checkpoint. Otherwise retry next tick.
        await db.query(
          `UPDATE facebook_lead_forms SET recovery_at=(SELECT max(to_time) FROM facebook_lead_scans WHERE company_id=$1 AND form_id=$2 AND NOT preview) WHERE company_id=$1 AND form_id=$2`,
          [f.company_id, f.form_id],
        );
      }
    });
  }
  async function outbox() {
    await transaction(pool, async (db) => {
      const rows = (
        await db.query(
          `SELECT o.*,j.company_id,j.contact_id,j.lead_id,c.user_id FROM facebook_lead_outbox o JOIN facebook_lead_jobs j ON j.id=o.job_id JOIN facebook_lead_connections c ON c.company_id=j.company_id WHERE o.delivered_at IS NULL AND c.token IS NOT NULL FOR UPDATE OF o SKIP LOCKED LIMIT 10`,
        )
      ).rows;
      for (const row of rows) {
        await markContactDirty(
          row.company_id,
          row.contact_id,
          "facebook_lead.imported",
        );
        // The durable inbox row is authoritative; APNs is at-most-once to prevent retry spam.
        await db.query(
          "UPDATE facebook_lead_outbox SET delivered_at=now() WHERE job_id=$1",
          [row.job_id],
        );
      }
    });
    const rows = (
      await pool.query(
        `UPDATE facebook_lead_outbox o SET push_attempted_at=now() FROM facebook_lead_jobs j,facebook_lead_connections c,lead_notifications n WHERE o.job_id=j.id AND c.company_id=j.company_id AND c.token IS NOT NULL AND n.id=j.id AND o.delivered_at IS NOT NULL AND o.push_attempted_at IS NULL RETURNING j.contact_id,j.company_id,j.lead_id,c.user_id`,
      )
    ).rows;
    for (const row of rows)
      try {
        await sendPushToUsers([row.user_id], "new_lead", {
          title: "New Facebook lead",
          body: "Open the contact to review the imported lead.",
          contactId: row.contact_id,
          threadId: `facebook_lead_${row.lead_id}`,
          inboxDelivery: true,
          payload: {
            type: "new_lead",
            contact_id: row.contact_id,
            source: "facebook_direct",
          },
        });
      } catch {
        /* Durable inbox remains available; do not repeat a possibly delivered push. */
      }
  }
  async function tick() {
    // Exhausted leases are visible failures rather than stuck processing forever.
    for (const table of ["facebook_lead_jobs", "facebook_lead_scans"])
      await pool.query(
        `UPDATE ${table} SET status='failed',error_code='facebook_retry_limit_reached',lease=NULL,lease_until=NULL WHERE attempts>=8 AND status='processing' AND lease_until<now()`,
      );
    await recover();
    const scan = await claim("facebook_lead_scans");
    if (scan) await processScan(scan);
    for (let i = 0; i < 5; i++) {
      const job = await claim("facebook_lead_jobs");
      if (!job) break;
      await processJob(job);
    }
    await outbox();
    // Probe only one overdue company's status per tick.
    const c = await one(
      pool,
      "SELECT company_id FROM facebook_lead_connections WHERE token IS NOT NULL AND (checked_at IS NULL OR checked_at<now()-interval '6 hours') ORDER BY checked_at NULLS FIRST LIMIT 1",
      [],
    );
    if (c)
      try {
        await store.refresh(c.company_id);
      } catch {
        /* refresh persists a sanitized actionable status. */
      }
  }
  return { claim, processJob, processScan, recover, outbox, tick };
}
