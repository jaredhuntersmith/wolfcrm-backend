import { randomUUID } from "node:crypto";
import { QuoteContractError, quoteInteger } from "./quote-contract-domain.js";

export const AGREEMENT_FOLLOWUP_RULES = Object.freeze([
  { key: "unopened", label: "No observed opening", delay_minutes: 1440 },
  { key: "opened_unsigned", label: "Opened but not signed", delay_minutes: 1440 },
  { key: "signing_incomplete", label: "Signing started but not submitted", delay_minutes: 120 },
  { key: "deposit_outstanding", label: "Signed but deposit outstanding", delay_minutes: 120 },
  { key: "booking_pending", label: "Eligible for booking but not booked", delay_minutes: 1440 },
  { key: "documents_failed", label: "Document processing needs attention", delay_minutes: 30 },
  { key: "plan_setup_pending", label: "Plan signed but setup or initial payment incomplete", delay_minutes: 120 },
  { key: "plan_service_due", label: "Plan service due without an appointment", delay_minutes: 1440 },
  { key: "payment_processing", label: "Payment processing needs review", delay_minutes: 60 },
  { key: "balance_overdue", label: "Balance overdue under the quoted due terms", delay_minutes: 60 },
  { key: "plan_payment_attention", label: "Plan payment failed, requires action, or needs review", delay_minutes: 30 },
]);
export const AGREEMENT_IMMEDIATE_EVENTS=Object.freeze([
  {key:'signature_submitted',label:'A signer submitted'}, {key:'signing_completed',label:'All required signers completed'},
  {key:'base_workflow_completed',label:'Signing and required deposit complete'},
  {key:'deposit_received',label:'Required deposit received'}, {key:'balance_received',label:'Remaining balance received'},
  {key:'payment_succeeded',label:'Other payment received'}, {key:'payment_failed',label:'Payment failed or needs action'}, {key:'payment_disputed',label:'Payment disputed'},
  {key:'booking_created',label:'Appointment booked'}, {key:'booking_rescheduled',label:'Appointment rescheduled'}, {key:'booking_canceled',label:'Appointment canceled'},
  {key:'plan_activated',label:'Plan enrollment activated'}, {key:'plan_pause',label:'Plan paused'}, {key:'plan_resume',label:'Plan resumed'}, {key:'plan_cancel',label:'Plan cancellation requested'},
  {key:'plan_payment_succeeded',label:'Plan payment received'}, {key:'plan_payment_review_required',label:'Plan payment requires staff review'}, {key:'plan_payment_failed',label:'Plan payment failed or needs authentication'},
  {key:'changes_requested',label:'Customer requested changes'}, {key:'declined',label:'Estimate declined'}, {key:'expired',label:'Unsigned estimate expired'},
]);
const immediateTypes = new Set(AGREEMENT_IMMEDIATE_EVENTS.map(event=>event.key));
const fail = (message) => { throw new QuoteContractError("agreement_notification_rule_invalid", message); };

export function normalizeAgreementNotificationRules(raw = {}) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) fail("Notification preferences must be an object.");
  const input = raw.rules ?? [];
  if (!Array.isArray(input) || input.length > AGREEMENT_FOLLOWUP_RULES.length) fail("Choose supported agreement follow-up rules.");
  const known = new Set(AGREEMENT_FOLLOWUP_RULES.map((rule) => rule.key));
  if (input.some((rule) => !rule || typeof rule !== "object" || !known.has(rule.key)) || new Set(input.map((rule) => rule.key)).size !== input.length) fail("Each follow-up rule must be unique and supported.");
  const boolean = (value, fallback) => { if (value !== undefined && typeof value !== "boolean") fail("Notification controls must be true or false."); return value ?? fallback; };
  const events=raw.events??[];
  if(!Array.isArray(events)||events.length>AGREEMENT_IMMEDIATE_EVENTS.length||events.some(event=>!event||!immediateTypes.has(event.key))||new Set(events.map(event=>event.key)).size!==events.length)fail('Choose unique supported notification events.');
  const override=value=>{if(value!=null&&typeof value!=='boolean')fail('Event controls must inherit or be true or false.');return value??null;};
  return {
    immediate_dashboard: boolean(raw.immediate_dashboard, true), immediate_push: boolean(raw.immediate_push, false),
    events:AGREEMENT_IMMEDIATE_EVENTS.map(definition=>{const setting=events.find(event=>event.key===definition.key)||{};return {...definition,dashboard:override(setting.dashboard),push:override(setting.push)};}),
    rules: AGREEMENT_FOLLOWUP_RULES.map((definition) => {
      const override = input.find((rule) => rule.key === definition.key) || {};
      return { ...definition, enabled: boolean(override.enabled, true), dashboard: boolean(override.dashboard, true), push: boolean(override.push, false), delay_minutes: quoteInteger(override.delay_minutes ?? definition.delay_minutes, "Follow-up delay", 43200, 1) };
    }),
  };
}

export function agreementFollowupConditions({ agreement, state, first_events = {}, document_failed_at = null, extra = {}, now = new Date() }) {
  const stopped = ["declined", "expired", "superseded", "revoked"].includes(state.decision);
  const unsigned = state.signing !== "submitted";
  return {
    unopened: !stopped && unsigned && !first_events.observed_open ? agreement.created_at : null,
    opened_unsigned: !stopped && unsigned ? first_events.observed_open || null : null,
    signing_incomplete: !stopped && unsigned ? first_events.signing_started || first_events.draft_progress || null : null,
    deposit_outstanding: !stopped && state.deposit === "outstanding" ? agreement.signed_at : null,
    booking_pending: !stopped && state.booking === "eligible" ? first_events.booking_eligible || null : null,
    documents_failed: document_failed_at && new Date(document_failed_at) <= now ? document_failed_at : null,
    plan_setup_pending: extra.plan_setup_pending || null,
    plan_service_due: extra.plan_service_due || null,
    payment_processing: extra.payment_processing || null,
    balance_overdue: extra.balance_overdue || null,
    plan_payment_attention: extra.plan_payment_attention || null,
  };
}

export async function installAgreementNotificationSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS agreement_notification_rules (
      company_id UUID PRIMARY KEY REFERENCES companies(id) ON DELETE RESTRICT,
      configuration JSONB NOT NULL, version INTEGER NOT NULL DEFAULT 1, updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    ALTER TABLE quote_agreements ADD COLUMN IF NOT EXISTS next_followup_at TIMESTAMPTZ NOT NULL DEFAULT now();
    CREATE INDEX IF NOT EXISTS quote_agreements_followup_idx ON quote_agreements(next_followup_at,id);
    CREATE INDEX IF NOT EXISTS agreement_predecessor_idx ON quote_agreements(predecessor_id);
    CREATE INDEX IF NOT EXISTS business_exceptions_agreement_idx ON business_exceptions(company_id,(metadata->>'agreement_id'),created_at);
    ALTER TABLE agreement_events ADD COLUMN IF NOT EXISTS automation_delivered_at TIMESTAMPTZ;
    ALTER TABLE agreement_events ADD COLUMN IF NOT EXISTS automation_next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now();
    ALTER TABLE agreement_events ADD COLUMN IF NOT EXISTS notification_queued_at TIMESTAMPTZ;
    CREATE TABLE IF NOT EXISTS agreement_notification_deliveries (
      id UUID PRIMARY KEY, event_id UUID NOT NULL REFERENCES agreement_events(id) ON DELETE RESTRICT,
      user_id UUID NOT NULL, notification_id UUID, push_requested BOOLEAN NOT NULL DEFAULT false,
      push_state TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
      next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(), last_error TEXT, delivered_at TIMESTAMPTZ,
      UNIQUE(event_id,user_id)
    );
  `);
}

async function transaction(pool, work) {
  const db = await pool.connect();
  try { await db.query("BEGIN"); const result = await work(db); await db.query("COMMIT"); return result; }
  catch (error) { await db.query("ROLLBACK"); throw error; }
  finally { db.release(); }
}

export function createAgreementNotifications({ pool, service, emitAutomationEvent = async () => null, sendPushToUsers = async () => ({ skipped: true, reason: "not_configured" }) }) {
  async function settings(db, companyId) {
    const row = (await db.query(`SELECT * FROM agreement_notification_rules WHERE company_id=$1`, [companyId])).rows[0];
    return { ...normalizeAgreementNotificationRules(row?.configuration), version: row?.version || 0 };
  }
  async function evaluate(limit = 100, now = new Date()) {
    let count = 0;
    for (let index = 0; index < limit; index++) {
      const worked = await transaction(pool, async (db) => {
        const row = (await db.query(`SELECT * FROM quote_agreements WHERE next_followup_at<=$1 ORDER BY next_followup_at,id FOR UPDATE SKIP LOCKED LIMIT 1`, [now])).rows[0];
        if (!row) return false;
        const preferences = await settings(db, row.company_id);
        const state = await service.state(db, row);
        let timestamps = (await db.query(`SELECT type,min(created_at) AS first_at FROM agreement_events WHERE agreement_id=$1 GROUP BY type`, [row.id])).rows;
        let first = Object.fromEntries(timestamps.map((entry) => [entry.type, entry.first_at]));
        if (state.booking === "eligible" && !first.booking_eligible) {
          await service.event(db, row.id, "booking_eligible");
          first.booking_eligible = now;
        }
        if (state.decision === "expired" && !first.expired) await service.event(db, row.id, "expired");
        if (state.base_workflow_complete && !first.base_workflow_completed) await service.event(db, row.id, "base_workflow_completed", { payload: { signatures_complete: true, required_deposit_confirmed: true } });
        const failed = (await db.query(`SELECT min(run_at) AS failed_at FROM agreement_jobs WHERE agreement_id=$1 AND state='failed'`, [row.id])).rows[0].failed_at;
        const extra = service.planFollowupContext ? await service.planFollowupContext(db,row) : {};
        if(service.planBillingFollowupContext)Object.assign(extra,await service.planBillingFollowupContext(db,row));
        if (service.paymentSummary) { const pending=(await db.query(`SELECT id,created_at FROM agreement_payment_attempts WHERE company_id=$1 AND agreement_id=$2 AND state IN ('creating','processing') ORDER BY created_at LIMIT 1`,[row.company_id,row.id])).rows[0];extra.payment_processing=pending?.created_at;extra.payment_processing_occurrence=pending?.id; }
        if(service.paymentSummary && row.snapshot.balance_due_days_after_service!=null && state.signing==='submitted'){
          const payment=await service.paymentSummary(db,row);
          if(payment?.balance_cents>0&&!payment.processing&&!payment.payment_review_required){
            const completed=(await db.query('SELECT count(*)>0 AND bool_and(finished_at IS NOT NULL) AS all_done,max(finished_at) AS finished FROM schedule_events WHERE company_id=$1 AND quote_id=$2',[row.company_id,row.quote_id])).rows[0];
            if(completed.all_done)extra.balance_overdue=new Date(new Date(completed.finished).getTime()+row.snapshot.balance_due_days_after_service*86400000);
          }
        }
        const conditions = agreementFollowupConditions({ agreement: row, state, first_events: first, document_failed_at: failed, extra, now });
        for (const rule of preferences.rules) {
          const prefix = `${row.id}:${rule.key}`;
          const sourceId = extra[`${rule.key}_occurrence`] ? `${prefix}:${extra[`${rule.key}_occurrence`]}` : prefix;
          const type = `agreement_${rule.key}`;
          const origin = conditions[rule.key];
          const due = origin ? new Date(new Date(origin).getTime() + rule.delay_minutes * 60000) : null;
          const actionable = rule.enabled && origin && due <= now;
          await db.query(`UPDATE business_exceptions SET status='resolved',resolved_at=$4,resolution_source='automatic',snoozed_until=NULL,status_updated_at=$4,updated_at=$4 WHERE company_id=$1 AND type=$2 AND source_type='agreement' AND source_id LIKE $3 AND source_id<>$5 AND status IN ('open','snoozed')`,[row.company_id,type,`${prefix}%`,now,sourceId]);
          if (!actionable || !rule.dashboard) {
            await db.query(`UPDATE business_exceptions SET status='resolved',resolved_at=$4,resolution_source='automatic',snoozed_until=NULL,status_updated_at=$4,updated_at=$4 WHERE company_id=$1 AND type=$2 AND source_type='agreement' AND source_id=$3 AND status IN ('open','snoozed')`, [row.company_id, type, sourceId, now]);
            if(!actionable)continue;
          }
          if (rule.dashboard) {
            const inserted = await db.query(`INSERT INTO business_exceptions(company_id,type,severity,source_type,source_id,fingerprint,title,explanation,recommended_action,destination,metadata,due_at)
              VALUES($1,$2,'medium','agreement',$3,$3,$4,$5,'Open the agreement and review the outstanding step.',$6::jsonb,$7::jsonb,$8)
              ON CONFLICT(company_id,type,source_type,source_id) DO NOTHING RETURNING id`, [row.company_id, type, sourceId, `${rule.label}: ${row.title} #${row.number}`, "The configured follow-up delay has elapsed. Completed signatures and payments remain preserved.", JSON.stringify({ type: "agreement", id: row.id, contact_id: row.contact_id }), JSON.stringify({ agreement_id: row.id, revision: row.revision, rule: rule.key }), due]);
            if (inserted.rowCount) await service.event(db, row.id, "followup_due", { payload: { rule: rule.key, occurrence:sourceId, push: rule.push, exception_id: inserted.rows[0].id } });
          } else if (rule.push && !(await db.query("SELECT 1 FROM agreement_events WHERE agreement_id=$1 AND type=$2 AND COALESCE(payload->>'occurrence',$3)=$4 LIMIT 1",[row.id,`followup_${rule.key}`,prefix,sourceId])).rowCount) {
            await service.event(db, row.id, `followup_${rule.key}`, { payload: { rule: rule.key, occurrence:sourceId, push: true } });
          }
        }
        await db.query(`UPDATE quote_agreements SET next_followup_at=$2 WHERE id=$1`, [row.id, new Date(now.getTime() + 60000)]);
        return true;
      });
      if (!worked) break;
      count++;
    }
    return count;
  }
  async function deliverEvents(limit = 100) {
    const rows = (await pool.query(`SELECT e.*,a.company_id,a.contact_id,a.number FROM agreement_events e JOIN quote_agreements a ON a.id=e.agreement_id WHERE (e.automation_delivered_at IS NULL AND e.automation_next_attempt_at<=now()) OR e.notification_queued_at IS NULL ORDER BY e.created_at,e.id LIMIT $1`, [limit])).rows;
    for (const event of rows) {
      if (!event.automation_delivered_at) {
        let result;
        try { result = await emitAutomationEvent({ companyId: event.company_id, eventType: `agreement.${event.type}`, subjectType: "agreement", subjectId: event.agreement_id, actorUserId: event.actor_type === "staff" ? event.actor_id : null, source: "agreements.outbox", dedupeKey: `agreement:${event.id}`, occurredAt: event.created_at, payload: { agreement_id: event.agreement_id, contact_id: event.contact_id, event_id: event.id, event_type: event.type } }); } catch { /* Retry durably without blocking dashboard delivery. */ }
        await pool.query(`UPDATE agreement_events SET automation_delivered_at=CASE WHEN $2 THEN now() ELSE automation_delivered_at END,automation_next_attempt_at=now()+interval '5 minutes' WHERE id=$1`, [event.id, !!result]);
      }
      if (event.notification_queued_at) continue;
      await transaction(pool, async (db) => {
        const locked = (await db.query(`SELECT notification_queued_at FROM agreement_events WHERE id=$1 FOR UPDATE`, [event.id])).rows[0];
        if (locked.notification_queued_at) return;
        const preferences = await settings(db, event.company_id);
        const preferenceKey=event.type==='payment_succeeded'&&['deposit','balance'].includes(event.payload.kind)?`${event.payload.kind}_received`:event.type;
        const immediate = immediateTypes.has(preferenceKey), followup = event.type.startsWith("followup_");
        const override=preferences.events.find(item=>item.key===preferenceKey);
        const dashboard=immediate&&(override?.dashboard??preferences.immediate_dashboard);
        const push = immediate ? override?.push??preferences.immediate_push : followup && event.payload.push === true;
        if (dashboard || push) {
          // Existing employer recipients and their normal push preference filter
          // are reused; operational customer content is omitted from lock screens.
          const users = (await db.query(`SELECT id FROM users WHERE company_id=$1 AND deleted_at IS NULL AND role='employer'`, [event.company_id])).rows;
          for (const user of users) {
            const notificationId = dashboard ? randomUUID() : null;
            const inserted = await db.query(`INSERT INTO agreement_notification_deliveries(id,event_id,user_id,notification_id,push_requested,push_state) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(event_id,user_id) DO NOTHING RETURNING id`, [randomUUID(), event.id, user.id, notificationId, push, push ? "pending" : "not_requested"]);
            if (inserted.rowCount && notificationId) await db.query(`INSERT INTO lead_notifications(id,user_id,company_id,contact_id,title,body) VALUES($1,$2,$3,$4,'Agreement update',$5)`, [notificationId, user.id, event.company_id, event.contact_id, `Estimate #${event.number}: ${event.type.replaceAll("_", " ")}. Open Agreements for details.`]);
          }
        }
        await db.query(`UPDATE agreement_events SET notification_queued_at=now() WHERE id=$1`, [event.id]);
      });
    }
    for (let index = 0; index < limit; index++) {
      const worked = await transaction(pool, async (db) => {
        const delivery = (await db.query(`SELECT d.*,e.agreement_id,a.contact_id FROM agreement_notification_deliveries d JOIN agreement_events e ON e.id=d.event_id JOIN quote_agreements a ON a.id=e.agreement_id WHERE d.push_requested AND d.push_state IN ('pending','retry') AND d.next_attempt_at<=now() ORDER BY d.next_attempt_at FOR UPDATE OF d SKIP LOCKED LIMIT 1`)).rows[0];
        if (!delivery) return false;
        let result;
        try { result = await sendPushToUsers([delivery.user_id], "agreements", { title: "Agreement update", body: "Open WolfCRM to review the latest agreement activity.", contactId: delivery.contact_id, payload: { type: "agreement", agreement_id: delivery.agreement_id, event_id: delivery.event_id }, threadId: `agreement:${delivery.agreement_id}`, collapseId: delivery.event_id }); }
        catch { result = { failed: 1 }; }
        const status = result.skipped ? "skipped" : result.failed ? delivery.attempts >= 7 ? "failed" : "retry" : "delivered";
        await db.query(`UPDATE agreement_notification_deliveries SET push_state=$2,attempts=attempts+1,last_error=$3,next_attempt_at=now()+interval '5 minutes',delivered_at=CASE WHEN $2='delivered' THEN now() ELSE NULL END WHERE id=$1`, [delivery.id, status, result.reason || (result.failed ? "push_delivery_failed" : null)]);
        return true;
      });
      if (!worked) break;
    }
    return rows.length;
  }
  return { settings, evaluate, deliverEvents };
}

export async function installAgreementNotifications({ app, pool, service, authRequired, requireCapability, emitAutomationEvent, sendPushToUsers, startWorker = true }) {
  await installAgreementNotificationSchema(pool);
  const notifications = createAgreementNotifications({ pool, service, emitAutomationEvent, sendPushToUsers });
  const wrap = (fn) => async (req, res) => {
    if (!req.companyId) return res.status(403).json({ error: "company_required" });
    try { await fn(req, res); }
    catch (error) { res.status(error instanceof QuoteContractError ? error.status : 500).json({ error: error.code || "agreement_notifications_failed", message: error instanceof QuoteContractError ? error.message : "The notification settings could not be updated." }); }
  };
  app.get("/api/agreements/notification-rules", authRequired, requireCapability("quotes.view"), wrap(async (req, res) => res.json(await notifications.settings(pool, req.companyId))));
  app.put("/api/agreements/notification-rules", authRequired, requireCapability("settings.manage_company"), wrap(async (req, res) => {
    const previous=await notifications.settings(pool,req.companyId);
    const configuration = normalizeAgreementNotificationRules({...req.body,events:req.body.events??previous.events});
    const row = (await pool.query(`INSERT INTO agreement_notification_rules(company_id,configuration) VALUES($1,$2::jsonb) ON CONFLICT(company_id) DO UPDATE SET configuration=EXCLUDED.configuration,version=agreement_notification_rules.version+1,updated_at=now() WHERE agreement_notification_rules.version=$3 RETURNING version`, [req.companyId, JSON.stringify(configuration), req.body.expected_version ?? 0])).rows[0];
    if (!row) throw new QuoteContractError("agreement_rules_changed", "Rules changed. Reload before saving.", 409);
    await pool.query(`UPDATE quote_agreements SET next_followup_at=now() WHERE company_id=$1`, [req.companyId]);
    res.json({ ...configuration, version: row.version });
  }));
  app.post("/api/agreements/:id/changes/:eventId/resolve", authRequired, requireCapability("quotes.edit"), wrap(async (req, res) => {
    await transaction(pool, async (db) => {
      const row = await service.loadStaff(db, req, req.params.id, true);
      const source = (await db.query(`SELECT id FROM agreement_events WHERE id::text=$1 AND agreement_id=$2 AND type='changes_requested'`, [req.params.eventId, row.id])).rows[0];
      if (!source) throw new QuoteContractError("agreement_change_missing", "This change request was not found.", 404);
      await db.query(`UPDATE business_exceptions SET status='resolved',resolved_at=now(),resolution_source='manual',status_updated_at=now(),status_updated_by=$3,updated_at=now() WHERE company_id=$1 AND source_type='agreement' AND source_id=$2 AND status<>'resolved'`, [row.company_id, source.id, req.userId]);
      if (!(await db.query(`SELECT 1 FROM agreement_events WHERE agreement_id=$1 AND type='change_request_addressed' AND payload->>'event_id'=$2`, [row.id, source.id])).rowCount) await service.event(db, row.id, "change_request_addressed", { actor_type: "staff", actor_id: req.userId, payload: { event_id: source.id } });
    });
    res.json({ resolved: true });
  }));
  let running = false, timer;
  const tick = async () => { if (running) return; running = true; try { await notifications.evaluate(); await notifications.deliverEvents(); } catch { console.error("[agreements] notification worker failed"); } finally { running = false; } };
  if (startWorker) { timer = setInterval(tick, 30000); timer.unref(); }
  return { ...notifications, stop: () => clearInterval(timer) };
}
