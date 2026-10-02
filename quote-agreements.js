import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { QuoteContractError, calculateQuotePricing, normalizeQuoteOptions, validateQuoteAddonScope, quoteText, quoteInteger, quoteContentHash, deriveAgreementState } from "./quote-contract-domain.js";
import { AGREEMENT_MERGE_FIELDS, resolveAgreementText, validateAndNormalizeAgreementPDF, normalizeAgreementFields, validateAgreementSignature, validateAgreementSubmission, generateQuoteAgreementPDF, populateAgreementPDF, agreementBytesHash, combineAgreementPDFs, qualifyAgreementDocumentLinks, validateAgreementSignerText } from "./quote-agreement-documents.js";
import { streamAgreementEvidence, agreementEvidenceMetadata } from "./agreement-evidence-export.js";
import { lockCompanySchedule } from "./schedule-booking-guard.js";
import { assertQuoteReferences, ServiceCatalogError } from "./services-catalog.js";
import { normalizeAgreementContent } from "./agreement-content.js";
export { normalizeAgreementContent } from "./agreement-content.js";
import { ensureDefaultQuoteTemplate, listQuoteTemplates, quoteTemplateTransaction, completeTemplateContent } from "./quote-templates.js";
import { createQuoteAddonSelection } from "./quote-addons.js";
import { installAgreementAuthoringSchema, installAgreementDraftRoutes, authoringRequest } from "./agreement-authoring.js";

const problem = (code, message, status = 400) => { throw new QuoteContractError(code, message, status); };
const digest = (text) => createHash("sha256").update(text).digest("hex");
const uuid = (value) => {
  if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) problem("agreement_id_invalid", "A valid record ID is required.");
  return value.toLowerCase();
};
const money = (cents) => new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(cents / 100);
const equal = (a, b) => typeof a === "string" && typeof b === "string" && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const safeJSON = (value) => JSON.stringify(value);
const packetCoverSnapshot = (snapshot) => snapshot.kind !== "quote" || snapshot.quote_position !== "excluded" ? snapshot : {
  ...snapshot, pricing: null, public_notes: "", scope_exclusions: "",
  agreement_text: `The accepted scope and price are preserved in the separately downloadable Quote #${snapshot.number}, revision ${snapshot.revision}. This scope attachment is part of this agreement and must be reviewed before signing. Scope integrity hash: ${snapshot.scope_reference_hash}.\n\n${snapshot.agreement_text || ""}`,
};

export async function installAgreementSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS agreement_settings (
      company_id UUID PRIMARY KEY REFERENCES companies(id) ON DELETE RESTRICT,
      content JSONB NOT NULL DEFAULT '{}'::jsonb,
      version INTEGER NOT NULL DEFAULT 1, updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS agreement_templates (
      template_id UUID NOT NULL, version INTEGER NOT NULL,
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
      name TEXT NOT NULL, content JSONB NOT NULL, archived_at TIMESTAMPTZ,
      created_by UUID, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY(template_id, version)
    );
    ALTER TABLE agreement_settings ADD COLUMN IF NOT EXISTS default_template_id UUID;
    ALTER TABLE quotes ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
    CREATE INDEX IF NOT EXISTS agreement_templates_company_idx ON agreement_templates(company_id, name, version DESC);
    CREATE TABLE IF NOT EXISTS agreement_assets (
      id UUID PRIMARY KEY, company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
      name TEXT NOT NULL, original_bytes BYTEA NOT NULL, normalized_bytes BYTEA NOT NULL,
      source_sha256 TEXT NOT NULL, normalized_sha256 TEXT NOT NULL, pages JSONB NOT NULL,
      created_by UUID, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      CHECK(octet_length(original_bytes) <= 10485760)
    );
    CREATE INDEX IF NOT EXISTS agreement_assets_company_idx ON agreement_assets(company_id,created_at DESC);
    CREATE TABLE IF NOT EXISTS agreement_number_sequences (
      company_id UUID PRIMARY KEY REFERENCES companies(id) ON DELETE RESTRICT, last_number BIGINT NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS quote_agreements (
      id UUID PRIMARY KEY, company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
      quote_id UUID REFERENCES quotes(id) ON DELETE RESTRICT, contact_id TEXT NOT NULL, created_by UUID NOT NULL,
      number TEXT NOT NULL, revision INTEGER NOT NULL,
      predecessor_id UUID REFERENCES quote_agreements(id) ON DELETE RESTRICT,
      request_id UUID NOT NULL, title TEXT NOT NULL, snapshot JSONB NOT NULL, packet_hash TEXT NOT NULL,
      decision TEXT NOT NULL DEFAULT 'published', token_generation INTEGER NOT NULL DEFAULT 1,
      revoked_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, signed_at TIMESTAMPTZ,
      documents_ready BOOLEAN NOT NULL DEFAULT false, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id,request_id), UNIQUE(company_id,number,revision)
    );
    CREATE INDEX IF NOT EXISTS quote_agreements_archive_idx ON quote_agreements(company_id,created_at DESC,id);
    CREATE INDEX IF NOT EXISTS quote_agreements_contact_idx ON quote_agreements(company_id,contact_id,created_at DESC);
    CREATE INDEX IF NOT EXISTS quote_agreements_quote_idx ON quote_agreements(quote_id,revision DESC);
    ALTER TABLE quote_agreements ADD COLUMN IF NOT EXISTS publication_request_hash TEXT;
    ALTER TABLE quote_agreements ADD COLUMN IF NOT EXISTS link_root_id UUID REFERENCES quote_agreements(id) ON DELETE RESTRICT;
    UPDATE quote_agreements SET link_root_id=id WHERE link_root_id IS NULL;
    UPDATE quote_agreements a SET link_root_id=a.id FROM quote_agreements root WHERE a.link_root_id=root.id AND a.id<>root.id AND (a.token_generation<>root.token_generation OR root.revoked_at IS NOT NULL);
    CREATE INDEX IF NOT EXISTS quote_agreements_link_root_idx ON quote_agreements(link_root_id);
    CREATE TABLE IF NOT EXISTS agreement_signing_sessions (
      id UUID PRIMARY KEY, agreement_id UUID NOT NULL REFERENCES quote_agreements(id) ON DELETE RESTRICT,
      role TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, token_generation INTEGER NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL, verification_method TEXT NOT NULL,
      draft_values JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS agreement_signatures (
      id UUID PRIMARY KEY, agreement_id UUID NOT NULL REFERENCES quote_agreements(id) ON DELETE RESTRICT,
      session_id UUID NOT NULL REFERENCES agreement_signing_sessions(id) ON DELETE RESTRICT,
      role TEXT NOT NULL, request_id UUID NOT NULL, request_hash TEXT NOT NULL,
      printed_name TEXT NOT NULL, consent_text TEXT NOT NULL, signature JSONB NOT NULL,
      field_values JSONB NOT NULL, packet_hash TEXT NOT NULL, verification_method TEXT NOT NULL,
      source_ip TEXT, user_agent TEXT, submitted_at TIMESTAMPTZ NOT NULL,
      UNIQUE(agreement_id,role), UNIQUE(agreement_id,request_id)
    );
    CREATE TABLE IF NOT EXISTS agreement_events (
      id UUID PRIMARY KEY, agreement_id UUID NOT NULL REFERENCES quote_agreements(id) ON DELETE RESTRICT,
      type TEXT NOT NULL, request_id UUID, request_hash TEXT, actor_type TEXT NOT NULL,
      actor_id TEXT, payload JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(agreement_id,request_id)
    );
    CREATE INDEX IF NOT EXISTS agreement_events_timeline_idx ON agreement_events(agreement_id,created_at,id);
    CREATE TABLE IF NOT EXISTS agreement_artifacts (
      id UUID PRIMARY KEY, agreement_id UUID NOT NULL REFERENCES quote_agreements(id) ON DELETE RESTRICT,
      kind TEXT NOT NULL, asset_id UUID, bytes BYTEA NOT NULL, sha256 TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE(agreement_id,kind)
    );
    CREATE TABLE IF NOT EXISTS agreement_artifact_deliveries (
      artifact_id UUID NOT NULL REFERENCES agreement_artifacts(id) ON DELETE RESTRICT,
      role TEXT NOT NULL CHECK(role IN ('customer','customer_2')), token_generation INTEGER NOT NULL,
      bytes BYTEA NOT NULL, sha256 TEXT NOT NULL, source_sha256 TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(artifact_id,role,token_generation)
    );
    CREATE TABLE IF NOT EXISTS agreement_jobs (
      id UUID PRIMARY KEY, agreement_id UUID NOT NULL REFERENCES quote_agreements(id) ON DELETE RESTRICT,
      kind TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
      run_at TIMESTAMPTZ NOT NULL DEFAULT now(), last_error TEXT, completed_at TIMESTAMPTZ,
      UNIQUE(agreement_id,kind)
    );
    CREATE INDEX IF NOT EXISTS agreement_jobs_due_idx ON agreement_jobs(run_at) WHERE state IN ('pending','retry');
    CREATE TABLE IF NOT EXISTS agreement_rate_windows (
      scope TEXT PRIMARY KEY, starts_at TIMESTAMPTZ NOT NULL, hits INTEGER NOT NULL
    );
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS agreement_id UUID;
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS quote_id UUID;
    ALTER TABLE schedule_events ADD COLUMN IF NOT EXISTS customer_note_entries JSONB NOT NULL DEFAULT '[]'::jsonb;
    CREATE INDEX IF NOT EXISTS payment_records_agreement_idx ON payment_records(company_id,agreement_id);
  `);
  await installAgreementAuthoringSchema(pool);
}


async function transaction(pool, work, { rollback = false } = {}) {
  const db = await pool.connect();
  try { await db.query("BEGIN"); const result = await work(db); await db.query(rollback ? "ROLLBACK" : "COMMIT"); return result; }
  catch (error) { await db.query("ROLLBACK"); throw error; }
  finally { db.release(); }
}

export function createAgreementService({ pool, getQuoteSettings, getStripe, env = process.env }) {
  const secret = () => {
    if (!env.QUOTE_LINK_SECRET || Buffer.byteLength(env.QUOTE_LINK_SECRET) < 32) problem("agreement_link_setup_required", "Configure the durable QUOTE_LINK_SECRET before publishing customer links.", 503);
    return env.QUOTE_LINK_SECRET;
  };
  const publicBase = () => {
    let url;
    try { url = new URL(env.QUOTE_PUBLIC_BASE_URL); } catch { problem("agreement_public_url_required", "Configure QUOTE_PUBLIC_BASE_URL for customer estimates.", 503); }
    if (url.protocol !== "https:" && !(env.NODE_ENV !== "production" && ["localhost", "127.0.0.1"].includes(url.hostname))) problem("agreement_public_url_invalid", "Customer links require an HTTPS origin.", 503);
    return url.origin;
  };
  const tokenFor = (id, generation, role) => `${id}.${generation}.${role}.${createHmac("sha256", secret()).update(`${id}:${generation}:${role}`).digest("base64url")}`;
  const makeToken = (agreement, role = "customer") => tokenFor(agreement.link_root_id || agreement.id, agreement.token_generation, role);
  const customerURL = (agreement, role) => `${publicBase()}/estimates/${makeToken(agreement, role)}`;

  async function loadStaff(db, req, id, lock = false) {
    const row = (await db.query(`SELECT * FROM quote_agreements WHERE id=$1 AND company_id=$2 ${lock ? "FOR UPDATE" : ""}`, [uuid(id), req.companyId])).rows[0];
    if (!row) problem("agreement_not_found", "This agreement is unavailable.", 404);
    return row;
  }
  async function loadPublic(db, token, lock = false) {
    if (typeof token !== "string" || token.length > 200) problem("agreement_link_invalid", "This link is unavailable. Contact the business.", 404);
    const [id, generation, role, mac, extra] = token.split(".");
    if (extra || !["customer", "customer_2"].includes(role) || !/^\d+$/.test(generation || "") || !mac || !/^[0-9a-f-]{36}$/i.test(id || "")) problem("agreement_link_invalid", "This link is unavailable. Contact the business.", 404);
    const anchor = (await db.query('SELECT * FROM quote_agreements WHERE id=$1', [id])).rows[0];
    if (!anchor || anchor.revoked_at || anchor.token_generation !== Number(generation) || !equal(token, tokenFor(id, Number(generation), role))) problem("agreement_link_invalid", "This link is unavailable. Contact the business.", 404);
    // Retired optional-choice packets retain their exact version for selection replay.
    const followsRevisions = anchor.quote_id && !anchor.snapshot.optional_addons?.length;
    const row = followsRevisions
      ? (await db.query(`SELECT * FROM quote_agreements WHERE quote_id=$1 AND company_id=$2 AND revoked_at IS NULL ORDER BY revision DESC LIMIT 1 ${lock ? "FOR UPDATE" : ""}`, [anchor.quote_id, anchor.company_id])).rows[0]
      : lock ? (await db.query('SELECT * FROM quote_agreements WHERE id=$1 FOR UPDATE', [anchor.id])).rows[0] : anchor;
    const currentAnchor = lock ? (await db.query("SELECT token_generation,revoked_at FROM quote_agreements WHERE id=$1", [id])).rows[0] : anchor;
    if (!row || row.revoked_at || currentAnchor.revoked_at || currentAnchor.token_generation !== Number(generation) || !row.snapshot.required_signers.includes(role)) problem("agreement_link_invalid", "This link is unavailable. Contact the business.", 404);
    return { row, role };
  }
  async function event(db, agreementId, type, { request_id = null, request_hash = null, actor_type = "system", actor_id = null, payload = {} } = {}) {
    const row = (await db.query(`INSERT INTO agreement_events(id,agreement_id,type,request_id,request_hash,actor_type,actor_id,payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb) ON CONFLICT(agreement_id,request_id) DO NOTHING RETURNING *`, [randomUUID(), agreementId, type, request_id, request_hash, actor_type, actor_id, safeJSON(payload)])).rows[0];
    if (row || !request_id) return row;
    const existing = (await db.query(`SELECT * FROM agreement_events WHERE agreement_id=$1 AND request_id=$2`, [agreementId, request_id])).rows[0];
    if (existing.type !== type || existing.request_hash !== request_hash) problem("agreement_request_conflict", "This request ID was already used for different content.", 409);
    return existing;
  }
  async function rate(db, scope, max = 30, seconds = 60) {
    const key = digest(scope);
    const row = (await db.query(`INSERT INTO agreement_rate_windows(scope,starts_at,hits) VALUES($1,now(),1)
      ON CONFLICT(scope) DO UPDATE SET hits=CASE WHEN agreement_rate_windows.starts_at < now()-($2 * interval '1 second') THEN 1 ELSE agreement_rate_windows.hits+1 END,
      starts_at=CASE WHEN agreement_rate_windows.starts_at < now()-($2 * interval '1 second') THEN now() ELSE agreement_rate_windows.starts_at END RETURNING hits`, [key, seconds])).rows[0];
    if (row.hits > max) problem("agreement_rate_limited", "Too many attempts. Please wait and try again.", 429);
  }
  async function state(db, row) {
    const roles = (await db.query(`SELECT role FROM agreement_signatures WHERE agreement_id=$1`, [row.id])).rows.map((entry) => entry.role);
    const payments = (await db.query(`SELECT status,amount_cents,COALESCE((to_jsonb(p)->>'refunded_amount_cents')::bigint,0) AS refunded_amount_cents FROM payment_records p WHERE company_id=$1 AND agreement_id=$2`, [row.company_id, row.id])).rows;
    const confirmed = payments.filter((p) => ["succeeded", "partially_refunded", "refunded"].includes(p.status)).reduce((sum, p) => sum + Math.max(0, p.amount_cents - (p.refunded_amount_cents || 0)), 0);
    const summary = service.paymentSummary && row.snapshot.pricing ? await service.paymentSummary(db, row) : null;
    const booking = service.bookingSummary ? await service.bookingSummary(db, row) : null;
    const result = deriveAgreementState({ decision: row.revoked_at ? "revoked" : row.decision, required_signers: row.snapshot.required_signers, submitted_signers: roles, deposit_cents: row.snapshot.pricing?.deposit_cents || 0, confirmed_payment_cents: summary?.paid_cents ?? confirmed, payment_processing: summary?.processing ?? payments.some((p) => ["pending", "processing"].includes(p.status)), payment_adjusted: summary?.payment_review_required ?? payments.some((p) => ["refunded", "partially_refunded", "disputed"].includes(p.status)), allow_customer_booking: row.snapshot.allow_customer_booking, booking_id: booking?.booking_id || null, expires_at: row.expires_at });
    result.addon_selection_required = Boolean(row.snapshot.optional_addons?.length && row.snapshot.addon_selection_finalized !== true);
    result.can_decide = result.can_sign && roles.length === 0;
    if (result.addon_selection_required) { result.can_sign = false; result.can_checkout = false; result.can_view_availability = false; result.base_workflow_complete = false; }
    if (service.planQuoteReady && !(await service.planQuoteReady(db,row))) { result.can_checkout=false; result.can_view_availability=false; result.base_workflow_complete=false; }
    return result;
  }
  async function detail(db, row, { staff = false, includeActivity = false, publicRole = null } = {}) {
    const signatures = (await db.query(`SELECT id,role,printed_name,signature,field_values,verification_method,submitted_at FROM agreement_signatures WHERE agreement_id=$1 ORDER BY submitted_at`, [row.id])).rows;
    const snapshot = structuredClone(row.snapshot);
    delete snapshot.recipient_emails;
    delete snapshot.verification;
    delete snapshot.addon_source;
    if (!staff) { delete snapshot.duration_minutes; snapshot.optional_addons = (snapshot.optional_addons || []).map(({ duration_minutes, ...line }) => line); }
    const result = { id: row.id, quote_id: row.quote_id, contact_id: row.contact_id, number: row.number, revision: row.revision, title: row.title, created_at: row.created_at, expires_at: row.expires_at, snapshot, packet_hash: row.packet_hash, state: await state(db, row), signatures, documents_ready: row.documents_ready };
    if (service.currentPlanPresence && (staff || publicRole === "customer")) result.has_current_plan = await service.currentPlanPresence(db,row);
    if(staff){
      result.predecessor_id=row.predecessor_id||null;
      result.latest_activity=(await db.query('SELECT type,created_at FROM agreement_events WHERE agreement_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1',[row.id])).rows[0]||null;
      result.unresolved_exception_count=(await db.query("SELECT count(*)::integer AS n FROM business_exceptions WHERE company_id=$1 AND metadata->>'agreement_id'=$2 AND status IN ('open','snoozed')",[row.company_id,row.id])).rows[0].n;
      if(includeActivity){
        result.exceptions=(await db.query("SELECT id,type,title,explanation,status,created_at,resolved_at,resolution_source,due_at FROM business_exceptions WHERE company_id=$1 AND metadata->>'agreement_id'=$2 ORDER BY created_at DESC,id",[row.company_id,row.id])).rows;
        result.related_agreements=(await db.query(`WITH RECURSIVE ancestors AS (
          SELECT id,predecessor_id,0 AS depth FROM quote_agreements WHERE id=$1 AND company_id=$2
          UNION ALL SELECT a.id,a.predecessor_id,p.depth+1 FROM quote_agreements a JOIN ancestors p ON p.predecessor_id=a.id WHERE a.company_id=$2 AND p.depth<100
        ), family AS (
          SELECT a.id,a.predecessor_id,0 AS depth FROM quote_agreements a WHERE a.id=(SELECT id FROM ancestors ORDER BY depth DESC LIMIT 1)
          UNION ALL SELECT a.id,a.predecessor_id,p.depth+1 FROM quote_agreements a JOIN family p ON a.predecessor_id=p.id WHERE a.company_id=$2 AND p.depth<100
        ) SELECT a.id,a.predecessor_id,a.quote_id,a.number,a.revision,a.title,a.snapshot->>'kind' AS kind,a.created_at FROM quote_agreements a WHERE a.company_id=$2 AND a.id IN (SELECT id FROM family) ORDER BY a.revision,a.created_at`,[row.id,row.company_id])).rows;
        if(service.plansReady){
          const associated=(await db.query(`SELECT DISTINCT a.id,a.predecessor_id,a.quote_id,a.number,a.revision,a.title,a.snapshot->>'kind' AS kind,a.created_at FROM agreement_plan_enrollments e JOIN quote_agreements a ON a.id=e.base_agreement_id OR a.id=e.plan_agreement_id WHERE e.company_id=$1 AND (e.base_agreement_id=$2 OR e.plan_agreement_id=$2)`,[row.company_id,row.id])).rows;
          const seen=new Set(result.related_agreements.map(item=>item.id));for(const item of associated)if(!seen.has(item.id))result.related_agreements.push(item);
        }
      }
    }
    if (!staff && publicRole && row.quote_id) {
      result.history = (await db.query(`SELECT a.id,a.revision,a.title,a.created_at,a.signed_at,a.documents_ready,
        COALESCE((SELECT jsonb_agg(jsonb_build_object('kind',f.kind) ORDER BY f.kind) FROM agreement_artifacts f WHERE f.agreement_id=a.id AND f.kind IN ('quote','terms','signed','packet','scope-certificate')),'[]'::jsonb) AS documents
        FROM quote_agreements a WHERE a.company_id=$1 AND a.quote_id=$2 AND a.contact_id=$3 AND a.id<>$4 AND a.revision<$5 AND a.revoked_at IS NULL AND a.snapshot->'required_signers' ? $6
        AND (EXISTS(SELECT 1 FROM agreement_signatures s WHERE s.agreement_id=a.id) OR EXISTS(SELECT 1 FROM payment_records p WHERE p.agreement_id=a.id))
        ORDER BY a.revision DESC`,[row.company_id,row.quote_id,row.contact_id,row.id,row.revision,publicRole])).rows;
    }
    if (staff && !row.revoked_at) {
      result.customer_url = customerURL(row);
      result.signer_links = row.snapshot.required_signers.filter((role) => role !== "business").map((role) => ({ role, url: customerURL(row, role) }));
    }
    if (service.paymentSummary && row.snapshot.pricing) result.payments = await service.paymentSummary(db, row);
    if (service.bookingSummary) result.booking = await service.bookingSummary(db, row);
    if (service.planSummary) result.plan = await service.planSummary(db, row, {publicRole:staff?'customer':publicRole});
    if (row.decision === "superseded" && row.snapshot.optional_addons?.length) {
      const replacement = (await db.query(`WITH RECURSIVE selected AS (
        SELECT a.* FROM quote_agreements a JOIN agreement_events e ON e.agreement_id=$1 AND e.type='addons_selected' AND e.payload->>'agreement_id'=a.id::text
        UNION ALL SELECT a.* FROM quote_agreements a JOIN selected p ON a.predecessor_id=p.id JOIN agreement_events e ON e.agreement_id=p.id AND e.type='addons_selected' AND e.payload->>'agreement_id'=a.id::text
      ) SELECT * FROM selected ORDER BY revision DESC LIMIT 1`,[row.id])).rows[0];
      if (replacement && !replacement.revoked_at && replacement.decision !== "superseded" && (staff || publicRole)) result.replacement_url = customerURL(replacement, publicRole || "customer");
    }
    if (includeActivity) result.activity = (await db.query(`SELECT id,type,actor_type,payload,created_at FROM agreement_events WHERE agreement_id=$1 ORDER BY created_at,id`, [row.id])).rows;
    return result;
  }
  async function validateDocuments(db, companyId, content, values = null) {
    if (content.show_agreement === false || content.agreement_mode === "text") {
      if (content.require_page_signature === false) problem("agreement_page_signature_required", "A customer-page signature is required unless the selected agreement PDF has a required customer signature.");
      return [];
    }
    const docs = [];
    for (const doc of content.documents) {
      const asset = (await db.query(`SELECT id,name,pages,normalized_bytes,normalized_sha256 FROM agreement_assets WHERE id=$1 AND company_id=$2`, [doc.asset_id, companyId])).rows[0];
      if (!asset) problem("agreement_asset_not_found", "A contract PDF is unavailable in this company.", 404);
      const fields = normalizeAgreementFields(doc.fields, asset.pages);
      if (fields.some((field) => field.role !== "staff" && !content.required_signers.includes(field.role))) problem("agreement_signer_role_unconfigured", "Every document signer role must be included in the agreement's required signers.");
      const prefills = {};
      if (values) {
        for (const field of fields) {
          if (field.type === "merge") {
            if (!values[field.source] && field.required) problem("agreement_merge_missing", `Enter ${AGREEMENT_MERGE_FIELDS[field.source]} before publishing.`);
            prefills[field.id] = values[field.source] || "";
          } else if (field.role === "staff") {
            if(field.type==='checkbox'){
              if(!['true','false',''].includes(field.value))problem('agreement_staff_checkbox_invalid',`Choose checked or unchecked for ${field.label||field.id}.`);
              prefills[field.id]=field.value==='true';
              if(field.required&&!prefills[field.id])problem('agreement_staff_field_missing',`Check ${field.label||field.id} before publishing.`);
            } else {
              if (field.required && !field.value.trim()) problem("agreement_staff_field_missing", `Complete ${field.label || field.id} before publishing.`);
              prefills[field.id] = field.value;
            }
          }
        }
        await populateAgreementPDF(asset.normalized_bytes, fields, prefills);
      }
      docs.push({ asset_id: asset.id, name: asset.name, pages: asset.pages, sha256: asset.normalized_sha256, fields, prefilled_values: prefills });
    }
    if (content.require_page_signature === false && !docs.some(doc => doc.fields.some(field => field.type === "signature" && field.role === "customer" && field.required))) problem("agreement_pdf_signature_required", "Place a required customer signature on the agreement PDF before turning off the customer-page signature.");
    const allIDs=docs.flatMap(document=>document.fields.map(field=>field.id));
    if(new Set(allIDs).size!==allIDs.length)problem("agreement_field_id_collision","Use unique field IDs across the entire document packet.");
    return docs;
  }
  async function publish(req, quoteId, raw, { preview = false } = {}) {
    publicBase(); secret();
    const defaultTemplate = await quoteTemplateTransaction(pool, db => ensureDefaultQuoteTemplate(db, req));
    const requestId = uuid(raw.request_id);
    const { request_id: ignoredRequestID, ...requestContent } = raw;
    const publicationRequestHash = quoteContentHash({ quote_id: quoteId, ...requestContent });
    return transaction(pool, async (db) => {
      await db.query(`SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, [`agreement-publish:${req.companyId}:${requestId}`]);
      if (quoteId) await db.query(`SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, [`payment:${req.companyId}:quote:${uuid(quoteId)}`]);
      const quote = quoteId ? (await db.query(`SELECT * FROM quotes WHERE id=$1 AND deleted_at IS NULL AND (company_id=$2 OR (company_id IS NULL AND user_id=$3)) FOR UPDATE`, [uuid(quoteId), req.companyId, req.userId])).rows[0] : { id: null, contact_id: quoteText(raw.contact_id, "Customer ID", 200), title: quoteText(raw.title, "Agreement title", 200).trim() || "Agreement", line_items: [], quote_options: {}, updated_at: null };
      if (!quote) problem("quote_not_found", "Save a quote in this company before publishing.", 404);
      const priorRequest = (await db.query(`SELECT * FROM quote_agreements WHERE company_id=$1 AND request_id=$2`, [req.companyId, requestId])).rows[0];
      if (priorRequest) { if (priorRequest.quote_id !== quote.id || (priorRequest.publication_request_hash && priorRequest.publication_request_hash !== publicationRequestHash)) problem("agreement_request_conflict", "This publication request was already used for different content.", 409); return detail(db, priorRequest, { staff: true }); }
      if (service.preparePlanQuoteRevision) await service.preparePlanQuoteRevision(db,req,quote);
      if (raw.expected_updated_at && new Date(raw.expected_updated_at).getTime() !== new Date(quote.updated_at).getTime()) problem("quote_changed", "The quote changed. Reload and preview it before publishing.", 409);
      const contact = (await db.query(`SELECT name,address,phone,email FROM contacts WHERE id::text=$1 AND company_id=$2`, [quote.contact_id, req.companyId])).rows[0];
      if (!contact) problem("agreement_contact_missing", "The quote's customer is unavailable in this company.", 404);
      const settings = await getQuoteSettings(db, req.companyId);
      const savedTemplate = quote.quote_options?.template;
      let sourceTemplate = defaultTemplate;
      const selectedID = raw.template_id || savedTemplate?.id;
      const selectedVersion = raw.template_version || (raw.template_id ? null : savedTemplate?.version);
      if (selectedID) {
        sourceTemplate = (await db.query(`SELECT * FROM agreement_templates WHERE template_id=$1 AND company_id=$2 ${selectedVersion ? "AND version=$3" : ""} ORDER BY version DESC LIMIT 1`, selectedVersion ? [uuid(selectedID), req.companyId, selectedVersion] : [uuid(selectedID), req.companyId])).rows[0];
        if (!sourceTemplate || (sourceTemplate.archived_at && savedTemplate?.id !== sourceTemplate.template_id)) problem("agreement_template_missing", "The selected template is unavailable.", 404);
      }
      const templateRef = { id: sourceTemplate.template_id, version: sourceTemplate.version };
      const contentSource = !raw.template_id && savedTemplate ? savedTemplate.content : sourceTemplate.content;
      const mergedContent = { ...contentSource, ...(raw.content || {}) };
      // Older clients attach PDFs without knowing the text/PDF mode field.
      if (raw.content?.documents && raw.content.agreement_mode == null) mergedContent.agreement_mode = raw.content.documents.length ? "pdf" : "text";
      let content = normalizeAgreementContent(mergedContent);
      // Legacy drafts retain their explicitly saved commercial settings until a
      // template is deliberately chosen. New drafts already hold a frozen selection.
      const useTemplateDefaults = !!savedTemplate || !!raw.template_id || raw.content?.quote_defaults != null;
      const options = normalizeQuoteOptions({ ...quote.quote_options, ...(useTemplateDefaults ? content.quote_defaults : {}),
        optional_addons: [], billing_address: "", public_notes: "", scope_exclusions: "" });
      delete options.template; // The issued packet carries only the immutable id/version below.

      validateQuoteAddonScope(quote.line_items, options);
      await assertQuoteReferences(db,req,{contact_id:quote.contact_id,line_items:[...quote.line_items,...options.optional_addons],existing_lines:[...quote.line_items,...options.optional_addons]});
      if (quoteId && !options.duration_minutes) problem("quote_duration_required", "Enter the estimated job duration before publishing this quote.");
      let pricing = calculateQuotePricing({ line_items: quote.line_items, tax_rate_basis_points: settings.tax_enabled ? settings.tax_rate_basis_points : 0, tax_inclusive:settings.tax_inclusive??false,discount:options.discount,deposit: options.deposit });
      const planQuote = content.plan_tier_id && service.preparePlanQuote ? await service.preparePlanQuote(db, req, {quote,content,pricing,options,settings}) : null;
      if (planQuote) { pricing=planQuote.pricing; content=planQuote.content; }
      if (options.optional_addons.length) calculateQuotePricing({line_items:[...quote.line_items,...options.optional_addons],tax_rate_basis_points:pricing.tax_rate_basis_points,tax_inclusive:pricing.tax_inclusive,discount:options.discount,deposit:options.deposit});
      if (quoteId && !pricing.line_items.length) problem("quote_lines_required", "Add the actual service scope before publishing.");
      // Publication of dependent features is gated by implementation readiness,
      // not a cosmetic option. Follow-on adapters lift these checks when wired.
      if (pricing.deposit_cents > 0 && !service.paymentReady) problem("agreement_payment_not_ready", "Deposit checkout must be configured before publishing a deposit quote.", 409);
      if (pricing.deposit_cents > 0) await service.validatePaymentReadiness(db, req.companyId, pricing.deposit_cents);
      const bookingEnabled=!!quoteId&&(useTemplateDefaults ? options.allow_customer_booking : raw.content?.booking_preference??quote.quote_options?.allow_customer_booking??content.booking_preference??false),plansEnabled=!!quoteId&&(useTemplateDefaults ? options.offer_service_plans : raw.content?.plan_offer_preference??quote.quote_options?.offer_service_plans??content.plan_offer_preference??false);
      if (bookingEnabled && !service.bookingReady) problem("agreement_booking_not_ready", "Customer booking is not ready. Finish schedule integration before publishing with booking enabled.", 409);
      if (bookingEnabled) await service.validateBookingReadiness(db, req.companyId, { quote_id: quote.id, duration_minutes: options.duration_minutes, line_items: pricing.line_items });
      if (plansEnabled && !service.plansReady) problem("agreement_plans_not_ready", "Customer plan enrollment is not ready. Finish plan integration before enabling offers.", 409);
      if (!quoteId && !(content.show_agreement && (content.agreement_mode === "pdf" ? content.documents.length : content.agreement_text.trim()))) problem("standalone_agreement_content_required", "Add agreement text or a contract PDF before publishing a standalone agreement.");
      if (!content.consent_text.trim()) problem("agreement_consent_required", "Configure the electronic signing consent wording in Quotes & Contracts.");
      if (!content.show_agreement || content.agreement_mode === "pdf") content.agreement_text = "";
      if (!content.show_agreement || content.agreement_mode === "text") content.documents = [];
      content.terms_text = "";
      if (!content.show_terms) { content.terms_text = ""; content.terms_asset_id = null; }
      const termsAsset = content.terms_asset_id ? (await db.query(`SELECT id,name,normalized_sha256,normalized_bytes FROM agreement_assets WHERE id=$1 AND company_id=$2`, [content.terms_asset_id, req.companyId])).rows[0] : null;
      if (content.terms_asset_id && !termsAsset) problem("agreement_terms_missing", "The Terms & Conditions PDF is unavailable in this company.", 404);
      let predecessor = (await db.query(`SELECT * FROM quote_agreements WHERE company_id=$1 AND quote_id=$2 ORDER BY revision DESC LIMIT 1`, [req.companyId, quote.id])).rows[0];
      if(!quoteId&&raw.predecessor_id){
        predecessor=await service.loadStaff(db,req,uuid(raw.predecessor_id),true);
        if(predecessor.quote_id||predecessor.snapshot.kind!=='standalone'||predecessor.contact_id!==quote.contact_id)problem('agreement_revision_mismatch','Choose a standalone agreement for this customer.',409);
        if((await db.query('SELECT 1 FROM quote_agreements WHERE predecessor_id=$1 LIMIT 1',[predecessor.id])).rowCount)problem('agreement_revision_changed','A newer revision exists. Open it before preparing another replacement.',409);
      }
      if (quoteId && predecessor?.revoked_at) problem("agreement_link_revoked", "Regenerate the customer link before issuing a revision.", 409);
      if (raw.predecessor_id && predecessor?.id !== uuid(raw.predecessor_id)) problem("agreement_revision_changed", "A newer quote revision exists. Reload it before revising.", 409);
      if (!preview && quote.id && service.paymentSummary && predecessor) {
        const payments = await service.paymentSummary(db, predecessor);
        if (payments?.active_checkout) problem("agreement_checkout_pending", "Resolve or cancel the current checkout before revising this quote. Its payment result must be preserved.", 409);
      }
      let suppliedQuotePDF = null;
      if (!preview && quote.id && raw.quote_pdf_base64 != null) {
        if (typeof raw.quote_pdf_base64 !== "string" || raw.quote_pdf_base64.length > 14000000 || !/^[A-Za-z0-9+/]+={0,2}$/.test(raw.quote_pdf_base64)) problem("quote_pdf_invalid", "The quote PDF could not be prepared. Try creating the link again.");
        suppliedQuotePDF = Buffer.from(raw.quote_pdf_base64, "base64");
        await validateAndNormalizeAgreementPDF(suppliedQuotePDF, { allowSanitize: false });
      }
      let number = predecessor?.number;
      if (!number) number = String((await db.query(`INSERT INTO agreement_number_sequences(company_id,last_number) VALUES($1,1) ON CONFLICT(company_id) DO UPDATE SET last_number=agreement_number_sequences.last_number+1 RETURNING last_number`, [req.companyId])).rows[0].last_number);
      const id = randomUUID(), issuedAt = new Date().toISOString();
      const expires = content.validity_days!==null?new Date(Date.now()+content.validity_days*86400000).toISOString():quote.expires_at || new Date(Date.now() + settings.valid_for_days * 86400000).toISOString();
      const values = { customer_name: contact.name, service_address: contact.address, billing_address: contact.address, customer_phone: contact.phone, customer_email: contact.email, business_name: settings.company_name, business_address: settings.company_address, business_phone: settings.phone || settings.company_phone, business_email: settings.email || settings.company_email, quote_number: number, issue_date: issuedAt, expires_at: new Date(expires).toISOString(), services: pricing.line_items.map((li) => `${li.name}\n${li.description}`).join("\n\n"), subtotal: money(pricing.subtotal_cents), tax: money(pricing.tax_cents), total: money(pricing.total_cents), deposit: money(pricing.deposit_cents), deposit_percentage: options.deposit.type === "percent" ? `${options.deposit.value / 100}%` : "", balance: money(pricing.balance_after_deposit_cents) };
      if(planQuote) Object.assign(values,{plan_name:planQuote.offer.configuration.name,service_frequency:`Every ${planQuote.offer.configuration.service_interval.count} ${planQuote.offer.configuration.service_interval.unit}`,contract_term:planQuote.offer.configuration.term.kind === "finite" ? `${planQuote.offer.configuration.term.visit_count} visits` : "Ongoing",plan_price:money(planQuote.offer.future_visit.total_cents),billing_information:planQuote.offer.financial_text});
      values.business_name=content.branding.display_name||settings.company_name;
      values.billing_address=options.billing_address||contact.address;
      const snapshot = {
        kind: quoteId ? "quote" : "standalone",
        ...(suppliedQuotePDF ? { quote_pdf_sha256: agreementBytesHash(suppliedQuotePDF), quote_pdf_source: "client_export" } : {}),
        title: quote.title || "Quote", number, revision: (predecessor?.revision || 0) + 1, issued_at: issuedAt, expires_at: new Date(expires).toISOString(),
        business: { name: values.business_name || "", address: settings.company_address || "", phone: settings.phone || settings.company_phone || "", email: settings.email || settings.company_email || "", logo_data_url: content.branding.show_logo ? settings.company_logo_data_url || "" : "" },
        customer: { name: contact.name || "", address: contact.address || "", billing_address:values.billing_address||"", phone: content.show_customer_phone ? contact.phone : null, email: content.show_customer_email ? contact.email : null },
        pricing: quoteId ? pricing : null, ...options, ...content, template: templateRef,
        ...(planQuote ? {plan_quote:planQuote.offer,financial_text:planQuote.offer.financial_text} : {}),
        discount_stacking_policy:settings.discount_stacking_policy||"best_price",tax_provenance:{source:"business_settings",settings_updated_at:settings.updated_at??null,tax_rate_basis_points:pricing.tax_rate_basis_points,tax_inclusive:pricing.tax_inclusive},
        allow_customer_booking:bookingEnabled,offer_service_plans:planQuote ? false : plansEnabled,
        scope_exclusions:"",
        agreement_text: resolveAgreementText(content.agreement_text, values), terms_text: resolveAgreementText(content.terms_text, values), consent_text: resolveAgreementText(content.consent_text, values),
        documents: await validateDocuments(db, req.companyId, content, values),
        terms_document: termsAsset ? { asset_id: termsAsset.id, name: termsAsset.name, sha256: termsAsset.normalized_sha256 } : null,
      };
      snapshot.selected_addon_ids = [];
      snapshot.addon_selection_finalized = options.optional_addons.length === 0;
      if (options.optional_addons.length) snapshot.addon_source = { base_line_items: pricing.line_items, base_duration_minutes: options.duration_minutes, pricing_inputs: {tax_rate_basis_points:pricing.tax_rate_basis_points,tax_inclusive:pricing.tax_inclusive,discount:options.discount,deposit:options.deposit}, merge_values:values, content:{...content,documents:snapshot.documents.map(document=>({asset_id:document.asset_id,fields:document.fields}))} };
      const fieldIDs = snapshot.documents.flatMap((doc) => doc.fields.map((field) => field.id));
      if (new Set(fieldIDs).size !== fieldIDs.length) problem("agreement_field_id_collision", "Use unique field IDs across the entire document packet.");
      if (snapshot.quote_position === "excluded") snapshot.scope_reference_hash = quoteContentHash({ number, revision: snapshot.revision, pricing: snapshot.pricing, public_notes: snapshot.public_notes, scope_exclusions: snapshot.scope_exclusions });
      const previewHash = quoteContentHash({
        quote: { id: quote.id, contact_id: quote.contact_id, title: quote.title, line_items: quote.line_items, options, expires_at: quote.expires_at || null, updated_at: quote.updated_at },
        contact, settings, content, template: templateRef, plan_quote:planQuote?.offer ?? null,
        documents: snapshot.documents.map(({ prefilled_values, ...document }) => document), terms_document: snapshot.terms_document,
      });
      if (!preview && !raw.expected_preview_hash) problem("agreement_preview_required", "Prepare and review the exact preview before creating the customer link.", 409);
      if (raw.expected_preview_hash && raw.expected_preview_hash !== previewHash) problem("agreement_preview_changed", "The quote, customer, branding, template or pricing changed. Review a fresh preview before publishing.", 409);
      if (preview) {
        const safeSnapshot = structuredClone(snapshot);
        delete safeSnapshot.recipient_emails;
        delete safeSnapshot.addon_source;
        const generated = await generateQuoteAgreementPDF(packetCoverSnapshot(snapshot));
        const contracts = [];
        for (const document of snapshot.documents) {
          const source = (await db.query(`SELECT normalized_bytes FROM agreement_assets WHERE id=$1 AND company_id=$2`, [document.asset_id, req.companyId])).rows[0];
          contracts.push(await populateAgreementPDF(source.normalized_bytes, document.fields, document.prefilled_values));
        }
        const packet = snapshot.quote_position === "last" ? [...contracts, generated] : [generated, ...contracts];
        if (snapshot.terms_text || termsAsset) {
          const cover = await generateQuoteAgreementPDF({ ...snapshot, title: "Terms & Conditions", pricing: null, agreement_text: "", public_notes: "", scope_exclusions: "", documents: [], consent_text: "" });
          packet.push(termsAsset ? await combineAgreementPDFs([cover, termsAsset.normalized_bytes]) : cover);
        }
        const pdf = await combineAgreementPDFs(packet);
        const exportPayload = quoteId ? {
          settings: { ...settings, company_name: snapshot.business.name, company_logo_data_url: snapshot.business.logo_data_url,
            phone: snapshot.business.phone, email: snapshot.business.email, notes: "", valid_for_days: content.validity_days || settings.valid_for_days },
          contact: { id: quote.contact_id, name: snapshot.customer.name, address: snapshot.customer.address, phone: snapshot.customer.phone || "", email: snapshot.customer.email || "" },
          quote: { ...quote, quote_options: options, notes: "", expires_at: snapshot.expires_at }, pricing,
        } : null;
        return { quote_export_payload: exportPayload, snapshot: safeSnapshot, packet_hash: quoteContentHash(snapshot), preview_hash: previewHash, quote_updated_at: quote.updated_at, pdf_base64: pdf.toString("base64"), validation: { ready: true, number_is_preview: true } };
      }
      const row = (await db.query(`INSERT INTO quote_agreements(id,company_id,quote_id,contact_id,created_by,number,revision,predecessor_id,request_id,title,snapshot,packet_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13) RETURNING *`, [id, req.companyId, quote.id, quote.contact_id, req.userId, number, snapshot.revision, predecessor?.id || null, requestId, snapshot.title, safeJSON(snapshot), quoteContentHash(snapshot), expires])).rows[0];
      if (service.createPlanQuoteEnrollment) await service.createPlanQuoteEnrollment(db,row);
      row.link_root_id = quoteId ? predecessor?.link_root_id || predecessor?.id || row.id : row.id;
      row.token_generation = quoteId ? predecessor?.token_generation || 1 : 1;
      await db.query(`UPDATE quote_agreements SET publication_request_hash=$2,link_root_id=$3,token_generation=$4 WHERE id=$1`, [id, publicationRequestHash, row.link_root_id, row.token_generation]);
      const pdf = suppliedQuotePDF || await generateQuoteAgreementPDF(snapshot, { customer_url: customerURL(row) });
      await storeArtifact(db, id, "quote", pdf);
      if (snapshot.terms_text || termsAsset) {
        const cover = await generateQuoteAgreementPDF({ ...snapshot, title: "Terms & Conditions", pricing: null, agreement_text: "", public_notes: "", scope_exclusions: "", documents: [], consent_text: "" }, { customer_url: customerURL(row) });
        await storeArtifact(db, id, "terms", termsAsset ? termsAsset.normalized_bytes : cover);
      }
      if (predecessor && (quoteId || !predecessor.signed_at)) await db.query(`UPDATE quote_agreements SET decision='superseded',updated_at=now() WHERE id=$1`, [predecessor.id]);
      await event(db, id, "link_created", { actor_type: "staff", actor_id: req.userId, payload: { revision: row.revision, predecessor_id: row.predecessor_id } });
      return detail(db, row, { staff: true });
    }, { rollback: preview });
  }
  async function storeArtifact(db, agreementId, kind, bytes, assetId = null) {
    await db.query(`INSERT INTO agreement_artifacts(id,agreement_id,kind,asset_id,bytes,sha256) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(agreement_id,kind) DO NOTHING`, [randomUUID(), agreementId, kind, assetId, bytes, agreementBytesHash(bytes)]);
  }
  async function session(db, row, role, token) {
    if (typeof token !== "string" || token.length > 100) problem("agreement_session_invalid", "Start or resume signing first.", 401);
    const result = (await db.query(`SELECT * FROM agreement_signing_sessions WHERE agreement_id=$1 AND token_hash=$2 AND role=$3 AND token_generation=$4 AND expires_at > now() FOR UPDATE`, [row.id, digest(token), role, row.token_generation])).rows[0];
    if (!result) problem("agreement_session_expired", "Your signing session expired. Start again; completed signatures remain saved.", 401);
    return result;
  }
  async function publicSession(token, raw = {}) {
    const { row, role } = await loadPublic(pool, token);
    const access = await state(pool, row);
    if (access.addon_selection_required && access.can_decide) return { completed: false, selection_required: true, role, agreement: await detail(pool,row,{publicRole:role}) };
    if (!access.can_sign) return { completed: true, role, agreement: await detail(pool, row, {publicRole:role}) };
    let resumedDraft = {};
    if (raw.session_token) {
      try {
        const current = await session(pool, row, role, raw.session_token);
        return { session_token: raw.session_token, verified: true, role, draft_values: current.draft_values };
      } catch (error) {
        if (!(error instanceof QuoteContractError) || error.code !== "agreement_session_expired") throw error;
        // Possession of both current role link and previous session token is
        // required. The current role link never grants another signer's draft.
        const previous = (await pool.query(`SELECT draft_values FROM agreement_signing_sessions WHERE agreement_id=$1 AND role=$2 AND token_generation=$3 AND token_hash=$4`,[row.id,role,row.token_generation,digest(raw.session_token)])).rows[0];
        resumedDraft = previous?.draft_values || {};
      }
    }
    await rate(pool, `session:${row.id}`, 20, 3600);
    const sessionToken = randomBytes(32).toString("base64url");
    await pool.query(`INSERT INTO agreement_signing_sessions(id,agreement_id,role,token_hash,token_generation,expires_at,verification_method,draft_values) VALUES($1,$2,$3,$4,$5,now()+interval '2 hours','link',$6::jsonb)`, [randomUUID(), row.id, role, digest(sessionToken), row.token_generation,safeJSON(resumedDraft)]);
    await event(pool, row.id, "signing_started", { actor_type: "customer", actor_id: role });
    return { session_token: sessionToken, verified: true, role, draft_values: resumedDraft };
  }
  async function sign(token, raw, observations = {}, staffReq = null) {
    const initial = staffReq ? { row: await loadStaff(pool, staffReq, token), role: "business" } : await loadPublic(pool, token);
    await rate(pool, `sign:${initial.row.id}`, 30, 3600);
    return transaction(pool, async (db) => {
      const { row, role } = staffReq ? { row: await loadStaff(db, staffReq, token, true), role: "business" } : await loadPublic(db, token, true);
      if (!row.snapshot.required_signers.includes(role)) problem("agreement_signer_not_required", "This agreement does not request this signer role.", 409);
      const requestId = uuid(raw.request_id);
      const requestHash = quoteContentHash({ packet_hash: raw.packet_hash ?? null, printed_name: raw.printed_name ?? "", consent: raw.consent ?? false, signature: raw.signature ?? null, values: raw.values || {} });
      const prior = (await db.query(`SELECT * FROM agreement_signatures WHERE agreement_id=$1 AND role=$2`, [row.id, role])).rows[0];
      if (prior) {
        if (prior.request_id === requestId && prior.request_hash !== requestHash) problem("agreement_request_conflict", "This submission ID was already used for different content.", 409);
        return detail(db, row, {staff:!!staffReq,publicRole:role});
      }
      const access = await state(db, row);
      if (!access.can_sign) problem("agreement_not_signable", "This version can no longer be signed. Contact the business for the current estimate.", 409);
      let current;
      if (staffReq) {
        current = (await db.query(`INSERT INTO agreement_signing_sessions(id,agreement_id,role,token_hash,token_generation,expires_at,verification_method) VALUES($1,$2,'business',$3,$4,now()+interval '1 hour','staff_authenticated') RETURNING *`, [randomUUID(), row.id, digest(randomBytes(32)), row.token_generation])).rows[0];
      } else current = await session(db, row, role, raw.session_token);
      if (raw.packet_hash !== row.packet_hash) problem("agreement_version_changed", "Reload and review the current agreement before signing.", 409);
      if (raw.consent !== true) problem("agreement_consent_required", "Affirm electronic signing consent before submitting.");
      const name = quoteText(raw.printed_name, "Printed signer name", 200).trim();
      if ([...name].filter(letter => /[\p{L}\p{N}]/u.test(letter)).length < 2) problem("agreement_signer_name_required", "Enter your printed name.");
      const submittedAt = new Date().toISOString();
      const fields = row.snapshot.documents.flatMap((doc) => doc.fields);
      if (new Set(fields.map((field) => field.id)).size !== fields.length) problem("agreement_field_id_collision", "The document packet has duplicate field IDs. Ask the business to correct the template.", 409);
      const fieldValues = validateAgreementSubmission(fields, raw.values || {}, { role, printed_name: name, submitted_at: submittedAt, require_drawn: !staffReq });
      const pdfSignature = row.snapshot.require_page_signature === false ? fields.find(field => field.role === role && field.type === "signature" && field.required && fieldValues[field.id]) : null;
      const signature = validateAgreementSignature(raw.signature ?? (pdfSignature ? fieldValues[pdfSignature.id] : null), { requireDrawn: !staffReq });
      await validateAgreementSignerText(name, signature);
      // Validate actual layout before final execution; artifact rendering after
      // this point may retry from immutable values without seeking a new signature.
      for (const doc of row.snapshot.documents) {
        const asset = (await db.query(`SELECT normalized_bytes FROM agreement_assets WHERE id=$1 AND company_id=$2`, [doc.asset_id, row.company_id])).rows[0];
        await populateAgreementPDF(asset.normalized_bytes, doc.fields, { ...doc.prefilled_values, ...fieldValues });
      }
      await db.query(`INSERT INTO agreement_signatures(id,agreement_id,session_id,role,request_id,request_hash,printed_name,consent_text,signature,field_values,packet_hash,verification_method,source_ip,user_agent,submitted_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11,$12,$13,$14,$15)`, [randomUUID(), row.id, current.id, role, requestId, requestHash, name, row.snapshot.consent_text, safeJSON(signature), safeJSON(fieldValues), row.packet_hash, staffReq ? "staff_authenticated" : "link_only", quoteText(observations.ip, "Observed IP", 100), quoteText(observations.user_agent, "User agent", 1000), submittedAt]);
      await event(db, row.id, "signature_submitted", { actor_type: staffReq ? "staff" : "customer", actor_id: staffReq?.userId || role, request_id: requestId, request_hash: requestHash, payload: { role, submitted_at: submittedAt } });
      const next = await state(db, row);
      if (next.signing === "submitted") {
        await db.query(`UPDATE quote_agreements SET signed_at=COALESCE(signed_at,now()),updated_at=now() WHERE id=$1`, [row.id]);
        await db.query(`INSERT INTO agreement_jobs(id,agreement_id,kind) VALUES($1,$2,'documents') ON CONFLICT(agreement_id,kind) DO NOTHING`, [randomUUID(), row.id]);
        await event(db,row.id,"signing_completed",{payload:{required_signers:row.snapshot.required_signers}});
      }
      return detail(db, row, {staff:!!staffReq,publicRole:role});
    });
  }
  async function decision(token, raw) {
    const { row: initial } = await loadPublic(pool, token);
    await rate(pool, `decision:${initial.id}`, 20, 3600);
    return transaction(pool, async (db) => {
      const { row, role } = await loadPublic(db, token, true);
      const requestId = uuid(raw.request_id);
      const message = quoteText(raw.message, "Message", 10000).trim();
      if (!["changes_requested", "declined"].includes(raw.decision)) problem("agreement_decision_invalid", "Choose a supported decision.");
      if (raw.decision === "changes_requested" && message.length < 3) problem("agreement_message_required", "Describe the changes you are requesting.");
      const requestHash = quoteContentHash({ decision: raw.decision, message });
      const prior = (await db.query(`SELECT * FROM agreement_events WHERE agreement_id=$1 AND request_id=$2`, [row.id, requestId])).rows[0];
      if (prior) { if (prior.request_hash !== requestHash) problem("agreement_request_conflict", "This request ID was already used.", 409); return detail(db, row, {publicRole:role}); }
      if (!(await state(db, row)).can_decide || (await db.query(`SELECT 1 FROM agreement_signatures WHERE agreement_id=$1 LIMIT 1`, [row.id])).rowCount) problem("agreement_decision_locked", "A submitted agreement cannot be undone here. Contact the business for an amendment.", 409);
      await db.query(`UPDATE quote_agreements SET decision=$2,updated_at=now() WHERE id=$1`, [row.id, raw.decision]);
      const saved = await event(db, row.id, raw.decision, { request_id: requestId, request_hash: requestHash, actor_type: "customer", actor_id: role, payload: { message, revision: row.revision } });
      if (raw.decision === "changes_requested") await db.query(`INSERT INTO business_exceptions(company_id,type,severity,source_type,source_id,fingerprint,title,explanation,recommended_action,destination,metadata)
        VALUES($1,'agreement_change_request','medium','agreement',$2,$3,$4,$5,'Review the message and issue an explicit revision if needed.',$6::jsonb,$7::jsonb)
        ON CONFLICT(company_id,type,source_type,source_id) DO NOTHING`, [row.company_id, saved.id, saved.id, `Changes requested: Estimate #${row.number}`, message, safeJSON({ type: "agreement", id: row.id, contact_id: row.contact_id }), safeJSON({ agreement_id: row.id, event_id: saved.id, revision: row.revision })]);
      return detail(db, { ...row, decision: raw.decision }, {publicRole:role});
    });
  }
  async function processDocumentJobs(limit = 5) {
    let processed = 0;
    for (let i = 0; i < limit; i++) {
      const found = await transaction(pool, async (db) => {
        const job = (await db.query(`SELECT * FROM agreement_jobs WHERE state IN ('pending','retry') AND run_at<=now() AND kind='documents' ORDER BY run_at FOR UPDATE SKIP LOCKED LIMIT 1`)).rows[0];
        if (!job) return false;
        // Savepoint lets error status survive while partially generated artifacts
        // roll back atomically. Other workers cannot duplicate this job.
        await db.query("SAVEPOINT artifact_work");
        try {
          const row = (await db.query(`SELECT * FROM quote_agreements WHERE id=$1`, [job.agreement_id])).rows[0];
          const signatures = (await db.query(`SELECT * FROM agreement_signatures WHERE agreement_id=$1 ORDER BY submitted_at`, [row.id])).rows.map((s) => ({ ...s, submitted_at: new Date(s.submitted_at).toISOString() }));
          const signed = await generateQuoteAgreementPDF(row.snapshot, { customer_url: customerURL(row), signatures });
          await storeArtifact(db, row.id, "signed", signed);
          const audit = await generateQuoteAgreementPDF(row.snapshot, { signatures, audit: true });
          await storeArtifact(db, row.id, "audit", audit);
          const values = Object.assign({}, ...signatures.map((s) => s.field_values));
          const contracts = [];
          for (const doc of row.snapshot.documents) {
            const asset = (await db.query(`SELECT normalized_bytes FROM agreement_assets WHERE id=$1 AND company_id=$2`, [doc.asset_id, row.company_id])).rows[0];
            const bytes = await populateAgreementPDF(asset.normalized_bytes, doc.fields, { ...doc.prefilled_values, ...values });
            await storeArtifact(db, row.id, `contract-${doc.asset_id}`, bytes, doc.asset_id);
            contracts.push(bytes);
          }
          const terms = (await db.query(`SELECT bytes FROM agreement_artifacts WHERE agreement_id=$1 AND kind='terms'`, [row.id])).rows[0];
          let packetCover = signed;
          if (row.snapshot.kind === "quote" && row.snapshot.quote_position === "excluded") {
            packetCover = await generateQuoteAgreementPDF(packetCoverSnapshot(row.snapshot), { customer_url: customerURL(row), signatures });
            await storeArtifact(db,row.id,"scope-certificate",packetCover);
          }
          const combined = row.snapshot.quote_position === "last" ? [...contracts, packetCover] : [packetCover, ...contracts];
          if (terms) combined.push(terms.bytes);
          await storeArtifact(db, row.id, "packet", await combineAgreementPDFs(combined));
          await db.query(`UPDATE quote_agreements SET documents_ready=true,updated_at=now() WHERE id=$1`, [row.id]);
          await db.query(`UPDATE agreement_jobs SET state='complete',completed_at=now(),attempts=attempts+1,last_error=NULL WHERE id=$1`, [job.id]);
          await event(db, row.id, "documents_ready");
        } catch (error) {
          await db.query("ROLLBACK TO SAVEPOINT artifact_work");
          await db.query(`UPDATE agreement_jobs SET state=CASE WHEN attempts>=7 THEN 'failed' ELSE 'retry' END,attempts=attempts+1,run_at=now()+interval '5 minutes',last_error=$2 WHERE id=$1`, [job.id, error instanceof QuoteContractError ? error.code : "artifact_generation_failed"]);
        }
        return true;
      });
      if (!found) break;
      processed++;
    }
    return processed;
  }

  const service = { pool, env, secret, publicBase, makeToken, customerURL, loadStaff, loadPublic, event, rate, state, detail, validateDocuments, publish, storeArtifact, session, publicSession, sign, decision, processDocumentJobs, getStripe, paymentReady: false, bookingReady: false, plansReady: false };
  service.selectAddons = createQuoteAddonSelection({pool,service});
  return service;
}

export async function installAgreementSystem({ app, pool, authRequired, requireCapability, getQuoteSettings, getStripe, env = process.env, startWorker = true }) {
  await installAgreementSchema(pool);
  const service = createAgreementService({ pool, getQuoteSettings, getStripe, env });
  const wrap = (fn) => async (req, res) => {
    res.set({ "Cache-Control": "private, no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff", "X-Robots-Tag": "noindex, nofollow" });
    try { await fn(req, res); }
    catch (error) {
      if (error instanceof QuoteContractError || error instanceof ServiceCatalogError) return res.status(error.status).json({ error: error.code, message: error.message });
      console.error("[agreements] request failed", { code: error?.code || "internal" });
      res.status(500).json({ error: "agreement_failed", message: "This action could not be completed. Please try again." });
    }
  };
  const staff = (capability) => [authRequired, requireCapability(capability), (req, res, next) => req.companyId ? next() : res.status(403).json({ error: "company_required" })];
  const publicWrite = (req, res, next) => {
    if (!req.is("application/json")) return res.status(415).json({ error: "json_required" });
    if (req.headers.origin && req.headers.origin !== env.QUOTE_PUBLIC_BASE_URL?.replace(/\/$/, "")) return res.status(403).json({ error: "origin_not_allowed" });
    next();
  };

  installAgreementDraftRoutes({ app, pool, staff, wrap });

  app.get("/api/agreements/settings", ...staff("quotes.view"), wrap(async (req, res) => {
    const row = (await pool.query(`SELECT * FROM agreement_settings WHERE company_id=$1`, [req.companyId])).rows[0];
    res.json({ content: normalizeAgreementContent(row?.content), version: row?.version || 0, merge_fields: AGREEMENT_MERGE_FIELDS, link_ready: Boolean(env.QUOTE_LINK_SECRET?.length >= 32 && env.QUOTE_PUBLIC_BASE_URL) });
  }));
  app.put("/api/agreements/settings", ...staff("settings.manage_company"), wrap(async (req, res) => {
    const content = normalizeAgreementContent(req.body.content);
    await service.validateDocuments(pool, req.companyId, content);
    const row = (await pool.query(`INSERT INTO agreement_settings(company_id,content) VALUES($1,$2::jsonb) ON CONFLICT(company_id) DO UPDATE SET content=EXCLUDED.content,version=agreement_settings.version+1,updated_at=now() WHERE agreement_settings.version=$3 RETURNING *`, [req.companyId, safeJSON(content), req.body.expected_version ?? 0])).rows[0];
    if (!row) problem("agreement_settings_changed", "Settings changed. Reload before saving.", 409);
    res.json(row);
  }));
  app.get("/api/agreements/templates", ...staff("quotes.view"), wrap(async (req, res) => res.json(await listQuoteTemplates(pool, req))));
  app.put("/api/agreements/templates/:id/default", ...staff("settings.manage_company"), wrap(async (req, res) => {
    const result = await transaction(pool, async db => {
      await ensureDefaultQuoteTemplate(db, req);
      const id = uuid(req.params.id);
      await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [`agreement-template:${id}`]);
      const row = (await db.query('SELECT * FROM agreement_templates WHERE company_id=$1 AND template_id=$2 AND archived_at IS NULL ORDER BY version DESC LIMIT 1', [req.companyId,id])).rows[0];
      if (!row) problem('agreement_template_missing', 'This template is unavailable.', 404);
      if (row.version !== req.body.expected_version) problem('agreement_template_changed', 'This template changed. Reload before selecting it.', 409);
      await db.query('UPDATE agreement_settings SET default_template_id=$2,updated_at=now() WHERE company_id=$1', [req.companyId,id]);
      return { ...row, content: completeTemplateContent(row.content), is_default: true };
    });
    res.json(result);
  }));
  app.get('/api/agreements/templates/:id/versions',...staff('quotes.view'),wrap(async(req,res)=>{
    const rows=(await pool.query('SELECT template_id,version,name,content,created_at,archived_at FROM agreement_templates WHERE template_id=$1 AND company_id=$2 ORDER BY version DESC',[uuid(req.params.id),req.companyId])).rows;
    if(!rows.length)problem('agreement_template_missing','This template is unavailable.',404);res.json(rows);
  }));
  app.post('/api/agreements/templates/:id/archive',...staff('settings.manage_company'),wrap(async(req,res)=>{
    const id=uuid(req.params.id);
    await transaction(pool,async(db)=>{
      const fallback = await ensureDefaultQuoteTemplate(db, req);
      if (fallback.template_id === id) problem('agreement_default_template_required', 'Select another default template before archiving this one.', 409);
      await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`agreement-template:${id}`]);
      const latest=(await db.query('SELECT version FROM agreement_templates WHERE template_id=$1 AND company_id=$2 ORDER BY version DESC LIMIT 1',[id,req.companyId])).rows[0];
      if(!latest)problem('agreement_template_missing','This template is unavailable.',404);
      if(latest.version!==req.body.expected_version)problem('agreement_template_changed','This template changed. Reload before archiving.',409);
      await db.query('UPDATE agreement_templates SET archived_at=COALESCE(archived_at,now()) WHERE template_id=$1 AND company_id=$2',[id,req.companyId]);
    });res.json({archived:true});
  }));
  app.post("/api/agreements/templates", ...staff("settings.manage_company"), wrap(async (req, res) => {
    const content = completeTemplateContent(req.body.content), id = req.body.template_id ? uuid(req.body.template_id) : randomUUID();
    const name = quoteText(req.body.name, "Template name", 200).trim();
    if (!name) problem("agreement_template_name_required", "Name this template.");
    await service.validateDocuments(pool, req.companyId, content);
    const row = await transaction(pool, async (db) => authoringRequest(db, req, "template", req.body, async () => {
      await db.query(`SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, [`agreement-template:${id}`]);
      const prior = (await db.query(`SELECT company_id,version,archived_at FROM agreement_templates WHERE template_id=$1 ORDER BY version DESC LIMIT 1`, [id])).rows[0];
      if (prior?.archived_at) problem("agreement_template_archived", "This template was archived. Save a new template instead.", 409);
      if (prior && (prior.company_id !== req.companyId || prior.version !== req.body.expected_version)) problem("agreement_template_changed", "Template unavailable or changed. Reload before saving.", 409);
      return (await db.query(`INSERT INTO agreement_templates(template_id,version,company_id,name,content,created_by) VALUES($1,$2,$3,$4,$5::jsonb,$6) RETURNING *`, [id, (prior?.version || 0) + 1, req.companyId, name, safeJSON(content), req.userId])).rows[0];
    }));
    const defaults = (await pool.query("SELECT default_template_id FROM agreement_settings WHERE company_id=$1", [req.companyId])).rows[0];
    res.status(201).json({ ...row, is_default: defaults?.default_template_id === row.template_id });
  }));
  app.post("/api/agreements/assets", ...staff("settings.manage_company"), wrap(async (req, res) => {
    const name = quoteText(req.body.name, "PDF name", 200).trim();
    if (!name || typeof req.body.base64 !== "string" || req.body.base64.length > 14_000_000 || !/^[A-Za-z0-9+/]*={0,2}$/.test(req.body.base64)) problem("agreement_pdf_invalid", "Choose a valid PDF up to 10 MB and provide its name.");
    const bytes = Buffer.from(req.body.base64, "base64"), pdf = await validateAndNormalizeAgreementPDF(bytes), id = randomUUID();
    await pool.query(`INSERT INTO agreement_assets(id,company_id,name,original_bytes,normalized_bytes,source_sha256,normalized_sha256,pages,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9)`, [id, req.companyId, name, bytes, pdf.normalized, pdf.source_sha256, pdf.normalized_sha256, safeJSON(pdf.pages), req.userId]);
    res.status(201).json({ id, name, pages: pdf.pages, sha256: pdf.normalized_sha256, removed_features: pdf.removed_features });
  }));
  app.get("/api/agreements/assets/:id", ...staff("quotes.view"), wrap(async (req, res) => {
    const row = (await pool.query(`SELECT normalized_bytes FROM agreement_assets WHERE id=$1 AND company_id=$2`, [uuid(req.params.id), req.companyId])).rows[0];
    if (!row) problem("agreement_asset_not_found", "This document is unavailable.", 404);
    res.type("application/pdf").send(row.normalized_bytes);
  }));
  app.post("/api/quotes/:id/publish", ...staff("quotes.create"), wrap(async (req, res) => res.status(201).json(await service.publish(req, req.params.id, req.body))));
  app.post("/api/quotes/:id/preview", ...staff("quotes.view"), wrap(async (req, res) => res.json(await service.publish(req, req.params.id, { ...req.body, request_id: randomUUID() }, { preview: true }))));
  app.post("/api/agreements", ...staff("quotes.create"), wrap(async (req, res) => res.status(201).json(await service.publish(req, null, req.body))));
  app.post("/api/agreements/preview", ...staff("quotes.view"), wrap(async (req, res) => res.json(await service.publish(req, null, { ...req.body, request_id: randomUUID() }, { preview: true }))));
  app.get("/api/agreements", ...staff("quotes.view"), wrap(async (req, res) => {
    if(service.archivePage)return res.json(await service.archivePage(req));
    const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 30)), offset = Math.max(0, Number(req.query.offset) || 0);
    if (!Number.isInteger(limit) || !Number.isInteger(offset)) problem("agreement_page_invalid", "Use whole-number pagination.");
    const contact = req.query.contact_id || null, search = quoteText(req.query.search, "Search", 200), quoteId = req.query.quote_id ? uuid(req.query.quote_id) : null;
    const rows = (await pool.query(`SELECT a.*,count(*) OVER()::integer AS match_count FROM quote_agreements a WHERE company_id=$1 AND ($2::text IS NULL OR contact_id=$2) AND ($3='' OR title ILIKE '%'||$3||'%' OR number ILIKE '%'||$3||'%' OR snapshot->'customer'->>'name' ILIKE '%'||$3||'%') AND ($6::uuid IS NULL OR quote_id=$6) ORDER BY created_at DESC,id LIMIT $4 OFFSET $5`, [req.companyId, contact, search, limit, offset, quoteId])).rows;
    res.json({ agreements: await Promise.all(rows.map((row) => service.detail(pool, row, { staff: true }))), total: rows[0]?.match_count || 0 });
  }));
  app.get("/api/agreements/:id([0-9a-fA-F-]{36})", ...staff("quotes.view"), wrap(async (req, res) => res.json(await service.detail(pool, await service.loadStaff(pool, req, req.params.id), { staff: true, includeActivity: true }))));
  app.post("/api/agreements/:id/countersign", ...staff("quotes.edit"), wrap(async (req, res) => res.json(await service.sign(req.params.id, req.body, { ip: req.ip, user_agent: req.get("user-agent") || "" }, req))));
  app.post("/api/agreements/:id/link", ...staff("quotes.edit"), wrap(async (req, res) => {
    const result = await transaction(pool, async (db) => {
      let row = await service.loadStaff(db, req, req.params.id);
      if (row.quote_id) {
        await db.query('SELECT id FROM quotes WHERE id=$1 FOR NO KEY UPDATE', [row.quote_id]);
        await db.query('SELECT id FROM quote_agreements WHERE quote_id=$1 AND company_id=$2 ORDER BY id FOR UPDATE', [row.quote_id, row.company_id]);
        row = await service.loadStaff(db, req, req.params.id);
      } else row = await service.loadStaff(db, req, req.params.id, true);
      if (!["copied", "regenerate", "revoke"].includes(req.body.action)) problem("agreement_link_action_invalid", "Choose a supported link action.");
      const requestId = uuid(req.body.request_id), hash = quoteContentHash({ action: req.body.action });
      const existing = (await db.query(`SELECT * FROM agreement_events WHERE agreement_id=$1 AND request_id=$2`, [row.id, requestId])).rows[0];
      if (existing) { if (existing.request_hash !== hash) problem("agreement_request_conflict", "This request ID was already used.", 409); return service.detail(db, row, { staff: true }); }
      if (req.body.action !== "copied") {
        const generation = row.quote_id ? Number((await db.query('SELECT max(token_generation) AS generation FROM quote_agreements WHERE quote_id=$1 AND company_id=$2', [row.quote_id,row.company_id])).rows[0].generation)+1 : row.token_generation+1;
        await db.query(`UPDATE quote_agreements SET token_generation=$3,revoked_at=CASE WHEN $2='revoke' THEN now() ELSE NULL END,updated_at=now() WHERE id=$1 OR (quote_id=$4 AND company_id=$5)`, [row.id,req.body.action,generation,row.quote_id,row.company_id]);
        row = await service.loadStaff(db,req,row.id);
      }
      await service.event(db, row.id, `link_${req.body.action}`, { request_id: requestId, request_hash: hash, actor_type: "staff", actor_id: req.userId });
      return service.detail(db, row, { staff: true });
    });
    res.json(result);
  }));
  app.get("/api/agreements/:id/evidence", ...staff("quotes.view"), wrap(async (req, res) => {
    const row = await service.loadStaff(pool, req, req.params.id);
    const signatures = (await pool.query(`SELECT * FROM agreement_signatures WHERE agreement_id=$1`, [row.id])).rows;
    const artifacts = (await pool.query(`SELECT id,kind,asset_id,sha256,created_at FROM agreement_artifacts WHERE agreement_id=$1`, [row.id])).rows;
    res.json({ format_version: 1, ...agreementEvidenceMetadata(await service.detail(pool, row, { staff: true, includeActivity: true })), signatures, artifacts, integrity_notice: "Application-stored hashes support integrity comparison; they are not independent notarization or a third-party digital seal." });
  }));
  app.get("/api/agreements/:id/evidence-package", ...staff("quotes.view"), wrap(async (req,res) => {
    const row=await service.loadStaff(pool,req,req.params.id);
    await streamAgreementEvidence({pool,service,row,response:res});
  }));
  app.post("/api/agreements/:id/retry-documents", ...staff("quotes.edit"), wrap(async (req, res) => {
    const row = await service.loadStaff(pool, req, req.params.id);
    await pool.query(`UPDATE agreement_jobs SET state='pending',run_at=now(),last_error=NULL WHERE agreement_id=$1 AND kind='documents' AND state IN ('failed','retry')`, [row.id]);
    res.json({ queued: true });
  }));
  const artifact = async (req, res, publicAccess) => {
    const access = publicAccess ? await service.loadPublic(pool, req.params.token) : {row:await service.loadStaff(pool, req, req.params.id)};
    let {row}=access; const {role}=access;
    if (publicAccess && req.params.historyID) {
      const previous = (await pool.query(`SELECT a.* FROM quote_agreements a WHERE a.id=$1 AND a.company_id=$2 AND a.quote_id=$3 AND a.contact_id=$4 AND a.revision<$5 AND a.revoked_at IS NULL AND a.snapshot->'required_signers' ? $6
        AND (EXISTS(SELECT 1 FROM agreement_signatures s WHERE s.agreement_id=a.id) OR EXISTS(SELECT 1 FROM payment_records p WHERE p.agreement_id=a.id))`, [uuid(req.params.historyID),row.company_id,row.quote_id,row.contact_id,row.revision,role])).rows[0];
      if (!previous) problem("agreement_document_missing", "This document is unavailable.", 404);
      row = previous;
    }
    const kind = req.params.kind;
    if (publicAccess && kind === "audit") problem("agreement_document_private", "Detailed audit records are staff-only.", 403);
    const assetId = kind.startsWith("contract-") ? kind.slice(9) : null;
    if (assetId && !row.snapshot.documents.some((doc) => doc.asset_id === assetId)) problem("agreement_document_missing", "This document is unavailable.", 404);
    if(publicAccess&&!['quote','terms','signed','scope-certificate','packet'].includes(kind)&&!assetId)problem('agreement_document_missing','This document is unavailable.',404);
    const output = (await pool.query(`SELECT id,bytes,sha256 FROM agreement_artifacts WHERE agreement_id=$1 AND kind=$2`, [row.id, kind])).rows[0];
    if (output) {
      let bytes=output.bytes;
      if(publicAccess && !(kind === "quote" && row.snapshot.quote_pdf_source === "client_export") && (role!=='customer'||row.token_generation!==1)){
        const cached=(await pool.query('SELECT bytes FROM agreement_artifact_deliveries WHERE artifact_id=$1 AND role=$2 AND token_generation=$3',[output.id,role,row.token_generation])).rows[0];
        if(cached)bytes=cached.bytes;
        else{
          bytes=await qualifyAgreementDocumentLinks(output.bytes,{agreement_id:row.id,link_root_id:row.link_root_id,customer_url:service.customerURL(row,role)});
          if(bytes!==output.bytes){
            await pool.query('INSERT INTO agreement_artifact_deliveries(artifact_id,role,token_generation,bytes,sha256,source_sha256) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING',[output.id,role,row.token_generation,bytes,agreementBytesHash(bytes),output.sha256]);
            bytes=(await pool.query('SELECT bytes FROM agreement_artifact_deliveries WHERE artifact_id=$1 AND role=$2 AND token_generation=$3',[output.id,role,row.token_generation])).rows[0].bytes;
          }
        }
      }
      return res.type("application/pdf").set("Content-Disposition", `inline; filename="quote-${row.number}-${kind}.pdf"`).send(bytes);
    }
    if (assetId) {
      const doc = row.snapshot.documents.find((item) => item.asset_id === assetId);
      const asset = (await pool.query(`SELECT normalized_bytes FROM agreement_assets WHERE id=$1 AND company_id=$2`, [assetId, row.company_id])).rows[0];
      const signatures=(await pool.query('SELECT field_values FROM agreement_signatures WHERE agreement_id=$1 ORDER BY submitted_at,id',[row.id])).rows;
      const submittedValues=Object.assign({},doc.prefilled_values,...signatures.map(signature=>signature.field_values));
      return res.type("application/pdf").send(await populateAgreementPDF(asset.normalized_bytes, doc.fields, submittedValues));
    }
    problem("agreement_document_processing", "This document is still being prepared. Your submitted agreement remains saved.", 409);
  };
  app.get("/api/agreements/:id/documents/:kind", ...staff("quotes.view"), wrap((req, res) => artifact(req, res, false)));
  app.get("/api/public/agreements/:token/metadata", wrap(async (req, res) => {
    const { row } = await service.loadPublic(pool, req.params.token);
    res.json({ title: `${row.snapshot.estimate_label||'Estimate'} from ${row.snapshot.business.name || "your service provider"}`, business_name: row.snapshot.business.name, logo_data_url: row.snapshot.business.logo_data_url });
  }));
  app.get("/api/public/agreements/:token", wrap(async (req, res) => {
    const { row, role } = await service.loadPublic(pool, req.params.token);
    res.json({ ...await service.detail(pool, row, {publicRole:role}), viewer_role: role });
  }));
  app.get("/api/public/agreements/:token/history/:historyID/documents/:kind", wrap((req, res) => artifact(req, res, true)));
  app.get("/api/public/agreements/:token/documents/:kind", wrap((req, res) => artifact(req, res, true)));
  app.post("/api/public/agreements/:token/session", publicWrite, wrap(async (req, res) => res.json(await service.publicSession(req.params.token, req.body))));
  app.post("/api/public/agreements/:token/sign", publicWrite, wrap(async (req, res) => res.json(await service.sign(req.params.token, req.body, { ip: req.ip, user_agent: req.get("user-agent") || "" }))));
  app.post("/api/public/agreements/:token/addons", publicWrite, wrap(async (req,res) => res.json(await service.selectAddons(req.params.token,req.body))));
  app.post("/api/public/agreements/:token/decision", publicWrite, wrap(async (req, res) => res.json(await service.decision(req.params.token, req.body))));
  app.post("/api/public/agreements/:token/observed-open", publicWrite, wrap(async (req, res) => {
    const { row, role } = await service.loadPublic(pool, req.params.token);
    if (/bot|crawler|spider|preview|facebookexternalhit|whatsapp|slackbot|twitterbot|linkedinbot/i.test(req.get("user-agent") || "")) return res.json({ recorded: false });
    await service.rate(pool, `observed-open:${row.id}`, 60, 3600);
    await service.event(pool, row.id, "observed_open", { request_id: uuid(req.body.request_id), request_hash: quoteContentHash({ role, observation: "visible_page" }), actor_type: "unverified_visitor", actor_id: role, payload: { observation: "visible_page", identity_verified: false } });
    res.json({ recorded: true });
  }));
  app.post("/api/public/agreements/:token/draft", publicWrite, wrap(async (req, res) => {
    const result = await transaction(pool, async (db) => {
      const { row, role } = await service.loadPublic(db, req.params.token, true);
      if (!(await service.state(db, row)).can_sign) problem("agreement_not_signable", "This version is no longer editable.", 409);
      const current = await service.session(db, row, role, req.body.session_token);
      const values = req.body.values;
      if (!values || Array.isArray(values) || typeof values !== "object" || Buffer.byteLength(safeJSON(values)) > 100000) problem("agreement_draft_invalid", "The signing draft is too large or invalid.");
      await db.query(`UPDATE agreement_signing_sessions SET draft_values=$2::jsonb WHERE id=$1`, [current.id, safeJSON(values)]);
      if (!(await db.query(`SELECT 1 FROM agreement_events WHERE agreement_id=$1 AND type='draft_progress' AND payload->>'session_id'=$2`, [row.id, current.id])).rowCount) await service.event(db, row.id, "draft_progress", { actor_type: "customer", actor_id: role, payload: { session_id: current.id, submission_complete: false } });
      return { status: "submission_incomplete" };
    });
    res.json(result);
  }));
  app.post("/api/public/agreements/:token/notes", publicWrite, wrap(async (req, res) => {
    const saved=await transaction(pool,async(db)=>{
      const preliminary=await service.loadPublic(db,req.params.token);
      await lockCompanySchedule(db,preliminary.row.company_id);
      const { row, role } = await service.loadPublic(db, req.params.token,true);
      if (!row.snapshot.customer_notes_enabled) problem("agreement_notes_disabled", "Customer notes are not enabled for this estimate.", 403);
      await service.rate(db, `notes:${row.id}`, 20, 3600);
      const message = quoteText(req.body.message, "Customer note", row.snapshot.customer_notes_limit||5000).trim();
      if (!message) problem("agreement_note_required", "Enter a note.");
      const entry=await service.event(db, row.id, "customer_note", { request_id: uuid(req.body.request_id), request_hash: quoteContentHash({ message }), actor_type: "customer", actor_id: role, payload: { message } });
      const notes=(await db.query(`SELECT e.id,e.created_at,e.actor_id AS signer_role,e.payload->>'message' AS message FROM agreement_events e JOIN quote_agreements a ON a.id=e.agreement_id WHERE a.company_id=$1 AND a.quote_id=$2 AND e.type='customer_note' ORDER BY e.created_at,e.id`,[row.company_id,row.quote_id])).rows;
      await db.query('UPDATE schedule_events SET customer_note_entries=$3::jsonb,updated_at=now() WHERE company_id=$1 AND quote_id=$2',[row.company_id,row.quote_id,safeJSON(notes)]);
      return entry;
    });
    res.json({ id: saved.id, saved: true });
  }));
  let timer;
  if (startWorker) { timer = setInterval(() => service.processDocumentJobs().catch(() => console.error("[agreements] document worker failed")), 15000); timer.unref(); }
  service.stop = () => clearInterval(timer);
  return service;
}
