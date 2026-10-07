import { randomUUID } from "node:crypto";
import { QuoteContractError, calculateQuotePricing, normalizeQuoteLines, quoteContentHash, quoteInteger } from "./quote-contract-domain.js";
import { resolveAgreementText, generateQuoteAgreementPDF, combineAgreementPDFs } from "./quote-agreement-documents.js";
import { assertQuoteReferences } from "./services-catalog.js";

const fail = (code, message, status = 409) => { throw new QuoteContractError(code, message, status); };
const uuid = value => typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
const money = cents => new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(cents / 100);

// Staff scheduling a quote uses the selected issued scope even if an older
// client still sends the original editable draft. Existing bound jobs keep the
// specific revision they were created from until an explicit amendment.
export async function selectedQuoteScheduleScope(db,{companyId,quoteId,previous,start,end,requestedServiceItems}) {
  if (!companyId || !(quoteId || previous?.agreement_id)) return null;
  if (!(await db.query("SELECT to_regclass('quote_agreements') IS NOT NULL AS present")).rows[0].present) return null;
  const targetQuote = previous?.quote_id || quoteId;
  if (targetQuote) {
    const quote = (await db.query("SELECT id,deleted_at FROM quotes WHERE id=$1 AND company_id=$2 FOR UPDATE",[targetQuote,companyId])).rows[0];
    if (!quote || (quote.deleted_at && previous?.quote_id !== targetQuote)) fail("quote_not_found", "This quote was removed. Select an active quote for new work.", 404);
  }
  const row = previous?.agreement_id
    ? (await db.query("SELECT * FROM quote_agreements WHERE id=$1 AND company_id=$2",[previous.agreement_id,companyId])).rows[0]
    : (await db.query("SELECT * FROM quote_agreements WHERE quote_id=$1 AND company_id=$2 ORDER BY revision DESC LIMIT 1",[quoteId,companyId])).rows[0];
  if (!row?.snapshot.pricing || row.snapshot.kind!=="quote") return null;
  if (previous?.agreement_id && quoteId !== row.quote_id) fail("quote_job_scope_locked","Keep this appointment linked to its accepted estimate. Issue an amendment to change its scope.");
  if (row.snapshot.optional_addons?.length && row.snapshot.addon_selection_finalized !== true) fail("quote_addon_selection_required","Finalize the optional services on the customer estimate before scheduling its scope.");
  if (!previous && (row.revoked_at || ["declined","superseded"].includes(row.decision))) fail("quote_job_scope_unavailable","Issue a current estimate before scheduling this selected scope.");
  const duration=(new Date(end)-new Date(start))/60000;
  if(duration<row.snapshot.duration_minutes) fail("quote_job_duration_required",`Allow at least ${row.snapshot.duration_minutes} minutes for this estimate's selected services.`);
  let items=row.snapshot.pricing.line_items;
  if(previous?.service_plan_id && Array.isArray(requestedServiceItems) && (await db.query("SELECT to_regclass('agreement_plan_jobs') IS NOT NULL AS present")).rows[0].present && (await db.query('SELECT 1 FROM agreement_plan_jobs WHERE job_id=$1 AND company_id=$2',[previous.id,companyId])).rowCount) {
    const requested=normalizeQuoteLines(requestedServiceItems.map(line=>({...line,price_cents:line.price_cents??line.priceCents})));
    if(items.some(line=>!requested.some(candidate=>candidate.id===line.id && candidate.qty===line.qty && candidate.service_id===line.service_id))) fail('quote_job_scope_locked','Keep the accepted quote services and quantities. Add extra services to this job, or issue an amendment to replace the original scope.');
    const ids=new Set(items.map(line=>line.id));items=[...items,...requested.filter(line=>!ids.has(line.id))];
  }
  return {agreement_id:row.id,quote_id:row.quote_id,contact_id:row.contact_id,service_items:items,services:items.map(line=>line.name),price_cents:previous?.agreement_id?previous.price_cents:row.snapshot.pricing.total_cents};
}

// Issued alternatives and their raw merge sources are frozen in the original
// packet. Selection never reads mutable quote prices, branding or templates.
export function createQuoteAddonSelection({ pool, service }) {
  return async function selectAddons(token, raw = {}) {
    if (!uuid(raw.request_id) || typeof raw.packet_hash !== "string" || !Array.isArray(raw.selected_addon_ids) || raw.selected_addon_ids.length > 50 || raw.selected_addon_ids.some(id => !uuid(id))) fail("quote_addon_selection_invalid", "Submit the current packet and selected option IDs.", 400);
    if (Object.keys(raw).some(key => !["request_id", "packet_hash", "selected_addon_ids"].includes(key))) fail("quote_addon_selection_invalid", "Only the offered option IDs may be submitted.", 400);
    const selected = raw.selected_addon_ids.map(id => id.toLowerCase()).sort();
    if (new Set(selected).size !== selected.length) fail("quote_addon_selection_invalid", "Each optional service may be selected once.", 400);
    const initial = await service.loadPublic(pool, token);
    if (initial.role !== "customer") fail("quote_addon_primary_customer_required", "The primary customer must finalize the optional services.", 403);
    await service.rate(pool, `quote-addons:${initial.row.id}`, 30, 3600);
    const requestHash = quoteContentHash({ packet_hash: raw.packet_hash, selected_addon_ids: selected });
    const db = await pool.connect();
    try {
      await db.query("BEGIN");
      // Same first lock as staff publication. Signature submission holds the
      // source row, so either selection wins or the signed packet is retained.
      await db.query("SELECT id FROM quotes WHERE id=$1 AND (company_id=$2 OR (company_id IS NULL AND user_id=$3)) FOR UPDATE", [initial.row.quote_id, initial.row.company_id, initial.row.created_by]);
      const { row, role } = await service.loadPublic(db, token, true);
      const prior = (await db.query("SELECT * FROM agreement_events WHERE agreement_id=$1 AND request_id=$2", [row.id, raw.request_id])).rows[0];
      if (prior) {
        if (prior.type !== "addons_selected" || prior.request_hash !== requestHash) fail("agreement_request_conflict", "This request ID was already used for different content.");
        const result = (await db.query("SELECT * FROM quote_agreements WHERE id=$1 AND company_id=$2", [prior.payload.agreement_id, row.company_id])).rows[0];
        if (!result) fail("agreement_not_found", "The selected agreement is unavailable.", 404);
        const response = { agreement: await service.detail(db, result, {publicRole:role}), customer_url: service.customerURL(result, role) };
        await db.query("COMMIT"); return response;
      }
      const source = row.snapshot.addon_source;
      if (!row.quote_id || !source || !row.snapshot.optional_addons?.length) fail("quote_addons_not_offered", "This estimate does not offer optional services.");
      const latest = (await db.query("SELECT id FROM quote_agreements WHERE company_id=$1 AND quote_id=$2 ORDER BY revision DESC LIMIT 1", [row.company_id,row.quote_id])).rows[0];
      if (latest?.id !== row.id || row.packet_hash !== raw.packet_hash) fail("agreement_version_changed", "Reload and review the current estimate before choosing optional services.");
      if (row.decision !== "published" || row.revoked_at || new Date(row.expires_at) <= new Date()) fail("quote_addon_selection_closed", "This estimate no longer accepts changes. Contact the business.");
      if ((await db.query("SELECT 1 FROM agreement_signatures WHERE agreement_id=$1 LIMIT 1", [row.id])).rowCount) fail("quote_addon_already_signed", "A signer has already accepted this packet. Ask the business to issue a revised estimate.");
      const payments = service.paymentSummary ? await service.paymentSummary(db,row) : null;
      const booking = service.bookingSummary ? await service.bookingSummary(db,row) : null;
      if (payments && (payments.paid_cents > 0 || payments.processing || payments.payment_review_required) || booking?.booking_id) fail("quote_addon_selection_closed", "This estimate already has a payment or appointment. Contact the business for a revision.");
      const offered = new Map(row.snapshot.optional_addons.map(item => [item.id,item]));
      if (selected.some(id => !offered.has(id))) fail("quote_addon_not_offered", "Choose only the optional services in this estimate.", 400);
      const chosen = row.snapshot.optional_addons.filter(item => selected.includes(item.id));
      const lines = [...source.base_line_items,...chosen];
      await assertQuoteReferences(db, { companyId: row.company_id, userId: row.created_by }, { contact_id: row.contact_id, line_items: lines, existing_lines: [...source.base_line_items,...row.snapshot.optional_addons] });
      const pricing = calculateQuotePricing({ ...source.pricing_inputs, line_items: lines });
      const duration = quoteInteger(source.base_duration_minutes + chosen.reduce((sum,item) => sum+item.duration_minutes,0), "Selected job duration in minutes", 10080, 1);
      if (pricing.deposit_cents > 0) {
        if (!service.paymentReady) fail("agreement_payment_not_ready", "Payment setup is unavailable. Contact the business.");
        await service.validatePaymentReadiness(db,row.company_id,pricing.deposit_cents);
      }
      if (row.snapshot.allow_customer_booking) {
        if (!service.bookingReady) fail("agreement_booking_not_ready", "Booking setup is unavailable. Contact the business.");
        await service.validateBookingReadiness(db,row.company_id,{quote_id:row.quote_id,duration_minutes:duration,line_items:pricing.line_items});
      }
      const id = randomUUID(), issuedAt = new Date().toISOString();
      const values = { ...source.merge_values, issue_date: issuedAt, services: pricing.line_items.map(line => `${line.name}\n${line.description}`).join("\n\n"), subtotal: money(pricing.subtotal_cents), tax: money(pricing.tax_cents), total: money(pricing.total_cents), deposit: money(pricing.deposit_cents), balance: money(pricing.balance_after_deposit_cents) };
      const snapshot = { ...row.snapshot, revision: row.revision+1, issued_at: issuedAt, pricing, duration_minutes: duration, selected_addon_ids: selected, addon_selection_finalized: true,
        agreement_text: resolveAgreementText(source.content.agreement_text,values), terms_text: resolveAgreementText(source.content.terms_text,values), consent_text: resolveAgreementText(source.content.consent_text,values), documents: await service.validateDocuments(db,row.company_id,source.content,values) };
      if (snapshot.documents.some((document,index) => document.sha256 !== row.snapshot.documents[index]?.sha256)) fail("agreement_asset_changed", "A document changed. Ask the business for a fresh estimate.");
      if (snapshot.quote_position === "excluded") snapshot.scope_reference_hash = quoteContentHash({number:row.number,revision:snapshot.revision,pricing,public_notes:snapshot.public_notes,scope_exclusions:snapshot.scope_exclusions});
      const conflictingRequest = (await db.query("SELECT 1 FROM quote_agreements WHERE company_id=$1 AND request_id=$2", [row.company_id,raw.request_id])).rowCount;
      if (conflictingRequest) fail("agreement_request_conflict", "This request ID was already used for another publication.");
      const created = (await db.query(`INSERT INTO quote_agreements(id,company_id,quote_id,contact_id,created_by,number,revision,predecessor_id,request_id,title,snapshot,packet_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13) RETURNING *`, [id,row.company_id,row.quote_id,row.contact_id,row.created_by,row.number,snapshot.revision,row.id,raw.request_id,row.title,JSON.stringify(snapshot),quoteContentHash(snapshot),row.expires_at])).rows[0];
      await service.storeArtifact(db,id,"quote",await generateQuoteAgreementPDF(snapshot,{customer_url:service.customerURL(created)}));
      if (snapshot.terms_text || snapshot.terms_document) {
        const cover = await generateQuoteAgreementPDF({...snapshot,title:"Terms & Conditions",pricing:null,agreement_text:"",public_notes:"",scope_exclusions:"",documents:[],consent_text:""},{customer_url:service.customerURL(created)});
        const asset = snapshot.terms_document ? (await db.query("SELECT normalized_bytes,normalized_sha256 FROM agreement_assets WHERE id=$1 AND company_id=$2",[snapshot.terms_document.asset_id,row.company_id])).rows[0] : null;
        if (snapshot.terms_document && asset?.normalized_sha256 !== snapshot.terms_document.sha256) fail("agreement_asset_changed", "The terms document changed. Ask the business for a fresh estimate.");
        await service.storeArtifact(db,id,"terms",asset ? await combineAgreementPDFs([cover,asset.normalized_bytes]) : cover);
      }
      await db.query("UPDATE quote_agreements SET decision='superseded',updated_at=now() WHERE id=$1",[row.id]);
      await service.event(db,row.id,"addons_selected",{actor_type:"customer",actor_id:role,request_id:raw.request_id,request_hash:requestHash,payload:{agreement_id:id,selected_addon_ids:selected}});
      await service.event(db,id,"addon_revision_created",{actor_type:"customer",actor_id:role,payload:{predecessor_id:row.id,selected_addon_ids:selected}});
      const response = { agreement: await service.detail(db,created,{publicRole:role}), customer_url: service.customerURL(created,role) };
      await db.query("COMMIT"); return response;
    } catch (error) { await db.query("ROLLBACK"); throw error; }
    finally { db.release(); }
  };
}
