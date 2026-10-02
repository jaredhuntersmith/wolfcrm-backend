import { randomUUID } from "node:crypto";
import { QuoteContractError, quoteContentHash, calculateQuotePricing, calculatePlanOffer } from "./quote-contract-domain.js";
import { buildPlanOffer } from "./agreement-plans-domain.js";

const fail = (code, message) => { throw new QuoteContractError(code, message, 409); };
export function installPlanQuotePublication(service, supportedBillingModes, plans) {
  service.preparePlanQuoteRevision = async (db, req, quote) => {
    if (!quote.id) return;
    // Publication owns the same payment-scope lock as activation. An unsigned
    // direct enrollment can be superseded atomically, including back to one-time.
    const prior = (await db.query(`SELECT * FROM agreement_plan_enrollments WHERE company_id=$1 AND collection_key=$2
      AND base_agreement_id=plan_agreement_id AND canceled_at IS NULL FOR UPDATE`, [req.companyId, `quote:${quote.id}`])).rows[0];
    if (!prior) return;
    const signed = (await db.query("SELECT 1 FROM agreement_signatures WHERE agreement_id=$1 LIMIT 1", [prior.plan_agreement_id])).rowCount;
    if (signed || prior.service_plan_id || prior.stripe_payment_method_id || prior.connected_account_id) {
      fail("plan_quote_already_issued", "This plan already has signatures or payment setup. Manage or cancel that enrollment before replacing its plan terms; its signed agreement and charges remain preserved.");
    }
    await db.query("UPDATE agreement_plan_enrollments SET state='canceled',canceled_at=now(),updated_at=now() WHERE id=$1", [prior.id]);
    await service.event(db, prior.plan_agreement_id, "unsigned_plan_revised", {actor_type:"staff",actor_id:req.userId,payload:{enrollment_id:prior.id}});
  };
  service.preparePlanQuote = async (db, req, { quote, content, pricing, options, settings }) => {
    if (!content.plan_tier_id) return null;
    if (!quote.id) fail("plan_quote_scope_required", "Create a quote with the covered services before choosing a plan tier.");
    const tier = (await db.query("SELECT * FROM service_plan_tiers WHERE company_id=$1 AND tier_id=$2 ORDER BY version DESC LIMIT 1", [req.companyId, content.plan_tier_id])).rows[0];
    if (!tier || tier.archived_at) fail("plan_tier_unavailable", "Choose an available saved service plan tier.");
    if (!supportedBillingModes.includes(tier.configuration.billing.mode)) fail("plan_billing_unavailable", "This tier’s billing is not available yet.");
    const existing = (await db.query("SELECT id,service_plan_id FROM agreement_plan_enrollments WHERE company_id=$1 AND collection_key=$2 AND canceled_at IS NULL", [req.companyId, `quote:${quote.id}`])).rows[0];
    if (existing) fail("plan_quote_already_issued", "This quote already has a plan enrollment. Manage or cancel that enrollment before issuing replacement plan terms; its signed agreement and charges must remain preserved.");
    const catalog = (await db.query("SELECT id FROM saved_services WHERE company_id=$1 AND plan_eligible AND archived_at IS NULL", [req.companyId])).rows;
    const company = (await db.query("SELECT timezone FROM companies WHERE id=$1", [req.companyId])).rows[0];
    const today = new Intl.DateTimeFormat("en-CA", {timeZone: company?.timezone || "America/New_York",year:"numeric",month:"2-digit",day:"2-digit"}).format(new Date());
    // Hidden tiers may be intentionally sent as direct plan quotes by staff.
    let offer = buildPlanOffer({ agreement: { id:quote.id, packet_hash:quoteContentHash(pricing), snapshot:{pricing,discount_stacking_policy:settings.discount_stacking_policy} }, tier:{...tier,configuration:{...tier.configuration,visible:true}}, eligible_service_ids:catalog.map(row=>row.id), today });
    if (!offer) fail("plan_scope_required", "Add at least one saved service eligible for this plan tier.");
    offer=await plans.withReplacement(db,{company_id:req.companyId,contact_id:quote.contact_id},offer);
    if(!offer) fail("plan_already_current","This customer already has this tier. Use their existing membership for recurring visits.");
    if(offer.switch_unavailable) fail("plan_switch_review_required",offer.switch_unavailable);
    const price = {...offer.current_pricing};
    const deposit = calculateQuotePricing({line_items:[{id:randomUUID(),name:"Plan quote",qty:1,price_cents:price.total_cents}],deposit:options.deposit}).deposit_cents;
    price.deposit_cents=deposit; price.balance_after_deposit_cents=price.total_cents-deposit;
    // The discount is already in this quote, so activation must not apply it again.
    offer.price_in_quote = true;
    offer.financial_text = offer.financial_text.replace('This adjustment takes effect only after all required plan signatures, required payment-method setup and initial payment succeed. Until activation, the initial job retains its original balance. No refund is issued automatically.', 'The plan discount is included in this quote. Card setup and activation are required before this job can be paid or booked. The discount is not applied a second time at activation.');
    delete offer.offer_hash;
    offer.offer_hash = quoteContentHash(offer);
    const agreement = offer.configuration.agreement;
    return { offer, pricing:price, content:{...content, ...Object.fromEntries(["agreement_mode","require_page_signature","agreement_text","consent_text","documents","required_signers"].map(key=>[key,agreement[key]])), show_agreement:true} };
  };
  service.createPlanQuoteEnrollment = async (db, row) => {
    const offer = row.snapshot.plan_quote;
    if (!offer) return;
    const enrollmentID = randomUUID();
    await db.query(`INSERT INTO agreement_plan_enrollments(id,company_id,contact_id,base_agreement_id,plan_agreement_id,tier_id,tier_version,collection_key,request_id,request_hash,offer_hash,snapshot)
      VALUES($1,$2,$3,$4,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)`, [enrollmentID,row.company_id,row.contact_id,row.id,offer.tier_id,offer.tier_version,`quote:${row.quote_id}`,row.request_id,quoteContentHash({agreement_id:row.id,offer_hash:offer.offer_hash}),offer.offer_hash,JSON.stringify(offer)]);
  };
  service.planQuoteReady = async (db,row) => !row.snapshot.plan_quote || Boolean((await db.query("SELECT 1 FROM agreement_plan_enrollments WHERE company_id=$1 AND plan_agreement_id=$2 AND service_plan_id IS NOT NULL AND activated_at IS NOT NULL",[row.company_id,row.id])).rowCount);
}

export async function priceQuoteForPlan(db, companyID, pricing, options) {
  const tierID=options.template?.content?.plan_tier_id;
  if(!tierID) return pricing;
  const tier=(await db.query("SELECT configuration,archived_at FROM service_plan_tiers WHERE company_id=$1 AND tier_id=$2 ORDER BY version DESC LIMIT 1",[companyID,tierID])).rows[0];
  if(!tier || tier.archived_at) fail("plan_tier_unavailable","Choose an available saved plan tier.");
  const catalog=(await db.query("SELECT id FROM saved_services WHERE company_id=$1 AND plan_eligible AND archived_at IS NULL",[companyID])).rows;
  const settings=(await db.query("SELECT discount_stacking_policy FROM quote_settings WHERE company_id=$1",[companyID])).rows[0];
  const offer=calculatePlanOffer({line_items:pricing.line_items,quoted_pricing:pricing,tax_rate_basis_points:pricing.tax_rate_basis_points,tax_inclusive:pricing.tax_inclusive,eligible_service_ids:catalog.map(row=>row.id),tier:tier.configuration,discount_stacking_policy:settings?.discount_stacking_policy || "best_price"});
  if(!offer) fail("plan_scope_required","Add a saved service eligible for this plan tier.");
  const deposit=calculateQuotePricing({line_items:[{name:"Plan quote",qty:1,price_cents:offer.current_total_cents}],deposit:options.deposit}).deposit_cents;
  return {...offer.current_pricing,deposit_cents:deposit,balance_after_deposit_cents:offer.current_total_cents-deposit};
}
