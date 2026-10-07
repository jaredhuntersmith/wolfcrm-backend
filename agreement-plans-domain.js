import { QuoteContractError, quoteInteger, quoteText, normalizeDeposit, calculatePlanOffer, calculatePlanInstallments, quoteContentHash } from './quote-contract-domain.js';
import { normalizeAgreementContent } from './quote-agreements.js';

const fail = (code, message) => { throw new QuoteContractError(code, message); };
const id = (value) => { if (typeof value !== 'string' || !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(value)) fail('plan_service_invalid', 'Choose saved services from this company.'); return value.toLowerCase(); };
const amount = (value) => new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(value / 100);
const boolean = (raw, key, fallback = false) => { if (raw[key] !== undefined && typeof raw[key] !== 'boolean') fail('plan_tier_invalid', `${key} must be true or false.`); return raw[key] ?? fallback; };
export const PLAN_BILLING_MODES = ['manual_per_visit', 'automatic_per_visit', 'calendar_installments', 'calendar_recurring', 'prepaid'];
export function normalizePlanInterval(raw = { unit: 'month', count: 3 }) {
  if (!raw || !['day', 'week', 'month', 'year'].includes(raw.unit)) fail('plan_interval_invalid', 'Choose a day, week, month or year interval.');
  return { unit: raw.unit, count: quoteInteger(raw.count, 'Interval count', raw.unit === 'day' ? 3650 : 120, 1) };
}
export function normalizePlanTier(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) fail('plan_tier_invalid', 'Provide a plan tier.');
  const name = quoteText(raw.name, 'Tier name', 120).trim();
  if (!name) fail('plan_name_required', 'Name this service plan tier.');
  const benefits = raw.benefits ?? [];
  if (!Array.isArray(benefits) || benefits.length > 30) fail('plan_benefits_invalid', 'Use up to 30 benefits.');
  const serviceIDs = raw.service_ids == null ? null : raw.service_ids;
  if (serviceIDs !== null && (!Array.isArray(serviceIDs) || serviceIDs.length > 500 || !serviceIDs.length)) fail('plan_services_required', 'Choose a service subset or all globally eligible services.');
  const term = raw.term ?? { kind: 'ongoing' };
  if (!['finite', 'ongoing'].includes(term.kind)) fail('plan_term_invalid', 'Choose a finite package or ongoing plan.');
  const billing = raw.billing ?? { mode: 'manual_per_visit' };
  if (!PLAN_BILLING_MODES.includes(billing.mode)) fail('plan_billing_invalid', 'Choose a supported billing mode.');
  if (term.kind !== 'finite' && ['calendar_installments', 'prepaid'].includes(billing.mode)) fail('plan_finite_term_required', 'Installments and prepaid packages need an explicit included visit count.');
  if (billing.mode === 'calendar_recurring' && term.kind !== 'ongoing') fail('plan_ongoing_required', 'Recurring calendar billing requires an ongoing plan. Use installments for a finite package.');
  if (billing.mode === 'calendar_recurring' && billing.calendar_requires_completed_service && JSON.stringify(normalizePlanInterval(billing.interval)) !== JSON.stringify(normalizePlanInterval(raw.service_interval))) fail('plan_calendar_cadence_mismatch', 'For calendar charges held until job completion, use the same billing and service frequency. Each charge covers one completed visit.');
  const content = normalizeAgreementContent(raw.agreement || {});
  if (!content.consent_text.trim() || (!(content.show_agreement && content.agreement_mode === "text" && content.agreement_text.trim()) && !(content.show_agreement && content.agreement_mode === "pdf" && content.documents.length))) fail('plan_agreement_required', 'Configure plan agreement text or a PDF and explicit signing consent.');
  const policy = quoteText(raw.cancellation_policy, 'Cancellation and renewal terms', 10000).trim();
  if (!policy) fail('plan_policy_required', 'State cancellation, renewal and price-change terms before offering this tier.');
  return {
    name, pitch: quoteText(raw.pitch, 'Plan pitch', 500), learn_more: quoteText(raw.learn_more, 'Plan details', 20000),
    benefits: benefits.map((benefit) => quoteText(benefit, 'Benefit', 500)),
    service_ids: serviceIDs === null ? null : [...new Set(serviceIDs.map(id))],
    visible: boolean(raw, 'visible', true), recommended: boolean(raw, 'recommended'), sort_order: quoteInteger(raw.sort_order ?? 0, 'Display order', 100000),
    discount: normalizeDeposit(raw.discount ?? { type: 'none', value: 0 }), discount_first_visit: boolean(raw, 'discount_first_visit'), current_visit_counts: boolean(raw, 'current_visit_counts'),
    service_interval: normalizePlanInterval(raw.service_interval),
    term: { kind: term.kind, visit_count: term.kind === 'finite' ? quoteInteger(term.visit_count, 'Included visits', 1000, 1) : null },
    billing: { mode: billing.mode, save_payment_method: boolean(billing, 'save_payment_method'), calendar_requires_completed_service: boolean(billing, 'calendar_requires_completed_service'), first_charge_date: billing.first_charge_date ? planDate(billing.first_charge_date).toISOString().slice(0,10) : null, interval: normalizePlanInterval(billing.interval ?? { unit: 'month', count: 1 }), installment_count: billing.mode === 'calendar_installments' ? quoteInteger(billing.installment_count, 'Installment count', 1200, 1) : 1,
      first_charge_delay_days: quoteInteger(billing.first_charge_delay_days ?? 0, 'First charge delay', 3650), enrollment_fee_cents: quoteInteger(billing.enrollment_fee_cents ?? 0, 'Enrollment fee'),
      collect_on: (() => { if (billing.collect_on !== undefined && !['scheduled','completed'].includes(billing.collect_on)) fail('plan_collection_timing_invalid', 'Collect when a visit is scheduled or completed.'); return billing.collect_on || 'completed'; })() },
    start_delay_days: quoteInteger(raw.start_delay_days ?? 0, 'Plan start delay', 3650), first_service_delay_days: raw.first_service_delay_days == null ? null : quoteInteger(raw.first_service_delay_days, 'First future service delay', 3650, 1),
    allow_after_service: boolean(raw, 'allow_after_service', true), allow_pause: boolean(raw, 'allow_pause'), allow_skip: boolean(raw, 'allow_skip'),
    cancellation_notice_days: quoteInteger(raw.cancellation_notice_days ?? 0, 'Cancellation notice', 365), cancellation_policy: policy,
    renewal: term.kind === 'ongoing' ? 'ongoing_until_canceled' : 'ends_after_included_visits', price_change_policy: 'new_signed_agreement_required', currency: 'usd', agreement: content,
  };
}

export function planDate(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) fail('plan_date_invalid', 'Use a calendar date in YYYY-MM-DD format.');
  const date = new Date(`${value}T12:00:00Z`);
  if (!Number.isFinite(date.getTime()) || date.toISOString().slice(0, 10) !== value) fail('plan_date_invalid', 'Choose an existing calendar date.');
  return date;
}
export function advancePlanDate(dateString, interval, occurrence = 1) {
  const date = planDate(dateString), { unit, count } = normalizePlanInterval(interval);
  quoteInteger(occurrence, 'Occurrence', 3650);
  if (unit === 'day' || unit === 'week') date.setUTCDate(date.getUTCDate() + count * occurrence * (unit === 'week' ? 7 : 1));
  else {
    const day = date.getUTCDate(); date.setUTCDate(1);
    date.setUTCMonth(date.getUTCMonth() + count * occurrence * (unit === 'year' ? 12 : 1));
    const lastDay = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 1, 0)).getUTCDate();
    date.setUTCDate(Math.min(day, lastDay));
  }
  return date.toISOString().slice(0, 10);
}
const cadence = (interval) => `every ${interval.count} ${interval.unit}${interval.count === 1 ? '' : 's'}`;

export function buildPlanOffer({ agreement, tier, eligible_service_ids, payments_cents = 0, today, serviced = false,prior_adjustment_cents=0,initial_visit_already_counted=false }) {
  const config = normalizePlanTier(tier.configuration);
  if (!config.visible || (serviced && !config.allow_after_service)) return null;
  const contactCollection = config.billing.mode === 'automatic_per_visit';
  if (contactCollection) { config.billing.collect_on = 'completed'; config.discount_first_visit = true; }
  const pricing = agreement.snapshot.pricing;
  if (!pricing) return null;
  const calculation = calculatePlanOffer({ line_items: pricing.line_items, eligible_service_ids, tier: config, payments_cents, tax_rate_basis_points: pricing.tax_rate_basis_points, tax_inclusive: pricing.tax_inclusive,quoted_pricing:pricing,discount_stacking_policy:agreement.snapshot.discount_stacking_policy||'best_price' });
  if (!calculation) return null;
  const priorAdjustment=Math.min(calculation.original_total_cents,quoteInteger(prior_adjustment_cents,'Prior signed adjustment'));
  calculation.current_adjustment_cents=Math.max(0,calculation.current_adjustment_cents-priorAdjustment);
  calculation.current_total_cents=calculation.original_total_cents-priorAdjustment-calculation.current_adjustment_cents;
  calculation.current_balance_cents=Math.max(0,calculation.current_total_cents-payments_cents);
  calculation.credit_due_cents=Math.max(0,payments_cents-calculation.current_total_cents);
  const effectiveDate = advancePlanDate(today, { unit: 'day', count: 1 }, config.start_delay_days);
  const appointmentAnchored = ['automatic_per_visit', 'manual_per_visit'].includes(config.billing.mode);
  const nextService = config.first_service_delay_days === null ? (appointmentAnchored ? effectiveDate : advancePlanDate(effectiveDate, config.service_interval)) : advancePlanDate(effectiveDate, { unit: 'day', count: 1 }, config.first_service_delay_days);
  let firstCharge = config.billing.first_charge_date || advancePlanDate(effectiveDate, { unit: 'day', count: 1 }, config.billing.first_charge_delay_days);
  if (config.billing.first_charge_date && firstCharge < effectiveDate) { let occurrence=0; const anchor=firstCharge; do { firstCharge=advancePlanDate(anchor, config.billing.interval, ++occurrence); } while(firstCharge < effectiveDate && occurrence < 3650); if(firstCharge < effectiveDate) fail('plan_charge_date_invalid','Choose a more recent first billing date.'); }
  const countedCurrent = !contactCollection && config.current_visit_counts && !initial_visit_already_counted && config.term.kind === 'finite' ? 1 : 0;
  const futureCount = config.term.kind === 'finite' ? config.term.visit_count - countedCurrent : null;
  // The initial visit remains on the initial job invoice. When it counts toward
  // a finite package, its complete agreed visit price is excluded from package
  // billing, whether already paid or still owed on that invoice.
  const priorAllocation = countedCurrent * calculation.future_visit.total_cents;
  const installments = config.term.kind === 'finite' ? calculatePlanInstallments({ visit_price_cents: calculation.future_visit.total_cents, visit_count: config.term.visit_count, installment_count: config.billing.mode === 'calendar_installments' ? config.billing.installment_count : 1, prior_credit_cents: priorAllocation, enrollment_fee_cents: config.billing.enrollment_fee_cents }) : null;
  const billingSchedule = ['calendar_installments', 'prepaid'].includes(config.billing.mode) ? installments.installments_cents.map((cents, index) => ({ sequence: index + 1, due_date: advancePlanDate(firstCharge, config.billing.interval, index), amount_cents: cents })) : [];
  const labels = {
    manual_per_visit: `Pay ${amount(calculation.future_visit.total_cents)} per future visit when ${config.billing.collect_on}, collected manually.`,
    automatic_per_visit: `Authorize automatic off-session payment of the full approved amount of each completed job for this customer, beginning with the first scheduled job. Covered services use the plan price (currently ${amount(calculation.future_visit.total_cents)} for the scope above); additional services and quantities are charged at their agreed job prices, including configured tax. Deposits and confirmed payments are credited once. Jobs containing only additional services are also collected after completion without consuming a covered visit.`,
    calendar_recurring: `Authorize ${amount(calculation.future_visit.total_cents)} ${cadence(config.billing.interval)} starting ${firstCharge}, until canceled.${config.billing.calendar_requires_completed_service ? ' Each dated charge is held until its corresponding covered visit has been completed; one charge per visit.' : ' These calendar charges are independent of appointment completion.'}`,
    calendar_installments: `${billingSchedule.length} installments ${cadence(config.billing.interval)} starting ${firstCharge}: ${billingSchedule.map((entry) => amount(entry.amount_cents)).join(', ')}.`,
    prepaid: `Prepay ${amount(installments?.remaining_cents || 0)} on ${firstCharge} for ${futureCount} future visits.`,
  };
  const financialText = [
    `Plan: ${config.name}.`, `Included future services: ${calculation.future_visit.line_items.map((line) => `${line.qty} × ${line.name}: ${line.description}`).join('; ')}.`,
    contactCollection ? `Service ${cadence(config.service_interval)} between covered appointments. Effective ${effectiveDate}; the first scheduled covered job is Visit 1 and is associated automatically through this customer. The plan discount applies from that first job, including when booked from this quote. This first-job rule supersedes any generic first-cleaning exclusion in the tier description. Later due dates are anchored to that appointment.` : appointmentAnchored ? `Service ${cadence(config.service_interval)} between covered appointments. Effective ${effectiveDate}; Visit 1 is the first explicitly linked covered appointment. Until then it is unscheduled. Later visits are due from that appointment date, not from enrollment. Separately invoiced initial work remains separate.` : `Service ${cadence(config.service_interval)}. Effective ${effectiveDate}; first future service due ${nextService}. Appointments remain subject to confirmed Schedule availability.`,
    `Future visit price ${amount(calculation.future_visit.total_cents)} including configured tax. ${labels[config.billing.mode]}`,
    `The one-time quote discount of ${amount(calculation.existing_quote_discount_cents)} does not repeat on future visits. For the initial job, ${calculation.discount_stacking_policy==='quote_then_plan'?'the plan discount applies after the allocated quote discount on eligible services':'eligible services retain the better price from the quote promotion or plan discount'}. Promotions on noneligible work remain unchanged.`,
    contactCollection ? 'By signing this plan and completing card setup, you authorize the business to save the card and collect each completed job’s full agreed balance automatically, including services outside this plan. The plan discount applies only to covered services. This completed-job collection timing replaces any unpaid upfront deposit requirement on the initial quote. No charge occurs merely because an appointment was booked. A separate ordinary quote checkout will not collect the same job again.' : ['calendar_installments','calendar_recurring'].includes(config.billing.mode) ? 'By separately signing this plan and completing payment-method setup, you authorize the business to save that payment method and debit the exact service-triggered charges or dated installments stated here. A card used only for the initial job is not treated as this authorization.' : (config.billing.save_payment_method ? 'By signing and completing card setup, you authorize saving your card for this plan. This does not authorize automatic recurring debits; you confirm manual payments separately.' : 'This plan does not authorize automatic recurring card debits.'),
    `Initial job: original ${amount(calculation.original_total_cents)}; prior signed adjustments ${amount(priorAdjustment)}; additional conditional plan adjustment ${amount(calculation.current_adjustment_cents)}; adjusted ${amount(calculation.current_total_cents)}; payments credited ${amount(payments_cents)}; amount due ${amount(calculation.current_balance_cents)}; credit due ${amount(calculation.credit_due_cents)}.`,
    calculation.current_adjustment_cents ? 'This adjustment takes effect only after all required plan signatures, required payment-method setup and initial payment succeed. Until activation, the initial job retains its original balance. No refund is issued automatically.' : 'The initial job invoice and prior payment records remain unchanged.',
    contactCollection ? 'Covered jobs consume one visit when completed. The first scheduled covered job is included in the stated term; no separate initial-job payment is added.' : initial_visit_already_counted ? 'The initial visit was already allocated to a prior signed plan and is not counted or credited again in this new term.' : config.current_visit_counts ? `The initial visit counts toward the term and remains billed on the original job. ${amount(priorAllocation)} of visit allocation is excluded from package billing to avoid charging it twice.` : 'The initial visit does not count toward future plan visits.',
    `Term: ${config.term.kind === 'finite' ? `${config.term.visit_count} included visits, ${futureCount} future visits; no automatic renewal` : 'ongoing until canceled under the stated policy'}. Enrollment fee ${amount(config.billing.enrollment_fee_cents)}${billingSchedule.length ? ', included in the payment schedule' : ', due at activation'}.`,
    `Cancellation notice: ${config.cancellation_notice_days} days. ${config.cancellation_policy}`,
    `Pause ${config.allow_pause ? 'permitted under the policy' : 'requires a new agreed arrangement'}; skip ${config.allow_skip ? 'permits deferring all remaining unbooked visits by one service cycle without consuming an entitlement or changing billing dates; existing appointments must be handled separately' : 'not included'}. Price changes require a new signed agreement.`,
  ].join('\n\n');
  const result = { ...(contactCollection ? { collection_model: 'contact_completed_job_v1' } : {}), ...(appointmentAnchored ? { schedule_model: 'appointment_anchored_v1' } : {}), tier_id: tier.tier_id, tier_version: tier.version, configuration: config, ...calculation,prior_adjustment_cents:priorAdjustment,initial_visit_already_counted, effective_date: effectiveDate, next_service_date: nextService, first_charge_date: firstCharge, future_visit_count: futureCount, installments, billing_schedule: billingSchedule, financial_text: financialText };
  return { ...result, offer_hash: quoteContentHash({ agreement_id: agreement.id, packet_hash: agreement.packet_hash, ...result }) };
}
