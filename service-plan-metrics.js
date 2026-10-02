// Monthly equivalent of contracted recurring service, not a forecast of collection dates.
export function monthlyPlanRevenueCents(plan) {
  if (plan.status !== 'active') return 0;
  const snapshot = plan.plan_snapshot;
  const config = snapshot?.configuration;
  // Signed per-visit/prepaid plans normalize the visit price over the service
  // cadence. Fees and the original one-time job never become recurring revenue.
  const perService = ['manual_per_visit', 'automatic_per_visit', 'prepaid'].includes(plan.billing_mode || config?.billing?.mode) || ['per_visit', 'prepaid'].includes(plan.billing_interval);
  const interval = perService ? (config?.service_interval?.unit || plan.service_interval) : plan.billing_interval;
  const count = Math.max(1, Number(perService ? (config?.service_interval?.count || plan.service_interval_count) : plan.billing_interval_count) || 1);
  let price = Number(perService ? (snapshot?.future_visit?.total_cents ?? plan.price_cents) : plan.price_cents);
  if (config?.billing?.mode === 'calendar_installments' && snapshot?.billing_schedule?.length) {
    price = (snapshot.billing_schedule.reduce((sum, row) => sum + row.amount_cents, 0) - (config.billing.enrollment_fee_cents || 0)) / snapshot.billing_schedule.length;
  }
  if (!Number.isFinite(price) || price < 0 || plan.remaining_visits === 0) return 0;
  const months = { day: count / 30, week: count * 7 / 30, month: count, year: count * 12 }[interval];
  return months ? price / months : 0;
}
