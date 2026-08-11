export function addDays(dateString, days) {
  const [year, month, day] = dateString.split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1, day + days));
  return date.toISOString().slice(0, 10);
}

export function addMonthsClamped(dateString, months) {
  const [year, month, day] = dateString.split("-").map(Number);
  const baseIndex = (year * 12) + (month - 1) + months;
  const nextYear = Math.floor(baseIndex / 12);
  const nextMonthIndex = ((baseIndex % 12) + 12) % 12;
  const lastDay = new Date(Date.UTC(nextYear, nextMonthIndex + 1, 0)).getUTCDate();
  return new Date(Date.UTC(nextYear, nextMonthIndex, Math.min(day, lastDay))).toISOString().slice(0, 10);
}

function periodsPerYear(frequency = "monthly") {
  switch (frequency) {
  case "weekly": return 52;
  case "biweekly": return 26;
  case "yearly": return 1;
  default: return 12;
  }
}

function nextPaymentDate(dateString, frequency = "monthly") {
  switch (frequency) {
  case "weekly": return addDays(dateString, 7);
  case "biweekly": return addDays(dateString, 14);
  case "yearly": return addMonthsClamped(dateString, 12);
  default: return addMonthsClamped(dateString, 1);
  }
}

function paymentFrequencyLabel(frequency = "monthly") {
  switch (frequency) {
  case "weekly": return "weekly";
  case "biweekly": return "every 2 weeks";
  case "yearly": return "yearly";
  default: return "monthly";
  }
}

export function estimateDebtPayoff({
  balanceCents,
  paymentCents,
  aprBasisPoints = null,
  startDate,
  frequency = "monthly",
  maxPayments = 600
}) {
  const balance = Math.max(0, Number(balanceCents || 0));
  const payment = Math.max(0, Number(paymentCents || 0));
  const aprBps = aprBasisPoints === null || aprBasisPoints === undefined ? null : Math.max(0, Number(aprBasisPoints || 0));
  const periodRate = aprBps === null ? 0 : (aprBps / 10000) / periodsPerYear(frequency);

  if (balance === 0) {
    return {
      status: "paid",
      estimated_payoff_date: startDate,
      estimated_number_of_payments: 0,
      estimated_total_future_payments_cents: 0,
      estimated_interest_paid_cents: 0,
      interest_included: aprBps !== null,
      payment_frequency: paymentFrequencyLabel(frequency)
    };
  }
  if (payment <= 0) {
    return {
      status: "no_payment_plan",
      estimated_payoff_date: null,
      estimated_number_of_payments: null,
      estimated_total_future_payments_cents: 0,
      estimated_interest_paid_cents: aprBps === null ? null : 0,
      interest_included: aprBps !== null,
      payment_frequency: paymentFrequencyLabel(frequency)
    };
  }

  let remaining = balance;
  let date = startDate;
  let count = 0;
  let totalPaid = 0;
  let totalInterest = 0;

  while (remaining > 0 && count < maxPayments) {
    const interest = Math.round(remaining * periodRate);
    if (interest > 0 && payment <= interest) {
      return {
        status: "not_payoff_capable",
        estimated_payoff_date: null,
        estimated_number_of_payments: null,
        estimated_total_future_payments_cents: totalPaid,
        estimated_interest_paid_cents: totalInterest,
        interest_included: aprBps !== null,
        payment_frequency: paymentFrequencyLabel(frequency)
      };
    }
    totalInterest += interest;
    const amountDue = remaining + interest;
    const paid = Math.min(payment, amountDue);
    totalPaid += paid;
    remaining = amountDue - paid;
    count += 1;
    date = nextPaymentDate(date, frequency);
  }

  if (remaining > 0) {
    return {
      status: "not_payoff_capable",
      estimated_payoff_date: null,
      estimated_number_of_payments: null,
      estimated_total_future_payments_cents: totalPaid,
      estimated_interest_paid_cents: totalInterest,
      interest_included: aprBps !== null,
      payment_frequency: paymentFrequencyLabel(frequency)
    };
  }

  return {
    status: "payoff_capable",
    estimated_payoff_date: date,
    estimated_number_of_payments: count,
    estimated_total_future_payments_cents: totalPaid,
    estimated_interest_paid_cents: aprBps === null ? null : totalInterest,
    interest_included: aprBps !== null,
    payment_frequency: paymentFrequencyLabel(frequency)
  };
}

export function requiredPaymentForTarget({
  balanceCents,
  aprBasisPoints = null,
  startDate,
  targetDate,
  frequency = "monthly"
}) {
  const balance = Math.max(0, Number(balanceCents || 0));
  if (balance === 0) return { status: "paid", required_payment_cents: 0 };
  if (!targetDate || targetDate <= startDate) {
    return { status: "invalid_target_date", required_payment_cents: null };
  }

  let periods = 0;
  let date = startDate;
  while (date < targetDate && periods < 600) {
    periods += 1;
    date = nextPaymentDate(date, frequency);
  }
  if (periods <= 0 || periods >= 600) return { status: "invalid_target_date", required_payment_cents: null };

  let low = 1;
  let high = Math.max(1, balance * 2);
  while (estimateDebtPayoff({ balanceCents: balance, paymentCents: high, aprBasisPoints, startDate, frequency }).estimated_payoff_date > targetDate) {
    high *= 2;
    if (high > balance * 100) break;
  }

  for (let i = 0; i < 32; i += 1) {
    const mid = Math.floor((low + high) / 2);
    const payoff = estimateDebtPayoff({ balanceCents: balance, paymentCents: mid, aprBasisPoints, startDate, frequency });
    if (payoff.status === "payoff_capable" && payoff.estimated_payoff_date <= targetDate) high = mid;
    else low = mid + 1;
  }

  return {
    status: "target_payment_available",
    required_payment_cents: high,
    interest_included: aprBasisPoints !== null && aprBasisPoints !== undefined,
    payment_frequency: paymentFrequencyLabel(frequency)
  };
}

export function summarizeBudget({ budget, occurrences }) {
  const planned = occurrences
    .filter((event) => event.direction === "expense" && event.category === budget.category)
    .reduce((sum, event) => sum + Number(event.amount_cents || 0), 0);
  const remaining = Number(budget.limit_cents || 0) - planned;
  return {
    budget_id: budget.id,
    name: budget.name,
    category: budget.category,
    limit_cents: Number(budget.limit_cents || 0),
    planned_spend_cents: planned,
    remaining_cents: remaining,
    overage_cents: Math.max(0, -remaining),
    percent_planned: budget.limit_cents > 0 ? Math.round((planned / budget.limit_cents) * 100) : 0,
    status: remaining < 0 ? "over_plan" : "on_plan"
  };
}

export function goalMetrics({ targetAmountCents, currentAmountCents, targetDate, startDate }) {
  const target = Math.max(0, Number(targetAmountCents || 0));
  const current = Math.max(0, Number(currentAmountCents || 0));
  const remaining = Math.max(0, target - current);
  const progress = target > 0 ? Math.min(100, Math.round((current / target) * 100)) : 0;
  let requiredWeekly = null;
  let requiredMonthly = null;

  if (targetDate && targetDate > startDate && remaining > 0) {
    const start = new Date(`${startDate}T00:00:00Z`);
    const end = new Date(`${targetDate}T00:00:00Z`);
    const days = Math.max(1, Math.ceil((end - start) / 86400000));
    requiredWeekly = Math.ceil(remaining / Math.max(1, days / 7));
    requiredMonthly = Math.ceil(remaining / Math.max(1, days / 30.4375));
  }

  return {
    target_amount_cents: target,
    current_amount_cents: current,
    remaining_cents: remaining,
    progress_percent: progress,
    required_weekly_cents: requiredWeekly,
    required_monthly_cents: requiredMonthly
  };
}
