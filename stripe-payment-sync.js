export function mapStripeSubscriptionStatus(status) {
  switch (status) {
    case "active":
    case "trialing":
      return "active";
    case "incomplete":
      return "payment_pending";
    case "past_due":
    case "unpaid":
      return "past_due";
    case "canceled":
      return "canceled";
    case "paused":
      return "paused";
    case "incomplete_expired":
      return "failed";
    default:
      return null;
  }
}

export function isStripePaymentCollectionPaused(subscription) {
  return Boolean(subscription?.pause_collection);
}

export function mapStripeSubscriptionToWolfCRMStatus(subscription) {
  if (isStripePaymentCollectionPaused(subscription)) return "paused";
  return mapStripeSubscriptionStatus(subscription?.status);
}

export function mapStripePaymentIntentStatus(paymentIntent) {
  switch (paymentIntent && paymentIntent.status) {
    case "succeeded":
      return "succeeded";
    case "processing":
      return "pending";
    case "canceled":
      return "canceled";
    case "requires_payment_method":
      return paymentIntent.last_payment_error ? "failed" : "pending";
    case "requires_action":
    case "requires_capture":
    case "requires_confirmation":
    default:
      return "pending";
  }
}

export function nextServiceDateAfterResume(nextServiceDate, today = new Date()) {
  if (!nextServiceDate) return null;
  const todayIso = today.toISOString().slice(0, 10);
  const nextIso = typeof nextServiceDate === "string"
    ? nextServiceDate.slice(0, 10)
    : new Date(nextServiceDate).toISOString().slice(0, 10);
  return nextIso < todayIso ? todayIso : nextIso;
}

export function subscriptionBlocksNewStart(status) {
  return Boolean(status);
}

export function subscriptionCanResumePayment(subscription) {
  const status = subscription && subscription.status;
  if (!["incomplete", "past_due", "unpaid"].includes(status)) return false;
  const invoice = subscription.latest_invoice && typeof subscription.latest_invoice === "object"
    ? subscription.latest_invoice
    : null;
  const paymentIntent = invoice?.payment_intent && typeof invoice.payment_intent === "object"
    ? invoice.payment_intent
    : null;
  return Boolean(paymentIntent?.client_secret && paymentIntent.status !== "succeeded" && paymentIntent.status !== "canceled");
}

export function stripeSubscriptionCustomerId(subscription) {
  const customer = subscription && subscription.customer;
  return typeof customer === "string" ? customer : customer?.id || null;
}

export function selectRecoverableSubscription(subscriptions, { planId, customerId = null } = {}) {
  const exactMatches = (subscriptions || []).filter((subscription) => {
    if (subscription?.metadata?.wolfcrm_plan_id !== planId) return false;
    if (!customerId) return true;
    return stripeSubscriptionCustomerId(subscription) === customerId;
  });
  const statuses = ["active", "trialing", "past_due", "unpaid", "incomplete"];
  for (const status of statuses) {
    const candidates = exactMatches.filter((subscription) => subscription.status === status);
    if (candidates.length === 1) {
      return { action: "adopt", subscription: candidates[0], reason: `single_${status}_metadata_match` };
    }
    if (status === "active" && candidates.length > 1) {
      return { action: "conflict", subscriptions: candidates, reason: "multiple_active_metadata_matches" };
    }
  }
  return { action: "none", subscriptions: exactMatches, reason: exactMatches.length ? "no_viable_metadata_match" : "no_metadata_match" };
}
