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
