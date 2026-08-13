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
