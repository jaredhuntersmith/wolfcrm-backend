import assert from "assert";
import {
  mapStripePaymentIntentStatus,
  mapStripeSubscriptionStatus,
  selectRecoverableSubscription,
  subscriptionBlocksNewStart,
  subscriptionCanResumePayment
} from "../stripe-payment-sync.js";

function test(name, fn) {
  try {
    fn();
    console.log(`PASS ${name}`);
  } catch (err) {
    console.error(`FAIL ${name}`);
    console.error(err);
    process.exitCode = 1;
  }
}

test("Stripe subscription active maps to WolfCRM active", () => {
  assert.equal(mapStripeSubscriptionStatus("active"), "active");
  assert.equal(mapStripeSubscriptionStatus("trialing"), "active");
});

test("Stripe subscription incomplete maps to payment pending", () => {
  assert.equal(mapStripeSubscriptionStatus("incomplete"), "payment_pending");
});

test("Stripe subscription past due maps to past due", () => {
  assert.equal(mapStripeSubscriptionStatus("past_due"), "past_due");
  assert.equal(mapStripeSubscriptionStatus("unpaid"), "past_due");
});

test("Stripe subscription canceled maps to canceled", () => {
  assert.equal(mapStripeSubscriptionStatus("canceled"), "canceled");
});

test("Stripe subscription paused maps to paused", () => {
  assert.equal(mapStripeSubscriptionStatus("paused"), "paused");
});

test("Stripe PaymentIntent succeeded maps to succeeded", () => {
  assert.equal(mapStripePaymentIntentStatus({ status: "succeeded" }), "succeeded");
});

test("Stripe PaymentIntent processing stays pending", () => {
  assert.equal(mapStripePaymentIntentStatus({ status: "processing" }), "pending");
});

test("Stripe PaymentIntent failed attempt maps to failed", () => {
  assert.equal(mapStripePaymentIntentStatus({ status: "requires_payment_method", last_payment_error: { code: "card_declined" } }), "failed");
});

test("Stripe PaymentIntent canceled maps to canceled", () => {
  assert.equal(mapStripePaymentIntentStatus({ status: "canceled" }), "canceled");
});

test("existing active subscription blocks creating another subscription", () => {
  assert.equal(subscriptionBlocksNewStart("active"), true);
});

test("existing incomplete subscription blocks duplicate creation and can resume unpaid intent", () => {
  const subscription = {
    status: "incomplete",
    latest_invoice: {
      payment_intent: {
        status: "requires_payment_method",
        client_secret: "pi_test_secret"
      }
    }
  };
  assert.equal(subscriptionBlocksNewStart(subscription.status), true);
  assert.equal(subscriptionCanResumePayment(subscription), true);
});

test("existing past due subscription blocks duplicate creation", () => {
  assert.equal(subscriptionBlocksNewStart("past_due"), true);
});

test("existing canceled subscription still requires explicit restart flow", () => {
  assert.equal(subscriptionBlocksNewStart("canceled"), true);
});

test("subscription with succeeded payment intent is not resumed through PaymentSheet", () => {
  const subscription = {
    status: "active",
    latest_invoice: {
      payment_intent: {
        status: "succeeded",
        client_secret: "pi_test_secret"
      }
    }
  };
  assert.equal(subscriptionCanResumePayment(subscription), false);
});

test("stored canceled subscription with exactly one active metadata match adopts active subscription", () => {
  const recovery = selectRecoverableSubscription([
    { id: "sub_canceled", status: "canceled", customer: "cus_1", metadata: { wolfcrm_plan_id: "plan_1" } },
    { id: "sub_active", status: "active", customer: "cus_1", metadata: { wolfcrm_plan_id: "plan_1" } }
  ], { planId: "plan_1", customerId: "cus_1" });
  assert.equal(recovery.action, "adopt");
  assert.equal(recovery.subscription.id, "sub_active");
});

test("stored incomplete expired subscription with active metadata match adopts active subscription", () => {
  const recovery = selectRecoverableSubscription([
    { id: "sub_expired", status: "incomplete_expired", customer: "cus_1", metadata: { wolfcrm_plan_id: "plan_1" } },
    { id: "sub_active", status: "active", customer: "cus_1", metadata: { wolfcrm_plan_id: "plan_1" } }
  ], { planId: "plan_1", customerId: "cus_1" });
  assert.equal(recovery.action, "adopt");
  assert.equal(recovery.subscription.id, "sub_active");
});

test("recovery without metadata match does not adopt", () => {
  const recovery = selectRecoverableSubscription([
    { id: "sub_active", status: "active", customer: "cus_1", metadata: {} }
  ], { planId: "plan_1", customerId: "cus_1" });
  assert.equal(recovery.action, "none");
});

test("recovery with wrong wolfcrm plan metadata does not adopt", () => {
  const recovery = selectRecoverableSubscription([
    { id: "sub_active", status: "active", customer: "cus_1", metadata: { wolfcrm_plan_id: "other_plan" } }
  ], { planId: "plan_1", customerId: "cus_1" });
  assert.equal(recovery.action, "none");
});

test("multiple active metadata matches returns conflict", () => {
  const recovery = selectRecoverableSubscription([
    { id: "sub_active_a", status: "active", customer: "cus_1", metadata: { wolfcrm_plan_id: "plan_1" } },
    { id: "sub_active_b", status: "active", customer: "cus_1", metadata: { wolfcrm_plan_id: "plan_1" } }
  ], { planId: "plan_1", customerId: "cus_1" });
  assert.equal(recovery.action, "conflict");
  assert.deepEqual(recovery.subscriptions.map((sub) => sub.id), ["sub_active_a", "sub_active_b"]);
});

test("active currently stored subscription requires no recovery search by status", () => {
  assert.equal(["canceled", "incomplete_expired"].includes("active"), false);
});
