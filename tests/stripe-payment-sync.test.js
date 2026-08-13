import assert from "assert";
import {
  mapStripePaymentIntentStatus,
  mapStripeSubscriptionStatus
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
