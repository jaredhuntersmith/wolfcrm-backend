import assert from "node:assert/strict";
import { calculateStripeConnectReadiness, friendlyStripeRequirement } from "../stripe-connect-status.js";

function run(name, fn) {
  try {
    fn();
    console.log(`PASS ${name}`);
  } catch (error) {
    console.error(`FAIL ${name}`);
    throw error;
  }
}

function account(overrides = {}) {
  return {
    id: "acct_test",
    charges_enabled: false,
    payouts_enabled: false,
    details_submitted: true,
    default_currency: "usd",
    requirements: {
      currently_due: [],
      eventually_due: [],
      past_due: [],
      pending_verification: [],
      disabled_reason: null,
      errors: []
    },
    capabilities: {
      card_payments: "inactive",
      transfers: "inactive"
    },
    ...overrides
  };
}

run("no account maps to not connected", () => {
  const result = calculateStripeConnectReadiness(null);
  assert.equal(result.stripe_connect_status, "not_connected");
  assert.equal(result.stripe_charges_enabled, false);
});

run("details not submitted maps to setup incomplete", () => {
  const result = calculateStripeConnectReadiness(account({ details_submitted: false }));
  assert.equal(result.stripe_connect_status, "setup_incomplete");
});

run("currently due maps to action required", () => {
  const result = calculateStripeConnectReadiness(account({
    requirements: { currently_due: ["individual.verification.document"], eventually_due: [], past_due: [], pending_verification: [], errors: [] }
  }));
  assert.equal(result.stripe_connect_status, "action_required");
  assert.deepEqual(result.stripe_requirements.friendly_currently_due, ["Identity verification document"]);
});

run("past due and requirement errors map to action required", () => {
  const result = calculateStripeConnectReadiness(account({
    requirements: {
      currently_due: [],
      eventually_due: [],
      past_due: ["external_account"],
      pending_verification: [],
      disabled_reason: "requirements.past_due",
      errors: [{ requirement: "external_account", message: "Bank account is required." }]
    }
  }));
  assert.equal(result.stripe_connect_status, "action_required");
  assert.equal(result.stripe_requirements.errors[0].message, "Bank account is required.");
});

run("pending verification maps to verification pending when nothing is actionable", () => {
  const result = calculateStripeConnectReadiness(account({
    requirements: { currently_due: [], eventually_due: [], past_due: [], pending_verification: ["individual.id_number"], disabled_reason: "requirements.pending_verification", errors: [] }
  }));
  assert.equal(result.stripe_connect_status, "verification_pending");
});

run("charges enabled maps to ready and preserves payout state", () => {
  const result = calculateStripeConnectReadiness(account({ charges_enabled: true, payouts_enabled: false }));
  assert.equal(result.stripe_connect_status, "ready");
  assert.equal(result.stripe_charges_enabled, true);
  assert.equal(result.stripe_payouts_enabled, false);
});

run("unknown requirement keys receive a readable fallback", () => {
  assert.equal(friendlyStripeRequirement("company.owners_provided"), "Company Owners Provided");
});
