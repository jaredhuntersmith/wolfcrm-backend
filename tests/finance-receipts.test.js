import assert from "node:assert/strict";
import {
  chooseReceiptMatch,
  merchantSimilarity,
  normalizeMerchantName,
  scoreReceiptCandidate
} from "../finance-receipt-matching.js";

function tx(overrides = {}) {
  return {
    id: overrides.id || "tx_1",
    direction: "expense",
    amount_cents: 14372,
    transaction_date: "2026-08-11",
    authorized_date: "2026-08-11",
    merchant_name: "LOWES #1234",
    original_name: "LOWES #1234",
    location_city: "Louisville",
    location_region: "KY",
    location_postal_code: "40202",
    account_mask: "1234",
    ...overrides
  };
}

function receipt(overrides = {}) {
  return {
    id: "receipt_1",
    merchant_name: "Lowe's",
    normalized_merchant_name: normalizeMerchantName("Lowe's"),
    amount_cents: 14372,
    purchase_date: "2026-08-11",
    city: "Louisville",
    state: "KY",
    postal_code: "40202",
    card_last_four: "1234",
    ...overrides
  };
}

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

test("merchant normalization strips store numbers and punctuation", () => {
  assert.equal(normalizeMerchantName("The Home Depot #2312"), "HOME DEPOT");
  assert.equal(normalizeMerchantName("McDonald's 1451"), "MCDONALDS");
});

test("merchant similarity handles common Plaid vs receipt names", () => {
  assert.ok(merchantSimilarity("LOWES #1234", "Lowe's") >= 0.9);
  assert.ok(merchantSimilarity("THE HOME DEPOT #2312", "Home Depot") >= 0.9);
});

test("exact amount date merchant creates high confidence", () => {
  assert.ok(scoreReceiptCandidate(receipt(), tx()) >= 95);
});

test("income transaction is excluded", () => {
  assert.equal(scoreReceiptCandidate(receipt(), tx({ direction: "income" })), 0);
});

test("date one day apart still scores as possible", () => {
  assert.ok(scoreReceiptCandidate(receipt({ purchase_date: "2026-08-10" }), tx()) >= 80);
});

test("posted date three days later can still match", () => {
  assert.ok(scoreReceiptCandidate(receipt({ purchase_date: "2026-08-08", card_last_four: null }), tx({ authorized_date: null })) >= 70);
});

test("different amounts do not auto match", () => {
  const decision = chooseReceiptMatch(receipt({ amount_cents: 6000 }), [tx({ merchant_name: "LOWES", amount_cents: 14372 })]);
  assert.equal(decision.autoMatch, false);
});

test("same-day identical purchases remain ambiguous", () => {
  const decision = chooseReceiptMatch(receipt(), [
    tx({ id: "tx_1" }),
    tx({ id: "tx_2" })
  ]);
  assert.equal(decision.autoMatch, false);
  assert.equal(decision.candidates.length, 2);
});

test("very high unique score auto matches", () => {
  const decision = chooseReceiptMatch(receipt(), [tx()]);
  assert.equal(decision.autoMatch, true);
});

test("best score too close to second avoids auto match", () => {
  const decision = chooseReceiptMatch(receipt({ card_last_four: null }), [
    tx({ id: "tx_1", location_postal_code: null }),
    tx({ id: "tx_2", merchant_name: "LOWES STORE", location_postal_code: null })
  ]);
  assert.equal(decision.autoMatch, false);
});

test("gas temporary hold does not auto match without amount evidence", () => {
  const decision = chooseReceiptMatch(receipt({ merchant_name: "Shell", normalized_merchant_name: normalizeMerchantName("Shell"), amount_cents: 7214 }), [
    tx({ id: "hold", merchant_name: "SHELL OIL", amount_cents: 10000, account_mask: null })
  ]);
  assert.equal(decision.autoMatch, false);
});

test("restaurant pending amount can remain possible until final posts", () => {
  const pendingDecision = chooseReceiptMatch(receipt({ merchant_name: "Restaurant", normalized_merchant_name: normalizeMerchantName("Restaurant"), amount_cents: 6000 }), [
    tx({ id: "pending", merchant_name: "RESTAURANT", amount_cents: 5000, pending: true })
  ]);
  assert.equal(pendingDecision.autoMatch, false);
  const postedDecision = chooseReceiptMatch(receipt({ merchant_name: "Restaurant", normalized_merchant_name: normalizeMerchantName("Restaurant"), amount_cents: 6000 }), [
    tx({ id: "posted", merchant_name: "RESTAURANT", amount_cents: 6000, pending: false })
  ]);
  assert.equal(postedDecision.autoMatch, true);
});

test("old receipt can match historical transaction by its own date", () => {
  assert.ok(scoreReceiptCandidate(receipt({ purchase_date: "2026-07-12" }), tx({ transaction_date: "2026-07-12", authorized_date: "2026-07-12" })) >= 95);
});

let passed = 0;
for (const item of tests) {
  try {
    item.fn();
    passed += 1;
    console.log(`PASS ${item.name}`);
  } catch (error) {
    console.error(`FAIL ${item.name}`);
    console.error(error);
    process.exitCode = 1;
    break;
  }
}

if (!process.exitCode) console.log(`PASS finance receipt matching (${passed}/${tests.length})`);
