import assert from "node:assert/strict";
import {
  collectPlaidSyncPages,
  decryptAccessToken,
  encryptAccessToken,
  getPlaidConfig,
  getPlaidEnvironmentConfig,
  isLiquidFinanceAccount,
  normalizePlaidTransactionAmount,
  plaidSecretForEnvironment,
  providerAmountToCents,
  reconcileTransactionRefs
} from "../finance-plaid-helpers.js";

const keyA = "0123456789abcdef0123456789abcdef";
const keyB = "abcdef0123456789abcdef0123456789";

function run(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => console.log(`PASS ${name}`))
    .catch((error) => {
      console.error(`FAIL ${name}`);
      throw error;
    });
}

await run("encrypt/decrypt access token", () => {
  const env = { FINANCE_TOKEN_ENCRYPTION_KEY: keyA };
  const encrypted = encryptAccessToken("access-sandbox-token", env);
  assert.equal(decryptAccessToken(encrypted, env), "access-sandbox-token");
  assert.equal(encrypted.token_encryption_version, 1);
});

await run("same token encrypts differently", () => {
  const env = { FINANCE_TOKEN_ENCRYPTION_KEY: keyA };
  const a = encryptAccessToken("same-token", env);
  const b = encryptAccessToken("same-token", env);
  assert.notEqual(a.access_token_ciphertext, b.access_token_ciphertext);
  assert.notEqual(a.access_token_iv, b.access_token_iv);
});

await run("wrong key fails", () => {
  const encrypted = encryptAccessToken("secret-token", { FINANCE_TOKEN_ENCRYPTION_KEY: keyA });
  assert.throws(() => decryptAccessToken(encrypted, { FINANCE_TOKEN_ENCRYPTION_KEY: keyB }));
});

await run("modified ciphertext fails authentication", () => {
  const env = { FINANCE_TOKEN_ENCRYPTION_KEY: keyA };
  const encrypted = encryptAccessToken("secret-token", env);
  encrypted.access_token_ciphertext = encrypted.access_token_ciphertext.replace(/.$/, "A");
  assert.throws(() => decryptAccessToken(encrypted, env));
});

await run("missing key handled safely", () => {
  assert.throws(() => encryptAccessToken("token", {}), /finance_token_encryption_key_missing/);
});

await run("Plaid active config uses environment-specific secret", () => {
  const env = {
    PLAID_ENV: "production",
    PLAID_CLIENT_ID: "client",
    PLAID_SECRET: "legacy-production-secret",
    PLAID_SANDBOX_SECRET: "sandbox-secret",
    FINANCE_TOKEN_ENCRYPTION_KEY: keyA
  };
  const config = getPlaidConfig(env);
  assert.equal(config.configured, true);
  assert.equal(config.environment, "production");
  assert.equal(plaidSecretForEnvironment("sandbox", env), "sandbox-secret");
  assert.equal(plaidSecretForEnvironment("production", env), "legacy-production-secret");
});

await run("sandbox Item can be configured while global environment is production", () => {
  const env = {
    PLAID_ENV: "production",
    PLAID_CLIENT_ID: "client",
    PLAID_SECRET: "production-secret",
    PLAID_SANDBOX_SECRET: "sandbox-secret"
  };
  assert.equal(getPlaidEnvironmentConfig("sandbox", env).configured, true);
  assert.equal(plaidSecretForEnvironment("sandbox", env), "sandbox-secret");
});

await run("missing sandbox secret is a clear environment config failure", () => {
  const env = {
    PLAID_ENV: "production",
    PLAID_CLIENT_ID: "client",
    PLAID_SECRET: "production-secret"
  };
  assert.equal(getPlaidEnvironmentConfig("sandbox", env).configured, false);
  assert.equal(plaidSecretForEnvironment("sandbox", env), null);
});

await run("provider amount to cents", () => {
  assert.equal(providerAmountToCents(10), 1000);
  assert.equal(providerAmountToCents(10.1), 1010);
  assert.equal(providerAmountToCents(10.01), 1001);
  assert.equal(providerAmountToCents(0), 0);
  assert.equal(providerAmountToCents(-10.01), -1001);
  assert.equal(providerAmountToCents(1234567.89), 123456789);
});

await run("Plaid expense/income normalization", () => {
  assert.deepEqual(normalizePlaidTransactionAmount(52.34), { direction: "expense", amount_cents: 5234 });
  assert.deepEqual(normalizePlaidTransactionAmount(-1500), { direction: "income", amount_cents: 150000 });
});

await run("liquid account rules", () => {
  assert.equal(isLiquidFinanceAccount({ source: "plaid", plaid_account_type: "depository", plaid_account_subtype: "checking" }), true);
  assert.equal(isLiquidFinanceAccount({ source: "plaid", plaid_account_type: "depository", plaid_account_subtype: "savings" }), true);
  assert.equal(isLiquidFinanceAccount({ source: "plaid", plaid_account_type: "credit", plaid_account_subtype: "credit card" }), false);
  assert.equal(isLiquidFinanceAccount({ source: "plaid", plaid_account_type: "loan", plaid_account_subtype: "student" }), false);
  assert.equal(isLiquidFinanceAccount({ source: "plaid", plaid_account_type: "depository", plaid_account_subtype: "checking", include_in_liquid_cash: false }), false);
  assert.equal(isLiquidFinanceAccount({ source: "plaid", plaid_account_type: "depository", plaid_account_subtype: "checking", plaid_item_status: "disconnected" }), false);
});

await run("pending to posted keeps stable transaction id", () => {
  let state = reconcileTransactionRefs({ transactions: new Map(), refs: new Map() }, {
    transaction_id: "wolf_tx_1",
    provider_transaction_id: "pending123",
    payload: { pending: true, amount_cents: 5000 }
  });
  state = reconcileTransactionRefs(state, {
    transaction_id: "wolf_tx_unused",
    provider_transaction_id: "posted987",
    pending_transaction_id: "pending123",
    payload: { pending: false, amount_cents: 5000 }
  });
  assert.equal(state.refs.get("posted987").transaction_id, "wolf_tx_1");
  assert.equal(state.refs.get("pending123").is_current, false);
  assert.equal(state.transactions.size, 1);
  assert.equal(state.transactions.get("wolf_tx_1").pending, false);
});

await run("modified transaction keeps same id", () => {
  let state = reconcileTransactionRefs({ transactions: new Map(), refs: new Map() }, {
    transaction_id: "wolf_tx_1",
    provider_transaction_id: "posted123",
    payload: { amount_cents: 1000, merchant_name: "Old" }
  });
  state = reconcileTransactionRefs(state, {
    transaction_id: "wolf_tx_new",
    provider_transaction_id: "posted123",
    payload: { amount_cents: 1200, merchant_name: "New" }
  });
  assert.equal(state.transactions.size, 1);
  assert.equal(state.transactions.get("wolf_tx_1").amount_cents, 1200);
  assert.equal(state.transactions.get("wolf_tx_1").merchant_name, "New");
});

await run("pagination merges all pages", async () => {
  const pages = [
    { added: [1], modified: [], removed: [], next_cursor: "c1", has_more: true },
    { added: [2], modified: [3], removed: [4], next_cursor: "c2", has_more: false }
  ];
  const result = await collectPlaidSyncPages(async () => pages.shift(), null);
  assert.deepEqual(result.added, [1, 2]);
  assert.deepEqual(result.modified, [3]);
  assert.deepEqual(result.removed, [4]);
  assert.equal(result.next_cursor, "c2");
});

await run("mutation during pagination restarts from original cursor", async () => {
  let calls = 0;
  const result = await collectPlaidSyncPages(async (cursor) => {
    calls += 1;
    if (calls === 2) {
      const error = new Error("mutation");
      error.code = "TRANSACTIONS_SYNC_MUTATION_DURING_PAGINATION";
      throw error;
    }
    assert.equal(cursor, calls === 1 || calls === 3 ? "original" : "retry1");
    return calls === 1
      ? { added: ["stale"], modified: [], removed: [], next_cursor: "retry1", has_more: true }
      : { added: ["fresh"], modified: [], removed: [], next_cursor: "done", has_more: false };
  }, "original");
  assert.deepEqual(result.added, ["fresh"]);
  assert.equal(result.restarts, 1);
});

await run("pagination retry guard works", async () => {
  await assert.rejects(
    () => collectPlaidSyncPages(async () => {
      const error = new Error("mutation");
      error.code = "TRANSACTIONS_SYNC_MUTATION_DURING_PAGINATION";
      throw error;
    }, "cursor", 1),
    /mutation/
  );
});
