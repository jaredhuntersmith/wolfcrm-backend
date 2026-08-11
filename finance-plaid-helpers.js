import crypto from "node:crypto";

export function getPlaidConfig(env = process.env) {
  const plaidEnv = (env.PLAID_ENV || "sandbox").toLowerCase();
  const supported = plaidEnv === "sandbox" || plaidEnv === "production";
  return {
    configured: Boolean(env.PLAID_CLIENT_ID && env.PLAID_SECRET && supported),
    encryption_configured: Boolean(env.FINANCE_TOKEN_ENCRYPTION_KEY),
    environment: supported ? plaidEnv : "sandbox",
    webhook_url: env.PLAID_WEBHOOK_URL || null,
    redirect_uri: env.PLAID_REDIRECT_URI || null
  };
}

export function encryptionKeyFromEnv(env = process.env) {
  const raw = env.FINANCE_TOKEN_ENCRYPTION_KEY;
  if (!raw) {
    const error = new Error("finance_token_encryption_key_missing");
    error.statusCode = 503;
    error.code = "finance_token_encryption_key_missing";
    throw error;
  }
  const trimmed = raw.trim();
  const candidates = [
    Buffer.from(trimmed, "base64"),
    Buffer.from(trimmed, "hex"),
    Buffer.from(trimmed, "utf8")
  ];
  const key = candidates.find((candidate) => candidate.length === 32);
  if (!key) {
    const error = new Error("finance_token_encryption_key_invalid");
    error.statusCode = 503;
    error.code = "finance_token_encryption_key_invalid";
    throw error;
  }
  return key;
}

export function encryptAccessToken(accessToken, env = process.env) {
  const key = encryptionKeyFromEnv(env);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(accessToken, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    access_token_ciphertext: ciphertext.toString("base64"),
    access_token_iv: iv.toString("base64"),
    access_token_auth_tag: tag.toString("base64"),
    token_encryption_version: 1
  };
}

export function decryptAccessToken(record, env = process.env) {
  const key = encryptionKeyFromEnv(env);
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(record.access_token_iv, "base64")
  );
  decipher.setAuthTag(Buffer.from(record.access_token_auth_tag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(record.access_token_ciphertext, "base64")),
    decipher.final()
  ]);
  return plaintext.toString("utf8");
}

export function providerAmountToCents(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    const error = new Error("provider_amount_invalid");
    error.code = "provider_amount_invalid";
    throw error;
  }
  return Math.round(value * 100);
}

export function normalizePlaidTransactionAmount(amount) {
  const cents = providerAmountToCents(amount);
  return {
    direction: cents >= 0 ? "expense" : "income",
    amount_cents: Math.abs(cents)
  };
}

export function normalizePlaidCategory(transaction) {
  const primary = transaction.personal_finance_category?.primary || "";
  const detailed = transaction.personal_finance_category?.detailed || "";
  const combined = `${primary} ${detailed}`.toUpperCase();
  if (combined.includes("FOOD") || combined.includes("RESTAURANT") || combined.includes("GROCER")) return "Food";
  if (combined.includes("TRAVEL") || combined.includes("GAS") || combined.includes("FUEL")) return "Fuel";
  if (combined.includes("RENT")) return "Rent";
  if (combined.includes("UTILITY")) return "Utilities";
  if (combined.includes("INSURANCE")) return "Insurance";
  if (combined.includes("LOAN") || combined.includes("CREDIT_CARD") || combined.includes("DEBT")) return "Debt Payment";
  if (combined.includes("TAX")) return "Taxes";
  if (combined.includes("SUBSCRIPTION")) return "Subscription";
  if (combined.includes("SHOP") || combined.includes("GENERAL_MERCHANDISE")) return "Materials";
  if (combined.includes("TRANSFER") || combined.includes("PAYROLL") || combined.includes("INCOME")) return "Other Income";
  return "Other";
}

export function isLiquidFinanceAccount(account) {
  if (account.archived_at) return false;
  if (account.source === "manual") return true;
  if (account.source !== "plaid") return false;
  const type = (account.plaid_account_type || account.account_type || "").toLowerCase();
  const subtype = (account.plaid_account_subtype || "").toLowerCase();
  if (type === "credit" || type === "loan" || type === "investment") return false;
  if (type === "depository") {
    return ["checking", "savings", "cash management", "money market", "prepaid"].includes(subtype);
  }
  return ["checking", "savings", "cash"].includes(account.account_type);
}

export function plaidAccountToFinanceAccount(account, item) {
  const balances = account.balances || {};
  const current = balances.current === null || balances.current === undefined ? 0 : providerAmountToCents(balances.current);
  const available = balances.available === null || balances.available === undefined ? null : providerAmountToCents(balances.available);
  const subtype = account.subtype || "other";
  const accountType = subtype === "checking" || subtype === "savings" ? subtype : "other";
  return {
    name: account.name || account.official_name || "Plaid Account",
    account_type: accountType,
    source: "plaid",
    current_balance_cents: current,
    available_balance_cents: available,
    currency: (balances.iso_currency_code || "USD").toLowerCase(),
    plaid_item_internal_id: item.id,
    plaid_account_id: account.account_id,
    institution_name: item.institution_name || null,
    official_name: account.official_name || null,
    mask: account.mask || null,
    plaid_account_type: account.type || null,
    plaid_account_subtype: account.subtype || null,
    iso_currency_code: balances.iso_currency_code || "USD",
    include_in_liquid_cash: isLiquidFinanceAccount({
      source: "plaid",
      account_type: accountType,
      plaid_account_type: account.type,
      plaid_account_subtype: account.subtype
    })
  };
}

export function safePlaidItemPayload(row) {
  return {
    id: row.id,
    company_id: row.company_id,
    institution_id: row.institution_id,
    institution_name: row.institution_name,
    environment: row.environment,
    status: row.status,
    last_successful_sync_at: row.last_successful_sync_at,
    last_attempted_sync_at: row.last_attempted_sync_at,
    last_balance_refresh_at: row.last_balance_refresh_at,
    last_transaction_refresh_at: row.last_transaction_refresh_at,
    last_webhook_at: row.last_webhook_at,
    error_code: row.error_code,
    error_message: row.error_message,
    consent_expiration_time: row.consent_expiration_time,
    disconnected_at: row.disconnected_at,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

export function transactionPayloadFromPlaid(transaction, accountId) {
  const amount = normalizePlaidTransactionAmount(transaction.amount);
  return {
    account_id: accountId,
    source: "plaid",
    status: transaction.pending ? "pending" : "posted",
    direction: amount.direction,
    amount_cents: amount.amount_cents,
    transaction_date: transaction.date,
    authorized_date: transaction.authorized_date || null,
    merchant_name: transaction.merchant_name || transaction.name || null,
    original_name: transaction.original_name || transaction.name || null,
    category_primary: transaction.personal_finance_category?.primary || null,
    category_detailed: transaction.personal_finance_category?.detailed || null,
    normalized_category: normalizePlaidCategory(transaction),
    payment_channel: transaction.payment_channel || null,
    pending: Boolean(transaction.pending),
    merchant_entity_id: transaction.merchant_entity_id || null,
    website: transaction.website || null,
    location_city: transaction.location?.city || null,
    location_region: transaction.location?.region || null,
    location_postal_code: transaction.location?.postal_code || null,
    location_country: transaction.location?.country || null,
    iso_currency_code: transaction.iso_currency_code || "USD",
    provider_metadata: {
      account_id: transaction.account_id,
      pending_transaction_id: transaction.pending_transaction_id || null,
      check_number: transaction.check_number || null
    }
  };
}

export function reconcileTransactionRefs(state, change) {
  const next = {
    transactions: new Map(state.transactions || []),
    refs: new Map(state.refs || [])
  };
  const providerId = change.provider_transaction_id;
  const pendingId = change.pending_transaction_id || null;
  const existingRef = next.refs.get(providerId);
  const pendingRef = pendingId ? next.refs.get(pendingId) : null;
  const transactionId = pendingRef?.transaction_id || existingRef?.transaction_id || change.transaction_id;
  next.transactions.set(transactionId, { ...(next.transactions.get(transactionId) || {}), ...change.payload, id: transactionId });
  if (pendingRef) next.refs.set(pendingId, { ...pendingRef, is_current: false });
  next.refs.set(providerId, { provider_transaction_id: providerId, transaction_id: transactionId, is_current: true });
  return next;
}

export async function collectPlaidSyncPages(fetchPage, originalCursor, maxRestarts = 3) {
  let cursor = originalCursor || null;
  let restarts = 0;
  const collected = { added: [], modified: [], removed: [] };

  while (true) {
    try {
      collected.added.length = 0;
      collected.modified.length = 0;
      collected.removed.length = 0;
      cursor = originalCursor || null;
      let hasMore = true;
      let nextCursor = cursor;
      while (hasMore) {
        const page = await fetchPage(nextCursor);
        collected.added.push(...(page.added || []));
        collected.modified.push(...(page.modified || []));
        collected.removed.push(...(page.removed || []));
        nextCursor = page.next_cursor;
        hasMore = Boolean(page.has_more);
      }
      return { ...collected, next_cursor: nextCursor, restarts };
    } catch (error) {
      if (error?.code === "TRANSACTIONS_SYNC_MUTATION_DURING_PAGINATION" && restarts < maxRestarts) {
        restarts += 1;
        continue;
      }
      throw error;
    }
  }
}
