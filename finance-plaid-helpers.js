import crypto from "node:crypto";

export function getPlaidConfig(env = process.env) {
  const plaidEnv = normalizePlaidEnvironment(env.PLAID_ENV || "sandbox");
  const supported = Boolean(plaidEnv);
  const environment = plaidEnv || "sandbox";
  return {
    configured: Boolean(env.PLAID_CLIENT_ID && plaidSecretForEnvironment(environment, env) && supported),
    encryption_configured: Boolean(env.FINANCE_TOKEN_ENCRYPTION_KEY),
    environment,
    webhook_url: env.PLAID_WEBHOOK_URL || null,
    redirect_uri: env.PLAID_REDIRECT_URI || null
  };
}

export function normalizePlaidEnvironment(value) {
  const normalized = (value || "").toString().trim().toLowerCase();
  if (normalized === "sandbox" || normalized === "development" || normalized === "production") return normalized;
  return null;
}

export function plaidSecretForEnvironment(environment, env = process.env) {
  const normalized = normalizePlaidEnvironment(environment);
  if (normalized === "sandbox") {
    return env.PLAID_SANDBOX_SECRET || (normalizePlaidEnvironment(env.PLAID_ENV) === "sandbox" ? env.PLAID_SECRET : null);
  }
  if (normalized === "development") {
    return env.PLAID_DEVELOPMENT_SECRET || (normalizePlaidEnvironment(env.PLAID_ENV) === "development" ? env.PLAID_SECRET : null);
  }
  if (normalized === "production") {
    return env.PLAID_PRODUCTION_SECRET || (normalizePlaidEnvironment(env.PLAID_ENV) === "production" ? env.PLAID_SECRET : null);
  }
  return null;
}

export function getPlaidEnvironmentConfig(environment, env = process.env) {
  const normalized = normalizePlaidEnvironment(environment);
  const secret = plaidSecretForEnvironment(normalized, env);
  return {
    configured: Boolean(env.PLAID_CLIENT_ID && secret && normalized),
    client_id: env.PLAID_CLIENT_ID || null,
    environment: normalized,
    secret_available: Boolean(secret)
  };
}

export function isSafeLocalDisconnectProviderFailure(error) {
  if (!error) return false;
  if (error.code === "finance_plaid_environment_unavailable") return true;
  if (error.code === "finance_token_encryption_key_missing" || error.code === "finance_token_encryption_key_invalid") return true;
  if (error.code === "ETIMEDOUT" || error.code === "ECONNRESET" || error.code === "ENOTFOUND" || error.code === "ECONNABORTED") return true;
  if ([408, 429, 500, 502, 503, 504].includes(error.response?.status || error.statusCode)) return true;
  const code = error.response?.data?.error_code || error.code;
  return [
    "ITEM_NOT_FOUND",
    "INVALID_ACCESS_TOKEN",
    "INVALID_INPUT",
    "ITEM_LOGIN_REQUIRED",
    "INSTITUTION_DOWN",
    "INSTITUTION_NOT_RESPONDING",
    "PRODUCT_NOT_READY"
  ].includes(code);
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
  if (account.include_in_liquid_cash === false) return false;
  if (account.source === "manual") return true;
  if (account.source !== "plaid") return false;
  if (account.plaid_item_status === "disconnected" || account.plaid_item_disconnected_at) return false;
  const type = (account.plaid_account_type || account.account_type || "").toLowerCase();
  const subtype = (account.plaid_account_subtype || "").toLowerCase();
  if (type === "credit" || type === "loan" || type === "investment") return false;
  if (type === "depository") {
    return ["checking", "savings", "cash management", "money market", "prepaid"].includes(subtype);
  }
  return ["checking", "savings", "cash"].includes(account.account_type);
}

export function effectiveFinanceAccountBalanceCents(account, settings = {}) {
  if (!isLiquidFinanceAccount(account)) return 0;
  if (account.include_in_liquid_cash === false) return 0;
  if (account.source !== "plaid") return Number(account.current_balance_cents || 0);
  if (!settings.use_available_bank_balance) return Number(account.current_balance_cents || 0);
  const type = (account.plaid_account_type || account.account_type || "").toLowerCase();
  const subtype = (account.plaid_account_subtype || "").toLowerCase();
  const eligible = type === "depository" && ["checking", "savings", "cash management", "money market", "prepaid"].includes(subtype);
  if (!eligible) return 0;
  return account.available_balance_cents === null || account.available_balance_cents === undefined
    ? Number(account.current_balance_cents || 0)
    : Number(account.available_balance_cents || 0);
}

export function totalEffectiveLiquidCashCents(accounts, settings = {}) {
  return (accounts || []).reduce((sum, account) => sum + effectiveFinanceAccountBalanceCents(account, settings), 0);
}

function dateOnly(value) {
  if (!value) return null;
  if (value instanceof Date) return value.toISOString().slice(0, 10);
  return String(value).slice(0, 10);
}

function daysBetween(a, b) {
  const left = new Date(`${a}T00:00:00Z`);
  const right = new Date(`${b}T00:00:00Z`);
  return Math.round((right - left) / 86400000);
}

function addDaysToDate(dateString, days) {
  const date = new Date(`${dateString}T00:00:00Z`);
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10);
}

function addMonthsClampedDate(dateString, months) {
  const [year, month, day] = dateString.split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1 + months, 1));
  const maxDay = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 1, 0)).getUTCDate();
  date.setUTCDate(Math.min(day, maxDay));
  return date.toISOString().slice(0, 10);
}

function median(values) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : Math.round((sorted[mid - 1] + sorted[mid]) / 2);
}

function average(values) {
  if (!values.length) return 0;
  return Math.round(values.reduce((sum, value) => sum + value, 0) / values.length);
}

function standardDeviation(values) {
  if (values.length < 2) return 0;
  const avg = average(values);
  const variance = values.reduce((sum, value) => sum + ((value - avg) ** 2), 0) / values.length;
  return Math.round(Math.sqrt(variance));
}

function titleCase(value) {
  return value
    .toLowerCase()
    .split(" ")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export function normalizeRecurringMerchantName(value) {
  let text = (value || "").toString().toUpperCase();
  text = text.replace(/^PAYPAL\s*[*-]\s*/, "");
  text = text.replace(/^SQ\s*[*-]\s*/, "");
  text = text.replace(/^TST\s*[*-]\s*/, "");
  text = text.replace(/APPLE\.COM\/BILL.*/, "APPLE");
  text = text.replace(/NETFLIX\.COM.*/, "NETFLIX");
  text = text.replace(/SPOTIFY.*/, "SPOTIFY");
  text = text.replace(/AMZN MKTP.*/, "AMAZON");
  text = text.replace(/[^A-Z0-9 ]+/g, " ");
  text = text.replace(/\b(COM|INC|LLC|USA|US|ONLINE|PAYMENT|PURCHASE|POS|DEBIT|CARD)\b/g, " ");
  text = text.replace(/\b\d{2,}\b/g, " ");
  text = text.replace(/\s+/g, " ").trim();
  return text || "UNKNOWN";
}

function inferCadence(intervals, occurrenceCount) {
  if (!intervals.length) return null;
  const med = median(intervals);
  const checks = [
    { cadence: "weekly", min: 6, max: 8, minOccurrences: 3, nextDays: 7 },
    { cadence: "biweekly", min: 12, max: 16, minOccurrences: 3, nextDays: 14 },
    { cadence: "monthly", min: 25, max: 35, minOccurrences: 2, nextMonths: 1 },
    { cadence: "quarterly", min: 75, max: 105, minOccurrences: 2, nextMonths: 3 },
    { cadence: "yearly", min: 330, max: 400, minOccurrences: 2, nextMonths: 12 }
  ];
  return checks.find((check) => occurrenceCount >= check.minOccurrences && med >= check.min && med <= check.max) || null;
}

function categoryForGroup(transactions) {
  const counts = new Map();
  for (const tx of transactions) {
    const category = tx.normalized_category || tx.category || tx.category_primary || "Other";
    counts.set(category, (counts.get(category) || 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || "Other";
}

function recurringCandidateType({ direction, displayName, category, variability, cadence }) {
  const text = `${displayName} ${category}`.toUpperCase();
  if (direction === "income") return "recurring_income";
  if (text.match(/LOAN|DEBT|CREDIT CARD|IRS|TAX PAYMENT/)) return "debt_payment";
  if (text.match(/RENT|UTILITY|UTILITIES|ELECTRIC|WATER|GAS BILL|INSURANCE|PHONE|INTERNET|TAX/)) return "recurring_bill";
  if (text.match(/NETFLIX|SPOTIFY|APPLE|SUBSCRIPTION|DIGITAL|STREAMING|ENTERTAINMENT|SOFTWARE|SAAS/)) return "subscription";
  if (text.match(/MCDONALD|RESTAURANT|FAST FOOD|FOOD|SHELL|GAS STATION|FUEL|HOME DEPOT|LOWE|HARDWARE|MATERIAL/)) return "repeated_merchant";
  if (["weekly", "biweekly", "monthly", "quarterly", "yearly"].includes(cadence) && variability !== "variable") return "recurring_expense";
  return "repeated_merchant";
}

function confidenceLabel(score) {
  if (score >= 78) return "high";
  if (score >= 55) return "medium";
  return "low";
}

export function monthlyEquivalentCents(amountCents, cadence) {
  switch (cadence) {
  case "weekly": return Math.round(amountCents * 52 / 12);
  case "biweekly": return Math.round(amountCents * 26 / 12);
  case "quarterly": return Math.round(amountCents / 3);
  case "yearly": return Math.round(amountCents / 12);
  default: return amountCents;
  }
}

export function analyzeRecurringTransactionPatterns(transactions, options = {}) {
  const groups = new Map();
  for (const raw of transactions || []) {
    const date = dateOnly(raw.transaction_date);
    if (!date || raw.removed_at || raw.pending || raw.status === "pending") continue;
    const name = raw.merchant_name || raw.original_name || raw.name || raw.description;
    const normalized = normalizeRecurringMerchantName(name);
    if (!normalized || normalized === "UNKNOWN") continue;
    const key = `${raw.direction || "expense"}:${normalized}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push({
      ...raw,
      transaction_date: date,
      amount_cents: Number(raw.amount_cents || 0),
      direction: raw.direction || "expense"
    });
  }

  const candidates = [];
  for (const [key, group] of groups.entries()) {
    const sorted = group.sort((a, b) => a.transaction_date.localeCompare(b.transaction_date));
    const occurrenceCount = sorted.length;
    if (occurrenceCount < 2) continue;
    const intervals = [];
    for (let index = 1; index < sorted.length; index += 1) {
      intervals.push(daysBetween(sorted[index - 1].transaction_date, sorted[index].transaction_date));
    }
    const cadenceInfo = inferCadence(intervals, occurrenceCount);
    const amounts = sorted.map((tx) => tx.amount_cents);
    const med = median(amounts);
    const avg = average(amounts);
    const min = Math.min(...amounts);
    const max = Math.max(...amounts);
    const std = standardDeviation(amounts);
    const variabilityRatio = med > 0 ? (max - min) / med : 0;
    const variability = variabilityRatio <= 0.05 ? "fixed" : variabilityRatio <= 0.20 ? "mostly_fixed" : "variable";
    const category = categoryForGroup(sorted);
    const direction = sorted[0].direction;
    const merchantNormalized = key.split(":").slice(1).join(":");
    const displayName = titleCase(merchantNormalized);
    const cadence = cadenceInfo?.cadence || "irregular";
    let candidateType = recurringCandidateType({ direction, displayName, category, variability, cadence });
    if (!cadenceInfo && occurrenceCount >= 3) candidateType = "repeated_merchant";
    if (!cadenceInfo && occurrenceCount < 3) continue;
    const cadenceConsistency = cadenceInfo ? intervals.filter((interval) => interval >= cadenceInfo.min && interval <= cadenceInfo.max).length / intervals.length : 0;
    let score = 20;
    score += Math.min(25, occurrenceCount * 5);
    score += Math.round(cadenceConsistency * 30);
    score += variability === "fixed" ? 20 : variability === "mostly_fixed" ? 12 : 4;
    if (candidateType !== "repeated_merchant") score += 8;
    score = Math.max(0, Math.min(100, score));
    const lastDate = sorted[sorted.length - 1].transaction_date;
    const nextExpectedDate = cadenceInfo?.nextMonths
      ? addMonthsClampedDate(lastDate, cadenceInfo.nextMonths)
      : cadenceInfo?.nextDays
        ? addDaysToDate(lastDate, cadenceInfo.nextDays)
        : null;
    candidates.push({
      merchant_normalized: merchantNormalized,
      display_name: displayName,
      direction,
      candidate_type: candidateType,
      cadence,
      average_amount_cents: avg,
      median_amount_cents: med,
      min_amount_cents: min,
      max_amount_cents: max,
      variability,
      variability_score_cents: std,
      first_seen_date: sorted[0].transaction_date,
      last_seen_date: lastDate,
      next_expected_date: nextExpectedDate,
      occurrence_count: occurrenceCount,
      confidence_score: score,
      confidence_label: confidenceLabel(score),
      source: "wolfcrm_inferred",
      category,
      account_id: sorted[sorted.length - 1].account_id || null,
      source_transaction_ids: sorted.map((tx) => tx.id).filter(Boolean),
      monthly_equivalent_cents: monthlyEquivalentCents(med, cadence)
    });
  }
  return candidates
    .filter((candidate) => candidate.confidence_score >= (options.minimumConfidence || 35))
    .sort((a, b) => b.confidence_score - a.confidence_score || b.occurrence_count - a.occurrence_count);
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
