const DAY_MS = 24 * 60 * 60 * 1000;

export function normalizeMerchantName(value) {
  return (value || "")
    .toString()
    .toUpperCase()
    .replace(/&/g, " AND ")
    .replace(/['’]/g, "")
    .replace(/\b(THE|INC|LLC|LTD|CO|CORP|CORPORATION|STORE)\b/g, " ")
    .replace(/#?\b\d{2,8}\b/g, " ")
    .replace(/[^A-Z0-9 ]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function dateOnly(value) {
  if (!value) return null;
  const raw = value instanceof Date ? value.toISOString().slice(0, 10) : value.toString().slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) return null;
  return raw;
}

function dayDiff(a, b) {
  const aa = dateOnly(a);
  const bb = dateOnly(b);
  if (!aa || !bb) return 99;
  return Math.round(Math.abs(Date.parse(`${aa}T00:00:00Z`) - Date.parse(`${bb}T00:00:00Z`)) / DAY_MS);
}

function tokenSet(value) {
  return new Set(normalizeMerchantName(value).split(" ").filter(Boolean));
}

export function merchantSimilarity(a, b) {
  const left = normalizeMerchantName(a);
  const right = normalizeMerchantName(b);
  if (!left || !right) return 0;
  if (left === right) return 1;
  if (left.includes(right) || right.includes(left)) return 0.9;
  const leftTokens = tokenSet(left);
  const rightTokens = tokenSet(right);
  const shared = [...leftTokens].filter((token) => rightTokens.has(token)).length;
  const total = new Set([...leftTokens, ...rightTokens]).size;
  return total ? shared / total : 0;
}

function amountScore(receipt, transaction) {
  if (receipt.amount_cents === null || receipt.amount_cents === undefined) return 0;
  const diff = Math.abs(Number(receipt.amount_cents) - Number(transaction.amount_cents || 0));
  if (diff === 0) return 1;
  if (diff <= 100) return 0.75;
  if (diff <= 500) return 0.35;
  return 0;
}

function dateScore(receipt, transaction) {
  const receiptDate = receipt.purchase_date;
  const authDiff = dayDiff(receiptDate, transaction.authorized_date);
  const postDiff = dayDiff(receiptDate, transaction.transaction_date);
  const diff = Math.min(authDiff, postDiff);
  if (diff === 0) return 1;
  if (diff === 1) return 0.9;
  if (diff <= 3) return 0.7;
  if (diff <= 7) return 0.35;
  return 0;
}

function locationScore(receipt, transaction) {
  let score = 0;
  if (receipt.city && transaction.location_city && receipt.city.toString().toLowerCase() === transaction.location_city.toString().toLowerCase()) score += 0.5;
  if (receipt.state && transaction.location_region && receipt.state.toString().toLowerCase() === transaction.location_region.toString().toLowerCase()) score += 0.3;
  if (receipt.postal_code && transaction.location_postal_code && receipt.postal_code.toString().slice(0, 5) === transaction.location_postal_code.toString().slice(0, 5)) score += 0.2;
  return Math.min(score, 1);
}

function cardScore(receipt, transaction) {
  const lastFour = (receipt.card_last_four || "").toString();
  if (!/^\d{4}$/.test(lastFour)) return 0;
  const mask = (transaction.account_mask || transaction.mask || "").toString();
  return mask === lastFour ? 1 : 0;
}

export function scoreReceiptCandidate(receipt, transaction) {
  if (transaction.direction !== "expense" || transaction.removed_at) return 0;
  const amount = amountScore(receipt, transaction);
  const date = dateScore(receipt, transaction);
  const merchant = merchantSimilarity(receipt.normalized_merchant_name || receipt.merchant_name, transaction.merchant_name || transaction.original_name);
  const location = locationScore(receipt, transaction);
  const card = cardScore(receipt, transaction);
  if (amount < 0.35 || date === 0) return Math.round((amount * 0.45 + date * 0.2 + merchant * 0.25 + location * 0.05 + card * 0.05) * 100);
  const score = amount * 0.45 + date * 0.2 + merchant * 0.25 + location * 0.05 + card * 0.05;
  return Math.round(Math.max(0, Math.min(score, 1)) * 100);
}

export function chooseReceiptMatch(receipt, transactions, { autoThreshold = 92, ambiguityMargin = 12, possibleThreshold = 55 } = {}) {
  const candidates = transactions
    .map((transaction) => ({ transaction, score: scoreReceiptCandidate(receipt, transaction) }))
    .filter((candidate) => candidate.score >= possibleThreshold)
    .sort((a, b) => b.score - a.score || String(a.transaction.id).localeCompare(String(b.transaction.id)));
  const best = candidates[0] || null;
  const second = candidates[1] || null;
  const autoMatch = Boolean(best && best.score >= autoThreshold && (!second || best.score - second.score >= ambiguityMargin));
  return { autoMatch, best, candidates };
}

export async function findReceiptCandidates(poolOrClient, companyId, receipt, { limit = 10 } = {}) {
  const values = [companyId];
  const conditions = ["t.company_id = $1", "t.removed_at IS NULL", "t.direction = 'expense'"];
  if (receipt.amount_cents !== null && receipt.amount_cents !== undefined) {
    values.push(Math.max(0, Number(receipt.amount_cents) - 500), Number(receipt.amount_cents) + 500);
    conditions.push(`t.amount_cents BETWEEN $${values.length - 1} AND $${values.length}`);
  }
  if (receipt.purchase_date) {
    values.push(receipt.purchase_date);
    conditions.push(`t.transaction_date BETWEEN ($${values.length}::date - INTERVAL '7 days') AND ($${values.length}::date + INTERVAL '7 days')`);
  }
  const { rows } = await poolOrClient.query(
    `SELECT t.*, a.name AS account_name, a.mask AS account_mask, a.institution_name
       FROM finance_transactions t
       JOIN finance_accounts a ON a.id = t.account_id AND a.company_id = t.company_id
      WHERE ${conditions.join(" AND ")}
      ORDER BY t.transaction_date DESC, t.created_at DESC
      LIMIT 80`,
    values
  );
  return chooseReceiptMatch(receipt, rows).candidates.slice(0, limit);
}

export async function matchUnmatchedReceiptsForTransactions(pool, companyId, transactions = []) {
  if (!transactions.length) return { checked: 0, matched: 0 };
  const dates = transactions.map((tx) => dateOnly(tx.transaction_date)).filter(Boolean).sort();
  if (!dates.length) return { checked: 0, matched: 0 };
  const { rows: receipts } = await pool.query(
    `SELECT *
       FROM finance_receipts
      WHERE company_id = $1
        AND archived_at IS NULL
        AND transaction_id IS NULL
        AND status IN ('unmatched','possible_match','processing')
        AND purchase_date BETWEEN ($2::date - INTERVAL '7 days') AND ($3::date + INTERVAL '7 days')`,
    [companyId, dates[0], dates[dates.length - 1]]
  );
  let matched = 0;
  for (const receipt of receipts) {
    const candidates = await findReceiptCandidates(pool, companyId, receipt, { limit: 5 });
    const decision = chooseReceiptMatch(receipt, candidates.map((candidate) => candidate.transaction));
    if (decision.autoMatch) {
      await pool.query(
        `UPDATE finance_receipts
            SET transaction_id = $3, status = 'matched', match_method = 'auto',
                match_confidence = $4, matched_at = now(), updated_at = now()
          WHERE id = $1 AND company_id = $2 AND transaction_id IS NULL`,
        [receipt.id, companyId, decision.best.transaction.id, decision.best.score]
      );
      await pool.query(
        `INSERT INTO finance_receipt_matches(company_id, receipt_id, transaction_id, method, confidence_score, was_selected)
         VALUES($1,$2,$3,'auto',$4,true)`,
        [companyId, receipt.id, decision.best.transaction.id, decision.best.score]
      );
      matched += 1;
    } else if (candidates.length) {
      await pool.query(
        `UPDATE finance_receipts SET status = 'possible_match', match_confidence = $3, updated_at = now()
          WHERE id = $1 AND company_id = $2 AND transaction_id IS NULL`,
        [receipt.id, companyId, candidates[0].score]
      );
    } else {
      await pool.query(
        `UPDATE finance_receipts SET status = 'unmatched', updated_at = now()
          WHERE id = $1 AND company_id = $2 AND transaction_id IS NULL`,
        [receipt.id, companyId]
      );
    }
  }
  return { checked: receipts.length, matched };
}
