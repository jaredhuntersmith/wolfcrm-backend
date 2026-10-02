import { randomUUID } from 'node:crypto';
import { QuoteContractError } from './quote-contract-domain.js';

// Financial and signed evidence deliberately has RESTRICT foreign keys. Removing
// a draft from the CRM must not cascade through those retained business records.
export async function removeQuote(pool, req, id) {
  if (typeof id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) throw new QuoteContractError('quote_id_invalid', 'Choose a valid quote.');
  const db = await pool.connect();
  try {
    await db.query('BEGIN');
    const scope = req.companyId ? '(company_id=$2 OR (company_id IS NULL AND user_id=$3))' : 'user_id=$2';
    const args = req.companyId ? [id, req.companyId, req.userId] : [id, req.userId];
    // Non-key lifecycle changes do not need to block foreign-key KEY SHARE
    // checks made by a concurrent signed customer's booking/payment transaction.
    const row = (await db.query(`SELECT * FROM quotes WHERE id=$1 AND ${scope} FOR NO KEY UPDATE`, args)).rows[0];
    if (!row) { await db.query('COMMIT'); return null; }
    if (!row.deleted_at) {
      const agreements = (await db.query('SELECT id FROM quote_agreements WHERE quote_id=$1 ORDER BY id FOR UPDATE', [id])).rows;
      for (const agreement of agreements) {
        const retained = (await db.query('SELECT EXISTS(SELECT 1 FROM agreement_signatures WHERE agreement_id=$1) OR EXISTS(SELECT 1 FROM payment_records WHERE agreement_id=$1) AS active', [agreement.id])).rows[0].active;
        if (!retained) await db.query('UPDATE quote_agreements SET revoked_at=COALESCE(revoked_at,now()),token_generation=token_generation+1,updated_at=now() WHERE id=$1', [agreement.id]);
        await db.query("INSERT INTO agreement_events(id,agreement_id,type,actor_type,actor_id,payload) VALUES($1,$2,'quote_removed',$3,$4,$5::jsonb)", [randomUUID(),agreement.id,req.userId ? "staff" : "automation",req.userId,JSON.stringify({quote_id:id,customer_access_retained:retained})]);
      }
      await db.query('UPDATE quotes SET deleted_at=now(),updated_at=now() WHERE id=$1', [id]);
    }
    await db.query('COMMIT');
    return row;
  } catch (error) { await db.query('ROLLBACK'); throw error; }
  finally { db.release(); }
}
