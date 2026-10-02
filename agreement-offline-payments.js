import { createHash, randomUUID } from "node:crypto";
import { QuoteContractError } from "./quote-contract-domain.js";

const fail = (code, message, status = 409) => { throw new QuoteContractError(code, message, status); };
const uuid = (value) => {
  if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) fail("payment_request_invalid", "Use a valid payment request ID.", 400);
  return value.toLowerCase();
};

export async function installAgreementOfflinePaymentSchema(pool) {
  await pool.query(`CREATE TABLE IF NOT EXISTS agreement_offline_payment_receipts (
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
    request_id UUID NOT NULL, request_hash TEXT NOT NULL,
    agreement_id UUID NOT NULL REFERENCES quote_agreements(id) ON DELETE RESTRICT,
    payment_record_id UUID NOT NULL UNIQUE REFERENCES payment_records(id) ON DELETE RESTRICT,
    method TEXT NOT NULL CHECK(method IN ('cash','check','other')),
    reference TEXT NOT NULL, note TEXT NOT NULL, received_at TIMESTAMPTZ NOT NULL,
    recorded_by UUID NOT NULL, recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    request_payload JSONB NOT NULL, PRIMARY KEY(company_id,request_id)
  ); CREATE INDEX IF NOT EXISTS agreement_offline_receipts_agreement_idx ON agreement_offline_payment_receipts(agreement_id,recorded_at);`);
}

function receiptInput(raw, now) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw) || Object.keys(raw).some(key => !["request_id","amount_cents","expected_balance_cents","method","reference","received_at","note"].includes(key))) fail("offline_payment_invalid", "Use the receipt amount, method, reference, and received date.", 400);
  const text = (value, max) => typeof value === "string" && value.length <= max && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value);
  if (!Number.isSafeInteger(raw.amount_cents) || raw.amount_cents < 1 || raw.amount_cents > 2000000000 || !Number.isSafeInteger(raw.expected_balance_cents) || raw.expected_balance_cents < 0 || raw.expected_balance_cents > 2000000000) fail("offline_payment_amount_invalid", "Enter positive whole cents and refresh the current balance.", 400);
  if (!["cash", "check", "other"].includes(raw.method) || !text(raw.reference ?? "", 200) || !text(raw.note ?? "", 1000) || (raw.method !== "cash" && !raw.reference?.trim())) fail("offline_payment_reference_required", "Choose a receipt method and provide a reference for check or other payments.", 400);
  const datePart = typeof raw.received_at === "string" ? raw.received_at.slice(0,10) : "";
  const calendarDate = Date.parse(`${datePart}T00:00:00Z`);
  if (typeof raw.received_at !== "string" || !/^\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,3})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/.test(raw.received_at) || !Number.isFinite(Date.parse(raw.received_at)) || !Number.isFinite(calendarDate) || datePart.startsWith("0000") || new Date(calendarDate).toISOString().slice(0,10) !== datePart || Date.parse(raw.received_at) > now.getTime() + 300000) fail("offline_payment_date_invalid", "Enter when this payment was actually received, at or before now.", 400);
  return { request_id: uuid(raw.request_id), amount_cents: raw.amount_cents, expected_balance_cents: raw.expected_balance_cents, method: raw.method,
    reference: raw.reference ?? "", received_at: raw.received_at, note: raw.note ?? "" };
}

export function createAgreementOfflineRecorder({ pool, service, paymentSummary, now = () => new Date() }) {
  return async function recordOffline(req, agreementID, raw) {
    const input = receiptInput(raw, now());
    const initial = await service.loadStaff(pool, req, agreementID);
    const payload = { agreement_id: initial.id, actor_id: req.userId, ...input };
    const hash = createHash("sha256").update(JSON.stringify(payload)).digest("hex");
    const db = await pool.connect();
    try {
      await db.query("BEGIN");
      await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [`payment:${initial.company_id}:${initial.quote_id ? `quote:${initial.quote_id}` : `agreement:${initial.id}`}`]);
      // Request scope is company-wide, including concurrent reuse on two quotes.
      await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [`offline-payment-request:${initial.company_id}:${input.request_id}`]);
      const row = await service.loadStaff(db, req, initial.id, true);
      const previous = (await db.query("SELECT * FROM agreement_offline_payment_receipts WHERE company_id=$1 AND request_id=$2", [row.company_id, input.request_id])).rows[0];
      if (previous && previous.request_hash !== hash) fail("payment_request_conflict", "This receipt request was already used for different content. Refresh before recording another payment.");
      if (previous) {
        const result = { payment_record_id: previous.payment_record_id, status: "recorded", payments: await paymentSummary(db, row) };
        await db.query("COMMIT"); return result;
      }
      if (!row.snapshot.pricing) fail("agreement_has_no_payment", "This agreement has no payment obligation.");
      if (row.revoked_at || ["declined", "superseded"].includes(row.decision)) fail("payment_agreement_unavailable", "Use the current agreement to record this payment.");
      const contact = (await db.query("SELECT id FROM contacts WHERE id=$1 AND company_id=$2", [row.contact_id, row.company_id])).rows[0];
      if (!contact) fail("payment_contact_unavailable", "This agreement's customer is unavailable in this company.");
      const roles = (await db.query("SELECT role FROM agreement_signatures WHERE agreement_id=$1", [row.id])).rows.map(signature => signature.role);
      if (!row.snapshot.required_signers.every(role => roles.includes(role))) fail("payment_signatures_required", "Complete all required signatures before recording payment against this agreement.");
      const summary = await paymentSummary(db, row);
      if (summary.payment_review_required) fail("payment_adjustment_review_required", "Resolve the payment review before recording another receipt.");
      if (summary.active_checkout || summary.processing) fail("payment_already_in_progress", "Reconcile or cancel the existing online checkout before recording an offline receipt.");
      if (input.expected_balance_cents !== summary.balance_cents) fail("payment_amount_changed", "The remaining balance changed. Refresh before recording this receipt.");
      if (input.amount_cents > summary.balance_cents) fail("offline_payment_exceeds_balance", "The receipt exceeds the remaining agreement balance. Review the payment before recording it.");
      const owner = (await db.query("SELECT owner_user_id FROM companies WHERE id=$1", [row.company_id])).rows[0]?.owner_user_id;
      if (!owner) fail("payment_business_unavailable", "The business payment owner is unavailable.");
      const jobs = (await db.query("SELECT id FROM schedule_events WHERE company_id=$1 AND quote_id=$2 AND contact_id=$3", [row.company_id, row.quote_id, row.contact_id])).rows;
      const recordID = randomUUID();
      // Reuse the existing manual representation. Provider identifiers stay NULL.
      await db.query(`INSERT INTO payment_records(id,user_id,company_id,created_by_user_id,contact_id,agreement_id,quote_id,job_id,
        payment_type,status,amount_cents,currency,description,paid_at,refund_amount_known)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,'manual','succeeded',$9,'usd',$10,$11,true)`,
      [recordID, owner, row.company_id, req.userId, row.contact_id, row.id, row.quote_id, jobs.length === 1 ? jobs[0].id : null,
        input.amount_cents, `Offline ${input.method} receipt for estimate #${row.number}`, input.received_at]);
      const receipt = (await db.query(`INSERT INTO agreement_offline_payment_receipts(company_id,request_id,request_hash,agreement_id,payment_record_id,method,reference,note,received_at,recorded_by,request_payload)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb) RETURNING recorded_at`,
      [row.company_id, input.request_id, hash, row.id, recordID, input.method, input.reference, input.note, input.received_at, req.userId, JSON.stringify(payload)])).rows[0];
      await service.event(db, row.id, "payment_succeeded", { request_id: input.request_id, request_hash: hash, actor_type: "staff", actor_id: req.userId,
        payload: { payment_record_id: recordID, kind: "offline", amount_cents: input.amount_cents, method: input.method, reference: input.reference,
          received_at: input.received_at, recorded_at: receipt.recorded_at } });
      const result = { payment_record_id: recordID, status: "recorded", payments: await paymentSummary(db, row) };
      await db.query("COMMIT"); return result;
    } catch (error) { await db.query("ROLLBACK"); throw error; }
    finally { db.release(); }
  };
}
