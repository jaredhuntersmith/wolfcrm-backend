const MAX_RECEIVABLE_ROWS = 500;
const MAX_JOB_CONTRIBUTION_ROWS = 500;
const MAX_OPERATIONAL_REPORT_DAYS = 731;
const COLLECTED_STATUSES = new Set(["succeeded", "paid", "partially_refunded", "refunded"]);
const APPROVED_MILEAGE_STATUSES = new Set(["approved", "paid"]);

export class OperationalAccountingError extends Error {
  constructor(code, message, statusCode = 400, details = {}) {
    super(message);
    this.name = "OperationalAccountingError";
    this.code = code;
    this.statusCode = statusCode;
    Object.assign(this, details);
  }
}

function cleanString(value, maxLength = 200) {
  return (value || "").toString().trim().slice(0, maxLength);
}

function exactNonnegativeCents(value, field = "amount_cents") {
  const parsed = typeof value === "string" && /^\d+$/.test(value.trim()) ? Number(value.trim()) : value;
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new OperationalAccountingError(`${field}_invalid`, `${field.replaceAll("_", " ")} must be exact nonnegative cents.`);
  }
  return parsed;
}

function positiveInteger(value, field) {
  const parsed = typeof value === "string" && /^\d+$/.test(value.trim()) ? Number(value.trim()) : value;
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new OperationalAccountingError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return parsed;
}

function dateOnly(value, field = "as_of") {
  const raw = cleanString(value, 20);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    throw new OperationalAccountingError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  const [year, month, day] = raw.split("-").map(Number);
  const parsed = new Date(Date.UTC(year, month - 1, day));
  if (parsed.getUTCFullYear() !== year || parsed.getUTCMonth() !== month - 1 || parsed.getUTCDate() !== day) {
    throw new OperationalAccountingError(`${field}_invalid`, `${field.replaceAll("_", " ")} is invalid.`);
  }
  return raw;
}

function addDays(value, days) {
  const [year, month, day] = value.split("-").map(Number);
  return new Date(Date.UTC(year, month - 1, day + days)).toISOString().slice(0, 10);
}

export function parseJobContributionRange(startValue, endValue) {
  const startDate = dateOnly(startValue, "start_date");
  const endDate = dateOnly(endValue, "end_date");
  if (startDate > endDate) {
    throw new OperationalAccountingError("accounting_range_invalid", "Start date must be on or before end date.");
  }
  if (addDays(startDate, MAX_OPERATIONAL_REPORT_DAYS - 1) < endDate) {
    throw new OperationalAccountingError(
      "accounting_range_too_large",
      `Direct Job Contribution ranges cannot exceed ${MAX_OPERATIONAL_REPORT_DAYS} days.`
    );
  }
  return { start_date: startDate, end_date: endDate };
}

function knownCents(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

export function clockEntrySeconds(entry = {}) {
  const start = new Date(entry.start_at);
  const end = new Date(entry.end_at);
  const breakSeconds = entry.break_seconds == null ? 0 : entry.break_seconds;
  if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || end < start) return null;
  if (!Number.isSafeInteger(breakSeconds) || breakSeconds < 0) return null;
  return Math.max(0, Math.floor((end.getTime() - start.getTime()) / 1000) - breakSeconds);
}

export function buildJobContributionSummary({ jobs = [], mileageLogs = [], timeEntries = [] } = {}) {
  const summary = {
    job_count: jobs.length,
    price_known_count: 0,
    material_known_count: 0,
    comparable_job_count: 0,
    price_unknown_count: 0,
    material_unknown_count: 0,
    known_revenue_cents: 0,
    known_material_cents: 0,
    comparable_revenue_cents: 0,
    comparable_material_cents: 0,
    direct_contribution_cents: 0
  };
  for (const job of jobs) {
    const price = knownCents(job.price_cents);
    const materials = knownCents(job.material_cost_cents);
    if (price == null) summary.price_unknown_count += 1;
    else {
      summary.price_known_count += 1;
      summary.known_revenue_cents += price;
    }
    if (materials == null) summary.material_unknown_count += 1;
    else {
      summary.material_known_count += 1;
      summary.known_material_cents += materials;
    }
    if (price != null && materials != null) {
      summary.comparable_job_count += 1;
      summary.comparable_revenue_cents += price;
      summary.comparable_material_cents += materials;
      summary.direct_contribution_cents += price - materials;
    }
  }

  const operationalCosts = {
    approved_mileage_log_count: 0,
    approved_mileage_reimbursement_cents: 0,
    invalid_approved_mileage_log_count: 0,
    excluded_mileage_log_count: 0,
    completed_clock_entry_count: 0,
    completed_clock_seconds: 0,
    invalid_completed_clock_entry_count: 0,
    open_clock_entry_count: 0,
    disapproved_clock_entry_count: 0
  };
  for (const log of mileageLogs) {
    if (!APPROVED_MILEAGE_STATUSES.has(cleanString(log.status, 40).toLowerCase())) {
      operationalCosts.excluded_mileage_log_count += 1;
      continue;
    }
    const reimbursement = knownCents(log.reimbursement_cents);
    if (reimbursement == null) {
      operationalCosts.invalid_approved_mileage_log_count += 1;
      continue;
    }
    operationalCosts.approved_mileage_log_count += 1;
    operationalCosts.approved_mileage_reimbursement_cents += reimbursement;
  }
  for (const entry of timeEntries) {
    if (cleanString(entry.manual_status || "approved", 40).toLowerCase() === "disapproved") {
      operationalCosts.disapproved_clock_entry_count += 1;
      continue;
    }
    if (!entry.end_at) {
      operationalCosts.open_clock_entry_count += 1;
      continue;
    }
    const seconds = clockEntrySeconds(entry);
    if (seconds == null) {
      operationalCosts.invalid_completed_clock_entry_count += 1;
      continue;
    }
    operationalCosts.completed_clock_entry_count += 1;
    operationalCosts.completed_clock_seconds += seconds;
  }
  return { summary, operational_costs: operationalCosts };
}

function dbInteger(value, field) {
  const parsed = typeof value === "string" && /^-?\d+$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(parsed)) {
    throw new OperationalAccountingError("accounting_source_inexact", `${field.replaceAll("_", " ")} exceeds exact integer range.`, 500);
  }
  return parsed;
}

function nullableDbInteger(value, field) {
  return value == null ? null : dbInteger(value, field);
}

function dateDifferenceDays(laterDate, earlierValue) {
  const earlier = earlierValue instanceof Date ? earlierValue : new Date(earlierValue);
  const later = new Date(`${laterDate}T00:00:00.000Z`);
  if (!Number.isFinite(earlier.getTime())) return 0;
  const earlierDay = Date.UTC(earlier.getUTCFullYear(), earlier.getUTCMonth(), earlier.getUTCDate());
  return Math.max(0, Math.floor((later.getTime() - earlierDay) / 86_400_000));
}

export function isCollectedPaymentStatus(status) {
  return COLLECTED_STATUSES.has(cleanString(status, 40).toLowerCase());
}

export function normalizeStripeRefundState({ paymentAmountCents, providerRefundedCents, providerFullyRefunded = false }) {
  const payment = exactNonnegativeCents(paymentAmountCents, "payment_amount_cents");
  const provider = exactNonnegativeCents(providerRefundedCents, "provider_refunded_cents");
  const refunded = Math.min(payment, provider);
  const fullyRefunded = providerFullyRefunded || (payment > 0 && refunded >= payment);
  return {
    refunded_amount_cents: refunded,
    refund_amount_known: true,
    status: fullyRefunded ? "refunded" : refunded > 0 ? "partially_refunded" : "succeeded"
  };
}

export function normalizePaymentJobLink({ body = {}, payment, job = null }) {
  const expectedVersion = positiveInteger(body.expected_version, "expected_version");
  const currentVersion = Number(payment.accounting_link_version || 1);
  if (expectedVersion !== currentVersion) {
    throw new OperationalAccountingError(
      "payment_job_link_stale",
      "This payment link changed after it was loaded. Refresh before saving again.",
      409,
      { current_version: currentVersion }
    );
  }

  const requestedJobId = body.job_id == null ? null : cleanString(body.job_id, 120) || null;
  const currentJobId = payment.job_id ? String(payment.job_id) : null;
  const reason = cleanString(body.reason, 500) || null;
  if (currentJobId && currentJobId !== requestedJobId && !reason) {
    throw new OperationalAccountingError(
      "payment_job_link_reason_required",
      "Add a reason before moving or removing an existing payment link."
    );
  }
  if (requestedJobId) {
    if (!job || String(job.id) !== requestedJobId) {
      throw new OperationalAccountingError("accounting_job_not_found", "The job was not found.", 404);
    }
    const paymentContact = payment.contact_id == null ? null : String(payment.contact_id);
    const jobContact = job.contact_id == null ? null : String(job.contact_id);
    if (!paymentContact || !jobContact || paymentContact !== jobContact) {
      throw new OperationalAccountingError(
        "payment_job_contact_mismatch",
        "Payments can only be linked to a job for the same customer.",
        409
      );
    }
  }
  return {
    expected_version: expectedVersion,
    job_id: requestedJobId,
    reason,
    changed: currentJobId !== requestedJobId
  };
}

export function buildReceivableSnapshot({ job, payments = [], asOf }) {
  const asOfDate = dateOnly(asOf);
  const hasPrice = Number.isSafeInteger(job.price_cents) && job.price_cents >= 0;
  const amount = hasPrice ? job.price_cents : 0;
  let gross = 0;
  let refunds = 0;
  let timingUnknown = 0;
  let refundUnknown = 0;
  let linkedCount = 0;
  for (const payment of payments) {
    linkedCount += 1;
    if (!isCollectedPaymentStatus(payment.status)) continue;
    if (payment.status === "refunded" && payment.refund_amount_known === false) {
      refundUnknown += 1;
      continue;
    }
    if (payment.paid_at && String(payment.paid_at).slice(0, 10) > asOfDate) continue;
    if (!payment.paid_at) timingUnknown += 1;
    const paymentAmount = exactNonnegativeCents(payment.amount_cents);
    const refundAmount = payment.refund_amount_known === false
      ? 0
      : Math.min(paymentAmount, exactNonnegativeCents(payment.refunded_amount_cents || 0, "refunded_amount_cents"));
    gross += paymentAmount;
    refunds += refundAmount;
  }
  const net = Math.max(0, gross - refunds);
  const outstanding = hasPrice ? Math.max(0, amount - net) : 0;
  const credit = hasPrice ? Math.max(0, net - amount) : 0;
  const status = !hasPrice ? "unpriced" : credit > 0 ? "credit" : outstanding === 0 ? "paid" : net > 0 ? "partial" : "unpaid";
  return {
    job_id: String(job.id),
    amount_cents: amount,
    has_price: hasPrice,
    gross_payment_cents: gross,
    refund_cents: refunds,
    net_payment_cents: net,
    outstanding_cents: outstanding,
    credit_cents: credit,
    linked_payment_count: linkedCount,
    payment_timing_unknown_count: timingUnknown,
    refund_amount_unknown_count: refundUnknown,
    age_days: dateDifferenceDays(asOfDate, job.finished_at),
    status
  };
}

export function summarizeReceivables(rows = []) {
  const summary = {
    job_count: rows.length,
    open_job_count: 0,
    paid_job_count: 0,
    credit_job_count: 0,
    unpriced_job_count: 0,
    receivable_cents: 0,
    net_payment_cents: 0,
    outstanding_cents: 0,
    credit_cents: 0,
    current_cents: 0,
    days_1_30_cents: 0,
    days_31_60_cents: 0,
    days_61_90_cents: 0,
    days_over_90_cents: 0,
    payment_timing_unknown_count: 0,
    refund_amount_unknown_count: 0
  };
  for (const row of rows) {
    if (row.has_price) summary.receivable_cents += Number(row.amount_cents || 0);
    summary.net_payment_cents += Number(row.net_payment_cents || 0);
    summary.outstanding_cents += Number(row.outstanding_cents || 0);
    summary.credit_cents += Number(row.credit_cents || 0);
    summary.payment_timing_unknown_count += Number(row.payment_timing_unknown_count || 0);
    summary.refund_amount_unknown_count += Number(row.refund_amount_unknown_count || 0);
    if (row.status === "unpriced") summary.unpriced_job_count += 1;
    else if (row.status === "paid") summary.paid_job_count += 1;
    else if (row.status === "credit") summary.credit_job_count += 1;
    else summary.open_job_count += 1;
    const outstanding = Number(row.outstanding_cents || 0);
    const age = Number(row.age_days || 0);
    if (age <= 0) summary.current_cents += outstanding;
    else if (age <= 30) summary.days_1_30_cents += outstanding;
    else if (age <= 60) summary.days_31_60_cents += outstanding;
    else if (age <= 90) summary.days_61_90_cents += outstanding;
    else summary.days_over_90_cents += outstanding;
  }
  return summary;
}

export async function installOperationalAccountingSchema(pool) {
  await pool.query(`
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS job_id TEXT;
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS paid_at TIMESTAMPTZ;
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS refunded_amount_cents BIGINT NOT NULL DEFAULT 0;
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS refunded_at TIMESTAMPTZ;
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS refund_amount_known BOOLEAN;
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS stripe_charge_id TEXT;
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS accounting_link_version INTEGER NOT NULL DEFAULT 1;
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS accounting_linked_at TIMESTAMPTZ;
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS accounting_linked_by UUID REFERENCES users(id) ON DELETE SET NULL;
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS client_result_status TEXT;
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS client_result_note TEXT;
    ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS client_result_at TIMESTAMPTZ;

    UPDATE payment_records p
       SET company_id = u.company_id
      FROM users u
     WHERE p.user_id = u.id AND p.company_id IS NULL AND u.company_id IS NOT NULL;
    UPDATE payment_records
       SET refund_amount_known = CASE WHEN status = 'refunded' THEN false ELSE true END
     WHERE refund_amount_known IS NULL;
    UPDATE payment_records
       SET paid_at = created_at
     WHERE paid_at IS NULL AND payment_type = 'manual' AND status IN ('succeeded','paid');
    ALTER TABLE payment_records ALTER COLUMN refund_amount_known SET DEFAULT true;
    ALTER TABLE payment_records ALTER COLUMN refund_amount_known SET NOT NULL;
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'payment_records_refunded_amount_check'
           AND conrelid = 'payment_records'::regclass
      ) THEN
        ALTER TABLE payment_records ADD CONSTRAINT payment_records_refunded_amount_check
          CHECK (refunded_amount_cents >= 0 AND refunded_amount_cents <= amount_cents);
      END IF;
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'payment_records_link_version_check'
           AND conrelid = 'payment_records'::regclass
      ) THEN
        ALTER TABLE payment_records ADD CONSTRAINT payment_records_link_version_check
          CHECK (accounting_link_version > 0);
      END IF;
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'payment_records_job_id_fkey'
           AND conrelid = 'payment_records'::regclass
      ) THEN
        ALTER TABLE payment_records ADD CONSTRAINT payment_records_job_id_fkey
          FOREIGN KEY (job_id) REFERENCES schedule_events(id) ON DELETE SET NULL;
      END IF;
    END $$;
    CREATE INDEX IF NOT EXISTS payment_records_company_job_idx ON payment_records(company_id, job_id);
    CREATE INDEX IF NOT EXISTS payment_records_company_contact_link_idx ON payment_records(company_id, contact_id, job_id, status);
    CREATE INDEX IF NOT EXISTS payment_records_company_pi_accounting_idx
      ON payment_records(company_id, stripe_payment_intent_id) WHERE stripe_payment_intent_id IS NOT NULL;

    CREATE TABLE IF NOT EXISTS finance_operational_sources (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      source_type TEXT NOT NULL CHECK (source_type IN ('job_receivable','payment','refund')),
      source_id TEXT NOT NULL,
      job_id TEXT REFERENCES schedule_events(id) ON DELETE SET NULL,
      payment_record_id UUID REFERENCES payment_records(id) ON DELETE SET NULL,
      contact_id TEXT,
      status TEXT NOT NULL,
      amount_cents BIGINT NOT NULL CHECK (amount_cents >= 0),
      currency TEXT NOT NULL DEFAULT 'usd',
      occurred_at TIMESTAMPTZ,
      evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
      source_version INTEGER NOT NULL DEFAULT 1 CHECK (source_version > 0),
      removed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(company_id, source_type, source_id)
    );
    CREATE INDEX IF NOT EXISTS finance_operational_sources_company_type_idx
      ON finance_operational_sources(company_id, source_type, status, occurred_at);
    CREATE INDEX IF NOT EXISTS finance_operational_sources_company_job_idx
      ON finance_operational_sources(company_id, job_id, source_type) WHERE removed_at IS NULL;
    CREATE INDEX IF NOT EXISTS finance_operational_sources_company_payment_idx
      ON finance_operational_sources(company_id, payment_record_id, source_type);

    CREATE TABLE IF NOT EXISTS finance_operational_link_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      payment_record_id UUID NOT NULL,
      actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      reason TEXT,
      before_job_id TEXT,
      after_job_id TEXT,
      before_version INTEGER NOT NULL,
      after_version INTEGER NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS finance_operational_link_audit_company_payment_idx
      ON finance_operational_link_audit(company_id, payment_record_id, created_at DESC);

    CREATE TABLE IF NOT EXISTS stripe_webhook_events (
      stripe_event_id TEXT PRIMARY KEY,
      connected_account_id TEXT,
      event_type TEXT NOT NULL,
      processing_state TEXT NOT NULL CHECK (processing_state IN ('processing','processed','failed')),
      attempt_count INTEGER NOT NULL DEFAULT 1 CHECK (attempt_count > 0),
      last_error TEXT,
      received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      processed_at TIMESTAMPTZ,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS stripe_webhook_events_state_updated_idx
      ON stripe_webhook_events(processing_state, updated_at);
    CREATE INDEX IF NOT EXISTS mileage_daily_logs_company_date_status_idx
      ON mileage_daily_logs(company_id, service_date, status);
    CREATE INDEX IF NOT EXISTS time_clock_entries_company_completed_start_idx
      ON time_clock_entries(company_id, start_at) WHERE end_at IS NOT NULL;
  `);
}

function sourceChangedSql(alias = "finance_operational_sources") {
  return `(${alias}.job_id, ${alias}.payment_record_id, ${alias}.contact_id, ${alias}.status,
           ${alias}.amount_cents, ${alias}.currency, ${alias}.occurred_at, ${alias}.evidence, ${alias}.removed_at)
          IS DISTINCT FROM
          (EXCLUDED.job_id, EXCLUDED.payment_record_id, EXCLUDED.contact_id, EXCLUDED.status,
           EXCLUDED.amount_cents, EXCLUDED.currency, EXCLUDED.occurred_at, EXCLUDED.evidence, NULL)`;
}

export async function syncOperationalAccountingSources(poolOrClient, companyId) {
  const changed = sourceChangedSql();
  await poolOrClient.query(
    `INSERT INTO finance_operational_sources (
       company_id, source_type, source_id, job_id, contact_id, status,
       amount_cents, currency, occurred_at, evidence
     )
     SELECT se.company_id, 'job_receivable', se.id, se.id, se.contact_id,
            'recognized',
            CASE WHEN se.price_cents >= 0 THEN se.price_cents ELSE 0 END, 'usd', se.finished_at,
            jsonb_build_object(
              'title', LEFT(se.title, 200),
              'has_price', se.price_cents IS NOT NULL AND se.price_cents >= 0,
              'finished_at', se.finished_at,
              'start_at', se.start_at
            )
       FROM schedule_events se WHERE se.company_id = $1 AND se.finished_at IS NOT NULL
     ON CONFLICT(company_id, source_type, source_id) DO UPDATE
       SET job_id = EXCLUDED.job_id,
           contact_id = EXCLUDED.contact_id,
           status = EXCLUDED.status,
           amount_cents = EXCLUDED.amount_cents,
           currency = EXCLUDED.currency,
           occurred_at = EXCLUDED.occurred_at,
           evidence = EXCLUDED.evidence,
           source_version = finance_operational_sources.source_version + 1,
           removed_at = NULL,
           updated_at = now()
     WHERE ${changed}`,
    [companyId]
  );
  await poolOrClient.query(
    `INSERT INTO finance_operational_sources (
       company_id, source_type, source_id, job_id, payment_record_id, contact_id,
       status, amount_cents, currency, occurred_at, evidence
     )
     SELECT p.company_id, 'payment', p.id::text, p.job_id, p.id, p.contact_id::text,
            p.status, p.amount_cents, LOWER(COALESCE(p.currency, 'usd')), p.paid_at,
            jsonb_build_object(
              'payment_type', p.payment_type,
              'description', LEFT(COALESCE(p.description, ''), 300),
              'refund_amount_known', p.refund_amount_known,
              'stripe_payment_intent_id', p.stripe_payment_intent_id
            )
       FROM payment_records p WHERE p.company_id = $1
     ON CONFLICT(company_id, source_type, source_id) DO UPDATE
       SET job_id = EXCLUDED.job_id,
           payment_record_id = EXCLUDED.payment_record_id,
           contact_id = EXCLUDED.contact_id,
           status = EXCLUDED.status,
           amount_cents = EXCLUDED.amount_cents,
           currency = EXCLUDED.currency,
           occurred_at = EXCLUDED.occurred_at,
           evidence = EXCLUDED.evidence,
           source_version = finance_operational_sources.source_version + 1,
           removed_at = NULL,
           updated_at = now()
     WHERE ${changed}`,
    [companyId]
  );
  await poolOrClient.query(
    `INSERT INTO finance_operational_sources (
       company_id, source_type, source_id, job_id, payment_record_id, contact_id,
       status, amount_cents, currency, occurred_at, evidence
     )
     SELECT p.company_id, 'refund', p.id::text, p.job_id, p.id, p.contact_id::text,
            CASE WHEN p.status = 'refunded' THEN 'refunded' ELSE 'partially_refunded' END,
            p.refunded_amount_cents, LOWER(COALESCE(p.currency, 'usd')), p.refunded_at,
            jsonb_build_object(
              'refund_amount_known', p.refund_amount_known,
              'stripe_charge_id', p.stripe_charge_id
            )
       FROM payment_records p
      WHERE p.company_id = $1 AND p.refund_amount_known = true AND p.refunded_amount_cents > 0
     ON CONFLICT(company_id, source_type, source_id) DO UPDATE
       SET job_id = EXCLUDED.job_id,
           payment_record_id = EXCLUDED.payment_record_id,
           contact_id = EXCLUDED.contact_id,
           status = EXCLUDED.status,
           amount_cents = EXCLUDED.amount_cents,
           currency = EXCLUDED.currency,
           occurred_at = EXCLUDED.occurred_at,
           evidence = EXCLUDED.evidence,
           source_version = finance_operational_sources.source_version + 1,
           removed_at = NULL,
           updated_at = now()
     WHERE ${changed}`,
    [companyId]
  );
  await poolOrClient.query(
    `UPDATE finance_operational_sources src
        SET status = 'removed', removed_at = COALESCE(removed_at, now()),
            source_version = source_version + 1, updated_at = now()
      WHERE src.company_id = $1 AND src.removed_at IS NULL AND (
        (src.source_type = 'job_receivable' AND NOT EXISTS (
          SELECT 1 FROM schedule_events se
           WHERE se.company_id = src.company_id AND se.id = src.source_id AND se.finished_at IS NOT NULL
        )) OR
        (src.source_type = 'payment' AND NOT EXISTS (
          SELECT 1 FROM payment_records p WHERE p.company_id = src.company_id AND p.id::text = src.source_id
        )) OR
        (src.source_type = 'refund' AND NOT EXISTS (
          SELECT 1 FROM payment_records p WHERE p.company_id = src.company_id AND p.id::text = src.source_id
            AND p.refund_amount_known = true AND p.refunded_amount_cents > 0
        ))
      )`,
    [companyId]
  );
}

function paymentPayload(row) {
  const amount = Number(row.amount_cents || 0);
  const refund = row.refund_amount_known === false ? null : Number(row.refunded_amount_cents || 0);
  return {
    id: String(row.id),
    contact_id: row.contact_id == null ? null : String(row.contact_id),
    job_id: row.job_id || null,
    service_plan_id: row.service_plan_id || null,
    payment_type: row.payment_type,
    status: row.status,
    amount_cents: amount,
    currency: row.currency || "usd",
    description: row.description || null,
    paid_at: row.paid_at || null,
    refunded_amount_cents: refund,
    refunded_at: row.refunded_at || null,
    refund_amount_known: row.refund_amount_known !== false,
    net_amount_cents: row.refund_amount_known === false ? null : Math.max(0, amount - Number(row.refunded_amount_cents || 0)),
    accounting_link_version: Number(row.accounting_link_version || 1),
    accounting_linked_at: row.accounting_linked_at || null,
    accounting_linked_by: row.accounting_linked_by || null,
    created_at: row.created_at || null,
    updated_at: row.updated_at || null
  };
}

function receivableRowPayload(row) {
  const hasPrice = row.has_price === true || row.has_price === "true";
  const amount = Number(row.amount_cents || 0);
  const gross = Number(row.gross_payment_cents || 0);
  const refunds = Number(row.refund_cents || 0);
  const net = Math.max(0, gross - refunds);
  const outstanding = hasPrice ? Math.max(0, amount - net) : 0;
  const credit = hasPrice ? Math.max(0, net - amount) : 0;
  const status = !hasPrice ? "unpriced" : credit > 0 ? "credit" : outstanding === 0 ? "paid" : net > 0 ? "partial" : "unpaid";
  return {
    job_id: row.job_id,
    contact_id: row.contact_id || null,
    contact_name: row.contact_name || null,
    title: row.title || "Job",
    finished_at: row.finished_at,
    amount_cents: amount,
    has_price: hasPrice,
    gross_payment_cents: gross,
    refund_cents: refunds,
    net_payment_cents: net,
    outstanding_cents: outstanding,
    credit_cents: credit,
    linked_payment_count: Number(row.linked_payment_count || 0),
    pending_payment_count: Number(row.pending_payment_count || 0),
    payment_timing_unknown_count: Number(row.payment_timing_unknown_count || 0),
    refund_amount_unknown_count: Number(row.refund_amount_unknown_count || 0),
    age_days: Number(row.age_days || 0),
    status,
    source_version: Number(row.source_version || 1)
  };
}

const RECEIVABLE_CTE = `
  WITH payment_facts AS (
    SELECT src.job_id,
           COALESCE(SUM(src.amount_cents) FILTER (
             WHERE src.source_type = 'payment'
               AND src.status IN ('succeeded','paid','partially_refunded','refunded')
               AND NOT (src.status = 'refunded' AND COALESCE((src.evidence->>'refund_amount_known')::boolean, false) = false)
               AND (src.occurred_at IS NULL OR src.occurred_at::date <= $2::date)
           ), 0)::bigint AS gross_payment_cents,
           COALESCE(SUM(src.amount_cents) FILTER (
             WHERE src.source_type = 'refund'
               AND (src.occurred_at IS NULL OR src.occurred_at::date <= $2::date)
           ), 0)::bigint AS refund_cents,
           COUNT(*) FILTER (WHERE src.source_type = 'payment')::int AS linked_payment_count,
           COUNT(*) FILTER (WHERE src.source_type = 'payment' AND src.status NOT IN ('succeeded','paid','partially_refunded','refunded'))::int AS pending_payment_count,
           COUNT(*) FILTER (
             WHERE src.source_type = 'payment' AND src.status IN ('succeeded','paid','partially_refunded','refunded')
               AND src.occurred_at IS NULL
               AND NOT (src.status = 'refunded' AND COALESCE((src.evidence->>'refund_amount_known')::boolean, false) = false)
           )::int AS payment_timing_unknown_count,
           COUNT(*) FILTER (
             WHERE src.source_type = 'payment' AND src.status = 'refunded'
               AND COALESCE((src.evidence->>'refund_amount_known')::boolean, false) = false
           )::int AS refund_amount_unknown_count
      FROM finance_operational_sources src
     WHERE src.company_id = $1 AND src.removed_at IS NULL AND src.job_id IS NOT NULL
     GROUP BY src.job_id
  ), receivables AS (
    SELECT job.job_id,
           job.contact_id,
           COALESCE(c.name, NULLIF(job.evidence->>'contact_name', '')) AS contact_name,
           COALESCE(NULLIF(job.evidence->>'title', ''), 'Job') AS title,
           job.occurred_at AS finished_at,
           job.amount_cents,
           COALESCE((job.evidence->>'has_price')::boolean, false) AS has_price,
           job.source_version,
           COALESCE(pay.gross_payment_cents, 0)::bigint AS gross_payment_cents,
           COALESCE(pay.refund_cents, 0)::bigint AS refund_cents,
           GREATEST(0, COALESCE(pay.gross_payment_cents, 0) - COALESCE(pay.refund_cents, 0))::bigint AS net_payment_cents,
           COALESCE(pay.linked_payment_count, 0)::int AS linked_payment_count,
           COALESCE(pay.pending_payment_count, 0)::int AS pending_payment_count,
           COALESCE(pay.payment_timing_unknown_count, 0)::int AS payment_timing_unknown_count,
           COALESCE(pay.refund_amount_unknown_count, 0)::int AS refund_amount_unknown_count,
           GREATEST(0, $2::date - job.occurred_at::date)::int AS age_days
      FROM finance_operational_sources job
      LEFT JOIN payment_facts pay ON pay.job_id = job.job_id
      LEFT JOIN contacts c ON c.id::text = job.contact_id AND c.company_id = job.company_id
     WHERE job.company_id = $1 AND job.source_type = 'job_receivable'
       AND job.status = 'recognized' AND job.removed_at IS NULL
       AND job.occurred_at::date <= $2::date
  )`;

async function loadReceivables(poolOrClient, companyId, asOf, filter, limit, jobId = null) {
  const { rows } = await poolOrClient.query(
    `${RECEIVABLE_CTE}
     SELECT *,
            CASE
              WHEN has_price = false THEN 'unpriced'
              WHEN net_payment_cents > amount_cents THEN 'credit'
              WHEN net_payment_cents = amount_cents THEN 'paid'
              WHEN net_payment_cents > 0 THEN 'partial'
              ELSE 'unpaid'
            END AS calculated_status
       FROM receivables
      WHERE ($3::text IS NULL OR job_id = $3)
        AND ($4 = 'all' OR ($4 = 'open' AND (has_price = false OR net_payment_cents < amount_cents))
             OR ($4 = 'paid' AND has_price = true AND net_payment_cents >= amount_cents))
      ORDER BY
        CASE WHEN has_price = false THEN 0 WHEN net_payment_cents < amount_cents THEN 1 ELSE 2 END,
        age_days DESC, finished_at, job_id
      LIMIT $5`,
    [companyId, asOf, jobId, filter, limit]
  );
  return rows.map(receivableRowPayload);
}

async function loadReceivableSummary(poolOrClient, companyId, asOf) {
  const { rows } = await poolOrClient.query(
    `${RECEIVABLE_CTE}
     SELECT COUNT(*)::int AS job_count,
            COUNT(*) FILTER (WHERE has_price = true AND net_payment_cents < amount_cents)::int AS open_job_count,
            COUNT(*) FILTER (WHERE has_price = true AND net_payment_cents = amount_cents)::int AS paid_job_count,
            COUNT(*) FILTER (WHERE has_price = true AND net_payment_cents > amount_cents)::int AS credit_job_count,
            COUNT(*) FILTER (WHERE has_price = false)::int AS unpriced_job_count,
            COALESCE(SUM(amount_cents) FILTER (WHERE has_price = true), 0)::bigint AS receivable_cents,
            COALESCE(SUM(LEAST(net_payment_cents, amount_cents)) FILTER (WHERE has_price = true), 0)::bigint AS net_payment_cents,
            COALESCE(SUM(GREATEST(0, amount_cents - net_payment_cents)) FILTER (WHERE has_price = true), 0)::bigint AS outstanding_cents,
            COALESCE(SUM(GREATEST(0, net_payment_cents - amount_cents)) FILTER (WHERE has_price = true), 0)::bigint AS credit_cents,
            COALESCE(SUM(GREATEST(0, amount_cents - net_payment_cents)) FILTER (WHERE has_price = true AND age_days = 0), 0)::bigint AS current_cents,
            COALESCE(SUM(GREATEST(0, amount_cents - net_payment_cents)) FILTER (WHERE has_price = true AND age_days BETWEEN 1 AND 30), 0)::bigint AS days_1_30_cents,
            COALESCE(SUM(GREATEST(0, amount_cents - net_payment_cents)) FILTER (WHERE has_price = true AND age_days BETWEEN 31 AND 60), 0)::bigint AS days_31_60_cents,
            COALESCE(SUM(GREATEST(0, amount_cents - net_payment_cents)) FILTER (WHERE has_price = true AND age_days BETWEEN 61 AND 90), 0)::bigint AS days_61_90_cents,
            COALESCE(SUM(GREATEST(0, amount_cents - net_payment_cents)) FILTER (WHERE has_price = true AND age_days > 90), 0)::bigint AS days_over_90_cents,
            COALESCE(SUM(payment_timing_unknown_count), 0)::int AS payment_timing_unknown_count,
            COALESCE(SUM(refund_amount_unknown_count), 0)::int AS refund_amount_unknown_count
       FROM receivables`,
    [companyId, asOf]
  );
  const row = rows[0] || {};
  return Object.fromEntries(Object.entries(row).map(([key, value]) => [key, Number(value || 0)]));
}

async function countReceivables(poolOrClient, companyId, asOf, filter) {
  const { rows } = await poolOrClient.query(
    `${RECEIVABLE_CTE}
     SELECT COUNT(*)::int AS count FROM receivables
      WHERE $3 = 'all' OR ($3 = 'open' AND (has_price = false OR net_payment_cents < amount_cents))
         OR ($3 = 'paid' AND has_price = true AND net_payment_cents >= amount_cents)`,
    [companyId, asOf, filter]
  );
  return Number(rows[0]?.count || 0);
}

function contributionSummaryPayload(row = {}) {
  const fields = [
    "job_count", "price_known_count", "material_known_count", "comparable_job_count",
    "price_unknown_count", "material_unknown_count", "known_revenue_cents", "known_material_cents",
    "comparable_revenue_cents", "comparable_material_cents", "direct_contribution_cents"
  ];
  return Object.fromEntries(fields.map((field) => [field, dbInteger(row[field] || 0, field)]));
}

function operationalCostPayload(mileage = {}, clock = {}) {
  const values = {
    approved_mileage_log_count: mileage.approved_mileage_log_count || 0,
    approved_mileage_reimbursement_cents: mileage.approved_mileage_reimbursement_cents || 0,
    invalid_approved_mileage_log_count: mileage.invalid_approved_mileage_log_count || 0,
    excluded_mileage_log_count: mileage.excluded_mileage_log_count || 0,
    completed_clock_entry_count: clock.completed_clock_entry_count || 0,
    completed_clock_seconds: clock.completed_clock_seconds || 0,
    invalid_completed_clock_entry_count: clock.invalid_completed_clock_entry_count || 0,
    open_clock_entry_count: clock.open_clock_entry_count || 0,
    disapproved_clock_entry_count: clock.disapproved_clock_entry_count || 0
  };
  return Object.fromEntries(Object.entries(values).map(([field, value]) => [field, dbInteger(value, field)]));
}

function contributionJobPayload(row) {
  return {
    job_id: String(row.job_id),
    contact_id: row.contact_id == null ? null : String(row.contact_id),
    contact_name: row.contact_name || null,
    title: row.title || "Job",
    finished_at: row.finished_at,
    price_cents: nullableDbInteger(row.price_cents, "price_cents"),
    material_cost_cents: nullableDbInteger(row.material_cost_cents, "material_cost_cents"),
    direct_contribution_cents: nullableDbInteger(row.direct_contribution_cents, "direct_contribution_cents"),
    has_price: row.has_price === true,
    has_material_cost: row.has_material_cost === true,
    worker_count: dbInteger(row.worker_count || 0, "worker_count")
  };
}

async function loadJobContributionReport(pool, companyId, range, limit) {
  const companyContext = `SELECT COALESCE(NULLIF(timezone, ''), 'America/New_York') AS timezone
                            FROM companies WHERE id = $1`;
  const jobRange = `(se.finished_at AT TIME ZONE company.timezone)::date >= $2::date
                    AND (se.finished_at AT TIME ZONE company.timezone)::date <= $3::date`;
  const [summaryResult, jobResult, mileageResult, clockResult] = await Promise.all([
    pool.query(
      `WITH company AS (${companyContext}), jobs AS (
         SELECT se.id, se.price_cents, se.material_cost_cents
           FROM schedule_events se CROSS JOIN company
          WHERE se.company_id = $1 AND se.finished_at IS NOT NULL AND ${jobRange}
       )
       SELECT (SELECT timezone FROM company) AS timezone,
              COUNT(id)::int AS job_count,
              COUNT(*) FILTER (WHERE price_cents IS NOT NULL AND price_cents >= 0)::int AS price_known_count,
              COUNT(*) FILTER (WHERE material_cost_cents IS NOT NULL AND material_cost_cents >= 0)::int AS material_known_count,
              COUNT(*) FILTER (WHERE price_cents IS NOT NULL AND price_cents >= 0
                                 AND material_cost_cents IS NOT NULL AND material_cost_cents >= 0)::int AS comparable_job_count,
              COUNT(*) FILTER (WHERE price_cents IS NULL OR price_cents < 0)::int AS price_unknown_count,
              COUNT(*) FILTER (WHERE material_cost_cents IS NULL OR material_cost_cents < 0)::int AS material_unknown_count,
              COALESCE(SUM(price_cents) FILTER (WHERE price_cents >= 0), 0)::bigint AS known_revenue_cents,
              COALESCE(SUM(material_cost_cents) FILTER (WHERE material_cost_cents >= 0), 0)::bigint AS known_material_cents,
              COALESCE(SUM(price_cents) FILTER (WHERE price_cents >= 0 AND material_cost_cents >= 0), 0)::bigint AS comparable_revenue_cents,
              COALESCE(SUM(material_cost_cents) FILTER (WHERE price_cents >= 0 AND material_cost_cents >= 0), 0)::bigint AS comparable_material_cents,
              COALESCE(SUM(price_cents::bigint - material_cost_cents::bigint)
                FILTER (WHERE price_cents >= 0 AND material_cost_cents >= 0), 0)::bigint AS direct_contribution_cents
         FROM jobs`,
      [companyId, range.start_date, range.end_date]
    ),
    pool.query(
      `WITH company AS (${companyContext})
       SELECT se.id AS job_id, se.contact_id, c.name AS contact_name, se.title, se.finished_at,
              CASE WHEN se.price_cents >= 0 THEN se.price_cents ELSE NULL END AS price_cents,
              CASE WHEN se.material_cost_cents >= 0 THEN se.material_cost_cents ELSE NULL END AS material_cost_cents,
              se.price_cents IS NOT NULL AND se.price_cents >= 0 AS has_price,
              se.material_cost_cents IS NOT NULL AND se.material_cost_cents >= 0 AS has_material_cost,
              CASE WHEN se.price_cents >= 0 AND se.material_cost_cents >= 0
                   THEN se.price_cents::bigint - se.material_cost_cents::bigint ELSE NULL END AS direct_contribution_cents,
              CASE WHEN jsonb_typeof(se.worker_user_ids) = 'array' THEN jsonb_array_length(se.worker_user_ids) ELSE 0 END AS worker_count
         FROM schedule_events se
         CROSS JOIN company
         LEFT JOIN contacts c ON c.company_id = se.company_id AND c.id::text = se.contact_id
        WHERE se.company_id = $1 AND se.finished_at IS NOT NULL AND ${jobRange}
        ORDER BY CASE WHEN se.price_cents >= 0 AND se.material_cost_cents >= 0 THEN 1 ELSE 0 END,
                 se.finished_at DESC, se.id
        LIMIT $4`,
      [companyId, range.start_date, range.end_date, limit]
    ),
    pool.query(
      `SELECT COUNT(*) FILTER (WHERE status IN ('approved','paid') AND reimbursement_cents >= 0)::int AS approved_mileage_log_count,
              COALESCE(SUM(reimbursement_cents) FILTER (WHERE status IN ('approved','paid') AND reimbursement_cents >= 0), 0)::bigint
                AS approved_mileage_reimbursement_cents,
              COUNT(*) FILTER (WHERE status IN ('approved','paid') AND reimbursement_cents < 0)::int
                AS invalid_approved_mileage_log_count,
              COUNT(*) FILTER (WHERE status NOT IN ('approved','paid'))::int AS excluded_mileage_log_count
         FROM mileage_daily_logs
        WHERE company_id = $1 AND service_date >= $2::date AND service_date <= $3::date`,
      [companyId, range.start_date, range.end_date]
    ),
    pool.query(
      `WITH company AS (${companyContext}), entries AS (
         SELECT e.* FROM time_clock_entries e CROSS JOIN company
          WHERE e.company_id = $1
            AND (e.start_at AT TIME ZONE company.timezone)::date >= $2::date
            AND (e.start_at AT TIME ZONE company.timezone)::date <= $3::date
       )
       SELECT COUNT(*) FILTER (
                WHERE COALESCE(manual_status, 'approved') <> 'disapproved' AND end_at IS NOT NULL
                  AND end_at >= start_at AND COALESCE(break_seconds, 0) >= 0
              )::int AS completed_clock_entry_count,
              COALESCE(SUM(GREATEST(0,
                FLOOR(EXTRACT(EPOCH FROM (end_at - start_at)))::bigint - COALESCE(break_seconds, 0)::bigint
              )) FILTER (
                WHERE COALESCE(manual_status, 'approved') <> 'disapproved' AND end_at IS NOT NULL
                  AND end_at >= start_at AND COALESCE(break_seconds, 0) >= 0
              ), 0)::bigint AS completed_clock_seconds,
              COUNT(*) FILTER (
                WHERE COALESCE(manual_status, 'approved') <> 'disapproved' AND end_at IS NOT NULL
                  AND (end_at < start_at OR COALESCE(break_seconds, 0) < 0)
              )::int AS invalid_completed_clock_entry_count,
              COUNT(*) FILTER (WHERE COALESCE(manual_status, 'approved') <> 'disapproved' AND end_at IS NULL)::int
                AS open_clock_entry_count,
              COUNT(*) FILTER (WHERE COALESCE(manual_status, 'approved') = 'disapproved')::int
                AS disapproved_clock_entry_count
         FROM entries`,
      [companyId, range.start_date, range.end_date]
    )
  ]);
  const rawSummary = summaryResult.rows[0] || {};
  const summary = contributionSummaryPayload(rawSummary);
  const operationalCosts = operationalCostPayload(mileageResult.rows[0], clockResult.rows[0]);
  const jobs = jobResult.rows.map(contributionJobPayload);
  const warnings = [
    "Direct Job Contribution is completed-job price minus material cost for jobs where both exact values are known. It is separate from cash-basis Profit & Loss and Accounts Receivable.",
    "This is not net income: payroll, mileage, overhead, taxes, refunds, and collection timing are not subtracted.",
    "Approved mileage reimbursement and completed clock time are company-level evidence only; neither is allocated to jobs, and clock time is not converted to payroll dollars."
  ];
  if (summary.price_unknown_count > 0 || summary.material_unknown_count > 0) {
    warnings.push("Some completed jobs are excluded from comparable contribution because price or material cost is missing or invalid.");
  }
  if (operationalCosts.invalid_approved_mileage_log_count > 0 || operationalCosts.invalid_completed_clock_entry_count > 0) {
    warnings.push("Invalid approved mileage or completed clock evidence was excluded instead of being treated as zero.");
  }
  if (operationalCosts.open_clock_entry_count > 0) {
    warnings.push("Open clock entries are excluded until clock-out creates complete duration evidence.");
  }
  return {
    basis: "completed_job_direct_contribution_current_source",
    start_date: range.start_date,
    end_date: range.end_date,
    timezone: rawSummary.timezone || "America/New_York",
    currency: "usd",
    summary,
    operational_costs: operationalCosts,
    total_count: summary.job_count,
    returned_count: jobs.length,
    truncated: summary.job_count > jobs.length,
    warnings,
    jobs
  };
}

function sendOperationalError(res, error, fallback) {
  if (error instanceof OperationalAccountingError || error?.statusCode) {
    return res.status(error.statusCode || 400).json({
      error: error.code || fallback,
      message: error.message,
      current_version: error.current_version
    });
  }
  console.error("[finance-operational-accounting]", fallback, { code: error?.code, message: error?.message });
  return res.status(500).json({ error: fallback, message: "Operational accounting request failed." });
}

export async function claimStripeWebhookEvent(pool, event) {
  const eventId = cleanString(event?.id, 255);
  const eventType = cleanString(event?.type, 160);
  if (!eventId || !eventType) throw new OperationalAccountingError("stripe_event_invalid", "Stripe event identity is missing.");
  const connectedAccountId = cleanString(event?.account, 255) || null;
  const claimed = await pool.query(
    `INSERT INTO stripe_webhook_events (
       stripe_event_id, connected_account_id, event_type, processing_state
     ) VALUES ($1,$2,$3,'processing')
     ON CONFLICT(stripe_event_id) DO UPDATE
       SET connected_account_id = EXCLUDED.connected_account_id,
           event_type = EXCLUDED.event_type,
           processing_state = 'processing',
           attempt_count = stripe_webhook_events.attempt_count + 1,
           last_error = NULL,
           processed_at = NULL,
           updated_at = now()
     WHERE stripe_webhook_events.processing_state = 'failed'
        OR (stripe_webhook_events.processing_state = 'processing'
            AND stripe_webhook_events.updated_at < now() - interval '5 minutes')
     RETURNING processing_state, attempt_count`,
    [eventId, connectedAccountId, eventType]
  );
  if (claimed.rowCount) return { claimed: true, duplicate: false, in_progress: false, attempt_count: Number(claimed.rows[0].attempt_count || 1) };
  const existing = await pool.query(`SELECT processing_state, attempt_count FROM stripe_webhook_events WHERE stripe_event_id = $1`, [eventId]);
  const state = existing.rows[0]?.processing_state;
  return {
    claimed: false,
    duplicate: state === "processed",
    in_progress: state === "processing",
    attempt_count: Number(existing.rows[0]?.attempt_count || 1)
  };
}

export async function completeStripeWebhookEvent(pool, eventId) {
  await pool.query(
    `UPDATE stripe_webhook_events
        SET processing_state = 'processed', processed_at = now(), last_error = NULL, updated_at = now()
      WHERE stripe_event_id = $1`,
    [eventId]
  );
}

export async function failStripeWebhookEvent(pool, eventId, error) {
  await pool.query(
    `UPDATE stripe_webhook_events
        SET processing_state = 'failed', last_error = $2, updated_at = now()
      WHERE stripe_event_id = $1`,
    [eventId, cleanString(error?.message || error, 500) || "webhook_processing_failed"]
  );
}

export function installOperationalAccountingRoutes({ app, pool, authRequired, requireEmployer }) {
  app.get("/api/finance/accounting/reports/job-contribution", authRequired, requireEmployer, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Accounting requires a company workspace." });
    try {
      const today = new Date().toISOString().slice(0, 10);
      const range = parseJobContributionRange(
        req.query.start_date || `${today.slice(0, 7)}-01`,
        req.query.end_date || today
      );
      const requestedLimit = Number(req.query.limit || 200);
      const limit = Math.min(
        Math.max(Number.isSafeInteger(requestedLimit) ? requestedLimit : 200, 1),
        MAX_JOB_CONTRIBUTION_ROWS
      );
      res.json(await loadJobContributionReport(pool, req.companyId, range, limit));
    } catch (error) {
      sendOperationalError(res, error, "job_contribution_report_failed");
    }
  });

  app.get("/api/finance/accounting/receivables", authRequired, requireEmployer, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Accounting requires a company workspace." });
    try {
      const asOf = dateOnly(req.query.as_of || new Date().toISOString().slice(0, 10));
      const filter = ["open", "paid", "all"].includes(req.query.status) ? req.query.status : "open";
      const requestedLimit = Number(req.query.limit || 200);
      const limit = Math.min(Math.max(Number.isSafeInteger(requestedLimit) ? requestedLimit : 200, 1), MAX_RECEIVABLE_ROWS);
      await syncOperationalAccountingSources(pool, req.companyId);
      const [summary, rows, total] = await Promise.all([
        loadReceivableSummary(pool, req.companyId, asOf),
        loadReceivables(pool, req.companyId, asOf, filter, limit, null),
        countReceivables(pool, req.companyId, asOf, filter)
      ]);
      const warnings = [
        "Operational receivables are separate from cash-basis Profit & Loss and include only completed WolfCRM jobs plus explicitly linked payments.",
        "Job prices and cumulative refunds reflect their current stored source state; this operational snapshot is not a historical general ledger."
      ];
      if (summary.unpriced_job_count > 0) warnings.push("Some completed jobs need a price and are excluded from receivable money totals.");
      if (summary.payment_timing_unknown_count > 0) warnings.push("Some legacy successful payments have no durable paid timestamp; historical as-of timing may reflect their current status.");
      if (summary.refund_amount_unknown_count > 0) warnings.push("Some legacy refunded payments lack an authoritative refund amount and are excluded from applied-payment totals until reviewed.");
      res.json({
        as_of: asOf,
        currency: "usd",
        status_filter: filter,
        summary,
        total_count: total,
        returned_count: rows.length,
        truncated: total > rows.length,
        warnings,
        receivables: rows
      });
    } catch (error) {
      sendOperationalError(res, error, "receivables_failed");
    }
  });

  app.get("/api/finance/accounting/receivables/:jobId", authRequired, requireEmployer, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Accounting requires a company workspace." });
    try {
      const asOf = dateOnly(req.query.as_of || new Date().toISOString().slice(0, 10));
      await syncOperationalAccountingSources(pool, req.companyId);
      const receivables = await loadReceivables(pool, req.companyId, asOf, "all", 1, req.params.jobId);
      if (!receivables.length) throw new OperationalAccountingError("receivable_not_found", "The completed job receivable was not found.", 404);
      const receivable = receivables[0];
      const paymentResult = await pool.query(
        `SELECT * FROM payment_records
          WHERE company_id = $1 AND (job_id = $2 OR (
            job_id IS NULL AND contact_id::text = $3
          ))
          ORDER BY job_id = $2 DESC, created_at DESC
          LIMIT 200`,
        [req.companyId, receivable.job_id, receivable.contact_id]
      );
      const linkedPayments = [];
      const candidatePayments = [];
      for (const row of paymentResult.rows) {
        const payload = paymentPayload(row);
        if (row.job_id === receivable.job_id) linkedPayments.push(payload);
        else candidatePayments.push(payload);
      }
      const auditResult = await pool.query(
        `SELECT audit.*
           FROM finance_operational_link_audit audit
          WHERE audit.company_id = $1 AND (audit.before_job_id = $2 OR audit.after_job_id = $2)
          ORDER BY audit.created_at DESC LIMIT 100`,
        [req.companyId, receivable.job_id]
      );
      res.json({
        as_of: asOf,
        receivable,
        linked_payments: linkedPayments,
        candidate_payments: candidatePayments,
        audit: auditResult.rows.map((row) => ({
          id: String(row.id), payment_record_id: String(row.payment_record_id), action: row.action,
          reason: row.reason || null, before_job_id: row.before_job_id || null, after_job_id: row.after_job_id || null,
          before_version: Number(row.before_version), after_version: Number(row.after_version),
          actor_user_id: row.actor_user_id || null, created_at: row.created_at
        }))
      });
    } catch (error) {
      sendOperationalError(res, error, "receivable_detail_failed");
    }
  });

  app.put("/api/finance/accounting/payments/:paymentId/job-link", authRequired, requireEmployer, async (req, res) => {
    if (!req.companyId) return res.status(400).json({ error: "company_required", message: "Accounting requires a company workspace." });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const paymentResult = await client.query(
        `SELECT * FROM payment_records WHERE company_id = $1 AND id::text = $2 FOR UPDATE`,
        [req.companyId, req.params.paymentId]
      );
      const payment = paymentResult.rows[0];
      if (!payment) throw new OperationalAccountingError("accounting_payment_not_found", "The payment was not found.", 404);
      const requestedJobId = req.body?.job_id == null ? null : cleanString(req.body.job_id, 120) || null;
      const job = requestedJobId
        ? (await client.query(`SELECT id, contact_id FROM schedule_events WHERE company_id = $1 AND id = $2 FOR UPDATE`, [req.companyId, requestedJobId])).rows[0]
        : null;
      const update = normalizePaymentJobLink({ body: req.body, payment, job });
      if (!update.changed) {
        await client.query("COMMIT");
        return res.json({ payment: paymentPayload(payment), replayed: true });
      }
      const updated = (await client.query(
        `UPDATE payment_records
            SET job_id = $3,
                accounting_link_version = accounting_link_version + 1,
                accounting_linked_at = now(),
                accounting_linked_by = $4,
                updated_at = now()
          WHERE company_id = $1 AND id::text = $2
          RETURNING *`,
        [req.companyId, req.params.paymentId, update.job_id, req.userId]
      )).rows[0];
      const action = !payment.job_id ? "payment_linked" : !update.job_id ? "payment_unlinked" : "payment_relinked";
      await client.query(
        `INSERT INTO finance_operational_link_audit (
           company_id, payment_record_id, actor_user_id, action, reason,
           before_job_id, after_job_id, before_version, after_version
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [req.companyId, payment.id, req.userId, action, update.reason, payment.job_id, update.job_id,
          Number(payment.accounting_link_version || 1), Number(updated.accounting_link_version)]
      );
      await syncOperationalAccountingSources(client, req.companyId);
      await client.query("COMMIT");
      res.json({ payment: paymentPayload(updated), replayed: false });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendOperationalError(res, error, "payment_job_link_failed");
    } finally {
      client.release();
    }
  });
}
