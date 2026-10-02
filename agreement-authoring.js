import { QuoteContractError, quoteContentHash } from './quote-contract-domain.js';

const fail = (code, message, status = 400) => { throw new QuoteContractError(code, message, status); };
const uuid = value => {
  if (typeof value !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) fail('editor_id_invalid', 'Choose a valid editor record.');
  return value.toLowerCase();
};

export async function installAgreementAuthoringSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS agreement_authoring_requests (
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
      user_id TEXT NOT NULL, action TEXT NOT NULL, request_id UUID NOT NULL,
      request_hash TEXT NOT NULL, response JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY(company_id,user_id,action,request_id)
    );
    CREATE TABLE IF NOT EXISTS agreement_editor_drafts (
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
      user_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('template','tier')), record_id UUID NOT NULL,
      revision INTEGER NOT NULL DEFAULT 1, base_version INTEGER, payload JSONB,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY(company_id,user_id,kind,record_id)
    );
  `);
}

// Caller owns the transaction: the committed mutation and replay response are atomic.
export async function authoringRequest(db, req, action, raw, work) {
  if (!raw.request_id) return work(); // Preserve older clients.
  const requestID = uuid(raw.request_id), hash = quoteContentHash(raw);
  const key = [req.companyId, String(req.userId), action, requestID];
  await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [`agreement-authoring:${key.join(':')}`]);
  const previous = (await db.query('SELECT request_hash,response FROM agreement_authoring_requests WHERE company_id=$1 AND user_id=$2 AND action=$3 AND request_id=$4', key)).rows[0];
  if (previous) {
    if (previous.request_hash !== hash) fail('editor_request_conflict', 'This save request was already used for different changes.', 409);
    return previous.response;
  }
  const response = await work();
  await db.query('INSERT INTO agreement_authoring_requests(company_id,user_id,action,request_id,request_hash,response) VALUES($1,$2,$3,$4,$5,$6::jsonb)', [...key, hash, JSON.stringify(response)]);
  return response;
}

export function installAgreementDraftRoutes({ app, pool, staff, wrap }) {
  const key = req => {
    if (!['template','tier'].includes(req.params.kind)) fail('editor_kind_invalid', 'Choose a template or tier draft.');
    return [req.companyId, String(req.userId), req.params.kind, uuid(req.params.id)];
  };
  app.get('/api/agreements/editor-drafts/:kind/:id', ...staff('settings.manage_company'), wrap(async (req, res) => {
    const row = (await pool.query('SELECT revision,base_version,payload,updated_at FROM agreement_editor_drafts WHERE company_id=$1 AND user_id=$2 AND kind=$3 AND record_id=$4', key(req))).rows[0];
    res.json(row || { revision: 0, base_version: null, payload: null });
  }));
  app.put('/api/agreements/editor-drafts/:kind/:id', ...staff('settings.manage_company'), wrap(async (req, res) => {
    const keys = key(req), raw = req.body;
    uuid(raw.request_id);
    if (!Number.isSafeInteger(raw.expected_revision) || raw.expected_revision < 0 || (raw.base_version != null && (!Number.isSafeInteger(raw.base_version) || raw.base_version < 0))) fail('editor_version_invalid', 'The editor draft version is invalid.');
    if (raw.payload !== null && (!raw.payload || typeof raw.payload !== 'object' || Array.isArray(raw.payload))) fail('editor_draft_invalid', 'The draft must be an object.');
    if (Buffer.byteLength(JSON.stringify(raw.payload)) > 1048576) fail('editor_draft_too_large', 'This editor draft is too large.');
    const db = await pool.connect();
    try {
      await db.query('BEGIN');
      const result = await authoringRequest(db, req, `draft:${keys[2]}:${keys[3]}`, raw, async () => {
        await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [`agreement-draft:${keys.join(':')}`]);
        const prior = (await db.query('SELECT revision FROM agreement_editor_drafts WHERE company_id=$1 AND user_id=$2 AND kind=$3 AND record_id=$4', keys)).rows[0];
        if ((prior?.revision || 0) !== raw.expected_revision) fail('editor_draft_changed', 'This draft changed on another device. Your local edits are retained; review the newer draft before replacing it.', 409);
        return (await db.query(`INSERT INTO agreement_editor_drafts(company_id,user_id,kind,record_id,base_version,payload)
          VALUES($1,$2,$3,$4,$5,$6::jsonb) ON CONFLICT(company_id,user_id,kind,record_id)
          DO UPDATE SET revision=agreement_editor_drafts.revision+1,base_version=EXCLUDED.base_version,payload=EXCLUDED.payload,updated_at=now()
          RETURNING revision,base_version,payload,updated_at`, [...keys, raw.base_version ?? null, JSON.stringify(raw.payload)])).rows[0];
      });
      await db.query('COMMIT'); res.json(result);
    } catch (error) { await db.query('ROLLBACK'); throw error; }
    finally { db.release(); }
  }));
}
