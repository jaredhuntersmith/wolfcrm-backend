import {lockCompanySchedule} from './schedule-booking-guard.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function installScheduleDraftSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS schedule_draft_epochs (
      scope_id UUID NOT NULL,
      contact_id TEXT NOT NULL,
      generation BIGINT NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY(scope_id, contact_id)
    );
    CREATE TABLE IF NOT EXISTS schedule_drafts (
      id UUID PRIMARY KEY,
      scope_id UUID NOT NULL,
      company_id UUID REFERENCES companies(id) ON DELETE CASCADE,
      owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      contact_id TEXT,
      quote_id UUID,
      payload JSONB NOT NULL DEFAULT '{}'::jsonb,
      contact_generation BIGINT,
      client_revision BIGINT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '30 days'
    );
    CREATE TABLE IF NOT EXISTS schedule_draft_tombstones (
      scope_id UUID NOT NULL,
      id UUID NOT NULL,
      PRIMARY KEY(scope_id,id),
      cleared_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS schedule_drafts_owner_idx
      ON schedule_drafts(scope_id, owner_user_id, updated_at DESC);
    CREATE INDEX IF NOT EXISTS schedule_drafts_contact_idx
      ON schedule_drafts(scope_id, contact_id);
    CREATE INDEX IF NOT EXISTS schedule_drafts_expiry_idx
      ON schedule_drafts(expires_at);
  `);
}

export async function clearScheduleDraftsForContact(db, scopeID, contactID, extraDraftID = null, extraOwnerID = null) {
  if (!scopeID || !contactID) return;
  await db.query(`
    INSERT INTO schedule_draft_epochs(scope_id, contact_id, generation)
    VALUES($1, $2, 1)
    ON CONFLICT(scope_id, contact_id) DO UPDATE
      SET generation=schedule_draft_epochs.generation+1, updated_at=now()
  `, [scopeID, contactID]);
  const deleted=await db.query('DELETE FROM schedule_drafts WHERE scope_id=$1 AND contact_id=$2 RETURNING id', [scopeID, contactID]);
  const ids=deleted.rows.map(row=>row.id);
  if (UUID.test(extraDraftID || '') && extraOwnerID) {
    const existing=await db.query('SELECT scope_id,owner_user_id FROM schedule_drafts WHERE id=$1', [extraDraftID]);
    if (!existing.rowCount || (existing.rows[0].scope_id===scopeID && existing.rows[0].owner_user_id===extraOwnerID)) ids.push(extraDraftID);
  }
  const uniqueIDs=[...new Set(ids)];
  if (uniqueIDs.length) await db.query(`INSERT INTO schedule_draft_tombstones(id,scope_id)
    SELECT value::uuid,$2 FROM unnest($1::uuid[]) AS value ON CONFLICT(scope_id,id) DO NOTHING`, [uniqueIDs,scopeID]);
}

async function lockedGeneration(db, scopeID, contactID) {
  await db.query(`INSERT INTO schedule_draft_epochs(scope_id,contact_id)
    VALUES($1,$2) ON CONFLICT(scope_id,contact_id) DO NOTHING`, [scopeID, contactID]);
  const {rows} = await db.query(`SELECT generation FROM schedule_draft_epochs
    WHERE scope_id=$1 AND contact_id=$2 FOR UPDATE`, [scopeID, contactID]);
  return Number(rows[0].generation);
}

function scope(req) { return req.companyId || req.userId; }
function validContactID(value) { return typeof value === 'string' && value.trim().length > 0 && value.length <= 256; }
function validRevision(value) { return Number.isSafeInteger(value) && value > 0 && value <= 1_000_000_000; }
function isObject(value) { return value && typeof value === 'object' && !Array.isArray(value); }
function draftForClient(row) {
  return {
    ...row,
    contact_generation: row.contact_generation == null ? null : Number(row.contact_generation),
    client_revision: Number(row.client_revision)
  };
}

export function installScheduleDraftRoutes({app,pool,authRequired,requireAllCapabilities,requireCapability,requireAnyCapability}) {
  app.get('/api/schedule/drafts', authRequired, requireAllCapabilities('schedule.view','jobs.view'), async (req,res) => {
    res.set('Cache-Control','private, no-store');
    const contactID=req.query.contact_id;
    if (contactID != null && !validContactID(contactID)) return res.status(400).json({error:'invalid_contact_id'});
    try {
      const {rows}=await pool.query(`SELECT id,contact_id,quote_id,payload,contact_generation,client_revision,
        created_at,updated_at,expires_at FROM schedule_drafts
        WHERE scope_id=$1 AND owner_user_id=$2 AND expires_at>now() ORDER BY updated_at DESC`, [scope(req),req.userId]);
      let contactGeneration=null;
      if (contactID) {
        const epoch=await pool.query('SELECT generation FROM schedule_draft_epochs WHERE scope_id=$1 AND contact_id=$2', [scope(req),contactID]);
        contactGeneration=Number(epoch.rows[0]?.generation || 0);
      }
      res.json({drafts:rows.map(draftForClient),contact_generation:contactGeneration,server_time:new Date().toISOString()});
    } catch(error) { console.error('[schedule] list drafts failed',error);res.status(500).json({error:'schedule_drafts_load_failed'}); }
  });

  app.put('/api/schedule/drafts/:id', authRequired, requireCapability('jobs.view'), requireAnyCapability('schedule.create','schedule.edit'), async (req,res) => {
    const id=req.params.id,body=req.body || {},contactID=body.contact_id ?? null,quoteID=body.quote_id ?? null;
    if (!UUID.test(id) || (contactID !== null && !validContactID(contactID)) ||
        (quoteID !== null && !UUID.test(quoteID)) || !isObject(body.payload) ||
        !validRevision(body.client_revision) || (contactID && !Number.isSafeInteger(body.contact_generation))) {
      return res.status(400).json({error:'invalid_schedule_draft'});
    }
    if (Buffer.byteLength(JSON.stringify(body.payload)) > 65536) return res.status(413).json({error:'schedule_draft_too_large'});
    const db=await pool.connect();
    try {
      await db.query('BEGIN');
      await lockCompanySchedule(db,scope(req));
      if ((await db.query('SELECT 1 FROM schedule_draft_tombstones WHERE id=$1 AND scope_id=$2', [id,scope(req)])).rowCount) {
        await db.query('ROLLBACK');return res.status(409).json({error:'schedule_draft_cleared'});
      }
      if (contactID) {
        const contact=await db.query(`SELECT id FROM contacts WHERE id=$1 AND ${req.companyId ? 'company_id=$2' : 'user_id=$2'}`, [contactID,scope(req)]);
        if (!contact.rowCount) { await db.query('ROLLBACK');return res.status(404).json({error:'contact_not_found'}); }
      }
      if (quoteID) {
        const quote=await db.query(`SELECT id FROM quotes WHERE id=$1 AND ${req.companyId ? 'company_id=$2' : 'user_id=$2'} AND contact_id=$3 AND deleted_at IS NULL`, [quoteID,scope(req),contactID]);
        if (!quote.rowCount) { await db.query('ROLLBACK');return res.status(404).json({error:'quote_not_found'}); }
      }
      const generation=contactID ? await lockedGeneration(db,scope(req),contactID) : null;
      if (contactID && generation !== body.contact_generation) {
        await db.query('ROLLBACK');return res.status(409).json({error:'schedule_draft_cleared',contact_generation:generation});
      }
      const {rows}=await db.query(`INSERT INTO schedule_drafts
        (id,scope_id,company_id,owner_user_id,contact_id,quote_id,payload,contact_generation,client_revision)
        VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)
        ON CONFLICT(id) DO UPDATE SET contact_id=EXCLUDED.contact_id,quote_id=EXCLUDED.quote_id,
          payload=EXCLUDED.payload,contact_generation=EXCLUDED.contact_generation,
          client_revision=EXCLUDED.client_revision,updated_at=now(),expires_at=now()+interval '30 days'
        WHERE schedule_drafts.scope_id=$2 AND schedule_drafts.owner_user_id=$4
          AND schedule_drafts.expires_at>now()
          AND schedule_drafts.client_revision<=EXCLUDED.client_revision
        RETURNING id,contact_id,quote_id,payload,contact_generation,client_revision,created_at,updated_at,expires_at`,
        [id,scope(req),req.companyId || null,req.userId,contactID,quoteID,JSON.stringify(body.payload),generation,body.client_revision]);
      if (!rows.length) { await db.query('ROLLBACK');return res.status(409).json({error:'schedule_draft_changed'}); }
      await db.query('COMMIT');res.json(draftForClient(rows[0]));
    } catch(error) { await db.query('ROLLBACK').catch(()=>{});console.error('[schedule] save draft failed',error);res.status(500).json({error:'schedule_draft_save_failed'}); }
    finally { db.release(); }
  });

  app.delete('/api/schedule/drafts/:id', authRequired, requireCapability('jobs.view'), requireAnyCapability('schedule.create','schedule.edit'), async (req,res) => {
    if (!UUID.test(req.params.id)) return res.status(400).json({error:'invalid_schedule_draft'});
    const db=await pool.connect();
    try {
      await db.query('BEGIN');
      await lockCompanySchedule(db,scope(req));
      const deleted=await db.query('DELETE FROM schedule_drafts WHERE id=$1 AND scope_id=$2 AND owner_user_id=$3 RETURNING id', [req.params.id,scope(req),req.userId]);
      if (deleted.rowCount) await db.query('INSERT INTO schedule_draft_tombstones(id,scope_id) VALUES($1,$2) ON CONFLICT(scope_id,id) DO NOTHING', [req.params.id,scope(req)]);
      await db.query('COMMIT');
      res.status(204).end();
    } catch(error) { await db.query('ROLLBACK').catch(()=>{});console.error('[schedule] delete draft failed',error);res.status(500).json({error:'schedule_draft_delete_failed'}); }
    finally { db.release(); }
  });
}
