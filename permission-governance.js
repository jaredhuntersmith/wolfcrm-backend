import { randomUUID } from 'node:crypto';
import { PERMISSION_CAPABILITIES, isKnownCapability, resolveAccess, validateAccessUpdate, legacyColumnsForCapabilities } from './permissions.js';

export class PermissionGovernanceError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}
const reject = (status, code, message) => { throw new PermissionGovernanceError(status, code, message); };
const uuid = value => typeof value === 'string' && /^[\da-f]{8}(-[\da-f]{4}){3}-[\da-f]{12}$/i.test(value);
const revision = value => { if (!Number.isSafeInteger(value) || value < 0) reject(400, 'permission_revision_required', 'Refresh employee access and include its current revision.'); return value; };
export function ownerIdentity(row) {
  const id = row.user_id || row.id;
  return Boolean(id && (row.company_id ? row.owner_user_id === id : row.role === 'employer'));
}
export async function installPermissionGovernanceSchema(pool) {
  await pool.query(`
    ALTER TABLE employee_permissions ADD COLUMN IF NOT EXISTS permission_revision bigint NOT NULL DEFAULT 1;
    CREATE TABLE IF NOT EXISTS employee_access_delegations (
      user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      company_id uuid NOT NULL REFERENCES companies(id), scope jsonb NOT NULL DEFAULT '[]'::jsonb,
      revision bigint NOT NULL DEFAULT 1, updated_by uuid NOT NULL REFERENCES users(id), updated_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS permission_governance_audit (
      id uuid PRIMARY KEY, company_id uuid NOT NULL REFERENCES companies(id), actor_user_id uuid NOT NULL REFERENCES users(id),
      target_user_id uuid NOT NULL REFERENCES users(id), action text NOT NULL, previous jsonb NOT NULL, current jsonb NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS permission_governance_audit_target ON permission_governance_audit(company_id,target_user_id,created_at DESC,id);
    CREATE TABLE IF NOT EXISTS permission_change_outbox (
      sequence bigserial PRIMARY KEY, id uuid UNIQUE NOT NULL, company_id uuid NOT NULL REFERENCES companies(id),
      user_id uuid NOT NULL REFERENCES users(id), permission_revision bigint NOT NULL, reason text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(), delivered_at timestamptz
    );
    CREATE INDEX IF NOT EXISTS permission_change_outbox_pending ON permission_change_outbox(sequence) WHERE delivered_at IS NULL;
  `);
}
const rowSQL = `SELECT u.id,u.email,u.display_name,u.role,u.company_id,u.deleted_at,c.owner_user_id,
  to_jsonb(p) AS permission_record,COALESCE(d.scope,'[]'::jsonb) AS delegation_scope,COALESCE(d.revision,0) AS delegation_revision
  FROM users u LEFT JOIN companies c ON c.id=u.company_id
  LEFT JOIN employee_permissions p ON p.user_id=u.id AND p.company_id=u.company_id
  LEFT JOIN employee_access_delegations d ON d.user_id=u.id AND d.company_id=u.company_id`;
function decorate(row) {
  const p = row.permission_record || {};
  const isOwner = ownerIdentity(row);
  return { ...row, isOwner, isAdmin: !isOwner && p.permission_preset === 'admin',
    access: resolveAccess({ role: row.role, isOwner, preset:p.permission_preset, overrides:p.permission_overrides, legacy:p }),
    permission_revision:Number(p.permission_revision || 0), delegation_revision:Number(row.delegation_revision || 0) };
}
const canManage = actor => actor.isOwner || (actor.isAdmin && actor.delegation_scope.length > 0);
function assertTarget(actor, target, next) {
  if (target.company_id !== actor.company_id || !actor.company_id) reject(404,'employee_not_found','Employee not found.');
  if (target.isOwner || target.id === actor.owner_user_id) reject(403,'owner_protected','The company owner cannot be modified through employee administration.');
  if (target.deleted_at) reject(409,'employee_inactive','Restore the employee before editing access.');
  if (!canManage(actor)) reject(403,'access_administration_denied','The employer has not delegated employee access administration.');
  if (!actor.isOwner) {
    if (target.id === actor.id || target.isAdmin || next?.preset === 'admin') reject(403,'admin_boundary','Admins cannot edit themselves, other admins, or grant Admin.');
    const allowed = new Set(actor.delegation_scope);
    for (const item of PERMISSION_CAPABILITIES) {
      if (next && target.access.capabilities[item.key] !== next.capabilities[item.key] && !allowed.has(item.key)) {
        reject(403,'delegation_scope_exceeded','This change exceeds the employer-defined delegation scope.');
      }
    }
    // A preset changes future defaults as well as today's effective booleans. Delegates only alter scoped overrides.
    if (next && next.preset !== target.access.preset) reject(403,'preset_owner_required','Only the employer may change an employee role template.');
  }
}
export function createPermissionGovernance({pool,onChange}) {
  async function load(db,id) {
    if (!uuid(id)) reject(400,'invalid_user_id','Invalid employee identifier.');
    const row = (await db.query(rowSQL+' WHERE u.id=$1',[id])).rows[0];
    if (!row) reject(404,'employee_not_found','Employee not found.');
    return decorate(row);
  }
  async function actorFor(db,context) {
    const actor=await load(db,context.userId);
    if(actor.deleted_at || actor.company_id!==context.companyId) reject(403,'account_inactive','Account access changed. Sign in again.');
    return actor;
  }
  async function record(db,actor,target,action,previous,current,newRevision) {
    await db.query('INSERT INTO permission_governance_audit(id,company_id,actor_user_id,target_user_id,action,previous,current) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb)',[randomUUID(),actor.company_id,actor.id,target.id,action,JSON.stringify(previous),JSON.stringify(current)]);
    const event=(await db.query('INSERT INTO permission_change_outbox(id,company_id,user_id,permission_revision,reason) VALUES($1,$2,$3,$4,$5) RETURNING *',[randomUUID(),actor.company_id,target.id,newRevision,action])).rows[0];
    return event;
  }
  async function transaction(context,work) {
    const db=await pool.connect();let result;
    try {
      await db.query('BEGIN');
      // One company lock makes whole-batch validation and persistence serializable with all governance mutations.
      if(!context.companyId || !(await db.query('SELECT id FROM companies WHERE id=$1 FOR UPDATE',[context.companyId])).rowCount) reject(403,'company_required','A company is required.');
      const actor=await actorFor(db,context);
      result=await work(db,actor);
      await db.query('COMMIT');
    }catch(error){await db.query('ROLLBACK');throw error;}finally{db.release();}
    // Only safe identifiers leave the transaction. Durable rows survive callback/provider failures.
    if(onChange) for(const event of result.events || []) {
      try { await onChange({id:event.id,companyId:event.company_id,userId:event.user_id,revision:Number(event.permission_revision),reason:event.reason});
        await pool.query('UPDATE permission_change_outbox SET delivered_at=now() WHERE id=$1',[event.id]);
      } catch { /* retained for drainInvalidations; no sensitive content logged */ }
    }
    return result.value;
  }
  async function persist(db,actor,target,next) {
    const legacy=legacyColumnsForCapabilities(next.capabilities),cols=Object.keys(legacy);
    const values=[target.id,actor.company_id,next.preset,JSON.stringify(next.overrides),...cols.map(k=>legacy[k])];
    const row=(await db.query(`INSERT INTO employee_permissions(user_id,company_id,permission_preset,permission_overrides,${cols.join(',')}) VALUES(${values.map((_,i)=>'$'+(i+1)+(i===3?'::jsonb':'')).join(',')}) ON CONFLICT(user_id) DO UPDATE SET company_id=EXCLUDED.company_id,permission_preset=EXCLUDED.permission_preset,permission_overrides=EXCLUDED.permission_overrides,${cols.map(k=>k+'=EXCLUDED.'+k).join(',')},permission_revision=employee_permissions.permission_revision+1,updated_at=now() RETURNING *`,values)).rows[0];
    await db.query(`INSERT INTO employee_permission_audit(company_id,employee_user_id,changed_by_user_id,previous_preset,previous_overrides,new_preset,new_overrides) VALUES($1,$2,$3,$4,$5::jsonb,$6,$7::jsonb)`,[actor.company_id,target.id,actor.id,target.access.preset,JSON.stringify(target.access.overrides),next.preset,JSON.stringify(next.overrides)]);
    if(next.preset!=='admin') await db.query("UPDATE employee_access_delegations SET scope='[]'::jsonb,revision=revision+1,updated_at=now(),updated_by=$2 WHERE user_id=$1",[target.id,actor.id]);
    const event=await record(db,actor,target,'access_changed',target.access,next,Number(row.permission_revision));
    return {event,value:{id:target.id,access:next,permission_revision:Number(row.permission_revision),permissions:{...legacy,preset:next.preset,overrides:next.overrides,capabilities:next.capabilities}}};
  }
  async function update(context,updates) {
    if(!Array.isArray(updates)||!updates.length||updates.length>100||new Set(updates.map(x=>x.id)).size!==updates.length) reject(400,'invalid_access_batch','Choose 1–100 unique employees.');
    const parsed=updates.map(input=>({id:input.id,expected:revision(input.expected_revision),next:validateAccessUpdate(input)}));
    return transaction(context,async(db,actor)=>{
      const targets=[];
      for(const input of parsed.slice().sort((a,b)=>a.id.localeCompare(b.id))){
        await db.query("SELECT pg_advisory_xact_lock(hashtextextended('comms-permissions:' || $1,0))",[input.id]);
        await db.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[input.id]);
        const target=await load(db,input.id);assertTarget(actor,target,input.next);
        if(target.permission_revision!==input.expected) reject(409,'permissions_changed','Employee access changed. Refresh before saving.');
        targets.push({target,...input});
      }
      const values=[],events=[];
      for(const item of targets){const saved=await persist(db,actor,item.target,item.next);values.push(saved.value);events.push(saved.event);}
      return {value:{employees:values},events};
    });
  }
  async function legacyUpdate(context,id,body) {
    return transaction(context,async(db,actor)=>{
      if(!actor.isOwner)reject(403,'owner_required','Only the employer can use legacy permission administration.');
      await db.query("SELECT pg_advisory_xact_lock(hashtextextended('comms-permissions:' || $1,0))",[id]);
      await db.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[id]);const target=await load(db,id);assertTarget(actor,target);
      const allowed=Object.keys(legacyColumnsForCapabilities({}));
      if(!body || Object.entries(body).some(([k,v])=>!allowed.includes(k)||typeof v!=='boolean'))reject(400,'invalid_permission_document','Legacy permission values must be known booleans.');
      const old=target.permission_record||{},legacy={...old,...body};
      const projected=resolveAccess({role:'employee',preset:'legacy_employee',legacy});
      const before=resolveAccess({role:'employee',preset:'legacy_employee',legacy:old});
      const overrides={...target.access.overrides};
      for(const item of PERMISSION_CAPABILITIES)if(before.capabilities[item.key]!==projected.capabilities[item.key])overrides[item.key]=projected.capabilities[item.key];
      const saved=await persist(db,actor,target,validateAccessUpdate({preset:target.access.preset,overrides}));
      return {value:{...saved.value.permissions,id},events:[saved.event]};
    });
  }
  async function delegation(context,id,input) {
    const expected=revision(input.expected_revision),scope=input.scope;
    if(!Array.isArray(scope)||scope.length>PERMISSION_CAPABILITIES.length||new Set(scope).size!==scope.length||scope.some(key=>!isKnownCapability(key)||key==='team.manage_access'||key==='team.manage'))reject(400,'invalid_delegation_scope','Select known feature actions; employee administration itself cannot be delegated onward.');
    return transaction(context,async(db,actor)=>{
      if(!actor.isOwner)reject(403,'owner_required','Only the employer can change Admin delegation.');
      await db.query("SELECT pg_advisory_xact_lock(hashtextextended('comms-permissions:' || $1,0))",[id]);
      const target=await load(db,id);assertTarget(actor,target);
      if(!target.isAdmin)reject(409,'admin_required','Assign the Admin role before delegating employee access administration.');
      if(target.delegation_revision!==expected)reject(409,'delegation_changed','Delegation changed. Refresh before saving.');
      const row=(await db.query(`INSERT INTO employee_access_delegations(user_id,company_id,scope,updated_by) VALUES($1,$2,$3::jsonb,$4) ON CONFLICT(user_id) DO UPDATE SET scope=EXCLUDED.scope,revision=employee_access_delegations.revision+1,updated_by=EXCLUDED.updated_by,updated_at=now() RETURNING scope,revision`,[id,actor.company_id,JSON.stringify(scope),actor.id])).rows[0];
      const event=await record(db,actor,target,'delegation_changed',{scope:target.delegation_scope},{scope},target.permission_revision);
      return {value:{id,delegation:{scope:row.scope,revision:Number(row.revision)}},events:[event]};
    });
  }
  async function effective(context){const actor=await actorFor(pool,context);return {is_company_owner:actor.isOwner,owner_user_id:actor.owner_user_id,permission_revision:actor.permission_revision,access:actor.access,can_manage_access:canManage(actor),delegation_scope:actor.isOwner?PERMISSION_CAPABILITIES.map(x=>x.key):actor.delegation_scope};}
  async function employees(context){
    const actor=await actorFor(pool,context);if(!canManage(actor))reject(403,'access_administration_denied','Employee access administration is unavailable.');
    const all=(await pool.query(rowSQL+' WHERE u.company_id=$1 AND u.id<>$2 ORDER BY COALESCE(u.display_name,u.email),u.id',[actor.company_id,actor.owner_user_id||actor.id])).rows.map(decorate);
    return {...await effective(context),employees:all.filter(row=>actor.isOwner||(!row.isAdmin&&row.id!==actor.id)).map(row=>({id:row.id,email:row.email,display_name:row.display_name,role:row.isOwner?'employer':'employee',deleted_at:row.deleted_at,is_admin:row.isAdmin,access:row.access,permission_revision:row.permission_revision,delegation:{scope:row.delegation_scope,revision:row.delegation_revision}}))};
  }
  async function audit(context,id){
    const actor=await actorFor(pool,context),target=await load(pool,id);
    if(!canManage(actor)||actor.company_id!==target.company_id||(!actor.isOwner&&(target.isAdmin||target.id===actor.id)))reject(403,'access_administration_denied','Access audit is unavailable.');
    const rows=(await pool.query(`SELECT history.*,u.display_name AS changed_by_display_name,u.email AS changed_by_email FROM (
      SELECT id,changed_by_user_id,employee_user_id,'access_changed'::text AS action,previous_preset,previous_overrides,new_preset,new_overrides,created_at FROM employee_permission_audit WHERE company_id=$1 AND employee_user_id=$2
      UNION ALL
      SELECT id,actor_user_id,target_user_id,action,'delegation',previous,'delegation',current,created_at FROM permission_governance_audit WHERE company_id=$1 AND target_user_id=$2 AND action<>'access_changed'
    ) history LEFT JOIN users u ON u.id=history.changed_by_user_id ORDER BY history.created_at DESC,history.id DESC LIMIT 100`,[actor.company_id,id])).rows;
    return {entries:rows};
  }

  async function drainInvalidations(callback=onChange,limit=100){if(!callback)return 0;const events=(await pool.query('SELECT * FROM permission_change_outbox WHERE delivered_at IS NULL ORDER BY sequence LIMIT $1',[Math.max(1,Math.min(limit,500))])).rows;for(const e of events){await callback({id:e.id,companyId:e.company_id,userId:e.user_id,revision:Number(e.permission_revision),reason:e.reason});await pool.query('UPDATE permission_change_outbox SET delivered_at=now() WHERE id=$1',[e.id]);}return events.length;}
  return {update,legacyUpdate,delegation,effective,employees,audit,drainInvalidations};
}
export function installPermissionGovernanceRoutes({app,pool,authRequired,onChange}) {
  const service=createPermissionGovernance({pool,onChange});
  const wrap=fn=>async(req,res)=>{res.set('Cache-Control','private, no-store');try{res.json(await fn(req));}catch(e){res.status(e.status||e.statusCode||500).json({error:e.code||'permission_update_failed',message:e.status||e.statusCode?e.message:'Employee access is temporarily unavailable.'});}};
  app.get('/api/me/access',authRequired,wrap(req=>service.effective(req)));
  app.get('/api/company/access/employees',authRequired,wrap(req=>service.employees(req)));
  app.put('/api/company/employees/access-batch',authRequired,wrap(req=>service.update(req,req.body.updates)));
  app.put('/api/company/employees/:id/access',authRequired,wrap(async req=>(await service.update(req,[{...req.body,id:req.params.id}])).employees[0]));
  app.put('/api/company/employees/:id/delegation',authRequired,wrap(req=>service.delegation(req,req.params.id,req.body)));
  app.put('/api/company/employees/:id/permissions',authRequired,wrap(req=>service.legacyUpdate(req,req.params.id,req.body)));
  app.get('/api/company/employees/:id/access-audit',authRequired,wrap(req=>service.audit(req,req.params.id)));
  return service;
}
