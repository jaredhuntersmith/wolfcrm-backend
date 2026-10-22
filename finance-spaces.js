import {installFinanceSourceLocks} from "./finance-source-locks.js";
import {lockFinanceSpaceActor,installFinanceTransactionAccess,checkFinanceTransactionActor} from './finance-space-access.js';
import {hasCapability} from './permissions.js';
import {trackRequestCleanup,hasActiveBusinessTransaction,serializeBusinessTransactionBlock} from './mcp/context.js';
import {installFinanceSpaceTransfers} from './finance-space-transfers.js';
import {AsyncLocalStorage} from 'node:async_hooks';

const context = new AsyncLocalStorage();
const role = 'wolf_finance_request';
const quote = value => '"' + value.replaceAll('"','""') + '"';
const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
function fail(status,message) { const error=new Error(message);error.status=status;throw error; }

export async function installFinanceSpacesSchema(pool) {
 const db=await pool.connect();
 try {
  await db.query('BEGIN');
  await db.query("SET LOCAL lock_timeout='10s'; SET LOCAL statement_timeout='120s'");
  await db.query(`CREATE TABLE IF NOT EXISTS finance_spaces (
   id uuid PRIMARY KEY DEFAULT gen_random_uuid(), company_id uuid NOT NULL REFERENCES companies(id),
   owner_id uuid NOT NULL REFERENCES users(id), name text NOT NULL CHECK(length(name) BETWEEN 1 AND 80),
   kind text NOT NULL DEFAULT 'business' CHECK(kind IN ('personal','business','portfolio')),
   audience text NOT NULL DEFAULT 'private' CHECK(audience IN ('private','selected','company')),
   is_default boolean NOT NULL DEFAULT false, revision integer NOT NULL DEFAULT 1,
   created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
   CHECK(NOT is_default OR kind='personal'), CHECK(kind<>'personal' OR audience='private'));
   ALTER TABLE finance_spaces ADD COLUMN IF NOT EXISTS default_key text;
   ALTER TABLE finance_spaces ADD COLUMN IF NOT EXISTS includes_company_activity boolean NOT NULL DEFAULT false;
   CREATE UNIQUE INDEX IF NOT EXISTS finance_spaces_company_activity ON finance_spaces(company_id) WHERE includes_company_activity;
   CREATE UNIQUE INDEX IF NOT EXISTS finance_spaces_default_key ON finance_spaces(company_id,owner_id,default_key) WHERE default_key IS NOT NULL;
   CREATE UNIQUE INDEX IF NOT EXISTS finance_spaces_default_owner ON finance_spaces(company_id,owner_id) WHERE is_default;
   CREATE INDEX IF NOT EXISTS finance_spaces_company_owner ON finance_spaces(company_id,owner_id);
   CREATE TABLE IF NOT EXISTS finance_space_members(space_id uuid NOT NULL REFERENCES finance_spaces(id) ON DELETE CASCADE,
     user_id uuid NOT NULL REFERENCES users(id), PRIMARY KEY(space_id,user_id));
   CREATE TABLE IF NOT EXISTS finance_space_audit(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),space_id uuid NOT NULL REFERENCES finance_spaces(id),
     actor_id uuid NOT NULL REFERENCES users(id),before_state jsonb,after_state jsonb,created_at timestamptz NOT NULL DEFAULT now());
   DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='${role}') THEN CREATE ROLE ${role} NOLOGIN NOSUPERUSER NOBYPASSRLS; END IF; END $$;`);
  const requestRole=(await db.query("SELECT rolsuper,rolbypassrls,rolcanlogin,rolcreaterole,rolcreatedb FROM pg_roles WHERE rolname=$1",[role])).rows[0];
  if(requestRole.rolsuper||requestRole.rolbypassrls||requestRole.rolcanlogin||requestRole.rolcreaterole||requestRole.rolcreatedb)throw new Error('finance_request_role_must_be_restricted');
  const login=(await db.query('SELECT current_user AS name')).rows[0].name;
  await db.query(`GRANT ${role} TO ${quote(login)}`);
  await db.query(`INSERT INTO finance_spaces(company_id,owner_id,name,kind,is_default)
    SELECT company_id,id,'Personal','personal',true FROM users WHERE company_id IS NOT NULL
    ON CONFLICT(company_id,owner_id) WHERE is_default DO NOTHING`);
  const tables=(await db.query(`SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'
    AND table_name LIKE 'finance\\_%' ESCAPE '\\' AND table_name NOT IN ('finance_spaces','finance_space_members','finance_space_audit') ORDER BY table_name`)).rows.map(r=>r.table_name);
  const columns=new Map();
  for(const table of tables) {
   await db.query(`ALTER TABLE ${quote(table)} ADD COLUMN IF NOT EXISTS id uuid NOT NULL DEFAULT gen_random_uuid()`);
   await db.query(`ALTER TABLE ${quote(table)} ADD COLUMN IF NOT EXISTS finance_space_id uuid REFERENCES finance_spaces(id)`);
   await db.query(`ALTER TABLE ${quote(table)} ALTER COLUMN finance_space_id SET DEFAULT nullif(current_setting('wolf.finance_space',true),'')::uuid`);
   await db.query(`CREATE INDEX IF NOT EXISTS ${quote(table+'_space_idx')} ON ${quote(table)}(finance_space_id)`);
   columns.set(table,new Set((await db.query('SELECT column_name FROM information_schema.columns WHERE table_schema=\'public\' AND table_name=$1',[table])).rows.map(r=>r.column_name)));
  }
  const links=(await db.query(`SELECT child.relname AS child,parent.relname AS parent, ca.attname AS child_key,pa.attname AS parent_key
   FROM pg_constraint c JOIN pg_class child ON child.oid=c.conrelid JOIN pg_class parent ON parent.oid=c.confrelid
   JOIN LATERAL unnest(c.conkey,c.confkey) keys(child_col,parent_col) ON true
   JOIN pg_attribute ca ON ca.attrelid=child.oid AND ca.attnum=keys.child_col
   JOIN pg_attribute pa ON pa.attrelid=parent.oid AND pa.attnum=keys.parent_col
   WHERE c.contype='f' AND child.relnamespace='public'::regnamespace AND parent.relnamespace='public'::regnamespace
   AND child.relname=ANY($1::text[]) AND parent.relname=ANY($1::text[]) AND ca.attname NOT IN ('company_id','finance_space_id')`,[tables])).rows;
  // Only recorded creators establish legacy ownership. Unknown ownership remains inaccessible.
  for(const table of tables) {
   const c=columns.get(table), creator=['created_by','owner_id','user_id','actor_user_id','reviewed_by'].find(name=>c.has(name));
   const parents=links.filter(l=>l.child===table);
   const rootOnly=parents.map(l=>`t.${quote(l.child_key)} IS NULL`).join(' AND ')||'true';
   if(creator&&c.has('company_id'))await db.query(`UPDATE ${quote(table)} t SET finance_space_id=s.id FROM finance_spaces s
    WHERE t.finance_space_id IS NULL AND (${rootOnly}) AND s.is_default AND s.owner_id=t.${quote(creator)} AND s.company_id=t.company_id`);
  }
  // Parent-owned evidence follows its account/item, including provider imports without a creator.
  for(let pass=0;pass<12;pass++) {
   let changed=0;
   for(const l of links)changed+=(await db.query(`UPDATE ${quote(l.child)} c SET finance_space_id=p.finance_space_id FROM ${quote(l.parent)} p
    WHERE c.${quote(l.child_key)}=p.${quote(l.parent_key)} AND c.finance_space_id IS NULL AND p.finance_space_id IS NOT NULL`)).rowCount;
   if(!changed)break;
  }
  // Company-keyed settings become independent space settings. Preserve ambiguous legacy rows.
  for(const table of ['finance_settings','finance_statement_coverage_profiles','finance_balance_sheet_rule_profiles']) {
   if(!tables.includes(table))continue;
   const pk=(await db.query("SELECT conname,pg_get_constraintdef(oid) AS definition FROM pg_constraint WHERE conrelid=$1::regclass AND contype='p'",[table])).rows[0];
   if(pk?.definition==='PRIMARY KEY (company_id)') {
    await db.query(`ALTER TABLE ${quote(table)} ADD COLUMN IF NOT EXISTS id uuid NOT NULL DEFAULT gen_random_uuid()`);
    await db.query(`ALTER TABLE ${quote(table)} DROP CONSTRAINT ${quote(pk.conname)}`);
    await db.query(`ALTER TABLE ${quote(table)} ADD PRIMARY KEY(id)`);
   }
   await db.query(`CREATE UNIQUE INDEX IF NOT EXISTS ${quote(table+'_space_unique')} ON ${quote(table)}(company_id,finance_space_id)`);
  }
  // Chart codes and system accounts must be independently provisioned in every space.
  if(tables.includes('finance_chart_accounts')) {
   const constraints=(await db.query("SELECT conname FROM pg_constraint WHERE conrelid='finance_chart_accounts'::regclass AND contype='u' AND pg_get_constraintdef(oid)='UNIQUE (company_id, code)'")).rows;
   for(const c of constraints)await db.query(`ALTER TABLE finance_chart_accounts DROP CONSTRAINT ${quote(c.conname)}`);
   await db.query(`DROP INDEX IF EXISTS finance_chart_accounts_system_key_idx;
     CREATE UNIQUE INDEX finance_chart_accounts_system_key_idx ON finance_chart_accounts(company_id,finance_space_id,system_key) WHERE system_key IS NOT NULL;
     CREATE UNIQUE INDEX IF NOT EXISTS finance_chart_accounts_space_code ON finance_chart_accounts(company_id,finance_space_id,code);`);
  }
  for(const [table,keys] of [['finance_recurring_candidates',['company_id','merchant_normalized','direction','cadence']],['finance_statement_period_closes',['company_id','version']]]) {
   if(!tables.includes(table))continue;
   const definition='UNIQUE ('+keys.join(', ')+')';
   const constraints=(await db.query("SELECT conname FROM pg_constraint WHERE conrelid=$1::regclass AND contype='u' AND pg_get_constraintdef(oid)=$2",[table,definition])).rows;
   for(const c of constraints)await db.query(`ALTER TABLE ${quote(table)} DROP CONSTRAINT ${quote(c.conname)}`);
   await db.query(`CREATE UNIQUE INDEX IF NOT EXISTS ${quote(table+'_space_natural_key')} ON ${quote(table)}(${keys.map(quote).join(',')},finance_space_id)`);
  }
  await db.query(`CREATE OR REPLACE FUNCTION wolf_finance_visible_spaces() RETURNS uuid[] LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
   SELECT coalesce(array_agg(s.id),'{}'::uuid[]) FROM public.finance_spaces s JOIN public.users u ON u.id=nullif(current_setting('wolf.finance_actor',true),'')::uuid AND u.company_id=s.company_id AND u.deleted_at IS NULL AND (to_jsonb(u)->>'locked_at') IS NULL
   WHERE s.company_id=nullif(current_setting('wolf.finance_company',true),'')::uuid
    AND (s.owner_id=u.id OR s.audience='company' OR (s.audience='selected' AND EXISTS(SELECT 1 FROM public.finance_space_members m WHERE m.space_id=s.id AND m.user_id=u.id)))
    AND (current_setting('wolf.finance_space',true)='combined' OR s.id=CASE WHEN current_setting('wolf.finance_space',true)<>'combined' THEN nullif(current_setting('wolf.finance_space',true),'')::uuid END)
   $$;
   REVOKE ALL ON FUNCTION wolf_finance_visible_spaces() FROM PUBLIC;
   GRANT EXECUTE ON FUNCTION wolf_finance_visible_spaces() TO ${role};
   GRANT USAGE ON SCHEMA public TO ${role};
   GRANT SELECT ON ALL TABLES IN SCHEMA public TO ${role};
   GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ${role};`);
  for(const table of tables) {
   await db.query(`ALTER TABLE ${quote(table)} ENABLE ROW LEVEL SECURITY;
     DROP POLICY IF EXISTS wolf_finance_space ON ${quote(table)};
     CREATE POLICY wolf_finance_space ON ${quote(table)} AS RESTRICTIVE TO ${role}
       USING(finance_space_id=ANY((SELECT wolf_finance_visible_spaces())::uuid[]))
       WITH CHECK(finance_space_id=ANY((SELECT wolf_finance_visible_spaces())::uuid[]));
     DROP POLICY IF EXISTS wolf_finance_request_access ON ${quote(table)};
     CREATE POLICY wolf_finance_request_access ON ${quote(table)} TO ${role} USING(true) WITH CHECK(true);
     GRANT SELECT,INSERT,UPDATE,DELETE ON ${quote(table)} TO ${role};`);
   // A row cannot link private evidence in another space, even when both are visible.
   const parentLinks=links.filter(l=>l.child===table);
   const checks=parentLinks.map(l=>`IF NEW.${quote(l.child_key)} IS NOT NULL THEN
     SELECT finance_space_id INTO parent_space FROM public.${quote(l.parent)} WHERE ${quote(l.parent_key)}=NEW.${quote(l.child_key)};
     IF parent_space IS NULL AND NEW.finance_space_id IS NOT NULL THEN RAISE EXCEPTION 'finance_parent_space_unassigned' USING ERRCODE='23514'; END IF;
     IF parent_space IS NOT NULL THEN
      IF NEW.finance_space_id IS NULL THEN NEW.finance_space_id:=parent_space;
      ELSIF NEW.finance_space_id<>parent_space THEN RAISE EXCEPTION 'finance_cross_space_reference' USING ERRCODE='23514'; END IF;
     END IF; END IF;`).join('\n');
   await db.query(`CREATE OR REPLACE FUNCTION ${quote(table+'_space_guard')}() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    DECLARE parent_space uuid; BEGIN IF current_user <> '${role}' AND current_setting('wolf.finance_move',true)='on' THEN RETURN NEW; END IF; ${checks} RETURN NEW; END $$;
    DROP TRIGGER IF EXISTS wolf_finance_space_guard ON ${quote(table)};
    CREATE TRIGGER wolf_finance_space_guard BEFORE INSERT OR UPDATE ON ${quote(table)} FOR EACH ROW EXECUTE FUNCTION ${quote(table+'_space_guard')}();`);
  }
  await db.query(`CREATE OR REPLACE FUNCTION wolf_finance_company_activity() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT EXISTS(SELECT 1 FROM public.finance_spaces s WHERE s.id=ANY(public.wolf_finance_visible_spaces()) AND s.includes_company_activity)
   $$; REVOKE ALL ON FUNCTION wolf_finance_company_activity() FROM PUBLIC; GRANT EXECUTE ON FUNCTION wolf_finance_company_activity() TO ${role};`);
  // These CRM sources remain company-owned; Finance can import them in one explicitly selected Business space.
  for(const table of ['schedule_events','payment_records','employee_pay_structures','mileage_daily_logs','time_clock_entries','time_clock_settings','quotes']) {
   const exists=await db.query("SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name=$1",[table]);
   if(!exists.rowCount)continue;
   const companyCheck=exists.rows.some(r=>r.column_name==='company_id')?"company_id=nullif(current_setting('wolf.finance_company',true),'')::uuid":"false";
   await db.query(`ALTER TABLE ${quote(table)} ENABLE ROW LEVEL SECURITY; DROP POLICY IF EXISTS wolf_finance_company_source ON ${quote(table)};
    CREATE POLICY wolf_finance_company_source ON ${quote(table)} AS RESTRICTIVE TO ${role} USING((${companyCheck}) AND (SELECT wolf_finance_company_activity())) WITH CHECK((${companyCheck}) AND (SELECT wolf_finance_company_activity()));
    DROP POLICY IF EXISTS wolf_finance_request_access ON ${quote(table)}; CREATE POLICY wolf_finance_request_access ON ${quote(table)} TO ${role} USING(true) WITH CHECK(true);`);
  }
  await db.query(`GRANT UPDATE(job_id,accounting_link_version,accounting_linked_at,accounting_linked_by,updated_at) ON payment_records TO ${role}; GRANT UPDATE(id) ON schedule_events TO ${role};`);
  await installFinanceSourceLocks(db);
  await installFinanceTransactionAccess(db);
  await db.query('COMMIT');
  return {tables:tables.length};
 } catch(error) {await db.query('ROLLBACK');throw error;} finally {db.release();}
}

export function financeScopedPool(pool) {
 async function connect() {
  const scope=context.getStore();if(!scope)fail(403,'Select a finance space first.');
  const client=await pool.connect();
  const borrowed=hasActiveBusinessTransaction();
  async function applyScope() {
   await client.query(`SELECT set_config('wolf.finance_actor',$1,false),set_config('wolf.finance_company',$2,false),set_config('wolf.finance_space',$3,false)`,[scope.userId,scope.companyId,scope.spaceId]);
   await client.query(`SET ROLE ${role}`);
  }
  try {if(!borrowed)await applyScope();}catch(error){client.release(true);throw error;}
  let released=false, pending=Promise.resolve(), cleanup=null, inTransaction=false;
  const boundary=()=>checkFinanceTransactionActor(client);
  async function query(...args) {
   const command=String(typeof args[0]==='string'?args[0]:args[0]?.text||'').trim().replace(/;\s*$/,'').toUpperCase();
   if(/^(BEGIN|START\s+TRANSACTION)\b/.test(command)) {
    const result=await client.query(...args);inTransaction=true;
    try {await boundary();return result;}
    catch(error){await client.query('ROLLBACK');inTransaction=false;throw error;}
   }
   if(/^(COMMIT|END|ROLLBACK)(?:\s+(?:WORK|TRANSACTION))?$/.test(command)) {
    const result=await client.query(...args);inTransaction=false;return result;
   }
   if(inTransaction)return client.query(...args);
   // MCP already owns the atomic unit. Borrowed connections may run parallel
   // reads; interleaving new savepoints would roll back another lease's work.
   if(hasActiveBusinessTransaction()){await boundary();return client.query(...args);}
   // Match normal autocommit behavior while keeping the access check and the
   // statement in one atomic unit. MCP's pool maps these to its savepoints.
   await client.query('BEGIN');
   try {await boundary();const result=await client.query(...args);await client.query('COMMIT');return result;}
   catch(error){await client.query('ROLLBACK');throw error;}
  }
  async function runQuery(...args) {
   if(!borrowed)return query(...args);
   return serializeBusinessTransactionBlock(async()=>{
    // An aborted transaction must reach ROLLBACK before scope setup can run.
    const rollback=/^\s*ROLLBACK\b/i.test(typeof args[0]==='string'?args[0]:args[0]?.text||'');
    let primaryError;
    try {if(!rollback)await applyScope();return await query(...args);}
    catch(error){primaryError=error;throw error;}
    finally {try{await client.query('RESET ROLE');}catch(error){if(!primaryError)throw error;}}
   });
  }
  return {query:(...args)=>{if(released)throw new Error('finance_connection_released');const next=pending.then(()=>runQuery(...args));pending=next.catch(()=>{});return next;},
   release:()=>{if(cleanup)return cleanup;released=true;cleanup=(async()=>{try {await pending;await serializeBusinessTransactionBlock(async()=>{await client.query('ROLLBACK');await client.query(borrowed?'RESET ROLE; RESET wolf.finance_actor; RESET wolf.finance_company; RESET wolf.finance_space':'RESET ROLE; RESET ALL');client.release();});}catch(error){client.release(true);throw error;}})();
    // Register synchronously: canonical handlers may send their response before
    // their finally block awaits cleanup. Internal callers must not commit an
    // MCP receipt until the scoped role/GUCs have been restored. Ordinary HTTP
    // fire-and-forget release still cannot create an unhandled rejection.
    cleanup.catch(()=>{});return trackRequestCleanup(cleanup);}};
 }
 return {connect,query:async(...args)=>{const db=await connect();try{return await db.query(...args);}finally{await db.release();}}};
}

export async function personalFinanceSpace(pool,userId,companyId) {
 if(!uuid(userId)||!uuid(companyId))fail(403,'Company membership required.');
 const db=await pool.connect();
 try {
 await db.query('BEGIN');
 await lockFinanceSpaceActor(db,userId,companyId);
 await db.query(`INSERT INTO finance_spaces(company_id,owner_id,name,kind,default_key)
 SELECT company_id,id,'Business','business','business' FROM users WHERE id=$1 AND company_id=$2 AND deleted_at IS NULL
 ON CONFLICT(company_id,owner_id,default_key) WHERE default_key IS NOT NULL DO NOTHING`,[userId,companyId]);
 const personal=(await db.query(`INSERT INTO finance_spaces(company_id,owner_id,name,kind,is_default)
 SELECT company_id,id,'Personal','personal',true FROM users WHERE id=$1 AND company_id=$2 AND deleted_at IS NULL
 ON CONFLICT(company_id,owner_id) WHERE is_default DO UPDATE SET owner_id=EXCLUDED.owner_id RETURNING *`,[userId,companyId])).rows[0];
 await db.query('COMMIT');return personal;
 }catch(error){await db.query('ROLLBACK');throw error;}finally{db.release();}
}
export async function withFinanceSpace(pool,userId,companyId,spaceId,work) {
 const personal=await personalFinanceSpace(pool,userId,companyId);if(!personal)fail(403,'Company membership required.');
 const selected=spaceId||personal.id;if(selected!=='combined'&&!uuid(selected))fail(400,'Choose a finance space.');
 const allowed=(await pool.query(`SELECT s.* FROM finance_spaces s WHERE company_id=$1 AND (owner_id=$2 OR audience='company' OR
  (audience='selected' AND EXISTS(SELECT 1 FROM finance_space_members m WHERE m.space_id=s.id AND m.user_id=$2))) AND ($3='combined' OR s.id::text=$3)`,[companyId,userId,selected])).rows;
 if(!allowed.length)fail(404,'This finance space is unavailable.');
 return context.run({userId,companyId,spaceId:selected},()=>work(financeScopedPool(pool),allowed));
}

export function installFinanceSpaceRoutes({app,pool,authRequired,requireEmployer}) {
 installFinanceSpaceTransfers({app,pool,authRequired,requireEmployer});
 const wrap=fn=>async(req,res)=>{res.set('Cache-Control','private, no-store');try {res.json(await fn(req));}catch(error){res.status(error.status||500).json({error:'finance_space_error',message:error.status?error.message:'Finance space could not be loaded or saved.'});}};
 app.get('/api/finance/spaces',authRequired,requireEmployer,wrap(async req=>{
  const personal=await personalFinanceSpace(pool,req.userId,req.companyId);
  const spaces=(await pool.query(`SELECT s.*,ARRAY(SELECT user_id FROM finance_space_members WHERE space_id=s.id) AS member_ids FROM finance_spaces s
   WHERE company_id=$1 AND (owner_id=$2 OR audience='company' OR (audience='selected' AND EXISTS(SELECT 1 FROM finance_space_members m WHERE m.space_id=s.id AND m.user_id=$2))) ORDER BY is_default DESC,created_at,id`,[req.companyId,req.userId])).rows;
  return {spaces,default_space_id:personal.id,maximum_owned_spaces:10};
 }));
 app.get('/api/finance/spaces/people',authRequired,requireEmployer,wrap(async req=>({people:(await pool.query('SELECT id,display_name FROM users WHERE company_id=$1 AND deleted_at IS NULL ORDER BY display_name,id',[req.companyId])).rows})));
 app.put('/api/finance/spaces/:id',authRequired,requireEmployer,wrap(async req=>{
  await personalFinanceSpace(pool,req.userId,req.companyId);
  if(!uuid(req.params.id))fail(400,'Invalid space.');
  const b=req.body,name=String(b.name||'').trim(),kind=b.kind||'business',audience=b.audience||'private';
  if(!name||name.length>80||!['personal','business','portfolio'].includes(kind)||!['private','selected','company'].includes(audience))fail(400,'Choose a name, space type and sharing setting.');
  if(kind==='personal'&&audience!=='private')fail(400,'Personal stays private. Use a Business or Portfolio space for sharing.');
  if(!Array.isArray(b.member_ids)||b.member_ids.length>200||b.member_ids.some(id=>!uuid(id)))fail(400,'Choose valid company members.');
  const members=audience==='selected'?[...new Set(b.member_ids)].filter(id=>id!==req.userId):[];
  if(audience==='selected'&&!members.length)fail(400,'Choose at least one person to share with.');
  const db=await pool.connect();try {
   await db.query('BEGIN');await lockFinanceSpaceActor(db,req.userId,req.companyId,{exclusiveCompany:true});
   await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))",['finance-space:'+req.params.id]);await db.query('SELECT id FROM users WHERE id=$1 AND company_id=$2 FOR UPDATE',[req.userId,req.companyId]);
   const old=(await db.query('SELECT * FROM finance_spaces WHERE id=$1 FOR UPDATE',[req.params.id])).rows[0];
   if(old&&(old.owner_id!==req.userId||old.company_id!==req.companyId))fail(404,'This space is unavailable.');
   if(old&&b.expected_revision!==old.revision)fail(409,'Sharing changed. Refresh and try again.');
   if(old?.is_default&&(kind!=='personal'||audience!=='private'))fail(400,'Your default Personal space stays private.');
   if(!old&&(await db.query('SELECT 1 FROM finance_spaces WHERE owner_id=$1 AND company_id=$2',[req.userId,req.companyId])).rowCount>=10)fail(409,'You can own up to ten finance spaces.');
   if(members.length!==(await db.query('SELECT id FROM users WHERE company_id=$1 AND deleted_at IS NULL AND id=ANY($2::uuid[])',[req.companyId,members])).rowCount)fail(400,'Only current company members can be selected.');
   if(b.includes_company_activity&&kind!=='business')fail(400,'Company activity belongs in a Business space.');
   if(b.includes_company_activity&&(await db.query('SELECT 1 FROM finance_spaces WHERE company_id=$1 AND includes_company_activity AND id<>$2',[req.companyId,req.params.id])).rowCount)fail(409,'Company activity is already connected to another space.');
   if(b.includes_company_activity&&(await db.query('SELECT 1 FROM finance_operational_sources WHERE company_id=$1 AND finance_space_id IS NOT NULL AND finance_space_id<>$2 LIMIT 1',[req.companyId,req.params.id])).rowCount)fail(409,'Existing company accounting belongs to another space. Re-enable company activity there to preserve its history.');
   const saved=(await db.query(`INSERT INTO finance_spaces(id,company_id,owner_id,name,kind,audience,includes_company_activity) VALUES($1,$2,$3,$4,$5,$6,$7)
    ON CONFLICT(id) DO UPDATE SET name=$4,kind=$5,audience=$6,includes_company_activity=$7,revision=finance_spaces.revision+1,updated_at=now() RETURNING *`,[req.params.id,req.companyId,req.userId,name,kind,audience,b.includes_company_activity===true])).rows[0];
   if(saved.includes_company_activity)await db.query('UPDATE finance_operational_sources SET finance_space_id=$1 WHERE company_id=$2 AND finance_space_id IS NULL',[saved.id,req.companyId]);
   await db.query('DELETE FROM finance_space_members WHERE space_id=$1',[saved.id]);
   if(audience==='selected')for(const id of members)await db.query('INSERT INTO finance_space_members VALUES($1,$2)',[saved.id,id]);
   await db.query('INSERT INTO finance_space_audit(space_id,actor_id,before_state,after_state) VALUES($1,$2,$3,$4)',[saved.id,req.userId,JSON.stringify(old||null),JSON.stringify({...saved,member_ids:audience==='selected'?members:[]})]);
   await db.query('COMMIT');return saved;
  }catch(error){await db.query('ROLLBACK');throw error;}finally{db.release();}
 }));
 app.get('/api/finance/spaces/combined',authRequired,requireEmployer,wrap(req=>withFinanceSpace(pool,req.userId,req.companyId,'combined',async(db,spaces)=>{
  const accounts=(await db.query('SELECT id,name,finance_space_id,current_balance_cents,currency,account_type FROM finance_accounts WHERE company_id=$1 AND archived_at IS NULL ORDER BY name,id',[req.companyId])).rows;
  const totals=Object.entries(accounts.reduce((sum,a)=>{const currency=a.currency.toLowerCase();sum[currency]=(sum[currency]||0)+Number(a.current_balance_cents);return sum;},{})).map(([currency,balance_cents])=>({currency,balance_cents}));
  const planning=hasCapability(req,'finance.planning.view')?(await db.query(`SELECT finance_space_id,direction,count(*)::int AS count,sum(amount_cents)::text AS amount_cents FROM finance_planned_items WHERE company_id=$1 AND archived_at IS NULL AND paused_at IS NULL AND scheduled_date>=current_date GROUP BY finance_space_id,direction`,[req.companyId])).rows:[];
  const debts=hasCapability(req,'finance.debts.view')?(await db.query(`SELECT finance_space_id,count(*)::int AS count,sum(current_balance_cents)::text AS amount_cents FROM finance_debts WHERE company_id=$1 AND archived_at IS NULL AND status='active' GROUP BY finance_space_id`,[req.companyId])).rows:[];
  return {spaces,accounts,totals,planning,debts,total_balance_cents:totals.find(t=>t.currency==='usd')?.balance_cents||0};
 })));
 app.use('/api/finance',(req,res,next)=>{
  res.set('Cache-Control','private, no-store');
  if(req.path==='/plaid/webhook')return next();
  authRequired(req,res,()=>{
   if(req.get('X-Finance-Space')==='combined')return res.status(400).json({error:'finance_select_space',message:'Choose one space to view details or make changes.'});
   withFinanceSpace(pool,req.userId,req.companyId,req.get('X-Finance-Space'),async()=>next()).catch(error=>{
    if(!res.headersSent)res.status(error.status||500).json({error:'finance_space_unavailable',message:error.status?error.message:'Finance is unavailable.'});
   });
  });
 });
}
