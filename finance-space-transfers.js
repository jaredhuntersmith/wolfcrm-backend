import {createHash} from 'node:crypto';
const roots={accounts:'finance_accounts','planned-items':'finance_planned_items',recurring:'finance_recurring_candidates',debts:'finance_debts',budgets:'finance_budgets',goals:'finance_goals',receipts:'finance_receipts'};
const quote=s=>'"'+s.replaceAll('"','""')+'"';
const fail=(status,message)=>{throw Object.assign(new Error(message),{status});};

// Transfer a connected evidence bundle, never severing bank, receipt or ledger links.
export function installFinanceSpaceTransfers({app,pool,authRequired,requireEmployer}) {
 const wrap=fn=>async(req,res)=>{res.set('Cache-Control','private, no-store');try{res.json(await fn(req));}catch(e){res.status(e.status||500).json({error:'finance_transfer_failed',message:e.status?e.message:'These records could not be moved. No records were changed.'});}};
 app.get('/api/finance/spaces/transfer-records',authRequired,requireEmployer,wrap(async req=>{
  const space=(await pool.query('SELECT id FROM finance_spaces WHERE id::text=$1 AND owner_id=$2 AND company_id=$3',[req.query.space_id,req.userId,req.companyId])).rows[0];if(!space)fail(404,'Choose one of your own spaces.');
  const records=[];
  for(const [kind,table] of Object.entries(roots)) {
   if(!(await pool.query('SELECT to_regclass($1) AS table',[table])).rows[0].table)continue;
   const rows=(await pool.query(`SELECT id::text,coalesce(to_jsonb(t)->>'name',to_jsonb(t)->>'title',to_jsonb(t)->>'merchant_name',to_jsonb(t)->>'merchant','Untitled') AS name FROM ${quote(table)} t WHERE finance_space_id=$1 ORDER BY id LIMIT 500`,[space.id])).rows;
   records.push(...rows.map(r=>({...r,kind})));
  }
  return {records};
 }));
 for(const execute of [false,true])app.post('/api/finance/spaces/transfer'+(execute?'':'-preview'),authRequired,requireEmployer,wrap(async req=>{
  const b=req.body,table=roots[b.kind];if(!table||!b.record_id||!b.source_space_id||!b.destination_space_id||b.source_space_id===b.destination_space_id)fail(400,'Choose a record and a different destination space.');
  const db=await pool.connect();try {
   await db.query('BEGIN');await db.query("SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='30s'");
   const spaces=(await db.query('SELECT * FROM finance_spaces WHERE id::text=ANY($1::text[]) AND owner_id=$2 AND company_id=$3 ORDER BY id FOR UPDATE',[[b.source_space_id,b.destination_space_id],req.userId,req.companyId])).rows;
   if(spaces.length!==2)fail(404,'Both spaces must belong to you.');
   const source=spaces.find(s=>s.id===b.source_space_id),destination=spaces.find(s=>s.id===b.destination_space_id);if(!source||!destination)fail(404,'Space unavailable.');
   const tables=(await db.query("SELECT table_name FROM information_schema.columns WHERE table_schema='public' AND column_name='finance_space_id' ORDER BY table_name")).rows.map(r=>r.table_name);
   if(execute)await db.query(`LOCK TABLE ${tables.map(quote).join(',')} IN SHARE ROW EXCLUSIVE MODE`);
   if(!(await db.query(`SELECT 1 FROM ${quote(table)} WHERE id::text=$1 AND finance_space_id=$2`,[b.record_id,source.id])).rowCount)fail(404,'Record unavailable.');
   const links=(await db.query(`SELECT child.relname AS child,parent.relname AS parent,ca.attname AS key,pa.attname AS parent_key FROM pg_constraint c
    JOIN pg_class child ON child.oid=c.conrelid JOIN pg_class parent ON parent.oid=c.confrelid
    JOIN LATERAL unnest(c.conkey,c.confkey) k(a,b) ON true JOIN pg_attribute ca ON ca.attrelid=child.oid AND ca.attnum=k.a JOIN pg_attribute pa ON pa.attrelid=parent.oid AND pa.attnum=k.b
    WHERE c.contype='f' AND child.relnamespace='public'::regnamespace AND parent.relnamespace='public'::regnamespace
    AND child.relname=ANY($1::text[]) AND parent.relname=ANY($1::text[]) AND ca.attname NOT IN ('company_id','finance_space_id')`,[tables])).rows;
   await db.query('CREATE TEMP TABLE finance_move_rows(table_name text,row_id text,PRIMARY KEY(table_name,row_id)) ON COMMIT DROP');
   await db.query('INSERT INTO finance_move_rows VALUES($1,$2)',[table,b.record_id]);
   let stable=false;
   for(let pass=0;pass<30;pass++) {
    let changed=0;
    for(const l of links)for(const backwards of [false,true]) {
     const to=backwards?l.parent:l.child,from=backwards?l.child:l.parent,toAlias=backwards?'p':'c',fromAlias=backwards?'c':'p';
     changed+=(await db.query(`INSERT INTO finance_move_rows SELECT $1,${toAlias}.id::text FROM ${quote(l.child)} c JOIN ${quote(l.parent)} p ON c.${quote(l.key)}=p.${quote(l.parent_key)} JOIN finance_move_rows m ON m.table_name=$2 AND m.row_id=${fromAlias}.id::text WHERE ${toAlias}.finance_space_id=$3 ON CONFLICT DO NOTHING`,[to,from,source.id])).rowCount;
    }
    if(!changed){stable=true;break;}
   }
   if(!stable)fail(409,'This evidence bundle is too complex to move automatically.');
   const counts=(await db.query('SELECT table_name,count(*)::int AS count FROM finance_move_rows GROUP BY table_name ORDER BY table_name')).rows;
   if(counts.some(c=>c.table_name.startsWith('finance_operational_')||c.table_name.startsWith('finance_payroll_')||c.table_name.startsWith('finance_stripe_')))fail(409,'This bundle includes company accounting evidence. Keep it in its company activity space.');
   const fingerprint=createHash('sha256');fingerprint.update(JSON.stringify(spaces));
   for(const c of counts) {
    const rows=(await db.query(`SELECT to_jsonb(t) AS record FROM ${quote(c.table_name)} t JOIN finance_move_rows m ON m.table_name=$1 AND m.row_id=t.id::text ORDER BY t.id`,[c.table_name])).rows;
    fingerprint.update(JSON.stringify(rows));
   }
   const token=fingerprint.digest('hex');
   const accounts=(await db.query("SELECT a.name FROM finance_accounts a JOIN finance_move_rows m ON m.table_name='finance_accounts' AND m.row_id=a.id::text ORDER BY name")).rows.map(r=>r.name);
   const result={source_name:source.name,destination_name:destination.name,destination_audience:destination.audience,accounts,counts:counts.map(c=>({kind:c.table_name.replace('finance_','').replaceAll('_',' '),count:c.count})),total_records:counts.reduce((n,c)=>n+c.count,0),confirmation_token:token};
   if(execute) {
    if(b.confirmation_token!==token)fail(409,'The records or sharing changed. Review a fresh preview before moving.');
    await db.query("SELECT set_config('wolf.finance_move','on',true)");
    // Existing chart codes in the destination must be resolved explicitly, never merged silently.
    if(counts.some(c=>c.table_name==='finance_chart_accounts')&&(await db.query(`SELECT 1 FROM finance_chart_accounts a JOIN finance_move_rows m ON m.table_name='finance_chart_accounts' AND m.row_id=a.id::text JOIN finance_chart_accounts d ON d.finance_space_id=$1 AND (d.code=a.code OR d.system_key=a.system_key) LIMIT 1`,[destination.id])).rowCount)fail(409,'The destination already has a chart of accounts. Move this linked ledger into an empty space to preserve its accounting history.');
    for(const c of counts)await db.query(`UPDATE ${quote(c.table_name)} t SET finance_space_id=$1 FROM finance_move_rows m WHERE m.table_name=$2 AND m.row_id=t.id::text`,[destination.id,c.table_name]);
    // Verify every moved relationship still resides wholly inside one space.
    for(const l of links)if((await db.query(`SELECT 1 FROM ${quote(l.child)} c JOIN ${quote(l.parent)} p ON c.${quote(l.key)}=p.${quote(l.parent_key)} JOIN finance_move_rows m ON (m.table_name=$1 AND m.row_id=c.id::text OR m.table_name=$2 AND m.row_id=p.id::text) WHERE c.finance_space_id IS DISTINCT FROM p.finance_space_id LIMIT 1`,[l.child,l.parent])).rowCount)fail(409,'Some related evidence has no confirmed owner. Resolve its ownership before moving this bundle.');
    await db.query('INSERT INTO finance_space_audit(space_id,actor_id,before_state,after_state) VALUES($1,$2,$3,$4)',[source.id,req.userId,JSON.stringify({action:'transfer',destination_space_id:destination.id,...result}),JSON.stringify({moved:true})]);
   }
   await db.query('COMMIT');return {...result,moved:execute};
  }catch(e){await db.query('ROLLBACK');throw e;}finally{db.release();}
 }));
}
