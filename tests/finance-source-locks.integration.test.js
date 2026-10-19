import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {installPayStructureSchema} from '../pay-structures.js';
import {installFinanceSystem} from '../finance.js';
import {personalFinanceSpace} from '../finance-spaces.js';
import {installFinanceSourceLocks, lockFinanceSourceRows} from '../finance-source-locks.js';

test('lock-only finance bridge preserves real source exclusion and current company/space visibility', {timeout:60000}, async () => {
  const local=startLocalPostgres(); local.configureEnvironment();
  let backend, reader, writer;
  try {
    backend=await import('../index.js'); await backend.bootstrap();
    const {app,pool,authRequired}=backend;
    await installPayStructureSchema(pool);
    const company=randomUUID(), actor=randomUUID(), foreignCompany=randomUUID(), foreign=randomUUID();
    for(const [c,u] of [[company,actor],[foreignCompany,foreign]]) {
      await pool.query('INSERT INTO companies(id,name,join_code,owner_user_id) VALUES($1,$2,$4,$3)',[c,'Lock fixture',u,c]);
      await pool.query("INSERT INTO users(id,company_id,email,role) VALUES($1,$2,$3,'employer')",[u,c,u+'@example.invalid']);
    }
    await installFinanceSystem({app,pool,authRequired,requireEmployer:(_req,_res,next)=>next(),getStripe:()=>null});
    await installFinanceSourceLocks(pool); await installFinanceSourceLocks(pool);
    const personal=(await personalFinanceSpace(pool,actor,company)).id;
    const business=(await pool.query("INSERT INTO finance_spaces(company_id,owner_id,name,kind,audience,includes_company_activity) VALUES($1,$2,'Business lock fixture','business','private',true) RETURNING id",[company,actor])).rows[0].id;
    const entry=randomUUID(), otherEntry=randomUUID();
    for(const [id,c,u] of [[entry,company,actor],[otherEntry,foreignCompany,foreign]]) await pool.query("INSERT INTO time_clock_entries(id,company_id,user_id,start_at,end_at) VALUES($1,$2,$3,'2026-10-01T10:00:00Z','2026-10-01T11:00:00Z')",[id,c,u]);
    const mileage=randomUUID(), foreignMileage=randomUUID(), pay=randomUUID();
    await pool.query("INSERT INTO mileage_daily_logs(id,company_id,employee_id,service_date) VALUES($1,$2,$3,'2026-10-01')",[mileage,company,actor]);
    await pool.query("INSERT INTO mileage_legs(id,log_id,sequence,from_label,to_label,distance_miles) VALUES($1,$2,1,'Synthetic A','Synthetic B',10)",[randomUUID(),mileage]);
    await pool.query("INSERT INTO mileage_daily_logs(id,company_id,employee_id,service_date) VALUES($1,$2,$3,'2026-10-01')",[foreignMileage,foreignCompany,foreign]);
    await pool.query("INSERT INTO mileage_legs(id,log_id,sequence,from_label,to_label,distance_miles) VALUES($1,$2,1,'Foreign A','Foreign B',10)",[randomUUID(),foreignMileage]);
    await pool.query("INSERT INTO employee_pay_structures(id,company_id,employee_id,effective_from,hourly_rate_cents) VALUES($1,$2,$3,'2026-10-01',2500)",[pay,company,actor]);
    reader=await pool.connect(); writer=await pool.connect();
    async function begin(space=business) {
      await reader.query('BEGIN');
      await reader.query("SELECT set_config('wolf.finance_actor',$1,true),set_config('wolf.finance_company',$2,true),set_config('wolf.finance_space',$3,true)",[actor,company,space]);
      await reader.query('SET LOCAL ROLE wolf_finance_request');
    }
    await begin();
    assert.equal((await reader.query('SELECT id FROM mileage_daily_logs WHERE id=$1',[mileage])).rowCount,1,'Business scope sees its company log');
    assert.equal((await reader.query('SELECT id FROM mileage_legs WHERE log_id=$1',[mileage])).rowCount,1,'Business scope sees legs through the authorized parent log');
    assert.equal((await reader.query('SELECT id FROM mileage_legs')).rowCount,1,'Foreign parent legs remain invisible');
    for(const table of ['time_clock_entries','mileage_daily_logs','employee_pay_structures','users']) assert.equal((await reader.query('SELECT has_table_privilege(current_user,$1,\'UPDATE\') AS allowed',[table])).rows[0].allowed,false);
    await lockFinanceSourceRows(reader,'time_clock_entries',company,[entry]);
    assert.equal((await reader.query('SELECT id FROM time_clock_entries WHERE id=$1',[entry])).rowCount,1);
    const pid=(await writer.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
    let wrote=false;
    const update=writer.query("UPDATE time_clock_entries SET note='canonical writer after finance commit' WHERE id=$1",[entry]).then(()=>{wrote=true;});
    const deadline=Date.now()+5000;
    while(!(await pool.query('SELECT 1 FROM pg_locks WHERE pid=$1 AND NOT granted',[pid])).rowCount) { assert.ok(Date.now()<deadline,'canonical update must wait for finance source lock'); await delay(10); }
    assert.equal(wrote,false); await reader.query('COMMIT'); await update; assert.equal(wrote,true);
    for(const [kind,id,sql] of [
      ['mileage_daily_logs',mileage,"UPDATE mileage_daily_logs SET owner_notes='reviewed after finance commit' WHERE id=$1"],
      ['employee_pay_structures',pay,'UPDATE employee_pay_structures SET hourly_rate_cents=2600 WHERE id=$1'],
      ['users',actor,"UPDATE users SET display_name='Still a current employee' WHERE id=$1"]
    ]) {
      await begin(); await lockFinanceSourceRows(reader,kind,company,[id]);
      let finished=false;
      const change=writer.query(sql,[id]).then(()=>{finished=true;});
      const limit=Date.now()+5000;
      while(!(await pool.query('SELECT 1 FROM pg_locks WHERE pid=$1 AND NOT granted',[pid])).rowCount) { assert.ok(Date.now()<limit,kind+' writer must wait'); await delay(10); }
      assert.equal(finished,false); await reader.query('COMMIT'); await change; assert.equal(finished,true);
    }
    // Private finance lacks company-activity access and cannot lock operational evidence.
    await begin(personal); await lockFinanceSourceRows(reader,'time_clock_entries',company,[entry]);
    assert.equal((await reader.query('SELECT id FROM time_clock_entries WHERE id=$1',[entry])).rowCount,0);
    assert.equal((await reader.query('SELECT id FROM mileage_legs WHERE log_id=$1',[mileage])).rowCount,0,'Personal cannot read Business mileage legs');
    await writer.query("SET lock_timeout='500ms'");
    await writer.query("UPDATE time_clock_entries SET note='not locked from private space' WHERE id=$1",[entry]);
    await reader.query('ROLLBACK');
    await begin(); await lockFinanceSourceRows(reader,'time_clock_entries',company,[otherEntry]);
    await writer.query("UPDATE time_clock_entries SET note='foreign row not locked' WHERE id=$1",[otherEntry]);
    assert.equal((await reader.query('SELECT id FROM time_clock_entries WHERE id=$1',[otherEntry])).rowCount,0);
    await reader.query('ROLLBACK');
    for(const [kind,c,code] of [['time_clock_entries',foreignCompany,'42501'],['companies',company,'22023']]) {
      await begin(); await assert.rejects(lockFinanceSourceRows(reader,kind,c,[entry]),e=>e.code===code); await reader.query('ROLLBACK');
    }
    await pool.query('UPDATE users SET deleted_at=now() WHERE id=$1',[actor]);
    await begin(); await assert.rejects(lockFinanceSourceRows(reader,'time_clock_entries',company,[entry]),e=>e.code==='42501'); await reader.query('ROLLBACK');
    const definition=(await pool.query("SELECT prosecdef,proconfig FROM pg_proc WHERE oid='public.wolf_finance_lock_source(text,uuid,text[])'::regprocedure")).rows[0];
    assert.equal(definition.prosecdef,true); assert.ok(definition.proconfig.includes('search_path=pg_catalog'));
    assert.equal((await pool.query("SELECT EXISTS(SELECT 1 FROM pg_proc p, LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE p.oid='public.wolf_finance_lock_source(text,uuid,text[])'::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE') AS allowed")).rows[0].allowed,false);
  } finally {
    for(const client of [reader,writer]) if(client) { await client.query('ROLLBACK').catch(()=>{}); client.release(); }
    await backend?.pool.end(); local.stop();
  }
});
