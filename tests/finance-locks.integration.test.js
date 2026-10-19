import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import pg from 'pg';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {lockFinanceCompany} from '../finance-locks.js';

test('restricted finance writers serialize per company until commit or rollback without company UPDATE privileges', {timeout:30000}, async () => {
  const local = startLocalPostgres();
  const pool = new pg.Pool(local.config);
  const company = randomUUID(), other = randomUUID();
  let first, second, observer;
  try {
    await pool.query('CREATE TABLE companies(id uuid PRIMARY KEY); CREATE ROLE wolf_finance_request NOLOGIN; GRANT SELECT ON companies TO wolf_finance_request');
    await pool.query('INSERT INTO companies VALUES($1),($2)', [company, other]);
    first = await pool.connect(); second = await pool.connect(); observer = await pool.connect();
    await first.query('BEGIN; SET LOCAL ROLE wolf_finance_request');
    assert.equal((await first.query("SELECT has_table_privilege(current_user,'companies','UPDATE') AS allowed")).rows[0].allowed, false);
    await first.query('SAVEPOINT permission_probe');
    await assert.rejects(first.query('SELECT id FROM companies WHERE id=$1 FOR UPDATE', [company]), error => error.code === '42501');
    await first.query('ROLLBACK TO SAVEPOINT permission_probe');
    // Existing statement-close writers use this key directly. The repaired
    // classification/posting writers must participate in that same mutex.
    await first.query('SELECT pg_advisory_xact_lock(hashtext($1::text))', [`${company}|accounting`]);
    await second.query('BEGIN; SET LOCAL ROLE wolf_finance_request');
    // An unrelated company remains available, even with the first lock held.
    await lockFinanceCompany(second, other);
    const pid = (await second.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
    let acquired = false;
    const waiting = lockFinanceCompany(second, company).then(() => { acquired = true; });
    const deadline = Date.now() + 5000;
    while (!(await observer.query("SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted", [pid])).rowCount) {
      assert.ok(Date.now() < deadline, 'second writer must wait for the same company lock');
      await delay(10);
    }
    assert.equal(acquired, false);
    await first.query('COMMIT'); await waiting;
    assert.equal(acquired, true);
    await second.query('ROLLBACK');
    await first.query('BEGIN; SET LOCAL ROLE wolf_finance_request');
    await first.query("SET LOCAL lock_timeout='1s'");
    await lockFinanceCompany(first, company);
    await lockFinanceCompany(first, other);
    assert.equal((await first.query("SELECT has_table_privilege(current_user,'companies','UPDATE') AS allowed")).rows[0].allowed, false);
    await first.query('ROLLBACK');
  } finally {
    for (const client of [first, second, observer]) { if (client) { await client.query('ROLLBACK').catch(() => {}); client.release(); } }
    await pool.end(); local.stop();
  }
});
