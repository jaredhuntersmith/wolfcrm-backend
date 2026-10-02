import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { startLocalPostgres } from './helpers/local-postgres.js';
import { drawnSignature } from './helpers/signatures.js';
import { installAgreementSchema, createAgreementService } from '../quote-agreements.js';
import { removeQuote } from '../quote-removal.js';
import { installAutomationSystem, automationTestHooks, syncAutomationSchedulesForQuote } from '../automations.js';
import { installGoogleSheetsSchema, loadCompanyContactExportData } from '../google-sheets.js';
import { installScheduleBookingGuard, lockCompanySchedule } from '../schedule-booking-guard.js';

const latch = () => { let release; const promise = new Promise(resolve => { release = resolve; }); return { promise, release }; };

test('removed quotes stay out of automation work and active Sheets exports while evidence survives', {timeout:120000}, async t => {
  const pg = startLocalPostgres(); pg.configureEnvironment(); let pool;
  try {
    const backend = await import('../index.js'); pool = backend.pool; await backend.bootstrap();
    await installAgreementSchema(pool); await installGoogleSheetsSchema(pool); await installScheduleBookingGuard(pool);
    let race, scheduleRace;
    // Delay only identified SQL boundaries; real PostgreSQL transactions and
    // locks determine which operation can observe the active quote.
    const observedPool = {
      query: (...args) => pool.query(...args),
      async connect() {
        const db = await pool.connect();
        return {
          async query(sql, args) {
            if (scheduleRace && args?.[0] === scheduleRace.scope && sql.startsWith('SELECT pg_advisory_xact_lock')) scheduleRace.waiting.release();
            if (race && args?.[0] === race.quoteID && sql.startsWith('SELECT updated_at FROM quotes')) race.conversionWaiting.release();
            const result = await db.query(sql, args);
            if (race && args?.[0] === race.quoteID && sql.startsWith('SELECT * FROM quotes WHERE id=$1 AND (') && /FOR (NO KEY )?UPDATE$/.test(sql)) {
              race.deletionLocked.release(); await race.continueDeletion.promise;
            }
            return result;
          },
          release: () => db.release(),
        };
      },
    };
    const app = {get(){},post(){},put(){},patch(){},delete(){}};
    await installAutomationSystem({app,pool:observedPool,authRequired:()=>{},requireEmployer:()=>{},disableProcessors:true});
    const company = randomUUID(), other = randomUUID(), user = randomUUID(), otherUser = randomUUID(), contact = randomUUID();
    await pool.query("INSERT INTO companies(id,name,join_code) VALUES($1,'Removal business','REMOVE_A'),($2,'Other business','REMOVE_B')",[company,other]);
    await pool.query("INSERT INTO users(id,email,role,company_id) VALUES($1,'owner@removal.invalid','employer',$3),($2,'other@removal.invalid','employer',$4)",[user,otherUser,company,other]);
    await pool.query('UPDATE companies SET owner_user_id=$2 WHERE id=$1',[company,user]);
    await pool.query("INSERT INTO contacts(id,user_id,company_id,name,address) VALUES($1,$2,$3,'Customer','Main Street')",[contact,user,company]);
    await pool.query("INSERT INTO google_sheets_connections(company_id,status,sync_mode) VALUES($1,'connected','after_every_change')",[company]);
    const automationID=randomUUID(),versionID=randomUUID();
    await pool.query("INSERT INTO automation_definitions(id,company_id,name) VALUES($1,$2,'Removal test')",[automationID,company]);
    await pool.query('INSERT INTO automation_versions(id,automation_id,company_id,version_number) VALUES($1,$2,$3,1)',[versionID,automationID,company]);
    const makeRun = async quote => (await pool.query("INSERT INTO automation_runs(company_id,automation_id,automation_version_id,subject_type,subject_id,manual_started_by_user_id) VALUES($1,$2,$3,'quote',$4,$5) RETURNING *",[company,automationID,versionID,quote.id,user])).rows[0];
    const makeQuote = async title => (await pool.query("INSERT INTO quotes(user_id,company_id,contact_id,title,line_items,total_cents,quote_options,expires_at) VALUES($1,$2,$3,$4,$5::jsonb,12000,$6::jsonb,now()+interval '14 days') RETURNING *",[user,company,contact,title,JSON.stringify([{id:randomUUID(),name:'Windows',qty:1,price_cents:12000}]),JSON.stringify({duration_minutes:120})])).rows[0];
    const service=createAgreementService({pool,getQuoteSettings:backend.getQuoteSettings,env:{NODE_ENV:'test',QUOTE_PUBLIC_BASE_URL:'http://localhost:3000',QUOTE_LINK_SECRET:'test-removal-key-at-least-thirty-two-characters'}});
    const request={companyId:company,userId:user};
    const publish=async quote=>{
      const body={request_id:randomUUID()};
      const preview=await service.publish(request,quote.id,body,{preview:true});
      return service.publish(request,quote.id,{...body,expected_preview_hash:preview.preview_hash});
    };
    const actions=automationTestHooks.actionExecutors();
    const unsigned=await makeQuote('Removed unsigned'), signed=await makeQuote('Removed signed'), active=await makeQuote('Still active');
    const unsignedPacket=await publish(unsigned), signedPacket=await publish(signed);
    const signedToken=signedPacket.customer_url.split('/').at(-1), session=await service.publicSession(signedToken,{});
    await service.sign(signedToken,{session_token:session.session_token,request_id:randomUUID(),packet_hash:signedPacket.packet_hash,printed_name:'Customer',signature:drawnSignature(),consent:true,values:{}});
    const unsignedRun=await makeRun(unsigned), signedRun=await makeRun(signed), node={id:randomUUID()};

    await t.test('automation removal uses shared retention and is repeatable without deleting records',async()=>{
      await syncAutomationSchedulesForQuote(company,unsigned);
      const result=await actions['quote.delete'](unsignedRun,node,{confirm_delete:true});
      assert.equal(result.deleted,true);
      await actions['quote.delete'](unsignedRun,node,{confirm_delete:true});
      const row=(await pool.query('SELECT deleted_at FROM quotes WHERE id=$1',[unsigned.id])).rows[0];
      assert.ok(row.deleted_at);
      assert.ok((await pool.query('SELECT revoked_at FROM quote_agreements WHERE id=$1',[unsignedPacket.id])).rows[0].revoked_at);
      assert.equal((await pool.query("SELECT count(*)::int n FROM agreement_events WHERE agreement_id=$1 AND type='quote_removed'",[unsignedPacket.id])).rows[0].n,1);
      assert.ok((await pool.query('SELECT 1 FROM agreement_artifacts WHERE agreement_id=$1',[unsignedPacket.id])).rowCount);
      assert.equal((await pool.query('SELECT dirty_reason FROM google_sheets_dirty_contacts WHERE company_id=$1 AND contact_id=$2',[company,contact])).rows[0].dirty_reason,'quote.deleted');
    });
    await t.test('signed evidence and manually shared service access survive automation removal',async()=>{
      const before=(await pool.query('SELECT snapshot,packet_hash FROM quote_agreements WHERE id=$1',[signedPacket.id])).rows[0];
      await actions['quote.delete'](signedRun,{id:randomUUID()},{confirm_delete:true});
      assert.deepEqual((await pool.query('SELECT snapshot,packet_hash FROM quote_agreements WHERE id=$1',[signedPacket.id])).rows[0],before);
      assert.equal((await pool.query('SELECT count(*)::int n FROM agreement_signatures WHERE agreement_id=$1',[signedPacket.id])).rows[0].n,1);
      assert.equal((await service.loadPublic(pool,signedToken)).row.id,signedPacket.id);
    });
    await t.test('removed context, searches, relation flags and exports exclude quotes without deleting job history',async()=>{
      assert.deepEqual(await automationTestHooks.loadQuoteContext(company,unsigned.id),{exists:false});
      const results=await actions['quotes.search'](unsignedRun,node,{});
      assert.deepEqual(results.quotes.map(row=>row.id),[active.id]);
      assert.equal(results.quotes[0].subtotal_cents,12000);
      assert.equal((await automationTestHooks.loadContactRelationshipFlags(company,contact)).has_quote,true);
      await pool.query("INSERT INTO schedule_events(id,user_id,company_id,title,start_at,end_at,contact_id,quote_id,finished_at) VALUES($1,$2,$3,'Retained completed work',now()-interval '2 days',now()-interval '1 day',$4,$5,now()-interval '1 day')",[randomUUID(),user,company,contact,signed.id]);
      const exported=await loadCompanyContactExportData(pool,company);
      assert.match(exported[0].history.Quotes,/Still active/);
      assert.doesNotMatch(exported[0].history.Quotes,/Removed unsigned|Removed signed/);
      assert.match(exported[0].history['Completed Jobs'],/Retained completed work/);
    });
    await t.test('removed quotes reject every existing mutation and conversion entrypoint',async()=>{
      for(const [key,config] of [
        ['quote.update',{title:'Resurrect'}],['quote.set_status',{status:'accepted'}],
        ['quote.add_line_item',{description:'Extra',price_cents:100}],['quote.remove_line_item',{}],
        ['quote.replace_line_items',{line_items:[]}],['quote.set_expiration',{expires_at:'2028-01-01'}],
        ['quote.convert_to_job',{}],['quote.create_followup_task',{}],['quote.create_invoice',{}],
      ]) await assert.rejects(actions[key](unsignedRun,{id:randomUUID()},config),/quote_not_found/,key);
      await assert.rejects(actions['quote.delete']({...unsignedRun,company_id:other,manual_started_by_user_id:otherUser},node,{quote_id:active.id,confirm_delete:true}),/quote_not_found/);
      assert.equal((await pool.query('SELECT deleted_at FROM quotes WHERE id=$1',[active.id])).rows[0].deleted_at,null);
    });
    await t.test('a delayed reminder refresh cannot recreate work after removal',async()=>{
      await syncAutomationSchedulesForQuote(company,unsigned);
      assert.equal((await pool.query("SELECT count(*)::int n FROM automation_scheduled_events WHERE subject_id=$1 AND status='scheduled'",[unsigned.id])).rows[0].n,0);
      assert.equal(await automationTestHooks.shouldFireScheduledAutomationEvent({company_id:company,subject_type:'quote',subject_id:unsigned.id,event_type:'quote.followup_due'}),false);
    });
    await t.test('live conversion commits the job and quote link together and retries reuse that job',async()=>{
      const quote=await makeQuote('Convert safely'), run=await makeRun(quote), step={id:randomUUID()};
      const result=await actions['quote.convert_to_job'](run,step,{start_at:'2028-01-01T10:00:00Z',end_at:'2028-01-01T12:00:00Z'});
      const changed=(await pool.query('SELECT status,converted_job_id FROM quotes WHERE id=$1',[quote.id])).rows[0];
      assert.equal(changed.status,'converted');assert.equal(changed.converted_job_id,result.job_id);
      const replay=await actions['quote.convert_to_job'](run,step,{});assert.equal(replay.job_id,result.job_id);
      assert.equal((await pool.query("SELECT count(*)::int n FROM schedule_events WHERE title='Convert safely'")).rows[0].n,1);
    });
    await t.test('deletion winning the PostgreSQL row lock stops already-read conversion from creating a job',async()=>{
      const quote=await makeQuote('Delete before conversion'), run=await makeRun(quote);
      race={quoteID:quote.id,deletionLocked:latch(),conversionWaiting:latch(),continueDeletion:latch()};
      const deletion=removeQuote(observedPool,request,quote.id);
      await race.deletionLocked.promise;
      const conversion=actions['quote.convert_to_job'](run,{id:randomUUID()},{}).then(value=>({value}),error=>({error}));
      await race.conversionWaiting.promise;
      race.continueDeletion.release();
      await deletion;
      const outcome=await conversion;assert.match(outcome.error?.message||'',/quote_not_found/);
      assert.equal((await pool.query("SELECT count(*)::int n FROM schedule_events WHERE title='Delete before conversion'")).rows[0].n,0);
      race=null;
    });
    await t.test('conversion follows staff scheduling lock order without holding the quote while waiting for the calendar',async()=>{
      const quote=await makeQuote('Consistent lock order'), run=await makeRun(quote), staff=await pool.connect();
      scheduleRace={scope:`schedule:${company}`,waiting:latch()};
      try {
        await staff.query('BEGIN'); await lockCompanySchedule(staff,company);
        const conversion=actions['quote.convert_to_job'](run,{id:randomUUID()},{}).then(value=>({value}),error=>({error}));
        await scheduleRace.waiting.promise;
        await staff.query("SET LOCAL lock_timeout='2s'");
        assert.equal((await staff.query('SELECT id FROM quotes WHERE id=$1 FOR UPDATE',[quote.id])).rowCount,1);
        await staff.query('COMMIT');
        const outcome=await conversion;assert.equal(outcome.error,undefined);assert.ok(outcome.value.job_id);
        const job=(await pool.query('SELECT start_at,end_at FROM schedule_events WHERE id=$1',[outcome.value.job_id])).rows[0];
        assert.equal(new Date(job.end_at)-new Date(job.start_at),3_600_000);
      } finally { await staff.query('ROLLBACK'); staff.release(); scheduleRace=null; }
    });
  } finally { if(pool)await pool.end();pg.stop(); }
});
