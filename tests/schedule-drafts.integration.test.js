import assert from 'node:assert/strict';
import test from 'node:test';
import {randomUUID} from 'node:crypto';
import {startLocalPostgres} from './helpers/local-postgres.js';

test('schedule drafts expire, remain private, and clear only after a saved job', {timeout:60000}, async () => {
  const postgres=startLocalPostgres();postgres.configureEnvironment();
  let pool,server;
  try {
    const backend=await import('../index.js');pool=backend.pool;await backend.bootstrap();
    const {installGoogleSheetsSchema}=await import('../google-sheets.js');await installGoogleSheetsSchema(pool);
    const companyA=randomUUID(),companyB=randomUUID(),ownerA=randomUUID(),ownerB=randomUUID();
    const contactA=randomUUID(),contactB=randomUUID(),quoteA=randomUUID();
    await pool.query("INSERT INTO companies(id,name,join_code) VALUES($1,'A','DRAFT-A'),($2,'B','DRAFT-B')",[companyA,companyB]);
    await pool.query("INSERT INTO users(id,email,role,company_id) VALUES($1,'draft-a@example.invalid','employer',$3),($2,'draft-b@example.invalid','employer',$4)",[ownerA,ownerB,companyA,companyB]);
    await pool.query('UPDATE companies SET owner_user_id=CASE WHEN id=$1 THEN $3::uuid ELSE $4::uuid END WHERE id IN ($1,$2)',[companyA,companyB,ownerA,ownerB]);
    await pool.query("INSERT INTO sessions(token,user_id) VALUES('draft-owner-a',$1),('draft-owner-b',$2)",[ownerA,ownerB]);
    await pool.query("INSERT INTO contacts(id,user_id,company_id,name) VALUES($1,$3,$5,'A contact'),($2,$4,$6,'B contact')",[contactA,contactB,ownerA,ownerB,companyA,companyB]);
    await pool.query("INSERT INTO quotes(id,user_id,company_id,contact_id,line_items,total_cents,quote_options) VALUES($1,$2,$3,$4,$5::jsonb,10000,$6::jsonb)",[quoteA,ownerA,companyA,contactA,JSON.stringify([{name:'Work',qty:1,price_cents:10000}]),JSON.stringify({duration_minutes:90})]);
    server=await new Promise(resolve=>{const listener=backend.app.listen(0,'127.0.0.1',()=>resolve(listener));});
    const base=`http://127.0.0.1:${server.address().port}`;
    async function request(path,{token='draft-owner-a',method='GET',body}={}) {
      const response=await fetch(base+path,{method,headers:{authorization:`Bearer ${token}`,'content-type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
      const raw=await response.text();return{status:response.status,body:raw?JSON.parse(raw):null};
    }
    const draftID=randomUUID(),otherDraftID=randomUUID();
    const payload={title:'Visit',duration_minutes:90,sales_user_ids:[ownerA],worker_user_ids:[ownerA]};
    const initial=await request(`/api/schedule/drafts?contact_id=${contactA}`);
    assert.equal(initial.status,200);assert.equal(initial.body.contact_generation,0);
    const saved=await request(`/api/schedule/drafts/${draftID}`,{method:'PUT',body:{contact_id:contactA,quote_id:quoteA,payload,client_revision:1,contact_generation:0}});
    assert.equal(saved.status,200,JSON.stringify(saved.body));assert.ok(saved.body.expires_at);
    assert.equal(saved.body.contact_generation,0);assert.equal(saved.body.client_revision,1);
    const listed=await request(`/api/schedule/drafts?contact_id=${contactA}`);
    assert.equal(listed.body.drafts[0].contact_generation,0);assert.equal(listed.body.drafts[0].client_revision,1);
    assert.equal((await request('/api/schedule/drafts',{token:'draft-owner-b'})).body.drafts.length,0);
    const foreignDraftID=randomUUID();
    assert.equal((await request(`/api/schedule/drafts/${foreignDraftID}`,{token:'draft-owner-b',method:'PUT',body:{contact_id:contactB,payload,client_revision:1,contact_generation:0}})).status,200);
    assert.equal((await request(`/api/schedule/drafts/${draftID}`,{token:'draft-owner-b',method:'PUT',body:{contact_id:contactB,payload,client_revision:2,contact_generation:0}})).status,409);
    assert.equal((await request(`/api/schedule/drafts/${draftID}`,{method:'PUT',body:{contact_id:contactA,quote_id:quoteA,payload,client_revision:0,contact_generation:0}})).status,400);
    assert.equal((await request(`/api/schedule/drafts/${draftID}`,{method:'PUT',body:{contact_id:contactA,quote_id:quoteA,payload,client_revision:2,contact_generation:0}})).status,200);
    assert.equal((await request(`/api/schedule/drafts/${draftID}`,{method:'PUT',body:{contact_id:contactA,quote_id:quoteA,payload,client_revision:1,contact_generation:0}})).body.error,'schedule_draft_changed');
    await request(`/api/schedule/drafts/${otherDraftID}`,{method:'PUT',body:{contact_id:contactA,payload,client_revision:1,contact_generation:0}});
    const jobID=randomUUID(),neverSavedDraftID=randomUUID(),start=new Date(Date.now()+86400000),end=new Date(start.getTime()+90*60000);
    const job={title:'Visit',contact_id:contactA,quote_id:quoteA,start:start.toISOString(),end:end.toISOString(),sales_user_ids:[ownerA],worker_user_ids:[ownerA],scheduling_draft_id:neverSavedDraftID};
    assert.equal((await request(`/api/schedule/${jobID}`,{method:'PUT',body:{...job,quote_id:null}})).status,400);
    assert.equal((await request('/api/schedule/drafts')).body.drafts.length,2);
    const scheduled=await request(`/api/schedule/${jobID}`,{method:'PUT',body:job});
    assert.equal(scheduled.status,200,JSON.stringify(scheduled.body));
    assert.equal((await request('/api/schedule/drafts')).body.drafts.length,0);
    assert.deepEqual((await request('/api/schedule/drafts',{token:'draft-owner-b'})).body.drafts.map(draft=>draft.id),[foreignDraftID]);
    const late=await request(`/api/schedule/drafts/${draftID}`,{method:'PUT',body:{contact_id:contactA,quote_id:quoteA,payload,client_revision:3,contact_generation:0}});
    assert.equal(late.status,409);assert.equal(late.body.error,'schedule_draft_cleared');
    const lateWithoutContact=await request(`/api/schedule/drafts/${neverSavedDraftID}`,{method:'PUT',body:{payload,client_revision:1}});
    assert.equal(lateWithoutContact.status,409);assert.equal(lateWithoutContact.body.error,'schedule_draft_cleared');
    assert.equal((await request(`/api/schedule/drafts?contact_id=${contactA}`)).body.contact_generation,1);
    const nextID=randomUUID();
    assert.equal((await request(`/api/schedule/drafts/${nextID}`,{method:'PUT',body:{contact_id:contactA,payload,client_revision:1,contact_generation:1}})).status,200);
    await pool.query("UPDATE schedule_drafts SET expires_at=now()-interval '1 second' WHERE id=$1",[nextID]);
    assert.equal((await request('/api/schedule/drafts')).body.drafts.length,0);
    assert.equal((await request(`/api/schedule/drafts/${nextID}`,{method:'PUT',body:{contact_id:contactA,payload,client_revision:2,contact_generation:1}})).body.error,'schedule_draft_changed');
    assert.equal((await request(`/api/schedule/drafts/${foreignDraftID}`,{token:'draft-owner-b',method:'DELETE'})).status,204);
    assert.equal((await request(`/api/schedule/drafts/${foreignDraftID}`,{token:'draft-owner-b',method:'PUT',body:{contact_id:contactB,payload,client_revision:2,contact_generation:0}})).body.error,'schedule_draft_cleared');
    assert.equal((await pool.query('SELECT count(*)::int AS n FROM quotes WHERE id=$1',[quoteA])).rows[0].n,1);
  } finally {
    if(server)await new Promise(resolve=>server.close(resolve));
    if(pool)await pool.end();postgres.stop();
  }
});
