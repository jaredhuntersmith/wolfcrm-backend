import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {installPayStructureSchema} from '../pay-structures.js';

test('weekly employee sales includes the employer and credits completion week with historical pay', {timeout:60000}, async()=>{
  const postgres=startLocalPostgres();postgres.configureEnvironment();let pool,server;
  try {
    const backend=await import('../index.js');pool=backend.pool;await backend.bootstrap();await installPayStructureSchema(pool);
    const company=randomUUID(),foreignCompany=randomUUID(),owner=randomUUID(),employee=randomUUID(),foreignOwner=randomUUID();
    await pool.query("INSERT INTO companies(id,name,join_code,timezone) VALUES($1,'Report','REPORT-A','America/New_York'),($2,'Foreign','REPORT-B','America/New_York')",[company,foreignCompany]);
    await pool.query("INSERT INTO users(id,email,role,company_id) VALUES($1,'report-owner@example.invalid','employer',$4),($2,'report-employee@example.invalid','employee',$4),($3,'foreign-report@example.invalid','employer',$5)",[owner,employee,foreignOwner,company,foreignCompany]);
    await pool.query('UPDATE companies SET owner_user_id=CASE WHEN id=$1 THEN $3::uuid ELSE $4::uuid END WHERE id IN ($1,$2)',[company,foreignCompany,owner,foreignOwner]);
    await pool.query("INSERT INTO sessions(token,user_id) VALUES('report-owner',$1)",[owner]);
    await pool.query("INSERT INTO employee_pay_structures(company_id,employee_id,effective_from,commission_tiers) VALUES($1,$2,'2020-01-01',$3::jsonb)",[company,owner,JSON.stringify([{id:randomUUID(),threshold_cents:0,percent_basis_points:1000}])]);
    server=await new Promise(resolve=>{const listener=backend.app.listen(0,'127.0.0.1',()=>resolve(listener));});
    const base=`http://127.0.0.1:${server.address().port}`;
    const get=async(userID)=>{const response=await fetch(`${base}/api/reports/weekly-sales?date=${encodeURIComponent(new Date().toISOString())}&user_id=${userID}`,{headers:{authorization:'Bearer report-owner'}});return{status:response.status,body:await response.json()};};
    const empty=await get(owner);assert.equal(empty.status,200,JSON.stringify(empty.body));
    const start=new Date(new Date(empty.body.start).getTime()-60*60000);
    const finished=new Date(new Date(empty.body.start).getTime()+60*60000);
    const jobID=randomUUID();
    await pool.query(`INSERT INTO schedule_events(id,user_id,company_id,created_by,title,start_at,end_at,finished_at,price_cents,sales_user_ids,worker_user_ids)
      VALUES($1,$2,$3,$2,'Prior service week',$4,$5,$6,101,$7::jsonb,$8::jsonb)`,[jobID,owner,company,start,new Date(start.getTime()+30*60000),finished,JSON.stringify([owner,employee]),JSON.stringify([owner])]);
    const self=await get(owner);assert.equal(self.status,200,JSON.stringify(self.body));
    assert.equal(self.body.jobs.length,1);assert.equal(self.body.jobs[0].id,jobID);
    assert.equal(self.body.jobs[0].credited_revenue_cents,51);
    assert.equal(self.body.jobs[0].commission_cents,5);
    assert.equal(self.body.total_revenue_cents,51);assert.equal(self.body.total_commission_cents,5);
    const other=await get(employee);assert.equal(other.status,200,JSON.stringify(other.body));
    assert.equal(other.body.jobs[0].credited_revenue_cents,50);
    assert.equal(other.body.jobs[0].commission_cents,null);
    await pool.query('UPDATE users SET deleted_at=now() WHERE id=$1',[employee]);
    assert.equal((await get(employee)).body.jobs[0].credited_revenue_cents,50);
    const peopleResponse=await fetch(`${base}/api/reports/weekly-sales/people`,{headers:{authorization:'Bearer report-owner'}});
    assert.equal(peopleResponse.status,200);
    const people=await peopleResponse.json();
    assert.equal(people.find(person=>person.id===employee).inactive,true);
    assert.equal(people.some(person=>person.id===foreignOwner),false);
    assert.equal((await get(foreignOwner)).status,404);
  } finally {
    if(server)await new Promise(resolve=>server.close(resolve));if(pool)await pool.end();postgres.stop();
  }
});
