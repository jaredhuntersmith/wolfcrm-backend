import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {startLocalPostgres} from './helpers/local-postgres.js';
import {installPayStructureSchema} from '../pay-structures.js';
import {installFinanceSchema} from '../finance.js';
import {installFinanceSpacesSchema,withFinanceSpace} from '../finance-spaces.js';
import {createWidgetDashboard} from '../widget-dashboard.js';

test('goal contributions and receipt action remain explicitly bound to an authorized Finance Space',{timeout:120000},async()=>{
 const pg=startLocalPostgres();pg.configureEnvironment();let pool;
 try {
  const backend=await import('../index.js');pool=backend.pool;await backend.bootstrap();
  const company=randomUUID(),owner=randomUUID(),other=randomUUID(),goal=randomUUID(),space=randomUUID(),hidden=randomUUID();
  await pool.query("INSERT INTO companies(id,name,join_code) VALUES($1,'Widget finance','WIDGET-FINANCE')",[company]);
  for(const id of[owner,other])await pool.query("INSERT INTO users(id,email,display_name,role,company_id) VALUES($1,$2,'Owner','employer',$3)",[id,id+'@example.invalid',company]);
  await pool.query('UPDATE companies SET owner_user_id=$2 WHERE id=$1',[company,owner]);
  await installPayStructureSchema(pool);await installFinanceSchema(pool);await installFinanceSpacesSchema(pool);
  for(const[id,user]of[[space,owner],[hidden,other]])await pool.query("INSERT INTO finance_spaces(id,company_id,owner_id,name,kind,audience) VALUES($1,$2,$3,'Private savings','business','private')",[id,company,user]);
  await withFinanceSpace(pool,owner,company,space,db=>db.query("INSERT INTO finance_goals(id,company_id,name,goal_type,target_amount_cents,current_amount_cents,created_by) VALUES($1,$2,'Equipment','equipment_purchase',100000,25000,$3)",[goal,company,owner]));
  await withFinanceSpace(pool,other,company,hidden,db=>db.query("INSERT INTO finance_goals(company_id,name,goal_type,target_amount_cents,current_amount_cents,created_by) VALUES($1,'SECRET','custom',999999,99999,$2)",[company,other]));
  const service=createWidgetDashboard({pool}),actor={userId:owner,companyId:company};
  const query=(kind,filters={})=>service.summary(actor,{slots:[{id:'a',kind,filters}]});
  let m=(await query('goals',{financeSpace:space,goal})).modules[0];assert.equal(m.state,'ready',JSON.stringify(m));assert.equal(m.value,'$250.00 / $1,000.00');assert.match(m.rows[0].subtitle,/25%/);assert.equal(m.count,1);
  assert.equal((await query('log_expense',{financeSpace:space})).modules[0].state,'ready');
  for(const kind of['goals','log_expense'])for(const filters of[{}, {financeSpace:hidden}]){m=(await query(kind,filters)).modules[0];assert.equal(m.state,'unavailable');assert.equal(m.value,undefined);assert.equal(JSON.stringify(m).includes('SECRET'),false);}
  await pool.query('UPDATE finance_spaces SET owner_id=$2 WHERE id=$1',[space,other]);
  assert.equal((await query('goals',{financeSpace:space})).modules[0].state,'unavailable');
 }finally{if(pool)await pool.end();pg.stop();}
});
