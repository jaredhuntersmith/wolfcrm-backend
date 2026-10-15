// Disposable local PostgreSQL + real application routes. No payment or bank providers.
import express from 'express';
import {randomUUID} from 'node:crypto';
import {startLocalPostgres} from '../tests/helpers/local-postgres.js';
import {installFinanceSystem} from '../finance.js';
import {withFinanceSpace} from '../finance-spaces.js';
import {installPayStructureSchema} from '../pay-structures.js';
import {installAgreementSchema} from '../quote-agreements.js';
import {installAgreementPlanSchema} from '../agreement-plans.js';
import {installAgreementPlanBillingSchema} from '../agreement-plan-billing.js';
import {installIdeaParking} from '../idea-parking.js';
import {installServicePlanReview} from '../service-plan-review.js';
import {hasCapability,requiredFinanceCapability,PERMISSION_CAPABILITIES} from '../permissions.js';
const local=startLocalPostgres();local.configureEnvironment();const backend=await import('../index.js');const {pool}=backend;await backend.bootstrap();
await installPayStructureSchema(pool);await installAgreementSchema(pool);await installAgreementPlanSchema(pool);await installAgreementPlanBillingSchema(pool);
const company=randomUUID(),alice=randomUUID(),bob=randomUUID(),contact=randomUUID();
await pool.query("INSERT INTO companies(id,name,join_code) VALUES($1,'Privacy QA','PRIVATEQA')",[company]);
for(const [id,name] of [[alice,'Alice'],[bob,'Bob']]){await pool.query("INSERT INTO users(id,email,display_name,role,company_id) VALUES($1,$2,$3,'employer',$4)",[id,name.toLowerCase()+'@example.test',name,company]);await pool.query('INSERT INTO sessions(token,user_id) VALUES($1,$2)',['privacy-qa-'+name,id]);}
await pool.query("INSERT INTO employee_permissions(user_id,company_id,permission_preset,permission_overrides) VALUES($1,$2,'admin',$3)",[bob,company,JSON.stringify(Object.fromEntries(PERMISSION_CAPABILITIES.map(c=>[c.key,true])))]);
await pool.query('UPDATE companies SET owner_user_id=$2 WHERE id=$1',[company,alice]);
await pool.query("INSERT INTO contacts(id,user_id,company_id,name) VALUES($1,$2,$3,'Plan Customer')",[contact,alice,company]);
for(const [name,status] of [['Current Plan','active'],['Waiting Plan','payment_pending'],['Ended Plan','canceled']])await pool.query("INSERT INTO service_plans(user_id,company_id,contact_id,plan_name,status,price_cents,billing_interval,service_interval) VALUES($1,$2,$3,$4,$5,10000,'month','month')",[alice,company,contact,name,status]);
await installFinanceSystem({app:backend.app,pool,authRequired:backend.authRequired,requireEmployer:(req,res,next)=>hasCapability(req,requiredFinanceCapability(req.method,req.path))?next():res.status(403).json({error:'permission_denied'}),getStripe:()=>null});
await installIdeaParking({app:backend.app,pool,authRequired:backend.authRequired});await installServicePlanReview({...backend,requireCapability:backend.requireCapability});
await withFinanceSpace(pool,alice,company,null,db=>db.query("INSERT INTO finance_accounts(company_id,name,account_type,current_balance_cents,created_by) VALUES($1,'Alice private bank','checking',123400,$2)",[company,alice]));
const outer=express();outer.use(express.json());
const makeUser=name=>({id:name==='Alice'?alice:bob,email:name.toLowerCase()+'@example.test',display_name:name,role:'employer',company:{id:company,name:'Privacy QA'},permissions:{capabilities:Object.fromEntries(PERMISSION_CAPABILITIES.map(c=>[c.key,true]))}});
outer.post('/auth/login',(req,res)=>{const name=req.body.email==='alice@example.test'?'Alice':req.body.email==='bob@example.test'?'Bob':null;if(!name||req.body.password!=='local-fixture')return res.sendStatus(401);res.json({user:makeUser(name),token:'privacy-qa-'+name});});
outer.get('/me',(req,res)=>{const name=req.get('Authorization')==='Bearer privacy-qa-Alice'?'Alice':req.get('Authorization')==='Bearer privacy-qa-Bob'?'Bob':null;if(!name)return res.sendStatus(401);res.json({user:makeUser(name)});});
outer.post('/__qa/reset',async(req,res)=>{
 const tables=(await pool.query("SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'finance\\_%' ESCAPE '\\'")).rows.map(r=>'"'+r.tablename+'"');
 await pool.query('TRUNCATE '+tables.join(',')+' CASCADE');
 await pool.query('TRUNCATE idea_parking_ideas,idea_parking_members,idea_parking_lists,service_plan_review_preferences CASCADE');
 await withFinanceSpace(pool,alice,company,null,db=>db.query("INSERT INTO finance_accounts(company_id,name,account_type,current_balance_cents,created_by) VALUES($1,'Alice private bank','checking',123400,$2)",[company,alice]));
 res.json({reset:true});
});
outer.get('/__qa/ready',(req,res)=>res.json({ready:true}));outer.use(backend.app);
const server=outer.listen(4113,'127.0.0.1',()=>console.log('Private workspace fixture ready'));
let closing=false;async function stop(){if(closing)return;closing=true;server.close();await pool.end();local.stop();process.exit(0);}process.on('SIGTERM',stop);process.on('SIGINT',stop);
