import {z} from 'zod';
import {fault,transaction} from '../mcp/context.js';

const month="(date_trunc('month',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')";
export const allocationInput=z.object({expected_revision:z.number().int().nonnegative(),enabled:z.boolean(),monthly_limit_micros:z.number().int().min(0).max(1000000000)}).strict();
const publicAllocation=r=>({user_id:r.user_id,enabled:r.enabled,monthly_limit_micros:Number(r.monthly_limit_micros),revision:r.revision,updated_at:r.updated_at});

// Funding allocation is a human owner operation. It never changes CRM/tool grants,
// exposes the shared API key, or makes an employee a permission administrator.
export function createFundingService(pool,env){
 async function authorize(s){
  if(s.funding!=='owner')return null;
  if(env.ASSISTANT_OWNER_FUNDING!=='true')throw fault(403,'owner_funding_disabled');
  const principal=(await pool.query('SELECT c.owner_user_id FROM companies c JOIN users u ON u.company_id=c.id WHERE c.id=$1 AND u.id=$2 AND u.deleted_at IS NULL',[s.company_id,s.user_id])).rows[0];
  if(!principal)throw fault(403,'membership_inactive');
  if(principal.owner_user_id===s.user_id)return {owner:true,monthly_limit_micros:null};
  const grant=(await pool.query('SELECT * FROM wolf_assistant_funding_allocations WHERE company_id=$1 AND user_id=$2',[s.company_id,s.user_id])).rows[0];
  if(!grant?.enabled||Number(grant.monthly_limit_micros)<=0)throw fault(403,'owner_funding_not_allocated','The company owner must allocate API funding to you in Assistant settings.');
  return publicAllocation(grant);
 }
 async function own(s){try{return {available:true,allocation:await authorize({...s,funding:'owner'})};}catch(e){return {available:false,allocation:null,reason:e.code};}}
 async function list(a){
  if(!a.isCompanyOwner)throw fault(403,'funding_owner_required');
  const rows=(await pool.query(`SELECT u.id AS user_id,u.display_name,COALESCE(g.enabled,false) enabled,COALESCE(g.monthly_limit_micros,0)::float8 monthly_limit_micros,COALESCE(g.revision,0) revision,g.updated_at,
    COALESCE(t.cost_micros,0)::float8 cost_micros,COALESCE(t.reserved_micros,0)::float8 reserved_micros
    FROM users u LEFT JOIN wolf_assistant_funding_allocations g ON g.company_id=u.company_id AND g.user_id=u.id
    LEFT JOIN (SELECT user_id,sum(cost_micros) cost_micros,sum(reserved_micros) reserved_micros FROM wolf_assistant_runs WHERE company_id=$1 AND funding='owner' AND created_at>=${month} GROUP BY user_id) t ON t.user_id=u.id
    WHERE u.company_id=$1 AND u.deleted_at IS NULL AND u.id<>$2 ORDER BY u.display_name,u.id`,[a.companyId,a.userId])).rows;
  return {items:rows,cost_status:'estimate_only',period:'Current UTC calendar month'};
 }
 async function save(a,userId,raw){
  if(!a.isCompanyOwner)throw fault(403,'funding_owner_required');
  const i=allocationInput.parse(raw);
  return transaction(pool,async db=>{
   const company=(await db.query('SELECT owner_user_id FROM companies WHERE id=$1 FOR UPDATE',[a.companyId])).rows[0];
   if(company?.owner_user_id!==a.userId)throw fault(403,'funding_owner_required');
   if(userId===a.userId)throw fault(400,'staff_allocation_required');
   if(!(await db.query('SELECT id FROM users WHERE id=$1 AND company_id=$2 AND deleted_at IS NULL',[userId,a.companyId])).rowCount)throw fault(404,'funding_member_unavailable');
   const old=(await db.query('SELECT * FROM wolf_assistant_funding_allocations WHERE company_id=$1 AND user_id=$2 FOR UPDATE',[a.companyId,userId])).rows[0];
   if((old?.revision||0)!==i.expected_revision)throw fault(409,'funding_allocation_changed');
   const saved=(await db.query(`INSERT INTO wolf_assistant_funding_allocations(company_id,user_id,enabled,monthly_limit_micros,granted_by_user_id) VALUES($1,$2,$3,$4,$5)
    ON CONFLICT(company_id,user_id) DO UPDATE SET enabled=EXCLUDED.enabled,monthly_limit_micros=EXCLUDED.monthly_limit_micros,granted_by_user_id=EXCLUDED.granted_by_user_id,revision=wolf_assistant_funding_allocations.revision+1,updated_at=now() RETURNING *`,[a.companyId,userId,i.enabled,i.monthly_limit_micros,a.userId])).rows[0];
   await db.query('INSERT INTO wolf_assistant_funding_revisions(company_id,user_id,revision,enabled,monthly_limit_micros,author_id) VALUES($1,$2,$3,$4,$5,$6)',[a.companyId,userId,saved.revision,i.enabled,i.monthly_limit_micros,a.userId]);
   return publicAllocation(saved);
  });
 }
 async function checkReservation(run,amount){
  const grant=await authorize(run);if(!grant||grant.owner)return;
  const total=(await pool.query(`SELECT COALESCE(sum(cost_micros+reserved_micros),0)::text total FROM wolf_assistant_runs WHERE company_id=$1 AND user_id=$2 AND funding='owner' AND created_at>=${month}`,[run.company_id,run.user_id])).rows[0];
  if(Number(total.total)+amount>grant.monthly_limit_micros)throw fault(403,'owner_funding_allocation_exceeded','Your owner-funded monthly allocation is exhausted. No funding source was switched.');
 }
 return {authorize,own,list,save,checkReservation};
}
