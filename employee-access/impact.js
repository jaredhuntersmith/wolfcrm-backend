import {createHash} from 'node:crypto';

// Read-only review of existing obligations. Disabling never deletes, reassigns or
// rewrites scheduled work. Crew-domain providers register their own schema here.
const providers=new Map();
export function registerEmployeeImpactProvider(name,provider){
 if(!/^[a-z][a-z0-9_]{0,39}$/.test(name)||typeof provider!=='function')throw new TypeError('Invalid employee impact provider');
 if(providers.has(name)&&providers.get(name)!==provider)throw new Error('Employee impact provider already registered');
 providers.set(name,provider);return ()=>{if(providers.get(name)===provider)providers.delete(name);};
}
export async function employeeImpact(db,actor,target){
 const rows=(await db.query(`SELECT id,title,start_at,end_at,updated_at,sales_user_ids,worker_user_ids FROM schedule_events
   WHERE company_id=$1 AND finished_at IS NULL AND end_at>=now() AND (sales_user_ids ? $2::text OR worker_user_ids ? $2::text)
   ORDER BY start_at,id`,[target.company_id,target.id])).rows;
 const scopes=[];
 // Existing customer-booking crews live in company settings. Keep membership
 // visible for review without changing or silently reactivating the bundle.
 const company=(await db.query("SELECT to_jsonb(c)->'customer_booking_settings' settings,to_jsonb(c)->'customer_booking_version' version FROM companies c WHERE id=$1",[target.company_id])).rows[0];
 const bundles=company?.settings?.resource_bundles;
 if(Array.isArray(bundles)){
  const records=bundles.filter(b=>Array.isArray(b.worker_user_ids)&&b.worker_user_ids.includes(target.id)).map(b=>({
   id:b.id,name:b.name,enabled:b.enabled===true,worker_user_ids:[...b.worker_user_ids].sort(),
   service_ids:Array.isArray(b.service_ids)?[...b.service_ids].sort():[],all_services:b.all_services===true,settings_version:company.version
  })).sort((a,b)=>String(a.id).localeCompare(String(b.id)));
  if(records.length)scopes.push({name:'customer_booking_crews',records});
 }
 for(const [name,provider] of [...providers].sort(([a],[b])=>a.localeCompare(b))){
  const result=await provider(db,{companyId:target.company_id,userId:target.id,actor});
  if(!Array.isArray(result))throw new TypeError('Impact provider must return ordered review records');
  scopes.push({name,records:result});
 }
 const canReview=actor.isOwner||actor.access.capabilities['schedule.view']===true;
 const reviewToken=createHash('sha256').update(JSON.stringify({revision:Number(target.account_revision),jobs:rows,scopes})).digest('hex');
 return {review_token:reviewToken,future_job_count:rows.length,future_jobs:canReview?rows.map(({id,title,start_at,end_at})=>({id,title,start_at,end_at})):[],
   other_obligations:canReview?scopes:[],can_review:canReview,retained_history:'Existing jobs, hours, pay, commissions, reimbursements, messages and shared company records remain attributed to this employee.'};
}
