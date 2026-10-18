import {missingRules} from './config.js';
import {fault,digest} from '../mcp/context.js';
export async function validateBookingConfiguration(db,companyId,c){
   for(const type of ['quote','job'])if(c[type+'_enabled']&&missingRules(c,type).length)throw fault(400,'booking_rules_incomplete',missingRules(c,type).join(', '));
   if(c.quote_worker_ids.length&&(await db.query('SELECT id FROM users WHERE company_id=$1 AND deleted_at IS NULL AND id=ANY($2::uuid[])',[companyId,c.quote_worker_ids])).rowCount!==new Set(c.quote_worker_ids).size)throw fault(400,'invalid_workers');
   const profileKeys=c.direct_job_profiles.map(p=>JSON.stringify([p.property_type,[...p.service_ids].sort()]));
   if(new Set(profileKeys).size!==profileKeys.length||new Set(c.direct_job_profiles.map(p=>p.id)).size!==c.direct_job_profiles.length)throw fault(400,'duplicate_direct_job_profile');
   const serviceIDs=[...new Set(c.direct_job_profiles.flatMap(p=>p.service_ids))];
   if(serviceIDs.length&&(await db.query('SELECT id FROM saved_services WHERE company_id=$1 AND archived_at IS NULL AND id=ANY($2::uuid[])',[companyId,serviceIDs])).rowCount!==serviceIDs.length)throw fault(400,'invalid_profile_services');
   if(c.job_rules_acknowledged){const company=(await db.query('SELECT customer_booking_settings,timezone FROM companies WHERE id=$1',[companyId])).rows[0];if(c.job_enabled&&(company.timezone!=='America/New_York'||company.customer_booking_settings?.enabled!==true))throw fault(400,'configure_schedule_booking_first');c.job_rules_hash=digest(company.customer_booking_settings);}
 return c;
}
