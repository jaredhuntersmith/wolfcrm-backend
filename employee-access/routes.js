import { createEmployeeAccountService } from './service.js';
import { createPermissionGovernance } from '../permission-governance.js';

export function installEmployeeAccountRoutes({app,pool,authRequired,onChange,onTransition}) {
  const service=createEmployeeAccountService({pool,onChange,onTransition});
  const governance=createPermissionGovernance({pool,onChange});
  const route=(method,path,work)=>app[method](path,authRequired,async(req,res)=>{
    res.set('Cache-Control','private, no-store');
    try{res.json(await work(req));}
    catch(error){res.status(error.status||500).json({error:error.code||'employee_access_failed',message:error.status?error.message:'Employee Access is temporarily unavailable.'});}
  });
  route('get','/api/company/employees/:id/account',r=>service.detail(r,r.params.id));
  route('get','/api/company/employee-accounts',r=>service.directory(r,{disabled:r.query.disabled==='true'}));
  for(const action of ['lock','unlock','disable','restore','review-eligibility'])route('post',`/api/company/employees/:id/${action}`,r=>service.transition(r,r.params.id,action,r.body));
  // Older clients must refresh into Employee Access to receive the revision and
  // recovery preview. They cannot silently invoke the old unbounded removal path.
  route('delete','/api/company/employees/:id',r=>service.transition(r,r.params.id,'disable',r.body||{}));
  route('put','/api/company/employees/:id/permission-windows',r=>service.windows(r,r.params.id,r.body));
  route('post','/api/company/employees/:id/apply-role',r=>governance.applyRolePreset(r,r.params.id,r.body));
  route('get','/api/company/employee-role-presets',r=>service.rolePresets(r));
  route('post','/api/company/employee-role-presets',r=>service.saveRolePreset(r,null,r.body));
  route('put','/api/company/employee-role-presets/:id',r=>service.saveRolePreset(r,r.params.id,r.body));
  route('delete','/api/company/employee-role-presets/:id',r=>service.deleteRolePreset(r,r.params.id,r.body));
  return service;
}
