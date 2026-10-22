import { randomUUID } from 'node:crypto';
import { ownerIdentity } from '../permission-governance.js';
import { PERMISSION_CAPABILITIES, resolveAccess, hasCapability, validateAccessUpdate } from '../permissions.js';
import { validatePermissionWindows, permissionWindowOpen } from '../permission-windows.js';
import { accountDenial, revokeAccountSessions } from './auth.js';
import {employeeImpact,registerEmployeeImpactProvider} from './impact.js';

export class EmployeeAccountError extends Error {
  constructor(status,code,message){super(message);this.status=status;this.code=code;}
}
export const reject=(status,code,message)=>{throw new EmployeeAccountError(status,code,message);};
const uuid=value=>typeof value==='string'&&/^[\da-f]{8}(-[\da-f]{4}){3}-[\da-f]{12}$/i.test(value);
const knownKeys=new Set(PERMISSION_CAPABILITIES.map(c=>c.key));
const stateFields=['locked_at','deleted_at','recovery_until','private_data_state','private_purged_at','operational_eligible','operational_review_required_at','account_revision'];
export const accountState=row=>Object.fromEntries(stateFields.map(key=>[key,key==='account_revision'?Number(row[key]):row[key]??null]));
export const loadAccountSQL=`SELECT u.*,c.owner_user_id,COALESCE(to_jsonb(c)->>'timezone','UTC') AS company_timezone,
  to_jsonb(p) AS permission_record,COALESCE(d.scope,'[]') AS delegation_scope FROM users u
  LEFT JOIN companies c ON c.id=u.company_id
  LEFT JOIN employee_permissions p ON p.user_id=u.id AND p.company_id=u.company_id
  LEFT JOIN employee_access_delegations d ON d.user_id=u.id AND d.company_id=u.company_id`;

export async function loadAccount(db,id) {
  if(!uuid(id))reject(400,'invalid_employee','Invalid employee identifier.');
  const row=(await db.query(loadAccountSQL+' WHERE u.id=$1',[id])).rows[0];
  if(!row)reject(404,'employee_not_found','Employee not found.');
  const isOwner=ownerIdentity(row),p=row.permission_record||{};
  const access=resolveAccess({isOwner,preset:p.permission_preset,overrides:p.permission_overrides,legacy:p,timeZone:row.company_timezone});
  return {...row,isOwner,isCompanyOwner:isOwner,isAdmin:!isOwner&&p.permission_preset==='admin',permissions:{capabilities:access.capabilities},access};
}
export async function accountActor(db,context) {
  const actor=await loadAccount(db,context.userId),denial=accountDenial(actor);
  if(denial)reject(401,denial.error,denial.message);
  if(!actor.company_id||actor.company_id!==context.companyId)reject(403,'membership_changed','Company membership changed. Sign in again.');
  return actor;
}
export function requireAccountAuthority(actor,target,capability='team.manage_accounts') {
  if(actor.company_id!==target.company_id)reject(404,'employee_not_found','Employee not found.');
  if(target.isOwner||target.id===actor.id)reject(403,'owner_or_self_protected','You cannot change yourself or the company owner here.');
  if(!actor.isOwner&&(!actor.isAdmin||!hasCapability(actor,capability)||target.isAdmin))reject(403,'account_administration_denied','Only the owner or an authorized Admin can manage ordinary employee accounts.');
}
export async function accountTransaction(pool,context,targetId,work) {
  const db=await pool.connect();
  try{
    await db.query('BEGIN');
    if(!context.companyId||!(await db.query('SELECT id FROM companies WHERE id=$1 FOR UPDATE',[context.companyId])).rowCount)reject(403,'company_required','A company is required.');
    const actor=await accountActor(db,context);
    if(!uuid(targetId))reject(400,'invalid_employee','Invalid employee identifier.');
    await db.query("SELECT pg_advisory_xact_lock(hashtextextended('comms-permissions:'||$1,0))",[targetId]);
    await db.query('SELECT id FROM users WHERE id=$1 AND company_id=$2 FOR UPDATE',[targetId,actor.company_id]);
    const target=await loadAccount(db,targetId);
    const value=await work(db,actor,target);
    await db.query('COMMIT');return value;
  }catch(error){await db.query('ROLLBACK');throw error;}finally{db.release();}
}
export function requireRevision(target,expected) {
  if(!Number.isSafeInteger(expected)||Number(target.account_revision)!==expected)reject(409,'account_changed','Employee state changed. Refresh before confirming.');
}
export async function recordAccountChange(db,actor,target,action) {
  const current=await loadAccount(db,target.id);
  await db.query('INSERT INTO employee_account_audit(id,company_id,user_id,actor_user_id,action,previous,current) VALUES($1,$2,$3,$4,$5,$6,$7)',
    [randomUUID(),target.company_id,target.id,actor?.id||null,action,JSON.stringify(accountState(target)),JSON.stringify(accountState(current))]);
  const event=(await db.query(`INSERT INTO permission_change_outbox(id,company_id,user_id,permission_revision,reason)
    VALUES($1,$2,$3,$4,$5) RETURNING *`,[randomUUID(),target.company_id,target.id,Number(current.permission_record?.permission_revision||0),action])).rows[0];
  return {employee:employeeDTO(current),event};
}
export function employeeDTO(row) {
  return {id:row.id,email:row.pre_delete_email||row.email,display_name:row.display_name,photo_url:row.photo_url,
    is_admin:row.isAdmin,...accountState(row),permission_revision:Number(row.permission_record?.permission_revision||0),
    permission_windows:row.permission_record?.permission_windows||{}};
}
export function createEmployeeAccountService({pool,onChange,onTransition}) {
  async function notify(result) {
    if(onChange&&result.event)try{
      const e=result.event;await onChange({id:e.id,companyId:e.company_id,userId:e.user_id,revision:Number(e.permission_revision),reason:e.reason});
      await pool.query('UPDATE permission_change_outbox SET delivered_at=now() WHERE id=$1',[e.id]);
    }catch{/* Existing durable permission outbox retries failed transports. */}
    return {success:true,employee:result.employee};
  }
  async function directory(context,{disabled=false}={}) {
    const actor=await accountActor(pool,context);
    const manages=actor.isOwner||(actor.isAdmin&&hasCapability(actor,'team.manage_accounts'));
    if(!manages)reject(403,'account_administration_denied','Employee account administration is unavailable.');
    const rows=(await pool.query(loadAccountSQL+' WHERE u.company_id=$1 AND u.id<>$2 AND (u.deleted_at IS NOT NULL)=$3 ORDER BY COALESCE(u.display_name,u.email),u.id',[actor.company_id,actor.owner_user_id,disabled])).rows;
    const employees=[];
    for(const row of rows){const p=row.permission_record||{};if(!actor.isOwner&&(row.id===actor.id||p.permission_preset==='admin'))continue;employees.push(employeeDTO({...row,isAdmin:p.permission_preset==='admin'}));}
    return {employees,company_timezone:actor.company_timezone,is_company_owner:actor.isOwner,can_purge_private:actor.isOwner||hasCapability(actor,'team.purge_private'),server_time:new Date().toISOString()};
  }
  async function detail(context,id) {
    const actor=await accountActor(pool,context),target=await loadAccount(pool,id);
    requireAccountAuthority(actor,target);
    return {employee:employeeDTO(target),company_timezone:actor.company_timezone,server_time:new Date().toISOString(),
      can_purge_private:actor.isOwner||hasCapability(actor,'team.purge_private'),impact:await employeeImpact(pool,actor,target)};
  }
  async function transition(context,id,action,input={}) {
    if(!['lock','unlock','disable','restore','review-eligibility'].includes(action))reject(400,'invalid_account_action','Choose a supported employee action.');
    const result=await accountTransaction(pool,context,id,async(db,actor,target)=>{
      requireAccountAuthority(actor,target);requireRevision(target,input.expected_revision);
      if(action==='lock'||action==='unlock'){
        if(target.deleted_at)reject(409,'employee_disabled','Restore the disabled employee before changing the lock.');
        if(action==='lock'){
          await db.query('UPDATE users SET locked_at=COALESCE(locked_at,now()),locked_by=$2,account_revision=account_revision+1 WHERE id=$1',[id,actor.id]);
          await revokeAccountSessions(db,id,'account_locked');
        }else await db.query('UPDATE users SET locked_at=NULL,locked_by=NULL,account_revision=account_revision+1 WHERE id=$1',[id]);
      }else if(action==='disable'){
        if(target.deleted_at)reject(409,'employee_disabled','This employee is already disabled.');
        await db.query(`UPDATE users SET deleted_at=now(),deleted_by=$2,recovery_until=now()+interval '720 hours',private_data_state='recoverable',
          operational_eligible=false,operational_review_required_at=now(),account_revision=account_revision+1 WHERE id=$1`,[id,actor.id]);
        await revokeAccountSessions(db,id,'account_disabled');
        // Names, photos, password hash and permission rows remain recoverable.
        // Auth checks account state before accepting login/reset/MCP credentials.
      }else if(action==='restore'){
        const eligible=(await db.query("SELECT 1 FROM users WHERE id=$1 AND deleted_at IS NOT NULL AND private_data_state='recoverable' AND recovery_until>now()",[id])).rowCount;
        if(!eligible)reject(409,'recovery_unavailable','The private-data recovery window has ended or this account requires legacy review.');
        await db.query(`UPDATE users SET deleted_at=NULL,deleted_by=NULL,recovery_until=NULL,private_data_state='active',
          locked_at=NULL,locked_by=NULL,operational_eligible=false,operational_review_required_at=now(),account_revision=account_revision+1 WHERE id=$1`,[id]);
        // Existing sessions remain revoked; restoration requires a new login.
      }else{
        if(target.deleted_at||target.locked_at)reject(409,'employee_inactive','Restore and unlock the employee before reviewing eligibility.');
        if(input.confirm_reviewed!==true)reject(400,'review_required','Review future jobs and crew membership before restoring operational eligibility.');
        const impact=await employeeImpact(db,actor,target);
        if(!impact.can_review)reject(403,'schedule_review_required','An administrator with schedule access must review the existing assignments.');
        if(input.expected_impact!==impact.review_token)reject(409,'employee_impact_changed','Existing assignments changed. Review the current jobs and crews again.');
        await db.query('UPDATE users SET operational_eligible=true,operational_review_required_at=NULL,account_revision=account_revision+1 WHERE id=$1',[id]);
      }
      const change=await recordAccountChange(db,actor,target,'account_'+action.replaceAll('-','_'));
      if(onTransition)await onTransition(db,{actor,target,action,eventID:change.event.id});
      return change;
    });
    return notify(result);
  }
  async function windows(context,id,input) {
    const windows=validatePermissionWindows(input.windows,knownKeys);
    const result=await accountTransaction(pool,context,id,async(db,actor,target)=>{
      const managementWindow=actor.permission_record?.permission_windows?.['team.manage_access'];
      if(target.isOwner||target.id===actor.id||(!actor.isOwner&&(!actor.isAdmin||target.isAdmin||!actor.delegation_scope.length||(managementWindow&&!permissionWindowOpen(managementWindow,actor.company_timezone)))))reject(403,'access_administration_denied','Permission administration is unavailable.');
      if(target.company_id!==actor.company_id)reject(404,'employee_not_found','Employee not found.');
      if(target.deleted_at)reject(409,'employee_disabled','Restore the employee before changing permission windows.');
      const p=target.permission_record||{};
      if(!Number.isInteger(input.expected_revision)||Number(p.permission_revision)!==input.expected_revision)reject(409,'permissions_changed','Employee access changed. Refresh before saving.');
      if(!actor.isOwner)for(const key of new Set([...Object.keys(windows),...Object.keys(p.permission_windows||{})])){
        if(JSON.stringify(windows[key])!==JSON.stringify(p.permission_windows?.[key])&&!actor.delegation_scope.includes(key))reject(403,'delegation_scope_exceeded','This window exceeds your delegated scope.');
      }
      await db.query('UPDATE employee_permissions SET permission_windows=$2,permission_revision=permission_revision+1,updated_at=now() WHERE user_id=$1',[id,JSON.stringify(windows)]);
      await db.query('INSERT INTO permission_governance_audit(id,company_id,actor_user_id,target_user_id,action,previous,current) VALUES($1,$2,$3,$4,$5,$6,$7)',[randomUUID(),actor.company_id,actor.id,id,'permission_windows_changed',JSON.stringify(p.permission_windows||{}),JSON.stringify(windows)]);
      const saved=await recordAccountChange(db,actor,target,'permission_windows_changed');
      return {...saved,company_timezone:actor.company_timezone};
    });
    return {...await notify(result),company_timezone:result.company_timezone};
  }
  async function rolePresets(context){const actor=await accountActor(pool,context);if(!actor.isOwner&&!(actor.isAdmin&&actor.delegation_scope.length))reject(403,'access_administration_denied','Role presets are unavailable.');return {presets:(await pool.query('SELECT id,name,base_preset,overrides,permission_windows,revision FROM employee_role_presets WHERE company_id=$1 ORDER BY name,id',[actor.company_id])).rows,can_edit:actor.isOwner};}
  async function saveRolePreset(context,id,input){
    const actor=await accountActor(pool,context);if(!actor.isOwner)reject(403,'owner_required','Only the owner may create or change company role presets.');
    const name=String(input.name||'').trim();if(!name||name.length>80)reject(400,'invalid_name','Use a role name from 1–80 characters.');
    const access=validateAccessUpdate({preset:input.base_preset,overrides:input.overrides});
    const windows=validatePermissionWindows(input.permission_windows||{},knownKeys);
    let row;
    if(id){if(!uuid(id)||!Number.isInteger(input.expected_revision))reject(400,'invalid_role','Refresh the role preset before saving.');row=(await pool.query('UPDATE employee_role_presets SET name=$3,base_preset=$4,overrides=$5,permission_windows=$6,revision=revision+1,updated_by=$7,updated_at=now() WHERE id=$1 AND company_id=$2 AND revision=$8 RETURNING *',[id,actor.company_id,name,access.preset,JSON.stringify(access.overrides),JSON.stringify(windows),actor.id,input.expected_revision])).rows[0];}
    else row=(await pool.query('INSERT INTO employee_role_presets(id,company_id,name,base_preset,overrides,permission_windows,created_by,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7,$7) RETURNING *',[randomUUID(),actor.company_id,name,access.preset,JSON.stringify(access.overrides),JSON.stringify(windows),actor.id])).rows[0];
    if(!row)reject(409,'role_changed','Role preset changed. Refresh before saving.');return {preset:row};
  }
  async function deleteRolePreset(context,id,input){const actor=await accountActor(pool,context);if(!actor.isOwner)reject(403,'owner_required','Only the owner may delete company role presets.');if(!uuid(id)||!Number.isInteger(input.expected_revision))reject(400,'invalid_role','Refresh the role before deleting.');const result=await pool.query('DELETE FROM employee_role_presets WHERE id=$1 AND company_id=$2 AND revision=$3',[id,actor.company_id,input.expected_revision]);if(!result.rowCount)reject(409,'role_changed','Role preset changed. Refresh before deleting.');return {success:true};}
  return {registerEmployeeImpactProvider,detail,directory,transition,windows,rolePresets,saveRolePreset,deleteRolePreset};
}
