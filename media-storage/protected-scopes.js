import { fail } from './domain.js';

// Server-owned registrations only. SQL uses stored_files alias f and parameters
// $1=current user, $2=current company. Never accept SQL or scope from an HTTP body.
const scopes=new Map();
export function registerProtectedStorageScope(name,definition) {
  if(!/^[a-z][a-z0-9_]{0,39}$/.test(name)||typeof definition?.predicate!=='function'||typeof definition?.authorizeAccess!=='function')throw new TypeError('Protected storage requires a named read predicate and action authorizer.');
  if(scopes.has(name)&&scopes.get(name)!==definition)throw new Error(`Protected storage scope already registered: ${name}`);
  scopes.set(name,definition);
  return ()=>{if(scopes.get(name)===definition)scopes.delete(name);};
}
export function requireProtectedStorageScope(name) {
  const definition=scopes.get(name);
  if(!definition)fail(403,'protected_scope_unavailable','This protected file is unavailable.');
  return definition;
}
export async function protectedStoragePredicate(db,actor) {
  const clauses=[];
  for(const [name,definition] of scopes){
    const sql=await definition.predicate(db,actor);
    if(typeof sql!=='string'||!sql.trim())throw new TypeError('Protected storage predicate must return SQL.');
    clauses.push(`(f.source_scope='${name}' AND (${sql}))`);
  }
  return clauses.length?`(f.source_protected AND f.visibility='private' AND f.company_id=$2 AND (${clauses.join(' OR ')}))`:'false';
}
export async function authorizeProtectedStorageAccess(db,actor,file,purpose) {
  if(!file.source_scope)return;
  if(!file.source_protected||file.visibility!=='private'||file.company_id!==actor.companyId)fail(404,'file_not_found','This protected file is unavailable.');
  await requireProtectedStorageScope(file.source_scope).authorizeAccess(db,actor,file,purpose);
}
