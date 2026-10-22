// Worker 3 contract: only author-owned, never-published personal definitions
// without retained history are deletable. Unknown schema/history stays retained.
export const privateTrainingAuditActions = [
 'definition.created','definition.updated','definition.duplicated',
 'definition.archived','definition.imported','asset.reserved','question_bank.imported'
];
const quote=value=>'"'+value.replaceAll('"','""')+'"';
export const privateTrainingBankAuditActions=['question_bank.created','question_bank.updated','question_bank.archived'];

export async function privateTrainingBankSQL(db,tables,{alias='b',user='$1',company='$2'}={}) {
 const required={training_question_banks:['id','company_id','created_by','scope','revision'],training_audit_events:['company_id','actor_id','recipient_id','definition_id','action','details']};
 if(Object.entries(required).some(([table,columns])=>columns.some(column=>!tables.get(table)?.has(column))))return 'false';
 const actions=privateTrainingBankAuditActions.map(action=>`'${action}'`).join(',');
 const clauses=[`${alias}.company_id=${company}`,`${alias}.created_by=${user}`,`${alias}.scope='personal'`,
  `NOT EXISTS(SELECT 1 FROM training_audit_events history WHERE history.details::text LIKE '%'||${alias}.id::text||'%' AND
   (history.action NOT IN (${actions}) OR history.recipient_id IS NOT NULL OR history.definition_id IS NOT NULL
    OR history.company_id<>${alias}.company_id OR history.actor_id<>${alias}.created_by OR history.details->>'bank_id' IS DISTINCT FROM ${alias}.id::text))`];
 const refs=(await db.query(`SELECT child.relname child,ca.attname column_name FROM pg_constraint c
  JOIN pg_class child ON child.oid=c.conrelid
  JOIN LATERAL unnest(c.conkey,c.confkey) keys(child_col,parent_col) ON true
  JOIN pg_attribute ca ON ca.attrelid=child.oid AND ca.attnum=keys.child_col
  JOIN pg_attribute pa ON pa.attrelid=c.confrelid AND pa.attnum=keys.parent_col
  WHERE c.contype='f' AND c.confrelid='training_question_banks'::regclass
   AND child.relnamespace='public'::regnamespace AND pa.attname='id'`)).rows;
 for(const ref of refs)clauses.push(`NOT EXISTS(SELECT 1 FROM ${quote(ref.child)} history WHERE history.${quote(ref.column_name)}=${alias}.id)`);
 for(const [table,column] of [['training_definitions','draft'],['training_versions','document'],['training_courses','draft'],['training_course_versions','document'],['training_domain_events','payload']])if(tables.get(table)?.has(column))clauses.push(`NOT EXISTS(SELECT 1 FROM ${quote(table)} history WHERE history.${quote(column)}::text LIKE '%'||${alias}.id::text||'%')`);
 if(tables.get('training_domain_events')?.has('subject_id'))clauses.push(`NOT EXISTS(SELECT 1 FROM training_domain_events history WHERE history.subject_id=${alias}.id::text)`);
 return '('+clauses.join(' AND ')+')';
}

export async function privateTrainingDraftSQL(db,tables,{alias='d',user='$1',company='$2'}={}) {
 const required={training_definitions:['id','company_id','created_by','scope','latest_version','draft_revision'],
  training_versions:['definition_id'],training_assignments:['definition_id'],
  training_onboarding_policies:['definition_id'],training_recurrence_rules:['definition_id'],
  training_question_banks:['source_definition_id'],training_asset_refs:['definition_id','file_id','company_id','purpose','version_id','recipient_id','attempt_id'],
  training_audit_events:['definition_id','action','recipient_id']};
 if(Object.entries(required).some(([table,columns])=>columns.some(column=>!tables.get(table)?.has(column))))return 'false';
 const clauses=[`${alias}.company_id=${company}`,`${alias}.created_by=${user}`,`${alias}.scope='personal'`,`${alias}.latest_version=0`];
 const privateBank=await privateTrainingBankSQL(db,tables,{alias:'retained',user,company});
 const refs=(await db.query(`SELECT child.relname child,ca.attname column_name FROM pg_constraint c
  JOIN pg_class child ON child.oid=c.conrelid
  JOIN LATERAL unnest(c.conkey,c.confkey) keys(child_col,parent_col) ON true
  JOIN pg_attribute ca ON ca.attrelid=child.oid AND ca.attnum=keys.child_col
  JOIN pg_attribute pa ON pa.attrelid=c.confrelid AND pa.attnum=keys.parent_col
  WHERE c.contype='f' AND c.confrelid='training_definitions'::regclass
   AND child.relnamespace='public'::regnamespace AND pa.attname='id'`)).rows;
 for(const ref of refs)if(!['training_asset_refs','training_audit_events'].includes(ref.child)){
  clauses.push(`NOT EXISTS(SELECT 1 FROM ${quote(ref.child)} retained WHERE retained.${quote(ref.column_name)}=${alias}.id${ref.child==='training_question_banks'?` AND NOT (${privateBank})`:''})`);
 }
 // Keep explicit predicates even if a legacy schema lost a foreign key.
 for(const [table,column] of [['training_versions','definition_id'],['training_assignments','definition_id'],['training_onboarding_policies','definition_id'],['training_recurrence_rules','definition_id'],['training_question_banks','source_definition_id']]){
  clauses.push(`NOT EXISTS(SELECT 1 FROM ${quote(table)} retained WHERE retained.${quote(column)}=${alias}.id${table==='training_question_banks'?` AND NOT (${privateBank})`:''})`);
 }
 const actions=privateTrainingAuditActions.map(action=>`'${action}'`).join(',');
 clauses.push(`NOT EXISTS(SELECT 1 FROM training_audit_events history WHERE history.definition_id=${alias}.id AND (history.recipient_id IS NOT NULL OR history.action NOT IN (${actions})))`);
 clauses.push(`NOT EXISTS(SELECT 1 FROM training_asset_refs history WHERE history.definition_id=${alias}.id AND (history.company_id<>${alias}.company_id OR history.purpose<>'content' OR num_nonnulls(history.version_id,history.recipient_id,history.attempt_id)>0))`);
 // These references are JSON/polymorphic rather than definition foreign keys.
 // Conservative UUID matching also retains future document shapes we do not know.
 for(const [table,column] of [['training_courses','draft'],['training_course_versions','document'],['training_domain_events','payload']])if(tables.get(table)?.has(column)){
  clauses.push(`NOT EXISTS(SELECT 1 FROM ${quote(table)} history WHERE history.${quote(column)}::text LIKE '%'||${alias}.id::text||'%')`);
 }
 if(tables.get('training_domain_events')?.has('subject_id'))clauses.push(`NOT EXISTS(SELECT 1 FROM training_domain_events history WHERE history.subject_id=${alias}.id::text)`);
 return '('+clauses.join(' AND ')+')';
}
