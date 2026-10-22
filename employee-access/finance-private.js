// Reviewed personal Finance records. New tables fail closed until their
// ownership/history contract is reviewed; this is deliberately not a prefix list.
const personalTables=new Set([
 'finance_accounts','finance_account_entries','finance_settings',
 'finance_planned_items','finance_debts','finance_debt_payments','finance_budgets','finance_goals','finance_goal_contributions',
 'finance_ai_conversations','finance_ai_messages','finance_ai_actions','finance_ai_action_proposals','finance_ai_memories',
 'finance_plaid_items','finance_plaid_item_events','finance_plaid_recurring_streams','finance_recurring_candidates','finance_recurring_candidate_transactions',
 'finance_transactions','finance_transaction_provider_refs','finance_transaction_splits','finance_transaction_audit',
 'finance_receipts','finance_receipt_matches','finance_receipt_detail_audit','finance_receipt_lifecycle_audit',
 'finance_chart_accounts','finance_account_chart_mappings','finance_account_chart_mapping_audit',
 'finance_bank_transaction_postings','finance_bank_transaction_posting_audit',
 'finance_transfer_pairs','finance_transfer_pair_members','finance_transfer_pair_audit',
 'finance_journal_entries','finance_journal_lines','finance_journal_audit',
 'finance_statement_coverage_profiles','finance_statement_coverage_audit','finance_statement_period_closes','finance_statement_period_close_audit',
 'finance_balance_sheet_rule_profiles','finance_balance_sheet_rule_audit',
]);
const personalTools=new Set(['finance_ai_conversations','finance_ai_messages','finance_ai_actions','finance_ai_action_proposals','finance_ai_memories',
 'finance_planned_items','finance_debts','finance_debt_payments','finance_budgets','finance_goals','finance_goal_contributions']);
const companyJournal=record=>['finance_operational_source','finance_operational_application','finance_payroll_evaluation','finance_stripe_settlement'].includes(record.source_type)
 ||['job_receivable','payment_application','refund_application','customer_credit_application','payroll_recognition','stripe_settlement'].includes(record.entry_kind);
const quote=value=>'"'+value.replaceAll('"','""')+'"';
const uuidPattern='[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
const maxRows=50000;
const review=()=>Object.assign(new Error('This Finance evidence graph requires a separate retention review. No private records were deleted.'),{status:409,code:'finance_retention_review_required'});
export const financeHistoryTable=table=>!personalTables.has(table);

// Used only by deliberate deletion preview/execute, never by a storage screen.
// The caller holds the company lifecycle lock; all request/provider writers use
// the same boundary. Unknown relationships cause retention, not a cascade.
export async function privateFinancePlan(db,tables,target){
 if(!tables.has('finance_spaces'))return {spaces:[],retainedSpaces:0,operations:[],receiptIDs:[],retainedReceiptIDs:[],mixedPrivateRecords:0};
 const allSpaces=(await db.query("SELECT id,revision,includes_company_activity FROM finance_spaces WHERE owner_id=$1 AND company_id=$2 AND audience='private' ORDER BY id",[target.id,target.company_id])).rows;
 const candidateSpaces=allSpaces.filter(s=>!s.includes_company_activity),spaceIDs=candidateSpaces.map(s=>s.id);
 const financeTables=[...tables].filter(([name,columns])=>name.startsWith('finance_')&&columns.has('finance_space_id')).map(([name])=>name).sort();
 const nodes=new Map(),byID=new Map(),byTable=new Map(),retained=new Set(),edges=new Map(),retainedSpaceIDs=new Set();
 let referenceCount=0;
 const key=(table,id)=>table+':'+id;
 const retain=k=>{if(nodes.has(k))retained.add(k);};
 const connect=(a,b)=>{if(a===b)return;if(!edges.has(a))edges.set(a,new Set());if(!edges.has(b))edges.set(b,new Set());edges.get(a).add(b);edges.get(b).add(a);};
 for(const table of financeTables){
  if(!tables.get(table).has('id'))throw review();
  const fields=['id','finance_space_id','company_id','owner_user_id','created_by','memory_scope','source_type','entry_kind'].map(name=>`'${name}',${tables.get(table).has(name)?'t.'+quote(name):'NULL'}`).join(',');
  const rows=(await db.query(`SELECT jsonb_build_object(${fields},'references',ARRAY(SELECT DISTINCT lower(m[1]) FROM regexp_matches(to_jsonb(t)::text,'${uuidPattern}','g') m)) AS record FROM ${quote(table)} t WHERE finance_space_id=ANY($1::uuid[]) ORDER BY id LIMIT $2`,[spaceIDs,maxRows+1-nodes.size])).rows;
  for(const {record} of rows){
   const k=key(table,record.id);referenceCount+=record.references.length;if(nodes.has(k)||nodes.size>=maxRows||referenceCount>250000)throw review();
   nodes.set(k,{table,record});if(!byID.has(record.id))byID.set(record.id,[]);byID.get(record.id).push(k);
   if(!byTable.has(table))byTable.set(table,[]);byTable.get(table).push(record.id);
   if(!personalTables.has(table)||record.company_id!==target.company_id
    ||(table==='finance_ai_memories'&&record.memory_scope!=='user')
    ||(table==='finance_journal_entries'&&companyJournal(record))
    ||(['finance_ai_memories','finance_ai_conversations','finance_ai_action_proposals'].includes(table)&&(record.owner_user_id||record.created_by)!==target.id))retained.add(k);
  }
 }
 // Statement close fingerprints summarize a whole ledger, not just UUID links.
 // If company history participated in that ledger, keep its accounting sources
 // intact. A wholly personal statement remains eligible for normal deletion.
 const closedSpaces=new Set([...nodes.values()].filter(({table})=>table==='finance_statement_period_closes').map(n=>n.record.finance_space_id));
 const financialRowsBySpace=new Map();for(const [k,{table,record}] of nodes)if(!personalTools.has(table)){
  if(!financialRowsBySpace.has(record.finance_space_id))financialRowsBySpace.set(record.finance_space_id,[]);
  financialRowsBySpace.get(record.finance_space_id).push(k);
 }
 // JSON snapshots and polymorphic source IDs are real relations too. Matching
 // UUIDs conservatively also retains text mentions rather than losing evidence.
 const outsideReferences=new Map();
 for(const [k,{record}] of nodes)for(const id of record.references){
  if(byID.has(id)){for(const other of byID.get(id))connect(k,other);}
  else {if(!outsideReferences.has(id))outsideReferences.set(id,new Set());outsideReferences.get(id).add(k);}
 }
 // Finance records in shared/other-owner/unknown spaces can refer to these rows
 // without FKs. Return only matched identities, never their private contents.
 const candidateIDs=[...byID.keys()];
 if(candidateIDs.length)for(const table of financeTables){
  const rows=(await db.query(`SELECT DISTINCT lower(m[1]) AS id FROM ${quote(table)} t CROSS JOIN LATERAL regexp_matches(to_jsonb(t)::text,'${uuidPattern}','g') m
   WHERE (t.finance_space_id IS NULL OR NOT(t.finance_space_id=ANY($1::uuid[])))
   AND ${tables.get(table).has('company_id')?'(t.company_id=$2 OR t.company_id IS NULL)':'$2::uuid IS NOT NULL'} AND lower(m[1])=ANY($3::text[])`,[spaceIDs,target.company_id,candidateIDs])).rows;
  for(const r of rows)for(const k of byID.get(r.id)||[])retain(k);
  // A private journal/proposal can point OUT to retained/shared evidence using
  // a soft UUID too. Follow that direction without reading the target payload.
  if(outsideReferences.size)for(const r of (await db.query(`SELECT id::text FROM ${quote(table)} WHERE id=ANY($1::uuid[])`,[[...outsideReferences.keys()]])).rows)for(const k of outsideReferences.get(r.id)||[])retain(k);
 }
 // Inspect complete constraints, including composite and non-ID unique keys.
 // External references are retained regardless of their ON DELETE behavior or
 // company, so a future CASCADE/SET NULL relation cannot erase company history.
 const links=(await db.query(`SELECT c.oid,child.relname child,parent.relname parent,
  array_agg(ca.attname::text ORDER BY k.ord) child_keys,array_agg(pa.attname::text ORDER BY k.ord) parent_keys
  FROM pg_constraint c JOIN pg_class child ON child.oid=c.conrelid JOIN pg_class parent ON parent.oid=c.confrelid
  JOIN LATERAL unnest(c.conkey,c.confkey) WITH ORDINALITY k(a,b,ord) ON true
  JOIN pg_attribute ca ON ca.attrelid=child.oid AND ca.attnum=k.a JOIN pg_attribute pa ON pa.attrelid=parent.oid AND pa.attnum=k.b
  WHERE c.contype='f' AND child.relnamespace='public'::regnamespace AND parent.relnamespace='public'::regnamespace
  AND (child.relname=ANY($1::text[]) OR parent.relname=ANY($1::text[]) OR parent.relname='finance_spaces')
  GROUP BY c.oid,child.relname,parent.relname ORDER BY c.oid`,[financeTables])).rows;
 for(const link of links){
  const childFinance=financeTables.includes(link.child),parentFinance=financeTables.includes(link.parent);
  if(['users','companies'].includes(link.parent))continue; // retained attribution, not owned payload
  const join=link.child_keys.map((column,i)=>`c.${quote(column)}=p.${quote(link.parent_keys[i])}`).join(' AND ');
  if(link.parent==='finance_spaces'){
   if(childFinance||['finance_space_audit','finance_space_members'].includes(link.child))continue;
   for(const row of (await db.query(`SELECT DISTINCT p.id FROM ${quote(link.child)} c JOIN finance_spaces p ON ${join} WHERE p.id=ANY($1::uuid[])`,[spaceIDs])).rows)retainedSpaceIDs.add(row.id);
   continue;
  }
  const scopes=[];if(childFinance)scopes.push('c.finance_space_id=ANY($1::uuid[])');if(parentFinance)scopes.push('p.finance_space_id=ANY($1::uuid[])');
  const rows=(await db.query(`SELECT DISTINCT ${childFinance?'c.id::text':'NULL::text'} child_id,${parentFinance?'p.id::text':'NULL::text'} parent_id
   FROM ${quote(link.child)} c JOIN ${quote(link.parent)} p ON ${join} WHERE ${scopes.join(' OR ')}`,[spaceIDs])).rows;
  for(const r of rows){const c=key(link.child,r.child_id),p=key(link.parent,r.parent_id);
   if(nodes.has(c)&&nodes.has(p))connect(c,p);else if(nodes.has(c))retain(c);else if(nodes.has(p))retain(p);
  }
 }
 // An unknown domain that holds the space itself can depend on all its content.
 for(const [k,{record}] of nodes)if(retainedSpaceIDs.has(record.finance_space_id))retain(k);
 const expandedCloses=new Set(),queue=[...retained];
 const enqueue=k=>{if(!retained.has(k)){retained.add(k);queue.push(k);}};
 for(let i=0;i<queue.length;i++){
  const {table,record}=nodes.get(queue[i]),space=record.finance_space_id;
  if(closedSpaces.has(space)&&!personalTools.has(table)&&!expandedCloses.has(space)){
   expandedCloses.add(space);for(const k of financialRowsBySpace.get(space)||[])enqueue(k);
  }
  for(const adjacent of edges.get(queue[i])||[])enqueue(adjacent);
 }
 for(const k of retained)retainedSpaceIDs.add(nodes.get(k).record.finance_space_id);
 const spaces=candidateSpaces.filter(s=>!retainedSpaceIDs.has(s.id)).map(({id,revision})=>({id,revision}));
 const operations=[];let mixedPrivateRecords=0;const receiptIDs=[],retainedReceiptIDs=[];
 for(const table of financeTables){const ids=[];for(const id of byTable.get(table)||[]){const k=key(table,id);if(retained.has(k))continue;ids.push(id);if(retainedSpaceIDs.has(nodes.get(k).record.finance_space_id))mixedPrivateRecords++;}
  if(ids.length)operations.push({table,where:'id=ANY($1::uuid[])',values:[ids]});if(table==='finance_receipts'){receiptIDs.push(...ids);retainedReceiptIDs.push(...(byTable.get(table)||[]).filter(id=>retained.has(key(table,id))));}
 }
 return {spaces,retainedSpaces:allSpaces.length-spaces.length,operations,receiptIDs,retainedReceiptIDs,mixedPrivateRecords};
}
