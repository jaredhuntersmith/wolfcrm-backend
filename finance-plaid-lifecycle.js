import {accountDenial} from './employee-access/auth.js';

// Service-pool background work has no authenticated request actor. Only a
// private space follows its owner's lifecycle; shared company evidence remains
// live. Call after BEGIN and before domain locks, never around provider I/O.
export async function lockPlaidBackgroundItem(db, expected) {
 const company=await db.query('SELECT id FROM companies WHERE id=$1 FOR KEY SHARE',[expected.company_id]);
 if(!company.rowCount)return {reason:'company_unavailable'};
 if(!expected.finance_space_id)return {reason:'space_unassigned'};
 const space=(await db.query('SELECT * FROM finance_spaces WHERE id=$1 AND company_id=$2 FOR KEY SHARE',[expected.finance_space_id,expected.company_id])).rows[0];
 if(!space)return {reason:'space_unavailable'};
 if(space.audience==='private') {
  const owner=(await db.query('SELECT * FROM users WHERE id=$1 AND company_id=$2',[space.owner_id,space.company_id])).rows[0];
  if(!owner)return {reason:'owner_unavailable'};
  const denial=accountDenial(owner);
  if(denial)return {reason:denial.error};
 }
 const item=(await db.query('SELECT * FROM finance_plaid_items WHERE id=$1 AND company_id=$2 AND finance_space_id=$3 FOR UPDATE',[expected.id,expected.company_id,space.id])).rows[0];
 if(!item)return {reason:'item_unavailable_or_moved'};
 if(item.status==='disconnected'||item.disconnected_at)return {reason:'disconnected'};
 await db.query("SELECT set_config('wolf.finance_space',$1,true)",[space.id]);
 return {item};
}

export async function withPlaidBackgroundItem(pool,item,work) {
 const db=await pool.connect();
 try {
  await db.query('BEGIN');
  const current=await lockPlaidBackgroundItem(db,item);
  if(!current.item){await db.query('ROLLBACK');return {skipped:true,reason:current.reason};}
  const value=await work(db,current.item);
  await db.query('COMMIT');
  return {skipped:false,value};
 }catch(error){await db.query('ROLLBACK').catch(()=>{});throw error;}
 finally{db.release();}
}
