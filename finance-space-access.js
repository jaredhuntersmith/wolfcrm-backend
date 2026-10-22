import {accountDenial} from './employee-access/auth.js';

// Finance caller SQL never needs service-role privileges. This fixed-scope
// bridge locks only the company/user in the existing request GUCs and returns
// lifecycle flags, never user content or credentials.
export async function installFinanceTransactionAccess(db) {
 await db.query(`CREATE OR REPLACE FUNCTION public.wolf_finance_transaction_actor()
  RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
  DECLARE actor_id uuid; scope_company uuid; actor jsonb; read_only boolean;
  BEGIN
   actor_id:=nullif(current_setting('wolf.finance_actor',true),'')::uuid;
   scope_company:=nullif(current_setting('wolf.finance_company',true),'')::uuid;
   IF actor_id IS NULL OR scope_company IS NULL THEN RETURN NULL; END IF;
   read_only:=current_setting('transaction_read_only')='on';
   IF read_only THEN
    PERFORM id FROM public.companies WHERE id=scope_company;
   ELSE
    PERFORM id FROM public.companies WHERE id=scope_company FOR KEY SHARE;
   END IF;
   IF NOT FOUND THEN RETURN NULL; END IF;
   IF read_only THEN
    SELECT jsonb_build_object('locked_at',to_jsonb(u)->'locked_at','deleted_at',u.deleted_at)
     INTO actor FROM public.users u WHERE id=actor_id AND company_id=scope_company;
   ELSE
    SELECT jsonb_build_object('locked_at',to_jsonb(u)->'locked_at','deleted_at',u.deleted_at)
     INTO actor FROM public.users u WHERE id=actor_id AND company_id=scope_company FOR KEY SHARE;
   END IF;
   RETURN actor;
  END $$;
  REVOKE ALL ON FUNCTION public.wolf_finance_transaction_actor() FROM PUBLIC;
  GRANT EXECUTE ON FUNCTION public.wolf_finance_transaction_actor() TO wolf_finance_request;`);
}

export async function checkFinanceTransactionActor(db) {
 const actor=(await db.query('SELECT public.wolf_finance_transaction_actor() AS actor')).rows[0]?.actor;
 if(!actor)throw Object.assign(new Error('Company membership changed. Sign in again.'),{status:403});
 const denial=accountDenial(actor);
 if(denial)throw Object.assign(new Error(denial.message),{status:401,code:denial.error});
}

// Call inside the caller's transaction, before user, space, or domain locks.
// Account lifecycle takes company FOR UPDATE first; ordinary space operations
// share the company boundary and recheck membership after any lifecycle wait.
export async function lockFinanceSpaceActor(db,userId,companyId,{exclusiveCompany=false}={}) {
 const company=await db.query(`SELECT id FROM companies WHERE id=$1 FOR ${exclusiveCompany?'UPDATE':'KEY SHARE'}`,[companyId]);
 if(!company.rowCount)throw Object.assign(new Error('Company membership required.'),{status:403});
 const actor=(await db.query('SELECT * FROM users WHERE id=$1 AND company_id=$2',[userId,companyId])).rows[0];
 if(!actor)throw Object.assign(new Error('Company membership changed. Sign in again.'),{status:403});
 const denial=accountDenial(actor);
 if(denial)throw Object.assign(new Error(denial.message),{status:401,code:denial.error});
 return actor;
}
