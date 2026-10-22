// Operational evidence remains read-only to the finance request role. Only
// scoped row locking crosses the role boundary; callers read through normal RLS.
export async function installFinanceSourceLocks(db) {
  // Legs inherit company ownership from their daily log (they have no
  // company_id column). Match the parent's existing Business-space visibility;
  // never grant writes or make operational evidence visible in Personal.
  await db.query(`ALTER TABLE public.mileage_legs ENABLE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS wolf_finance_company_source ON public.mileage_legs;
    CREATE POLICY wolf_finance_company_source ON public.mileage_legs AS RESTRICTIVE TO wolf_finance_request
      USING ((SELECT public.wolf_finance_company_activity()) AND EXISTS (
        SELECT 1 FROM public.mileage_daily_logs parent WHERE parent.id=mileage_legs.log_id
          AND parent.company_id=nullif(current_setting('wolf.finance_company',true),'')::uuid))
      WITH CHECK ((SELECT public.wolf_finance_company_activity()) AND EXISTS (
        SELECT 1 FROM public.mileage_daily_logs parent WHERE parent.id=mileage_legs.log_id
          AND parent.company_id=nullif(current_setting('wolf.finance_company',true),'')::uuid));
    DROP POLICY IF EXISTS wolf_finance_request_access ON public.mileage_legs;
    CREATE POLICY wolf_finance_request_access ON public.mileage_legs TO wolf_finance_request USING(true) WITH CHECK(true);`);
  await db.query(`CREATE OR REPLACE FUNCTION public.wolf_finance_lock_source(
    source_kind text, expected_company uuid, source_ids text[])
    RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
    DECLARE actor_id uuid; scope_company uuid; company_activity boolean;
    BEGIN
      actor_id := nullif(current_setting('wolf.finance_actor', true), '')::uuid;
      scope_company := nullif(current_setting('wolf.finance_company', true), '')::uuid;
      IF actor_id IS NULL OR scope_company IS NULL OR expected_company IS DISTINCT FROM scope_company
        OR NOT EXISTS(SELECT 1 FROM public.users u WHERE id=actor_id AND company_id=scope_company AND deleted_at IS NULL AND (to_jsonb(u)->>'locked_at') IS NULL)
      THEN RAISE EXCEPTION 'finance_source_lock_scope_invalid' USING ERRCODE='42501'; END IF;
      IF source_ids IS NULL OR cardinality(source_ids)>1000 THEN
        RAISE EXCEPTION 'finance_source_lock_ids_invalid' USING ERRCODE='22023'; END IF;
      IF cardinality(public.wolf_finance_visible_spaces())=0 THEN RETURN; END IF;
      company_activity := public.wolf_finance_company_activity();
      CASE source_kind
        WHEN 'time_clock_entries' THEN
          PERFORM id FROM public.time_clock_entries WHERE company_id=scope_company
            AND company_activity AND id::text=ANY(source_ids) ORDER BY id FOR UPDATE;
        WHEN 'mileage_daily_logs' THEN
          PERFORM id FROM public.mileage_daily_logs WHERE company_id=scope_company
            AND company_activity AND id::text=ANY(source_ids) ORDER BY id FOR UPDATE;
        WHEN 'employee_pay_structures' THEN
          PERFORM id FROM public.employee_pay_structures WHERE company_id=scope_company
            AND company_activity AND id::text=ANY(source_ids) ORDER BY id FOR UPDATE;
        WHEN 'users' THEN
          PERFORM id FROM public.users WHERE company_id=scope_company
            AND id::text=ANY(source_ids) ORDER BY id FOR UPDATE;
        ELSE RAISE EXCEPTION 'finance_source_lock_kind_invalid' USING ERRCODE='22023';
      END CASE;
    END $$;
    REVOKE ALL ON FUNCTION public.wolf_finance_lock_source(text,uuid,text[]) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION public.wolf_finance_lock_source(text,uuid,text[]) TO wolf_finance_request;`);
}

export async function lockFinanceSourceRows(client, sourceKind, companyId, ids) {
  if (ids.length) await client.query('SELECT public.wolf_finance_lock_source($1,$2,$3::text[])', [sourceKind, companyId, ids.map(String)]);
}
