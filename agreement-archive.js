import { QuoteContractError, quoteText } from './quote-contract-domain.js';
const choices={signing:['not_started','required_signers_pending','submitted'],decision:['published','changes_requested','declined','expired','superseded','revoked'],deposit:['not_required','locked','outstanding','processing','paid','adjusted_review_required'],booking:['not_offered','locked','eligible','booked'],plan:['agreement_pending','setup_pending','cancellation_pending','payment_conflict','base_review_required','active','past_due','paused','canceled','expired','failed']};

export async function installAgreementArchive({pool,service,startWorker=true}){
  await pool.query(`CREATE TABLE IF NOT EXISTS agreement_archive_index(
    agreement_id UUID PRIMARY KEY REFERENCES quote_agreements(id) ON DELETE RESTRICT,
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
    signing TEXT,decision TEXT,deposit TEXT,booking TEXT,plan TEXT,
    dirty BOOLEAN NOT NULL DEFAULT true,checked_at TIMESTAMPTZ
  );
  CREATE INDEX IF NOT EXISTS agreement_archive_company_status_idx ON agreement_archive_index(company_id,signing,decision,deposit,booking,plan);
  CREATE INDEX IF NOT EXISTS agreement_archive_dirty_idx ON agreement_archive_index(checked_at NULLS FIRST) WHERE dirty;
  INSERT INTO agreement_archive_index(agreement_id,company_id) SELECT id,company_id FROM quote_agreements ON CONFLICT DO NOTHING;
  CREATE OR REPLACE FUNCTION wolfcrm_agreement_archive_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
  BEGIN
    IF TG_TABLE_NAME='quote_agreements' THEN
      INSERT INTO agreement_archive_index(agreement_id,company_id,dirty) VALUES(NEW.id,NEW.company_id,true) ON CONFLICT(agreement_id) DO UPDATE SET dirty=true;
    ELSIF TG_TABLE_NAME='agreement_events' THEN
      UPDATE agreement_archive_index SET dirty=true WHERE agreement_id=NEW.agreement_id;
    ELSIF TG_TABLE_NAME='agreement_plan_enrollments' THEN
      UPDATE agreement_archive_index SET dirty=true WHERE agreement_id IN (NEW.base_agreement_id,NEW.plan_agreement_id);
    ELSIF TG_TABLE_NAME='service_plans' THEN
      UPDATE agreement_archive_index i SET dirty=true FROM agreement_plan_enrollments e WHERE e.service_plan_id=NEW.id AND i.agreement_id IN (e.base_agreement_id,e.plan_agreement_id);
    ELSIF TG_TABLE_NAME='payment_records' THEN
      UPDATE agreement_archive_index i SET dirty=true FROM quote_agreements a WHERE i.agreement_id=a.id AND a.company_id=NEW.company_id AND (a.id=NEW.agreement_id OR a.quote_id=NEW.quote_id OR a.quote_id IN (SELECT quote_id FROM schedule_events WHERE id=NEW.job_id AND company_id=NEW.company_id) OR a.id IN (SELECT base_agreement_id FROM agreement_plan_enrollments WHERE id=NEW.enrollment_id));
    ELSE
      UPDATE agreement_archive_index i SET dirty=true FROM quote_agreements a WHERE i.agreement_id=a.id AND a.company_id=COALESCE(NEW.company_id,OLD.company_id) AND a.quote_id=COALESCE(NEW.quote_id,OLD.quote_id);
    END IF;
    RETURN NULL;
  END $$;
  DROP TRIGGER IF EXISTS wolfcrm_agreement_archive_changed ON quote_agreements;
  CREATE TRIGGER wolfcrm_agreement_archive_changed AFTER INSERT OR UPDATE ON quote_agreements FOR EACH ROW EXECUTE FUNCTION wolfcrm_agreement_archive_dirty();
  DROP TRIGGER IF EXISTS wolfcrm_agreement_archive_event ON agreement_events;
  CREATE TRIGGER wolfcrm_agreement_archive_event AFTER INSERT ON agreement_events FOR EACH ROW EXECUTE FUNCTION wolfcrm_agreement_archive_dirty();
  DROP TRIGGER IF EXISTS wolfcrm_agreement_archive_payment ON payment_records;
  CREATE TRIGGER wolfcrm_agreement_archive_payment AFTER INSERT OR UPDATE ON payment_records FOR EACH ROW EXECUTE FUNCTION wolfcrm_agreement_archive_dirty();
  DROP TRIGGER IF EXISTS wolfcrm_agreement_archive_enrollment ON agreement_plan_enrollments;
  CREATE TRIGGER wolfcrm_agreement_archive_enrollment AFTER INSERT OR UPDATE ON agreement_plan_enrollments FOR EACH ROW EXECUTE FUNCTION wolfcrm_agreement_archive_dirty();
  DROP TRIGGER IF EXISTS wolfcrm_agreement_archive_membership ON service_plans;
  CREATE TRIGGER wolfcrm_agreement_archive_membership AFTER UPDATE OF status ON service_plans FOR EACH ROW EXECUTE FUNCTION wolfcrm_agreement_archive_dirty();
  DROP TRIGGER IF EXISTS wolfcrm_agreement_archive_schedule ON schedule_events;
  CREATE TRIGGER wolfcrm_agreement_archive_schedule AFTER INSERT OR UPDATE OR DELETE ON schedule_events FOR EACH ROW EXECUTE FUNCTION wolfcrm_agreement_archive_dirty();`);
  async function refresh(limit=100){
    let count=0;
    for(let n=0;n<limit;n++){
      const db=await pool.connect();
      try{
        await db.query('BEGIN');
        const row=(await db.query(`SELECT a.* FROM agreement_archive_index i JOIN quote_agreements a ON a.id=i.agreement_id WHERE i.dirty OR i.checked_at<now()-interval '5 minutes' ORDER BY i.checked_at NULLS FIRST FOR UPDATE OF i SKIP LOCKED LIMIT 1`)).rows[0];
        if(!row){await db.query('COMMIT');break;}
        const state=await service.state(db,row),plan=service.planSummary?await service.planSummary(db,row):null;
        await db.query('UPDATE agreement_archive_index SET signing=$2,decision=$3,deposit=$4,booking=$5,plan=$6,dirty=false,checked_at=now() WHERE agreement_id=$1',[row.id,state.signing,state.decision,state.deposit,state.booking,plan?.state||null]);
        await db.query('COMMIT');count++;
      }catch(error){await db.query('ROLLBACK');throw error;}finally{db.release();}
    }
    return count;
  }
  async function page(req){
    const query=req.query,values=[req.companyId],conditions=['a.company_id=$1'];
    const arg=value=>{values.push(value);return `$${values.length}`;};
    const integer=(raw,fallback,max)=>{const value=raw===undefined?fallback:Number(raw);if(!Number.isInteger(value)||value<0||value>max)throw new QuoteContractError('agreement_page_invalid','Use valid whole-number pagination.');return value;};
    const limit=Math.max(1,integer(query.limit,30,100)),offset=integer(query.offset,0,1000000);
    if(query.contact_id)conditions.push(`a.contact_id=${arg(String(query.contact_id))}`);
    if(query.quote_id)conditions.push(`a.quote_id::text=${arg(String(query.quote_id))}`);
    if(query.template_id)conditions.push(`a.snapshot->'template'->>'id'=${arg(String(query.template_id))}`);
    if(query.kind){if(!['quote','standalone','plan'].includes(query.kind))throw new QuoteContractError('agreement_filter_invalid','Choose quote, standalone or plan agreements.');conditions.push(`a.snapshot->>'kind'=${arg(query.kind)}`);}
    if(query.search){const search=arg(quoteText(query.search,'Search',200));conditions.push(`(a.title ILIKE '%'||${search}||'%' OR a.number ILIKE '%'||${search}||'%' OR a.snapshot->'customer'->>'name' ILIKE '%'||${search}||'%')`);}
    let dateTimezone=null;
    if(query.from_date||query.to_date){
      dateTimezone=(await pool.query('SELECT timezone FROM companies WHERE id=$1',[req.companyId])).rows[0]?.timezone||'America/New_York';
      try{new Intl.DateTimeFormat('en-US',{timeZone:dateTimezone}).format();}catch{dateTimezone='UTC';}
      if(query.from_date&&query.to_date&&query.from_date>query.to_date)throw new QuoteContractError('agreement_filter_invalid','The issue-date range ends before it starts.');
    }
    for(const [name,operator] of [['from_date','>='],['to_date','<']])if(query[name]){
      if(!/^\d{4}-\d{2}-\d{2}$/.test(query[name])||Number.isNaN(Date.parse(query[name]))||new Date(query[name]).toISOString().slice(0,10)!==query[name])throw new QuoteContractError('agreement_filter_invalid','Choose valid issue dates.');
      const date=arg(query[name]),zone=arg(dateTimezone);
      conditions.push(`a.created_at ${operator} ((${date}::date${name==='to_date'?"+interval '1 day'":''})::timestamp AT TIME ZONE ${zone})`);
    }
    for(const [field,allowed] of Object.entries(choices))if(query[field]){if(!allowed.includes(query[field]))throw new QuoteContractError('agreement_filter_invalid',`Choose a supported ${field} state.`);conditions.push(`i.${field}=${arg(query[field])}`);}
    if(query.unresolved==='true')conditions.push(`EXISTS(SELECT 1 FROM business_exceptions x WHERE x.company_id=a.company_id AND x.source_type='agreement' AND x.metadata->>'agreement_id'=a.id::text AND x.status IN ('open','snoozed'))`);
    const where=conditions.join(' AND '),joins='FROM quote_agreements a LEFT JOIN agreement_archive_index i ON i.agreement_id=a.id';
    const total=Number((await pool.query(`SELECT count(*)::integer AS n ${joins} WHERE ${where}`,values)).rows[0].n);
    const rows=(await pool.query(`SELECT a.*,i.checked_at AS indexed_at,i.dirty AS status_pending ${joins} WHERE ${where} ORDER BY a.created_at DESC,a.id LIMIT ${arg(limit)} OFFSET ${arg(offset)}`,values)).rows;
    const agreements=[];
    // Bound concurrent DB work. Details always use live authoritative states;
    // status filtering uses the worker-maintained read index, never billing truth.
    for(let start=0;start<rows.length;start+=5)agreements.push(...await Promise.all(rows.slice(start,start+5).map(async row=>({...await service.detail(pool,row,{staff:true}),status_indexed_at:row.indexed_at,status_refresh_pending:!!row.status_pending}))));
    return {agreements,total,limit,offset,status_filter_refresh_seconds:5,date_filter_timezone:dateTimezone};
  }
  service.archivePage=page;
  let running=false,timer;
  if(startWorker){timer=setInterval(async()=>{if(running)return;running=true;try{await refresh();}catch{console.error('[agreements] archive index refresh pending');}finally{running=false;}},5000);timer.unref();}
  return {refresh,page,stop:()=>clearInterval(timer)};
}
