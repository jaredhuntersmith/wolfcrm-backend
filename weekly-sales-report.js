function dateOnly(value) {
  if (value instanceof Date) return value.toISOString().slice(0,10);
  return String(value || '').slice(0,10);
}

function creditedShare(cents, ids, userID) {
  if (!Number.isSafeInteger(cents) || cents < 0 || !ids.length) return null;
  const index=ids.indexOf(userID);
  if (index < 0) return null;
  return Math.floor(cents/ids.length)+(index < cents%ids.length ? 1 : 0);
}

export function tierCommissionCents(revenueCents, tiers) {
  if (!Number.isSafeInteger(revenueCents) || revenueCents < 0 || !Array.isArray(tiers)) return null;
  if (!tiers.length || revenueCents === 0) return 0;
  const ordered=[...tiers].sort((a,b)=>Number(a.threshold_cents)-Number(b.threshold_cents));
  if (Number(ordered[0].threshold_cents)!==0) return null;
  let earned=0;
  for (let index=0;index<ordered.length;index++) {
    const start=Number(ordered[index].threshold_cents);
    const end=index+1<ordered.length?Number(ordered[index+1].threshold_cents):revenueCents;
    const basisPoints=Number(ordered[index].percent_basis_points);
    if (![start,end,basisPoints].every(Number.isSafeInteger)||start<0||end<start||basisPoints<0||basisPoints>10000) return null;
    earned+=Math.max(0,Math.min(revenueCents,end)-start)*basisPoints/10000;
  }
  const rounded=Math.round(earned);
  return Number.isSafeInteger(rounded)?rounded:null;
}

function effectivePay(rows, date) {
  const matches=rows.filter(row=>dateOnly(row.effective_from)<=date &&
    (!row.effective_to || dateOnly(row.effective_to)>=date));
  return matches.length===1?matches[0]:null;
}

export function buildWeeklySalesReport({rows,userID,payStructures=[],range,employeeName=null}) {
  const chronological=[...rows].sort((a,b)=>new Date(a.finished_at)-new Date(b.finished_at)||String(a.id).localeCompare(String(b.id)));
  let cumulativeRevenue=0,knownRevenue=0,knownCommission=0,unknownRevenue=0,unknownCommission=0;
  const jobs=chronological.map(row=>{
    const explicit=Array.isArray(row.sales_user_ids)?[...new Set(row.sales_user_ids.filter(id=>typeof id==='string'))]:[];
    const ids=explicit.length?explicit:(row.created_by?[row.created_by]:[]);
    const price=row.price_cents==null?null:Number(row.price_cents);
    const credit=creditedShare(price,ids,userID);
    const pay=effectivePay(payStructures,row.finished_company_date);
    const before=unknownRevenue?null:cumulativeRevenue;
    const after=before==null||credit==null?null:before+credit;
    const beforeCommission=pay&&before!=null?tierCommissionCents(before,pay.commission_tiers):null;
    const afterCommission=pay&&after!=null?tierCommissionCents(after,pay.commission_tiers):null;
    const commission=beforeCommission==null||afterCommission==null?null:afterCommission-beforeCommission;
    if (credit==null) unknownRevenue++; else { knownRevenue+=credit;cumulativeRevenue+=credit; }
    if (commission==null) unknownCommission++; else knownCommission+=commission;
    return {
      ...row,
      credited_revenue_cents:credit,
      commission_cents:commission,
      commission_source:credit==null?'revenue_missing':before==null?'prior_revenue_missing':pay?'effective_pay_structure':'pay_structure_missing',
      attribution_source:explicit.length?'selected_salesperson':'legacy_creator',
      material_cost_source:row.material_cost_cents!=null?'actual_or_legacy':row.quote_material_estimate_cents!=null?'quote_estimate':'unknown'
    };
  }).reverse();
  return {
    user_id:userID,
    employee_name:employeeName,
    start:range.start.toISOString(),
    end:range.end.toISOString(),
    period_basis:'finished_at',
    total_revenue_cents:unknownRevenue?null:knownRevenue,
    known_revenue_cents:knownRevenue,
    revenue_coverage:unknownRevenue?'partial':'complete',
    total_commission_cents:unknownCommission?null:knownCommission,
    known_commission_cents:knownCommission,
    commission_coverage:unknownCommission?'partial':'complete',
    jobs
  };
}
