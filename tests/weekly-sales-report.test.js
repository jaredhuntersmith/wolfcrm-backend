import test from 'node:test';
import assert from 'node:assert/strict';
import {buildWeeklySalesReport,tierCommissionCents} from '../weekly-sales-report.js';

test('weekly sales allocates odd cents exactly and uses effective commission tiers',()=>{
  const owner='00000000-0000-4000-8000-000000000001',other='00000000-0000-4000-8000-000000000002';
  const range={start:new Date('2026-10-18T00:00:00Z'),end:new Date('2026-10-25T00:00:00Z')};
  const rows=[
    {id:'a',title:'Prior start, completed now',start:'2026-10-15T10:00:00Z',finished_at:'2026-10-20T10:00:00Z',finished_company_date:'2026-10-20',price_cents:101,sales_user_ids:[owner,other],created_by:other},
    {id:'b',title:'Same person in both roles',start:'2026-10-20T10:00:00Z',finished_at:'2026-10-21T10:00:00Z',finished_company_date:'2026-10-21',price_cents:10000,sales_user_ids:[owner],worker_user_ids:[owner],created_by:other}
  ];
  const payStructures=[{effective_from:'2026-10-01',effective_to:'2026-10-20',commission_tiers:[{threshold_cents:0,percent_basis_points:1000}]},{effective_from:'2026-10-21',effective_to:null,commission_tiers:[{threshold_cents:0,percent_basis_points:2000}]}];
  const report=buildWeeklySalesReport({rows,userID:owner,payStructures,range,employeeName:'Owner'});
  assert.equal(report.period_basis,'finished_at');
  assert.equal(report.employee_name,'Owner');
  assert.equal(report.total_revenue_cents,10051);
  assert.deepEqual(report.jobs.map(job=>job.credited_revenue_cents),[10000,51]);
  assert.deepEqual(report.jobs.map(job=>job.commission_cents),[2000,5]);
  assert.equal(report.total_commission_cents,2005);
  const otherReport=buildWeeklySalesReport({rows:[rows[0]],userID:other,payStructures,range});
  assert.equal(otherReport.jobs[0].credited_revenue_cents,50);
  assert.equal(report.jobs[0].attribution_source,'selected_salesperson');
});

test('missing revenue or historical pay remains unknown',()=>{
  const userID='00000000-0000-4000-8000-000000000001';
  const range={start:new Date('2026-10-18T00:00:00Z'),end:new Date('2026-10-25T00:00:00Z')};
  const rows=[{id:'a',finished_at:'2026-10-20T10:00:00Z',finished_company_date:'2026-10-20',price_cents:null,sales_user_ids:[],created_by:userID},
    {id:'b',finished_at:'2026-10-21T10:00:00Z',finished_company_date:'2026-10-21',price_cents:10000,sales_user_ids:[userID],created_by:userID}];
  const report=buildWeeklySalesReport({rows,userID,payStructures:[],range});
  assert.equal(report.total_revenue_cents,null);
  assert.equal(report.known_revenue_cents,10000);
  assert.equal(report.revenue_coverage,'partial');
  assert.equal(report.total_commission_cents,null);
  assert.equal(report.commission_coverage,'partial');
  assert.equal(report.jobs.find(job=>job.id==='a').attribution_source,'legacy_creator');
  assert.equal(tierCommissionCents(10000,[{threshold_cents:0,percent_basis_points:1000}]),1000);
});
