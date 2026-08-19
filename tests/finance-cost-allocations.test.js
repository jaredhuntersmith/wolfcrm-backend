import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  CostAllocationError,
  installFinanceCostAllocationRoutes,
  installFinanceCostAllocationSchema,
  parseTimeAllocationRange,
  planTimeJobLinkUpdate,
  timeEntryAllocationSnapshot,
  timeLinkMatchesSnapshot
} from "../finance-cost-allocations.js";

const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

function completedEntry(overrides = {}) {
  return {
    id: "entry_1",
    user_id: "employee_1",
    start_at: "2026-08-19T13:00:00.000Z",
    end_at: "2026-08-19T17:30:00.000Z",
    break_seconds: 1_800,
    manual_status: "approved",
    ...overrides
  };
}

function existingLink(overrides = {}) {
  return {
    id: "link_1",
    time_entry_id: "entry_1",
    employee_id: "employee_1",
    job_id: "job_1",
    source_start_at: "2026-08-19T13:00:00.000Z",
    source_end_at: "2026-08-19T17:30:00.000Z",
    source_break_seconds: 1_800,
    source_work_seconds: 14_400,
    version: 3,
    ...overrides
  };
}

test("completed time snapshots preserve exact source evidence", () => {
  const snapshot = timeEntryAllocationSnapshot(completedEntry());
  assert.deepEqual(snapshot, {
    employee_id: "employee_1",
    source_start_at: "2026-08-19T13:00:00.000Z",
    source_end_at: "2026-08-19T17:30:00.000Z",
    source_break_seconds: 1_800,
    source_work_seconds: 14_400
  });
  assert.equal(timeLinkMatchesSnapshot(existingLink(), snapshot), true);
  assert.equal(timeLinkMatchesSnapshot(existingLink({ source_break_seconds: 900 }), snapshot), false);
});

test("open, disapproved, and invalid durations fail closed", () => {
  assert.throws(
    () => timeEntryAllocationSnapshot(completedEntry({ end_at: null })),
    (error) => error.code === "time_entry_open" && error.statusCode === 409
  );
  assert.throws(
    () => timeEntryAllocationSnapshot(completedEntry({ manual_status: "disapproved" })),
    (error) => error.code === "time_entry_disapproved"
  );
  assert.throws(
    () => timeEntryAllocationSnapshot(completedEntry({ break_seconds: 16_200 })),
    (error) => error.code === "time_entry_duration_invalid"
  );
  assert.throws(
    () => timeEntryAllocationSnapshot(completedEntry({ break_seconds: 1.5 })),
    (error) => error.code === "break_seconds_invalid"
  );
});

test("time links create, replay, relink, unlink, and refresh stale evidence", () => {
  const create = planTimeJobLinkUpdate({
    body: { expected_version: 0, job_id: "job_1", reason: "Reviewed against dispatch" },
    entry: completedEntry(),
    job: { id: "job_1" }
  });
  assert.equal(create.mode, "create");
  assert.equal(create.action, "time_job_linked");

  const replay = planTimeJobLinkUpdate({
    body: { expected_version: 3, job_id: "job_1", reason: "Retry" },
    entry: completedEntry(), currentLink: existingLink(), job: { id: "job_1" }
  });
  assert.equal(replay.mode, "replay");

  const relink = planTimeJobLinkUpdate({
    body: { expected_version: 3, job_id: "job_2", reason: "Corrected job" },
    entry: completedEntry(), currentLink: existingLink(), job: { id: "job_2" }
  });
  assert.equal(relink.mode, "update");
  assert.equal(relink.action, "time_job_relinked");

  const unlink = planTimeJobLinkUpdate({
    body: { expected_version: 3, job_id: null, reason: "Shift spans jobs" },
    entry: completedEntry(), currentLink: existingLink()
  });
  assert.equal(unlink.action, "time_job_unlinked");

  const invalidSourceUnlink = planTimeJobLinkUpdate({
    body: { expected_version: 3, job_id: null, reason: "Remove before correcting source" },
    entry: completedEntry({ end_at: null }), currentLink: existingLink()
  });
  assert.equal(invalidSourceUnlink.action, "time_job_unlinked");
  assert.equal(invalidSourceUnlink.snapshot.source_work_seconds, 14_400);

  const refresh = planTimeJobLinkUpdate({
    body: { expected_version: 3, job_id: "job_1", reason: "Reviewed corrected break" },
    entry: completedEntry({ break_seconds: 900 }), currentLink: existingLink(), job: { id: "job_1" }
  });
  assert.equal(refresh.action, "time_job_link_refreshed");
  assert.equal(refresh.snapshot.source_work_seconds, 15_300);
});

test("time link updates require exact versions, reasons, and company jobs", () => {
  assert.throws(
    () => planTimeJobLinkUpdate({
      body: { expected_version: 2, job_id: "job_1", reason: "Review" },
      entry: completedEntry(), currentLink: existingLink(), job: { id: "job_1" }
    }),
    (error) => error.code === "time_job_link_stale" && error.current_version === 3
  );
  assert.throws(
    () => planTimeJobLinkUpdate({
      body: { expected_version: 3, job_id: null, reason: " " },
      entry: completedEntry(), currentLink: existingLink()
    }),
    (error) => error.code === "time_job_link_reason_required"
  );
  assert.throws(
    () => planTimeJobLinkUpdate({
      body: { expected_version: 3, job_id: "foreign_job", reason: "Review" },
      entry: completedEntry(), currentLink: existingLink(), job: null
    }),
    (error) => error.code === "accounting_job_not_found" && error.statusCode === 404
  );
});

test("allocation report dates are inclusive, valid, and bounded", () => {
  assert.deepEqual(parseTimeAllocationRange("2026-01-01", "2026-12-31"), {
    start_date: "2026-01-01", end_date: "2026-12-31"
  });
  assert.deepEqual(parseTimeAllocationRange("2024-01-01", "2025-12-31"), {
    start_date: "2024-01-01", end_date: "2025-12-31"
  });
  assert.throws(
    () => parseTimeAllocationRange("2024-01-01", "2026-01-01"),
    (error) => error instanceof CostAllocationError && error.code === "accounting_range_too_large"
  );
  assert.throws(
    () => parseTimeAllocationRange("2026-12-31", "2026-01-01"),
    (error) => error.code === "accounting_range_invalid"
  );
  assert.throws(() => parseTimeAllocationRange("2026-02-30", "2026-03-01"));
});

test("allocation schema is additive, audited, and tenant indexed", async () => {
  const calls = [];
  await installFinanceCostAllocationSchema({
    async query(sql) { calls.push(sql); return { rows: [], rowCount: 0 }; }
  });
  assert.equal(calls.length, 1);
  assert.match(calls[0], /CREATE TABLE IF NOT EXISTS finance_time_job_links/);
  assert.match(calls[0], /UNIQUE\(company_id, time_entry_id\)/);
  assert.match(calls[0], /CREATE TABLE IF NOT EXISTS finance_time_job_link_audit/);
  assert.match(calls[0], /finance_time_job_links_company_job_idx/);
  assert.doesNotMatch(calls[0], /DROP TABLE|TRUNCATE/);
});

test("allocation routes keep all operations authenticated and finance-gated", () => {
  const routes = [];
  const app = {
    get(path, ...handlers) { routes.push({ method: "GET", path, handlers }); },
    put(path, ...handlers) { routes.push({ method: "PUT", path, handlers }); }
  };
  const auth = () => {};
  const finance = () => {};
  installFinanceCostAllocationRoutes({
    app,
    pool: {},
    authRequired: auth,
    requireFinanceAccess: finance
  });
  assert.equal(routes.length, 3);
  assert.deepEqual(routes.map((route) => `${route.method} ${route.path}`), [
    "GET /api/finance/accounting/time-allocations",
    "GET /api/finance/accounting/time-allocations/:entryId",
    "PUT /api/finance/accounting/time-allocations/:entryId/job-link"
  ]);
  assert.ok(routes.every((route) => route.handlers[0] === auth && route.handlers[1] === finance));
});

test("allocation report returns exact operational hours without labor dollars", async () => {
  let reportHandler;
  const calls = [];
  const app = {
    get(path, ...handlers) {
      if (path === "/api/finance/accounting/time-allocations") reportHandler = handlers.at(-1);
    },
    put() {}
  };
  const pool = {
    async query(sql, values) {
      calls.push({ sql, values });
      if (/^\s*SELECT COALESCE\(NULLIF\(timezone/.test(sql)) return { rows: [{ timezone: "America/Chicago" }] };
      if (sql.includes("review_row_count")) return { rows: [{
        completed_entry_count: "2", valid_entry_count: "2", allocated_entry_count: "1",
        allocated_seconds: "14400", unallocated_entry_count: "1", unallocated_seconds: "12600",
        stale_link_count: "1", invalid_entry_count: "0", review_row_count: "2"
      }] };
      if (sql.includes("open_entry_count")) return { rows: [{ open_entry_count: "1", disapproved_entry_count: "0" }] };
      if (sql.includes("SELECT * FROM scoped")) return { rows: [{
        time_entry_id: "entry_1", employee_id: "employee_1", employee_name: "Taylor Tech",
        start_at: "2026-08-19T13:00:00Z", end_at: "2026-08-19T17:30:00Z",
        break_seconds: "1800", work_seconds: "14400", manual_entry: false, manual_status: "approved",
        job_id: "job_1", job_title: "Exterior wash", link_version: "3",
        duration_valid: true, source_current: true, job_exists: true
      }] };
      throw new Error("unexpected query");
    }
  };
  installFinanceCostAllocationRoutes({ app, pool, authRequired() {}, requireFinanceAccess() {} });
  let responseStatus = 200;
  let payload;
  await reportHandler(
    { companyId: "company_1", query: { start_date: "2026-08-01", end_date: "2026-08-31", limit: "20" } },
    {
      status(value) { responseStatus = value; return this; },
      json(value) { payload = value; return this; }
    }
  );
  assert.equal(responseStatus, 200);
  assert.equal(payload.timezone, "America/Chicago");
  assert.equal(payload.summary.allocated_seconds, 14_400);
  assert.equal(payload.summary.unallocated_seconds, 12_600);
  assert.equal(payload.entries[0].allocated_seconds, 14_400);
  assert.equal(payload.entries[0].manual_status, "approved");
  assert.equal("labor_cost_cents" in payload.summary, false);
  assert.equal("payroll_cents" in payload.summary, false);
  assert.ok(calls.every((call) => call.values[0] === "company_1"));
});

test("time entry deletion serializes with allocation writes and protects linked evidence", async () => {
  const source = await readFile(new URL("../index.js", import.meta.url), "utf8");
  const start = source.indexOf('app.delete("/api/time-clock/entries/:id"');
  const end = source.indexOf('app.get("/api/time-clock/manual-entries"', start);
  const route = source.slice(start, end);
  assert.match(route, /SELECT start_at FROM time_clock_entries[\s\S]*FOR UPDATE/);
  assert.match(route, /finance_time_job_links[\s\S]*job_id IS NOT NULL/);
  assert.match(route, /accounting_time_linked/);
  assert.ok(route.indexOf("FOR UPDATE") < route.indexOf("finance_time_job_links"));
  assert.ok(route.indexOf("finance_time_job_links") < route.indexOf("DELETE FROM time_clock_entries"));
});

let passed = 0;
for (const item of tests) {
  try {
    await item.fn();
    passed += 1;
    console.log(`PASS ${item.name}`);
  } catch (error) {
    console.error(`FAIL ${item.name}`);
    console.error(error);
    process.exitCode = 1;
    break;
  }
}
if (!process.exitCode) console.log(`PASS finance cost allocations (${passed}/${tests.length})`);
