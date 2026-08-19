import test from "node:test";
import assert from "node:assert/strict";
import { normalizeAssignmentIDs, summarizeScheduleTeam, validateAssignments, validateAvailability } from "../schedule-team.js";

const owner = "11111111-1111-4111-8111-111111111111";
const worker = "22222222-2222-4222-8222-222222222222";
const outsider = "33333333-3333-4333-8333-333333333333";

test("assignment IDs are unique, bounded, and active-company scoped", () => {
  assert.deepEqual(normalizeAssignmentIDs([worker, worker.toUpperCase()], { field: "worker_user_ids", max: 2 }), [worker]);
  assert.deepEqual(validateAssignments({ salesIDs: [owner], workerIDs: [worker], activeMemberIDs: [owner, worker] }), {
    sales_user_ids: [owner],
    worker_user_ids: [worker]
  });
  assert.throws(
    () => validateAssignments({ salesIDs: [], workerIDs: [outsider], activeMemberIDs: [owner, worker] }),
    (error) => error.code === "invalid_assignment_users" && error.details.user_ids[0] === outsider
  );
});

test("availability requires ISO weekdays and a non-overnight HH:mm interval", () => {
  assert.deepEqual(validateAvailability({ enabled: true, weekdays: [5, 1, 1], start_time: "08:30", end_time: "17:00" }), {
    enabled: true,
    weekdays: [1, 5],
    start_time: "08:30",
    end_time: "17:00"
  });
  assert.throws(() => validateAvailability({ weekdays: [0], start_time: "08:00", end_time: "17:00" }), /ISO weekdays/);
  assert.throws(() => validateAvailability({ weekdays: [1], start_time: "17:00", end_time: "08:00" }), /after start/);
});

test("team summary finds unassigned, overlapping, and outside-hours work", () => {
  const events = [
    { id: "a", start: "2026-08-17T13:00:00Z", end: "2026-08-17T15:00:00Z", worker_user_ids: [worker] },
    { id: "b", start: "2026-08-17T14:30:00Z", end: "2026-08-17T16:00:00Z", worker_user_ids: [worker] },
    { id: "c", start: "2026-08-17T22:00:00Z", end: "2026-08-17T23:00:00Z", worker_user_ids: [worker] },
    { id: "unassigned", start: "2026-08-17T16:00:00Z", end: "2026-08-17T17:00:00Z", worker_user_ids: [] }
  ];
  const summary = summarizeScheduleTeam({
    events,
    timeZone: "America/New_York",
    companyAvailability: { weekdays: [1, 2, 3, 4, 5], start_time: "08:00", end_time: "17:00", enabled: true }
  });
  assert.deepEqual(summary.unassigned_event_ids, ["unassigned"]);
  assert.deepEqual(summary.conflicts, [{ worker_user_id: worker, event_ids: ["a", "b"] }]);
  assert.deepEqual(summary.outside_availability, [{ worker_user_id: worker, event_id: "c" }]);
  assert.equal(summary.assigned_minutes_by_user[worker], 270);
});

test("back-to-back jobs do not conflict and finished jobs do not consume current capacity", () => {
  const summary = summarizeScheduleTeam({ events: [
    { id: "first", start: "2026-08-17T13:00:00Z", end: "2026-08-17T14:00:00Z", worker_user_ids: [worker] },
    { id: "second", start: "2026-08-17T14:00:00Z", end: "2026-08-17T15:00:00Z", worker_user_ids: [worker] },
    { id: "done", start: "2026-08-17T13:30:00Z", end: "2026-08-17T14:30:00Z", worker_user_ids: [worker], finished_at: "2026-08-17T15:00:00Z" }
  ] });
  assert.deepEqual(summary.conflicts, []);
  assert.equal(summary.assigned_minutes_by_user[worker], 120);
});

