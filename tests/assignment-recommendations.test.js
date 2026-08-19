import test from "node:test";
import assert from "node:assert/strict";
import {
  buildAssignmentRecommendations,
  planAssignmentApplication
} from "../assignment-recommendations.js";

const now = new Date("2026-08-19T12:00:00Z");
const target = {
  id: "target",
  title: "Exterior windows",
  start_at: "2026-08-20T14:00:00Z",
  end_at: "2026-08-20T15:00:00Z",
  worker_user_ids: [],
  updated_at: "2026-08-19T16:00:00.000Z",
  contact_latitude: 38.25,
  contact_longitude: -85.75
};
const workers = [
  { id: "worker-a", display_name: "Alex", permitted: true },
  { id: "worker-b", display_name: "Blair", permitted: true }
];
const availability = { weekdays: [1, 2, 3, 4, 5], start_time: "08:00", end_time: "17:00", enabled: true };

function recommend(overrides = {}) {
  return buildAssignmentRecommendations({
    targetJob: target,
    workers,
    existingJobs: [],
    companyAvailability: availability,
    timeZone: "America/New_York",
    routingStatus: { configured: true, provider: "google" },
    now,
    ...overrides
  });
}

test("a clear eligible worker ranks above an overlapping worker", () => {
  const report = recommend({
    existingJobs: [{
      id: "conflict",
      title: "Roof job",
      start_at: "2026-08-20T14:30:00Z",
      end_at: "2026-08-20T15:30:00Z",
      worker_user_ids: ["worker-a"]
    }]
  });
  assert.equal(report.best_worker_id, "worker-b");
  assert.equal(report.recommendations[0].worker_id, "worker-b");
  const alex = report.recommendations.find((item) => item.worker_id === "worker-a");
  assert.equal(alex.eligible, false);
  assert.deepEqual(alex.conflict_job_ids, ["conflict"]);
  assert.ok(alex.reasons.some((reason) => reason.code === "schedule_overlap"));
});

test("company timezone availability is a hard eligibility rule", () => {
  const report = recommend({
    targetJob: { ...target, start_at: "2026-08-20T22:00:00Z", end_at: "2026-08-20T23:00:00Z" }
  });
  assert.equal(report.best_worker_id, null);
  assert.ok(report.recommendations.every((item) => !item.fits_availability && !item.eligible));
});

test("back-to-back work is non-overlapping but impossible road travel blocks eligibility", () => {
  const report = recommend({
    existingJobs: [{
      id: "prior",
      title: "Prior job",
      start_at: "2026-08-20T13:00:00Z",
      end_at: "2026-08-20T14:00:00Z",
      worker_user_ids: ["worker-a"]
    }],
    travelByWorker: {
      "worker-a": { coverage: "complete", incoming_seconds: 600, outgoing_seconds: 0, baseline_seconds: 0, added_seconds: 600 },
      "worker-b": { coverage: "complete", incoming_seconds: 300, outgoing_seconds: 0, baseline_seconds: 0, added_seconds: 300 }
    }
  });
  const alex = report.recommendations.find((item) => item.worker_id === "worker-a");
  assert.deepEqual(alex.conflict_job_ids, []);
  assert.equal(alex.previous_gap_seconds, 0);
  assert.equal(alex.eligible, false);
  assert.ok(alex.reasons.some((reason) => reason.code === "incoming_travel_conflict"));
  assert.equal(report.best_worker_id, "worker-b");
});

test("added road time and workload produce deterministic eligible ranking", () => {
  const report = recommend({
    existingJobs: [{
      id: "morning",
      title: "Morning job",
      start_at: "2026-08-20T12:00:00Z",
      end_at: "2026-08-20T13:00:00Z",
      worker_user_ids: ["worker-a"]
    }],
    travelByWorker: {
      "worker-a": { coverage: "complete", incoming_seconds: 600, outgoing_seconds: 300, baseline_seconds: 500, added_seconds: 400 },
      "worker-b": { coverage: "complete", incoming_seconds: 1_200, outgoing_seconds: 600, baseline_seconds: 300, added_seconds: 1_500 }
    }
  });
  assert.equal(report.best_worker_id, "worker-a");
  assert.ok(report.recommendations[0].score > report.recommendations[1].score);
  assert.equal(report.recommendations[0].previous_job.id, "morning");
  assert.equal(report.recommendations[0].assigned_seconds, 3_600);
});

test("adjacent jobs and workload stay on the target company-local day", () => {
  const report = recommend({
    existingJobs: [
      {
        id: "same-day-prior",
        title: "Same day",
        start_at: "2026-08-20T12:00:00Z",
        end_at: "2026-08-20T13:00:00Z",
        worker_user_ids: ["worker-a"]
      },
      {
        id: "previous-day-late",
        title: "Previous local day",
        start_at: "2026-08-20T02:30:00Z",
        end_at: "2026-08-20T03:30:00Z",
        worker_user_ids: ["worker-a"]
      }
    ]
  });
  const alex = report.recommendations.find((item) => item.worker_id === "worker-a");
  assert.equal(alex.previous_job.id, "same-day-prior");
  assert.equal(alex.assigned_seconds, 3_600);
});

test("missing road evidence lowers confidence without fabricating travel or a conflict", () => {
  const report = recommend({
    targetJob: { ...target, contact_latitude: null, contact_longitude: null },
    routingStatus: { configured: false, provider: "google" }
  });
  assert.equal(report.best_worker_id, "worker-a");
  assert.equal(report.recommendations[0].confidence, "low");
  assert.equal(report.recommendations[0].travel.added_seconds, null);
  assert.ok(report.warnings.some((warning) => warning.includes("not configured")));
  assert.ok(report.warnings.some((warning) => warning.includes("no saved coordinates")));
});

test("permission and stable identity break otherwise equal candidates safely", () => {
  const report = recommend({
    workers: [
      { id: "worker-b", display_name: "Same", permitted: true },
      { id: "worker-a", display_name: "Same", permitted: true },
      { id: "worker-c", display_name: "Aardvark", permitted: false }
    ]
  });
  assert.deepEqual(report.recommendations.map((item) => item.worker_id), ["worker-a", "worker-b", "worker-c"]);
  assert.equal(report.best_worker_id, "worker-a");
  assert.equal(report.recommendations[2].eligible, false);
  assert.ok(report.recommendations[2].reasons.some((reason) => reason.code === "jobs_work_required"));
});

test("a team with no job-work permission returns an explicit warning", () => {
  const report = recommend({
    workers: workers.map((worker) => ({ ...worker, permitted: false }))
  });
  assert.equal(report.best_worker_id, null);
  assert.ok(report.warnings.some((warning) => warning.includes("permission to perform job work")));
});

test("started, finished, or past target jobs fail closed", () => {
  for (const targetJob of [
    { ...target, started_at: "2026-08-20T14:01:00Z" },
    { ...target, finished_at: "2026-08-20T15:00:00Z" },
    { ...target, start_at: "2026-08-18T14:00:00Z", end_at: "2026-08-18T15:00:00Z" }
  ]) {
    assert.throws(
      () => recommend({ targetJob }),
      (error) => error.code === "assignment_job_not_eligible" && error.statusCode === 409
    );
  }
});

test("assignment application explicitly adds to or replaces the current crew", () => {
  const report = recommend({ targetJob: { ...target, worker_user_ids: ["worker-a"] } });
  const common = {
    report,
    selectedWorkerID: "worker-b",
    expectedUpdatedAt: target.updated_at
  };
  assert.deepEqual(planAssignmentApplication({ ...common, assignmentMode: "add" }).new_worker_user_ids, ["worker-a", "worker-b"]);
  assert.deepEqual(planAssignmentApplication({ ...common, assignmentMode: "replace" }).new_worker_user_ids, ["worker-b"]);
});

test("assignment application rejects stale versions and newly ineligible workers", () => {
  const report = recommend({
    workers: [{ id: "worker-a", display_name: "Alex", permitted: false }]
  });
  assert.throws(
    () => planAssignmentApplication({
      report,
      selectedWorkerID: "worker-a",
      assignmentMode: "replace",
      expectedUpdatedAt: target.updated_at
    }),
    (error) => error.code === "assignment_candidate_ineligible" && error.statusCode === 409
  );
  assert.throws(
    () => planAssignmentApplication({
      report: recommend(),
      selectedWorkerID: "worker-a",
      assignmentMode: "replace",
      expectedUpdatedAt: "2026-08-19T15:59:59.000Z"
    }),
    (error) => error.code === "assignment_job_changed" && error.statusCode === 409
  );
});
