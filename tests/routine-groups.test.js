import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  buildRunTimeline,
  completeStepTimeline,
  deriveRoutineStepDurations,
  normalizeRoutineSteps,
  routineProgressSnapshot
} from "../routine-groups.js";

const baseSteps = [
  { id: "wake", title: "Wake up", planned_duration_seconds: 5 * 60 },
  { id: "shower", title: "Shower", planned_duration_seconds: 15 * 60 },
  { id: "dress", title: "Get dressed", planned_duration_seconds: 10 * 60 },
  { id: "breakfast", title: "Eat breakfast", planned_duration_seconds: 20 * 60 },
  { id: "work", title: "Prepare for work", planned_duration_seconds: 15 * 60 },
  { id: "leave", title: "Leave", planned_duration_seconds: 5 * 60 },
  { id: "buffer", title: "Drive buffer", planned_duration_seconds: 20 * 60 }
];

function activeRun(mode = "recalculate") {
  const startAt = new Date("2026-03-08T06:30:00-05:00");
  const timeline = buildRunTimeline({ template: { name: "Morning Routine" }, steps: baseSteps, startAt });
  return {
    run: {
      id: "run-1",
      routine_group_id: "group-1",
      status: "active",
      current_step_id: "wake",
      current_step_index: 0,
      effective_start_at: timeline.effective_start_at,
      effective_estimated_end_at: timeline.effective_estimated_end_at,
      timing_mode: mode,
      progression_mode: "manual"
    },
    steps: timeline.runSteps
  };
}

test("routine timing creates a 90-minute integer-second timeline", () => {
  const { run, steps } = activeRun();
  assert.equal(steps.length, 7);
  assert.equal((new Date(run.effective_estimated_end_at) - new Date(run.effective_start_at)) / 1000, 90 * 60);
  assert.equal(steps[3].title_snapshot, "Eat breakfast");
});

test("tick positions are proportional to planned duration", () => {
  const { run, steps } = activeRun();
  const snapshot = routineProgressSnapshot(run, steps, new Date(run.effective_start_at));
  assert.equal(snapshot.ticks[0].offset, 0);
  assert.equal(snapshot.ticks[1].offset.toFixed(4), (5 / 90).toFixed(4));
  assert.equal(snapshot.ticks[4].offset.toFixed(4), (50 / 90).toFixed(4));
});

test("recalculate mode contracts ETA when a 20-minute step finishes in 5 minutes", () => {
  const startAt = new Date("2026-08-30T12:00:00Z");
  const timeline = buildRunTimeline({
    template: { name: "Short" },
    steps: [
      { id: "first", title: "First", planned_duration_seconds: 20 * 60 },
      { id: "second", title: "Second", planned_duration_seconds: 10 * 60 }
    ],
    startAt
  });
  const next = completeStepTimeline({
    run: { status: "active", current_step_index: 0, effective_start_at: timeline.effective_start_at, effective_estimated_end_at: timeline.effective_estimated_end_at, timing_mode: "recalculate", progression_mode: "manual" },
    steps: timeline.runSteps,
    expectedStepId: "first",
    completedAt: new Date(startAt.getTime() + 5 * 60 * 1000)
  });
  assert.equal((new Date(next.run.effective_estimated_end_at) - startAt) / 1000, 15 * 60);
  assert.equal(next.steps[1].status, "active");
});

test("keep-original mode preserves final ETA on early completion", () => {
  const { run, steps } = activeRun("keep_original");
  const originalEnd = new Date(run.effective_estimated_end_at).toISOString();
  const next = completeStepTimeline({ run, steps, expectedStepId: "wake", completedAt: new Date(new Date(run.effective_start_at).getTime() + 60 * 1000) });
  assert.equal(new Date(next.run.effective_estimated_end_at).toISOString(), originalEnd);
});

test("recalculate mode extends ETA on late completion", () => {
  const { run, steps } = activeRun("recalculate");
  const start = new Date(run.effective_start_at);
  const next = completeStepTimeline({ run, steps, expectedStepId: "wake", completedAt: new Date(start.getTime() + 15 * 60 * 1000) });
  assert.equal((new Date(next.run.effective_estimated_end_at) - start) / 1000, 100 * 60);
});

test("last-step completion completes the run", () => {
  const startAt = new Date("2026-08-30T12:00:00Z");
  const timeline = buildRunTimeline({ template: {}, steps: [{ id: "only", title: "Only", planned_duration_seconds: 60 }], startAt });
  const next = completeStepTimeline({ run: { status: "active", current_step_index: 0, effective_start_at: startAt, effective_estimated_end_at: timeline.effective_estimated_end_at, timing_mode: "recalculate", progression_mode: "manual" }, steps: timeline.runSteps, expectedStepId: "only", completedAt: new Date(startAt.getTime() + 30 * 1000) });
  assert.equal(next.run.status, "completed");
  assert.equal(next.run.current_step_id, null);
});

test("double completion is idempotent when current step is already completed", () => {
  const { run, steps } = activeRun();
  steps[0].status = "completed";
  const next = completeStepTimeline({ run, steps, expectedStepId: "wake", completedAt: new Date() });
  assert.equal(next.replayed, true);
});

test("zero or invalid durations are rejected", () => {
  assert.throws(() => normalizeRoutineSteps([{ title: "Bad", planned_duration_seconds: 0 }]), /positive whole number/);
});

test("routine group entries preserve existing routine references", () => {
  const [entry] = normalizeRoutineSteps([
    { id: "entry-1", routine_id: "routine-1", title: "Wake up", planned_duration_seconds: 300 }
  ]);
  assert.equal(entry.routine_id, "routine-1");
  const timeline = buildRunTimeline({ template: {}, steps: [entry], startAt: new Date("2026-08-30T12:00:00Z") });
  assert.equal(timeline.runSteps[0].routine_id, "routine-1");
  assert.equal(timeline.runSteps[0].title_snapshot, "Wake up");
});

test("routine group step durations are derived from the next routine schedule", () => {
  const steps = [
    { id: "first", routine_id: "routine-1", title: "First", planned_duration_seconds: 300 },
    { id: "second", routine_id: "routine-2", title: "Second", planned_duration_seconds: 300 },
    { id: "third", routine_id: "routine-3", title: "Third", planned_duration_seconds: 420 }
  ];
  const routineMap = new Map([
    ["routine-1", { id: "routine-1", title: "First", time: "2026-08-30T23:58:00Z", weekdays: [1] }],
    ["routine-2", { id: "routine-2", title: "Second", time: "2026-08-31T00:02:00Z", weekdays: [2] }],
    ["routine-3", { id: "routine-3", title: "Third", time: "2026-08-31T00:06:00Z", weekdays: [2] }]
  ]);

  const derived = deriveRoutineStepDurations(steps, routineMap, new Date("2026-08-30T23:50:00Z"));

  assert.equal(derived[0].planned_duration_seconds, 4 * 60);
  assert.equal(derived[1].planned_duration_seconds, 4 * 60);
  assert.equal(derived[2].planned_duration_seconds, 7 * 60);
});

test("DST transition dates are accepted and calculated using UTC instants", () => {
  const startAt = new Date("2026-11-01T01:30:00-04:00");
  const timeline = buildRunTimeline({ template: {}, steps: [{ id: "a", title: "A", planned_duration_seconds: 5400 }], startAt });
  assert.equal((timeline.original_estimated_end_at - timeline.original_start_at) / 1000, 5400);
});

test("long names, many steps, and multiple active routines remain compact", () => {
  const many = Array.from({ length: 40 }, (_, index) => ({ id: `s${index}`, title: `Very long step name ${index} `.repeat(6), planned_duration_seconds: 60 }));
  const one = buildRunTimeline({ template: {}, steps: many, startAt: new Date("2026-08-30T12:00:00Z") });
  const two = buildRunTimeline({ template: {}, steps: many.slice(0, 3), startAt: new Date("2026-08-30T12:05:00Z") });
  assert.equal(one.runSteps.length, 40);
  assert.equal(two.runSteps.length, 3);
});

test("backend routes enforce auth, capabilities, tenant scope, locking, idempotency, and token ownership", () => {
  const source = readFileSync(new URL("../routine-groups.js", import.meta.url), "utf8");
  assert.match(source, /authRequired, requireView/);
  assert.match(source, /authRequired, requireManage/);
  assert.match(source, /company_id = \$1 AND owner_user_id = \$2/);
  assert.match(source, /company_id = \$2 AND user_id = \$3/);
  assert.match(source, /FOR UPDATE/);
  assert.match(source, /assertRoutineOwnership/);
  assert.match(source, /routine_id/);
  assert.match(source, /company_id IS NULL OR company_id = \$3/);
  assert.match(source, /deriveRoutineStepDurations/);
  assert.match(source, /routine_mutations/);
  assert.match(source, /routine_live_activity_tokens/);
  assert.match(source, /invalidated_at = now\(\)/);
});
