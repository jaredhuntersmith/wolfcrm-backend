import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { normalizeRepairCreate, normalizeRepairUpdate, repairLifecycleTimestamps } from "../operations-repairs.js";

const indexSource = readFileSync(new URL("../index.js", import.meta.url), "utf8");

test("repair inputs are bounded and use native-compatible lifecycle values", () => {
  const repair = normalizeRepairCreate({ item_id: "item-1", request_id: "request-1", problem: " Broken belt ", priority: "urgent", estimated_cost_cents: 12500, scheduled_at: "2026-09-01T14:30:00Z" });
  assert.equal(repair.problem, "Broken belt");
  assert.equal(repair.status, "reported");
  assert.equal(repair.scheduled_at, "2026-09-01T14:30:00.000Z");
  assert.throws(() => normalizeRepairCreate({ item_id: "item-1", problem: "", priority: "normal" }), /Problem/);
  assert.throws(() => normalizeRepairCreate({ item_id: "item-1", problem: "Broken", priority: "critical" }), /priority/);
  assert.throws(() => normalizeRepairCreate({ item_id: "item-1", problem: "Broken", priority: "normal", assigned_user_id: "not-a-user" }), /valid identifier/);
  assert.throws(() => normalizeRepairUpdate({ status: "deleted" }), /status/);
});

test("repair updates can clear optional fields but cannot be empty", () => {
  assert.deepEqual(normalizeRepairUpdate({ vendor: null, diagnosis: " Tested " }), { vendor: null, diagnosis: "Tested" });
  assert.throws(() => normalizeRepairUpdate({ item_id: "other-item" }), /at least one/);
});

test("repair lifecycle timestamps start, complete, and safely reopen", () => {
  const started = repairLifecycleTimestamps({ nextStatus: "in_repair", now: new Date("2026-08-28T12:00:00Z") });
  assert.equal(started.started_at, "2026-08-28T12:00:00.000Z");
  const completed = repairLifecycleTimestamps({ previousStatus: "in_repair", nextStatus: "completed", startedAt: started.started_at, now: new Date("2026-08-29T12:00:00Z") });
  assert.equal(completed.completed_at, "2026-08-29T12:00:00.000Z");
  const reopened = repairLifecycleTimestamps({ previousStatus: "completed", nextStatus: "approved", startedAt: started.started_at, completedAt: completed.completed_at, now: new Date("2026-08-30T12:00:00Z") });
  assert.equal(reopened.completed_at, null);
});

test("repair and history routes keep capability and tenant checks authoritative", () => {
  assert.match(indexSource, /app\.get\("\/api\/operations\/inventory\/items\/:id\/history", authRequired, requireCapability\("operations\.view"\)/);
  assert.match(indexSource, /app\.get\("\/api\/operations\/repairs", authRequired, requireCapability\("operations\.view"\)/);
  assert.match(indexSource, /app\.post\("\/api\/operations\/repairs", authRequired, requireCapability\("operations\.manage"\)/);
  assert.match(indexSource, /app\.patch\("\/api\/operations\/repairs\/:id", authRequired, requireCapability\("operations\.manage"\)/);
  assert.match(indexSource, /WHERE r\.id = \$1 AND r\.company_id = \$2/);
  assert.match(indexSource, /equipment_repairs_request_idx/);
});
