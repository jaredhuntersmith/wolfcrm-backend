import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { countAdjustment, normalizeCountGeneration, normalizeCountReview, normalizeCountSchedule, normalizeCountSubmission } from "../operations-inventory-counts.js";

const indexSource = readFileSync(new URL("../index.js", import.meta.url), "utf8");

test("count schedule input is bounded and native compatible", () => {
  const value = normalizeCountSchedule({ name: " Weekly shop ", location_id: "shop", frequency: "weekly", due_date: "2026-09-01", due_time: "08:30", variance_threshold: 2, approval_required: false });
  assert.equal(value.name, "Weekly shop");
  assert.equal(value.approval_required, false);
  assert.throws(() => normalizeCountSchedule({ name: "Bad", location_id: "shop", frequency: "daily" }), /frequency/i);
  assert.throws(() => normalizeCountSchedule({ name: "Bad", location_id: "shop", frequency: "weekly", due_time: "25:00" }), /HH:mm/);
  assert.throws(() => normalizeCountGeneration({ due_date: "2026-02-30" }), /valid YYYY-MM-DD/);
  assert.deepEqual(normalizeCountGeneration({ due_date: "2026-10-02" }), { due_date: "2026-10-02" });
});

test("count submissions require unique nonnegative bounded quantities", () => {
  const value = normalizeCountSubmission({ items: [{ item_id: "filter", counted_quantity: 4.5, note: " Top shelf " }] });
  assert.equal(value.items[0].note, "Top shelf");
  assert.throws(() => normalizeCountSubmission({ items: [] }), /1–500/);
  assert.throws(() => normalizeCountSubmission({ items: [{ item_id: "filter", counted_quantity: -1 }] }), /quantity/i);
  assert.throws(() => normalizeCountSubmission({ items: [{ item_id: "filter", counted_quantity: 1 }, { item_id: "filter", counted_quantity: 2 }] }), /once/i);
});

test("review actions and current-to-physical reconciliation are deterministic", () => {
  assert.deepEqual(normalizeCountReview({ action: "approve", note: " Verified " }), { action: "approve", note: "Verified" });
  assert.throws(() => normalizeCountReview({ action: "delete" }), /approve or reject/i);
  assert.equal(countAdjustment(7, 5), -2);
  assert.equal(countAdjustment(3, 5), 2);
});

test("inventory count routes retain tenant and capability boundaries", () => {
  assert.match(indexSource, /inventory_count_schedules_company_idx/);
  assert.match(indexSource, /app\.get\("\/api\/operations\/inventory-counts\/schedules", authRequired, requireCapability\("operations\.view"\)/);
  assert.match(indexSource, /app\.put\("\/api\/operations\/inventory-counts\/schedules\/:id", authRequired, requireCapability\("operations\.manage"\)/);
  assert.match(indexSource, /app\.get\("\/api\/operations\/inventory-counts\/assignees", authRequired, requireCapability\("operations\.manage"\)/);
  assert.match(indexSource, /app\.post\("\/api\/operations\/inventory-counts\/submissions\/:id\/submit", authRequired, requireCapability\("operations\.request"\)/);
  assert.match(indexSource, /app\.post\("\/api\/operations\/inventory-counts\/submissions\/:id\/review", authRequired, requireCapability\("operations\.manage"\)/);
  assert.match(indexSource, /s\.company_id = \$2/);
});
