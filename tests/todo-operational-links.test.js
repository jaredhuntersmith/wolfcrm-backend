import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { TodoOperationalLinkError, normalizeTaskOperationalLinks, validateTaskOperationalLinks } from "../todo-operational-links.js";

const indexSource = readFileSync(new URL("../index.js", import.meta.url), "utf8");

test("task operational links normalize explicit clears and preserve omitted fields", () => {
  const links = normalizeTaskOperationalLinks(
    { linked_equipment_id: " asset-1 ", linked_inventory_count_id: null },
    { linked_equipment_request_id: "request-1", linked_inventory_count_id: "count-old" }
  );
  assert.deepEqual(links, {
    linked_equipment_id: "asset-1",
    linked_equipment_request_id: "request-1",
    linked_inventory_count_id: null,
  });
  assert.throws(() => normalizeTaskOperationalLinks({ linked_equipment_id: 42 }), TodoOperationalLinkError);
});

test("task operational links are validated inside the authenticated company", async () => {
  const calls = [];
  const queryable = {
    async query(sql, params) {
      calls.push({ sql, params });
      return { rows: [{ equipment_exists: true, request_exists: true, count_exists: true }] };
    },
  };
  const links = normalizeTaskOperationalLinks({ linked_equipment_id: "asset-1", linked_equipment_request_id: "request-1", linked_inventory_count_id: "count-1" });
  await validateTaskOperationalLinks(queryable, "company-1", links);
  assert.deepEqual(calls[0].params, ["company-1", "asset-1", "request-1", "count-1"]);
  assert.match(calls[0].sql, /inventory_items[\s\S]*company_id = \$1/);
  assert.match(calls[0].sql, /equipment_requests[\s\S]*company_id = \$1/);
  assert.match(calls[0].sql, /inventory_count_submissions[\s\S]*company_id = \$1/);
});

test("missing or cross-company operational targets fail closed", async () => {
  const queryable = { async query() { return { rows: [{ equipment_exists: true, request_exists: false, count_exists: true }] }; } };
  await assert.rejects(
    validateTaskOperationalLinks(queryable, "company-1", normalizeTaskOperationalLinks({ linked_equipment_request_id: "foreign" })),
    (error) => error instanceof TodoOperationalLinkError && error.code === "linked_equipment_request_not_found" && error.statusCode === 404
  );
});

test("todo task storage and responses include every operational link", () => {
  assert.match(indexSource, /ADD COLUMN IF NOT EXISTS linked_equipment_request_id TEXT/);
  assert.match(indexSource, /ADD COLUMN IF NOT EXISTS linked_inventory_count_id TEXT/);
  assert.match(indexSource, /linked_equipment_id, linked_equipment_request_id, linked_inventory_count_id/);
  assert.match(indexSource, /validateTaskOperationalLinks\(pool, req\.companyId, operationalLinks\)/);
});
