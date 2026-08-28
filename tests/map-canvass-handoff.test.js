import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("../index.js", import.meta.url), "utf8");

test("canvass handoff requires both operations and Contact authority", () => {
  assert.match(source, /app\.post\("\/api\/map-pins\/canvass", authRequired, requireAllCapabilities\("operations\.manage", "contacts\.view"\)/);
  assert.match(source, /WHERE \$\{contactScope\.sql\} AND deleted_at IS NULL AND id = ANY\(\$2::uuid\[\]\)/);
});

test("canvass handoff locks per user and reuses owned linked pins", () => {
  assert.match(source, /pg_advisory_xact_lock\(hashtext\(\$1\)\)/);
  assert.match(source, /WHERE p\.user_id = \$1 AND p\.contact_id = ANY\(\$2::text\[\]\)/);
  assert.match(source, /outcome: "reused"/);
});

test("canvass pin creation is Railway-owned and emits Web automation evidence", () => {
  assert.match(source, /INSERT INTO map_pins\(id, user_id, latitude, longitude, name, address, notes, status, phone, email, contact_id, source\)/);
  assert.match(source, /eventType: "map\.pin_created"[\s\S]+source: "web"/);
  assert.match(source, /reason: "missing_coordinates"/);
});
