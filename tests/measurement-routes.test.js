import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("../index.js", import.meta.url), "utf8");

test("measurement routes keep operations capabilities and verified user/company ownership authoritative", () => {
  assert.match(source, /app\.get\("\/api\/measurements", authRequired, requireCapability\("operations\.view"\)/);
  assert.match(source, /app\.put\("\/api\/measurements\/:id", authRequired, requireCapability\("operations\.manage"\)/);
  assert.match(source, /app\.delete\("\/api\/measurements\/:id", authRequired, requireCapability\("operations\.manage"\)/);
  assert.match(source, /scope_verified BOOLEAN NOT NULL DEFAULT false/);
  assert.match(source, /WHERE user_id = \$1 AND scope_verified = true AND company_id IS NOT DISTINCT FROM \$2::uuid/);
  assert.match(source, /WHERE id = \$1 AND user_id = \$2 AND scope_verified = true/);
  assert.match(source, /measurements\.company_id IS NOT DISTINCT FROM \$3::uuid/);
});

test("measurement Contact links are capability checked and tenant scoped", () => {
  assert.match(source, /hasCapability\(req, "contacts\.view"\)/);
  assert.match(source, /const tenantColumn = req\.companyId \? "company_id" : "user_id"/);
  assert.match(source, /id::text = ANY\(\$1::text\[\]\)/);
  assert.match(source, /invalid_linked_contact_ids/);
});

test("measurement delete events require an actual deleted row", () => {
  assert.match(source, /DELETE FROM measurements[\s\S]*WHERE id = \$1 AND user_id = \$2 AND scope_verified = true[\s\S]*RETURNING id/);
  assert.match(source, /if \(deleted\) \{[\s\S]*eventType: "measurement\.deleted"/);
});
