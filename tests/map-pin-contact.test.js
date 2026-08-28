import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("../index.js", import.meta.url), "utf8");

test("map pin conversion is owner and company scoped under operations management", () => {
  assert.match(source, /app\.post\("\/api\/map-pins\/:id\/contact", authRequired, requireCapability\("operations\.manage"\)/);
  assert.match(source, /p\.user_id = \$2 OR \(\$3 = 'employer' AND u\.company_id = \$4\)/);
  assert.match(source, /FOR UPDATE OF p/);
});

test("map pin conversion dynamically enforces Contact capabilities and is idempotent", () => {
  assert.match(source, /hasCapability\(req, "contacts\.view"\)/);
  assert.match(source, /hasCapability\(req, "contacts\.create"\)/);
  assert.match(source, /hasCapability\(req, "contacts\.edit"\)/);
  assert.match(source, /if \(previousPin\.contact_id\)/);
  assert.match(source, /SET contact_id = \$2/);
});

test("schedule intent marks the shared pin and Contact won and emits existing effects", () => {
  assert.match(source, /map_pin_schedule_fields_required/);
  assert.match(source, /CASE WHEN \$3 = 'schedule' THEN 'won' ELSE status END/);
  assert.match(source, /emitContactCreatedEffects\(req, contact, "map"\)/);
  assert.match(source, /eventType: "map\.pin_converted_to_contact"/);
  assert.match(source, /eventType: "map\.pin_status_changed"/);
  assert.match(source, /syncAutomationSchedulesForMapPin\(req\.companyId, pin, "status_changed"\)/);
});
