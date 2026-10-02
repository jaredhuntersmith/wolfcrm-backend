import assert from "node:assert/strict";
import test from "node:test";
import { normalizeSavedService, assertQuoteReferences, serviceUUID } from "../services-catalog.js";

const serviceID = "11111111-1111-4111-8111-111111111111";
const presetID = "22222222-2222-4222-8222-222222222222";
const lineID = "33333333-3333-4333-8333-333333333333";

test("saved service import preserves descriptions and prices without enabling plans", () => {
  const result = normalizeSavedService({ name: "Windows", default_price_cents: 30000, default_description: "First paragraph\n\nSecond paragraph", plan_eligible: true }, { importing: true });
  assert.equal(result.default_description, "First paragraph\n\nSecond paragraph");
  assert.equal(result.default_price_cents, 30000);
  assert.equal(result.plan_eligible, false);
  assert.equal(normalizeSavedService({ name: "New service" }).plan_eligible, false);
  assert.equal(normalizeSavedService({ name: "Windows", plan_eligible: true }).plan_eligible, true);
});

test("saved service invalid pricing and oversized text are rejected without truncation", () => {
  for (const price of [-1, 1.5, 2000000001, "100", Infinity]) assert.throws(() => normalizeSavedService({ name: "Windows", default_price_cents: price }), { code: "service_price_invalid" });
  assert.throws(() => normalizeSavedService({ name: "Windows", default_description: "a".repeat(20001) }), { code: "service_field_invalid" });
  assert.throws(() => normalizeSavedService({ name: "Windows", plan_eligible: "false" }), { code: "service_eligibility_invalid" });
});

test("default descriptions reference a unique preset on the same service", () => {
  const preset = { id: presetID, name: "Exterior", description: "Glass only\nNo screens" };
  const normalized = normalizeSavedService({ name: "Windows", description_presets: [preset], default_preset_id: presetID });
  assert.deepEqual(normalized.description_presets, [preset]);
  assert.throws(() => normalizeSavedService({ name: "Windows", description_presets: [preset, preset] }), { code: "service_presets_invalid" });
  assert.throws(() => normalizeSavedService({ name: "Windows", default_preset_id: presetID }), { code: "service_default_preset_invalid" });
  assert.throws(() => serviceUUID("starter-windows"), { code: "service_id_invalid" });
});

test("quote contact and service ownership is always checked against the active company", async () => {
  const req = { companyId: "company-a", userId: "employee-a" };
  let statements = [];
  const foreignContactDB = { query: async (sql, params) => { statements.push({ sql, params }); return { rows: [], rowCount: 0 }; } };
  await assert.rejects(assertQuoteReferences(foreignContactDB, req, { contact_id: "foreign-contact" }), { code: "contact_not_found" });
  assert.match(statements[0].sql, /company_id = \$2/);
  assert.deepEqual(statements[0].params, ["foreign-contact", "company-a"]);
  statements = [];
  await assert.rejects(assertQuoteReferences(foreignContactDB, req, { line_items: [{ service_id: serviceID }] }), { code: "quote_service_not_found" });
  assert.match(statements[0].sql, /company_id = \$1/);
  assert.deepEqual(statements[0].params, ["company-a", [serviceID]]);
});

test("archival preserves existing quote lines but does not permit adding new archived lines", async () => {
  const db = { query: async () => ({ rows: [{ id: serviceID, archived_at: new Date() }], rowCount: 1 }) };
  const existing = { id: lineID, service_id: serviceID, description: "Frozen quote wording" };
  const req = { companyId: "company-a" };
  await assertQuoteReferences(db, req, { line_items: [existing], existing_lines: [existing] });
  await assert.rejects(assertQuoteReferences(db, req, { line_items: [existing] }), { code: "quote_service_archived" });
  await assert.rejects(assertQuoteReferences(db, req, { line_items: [existing, { ...existing, id: presetID }], existing_lines: [existing] }), { code: "quote_service_archived" });
});
