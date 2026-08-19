import test from "node:test";
import assert from "node:assert/strict";
import {
  MAX_PRIMARY_TABS,
  TAB_CATALOG,
  defaultTabLayout,
  resolveTabNavigation,
  sanitizePersistedTabLayout,
  tabCatalogPayload,
  validateTabLayout
} from "../navigation-tabs.js";

const allCapabilities = Object.fromEntries(TAB_CATALOG.flatMap((tab) => tab.any_capabilities).map((key) => [key, true]));

test("tab catalog and built-in role defaults remain valid", () => {
  const catalog = tabCatalogPayload();
  assert.equal(catalog.version, 1);
  assert.equal(catalog.max_primary_tabs, 5);
  assert.equal(new Set(catalog.tabs.map((tab) => tab.id)).size, catalog.tabs.length);
  for (const preset of ["admin", "manager", "sales", "technician", "office", "legacy_employee"]) {
    assert.doesNotThrow(() => validateTabLayout(defaultTabLayout({ role: "employee", preset }), { allowLocked: true }));
  }
});

test("layout validation rejects system IDs, duplicates, unknown fields, and too many direct tabs", () => {
  assert.throws(() => validateTabLayout({ order: ["dashboard", "more"], hidden: ["contacts"] }), /Unknown order tab ID/);
  assert.throws(() => validateTabLayout({ order: ["dashboard", "dashboard"], hidden: ["contacts"] }), /Duplicate order/);
  assert.throws(() => validateTabLayout({ order: ["dashboard"], hidden: ["contacts"], locked: true }), /Locked is only valid/);
  assert.throws(() => validateTabLayout({ order: ["dashboard"], hidden: ["contacts"], extra: true }), /Unknown tab layout field/);
  assert.throws(() => validateTabLayout({ order: ["dashboard"], hidden: [] }), /At most 5/);
});

test("partial orders append new catalog IDs and normalize hidden ordering", () => {
  const result = validateTabLayout({ order: ["messages", "dashboard"], hidden: ["map", "stages"] });
  assert.deepEqual(result.order, ["messages", "dashboard", "contacts", "stages", "schedule", "map"]);
  assert.deepEqual(result.hidden, ["stages", "map"]);
});

test("individual locked policy takes precedence over role policy and user preference", () => {
  const response = resolveTabNavigation({
    role: "employee",
    preset: "technician",
    capabilities: allCapabilities,
    rolePolicies: { technician: { order: ["schedule", "dashboard"], hidden: ["stages"], locked: false } },
    employeePolicy: { order: ["messages", "schedule"], hidden: ["stages"], locked: true },
    userPreferences: { order: ["contacts", "dashboard"], hidden: ["map"] }
  });
  assert.equal(response.policy_source, "employee");
  assert.equal(response.source, "employee");
  assert.equal(response.customizable, false);
  assert.equal(response.effective.primary[0], "messages");
});

test("unlocked policy permits a valid user preference", () => {
  const response = resolveTabNavigation({
    role: "employee",
    preset: "sales",
    capabilities: allCapabilities,
    rolePolicies: { sales: { order: ["contacts"], hidden: ["map"], locked: false } },
    userPreferences: { order: ["messages", "contacts"], hidden: ["map"] }
  });
  assert.equal(response.source, "user");
  assert.equal(response.policy_source, "role");
  assert.deepEqual(response.effective.primary.slice(0, 2), ["messages", "contacts"]);
});

test("permissions filter primary and overflow with Messages OR semantics", () => {
  const response = resolveTabNavigation({
    role: "employee",
    preset: "technician",
    capabilities: { "schedule.view": true, "communications.view": true },
    userPreferences: { order: ["contacts", "messages", "schedule"], hidden: ["map"] }
  });
  assert.deepEqual(response.effective.order, ["messages", "schedule"]);
  assert.deepEqual(response.effective.primary, ["messages", "schedule"]);
  assert.deepEqual(response.effective.overflow, []);
});

test("the direct tab cap moves remaining permitted destinations into overflow", () => {
  const response = resolveTabNavigation({
    role: "employer",
    userPreferences: { order: TAB_CATALOG.map((tab) => tab.id), hidden: ["messages"] }
  });
  assert.equal(response.effective.primary.length, MAX_PRIMARY_TABS);
  assert.deepEqual(response.effective.overflow, ["messages"]);
});

test("invalid persisted documents safely fall back to the built-in role layout", () => {
  assert.equal(sanitizePersistedTabLayout({ order: ["not-real"], hidden: [] }), null);
  const response = resolveTabNavigation({
    role: "employee",
    preset: "office",
    capabilities: allCapabilities,
    userPreferences: { order: ["not-real"], hidden: [] }
  });
  assert.equal(response.source, "built_in");
  assert.equal(response.effective.primary[0], "schedule");
});

test("no permitted core destination leaves More as the safe fallback", () => {
  const response = resolveTabNavigation({ role: "employee", preset: "technician", capabilities: {} });
  assert.deepEqual(response.effective.primary, []);
  assert.deepEqual(response.effective.overflow, []);
});

