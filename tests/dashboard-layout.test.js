import test from "node:test";
import assert from "node:assert/strict";
import {
  DASHBOARD_CARD_CATALOG,
  dashboardCardCatalogPayload,
  defaultDashboardLayout,
  resolveDashboardLayout,
  validateDashboardLayout
} from "../dashboard-layout.js";

const allCapabilities = Object.fromEntries(DASHBOARD_CARD_CATALOG.flatMap((item) => item.required_capabilities).map((key) => [key, true]));

test("catalog is unique and built-in defaults keep a visible card", () => {
  assert.equal(new Set(DASHBOARD_CARD_CATALOG.map((item) => item.id)).size, DASHBOARD_CARD_CATALOG.length);
  assert.equal(dashboardCardCatalogPayload().version, 1);
  for (const preset of ["admin", "manager", "sales", "technician", "office", "legacy_employee"]) {
    const layout = defaultDashboardLayout({ role: "employee", preset });
    assert.ok(layout.order.length > layout.hidden.length);
  }
});

test("validation is strict and appends newly omitted catalog cards", () => {
  const result = validateDashboardLayout({ order: ["sales_tracking", "command_center"], hidden: ["command_center"] });
  assert.equal(result.order[0], "sales_tracking");
  assert.deepEqual(new Set(result.order), new Set(DASHBOARD_CARD_CATALOG.map((item) => item.id)));
  assert.throws(() => validateDashboardLayout({ order: ["not_real"], hidden: [] }), (error) => error.code === "invalid_dashboard_layout");
  assert.throws(() => validateDashboardLayout({ order: ["command_center", "command_center"], hidden: [] }), (error) => error.code === "invalid_dashboard_layout");
  assert.throws(() => validateDashboardLayout({ order: DASHBOARD_CARD_CATALOG.map((item) => item.id), hidden: DASHBOARD_CARD_CATALOG.map((item) => item.id) }), (error) => error.code === "invalid_dashboard_layout");
  assert.throws(() => validateDashboardLayout({ order: ["command_center"], hidden: [], locked: true }), (error) => error.code === "invalid_dashboard_layout");
});

test("personal preference overrides an unlocked role policy", () => {
  const result = resolveDashboardLayout({
    role: "employee",
    preset: "manager",
    capabilities: allCapabilities,
    rolePolicies: { manager: { order: ["command_center", "sales_tracking"], hidden: ["sales_tracking"], locked: false } },
    userPreferences: { order: ["sales_tracking", "command_center"], hidden: [] }
  });
  assert.equal(result.source, "user");
  assert.equal(result.effective.visible[0], "sales_tracking");
});

test("individual locked policy wins and retains ignored preference", () => {
  const cardIDs = DASHBOARD_CARD_CATALOG.map((item) => item.id);
  const result = resolveDashboardLayout({
    role: "employee",
    preset: "sales",
    capabilities: allCapabilities,
    rolePolicies: { sales: { order: ["sales_tracking", "command_center"], hidden: [], locked: false } },
    employeePolicy: { order: cardIDs, hidden: cardIDs.filter((id) => id !== "command_center"), locked: true },
    userPreferences: { order: ["sales_tracking", "command_center"], hidden: [] }
  });
  assert.equal(result.source, "employee");
  assert.equal(result.customizable, false);
  assert.deepEqual(result.effective.visible, ["command_center"]);
  assert.ok(result.preference);
});

test("permissions filter cards and owner-only service plans never leak", () => {
  const employee = resolveDashboardLayout({
    role: "employee",
    preset: "manager",
    capabilities: { "dashboard.view": true, "time.view_all": true, "pay.view_all": false }
  });
  assert.deepEqual(employee.effective.order, ["command_center"]);
  assert.ok(!employee.effective.order.includes("service_plans"));
  assert.ok(!employee.effective.order.includes("employee_hours"));

  const owner = resolveDashboardLayout({ role: "employer", preset: "owner", capabilities: {} });
  assert.ok(owner.effective.visible.includes("service_plans"));
});

test("permission filtering safely restores one permitted hidden card", () => {
  const result = resolveDashboardLayout({
    role: "employee",
    preset: "sales",
    capabilities: { "dashboard.view": true },
    userPreferences: { order: ["command_center"], hidden: ["command_center"] }
  });
  // Persisted all-hidden input is invalid, so resolution falls back to the built-in layout.
  assert.deepEqual(result.effective.visible, ["command_center"]);
});
