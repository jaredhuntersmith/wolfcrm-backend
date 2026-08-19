import assert from "node:assert/strict";
import {
  PERMISSION_CAPABILITIES,
  PERMISSION_GROUPS,
  PERMISSION_PRESETS,
  hasCapability,
  legacyColumnsForCapabilities,
  permissionCatalogPayload,
  requiredAutomationCapability,
  requiredFinanceCapability,
  resolveAccess,
  validateAccessUpdate
} from "../permissions.js";

function testCatalogIsUniqueAndComplete() {
  const keys = PERMISSION_CAPABILITIES.map((item) => item.key);
  const groupIds = new Set(PERMISSION_GROUPS.map((item) => item.id));
  assert.equal(new Set(keys).size, keys.length);
  assert.equal(new Set(PERMISSION_PRESETS.map((item) => item.id)).size, PERMISSION_PRESETS.length);
  assert.ok(PERMISSION_CAPABILITIES.every((item) => groupIds.has(item.group_id)));
  assert.ok(PERMISSION_CAPABILITIES.every((item) => item.depends_on.every((dependency) => keys.includes(dependency))));
  const payload = permissionCatalogPayload();
  assert.equal(payload.version, 3);
  assert.equal(Object.keys(payload.presets.find((item) => item.id === "admin").capabilities).length, keys.length);
}

function testOwnerAlwaysHasEveryCapability() {
  const access = resolveAccess({
    role: "employer",
    preset: "technician",
    overrides: { "contacts.view": false, "team.manage": false }
  });
  assert.equal(access.preset, "owner");
  assert.ok(Object.values(access.capabilities).every(Boolean));
  assert.equal(hasCapability({ role: "employer" }, "team.manage"), true);
}

function testTechnicianPresetIsOperationalButRestricted() {
  const access = resolveAccess({ role: "employee", preset: "technician" });
  assert.equal(access.capabilities["jobs.work"], true);
  assert.equal(access.capabilities["routes.view"], true);
  assert.equal(access.capabilities["finance.view"], false);
  assert.equal(access.capabilities["team.manage"], false);
  assert.equal(access.capabilities["contacts.delete"], false);
  assert.equal(access.capabilities["dashboard.exceptions.view"], false);
  assert.equal(access.capabilities["dashboard.exceptions.manage"], false);
}

function testBusinessExceptionAccessIsLimitedToOperationalLeaders() {
  const manager = resolveAccess({ role: "employee", preset: "manager" }).capabilities;
  const office = resolveAccess({ role: "employee", preset: "office" }).capabilities;
  const sales = resolveAccess({ role: "employee", preset: "sales" }).capabilities;
  const legacy = resolveAccess({ role: "employee", preset: "legacy_employee" }).capabilities;
  assert.equal(manager["dashboard.exceptions.view"], true);
  assert.equal(manager["dashboard.exceptions.manage"], true);
  assert.equal(office["dashboard.exceptions.view"], true);
  assert.equal(office["dashboard.exceptions.manage"], true);
  assert.equal(sales["dashboard.exceptions.view"], false);
  assert.equal(sales["dashboard.exceptions.manage"], false);
  assert.equal(legacy["dashboard.exceptions.view"], false);
  assert.equal(legacy["dashboard.exceptions.manage"], false);
}

function testSparseOverrideAddsDependencies() {
  const update = validateAccessUpdate({ preset: "technician", overrides: { "quotes.edit": true } });
  assert.equal(update.capabilities["quotes.edit"], true);
  assert.equal(update.capabilities["quotes.view"], true);
  assert.equal(update.overrides["quotes.edit"], true);
  assert.equal(update.overrides["quotes.view"], true);

  const accounting = validateAccessUpdate({ preset: "technician", overrides: { "accounting.manage": true } });
  assert.equal(accounting.capabilities["accounting.view"], true);
  assert.equal(accounting.capabilities["finance.transactions.view"], true);
  assert.equal(accounting.capabilities["finance.manage"], true);
}

function testExplicitViewDenyCascadesToActions() {
  const update = validateAccessUpdate({
    preset: "office",
    overrides: { "contacts.view": false, "contacts.create": true, "contacts.edit": true }
  });
  assert.equal(update.capabilities["contacts.view"], false);
  assert.equal(update.capabilities["contacts.create"], false);
  assert.equal(update.capabilities["contacts.edit"], false);
}

function testInvalidDocumentsFailClosed() {
  assert.throws(
    () => validateAccessUpdate({ preset: "owner", overrides: {} }),
    (error) => error.code === "invalid_permission_document" && error.statusCode === 400
  );
  assert.throws(
    () => validateAccessUpdate({ preset: "technician", overrides: { "made.up": true } }),
    (error) => error.code === "invalid_permission_document"
  );
  assert.throws(
    () => validateAccessUpdate({ preset: "technician", overrides: { "routes.view": "yes" } }),
    (error) => error.code === "invalid_permission_document"
  );
}

function testUnknownPersistedPresetUsesSafeDefault() {
  const access = resolveAccess({ role: "employee", preset: "future-invalid-preset" });
  assert.equal(access.preset, "technician");
  assert.equal(access.capabilities["jobs.work"], true);
  assert.equal(access.capabilities["team.manage"], false);
}

function testLegacyColumnsRemainEffective() {
  const access = resolveAccess({
    role: "employee",
    preset: "legacy_employee",
    legacy: {
      can_delete_contacts: true,
      can_view_finance: true,
      can_edit_finance_budgets: true,
      can_use_finance_ai: true
    }
  });
  assert.equal(access.capabilities["contacts.delete"], true);
  assert.equal(access.capabilities["finance.view"], true);
  assert.equal(access.capabilities["finance.manage"], false);
  assert.equal(access.capabilities["finance.budgets.edit"], true);
  assert.equal(access.capabilities["finance.accounts.edit"], false);
  assert.equal(access.capabilities["ai.use"], true);
}

function testLegacyColumnSynchronization() {
  const access = resolveAccess({ role: "employee", preset: "admin" });
  const columns = legacyColumnsForCapabilities(access.capabilities);
  assert.equal(columns.can_delete_contacts, true);
  assert.equal(columns.can_view_finance, true);
  assert.equal(columns.can_edit_finance_transactions, true);
  assert.equal(columns.can_manage_company_finance_ai_memories, true);

  const technician = legacyColumnsForCapabilities(resolveAccess({ role: "employee", preset: "technician" }).capabilities);
  assert.equal(technician.can_delete_contacts, false);
  assert.equal(technician.can_view_finance, false);
  assert.equal(technician.can_use_finance_ai, false);
}

function testAdministrativeRouteClassification() {
  assert.equal(requiredAutomationCapability("GET", "/api/automations"), "automations.view");
  assert.equal(requiredAutomationCapability("POST", "/api/automations/123/manual-run"), "automations.run");
  assert.equal(requiredAutomationCapability("PATCH", "/api/automations/123"), "automations.manage");
  assert.equal(requiredFinanceCapability("GET", "/api/finance/transactions"), "finance.transactions.view");
  assert.equal(requiredFinanceCapability("POST", "/api/finance/accounts"), "finance.accounts.create");
  assert.equal(requiredFinanceCapability("POST", "/api/finance/accounts/123/balance-adjustments"), "finance.accounts.adjust");
  assert.equal(requiredFinanceCapability("PATCH", "/api/finance/ai/memories/123"), "finance.ai.manage_memory");
  assert.equal(requiredFinanceCapability("GET", "/api/finance/accounting/reports/profit-loss"), "accounting.view");
  assert.equal(requiredFinanceCapability("GET", "/api/finance/accounting/reports/job-contribution"), "accounting.view");
  assert.equal(requiredFinanceCapability("GET", "/api/finance/accounting/time-allocations"), "accounting.view");
  assert.equal(requiredFinanceCapability("PUT", "/api/finance/accounting/time-allocations/123/job-link"), "accounting.manage");
  assert.equal(requiredFinanceCapability("GET", "/api/finance/accounting/mileage-allocations"), "accounting.view");
  assert.equal(requiredFinanceCapability("GET", "/api/finance/accounting/mileage-allocations/123"), "accounting.view");
  assert.equal(requiredFinanceCapability("PUT", "/api/finance/accounting/mileage-allocations/123"), "accounting.manage");
  assert.equal(requiredFinanceCapability("GET", "/api/finance/accounting/payroll-costs"), "accounting.view");
  assert.equal(requiredFinanceCapability("PUT", "/api/finance/accounting/payroll-costs/recognition"), "accounting.manage");
  assert.equal(requiredFinanceCapability("PUT", "/api/finance/accounting/transactions/123"), "accounting.manage");
}

const tests = [
  ["catalog uniqueness and completeness", testCatalogIsUniqueAndComplete],
  ["owner invariant", testOwnerAlwaysHasEveryCapability],
  ["technician preset", testTechnicianPresetIsOperationalButRestricted],
  ["business exception access", testBusinessExceptionAccessIsLimitedToOperationalLeaders],
  ["override dependency expansion", testSparseOverrideAddsDependencies],
  ["explicit parent deny", testExplicitViewDenyCascadesToActions],
  ["invalid document validation", testInvalidDocumentsFailClosed],
  ["unknown persisted preset fallback", testUnknownPersistedPresetUsesSafeDefault],
  ["legacy permission bridge", testLegacyColumnsRemainEffective],
  ["legacy column synchronization", testLegacyColumnSynchronization],
  ["administrative route classification", testAdministrativeRouteClassification]
];

let failures = 0;
for (const [name, test] of tests) {
  try {
    test();
    console.log(`PASS ${name}`);
  } catch (error) {
    failures += 1;
    console.error(`FAIL ${name}`);
    console.error(error);
  }
}

if (failures) process.exitCode = 1;
else console.log(`Permission domain tests passed (${tests.length}).`);
