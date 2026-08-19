export const DASHBOARD_CARD_CATALOG_VERSION = 1;

export const DASHBOARD_CARD_CATALOG = Object.freeze([
  card("command_center", "Command Center", "command", ["dashboard.view"]),
  card("business_exceptions", "Business Exceptions", "exclamationmark.triangle.fill", ["dashboard.exceptions.view"]),
  card("time_clock", "Time Clock", "clock.fill", ["time.view_self"]),
  card("sales_tracking", "Sales Tracking", "chart.line.uptrend.xyaxis", ["sales.view_self"]),
  card("sales_leaderboard", "Sales Leaderboard", "trophy.fill", ["sales.view_all"]),
  card("employee_hours", "Employee Hours", "person.3.fill", ["time.view_all", "pay.view_all"]),
  card("service_plans", "Service Plans", "arrow.triangle.2.circlepath.circle.fill", [], true)
]);

export const DASHBOARD_LAYOUT_ROLE_PRESETS = Object.freeze([
  { id: "admin", name: "Admin" },
  { id: "manager", name: "Manager" },
  { id: "sales", name: "Sales" },
  { id: "technician", name: "Technician" },
  { id: "office", name: "Office" },
  { id: "legacy_employee", name: "Legacy Employee", hidden: true }
]);

const CARD_IDS = Object.freeze(DASHBOARD_CARD_CATALOG.map((item) => item.id));
const KNOWN_CARD_IDS = new Set(CARD_IDS);
const KNOWN_ROLE_PRESETS = new Set(DASHBOARD_LAYOUT_ROLE_PRESETS.map((item) => item.id));
const DEFAULT_VISIBLE_BY_PRESET = Object.freeze({
  owner: CARD_IDS,
  admin: ["command_center", "business_exceptions", "time_clock", "sales_tracking", "sales_leaderboard", "employee_hours"],
  manager: ["command_center", "business_exceptions", "time_clock", "sales_tracking", "sales_leaderboard", "employee_hours"],
  sales: ["command_center", "time_clock", "sales_tracking"],
  technician: ["command_center", "time_clock", "sales_tracking"],
  office: ["command_center", "business_exceptions", "time_clock", "sales_tracking", "sales_leaderboard"],
  legacy_employee: ["command_center", "time_clock", "sales_tracking"]
});

function card(id, title, systemImage, requiredCapabilities, ownerOnly = false) {
  return Object.freeze({
    id,
    title,
    system_image: systemImage,
    required_capabilities: Object.freeze(requiredCapabilities),
    owner_only: ownerOnly
  });
}

function invalidLayout(message, details = {}) {
  const error = new Error(message);
  error.code = "invalid_dashboard_layout";
  error.status = 400;
  error.details = details;
  return error;
}

function completeOrder(order) {
  return [...order, ...CARD_IDS.filter((id) => !order.includes(id))];
}

export function isKnownDashboardRolePreset(value) {
  return typeof value === "string" && KNOWN_ROLE_PRESETS.has(value);
}

export function validateDashboardLayout(raw, { allowLocked = false } = {}) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw invalidLayout("A Dashboard layout document is required.");
  }
  const allowedFields = new Set(["order", "hidden", "locked"]);
  const unknown = Object.keys(raw).find((key) => !allowedFields.has(key));
  if (unknown) throw invalidLayout(`Unknown Dashboard layout field: ${unknown}.`, { field: unknown });
  if (!Array.isArray(raw.order) || !raw.order.length || raw.order.length > CARD_IDS.length) {
    throw invalidLayout("Dashboard order must be a non-empty array of known card IDs.", { field: "order" });
  }
  if (!Array.isArray(raw.hidden) || raw.hidden.length > CARD_IDS.length) {
    throw invalidLayout("Hidden Dashboard cards must be an array of known card IDs.", { field: "hidden" });
  }
  if (Object.hasOwn(raw, "locked") && (!allowLocked || typeof raw.locked !== "boolean")) {
    throw invalidLayout("Locked is only valid as a boolean owner policy field.", { field: "locked" });
  }
  for (const [field, values] of [["order", raw.order], ["hidden", raw.hidden]]) {
    const seen = new Set();
    for (const id of values) {
      if (typeof id !== "string" || !KNOWN_CARD_IDS.has(id)) {
        throw invalidLayout(`Unknown ${field} Dashboard card ID.`, { field, value: id });
      }
      if (seen.has(id)) throw invalidLayout(`Duplicate ${field} Dashboard card ID: ${id}.`, { field, value: id });
      seen.add(id);
    }
  }
  const order = completeOrder(raw.order);
  const hiddenSet = new Set(raw.hidden);
  const hidden = order.filter((id) => hiddenSet.has(id));
  if (hidden.length === order.length) {
    throw invalidLayout("At least one Dashboard card must remain visible.", { field: "hidden" });
  }
  const result = { order, hidden };
  if (allowLocked) result.locked = raw.locked === true;
  return result;
}

export function sanitizePersistedDashboardLayout(raw, options = {}) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw) || Object.keys(raw).length === 0) return null;
  try {
    return validateDashboardLayout(raw, options);
  } catch {
    return null;
  }
}

export function defaultDashboardLayout({ role, preset } = {}) {
  const key = role === "employer" ? "owner" : (isKnownDashboardRolePreset(preset) ? preset : "technician");
  const visible = new Set(DEFAULT_VISIBLE_BY_PRESET[key] || DEFAULT_VISIBLE_BY_PRESET.technician);
  return { order: [...CARD_IDS], hidden: CARD_IDS.filter((id) => !visible.has(id)), locked: false };
}

export function dashboardCardCatalogPayload() {
  return {
    version: DASHBOARD_CARD_CATALOG_VERSION,
    cards: DASHBOARD_CARD_CATALOG.map((item) => ({
      ...item,
      required_capabilities: [...item.required_capabilities]
    })),
    role_presets: DASHBOARD_LAYOUT_ROLE_PRESETS.map((item) => ({ ...item }))
  };
}

export function resolveDashboardLayout({ role, preset, capabilities = {}, userPreferences, employeePolicy, rolePolicies } = {}) {
  const builtIn = defaultDashboardLayout({ role, preset });
  const rolePolicy = role === "employer" ? null : sanitizePersistedDashboardLayout(rolePolicies?.[preset], { allowLocked: true });
  const individualPolicy = role === "employer" ? null : sanitizePersistedDashboardLayout(employeePolicy, { allowLocked: true });
  const controlling = individualPolicy || rolePolicy || builtIn;
  const policySource = individualPolicy ? "employee" : (rolePolicy ? "role" : "built_in");
  const preference = sanitizePersistedDashboardLayout(userPreferences);
  const customizable = role === "employer" || controlling.locked !== true;
  const selected = customizable && preference ? preference : controlling;
  const source = customizable && preference ? "user" : policySource;
  const ordered = completeOrder(selected.order);
  const permitted = ordered.filter((id) => cardIsPermitted(id, role, capabilities));
  const selectedHidden = new Set(selected.hidden);
  let visible = permitted.filter((id) => !selectedHidden.has(id));
  if (!visible.length && permitted.length) visible = [permitted[0]];
  const visibleSet = new Set(visible);
  return {
    source,
    policy_source: policySource,
    customizable,
    preference,
    policy: { order: [...controlling.order], hidden: [...controlling.hidden], locked: controlling.locked === true },
    effective: {
      order: permitted,
      visible,
      hidden: permitted.filter((id) => !visibleSet.has(id))
    }
  };
}

function cardIsPermitted(id, role, capabilities) {
  const definition = DASHBOARD_CARD_CATALOG.find((item) => item.id === id);
  if (!definition) return false;
  if (role === "employer") return true;
  if (definition.owner_only) return false;
  return definition.required_capabilities.every((key) => capabilities?.[key] === true);
}
