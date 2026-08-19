export const TAB_CATALOG_VERSION = 1;
export const MAX_PRIMARY_TABS = 5;

export const TAB_CATALOG = Object.freeze([
  tab("dashboard", "Dashboard", "gauge.with.dots.needle.33percent", ["dashboard.view"]),
  tab("contacts", "Contacts", "person.2.fill", ["contacts.view"]),
  tab("stages", "Stages", "chart.bar.doc.horizontal.fill", ["pipeline.view"]),
  tab("schedule", "Schedule", "calendar", ["schedule.view"]),
  tab("map", "Map", "map.fill", ["operations.view"]),
  tab("messages", "Messages", "bubble.left.and.bubble.right.fill", ["messaging.customer.view", "communications.view"])
]);

const TAB_IDS = Object.freeze(TAB_CATALOG.map((item) => item.id));
const KNOWN_TAB_IDS = new Set(TAB_IDS);

const DEFAULT_ORDER_BY_PRESET = Object.freeze({
  owner: ["dashboard", "schedule", "contacts", "stages", "map", "messages"],
  admin: ["dashboard", "schedule", "contacts", "stages", "map", "messages"],
  manager: ["dashboard", "schedule", "contacts", "stages", "map", "messages"],
  sales: ["dashboard", "contacts", "stages", "schedule", "messages", "map"],
  technician: ["schedule", "map", "messages", "dashboard", "contacts", "stages"],
  office: ["schedule", "contacts", "messages", "stages", "dashboard", "map"],
  legacy_employee: ["dashboard", "contacts", "stages", "schedule", "map", "messages"]
});

export const TAB_ROLE_PRESETS = Object.freeze([
  { id: "admin", name: "Admin" },
  { id: "manager", name: "Manager" },
  { id: "sales", name: "Sales" },
  { id: "technician", name: "Technician" },
  { id: "office", name: "Office" },
  { id: "legacy_employee", name: "Legacy Employee", hidden: true }
]);

const KNOWN_ROLE_PRESETS = new Set(TAB_ROLE_PRESETS.map((item) => item.id));

function tab(id, title, systemImage, anyCapabilities) {
  return Object.freeze({ id, title, system_image: systemImage, any_capabilities: Object.freeze(anyCapabilities) });
}

function invalidLayout(message, details = {}) {
  const error = new Error(message);
  error.code = "invalid_tab_layout";
  error.status = 400;
  error.details = details;
  return error;
}

function completeOrder(order) {
  return [...order, ...TAB_IDS.filter((id) => !order.includes(id))];
}

function normalizedHidden(hidden, order) {
  const values = new Set(hidden);
  return order.filter((id) => values.has(id));
}

export function isKnownTabRolePreset(value) {
  return typeof value === "string" && KNOWN_ROLE_PRESETS.has(value);
}

export function validateTabLayout(raw, { allowLocked = false } = {}) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw invalidLayout("A tab layout document is required.");
  }

  const allowedFields = new Set(["order", "hidden", "locked"]);
  const unknownField = Object.keys(raw).find((key) => !allowedFields.has(key));
  if (unknownField) throw invalidLayout(`Unknown tab layout field: ${unknownField}.`, { field: unknownField });
  if (!Array.isArray(raw.order) || !raw.order.length || raw.order.length > TAB_IDS.length) {
    throw invalidLayout("Tab order must be a non-empty array of known tab IDs.", { field: "order" });
  }
  if (!Array.isArray(raw.hidden) || raw.hidden.length > TAB_IDS.length) {
    throw invalidLayout("Hidden tabs must be an array of known tab IDs.", { field: "hidden" });
  }
  if (Object.hasOwn(raw, "locked") && (!allowLocked || typeof raw.locked !== "boolean")) {
    throw invalidLayout("Locked is only valid as a boolean owner policy field.", { field: "locked" });
  }

  for (const [field, values] of [["order", raw.order], ["hidden", raw.hidden]]) {
    const seen = new Set();
    for (const id of values) {
      if (typeof id !== "string" || !KNOWN_TAB_IDS.has(id)) {
        throw invalidLayout(`Unknown ${field} tab ID.`, { field, value: id });
      }
      if (seen.has(id)) throw invalidLayout(`Duplicate ${field} tab ID: ${id}.`, { field, value: id });
      seen.add(id);
    }
  }

  const order = completeOrder(raw.order);
  const hidden = normalizedHidden(raw.hidden, order);
  const directCount = order.length - hidden.length;
  if (directCount < 1) {
    throw invalidLayout("At least one destination must remain in the tab bar.", { field: "hidden" });
  }
  if (directCount > MAX_PRIMARY_TABS) {
    throw invalidLayout(`At most ${MAX_PRIMARY_TABS} destinations may appear in the tab bar.`, { field: "hidden" });
  }

  const result = { order, hidden };
  if (allowLocked) result.locked = raw.locked === true;
  return result;
}

export function sanitizePersistedTabLayout(raw, options = {}) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw) || Object.keys(raw).length === 0) return null;
  try {
    return validateTabLayout(raw, options);
  } catch {
    return null;
  }
}

export function defaultTabLayout({ role, preset } = {}) {
  const key = role === "employer" ? "owner" : (isKnownTabRolePreset(preset) ? preset : "technician");
  const order = [...(DEFAULT_ORDER_BY_PRESET[key] || DEFAULT_ORDER_BY_PRESET.technician)];
  return { order, hidden: order.slice(MAX_PRIMARY_TABS), locked: false };
}

export function tabCatalogPayload() {
  return {
    version: TAB_CATALOG_VERSION,
    max_primary_tabs: MAX_PRIMARY_TABS,
    tabs: TAB_CATALOG.map((item) => ({ ...item, any_capabilities: [...item.any_capabilities] })),
    role_presets: TAB_ROLE_PRESETS.map((item) => ({ ...item }))
  };
}

export function resolveTabNavigation({ role, preset, capabilities = {}, userPreferences, employeePolicy, rolePolicies } = {}) {
  const builtIn = defaultTabLayout({ role, preset });
  const rolePolicy = role === "employer" ? null : sanitizePersistedTabLayout(rolePolicies?.[preset], { allowLocked: true });
  const individualPolicy = role === "employer" ? null : sanitizePersistedTabLayout(employeePolicy, { allowLocked: true });
  const controllingPolicy = individualPolicy || rolePolicy || builtIn;
  const policySource = individualPolicy ? "employee" : (rolePolicy ? "role" : "built_in");
  const preferences = sanitizePersistedTabLayout(userPreferences);
  const customizable = role === "employer" || controllingPolicy.locked !== true;
  const selected = customizable && preferences ? preferences : controllingPolicy;
  const source = customizable && preferences ? "user" : policySource;

  const ordered = completeOrder(selected.order);
  const allowed = ordered.filter((id) => tabIsAllowed(id, role, capabilities));
  const hidden = new Set(selected.hidden);
  let primary = allowed.filter((id) => !hidden.has(id)).slice(0, MAX_PRIMARY_TABS);
  if (!primary.length && allowed.length) primary = [allowed[0]];
  const primarySet = new Set(primary);
  const overflow = allowed.filter((id) => !primarySet.has(id));

  return {
    source,
    policy_source: policySource,
    customizable,
    preference: preferences,
    policy: { order: [...controllingPolicy.order], hidden: [...controllingPolicy.hidden], locked: controllingPolicy.locked === true },
    effective: { order: allowed, primary, overflow }
  };
}

function tabIsAllowed(id, role, capabilities) {
  if (role === "employer") return true;
  const definition = TAB_CATALOG.find((item) => item.id === id);
  return Boolean(definition?.any_capabilities.some((key) => capabilities?.[key] === true));
}
