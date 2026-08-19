export const PERMISSION_CATALOG_VERSION = 3;

export const PERMISSION_GROUPS = Object.freeze([
  group("dashboard", "Dashboard", "Command center and daily business overview."),
  group("contacts", "Contacts & Customer Information", "Customer records, exports, and destructive contact actions."),
  group("sales", "Sales, Pipeline & Quotes", "Lead stages, opportunities, quotes, and sales reporting."),
  group("schedule", "Schedule & Jobs", "Scheduling, job execution, completion, and workflow templates."),
  group("routes", "Routes", "View, build, edit, and administer field routes."),
  group("messaging", "Customer Messaging", "Customer conversations and message deletion."),
  group("communications", "Company Communication", "Internal channels, direct messages, and channel administration."),
  group("operations", "Operations", "Equipment, inventory, requests, measurements, maps, and mileage operations."),
  group("payments", "Payments", "Collect, view, manage, refund, or credit customer payments."),
  group("finance", "Finance & Accounting", "Company financial data, planning, accounting, receipts, and Finance AI."),
  group("pay", "Pay & Reports", "Personal/company pay, payroll inputs, and company sales reports."),
  group("team", "Employees & Team", "View the team and manage employee access."),
  group("automations", "Automations", "View, edit, test, run, and stop company automations."),
  group("integrations", "Integrations", "View and manage external providers, tokens, and synchronization."),
  group("settings", "Settings & Exports", "App settings, company configuration, and data exports."),
  group("ai", "AI Capabilities", "Use or administer WolfCRM AI/operator capabilities.")
]);

export const PERMISSION_CAPABILITIES = Object.freeze([
  capability("dashboard.view", "dashboard", "View dashboard", "See the command center and daily summaries."),
  capability("dashboard.exceptions.view", "dashboard", "View business exceptions", "See company-wide operational exceptions and affected records.", true, ["dashboard.view"]),
  capability("dashboard.exceptions.manage", "dashboard", "Manage business exceptions", "Snooze, dismiss, resolve, or reopen company-wide exceptions.", true, ["dashboard.exceptions.view"]),
  capability("tasks.view", "dashboard", "View tasks", "See personal tasks, routines, reminders, and logs."),
  capability("tasks.manage", "dashboard", "Manage tasks", "Create, complete, edit, or delete tasks and routines.", false, ["tasks.view"]),

  capability("contacts.view", "contacts", "View contacts", "See customer identity and contact details."),
  capability("contacts.create", "contacts", "Create contacts", "Add customers and leads.", false, ["contacts.view"]),
  capability("contacts.edit", "contacts", "Edit contacts", "Change customer and lead details.", false, ["contacts.view"]),
  capability("contacts.delete", "contacts", "Delete contacts", "Remove customer records.", true, ["contacts.view"]),
  capability("contacts.export", "contacts", "Export contacts", "Export customer information outside WolfCRM.", true, ["contacts.view"]),

  capability("pipeline.view", "sales", "View pipeline", "See stages, opportunities, and lead status."),
  capability("pipeline.manage", "sales", "Manage pipeline", "Move opportunities and configure stages.", false, ["pipeline.view"]),
  capability("quotes.view", "sales", "View quotes", "See customer estimates and quote totals."),
  capability("quotes.create", "sales", "Create quotes", "Create and send new estimates.", false, ["quotes.view", "contacts.view"]),
  capability("quotes.edit", "sales", "Edit quotes", "Change existing estimates.", false, ["quotes.view"]),
  capability("quotes.delete", "sales", "Delete quotes", "Delete estimates.", true, ["quotes.view"]),
  capability("sales.view_self", "sales", "View own sales", "See personal sales and performance."),
  capability("sales.view_all", "sales", "View company sales", "See sales and leaderboards for all employees.", true, ["sales.view_self"]),
  capability("sales.manage", "sales", "Manage sales reporting", "Manage company sales tracking inputs.", true, ["sales.view_all"]),

  capability("schedule.view", "schedule", "View schedule", "See scheduled work."),
  capability("schedule.create", "schedule", "Create jobs", "Schedule new work.", false, ["schedule.view", "contacts.view"]),
  capability("schedule.edit", "schedule", "Edit jobs", "Reschedule and edit job details.", false, ["schedule.view"]),
  capability("schedule.delete", "schedule", "Delete jobs", "Move scheduled jobs to deleted jobs.", true, ["schedule.view"]),
  capability("schedule.manage_team", "schedule", "Manage team availability", "Configure employee workdays and scheduling availability.", true, ["schedule.view", "team.view"]),
  capability("jobs.view", "schedule", "View job details", "See job workflow, services, photos, and customer details."),
  capability("jobs.work", "schedule", "Work assigned jobs", "Start jobs, update workflow, and add job photos.", false, ["jobs.view"]),
  capability("jobs.complete", "schedule", "Complete jobs", "Mark operational work complete.", false, ["jobs.view", "jobs.work"]),
  capability("jobs.manage_templates", "schedule", "Manage job workflows", "Create and edit company workflow templates.", true, ["jobs.view"]),

  capability("routes.view", "routes", "View routes", "See saved route details and stops."),
  capability("routes.create", "routes", "Build routes", "Calculate and save new routes.", false, ["routes.view", "contacts.view"]),
  capability("routes.edit", "routes", "Edit routes", "Reorder, recalculate, and update routes.", false, ["routes.view"]),
  capability("routes.manage", "routes", "Manage routes", "Administer route assignments and destructive route actions.", true, ["routes.view", "routes.edit"]),

  capability("messaging.customer.view", "messaging", "View customer messages", "Read customer SMS, iMessage, calls, and voicemail."),
  capability("messaging.customer.send", "messaging", "Message customers", "Send customer messages and place calls.", false, ["messaging.customer.view", "contacts.view"]),
  capability("messaging.customer.delete", "messaging", "Delete customer messages", "Delete conversations, messages, or voicemail.", true, ["messaging.customer.view"]),

  capability("communications.view", "communications", "View company communication", "Read internal channels and direct messages."),
  capability("communications.send", "communications", "Send company messages", "Post to internal channels and direct messages.", false, ["communications.view"]),
  capability("communications.manage", "communications", "Manage company communication", "Create or remove shared channels and conversations.", true, ["communications.view", "communications.send"]),

  capability("operations.view", "operations", "View operations", "See equipment, inventory, maps, measurements, requests, and mileage."),
  capability("operations.request", "operations", "Submit operations requests", "Request equipment/materials and submit mileage items.", false, ["operations.view"]),
  capability("operations.manage", "operations", "Manage operations", "Manage inventory, requests, maps, measurements, and mileage approvals.", true, ["operations.view"]),

  capability("payments.collect", "payments", "Collect payments", "Take customer and service-plan payments.", true, ["contacts.view"]),
  capability("payments.view", "payments", "View payments", "See company payment records and amounts.", true),
  capability("payments.manage", "payments", "Manage payments", "Manage payment plans and provider operations.", true, ["payments.view"]),
  capability("payments.refund", "payments", "Refund or credit payments", "Issue refunds or customer credits when supported.", true, ["payments.view", "payments.manage"]),

  capability("finance.view", "finance", "View Finance", "See company accounts, transactions, receipts, budgets, goals, and debts.", true),
  capability("finance.manage", "finance", "Manage Finance", "Create or edit company financial records and planning.", true, ["finance.view"]),
  capability("finance.transactions.view", "finance", "View transactions", "See company financial transactions.", true, ["finance.view"]),
  capability("finance.transactions.edit", "finance", "Edit transactions", "Create, classify, or edit financial transactions.", true, ["finance.transactions.view"]),
  capability("finance.accounts.view", "finance", "View accounts", "See company financial accounts and balances.", true, ["finance.view"]),
  capability("finance.accounts.create", "finance", "Create accounts", "Add company financial accounts.", true, ["finance.accounts.view"]),
  capability("finance.accounts.edit", "finance", "Edit accounts", "Change or archive company financial accounts.", true, ["finance.accounts.view"]),
  capability("finance.accounts.adjust", "finance", "Adjust balances", "Post manual balance adjustments.", true, ["finance.accounts.view", "finance.accounts.edit"]),
  capability("finance.receipts.view", "finance", "View receipts", "See company receipts and receipt images.", true, ["finance.view"]),
  capability("finance.receipts.edit", "finance", "Edit receipts", "Upload, match, or change receipts.", true, ["finance.receipts.view"]),
  capability("finance.planning.view", "finance", "View planning", "See projections and planned financial items.", true, ["finance.view"]),
  capability("finance.planning.edit", "finance", "Edit planning", "Create or change planned financial items.", true, ["finance.planning.view"]),
  capability("finance.budgets.view", "finance", "View budgets", "See company budgets and progress.", true, ["finance.view"]),
  capability("finance.budgets.edit", "finance", "Edit budgets", "Create or change company budgets.", true, ["finance.budgets.view"]),
  capability("finance.goals.view", "finance", "View goals", "See company financial goals.", true, ["finance.view"]),
  capability("finance.goals.edit", "finance", "Edit goals", "Create, contribute to, or change financial goals.", true, ["finance.goals.view"]),
  capability("finance.debts.view", "finance", "View debts", "See company debts and payoff details.", true, ["finance.view"]),
  capability("finance.debts.edit", "finance", "Edit debts", "Create, pay, or change company debts.", true, ["finance.debts.view"]),
  capability("finance.settings.view", "finance", "View Finance settings", "See Finance configuration.", true, ["finance.view"]),
  capability("finance.settings.edit", "finance", "Edit Finance settings", "Change Finance configuration and connections.", true, ["finance.settings.view"]),
  capability("finance.ai.use", "finance", "Use Finance AI", "Use AI with permitted company finance data.", true, ["finance.view", "ai.use"]),
  capability("finance.ai.manage_memory", "finance", "Manage Finance AI memory", "Change company-wide Finance AI memory.", true, ["finance.ai.use", "ai.manage"]),
  capability("accounting.view", "finance", "View accounting", "See accounting records and reports.", true, ["finance.view"]),
  capability("accounting.manage", "finance", "Manage accounting", "Classify, reconcile, and edit accounting records.", true, ["accounting.view", "finance.transactions.view", "finance.manage"]),

  capability("pay.view_self", "pay", "View own pay", "See personal pay and mileage reimbursement."),
  capability("pay.view_all", "pay", "View employee pay", "See pay information for all employees.", true, ["pay.view_self"]),
  capability("pay.manage", "pay", "Manage pay", "Configure pay structures and approve pay/mileage items.", true, ["pay.view_all"]),
  capability("time.view_self", "pay", "View own time", "See personal time-clock entries."),
  capability("time.clock", "pay", "Use time clock", "Clock in, clock out, and submit personal time entries.", false, ["time.view_self"]),
  capability("time.view_all", "pay", "View company time", "See time-clock entries for all employees.", true, ["time.view_self"]),
  capability("time.manage", "pay", "Manage company time", "Configure, correct, approve, or delete employee time entries.", true, ["time.view_all"]),

  capability("team.view", "team", "View team", "See active company employees."),
  capability("team.manage", "team", "Manage employees", "Change employee access, deactivate, and restore accounts.", true, ["team.view"]),

  capability("automations.view", "automations", "View automations", "See company automation definitions and runs."),
  capability("automations.manage", "automations", "Manage automations", "Create, publish, archive, and emergency-stop automations.", true, ["automations.view"]),
  capability("automations.run", "automations", "Run automations", "Test, manually run, retry, or cancel automation runs.", true, ["automations.view"]),

  capability("integrations.view", "integrations", "View integrations", "See integration connection and health status."),
  capability("integrations.manage", "integrations", "Manage integrations", "Change provider credentials, tokens, synchronization, and phone setup.", true, ["integrations.view"]),

  capability("settings.view", "settings", "View settings", "See app and permitted company settings."),
  capability("settings.manage_company", "settings", "Manage company settings", "Change company-wide configuration.", true, ["settings.view"]),
  capability("exports.run", "settings", "Run exports", "Export company or customer information.", true),

  capability("ai.use", "ai", "Use AI capabilities", "Use enabled WolfCRM AI assistants."),
  capability("ai.manage", "ai", "Manage AI", "Manage company AI policies, memory, and actions.", true, ["ai.use"])
]);

const ALL_KEYS = Object.freeze(PERMISSION_CAPABILITIES.map((item) => item.key));
const KNOWN_KEYS = new Set(ALL_KEYS);
const CAPABILITY_BY_KEY = new Map(PERMISSION_CAPABILITIES.map((item) => [item.key, item]));

const legacyEmployee = new Set(ALL_KEYS.filter((key) => !key.startsWith("finance.") && !key.startsWith("accounting.") && ![
  "dashboard.exceptions.view", "dashboard.exceptions.manage",
  "contacts.delete", "contacts.export", "sales.view_all", "sales.manage",
  "jobs.manage_templates", "routes.manage", "communications.manage",
  "operations.manage", "payments.manage", "payments.refund",
  "pay.view_all", "pay.manage", "time.view_all", "time.manage", "team.manage", "automations.view",
  "automations.manage", "automations.run", "integrations.manage",
  "settings.manage_company", "exports.run", "ai.use", "ai.manage"
].includes(key)));

const PRESET_KEYS = Object.freeze({
  admin: new Set(ALL_KEYS),
  manager: keys(
    "dashboard.*", "tasks.*", "contacts.*", "pipeline.*", "quotes.*", "sales.*",
    "schedule.*", "jobs.*", "routes.*", "messaging.customer.*",
    "communications.*", "operations.*", "payments.collect", "payments.view",
    "pay.view_self", "pay.view_all", "time.*", "team.view", "automations.view",
    "automations.run", "integrations.view", "settings.view", "exports.run", "ai.use"
  ),
  sales: keys(
    "dashboard.view", "tasks.*", "contacts.view", "contacts.create", "contacts.edit",
    "pipeline.*", "quotes.*", "sales.view_self", "schedule.view",
    "schedule.create", "schedule.edit", "jobs.view", "routes.view",
    "routes.create", "messaging.customer.view", "messaging.customer.send",
    "communications.view", "communications.send", "payments.collect",
    "payments.view", "pay.view_self", "time.view_self", "time.clock", "settings.view", "ai.use"
  ),
  technician: keys(
    "dashboard.view", "tasks.*", "contacts.view", "schedule.view", "jobs.view", "jobs.work",
    "jobs.complete", "routes.view", "messaging.customer.view",
    "messaging.customer.send", "communications.view", "communications.send",
    "operations.view", "operations.request", "payments.collect", "pay.view_self", "time.view_self", "time.clock",
    "sales.view_self", "settings.view"
  ),
  office: keys(
    "dashboard.view", "dashboard.exceptions.view", "dashboard.exceptions.manage", "tasks.*", "contacts.view", "contacts.create", "contacts.edit",
    "pipeline.*", "quotes.*", "sales.view_self", "sales.view_all",
    "schedule.*", "jobs.view", "jobs.work", "routes.view", "routes.create",
    "routes.edit", "messaging.customer.view", "messaging.customer.send",
    "communications.*", "operations.*", "payments.collect", "payments.view",
    "payments.manage", "pay.view_self", "time.view_self", "time.clock", "time.view_all", "team.view", "automations.view",
    "integrations.view", "settings.view", "exports.run", "ai.use"
  ),
  legacy_employee: legacyEmployee
});

export const PERMISSION_PRESETS = Object.freeze([
  preset("admin", "Admin", "Broad delegated administration; ownership remains protected."),
  preset("manager", "Manager", "Runs day-to-day staff, schedule, jobs, routes, and operations."),
  preset("sales", "Sales", "Contacts, pipeline, quotes, customer communication, and personal sales."),
  preset("technician", "Technician", "Assigned jobs, routes, customer communication, time, and personal pay."),
  preset("office", "Office", "Coordinates customers, scheduling, jobs, routes, messages, and payments."),
  preset("legacy_employee", "Legacy Employee", "Preserves the pre-permissions operational surface.", true)
]);

export function permissionCatalogPayload() {
  return {
    version: PERMISSION_CATALOG_VERSION,
    groups: PERMISSION_GROUPS.map((value) => ({ ...value })),
    presets: PERMISSION_PRESETS.map((value) => ({
      ...value,
      capabilities: effectivePresetCapabilities(value.id)
    })),
    capabilities: PERMISSION_CAPABILITIES.map((value) => ({ ...value, depends_on: [...value.depends_on] }))
  };
}

export function validateAccessUpdate(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw invalidDocument("An access document is required.");
  const presetId = cleanPreset(raw.preset);
  if (!presetId) throw invalidDocument("Unknown permission preset.", { field: "preset" });
  const source = raw.overrides ?? {};
  if (!source || typeof source !== "object" || Array.isArray(source)) {
    throw invalidDocument("Permission overrides must be an object.", { field: "overrides" });
  }
  const entries = Object.entries(source);
  if (entries.length > ALL_KEYS.length) throw invalidDocument("Too many permission overrides.", { field: "overrides" });
  const overrides = {};
  for (const [key, value] of entries) {
    if (!KNOWN_KEYS.has(key)) throw invalidDocument(`Unknown capability: ${key}.`, { field: `overrides.${key}` });
    if (typeof value !== "boolean") throw invalidDocument(`Capability ${key} must be true or false.`, { field: `overrides.${key}` });
    overrides[key] = value;
  }

  const presetCapabilities = effectivePresetCapabilities(presetId);
  const effective = normalizeCapabilities({ ...presetCapabilities, ...overrides }, overrides);
  const sparse = {};
  for (const key of ALL_KEYS) {
    if (effective[key] !== presetCapabilities[key]) sparse[key] = effective[key];
  }
  return { preset: presetId, overrides: sparse, capabilities: effective };
}

export function resolveAccess({ role, preset: rawPreset, overrides, legacy = {} } = {}) {
  if (role === "employer") {
    return { preset: "owner", overrides: {}, capabilities: Object.fromEntries(ALL_KEYS.map((key) => [key, true])) };
  }
  const presetId = cleanPreset(rawPreset) || "technician";
  const safeOverrides = cleanOverrides(overrides);
  let merged = { ...effectivePresetCapabilities(presetId) };
  if (presetId === "legacy_employee") merged = { ...merged, ...legacyCapabilityBridge(legacy) };
  merged = { ...merged, ...safeOverrides };
  return {
    preset: presetId,
    overrides: safeOverrides,
    capabilities: normalizeCapabilities(merged, safeOverrides)
  };
}

export function hasCapability(context, key) {
  if (!KNOWN_KEYS.has(key)) return false;
  if (context?.role === "employer") return true;
  return Boolean(context?.permissions?.capabilities?.[key] ?? context?.capabilities?.[key]);
}

export function legacyColumnsForCapabilities(capabilities = {}) {
  const financeManage = Boolean(capabilities["finance.manage"]);
  const financeView = Boolean(capabilities["finance.view"] || financeManage);
  const aiUse = Boolean(capabilities["ai.use"]);
  const aiManage = Boolean(capabilities["ai.manage"]);
  return {
    can_delete_contacts: Boolean(capabilities["contacts.delete"]),
    can_view_finance: financeView,
    can_use_finance_ai: aiUse,
    can_view_finance_transactions: Boolean(capabilities["finance.transactions.view"] || financeManage),
    can_edit_finance_transactions: Boolean(capabilities["finance.transactions.edit"] || financeManage),
    can_view_finance_accounts: Boolean(capabilities["finance.accounts.view"] || financeManage),
    can_create_finance_accounts: Boolean(capabilities["finance.accounts.create"] || financeManage),
    can_edit_finance_accounts: Boolean(capabilities["finance.accounts.edit"] || financeManage),
    can_adjust_finance_account_balances: Boolean(capabilities["finance.accounts.adjust"] || financeManage),
    can_view_finance_receipts: Boolean(capabilities["finance.receipts.view"] || financeManage),
    can_edit_finance_receipts: Boolean(capabilities["finance.receipts.edit"] || financeManage),
    can_view_finance_planning: Boolean(capabilities["finance.planning.view"] || financeManage),
    can_edit_finance_planning: Boolean(capabilities["finance.planning.edit"] || financeManage),
    can_view_finance_budgets: Boolean(capabilities["finance.budgets.view"] || financeManage),
    can_edit_finance_budgets: Boolean(capabilities["finance.budgets.edit"] || financeManage),
    can_view_finance_goals: Boolean(capabilities["finance.goals.view"] || financeManage),
    can_edit_finance_goals: Boolean(capabilities["finance.goals.edit"] || financeManage),
    can_view_finance_debts: Boolean(capabilities["finance.debts.view"] || financeManage),
    can_edit_finance_debts: Boolean(capabilities["finance.debts.edit"] || financeManage),
    can_view_finance_settings: Boolean(capabilities["finance.settings.view"] || financeManage),
    can_edit_finance_settings: Boolean(capabilities["finance.settings.edit"] || financeManage),
    can_manage_company_finance_ai_memories: Boolean(capabilities["finance.ai.manage_memory"] || aiManage)
  };
}

export function isKnownCapability(key) {
  return KNOWN_KEYS.has(key);
}

export function requiredAutomationCapability(method, path = "") {
  if (/manual-run|\/test|\/retry|\/cancel/.test(path)) return "automations.run";
  return method === "GET" ? "automations.view" : "automations.manage";
}

export function requiredFinanceCapability(method, path = "") {
  const isRead = method === "GET";
  if (path.includes("/finance/accounting")) {
    return isRead ? "accounting.view" : "accounting.manage";
  }
  if (path.includes("/finance/ai")) {
    return !isRead && /memor/.test(path) ? "finance.ai.manage_memory" : "finance.ai.use";
  }
  if (path.includes("/receipts")) return isRead ? "finance.receipts.view" : "finance.receipts.edit";
  if (path.includes("/transactions") || path.includes("/recurring")) {
    return isRead ? "finance.transactions.view" : "finance.transactions.edit";
  }
  if (path.includes("/accounts")) {
    if (isRead) return "finance.accounts.view";
    if (path.includes("balance-adjustments")) return "finance.accounts.adjust";
    if (method === "POST" && path === "/api/finance/accounts") return "finance.accounts.create";
    return "finance.accounts.edit";
  }
  if (path.includes("/planned-items") || path.includes("/projection")) {
    return isRead ? "finance.planning.view" : "finance.planning.edit";
  }
  if (path.includes("/budgets") || path.includes("/budget-summary")) {
    return isRead ? "finance.budgets.view" : "finance.budgets.edit";
  }
  if (path.includes("/goals")) return isRead ? "finance.goals.view" : "finance.goals.edit";
  if (path.includes("/debts")) return isRead ? "finance.debts.view" : "finance.debts.edit";
  if (path.includes("/settings") || path.includes("/plaid")) {
    return isRead ? "finance.settings.view" : "finance.settings.edit";
  }
  return isRead ? "finance.view" : "finance.manage";
}

function normalizeCapabilities(source, explicit = {}) {
  const result = Object.fromEntries(ALL_KEYS.map((key) => [key, Boolean(source[key])]));
  let changed = true;
  while (changed) {
    changed = false;
    for (const item of PERMISSION_CAPABILITIES) {
      if (!result[item.key]) continue;
      for (const dependency of item.depends_on) {
        if (explicit[dependency] === false) {
          result[item.key] = false;
          changed = true;
          break;
        }
        if (!result[dependency]) {
          result[dependency] = true;
          changed = true;
        }
      }
    }
  }
  return result;
}

function effectivePresetCapabilities(id) {
  const enabled = PRESET_KEYS[id] || PRESET_KEYS.technician;
  return normalizeCapabilities(Object.fromEntries(ALL_KEYS.map((key) => [key, enabled.has(key)])));
}

function legacyCapabilityBridge(row) {
  const globalFinanceView = legacyBoolean(row, "can_view_finance");
  const anyFinanceManage = [
    "can_edit_finance_transactions", "can_create_finance_accounts", "can_edit_finance_accounts",
    "can_adjust_finance_account_balances", "can_edit_finance_receipts", "can_edit_finance_planning",
    "can_edit_finance_budgets", "can_edit_finance_goals", "can_edit_finance_debts", "can_edit_finance_settings"
  ].some((key) => legacyBoolean(row, key));
  const anyFinanceView = globalFinanceView || [
    "can_view_finance_transactions", "can_view_finance_accounts", "can_view_finance_receipts",
    "can_view_finance_planning", "can_view_finance_budgets", "can_view_finance_goals",
    "can_view_finance_debts", "can_view_finance_settings"
  ].some((key) => legacyBoolean(row, key));
  return {
    "contacts.delete": legacyBoolean(row, "can_delete_contacts"),
    "finance.view": anyFinanceView || anyFinanceManage,
    "finance.manage": false,
    "finance.transactions.view": globalFinanceView || legacyBoolean(row, "can_view_finance_transactions"),
    "finance.transactions.edit": legacyBoolean(row, "can_edit_finance_transactions"),
    "finance.accounts.view": globalFinanceView || legacyBoolean(row, "can_view_finance_accounts"),
    "finance.accounts.create": legacyBoolean(row, "can_create_finance_accounts"),
    "finance.accounts.edit": legacyBoolean(row, "can_edit_finance_accounts"),
    "finance.accounts.adjust": legacyBoolean(row, "can_adjust_finance_account_balances"),
    "finance.receipts.view": globalFinanceView || legacyBoolean(row, "can_view_finance_receipts"),
    "finance.receipts.edit": legacyBoolean(row, "can_edit_finance_receipts"),
    "finance.planning.view": globalFinanceView || legacyBoolean(row, "can_view_finance_planning"),
    "finance.planning.edit": legacyBoolean(row, "can_edit_finance_planning"),
    "finance.budgets.view": globalFinanceView || legacyBoolean(row, "can_view_finance_budgets"),
    "finance.budgets.edit": legacyBoolean(row, "can_edit_finance_budgets"),
    "finance.goals.view": globalFinanceView || legacyBoolean(row, "can_view_finance_goals"),
    "finance.goals.edit": legacyBoolean(row, "can_edit_finance_goals"),
    "finance.debts.view": globalFinanceView || legacyBoolean(row, "can_view_finance_debts"),
    "finance.debts.edit": legacyBoolean(row, "can_edit_finance_debts"),
    "finance.settings.view": globalFinanceView || legacyBoolean(row, "can_view_finance_settings"),
    "finance.settings.edit": legacyBoolean(row, "can_edit_finance_settings"),
    "finance.ai.use": legacyBoolean(row, "can_use_finance_ai"),
    "finance.ai.manage_memory": legacyBoolean(row, "can_manage_company_finance_ai_memories"),
    "accounting.view": anyFinanceView || anyFinanceManage,
    "accounting.manage": false,
    "ai.use": legacyBoolean(row, "can_use_finance_ai"),
    "ai.manage": legacyBoolean(row, "can_manage_company_finance_ai_memories")
  };
}

function legacyBoolean(row, snakeKey) {
  if (typeof row?.[snakeKey] === "boolean") return row[snakeKey];
  const camelKey = snakeKey.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());
  return Boolean(row?.[camelKey]);
}

function cleanOverrides(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return Object.fromEntries(Object.entries(value).filter(([key, item]) => KNOWN_KEYS.has(key) && typeof item === "boolean"));
}

function cleanPreset(value) {
  return typeof value === "string" && Object.hasOwn(PRESET_KEYS, value) ? value : null;
}

function keys(...patterns) {
  const result = new Set();
  for (const pattern of patterns) {
    if (pattern.endsWith(".*")) {
      const prefix = pattern.slice(0, -1);
      for (const key of ALL_KEYS) if (key.startsWith(prefix)) result.add(key);
    } else if (KNOWN_KEYS.has(pattern)) {
      result.add(pattern);
    }
  }
  return result;
}

function group(id, title, description) {
  return Object.freeze({ id, title, description });
}

function capability(key, groupId, label, description, highRisk = false, dependsOn = []) {
  return Object.freeze({ key, group_id: groupId, label, description, high_risk: highRisk, depends_on: Object.freeze(dependsOn) });
}

function preset(id, name, description, hidden = false) {
  return Object.freeze({ id, name, description, hidden });
}

function invalidDocument(message, details = null) {
  const error = new Error(message);
  error.code = "invalid_permission_document";
  error.statusCode = 400;
  error.details = details;
  return error;
}
