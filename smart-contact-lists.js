export const SMART_CONTACT_LIST_LIMITS = Object.freeze({
  maximumSourceContacts: 2_000,
  maximumReturnedContacts: 500,
  maximumFilterValues: 50,
  maximumTextLength: 120,
  maximumSavedLists: 100,
  maximumSnapshotContacts: 500,
  maximumNameLength: 80,
  maximumBulkTasks: 100,
  maximumTaskTitleLength: 160,
  maximumTaskDetailLength: 4_000,
  maximumTaskAssignees: 20,
  maximumBulkSMSContacts: 100,
  maximumSMSBodyLength: 1_600
});

export class SmartContactListError extends Error {
  constructor(code, message, { statusCode = 400, details = null } = {}) {
    super(message);
    this.name = "SmartContactListError";
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
  }
}

export function validateSmartContactFilters(raw = {}) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw invalidFilters();
  const allowedKeys = new Set([
    "version", "distance_mode", "radius_miles", "origin", "stage_ids", "not_stage_ids",
    "previous_customer", "job_completed_before", "job_completed_months_ago", "never_scheduled",
    "lost_lead", "quote", "quote_min_age_days", "quote_max_age_days", "tags_any", "tags_all",
    "tags_none", "job_types", "sources", "no_recent_contact_days", "minimum_value_cents",
    "maximum_value_cents", "routable_only", "sort", "limit"
  ]);
  const unknownKeys = Object.keys(raw).filter((key) => !allowedKeys.has(key));
  if (unknownKeys.length) {
    throw new SmartContactListError(
      "smart_contacts_filters_invalid",
      `Unsupported smart contact filter: ${unknownKeys[0]}.`,
      { details: { fields: unknownKeys.join(",") } }
    );
  }
  const version = raw.version == null ? 1 : integer(raw.version, 1, 1, "version");
  if (raw.distance_mode != null && !["none", "inside", "outside"].includes(raw.distance_mode)) throw invalidFilters();
  const distanceMode = ["none", "inside", "outside"].includes(raw.distance_mode) ? raw.distance_mode : "none";
  const radiusMiles = raw.radius_miles == null ? null : finite(raw.radius_miles, 0.1, 500, "radius_miles");
  const origin = normalizeOrigin(raw.origin);
  if (distanceMode !== "none" && (!origin || radiusMiles == null)) {
    throw new SmartContactListError("smart_contacts_origin_required", "Choose an origin and radius for the distance filter.");
  }
  if (distanceMode === "none" && (origin || radiusMiles != null)) {
    throw new SmartContactListError("smart_contacts_distance_filter_invalid", "Choose Inside or Outside to use an origin or radius.");
  }

  const previousCustomer = boolean(raw.previous_customer, "previous_customer");
  const neverScheduled = boolean(raw.never_scheduled, "never_scheduled");
  if (previousCustomer && neverScheduled) {
    throw new SmartContactListError("smart_contacts_filters_conflict", "Previous customer and Never scheduled cannot be combined.");
  }
  if (raw.quote != null && !["any", "exists", "none"].includes(raw.quote)) throw invalidFilters();
  const quote = ["any", "exists", "none"].includes(raw.quote) ? raw.quote : "any";
  const quoteMinAgeDays = optionalInteger(raw.quote_min_age_days, 0, 3_650, "quote_min_age_days");
  const quoteMaxAgeDays = optionalInteger(raw.quote_max_age_days, 0, 3_650, "quote_max_age_days");
  if ((quoteMinAgeDays != null || quoteMaxAgeDays != null) && quote === "none") {
    throw new SmartContactListError("smart_contacts_filters_conflict", "Quote age cannot be used with No quote.");
  }
  if (quoteMinAgeDays != null && quoteMaxAgeDays != null && quoteMinAgeDays > quoteMaxAgeDays) {
    throw new SmartContactListError("smart_contacts_filters_conflict", "Minimum quote age cannot exceed maximum quote age.");
  }
  const minimumValueCents = optionalInteger(raw.minimum_value_cents, 0, 100_000_000_000, "minimum_value_cents");
  const maximumValueCents = optionalInteger(raw.maximum_value_cents, 0, 100_000_000_000, "maximum_value_cents");
  if (minimumValueCents != null && maximumValueCents != null && minimumValueCents > maximumValueCents) {
    throw new SmartContactListError("smart_contacts_filters_conflict", "Minimum customer value cannot exceed maximum customer value.");
  }

  if (raw.sort != null && !["distance", "value_desc", "last_contact_oldest", "name"].includes(raw.sort)) throw invalidFilters();
  const sort = ["distance", "value_desc", "last_contact_oldest", "name"].includes(raw.sort) ? raw.sort : (distanceMode === "none" ? "name" : "distance");
  if (sort === "distance" && distanceMode === "none") {
    throw new SmartContactListError("smart_contacts_filters_conflict", "Distance sorting requires an Inside or Outside radius filter.");
  }
  const stageIDs = stringList(raw.stage_ids, "stage_ids", { lower: false });
  const notStageIDs = stringList(raw.not_stage_ids, "not_stage_ids", { lower: false });
  if (stageIDs.some((id) => notStageIDs.includes(id))) {
    throw new SmartContactListError("smart_contacts_filters_conflict", "A stage cannot be both required and excluded.");
  }
  return {
    version,
    distance_mode: distanceMode,
    radius_miles: radiusMiles,
    origin,
    stage_ids: stageIDs,
    not_stage_ids: notStageIDs,
    previous_customer: previousCustomer,
    job_completed_before: optionalDate(raw.job_completed_before, "job_completed_before"),
    job_completed_months_ago: optionalInteger(raw.job_completed_months_ago, 1, 240, "job_completed_months_ago"),
    never_scheduled: neverScheduled,
    lost_lead: boolean(raw.lost_lead, "lost_lead"),
    quote,
    quote_min_age_days: quoteMinAgeDays,
    quote_max_age_days: quoteMaxAgeDays,
    tags_any: stringList(raw.tags_any, "tags_any"),
    tags_all: stringList(raw.tags_all, "tags_all"),
    tags_none: stringList(raw.tags_none, "tags_none"),
    job_types: stringList(raw.job_types, "job_types"),
    sources: stringList(raw.sources, "sources"),
    no_recent_contact_days: optionalInteger(raw.no_recent_contact_days, 1, 3_650, "no_recent_contact_days"),
    minimum_value_cents: minimumValueCents,
    maximum_value_cents: maximumValueCents,
    routable_only: boolean(raw.routable_only, "routable_only"),
    sort,
    limit: optionalInteger(raw.limit, 1, SMART_CONTACT_LIST_LIMITS.maximumReturnedContacts, "limit") || 200
  };
}

export function validateSmartContactListName(value) {
  const name = clean(value).replace(/\s+/g, " ");
  if (!name || name.length > SMART_CONTACT_LIST_LIMITS.maximumNameLength || /[\u0000-\u001f\u007f]/.test(name)) {
    throw new SmartContactListError(
      "smart_contact_list_name_invalid",
      `List names must contain 1–${SMART_CONTACT_LIST_LIMITS.maximumNameLength} visible characters.`
    );
  }
  return name;
}

export function validateSmartContactListMode(value) {
  if (value !== "dynamic" && value !== "snapshot") {
    throw new SmartContactListError(
      "smart_contact_list_mode_invalid",
      "Choose a Dynamic or Snapshot saved list."
    );
  }
  return value;
}

export function prepareSmartContactListPersistence({
  mode,
  filters = {},
  contact_ids = [],
  origin_policy = "transient"
} = {}) {
  const normalizedMode = validateSmartContactListMode(mode);
  if (origin_policy !== "transient" && origin_policy !== "fixed") {
    throw new SmartContactListError(
      "smart_contact_list_origin_policy_invalid",
      "Choose whether this geographic origin is transient or a saved fixed location."
    );
  }
  const normalizedFilters = validateSmartContactFilters(filters);
  let persistedFilters = serializeFilters(normalizedFilters);
  let originRedacted = false;

  if (normalizedFilters.distance_mode !== "none" && origin_policy === "transient") {
    if (normalizedMode === "dynamic") {
      throw new SmartContactListError(
        "smart_contact_list_fixed_origin_required",
        "Dynamic geographic lists require an explicitly saved fixed origin."
      );
    }
    persistedFilters = {
      ...persistedFilters,
      distance_mode: "none",
      radius_miles: null,
      origin: null,
      sort: normalizedFilters.sort === "distance" ? "name" : normalizedFilters.sort
    };
    originRedacted = true;
  }

  if (normalizedFilters.distance_mode !== "none" && origin_policy === "fixed" && !clean(normalizedFilters.origin?.label)) {
    throw new SmartContactListError(
      "smart_contact_list_origin_label_required",
      "Name the fixed origin before saving this geographic list."
    );
  }

  const contactIDs = normalizeSnapshotContactIDs(contact_ids);
  if (normalizedMode === "snapshot" && !contactIDs.length) {
    throw new SmartContactListError(
      "smart_contact_list_snapshot_empty",
      "Select at least one contact before saving a Snapshot list."
    );
  }
  if (normalizedMode === "dynamic" && contactIDs.length) {
    throw new SmartContactListError(
      "smart_contact_list_members_not_allowed",
      "Dynamic lists are defined by filters and cannot store snapshot members."
    );
  }

  return {
    mode: normalizedMode,
    filters: persistedFilters,
    filter_version: normalizedFilters.version,
    contact_ids: contactIDs,
    origin_redacted: originRedacted
  };
}

export function validateSmartContactTaskAction(raw = {}) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new SmartContactListError("smart_contact_task_request_invalid", "The bulk task request is invalid.");
  }
  const allowedKeys = new Set([
    "contact_ids", "title_template", "detail_template", "due_date", "priority",
    "assignee_ids", "source_list_id", "filters", "idempotency_key"
  ]);
  const unknown = Object.keys(raw).filter((key) => !allowedKeys.has(key));
  if (unknown.length) {
    throw new SmartContactListError(
      "smart_contact_task_request_invalid",
      `Unsupported bulk task field: ${unknown[0]}.`,
      { details: { fields: unknown.join(",") } }
    );
  }

  const contactIDs = normalizeUUIDList(raw.contact_ids, {
    field: "contact_ids",
    maximum: SMART_CONTACT_LIST_LIMITS.maximumBulkTasks,
    minimum: 1,
    errorCode: "smart_contact_task_contacts_invalid"
  });
  const titleTemplate = clean(raw.title_template).replace(/\s+/g, " ");
  if (!titleTemplate || titleTemplate.length > SMART_CONTACT_LIST_LIMITS.maximumTaskTitleLength || /[\u0000-\u001f\u007f]/.test(titleTemplate)) {
    throw new SmartContactListError(
      "smart_contact_task_title_invalid",
      `Task titles must contain 1–${SMART_CONTACT_LIST_LIMITS.maximumTaskTitleLength} visible characters.`
    );
  }
  const detailTemplate = raw.detail_template == null ? null : String(raw.detail_template).trim();
  if ((detailTemplate?.length || 0) > SMART_CONTACT_LIST_LIMITS.maximumTaskDetailLength || /[\u0000\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(detailTemplate || "")) {
    throw new SmartContactListError(
      "smart_contact_task_detail_invalid",
      `Task details may contain at most ${SMART_CONTACT_LIST_LIMITS.maximumTaskDetailLength} characters.`
    );
  }
  const dueDate = raw.due_date == null || raw.due_date === "" ? null : validDate(raw.due_date);
  if (raw.due_date != null && raw.due_date !== "" && !dueDate) {
    throw new SmartContactListError("smart_contact_task_due_date_invalid", "Choose a valid task due date.");
  }
  const priority = raw.priority == null ? "normal" : clean(raw.priority).toLowerCase();
  if (!["low", "normal", "high", "urgent"].includes(priority)) {
    throw new SmartContactListError("smart_contact_task_priority_invalid", "Choose a valid task priority.");
  }
  const assigneeIDs = normalizeUUIDList(raw.assignee_ids || [], {
    field: "assignee_ids",
    maximum: SMART_CONTACT_LIST_LIMITS.maximumTaskAssignees,
    minimum: 0,
    errorCode: "smart_contact_task_assignees_invalid"
  });
  const sourceListID = optionalUUID(raw.source_list_id, "smart_contact_task_source_list_invalid");
  const idempotencyKey = optionalUUID(raw.idempotency_key, "smart_contact_task_idempotency_key_required");
  if (!idempotencyKey) {
    throw new SmartContactListError(
      "smart_contact_task_idempotency_key_required",
      "Reload the task confirmation and try again."
    );
  }
  const filters = validateSmartContactFilters(raw.filters || {});

  return {
    contact_ids: contactIDs,
    title_template: titleTemplate,
    detail_template: detailTemplate || null,
    due_date: dueDate?.toISOString() || null,
    priority,
    assignee_ids: assigneeIDs,
    source_list_id: sourceListID,
    filters: redactSmartContactFiltersForAudit(filters),
    idempotency_key: idempotencyKey
  };
}

export function renderSmartContactTaskTemplate(template, contactName) {
  const name = clean(contactName) || "Contact";
  return String(template || "").replaceAll("{{contact}}", name);
}

export function validateSmartContactSMSPreview(raw = {}) {
  return validateSmartContactSMSRequest(raw, false);
}

export function validateSmartContactSMSSend(raw = {}) {
  return validateSmartContactSMSRequest(raw, true);
}

export function renderSmartContactSMSTemplate(template, { contactName, companyName } = {}) {
  return String(template || "")
    .replaceAll("{{contact}}", clean(contactName) || "there")
    .replaceAll("{{company}}", clean(companyName) || "Our team");
}

export function smartContactSMSRequestSnapshot(action = {}) {
  return {
    campaign_type: "marketing",
    contact_ids: Array.isArray(action.contact_ids) ? action.contact_ids : [],
    message_template: action.message_template || "",
    source_list_id: action.source_list_id || null,
    filters: action.filters || {}
  };
}

export function evaluateSmartContactSMSEligibility({
  contactExists = true,
  phoneValid = false,
  consentStatus = null,
  recipientTimeZone = null,
  providerReady = true,
  now = new Date()
} = {}) {
  if (!contactExists) return { eligible: false, reason: "contact_not_found" };
  if (!phoneValid) return { eligible: false, reason: "invalid_phone" };
  if (consentStatus === "opted_out") return { eligible: false, reason: "opted_out" };
  if (consentStatus !== "opted_in") return { eligible: false, reason: "marketing_consent_required" };
  if (!clean(recipientTimeZone)) return { eligible: false, reason: "recipient_timezone_unknown" };
  const localHour = hourInTimeZone(now, recipientTimeZone);
  if (localHour == null) return { eligible: false, reason: "recipient_timezone_unknown" };
  if (localHour < 8 || localHour >= 21) return { eligible: false, reason: "quiet_hours" };
  if (!providerReady) return { eligible: false, reason: "provider_unavailable" };
  return { eligible: true, reason: null };
}

function validateSmartContactSMSRequest(raw, send) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new SmartContactListError("smart_contact_sms_request_invalid", "The message campaign request is invalid.");
  }
  const allowedKeys = new Set([
    "contact_ids", "message_template", "source_list_id", "filters",
    ...(send ? ["preview_id", "idempotency_key", "confirmed"] : [])
  ]);
  const unknown = Object.keys(raw).filter((key) => !allowedKeys.has(key));
  if (unknown.length) {
    throw new SmartContactListError(
      "smart_contact_sms_request_invalid",
      `Unsupported message campaign field: ${unknown[0]}.`,
      { details: { fields: unknown.join(",") } }
    );
  }
  const contactIDs = normalizeUUIDList(raw.contact_ids, {
    field: "contact_ids",
    maximum: SMART_CONTACT_LIST_LIMITS.maximumBulkSMSContacts,
    minimum: 1,
    errorCode: "smart_contact_sms_contacts_invalid"
  });
  const messageTemplate = raw.message_template == null ? "" : String(raw.message_template).trim();
  if (!messageTemplate
      || messageTemplate.length > SMART_CONTACT_LIST_LIMITS.maximumSMSBodyLength
      || /[\u0000\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(messageTemplate)) {
    throw new SmartContactListError(
      "smart_contact_sms_message_invalid",
      `Campaign messages must contain 1–${SMART_CONTACT_LIST_LIMITS.maximumSMSBodyLength} characters.`
    );
  }
  const placeholders = [...messageTemplate.matchAll(/\{\{([^{}]+)\}\}/g)].map((match) => match[1]);
  const unsupported = placeholders.filter((placeholder) => !["contact", "company"].includes(placeholder));
  if (unsupported.length) {
    throw new SmartContactListError(
      "smart_contact_sms_placeholder_invalid",
      `Unsupported message placeholder: {{${unsupported[0]}}}.`
    );
  }
  if (!messageTemplate.includes("{{company}}")) {
    throw new SmartContactListError(
      "smart_contact_sms_company_required",
      "Campaign messages must identify the sender with {{company}}."
    );
  }
  if (!/\breply\s+stop\b/i.test(messageTemplate)) {
    throw new SmartContactListError(
      "smart_contact_sms_opt_out_language_required",
      "Campaign messages must include “Reply STOP” opt-out instructions."
    );
  }
  const sourceListID = optionalUUID(raw.source_list_id, "smart_contact_sms_source_list_invalid");
  const filters = redactSmartContactFiltersForAudit(validateSmartContactFilters(raw.filters || {}));
  const normalized = {
    contact_ids: contactIDs,
    message_template: messageTemplate,
    source_list_id: sourceListID,
    filters
  };
  if (!send) return normalized;
  const previewID = optionalUUID(raw.preview_id, "smart_contact_sms_preview_required");
  if (!previewID) {
    throw new SmartContactListError("smart_contact_sms_preview_required", "Preview this campaign again before sending.");
  }
  const idempotencyKey = optionalUUID(raw.idempotency_key, "smart_contact_sms_idempotency_key_required");
  if (!idempotencyKey) {
    throw new SmartContactListError("smart_contact_sms_idempotency_key_required", "Reload the campaign confirmation and try again.");
  }
  if (raw.confirmed !== true) {
    throw new SmartContactListError("smart_contact_sms_confirmation_required", "Review and explicitly confirm the campaign before sending.");
  }
  return {
    ...normalized,
    preview_id: previewID,
    idempotency_key: idempotencyKey,
    confirmed: true
  };
}

function hourInTimeZone(value, timeZone) {
  const date = validDate(value);
  if (!date) return null;
  try {
    const parts = new Intl.DateTimeFormat("en-US", {
      timeZone,
      hour: "2-digit",
      hourCycle: "h23"
    }).formatToParts(date);
    const hour = Number(parts.find((part) => part.type === "hour")?.value);
    return Number.isInteger(hour) && hour >= 0 && hour <= 23 ? hour : null;
  } catch (_) {
    return null;
  }
}

export function redactSmartContactFiltersForAudit(rawFilters = {}) {
  const filters = rawFilters?.job_completed_before instanceof Date
    ? rawFilters
    : validateSmartContactFilters(rawFilters);
  const serialized = serializeFilters(filters);
  return {
    ...serialized,
    origin: serialized.origin
      ? { label: clean(serialized.origin.label) || null, redacted: true }
      : null
  };
}

export function buildSmartContactPreview({
  contacts = [],
  filters = {},
  now = new Date(),
  sourceTruncated = false,
  communicationCoverage = { sms: true, calls: true, consent: true }
} = {}) {
  const normalizedFilters = validateSmartContactFilters(filters);
  const currentTime = validDate(now);
  if (!currentTime) throw new SmartContactListError("smart_contacts_now_invalid", "Preview time is invalid.");
  if (!Array.isArray(contacts) || contacts.length > SMART_CONTACT_LIST_LIMITS.maximumSourceContacts) {
    throw new SmartContactListError("smart_contacts_source_too_large", `Preview supports at most ${SMART_CONTACT_LIST_LIMITS.maximumSourceContacts} contacts.`);
  }
  if (normalizedFilters.no_recent_contact_days != null && (!communicationCoverage.sms || !communicationCoverage.calls)) {
    throw new SmartContactListError(
      "smart_contacts_engagement_unavailable",
      "Recent contact history is temporarily incomplete. Remove that filter or try again.",
      { statusCode: 503 }
    );
  }

  const normalizedContacts = contacts.map(normalizeContactFact).filter(Boolean);
  const missingCoordinateCount = normalizedContacts.filter((contact) => contact.latitude == null || contact.longitude == null).length;
  const matches = normalizedContacts.flatMap((contact) => {
    const evaluated = matchContact(contact, normalizedFilters, currentTime);
    return evaluated ? [{ ...contactPayload(contact, communicationCoverage), ...evaluated }] : [];
  });
  matches.sort((lhs, rhs) => compareResults(lhs, rhs, normalizedFilters.sort));
  const returned = matches.slice(0, normalizedFilters.limit);
  const messaging = { eligible: 0, opted_out: 0, invalid_phone: 0, unknown: 0 };
  for (const contact of matches) {
    if (contact.sms_eligibility === "eligible") messaging.eligible += 1;
    else if (contact.sms_eligibility === "opted_out") messaging.opted_out += 1;
    else if (contact.sms_eligibility === "invalid_phone") messaging.invalid_phone += 1;
    else messaging.unknown += 1;
  }
  const warnings = [];
  if (sourceTruncated) warnings.push(`Only the first ${SMART_CONTACT_LIST_LIMITS.maximumSourceContacts} company contacts were evaluated.`);
  if (!communicationCoverage.sms || !communicationCoverage.calls) warnings.push("Recent contact evidence is partially unavailable.");
  if (!communicationCoverage.consent) warnings.push("SMS consent evidence is unavailable; messaging actions must remain blocked.");
  if (normalizedFilters.distance_mode !== "none" && missingCoordinateCount) {
    warnings.push(`${missingCoordinateCount} contacts without saved coordinates could not be evaluated for distance.`);
  }

  return {
    generated_at: currentTime.toISOString(),
    filters: serializeFilters(normalizedFilters),
    source_contact_count: normalizedContacts.length,
    source_truncated: Boolean(sourceTruncated),
    matched_count: matches.length,
    returned_count: returned.length,
    results_truncated: returned.length < matches.length,
    missing_coordinate_count: missingCoordinateCount,
    messaging,
    communication_coverage: {
      sms: Boolean(communicationCoverage.sms),
      calls: Boolean(communicationCoverage.calls),
      consent: Boolean(communicationCoverage.consent),
      complete: Boolean(communicationCoverage.sms && communicationCoverage.calls && communicationCoverage.consent)
    },
    warnings,
    contacts: returned
  };
}

function matchContact(contact, filters, now) {
  const reasons = [];
  let distanceMiles = null;
  if (filters.distance_mode !== "none") {
    if (contact.latitude == null || contact.longitude == null) return null;
    distanceMiles = haversineMiles(filters.origin.latitude, filters.origin.longitude, contact.latitude, contact.longitude);
    const inside = distanceMiles <= filters.radius_miles;
    if ((filters.distance_mode === "inside" && !inside) || (filters.distance_mode === "outside" && inside)) return null;
    reasons.push(filters.distance_mode === "inside" ? "inside_radius" : "outside_radius");
  }
  if (filters.stage_ids.length && !filters.stage_ids.some((id) => contact.stageIDs.includes(id))) return null;
  if (filters.stage_ids.length) reasons.push("stage_match");
  if (filters.not_stage_ids.some((id) => contact.stageIDs.includes(id))) return null;
  if (filters.not_stage_ids.length) reasons.push("stage_excluded_absent");
  if (filters.previous_customer && contact.completedJobCount < 1) return null;
  if (filters.previous_customer) reasons.push("previous_customer");
  if (filters.job_completed_before && (!contact.latestCompletedAt || contact.latestCompletedAt >= filters.job_completed_before)) return null;
  if (filters.job_completed_before) reasons.push("completed_before");
  if (filters.job_completed_months_ago != null) {
    const cutoff = subtractUTCMonths(now, filters.job_completed_months_ago);
    if (!contact.latestCompletedAt || contact.latestCompletedAt > cutoff) return null;
    reasons.push("completed_months_ago");
  }
  if (filters.never_scheduled && contact.jobCount !== 0) return null;
  if (filters.never_scheduled) reasons.push("never_scheduled");
  if (filters.lost_lead && !contact.lostLead) return null;
  if (filters.lost_lead) reasons.push("lost_lead");
  if (filters.quote === "exists" && contact.quoteCount < 1) return null;
  if (filters.quote === "none" && contact.quoteCount !== 0) return null;
  if (filters.quote !== "any") reasons.push(filters.quote === "exists" ? "quote_exists" : "no_quote");
  if (filters.quote_min_age_days != null) {
    const cutoff = new Date(now.getTime() - filters.quote_min_age_days * 86_400_000);
    if (!contact.latestQuoteAt || contact.latestQuoteAt > cutoff) return null;
    reasons.push("quote_min_age");
  }
  if (filters.quote_max_age_days != null) {
    const cutoff = new Date(now.getTime() - filters.quote_max_age_days * 86_400_000);
    if (!contact.latestQuoteAt || contact.latestQuoteAt < cutoff) return null;
    reasons.push("quote_max_age");
  }
  if (filters.tags_any.length && !filters.tags_any.some((tag) => contact.tags.includes(tag))) return null;
  if (filters.tags_any.length) reasons.push("tags_any");
  if (filters.tags_all.length && !filters.tags_all.every((tag) => contact.tags.includes(tag))) return null;
  if (filters.tags_all.length) reasons.push("tags_all");
  if (filters.tags_none.some((tag) => contact.tags.includes(tag))) return null;
  if (filters.tags_none.length) reasons.push("tags_none");
  if (filters.job_types.length && !filters.job_types.includes(contact.jobTypeKey)) return null;
  if (filters.job_types.length) reasons.push("job_type");
  if (filters.sources.length && !filters.sources.includes(contact.sourceKey)) return null;
  if (filters.sources.length) reasons.push("source");
  if (filters.no_recent_contact_days != null) {
    const cutoff = new Date(now.getTime() - filters.no_recent_contact_days * 86_400_000);
    if (contact.lastContactAt && contact.lastContactAt > cutoff) return null;
    reasons.push(contact.lastContactAt ? "no_recent_contact" : "never_contacted");
  }
  if (filters.minimum_value_cents != null && (contact.valueCents == null || contact.valueCents < filters.minimum_value_cents)) return null;
  if (filters.minimum_value_cents != null) reasons.push("minimum_value");
  if (filters.maximum_value_cents != null && (contact.valueCents == null || contact.valueCents > filters.maximum_value_cents)) return null;
  if (filters.maximum_value_cents != null) reasons.push("maximum_value");
  if (filters.routable_only && (contact.latitude == null || contact.longitude == null)) return null;
  if (filters.routable_only) reasons.push("routable");
  return { distance_miles: distanceMiles == null ? null : rounded(distanceMiles, 3), match_reasons: reasons };
}

function normalizeContactFact(raw) {
  const id = clean(raw?.id);
  if (!id) return null;
  const value = raw.value_cents == null ? null : Number(raw.value_cents);
  const lastSMS = validDate(raw.last_sms_at);
  const lastCall = validDate(raw.last_call_at);
  const displayTags = tagsArray(raw.tags);
  const jobType = clean(raw.job_type);
  const source = clean(raw.source);
  return {
    id,
    name: clean(raw.name) || "Unnamed",
    phone: clean(raw.phone) || null,
    email: clean(raw.email) || null,
    address: clean(raw.address) || null,
    valueCents: Number.isSafeInteger(value) && value >= 0 ? value : null,
    latitude: coordinate(raw.lat ?? raw.latitude, -90, 90),
    longitude: coordinate(raw.lng ?? raw.longitude, -180, 180),
    tags: [...new Set(displayTags.map((tag) => tag.toLowerCase()))],
    displayTags,
    jobType,
    jobTypeKey: jobType.toLowerCase(),
    source,
    sourceKey: source.toLowerCase(),
    stageIDs: stringListLoose(raw.stage_ids),
    lostLead: Boolean(raw.lost_lead),
    jobCount: nonnegativeInteger(raw.job_count),
    completedJobCount: nonnegativeInteger(raw.completed_job_count),
    latestCompletedAt: validDate(raw.latest_completed_at),
    quoteCount: nonnegativeInteger(raw.quote_count),
    latestQuoteAt: validDate(raw.latest_quote_at),
    lastSMSAt: lastSMS,
    lastCallAt: lastCall,
    lastContactAt: latestDate(lastSMS, lastCall),
    smsPhoneValid: raw.sms_phone_valid === true,
    smsOptedOut: raw.sms_opted_out === true,
    createdAt: validDate(raw.created_at),
    updatedAt: validDate(raw.updated_at)
  };
}

function contactPayload(contact, coverage) {
  let smsEligibility = "unknown";
  if (coverage.consent) {
    smsEligibility = !contact.smsPhoneValid ? "invalid_phone" : contact.smsOptedOut ? "opted_out" : "eligible";
  }
  return {
    id: contact.id,
    name: contact.name,
    phone: contact.phone,
    email: contact.email,
    address: contact.address,
    value_cents: contact.valueCents,
    latitude: contact.latitude,
    longitude: contact.longitude,
    tags: contact.displayTags,
    job_type: contact.jobType || null,
    source: contact.source || null,
    stage_ids: contact.stageIDs,
    lost_lead: contact.lostLead,
    job_count: contact.jobCount,
    completed_job_count: contact.completedJobCount,
    latest_completed_at: contact.latestCompletedAt?.toISOString() || null,
    quote_count: contact.quoteCount,
    latest_quote_at: contact.latestQuoteAt?.toISOString() || null,
    last_contact_at: contact.lastContactAt?.toISOString() || null,
    sms_eligibility: smsEligibility,
    created_at: contact.createdAt?.toISOString() || null,
    updated_at: contact.updatedAt?.toISOString() || null
  };
}

function compareResults(lhs, rhs, sort) {
  if (sort === "distance") {
    const distance = (lhs.distance_miles ?? Number.POSITIVE_INFINITY) - (rhs.distance_miles ?? Number.POSITIVE_INFINITY);
    if (distance) return distance;
  } else if (sort === "value_desc") {
    const value = (rhs.value_cents ?? -1) - (lhs.value_cents ?? -1);
    if (value) return value;
  } else if (sort === "last_contact_oldest") {
    const lhsTime = lhs.last_contact_at ? new Date(lhs.last_contact_at).getTime() : Number.NEGATIVE_INFINITY;
    const rhsTime = rhs.last_contact_at ? new Date(rhs.last_contact_at).getTime() : Number.NEGATIVE_INFINITY;
    if (lhsTime !== rhsTime) return lhsTime - rhsTime;
  }
  const name = lhs.name.localeCompare(rhs.name, "en", { sensitivity: "base" });
  return name || lhs.id.localeCompare(rhs.id);
}

function normalizeOrigin(raw) {
  if (raw == null) return null;
  if (typeof raw !== "object" || Array.isArray(raw)) throw invalidFilters();
  if (Object.keys(raw).some((key) => !["latitude", "longitude", "label"].includes(key))) throw invalidFilters();
  const latitude = coordinate(raw.latitude, -90, 90);
  const longitude = coordinate(raw.longitude, -180, 180);
  if (latitude == null || longitude == null) {
    throw new SmartContactListError("smart_contacts_origin_invalid", "Origin coordinates are invalid.");
  }
  const label = clean(raw.label);
  if (label.length > SMART_CONTACT_LIST_LIMITS.maximumTextLength) throw invalidFilters();
  return { latitude, longitude, ...(label ? { label } : {}) };
}

function serializeFilters(filters) {
  return {
    ...filters,
    job_completed_before: filters.job_completed_before?.toISOString() || null
  };
}

function normalizeSnapshotContactIDs(value) {
  if (value == null) return [];
  if (!Array.isArray(value) || value.length > SMART_CONTACT_LIST_LIMITS.maximumSnapshotContacts) {
    throw new SmartContactListError(
      "smart_contact_list_members_invalid",
      `Snapshot lists support at most ${SMART_CONTACT_LIST_LIMITS.maximumSnapshotContacts} selected contacts.`
    );
  }
  const ids = [];
  for (const item of value) {
    const id = clean(item).toLowerCase();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id)) {
      throw new SmartContactListError(
        "smart_contact_list_members_invalid",
        "One or more selected contacts are invalid. Refresh the results and try again."
      );
    }
    if (!ids.includes(id)) ids.push(id);
  }
  return ids;
}

function normalizeUUIDList(value, { field, maximum, minimum, errorCode }) {
  if (!Array.isArray(value) || value.length > maximum) {
    throw new SmartContactListError(errorCode, `${field} must contain ${minimum}–${maximum} valid IDs.`);
  }
  const ids = [];
  for (const item of value) {
    const id = optionalUUID(item, errorCode);
    if (!id) throw new SmartContactListError(errorCode, `${field} contains an invalid ID.`);
    if (!ids.includes(id)) ids.push(id);
  }
  if (ids.length < minimum) {
    throw new SmartContactListError(errorCode, `${field} must contain ${minimum}–${maximum} valid IDs.`);
  }
  return ids;
}

function optionalUUID(value, errorCode) {
  if (value == null || value === "") return null;
  const id = clean(value).toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id)) {
    throw new SmartContactListError(errorCode, "One or more IDs are invalid.");
  }
  return id;
}

function stringList(value, field, { lower = true } = {}) {
  if (value == null) return [];
  if (!Array.isArray(value) || value.length > SMART_CONTACT_LIST_LIMITS.maximumFilterValues) {
    throw new SmartContactListError("smart_contacts_filters_invalid", `${field} has too many or invalid values.`);
  }
  const result = [];
  for (const item of value) {
    let text = clean(item);
    if (!text || text.length > SMART_CONTACT_LIST_LIMITS.maximumTextLength) throw invalidFilters();
    if (lower) text = text.toLowerCase();
    if (!result.includes(text)) result.push(text);
  }
  return result;
}

function stringListLoose(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map(clean).filter(Boolean))];
}

function tagsArray(value) {
  if (Array.isArray(value)) return [...new Set(value.flatMap(tagsArray))];
  if (value == null) return [];
  let text = String(value).trim();
  if (text.startsWith("{") && text.endsWith("}")) text = text.slice(1, -1).replaceAll('"', "");
  return [...new Set(text.split(/[;,]/).map(clean).filter(Boolean))];
}

function subtractUTCMonths(date, count) {
  const year = date.getUTCFullYear();
  const month = date.getUTCMonth() - count;
  const day = date.getUTCDate();
  const first = new Date(Date.UTC(year, month, 1, date.getUTCHours(), date.getUTCMinutes(), date.getUTCSeconds(), date.getUTCMilliseconds()));
  const lastDay = new Date(Date.UTC(first.getUTCFullYear(), first.getUTCMonth() + 1, 0)).getUTCDate();
  first.setUTCDate(Math.min(day, lastDay));
  return first;
}

function haversineMiles(lat1, lon1, lat2, lon2) {
  const radians = (degrees) => degrees * Math.PI / 180;
  const deltaLat = radians(lat2 - lat1);
  const deltaLon = radians(lon2 - lon1);
  const a = Math.sin(deltaLat / 2) ** 2
    + Math.cos(radians(lat1)) * Math.cos(radians(lat2)) * Math.sin(deltaLon / 2) ** 2;
  return 3_958.7613 * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function optionalDate(value, field) {
  if (value == null || value === "") return null;
  const date = validDate(value);
  if (!date) throw new SmartContactListError("smart_contacts_filters_invalid", `${field} is not a valid date.`);
  return date;
}

function optionalInteger(value, minimum, maximum, field) {
  return value == null || value === "" ? null : integer(value, minimum, maximum, field);
}

function integer(value, minimum, maximum, field) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum) {
    throw new SmartContactListError("smart_contacts_filters_invalid", `${field} is outside its supported range.`);
  }
  return number;
}

function finite(value, minimum, maximum, field) {
  const number = Number(value);
  if (!Number.isFinite(number) || number < minimum || number > maximum) {
    throw new SmartContactListError("smart_contacts_filters_invalid", `${field} is outside its supported range.`);
  }
  return number;
}

function boolean(value, field) {
  if (value == null) return false;
  if (typeof value !== "boolean") throw new SmartContactListError("smart_contacts_filters_invalid", `${field} must be true or false.`);
  return value;
}

function coordinate(value, minimum, maximum) {
  if (value == null || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= minimum && number <= maximum ? number : null;
}

function nonnegativeInteger(value) {
  const number = Number(value);
  return Number.isSafeInteger(number) && number >= 0 ? number : 0;
}

function latestDate(...dates) {
  return dates.filter(Boolean).sort((lhs, rhs) => rhs - lhs)[0] || null;
}

function validDate(value) {
  if (value == null || value === "") return null;
  const date = value instanceof Date ? new Date(value) : new Date(value);
  return Number.isFinite(date.getTime()) ? date : null;
}

function rounded(value, digits) {
  const scale = 10 ** digits;
  return Math.round(value * scale) / scale;
}

function clean(value) {
  return value == null ? "" : String(value).trim();
}

function invalidFilters() {
  return new SmartContactListError("smart_contacts_filters_invalid", "One or more smart contact filters are invalid.");
}
