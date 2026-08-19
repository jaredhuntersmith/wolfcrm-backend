export const SMART_CONTACT_LIST_LIMITS = Object.freeze({
  maximumSourceContacts: 2_000,
  maximumReturnedContacts: 500,
  maximumFilterValues: 50,
  maximumTextLength: 120
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
