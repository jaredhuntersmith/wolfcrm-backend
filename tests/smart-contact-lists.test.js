import test from "node:test";
import assert from "node:assert/strict";
import {
  SmartContactListError,
  buildSmartContactPreview,
  evaluateSmartContactSMSEligibility,
  prepareSmartContactListPersistence,
  redactSmartContactFiltersForAudit,
  renderSmartContactSMSTemplate,
  renderSmartContactTaskTemplate,
  smartContactSMSRequestSnapshot,
  validateSmartContactSMSPreview,
  validateSmartContactSMSSend,
  validateSmartContactTaskAction,
  validateSmartContactListMode,
  validateSmartContactListName,
  validateSmartContactFilters
} from "../smart-contact-lists.js";

const now = new Date("2026-08-19T12:00:00Z");

function contact(id, overrides = {}) {
  return {
    id,
    name: `Contact ${id}`,
    phone: "+15025550100",
    address: "123 Main St",
    lat: 38,
    lng: -85,
    tags: "VIP, Residential",
    job_type: "Window Cleaning",
    source: "Referral",
    value_cents: 50_000,
    stage_ids: [],
    lost_lead: false,
    job_count: 0,
    completed_job_count: 0,
    quote_count: 0,
    sms_phone_valid: true,
    sms_opted_out: false,
    ...overrides
  };
}

function preview(contacts, filters = {}, overrides = {}) {
  return buildSmartContactPreview({ contacts, filters, now, ...overrides });
}

test("filter validation rejects broadening mistakes and incompatible filters", () => {
  assert.throws(
    () => validateSmartContactFilters({ stage_id: "misspelled" }),
    (error) => error.code === "smart_contacts_filters_invalid" && error.details.fields === "stage_id"
  );
  assert.throws(
    () => validateSmartContactFilters({ distance_mode: "inside", radius_miles: 10 }),
    (error) => error.code === "smart_contacts_origin_required"
  );
  assert.throws(
    () => validateSmartContactFilters({ distance_mode: "nearby" }),
    (error) => error.code === "smart_contacts_filters_invalid"
  );
  assert.throws(
    () => validateSmartContactFilters({ previous_customer: true, never_scheduled: true }),
    (error) => error.code === "smart_contacts_filters_conflict"
  );
  assert.throws(
    () => validateSmartContactFilters({ quote: "none", quote_min_age_days: 30 }),
    (error) => error.code === "smart_contacts_filters_conflict"
  );
  assert.throws(
    () => validateSmartContactFilters({ sort: "distance" }),
    (error) => error.code === "smart_contacts_filters_conflict"
  );
  assert.throws(
    () => validateSmartContactFilters({ stage_ids: ["a"], not_stage_ids: ["a"] }),
    (error) => error.code === "smart_contacts_filters_conflict"
  );
});

test("saved-list metadata validates names modes and bounded snapshot members", () => {
  assert.equal(validateSmartContactListName("  Spring   Follow Up  "), "Spring Follow Up");
  assert.equal(validateSmartContactListMode("dynamic"), "dynamic");
  assert.throws(
    () => validateSmartContactListName("   "),
    (error) => error.code === "smart_contact_list_name_invalid"
  );
  assert.throws(
    () => validateSmartContactListMode("automatic"),
    (error) => error.code === "smart_contact_list_mode_invalid"
  );
  assert.throws(
    () => prepareSmartContactListPersistence({
      mode: "snapshot",
      contact_ids: Array.from({ length: 501 }, (_, index) => `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`)
    }),
    (error) => error.code === "smart_contact_list_members_invalid"
  );
});

test("dynamic geographic lists require an explicit named fixed origin", () => {
  const filters = {
    distance_mode: "inside",
    radius_miles: 15,
    origin: { latitude: 38.25, longitude: -85.75, label: "Main Office" }
  };
  assert.throws(
    () => prepareSmartContactListPersistence({ mode: "dynamic", filters, origin_policy: "transient" }),
    (error) => error.code === "smart_contact_list_fixed_origin_required"
  );
  const prepared = prepareSmartContactListPersistence({ mode: "dynamic", filters, origin_policy: "fixed" });
  assert.equal(prepared.filters.distance_mode, "inside");
  assert.equal(prepared.filters.origin.label, "Main Office");
  assert.equal(prepared.origin_redacted, false);
});

test("snapshot persistence deduplicates members and redacts transient coordinates", () => {
  const first = "11111111-1111-4111-8111-111111111111";
  const second = "22222222-2222-4222-8222-222222222222";
  const prepared = prepareSmartContactListPersistence({
    mode: "snapshot",
    origin_policy: "transient",
    contact_ids: [first, second, first.toUpperCase()],
    filters: {
      distance_mode: "outside",
      radius_miles: 5,
      origin: { latitude: 38.25, longitude: -85.75, label: "Current Location" },
      sort: "distance",
      tags_any: ["VIP"]
    }
  });
  assert.deepEqual(prepared.contact_ids, [first, second]);
  assert.equal(prepared.origin_redacted, true);
  assert.equal(prepared.filters.distance_mode, "none");
  assert.equal(prepared.filters.origin, null);
  assert.equal(prepared.filters.radius_miles, null);
  assert.equal(prepared.filters.sort, "name");
  assert.deepEqual(prepared.filters.tags_any, ["vip"]);
});

test("bulk task actions validate exact bounded inputs and normalize idempotency", () => {
  const first = "11111111-1111-4111-8111-111111111111";
  const second = "22222222-2222-4222-8222-222222222222";
  const prepared = validateSmartContactTaskAction({
    contact_ids: [first, second, first.toUpperCase()],
    title_template: "  Follow   up with {{contact}}  ",
    detail_template: "Review the prior quote.",
    due_date: "2026-08-20T13:00:00Z",
    priority: "HIGH",
    assignee_ids: ["33333333-3333-4333-8333-333333333333"],
    filters: { tags_any: ["VIP"] },
    idempotency_key: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"
  });
  assert.deepEqual(prepared.contact_ids, [first, second]);
  assert.equal(prepared.title_template, "Follow up with {{contact}}");
  assert.equal(prepared.priority, "high");
  assert.equal(prepared.idempotency_key, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
  assert.throws(
    () => validateSmartContactTaskAction({ contact_ids: [], title_template: "Call", idempotency_key: prepared.idempotency_key }),
    (error) => error.code === "smart_contact_task_contacts_invalid"
  );
  assert.throws(
    () => validateSmartContactTaskAction({ contact_ids: [first], title_template: "Call", extra: true, idempotency_key: prepared.idempotency_key }),
    (error) => error.code === "smart_contact_task_request_invalid"
  );
});

test("bulk task templates are literal and audit filters redact origin coordinates", () => {
  assert.equal(renderSmartContactTaskTemplate("Call {{contact}} about {{offer}}", "Morgan Home"), "Call Morgan Home about {{offer}}");
  const filters = redactSmartContactFiltersForAudit({
    distance_mode: "inside",
    radius_miles: 12,
    origin: { latitude: 38.2, longitude: -85.7, label: "Main Office" }
  });
  assert.deepEqual(filters.origin, { label: "Main Office", redacted: true });
  assert.equal(JSON.stringify(filters).includes("38.2"), false);
  assert.equal(JSON.stringify(filters).includes("-85.7"), false);
});

test("SMS campaign requests require bounded exact recipients and compliant copy", () => {
  const first = "11111111-1111-4111-8111-111111111111";
  const second = "22222222-2222-4222-8222-222222222222";
  const request = validateSmartContactSMSPreview({
    contact_ids: [first, second, first.toUpperCase()],
    message_template: "{{company}}: Hi {{contact}}, save 10% this week. Reply STOP to opt out.",
    filters: { tags_any: ["Customer"] }
  });
  assert.deepEqual(request.contact_ids, [first, second]);
  assert.equal(request.filters.tags_any[0], "customer");
  assert.throws(
    () => validateSmartContactSMSPreview({ contact_ids: [first], message_template: "Hi {{contact}}. Reply STOP." }),
    (error) => error.code === "smart_contact_sms_company_required"
  );
  assert.throws(
    () => validateSmartContactSMSPreview({ contact_ids: [first], message_template: "{{company}}: Hi. Opt out anytime." }),
    (error) => error.code === "smart_contact_sms_opt_out_language_required"
  );
  assert.throws(
    () => validateSmartContactSMSPreview({ contact_ids: [first], message_template: "{{company}}: {{offer}}. Reply STOP." }),
    (error) => error.code === "smart_contact_sms_placeholder_invalid"
  );
});

test("SMS campaign send requires an unchanged explicit confirmation boundary", () => {
  const request = {
    contact_ids: ["11111111-1111-4111-8111-111111111111"],
    message_template: "{{company}}: Hi {{contact}}, an offer for you. Reply STOP to opt out.",
    preview_id: "22222222-2222-4222-8222-222222222222",
    idempotency_key: "33333333-3333-4333-8333-333333333333",
    confirmed: true
  };
  const action = validateSmartContactSMSSend(request);
  assert.equal(action.confirmed, true);
  assert.equal(action.preview_id, request.preview_id);
  assert.deepEqual(
    smartContactSMSRequestSnapshot(action),
    smartContactSMSRequestSnapshot(validateSmartContactSMSPreview({
      contact_ids: request.contact_ids,
      message_template: request.message_template
    }))
  );
  assert.throws(
    () => validateSmartContactSMSSend({ ...request, confirmed: false }),
    (error) => error.code === "smart_contact_sms_confirmation_required"
  );
});

test("SMS campaign templates replace only supported literal contact and company fields", () => {
  assert.equal(
    renderSmartContactSMSTemplate("{{company}} for {{contact}} — {{other}}", {
      contactName: "Morgan Home",
      companyName: "Wolf Services"
    }),
    "Wolf Services for Morgan Home — {{other}}"
  );
});

test("SMS campaign eligibility requires opt-in local time and provider readiness", () => {
  const eligible = evaluateSmartContactSMSEligibility({
    contactExists: true,
    phoneValid: true,
    consentStatus: "opted_in",
    recipientTimeZone: "America/New_York",
    providerReady: true,
    now: "2026-08-19T13:00:00Z"
  });
  assert.deepEqual(eligible, { eligible: true, reason: null });
  assert.equal(evaluateSmartContactSMSEligibility({
    contactExists: true,
    phoneValid: true,
    consentStatus: "opted_in",
    recipientTimeZone: "America/Los_Angeles",
    providerReady: true,
    now: "2026-08-19T13:00:00Z"
  }).reason, "quiet_hours");
  assert.equal(evaluateSmartContactSMSEligibility({
    contactExists: true,
    phoneValid: true,
    consentStatus: null,
    recipientTimeZone: "America/New_York",
    providerReady: true,
    now: "2026-08-19T13:00:00Z"
  }).reason, "marketing_consent_required");
  assert.equal(evaluateSmartContactSMSEligibility({
    contactExists: true,
    phoneValid: true,
    consentStatus: "opted_out",
    recipientTimeZone: "America/New_York",
    providerReady: true,
    now: "2026-08-19T13:00:00Z"
  }).reason, "opted_out");
  assert.equal(evaluateSmartContactSMSEligibility({
    contactExists: true,
    phoneValid: true,
    consentStatus: "opted_in",
    recipientTimeZone: null,
    providerReady: true,
    now: "2026-08-19T13:00:00Z"
  }).reason, "recipient_timezone_unknown");
  assert.equal(evaluateSmartContactSMSEligibility({
    contactExists: true,
    phoneValid: true,
    consentStatus: "opted_in",
    recipientTimeZone: "America/New_York",
    providerReady: false,
    now: "2026-08-19T13:00:00Z"
  }).reason, "provider_unavailable");
});

test("snapshot membership is required and dynamic definitions reject members", () => {
  const contactID = "33333333-3333-4333-8333-333333333333";
  assert.throws(
    () => prepareSmartContactListPersistence({ mode: "snapshot" }),
    (error) => error.code === "smart_contact_list_snapshot_empty"
  );
  assert.throws(
    () => prepareSmartContactListPersistence({ mode: "dynamic", contact_ids: [contactID] }),
    (error) => error.code === "smart_contact_list_members_not_allowed"
  );
});

test("inside-radius preview calculates distance and excludes missing coordinates", () => {
  const report = preview([
    contact("near", { lng: -85.1 }),
    contact("far", { lng: -86 }),
    contact("missing", { lat: null, lng: null })
  ], {
    distance_mode: "inside",
    radius_miles: 10,
    origin: { latitude: 38, longitude: -85, label: "Current location" }
  });
  assert.deepEqual(report.contacts.map((item) => item.id), ["near"]);
  assert.ok(report.contacts[0].distance_miles > 5 && report.contacts[0].distance_miles < 6);
  assert.equal(report.missing_coordinate_count, 1);
  assert.ok(report.warnings.some((warning) => warning.includes("without saved coordinates")));
});

test("outside-radius excludes unknown geography instead of treating it as infinitely far", () => {
  const report = preview([
    contact("near", { lng: -85.05 }),
    contact("far", { lng: -86 }),
    contact("unknown", { lat: null, lng: null })
  ], {
    distance_mode: "outside",
    radius_miles: 20,
    origin: { latitude: 38, longitude: -85 }
  });
  assert.deepEqual(report.contacts.map((item) => item.id), ["far"]);
  assert.ok(report.contacts[0].match_reasons.includes("outside_radius"));
});

test("pipeline tags job type source and inclusive value filters combine with AND", () => {
  const report = preview([
    contact("match", { stage_ids: ["stage-a"], value_cents: 25_000 }),
    contact("wrong-stage", { stage_ids: ["stage-b"], value_cents: 25_000 }),
    contact("banned-tag", { stage_ids: ["stage-a"], tags: "VIP, Do Not Visit", value_cents: 25_000 }),
    contact("too-high", { stage_ids: ["stage-a"], value_cents: 25_001 })
  ], {
    stage_ids: ["stage-a"],
    not_stage_ids: ["stage-z"],
    tags_all: ["vip", "residential"],
    tags_none: ["do not visit"],
    job_types: ["window cleaning"],
    sources: ["referral"],
    minimum_value_cents: 25_000,
    maximum_value_cents: 25_000
  });
  assert.deepEqual(report.contacts.map((item) => item.id), ["match"]);
  assert.deepEqual(report.contacts[0].tags, ["VIP", "Residential"]);
});

test("job history distinguishes completed customers from scheduled and never scheduled", () => {
  const previous = contact("previous", {
    job_count: 2,
    completed_job_count: 1,
    latest_completed_at: "2025-12-01T12:00:00Z"
  });
  const unfinished = contact("unfinished", { job_count: 1 });
  const never = contact("never");
  assert.deepEqual(preview([previous, unfinished, never], { previous_customer: true }).contacts.map((item) => item.id), ["previous"]);
  assert.deepEqual(preview([previous, unfinished, never], { never_scheduled: true }).contacts.map((item) => item.id), ["never"]);
  assert.deepEqual(preview([previous], { job_completed_months_ago: 6 }).contacts.map((item) => item.id), ["previous"]);
  assert.equal(preview([previous], { job_completed_before: "2025-01-01T00:00:00Z" }).matched_count, 0);
});

test("lost lead and quote existence/age use explicit server facts", () => {
  const oldQuote = contact("old", {
    lost_lead: true,
    quote_count: 2,
    latest_quote_at: "2026-06-01T12:00:00Z"
  });
  const freshQuote = contact("fresh", {
    lost_lead: true,
    quote_count: 1,
    latest_quote_at: "2026-08-15T12:00:00Z"
  });
  const noQuote = contact("none", { lost_lead: true });
  assert.deepEqual(preview([oldQuote, freshQuote, noQuote], {
    lost_lead: true,
    quote: "exists",
    quote_min_age_days: 30
  }).contacts.map((item) => item.id), ["old"]);
  assert.deepEqual(preview([oldQuote, noQuote], { quote: "none" }).contacts.map((item) => item.id), ["none"]);
});

test("no-recent-contact includes never-contacted contacts and fails when evidence is partial", () => {
  const report = preview([
    contact("recent", { last_sms_at: "2026-08-18T12:00:00Z" }),
    contact("old", { last_call_at: "2026-06-01T12:00:00Z" }),
    contact("never")
  ], { no_recent_contact_days: 30, sort: "last_contact_oldest" });
  assert.deepEqual(report.contacts.map((item) => item.id), ["never", "old"]);
  assert.ok(report.contacts[0].match_reasons.includes("never_contacted"));
  assert.throws(
    () => preview([contact("a")], { no_recent_contact_days: 30 }, {
      communicationCoverage: { sms: false, calls: true, consent: true }
    }),
    (error) => error instanceof SmartContactListError
      && error.code === "smart_contacts_engagement_unavailable"
      && error.statusCode === 503
  );
});

test("SMS eligibility counts opted-out invalid and unknown recipients without hiding them", () => {
  const complete = preview([
    contact("eligible"),
    contact("opted", { sms_opted_out: true }),
    contact("invalid", { sms_phone_valid: false })
  ]);
  assert.deepEqual(complete.messaging, { eligible: 1, opted_out: 1, invalid_phone: 1, unknown: 0 });
  const partial = preview([contact("eligible")], {}, {
    communicationCoverage: { sms: true, calls: true, consent: false }
  });
  assert.equal(partial.contacts[0].sms_eligibility, "unknown");
  assert.equal(partial.messaging.unknown, 1);
});

test("result limits and stable name/ID ties report truncation truthfully", () => {
  const report = preview([
    contact("b", { name: "Same" }),
    contact("a", { name: "Same" }),
    contact("c", { name: "Zulu" })
  ], { limit: 2, sort: "name" }, { sourceTruncated: true });
  assert.deepEqual(report.contacts.map((item) => item.id), ["a", "b"]);
  assert.equal(report.matched_count, 3);
  assert.equal(report.returned_count, 2);
  assert.equal(report.results_truncated, true);
  assert.equal(report.source_truncated, true);
});

test("routable-only does not accept a partial coordinate", () => {
  const report = preview([
    contact("complete"),
    contact("latitude-only", { lng: null }),
    contact("none", { lat: null, lng: null })
  ], { routable_only: true });
  assert.deepEqual(report.contacts.map((item) => item.id), ["complete"]);
});
