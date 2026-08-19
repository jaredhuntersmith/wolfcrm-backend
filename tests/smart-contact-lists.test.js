import test from "node:test";
import assert from "node:assert/strict";
import {
  SmartContactListError,
  buildSmartContactPreview,
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
