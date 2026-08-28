import assert from "node:assert/strict";
import test from "node:test";

import {
  MEASUREMENT_LIMITS,
  MeasurementInputError,
  measurementContactLinksEqual,
  measurementEventPayload,
  measurementMetrics,
  normalizeMeasurementID,
  normalizeMeasurementInput
} from "../measurement-contract.js";

const square = [
  { lat: 41, lng: -87 },
  { lat: 41, lng: -86.999 },
  { lat: 41.001, lng: -86.999 },
  { lat: 41.001, lng: -87 }
];

test("measurement input normalizes legacy-compatible fields and Contact links", () => {
  assert.deepEqual(normalizeMeasurementInput({
    name: "  North roof  ",
    points: square,
    created_at: "2026-08-27T12:00:00Z",
    linked_contact_ids: ["contact-1", "contact-1", "contact-2"],
    units: "meters"
  }), {
    name: "North roof",
    points: square,
    created_at: "2026-08-27T12:00:00.000Z",
    linked_contact_ids: ["contact-1", "contact-2"],
    units: "meters"
  });
  assert.equal(normalizeMeasurementID(" measure-1 "), "measure-1");
});

test("measurement input rejects malformed and excessive user-controlled data", () => {
  assert.throws(() => normalizeMeasurementInput({}), (error) => error instanceof MeasurementInputError && error.code === "missing_points");
  assert.throws(() => normalizeMeasurementInput({ points: [{ lat: 91, lng: 0 }] }), (error) => error.code === "invalid_measurement_point");
  assert.throws(
    () => normalizeMeasurementInput({ points: Array.from({ length: MEASUREMENT_LIMITS.maximumPoints + 1 }, () => ({ lat: 0, lng: 0 })) }),
    (error) => error.code === "too_many_measurement_points"
  );
  assert.throws(
    () => normalizeMeasurementInput({ points: [], linked_contact_ids: Array.from({ length: MEASUREMENT_LIMITS.maximumContactLinks + 1 }, (_, index) => `contact-${index}`) }),
    (error) => error.code === "too_many_measurement_contact_links"
  );
  assert.throws(() => normalizeMeasurementInput({ points: [], created_at: "not-a-date" }), (error) => error.code === "invalid_measurement_created_at");
});

test("measurement metrics and event payload expose finite distance and area evidence", () => {
  const metrics = measurementMetrics(square);
  assert.ok(metrics.distance > 380 && metrics.distance < 410);
  assert.ok(metrics.area > 9_000 && metrics.area < 9_500);
  assert.equal(metrics.type, "area");
  const payload = measurementEventPayload({ id: "measure-1", name: "Roof", units: "feet", points: square, linked_contact_ids: ["contact-1"] });
  assert.equal(payload.measurement_id, "measure-1");
  assert.equal(payload.point_count, 4);
  assert.equal(payload.type, "area");
  assert.deepEqual(payload.linked_contact_ids, ["contact-1"]);
});

test("measurement Contact-link comparison permits hidden-link preservation but detects mutation", () => {
  assert.equal(measurementContactLinksEqual(["contact-2", "contact-1"], ["contact-1", "contact-2", "contact-1"]), true);
  assert.equal(measurementContactLinksEqual(["contact-1"], []), false);
  assert.equal(measurementContactLinksEqual(null, []), true);
});
