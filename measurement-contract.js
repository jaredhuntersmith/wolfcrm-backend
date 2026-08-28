export const MEASUREMENT_LIMITS = Object.freeze({
  maximumPoints: 250,
  maximumContactLinks: 50,
  maximumNameCharacters: 160,
  maximumIdentifierCharacters: 128
});

export class MeasurementInputError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "MeasurementInputError";
    this.code = code;
    this.details = details;
  }
}

function identifier(value, code, label) {
  const clean = typeof value === "string" ? value.trim() : "";
  if (!clean || clean.length > MEASUREMENT_LIMITS.maximumIdentifierCharacters) {
    throw new MeasurementInputError(code, `${label} is invalid.`);
  }
  return clean;
}

function normalizePoint(value, index) {
  const lat = value && typeof value === "object" ? value.lat : null;
  const lng = value && typeof value === "object" ? value.lng : null;
  if (
    typeof lat !== "number" || !Number.isFinite(lat) || Math.abs(lat) > 90 ||
    typeof lng !== "number" || !Number.isFinite(lng) || Math.abs(lng) > 180
  ) {
    throw new MeasurementInputError(
      "invalid_measurement_point",
      `Measurement point ${index + 1} must contain valid latitude and longitude.`,
      { point_index: index }
    );
  }
  return { lat, lng };
}

function normalizeCreatedAt(value) {
  if (value == null || value === "") return null;
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    throw new MeasurementInputError("invalid_measurement_created_at", "Measurement creation time is invalid.");
  }
  return new Date(value).toISOString();
}

export function normalizeMeasurementID(value) {
  return identifier(value, "invalid_measurement_id", "Measurement identifier");
}

export function normalizeMeasurementInput(body = {}) {
  if (!Array.isArray(body.points)) {
    throw new MeasurementInputError("missing_points", "Measurement points are required.");
  }
  if (body.points.length > MEASUREMENT_LIMITS.maximumPoints) {
    throw new MeasurementInputError(
      "too_many_measurement_points",
      `Measurements support up to ${MEASUREMENT_LIMITS.maximumPoints} points.`
    );
  }
  const rawName = typeof body.name === "string" ? body.name.trim() : "";
  if (rawName.length > MEASUREMENT_LIMITS.maximumNameCharacters) {
    throw new MeasurementInputError(
      "measurement_name_too_long",
      `Measurement names may be at most ${MEASUREMENT_LIMITS.maximumNameCharacters} characters.`
    );
  }
  if (body.linked_contact_ids != null && !Array.isArray(body.linked_contact_ids)) {
    throw new MeasurementInputError("invalid_linked_contact_ids", "Linked Contacts are invalid.");
  }
  const linkedContactIDs = [...new Set((body.linked_contact_ids || []).map((value) =>
    identifier(value, "invalid_linked_contact_ids", "Linked Contact identifier")
  ))];
  if (linkedContactIDs.length > MEASUREMENT_LIMITS.maximumContactLinks) {
    throw new MeasurementInputError(
      "too_many_measurement_contact_links",
      `Measurements support up to ${MEASUREMENT_LIMITS.maximumContactLinks} linked Contacts.`
    );
  }
  return {
    name: rawName,
    points: body.points.map(normalizePoint),
    created_at: normalizeCreatedAt(body.created_at),
    linked_contact_ids: linkedContactIDs,
    units: body.units === "meters" ? "meters" : "feet"
  };
}

export function measurementContactLinksEqual(left, right) {
  const normalized = (value) => [...new Set((Array.isArray(value) ? value : []).map(String))].sort();
  return JSON.stringify(normalized(left)) === JSON.stringify(normalized(right));
}

const earthRadiusMeters = 6_371_008.8;
const radians = (degrees) => degrees * Math.PI / 180;

function segmentMeters(a, b) {
  const latitudeDelta = radians(b.lat - a.lat);
  const longitudeDelta = radians(b.lng - a.lng);
  const haversine = Math.sin(latitudeDelta / 2) ** 2 +
    Math.cos(radians(a.lat)) * Math.cos(radians(b.lat)) * Math.sin(longitudeDelta / 2) ** 2;
  return 2 * earthRadiusMeters * Math.asin(Math.min(1, Math.sqrt(haversine)));
}

function longitudeDelta(longitude, origin) {
  let delta = longitude - origin;
  while (delta > 180) delta -= 360;
  while (delta < -180) delta += 360;
  return delta;
}

export function measurementMetrics(points = []) {
  if (!Array.isArray(points)) return { distance: 0, area: 0, type: "distance" };
  let distance = 0;
  for (let index = 1; index < points.length; index += 1) {
    distance += segmentMeters(points[index - 1], points[index]);
  }
  if (points.length >= 3) distance += segmentMeters(points.at(-1), points[0]);

  let area = 0;
  if (points.length >= 3) {
    const origin = points[0];
    const averageLatitude = points.reduce((sum, point) => sum + point.lat, 0) / points.length;
    const cosine = Math.cos(radians(averageLatitude));
    const projected = points.map((point) => ({
      x: earthRadiusMeters * radians(longitudeDelta(point.lng, origin.lng)) * cosine,
      y: earthRadiusMeters * radians(point.lat - origin.lat)
    }));
    let twiceArea = 0;
    for (let index = 0; index < projected.length; index += 1) {
      const next = projected[(index + 1) % projected.length];
      twiceArea += projected[index].x * next.y - next.x * projected[index].y;
    }
    area = Math.abs(twiceArea) / 2;
  }
  return {
    distance: Number.isFinite(distance) ? distance : 0,
    area: Number.isFinite(area) ? area : 0,
    type: points.length >= 3 ? "area" : "distance"
  };
}

export function measurementEventPayload(measurement) {
  const points = Array.isArray(measurement?.points) ? measurement.points : [];
  const metrics = measurementMetrics(points);
  return {
    measurement_id: measurement.id,
    name: measurement.name || "",
    units: measurement.units === "meters" ? "meters" : "feet",
    point_count: points.length,
    linked_contact_ids: Array.isArray(measurement.linked_contact_ids) ? measurement.linked_contact_ids : [],
    distance: metrics.distance,
    area: metrics.area,
    type: metrics.type
  };
}
