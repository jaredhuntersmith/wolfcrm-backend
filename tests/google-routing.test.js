import assert from "node:assert/strict";
import {
  GOOGLE_ROUTING_LIMITS,
  GoogleRoutingError,
  createGoogleRoutingService,
  normalizePlanRequest
} from "../google-routing.js";

const FIXED_NOW = new Date("2026-08-19T12:00:00.000Z");

function response(json, status = 200, headers = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name) => headers[name.toLowerCase()] ?? null },
    async json() { return structuredClone(json); }
  };
}

function waypointCoordinate(waypoint) {
  return waypoint.location.latLng;
}

function makeStops(count, overrides = {}) {
  return Array.from({ length: count }, (_, index) => ({
    id: `stop-${index + 1}`,
    label: `Stop ${index + 1}`,
    latitude: 38 + ((index + 1) * 0.001),
    longitude: -85 + ((index + 1) * 0.001),
    service_duration_seconds: index % 3 === 0 ? 300 : 0,
    ...(overrides[index] || {})
  }));
}

function planBody(count, extra = {}) {
  return {
    start: { id: "route-start", latitude: 38, longitude: -85 },
    stops: makeStops(count),
    ending_behavior: "finish_at_final_stop",
    optimize_order: true,
    departure_time: FIXED_NOW.toISOString(),
    ...extra
  };
}

function routesApiFake(calls) {
  return async (url, init) => {
    const body = JSON.parse(init.body);
    if (url.includes("computeRouteMatrix")) {
      const elementCount = body.origins.length * body.destinations.length;
      assert.ok(elementCount <= GOOGLE_ROUTING_LIMITS.matrixMaximumElements);
      calls.matrix.push({ url, body, headers: init.headers });
      const elements = [];
      for (let originIndex = 0; originIndex < body.origins.length; originIndex += 1) {
        for (let destinationIndex = 0; destinationIndex < body.destinations.length; destinationIndex += 1) {
          const origin = waypointCoordinate(body.origins[originIndex].waypoint);
          const destination = waypointCoordinate(body.destinations[destinationIndex].waypoint);
          const steps = Math.max(1, Math.round(Math.abs(destination.latitude - origin.latitude) * 1000));
          elements.push({
            originIndex,
            destinationIndex,
            status: {},
            condition: "ROUTE_EXISTS",
            distanceMeters: steps * 100,
            duration: `${steps * 10}s`
          });
        }
      }
      return response(elements);
    }
    if (url.includes("computeRoutes")) {
      assert.ok((body.intermediates || []).length <= GOOGLE_ROUTING_LIMITS.computeRoutesMaximumIntermediates);
      calls.routes.push({ url, body, headers: init.headers });
      const count = (body.intermediates || []).length + 1;
      return response({
        routes: [{
          legs: Array.from({ length: count }, () => ({ distanceMeters: 1000, duration: "10s" })),
          polyline: { encodedPolyline: "_p~iF~ps|U_ulLnnqC_mqNvxq`@" },
          warnings: []
        }]
      });
    }
    throw new Error(`Unexpected URL: ${url}`);
  };
}

async function testThirtySevenStopMatrixBatching() {
  const calls = { matrix: [], routes: [] };
  const body = planBody(37);
  body.stops[9].locked_order = 10;
  const service = createGoogleRoutingService({
    apiKey: "test-key",
    routeOptimizationEnabled: false,
    fetchImpl: routesApiFake(calls),
    sleep: async () => {},
    now: () => FIXED_NOW
  });

  const result = await service.plan(body);
  assert.equal(calls.matrix.length, 4, "38 locations should use four 25x25-or-smaller matrix calls");
  assert.equal(calls.routes.length, 2, "37 stops should use two Compute Routes chunks");
  assert.equal(result.ordered_stop_ids.length, 37);
  assert.equal(new Set(result.ordered_stop_ids).size, 37);
  assert.equal(result.ordered_stop_ids[9], "stop-10");
  assert.equal(result.legs.length, 37);
  assert.equal(result.distance_meters, 37_000);
  assert.equal(result.travel_time_seconds, 370);
  assert.equal(result.strategy, "route_matrix");
  assert.equal(result.provider, "google");
}

async function testFixedOrderChunking() {
  const calls = { matrix: [], routes: [] };
  const service = createGoogleRoutingService({
    apiKey: "test-key",
    routeOptimizationEnabled: false,
    fetchImpl: routesApiFake(calls),
    now: () => FIXED_NOW
  });
  const body = planBody(37, { optimize_order: false });
  const result = await service.plan(body);
  assert.equal(calls.matrix.length, 0);
  assert.equal(calls.routes.length, 2);
  assert.deepEqual(result.ordered_stop_ids, body.stops.map((stop) => stop.id));
  assert.equal(result.strategy, "fixed_order");
}

async function testRouteOptimizationResponse() {
  const fetchImpl = async (url, init) => {
    assert.match(url, /routeoptimization\.googleapis\.com/);
    const body = JSON.parse(init.body);
    assert.equal(body.model.shipments.length, 3);
    return response({
      routes: [{
        vehicleStartTime: "2026-08-19T12:00:00Z",
        vehicleEndTime: "2026-08-19T12:23:00Z",
        visits: [
          { shipmentLabel: "stop-3", startTime: "2026-08-19T12:05:00Z" },
          { shipmentLabel: "stop-2", startTime: "2026-08-19T12:10:00Z" },
          { shipmentLabel: "stop-1", startTime: "2026-08-19T12:18:00Z" }
        ],
        transitions: [
          { travelDuration: "300s", travelDistanceMeters: 2000 },
          { travelDuration: "300s", travelDistanceMeters: 2100 },
          { travelDuration: "480s", travelDistanceMeters: 2200 },
          { travelDuration: "0s", travelDistanceMeters: 0 }
        ],
        routePolyline: { points: "_p~iF~ps|U_ulLnnqC_mqNvxq`@" }
      }]
    });
  };
  const service = createGoogleRoutingService({
    apiKey: "test-key",
    projectId: "test-project",
    routeOptimizationEnabled: true,
    fetchImpl,
    now: () => FIXED_NOW
  });
  const result = await service.plan(planBody(3));
  assert.deepEqual(result.ordered_stop_ids, ["stop-3", "stop-2", "stop-1"]);
  assert.equal(result.strategy, "route_optimization");
  assert.equal(result.legs.length, 3);
  assert.equal(result.distance_meters, 6300);
  assert.equal(result.encoded_polylines.length, 1);
  assert.equal(result.legs[0].estimated_arrival_at, "2026-08-19T12:05:00.000Z");
}

async function testRetryAfterRateLimit() {
  let attempts = 0;
  const delays = [];
  const service = createGoogleRoutingService({
    apiKey: "test-key",
    routeOptimizationEnabled: false,
    maximumAttempts: 2,
    fetchImpl: async () => {
      attempts += 1;
      if (attempts === 1) return response({ error: { message: "slow down" } }, 429, { "retry-after": "0" });
      return response({ routes: [{ legs: [{ distanceMeters: 10, duration: "2s" }], polyline: { encodedPolyline: "abc" } }] });
    },
    sleep: async (delay) => { delays.push(delay); },
    now: () => FIXED_NOW
  });
  const result = await service.plan(planBody(1, { optimize_order: false }));
  assert.equal(attempts, 2);
  assert.equal(delays.length, 1);
  assert.equal(result.travel_time_seconds, 2);
}

async function testMissingRoadMatrixElementFailsClosed() {
  let routeCalls = 0;
  const service = createGoogleRoutingService({
    apiKey: "test-key",
    routeOptimizationEnabled: false,
    maximumAttempts: 1,
    fetchImpl: async (url) => {
      if (url.includes("computeRouteMatrix")) return response([]);
      routeCalls += 1;
      return response({ routes: [] });
    },
    now: () => FIXED_NOW
  });

  await assert.rejects(
    () => service.plan(planBody(1)),
    (error) => error instanceof GoogleRoutingError && error.code === "google_route_not_found" && error.statusCode === 422
  );
  assert.equal(routeCalls, 0, "a missing road route must not fall through to straight-line or final-route estimates");
}

async function testRouteOptimizationFallsBackToGoogleMatrix() {
  const calls = { matrix: [], routes: [] };
  const routesFake = routesApiFake(calls);
  let optimizationCalls = 0;
  const service = createGoogleRoutingService({
    apiKey: "test-key",
    projectId: "test-project",
    routeOptimizationEnabled: true,
    maximumAttempts: 1,
    fetchImpl: async (url, init) => {
      if (url.includes("routeoptimization.googleapis.com")) {
        optimizationCalls += 1;
        return response({ error: { message: "provider unavailable" } }, 503);
      }
      return routesFake(url, init);
    },
    now: () => FIXED_NOW
  });

  const result = await service.plan(planBody(2));
  assert.equal(optimizationCalls, 1);
  assert.equal(calls.matrix.length, 1);
  assert.equal(calls.routes.length, 1);
  assert.equal(result.strategy, "route_matrix");
  assert.ok(result.warnings.some((warning) => warning.includes("Route Optimization was unavailable")));
}

async function testValidationAndConfigurationFailures() {
  const unconfigured = createGoogleRoutingService({ apiKey: null, now: () => FIXED_NOW });
  await assert.rejects(
    () => unconfigured.plan(planBody(1)),
    (error) => error instanceof GoogleRoutingError && error.code === "google_routing_not_configured" && error.statusCode === 503
  );

  const duplicateLocks = planBody(2);
  duplicateLocks.stops[0].locked_order = 1;
  duplicateLocks.stops[1].locked_order = 1;
  assert.throws(
    () => normalizePlanRequest(duplicateLocks, FIXED_NOW),
    (error) => error.code === "invalid_route_request" && error.statusCode === 400
  );
}

const tests = [
  ["37-stop matrix batching", testThirtySevenStopMatrixBatching],
  ["fixed-order Compute Routes chunking", testFixedOrderChunking],
  ["Route Optimization response parsing", testRouteOptimizationResponse],
  ["rate-limit retry", testRetryAfterRateLimit],
  ["missing matrix element fails closed", testMissingRoadMatrixElementFailsClosed],
  ["Route Optimization Google-matrix fallback", testRouteOptimizationFallsBackToGoogleMatrix],
  ["validation and configuration failures", testValidationAndConfigurationFailures]
];

let failures = 0;
for (const [name, test] of tests) {
  try {
    await test();
    console.log(`PASS ${name}`);
  } catch (error) {
    failures += 1;
    console.error(`FAIL ${name}`);
    console.error(error);
  }
}

if (failures) process.exitCode = 1;
else console.log(`Google routing tests passed (${tests.length}).`);
