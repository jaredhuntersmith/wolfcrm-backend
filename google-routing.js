const ROUTES_BASE_URL = "https://routes.googleapis.com";
const ROUTE_OPTIMIZATION_BASE_URL = "https://routeoptimization.googleapis.com";

export const GOOGLE_ROUTING_LIMITS = Object.freeze({
  maximumStops: 100,
  matrixBatchSize: 25,
  matrixMaximumElements: 625,
  computeRoutesMaximumIntermediates: 25
});

const RETRYABLE_STATUS_CODES = new Set([408, 429, 500, 502, 503, 504]);
const ENDING_BEHAVIORS = new Set(["finish_at_final_stop", "return_to_start", "custom_address"]);

export class GoogleRoutingError extends Error {
  constructor(code, message, { statusCode = 500, retryable = false, details = null, cause = null } = {}) {
    super(message, cause ? { cause } : undefined);
    this.name = "GoogleRoutingError";
    this.code = code;
    this.statusCode = statusCode;
    this.retryable = retryable;
    this.details = details;
  }
}

class AsyncGate {
  constructor(limit) {
    this.limit = Math.max(1, limit);
    this.active = 0;
    this.queue = [];
  }

  async run(operation, signal) {
    await this.acquire(signal);
    try {
      return await operation();
    } finally {
      this.release();
    }
  }

  acquire(signal) {
    if (signal?.aborted) return Promise.reject(abortedError(signal));
    if (this.active < this.limit) {
      this.active += 1;
      return Promise.resolve();
    }
    return new Promise((resolve, reject) => {
      const entry = { resolve, reject, signal, aborted: false, abortHandler: null };
      if (signal) {
        entry.abortHandler = () => {
          entry.aborted = true;
          reject(abortedError(signal));
        };
        signal.addEventListener("abort", entry.abortHandler, { once: true });
      }
      this.queue.push(entry);
    });
  }

  release() {
    this.active = Math.max(0, this.active - 1);
    while (this.queue.length) {
      const entry = this.queue.shift();
      if (entry.aborted || entry.signal?.aborted) continue;
      if (entry.signal && entry.abortHandler) {
        entry.signal.removeEventListener("abort", entry.abortHandler);
      }
      this.active += 1;
      entry.resolve();
      return;
    }
  }
}

class TimedCache {
  constructor({ ttlMs, maximumEntries = 250, now }) {
    this.ttlMs = ttlMs;
    this.maximumEntries = maximumEntries;
    this.now = now;
    this.entries = new Map();
  }

  get(key) {
    const entry = this.entries.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= this.now().getTime()) {
      this.entries.delete(key);
      return null;
    }
    this.entries.delete(key);
    this.entries.set(key, entry);
    return structuredClone(entry.value);
  }

  set(key, value) {
    this.entries.delete(key);
    this.entries.set(key, { expiresAt: this.now().getTime() + this.ttlMs, value: structuredClone(value) });
    while (this.entries.size > this.maximumEntries) {
      this.entries.delete(this.entries.keys().next().value);
    }
  }
}

export function googleRoutingConfigFromEnv(env = process.env) {
  const apiKey = firstNonEmpty(
    env.GOOGLE_MAPS_PLATFORM_API_KEY,
    env.GOOGLE_MAPS_API_KEY,
    env.GOOGLE_ROUTES_API_KEY
  );
  const projectId = firstNonEmpty(env.GOOGLE_CLOUD_PROJECT_ID, env.GOOGLE_PROJECT_ID);
  return {
    apiKey,
    projectId,
    routeOptimizationEnabled: parseBoolean(env.GOOGLE_ROUTE_OPTIMIZATION_ENABLED, Boolean(projectId)),
    maximumConcurrency: clampInteger(env.GOOGLE_ROUTING_MAX_CONCURRENCY, 2, 1, 5),
    requestTimeoutMs: clampInteger(env.GOOGLE_ROUTING_TIMEOUT_MS, 12_000, 2_000, 30_000),
    overallTimeoutMs: clampInteger(env.GOOGLE_ROUTING_OVERALL_TIMEOUT_MS, 55_000, 10_000, 90_000),
    cacheTtlMs: clampInteger(env.GOOGLE_ROUTING_CACHE_TTL_MS, 120_000, 0, 900_000),
    maximumAttempts: clampInteger(env.GOOGLE_ROUTING_MAX_ATTEMPTS, 3, 1, 4)
  };
}

export function createGoogleRoutingService(options = {}) {
  const config = { ...googleRoutingConfigFromEnv(options.env), ...options };
  return new GoogleRoutingService(config);
}

export class GoogleRoutingService {
  constructor({
    apiKey = null,
    projectId = null,
    routeOptimizationEnabled = Boolean(projectId),
    maximumConcurrency = 2,
    requestTimeoutMs = 12_000,
    overallTimeoutMs = 55_000,
    cacheTtlMs = 120_000,
    maximumAttempts = 3,
    fetchImpl = globalThis.fetch,
    sleep = defaultSleep,
    now = () => new Date()
  } = {}) {
    this.apiKey = firstNonEmpty(apiKey);
    this.projectId = firstNonEmpty(projectId);
    this.routeOptimizationEnabled = Boolean(routeOptimizationEnabled);
    this.requestTimeoutMs = requestTimeoutMs;
    this.overallTimeoutMs = overallTimeoutMs;
    this.maximumAttempts = maximumAttempts;
    this.fetchImpl = fetchImpl;
    this.sleep = sleep;
    this.now = now;
    this.gate = new AsyncGate(maximumConcurrency);
    this.cache = new TimedCache({ ttlMs: cacheTtlMs, now });
  }

  status() {
    return {
      configured: Boolean(this.apiKey),
      routes_api_configured: Boolean(this.apiKey),
      route_optimization_configured: Boolean(this.apiKey && this.projectId && this.routeOptimizationEnabled),
      provider: "google",
      maximum_stops: GOOGLE_ROUTING_LIMITS.maximumStops,
      matrix_maximum_elements: GOOGLE_ROUTING_LIMITS.matrixMaximumElements,
      compute_routes_maximum_intermediates: GOOGLE_ROUTING_LIMITS.computeRoutesMaximumIntermediates
    };
  }

  async plan(rawRequest, { signal = null } = {}) {
    if (!this.apiKey) {
      throw new GoogleRoutingError(
        "google_routing_not_configured",
        "Google routing is not configured for this WolfCRM server.",
        { statusCode: 503 }
      );
    }
    const request = normalizePlanRequest(rawRequest, this.now());
    const deadline = linkedTimeoutSignal(signal, this.overallTimeoutMs);
    const warnings = [];
    try {
      if (request.optimizeOrder && request.lockedOrders.size === 0 && this.routeOptimizationEnabled && this.projectId) {
        try {
          return await this.optimizeTours(request, deadline.signal);
        } catch (error) {
          if (deadline.signal.aborted) throw abortedError(deadline.signal);
          if (error instanceof GoogleRoutingError && error.code === "invalid_route_request") throw error;
          warnings.push("Google Route Optimization was unavailable, so WolfCRM used Google road-time matrix optimization.");
        }
      }

      let orderedStops = request.stops;
      let strategy = "fixed_order";
      if (request.optimizeOrder) {
        const matrix = await this.computeCompleteMatrix(request, deadline.signal);
        const orderedIds = optimizeWithMatrix(request, matrix);
        const byId = new Map(request.stops.map((stop) => [stop.id, stop]));
        orderedStops = orderedIds.map((id) => byId.get(id));
        strategy = "route_matrix";
      }
      return await this.computeFixedRoute({ ...request, stops: orderedStops }, strategy, warnings, deadline.signal);
    } finally {
      deadline.cleanup();
    }
  }

  async optimizeTours(request, signal) {
    const startTime = request.departureTime;
    const endTime = new Date(startTime.getTime() + Math.max(7 * 86_400_000, request.serviceTimeSeconds * 1000 + 86_400_000));
    const vehicle = {
      label: "wolfcrm-route",
      startWaypoint: googleWaypoint(request.start),
      startTimeWindows: [{
        startTime: startTime.toISOString(),
        endTime: new Date(startTime.getTime() + 60_000).toISOString()
      }],
      costPerTraveledHour: 1
    };
    if (request.end) vehicle.endWaypoint = googleWaypoint(request.end);

    const body = {
      timeout: "20s",
      searchMode: "CONSUME_ALL_AVAILABLE_TIME",
      populatePolylines: true,
      populateTransitionPolylines: true,
      model: {
        globalStartTime: startTime.toISOString(),
        globalEndTime: endTime.toISOString(),
        globalDurationCostPerHour: 1,
        shipments: request.stops.map((stop) => ({
          label: stop.id,
          penaltyCost: 1_000_000,
          deliveries: [{
            label: stop.id,
            arrivalWaypoint: googleWaypoint(stop),
            duration: secondsDuration(stop.serviceDurationSeconds)
          }]
        })),
        vehicles: [vehicle]
      }
    };

    const endpoint = `${ROUTE_OPTIMIZATION_BASE_URL}/v1/projects/${encodeURIComponent(this.projectId)}:optimizeTours`;
    const response = await this.googleRequest(endpoint, body, { signal, cacheable: false });
    if (Array.isArray(response.skippedShipments) && response.skippedShipments.length) {
      throw new GoogleRoutingError("google_optimization_skipped_stops", "Google could not include every stop in this route.", { statusCode: 502 });
    }
    const route = Array.isArray(response.routes) ? response.routes[0] : null;
    if (!route || !Array.isArray(route.visits)) {
      throw new GoogleRoutingError("google_optimization_empty", "Google did not return an optimized route.", { statusCode: 502 });
    }

    const byId = new Map(request.stops.map((stop) => [stop.id, stop]));
    const orderedStops = route.visits.map((visit) => {
      const fallbackIndex = Number.isInteger(visit.shipmentIndex) ? visit.shipmentIndex : 0;
      const id = visit.shipmentLabel || request.stops[fallbackIndex]?.id;
      return byId.get(id);
    });
    validateReturnedStops(request.stops, orderedStops);

    const transitions = Array.isArray(route.transitions) ? route.transitions : [];
    if (transitions.length < orderedStops.length) {
      throw new GoogleRoutingError("google_optimization_incomplete", "Google returned an incomplete set of route legs.", { statusCode: 502 });
    }
    const legs = [];
    let sourceId = request.start.id;
    let rollingTime = parseDate(route.vehicleStartTime) || startTime;
    for (let index = 0; index < orderedStops.length; index += 1) {
      const stop = orderedStops[index];
      const visit = route.visits[index] || {};
      const transition = transitions[index] || {};
      const travelSeconds = parseDurationSeconds(transition.travelDuration);
      const distanceMeters = finiteNumber(transition.travelDistanceMeters, 0);
      const arrival = parseDate(visit.startTime) || new Date(rollingTime.getTime() + travelSeconds * 1000);
      const departure = new Date(arrival.getTime() + stop.serviceDurationSeconds * 1000);
      legs.push(routeLeg(sourceId, stop.id, distanceMeters, travelSeconds, stop.serviceDurationSeconds, arrival, departure, encodedPolyline(transition.routePolyline)));
      sourceId = stop.id;
      rollingTime = departure;
    }
    if (request.end) {
      const transition = transitions[orderedStops.length];
      if (!transition) {
        throw new GoogleRoutingError("google_optimization_incomplete", "Google omitted the final endpoint leg.", { statusCode: 502 });
      }
      const travelSeconds = parseDurationSeconds(transition.travelDuration);
      const arrival = parseDate(route.vehicleEndTime) || new Date(rollingTime.getTime() + travelSeconds * 1000);
      legs.push(routeLeg(sourceId, request.end.id, finiteNumber(transition.travelDistanceMeters, 0), travelSeconds, 0, arrival, arrival, encodedPolyline(transition.routePolyline)));
      rollingTime = arrival;
    }

    const estimatedStart = parseDate(route.vehicleStartTime) || startTime;
    const estimatedFinish = parseDate(route.vehicleEndTime) || rollingTime;
    const travelTimeSeconds = legs.reduce((sum, leg) => sum + leg.travel_time_seconds, 0);
    const distanceMeters = legs.reduce((sum, leg) => sum + leg.distance_meters, 0);
    const totalRouteTimeSeconds = Math.max(
      travelTimeSeconds + request.serviceTimeSeconds,
      (estimatedFinish.getTime() - estimatedStart.getTime()) / 1000
    );
    const overallPolyline = encodedPolyline(route.routePolyline);
    const polylines = overallPolyline
      ? [overallPolyline]
      : uniqueStrings(legs.map((leg) => leg.encoded_polyline));
    return {
      provider: "google",
      strategy: "route_optimization",
      optimized: true,
      ordered_stop_ids: orderedStops.map((stop) => stop.id),
      distance_meters: distanceMeters,
      travel_time_seconds: travelTimeSeconds,
      service_time_seconds: request.serviceTimeSeconds,
      total_route_time_seconds: totalRouteTimeSeconds,
      estimated_start_at: estimatedStart.toISOString(),
      estimated_finish_at: estimatedFinish.toISOString(),
      calculated_at: this.now().toISOString(),
      legs,
      encoded_polylines: polylines,
      warnings: []
    };
  }

  async computeCompleteMatrix(request, signal) {
    const locations = [request.start, ...request.stops, ...(request.end ? [request.end] : [])];
    const blocks = chunked(locations, GOOGLE_ROUTING_LIMITS.matrixBatchSize);
    const tasks = [];
    for (const origins of blocks) {
      for (const destinations of blocks) tasks.push({ origins, destinations });
    }

    const matrix = new Map();
    for (const location of locations) matrix.set(matrixKey(location.id, location.id), { duration: 0, distance: 0 });
    await runWorkerPool(tasks, 2, async ({ origins, destinations }) => {
      const body = {
        origins: origins.map((location) => ({ waypoint: googleWaypoint(location) })),
        destinations: destinations.map((location) => ({ waypoint: googleWaypoint(location) })),
        travelMode: "DRIVE",
        routingPreference: "TRAFFIC_AWARE",
        departureTime: request.departureTime.toISOString()
      };
      const elements = await this.googleRequest(`${ROUTES_BASE_URL}/distanceMatrix/v2:computeRouteMatrix`, body, {
        signal,
        fieldMask: "originIndex,destinationIndex,status,condition,distanceMeters,duration",
        cacheable: true
      });
      if (!Array.isArray(elements)) {
        throw new GoogleRoutingError("google_matrix_invalid", "Google returned an invalid route matrix.", { statusCode: 502 });
      }
      for (const element of elements) {
        const origin = origins[element.originIndex];
        const destination = destinations[element.destinationIndex];
        if (!origin || !destination || origin.id === destination.id) continue;
        const statusCode = finiteNumber(element.status?.code, 0);
        if (statusCode !== 0 || element.condition !== "ROUTE_EXISTS") continue;
        const duration = parseDurationSeconds(element.duration);
        const distance = finiteNumber(element.distanceMeters, null);
        if (distance == null) continue;
        matrix.set(matrixKey(origin.id, destination.id), { duration, distance });
      }
    }, signal);
    return matrix;
  }

  async computeFixedRoute(request, strategy, warnings, signal) {
    const points = [request.start, ...request.stops, ...(request.end ? [request.end] : [])];
    const maximumPoints = GOOGLE_ROUTING_LIMITS.computeRoutesMaximumIntermediates + 2;
    const legs = [];
    const encodedPolylines = [];
    const providerWarnings = [...warnings];
    let cursorTime = request.departureTime;

    for (let offset = 0; offset < points.length - 1; offset += maximumPoints - 1) {
      const routePoints = points.slice(offset, Math.min(points.length, offset + maximumPoints));
      const body = {
        origin: googleWaypoint(routePoints[0]),
        destination: googleWaypoint(routePoints[routePoints.length - 1]),
        intermediates: routePoints.slice(1, -1).map(googleWaypoint),
        travelMode: "DRIVE",
        routingPreference: "TRAFFIC_AWARE",
        departureTime: cursorTime.toISOString(),
        computeAlternativeRoutes: false,
        polylineQuality: "OVERVIEW",
        polylineEncoding: "ENCODED_POLYLINE"
      };
      const response = await this.googleRequest(`${ROUTES_BASE_URL}/directions/v2:computeRoutes`, body, {
        signal,
        fieldMask: "routes.legs.distanceMeters,routes.legs.duration,routes.polyline.encodedPolyline,routes.warnings",
        cacheable: true
      });
      const route = Array.isArray(response.routes) ? response.routes[0] : null;
      const routeLegs = route?.legs;
      if (!route || !Array.isArray(routeLegs) || routeLegs.length !== routePoints.length - 1) {
        throw new GoogleRoutingError("google_route_incomplete", "Google returned an incomplete route.", { statusCode: 502 });
      }
      const routePolyline = encodedPolyline(route.polyline);
      if (routePolyline) encodedPolylines.push(routePolyline);
      if (Array.isArray(route.warnings)) providerWarnings.push(...route.warnings.filter((value) => typeof value === "string"));

      for (let index = 0; index < routeLegs.length; index += 1) {
        const rawLeg = routeLegs[index];
        const source = routePoints[index];
        const destination = routePoints[index + 1];
        const travelSeconds = parseDurationSeconds(rawLeg.duration);
        const distanceMeters = finiteNumber(rawLeg.distanceMeters, null);
        if (distanceMeters == null) {
          throw new GoogleRoutingError("google_route_incomplete", `Google omitted road distance for ${source.id} to ${destination.id}.`, { statusCode: 502 });
        }
        const arrival = new Date(cursorTime.getTime() + travelSeconds * 1000);
        const serviceDuration = destination.kind === "stop" ? destination.serviceDurationSeconds : 0;
        const departure = new Date(arrival.getTime() + serviceDuration * 1000);
        legs.push(routeLeg(source.id, destination.id, distanceMeters, travelSeconds, serviceDuration, arrival, departure, null));
        cursorTime = departure;
      }
    }

    const distanceMeters = legs.reduce((sum, leg) => sum + leg.distance_meters, 0);
    const travelTimeSeconds = legs.reduce((sum, leg) => sum + leg.travel_time_seconds, 0);
    return {
      provider: "google",
      strategy,
      optimized: strategy !== "fixed_order",
      ordered_stop_ids: request.stops.map((stop) => stop.id),
      distance_meters: distanceMeters,
      travel_time_seconds: travelTimeSeconds,
      service_time_seconds: request.serviceTimeSeconds,
      total_route_time_seconds: travelTimeSeconds + request.serviceTimeSeconds,
      estimated_start_at: request.departureTime.toISOString(),
      estimated_finish_at: cursorTime.toISOString(),
      calculated_at: this.now().toISOString(),
      legs,
      encoded_polylines: uniqueStrings(encodedPolylines),
      warnings: uniqueStrings(providerWarnings)
    };
  }

  async googleRequest(url, body, { signal, fieldMask = null, cacheable = false }) {
    const cacheKey = cacheable ? JSON.stringify([url, fieldMask, body]) : null;
    if (cacheKey) {
      const cached = this.cache.get(cacheKey);
      if (cached != null) return cached;
    }

    let lastError = null;
    for (let attempt = 0; attempt < this.maximumAttempts; attempt += 1) {
      if (signal?.aborted) throw abortedError(signal);
      try {
        const value = await this.gate.run(async () => {
          const attemptSignal = linkedTimeoutSignal(signal, this.requestTimeoutMs);
          try {
            const headers = {
              "Content-Type": "application/json",
              "X-Goog-Api-Key": this.apiKey
            };
            if (fieldMask) headers["X-Goog-FieldMask"] = fieldMask;
            const response = await this.fetchImpl(url, {
              method: "POST",
              headers,
              body: JSON.stringify(body),
              signal: attemptSignal.signal
            });
            if (!response.ok) {
              const retryAfterMs = retryAfterMilliseconds(response.headers?.get?.("retry-after"));
              const upstream = await safeResponseJson(response);
              throw new GoogleRoutingError(
                "google_routing_upstream_error",
                upstream?.error?.message || `Google routing returned HTTP ${response.status}.`,
                {
                  statusCode: 502,
                  retryable: RETRYABLE_STATUS_CODES.has(response.status),
                  details: { upstream_status: response.status, retry_after_ms: retryAfterMs }
                }
              );
            }
            return await response.json();
          } catch (error) {
            if (signal?.aborted) throw abortedError(signal);
            if (attemptSignal.signal.aborted) {
              throw new GoogleRoutingError("google_routing_timeout", "Google routing timed out.", { statusCode: 504, retryable: true, cause: error });
            }
            if (error instanceof GoogleRoutingError) throw error;
            throw new GoogleRoutingError("google_routing_network_error", "Google routing could not be reached.", { statusCode: 502, retryable: true, cause: error });
          } finally {
            attemptSignal.cleanup();
          }
        }, signal);
        if (cacheKey) this.cache.set(cacheKey, value);
        return value;
      } catch (error) {
        lastError = error;
        if (signal?.aborted) throw abortedError(signal);
        if (!isRetryable(error) || attempt >= this.maximumAttempts - 1) throw error;
        const retryAfter = finiteNumber(error.details?.retry_after_ms, 0);
        const backoff = Math.max(retryAfter, Math.min(3_000, 250 * (2 ** attempt) + Math.floor(Math.random() * 100)));
        await this.sleep(backoff, signal);
      }
    }
    throw lastError || new GoogleRoutingError("google_routing_failed", "Google routing failed.", { statusCode: 502 });
  }
}

export function normalizePlanRequest(raw, now = new Date()) {
  if (!raw || typeof raw !== "object") throw invalidRequest("A route plan body is required.");
  const start = normalizeLocation(raw.start, "route-start", "start");
  const rawStops = Array.isArray(raw.stops) ? raw.stops : [];
  if (!rawStops.length) throw invalidRequest("At least one route stop is required.", { field: "stops" });
  if (rawStops.length > GOOGLE_ROUTING_LIMITS.maximumStops) {
    throw invalidRequest(`Routes support up to ${GOOGLE_ROUTING_LIMITS.maximumStops} stops.`, { field: "stops", maximum: GOOGLE_ROUTING_LIMITS.maximumStops });
  }
  const ids = new Set();
  const lockedPositions = new Set();
  const lockedOrders = new Map();
  const stops = rawStops.map((rawStop, index) => {
    const id = cleanId(rawStop?.id);
    if (!id || id === start.id || id === "route-end") throw invalidRequest(`Stop ${index + 1} needs a unique ID.`, { field: `stops[${index}].id` });
    if (ids.has(id)) throw invalidRequest(`Duplicate stop ID: ${id}.`, { field: `stops[${index}].id` });
    ids.add(id);
    const location = normalizeLocation(rawStop, id, `stops[${index}]`);
    const serviceDurationSeconds = optionalBoundedNumber(rawStop.service_duration_seconds ?? rawStop.serviceDurationSeconds, 0, 86_400, 0);
    const lockedOrderValue = rawStop.locked_order ?? rawStop.lockedOrder;
    if (lockedOrderValue != null) {
      const lockedOrder = Number(lockedOrderValue);
      if (!Number.isInteger(lockedOrder) || lockedOrder < 1 || lockedOrder > rawStops.length) {
        throw invalidRequest(`Locked position for ${id} is outside this route.`, { field: `stops[${index}].locked_order` });
      }
      if (lockedPositions.has(lockedOrder)) {
        throw invalidRequest(`More than one stop is locked at position ${lockedOrder}.`, { field: `stops[${index}].locked_order` });
      }
      lockedPositions.add(lockedOrder);
      lockedOrders.set(id, lockedOrder);
    }
    return { ...location, kind: "stop", serviceDurationSeconds, lockedOrder: lockedOrders.get(id) ?? null };
  });

  const endingBehavior = ENDING_BEHAVIORS.has(raw.ending_behavior) ? raw.ending_behavior : "finish_at_final_stop";
  let end = null;
  if (endingBehavior === "return_to_start") {
    end = { ...start, id: "route-end", label: "Return to start", kind: "endpoint" };
  } else if (endingBehavior === "custom_address") {
    end = { ...normalizeLocation(raw.end, "route-end", "end"), kind: "endpoint" };
  }

  let departureTime = parseDate(raw.departure_time) || now;
  if (departureTime.getTime() < now.getTime() - 300_000) departureTime = now;
  if (departureTime.getTime() > now.getTime() + 31 * 86_400_000) {
    throw invalidRequest("Departure time must be within 31 days.", { field: "departure_time" });
  }
  const serviceTimeSeconds = stops.reduce((sum, stop) => sum + stop.serviceDurationSeconds, 0);
  return {
    start: { ...start, kind: "start" },
    stops,
    end,
    endingBehavior,
    optimizeOrder: raw.optimize_order !== false,
    lockedOrders,
    departureTime,
    serviceTimeSeconds
  };
}

export function optimizeWithMatrix(request, matrix) {
  const stopIds = request.stops.map((stop) => stop.id);
  if (stopIds.length <= 1) {
    ensurePathExists([request.start.id, ...stopIds, ...(request.end ? [request.end.id] : [])], matrix);
    return stopIds;
  }
  const order = Array(stopIds.length).fill(null);
  const remaining = new Set(stopIds);
  for (const [id, oneBasedPosition] of request.lockedOrders) {
    order[oneBasedPosition - 1] = id;
    remaining.delete(id);
  }

  let cursor = request.start.id;
  for (let index = 0; index < order.length; index += 1) {
    if (order[index]) {
      requireMatrixCost(matrix, cursor, order[index]);
      cursor = order[index];
      continue;
    }
    const nextLocked = order.slice(index + 1).find(Boolean) || request.end?.id || null;
    let best = null;
    let bestScore = Number.POSITIVE_INFINITY;
    for (const candidate of remaining) {
      const primary = matrix.get(matrixKey(cursor, candidate))?.duration;
      if (!Number.isFinite(primary)) continue;
      const secondary = nextLocked ? matrix.get(matrixKey(candidate, nextLocked))?.duration : 0;
      const score = primary + (Number.isFinite(secondary) ? secondary * 0.001 : 1_000_000_000);
      if (score < bestScore || (score === bestScore && candidate < best)) {
        best = candidate;
        bestScore = score;
      }
    }
    if (!best) throw noRoute(cursor, nextLocked || "remaining stops");
    order[index] = best;
    remaining.delete(best);
    cursor = best;
  }

  const lockedIndexes = new Set([...request.lockedOrders.values()].map((position) => position - 1));
  let best = order;
  let bestCost = routeTravelTime(best, request, matrix);
  for (let pass = 0; pass < 8; pass += 1) {
    let improved = false;
    for (let first = 0; first < best.length; first += 1) {
      if (lockedIndexes.has(first)) continue;
      for (let second = first + 1; second < best.length; second += 1) {
        if (lockedIndexes.has(second)) continue;
        const candidate = [...best];
        [candidate[first], candidate[second]] = [candidate[second], candidate[first]];
        const candidateCost = routeTravelTime(candidate, request, matrix, false);
        if (candidateCost + 1 < bestCost) {
          best = candidate;
          bestCost = candidateCost;
          improved = true;
        }
      }
    }
    if (!improved) break;
  }
  ensurePathExists([request.start.id, ...best, ...(request.end ? [request.end.id] : [])], matrix);
  return best;
}

function routeTravelTime(order, request, matrix, shouldThrow = true) {
  const ids = [request.start.id, ...order, ...(request.end ? [request.end.id] : [])];
  let total = 0;
  for (let index = 0; index < ids.length - 1; index += 1) {
    const value = matrix.get(matrixKey(ids[index], ids[index + 1]))?.duration;
    if (!Number.isFinite(value)) {
      if (shouldThrow) throw noRoute(ids[index], ids[index + 1]);
      return Number.POSITIVE_INFINITY;
    }
    total += value;
  }
  return total;
}

function validateReturnedStops(requested, returned) {
  if (returned.length !== requested.length || returned.some((stop) => !stop)) {
    throw new GoogleRoutingError("google_optimization_incomplete", "Google did not return every requested stop.", { statusCode: 502 });
  }
  const expected = new Set(requested.map((stop) => stop.id));
  const actual = new Set(returned.map((stop) => stop.id));
  if (actual.size !== expected.size || [...expected].some((id) => !actual.has(id))) {
    throw new GoogleRoutingError("google_optimization_incomplete", "Google returned duplicate or unknown stops.", { statusCode: 502 });
  }
}

function normalizeLocation(raw, fallbackId, field) {
  if (!raw || typeof raw !== "object") throw invalidRequest(`${field} coordinates are required.`, { field });
  const latitude = Number(raw.latitude ?? raw.lat);
  const longitude = Number(raw.longitude ?? raw.lng);
  if (!Number.isFinite(latitude) || latitude < -90 || latitude > 90) {
    throw invalidRequest(`${field} latitude is invalid.`, { field: `${field}.latitude` });
  }
  if (!Number.isFinite(longitude) || longitude < -180 || longitude > 180) {
    throw invalidRequest(`${field} longitude is invalid.`, { field: `${field}.longitude` });
  }
  return {
    id: cleanId(raw.id) || fallbackId,
    label: cleanLabel(raw.label, fallbackId),
    latitude,
    longitude
  };
}

function googleWaypoint(location) {
  return { location: { latLng: { latitude: location.latitude, longitude: location.longitude } } };
}

function routeLeg(sourceId, destinationId, distanceMeters, travelSeconds, serviceSeconds, arrival, departure, polyline) {
  return {
    from_id: sourceId,
    to_id: destinationId,
    distance_meters: distanceMeters,
    travel_time_seconds: travelSeconds,
    service_duration_seconds: serviceSeconds,
    estimated_arrival_at: arrival.toISOString(),
    estimated_departure_at: departure.toISOString(),
    encoded_polyline: polyline || null
  };
}

function encodedPolyline(value) {
  const result = value?.points ?? value?.encodedPolyline;
  return typeof result === "string" && result.length ? result : null;
}

function parseDurationSeconds(value) {
  if (typeof value === "number" && Number.isFinite(value) && value >= 0) return value;
  if (typeof value !== "string" || !/^\d+(?:\.\d+)?s$/.test(value)) {
    throw new GoogleRoutingError("google_duration_invalid", "Google returned an invalid route duration.", { statusCode: 502 });
  }
  return Number(value.slice(0, -1));
}

function secondsDuration(value) {
  const safe = Math.max(0, finiteNumber(value, 0));
  return `${Number.isInteger(safe) ? safe : safe.toFixed(3).replace(/0+$/, "").replace(/\.$/, "")}s`;
}

function matrixKey(sourceId, destinationId) {
  return `${sourceId}\u0000${destinationId}`;
}

function requireMatrixCost(matrix, sourceId, destinationId) {
  const cost = matrix.get(matrixKey(sourceId, destinationId));
  if (!cost || !Number.isFinite(cost.duration)) throw noRoute(sourceId, destinationId);
  return cost;
}

function ensurePathExists(ids, matrix) {
  for (let index = 0; index < ids.length - 1; index += 1) requireMatrixCost(matrix, ids[index], ids[index + 1]);
}

function noRoute(sourceId, destinationId) {
  return new GoogleRoutingError(
    "google_route_not_found",
    `Google could not find a driving route from ${sourceId} to ${destinationId}.`,
    { statusCode: 422, details: { source_id: sourceId, destination_id: destinationId } }
  );
}

function invalidRequest(message, details = null) {
  return new GoogleRoutingError("invalid_route_request", message, { statusCode: 400, details });
}

function linkedTimeoutSignal(parentSignal, timeoutMs) {
  const controller = new AbortController();
  const abortFromParent = () => controller.abort(parentSignal?.reason || new Error("cancelled"));
  if (parentSignal?.aborted) abortFromParent();
  else parentSignal?.addEventListener("abort", abortFromParent, { once: true });
  const timer = setTimeout(() => controller.abort(new Error("timeout")), timeoutMs);
  return {
    signal: controller.signal,
    cleanup() {
      clearTimeout(timer);
      parentSignal?.removeEventListener("abort", abortFromParent);
    }
  };
}

function abortedError(signal) {
  const isTimeout = signal?.reason?.message === "timeout";
  return new GoogleRoutingError(
    isTimeout ? "google_routing_timeout" : "google_routing_cancelled",
    isTimeout ? "Google routing timed out." : "Route calculation was cancelled.",
    { statusCode: isTimeout ? 504 : 499, retryable: isTimeout }
  );
}

async function runWorkerPool(items, concurrency, operation, signal) {
  let cursor = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (true) {
      if (signal?.aborted) throw abortedError(signal);
      const index = cursor;
      cursor += 1;
      if (index >= items.length) return;
      await operation(items[index], index);
    }
  });
  await Promise.all(workers);
}

function chunked(values, size) {
  const chunks = [];
  for (let index = 0; index < values.length; index += size) chunks.push(values.slice(index, index + size));
  return chunks;
}

function isRetryable(error) {
  return Boolean(error?.retryable);
}

function retryAfterMilliseconds(value) {
  if (!value) return 0;
  const seconds = Number(value);
  if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000);
  const date = Date.parse(value);
  return Number.isFinite(date) ? Math.max(0, date - Date.now()) : 0;
}

async function safeResponseJson(response) {
  try { return await response.json(); } catch { return null; }
}

function defaultSleep(milliseconds, signal) {
  if (signal?.aborted) return Promise.reject(abortedError(signal));
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, milliseconds);
    const abort = () => {
      clearTimeout(timer);
      reject(abortedError(signal));
    };
    signal?.addEventListener("abort", abort, { once: true });
  });
}

function parseDate(value) {
  if (value instanceof Date && Number.isFinite(value.getTime())) return new Date(value);
  if (typeof value !== "string") return null;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed : null;
}

function cleanId(value) {
  if (typeof value !== "string") return null;
  const clean = value.trim();
  return clean && clean.length <= 200 ? clean : null;
}

function cleanLabel(value, fallback) {
  if (typeof value !== "string") return fallback;
  const clean = value.trim();
  return clean ? clean.slice(0, 300) : fallback;
}

function optionalBoundedNumber(value, minimum, maximum, fallback) {
  if (value == null || value === "") return fallback;
  const number = Number(value);
  if (!Number.isFinite(number) || number < minimum || number > maximum) {
    throw invalidRequest(`Numeric value must be between ${minimum} and ${maximum}.`);
  }
  return number;
}

function finiteNumber(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

function firstNonEmpty(...values) {
  for (const value of values) {
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return null;
}

function parseBoolean(value, fallback) {
  if (value == null || value === "") return fallback;
  return !["0", "false", "no", "off"].includes(String(value).trim().toLowerCase());
}

function clampInteger(value, fallback, minimum, maximum) {
  const parsed = Number.parseInt(value, 10);
  return Math.min(maximum, Math.max(minimum, Number.isFinite(parsed) ? parsed : fallback));
}

function uniqueStrings(values) {
  return [...new Set(values.filter((value) => typeof value === "string" && value.trim()).map((value) => value.trim()))];
}
