import test from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_WEATHER_NOTIFICATION_TEMPLATE,
  DEFAULT_WEATHER_SETTINGS,
  buildWeatherRiskReport,
  classifyWeatherExposure,
  createGoogleWeatherService,
  evaluateWeatherRisk,
  planWeatherReschedule,
  renderWeatherRescheduleMessage,
  validateWeatherExpectedIntervals,
  validateWeatherSettings
} from "../weather-scheduling.js";

test("weather settings validate thresholds, keywords, and message placeholders", () => {
  const settings = validateWeatherSettings({
    enabled: true,
    lookahead_days: 5,
    precipitation_probability_percent: 55,
    thunderstorm_probability_percent: 25,
    wind_speed_mph: 22.5,
    minimum_temperature_f: 30,
    maximum_temperature_f: 100,
    severe_alerts_enabled: true,
    automatic_default_exposure: "unknown",
    outdoor_keywords: [" Exterior ", "exterior", "roof"],
    indoor_keywords: ["interior"],
    notification_template: DEFAULT_WEATHER_NOTIFICATION_TEMPLATE
  });
  assert.deepEqual(settings.outdoor_keywords, ["exterior", "roof"]);
  assert.equal(settings.wind_speed_mph, 22.5);
  assert.throws(
    () => validateWeatherSettings({ ...settings, minimum_temperature_f: 100, maximum_temperature_f: 90 }),
    (error) => error.code === "invalid_weather_settings"
  );
  assert.throws(
    () => validateWeatherSettings({ ...settings, notification_template: "Hi {{unsupported}}" }),
    (error) => error.code === "unsupported_weather_placeholder"
  );
});

test("explicit exposure wins and automatic classification gives indoor keywords precedence", () => {
  assert.deepEqual(
    classifyWeatherExposure({ weather_exposure: "outdoor", title: "Interior windows" }, DEFAULT_WEATHER_SETTINGS),
    { exposure: "outdoor", source: "explicit", matched_keyword: null }
  );
  assert.deepEqual(
    classifyWeatherExposure({ weather_exposure: "auto", title: "Interior and exterior windows" }, DEFAULT_WEATHER_SETTINGS),
    { exposure: "indoor", source: "indoor_keyword", matched_keyword: "interior" }
  );
  assert.equal(
    classifyWeatherExposure({ weather_exposure: "auto", service_items: [{ name: "Gutter Cleaning" }] }, DEFAULT_WEATHER_SETTINGS).exposure,
    "outdoor"
  );
  assert.throws(
    () => classifyWeatherExposure({ weather_exposure: "", title: "Roof" }, DEFAULT_WEATHER_SETTINGS),
    (error) => error.code === "invalid_weather_exposure"
  );
});

test("risk evaluation uses only overlapping forecast hours and active public alerts", () => {
  const job = { id: "job", start_at: "2026-08-20T14:00:00Z", end_at: "2026-08-20T16:00:00Z" };
  const forecast = {
    hours: [
      normalizedHour("2026-08-20T13:00:00Z", { precipitation: 99 }),
      normalizedHour("2026-08-20T14:00:00Z", { precipitation: 65, thunderstorm: 35, wind: 20, temperature: 88 }),
      normalizedHour("2026-08-20T15:00:00Z", { precipitation: 70, thunderstorm: 45, wind: 33, temperature: 94 }),
      normalizedHour("2026-08-20T16:00:00Z", { precipitation: 100 })
    ],
    alerts: [
      { id: "alert-active", title: "Severe Thunderstorm Warning", severity: "SEVERE", start_at: "2026-08-20T15:00:00Z", expires_at: "2026-08-20T17:00:00Z" },
      { id: "alert-expired", title: "Old Warning", severity: "EXTREME", start_at: "2026-08-20T10:00:00Z", expires_at: "2026-08-20T12:00:00Z" }
    ]
  };
  const risk = evaluateWeatherRisk(job, forecast, { ...DEFAULT_WEATHER_SETTINGS, maximum_temperature_f: 90 });
  assert.equal(risk.severity, "high");
  assert.equal(risk.conditions.precipitation_probability_percent, 70);
  assert.equal(risk.conditions.maximum_temperature_f, 94);
  assert.deepEqual(risk.alerts.map((alert) => alert.id), ["alert-active"]);
  assert.ok(risk.reasons.some((reason) => reason.code === "high_temperature"));
});

test("missing provider measurements do not become zero-value weather risks", () => {
  const job = { id: "job", start_at: "2026-08-20T14:00:00Z", end_at: "2026-08-20T15:00:00Z" };
  const hour = normalizedHour("2026-08-20T14:00:00Z");
  hour.precipitation_probability_percent = null;
  hour.thunderstorm_probability_percent = null;
  hour.wind_speed_mph = null;
  hour.wind_gust_mph = null;
  hour.temperature_f = null;
  assert.equal(evaluateWeatherRisk(job, { hours: [hour], alerts: [] }, {
    ...DEFAULT_WEATHER_SETTINGS,
    minimum_temperature_f: 32
  }), null);
});

test("risk report groups nearby locations and exposes partial provider failures", async () => {
  const calls = [];
  const service = {
    status: () => ({ provider: "fake_weather", configured: true }),
    lookup: async ({ latitude, longitude, hours }) => {
      calls.push({ latitude, longitude, hours });
      if (latitude > 39) throw Object.assign(new Error("unavailable"), { code: "forecast_failed" });
      return {
        hours: [normalizedHour("2026-08-20T14:00:00Z", { precipitation: 80 })],
        alerts: []
      };
    }
  };
  const jobs = [
    outdoorJob("one", 38.250, -85.750),
    outdoorJob("two", 38.251, -85.751),
    outdoorJob("three", 40.000, -85.000),
    { ...outdoorJob("missing", null, null), contact_latitude: null, contact_longitude: null }
  ];
  const report = await buildWeatherRiskReport({ jobs, settings: { ...DEFAULT_WEATHER_SETTINGS, enabled: true }, weatherService: service, now: new Date("2026-08-19T12:00:00Z") });
  assert.equal(calls.length, 2);
  assert.deepEqual(report.risks.map((risk) => risk.job_id).sort(), ["one", "two"]);
  assert.equal(report.coverage.missing_location_jobs, 1);
  assert.equal(report.coverage.provider_failed_jobs, 1);
  assert.equal(report.provider_errors[0].code, "forecast_failed");
});

test("risk report excludes jobs that have already started", async () => {
  let calls = 0;
  const report = await buildWeatherRiskReport({
    jobs: [{ ...outdoorJob("started", 38.25, -85.75), started_at: "2026-08-20T14:00:00Z" }],
    settings: { ...DEFAULT_WEATHER_SETTINGS, enabled: true },
    weatherService: {
      status: () => ({ provider: "fake_weather", configured: true }),
      lookup: async () => { calls += 1; return { hours: [], alerts: [] }; }
    },
    now: new Date("2026-08-19T12:00:00Z")
  });
  assert.equal(calls, 0);
  assert.equal(report.coverage.total_jobs, 0);
});

test("risk report marks non-outdoor jobs safe for observation resolution", async () => {
  let calls = 0;
  const report = await buildWeatherRiskReport({
    jobs: [{ ...outdoorJob("indoor", 38.25, -85.75), weather_exposure: "indoor" }],
    settings: { ...DEFAULT_WEATHER_SETTINGS, enabled: true },
    weatherService: {
      status: () => ({ provider: "fake_weather", configured: true }),
      lookup: async () => { calls += 1; return { hours: [], alerts: [] }; }
    },
    now: new Date("2026-08-19T12:00:00Z")
  });
  assert.equal(calls, 0);
  assert.deepEqual(report.observation_resolution_job_ids, ["indoor"]);
});

test("bulk reschedule preserves durations and relative spacing", () => {
  const plan = planWeatherReschedule([
    { id: "later", start_at: "2026-08-20T16:00:00Z", end_at: "2026-08-20T17:30:00Z" },
    { id: "first", start_at: "2026-08-20T14:00:00Z", end_at: "2026-08-20T15:00:00Z" }
  ], "2026-08-22T13:00:00Z", { now: new Date("2026-08-19T12:00:00Z") });
  assert.equal(plan.items[0].job_id, "first");
  assert.equal(plan.items[0].new_start_at, "2026-08-22T13:00:00.000Z");
  assert.equal(plan.items[1].new_start_at, "2026-08-22T15:00:00.000Z");
  assert.equal(plan.items[1].duration_seconds, 5_400);
  assert.throws(
    () => planWeatherReschedule([{ id: "started", start_at: "2026-08-20T14:00:00Z", end_at: "2026-08-20T15:00:00Z", started_at: "2026-08-20T14:01:00Z" }], "2026-08-22T13:00:00Z", { now: new Date("2026-08-19T12:00:00Z") }),
    (error) => error.code === "weather_job_already_in_progress"
  );
});

test("apply-time interval validation rejects a stale preview", () => {
  const jobs = [{ id: "job", start_at: "2026-08-20T14:00:00Z", end_at: "2026-08-20T15:00:00Z" }];
  assert.equal(validateWeatherExpectedIntervals(jobs, [{ job_id: "job", old_start_at: "2026-08-20T14:00:00Z", old_end_at: "2026-08-20T15:00:00Z" }]), true);
  assert.throws(
    () => validateWeatherExpectedIntervals(jobs, [{ job_id: "job", old_start_at: "2026-08-20T14:30:00Z", old_end_at: "2026-08-20T15:30:00Z" }]),
    (error) => error.code === "weather_jobs_changed" && error.statusCode === 409
  );
});

test("reschedule notification renders company-local appointment context", () => {
  const message = renderWeatherRescheduleMessage(DEFAULT_WEATHER_NOTIFICATION_TEMPLATE, {
    customerName: "Morgan Lee",
    companyName: "Window Wolves",
    serviceName: "Exterior Windows",
    oldTime: "2026-08-20T18:00:00Z",
    newTime: "2026-08-21T19:30:00Z",
    timeZone: "America/New_York"
  });
  assert.match(message, /^Hi Morgan,/);
  assert.match(message, /Thursday, Aug 20, 2:00 PM/);
  assert.match(message, /Friday, Aug 21, 3:30 PM/);
  assert.doesNotMatch(message, /{{/);
});

test("Google provider paginates hourly forecasts and normalizes imperial conditions", async () => {
  const calls = [];
  const fetchImpl = async (requestUrl) => {
    const url = new URL(requestUrl);
    calls.push(url);
    if (url.pathname.includes("publicAlerts")) {
      return jsonResponse({ weatherAlerts: [{ alertId: "a1", alertTitle: { text: "Wind Advisory" }, severity: "MODERATE", startTime: "2026-08-20T00:00:00Z", expirationTime: "2026-08-21T00:00:00Z" }] });
    }
    if (!url.searchParams.get("pageToken")) {
      return jsonResponse({
        forecastHours: Array.from({ length: 24 }, (_, index) => providerHour(index)),
        nextPageToken: "next-page",
        timeZone: { id: "America/New_York" }
      });
    }
    return jsonResponse({ forecastHours: [providerHour(24)], timeZone: { id: "America/New_York" } });
  };
  const service = createGoogleWeatherService({ apiKey: "test-key", fetchImpl, sleepImpl: async () => {} });
  const forecast = await service.lookup({ latitude: 38.25, longitude: -85.75, hours: 25 });
  assert.equal(forecast.hours.length, 25);
  assert.equal(forecast.hours[0].temperature_f, 68);
  assert.equal(Math.round(forecast.hours[0].wind_speed_mph), 12);
  assert.equal(forecast.alerts[0].title, "Wind Advisory");
  assert.equal(calls.filter((url) => url.pathname.includes("forecast")).length, 2);
  assert.equal(calls.find((url) => url.searchParams.get("pageToken"))?.searchParams.get("pageToken"), "next-page");
  assert.ok(calls.every((url) => url.searchParams.get("key") === "test-key"));
});

test("Google provider retries rate limits without leaking the credential in errors", async () => {
  let attempts = 0;
  const fetchImpl = async (requestUrl) => {
    const url = new URL(requestUrl);
    if (url.pathname.includes("publicAlerts")) return jsonResponse({ weatherAlerts: [] });
    attempts += 1;
    if (attempts === 1) return jsonResponse({ error: { message: "quota" } }, 429, { "retry-after": "0" });
    return jsonResponse({ forecastHours: [providerHour(0)] });
  };
  const service = createGoogleWeatherService({ apiKey: "never-print-this", fetchImpl, sleepImpl: async () => {} });
  const forecast = await service.lookup({ latitude: 38.25, longitude: -85.75, hours: 1 });
  assert.equal(forecast.hours.length, 1);
  assert.equal(attempts, 2);
});

function normalizedHour(start, { precipitation = 0, thunderstorm = 0, wind = 0, temperature = 70 } = {}) {
  const startDate = new Date(start);
  return {
    start_at: startDate.toISOString(),
    end_at: new Date(startDate.getTime() + 3_600_000).toISOString(),
    precipitation_probability_percent: precipitation,
    thunderstorm_probability_percent: thunderstorm,
    wind_speed_mph: wind,
    wind_gust_mph: wind,
    temperature_f: temperature,
    condition_description: precipitation ? "Rain" : "Clear"
  };
}

function outdoorJob(id, latitude, longitude) {
  return {
    id,
    title: `Job ${id}`,
    start_at: "2026-08-20T14:00:00Z",
    end_at: "2026-08-20T15:00:00Z",
    weather_exposure: "outdoor",
    contact_latitude: latitude,
    contact_longitude: longitude,
    service_items: [{ name: "Exterior Windows" }]
  };
}

function providerHour(index) {
  const start = new Date(Date.UTC(2026, 7, 20, index));
  return {
    interval: { startTime: start.toISOString(), endTime: new Date(start.getTime() + 3_600_000).toISOString() },
    weatherCondition: { type: "RAIN", description: { text: "Rain" } },
    temperature: { degrees: 20, unit: "CELSIUS" },
    precipitation: { probability: { percent: 75, type: "RAIN" } },
    thunderstormProbability: 35,
    wind: {
      speed: { value: 20, unit: "KILOMETERS_PER_HOUR" },
      gust: { value: 30, unit: "KILOMETERS_PER_HOUR" }
    }
  };
}

function jsonResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers }
  });
}
