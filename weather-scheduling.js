const FORECAST_ENDPOINT = "https://weather.googleapis.com/v1/forecast/hours:lookup";
const ALERTS_ENDPOINT = "https://weather.googleapis.com/v1/publicAlerts:lookup";

export const WEATHER_SETTINGS_VERSION = 1;
export const WEATHER_LIMITS = Object.freeze({
  maximumLookaheadDays: 10,
  maximumForecastHours: 240,
  maximumReportJobs: 150,
  maximumForecastClusters: 25,
  maximumRescheduleJobs: 50,
  forecastClusterDegrees: 0.05
});

export const DEFAULT_WEATHER_NOTIFICATION_TEMPLATE = "Hi {{customer_first_name}}, due to the weather forecast, your {{service_name}} appointment has been moved from {{old_time}} to {{new_time}}. Reply here if this new time does not work. — {{company_name}}";

export const DEFAULT_WEATHER_SETTINGS = Object.freeze({
  version: WEATHER_SETTINGS_VERSION,
  enabled: false,
  lookahead_days: 7,
  precipitation_probability_percent: 60,
  thunderstorm_probability_percent: 30,
  wind_speed_mph: 25,
  minimum_temperature_f: null,
  maximum_temperature_f: null,
  severe_alerts_enabled: true,
  automatic_default_exposure: "unknown",
  outdoor_keywords: Object.freeze([
    "exterior", "outside", "window cleaning", "gutter", "pressure wash", "power wash",
    "roof", "lawn", "landscape", "yard", "driveway", "siding", "deck", "solar",
    "chimney", "pool", "snow", "outdoor pest"
  ]),
  indoor_keywords: Object.freeze(["interior", "inside", "indoor"]),
  notification_template: DEFAULT_WEATHER_NOTIFICATION_TEMPLATE
});

const WEATHER_EXPOSURES = new Set(["auto", "outdoor", "indoor"]);
const AUTOMATIC_DEFAULT_EXPOSURES = new Set(["unknown", "outdoor", "indoor"]);
const TEMPLATE_PLACEHOLDERS = new Set([
  "customer_name", "customer_first_name", "company_name", "service_name", "old_time", "new_time"
]);
const ALERT_SEVERITY_RANK = Object.freeze({ UNKNOWN: 0, MINOR: 1, MODERATE: 2, SEVERE: 3, EXTREME: 4 });
const RISK_SEVERITY_RANK = Object.freeze({ low: 1, medium: 2, high: 3, critical: 4 });

export class WeatherSchedulingError extends Error {
  constructor(code, message, { statusCode = 400, details = null } = {}) {
    super(message);
    this.name = "WeatherSchedulingError";
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
  }
}

export function normalizeWeatherExposure(value) {
  const exposure = value == null ? "auto" : String(value).trim().toLowerCase();
  if (!WEATHER_EXPOSURES.has(exposure)) {
    throw new WeatherSchedulingError("invalid_weather_exposure", "Weather sensitivity must be Automatic, Outdoor, or Indoor.", {
      details: { field: "weather_exposure" }
    });
  }
  return exposure;
}

export function validateWeatherSettings(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw settingsError("Weather settings are required.");
  }
  const merged = { ...DEFAULT_WEATHER_SETTINGS, ...raw };
  if (typeof merged.enabled !== "boolean") throw settingsError("Enabled must be true or false.", "enabled");
  if (typeof merged.severe_alerts_enabled !== "boolean") throw settingsError("Severe alerts must be true or false.", "severe_alerts_enabled");

  const lookahead = strictInteger(merged.lookahead_days, 1, WEATHER_LIMITS.maximumLookaheadDays, "lookahead_days");
  const precipitation = strictInteger(merged.precipitation_probability_percent, 0, 100, "precipitation_probability_percent");
  const thunderstorm = strictInteger(merged.thunderstorm_probability_percent, 0, 100, "thunderstorm_probability_percent");
  const wind = strictNumber(merged.wind_speed_mph, 1, 150, "wind_speed_mph");
  const minimumTemperature = optionalStrictNumber(merged.minimum_temperature_f, -100, 150, "minimum_temperature_f");
  const maximumTemperature = optionalStrictNumber(merged.maximum_temperature_f, -100, 150, "maximum_temperature_f");
  if (minimumTemperature != null && maximumTemperature != null && minimumTemperature >= maximumTemperature) {
    throw settingsError("Maximum temperature must be higher than minimum temperature.", "maximum_temperature_f");
  }

  const automaticDefault = String(merged.automatic_default_exposure || "unknown").trim().toLowerCase();
  if (!AUTOMATIC_DEFAULT_EXPOSURES.has(automaticDefault)) {
    throw settingsError("Automatic default must be Unknown, Outdoor, or Indoor.", "automatic_default_exposure");
  }
  const outdoorKeywords = validateKeywords(merged.outdoor_keywords, "outdoor_keywords");
  const indoorKeywords = validateKeywords(merged.indoor_keywords, "indoor_keywords");
  const notificationTemplate = validateWeatherNotificationTemplate(merged.notification_template);

  return {
    version: WEATHER_SETTINGS_VERSION,
    enabled: merged.enabled,
    lookahead_days: lookahead,
    precipitation_probability_percent: precipitation,
    thunderstorm_probability_percent: thunderstorm,
    wind_speed_mph: roundTo(wind, 1),
    minimum_temperature_f: minimumTemperature == null ? null : roundTo(minimumTemperature, 1),
    maximum_temperature_f: maximumTemperature == null ? null : roundTo(maximumTemperature, 1),
    severe_alerts_enabled: merged.severe_alerts_enabled,
    automatic_default_exposure: automaticDefault,
    outdoor_keywords: outdoorKeywords,
    indoor_keywords: indoorKeywords,
    notification_template: notificationTemplate
  };
}

export function resolveWeatherSettings(raw) {
  try {
    return validateWeatherSettings(raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {});
  } catch (_) {
    return validateWeatherSettings({});
  }
}

export function validateWeatherNotificationTemplate(value) {
  const template = String(value ?? "").trim();
  if (!template) throw settingsError("A customer notification template is required.", "notification_template");
  if (template.length > 1_200) throw settingsError("The customer notification template must be 1,200 characters or fewer.", "notification_template");
  const placeholders = [...template.matchAll(/{{\s*([a-z0-9_]+)\s*}}/gi)].map((match) => match[1].toLowerCase());
  const unknown = placeholders.find((placeholder) => !TEMPLATE_PLACEHOLDERS.has(placeholder));
  if (unknown) {
    throw new WeatherSchedulingError("unsupported_weather_placeholder", `Unsupported weather-message placeholder: {{${unknown}}}.`, {
      details: { field: "notification_template", placeholder: unknown }
    });
  }
  return template;
}

export function classifyWeatherExposure(job, settings = DEFAULT_WEATHER_SETTINGS) {
  const explicit = normalizeWeatherExposure(job?.weather_exposure);
  if (explicit !== "auto") {
    return { exposure: explicit, source: "explicit", matched_keyword: null };
  }
  const text = weatherClassificationText(job);
  const indoorMatch = settings.indoor_keywords.find((keyword) => text.includes(keyword.toLowerCase()));
  if (indoorMatch) return { exposure: "indoor", source: "indoor_keyword", matched_keyword: indoorMatch };
  const outdoorMatch = settings.outdoor_keywords.find((keyword) => text.includes(keyword.toLowerCase()));
  if (outdoorMatch) return { exposure: "outdoor", source: "outdoor_keyword", matched_keyword: outdoorMatch };
  return { exposure: settings.automatic_default_exposure, source: "company_default", matched_keyword: null };
}

export function evaluateWeatherRisk(job, forecast, settings = DEFAULT_WEATHER_SETTINGS) {
  const jobStart = validDate(job?.start_at ?? job?.start);
  const jobEnd = validDate(job?.end_at ?? job?.end);
  if (!jobStart || !jobEnd || jobEnd <= jobStart) {
    throw new WeatherSchedulingError("invalid_weather_job_interval", "Job has an invalid schedule interval.");
  }
  const hours = (forecast?.hours || []).filter((hour) => intervalsOverlap(
    validDate(hour.start_at), validDate(hour.end_at), jobStart, jobEnd
  ));
  if (!hours.length) return null;

  const maxPrecipitation = maximum(hours.map((hour) => hour.precipitation_probability_percent));
  const maxThunderstorm = maximum(hours.map((hour) => hour.thunderstorm_probability_percent));
  const maxWind = maximum(hours.flatMap((hour) => [hour.wind_speed_mph, hour.wind_gust_mph]));
  const temperatures = hours.map((hour) => finiteOrNull(hour.temperature_f)).filter((value) => value != null);
  const minTemperature = temperatures.length ? Math.min(...temperatures) : null;
  const maxTemperature = temperatures.length ? Math.max(...temperatures) : null;
  const reasons = [];

  if (maxPrecipitation != null && maxPrecipitation >= settings.precipitation_probability_percent) {
    reasons.push(reason("precipitation", `${Math.round(maxPrecipitation)}% precipitation risk`, maxPrecipitation, settings.precipitation_probability_percent));
  }
  if (maxThunderstorm != null && maxThunderstorm >= settings.thunderstorm_probability_percent) {
    reasons.push(reason("thunderstorm", `${Math.round(maxThunderstorm)}% thunderstorm risk`, maxThunderstorm, settings.thunderstorm_probability_percent));
  }
  if (maxWind != null && maxWind >= settings.wind_speed_mph) {
    reasons.push(reason("wind", `Wind or gusts up to ${Math.round(maxWind)} mph`, maxWind, settings.wind_speed_mph));
  }
  if (settings.minimum_temperature_f != null && minTemperature != null && minTemperature <= settings.minimum_temperature_f) {
    reasons.push(reason("low_temperature", `Temperature as low as ${Math.round(minTemperature)}°F`, minTemperature, settings.minimum_temperature_f));
  }
  if (settings.maximum_temperature_f != null && maxTemperature != null && maxTemperature >= settings.maximum_temperature_f) {
    reasons.push(reason("high_temperature", `Temperature as high as ${Math.round(maxTemperature)}°F`, maxTemperature, settings.maximum_temperature_f));
  }

  const alerts = settings.severe_alerts_enabled
    ? (forecast?.alerts || []).filter((alert) => alertIntersectsJob(alert, jobStart, jobEnd))
    : [];
  for (const alert of alerts) {
    const title = alert.title || humanizeEnum(alert.event_type) || "Public weather alert";
    reasons.push({
      code: "public_alert",
      label: title,
      value: null,
      threshold: null,
      alert_id: alert.id || null
    });
  }
  if (!reasons.length) return null;

  const severity = determineRiskSeverity({ maxPrecipitation, maxThunderstorm, maxWind, reasons, alerts });
  return {
    severity,
    summary: reasons.slice(0, 2).map((item) => item.label).join(" · "),
    reasons,
    conditions: {
      precipitation_probability_percent: maxPrecipitation == null ? null : Math.round(maxPrecipitation),
      thunderstorm_probability_percent: maxThunderstorm == null ? null : Math.round(maxThunderstorm),
      wind_speed_mph: maxWind == null ? null : roundTo(maxWind, 1),
      minimum_temperature_f: minTemperature == null ? null : roundTo(minTemperature, 1),
      maximum_temperature_f: maxTemperature == null ? null : roundTo(maxTemperature, 1),
      condition_description: mostRelevantDescription(hours)
    },
    alerts,
    forecast_hour_count: hours.length
  };
}

export async function buildWeatherRiskReport({
  jobs,
  settings: rawSettings,
  weatherService,
  now = new Date(),
  maximumJobs = WEATHER_LIMITS.maximumReportJobs,
  maximumClusters = WEATHER_LIMITS.maximumForecastClusters
}) {
  const settings = resolveWeatherSettings(rawSettings);
  const generatedAt = new Date(now);
  const horizon = new Date(generatedAt.getTime() + settings.lookahead_days * 86_400_000);
  const sourceJobs = Array.isArray(jobs) ? jobs : [];
  const sourceJobCount = sourceJobs.reduce(
    (count, job) => Math.max(count, Number(job?.weather_query_total) || 0),
    sourceJobs.length
  );
  const candidates = sourceJobs
    .filter((job) => !job.started_at)
    .filter((job) => !job.finished_at)
    .filter((job) => {
      const start = validDate(job.start_at ?? job.start);
      const end = validDate(job.end_at ?? job.end);
      return start && end && end > generatedAt && start < horizon;
    })
    .sort(compareJobs)
    .slice(0, Math.max(1, maximumJobs));

  const coverage = {
    total_jobs: candidates.length,
    truncated_jobs: Math.max(0, sourceJobCount - candidates.length),
    outdoor_jobs: 0,
    indoor_jobs: 0,
    unknown_jobs: 0,
    missing_location_jobs: 0,
    cluster_limited_jobs: 0,
    provider_failed_jobs: 0,
    evaluated_jobs: 0
  };
  const classified = candidates.map((job) => {
    const classification = classifyWeatherExposure(job, settings);
    if (classification.exposure === "outdoor") coverage.outdoor_jobs += 1;
    else if (classification.exposure === "indoor") coverage.indoor_jobs += 1;
    else coverage.unknown_jobs += 1;
    return { job, classification };
  });
  const outdoorWithLocation = classified.filter(({ job, classification }) => {
    if (classification.exposure !== "outdoor") return false;
    const valid = validCoordinate(job.contact_latitude ?? job.latitude, job.contact_longitude ?? job.longitude);
    if (!valid) coverage.missing_location_jobs += 1;
    return valid;
  });
  const clusters = new Map();
  for (const item of outdoorWithLocation) {
    const latitude = Number(item.job.contact_latitude ?? item.job.latitude);
    const longitude = Number(item.job.contact_longitude ?? item.job.longitude);
    const key = weatherClusterKey(latitude, longitude);
    if (!clusters.has(key)) clusters.set(key, { key, latitude, longitude, items: [] });
    clusters.get(key).items.push(item);
  }
  const orderedClusters = [...clusters.values()].sort((lhs, rhs) => compareJobs(lhs.items[0].job, rhs.items[0].job));
  const selectedClusters = orderedClusters.slice(0, Math.max(1, maximumClusters));
  coverage.cluster_limited_jobs = orderedClusters.slice(selectedClusters.length).reduce((sum, cluster) => sum + cluster.items.length, 0);

  const status = weatherService?.status?.() || { configured: false, provider: "google_weather" };
  const risks = [];
  const providerErrors = [];
  const evaluatedJobIDs = [];
  if (settings.enabled && status.configured) {
    await mapWithConcurrency(selectedClusters, 4, async (cluster) => {
      const latestEnd = cluster.items.reduce((latest, item) => {
        const end = validDate(item.job.end_at ?? item.job.end);
        return end && end > latest ? end : latest;
      }, generatedAt);
      const hours = Math.max(1, Math.min(
        WEATHER_LIMITS.maximumForecastHours,
        Math.ceil((latestEnd.getTime() - generatedAt.getTime()) / 3_600_000) + 1
      ));
      try {
        const forecast = await weatherService.lookup({ latitude: cluster.latitude, longitude: cluster.longitude, hours });
        for (const warning of forecast?.warnings || []) {
          providerErrors.push({
            cluster: cluster.key,
            job_ids: cluster.items.map((item) => String(item.job.id)),
            code: warning?.code || "weather_provider_warning",
            message: cleanText(warning?.message).slice(0, 240) || "Part of the weather provider response is temporarily unavailable."
          });
        }
        for (const { job, classification } of cluster.items) {
          coverage.evaluated_jobs += 1;
          evaluatedJobIDs.push(String(job.id));
          const evaluated = evaluateWeatherRisk(job, forecast, settings);
          if (!evaluated) continue;
          risks.push({
            id: `${job.id}:${new Date(job.start_at ?? job.start).toISOString()}`,
            job_id: String(job.id),
            contact_id: job.contact_id == null ? null : String(job.contact_id),
            contact_name: job.contact_name || job.title || "Customer",
            title: job.title || job.contact_name || "Job",
            start_at: new Date(job.start_at ?? job.start).toISOString(),
            end_at: new Date(job.end_at ?? job.end).toISOString(),
            services: serviceNames(job),
            worker_user_ids: Array.isArray(job.worker_user_ids) ? job.worker_user_ids.map(String) : [],
            weather_exposure: normalizeWeatherExposure(job.weather_exposure),
            exposure_source: classification.source,
            matched_keyword: classification.matched_keyword,
            forecast_location: { latitude: cluster.latitude, longitude: cluster.longitude },
            ...evaluated
          });
        }
      } catch (error) {
        coverage.provider_failed_jobs += cluster.items.length;
        providerErrors.push({
          cluster: cluster.key,
          job_ids: cluster.items.map((item) => String(item.job.id)),
          code: error?.code || "weather_provider_failed",
          message: safeProviderMessage(error)
        });
      }
    });
  }

  risks.sort((lhs, rhs) => {
    const severityDifference = (RISK_SEVERITY_RANK[rhs.severity] || 0) - (RISK_SEVERITY_RANK[lhs.severity] || 0);
    return severityDifference || new Date(lhs.start_at) - new Date(rhs.start_at) || lhs.job_id.localeCompare(rhs.job_id);
  });
  const observationResolutionJobIDs = [...new Set([
    ...classified
      .filter(({ classification }) => classification.exposure !== "outdoor")
      .map(({ job }) => String(job.id)),
    ...evaluatedJobIDs
  ])];
  return {
    generated_at: generatedAt.toISOString(),
    range_start: generatedAt.toISOString(),
    range_end: horizon.toISOString(),
    provider: status.provider || "google_weather",
    provider_configured: !!status.configured,
    monitoring_enabled: settings.enabled,
    settings,
    coverage,
    provider_errors: providerErrors,
    evaluated_job_ids: evaluatedJobIDs,
    observation_resolution_job_ids: observationResolutionJobIDs,
    risks
  };
}

export function planWeatherReschedule(jobs, replacementStart, { now = new Date() } = {}) {
  if (!Array.isArray(jobs) || !jobs.length || jobs.length > WEATHER_LIMITS.maximumRescheduleJobs) {
    throw new WeatherSchedulingError("invalid_weather_reschedule_jobs", `Choose between 1 and ${WEATHER_LIMITS.maximumRescheduleJobs} jobs.`);
  }
  const ids = jobs.map((job) => String(job?.id || "").trim()).filter(Boolean);
  if (ids.length !== jobs.length || new Set(ids).size !== ids.length) {
    throw new WeatherSchedulingError("invalid_weather_reschedule_jobs", "Every selected job must be unique.");
  }
  const anchor = validDate(replacementStart);
  if (!anchor || anchor <= now) {
    throw new WeatherSchedulingError("weather_replacement_must_be_future", "Choose a replacement time in the future.");
  }
  const normalized = jobs.map((job) => {
    const start = validDate(job.start_at ?? job.start);
    const end = validDate(job.end_at ?? job.end);
    if (!start || !end || end <= start) throw new WeatherSchedulingError("invalid_weather_job_interval", `Job ${job.id} has an invalid schedule interval.`);
    if (job.started_at || job.finished_at) {
      throw new WeatherSchedulingError("weather_job_already_in_progress", `Job ${job.id} has already started or finished.` , { statusCode: 409 });
    }
    return { job, start, end };
  }).sort((lhs, rhs) => lhs.start - rhs.start || String(lhs.job.id).localeCompare(String(rhs.job.id)));
  const deltaMilliseconds = anchor.getTime() - normalized[0].start.getTime();
  return {
    replacement_start_at: anchor.toISOString(),
    shift_seconds: Math.round(deltaMilliseconds / 1000),
    items: normalized.map(({ job, start, end }) => ({
      job_id: String(job.id),
      contact_id: job.contact_id == null ? null : String(job.contact_id),
      contact_name: job.contact_name || job.title || "Customer",
      title: job.title || job.contact_name || "Job",
      old_start_at: start.toISOString(),
      old_end_at: end.toISOString(),
      new_start_at: new Date(start.getTime() + deltaMilliseconds).toISOString(),
      new_end_at: new Date(end.getTime() + deltaMilliseconds).toISOString(),
      duration_seconds: Math.round((end.getTime() - start.getTime()) / 1000)
    }))
  };
}

export function validateWeatherExpectedIntervals(jobs, expectedIntervals) {
  if (!Array.isArray(expectedIntervals) || expectedIntervals.length !== jobs.length) {
    throw new WeatherSchedulingError("weather_reschedule_preview_required", "Reload and review the reschedule preview before applying changes.", { statusCode: 409 });
  }
  const expectedByID = new Map(expectedIntervals.map((item) => [String(item?.job_id || ""), item]));
  for (const job of jobs) {
    const expected = expectedByID.get(String(job.id));
    const currentStart = validDate(job.start_at ?? job.start);
    const currentEnd = validDate(job.end_at ?? job.end);
    const expectedStart = validDate(expected?.old_start_at);
    const expectedEnd = validDate(expected?.old_end_at);
    if (!expected || !currentStart || !currentEnd || !expectedStart || !expectedEnd
        || currentStart.getTime() !== expectedStart.getTime() || currentEnd.getTime() !== expectedEnd.getTime()) {
      throw new WeatherSchedulingError("weather_jobs_changed", "One or more selected jobs changed after preview. Reload and review the new times.", {
        statusCode: 409,
        details: { job_id: String(job.id) }
      });
    }
  }
  return true;
}

export function renderWeatherRescheduleMessage(template, context = {}) {
  let message = validateWeatherNotificationTemplate(template);
  const customerName = cleanText(context.customerName) || "there";
  const replacements = {
    customer_name: customerName,
    customer_first_name: customerName.split(/\s+/)[0] || "there",
    company_name: cleanText(context.companyName) || "Our team",
    service_name: cleanText(context.serviceName) || "service",
    old_time: formatAppointment(context.oldTime, context.timeZone),
    new_time: formatAppointment(context.newTime, context.timeZone)
  };
  for (const [key, value] of Object.entries(replacements)) {
    message = message.replace(new RegExp(`{{\\s*${key}\\s*}}`, "gi"), value);
  }
  return message.replace(/\s+/g, " ").trim();
}

export function createGoogleWeatherService({
  apiKey = (process.env.GOOGLE_WEATHER_API_KEY || process.env.GOOGLE_MAPS_PLATFORM_API_KEY || "").trim(),
  fetchImpl = globalThis.fetch,
  timeoutMs = 12_000,
  maximumRetries = 3,
  cacheTtlMs = 15 * 60_000,
  sleepImpl = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds))
} = {}) {
  const cache = new Map();
  const configured = Boolean(apiKey && typeof fetchImpl === "function");

  async function requestJson(url) {
    let lastError;
    for (let attempt = 0; attempt < maximumRetries; attempt += 1) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const response = await fetchImpl(url, { method: "GET", signal: controller.signal, headers: { Accept: "application/json" } });
        const body = await response.json().catch(() => ({}));
        if (response.ok) return body;
        const retryable = response.status === 429 || response.status >= 500;
        const code = response.status === 429 ? "google_weather_rate_limited"
          : response.status === 401 || response.status === 403 ? "google_weather_not_authorized"
            : "google_weather_request_failed";
        lastError = new WeatherSchedulingError(code, providerErrorMessage(code), { statusCode: response.status >= 500 ? 502 : response.status });
        if (!retryable || attempt + 1 >= maximumRetries) throw lastError;
        const retryAfter = parseRetryAfter(response.headers?.get?.("retry-after"));
        await sleepImpl(retryAfter ?? Math.min(4_000, 300 * 2 ** attempt));
      } catch (error) {
        const normalized = error instanceof WeatherSchedulingError
          ? error
          : new WeatherSchedulingError(
            error?.name === "AbortError" ? "google_weather_timeout" : "google_weather_unavailable",
            error?.name === "AbortError" ? "Google Weather timed out." : "Google Weather is temporarily unavailable.",
            { statusCode: 502 }
          );
        lastError = normalized;
        if (error instanceof WeatherSchedulingError || attempt + 1 >= maximumRetries) throw normalized;
        await sleepImpl(Math.min(4_000, 300 * 2 ** attempt));
      } finally {
        clearTimeout(timeout);
      }
    }
    throw lastError || new WeatherSchedulingError("google_weather_unavailable", "Google Weather is temporarily unavailable.", { statusCode: 502 });
  }

  async function loadForecast(latitude, longitude, hours) {
    const records = [];
    let pageToken = null;
    let timeZone = null;
    let pageCount = 0;
    do {
      const url = weatherUrl(FORECAST_ENDPOINT, apiKey, latitude, longitude, {
        hours: String(hours),
        pageSize: "24",
        unitsSystem: "IMPERIAL",
        languageCode: "en",
        ...(pageToken ? { pageToken } : {})
      });
      const body = await requestJson(url);
      records.push(...(Array.isArray(body.forecastHours) ? body.forecastHours.map(normalizeForecastHour).filter(Boolean) : []));
      timeZone = body.timeZone?.id || timeZone;
      pageToken = body.nextPageToken || null;
      pageCount += 1;
      if (pageCount > 12) throw new WeatherSchedulingError("google_weather_pagination_failed", "Google Weather returned too many forecast pages.", { statusCode: 502 });
    } while (pageToken && records.length < hours);
    if (!records.length) throw new WeatherSchedulingError("google_weather_forecast_empty", "Google Weather returned no hourly forecast for this location.", { statusCode: 502 });
    return { hours: records.slice(0, hours), time_zone: timeZone };
  }

  async function loadAlerts(latitude, longitude) {
    const alerts = [];
    let pageToken = null;
    let pageCount = 0;
    do {
      const url = weatherUrl(ALERTS_ENDPOINT, apiKey, latitude, longitude, {
        pageSize: "20",
        languageCode: "en",
        ...(pageToken ? { pageToken } : {})
      });
      const body = await requestJson(url);
      alerts.push(...(Array.isArray(body.weatherAlerts) ? body.weatherAlerts.map(normalizeWeatherAlert).filter(Boolean) : []));
      pageToken = body.nextPageToken || null;
      pageCount += 1;
    } while (pageToken && pageCount < 3);
    return alerts;
  }

  async function lookup({ latitude, longitude, hours }) {
    if (!configured) throw new WeatherSchedulingError("google_weather_not_configured", "Google Weather is not configured.", { statusCode: 503 });
    const coordinate = validCoordinate(latitude, longitude);
    if (!coordinate) throw new WeatherSchedulingError("invalid_weather_coordinate", "A valid forecast coordinate is required.");
    const requestedHours = strictInteger(hours, 1, WEATHER_LIMITS.maximumForecastHours, "hours");
    const key = `${coordinate.latitude.toFixed(3)}:${coordinate.longitude.toFixed(3)}:${requestedHours}`;
    const cached = cache.get(key);
    if (cached && cached.expires_at > Date.now()) return cached.value ?? cached.promise;
    const promise = (async () => {
      const forecast = await loadForecast(coordinate.latitude, coordinate.longitude, requestedHours);
      let alerts = [];
      const warnings = [];
      try {
        alerts = await loadAlerts(coordinate.latitude, coordinate.longitude);
      } catch (error) {
        warnings.push({ code: error?.code || "google_weather_alerts_unavailable", message: "Public weather alerts are temporarily unavailable." });
      }
      return {
        provider: "google_weather",
        latitude: coordinate.latitude,
        longitude: coordinate.longitude,
        fetched_at: new Date().toISOString(),
        time_zone: forecast.time_zone,
        hours: forecast.hours,
        alerts,
        warnings
      };
    })();
    cache.set(key, { expires_at: Date.now() + cacheTtlMs, promise });
    try {
      const value = await promise;
      cache.set(key, { expires_at: Date.now() + cacheTtlMs, value });
      return value;
    } catch (error) {
      cache.delete(key);
      throw error;
    }
  }

  return {
    status() {
      return {
        provider: "google_weather",
        configured,
        maximum_forecast_hours: WEATHER_LIMITS.maximumForecastHours,
        cache_ttl_seconds: Math.round(cacheTtlMs / 1000)
      };
    },
    lookup
  };
}

function normalizeForecastHour(raw) {
  const start = validDate(raw?.interval?.startTime);
  const end = validDate(raw?.interval?.endTime);
  if (!start || !end || end <= start) return null;
  return {
    start_at: start.toISOString(),
    end_at: end.toISOString(),
    condition_type: raw.weatherCondition?.type || null,
    condition_description: raw.weatherCondition?.description?.text || null,
    temperature_f: temperatureF(raw.temperature),
    precipitation_probability_percent: finiteOrNull(raw.precipitation?.probability?.percent),
    precipitation_type: raw.precipitation?.probability?.type || null,
    thunderstorm_probability_percent: finiteOrNull(raw.thunderstormProbability),
    wind_speed_mph: speedMph(raw.wind?.speed),
    wind_gust_mph: speedMph(raw.wind?.gust)
  };
}

function normalizeWeatherAlert(raw) {
  if (!raw || typeof raw !== "object") return null;
  return {
    id: raw.alertId || null,
    title: raw.alertTitle?.text || humanizeEnum(raw.eventType) || "Public weather alert",
    event_type: raw.eventType || null,
    severity: raw.severity || "UNKNOWN",
    certainty: raw.certainty || null,
    urgency: raw.urgency || null,
    area_name: raw.areaName || null,
    start_at: validDate(raw.startTime)?.toISOString() || null,
    expires_at: validDate(raw.expirationTime)?.toISOString() || null,
    description: cleanText(raw.description)?.slice(0, 1_000) || null,
    source_name: raw.dataSource?.name || null,
    source_url: /^https:\/\//i.test(raw.dataSource?.authorityUri || "") ? raw.dataSource.authorityUri : null
  };
}

function determineRiskSeverity({ maxPrecipitation, maxThunderstorm, maxWind, reasons, alerts }) {
  const alertRank = alerts.reduce((rank, alert) => Math.max(rank, ALERT_SEVERITY_RANK[String(alert.severity || "UNKNOWN").toUpperCase()] || 0), 0);
  if (alertRank >= 4) return "critical";
  if (alertRank >= 3 || maxThunderstorm >= 70 || maxWind >= 45) return "high";
  if (alertRank >= 2 || maxThunderstorm >= 40 || maxPrecipitation >= 80 || maxWind >= 30 || reasons.length >= 3) return "medium";
  return "low";
}

function alertIntersectsJob(alert, jobStart, jobEnd) {
  const start = validDate(alert?.start_at) || new Date(0);
  const end = validDate(alert?.expires_at) || new Date(8_640_000_000_000_000);
  return intervalsOverlap(start, end, jobStart, jobEnd);
}

function mostRelevantDescription(hours) {
  const descriptions = hours.map((hour) => cleanText(hour.condition_description)).filter(Boolean);
  if (!descriptions.length) return null;
  const counts = new Map();
  descriptions.forEach((description) => counts.set(description, (counts.get(description) || 0) + 1));
  return [...counts.entries()].sort((lhs, rhs) => rhs[1] - lhs[1] || lhs[0].localeCompare(rhs[0]))[0][0];
}

function serviceNames(job) {
  const items = Array.isArray(job?.service_items) ? job.service_items : [];
  const services = items.map((item) => cleanText(item?.name ?? item)).filter(Boolean);
  if (services.length) return [...new Set(services)];
  return (Array.isArray(job?.services) ? job.services : []).map(cleanText).filter(Boolean);
}

function weatherClassificationText(job) {
  return [job?.title, job?.contact_job_type, ...serviceNames(job)]
    .map(cleanText)
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function weatherClusterKey(latitude, longitude) {
  const size = WEATHER_LIMITS.forecastClusterDegrees;
  return `${(Math.round(Number(latitude) / size) * size).toFixed(2)}:${(Math.round(Number(longitude) / size) * size).toFixed(2)}`;
}

function weatherUrl(endpoint, apiKey, latitude, longitude, extra) {
  const url = new URL(endpoint);
  url.searchParams.set("key", apiKey);
  url.searchParams.set("location.latitude", String(latitude));
  url.searchParams.set("location.longitude", String(longitude));
  Object.entries(extra).forEach(([key, value]) => url.searchParams.set(key, value));
  return url;
}

function validateKeywords(value, field) {
  if (!Array.isArray(value)) throw settingsError("Keywords must be a list.", field);
  if (value.length > 40) throw settingsError("Use no more than 40 keywords.", field);
  const output = [];
  for (const raw of value) {
    const keyword = cleanText(raw).toLowerCase();
    if (!keyword || keyword.length > 48) throw settingsError("Each keyword must contain 1–48 characters.", field);
    if (!output.includes(keyword)) output.push(keyword);
  }
  return output;
}

function settingsError(message, field = null) {
  return new WeatherSchedulingError("invalid_weather_settings", message, { details: field ? { field } : null });
}

function strictInteger(value, minimum, maximum, field) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < minimum || number > maximum) {
    throw settingsError(`${field} must be an integer between ${minimum} and ${maximum}.`, field);
  }
  return number;
}

function strictNumber(value, minimum, maximum, field) {
  const number = Number(value);
  if (!Number.isFinite(number) || number < minimum || number > maximum) {
    throw settingsError(`${field} must be between ${minimum} and ${maximum}.`, field);
  }
  return number;
}

function optionalStrictNumber(value, minimum, maximum, field) {
  if (value == null || value === "") return null;
  return strictNumber(value, minimum, maximum, field);
}

function validCoordinate(latitude, longitude) {
  if (latitude == null || longitude == null || latitude === "" || longitude === "") return null;
  const lat = Number(latitude);
  const lng = Number(longitude);
  if (!Number.isFinite(lat) || !Number.isFinite(lng) || lat < -90 || lat > 90 || lng < -180 || lng > 180) return null;
  return { latitude: lat, longitude: lng };
}

function intervalsOverlap(firstStart, firstEnd, secondStart, secondEnd) {
  return firstStart instanceof Date && firstEnd instanceof Date && secondStart instanceof Date && secondEnd instanceof Date
    && firstStart < secondEnd && firstEnd > secondStart;
}

function compareJobs(lhs, rhs) {
  return new Date(lhs.start_at ?? lhs.start) - new Date(rhs.start_at ?? rhs.start) || String(lhs.id).localeCompare(String(rhs.id));
}

function validDate(value) {
  if (value == null) return null;
  const date = value instanceof Date ? new Date(value) : new Date(value);
  return Number.isFinite(date.getTime()) ? date : null;
}

function finiteOrNull(value) {
  if (value == null || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function maximum(values) {
  const numbers = values.map(finiteOrNull).filter((value) => value != null);
  return numbers.length ? Math.max(...numbers) : null;
}

function temperatureF(value) {
  const degrees = finiteOrNull(value?.degrees);
  if (degrees == null) return null;
  return String(value?.unit || "").toUpperCase() === "CELSIUS" ? degrees * 9 / 5 + 32 : degrees;
}

function speedMph(value) {
  const speed = finiteOrNull(value?.value);
  if (speed == null) return null;
  const unit = String(value?.unit || "").toUpperCase();
  if (unit === "KILOMETERS_PER_HOUR") return speed * 0.621371;
  if (unit === "METERS_PER_SECOND") return speed * 2.23694;
  return speed;
}

function reason(code, label, value, threshold) {
  return { code, label, value: roundTo(value, 1), threshold: roundTo(threshold, 1), alert_id: null };
}

function roundTo(value, places) {
  const factor = 10 ** places;
  return Math.round(Number(value) * factor) / factor;
}

function cleanText(value) {
  return String(value ?? "").replace(/\s+/g, " ").trim();
}

function humanizeEnum(value) {
  const text = cleanText(value);
  if (!text) return null;
  return text.toLowerCase().split("_").map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(" ");
}

function formatAppointment(value, timeZone) {
  const date = validDate(value);
  if (!date) return "the new time";
  try {
    return new Intl.DateTimeFormat("en-US", {
      timeZone: cleanText(timeZone) || "America/New_York",
      weekday: "long",
      month: "short",
      day: "numeric",
      hour: "numeric",
      minute: "2-digit"
    }).format(date);
  } catch (_) {
    return new Intl.DateTimeFormat("en-US", {
      timeZone: "UTC", weekday: "long", month: "short", day: "numeric", hour: "numeric", minute: "2-digit"
    }).format(date);
  }
}

function parseRetryAfter(value) {
  if (!value) return null;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.min(10_000, seconds * 1000);
  const date = validDate(value);
  return date ? Math.max(0, Math.min(10_000, date.getTime() - Date.now())) : null;
}

function providerErrorMessage(code) {
  if (code === "google_weather_rate_limited") return "Google Weather is rate limited. Try again shortly.";
  if (code === "google_weather_not_authorized") return "Google Weather is not enabled or the server key is not authorized.";
  return "Google Weather could not return this forecast.";
}

function safeProviderMessage(error) {
  if (error instanceof WeatherSchedulingError) return error.message;
  return "Weather forecast is temporarily unavailable for this location.";
}

async function mapWithConcurrency(items, concurrency, work) {
  let cursor = 0;
  async function worker() {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      await work(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(Math.max(1, concurrency), items.length) }, worker));
}
