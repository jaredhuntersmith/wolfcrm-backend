import { createHash } from "crypto";

export const FOCUS_MEDIA_TYPES = Object.freeze(["reel", "post"]);
export const FOCUS_FEED_MODES = Object.freeze(["for_you", "following"]);
export const FOCUS_NATIVE_REJECTION_REASONS = Object.freeze([
  "no_direct_media_url",
  "licensed_audio_restricted",
  "creator_download_restricted",
  "inaccessible_private_deleted",
  "expired_media",
  "unsupported_media_format",
  "unknown_native_unavailable",
  "creator_identity_unresolved",
  "carousel_asset_unavailable"
]);

const POSITIVE_DEFAULTS = [
  "window cleaning", "pressure washing", "home service", "entrepreneurship", "business operations",
  "growth", "sales", "door to door sales", "hiring", "leadership", "marketing", "advertising",
  "lead generation", "useful business ai", "automation", "health education", "exercise", "weightlifting",
  "running", "cardio", "nutrition", "sleep", "mindset", "discipline", "productivity", "habits", "self improvement"
];
const NEGATIVE_DEFAULTS = [
  "memes", "comedy sketches", "pranks", "celebrity gossip", "gaming", "movie tv", "random viral clips",
  "relationship drama", "rage bait", "luxury flex", "supercar motivation", "paid partnership", "sponsored", "sponsor read"
];

export const DEFAULT_FOCUS_SETTINGS = Object.freeze({
  enabled: false,
  reels_ready_target: 100,
  posts_ready_target: 100,
  reels_reserve_multiplier: 5,
  posts_reserve_multiplier: 5,
  reels_standby_limit: 100,
  posts_standby_limit: 100,
  automatic_discovery_enabled: true,
  external_creator_discovery_enabled: true,
  minimum_discovery_followers: 10_000,
  strict_discovery: true,
  exploration_percent: 15,
  max_search_queries_day: 10,
  max_search_queries_month: 200,
  reels_processing_paused: false,
  posts_processing_paused: false,
  autoplay_enabled: true,
  muted: false,
  generated_captions_enabled: false,
  wifi_reel_preload: 2,
  cellular_reel_preload: 1,
  refill_threshold_seconds: 1,
  freshness_mode_reels: "strict",
  freshness_mode_posts: "strict",
  balanced_tolerance_reels: 0,
  balanced_tolerance_posts: 0,
  daily_ai_budget_micros: 1_000_000,
  monthly_ai_budget_micros: 10_000_000,
  transcription_enabled: false,
  transcription_daily_seconds: 0,
  visual_analysis_enabled: false,
  timezone: "America/Kentucky/Louisville",
  show_me: POSITIVE_DEFAULTS.join(", "),
  never_show_me: NEGATIVE_DEFAULTS.join(", "),
  creator_whitelist: [],
  creator_blacklist: [],
  reels_freshness_rules: [
    { percentage: 50, value: 8, unit: "weeks" },
    { percentage: 75, value: 2, unit: "months" },
    { percentage: 90, value: 6, unit: "months" },
    { percentage: 95, value: 1, unit: "years" }
  ],
  posts_freshness_rules: [
    { percentage: 50, value: 8, unit: "weeks" },
    { percentage: 75, value: 2, unit: "months" },
    { percentage: 90, value: 6, unit: "months" },
    { percentage: 95, value: 1, unit: "years" }
  ],
  reels_maximum_age: { value: 15, unit: "months" },
  posts_maximum_age: { value: 15, unit: "months" },
  diversity: {
    same_creator_target_gap: 8,
    max_creator_in_20: 2,
    max_creator_in_100: 8,
    max_topic_streak: 3,
    stochastic_jitter: 0.06,
    fatigue_similarity_threshold: 0.92
  }
});

export function defaultFocusRuleText() {
  return { show_me: POSITIVE_DEFAULTS.join(", "), never_show_me: NEGATIVE_DEFAULTS.join(", ") };
}

export function requireFocusMediaType(value) {
  if (!FOCUS_MEDIA_TYPES.includes(value)) throw focusValidationError("invalid_media_type");
  return value;
}

export function requireFocusFeedMode(value) {
  if (!FOCUS_FEED_MODES.includes(value)) throw focusValidationError("invalid_feed_mode");
  return value;
}

export function focusValidationError(code, message = code) {
  return Object.assign(new Error(message), { code, statusCode: 400 });
}

export function normalizeFocusSettings(input = {}) {
  const result = structuredClone(DEFAULT_FOCUS_SETTINGS);
  for (const [key, value] of Object.entries(input || {})) {
    if (value !== undefined && key in result) result[key] = value;
  }
  result.reels_ready_target = wholeInRange(result.reels_ready_target, 10, 1000, "invalid_reels_ready_target");
  result.posts_ready_target = wholeInRange(result.posts_ready_target, 10, 1000, "invalid_posts_ready_target");
  result.reels_reserve_multiplier = wholeInRange(result.reels_reserve_multiplier, 1, 20, "invalid_reels_reserve_multiplier");
  result.posts_reserve_multiplier = wholeInRange(result.posts_reserve_multiplier, 1, 20, "invalid_posts_reserve_multiplier");
  result.reels_standby_limit = wholeInRange(result.reels_standby_limit, 0, 10_000, "invalid_reels_standby_limit");
  result.posts_standby_limit = wholeInRange(result.posts_standby_limit, 0, 10_000, "invalid_posts_standby_limit");
  result.minimum_discovery_followers = wholeInRange(result.minimum_discovery_followers, 0, 10_000_000, "invalid_minimum_discovery_followers");
  result.exploration_percent = wholeInRange(result.exploration_percent, 0, 50, "invalid_exploration_percent");
  result.max_search_queries_day = wholeInRange(result.max_search_queries_day, 0, 1_000, "invalid_max_search_queries_day");
  result.max_search_queries_month = wholeInRange(result.max_search_queries_month, 0, 20_000, "invalid_max_search_queries_month");
  result.wifi_reel_preload = wholeInRange(result.wifi_reel_preload, 0, 3, "invalid_wifi_reel_preload");
  result.cellular_reel_preload = wholeInRange(result.cellular_reel_preload, 0, 3, "invalid_cellular_reel_preload");
  result.refill_threshold_seconds = decimalInRange(result.refill_threshold_seconds, 0.25, 10, "invalid_refill_threshold_seconds");
  for (const key of ["daily_ai_budget_micros", "monthly_ai_budget_micros", "transcription_daily_seconds"]) {
    result[key] = wholeInRange(result[key], 0, key === "monthly_ai_budget_micros" ? 1_000_000_000 : 100_000_000, `invalid_${key}`);
  }
  for (const mode of [result.freshness_mode_reels, result.freshness_mode_posts]) {
    if (!["strict", "balanced", "fill"].includes(mode)) throw focusValidationError("invalid_freshness_mode");
  }
  result.balanced_tolerance_reels = wholeInRange(result.balanced_tolerance_reels, 0, 50, "invalid_balanced_tolerance_reels");
  result.balanced_tolerance_posts = wholeInRange(result.balanced_tolerance_posts, 0, 50, "invalid_balanced_tolerance_posts");
  result.reels_freshness_rules = normalizeFreshnessRules(result.reels_freshness_rules, result.reels_maximum_age);
  result.posts_freshness_rules = normalizeFreshnessRules(result.posts_freshness_rules, result.posts_maximum_age);
  result.reels_maximum_age = normalizeDuration(result.reels_maximum_age, "invalid_reels_maximum_age");
  result.posts_maximum_age = normalizeDuration(result.posts_maximum_age, "invalid_posts_maximum_age");
  result.diversity = normalizeDiversity(result.diversity);
  for (const key of ["show_me", "never_show_me"]) {
    if (typeof result[key] !== "string" || result[key].trim().length > 4_000) throw focusValidationError(`invalid_${key}`);
    result[key] = result[key].trim();
  }
  result.creator_whitelist = normalizeCreatorList(result.creator_whitelist, "invalid_creator_whitelist");
  result.creator_blacklist = normalizeCreatorList(result.creator_blacklist, "invalid_creator_blacklist");
  for (const key of ["enabled", "automatic_discovery_enabled", "external_creator_discovery_enabled", "strict_discovery", "reels_processing_paused", "posts_processing_paused", "autoplay_enabled", "muted", "generated_captions_enabled", "transcription_enabled", "visual_analysis_enabled"]) {
    if (typeof result[key] !== "boolean") throw focusValidationError(`invalid_${key}`);
  }
  if (typeof result.timezone !== "string" || !isTimezone(result.timezone)) throw focusValidationError("invalid_timezone");
  return result;
}

function normalizeCreatorList(value, code) {
  if (!Array.isArray(value) || value.length > 500) throw focusValidationError(code);
  const normalized = value.map((item) => String(item || "").trim().replace(/^@/, "").toLowerCase());
  if (normalized.some((item) => !/^[a-z0-9._]{1,30}$/.test(item))) throw focusValidationError(code);
  return [...new Set(normalized)];
}

function normalizeDiversity(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw focusValidationError("invalid_diversity_settings");
  return {
    same_creator_target_gap: wholeInRange(value.same_creator_target_gap, 0, 100, "invalid_same_creator_target_gap"),
    max_creator_in_20: wholeInRange(value.max_creator_in_20, 1, 20, "invalid_max_creator_in_20"),
    max_creator_in_100: wholeInRange(value.max_creator_in_100, 1, 100, "invalid_max_creator_in_100"),
    max_topic_streak: wholeInRange(value.max_topic_streak, 1, 20, "invalid_max_topic_streak"),
    stochastic_jitter: decimalInRange(value.stochastic_jitter, 0, 0.25, "invalid_stochastic_jitter"),
    fatigue_similarity_threshold: decimalInRange(value.fatigue_similarity_threshold, 0.5, 0.999, "invalid_fatigue_similarity_threshold")
  };
}

export function normalizeFreshnessRules(value, maximumAge) {
  if (!Array.isArray(value) || !value.length || value.length > 12) throw focusValidationError("invalid_freshness_rules");
  const normalizedMaximum = normalizeDuration(maximumAge, "invalid_maximum_age");
  const seen = new Set();
  const result = value.map((rule) => {
    if (!rule || typeof rule !== "object") throw focusValidationError("invalid_freshness_rule");
    const normalized = {
      percentage: wholeInRange(rule.percentage, 1, 100, "invalid_freshness_percentage"),
      ...normalizeDuration(rule, "invalid_freshness_duration")
    };
    const signature = `${normalized.value}:${normalized.unit}`;
    if (seen.has(signature)) throw focusValidationError("duplicate_freshness_horizon");
    seen.add(signature);
    if (durationApproximateDays(normalized) > durationApproximateDays(normalizedMaximum)) throw focusValidationError("freshness_horizon_exceeds_maximum_age");
    return normalized;
  });
  return result;
}

export function normalizeDuration(value, errorCode = "invalid_duration") {
  if (!value || typeof value !== "object") throw focusValidationError(errorCode);
  const unit = value.unit;
  if (!["days", "weeks", "months", "years"].includes(unit)) throw focusValidationError(errorCode);
  return { value: wholeInRange(value.value, 1, 1200, errorCode), unit };
}

function wholeInRange(value, min, max, code) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < min || number > max) throw focusValidationError(code);
  return number;
}
function decimalInRange(value, min, max, code) {
  const number = Number(value);
  if (!Number.isFinite(number) || number < min || number > max) throw focusValidationError(code);
  return number;
}
function isTimezone(value) {
  try { new Intl.DateTimeFormat("en-US", { timeZone: value }).format(); return true; } catch { return false; }
}
function durationApproximateDays(duration) {
  return duration.value * ({ days: 1, weeks: 7, months: 30.44, years: 365.25 }[duration.unit]);
}

export function evaluateAutomaticFollowerGate({ followerCount, minimumFollowers, isFocusFollowed = false, isManual = false, strict = true }) {
  if (isFocusFollowed) return { eligible: true, status: "exempt", exemption_reason: "focus_followed" };
  if (isManual) return { eligible: true, status: "exempt", exemption_reason: "manual_seed" };
  const minimum = wholeInRange(minimumFollowers, 0, 10_000_000, "invalid_minimum_discovery_followers");
  if (minimum === 0) return { eligible: true, status: "passed", exemption_reason: null };
  if (!Number.isSafeInteger(followerCount) || followerCount < 0) {
    return { eligible: !strict, status: "unknown", rejection_reason: strict ? "follower_count_unknown" : null };
  }
  if (followerCount < minimum) return { eligible: false, status: "below_threshold", rejection_reason: "below_follower_threshold" };
  return { eligible: true, status: "passed", exemption_reason: null };
}

export function extractInstagramProfileUsernames(results) {
  const usernames = new Set();
  for (const result of Array.isArray(results) ? results : []) {
    const value = typeof result === "string" ? result : result?.url;
    if (typeof value !== "string") continue;
    try {
      const url = new URL(value);
      const host = url.hostname.toLowerCase();
      if (!(host === "instagram.com" || host === "www.instagram.com")) continue;
      const parts = url.pathname.split("/").filter(Boolean);
      if (parts.length !== 1) continue;
      const username = parts[0].toLowerCase();
      if (!/^[a-z0-9._]{1,30}$/.test(username)) continue;
      if (["p", "reel", "reels", "tv", "stories", "explore", "accounts", "about", "developer", "direct", "web", "challenge", "oauth", "api", "static", "help", "legal"].includes(username)) continue;
      usernames.add(username);
    } catch { /* an invalid result cannot nominate a creator */ }
  }
  return [...usernames];
}

export function nativeMediaEligibility(candidate) {
  if (!candidate?.creator_id) return rejection("creator_identity_unresolved");
  if (!["reel", "post"].includes(candidate.media_type)) return rejection("unsupported_media_format");
  if (candidate.ad_status === "confirmed_ad" || candidate.sponsorship_status === "confirmed_sponsored") return rejection("confirmed_advertising");
  if (candidate.media_type === "reel") {
    if (!isDirectNativeMediaURL(candidate.media_url, "video")) return rejection(candidate.native_rejection_reason || "no_direct_media_url");
    return { eligible: true, native_state: "native_verified", rejection_reason: null };
  }
  const assets = Array.isArray(candidate.assets) && candidate.assets.length ? candidate.assets : candidate.media_url ? [{ url: candidate.media_url, media_kind: "image" }] : [];
  if (!assets.length || assets.some((asset) => !isDirectNativeMediaURL(asset.url, asset.media_kind || "image"))) {
    return rejection(candidate.native_rejection_reason || "carousel_asset_unavailable");
  }
  return { eligible: true, native_state: "native_verified", rejection_reason: null };
}

export function isDirectNativeMediaURL(value, kind = "video") {
  if (typeof value !== "string" || value.length > 4096) return false;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password || !url.hostname) return false;
    const host = url.hostname.toLowerCase();
    const acceptedProviderHost = host.endsWith(".fbcdn.net") || host.endsWith(".cdninstagram.com") || host.includes("scontent");
    if (!acceptedProviderHost) return false;
    const path = url.pathname.toLowerCase();
    if ([".html", ".htm"].some((extension) => path.endsWith(extension))) return false;
    if (kind === "video" && !/(\.mp4|\.m3u8|video)/.test(path + url.search.toLowerCase())) return false;
    return true;
  } catch { return false; }
}

function rejection(reason) {
  return { eligible: false, native_state: "rejected", rejection_reason: FOCUS_NATIVE_REJECTION_REASONS.includes(reason) || reason === "confirmed_advertising" ? reason : "unknown_native_unavailable" };
}

export function deterministicPolicyScreen(candidate, policy = {}) {
  const native = nativeMediaEligibility(candidate);
  if (!native.eligible) return native;
  const caption = `${candidate.caption || ""} ${(candidate.hashtags || []).join(" ")}`.toLocaleLowerCase();
  const denied = [...(policy.deny_phrases || []), ...(policy.negative_topics || [])].find((phrase) => hasPhrase(caption, phrase));
  if (denied) return { eligible: false, rejection_reason: "explicit_deny_rule", matched_rule: denied };
  if (candidate.ad_status === "confirmed_ad" || candidate.sponsorship_status === "confirmed_sponsored") return { eligible: false, rejection_reason: "confirmed_advertising" };
  const required = [...(policy.allow_phrases || []), ...(policy.positive_topics || [])];
  if (required.length && !required.some((phrase) => hasPhrase(caption, phrase))) return { eligible: false, rejection_reason: "required_allow_topic_missing" };
  return { eligible: true, native_state: native.native_state, rejection_reason: null };
}

// Rule text stays human-editable. This conservative parser turns comma, newline,
// and semicolon-separated terms into deterministic first-pass rules; AI receives
// the raw rule text separately and can only refine classification, never override
// the hard native/ad/creator checks.
export function focusRulePhrases(value) {
  return [...new Set(String(value || "").split(/[\n,;]/).map((part) => part.trim().replace(/^(?:show me|never show me|do not show me|don't show me)\s*:?\s*/i, "").trim().toLowerCase()).filter((part) => part.length >= 2).slice(0, 200))];
}

export function hasPhrase(text, phrase) {
  if (typeof phrase !== "string" || !phrase.trim()) return false;
  const escaped = phrase.trim().toLocaleLowerCase().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(^|[^\\p{L}\\p{N}])${escaped}(?=$|[^\\p{L}\\p{N}])`, "iu").test(text || "");
}

export function isConfirmedAdEvidence({ ad_status, sponsorship_status, classifier }) {
  return ad_status === "confirmed_ad" || sponsorship_status === "confirmed_sponsored" || classifier?.advertisement_intent === "confirmed_ad";
}

export function evaluateFreshness(items, rules, maximumAge, now = new Date(), timeZone = "America/Kentucky/Louisville") {
  const normalizedRules = normalizeFreshnessRules(rules, maximumAge);
  const normalizedMax = normalizeDuration(maximumAge);
  const validItems = (Array.isArray(items) ? items : []).filter((item) => item?.published_at && Number.isFinite(new Date(item.published_at).valueOf()));
  const fresh = validItems.filter((item) => publishedWithin(item.published_at, normalizedMax, now, timeZone));
  const total = Array.isArray(items) ? items.length : 0;
  const tiers = normalizedRules.map((rule) => {
    const count = fresh.filter((item) => publishedWithin(item.published_at, rule, now, timeZone)).length;
    const required = Math.ceil(total * rule.percentage / 100);
    return { ...rule, required, actual: count, actual_percentage: total ? (count * 100 / total) : null, shortfall: Math.max(0, required - count), satisfied: count >= required };
  });
  return { total, dated_items: validItems.length, maximum_age_count: fresh.length, tiers, satisfies: total > 0 && validItems.length === total && fresh.length === total && tiers.every((tier) => tier.satisfied) };
}

export function selectFreshnessCandidates(candidates, { existing = [], desiredCount, rules, maximumAge, mode, balancedTolerance = 0, now = new Date(), timeZone = "America/Kentucky/Louisville" } = {}) {
  const capacity = Math.max(0, Number(desiredCount) || 0);
  const normalizedRules = normalizeFreshnessRules(rules, maximumAge);
  const valid = dedupeBy(candidates || [], (item) => item.id)
    .filter((item) => publishedWithin(item?.published_at, maximumAge, now, timeZone));
  if (mode === "fill") return { items: valid.slice(0, capacity), excluded: (candidates || []).length - valid.length, enforcement: "maximum_age_only" };
  const selected = [];
  const available = [...valid];
  while (available.length && selected.length < capacity) {
    const ranked = available
      .map((candidate) => ({ candidate, freshCoverage: normalizedRules.reduce((score, rule) => score + (publishedWithin(candidate.published_at, rule, now, timeZone) ? rule.percentage : 0), 0), score: normalizedScore(candidate) }))
      .sort((left, right) => right.freshCoverage - left.freshCoverage || right.score - left.score || new Date(right.candidate.published_at) - new Date(left.candidate.published_at));
    const picked = ranked.find(({ candidate }) => freshnessAdmissionAllowed([...existing, ...selected, candidate], normalizedRules, maximumAge, mode, balancedTolerance, now, timeZone));
    if (!picked) break;
    selected.push(picked.candidate);
    available.splice(available.findIndex((item) => item.id === picked.candidate.id), 1);
  }
  return { items: selected, excluded: (candidates || []).length - selected.length, enforcement: mode };
}

function freshnessAdmissionAllowed(items, rules, maximumAge, mode, tolerance, now, timeZone) {
  const evaluation = evaluateFreshness(items, rules, maximumAge, now, timeZone);
  if (mode === "strict") return evaluation.satisfies;
  if (mode === "balanced") return evaluation.maximum_age_count === evaluation.total && evaluation.dated_items === evaluation.total && evaluation.tiers.every((tier) => (tier.actual_percentage || 0) + tolerance >= tier.percentage);
  return true;
}

export function publishedWithin(publishedAt, duration, now = new Date(), timeZone = "America/Kentucky/Louisville") {
  const published = new Date(publishedAt);
  if (!Number.isFinite(published.valueOf()) || published > now) return false;
  const cutoff = subtractCalendarDuration(now, normalizeDuration(duration), timeZone);
  return published >= cutoff;
}

export function subtractCalendarDuration(now, duration, timeZone) {
  // Calendar months/years preserve the target timezone's calendar day; days/weeks are elapsed-day durations.
  if (duration.unit === "days" || duration.unit === "weeks") return new Date(now.valueOf() - duration.value * (duration.unit === "weeks" ? 7 : 1) * 86_400_000);
  const parts = zonedParts(now, timeZone);
  let year = parts.year - (duration.unit === "years" ? duration.value : 0);
  let month = parts.month - (duration.unit === "months" ? duration.value : 0);
  while (month <= 0) { month += 12; year -= 1; }
  const day = Math.min(parts.day, daysInMonth(year, month));
  // Offset correction gives the matching civil instant across DST without treating months as 30 days.
  const approximate = Date.UTC(year, month - 1, day, parts.hour, parts.minute, parts.second);
  const offset = zoneOffsetMilliseconds(new Date(approximate), timeZone);
  return new Date(approximate - offset);
}

function zonedParts(date, timeZone) {
  const formatter = new Intl.DateTimeFormat("en-US", { timeZone, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" });
  const result = Object.fromEntries(formatter.formatToParts(date).filter((part) => part.type !== "literal").map((part) => [part.type, Number(part.value)]));
  return result;
}
function zoneOffsetMilliseconds(date, timeZone) {
  const parts = zonedParts(date, timeZone);
  return Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second) - date.valueOf();
}
function daysInMonth(year, month) { return new Date(Date.UTC(year, month, 0)).getUTCDate(); }

export function sequenceFocusCandidates(candidates, { seed, history = [], diversity = DEFAULT_FOCUS_SETTINGS.diversity, windowSize = 100 } = {}) {
  const rng = seededRandom(seed || "focus");
  const available = dedupeBy(candidates || [], (item) => item.id);
  const output = [];
  const relaxations = [];
  while (available.length && output.length < windowSize) {
    const recent = [...history, ...output];
    const sorted = available
      .map((candidate) => ({ candidate, score: normalizedScore(candidate) + rng() * diversity.stochastic_jitter }))
      .sort((a, b) => b.score - a.score);
    let selected = sorted.find(({ candidate }) => allowedByDiversity(candidate, recent, available, diversity, false));
    if (!selected) {
      selected = sorted.find(({ candidate }) => allowedByDiversity(candidate, recent, available, diversity, true));
      if (selected) relaxations.push({ item_id: selected.candidate.id, reason: "soft_diversity_relaxed_inventory_scarcity" });
    }
    if (!selected) selected = sorted[0];
    output.push(selected.candidate);
    available.splice(available.findIndex((item) => item.id === selected.candidate.id), 1);
  }
  return { items: output, relaxations };
}

function allowedByDiversity(candidate, recent, available, diversity, relaxed) {
  // Do not strand a one-creator Following feed. The adjacent-creator invariant is
  // only enforceable while an actual different creator remains eligible.
  const poolOtherCreatorExists = available.some((item) => item.creator_id !== candidate.creator_id);
  const adjacent = recent.at(-1);
  if (adjacent?.creator_id === candidate.creator_id && poolOtherCreatorExists) return false;
  if (relaxed) return true;
  const creatorGap = [...recent].reverse().findIndex((item) => item.creator_id === candidate.creator_id);
  if (creatorGap >= 0 && creatorGap < diversity.same_creator_target_gap) return false;
  if (recent.slice(-20).filter((item) => item.creator_id === candidate.creator_id).length >= diversity.max_creator_in_20) return false;
  if (recent.slice(-100).filter((item) => item.creator_id === candidate.creator_id).length >= diversity.max_creator_in_100) return false;
  const topic = candidate.dominant_topic || "unknown";
  const topicStreak = [...recent].reverse().findIndex((item) => (item.dominant_topic || "unknown") !== topic);
  if (topicStreak === -1 ? recent.length >= diversity.max_topic_streak : topicStreak >= diversity.max_topic_streak) return false;
  return true;
}
function normalizedScore(candidate) { return Number.isFinite(Number(candidate.score)) ? Number(candidate.score) : 0; }
function dedupeBy(values, identity) { const seen = new Set(); return values.filter((value) => value && !seen.has(identity(value)) && seen.add(identity(value))); }
function seededRandom(seed) {
  let state = Number.parseInt(createHash("sha256").update(String(seed)).digest("hex").slice(0, 8), 16) || 1;
  return () => { state |= 0; state = state + 0x6D2B79F5 | 0; let next = Math.imul(state ^ state >>> 15, 1 | state); next = next + Math.imul(next ^ next >>> 7, 61 | next) ^ next; return ((next ^ next >>> 14) >>> 0) / 4_294_967_296; };
}

export function estimateSupplyProjection({ acceptedNativeItems = 0, requests = 0, consumptionPerDay = 0, target = 0, sampleHours = 0 }) {
  const nativeEligiblePerRequest = requests > 0 ? acceptedNativeItems / requests : null;
  const measuredPerDay = sampleHours > 0 ? acceptedNativeItems * 24 / sampleHours : null;
  return {
    native_eligible_per_request: nativeEligiblePerRequest,
    measured_eligible_per_day: measuredPerDay,
    candidate_requests_needed_for_daily_consumption: nativeEligiblePerRequest && consumptionPerDay > 0 ? Math.ceil(consumptionPerDay / nativeEligiblePerRequest) : null,
    bank_refill_days_at_measured_yield: measuredPerDay && target > 0 ? target / measuredPerDay : null,
    sustained_supply_assessment: sampleHours >= 24 ? "measurement_window_at_least_24h" : "projection_only_short_sample"
  };
}

export function stableFingerprint(value) {
  return createHash("sha256").update(JSON.stringify(sortRecursively(value))).digest("hex");
}

export function canReserveFocusCost({ dailySpendMicros = 0, monthlySpendMicros = 0, amountMicros = 0, dailyLimitMicros = 0, monthlyLimitMicros = 0 }) {
  const values = [dailySpendMicros, monthlySpendMicros, amountMicros, dailyLimitMicros, monthlyLimitMicros].map(Number);
  if (values.some((value) => !Number.isFinite(value) || value < 0)) return false;
  return values[0] + values[2] <= values[3] && values[1] + values[2] <= values[4];
}

export function nativeMediaRefreshRequired(expiresAt, now = new Date(), safetyWindowMilliseconds = 5 * 60 * 1000) {
  if (!expiresAt) return false;
  const expiry = new Date(expiresAt);
  return !Number.isFinite(expiry.valueOf()) || expiry.valueOf() <= now.valueOf() + safetyWindowMilliseconds;
}
function sortRecursively(value) {
  if (Array.isArray(value)) return value.map(sortRecursively);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortRecursively(value[key])]));
  return value;
}
