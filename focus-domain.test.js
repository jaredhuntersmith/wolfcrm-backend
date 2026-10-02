import assert from "node:assert/strict";
import test from "node:test";
import {
  DEFAULT_FOCUS_SETTINGS,
  canReserveFocusCost,
  evaluateAutomaticFollowerGate,
  evaluateFreshness,
  extractInstagramProfileUsernames,
  hasPhrase,
  nativeMediaEligibility,
  nativeMediaRefreshRequired,
  normalizeFocusSettings,
  selectFreshnessCandidates,
  sequenceFocusCandidates
} from "./focus-domain.js";

test("automatic 9,999-follower discovery is stopped before expensive work", () => {
  assert.deepEqual(evaluateAutomaticFollowerGate({ followerCount: 9_999, minimumFollowers: 10_000, strict: true }), {
    eligible: false, status: "below_threshold", rejection_reason: "below_follower_threshold"
  });
  assert.equal(evaluateAutomaticFollowerGate({ followerCount: 10_000, minimumFollowers: 10_000, strict: true }).eligible, true);
});

test("local Focus follow and manual seed bypass only the popularity gate", () => {
  assert.equal(evaluateAutomaticFollowerGate({ followerCount: 500, minimumFollowers: 10_000, isFocusFollowed: true }).exemption_reason, "focus_followed");
  assert.equal(evaluateAutomaticFollowerGate({ followerCount: null, minimumFollowers: 10_000, isManual: true }).eligible, true);
  assert.equal(evaluateAutomaticFollowerGate({ followerCount: null, minimumFollowers: 10_000, strict: true }).rejection_reason, "follower_count_unknown");
});

test("native eligibility never treats permalink-only or creatorless media as a Reel", () => {
  assert.equal(nativeMediaEligibility({ creator_id: "c", media_type: "reel", media_url: "https://www.instagram.com/reel/a/" }).eligible, false);
  assert.equal(nativeMediaEligibility({ creator_id: null, media_type: "reel", media_url: "https://scontent.cdninstagram.com/video.mp4" }).rejection_reason, "creator_identity_unresolved");
  assert.equal(nativeMediaEligibility({ creator_id: "c", media_type: "reel", media_url: "https://scontent.cdninstagram.com/video.mp4" }).eligible, true);
  assert.equal(nativeMediaEligibility({ creator_id: "c", media_type: "post", assets: [{ url: "https://scontent.cdninstagram.com/one.jpg", media_kind: "image" }, { url: "https://instagram.com/p/broken/", media_kind: "image" }] }).eligible, false);
});

test("Brave discovery accepts only unmistakable public Instagram profile URLs", () => {
  assert.deepEqual(extractInstagramProfileUsernames([
    { url: "https://www.instagram.com/windowwolves/" },
    { url: "https://instagram.com/reel/ABC/" },
    { url: "https://instagram.com/p/ABC/" },
    { url: "https://example.com/windowwolves" },
    { url: "https://instagram.com/Fitness.Coach?igsh=one" }
  ]), ["windowwolves", "fitness.coach"]);
});

test("exact phrase matching avoids substring false positives", () => {
  assert.equal(hasPhrase("Educational marketing tactics", "marketing"), true);
  assert.equal(hasPhrase("remarketing tactics", "marketing"), false);
});

test("freshness tiers are cumulative and ceiling rounded", () => {
  const now = new Date("2028-03-01T17:00:00.000Z");
  const items = Array.from({ length: 10 }, (_, index) => ({ published_at: new Date(now.valueOf() - (index + 1) * 86_400_000).toISOString() }));
  const result = evaluateFreshness(items, DEFAULT_FOCUS_SETTINGS.reels_freshness_rules, DEFAULT_FOCUS_SETTINGS.reels_maximum_age, now);
  assert.equal(result.satisfies, true);
  assert.equal(result.tiers.at(-1).required, 10);
  assert.equal(result.tiers.at(-1).actual, 10);
});

test("settings maintain independent ready targets and bounded player preloads", () => {
  const settings = normalizeFocusSettings({ reels_ready_target: 10, posts_ready_target: 1000, wifi_reel_preload: 3, cellular_reel_preload: 0 });
  assert.equal(settings.reels_ready_target, 10);
  assert.equal(settings.posts_ready_target, 1000);
  assert.throws(() => normalizeFocusSettings({ wifi_reel_preload: 4 }), /invalid_wifi_reel_preload/);
});

test("weighted sequencing is stable and prevents adjacent creator duplication with alternatives", () => {
  const candidates = Array.from({ length: 30 }, (_, index) => ({
    id: `item-${index}`,
    creator_id: index < 20 ? "creator-a" : index % 2 ? "creator-b" : "creator-c",
    dominant_topic: index % 2 ? "business" : "fitness",
    score: 100 - index
  }));
  const first = sequenceFocusCandidates(candidates, { seed: "stable-seed", windowSize: 20 });
  const second = sequenceFocusCandidates(candidates, { seed: "stable-seed", windowSize: 20 });
  assert.deepEqual(first.items.map((item) => item.id), second.items.map((item) => item.id));
  for (let index = 1; index < first.items.length; index += 1) assert.notEqual(first.items[index - 1].creator_id, first.items[index].creator_id);
  assert.equal(new Set(first.items.map((item) => item.id)).size, first.items.length);
});

test("strict freshness refuses an over-age quota violation while fill stays bounded by maximum age", () => {
  const now = new Date("2028-03-01T17:00:00.000Z");
  const candidates = [
    { id: "new", published_at: "2028-02-28T17:00:00.000Z", score: 1 },
    { id: "old-a", published_at: "2027-12-01T17:00:00.000Z", score: 9 },
    { id: "old-b", published_at: "2027-11-01T17:00:00.000Z", score: 8 },
    { id: "expired", published_at: "2026-01-01T17:00:00.000Z", score: 99 }
  ];
  const rules = [{ percentage: 50, value: 8, unit: "weeks" }];
  const maximumAge = { value: 1, unit: "years" };
  const strict = selectFreshnessCandidates(candidates, { desiredCount: 4, rules, maximumAge, mode: "strict", now });
  const fill = selectFreshnessCandidates(candidates, { desiredCount: 4, rules, maximumAge, mode: "fill", now });
  assert.deepEqual(strict.items.map((item) => item.id), ["new", "old-a"]);
  assert.deepEqual(fill.items.map((item) => item.id), ["new", "old-a", "old-b"]);
});

test("a Following feed with one creator remains usable when no diversity alternative exists", () => {
  const result = sequenceFocusCandidates([
    { id: "one", creator_id: "creator-a", dominant_topic: "business", score: 3 },
    { id: "two", creator_id: "creator-a", dominant_topic: "business", score: 2 }
  ], { seed: "one-creator", diversity: { ...DEFAULT_FOCUS_SETTINGS.diversity, max_topic_streak: 10 }, windowSize: 2 });
  assert.deepEqual(result.items.map((item) => item.id).sort(), ["one", "two"]);
});

test("hard cost ceilings and expiring native URLs fail closed", () => {
  assert.equal(canReserveFocusCost({ dailySpendMicros: 900, monthlySpendMicros: 9_000, amountMicros: 100, dailyLimitMicros: 1_000, monthlyLimitMicros: 10_000 }), true);
  assert.equal(canReserveFocusCost({ dailySpendMicros: 901, monthlySpendMicros: 9_000, amountMicros: 100, dailyLimitMicros: 1_000, monthlyLimitMicros: 10_000 }), false);
  const now = new Date("2028-03-01T12:00:00.000Z");
  assert.equal(nativeMediaRefreshRequired("2028-03-01T12:04:59.000Z", now), true);
  assert.equal(nativeMediaRefreshRequired("2028-03-01T12:05:01.000Z", now), false);
});
