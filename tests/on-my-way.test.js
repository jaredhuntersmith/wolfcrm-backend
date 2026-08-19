import test from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_ON_MY_WAY_TEMPLATE,
  blocksRecentOnMyWay,
  friendlyOnMyWayEta,
  normalizeOnMyWayChannel,
  parseOnMyWayCoordinate,
  renderOnMyWayTemplate,
  validateOnMyWayMessage,
  validateOnMyWayTemplate
} from "../on-my-way.js";

test("On My Way templates render customer, employee, company, and road ETA", () => {
  assert.equal(
    renderOnMyWayTemplate(DEFAULT_ON_MY_WAY_TEMPLATE, {
      customerName: "Morgan Lee",
      employeeName: "Alex Tech",
      companyName: "Window Wolves",
      etaSeconds: 721
    }),
    "Hi Morgan, Alex Tech from Window Wolves is on the way. Estimated arrival: about 15 minutes."
  );
  assert.equal(friendlyOnMyWayEta(3_601), "about 1 hour 5 minutes");
  assert.equal(friendlyOnMyWayEta(null), "soon");
});

test("missing names and ETA render safe text without raw placeholders", () => {
  assert.equal(
    renderOnMyWayTemplate("Hi {{customer_name}}, {{employee_name}} from {{company_name}} will arrive {{eta}}."),
    "Hi there, A team member from Our team will arrive soon."
  );
});

test("template and message validation reject unknown placeholders and oversized content", () => {
  assert.throws(
    () => validateOnMyWayTemplate("Hi {{unknown_value}}"),
    (error) => error.code === "unsupported_on_my_way_placeholder"
  );
  assert.throws(() => validateOnMyWayTemplate("  "), (error) => error.code === "on_my_way_template_required");
  assert.throws(() => validateOnMyWayMessage("x".repeat(1_201)), (error) => error.code === "on_my_way_message_too_long");
});

test("coordinates and channel are strict while absent coordinates remain optional", () => {
  assert.deepEqual(parseOnMyWayCoordinate("38.25", -85.75), { latitude: 38.25, longitude: -85.75 });
  assert.equal(parseOnMyWayCoordinate(null, null), null);
  assert.throws(() => parseOnMyWayCoordinate(91, 0), (error) => error.code === "invalid_on_my_way_coordinate");
  assert.equal(normalizeOnMyWayChannel("SMS"), "sms");
  assert.throws(() => normalizeOnMyWayChannel("imessage"), (error) => error.code === "on_my_way_channel_unavailable");
});

test("recent in-flight and accepted sends block ordinary duplicates", () => {
  const now = new Date("2026-08-19T15:00:00Z");
  assert.equal(blocksRecentOnMyWay({ status: "queued", created_at: "2026-08-19T14:45:00Z" }, { now }), true);
  assert.equal(blocksRecentOnMyWay({ status: "sending", created_at: "2026-08-19T14:59:00Z" }, { now }), true);
  assert.equal(blocksRecentOnMyWay({ status: "failed", created_at: "2026-08-19T14:59:00Z" }, { now }), false);
  assert.equal(blocksRecentOnMyWay({ status: "delivered", created_at: "2026-08-19T14:29:59Z" }, { now }), false);
});
