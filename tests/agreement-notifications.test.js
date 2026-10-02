import test from "node:test";
import assert from "node:assert/strict";
import { agreementFollowupConditions, normalizeAgreementNotificationRules } from "../agreement-notifications.js";

test("follow-up configuration requires bounded delay and explicit boolean switches", () => {
  const defaults = normalizeAgreementNotificationRules();
  assert.equal(defaults.immediate_push, false);
  for (const raw of [{ rules: [null] }, { rules: [{ key: "unknown" }] }, { rules: [{ key: "unopened", delay_minutes: 0 }] }, { immediate_push: "false" }, { rules: [{ key: "unopened" }, { key: "unopened" }] }]) assert.throws(() => normalizeAgreementNotificationRules(raw));
  assert.equal(normalizeAgreementNotificationRules({ rules: [{ key: "unopened", delay_minutes: 30, push: true }] }).rules[0].delay_minutes, 30);
  assert.ok(defaults.events.every(event=>event.dashboard===null&&event.push===null));
  const configured=normalizeAgreementNotificationRules({events:[{key:'deposit_received',dashboard:false,push:true}]});
  assert.deepEqual(configured.events.find(event=>event.key==='deposit_received'),{key:'deposit_received',label:'Required deposit received',dashboard:false,push:true});
  for(const events of [[{key:'unknown'}],[{key:'deposit_received',push:'false'}],[{key:'deposit_received'},{key:'deposit_received'}]])assert.throws(()=>normalizeAgreementNotificationRules({events}));
});

test("delayed conditions begin at persisted events and distinguish payment processing from abandonment", () => {
  const agreement = { created_at: "2026-10-01T10:00:00Z", signed_at: "2026-10-01T11:00:00Z" };
  const open = { decision: "published", signing: "not_started", deposit: "locked", booking: "locked" };
  let conditions = agreementFollowupConditions({ agreement, state: open });
  assert.equal(conditions.unopened, agreement.created_at);
  assert.equal(conditions.opened_unsigned, null);
  conditions = agreementFollowupConditions({ agreement, state: { ...open, signing: "submitted", deposit: "processing" }, first_events: { observed_open: agreement.created_at } });
  assert.equal(conditions.unopened, null);
  assert.equal(conditions.deposit_outstanding, null);
  conditions = agreementFollowupConditions({ agreement, state: { ...open, signing: "submitted", deposit: "outstanding" } });
  assert.equal(conditions.deposit_outstanding, agreement.signed_at);
  const eligibleAt = "2026-10-01T11:30:00Z";
  conditions = agreementFollowupConditions({ agreement, state: { ...open, signing: "submitted", deposit: "paid", booking: "eligible" }, first_events: { booking_eligible: eligibleAt } });
  assert.equal(conditions.booking_pending, eligibleAt);
});

test("decline, expiration and supersession stop obsolete unsigned follow-ups without deleting history", () => {
  for (const decision of ["declined", "expired", "superseded", "revoked"]) {
    const conditions = agreementFollowupConditions({ agreement: { created_at: new Date() }, state: { decision, signing: "not_started", booking: "locked" }, first_events: { observed_open: new Date(), signing_started: new Date() } });
    assert.equal(conditions.unopened, null);
    assert.equal(conditions.opened_unsigned, null);
    assert.equal(conditions.signing_incomplete, null);
  }
});
