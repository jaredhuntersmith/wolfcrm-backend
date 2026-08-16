import assert from "node:assert/strict";
import crypto from "node:crypto";
import { normalizeIMessageE164, verifyTextingBlueSignature } from "../imessage.js";

function sign(rawBody, secret) {
  return `sha256=${crypto.createHmac("sha256", secret).update(rawBody).digest("hex")}`;
}

function testNormalizeE164() {
  assert.equal(normalizeIMessageE164("(606) 213-1071"), "+16062131071");
  assert.equal(normalizeIMessageE164("1-606-213-1071"), "+16062131071");
  assert.equal(normalizeIMessageE164("+14155551234"), "+14155551234");
  assert.equal(normalizeIMessageE164("+04155551234"), null);
  assert.equal(normalizeIMessageE164("12345"), null);
}

function testRawSignatureVerification() {
  const secret = "whsec_test_secret";
  const raw = Buffer.from('{"id":"evt_1","type":"message.received","data":{"id":"msg_1","content":"hello"}}');
  const signature = sign(raw, secret);
  assert.equal(verifyTextingBlueSignature(raw, signature, secret), true);
  assert.equal(verifyTextingBlueSignature(raw, signature.replace(/.$/, "0"), secret), false);
}

function testSignatureUsesRawBytes() {
  const secret = "whsec_test_secret";
  const raw = Buffer.from('{\n  "id": "evt_1",\n  "data": { "id": "msg_1" }\n}');
  const signature = sign(raw, secret);
  const reserialized = Buffer.from(JSON.stringify(JSON.parse(raw.toString("utf8"))));
  assert.notEqual(raw.toString("utf8"), reserialized.toString("utf8"));
  assert.equal(verifyTextingBlueSignature(raw, signature, secret), true);
  assert.equal(verifyTextingBlueSignature(reserialized, signature, secret), false);
}

testNormalizeE164();
testRawSignatureVerification();
testSignatureUsesRawBytes();

console.log("imessage tests passed");
