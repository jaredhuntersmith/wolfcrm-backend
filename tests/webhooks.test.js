import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import {
  configSchema,
  mapPayload,
  render,
  sign,
  authenticate,
  retryDelay,
  boundJSON,
} from "../webhooks/domain.js";
import {
  publicAddress,
  destinationURL,
  resolveDestination,
  sendHTTPS,
} from "../webhooks/network.js";

test("raw byte HMAC authentication, clock bounds and bearer comparison", () => {
  const raw = Buffer.from('{ "value":1 }'),
    timestamp = String(Math.floor(Date.now() / 1000)),
    nonce = "0123456789abcdef",
    secret = "test-value-not-a-credential";
  const h = {
    "x-wolf-timestamp": timestamp,
    "x-wolf-nonce": nonce,
    "x-wolf-signature": "v1=" + sign(secret, timestamp, nonce, raw),
  };
  assert.equal(
    authenticate({ auth_mode: "hmac" }, { ingress: secret }, h, raw),
    nonce,
  );
  assert.throws(
    () =>
      authenticate(
        { auth_mode: "hmac" },
        { ingress: secret },
        h,
        Buffer.from('{"value":1}'),
      ),
    /authentication_failed/,
  );
  assert.throws(
    () =>
      authenticate(
        { auth_mode: "hmac" },
        { ingress: secret },
        h,
        raw,
        Date.now() + 301000,
      ),
    /authentication_failed/,
  );
  assert.throws(
    () =>
      authenticate(
        { auth_mode: "hmac" },
        { ingress: secret },
        { ...h, "x-wolf-nonce": "short" },
        raw,
      ),
    /authentication_failed/,
  );
  assert.equal(
    authenticate(
      { auth_mode: "bearer" },
      { ingress: secret },
      { authorization: "Bearer " + secret },
      raw,
    ),
    null,
  );
  assert.throws(() =>
    authenticate(
      { auth_mode: "bearer" },
      { ingress: secret },
      { authorization: "Bearer wrong" },
      raw,
    ),
  );
});
test("nested, array and escaped mapping; strict conversion, required and typed defaults", () => {
  const c = configSchema.parse({
    name: "test",
    direction: "incoming",
    mappings: [
      {
        name: "amount",
        path: "/items/0/amount",
        type: "number",
        required: true,
        transform: "number",
      },
      { name: "ok", path: "/ok", type: "boolean", default_value: false },
      { name: "date", path: "/date", type: "date", transform: "date" },
      {
        name: "title",
        path: "/a~1b",
        type: "text",
        template: "Hello {{value}}",
      },
    ],
  });
  assert.deepEqual(
    mapPayload(
      { items: [{ amount: "12.50" }], date: "2026-10-18", "a/b": "Wolf" },
      c.mappings,
    ),
    {
      amount: 12.5,
      ok: false,
      date: "2026-10-18T00:00:00.000Z",
      title: "Hello Wolf",
    },
  );
  assert.throws(
    () => mapPayload({ items: [{ amount: "12abc" }] }, c.mappings),
    (e) => e.code === "mapping_invalid" && e.diagnostics[0].field === "amount",
  );
  assert.throws(() => boundJSON(JSON.parse('{"__proto__":{"x":1}}')));
  let deep = {};
  for (let i = 0; i < 18; i++) deep = { deep };
  assert.throws(() => boundJSON(deep));
});
test("templates retain typed values, redact secret references and reject missing variables", () => {
  assert.deepEqual(
    render(
      { x: "{{variables.amount}}", auth: "Bearer {{secret.api_key}}" },
      { variables: { amount: 12 } },
      { api_key: "hidden" },
      true,
    ),
    { x: 12, auth: "Bearer [secret]" },
  );
  assert.throws(() => render("{{missing.value}}", {}));
  assert.throws(() => render("{{constructor.foo}}", {}));
  assert.throws(() =>
    configSchema.parse({
      name: "bad",
      direction: "outgoing",
      headers: [{ name: "Authorization", value: "Bearer literal-secret" }],
    }),
  );
  assert.throws(() =>
    configSchema.parse({
      name: "bad",
      direction: "incoming",
      allowed_actions: ["job.create"],
      require_approval: false,
    }),
  );
});
test("public-only URL and DNS validation includes IPv6, mapped addresses and mixed DNS", async () => {
  for (const address of [
    "127.0.0.2",
    "0.0.0.0",
    "10.0.0.2",
    "100.64.0.1",
    "169.254.169.254",
    "172.16.0.2",
    "192.168.1.2",
    "192.0.2.1",
    "224.0.0.1",
    "::1",
    "::",
    "fc00::1",
    "fe80::1",
    "ff02::1",
    "::ffff:127.0.0.1",
    "64:ff9b::a00:1",
    "2001:db8::1",
  ])
    assert.equal(publicAddress(address), false, address);
  for (const address of ["8.8.8.8", "2606:4700:4700::1111"])
    assert.equal(publicAddress(address), true, address);
  for (const url of [
    "http://example.com",
    "https://user:pass@example.com",
    "https://127.1",
    "https://2130706433",
    "https://[::1]",
    "https://example.com:8080",
    "https://metadata.google.internal",
    "https://host.local",
    "https://example.com/#fragment",
  ])
    assert.throws(() => destinationURL(url), undefined, url);
  await assert.rejects(
    resolveDestination("https://example.com", async () => [
      { address: "8.8.8.8", family: 4 },
      { address: "127.0.0.1", family: 4 },
    ]),
  );
});
test("transport pins DNS, never follows redirects, bounds response and request sizes", async () => {
  let calls = 0;
  const request = (url, options, callback) => {
    calls++;
    assert.equal(url.hostname, "example.com");
    assert.equal(options.rejectUnauthorized, true);
    assert.equal(options.agent, false);
    options.lookup("example.com", {}, (e, address, family) => {
      assert.equal(e, null);
      assert.equal(address, "8.8.8.8");
      assert.equal(family, 4);
    });
    const req = new EventEmitter();
    req.destroy = () => {};
    req.end = () => {
      const res = new EventEmitter();
      res.statusCode = 302;
      res.headers = { location: "https://127.0.0.1" };
      res.destroy = () => {};
      callback(res);
    };
    return req;
  };
  const result = await sendHTTPS(
    { url: "https://example.com", method: "POST", headers: {}, body: "{}" },
    { lookup: async () => [{ address: "8.8.8.8", family: 4 }], request },
  );
  assert.equal(result.status, 302);
  assert.equal(calls, 1);
  await assert.rejects(
    sendHTTPS({
      url: "https://example.com",
      method: "POST",
      headers: {},
      body: "x".repeat(65537),
    }),
  );
});
test("retry backoff honors bounded Retry-After", () => {
  assert.equal(retryDelay(1, "30"), 30000);
  assert.equal(retryDelay(1, "999999"), 3600000);
  assert.equal(
    retryDelay(1, null, Date.now(), () => 0.5),
    5000,
  );
});

test("transport bounds a successful response and never accepts DNS rebinding fallback", async () => {
  const request = (_url, _options, callback) => {
    const req = new EventEmitter();
    req.destroy = () => {};
    req.end = () => {
      const res = new EventEmitter();
      res.statusCode = 200;
      res.headers = {};
      res.destroy = () => {};
      callback(res);
      res.emit("data", Buffer.alloc(65537));
      res.emit("end");
    };
    return req;
  };
  await assert.rejects(
    sendHTTPS(
      { url: "https://example.com", method: "POST", headers: {}, body: "{}" },
      { lookup: async () => [{ address: "8.8.8.8", family: 4 }], request },
    ),
    (e) => e.code === "response_too_large",
  );
  let called = false;
  await assert.rejects(
    sendHTTPS(
      { url: "https://example.com", method: "POST", headers: {}, body: "{}" },
      {
        lookup: async () => [{ address: "127.0.0.1", family: 4 }],
        request: () => {
          called = true;
        },
      },
    ),
    (e) => e.code === "destination_not_public_https",
  );
  assert.equal(called, false);
});

test("date mappings reject impossible calendar values instead of normalizing them", () => {
  const mappings = configSchema.parse({
    name: "Dates",
    direction: "incoming",
    mappings: [
      { name: "date", path: "/date", type: "date", transform: "date" },
    ],
  }).mappings;
  for (const date of [
    "2026-02-30",
    "2025-02-29",
    "2026-13-01",
    "2026-01-01T24:00:00Z",
  ])
    assert.throws(
      () => mapPayload({ date }, mappings),
      (e) => e.code === "mapping_invalid",
    );
  assert.equal(
    mapPayload({ date: "2024-02-29" }, mappings).date,
    "2024-02-29T00:00:00.000Z",
  );
});
