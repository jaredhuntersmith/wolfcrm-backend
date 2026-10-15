import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import {
  mapLead,
  mergeContact,
  validateMappings,
  DEFAULT_SETTINGS,
  definitionSources,
  normalizePhone,
} from "../facebook-leads/domain.js";
import {
  encrypt,
  decrypt,
  validSignature,
  signedRequest,
  FacebookGraph,
} from "../facebook-leads/provider.js";
const form = {
  form_id: "20",
  page_id: "10",
  name: "Windows",
  sources: definitionSources([
    { key: "services", label: "Which services?" },
    { key: "email", label: "Email" },
    { key: "full_name", label: "Full name" },
    { key: "private", label: "Private" },
  ]),
  mappings: { "field:private": { destination: "ignore", origin: "manual" } },
};
const lead = {
  id: "30",
  form_id: "20",
  field_data: [
    { name: "services", values: ["Windows", "Gutters", "你好\nLine 2"] },
    { name: "private", values: ["DO_NOT_STORE_SENTINEL"] },
    { name: "email", values: ["hello@example.invalid"] },
    { name: "full_name", values: ["Jordán Sample"] },
  ],
};
test("all custom answers survive and ignored values are absent from every mapping output", () => {
  const result = mapLead(lead, form);
  assert.ok(!JSON.stringify(result).includes("DO_NOT_STORE_SENTINEL"));
  assert.equal(result.entries[0].value, "Windows\nGutters\n你好\nLine 2");
  assert.equal(result.contact.name, "Jordán Sample");
  assert.deepEqual(result.ignored, [
    "field:private",
    "meta:id",
    "meta:page_id",
    "meta:form_id",
    "meta:form_name",
  ]);
  const contact = mergeContact(null, result, DEFAULT_SETTINGS, "30");
  assert.match(contact.lead_info.join(""), /Which services\?/);
  assert.match(contact.lead_info.join(""), /你好/);
});
test("manual overrides beat defaults; unknown discard never leaks values", () => {
  const result = mapLead(
    {
      ...lead,
      field_data: [
        ...lead.field_data,
        { name: "new", values: ["SECRET_UNKNOWN"] },
      ],
    },
    {
      ...form,
      mappings: {
        ...form.mappings,
        "field:email": { destination: "lead_info:2", origin: "manual" },
      },
    },
    { ...DEFAULT_SETTINGS, unknown_policy: "ignore" },
  );
  assert.equal(result.contact.email, undefined);
  assert.ok(!JSON.stringify(result).includes("SECRET_UNKNOWN"));
  assert.equal(
    result.entries.find((e) => e.key === "field:email").destination,
    "lead_info:2",
  );
});
test("invalid/deleted targets and optional invalid email preserve Q&A; multiple email answers never take first silently", () => {
  const result = mapLead(
    {
      ...lead,
      field_data: [
        { name: "email", values: ["a@example.invalid", "b@example.invalid"] },
        { name: "services", values: ["Complete answer"] },
      ],
    },
    {
      ...form,
      mappings: { "field:services": { destination: "deleted_custom_field" } },
    },
  );
  assert.equal(result.contact.email, undefined);
  assert.equal(result.issues.length, 2);
  assert.match(
    result.entries.map((e) => e.value).join(""),
    /b@example.invalid/,
  );
});
test("components compose actual fields, priorities are explicit and scalar conflicts reject", () => {
  const sources = definitionSources(
    ["first_name", "last_name", "street_address", "city", "country"].map(
      (key) => ({ key }),
    ),
  );
  const result = mapLead(
    {
      field_data: sources.map((s) => ({
        name: s.key.slice(6),
        values: [s.key.slice(6)],
      })),
    },
    { ...form, sources, mappings: {} },
  );
  assert.equal(result.contact.name, "first_name last_name");
  assert.equal(result.contact.address, "street_address, city, country");
  assert.throws(
    () =>
      validateMappings(
        {
          "field:a": { destination: "email" },
          "field:b": { destination: "email" },
        },
        [{ key: "field:a" }, { key: "field:b" }],
      ),
    /competing/,
  );
  assert.throws(
    () => validateMappings({ "field:a": { destination: "company_id" } }, []),
    /destination/,
  );
});
test("same box appends, legacy boxes survive, overflow never truncates and empty input never erases", () => {
  const mapped = mapLead(lead, {
    ...form,
    mappings: {
      ...form.mappings,
      "field:services": { destination: "lead_info:1" },
    },
  });
  const old = {
    name: "Existing",
    email: "existing@example.invalid",
    lead_info: Array.from({ length: 25 }, (_, i) => `Box ${i + 1}`),
  };
  const result = mergeContact(old, mapped, DEFAULT_SETTINGS, "30");
  assert.equal(result.name, "Existing");
  assert.equal(result.email, "existing@example.invalid");
  assert.equal(result.lead_info.length, 25);
  assert.match(result.lead_info[0], /Box 1/);
  assert.match(result.lead_info[0], /Gutters/);
  assert.match(result.lead_info[24], /hello@example.invalid/);
  assert.equal(
    mergeContact(
      old,
      mapLead({ field_data: [] }, form),
      { overwrite: true },
      "31",
    ).email,
    old.email,
  );
});
test("consent is data only; missing and unchecked are not consent grants", () => {
  const result = mapLead(
    {
      custom_disclaimer_responses: [
        { checkbox_key: "sms", is_checked: "" },
        { checkbox_key: "email", is_checked: "0" },
      ],
    },
    form,
  );
  assert.equal(Object.keys(result.contact).length, 0);
  assert.match(result.entries[0].value, /Not checked/);
  assert.equal(result.entries[1].value, "0");
  assert.equal(result.entries[1].key, "consent:email");
});
test("conditional questions and consent definitions keep stable keys and labels before submissions", () => {
  const sources = definitionSources(
    [
      {
        key: "services",
        label: "Services?",
        dependent_conditional_questions: [
          {
            field_key: "floors",
            name: "How many floors?",
            input_type: "CUSTOM",
          },
        ],
      },
    ],
    {
      custom_disclaimer: {
        checkboxes: [
          {
            key: "contact_permission",
            text: "May we contact you about this request?",
            is_checked_by_default: true,
          },
        ],
      },
    },
  );
  assert.equal(
    sources.find((s) => s.key === "field:floors").label,
    "How many floors?",
  );
  assert.equal(
    sources.find((s) => s.key === "consent:contact_permission").label,
    "May we contact you about this request?",
  );
  const mapped = mapLead(
    {
      custom_disclaimer_responses: [
        { checkbox_key: "contact_permission", is_checked: false },
      ],
    },
    { ...form, sources },
  );
  assert.equal(
    mapped.entries.find(
      (e) => e.label === "May we contact you about this request?",
    ).value,
    "false",
  );
  assert.ok(!JSON.stringify(sources).includes("is_checked_by_default"));
});
test("optional Meta errors preserve core answers and expose availability without echoing provider data", async () => {
  const graph = new FacebookGraph(
    { FACEBOOK_LEADS_APP_SECRET: "fixture" },
    async (url) => {
      const fields = new URL(url).searchParams.get("fields");
      if (fields === "id,form_id,created_time,field_data")
        return Response.json(lead);
      return Response.json(
        { error: { code: 100, message: "PRIVATE PROVIDER ANSWER" } },
        { status: 400 },
      );
    },
  );
  const fetched = await graph.lead("30", "fixture");
  assert.deepEqual(fetched.lead.field_data, lead.field_data);
  assert.equal(fetched.issues.length, 3);
  assert.ok(!JSON.stringify(fetched.issues).includes("PRIVATE"));
});
test("signature exact bytes and company-scoped token encryption", () => {
  const env = {
      FACEBOOK_LEADS_ENCRYPTION_KEY: Buffer.alloc(32, 1).toString("base64"),
    },
    secret = "test",
    raw = Buffer.from('{"a":1}'),
    sig = "sha256=" + createHmac("sha256", secret).update(raw).digest("hex");
  assert.ok(validSignature(raw, sig, secret));
  assert.ok(!validSignature(Buffer.from('{"a": 1}'), sig, secret));
  assert.ok(!validSignature(raw, sig, ""));
  const token = encrypt("token-secret", "company-a", env);
  assert.equal(decrypt(token, "company-a", env), "token-secret");
  assert.throws(() => decrypt(token, "company-b", env));
  const payload = Buffer.from(
      JSON.stringify({ algorithm: "HMAC-SHA256", user_id: "123" }),
    ).toString("base64url"),
    signed =
      createHmac("sha256", secret).update(payload).digest("base64url") +
      "." +
      payload;
  assert.equal(signedRequest(signed, secret).user_id, "123");
  assert.throws(() => signedRequest(signed + "x", secret));
  assert.equal(normalizePhone("+1 (202) 555-0123"), "2025550123");
});
test("a dedicated Meta app is required to preserve the existing Focus webhook configuration", () => {
  const graph = new FacebookGraph({
    FACEBOOK_LEADS_APP_ID: "shared",
    FOCUS_META_APP_ID: "shared",
  });
  assert.equal(graph.configured(), false);
  assert.throws(
    () => graph.loginURL("state"),
    (e) => e.code === "facebook_dedicated_meta_app_required",
  );
});
test("Graph pagination follows only opaque cursors on fixed graph origin, errors never contain provider PII", async () => {
  const calls = [],
    env = { FACEBOOK_LEADS_APP_SECRET: "secret" },
    fetcher = async (url, init) => {
      calls.push([String(url), init]);
      return Response.json(
        calls.length === 1
          ? {
              data: [{ id: "1" }],
              paging: {
                next: "https://attacker.invalid?access_token=secret",
                cursors: { after: "cursor" },
              },
            }
          : { data: [{ id: "2" }] },
      );
    };
  const g = new FacebookGraph(env, fetcher);
  assert.equal((await g.all("me/accounts", "secret")).length, 2);
  assert.ok(calls.every(([u]) => u.startsWith("https://graph.facebook.com/")));
  assert.match(calls[1][0], /after=cursor/);
  assert.ok(calls.every(([u]) => !u.includes("access_token")));
  const bad = new FacebookGraph(env, async () =>
    Response.json(
      { error: { code: 190, message: "PRIVATE ANSWER TOKEN" } },
      { status: 400 },
    ),
  );
  await assert.rejects(
    bad.request("1", "token"),
    (e) =>
      e.code === "facebook_token_expired_reconnect" &&
      !e.message.includes("PRIVATE"),
  );
  const truncated = new FacebookGraph(env, async () =>
    Response.json({
      data: [{ id: "1" }],
      paging: { next: "https://graph.facebook.com/next" },
    }),
  );
  await assert.rejects(
    truncated.all("me/accounts", "secret"),
    (e) => e.code === "facebook_pagination_cursor_missing",
  );
});

test("numeric/tag destinations validate real writable types without dropping extra answers", () => {
  const f = {
    ...form,
    mappings: {
      "field:amount": { destination: "value_cents" },
      "field:latitude": { destination: "lat" },
      "field:labels": { destination: "tags" },
    },
  };
  const result = mapLead(
    {
      field_data: [
        { name: "amount", values: ["12500"] },
        { name: "latitude", values: ["1000"] },
        { name: "labels", values: ["A", "B, with comma"] },
      ],
    },
    f,
  );
  assert.equal(result.contact.value_cents, 12500);
  assert.equal(result.contact.lat, undefined);
  assert.deepEqual(result.contact.tags, ["A", "B, with comma"]);
  assert.ok(result.entries.some((e) => e.value === "1000"));
});
