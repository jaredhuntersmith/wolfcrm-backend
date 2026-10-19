import { z } from "zod";
import { createHmac, timingSafeEqual } from "node:crypto";
import { hoursSchema, alwaysHours } from "../mcp/hours.js";
import { fault } from "../mcp/context.js";

export const LIMIT = 65536;
const name = z
  .string()
  .regex(/^[A-Za-z][A-Za-z0-9_]{0,63}$/)
  .refine((v) => !["constructor", "prototype"].includes(v));
const sensitive = /authorization|cookie|password|secret|token|api[_-]?key/i;
export function redactSensitive(v) {
  if (Array.isArray(v)) return v.map(redactSensitive);
  if (v && typeof v === "object")
    return Object.fromEntries(
      Object.entries(v).map(([k, x]) => [
        k,
        sensitive.test(k) ? "[redacted]" : redactSensitive(x),
      ]),
    );
  return v;
}
const unsafe = new Set(["__proto__", "prototype", "constructor"]);
export const pointer = z
  .string()
  .max(500)
  .refine((v) => v === "" || v.startsWith("/"))
  .refine((v) => !v.split("/").some((p) => unsafe.has(p)));
export const mappingSchema = z
  .object({
    name,
    path: pointer,
    type: z.enum(["text", "number", "boolean", "date", "object", "array"]),
    required: z.boolean().default(false),
    transform: z.enum(["none", "number", "date", "text"]).default("none"),
    default_value: z.json().optional(),
    template: z.string().max(2000).optional(),
  })
  .strict();
export const responseMappingSchema = mappingSchema.extend({
  source: z.enum(['body','headers']).default('body'),
}).superRefine((m,ctx)=>{
  if(m.source==='headers' && (!/^\/[a-zA-Z0-9-]+$/.test(m.path) || sensitive.test(m.path)))
    ctx.addIssue({code:'custom',message:'Select one non-sensitive response header.'});
});
export const pureActions = new Set([
  "collection.filter",
  "collection.map",
  "collection.sort",
  "collection.limit",
  "collection.first",
  "collection.last",
  "collection.count",
  "collection.unique",
  "collection.concat",
  "collection.flatten",
  "collection.contains",
  "object.get",
  "object.build",
  "coalesce",
  "math",
  "text",
  "date",
]);
export const actionPermissions = Object.freeze({
  "task.create": ["tasks.manage", "tasks.view"],
  "contact.update_fields": ["contacts.edit", "contacts.view"],
  "job.create": ["schedule.create", "schedule.view", "schedule.manage_team"],
  "note.create": ["notes.create", "notes.view"],
  "webhook.send": ["integrations.manage"],
});
export const configSchema = z
  .object({
    name: z.string().trim().min(1).max(100),
    description: z.string().max(1000).default(""),
    direction: z.enum(["incoming", "outgoing"]),
    enabled: z.boolean().default(false),
    operating_hours: hoursSchema.default(alwaysHours()),
    auth_mode: z.enum(["bearer", "hmac"]).default("bearer"),
    mappings: z.array(mappingSchema).max(64).default([]),
    dedupe_path: pointer.default(""),
    automation_id: z.uuid().nullable().default(null),
    allowed_actions: z
      .array(z.enum(Object.keys(actionPermissions)))
      .max(5)
      .default([]),
    require_approval: z.boolean().default(true),
    url: z.string().max(2048).default(""),
    method: z.enum(["POST", "PUT", "PATCH"]).default("POST"),
    headers: z
      .array(
        z
          .object({
            name: z.string().regex(/^[A-Za-z0-9-]{1,64}$/),
            value: z.string().max(2000),
          })
          .strict(),
      )
      .max(20)
      .default([]),
    body_template: z.json().default({
      event_id: "{{event.id}}",
      event_type: "{{event.type}}",
      timestamp: "{{event.timestamp}}",
      schema_version: 1,
      data: "{{event.data}}",
    }),
    subscriptions: z.array(z.string().max(100)).max(30).default([]),
    sign_requests: z.boolean().default(false),
    response_mappings: z.array(responseMappingSchema).max(16).default([]),
    timeout_ms: z.number().int().min(1000).max(10000).default(8000),
    max_attempts: z.number().int().min(1).max(5).default(3),
    retention_days: z.number().int().min(1).max(30).default(7),
  })
  .strict()
  .superRefine((c, ctx) => {
    for (const ms of [c.mappings, c.response_mappings])
      if (new Set(ms.map((m) => m.name)).size !== ms.length)
        ctx.addIssue({
          code: "custom",
          message: "Variable names must be unique",
        });
    if (c.allowed_actions.includes("job.create") && !c.require_approval)
      ctx.addIssue({
        code: "custom",
        message: "Scheduling requires receipt approval",
      });
    for (const h of c.headers) {
      if (
        /^(host|connection|content-length|transfer-encoding|cookie|content-type|idempotency-key|x-wolf-.*)$/i.test(
          h.name,
        ) ||
        /[\r\n]/.test(h.value)
      )
        ctx.addIssue({ code: "custom", message: "Reserved or invalid header" });
      if (
        /authorization|token|secret|api.?key/i.test(h.name) &&
        !/^([^{}]*\s)?\{\{secret\.[A-Za-z][A-Za-z0-9_]{0,63}\}\}$/.test(h.value)
      )
        ctx.addIssue({
          code: "custom",
          message: "Authentication headers require a secret reference",
        });
    }
    if (
      new Set(c.headers.map((h) => h.name.toLowerCase())).size !==
      c.headers.length
    )
      ctx.addIssue({ code: "custom", message: "Header names must be unique" });
  });
export function boundJSON(value) {
  let count = 0;
  const visit = (v, depth) => {
    if (++count > 2000 || depth > 16) throw fault(400, "payload_too_complex");
    if (v && typeof v === "object")
      for (const [k, x] of Object.entries(v)) {
        if (unsafe.has(k)) throw fault(400, "unsafe_field");
        visit(x, depth + 1);
      }
  };
  if (Buffer.byteLength(JSON.stringify(value)) > LIMIT)
    throw fault(413, "payload_too_large");
  visit(value, 0);
  return value;
}
export function atPath(value, path) {
  if (path === "") return value;
  let v = value;
  for (const part of pointer.parse(path).slice(1).split("/")) {
    const p = part.replaceAll("~1", "/").replaceAll("~0", "~");
    if (
      unsafe.has(p) ||
      v === null ||
      typeof v !== "object" ||
      !Object.hasOwn(v, p)
    )
      return undefined;
    v = v[p];
  }
  return v;
}
export function structure(value) {
  boundJSON(value);
  const result = [];
  const walk = (v, path) => {
    result.push({
      path,
      type: Array.isArray(v)
        ? "array"
        : v === null
          ? "null"
          : typeof v === "object"
            ? "object"
            : typeof v === "string"
              ? "text"
              : typeof v,
    });
    if (v && typeof v === "object")
      for (const [k, x] of Object.entries(v))
        walk(x, path + "/" + k.replaceAll("~", "~0").replaceAll("/", "~1"));
  };
  walk(value, "");
  return result;
}
function validISODate(value, requireTime = false) {
  if (typeof value !== "string") return false;
  const m =
    /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2}))?$/.exec(
      value,
    );
  if (!m || (requireTime && !m[4])) return false;
  const year = +m[1],
    month = +m[2],
    day = +m[3],
    leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return (
    month >= 1 &&
    month <= 12 &&
    day >= 1 &&
    day <= days[month - 1] &&
    (!m[4] || (+m[4] < 24 && +m[5] < 60 && +m[6] < 60)) &&
    Number.isFinite(Date.parse(value))
  );
}
export function mapPayload(value, mappings) {
  boundJSON(value);
  const out = {},
    errors = [];
  for (const m of mappings) {
    let v = atPath(value, m.path);
    if (v === undefined || v === null) {
      if (Object.hasOwn(m, "default_value")) v = m.default_value;
      else if (!m.required) continue;
      else {
        errors.push({ field: m.name, code: "required", path: m.path });
        continue;
      }
    }
    if (
      m.transform === "number" &&
      typeof v === "string" &&
      /^-?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/.test(v.trim())
    )
      v = Number(v);
    if (m.transform === "date" && validISODate(v))
      v = new Date(v).toISOString();
    if (
      m.transform === "text" &&
      ["string", "number", "boolean"].includes(typeof v)
    )
      v = String(v);
    if (m.template) {
      if (typeof v !== "string") {
        errors.push({
          field: m.name,
          code: "template_requires_text",
          path: m.path,
        });
        continue;
      }
      v = m.template.replaceAll("{{value}}", v);
    }
    const valid =
      m.type === "text"
        ? typeof v === "string"
        : m.type === "number"
          ? typeof v === "number" && Number.isFinite(v)
          : m.type === "boolean"
            ? typeof v === "boolean"
            : m.type === "date"
              ? validISODate(v, true)
              : m.type === "array"
                ? Array.isArray(v)
                : v !== null && typeof v === "object" && !Array.isArray(v);
    if (!valid)
      errors.push({ field: m.name, code: "expected_" + m.type, path: m.path });
    else out[m.name] = v;
  }
  if (errors.length)
    throw Object.assign(fault(422, "mapping_invalid"), { diagnostics: errors });
  return boundJSON(redactSensitive(out));
}
function dotted(context, path) {
  if (path.split(".").some((p) => unsafe.has(p)))
    throw fault(400, "unsafe_template");
  return path
    .split(".")
    .reduce(
      (v, p) =>
        v && typeof v === "object" && Object.hasOwn(v, p) ? v[p] : undefined,
      context,
    );
}
export function render(template, context, secrets = {}, preview = false) {
  boundJSON(template);
  const token = /\{\{([A-Za-z][A-Za-z0-9_.]*)\}\}/g;
  const read = (p) => {
    if (p.startsWith("secret.")) {
      if (preview) return "[secret]";
      if (!Object.hasOwn(secrets, p.slice(7)))
        throw fault(400, "secret_reference_missing");
      return secrets[p.slice(7)];
    }
    const v = dotted(context, p);
    if (v === undefined) throw fault(422, "template_value_missing");
    return v;
  };
  const walk = (v) => {
    if (typeof v === "string") {
      const exact = /^\{\{([A-Za-z][A-Za-z0-9_.]*)\}\}$/.exec(v);
      if (exact) return read(exact[1]);
      return v.replace(token, (_, p) => {
        const x = read(p);
        return typeof x === "object" ? JSON.stringify(x) : String(x);
      });
    }
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === "object")
      return Object.fromEntries(
        Object.entries(v).map(([k, x]) => [k, walk(x)]),
      );
    return v;
  };
  return boundJSON(walk(template));
}
export function sign(secret, timestamp, nonce, raw) {
  return createHmac("sha256", secret)
    .update(`${timestamp}.${nonce}.`)
    .update(raw)
    .digest("hex");
}
export function equal(a, b) {
  const aa = Buffer.from(a || ""),
    bb = Buffer.from(b || "");
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}
export function authenticate(config, secrets, headers, raw, now = Date.now()) {
  if (!secrets.ingress) throw fault(401, "authentication_failed");
  if (config.auth_mode === "bearer") {
    if (!equal(headers.authorization, "Bearer " + secrets.ingress))
      throw fault(401, "authentication_failed");
    return null;
  }
  const timestamp = headers["x-wolf-timestamp"],
    nonce = headers["x-wolf-nonce"],
    signature = headers["x-wolf-signature"];
  if (
    !/^\d{10}$/.test(timestamp || "") ||
    Math.abs(now / 1000 - Number(timestamp)) > 300 ||
    !/^[A-Za-z0-9_-]{16,128}$/.test(nonce || "") ||
    !/^v1=[a-f0-9]{64}$/.test(signature || "") ||
    !equal(signature, "v1=" + sign(secrets.ingress, timestamp, nonce, raw))
  )
    throw fault(401, "authentication_failed");
  return nonce;
}
export function retryDelay(
  attempt,
  retryAfter,
  now = Date.now(),
  random = Math.random,
) {
  let seconds =
    retryAfter === null || retryAfter === undefined || retryAfter === ""
      ? NaN
      : Number(retryAfter);
  if (!Number.isFinite(seconds))
    seconds = (Date.parse(retryAfter) - now) / 1000;
  return Math.min(
    3600000,
    Math.max(
      1000,
      Number.isFinite(seconds)
        ? seconds * 1000
        : 5000 * 2 ** (attempt - 1) * (0.75 + random() * 0.5),
    ),
  );
}
