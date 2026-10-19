import https from "node:https";
import dns from "node:dns/promises";
import net from "node:net";
import ipaddr from "ipaddr.js";
import { fault } from "../mcp/context.js";
import { LIMIT } from "./domain.js";
import {safeResponseHeaders} from './responses.js';

export function publicAddress(address) {
  try {
    const ip = ipaddr.parse(address);
    return ip.range() === "unicast" && !ip.zoneId;
  } catch {
    return false;
  }
}
export function destinationURL(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw fault(400, "invalid_destination");
  }
  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.hash ||
    (url.port && url.port !== "443") ||
    host.endsWith(".") ||
    (!host.includes(".") && !net.isIP(host)) ||
    /(^|\.)(localhost|local|internal|lan|home|test|invalid|localhost\.localdomain)$/.test(
      host,
    ) ||
    host === "metadata.google.internal" ||
    (net.isIP(host) && !publicAddress(host))
  )
    throw fault(400, "destination_not_public_https");
  return url;
}
export async function resolveDestination(value, lookup = dns.lookup) {
  const url = destinationURL(value),
    hostname = url.hostname.replace(/^\[|\]$/g, "");
  let addresses;
  try {
    addresses = net.isIP(hostname)
      ? [{ address: hostname, family: net.isIP(hostname) }]
      : await lookup(hostname, { all: true, verbatim: true });
  } catch {
    throw fault(503, "destination_dns_failed");
  }
  if (
    !addresses.length ||
    addresses.length > 32 ||
    addresses.some((a) => !publicAddress(a.address))
  )
    throw fault(400, "destination_not_public_https");
  return { url, addresses };
}
// No proxy environment, redirects or second DNS resolution. Host and TLS SNI remain
// the user's hostname; only a validated address is handed to the socket lookup.
export async function sendHTTPS(
  { url, method, headers, body, timeout_ms = 8000 },
  { lookup = dns.lookup, request = https.request } = {},
) {
  if (Buffer.byteLength(body) > LIMIT) throw fault(413, "payload_too_large");
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(
      () => reject(fault(504, "delivery_timeout")),
      timeout_ms,
    );
  });
  let target;
  try {
    target = await Promise.race([resolveDestination(url, lookup), deadline]);
  } finally {
    clearTimeout(timer);
  }
  const pinned = target.addresses[0];
  return new Promise((resolve, reject) => {
    let done = false;
    const finish = (e, v) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (e) reject(e);
      else resolve(v);
    };
    const req = request(
      target.url,
      {
        method,
        agent: false,
        rejectUnauthorized: true,
        headers: {
          ...headers,
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
        },
        lookup: (_host, options, cb) =>
          options.all
            ? cb(null, [pinned])
            : cb(null, pinned.address, pinned.family),
      },
      (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400) {
          res.destroy();
          finish(null, {
            status: res.statusCode,
            body: null,
            retryAfter: null,
          });
          return;
        }
        const chunks = [];
        let size = 0;
        res.on("data", (chunk) => {
          size += chunk.length;
          if (size > LIMIT) {
            res.destroy();
            finish(fault(502, "response_too_large"));
          } else chunks.push(chunk);
        });
        res.on("error", () => finish(fault(502, "response_interrupted")));
        res.on("end", () =>
          finish(null, {
            status: res.statusCode,
            body: Buffer.concat(chunks).toString("utf8"),
            headers: safeResponseHeaders(res.headers),
            retryAfter: res.headers["retry-after"] || null,
          }),
        );
      },
    );
    timer = setTimeout(() => {
      req.destroy();
      finish(fault(504, "delivery_timeout"));
    }, timeout_ms);
    req.on("error", () => finish(fault(502, "delivery_network_error")));
    req.end(body);
  });
}
