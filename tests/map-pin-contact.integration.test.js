import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { startLocalPostgres } from "./helpers/local-postgres.js";

test("Map pin conversion persists one company-scoped contact and survives stale pin writes", { timeout: 120_000 }, async () => {
  const postgres = startLocalPostgres();
  postgres.configureEnvironment();
  let pool;
  let server;
  try {
    const backend = await import("../index.js");
    pool = backend.pool;
    await backend.bootstrap();
    const { installGoogleSheetsSchema } = await import("../google-sheets.js");
    await installGoogleSheetsSchema(pool);
    const { installAutomationSystem } = await import("../automations.js");
    await installAutomationSystem({
      app: backend.app,
      pool,
      authRequired: backend.authRequired,
      requireEmployer: backend.requireCapability("automations.manage"),
      disableProcessors: true
    });
    const companyA = randomUUID();
    const companyB = randomUUID();
    const ownerA = randomUUID();
    const ownerB = randomUUID();
    const pinID = randomUUID();
    await pool.query("INSERT INTO companies(id,name,join_code) VALUES($1,'Map Test A','MAP-A'),($2,'Map Test B','MAP-B')", [companyA, companyB]);
    await pool.query("INSERT INTO users(id,email,role,company_id) VALUES($1,'map-a@example.invalid','employer',$3),($2,'map-b@example.invalid','employer',$4)", [ownerA, ownerB, companyA, companyB]);
    await pool.query("UPDATE companies SET owner_user_id=CASE WHEN id=$1 THEN $3::uuid ELSE $4::uuid END WHERE id IN ($1,$2)", [companyA, companyB, ownerA, ownerB]);
    await pool.query("INSERT INTO sessions(token,user_id) VALUES('map-owner-a',$1),('map-owner-b',$2)", [ownerA, ownerB]);
    server = await new Promise((resolve) => {
      const listener = backend.app.listen(0, "127.0.0.1", () => resolve(listener));
    });
    const base = `http://127.0.0.1:${server.address().port}`;
    async function request(path, { token = "map-owner-a", method = "GET", body } = {}) {
      const response = await fetch(base + path, {
        method,
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body)
      });
      return { status: response.status, body: await response.json() };
    }

    const original = {
      latitude: 38.25, longitude: -85.75, name: "Maya Jones", address: "12 Oak Street",
      phone: "+15025550123", email: "maya@example.invalid", notes: "Blue door", status: "reloop",
      contact_id: null
    };
    const missing = await request(`/api/map-pins/${pinID}/contact`, { method: "POST", body: { intent: "convert" } });
    assert.equal(missing.status, 404);
    const saved = await request(`/api/map-pins/${pinID}`, { method: "PUT", body: original });
    assert.equal(saved.status, 200, JSON.stringify(saved.body));
    const foreign = await request(`/api/map-pins/${pinID}/contact`, { token: "map-owner-b", method: "POST", body: { intent: "convert" } });
    assert.equal(foreign.status, 404);

    const converted = await request(`/api/map-pins/${pinID}/contact`, { method: "POST", body: { intent: "convert" } });
    assert.equal(converted.status, 201, JSON.stringify(converted.body));
    assert.equal(converted.body.created, true);
    assert.equal(converted.body.pin.contact_id, converted.body.contact.id);
    assert.equal(converted.body.pin.status, "reloop");
    assert.equal(converted.body.contact.name, original.name);
    assert.equal(converted.body.contact.address, original.address);
    assert.equal(converted.body.contact.phone, original.phone);
    assert.equal(converted.body.contact.email, original.email);
    assert.equal(converted.body.contact.source, "Door-to-Door");
    assert.ok(converted.body.contact.lead_source_id);
    assert.equal(converted.body.contact.company_id, companyA);
    const contactID = converted.body.contact.id;

    const retried = await request(`/api/map-pins/${pinID}/contact`, { method: "POST", body: { intent: "convert" } });
    assert.equal(retried.status, 200, JSON.stringify(retried.body));
    assert.equal(retried.body.created, false);
    assert.equal(retried.body.contact.id, contactID);
    const lateWrite = await request(`/api/map-pins/${pinID}`, { method: "PUT", body: original });
    assert.equal(lateWrite.status, 200);
    assert.equal(lateWrite.body.contact_id, contactID);
    assert.equal(Number((await pool.query("SELECT count(*) AS count FROM contacts WHERE company_id=$1 AND id=$2", [companyA, contactID])).rows[0].count), 1);

    const scheduled = await request(`/api/map-pins/${pinID}/contact`, { method: "POST", body: { intent: "schedule" } });
    assert.equal(scheduled.status, 200, JSON.stringify(scheduled.body));
    assert.equal(scheduled.body.contact.id, contactID);
    assert.equal(scheduled.body.pin.status, "won");
    assert.match(scheduled.body.contact.tags, /won/i);
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
    if (pool) await pool.end();
    postgres.stop();
  }
});
