import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { startLocalPostgres } from "./helpers/local-postgres.js";

test("company lead sources retain identities through contact edits, intake, renames and archive", { timeout: 120_000 }, async () => {
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
    await installAutomationSystem({ app: backend.app, pool, authRequired: backend.authRequired,
      requireEmployer: backend.requireCapability("automations.manage"), disableProcessors: true });
    const companyA = randomUUID(), companyB = randomUUID();
    const ownerA = randomUUID(), ownerB = randomUUID();
    await pool.query("INSERT INTO companies(id,name,join_code) VALUES($1,'Sources A','SOURCES-A'),($2,'Sources B','SOURCES-B')", [companyA, companyB]);
    await pool.query("INSERT INTO users(id,email,role,company_id) VALUES($1,'sources-a@example.invalid','employer',$3),($2,'sources-b@example.invalid','employer',$4)", [ownerA, ownerB, companyA, companyB]);
    await pool.query("UPDATE companies SET owner_user_id=CASE WHEN id=$1 THEN $3::uuid ELSE $4::uuid END WHERE id IN ($1,$2)", [companyA, companyB, ownerA, ownerB]);
    await pool.query("INSERT INTO sessions(token,user_id) VALUES('sources-owner-a',$1),('sources-owner-b',$2)", [ownerA, ownerB]);
    const webhookToken = "source-test-webhook-token-123";
    await pool.query("INSERT INTO zapier_tokens(user_id,token) VALUES($1,$2)", [ownerA, webhookToken]);
    server = await new Promise((resolve) => {
      const listener = backend.app.listen(0, "127.0.0.1", () => resolve(listener));
    });
    const base = `http://127.0.0.1:${server.address().port}`;
    async function request(path, { token = "sources-owner-a", method = "GET", body, auth = true } = {}) {
      const response = await fetch(base + path, { method,
        headers: { ...(auth ? { authorization: `Bearer ${token}` } : {}), "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body) });
      return { status: response.status, body: response.status === 204 ? null : await response.json() };
    }

    const made = await request("/api/lead-sources", { method: "POST", body: { name: "Neighborhood Flyer" } });
    assert.equal(made.status, 201, JSON.stringify(made.body));
    const sourceID = made.body.id;
    const foreign = await request("/api/contacts", { token: "sources-owner-b", method: "POST", body: { name: "Foreign", lead_source_id: sourceID } });
    assert.equal(foreign.status, 404);
    const contact = await request("/api/contacts", { method: "POST", body: { name: "Flyer Lead", lead_source_id: sourceID } });
    assert.equal(contact.status, 201, JSON.stringify(contact.body));
    assert.deepEqual(contact.body.tags, ["lead"]);
    assert.equal(contact.body.lead_source_id, sourceID);
    assert.equal(contact.body.source, "Neighborhood Flyer");
    const listID = randomUUID();
    await pool.query(
      "INSERT INTO smart_contact_lists(id,company_id,created_by,name,mode,filters) VALUES($1,$2,$3,'Flyer Followups','dynamic',$4::jsonb)",
      [listID, companyA, ownerA, JSON.stringify({ sources: ["neighborhood flyer"] })]
    );
    const renamed = await request(`/api/lead-sources/${sourceID}`, { method: "PUT", body: { name: "Street Flyer" } });
    assert.equal(renamed.status, 200, JSON.stringify(renamed.body));
    const updated = await request(`/api/contacts/${contact.body.id}`);
    assert.deepEqual(updated.body.tags, ["lead"]);
    assert.equal(updated.body.source, "Street Flyer");
    const listed = await request("/api/contacts");
    assert.deepEqual(listed.body.find((row) => row.id === contact.body.id)?.tags, ["lead"]);
    assert.equal(updated.body.lead_source_id, sourceID);
    assert.deepEqual((await pool.query("SELECT filters->'sources' AS sources FROM smart_contact_lists WHERE id=$1", [listID])).rows[0].sources, ["street flyer"]);
    const archived = await request(`/api/lead-sources/${sourceID}`, { method: "DELETE" });
    assert.equal(archived.status, 204);
    assert.equal((await request("/api/lead-sources")).body.some((source) => source.id === sourceID), false);
    assert.equal((await request(`/api/contacts/${contact.body.id}`)).body.lead_source_id, sourceID);
    assert.equal((await request(`/api/contacts/${contact.body.id}`, { token: "sources-owner-b" })).status, 404);
    const cannotReuseArchived = await request("/api/contacts", { method: "POST", body: { name: "New Flyer", lead_source_id: sourceID } });
    assert.equal(cannotReuseArchived.status, 404);

    const zapier = await request(`/webhooks/leads/${webhookToken}`, { method: "POST", auth: false,
      body: { name: "Zapier Lead Person", email: "zapier@example.invalid" } });
    assert.equal(zapier.status, 201, JSON.stringify(zapier.body));
    const facebook = await request(`/webhooks/leads/${webhookToken}`, { method: "POST", auth: false,
      body: { id: "fb-123", name: "Facebook Lead Person", email: "facebook@example.invalid" } });
    assert.equal(facebook.status, 201, JSON.stringify(facebook.body));
    const intake = (await pool.query(
      "SELECT source,source_raw,lead_source_id FROM contacts WHERE id=ANY($1::uuid[]) ORDER BY source_raw",
      [[zapier.body.contact_id, facebook.body.contact_id]]
    )).rows;
    assert.deepEqual(intake.map((row) => [row.source_raw, row.source]),
      [["facebook_zapier", "Facebook Lead"], ["zapier", "Zapier Lead"]]);
    assert.ok(intake.every((row) => row.lead_source_id));

    const start = new Date(Date.now() - 86_400_000).toISOString();
    const end = new Date(Date.now() + 86_400_000).toISOString();
    const report = await request(`/api/sales/analytics?start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}`);
    assert.equal(report.status, 200, JSON.stringify(report.body));
    const flyer = report.body.sources.find((row) => row.id === sourceID);
    assert.equal(flyer?.label, "Street Flyer (archived)");
    assert.equal(flyer?.new_contacts, 1);

    const historicalID = randomUUID();
    await pool.query("INSERT INTO contacts(id,user_id,company_id,name,source) VALUES($1,$2,$3,'Unknown Old Lead','mystery-import')", [historicalID, ownerA, companyA]);
    const { installLeadSourcesSchema } = await import("../lead-sources.js");
    await installLeadSourcesSchema(pool);
    const historical = (await pool.query("SELECT source,source_raw,lead_source_id FROM contacts WHERE id=$1", [historicalID])).rows[0];
    assert.equal(historical.source_raw, "mystery-import");
    assert.equal(historical.source, "mystery-import");
    assert.ok(historical.lead_source_id);
    assert.equal((await pool.query("SELECT name FROM lead_sources WHERE id=$1", [historical.lead_source_id])).rows[0].name, "mystery-import");
    const automationID = randomUUID();
    await pool.query("INSERT INTO contacts(id,user_id,company_id,name,source) VALUES($1,$2,$3,'Automated Contact','website-builder')", [automationID, ownerA, companyA]);
    const automatic = (await pool.query("SELECT source,source_raw,lead_source_id FROM contacts WHERE id=$1", [automationID])).rows[0];
    assert.equal(automatic.source_raw, "website-builder");
    assert.ok(automatic.lead_source_id);
    await installLeadSourcesSchema(pool);
    assert.equal((await pool.query("SELECT archived_at IS NOT NULL AS archived FROM lead_sources WHERE id=$1", [sourceID])).rows[0].archived, true);
    assert.equal((await pool.query("SELECT count(*)::int AS count FROM lead_sources WHERE company_id=$1 AND name='Street Flyer' AND archived_at IS NULL", [companyA])).rows[0].count, 0);
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
    if (pool) await pool.end();
    postgres.stop();
  }
});
