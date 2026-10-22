import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { startLocalPostgres } from "./helpers/local-postgres.js";

test("measurements stay with their verified user and company while legacy rows remain quarantined", { timeout: 180000 }, async () => {
  const postgres = startLocalPostgres();
  postgres.configureEnvironment();
  let backend;
  let server;
  try {
    backend = await import("../index.js");
    await backend.bootstrap();
    const { pool, app } = backend;
    const userID = randomUUID();
    const otherUserID = randomUUID();
    const companyA = randomUUID();
    const companyB = randomUUID();
    const token = randomUUID();
    const otherToken = randomUUID();
    await pool.query(
      `INSERT INTO companies(id, name, join_code, owner_user_id)
       VALUES ($1, 'Measure A', $3, $2), ($4, 'Measure B', $5, $2)`,
      [companyA, userID, `MEAS${randomUUID().slice(0, 8)}`, companyB, `MEAS${randomUUID().slice(0, 8)}`]
    );
    await pool.query(
      `INSERT INTO users(id, email, role, company_id) VALUES
       ($1, 'measure-owner@example.invalid', 'employer', $2),
       ($3, 'measure-other@example.invalid', 'employer', NULL)`,
      [userID, companyA, otherUserID]
    );
    await pool.query("INSERT INTO sessions(token, user_id) VALUES ($1, $2), ($3, $4)", [token, userID, otherToken, otherUserID]);
    server = await new Promise((resolve) => {
      const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
    });
    const base = `http://127.0.0.1:${server.address().port}`;
    const request = async (path, { method = "GET", body, bearer = token } = {}) => {
      const response = await fetch(base + path, {
        method,
        headers: { authorization: `Bearer ${bearer}`, "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body)
      });
      const raw = await response.text();
      return { status: response.status, body: raw ? JSON.parse(raw) : null };
    };
    const value = (name) => ({ name, points: [{ lat: 39, lng: -98 }], linked_contact_ids: [], units: "feet" });
    const ids = { legacy: randomUUID(), a: randomUUID(), b: randomUUID(), personal: randomUUID() };

    await pool.query(
      "INSERT INTO measurements(id, user_id, name, points) VALUES ($1, $2, 'Unattributed', '[]'::jsonb)",
      [ids.legacy, userID]
    );
    assert.deepEqual((await request("/api/measurements")).body, []);
    assert.equal((await request(`/api/measurements/${ids.legacy}`, { method: "PUT", body: value("Claim attempt") })).status, 409);
    assert.equal((await request(`/api/measurements/${ids.legacy}`, { method: "DELETE" })).status, 204);
    assert.equal((await pool.query("SELECT scope_verified FROM measurements WHERE id = $1", [ids.legacy])).rows[0].scope_verified, false);

    assert.equal((await request(`/api/measurements/${ids.a}`, { method: "PUT", body: value("Company A") })).status, 200);
    assert.deepEqual((await request("/api/measurements")).body.map((item) => item.id), [ids.a]);
    assert.equal((await request("/api/measurements", { bearer: otherToken })).body.length, 0);
    const savedA = (await pool.query("SELECT company_id, scope_verified FROM measurements WHERE id = $1", [ids.a])).rows[0];
    assert.equal(savedA.company_id, companyA);
    assert.equal(savedA.scope_verified, true);

    await pool.query("UPDATE users SET company_id = $2 WHERE id = $1", [userID, companyB]);
    assert.deepEqual((await request("/api/measurements")).body, []);
    assert.equal((await request(`/api/measurements/${ids.a}`, { method: "PUT", body: value("Cross-company overwrite") })).status, 409);
    assert.equal((await request(`/api/measurements/${ids.a}`, { method: "DELETE" })).status, 204);
    assert.equal((await pool.query("SELECT name FROM measurements WHERE id = $1", [ids.a])).rows[0].name, "Company A");
    assert.equal((await request(`/api/measurements/${ids.b}`, { method: "PUT", body: value("Company B") })).status, 200);
    assert.deepEqual((await request("/api/measurements")).body.map((item) => item.id), [ids.b]);

    await pool.query("UPDATE users SET company_id = NULL WHERE id = $1", [userID]);
    assert.deepEqual((await request("/api/measurements")).body, []);
    assert.equal((await request(`/api/measurements/${ids.personal}`, { method: "PUT", body: value("Personal") })).status, 200);
    const personal = (await pool.query("SELECT company_id, scope_verified FROM measurements WHERE id = $1", [ids.personal])).rows[0];
    assert.equal(personal.company_id, null);
    assert.equal(personal.scope_verified, true);
    assert.deepEqual((await request("/api/measurements")).body.map((item) => item.id), [ids.personal]);

    await pool.query("UPDATE users SET company_id = $2 WHERE id = $1", [userID, companyA]);
    assert.deepEqual((await request("/api/measurements")).body.map((item) => item.id), [ids.a]);
    assert.equal((await request(`/api/measurements/${ids.a}`, { method: "PUT", body: value("Company A updated") })).status, 200);
    assert.equal((await request(`/api/measurements/${ids.a}`, { method: "DELETE" })).status, 204);
    assert.deepEqual((await request("/api/measurements")).body, []);
    assert.equal((await pool.query("SELECT count(*)::int AS n FROM measurements WHERE id = ANY($1::text[])", [[ids.legacy, ids.b, ids.personal]])).rows[0].n, 3);
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
    if (backend) await backend.pool.end();
    postgres.stop();
  }
});
