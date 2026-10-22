import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { startLocalPostgres } from "./helpers/local-postgres.js";

test("real PostgreSQL quote and service routes preserve ownership, history, options and amounts", { timeout: 60000 }, async (t) => {
  const postgres = startLocalPostgres();
  postgres.configureEnvironment();
  let pool, server;
  try {
    const backend = await import("../index.js");
    pool = backend.pool;
    await backend.bootstrap();
    const { installGoogleSheetsSchema } = await import("../google-sheets.js");
    await installGoogleSheetsSchema(pool);
    const { installServiceCatalogSchema } = await import("../services-catalog.js");
    const companyA = randomUUID(), companyB = randomUUID();
    const ownerA = randomUUID(), ownerB = randomUUID(), worker = randomUUID();
    const contactA = randomUUID(), contactB = randomUUID();
    await pool.query(`INSERT INTO companies(id,name,join_code) VALUES($1,'Test A','TEST-A'),($2,'Test B','TEST-B')`, [companyA, companyB]);
    await pool.query(`INSERT INTO users(id,email,role,company_id) VALUES($1,'a@example.invalid','employer',$4),($2,'b@example.invalid','employer',$5),($3,'worker@example.invalid','employee',$4)`, [ownerA, ownerB, worker, companyA, companyB]);
    await pool.query('UPDATE companies SET owner_user_id=CASE WHEN id=$1 THEN $3::uuid ELSE $4::uuid END WHERE id IN ($1,$2)',[companyA,companyB,ownerA,ownerB]);
    await pool.query(`INSERT INTO employee_permissions(user_id,company_id,permission_preset) VALUES($1,$2,'technician')`, [worker, companyA]);
    await pool.query(`INSERT INTO sessions(token,user_id) VALUES('owner-a',$1),('owner-b',$2),('worker',$3)`, [ownerA, ownerB, worker]);
    await pool.query(`INSERT INTO contacts(id,user_id,company_id,name) VALUES($1,$3,$5,'Customer A'),($2,$4,$6,'Customer B')`, [contactA, contactB, ownerA, ownerB, companyA, companyB]);
    const historicalQuote = randomUUID();
    const historicalLines = [{ name: "Original service", qty: 2, price_cents: 12345 }];
    await pool.query(`INSERT INTO quotes(id,user_id,company_id,contact_id,line_items,total_cents) VALUES($1,$2,$3,$4,$5::jsonb,24690)`, [historicalQuote, ownerA, companyA, contactA, JSON.stringify(historicalLines)]);
    await installServiceCatalogSchema(pool);
    await installServiceCatalogSchema(pool);
    const historical = (await pool.query("SELECT line_items,total_cents FROM quotes WHERE id=$1", [historicalQuote])).rows[0];
    assert.deepEqual(historical.line_items, historicalLines);
    assert.equal(historical.total_cents, 24690);
    server = await new Promise((resolve) => { const listener = backend.app.listen(0, "127.0.0.1", () => resolve(listener)); });
    const base = `http://127.0.0.1:${server.address().port}`;
    async function request(path, { token = "owner-a", method = "GET", body } = {}) {
      const response = await fetch(base + path, { method, headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
      return { status: response.status, body: await response.json() };
    }
    const serviceID = randomUUID(), presetID = randomUUID();
    const service = { name: "Window cleaning", default_price_cents: 30000, default_description: "Outside glass\n\nScreens excluded", description_presets: [{ id: presetID, name: "Standard", description: "Default wording" }], default_preset_id: presetID };
    await t.test("company catalog create, duplicate names, import and optimistic concurrency", async () => {
      const first = await request(`/api/services/${serviceID}`, { method: "PUT", body: service });
      assert.equal(first.status, 200);
      assert.equal(first.body.plan_eligible, false);
      assert.equal(first.body.default_description, service.default_description);
      const imported = await request("/api/services/import", { method: "POST", body: { services: [{ ...service, id: serviceID, name: "Should not replace", plan_eligible: true }, { ...service, id: randomUUID() }] } });
      assert.equal(imported.status, 200);
      assert.equal(imported.body.length, 2);
      assert.equal(imported.body.find((row) => row.id === serviceID).name, service.name);
      assert.ok(imported.body.every((row) => row.plan_eligible === false));
      const writes = await Promise.all([1, 2].map((value) => request(`/api/services/${serviceID}`, { method: "PUT", body: { ...service, name: `Version ${value}`, expected_version: 1 } })));
      assert.deepEqual(writes.map((result) => result.status).sort(), [200, 409]);
    });
    await t.test("cross-company identifiers and unauthorized mutations are rejected", async () => {
      assert.equal((await request(`/api/services/${serviceID}`, { token: "owner-b", method: "PUT", body: service })).status, 409);
      assert.equal((await request(`/api/services/${serviceID}`, { token: "owner-b", method: "DELETE" })).status, 404);
      assert.equal((await request(`/api/services/${randomUUID()}`, { token: "worker", method: "PUT", body: service })).status, 403);
      assert.deepEqual((await request("/api/services", { token: "owner-b" })).body, []);
      const attempt = await request("/api/services/import", { token: "owner-b", method: "POST", body: { services: [{ ...service, id: randomUUID() }, { ...service, id: serviceID }] } });
      assert.equal(attempt.status, 409);
      assert.deepEqual((await request("/api/services", { token: "owner-b" })).body, []);
      const foreign = await request("/api/quotes", { method: "POST", body: { contact_id: contactB, line_items: [{ name: "Foreign", qty: 1, price_cents: 100 }] } });
      assert.equal(foreign.status, 404);
    });
    let quote;
    const line = { id: randomUUID(), service_id: serviceID, name: "Windows", qty: 2.5, price_cents: 12345, description: "Quote-specific\n\nParagraphs" };
    const options = { duration_minutes: 90, deposit: { type: "percent", value: 2500 }, allow_customer_booking: true, public_notes: "Customer message" };
    await t.test("create and edit preserve quantities, descriptions, options and private notes", async () => {
      const created = await request("/api/quotes", { method: "POST", body: { contact_id: contactA, line_items: [line], quote_options: options, notes: "Private CRM note" } });
      assert.equal(created.status, 201, JSON.stringify(created.body));
      quote = created.body;
      assert.equal(quote.total_cents, 30863);
      assert.equal(quote.line_items[0].description, line.description);
      assert.equal(quote.notes, "Private CRM note");
      assert.equal(quote.quote_options.public_notes, "");
      assert.ok(quote.quote_options.template?.id);
      const update = await request(`/api/quotes/${quote.id}`, { method: "PUT", body: { title: "Updated" } });
      assert.equal(update.status, 200, JSON.stringify(update.body));
      assert.deepEqual(update.body.line_items, quote.line_items);
      assert.deepEqual(update.body.quote_options, quote.quote_options);
      assert.equal(update.body.total_cents, 30863);
      const foreign = await request(`/api/quotes/${quote.id}`, { token: "owner-b", method: "PUT", body: { title: "Hijack" } });
      assert.equal(foreign.status, 404);
      const legacy = await request(`/api/quotes/${historicalQuote}`, { method: "PUT", body: { title: "Legacy edit" } });
      assert.equal(legacy.status, 200, JSON.stringify(legacy.body));
      assert.deepEqual(legacy.body.line_items, historicalLines);
    });
    await t.test("only a quote linked to a completed job is marked finished", async () => {
      const first = await request(`/api/quotes?contact_id=${contactA}`);
      assert.equal(first.status, 200);
      assert.equal(first.body.find((row) => row.id === quote.id).finished_job_at, null);
      await pool.query(`INSERT INTO schedule_events(id,user_id,company_id,title,start_at,end_at,contact_id,quote_id,finished_at)
        VALUES($1,$2,$3,'Completed windows',now()-interval '2 hours',now()-interval '1 hour',$4,$5,now())`,
      [randomUUID(), ownerA, companyA, contactA, quote.id]);
      const linked = await request(`/api/quotes?contact_id=${contactA}`);
      assert.equal(linked.status, 200);
      assert.ok(linked.body.find((row) => row.id === quote.id).finished_job_at);
      assert.equal(linked.body.find((row) => row.id === historicalQuote).finished_job_at, null);
    });
    await t.test("preview uses server tax settings and rejects invalid money and foreign services", async () => {
      await pool.query("INSERT INTO quote_settings(company_id,tax_enabled,tax_rate_basis_points) VALUES($1,true,1000)", [companyA]);
      const preview = await request("/api/quotes/pricing", { method: "POST", body: { line_items: [line], quote_options: options, tax_rate_basis_points: 0 } });
      assert.equal(preview.status, 200);
      assert.equal(preview.body.subtotal_cents, 30863);
      assert.equal(preview.body.tax_cents, 3086);
      assert.equal(preview.body.total_cents, 33949);
      assert.equal(preview.body.deposit_cents, 8487);
      assert.equal((await request("/api/quotes", { method: "POST", body: { contact_id: contactA, line_items: [{ ...line, price_cents: -1 }] } })).status, 400);
      assert.equal((await request("/api/quotes", { method: "POST", body: { contact_id: contactA, line_items: [{ ...line, service_id: randomUUID() }] } })).status, 404);
    });
    await t.test("archive preserves historical quote lines and excludes new selections", async () => {
      assert.equal((await request(`/api/services/${serviceID}`, { method: "DELETE" })).status, 200);
      assert.ok(!(await request("/api/services")).body.some((row) => row.id === serviceID));
      assert.ok((await request("/api/services?include_archived=true")).body.some((row) => row.id === serviceID && row.archived_at));
      const edited = await request(`/api/quotes/${quote.id}`, { method: "PUT", body: { line_items: [line] } });
      assert.equal(edited.status, 200, JSON.stringify(edited.body));
      const savedPricing = await request(`/api/quotes/${quote.id}/pricing`);
      assert.equal(savedPricing.status, 200);
      assert.equal(savedPricing.body.total_cents, 33949);
      assert.equal((await request(`/api/quotes/${quote.id}/pricing`, { token: "owner-b" })).status, 404);
      assert.equal((await request("/api/quotes", { method: "POST", body: { contact_id: contactA, line_items: [line] } })).status, 409);
      assert.equal((await request(`/api/quotes/${quote.id}`, { method: "PUT", body: { line_items: [line, { ...line, id: randomUUID() }] } })).status, 409);
    });
    await t.test("Use Again keeps the finished source and restores only its archived service", async () => {
      const requestKey = randomUUID();
      const created = await request(`/api/quotes/${quote.id}/reuse`, { method: "POST", body: { request_key: requestKey } });
      assert.equal(created.status, 201, JSON.stringify(created.body));
      assert.notEqual(created.body.quote.id, quote.id);
      assert.equal(created.body.quote.status, "draft");
      assert.deepEqual(created.body.quote.line_items, quote.line_items);
      assert.equal(created.body.restored_services, 1);
      assert.equal((await request(`/api/quotes/${quote.id}/reuse`, { method: "POST", body: { request_key: requestKey } })).body.quote.id, created.body.quote.id);
      assert.equal((await request(`/api/quotes/${historicalQuote}/reuse`, { method: "POST", body: { request_key: requestKey } })).status, 409);
      assert.equal((await request(`/api/quotes/${quote.id}/reuse`, { token: "owner-b", method: "POST", body: { request_key: randomUUID() } })).status, 404);
      assert.ok((await request("/api/services")).body.some(row => row.id === serviceID));
      const listed = (await request(`/api/quotes?contact_id=${contactA}`)).body;
      assert.ok(listed.find(row => row.id === quote.id).finished_job_at);
      assert.equal(listed.find(row => row.id === created.body.quote.id).finished_job_at, null);
    });
    await t.test("materials snapshot internal cost separately from customer charge and survive catalog archive", async () => {
      const materialID = randomUUID(), materialLineID = randomUUID();
      const catalog = await request(`/api/quote-materials/${materialID}`, { method: "PUT", body: {
        name: "Stone", unit: "bags", default_cost_per_unit_cents: 1000, default_charge_per_unit_cents: 2500
      } });
      assert.equal(catalog.status, 200, JSON.stringify(catalog.body));
      assert.equal((await request(`/api/quote-materials/${materialID}`, { token: "owner-b", method: "PUT", body: { name: "Foreign" } })).status, 409);
      const materials = [{ id: materialLineID, material_id: materialID, name: "Stone", quantity: 2, unit: "bags",
        cost_mode: "unit", cost_unit_cents: 1000, charge_mode: "unit", charge_unit_cents: 2500 }];
      const created = await request('/api/quotes', { method: 'POST', body: { contact_id: contactA,
        line_items: [{ id: randomUUID(), name: 'Installation', qty: 1, price_cents: 10000 }], materials,
        quote_options: { duration_minutes: 90, material_visibility: 'hidden' } } });
      assert.equal(created.status, 201, JSON.stringify(created.body));
      assert.equal(created.body.total_cents, 15000);
      assert.equal(created.body.materials[0].cost_cents, 2000);
      assert.equal(created.body.materials[0].charge_cents, 5000);
      const priced = await request(`/api/quotes/${created.body.id}/pricing`);
      assert.equal(priced.body.total_cents, 16500);
      assert.ok(!JSON.stringify(priced.body).includes('cost_cents'));
      const jobID = randomUUID();
      const scheduleBody = { title: 'Stone installation', start: '2026-10-22T15:00:00.000Z', end: '2026-10-22T17:00:00.000Z',
        contact_id: contactA, quote_id: created.body.id, sales_user_ids: [ownerA], worker_user_ids: [ownerA] };
      const withoutQuote = await request(`/api/schedule/${randomUUID()}`, { method: 'PUT', body: { ...scheduleBody, quote_id: null } });
      assert.equal(withoutQuote.body.error, 'schedule_quote_required');
      const withoutSales = await request(`/api/schedule/${randomUUID()}`, { method: 'PUT', body: { ...scheduleBody, sales_user_ids: [] } });
      assert.equal(withoutSales.body.error, 'schedule_salesperson_required');
      const omittedSales = await request(`/api/schedule/${randomUUID()}`, { method: 'PUT', body: { ...scheduleBody, sales_user_ids: undefined } });
      assert.equal(omittedSales.body.error, 'schedule_salesperson_required');
      const withoutTechnician = await request(`/api/schedule/${randomUUID()}`, { method: 'PUT', body: { ...scheduleBody, worker_user_ids: [] } });
      assert.equal(withoutTechnician.body.error, 'schedule_technician_required');
      const shortDuration = await request(`/api/schedule/${randomUUID()}`, { method: 'PUT', body: { ...scheduleBody, end: '2026-10-22T15:30:00.000Z' } });
      assert.equal(shortDuration.body.error, 'schedule_quote_duration_required');
      const scheduled = await request(`/api/schedule/${jobID}`, { method: 'PUT', body: scheduleBody });
      assert.equal(scheduled.status, 200, JSON.stringify(scheduled.body));
      assert.equal(scheduled.body.quote_material_estimate_cents, 2000);
      assert.equal(scheduled.body.material_cost_cents, null);
      await pool.query('UPDATE schedule_events SET finished_at=now() WHERE id=$1', [jobID]);
      const estimatedRow = (await pool.query('SELECT COALESCE(material_cost_cents,quote_material_estimate_cents) AS cost FROM schedule_events WHERE id=$1', [jobID])).rows[0];
      assert.equal(estimatedRow.cost, 2000);
      await pool.query('UPDATE schedule_events SET material_cost_cents=900 WHERE id=$1', [jobID]);
      const updatedJob = await request(`/api/schedule/${jobID}`, { method: 'PUT', body: scheduleBody });
      assert.equal(updatedJob.status, 200, JSON.stringify(updatedJob.body));
      assert.equal(updatedJob.body.quote_material_estimate_cents, 2000);
      assert.equal(updatedJob.body.material_cost_cents, 900);
      const actualRow = (await pool.query('SELECT COALESCE(material_cost_cents,quote_material_estimate_cents) AS cost FROM schedule_events WHERE id=$1', [jobID])).rows[0];
      assert.equal(actualRow.cost, 900);
      assert.equal((await request(`/api/quote-materials/${materialID}`, { method: 'DELETE' })).status, 200);
      assert.equal((await request('/api/quote-materials')).body.some(row => row.id === materialID), false);
      assert.equal((await request('/api/quotes', { method: 'POST', body: { contact_id: contactA, line_items: [], materials } })).status, 409);
      const saved = await request(`/api/quotes/${created.body.id}`, { method: 'PUT', body: { materials } });
      assert.equal(saved.status, 200, JSON.stringify(saved.body));
      assert.equal(saved.body.materials[0].cost_cents, 2000);
      assert.equal((await request(`/api/quote-materials?include_archived=true`, { token: "owner-b" })).body.length, 0);
    });
    await t.test("company inclusive tax and one-time discount flow through saved pricing while partial patches preserve new fields",async()=>{
      const settings=await request('/api/quotes/settings',{method:'PATCH',body:{tax_inclusive:true,discount_stacking_policy:'quote_then_plan'}});assert.equal(settings.status,200,JSON.stringify(settings.body));assert.equal(settings.body.tax_enabled,true);assert.equal(settings.body.tax_rate_basis_points,1000);assert.equal(settings.body.tax_inclusive,true);assert.ok(settings.body.updated_at);
      const discount={type:'percent',value:1000};const updated=await request(`/api/quotes/${quote.id}`,{method:'PUT',body:{quote_options:{discount}}});assert.equal(updated.status,200,JSON.stringify(updated.body));assert.equal(updated.body.quote_options.duration_minutes,90);assert.deepEqual(updated.body.quote_options.deposit,options.deposit);
      const legacy=await request(`/api/quotes/${quote.id}`,{method:'PUT',body:{quote_options:{allow_customer_booking:true,public_notes:'Old client edit'}}});assert.equal(legacy.status,200,JSON.stringify(legacy.body));assert.deepEqual(legacy.body.quote_options.discount,discount);
      const saved=(await request(`/api/quotes/${quote.id}/pricing`)).body;assert.equal(saved.subtotal_cents,30863);assert.equal(saved.discount_cents,3086);assert.equal(saved.total_cents,27777);assert.equal(saved.tax_cents,2525);assert.equal(saved.deposit_cents,6944);assert.equal(saved.tax_inclusive,true);
      const preview=await request('/api/quotes/pricing',{method:'POST',body:{quote_id:quote.id,line_items:[line],quote_options:legacy.body.quote_options,tax_inclusive:false}});assert.equal(preview.status,200);assert.equal(preview.body.total_cents,saved.total_cents);
      assert.equal((await request('/api/quotes/settings',{token:'worker',method:'PATCH',body:{tax_inclusive:false}})).status,403);
      assert.equal((await request('/api/quotes/settings',{method:'PATCH',body:{discount_stacking_policy:'silent-double-discount'}})).status,400);
      assert.equal((await request('/api/quotes/settings',{method:'PATCH',body:{tax_inclusive:'true'}})).status,400);
      const partial=(await request('/api/quotes/settings',{method:'PATCH',body:{tagline:'Only change text'}})).body;assert.equal(partial.tax_inclusive,true);assert.equal(partial.discount_stacking_policy,'quote_then_plan');
    });
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
    if (pool) await pool.end();
    postgres.stop();
  }
});
