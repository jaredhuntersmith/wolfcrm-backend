import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { startLocalPostgres } from "./helpers/local-postgres.js";

test("personal To-Dos remain owned by their creator while legacy assignments survive", { timeout: 120_000 }, async () => {
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
    const { installCommsSchema } = await import("../company-comms/schema.js");
    const { installCollaborationSchema } = await import("../company-comms/collaboration-schema.js");
    const { installStorageSchema } = await import("../media-storage/schema.js");
    await installStorageSchema(pool);
    await installCommsSchema(pool);
    await installCollaborationSchema(pool);
    const { installAutomationSystem, automationTestHooks } = await import("../automations.js");
    await installAutomationSystem({
      app: backend.app, pool, authRequired: backend.authRequired,
      requireEmployer: backend.requireCapability("automations.manage"), disableProcessors: true
    });
    const company = randomUUID();
    const owner = randomUUID();
    const colleague = randomUUID();
    await pool.query("INSERT INTO companies(id,name,join_code) VALUES($1,'Personal Tasks Test','TODO-A')", [company]);
    await pool.query("INSERT INTO users(id,email,role,company_id) VALUES($1,'todo-owner@example.invalid','employer',$3),($2,'todo-colleague@example.invalid','employer',$3)", [owner, colleague, company]);
    await pool.query("UPDATE companies SET owner_user_id=$2 WHERE id=$1", [company, owner]);
    await pool.query("INSERT INTO sessions(token,user_id) VALUES('todo-owner',$1),('todo-colleague',$2)", [owner, colleague]);
    server = await new Promise((resolve) => {
      const listener = backend.app.listen(0, "127.0.0.1", () => resolve(listener));
    });
    const base = `http://127.0.0.1:${server.address().port}`;
    async function request(path, { token = "todo-owner", method = "GET", body } = {}) {
      const response = await fetch(base + path, {
        method, headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body)
      });
      return { status: response.status, body: response.status === 204 ? null : await response.json() };
    }

    const personalID = randomUUID();
    const created = await request(`/api/todo/tasks/${personalID}`, { method: "PUT", body: { title: "Personal task", assignee_ids: [] } });
    assert.equal(created.status, 200, JSON.stringify(created.body));
    assert.deepEqual(created.body.assignee_ids, []);
    assert.equal((await pool.query("SELECT user_id FROM todo_tasks WHERE id=$1", [personalID])).rows[0].user_id, owner);
    assert.deepEqual((await request("/api/todo/tasks", { token: "todo-colleague" })).body, []);
    const foreignEdit = await request(`/api/todo/tasks/${personalID}`, { token: "todo-colleague", method: "PUT", body: { title: "Changed" } });
    assert.equal(foreignEdit.status, 403);
    const assign = await request(`/api/todo/tasks/${randomUUID()}`, { method: "PUT", body: { title: "Assign colleague", assignee_ids: [colleague] } });
    assert.equal(assign.status, 400);
    assert.equal(assign.body.error, "todo_assignment_not_supported");
    const bulkAssign = await request("/api/smart-contact-lists/actions/tasks", {
      method: "POST",
      body: {
        contact_ids: [randomUUID()], title_template: "Follow up", assignee_ids: [colleague],
        idempotency_key: randomUUID()
      }
    });
    assert.equal(bulkAssign.status, 400);
    assert.equal(bulkAssign.body.error, "personal_task_assignment_not_supported");
    const run = { id: randomUUID(), company_id: company, manual_started_by_user_id: owner };
    const node = { id: randomUUID() };
    const actions = automationTestHooks.actionExecutors();
    await assert.rejects(
      actions["task.create"](run, node, { title: "Other person's task", assigned_user_id: colleague }),
      /personal_task_assignment_not_supported/
    );
    await assert.rejects(
      actions["task.update"](run, node, { task_id: personalID, assigned_user_id: colleague }),
      /personal_task_assignment_not_supported/
    );
    await assert.rejects(actions["task.assign"](run, node, { task_id: personalID, assigned_user_id: colleague }), /personal_task_assignment_not_supported/);
    await assert.rejects(actions["task.unassign"](run, node, { task_id: personalID }), /personal_task_assignment_not_supported/);
    await assert.rejects(actions["employee.create_task"](run, node, { employee_id: colleague }), /personal_task_assignment_not_supported/);
    const colleagueTaskID = randomUUID();
    await pool.query("INSERT INTO todo_tasks(id,user_id,title) VALUES($1,$2,'Colleague personal task')", [colleagueTaskID, colleague]);
    await assert.rejects(actions["task.complete"](run, node, { task_id: colleagueTaskID }), /task_not_found/);
    assert.equal((await pool.query("SELECT completed FROM todo_tasks WHERE id=$1", [colleagueTaskID])).rows[0].completed, false);

    const legacyID = randomUUID();
    await pool.query(
      "INSERT INTO todo_tasks(id,user_id,title,creator_id,assignee_ids) VALUES($1,$2,'Legacy assigned',$2,$3::jsonb)",
      [legacyID, owner, JSON.stringify([colleague])]
    );
    assert.deepEqual((await request("/api/todo/tasks", { token: "todo-colleague" })).body.map((task) => task.id), [colleagueTaskID]);
    const edited = await request(`/api/todo/tasks/${legacyID}`, { method: "PUT", body: { title: "Legacy edited", assignee_ids: [colleague] } });
    assert.equal(edited.status, 200, JSON.stringify(edited.body));
    assert.deepEqual(edited.body.assignee_ids, [colleague]);
    const changedAudience = await request(`/api/todo/tasks/${legacyID}`, { method: "PUT", body: { title: "Try reassignment", assignee_ids: [] } });
    assert.equal(changedAudience.status, 400);
    assert.deepEqual((await pool.query("SELECT assignee_ids FROM todo_tasks WHERE id=$1", [legacyID])).rows[0].assignee_ids, [colleague]);
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
    if (pool) await pool.end();
    postgres.stop();
  }
});
