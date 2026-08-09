import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;

function refuse(message) {
  console.error(message);
  process.exit(2);
}

if (!TEST_DATABASE_URL) refuse("TEST_DATABASE_URL is required.");
if (process.env.DATABASE_URL && process.env.DATABASE_URL !== TEST_DATABASE_URL) {
  refuse("Refusing to run: DATABASE_URL is set separately from TEST_DATABASE_URL.");
}
if (!/test|local|dev|localhost|127\.0\.0\.1/i.test(TEST_DATABASE_URL)) {
  refuse("Refusing to run: TEST_DATABASE_URL must clearly identify a test/local/dev database.");
}
if (/railway|render|supabase|neon|amazonaws|prod|production/i.test(TEST_DATABASE_URL)) {
  refuse("Refusing to run: TEST_DATABASE_URL looks like a hosted or production database.");
}

process.env.NODE_ENV = "test";
process.env.WOLFCRM_SKIP_SERVER_START = "true";
process.env.DATABASE_URL = TEST_DATABASE_URL;
process.env.DB_SSL = "false";

const pg = await import("pg");
const { Pool } = pg.default;
const pool = new Pool({ connectionString: TEST_DATABASE_URL, ssl: false });

const {
  installAutomationSystem,
  emitAutomationEvent,
  syncAutomationSchedulesForJob,
  syncAutomationSchedulesForServicePlan,
  automationTestHooks
} = await import("../automations.js");

const backend = await import("../index.js");

const state = {
  smsMode: "accept",
  smsCalls: [],
  pushCalls: [],
  stripeCalls: []
};

const fakeApp = {
  get() {},
  post() {},
  put() {},
  patch() {},
  delete() {}
};

function authNoop(_req, _res, next) {
  if (typeof next === "function") next();
}

function fakeTwilioClient() {
  return {
    messages: {
      create: async (payload) => {
        state.smsCalls.push(payload);
        if (state.smsMode === "reject") {
          const error = new Error("Mock Twilio rejected outbound SMS");
          error.code = "twilio_rejected";
          throw error;
        }
        return {
          sid: `SM_TEST_${randomUUID().replace(/-/g, "")}`,
          status: "queued",
          ...payload
        };
      }
    }
  };
}

function fakeStripe() {
  return {
    paymentIntents: {
      create: async (payload) => {
        state.stripeCalls.push({ type: "paymentIntent.create", payload });
        return { id: `pi_test_${randomUUID().replace(/-/g, "")}`, client_secret: "pi_test_secret", status: "requires_payment_method" };
      }
    },
    checkout: {
      sessions: {
        create: async (payload) => {
          state.stripeCalls.push({ type: "checkout.session.create", payload });
          return { id: `cs_test_${randomUUID().replace(/-/g, "")}`, url: "https://example.test/pay" };
        }
      }
    }
  };
}

function twilioPublicUrl(path = "") {
  return `https://wolfcrm.test${path}`;
}

async function sendPushToUsers(userIds, category, options) {
  state.pushCalls.push({ userIds, category, options });
  return { sent: userIds.length, failed: 0, skipped: false };
}

async function bootstrapSchema() {
  await backend.bootstrap();
  await installAutomationSystem({
    app: fakeApp,
    pool,
    authRequired: authNoop,
    requireEmployer: authNoop,
    sendPushToUsers,
    createTwilioClient: fakeTwilioClient,
    twilioPublicUrl,
    getStripe: fakeStripe,
    disableProcessors: true
  });
}

async function resetDatabase() {
  const { rows } = await pool.query(`
    SELECT tablename
      FROM pg_tables
     WHERE schemaname = 'public'
       AND tablename NOT LIKE 'pg_%'
  `);
  if (!rows.length) return;
  const names = rows.map((r) => `"public"."${r.tablename.replace(/"/g, '""')}"`).join(", ");
  await pool.query(`TRUNCATE ${names} RESTART IDENTITY CASCADE`);
}

async function scalar(sql, params = []) {
  const { rows } = await pool.query(sql, params);
  return rows[0];
}

async function rows(sql, params = []) {
  return (await pool.query(sql, params)).rows;
}

function testName(name) {
  return `AUTOMATION_TEST_${name}_${randomUUID().slice(0, 8)}`;
}

async function seedCompany() {
  const companyId = randomUUID();
  const userId = randomUUID();
  await pool.query(
    `INSERT INTO companies(id, name, join_code, automations_enabled, automated_customer_messages_enabled)
     VALUES($1,$2,$3,true,true)`,
    [companyId, testName("Company"), `AUTO${randomUUID().slice(0, 8)}`]
  );
  await pool.query(
    `INSERT INTO users(id, email, role, company_id, display_name)
     VALUES($1,$2,'employer',$3,$4)`,
    [userId, `${randomUUID()}@automation.test`, companyId, "Automation Test Owner"]
  );
  await pool.query(`UPDATE companies SET owner_user_id = $1 WHERE id = $2`, [userId, companyId]);
  await pool.query(
    `INSERT INTO phone_lines(company_id, phone_number, twilio_phone_number_sid, status, active)
     VALUES($1,$2,$3,'active',true)`,
    [companyId, `+1555${String(Math.floor(Math.random() * 10000000)).padStart(7, "0")}`, `PN_TEST_${randomUUID().replace(/-/g, "")}`]
  );
  const stageId = `stage_${randomUUID()}`;
  await pool.query(
    `INSERT INTO stages(id, user_id, company_id, name, order_idx)
     VALUES($1,$2,$3,'Contacted - No Answer',1)`,
    [stageId, userId, companyId]
  );
  return { companyId, userId, stageId };
}

async function createContact(seed, attrs = {}) {
  const id = attrs.id || randomUUID();
  await pool.query(
    `INSERT INTO contacts(id, user_id, company_id, name, phone, email, address, tags)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
    [
      id,
      seed.userId,
      seed.companyId,
      attrs.name || testName("Contact"),
      attrs.phone || "6062131071",
      attrs.email || null,
      attrs.address || "100 Test Way",
      attrs.tags || ""
    ]
  );
  return id;
}

async function emitContactCreated(seed, contactId, dedupeKey = `contact.created:${contactId}`) {
  return emitAutomationEvent({
    companyId: seed.companyId,
    eventType: "contact.created",
    subjectType: "contact",
    subjectId: contactId,
    actorUserId: seed.userId,
    source: "test",
    dedupeKey,
    payload: { contact_id: contactId }
  });
}

async function createJob(seed, contactId, attrs = {}) {
  const id = randomUUID();
  const start = attrs.start || new Date(Date.now() + 3600000).toISOString();
  const end = attrs.end || new Date(Date.now() + 7200000).toISOString();
  await pool.query(
    `INSERT INTO schedule_events(id, user_id, company_id, created_by, title, start_at, end_at, color, contact_id, reminder_minutes, services, service_items, sales_user_ids, worker_user_ids)
     VALUES($1,$2,$3,$2,$4,$5,$6,'#3478F6',$7,'[]'::jsonb,'[]'::jsonb,'[]'::jsonb,'[]'::jsonb,'[]'::jsonb)`,
    [id, seed.userId, seed.companyId, attrs.title || "Automation Test Job", start, end, contactId]
  );
  return id;
}

async function createTask(seed, attrs = {}) {
  const id = randomUUID();
  await pool.query(
    `INSERT INTO todo_tasks(id, user_id, title, due_date, reminders, subtasks, completed, color_hex)
     VALUES($1,$2,$3,$4::timestamptz,'[]'::jsonb,'[]'::jsonb,false,'#3478F6')`,
    [id, seed.userId, attrs.title || "Automation Test Task", attrs.due || null]
  );
  return id;
}

async function createAutomation(seed, graph, metadata = {}) {
  const automationId = randomUUID();
  const draftId = randomUUID();
  await pool.query(
    `INSERT INTO automation_definitions(id, company_id, name, description, status, allow_manual_trigger, metadata, created_by_user_id, updated_by_user_id)
     VALUES($1,$2,$3,'Integration test automation','draft',true,$4::jsonb,$5,$5)`,
    [automationId, seed.companyId, testName("Automation"), JSON.stringify({ reentry_mode: "after_previous_completion", ...metadata }), seed.userId]
  );
  await pool.query(
    `INSERT INTO automation_versions(id, automation_id, company_id, version_number, status, created_by_user_id)
     VALUES($1,$2,$3,1,'draft',$4)`,
    [draftId, automationId, seed.companyId, seed.userId]
  );
  await pool.query(`UPDATE automation_definitions SET draft_version_id = $1 WHERE id = $2`, [draftId, automationId]);
  await automationTestHooks.saveDraftGraph(draftId, seed.companyId, graph);
  return { automationId, draftId };
}

function node(node_key, node_type, config, title = node_key) {
  return {
    id: randomUUID(),
    node_key,
    node_type,
    title,
    config,
    position_x: 0,
    position_y: 0
  };
}

function edge(source, target, port = "default") {
  return {
    id: randomUUID(),
    source_node_id: source.id,
    target_node_id: target.id,
    source_port: port,
    target_port: null,
    priority: 0,
    config: {}
  };
}

function graphFrom(nodes, edges, settings = {}) {
  return { nodes, edges, settings };
}

async function publish(seed, automationId) {
  const result = await automationTestHooks.publishAutomation(automationId, seed.companyId, seed.userId);
  assert.equal(result?.valid, true, JSON.stringify(result));
  return result;
}

async function processAll() {
  for (let i = 0; i < 6; i += 1) {
    await automationTestHooks.processAutomationEvents();
    await automationTestHooks.processDueWaits();
    await automationTestHooks.processScheduledAutomationEvents();
  }
}

async function waitForRuns(seed, automationId, expected, label) {
  await processAll();
  const found = await rows(
    `SELECT * FROM automation_runs WHERE company_id = $1 AND automation_id = $2 ORDER BY created_at ASC`,
    [seed.companyId, automationId]
  );
  assert.equal(found.length, expected, `${label}: expected ${expected} runs, got ${found.length}`);
  return found;
}

async function assertRunCompleted(runId) {
  await processAll();
  const run = await scalar(`SELECT status FROM automation_runs WHERE id = $1`, [runId]);
  assert.equal(run.status, "completed");
}

async function runEventAutomation(seed, graph, contactId = null) {
  const created = await createAutomation(seed, graph);
  await publish(seed, created.automationId);
  const subjectId = contactId || await createContact(seed);
  const eventId = await emitContactCreated(seed, subjectId);
  assert.ok(eventId, "contact.created event should be persisted");
  const runs = await waitForRuns(seed, created.automationId, 1, "event automation");
  return { ...created, run: runs[0], contactId: subjectId, eventId };
}

async function testPublishAndRepublish() {
  const seed = await seedCompany();
  const t = node("trigger_1", "trigger", { trigger_key: "contact.created" });
  const a = node("tag_1", "action", { action_key: "contact.add_tag", target_mode: "current_contact", tags: ["Automation Test"] });
  const created = await createAutomation(seed, graphFrom([t, a], [edge(t, a)]));
  const first = await publish(seed, created.automationId);
  assert.equal(first.published_version.version_number, 2);
  assert.equal(first.draft_version.version_number, 3);
  let def = await scalar(`SELECT active_version_id, draft_version_id, status FROM automation_definitions WHERE id = $1`, [created.automationId]);
  assert.equal(def.active_version_id, first.published_version.id);
  assert.equal(def.draft_version_id, first.draft_version.id);
  assert.equal(def.status, "published");
  const t2 = node("trigger_1", "trigger", { trigger_key: "contact.created" });
  const a2 = node("tag_1", "action", { action_key: "contact.add_tag", target_mode: "current_contact", tags: ["Automation Test Edited"] });
  await automationTestHooks.saveDraftGraph(first.draft_version.id, seed.companyId, graphFrom([t2, a2], [edge(t2, a2)]));
  const second = await publish(seed, created.automationId);
  assert.equal(second.published_version.version_number, 4);
  assert.equal(second.draft_version.version_number, 5);
}

async function testDraftDoesNotRun() {
  const seed = await seedCompany();
  const t = node("trigger_1", "trigger", { trigger_key: "contact.created" });
  const a = node("tag_1", "action", { action_key: "contact.add_tag", target_mode: "current_contact", tags: ["Draft Should Not Run"] });
  const created = await createAutomation(seed, graphFrom([t, a], [edge(t, a)]));
  const contact1 = await createContact(seed);
  await emitContactCreated(seed, contact1);
  await processAll();
  assert.equal((await scalar(`SELECT COUNT(*)::int AS count FROM automation_runs WHERE automation_id = $1`, [created.automationId])).count, 0);
  await publish(seed, created.automationId);
  const contact2 = await createContact(seed);
  await emitContactCreated(seed, contact2);
  const runs = await waitForRuns(seed, created.automationId, 1, "published draft-not-live");
  await assertRunCompleted(runs[0].id);
}

async function testDraftRunSafety() {
  const seed = await seedCompany();
  const contactId = await createContact(seed);
  const t = node("trigger_1", "trigger", { trigger_key: "contact.created" });
  const tag = node("tag_1", "action", { action_key: "contact.add_tag", target_mode: "current_contact", tags: ["Dry Run Tag"] });
  const pipe = node("pipe_1", "action", { action_key: "pipeline.move_stage", target_mode: "current_contact", stage_id: seed.stageId, if_missing: "create" });
  const sms = node("sms_1", "action", { action_key: "sms.send", target_mode: "current_contact", body: "Dry run" });
  const created = await createAutomation(seed, graphFrom([t, tag, pipe, sms], [edge(t, tag), edge(tag, pipe), edge(pipe, sms)]));
  state.smsCalls = [];
  const run = await automationTestHooks.startDraftTestRun(created.automationId, seed.companyId, seed.userId, {
    subject_type: "contact",
    subject_id: contactId,
    trigger_key: "contact.created",
    payload: { contact_id: contactId }
  });
  await automationTestHooks.runAutomation(run.id);
  await assertRunCompleted(run.id);
  assert.equal((await scalar(`SELECT tags FROM contacts WHERE id = $1`, [contactId])).tags || "", "");
  assert.equal((await scalar(`SELECT COUNT(*)::int AS count FROM opportunities WHERE company_id = $1 AND contact_id = $2`, [seed.companyId, contactId])).count, 0);
  assert.equal(state.smsCalls.length, 0);
  const dryNodes = await rows(`SELECT output_snapshot FROM automation_run_nodes WHERE run_id = $1 AND node_key IN ('tag_1','pipe_1','sms_1')`, [run.id]);
  assert.equal(dryNodes.length, 3);
  assert.ok(dryNodes.every((r) => r.output_snapshot?.would_execute));
}

async function testContactToTag() {
  const seed = await seedCompany();
  const t = node("trigger_1", "trigger", { trigger_key: "contact.created" });
  const a = node("tag_1", "action", { action_key: "contact.add_tag", target_mode: "current_contact", tags: ["Automation Test"] });
  const { run, contactId } = await runEventAutomation(seed, graphFrom([t, a], [edge(t, a)]));
  await assertRunCompleted(run.id);
  assert.match((await scalar(`SELECT tags FROM contacts WHERE id = $1`, [contactId])).tags, /Automation Test/);
  const out = await scalar(`SELECT output_snapshot FROM automation_run_nodes WHERE run_id = $1 AND node_key = 'tag_1'`, [run.id]);
  assert.equal(out.output_snapshot.contact_id, contactId);
}

async function testContactToPipeline() {
  const seed = await seedCompany();
  const t = node("trigger_1", "trigger", { trigger_key: "contact.created" });
  const a = node("pipe_1", "action", { action_key: "pipeline.move_stage", target_mode: "current_contact", stage_id: seed.stageId, if_missing: "create" });
  const { run, contactId } = await runEventAutomation(seed, graphFrom([t, a], [edge(t, a)]));
  await assertRunCompleted(run.id);
  const opps = await rows(`SELECT * FROM opportunities WHERE company_id = $1 AND contact_id = $2`, [seed.companyId, contactId]);
  assert.equal(opps.length, 1);
  assert.equal(opps[0].stage_id, seed.stageId);
}

async function testContactToSms() {
  const seed = await seedCompany();
  const t = node("trigger_1", "trigger", { trigger_key: "contact.created" });
  const a = node("sms_1", "action", { action_key: "sms.send", target_mode: "current_contact", body: "Automation Test" });
  state.smsMode = "accept";
  state.smsCalls = [];
  const { run, contactId } = await runEventAutomation(seed, graphFrom([t, a], [edge(t, a)]));
  await assertRunCompleted(run.id);
  assert.equal(state.smsCalls.length, 1);
  assert.equal(state.smsCalls[0].to, "+16062131071");
  const msg = await scalar(`SELECT * FROM sms_messages ORDER BY created_at DESC LIMIT 1`);
  assert.ok(msg.twilio_message_sid?.startsWith("SM_TEST_"));
  const out = await scalar(`SELECT output_snapshot FROM automation_run_nodes WHERE run_id = $1 AND node_key = 'sms_1'`, [run.id]);
  assert.equal(out.output_snapshot.to_number, "+16062131071");
  assert.ok(contactId);
}

async function testExactWorkflow() {
  const seed = await seedCompany();
  const t = node("trigger_1", "trigger", { trigger_key: "contact.created" });
  const sms = node("sms_1", "action", { action_key: "sms.send", target_mode: "current_contact", body: "Hey man" });
  const pipe = node("pipe_1", "action", { action_key: "pipeline.move_stage", target_mode: "current_contact", stage_id: seed.stageId, if_missing: "create" });
  state.smsMode = "accept";
  state.smsCalls = [];
  const { run, contactId } = await runEventAutomation(seed, graphFrom([t, sms, pipe], [edge(t, sms), edge(sms, pipe)]));
  await assertRunCompleted(run.id);
  assert.equal((await scalar(`SELECT COUNT(*)::int AS count FROM automation_events WHERE event_type = 'contact.created' AND subject_id = $1`, [contactId])).count, 1);
  assert.equal(run.subject_id, contactId);
  assert.equal(state.smsCalls.length, 1);
  assert.equal(state.smsCalls[0].to, "+16062131071");
  const nodeRows = await rows(`SELECT node_key, status, output_snapshot, started_at FROM automation_run_nodes WHERE run_id = $1 ORDER BY started_at ASC`, [run.id]);
  assert.deepEqual(nodeRows.map((r) => r.node_key), ["trigger_1", "sms_1", "pipe_1"]);
  assert.equal(nodeRows[1].status, "completed");
  assert.equal(nodeRows[2].status, "completed");
  const opps = await rows(`SELECT * FROM opportunities WHERE company_id = $1 AND contact_id = $2`, [seed.companyId, contactId]);
  assert.equal(opps.length, 1);
  assert.equal(opps[0].stage_id, seed.stageId);
}

async function testInitialSmsFailureAndErrorPath() {
  const seed = await seedCompany();
  const t = node("trigger_1", "trigger", { trigger_key: "contact.created" });
  const sms = node("sms_1", "action", { action_key: "sms.send", target_mode: "current_contact", body: "Fail", on_error: "error_path" });
  const success = node("tag_1", "action", { action_key: "contact.add_tag", target_mode: "current_contact", tags: ["Should Not Exist"] });
  const err = node("task_1", "action", { action_key: "task.create", title: "SMS failed" });
  state.smsMode = "reject";
  const { run, contactId } = await runEventAutomation(seed, graphFrom([t, sms, success, err], [edge(t, sms), edge(sms, success), edge(sms, err, "error")]));
  await assertRunCompleted(run.id);
  assert.doesNotMatch((await scalar(`SELECT tags FROM contacts WHERE id = $1`, [contactId])).tags || "", /Should Not Exist/);
  assert.equal((await scalar(`SELECT COUNT(*)::int AS count FROM todo_tasks WHERE title = 'SMS failed'`, [])).count, 1);
  const failed = await scalar(`SELECT status FROM automation_run_nodes WHERE run_id = $1 AND node_key = 'sms_1'`, [run.id]);
  assert.equal(failed.status, "failed");
  state.smsMode = "accept";
}

async function testSmsFailureStopsDefaultPath() {
  const seed = await seedCompany();
  const t = node("trigger_1", "trigger", { trigger_key: "contact.created" });
  const sms = node("sms_1", "action", { action_key: "sms.send", target_mode: "current_contact", body: "Fail" });
  const pipe = node("pipe_1", "action", { action_key: "pipeline.move_stage", target_mode: "current_contact", stage_id: seed.stageId, if_missing: "create" });
  state.smsMode = "reject";
  const { run, contactId } = await runEventAutomation(seed, graphFrom([t, sms, pipe], [edge(t, sms), edge(sms, pipe)]));
  const latest = await scalar(`SELECT status FROM automation_runs WHERE id = $1`, [run.id]);
  assert.equal(latest.status, "failed");
  assert.equal((await scalar(`SELECT COUNT(*)::int AS count FROM opportunities WHERE company_id = $1 AND contact_id = $2`, [seed.companyId, contactId])).count, 0);
  state.smsMode = "accept";
}

async function testLaterSmsUndeliveredDoesNotRollbackRun() {
  const seed = await seedCompany();
  const t = node("trigger_1", "trigger", { trigger_key: "contact.created" });
  const sms = node("sms_1", "action", { action_key: "sms.send", target_mode: "current_contact", body: "Accepted" });
  const pipe = node("pipe_1", "action", { action_key: "pipeline.move_stage", target_mode: "current_contact", stage_id: seed.stageId, if_missing: "create" });
  const { run } = await runEventAutomation(seed, graphFrom([t, sms, pipe], [edge(t, sms), edge(sms, pipe)]));
  await assertRunCompleted(run.id);
  const msg = await scalar(`SELECT * FROM sms_messages ORDER BY created_at DESC LIMIT 1`);
  await pool.query(`UPDATE sms_messages SET message_status = 'undelivered', twilio_error_code = '30007' WHERE id = $1`, [msg.id]);
  await emitAutomationEvent({
    companyId: seed.companyId,
    eventType: "sms.undelivered",
    subjectType: "sms_message",
    subjectId: msg.id,
    source: "test",
    dedupeKey: `sms.undelivered:${msg.id}`,
    payload: { message_id: msg.id, status: "undelivered" }
  });
  await processAll();
  assert.equal((await scalar(`SELECT status FROM automation_runs WHERE id = $1`, [run.id])).status, "completed");
  assert.equal((await scalar(`SELECT status FROM automation_run_nodes WHERE run_id = $1 AND node_key = 'pipe_1'`, [run.id])).status, "completed");
}

async function testPipelineIdempotency() {
  const seed = await seedCompany();
  const contactId = await createContact(seed);
  const t = node("trigger_1", "trigger", { trigger_key: "contact.created" });
  const p1 = node("pipe_1", "action", { action_key: "pipeline.move_stage", target_mode: "current_contact", stage_id: seed.stageId, if_missing: "create" });
  const p2 = node("pipe_2", "action", { action_key: "pipeline.move_stage", target_mode: "current_contact", stage_id: seed.stageId, if_missing: "create" });
  const created = await createAutomation(seed, graphFrom([t, p1, p2], [edge(t, p1), edge(p1, p2)]));
  await publish(seed, created.automationId);
  await emitContactCreated(seed, contactId);
  const [run] = await waitForRuns(seed, created.automationId, 1, "pipeline idempotency");
  await assertRunCompleted(run.id);
  assert.equal((await scalar(`SELECT COUNT(*)::int AS count FROM opportunities WHERE company_id = $1 AND contact_id = $2`, [seed.companyId, contactId])).count, 1);
}

async function testTaskAndJobCore() {
  const seed = await seedCompany();
  const contactId = await createContact(seed);
  const t = node("trigger_1", "trigger", { trigger_key: "manual" });
  const task = node("task_1", "action", { action_key: "task.create", title: "Call {{contact.name}}", due_date: "1 hour" });
  const job = node("job_1", "action", { action_key: "job.create", title: "Install", start_at: "1 hour", end_at: "2 hours" });
  const created = await createAutomation(seed, graphFrom([t, task, job], [edge(t, task), edge(task, job)]));
  await publish(seed, created.automationId);
  const run = await automationTestHooks.startManualRun(created.automationId, seed.companyId, seed.userId, { subject_type: "contact", subject_id: contactId });
  await automationTestHooks.runAutomation(run.id);
  await assertRunCompleted(run.id);
  assert.equal((await scalar(`SELECT COUNT(*)::int AS count FROM todo_tasks WHERE title LIKE 'Call %'`, [])).count, 1);
  assert.equal((await scalar(`SELECT COUNT(*)::int AS count FROM schedule_events WHERE company_id = $1 AND contact_id = $2`, [seed.companyId, contactId])).count, 1);

  const taskId = await createTask(seed);
  const mt = node("trigger_task", "trigger", { trigger_key: "manual" });
  const complete = node("task_complete", "action", { action_key: "task.complete", target_mode: "specific_task", task_id: taskId });
  const taskAutomation = await createAutomation(seed, graphFrom([mt, complete], [edge(mt, complete)]));
  await publish(seed, taskAutomation.automationId);
  const taskRun = await automationTestHooks.startManualRun(taskAutomation.automationId, seed.companyId, seed.userId, { subject_type: "task", subject_id: taskId });
  await automationTestHooks.runAutomation(taskRun.id);
  await assertRunCompleted(taskRun.id);
  assert.equal((await scalar(`SELECT completed FROM todo_tasks WHERE id = $1`, [taskId])).completed, true);
}

async function testJobCompletedTrigger() {
  const seed = await seedCompany();
  const contactId = await createContact(seed);
  const jobId = await createJob(seed, contactId);
  const t = node("trigger_1", "trigger", { trigger_key: "job.completed" });
  const task = node("task_1", "action", { action_key: "task.create", title: "Follow up after job" });
  const created = await createAutomation(seed, graphFrom([t, task], [edge(t, task)]));
  await publish(seed, created.automationId);
  await pool.query(`UPDATE schedule_events SET finished_at = now(), finished_by = $2 WHERE id = $1`, [jobId, seed.userId]);
  await emitAutomationEvent({
    companyId: seed.companyId,
    eventType: "job.completed",
    subjectType: "job",
    subjectId: jobId,
    source: "test",
    dedupeKey: `job.completed:${jobId}`,
    payload: { job_id: jobId, contact_id: contactId }
  });
  const runs = await waitForRuns(seed, created.automationId, 1, "job completed");
  await assertRunCompleted(runs[0].id);
  assert.equal((await scalar(`SELECT COUNT(*)::int AS count FROM todo_tasks WHERE title = 'Follow up after job'`, [])).count, 1);
}

async function testWaitPauseCancel() {
  const seed = await seedCompany();
  const t = node("trigger_1", "trigger", { trigger_key: "manual" });
  const wait = node("wait_1", "wait", { mode: "duration", duration: "0 seconds" });
  const task = node("task_1", "action", { action_key: "task.create", title: "After wait" });
  const created = await createAutomation(seed, graphFrom([t, wait, task], [edge(t, wait), edge(wait, task)]));
  await publish(seed, created.automationId);
  const run = await automationTestHooks.startManualRun(created.automationId, seed.companyId, seed.userId, {});
  await automationTestHooks.runAutomation(run.id);
  assert.equal((await scalar(`SELECT COUNT(*)::int AS count FROM automation_waits WHERE run_id = $1`, [run.id])).count, 1);
  await automationTestHooks.processDueWaits();
  await assertRunCompleted(run.id);
  assert.equal((await scalar(`SELECT COUNT(*)::int AS count FROM todo_tasks WHERE title = 'After wait'`, [])).count, 1);

  const t2 = node("trigger_2", "trigger", { trigger_key: "manual" });
  const wait2 = node("wait_cancel", "wait", { mode: "duration", duration: "1 hour" });
  const task2 = node("task_cancel", "action", { action_key: "task.create", title: "Should not run" });
  const created2 = await createAutomation(seed, graphFrom([t2, wait2, task2], [edge(t2, wait2), edge(wait2, task2)]));
  await publish(seed, created2.automationId);
  const run2 = await automationTestHooks.startManualRun(created2.automationId, seed.companyId, seed.userId, {});
  await automationTestHooks.runAutomation(run2.id);
  const canceled = await automationTestHooks.cancelAutomationRun(run2.id, seed.companyId);
  assert.ok(canceled.run);
  await automationTestHooks.processDueWaits();
  assert.equal((await scalar(`SELECT COUNT(*)::int AS count FROM todo_tasks WHERE title = 'Should not run'`, [])).count, 0);
}

async function testPauseAndPauseUntil() {
  const seed = await seedCompany();
  const t = node("trigger_1", "trigger", { trigger_key: "contact.created" });
  const a = node("tag_1", "action", { action_key: "contact.add_tag", target_mode: "current_contact", tags: ["Pause Test"] });
  const created = await createAutomation(seed, graphFrom([t, a], [edge(t, a)]));
  await publish(seed, created.automationId);
  await pool.query(`UPDATE automation_definitions SET status = 'paused' WHERE id = $1`, [created.automationId]);
  await emitContactCreated(seed, await createContact(seed));
  await processAll();
  assert.equal((await scalar(`SELECT COUNT(*)::int AS count FROM automation_runs WHERE automation_id = $1`, [created.automationId])).count, 0);
  await pool.query(`UPDATE automation_definitions SET status = 'published', pause_until = NULL WHERE id = $1`, [created.automationId]);
  await emitContactCreated(seed, await createContact(seed));
  await waitForRuns(seed, created.automationId, 1, "pause resume");

  const future = new Date(Date.now() + 30000).toISOString();
  await pool.query(`UPDATE automation_definitions SET status = 'published', pause_until = $2 WHERE id = $1`, [created.automationId, future]);
  await emitContactCreated(seed, await createContact(seed));
  await processAll();
  assert.equal((await scalar(`SELECT COUNT(*)::int AS count FROM automation_runs WHERE automation_id = $1`, [created.automationId])).count, 1);
  await pool.query(`UPDATE automation_definitions SET pause_until = now() - interval '1 second' WHERE id = $1`, [created.automationId]);
  await emitContactCreated(seed, await createContact(seed));
  await waitForRuns(seed, created.automationId, 2, "pause until expired");
}

async function testMapServicePaymentAndDedupe() {
  const seed = await seedCompany();
  const contactId = await createContact(seed);
  const pinId = `pin_${randomUUID()}`;
  await pool.query(
    `INSERT INTO map_pins(id, user_id, latitude, longitude, name, address, status, contact_id)
     VALUES($1,$2,38.0,-84.0,'Pin','101 Map Test','later',$3)`,
    [pinId, seed.userId, contactId]
  );
  const mt = node("map_trigger", "trigger", { trigger_key: "map.pin_status_changed", to_status: "lead" });
  const createContactNode = node("contact_from_pin", "action", { action_key: "contact.create", name: "{{map.address}}", phone: "{{map.phone}}", address: "{{map.address}}" });
  const mapAutomation = await createAutomation(seed, graphFrom([mt, createContactNode], [edge(mt, createContactNode)]));
  await publish(seed, mapAutomation.automationId);
  await pool.query(`UPDATE map_pins SET status = 'lead' WHERE id = $1`, [pinId]);
  await emitAutomationEvent({
    companyId: seed.companyId,
    eventType: "map.pin_status_changed",
    subjectType: "map_pin",
    subjectId: pinId,
    source: "test",
    dedupeKey: `map.pin_status_changed:${pinId}:lead`,
    payload: { pin_id: pinId, old_status: "later", new_status: "lead", status: "lead", address: "101 Map Test", contact_id: contactId }
  });
  const runs = await waitForRuns(seed, mapAutomation.automationId, 1, "map pin lead");
  await assertRunCompleted(runs[0].id);

  const planId = randomUUID();
  await pool.query(
    `INSERT INTO service_plans(id, user_id, company_id, created_by_user_id, contact_id, plan_name, status, price_cents, billing_interval, service_interval, next_service_date)
     VALUES($1,$2,$3,$2,$4,'Automation Plan','active',10000,'month','month',CURRENT_DATE)`,
    [planId, seed.userId, seed.companyId, contactId]
  );
  const st = node("service_trigger", "trigger", { trigger_key: "service_plan.service_due" });
  const sa = node("service_task", "action", { action_key: "service_plan.create_service_task", title: "Service due task" });
  const serviceAutomation = await createAutomation(seed, graphFrom([st, sa], [edge(st, sa)]));
  await publish(seed, serviceAutomation.automationId);
  await syncAutomationSchedulesForServicePlan(seed.companyId, { id: planId, next_service_date: new Date(Date.now() - 1000).toISOString().slice(0, 10), status: "active", contact_id: contactId });
  await automationTestHooks.processScheduledAutomationEvents();
  await processAll();
  assert.equal((await scalar(`SELECT COUNT(*)::int AS count FROM automation_runs WHERE automation_id = $1`, [serviceAutomation.automationId])).count, 1);

  const paymentId = randomUUID();
  await pool.query(
    `INSERT INTO payment_records(id, user_id, company_id, created_by_user_id, contact_id, status, amount_cents, currency, stripe_payment_intent_id)
     VALUES($1,$2,$3,$2,$4,'succeeded',2500,'usd','pi_test_dedupe')`,
    [paymentId, seed.userId, seed.companyId, contactId]
  );
  const pt = node("payment_trigger", "trigger", { trigger_key: "payment.succeeded" });
  const pa = node("payment_task", "action", { action_key: "task.create", title: "Payment received" });
  const paymentAutomation = await createAutomation(seed, graphFrom([pt, pa], [edge(pt, pa)]));
  await publish(seed, paymentAutomation.automationId);
  const event = {
    companyId: seed.companyId,
    eventType: "payment.succeeded",
    subjectType: "payment",
    subjectId: paymentId,
    source: "stripe_test",
    dedupeKey: "stripe:evt_test_payment_success",
    payload: { payment_id: paymentId, contact_id: contactId, status: "succeeded", amount_cents: 2500 }
  };
  await emitAutomationEvent(event);
  await emitAutomationEvent(event);
  await waitForRuns(seed, paymentAutomation.automationId, 1, "payment dedupe");
}

async function testForeachMergeReentryAndRunCompletion() {
  const seed = await seedCompany();
  const contacts = [
    await createContact(seed),
    await createContact(seed),
    await createContact(seed)
  ];
  const t = node("trigger_1", "trigger", { trigger_key: "manual" });
  const each = node("foreach_1", "foreach", {
    collection: JSON.stringify(contacts.map((id) => ({ id }))),
    execution_mode: "sequential",
    max_items: 3
  });
  const tag = node("tag_item", "action", { action_key: "contact.add_tag", target_mode: "contact_id", contact_id: "{{iteration.item.id}}", tags: ["Processed"] });
  const doneTask = node("done_task", "action", { action_key: "task.create", title: "Foreach done" });
  const foreachAutomation = await createAutomation(seed, graphFrom([t, each, tag, doneTask], [edge(t, each), edge(each, tag, "item"), edge(each, doneTask, "done")]));
  await publish(seed, foreachAutomation.automationId);
  const foreachRun = await automationTestHooks.startManualRun(foreachAutomation.automationId, seed.companyId, seed.userId, {});
  await automationTestHooks.runAutomation(foreachRun.id);
  await assertRunCompleted(foreachRun.id);
  assert.equal((await scalar(`SELECT COUNT(*)::int AS count FROM automation_run_iterations WHERE run_id = $1 AND status = 'completed'`, [foreachRun.id])).count, 3);
  assert.equal((await scalar(`SELECT COUNT(*)::int AS count FROM contacts WHERE company_id = $1 AND tags LIKE '%Processed%'`, [seed.companyId])).count, 3);
  assert.equal((await scalar(`SELECT COUNT(*)::int AS count FROM todo_tasks WHERE user_id = $1 AND title = 'Foreach done'`, [seed.userId])).count, 1);

  const mt = node("merge_trigger", "trigger", { trigger_key: "manual" });
  const parallel = node("parallel_1", "parallel", { paths: [{ id: "path_a" }, { id: "path_b" }] });
  const waitA = node("wait_a", "wait", { mode: "duration", duration: "0 seconds" });
  const waitB = node("wait_b", "wait", { mode: "duration", duration: "0 seconds" });
  const merge = node("merge_1", "merge", { mode: "all" });
  const mergedTask = node("merged_task", "action", { action_key: "task.create", title: "Merge complete" });
  const mergeAutomation = await createAutomation(seed, graphFrom(
    [mt, parallel, waitA, waitB, merge, mergedTask],
    [edge(mt, parallel), edge(parallel, waitA, "path_a"), edge(parallel, waitB, "path_b"), edge(waitA, merge), edge(waitB, merge), edge(merge, mergedTask)]
  ));
  await publish(seed, mergeAutomation.automationId);
  const mergeRun = await automationTestHooks.startManualRun(mergeAutomation.automationId, seed.companyId, seed.userId, {});
  await automationTestHooks.runAutomation(mergeRun.id);
  await automationTestHooks.processDueWaits();
  await automationTestHooks.processDueWaits();
  await assertRunCompleted(mergeRun.id);
  assert.equal((await scalar(`SELECT COUNT(*)::int AS count FROM automation_merge_arrivals WHERE run_id = $1`, [mergeRun.id])).count, 2);
  assert.equal((await scalar(`SELECT COUNT(*)::int AS count FROM todo_tasks WHERE user_id = $1 AND title = 'Merge complete'`, [seed.userId])).count, 1);

  const contactId = await createContact(seed);
  const rt = node("reentry_trigger", "trigger", { trigger_key: "contact.created" });
  const ra = node("reentry_tag", "action", { action_key: "contact.add_tag", target_mode: "current_contact", tags: ["Reentry Once"] });
  const once = await createAutomation(seed, graphFrom([rt, ra], [edge(rt, ra)]), { reentry_mode: "once_ever_per_subject" });
  await pool.query(`UPDATE automation_definitions SET reentry_mode = 'once_ever_per_subject' WHERE id = $1`, [once.automationId]);
  await publish(seed, once.automationId);
  await emitContactCreated(seed, contactId, `contact.created:${contactId}:a`);
  await emitContactCreated(seed, contactId, `contact.created:${contactId}:b`);
  await waitForRuns(seed, once.automationId, 1, "once ever reentry");

  const rt2 = node("reentry_trigger", "trigger", { trigger_key: "contact.created" });
  const ra2 = node("reentry_tag", "action", { action_key: "contact.add_tag", target_mode: "current_contact", tags: ["Reentry Always"] });
  const always = await createAutomation(seed, graphFrom([rt2, ra2], [edge(rt2, ra2)]), { reentry_mode: "unlimited" });
  await pool.query(`UPDATE automation_definitions SET reentry_mode = 'unlimited' WHERE id = $1`, [always.automationId]);
  await publish(seed, always.automationId);
  await emitContactCreated(seed, contactId, `contact.created:${contactId}:c`);
  await emitContactCreated(seed, contactId, `contact.created:${contactId}:d`);
  await waitForRuns(seed, always.automationId, 2, "unlimited reentry");

  const active = await scalar(
    `SELECT COUNT(*)::int AS count
       FROM automation_runs
      WHERE company_id = $1
        AND status IN ('queued','running')
        AND NOT EXISTS (SELECT 1 FROM automation_waits w WHERE w.run_id = automation_runs.id AND w.status = 'waiting')`,
    [seed.companyId]
  );
  assert.equal(active.count, 0);
}

async function testValidationCatalogScopeAndDryRunExternalSafety() {
  const seed = await seedCompany();
  const invalidTask = graphFrom([node("bad_task", "action", { action_key: "task.complete", target_mode: "current_task" })], []);
  assert.equal(automationTestHooks.validateGraphPayload(invalidTask).valid, false);
  const invalidPhone = graphFrom([
    node("sms", "action", { action_key: "sms.send", target_mode: "phone_number", phone: "{{6062131071}}", body: "Bad" })
  ], []);
  assert.equal(automationTestHooks.validateGraphPayload(invalidPhone).valid, false);
  const phoneTrigger = node("phone_trigger", "trigger", { trigger_key: "manual" });
  const phoneSms = node("sms", "action", { action_key: "sms.send", target_mode: "phone_number", phone: "6062131071", body: "Good" });
  const validPhone = graphFrom([phoneTrigger, phoneSms], [edge(phoneTrigger, phoneSms)]);
  assert.equal(automationTestHooks.validateGraphPayload(validPhone).valid, true);

  const hiddenActions = automationTestHooks.actionCatalog().filter((a) => a.visibility !== "hidden").map((a) => a.key);
  assert.equal(hiddenActions.some((key) => key.startsWith("route.") || key.startsWith("invoice.")), false);
  const coreActions = automationTestHooks.actionCatalog().filter((a) => a.visibility === "core");
  const executors = automationTestHooks.actionExecutors();
  for (const action of coreActions) assert.ok(executors[action.key], `core executor missing: ${action.key}`);
  const coreTriggers = automationTestHooks.triggerCatalog().filter((t) => t.visibility === "core");
  for (const trigger of coreTriggers) assert.notEqual(trigger.wired, false, `core trigger unwired: ${trigger.key}`);

  const companyB = await seedCompany();
  const foreignContact = await createContact(companyB);
  const t = node("trigger_1", "trigger", { trigger_key: "manual" });
  const a = node("tag_1", "action", { action_key: "contact.add_tag", target_mode: "specific_contact", contact_id: foreignContact, tags: ["Cross Company"] });
  const created = await createAutomation(seed, graphFrom([t, a], [edge(t, a)]));
  await publish(seed, created.automationId);
  const run = await automationTestHooks.startManualRun(created.automationId, seed.companyId, seed.userId, { subject_type: "generic" });
  await automationTestHooks.runAutomation(run.id);
  assert.equal((await scalar(`SELECT status FROM automation_runs WHERE id = $1`, [run.id])).status, "failed");
  assert.doesNotMatch((await scalar(`SELECT tags FROM contacts WHERE id = $1`, [foreignContact])).tags || "", /Cross Company/);

  const contactId = await createContact(seed);
  const sms = node("sms_1", "action", { action_key: "sms.send", target_mode: "current_contact", body: "Dry" });
  const push = node("push_1", "action", { action_key: "notification.send_push", title: "Dry", body: "Dry" });
  const payment = node("pay_1", "action", { action_key: "payment.create_payment_link", target_mode: "current_contact", amount_cents: 5000, description: "Dry" });
  const trigger = node("trigger_dry", "trigger", { trigger_key: "contact.created" });
  const dry = await createAutomation(seed, graphFrom([trigger, sms, push, payment], [edge(trigger, sms), edge(sms, push), edge(push, payment)]));
  state.smsCalls = [];
  state.pushCalls = [];
  state.stripeCalls = [];
  const dryRun = await automationTestHooks.startDraftTestRun(dry.automationId, seed.companyId, seed.userId, { subject_type: "contact", subject_id: contactId, trigger_key: "contact.created" });
  await automationTestHooks.runAutomation(dryRun.id);
  await assertRunCompleted(dryRun.id);
  assert.equal(state.smsCalls.length, 0);
  assert.equal(state.pushCalls.length, 0);
  assert.equal(state.stripeCalls.length, 0);
}

const tests = [
  ["Publish", testPublishAndRepublish],
  ["Draft-not-live", testDraftDoesNotRun],
  ["Draft Test", testDraftRunSafety],
  ["Contact -> Tag", testContactToTag],
  ["Contact -> Pipeline", testContactToPipeline],
  ["Contact -> SMS", testContactToSms],
  ["EXACT Contact -> SMS -> Pipeline", testExactWorkflow],
  ["Initial SMS failure stops default path", testSmsFailureStopsDefaultPath],
  ["Later SMS undelivered remains separate", testLaterSmsUndeliveredDoesNotRollbackRun],
  ["Error Path", testInitialSmsFailureAndErrorPath],
  ["Pipeline idempotency", testPipelineIdempotency],
  ["Task create/complete and Job create", testTaskAndJobCore],
  ["Job completed trigger", testJobCompletedTrigger],
  ["Wait, due resume, cancel wait", testWaitPauseCancel],
  ["Pause and Pause Until", testPauseAndPauseUntil],
  ["Map pin, service due, payment dedupe", testMapServicePaymentAndDedupe],
  ["Foreach, Merge ALL, Re-entry, Run completion", testForeachMergeReentryAndRunCompletion],
  ["Validation, catalog, scope, dry-run external safety", testValidationCatalogScopeAndDryRunExternalSafety]
];

let passed = 0;
let failed = 0;

try {
  await bootstrapSchema();
  await resetDatabase();
  for (const [name, fn] of tests) {
    try {
      await fn();
      passed += 1;
      console.log(`PASS ${name}`);
    } catch (error) {
      failed += 1;
      console.error(`FAIL ${name}: ${error?.stack || error?.message || error}`);
      break;
    }
  }
} finally {
  if (failed === 0 && process.env.KEEP_AUTOMATION_TEST_DATA !== "true") {
    await resetDatabase().catch((error) => {
      console.error(`WARN cleanup failed: ${error?.message || error}`);
    });
  }
  await pool.end().catch(() => {});
  await backend.pool?.end?.().catch(() => {});
}

console.log(`RESULT automation-core integration: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
