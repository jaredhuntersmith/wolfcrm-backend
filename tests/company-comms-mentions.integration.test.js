import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import express from "express";
import { createCommsFixture } from "./helpers/comms-fixture.js";
import { createConversationService } from "../company-comms/messages.js";
import { createGroupService } from "../company-comms/groups.js";
import { createScheduled } from "../company-comms/scheduled.js";
import { installCompanyComms } from "../company-comms/index.js";

const rejected = (promise, code) =>
  assert.rejects(promise, (error) => error.code === code);
test(
  "controlled mentions and authorized reply participants on PostgreSQL",
  { timeout: 120000 },
  async (t) => {
    const f = await createCommsFixture(),
      { pool, ids, companies } = f;
    const messages = createConversationService({ pool }),
      groups = createGroupService({ pool }),
      scheduled = createScheduled({ pool, messages });
    let server, core;
    const override = (user, values) =>
      pool.query(
        "UPDATE employee_permissions SET permission_overrides=permission_overrides||$2::jsonb WHERE user_id=$1",
        [user, JSON.stringify(values)],
      );
    const send = (who, conversation, body = {}) =>
      messages.send(actors[who], conversation, {
        client_key: randomUUID(),
        body: "Mention test",
        ...body,
      });
    const makeRoom = () =>
      messages.create(actors.alice, {
        client_key: randomUUID(),
        member_ids: [ids.bob, ids.carol],
        title: "Mention group",
      });
    const storedMentions = async (id) =>
      (
        await pool.query(
          "SELECT user_id FROM comms_mentions WHERE message_id=$1 ORDER BY user_id",
          [id],
        )
      ).rows.map((row) => row.user_id);
    const presence = (user, availability, duration = 60) =>
      pool.query(
        `INSERT INTO comms_presence(user_id,company_id,availability,expires_at) VALUES($1,$2,$3,now()+$4::int*interval '1 second') ON CONFLICT(user_id) DO UPDATE SET availability=excluded.availability,expires_at=excluded.expires_at`,
        [user, companies.a, availability, duration],
      );
    let actors;
    try {
      await override(ids.alice, { "communications.manage": true });
      await override(ids.bob, { "communications.manage": false });
      actors = Object.fromEntries(
        await Promise.all(
          Object.keys(ids).map(async (key) => [key, await f.actor(key)]),
        ),
      );

      await t.test(
        "person IDs require current authorized audience; raw text is not broadcast authority",
        async () => {
          const room = await makeRoom();
          const person = await send("bob", room.id, {
            mention_user_ids: [ids.alice, ids.alice],
            body: "@channel typed text",
          });
          assert.deepEqual(await storedMentions(person.id), [ids.alice]);
          assert.deepEqual(person.mention_user_ids, [ids.alice]);
          assert.equal(person.mention_scope, null);
          await rejected(
            send("bob", room.id, { mention_scope: "group" }),
            "permission_denied",
          );
          await rejected(
            send("alice", room.id, { mention_user_ids: [ids.foreign] }),
            "invalid_mention",
          );
          await rejected(
            send("alice", room.id, { mention_user_ids: [ids.admin] }),
            "invalid_mention",
          );
          await override(ids.bob, { "communications.view": false });
          await rejected(
            send("alice", room.id, { mention_user_ids: [ids.bob] }),
            "invalid_mention",
          );
          await rejected(send("bob", room.id, {}), "permission_denied");
          await override(ids.bob, { "communications.view": true });
          await rejected(
            send("alice", room.id, { mention_scope: "everyone" }),
            "invalid_mention_scope",
          );
          await rejected(
            send("alice", room.id, { mention_scope: "channel" }),
            "invalid_mention_scope",
          );
          const dm = await messages.create(actors.alice, {
            client_key: randomUUID(),
            member_ids: [ids.bob],
          });
          await rejected(
            send("alice", dm.id, { mention_scope: "group" }),
            "invalid_mention_scope",
          );
        },
      );

      await t.test(
        "broadcast scopes share a transactional cooldown and retry exactly once",
        async () => {
          const room = await makeRoom(),
            key = randomUUID();
          const [one, retry] = await Promise.all([
            send("alice", room.id, { client_key: key, mention_scope: "group" }),
            send("alice", room.id, { client_key: key, mention_scope: "group" }),
          ]);
          assert.equal(one.id, retry.id);
          assert.deepEqual(
            new Set(await storedMentions(one.id)),
            new Set([ids.alice, ids.bob, ids.carol]),
          );
          assert.equal(
            (
              await pool.query(
                "SELECT count(*)::int AS count FROM messages WHERE client_key=$1",
                [key],
              )
            ).rows[0].count,
            1,
          );
          await rejected(
            send("alice", room.id, { mention_scope: "here" }),
            "mention_rate_limited",
          );
          await send("alice", room.id, { mention_user_ids: [ids.bob] });
          await messages.edit(
            actors.alice,
            one.id,
            { expected_revision: 1 },
            true,
          );
          await rejected(
            send("alice", room.id, { mention_scope: "group" }),
            "mention_rate_limited",
          );
          await pool.query(
            `UPDATE messages SET created_at=now()-interval '61 seconds' WHERE id=$1`,
            [one.id],
          );
          const later = await send("alice", room.id, { mention_all: true });
          assert.equal(later.mention_scope, "group");
          await override(ids.alice, { "communications.manage": false });
          assert.equal(
            (
              await send("alice", room.id, {
                client_key: later.client_key,
                mention_scope: "group",
              })
            ).id,
            later.id,
          );
          await rejected(
            send("alice", room.id, { mention_scope: "group" }),
            "permission_denied",
          );
          await override(ids.alice, { "communications.manage": true });
        },
      );

      await t.test(
        "Channel mentions stay inside the current private Thread audience",
        async () => {
          let group = await groups.create(actors.alice, {
            id: randomUUID(),
            name: "Crew",
            member_ids: [ids.bob, ids.carol],
          });
          await groups.membership(actors.bob, group.group.id, {
            action: "accept",
            accept_history: true,
          });
          await groups.membership(actors.carol, group.group.id, {
            action: "accept",
            accept_history: true,
          });
          group = await groups.detail(actors.alice, group.group.id);
          group = await groups.structure(
            actors.alice,
            group.group.id,
            "thread",
            null,
            {
              name: "Private",
              kind: "text",
              permission_mode: "override",
              restricted: true,
              member_ids: [ids.bob],
              expected_group_revision: group.group.revision,
            },
          );
          const thread = group.threads.find((row) => row.name === "Private");
          const sent = await send("alice", thread.conversation_id, {
            mention_scope: "channel",
          });
          assert.deepEqual(
            new Set(await storedMentions(sent.id)),
            new Set([ids.alice, ids.bob]),
          );
          await rejected(
            send("alice", thread.conversation_id, {
              mention_user_ids: [ids.carol],
            }),
            "invalid_mention",
          );
          await rejected(
            send("carol", thread.conversation_id, {}),
            "conversation_unavailable",
          );
          await rejected(
            send("alice", thread.conversation_id, { mention_scope: "group" }),
            "invalid_mention_scope",
          );
        },
      );

      await t.test(
        "here resolves available nonexpired presence without including outsiders",
        async () => {
          const room = await makeRoom();
          await presence(ids.alice, "available");
          await presence(ids.bob, "away");
          await presence(ids.carol, "available", -1);
          await presence(ids.admin, "available");
          const sent = await send("alice", room.id, { mention_scope: "here" });
          assert.deepEqual(await storedMentions(sent.id), [ids.alice]);
          assert.equal(sent.mention_scope, "here");
        },
      );

      await t.test(
        "large candidate audiences fail closed even when early users lose access",
        async () => {
          const room = await makeRoom();
          await pool.query(
            `WITH inserted AS(INSERT INTO users(id,company_id,email,display_name,role) SELECT gen_random_uuid(),$1,'large-'||n||'@example.invalid','000-'||lpad(n::text,3,'0'),'employee' FROM generate_series(1,220) n RETURNING id,display_name), perms AS(INSERT INTO employee_permissions(user_id,company_id,permission_preset,permission_overrides) SELECT id,$1,'manager',CASE WHEN display_name<'000-101' THEN '{"communications.view":false}'::jsonb ELSE '{}'::jsonb END FROM inserted) INSERT INTO conversation_participants(id,conversation_id,user_id) SELECT gen_random_uuid()::text,$2,id FROM inserted`,
            [companies.a, room.id],
          );
          await rejected(
            send("alice", room.id, { mention_scope: "group" }),
            "mention_audience_too_large",
          );
          await rejected(
            send("alice", room.id, { mention_scope: "here" }),
            "mention_audience_too_large",
          );
          assert.equal(
            (
              await pool.query(
                "SELECT count(*)::int AS count FROM messages WHERE conversation_id=$1",
                [room.id],
              )
            ).rows[0].count,
            0,
          );
        },
      );

      await t.test(
        "scheduled scope and reply destination survive edits and resolve at delivery",
        async () => {
          const room = await makeRoom(),
            root = await send("alice", room.id);
          await presence(ids.alice, "available");
          await presence(ids.bob, "away");
          await presence(ids.carol, "away");
          const created = await scheduled.save(actors.alice, room.id, null, {
            client_key: randomUUID(),
            body: "Later in this reply",
            reply_root_id: root.id,
            mention_scope: "here",
            mention_user_ids: [],
            send_at: new Date(Date.now() + 60000).toISOString(),
            timezone: "UTC",
          });
          const edited = await scheduled.save(actors.alice, null, created.id, {
            expected_revision: created.revision,
            body: "Edited later",
          });
          assert.equal(edited.mention_scope, "here");
          assert.equal(edited.reply_root_id, root.id);
          await presence(ids.alice, "away");
          await presence(ids.carol, "available");
          await pool.query(
            `UPDATE comms_scheduled_messages SET send_at=now()-interval '1 second' WHERE id=$1`,
            [created.id],
          );
          await scheduled.tick();
          const delivered = (
            await pool.query(
              "SELECT * FROM comms_scheduled_messages WHERE id=$1",
              [created.id],
            )
          ).rows[0];
          assert.equal(delivered.status, "sent");
          const message = (
            await pool.query("SELECT * FROM messages WHERE id=$1", [
              delivered.message_id,
            ])
          ).rows[0];
          assert.equal(message.reply_root_id, root.id);
          assert.equal(message.mention_scope, "here");
          assert.deepEqual(await storedMentions(message.id), [ids.carol]);
          const removable = await scheduled.save(actors.alice, room.id, null, {
            client_key: randomUUID(),
            body: "Optional fields",
            reply_root_id: root.id,
            mention_scope: "group",
            mention_user_ids: [ids.bob],
            send_at: new Date(Date.now() + 60000).toISOString(),
            timezone: "UTC",
          });
          const cleared = await scheduled.save(
            actors.alice,
            null,
            removable.id,
            {
              expected_revision: removable.revision,
              mention_scope: null,
              mention_user_ids: [],
              reply_root_id: null,
            },
          );
          assert.equal(cleared.mention_scope, null);
          assert.deepEqual(cleared.mention_user_ids, []);
          assert.equal(cleared.reply_root_id, null);
        },
      );

      await t.test(
        "scheduled sender access and broadcast capability are rechecked at delivery",
        async () => {
          const room = await makeRoom();
          const created = await scheduled.save(actors.alice, room.id, null, {
            client_key: randomUUID(),
            body: "No revoked alert",
            mention_scope: "group",
            send_at: new Date(Date.now() + 60000).toISOString(),
            timezone: "UTC",
          });
          await override(ids.alice, { "communications.manage": false });
          await pool.query(
            `UPDATE comms_scheduled_messages SET send_at=now()-interval '1 second' WHERE id=$1`,
            [created.id],
          );
          await scheduled.tick();
          const failed = (
            await pool.query(
              "SELECT * FROM comms_scheduled_messages WHERE id=$1",
              [created.id],
            )
          ).rows[0];
          assert.equal(failed.status, "failed");
          assert.equal(failed.error_code, "permission_denied");
          assert.equal(failed.message_id, null);
          await override(ids.alice, { "communications.manage": true });
        },
      );

      await t.test(
        "reply counts and names respect history, source, deletion and current author eligibility",
        async () => {
          const room = await makeRoom(),
            root = await send("alice", room.id);
          const bob = await send("bob", room.id, {
            reply_root_id: root.id,
            body: "Visible reply",
          });
          const carol = await send("carol", room.id, {
            reply_root_id: root.id,
            body: "Older reply",
          });
          await pool.query(
            `UPDATE messages SET created_at=now()-interval '1 day' WHERE id=$1`,
            [carol.id],
          );
          await pool.query(
            `UPDATE conversation_participants SET history_from=now()-interval '1 hour' WHERE conversation_id=$1 AND user_id=$2`,
            [room.id, ids.alice],
          );
          let current = (
            await messages.history(actors.alice, room.id)
          ).messages.find((row) => row.id === root.id);
          assert.equal(current.reply_count, 1);
          assert.equal(current.reply_participant_count, 1);
          assert.deepEqual(current.reply_participants, [
            { id: ids.bob, display_name: "bob" },
          ]);
          await override(ids.bob, { "communications.view": false });
          current = (
            await messages.history(actors.alice, room.id)
          ).messages.find((row) => row.id === root.id);
          assert.equal(current.reply_count, 1);
          assert.equal(current.reply_participant_count, 0);
          assert.deepEqual(current.reply_participants, []);
          await override(ids.bob, { "communications.view": true });
          await messages.edit(
            actors.bob,
            bob.id,
            { expected_revision: 1 },
            true,
          );
          assert.equal(
            (await messages.history(actors.alice, room.id)).messages.find(
              (row) => row.id === root.id,
            ).reply_count,
            0,
          );
          const source = await makeRoom();
          await pool.query(
            `UPDATE conversations SET source_kind='conversation',source_id=$2 WHERE id=$1`,
            [room.id, source.id],
          );
          await pool.query(
            "UPDATE conversation_participants SET left_at=now() WHERE conversation_id=$1 AND user_id=$2",
            [source.id, ids.alice],
          );
          await rejected(
            messages.replyParticipants(actors.alice, root.id),
            "conversation_unavailable",
          );
          await rejected(
            messages.history(actors.alice, room.id),
            "conversation_unavailable",
          );
        },
      );

      await t.test(
        "reply previews are bounded and participant pages preserve history and tenant isolation",
        async () => {
          const room = await makeRoom(),
            root = await send("alice", room.id);
          const authors = (
            await pool.query(
              `WITH inserted AS(INSERT INTO users(id,company_id,email,display_name,role) SELECT gen_random_uuid(),$1,'reply-'||n||'@example.invalid','Reply person '||n,'employee' FROM generate_series(1,55) n RETURNING id), perms AS(INSERT INTO employee_permissions(user_id,company_id,permission_preset) SELECT id,$1,'manager' FROM inserted), membership AS(INSERT INTO conversation_participants(id,conversation_id,user_id) SELECT gen_random_uuid()::text,$2,id FROM inserted) INSERT INTO messages(id,company_id,conversation_id,sender_id,body,reply_root_id) SELECT gen_random_uuid()::text,$1,$2,id,'Reply',$3 FROM inserted RETURNING sender_id`,
              [companies.a, room.id, root.id],
            )
          ).rows;
          const current = (
            await messages.history(actors.alice, room.id)
          ).messages.find((row) => row.id === root.id);
          assert.equal(current.reply_count, 55);
          assert.equal(current.reply_participants.length, 8);
          assert.equal(current.reply_participant_count, 55);
          assert.equal(current.reply_participants_truncated, true);
          const first = await messages.replyParticipants(actors.alice, root.id);
          assert.equal(first.participants.length, 50);
          assert.ok(first.next_cursor);
          const second = await messages.replyParticipants(
            actors.alice,
            root.id,
            { after_id: first.next_cursor },
          );
          assert.equal(second.participants.length, 5);
          assert.equal(second.next_cursor, null);
          assert.equal(
            new Set(
              [...first.participants, ...second.participants].map(
                (row) => row.id,
              ),
            ).size,
            authors.length,
          );
          await rejected(
            messages.replyParticipants(actors.foreign, root.id),
            "message_unavailable",
          );
          await rejected(
            messages.replyParticipants(actors.bob, root.id, {
              after_id: "bad",
            }),
            "invalid_id",
          );
        },
      );

      await t.test(
        "large reply histories have truthful unknown totals and advance across denied authors",
        async () => {
          const room = await makeRoom(),
            root = await send("alice", room.id);
          const authors = (
            await pool.query(
              `WITH inserted AS(INSERT INTO users(id,company_id,email,display_name,role) SELECT gen_random_uuid(),$1,'bounded-reply-'||n||'@example.invalid','Bounded author '||n,'employee' FROM generate_series(1,201) n RETURNING id), perms AS(INSERT INTO employee_permissions(user_id,company_id,permission_preset,permission_overrides) SELECT id,$1,'manager','{"communications.view":false}'::jsonb FROM inserted), membership AS(INSERT INTO conversation_participants(id,conversation_id,user_id) SELECT gen_random_uuid()::text,$2,id FROM inserted) INSERT INTO messages(id,company_id,conversation_id,sender_id,body,reply_root_id) SELECT gen_random_uuid()::text,$1,$2,id,'Reply',$3 FROM inserted RETURNING sender_id`,
              [companies.a, room.id, root.id],
            )
          ).rows
            .map((row) => row.sender_id)
            .sort();
          await override(authors.at(-1), { "communications.view": true });
          const current = (
            await messages.history(actors.alice, room.id)
          ).messages.find((row) => row.id === root.id);
          assert.equal(current.reply_count, 201);
          assert.equal(current.reply_participant_count, null);
          assert.equal(current.reply_participants_truncated, true);
          assert.deepEqual(current.reply_participants, []);
          const first = await messages.replyParticipants(actors.alice, root.id);
          assert.deepEqual(first.participants, []);
          assert.ok(first.next_cursor);
          const second = await messages.replyParticipants(
            actors.alice,
            root.id,
            { after_id: first.next_cursor },
          );
          assert.equal(second.participants.length, 1);
          assert.equal(second.participants[0].id, authors.at(-1));
          assert.equal(second.next_cursor, null);
        },
      );

      await t.test(
        "HTTP participant options and reply details use authoritative capabilities",
        async () => {
          const app = express();
          app.use(express.json());
          const authRequired = async (req, res, next) => {
            const key = req.get("authorization");
            if (!ids[key]) return res.sendStatus(401);
            Object.assign(req, await f.actor(key));
            next();
          };
          core = await installCompanyComms({
            app,
            pool,
            authRequired,
            startWorker: false,
          });
          server = app.listen(0, "127.0.0.1");
          await new Promise((resolve) => server.once("listening", resolve));
          const base = "http://127.0.0.1:" + server.address().port,
            room = await makeRoom(),
            root = await send("alice", room.id);
          await send("bob", room.id, { reply_root_id: root.id });
          const get = (path, who) =>
            fetch(base + "/api/comms" + path, {
              headers: { authorization: who },
            });
          const options = await (
            await get("/conversations/" + room.id + "/participants", "alice")
          ).json();
          assert.deepEqual(options.mention_scopes, ["group", "here"]);
          assert.equal(options.conversation_scope, "group_dm");
          assert.deepEqual(
            (
              await (
                await get("/conversations/" + room.id + "/participants", "bob")
              ).json()
            ).mention_scopes,
            [],
          );
          assert.equal(
            (
              await (
                await get(
                  "/messages/" + root.id + "/reply-participants",
                  "alice",
                )
              ).json()
            ).participants[0].id,
            ids.bob,
          );
          assert.equal(
            (
              await get(
                "/messages/" + root.id + "/reply-participants",
                "foreign",
              )
            ).status,
            404,
          );
        },
      );
    } finally {
      core?.stop();
      if (server) await new Promise((resolve) => server.close(resolve));
      await f.close();
    }
  },
);
