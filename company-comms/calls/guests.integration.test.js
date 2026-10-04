import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createCommsFixture } from "../../tests/helpers/comms-fixture.js";
import { authorizeConversation, publish } from "../access.js";
import { installCallsSchema } from "./schema.js";
import { createCallsService } from "./service.js";
import { installGuestSchema, createGuestService } from "./guests.js";

test(
  "optional guests stay within one admitted live meeting",
  { timeout: 120000 },
  async (t) => {
    const f = await createCommsFixture(),
      { pool, companies, ids } = f;
    const minted = [];
    const provider = {
      configured: true,
      recordingConfigured: true,
      create: async () => {},
      token: async (c, p) => {
        minted.push(p);
        return { url: "wss://example.invalid", token: "fake-provider-token" };
      },
    };
    const calls = createCallsService({
        pool,
        provider,
        authorizeConversation,
        publish,
        adoptRecording: async () => {},
      }),
      guests = createGuestService({
        pool,
        provider,
        authorizeConversation,
        publish,
        env: { COMMS_GUESTS_ENABLED: "true" },
      });
    calls.guests = guests;
    const owner = await f.actor("owner");
    let meeting, call;
    const invite = () =>
      guests.invite(owner, meeting.id, { label: "Client meeting guest" });
    const redeem = async () => {
      const invitation = await invite();
      const token = new URL(invitation.join_url).hash.slice("#token=".length);
      const session = await guests.redeem(token, "Visitor");
      return { invitation, token, session };
    };
    try {
      await installCallsSchema(pool);
      await installGuestSchema(pool);
      await installGuestSchema(pool);
      await pool.query(
        "INSERT INTO conversations(id,company_id,title,created_by) VALUES('guest-source',$1,'Private source',$2)",
        [companies.a, ids.owner],
      );
      await pool.query(
        "INSERT INTO conversation_participants(id,conversation_id,user_id) VALUES($1,'guest-source',$2)",
        [randomUUID(), ids.owner],
      );
      meeting = await calls.saveMeeting(owner, {
        id: randomUUID(),
        conversation_id: "guest-source",
        title: "Guest meeting",
        agenda: "Private agenda",
        starts_at: new Date(Date.now() + 60000).toISOString(),
        duration_minutes: 30,
        timezone: "UTC",
        attendee_ids: [],
      });
      call = await calls.joinMeeting(owner, meeting.id);
      await t.test(
        "disabled by company default and denied for foreign/nonhost actors",
        async () => {
          await assert.rejects(
            invite(),
            (e) => e.code === "guest_join_disabled",
          );
          await pool.query(
            "UPDATE comms_call_settings SET guests_enabled=true WHERE company_id=$1",
            [companies.a],
          );
          await assert.rejects(
            guests.invite(await f.actor("foreign"), meeting.id, {}),
            (e) => [403, 404].includes(e.status),
          );
          await assert.rejects(
            guests.invite(await f.actor("alice"), meeting.id, {}),
            (e) => [403, 404].includes(e.status),
          );
        },
      );
      await t.test(
        "invitation is one-use, hashed, expiring and reveals no CRM identifiers",
        async () => {
          const { invitation, token, session } = await redeem();
          assert.match(invitation.join_url, /^wolfcrm:\/\/comms-guest#token=/);
          assert.equal(session.state, "waiting");
          assert.equal(session.company_id, undefined);
          assert.equal(session.conversation_id, undefined);
          assert.equal(session.agenda, undefined);
          const row = (
            await pool.query("SELECT * FROM comms_guest_invites WHERE id=$1", [
              invitation.id,
            ])
          ).rows[0];
          assert.notEqual(row.token_hash, token);
          assert.ok(row.consumed_at);
          await assert.rejects(
            guests.redeem(token, "Second guest"),
            (e) => e.code === "guest_invitation_unavailable",
          );
          const status = await guests.token(session.session_token);
          assert.equal(status.waiting, true);
          assert.equal(status.token, undefined);
          assert.equal(minted.length, 0);
          assert.equal(
            Number(
              (await pool.query("SELECT count(*) FROM users")).rows[0].count,
            ),
            Object.keys(ids).length,
          );
          await guests.revoke(owner, meeting.id, invitation.id);
          await assert.rejects(
            guests.status(session.session_token),
            (e) => e.status === 404,
          );
        },
      );
      await t.test(
        "host admission is mandatory and guest media grant never allows screen or data access",
        async () => {
          const { session } = await redeem();
          await guests.status(session.session_token);
          await guests.moderate(owner, meeting.id, session.guest_id, {
            action: "admit",
          });
          const connection = await guests.token(session.session_token);
          assert.equal(connection.waiting, false);
          assert.equal(minted.at(-1).can_screen_share, false);
          assert.match(minted.at(-1).display_name, /\(Guest\)$/);
          await assert.rejects(
            calls.recording(owner, call.id, { id: randomUUID() }),
            (e) =>
              ["recording_disabled", "guest_recording_disabled"].includes(
                e.code,
              ),
          );
          await guests.moderate(owner, meeting.id, session.guest_id, {
            action: "remove",
          });
          await assert.rejects(
            guests.token(session.session_token),
            (e) => e.status === 404,
          );
          assert.ok(
            (
              await pool.query(
                "SELECT 1 FROM comms_call_jobs WHERE kind='remove' AND call_id=$1",
                [call.id],
              )
            ).rowCount,
          );
        },
      );
      await t.test(
        "recording in progress prevents admission; expiration prevents token issuance",
        async () => {
          const { session } = await redeem(),
            recording = randomUUID();
          await guests.status(session.session_token);
          await pool.query(
            "INSERT INTO comms_call_recordings(id,call_id,company_id,requested_by,object_key,media,status) VALUES($1,$2,$3,$4,$5,'video','recording')",
            [recording, call.id, companies.a, ids.owner, "test/" + recording],
          );
          await assert.rejects(
            guests.moderate(owner, meeting.id, session.guest_id, {
              action: "admit",
            }),
            (e) => e.code === "recording_in_progress",
          );
          await pool.query(
            "UPDATE comms_call_recordings SET status='failed' WHERE id=$1",
            [recording],
          );
          await pool.query(
            "UPDATE comms_guest_sessions SET expires_at=now()-interval '1 second' WHERE id=$1",
            [session.guest_id],
          );
          await assert.rejects(
            guests.token(session.session_token),
            (e) => e.status === 404,
          );
        },
      );
      await t.test(
        "host membership removal revokes guest session without waiting for a new user token",
        async () => {
          const { session } = await redeem();
          await guests.status(session.session_token);
          await guests.moderate(owner, meeting.id, session.guest_id, {
            action: "admit",
          });
          await pool.query(
            "UPDATE conversation_participants SET left_at=now() WHERE conversation_id='guest-source' AND user_id=$1",
            [ids.owner],
          );
          await guests.reconcile();
          await assert.rejects(guests.token(session.session_token), (e) =>
            [403, 404].includes(e.status),
          );
        },
      );
    } finally {
      await f.close();
    }
  },
);
