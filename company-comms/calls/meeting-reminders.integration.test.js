import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createCommsFixture } from "../../tests/helpers/comms-fixture.js";
import { authorizeConversation, publish } from "../access.js";
import {
  createNotifications,
  installNotificationsSchema,
} from "../notifications.js";
import { installCallsSchema } from "./schema.js";
import { createCallsService } from "./service.js";
import {
  createMeetingDelivery,
  installMeetingDeliverySchema,
} from "./meeting-reminders.js";

test(
  "meeting invitation, update and reminders use the authorized canonical inbox",
  { timeout: 120000 },
  async (t) => {
    const f = await createCommsFixture(),
      { pool, ids, companies } = f;
    try {
      await installCallsSchema(pool);
      await installMeetingDeliverySchema(pool);
      await installNotificationsSchema(pool);
      const notifications = createNotifications({ pool }),
        delivery = createMeetingDelivery({
          pool,
          notifications,
          authorizeConversation,
        });
      const calls = createCallsService({
        pool,
        authorizeConversation,
        publish,
        provider: { configured: true },
        meetingDelivery: delivery,
      });
      await pool.query(
        "INSERT INTO conversations(id,company_id,created_by,title) VALUES('meeting-source',$1,$2,'Private')",
        [companies.a, ids.owner],
      );
      for (const user of [ids.owner, ids.alice, ids.bob])
        await pool.query(
          "INSERT INTO conversation_participants(id,conversation_id,user_id) VALUES($1,'meeting-source',$2)",
          [randomUUID(), user],
        );
      const owner = await f.actor("owner"),
        alice = await f.actor("alice");
      const body = {
        id: randomUUID(),
        conversation_id: "meeting-source",
        title: "Team meeting",
        starts_at: new Date(Date.now() + 10 * 60000).toISOString(),
        duration_minutes: 30,
        timezone: "America/New_York",
        attendee_ids: [ids.alice, ids.bob],
      };
      const meeting = await calls.saveMeeting(owner, body);
      await t.test(
        "invitations are deduplicated and never sent across companies",
        async () => {
          assert.equal(
            (
              await pool.query(
                "SELECT count(*) FROM notifications WHERE kind='comms.meeting_updated'",
              )
            ).rows[0].count,
            "3",
          );
          await calls.saveMeeting(owner, body);
          assert.equal(
            (await pool.query("SELECT count(*) FROM notifications")).rows[0]
              .count,
            "3",
          );
          assert.equal(
            (
              await pool.query(
                "SELECT 1 FROM notifications WHERE company_id=$1",
                [companies.b],
              )
            ).rowCount,
            0,
          );
        },
      );
      await t.test(
        "declined and newly unauthorized attendees receive no due reminder; concurrent scans converge",
        async () => {
          await calls.meetingAction(alice, meeting.id, { rsvp: "declined" });
          await pool.query(
            "UPDATE conversation_participants SET left_at=now() WHERE conversation_id='meeting-source' AND user_id=$1",
            [ids.bob],
          );
          await Promise.all([delivery.tick(), delivery.tick()]);
          const rows = (
            await pool.query(
              "SELECT user_id FROM notifications WHERE kind='comms.meeting_reminder'",
            )
          ).rows;
          assert.deepEqual(
            rows.map((x) => x.user_id),
            [ids.owner],
          );
          await delivery.tick();
          assert.equal(
            (
              await pool.query(
                "SELECT 1 FROM notifications WHERE kind='comms.meeting_reminder'",
              )
            ).rowCount,
            1,
          );
        },
      );
      await t.test(
        "stale meeting edits fail and cancel produces no new reminders or job records",
        async () => {
          await assert.rejects(
            calls.saveMeeting(
              owner,
              { ...body, attendee_ids: [ids.alice], expected_version: 0 },
              meeting.id,
            ),
            (e) => e.code === "stale_meeting",
          );
          await calls.meetingAction(owner, meeting.id, { action: "cancel" });
          await delivery.tick();
          assert.equal(
            (
              await pool.query(
                "SELECT 1 FROM notifications WHERE kind='comms.meeting_canceled'",
              )
            ).rowCount,
            2,
          );
          assert.equal(
            (await pool.query("SELECT 1 FROM schedule_events")).rowCount,
            0,
          );
          assert.equal(
            (await pool.query("SELECT 1 FROM todo_tasks")).rowCount,
            0,
          );
        },
      );
    } finally {
      await f.close();
    }
  },
);
