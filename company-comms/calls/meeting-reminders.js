import { transact, loadActor } from "../access.js";
export async function installMeetingDeliverySchema(db) {
  await db.query(
    `CREATE TABLE IF NOT EXISTS comms_meeting_delivery(meeting_id uuid NOT NULL REFERENCES comms_meetings(id),user_id uuid NOT NULL REFERENCES users(id),version integer NOT NULL,kind text NOT NULL,delivered_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(meeting_id,user_id,version,kind));`,
  );
}
// Uses the canonical notification inbox/outbox, including its quiet hours and delivery-time ACLs.
export function createMeetingDelivery({
  pool,
  notifications,
  authorizeConversation,
}) {
  async function changed(db, meeting, kind = "updated") {
    if (!notifications) return;
    const source = meeting.source_conversation_id || meeting.conversation_id;
    const attendees = (
      await db.query(
        "SELECT user_id FROM comms_meeting_attendees WHERE meeting_id=$1 AND ($2<>'reminder' OR rsvp<>'declined')",
        [meeting.id, kind],
      )
    ).rows;
    for (const { user_id } of attendees) {
      try {
        const actor = await loadActor(db, {
          userId: user_id,
          companyId: meeting.company_id,
        });
        await authorizeConversation(db, actor, source, {
          capability: "communications.calls",
        });
      } catch (error) {
        if ([400, 403, 404].includes(error.status)) continue;
        throw error;
      }
      const inserted = await db.query(
        "INSERT INTO comms_meeting_delivery(meeting_id,user_id,version,kind) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING meeting_id",
        [meeting.id, user_id, meeting.version, kind],
      );
      if (!inserted.rowCount) continue;
      await notifications.enqueue(db, {
        userId: user_id,
        companyId: meeting.company_id,
        kind: "comms.meeting_" + kind,
        title:
          kind === "reminder"
            ? "Meeting starts soon"
            : kind === "canceled"
              ? "Meeting canceled"
              : "Meeting invitation updated",
        body:
          kind === "reminder"
            ? "An eligible meeting starts within 15 minutes. Open Calls & Meetings."
            : "Open Calls & Meetings to review this update.",
        conversationId: source,
        data: { meeting_id: meeting.id },
        requirements: ["communications.view", "communications.calls"],
        eventKey: `meeting:${meeting.id}:${meeting.version}:${kind}`,
      });
    }
  }
  async function tick() {
    if (!notifications) return;
    return transact(pool, async (db) => {
      const meetings = (
        await db.query(
          "SELECT m.* FROM comms_meetings m WHERE m.status='scheduled' AND m.starts_at>now() AND m.starts_at<=now()+interval '15 minutes' AND EXISTS(SELECT 1 FROM comms_meeting_attendees a WHERE a.meeting_id=m.id AND a.rsvp<>'declined' AND NOT EXISTS(SELECT 1 FROM comms_meeting_delivery d WHERE d.meeting_id=m.id AND d.user_id=a.user_id AND d.version=m.version AND d.kind='reminder')) ORDER BY m.starts_at LIMIT 20 FOR UPDATE OF m SKIP LOCKED",
        )
      ).rows;
      for (const m of meetings) await changed(db, m, "reminder");
      return { checked: meetings.length };
    });
  }
  return { changed, tick };
}
