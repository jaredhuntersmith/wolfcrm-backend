import { randomUUID } from "node:crypto";
// Provider events can arrive out of order. Finalization never moves backwards to active capture.
export async function observeRecording(
  db,
  call,
  recording,
  info,
  publish = async () => {},
) {
  if (
    !["starting", "recording", "stopping", "processing"].includes(
      recording.status,
    )
  )
    return false;
  let changed = false;
  if (info.status === 1 && recording.status === "starting") {
    await db.query(
      "UPDATE comms_call_recordings SET status='recording',started_at=COALESCE(started_at,now()) WHERE id=$1",
      [recording.id],
    );
    changed = true;
  } else if (info.status === 3 && recording.status !== "processing") {
    await db.query(
      "UPDATE comms_call_recordings SET status='processing',ended_at=COALESCE(ended_at,now()) WHERE id=$1",
      [recording.id],
    );
    await db.query(
      "INSERT INTO comms_call_jobs(id,call_id,kind,payload) VALUES($1,$2,'adopt_recording',$3)",
      [
        randomUUID(),
        call.id,
        {
          id: recording.id,
          size: String(info.fileResults?.[0]?.size || 0),
          duration: String(info.fileResults?.[0]?.duration || 0),
        },
      ],
    );
    changed = true;
  } else if (
    [4, 5, 6].includes(info.status) &&
    recording.status !== "processing"
  ) {
    await db.query(
      "UPDATE comms_call_recordings SET status='failed',error_code=$2,ended_at=COALESCE(ended_at,now()) WHERE id=$1",
      [recording.id, "provider_" + info.status],
    );
    changed = true;
  }
  if (changed)
    await publish(
      db,
      { companyId: call.company_id, userId: call.host_user_id },
      call.conversation_id,
      "call.recording_updated",
      call.id,
      { call_id: call.id },
    );
  return changed;
}
