import apn from "@parse/node-apn";
export function createCallPush({ pool, getApnProvider, env = process.env }) {
  if (
    !getApnProvider ||
    !env.APNS_BUNDLE_ID ||
    !env.APNS_KEY_P8 ||
    !env.APNS_KEY_ID ||
    !env.APNS_TEAM_ID
  )
    return null;
  return async (call, userId) => {
    const devices = (
      await pool.query(
        `SELECT d.token,d.environment FROM comms_voip_devices d JOIN users u ON u.id=d.user_id WHERE d.user_id=$1 AND u.company_id=$2 AND u.deleted_at IS NULL`,
        [userId, call.company_id],
      )
    ).rows;
    for (const device of devices) {
      const provider = getApnProvider(device.environment);
      if (!provider) throw new Error("apns_not_configured");
      const note = new apn.Notification();
      note.topic = env.APNS_BUNDLE_ID + ".voip";
      note.pushType = "voip";
      note.priority = 10;
      note.expiry = 0;
      note.payload = {
        type: "comms_call",
        call_id: call.id,
        has_video: call.media === "video",
        expires_at: new Date(call.expires_at).toISOString(),
      };
      const result = await provider.send(note, device.token);
      if (result.failed?.length) {
        if (
          result.failed.some(
            (f) => f.status === "410" || f.response?.reason === "Unregistered",
          )
        )
          await pool.query("DELETE FROM comms_voip_devices WHERE token=$1", [
            device.token,
          ]);
        else throw new Error("apns_delivery_failed");
      }
    }
  };
}
