import {
  AccessToken,
  AgentDispatchClient,
  RoomServiceClient,
  WebhookReceiver,
  EgressClient,
  StartEgressRequest,
  TrackSource,
} from "livekit-server-sdk";
import { CallError } from "./domain.js";
// All credentials and administrative provider privileges remain on this server.
export function createLiveKitProvider(env = process.env) {
  const configured = Boolean(
    env.LIVEKIT_URL && env.LIVEKIT_API_KEY && env.LIVEKIT_API_SECRET,
  );
  const endpoint = (env.LIVEKIT_URL || "")
    .replace(/^wss:/, "https:")
    .replace(/^ws:/, "http:");
  const client = configured
    ? new RoomServiceClient(
        endpoint,
        env.LIVEKIT_API_KEY,
        env.LIVEKIT_API_SECRET,
        { requestTimeout: 10000 },
      )
    : null;
  const agentDispatch = configured
    ? new AgentDispatchClient(
        endpoint,
        env.LIVEKIT_API_KEY,
        env.LIVEKIT_API_SECRET,
        { requestTimeout: 10000 },
      )
    : null;
  const egress = configured
    ? new EgressClient(endpoint, env.LIVEKIT_API_KEY, env.LIVEKIT_API_SECRET, {
        requestTimeout: 15000,
      })
    : null;
  const recordingConfigured =
    configured &&
    Boolean(
      env.COMMS_RECORDING_S3_ENDPOINT &&
        env.COMMS_RECORDING_S3_BUCKET &&
        env.COMMS_RECORDING_S3_ACCESS_KEY &&
        env.COMMS_RECORDING_S3_SECRET,
    );
  const ignoreGone = async (fn) => {
    try {
      return await fn();
    } catch (error) {
      if (error.code === "not_found" || error.status === 404) return null;
      throw error;
    }
  };
  const containsValue = (value, match) =>
    value === match ||
    (value &&
      typeof value === "object" &&
      Object.values(value).some((v) => containsValue(v, match)));
  const ready = () => {
    if (!configured)
      throw new CallError(
        503,
        "calling_not_configured",
        "Calling is not configured.",
      );
  };
  const findRecording = async (call, recording) => {
    ready();
    return (await egress.listEgress({ roomName: call.room_name })).find(
      (info) =>
        containsValue(info.toJson ? info.toJson() : info, recording.object_key),
    );
  };
  return {
    configured,
    findRecording,
    recordingConfigured,
    async captionDispatches(call) {
      ready();
      return agentDispatch.listDispatch(call.room_name);
    },
    async startCaptions(call, run) {
      ready();
      const metadata = JSON.stringify({ caption_run_id: run.id });
      const existing = (await agentDispatch.listDispatch(call.room_name)).find(
        (d) => d.agentName === "wolf-comms-captions" && d.metadata === metadata,
      );
      return (
        existing ||
        agentDispatch.createDispatch(call.room_name, "wolf-comms-captions", {
          metadata,
        })
      );
    },
    async stopCaptions(call, dispatchId) {
      ready();
      return ignoreGone(() =>
        agentDispatch.deleteDispatch(dispatchId, call.room_name),
      );
    },
    async token(call, participant) {
      ready();
      const token = new AccessToken(
        env.LIVEKIT_API_KEY,
        env.LIVEKIT_API_SECRET,
        {
          identity: participant.identity,
          name: String(participant.display_name || "Team member").slice(0, 100),
          ttl: "2m",
        },
      );
      token.addGrant({
        room: call.room_name,
        roomJoin: true,
        canPublish: true,
        canSubscribe: true,
        canPublishData: false,
        canUpdateOwnMetadata: false,
        canPublishSources: [
          TrackSource.MICROPHONE,
          TrackSource.CAMERA,
          ...(participant.can_screen_share ? [TrackSource.SCREEN_SHARE] : []),
        ],
      });
      return {
        url: env.LIVEKIT_URL,
        token: await token.toJwt(),
        expires_in: 120,
      };
    },
    async create(call, capacity) {
      ready();
      return client.createRoom({
        name: call.room_name,
        maxParticipants: capacity,
        emptyTimeout: 60,
        departureTimeout: 45,
      });
    },
    async remove(call, identity) {
      ready();
      return ignoreGone(() =>
        client.removeParticipant(call.room_name, identity, {
          revokeTokenTs: BigInt(Math.floor(Date.now() / 1000) + 1),
        }),
      );
    },
    async close(call) {
      ready();
      return ignoreGone(() => client.deleteRoom(call.room_name));
    },
    async participants(call) {
      ready();
      return (
        (await ignoreGone(() => client.listParticipants(call.room_name))) || []
      );
    },
    async restrict(call, identity, { canPublish, canScreenShare = true }) {
      ready();
      return client.updateParticipant(call.room_name, identity, {
        permission: {
          canPublish,
          canSubscribe: true,
          canPublishData: false,
          canUpdateMetadata: false,
          canPublishSources: [
            TrackSource.MICROPHONE,
            TrackSource.CAMERA,
            ...(canScreenShare ? [TrackSource.SCREEN_SHARE] : []),
          ],
        },
      });
    },
    async mute(call, identity) {
      ready();
      const participant = await ignoreGone(() =>
        client.getParticipant(call.room_name, identity),
      );
      for (const track of participant?.tracks || [])
        if (track.source === TrackSource.MICROPHONE)
          await client.mutePublishedTrack(
            call.room_name,
            identity,
            track.sid,
            true,
          );
    },
    async webhook(body, authorization) {
      ready();
      return new WebhookReceiver(
        env.LIVEKIT_API_KEY,
        env.LIVEKIT_API_SECRET,
      ).receive(body, authorization);
    },
    async record(call, recording) {
      ready();
      if (!recordingConfigured)
        throw new CallError(503, "recording_storage_unavailable");
      const existing = await findRecording(call, recording);
      if (existing) return existing;
      const json = {
        room_name: call.room_name,
        template:
          recording.media === "audio"
            ? { audio_only: true }
            : { layout: "grid" },
        outputs: [
          {
            file: {
              filepath: recording.object_key,
              file_type: recording.media === "audio" ? "OGG" : "MP4",
            },
          },
        ],
        storage: {
          s3: {
            access_key: env.COMMS_RECORDING_S3_ACCESS_KEY,
            secret: env.COMMS_RECORDING_S3_SECRET,
            bucket: env.COMMS_RECORDING_S3_BUCKET,
            endpoint: env.COMMS_RECORDING_S3_ENDPOINT,
            region: env.COMMS_RECORDING_S3_REGION || "auto",
            force_path_style: true,
            metadata: { "wolf-recording-id": recording.id },
          },
        },
      };
      return egress.startEgress(StartEgressRequest.fromJson(json));
    },
    async stopRecording(id) {
      ready();
      return ignoreGone(() => egress.stopEgress(id));
    },
    async recordings(call) {
      ready();
      return egress.listEgress({ roomName: call.room_name });
    },
  };
}
