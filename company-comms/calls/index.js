import express from "express";
import { installCaptionSchema } from "./caption-schema.js";
import { createCaptionService } from "./captions.js";
import {
  installMeetingDeliverySchema,
  createMeetingDelivery,
} from "./meeting-reminders.js";
import { installGuestSchema, createGuestService } from "./guests.js";
import { installRateLimits, takeRateLimit } from "../rate-limits.js";
import {
  installProcessingSchema,
  createProcessingService,
} from "./processing.js";
import { createProcessingProvider } from "./processing-provider.js";
import { installCallsSchema } from "./schema.js";
import { createCallsService } from "./service.js";
import { createLiveKitProvider } from "./provider.js";
import { recordingStorage } from "./storage.js";
import { createCallPush } from "./push.js";
export async function installCommsCalls({
  app,
  pool,
  authRequired,
  authorizeConversation,
  publish,
  resolveActor,
  provider,
  getApnProvider,
  sendIncomingCall,
  notifications,
  adoptRecording,
  startWorker = true,
  processingProvider,
  env = process.env,
}) {
  await installCallsSchema(pool);
  await installCaptionSchema(pool);
  await installGuestSchema(pool);
  await installMeetingDeliverySchema(pool);
  await installRateLimits(pool);
  provider ||= createLiveKitProvider(env);
  adoptRecording ||= recordingStorage(env);
  sendIncomingCall ||= createCallPush({ pool, getApnProvider, env });
  await installProcessingSchema(pool);
  processingProvider ||= createProcessingProvider(env);
  provider.transcriptionConfigured = processingProvider.configured;
  provider.aiConfigured = processingProvider.aiConfigured;
  const meetingDelivery = createMeetingDelivery({
    pool,
    notifications,
    authorizeConversation,
  });
  const service = createCallsService({
    pool,
    provider,
    authorizeConversation,
    publish,
    resolveActor,
    adoptRecording,
    sendIncomingCall,
    meetingDelivery,
    env,
  });
  const guests = createGuestService({
    pool,
    provider,
    authorizeConversation,
    publish,
    env,
  });
  service.guests = guests;
  const captions = createCaptionService({
    pool,
    provider,
    authorizeConversation,
    publish,
    env,
  });
  service.captions = captions;
  const processing = createProcessingService({
    pool,
    calls: service,
    authorizeConversation,
    publish,
    provider: processingProvider,
  });
  const route = (method, path, fn) =>
    app[method]("/api/comms" + path, authRequired, async (req, res) => {
      res.set("Cache-Control", "private, no-store");
      try {
        await takeRateLimit(pool, req);
        res.json(await fn(await service.actorFor(req), req));
      } catch (e) {
        res.status(e.status || 503).json({
          error: e.status ? e.code : "calling_unavailable",
          message: e.status
            ? e.message
            : "Calling is temporarily unavailable. Please retry.",
        });
      }
    });
  route("get", "/calls/:id/captions", (a, r) => captions.get(a, r.params.id));
  route("post", "/calls/:id/captions", (a, r) => {
    if (!["start", "stop"].includes(r.body?.action)) {
      const error = new Error("invalid_caption_action");
      error.status = 400;
      error.code = "invalid_caption_action";
      throw error;
    }
    return r.body.action === "stop"
      ? captions.stop(a, r.params.id)
      : captions.start(a, r.params.id, r.body);
  });
  route("post", "/calls/:id/captions/consent", (a, r) =>
    captions.consent(a, r.params.id, r.body),
  );
  for (const action of ["lease", "failure"])
    app.post("/api/comms/captions/worker/" + action, async (req, res) => {
      res.set("Cache-Control", "no-store");
      try {
        if (!captions.workerAuthorized(req.get("Authorization")))
          return res.status(401).json({ error: "worker_unauthorized" });
        if (
          typeof req.body?.run_id !== "string" ||
          !/^[0-9a-f-]{36}$/i.test(req.body.run_id)
        )
          return res.status(400).json({ error: "invalid_id" });
        await takeRateLimit(pool, req, {
          bucket: "caption_worker:" + req.body.run_id,
          limit: 120,
        });
        res.json(await captions[action](req.body));
      } catch (error) {
        res.status(error.status || 503).json({
          error: error.status ? error.code : "caption_worker_unavailable",
        });
      }
    });
  route("get", "/calls/readiness", (a) => service.diagnostics(a));
  route("get", "/calls/diagnostics", (a, r) =>
    service.ownerDiagnostics(a, r.query),
  );
  route("get", "/calls/settings", (a) => service.getSettings(a));
  route("patch", "/calls/settings", (a, r) =>
    service.updateSettings(a, r.body),
  );
  route("get", "/calls/usage", (a) => service.usage(a));
  route("get", "/calls", (a, r) => service.list(a, r.query));
  route("post", "/calls", (a, r) => service.create(a, r.body));
  route("get", "/calls/context/:id", (a, r) => service.context(a, r.params.id));
  route("get", "/calls/presence", async (a, r) => {
    await takeRateLimit(pool, r, { bucket: "call_presence", limit: 60 });
    return service.presence(
      a,
      typeof r.query.conversation_ids === "string"
        ? r.query.conversation_ids.split(",").filter(Boolean)
        : [],
    );
  });
  route("get", "/calls/:id/invitees", (a, r) =>
    service.inviteCandidates(a, r.params.id),
  );
  route("get", "/calls/:id", (a, r) => service.get(a, r.params.id));
  route("post", "/calls/:id/accept", (a, r) =>
    service.accept(a, r.params.id, r.body),
  );
  route("post", "/calls/:id/join", (a, r) =>
    service.join(a, r.params.id, r.body),
  );
  for (const action of [
    "leave",
    "end",
    "decline",
    "admit",
    "remove",
    "mute",
    "lock",
    "screen-permission",
    "transfer-host",
    "hand",
    "reaction",
    "invite",
  ])
    route("post", "/calls/:id/" + action, (a, r) =>
      service.action(a, r.params.id, action, r.body),
    );
  route("post", "/calls/:id/consent", (a, r) =>
    service.consent(a, r.params.id, r.body),
  );
  route("post", "/calls/:id/recordings", (a, r) =>
    service.recording(a, r.params.id, r.body),
  );
  route("post", "/calls/devices", (a, r) => service.registerDevice(a, r.body));
  route("delete", "/calls/devices/:id", (a, r) =>
    service.unregisterDevice(a, r.params.id),
  );
  route("get", "/meetings/invitees", (a, r) =>
    service.meetingInvitees(a, r.query),
  );
  route("get", "/meetings", (a, r) => service.meetings(a, r.query));
  route("post", "/meetings", (a, r) => service.saveMeeting(a, r.body));
  route("patch", "/meetings/:id", (a, r) =>
    service.saveMeeting(a, r.body, r.params.id),
  );
  route("post", "/meetings/:id/join", (a, r) =>
    service.joinMeeting(a, r.params.id),
  );
  route("post", "/meetings/:id/respond", (a, r) =>
    service.meetingAction(a, r.params.id, r.body),
  );
  route("get", "/recordings/:id", (a, r) =>
    service.recordingMetadata(a, r.params.id),
  );
  route("get", "/recordings/:id/processing", (a, r) =>
    processing.get(a, r.params.id),
  );
  route("post", "/recordings/:id/processing/consent", (a, r) =>
    processing.consent(a, r.params.id, r.body),
  );
  route("post", "/recordings/:id/processing", (a, r) =>
    processing.request(a, r.params.id, r.body),
  );
  route("patch", "/processing/jobs/:id/summary", (a, r) =>
    processing.editSummary(a, r.params.id, r.body),
  );
  route("post", "/processing/actions/:id/review", (a, r) =>
    processing.review(a, r.params.id, r.body),
  );
  route("get", "/recordings/:id/transcript/export", (a, r) =>
    processing.export(a, r.params.id),
  );
  route("delete", "/recordings/:id/processing", (a, r) =>
    processing.remove(a, r.params.id),
  );
  route("post", "/meetings/:id/guests", (a, r) =>
    guests.invite(a, r.params.id, r.body),
  );
  route("get", "/meetings/:id/guests", (a, r) => guests.list(a, r.params.id));
  route("post", "/meetings/:id/guests/:guestID", (a, r) =>
    guests.moderate(a, r.params.id, r.params.guestID, r.body),
  );
  route("delete", "/meetings/:id/guest-invites/:inviteID", (a, r) =>
    guests.revoke(a, r.params.id, r.params.inviteID),
  );
  const guestRoute = (method, path, fn) =>
    app[method]("/api/comms/guest" + path, async (req, res) => {
      res.set("Cache-Control", "private, no-store");
      try {
        await takeRateLimit(pool, req, {
          bucket: path === "/redeem" ? "guest_join" : "guest_session",
          limit: path === "/redeem" ? 12 : 120,
        });
        res.json(await fn(req));
      } catch (e) {
        res.status(e.status || 503).json({
          error: e.status ? e.code : "guest_unavailable",
          message: e.status
            ? e.message
            : "Guest meeting is temporarily unavailable.",
        });
      }
    });
  const guestToken = (req) =>
    /^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.get("Authorization") || "")?.[1];
  guestRoute("post", "/redeem", (r) =>
    guests.redeem(r.body?.token, r.body?.display_name),
  );
  guestRoute("get", "/session", (r) => guests.status(guestToken(r)));
  guestRoute("post", "/token", (r) => guests.token(guestToken(r)));
  guestRoute("post", "/leave", (r) => guests.leave(guestToken(r)));
  app.post(
    "/api/comms/livekit/webhook",
    express.raw({ type: "application/webhook+json", limit: "1mb" }),
    async (req, res) => {
      try {
        if (!Buffer.isBuffer(req.body))
          return res.status(400).json({ error: "raw_body_required" });
        res.json(
          await service.webhook(
            req.body.toString("utf8"),
            req.get("Authorization"),
          ),
        );
      } catch {
        res.status(401).json({ error: "invalid_provider_event" });
      }
    },
  );
  let working = false;
  const tick = async () => {
    if (working) return;
    working = true;
    try {
      for (let i = 0; i < 10; i++) await service.work();
      await service.reconcile();
      await guests.reconcile();
      await meetingDelivery.tick();
      await service.reconcileEgress();
      await captions.reconcile();
    } catch {
      console.error("[comms_calls] reconciliation deferred");
    } finally {
      working = false;
    }
  };
  const timer = startWorker ? setInterval(tick, 3000) : null;
  timer?.unref();
  let processingBusy = false;
  const processingTimer = startWorker
    ? setInterval(async () => {
        if (processingBusy) return;
        processingBusy = true;
        try {
          await processing.runOnce();
        } catch {
          console.error("[comms_processing] worker deferred");
        } finally {
          processingBusy = false;
        }
      }, 10000)
    : null;
  processingTimer?.unref();
  return {
    configured: provider.configured,
    service,
    processing,
    guests,
    captions,
    revokeUser: service.revokeUser,
    stop: () => {
      clearInterval(timer);
      clearInterval(processingTimer);
    },
  };
}
