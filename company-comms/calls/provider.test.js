import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { AccessToken, TokenVerifier } from "livekit-server-sdk";
import { createLiveKitProvider } from "./provider.js";
import { validateSummary, validateTranscript } from "./processing.js";

const env = {
  LIVEKIT_URL: "wss://example.invalid",
  LIVEKIT_API_KEY: "local-test-key",
  LIVEKIT_API_SECRET: "local-test-secret-not-a-real-provider-key",
};
test("missing provider configuration is explicit", async () => {
  const p = createLiveKitProvider({});
  assert.equal(p.configured, false);
  await assert.rejects(
    p.token({}, {}),
    (e) => e.code === "calling_not_configured",
  );
});
test("locally signed room token grants only allowed media sources and room scope", async () => {
  const p = createLiveKitProvider(env),
    call = { room_name: "opaque-test-room", media: "audio" },
    member = { identity: "opaque-test-member", can_screen_share: false };
  const result = await p.token(call, member),
    jwt = await new TokenVerifier(
      env.LIVEKIT_API_KEY,
      env.LIVEKIT_API_SECRET,
    ).verify(result.token);
  assert.equal(jwt.sub, member.identity);
  assert.equal(jwt.video.room, call.room_name);
  assert.equal(jwt.video.roomJoin, true);
  assert.equal(jwt.video.canPublishData, false);
  assert.equal(jwt.video.canUpdateOwnMetadata, false);
  assert.deepEqual(jwt.video.canPublishSources, ["microphone", "camera"]);
  assert.equal(jwt.video.roomAdmin, undefined);
  assert.ok(jwt.exp - jwt.nbf <= 120);
  const shared = await new TokenVerifier(
    env.LIVEKIT_API_KEY,
    env.LIVEKIT_API_SECRET,
  ).verify((await p.token(call, { ...member, can_screen_share: true })).token);
  assert.ok(shared.video.canPublishSources.includes("screen_share"));
});
test("webhook validates signed exact raw body and rejects alteration/unsigned replay", async () => {
  const p = createLiveKitProvider(env),
    body = JSON.stringify({
      id: "EV_test",
      event: "room_finished",
      room: { name: "opaque-test-room" },
    }),
    token = new AccessToken(env.LIVEKIT_API_KEY, env.LIVEKIT_API_SECRET, {
      ttl: "1m",
    });
  token.sha256 = createHash("sha256").update(body).digest("base64");
  const signed = await token.toJwt();
  assert.equal((await p.webhook(body, signed)).id, "EV_test");
  await assert.rejects(p.webhook(body + " ", signed));
  await assert.rejects(p.webhook(body, undefined));
});
test("AI output cannot invent evidence IDs or execute ungrounded tasks", () => {
  const segments = [
    {
      id: "0:0",
      start: 0,
      end: 2,
      speaker: "Unknown speaker",
      text: "Please prepare a quote.",
    },
  ];
  validateTranscript({ segments, text: segments[0].text });
  validateSummary(
    {
      summary: "A quote was requested.",
      tasks: [
        {
          title: "Prepare quote",
          detail: "Review first",
          segment_ids: ["0:0"],
        },
      ],
      decisions: [],
      questions: [],
    },
    segments,
  );
  assert.throws(
    () =>
      validateSummary(
        {
          summary: "Do it",
          tasks: [
            { title: "Delete records", detail: "", segment_ids: ["missing"] },
          ],
          decisions: [],
          questions: [],
        },
        segments,
      ),
    (e) => e.code === "summary_evidence_invalid",
  );
  assert.throws(
    () =>
      validateTranscript({
        segments: [{ ...segments[0], start: -1 }],
        text: "x",
      }),
    (e) => e.code === "invalid_transcript_output",
  );
});
