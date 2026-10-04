"""Explicit, ephemeral LiveKit captions. Never start this process as an automated test."""
from __future__ import annotations
import asyncio
import logging
import os
import sys
from dataclasses import dataclass
from uuid import uuid4
from livekit import rtc
from livekit.agents import Agent, AgentServer, AgentSession, AutoSubscribe, JobContext, JobRequest, StopResponse, WorkerPermissions, cli, inference, room_io
from backend import BackendClient
from control import AGENT_NAME, CaptionController, CaptionStop, Config, agent_identity, run_from_metadata


class Transcriber(Agent):
    def __init__(self):
        # LiveKit Inference uses the server environment credentials. No LLM/TTS,
        # fallback provider, room chat, uploaded audio or transcript persistence.
        super().__init__(instructions="", stt=inference.STT("deepgram/nova-3", extra_kwargs={"mip_opt_out": True}), llm=None, tts=None)

    async def on_user_turn_completed(self, chat_ctx, new_message):
        raise StopResponse()


@dataclass
class Speaker:
    session: AgentSession
    track_id: str
    generation: int
    segment_id: str


class LiveKitAdapter:
    def __init__(self, ctx: JobContext):
        self.ctx = ctx
        self.controller: CaptionController | None = None
        self.connected = False
        self.speakers: dict[str, Speaker] = {}
        self.tasks: set[asyncio.Task] = set()
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=32)
        self.lock = asyncio.Lock()
        self.closed = False
        self.reconcile_task: asyncio.Task | None = None
        self.reconcile_pending = False
        self.publish_task: asyncio.Task | None = None
        self.subscriptions: dict[str, bool] = {}

    async def connect(self):
        if self.connected or self.closed or not self.controller.current():
            return
        try:
            await asyncio.wait_for(self.ctx.connect(auto_subscribe=AutoSubscribe.SUBSCRIBE_NONE), timeout=8)
            self.connected = True
            if self.ctx.room.name != self.controller.room_name or self.ctx.room.local_participant.identity != agent_identity(self.controller.run_id):
                raise CaptionStop("connected_scope_mismatch")
            for event in ("participant_connected", "participant_disconnected", "track_published", "track_unpublished", "track_subscribed", "track_unsubscribed"):
                self.ctx.room.on(event, self._room_changed)
            self.ctx.room.on("disconnected", self._disconnected)
            self._track_task(self._publish_loop())
        except Exception:
            self.controller.stop("caption_worker_failed", "caption_worker_failed")
            raise CaptionStop("caption_worker_failed") from None

    def _track_task(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.tasks.add(task)
        def done(value):
            self.tasks.discard(value)
            if not value.cancelled() and value.exception() is not None:
                self.controller.stop("caption_worker_failed", "caption_worker_failed")
        task.add_done_callback(done)
        return task

    def _room_changed(self, *_):
        if not self.closed:
            self.reconcile_pending = True
            if self.reconcile_task is None or self.reconcile_task.done():
                self.reconcile_task = self._track_task(self._reconcile_events())

    async def _reconcile_events(self):
        while self.reconcile_pending and not self.closed:
            self.reconcile_pending = False
            await self.reconcile()

    def _subscribe(self, publication, enabled):
        if self.subscriptions.get(publication.sid) != enabled:
            self.subscriptions[publication.sid] = enabled
            publication.set_subscribed(enabled)

    def _disconnected(self, *_):
        self.controller.stop("room_disconnected")

    def stop_capture(self):
        if self.publish_task:
            self.publish_task.cancel()
        for speaker in list(self.speakers.values()):
            speaker.session.input.set_audio_enabled(False)
            speaker.session.shutdown(drain=False)
        if self.connected:
            for participant in self.ctx.room.remote_participants.values():
                for publication in participant.track_publications.values():
                    self._subscribe(publication, False)
        while not self.queue.empty():
            self.queue.get_nowait()

    async def reconcile(self):
        if not self.connected or self.closed:
            return
        async with self.lock:
            lease = self.controller.current()
            desired = {}
            present_tracks = {pub.sid for person in self.ctx.room.remote_participants.values() for pub in person.track_publications.values()}
            self.subscriptions = {sid: value for sid, value in self.subscriptions.items() if sid in present_tracks}
            for participant in list(self.ctx.room.remote_participants.values()):
                eligible = lease is not None and participant.identity in lease.participants
                microphones = sorted((pub for pub in participant.track_publications.values() if eligible and pub.kind == rtc.TrackKind.KIND_AUDIO and pub.source == rtc.TrackSource.SOURCE_MICROPHONE), key=lambda pub: pub.sid)
                chosen = microphones[0] if microphones else None
                for publication in participant.track_publications.values():
                    self._subscribe(publication, chosen is not None and publication.sid == chosen.sid)
                if chosen:
                    desired[participant.identity] = chosen.sid
            for identity, speaker in list(self.speakers.items()):
                if desired.get(identity) != speaker.track_id or speaker.generation != self.controller.generation:
                    self.speakers.pop(identity, None)
                    speaker.session.input.set_audio_enabled(False)
                    speaker.session.shutdown(drain=False)
                    await asyncio.wait_for(speaker.session.aclose(), timeout=2)
            for identity, track_id in desired.items():
                if identity not in self.speakers and self.controller.current():
                    await self._start(identity, track_id)

    async def _start(self, identity: str, track_id: str):
        session = AgentSession()
        speaker = Speaker(session, track_id, self.controller.generation, str(uuid4()))
        self.speakers[identity] = speaker
        @session.on("user_input_transcribed")
        def transcribed(event):
            lease = self.controller.current()
            if self.speakers.get(identity) is not speaker or speaker.generation != self.controller.generation or not lease or identity not in lease.participants or not lease.recipients:
                return
            content = event.transcript[:2000]
            if not content:
                return
            segment_id = speaker.segment_id
            if event.is_final:
                speaker.segment_id = str(uuid4())
            try:
                self.queue.put_nowait((identity, track_id, speaker.generation, segment_id, bool(event.is_final), content))
            except asyncio.QueueFull:
                # Bounded memory; never silently present a running but stalled captioner.
                self.controller.stop("caption_worker_failed", "caption_worker_failed")
        @session.on("error")
        def failed(_):
            self.controller.stop("stt_unavailable", "stt_unavailable")
        try:
            await session.start(agent=Transcriber(), room=self.ctx.room, session_host=False, record=False,
                                room_options=room_io.RoomOptions(participant_identity=identity,
                                    audio_input=room_io.AudioInputOptions(pre_connect_audio=False),
                                    video_input=False, text_input=False, audio_output=False, text_output=False))
            if not self.controller.current() or speaker.generation != self.controller.generation:
                session.input.set_audio_enabled(False)
                session.shutdown(drain=False)
        except Exception:
            self.controller.stop("stt_unavailable", "stt_unavailable")
            raise CaptionStop("stt_unavailable") from None

    async def _publish_loop(self):
        while not self.closed:
            identity, track_id, generation, segment_id, final, content = await self.queue.get()
            lease = self.controller.current()
            speaker = self.speakers.get(identity)
            if not lease or not speaker or identity not in lease.participants or generation != self.controller.generation or speaker.track_id != track_id or not lease.recipients:
                continue
            # An empty target list means broadcast in the SDK: it is never permitted.
            recipients = list(lease.recipients)
            timeout = min(0.8, lease.expires_at - self.controller.clock())
            if timeout <= 0:
                continue
            self.publish_task = asyncio.create_task(self.ctx.room.local_participant.send_text(content, topic="lk.transcription", destination_identities=recipients,
                attributes={"lk.transcribed_track_id": track_id, "wolf.participant_identity": identity,
                            "wolf.caption_run_id": lease.run_id, "lk.segment_id": segment_id,
                            "lk.transcription_final": "true" if final else "false"}))
            try:
                await asyncio.wait_for(self.publish_task, timeout=timeout)
            except asyncio.CancelledError:
                if self.closed or asyncio.current_task().cancelling():
                    raise
                # Consent or audience changes cancel only the outstanding text
                # stream. The publisher stays available for a fresh lease.
            finally:
                self.publish_task = None

    async def close(self):
        if self.closed:
            return
        self.closed = True
        self.stop_capture()
        for event in ("participant_connected", "participant_disconnected", "track_published", "track_unpublished", "track_subscribed", "track_unsubscribed"):
            self.ctx.room.off(event, self._room_changed)
        self.ctx.room.off("disconnected", self._disconnected)
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*list(self.tasks), return_exceptions=True)
        sessions = [speaker.session for speaker in self.speakers.values()]
        self.speakers.clear()
        for session in sessions:
            try:
                await asyncio.wait_for(session.aclose(), timeout=2)
            except Exception:
                pass
        if self.connected:
            await self.ctx.room.disconnect()
            self.connected = False


def quiet_sdk_logs():
    # The upstream example logs transcript text; this service never does. Prevent
    # SDK debug transcript messages and external session recording/tracing exports.
    # Provider exceptions can include private input even at WARNING/ERROR. This
    # media subprocess emits no Python logs; fixed failure codes go to Node.
    logging.disable(logging.CRITICAL)


async def accept_job(request: JobRequest):
    try:
        run_id = run_from_metadata(request.job.metadata)
        if request.job.agent_name != AGENT_NAME:
            raise CaptionStop("invalid_agent_name")
    except CaptionStop:
        await request.reject()
        return
    await request.accept(name="WolfCRM live captions", identity=agent_identity(run_id))


server = AgentServer(permissions=WorkerPermissions(can_publish=False, can_subscribe=True, can_publish_data=True, can_update_metadata=False, hidden=False),
                     num_idle_processes=0, job_memory_warn_mb=384, job_memory_limit_mb=512,
                     drain_timeout=10, shutdown_process_timeout=5, log_level="WARN")

@server.rtc_session(agent_name=AGENT_NAME, on_request=accept_job)
async def entrypoint(ctx: JobContext):
    quiet_sdk_logs()
    config = Config.from_env(os.environ)
    run_id = run_from_metadata(ctx.job.metadata)
    adapter = LiveKitAdapter(ctx)
    async with BackendClient(config) as client:
        controller = CaptionController(client, adapter, run_id, ctx.job.room.name)
        adapter.controller = controller
        async def cleanup(*_):
            controller.stop("job_shutdown")
            await adapter.close()
        ctx.add_shutdown_callback(cleanup)
        await controller.serve()
    ctx.shutdown(reason="caption_session_finished")

if __name__ == "__main__":
    try:
        Config.from_env(os.environ)
        if len(sys.argv) < 2 or sys.argv[1] not in {"start", "dev"}:
            raise CaptionStop("use_explicit_dispatch_worker_start")
        if not all(os.environ.get(key) for key in ("LIVEKIT_URL", "LIVEKIT_API_KEY", "LIVEKIT_API_SECRET")):
            raise CaptionStop("missing_livekit_configuration")
    except CaptionStop as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2)
    cli.run_app(server)
