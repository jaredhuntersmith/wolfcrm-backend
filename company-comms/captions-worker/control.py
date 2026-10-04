"""Fail-closed caption lease protocol. No SDK, media, transcript persistence or credentials in logs."""
from __future__ import annotations
import asyncio
import json
import math
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

AGENT_NAME = "wolf-comms-captions"
MAX_PARTICIPANTS = 100
MAX_LEASE_SECONDS = 3.0
MAX_RUN_SECONDS = 7200.0
MAX_PAUSE_SECONDS = 30.0

class CaptionStop(Exception):
    """Only fixed reason codes are exposed; provider/HTTP content is never included."""


def canonical_uuid(value: Any) -> str:
    if not isinstance(value, str) or len(value) != 36:
        raise CaptionStop("invalid_identifier")
    try:
        result = str(UUID(value))
    except (ValueError, AttributeError):
        raise CaptionStop("invalid_identifier") from None
    if result != value.lower():
        raise CaptionStop("invalid_identifier")
    return result


def run_from_metadata(raw: str) -> str:
    if not isinstance(raw, str) or len(raw) > 256:
        raise CaptionStop("invalid_dispatch")
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        raise CaptionStop("invalid_dispatch") from None
    if not isinstance(value, dict) or set(value) != {"caption_run_id"}:
        raise CaptionStop("invalid_dispatch")
    return canonical_uuid(value["caption_run_id"])


def agent_identity(run_id: str) -> str:
    return "cc_" + canonical_uuid(run_id).replace("-", "")


@dataclass(frozen=True)
class Config:
    api_url: str
    worker_secret: str = field(repr=False)

    @classmethod
    def from_env(cls, env: Any) -> "Config":
        origin = env.get("WOLFCRM_COMMS_API_URL", "").rstrip("/")
        try:
            url = urlsplit(origin)
            _ = url.port
        except ValueError:
            raise CaptionStop("invalid_backend_origin") from None
        local = env.get("WOLFCRM_CAPTIONS_ALLOW_LOCAL_HTTP") == "1" and url.hostname in {"127.0.0.1", "localhost", "::1"}
        if (url.scheme != "https" and not (url.scheme == "http" and local)) or not url.hostname or url.username or url.password or url.path or url.query or url.fragment:
            raise CaptionStop("invalid_backend_origin")
        secret = env.get("COMMS_CAPTIONS_WORKER_SECRET", "")
        if not isinstance(secret, str) or len(secret) < 32 or "\n" in secret or "\r" in secret:
            raise CaptionStop("missing_worker_secret")
        if env.get("LIVEKIT_AGENT_NAME_OVERRIDE", AGENT_NAME) != AGENT_NAME:
            raise CaptionStop("invalid_agent_name_override")
        return cls(origin, secret)


def bounded_identity(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 200 or any(ord(char) < 33 or ord(char) == 127 for char in value):
        raise CaptionStop("invalid_participant")
    return value


@dataclass(frozen=True)
class Lease:
    run_id: str
    call_id: str
    room_name: str
    participants: frozenset[str]
    recipients: tuple[str, ...]
    expires_at: float
    run_deadline: float

    @classmethod
    def parse(cls, payload: Any, *, run_id: str, room_name: str, requested_at: float, now: float, previous: "Lease | None" = None) -> "Lease":
        if not isinstance(payload, dict) or payload.get("active") is not True:
            raise CaptionStop("lease_inactive")
        if canonical_uuid(payload.get("run_id")) != run_id or payload.get("agent_identity") != agent_identity(run_id) or payload.get("room_name") != room_name:
            raise CaptionStop("lease_scope_mismatch")
        if payload.get("status") not in {"starting", "active"}:
            raise CaptionStop("lease_inactive")
        call_id = canonical_uuid(payload.get("call_id"))
        if previous and call_id != previous.call_id:
            raise CaptionStop("lease_scope_mismatch")
        duration, remaining = payload.get("lease_seconds"), payload.get("remaining_seconds")
        if type(duration) not in (int, float) or type(remaining) not in (int, float) or not math.isfinite(duration) or not math.isfinite(remaining) or not 0 < duration <= MAX_LEASE_SECONDS or remaining <= 0:
            raise CaptionStop("invalid_lease_duration")
        raw_participants, raw_recipients = payload.get("participants"), payload.get("recipients")
        if not isinstance(raw_participants, list) or not 1 <= len(raw_participants) <= MAX_PARTICIPANTS or not isinstance(raw_recipients, list) or not 1 <= len(raw_recipients) <= MAX_PARTICIPANTS:
            raise CaptionStop("empty_or_oversized_audience")
        identities = [bounded_identity(person.get("identity")) for person in raw_participants if isinstance(person, dict)]
        recipients = tuple(bounded_identity(value) for value in raw_recipients)
        if len(identities) != len(raw_participants) or len(set(identities)) != len(identities) or len(set(recipients)) != len(recipients) or not set(recipients).issubset(identities) or agent_identity(run_id) in identities:
            raise CaptionStop("invalid_audience")
        deadline = min(requested_at + min(remaining, MAX_RUN_SECONDS), previous.run_deadline if previous else math.inf)
        expires = min(requested_at + duration, deadline)
        if expires <= now:
            raise CaptionStop("lease_expired")
        return cls(run_id, call_id, room_name, frozenset(identities), recipients, expires, deadline)


class CaptionController:
    """One job, one claimed worker, bounded renewal and no offline continuation."""
    def __init__(self, client: Any, adapter: Any, run_id: str, room_name: str, *, clock=time.monotonic, worker_id: str | None = None):
        self.client, self.adapter = client, adapter
        self.run_id, self.room_name = canonical_uuid(run_id), room_name
        self.worker_id = worker_id or str(uuid4())
        self.clock = clock
        self.lease: Lease | None = None
        self.stopped = asyncio.Event()
        self.failure_code: str | None = None
        self.pause_since: float | None = None
        self.run_deadline = self.clock() + MAX_RUN_SECONDS
        self.generation = 0
        self.stop_reason: str | None = None
        self.bound_call_id: str | None = None

    def current(self) -> Lease | None:
        if self.stopped.is_set() or self.lease is None or self.clock() >= self.lease.expires_at:
            return None
        return self.lease

    def stop(self, reason: str, failure_code: str | None = None) -> None:
        if not self.stopped.is_set():
            self.stop_reason, self.failure_code = reason, failure_code
            self.stopped.set()
            self.lease = None
            self.adapter.stop_capture()  # Synchronous unsubscribe/input disable before cleanup awaits.

    def pause(self, reason: str) -> None:
        if self.pause_since is None:
            self.pause_since = self.clock()
        self.lease = None
        self.generation += 1
        self.adapter.stop_capture()

    async def renew(self) -> None:
        requested_at = self.clock()
        try:
            response = await self.client.lease(self.run_id, self.worker_id)
            if self.stopped.is_set():
                return
            if isinstance(response, dict) and response.get("active") is False and response.get("status") in {"consent", "starting"}:
                self.pause("consent_pending")
                await self.adapter.reconcile()
                return
            lease = Lease.parse(response, run_id=self.run_id, room_name=self.room_name, requested_at=requested_at, now=self.clock(), previous=self.lease)
            if self.bound_call_id and self.bound_call_id != lease.call_id:
                raise CaptionStop("lease_scope_mismatch")
            self.bound_call_id = lease.call_id
            self.run_deadline = min(self.run_deadline, lease.run_deadline)
            if self.clock() >= self.run_deadline:
                self.stop("run_expired")
                return
            if self.lease and (self.lease.participants != lease.participants or self.lease.recipients != lease.recipients):
                self.pause("audience_changed")
            self.lease, self.pause_since = lease, None
            await self.adapter.connect()
            await self.adapter.reconcile()
        except asyncio.CancelledError:
            raise
        except CaptionStop as error:
            self.stop(str(error))
        except Exception:
            self.pause("lease_request_failed")
            await self.adapter.reconcile()

    async def _renew_loop(self) -> None:
        while not self.stopped.is_set():
            await self.renew()
            await asyncio.sleep(1)

    async def _expiry_loop(self) -> None:
        while not self.stopped.is_set():
            now = self.clock()
            if now >= self.run_deadline:
                self.stop("run_expired")
            elif self.pause_since is not None and now - self.pause_since >= MAX_PAUSE_SECONDS:
                self.stop("caption_recovery_expired", "caption_worker_failed")
            elif self.lease is not None and now >= self.lease.expires_at:
                self.pause("lease_expired")
            await asyncio.sleep(0.05)

    async def serve(self) -> None:
        tasks = [asyncio.create_task(self._renew_loop()), asyncio.create_task(self._expiry_loop())]
        for task in tasks:
            task.add_done_callback(self._background_done)
        try:
            await self.stopped.wait()
        finally:
            self.stop(self.stop_reason or "job_shutdown")
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await self.adapter.close()
            if self.failure_code:
                try:
                    await self.client.failure(self.run_id, self.worker_id, self.failure_code)
                except Exception:
                    pass  # Backend's missed-lease watchdog also terminates a silent worker.

    def _background_done(self, task: asyncio.Task) -> None:
        if not task.cancelled() and task.exception() is not None:
            self.stop("caption_worker_failed", "caption_worker_failed")
