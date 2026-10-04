"""Fixed-origin HTTPS backend calls. No retries, redirects, credential logging or transcript upload."""
from __future__ import annotations
import json
import aiohttp
from control import CaptionStop, Config

class BackendClient:
    def __init__(self, config: Config):
        self.config = config
        self.session: aiohttp.ClientSession | None = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=0.9), trust_env=False)
        return self

    async def __aexit__(self, *_):
        await self.session.close()

    async def _post(self, route: str, body: dict):
        if self.session is None:
            raise CaptionStop("backend_not_open")
        async with self.session.post(self.config.api_url + "/api/comms/captions/worker/" + route, json=body,
                                     headers={"Authorization": "Bearer " + self.config.worker_secret}, allow_redirects=False) as response:
            if response.status >= 500 or response.status == 429:
                raise ConnectionError("backend_temporarily_unavailable")
            if response.status != 200:
                raise CaptionStop("lease_denied")
            payload = bytearray()
            async for chunk in response.content.iter_chunked(4096):
                payload.extend(chunk)
                if len(payload) > 32768:
                    raise CaptionStop("oversized_lease_response")
            try:
                return json.loads(payload)
            except (ValueError, UnicodeError):
                raise CaptionStop("invalid_lease_response") from None

    async def lease(self, run_id: str, worker_id: str):
        return await self._post("lease", {"run_id": run_id, "worker_id": worker_id})

    async def failure(self, run_id: str, worker_id: str, code: str):
        if code not in {"stt_unavailable", "caption_worker_failed"}:
            raise CaptionStop("invalid_failure_code")
        return await self._post("failure", {"run_id": run_id, "worker_id": worker_id, "code": code})
