# Optional live caption worker

This is the real, explicitly dispatched LiveKit speech-to-text worker for Company Comms. It is disabled until the backend, owner settings, worker service and LiveKit Inference access are configured. No deployment, live STT request, paid traffic or physical-device caption test has been performed.

The implementation follows LiveKit's [multi-user transcription example](https://github.com/livekit/agents/blob/main/examples/other/transcription/multi-user-transcriber.py), [explicit agent dispatch](https://docs.livekit.io/agents/server/agent-dispatch/) and [session events](https://docs.livekit.io/reference/agents/events/), with additional WolfCRM consent and delivery boundaries. The verified SDK is [livekit-agents 1.8.4](https://pypi.org/project/livekit-agents/1.8.4/). It runs one STT-only session per authorized microphone using LiveKit Inference `deepgram/nova-3`; no LLM or TTS is instantiated. Dependency packages may include those APIs because they are dependencies of the official SDK.

## Install and test locally

Use Python 3.13 in an isolated virtual environment. `requirements.in` lists exact direct dependencies. `requirements.lock` pins the full resolved environment verified on macOS arm64/Python 3.13.7; Linux packaging must be smoke-tested in the intended deployment image before rollout. No package is installed globally.

```sh
python3.13 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s . -p 'test_*.py' -v
```

All 24 tests pass with the actual pinned SDK imported and fake media, speech and HTTP boundaries. Tests do not connect a worker, join a room or call a speech provider. The control-only subset requires only Python's standard library: `python3 -m unittest test_control -v`.

## Authorized setup and launch

Deploying or enabling services requires separate authorization. After approval, configure the backend's existing LiveKit connection, `COMMS_CAPTIONS_ENABLED=true` and a new high-entropy `COMMS_CAPTIONS_WORKER_SECRET` of at least 32 characters. Set the same secret only in the isolated worker service environment, together with `WOLFCRM_COMMS_API_URL`, `LIVEKIT_URL`, `LIVEKIT_API_KEY` and `LIVEKIT_API_SECRET` shown in `.env.example`. LiveKit Inference must be available for the project. Do not put service credentials in iOS, the desktop client, source control or room dispatch metadata. The backend origin must use HTTPS with no path, query, fragment or embedded credentials. Explicit localhost HTTP is permitted only with the documented development flag.

From this directory, run:

```sh
.venv/bin/python worker.py start
```

The SDK's `dev` process mode is also accepted for a separately authorized development service. `console`, `connect`, an overridden agent name and unnamed/automatic room dispatch are rejected. Do not use a generic agent auto-dispatch rule. The sole registered name is `wolf-comms-captions`; no worker is dispatched simply because an idle channel exists. Starting this command connects to the configured LiveKit project and must not be used as a test without authorization. No model-download command or local audio device is needed.

The owner enables captions and a usage limit in Company Comms calling settings. The host requests captions during a call; every active employee participant must consent before audio is subscribed. A new unconsented participant pauses all captions. Guests currently prevent captioning because guest consent is not implemented. Captions are an ephemeral aid; they are not a saved transcript or a recording.

## Lease and privacy contract

Dispatch metadata contains only `{ "caption_run_id": "UUID" }`. The worker accepts that exact shape, uses identity `cc_` plus the run UUID without hyphens, and checks the authoritative room name and actual connected agent identity. Its grant cannot publish audio or video. It connects using `AutoSubscribe.SUBSCRIBE_NONE` and explicitly subscribes only to one microphone track per authorized participant; camera, screen audio and unknown participant tracks stay unsubscribed.

`POST /api/comms/captions/worker/lease` uses the worker bearer secret and `{run_id,worker_id}`. One generated worker UUID claims the run. The active response includes `active`, `status`, `run_id`, `call_id`, `room_name`, `agent_identity`, `participants`, `recipients`, `lease_seconds` and `remaining_seconds`. The backend rechecks company, employee status, conversation/source access, consent and budget for each renewal. `remaining_seconds` includes the currently reserved lease. This is a server service boundary; employee tokens do not authorize it.

Renewal occurs every second; every lease is at most three seconds measured from request start, so HTTP latency cannot extend it. Consent withdrawal, audience changes, failed renewal or lease expiry disable audio, unsubscribe tracks, cancel any pending caption stream, discard queued text and reject late events. The expiry guard checks every 50 milliseconds; ordinary process scheduling and already delivered network packets cannot be recalled. Only fresh authorization can resume. Transient HTTP 429/5xx/network failure pauses immediately; the pause/recovery window is at most 30 seconds. Persistent failure ends the worker and reports a fixed failure code. Local run duration cannot exceed two hours and cannot be extended by renewal or pauses; the backend may impose a shorter budget. All subjects must consent again according to server state after changes.

SDK session recording and hosted session inspection are disabled (`record=False`, `session_host=False`). Text input, built-in text/audio output, video input and pre-connect audio are disabled. Python logging is suppressed inside the media subprocess because provider errors can contain private input. The worker does not write audio/transcripts to files, SQL, logs or the WolfCRM API. LiveKit/STT infrastructure necessarily processes authorized audio; provider account policy and real deployment retention behavior require separate review. Deepgram model-improvement opt-out is requested in the inference options.

The worker publishes `lk.transcription` text streams only with a nonempty explicit list of current authorized destination identities. It never uses the SDK's broadcast default. Attributes carry the actual microphone track SID, participant identity, caption run, stable segment ID and final flag. Native rendering independently verifies the server-provided agent/run identity and maps speaker names from trusted server state. Queue size, text length, participants and event-reconciliation tasks are bounded. Text is ephemeral and revocation cannot erase a caption already seen by its authorized recipient.

`POST /api/comms/captions/worker/failure` reports only `{run_id,worker_id,code}`, where `code` is `stt_unavailable` or `caption_worker_failed`. The server's missed-lease watchdog, dispatch deletion and strict agent removal cover disconnected or failed workers. No raw provider error is uploaded.

## Required live acceptance

After separately authorized setup, verify two physical iPhones and the real worker: explicit host start and every participant's consent; exact agent identity and speaker mapping; a participant without transcription permission receives no text; late join pauses; consent/feature/source revocation stops capture and delivery; lease loss and STT failure become truthful failure states; budget exhaustion stops the worker; stop/call end removes the agent; no session recordings, transcripts or sensitive logs appear in the deployed provider/service configuration. Measure observed revocation latency and reconnect behavior. These checks remain unverified.
