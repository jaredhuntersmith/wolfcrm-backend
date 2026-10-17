# Riley / Retell

Official docs verified 2026-10-17:
- https://docs.retellai.com/build/single-multi-prompt/mcp (Streamable HTTP, request headers, tool selection)
- https://docs.retellai.com/features/secure-webhook (raw bytes, webhook-badged API key, SDK verification)
- https://docs.retellai.com/features/webhook-overview (10-second response, three retries, call ID/event dedupe)

## Configuration
`RETELL_ENABLED=true` enables the integration; `MCP_ENABLED=true` is also required.
`RETELL_ENCRYPTION_KEY` is a durable random 32-byte base64 AES key stored in Railway.
Back it up securely. Replacing it without re-encrypting stored webhook secrets makes
those secrets unreadable. It is NOT the Retell API key or the MCP service key.
Existing MCP HTTPS origin/host validation and ChatGPT OAuth settings are unchanged.
No Retell browser Origin needs allowlisting: Retell calls server-to-server. Optional
IP restriction is deliberately not enabled because trusted Railway proxy hops have
not been established. Official SDK signature verification is mandatory.

Owner configuration: Web Settings → AI Connections → Riley. Enter the agent ID and
Retell's API key marked with the webhook badge directly into the password field.
The provider key is encrypted with company-bound authenticated encryption. Create a
separate Wolf service key, choose its expiry (1–365 days), and copy its Authorization
value directly into Retell. Clear the display afterward; it also clears in two minutes.
The service key is shown once and only its SHA-256 hash/prefix is persisted. Rotation
invalidates the old key immediately. Revocation stops tools and queued reporting.

Booking starts disabled. Configure ZIP service area, quote weekday/hours, visit
length, notice, horizon, increments, travel padding and workers explicitly. Travel
padding is a fixed policy, not a live routing estimate. The address must end in a US
ZIP. Jobs reuse Schedule's current booking policy, timezone and crew qualifications.
Choose Riley-only quote-acceptance and deposit requirements explicitly. A required
deposit needs a published agreement defining its amount and confirmed payment.
New direct work without an agreement can book only when both requirements are off
and an owner-authored profile matches the exact saved services, property type,
maximum stories/window count and fixed total duration. Issued agreement obligations
always remain in force. No other booking flow is weakened. A change to
Schedule booking policy requires re-saving the Riley acknowledgement. Profiles do not infer time from unknown property details. Missing policy, duration,
staffing or schedule rules returns configuration_required; out-of-profile properties
require a quote visit. Profiles start empty and test fixtures are never defaults.
Owner must separately check automatic-booking authorization and save.

## Retell setup
MCP URL: https://wolfcrm-backend-production.up.railway.app/mcp
Retell agent → MCPs → Add MCP → name Wolf CRM → URL above → header Authorization
with the copied Bearer value. Never put the secret in the URL, prompt or dynamic
variables. Select all three tools: check_quote_availability, check_job_availability,
create_appointment. A 10-second timeout is supported; client timeouts must retry the
exact same booking payload with the same call_id as idempotency_key.

Set agent webhook to https://wolfcrm-backend-production.up.railway.app/retell/webhook
and subscribe to call_analyzed. Custom analysis fields: call_outcome,
services_requested, property_address, appointment_type, appointment_id,
appointment_start, appointment_status, call_summary. Use lead_id (a Wolf contact ID)
in retell_llm_dynamic_variables when known. Never substitute an opportunity ID.
Calls without a lead ID are logged without guessing a customer; foreign/invalid IDs
are held for review and cannot modify another account. Analysis text is untrusted.
A claimed confirmation is stored as reported text; actual confirmation comes only
from this connection's saved booking for that call ID.

Riley prompt guidance: collect a full address ending in ZIP; call availability before
booking; use exact returned slot_id and the same customer/service details. Supply dynamic lead_id and address, services (saved names or IDs), property_type,
stories and window_count when required by the profile. Both availability tools return
eligibility.quote_visit, eligibility.direct_job, recommended_path and configuration
requirements. Missing/foreign lead IDs never resolve to an unrelated customer.
check_job_availability returns direct-job slots only for an eligible lead. Only say booked
when status is confirmed. pending_approval means no time is reserved. A fresh booking
attempt after changing inputs needs a distinct intended operation; do not blindly
change idempotency keys after a timeout. Ask the business to review unclear results.
All output dates include America/New_York offsets; range <=14 days and <=30 slots.
Responses are bounded below 15,000 characters.

Refresh Retell's tool list/re-add tools after schema changes. ChatGPT continues to
use OAuth; its tools and approval semantics are unchanged. No outbound trigger or
create-phone-call operation is installed. A real own-number test is required before
a future outbound-calling feature can be enabled.

## Persistence, safety and rollback
installRetellSchema is additive/idempotent: five retell_* tables and two provider
columns/index on existing phone_calls. Back up and restore-test PostgreSQL before
release. Slots expire in 15 minutes. Requests are durable, company/connection bound,
and compare input hashes. Booking uses the existing advisory lock and canonical
calendar constraints/workflows. Pending requests are reviewed in owner settings;
marking reviewed does not schedule anything. Call events are safely persisted before
202, then processed in locked transactions; five failures become review_required.
Do not automatically requeue a foreign-lead or revoked-connection event.

Rollback: RETELL_ENABLED=false with redeploy stops service tools and intake. Revoke
individual connections to stop their access. Keep additive tables/audit and the
enciphering key; do not restore an old database over new production writes. Roll back
the backend/web deployment if necessary; keep automatic publisher disabled and align
its receipt/source before the next reviewed release. OAuth continues independently.

Validation: npm run test:retell, npm run test:mcp, npm run test:agreement-booking:db,
npm test. All test writes use disposable PostgreSQL fixtures. Real client/call
verification requires the owner's Retell account and must be reported separately.

Full machine-readable input/output JSON Schemas: docs/retell/TOOLS.json in the iOS repository. Slot-bound facts are revalidated at save; callers may repeat them in create_appointment but cannot change them while keeping a slot. Only confirmed means a saved appointment. Other results reserve no time.
