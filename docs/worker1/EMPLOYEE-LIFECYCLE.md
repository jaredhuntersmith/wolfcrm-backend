# Employee lifecycle and protected delivery handoff

2026-10-22, Worker 1, branch `codex/worker1-access-storage`. Depends on capability commit `e14a691` and protected-media commit `ab48b98`.

## Implemented and verified

Additive `installEmployeeAccountSchema` follows existing permission-governance schema. No user rows, names, photos, password hashes or permission grants are deleted on lock/disable. Lock is reversible without a retention timer; disable revokes sessions/tokens and starts a server-authoritative 720-hour private recovery window. Restore uses revision compare-and-swap and keeps operational eligibility off until a current future-job/crew review. Legacy-removed accounts are explicitly marked for review, with no automatic destructive backfill.

Authenticated account routes are owner or explicitly authorized Admin only, exclude self/owner/peer-admin manipulation, and recheck company membership. `GET /api/company/employee-accounts?disabled=true` deliberately opens disabled employees; `GET /api/company/employees/:id/account` returns state, deadline and impact. POST suffixes `lock`, `unlock`, `disable`, `restore`, `review-eligibility` require `expected_revision`; eligibility review also requires `confirm_reviewed:true` and the current impact `review_token` as `expected_impact`. The old DELETE removal route now requires this revision and cannot scrub identity. Authentication returns fixed `account_locked` / `account_disabled` messages and hashed revoked-session tombstones, while login session issuance locks the user against concurrent disable.

Permission windows restrict existing grants using the company IANA timezone. Raw grants remain intact in permission editors. Custom company role presets support optimistic versions and atomic application of grants + windows; snapshot application survives later template editing/deletion. Existing delegation scope and owner-only rules remain enforced. Runtime permission invalidation uses the existing durable outbox and Comms disconnect path.

Protected media now issues five-minute session-bound backend delivery tickets. Each GET/HEAD rechecks fresh membership, account state, capability, audience/source references, and session. Byte-range delivery streams provider bytes without full buffering. Long transfers recheck authorization once per second and explicit access/account changes cancel active transfers and tickets immediately. Provider access URLs are no longer returned by installed production routes. Absolute ticket URLs use only a trusted configured origin (`PUBLIC_BACKEND_URL`, existing `MCP_PUBLIC_ORIGIN`, or `RAILWAY_PUBLIC_DOMAIN`); missing/invalid origin fails closed. Request Host and forwarded headers are ignored. Non-HTTPS is limited to non-production loopback. Existing downloaded/offline bytes cannot be remotely erased.

## Worker interfaces

- New operational selectors: `deleted_at IS NULL AND operational_eligible`, or SQL `wolf_employee_operational(u)`. Historical joins keep the user identity and all completed/pay/commission/mileage records.
- Register crew/domain obligations with `registerEmployeeImpactProvider(name, async(db,{companyId,userId,actor}) => orderedRecords)` from `employee-access/impact.js` (also exposed on installed service). Include record revisions/assignment IDs in deterministic records so review tokens invalidate after changes. Do not alter jobs automatically.
- Worker 3 protected scope contract from `PROTECTED-STORAGE.md` still applies. Delivery revalidates `authorizeAccess` for every fetch and during transfers. Retained training references must survive future private purge.
- Production bootstrap installs account schema before routes, storage schema before Comms/delivery, then account routes after Comms. Existing automation events for disable/restore remain enqueued in the same account transaction. No production migration has been run.

## Verification

`node --test tests/employee-account.integration.test.js tests/permission-governance.integration.test.js tests/storage-delivery.integration.test.js tests/media-storage.integration.test.js tests/protected-storage.integration.test.js tests/company-comms-audit.integration.test.js` — **37 passed, 0 failed/skipped**, 11.86 seconds. Log `/tmp/wolf-worker1-lifecycle-release.log`. Disposable PostgreSQL/HTTP and synthetic streamed provider bytes only. Whitespace validation passed. Native session tests separately passed 18 tests; native account UI is being runtime-verified before its own commit.

## Remaining, not claimed complete

Automatic expiration/private purge processing, explicit purge preview, storage totals and company cleanup are the next slice. The additive purge-job table is schema preparation only. Native custom-role/window UI and broader selector adoption are in progress. Existing legacy-removed accounts have already lost data under the prior version and cannot be promised full recovery. Actual provider playback and remote/disconnected device behavior need integrated environment verification. Database backups/provider retention follow their own configured policies; no promise of erasure from backups.

## Notes recordings and Finance receipts: revocable delivery follow-up

`registerDeliverySource(name, { authorize, bucket? })` and `issueSourceDelivery(actor, name, id, { purpose, variant })` extend the existing session-bound ticket service to domain-owned objects without duplicating them into `stored_files`. The additive ticket schema keeps the original stored-file path and requires exactly one file/domain source. Unknown sources deny access. Trusted configured origin, five-minute expiry, no-store headers, byte ranges, fresh source authorization and in-flight revocation remain enforced.

Notes playback registers `notes_audio`, checks current page audience and `audio.play`, and returns the revocable endpoint. Finance receipt original/thumbnail playback registers `finance_receipt`, reloads the actor and `finance.receipts.view`, then uses existing `withFinanceSpace` + scoped RLS for the receipt's actual space. Employer status does not bypass private Finance. No Finance sharing/accounting rules changed. Storage installation precedes Notes/Finance in production. Isolated domain installers without a delivery service return an explicit unavailable response for protected downloads.

Previously issued provider URLs cannot be recalled by this adapter; they expire under their earlier provider TTL. New links reauthorize against the current session on each request and while transferring. The local native fixture uses synthetic objects and a private cleanup control route only in its test script.

Validation: `/tmp/wolf-worker1-protected-domain-release.log` **38 Node tests passed**, zero failures/skips, including all Notes tests, actual Finance-space/receipt route tests, governance route inventory, private purge and original delivery ranges/revocation. Receipt unit harness also passes. Regression fixtures verify private owner separation, selected-member removal, capability denial, lock and session revocation. No provider or production requests.

### Existing booking crew review

`employee-access/impact.js` reads existing `companies.customer_booking_settings.resource_bundles` without modifying membership. Relevant named crews, members, qualifications, enabled state and settings version participate in the eligibility review digest. A booking-settings change invalidates an old confirmation. Optional domain impact providers remain supported. The real HTTP lifecycle test installs the existing booking schema and proves stale crew review returns 409, followed by a successful current review. Worker 2 owns applying `wolf_employee_operational(u)` in booking activeIDs; this slice does not alter schedule/booking files.
