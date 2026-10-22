# Employee private recovery, purge and storage — ready backend slice

Local implementation only. No production migration or deployment. Depends on lifecycle `de5072c` and delivery-origin `f41eb60`.

## Interface and installation

`employee-access/purge.js` installs additive queue/object metadata plus private-background-write guards after Notes, Finance, Focus and Assistant schemas exist. Existing media maintenance calls `employeePrivateData.tick()` every 60 seconds. Installation is idempotent. No new scheduler, whole-bucket scan or external communication.

- `GET /api/company/employees/:id/private-purge-preview`: authorized owner/Admin with `team.purge_private`; disabled recoverable account only; returns counts, server timestamps, revision and digest token. No private content or filenames.
- `POST /api/company/employees/:id/private-purge`: current preview fields plus exact confirmation `DELETE PRIVATE DATA`. Company/advisory/account locks serialize restore and purge. Private rows change in one transaction. Bytes remain counted while queued/cloud deletion retries.
- `GET /api/company/storage-usage`: explicit `storage.view_usage` for owner/Admin. Company/account/category aggregate object metadata, zero-byte and disabled accounts, pending reservations, unknown receipt-thumbnail sizes, shared-upload attribution and last calculation time. Private contents are not exposed.
- `GET /api/company/storage-cleanup`: independently authorized `storage.cleanup_company`; largest 100 company files.
- `GET /api/company/storage-cleanup/:id`: reference-aware version/token preview.
- `POST /api/company/storage-cleanup/:id`: current token and exact `DELETE COMPANY FILE`; rejects referenced domain files. Existing cloud cleanup releases bytes only after confirmation.

## Retention boundary

User identity/photo/permission rows remain. Shared/inherited Notes, participant messages and attachment references, company files, source-protected training assets and other domain foreign-key references remain. Private Notes payload/history, personal preferences, eligible personal tasks/ideas/Focus/Assistant data and employee-owned private Finance spaces are eligible. Billing totals retain minimal attribution while Assistant content and MCP payload/results are redacted.

**Conservative exception:** private Finance spaces with payroll, commissions, mileage, operational or time/job records are retained as a whole. The preview reports `retained_finance_spaces` and expressly says their other private rows remain. This protects legacy mixed spaces pending Worker 2 accounting reconciliation; it does not expose them to employers. Source-protected private files are likewise retained pending domain classification. Browser device data and external media/backups cannot be claimed erased. Native UI is a subsequent slice.

Purge queues Notes audio and private receipt objects through existing storage adapters. A retained receipt sharing the same object key prevents deletion; metadata accounting deduplicates provider/key. Failed provider deletion keeps account `purging` and bytes charged, with retry. Old `legacy_disabled` accounts receive no automatic deadline. New late private Focus/Assistant writes are rejected during/after purge. Unexpected retained FK dependency rolls the private-data transaction back and retries for review, never disables integrity constraints.

## Validation

Disposable PostgreSQL and fake provider only. `/tmp/wolf-worker1-purge-release.log`: **39 passed, 0 failed/skipped**. Covers real HTTP account authority/session controls, governance, media/privacy, private purge, full Finance bootstrap, failed cloud deletion/retry, stale preview, concurrent restore-vs-purge atomic outcome, deduplicated receipt objects, storage view/cleanup capability separation and unknown/private content exclusion. Exact before/after historical rows preserved for completed jobs, technician/sales assignments, hours, pay rates, commissions, mileage reimbursements, name/photo; participant messages and company/shared assets survive. Syntax and `git diff --check` pass.

Synthetic totals: 550 bytes before/after disable and failed cloud cleanup; 400 after eligible purge; 300 after explicit company-file cleanup. Duplicate legacy receipt fixture: 180 before, 100 after private purge, shared receipt bytes retained once.

### Required Notes clone follow-up

Notes template copies reuse the same recording object key with a new page/recording ID. The follow-up retains that key whenever another page references it, deletes only private recording metadata, and queues one object only when the last eligible private reference is purged. Queue metadata retains the charge until provider success. Added actual PostgreSQL test verifies 75 bytes counted once across two users, first purge keeps 75 and the second removes the object exactly once. Focused combined purge/Notes/delivery run: 8 passed, `/tmp/wolf-worker1-cloned-audio-regression.log`.

### Private Notes exports

A source-protected file with verified Notes provenance is now eligible when its source page is in the same owner's private purge plan and no retained note, participant or other domain references the file. This removes private PDF/text exports as well as page payloads. Shared-source exports and unknown protected domains stay retained. Actual-schema regression proves one private export is deleted and one shared-source export remains; storage classifies them as recoverable versus retained before deletion. Combined lifecycle/purge tests: 13 passed (`/tmp/wolf-worker1-impact-export.log`).

Personal preference follow-up: permanent purge now clears tab/dashboard preference payloads and password hashes, deletes personal Comms/service-plan review/dashboard dismissal settings, and redacts employee-specific layout snapshots while retaining audit actor/target/company identity. Disable and restore still preserve preferences/credentials. Company role layouts, other employees and shared messages are unchanged. Preview digest includes the personal user payload to reject stale confirmations.

Private file metadata is redacted when the purge transaction commits, including files whose cloud bytes were previously deleted. Private transfer receipts are removed; public activity/receipts remain company history. This does not reduce measured cloud bytes before provider confirmation. The six purge/Finance PG checks pass with assertions for active and already-deleted private filenames, captions and receipts, plus retained public history. Company usage now also returns `company_timezone` for deadline presentation.

## Retained attachment references and concurrent cleanup

The retention predicate now includes Notes block preview images, current and retired database-property values, legacy attachment versions, and structured Notes versions (cover, block asset/preview and row-property files). Only references held by a retained page protect bytes during an employee's private purge; the same forms inside eligible private pages are purged with those pages. Retired UUID properties are conservatively retained even when the former column definition is unavailable. Pending scheduled conversation attachments and workflow submission assets also protect their source files; canceled scheduled drafts no longer do.

Company cleanup and account purge already take the company row `FOR UPDATE` before user/domain/file locks. Comms and Notes mutation transactions now take the compatible company `FOR KEY SHARE` first, followed by the existing permission lock. The scheduled-message sender uses the same order. This prevents cleanup from passing its final reference check between attachment authorization and reference insertion. Normal writers stay concurrent; cleanup waits for committed references, and writers starting after cleanup see an unavailable file. Worker 3 matched this order for training reserve/publish in `651a954`.

Actual PostgreSQL tests pause transactions at the attachment validation and deletion boundaries and observe the competing database lock wait. Both orders are covered, together with private-versus-retained Notes history and explicit company cleanup. Existing Notes/Comms regression suite: 58 passed, zero failures/skips (`/tmp/wolf-worker1-retention-regression.log`). Final `npm run test:employee-access`: 22 passed, zero failures/skips (`/tmp/wolf-worker1-retention-access.log`).
