# WOLF-060 backend integration candidate

Branch: `codex/facebook-settings-usability`. Base: `7389a58b8e7b1e3c056689cc11124cb82a46a63a` (the deployed combined release source). Independent Backend worktree, not the primary checkout. No deployment, production migration, main merge, cross-chat coordination or polling performed.

## Implementation

- Shared `/api/integrations/facebook` status, human OAuth/start/callback, refresh, independent controls and full disconnect; legacy Leads/Ads OAuth URLs delegate safely and retain in-flight legacy support.
- Existing Leads app, combined grants, app-scoped USER-token validation, current session/company/role validation, single-use hashed OAuth state. User credentials use distinct encrypted AAD for shared/Lead/Ads storage; Page credentials remain separate.
- Five readiness results explain grants, selected assets, Page subscription/retrieval, enable flags and task access. Legacy tokens/configuration remain until fresh combined authorization; no cross-app token copying.
- Reconnect, permission removal, expiry, deauthorization and deletion propagate across both modules. Snapshot guards prevent an old response from poisoning new credentials. Full disconnect clears credentials while retaining business configuration/history. Signed deletion callbacks additionally remove integration personal data and return a confirmation URL.
- Pause prevents worker claim/commit/recovery while retaining pending work. Disabling Ads blocks the existing operation/receipt paths without deleting saved reports. Existing deduplication, routing, Zapier, MCP, automation and approval contracts remain in place.
- Navigation catalog v5 adds `ads` under More for old layouts; existing primary order remains intact.

## Verified locally

`node --test --test-concurrency=1 tests/facebook-connection*.test.js tests/facebook-leads*.test.js tests/facebook-ads*.test.js tests/navigation-tabs.test.js`

**69 passed, 0 failed** on disposable PostgreSQL with mocked Meta traffic. Includes cross-company/role access, bad app/token/state/session, replay, cancellation, partial grants, preserved forms/accounts/mappings/views, independent controls, import dedupe, expiry from pagination and the worker, stale responses after reconnect, signed revocation/deletion/legacy callbacks, navigation migrations and existing Ads/Leads/MCP/automation contracts. No live campaign mutation, customer communication or outbound call was used.

`tests/helpers/facebook-settings-simulator.js` starts an explicit localhost-only QA server at `127.0.0.1:18607`, using disposable PostgreSQL and provider fixtures. It is a test helper, never a production process. The untracked node_modules symlink reuses dependencies and must not be committed or deployed.

## Later integration requirements

1. Combine this commit with the final Ask Wolf repair only when Jared requests integration. Preserve the repair's independent assistant/MCP changes; this candidate has no edits to the MCP registry or assistant backend.
2. Deploy the native and Backend candidates together through the established release process. New native shared-connection endpoints require this Backend; old clients retain compatible routes.
3. Startup installs additive shared connection/state/deletion tables and the Lead/Ads enable/unified/expiry columns after the existing module schemas. No destructive production data migration is required, and none was run. Retain the existing encryption key.
4. Apply [Meta setup](facebook-connection-setup.md), retaining legacy redirect URLs and existing Page webhook. Real consent, selected business assets and real webhook delivery are owner setup/combined-release checks; local tests do not claim those external checks passed.
5. Run this focused suite again on the merged source. Smoke-test auth, Ads/Leads readiness, old callback URLs, current MCP approval behavior and existing form routing before release.
6. For rollback to older code, first disable `FACEBOOK_ADS_ENABLED` and `FACEBOOK_LEADS_WORKER_ENABLED`: older workers do not understand the new per-company pause flags. Keep additive tables/columns and encrypted records intact; do not drop or rewrite them.

Production release and iPhone installation remain explicitly on hold until the user requests the combined integration.
