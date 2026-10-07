# Focus activation checkpoint

Updated: 2026-10-07

## Production connection repair

- [x] Record an explicit Meta connection state in the API and iOS client.
- [x] Classify a missing or unreadable stored token as `CONNECTION ERROR`, not
  `TOKEN EXPIRED`.
- [x] Preserve a provisional encrypted Meta connection record before attempting
  Page-to-Instagram account resolution.
- [x] Persist a sanitized provider diagnostic for OAuth and linked-account
  resolution failures.
- [x] Deploy the repair (`5c801f5`) to the production backend.
- [x] Verify the deployed service starts, connects to Postgres, and serves its
  health endpoint.
- [x] Keep background Focus processing, Brave discovery, and OpenAI processing
  disabled until a bounded live Meta verification succeeds.
- [ ] Add `pages_read_engagement` to the existing Facebook Login for Business
  User Access Token configuration, preserving the existing four permissions and
  selected Window Wolves assets.
- [ ] Reconnect through the repaired OAuth callback.
- [ ] Verify the Facebook Page, its linked Instagram Professional account, a
  bounded profile/media read, and the granted capabilities.
- [ ] Run one bounded live Supply Probe before enabling continuous processing.

## Current evidence

The prior production OAuth exchange reached Meta successfully, but the server
logged `meta_linked_professional_account_not_found` while resolving the selected
Facebook Page's Instagram Professional account. The old callback stored a token
only after that resolution, so it discarded the exchanged authorization and the
client subsequently presented a misleading "Token expired / Focus Token
Unavailable" message.

The repaired callback stores encrypted connection material first and reports the
actual, sanitized Meta account-resolution result. The documented Facebook Login
path requires `pages_read_engagement` alongside the existing Instagram and Page
permissions before the Page-linked professional-account read can be relied on.
