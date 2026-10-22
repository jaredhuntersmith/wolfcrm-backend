# Protected storage registration

Additive migration: installStorageSchema adds nullable `stored_files.source_scope`. Existing rows keep their existing Company Comms provenance rules. Install storage schema before any protected-domain schema with foreign keys to stored_files. Register each domain after its schema exists and before listening for requests. No production migration was run.

`storage.registerProtectedStorageScope(name, {predicate, authorizeAccess})` registers a server-owned definition and returns an unregister closure for tests. Importing the same function from `media-storage/protected-scopes.js` is supported. Names are restricted identifiers; duplicate different definitions fail.

- `predicate(db, actor)` returns SQL using alias `f`, `$1` current user and `$2` company only. Include retained refs and pending-upload access; the predicate never implies owner/employer bypass. Use current domain authorization and scoped audience. Unknown scope fails closed across browse, direct access, search, state and verify.
- `authorizeAccess(db, actor, file, purpose)` throws on denial. Purposes are `preview`, `stream`, `download`, `upload`, `edit`, `delete`. Handle every action explicitly; reject unsupported actions. This permits training policy independent of communications.download. General storage/category capabilities still apply.
- In an already-authorized domain transaction call `storage.reserveInTransaction(db, actor, body, {sourceProtected:true, sourceScope:name})`, insert domain references in the same transaction, then commit. Reserve never accepts a scope from HTTP body. Retries cannot change source scope. Parts/completion/thumbnails require domain action authorization. Files stay private; setting company visibility is forbidden.

Training contract: `training_asset_refs.file_id uuid REFERENCES stored_files(id)` plus company_id and domain target fields. Evidence/content associated with retained training must survive employee private purge. Do not infer company-wide visibility from company_id. Private-purge integration is a later Worker 1 slice; this commit does not implement purge.

Company-shared files remain company property if the uploader is disabled or leaves. Former uploaders cannot continue accessing company-visible files belonging to a prior company. Private files and participant-scoped Comms remain governed by their own audience.

Validation: 32 Node tests pass across protected-storage integration, storage lifecycle, Comms quote exports and Comms core. Tests cover owner/peer/cross-company denial, registered audience, scope stripping/replay, protected action denial, revocation/lock, unknown scope, no company visibility bypass, and retained company sharing. All use disposable local PostgreSQL/provider fakes. Existing S3 delivery URLs remain short-lived in this slice; revocable proxy delivery is separate ongoing work.
