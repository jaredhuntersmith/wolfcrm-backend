# Personal training draft purge

The adapter follows Worker 3's author/private scope contract. It deletes only the disabled account's unpublished personal definitions with no published version, assignment, onboarding/recurrence use, question-bank source, or retained history. Draft-only audit actions are explicitly enumerated, including portable `definition.imported`. Unknown actions, recipient history, unexpected foreign-key references, course JSON references and polymorphic domain events retain the definition.

Draft media references and allowed audit rows are removed in the same private-purge transaction before the definition. Protected media is eligible only when every training reference belongs to an eligible draft owned by the account and no other domain or company reference remains. Existing storage cleanup queues provider deletion; there is no provider deletion inside this adapter. The durable purge manifest keeps queued bytes classified as private/purging after the source references disappear, until cloud deletion succeeds. A new optional preview count, `private_training_drafts`, identifies this category without disclosing draft titles or contents.

## Dependency and integration

For local verification only, commit `39aa2c2` imports exact Worker 3 `training/schema.js` from Backend `5195524`, SHA-256 `977b5065e3569e23ef41de9c3bd33c400ae701e25cbb11a49a7a2c36ac1f1cbc`. Coordinator approved this dependency snapshot. Do not cherry-pick that dependency commit into the combined candidate; it already has the real training module. Apply only the subsequent Worker 1 adapter/test commit. The adapter fails closed when required training schema is absent and adds no migration of its own.

Integration gate: W1 found existing training writers load their actor before the transaction and some lack the company lifecycle boundary. Worker 3 owns a fresh actor/capability recheck after the company lock and before domain writes, plus concurrency tests. Until that is verified, do not claim all stale training writes are excluded. Personal question-bank retention needs its own agreed predicate; this slice retains them and any source definition they reference.

## Verification

- `/tmp/wolf-worker1-training-purge-final.log`: one disposable-PostgreSQL test PASS on the real installed training schema. Eligible/imported drafts and their audits are removed; published/company/other-account/other-company/bank/course/domain/unknown-FK history survives unchanged. Shared and orphan protected assets remain; a stale preview is rejected; failed provider cleanup keeps 300 tracked bytes/100 purging bytes until a successful retry reduces the total to200. Identity survives.
- `/tmp/wolf-worker1-training-purge-access.log`: project employee-access suite PASS23/23, zero skips, including existing Finance/Notes/Comms/media/purge regressions.
- Syntax and diff checks PASS. Native optional preview row is implemented but not yet built or runtime verified.

Server authorization and retention apply to every client. No MCP lifecycle action or sensitive field exposure is added. Desktop administration presentation remains explicitly deferred as recorded in the client parity document; no tool refresh is needed.

## Personal question-bank follow-up

Worker 3 and the coordinator agreed a joint plan: select author-owned personal banks with no import, unknown audit, foreign-key, document or domain-event history; remove only their created/updated/archived audit rows and bank records. Draft eligibility can ignore only those same-transaction bank rows. The draft still independently must satisfy every unpublished/private/history predicate. A company or retained source definition and its files do not become deletable just because a private bank pointed to them. Any imported bank is conservatively retained, including its source; published copies are untouched.

The preview adds optional `private_training_question_banks`. The expanded real-PG suite passes2/2 (`/tmp/wolf-worker1-training-banks-first.log`): simultaneous bank/draft cleanup, retained company source, imported/unknown/FK-linked banks, other owners/companies, draft-only audit deletion and no inline provider erasure. Project employee-access regression passes23/23 again (`/tmp/wolf-worker1-training-banks-access.log`), zero skips. No migration or MCP exposure change. The Worker 3 fresh-actor mutation gate still applies.
