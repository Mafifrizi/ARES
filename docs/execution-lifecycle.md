# Execution-lifecycle persistence

Revision `0010` adds an additive, test-only persistence contract for future
canonical execution. It does not integrate the API, engine, CLI, SDK,
Strategy, Goal, workers, Redis, subprocesses, sandbox, modules, or plugins.
The existing `module_runs` relation and historical `DONE`, outcome, and success
values remain legacy-unclassified; they are never promoted to authoritative
success.

Revision `0011` extends that protected base with the P1-C authority-and-
admission contract. Its scope is **C-core only**: store requests, authority
producers, locking, durable admission/retry decisions, and replay. It does not
make an HTTP, engine, CLI, SDK, Strategy, Goal, worker, or module path use the
new admission boundary. Authentication before entry to C-core and every live
producer integration are C-live work and remain pending. Nothing in this
document claims that a current public execution endpoint is enforced by
C-core.

Revision `0010` is byte-protected. Revision `0011` is an append-only child; it
must not rewrite the `0010` migration or reinterpret rows created under its
version-2 binding contracts.

`execution_gateway_state.mode=disabled` means only that the new canonical
gateway is inactive. It does not disable or secure existing legacy engine
entry points. Operators who require a no-execution migration window must drain
those paths externally. Global fail-closed enforcement remains a later phase.

## Catalog

Generation 10 adds exactly eleven ordinary, permanent relations:

1. `logical_executions`
2. `execution_attempts`
3. `execution_actor_authority_revisions`
4. `campaign_execution_authority_revisions`
5. `campaign_execution_budgets`
6. `execution_attempt_approvals`
7. `campaign_execution_budget_ledger`
8. `execution_output_links`
9. `execution_publication_outbox`
10. `execution_gateway_state`
11. `execution_operation_receipts`

Operation receipts are append-only replay authority. Each globally unique
operation UUID binds a fixed operation code, immutable campaign and target
identities, a canonical principal kind/subject/user/authority revision,
explicit expected-revision presence, ownership facts, a version-2
length-framed request digest, the fixed first result, its exact replay code,
every resulting identity/revision with explicit presence, and the matching
version-2 result digest. Mutable `latest_operation_*` columns are lookup hints
only. Exact replay is answered entirely from the stored receipt: later target
revision, target deletion, authority change, or campaign deletion cannot
rewrite the historical result. A same operation UUID with any changed binding
is always `conflict_operation` before mutable target or authority lookup.
Receipt insertion and the corresponding domain mutation share one transaction
and savepoint, so neither can commit without the other. Receipt bindings
contain only sanitized lifecycle facts and never raw request, destination,
credential, evidence, diagnostic, or secret-derived material.

Receipts retain historical UUID facts without foreign keys to mutable campaign,
target, or principal rows. SQLite blocks receipt `UPDATE` and `DELETE` with two
exact catalog-fingerprinted triggers. PostgreSQL uses one exact
`BEFORE UPDATE OR DELETE` trigger whose exact function and trigger definitions
are catalog-fingerprinted. No other lifecycle trigger is permitted.

They use named row-local checks, named primary/unique/foreign-key constraints,
and deterministic indexes. PostgreSQL relations are ordinary logged heap
tables with RLS disabled and no policies, inheritance, partitioning, or rewrite
rules. The receipt immutability trigger is the sole allowed user trigger.
SQLite and PostgreSQL foreign keys are deferred where
whole-campaign deletion or the logical/attempt cycle requires transaction-wide
validation.

Identifiers are lowercase canonical RFC-4122 UUIDv4 strings. Descriptor and
catalog digests are 64 lowercase hexadecimal characters. Persisted counts and
Unix-millisecond timestamps use the exact `0..9007199254740991` range. Request
and policy contract versions are `1`; descriptor contract version is
`ares.module-descriptor.v2`; capability, descriptor-blocker, and policy-reason
masks are version `1` with explicit numeric allocations independent of enum
declaration order.

Raw parameters, destinations, credentials, evidence, result bodies, SQL,
exception text, URLs, DSNs, hostnames, worker addresses, and secret-derived
hashes do not belong in lifecycle or outbox rows.

## Attempts and settlement

The 15 durable states are `rejected`, `blocked`, `accepted`, `queued`,
`dispatching`, `running`, `cancelling`, `settlement_pending`, `succeeded`,
`partial`, `failed`, `skipped`, `cancelled`, `timed_out`, and `indeterminate`.
The frozen graph has 31 legal and 194 illegal ordered pairs.

`settlement_pending` is nonterminal, non-dispatchable, holds budget
reservations, invalidates its lease, exposes no authoritative outputs, forbids
retry, and publishes one recovery-required event. Its recovery deadline is
exactly 24 hours after entry. It may resolve only to a known authoritative
terminal result or to final `indeterminate`. Final `indeterminate` requires a
current authenticated admin, a persisted opaque resolver reference and
authority revision, bounded-recovery proof after the deadline, conservative
noise/exfiltration consumption, concurrency release, and one terminal event.

External module effect is forbidden before the successful
`dispatching -> running` CAS. A dispatch/start failure is a no-effect failure:
it releases every reservation and has no outputs. Dispatch ownership history,
lease generation, original duration, and original expiry remain immutable;
`lease_invalidated_at` marks inactive ownership.

Cancellation has three persisted shapes. Never-leased cancellation has no
dispatch/start history. Leased-but-not-started cancellation preserves lease
history but cannot produce success, partial, or timeout. Started cancellation
may resolve truthfully to success, partial, failed, cancelled, timed out, or
settlement pending. A cancellation request records intent only; the exact
owner may still win with an authoritative result. Cancellation acknowledgement
may produce `cancelled` only with proof that no terminal module result won.

Every transition has one authoritative operation UUID. Cancellation terminal
results use the acknowledgement operation, timeouts use the timeout operation,
settlement-pending entry uses its recovery operation, ordinary terminal states
use the terminal operation, and explicit logical closure uses the closure
operation. Cancellation acknowledgement presents the immutable post-CAS
request revision.

## C-core admission authority

C-core accepts an immutable caller intent and a trusted stable principal. The
intent contains identities and requested work, but no claims about current
gateway, role, ownership, descriptor, credential, approval, or budget
authority. It also contains no caller-chosen outbox identity or publication
key. The principal is established outside C-core. A caller cannot promote a
snapshot, role, revision, ownership flag, catalog digest, or budget claim to
authority by placing it in the intent.

C-live must authenticate before calling C-core. A missing, invalid, revoked,
deleted, inactive, or demoted live principal must be rejected before submission
lookup. That authentication boundary is pending and is not implemented or
claimed by the C-core store contract.

Once the stable principal has been established, exact replay is intentionally
independent of later mutable-authority changes. The logical submission row is
the sole admission replay authority. An exact request by the same stable
principal may replay after gateway or authority revision changes, or after a
mutable descriptor, destination, or credential authority row is deleted. A
different principal or any changed immutable intent conflicts. Historical
replay never means that an unauthenticated caller may reach submission lookup.

### Version-2 and version-3 bindings

| Stored binding | Creation authority | Exact replay | Changed binding | Mutable-authority lookup |
| --- | --- | --- | --- | --- |
| Historical v2 initial submission | Preserved `0010` row only | Preserved exactly | `conflict_operation` | Not required for exact replay |
| New v2 initial submission | Forbidden | Not applicable | `invalid_contract` | Not applicable |
| New v3 initial submission | Trusted principal plus immutable intent | Stored logical submission result | `conflict_operation` | Required only on first application |
| Historical v2 retry | Preserved v2 receipt/child binding only | Preserved exactly | `conflict_operation` | Not required for exact replay |
| New v2 retry | Forbidden | Not applicable | `invalid_contract` | Not applicable |
| New v3 retry | Trusted principal plus immutable retry intent | Stored retry receipt/result | `conflict_operation` | Required only on first application |

Version 3 binds the trusted principal and complete immutable intent. A v3 row
cannot be downgraded to v2, and new code cannot manufacture a v2 request to
bypass the v3 resolver. Existing v2 rows are neither upgraded in place nor
backfilled from current mutable authority.

Admission deliberately creates **no** `execution_operation_receipts` row.
`logical_executions` stores the admission operation, binding version, request
digest, first result, replay result, and result digest. This avoids two replay
authorities for one submission. Retry and authority mutations continue to use
operation receipts where their contracts require them.

### Transaction, lock, and result order

The first application of a v3 submission uses one transaction and a fixed lock
order. Contract shape is validated first. The store then locks the submission
identity and classifies an existing logical submission before consulting
mutable gateway or work authority. A matching row replays; a changed binding
conflicts. Only a new submission proceeds to locked reads of gateway, actor,
campaign, campaign grant, descriptor/catalog, destination, credential,
approval, and budget authority. The derived snapshot, logical execution,
attempt, optional approval consumption, budget reservations, and publication
state commit atomically.

The result precedence is fixed rather than dependent on query order:

1. Invalid input or an attempted untrusted authority claim is
   `invalid_contract`.
2. An existing submission is exact replay or `conflict_operation`.
3. A contradiction or incoherence in required persisted authority is
   `authority_stale`.
4. Current authority is reduced to the existing canonical policy kernel.
   Canonical `REJECTED` and `BLOCKED` verdicts are applied admission decisions,
   not store failures.
5. An otherwise accepted request without budget capacity is
   `capacity_unavailable`.
6. A fully current, policy-accepted, capacity-available first application is
   `applied`.

`invalid_contract`, `conflict_operation`, `authority_stale`, and
`capacity_unavailable` have complete zero durable delta. By contrast, an
applied canonical policy `REJECTED` or `BLOCKED` decision durably creates only
the terminal logical execution, its closing attempt, one zero-count outbox
row, and the outbox operation receipt required by the existing publication
contract. The store derives the terminal outbox identity and publication key
deterministically from the admission operation; the caller supplies neither.
No admission outbox identity is allocated for a canonical accepted decision.
An applied rejection or block consumes no approval and reserves no budget.
PostgreSQL uses row locks in the admitting transaction. SQLite uses its
serialized writer transaction; durability is independently observable from a
second connection. Retry uses the same authority derivation and locking rules
after its historical receipt check and admits only a canonical accepted
decision.

Gateway handling is explicit. `emergency_disabled` is not evaluated and is
applied as `BLOCKED`. `disabled` and `shadow_candidate` still run the canonical
policy evaluator, then are forced to `BLOCKED` with
`AUTHORITY_RESOLUTION_REQUIRED`. `enforced` honors the canonical evaluator.
The C-core role adapter maps `reporter` directly to
`BLOCKED`/`INSUFFICIENT_ROLE`; the unsupported core role `recon` is an
`authority_stale` zero-delta result rather than a new policy role.

### Authority rules and producers

Descriptor authority is the immutable module identity, descriptor contract
version `ares.module-descriptor.v2`, and semantic digest, bound to the current
gateway catalog digest/revision. No numeric per-descriptor revision is implied.

Destination authority requires complete extraction and proof that the complete
canonical destination set is within the campaign's persisted scope. The store
binds the campaign destination-authority revision/digest; it does not add a
live foreign key from a historical attempt to each destination.

Credential authority accepts only current opaque handles owned by the campaign
under the stored credential-authority revision. Raw and ambient credentials
remain forbidden. Historical logical/attempt snapshots contain immutable
identities and digests and have no live foreign keys to mutable descriptor,
destination, or credential authority rows.

An attempt-bound approval is current, exactly bound, and single-use. Admission
locks and consumes it in the same transaction as the attempt. Exact submission
replay does not consume it twice; conflict, stale-authority, capacity failure,
or rollback does not consume it at all.

Every authority producer is an operation-UUID mutation with an exact replay
receipt. Receipts retain binding contract v2; the admission/submission
authority contract is v3. The fifteen generation-11 authority operation codes
are:

1. `gateway_authority_update`
2. `actor_authority_activate`
3. `actor_authority_update`
4. `actor_authority_revoke`
5. `campaign_authority_activate`
6. `campaign_authority_update`
7. `campaign_authority_revoke`
8. `campaign_actor_grant_put`
9. `campaign_actor_grant_revoke`
10. `destination_authority_update`
11. `destination_authority_revoke`
12. `credential_authority_update`
13. `credential_authority_revoke`
14. `approval_authority_grant`
15. `approval_authority_revoke`

`campaign_actor_grant_put` is the sole operation with an optional primary
expected revision: it is absent for create and present for a CAS update. Its
secondary expected revision is always absent. Existing actor/campaign
`*_invalidate` codes remain distinct historical revision-bump operations; they
are not aliases for revoke.

## Admission, retry, closure, and budgets

Malformed, unknown-campaign, unresolved-ownership, or otherwise stale-authority
requests create no lifecycle row. Authentication belongs to the pending C-live
boundary described above. A canonical policy rejection or block is an applied
admission decision: it creates a logical execution, one closing terminal
attempt, no approval or budget row, one zero-count terminal outbox event, and
the corresponding outbox receipt. `preview_ready` received for live mode is
durably blocked. `emergency_disabled` is valid only for initial blocked
metadata. Revision `0011` authority producers change gateway state only through
their receipt-bound CAS contract.

For preview evaluation, canonical `PREVIEW_READY` is integrated as an applied
terminal `BLOCKED` attempt while preserving
`evaluation_mode=preview`, `policy_evaluation_state=evaluated`, and
`policy_verdict=preview_ready` in the immutable snapshot. It is not converted
to a live candidate or dispatchable state.

Submission identity is the lost-response authority for admission. The
`(campaign_id,submission_id)` row stores the admission operation UUID, binding
contract version, complete request digest, fixed first result, exact replay
code, and result binding. Its v2/v3 behavior is fixed by the table above.

Acceptance is one transaction containing the logical and attempt identities,
the exact derived descriptor/policy snapshot, an attempt-bound approval when
required, and reservations in all three configured budgets. Migration `0011`
does not infer current authority or capacity for historical work.

Retry always allocates a new child UUID, preserves a linear same-logical parent
chain, and revalidates every authority and policy fact. A retry-eligible parent
is failed or timed out, has no outputs, is non-closing, read-only, proven
idempotent, after-revalidation, and settled. The one exception is a proven
no-start/no-effect failure: settlement is not applicable, proof is
`no_dispatch`, termination confirmation is false, and all reservations were
released. Retry creation and `close_without_retry` lock the same logical and
parent rows and compete as mutually exclusive CAS operations. Permanent
closure authority and operation identity remain on the logical row after
outbox purge.

Budget arithmetic is literal: reservation adds to `reserved`; release removes
the reservation without consumption; consumption removes the reservation and
adds authoritative actual usage. Concurrency always releases with zero
consumption. Unknown final outcome consumes the full noise/exfiltration
reservation and releases concurrency. Both ledger revision fields record the
post-CAS budget revision, which makes lost-response replay non-duplicating.

## Outputs and publication

Output links are immutable observations of canonical finding, credential,
host, or loot IDs. An attempt may link each target once; multiple attempts may
observe the same target. Links preserve target identity, not a byte snapshot of
later-mutated entity fields. Identity-preserving UPSERT must retain the
canonical row ID and its links. Counts are distinct links for the current
attempt, and output links, budget settlement, terminal state, and outbox insert
commit in one transaction before publication.

The outbox is at-least-once. Consumers deduplicate with `publication_key`.
Claims use a 60-second lease; successful renewals add exactly 60 seconds.
Claim, reclaim, renewal, publication acknowledgement, retryable failure,
nonretryable failure, and poison are revisioned operation-UUID CAS mutations.
Retry delay is `min(2^(attempt-1)*1000,600000)` milliseconds for attempts
1–19. An expired twentieth claim is poisoned by an owner-independent CAS so it
cannot remain claimed forever. A lost publish acknowledgement may redeliver.
Publication failure never changes the committed attempt outcome.

Only succeeded and partial events may carry nonzero counts; partial requires
at least one link, and both event types must exactly match committed links.
Every other event has zero counts. Cross-row equality, approval existence,
immediate-child existence, and logical/attempt closer agreement are enforced
inside the locking transaction API, never by a trigger or cross-row CHECK.

## Startup, deletion, and rollout

A proven-empty ordinary SQLite file is upgraded canonically to Alembic head
and then verified at `0011`. Managed SQLite revisions `0001` through `0010` are
migration-required and are never silently upgraded. Exact recognized
unversioned catalogs remain adoption-required. Explicit raw SQLite URI or
in-memory use retains the bounded unstamped generation-10 fallback and its
nonauthoritative `SCHEMA_VERSION=9` marker. Empty PostgreSQL is always
migration-required and has no runtime fallback.

Lifecycle rows never block physical user deletion: immutable opaque subject
references remain while nullable live-user foreign keys become null. Direct
attempt or logical deletion is unsupported. Whole-campaign deletion locks the
campaign, lifecycle tree, and budgets; rejects active, open, recovery-pending,
or externally claimed work; then removes links, outbox, approvals, ledgers,
attempts leaf-to-root, logical executions, budgets, authority, and existing
campaign-owned rows in one transaction. Campaign deletion itself has an
operation receipt checked before the campaign row. Historical receipts are
retained. Existing callers that do not yet supply an operation/principal use
`delete_campaign(campaign_id)`, which derives a deterministic compatibility
operation UUID and fixed system principal while preserving the legacy literal
boolean result (`true` only for the first applied deletion). Explicit lifecycle
callers use `delete_campaign_lifecycle(...)` and retain the stable
`OperationResult` distinction between applied, replayed, and conflicting
bindings. Both forms replay exactly after the campaign is gone, and a reused
operation UUID with changed campaign or principal conflicts.

Deploy revision `0011` during an externally enforced drain: back up, stop old
processes, run the canonical migration, deploy the `0011`-aware C-core release,
and verify managed startup. The migration accepts only the exact protected
`0010` catalog, preserves every historical v2 binding unchanged, and never
infers current authority for an existing submission or receipt. A failed
upgrade must roll back completely and permit a successful retry. Downgrade is
refused before mutation, and mixed `0010`/`0011` application versions are
unsupported.

Gateway mode remains `disabled`; Strategy, Goal, workers, Redis, subprocesses,
shadow, public authentication/admission, and enforcement remain drained,
inactive, or C-live pending. Before a future activation surface exists, normal
and emergency rollback both retain `disabled`. Once `0011` data exists,
recovery is forward-fix-only; database downgrade is forbidden.

Validation of a candidate containing `0011` must cover the C-core admission
inventory on both backends, fresh and supported upgrades, rollback followed by
successful retry, exact catalog and drift checks, deletion/foreign-key history,
and the already-established P1-A, P1-B, transition, and lifecycle compatibility
families on that candidate ledger. This does not substitute for future C-live
authentication, endpoint, producer-integration, or end-to-end tests.
