# Offline execution-policy kernel

Phase 5C.2A adds a deterministic policy library at
`ares.core.execution_policy`. It is an offline, test-only boundary. No ARES
execution ingress imports it, and this phase supplies its reduced facts only
from synthetic tests. It is not live enforcement and it is not evidence that
any current module is safe to execute.

The kernel is not a second module-descriptor catalog. It stores no module IDs,
parameters, destinations, identities, credentials, or descriptor objects. A
future adapter must establish all authority and reduce it to immutable facts
before evaluation. The kernel itself does not construct modules; parse,
coerce, validate, or serialize requests; resolve authority; reserve budgets;
persist lifecycle state; dispatch work; retry; cancel; or publish results. It
also performs no I/O, logging, telemetry, time, randomness, or hashing.

## Decisions

Evaluation has a fixed order:

1. Reject invalid types, versions, enum values, bitmasks, bounds, and
   contradictory facts.
2. Reject invalid or noncanonical request-shape facts.
3. Reject untrusted, stale, incomplete, or statically unevaluable descriptor
   facts.
4. Block incomplete or stale authority snapshots.
5. Block invalid actor or campaign authority.
6. Block insufficient role, HIGH_NOISE use below `team_lead`, or missing,
   stale, or incorrectly bound required approval.
7. Require every capability bit declared by the descriptor.
8. Require complete destination extraction and in-scope destinations.
9. Require current credential authority, permitted opaque-handle kinds, and
   the absence of raw and ambient credentials.
10. Require current budget authority and available capacity.
11. Block any descriptor blocker bit.
12. Apply preview or live readiness checks.

The only verdicts are `REJECTED`, `BLOCKED`, `PREVIEW_READY`, and
`LIVE_CANDIDATE`. A live candidate is merely a set of supplied static facts
that passed offline evaluation. It is not accepted, authorized, reserved,
queued, dispatched, or executable. Only a future durable transaction may
accept an attempt.

## Current project truth

Phase 5C.1 remains audit-only. The catalog is descriptor-complete and
statically policy-evaluable for 62 of 62 first-party IDs, but current ARES is:

- preview-ready: 0 of 62;
- future-gateway-eligible: 0 of 62;
- shadow-active: 0 of 62;
- enforcement-active: 0 of 62.

Positive preview and live-candidate tests use deliberately synthetic trusted
facts. They do not change those counts or claim readiness for a real module.

## C-core authority reduction

Revision `0011` supplies a store-only C-core resolver that can derive the
kernel's admission facts from persisted authority under the admitting
transaction. The public request contributes immutable intent; a trusted stable
principal is established outside C-core. Caller-supplied gateway mode,
revision, role, ownership, descriptor, destination, credential, approval,
policy, or budget claims are never authority. Initial contract-v3 intent also
forbids caller-supplied outbox identity and publication key.

C-live authentication and endpoint integration remain pending. A future live
caller must authenticate before C-core or submission lookup. After that stable
principal is established, an exact stored submission may replay without
re-reading mutable work authority; the same submission with a different
principal or immutable intent conflicts. This preserves lost-response recovery
without treating a stale or unauthenticated caller snapshot as authority.

For a first v3 application, the store classifies the logical submission before
locking and reducing mutable gateway, actor, campaign/grant, descriptor/catalog,
destination, credential, approval, and budget facts. The snapshot and all
admission effects commit atomically. Invalid contracts take precedence over
submission replay/conflict, which precedes stale authority and canonical policy
evaluation; capacity is considered only for an accepted decision.
`invalid_contract`, `conflict_operation`, `authority_stale`, and
`capacity_unavailable` have zero durable delta. Canonical policy `REJECTED` and
`BLOCKED` verdicts are instead applied admission decisions: they persist only
the terminal logical execution, closing attempt, zero-count outbox row, and
outbox operation receipt, with no approval consumption or budget reservation.
The store derives that terminal outbox identity and publication key
deterministically from the admission operation. An accepted initial admission
allocates neither from caller input.

Gateway mode does not bypass canonical reduction. `emergency_disabled` is
`NOT_EVALUATED` and durably `BLOCKED`. `disabled` and `shadow_candidate` are
evaluated, then forced to `BLOCKED` with `AUTHORITY_RESOLUTION_REQUIRED`;
`enforced` honors the evaluator result. The C-core adapter maps `reporter`
directly to `BLOCKED` with `INSUFFICIENT_ROLE`. The kernel has no `recon` role,
so a persisted `recon` principal is `authority_stale` with zero durable delta,
not a caller-selectable role translation.

Canonical `PREVIEW_READY` is a successful policy evaluation, but C-core stores
it as an applied terminal `BLOCKED` attempt. Its immutable snapshot retains
`evaluation_mode=preview` and `policy_verdict=preview_ready`; it never becomes
accepted or dispatchable work.

The logical submission is the sole replay authority for initial admission; no
admission operation receipt is created. Historical v2 replay remains exact,
new v2 creation is forbidden, and a v3 binding cannot be downgraded. Retry uses
the same persisted-authority reduction after its historical replay check.

Destination facts are complete canonical extraction plus campaign scope and
the campaign destination-authority revision/digest. Credential facts accept
only a current opaque campaign-owned handle and its authority revision; raw or
ambient credentials remain invalid. Attempt-bound approval is exact and
single-use, is consumed in the admission transaction, and is not consumed by
replay, conflict, stale authority, capacity failure, or rollback. Historical
attempt observations are immutable snapshots, not live foreign keys to mutable
authority rows.

## Dependencies and cutover boundary

Revision `0010` remains the protected execution/attempt persistence base, and
revision `0011` adds the C-core authority and admission store contract. No live
snapshot adapter, authenticated endpoint, or execution consumer uses that
contract yet. C-live integration remains required before public acceptance,
live shadow correlation, or result publication can exist. Module, lifecycle,
result-authority, cancellation, timeout-settlement, and transport blockers
outside the C-core store boundary remain unresolved.

Strategy, Goal, CLI, SDK, execution chains, workers, Redis, isolated
subprocesses, the sandbox, and LLM boundaries must converge on one authority
before global enforcement. Live shadow evaluation remains prohibited until an
authoritative attempt identity and strict noninterference are proven. The
eventual global cutover must not retain a legacy execution fallback beside the
enforced gateway.
