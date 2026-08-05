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

## Dependencies and cutover boundary

Revision 0010 and an authoritative execution/attempt lifecycle remain
required before acceptance, durable reservation, live shadow correlation, or
result publication can exist. Module, credential, destination, lifecycle,
result-authority, cancellation, timeout-settlement, and transport blockers
remain unresolved.

Strategy, Goal, CLI, SDK, execution chains, workers, Redis, isolated
subprocesses, the sandbox, and LLM boundaries must converge on one authority
before global enforcement. Live shadow evaluation remains prohibited until an
authoritative attempt identity and strict noninterference are proven. The
eventual global cutover must not retain a legacy execution fallback beside the
enforced gateway.
