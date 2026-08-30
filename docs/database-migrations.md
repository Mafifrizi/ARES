# Database migrations and verified adoption

Alembic is the canonical schema history for every persistent ARES database.
Fresh databases are initialized as managed databases and current managed
databases are validated at startup. Application startup never stamps or adopts
an existing unversioned catalog.

## Managed and unversioned databases

A managed database has one valid `alembic_version` relation and exactly one
known revision row. Revision `0011` is current and forward-only. Managed
revisions `0001` through `0010` require an operator-run Alembic migration;
malformed or unknown version metadata is rejected.

An unversioned database has no Alembic version relation. The adoption verifier
accepts only the complete, audited runtime-bootstrap generations 6, 7, and the
exact SQLite runtime generation 10. It
does not use `schema_version`, table presence, or partial column matching as
authority. Unknown or locally modified catalogs require owner-reviewed manual
recovery and are not stamped.

Stop all ARES workers before verification, adoption, or SQLite restoration.
Use the same configured `ARES_DATABASE_URL` or `.env` used by the deployment;
never put a database URL or credential on the command line.

## Verification-only workflow

Run the read-only classifier first:

```text
python -m ares.db.migrations verify-adoption
```

A supported unversioned catalog reports a fixed readiness identifier ending in
its proven predecessor (`0006` or `0007`). A current managed database reports
`ARES-M2B-ALREADY-MANAGED:0011`. No version relation is created by verification.

After adoption or normal migration, verify the managed contract:

```text
python -m ares.db.migrations verify-managed
```

## SQLite adoption and recovery

SQLite adoption requires exclusive ownership and a new backup destination:

```text
python -m ares.db.migrations adopt --confirm-adoption --sqlite-backup <backup-file>
```

The backup is created with SQLite's online backup API, independently checked,
and durably synchronized before the source is locked or changed. The source and
backup are compared under an exclusive lock. Adoption stamps only the proven
predecessor and then runs normal Alembic upgrades on the same connection. The
backup is retained after success and after failure; it is never overwritten or
silently deleted.

If the command reports `ARES-M2B-E10:RECOVERY-REQUIRED`, do not start ARES.
Preserve both files and restore only after establishing exclusive ownership:

```text
python -m ares.db.migrations restore-sqlite --confirm-restore --sqlite-backup <backup-file>
```

Restoration does not delete the backup. A failed application rollout after a
successful adoption normally leaves the additive managed schema installed. Use
the verified backup only when the database itself must be returned to the
pre-adoption state.

## PostgreSQL adoption

Take and verify an external database backup, stop all application workers, and
run:

```text
python -m ares.db.migrations adopt --confirm-adoption --confirm-external-backup
```

PostgreSQL adoption uses one connection, one explicit transaction, and a stable
transaction-scoped advisory lock. Complete verification occurs under that lock;
the proven predecessor is stamped and upgraded through `0011` on the same
connection. DDL, data, and version metadata roll back together on failure.
Concurrent adoption reports a fixed ownership-busy result. Objects in unrelated
schemas are not changed; unexpected objects in the selected schema are rejected.

For multi-worker deployments, keep every worker stopped through backup,
verification, adoption, post-adoption verification, and the application
restart. A committed adoption is idempotent: rerunning verification reports the
already-managed result.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Verified, adopted, restored, or already current |
| 2 | Invalid command or missing confirmation |
| 3 | Fixed configuration or connection failure |
| 4 | Managed revision requires normal migration |
| 5 | Malformed or unknown managed metadata |
| 6 | Unknown, ambiguous, or unsafe unversioned catalog |
| 7 | Exclusive ownership or advisory lock unavailable |
| 8 | Backup creation, durability, or verification failed |
| 9 | Adoption failed and pristine rollback was proven |
| 10 | Recovery state is indeterminate; startup is prohibited |
| 11 | Post-adoption managed verification failed |

Diagnostics are fixed identifiers and never contain database URLs, credentials,
paths, schema identities, SQL, rows, digests, or exception text. Direct or blind
`alembic stamp 0011` is unsupported. Application rollback does not remove
additive schema or migration history.

## Revision 0011 authority and admission

Revision `0011` is an append-only child of the byte-protected `0010` lifecycle
catalog. It adds the C-core authority/admission store contract; it does not
activate an HTTP endpoint, execution engine, worker, or other C-live caller.
Authentication before C-core and live producer integration remain pending.

The migration adds five ordinary authority/observation relations:

1. `campaign_execution_actor_grants`
2. `campaign_execution_destination_authorities`
3. `execution_approval_authorities`
4. `execution_attempt_destination_observations`
5. `execution_attempt_credential_observations`

Existing actor and campaign authority rows gain state, binding-digest, and
latest-operation fields. Credential rows gain execution-authority state,
revision, binding-digest, and latest-operation fields. Logical submissions gain
an admission-authority contract version, canonical principal user identity, and
immutable-intent digest. Attempts gain the authority contract version, trusted
principal references, immutable-intent binding, relevant gateway/grant
revisions, and destination, credential, and approval binding digests.

Upgrade accepts only the exact protected `0010` catalog. Historical logical and
attempt rows are marked contract v2 without changing the meaning or replay of
their existing bindings. The migration fabricates no historical attempt
destination/credential observation and no historical approval. Current
campaign destination authority is initialized from the campaign's stored
destination configuration; current credential authority starts active at
revision zero with a deterministic row binding. Neither initialization is used
to reinterpret a historical v2 submission or receipt.

New initial and retry requests use contract v3. New v2 creation and v3-to-v2
downgrade are forbidden. Initial admission creates no operation receipt: the
logical submission remains its sole replay authority. Authority mutations use
receipt-bound operation UUIDs and the fifteen operation codes documented in
[`execution-lifecycle.md`](execution-lifecycle.md). Approval consumption is
single-use and occurs in the same transaction as admission.

Store failures (`invalid_contract`, `conflict_operation`, `authority_stale`,
and `capacity_unavailable`) leave no durable admission rows. Canonical policy
`REJECTED` and `BLOCKED` verdicts are applied terminal admissions and persist
only their logical execution, closing attempt, zero-count outbox row, and
outbox operation receipt; they consume no approval and reserve no budget.
The terminal outbox identity and publication key are derived from the admission
operation and are never caller-supplied. Initial admission still has no
separate admission receipt. Retry contract v3 admits only a canonical accepted
decision.

The migration, data backfill, and revision advance are atomic. A failed upgrade
must roll back and allow a successful retry. Downgrade is refused before
mutation when it could discard authority history or approval-consumption data;
operational recovery is forward-fix-only. Mixed `0010`/`0011` binaries are
unsupported. Validation covers fresh/bootstrap and supported upgrades on both
backends, rollback/retry, catalog drift, deletion/foreign-key history, the full
C-core admission inventory, and all P1-A/P1-B/transition/lifecycle families on
the resulting candidate ledger. C-live endpoint and authentication tests are
not implied by those gates.

## Revision 0010 execution-lifecycle persistence

Revision `0010` adds the eleven-table execution-lifecycle catalog described in
[`execution-lifecycle.md`](execution-lifecycle.md). It seeds no authority,
budget capacity, attempt, approval, output link, or outbox row, and initializes
the gateway singleton in `disabled` mode. It does not activate a gateway or
disable legacy execution paths. Its bytes and existing v2 row meanings are
protected. Mixed `0009`/`0010` binaries are unsupported, and downgrade is
refused before mutation.

## Revision 0009 token-family rollout

Revision `0009` adds refresh-token families, one-time lineage, user
authentication epochs, and bearer-family binding for WebSocket tickets. It is
additive and forward-only. Existing canonical hashed refresh tokens and bearer
tickets are preserved but deliberately moved into revoked `rollout_reset`
families, so every existing browser bearer session must sign in again after the
upgrade. Unsafe legacy refresh identifiers are rejected before revision
advancement; they are never deleted or normalized.

Revision `0009` must be deployed during an atomic maintenance window. Stop all
old workers, back up the database, upgrade, deploy the matching backend and
frontend, and require reauthentication. Workers that require exact revision
`0008` cannot run against `0009`; mixed old/new workers are unsupported. A code
rollback leaves the additive migration installed and requires a compatible
forward deployment rather than a database downgrade.
