# Database migrations and verified adoption

Alembic is the canonical schema history for every persistent ARES database.
Fresh databases are initialized as managed databases and current managed
databases are validated at startup. Application startup never stamps or adopts
an existing unversioned catalog.

## Managed and unversioned databases

A managed database has one valid `alembic_version` relation and exactly one
known revision row. Revision `0009` is current and forward-only. Managed
revisions `0001` through `0008` use normal Alembic migration; malformed or
unknown version metadata is rejected.

An unversioned database has no Alembic version relation. The adoption verifier
accepts only the complete, audited runtime-bootstrap generations 6 and 7. It
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
`ARES-M2B-ALREADY-MANAGED:0009`. No version relation is created by verification.

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
the proven predecessor is stamped and upgraded through `0009` on the same
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
`alembic stamp 0009` is unsupported. Application rollback does not remove
additive schema or migration history.

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
