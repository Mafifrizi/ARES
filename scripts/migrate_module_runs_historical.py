#!/usr/bin/env python3
"""
scripts/migrate_module_runs_historical.py

One-off migration to normalize historical module_runs outcome and success columns.
Converts stringified Enum values ('ModuleStatus.DONE', 'ModuleStatus.FAILED') to
lowercase canonical strings ('done', 'failed') and sets success flag appropriately.

Supports SQLite and PostgreSQL. Idempotent and transaction-safe.
"""

import argparse
import os
import sys


def migrate_sqlite(db_path: str, dry_run: bool, skip_backup_check: bool = False) -> None:
    import sqlite3

    if not os.path.exists(db_path):
        print(f"ERROR: SQLite database file not found at: {db_path}", file=sys.stderr)
        sys.exit(1)

    backup_path = f"{db_path}.backup"
    if not dry_run and not skip_backup_check and not os.path.exists(backup_path):
        print(
            f"ERROR: Safety check failed. Expected backup file '{backup_path}' not found.\n"
            f"Create a backup before running without --dry-run, or pass --skip-backup-check.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"Connecting to SQLite database: {db_path}")
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()

        print("--- CURRENT STATE IN SQLite ---")
        cur.execute(
            "SELECT outcome, success, COUNT(*) FROM module_runs "
            "GROUP BY outcome, success ORDER BY outcome, success"
        )
        for row in cur.fetchall():
            print(f"  outcome: {row[0]!r:<24} | success: {row[1]!r:<6} | count: {row[2]}")

        cur.execute("SELECT COUNT(*) FROM module_runs WHERE outcome = 'ModuleStatus.DONE'")
        done_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM module_runs WHERE outcome = 'ModuleStatus.FAILED'")
        failed_count = cur.fetchone()[0]

        total_affected = done_count + failed_count
        print(f"\nRows to migrate: {total_affected} (DONE: {done_count}, FAILED: {failed_count})")

        if dry_run:
            print("[DRY-RUN] No changes were written to database.")
            return

        if total_affected == 0:
            print("Database is already up to date. 0 rows modified.")
            return

        cur.execute(
            "UPDATE module_runs SET success = 1, outcome = 'done' WHERE outcome = 'ModuleStatus.DONE'"
        )
        cur.execute(
            "UPDATE module_runs SET outcome = 'failed' WHERE outcome = 'ModuleStatus.FAILED'"
        )
        conn.commit()
        print(f"Successfully migrated {total_affected} rows.")

        print("\n--- FINAL STATE IN SQLite ---")
        cur.execute(
            "SELECT outcome, success, COUNT(*) FROM module_runs "
            "GROUP BY outcome, success ORDER BY outcome, success"
        )
        for row in cur.fetchall():
            print(f"  outcome: {row[0]!r:<24} | success: {row[1]!r:<6} | count: {row[2]}")

    except Exception as exc:
        conn.rollback()
        print(f"ERROR: Migration failed, rolled back transaction: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        conn.close()


def migrate_postgres(dsn: str, dry_run: bool) -> None:
    try:
        import psycopg2
    except ImportError:
        print("ERROR: psycopg2 is required for PostgreSQL migration.", file=sys.stderr)
        sys.exit(1)

    print("Connecting to PostgreSQL...")
    conn = psycopg2.connect(dsn)
    try:
        with conn.cursor() as cur:
            print("--- CURRENT STATE IN PostgreSQL ---")
            cur.execute(
                "SELECT outcome, success, COUNT(*) FROM module_runs "
                "GROUP BY outcome, success ORDER BY outcome, success"
            )
            for row in cur.fetchall():
                print(f"  outcome: {row[0]!r:<24} | success: {row[1]!r:<6} | count: {row[2]}")

            cur.execute("SELECT COUNT(*) FROM module_runs WHERE outcome = 'ModuleStatus.DONE'")
            done_count = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM module_runs WHERE outcome = 'ModuleStatus.FAILED'")
            failed_count = cur.fetchone()[0]

            total_affected = done_count + failed_count
            print(f"\nRows to migrate: {total_affected} (DONE: {done_count}, FAILED: {failed_count})")

            if dry_run:
                conn.rollback()
                print("[DRY-RUN] No changes were written to database.")
                return

            if total_affected == 0:
                print("Database is already up to date. 0 rows modified.")
                return

            cur.execute(
                "UPDATE module_runs SET success = TRUE, outcome = 'done' WHERE outcome = 'ModuleStatus.DONE'"
            )
            cur.execute(
                "UPDATE module_runs SET outcome = 'failed' WHERE outcome = 'ModuleStatus.FAILED'"
            )
            conn.commit()
            print(f"Successfully migrated {total_affected} rows.")

    except Exception as exc:
        conn.rollback()
        print(f"ERROR: Migration failed, rolled back transaction: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="One-off migration to normalize module_runs historical outcome and success columns."
    )
    parser.add_argument(
        "--backend",
        choices=["sqlite", "postgres"],
        required=True,
        help="Database backend (explicit selection required: 'sqlite' or 'postgres')",
    )
    parser.add_argument(
        "--db-path",
        default="ares.db",
        help="Path to SQLite database file (default: ares.db)",
    )
    parser.add_argument(
        "--pg-dsn",
        default=os.environ.get("ARES_POSTGRES_DSN", ""),
        help="PostgreSQL DSN / connection string (default: $ARES_POSTGRES_DSN)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate migration and report affected rows without applying changes",
    )
    parser.add_argument(
        "--skip-backup-check",
        action="store_true",
        help="Bypass verification of backup file existence",
    )

    args = parser.parse_args()

    if args.backend == "sqlite":
        migrate_sqlite(args.db_path, dry_run=args.dry_run, skip_backup_check=args.skip_backup_check)
    elif args.backend == "postgres":
        if not args.pg_dsn:
            print("ERROR: --pg-dsn or ARES_POSTGRES_DSN environment variable required for postgres backend.", file=sys.stderr)
            sys.exit(1)
        migrate_postgres(args.pg_dsn, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
