"""
ARES Database Migrations — Alembic is canonical.

This package previously contained a custom migration runner (runner.py).
That has been removed. Alembic in migrations/ at repo root is the single
source of truth for all schema changes.

To run migrations:
    alembic upgrade head           # apply all pending
    alembic downgrade -1           # roll back one step
    alembic revision -m "add_x"   # create a new migration

AresDatabase.connect() runs `alembic upgrade head` automatically at startup.
See: migrations/versions/ for the migration chain.
"""
# Nothing to import — Alembic is invoked programmatically via database.py

# No public exports — Alembic is invoked programmatically.
__all__: list = []
