"""
ARES Alembic migrations package.

CLI usage:
    alembic upgrade head           # Apply all pending migrations
    alembic upgrade +1             # Apply one step forward
    alembic downgrade -1           # Roll back one step
    alembic revision -m "add_X"   # Create new migration (auto-generates file)
    alembic history                # Show migration chain
    alembic current                # Show which revision is active in the DB

Programmatic usage (done automatically at startup):
    from ares.db.database import AresDatabase
    db = await AresDatabase.connect("ares.db")
    # Migrations run automatically in connect()

Adding a new migration:
    1. alembic revision -m "describe_your_change"
    2. Edit the generated file in migrations/versions/
    3. Implement upgrade() and downgrade()
    4. Test: alembic upgrade head && alembic downgrade -1
"""
