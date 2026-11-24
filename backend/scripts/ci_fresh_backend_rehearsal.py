"""CI-only fresh encrypted rehearsal. Never migrate or open an existing database.

The recovered historical revision is corroborated in the Notion recovery roadmap.
The full migration chain is absent from the export; this is NOT an upgrade or
release certification. Use the existing empty-baseline helper, never stamp by hand.
"""
import os
import pathlib
import sqlite3

from backend.config import settings
from backend.core.runtime_safety import (
    REHEARSAL_MIGRATION_ONLY,
    assert_runtime_startup_allowed,
)
from backend.core.schema_runtime import (
    CURRENT_ALEMBIC_HEAD,
    assert_database_at_current_head,
)
from backend.core.sqlite_alembic_baseline import bootstrap_empty_sqlite_to_head


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("CI-only rehearsal")
    if settings.ENVIRONMENT != "e2e_install_rehearsal":
        raise RuntimeError("Expected rehearsal environment")
    lab = pathlib.Path(os.environ["DC_LAB_ROOT"]).resolve(strict=True)
    db = lab / "fresh-rehearsal.db"
    if lab.parent != pathlib.Path(os.environ["RUNNER_TEMP"]).resolve(strict=True):
        raise RuntimeError("LAB must be directly inside runner temp")
    if settings.DATABASE_URL != f"sqlite:///{db}" or db.exists() or db.is_symlink():
        raise RuntimeError("Refusing non-fresh or unexpected database")
    if assert_runtime_startup_allowed(settings) != REHEARSAL_MIGRATION_ONLY:
        raise RuntimeError("Isolation guard failed")
    if CURRENT_ALEMBIC_HEAD != "neo000000033":
        raise RuntimeError("Recovered historical revision mismatch")
    # Import the actual application to load its complete ORM registry, exactly
    # as it will be loaded by the subsequent Uvicorn process. No lifespan yet.
    from backend.main import app
    from backend import models, database
    from sqlalchemy import inspect, text
    if app is None or database.engine.dialect.driver != "pysqlcipher":
        raise RuntimeError("Actual application/SQLCipher driver required")
    print("FASTAPI_IMPORT_PASS", flush=True)
    # Match the operator baseline metadata, including default-inert print tables.
    from backend.core.operator_baseline_metadata import register_operator_baseline_metadata
    from backend.core.print_audit_ddl import PROTECTED_PRINT_AUDITS
    register_operator_baseline_metadata(models.Base.metadata)
    print("OPERATOR_BASELINE_METADATA_PASS", flush=True)
    with database.engine.begin() as connection:
        if not connection.execute(text("PRAGMA cipher_version")).scalar():
            raise RuntimeError("SQLCipher unavailable")
        if not bootstrap_empty_sqlite_to_head(
            connection, models.Base.metadata, [CURRENT_ALEMBIC_HEAD]
        ):
            raise RuntimeError("Fresh baseline rejected")
    assert_database_at_current_head(database.engine)
    with database.engine.connect() as connection:
        tables = set(inspect(connection).get_table_names())
        expected = set(models.Base.metadata.tables)
        if not expected <= tables:
            raise RuntimeError("Incomplete ORM metadata")
        required_guards = {
            f"dc_immutable_{table}_{operation}"
            for table in PROTECTED_PRINT_AUDITS
            for operation in ("update", "delete")
        }
        installed_guards = set(connection.execute(text(
            "SELECT name FROM sqlite_master WHERE type = 'trigger'"
        )).scalars())
        if not required_guards <= installed_guards:
            raise RuntimeError("Append-only print audit guards missing")
        print(f"PRINT_AUDIT_GUARDS_PRESENT count={len(required_guards)}", flush=True)
        for table in ("patients", "users"):
            if connection.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar() != 0:
                raise RuntimeError("Synthetic baseline unexpectedly populated")
    database.engine.dispose()
    try:
        with sqlite3.connect(db) as plain:
            plain.execute("SELECT name FROM sqlite_master").fetchall()
    except sqlite3.DatabaseError:
        pass
    else:
        raise RuntimeError("Database unexpectedly readable without SQLCipher")
    print(f"FRESH_SQLCIPHER_BASELINE_PASS tables={len(tables)} revision={CURRENT_ALEMBIC_HEAD} users=0 patients=0")


if __name__ == "__main__":
    main()
