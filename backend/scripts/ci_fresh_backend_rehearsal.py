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



def verify_print_audit_persistence(engine, metadata, lab, protected_tables):
    """Exercise real guards on a SECOND disposable encrypted database, never the HTTP DB."""
    from datetime import datetime, timezone
    import secrets

    from sqlalchemy import create_engine, event, text
    from sqlalchemy.exc import DBAPIError, IntegrityError
    from sqlalchemy.pool import NullPool

    path = lab / "audit-guard-synthetic.db"
    if path.exists() or path.is_symlink():
        raise RuntimeError("Guard test requires a new database")
    # Retain the application's exact SQLCipher dialect and key, but not its DB path.
    url = engine.url.set(database=str(path))
    test_engine = create_engine(url, poolclass=NullPool, hide_parameters=True)

    @event.listens_for(test_engine, "connect")
    def enable_fk(dbapi_connection, _record):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")

    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    tenant = 1
    printer = "CI-SYNTHETIC-NOT-A-DEVICE"
    delivery = "a" * 64
    evidence = "b" * 64
    fixtures = {
        "station_print_config_audit": dict(
            tenant_id=tenant, revision=1, actor_user_id=tenant,
            mode="disabled", changed_at=now,
        ),
        "station_print_claim_events": dict(
            tenant_id=tenant, delivery_key=delivery, revision=1,
            transition="held_reserved", created_at=now,
        ),
        "station_print_device_evidence": dict(
            tenant_id=tenant, printer_id=printer, evidence_sha256=evidence,
            recorded_by=tenant, status="pending_field_verification", recorded_at=now,
        ),
        "station_print_uncertain_reviews": dict(
            tenant_id=tenant, delivery_key=delivery, reviewed_by=tenant,
            finding="investigating", evidence_sha256=evidence, recorded_at=now,
        ),
    }
    if set(fixtures) != set(protected_tables):
        raise RuntimeError("Guard fixture coverage mismatch")
    try:
        with test_engine.begin() as connection:
            if connection.dialect.driver != "pysqlcipher":
                raise RuntimeError("Expected SQLCipher on guard test")
            if not connection.execute(text("PRAGMA cipher_version")).scalar():
                raise RuntimeError("Missing cipher version")
            if connection.execute(text("PRAGMA foreign_keys")).scalar() != 1:
                raise RuntimeError("Fixture FK enforcement missing")
            if not bootstrap_empty_sqlite_to_head(
                connection, metadata, [CURRENT_ALEMBIC_HEAD]
            ):
                raise RuntimeError("Guard test baseline rejected")
            connection.execute(metadata.tables["users"].insert().values(
                id=tenant, email="ci-audit-fixture@example.invalid",
                hashed_password="INVALID-NOT-A-PASSWORD-HASH",
                is_active=False, is_licensed=False,
                is_archived=True, is_suspended=True,
            ))
            connection.execute(metadata.tables["station_print_printer_drafts"].insert().values(
                tenant_id=tenant, printer_id=printer, location="reception",
                station_id=None, revision=1, updated_by=tenant, updated_at=now,
            ))
            connection.execute(metadata.tables["station_print_held_claims"].insert().values(
                tenant_id=tenant, delivery_key=delivery, first_printer_id=printer,
                state="uncertain", revision=1, created_at=now, updated_at=now,
            ))
            for name, values in fixtures.items():
                connection.execute(metadata.tables[name].insert().values(**values))
            if connection.execute(text("PRAGMA foreign_key_check")).fetchall():
                raise RuntimeError("Fixture foreign key violation")
        # Successful commit and independent connections prove actual persistence.
        test_engine.dispose()
        snapshots = {}
        with test_engine.connect() as connection:
            for name in protected_tables:
                rows = connection.execute(metadata.tables[name].select()).fetchall()
                if len(rows) != 1:
                    raise RuntimeError("Missing persisted fixture: " + name)
                snapshots[name] = rows
            if connection.execute(text("SELECT COUNT(*) FROM patients")).scalar() != 0:
                raise RuntimeError("Unexpected patient data")
            if connection.execute(text("PRAGMA integrity_check")).scalar() != "ok":
                raise RuntimeError("Guard fixture database integrity check failed")
        rejected = 0
        for name in protected_tables:
            table = metadata.tables[name]
            key = next(iter(table.primary_key.columns))
            for statement in (table.update().values({key.name: key}), table.delete()):
                try:
                    with test_engine.begin() as connection:
                        connection.execute(statement)
                except IntegrityError as exc:
                    if "DC_PRINT_AUDIT_APPEND_ONLY" not in str(exc.orig):
                        raise RuntimeError("Unexpected rejection reason: " + name) from None
                    rejected += 1
                else:
                    raise RuntimeError("Audit mutation unexpectedly allowed: " + name)
        test_engine.dispose()
        with test_engine.connect() as connection:
            for name in protected_tables:
                if connection.execute(metadata.tables[name].select()).fetchall() != snapshots[name]:
                    raise RuntimeError("Audit row changed: " + name)
            if connection.execute(text("PRAGMA foreign_key_check")).fetchall():
                raise RuntimeError("Foreign key check failed after mutation attempts")
        assert_database_at_current_head(test_engine)
        # A nonempty database must not be rebuilt or restamped by the baseline helper.
        with test_engine.begin() as connection:
            if bootstrap_empty_sqlite_to_head(connection, metadata, [CURRENT_ALEMBIC_HEAD]):
                raise RuntimeError("Nonempty baseline unexpectedly accepted")
        wrong_engine = create_engine(
            url.set(password=secrets.token_hex(32)), poolclass=NullPool,
            hide_parameters=True,
        )
        try:
            try:
                with wrong_engine.connect() as connection:
                    connection.execute(text("SELECT name FROM sqlite_master")).fetchall()
            except DBAPIError as exc:
                if "not a database" not in str(exc.orig).lower():
                    raise RuntimeError("Unexpected wrong-key rejection") from None
            else:
                raise RuntimeError("Wrong SQLCipher key unexpectedly accepted")
        finally:
            wrong_engine.dispose()
        if rejected != 2 * len(protected_tables):
            raise RuntimeError("Guard negative-test coverage mismatch")
        print(f"PRINT_AUDIT_MUTATION_DENIED_PASS count={rejected}", flush=True)
        print(f"PRINT_AUDIT_PERSISTENCE_PASS tables={len(snapshots)}", flush=True)
        print("SQLCIPHER_WRONG_KEY_DENIED_PASS", flush=True)
        print("NONEMPTY_BASELINE_REFUSED_PASS", flush=True)
        print("SYNTHETIC_FIXTURE_FK_INTEGRITY_PASS", flush=True)
    finally:
        test_engine.dispose()


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
    verify_print_audit_persistence(database.engine, models.Base.metadata, lab, PROTECTED_PRINT_AUDITS)
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
