"""CI-only probe of actual application SQLCipher pool and referential actions."""
import os
from pathlib import Path


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("ENVIRONMENT") != "e2e_install_rehearsal":
        raise RuntimeError("CI rehearsal only")
    lab = Path(os.environ["DC_LAB_ROOT"]).resolve(strict=True)
    db = lab / "fresh-rehearsal.db"
    if lab.parent != Path(os.environ["RUNNER_TEMP"]).resolve(strict=True) or db.is_symlink() or not db.is_file():
        raise RuntimeError("Invalid synthetic LAB")
    if os.environ.get("DATABASE_URL") != f"sqlite:///{db}":
        raise RuntimeError("Unexpected database")
    if {p.name for p in Path("/sys/class/net").iterdir()} != {"lo"}:
        # Network namespaces may not be reflected by sysfs on every runner;
        # use the actual namespace interface list instead.
        import subprocess
        assert len(subprocess.check_output(["ip", "-o", "link", "show"], text=True).splitlines()) == 1
    from backend.config import settings
    from backend.core.runtime_safety import REHEARSAL_MIGRATION_ONLY, assert_runtime_startup_allowed
    assert assert_runtime_startup_allowed(settings) == REHEARSAL_MIGRATION_ONLY
    from backend.database import engine
    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError

    assert engine.dialect.driver == "pysqlcipher"
    assert Path(engine.url.database).resolve() == db
    def scalar(c, sql):
        return c.execute(text(sql)).scalar()
    def check(c):
        assert scalar(c, "PRAGMA foreign_keys") == 1
        assert scalar(c, "PRAGMA cipher_version")
    def rejected(sql):
        try:
            with engine.begin() as c:
                c.execute(text(sql))
        except IntegrityError as e:
            assert "FOREIGN KEY constraint failed" in str(e.orig)
        else:
            raise AssertionError("Orphan mutation accepted")

    # Verify multiple live pool connections, not just the first.
    with engine.connect() as a, engine.connect() as b:
        check(a)
        check(b)
        assert not a.execute(text("PRAGMA foreign_key_check")).fetchall()
        assert scalar(a, "SELECT COUNT(*) FROM users") == 0
        assert scalar(a, "SELECT COUNT(*) FROM patients") == 0
    print("FK_MULTIPLE_CONNECTIONS_PASS")
    # Disposable tables isolate cascade semantics from clinical schemas.
    # The real workstation declaration is separately checked with an orphan insert.
    with engine.begin() as c:
        c.execute(text("CREATE TABLE ci_fk_parent(id INTEGER PRIMARY KEY)"))
        c.execute(text("CREATE TABLE ci_fk_cascade(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES ci_fk_parent(id) ON DELETE CASCADE)"))
        c.execute(text("CREATE TABLE ci_fk_setnull(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES ci_fk_parent(id) ON DELETE SET NULL)"))
        c.execute(text("INSERT INTO ci_fk_parent VALUES (1)"))
        c.execute(text("INSERT INTO ci_fk_cascade VALUES (1,1)"))
        c.execute(text("INSERT INTO ci_fk_setnull VALUES (1,1)"))
    rejected("INSERT INTO ci_fk_cascade VALUES (2,999)")
    rejected("UPDATE ci_fk_setnull SET parent_id=999 WHERE id=1")
    rejected("INSERT INTO workstation_modes(id,employer_id,token_hash,mode_revision,created_at,updated_at) VALUES ('CI-FK-ORPHAN',999999,'ci-fk-token',0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)")
    with engine.begin() as c:
        c.execute(text("DELETE FROM ci_fk_parent WHERE id=1"))
        assert scalar(c,"SELECT COUNT(*) FROM ci_fk_cascade") == 0
        assert scalar(c,"SELECT COUNT(*) FROM ci_fk_setnull WHERE parent_id IS NULL") == 1
        c.execute(text("DROP TABLE ci_fk_cascade"))
        c.execute(text("DROP TABLE ci_fk_setnull"))
        c.execute(text("DROP TABLE ci_fk_parent"))
        assert not c.execute(text("PRAGMA foreign_key_check")).fetchall()
    print("FK_ORPHAN_INSERT_UPDATE_AND_WORKSTATION_DENIED_PASS count=3")
    print("FK_CASCADE_SET_NULL_PASS count=2")
    # Disable enforcement deliberately on a checked-out synthetic connection,
    # return it, then prove checkout discards it and creates an enforced one.
    engine.dispose()
    with engine.connect() as c:
        check(c)
        c.exec_driver_sql("PRAGMA foreign_keys=OFF")
        assert scalar(c,"PRAGMA foreign_keys") == 0
    with engine.connect() as c:
        check(c)
    engine.dispose()
    with engine.connect() as c:
        check(c)
        assert not c.execute(text("PRAGMA foreign_key_check")).fetchall()
        assert scalar(c,"PRAGMA integrity_check") == "ok"
    print("FK_POOL_TAMPER_RECONNECT_PASS")
    print("FK_RUNTIME_PROBE_PASS")


if __name__ == "__main__":
    main()
