"""CI-only Windows packaging probe for the real Digital Crown database module.

Not a clinical launcher, installer, migration or patient database. No network
services or actual application startup. Each child validates its disposable root
before importing any backend package.
"""
from pathlib import Path
from types import SimpleNamespace
import os
import sqlite3
import stat
import sys


def require(condition, marker):
    if not condition:
        raise RuntimeError(marker)


def check_root():
    require(os.name == "nt" and os.environ.get("GITHUB_ACTIONS") == "true",
            "WINDOWS_CI_ONLY")
    require(os.environ.get("ENVIRONMENT") == "e2e_install_rehearsal", "REHEARSAL_ONLY")
    root = Path(os.environ["DC_NATIVE_PROBE_ROOT"])
    runner = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    require(root.is_absolute() and root.parent.resolve(strict=True) == runner
            and root.name.startswith("dc-native-probe-") and root.is_dir()
            and not root.is_symlink() and not (getattr(root.stat(), "st_file_attributes", 0)
            & stat.FILE_ATTRIBUTE_REPARSE_POINT), "INVALID_PROBE_ROOT")
    for name in ("DIGITALCROWN_USER_DATA_DIR", "DIGITALCROWN_CONFIG_DIR",
                 "DIGITALCROWN_LOG_DIR", "DIGITALCROWN_RUNTIME_DIR", "MEDIA_ROOT"):
        require(Path(os.environ[name]) == root, "INVALID_DATA_ROOT")
    env_file = root / "empty-rehearsal.env"
    require(Path(os.environ["DIGITALCROWN_ENV_FILE"]) == env_file
            and env_file.is_file() and not env_file.is_symlink()
            and env_file.stat().st_size == 0, "INVALID_ENV_FILE")
    db = root / "synthetic-native.db"
    require(os.environ["DATABASE_URL"] == f"sqlite:///{db}" and not db.is_symlink(),
            "INVALID_DB_TARGET")
    return db


def main():
    db = check_root()
    stage = sys.argv[1]
    require(stage in {"write", "read", "wrong"}, "INVALID_STAGE")
    require((stage == "write" and not db.exists()) or
            (stage != "write" and db.is_file()), "INVALID_DB_STATE")
    from backend.core.runtime_safety import (
        REHEARSAL_MIGRATION_ONLY, assert_runtime_startup_allowed,
        database_target_fingerprint,
    )
    os.environ["DIGITALCROWN_ISOLATION_DB_FINGERPRINT"] = database_target_fingerprint(
        os.environ["DATABASE_URL"])
    require(assert_runtime_startup_allowed(SimpleNamespace(
        ENVIRONMENT=os.environ["ENVIRONMENT"], DATABASE_URL=os.environ["DATABASE_URL"]
    )) == REHEARSAL_MIGRATION_ONLY, "ISOLATION_GUARD_FAILED")

    from backend.database import engine
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError, IntegrityError
    require(engine.dialect.driver == "pysqlcipher", "SQLCIPHER_FALLBACK_REFUSED")
    try:
        if stage == "wrong":
            try:
                with engine.connect() as conn:
                    conn.execute(text("SELECT name FROM sqlite_master")).all()
            except DBAPIError as exc:
                require("not a database" in str(exc.orig).lower(), "UNEXPECTED_WRONG_KEY_ERROR")
            else:
                raise RuntimeError("WRONG_KEY_ACCEPTED")
            print("R02_NATIVE_WRONG_KEY_DENIED_PASS", flush=True)
            return
        with engine.begin() as conn:
            require(bool(conn.execute(text("PRAGMA cipher_version")).scalar()), "CIPHER_MISSING")
            require(conn.execute(text("PRAGMA foreign_keys")).scalar() == 1, "FK_DISABLED")
            if stage == "write":
                conn.execute(text("CREATE TABLE synthetic_parent (id INTEGER PRIMARY KEY)"))
                conn.execute(text("CREATE TABLE synthetic_child (id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL REFERENCES synthetic_parent(id))"))
                conn.execute(text("INSERT INTO synthetic_parent VALUES (1)"))
                conn.execute(text("INSERT INTO synthetic_child VALUES (1, 1)"))
            else:
                require(conn.execute(text("SELECT parent_id FROM synthetic_child WHERE id=1")).scalar() == 1, "PERSISTENCE_FAILED")
            require(conn.execute(text("PRAGMA integrity_check")).scalar() == "ok", "INTEGRITY_FAILED")
            require(not conn.execute(text("PRAGMA foreign_key_check")).all(), "FK_INTEGRITY_FAILED")
        try:
            with engine.begin() as conn:
                conn.execute(text("INSERT INTO synthetic_child VALUES (2, 999)"))
        except IntegrityError:
            pass
        else:
            raise RuntimeError("ORPHAN_ACCEPTED")
        try:
            with engine.begin() as conn:
                conn.execute(text("PRAGMA foreign_keys=OFF"))
        except DBAPIError:
            pass
        else:
            raise RuntimeError("FK_DISABLE_ACCEPTED")
        with engine.connect() as conn:
            require(conn.execute(text("PRAGMA foreign_keys")).scalar() == 1, "FK_DISABLED_AFTER_DENIAL")
            require(conn.execute(text("SELECT COUNT(*) FROM synthetic_child")).scalar() == 1, "UNEXPECTED_ROW")
        print("R02_NATIVE_" + stage.upper() + "_FK_INTEGRITY_PASS", flush=True)
    finally:
        engine.dispose()
    try:
        with sqlite3.connect(db) as plain:
            plain.execute("SELECT name FROM sqlite_master").fetchall()
    except sqlite3.DatabaseError:
        print("R02_NATIVE_PLAINTEXT_DENIED_PASS", flush=True)
    else:
        raise RuntimeError("PLAINTEXT_READ_ACCEPTED")


if __name__ == "__main__":
    main()
