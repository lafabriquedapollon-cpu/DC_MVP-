"""CI-only orphan restore rejection and preserved target on SQLCipher copies."""
import os
from pathlib import Path
import hashlib
import shutil


def main():
    from backend.config import settings
    from backend.core.runtime_safety import REHEARSAL_MIGRATION_ONLY, assert_runtime_startup_allowed
    lab=Path(os.environ["DC_LAB_ROOT"]).resolve(strict=True)
    assert os.environ.get("GITHUB_ACTIONS")=="true"
    assert settings.ENVIRONMENT=="e2e_install_rehearsal"
    assert lab.parent==Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    assert settings.DATABASE_URL==f"sqlite:///{lab/'fresh-rehearsal.db'}"
    assert assert_runtime_startup_allowed(settings)==REHEARSAL_MIGRATION_ONLY
    from sqlcipher3 import dbapi2 as driver
    from backend.core.key_material import sqlcipher_passphrase
    from backend.services.backup_service import BackupService
    from backend.services.guided_restore_archive import _validate_database_file
    from backend.services.guided_restore_worker import GuidedRestoreWorker
    from backend.core.schema_runtime import assert_database_at_current_head, CURRENT_ALEMBIC_HEAD
    from backend.database import engine
    from sqlalchemy import create_engine
    from sqlalchemy.pool import NullPool
    key=sqlcipher_passphrase()
    def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
    def build(name, orphan):
        p=lab/name
        assert not p.exists()
        c=driver.connect(str(p))
        try:
            c.execute("PRAGMA key = '"+key.replace("'","''")+"'")
            c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY)")
            c.execute("CREATE TABLE patients(id INTEGER PRIMARY KEY, employer_id REFERENCES users(id))")
            c.execute("CREATE TABLE alembic_version(version_num VARCHAR(32) NOT NULL)")
            c.execute("INSERT INTO alembic_version VALUES (?)",(CURRENT_ALEMBIC_HEAD,))
            c.execute("INSERT INTO users VALUES (1)")
            c.execute("INSERT INTO patients VALUES (1,?)",(999 if orphan else 1,))
            c.commit()
            assert c.execute("PRAGMA integrity_check").fetchone()==("ok",)
        finally: c.close()
        return p
    good=build("good.db",False); bad=build("orphan.db",True)
    target=lab/"restore-target.db"; shutil.copyfile(good,target)
    sentinel=digest(target)
    cipher=BackupService._get_or_create_key()
    good_enc=lab/"good.db.enc"; bad_enc=lab/"orphan.db.enc"
    good_enc.write_bytes(cipher.encrypt(good.read_bytes()))
    bad_enc.write_bytes(cipher.encrypt(bad.read_bytes()))
    def refuses(fn, error):
        try: fn()
        except (RuntimeError, ValueError) as e:
            assert error in str(e), type(e).__name__
        else: raise AssertionError("Orphan copy accepted")
    refuses(lambda: _validate_database_file(bad,"pysqlcipher"),"référentielle")
    refuses(lambda: BackupService.restore_backup(bad_enc,target,verify_sqlcipher=True,passphrase=key),"foreign_key_check")
    assert digest(target)==sentinel
    refuses(lambda: GuidedRestoreWorker._apply_database(bad_enc,target,"pysqlcipher"),"référentielle")
    assert digest(target)==sentinel
    refuses(lambda: BackupService.restore_backup(good_enc,target,verify_sqlcipher=False),"verification required")
    assert digest(target)==sentinel
    _validate_database_file(bad,"pysqlcipher",require_referential_integrity=False)
    BackupService._verify_sqlcipher_file(bad,key,require_referential_integrity=False)
    print("RESTORE_ORPHAN_REJECT_TARGET_UNCHANGED_PASS count=3")
    print("RESCUE_ORPHAN_PRESERVATION_PASS")
    BackupService.restore_backup(good_enc,target,verify_sqlcipher=True,passphrase=key)
    assert digest(target)==digest(good)
    GuidedRestoreWorker._apply_database(good_enc,target,"pysqlcipher")
    _validate_database_file(target,"pysqlcipher")
    print("RESTORE_CLEAN_COPY_PASS count=2")
    for p,orphan in ((good,False),(bad,True)):
        probe=create_engine(engine.url.set(database=str(p)),poolclass=NullPool,hide_parameters=True)
        try:
            if orphan: refuses(lambda: assert_database_at_current_head(probe),"référentielle")
            else: assert_database_at_current_head(probe)
        finally: probe.dispose()
    assert not list(lab.glob(".guided-restore-*.db"))
    assert not list(lab.glob(".tmp_*restore-target.db"))
    print("STARTUP_REFERENTIAL_GATE_PASS")
    print("RESTORE_REFERENTIAL_PROBE_PASS")


if __name__=="__main__":
    main()
