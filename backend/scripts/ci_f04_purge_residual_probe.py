"""Synthetic-only residual checks of archive deletion, media and rollback."""
import os
from pathlib import Path
from datetime import datetime
from sqlalchemy import event, text
from backend.core.runtime_safety import REHEARSAL_MIGRATION_ONLY, assert_runtime_startup_allowed

def main():
    from backend.config import settings
    lab=Path(os.environ["DC_LAB_ROOT"]).resolve(strict=True)
    assert os.environ.get("GITHUB_ACTIONS")=="true"
    assert settings.ENVIRONMENT=="e2e_install_rehearsal"
    assert lab.parent==Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    assert settings.DATABASE_URL==f"sqlite:///{lab/'fresh-rehearsal.db'}"
    assert assert_runtime_startup_allowed(settings)==REHEARSAL_MIGRATION_ONLY
    from backend import database, models
    from backend.services.archive_service import ArchiveService
    assert database.engine.dialect.driver=="pysqlcipher"
    with database.SessionLocal() as db:
        p=db.query(models.Patient).one()
        assert p.nom=="CI-SYNTHETIC"
        owner=db.query(models.User).filter_by(email="ci-retain-owner@example.com").one()
        pid=p.id
        uid=owner.id
        def new(name,path):
            row=models.DocumentArchive(patient_id=pid,uploaded_by_id=uid,document_type=models.DocumentType.AUTRE,
                filename=name,original_filename=name,document_group_id=name,
                file_hash="c"*64,file_size=9,file_path=str(path))
            db.add(row); db.flush()
            return row.id
        ordinary=lab/"unreferenced.txt"
        shared=lab/"shared.txt"
        rollback=lab/"rollback.txt"
        for path in (ordinary,shared,rollback):
            path.write_bytes(b"synthetic")
        ordinary_id=new("ordinary",ordinary)
        shared_a=new("shared_a",shared)
        shared_b=new("shared_b",shared)
        rollback_id=new("rollback",rollback)
        db.commit()
        service=ArchiveService(db)
        assert service.permanent_delete(ordinary_id)
        assert db.get(models.DocumentArchive,ordinary_id) is None and not ordinary.exists()
        print("F04_PURGE_UNREFERENCED_PASS")
        assert service.permanent_delete(shared_a)
        assert db.get(models.DocumentArchive,shared_a) is None
        assert db.get(models.DocumentArchive,shared_b) is not None
        assert shared.read_bytes()==b"synthetic"
        print("F04_PURGE_SHARED_MEDIA_PASS")
        class InjectedCommitFailure(RuntimeError): pass
        def reject_commit(session):
            raise InjectedCommitFailure("synthetic")
        event.listen(db,"before_commit",reject_commit)
        try:
            try: service.permanent_delete(rollback_id)
            except InjectedCommitFailure: pass
            else: raise AssertionError("commit failure not injected")
        finally:
            event.remove(db,"before_commit",reject_commit)
            db.rollback()
        assert db.get(models.DocumentArchive,rollback_id) is not None
        assert rollback.read_bytes()==b"synthetic"
        assert not db.execute(text("PRAGMA foreign_key_check")).fetchall()
        print("F04_PURGE_COMMIT_FAILURE_PRESERVES_MEDIA_PASS")
    database.engine.dispose()
    with database.SessionLocal() as db:
        assert db.get(models.DocumentArchive,rollback_id) is not None
        assert db.get(models.DocumentArchive,shared_b) is not None
        assert rollback.read_bytes()==shared.read_bytes()==b"synthetic"
        assert db.get(models.DocumentArchive,ordinary_id) is None
    print("F04_PURGE_RESIDUAL_PROBE_PASS count=3")

if __name__=="__main__":
    main()
