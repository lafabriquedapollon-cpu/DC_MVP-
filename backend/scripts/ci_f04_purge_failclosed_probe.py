"""Synthetic SQLCipher proof: fail closed on manual and automatic media purge."""
import os
from pathlib import Path
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
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
    from backend.main import app
    from backend.security import create_access_token
    from backend.services.archive_service import ArchiveService, ReferencedArchiveDeletionDenied
    from fastapi.testclient import TestClient
    from sqlalchemy import text
    assert database.engine.dialect.driver=="pysqlcipher"
    media=lab/"purge-shared.txt"; media.write_bytes(b"synthetic")
    absent=lab/"purge-missing.txt"
    assert not absent.exists()
    with database.SessionLocal() as db:
        patient=db.query(models.Patient).one()
        assert patient.nom=="CI-SYNTHETIC"
        owner=db.query(models.User).filter_by(email="ci-retain-owner@example.com").one()
        # Reopen only the synthetic patient to exercise the real auth boundary.
        patient.deleted_at=None; patient.deleted_by=None
        pid=patient.id; uid=owner.id
        token=create_access_token(data={"sub":owner.email})
        def add(db,name,path):
            doc=models.DocumentArchive(patient_id=pid,uploaded_by_id=uid,document_type=models.DocumentType.AUTRE,
                filename=name,original_filename=name,document_group_id=name,file_hash="d"*64,
                file_size=9,file_path=str(path),status=models.DocumentStatus.SUPPRIME,
                deleted_at=datetime.now()-timedelta(days=400),
                permanent_delete_at=datetime.now()-timedelta(days=1))
            db.add(doc); db.flush()
            return doc.id
        ordinary=add(db,"ci-purge-original",media)
        missing=add(db,"ci-purge-missing",absent)
        db.commit()
    def deny(db,ident):
        try:
            ArchiveService(db).permanent_delete(ident)
        except ReferencedArchiveDeletionDenied as exc:
            assert "maintenance hors ligne" in str(exc)
            db.rollback()
        else:
            raise AssertionError("Unsafe runtime purge accepted")
    with TestClient(app) as client:
        for ident in (ordinary,missing):
            response=client.delete(f"/api/documents/{ident}?confirm=true",headers={"Authorization":"Bearer "+token})
            assert response.status_code==409,response.status_code
            assert "maintenance hors ligne" in response.json()["detail"]
    print("F04_PURGE_API_FAILCLOSED_PASS count=2")
    with database.SessionLocal() as db:
        assert ArchiveService(db).cleanup_expired_trash()==0
        assert db.get(models.DocumentArchive,ordinary)
        assert db.get(models.DocumentArchive,missing)
        assert media.read_bytes()==b"synthetic"
    print("F04_PURGE_EXPIRED_CLEANUP_PRESERVATION_PASS")
    # Two actual sessions: new shared reference and repeated purge requests.
    # The runtime purge has no destructive branch, regardless of scheduling.
    barrier=Barrier(2)
    def writer():
        with database.SessionLocal() as db:
            barrier.wait(timeout=20)
            ident=add(db,"ci-purge-concurrent",media)
            db.commit()
            return ident
    def purger():
        with database.SessionLocal() as db:
            barrier.wait(timeout=20)
            for _ in range(5):
                deny(db,ordinary)
    with ThreadPoolExecutor(max_workers=2) as pool:
        wr=pool.submit(writer); pr=pool.submit(purger)
        new_id=wr.result(timeout=30); pr.result(timeout=30)
    database.engine.dispose()
    with database.SessionLocal() as db:
        for ident in (ordinary,missing,new_id):
            assert db.get(models.DocumentArchive,ident)
        assert db.get(models.DocumentArchive,new_id).file_path==str(media)
        assert media.read_bytes()==b"synthetic"
        assert not absent.exists()
        assert not db.execute(text("PRAGMA foreign_key_check")).fetchall()
    print("F04_PURGE_CONCURRENT_REFERENCE_PRESERVATION_PASS")
    print("F04_RUNTIME_PURGE_FAILCLOSED_PASS")

if __name__=="__main__":
    main()
