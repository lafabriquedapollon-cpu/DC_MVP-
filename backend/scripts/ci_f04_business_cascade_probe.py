"""CI only: real patient archive, document lifecycle and installment references."""
import os
from pathlib import Path
from datetime import datetime


def main():
    from backend.config import settings
    from backend.core.runtime_safety import REHEARSAL_MIGRATION_ONLY, assert_runtime_startup_allowed
    lab=Path(os.environ["DC_LAB_ROOT"]).resolve(strict=True)
    assert os.environ.get("GITHUB_ACTIONS")=="true"
    assert settings.ENVIRONMENT=="e2e_install_rehearsal"
    assert lab.parent==Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    assert settings.DATABASE_URL==f"sqlite:///{lab/'fresh-rehearsal.db'}"
    assert assert_runtime_startup_allowed(settings)==REHEARSAL_MIGRATION_ONLY
    from backend.main import app
    from backend import database, models
    from backend.security import create_access_token
    from backend.services.archive_service import ArchiveService
    from fastapi.testclient import TestClient
    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError
    assert database.engine.dialect.driver=="pysqlcipher"
    # Reuse the strictly synthetic retention probe's committed rows.
    with database.SessionLocal() as db:
        owner=db.query(models.User).filter_by(email="ci-retain-owner@example.com").one()
        other=db.query(models.User).filter_by(email="ci-retain-other@example.com").one()
        patient=db.query(models.Patient).one()
        acte=db.query(models.Acte).one()
        doc=db.query(models.DocumentArchive).one()
        payment=db.query(models.Payment).one()
        assert patient.nom=="CI-SYNTHETIC"
        media=lab/"synthetic.txt"; media.write_bytes(b"CI synthetic")
        def plan(status, link_payment=False):
            p=models.InstallmentPlan(patient_id=patient.id,title="CI plan",total_amount=100)
            db.add(p); db.flush()
            n=models.Installment(plan_id=p.id,label="CI",amount=100,due_date=datetime(2027,1,1),status=status)
            db.add(n); db.flush()
            if link_payment: db.add(models.Payment(patient_id=patient.id,installment_id=n.id,amount=20))
            return p.id,n.id
        unpaid=plan("EN_ATTENTE")
        paid=plan("PAYE")
        partial=plan("PARTIEL",True)
        inconsistent=plan("EN_ATTENTE",True)
        legacy=models.DocumentArchive(patient_id=patient.id,uploaded_by_id=owner.id,document_type=models.DocumentType.AUTRE,
            filename="legacy.txt",original_filename="legacy.txt",document_group_id="ci-legacy",
            file_hash="b"*64,file_size=1,file_path=str(lab/"legacy.txt"))
        (lab/"legacy.txt").write_bytes(b"x")
        db.add(legacy); db.flush()
        db.add(models.Payment(patient_id=patient.id,amount=10,notes=f"Lien Doc ID: {legacy.id}"))
        db.commit()
        pid,aid,did,payid,legacyid=patient.id,acte.id,doc.id,payment.id,legacy.id
        tokens=[create_access_token(data={"sub":x.email}) for x in (owner,other)]
    def denied(sql,ident):
        try:
            with database.engine.begin() as c: c.execute(text(sql),{"id":ident})
        except IntegrityError as e:
            assert "FOREIGN KEY constraint failed" in str(e.orig)
        else: raise AssertionError("Referenced deletion accepted")
    denied("DELETE FROM document_archives WHERE id=:id",did)
    denied("DELETE FROM installment_plans WHERE id=:id",partial[0])
    print("F04_DIRECT_REFERENCED_DELETION_DENIED_PASS count=2")
    with TestClient(app) as client:
        def req(method,url,code,who=0):
            client.cookies.clear()
            r=client.request(method,url,headers={"Authorization":"Bearer "+tokens[who]})
            assert r.status_code==code,(method,url,r.status_code,code)
            return r
        for p in (paid,partial,inconsistent):
            req("DELETE",f"/api/installments/plan/{p[0]}",409)
        req("DELETE",f"/api/installments/plan/{unpaid[0]}",403,1)
        req("DELETE",f"/api/installments/plan/{unpaid[0]}",204)
        req("DELETE",f"/api/documents/{did}?confirm=true",409)
        req("DELETE",f"/api/documents/{legacyid}?confirm=true",409)
        req("POST",f"/api/documents/{did}/trash",200)
        with database.SessionLocal() as db:
            assert db.get(models.DocumentArchive,did).status==models.DocumentStatus.SUPPRIME
            assert db.get(models.Acte,aid).deleted_at is not None
            assert db.get(models.Payment,payid).acte_id==aid
        req("POST",f"/api/documents/{did}/restore",200)
        with database.SessionLocal() as db:
            assert db.get(models.DocumentArchive,did).status==models.DocumentStatus.ACTIF
            assert db.get(models.Acte,aid).deleted_at is None
        req("DELETE",f"/api/patients/{pid}",403,1)
        req("DELETE",f"/api/patients/{pid}",204)
        req("DELETE",f"/api/patients/{pid}",404)
    database.engine.dispose()
    with database.SessionLocal() as db:
        assert db.get(models.Patient,pid).deleted_at is not None
        assert db.query(models.DossierClinique).filter_by(patient_id=pid).count()==1
        assert db.get(models.Acte,aid).document_archive_id==did
        assert db.get(models.Payment,payid).acte_id==aid
        assert db.get(models.DocumentArchive,did) and media.read_bytes()==b"CI synthetic"
        assert db.get(models.DocumentArchive,legacyid) and (lab/"legacy.txt").read_bytes()==b"x"
        assert db.get(models.InstallmentPlan,unpaid[0]) is None and db.get(models.Installment,unpaid[1]) is None
        for p in (paid,partial,inconsistent):
            assert db.get(models.InstallmentPlan,p[0]) and db.get(models.Installment,p[1])
        for p in (partial,inconsistent):
            assert db.query(models.Payment).filter_by(installment_id=p[1]).count()==1
        assert not db.execute(text("PRAGMA foreign_key_check")).fetchall()
    print("F04_INSTALLMENT_PAYMENT_RETENTION_PASS")
    print("F04_DOCUMENT_TRASH_RESTORE_AND_REFERENCED_DELETE_DENIED_PASS")
    print("F04_PATIENT_ARCHIVE_TENANT_AND_REFERENCE_RETENTION_PASS")
    print("F04_REAL_BUSINESS_CASCADES_PASS")


if __name__=="__main__":
    main()
