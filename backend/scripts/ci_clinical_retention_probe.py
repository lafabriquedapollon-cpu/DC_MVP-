"""CI-only real API clinical-retention probe on a fresh encrypted synthetic LAB."""
import os
from pathlib import Path
from datetime import datetime


def main():
    from backend.config import settings
    from backend.core.runtime_safety import REHEARSAL_MIGRATION_ONLY, assert_runtime_startup_allowed
    lab = Path(os.environ["DC_LAB_ROOT"]).resolve(strict=True)
    path = lab / "fresh-rehearsal.db"
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert settings.ENVIRONMENT == "e2e_install_rehearsal"
    assert lab.parent == Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    assert settings.DATABASE_URL == f"sqlite:///{path}" and path.is_file() and not path.is_symlink()
    assert assert_runtime_startup_allowed(settings) == REHEARSAL_MIGRATION_ONLY
    from backend.main import app
    from backend import database, models
    from backend.security import create_access_token, create_refresh_token
    from fastapi.testclient import TestClient
    from sqlalchemy import text, select, func
    from sqlalchemy.exc import IntegrityError
    assert database.engine.dialect.driver == "pysqlcipher"
    with database.SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(models.User)) == 0
        assert db.scalar(select(func.count()).select_from(models.Patient)) == 0
        pw = database.pwd_context.hash("CI-synthetic-retention-credential")
        def user(email, employer=None):
            return models.User(email=email, hashed_password=pw, role=models.UserRole.DENTISTE,
                               is_active=True, is_licensed=True, employer_id=employer,
                               subscription_plan="ELITE", approval_status="approved")
        owner=user("ci-retain-owner@example.com"); other=user("ci-retain-other@example.com")
        db.add_all([owner,other]); db.flush()
        member=user("ci-retain-member@example.com", owner.id)
        db.add(member); db.flush()
        p=models.Patient(nom="CI-SYNTHETIC",prenom="Retention",date_naissance=datetime(2000,1,1),sexe="M",employer_id=owner.id)
        db.add(p); db.flush()
        dossier=models.DossierClinique(patient_id=p.id)
        acte=models.Acte(patient_id=p.id,praticien_id=member.id,type_acte=models.ActeType.SOIN,libelle="CI",montant=100)
        db.add_all([dossier,acte]); db.flush()
        payment=models.Payment(patient_id=p.id,acte_id=acte.id,amount=100)
        db.add(payment); db.commit()
        ids=(owner.id,other.id,member.id,p.id,dossier.id,acte.id,payment.id)
        emails=(owner.email,other.email,member.email)
    owner_id,other_id,member_id,pid,did,aid,payid=ids
    with database.engine.connect() as c:
        assert c.execute(text("PRAGMA foreign_keys")).scalar()==1
        fk=[r for r in c.execute(text("PRAGMA foreign_key_list(actes)")) if r[3]=="praticien_id"]
        assert len(fk)==1 and fk[0][6].upper()=="RESTRICT"
    try:
        with database.engine.begin() as c:
            c.execute(text("DELETE FROM users WHERE id=:id"),{"id":member_id})
    except IntegrityError as exc:
        assert "FOREIGN KEY constraint failed" in str(exc.orig)
    else:
        raise AssertionError("Clinical practitioner SQL delete accepted")
    print("CLINICAL_DIRECT_DELETE_RESTRICT_PASS")
    with database.SessionLocal() as db:
        doc=models.DocumentArchive(patient_id=pid,uploaded_by_id=member_id,document_type=models.DocumentType.AUTRE,
            filename="synthetic.txt",original_filename="synthetic.txt",document_group_id="ci-retention",
            file_hash="a"*64,file_size=0,file_path=str(lab/"synthetic.txt"))
        db.add(doc); db.flush()
        db.get(models.Acte,aid).document_archive_id=doc.id
        db.commit(); docid=doc.id
    tokens=[create_access_token(data={"sub":email}) for email in emails]
    refresh=create_refresh_token(data={"sub":emails[2]})
    def headers(i): return {"Authorization":"Bearer "+tokens[i]}
    with TestClient(app) as client:
        def request(method,path,who,expected,**kwargs):
            client.cookies.clear()
            r=client.request(method,path,headers=headers(who),**kwargs)
            assert r.status_code==expected, (method,path,r.status_code,expected)
            return r
        request("GET","/api/auth/me",2,200)
        before=request("GET","/api/team/quota",0,200).json()
        url=f"/api/team/{member_id}"
        request("DELETE",url,1,404)
        request("DELETE",url,0,204)
        request("DELETE",url,0,204)
        after=request("GET","/api/team/quota",0,200).json()
        assert before["dentistes_used"]-after["dentistes_used"]==1
        request("GET","/api/auth/me",2,401)
        request("POST","/api/auth/refresh",2,401,json={"refresh_token":refresh})
        request("PUT",url,0,409,json={"is_active":True})
        request("POST",url+"/approve",0,409)
        members=request("GET","/api/team/",0,200).json()
        row=next(x for x in members if x["id"]==member_id)
        assert row["is_archived"] is True and row["is_active"] is False and row["approval_status"]=="rejected"
    database.engine.dispose()
    with database.SessionLocal() as db:
        u=db.get(models.User,member_id); a=db.get(models.Acte,aid); pay=db.get(models.Payment,payid)
        assert u and u.employer_id==owner_id and u.email==emails[2] and u.is_archived and not u.is_active
        assert a and a.praticien_id==member_id and a.patient_id==pid and a.document_archive_id==docid and a.montant==100
        assert pay and pay.acte_id==aid and pay.patient_id==pid and pay.amount==100
        assert db.get(models.Patient,pid).employer_id==owner_id
        assert db.get(models.DossierClinique,did).patient_id==pid
        assert db.get(models.DocumentArchive,docid).uploaded_by_id==member_id
        assert not db.execute(text("PRAGMA foreign_key_check")).fetchall()
    print("CLINICAL_ARCHIVE_ACCESS_QUOTA_TENANT_PASS")
    print("CLINICAL_ACT_PAYMENT_DOCUMENT_DOSSIER_PERSISTENCE_PASS")
    print("CLINICAL_RETENTION_PROBE_PASS")


if __name__=="__main__":
    main()
