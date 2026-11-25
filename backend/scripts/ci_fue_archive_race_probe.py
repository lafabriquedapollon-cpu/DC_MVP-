"""Synthetic FUE: overlap actual approve and archive API requests on SQLCipher."""
import os
from pathlib import Path
from threading import Event
from concurrent.futures import ThreadPoolExecutor
from sqlalchemy import event, text
from sqlalchemy.orm import Session
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
    from fastapi.testclient import TestClient
    assert database.engine.dialect.driver=="pysqlcipher"
    with database.SessionLocal() as db:
        owner=db.query(models.User).filter_by(email="ci-retain-owner@example.com").one()
        member=models.User(email="ci-fue-race@example.com",hashed_password=owner.hashed_password,
            role=models.UserRole.DENTISTE,is_active=False,is_licensed=True,employer_id=owner.id,
            subscription_plan="ELITE",approval_status="pending")
        db.add(member); db.commit()
        mid=member.id
        owner_token=create_access_token(data={"sub":owner.email})
        member_token=create_access_token(data={"sub":member.email})
    url=f"/api/team/{mid}"
    owner_headers={"Authorization":"Bearer "+owner_token}
    member_headers={"Authorization":"Bearer "+member_token}
    entered=Event(); release=Event()
    def pause_approval(state):
        if state.is_update and state.execution_options.get("dc_team_mutation") == "approve":
            entered.set()
            if not release.wait(timeout=20):
                raise RuntimeError("FUE_APPROVAL_BARRIER_TIMEOUT")
    with TestClient(app) as client:
        before=client.get("/api/auth/me",headers=member_headers)
        assert before.status_code==401,before.status_code
        print("FUE_ARCHIVE_RACE_BEFORE_PENDING_DENIED_PASS")
        event.listen(Session,"do_orm_execute",pause_approval)
        try:
            def approve():
                with TestClient(app,raise_server_exceptions=False) as approval_client:
                    return approval_client.post(url+"/approve",headers=owner_headers).status_code
            with ThreadPoolExecutor(max_workers=1) as pool:
                future=pool.submit(approve)
                try:
                    assert entered.wait(timeout=20),"approval did not reach SQL write barrier"
                    archived=client.delete(url,headers=owner_headers)
                    assert archived.status_code==204,archived.status_code
                    print("FUE_ARCHIVE_RACE_ACTION_ARCHIVED_PASS")
                finally:
                    release.set()
                approval_status=future.result(timeout=30)
        finally:
            event.remove(Session,"do_orm_execute",pause_approval)
        client.cookies.clear()
        access=client.get("/api/auth/me",headers=member_headers)
        with database.SessionLocal() as db:
            row=db.get(models.User,mid)
            assert row is not None and row.is_archived
            print(f"FUE_ARCHIVE_RACE_AFTER approval_http={approval_status} member_http={access.status_code} archived={row.is_archived} active={row.is_active} approval={row.approval_status}")
            assert not db.execute(text("PRAGMA foreign_key_check")).fetchall()
            assert approval_status==409 and not row.is_active and row.approval_status=="rejected" and access.status_code==401, "FUE_ARCHIVE_RACE_REACTIVATION_DETECTED"
    print("FUE_ARCHIVE_RACE_PASS")
    # Independent second counter-test: an already-archived principal with
    # inconsistent active/approved legacy flags must still be denied.
    with database.SessionLocal() as db:
        row=db.get(models.User,mid)
        row.is_active=True; row.approval_status="approved"
        db.commit()
    with TestClient(app) as client:
        assert client.get("/api/auth/me",headers=member_headers).status_code==401
    with database.SessionLocal() as db:
        row=db.get(models.User,mid)
        row.is_active=False; row.approval_status="rejected"
        db.commit()
    print("FUE_ARCHIVED_INCONSISTENT_ACCESS_DENIED_PASS")

if __name__=="__main__":
    main()
