"""Synthetic FUE: archive invariant across paired mobile tokens, quota and concurrent edits."""
import os
from pathlib import Path
from threading import Event
from concurrent.futures import ThreadPoolExecutor
from sqlalchemy import event, text
from sqlalchemy.orm import Session
from jose import jwt
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
    from backend.routers import mobile
    from backend.security import create_access_token, SECRET_KEY, ALGORITHM
    from fastapi.testclient import TestClient
    assert database.engine.dialect.driver=="pysqlcipher"
    with database.SessionLocal() as db:
        owner=db.query(models.User).filter_by(email="ci-retain-owner@example.com").one()
        oid=owner.id
        owner_headers={"Authorization":"Bearer "+create_access_token(data={"sub":owner.email})}
        def new_member(name):
            u=models.User(email=f"ci-fue-{name}@example.com",hashed_password=owner.hashed_password,
                role=models.UserRole.DENTISTE,is_active=True,is_licensed=True,employer_id=oid,
                subscription_plan="ELITE",approval_status="approved",permissions={"agenda":True,"patients":True})
            db.add(u); db.flush(); return u.id
        mid=new_member("mobile")
        putid=new_member("put")
        rejectid=new_member("reject")
        device="00000000-0000-4000-8000-000000000123"
        access=mobile._create_mobile_jwt(mid,"DENTISTE",oid,device)
        refresh=mobile._create_mobile_refresh_jwt(mid,"DENTISTE",oid,device)
        db.add(models.MobilePairedDevice(device_id=device,user_id=mid,employer_id=oid,
            client_public_key_hex="04"+"00"*64,refresh_jti=jwt.decode(refresh,SECRET_KEY,algorithms=[ALGORITHM])["jti"]))
        db.commit()
    def owner_request(client,method,path,expected,**kwargs):
        client.cookies.clear()
        r=client.request(method,path,headers=owner_headers,**kwargs)
        assert r.status_code==expected,(method,path,r.status_code,expected)
        return r
    with TestClient(app) as client:
        def mobile_request(method,path,expected,token=None,**kwargs):
            client.cookies.clear()
            r=client.request(method,path,headers={"Authorization":"Bearer "+token} if token else {},**kwargs)
            assert r.status_code==expected,(method,path,r.status_code,expected)
            return r
        # Before: real paired identity and rotation succeed.
        mobile_request("GET","/api/mobile/passkey/status",200,access)
        rotated=mobile_request("POST","/api/mobile/refresh-token",200,json={"refresh_token":refresh}).json()
        access,refresh=rotated["access_token"],rotated["refresh_token"]
        quota=owner_request(client,"GET","/api/team/quota",200).json()["dentistes_used"]
        targets=owner_request(client,"GET","/api/mobile/bridge-options",200).json()["targets"]
        assert mid in [x["id"] for x in targets]
        owner_request(client,"DELETE",f"/api/team/{mid}",204)
        # Force contradictory historical flags; archive remains authoritative.
        with database.SessionLocal() as db:
            u=db.get(models.User,mid); u.is_active=True; u.approval_status="approved"; db.commit()
        mobile_request("GET","/api/mobile/passkey/status",401,access)
        mobile_request("POST","/api/mobile/refresh-token",401,json={"refresh_token":refresh})
        targets=owner_request(client,"GET","/api/mobile/bridge-options",200).json()["targets"]
        assert mid not in [x["id"] for x in targets]
        owner_request(client,"POST","/api/mobile/bridge-pairing",403,json={"target_user_id":mid,"destination":"agenda"})
        assert owner_request(client,"GET","/api/team/quota",200).json()["dentistes_used"]==quota-1
        with database.SessionLocal() as db:
            d=db.get(models.MobilePairedDevice,device)
            assert d.refresh_jti==jwt.decode(refresh,SECRET_KEY,algorithms=[ALGORITHM])["jti"]
            u=db.get(models.User,mid); u.is_active=False; u.approval_status="rejected"; db.commit()
        print("FUE_MOBILE_ARCHIVED_ACCESS_REFRESH_BRIDGE_QUOTA_PASS")
        for action,ident,method,suffix,kwargs in (
            ("update",putid,"PUT","",{"json":{"nom_complet":"stale update"}}),
            ("reject",rejectid,"POST","/reject",{}),
        ):
            entered=Event(); release=Event()
            def pause(state):
                if state.is_update and state.execution_options.get("dc_team_mutation")==action:
                    entered.set()
                    if not release.wait(timeout=20): raise RuntimeError("FUE_WRITE_BARRIER_TIMEOUT")
            event.listen(Session,"do_orm_execute",pause)
            try:
                def mutate():
                    with TestClient(app,raise_server_exceptions=False) as c:
                        return c.request(method,f"/api/team/{ident}"+suffix,headers=owner_headers,**kwargs).status_code
                with ThreadPoolExecutor(max_workers=1) as pool:
                    future=pool.submit(mutate)
                    try:
                        assert entered.wait(timeout=20),"mutation did not reach SQL barrier"
                        owner_request(client,"DELETE",f"/api/team/{ident}",204)
                    finally:
                        release.set()
                    assert future.result(timeout=30)==409
            finally:
                event.remove(Session,"do_orm_execute",pause)
            with database.SessionLocal() as db:
                u=db.get(models.User,ident)
                assert u.is_archived and not u.is_active and u.approval_status=="rejected"
                assert u.nom_complet!="stale update"
            print(f"FUE_ARCHIVE_{action.upper()}_RACE_PASS")
    database.engine.dispose()
    with database.SessionLocal() as db:
        for ident in (mid,putid,rejectid):
            u=db.get(models.User,ident)
            assert u.is_archived and not u.is_active and u.approval_status=="rejected"
        assert not db.execute(text("PRAGMA foreign_key_check")).fetchall()
    print("FUE_ARCHIVE_MOBILE_AND_MUTATIONS_PASS")

if __name__=="__main__":
    main()
