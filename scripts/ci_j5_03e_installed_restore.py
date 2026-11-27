"""Installed Windows LAB only. Actual restore service/worker, real SQLCipher,
real FastAPI child PE. Adapter changes only worker launch arguments and failure
timing; public cabinet request_apply and authority admission stay disabled.
"""
import os
import subprocess
import sys
import time
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

def require(ok, marker):
    if not ok: raise RuntimeError(marker)

def exercise_restore(root, db_path):
    from backend import database, models
    from backend.core.media_paths import get_media_root
    from backend.core.schema_runtime import assert_database_at_current_head
    from backend.services.cabinet_bundle import CabinetBundleService
    from backend.services.guided_restore import GuidedRestoreService as Service
    from backend.services.guided_restore_worker import GuidedRestoreWorker as Worker
    from backend.security import token_blacklist
    from sqlalchemy import text
    import urllib.request
    import json
    require(os.name=="nt" and getattr(sys,"frozen",False) and os.getenv("GITHUB_ACTIONS")=="true"
            and os.getenv("DC_RESTORE_LAB")=="true" and os.getenv("DC_INSTALLER_REHEARSAL")=="true"
            and os.getenv("ENVIRONMENT")=="e2e_install_rehearsal","J5_03E_ISOLATION_REQUIRED")
    scenario=os.environ["DC_RESTORE_SCENARIO"]
    require(scenario in {"success","rollback"} and not Service.runtime_apply_supported(),"J5_03E_REAL_APPLY_MUST_BE_DENIED")
    media=get_media_root()
    require(media==root/"rehearsal-media" and Path(database.engine.url.database)==db_path,"J5_03E_TARGET_MISMATCH")
    # Reuse the disabled synthetic owner from actual installed init.
    now=datetime.now(timezone.utc).replace(tzinfo=None)
    with database.engine.begin() as c:
        users=models.User.__table__
        c.execute(users.update().where(users.c.id==1).values(is_licensed=True,license_expires_at=now+timedelta(days=90)))
        c.execute(models.CabinetConfig.__table__.insert().values(owner_id=1,clinic_id="synthetic-j5-restore",nom_cabinet="AFTER"))
        c.execute(models.ZKAPairingToken.__table__.insert().values(token="synthetic-j5-pair",employer_id=1,user_id=1,public_id="synthetic-j5",master_key="SYNTHETIC_NOT_SECRET",expires_at=now+timedelta(minutes=30)))
        c.execute(models.MobilePairedDevice.__table__.insert().values(device_id="synthetic-j5-device",user_id=1,employer_id=1,client_public_key_hex="ab"*65,refresh_jti="synthetic-j5-refresh"))
    database.engine.dispose()
    marker=media/"uploads"/"restore-proof.bin"
    marker.write_bytes(b"SYNTHETIC_AFTER")
    phrase=secrets.token_hex(32)
    package=root/"synthetic.dcbundle"
    CabinetBundleService.create_bundle(package,phrase)
    with database.engine.begin() as c:
        c.execute(models.CabinetConfig.__table__.update().where(models.CabinetConfig.__table__.c.owner_id==1).values(nom_cabinet="BEFORE"))
    database.engine.dispose()
    marker.write_bytes(b"SYNTHETIC_BEFORE")
    vault=root/"license_vault.bin";vault.write_bytes(b"INERT_BEFORE_VAULT")
    converted=root/"restore.zip"
    CabinetBundleService.to_local_guided_restore_archive(package,phrase,converted)
    pre=Service.preflight_file(converted,original_name="synthetic.zip",owner_employer_id=1)
    require(pre["compatible"] and pre["status"]=="preflight_ready" and pre["restore_media"],"J5_03E_PREFLIGHT_FAILED")
    rid=pre["restore_id"]
    try: Service.prepare(rid,owner_employer_id=2)
    except PermissionError: pass
    else: raise RuntimeError("J5_03E_WRONG_OWNER_ACCEPTED")
    require(Service.prepare(rid,owner_employer_id=1)["status"]=="prepared","J5_03E_PREPARE_FAILED")
    database.engine.dispose()
    job=Service.get_job(rid)
    require(Path(job["target_db_path"])==db_path and job["active_driver"]=="pysqlcipher","J5_03E_JOB_TARGET_MISMATCH")
    # LAB controller schedules only the already prepared synthetic job. Never
    # monkeypatch runtime_apply_supported or use cabinet environment.
    job["status"]="scheduled";Service._write_job(job)
    children=[]
    logs=[]
    stop=root/"stop-restore-health"
    def launch(stage):
        log=root/("restore-child-"+str(len(children))+".log")
        with log.open("wb") as h:
            proc=subprocess.Popen([sys.executable,stage],executable=sys.executable,cwd=str(root),
                                  stdin=subprocess.DEVNULL,stdout=h,stderr=subprocess.STDOUT)
        children.append(proc);logs.append(log)
        return proc
    # Exercise real PID wait with an actual exited process.
    parent=launch("restore-fail-health")
    require(parent.wait(timeout=60)==0,"J5_03E_PARENT_EXIT_FAILED")
    calls=0
    smoke=Worker._smoke_check
    def launch_adapter(executable):
        nonlocal calls
        require(executable==sys.executable,"J5_03E_WRONG_EXECUTABLE")
        calls+=1
        return launch("restore-fail-health" if scenario=="rollback" and calls==1 else "restore-health")
    def smoke_adapter():
        # Failure case uses a real absent listener, not a mocked success.
        return smoke(timeout=8 if scenario=="rollback" and calls==1 else 60)
    Worker._launch_app=staticmethod(launch_adapter)
    Worker._smoke_check=staticmethod(smoke_adapter)
    try:
        rc=Worker.run(rid,parent.pid,sys.executable)
        final=Service.get_job(rid)
        require((rc,final["status"],final.get("rollback"))==((0,"success","not_needed") if scenario=="success" else (2,"rolled_back","passed")),"J5_03E_WORKER_STATUS_"+str(rc)+"_"+str(final.get("status")))
        require(calls==(1 if scenario=="success" else 2),"J5_03E_LAUNCH_COUNT")
        # Confirm the actual child reaches its existing real HTTP verification
        # and exits gracefully, not merely an unrelated /health responder.
        child=children[-1];log=logs[-1]
        for _ in range(300):
            if b"R02_DESKTOP_LOOPBACK_READY" in log.read_bytes(): break
            require(child.poll() is None,"J5_03E_CHILD_EXITED")
            time.sleep(.1)
        else: raise RuntimeError("J5_03E_CHILD_READY_TIMEOUT")
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open("http://127.0.0.1:8008/health",timeout=5) as response:
            require(json.load(response)=={"status":"ok","db":"ok","instance_id":os.environ["DIGITALCROWN_INSTANCE_ID"]},"J5_03E_HEALTH_IDENTITY")
        stop.touch(exist_ok=False)
        require(child.wait(timeout=30)==0 and b"J5_03E_REAL_RESTART_HEALTH_PASS" in log.read_bytes(),"J5_03E_RESTART_FAILED")
        database.engine.dispose()
        assert_database_at_current_head(database.engine)
        with database.engine.connect() as c:
            require(c.execute(text("PRAGMA integrity_check")).scalar()=="ok" and not c.execute(text("PRAGMA foreign_key_check")).all(),"J5_03E_DB_INTEGRITY")
            expected=scenario=="success"
            require(c.execute(text("SELECT nom_cabinet FROM cabinet_configs WHERE owner_id=1")).scalar()==("AFTER" if expected else "BEFORE"),"J5_03E_DB_ORACLE")
            require(c.execute(text("SELECT is_licensed FROM users WHERE id=1")).scalar()==(0 if expected else 1),"J5_03E_LICENSE_ORACLE")
            require(c.execute(text("SELECT count(*) FROM zka_pairing_tokens WHERE employer_id=1")).scalar()==(0 if expected else 1),"J5_03E_PAIRING_ORACLE")
            require((c.execute(text("SELECT revoked_at FROM mobile_paired_devices WHERE employer_id=1")).scalar() is not None)==expected,"J5_03E_DEVICE_ORACLE")
            require((c.execute(text("SELECT count(*) FROM revoked_tokens WHERE jti LIKE :prefix"),{"prefix":token_blacklist.MOBILE_EPOCH_PREFIX+"1:%"}).scalar()>0)==expected,"J5_03E_CUTOFF_ORACLE")
            require(c.execute(text("SELECT count(*) FROM patients")).scalar()==0,"J5_03E_PATIENTS_NOT_EMPTY")
        require(marker.read_bytes()==(b"SYNTHETIC_AFTER" if expected else b"SYNTHETIC_BEFORE"),"J5_03E_MEDIA_ORACLE")
        require(not vault.exists() if expected else vault.read_bytes()==b"INERT_BEFORE_VAULT","J5_03E_VAULT_ORACLE")
        print("J5_03E_INSTALLED_RESTORE_"+scenario.upper()+"_PASS",flush=True)
    finally:
        database.engine.dispose()
        for p in children:
            if p.poll() is None:
                p.terminate()
                try:p.wait(timeout=10)
                except subprocess.TimeoutExpired:p.kill();p.wait(timeout=10)
