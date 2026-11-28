"""SQLCipher persistence LAB; never creates these tables in a real application DB."""
import os,json,secrets
from datetime import datetime,timedelta,timezone
from pathlib import Path
from sqlalchemy import insert,update,select
from backend.config import settings
from backend.core.runtime_safety import REHEARSAL_MIGRATION_ONLY,assert_runtime_startup_allowed
from backend import database
from backend.services.pocket_external_store_candidate import metadata,principals as p,assignments as a,sessions as s,digest_token,permits_read
lab=Path(os.environ["DC_LAB_ROOT"]).resolve(strict=True)
dbpath=lab/"fresh-rehearsal.db"
assert os.environ.get("GITHUB_ACTIONS")=="true"
assert settings.ENVIRONMENT=="e2e_install_rehearsal"
assert lab.parent==Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
assert settings.DATABASE_URL==f"sqlite:///{dbpath}" and dbpath.is_file() and not dbpath.is_symlink()
assert assert_runtime_startup_allowed(settings)==REHEARSAL_MIGRATION_ONLY
assert database.engine.dialect.driver=="pysqlcipher"
rows=[]
now=datetime.now(timezone.utc).replace(tzinfo=None)
raw_lab,raw_tech,raw_expired,raw_long=[secrets.token_hex(32) for _ in range(4)]
def check(label,fn):
    passed=bool(fn())
    row={"label":label,"pass":passed};rows.append(row);print(json.dumps(row),flush=True)
    assert passed,label
def permitted(raw=raw_lab,device="device-lab",action="assigned-order.read",cabinet=1,resource=10):
    with database.SessionLocal() as db:
        return permits_read(db,raw_token=raw,device_id=device,action=action,cabinet_id=cabinet,resource_id=resource)
try:
    metadata.create_all(database.engine)
    with database.engine.begin() as c:
        c.execute(insert(p),[dict(id="lab-a",kind="laboratory",organization_id="org-lab"),dict(id="tech-a",kind="technical",organization_id="org-tech")])
        c.execute(insert(a),[dict(principal_id="lab-a",cabinet_id=1,resource_id=10),dict(principal_id="tech-a",cabinet_id=1,resource_id=20)])
        c.execute(insert(s),[
            dict(token_digest=digest_token(raw_lab),principal_id="lab-a",device_id="device-lab",issued_at=now,expires_at=now+timedelta(minutes=5)),
            dict(token_digest=digest_token(raw_tech),principal_id="tech-a",device_id="device-tech",issued_at=now,expires_at=now+timedelta(minutes=5)),
            dict(token_digest=digest_token(raw_expired),principal_id="lab-a",device_id="device-lab",issued_at=now-timedelta(minutes=10),expires_at=now-timedelta(minutes=1)),
            dict(token_digest=digest_token(raw_long),principal_id="lab-a",device_id="device-lab",issued_at=now,expires_at=now+timedelta(days=1))])
    check("lab exact order",lambda:permitted())
    check("tech exact diagnostic",lambda:permitted(raw_tech,"device-tech","diagnostic.read",1,20))
    check("lab wrong cabinet",lambda:not permitted(cabinet=2))
    check("lab wrong resource",lambda:not permitted(resource=11))
    check("wrong device scope",lambda:not permitted(device="other"))
    check("unknown session",lambda:not permitted(raw=secrets.token_hex(32)))
    check("staff JWT syntax not accepted",lambda:not permitted(raw="eyJ.invalid.token"))
    check("expired session",lambda:not permitted(raw=raw_expired))
    check("overlong session",lambda:not permitted(raw=raw_long))
    check("lab cannot read clinical records",lambda:not permitted(action="cabinet.clinical.read"))
    check("lab cannot mutate order",lambda:not permitted(action="assigned-order.write"))
    check("tech cannot access lab",lambda:not permitted(raw_tech,"device-tech","assigned-order.read",1,20))
    check("tech cannot access patient data",lambda:not permitted(raw_tech,"device-tech","cabinet.patients.read",1,20))
    with database.engine.connect() as c:
        check("only digests stored",lambda:all(v not in (raw_lab,raw_tech,raw_expired,raw_long) for v in c.execute(select(s.c.token_digest)).scalars()))
    database.engine.dispose()
    check("new DB connection retains assignment",lambda:permitted())
    with database.engine.begin() as c:
        c.execute(update(a).where(a.c.principal_id=="lab-a").values(revoked_at=now))
    check("assignment revocation immediate",lambda:not permitted())
    check("other principal unaffected",lambda:permitted(raw_tech,"device-tech","diagnostic.read",1,20))
    with database.engine.begin() as c:
        c.execute(update(s).where(s.c.token_digest==digest_token(raw_tech)).values(revoked_at=now))
    database.engine.dispose()
    check("session revocation survives reconnection",lambda:not permitted(raw_tech,"device-tech","diagnostic.read",1,20))
    with database.engine.begin() as c:
        c.execute(update(a).where(a.c.principal_id=="lab-a").values(revoked_at=None))
        c.execute(update(p).where(p.c.id=="lab-a").values(revoked_at=now))
    check("principal revocation overrides active assignment",lambda:not permitted())
finally:
    metadata.drop_all(database.engine)
    database.engine.dispose()
    Path(os.environ["DC_EVIDENCE"],"external-store.json").write_text(json.dumps(rows,indent=2))
assert len(rows)==19
