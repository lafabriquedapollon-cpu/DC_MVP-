"""SQLCipher proof-of-possession LAB with real Ed25519 signing and no external routes."""
import os,json,secrets
from datetime import timedelta
from pathlib import Path
from sqlalchemy import insert,update,select
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from backend.config import settings
from backend.core.runtime_safety import REHEARSAL_MIGRATION_ONLY,assert_runtime_startup_allowed
from backend import database
from backend.services.pocket_external_store_candidate import metadata,principals as p,assignments as a,sessions as s,digest_token
from backend.services.pocket_external_device_candidate import devices as d,challenges as c,stage_challenge,stage_signed_read,message,now_utc
lab=Path(os.environ["DC_LAB_ROOT"]).resolve(strict=True)
dbpath=lab/"fresh-rehearsal.db"
assert os.environ.get("GITHUB_ACTIONS")=="true" and settings.ENVIRONMENT=="e2e_install_rehearsal"
assert lab.parent==Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
assert settings.DATABASE_URL==f"sqlite:///{dbpath}" and dbpath.is_file() and not dbpath.is_symlink()
assert assert_runtime_startup_allowed(settings)==REHEARSAL_MIGRATION_ONLY
assert database.engine.dialect.driver=="pysqlcipher"
key,wrong=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
raw=secrets.token_hex(32); digest=digest_token(raw)
now=now_utc(); rows=[]
args=dict(raw_token=raw,device_id="device-lab",action="assigned-order.read",cabinet_id=1,resource_id=10)
def check(label,value):
    passed=bool(value)
    row={"label":label,"pass":passed};rows.append(row);print(json.dumps(row),flush=True)
    assert passed,label
def issue(**over):
    with database.SessionLocal() as db:
        with db.begin(): return stage_challenge(db,**{**args,**over})
def sign(nonce,signer=key,**over):
    fields={k:v for k,v in args.items() if k!="raw_token"}
    return signer.sign(message(session_digest=digest,nonce=nonce,**{**fields,**over})).hex()
def read(nonce,sig,**over):
    with database.SessionLocal() as db:
        with db.begin(): return stage_signed_read(db,**{**args,"nonce":nonce,"signature_hex":sig,**over})
try:
    metadata.create_all(database.engine)
    with database.engine.begin() as conn:
        conn.execute(insert(p).values(id="lab-a",kind="laboratory",organization_id="org-lab"))
        conn.execute(insert(a),[dict(principal_id="lab-a",cabinet_id=1,resource_id=10),dict(principal_id="lab-a",cabinet_id=1,resource_id=11)])
        conn.execute(insert(s).values(token_digest=digest,principal_id="lab-a",device_id="device-lab",issued_at=now,expires_at=now+timedelta(minutes=5)))
        conn.execute(insert(d).values(id="device-lab",principal_id="lab-a",public_key_hex=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()))
    n=issue();check("authorized scoped challenge",bool(n))
    check("unknown token cannot issue",issue(raw_token=secrets.token_hex(32)) is None)
    check("wrong cabinet cannot issue",issue(cabinet_id=2) is None)
    check("clinical read cannot issue",issue(action="cabinet.clinical.read") is None)
    check("stolen token without key denied",not read(n,sign(n,wrong)))
    check("malformed signature denied",not read(n,"bad"))
    check("different assigned resource denied",not read(n,sign(n),resource_id=11))
    check("different resource even with valid signature denied",not read(n,sign(n,resource_id=11),resource_id=11))
    check("different device denied",not read(n,sign(n),device_id="device-other"))
    check("valid signed read accepted",read(n,sign(n)))
    check("replay denied",not read(n,sign(n)))
    n=issue()
    with database.SessionLocal() as db:
        try:
            with db.begin():
                assert stage_signed_read(db,**args,nonce=n,signature_hex=sign(n))
                raise RuntimeError("synthetic rollback")
        except RuntimeError as e:
            assert str(e)=="synthetic rollback"
    check("rollback leaves challenge available",read(n,sign(n)))
    n=issue()
    with database.engine.begin() as conn: conn.execute(update(c).where(c.c.nonce==n).values(expires_at=now-timedelta(seconds=1)))
    check("expired proof denied",not read(n,sign(n)))
    n=issue()
    database.engine.dispose()
    check("new DB connection can verify persisted challenge",read(n,sign(n)))
    n=issue()
    with database.engine.begin() as conn: conn.execute(update(a).where(a.c.resource_id==10).values(revoked_at=now))
    check("assignment revocation after challenge denied",not read(n,sign(n)))
    with database.engine.begin() as conn: conn.execute(update(a).where(a.c.resource_id==10).values(revoked_at=None))
    n=issue()
    with database.engine.begin() as conn: conn.execute(update(d).where(d.c.id=="device-lab").values(revoked_at=now))
    check("device revocation after challenge denied",not read(n,sign(n)))
    check("revoked device cannot issue",issue() is None)
    with database.engine.begin() as conn: conn.execute(update(d).where(d.c.id=="device-lab").values(revoked_at=None))
    n=issue()
    with database.engine.begin() as conn: conn.execute(update(s).where(s.c.token_digest==digest).values(revoked_at=now))
    check("session revocation after challenge denied",not read(n,sign(n)))
finally:
    metadata.drop_all(database.engine);database.engine.dispose()
    Path(os.environ["DC_EVIDENCE"],"external-device.json").write_text(json.dumps(rows,indent=2))
assert len(rows)==18
