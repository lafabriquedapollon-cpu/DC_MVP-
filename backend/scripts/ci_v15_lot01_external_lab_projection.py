"""Real SQLCipher candidate binding and minimized LabJob projection; synthetic only."""
import os,json,secrets
from pathlib import Path
from datetime import timedelta
from sqlalchemy import insert,update,select
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from backend.config import settings
from backend.core.runtime_safety import REHEARSAL_MIGRATION_ONLY,assert_runtime_startup_allowed
from backend import database,models
from backend.services.pocket_external_store_candidate import metadata,principals as p,assignments as a,sessions as s,digest_token
from backend.services.pocket_external_device_candidate import devices as d,challenges as c,stage_challenge,message,now_utc
from backend.services.pocket_external_lab_projection_candidate import lab_bindings as b,stage_lab_projection,ProjectionRefused
lab=Path(os.environ["DC_LAB_ROOT"]).resolve(strict=True)
dbpath=lab/"fresh-rehearsal.db"
assert os.environ.get("GITHUB_ACTIONS")=="true" and settings.ENVIRONMENT=="e2e_install_rehearsal"
assert lab.parent==Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
assert settings.DATABASE_URL==f"sqlite:///{dbpath}" and dbpath.is_file() and not dbpath.is_symlink()
assert assert_runtime_startup_allowed(settings)==REHEARSAL_MIGRATION_ONLY
assert database.engine.dialect.driver=="pysqlcipher"
rows=[];now=now_utc();key=Ed25519PrivateKey.generate();raw=secrets.token_hex(32);digest=digest_token(raw)
def check(label,value):
    row={"label":label,"pass":bool(value)};rows.append(row);print(json.dumps(row),flush=True);assert row["pass"],label
def issue(cabinet,order):
    with database.SessionLocal() as db:
        with db.begin(): return stage_challenge(db,raw_token=raw,device_id="lab-device",action="assigned-order.read",cabinet_id=cabinet,resource_id=order)
def read(cabinet,order,nonce,signer=key):
    sig=signer.sign(message(session_digest=digest,device_id="lab-device",action="assigned-order.read",cabinet_id=cabinet,resource_id=order,nonce=nonce)).hex()
    try:
        with database.SessionLocal() as db:
            with db.begin():
                return stage_lab_projection(db,raw_token=raw,device_id="lab-device",cabinet_id=cabinet,resource_id=order,nonce=nonce,signature_hex=sig)
    except ProjectionRefused:
        return None
try:
    metadata.create_all(database.engine)
    with database.SessionLocal() as db:
        with db.begin():
            owners=db.query(models.User).filter(models.User.employer_id.is_(None)).order_by(models.User.id).limit(2).all()
            assert len(owners)==2
            ca,cb=[x.id for x in owners]
            def make_order(cabinet,tag,other_lab=None):
                patient=models.Patient(nom="SYNTH_PRIVATE_"+tag,prenom="SYNTH",date_naissance=now,sexe="M",employer_id=cabinet)
                db.add(patient);db.flush()
                act=models.Acte(patient_id=patient.id,praticien_id=cabinet,type_acte=models.ActeType.PROTHESE,libelle="SYNTH_PRIVATE_ACT",montant=999)
                db.add(act);db.flush()
                lab=models.Lab(employer_id=cabinet,name="SYNTH_LAB_"+tag);db.add(lab);db.flush()
                job=models.LabJob(patient_id=patient.id,act_id=act.id,lab_id=lab.id if other_lab is None else other_lab,material="SYNTH_PRIVATE_MATERIAL",type="SYNTH_PRIVATE_TYPE",notes="SYNTH_PRIVATE_NOTE",deadline=now+timedelta(days=1),status=models.LabJobStatus.SENT)
                db.add(job);db.flush();return lab.id,job.id
            la,ja=make_order(ca,"A");la2,ja2=make_order(ca,"A2");lb,jb=make_order(cb,"B")
            db.execute(insert(p).values(id="lab-principal",kind="laboratory",organization_id="lab-org"))
            db.execute(insert(a),[dict(principal_id="lab-principal",cabinet_id=cab,resource_id=order) for cab,order in [(ca,ja),(ca,ja2),(cb,jb)]])
            db.execute(insert(s).values(token_digest=digest,principal_id="lab-principal",device_id="lab-device",issued_at=now,expires_at=now+timedelta(minutes=10)))
            db.execute(insert(d).values(id="lab-device",principal_id="lab-principal",public_key_hex=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()))
            db.execute(insert(b).values(organization_id="lab-org",cabinet_id=ca,lab_id=la))
    n=issue(ca,ja);check("assigned real order challenge",bool(n))
    check("stolen token without key refused",read(ca,ja,n,Ed25519PrivateKey.generate()) is None)
    value=read(ca,ja,n);check("minimal exact real LabJob projection",value=={"order_id":ja,"status":"SENT","deadline":(now+timedelta(days=1)).isoformat()})
    check("no patient identifiers or free text",set(value)=={"order_id","status","deadline"} and "SYNTH_PRIVATE" not in json.dumps(value))
    check("proof replay refused",read(ca,ja,n) is None)
    n=issue(ca,ja2);check("assigned but different laboratory denied",bool(n) and read(ca,ja2,n) is None)
    n=issue(cb,jb);check("assigned but unbound cabinet denied",bool(n) and read(cb,jb,n) is None)
    n=issue(ca,ja)
    with database.SessionLocal() as db:
        with db.begin(): db.get(models.LabJob,ja).lab_id=la2
    check("live order reassignment denies prior proof",read(ca,ja,n) is None)
    with database.SessionLocal() as db:
        with db.begin(): db.get(models.LabJob,ja).lab_id=la
    n=issue(ca,ja)
    with database.engine.begin() as conn: conn.execute(update(b).where(b.c.lab_id==la).values(revoked_at=now))
    check("binding revoked after issue denies",read(ca,ja,n) is None)
    with database.engine.begin() as conn:
        used=conn.execute(select(c.c.used_at).where(c.c.nonce==n)).scalar_one()
        check("denied projection rolls back proof consumption",used is None)
        conn.execute(update(b).where(b.c.lab_id==la).values(revoked_at=None))
    n=issue(ca,ja)
    with database.engine.begin() as conn: conn.execute(update(a).where(a.c.resource_id==ja).values(revoked_at=now))
    check("assignment revocation independently denies",read(ca,ja,n) is None)
    with database.engine.begin() as conn:
        conn.execute(update(a).where(a.c.resource_id==ja).values(revoked_at=None))
    n=issue(ca,ja);database.engine.dispose()
    check("new DB connection reads authorized minimal projection",read(ca,ja,n)==value)
finally:
    metadata.drop_all(database.engine);database.engine.dispose()
    Path(os.environ["DC_EVIDENCE"],"external-lab-projection.json").write_text(json.dumps(rows,indent=2))
assert len(rows)==12
