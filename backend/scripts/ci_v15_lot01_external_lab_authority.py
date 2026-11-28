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
from backend.services.pocket_external_lab_authority_candidate import stage_grant,stage_revoke,AuthorityRefused
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
            owners=db.query(models.User).filter(models.User.employer_id.is_(None),models.User.is_active.is_(True),models.User.role.in_([models.UserRole.ADMIN,models.UserRole.DENTISTE])).order_by(models.User.id).limit(2).all()
            assert len(owners)==2
            ca,cb=[x.id for x in owners]
            staff=db.query(models.User).filter(models.User.employer_id.is_not(None)).first()
            assert staff is not None
            staff_id=staff.id
            from backend.security import verify_password
            password=os.environ["DC_SYNTH_PASSWORD"]
            assert verify_password(password,owners[0].hashed_password)
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
            db.execute(insert(p).values(id="tech-principal",kind="technical",organization_id="lab-org"))
            db.execute(insert(p).values(id="revoked-principal",kind="laboratory",organization_id="lab-org",revoked_at=now))
            db.execute(insert(s).values(token_digest=digest,principal_id="lab-principal",device_id="lab-device",issued_at=now,expires_at=now+timedelta(minutes=10)))
            db.execute(insert(d).values(id="lab-device",principal_id="lab-principal",public_key_hex=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()))
            db.execute(insert(b).values(organization_id="lab-org",cabinet_id=ca,lab_id=la))
    def change(fn=stage_grant,**over):
        args=dict(actor_id=ca,cabinet_id=ca,principal_id="lab-principal",order_id=ja,password=password,confirm=True)
        try:
            with database.SessionLocal() as db:
                with db.begin(): fn(db,**{**args,**over})
            return True
        except AuthorityRefused:return False
    check("no assignment by default",issue(ca,ja) is None)
    check("staff cannot grant",not change(actor_id=staff_id))
    check("different owner cannot grant",not change(actor_id=cb))
    check("wrong password denied",not change(password="synthetic-wrong"))
    check("false confirmation denied",not change(confirm=False))
    check("technical principal denied",not change(principal_id="tech-principal"))
    check("revoked principal denied",not change(principal_id="revoked-principal"))
    check("unknown principal denied",not change(principal_id="missing"))
    check("wrong laboratory denied",not change(order_id=ja2))
    check("cross-cabinet order denied",not change(order_id=jb))
    check("owner explicit grant accepted",change())
    check("duplicate grant denied",not change())
    n=issue(ca,ja);check("new grant permits signed minimal read",bool(n) and read(ca,ja,n)=={"order_id":ja,"status":"SENT","deadline":(now+timedelta(days=1)).isoformat()})
    n=issue(ca,ja)
    check("different owner cannot revoke",not change(stage_revoke,actor_id=cb))
    check("owner explicitly revokes",change(stage_revoke))
    check("existing challenge denied after revoke",read(ca,ja,n) is None)
    check("new challenge denied after revoke",issue(ca,ja) is None)
    check("duplicate revocation denied",not change(stage_revoke))
    check("implicit regrant denied",not change())
    database.engine.dispose()
    with database.SessionLocal() as db:
        check("grant audit persisted exactly once",db.query(models.AuditLog).filter_by(action="EXTERNAL_LAB_ASSIGNMENT_GRANTED",resource_id=str(ja),user_id=ca,employer_id=ca,severity="CRITICAL").count()==1)
        check("revoke audit persisted exactly once",db.query(models.AuditLog).filter_by(action="EXTERNAL_LAB_ASSIGNMENT_REVOKED",resource_id=str(ja),user_id=ca,employer_id=ca,severity="CRITICAL").count()==1)
        check("revocation persists",db.execute(select(a.c.revoked_at).where(a.c.resource_id==ja)).scalar_one() is not None)
finally:
    metadata.drop_all(database.engine);database.engine.dispose()
    Path(os.environ["DC_EVIDENCE"],"external-lab-authority.json").write_text(json.dumps(rows,indent=2))
assert len(rows)==22
