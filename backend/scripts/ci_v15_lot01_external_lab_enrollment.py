"""Real SQLCipher candidate enrollment, synthetic CI only."""
import os,json,secrets
from pathlib import Path
from datetime import timedelta
from sqlalchemy import select,update,func,insert
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from backend.config import settings
from backend.core.runtime_safety import REHEARSAL_MIGRATION_ONLY,assert_runtime_startup_allowed
from backend import database,models
from backend.services.pocket_external_store_candidate import metadata,principals,assignments,sessions,digest_token
from backend.services.pocket_external_device_candidate import devices,now_utc,stage_challenge,message
from backend.services.pocket_external_lab_projection_candidate import lab_bindings,stage_lab_projection,ProjectionRefused
from backend.services.pocket_external_lab_authority_candidate import stage_grant
from backend.services.pocket_external_lab_enrollment_candidate import enrollments,stage_prepare,stage_complete,stage_revoke_enrollment,fingerprint,AuthorityRefused
lab=Path(os.environ["DC_LAB_ROOT"]).resolve(strict=True)
dbpath=lab/"fresh-rehearsal.db"
assert os.environ.get("GITHUB_ACTIONS")=="true" and settings.ENVIRONMENT=="e2e_install_rehearsal"
assert lab.parent==Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
assert settings.DATABASE_URL==f"sqlite:///{dbpath}" and dbpath.is_file() and not dbpath.is_symlink()
assert assert_runtime_startup_allowed(settings)==REHEARSAL_MIGRATION_ONLY
assert database.engine.dialect.driver=="pysqlcipher"
rows=[]
def check(label,value):
    row={"label":label,"pass":bool(value)};rows.append(row);print(json.dumps(row),flush=True);assert row["pass"],label
def public(key): return key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
def call(fn,**args):
    try:
        with database.SessionLocal() as db:
            with db.begin(): return True,fn(db,**args)
    except AuthorityRefused: return False,None
def count(table):
    with database.SessionLocal() as db:
        return db.execute(select(func.count()).select_from(table)).scalar_one()
def sign(key,row):return key.sign(row["message"]).hex()
try:
    metadata.create_all(database.engine)
    with database.SessionLocal() as db:
        with db.begin():
            owners=db.query(models.User).filter(models.User.employer_id.is_(None),models.User.is_active.is_(True),models.User.role.in_([models.UserRole.ADMIN,models.UserRole.DENTISTE])).order_by(models.User.id).limit(2).all()
            assert len(owners)==2
            ca,cb=[x.id for x in owners]
            staff=db.query(models.User).filter(models.User.employer_id.is_not(None)).first().id
            def make_lab(owner,tag):
                item=models.Lab(employer_id=owner,name="SYNTH_ENROLL_"+tag);db.add(item);db.flush();return item.id
            la,lb,lc,ld=make_lab(ca,"A"),make_lab(cb,"B"),make_lab(ca,"C"),make_lab(ca,"D")
    key=Ed25519PrivateKey.generate();other=Ed25519PrivateKey.generate()
    password=os.environ["DC_SYNTH_PASSWORD"]
    base=dict(actor_id=ca,cabinet_id=ca,lab_id=la,public_key_hex=public(key),
              verified_fingerprint=fingerprint(public(key)),password=password,confirm=True)
    def prepare(**kw):return call(stage_prepare,**{**base,**kw})
    def complete(row,signer=key,**kw):return call(stage_complete,**{"nonce":row["nonce"],"signature_hex":sign(signer,row),**kw})
    def revoke(**kw):return call(stage_revoke_enrollment,**{**dict(actor_id=ca,cabinet_id=ca,lab_id=la,password=password,confirm=True),**kw})
    check("staff denied",not prepare(actor_id=staff)[0])
    check("foreign owner denied",not prepare(actor_id=cb)[0])
    check("cross cabinet lab denied",not prepare(lab_id=lb)[0])
    check("wrong password denied",not prepare(password="wrong")[0])
    check("confirmation required",not prepare(confirm=False)[0])
    check("key fingerprint mismatch denied",not prepare(verified_fingerprint=fingerprint(public(other)))[0])
    check("malformed public key denied",not prepare(public_key_hex="bad")[0])
    check("no pending or authority on refusals",count(enrollments)==count(principals)==count(lab_bindings)==0)
    ok,row=prepare();check("owner prepares enrollment",ok and row is not None)
    check("pending grants nothing",count(principals)==count(devices)==count(lab_bindings)==count(assignments)==count(sessions)==0)
    check("duplicate lab refused",not prepare()[0])
    check("duplicate key for different lab refused",not prepare(lab_id=lc)[0])
    check("wrong key proof denied",not complete(row,other)[0])
    check("malformed proof denied",not complete(row,signature_hex="bad")[0])
    check("altered nonce denied",not complete(row,nonce="0"*64)[0])
    check("denied proofs create nothing",count(principals)==0)
    with database.SessionLocal() as db:
        tx=db.begin()
        stage_complete(db,nonce=row["nonce"],signature_hex=sign(key,row))
        tx.rollback()
    check("completion rollback leaves no authority",count(principals)==count(devices)==count(lab_bindings)==0)
    check("correct proof completes",complete(row)[0])
    check("replay denied",not complete(row)[0])
    check("exact one principal device binding",count(principals)==count(devices)==count(lab_bindings)==1)
    check("no automatic order grant or session",count(assignments)==count(sessions)==0)
    with database.SessionLocal() as db:
        b=db.execute(select(lab_bindings)).mappings().one()
        d=db.execute(select(devices)).mappings().one()
        p=db.execute(select(principals)).mappings().one()
        check("exact cabinet lab and principal binding",b["cabinet_id"]==ca and b["lab_id"]==la and b["organization_id"]==p["organization_id"] and d["principal_id"]==p["id"]==row["principal_id"])
        check("public key only",d["public_key_hex"]==public(key))
    # Explicit grant and synthetic session only; no production session issuer.
    raw=secrets.token_hex(32); now=now_utc()
    with database.SessionLocal() as db:
        with db.begin():
            patient=models.Patient(nom="SYNTH_ENROLL_PATIENT",prenom="SYNTH",date_naissance=now,sexe="M",employer_id=ca)
            db.add(patient);db.flush()
            act=models.Acte(patient_id=patient.id,praticien_id=ca,type_acte=models.ActeType.PROTHESE,libelle="SYNTH_ACT",montant=999)
            db.add(act);db.flush()
            job=models.LabJob(patient_id=patient.id,act_id=act.id,lab_id=la,material="SYNTH",type="SYNTH",notes="SYNTH_PRIVATE",deadline=now+timedelta(days=1),status=models.LabJobStatus.SENT)
            db.add(job);db.flush();order=job.id
            db.execute(insert(sessions).values(token_digest=digest_token(raw),principal_id=row["principal_id"],device_id=row["device_id"],issued_at=now,expires_at=now+timedelta(minutes=10)))
            stage_grant(db,actor_id=ca,cabinet_id=ca,principal_id=row["principal_id"],order_id=order,password=password,confirm=True)
    def issue():
        with database.SessionLocal() as db:
            with db.begin():
                return stage_challenge(db,raw_token=raw,device_id=row["device_id"],action="assigned-order.read",cabinet_id=ca,resource_id=order)
    def read(nonce):
        sig=key.sign(message(session_digest=digest_token(raw),device_id=row["device_id"],action="assigned-order.read",cabinet_id=ca,resource_id=order,nonce=nonce)).hex()
        try:
            with database.SessionLocal() as db:
                with db.begin():
                    return stage_lab_projection(db,raw_token=raw,device_id=row["device_id"],cabinet_id=ca,resource_id=order,nonce=nonce,signature_hex=sig)
        except ProjectionRefused:return None
    proof=issue()
    check("enrolled key can read explicitly granted minimal order",bool(proof) and read(proof)=={"order_id":order,"status":"SENT","deadline":(now+timedelta(days=1)).isoformat()})
    pending=issue();check("pre-revocation challenge exists",bool(pending))
    check("foreign owner cannot revoke",not revoke(actor_id=cb)[0])
    check("owner revokes",revoke()[0])
    check("issued proof refused after enrollment revoke",read(pending) is None)
    check("new challenge refused after enrollment revoke",issue() is None)
    check("repeat revocation denied",not revoke()[0])
    check("revoked cannot reenroll",not prepare()[0] and not complete(row)[0])
    database.engine.dispose()
    with database.SessionLocal() as db:
        check("revocation persists across connection",all(db.execute(select(t.c.revoked_at)).scalar_one() is not None for t in (principals,devices,lab_bindings,sessions,assignments)))
        check("exact audit lifecycle",all(db.query(models.AuditLog).filter_by(action=a,user_id=ca,employer_id=ca,resource_type="Lab",resource_id=str(la),severity="CRITICAL").count()==1 for a in ("EXTERNAL_LAB_ENROLLMENT_PREPARED","EXTERNAL_LAB_ENROLLMENT_COMPLETED","EXTERNAL_LAB_ENROLLMENT_REVOKED")))
    ok,expired=prepare(lab_id=lc,public_key_hex=public(other),verified_fingerprint=fingerprint(public(other)));assert ok
    with database.SessionLocal() as db:
        with db.begin():db.execute(update(enrollments).where(enrollments.c.nonce==expired["nonce"]).values(expires_at=now_utc()-timedelta(seconds=1)))
    check("expired challenge denied",not complete(expired,other)[0])
    third=Ed25519PrivateKey.generate()
    ok,cancelled=prepare(lab_id=ld,public_key_hex=public(third),verified_fingerprint=fingerprint(public(third)));assert ok
    check("pending revocation accepted",revoke(lab_id=ld)[0])
    check("cancelled challenge denied",not complete(cancelled,third)[0])
    check("no new authority after expired or cancelled",count(principals)==count(devices)==count(lab_bindings)==1)
finally:
    metadata.drop_all(database.engine);database.engine.dispose()
    Path(os.environ["DC_EVIDENCE"],"external-lab-enrollment.json").write_text(json.dumps(rows,indent=2))
assert len(rows)==36
