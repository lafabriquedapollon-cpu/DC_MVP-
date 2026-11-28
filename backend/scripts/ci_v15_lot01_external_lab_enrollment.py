"""Real SQLCipher candidate enrollment, synthetic CI only."""
import os,json,secrets
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from sqlalchemy.exc import OperationalError
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
from backend.services.pocket_external_lab_session_candidate import issuance,stage_session_challenge,stage_issue_session,SessionRefused
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
    except (AuthorityRefused,SessionRefused): return False,None
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
    # Actual candidate issuance, using ephemeral LAB keys only.
    def challenge(**kw):
        return call(stage_session_challenge,**{**dict(device_id=row["device_id"],cabinet_id=ca),**kw})
    def mint(proof,signer=key,**kw):
        return call(stage_issue_session,**{**dict(nonce=proof["nonce"],signature_hex=sign(signer,proof)),**kw})
    check("unknown device session refused",not challenge(device_id="missing")[0])
    check("cross cabinet session refused",not challenge(cabinet_id=cb)[0])
    ok,proof=challenge();check("active enrolled device receives session challenge",ok)
    check("challenge alone creates no session",count(sessions)==0)
    check("wrong session signer refused",not mint(proof,other)[0])
    check("malformed session signature refused",not mint(proof,signature_hex="bad")[0])
    check("unknown session nonce refused",not mint(proof,nonce="0"*64)[0])
    check("failed issuance creates no session",count(sessions)==0)
    with database.SessionLocal() as db:
        tx=db.begin()
        stage_issue_session(db,nonce=proof["nonce"],signature_hex=sign(key,proof))
        tx.rollback()
    check("issuance rollback leaves no session",count(sessions)==0)
    ok,token=mint(proof);check("correct device proof issues token",ok and len(token["token"])==64)
    raw=token["token"]
    check("session proof replay refused",not mint(proof)[0])
    with database.SessionLocal() as db:
        stored=db.execute(select(sessions)).mappings().one()
        check("only domain-separated token digest persisted",stored["token_digest"]==digest_token(raw) and stored["token_digest"]!=raw)
        check("token scope and ten minute lifetime",stored["principal_id"]==row["principal_id"] and stored["device_id"]==row["device_id"] and stored["expires_at"]-stored["issued_at"]==timedelta(minutes=10))
    ok,expired_session=challenge();assert ok
    with database.SessionLocal() as db:
        with db.begin():db.execute(update(issuance).where(issuance.c.nonce==expired_session["nonce"]).values(expires_at=now_utc()-timedelta(seconds=1)))
    check("expired session challenge refused",not mint(expired_session)[0])
    now=now_utc()
    with database.SessionLocal() as db:
        with db.begin():
            patient=models.Patient(nom="SYNTH_ENROLL_PATIENT",prenom="SYNTH",date_naissance=now,sexe="M",employer_id=ca)
            db.add(patient);db.flush()
            act=models.Acte(patient_id=patient.id,praticien_id=ca,type_acte=models.ActeType.PROTHESE,libelle="SYNTH_ACT",montant=999)
            db.add(act);db.flush()
            job=models.LabJob(patient_id=patient.id,act_id=act.id,lab_id=la,material="SYNTH",type="SYNTH",notes="SYNTH_PRIVATE",deadline=now+timedelta(days=1),status=models.LabJobStatus.SENT)
            db.add(job);db.flush();order=job.id
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
    old_raw=raw
    old_proof=issue()
    ok,renew=challenge();assert ok
    ok,renewed=mint(renew);check("fresh proof rotates session",ok and renewed["token"]!=old_raw)
    with database.SessionLocal() as db:
        old=db.execute(select(sessions.c.revoked_at).where(sessions.c.token_digest==digest_token(old_raw))).scalar_one()
        check("previous session revoked on rotation",old is not None)
    check("rotated token cannot request proof",issue() is None)
    check("prior signed read proof refused after rotation",read(old_proof) is None)
    raw=renewed["token"]
    next_proof=issue();check("new session signed read works",bool(next_proof) and read(next_proof) is not None)
    # Independent connections, real SQLCipher WAL; no mock or blind retry.
    def race(*ops):
        gate=Barrier(len(ops),timeout=15)
        def worker(op):
            with database.SessionLocal() as db:
                with db.begin():
                    db.connection()
                    gate.wait()
                    try:
                        value=op(db)
                    except (AuthorityRefused,SessionRefused,ProjectionRefused):
                        db.rollback()
                        return ("refused",None)
                    except OperationalError as exc:
                        db.rollback()
                        if not any(s in str(exc.orig).lower() for s in ("database is locked","database table is locked","database is busy")):
                            raise
                        return ("busy",None)
                return ("committed",value)
        with ThreadPoolExecutor(max_workers=len(ops)) as pool:
            futures=[pool.submit(worker,op) for op in ops]
            return [f.result(timeout=30) for f in futures]
    def mint_op(proof):
        sig=sign(key,proof)
        return lambda db:stage_issue_session(db,nonce=proof["nonce"],signature_hex=sig)
    def active_count():
        with database.SessionLocal() as db:
            return db.execute(select(func.count()).select_from(sessions).where(sessions.c.revoked_at.is_(None),sessions.c.device_id==row["device_id"])).scalar_one()
    ok,same=challenge();assert ok
    pair=race(mint_op(same),mint_op(same))
    winners=[v for status,v in pair if status=="committed"]
    check("concurrent same issuance proof commits exactly once",len(winners)==1)
    check("concurrent same proof leaves one active session",active_count()==1)
    check("concurrent same proof cannot be reused",not mint(same)[0])
    raw=winners[0]["token"]
    ok,first=challenge();assert ok
    ok,second=challenge();assert ok
    pair=race(mint_op(first),mint_op(second))
    winners=[v for status,v in pair if status=="committed"]
    check("concurrent distinct issuance makes progress",len(winners)>=1)
    check("concurrent distinct issuance leaves exactly one active session",active_count()==1)
    with database.SessionLocal() as db:
        current=db.execute(select(sessions.c.token_digest).where(sessions.c.revoked_at.is_(None),sessions.c.device_id==row["device_id"])).scalar_one()
    live=[v for v in winners if digest_token(v["token"])==current]
    check("exactly one committed concurrent token remains active",len(live)==1)
    raw=live[0]["token"]
    proof=issue();assert proof
    sig=key.sign(message(session_digest=digest_token(raw),device_id=row["device_id"],action="assigned-order.read",cabinet_id=ca,resource_id=order,nonce=proof)).hex()
    def project(db):
        return stage_lab_projection(db,raw_token=raw,device_id=row["device_id"],cabinet_id=ca,resource_id=order,nonce=proof,signature_hex=sig)
    pair=race(project,project)
    check("concurrent signed read proof discloses once",sum(s=="committed" for s,v in pair)==1)
    check("concurrent read replay refused",read(proof) is None)
    pending=issue();check("pre-revocation challenge exists",bool(pending))
    ok,pending_session=challenge();assert ok
    check("foreign owner cannot revoke",not revoke(actor_id=cb)[0])
    check("owner revokes",revoke()[0])
    check("issued proof refused after enrollment revoke",read(pending) is None)
    check("new challenge refused after enrollment revoke",issue() is None)
    check("pending session issuance refused after revoke",not mint(pending_session)[0])
    check("new session challenge refused after revoke",not challenge()[0])
    check("repeat revocation denied",not revoke()[0])
    check("revoked cannot reenroll",not prepare()[0] and not complete(row)[0])
    database.engine.dispose()
    with database.SessionLocal() as db:
        check("revocation persists across connection",all(all(v is not None for v in db.execute(select(t.c.revoked_at)).scalars().all()) for t in (principals,devices,lab_bindings,sessions,assignments)))
        check("exact audit lifecycle",all(db.query(models.AuditLog).filter_by(action=a,user_id=ca,employer_id=ca,resource_type="Lab",resource_id=str(la),severity="CRITICAL").count()==1 for a in ("EXTERNAL_LAB_ENROLLMENT_PREPARED","EXTERNAL_LAB_ENROLLMENT_COMPLETED","EXTERNAL_LAB_ENROLLMENT_REVOKED")))
    with database.SessionLocal() as db:
        check("committed issuances audited exactly once per session",db.query(models.AuditLog).filter_by(action="EXTERNAL_LAB_SESSION_ISSUED",resource_type="Lab",resource_id=str(la),severity="CRITICAL").count()==db.execute(select(func.count()).select_from(sessions).where(sessions.c.device_id==row["device_id"])).scalar_one())
    # Separate fresh binding for issuance versus revocation, without affecting prior evidence.
    race_key=Ed25519PrivateKey.generate()
    with database.SessionLocal() as db:
        with db.begin():race_lab=make_lab(ca,"RACE")
    ok,race_row=prepare(lab_id=race_lab,public_key_hex=public(race_key),verified_fingerprint=fingerprint(public(race_key)));assert ok
    ok,_=complete(race_row,race_key);assert ok
    ok,race_proof=challenge(device_id=race_row["device_id"]);assert ok
    def revoke_op(db):
        stage_revoke_enrollment(db,actor_id=ca,cabinet_id=ca,lab_id=race_lab,password=password,confirm=True)
    def race_mint(db):
        return stage_issue_session(db,nonce=race_proof["nonce"],signature_hex=sign(race_key,race_proof))
    pair=race(race_mint,revoke_op)
    check("issuance revocation race makes progress",any(s=="committed" for s,v in pair))
    # A busy revoke is not success. Explicitly finish it in a new transaction.
    if pair[1][0]!="committed":
        assert revoke(lab_id=race_lab)[0]
    check("session issuance denied after committed race revocation",not mint(race_proof,race_key)[0])
    check("new challenge denied after committed race revocation",not challenge(device_id=race_row["device_id"])[0])
    database.engine.dispose()
    with database.SessionLocal() as db:
        check("no active session survives committed race revocation",db.execute(select(func.count()).select_from(sessions).where(sessions.c.device_id==race_row["device_id"],sessions.c.revoked_at.is_(None))).scalar_one()==0)
        check("race revocation audit exactly once",db.query(models.AuditLog).filter_by(action="EXTERNAL_LAB_ENROLLMENT_REVOKED",resource_type="Lab",resource_id=str(race_lab),severity="CRITICAL").count()==1)
    ok,expired=prepare(lab_id=lc,public_key_hex=public(other),verified_fingerprint=fingerprint(public(other)));assert ok
    with database.SessionLocal() as db:
        with db.begin():db.execute(update(enrollments).where(enrollments.c.nonce==expired["nonce"]).values(expires_at=now_utc()-timedelta(seconds=1)))
    check("expired challenge denied",not complete(expired,other)[0])
    third=Ed25519PrivateKey.generate()
    ok,cancelled=prepare(lab_id=ld,public_key_hex=public(third),verified_fingerprint=fingerprint(public(third)));assert ok
    check("pending revocation accepted",revoke(lab_id=ld)[0])
    check("cancelled challenge denied",not complete(cancelled,third)[0])
    check("no new authority after expired or cancelled",count(principals)==count(devices)==count(lab_bindings)==2)
finally:
    metadata.drop_all(database.engine);database.engine.dispose()
    Path(os.environ["DC_EVIDENCE"],"external-lab-enrollment.json").write_text(json.dumps(rows,indent=2))
EXPECTED_LABELS = [
    "staff denied",
    "foreign owner denied",
    "cross cabinet lab denied",
    "wrong password denied",
    "confirmation required",
    "key fingerprint mismatch denied",
    "malformed public key denied",
    "no pending or authority on refusals",
    "owner prepares enrollment",
    "pending grants nothing",
    "duplicate lab refused",
    "duplicate key for different lab refused",
    "wrong key proof denied",
    "malformed proof denied",
    "altered nonce denied",
    "denied proofs create nothing",
    "completion rollback leaves no authority",
    "correct proof completes",
    "replay denied",
    "exact one principal device binding",
    "no automatic order grant or session",
    "exact cabinet lab and principal binding",
    "public key only",
    "unknown device session refused",
    "cross cabinet session refused",
    "active enrolled device receives session challenge",
    "challenge alone creates no session",
    "wrong session signer refused",
    "malformed session signature refused",
    "unknown session nonce refused",
    "failed issuance creates no session",
    "issuance rollback leaves no session",
    "correct device proof issues token",
    "session proof replay refused",
    "only domain-separated token digest persisted",
    "token scope and ten minute lifetime",
    "expired session challenge refused",
    "enrolled key can read explicitly granted minimal order",
    "fresh proof rotates session",
    "previous session revoked on rotation",
    "rotated token cannot request proof",
    "prior signed read proof refused after rotation",
    "new session signed read works",
    "concurrent same issuance proof commits exactly once",
    "concurrent same proof leaves one active session",
    "concurrent same proof cannot be reused",
    "concurrent distinct issuance makes progress",
    "concurrent distinct issuance leaves exactly one active session",
    "exactly one committed concurrent token remains active",
    "concurrent signed read proof discloses once",
    "concurrent read replay refused",
    "pre-revocation challenge exists",
    "foreign owner cannot revoke",
    "owner revokes",
    "issued proof refused after enrollment revoke",
    "new challenge refused after enrollment revoke",
    "pending session issuance refused after revoke",
    "new session challenge refused after revoke",
    "repeat revocation denied",
    "revoked cannot reenroll",
    "revocation persists across connection",
    "exact audit lifecycle",
    "committed issuances audited exactly once per session",
    "issuance revocation race makes progress",
    "session issuance denied after committed race revocation",
    "new challenge denied after committed race revocation",
    "no active session survives committed race revocation",
    "race revocation audit exactly once",
    "expired challenge denied",
    "pending revocation accepted",
    "cancelled challenge denied",
    "no new authority after expired or cancelled"
]
assert [row['label'] for row in rows] == EXPECTED_LABELS
assert all(row['pass'] is True for row in rows)
