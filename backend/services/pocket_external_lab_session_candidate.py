"""Unmounted LAB-only session issuer. No client key storage, router or migration.

The adapter must enforce authenticated TLS, request rate limits, commit before
returning a token, and never log secrets. A fresh signature is required for
issuance and again for every protected read. No bearer-only authorization.
"""
import json
import secrets
from datetime import timedelta
from sqlalchemy import Table, Column, String, Integer, DateTime, ForeignKey, select, insert, update
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from backend import models
from backend.services.pocket_external_store_candidate import metadata, principals, sessions, digest_token
from backend.services.pocket_external_device_candidate import devices, now_utc, _hex
from backend.services.pocket_external_lab_projection_candidate import lab_bindings
from backend.services.pocket_external_lab_enrollment_candidate import enrollments

issuance = Table("pocket_external_session_issuance_candidate", metadata,
    Column("nonce", String(64), primary_key=True),
    Column("device_id", String(36), ForeignKey(devices.c.id), nullable=False),
    Column("principal_id", String(36), ForeignKey(principals.c.id), nullable=False),
    Column("cabinet_id", Integer, nullable=False),
    Column("lab_id", Integer, nullable=False),
    Column("expires_at", DateTime, nullable=False),
    Column("used_at", DateTime))

class SessionRefused(Exception):
    pass

def _deny():
    raise SessionRefused("session refused")

def _active(db,device_id,cabinet_id):
    if type(device_id) is not str or not 0<len(device_id)<=36 or type(cabinet_id) is not int or not 0<cabinet_id<=2**63-1:
        _deny()
    e,d,p,b=enrollments,devices,principals,lab_bindings
    row=db.execute(select(e.c.principal_id,e.c.device_id,e.c.cabinet_id,e.c.lab_id,e.c.public_key_hex)
        .select_from(e.join(d,d.c.id==e.c.device_id).join(p,p.c.id==d.c.principal_id)
        .join(b,b.c.organization_id==p.c.organization_id).join(models.Lab,models.Lab.id==b.c.lab_id)
        .join(models.User,models.User.id==b.c.cabinet_id))
        .where(e.c.device_id==device_id,e.c.cabinet_id==cabinet_id,e.c.used_at.is_not(None),e.c.cancelled_at.is_(None),
        e.c.principal_id==p.c.id,e.c.organization_id==p.c.organization_id,e.c.public_key_hex==d.c.public_key_hex,
        d.c.revoked_at.is_(None),p.c.revoked_at.is_(None),p.c.kind=="laboratory",
        b.c.revoked_at.is_(None),b.c.cabinet_id==cabinet_id,b.c.lab_id==e.c.lab_id,
        models.Lab.employer_id==cabinet_id,models.User.employer_id.is_(None),
        models.User.role.in_([models.UserRole.ADMIN,models.UserRole.DENTISTE]),
        models.User.is_active.is_(True),models.User.is_archived.is_(False),models.User.is_suspended.is_(False))).mappings().one_or_none()
    if row is None:
        _deny()
    return row

def session_message(row):
    return json.dumps(["dc/external-lab-session/v1",row["nonce"],row["device_id"],
        row["principal_id"],row["cabinet_id"],row["lab_id"],row["expires_at"].isoformat()],
        ensure_ascii=True,separators=(",",":")).encode("ascii")

def stage_session_challenge(db,*,device_id,cabinet_id):
    active=_active(db,device_id,cabinet_id)
    row={k:active[k] for k in ("device_id","principal_id","cabinet_id","lab_id")}
    row.update(nonce=secrets.token_hex(32),expires_at=now_utc()+timedelta(seconds=60))
    db.execute(insert(issuance).values(**row))
    return {**row,"message":session_message(row)}

def stage_issue_session(db,*,nonce,signature_hex):
    try:
        _hex(nonce,64)
        signature=bytes.fromhex(_hex(signature_hex,128))
    except (ValueError,TypeError):
        _deny()
    row=db.execute(select(issuance).where(issuance.c.nonce==nonce)).mappings().one_or_none()
    now=now_utc()
    if row is None or row["used_at"] is not None or row["expires_at"]<=now:
        _deny()
    active=_active(db,row["device_id"],row["cabinet_id"])
    if any(active[k]!=row[k] for k in ("device_id","principal_id","cabinet_id","lab_id")):
        _deny()
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(active["public_key_hex"])).verify(signature,session_message(row))
    except (ValueError,InvalidSignature):
        _deny()
    result=db.execute(update(issuance).where(issuance.c.nonce==nonce,issuance.c.used_at.is_(None),
        issuance.c.expires_at>now).values(used_at=now))
    if result.rowcount!=1:
        _deny()
    # Recheck authority after the guarded write; SQLite transaction conflicts
    # must fail closed and be rolled back by the caller, not retried blindly.
    _active(db,row["device_id"],row["cabinet_id"])
    db.execute(update(sessions).where(sessions.c.device_id==row["device_id"],
        sessions.c.principal_id==row["principal_id"],sessions.c.revoked_at.is_(None)).values(revoked_at=now))
    raw=secrets.token_hex(32)
    expires=now+timedelta(minutes=10)
    db.execute(insert(sessions).values(token_digest=digest_token(raw),principal_id=row["principal_id"],
        device_id=row["device_id"],issued_at=now,expires_at=expires))
    db.add(models.AuditLog(user_id=row["cabinet_id"],employer_id=row["cabinet_id"],
        action="EXTERNAL_LAB_SESSION_ISSUED",resource_type="Lab",resource_id=str(row["lab_id"]),
        severity="CRITICAL",details="External laboratory device proof verified; prior session revoked."))
    db.flush()
    return {"token":raw,"expires_at":expires.isoformat()}
