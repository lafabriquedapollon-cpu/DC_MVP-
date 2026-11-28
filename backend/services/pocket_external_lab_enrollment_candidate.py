"""Unmounted synthetic LAB enrollment. No routes or migrations.

Owner must verify the laboratory identity and fingerprint independently before
approval. Caller identity must come from trusted Desktop session; workstation
guard and rate limit remain adapter requirements. No session issuance, private
key custody, cross-cabinet federation or re-enrollment of revoked binding.
Caller owns transaction and commits before returning any successful response.
"""
import hashlib
import json
import secrets
import uuid
from datetime import timedelta
from sqlalchemy import Table, Column, String, Integer, DateTime, UniqueConstraint, select, insert, update
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from backend import models
from backend.services.pocket_external_store_candidate import metadata, principals, sessions, assignments
from backend.services.pocket_external_device_candidate import devices, now_utc, _hex
from backend.services.pocket_external_lab_projection_candidate import lab_bindings
from backend.services.pocket_external_lab_authority_candidate import _owner, AuthorityRefused

enrollments = Table("pocket_external_enrollments_candidate", metadata,
    Column("nonce", String(64), primary_key=True),
    Column("cabinet_id", Integer, nullable=False),
    Column("lab_id", Integer, nullable=False),
    Column("public_key_hex", String(64), nullable=False, unique=True),
    Column("principal_id", String(36), nullable=False, unique=True),
    Column("organization_id", String(36), nullable=False, unique=True),
    Column("device_id", String(36), nullable=False, unique=True),
    Column("expires_at", DateTime, nullable=False),
    Column("used_at", DateTime),
    Column("cancelled_at", DateTime),
    UniqueConstraint("cabinet_id", "lab_id"))

def _deny():
    raise AuthorityRefused("enrollment refused")

def _lab(db, cabinet_id, lab_id):
    if type(lab_id) is not int or not 0 < lab_id <= 2**63-1:
        _deny()
    if db.query(models.Lab.id).filter_by(id=lab_id, employer_id=cabinet_id).first() is None:
        _deny()

def _audit(db, cabinet_id, lab_id, action):
    db.add(models.AuditLog(user_id=cabinet_id, employer_id=cabinet_id, action=action,
        resource_type="Lab", resource_id=str(lab_id), severity="CRITICAL",
        details="Explicit laboratory enrollment lifecycle change."))
    db.flush()

def fingerprint(public_key_hex):
    return hashlib.sha256(bytes.fromhex(_hex(public_key_hex,64))).hexdigest()

def enrollment_message(row):
    return json.dumps(["dc/external-lab-enrollment/v1", row["nonce"], row["cabinet_id"],
        row["lab_id"], row["public_key_hex"], row["principal_id"],
        row["organization_id"], row["device_id"], row["expires_at"].isoformat()],
        ensure_ascii=True,separators=(",",":")).encode("ascii")

def stage_prepare(db, *, actor_id, cabinet_id, lab_id, public_key_hex,
                  verified_fingerprint, password, confirm):
    _owner(db,actor_id,cabinet_id,password,confirm)
    _lab(db,cabinet_id,lab_id)
    try:
        if not secrets.compare_digest(fingerprint(public_key_hex),_hex(verified_fingerprint,64)):
            _deny()
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    except (ValueError,TypeError):
        _deny()
    # Never replace a prior key or binding, even if expired or revoked.
    e,b,d=enrollments,lab_bindings,devices
    if db.execute(select(e.c.nonce).where((e.c.public_key_hex==public_key_hex) |
            ((e.c.cabinet_id==cabinet_id)&(e.c.lab_id==lab_id)))).first():
        _deny()
    if db.execute(select(b.c.id).where(b.c.cabinet_id==cabinet_id,b.c.lab_id==lab_id)).first():
        _deny()
    if db.execute(select(d.c.id).where(d.c.public_key_hex==public_key_hex)).first():
        _deny()
    row=dict(nonce=secrets.token_hex(32),cabinet_id=cabinet_id,lab_id=lab_id,
        public_key_hex=public_key_hex,principal_id=str(uuid.uuid4()),
        organization_id=str(uuid.uuid4()),device_id=str(uuid.uuid4()),
        expires_at=now_utc()+timedelta(minutes=5))
    db.execute(insert(e).values(**row))
    _audit(db,cabinet_id,lab_id,"EXTERNAL_LAB_ENROLLMENT_PREPARED")
    return {**row,"message":enrollment_message(row)}

def stage_complete(db, *, nonce, signature_hex):
    e=enrollments
    try:
        _hex(nonce,64)
        signature=bytes.fromhex(_hex(signature_hex,128))
    except (ValueError,TypeError):
        _deny()
    row=db.execute(select(e).where(e.c.nonce==nonce)).mappings().one_or_none()
    now=now_utc()
    if row is None or row["used_at"] is not None or row["cancelled_at"] is not None or row["expires_at"]<=now:
        _deny()
    ca,lab=row["cabinet_id"],row["lab_id"]
    _lab(db,ca,lab)
    owner=db.query(models.User).filter_by(id=ca).first()
    if owner is None or owner.employer_id is not None or owner.role not in (models.UserRole.ADMIN,models.UserRole.DENTISTE) or not owner.is_active or owner.is_archived or owner.is_suspended:
        _deny()
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(row["public_key_hex"])).verify(signature,enrollment_message(row))
    except (ValueError,InvalidSignature):
        _deny()
    result=db.execute(update(e).where(e.c.nonce==nonce,e.c.used_at.is_(None),
        e.c.cancelled_at.is_(None),e.c.expires_at>now).values(used_at=now))
    if result.rowcount!=1:
        _deny()
    db.execute(insert(principals).values(id=row["principal_id"],kind="laboratory",organization_id=row["organization_id"]))
    db.execute(insert(devices).values(id=row["device_id"],principal_id=row["principal_id"],public_key_hex=row["public_key_hex"]))
    db.execute(insert(lab_bindings).values(organization_id=row["organization_id"],cabinet_id=ca,lab_id=lab))
    _audit(db,ca,lab,"EXTERNAL_LAB_ENROLLMENT_COMPLETED")
    return {"principal_id":row["principal_id"],"device_id":row["device_id"]}

def stage_revoke_enrollment(db, *, actor_id,cabinet_id,lab_id,password,confirm):
    _owner(db,actor_id,cabinet_id,password,confirm)
    _lab(db,cabinet_id,lab_id)
    e=enrollments
    row=db.execute(select(e).where(e.c.cabinet_id==cabinet_id,e.c.lab_id==lab_id)).mappings().one_or_none()
    if row is None or row["cancelled_at"] is not None:
        _deny()
    now=now_utc()
    result=db.execute(update(e).where(e.c.nonce==row["nonce"],e.c.cancelled_at.is_(None)).values(cancelled_at=now))
    if result.rowcount!=1:
        _deny()
    if row["used_at"] is not None:
        p=row["principal_id"]
        for table,condition in ((principals,principals.c.id==p),
                (devices,devices.c.principal_id==p),(sessions,sessions.c.principal_id==p),
                (assignments,assignments.c.principal_id==p),
                (lab_bindings,(lab_bindings.c.organization_id==row["organization_id"]) &
                 (lab_bindings.c.cabinet_id==cabinet_id)&(lab_bindings.c.lab_id==lab_id))):
            db.execute(update(table).where(condition,table.c.revoked_at.is_(None)).values(revoked_at=now))
    _audit(db,cabinet_id,lab_id,"EXTERNAL_LAB_ENROLLMENT_REVOKED")
