"""LAB-only candidate: single-use signed proof for an exact external read.

No router, enrollment or production migration. Public keys are provisioned by
a trusted authority, never supplied by the read caller. No credential issuance.
"""
from datetime import datetime, timedelta, timezone
import json
import secrets
from hashlib import sha256
from sqlalchemy import Table, Column, String, Integer, DateTime, ForeignKey, select, insert, update
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from backend.services.pocket_external_store_candidate import metadata, principals, sessions, digest_token, permits_read

devices = Table("pocket_external_devices_candidate", metadata,
    Column("id",String(36),primary_key=True),
    Column("principal_id",String(36),ForeignKey(principals.c.id),nullable=False),
    Column("public_key_hex",String(64),nullable=False),
    Column("revoked_at",DateTime))
challenges = Table("pocket_external_read_proofs_candidate", metadata,
    Column("nonce",String(64),primary_key=True),
    Column("session_digest",String(64),ForeignKey(sessions.c.token_digest),nullable=False),
    Column("device_id",String(36),ForeignKey(devices.c.id),nullable=False),
    Column("intent_digest",String(64),nullable=False),
    Column("expires_at",DateTime,nullable=False),
    Column("used_at",DateTime))

def now_utc():
    return datetime.now(timezone.utc).replace(tzinfo=None)

def _hex(value, length):
    if type(value) is not str or len(value)!=length or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("invalid proof encoding")
    return value

def message(*, session_digest, device_id, action, cabinet_id, resource_id, nonce):
    _hex(session_digest,64); _hex(nonce,64)
    if type(device_id) is not str or not 0<len(device_id)<=36:
        raise ValueError("invalid device")
    if action not in ("diagnostic.read","assigned-order.read"):
        raise ValueError("invalid action")
    if any(type(x) is not int or not 0<x<=2**63-1 for x in (cabinet_id,resource_id)):
        raise ValueError("invalid resource")
    return json.dumps(["dc/external-device-read/v1",session_digest,device_id,action,cabinet_id,resource_id,nonce],
                      ensure_ascii=True,separators=(",",":")).encode("ascii")

def _device(db, digest, device_id):
    return db.execute(select(devices.c.public_key_hex)
        .select_from(devices.join(sessions, devices.c.principal_id==sessions.c.principal_id))
        .where(devices.c.id==device_id,devices.c.revoked_at.is_(None),
               sessions.c.token_digest==digest,sessions.c.device_id==device_id,
               sessions.c.revoked_at.is_(None))).scalar_one_or_none()

def stage_challenge(db, *, raw_token, device_id, action, cabinet_id, resource_id):
    if not permits_read(db,raw_token=raw_token,device_id=device_id,action=action,cabinet_id=cabinet_id,resource_id=resource_id):
        return None
    digest=digest_token(raw_token)
    if _device(db,digest,device_id) is None:
        return None
    nonce=secrets.token_hex(32)
    data=message(session_digest=digest,device_id=device_id,action=action,cabinet_id=cabinet_id,resource_id=resource_id,nonce=nonce)
    db.execute(insert(challenges).values(nonce=nonce,session_digest=digest,device_id=device_id,
        intent_digest=sha256(data).hexdigest(),expires_at=now_utc()+timedelta(seconds=60)))
    return nonce

def stage_signed_read(db, *, raw_token, device_id, action, cabinet_id, resource_id, nonce, signature_hex):
    """Caller owns transaction; commit before disclosing any minimized projection.

    A successful result only proves the candidate binding. An eventual route
    must read its authorized projection in the same transaction and must not
    expose generic cabinet resources.
    """
    try:
        digest=digest_token(raw_token)
        data=message(session_digest=digest,device_id=device_id,action=action,cabinet_id=cabinet_id,resource_id=resource_id,nonce=nonce)
        signature=bytes.fromhex(_hex(signature_hex,128))
    except (ValueError,TypeError):
        return False
    if not permits_read(db,raw_token=raw_token,device_id=device_id,action=action,cabinet_id=cabinet_id,resource_id=resource_id):
        return False
    key=_device(db,digest,device_id)
    if key is None:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(_hex(key,64))).verify(signature,data)
    except (ValueError,InvalidSignature):
        return False
    now=now_utc()
    result=db.execute(update(challenges).where(
        challenges.c.nonce==nonce,challenges.c.session_digest==digest,challenges.c.device_id==device_id,
        challenges.c.intent_digest==sha256(data).hexdigest(),challenges.c.used_at.is_(None),
        challenges.c.expires_at>now).values(used_at=now))
    return result.rowcount==1
