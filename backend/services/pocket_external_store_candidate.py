"""External identity persistence candidate, unmounted pending schema/authority approval.

Separate metadata deliberately prevents implicit schema creation by application
startup. Production migration, enrollment and endpoints are NOT provided.
Only an authoritative server assignment may grant a scoped nonclinical read.
"""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from sqlalchemy import (MetaData, Table, Column, String, Integer, Boolean, DateTime,
                        ForeignKey, CheckConstraint, UniqueConstraint, select, and_)
from backend.services.pocket_external_scope import ExternalScope, ResourceAssignment, matches_read_scope

metadata = MetaData()
principals = Table("pocket_external_principals_candidate", metadata,
    Column("id", String(36), primary_key=True), Column("kind", String(16), nullable=False),
    Column("organization_id", String(36), nullable=False), Column("revoked_at", DateTime),
    CheckConstraint("kind IN ('technical','laboratory')"))
assignments = Table("pocket_external_assignments_candidate", metadata,
    Column("id", Integer, primary_key=True),
    Column("principal_id", String(36), ForeignKey(principals.c.id), nullable=False),
    Column("cabinet_id", Integer, nullable=False), Column("resource_id", Integer, nullable=False),
    Column("revoked_at", DateTime),
    CheckConstraint("cabinet_id > 0 AND resource_id > 0"),
    UniqueConstraint("principal_id", "cabinet_id", "resource_id"))
sessions = Table("pocket_external_sessions_candidate", metadata,
    Column("token_digest", String(64), primary_key=True),
    Column("principal_id", String(36), ForeignKey(principals.c.id), nullable=False),
    Column("device_id", String(36), nullable=False),
    Column("issued_at", DateTime, nullable=False), Column("expires_at", DateTime, nullable=False),
    Column("revoked_at", DateTime),
    CheckConstraint("expires_at > issued_at"))

def digest_token(raw: str) -> str:
    # A random 256-bit opaque token, encoded as 64 lowercase hex digits.
    if type(raw) is not str or len(raw) != 64 or any(c not in "0123456789abcdef" for c in raw):
        raise ValueError("invalid external token")
    return sha256(("dc/external-session/v1:" + raw).encode("ascii")).hexdigest()

def permits_read(db, *, raw_token, device_id, action, cabinet_id, resource_id):
    """Read-only resolution from live persistent records; never trust caller role/org.

    Device id is a scope identifier, NOT proof of possession. A production adapter
    must bind the session to a verified device credential, use protected transport,
    and serve only a minimized projection in the same authoritative transaction.
    """
    if type(device_id) is not str or not device_id or type(cabinet_id) is not int or type(resource_id) is not int:
        return False
    try:
        token_digest = digest_token(raw_token)
    except ValueError:
        return False
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    s,p,a = sessions,principals,assignments
    row = db.execute(select(p.c.id, p.c.kind, p.c.organization_id, a.c.cabinet_id, a.c.resource_id,
                            s.c.issued_at,s.c.expires_at)
        .select_from(s.join(p,s.c.principal_id==p.c.id).join(a,a.c.principal_id==p.c.id))
        .where(and_(s.c.token_digest==token_digest,s.c.device_id==device_id,
                    s.c.revoked_at.is_(None),p.c.revoked_at.is_(None),a.c.revoked_at.is_(None),
                    s.c.issued_at<=now,s.c.expires_at>now,
                    a.c.cabinet_id==cabinet_id,a.c.resource_id==resource_id))).mappings().one_or_none()
    if row is None or row["expires_at"]-row["issued_at"]>timedelta(minutes=15):
        return False
    scope = ExternalScope(row["kind"],row["id"],row["organization_id"])
    assignment = ResourceAssignment(row["kind"],row["id"],row["organization_id"],
                                    row["cabinet_id"],row["resource_id"],True)
    return matches_read_scope(scope,assignment,action=action,cabinet_id=cabinet_id,resource_id=resource_id)
