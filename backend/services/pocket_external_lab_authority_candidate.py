"""Unmounted LAB authorization contract, no production entrypoint.
Caller must supply the actor ID from a verified Desktop session, never request
data, with fresh password confirmation and workstation policy enforced.
An approved external principal and organization binding are prerequisites.
No creation of principals, keys, bindings, or sessions here.
"""
from datetime import datetime, timezone
from sqlalchemy import select, insert, update
from backend import models
from backend.security import verify_password
from backend.services.pocket_external_store_candidate import principals, assignments
from backend.services.pocket_external_lab_projection_candidate import lab_bindings

class AuthorityRefused(Exception):
    pass

def _owner(db, actor_id, cabinet_id, password, confirm):
    if any(type(x) is not int or x<=0 for x in (actor_id,cabinet_id)) or actor_id!=cabinet_id or confirm is not True:
        raise AuthorityRefused("authorization refused")
    if type(password) is not str or not 1<=len(password.encode("utf-8"))<=72:
        raise AuthorityRefused("authorization refused")
    actor=db.query(models.User).filter_by(id=actor_id).first()
    if actor is None or actor.employer_id is not None or actor.role not in (models.UserRole.ADMIN,models.UserRole.DENTISTE) or not actor.is_active or actor.is_archived or actor.is_suspended:
        raise AuthorityRefused("authorization refused")
    try: valid=verify_password(password,actor.hashed_password)
    except (ValueError,TypeError): valid=False
    if not valid: raise AuthorityRefused("authorization refused")

def _audit(db,actor_id,cabinet_id,order_id,action):
    db.add(models.AuditLog(user_id=actor_id,employer_id=cabinet_id,action=action,
        resource_type="LabJob",resource_id=str(order_id),severity="CRITICAL",
        details="Explicit cabinet-owner external laboratory assignment change."))
    db.flush()

def stage_grant(db,*,actor_id,cabinet_id,principal_id,order_id,password,confirm):
    _owner(db,actor_id,cabinet_id,password,confirm)
    if type(principal_id) is not str or not 1<=len(principal_id)<=36 or type(order_id) is not int or order_id<=0:
        raise AuthorityRefused("authorization refused")
    p,b=principals,lab_bindings
    j,l,patient,act=models.LabJob,models.Lab,models.Patient,models.Acte
    valid=db.execute(select(p.c.id).select_from(p.join(b,b.c.organization_id==p.c.organization_id)
        .join(l,l.id==b.c.lab_id).join(j,j.lab_id==l.id).join(patient,patient.id==j.patient_id)
        .join(act,act.id==j.act_id)).where(p.c.id==principal_id,p.c.kind=="laboratory",
        p.c.revoked_at.is_(None),b.c.revoked_at.is_(None),b.c.cabinet_id==cabinet_id,
        l.employer_id==cabinet_id,patient.employer_id==cabinet_id,act.patient_id==patient.id,j.id==order_id)).scalar_one_or_none()
    if valid is None: raise AuthorityRefused("authorization refused")
    a=assignments
    match=(a.c.principal_id==principal_id,a.c.cabinet_id==cabinet_id,a.c.resource_id==order_id)
    previous=db.execute(select(a.c.id,a.c.revoked_at).where(*match)).one_or_none()
    # Never resurrect revoked authority implicitly. A new enrollment/generation
    # contract is required before regrant; this candidate deliberately denies it.
    if previous is not None: raise AuthorityRefused("assignment already exists")
    db.execute(insert(a).values(principal_id=principal_id,cabinet_id=cabinet_id,resource_id=order_id))
    _audit(db,actor_id,cabinet_id,order_id,"EXTERNAL_LAB_ASSIGNMENT_GRANTED")

def stage_revoke(db,*,actor_id,cabinet_id,principal_id,order_id,password,confirm):
    _owner(db,actor_id,cabinet_id,password,confirm)
    if type(principal_id) is not str or not 1<=len(principal_id)<=36 or type(order_id) is not int or order_id<=0:
        raise AuthorityRefused("authorization refused")
    a=assignments
    result=db.execute(update(a).where(a.c.principal_id==principal_id,a.c.cabinet_id==cabinet_id,
        a.c.resource_id==order_id,a.c.revoked_at.is_(None)).values(revoked_at=datetime.now(timezone.utc).replace(tzinfo=None)))
    if result.rowcount!=1: raise AuthorityRefused("authorization refused")
    _audit(db,actor_id,cabinet_id,order_id,"EXTERNAL_LAB_ASSIGNMENT_REVOKED")
