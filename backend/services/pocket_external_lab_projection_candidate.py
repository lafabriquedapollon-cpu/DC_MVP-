"""LAB-only read adapter. Explicit organization-to-cabinet-lab binding.
No route, production migration, enrollment or automatic grant. The eventual
authority must create/revoke these bindings independently of external callers.
Caller owns the transaction; commit before disclosing a projection.
"""
from sqlalchemy import Table, Column, String, Integer, DateTime, UniqueConstraint, CheckConstraint, select
from backend import models
from backend.services.pocket_external_store_candidate import metadata, principals, sessions, digest_token
from backend.services.pocket_external_device_candidate import stage_signed_read

lab_bindings = Table("pocket_external_lab_bindings_candidate", metadata,
    Column("id", Integer, primary_key=True),
    Column("organization_id", String(36), nullable=False),
    Column("cabinet_id", Integer, nullable=False),
    Column("lab_id", Integer, nullable=False),
    Column("revoked_at", DateTime),
    CheckConstraint("cabinet_id > 0 AND lab_id > 0"),
    UniqueConstraint("cabinet_id", "lab_id"))

class ProjectionRefused(Exception):
    pass

def stage_lab_projection(db, *, raw_token, device_id, cabinet_id, resource_id, nonce, signature_hex):
    # A valid signature alone never grants access to a different laboratory.
    if not stage_signed_read(db,raw_token=raw_token,device_id=device_id,
        action="assigned-order.read",cabinet_id=cabinet_id,resource_id=resource_id,
        nonce=nonce,signature_hex=signature_hex):
        raise ProjectionRefused("read refused")
    p,s,b=principals,sessions,lab_bindings
    j,l,patient,act=models.LabJob,models.Lab,models.Patient,models.Acte
    # Only allow-listed columns. Never material, notes, patient/act identifiers,
    # names, contacts, finances, clinical history, media or free text.
    row=db.execute(select(j.id,j.status,j.deadline)
        .select_from(s.join(p,s.c.principal_id==p.c.id)
            .join(b,b.c.organization_id==p.c.organization_id)
            .join(l,l.id==b.c.lab_id)
            .join(j,j.lab_id==l.id)
            .join(patient,patient.id==j.patient_id)
            .join(act,act.id==j.act_id))
        .where(s.c.token_digest==digest_token(raw_token),p.c.kind=="laboratory",
            b.c.revoked_at.is_(None),b.c.cabinet_id==cabinet_id,
            l.employer_id==cabinet_id,patient.employer_id==cabinet_id,
            act.patient_id==patient.id,j.id==resource_id)).one_or_none()
    if row is None:
        raise ProjectionRefused("read refused")
    return {"order_id":row.id,"status":row.status.value,"deadline":row.deadline.isoformat()}
