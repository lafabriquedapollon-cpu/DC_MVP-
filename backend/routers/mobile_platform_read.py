"""R5-A: narrow read-only Pocket platform API. Desktop contracts remain separate."""
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from backend import database, models
from backend.routers.partner_superadmin_security import require_pocket_platform_reader

router = APIRouter(prefix="/superadmin", tags=["Pocket SuperAdmin"])


@router.get("/clients")
def clients(response: Response, limit: int = Query(50, ge=1, le=100),
            offset: int = Query(0, ge=0),
            db: Session = Depends(database.get_db),
            admin: models.User = Depends(require_pocket_platform_reader)):
    response.headers["Cache-Control"] = "no-store"
    u = models.User
    rows = db.query(u.id, u.email, u.nom_complet, u.role, u.is_active, u.is_licensed,
                    u.license_expires_at, u.is_archived, u.is_suspended, u.subscription_plan).filter(
        u.role.in_([models.UserRole.ADMIN, models.UserRole.DENTISTE]),
        u.employer_id.is_(None),
    ).order_by(u.id).offset(offset).limit(limit).all()
    return [dict(row._mapping) for row in rows]


@router.get("/trial-codes")
def trials(response: Response, limit: int = Query(50, ge=1, le=100),
           offset: int = Query(0, ge=0),
           db: Session = Depends(database.get_db),
           admin: models.User = Depends(require_pocket_platform_reader)):
    response.headers["Cache-Control"] = "no-store"
    t = models.TrialActivationCode
    rows = db.query(t.id, t.email, t.cabinet_name, t.trial_days,
                    t.expires_at, t.consumed_at, t.revoked_at, t.created_at).order_by(
        t.created_at.desc(), t.id.desc()).offset(offset).limit(limit).all()
    return [dict(row._mapping) for row in rows]


@router.get("/marketplace/overview")
def marketplace(response: Response,
                db: Session = Depends(database.get_db),
                admin: models.User = Depends(require_pocket_platform_reader)):
    response.headers["Cache-Control"] = "no-store"
    from backend.routers.partner_superadmin import overview
    return overview(db=db, admin=admin)


# Separate pilot mutation boundary: no changes to the reader dependency or Desktop routes.
# Desktop independently approves one exact target with its password. Pocket must still
# present the live UV session and independent platform approval at execution.
from datetime import datetime
import hashlib
import secrets
import uuid
from fastapi import HTTPException, Request
from jose import jwt
from pydantic import BaseModel, ConfigDict, Field, SecretStr, StrictBool
from backend.models_mobile_passkey import MobileWebAuthnChallenge
from backend.routers.auth import require_superadmin, is_superadmin_user
from backend.routers import mobile_legacy
from backend.routers.partner_superadmin_security import _enforce_marketplace_control_plane_request
from backend.security import verify_password
from backend.services.mobile_biometric import (
    assert_stable_webauthn_origin, require_platform_approval, credential_for_device,
    platform_credential_binding, require_bound_biometric_uv, b64url_encode, CHALLENGE_TTL,
)
from backend.services.platform_mutation_intent import PlatformMutationIntent
from backend.services.platform_mutation_transaction import stage_trial_revocation, MutationIntentRefused, PURPOSE
from backend.utils.rate_limit import check_rate_limit

class RevocationBinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: str = Field(min_length=36, max_length=36)
    approval_jti: str = Field(pattern=r"^[0-9a-f]{32}$")
    uv_jti_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    nonce: str = Field(pattern=r"^[0-9a-f]{64}$")

class DesktopRevocationApproval(RevocationBinding):
    password: SecretStr = Field(min_length=1, max_length=72)
    confirm: StrictBool

class RevocationExecution(BaseModel):
    model_config = ConfigDict(extra="forbid")
    challenge_id: str = Field(min_length=36, max_length=36)
    nonce: str = Field(pattern=r"^[0-9a-f]{64}$")
    confirm: StrictBool

def _active_trial(db, target_id):
    t = models.TrialActivationCode
    if db.query(t.id).filter(t.id == target_id, t.consumed_at.is_(None), t.revoked_at.is_(None)).first() is None:
        raise HTTPException(status_code=404, detail="Code d'essai indisponible.")

def _pocket_intent(request, db, target_id, nonce):
    assert_stable_webauthn_origin(request.headers.get("origin"))
    user, tenant, claims = mobile_legacy._decode_mobile_identity(request.headers.get("authorization", ""), db)
    if not is_superadmin_user(user):
        raise HTTPException(status_code=403, detail="Accès SuperAdmin requis.")
    device = str(claims.get("device_id") or "")
    credential = credential_for_device(db, user_id=user.id, employer_id=int(tenant), device_id=device)
    require_bound_biometric_uv(claims, credential, active=True)
    proof = request.headers.get("x-platform-approval", "")
    require_platform_approval(db, user_id=user.id, employer_id=int(tenant), device_id=device, proof=proof)
    # Only extract claims AFTER signature, expiry, binding and revocation validation.
    approval = jwt.get_unverified_claims(proof)
    intent = PlatformMutationIntent("trial-code.revoke", target_id, user.id, int(tenant), device,
        platform_credential_binding(credential), approval["jti"],
        hashlib.sha256(claims["jti"].encode()).hexdigest(), nonce)
    try:
        intent.digest()
    except (ValueError, TypeError):
        raise HTTPException(status_code=403, detail="Intention invalide.") from None
    return intent

@router.post("/trial-codes/{target_id}/revocation-intent")
def prepare_revocation(target_id: int, request: Request, response: Response, db: Session = Depends(database.get_db)):
    intent = _pocket_intent(request, db, target_id, secrets.token_hex(32))
    _active_trial(db, target_id)
    response.headers["Cache-Control"] = "no-store"
    return {"device_id": intent.device_id, "approval_jti": intent.approval_jti,
            "uv_jti_hash": intent.uv_jti, "nonce": intent.nonce}

@router.post("/trial-codes/{target_id}/desktop-approval")
def approve_revocation(target_id: int, body: DesktopRevocationApproval, request: Request,
                       response: Response, db: Session = Depends(database.get_db),
                       admin: models.User = Depends(require_superadmin)):
    _enforce_marketplace_control_plane_request(request, require_cookie_origin=True)
    check_rate_limit(request, scope="platform-trial-revocation-approval")
    if body.confirm is not True:
        raise HTTPException(status_code=409, detail="Confirmation explicite requise.")
    try:
        password_ok = verify_password(body.password.get_secret_value(), admin.hashed_password)
    except (ValueError, TypeError):
        password_ok = False
    if not password_ok:
        raise HTTPException(status_code=401, detail="Vérification Desktop refusée.")
    tenant = int(admin.get_employer_id())
    d = models.MobilePairedDevice
    device = db.query(d).filter(d.device_id == body.device_id, d.user_id == admin.id,
                                d.employer_id == tenant, d.revoked_at.is_(None)).first()
    credential = credential_for_device(db,user_id=admin.id,employer_id=tenant,device_id=body.device_id)
    if device is None or credential is None or credential.enabled_at is None:
        raise HTTPException(status_code=404, detail="Appareil indisponible.")
    _active_trial(db, target_id)
    intent = PlatformMutationIntent("trial-code.revoke", target_id, admin.id, tenant, body.device_id,
        platform_credential_binding(credential), body.approval_jti, body.uv_jti_hash, body.nonce)
    try:
        digest = b64url_encode(intent.digest())
    except (ValueError, TypeError):
        raise HTTPException(status_code=422, detail="Intention invalide.") from None
    now = datetime.utcnow()
    challenge_id = str(uuid.uuid4())
    try:
        db.query(MobileWebAuthnChallenge).filter(
            MobileWebAuthnChallenge.purpose == PURPOSE, MobileWebAuthnChallenge.user_id == admin.id,
            MobileWebAuthnChallenge.employer_id == tenant, MobileWebAuthnChallenge.device_id == body.device_id,
            MobileWebAuthnChallenge.used_at.is_(None),
        ).update({MobileWebAuthnChallenge.used_at: now}, synchronize_session=False)
        db.add(MobileWebAuthnChallenge(id=challenge_id, challenge_b64url=digest, purpose=PURPOSE,
            user_id=admin.id, employer_id=tenant, device_id=body.device_id, expires_at=now+CHALLENGE_TTL))
        db.add(models.AuditLog(user_id=admin.id, employer_id=tenant, action="PLATFORM_TRIAL_REVOCATION_APPROVED",
            resource_type="TrialActivationCode", resource_id=str(target_id), severity="CRITICAL",
            details="Desktop confirmed exact trial revocation; no authorization material logged."))
        db.commit()
    except Exception:
        db.rollback()
        raise
    response.headers["Cache-Control"] = "no-store"
    return {"challenge_id": challenge_id, "expires_in": int(CHALLENGE_TTL.total_seconds())}

@router.post("/trial-codes/{target_id}/revoke")
def execute_revocation(target_id: int, body: RevocationExecution, request: Request,
                       response: Response, db: Session = Depends(database.get_db)):
    if body.confirm is not True:
        raise HTTPException(status_code=409, detail="Confirmation explicite requise.")
    intent = _pocket_intent(request, db, target_id, body.nonce)
    try:
        stage_trial_revocation(db, intent=intent, challenge_id=body.challenge_id)
        db.commit()
    except MutationIntentRefused:
        db.rollback()
        raise HTTPException(status_code=409, detail="Autorisation ou cible indisponible.") from None
    except Exception:
        db.rollback()
        raise
    response.headers["Cache-Control"] = "no-store"
    return {"revoked": True}
