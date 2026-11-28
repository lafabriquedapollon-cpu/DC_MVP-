"""M6-I — WebAuthn/passkey biometric step-up for paired mobile devices."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend import database, models
from backend.models_mobile_passkey import MobilePasskeyCredential, MobileWebAuthnChallenge
from backend.routers import mobile_legacy as _legacy
from backend.services.mobile_biometric import (
    WEBAUTHN_ORIGIN,
    WEBAUTHN_RP_ID,
    WEBAUTHN_RP_NAME,
    assert_stable_webauthn_origin,
    b64url_decode,
    b64url_encode,
    consume_challenge,
    credential_for_device,
    credential_uv_binding,
    require_bound_biometric_uv,
    issue_biometric_access_token,
    issue_platform_transfer,
    claim_platform_transfer,
    issue_challenge,
    opaque_user_handle,
    payload_has_biometric_uv,
)
from backend.services.mobile_mdns import start_mdns_if_secure, stop_mdns
from backend.security import token_blacklist, verify_password
from backend.routers.auth import require_superadmin, is_superadmin_user
from backend.services.audit_service import audit_service
from backend.utils.rate_limit import check_rate_limit

router = APIRouter(
    tags=["Mobile Passkey"],
    on_startup=[start_mdns_if_secure],
    on_shutdown=[stop_mdns],
)


class CeremonyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    challenge_id: str = Field(min_length=36, max_length=36)
    credential: dict[str, Any]


class PlatformApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: str = Field(min_length=36, max_length=36)
    credential_id: str = Field(min_length=8, max_length=1024)
    password: SecretStr = Field(min_length=1, max_length=72)
    confirm: bool


class PlatformTransferClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ticket: SecretStr = Field(min_length=80, max_length=80)


class EnablePasskeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    credential_id: str = Field(min_length=8, max_length=1024)


def _base_mobile_identity(authorization: str, db: Session):
    decoder = getattr(_legacy, "_m6i_base_decode_mobile_identity", _legacy._decode_mobile_identity)
    return decoder(authorization, db)


def _identity(authorization: str, db: Session, *, require_uv: bool = False):
    user, tenant_id, payload = _base_mobile_identity(authorization, db)
    device_id = str(payload.get("device_id") or "")
    if not device_id:
        raise HTTPException(status_code=401, detail="Session mobile non appairée.")
    if require_uv or payload_has_biometric_uv(payload):
        credential = credential_for_device(db, user_id=user.id, employer_id=tenant_id, device_id=device_id)
        # Pending UV grants may only reach the passkey ceremony boundary.
        require_bound_biometric_uv(payload, credential, active=False)
    return user, int(tenant_id), device_id, payload


def _origin(request: Request) -> str | None:
    return request.headers.get("origin")


def _enum_value(value: Any) -> str:
    return str(getattr(value, "value", value))


def _options_payload(options, *, challenge_id: str) -> dict[str, Any]:
    from webauthn import options_to_json

    payload = json.loads(options_to_json(options))
    payload["challenge_id"] = challenge_id
    return payload


def install_stable_lan_url_overrides() -> None:
    """Route new pairing QR discovery through the exact stable WebAuthn frontend origin."""
    import os

    secure = os.getenv("DIGITALCROWN_ENABLE_HTTPS", "false").strip().lower() in {"1", "true", "yes", "on"}
    if not secure:
        return
    _legacy.get_lan_base_url = lambda: WEBAUTHN_ORIGIN
    _legacy.get_lan_frontend_url = lambda: WEBAUTHN_ORIGIN


@router.get("/passkey/platform-devices", summary="Appareils personnels autorisables par le SuperAdmin Desktop")
def platform_devices(response: Response, db: Session = Depends(database.get_db),
                     admin: models.User = Depends(require_superadmin)):
    tenant_id = admin.get_employer_id()
    c = MobilePasskeyCredential
    d = models.MobilePairedDevice
    rows = db.query(c.device_id, c.credential_id, c.enabled_at, d.last_seen_at).join(
        d, d.device_id == c.device_id
    ).filter(
        c.user_id == admin.id, c.employer_id == tenant_id,
        d.user_id == admin.id, d.employer_id == tenant_id, d.revoked_at.is_(None),
        c.enabled_at.is_not(None), c.last_used_at.is_not(None),
    ).order_by(c.enabled_at.desc(), c.device_id).limit(200).all()
    response.headers["Cache-Control"] = "no-store"
    return [dict(row._mapping) for row in rows]


@router.get("/passkey/platform-eligibility", summary="Vérifier l'identité plateforme Pocket avant autorisation")
def platform_eligibility(response: Response, authorization: str = Header(...),
                         db: Session = Depends(database.get_db)):
    user, tenant_id, payload = _legacy._decode_mobile_identity(authorization, db)
    if not is_superadmin_user(user):
        raise HTTPException(status_code=403, detail="Accès SuperAdmin requis.")
    credential = credential_for_device(db, user_id=user.id, employer_id=tenant_id,
                                       device_id=str(payload.get("device_id") or ""))
    require_bound_biometric_uv(payload, credential, active=True)
    response.headers["Cache-Control"] = "no-store"
    return {"eligible": True}


@router.post("/passkey/platform-approval", summary="Autorisation Desktop indépendante d'une passkey SuperAdmin")
def approve_platform_passkey(
    body: PlatformApprovalRequest,
    request: Request,
    response: Response,
    db: Session = Depends(database.get_db),
    admin: models.User = Depends(require_superadmin),
):
    # Desktop identity/Station is resolved by the canonical desktop dependency.
    # Cookie-based mutations must also satisfy the existing control-plane policy.
    from backend.routers.partner_superadmin_security import _enforce_marketplace_control_plane_request
    _enforce_marketplace_control_plane_request(request, require_cookie_origin=True)
    check_rate_limit(request, scope="platform-passkey-approval")
    if body.confirm is not True:
        raise HTTPException(status_code=409, detail="Confirmation explicite requise.")
    try:
        password_ok = verify_password(body.password.get_secret_value(), admin.hashed_password)
    except (ValueError, TypeError):
        password_ok = False
    if not password_ok:
        raise HTTPException(status_code=401, detail="Vérification Desktop refusée.")
    tenant_id = admin.get_employer_id()
    device = db.query(models.MobilePairedDevice).filter(
        models.MobilePairedDevice.device_id == body.device_id,
        models.MobilePairedDevice.user_id == admin.id,
        models.MobilePairedDevice.employer_id == tenant_id,
        models.MobilePairedDevice.revoked_at.is_(None),
    ).first()
    credential = credential_for_device(db, user_id=admin.id, employer_id=tenant_id, device_id=body.device_id)
    if device is None or credential is None or credential.credential_id != body.credential_id:
        raise HTTPException(status_code=404, detail="Appareil ou passkey introuvable.")
    ticket, expires_in = issue_platform_transfer(db, credential)
    if audit_service.log(db=db, user_id=admin.id, employer_id=tenant_id,
                         action="PLATFORM_PASSKEY_APPROVED", resource_type="MobilePairedDevice",
                         resource_id=device.device_id, severity="CRITICAL",
                         details="Autorisation Desktop indépendante de la passkey active.") is not True:
        raise HTTPException(status_code=503, detail="Audit de l'autorisation indisponible.")
    response.headers["Cache-Control"] = "no-store"
    return {"ticket": ticket, "expires_in": expires_in}


@router.post("/passkey/platform-approval/claim", summary="Échanger le ticket Desktop sur le Pocket vérifié")
def claim_platform_passkey(body: PlatformTransferClaim, request: Request, response: Response,
                           authorization: str = Header(...), db: Session = Depends(database.get_db)):
    assert_stable_webauthn_origin(_origin(request))
    user, tenant_id, payload = _legacy._decode_mobile_identity(authorization, db)
    if not is_superadmin_user(user):
        raise HTTPException(status_code=403, detail="Accès SuperAdmin requis.")
    device_id = str(payload.get("device_id") or "")
    credential = credential_for_device(db, user_id=user.id, employer_id=tenant_id, device_id=device_id)
    require_bound_biometric_uv(payload, credential, active=True)
    proof, expires_in = claim_platform_transfer(db, credential=credential, ticket=body.ticket.get_secret_value())
    if audit_service.log(db=db, user_id=user.id, employer_id=tenant_id,
                         action="PLATFORM_PASSKEY_CLAIMED", resource_type="MobilePairedDevice",
                         resource_id=device_id, severity="CRITICAL",
                         details="Ticket Desktop consommé par le Pocket biométrique.") is not True:
        raise HTTPException(status_code=503, detail="Audit du transfert indisponible.")
    response.headers["Cache-Control"] = "no-store"
    return {"approval": proof, "expires_in": expires_in}


@router.get("/passkey/status", summary="État du verrou biométrique de l'appareil")
def passkey_status(
    request: Request,
    authorization: str = Header(...),
    db: Session = Depends(database.get_db),
):
    user, tenant_id, device_id, _payload = _identity(authorization, db)
    credential = credential_for_device(
        db, user_id=user.id, employer_id=tenant_id, device_id=device_id
    )
    origin = (_origin(request) or "").rstrip("/").lower()
    state = "disabled"
    credential_id = None
    if credential is not None:
        credential_id = credential.credential_id
        state = "enabled" if credential.enabled_at is not None else "pending"
    return {
        "state": state,
        "credential_id": credential_id,
        "rp_id": WEBAUTHN_RP_ID,
        "expected_origin": WEBAUTHN_ORIGIN,
        "origin_ready": origin == WEBAUTHN_ORIGIN.lower(),
        "user_verification": "required",
        "server_gate": state == "enabled",
    }


@router.post("/passkey/registration/options", summary="Préparer l'enrôlement passkey")
def registration_options(
    request: Request,
    authorization: str = Header(...),
    db: Session = Depends(database.get_db),
):
    assert_stable_webauthn_origin(_origin(request))
    user, tenant_id, device_id, _payload = _identity(authorization, db)
    existing = credential_for_device(db, user_id=user.id, employer_id=tenant_id, device_id=device_id)
    if existing is not None:
        if existing.enabled_at is not None:
            raise HTTPException(
                status_code=423,
                detail={
                    "code": "PASSKEY_REPLACEMENT_REQUIRES_DISABLE",
                    "message": "Désactivez d'abord la passkey actuelle après vérification biométrique.",
                },
            )
        raise HTTPException(
            status_code=409,
            detail={"code": "PASSKEY_ENROLLMENT_PENDING", "message": "Un enrôlement passkey est déjà en attente."},
        )

    from webauthn import generate_registration_options
    from webauthn.helpers.structs import (
        AuthenticatorAttachment,
        AuthenticatorSelectionCriteria,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )

    options = generate_registration_options(
        rp_id=WEBAUTHN_RP_ID,
        rp_name=WEBAUTHN_RP_NAME,
        user_id=opaque_user_handle(user_id=user.id, employer_id=tenant_id, device_id=device_id),
        user_name=f"user-{user.id}",
        user_display_name=user.nom_complet or "Utilisateur Digital Crown",
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        timeout=60000,
    )
    challenge_id = issue_challenge(
        db,
        purpose="register",
        user_id=user.id,
        employer_id=tenant_id,
        device_id=device_id,
        challenge=options.challenge,
    )
    return _options_payload(options, challenge_id=challenge_id)


@router.post("/passkey/registration/verify", summary="Vérifier et stocker une passkey pending")
def registration_verify(
    request: Request,
    body: CeremonyResponse,
    authorization: str = Header(...),
    db: Session = Depends(database.get_db),
):
    assert_stable_webauthn_origin(_origin(request))
    user, tenant_id, device_id, _payload = _identity(authorization, db)
    if credential_for_device(db, user_id=user.id, employer_id=tenant_id, device_id=device_id) is not None:
        raise HTTPException(status_code=409, detail="Une passkey existe déjà pour cet appareil.")

    expected_challenge = consume_challenge(
        db,
        challenge_id=body.challenge_id,
        purpose="register",
        user_id=user.id,
        employer_id=tenant_id,
        device_id=device_id,
    )
    try:
        from webauthn import verify_registration_response
        from webauthn.helpers.exceptions import InvalidRegistrationResponse

        verification = verify_registration_response(
            credential=body.credential,
            expected_challenge=expected_challenge,
            expected_rp_id=WEBAUTHN_RP_ID,
            expected_origin=WEBAUTHN_ORIGIN,
            require_user_verification=True,
        )
    except InvalidRegistrationResponse as exc:
        raise HTTPException(status_code=400, detail="Réponse WebAuthn d'enrôlement invalide.") from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Enrôlement WebAuthn impossible.") from exc

    credential_id = b64url_encode(verification.credential_id)
    response = body.credential.get("response") if isinstance(body.credential, dict) else None
    transports = response.get("transports", []) if isinstance(response, dict) else []
    transports = [str(value)[:32] for value in transports[:8] if isinstance(value, str)]
    row = MobilePasskeyCredential(
        credential_id=credential_id,
        user_id=user.id,
        employer_id=tenant_id,
        device_id=device_id,
        credential_public_key=b64url_encode(verification.credential_public_key),
        sign_count=int(verification.sign_count),
        transports=transports,
        credential_device_type=_enum_value(verification.credential_device_type),
        credential_backed_up=bool(verification.credential_backed_up),
        created_at=datetime.utcnow(),
        enabled_at=None,
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Une passkey existe déjà pour cet appareil.") from exc
    return {"state": "pending", "credential_id": credential_id, "user_verified": True}


@router.delete("/passkey/pending", summary="Annuler un enrôlement passkey non activé")
def reset_pending_passkey(
    authorization: str = Header(...),
    db: Session = Depends(database.get_db),
):
    user, tenant_id, device_id, _payload = _identity(authorization, db)
    row = credential_for_device(db, user_id=user.id, employer_id=tenant_id, device_id=device_id)
    if row is None:
        return {"state": "disabled"}
    if row.enabled_at is not None:
        raise HTTPException(status_code=423, detail="Une passkey active ne peut pas être remplacée sans désactivation UV.")
    db.delete(row)
    db.query(MobileWebAuthnChallenge).filter(
        MobileWebAuthnChallenge.user_id == user.id,
        MobileWebAuthnChallenge.employer_id == tenant_id,
        MobileWebAuthnChallenge.device_id == device_id,
    ).delete(synchronize_session=False)
    db.commit()
    return {"state": "disabled"}


@router.post("/passkey/authentication/options", summary="Préparer un déverrouillage passkey")
def authentication_options(
    request: Request,
    authorization: str = Header(...),
    db: Session = Depends(database.get_db),
):
    assert_stable_webauthn_origin(_origin(request))
    user, tenant_id, device_id, _payload = _identity(authorization, db)
    credential = credential_for_device(db, user_id=user.id, employer_id=tenant_id, device_id=device_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="Aucune passkey liée à cet appareil.")

    from webauthn import generate_authentication_options
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement

    options = generate_authentication_options(
        rp_id=WEBAUTHN_RP_ID,
        allow_credentials=[PublicKeyCredentialDescriptor(id=b64url_decode(credential.credential_id))],
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=60000,
    )
    challenge_id = issue_challenge(
        db,
        purpose="authenticate",
        user_id=user.id,
        employer_id=tenant_id,
        device_id=device_id,
        challenge=options.challenge,
    )
    payload = _options_payload(options, challenge_id=challenge_id)
    payload["credential_state"] = "enabled" if credential.enabled_at is not None else "pending"
    return payload


@router.post("/passkey/authentication/verify", summary="Vérifier la passkey et émettre une session UV courte")
def authentication_verify(
    request: Request,
    body: CeremonyResponse,
    authorization: str = Header(...),
    db: Session = Depends(database.get_db),
):
    assert_stable_webauthn_origin(_origin(request))
    user, tenant_id, device_id, _payload = _identity(authorization, db)
    credential = credential_for_device(db, user_id=user.id, employer_id=tenant_id, device_id=device_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="Aucune passkey liée à cet appareil.")

    expected_challenge = consume_challenge(
        db,
        challenge_id=body.challenge_id,
        purpose="authenticate",
        user_id=user.id,
        employer_id=tenant_id,
        device_id=device_id,
    )
    try:
        from webauthn import verify_authentication_response
        from webauthn.helpers.exceptions import InvalidAuthenticationResponse

        verification = verify_authentication_response(
            credential=body.credential,
            expected_challenge=expected_challenge,
            expected_rp_id=WEBAUTHN_RP_ID,
            expected_origin=WEBAUTHN_ORIGIN,
            credential_public_key=b64url_decode(credential.credential_public_key),
            credential_current_sign_count=int(credential.sign_count),
            require_user_verification=True,
        )
    except InvalidAuthenticationResponse as exc:
        raise HTTPException(status_code=401, detail="Vérification biométrique refusée.") from exc
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Vérification biométrique impossible.") from exc

    if b64url_encode(verification.credential_id) != credential.credential_id:
        raise HTTPException(status_code=401, detail="Passkey incompatible avec cet appareil.")
    credential.sign_count = int(verification.new_sign_count)
    credential.last_used_at = datetime.utcnow()
    credential.credential_device_type = _enum_value(verification.credential_device_type)
    credential.credential_backed_up = bool(verification.credential_backed_up)
    # Snapshot the verified record and revocation generation before commit.
    # A concurrent re-enrollment or new ceremony invalidates this binding.
    binding = credential_uv_binding(credential)
    epoch = _payload.get("mobile_epoch") or token_blacklist.current_mobile_epoch(tenant_id, db)
    db.commit()

    access_token, expires_in = issue_biometric_access_token(
        user=user, employer_id=tenant_id, device_id=device_id, binding=binding, mobile_epoch=epoch
    )
    return {
        "access_token": access_token,
        "expires_in": expires_in,
        "credential_id": credential.credential_id,
        "credential_state": "enabled" if credential.enabled_at is not None else "pending",
        "user_verified": bool(verification.user_verified),
    }


@router.post("/passkey/enable", summary="Activer le gate biométrique après scellement local")
def enable_passkey(
    body: EnablePasskeyRequest,
    authorization: str = Header(...),
    db: Session = Depends(database.get_db),
):
    user, tenant_id, device_id, _payload = _identity(authorization, db, require_uv=True)
    credential = credential_for_device(db, user_id=user.id, employer_id=tenant_id, device_id=device_id)
    if credential is None or credential.credential_id != body.credential_id:
        raise HTTPException(status_code=404, detail="Passkey pending introuvable.")
    if credential.enabled_at is None:
        credential.enabled_at = datetime.utcnow()
        db.commit()
    return {"state": "enabled", "credential_id": credential.credential_id}


@router.delete("/passkey", summary="Désactiver la passkey après step-up biométrique")
def disable_passkey(
    authorization: str = Header(...),
    db: Session = Depends(database.get_db),
):
    user, tenant_id, device_id, _payload = _identity(authorization, db, require_uv=True)
    credential = credential_for_device(db, user_id=user.id, employer_id=tenant_id, device_id=device_id)
    if credential is None:
        return {"state": "disabled"}
    db.delete(credential)
    db.query(MobileWebAuthnChallenge).filter(
        MobileWebAuthnChallenge.user_id == user.id,
        MobileWebAuthnChallenge.employer_id == tenant_id,
        MobileWebAuthnChallenge.device_id == device_id,
    ).delete(synchronize_session=False)
    db.commit()
    return {"state": "disabled"}