"""Unexposed transaction building block for an already authenticated intent.

No API calls this module yet. Caller must validate live SuperAdmin authority,
UV and independent approval, construct the exact intent from verified claims,
and own a transaction which rolls back on every error. No commit here.
"""
from datetime import datetime
from sqlalchemy.orm import Session
from backend import models
from backend.models_mobile_passkey import MobileWebAuthnChallenge
from backend.services.mobile_biometric import b64url_encode
from backend.services.platform_mutation_intent import PlatformMutationIntent

PURPOSE = "platform_mutation"

class MutationIntentRefused(Exception):
    pass

def stage_trial_revocation(db: Session, *, intent: PlatformMutationIntent, challenge_id: str) -> None:
    if intent.action != "trial-code.revoke":
        raise MutationIntentRefused("action refused")
    now = datetime.utcnow()
    digest = b64url_encode(intent.digest())
    consumed = db.query(MobileWebAuthnChallenge).filter(
        MobileWebAuthnChallenge.id == challenge_id,
        MobileWebAuthnChallenge.purpose == PURPOSE,
        MobileWebAuthnChallenge.user_id == intent.actor_id,
        MobileWebAuthnChallenge.employer_id == intent.tenant_id,
        MobileWebAuthnChallenge.device_id == intent.device_id,
        MobileWebAuthnChallenge.challenge_b64url == digest,
        MobileWebAuthnChallenge.used_at.is_(None),
        MobileWebAuthnChallenge.expires_at > now,
    ).update({MobileWebAuthnChallenge.used_at: now}, synchronize_session=False)
    if consumed != 1:
        raise MutationIntentRefused("intent refused")
    changed = db.query(models.TrialActivationCode).filter(
        models.TrialActivationCode.id == intent.target_id,
        models.TrialActivationCode.consumed_at.is_(None),
        models.TrialActivationCode.revoked_at.is_(None),
    ).update({models.TrialActivationCode.revoked_at: now}, synchronize_session=False)
    if changed != 1:
        raise MutationIntentRefused("target refused")
    db.add(models.AuditLog(user_id=intent.actor_id, employer_id=intent.tenant_id,
                          action="PLATFORM_TRIAL_REVOKED", resource_type="TrialActivationCode",
                          resource_id=str(intent.target_id), severity="CRITICAL",
                          details="Scoped platform mutation; authorization material not logged."))
    db.flush()
