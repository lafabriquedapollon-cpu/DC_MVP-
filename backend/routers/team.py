"""
Routes de gestion d'equipe — M1 : quotas abonnement + workflow approbation.

Plans :
  GOLD    : 1 dentiste total (owner) + 2 assistantes
  PREMIUM : 2 dentistes total + 6 assistantes
  ELITE   : illimite (clinique)

Workflow :
  create  -> approval_status=pending, is_active=False
  approve -> approval_status=approved, is_active=True
  reject  -> approval_status=rejected, is_active=False

Pending + approved comptent dans le quota (evite le gaming).
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func, update

from backend import models, schemas, database
from backend.routers.auth import get_current_user, is_superadmin_user
from backend.security import get_password_hash
from backend.services.subscription_policy import (
    TEAM_LIMITS,
    count_reserved_team_usage,
    exceeds_limit,
    get_team_limits,
    is_limit_reached,
    normalize_plan,
)

router = APIRouter(tags=["Team Management"])

ALLOWED_TEAM_PERMISSIONS = {
    "agenda",
    "patients",
    "stock_write",
    "prescriptions",
    "accounting",
    "payments",
    "clinical",
    "panoramic",
    "cephalo",
    "settings",
}


def sanitize_permissions(permissions: dict | None, defaults: dict) -> dict:
    source = permissions if permissions is not None else defaults
    return {key: bool(source.get(key, False)) for key in ALLOWED_TEAM_PERMISSIONS}


# --- DEPENDANCE RBAC : Praticien uniquement ---

def require_employer(current_user: models.User = Depends(get_current_user)) -> models.User:
    """Bloque l'acces aux sous-comptes (SECRETAIRE) pour les operations de gestion d'equipe."""
    if is_superadmin_user(current_user):
        return current_user
    if current_user.role not in [models.UserRole.ADMIN, models.UserRole.DENTISTE] or current_user.employer_id is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acces reserve au praticien principal."
        )
    return current_user


# --- HELPERS QUOTA ---

def _get_plan(owner: models.User) -> str:
    return normalize_plan(getattr(owner, "subscription_plan", None))


class _QuotaCount(int):
    """Compatibilite temporaire pour les consommateurs legacy du dashboard.

    La policy canonique utilise None pour une limite illimitee. Le dashboard
    historique compare encore directement `used >= limit`; cette sous-classe
    preserve cette comparaison sans reinjecter un faux plafond comme 999.
    """

    def __new__(cls, value: int):
        return super().__new__(cls, value)

    def __add__(self, other):
        return _QuotaCount(int(self) + int(other))

    def __radd__(self, other):
        return _QuotaCount(int(other) + int(self))

    def __ge__(self, other):
        if other is None:
            return False
        return super().__ge__(other)


# Surface legacy derivee exclusivement de la policy canonique.
# Ne jamais dupliquer de limites commerciales ici.
PLAN_QUOTAS = {
    plan: {
        "dentistes": limits.dentists,
        "secretaires": limits.secretaries,
    }
    for plan, limits in TEAM_LIMITS.items()
}


def _count_team(db: Session, employer_id: int) -> dict:
    """Adapte le comptage canonique au contrat historique du dashboard."""
    usage = count_reserved_team_usage(db, employer_id)
    return {
        "dentistes": _QuotaCount(max(0, usage.dentists - 1)),
        "secretaires": _QuotaCount(usage.secretaries),
        "pending": usage.pending,
    }


def _build_quota(owner: models.User, db: Session) -> schemas.QuotaOut:
    plan = _get_plan(owner)
    limits = get_team_limits(plan)
    usage = count_reserved_team_usage(db, owner.id)

    return schemas.QuotaOut(
        plan=plan,
        dentistes_used=usage.dentists,
        dentistes_max=limits.dentists,
        secretaires_used=usage.secretaries,
        secretaires_max=limits.secretaries,
        pending_count=usage.pending,
        can_add_dentiste=not is_limit_reached(usage.dentists, limits.dentists),
        can_add_secretaire=not is_limit_reached(usage.secretaries, limits.secretaries),
    )


# --- CRUD SOUS-COMPTES ---

@router.get("/quota", response_model=schemas.QuotaOut)
def get_team_quota(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_employer),
):
    """Retourne les quotas du cabinet (plan, utilisation, disponibilite)."""
    return _build_quota(current_user, db)


@router.get("/", response_model=List[schemas.TeamMemberOut])
def list_team_members(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_employer),
):
    """Liste les membres de l'equipe rattaches au praticien connecte."""
    members = db.query(models.User).filter(
        models.User.employer_id == current_user.id
    ).order_by(models.User.created_at.desc()).all()
    return members


@router.post("/", response_model=schemas.TeamMemberOut, status_code=status.HTTP_201_CREATED)
def create_team_member(
    member: schemas.TeamMemberCreate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_employer),
):
    """Cree un sous-compte (statut pending — doit etre approuve par le praticien)."""
    normalized_email = member.email.lower()
    existing = db.query(models.User).filter(func.lower(models.User.email) == normalized_email).first()
    if existing:
        if existing.employer_id == current_user.id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Compte archive : cette adresse est conservee pour la tracabilite." if existing.is_archived else
                    "Ce collaborateur existe deja dans votre equipe. Utilisez la liste des membres pour le reactiver ou modifier ses droits."
                )
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"L'email '{member.email}' est deja utilise par un autre compte.",
        )

    quota = _build_quota(current_user, db)
    target_role = models.UserRole.DENTISTE if member.role == "DENTISTE" else models.UserRole.SECRETAIRE

    if target_role == models.UserRole.DENTISTE and not quota.can_add_dentiste:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=(
                f"Quota dentistes atteint ({quota.dentistes_used}/{quota.dentistes_max}) "
                f"pour le plan {quota.plan}. Passez au plan superieur pour ajouter un dentiste."
            ),
        )
    if target_role == models.UserRole.SECRETAIRE and not quota.can_add_secretaire:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=(
                f"Quota assistantes atteint ({quota.secretaires_used}/{quota.secretaires_max}) "
                f"pour le plan {quota.plan}. Passez au plan superieur pour ajouter une assistante."
            ),
        )

    default_permissions = {
        "agenda": True, "patients": True, "stock_write": False, "prescriptions": False,
        "accounting": False, "payments": False, "clinical": False,
        "panoramic": False, "cephalo": False, "settings": False,
    }
    if member.role == "DENTISTE":
        default_permissions = {
            "agenda": True, "patients": True, "stock_write": True, "prescriptions": True,
            "accounting": True, "payments": True, "clinical": True,
            "panoramic": True, "cephalo": True, "settings": False,
        }
    user_perms = sanitize_permissions(member.permissions, default_permissions)

    new_user = models.User(
        email=normalized_email,
        hashed_password=get_password_hash(member.password),
        role=target_role,
        nom_complet=member.nom_complet,
        telephone_mobile=member.telephone_mobile,
        employer_id=current_user.id,
        is_active=False,
        approval_status="pending",
        permissions=user_perms,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


def _write_unarchived_member(db: Session, member: models.User, values: dict, *, action: str, expected_approval=None):
    # Check archive state at the actual SQL write, not only at the earlier read.
    stmt = update(models.User).where(
        models.User.id == member.id,
        models.User.employer_id == member.employer_id,
        models.User.is_archived.is_(False),
    )
    if expected_approval is not None:
        stmt = stmt.where(models.User.approval_status == expected_approval)
    result = db.execute(stmt.values(**values).execution_options(
        synchronize_session=False, dc_team_mutation=action,
    ))
    if result.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=409, detail="Compte archive ou modifie concurremment.")
    db.commit()
    db.refresh(member)
    return member


@router.post("/{member_id}/approve", response_model=schemas.TeamMemberOut)
def approve_team_member(
    member_id: int,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_employer),
):
    """Approuve un membre en attente — active le compte."""
    member = db.query(models.User).filter(
        models.User.id == member_id,
        models.User.employer_id == current_user.id,
    ).first()
    if not member:
        raise HTTPException(status_code=404, detail="Membre introuvable dans votre equipe.")
    if member.is_archived:
        raise HTTPException(status_code=409, detail="Compte archive : reactivation interdite.")
    if getattr(member, "approval_status", "approved") != "pending":
        raise HTTPException(status_code=400, detail="Ce membre n'est pas en attente d'approbation.")

    # Pending members already reserve their seat. Approval must therefore
    # reject only an existing over-quota state, not a usage equal to the cap.
    plan = _get_plan(current_user)
    limits = get_team_limits(plan)
    usage = count_reserved_team_usage(db, current_user.id)
    if member.role == models.UserRole.DENTISTE:
        role_label = "dentistes"
        role_used = usage.dentists
        role_limit = limits.dentists
    else:
        role_label = "secretaires"
        role_used = usage.secretaries
        role_limit = limits.secretaries

    if exceeds_limit(role_used, role_limit):
        raise HTTPException(
            status_code=402,
            detail=f"Quota {role_label} depasse ({role_used}/{role_limit}) pour le plan {plan}. Passez a un plan superieur.",
        )

    return _write_unarchived_member(
        db, member, {"approval_status": "approved", "is_active": True},
        action="approve", expected_approval="pending",
    )


@router.post("/{member_id}/reject", response_model=schemas.TeamMemberOut)
def reject_team_member(
    member_id: int,
    note: Optional[str] = None,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_employer),
):
    """Refuse un membre en attente. Note optionnelle transmise au compte."""
    member = db.query(models.User).filter(
        models.User.id == member_id,
        models.User.employer_id == current_user.id,
    ).first()
    if not member:
        raise HTTPException(status_code=404, detail="Membre introuvable dans votre equipe.")
    if getattr(member, "approval_status", "approved") not in ("pending", "approved"):
        raise HTTPException(status_code=400, detail="Ce membre est deja refuse.")

    return _write_unarchived_member(
        db, member, {"approval_status": "rejected", "is_active": False, "approval_note": note},
        action="reject", expected_approval=member.approval_status,
    )


@router.put("/{member_id}", response_model=schemas.TeamMemberOut)
def update_team_member(
    member_id: int,
    updates: schemas.TeamMemberUpdate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_employer),
):
    """Met a jour un sous-compte existant (nom, email, statut, mot de passe, permissions)."""
    member = db.query(models.User).filter(
        models.User.id == member_id,
        models.User.employer_id == current_user.id,
    ).first()
    if not member:
        raise HTTPException(status_code=404, detail="Membre introuvable dans votre equipe.")

    if member.is_archived:
        raise HTTPException(status_code=409, detail="Compte archive : modification interdite.")

    values = {}
    if updates.nom_complet is not None:
        values["nom_complet"] = updates.nom_complet
    if updates.email is not None:
        normalized_email = updates.email.lower()
        conflict = db.query(models.User).filter(
            func.lower(models.User.email) == normalized_email,
            models.User.id != member_id,
        ).first()
        if conflict:
            raise HTTPException(status_code=409, detail=f"L'email '{updates.email}' est deja utilise.")
        values["email"] = normalized_email
    if updates.telephone_mobile is not None:
        values["telephone_mobile"] = updates.telephone_mobile
    if updates.is_active is not None:
        approval_status = getattr(member, "approval_status", "approved") or "approved"
        if updates.is_active and approval_status != "approved":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Ce compte ne peut pas etre reactive tant que son statut "
                    "d'approbation n'est pas 'approved'."
                ),
            )
        values["is_active"] = updates.is_active
    if updates.new_password is not None:
        values["hashed_password"] = get_password_hash(updates.new_password)
    if updates.permissions is not None:
        values["permissions"] = sanitize_permissions(updates.permissions, member.permissions or {})

    if not values:
        return member
    return _write_unarchived_member(
        db, member, values, action="update",
        expected_approval=member.approval_status if updates.is_active is True else None,
    )


@router.delete("/{member_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_team_member(
    member_id: int,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(require_employer),
):
    """Archive le sous-compte et revoque son acces sans supprimer son historique."""
    member = db.query(models.User).filter(
        models.User.id == member_id,
        models.User.employer_id == current_user.id,
    ).first()
    if not member:
        raise HTTPException(status_code=404, detail="Membre introuvable dans votre equipe.")

    # Preserve historical principal and clinical/financial references.
    # Rejected members no longer reserve a seat; archived addresses remain reserved.
    # Explicitly write all three values even when the stale ORM snapshot
    # already shows one of them (e.g. pending/inactive before approval).
    db.execute(update(models.User).where(
        models.User.id == member_id, models.User.employer_id == current_user.id,
    ).values(is_active=False, is_archived=True, approval_status="rejected")
        .execution_options(synchronize_session=False, dc_team_mutation="archive"))
    db.commit()
