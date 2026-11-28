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
