"""CI-only synthetic fixture provisioning and post-restart verification."""
import os
import pathlib
import sys

from backend.config import settings
from backend.core.runtime_safety import (
    REHEARSAL_MIGRATION_ONLY, assert_runtime_startup_allowed,
)
from backend.core.schema_runtime import assert_database_at_current_head


def main():
    lab = pathlib.Path(os.environ["DC_LAB_ROOT"]).resolve(strict=True)
    path = lab / "fresh-rehearsal.db"
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or settings.ENVIRONMENT != "e2e_install_rehearsal"
        or lab.parent != pathlib.Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        or settings.DATABASE_URL != f"sqlite:///{path}"
        or not path.is_file() or path.is_symlink()
        or assert_runtime_startup_allowed(settings) != REHEARSAL_MIGRATION_ONLY
    ):
        raise RuntimeError("Synthetic CI scope required")
    from backend.main import app
    from backend import database, models
    from sqlalchemy import select, func
    assert app is not None and database.engine.dialect.driver == "pysqlcipher"
    assert_database_at_current_head(database.engine)
    with database.SessionLocal() as db:
        if sys.argv[1:] == ["seed"]:
            assert db.scalar(select(func.count()).select_from(models.User)) == 0
            assert db.scalar(select(func.count()).select_from(models.Patient)) == 0
            # Validate fixture addresses with the actual response schema before DB writes.
            from backend.schemas.auth import UserOut
            for address in ("ci-owner@example.com", "ci-other@example.com", "ci-restricted@example.com"):
                UserOut(id=1, email=address, role="DENTISTE")
            password_hash = database.pwd_context.hash(os.environ["DC_SYNTH_PASSWORD"])
            owner = models.User(
                email="ci-owner@example.com", hashed_password=password_hash,
                role=models.UserRole.DENTISTE, is_active=True, is_licensed=True,
                nom_complet="CI Synthetic Owner",
            )
            other = models.User(
                email="ci-other@example.com", hashed_password=password_hash,
                role=models.UserRole.DENTISTE, is_active=True, is_licensed=True,
                nom_complet="CI Synthetic Other",
            )
            assert settings.SUPERADMIN_EMAIL == "ci-platform-admin@example.com"
            UserOut(id=1, email=settings.SUPERADMIN_EMAIL, role="ADMIN")
            platform = models.User(
                email=settings.SUPERADMIN_EMAIL, hashed_password=password_hash,
                role=models.UserRole.ADMIN, is_active=True, is_licensed=True,
                nom_complet="CI Synthetic Platform Admin",
            )
            db.add_all([owner, other, platform])
            db.flush()
            restricted = models.User(
                email="ci-restricted@example.com", hashed_password=password_hash,
                role=models.UserRole.SECRETAIRE, is_active=True, is_licensed=True,
                employer_id=owner.id, permissions={"patients": False},
                nom_complet="CI Synthetic Restricted",
            )
            db.add(restricted)
            for address, grants in (
                ("ci-stock-reader@example.com", {"agenda": True, "patients": True, "stock_write": False}),
                ("ci-stock-writer@example.com", {"agenda": True, "patients": True, "stock_write": True}),
            ):
                UserOut(id=1, email=address, role="SECRETAIRE")
                db.add(models.User(
                    email=address, hashed_password=password_hash,
                    role=models.UserRole.SECRETAIRE, is_active=True, is_licensed=True,
                    employer_id=owner.id, permissions=grants,
                    nom_complet="CI Synthetic Stock Staff",
                ))
            for user in (owner, other):
                db.add(models.CabinetConfig(
                    owner_id=user.id, is_initialized=True,
                    nom_cabinet="CI SYNTHETIC CABINET",
                    nom_praticien="CI SYNTHETIC OWNER",
                ))
            db.commit()
            print("SYNTHETIC_FIXTURE_PASS users=6 patients=0", flush=True)
        elif sys.argv[1:] == ["verify"]:
            owner = db.scalar(select(models.User).where(models.User.email == "ci-owner@example.com"))
            rows = db.scalars(select(models.Patient)).all()
            assert owner is not None and len(rows) == 1
            row = rows[0]
            assert row.nom == "CI-SYNTHETIC" and row.prenom == "Fixture"
            assert row.employer_id == owner.id and row.date_naissance.year == 2000
            assert db.scalar(select(func.count()).select_from(models.DossierClinique).where(
                models.DossierClinique.patient_id == row.id)) == 1
            print("SQLCIPHER_PATIENT_PERSISTENCE_PASS patients=1 dossiers=1", flush=True)
        else:
            raise RuntimeError("Expected seed or verify")
    database.engine.dispose()


if __name__ == "__main__":
    main()
