"""Recovery-stage Windows entrypoint. Not a cabinet release launcher yet.

No backend, configuration, network or first-boot side effects are allowed before
release admission. Positive activation remains disabled pending the independently
approved signing authority and the qualified provisioning/restore contract.
"""
from pathlib import Path
import sys

from dc_release_gate.release_certification import (
    ReleaseCertificationError,
    verify_installable_release_identity,
)


def main() -> int:
    if not getattr(sys, "frozen", False):
        print("R02_LAUNCH_REFUSED_SOURCE_CHECKOUT", file=sys.stderr)
        return 2

    bundle = getattr(sys, "_MEIPASS", None)
    if not bundle or not Path(bundle).is_absolute() or not Path(bundle).is_dir():
        print("R02_LAUNCH_REFUSED_BUNDLE_ROOT", file=sys.stderr)
        return 2

    try:
        verify_installable_release_identity(Path(bundle))
    except (ReleaseCertificationError, OSError, ValueError, RuntimeError):
        print("R02_LAUNCH_REFUSED_UNVERIFIED_RELEASE", file=sys.stderr)
        return 2

    # Metadata integrity is not a new trust root or authorization to start a
    # clinical runtime. Never create config/DB, run restore, or import backend here.
    print("R02_LAUNCH_REFUSED_AUTHORITY_AND_PROVISIONING_PENDING", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
