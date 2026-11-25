# Recovery-stage preflight only. Deliberately produces no cabinet executable.
# PyInstaller's SPECPATH is the directory containing this spec.
from pathlib import Path
import sys

root = Path(SPECPATH).resolve()
sys.path.insert(0, str(root))
from dc_release_gate.release_certification import verify_installable_release_directory

# Do not begin Analysis, collect models, or copy any files before this gate.
verify_installable_release_directory(root)
raise SystemExit("R02_SPEC_REFUSED_AUTHORITY_AND_PROVISIONING_PENDING")
