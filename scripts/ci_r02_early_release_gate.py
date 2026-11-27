"""Read-only early release gate: no backend import or pre-verification writes."""
import json
import os
import sys
import tempfile
from pathlib import Path
import unittest


class EarlyReleaseGate(unittest.TestCase):
    def test_rejection_is_side_effect_free(self):
        with tempfile.TemporaryDirectory(prefix="dc-early-gate-synthetic-") as tmp:
            root = Path(tmp)
            target = root / "uncertified"
            target.mkdir()
            overrides = {
                "DIGITALCROWN_USER_DATA_DIR": root / "user-data",
                "DIGITALCROWN_CONFIG_DIR": root / "config",
                "DIGITALCROWN_LOG_DIR": root / "logs",
                "DIGITALCROWN_RUNTIME_DIR": root / "runtime",
                "MEDIA_ROOT": root / "media",
            }
            from unittest.mock import patch
            with patch.dict(os.environ, {k: str(v) for k, v in overrides.items()}, clear=True):
                self.assertFalse(any(k == "backend" or k.startswith("backend.") for k in sys.modules))
                from dc_release_gate.release_certification import (
                    ReleaseCertificationError, verify_installable_release_identity,
                    verify_installable_release_directory,
                )
                from dc_release_gate.runtime_asset_certification import (
                    RuntimeAssetCertificationError, inspect_registry_coverage,
                )
                for verify in (verify_installable_release_identity, verify_installable_release_directory):
                    with self.assertRaisesRegex(ReleaseCertificationError, "Missing release-certification.json"):
                        verify(target)
                with self.assertRaisesRegex(RuntimeAssetCertificationError, "scientific_assets.json is missing"):
                    inspect_registry_coverage(target)
                (target / "release-certification.json").write_text(json.dumps({
                    "certificate_version": 1, "repository": "synthetic/untrusted",
                }), encoding="utf-8")
                with self.assertRaisesRegex(ReleaseCertificationError, "Unexpected certificate repository"):
                    verify_installable_release_identity(target)
                self.assertFalse(any(k == "backend" or k.startswith("backend.") for k in sys.modules))
                self.assertEqual({p.name for p in root.iterdir()}, {"uncertified"})
                self.assertEqual({p.name for p in target.iterdir()}, {"release-certification.json"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
