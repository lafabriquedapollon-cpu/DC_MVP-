"""R0.2 packaging guard tests; synthetic temporary fixtures only, no issuance."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from backend.core.runtime_safety import assert_runtime_startup_allowed
from backend.release_certification import (
    ReleaseCertificationError, verify_release_directory,
    verify_installable_release_directory,
)
from backend.runtime_asset_certification import (
    RuntimeAssetCertificationError, inspect_registry_coverage,
    iter_runtime_asset_files,
)

ROOT = Path(__file__).resolve().parents[2]


class PackagingGuards(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="dc-packaging-synthetic-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_legacy_imports_same_implementation(self):
        import backend.release_certification as legacy_code
        import backend.runtime_asset_certification as legacy_assets
        from dc_release_gate import release_certification, runtime_asset_certification
        self.assertIs(legacy_code, release_certification)
        self.assertIs(legacy_assets, runtime_asset_certification)

    def test_missing_code_certificate(self):
        with self.assertRaisesRegex(ReleaseCertificationError, "Missing release-certification.json"):
            verify_release_directory(self.root)

    def test_unapproved_repository(self):
        (self.root / "release-certification.json").write_text(json.dumps({
            "certificate_version": 1, "repository": "synthetic/untrusted",
        }), encoding="utf-8")
        with self.assertRaisesRegex(ReleaseCertificationError, "Unexpected certificate repository"):
            verify_release_directory(self.root)

    def test_installable_without_certificate(self):
        with self.assertRaises(ReleaseCertificationError):
            verify_installable_release_directory(self.root)

    def test_missing_scientific_registry(self):
        with self.assertRaisesRegex(RuntimeAssetCertificationError, "scientific_assets.json is missing"):
            inspect_registry_coverage(self.root)

    def test_missing_model_root(self):
        with self.assertRaisesRegex(RuntimeAssetCertificationError, "Runtime asset root missing"):
            list(iter_runtime_asset_files(self.root / "absent"))

    def test_legacy_builder_disabled(self):
        run = subprocess.run([sys.executable, str(ROOT / "scripts/build_exe.py")],
                             cwd=self.root, capture_output=True, text=True, timeout=15)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("SEC-P0", run.stderr)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_cabinet_boot_uncertified(self):
        for environment in ("cabinet", "production"):
            with self.subTest(environment=environment):
                with self.assertRaisesRegex(RuntimeError, "INSTALLABLE_CERTIFIED"):
                    assert_runtime_startup_allowed(SimpleNamespace(
                        ENVIRONMENT=environment, DATABASE_URL="sqlite:///:memory:"
                    ))


if __name__ == "__main__":
    unittest.main(verbosity=2)
