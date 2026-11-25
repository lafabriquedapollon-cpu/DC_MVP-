"""Exercise the actual recovery entrypoint and spec without issuing certificates."""
import contextlib
import io
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch

import run

ROOT = Path(__file__).resolve().parents[1]


class LauncherAdmission(unittest.TestCase):
    def test_source_launch_refused(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(run.main(), 2)
        self.assertIn("R02_LAUNCH_REFUSED_SOURCE_CHECKOUT", err.getvalue())

    def test_frozen_missing_certificate_and_restore_flags_refused(self):
        for args in ([], ["--initialize-new-cabinet"],
                     ["--guided-restore-worker", "synthetic", "--parent-pid", "1"]):
            with self.subTest(args=args), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                with patch.object(sys, "frozen", True, create=True), patch.object(
                    sys, "_MEIPASS", tmp, create=True
                ), patch.object(sys, "argv", ["run.py", *args]), contextlib.redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(run.main(), 2)
                self.assertIn("R02_LAUNCH_REFUSED_UNVERIFIED_RELEASE", err.getvalue())
                self.assertEqual(list(root.iterdir()), [])
        self.assertFalse(any(k == "backend" or k.startswith("backend.") for k in sys.modules))

    def test_spec_refuses_before_analysis(self):
        from dc_release_gate.release_certification import ReleaseCertificationError
        with tempfile.TemporaryDirectory() as tmp:
            original = list(sys.path)
            try:
                with self.assertRaisesRegex(ReleaseCertificationError, "Missing release-certification.json"):
                    runpy.run_path(str(ROOT / "DigitalCrown.spec"), init_globals={"SPECPATH": tmp})
            finally:
                sys.path[:] = original
            self.assertEqual(list(Path(tmp).iterdir()), [])
        self.assertFalse(any(k == "backend" or k.startswith("backend.") for k in sys.modules))


if __name__ == "__main__":
    unittest.main(verbosity=2)
