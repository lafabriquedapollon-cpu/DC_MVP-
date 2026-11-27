"""J5-03: read-only packaging reconciliation and fail-closed input admission.
No model downloads, certification, release creation or changes to production gates.
"""
import hashlib
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from dc_release_gate import release_certification as legacy
from dc_release_gate import recovery_authority as proposed
from dc_release_gate.runtime_asset_certification import inspect_registry_coverage, RuntimeAssetCertificationError

ROOT=Path(__file__).resolve().parents[1]
BASE="7cf1668b3145ac8e2c78b3ad5844f16a3adc8554"
MODEL_SIZE=267484931
MODEL_SHA="a5ecd466d6d2c4ef02e145a143076a05720c0be56a260224812c23e2ecf42ddb"
REQUIRED=("python_runtime","backend","frontend_dist","native_dlls","sqlcipher","pdf_fonts","model_registry","authorized_weights","provision_restore","owner_authority","provenance","installed_runtime")
class Denied(ValueError): pass
def admit_fixture(evidence):
    if type(evidence) is not dict or set(evidence)!=set(REQUIRED):raise Denied("schema")
    missing=sorted(k for k,v in evidence.items() if v is not True)
    return {"status":"BLOCKED" if missing else "EXTERNAL_CERTIFICATION_REQUIRED","missing":missing}
def verify_bytes(path,*,size,digest):
    if type(size) is not int or size<=0 or not isinstance(digest,str) or not re.fullmatch("[0-9a-f]{64}",digest):raise Denied("pin")
    if not path.is_file() or path.is_symlink() or path.stat().st_size!=size:raise Denied("missing or wrong size")
    with path.open("rb") as f: actual=hashlib.file_digest(f,"sha256").hexdigest()
    if actual!=digest:raise Denied("hash")
def git(*args):
    return subprocess.check_output(["git",*args],cwd=ROOT,text=True).strip()
class Tests(unittest.TestCase):
    def test_each_requirement(self):
        for key in REQUIRED:
            e=dict.fromkeys(REQUIRED,True);e[key]=False
            self.assertEqual(admit_fixture(e),{"status":"BLOCKED","missing":[key]})
    def test_no_self_certification(self):
        self.assertEqual(admit_fixture(dict.fromkeys(REQUIRED,True))["status"],"EXTERNAL_CERTIFICATION_REQUIRED")
    def test_schema(self):
        with self.assertRaises(Denied):admit_fixture({})
        with self.assertRaises(Denied):admit_fixture(dict(dict.fromkeys(REQUIRED,True),extra=True))
    def test_nonboolean(self):
        e=dict.fromkeys(REQUIRED,True);e["owner_authority"]=1
        self.assertEqual(admit_fixture(e)["missing"],["owner_authority"])
    def test_pin_positive_and_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"inert.bin";p.write_bytes(b"abc")
            h=hashlib.sha256(b"abc").hexdigest()
            verify_bytes(p,size=3,digest=h)
            p.write_bytes(b"abd")
            with self.assertRaises(Denied):verify_bytes(p,size=3,digest=h)
            p.write_bytes(b"ab")
            with self.assertRaises(Denied):verify_bytes(p,size=3,digest=h)
    def test_missing_and_unpinned(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"missing"
            with self.assertRaises(Denied):verify_bytes(p,size=MODEL_SIZE,digest=MODEL_SHA)
            p.write_bytes(b"x")
            with self.assertRaises(Denied):verify_bytes(p,size=1,digest="")
    def test_current_registry_absent(self):
        self.assertFalse((ROOT/"backend/scientific_assets.json").exists())
        with self.assertRaises(RuntimeAssetCertificationError):inspect_registry_coverage(ROOT)
    def test_no_tracked_model_weights(self):
        paths=git("ls-files").splitlines()
        self.assertFalse([p for p in paths if Path(p).suffix.lower() in {".onnx",".pt",".pth",".safetensors"}])
    def test_legacy_authority_preserved(self):
        self.assertNotEqual(legacy.REPOSITORY,proposed.REPOSITORY)
        for p in ("run.py","DigitalCrown.spec","dc_release_gate/release_certification.py","dc_release_gate/runtime_asset_certification.py","backend/scripts/compose_installable_release.py"):
            self.assertEqual(git("rev-parse",BASE+":"+p),git("rev-parse","HEAD:"+p))
    def test_dependencies_existing(self):
        lock=(ROOT/"backend/requirements.txt").read_text()
        for name in ("torch","onnxruntime","sqlcipher3","weasyprint","reportlab","opencv-python-headless","fastapi"):
            self.assertRegex(lock,r"(?m)^"+re.escape(name)+r"==")
        self.assertTrue((ROOT/"frontend/package-lock.json").is_file())
        self.assertTrue((ROOT/"backend/requirements-windows-build.txt").is_file())
if __name__=="__main__":
    unittest.main(verbosity=2)
