"""Synthetic admission checks; no historical profile bytes or patient data."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("projection", ROOT / "backend/services/cephalo_protocol_projection.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Admission(unittest.TestCase):
    def test_contracts(self):
        for identity, key in (("STEINER_STATIC_PROTOCOL_PROFILE_V1", "norm_sets"),
                              ("TWEED_MERRIFIELD_DC_PROTOCOL_PROFILE_V1", "reference_contexts")):
            with self.subTest(identity=identity), tempfile.TemporaryDirectory() as tmp:
                p = Path(tmp) / "fixture.json"
                obj = {"schema_version": "ORTHO_ANALYSIS_PROTOCOL_PROFILE_V1",
                       "protocol_profile_id": identity, "scientific_authority": "LOT06_CANONICAL_MEASUREMENT_REGISTRY",
                       "status": "SOURCE_LOCKED", "pre_code_gate": {
                           "gate": "ORTHO_ANALYSIS_PROTOCOLS_SOURCE_LOCKED", "scope": identity, "status": "SATISFIED"},
                       "scope_resolutions": {"AUTONOMOUS_TREATMENT": "FORBIDDEN", "EXTRACTION_NON_EXTRACTION": "CLINICIAN_ONLY"},
                       key: [{"classification_authority": False, "runtime_delta_authority": False}],
                       "final_gate": {"status": "SATISFIED"}}
                raw = json.dumps(obj).encode()
                pin = hashlib.sha256(raw).hexdigest()
                p.write_bytes(raw)
                self.assertEqual(m._admit_profile(p, pin, identity, key), obj)
                self.assertEqual(m._uncertified_final_gate()["status"], "OPEN")
                loader = m._load_profile if key == "norm_sets" else m._load_tweed_merrifield_profile
                path_attr, pin_attr = ("_PROFILE_PATH", "_STEINER_PIN") if key == "norm_sets" else ("_TWEED_MERRIFIELD_PROFILE_PATH", "_TWEED_PIN")
                with patch.object(m, path_attr, p), patch.object(m, pin_attr, pin):
                    self.assertEqual(loader(), obj)
                    p.write_bytes(raw + b" ")
                    with self.assertRaises(ValueError):
                        loader()
                    p.write_bytes(raw)
                mutations = [
                    ("identity", lambda x: x.update(protocol_profile_id="wrong")),
                    ("schema", lambda x: x.update(schema_version="wrong")),
                    ("source", lambda x: x.update(scientific_authority="wrong")),
                    ("status", lambda x: x.update(status="OPEN")),
                    ("gate", lambda x: x["pre_code_gate"].update(scope="wrong")),
                    ("class", lambda x: x[key][0].update(classification_authority=True)),
                    ("false string", lambda x: x[key][0].update(classification_authority="false")),
                    ("missing", lambda x: x[key][0].pop("classification_authority")),
                    ("empty", lambda x: x.update({key: []})),
                    ("treatment", lambda x: x["scope_resolutions"].update(AUTONOMOUS_TREATMENT="ALLOWED")),
                    ("extraction", lambda x: x["scope_resolutions"].update(EXTRACTION_NON_EXTRACTION="AUTO")),
                ]
                if key == "reference_contexts":
                    mutations.append(("delta", lambda x: x[key][0].update(runtime_delta_authority=True)))
                for name, mutate in mutations:
                    with self.subTest(mutation=name):
                        changed = json.loads(raw)
                        mutate(changed)
                        bad = json.dumps(changed).encode()
                        p.write_bytes(bad)
                        with self.assertRaises(ValueError):
                            m._admit_profile(p, pin, identity, key)
                        with self.assertRaises(ValueError):
                            m._admit_profile(p, hashlib.sha256(bad).hexdigest(), identity, key)
                p.write_bytes(b"x" * 65537)
                with self.assertRaises(ValueError):
                    m._admit_profile(p, hashlib.sha256(p.read_bytes()).hexdigest(), identity, key)
                p.unlink()
                with self.assertRaises(FileNotFoundError):
                    m._admit_profile(p, pin, identity, key)


if __name__ == "__main__":
    unittest.main(verbosity=2)
