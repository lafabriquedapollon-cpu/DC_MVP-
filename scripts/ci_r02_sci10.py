"""SCI10: source-only synthetic regression; no private resources or activation."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "backend/services" / (name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

rcp = load("medication_rcp_manifest")
ngap = load("ngap_dental_reference")

def entry():
    return {"regulatory_presentation_id": "ammps-reg:" + "a"*24,
            "source_page_url": "https://ammps.gov.ma/synthetic",
            "capture_status":"PENDING_DOWNLOAD", "rcp_url":None, "rcp_sha256":None,
            "rcp_checked_at":None,"local_artifact_path":None,"extracted_clinical_fields":{}}

def manifest(entries):
    return {"schema_version":"m1b-rcp.1","authority":"AMMPS",
            "source_scope":"OFFICIAL_RCP_CAPTURE_MANIFEST","runtime_behavior_change":False,
            "entries":entries}

def dental():
    special={"D630":"ceiling","D718":"anesthesia","D719":"anesthesia",
             "D722":"anesthesia","D723":"anesthesia","D757":"calculation_rule","D816":"quote_required"}
    return {"schema_version":1,"dataset_id":ngap.DATASET_ID,"status":ngap.REFERENCE_STATUS,
            "reference":{"source_sha256":ngap.EXPECTED_SOURCE_SHA256,"arrete":ngap.EXPECTED_LEGAL_REFERENCE},
            "columns":ngap.EXPECTED_COLUMNS,"scope":{"entry_count":145},
            "acts":[[c,"SYNTHETIC",None if special.get(c) in {"calculation_rule","quote_required"} else 1,
                      None,special.get(c,"act")] for c in ngap._expected_codes()]}

class GateTests(unittest.TestCase):
    def test_pending_and_reject_promotions(self):
        self.assertIsNone(rcp._APPROVED_PROMOTION_MANIFEST_SHA256)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            path=root/"manifest.json"
            artifact=root/"backend/data/rcp/synthetic.pdf"
            artifact.parent.mkdir(parents=True)
            fake=b"%PDF-1.7\\nSYNTHETIC NOT AN OFFICIAL RCP"
            artifact.write_bytes(fake)
            forged={**entry(),"capture_status":"SNAPSHOT_VERIFIED","rcp_url":"https://ammps.gov.ma/synthetic.pdf",
                    "rcp_sha256":hashlib.sha256(fake).hexdigest(),"rcp_checked_at":"2026-11-26",
                    "local_artifact_path":"backend/data/rcp/synthetic.pdf"}
            unavailable={**entry(),"capture_status":"UNAVAILABLE_VERIFIED","rcp_checked_at":"2026-11-26",
                         "unavailability_evidence":"OFFICIAL_SOURCE_EXPLICIT_NO_RCP"}
            with patch.multiple(rcp,_MANIFEST_PATH=path,_REPO_ROOT=root,_MANIFEST=None):
                path.write_text(json.dumps(manifest([entry()])),encoding="utf-8")
                self.assertEqual(rcp.manifest_metadata()["entry_count"],1)
                self.assertEqual(rcp.get_rcp_evidence(entry()["regulatory_presentation_id"])["capture_status"],"PENDING_DOWNLOAD")
                self.assertTrue(rcp.snapshot_is_verified(forged)) # byte integrity only
                for bad in ([forged],[unavailable],[entry(),entry()],
                            [{**entry(),"source_page_url":"https://user@ammps.gov.ma/a"}],
                            [{**entry(),"source_page_url":"https://ammps.gov.ma:444/a"}],
                            [{**entry(),"extracted_clinical_fields":{"synthetic":True}}]):
                    with self.subTest(bad=bad):
                        rcp._MANIFEST=None
                        path.write_text(json.dumps(manifest(bad)),encoding="utf-8")
                        self.assertFalse(rcp.manifest_metadata()["available"])
                        self.assertIsNone(rcp.get_rcp_evidence(entry()["regulatory_presentation_id"]))
                rcp._MANIFEST=None
                path.write_text(json.dumps(manifest([entry()])).replace('"authority":','"authority":"fake","authority":',1),encoding="utf-8")
                self.assertFalse(rcp.manifest_metadata()["available"])

    def test_ngap_reference_only_and_nonfinite(self):
        good=dental()
        self.assertEqual(len(ngap.validate_ngap_dental_reference(good)["acts"]),145)
        for value in (float("nan"),float("inf"),True,-1):
            for index in (2,3):
                bad=copy.deepcopy(good)
                bad["acts"][0][index]=value
                with self.subTest(value=value,index=index),self.assertRaises(ValueError):
                    ngap.validate_ngap_dental_reference(bad)
        bad=copy.deepcopy(good)
        bad["acts"][30][4]="act" # D630 ceiling cannot become autonomous act
        with self.assertRaisesRegex(ValueError,"entry type mismatch"):
            ngap.validate_ngap_dental_reference(bad)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"ref.json"
            for content in ('{"status":"x","status":"y"}','{"coefficient":NaN}'):
                p.write_text(content,encoding="utf-8")
                with self.assertRaises(ValueError): ngap.load_ngap_dental_reference(p)

if __name__=="__main__":
    unittest.main(verbosity=2)
