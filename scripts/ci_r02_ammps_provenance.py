"""Targeted standard-library CI qualification, synthetic records only.
Execute exact tracked modules in a temporary package, without backend startup.
No private source data, no network, no database, no prescription generation.
"""
import copy
import hashlib
import importlib
import json
import logging
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]


def fixture():
    row = {
        "nom": "SYNTHETIC MEDICINE", "dci": "SYNTHETIC DCI", "dosage": "1",
        "unite": "MG", "forme": "SYNTHETIC FORM", "presentation": "SYNTHETIC BOX",
        "epi": "SYNTHETIC ENTITY", "source_snapshot_date": "2026-10-01",
        "market_status_checked_at": "2026-10-01", "source_page_url": "https://ammps.gov.ma/recherche-medicaments",
        "amm_status": "PENDING_VERIFICATION", "market_status": "OBSERVED SYNTHETIC",
        "rcp_link_observed": False, "rcp_url": None, "rcp_snapshot_status": "PENDING_DOWNLOAD",
        "rcp_sha256": None, "rcp_checked_at": None,
    }
    key = "|".join(row[k].strip().upper() for k in ("nom","dci","dosage","unite","forme","presentation","epi"))
    row["regulatory_presentation_id"] = "ammps-reg:" + hashlib.sha256(key.encode()).hexdigest()[:24]
    return row


class ProvenanceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="dc-ammps-fixture-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / "candidate.json"
        self.legacy = self.root / "legacy.json"
        self.legacy.write_text(json.dumps([{"nom":"SYNTHETIC LEGACY", "dci":"SYNTHETIC DCI",
            "dosage":"1","unite":"MG","forme":"SYNTHETIC FORM"}]), encoding="utf-8")
        self.addCleanup(patch.stopall)
        patch.multiple(med, _DATA_PATH=str(self.legacy), _AMMPS_DATA_PATH=str(self.root/"absent.json"),
            _AMMPS_CURRENT_DATA_PATH=str(self.path), _MEDS=[], _LOADED=False,
            _AMMPS_APPROVED_SNAPSHOT_SHA256=None).start()

    def write(self, rows):
        return self.write_bytes(json.dumps(rows).encode())

    def write_bytes(self, payload):
        self.path.write_bytes(payload)
        med._AMMPS_APPROVED_SNAPSHOT_SHA256 = hashlib.sha256(payload).hexdigest()

    def rejected(self, rows, marker):
        self.write(rows)
        with self.assertRaisesRegex(ValueError, marker):
            med._read_current_records(str(self.path))
        self.assertEqual(med.search_regulatory_presentations("SYNTHETIC"), [])
        self.assertEqual(len(med.search("SYNTHETIC")), 1)
        self.assertFalse(med.catalog_metadata()["sources"][0]["available"])

    def test_default_unapproved(self):
        self.write([fixture()])
        med._AMMPS_APPROVED_SNAPSHOT_SHA256 = None
        with self.assertRaisesRegex(ValueError,"NOT_APPROVED"):
            med._read_current_records(str(self.path))
        self.assertEqual(med.search_regulatory_presentations("SYNTHETIC"), [])
        self.assertEqual(med.get_regulatory_presentation(fixture()["regulatory_presentation_id"]), None)

    def test_hash_tampering(self):
        self.write([fixture()])
        self.path.write_bytes(self.path.read_bytes()+b" ")
        with self.assertRaisesRegex(ValueError,"HASH_MISMATCH"):
            med._read_current_records(str(self.path))

    def test_mixed_dates_all_or_nothing(self):
        good = fixture()
        bad = {**good, "source_snapshot_date":"2026-09-15"}
        self.rejected([good,bad],"DATE_MISMATCH")

    def test_missing_market_date(self):
        row = fixture()
        del row["market_status_checked_at"]
        self.rejected([row],"DATE_MISMATCH")

    def test_forged_id(self):
        self.rejected([{**fixture(),"regulatory_presentation_id":"ammps-reg:"+"0"*24}],"ID_INVALID")

    def test_duplicate_id(self):
        self.rejected([fixture(),fixture()],"DUPLICATE")

    def test_untrusted_url(self):
        for url in ("https://ammps.gov.ma.example.invalid/a","http://ammps.gov.ma/a",
                    "https://user@ammps.gov.ma/a","https://ammps.gov.ma:444/a"):
            with self.subTest(url=url):
                self.write([{**fixture(),"source_page_url":url}])
                with self.assertRaisesRegex(ValueError,"SOURCE_URL_INVALID"):
                    med._read_current_records(str(self.path))

    def test_invalid_identity(self):
        self.rejected([{**fixture(),"presentation":None}],"IDENTITY_INVALID")

    def test_verified_rcp_without_bytes(self):
        self.rejected([{**fixture(),"rcp_snapshot_status":"SNAPSHOT_VERIFIED",
                        "rcp_sha256":"a"*64}],"RCP_UNSUPPORTED_CLAIM")

    def test_invalid_rcp_url(self):
        self.rejected([{**fixture(),"rcp_url":"https://example.invalid/rcp"}],"RCP_UNSUPPORTED_CLAIM")

    def test_forged_amm_status(self):
        self.rejected([{**fixture(),"amm_status":"VERIFIED"}],"AUTHORIZATION_STATUS_INVALID")

    def test_duplicate_json_key(self):
        payload=json.dumps([fixture()]).replace('"nom":','"nom":"duplicate","nom":',1).encode()
        self.write_bytes(payload)
        with self.assertRaisesRegex(ValueError,"DUPLICATE_JSON_KEY"):
            med._read_current_records(str(self.path))

    def test_empty_snapshot(self):
        self.rejected([],"INVALID_ROOT")

    def test_missing_snapshot(self):
        med._AMMPS_APPROVED_SNAPSHOT_SHA256 = "a"*64
        self.assertEqual(med.search_regulatory_presentations("SYNTHETIC"),[])
        self.assertFalse(med.catalog_metadata()["sources"][0]["available"])

    def test_positive_documentary_only_and_actual_safety_block(self):
        row = fixture()
        row.update(amm_status="AMM ENREGISTREE",rcp_link_observed=True,
                   rcp_url="https://ammps.gov.ma/rcp/synthetic",
                   _source={"current_marketing_status_verified":True})
        self.write([row])
        hit = med.get_regulatory_presentation(row["regulatory_presentation_id"])
        self.assertIsNotNone(hit)
        self.assertEqual(hit["source"]["snapshot_date"],"2026-10-01")
        self.assertEqual(hit["amm_status"],"PENDING_VERIFICATION")
        self.assertEqual(hit["observed_amm_status"],"AMM ENREGISTREE")
        self.assertNotIn("market_status",hit)
        self.assertFalse(hit["source"]["current_marketing_status_verified"])
        unified=med.search_unified("SYNTHETIC MEDICINE")[0]
        self.assertEqual(unified["neo_source_state"],"DATED_REGULATORY_REFERENCE")
        self.assertFalse(unified["may_claim_current_marketing_status"])
        self.assertEqual(len(med.search("SYNTHETIC")),1)
        self.assertTrue(med.catalog_metadata()["sources"][0]["available"])
        result=safety.evaluate_neo_prescription_safety(presentation_id=hit["presentation_id"],
            patient_context={},age_years=30)
        self.assertEqual(result.status,"BLOCKED")
        self.assertIn("CURRENT_MARKETING_STATUS_NOT_VERIFIED",result.blockers)
        self.assertFalse(result.current_marketing_status_verified)


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    with tempfile.TemporaryDirectory(prefix="dc-ammps-source-") as tmp:
        root=Path(tmp).resolve(strict=True)
        service=root/"backend"/"services"
        service.mkdir(parents=True)
        for package in (service,service.parent):
            (package/"__init__.py").write_text("",encoding="utf-8")
        for name in ("medication_dict.py","neo_prescription_safety.py","neo_medication_evidence.py"):
            shutil.copyfile(REPO/"backend"/"services"/name,service/name)
        sys.path.insert(0,str(root))
        med=importlib.import_module("backend.services.medication_dict")
        safety=importlib.import_module("backend.services.neo_prescription_safety")
        # Windows may expand a short TEMP path when resolving module filenames.
        # Compare both sides canonically, with exact filename and byte identity.
        for name in ("medication_dict.py","neo_prescription_safety.py","neo_medication_evidence.py"):
            module = sys.modules["backend.services."+name[:-3]]
            actual = Path(module.__file__).resolve(strict=True)
            expected = (service/name).resolve(strict=True)
            if not actual.is_relative_to(root) or actual != expected:
                raise RuntimeError("ISOLATED_MODULE_ORIGIN_MISMATCH "+name)
            if actual.read_bytes() != (REPO/"backend"/"services"/name).read_bytes():
                raise RuntimeError("ISOLATED_MODULE_BYTES_MISMATCH "+name)
        for name, package in (("backend",service.parent),("backend.services",service)):
            actual = Path(sys.modules[name].__file__).resolve(strict=True)
            if actual != (package/"__init__.py").resolve(strict=True) or actual.read_bytes():
                raise RuntimeError("ISOLATED_PACKAGE_ORIGIN_MISMATCH "+name)
        if med._AMMPS_APPROVED_SNAPSHOT_SHA256 is not None:
            raise RuntimeError("UNEXPECTED_AMMPS_APPROVAL")
        print("R02_AMMPS_ISOLATED_MODULE_IDENTITY_PASS modules=3 packages=2",flush=True)
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ProvenanceTest))
        if not result.wasSuccessful():
            raise SystemExit(1)
        print("R02_AMMPS_PROVENANCE_TARGETED_PASS tests="+str(result.testsRun),flush=True)
