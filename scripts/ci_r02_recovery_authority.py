"""Proposed authority tests. Synthetic claims are never clinical certificates."""
from pathlib import Path
import tempfile
import unittest

from dc_release_gate import recovery_authority as a
from dc_release_gate import release_certification as existing

SHA = "a" * 40


class RecoveryAuthority(unittest.TestCase):
    def test_repository_identity(self):
        a.check_repository_identity({"full_name": a.REPOSITORY, "id": a.REPOSITORY_ID,
                                     "owner": {"id": a.OWNER_ID}, "default_branch": "main"})

    def test_repository_recreation_denied(self):
        for overrides in ({"id": 1}, {"owner": {"id": 1}}, {"full_name": "synthetic/other"},
                          {"default_branch": "master"}):
            with self.subTest(overrides=overrides), self.assertRaises(a.AuthorityDenied):
                a.check_repository_identity({"full_name": a.REPOSITORY, "id": a.REPOSITORY_ID,
                    "owner": {"id": a.OWNER_ID}, "default_branch": "main", **overrides})

    def test_unprotected_main_denied(self):
        with self.assertRaisesRegex(a.AuthorityDenied, "PROTECTED_MAIN_REQUIRED"):
            a.check_candidate_ref({"name": "main", "protected": False, "commit": {"sha": SHA}},
                                  approved_sha=SHA)

    def test_wrong_ref_or_sha_denied(self):
        for branch in ({"name": "feature", "protected": True, "commit": {"sha": SHA}},
                       {"name": "main", "protected": True, "commit": {"sha": "b" * 40}}):
            with self.subTest(branch=branch), self.assertRaises(a.AuthorityDenied):
                a.check_candidate_ref(branch, approved_sha=SHA)

    def test_exact_protected_ref(self):
        a.check_candidate_ref({"name": "main", "protected": True, "commit": {"sha": SHA}},
                              approved_sha=SHA)

    def test_invalid_sha_denied(self):
        for sha in ("main", "a" * 7, "A" * 40, "a" * 40 + "\n", "g" * 40):
            with self.subTest(sha=sha), self.assertRaises(a.AuthorityDenied):
                a.exact_sha(sha)

    def test_fixed_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            subject = Path(tmp) / "synthetic-subject.txt"
            subject.write_text("inert", encoding="ascii")
            args = a.verification_plan(subject, approved_sha=SHA)
            self.assertEqual(args[:3], ("attestation", "verify", str(subject)))
            for flag, value in (("--repo", a.REPOSITORY), ("--signer-workflow", a.SIGNER_WORKFLOW),
                                ("--signer-digest", SHA), ("--source-digest", SHA),
                                ("--source-ref", "refs/heads/main"), ("--cert-oidc-issuer", a.OIDC_ISSUER),
                                ("--predicate-type", a.PREDICATE), ("--hostname", "github.com")):
                self.assertEqual(args[args.index(flag) + 1], value)
            self.assertIn("--deny-self-hosted-runners", args)
            for flag in ("--bundle", "--custom-trusted-root", "--owner", "--cert-identity-regex"):
                self.assertNotIn(flag, args)

    def test_missing_subject_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(a.AuthorityDenied):
                a.verification_plan(Path(tmp) / "absent", approved_sha=SHA)

    def test_production_identity_not_switched(self):
        self.assertEqual(existing.REPOSITORY, "hraaaaf/Digital_crown")
        self.assertEqual(existing.GITHUB_SIGNER_WORKFLOW,
                         "hraaaaf/Digital_crown/.github/workflows/cabinet-release-certification.yml")


if __name__ == "__main__":
    unittest.main(verbosity=2)
