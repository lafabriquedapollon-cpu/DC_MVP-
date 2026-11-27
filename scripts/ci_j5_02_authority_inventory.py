"""Read-only J5-02 reconciliation inventory. Never authorizes a release."""
import json
import os
from pathlib import Path
import subprocess
import unittest
from dc_release_gate import recovery_authority as proposed
from dc_release_gate import release_certification as legacy
from scripts.ci_r02_recovery_authority import RecoveryAuthority

BASE = "cdcea2deb8b27178223118512fc80e964f5f1cc3"
BRANCH = "ci/j5-02-authority-reconciliation-20261127"
PINNED = (
    "run.py", "DigitalCrown.spec",
    "dc_release_gate/release_certification.py",
    "dc_release_gate/runtime_asset_certification.py",
    "dc_release_gate/recovery_authority.py",
    "backend/scripts/create_release.ps1",
    "backend/scripts/compose_installable_release.py",
    "backend/core/runtime_safety.py",
)

def run(*args):
    return subprocess.check_output(args, text=True, timeout=60).strip()

def main():
    assert os.environ["GITHUB_REF"] == "refs/heads/" + BRANCH
    assert os.environ["GITHUB_REPOSITORY"] == proposed.REPOSITORY
    assert os.environ["GITHUB_REPOSITORY_ID"] == str(proposed.REPOSITORY_ID)
    assert os.environ["GITHUB_REPOSITORY_OWNER_ID"] == str(proposed.OWNER_ID)
    assert os.environ["RUNNER_ENVIRONMENT"] == "github-hosted"
    assert run("git", "rev-parse", "HEAD") == os.environ["GITHUB_SHA"]
    for path in PINNED:
        assert run("git", "rev-parse", BASE + ":" + path) == run("git", "rev-parse", "HEAD:" + path), path
    assert legacy.REPOSITORY == "hraaaaf/Digital_crown"
    assert proposed.REPOSITORY != legacy.REPOSITORY
    print("J5_AUTHORITY_GUARDS_UNCHANGED_PASS count=" + str(len(PINNED)))
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RecoveryAuthority))
    assert result.wasSuccessful()
    # Paths only, never dump source, environment, credentials or API response bodies.
    for label, pattern in (("legacy_identity", "hraaaaf/Digital_crown"), ("proposed_identity", proposed.REPOSITORY), ("release_workflow", "cabinet-release-certification.yml"), ("publisher_gate", "PublisherCertSha256PinFile"), ("provisioning_gate", "AUTHORITY_AND_PROVISIONING_PENDING")):
        p = subprocess.run(["git", "grep", "-l", "-I", "-F", pattern, "HEAD", "--", "."], capture_output=True, text=True, timeout=60)
        assert p.returncode in (0, 1)
        paths = sorted(p.stdout.splitlines())
        print("J5_INVENTORY " + label + " count=" + str(len(paths)))
        for path in paths:
            print("J5_PATH " + label + " " + json.dumps(path, ensure_ascii=True))
    repo = json.loads(run("gh", "api", "repos/" + proposed.REPOSITORY))
    proposed.check_repository_identity(repo)
    main_ref = json.loads(run("gh", "api", "repos/" + proposed.REPOSITORY + "/branches/main"))
    print("J5_LIVE_REPO_IDENTITY_PASS")
    print("J5_MAIN_PROTECTED=" + str(main_ref.get("protected") is True).lower())
    print("J5_REPOSITORY_PRIVATE=" + str(repo.get("private") is True).lower())
    # No real owner approval exists in this laboratory. Even a protected branch
    # and valid SHA would be insufficient; this script never issues admission.
    try:
        proposed.check_candidate_ref(main_ref, approved_sha=os.environ["GITHUB_SHA"])
    except proposed.AuthorityDenied as e:
        assert str(e) in ("PROTECTED_MAIN_REQUIRED", "APPROVED_SOURCE_SHA_MISMATCH")
        print("J5_ACTUAL_CANDIDATE_DENIED " + str(e))
    else:
        raise AssertionError("LAB_CANDIDATE_UNEXPECTEDLY_MAIN")
    assert not Path(".github/workflows/cabinet-release-certification.yml").exists()
    print("J5_CERTIFICATION_WORKFLOW_ABSENT")
    print("J5_02_READONLY_RECONCILIATION_PASS NOT_AUTHORIZED_NOT_A_RELEASE")

if __name__ == "__main__":
    main()
