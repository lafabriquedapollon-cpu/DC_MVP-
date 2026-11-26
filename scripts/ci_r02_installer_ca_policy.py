"""Focused real public CA wheel admission regression; no PE rebuild or install."""
import importlib.util
from importlib import metadata
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

here=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("installer_policy",here/"ci_r02_installer_rehearsal.py")
policy=importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
policy.require(os.name=="nt" and os.environ.get("GITHUB_ACTIONS")=="true","WINDOWS_CI_ONLY")
lock=json.loads((here/"r02-desktop-proven-versions.json").read_text(encoding="utf-8"))["packages"]
runner=Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)

def reject(root, marker):
    try:
        policy.inventory(root)
    except RuntimeError as exc:
        policy.require(str(exc).startswith(marker),"WRONG_PEM_DENIAL")
    else:
        raise RuntimeError("INVALID_PEM_ACCEPTED")

with tempfile.TemporaryDirectory(prefix="dc-pem-probe-",dir=runner) as temp:
    root=Path(temp).resolve(strict=True)
    (root/"fixture.txt").write_bytes(b"synthetic")
    for relative,(package,version,wheel_path) in policy._PUBLIC_CA.items():
        policy.require(lock[package]==version,"PUBLIC_CA_LOCK_MISMATCH")
        source=Path(metadata.distribution(package).locate_file(wheel_path)).resolve(strict=True)
        target=root/relative
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(source,target)
    expected=policy.inventory(root)
    policy.require(len(expected)==3,"PUBLIC_CA_FIXTURE_COUNT")
    for relative in policy._PUBLIC_CA:
        target=root/relative
        original=target.read_bytes()
        target.write_bytes(original+b"\n# tampered\n")
        reject(root,"INSTALL_PUBLIC_CA_IDENTITY_FAILED")
        target.write_bytes(b"-----BEGIN PRIVATE KEY-----\nU1lOVEhFVElD\n-----END PRIVATE KEY-----\n")
        reject(root,"INSTALL_PUBLIC_CA_IDENTITY_FAILED")
        target.write_bytes(original)
    unknown=root/"unknown.pem"
    unknown.write_bytes((root/next(iter(policy._PUBLIC_CA))).read_bytes())
    reject(root,"INSTALL_UNAPPROVED_PEM_REFUSED")
    unknown.unlink()
    unknown=root/"private.key"
    unknown.write_bytes(b"synthetic invalid key")
    reject(root,"INSTALL_PRIVATE_PAYLOAD_REFUSED")
    unknown.unlink()
    policy.require(policy.inventory(root)==expected,"PUBLIC_CA_RESTORE_MISMATCH")
    print("R02_INSTALLER_PUBLIC_CA_TARGETED_PASS positive=2 negative=6",flush=True)
policy.require(not root.exists(),"PUBLIC_CA_LAB_RESIDUE")
print("R02_INSTALLER_PUBLIC_CA_LAB_CLEANUP_PASS",flush=True)
