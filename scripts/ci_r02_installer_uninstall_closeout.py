"""Target the remaining uninstall closeout using a real Inno setup and 5051 files.
No full backend, scientific asset, CA wheel or independent smoke reruns.
"""
import importlib.util
import os
from pathlib import Path
import secrets
import subprocess
import tempfile

here=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("installer_policy",here/"ci_r02_installer_rehearsal.py")
policy=importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
policy.require(os.name=="nt" and os.environ.get("GITHUB_ACTIONS")=="true","WINDOWS_CI_ONLY")
runner=Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)

# Direct negative proof: no residual file or directory junction may be removed.
with tempfile.TemporaryDirectory(prefix="dc-installer-rehearsal-",dir=runner) as tmp:
    root=Path(tmp).resolve(strict=True)
    dest=root/"installed"
    dest.mkdir()
    empty=dest/"empty"/"nested"
    empty.mkdir(parents=True)
    retained=dest/"keep.txt"
    retained.write_bytes(b"synthetic retain")
    try:
        policy.cleanup_empty_residue(dest,root)
    except RuntimeError as exc:
        policy.require(str(exc)=="UNINSTALL_NONEMPTY_OR_REPARSE_RESIDUE","WRONG_RESIDUE_REFUSAL")
    else:
        raise RuntimeError("RESIDUAL_FILE_DELETED")
    policy.require(retained.read_bytes()==b"synthetic retain" and empty.is_dir(),"RESIDUAL_TREE_MUTATED")
    retained.unlink()
    outside=root/"outside"
    outside.mkdir()
    sentinel=outside/"sentinel.txt"
    sentinel.write_bytes(b"synthetic outside")
    junction=dest/"junction"
    cmd=Path(os.environ["SystemRoot"])/"System32"/"cmd.exe"
    result=subprocess.run([str(cmd),"/d","/c","mklink","/J",str(junction),str(outside)],
                          capture_output=True,timeout=20)
    policy.require(result.returncode==0 and junction.is_dir(),"JUNCTION_FIXTURE_FAILED")
    try:
        try:
            policy.cleanup_empty_residue(dest,root)
        except RuntimeError as exc:
            policy.require(str(exc)=="UNINSTALL_NONEMPTY_OR_REPARSE_RESIDUE","WRONG_JUNCTION_REFUSAL")
        else:
            raise RuntimeError("JUNCTION_ACCEPTED")
        policy.require(sentinel.read_bytes()==b"synthetic outside","OUTSIDE_MUTATED")
    finally:
        # Remove the synthetic junction itself, never the target.
        junction.rmdir()
    policy.require(policy.cleanup_empty_residue(dest,root)==3 and not dest.exists(),
                   "EMPTY_DIR_ONLY_CLEANUP_FAILED")
    policy.require(sentinel.read_bytes()==b"synthetic outside","OUTSIDE_SENTINEL_MUTATED")
print("R02_INSTALLER_RESIDUAL_POLICY_PASS negative=2 positive=1",flush=True)

with tempfile.TemporaryDirectory(prefix="dc-uninstall-payload-",dir=runner) as tmp:
    source=Path(tmp).resolve(strict=True)
    for i in range(5051):
        path=source/"_internal"/("package-"+str(i//50).zfill(3))/("nested-"+str(i%7))/("file-"+str(i)+".txt")
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(("synthetic "+str(i)).encode("ascii"))
    with policy.installed_bundle(source,runner) as installed:
        # Simulate directories created at runtime without touching installed bytes.
        (installed/"_internal"/"synthetic-runtime-empty"/"nested").mkdir(parents=True)
        policy.require(len(policy.inventory(source))==5051,"SYNTHETIC_PAYLOAD_COUNT_MISMATCH")
    policy.require(not installed.exists(),"INSTALL_DIR_STILL_EXISTS")
print("R02_INSTALLER_LARGE_UNINSTALL_TARGETED_PASS files=5051",flush=True)
