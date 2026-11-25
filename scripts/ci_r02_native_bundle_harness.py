"""Run bounded source and frozen native bundle probes plus tamper denial."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


def run(command, expected, *, negative=False):
    result = subprocess.run(command, cwd=Path(sys.prefix), stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=90)
    for line in result.stdout.splitlines():
        if (re.fullmatch(r"R02_RELOCATED_NATIVE_[A-Z_]+(?: dlls=[0-9]+)?", line)
                or re.fullmatch(r"R02_RELOCATED_NATIVE_COLLISION name=[a-z0-9_.+-]+\.dll origin=(?:python-runtime|base-python|windows-system|other) sha256=[a-f0-9]{64} same_bytes=[01]", line)):
            print(line, flush=True)
    if negative:
        if result.returncode == 0 or expected not in result.stderr:
            raise RuntimeError("NATIVE_TAMPER_NOT_REFUSED")
        print("R02_NATIVE_BUNDLE_TAMPER_REFUSED_PASS", flush=True)
    elif result.returncode or expected not in result.stdout.splitlines():
        # Source-only public dependency diagnostics; no raw stderr or paths.
        errors = re.findall(r"(?m)^([A-Za-z0-9_.]+(?:Error|Exception)):", result.stderr)
        markers = re.findall(r"(?m)^RuntimeError: ([A-Z0-9_]+(?: [a-z0-9_.+-]+)?)\s*$", result.stderr)
        raise RuntimeError(f"NATIVE_BUNDLE_PROBE_FAILED rc={result.returncode} types={errors[-3:]} markers={markers[-3:]}")


def main():
    lab = Path(sys.prefix).resolve(strict=True)
    require = lab.parent == Path(os.environ["RUNNER_TEMP"]).resolve(strict=True) and lab.name.startswith("dc-full-deps-")
    if not require or os.environ.get("GITHUB_ACTIONS") != "true" or os.name != "nt":
        raise RuntimeError("INVALID_CI_LAB")
    script = Path(__file__).resolve().with_name("ci_r02_relocated_native_probe.py")
    native = lab / "native-bundle"
    run([sys.executable, "-I", "-B", str(script), str(native)], "R02_RELOCATED_NATIVE_SOURCE_PASS")
    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir",
           "--name", "dc_native_bundle_rehearsal", "--collect-data", "weasyprint",
           "--collect-submodules", "weasyprint", "--hidden-import", "magic", str(script)]
    built = subprocess.run(cmd, cwd=lab, stdin=subprocess.DEVNULL, timeout=300)
    if built.returncode:
        raise RuntimeError("NATIVE_BUNDLE_BUILD_FAILED")
    output = lab / "dist" / "dc_native_bundle_rehearsal"
    shutil.copytree(native, output / "native")
    exe = output / "dc_native_bundle_rehearsal.exe"
    run([str(exe)], "R02_RELOCATED_NATIVE_FROZEN_PASS")
    # Negative: append one byte to copied DB, must deny before importing native code.
    db = output / "native" / "share" / "misc" / "magic.mgc"
    with db.open("ab") as handle:
        handle.write(b"\x00")
    run([str(exe)], "NATIVE_FILE_HASH_MISMATCH", negative=True)
    shutil.copyfile(native / "share" / "misc" / "magic.mgc", db)
    run([str(exe)], "R02_RELOCATED_NATIVE_FROZEN_PASS")
    print("R02_NATIVE_BUNDLE_SOURCE_FROZEN_TAMPER_PASS", flush=True)


if __name__ == "__main__":
    main()
