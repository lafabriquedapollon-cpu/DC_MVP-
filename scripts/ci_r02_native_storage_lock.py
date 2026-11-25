"""Validate the isolated Windows storage rehearsal's complete package slice.

The official runtime and Windows build locks remain unchanged. Extra build-only
tools are pinned to versions observed in the last passing Windows runner.
This is version parity, not wheel-hash or reproducible-build certification.
"""
from importlib import metadata
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
BUILD_ONLY = {"altgraph", "pefile", "pyinstaller-hooks-contrib", "pywin32-ctypes"}
RUNTIME_NAMES = ["annotated-types","anyio","bcrypt","cffi","dnspython","email-validator","fastapi","greenlet","idna","packaging","passlib","pycparser","pydantic","pydantic-core","python-dotenv","setuptools","sqlalchemy","sqlcipher3","starlette","typing-extensions"]


def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def load(path):
    pins = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([^\s;]+)(?:; .+)?", line)
        if match:
            key = normalize(match[1])
            if key in pins:
                raise RuntimeError("DUPLICATE_PIN " + key)
            pins[key] = match[2]
    return pins


def main():
    runtime = load(ROOT / "backend" / "requirements.txt")
    build = load(ROOT / "backend" / "requirements-windows-build.txt")
    rehearsal = load(ROOT / "scripts" / "requirements-r02-native-storage-rehearsal.txt")
    expected_names = set(RUNTIME_NAMES) | BUILD_ONLY | {"pyinstaller"}
    if rehearsal.keys() != expected_names:
        raise RuntimeError("NATIVE_LOCK_SCOPE_MISMATCH")
    for name in RUNTIME_NAMES:
        if runtime.get(name) != rehearsal[name]:
            raise RuntimeError("RUNTIME_VERSION_DRIFT " + name)
    if build.get("pyinstaller") != rehearsal["pyinstaller"]:
        raise RuntimeError("BUILD_VERSION_DRIFT")
    installed = {}
    for dist in metadata.distributions():
        name = normalize(dist.metadata["Name"])
        if name in installed:
            raise RuntimeError("DUPLICATE_DISTRIBUTION " + name)
        installed[name] = dist.version
    pip_version = installed.pop("pip", None)
    if not pip_version:
        raise RuntimeError("PIP_MISSING")
    if installed != rehearsal:
        mismatched = sorted(name for name in installed.keys() | rehearsal.keys()
                            if installed.get(name) != rehearsal.get(name))
        raise RuntimeError("INSTALLED_LOCK_MISMATCH " + ",".join(mismatched))
    print("R02_NATIVE_STORAGE_EXACT_PACKAGE_SET_PASS count=" + str(len(rehearsal)))
    print("R02_NATIVE_STORAGE_RUNTIME_PARITY_PASS count=" + str(len(RUNTIME_NAMES)))
    print("R02_NATIVE_STORAGE_INSTALLER_PIP_VERSION=" + pip_version)


if __name__ == "__main__":
    main()
