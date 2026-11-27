"""Verify the freshly recreated dependency versions against the qualified run.
Version parity is not wheel-hash or OS-image identity. Do not claim a new native suite PASS.
"""
import json
import os
import sys
from pathlib import Path
from importlib import metadata
from packaging.utils import canonicalize_name
from packaging.version import Version


def main():
    if os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("WINDOWS_CI_ONLY")
    lock = json.loads(Path(__file__).with_name("r02-desktop-proven-versions.json").read_text(encoding="utf-8"))
    if lock["schema"] != 1 or sys.version.split()[0] != lock["python"]:
        raise RuntimeError("QUALIFIED_PYTHON_VERSION_MISMATCH")
    expected = lock["packages"]
    installed = {}
    for dist in metadata.distributions():
        name = canonicalize_name(dist.metadata["Name"])
        if name == "pip":
            continue  # bootstrap pip version was not logged in the previous proof
        if name in installed:
            raise RuntimeError("DUPLICATE_INSTALLED_DISTRIBUTION")
        installed[name] = dist.version
    changed = sorted(name for name in expected.keys() | installed.keys()
                     if name not in expected or name not in installed
                     or Version(expected[name]) != Version(installed[name]))
    if changed:
        print("R02_DESKTOP_DEPENDENCY_DRIFT " + ",".join(changed), flush=True)
        raise RuntimeError("DEPENDENCY_REQUALIFICATION_REQUIRED")
    if len(installed) != 187:
        raise RuntimeError("QUALIFIED_GRAPH_COUNT_MISMATCH")
    print("R02_DESKTOP_PROVEN_VERSION_PARITY_PASS count=187", flush=True)


if __name__ == "__main__":
    main()
