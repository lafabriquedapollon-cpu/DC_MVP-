"""Windows CI-only dependency qualification; no application startup or model execution."""
from importlib import metadata
import importlib
import os
from pathlib import Path
import re
import sys

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]
CPU = {"torch", "torchvision", "torchaudio"}
NATIVE = ("sqlcipher3.dbapi2", "numpy", "scipy", "onnx", "onnxruntime",
          "torch", "torchvision", "torchaudio", "cv2", "PIL.Image",
          "cryptography", "grpc", "pymupdf", "magic", "weasyprint", "uvicorn")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    require(os.name == "nt" and os.environ.get("GITHUB_ACTIONS") == "true", "WINDOWS_CI_ONLY")
    installed = {canonicalize_name(d.metadata["Name"]): d.version for d in metadata.distributions()}
    expected = {}
    for line in (ROOT / "backend" / "requirements.txt").read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        req = Requirement(line)
        if req.marker is not None and not req.marker.evaluate():
            continue
        name = canonicalize_name(req.name)
        require(name not in expected, "DUPLICATE_REQUIREMENT " + name)
        pins = list(req.specifier)
        require(len(pins) == 1 and pins[0].operator == "==", "NONEXACT_PIN " + name)
        expected[name] = pins[0].version
    for name, pin in expected.items():
        actual = installed.get(name, "")
        require(bool(actual), "MISSING_RUNTIME_PACKAGE " + name)
        version = Version(actual)
        if name in CPU:
            require(version.public == pin and version.local == "cpu", "CPU_WHEEL_PIN_MISMATCH " + name)
        else:
            require(version == Version(pin), "RUNTIME_VERSION_MISMATCH " + name)
    for name in ("onnxruntime-gpu", "onnxruntime-directml", "onnxruntime-qnn"):
        require(name not in installed, "FORBIDDEN_ORT_VARIANT " + name)
    require(installed.get("pyinstaller") == "6.22.3", "BUILD_PIN_MISMATCH")
    print("R02_FULL_WINDOWS_RUNTIME_PINS_PASS count=" + str(len(expected)), flush=True)
    print("R02_FULL_WINDOWS_TRANSITIVE_COUNT=" + str(len(installed.keys() - expected.keys())), flush=True)
    failed = []
    for name in NATIVE:
        try:
            importlib.import_module(name)
        except Exception as exc:
            error = type(exc).__name__
            missing = getattr(exc, "name", None)
            if not isinstance(missing, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", missing):
                missing = "unidentified"
            print(f"R02_FULL_WINDOWS_NATIVE_IMPORT_FAIL module={name} type={error} missing={missing}", flush=True)
            failed.append(name)
        else:
            print("R02_FULL_WINDOWS_NATIVE_IMPORT_PASS module=" + name, flush=True)
    require(not failed, "NATIVE_IMPORT_FAILURES " + ",".join(failed))
    import torch
    import onnxruntime
    require(torch.version.cuda is None and not torch.cuda.is_available(), "TORCH_NOT_CPU")
    providers = onnxruntime.get_available_providers()
    require("CPUExecutionProvider" in providers, "ORT_CPU_PROVIDER_MISSING")
    require(not any(p in providers for p in ("CUDAExecutionProvider", "DmlExecutionProvider",
                "TensorrtExecutionProvider", "QNNExecutionProvider")), "ORT_NONCPU_PROVIDER")
    print("R02_FULL_WINDOWS_CPU_RUNTIME_IMPORTS_PASS", flush=True)


if __name__ == "__main__":
    main()
