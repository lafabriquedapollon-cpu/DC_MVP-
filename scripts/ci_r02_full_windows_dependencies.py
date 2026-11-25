"""Windows CI-only dependency qualification; no application startup or model execution."""
from importlib import metadata
import importlib
import faulthandler
import subprocess
import tempfile
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
    # Each dependency gets an independent bounded process. Then verify the
    # original shared-process import order, which catches DLL interactions.
    failed = []
    for name in NATIVE:
        if not run_bounded(name, 45):
            failed.append(name)
    require(not failed, "NATIVE_IMPORT_FAILURES " + ",".join(failed))
    require(run_bounded("combined", 90), "COMBINED_NATIVE_IMPORT_FAILURE")
    print("R02_FULL_WINDOWS_INDIVIDUAL_AND_COMBINED_IMPORTS_PASS", flush=True)


def native_worker(name):
    require(name in NATIVE or name == "combined", "UNKNOWN_PROBE")
    faulthandler.dump_traceback_later(15, repeat=False)
    try:
        for module in (NATIVE if name == "combined" else (name,)):
            print("R02_FULL_WINDOWS_NATIVE_IMPORT_BEGIN module=" + module, flush=True)
            if module == "magic":
                # Report overlapping package ownership, not machine paths.
                for dist_name in ("python-magic", "python-magic-bin"):
                    dist = metadata.distribution(dist_name)
                    owned = {str(p).replace("\\", "/") for p in (dist.files or ())}
                    magic_files = sorted(p for p in owned if p.startswith("magic/") or p == "magic.py")
                    print(f"R02_MAGIC_DISTRIBUTION {dist_name} version={dist.version} files={len(magic_files)}", flush=True)
            try:
                importlib.import_module(module)
            except Exception as exc:
                missing = getattr(exc, "name", None)
                if not isinstance(missing, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", missing):
                    missing = "unidentified"
                print(f"R02_FULL_WINDOWS_NATIVE_IMPORT_FAIL module={module} type={type(exc).__name__} missing={missing}", flush=True)
                return 1
            print("R02_FULL_WINDOWS_NATIVE_IMPORT_PASS module=" + module, flush=True)
        if name == "combined":
            check_cpu()
        print("R02_FULL_WINDOWS_NATIVE_WORKER_PASS probe=" + name, flush=True)
        return 0
    finally:
        faulthandler.cancel_dump_traceback_later()


def run_bounded(name, seconds):
    print(f"R02_FULL_WINDOWS_BOUNDED_BEGIN probe={name} limit={seconds}", flush=True)
    with tempfile.TemporaryDirectory(prefix="dc-import-probe-", dir=sys.prefix) as temp:
        out_path = Path(temp) / "stdout.txt"
        err_path = Path(temp) / "stderr.txt"
        with out_path.open("wb") as out, err_path.open("wb") as err:
            proc = subprocess.Popen(
                [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--native-worker", name],
                cwd=temp, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            )
            timed_out = False
            try:
                proc.wait(timeout=seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                killer = Path(os.environ["SystemRoot"]) / "System32" / "taskkill.exe"
                try:
                    subprocess.run([str(killer), "/PID", str(proc.pid), "/T", "/F"],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=10, check=False)
                finally:
                    if proc.poll() is None:
                        proc.kill()
                    proc.wait(timeout=10)
                print("R02_FULL_WINDOWS_NATIVE_IMPORT_TIMEOUT probe=" + name, flush=True)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=10)
        lines = out_path.read_text(encoding="utf-8", errors="replace").splitlines()
        for line in lines:
            if re.fullmatch(r"R02_(?:FULL_WINDOWS_[A-Z_]+|MAGIC_DISTRIBUTION)[A-Za-z0-9_.= -]*", line):
                print(line, flush=True)
        if timed_out or proc.returncode != 0:
            # Only basename, line and function from the watchdog traceback.
            stderr = err_path.read_text(encoding="utf-8", errors="replace")
            for file, lineno, function in re.findall(r'File "([^"]+)", line ([0-9]+) in ([A-Za-z0-9_.<>]+)', stderr)[-12:]:
                basename = Path(file).name
                if re.fullmatch(r"[A-Za-z0-9_.<>-]+", basename):
                    print(f"R02_FULL_WINDOWS_STACK {basename}:{lineno} {function}", flush=True)
            print(f"R02_FULL_WINDOWS_NATIVE_WORKER_FAIL probe={name} rc={proc.returncode}", flush=True)
            return False
        return "R02_FULL_WINDOWS_NATIVE_WORKER_PASS probe=" + name in lines


def check_cpu():
    import torch
    import onnxruntime
    require(torch.version.cuda is None and not torch.cuda.is_available(), "TORCH_NOT_CPU")
    providers = onnxruntime.get_available_providers()
    require("CPUExecutionProvider" in providers, "ORT_CPU_PROVIDER_MISSING")
    require(not any(p in providers for p in ("CUDAExecutionProvider", "DmlExecutionProvider",
                "TensorrtExecutionProvider", "QNNExecutionProvider")), "ORT_NONCPU_PROVIDER")
    print("R02_FULL_WINDOWS_CPU_RUNTIME_IMPORTS_PASS", flush=True)


if __name__ == "__main__":
    require(os.name == "nt" and os.environ.get("GITHUB_ACTIONS") == "true", "WINDOWS_CI_ONLY")
    if len(sys.argv) == 3 and sys.argv[1] == "--native-worker":
        raise SystemExit(native_worker(sys.argv[2]))
    require(len(sys.argv) == 1, "UNKNOWN_ARGUMENTS")
    main()
