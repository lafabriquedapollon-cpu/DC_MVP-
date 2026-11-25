"""Own synthetic test roots, secrets, separate process lifecycles and cleanup."""
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile


def run(command):
    base = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix="dc-native-probe-", dir=base))
    try:
        empty = root / "empty-rehearsal.env"
        empty.touch(exist_ok=False)
        # No inherited cabinet credentials/configuration or real user profile.
        keep = ("SystemRoot", "WINDIR", "SystemDrive", "PATH", "PATHEXT", "COMSPEC")
        env = {k: os.environ[k] for k in keep if k in os.environ}
        env.update({k: str(root) for k in (
            "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP",
            "DIGITALCROWN_USER_DATA_DIR", "DIGITALCROWN_CONFIG_DIR",
            "DIGITALCROWN_LOG_DIR", "DIGITALCROWN_RUNTIME_DIR", "MEDIA_ROOT",
            "DC_NATIVE_PROBE_ROOT",
        )})
        env.update(GITHUB_ACTIONS="true", RUNNER_TEMP=str(base),
                   ENVIRONMENT="e2e_install_rehearsal", DIGITALCROWN_ENV_FILE=str(empty),
                   DIGITALCROWN_ISOLATED_RUNTIME="true", TELEMETRY_ENABLED="false",
                   DATABASE_URL=f"sqlite:///{root / 'synthetic-native.db'}",
                   SECRET_KEY=secrets.token_hex(32), CABINET_MASTER_KEY_HEX=secrets.token_hex(32),
                   SQLCIPHER_KEY_HEX=secrets.token_hex(32), MOBILE_PAIRING_KEY_HEX=secrets.token_hex(32),
                   PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1")
        # Explicit local source path only for the non-frozen subprocess.
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
        db = root / "synthetic-native.db"
        for stage in ("write", "read", "wrong", "read"):
            child_env = dict(env)
            before = None
            if stage == "wrong":
                child_env["SQLCIPHER_KEY_HEX"] = secrets.token_hex(32)
                before = hashlib.sha256(db.read_bytes()).hexdigest()
            result = subprocess.run([*command, stage], cwd=root, env=child_env,
                                    capture_output=True, text=True, encoding="utf-8",
                                    errors="replace", timeout=90)
            expected = "R02_NATIVE_WRONG_KEY_DENIED_PASS" if stage == "wrong" else (
                "R02_NATIVE_" + stage.upper() + "_FK_INTEGRITY_PASS")
            # Emit only controlled markers; do not print raw exception messages/keys.
            for line in result.stdout.splitlines():
                if line in {expected, "R02_NATIVE_PLAINTEXT_DENIED_PASS"}:
                    print(line, flush=True)
            if result.returncode or expected not in result.stdout.splitlines():
                error_types = [line.split(":", 1)[0] for line in result.stderr.splitlines()
                               if line.split(":", 1)[0].endswith(("Error", "Exception"))]
                raise RuntimeError(f"NATIVE_PROBE_FAILED stage={stage} rc={result.returncode} types={error_types[-3:]}")
            if stage != "wrong" and "R02_NATIVE_PLAINTEXT_DENIED_PASS" not in result.stdout.splitlines():
                raise RuntimeError("PLAINTEXT_NEGATIVE_MISSING")
            if before is not None and hashlib.sha256(db.read_bytes()).hexdigest() != before:
                raise RuntimeError("WRONG_KEY_MUTATED_DB")
    finally:
        shutil.rmtree(root)
        if root.exists():
            raise RuntimeError("NATIVE_PROBE_CLEANUP_FAILED")
    print("R02_NATIVE_PROBE_RESTART_PERSISTENCE_CLEANUP_PASS", flush=True)


if __name__ == "__main__":
    run(sys.argv[1:])
