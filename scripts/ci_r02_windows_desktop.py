"""CI-only same-origin browser qualification of a compiled backend."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time
import urllib.request


def require(ok, marker):
    if not ok:
        raise RuntimeError(marker)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stage_assets(repo, lab):
    source = repo / "frontend" / "dist-rehearsal"
    manifest = json.loads((source / "build-manifest.json").read_text(encoding="utf-8"))
    head = os.environ["GITHUB_SHA"]
    require(re.fullmatch(r"[0-9a-f]{40}", head) and manifest["commit"] == head
            and manifest["mode"] == "rehearsal", "UNQUALIFIED_FRONTEND_BUILD")
    allowed = {".html", ".js", ".mjs", ".css", ".json", ".svg", ".png", ".ico",
               ".woff", ".woff2", ".wasm", ".webp", ".jpg", ".jpeg"}
    target = lab / "desktop-assets"
    target.mkdir()
    files = {}
    for file in sorted(source.rglob("*")):
        require(not file.is_symlink() and not (
            getattr(file.stat(), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT),
            "UNSAFE_FRONTEND_ASSET")
        if file.is_dir():
            continue
        rel = file.relative_to(source)
        require(file.is_file() and file.suffix.lower() in allowed
                and not any(part.startswith(".") for part in rel.parts), "UNAPPROVED_FRONTEND_ASSET_TYPE")
        dest = target / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(file, dest)
        require(sha(dest) == sha(file), "ASSET_COPY_MISMATCH")
        files[rel.as_posix()] = sha(dest)
    require({"index.html", "pwa-sw.js", "push-sw.js", "manifest.json", "build-manifest.json"} <= files.keys()
            and any(p.startswith("assets/") and p.endswith(".js") for p in files), "INCOMPLETE_FRONTEND_ASSETS")
    identity = lab / "desktop-assets.json"
    identity.write_text(json.dumps({"sha": head, "files": files}, sort_keys=True), encoding="utf-8")
    print(f"R02_DESKTOP_STAGED_ASSETS_PASS files={len(files)} sha256={sha(identity)}", flush=True)
    return target, identity


def kill_tree(proc):
    if proc.poll() is None:
        taskkill = Path(os.environ["SystemRoot"]) / "System32" / "taskkill.exe"
        subprocess.run([str(taskkill), "/PID", str(proc.pid), "/T", "/F"], timeout=15,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=10)


def wait_health(proc, env):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for _ in range(100):
        require(proc.poll() is None, "DESKTOP_SERVER_EXITED")
        try:
            with opener.open("http://127.0.0.1:8008/health", timeout=2) as r:
                data = json.load(r)
            if data == {"status": "ok", "db": "ok", "instance_id": env["DIGITALCROWN_INSTANCE_ID"]}:
                return
        except (OSError, ValueError):
            pass
        time.sleep(.5)
    raise RuntimeError("DESKTOP_HEALTH_TIMEOUT")


def browser_executable():
    roots = [os.environ.get("ProgramFiles", ""), os.environ.get("ProgramFiles(x86)", "")]
    for root in roots:
        if not root:
            continue
        for rel in ("Google/Chrome/Application/chrome.exe", "Microsoft/Edge/Application/msedge.exe"):
            path = Path(root) / rel
            if path.is_file():
                return path
    raise RuntimeError("CHROMIUM_NOT_FOUND")


def desktop_cycle(repo, root, exe, env):
    node = shutil.which("node")
    require(bool(node), "NODE_MISSING")
    evidence = root / "screenshots"
    evidence.mkdir()
    # Only the CI driver receives the synthetic credentials. No browser command
    # line, logs, or screenshots contain tokens by design.
    driver_env = dict(env)
    driver_env.update(DC_EVIDENCE=str(evidence), DC_BUILT_REHEARSAL="true", DC_PACKAGED_DESKTOP="true")
    browser_env = {k: v for k, v in env.items() if k in {
        "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "PROCESSOR_ARCHITECTURE",
        "NUMBER_OF_PROCESSORS", "SYSTEMDRIVE", "PATH", "HOME", "USERPROFILE",
        "APPDATA", "LOCALAPPDATA", "TEMP", "TMP"}}
    browser = None
    try:
        for stage in ("desktop-serve", "desktop-restart"):
            log = root / (stage + ".log")
            with log.open("wb") as handle:
                proc = subprocess.Popen([str(exe), stage], env=env, cwd=root, stdin=subprocess.DEVNULL,
                                        stdout=handle, stderr=subprocess.STDOUT)
                try:
                    wait_health(proc, env)
                    if browser is None:
                        browser = subprocess.Popen([str(browser_executable()), "--headless",
                            "--disable-background-networking", "--disable-sync", "--disable-extensions",
                            "--no-first-run", "--no-default-browser-check", "--disable-quic",
                            "--proxy-server=http://127.0.0.1:1", "--proxy-bypass-list=127.0.0.1;localhost;[::1]",
                            "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost",
                            "--window-size=1440,900", "--remote-debugging-address=127.0.0.1",
                            "--remote-debugging-port=9222", "--user-data-dir=" + str(root / "chrome"),
                            "http://127.0.0.1:8008/login"], env=browser_env, cwd=root,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    command = [node, str(repo / "frontend/scripts/ci-desktop-integration.mjs")]
                    if stage == "desktop-restart":
                        command.append("--verify-restart")
                    result = subprocess.run(command, env=driver_env, cwd=root, timeout=300,
                                            capture_output=True, text=True, encoding="utf-8", errors="replace")
                    # Only markers; never print response bodies, credentials, CDP expressions.
                    for line in result.stdout.splitlines():
                        if re.fullmatch(r"[A-Z][A-Z0-9_]+_PASS(?: [A-Za-z0-9_.=+-]+)*", line):
                            print(line, flush=True)
                        elif line.startswith("INTEGRATION_ERROR "):
                            print("R02_DESKTOP_DRIVER_REPORTED_ERROR", flush=True)
                    require(result.returncode == 0, "DESKTOP_BROWSER_FAILED")
                    (root / ("stop-" + stage)).touch(exist_ok=False)
                    require(proc.wait(timeout=25) == 0, "DESKTOP_SERVER_SHUTDOWN_FAILED")
                finally:
                    kill_tree(proc)
            lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
            for line in lines:
                if re.fullmatch(r"(?:R02_[A-Z_-]+(?: [A-Za-z0-9_.=+-]+)*|SQLCIPHER_PATIENT_PERSISTENCE_PASS patients=1 dossiers=1)", line):
                    print(line, flush=True)
            require("R02_BACKEND_FROZEN_" + stage.upper() + "_PASS" in lines
                    and "SQLCIPHER_PATIENT_PERSISTENCE_PASS patients=1 dossiers=1" in lines,
                    "DESKTOP_FROZEN_PERSISTENCE_PROOF_MISSING")
        # Publish only known synthetic screenshots, never raw logs/profile/DB.
        approved = {"01-login.png", "02-dashboard.png", "02b-crownbot-default-off.png",
                    "03-patient-form.png", "04-patient-detail.png", "05-recovery-hub.png",
                    "06-patient-restarted.png"}
        required = approved - {"05-recovery-hub.png"}
        present = {p.name for p in evidence.iterdir()}
        require(required <= present <= approved, "DESKTOP_SCREENSHOT_SET_MISMATCH")
        output = Path(os.environ["RUNNER_TEMP"]) / "dc-packaged-desktop-evidence"
        output.mkdir(exist_ok=False)
        for file in evidence.iterdir():
            require(file.is_file() and file.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"), "INVALID_SCREENSHOT")
            shutil.copyfile(file, output / file.name)
        (output / "head.txt").write_text(env["DC_DESKTOP_HEAD"] + "\n", encoding="ascii")
        print("R02_DESKTOP_FROZEN_BROWSER_RESTART_PASS", flush=True)
    finally:
        if browser is not None:
            kill_tree(browser)
