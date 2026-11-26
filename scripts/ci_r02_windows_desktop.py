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


def verify_served_assets():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    base = "http://127.0.0.1:8008"
    with opener.open(base + "/login", timeout=5) as response:
        page = response.read()
        require(response.headers.get_content_type() == "text/html" and b'id="root"' in page,
                "DESKTOP_LOGIN_HTML_MISMATCH")
    with opener.open(base + "/build-manifest.json", timeout=5) as response:
        manifest = json.load(response)
        require(manifest["commit"] == os.environ["GITHUB_SHA"] and manifest["mode"] == "rehearsal",
                "DESKTOP_SERVED_HEAD_MISMATCH")
    with opener.open(base + "/pwa-sw.js", timeout=5) as response:
        require("javascript" in response.headers.get_content_type() and b"push-sw.js" in response.read(),
                "DESKTOP_SERVED_SW_MISMATCH")
    print("R02_DESKTOP_SERVED_HTML_HEAD_SW_PASS", flush=True)


def wait_signal(controller, path, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            require(not path.is_symlink() and path.stat().st_size == 0, "INVALID_BROWSER_SIGNAL")
            return
        require(controller.poll() is None, "DESKTOP_PIPE_CONTROLLER_EXITED")
        time.sleep(.25)
    raise RuntimeError("DESKTOP_PIPE_PHASE_TIMEOUT")


def emit_controller_log(log):
    if not log.is_file():
        return
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        if re.fullmatch(r"[A-Z][A-Z0-9_]+_PASS(?: [A-Za-z0-9_.=+-]+)*", line):
            print(line, flush=True)
        elif re.fullmatch(r"PWA_BROWSER_ACTIVE_STATIC_ONLY_PASS \{\"controlled\":(?:true|false),\"entries\":[0-9]+,\"apiEntries\":0,\"foreignEntries\":0\}", line):
            print(line, flush=True)
        elif re.fullmatch(r"R02_DESKTOP_PIPE_FAILURE phase=[A-Z_]+ type=[A-Za-z0-9_]+", line):
            print(line, flush=True)
        elif line.startswith("INTEGRATION_ERROR "):
            labels = ("login form", "actual PWA registration and precache", "real login API",
                      "dashboard", "authenticated profile GET", "CrownBot launcher",
                      "CrownBot chat tab", "default-off chat", "patient form", "patient POST",
                      "patient detail", "patient detail API", "rendered patient identity",
                      "restart patient route", "restart patient GET", "restart patient identity")
            label = next((v for v in labels if line == "INTEGRATION_ERROR " + v + " timeout"), None)
            print("R02_DESKTOP_DRIVER_REPORTED_ERROR" + (" phase=" + label.replace(" ", "_") if label else ""), flush=True)


def desktop_cycle(repo, root, exe, env):
    node = shutil.which("node")
    require(bool(node), "NODE_MISSING")
    evidence = root / "screenshots"
    evidence.mkdir()
    # Only the CI driver receives the synthetic credentials. No browser command
    # line, logs, or screenshots contain tokens by design.
    driver_env = dict(env)
    driver_env.update(DC_EVIDENCE=str(evidence), DC_BUILT_REHEARSAL="true", DC_PACKAGED_DESKTOP="true")
    tools = Path(os.environ["DC_BROWSER_TOOLS"]).resolve(strict=True)
    runner = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    require(tools.parent == runner and tools.name.startswith("dc-browser-tools-"),
            "INVALID_BROWSER_TOOLS_ROOT")
    driver_env["DC_BROWSER_TOOLS"] = str(tools)
    driver_env["PLAYWRIGHT_BROWSERS_PATH"] = str(tools / "browsers")
    for name in ("ProgramFiles", "ProgramFiles(x86)", "ProgramData", "PUBLIC", "HOMEDRIVE", "HOMEPATH"):
        if name in os.environ:
            driver_env[name.upper()] = os.environ[name]
    controller = None
    browser_log = root / "browser-controller.log"
    try:
        with browser_log.open("wb") as browser_output:
            for stage in ("desktop-serve", "desktop-restart"):
                log = root / (stage + ".log")
                with log.open("wb") as handle:
                    proc = subprocess.Popen([str(exe), stage], env=env, cwd=root, stdin=subprocess.DEVNULL,
                                            stdout=handle, stderr=subprocess.STDOUT)
                    try:
                        wait_health(proc, env)
                        verify_served_assets()
                        if controller is None:
                            controller = subprocess.Popen([node, str(repo / "frontend/scripts/ci-r02-windows-browser.mjs")],
                                env=driver_env, cwd=root, stdin=subprocess.DEVNULL,
                                stdout=browser_output, stderr=subprocess.STDOUT)
                            wait_signal(controller, root / "browser-first-pass", 300)
                        else:
                            (root / "browser-restart-ready").touch(exist_ok=False)
                            require(controller.wait(timeout=300) == 0, "DESKTOP_BROWSER_RESTART_FAILED")
                            require((root / "browser-restart-pass").is_file(), "DESKTOP_RESTART_SIGNAL_MISSING")
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
        if controller is not None:
            kill_tree(controller)
        emit_controller_log(browser_log)
