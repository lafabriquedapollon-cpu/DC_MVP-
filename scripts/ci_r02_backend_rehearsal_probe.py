"""CI-only actual backend startup rehearsal; never a cabinet launcher."""
import asyncio
import json
import hashlib
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import subprocess
import sys
import urllib.request
import urllib.error
from types import SimpleNamespace

if not getattr(sys, "frozen", False):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_r02_relocated_native_probe import verify, verify_single_ffi, module_paths


def require(ok, marker):
    if not ok:
        raise RuntimeError(marker)


def ordinary(path):
    return not path.is_symlink() and not (
        getattr(path.stat(), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def checked_root():
    require(os.name == "nt" and os.environ.get("GITHUB_ACTIONS") == "true", "WINDOWS_CI_ONLY")
    require(os.environ.get("ENVIRONMENT") == "e2e_install_rehearsal", "REHEARSAL_ONLY")
    runner = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    root = Path(os.environ["DC_LAB_ROOT"])
    require(root.is_absolute() and root.parent.resolve(strict=True) == runner
            and root.name.startswith("dc-backend-rehearsal-") and root.is_dir()
            and ordinary(root), "INVALID_LAB")
    for key in ("DIGITALCROWN_USER_DATA_DIR", "DIGITALCROWN_CONFIG_DIR",
                "DIGITALCROWN_LOG_DIR", "DIGITALCROWN_RUNTIME_DIR", "MEDIA_ROOT",
                "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP"):
        path = Path(os.environ[key])
        expected = root / "rehearsal-media" if key == "MEDIA_ROOT" and os.environ.get("DC_RESTORE_LAB") == "true" else root
        require(path == expected and ordinary(path), "INVALID_ISOLATED_PATH " + key)
    env = root / "empty-rehearsal.env"
    require(Path(os.environ["DIGITALCROWN_ENV_FILE"]) == env and env.is_file()
            and ordinary(env) and env.stat().st_size == 0, "INVALID_ENV_FILE")
    db = root / "fresh-rehearsal.db"
    require(os.environ["DATABASE_URL"] == f"sqlite:///{db}"
            and (not db.exists() or (db.is_file() and ordinary(db))), "INVALID_DB_TARGET")
    require(os.environ.get("DIGITALCROWN_ISOLATED_RUNTIME") == "true", "ISOLATION_REQUIRED")
    return root, db


def network_guard(event, args):
    # Python-layer guard, not an OS network sandbox. No external DNS, sockets,
    # or child processes; the only service is the disposable loopback listener.
    if event in {"socket.connect", "socket.bind"}:
        address = args[1]
        if not isinstance(address, tuple) or address[0] not in {"127.0.0.1", "::1"}:
            raise PermissionError("REHEARSAL_NONLOOPBACK_REFUSED")
    elif event in {"socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyname_ex"}:
        if args[0] not in {"127.0.0.1", "::1", "localhost", None}:
            raise PermissionError("REHEARSAL_DNS_REFUSED")
    elif event in {"subprocess.Popen", "os.system", "os.startfile", "os.spawn"}:
        # Only the installed restore LAB controller can spawn its exact own PE
        # with one of two fixed health stages, never an arbitrary command.
        if (event == "subprocess.Popen" and getattr(sys, "frozen", False)
                and os.environ.get("DC_RESTORE_LAB") == "true"
                and sys.argv[1:] == ["restore-lab"]
                and args[0] == sys.executable
                and args[1] in {subprocess.list2cmdline([sys.executable, stage])
                                for stage in ("restore-health", "restore-fail-health")}
                and args[2] == os.environ["DC_LAB_ROOT"]):
            return
        # The real Windows platform PID check uses tasklist. Permit only the
        # exact filter for the child already launched by this LAB controller.
        if (event == "subprocess.Popen" and getattr(sys, "frozen", False)
                and os.environ.get("DC_RESTORE_LAB") == "true"
                and sys.argv[1:] == ["restore-lab"]):
            pid = os.environ.get("DC_RESTORE_PARENT_PID", "")
            system = Path(os.environ["SystemRoot"]) / "System32" / "tasklist.exe"
            if (pid.isascii() and pid.isdigit() and int(pid) > 0
                    and args[0] == str(system)
                    and args[1] == subprocess.list2cmdline(
                        [str(system), "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"])
                    and args[2] == os.environ["DC_LAB_ROOT"] and args[3] is None):
                return
        raise PermissionError("REHEARSAL_PROCESS_REFUSED")


def check_network_guard():
    with socket.socket() as probe:
        try:
            probe.connect(("192.0.2.1", 9))
        except PermissionError as exc:
            require(str(exc) == "REHEARSAL_NONLOOPBACK_REFUSED", "UNEXPECTED_NETWORK_DENIAL")
        else:
            raise RuntimeError("NETWORK_GUARD_NOT_ENFORCED")
    print("R02_BACKEND_PYTHON_EGRESS_DENIED_PASS", flush=True)


def observed_imports(source):
    roots = (Path(sys.prefix).resolve(), source.resolve())
    names = []
    for name, module in tuple(sys.modules.items()):
        spec = getattr(module, "__spec__", None)
        origin = getattr(spec, "origin", None)
        if (not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", name)
                or getattr(spec, "name", None) != name
                or not isinstance(origin, str) or not Path(origin).is_absolute()):
            continue
        if any(Path(origin).resolve().is_relative_to(root) for root in roots):
            names.append(name)
    return sorted(set(names))


def http(port, path, expected=200):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(f"http://127.0.0.1:{port}{path}", timeout=5) as response:
            code, payload = response.status, response.read(65536)
    except urllib.error.HTTPError as exc:
        code, payload = exc.code, exc.read(65536)
    require(code == expected, "UNEXPECTED_HTTP_STATUS " + str(code))
    return json.loads(payload)


async def exercise_http(app, desktop=False, stop_file=None):
    import uvicorn
    from backend.services.panoramic_service import panoramic_engine
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 8008 if desktop else 0))
        port = listener.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port,
                                               lifespan="on", loop="asyncio",
                                               http="h11", ws="websockets",
                                               timeout_graceful_shutdown=5,
                                               log_level="warning", access_log=False))
        task = asyncio.create_task(server.serve(sockets=[listener]))
        try:
            for _ in range(300):
                if task.done():
                    await task
                    raise RuntimeError("BACKEND_STARTUP_EXITED")
                if server.started:
                    break
                await asyncio.sleep(0.1)
            require(server.started, "BACKEND_STARTUP_TIMEOUT")
            require(not panoramic_engine.is_ready and panoramic_engine.session is None,
                    "UNEXPECTED_CLINICAL_MODEL")
            health = await asyncio.to_thread(http, port, "/health")
            require(health == {"status": "ok", "db": "ok",
                               "instance_id": os.environ["DIGITALCROWN_INSTANCE_ID"]}, "ROOT_HEALTH_MISMATCH")
            api = await asyncio.to_thread(http, port, "/api/health")
            require(api["status"] == "ok" and api["database"] == "ok"
                    and api["environment"] == "e2e_install_rehearsal", "API_HEALTH_MISMATCH")
            require((await asyncio.to_thread(http, port, "/api/health/db"))["status"] == "ok",
                    "DB_HEALTH_MISMATCH")
            require((await asyncio.to_thread(http, port, "/api/health/storage"))["status"] == "ok",
                    "STORAGE_HEALTH_MISMATCH")
            # Non-authenticated clinical read must be denied, not an empty successful response.
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            def denied():
                try:
                    opener.open(f"http://127.0.0.1:{port}/api/patients/", timeout=5).close()
                except urllib.error.HTTPError as exc:
                    return exc.code in (401, 403)
                return False
            require(await asyncio.to_thread(denied), "UNAUTHENTICATED_PATIENT_READ_NOT_DENIED")
            print("R02_BACKEND_LOOPBACK_HEALTH_AUTH_DENIAL_PASS", flush=True)
            if os.environ.get("DC_INSTALLER_REHEARSAL") == "true":
                def installed_assets():
                    with opener.open(f"http://127.0.0.1:{port}/login", timeout=5) as response:
                        require(response.headers.get_content_type()=="text/html" and b'id="root"' in response.read(),
                                "INSTALLED_LOGIN_HTML_INVALID")
                    manifest = http(port, "/build-manifest.json")
                    require(manifest["commit"] == os.environ["DC_DESKTOP_HEAD"]
                            and manifest["mode"] == "rehearsal", "INSTALLED_FRONTEND_HEAD_INVALID")
                    with opener.open(f"http://127.0.0.1:{port}/pwa-sw.js", timeout=5) as response:
                        require("javascript" in response.headers.get_content_type()
                                and b"push-sw.js" in response.read(), "INSTALLED_SW_INVALID")
                await asyncio.to_thread(installed_assets)
                from backend.services import medication_dict
                meta = medication_dict.catalog_metadata()
                require(meta["sources"][0]["record_count"] == 0 and not meta["sources"][0]["available"]
                        and not meta["sources"][0]["current_marketing_status_verified"]
                        and medication_dict.search_regulatory_presentations("SYNTHETIC") == [],
                        "INSTALLED_UNAPPROVED_AMMPS_EXPOSED")
                print("R02_INSTALLER_SERVED_FRONTEND_AMMPS_DENIAL_PASS", flush=True)
            if desktop:
                require(stop_file is not None and not stop_file.exists(), "STALE_STOP_FILE")
                print("R02_DESKTOP_LOOPBACK_READY", flush=True)
                for _ in range(3600):
                    if stop_file.is_file():
                        require(ordinary(stop_file) and stop_file.stat().st_size == 0,
                                "INVALID_STOP_FILE")
                        break
                    if task.done():
                        raise RuntimeError("DESKTOP_SERVER_EARLY_EXIT")
                    await asyncio.sleep(0.1)
                else:
                    raise RuntimeError("DESKTOP_RUN_TIMEOUT")
        finally:
            server.should_exit = True
            await asyncio.wait_for(task, timeout=12)
        require(task.done() and not task.cancelled(), "BACKEND_SHUTDOWN_FAILED")
        print("R02_BACKEND_GRACEFUL_SHUTDOWN_PASS", flush=True)


def main():
    root, db = checked_root()
    frozen = bool(getattr(sys, "frozen", False))
    require(len(sys.argv) == (2 if frozen else 4), "INVALID_ARGUMENTS")
    stage = sys.argv[1]
    desktop = stage in {"desktop-init", "desktop-serve", "desktop-restart"}
    restore = stage in {"restore-lab", "restore-health", "restore-fail-health"}
    require(stage in {"init", "serve", "restart"} or (desktop and frozen)
            or (restore and frozen and os.environ.get("DC_RESTORE_LAB") == "true"
                and os.environ.get("DC_INSTALLER_REHEARSAL") == "true"), "INVALID_STAGE")
    if restore:
        require(os.environ.get("DC_RESTORE_SCENARIO") in {"success", "rollback"}, "INVALID_RESTORE_SCENARIO")
    initial = stage in {"init", "desktop-init"}
    require((initial and not db.exists()) or (not initial and db.is_file()), "INVALID_DB_STATE")
    source = Path(sys._MEIPASS) if frozen else Path(sys.argv[2]).resolve(strict=True)
    native = Path(sys.executable).parent / "native" if frozen else Path(sys.argv[3]).resolve(strict=True)
    require(source.is_relative_to(Path(os.environ["RUNNER_TEMP"]).resolve())
            and native.is_relative_to(Path(os.environ["RUNNER_TEMP"]).resolve()), "INVALID_CODE_ROOT")
    require(not (source / "backend" / ".env").exists()
            and not (source / "backend" / ".env.local").exists(), "PRIVATE_ENV_REFUSED")
    require(not (source / "backend" / "ai_models").exists(), "MODEL_DIRECTORY_REFUSED")
    if desktop or os.environ.get("DC_INSTALLER_REHEARSAL") == "true":
        require(frozen, "INSTALLER_FROZEN_REQUIRED")
        dist = source / "frontend" / "dist"
        manifest = json.loads((source / "desktop-assets.json").read_text(encoding="utf-8"))
        require(manifest["sha"] == os.environ["DC_DESKTOP_HEAD"], "FRONTEND_HEAD_MISMATCH")
        expected = manifest["files"]
        actual = {p.relative_to(dist).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in dist.rglob("*") if p.is_file() and ordinary(p)}
        require(actual == expected and "index.html" in actual and "pwa-sw.js" in actual,
                "FRONTEND_ASSET_SET_MISMATCH")
        print("R02_DESKTOP_ASSET_INTEGRITY_PASS", flush=True)
    listed = verify(native)
    verify_single_ffi(frozen)
    win = Path(os.environ["SystemRoot"]).resolve(strict=True)
    dlls = native / "bin"
    os.environ["PATH"] = os.pathsep.join(map(str, (dlls, win / "System32", win)))
    os.environ["MAGIC"] = str(native / "share" / "misc" / "magic.mgc")
    os.environ["WEASYPRINT_DLL_DIRECTORIES"] = str(dlls)
    if not frozen:
        sys.path.insert(0, str(source))
    sys.addaudithook(network_guard)
    check_network_guard()
    with os.add_dll_directory(str(dlls)):
        from backend.core.runtime_safety import (
            REHEARSAL_MIGRATION_ONLY, assert_runtime_startup_allowed, database_target_fingerprint,
        )
        os.environ["DIGITALCROWN_ISOLATION_DB_FINGERPRINT"] = database_target_fingerprint(os.environ["DATABASE_URL"])
        require(assert_runtime_startup_allowed(SimpleNamespace(
            ENVIRONMENT=os.environ["ENVIRONMENT"], DATABASE_URL=os.environ["DATABASE_URL"]
        )) == REHEARSAL_MIGRATION_ONLY, "BOOT_POLICY_FAILED")
        from backend.main import app
        from backend import database, models
        from backend.core.schema_runtime import assert_database_at_current_head
        from sqlalchemy import text
        require(database.engine.dialect.driver == "pysqlcipher", "SQLCIPHER_FALLBACK_REFUSED")
        print("R02_BACKEND_REAL_FASTAPI_IMPORT_PASS", flush=True)
        if os.environ.get("DC_INSTALLER_REHEARSAL") == "true":
            from backend.core.media_paths import get_imaging_root
            imaging = get_imaging_root().resolve(strict=True)
            require(imaging == Path(os.environ["MEDIA_ROOT"]) / "uploads" and ordinary(imaging),
                    "INSTALLED_MEDIA_ROOT_NOT_ISOLATED")
            sentinel = imaging / "ci-install-rehearsal-sentinel.bin"
            if initial:
                with sentinel.open("xb") as handle:
                    handle.write(b"synthetic media persistence")
            require(sentinel.is_file() and ordinary(sentinel)
                    and sentinel.read_bytes() == b"synthetic media persistence",
                    "INSTALLED_MEDIA_PERSISTENCE_FAILED")
            print("R02_INSTALLER_MEDIA_PERSISTENCE_PASS", flush=True)
        if restore:
            from backend.core.schema_runtime import assert_database_at_current_head
            assert_database_at_current_head(database.engine)
            if stage == "restore-fail-health":
                database.engine.dispose()
                print("J5_03E_INJECTED_STARTUP_FAILURE", flush=True)
                return
            if stage == "restore-health":
                asyncio.run(exercise_http(app, desktop=True, stop_file=root / "stop-restore-health"))
                database.engine.dispose()
                print("J5_03E_REAL_RESTART_HEALTH_PASS", flush=True)
                return
            from ci_j5_03e_installed_restore import exercise_restore
            exercise_restore(root, db)
            return
        if initial:
            from backend.scripts.ci_fresh_backend_rehearsal import main as baseline
            baseline()
            if desktop:
                from backend.scripts.ci_desktop_integration import main as fixture
                old = sys.argv[:]
                try:
                    sys.argv = [old[0], "seed"]
                    fixture()
                finally:
                    sys.argv = old
            else:
                with database.engine.begin() as conn:
                    conn.execute(models.Base.metadata.tables["users"].insert().values(
                        id=1, email="ci-frozen-fixture@example.invalid",
                        hashed_password="INVALID-NOT-A-PASSWORD-HASH",
                        is_active=False, is_licensed=False, is_archived=True, is_suspended=True,
                    ))
        else:
            assert_database_at_current_head(database.engine)
            asyncio.run(exercise_http(app, desktop=desktop, stop_file=root / ("stop-" + stage)))
            if desktop:
                from backend.scripts.ci_desktop_integration import main as fixture
                old = sys.argv[:]
                try:
                    sys.argv = [old[0], "verify"]
                    fixture()
                finally:
                    sys.argv = old
        with database.engine.connect() as conn:
            require(bool(conn.execute(text("PRAGMA cipher_version")).scalar()), "CIPHER_MISSING")
            require(conn.execute(text("PRAGMA foreign_keys")).scalar() == 1, "FK_DISABLED")
            require(conn.execute(text("PRAGMA integrity_check")).scalar() == "ok", "DB_INTEGRITY_FAILED")
            require(not conn.execute(text("PRAGMA foreign_key_check")).all(), "FK_INTEGRITY_FAILED")
            if desktop:
                require(conn.execute(text("SELECT COUNT(*) FROM users")).scalar() == 3
                        and conn.execute(text("SELECT COUNT(*) FROM patients")).scalar() == (0 if initial else 1),
                        "DESKTOP_SYNTHETIC_PERSISTENCE_FAILED")
            else:
                require(conn.execute(text("SELECT COUNT(*) FROM users")).scalar() == 1
                        and conn.execute(text("SELECT COUNT(*) FROM users WHERE email='ci-frozen-fixture@example.invalid'")).scalar() == 1
                        and conn.execute(text("SELECT COUNT(*) FROM patients")).scalar() == 0,
                        "SYNTHETIC_PERSISTENCE_FAILED")
        database.engine.dispose()
        try:
            with sqlite3.connect(db) as plain:
                plain.execute("SELECT name FROM sqlite_master").fetchall()
        except sqlite3.DatabaseError:
            pass
        else:
            raise RuntimeError("PLAINTEXT_ACCEPTED")
        verify_single_ffi(frozen)
        loaded = module_paths()
        msys = Path(r"C:\msys64").resolve()
        require(not any(p.is_relative_to(msys) or "\\git\\" in str(p).lower() for p in loaded),
                "EXTERNAL_NATIVE_DLL")
        require(not any("bin/" + p.name.lower() in listed and p.parent != dlls for p in loaded),
                "NATIVE_DLL_COLLISION")
        print("R02_BACKEND_SQLCIPHER_PERSISTENCE_PASS", flush=True)
    if not frozen:
        print("R02_BACKEND_OBSERVED_IMPORTS=" + json.dumps(observed_imports(source)), flush=True)
    print("R02_BACKEND_" + ("FROZEN" if frozen else "SOURCE") + "_" + stage.upper() + "_PASS", flush=True)


if __name__ == "__main__":
    try:
        main()
    except BaseException as exc:
        name = getattr(exc, "name", "")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", name):
            name = "unidentified"
        marker = str(exc)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]+(?: [A-Za-z0-9_.+-]+)?", marker):
            marker = "unidentified"
        if getattr(sys, "frozen", False) and os.environ.get("DC_RESTORE_LAB") == "true":
            import traceback
            # Log only allowlisted source basenames/line numbers, never paths,
            # raw exception strings, SQL, environment or fixture values.
            allowed = {"ci_r02_backend_rehearsal_probe.py", "ci_j5_03e_installed_restore.py",
                       "guided_restore.py", "guided_restore_worker.py", "cabinet_bundle.py",
                       "backup_service.py", "guided_restore_archive.py", "portability_license_rebind.py",
                       "platform.py", "subprocess.py", "database.py", "schema_runtime.py"}
            for frame in traceback.extract_tb(exc.__traceback__):
                file = Path(frame.filename).name
                if file in allowed:
                    print(f"J5_03E_SAFE_FRAME file={file} line={frame.lineno}", flush=True)
        print(f"R02_BACKEND_PROBE_FAIL type={type(exc).__name__} module={name} marker={marker}", flush=True)
        raise SystemExit(1) from None
