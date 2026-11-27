"""Build a CI-only backend PE using real source import observations, no release."""
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from importlib import metadata
if not getattr(sys, "frozen", False):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_r02_windows_desktop import stage_assets, desktop_cycle
from ci_r02_installer_rehearsal import installed_bundle, directory_inventory, assert_directory_inventory
from ci_j5_03c_asset_exclusion import scan as scan_unadmitted_assets


def require(ok, marker):
    if not ok:
        raise RuntimeError(marker)


def run(command, env, cwd, expected, timeout):
    out = subprocess.run(command, env=env, cwd=cwd, stdin=subprocess.DEVNULL,
                         capture_output=True, encoding="utf-8", errors="replace", timeout=timeout)
    observed = set()
    lines = out.stdout.splitlines()
    for line in lines:
        if line.startswith("R02_BACKEND_OBSERVED_IMPORTS="):
            values = json.loads(line.split("=", 1)[1])
            require(all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", v) for v in values), "INVALID_IMPORT_NAME")
            observed.update(values)
        elif re.fullmatch(r"J5_03E_[A-Z_]+(?: [A-Za-z0-9_.=+-]+)*", line):
            print(line, flush=True)
        elif re.fullmatch(r"(?:R02_BACKEND_[A-Z_-]+|R02_DESKTOP_[A-Z_]+|R02_INSTALLER_[A-Z_]+|R02_RELOCATED_NATIVE_[A-Z_]+)(?: [A-Za-z0-9_.=+-]+)*", line) or re.fullmatch(r"(?:FASTAPI_IMPORT_PASS|OPERATOR_BASELINE_METADATA_PASS|PRINT_AUDIT_[A-Z_]+|SQLCIPHER_WRONG_KEY_DENIED_PASS|NONEMPTY_BASELINE_REFUSED_PASS|SYNTHETIC_FIXTURE_FK_INTEGRITY_PASS|FRESH_SQLCIPHER_BASELINE_PASS|SYNTHETIC_FIXTURE_PASS)(?: [A-Za-z0-9_.=+-]+)*", line):
            print(line, flush=True)
    require(out.returncode == 0 and expected in lines, "BACKEND_CHILD_FAILED " + expected)
    return observed


def child_env(root, lab):
    # Construct from an allowlist, not inherited project configuration or tokens.
    keep = ("SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "PROCESSOR_ARCHITECTURE",
            "NUMBER_OF_PROCESSORS", "SYSTEMDRIVE", "RUNNER_TEMP")
    env = {key.upper(): os.environ[key] for key in keep if key in os.environ}
    win = Path(os.environ["SystemRoot"])
    env["PATH"] = os.pathsep.join(map(str, (win / "System32", win)))
    for key in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP",
                "DIGITALCROWN_USER_DATA_DIR", "DIGITALCROWN_CONFIG_DIR",
                "DIGITALCROWN_LOG_DIR", "DIGITALCROWN_RUNTIME_DIR", "MEDIA_ROOT"):
        env[key] = str(root)
    empty = root / "empty-rehearsal.env"
    empty.touch(exist_ok=False)
    env.update(GITHUB_ACTIONS="true", ENVIRONMENT="e2e_install_rehearsal",
               DC_LAB_ROOT=str(root), DATABASE_URL=f"sqlite:///{root / 'fresh-rehearsal.db'}",
               DIGITALCROWN_ENV_FILE=str(empty), DIGITALCROWN_ISOLATED_RUNTIME="true",
               DIGITALCROWN_INSTANCE_ID=secrets.token_hex(16), TELEMETRY_ENABLED="false",
               HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_DATASETS_OFFLINE="1",
               SECRET_KEY=secrets.token_hex(32), CABINET_MASTER_KEY_HEX=secrets.token_hex(32),
               SQLCIPHER_KEY_HEX=secrets.token_hex(32), MOBILE_PAIRING_KEY_HEX=secrets.token_hex(32))
    return env


def stage_source(repo, lab):
    source = lab / "backend-source"
    source.mkdir()
    git = shutil.which("git")
    require(bool(git), "GIT_MISSING")
    names = subprocess.check_output([git, "-C", str(repo), "ls-files", "-z", "--", "backend", "dc_release_gate", "relay"],
                                    timeout=20).decode("utf-8").split("\0")
    count = 0
    for name in names:
        if not name:
            continue
        rel = Path(name)
        require(not rel.is_absolute() and ".." not in rel.parts, "UNSAFE_SOURCE_PATH")
        if rel.suffix != ".py" and not (name.startswith("backend/templates/") and rel.suffix == ".html"):
            continue
        if "tests" in rel.parts or rel.name.startswith("test_"):
            continue
        file = repo / rel
        require(file.is_file() and not file.is_symlink() and not (
            getattr(file.stat(), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT),
            "UNSAFE_SOURCE_FILE")
        target = source / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(file, target)
        count += 1
    require(all((source / name).is_file() for name in (
        "backend/main.py", "relay/__init__.py", "relay/contract.py", "dc_release_gate/__init__.py"
    )) and count > 400, "INCOMPLETE_BACKEND_SOURCE")
    print("R02_BACKEND_STAGED_SOURCE_PASS files=" + str(count), flush=True)
    return source


def main():
    require(os.name == "nt" and os.environ.get("GITHUB_ACTIONS") == "true", "WINDOWS_CI_ONLY")
    lab = Path(sys.prefix).resolve(strict=True)
    runner = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    require(lab.parent == runner and lab.name.startswith("dc-full-deps-"), "INVALID_LAB")
    repo = Path(__file__).resolve().parents[1]
    script = Path(__file__).resolve().with_name("ci_r02_backend_rehearsal_probe.py")
    native = lab / "native-bundle"
    final_only = sys.argv[1:] == ["--desktop-final-only"]
    installer_only = sys.argv[1:] == ["--installer-only"]
    require(not sys.argv[1:] or final_only or installer_only, "UNEXPECTED_HARNESS_ARGUMENT")
    if installer_only:
        require(os.environ.get("GITHUB_REF_NAME") in {"ci/r02-installer-rehearsal-20261126", "ci/r03-conv04-installer-20261127", "ci/j5-03c-scientific-admission-20261127", "ci/j5-03e-installed-restore-20261127"},
                "INSTALLER_BRANCH_REQUIRED")
    if final_only:
        require(os.environ.get("GITHUB_REF_NAME") in {"ci/r02-desktop-final-20261126", "ci/r03-convergence-20261126"},
                "FINAL_ONLY_BRANCH_REQUIRED")
    source = stage_source(repo, lab)
    assets, asset_manifest = stage_assets(repo, lab)
    with tempfile.TemporaryDirectory(prefix="dc-backend-rehearsal-", dir=runner) as temp:
        root = Path(temp)
        env = child_env(root, lab)
        observed = set()
        for stage in ("init", "serve", "restart"):
            observed.update(run([sys.executable, "-I", "-B", str(script), stage, str(source), str(native)],
                                env, root, "R02_BACKEND_SOURCE_" + stage.upper() + "_PASS", 150))
        require({"backend.main", "backend.database", "backend.scripts.ci_fresh_backend_rehearsal",
                 "sqlcipher3.dbapi2", "uvicorn"} <= observed, "INCOMPLETE_REAL_IMPORT_INVENTORY")
        print("R02_BACKEND_SOURCE_IMPORT_INVENTORY_PASS count=" + str(len(observed)), flush=True)
    # A generated lab-only spec avoids Windows command-line length limits. No
    # models, credentials, databases, frontend or historical private assets.
    spec = lab / "dc_backend_rehearsal.spec"
    ffi = Path(sys.base_prefix) / "DLLs" / "libffi-8.dll"
    # Package metadata is public dependency metadata, not runtime configuration.
    packages = sorted({d.metadata["Name"] for d in metadata.distributions()
                       if d.metadata.get("Name") and re.fullmatch(r"[A-Za-z0-9_.-]+", d.metadata["Name"])})
    code = "from PyInstaller.utils.hooks import collect_data_files, copy_metadata\n"
    code += "datas = " + repr([(str(source / "backend/templates"), "backend/templates"),
                              (str(assets), "frontend/dist"),
                              (str(asset_manifest), ".")]) + "\n"
    code += "datas += collect_data_files('weasyprint') + collect_data_files('tzdata')\n"
    code += "for package in " + repr(packages) + ":\n    datas += copy_metadata(package)\n"
    code += "a = Analysis(" + repr([str(script)]) + ", pathex=" + repr([str(source), str(script.parent)]) + ", binaries=" + repr([(str(ffi), ".")]) + ", datas=datas, hiddenimports=" + repr(sorted(observed | {"backend.scripts.ci_desktop_integration"})) + ", excludes=['pytest', 'IPython', 'jupyter', 'matplotlib.tests'], noarchive=False)\n"
    code += "pyz = PYZ(a.pure)\nexe = EXE(pyz, a.scripts, [], exclude_binaries=True, name='dc_backend_rehearsal', console=True, upx=False)\n"
    code += "coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name='dc_backend_rehearsal')\n"
    spec.write_text(code, encoding="utf-8")
    buildenv = dict(os.environ)
    win = Path(os.environ["SystemRoot"])
    buildenv["PATH"] = os.pathsep.join(map(str, (lab / "Scripts", Path(sys.base_prefix), win / "System32", win)))
    # Build subprocesses only see the disposable profile; no runtime secrets.
    buildenv["ENVIRONMENT"] = "packaging-rehearsal"
    buildenv.pop("PYTHONPATH", None)
    result = subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", str(spec)],
                            env=buildenv, cwd=lab, stdin=subprocess.DEVNULL, timeout=900)
    require(result.returncode == 0, "BACKEND_PE_BUILD_FAILED")
    bundle = lab / "dist" / "dc_backend_rehearsal"
    exe = bundle / "dc_backend_rehearsal.exe"
    require(exe.is_file() and exe.open("rb").read(2) == b"MZ", "BACKEND_PE_MISSING")
    shutil.copytree(native, bundle / "native")
    # Reject forbidden payloads before boot. Do not publish any binary artifact.
    for file in bundle.rglob("*"):
        if file.is_file():
            require(file.name.lower() not in {".env", ".env.local", "firebase_creds.json"}
                    and file.suffix.lower() not in {".db", ".sqlite", ".sqlite3", ".onnx", ".pt", ".pth"},
                    "FORBIDDEN_BUNDLE_PAYLOAD")
    scan_unadmitted_assets(bundle)
    print("J5_03C_UNADMITTED_ASSETS_EXCLUDED_PASS", flush=True)
    print("R02_BACKEND_REAL_PE_BUILD_PASS", flush=True)
    if installer_only:
        with installed_bundle(bundle, runner) as installed:
            scan_unadmitted_assets(installed)
            print("J5_03C_INSTALLED_ASSET_EXCLUSION_PASS", flush=True)
            installed_exe = installed / exe.name
            installed_dirs = directory_inventory(installed)
            require("_internal/backend/static/uploads" not in installed_dirs,
                    "INSTALLED_LEGACY_UPLOAD_DIR_PRESENT")
            with tempfile.TemporaryDirectory(prefix="dc-backend-rehearsal-", dir=runner) as temp:
                root = Path(temp).resolve(strict=True)
                env = child_env(root, lab)
                env["DC_INSTALLER_REHEARSAL"] = "true"
                env["DC_DESKTOP_HEAD"] = os.environ["GITHUB_SHA"]
                # Normal execution without the CI gate must refuse before creating DB.
                denied = dict(env)
                denied["GITHUB_ACTIONS"] = "false"
                before = set(root.iterdir())
                result = subprocess.run([str(installed_exe), "init"], env=denied, cwd=root,
                                        stdin=subprocess.DEVNULL, capture_output=True,
                                        encoding="utf-8", errors="replace", timeout=60)
                require(result.returncode == 1 and "marker=WINDOWS_CI_ONLY" in result.stdout
                        and set(root.iterdir()) == before, "INSTALLED_NON_CI_ADMISSION_FAILED")
                print("R02_INSTALLER_NON_CI_RUNTIME_DENIAL_PASS", flush=True)
                assert_directory_inventory(installed, installed_dirs)
                # A runtime redirected to the installed tree must refuse before imports.
                denied = dict(env)
                denied["MEDIA_ROOT"] = str(installed / "_internal" / "backend" / "static" / "uploads")
                result = subprocess.run([str(installed_exe), "init"], env=denied, cwd=root,
                                        stdin=subprocess.DEVNULL, capture_output=True,
                                        encoding="utf-8", errors="replace", timeout=60)
                require(result.returncode == 1 and "marker=INVALID_ISOLATED_PATH MEDIA_ROOT" in result.stdout
                        and set(root.iterdir()) == before, "INSTALLED_MEDIA_REDIRECTION_ACCEPTED")
                assert_directory_inventory(installed, installed_dirs)
                print("R02_INSTALLER_MEDIA_REDIRECTION_DENIAL_PASS", flush=True)
                for stage in ("init", "serve", "restart"):
                    run([str(installed_exe), stage], env, root,
                        "R02_BACKEND_FROZEN_" + stage.upper() + "_PASS", 180)
                    assert_directory_inventory(installed, installed_dirs)
                    print("R02_INSTALLER_DIRECTORY_TREE_PASS stage=" + stage, flush=True)
                print("R02_INSTALLER_INSTALLED_BACKEND_RESTART_PASS", flush=True)
            require(not root.exists(), "INSTALLED_DATA_LAB_RESIDUE")
            if os.environ.get("GITHUB_REF_NAME") == "ci/j5-03e-installed-restore-20261127":
                for scenario in ("success", "rollback"):
                    with tempfile.TemporaryDirectory(prefix="dc-backend-rehearsal-", dir=runner) as temp:
                        root = Path(temp).resolve(strict=True)
                        env = child_env(root, lab)
                        media = root / "rehearsal-media"
                        media.mkdir()
                        env.update(DC_INSTALLER_REHEARSAL="true", DC_DESKTOP_HEAD=os.environ["GITHUB_SHA"],
                                   DC_RESTORE_LAB="true", DC_RESTORE_SCENARIO=scenario,
                                   MEDIA_ROOT=str(media), CABINET_PORT="8008",
                                   ALLOWED_ORIGINS="http://127.0.0.1:8008")
                        run([str(installed_exe), "init"], env, root, "R02_BACKEND_FROZEN_INIT_PASS", 180)
                        run([str(installed_exe), "restore-lab"], env, root,
                            "J5_03E_INSTALLED_RESTORE_" + scenario.upper() + "_PASS", 240)
                        assert_directory_inventory(installed, installed_dirs)
                    require(not root.exists(), "J5_03E_RESTORE_LAB_RESIDUE")
                print("J5_03E_INSTALLED_RESTORE_CLEANUP_PASS", flush=True)
        print("R02_INSTALLER_INTEGRATED_PASS", flush=True)
        return
    if not final_only:
        with tempfile.TemporaryDirectory(prefix="dc-backend-rehearsal-", dir=runner) as temp:
            root = Path(temp)
            env = child_env(root, lab)
            for stage in ("init", "serve", "restart"):
                run([str(exe), stage], env, root, "R02_BACKEND_FROZEN_" + stage.upper() + "_PASS", 180)
        print("R02_BACKEND_SOURCE_FROZEN_RESTART_PASS", flush=True)
    else:
        print("R02_DESKTOP_INTEGRATED_CLOSEOUT_ONLY", flush=True)
    with tempfile.TemporaryDirectory(prefix="dc-backend-rehearsal-", dir=runner) as temp:
        root = Path(temp)
        env = child_env(root, lab)
        env["DC_SYNTH_PASSWORD"] = secrets.token_urlsafe(24)
        env["DC_DESKTOP_HEAD"] = os.environ["GITHUB_SHA"]
        env["ALLOWED_ORIGINS"] = "http://127.0.0.1:8008"
        run([str(exe), "desktop-init"], env, root, "R02_BACKEND_FROZEN_DESKTOP-INIT_PASS", 180)
        desktop_cycle(repo, root, exe, env)


if __name__ == "__main__":
    main()
