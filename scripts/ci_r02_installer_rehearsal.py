"""Disposable Windows runner only: exercise real Inno install/uninstall.
No cabinet admission, no distribution, no patient data, no persistent OS changes.
"""
from contextlib import contextmanager
import hashlib
import base64
from importlib import metadata
import ssl
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time


def require(ok, marker):
    if not ok:
        raise RuntimeError(marker)


def ordinary(p):
    return not p.is_symlink() and not (p.stat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def digest(p):
    with p.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


# Only the exact public CA resources of these locked dependencies may enter.
_PUBLIC_CA = {
    "_internal/certifi/cacert.pem": ("certifi", "2026.1.4", "certifi/cacert.pem"),
    "_internal/grpc/_cython/_credentials/roots.pem": ("grpcio", "1.78.0", "grpc/_cython/_credentials/roots.pem"),
}


def verify_public_ca(p, rel):
    if rel not in _PUBLIC_CA:
        # Bundle paths originate from the public build. Never print contents.
        safe = rel if re.fullmatch(r"[A-Za-z0-9_./-]{1,200}", rel) else "unidentified"
        raise RuntimeError("INSTALL_UNAPPROVED_PEM_REFUSED path=" + safe)
    package, version, wheel_path = _PUBLIC_CA[rel]
    dist = metadata.distribution(package)
    require(dist.version == version, "INSTALL_PUBLIC_CA_VERSION_MISMATCH")
    entries = [entry for entry in (dist.files or ()) if entry.as_posix() == wheel_path]
    require(len(entries) == 1, "INSTALL_PUBLIC_CA_RECORD_MISSING")
    entry = entries[0]
    require(entry.hash is not None and entry.hash.mode == "sha256" and entry.size is not None,
            "INSTALL_PUBLIC_CA_RECORD_HASH_MISSING")
    original = Path(dist.locate_file(entry)).resolve(strict=True)
    require(original.is_file() and ordinary(original)
            and original.is_relative_to(Path(sys.prefix).resolve(strict=True)), "INSTALL_PUBLIC_CA_ORIGIN_REFUSED")
    data = p.read_bytes()
    actual_hash = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii").rstrip("=")
    require(len(data) == entry.size and actual_hash == entry.hash.value
            and data == original.read_bytes(), "INSTALL_PUBLIC_CA_IDENTITY_FAILED")
    starts = re.findall(rb"-----BEGIN ([A-Z0-9 ]+)-----", data)
    ends = re.findall(rb"-----END ([A-Z0-9 ]+)-----", data)
    require(starts and starts == ends and set(starts) == {b"CERTIFICATE"}
            and b"PRIVATE KEY" not in data, "INSTALL_NONCERTIFICATE_PEM_REFUSED")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Official CA bundles may contain non-ASCII descriptive comments.
    # OpenSSL's native PEM file parser consumes the original verified bytes.
    # Do not transcode, strip or repair the bundle.
    context.load_verify_locations(cafile=str(p))
    require(p.read_bytes() == data, "INSTALL_PUBLIC_CA_CHANGED_DURING_PARSE")
    require(context.cert_store_stats()["x509"] > 0, "INSTALL_PUBLIC_CA_X509_EMPTY")
    print("R02_INSTALLER_PUBLIC_CA_PASS package="+package+" sha256="+digest(p), flush=True)


def inventory(root):
    require(root.is_dir() and ordinary(root), "INSTALL_ROOT_INVALID")
    result = {}
    for p in root.rglob("*"):
        require(ordinary(p), "INSTALL_REPARSE_REFUSED")
        if p.is_dir():
            continue
        require(p.is_file(), "INSTALL_NONFILE_REFUSED")
        rel = p.relative_to(root).as_posix()
        require(p.name.lower() not in {".env", ".env.local", "firebase_creds.json"}
                and p.suffix.lower() not in {".db", ".sqlite", ".sqlite3", ".onnx", ".pt", ".pth", ".pfx", ".key"},
                "INSTALL_PRIVATE_PAYLOAD_REFUSED")
        if p.suffix.lower() == ".pem":
            verify_public_ca(p, rel)
        result[rel] = (p.stat().st_size, digest(p))
    return result


def run(command, env, cwd, timeout):
    p = subprocess.Popen([str(x) for x in command], env=env, cwd=cwd, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        return p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        subprocess.run([str(Path(os.environ["SystemRoot"])/"System32"/"taskkill.exe"),
                        "/PID", str(p.pid), "/T", "/F"], timeout=15, check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if p.poll() is None:
            p.kill()
        p.wait(timeout=10)
        raise RuntimeError("INSTALLER_PROCESS_TIMEOUT") from None


def safe_path(path):
    value = str(path)
    require(re.fullmatch(r"[A-Za-z]:\\[A-Za-z0-9 _().\\-]+", value) and "'" not in value,
            "UNSAFE_GENERATED_INSTALLER_PATH")
    return value


def compiler():
    path = Path(os.environ["ProgramFiles(x86)"])/"Inno Setup 6"/"ISCC.exe"
    require(path.is_file() and ordinary(path), "INNO_COMPILER_MISSING")
    # Exact tool version is verified in the workflow before calling this helper.
    require(os.environ.get("DC_INNO_VERSION") == "6.7.1", "INNO_VERSION_NOT_QUALIFIED")
    print("R02_INSTALLER_COMPILER_SHA256="+digest(path), flush=True)
    return path


def environment(root, token):
    # No inherited CI token or project environment.
    keys = ("SystemRoot","WINDIR","COMSPEC","PATHEXT","SystemDrive","COMPUTERNAME",
            "USERNAME","USERPROFILE","APPDATA","LOCALAPPDATA","PROGRAMDATA",
            "ProgramFiles","ProgramFiles(x86)","PUBLIC","TEMP","TMP","PATH")
    env = {k.upper(): os.environ[k] for k in keys if k in os.environ}
    temp = root/"temp"
    temp.mkdir()
    env.update(TEMP=str(temp), TMP=str(temp), GITHUB_ACTIONS="true",
               DC_INSTALLER_LAB_ID=token, RUNNER_TEMP=os.environ["RUNNER_TEMP"])
    return env


def make_script(bundle, root, dest, token):
    host = os.environ["COMPUTERNAME"]
    require(re.fullmatch(r"[A-Za-z0-9-]+",host), "INSTALL_HOST_INVALID")
    script = root/"rehearsal.iss"
    # The generated installer can run only within this disposable test session.
    # These are scope markers, not an authentication or clinical trust root.
    script.write_text(f'''[Setup]
AppId=DC-REHEARSAL-{token}
AppName=Digital Crown - SYNTHETIC REHEARSAL ONLY
AppVersion=0.0.0
DefaultDirName={safe_path(dest)}
OutputDir={safe_path(root)}
OutputBaseFilename=dc-rehearsal-setup
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableStartupPrompt=yes
UsePreviousAppDir=no
CreateUninstallRegKey=no
Uninstallable=yes
Compression=zip
SolidCompression=no
CloseApplications=no
RestartApplications=no
[Files]
Source: "{safe_path(bundle)}\\*"; DestDir: "{{app}}"; Flags: ignoreversion recursesubdirs createallsubdirs
[Code]
function IsLab(): Boolean;
begin
  Result := (GetEnv('GITHUB_ACTIONS') = 'true') and
            (GetEnv('DC_INSTALLER_LAB_ID') = '{token}') and
            (GetEnv('COMPUTERNAME') = '{host}') and
            FileExists('{safe_path(root/"lab.marker")}');
end;
function InitializeSetup(): Boolean;
begin
  Result := IsLab();
end;
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if (not IsLab()) or (CompareText(WizardDirValue, '{safe_path(dest)}') <> 0)
     or DirExists('{safe_path(dest)}') or FileExists('{safe_path(dest)}') then
    Result := 'SYNTHETIC REHEARSAL SCOPE REFUSED';
end;
function InitializeUninstall(): Boolean;
begin
  Result := IsLab() and
            (CompareText(ExpandConstant('{{app}}'), '{safe_path(dest)}') = 0);
end;
''',encoding="utf-8-sig")
    return script


def wait_absent(dest):
    for _ in range(120):
        if not dest.exists():
            return
        time.sleep(.25)
    raise RuntimeError("UNINSTALL_RESIDUE")


@contextmanager
def installed_bundle(bundle, runner, negative=False):
    require(os.name=="nt" and os.environ.get("GITHUB_ACTIONS")=="true", "WINDOWS_CI_ONLY")
    runner=runner.resolve(strict=True)
    require(runner==Path(os.environ["RUNNER_TEMP"]).resolve(strict=True), "RUNNER_ROOT_MISMATCH")
    bundle=bundle.resolve(strict=True)
    require(bundle.is_relative_to(runner), "BUNDLE_OUTSIDE_RUNNER")
    expected=inventory(bundle)
    require(expected, "EMPTY_INSTALL_PAYLOAD")
    with tempfile.TemporaryDirectory(prefix="dc-installer-rehearsal-",dir=runner) as temp:
        root=Path(temp).resolve(strict=True)
        require(root.parent==runner and ordinary(root), "INSTALL_LAB_INVALID")
        dest=root/"installed"
        token=secrets.token_hex(16)
        (root/"lab.marker").touch(exist_ok=False)
        (root/"outside-sentinel.txt").write_bytes(b"synthetic preserve")
        env=environment(root,token)
        script=make_script(bundle,root,dest,token)
        built = subprocess.run([str(compiler()),"/Qp",str(script)],env=env,cwd=root,
                               stdin=subprocess.DEVNULL,capture_output=True,text=True,
                               encoding="utf-8",errors="replace",timeout=1200)
        if built.returncode != 0:
            # Compiler errors may identify a script line; never emit the generated script or lab token.
            for line in (built.stdout+"\n"+built.stderr).splitlines():
                if "Error" in line or "error" in line:
                    print(line.replace(token,"[lab-id]"),flush=True)
            raise RuntimeError("INNO_BUILD_FAILED")
        setup=root/"dc-rehearsal-setup.exe"
        require(setup.is_file() and ordinary(setup), "INNO_OUTPUT_MISSING")
        with setup.open("rb") as f:
            require(f.read(2)==b"MZ","INNO_NOT_PE")
        print("R02_INSTALLER_REAL_SETUP_PE_PASS bytes="+str(setup.stat().st_size)+" sha256="+digest(setup),flush=True)
        args=["/VERYSILENT","/SUPPRESSMSGBOXES","/NORESTART","/SP-"]
        if negative:
            denied=dict(env)
            denied.pop("DC_INSTALLER_LAB_ID")
            require(run([setup,*args],denied,root,60)!=0 and not dest.exists(),"INSTALL_WITHOUT_LAB_ACCEPTED")
            escape=root/"refused-destination"
            require(run([setup,*args,"/DIR="+str(escape)],env,root,60)!=0
                    and not escape.exists() and not dest.exists(),"INSTALL_REDIRECTION_ACCEPTED")
            dest.mkdir()
            sentinel=dest/"preexisting.txt"
            sentinel.write_bytes(b"synthetic existing")
            require(run([setup,*args],env,root,60)!=0 and inventory(dest)==
                    {"preexisting.txt":(len(b"synthetic existing"),hashlib.sha256(b"synthetic existing").hexdigest())},
                    "INSTALL_OVERWRITE_ACCEPTED")
            sentinel.unlink()
            dest.rmdir()
            print("R02_INSTALLER_SCOPE_AND_OVERWRITE_DENIAL_PASS",flush=True)
        require(run([setup,*args],env,root,900)==0,"INNO_INSTALL_FAILED")
        actual=inventory(dest)
        extra=set(actual)-set(expected)
        require(extra in ({"unins000.exe","unins000.dat"},{"unins000.exe","unins000.dat","unins000.msg"})
                and all(actual.get(k)==v for k,v in expected.items()), "INSTALLED_FILE_SET_OR_HASH_MISMATCH")
        uninstaller=dest/"unins000.exe"
        print("R02_INSTALLER_EXACT_PAYLOAD_PASS files="+str(len(expected)),flush=True)
        try:
            if negative:
                denied=dict(env)
                denied.pop("DC_INSTALLER_LAB_ID")
                require(run([uninstaller,"/VERYSILENT","/SUPPRESSMSGBOXES","/NORESTART"],denied,root,60)!=0
                        and inventory(dest)==actual,"UNINSTALL_WITHOUT_LAB_ACCEPTED")
                print("R02_INSTALLER_UNAUTHORIZED_UNINSTALL_DENIED_PASS",flush=True)
            yield dest
            require(inventory(dest)==actual,"INSTALLED_PAYLOAD_MUTATED")
        finally:
            require(run([uninstaller,"/VERYSILENT","/SUPPRESSMSGBOXES","/NORESTART"],env,root,900)==0,
                    "INNO_UNINSTALL_FAILED")
            wait_absent(dest)
            require((root/"outside-sentinel.txt").read_bytes()==b"synthetic preserve","UNINSTALL_OUTSIDE_MUTATION")
            print("R02_INSTALLER_UNINSTALL_CLEAN_PASS",flush=True)
    require(not root.exists(),"INSTALL_LAB_RESIDUE")
    print("R02_INSTALLER_LAB_CLEANUP_PASS",flush=True)


if __name__=="__main__":
    require(sys.argv[1:]==["--synthetic-smoke"],"INSTALLER_SMOKE_ARGUMENTS")
    require(os.name=="nt" and os.environ.get("GITHUB_ACTIONS")=="true","WINDOWS_CI_ONLY")
    runner=Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="dc-installer-fixture-",dir=runner) as tmp:
        root=Path(tmp).resolve(strict=True)
        (root/"nested").mkdir()
        (root/"nested"/"fixture.txt").write_bytes(b"synthetic only")
        (root/"README.txt").write_bytes(b"NON CLINICAL REHEARSAL")
        with installed_bundle(root,runner,negative=True) as dest:
            require((dest/"nested"/"fixture.txt").read_bytes()==b"synthetic only","FIXTURE_CONTENT_MISMATCH")
    print("R02_INSTALLER_SYNTHETIC_SMOKE_PASS",flush=True)
