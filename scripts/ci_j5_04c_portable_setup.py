"""Native portable installer admission on hosted Windows; never publish plaintext."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import ctypes
from ci_r02_installer_rehearsal import require,ordinary,inventory,compiler,safe_path,environment,run,digest,wait_inno_uninstall_helper

def target():
    p=ctypes.create_unicode_buffer(32768)
    require(ctypes.windll.shell32.SHGetFolderPathW(None,0x26,None,0,p)==0,"PROGRAM_FILES_UNKNOWN")
    return Path(p.value)/"DigitalCrown-Commissioning-LAB"

def exercise_portable(bundle,runner):
    require(os.name=="nt" and os.getenv("GITHUB_ACTIONS")=="true" and os.getenv("RUNNER_ENVIRONMENT")=="github-hosted","PORTABLE_TEST_CI_ONLY")
    dest=target()
    require(not dest.exists() and not dest.is_symlink() and all(ordinary(p) for p in dest.parents),"PORTABLE_TARGET_OCCUPIED")
    expected=inventory(bundle)
    with tempfile.TemporaryDirectory(prefix="dc-installer-rehearsal-",dir=runner) as tmp:
        root=Path(tmp)
        env=environment(root,"unused")
        for key in ("GITHUB_ACTIONS","DC_INSTALLER_LAB_ID","RUNNER_TEMP"):
            env.pop(key,None)
        iss=root/"portable.iss"
        iss.write_text(f'''[Setup]
AppId=DigitalCrown-Commissioning-LAB-NonClinical
AppName=Digital Crown - COMMISSIONING NON CLINICAL
AppVersion=0.0.0
DefaultDirName={{autopf}}\\DigitalCrown-Commissioning-LAB
OutputDir={safe_path(root)}
OutputBaseFilename=DigitalCrown-Commissioning-Setup
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableStartupPrompt=yes
UsePreviousAppDir=no
CreateUninstallRegKey=yes
Uninstallable=yes
Compression=zip
SolidCompression=no
CloseApplications=no
RestartApplications=no
[Files]
Source: "{safe_path(bundle)}\\*"; DestDir: "{{app}}"; Flags: ignoreversion recursesubdirs createallsubdirs
[Run]
Filename: "{{app}}\\commissioning-check\\dc-commissioning-check.exe"; Parameters: "--selftest"; Description: "Run synthetic commissioning check (no clinical use)"; Flags: postinstall unchecked skipifsilent waituntilterminated
[Code]
function GetFileAttributesW(lpFileName: String): LongWord;
  external 'GetFileAttributesW@kernel32.dll stdcall';
function SafeAncestors(P: String): Boolean;
var A: LongWord; Parent: String;
begin
  Result := False;
  repeat
    A := GetFileAttributesW(P);
    if (A = $FFFFFFFF) or ((A and $400) <> 0) or ((A and $10) = 0) then Exit;
    Parent := ExtractFileDir(P);
    if (Parent = P) or (Parent = '') then Break;
    P := Parent;
  until False;
  Result := True;
end;
function ServiceAbsent(): Boolean;
var RC: Integer;
begin
  Result := Exec(ExpandConstant('{{sys}}\\sc.exe'), 'query DigitalCrownOwnerCommissioning', '', SW_HIDE, ewWaitUntilTerminated, RC) and (RC = 1060);
end;
function PrepareToInstall(var NeedsRestart: Boolean): String;
var P: String;
begin
  P := ExpandConstant('{{autopf}}\\DigitalCrown-Commissioning-LAB');
  Result := 'COMMISSIONING SCOPE REFUSED';
  if (CompareText(WizardDirValue,P) = 0) and SafeAncestors(ExtractFileDir(P))
     and (GetFileAttributesW(P) = $FFFFFFFF) and ServiceAbsent() then Result := '';
end;
function InitializeUninstall(): Boolean;
begin
  Result := (CompareText(ExpandConstant('{{app}}'),ExpandConstant('{{autopf}}\\DigitalCrown-Commissioning-LAB')) = 0)
    and SafeAncestors(ExpandConstant('{{app}}')) and ServiceAbsent();
end;
''',encoding="utf-8-sig")
        r=subprocess.run([str(compiler()),"/Qp",str(iss)],env=env,cwd=root,capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=1200)
        if r.returncode:
            for line in (r.stdout+"\n"+r.stderr).splitlines():
                if "Error" in line:print(line,flush=True)
            raise RuntimeError("PORTABLE_INNO_BUILD_FAILED")
        setup=root/"DigitalCrown-Commissioning-Setup.exe"
        require(setup.is_file() and setup.open("rb").read(2)==b"MZ","PORTABLE_SETUP_MISSING")
        setup_hash=digest(setup)
        print("J5_04C_PORTABLE_PE_PASS bytes="+str(setup.stat().st_size)+" sha256="+setup_hash,flush=True)
        args=["/VERYSILENT","/SUPPRESSMSGBOXES","/NORESTART","/SP-"]
        escape=root/"refused"
        require(run([setup,*args,"/DIR="+str(escape)],env,root,60)!=0 and not dest.exists() and not escape.exists(),"PORTABLE_REDIRECT_ACCEPTED")
        dest.mkdir()
        sentinel=dest/"synthetic-existing.txt";sentinel.write_bytes(b"preserve")
        try:require(run([setup,*args],env,root,60)!=0 and sentinel.read_bytes()==b"preserve","PORTABLE_OVERWRITE_ACCEPTED")
        finally:sentinel.unlink();dest.rmdir()
        require(run([setup,*args],env,root,900)==0,"PORTABLE_INSTALL_FAILED")
        actual=inventory(dest)
        require(all(actual.get(k)==v for k,v in expected.items()) and set(actual)-set(expected) in
                ({"unins000.exe","unins000.dat"},{"unins000.exe","unins000.dat","unins000.msg"}),"PORTABLE_PAYLOAD_MISMATCH")
        try:
            controller=dest/"commissioning-check"/"dc-commissioning-check.exe"
            result=subprocess.run([str(controller),"--selftest"],cwd=dest,env=env,capture_output=True,encoding="utf-8",errors="replace",timeout=300)
            for line in result.stdout.splitlines():
                if re.fullmatch(r"J5_04C_[A-Z_]+(?: [A-Za-z0-9_.=+-]+)*",line):print(line,flush=True)
            if result.returncode:
                for line in result.stderr.splitlines()[-12:]:
                    if line.startswith(("RuntimeError: ","ValueError: ","TimeoutError: ","pywintypes.error: ","scripts.j5_owner_store.Denied: ")):print(line[:180],flush=True)
            require(result.returncode==0 and "J5_04C_PORTABLE_SYNTHETIC_SELFTEST_PASS NOT_A_RELEASE" in result.stdout.splitlines(),"PORTABLE_SELFTEST_FAILED")
            denied=subprocess.run([str(dest/"dc_backend_rehearsal.exe"),"init"],cwd=dest,env=env,capture_output=True,timeout=60)
            require(denied.returncode!=0 and b"WINDOWS_CI_ONLY" in denied.stdout,"PORTABLE_CLINICAL_GUARD_REGRESSION")
            require(inventory(dest)==actual,"PORTABLE_PAYLOAD_MUTATED")
            print("J5_04C_PORTABLE_BACKEND_LOCK_AND_PAYLOAD_PASS",flush=True)
        finally:
            require(run([dest/"unins000.exe","/VERYSILENT","/SUPPRESSMSGBOXES","/NORESTART"],env,root,900)==0,"PORTABLE_UNINSTALL_FAILED")
            deadline=time.monotonic()+120
            while dest.exists() and time.monotonic()<deadline:time.sleep(.25)
            require(not dest.exists(),"PORTABLE_UNINSTALL_RESIDUE")
            wait_inno_uninstall_helper(root)
        print("J5_04C_PORTABLE_NATIVE_INSTALL_SELFTEST_UNINSTALL_PASS NOT_A_RELEASE",flush=True)
        if os.environ.get("GITHUB_REF_NAME")=="ci/j5-04c-private-delivery-20261127":
            from ci_j5_04c_sealed_delivery import seal
            seal(setup,runner,setup_hash)
    require(not root.exists(),"PORTABLE_TEMP_RESIDUE")
    print("J5_04C_PORTABLE_CLEANUP_PASS",flush=True)
