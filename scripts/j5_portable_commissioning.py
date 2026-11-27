"""Explicit synthetic commissioning check; no real OWNER or clinical launcher."""
import ctypes
import hashlib
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
from scripts.ci_j5_04c_native_broker import exercise
from scripts.j5_owner_broker import require

def program_files():
    path=ctypes.create_unicode_buffer(32768)
    require(ctypes.windll.shell32.SHGetFolderPathW(None,0x26,None,0,path)==0,"PROGRAM_FILES_UNKNOWN")
    return Path(path.value)/"DigitalCrown-Commissioning-LAB"

def ordinary(path):
    return not path.is_symlink() and not (path.stat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)

def snapshot(root):
    require(root.is_dir() and ordinary(root),"PORTABLE_BROKER_ROOT")
    files={}
    for p in root.rglob("*"):
        require(ordinary(p),"PORTABLE_REPARSE")
        if p.is_file():
            with p.open("rb") as f:files[p.relative_to(root).as_posix()]=hashlib.file_digest(f,"sha256").hexdigest()
        else:require(p.is_dir(),"PORTABLE_NONFILE")
    return files

def main():
    require(os.name=="nt" and getattr(sys,"frozen",False) and sys.argv[1:]==["--selftest"],"EXPLICIT_SYNTHETIC_SELFTEST_REQUIRED")
    require(ctypes.windll.shell32.IsUserAnAdmin(),"ADMIN_REQUIRED_FOR_SYNTHETIC_SCM")
    installed=program_files()
    require(Path(sys.executable)==installed/"commissioning-check"/"dc-commissioning-check.exe","PORTABLE_INSTALL_PATH_REQUIRED")
    require(all(p.is_dir() and ordinary(p) for p in (installed,*installed.parents)),"PORTABLE_INSTALL_REPARSE")
    marker=installed/"COMMISSIONING-NOT-CLINICAL.txt"
    require(marker.is_file() and ordinary(marker) and marker.read_text(encoding="ascii")==
        "SYNTHETIC COMMISSIONING ONLY. No clinical data, real OWNER or release authority. CI scope only.","PORTABLE_MARKER_REQUIRED")
    source=installed/"owner-commissioning"
    before=snapshot(source)
    # A fresh admin-owned scratch folder only, not user or cabinet data.
    # Clone broker to avoid changing installed payload ACLs during SCM test.
    with tempfile.TemporaryDirectory(prefix="dc-portable-synthetic-",dir=installed) as tmp:
        root=Path(tmp)
        clone=root/"owner-commissioning"
        shutil.copytree(source,clone)
        require(snapshot(clone)==before,"PORTABLE_BROKER_COPY_MISMATCH")
        exercise(clone,root)
        require(snapshot(source)==before,"PORTABLE_BROKER_MUTATED")
    require(not root.exists(),"PORTABLE_SCRATCH_RESIDUE")
    print("J5_04C_PORTABLE_SYNTHETIC_SELFTEST_PASS NOT_A_RELEASE",flush=True)
if __name__=="__main__":main()
