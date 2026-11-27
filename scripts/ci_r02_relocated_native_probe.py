"""Qualify a relocated native sidecar in an isolated synthetic CI process.

This executable cannot boot Digital Crown, open patient data, or issue a release.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from xml.sax.saxutils import escape


def require(ok, marker):
    if not ok:
        raise RuntimeError(marker)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


SHARED_FFI_SHA256 = "eff52743773eb550fcc6ce3efc37c85724502233b6b002a35496d828bd7b280a"


def verify(root):
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    require(manifest.get("schema") == 2 and manifest.get("scope") == "synthetic-native-rehearsal",
            "INVALID_NATIVE_MANIFEST")
    shared = manifest.get("shared_runtime", {})
    require(shared.get("name") == "libffi-8.dll" and shared.get("sha256") == SHARED_FFI_SHA256
            and shared.get("provider") == "CPython 3.12.10 x64"
            and sys.version_info[:3] == (3, 12, 10), "INVALID_SHARED_FFI_MANIFEST")
    paths = set()
    for entry in manifest["files"]:
        rel = entry["path"]
        require(re.fullmatch(r"bin/[a-z0-9_.+-]+\.dll", rel) or rel == "share/misc/magic.mgc",
                "INVALID_NATIVE_PATH")
        path = root / rel
        require(rel not in paths and path.is_file() and not path.is_symlink()
                and not (getattr(path.stat(), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT),
                "INVALID_NATIVE_FILE")
        require(path.stat().st_size == entry["bytes"] and sha(path) == entry["sha256"],
                "NATIVE_FILE_HASH_MISMATCH " + rel)
        paths.add(rel)
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    require(actual == paths | {"manifest.json"} and "bin/libffi-8.dll" not in paths,
            "NATIVE_FILE_SET_MISMATCH")
    print("R02_RELOCATED_NATIVE_MANIFEST_PASS", flush=True)
    return paths


def module_paths():
    kernel = ctypes.windll.kernel32
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    enum = ctypes.windll.psapi.EnumProcessModulesEx
    enum.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_ulong,
                     ctypes.POINTER(ctypes.c_ulong), ctypes.c_ulong]
    enum.restype = ctypes.c_int
    handles = (ctypes.c_void_p * 2048)()
    needed = ctypes.c_ulong()
    require(enum(kernel.GetCurrentProcess(), handles, ctypes.sizeof(handles), ctypes.byref(needed), 3)
            and needed.value <= ctypes.sizeof(handles), "MODULE_ENUMERATION_FAILED")
    getname = kernel.GetModuleFileNameW
    getname.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint]
    getname.restype = ctypes.c_uint
    paths = set()
    for handle in handles[:needed.value // ctypes.sizeof(ctypes.c_void_p)]:
        buf = ctypes.create_unicode_buffer(32768)
        length = getname(handle, buf, len(buf))
        require(0 < length < len(buf), "MODULE_PATH_FAILED")
        paths.add(Path(buf.value).resolve(strict=True))
    return paths


def verify_single_ffi(frozen):
    expected = ((Path(sys._MEIPASS) / "libffi-8.dll") if frozen else
                (Path(sys.base_prefix) / "DLLs" / "libffi-8.dll")).resolve(strict=True)
    loaded = {p for p in module_paths() if p.name.lower() == "libffi-8.dll"}
    require(loaded == {expected}, "SHARED_FFI_PROVIDER_MISMATCH")
    require(sha(expected) == SHARED_FFI_SHA256, "SHARED_FFI_HASH_MISMATCH")
    # Real ctypes callback exercises the pinned interpreter ABI.
    callback = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)(lambda n: n + 7)
    require(callback(35) == 42, "SHARED_FFI_CALLBACK_FAILED")
    print("R02_RELOCATED_NATIVE_SHARED_FFI_PASS", flush=True)


def main():
    require(os.name == "nt" and os.environ.get("GITHUB_ACTIONS") == "true", "WINDOWS_CI_ONLY")
    runner = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    frozen = bool(getattr(sys, "frozen", False))
    require(len(sys.argv) == (1 if frozen else 2), "INVALID_ARGUMENTS")
    root = (Path(sys.executable).parent / "native" if frozen else Path(sys.argv[1])).resolve(strict=True)
    require(root.is_relative_to(runner) and root.name in {"native", "native-bundle"}, "INVALID_NATIVE_ROOT")
    listed = verify(root)
    verify_single_ffi(frozen)
    native = root / "bin"
    win = Path(os.environ["SystemRoot"]).resolve(strict=True)
    os.environ["PATH"] = os.pathsep.join(map(str, (native, win / "System32", win)))
    os.environ["MAGIC"] = str(root / "share" / "misc" / "magic.mgc")
    os.environ["WEASYPRINT_DLL_DIRECTORIES"] = str(native)
    with tempfile.TemporaryDirectory(prefix="dc-native-font-", dir=runner) as tmp:
        cfg = Path(tmp)
        fonts = escape((win / "Fonts").as_posix())
        cache = escape((cfg / "cache").as_posix())
        config = cfg / "fonts.conf"
        config.write_text('<?xml version="1.0"?><!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd">'
                          '<fontconfig><dir>' + fonts + '</dir><cachedir>' + cache + '</cachedir></fontconfig>',
                          encoding="utf-8")
        os.environ["FONTCONFIG_FILE"] = str(config)
        os.environ["FONTCONFIG_PATH"] = str(cfg)
        with os.add_dll_directory(str(native)):
            import magic
            from weasyprint import HTML
            import pymupdf
            require(magic.from_buffer(b"%PDF-1.7\n% synthetic\n", mime=True) == "application/pdf",
                    "MIME_PDF_FAILED")
            require(magic.from_buffer(b"synthetic plain text only\n", mime=True) == "text/plain",
                    "MIME_TEXT_FAILED")
            def deny_external(*args, **kwargs):
                raise RuntimeError("EXTERNAL_RESOURCE_REFUSED")
            payload = HTML(string="<html><body><p>Digital Crown synthetic native bundle</p></body></html>",
                           url_fetcher=deny_external).write_pdf()
            with pymupdf.open(stream=payload, filetype="pdf") as doc:
                require(len(doc) == 1 and "Digital Crown synthetic native bundle" in doc[0].get_text(),
                        "PDF_CONTENT_FAILED")
            verify_single_ffi(frozen)
            loaded = module_paths()
            source = Path(r"C:\msys64").resolve()
            require(not any(p.is_relative_to(source) for p in loaded), "EXTERNAL_MSYS_DLL_LOADED")
            require(not any("\\git\\" in str(p).lower() for p in loaded), "EXTERNAL_GIT_DLL_LOADED")
            required = {"libmagic-1.dll", "libpango-1.0-0.dll",
                        "libgobject-2.0-0.dll", "libpangoft2-1.0-0.dll"}
            observed = {p.name.lower() for p in loaded if p.parent == native}
            require(required <= observed and all("bin/" + name in listed for name in observed),
                    "NATIVE_LOADER_PATH_MISMATCH")
            # Diagnose collisions, including Python's own already loaded runtime DLLs.
            # Keep strict denial until ownership and ABI compatibility are established.
            duplicates = sorted(p for p in loaded if "bin/" + p.name.lower() in listed and p.parent != native)
            for p in duplicates:
                if p.is_relative_to(Path(sys.prefix).resolve()):
                    origin = "python-runtime"
                elif p.is_relative_to(Path(sys.base_prefix).resolve()):
                    origin = "base-python"
                elif p.is_relative_to(win):
                    origin = "windows-system"
                else:
                    origin = "other"
                same = sha(p) == sha(native / p.name.lower())
                print("R02_RELOCATED_NATIVE_COLLISION name=" + p.name.lower() +
                      " origin=" + origin + " sha256=" + sha(p) +
                      " same_bytes=" + str(int(same)), flush=True)
            require(not duplicates, "DUPLICATE_EXTERNAL_NATIVE_DLL")
            print(f"R02_RELOCATED_NATIVE_MIME_PDF_PASS dlls={len(observed)}", flush=True)
    print("R02_RELOCATED_NATIVE_" + ("FROZEN" if frozen else "SOURCE") + "_PASS", flush=True)


if __name__ == "__main__":
    main()
