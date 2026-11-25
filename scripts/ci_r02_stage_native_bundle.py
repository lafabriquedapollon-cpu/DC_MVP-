"""Stage a closed native DLL rehearsal bundle from the qualified MSYS2 prefix.

No clinical data, application startup, publication or installation. Package hashes
and imported PE edges are evidence for the exact run, not a release certificate.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

import pefile

ANCHORS = {
    "libmagic-1.dll": "73e9ab47916462ca1631cf165385eeb8664333cf7740c54ed6f9e2e2d8f6c798",
    "libpango-1.0-0.dll": "078881c139e7dd422c4cb5f9c43b939712eb7ad4f3d7d25c41639873e8aec6d6",
    "libgobject-2.0-0.dll": "a417864358cbe7a1da74b7cfcc61f7d49b03772b02f29fa611b01a67d5b99632",
    "libpangoft2-1.0-0.dll": "38602e75c85e149bf7294bccb8792f54299daed45509a8ac4b3a18e3921ec56e",
}
SHARED_FFI_SHA256 = "eff52743773eb550fcc6ce3efc37c85724502233b6b002a35496d828bd7b280a"
SEEDS = set(ANCHORS) | {"libfontconfig-1.dll", "libglib-2.0-0.dll",
                        "libharfbuzz-0.dll", "libfreetype-6.dll"}


def require(ok, marker):
    if not ok:
        raise RuntimeError(marker)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ordinary(path):
    return path.is_file() and not path.is_symlink() and not (
        getattr(path.stat(), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def package_owner(rel):
    # The path is constructed solely from a validated DLL basename or fixed DB path.
    bash = r"C:\msys64\usr\bin\bash.exe"
    out = subprocess.run([bash, "-lc", "pacman -Qoq -- /mingw64/" + rel],
                         capture_output=True, text=True, timeout=15, check=True)
    name = out.stdout.strip()
    require(re.fullmatch(r"mingw-w64-x86_64-[A-Za-z0-9_.+-]+", name), "UNAPPROVED_PACKAGE_OWNER")
    info = subprocess.run([bash, "-lc", "pacman -Q -- " + name],
                          capture_output=True, text=True, timeout=15, check=True).stdout.strip()
    require(info.startswith(name + " ") and re.fullmatch(r"[A-Za-z0-9_.+:-]+", info[len(name)+1:]),
            "INVALID_PACKAGE_VERSION")
    return info


def imported_dlls(path):
    pe = pefile.PE(str(path), fast_load=True)
    try:
        require(pe.FILE_HEADER.Machine == 0x8664, "NON_AMD64_DLL " + path.name)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
        ])
        names = set()
        for attr in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
            for item in getattr(pe, attr, ()):
                name = item.dll.decode("ascii").lower()
                require(re.fullmatch(r"[a-z0-9_.+-]+\.dll", name), "INVALID_PE_IMPORT_NAME")
                require(name != "msys-2.0.dll" and name != "cygwin1.dll", "NON_NATIVE_DLL_REFUSED")
                names.add(name)
        return sorted(names)
    finally:
        pe.close()


def imported_ffi_symbols(path):
    pe = pefile.PE(str(path), fast_load=True)
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
        ])
        names = set()
        for attr in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
            for item in getattr(pe, attr, ()):
                if item.dll.decode("ascii").lower() != "libffi-8.dll":
                    continue
                for symbol in item.imports:
                    require(symbol.name is not None, "FFI_ORDINAL_IMPORT_REFUSED")
                    names.add(symbol.name.decode("ascii"))
        return names
    finally:
        pe.close()


def qualify_shared_ffi(root, entries):
    # Verify exact source closure first, then replace the duplicated runtime
    # provider with the observed, hash-pinned CPython DLL.
    require(sys.version_info[:3] == (3, 12, 10), "SHARED_FFI_PYTHON_VERSION_DRIFT")
    dll = Path(sys.base_prefix).resolve(strict=True) / "DLLs" / "libffi-8.dll"
    require(ordinary(dll) and digest(dll) == SHARED_FFI_SHA256, "SHARED_FFI_HASH_DRIFT")
    require(bool(imported_dlls(dll)), "SHARED_FFI_IMPORTS_MISSING")
    required = set()
    consumers = []
    for entry in entries:
        if "libffi-8.dll" in entry["imports"]:
            names = imported_ffi_symbols(root / entry["path"])
            require(bool(names), "FFI_CONSUMER_SYMBOLS_MISSING")
            required.update(names)
            consumers.append(entry["path"])
    ctypes_ext = Path(sys.base_prefix) / "DLLs" / "_ctypes.pyd"
    ctypes_names = imported_ffi_symbols(ctypes_ext)
    require(bool(ctypes_names) and bool(consumers), "FFI_CONSUMER_MISSING")
    required.update(ctypes_names)
    pe = pefile.PE(str(dll), fast_load=True)
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        exported = {sym.name.decode("ascii") for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols
                    if sym.name and sym.forwarder is None}
    finally:
        pe.close()
    missing = sorted(required - exported)
    require(not missing, "SHARED_FFI_MISSING_EXPORTS " + ",".join(missing))
    print("R02_SHARED_FFI_EXPORTS_PASS required=" + str(len(required)) +
          " consumers=" + str(len(consumers) + 1), flush=True)
    # Remove only the locked redundant copy after its provenance was verified.
    redundant = root / "bin" / "libffi-8.dll"
    require(ordinary(redundant), "REDUNDANT_FFI_MISSING")
    redundant.unlink()
    return {"name": "libffi-8.dll", "sha256": SHARED_FFI_SHA256,
            "provider": "CPython 3.12.10 x64", "required_symbols": sorted(required),
            "consumers": sorted(consumers + ["_ctypes.pyd"])}


def main():
    require(os.name == "nt" and os.environ.get("GITHUB_ACTIONS") == "true", "WINDOWS_CI_ONLY")
    lab = Path(sys.prefix).resolve(strict=True)
    require(lab.parent == Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
            and lab.name.startswith("dc-full-deps-"), "INVALID_LAB")
    source = Path(r"C:\msys64\mingw64").resolve(strict=True)
    root = lab / "native-bundle"
    root.mkdir(exist_ok=False)
    (root / "bin").mkdir()
    (root / "share" / "misc").mkdir(parents=True)
    system = Path(os.environ["SystemRoot"]) / "System32"
    todo, processed, entries = set(SEEDS), set(), []
    while todo:
        name = min(todo)
        todo.remove(name)
        if name in processed:
            continue
        path = source / "bin" / name
        require(ordinary(path), "MISSING_NATIVE_DLL " + name)
        sha = digest(path)
        if name in ANCHORS:
            require(sha == ANCHORS[name], "QUALIFIED_DLL_HASH_DRIFT " + name)
        imports = imported_dlls(path)
        for dep in imports:
            if ordinary(source / "bin" / dep):
                if dep not in processed:
                    todo.add(dep)
            else:
                require(dep.startswith(("api-ms-win-", "ext-ms-win-")) or ordinary(system / dep),
                        "UNRESOLVED_PE_IMPORT " + name + " " + dep)
        rel = "bin/" + name
        target = root / rel
        shutil.copyfile(path, target)
        require(digest(target) == sha, "COPY_HASH_MISMATCH")
        owner = package_owner(rel)
        entries.append({"path": rel, "sha256": sha, "bytes": target.stat().st_size,
                        "package": owner, "imports": imports})
        processed.add(name)
    rel = "share/misc/magic.mgc"
    db = source / rel
    require(ordinary(db), "MISSING_MAGIC_DATABASE")
    shutil.copyfile(db, root / rel)
    require(digest(db) == digest(root / rel), "MAGIC_DATABASE_COPY_MISMATCH")
    entries.append({"path": rel, "sha256": digest(db), "bytes": db.stat().st_size,
                    "package": package_owner(rel), "imports": []})
    manifest = {"schema": 1, "scope": "synthetic-native-rehearsal", "files": entries}
    lock = json.loads(Path(__file__).resolve().with_name("r02-native-bundle-lock.json").read_text(encoding="utf-8"))
    actual = {entry["path"]: entry for entry in entries}
    expected = {entry["path"]: entry for entry in lock["files"]}
    require(lock["schema"] == 1 and lock["scope"] == manifest["scope"]
            and len(expected) == len(lock["files"]) and actual == expected,
            "NATIVE_BUNDLE_LOCK_DRIFT")
    print("R02_NATIVE_BUNDLE_EXACT_LOCK_PASS count=" + str(len(actual)), flush=True)
    shared = qualify_shared_ffi(root, entries)
    manifest["schema"] = 2
    manifest["shared_runtime"] = shared
    manifest["files"] = [entry for entry in entries if entry["path"] != "bin/libffi-8.dll"]
    data = json.dumps(manifest, sort_keys=True, indent=2) + "\n"
    (root / "manifest.json").write_text(data, encoding="utf-8")
    # Only non-sensitive public package identity and hash evidence, no binary upload.
    for entry in entries:
        print("R02_NATIVE_BUNDLE_FILE " + json.dumps(entry, sort_keys=True), flush=True)
    print(f"R02_NATIVE_BUNDLE_CLOSURE_PASS dlls={len(processed)} files={len(entries)}", flush=True)
    print("R02_NATIVE_BUNDLE_RUNTIME_LAYOUT_PASS sidecar_files=" + str(len(manifest["files"])) +
          " shared_dlls=1", flush=True)
    print("R02_NATIVE_BUNDLE_MANIFEST_SHA256=" + digest(root / "manifest.json"), flush=True)


if __name__ == "__main__":
    main()
