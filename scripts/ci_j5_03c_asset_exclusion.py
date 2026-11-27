"""Synthetic installer asset exclusion policy. No clinical activation or licensing inference."""
from pathlib import Path
import stat

MODEL_SUFFIXES={".onnx",".pt",".pth",".safetensors",".ckpt",".tflite",".pb",".h5",".hdf5",".keras",".pkl",".pickle",".gguf",".ggml",".ort"}
# Third-party runtimes may contain serialized internal code/resources (e.g. .pkl);
# inspect model paths as well as explicit executable model formats. Do not
# prohibit dependency internals generically without a qualified inventory.
FORBIDDEN_SUFFIXES={".onnx",".pt",".pth",".safetensors",".ckpt",".tflite",".gguf",".ggml",".ort"}
PRIVATE_SUFFIXES={".db",".sqlite",".sqlite3",".key",".pfx"}
PRIVATE_NAMES={".env",".env.local","firebase_creds.json"}
def check_path(relative):
    parts=Path(relative).parts
    if not parts or Path(relative).is_absolute() or ".." in parts:
        raise RuntimeError("J5_SCIENTIFIC_PATH_REFUSED")
    lower=tuple(p.lower() for p in parts)
    p=Path(lower[-1])
    if "ai_models" in lower or p.suffix in FORBIDDEN_SUFFIXES or p.suffix in PRIVATE_SUFFIXES or p.name in PRIVATE_NAMES or p.name.startswith(".env.") or p.name=="scientific_assets.json":
        raise RuntimeError("J5_UNADMITTED_SCIENTIFIC_OR_PRIVATE_ASSET")
def scan(root):
    root=Path(root)
    if not root.is_dir() or root.is_symlink() or getattr(root.stat(),"st_file_attributes",0)&stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise RuntimeError("J5_SCIENTIFIC_ROOT_REFUSED")
    for p in root.rglob("*"):
        if p.is_symlink() or getattr(p.stat(),"st_file_attributes",0)&stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise RuntimeError("J5_SCIENTIFIC_REPARSE_REFUSED")
        check_path(p.relative_to(root))
        if not (p.is_file() or p.is_dir()):
            raise RuntimeError("J5_SCIENTIFIC_NONFILE_REFUSED")
