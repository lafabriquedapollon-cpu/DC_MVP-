import tempfile
import unittest
from pathlib import Path
from scripts.ci_j5_03c_asset_exclusion import scan,check_path
class Tests(unittest.TestCase):
    def test_runtime_allowed(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            for n in ("DigitalCrown.exe","_internal/onnxruntime/capi/onnxruntime.dll","_internal/torch/lib/torch_cpu.dll","frontend/dist/index.html","native/libpango-1.0-0.dll"):
                p=root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b"fixture")
            scan(root)
    def test_model_formats(self):
        for ext in (".onnx",".PT",".pth",".safetensors",".ckpt",".tflite",".gguf",".ggml",".ort"):
            with self.subTest(ext=ext),self.assertRaises(RuntimeError):check_path("nested/model"+ext)
    def test_model_root(self):
        for p in ("backend/ai_models","_internal/backend/AI_MODELS/renamed.bin"):
            with self.assertRaises(RuntimeError):check_path(p)
    def test_registry(self):
        with self.assertRaises(RuntimeError):check_path("backend/scientific_assets.json")
    def test_private(self):
        for p in (".env",".env.production","a.sqlite3","a.db","firebase_creds.json","a.pfx","a.key"):
            with self.assertRaises(RuntimeError):check_path(p)
    def test_actual_tree_negative(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);p=root/"nested"/"model.safetensors";p.parent.mkdir();p.write_bytes(b"not a model")
            with self.assertRaises(RuntimeError):scan(root)
    def test_empty_model_directory(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);(root/"AI_MODELS").mkdir()
            with self.assertRaises(RuntimeError):scan(root)
    def test_traversal(self):
        with self.assertRaises(RuntimeError):check_path("../outside")
if __name__=="__main__":unittest.main(verbosity=2)
