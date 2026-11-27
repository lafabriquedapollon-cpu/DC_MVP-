"""J5-03D: actual SQLCipher portable export/rekey, isolated source slice.
Not full GuidedRestore worker, frozen launcher, physical PC or OWNER activation.
"""
import hashlib
import json
import os
import secrets
import sqlite3
import sys
import tempfile
import types
import zipfile
from contextlib import closing
from pathlib import Path
import unittest

from scripts.restore03_cross_host_lab import load_slice
from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlcipher3 import dbapi2 as sqlcipher

def check(ok, label):
    if not ok:
        raise RuntimeError(label)

def sha(p):
    with p.open("rb") as f:
        return hashlib.file_digest(f,"sha256").hexdigest()

class Restore(unittest.TestCase):
    def test_real_sqlcipher_portable_roundtrip(self):
        check(os.name=="nt" and os.getenv("GITHUB_ACTIONS")=="true","WINDOWS_CI_ONLY")
        for k in ("DATABASE_URL","DIGITALCROWN_USER_DATA_DIR","SQLCIPHER_KEY_HEX","CABINET_MASTER_KEY_HEX","SECRET_KEY","MEDIA_ROOT"):
            check(not os.getenv(k),"INHERITED_RUNTIME_REFUSED")
        with tempfile.TemporaryDirectory(prefix="dc-j5-restore-",dir=os.environ["RUNNER_TEMP"]) as tmp:
            root=Path(tmp)
            source=root/"source.db"
            destination=root/"restored.db"
            media=root/"media";media.mkdir()
            (media/"synthetic.txt").write_bytes(b"INERT_RESTORE_FIXTURE")
            key_a,key_b,secret,master_a,master_b=[secrets.token_hex(32) for _ in range(5)]
            os.environ.update(DIGITALCROWN_USER_DATA_DIR=str(root/"source-data"),SQLCIPHER_KEY_HEX=key_a,CABINET_MASTER_KEY_HEX=master_a,CABINET_PORT="8008")
            backup,archive,bundle=load_slice()
            db_module=types.ModuleType("backend.database")
            sys.modules["backend.database"]=db_module
            import backend
            backend.database=db_module
            def bind(path,key):
                eng=create_engine(URL.create("sqlite+pysqlcipher",password=key,database=str(path)),module=sqlcipher)
                db_module.engine=eng
                return eng
            eng=bind(source,key_a)
            try:
                with closing(sqlcipher.connect(str(source))) as db:
                    db.execute("PRAGMA key = '"+key_a+"'")
                    db.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT)")
                    db.execute("CREATE TABLE patients(id INTEGER PRIMARY KEY, nom TEXT)")
                    db.execute("CREATE TABLE truth(value TEXT NOT NULL)")
                    db.execute("INSERT INTO truth VALUES ('SYNTHETIC_ONLY')")
                    db.execute("PRAGMA user_version=63")
                    db.commit()
                archive._validate_database_file(source,"pysqlcipher")
                orig=sha(source)
                pack=root/"synthetic.dcbundle"
                report=bundle.create_bundle(pack,secret,media_root=media)
                self.assertEqual(report["sha256"],sha(pack))
                self.assertEqual(sha(source),orig)
                with zipfile.ZipFile(pack) as z:
                    self.assertEqual(set(z.namelist()),{"manifest.json","payload.enc"})
                    self.assertNotIn(b"SYNTHETIC_ONLY",z.read("payload.enc"))
                print("J5_REAL_SQLCIPHER_EXPORT_PASS",flush=True)
            finally:eng.dispose()
            os.environ.update(DIGITALCROWN_USER_DATA_DIR=str(root/"target-data"),SQLCIPHER_KEY_HEX=key_b,CABINET_MASTER_KEY_HEX=master_b)
            eng=bind(destination,key_b)
            try:
                bad=root/"wrong.zip"
                with self.assertRaises(ValueError):bundle.to_local_guided_restore_archive(pack,secrets.token_hex(32),bad,active_engine=("sqlite","pysqlcipher"))
                self.assertFalse(bad.exists())
                damaged=root/"damaged.dcbundle"
                with zipfile.ZipFile(pack) as z,zipfile.ZipFile(damaged,"w") as out:
                    out.writestr("manifest.json",z.read("manifest.json"))
                    blob=bytearray(z.read("payload.enc"));blob[0]^=1
                    out.writestr("payload.enc",blob)
                with self.assertRaises(ValueError):bundle.to_local_guided_restore_archive(damaged,secret,bad,active_engine=("sqlite","pysqlcipher"))
                self.assertFalse(bad.exists())
                restore=root/"restore.zip"
                bundle.to_local_guided_restore_archive(pack,secret,restore,active_engine=("sqlite","pysqlcipher"))
                with zipfile.ZipFile(restore) as z:
                    db_enc=root/"db.enc";db_enc.write_bytes(z.read("database.db.enc"))
                    media_enc=root/"media.enc";media_enc.write_bytes(z.read("media.zip.enc"))
                    manifest=json.loads(z.read("manifest.json"))
                archive._decrypt_backup_key(db_enc,destination)
                archive._validate_database_file(destination,"pysqlcipher")
                with closing(sqlcipher.connect(str(destination))) as db:
                    db.execute("PRAGMA key = '"+key_b+"'")
                    self.assertEqual(db.execute("SELECT value FROM truth").fetchone()[0],"SYNTHETIC_ONLY")
                    self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0],63)
                    self.assertEqual(db.execute("SELECT count(*) FROM patients").fetchone()[0],0)
                with closing(sqlcipher.connect(str(destination))) as db:
                    db.execute("PRAGMA key = '"+key_a+"'")
                    with self.assertRaises(sqlcipher.DatabaseError):db.execute("SELECT * FROM truth").fetchall()
                with closing(sqlite3.connect(str(destination))) as db:
                    with self.assertRaises(sqlite3.DatabaseError):db.execute("SELECT * FROM truth").fetchall()
                out=root/"restored-media";archive._extract_encrypted_media(media_enc,out)
                self.assertEqual((out/"synthetic.txt").read_bytes(),b"INERT_RESTORE_FIXTURE")
                self.assertEqual(manifest["portable"]["config"]["destination_policy"]["license"],"rebind")
                self.assertEqual(sha(source),orig)
                print("J5_REAL_SQLCIPHER_REKEY_REOPEN_MEDIA_PASS",flush=True)
                print("J5_WRONG_KEY_TAMPER_WRONG_PHRASE_DENIED_PASS",flush=True)
            finally:eng.dispose()
        print("J5_PRIVATE_TEMP_CLEANUP_PASS",flush=True)

if __name__=="__main__":unittest.main(verbosity=2)
