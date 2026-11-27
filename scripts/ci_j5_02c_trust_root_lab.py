"""J5-02C.4 synthetic trust-root boundary. NOT A RELEASE.
A second SQLite DB represents an independent trusted anchor in this LAB only.
Restoring both stores, privileged tampering, and physical independence are NOT proven.
No network, real credentials, release signing, or activation.
"""
import hashlib
import os
import shutil
import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

from dc_release_gate import recovery_authority as authority
from scripts.ci_j5_02c_recovery_lab import (
    Lab, RP, ORIGIN, TTL, canon, sha, b64, decode, fixture, assertion, registration
)
import secrets

DOMAIN = "DIGITAL-CROWN/J5-02C.4/SYNTHETIC/NOT-A-RELEASE"
SOURCE_SHA = "1264f103507ddcc3d442c31e475df11ed00d8203"
ARTIFACT = b"inert synthetic artifact: no executable or release"
EXPECTED = {
    "domain": DOMAIN, "repository": authority.REPOSITORY,
    "repository_id": authority.REPOSITORY_ID, "owner_id": authority.OWNER_ID,
    "source_ref": authority.SOURCE_REF, "source_sha": SOURCE_SHA,
    "artifact_sha256": hashlib.sha256(ARTIFACT).hexdigest(),
    "rp": RP, "origin": ORIGIN,
}

class Denied(ValueError): pass

def snapshot(db):
    schema = [tuple(r) for r in db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")]
    tables = ("state","credentials","challenges","approval_context","receipts")
    def typed(v):
        if isinstance(v, bytes): return ["blob",v.hex()]
        return [type(v).__name__,v]
    rows = {}
    for table in tables:
        rows[table] = [[typed(v) for v in row] for row in db.execute("SELECT * FROM "+table+" ORDER BY 1")]
    return sha(canon([schema,rows])).hex()

class BoundLab(Lab):
    @classmethod
    def provision_fixture(cls, path, anchor, primary, backup, *, clock):
        path,anchor=Path(path),Path(anchor)
        if path.resolve()==anchor.resolve() or path.parent.resolve()==anchor.parent.resolve(): raise Denied("separate anchor required")
        # Explicit one-time fixture provisioning; never silently recreate an anchor.
        if path.exists() or anchor.exists(): raise Denied("already provisioned")
        path.touch(exist_ok=False)
        core=Lab(path)
        core.bootstrap_fixture(primary,backup)
        with core.tx() as db:
            db.execute("CREATE TABLE approval_context(id TEXT PRIMARY KEY, context BLOB NOT NULL)")
            db.execute("CREATE TABLE receipts(id TEXT PRIMARY KEY, context BLOB NOT NULL, epoch INTEGER NOT NULL)")
            digest=snapshot(db)
        anchor.touch(exist_ok=False)
        with sqlite3.connect(anchor) as db:
            db.execute("CREATE TABLE anchor(id INTEGER PRIMARY KEY CHECK(id=1), digest TEXT NOT NULL, high_water INTEGER NOT NULL, version INTEGER NOT NULL)")
            db.execute("INSERT INTO anchor VALUES(1,?,?,0)",(digest,clock()))
        return cls(path,anchor,clock=clock)
    def __init__(self,path,anchor,*,clock=None):
        self.path,self.anchor=Path(path),Path(anchor)
        self.clock=clock or (lambda: time.time_ns()//1_000_000_000)
        self.local=threading.local()
        if self.path.parent.resolve()==self.anchor.parent.resolve(): raise Denied("separate anchor required")
        with self.tx(): pass
    def bootstrap_fixture(self,*args,**kwargs): raise Denied("bootstrap disabled")
    @contextmanager
    def tx(self):
        # Nested calls only from trusted service code. One outer transaction owns both locks.
        if getattr(self.local,"db",None) is not None:
            yield self.local.db
            return
        if not self.path.is_file() or not self.anchor.is_file() or self.path.is_symlink() or self.anchor.is_symlink(): raise Denied("state or anchor missing")
        a=sqlite3.connect(self.anchor.resolve().as_uri()+"?mode=rw",uri=True,isolation_level=None,timeout=10)
        d=None
        try:
            a.execute("BEGIN IMMEDIATE")
            d=sqlite3.connect(self.path.resolve().as_uri()+"?mode=rw",uri=True,isolation_level=None,timeout=10)
            d.row_factory=sqlite3.Row
            d.execute("BEGIN IMMEDIATE")
            row=a.execute("SELECT digest,high_water,version FROM anchor WHERE id=1").fetchone()
            if row is None or row[0]!=snapshot(d): raise Denied("rollback or state divergence")
            now=self.clock()
            if type(now) is not int or now<row[1]: raise Denied("clock rollback")
            self.local.db,self.local.now=d,now
            yield d
            updated=snapshot(d)
            # Commit protected anchor FIRST. A crash before main commit locks service,
            # not a rollback of the anchor. No automatic repair or lowering the anchor.
            a.execute("UPDATE anchor SET digest=?,high_water=?,version=? WHERE id=1",(updated,now,row[2]+1))
            a.commit()
            self.before_main_commit_fixture()
            d.commit()
        except BaseException:
            if d is not None: d.rollback()
            a.rollback()
            raise
        finally:
            self.local.db=None
            self.local.now=None
            if d is not None: d.close()
            a.close()
    def before_main_commit_fixture(self): pass
    def issue_registration(self):
        with self.tx():
            return super().issue_registration(now=self.local.now)
    def register(self,nonce,credential):
        with self.tx():
            return super().register(nonce,credential,now=self.local.now)
    def issue(self,action,actor,target=None):
        if action=="approve": raise Denied("bound approval required")
        with self.tx():
            return super().issue(action,actor,target,now=self.local.now)
    def finish(self,nonce,proof):
        with self.tx() as db:
            row=db.execute("SELECT action FROM challenges WHERE id=?",(nonce,)).fetchone()
            if row is not None and row["action"]=="approve": raise Denied("bound approval required")
            return super().finish(nonce,proof,now=self.local.now)
    @staticmethod
    def context(record,artifact):
        if not isinstance(record,dict) or set(record)!=set(EXPECTED): raise Denied("context schema")
        if any(type(record[k]) is not type(v) or record[k]!=v for k,v in EXPECTED.items()): raise Denied("context binding")
        if not isinstance(artifact,bytes) or sha(artifact).hex()!=EXPECTED["artifact_sha256"]: raise Denied("artifact mismatch")
        authority.exact_sha(record["source_sha"])
        return canon(record)
    def issue_approval(self,actor,record,artifact):
        ctx=self.context(record,artifact)
        with self.tx() as db:
            self.policy(db,"approve",actor,None)
            epoch=self.epoch(db)
            now=self.local.now
            nonce=secrets.token_hex(32)
            challenge=sha(canon([DOMAIN,"approve",actor,epoch,nonce,now,now+TTL,ctx.hex()]))
            db.execute("INSERT INTO challenges VALUES (?,?, 'approve',?,NULL,?,?,?,0)",(nonce,challenge,actor,epoch,now,now+TTL))
            db.execute("INSERT INTO approval_context VALUES (?,?)",(nonce,ctx))
            return nonce,challenge
    def finish_approval(self,nonce,proof,record,artifact):
        ctx=self.context(record,artifact)
        with self.tx() as db:
            row=db.execute("SELECT context FROM approval_context WHERE id=?",(nonce,)).fetchone()
            if row is None or row["context"]!=ctx: raise Denied("unbound challenge")
            # The current role, epoch, signature, RP, origin, challenge and TTL
            # are validated by the previously qualified lifecycle.
            super().finish(nonce,proof,now=self.local.now)
            db.execute("INSERT INTO receipts VALUES (?,?,?)",(nonce,ctx,self.epoch(db)))
            return {"status":"SYNTHETIC_APPROVAL_ONLY","id":nonce,"context_sha256":sha(ctx).hex()}
    def receipt_valid(self,nonce,record,artifact):
        ctx=self.context(record,artifact)
        with self.tx() as db:
            r=db.execute("SELECT context,epoch FROM receipts WHERE id=?",(nonce,)).fetchone()
            return r is not None and r["context"]==ctx and r["epoch"]==self.epoch(db)

class Tests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        root=Path(t.name)
        (root/"restorable").mkdir();(root/"protected_fixture").mkdir()
        self.path=root/"restorable"/"lab.sqlite"
        self.anchor=root/"protected_fixture"/"anchor.sqlite"
        self.now=1000
        self.p,self.b,self.c=fixture(),fixture(),fixture()
        self.lab=BoundLab.provision_fixture(self.path,self.anchor,self.p[:2],self.b[:2],clock=lambda:self.now)
        self.saved=root/"saved.sqlite"
    def open(self): return BoundLab(self.path,self.anchor,clock=lambda:self.now)
    def issue(self): return self.lab.issue_approval(self.p[0],dict(EXPECTED),ARTIFACT)
    def finish(self,q,**kw): return self.lab.finish_approval(q[0],assertion(self.p,q[1]),kw.get("record",dict(EXPECTED)),kw.get("artifact",ARTIFACT))
    def candidate(self):
        q=self.lab.issue_registration()
        self.lab.register(q[0],registration(self.c,q[1]))
        q=self.lab.issue("prove",self.c[0])
        self.lab.finish(q[0],assertion(self.c,q[1]))
    def save(self): shutil.copyfile(self.path,self.saved)
    def restore(self): shutil.copyfile(self.saved,self.path)
    def test_01_bound_approval(self):
        q=self.issue();r=self.finish(q)
        self.assertEqual(r["status"],"SYNTHETIC_APPROVAL_ONLY")
        self.assertTrue(self.open().receipt_valid(q[0],dict(EXPECTED),ARTIFACT))
    def test_02_wrong_context(self):
        for k,v in EXPECTED.items():
            with self.subTest(field=k),self.assertRaises(Denied):
                self.lab.issue_approval(self.p[0],dict(EXPECTED,**{k:0 if type(v)is int else "wrong"}),ARTIFACT)
    def test_03_wrong_artifact(self):
        q=self.issue()
        with self.assertRaises(Denied): self.finish(q,artifact=ARTIFACT+b"tamper")
        self.finish(q)
    def test_04_changed_context_at_finish(self):
        q=self.issue()
        with self.assertRaises(Denied): self.finish(q,record=dict(EXPECTED,source_sha="a"*40))
        self.finish(q)
    def test_05_unbound_path(self):
        with self.assertRaises(Denied): self.lab.issue("approve",self.p[0])
        q=self.issue()
        with self.assertRaises(Denied): self.lab.finish(q[0],assertion(self.p,q[1]))
    def test_06_replay(self):
        q=self.issue();self.finish(q);self.lab=self.open()
        with self.assertRaises(ValueError): self.finish(q)
    def test_07_rollback_used_nonce(self):
        q=self.issue();self.save();self.finish(q);self.restore()
        with self.assertRaisesRegex(Denied,"rollback"): self.open()
    def test_08_rollback_revocation(self):
        self.candidate();self.save()
        q=self.lab.issue("rotate",self.p[0],self.c[0]);self.lab.finish(q[0],assertion(self.p,q[1]))
        self.restore()
        with self.assertRaisesRegex(Denied,"rollback"): self.open()
    def test_09_missing_anchor(self):
        self.anchor.unlink()
        with self.assertRaises(Denied): self.open()
    def test_10_missing_main(self):
        self.path.unlink()
        with self.assertRaises(Denied): self.open()
    def test_11_clock_backward(self):
        q=self.issue();self.now+=10;self.finish(q);self.now-=1
        with self.assertRaisesRegex(Denied,"clock"): self.open()
    def test_12_expired(self):
        q=self.issue();self.now+=TTL
        with self.assertRaises(ValueError): self.finish(q)
    def test_13_crash_window_fail_closed(self):
        q=self.issue()
        def fail(): raise RuntimeError("injected between commits")
        self.lab.before_main_commit_fixture=fail
        with self.assertRaisesRegex(RuntimeError,"injected"): self.finish(q)
        with self.assertRaisesRegex(Denied,"rollback"): self.open()
    def test_14_same_epoch_tamper(self):
        q=self.issue();self.finish(q)
        with sqlite3.connect(self.path) as db: db.execute("UPDATE challenges SET used=0 WHERE id=?",(q[0],))
        with self.assertRaisesRegex(Denied,"rollback"): self.open()
    def test_15_rotation_invalidates_receipt(self):
        q=self.issue();self.finish(q);self.candidate()
        r=self.lab.issue("rotate",self.p[0],self.c[0]);self.lab.finish(r[0],assertion(self.p,r[1]))
        self.assertFalse(self.lab.receipt_valid(q[0],dict(EXPECTED),ARTIFACT))
        with self.assertRaises(ValueError): self.issue()
        n=self.lab.issue_approval(self.c[0],dict(EXPECTED),ARTIFACT)
        self.lab.finish_approval(n[0],assertion(self.c,n[1]),dict(EXPECTED),ARTIFACT)
    def test_16_wrong_signer(self):
        q=self.issue()
        with self.assertRaises(Exception):
            self.lab.finish_approval(q[0],assertion((self.p[0],self.p[1],self.b[2]),q[1]),dict(EXPECTED),ARTIFACT)
        self.finish(q)
    def test_17_concurrent_replay(self):
        q=self.issue();proof=assertion(self.p,q[1])
        def attempt(_):
            try: self.open().finish_approval(q[0],proof,dict(EXPECTED),ARTIFACT);return True
            except ValueError: return False
        with ThreadPoolExecutor(max_workers=8) as ex: self.assertEqual(sum(ex.map(attempt,range(8))),1)
    def test_18_provision_again_denied(self):
        with self.assertRaises(Denied):
            BoundLab.provision_fixture(self.path,self.anchor,self.p[:2],self.b[:2],clock=lambda:self.now)
    def test_19_anchor_and_main_rollback_limit(self):
        # Explicit negative-control documenting the threat boundary.
        q=self.issue();self.save();old=self.saved.with_suffix(".anchor")
        shutil.copyfile(self.anchor,old)
        self.finish(q);self.restore();shutil.copyfile(old,self.anchor)
        self.lab=self.open()
        self.finish(q)  # Both stores rolled back: NOT protected by this LAB.
    def test_20_invalid_role(self):
        with self.assertRaises(ValueError): self.lab.issue_approval(self.b[0],dict(EXPECTED),ARTIFACT)
    def test_21_schema_tamper(self):
        with sqlite3.connect(self.path) as db: db.execute("CREATE TABLE tampered(x)")
        with self.assertRaisesRegex(Denied,"rollback"): self.open()
    def test_22_separate_location(self):
        with self.assertRaises(Denied): BoundLab(self.path,self.path.parent/"other.sqlite",clock=lambda:self.now)

if __name__=="__main__":
    unittest.main(verbosity=2)
