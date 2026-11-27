"""J5-02C.5 TPM 2.0 NV extend admission, synthetic emulator only.
Never connects to a physical TPM, never a release authority.
"""
import hashlib
import json
import os
import pathlib
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import time
import unittest
import threading
from contextlib import contextmanager

from scripts.ci_j5_02c_trust_root_lab import snapshot, EXPECTED, ARTIFACT, BoundLab
from scripts.ci_j5_02c_recovery_lab import Lab, fixture, assertion, registration, sha, canon, TTL

INDEX = "0x01500020"
DOMAIN = "DC/J5-02C.5/TPM-NV-EXTEND/SYNTHETIC/v1"

class Denied(ValueError): pass

class Emulator:
    def __init__(self,root):
        self.root=pathlib.Path(root)
        self.state=self.root/"vtpm"
        self.state.mkdir()
        self.sock=self.root/"tpm.sock"
        self.auth=self.root/"fixture.auth"
        self.auth.write_bytes(secrets.token_bytes(32))
        self.auth.chmod(0o600)
        self.env=dict(os.environ,TPM2TOOLS_TCTI="swtpm:path="+str(self.sock))
        self.process=None
        self.start()
    def run(self,*args,data=None,ok=True):
        # Explicit TCTI on every command; never falls back to /dev/tpm.
        r=subprocess.run([args[0],"-T",self.env["TPM2TOOLS_TCTI"],*args[1:]],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=self.env,timeout=15)
        if ok and r.returncode: raise RuntimeError(args[0]+" failed: "+r.stderr.decode(errors="replace"))
        return r
    def start(self):
        self.process=subprocess.Popen(["swtpm","socket","--tpm2","--tpmstate","dir="+str(self.state),"--server","type=unixio,path="+str(self.sock),"--ctrl","type=unixio,path="+str(self.sock)+".ctrl","--flags","not-need-init,startup-clear"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(100):
            if self.process.poll() is not None: raise RuntimeError("swtpm exited")
            if self.sock.exists() and pathlib.Path(str(self.sock)+".ctrl").exists():
                if self.run("tpm2_getcap","properties-fixed",ok=False).returncode==0: return
            time.sleep(.05)
        raise RuntimeError("swtpm not ready")
    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.run("tpm2_shutdown","-c",ok=False)
            self.process.terminate()
            try: self.process.wait(timeout=5)
            except subprocess.TimeoutExpired: self.process.kill();self.process.wait()
        self.process=None
        self.sock.unlink(missing_ok=True)
        pathlib.Path(str(self.sock)+".ctrl").unlink(missing_ok=True)
    def close(self):
        self.stop()
    def define(self,*,protected=False):
        if not protected:
            self.run("tpm2_nvdefine","-C","o","-g","sha256","-s","32","-a","nt=extend|authread|authwrite|no_da","-p","file:"+str(self.auth),INDEX)
            return
        # Disposable emulator only. This deliberately non-deletable policy
        # has NO approved hardware provisioning or decommissioning ceremony.
        session=self.root/"anchor-trial.ctx"
        policy=self.root/"anchor-policy.digest"
        self.run("tpm2_startauthsession","-S",str(session))
        try:
            self.run("tpm2_policycommandcode","-S",str(session),"-L",str(policy),"TPM2_CC_NV_Read")
        finally:
            self.run("tpm2_flushcontext",str(session))
        self.run("tpm2_nvdefine","-C","p","-g","sha256","-s","32","-a","nt=extend|authread|authwrite|no_da|platformcreate|policydelete","-L",str(policy),"-p","file:"+str(self.auth),INDEX)
    def read(self):
        r=self.run("tpm2_nvread","-C",INDEX,"-P","file:"+str(self.auth),"-s","32",INDEX)
        if len(r.stdout)!=32: raise Denied("wrong anchor length")
        return r.stdout
    def extend(self,payload):
        if len(payload)!=32: raise Denied("payload length")
        self.run("tpm2_nvextend","-C",INDEX,"-P","file:"+str(self.auth),"-i","-",INDEX,data=payload)
        return self.read()

def digest(previous,sequence,state_digest,now):
    return sha(canon([DOMAIN,previous.hex(),sequence,state_digest,now]))

class Protocol:
    """Fixture adapter for a restorable SQLite DB and TPM extend commitment.
    Serialization is by a single trusted process in this test; multi-process
    broker, authenticated TBS transport and NV deletion policy remain gates.
    """
    def __init__(self,db,tpm):
        self.db=pathlib.Path(db);self.tpm=tpm
    def connect(self):
        if not self.db.is_file(): raise Denied("missing local state")
        return sqlite3.connect(self.db.resolve().as_uri()+"?mode=rw",uri=True,isolation_level=None)
    @staticmethod
    def state(db):
        return sha(canon([list(r) for r in db.execute("SELECT id,status FROM state ORDER BY id")])).hex()
    def provision_fixture(self,now):
        if self.db.exists(): raise Denied("already provisioned")
        self.tpm.define()
        with sqlite3.connect(self.db) as db:
            db.execute("CREATE TABLE state(id TEXT PRIMARY KEY,status TEXT NOT NULL)")
            db.execute("INSERT INTO state VALUES ('primary','active')")
            db.execute("CREATE TABLE checkpoint(id INTEGER PRIMARY KEY CHECK(id=1),prev BLOB NOT NULL,seq INTEGER NOT NULL,clock INTEGER NOT NULL)")
            prev=bytes(32);p=digest(prev,0,self.state(db),now)
            if self.tpm.extend(p)!=sha(prev+p): raise Denied("genesis mismatch")
            db.execute("INSERT INTO checkpoint VALUES (1,?,?,?)",(prev,0,now))
    def check(self,db,now):
        row=db.execute("SELECT prev,seq,clock FROM checkpoint WHERE id=1").fetchone()
        if row is None: raise Denied("missing checkpoint")
        prev,seq,clock=row
        expected=sha(prev+digest(prev,seq,self.state(db),clock))
        if self.tpm.read()!=expected: raise Denied("anchor mismatch")
        if type(now) is not int or now<clock: raise Denied("clock rollback")
        return expected,seq
    def verify(self,now):
        with self.connect() as db:
            return self.check(db,now)
    def transition(self,status,now,*,fail=False):
        db=self.connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            prev,seq=self.check(db,now)
            db.execute("UPDATE state SET status=? WHERE id='primary'",(status,))
            p=digest(prev,seq+1,self.state(db),now)
            expected=sha(prev+p)
            if self.tpm.extend(p)!=expected: raise Denied("extend mismatch")
            if fail: raise RuntimeError("injected between TPM and DB commit")
            db.execute("UPDATE checkpoint SET prev=?,seq=?,clock=? WHERE id=1",(prev,seq+1,now))
            db.commit()
            return expected
        except BaseException:
            db.rollback();raise
        finally: db.close()

class Tests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory(prefix="dc-tpm-");self.addCleanup(t.cleanup)
        self.root=pathlib.Path(t.name)
        self.tpm=Emulator(self.root);self.addCleanup(self.tpm.close)
        self.db=self.root/"restore.sqlite";self.old=self.root/"old.sqlite"
        self.p=Protocol(self.db,self.tpm)
        self.p.provision_fixture(1000)
    def test_01_extend_oracle(self):
        prior,_=self.p.verify(1000)
        after=self.p.transition("revoked",1001)
        self.assertNotEqual(prior,after)
        self.assertEqual(self.p.verify(1001)[0],after)
    def test_02_restore_old_db(self):
        shutil.copyfile(self.db,self.old);self.p.transition("revoked",1001)
        shutil.copyfile(self.old,self.db)
        with self.assertRaisesRegex(Denied,"anchor mismatch"):self.p.verify(1001)
    def test_03_same_sequence_tamper(self):
        self.p.transition("revoked",1001)
        with sqlite3.connect(self.db) as db:db.execute("UPDATE state SET status='active'")
        with self.assertRaisesRegex(Denied,"anchor mismatch"):self.p.verify(1001)
    def test_04_restart_persists(self):
        want=self.p.transition("revoked",1001)
        self.tpm.stop();self.tpm.start()
        self.assertEqual(self.p.verify(1002)[0],want)
    def test_05_wrong_auth_rejected(self):
        prior=self.tpm.read()
        r=self.tpm.run("tpm2_nvextend","-C",INDEX,"-P","hex:"+"00"*32,"-i","-",INDEX,data=bytes(32),ok=False)
        self.assertNotEqual(r.returncode,0);self.assertEqual(self.tpm.read(),prior)
    def test_06_ordinary_write_rejected(self):
        prior=self.tpm.read()
        r=self.tpm.run("tpm2_nvwrite","-C",INDEX,"-P","file:"+str(self.tpm.auth),"-i","-",INDEX,data=bytes(32),ok=False)
        self.assertNotEqual(r.returncode,0);self.assertEqual(self.tpm.read(),prior)
    def test_07_crash_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError,"injected"):self.p.transition("revoked",1001,fail=True)
        with self.assertRaisesRegex(Denied,"anchor mismatch"):self.p.verify(1001)
    def test_08_clock_rollback(self):
        self.p.transition("revoked",1001)
        with self.assertRaisesRegex(Denied,"clock rollback"):self.p.verify(1000)
    def test_09_missing_index_denied(self):
        self.tpm.run("tpm2_nvundefine","-C","o",INDEX)
        with self.assertRaises(RuntimeError):self.p.verify(1001)
    def test_10_redefine_limit(self):
        # Privileged owner hierarchy can reconstruct a recorded commitment.
        # This is a negative-control demonstrating why production deletion
        # authorization and independent enrollment cannot be inferred.
        prior=self.tpm.read()
        with sqlite3.connect(self.db) as db:
            payload=digest(bytes(32),0,self.p.state(db),1000)
        self.tpm.run("tpm2_nvundefine","-C","o",INDEX)
        self.tpm.define();self.assertEqual(self.tpm.extend(payload),prior)
        self.p.verify(1001)
    def test_11_emulator_full_snapshot_limit(self):
        # Software TPM state is itself restorable; deliberately prove limitation.
        self.tpm.stop()
        saved=self.root/"old-vtpm";shutil.copytree(self.tpm.state,saved)
        shutil.copyfile(self.db,self.old)
        self.tpm.start();self.p.transition("revoked",1001);self.tpm.stop()
        shutil.rmtree(self.tpm.state);shutil.copytree(saved,self.tpm.state)
        shutil.copyfile(self.old,self.db);self.tpm.start()
        self.p.verify(1001)
    def test_12_no_silent_reprovision(self):
        with self.assertRaises(Denied):self.p.provision_fixture(1001)

    def test_13_platform_policy_delete_guard(self):
        # An emulator-only platform-created index with deletion authorization
        # deliberately bound to another command. NOT a provisioning recipe.
        index="0x01500021"
        session=self.root/"trial.ctx"
        policy=self.root/"policy.digest"
        self.tpm.run("tpm2_startauthsession","-S",str(session))
        self.tpm.run("tpm2_policycommandcode","-S",str(session),"-L",str(policy),"TPM2_CC_NV_Read")
        self.tpm.run("tpm2_flushcontext",str(session))
        self.tpm.run("tpm2_nvdefine","-C","p","-g","sha256","-s","32","-a","nt=extend|authread|authwrite|no_da|platformcreate|policydelete","-L",str(policy),"-p","file:"+str(self.tpm.auth),index)
        self.tpm.run("tpm2_nvextend","-C",index,"-P","file:"+str(self.tpm.auth),"-i","-",index,data=bytes(32))
        want=sha(bytes(64))
        def read():
            return self.tpm.run("tpm2_nvread","-C",index,"-P","file:"+str(self.tpm.auth),"-s","32",index).stdout
        self.assertEqual(read(),want)
        for hierarchy in ("o","p"):
            r=self.tpm.run("tpm2_nvundefine","-C",hierarchy,index,ok=False)
            self.assertNotEqual(r.returncode,0)
            self.assertEqual(read(),want)
        session=self.root/"wrong-delete.ctx"
        self.tpm.run("tpm2_startauthsession","--policy-session","-S",str(session))
        self.tpm.run("tpm2_policycommandcode","-S",str(session),"TPM2_CC_NV_UndefineSpaceSpecial")
        try:
            r=self.tpm.run("tpm2_nvundefine","-C","p","-S",str(session),index,ok=False)
            self.assertNotEqual(r.returncode,0)
            self.assertEqual(read(),want)
        finally:
            self.tpm.run("tpm2_flushcontext",str(session),ok=False)

class TPMBoundLab(BoundLab):
    """Reuse bound WebAuthn service; substitute TPM extend for SQLite anchor.
    Synthetic emulator only; no physical TPM path and no HTTP endpoint.
    """
    @classmethod
    def provision_fixture(cls,path,tpm,primary,backup,*,clock):
        path=pathlib.Path(path)
        if path.exists(): raise Denied("already provisioned")
        tpm.define(protected=True)
        core=Lab(path)
        core.bootstrap_fixture(primary,backup)
        with core.tx() as db:
            db.execute("CREATE TABLE approval_context(id TEXT PRIMARY KEY, context BLOB NOT NULL)")
            db.execute("CREATE TABLE receipts(id TEXT PRIMARY KEY, context BLOB NOT NULL, epoch INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0)")
            db.execute("CREATE TABLE credential_policy(id TEXT PRIMARY KEY, backup_eligible INTEGER NOT NULL)")
            db.execute("INSERT INTO credential_policy VALUES (?,0)",(primary[0],))
            db.execute("INSERT INTO credential_policy VALUES (?,1)",(backup[0],))
            db.execute("CREATE TABLE tpm_checkpoint(id INTEGER PRIMARY KEY CHECK(id=1), prev BLOB NOT NULL, seq INTEGER NOT NULL, clock INTEGER NOT NULL)")
            now=clock()
            prev=bytes(32)
            payload=digest(prev,0,snapshot(db),now)
            if tpm.extend(payload)!=sha(prev+payload): raise Denied("genesis mismatch")
            db.execute("INSERT INTO tpm_checkpoint VALUES (1,?,?,?)",(prev,0,now))
        return cls(path,tpm,clock=clock)
    def __init__(self,path,tpm,*,clock):
        self.path=pathlib.Path(path)
        self.tpm=tpm
        self.clock=clock
        self.local=threading.local()
        with self.tx(): pass
    @contextmanager
    def tx(self):
        if getattr(self.local,"db",None) is not None:
            yield self.local.db
            return
        if not self.path.is_file() or self.path.is_symlink(): raise Denied("missing local state")
        db=sqlite3.connect(self.path.resolve().as_uri()+"?mode=rw",uri=True,isolation_level=None,timeout=10)
        db.row_factory=sqlite3.Row
        rejected=None
        try:
            db.execute("BEGIN IMMEDIATE")
            cp=db.execute("SELECT prev,seq,clock FROM tpm_checkpoint WHERE id=1").fetchone()
            if cp is None: raise Denied("missing checkpoint")
            prev,seq,high=cp
            before=snapshot(db)
            current=sha(prev+digest(prev,seq,before,high))
            if self.tpm.read()!=current: raise Denied("anchor mismatch")
            now=self.clock()
            if type(now) is not int or now<high: raise Denied("clock rollback")
            self.local.db,self.local.now=db,now
            db.execute("SAVEPOINT operation")
            try:
                yield db
            except Exception as exc:
                db.execute("ROLLBACK TO operation")
                rejected=exc
            db.execute("RELEASE operation")
            after=snapshot(db)
            # Persist high-water even for denied operations; do not write if
            # neither state nor time changed.
            if after!=before or now!=high:
                payload=digest(current,seq+1,after,now)
                expected=sha(current+payload)
                if self.tpm.extend(payload)!=expected: raise Denied("extend mismatch")
                self.before_main_commit_fixture()
                db.execute("UPDATE tpm_checkpoint SET prev=?,seq=?,clock=? WHERE id=1",(current,seq+1,now))
            db.commit()
            if rejected is not None: raise rejected
        except BaseException:
            db.rollback()
            raise
        finally:
            self.local.db=None
            self.local.now=None
            db.close()

class IntegratedTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory(prefix="dc-tpm-int-");self.addCleanup(t.cleanup)
        self.root=pathlib.Path(t.name)
        self.tpm=Emulator(self.root);self.addCleanup(self.tpm.close)
        self.db=self.root/"restore.sqlite";self.old=self.root/"old.sqlite"
        self.now=1000
        self.p,self.b,self.c=fixture(),fixture(),fixture()
        self.lab=TPMBoundLab.provision_fixture(self.db,self.tpm,self.p[:2],self.b[:2],clock=lambda:self.now)
    def open(self): return TPMBoundLab(self.db,self.tpm,clock=lambda:self.now)
    def approve(self,f):
        q=self.lab.issue_approval(f[0],dict(EXPECTED),ARTIFACT)
        r=self.lab.finish_approval(q[0],assertion(f,q[1]),dict(EXPECTED),ARTIFACT)
        self.assertEqual(r["status"],"SYNTHETIC_APPROVAL_ONLY")
        return q
    def candidate(self):
        q=self.lab.issue_registration()
        self.lab.register(q[0],registration(self.c,q[1]))
        q=self.lab.issue("prove",self.c[0])
        self.lab.finish(q[0],assertion(self.c,q[1]))
    def test_14_bound_receipt_restart_and_single_use(self):
        q=self.approve(self.p)
        self.tpm.stop();self.tpm.start();self.lab=self.open()
        self.assertTrue(self.lab.receipt_valid(q[0],dict(EXPECTED),ARTIFACT))
        self.assertEqual(self.lab.redeem_fixture(q[0],dict(EXPECTED),ARTIFACT),"INERT_FIXTURE_ONLY")
        self.assertFalse(self.open().receipt_valid(q[0],dict(EXPECTED),ARTIFACT))
        with self.assertRaises(ValueError):self.lab.redeem_fixture(q[0],dict(EXPECTED),ARTIFACT)
    def test_15_revoked_credential_rollback(self):
        self.candidate()
        shutil.copyfile(self.db,self.old)
        q=self.lab.issue("rotate",self.p[0],self.c[0])
        self.lab.finish(q[0],assertion(self.p,q[1]))
        self.approve(self.c)
        with self.assertRaises(ValueError):self.approve(self.p)
        shutil.copyfile(self.old,self.db)
        with self.assertRaisesRegex(Denied,"anchor mismatch"):self.open()
    def test_16_receipt_restore_denied(self):
        q=self.approve(self.p)
        shutil.copyfile(self.db,self.old)
        self.lab.redeem_fixture(q[0],dict(EXPECTED),ARTIFACT)
        shutil.copyfile(self.old,self.db)
        with self.assertRaisesRegex(Denied,"anchor mismatch"):self.open()
    def test_17_recovery_backup_and_old_primary(self):
        self.candidate()
        q=self.lab.issue("recover",self.b[0],self.c[0])
        self.lab.finish(q[0],assertion(self.b,q[1],flags=5))
        self.approve(self.c)
        with self.assertRaises(ValueError):self.approve(self.p)
    def test_18_rejected_expiry_persists_time(self):
        q=self.lab.issue_approval(self.p[0],dict(EXPECTED),ARTIFACT)
        self.now+=TTL
        with self.assertRaises(ValueError):
            self.lab.finish_approval(q[0],assertion(self.p,q[1]),dict(EXPECTED),ARTIFACT)
        self.now-=1
        with self.assertRaisesRegex(Denied,"clock rollback"):self.open()
    def test_19_intercommit_failure(self):
        q=self.lab.issue_approval(self.p[0],dict(EXPECTED),ARTIFACT)
        def fail():raise RuntimeError("injected")
        self.lab.before_main_commit_fixture=fail
        with self.assertRaisesRegex(RuntimeError,"injected"):
            self.lab.finish_approval(q[0],assertion(self.p,q[1]),dict(EXPECTED),ARTIFACT)
        with self.assertRaisesRegex(Denied,"anchor mismatch"):self.open()

    def test_20_integrated_index_delete_denied(self):
        q=self.approve(self.p)
        before=self.tpm.read()
        for hierarchy in ("o","p"):
            r=self.tpm.run("tpm2_nvundefine","-C",hierarchy,INDEX,ok=False)
            self.assertNotEqual(r.returncode,0)
            self.assertEqual(self.tpm.read(),before)
        self.assertTrue(self.open().receipt_valid(q[0],dict(EXPECTED),ARTIFACT))

if __name__=="__main__":
    unittest.main(verbosity=2)
