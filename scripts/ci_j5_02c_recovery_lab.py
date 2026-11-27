"""J5-02C.3 synthetic-only local SQLite lifecycle. NOT A RELEASE.
No network listener, real identity, secret persistence or release authority.
Bootstrap and candidate public keys in this LAB come from synthetic fixtures.
A candidate must prove possession before an active credential authorizes its use.
"""
import base64
import hashlib
import json
import secrets
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn import verify_authentication_response

RP = "approval-lab-7c28d6.pages.dev"
ORIGIN = "https://" + RP
DOMAIN = "DIGITAL-CROWN/J5-02C.3/SYNTHETIC/NOT-A-RELEASE"
TTL = 120
ACTIONS = {"approve", "prove", "rotate", "recover", "replace_backup", "revoke_backup"}

def sha(x): return hashlib.sha256(x).digest()
def b64(x): return base64.urlsafe_b64encode(x).rstrip(b"=").decode("ascii")
def decode(x):
    if not isinstance(x, str) or not x or len(x) > 16384: raise ValueError("encoding")
    raw = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
    if b64(raw) != x: raise ValueError("encoding")
    return raw
def canon(x): return json.dumps(x, sort_keys=True, separators=(",", ":")).encode()
def unique(pairs):
    out = {}
    for k, v in pairs:
        if k in out: raise ValueError("duplicate JSON")
        out[k] = v
    return out

class Lab:
    def __init__(self, path):
        self.path = path
        with self.tx() as db:
            db.execute("CREATE TABLE IF NOT EXISTS state(id INTEGER PRIMARY KEY CHECK(id=1), epoch INTEGER NOT NULL)")
            db.execute("INSERT OR IGNORE INTO state VALUES (1,0)")
            db.execute("CREATE TABLE IF NOT EXISTS credentials(id TEXT PRIMARY KEY, key BLOB NOT NULL, role TEXT NOT NULL CHECK(role IN ('primary','backup','candidate','revoked')), count INTEGER NOT NULL DEFAULT 0, epoch INTEGER NOT NULL, proven INTEGER NOT NULL DEFAULT 0)")
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS role_unique ON credentials(role) WHERE role IN ('primary','backup')")
            db.execute("CREATE TABLE IF NOT EXISTS challenges(id TEXT PRIMARY KEY, challenge BLOB NOT NULL UNIQUE, action TEXT NOT NULL, actor TEXT NOT NULL, target TEXT, epoch INTEGER NOT NULL, issued INTEGER NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0)")
    @contextmanager
    def tx(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()
    def bootstrap_fixture(self, primary, backup):
        """Fixture-only trusted setup; no service API exposes this."""
        with self.tx() as db:
            if db.execute("SELECT 1 FROM credentials").fetchone(): raise ValueError("already bootstrapped")
            if primary[0] == backup[0] or primary[1] == backup[1]: raise ValueError("not independent")
            for role,(cid,key) in (("primary",primary),("backup",backup)):
                db.execute("INSERT INTO credentials(id,key,role,epoch,proven) VALUES (?,?,?,0,1)",(cid,key,role))
    def candidate_fixture(self, cid, key):
        """Fixture registration boundary: not actual WebAuthn registration endpoint."""
        with self.tx() as db:
            epoch = self.epoch(db)
            if db.execute("SELECT 1 FROM credentials WHERE key=?",(key,)).fetchone(): raise ValueError("duplicate key")
            db.execute("INSERT INTO credentials(id,key,role,epoch) VALUES (?,?,'candidate',?)",(cid,key,epoch))
    @staticmethod
    def epoch(db): return db.execute("SELECT epoch FROM state WHERE id=1").fetchone()[0]
    @staticmethod
    def cred(db,cid):
        row = db.execute("SELECT * FROM credentials WHERE id=?",(cid,)).fetchone()
        if row is None: raise ValueError("unknown credential")
        return row
    def policy(self, db, action, actor, target):
        epoch = self.epoch(db)
        if action not in ACTIONS: raise ValueError("action")
        row = self.cred(db,actor)
        role = {"approve":"primary","prove":"candidate","rotate":"primary","recover":"backup","replace_backup":"primary","revoke_backup":"primary"}[action]
        if row["role"] != role: raise ValueError("role")
        if action == "prove" and (row["epoch"] != epoch or row["proven"]): raise ValueError("candidate stale or proven")
        if action in {"rotate","recover","replace_backup"}:
            c = self.cred(db,target)
            if c["role"] != "candidate" or c["epoch"] != epoch or not c["proven"]: raise ValueError("unproven or stale target")
        elif target is not None: raise ValueError("unexpected target")
        if action == "revoke_backup" and not db.execute("SELECT 1 FROM credentials WHERE role='backup'").fetchone(): raise ValueError("no backup")
        return row
    def issue(self, action, actor, target=None, *, now):
        with self.tx() as db:
            self.policy(db,action,actor,target)
            epoch = self.epoch(db)
            nonce = secrets.token_hex(32)
            # Binding is created by trusted server, never accepted from client.
            ch = sha(canon([DOMAIN,RP,ORIGIN,nonce,action,actor,target,epoch,now,now+TTL]))
            db.execute("INSERT INTO challenges VALUES (?,?,?,?,?,?,?,?,0)",(nonce,ch,action,actor,target,epoch,now,now+TTL))
            return nonce,ch
    def finish(self, nonce, assertion, *, now):
        with self.tx() as db:
            c = db.execute("SELECT * FROM challenges WHERE id=?",(nonce,)).fetchone()
            if c is None or c["used"] or c["epoch"] != self.epoch(db) or not c["issued"] <= now < c["expires"]: raise ValueError("unknown/replay/stale/expired challenge")
            action, actor, target = c["action"], c["actor"], c["target"]
            row = self.policy(db,action,actor,target)
            if assertion.get("id") != actor or assertion.get("rawId") != actor or assertion.get("type") != "public-key": raise ValueError("credential binding")
            response = assertion["response"]
            data = json.loads(decode(response["clientDataJSON"]), object_pairs_hook=unique)
            if data.get("type") != "webauthn.get" or data.get("origin") != ORIGIN or data.get("crossOrigin",False) is not False or "topOrigin" in data or decode(data.get("challenge")) != c["challenge"]: raise ValueError("client binding")
            auth = decode(response["authenticatorData"])
            if len(auth) != 37 or auth[:32] != sha(RP.encode()) or auth[32] & 5 != 5 or auth[32] & 0xc0 or (auth[32] & 16 and not auth[32] & 8): raise ValueError("auth data")
            verified = verify_authentication_response(credential=assertion,expected_challenge=c["challenge"],expected_rp_id=RP,expected_origin=ORIGIN,credential_public_key=row["key"],credential_current_sign_count=row["count"],require_user_verification=True)
            db.execute("UPDATE challenges SET used=1 WHERE id=?",(nonce,))
            db.execute("UPDATE credentials SET count=? WHERE id=?",(verified.new_sign_count,actor))
            if action == "prove":
                db.execute("UPDATE credentials SET proven=1 WHERE id=?",(actor,))
            elif action != "approve":
                role = "backup" if action in {"replace_backup","revoke_backup"} else "primary"
                db.execute("UPDATE credentials SET role='revoked' WHERE role=?",(role,))
                if target is not None: db.execute("UPDATE credentials SET role=? WHERE id=?",(role,target))
                # Invalidate every outstanding challenge and unselected candidate.
                db.execute("UPDATE credentials SET role='revoked' WHERE role='candidate'")
                db.execute("UPDATE state SET epoch=epoch+1 WHERE id=1")
            return action

def fixture():
    key = ec.generate_private_key(ec.SECP256R1())
    p = key.public_key().public_numbers()
    cose = cbor2.dumps({1:2,3:-7,-1:1,-2:p.x.to_bytes(32,"big"),-3:p.y.to_bytes(32,"big")})
    return b64(secrets.token_bytes(32)),cose,key
def assertion(f, ch, *, origin=ORIGIN,rp=RP,flags=29,count=0,extra=None):
    cid,_,key=f
    d=dict(type="webauthn.get",origin=origin,challenge=b64(ch),crossOrigin=False)
    d.update(extra or {})
    raw=canon(d)
    auth=sha(rp.encode())+bytes([flags])+count.to_bytes(4,"big")
    sig=key.sign(auth+sha(raw),ec.ECDSA(hashes.SHA256()))
    return dict(id=cid,rawId=cid,type="public-key",response=dict(clientDataJSON=b64(raw),authenticatorData=b64(auth),signature=b64(sig)))

class Tests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.path=Path(t.name)/"synthetic.sqlite"
        self.lab=Lab(self.path);self.now=1000
        self.p,self.b,self.c=fixture(),fixture(),fixture()
        self.lab.bootstrap_fixture(self.p[:2],self.b[:2])
    def issue(self, action, actor, target=None):
        return self.lab.issue(action,actor[0],target[0] if target else None,now=self.now)
    def finish(self,pair,actor,**kw):
        return self.lab.finish(pair[0],assertion(actor,pair[1],**kw),now=self.now)
    def candidate(self):
        self.lab.candidate_fixture(*self.c[:2])
        pair=self.issue("prove",self.c)
        self.assertEqual(self.finish(pair,self.c),"prove")
    def test_01_replay_after_restart(self):
        q=self.issue("approve",self.p);self.finish(q,self.p)
        self.lab=Lab(self.path)
        with self.assertRaises(ValueError): self.finish(q,self.p)
    def test_02_unknown_server_nonce(self):
        with self.assertRaises(ValueError): self.finish(("client-made",secrets.token_bytes(32)),self.p)
    def test_03_expiry(self):
        q=self.issue("approve",self.p);self.now+=TTL
        with self.assertRaises(ValueError): self.finish(q,self.p)
    def test_04_future(self):
        q=self.issue("approve",self.p);self.now-=1
        with self.assertRaises(ValueError): self.finish(q,self.p)
    def test_05_wrong_challenge(self):
        a=self.issue("approve",self.p);b=self.issue("approve",self.p)
        with self.assertRaises(ValueError): self.finish((a[0],b[1]),self.p)
        self.finish(a,self.p)
    def test_06_origin(self):
        q=self.issue("approve",self.p)
        with self.assertRaises(ValueError): self.finish(q,self.p,origin="https://evil.invalid")
    def test_07_rp(self):
        q=self.issue("approve",self.p)
        with self.assertRaises(ValueError): self.finish(q,self.p,rp="evil.invalid")
    def test_08_uv(self):
        q=self.issue("approve",self.p)
        with self.assertRaises(ValueError): self.finish(q,self.p,flags=1)
    def test_09_cross_origin(self):
        q=self.issue("approve",self.p)
        with self.assertRaises(ValueError): self.finish(q,self.p,extra={"crossOrigin":True})
    def test_10_wrong_signer(self):
        q=self.issue("approve",self.p)
        with self.assertRaises(Exception): self.finish(q,(self.p[0],self.p[1],self.b[2]))
        self.finish(q,self.p)
    def test_11_concurrent_replay(self):
        q=self.issue("approve",self.p)
        a=assertion(self.p,q[1])
        def attempt(_):
            try: Lab(self.path).finish(q[0],a,now=self.now);return True
            except ValueError: return False
        with ThreadPoolExecutor(max_workers=8) as ex: self.assertEqual(sum(ex.map(attempt,range(8))),1)
    def test_12_unproven_candidate(self):
        self.lab.candidate_fixture(*self.c[:2])
        with self.assertRaises(ValueError): self.issue("rotate",self.p,self.c)
    def test_13_rotation(self):
        self.candidate();old=self.issue("approve",self.p)
        self.finish(self.issue("rotate",self.p,self.c),self.p)
        self.lab=Lab(self.path)
        with self.assertRaises(ValueError): self.finish(old,self.p)
        with self.assertRaises(ValueError): self.issue("approve",self.p)
        self.finish(self.issue("approve",self.c),self.c)
    def test_14_recovery(self):
        self.candidate()
        self.finish(self.issue("recover",self.b,self.c),self.b)
        with self.assertRaises(ValueError): self.issue("approve",self.p)
        self.finish(self.issue("approve",self.c),self.c)
    def test_15_wrong_role(self):
        self.candidate()
        for action,actor in (("recover",self.p),("rotate",self.b),("approve",self.b)):
            with self.assertRaises(ValueError): self.issue(action,actor,self.c if action!="approve" else None)
    def test_16_revoke_backup(self):
        self.candidate();old=self.issue("recover",self.b,self.c)
        self.finish(self.issue("revoke_backup",self.p),self.p)
        with self.assertRaises(ValueError): self.finish(old,self.b)
        with self.assertRaises(ValueError): self.issue("recover",self.b,self.c)
        self.finish(self.issue("approve",self.p),self.p)
    def test_17_replace_backup(self):
        self.candidate();self.finish(self.issue("replace_backup",self.p,self.c),self.p)
        n=fixture();self.lab.candidate_fixture(*n[:2]);self.finish(self.issue("prove",n),n)
        with self.assertRaises(ValueError): self.issue("recover",self.b,n)
        self.finish(self.issue("recover",self.c,n),self.c)
        self.finish(self.issue("approve",n),n)
    def test_18_wrong_target(self):
        self.candidate();q=self.issue("rotate",self.p,self.c)
        n=fixture();self.lab.candidate_fixture(*n[:2]);self.finish(self.issue("prove",n),n)
        other=self.issue("rotate",self.p,n)
        with self.assertRaises(ValueError): self.finish((q[0],other[1]),self.p)
        self.finish(q,self.p)
    def test_19_atomic_failure(self):
        self.candidate();q=self.issue("rotate",self.p,self.c)
        with self.lab.tx() as db:
            db.execute("CREATE TRIGGER fail_epoch BEFORE UPDATE ON state BEGIN SELECT RAISE(ABORT,'injected'); END")
        with self.assertRaises(sqlite3.IntegrityError): self.finish(q,self.p)
        with self.lab.tx() as db:
            self.assertEqual(db.execute("SELECT used FROM challenges WHERE id=?",(q[0],)).fetchone()[0],0)
            self.assertEqual(self.lab.cred(db,self.p[0])["role"],"primary")
            self.assertEqual(self.lab.cred(db,self.c[0])["role"],"candidate")
            db.execute("DROP TRIGGER fail_epoch")
        self.finish(q,self.p)
    def test_20_counter(self):
        self.finish(self.issue("approve",self.p),self.p,count=3)
        q=self.issue("approve",self.p)
        with self.assertRaises(Exception): self.finish(q,self.p,count=2)
        self.finish(q,self.p,count=4)
    def test_21_duplicate_key(self):
        with self.assertRaises(ValueError): self.lab.candidate_fixture(self.c[0],self.p[1])
    def test_22_zero_counter(self):
        self.finish(self.issue("approve",self.p),self.p)
        self.finish(self.issue("approve",self.p),self.p)

if __name__=="__main__":
    unittest.main(verbosity=2)
