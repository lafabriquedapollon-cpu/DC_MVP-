"""Local commissioning-only enrollment. No release issuance or production authority."""
import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
import cbor2
from scripts.ci_j5_02c_recovery_lab import Lab, RP, ORIGIN, TTL, canon, sha, b64, decode, unique

DOMAIN="DIGITAL-CROWN/J5-04C/COMMISSIONING/NOT-A-RELEASE"
ROLES=("primary","backup","replacement")
class Denied(ValueError): pass
def require(ok,marker):
    if not ok:raise Denied(marker)

class Store(Lab):
    @classmethod
    def provision(cls,path):
        path=Path(path)
        require(not path.exists(),"ALREADY_PROVISIONED")
        path.touch(exist_ok=False)
        base=Lab(path)
        with base.tx() as db:
            db.execute("CREATE TABLE slots(role TEXT PRIMARY KEY,cid TEXT UNIQUE,nonce TEXT UNIQUE,proven INTEGER NOT NULL DEFAULT 0)")
            db.execute("CREATE TABLE policy(cid TEXT PRIMARY KEY,be INTEGER NOT NULL)")
            db.execute("CREATE TABLE admission(id INTEGER PRIMARY KEY CHECK(id=1), phase TEXT NOT NULL, high INTEGER NOT NULL, attempts INTEGER NOT NULL)")
            db.execute("INSERT INTO admission VALUES(1,'pending',0,0)")
    def __init__(self,path):
        self.path=Path(path);self._db=None
        require(self.path.is_file() and not self.path.is_symlink(),"STATE_MISSING")
        with self.tx() as db:require(db.execute("SELECT phase FROM admission WHERE id=1").fetchone() is not None,"STATE_INVALID")
    def bootstrap_fixture(self,*args,**kwargs):raise Denied("NO_BOOTSTRAP")
    @contextmanager
    def tx(self):
        if self._db is not None:
            yield self._db;return
        require(self.path.is_file() and not self.path.is_symlink(),"STATE_MISSING")
        db=sqlite3.connect(self.path.resolve().as_uri()+"?mode=rw",uri=True,isolation_level=None,timeout=5)
        db.row_factory=sqlite3.Row
        try:
            db.execute("BEGIN IMMEDIATE");self._db=db
            yield db
            db.commit()
        except BaseException:db.rollback();raise
        finally:self._db=None;db.close()
    def dispatch(self,op,payload):
        schemas={"status":set(),"register_begin":{"role"},"register_finish":{"nonce","credential"},
                 "prove_begin":{"cid"},"prove_finish":{"nonce","proof"},
                 "recover_begin":{"cid"},"recover_finish":{"nonce","proof"}}
        require(op in schemas and type(payload)is dict and set(payload)==schemas[op],"OP_OR_SCHEMA")
        # Persist conservative attempt quota and high-water even for later denial.
        # Wall clock is LAB only, not an independent time source.
        with self.tx() as db:
            a=db.execute("SELECT * FROM admission WHERE id=1").fetchone()
            now=int(time.time())
            require(now>=a["high"] and a["attempts"]<512,"CLOCK_OR_BUDGET")
            db.execute("UPDATE admission SET high=?,attempts=attempts+1 WHERE id=1",(now,))
        with self.tx() as db:
            phase=db.execute("SELECT phase FROM admission").fetchone()[0]
            if op=="status":return {"mode":"COMMISSIONING_ONLY","phase":phase,"release_enabled":False}
            if op=="register_begin":
                role=payload["role"]
                require(role in ROLES and ((phase=="pending" and role!="replacement") or (phase=="enrolled_lab" and role=="replacement")),"ROLE_OR_PHASE")
                row=db.execute("SELECT * FROM slots WHERE role=?",(role,)).fetchone()
                if row is not None:
                    c=db.execute("SELECT expires FROM challenges WHERE id=?",(row["nonce"],)).fetchone()
                    require(row["cid"] is None and c is not None and now>=c["expires"],"SLOT_OCCUPIED")
                    db.execute("DELETE FROM slots WHERE role=?",(role,))
                nonce=secrets.token_hex(32);epoch=self.epoch(db)
                challenge=sha(canon([DOMAIN,RP,ORIGIN,role,epoch,nonce,now,now+TTL]))
                db.execute("INSERT INTO challenges VALUES (?,?,'register','',NULL,?,?,?,0)",(nonce,challenge,epoch,now,now+TTL))
                db.execute("INSERT INTO slots(role,nonce) VALUES (?,?)",(role,nonce))
                return {"nonce":nonce,"challenge":b64(challenge),"rp":RP,"origin":ORIGIN}
            if op=="register_finish":
                nonce=payload["nonce"];credential=payload["credential"]
                slot=db.execute("SELECT * FROM slots WHERE nonce=? AND cid IS NULL",(nonce,)).fetchone()
                require(slot is not None,"UNKNOWN_REGISTRATION")
                auth=cbor2.loads(decode(credential["response"]["attestationObject"]))["authData"]
                be=int(bool(auth[32]&8))
                require(slot["role"]!="backup" or be==0,"SYNCED_BACKUP_DENIED")
                cid=super().register(nonce,credential,now=now)
                db.execute("INSERT INTO policy VALUES (?,?)",(cid,be))
                db.execute("UPDATE slots SET cid=? WHERE role=?",(cid,slot["role"]))
                return {"cid":cid}
            if op in ("prove_begin","recover_begin"):
                cid=payload["cid"]
                slot=db.execute("SELECT * FROM slots WHERE cid=?",(cid,)).fetchone()
                require(slot is not None,"UNKNOWN_SLOT")
                if op=="prove_begin":
                    require(slot["proven"]==0,"ALREADY_PROVEN")
                    q=super().issue("prove",cid,now=now)
                else:
                    require(phase=="enrolled_lab" and slot["role"]=="replacement" and slot["proven"]==1,"RECOVERY_TARGET")
                    backup=db.execute("SELECT cid FROM slots WHERE role='backup' AND proven=1").fetchone()
                    require(backup is not None,"BACKUP_MISSING")
                    q=super().issue("recover",backup["cid"],cid,now=now)
                return {"nonce":q[0],"challenge":b64(q[1])}
            nonce=payload["nonce"];proof=payload["proof"]
            c=db.execute("SELECT action,actor,target FROM challenges WHERE id=?",(nonce,)).fetchone()
            require(c is not None and c["action"]==("prove" if op=="prove_finish" else "recover"),"ACTION_BINDING")
            policy=db.execute("SELECT be FROM policy WHERE cid=?",(c["actor"],)).fetchone()
            auth=decode(proof["response"]["authenticatorData"])
            require(policy is not None and len(auth)==37 and bool(auth[32]&8)==bool(policy["be"]),"BACKUP_FLAGS")
            super().finish(nonce,proof,now=now)
            if op=="prove_finish":
                db.execute("UPDATE slots SET proven=1 WHERE cid=?",(c["actor"],))
                if phase=="pending" and db.execute("SELECT count(*) FROM slots WHERE role IN ('primary','backup') AND proven=1").fetchone()[0]==2:
                    for row in db.execute("SELECT role,cid FROM slots WHERE role IN ('primary','backup')").fetchall():
                        db.execute("UPDATE credentials SET role=? WHERE id=?",(row["role"],row["cid"]))
                    db.execute("UPDATE admission SET phase='enrolled_lab' WHERE id=1")
                return {"proved":True}
            db.execute("DELETE FROM slots WHERE role='primary'")
            db.execute("UPDATE slots SET role='primary' WHERE role='replacement' AND cid=?",(c["target"],))
            return {"recovered_lab":True}
