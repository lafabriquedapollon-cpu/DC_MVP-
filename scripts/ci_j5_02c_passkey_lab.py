"""J5-02C isolated WebAuthn approval laboratory. Never a release authority."""
import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn import verify_authentication_response
from dc_release_gate import recovery_authority as authority
from dc_release_gate import release_certification as legacy

DOMAIN = "DIGITAL-CROWN/J5-02C/WEBAUTHN-LAB/NOT-A-RELEASE/v1"
RP = "owner-lab.example.invalid"
ORIGIN = "https://" + RP
BASE = "7f210ff53cb89fb3a2378e234b1027f1f9fec83d"
BRANCH = "ci/j5-02c-passkey-lab-20261127"

def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

def sha(data):
    return hashlib.sha256(data).digest()

def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def decode(value):
    if not isinstance(value, str) or len(value) > 16384 or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("ENCODING")
    result = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if b64(result) != value:
        raise ValueError("NONCANONICAL")
    return result

def unique(pairs):
    d = {}
    for key, val in pairs:
        if key in d:
            raise ValueError("DUPLICATE_JSON")
        d[key] = val
    return d

def challenge(record, expected, now):
    if set(record) != set(expected) | {"nonce", "issued", "expires"}:
        raise ValueError("SCHEMA")
    if any(type(record[k]) is not type(v) or record[k] != v for k,v in expected.items()):
        raise ValueError("BINDING")
    if not isinstance(record["nonce"], str) or not re.fullmatch(r"[0-9a-f]{64}", record["nonce"]):
        raise ValueError("NONCE")
    a,b = record["issued"],record["expires"]
    if type(a) is not int or type(b) is not int or not a <= now < b or not 0 < b-a <= 300:
        raise ValueError("TTL")
    return sha(canon(record))

def verify(record, assertion, *, expected, now, credential_id, cose_key, db):
    ch = challenge(record, expected, now)
    if assertion["id"] != b64(credential_id) or assertion["rawId"] != b64(credential_id):
        raise ValueError("CREDENTIAL")
    data = json.loads(decode(assertion["response"]["clientDataJSON"]), object_pairs_hook=unique)
    if data.get("crossOrigin", False) is not False or "topOrigin" in data:
        raise ValueError("CROSS_ORIGIN")
    if data.get("type") != "webauthn.get" or data.get("origin") != ORIGIN or decode(data.get("challenge")) != ch:
        raise ValueError("CLIENT_DATA")
    auth = decode(assertion["response"]["authenticatorData"])
    # This narrow laboratory accepts ES256 assertions without extension payloads.
    if len(auth) != 37 or auth[:32] != sha(RP.encode()) or auth[32] & 5 != 5 or auth[32] & 0xc0:
        raise ValueError("AUTH_DATA")
    with sqlite3.connect(db, timeout=5, isolation_level=None) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("CREATE TABLE IF NOT EXISTS used(nonce TEXT PRIMARY KEY)")
        conn.execute("CREATE TABLE IF NOT EXISTS counter(id TEXT PRIMARY KEY, count INTEGER NOT NULL)")
        row = conn.execute("SELECT count FROM counter WHERE id=?", (b64(credential_id),)).fetchone()
        if conn.execute("SELECT 1 FROM used WHERE nonce=?", (record["nonce"],)).fetchone():
            raise ValueError("REPLAY")
        # Use the project's existing WebAuthn verifier, not a custom signature verifier.
        result = verify_authentication_response(
            credential=assertion, expected_challenge=ch, expected_rp_id=RP,
            expected_origin=ORIGIN, credential_public_key=cose_key,
            credential_current_sign_count=row[0] if row else 0,
            require_user_verification=True)
        conn.execute("INSERT INTO used VALUES (?)", (record["nonce"],))
        conn.execute("INSERT INTO counter VALUES (?,?) ON CONFLICT(id) DO UPDATE SET count=excluded.count",
                     (b64(credential_id),result.new_sign_count))
        conn.commit()
    return result

class Lab(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name)/"lab.sqlite"
        self.key = ec.generate_private_key(ec.SECP256R1())
        p = self.key.public_key().public_numbers()
        self.cose = cbor2.dumps({1:2,3:-7,-1:1,-2:p.x.to_bytes(32,"big"),-3:p.y.to_bytes(32,"big")})
        self.cid = secrets.token_bytes(32)
        self.now = int(time.time())
        self.expected = {"domain":DOMAIN,"repo":authority.REPOSITORY,"repo_id":authority.REPOSITORY_ID,
                         "owner_id":authority.OWNER_ID,"source_sha":os.environ["GITHUB_SHA"],
                         "artifact_sha256":sha(b"inert synthetic artifact").hex(),"rp":RP,"origin":ORIGIN}
        self.rec = dict(self.expected, nonce=secrets.token_hex(32), issued=self.now, expires=self.now+120)

    def assertion(self, rec=None, *, origin=ORIGIN, rp=RP, flags=5, count=0, key=None, cid=None, extra=None):
        rec = self.rec if rec is None else rec
        data = {"type":"webauthn.get","origin":origin,"challenge":b64(sha(canon(rec))),"crossOrigin":False}
        data.update(extra or {})
        raw = canon(data)
        auth = sha(rp.encode()) + bytes([flags]) + count.to_bytes(4,"big")
        sig = (key or self.key).sign(auth+sha(raw),ec.ECDSA(hashes.SHA256()))
        cid = cid or self.cid
        return {"id":b64(cid),"rawId":b64(cid),"type":"public-key","response":{
            "clientDataJSON":b64(raw),"authenticatorData":b64(auth),"signature":b64(sig)}}

    def check(self, rec=None, assertion=None, now=None):
        rec = self.rec if rec is None else rec
        return verify(rec, self.assertion(rec) if assertion is None else assertion,
                      expected=self.expected, now=self.now if now is None else now,
                      credential_id=self.cid,cose_key=self.cose,db=self.db)

    def test_positive_and_persisted_replay(self):
        self.check()
        with self.assertRaisesRegex(ValueError,"REPLAY"):
            self.check()
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM used").fetchone()[0],1)

    def test_bindings(self):
        for field,val in (("domain","release"),("repo","other/repo"),("repo_id",1),("owner_id",1),
                          ("source_sha","0"*40),("artifact_sha256","0"*64),("rp","other.invalid"),
                          ("origin","https://other.invalid")):
            rec = dict(self.rec, **{field:val})
            with self.subTest(field=field), self.assertRaisesRegex(ValueError,"BINDING"):
                self.check(rec)
        self.check()

    def test_client_and_authenticator_denials(self):
        for opts in ({"origin":"https://other.invalid"},{"rp":"other.invalid"},{"flags":1},{"flags":4},
                     {"extra":{"crossOrigin":True}},{"extra":{"type":"webauthn.create"}},
                     {"extra":{"challenge":b64(secrets.token_bytes(32))}},
                     {"cid":secrets.token_bytes(32)},{"key":ec.generate_private_key(ec.SECP256R1())}):
            with self.subTest(opts=list(opts)), self.assertRaises(Exception):
                self.check(assertion=self.assertion(**opts))
        self.check()

    def test_expiry_and_schema(self):
        for rec,now in ((self.rec,self.rec["expires"]),(dict(self.rec,issued=self.now+1),self.now),
                        (dict(self.rec,expires=self.now+301),self.now),(dict(self.rec,extra=1),self.now)):
            with self.assertRaises(ValueError):
                self.check(rec,now=now)
        self.check()

    def test_counter_regression_and_zero(self):
        self.check(assertion=self.assertion(count=4))
        new = dict(self.rec,nonce=secrets.token_hex(32))
        with self.assertRaises(Exception):
            self.check(new,self.assertion(new,count=3))
        self.check(new,self.assertion(new,count=5))

    def test_synced_zero_counter_unique_challenges(self):
        self.check(assertion=self.assertion(flags=29,count=0))
        new = dict(self.rec,nonce=secrets.token_hex(32))
        self.check(new,self.assertion(new,flags=29,count=0))

if __name__ == "__main__":
    assert os.environ["GITHUB_REF"] == "refs/heads/"+BRANCH
    assert os.environ["GITHUB_REPOSITORY"] == authority.REPOSITORY
    assert os.environ["GITHUB_REPOSITORY_ID"] == str(authority.REPOSITORY_ID)
    assert os.environ["GITHUB_REPOSITORY_OWNER_ID"] == str(authority.OWNER_ID)
    assert os.environ["RUNNER_ENVIRONMENT"] == "github-hosted"
    assert subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip() == os.environ["GITHUB_SHA"]
    for path in ("run.py","DigitalCrown.spec","dc_release_gate/release_certification.py","dc_release_gate/recovery_authority.py","backend/routers/mobile_passkey.py"):
        def blob(ref): return subprocess.check_output(["git","rev-parse",ref+":"+path],text=True).strip()
        assert blob(BASE)==blob("HEAD"), path
    assert legacy.REPOSITORY != authority.REPOSITORY
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Lab))
    if not result.wasSuccessful():
        raise SystemExit(1)
    print("J5_PASSKEY_LAB_PASS NOT_OWNER_ENROLLED_NOT_A_RELEASE")
