"""Isolated R5 characterization: actual HTTP and synthetic WebAuthn ES256.
No server-minted fixture JWT, authorization mock, live endpoint or clinical data.
Security expectations are aggregated so multiple failures remain observable.
"""
import base64
import hashlib
import json
import os
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

assert os.environ.get("GITHUB_ACTIONS") == "true"
assert os.environ.get("DC_TEST_SCOPE") == "platform-uv"
assert os.environ.get("ENVIRONMENT") == "e2e_install_rehearsal"
BASE = "http://127.0.0.1:8008"
ORIGIN = "https://digitalcrown.local:8005"
RP = "digitalcrown.local"
M = "/api/mobile"
P = M + "/passkey"
S = "/api/superadmin/marketplace/overview"
F = M + "/superadmin"
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
rows = []

def b64(x):
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode("ascii")

def sha(x):
    return hashlib.sha256(x).digest()

def request(label, path, expected, *, method="GET", token=None, data=None,
            cookie=None, origin=None, soft=False, form=False, approval=None):
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    if cookie:
        headers["Cookie"] = cookie
    if origin:
        headers["Origin"] = origin
    if approval:
        headers["X-Platform-Approval"] = approval
    body = None
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
        body = urllib.parse.urlencode(data).encode() if form else json.dumps(data).encode()
    try:
        response = opener.open(urllib.request.Request(BASE + path, data=body, headers=headers, method=method), timeout=15)
    except urllib.error.HTTPError as exc:
        response = exc
    with response as r:
        status = r.status
        raw = r.read()
        cookies = r.headers.get_all("Set-Cookie") or []
    allowed = (expected,) if isinstance(expected, int) else tuple(expected)
    ok = status in allowed
    row = {"label": label, "method": method, "status": status, "expected": list(allowed), "pass": ok}
    rows.append(row)
    print("LOT01_R5_UV_CASE " + json.dumps(row), flush=True)
    if not soft:
        assert ok, label
    try:
        parsed = json.loads(raw)
    except (ValueError, UnicodeError):
        parsed = None
    return parsed, cookies

def paired(email):
    login, _ = request("desktop synthetic login", "/api/auth/login", 200, method="POST", form=True,
                       data={"username": email, "password": os.environ["DC_SYNTH_PASSWORD"]})
    access = login["access_token"]
    _, cookies = request("workstation", "/api/workstation/state", 200, token=access)
    cookie = next(c.split(";")[0] for c in cookies if c.startswith("dc_workstation="))
    identity, _ = request("desktop identity", "/api/auth/me", 200, token=access, cookie=cookie)
    issued, _ = request("own authorized pairing", M + "/bridge-pairing", 200, method="POST",
                        token=access, cookie=cookie, data={"target_user_id": identity["id"], "destination": "agenda"})
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    claim = {"token": issued["token_code"], "client_public_key_hex": public.hex()}
    mobile, _ = request("real ECDH pairing", M + "/claim-token", 200, method="POST", data=claim)
    assert mobile["user_id"] == identity["id"]
    request("pairing replay", M + "/claim-token", 404, method="POST", data=claim)
    return access, cookie, mobile, identity

def ceremony_data(kind, challenge):
    return json.dumps({"type": kind, "challenge": challenge, "origin": ORIGIN, "crossOrigin": False},
                      separators=(",", ":")).encode()

def credential_base(cid):
    return {"id": b64(cid), "rawId": b64(cid), "type": "public-key"}

def register(options, key, cid):
    pub = key.public_key().public_numbers()
    cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: pub.x.to_bytes(32, "big"), -3: pub.y.to_bytes(32, "big")})
    auth = sha(RP.encode()) + bytes([0x45]) + bytes(4) + bytes(16) + len(cid).to_bytes(2, "big") + cid + cose
    att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth})
    return {**credential_base(cid), "response": {"clientDataJSON": b64(ceremony_data("webauthn.create", options["challenge"])),
              "attestationObject": b64(att), "transports": ["internal"]}}

def assertion(options, key, cid, count, flags=5):
    raw = ceremony_data("webauthn.get", options["challenge"])
    auth = sha(RP.encode()) + bytes([flags]) + count.to_bytes(4, "big")
    sig = key.sign(auth + sha(raw), ec.ECDSA(hashes.SHA256()))
    return {**credential_base(cid), "response": {"clientDataJSON": b64(raw), "authenticatorData": b64(auth),
             "signature": b64(sig)}}

def verify_body(options, credential):
    return {"challenge_id": options["challenge_id"], "credential": credential}

def options(token):
    result, _ = request("authentication challenge", P + "/authentication/options", 200, method="POST",
                        token=token, origin=ORIGIN)
    assert result["userVerification"] == "required"
    return result

def run():
    desktop, cookie, mobile, identity = paired("ci-platform-admin@example.com")
    assert identity["is_superadmin"] is True
    ordinary_desktop, ordinary_cookie, ordinary, ordinary_identity = paired("ci-other@example.com")
    assert ordinary_identity["is_superadmin"] is False
    token = mobile["access_token"]
    other = ordinary["access_token"]
    discover = P + "/platform-devices"
    eligible = P + "/platform-eligibility"
    request("platform device discovery anonymous refused", discover, 401)
    request("platform device discovery ordinary Desktop refused", discover, 403, token=ordinary_desktop, cookie=ordinary_cookie)
    request("platform device discovery Pocket refused", discover, 401, token=token)
    empty_devices, _ = request("platform device discovery excludes unenrolled phones", discover, 200, token=desktop, cookie=cookie)
    assert empty_devices == []
    request("unenrolled platform Pocket not eligible", eligible, 423, token=token)
    request("ordinary Pocket not eligible", eligible, 403, token=other)
    request("durable platform token denied Marketplace", S, 403, token=token)
    request("ordinary token denied Marketplace", S, 403, token=other)
    request("desktop token refused on mobile passkey status", P + "/status", 401, token=desktop)
    status, _ = request("paired platform passkey status", P + "/status", 200, token=token, origin=ORIGIN)
    assert status["state"] == "disabled" and status["origin_ready"] is True
    request("wrong origin rejected", P + "/registration/options", 409, method="POST", token=token,
            origin="https://invalid.example")
    reg, _ = request("registration challenge", P + "/registration/options", 200, method="POST", token=token, origin=ORIGIN)
    assert reg["rp"]["id"] == RP and reg["authenticatorSelection"]["userVerification"] == "required"
    key, cid = ec.generate_private_key(ec.SECP256R1()), secrets.token_bytes(32)
    pending, _ = request("real verifier registration", P + "/registration/verify", 200, method="POST", token=token,
                         origin=ORIGIN, data=verify_body(reg, register(reg, key, cid)))
    assert pending["state"] == "pending" and pending["credential_id"] == b64(cid)
    bad = options(token)
    request("UV absent rejected by cryptographic verifier", P + "/authentication/verify", 401, method="POST",
            token=token, origin=ORIGIN, data=verify_body(bad, assertion(bad, key, cid, 1, flags=1)))
    good = options(token)
    body = verify_body(good, assertion(good, key, cid, 1))
    verified, _ = request("real signed UV verification", P + "/authentication/verify", 200, method="POST",
                          token=token, origin=ORIGIN, data=body)
    assert verified["user_verified"] is True and verified["credential_state"] == "pending"
    assert 0 < verified["expires_in"] <= 300
    uv = verified["access_token"]
    request("challenge replay denied", P + "/authentication/verify", 410, method="POST", token=token, origin=ORIGIN, data=body)
    request("pending credential must not grant platform read", S, (401,403,423), token=uv, soft=True)
    pending_devices, _ = request("platform device discovery excludes pending passkey", discover, 200, token=desktop, cookie=cookie)
    assert pending_devices == []
    request("pending UV not eligible", eligible, 423, token=uv)
    enabled, _ = request("enable credential after UV", P + "/enable", 200, method="POST", token=uv,
                         data={"credential_id": b64(cid)})
    assert enabled["state"] == "enabled"
    devices, _ = request("Desktop discovers its active platform passkey", discover, 200, token=desktop, cookie=cookie)
    assert len(devices) == 1 and set(devices[0]) == {"device_id", "credential_id", "enabled_at", "last_seen_at"}
    assert devices[0]["device_id"] == mobile["device_id"] and devices[0]["credential_id"] == b64(cid)
    eligibility, _ = request("active UV platform eligibility without approval", eligible, 200, token=uv)
    assert eligibility == {"eligible": True}
    request("Desktop bearer cannot use Pocket eligibility", eligible, 401, token=desktop, cookie=cookie)
    request("durable bearer cannot use Pocket eligibility", eligible, 423, token=token)
    request("durable token denied after enabling gate", S, (403,423), token=token)
    request("self-enrolled active UV has no independent authority", S, 403, token=uv)
    approve_path = P + "/platform-approval"
    approve_body = {"device_id": mobile["device_id"], "credential_id": b64(cid),
                    "password": os.environ["DC_SYNTH_PASSWORD"], "confirm": True}
    request("mobile bearer cannot approve platform credential", approve_path, 401,
            method="POST", token=token, data=approve_body)
    request("ordinary desktop cannot approve platform credential", approve_path, 403,
            method="POST", token=ordinary_desktop, cookie=ordinary_cookie, data=approve_body)
    request("wrong Desktop password cannot approve", approve_path, 401, method="POST",
            token=desktop, cookie=cookie, data={**approve_body, "password": "wrong-synthetic-password"})
    request("explicit approval confirmation required", approve_path, 409, method="POST",
            token=desktop, cookie=cookie, data={**approve_body, "confirm": False})
    request("mixed cookie bearer approval requires trusted browser origin", approve_path, 403,
            method="POST", token=desktop, cookie=cookie + "; access_token=" + desktop,
            data=approve_body, origin="https://invalid.example")
    granted, _ = request("independent Desktop approval", approve_path, 200, method="POST",
                         token=desktop, cookie=cookie, data=approve_body)
    assert set(granted) == {"ticket", "expires_in"} and granted["expires_in"] == 180
    ticket = granted["ticket"]
    claim_path = approve_path + "/claim"
    request("ticket alone cannot read platform", S, 401, token=ticket)
    request("Desktop cannot claim Pocket transfer", claim_path, 401, method="POST",
            token=desktop, origin=ORIGIN, data={"ticket": ticket})
    request("ordinary Pocket cannot claim transfer", claim_path, 403, method="POST",
            token=other, origin=ORIGIN, data={"ticket": ticket})
    request("durable Pocket cannot claim transfer", claim_path, 423, method="POST",
            token=token, origin=ORIGIN, data={"ticket": ticket})
    request("wrong origin cannot claim transfer", claim_path, 409, method="POST",
            token=uv, origin="https://invalid.example", data={"ticket": ticket})
    forged = ticket.split(".")[0] + "." + b64(secrets.token_bytes(32))
    request("wrong transfer secret refused without consumption", claim_path, 403, method="POST",
            token=uv, origin=ORIGIN, data={"ticket": forged})
    claimed, _ = request("Pocket exchanges Desktop ticket", claim_path, 200, method="POST",
                         token=uv, origin=ORIGIN, data={"ticket": ticket})
    approval = claimed["approval"]
    assert claimed["expires_in"] == 30 * 86400
    request("transfer replay refused", claim_path, 410, method="POST",
            token=uv, origin=ORIGIN, data={"ticket": ticket})
    request("active verified platform read", S, 200, token=uv, approval=approval)
    request("facade anonymous denied", F + "/clients", 401)
    request("facade desktop bearer denied", F + "/clients", 401, token=desktop)
    request("facade durable platform bearer denied", F + "/clients", 423, token=token)
    request("facade UV without independent approval denied", F + "/clients", 403, token=uv)
    request("facade ordinary bearer denied", F + "/trial-codes", 403, token=other)
    clients, _ = request("facade actual client directory", F + "/clients", 200, token=uv, approval=approval)
    assert len(clients) == 3 and {c["email"] for c in clients} == {
        "ci-platform-admin@example.com", "ci-owner@example.com", "ci-other@example.com"}
    expected_client_keys = {"id", "email", "nom_complet", "role", "is_active", "is_licensed",
                            "license_expires_at", "is_archived", "is_suspended", "subscription_plan"}
    assert all(set(c) == expected_client_keys for c in clients)
    page, _ = request("facade bounded pagination", F + "/clients?limit=1&offset=1", 200, token=uv, approval=approval)
    assert len(page) == 1 and page[0]["id"] == clients[1]["id"]
    request("facade excessive limit refused", F + "/clients?limit=101", 422, token=uv, approval=approval)
    # Create only an inert, isolated synthetic trial via the real Desktop API; no email or activation.
    trial, _ = request("Desktop synthetic trial fixture", "/api/superadmin/trial-codes", 200, method="POST",
                       token=desktop, cookie=cookie, data={"email":"ci-trial@example.com","trial_days":14,
                       "cabinet_name":"CI SYNTHETIC","notes":"CI PRIVATE MARKER"})
    trials, _ = request("facade actual trial metadata", F + "/trial-codes", 200, token=uv, approval=approval)
    assert len(trials) == 1 and trials[0]["id"] == trial["id"] and trials[0]["trial_days"] == 14
    assert set(trials[0]) == {"id","email","cabinet_name","trial_days","expires_at","consumed_at","revoked_at","created_at"}
    assert trial["code"] not in json.dumps(trials) and "CI PRIVATE MARKER" not in json.dumps(trials)
    # Transaction qualification in the already isolated SQLCipher LAB, no API exposure.
    from dataclasses import replace
    from jose import jwt
    from backend import database, models
    from backend.models_mobile_passkey import MobileWebAuthnChallenge
    from backend.services.mobile_biometric import issue_challenge, credential_for_device, platform_credential_binding
    from backend.services.platform_mutation_intent import PlatformMutationIntent
    from backend.services.platform_mutation_transaction import stage_trial_revocation, MutationIntentRefused, PURPOSE
    uclaims = jwt.get_unverified_claims(uv)
    aclaims = jwt.get_unverified_claims(approval)
    actor_id, tenant_id = int(uclaims["sub"]), int(uclaims["tenant_id"])
    with database.SessionLocal() as db:
        credential = credential_for_device(db,user_id=actor_id,employer_id=tenant_id,device_id=mobile["device_id"])
        intent = PlatformMutationIntent("trial-code.revoke",trial["id"],actor_id,tenant_id,mobile["device_id"],
            platform_credential_binding(credential),aclaims["jti"],hashlib.sha256(uclaims["jti"].encode()).hexdigest(),secrets.token_hex(32))
        challenge = issue_challenge(db,purpose=PURPOSE,user_id=actor_id,employer_id=tenant_id,
            device_id=mobile["device_id"],challenge=intent.digest())
    def tx_check(label, fn):
        fn()
        row={"label":label,"pass":True}
        rows.append(row)
        print("LOT01_R5_UV_CASE "+json.dumps(row),flush=True)
    def untouched():
        with database.SessionLocal() as db:
            assert db.get(MobileWebAuthnChallenge,challenge).used_at is None
            assert db.get(models.TrialActivationCode,trial["id"]).revoked_at is None
            assert db.query(models.AuditLog).filter_by(action="PLATFORM_TRIAL_REVOKED",resource_id=str(trial["id"])).count()==0
    def wrong_intent():
        with database.SessionLocal() as db:
            try:
                with db.begin():
                    stage_trial_revocation(db,intent=replace(intent,target_id=trial["id"]+1),challenge_id=challenge)
            except MutationIntentRefused: pass
            else: raise AssertionError("wrong target admitted")
        untouched()
    tx_check("transaction rejects changed target without consumption",wrong_intent)
    def rollback():
        with database.SessionLocal() as db:
            try:
                with db.begin():
                    stage_trial_revocation(db,intent=intent,challenge_id=challenge)
                    raise RuntimeError("synthetic rollback")
            except RuntimeError as e:
                assert str(e)=="synthetic rollback"
        untouched()
    tx_check("transaction rollback restores intent target audit",rollback)
    def commit():
        with database.SessionLocal() as db:
            with db.begin():
                stage_trial_revocation(db,intent=intent,challenge_id=challenge)
        with database.SessionLocal() as db:
            assert db.get(MobileWebAuthnChallenge,challenge).used_at is not None
            assert db.get(models.TrialActivationCode,trial["id"]).revoked_at is not None
            assert db.query(models.AuditLog).filter_by(action="PLATFORM_TRIAL_REVOKED",resource_id=str(trial["id"]),severity="CRITICAL").count()==1
    tx_check("transaction commits nonce target and audit together",commit)
    def replay():
        with database.SessionLocal() as db:
            try:
                with db.begin():
                    stage_trial_revocation(db,intent=intent,challenge_id=challenge)
            except MutationIntentRefused: pass
            else: raise AssertionError("replay admitted")
        with database.SessionLocal() as db:
            assert db.query(models.AuditLog).filter_by(action="PLATFORM_TRIAL_REVOKED",resource_id=str(trial["id"])).count()==1
    tx_check("transaction rejects replay without duplicate audit",replay)
    request("facade sees persisted synthetic revocation", F + "/trial-codes", 200, token=uv, approval=approval)
    # Dedicated HTTP pilot. Use independent real Desktop password approval for a second fixture.
    trial2, _ = request("pilot second synthetic trial", "/api/superadmin/trial-codes", 200, method="POST",
        token=desktop,cookie=cookie,data={"email":"ci-trial2@example.com","trial_days":14})
    target = F + "/trial-codes/" + str(trial2["id"])
    prepare = target + "/revocation-intent"
    approve = target + "/desktop-approval"
    execute = target + "/revoke"
    request("pilot prepare requires platform approval",prepare,403,method="POST",token=uv,origin=ORIGIN)
    binding, _ = request("pilot Pocket prepares exact intent",prepare,200,method="POST",token=uv,approval=approval,origin=ORIGIN)
    assert set(binding)=={"device_id","approval_jti","uv_jti_hash","nonce"}
    body={**binding,"password":os.environ["DC_SYNTH_PASSWORD"],"confirm":True}
    request("pilot Pocket cannot approve itself",approve,401,method="POST",token=uv,approval=approval,origin=ORIGIN,data=body)
    request("pilot ordinary Desktop cannot approve",approve,403,method="POST",token=ordinary_desktop,cookie=ordinary_cookie,data=body)
    request("pilot Desktop confirmation required",approve,409,method="POST",token=desktop,cookie=cookie,data={**body,"confirm":False})
    granted, _ = request("pilot independent Desktop action approval",approve,200,method="POST",token=desktop,cookie=cookie,data=body)
    execution={"challenge_id":granted["challenge_id"],"nonce":binding["nonce"],"confirm":True}
    request("pilot wrong target denied",F+"/trial-codes/"+str(trial["id"])+"/revoke",409,method="POST",token=uv,approval=approval,origin=ORIGIN,data=execution)
    request("pilot wrong nonce denied",execute,409,method="POST",token=uv,approval=approval,origin=ORIGIN,data={**execution,"nonce":secrets.token_hex(32)})
    request("pilot wrong origin denied",execute,409,method="POST",token=uv,approval=approval,origin="https://invalid.example",data=execution)
    request("pilot missing approval denied",execute,403,method="POST",token=uv,origin=ORIGIN,data=execution)
    request("pilot confirmation required",execute,409,method="POST",token=uv,approval=approval,origin=ORIGIN,data={**execution,"confirm":False})
    with database.SessionLocal() as db:
        assert db.get(models.TrialActivationCode,trial2["id"]).revoked_at is None
    # Simultaneous requests for the same valid one-shot proof: exactly one commit.
    simultaneous = Barrier(2)
    def attempt_execution(i):
        simultaneous.wait(timeout=10)
        request("pilot concurrent execution " + str(i),execute,(200,409),method="POST",
                token=uv,approval=approval,origin=ORIGIN,data=execution)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(attempt_execution,(1,2)))
    tx_check("pilot simultaneous requests exactly one success",lambda: (
        None if sorted(row["status"] for row in rows if row["label"].startswith("pilot concurrent execution "))==[200,409]
        else (_ for _ in ()).throw(AssertionError("expected exactly one success and one conflict"))))
    request("pilot execution replay denied",execute,409,method="POST",token=uv,approval=approval,origin=ORIGIN,data=execution)
    with database.SessionLocal() as db:
        assert db.get(models.TrialActivationCode,trial2["id"]).revoked_at is not None
        assert db.query(models.AuditLog).filter_by(action="PLATFORM_TRIAL_REVOKED",resource_id=str(trial2["id"])).count()==1
        assert db.query(models.AuditLog).filter_by(action="PLATFORM_TRIAL_REVOCATION_APPROVED",resource_id=str(trial2["id"])).count()==1
        assert db.get(MobileWebAuthnChallenge,granted["challenge_id"]).used_at is not None
    # Fresh independent approval for another inert fixture, then expire the proof in LAB.
    trial3, _ = request("pilot expiry synthetic trial", "/api/superadmin/trial-codes",200,method="POST",
        token=desktop,cookie=cookie,data={"email":"ci-trial3@example.com","trial_days":14})
    path3=F+"/trial-codes/"+str(trial3["id"])
    binding3,_=request("pilot expiry prepare",path3+"/revocation-intent",200,method="POST",token=uv,approval=approval,origin=ORIGIN)
    grant3,_=request("pilot expiry Desktop confirmation",path3+"/desktop-approval",200,method="POST",
        token=desktop,cookie=cookie,data={**binding3,"password":os.environ["DC_SYNTH_PASSWORD"],"confirm":True})
    from datetime import datetime,timedelta
    with database.SessionLocal() as db:
        challenge3=db.get(MobileWebAuthnChallenge,grant3["challenge_id"])
        challenge3.expires_at=datetime.utcnow()-timedelta(seconds=1)
        db.commit()
    execution3={"challenge_id":grant3["challenge_id"],"nonce":binding3["nonce"],"confirm":True}
    request("pilot expired intent denied",path3+"/revoke",409,method="POST",token=uv,approval=approval,origin=ORIGIN,data=execution3)
    def expired_unchanged():
        with database.SessionLocal() as db:
            assert db.get(models.TrialActivationCode,trial3["id"]).revoked_at is None
            assert db.get(MobileWebAuthnChallenge,grant3["challenge_id"]).used_at is None
            assert db.query(models.AuditLog).filter_by(action="PLATFORM_TRIAL_REVOKED",resource_id=str(trial3["id"])).count()==0
    tx_check("pilot expiry leaves target and audit unchanged",expired_unchanged)
    # No manual secret transfer: Desktop finds a server-persisted exact request.
    trial4,_=request("rendezvous synthetic trial","/api/superadmin/trial-codes",200,method="POST",
        token=desktop,cookie=cookie,data={"email":"ci-trial4@example.com","trial_days":14})
    path4=F+"/trial-codes/"+str(trial4["id"])
    inbox=F+"/revocation-requests"
    pending,_=request("Pocket creates persisted revocation request",path4+"/revocation-request",200,
        method="POST",token=uv,approval=approval,origin=ORIGIN)
    assert set(pending)=={"challenge_id","nonce","expires_in"}
    checkbody={"challenge_id":pending["challenge_id"],"nonce":pending["nonce"]}
    request("Pocket cannot list Desktop pending requests",inbox,401,token=uv,approval=approval)
    request("ordinary Desktop cannot list platform requests",inbox,403,token=ordinary_desktop,cookie=ordinary_cookie)
    listing,_=request("Desktop sees exact pending request",inbox,200,token=desktop,cookie=cookie)
    assert len(listing)==1 and listing[0]["request_id"]==pending["challenge_id"] and listing[0]["target_id"]==trial4["id"]
    assert set(listing[0])=={"request_id","target_id","email","cabinet_name","device_id","expires_in"} and pending["nonce"] not in json.dumps(listing)
    status4,_=request("Pocket observes pending state",path4+"/revocation-status",200,method="POST",
        token=uv,approval=approval,origin=ORIGIN,data=checkbody)
    assert status4["state"]=="pending"
    request("pending request cannot execute",path4+"/revoke",409,method="POST",token=uv,approval=approval,origin=ORIGIN,data={**checkbody,"confirm":True})
    approval4=inbox+"/"+pending["challenge_id"]+"/approve"
    b4={"target_id":trial4["id"],"password":os.environ["DC_SYNTH_PASSWORD"],"confirm":True}
    request("Desktop cannot approve wrong target",approval4,409,method="POST",token=desktop,cookie=cookie,data={**b4,"target_id":trial3["id"]})
    request("Desktop explicitly approves stored target",approval4,200,method="POST",token=desktop,cookie=cookie,data=b4)
    request("Desktop approval replay denied",approval4,409,method="POST",token=desktop,cookie=cookie,data=b4)
    request("Pocket wrong nonce cannot see approval",path4+"/revocation-status",409,method="POST",
        token=uv,approval=approval,origin=ORIGIN,data={**checkbody,"nonce":secrets.token_hex(32)})
    approved4,_=request("Pocket observes approved state",path4+"/revocation-status",200,method="POST",
        token=uv,approval=approval,origin=ORIGIN,data=checkbody)
    assert approved4["state"]=="approved"
    request("Pocket executes stored approved request",path4+"/revoke",200,method="POST",token=uv,approval=approval,origin=ORIGIN,data={**checkbody,"confirm":True})
    request("Pocket stored approval replay denied",path4+"/revoke",409,method="POST",token=uv,approval=approval,origin=ORIGIN,data={**checkbody,"confirm":True})
    with database.SessionLocal() as db:
        assert db.get(models.TrialActivationCode,trial4["id"]).revoked_at is not None
        assert db.query(models.AuditLog).filter_by(action="PLATFORM_TRIAL_REVOKED",resource_id=str(trial4["id"])).count()==1
        assert db.query(models.AuditLog).filter_by(action="PLATFORM_TRIAL_REVOCATION_APPROVED",resource_id=str(trial4["id"])).count()==1
    # Separate fresh isolated LAB jobs preserve the real rate-limit budget.
    variant=os.environ.get("DC_RACE_VARIANT","full")
    assert variant in ("full","terminal-race")
    if variant=="full":
        # Exact cancellation must retire pending and approved requests, not the trial itself.
        trial5,_=request("cancel synthetic trial","/api/superadmin/trial-codes",200,method="POST",
            token=desktop,cookie=cookie,data={"email":"ci-trial5@example.com","trial_days":14})
        path5=F+"/trial-codes/"+str(trial5["id"])
        def cancel_fixture():
            p5,_=request("cancel fixture request",path5+"/revocation-request",200,method="POST",token=uv,approval=approval,origin=ORIGIN)
            return {"challenge_id":p5["challenge_id"],"nonce":p5["nonce"]}
        def cancel_call(body,expected,**kwargs):
            return request("cancel exact proof "+str(expected),path5+"/revocation-cancel",expected,method="POST",
                token=uv,approval=approval,origin=ORIGIN,data=body,**kwargs)
        pending5=cancel_fixture()
        cancel_call({**pending5,"nonce":secrets.token_hex(32)},409)
        cancel_call(pending5,200)
        request("cancelled pending absent from inbox",inbox,200,token=desktop,cookie=cookie)
        request("cancelled pending cannot be approved",inbox+"/"+pending5["challenge_id"]+"/approve",409,
            method="POST",token=desktop,cookie=cookie,data={"target_id":trial5["id"],"password":os.environ["DC_SYNTH_PASSWORD"],"confirm":True})
        request("cancelled pending cannot execute",path5+"/revoke",409,method="POST",token=uv,approval=approval,origin=ORIGIN,data={**pending5,"confirm":True})
        pending6=cancel_fixture()
        request("Desktop approves separate cancellation fixture",inbox+"/"+pending6["challenge_id"]+"/approve",200,
            method="POST",token=desktop,cookie=cookie,data={"target_id":trial5["id"],"password":os.environ["DC_SYNTH_PASSWORD"],"confirm":True})
        cancel_call(pending6,200)
        cancel_call(pending6,409)
        request("cancelled approved intent cannot execute",path5+"/revoke",409,method="POST",token=uv,approval=approval,origin=ORIGIN,data={**pending6,"confirm":True})
        def cancellation_persistence():
            with database.SessionLocal() as db:
                assert db.get(models.TrialActivationCode,trial5["id"]).revoked_at is None
                assert db.query(models.AuditLog).filter_by(action="PLATFORM_TRIAL_REVOKED",resource_id=str(trial5["id"])).count()==0
                assert db.query(models.AuditLog).filter_by(action="PLATFORM_TRIAL_REVOCATION_CANCELLED",resource_id=str(trial5["id"]),severity="CRITICAL").count()==2
        tx_check("cancel both phases persists without revoking trial",cancellation_persistence)
        # Exercise the real production quota, not a test override.
        limited=cancel_fixture()
        limited_path=inbox+"/"+limited["challenge_id"]+"/approve"
        request("sixth Desktop rendezvous approval rate limited",limited_path,429,method="POST",
            token=desktop,cookie=cookie,data={"target_id":trial5["id"],"password":os.environ["DC_SYNTH_PASSWORD"],"confirm":True})
        def rate_limit_persistence():
            with database.SessionLocal() as db:
                assert db.get(models.TrialActivationCode,trial5["id"]).revoked_at is None
                assert db.get(MobileWebAuthnChallenge,limited["challenge_id"]).used_at is None
                assert db.query(models.AuditLog).filter_by(action="PLATFORM_TRIAL_REVOCATION_APPROVED",resource_id=str(trial5["id"])).count()==1
        tx_check("rate limit preserves target and does not create approval audit",rate_limit_persistence)
    else:
        # Race between cancellation and execution of a single already approved intent.
        race_trial,_=request("cancel-execute race fixture","/api/superadmin/trial-codes",200,method="POST",
            token=desktop,cookie=cookie,data={"email":"ci-race-cancel@example.com","trial_days":14})
        racepath=F+"/trial-codes/"+str(race_trial["id"])
        race_intent,_=request("cancel-execute race prepare",racepath+"/revocation-request",200,method="POST",
            token=uv,approval=approval,origin=ORIGIN)
        rb={"challenge_id":race_intent["challenge_id"],"nonce":race_intent["nonce"]}
        request("cancel-execute race Desktop approval",inbox+"/"+rb["challenge_id"]+"/approve",200,method="POST",
            token=desktop,cookie=cookie,data={"target_id":race_trial["id"],"password":os.environ["DC_SYNTH_PASSWORD"],"confirm":True})
        gate=Barrier(2)
        def cancel_execute_race(action):
            gate.wait(timeout=10)
            request("cancel-execute race "+action,racepath+"/"+action,(200,409),method="POST",token=uv,
                approval=approval,origin=ORIGIN,data=rb if action=="revocation-cancel" else {**rb,"confirm":True})
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(cancel_execute_race,("revocation-cancel","revoke")))
        def race_persisted():
            outcomes={r["label"]:r["status"] for r in rows if r["label"] in ("cancel-execute race revocation-cancel","cancel-execute race revoke")}
            assert sorted(outcomes.values())==[200,409]
            cancelled=outcomes["cancel-execute race revocation-cancel"]==200
            with database.SessionLocal() as db:
                assert (db.get(models.TrialActivationCode,race_trial["id"]).revoked_at is None)==cancelled
                for action,expected in (("PLATFORM_TRIAL_REVOCATION_CANCELLED",int(cancelled)),("PLATFORM_TRIAL_REVOKED",int(not cancelled))):
                    assert db.query(models.AuditLog).filter_by(action=action,resource_id=str(race_trial["id"]),severity="CRITICAL").count()==expected
                assert db.get(MobileWebAuthnChallenge,rb["challenge_id"]).used_at is not None
        tx_check("cancel-execute race exactly one terminal audit and consistent target",race_persisted)
        request("cancel-execute race proof cannot cancel twice",racepath+"/revocation-cancel",409,method="POST",token=uv,approval=approval,origin=ORIGIN,data=rb)
        request("cancel-execute race proof cannot execute twice",racepath+"/revoke",409,method="POST",token=uv,approval=approval,origin=ORIGIN,data={**rb,"confirm":True})
    overview, _ = request("facade Marketplace summary", F + "/marketplace/overview", 200, token=uv, approval=approval)
    desktop_overview, _ = request("Desktop Marketplace summary for comparison", S, 200, token=desktop, cookie=cookie)
    assert overview == desktop_overview
    request("facade read-only clients POST refused", F + "/clients", 405, method="POST", token=uv, approval=approval, data={})
    request("facade read-only trials POST refused", F + "/trial-codes", 405, method="POST", token=uv, approval=approval, data={})
    request("legacy detailed Marketplace mobile route denied", "/api/superadmin/marketplace/orders", 403, token=uv, approval=approval)
    request("approval alone is not Desktop session", "/api/superadmin/clients", 401, token=approval)
    request("approval alone is not mobile UV session", S, 401, token=approval)
    request("tampered approval refused", S, 403, token=uv, approval=approval[:-5]+"xxxxx")
    request("active mobile UV cannot mutate Marketplace", "/api/superadmin/marketplace/suppliers/999999/governance",
            403, method="PATCH", token=uv, approval=approval, data={"confirm": True, "isActive": False})
    request("desktop mutation boundary unchanged", "/api/superadmin/marketplace/suppliers/999999/governance",
            404, method="PATCH", token=desktop, cookie=cookie, data={"confirm": True, "isActive": False})
    request("UV mobile token refused on desktop clients", "/api/superadmin/clients", 401, token=uv)
    # Parallel A: existing mobile facade must remain read-only before any new mutation design.
    for resource in ("/clients", "/trial-codes", "/marketplace/overview"):
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            request("A baseline mobile facade refuses " + method + " " + resource,
                    F + resource, 405, method=method, token=uv, approval=approval,
                    data={} if method != "DELETE" else None)
    request("A baseline read remains authorized after mutation denials", F + "/clients", 200,
            token=uv, approval=approval)
    request("disable credential after UV", P, 200, method="DELETE", token=uv)
    request("disabled credential must invalidate old privileged token", S, (401,403,423), token=uv, approval=approval, soft=True)
    request("stale UV cannot enable another credential", P + "/enable", 423, method="POST",
            token=uv, data={"credential_id": b64(cid)})
    reg2, _ = request("re-enrollment challenge", P + "/registration/options", 200, method="POST", token=token, origin=ORIGIN)
    request("re-enroll same authenticator", P + "/registration/verify", 200, method="POST", token=token,
            origin=ORIGIN, data=verify_body(reg2, register(reg2, key, cid)))
    fresh = options(token)
    renewed, _ = request("fresh UV after re-enrollment", P + "/authentication/verify", 200, method="POST", token=token,
                         origin=ORIGIN, data=verify_body(fresh, assertion(fresh, key, cid, 2)))
    uv2 = renewed["access_token"]
    request("enable re-enrolled credential", P + "/enable", 200, method="POST", token=uv2, data={"credential_id": b64(cid)})
    request("old UV remains denied after same credential re-enrollment", S, 423, token=uv)
    request("old approval cannot authorize re-enrollment", S, 403, token=uv2, approval=approval)
    request("facade old approval cannot authorize re-enrollment", F + "/clients", 403, token=uv2, approval=approval)
    request("fresh UV without new Desktop approval denied", S, 403, token=uv2)
    granted2, _ = request("Desktop approves replacement credential", approve_path, 200, method="POST",
                          token=desktop, cookie=cookie, data=approve_body)
    claimed2, _ = request("replacement Pocket exchanges Desktop ticket", claim_path, 200, method="POST",
                          token=uv2, origin=ORIGIN, data={"ticket": granted2["ticket"]})
    approval = claimed2["approval"]
    request("fresh UV accepted after re-enrollment", S, 200, token=uv2, approval=approval)
    next_challenge = options(token)
    next_verified, _ = request("new signed UV ceremony", P + "/authentication/verify", 200, method="POST", token=token,
                               origin=ORIGIN, data=verify_body(next_challenge, assertion(next_challenge, key, cid, 3)))
    uv3 = next_verified["access_token"]
    request("previous UV invalidated by new ceremony", S, 423, token=uv2)
    request("latest UV active", S, 200, token=uv3, approval=approval)
    ordinary_reg, _ = request("ordinary registration challenge", P + "/registration/options", 200, method="POST",
                              token=other, origin=ORIGIN)
    ordinary_key, ordinary_cid = ec.generate_private_key(ec.SECP256R1()), secrets.token_bytes(32)
    request("ordinary registration verified", P + "/registration/verify", 200, method="POST", token=other,
            origin=ORIGIN, data=verify_body(ordinary_reg, register(ordinary_reg, ordinary_key, ordinary_cid)))
    ordinary_auth = options(other)
    ordinary_verified, _ = request("ordinary signed UV", P + "/authentication/verify", 200, method="POST", token=other,
                                    origin=ORIGIN, data=verify_body(ordinary_auth, assertion(ordinary_auth, ordinary_key, ordinary_cid, 1)))
    ordinary_uv = ordinary_verified["access_token"]
    request("ordinary credential enabled", P + "/enable", 200, method="POST", token=ordinary_uv,
            data={"credential_id": b64(ordinary_cid)})
    request("ordinary active UV never gains platform authority", S, 403, token=ordinary_uv, approval=approval)
    request("facade ordinary active UV denied with approval", F + "/clients", 403, token=ordinary_uv, approval=approval)
    request("ordinary active UV eligibility refused", eligible, 403, token=ordinary_uv)
    own_only, _ = request("Desktop discovery excludes other active passkey", discover, 200, token=desktop, cookie=cookie)
    assert len(own_only) == 1 and own_only[0]["device_id"] == mobile["device_id"]

    # Real HTTP races; no test-generated JWT, clock override or mocked verifier.
    superseded = options(token)
    current = options(token)
    request("superseded live challenge refused", P + "/authentication/verify", 410, method="POST",
            token=token, origin=ORIGIN, data=verify_body(superseded, assertion(superseded, key, cid, 4)))
    request("cross-device challenge rejected", P + "/authentication/verify", 410, method="POST",
            token=other, origin=ORIGIN, data=verify_body(current, assertion(current, key, cid, 4)))
    concurrent_body = verify_body(current, assertion(current, key, cid, 4))
    gate = Barrier(2)
    def concurrent_verify():
        gate.wait(timeout=10)
        return request("simultaneous one-shot UV verification", P + "/authentication/verify", (200, 410),
                       method="POST", token=token, origin=ORIGIN, data=concurrent_body)[0]
    with ThreadPoolExecutor(max_workers=2) as workers:
        a, b = workers.submit(concurrent_verify), workers.submit(concurrent_verify)
        outcomes = [a.result(), b.result()]
    winners = [result for result in outcomes if isinstance(result, dict) and "access_token" in result]
    race_rows = [row for row in rows if row["label"] == "simultaneous one-shot UV verification"]
    assert sorted(row["status"] for row in race_rows) == [200, 410] and len(winners) == 1
    winner = winners[0]
    uv3 = winner["access_token"]
    request("winning UV session active", S, 200, token=uv3, approval=approval)
    expiring_grant, _ = request("Desktop issues expiring transfer", approve_path, 200, method="POST",
                                token=desktop, cookie=cookie, data=approve_body)
    expiring_challenge = options(token)
    # Use the actual production TTL and wall-clock passage, never shorten it.
    assert winner["expires_in"] == 300
    print("LOT01_R5_UV_REAL_EXPIRY_BEGIN", flush=True)
    start = time.monotonic()
    time.sleep(winner["expires_in"] + 2)
    assert time.monotonic() - start >= winner["expires_in"]
    request("expired UV token refused on platform API", S, 401, token=uv3, approval=approval)
    request("facade expired UV denied", F + "/clients", 401, token=uv3, approval=approval)
    request("expired UV token refused on passkey API", P + "/status", 401, token=uv3)
    request("expired challenge refused", P + "/authentication/verify", 410, method="POST",
            token=token, origin=ORIGIN, data=verify_body(expiring_challenge, assertion(expiring_challenge, key, cid, 5)))
    refreshed = options(token)
    replacement, _ = request("new UV after actual expiration", P + "/authentication/verify", 200, method="POST",
                              token=token, origin=ORIGIN, data=verify_body(refreshed, assertion(refreshed, key, cid, 5)))
    uv3 = replacement["access_token"]
    request("fresh UV active after expiration", S, 200, token=uv3, approval=approval)
    request("expired Desktop transfer refused with fresh UV", claim_path, 410, method="POST",
            token=uv3, origin=ORIGIN, data={"ticket": expiring_grant["ticket"]})
    # Ordinary session also expired during the real-time window; authenticate again.
    ordinary_fresh = options(other)
    ordinary_new, _ = request("ordinary UV renewed after expiration", P + "/authentication/verify", 200, method="POST",
                               token=other, origin=ORIGIN, data=verify_body(ordinary_fresh, assertion(ordinary_fresh, ordinary_key, ordinary_cid, 2)))
    ordinary_uv = ordinary_new["access_token"]
    request("desktop revokes paired platform device", "/api/admin/mobile-devices/" + mobile["device_id"] + "/revoke",
            200, method="POST", token=desktop, cookie=cookie)
    request("revoked device current UV refused", S, 401, token=uv3, approval=approval)
    request("facade revoked device denied", F + "/trial-codes", 401, token=uv3, approval=approval)
    revoked_devices, _ = request("Desktop discovery excludes revoked device", discover, 200, token=desktop, cookie=cookie)
    assert revoked_devices == []
    request("revoked device durable refresh refused", M + "/refresh-token", 401, method="POST",
            data={"refresh_token": mobile["refresh_token"]})
    request("other device remains alive", P + "/status", 200, token=other)
    request("other device active UV still valid", P + "/status", 200, token=ordinary_uv)
    request("tenant-wide revoke ordinary sessions", "/api/admin/revoke-mobile", 200, method="POST",
            token=ordinary_desktop, cookie=ordinary_cookie)
    request("tenant-wide revoke invalidates active UV", P + "/status", 401, token=ordinary_uv)
    request("tenant-wide revoke invalidates durable token", P + "/status", 401, token=other)
    request("desktop platform unchanged", S, 200, token=desktop, cookie=cookie)
    assert all(row["pass"] for row in rows), "R5 negative security expectation failed"

try:
    run()
finally:
    evidence = Path(os.environ["DC_EVIDENCE"])
    evidence.joinpath("platform-uv-status.json").write_text(json.dumps(rows, indent=2))
