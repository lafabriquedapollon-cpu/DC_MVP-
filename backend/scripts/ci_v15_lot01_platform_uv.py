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
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
rows = []

def b64(x):
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode("ascii")

def sha(x):
    return hashlib.sha256(x).digest()

def request(label, path, expected, *, method="GET", token=None, data=None,
            cookie=None, origin=None, soft=False, form=False):
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    if cookie:
        headers["Cookie"] = cookie
    if origin:
        headers["Origin"] = origin
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
    enabled, _ = request("enable credential after UV", P + "/enable", 200, method="POST", token=uv,
                         data={"credential_id": b64(cid)})
    assert enabled["state"] == "enabled"
    request("durable token denied after enabling gate", S, (403,423), token=token)
    request("active verified platform read", S, 200, token=uv)
    request("active mobile UV cannot mutate Marketplace", "/api/superadmin/marketplace/suppliers/999999/governance",
            403, method="PATCH", token=uv, data={"confirm": True, "isActive": False})
    request("desktop mutation boundary unchanged", "/api/superadmin/marketplace/suppliers/999999/governance",
            404, method="PATCH", token=desktop, cookie=cookie, data={"confirm": True, "isActive": False})
    request("UV mobile token refused on desktop clients", "/api/superadmin/clients", 401, token=uv)
    request("disable credential after UV", P, 200, method="DELETE", token=uv)
    request("disabled credential must invalidate old privileged token", S, (401,403,423), token=uv, soft=True)
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
    request("fresh UV accepted after re-enrollment", S, 200, token=uv2)
    next_challenge = options(token)
    next_verified, _ = request("new signed UV ceremony", P + "/authentication/verify", 200, method="POST", token=token,
                               origin=ORIGIN, data=verify_body(next_challenge, assertion(next_challenge, key, cid, 3)))
    uv3 = next_verified["access_token"]
    request("previous UV invalidated by new ceremony", S, 423, token=uv2)
    request("latest UV active", S, 200, token=uv3)
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
    request("ordinary active UV never gains platform authority", S, 403, token=ordinary_uv)

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
    request("winning UV session active", S, 200, token=uv3)
    expiring_challenge = options(token)
    # Use the actual production TTL and wall-clock passage, never shorten it.
    assert winner["expires_in"] == 300
    print("LOT01_R5_UV_REAL_EXPIRY_BEGIN", flush=True)
    start = time.monotonic()
    time.sleep(winner["expires_in"] + 2)
    assert time.monotonic() - start >= winner["expires_in"]
    request("expired UV token refused on platform API", S, 401, token=uv3)
    request("expired UV token refused on passkey API", P + "/status", 401, token=uv3)
    request("expired challenge refused", P + "/authentication/verify", 410, method="POST",
            token=token, origin=ORIGIN, data=verify_body(expiring_challenge, assertion(expiring_challenge, key, cid, 5)))
    refreshed = options(token)
    replacement, _ = request("new UV after actual expiration", P + "/authentication/verify", 200, method="POST",
                              token=token, origin=ORIGIN, data=verify_body(refreshed, assertion(refreshed, key, cid, 5)))
    uv3 = replacement["access_token"]
    request("fresh UV active after expiration", S, 200, token=uv3)
    # Ordinary session also expired during the real-time window; authenticate again.
    ordinary_fresh = options(other)
    ordinary_new, _ = request("ordinary UV renewed after expiration", P + "/authentication/verify", 200, method="POST",
                               token=other, origin=ORIGIN, data=verify_body(ordinary_fresh, assertion(ordinary_fresh, ordinary_key, ordinary_cid, 2)))
    ordinary_uv = ordinary_new["access_token"]
    request("desktop revokes paired platform device", "/api/admin/mobile-devices/" + mobile["device_id"] + "/revoke",
            200, method="POST", token=desktop, cookie=cookie)
    request("revoked device current UV refused", S, 401, token=uv3)
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
