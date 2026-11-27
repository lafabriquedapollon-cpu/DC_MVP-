import base64,json,os
from pathlib import Path
from webauthn import verify_registration_response,verify_authentication_response
from webauthn.helpers.structs import COSEAlgorithmIdentifier
p=Path(os.environ["RUNNER_TEMP"])/"passkey-lab-proof.json"
def dec(s):return base64.urlsafe_b64decode(s+"="*(-len(s)%4))
try:
 d=json.loads(p.read_bytes())
 assert d["domain"]=="DIGITAL-CROWN/PASSKEY-BROWSER-LAB/NOT-A-RELEASE/v1"
 assert d["rp"]=="127.0.0.1" and d["origin"].startswith("http://127.0.0.1:")
 r=verify_registration_response(credential=d["registration"],expected_challenge=dec(d["registrationChallenge"]),expected_rp_id=d["rp"],expected_origin=d["origin"],require_user_verification=True,supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_256])
 assert dec(d["authentication"]["id"])==r.credential_id
 verify_authentication_response(credential=d["authentication"],expected_challenge=dec(d["authenticationChallenge"]),expected_rp_id=d["rp"],expected_origin=d["origin"],credential_public_key=r.credential_public_key,credential_current_sign_count=r.sign_count,require_user_verification=True)
 print("INDEPENDENT_BROWSER_PROOF_PASS NOT_OWNER_ENROLLED")
finally:p.unlink(missing_ok=True)
