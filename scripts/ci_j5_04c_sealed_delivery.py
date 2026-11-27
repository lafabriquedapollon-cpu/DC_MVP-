"""Seal only a freshly qualified nonclinical PE; no raw binary in public artifacts."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RECIPIENT=b"""-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAsrzkn8B5C4EL/JhDxmz+
XPb4eMcQiSe+Rqxaw5TMiPjGCoaEYfJY7C+/SeymQr2/6K7SSKPmgwv/kAzaKUzD
rFl04QAF8Meh7JzSQ76o8sWWqx3SAbJGlPuNI4qzo96UYwNYla2FmysGD/u34DG6
arLGGjOT7NVkOpH87kIf5nIDxWk+lrAo7VEz3fX/WGSp9C5ENjjQFJWxejTctwUO
NmWO0jk/rYfB59y2NHGsIq7jGIo8R+Gh4MNnBza/1nPwd5sboXneBQgPIqsxlsZT
O+XjXoSfZBDAqhRk1UbOPYlTjrBlUAea/TGtKbm2I4hS5x0nzxhwf+0xNVCYOsbg
melfNA7OoCYPddwBJlUFN2ZuzOEWSmKHaMcBMGOH/RYdH1VCb7IswfR5+Fx/U6mm
bpplDbVr7wi0QtlxNXTbRcHQ1Ricncyxo3MKy3lVYt3xJbtCvTaKij21l7bpeAFo
MZlei6L+nqCnuieS7DYUYYL9C2l13ZapJWGZUS8byEHxAgMBAAE=
-----END PUBLIC KEY-----
"""
RECIPIENT_SHA="20c184a56334930bdd4a83277c5ab69825b107e15ab410111c64ece7eeb846d1"
DOMAIN=b"DC-J5-04C-PORTABLE-DELIVERY-V1"
CHUNK=64*1024*1024
def require(ok,marker):
    if not ok:raise RuntimeError(marker)
def sha(data):return hashlib.sha256(data).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")
def ordinary(p):return not p.is_symlink() and not (getattr(p.stat(),"st_file_attributes",0)&stat.FILE_ATTRIBUTE_REPARSE_POINT)
def oaep():return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=DOMAIN)
def aad(header,index):return DOMAIN+b"\0"+canonical(header)+b"\0"+str(index).encode("ascii")
def seal(setup,runner,expected_hash):
    require(os.name=="nt" and os.getenv("GITHUB_ACTIONS")=="true" and os.getenv("RUNNER_ENVIRONMENT")=="github-hosted","DELIVERY_CI_ONLY")
    require(os.getenv("GITHUB_REPOSITORY")=="lafabriquedapollon-cpu/DC_MVP-" and os.getenv("GITHUB_REF_NAME")=="ci/j5-04c-private-delivery-20261127","DELIVERY_REF_REFUSED")
    runner=Path(runner).resolve(strict=True)
    require(runner==Path(os.environ["RUNNER_TEMP"]).resolve(strict=True),"DELIVERY_RUNNER_ROOT")
    setup=Path(setup)
    require(setup.parent.parent==runner and setup.parent.name.startswith("dc-installer-rehearsal-") and setup.name=="DigitalCrown-Commissioning-Setup.exe" and ordinary(setup.parent) and setup.is_file() and ordinary(setup),"DELIVERY_PE_SCOPE")
    size=setup.stat().st_size
    require(6*CHUNK<size<=7*CHUNK,"DELIVERY_SIZE_OUTSIDE_SEVEN_PARTS")
    head=os.environ["GITHUB_SHA"];rid=os.environ["GITHUB_RUN_ID"];attempt=os.environ["GITHUB_RUN_ATTEMPT"]
    require(re.fullmatch(r"[0-9a-f]{40}",head) and re.fullmatch(r"[0-9]+",rid) and re.fullmatch(r"[0-9]+",attempt) and re.fullmatch(r"[0-9a-f]{64}",expected_hash),"DELIVERY_IDENTITY")
    require(sha(RECIPIENT)==RECIPIENT_SHA,"RECIPIENT_FINGERPRINT")
    public=serialization.load_pem_public_key(RECIPIENT)
    require(public.key_size==3072,"RECIPIENT_KEY_SIZE")
    root=runner/f"dc-commissioning-transfer-{rid}-{attempt}"
    root.mkdir(exist_ok=False)
    header={"schema":1,"domain":DOMAIN.decode(),"repository":os.environ["GITHUB_REPOSITORY"],"ref":os.environ["GITHUB_REF_NAME"],"head":head,"run_id":rid,"run_attempt":attempt,"name":setup.name,"size":size,"sha256":expected_hash,"recipient_sha256":RECIPIENT_SHA,"chunk_size":CHUNK,"count":7,"scope":"SYNTHETIC_NONCLINICAL_NOT_A_RELEASE"}
    key=AESGCM.generate_key(bit_length=256)
    aes=AESGCM(key)
    wrapped=public.encrypt(key,oaep())
    parts=[];nonces=set();whole=hashlib.sha256();total=0
    with setup.open("rb") as src:
        for index in range(1,8):
            clear=src.read(CHUNK)
            require(len(clear)==min(CHUNK,size-total),"DELIVERY_PART_SIZE")
            if index==1:require(clear[:2]==b"MZ","DELIVERY_PE_MAGIC")
            whole.update(clear);total+=len(clear)
            nonce=secrets.token_bytes(12)
            require(nonce not in nonces,"DELIVERY_NONCE_REUSE");nonces.add(nonce)
            ciphertext=nonce+aes.encrypt(nonce,clear,aad(header,index))
            require(aes.decrypt(nonce,ciphertext[12:],aad(header,index))==clear,"DELIVERY_SEAL_ROUNDTRIP")
            # Negative controls with actual AEAD: wrong chunk identity and mutation.
            if index==1:
                from cryptography.exceptions import InvalidTag
                for data,context in ((ciphertext[12:],aad(header,2)),(ciphertext[12:-1]+bytes([ciphertext[-1]^1]),aad(header,index))):
                    try:aes.decrypt(nonce,data,context)
                    except InvalidTag:pass
                    else:raise RuntimeError("DELIVERY_TAMPER_ACCEPTED")
            name=f"part-{index:02d}.bin"
            with (root/name).open("xb") as out:out.write(ciphertext)
            parts.append({"index":index,"name":name,"size":len(ciphertext),"sha256":sha(ciphertext),"plaintext_size":len(clear)})
            del clear,ciphertext
        require(not src.read(1),"DELIVERY_UNEXPECTED_TAIL")
    require(total==size and whole.hexdigest()==expected_hash,"DELIVERY_QUALIFIED_PE_CHANGED")
    manifest={"header":header,"wrapped_dek":base64.b64encode(wrapped).decode("ascii"),"parts":parts}
    data=canonical(manifest)+b"\n"
    with (root/"manifest.json").open("xb") as out:out.write(data)
    require(set(p.name for p in root.iterdir())=={"manifest.json",*(x["name"] for x in parts)},"DELIVERY_STAGE_FILE_SET")
    print("J5_04C_SEALED_DELIVERY_PASS parts=7 bytes="+str(size)+" pe_sha256="+expected_hash+" manifest_sha256="+sha(data),flush=True)
