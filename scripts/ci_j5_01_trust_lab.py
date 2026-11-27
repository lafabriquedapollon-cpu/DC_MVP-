"""TRUST-02-LAB only. No production trust anchor, clinical certificate or startup."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time

REPO = "lafabriquedapollon-cpu/DC_MVP-"
REPO_ID = 1468617084
OWNER_ID = 262976758
REF = "refs/heads/ci/j5-01-release-pipeline-20261127"
WORKFLOW = REPO + "/.github/workflows/j5-01-trust-lab.yml"
DOMAIN = "DIGITAL-CROWN/J5-01-LAB/NOT-A-RELEASE/v1"


class Denied(RuntimeError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked(argv):
    return subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=90, check=False)


def openssl(*args):
    return checked(["openssl", *map(str, args)])


def sign(private, record, root):
    p = root / "approval-input"
    s = root / "approval-signature"
    p.write_bytes(canonical(record))
    if openssl("pkeyutl", "-sign", "-rawin", "-inkey", private, "-in", p, "-out", s).returncode:
        raise RuntimeError("LAB_SIGN_FAILED")
    return s.read_bytes()


def verify_approval(record, signature, *, expected, public, public_pin, now, scratch):
    if type(record) is not dict or set(record) != set(expected) | {"nonce", "issued", "expires"}:
        raise Denied("SCHEMA")
    for k, v in expected.items():
        if type(record[k]) is not type(v) or record[k] != v:
            raise Denied("BINDING")
    if not isinstance(record["nonce"], str) or not re.fullmatch("[0-9a-f]{32}", record["nonce"]):
        raise Denied("NONCE")
    start, end = record["issued"], record["expires"]
    if type(start) is not int or type(end) is not int or not (start <= now < end and 0 < end-start <= 300):
        raise Denied("TIME")
    if public.is_symlink() or not public.is_file() or digest(public) != public_pin:
        raise Denied("ANCHOR")
    p = scratch / "verify-input"
    s = scratch / "verify-signature"
    p.write_bytes(canonical(record))
    s.write_bytes(signature)
    if openssl("pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", public, "-in", p, "-sigfile", s).returncode:
        raise Denied("SIGNATURE")


def consume(db, nonce):
    try:
        with sqlite3.connect(db) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS used_nonce (nonce TEXT PRIMARY KEY)")
            conn.execute("INSERT INTO used_nonce VALUES (?)", (nonce,))
    except sqlite3.IntegrityError as exc:
        raise Denied("REPLAY") from exc


def gh_args(subject, sha, workflow=WORKFLOW, ref=REF):
    if not re.fullmatch("[0-9a-f]{40}", sha):
        raise Denied("SHA")
    return ["gh", "attestation", "verify", str(subject), "--hostname", "github.com",
            "--repo", REPO, "--signer-workflow", workflow, "--signer-digest", sha,
            "--source-digest", sha, "--source-ref", ref,
            "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
            "--predicate-type", "https://slsa.dev/provenance/v1",
            "--deny-self-hosted-runners", "--format", "json"]


def gh_positive(subject, sha):
    result = checked(gh_args(subject, sha))
    if result.returncode:
        print("ATTESTATION_VERIFY_ERROR", result.stderr.decode(errors="replace")[-1500:])
        raise Denied("ATTESTATION")
    evidence = json.loads(result.stdout)
    if not isinstance(evidence, list) or not evidence:
        raise Denied("EMPTY_EVIDENCE")
    print("TRUST02_REAL_ATTESTATION_PASS subject_sha256=" + digest(subject), flush=True)


def expect_denial(label, fn, reason):
    try:
        fn()
    except Denied as exc:
        if str(exc) != reason:
            raise AssertionError((label, str(exc), reason)) from exc
    else:
        raise AssertionError("UNEXPECTED_ACCEPT " + label)
    print("TRUST02_DENIAL_PASS " + label, flush=True)


def identity():
    sha = os.environ["GITHUB_SHA"]
    if not re.fullmatch("[0-9a-f]{40}", sha):
        raise Denied("SHA")
    if (os.environ["GITHUB_REPOSITORY"] != REPO
            or os.environ["GITHUB_REPOSITORY_ID"] != str(REPO_ID)
            or os.environ["GITHUB_REPOSITORY_OWNER_ID"] != str(OWNER_ID)
            or os.environ["GITHUB_REF"] != REF
            or os.environ["GITHUB_WORKFLOW_REF"] != WORKFLOW + "@" + REF
            or os.environ["GITHUB_WORKFLOW_SHA"] != sha
            or os.environ["RUNNER_ENVIRONMENT"] != "github-hosted"):
        raise Denied("LAB_IDENTITY")
    if checked(["git", "rev-parse", "HEAD"]).stdout.decode().strip() != sha:
        raise Denied("CHECKOUT")
    return sha


def main():
    sha = identity()
    subject = Path(os.environ["RUNNER_TEMP"]) / "trust02-inert-subject.txt"
    content = canonical({"domain": DOMAIN, "sha": sha, "run": os.environ["GITHUB_RUN_ID"],
                         "attempt": os.environ["GITHUB_RUN_ATTEMPT"]}) + b"\n"
    if sys.argv[1:] == ["make"]:
        with subject.open("xb") as f:
            f.write(content)
        print("TRUST02_INERT_SUBJECT_SHA256=" + digest(subject))
        return
    if sys.argv[1:] != ["verify"] or subject.is_symlink() or subject.read_bytes() != content:
        raise Denied("INERT_SUBJECT")
    with tempfile.TemporaryDirectory(prefix="trust02-lab-", dir=os.environ["RUNNER_TEMP"]) as tmp:
        root = Path(tmp)
        private, public = root / "ephemeral-lab-private.pem", root / "ephemeral-lab-public.pem"
        os.umask(0o077)
        if openssl("genpkey", "-algorithm", "ED25519", "-out", private).returncode:
            raise RuntimeError("LAB_KEYGEN_FAILED")
        if openssl("pkey", "-in", private, "-pubout", "-out", public).returncode:
            raise RuntimeError("LAB_PUBLIC_KEY_FAILED")
        pin = digest(public)
        now = int(time.time())
        expected = {"domain": DOMAIN, "repo": REPO, "repo_id": REPO_ID, "owner_id": OWNER_ID,
                    "source_sha": sha, "signer_sha": sha, "ref": REF, "workflow": WORKFLOW,
                    "subject_sha256": digest(subject), "run": os.environ["GITHUB_RUN_ID"],
                    "attempt": os.environ["GITHUB_RUN_ATTEMPT"]}
        record = dict(expected, nonce=secrets.token_hex(16), issued=now, expires=now+120)
        signature = sign(private, record, root)
        def validate(rec=record, sig=signature, anchor=pin):
            verify_approval(rec, sig, expected=expected, public=public, public_pin=anchor,
                            now=now, scratch=root)
        validate()
        print("TRUST02_SYNTHETIC_APPROVAL_SIGNATURE_PASS")
        for field, value in (("repo_id", 1), ("owner_id", 1), ("source_sha", "0"*40),
                             ("signer_sha", "0"*40), ("ref", "refs/heads/main"),
                             ("workflow", "unexpected"), ("subject_sha256", "0"*64),
                             ("domain", "CLINICAL"), ("run", "0"), ("attempt", "0")):
            changed = dict(record, **{field: value})
            forged = sign(private, changed, root)
            expect_denial(field, lambda: validate(changed, forged), "BINDING")
        expect_denial("expired", lambda: validate(dict(record, issued=now-120, expires=now)), "TIME")
        expect_denial("future", lambda: validate(dict(record, issued=now+1)), "TIME")
        expect_denial("tampered_signature", lambda: validate(sig=bytes([signature[0]^1])+signature[1:]), "SIGNATURE")
        expect_denial("wrong_anchor", lambda: validate(anchor="0"*64), "ANCHOR")
        expect_denial("extra_field", lambda: validate(dict(record, extra=True)), "SCHEMA")
        # Actual online verification, no mocks, no locally supplied trust bundle.
        gh_positive(subject, sha)
        wrong = "0"*40 if sha != "0"*40 else "1"*40
        altered = root / "altered.txt"
        altered.write_bytes(content+b"tampered")
        for label, args in (
            ("wrong_source_signer_sha", gh_args(subject, wrong)),
            ("wrong_workflow", gh_args(subject, sha, workflow=WORKFLOW+".invalid")),
            ("wrong_ref", gh_args(subject, sha, ref="refs/heads/main")),
            ("mutated_subject", gh_args(altered, sha)),
        ):
            if checked(args).returncode == 0:
                raise AssertionError("UNEXPECTED_ATTESTATION_ACCEPT " + label)
            print("TRUST02_ATTESTATION_DENIAL_PASS " + label, flush=True)
        # Recheck positive after negatives to distinguish systemic outage.
        gh_positive(subject, sha)
        validate()
        db = root / "lab-nonce.sqlite"
        consume(db, record["nonce"])
        expect_denial("persisted_replay", lambda: consume(db, record["nonce"]), "REPLAY")
        private.unlink()
    subject.unlink()
    print("TRUST02_LAB_PASS NOT_A_CLINICAL_CERTIFICATE", flush=True)


if __name__ == "__main__":
    main()
