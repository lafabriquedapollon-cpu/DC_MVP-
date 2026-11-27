"""J5-04 inert provenance + WebAuthn + emulator chain. NEVER release authority."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from dc_release_gate import recovery_authority as authority
from scripts.ci_j5_02c_recovery_lab import RP, ORIGIN, TTL, canon, sha, fixture, assertion
from scripts.ci_j5_02c_tpm_anchor_lab import Emulator, TPMBoundLab
from scripts.ci_j5_02c_trust_root_lab import Denied

BRANCH="ci/j5-04-certification-chain-20261127"
REF="refs/heads/"+BRANCH
WORKFLOW=authority.REPOSITORY+"/.github/workflows/j5-04-certification-chain.yml"
DOMAIN="DIGITAL-CROWN/J5-04/SYNTHETIC/NOT-A-RELEASE/v1"

def require(ok,marker):
    if not ok: raise Denied(marker)

def command(args):
    return subprocess.run(args,capture_output=True,check=False,timeout=90)

def identity():
    head=authority.exact_sha(os.environ["GITHUB_SHA"])
    for k,v in {"GITHUB_REPOSITORY":authority.REPOSITORY,
                "GITHUB_REPOSITORY_ID":str(authority.REPOSITORY_ID),
                "GITHUB_REPOSITORY_OWNER_ID":str(authority.OWNER_ID),
                "GITHUB_REF":REF,"GITHUB_WORKFLOW_REF":WORKFLOW+"@"+REF,
                "GITHUB_WORKFLOW_SHA":head,"RUNNER_ENVIRONMENT":"github-hosted"}.items():
        require(os.environ.get(k)==v,"LAB_IDENTITY_MISMATCH")
    r=command(["git","rev-parse","HEAD"])
    require(r.returncode==0 and r.stdout.decode().strip()==head,"CHECKOUT_MISMATCH")
    require(re.fullmatch(r"[1-9][0-9]*",os.environ["GITHUB_RUN_ID"]) and re.fullmatch(r"[1-9][0-9]*",os.environ["GITHUB_RUN_ATTEMPT"]),"RUN_ID_INVALID")
    return head

def subject_bytes(head):
    return canon({"domain":DOMAIN,"head":head,"run":os.environ["GITHUB_RUN_ID"],
                  "attempt":os.environ["GITHUB_RUN_ATTEMPT"]})+b"\n"

def expected(head,artifact):
    require(artifact==subject_bytes(head),"NOT_INERT_SUBJECT")
    return {"domain":DOMAIN,"repository":authority.REPOSITORY,"repository_id":authority.REPOSITORY_ID,
            "owner_id":authority.OWNER_ID,"source_ref":REF,"source_sha":head,
            "signer_workflow":WORKFLOW,"signer_sha":head,"artifact_sha256":sha(artifact).hex(),
            "artifact_bytes":len(artifact),"run":os.environ["GITHUB_RUN_ID"],
            "attempt":os.environ["GITHUB_RUN_ATTEMPT"],"rp":RP,"origin":ORIGIN}

class ChainLab(TPMBoundLab):
    @staticmethod
    def context(record,artifact):
        exp=expected(identity(),artifact)
        require(type(record) is dict and record.keys()==exp.keys(),"CONTEXT_SCHEMA")
        require(all(type(record[k]) is type(v) and record[k]==v for k,v in exp.items()),"CONTEXT_MISMATCH")
        return canon(record)

    def redeem_fixture(self,nonce,record,artifact):
        # The old fixture checked epoch/one-use but not receipt age.
        # Enforce the original approval challenge deadline atomically.
        with self.tx() as db:
            c=db.execute("SELECT expires,action,used FROM challenges WHERE id=?",(nonce,)).fetchone()
            require(c is not None and c["action"]=="approve" and c["used"]==1
                    and self.local.now<c["expires"],"RECEIPT_EXPIRED_OR_ABSENT")
            return super().redeem_fixture(nonce,record,artifact)

def gh_args(path,head,*,source=None,signer=None,workflow=WORKFLOW,ref=REF):
    return ["gh","attestation","verify",str(path),"--hostname","github.com",
            "--repo",authority.REPOSITORY,"--signer-workflow",workflow,
            "--signer-digest",signer or head,"--source-digest",source or head,
            "--source-ref",ref,"--cert-oidc-issuer",authority.OIDC_ISSUER,
            "--predicate-type",authority.PREDICATE,"--deny-self-hosted-runners","--format","json"]

def verify(path,head,**overrides):
    r=command(gh_args(path,head,**overrides))
    if r.returncode: raise Denied("PROVENANCE_REJECTED")
    data=json.loads(r.stdout)
    require(isinstance(data,list) and len(data)>0,"PROVENANCE_EMPTY")

def denied(label,fn):
    try: fn()
    except ValueError: pass
    else: raise RuntimeError("UNEXPECTED_ACCEPT_"+label)
    print("J5_04_DENIAL_PASS "+label,flush=True)

def main():
    head=identity()
    p=Path(os.environ["RUNNER_TEMP"])/"j5-04-inert-subject.txt"
    artifact=subject_bytes(head)
    if sys.argv[1:]==["make"]:
        with p.open("xb") as f:f.write(artifact)
        print("J5_04_INERT_SUBJECT_SHA256="+sha(artifact).hex())
        return
    require(sys.argv[1:]==["verify"] and p.is_file() and not p.is_symlink()
            and p.read_bytes()==artifact,"SUBJECT_MISMATCH")
    record=expected(head,artifact)
    repo=command(["gh","api","repos/"+authority.REPOSITORY])
    require(repo.returncode==0,"REPO_LOOKUP")
    authority.check_repository_identity(json.loads(repo.stdout))
    mainref=command(["gh","api","repos/"+authority.REPOSITORY+"/branches/main"])
    require(mainref.returncode==0,"MAIN_LOOKUP")
    mainbranch=json.loads(mainref.stdout)
    require(mainbranch.get("protected") is True and mainbranch.get("commit",{}).get("sha")!=head,"PROTECTED_MAIN_EXPECTED")
    try:authority.check_candidate_ref(mainbranch,approved_sha=head)
    except authority.AuthorityDenied:print("J5_04_REAL_MAIN_ADMISSION_DENIED_PASS",flush=True)
    else:raise RuntimeError("UNEXPECTED_PRODUCTION_ADMISSION")
    verify(p,head)
    print("J5_04_REAL_SIGSTORE_PASS",flush=True)
    with tempfile.TemporaryDirectory(prefix="j5-04-chain-",dir=os.environ["RUNNER_TEMP"]) as temp:
        root=Path(temp)
        altered=root/"altered.txt";altered.write_bytes(artifact+b"tamper")
        wrong="0"*40
        for label,fn in [
            ("subject",lambda:verify(altered,head)),
            ("source",lambda:verify(p,head,source=wrong)),
            ("signer",lambda:verify(p,head,signer=wrong)),
            ("workflow",lambda:verify(p,head,workflow=WORKFLOW+".invalid")),
            ("main_ref",lambda:verify(p,head,ref=authority.SOURCE_REF))]:
            denied(label,fn)
        # Positive after all negatives guards against blanket network denial.
        verify(p,head)
        tpm=Emulator(root)
        try:
            db=root/"lab.sqlite";old=root/"old.sqlite"
            primary,backup=fixture(),fixture()
            now=1000
            lab=ChainLab.provision_fixture(db,tpm,primary[:2],backup[:2],clock=lambda:now)
            for field in record:
                value=record[field]
                denied("binding_"+field,lambda f=field,v=value:lab.issue_approval(primary[0],dict(record,**{f:0 if type(v)is int else "wrong"}),artifact))
            denied("artifact_mutation",lambda:lab.issue_approval(primary[0],record,artifact+b"x"))
            q=lab.issue_approval(primary[0],record,artifact)
            receipt=lab.finish_approval(q[0],assertion(primary,q[1]),record,artifact)
            require(receipt["context_sha256"]==sha(canon(record)).hex(),"RECEIPT_BINDING")
            require(receipt["status"]=="SYNTHETIC_APPROVAL_ONLY","FIXTURE_ONLY")
            # No generic path or caller-supplied provenance evidence accepted.
            verify(p,head)
            require(p.read_bytes()==artifact,"POST_VERIFY_SUBJECT_CHANGED")
            shutil.copyfile(db,old)
            tpm.stop();tpm.start()
            lab=ChainLab(db,tpm,clock=lambda:now)
            require(lab.redeem_fixture(q[0],record,artifact)=="INERT_FIXTURE_ONLY","REDEEM")
            denied("replay",lambda:lab.redeem_fixture(q[0],record,artifact))
            q2=lab.issue_approval(primary[0],record,artifact)
            lab.finish_approval(q2[0],assertion(primary,q2[1]),record,artifact)
            now+=TTL
            denied("receipt_expiry",lambda:lab.redeem_fixture(q2[0],record,artifact))
            shutil.copyfile(old,db)
            denied("sqlite_rollback",lambda:ChainLab(db,tpm,clock=lambda:now))
            print("J5_04_CHAIN_BOUND_RECEIPT_TPM_EMULATOR_PASS",flush=True)
        finally:tpm.close()
    print("J5_04_CHAIN_LAB_PASS NOT_A_RELEASE",flush=True)

if __name__=="__main__":main()
